"""Appending to the audit ledger and rebuilding the Merkle log from it.

Two independent tamper-evidence structures sit over the same leaves, on
purpose. ``entry_hash`` is a plain sequential hash chain -- the classic
"blockchain" shape a reader already recognises, and cheap to check locally
with no proof math (`` entry_hash[n] = H(entry_hash[n-1] || leaf_hash[n])``).
The Merkle tree built from the same ``leaf_hash`` values (``merkle.py``) is
what actually gets anchored and proven externally (``docs/SCOPE.md`` D7). The
two are deliberately redundant: a bug in one construction does not silently
defeat the other, and the sequential chain gives ``verify.py`` an O(1)-per-row
check to run before it reaches for proof machinery at all.

Every hashing decision here is pinned down explicitly rather than left to
"whatever the caller passed in", because the whole point of the leaf hash is
that the same entry always reproduces the same bytes. In particular:

* ``created_at`` is part of what the leaf commits to, not just a column next
  to it -- otherwise a rewritten timestamp would be invisible to
  ``verify_chain``.
* ``risk_before``/``risk_after`` are rounded to two decimal places *before*
  hashing, matching the width of the ``DECIMAL(4,2)`` column they are stored
  in. Hashing the caller's raw float and then storing MySQL's rounded version
  would make every recomputation disagree with the stored leaf.
* ``seq`` itself is deliberately left out of the hashed content. It does not
  need to be: an entry's position in the log *is* its Merkle leaf index, so
  its ordering is already committed to by where it sits in the tree.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping

from sqlalchemy import text

from audit.merkle import MerkleLog
from core.ids import audit_leaf_hash

#: Sentinel used in place of a real previous hash for the first entry in the
#: log, so ``compute_entry_hash`` never has to special-case ``None`` at the
#: call site.
GENESIS_HASH = b"\x00" * 32


def compute_entry_hash(prev_hash: bytes | None, leaf_hash: bytes) -> bytes:
    """The sequential chain link: ``sha256(prev_hash-or-genesis || leaf_hash)``.

    This is not the Merkle tree -- see the module docstring for why the two
    are kept as separate, redundant structures over the same leaves.
    """
    prefix = prev_hash if prev_hash is not None else GENESIS_HASH
    return hashlib.sha256(prefix + leaf_hash).digest()


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _entry_content(
    action_code: str,
    actor: str,
    target_kind: str | None,
    target_id: str | None,
    payload: Mapping[str, Any],
    graph_version_id: int | None,
    scoring_version: str | None,
    risk_before: float | None,
    risk_after: float | None,
    created_at: datetime,
) -> dict[str, Any]:
    """Everything the leaf hash commits to, other than the salt itself."""
    return {
        "action_code": action_code,
        "actor": actor,
        "target_kind": target_kind,
        "target_id": target_id,
        "payload": payload,
        "graph_version_id": graph_version_id,
        "scoring_version": scoring_version,
        "risk_before": risk_before,
        "risk_after": risk_after,
        "created_at": created_at.isoformat(),
    }


def build_entry(
    *,
    action_code: str,
    actor: str,
    payload: Mapping[str, Any],
    prev_hash: bytes | None,
    target_kind: str | None = None,
    target_id: str | None = None,
    graph_version_id: int | None = None,
    scoring_version: str | None = None,
    risk_before: float | None = None,
    risk_after: float | None = None,
    created_at: datetime | None = None,
    salt: bytes | None = None,
) -> dict[str, Any]:
    """Compute every derived field for one entry, without touching the database.

    Kept separate from :func:`append_entry` so the hashing and chaining logic
    -- including the tamper-detection path exercised in
    ``tests/audit/test_log.py`` -- can be tested without a live database
    connection. ``append_entry`` is a thin wrapper: read the previous
    ``entry_hash`` under a lock, call this, insert the result.
    """
    created_at = created_at or datetime.now(timezone.utc).replace(tzinfo=None)
    risk_before = round(risk_before, 2) if risk_before is not None else None
    risk_after = round(risk_after, 2) if risk_after is not None else None
    salt = salt if salt is not None else os.urandom(16)

    content = _entry_content(
        action_code, actor, target_kind, target_id, payload,
        graph_version_id, scoring_version, risk_before, risk_after, created_at,
    )
    leaf_hash = audit_leaf_hash(salt, content)
    entry_hash = compute_entry_hash(prev_hash, leaf_hash)

    return {
        "action_code": action_code,
        "actor": actor,
        "target_kind": target_kind,
        "target_id": target_id,
        "payload": dict(payload),
        "graph_version_id": graph_version_id,
        "scoring_version": scoring_version,
        "risk_before": risk_before,
        "risk_after": risk_after,
        "salt": salt,
        "leaf_hash": leaf_hash,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "created_at": created_at,
    }


def recompute_leaf_hash(row: Mapping[str, Any]) -> bytes:
    """Recompute a stored row's leaf hash from its own content and salt.

    Used by ``verify.py`` to check a row against itself -- the first, cheapest
    (and, on its own, weakest -- see D7) layer of verification. Tolerant of
    the shapes a row can arrive in: ``payload`` may already be a parsed
    dict/list (pymysql decodes JSON columns automatically) or a raw JSON
    string; ``created_at`` may be a ``datetime`` or an ISO string;
    ``risk_before``/``risk_after`` may be ``Decimal`` (MySQL's native numeric
    type) or ``float``.
    """
    payload = row["payload"]
    if isinstance(payload, (str, bytes)):
        payload = json.loads(payload)

    created_at = row["created_at"]
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)

    content = _entry_content(
        row["action_code"],
        row["actor"],
        row.get("target_kind"),
        row.get("target_id"),
        payload,
        row.get("graph_version_id"),
        row.get("scoring_version"),
        _to_float(row.get("risk_before")),
        _to_float(row.get("risk_after")),
        created_at,
    )
    return audit_leaf_hash(bytes(row["salt"]), content)


def append_entry(
    action_code: str,
    actor: str,
    payload: Mapping[str, Any],
    *,
    target_kind: str | None = None,
    target_id: str | None = None,
    graph_version_id: int | None = None,
    scoring_version: str | None = None,
    risk_before: float | None = None,
    risk_after: float | None = None,
) -> dict[str, Any]:
    """Append one row to ``audit_entry`` and return it, including the assigned ``seq``.

    Holds a named lock (``GET_LOCK``) around the read-compute-insert sequence.
    Without it, two concurrent appends could both read the same "last
    entry_hash" and each compute a link from it, which would fork the chain --
    two entries both claiming the same predecessor is exactly the kind of
    inconsistency this ledger exists to make impossible.
    """
    from app.db import mysql_engine  # local import: see engine/persistence.py for the same convention

    with mysql_engine().begin() as conn:
        conn.execute(text("SELECT GET_LOCK('faultline_audit_append', 10)"))
        try:
            prev_row = conn.execute(
                text("SELECT entry_hash FROM audit_entry ORDER BY seq DESC LIMIT 1")
            ).mappings().first()
            prev_hash = bytes(prev_row["entry_hash"]) if prev_row else None

            entry = build_entry(
                action_code=action_code,
                actor=actor,
                payload=payload,
                prev_hash=prev_hash,
                target_kind=target_kind,
                target_id=target_id,
                graph_version_id=graph_version_id,
                scoring_version=scoring_version,
                risk_before=risk_before,
                risk_after=risk_after,
            )

            result = conn.execute(
                text(
                    """
                    INSERT INTO audit_entry
                      (action_code, actor, target_kind, target_id, payload,
                       graph_version_id, scoring_version, risk_before, risk_after,
                       salt, leaf_hash, prev_hash, entry_hash, created_at)
                    VALUES
                      (:action_code, :actor, :target_kind, :target_id, :payload,
                       :graph_version_id, :scoring_version, :risk_before, :risk_after,
                       :salt, :leaf_hash, :prev_hash, :entry_hash, :created_at)
                    """
                ),
                {
                    "action_code": entry["action_code"],
                    "actor": entry["actor"],
                    "target_kind": entry["target_kind"],
                    "target_id": entry["target_id"],
                    "payload": json.dumps(entry["payload"]),
                    "graph_version_id": entry["graph_version_id"],
                    "scoring_version": entry["scoring_version"],
                    "risk_before": entry["risk_before"],
                    "risk_after": entry["risk_after"],
                    "salt": entry["salt"],
                    "leaf_hash": entry["leaf_hash"],
                    "prev_hash": entry["prev_hash"],
                    "entry_hash": entry["entry_hash"],
                    "created_at": entry["created_at"],
                },
            )
            entry["seq"] = int(result.lastrowid)
        finally:
            conn.execute(text("SELECT RELEASE_LOCK('faultline_audit_append')"))

    return entry


def load_entries(limit: int | None = None) -> list[dict[str, Any]]:
    """Every ``audit_entry`` row, in ``seq`` order -- the order the Merkle tree indexes by."""
    from app.db import fetch_all

    sql = "SELECT * FROM audit_entry ORDER BY seq"
    params: dict[str, Any] = {}
    if limit is not None:
        sql += " LIMIT :limit"
        params["limit"] = limit
    return fetch_all(sql, params)


def build_merkle_log(entries: list[dict[str, Any]] | None = None) -> MerkleLog:
    """A :class:`~audit.merkle.MerkleLog` over every leaf hash, in ``seq`` order."""
    rows = entries if entries is not None else load_entries()
    return MerkleLog([bytes(r["leaf_hash"]) for r in rows])
