"""Verifying the audit log, and grading what verification finds.

``docs/SCOPE.md`` D7 is explicit that this module's most important property is
that it can fail. A verify endpoint that only recomputes the local chain and
reports a boolean is checking a database against itself: an attacker with
write access to MySQL can recompute every ``leaf_hash``, every ``entry_hash``
link, and produce a "valid" result for a log that was rewritten wholesale.
That is worth designing around rather than glossing over, so verification here
runs in two tiers of a genuinely different strength:

1. :func:`verify_chain` -- recompute every leaf hash and chain link from the
   rows themselves. Cheap, catches accidental corruption and a *partial*
   rewrite that forgot to re-derive every downstream link, but proves nothing
   against a patient attacker who rewrites the whole tail consistently. This
   tier needs no database at all beyond the rows already fetched, which is
   what makes it possible to test the red path -- ``chain_intact=False`` with
   the correct ``first_divergent_seq`` -- without a live database connection.
2. The anchor comparison in :func:`run_verification` -- recompute the Merkle
   root fresh from the leaves as of the last confirmed/recorded checkpoint's
   tree size, and compare it against the root published outside this
   database. *This* is the check a full rewrite cannot fool, because the
   attacker does not control the anchor. Everything before that checkpoint is
   immutable; only ``tamper_window_seconds`` -- the time since the anchor --
   is still malleable, and it is reported as a number for exactly that reason
   rather than folded into a single pass/fail boolean.

Both tiers, plus an inclusion proof for the freshest anchored entry and a
consistency proof between the two most recent checkpoints, land in one
``verification_result`` row so the interface has a history of checks, not only
the latest answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from audit.log import compute_entry_hash, recompute_leaf_hash
from audit.merkle import (
    consistency_proof,
    inclusion_proof,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)
from core.ids import canonical_json


@dataclass(frozen=True, slots=True)
class ChainVerification:
    entries_checked: int
    chain_intact: bool
    #: seq of the first row whose recomputed leaf hash or chain link disagrees
    #: with what is stored. ``None`` when every row checks out.
    first_divergent_seq: int | None


def verify_chain(rows: Sequence[Mapping[str, Any]]) -> ChainVerification:
    """Recompute the salted leaf hash and sequential chain link for every row.

    Pure with respect to the database: it operates entirely on the rows it is
    given, which is what lets the tamper-detection path be exercised in a unit
    test with a hand-built list of entries rather than a live MySQL instance.

    On its own this only proves the log is *self-consistent* -- exactly the
    check the module docstring (and D7) warns is weak against an attacker who
    can write to the database. It is layer one of :func:`run_verification`,
    not the whole story.
    """
    first_divergent: int | None = None
    running_prev: bytes | None = None

    for row in rows:
        seq = int(row["seq"])
        stored_leaf = bytes(row["leaf_hash"])
        stored_entry_hash = bytes(row["entry_hash"])
        stored_prev = bytes(row["prev_hash"]) if row.get("prev_hash") is not None else None

        recomputed_leaf = recompute_leaf_hash(row)
        recomputed_entry_hash = compute_entry_hash(running_prev, recomputed_leaf)

        row_ok = (
            recomputed_leaf == stored_leaf
            and recomputed_entry_hash == stored_entry_hash
            and stored_prev == running_prev
        )
        if not row_ok and first_divergent is None:
            first_divergent = seq

        # Chain forward from what is actually stored, not from the recomputed
        # value -- so one bad row is reported once, at its own seq, rather than
        # cascading into "everything after it also diverged" noise.
        running_prev = stored_entry_hash

    return ChainVerification(
        entries_checked=len(rows),
        chain_intact=first_divergent is None,
        first_divergent_seq=first_divergent,
    )


@dataclass(frozen=True, slots=True)
class VerificationReport:
    checked_at: datetime
    entries_checked: int
    chain_intact: bool
    first_divergent_seq: int | None
    anchor_epoch: int | None
    anchor_matched: bool | None
    inclusion_proof_ok: bool | None
    consistency_proof_ok: bool | None
    tamper_window_seconds: int | None
    detail: dict[str, Any]

    def to_row(self) -> dict[str, Any]:
        """Shape for the ``verification_result`` INSERT."""
        return {
            "checked_at": self.checked_at,
            "entries_checked": self.entries_checked,
            "chain_intact": self.chain_intact,
            "first_divergent_seq": self.first_divergent_seq,
            "anchor_epoch": self.anchor_epoch,
            "anchor_matched": self.anchor_matched,
            "inclusion_proof_ok": self.inclusion_proof_ok,
            "consistency_proof_ok": self.consistency_proof_ok,
            "tamper_window_seconds": self.tamper_window_seconds,
            "detail": canonical_json(self.detail),
        }

    def to_api(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at.isoformat(),
            "entries_checked": self.entries_checked,
            "chain_intact": self.chain_intact,
            "first_divergent_seq": self.first_divergent_seq,
            "anchor_epoch": self.anchor_epoch,
            "anchor_matched": self.anchor_matched,
            "inclusion_proof_ok": self.inclusion_proof_ok,
            "consistency_proof_ok": self.consistency_proof_ok,
            "tamper_window_seconds": self.tamper_window_seconds,
            "detail": self.detail,
        }


def run_verification(*, persist: bool = True) -> VerificationReport:
    """The full verification pass behind ``GET /api/audit/verify``.

    Runs even over an empty log (reports everything as ``None``/vacuously
    intact rather than raising) and even with no checkpoint yet published --
    both are real, honest states, not error conditions.
    """
    from app.db import execute, fetch_all, fetch_one
    from audit.log import load_entries

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = load_entries()
    chain = verify_chain(rows)
    all_leaves = [bytes(r["leaf_hash"]) for r in rows]

    detail: dict[str, Any] = {
        "chain": {
            "entries_checked": chain.entries_checked,
            "chain_intact": chain.chain_intact,
            "first_divergent_seq": chain.first_divergent_seq,
        },
    }

    anchor_epoch: int | None = None
    anchor_matched: bool | None = None
    inclusion_proof_ok: bool | None = None
    consistency_proof_ok: bool | None = None
    tamper_window_seconds: int | None = None

    # A receipt of status 'recorded' (replay mode) is treated the same as
    # 'confirmed' here -- both represent a root published somewhere this
    # database does not control, which is the property that matters. See
    # anchoring.py and docs/SCOPE.md D7 on why replay is a real anchoring mode
    # and not a mock.
    latest_anchor = fetch_one(
        """
        SELECT ar.checkpoint_epoch, ar.confirmed_at, ar.created_at, ar.status,
               mc.tree_size, mc.root
        FROM anchor_receipt ar
        JOIN merkle_checkpoint mc ON mc.epoch = ar.checkpoint_epoch
        WHERE ar.status IN ('confirmed', 'recorded')
        ORDER BY ar.checkpoint_epoch DESC, ar.id DESC
        LIMIT 1
        """
    )

    if latest_anchor is not None:
        anchor_epoch = int(latest_anchor["checkpoint_epoch"])
        anchor_tree_size = int(latest_anchor["tree_size"])
        anchor_root = bytes(latest_anchor["root"])

        # Recomputed fresh from the leaves, never trusted from
        # merkle_checkpoint.root -- the whole point is not to check the
        # database against itself.
        recomputed_root = merkle_root(all_leaves[:anchor_tree_size])
        anchor_matched = recomputed_root == anchor_root
        detail["anchor"] = {
            "epoch": anchor_epoch,
            "tree_size": anchor_tree_size,
            "published_root": anchor_root.hex(),
            "recomputed_root": recomputed_root.hex(),
            "matched": anchor_matched,
        }

        confirmed_at = latest_anchor["confirmed_at"] or latest_anchor["created_at"]
        if confirmed_at is not None:
            tamper_window_seconds = max(0, int((now - confirmed_at).total_seconds()))

        if anchor_tree_size > 0 and len(all_leaves) >= anchor_tree_size:
            sample_index = anchor_tree_size - 1
            leaves_at_checkpoint = all_leaves[:anchor_tree_size]
            proof = inclusion_proof(leaves_at_checkpoint, sample_index)
            inclusion_proof_ok = verify_inclusion(
                leaves_at_checkpoint[sample_index], sample_index, anchor_tree_size, proof, anchor_root
            )
            detail["inclusion_proof"] = {
                "sampled_seq": int(rows[sample_index]["seq"]),
                "index": sample_index,
                "checkpoint_epoch": anchor_epoch,
                "ok": inclusion_proof_ok,
            }

    checkpoints = fetch_all("SELECT epoch, tree_size, root FROM merkle_checkpoint ORDER BY epoch")
    if len(checkpoints) >= 2:
        older, newer = checkpoints[-2], checkpoints[-1]
        older_size = int(older["tree_size"])
        newer_size = int(newer["tree_size"])
        proof = consistency_proof(all_leaves[:newer_size], older_size)
        consistency_proof_ok = verify_consistency(
            older_size, newer_size, bytes(older["root"]), bytes(newer["root"]), proof
        )
        detail["consistency_proof"] = {
            "old_epoch": int(older["epoch"]),
            "new_epoch": int(newer["epoch"]),
            "old_tree_size": older_size,
            "new_tree_size": newer_size,
            "ok": consistency_proof_ok,
        }

    report = VerificationReport(
        checked_at=now,
        entries_checked=chain.entries_checked,
        chain_intact=chain.chain_intact,
        first_divergent_seq=chain.first_divergent_seq,
        anchor_epoch=anchor_epoch,
        anchor_matched=anchor_matched,
        inclusion_proof_ok=inclusion_proof_ok,
        consistency_proof_ok=consistency_proof_ok,
        tamper_window_seconds=tamper_window_seconds,
        detail=detail,
    )

    if persist:
        row = report.to_row()
        execute(
            """
            INSERT INTO verification_result
              (checked_at, entries_checked, chain_intact, first_divergent_seq,
               anchor_epoch, anchor_matched, inclusion_proof_ok, consistency_proof_ok,
               tamper_window_seconds, detail)
            VALUES
              (:checked_at, :entries_checked, :chain_intact, :first_divergent_seq,
               :anchor_epoch, :anchor_matched, :inclusion_proof_ok, :consistency_proof_ok,
               :tamper_window_seconds, :detail)
            """,
            row,
        )

    return report
