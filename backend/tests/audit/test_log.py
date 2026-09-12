"""Tests for ``audit.log`` -- entry construction, hashing and chaining.

Everything here operates on :func:`audit.log.build_entry` directly, never on
``append_entry``, so none of it touches a database. That is deliberate: the
hashing and chaining logic is the part that has to be right, and it should be
checkable without MySQL running.
"""

from __future__ import annotations

from datetime import datetime, timezone

from audit.log import GENESIS_HASH, build_entry, compute_entry_hash, recompute_leaf_hash
from core.ids import audit_leaf_hash


def _fixed_time() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc).replace(tzinfo=None)


def test_build_entry_leaf_hash_matches_core_ids_directly():
    """The leaf hash is exactly ``audit_leaf_hash`` over the documented content shape."""
    entry = build_entry(
        action_code="analysis_run",
        actor="netraj@daiko.app",
        payload={"threat_model": "external_phish"},
        prev_hash=None,
        salt=b"\x01" * 16,
        created_at=_fixed_time(),
    )
    expected_content = {
        "action_code": "analysis_run",
        "actor": "netraj@daiko.app",
        "target_kind": None,
        "target_id": None,
        "payload": {"threat_model": "external_phish"},
        "graph_version_id": None,
        "scoring_version": None,
        "risk_before": None,
        "risk_after": None,
        "created_at": _fixed_time().isoformat(),
    }
    assert entry["leaf_hash"] == audit_leaf_hash(b"\x01" * 16, expected_content)


def test_first_entry_chains_from_genesis():
    entry = build_entry(
        action_code="demo_reset", actor="system", payload={}, prev_hash=None, salt=b"\x00" * 16,
    )
    assert entry["prev_hash"] is None
    assert entry["entry_hash"] == compute_entry_hash(GENESIS_HASH, entry["leaf_hash"])


def test_chain_links_successive_entries():
    first = build_entry(action_code="demo_reset", actor="system", payload={"n": 1}, prev_hash=None)
    second = build_entry(action_code="demo_reset", actor="system", payload={"n": 2}, prev_hash=first["entry_hash"])
    assert second["prev_hash"] == first["entry_hash"]
    assert second["entry_hash"] == compute_entry_hash(first["entry_hash"], second["leaf_hash"])
    # Different payload -> different leaf -> different entry_hash, even with
    # the same predecessor -- content is genuinely part of the commitment.
    third = build_entry(action_code="demo_reset", actor="system", payload={"n": 3}, prev_hash=first["entry_hash"])
    assert third["entry_hash"] != second["entry_hash"]


def test_risk_fields_rounded_to_column_width_before_hashing():
    """DECIMAL(4,2) rounds; the hash must be computed over the same rounded value that gets stored.

    Otherwise a fresh round trip through the database (round -> store -> read
    back -> recompute) would disagree with the hash computed at write time,
    which would make every legitimate entry look tampered.
    """
    entry = build_entry(
        action_code="fix_applied", actor="system", payload={}, prev_hash=None,
        risk_before=7.4219, risk_after=2.001,
    )
    assert entry["risk_before"] == 7.42
    assert entry["risk_after"] == 2.0
    # Recomputing from a row shaped like what MySQL would hand back (Decimal,
    # already rounded) must reproduce the same leaf hash.
    row = {**entry, "risk_before": entry["risk_before"], "risk_after": entry["risk_after"]}
    assert recompute_leaf_hash(row) == entry["leaf_hash"]


def test_recompute_leaf_hash_tolerates_json_string_payload_and_iso_created_at():
    """A row read back through a raw DB driver may hand payload/created_at as strings."""
    entry = build_entry(
        action_code="analysis_run", actor="engine", payload={"a": 1, "b": [1, 2, 3]}, prev_hash=None,
    )
    row_from_db = {
        **entry,
        "payload": '{"a": 1, "b": [1, 2, 3]}',
        "created_at": entry["created_at"].isoformat(),
    }
    assert recompute_leaf_hash(row_from_db) == entry["leaf_hash"]


def test_tampering_payload_changes_leaf_hash():
    entry = build_entry(action_code="fix_applied", actor="system", payload={"target": "svc-01"}, prev_hash=None)
    tampered_row = {**entry, "payload": {"target": "svc-99"}}
    assert recompute_leaf_hash(tampered_row) != entry["leaf_hash"]
