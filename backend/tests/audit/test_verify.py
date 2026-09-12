"""Tests for ``audit.verify.verify_chain`` -- the local chain-recomputation layer.

Every test here builds a small chain in memory with :func:`audit.log.build_entry`
and hands the resulting rows straight to :func:`audit.verify.verify_chain`; none
of it touches a database. That is the point: the tamper-detection path this
module exists for (``docs/SCOPE.md`` D7's "must be able to render red") has to
be provable without depending on a live MySQL instance to run at all.
"""

from __future__ import annotations

import copy

from audit.log import build_entry
from audit.verify import verify_chain


def _row(seq: int, entry: dict) -> dict:
    """Shape a ``build_entry`` result the way a fetched ``audit_entry`` row looks, with a seq."""
    return {**entry, "seq": seq}


def _build_chain(n: int) -> list[dict]:
    rows: list[dict] = []
    prev_hash = None
    for i in range(1, n + 1):
        entry = build_entry(
            action_code="analysis_run",
            actor="engine",
            payload={"run": i},
            prev_hash=prev_hash,
            target_kind="analysis_run",
            target_id=str(i),
        )
        rows.append(_row(i, entry))
        prev_hash = entry["entry_hash"]
    return rows


def test_empty_log_is_vacuously_intact():
    result = verify_chain([])
    assert result.entries_checked == 0
    assert result.chain_intact is True
    assert result.first_divergent_seq is None


def test_untampered_chain_of_several_entries_is_intact():
    rows = _build_chain(5)
    result = verify_chain(rows)
    assert result.entries_checked == 5
    assert result.chain_intact is True
    assert result.first_divergent_seq is None


def test_single_entry_chain_is_intact():
    rows = _build_chain(1)
    result = verify_chain(rows)
    assert result.chain_intact is True
    assert result.first_divergent_seq is None


def test_corrupted_payload_is_detected_at_the_right_seq():
    """The red path: rewrite one entry's content in place (as a DB-write attacker would)
    without touching its leaf_hash/entry_hash columns, and confirm verification catches it.

    This is the exact scenario docs/SCOPE.md D7 says a self-consistency check
    must be able to catch: content that no longer matches what its own leaf
    hash commits to.
    """
    rows = _build_chain(6)
    tampered = copy.deepcopy(rows)
    tampered[3]["payload"] = {"run": 999, "injected": True}  # seq 4, content changed but hashes left stale

    result = verify_chain(tampered)
    assert result.chain_intact is False
    assert result.first_divergent_seq == 4
    assert result.entries_checked == 6


def test_corrupted_middle_entry_reports_its_own_seq_not_the_first_seq():
    rows = _build_chain(8)
    tampered = copy.deepcopy(rows)
    tampered[5]["actor"] = "attacker"  # seq 6

    result = verify_chain(tampered)
    assert result.chain_intact is False
    assert result.first_divergent_seq == 6


def test_tampering_earliest_of_two_corruptions_is_the_one_reported():
    rows = _build_chain(10)
    tampered = copy.deepcopy(rows)
    tampered[2]["target_id"] = "forged"  # seq 3
    tampered[7]["target_id"] = "also-forged"  # seq 8

    result = verify_chain(tampered)
    assert result.chain_intact is False
    assert result.first_divergent_seq == 3


def test_forged_entry_hash_without_content_change_is_still_caught():
    """Even if content and leaf_hash are left alone, a forged chain link is a divergence."""
    rows = _build_chain(4)
    tampered = copy.deepcopy(rows)
    tampered[2]["entry_hash"] = b"\xff" * 32  # seq 3, no other field touched

    result = verify_chain(tampered)
    assert result.chain_intact is False
    assert result.first_divergent_seq == 3


def test_fully_consistent_rewrite_of_the_tail_is_not_caught_by_chain_alone():
    """The documented limitation: an attacker who recomputes every downstream
    hash after a tampered entry produces a chain that is once again internally
    consistent. verify_chain cannot see this -- only the anchored-root
    comparison in run_verification can, because the attacker does not control
    the anchor. This test exists so that limitation is asserted, not assumed.
    """
    rows = _build_chain(5)
    tampered = copy.deepcopy(rows)
    tampered[2]["payload"] = {"run": "forged"}

    from audit.log import compute_entry_hash, recompute_leaf_hash

    prev_hash = tampered[1]["entry_hash"]
    for row in tampered[2:]:
        new_leaf = recompute_leaf_hash(row)
        row["leaf_hash"] = new_leaf
        row["prev_hash"] = prev_hash
        row["entry_hash"] = compute_entry_hash(prev_hash, new_leaf)
        prev_hash = row["entry_hash"]

    result = verify_chain(tampered)
    assert result.chain_intact is True
    assert result.first_divergent_seq is None
