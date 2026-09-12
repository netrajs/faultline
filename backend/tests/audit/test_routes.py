"""Tests for /api/audit/*.

Request-validation paths that never touch the database run unconditionally,
same convention as ``tests/app/test_settings_routes.py``. Everything that
reads or writes ``audit_entry``/``merkle_checkpoint``/``anchor_receipt`` is
guarded behind ``requires_db`` and skips cleanly when MySQL is not reachable.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.db import store_health
from app.main import app

client = TestClient(app)


def _db_available() -> bool:
    return bool(store_health()["mysql"])


requires_db = pytest.mark.skipif(not _db_available(), reason="MySQL is not reachable in this environment")


def test_anchor_rejects_unknown_mode():
    response = client.post("/api/audit/anchor", params={"mode": "ethereum-sepolia"})
    assert response.status_code == 422
    assert "mode must be one of" in response.json()["detail"]


@requires_db
def test_entries_empty_state_shape():
    response = client.get("/api/audit/entries", params={"limit": 1})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "total"}
    assert isinstance(body["items"], list)
    assert isinstance(body["total"], int)


@requires_db
def test_actions_catalogue_is_seeded():
    response = client.get("/api/audit/actions")
    assert response.status_code == 200
    codes = {row["code"] for row in response.json()}
    assert "checkpoint_anchored" in codes
    assert "fix_applied" in codes


@requires_db
def test_append_then_list_then_verify_round_trip():
    """A real end-to-end pass: log two entries, run verification, confirm it renders green."""
    from audit.log import append_entry

    first = append_entry("analysis_run", "test-suite", {"scenario": "route-test-1"})
    second = append_entry(
        "fix_applied", "test-suite", {"scenario": "route-test-2"}, risk_before=6.4, risk_after=2.1,
    )
    assert second["seq"] > first["seq"]

    listed = client.get("/api/audit/entries", params={"actor": "test-suite", "limit": 10}).json()
    assert listed["total"] >= 2
    seqs = {row["seq"] for row in listed["items"]}
    assert first["seq"] in seqs and second["seq"] in seqs

    verify_response = client.get("/api/audit/verify")
    assert verify_response.status_code == 200
    report = verify_response.json()
    assert report["chain_intact"] is True
    assert report["first_divergent_seq"] is None
    assert report["entries_checked"] >= 2


@requires_db
def test_anchor_replay_then_checkpoints_list_shows_it_recorded():
    from audit.log import append_entry

    append_entry("demo_reset", "test-suite", {"note": "route anchor test"})
    anchor_response = client.post("/api/audit/anchor", params={"mode": "replay"})
    assert anchor_response.status_code == 200
    body = anchor_response.json()
    assert body["receipt"]["status"] == "recorded"

    checkpoints = client.get("/api/audit/checkpoints").json()
    assert checkpoints["total"] >= 1
    latest = checkpoints["items"][0]
    assert any(r["mode"] == "replay" and r["status"] == "recorded" for r in latest["receipts"])


@requires_db
def test_verify_renders_red_after_a_real_row_is_corrupted():
    """The end-to-end red path against a real database: append two entries,
    corrupt one row's payload in place with a direct UPDATE -- exactly what an
    attacker with database write access could do -- and confirm
    /api/audit/verify reports chain_intact=False with the corrupted row's seq,
    per docs/SCOPE.md D7. The row is restored afterwards so the shared demo
    database is left as this test found it.
    """
    import json

    from app.db import execute, fetch_one
    from audit.log import append_entry

    append_entry("analysis_run", "test-suite", {"scenario": "red-path-before"})
    corrupted = append_entry("analysis_run", "test-suite", {"scenario": "red-path-target"})
    append_entry("analysis_run", "test-suite", {"scenario": "red-path-after"})

    original_row = fetch_one("SELECT payload FROM audit_entry WHERE seq = :seq", {"seq": corrupted["seq"]})
    try:
        execute(
            "UPDATE audit_entry SET payload = :payload WHERE seq = :seq",
            {"payload": json.dumps({"scenario": "tampered-by-test"}), "seq": corrupted["seq"]},
        )

        response = client.get("/api/audit/verify")
        assert response.status_code == 200
        report = response.json()
        assert report["chain_intact"] is False
        assert report["first_divergent_seq"] == corrupted["seq"]
    finally:
        execute(
            "UPDATE audit_entry SET payload = :payload WHERE seq = :seq",
            {"payload": json.dumps(original_row["payload"]) if isinstance(original_row["payload"], (dict, list))
             else original_row["payload"], "seq": corrupted["seq"]},
        )


@requires_db
def test_anchor_live_modes_report_unavailable_not_a_fake_success():
    from audit.log import append_entry

    append_entry("demo_reset", "test-suite", {"note": "route anchor live-mode test"})
    response = client.post("/api/audit/anchor", params={"mode": "anvil"})
    assert response.status_code == 501
    assert "not available in this environment" in response.json()["detail"]
