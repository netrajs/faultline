"""Tests for ``audit.anchoring``.

The replay-mode receipt builder and the live-mode dispatch/error path are pure
functions of their inputs and are tested directly, with no database. Only
``publish_checkpoint`` itself needs a database (it reads the log and writes
``merkle_checkpoint``/``anchor_receipt`` rows), so those tests follow the
``requires_db`` skip convention already used in ``tests/app/test_settings_routes.py``
and are the one part of this suite that does not run in an environment with no
MySQL 8 instance configured.
"""

from __future__ import annotations

import pytest

from audit.anchoring import (
    AnchoringError,
    AnchoringUnavailableError,
    _anchor_live,
    _anchor_replay,
    publish_checkpoint,
)


def test_anchor_replay_is_labelled_recorded_not_confirmed():
    receipt = _anchor_replay(epoch=1, tree_size=3, root=b"\x11" * 32)
    assert receipt["status"] == "recorded"
    assert receipt["tx_hash"].startswith("0x")
    assert receipt["confirmed_at"] is not None


def test_anchor_replay_varies_by_epoch_and_root():
    a = _anchor_replay(epoch=1, tree_size=1, root=b"\x01" * 32)
    b = _anchor_replay(epoch=2, tree_size=2, root=b"\x02" * 32)
    assert a["tx_hash"] != b["tx_hash"]


def test_anchor_replay_is_deterministic_for_the_same_epoch_and_root():
    a = _anchor_replay(epoch=1, tree_size=1, root=b"\xaa" * 32)
    b = _anchor_replay(epoch=1, tree_size=1, root=b"\xaa" * 32)
    assert a["tx_hash"] == b["tx_hash"]


def test_anchor_replay_cycles_through_fixture_sessions():
    """More epochs than recorded sessions should still produce a receipt, cycling."""
    receipt = _anchor_replay(epoch=57, tree_size=1, root=b"\x03" * 32)
    assert receipt["status"] == "recorded"
    assert receipt["chain_id"] is not None


@pytest.mark.parametrize("mode", ["anvil", "base-sepolia", "polygon-amoy"])
def test_live_modes_raise_without_a_chain_client(mode):
    """No Foundry/web3/live RPC in this environment -- must fail loudly, not fabricate a receipt."""
    from app.core.settings import Settings

    settings = Settings(
        mysql_host="", mysql_port=3306, mysql_user="", mysql_password="", mysql_database="",
        neo4j_uri="", neo4j_user="", neo4j_password="", neo4j_database="",
        openai_api_key="", openai_model="", anchor_mode="replay",
        anchor_rpc_url="http://127.0.0.1:8545", anchor_contract_address="0xabc",
    )
    with pytest.raises(AnchoringUnavailableError, match="submitCheckpoint"):
        _anchor_live(mode, epoch=1, tree_size=1, root=b"\x00" * 32, settings=settings, chain_client=None)


def test_live_mode_uses_an_injected_chain_client():
    """Structurally correct and mockable: a stub client proves the storage shape works
    without needing a real chain, per the task scoping for anvil/base-sepolia.
    """
    from app.core.settings import Settings

    settings = Settings(
        mysql_host="", mysql_port=3306, mysql_user="", mysql_password="", mysql_database="",
        neo4j_uri="", neo4j_user="", neo4j_password="", neo4j_database="",
        openai_api_key="", openai_model="", anchor_mode="replay",
        anchor_rpc_url="http://127.0.0.1:8545", anchor_contract_address="0xabc",
    )

    def fake_client(mode, epoch, root, tree_size):
        assert mode == "anvil"
        assert epoch == 1
        assert tree_size == 4
        return {
            "chain_id": 31337,
            "tx_hash": "0xdeadbeef",
            "block_number": 42,
            "status": "confirmed",
        }

    receipt = _anchor_live("anvil", epoch=1, tree_size=4, root=b"\x00" * 32, settings=settings, chain_client=fake_client)
    assert receipt["status"] == "confirmed"
    assert receipt["tx_hash"] == "0xdeadbeef"
    assert receipt["contract_address"] == "0xabc"


# ---------------------------------------------------------------------------
# publish_checkpoint over an empty log -- monkeypatched, needs no database at
# all: the empty-log guard runs and raises before publish_checkpoint ever
# opens a connection.
# ---------------------------------------------------------------------------


def test_publish_checkpoint_over_empty_log_raises(monkeypatch: pytest.MonkeyPatch):
    import audit.log as audit_log

    monkeypatch.setattr(audit_log, "load_entries", lambda *a, **k: [])
    with pytest.raises(AnchoringError, match="empty"):
        publish_checkpoint(mode="replay")


def test_publish_checkpoint_rejects_unknown_mode(monkeypatch: pytest.MonkeyPatch):
    import audit.log as audit_log

    # A non-empty log so the mode check has to be what actually rejects this --
    # otherwise a bug that lets an invalid mode through empty-log handling
    # first would go unnoticed.
    monkeypatch.setattr(audit_log, "load_entries", lambda *a, **k: [{"leaf_hash": b"\x00" * 32}])
    with pytest.raises(AnchoringError, match="mode must be one of"):
        publish_checkpoint(mode="ethereum-sepolia")


# ---------------------------------------------------------------------------
# publish_checkpoint end to end -- needs a real database.
# ---------------------------------------------------------------------------


def _db_available() -> bool:
    from app.db import store_health

    return bool(store_health()["mysql"])


requires_db = pytest.mark.skipif(not _db_available(), reason="MySQL is not reachable in this environment")


@requires_db
def test_publish_checkpoint_replay_round_trip():
    """Append one real entry, publish a replay-mode checkpoint, and confirm the
    receipt is stored and clearly labelled recorded rather than live."""
    from audit.log import append_entry

    append_entry("demo_reset", "test-suite", {"note": "audit anchoring round trip"})
    result = publish_checkpoint(mode="replay")
    assert result["receipt"]["mode"] == "replay"
    assert result["receipt"]["status"] == "recorded"
    assert result["checkpoint"]["tree_size"] >= 1
