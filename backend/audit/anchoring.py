"""Publishing a checkpoint over the audit log, outside this database.

This is the step that turns the self-consistency ``audit.log``/``audit.verify``
can check into actual evidence (``docs/SCOPE.md`` D7). Three modes, selected by
``Settings.anchor_mode`` or overridden per call, so a demo never depends on
conference wifi:

``replay``
    No live chain call. Serves a receipt built from a small local fixture of
    previously "recorded" sessions (``audit/fixtures/replay_receipts.json``),
    labelled with status ``recorded`` end to end -- the database, the API
    response and the frontend all say "recorded", never "live". This is the
    only mode this module fully exercises in an environment with no Foundry
    installation and no running chain; see the module-level test suite.

``anvil`` / ``base-sepolia`` / ``polygon-amoy``
    Structurally wired to the same call shape a real anchor would use --
    ``CheckpointRegistry.submitCheckpoint(epoch, root, treeSize)``, see
    ``contracts/src/CheckpointRegistry.sol`` -- and mockable via the
    ``chain_client`` parameter, so the storage path (checkpoint row, receipt
    row, status transitions) can be exercised end to end with a fake client in
    tests without a real RPC endpoint. With no client supplied, which is the
    only way this runs today (no Foundry binary, no web3 dependency, no chain
    listening on ``settings.anchor_rpc_url`` in this environment), publishing
    raises :class:`AnchoringUnavailableError` rather than fabricating a
    receipt that looks live but isn't -- a checkpoint that silently isn't
    anchored is worse than an endpoint that says so.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import text

from app.core.settings import Settings, load_settings

VALID_MODES = ("anvil", "base-sepolia", "polygon-amoy", "replay")

_FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "replay_receipts.json"


class AnchoringError(RuntimeError):
    """A checkpoint could not be published as requested."""


class AnchoringUnavailableError(AnchoringError):
    """The requested mode has no working backend in this environment."""


class ChainClient(Protocol):
    """What a live-chain anchor call needs to supply, for injection in tests.

    A real implementation would sign and send
    ``CheckpointRegistry.submitCheckpoint(epoch, root, treeSize)`` over
    ``settings.anchor_rpc_url`` and wait for a confirmation; none is wired up
    here (see the module docstring). Tests can pass a stub matching this
    signature to prove the surrounding storage logic is correct without one.
    """

    def __call__(self, mode: str, epoch: int, root: bytes, tree_size: int) -> dict[str, Any]: ...


def _load_replay_sessions() -> list[dict[str, Any]]:
    with _FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)["recorded_sessions"]


def _anchor_replay(epoch: int, tree_size: int, root: bytes) -> dict[str, Any]:
    """Build a 'recorded' receipt from the replay fixture.

    The session template supplies the parts a real chain would (a chain id, a
    plausible contract address, an explorer URL shape); the transaction hash
    and block number are derived per checkpoint from the epoch and root, so
    every replayed anchor is still unique to what it is standing in for
    instead of every demo run reusing the same fabricated transaction
    identity verbatim.
    """
    sessions = _load_replay_sessions()
    session = sessions[(epoch - 1) % len(sessions)]
    derived = hashlib.sha256(f"{session['mode']}:{epoch}:{root.hex()}".encode()).hexdigest()
    tx_hash = f"0x{derived}"
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return {
        "chain_id": session["chain_id"],
        "contract_address": session["contract_address"],
        "tx_hash": tx_hash,
        "block_number": session["block_number_base"] + epoch,
        "block_timestamp": now,
        "gas_used": session["gas_used"],
        "explorer_url": session["explorer_url_template"].format(tx_hash=tx_hash),
        "status": "recorded",
        "confirmed_at": now,
    }


def _anchor_live(
    mode: str, epoch: int, tree_size: int, root: bytes, settings: Settings, chain_client: ChainClient | None,
) -> dict[str, Any]:
    if chain_client is not None:
        result = chain_client(mode, epoch, root, tree_size)
        return {
            "chain_id": result.get("chain_id"),
            "contract_address": result.get("contract_address") or settings.anchor_contract_address or None,
            "tx_hash": result.get("tx_hash"),
            "block_number": result.get("block_number"),
            "block_timestamp": result.get("block_timestamp"),
            "gas_used": result.get("gas_used"),
            "explorer_url": result.get("explorer_url"),
            "status": result.get("status", "confirmed"),
            "confirmed_at": result.get("confirmed_at"),
            "error_text": result.get("error_text"),
        }

    raise AnchoringUnavailableError(
        f"{mode} anchoring is not available in this environment. It requires a live JSON-RPC "
        f"endpoint (Settings.anchor_rpc_url) and the Foundry/web3 toolchain to sign and send "
        f"CheckpointRegistry.submitCheckpoint(epoch={epoch}, root=0x{root.hex()}, treeSize={tree_size}) "
        "against Settings.anchor_contract_address -- neither is installed here. "
        "Use ANCHOR_MODE=replay (the default) to anchor against recorded receipts instead."
    )


def publish_checkpoint(mode: str | None = None, *, chain_client: ChainClient | None = None) -> dict[str, Any]:
    """Publish a new checkpoint over the current log, plus an anchor receipt for it.

    If the log has not grown since the last checkpoint, no new
    ``merkle_checkpoint`` row is created (its ``tree_size`` is unique) -- the
    existing one is reused and a fresh receipt is recorded against it, which
    is a legitimate thing to do (e.g. re-anchoring the same root on a second
    chain, or retrying a failed live attempt).
    """
    from app.db import mysql_engine
    from audit.log import build_merkle_log, load_entries

    # Validated before anything else touches settings or the database, so an
    # invalid mode is reported as exactly that rather than masked by whichever
    # of those happens to fail first.
    if mode is not None and mode not in VALID_MODES:
        raise AnchoringError(f"mode must be one of {VALID_MODES}, got {mode!r}")

    entries = load_entries()
    if not entries:
        raise AnchoringError("Cannot publish a checkpoint over an empty audit log.")

    settings = load_settings()
    mode = mode or settings.anchor_mode

    tree = build_merkle_log(entries)
    tree_size = tree.size
    root = tree.root
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    with mysql_engine().begin() as conn:
        existing = conn.execute(
            text("SELECT epoch FROM merkle_checkpoint WHERE tree_size = :n"), {"n": tree_size}
        ).mappings().first()
        if existing:
            epoch = int(existing["epoch"])
        else:
            result = conn.execute(
                text("INSERT INTO merkle_checkpoint (tree_size, root, created_at) VALUES (:n, :root, :now)"),
                {"n": tree_size, "root": root, "now": now},
            )
            epoch = int(result.lastrowid)

        if mode == "replay":
            receipt = _anchor_replay(epoch, tree_size, root)
        else:
            receipt = _anchor_live(mode, epoch, tree_size, root, settings, chain_client)

        receipt_row = {
            "checkpoint_epoch": epoch,
            "mode": mode,
            "chain_id": receipt.get("chain_id"),
            "contract_address": receipt.get("contract_address"),
            "tx_hash": receipt.get("tx_hash"),
            "block_number": receipt.get("block_number"),
            "block_timestamp": receipt.get("block_timestamp"),
            "gas_used": receipt.get("gas_used"),
            "explorer_url": receipt.get("explorer_url"),
            "status": receipt["status"],
            "error_text": receipt.get("error_text"),
            "created_at": now,
            "confirmed_at": receipt.get("confirmed_at"),
        }
        receipt_id = conn.execute(
            text(
                """
                INSERT INTO anchor_receipt
                  (checkpoint_epoch, mode, chain_id, contract_address, tx_hash, block_number,
                   block_timestamp, gas_used, explorer_url, status, error_text, created_at, confirmed_at)
                VALUES
                  (:checkpoint_epoch, :mode, :chain_id, :contract_address, :tx_hash, :block_number,
                   :block_timestamp, :gas_used, :explorer_url, :status, :error_text, :created_at, :confirmed_at)
                """
            ),
            receipt_row,
        ).lastrowid

    return {
        "checkpoint": {
            "epoch": epoch,
            "tree_size": tree_size,
            "root": root.hex(),
            "created_at": now.isoformat(),
        },
        "receipt": {
            "id": int(receipt_id),
            "checkpoint_epoch": epoch,
            "mode": mode,
            "chain_id": receipt_row["chain_id"],
            "contract_address": receipt_row["contract_address"],
            "tx_hash": receipt_row["tx_hash"],
            "block_number": receipt_row["block_number"],
            "block_timestamp": receipt_row["block_timestamp"].isoformat() if receipt_row["block_timestamp"] else None,
            "gas_used": receipt_row["gas_used"],
            "explorer_url": receipt_row["explorer_url"],
            "status": receipt_row["status"],
            "created_at": now.isoformat(),
            "confirmed_at": receipt_row["confirmed_at"].isoformat() if receipt_row["confirmed_at"] else None,
        },
    }
