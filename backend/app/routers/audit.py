"""Audit trail endpoints: the append-only log, its Merkle checkpoints and
external anchors, and the verification pass that can render red.

Reads a store the rest of the product writes to incidentally -- appending an
entry is the job of whichever action just happened (see ``audit/log.py``),
not something this router does on its own. What lives here is: browsing the
log, publishing and listing checkpoints/anchors, and running verification.
See ``docs/SCOPE.md`` D7 for why a local hash chain alone is weak evidence and
what anchoring and verification are meant to prove instead.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.db import fetch_all, fetch_scalar
from audit.anchoring import VALID_MODES, AnchoringError, AnchoringUnavailableError, publish_checkpoint
from audit.verify import run_verification

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/actions")
def actions() -> list[dict]:
    """The action catalogue: code, label, colour, whether it mutates state.

    Served so the entry log and its legend read from one row each rather than
    hardcoding a colour or a label for an action code in the frontend (D12).
    """
    return fetch_all(
        "SELECT code, label, description, is_mutation, ui_color, sort_order "
        "FROM audit_action ORDER BY sort_order"
    )


@router.get("/entries")
def entries(
    action_code: str | None = None,
    actor: str | None = None,
    target_kind: str | None = None,
    target_id: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """Paginated, filterable view of ``audit_entry``.

    ``salt`` and the raw hash columns are returned hex-encoded rather than
    omitted -- releasing a salt alongside its entry is exactly the selective
    disclosure D7 describes (it proves that one entry without exposing any
    other), and hiding it here would make the inclusion-proof story harder to
    demonstrate, not more secure.
    """
    filters = []
    params: dict = {"limit": limit, "offset": offset}
    if action_code:
        filters.append("action_code = :action_code")
        params["action_code"] = action_code
    if actor:
        filters.append("actor = :actor")
        params["actor"] = actor
    if target_kind:
        filters.append("target_kind = :target_kind")
        params["target_kind"] = target_kind
    if target_id:
        filters.append("target_id = :target_id")
        params["target_id"] = target_id
    where = f"WHERE {' AND '.join(filters)}" if filters else ""

    rows = fetch_all(
        f"""
        SELECT seq, action_code, actor, target_kind, target_id, payload,
               graph_version_id, scoring_version, risk_before, risk_after,
               HEX(salt) AS salt_hex, HEX(leaf_hash) AS leaf_hash_hex,
               HEX(prev_hash) AS prev_hash_hex, HEX(entry_hash) AS entry_hash_hex,
               created_at
        FROM audit_entry
        {where}
        ORDER BY seq DESC
        LIMIT :limit OFFSET :offset
        """,
        params,
    )
    total = fetch_scalar(f"SELECT COUNT(*) FROM audit_entry {where}", params)
    return {"items": [_floatify(r) for r in rows], "total": int(total or 0)}


@router.get("/checkpoints")
def checkpoints(limit: int = Query(50, ge=1, le=500)) -> dict:
    """Every published checkpoint, with the anchor receipts recorded against it."""
    epochs = fetch_all(
        "SELECT epoch, tree_size, HEX(root) AS root_hex, created_at "
        "FROM merkle_checkpoint ORDER BY epoch DESC LIMIT :limit",
        {"limit": limit},
    )
    if not epochs:
        return {"items": [], "total": 0}

    # Fetched unfiltered and grouped in Python rather than an `IN` clause --
    # the epoch set here is at most `limit` (<=500) checkpoints, so the extra
    # rows cost nothing, and it sidesteps SQLAlchemy's expanding-bindparam
    # ceremony for a tuple parameter.
    wanted_epochs = {e["epoch"] for e in epochs}
    receipts = fetch_all(
        """
        SELECT id, checkpoint_epoch, mode, chain_id, contract_address, tx_hash,
               block_number, block_timestamp, gas_used, explorer_url, status,
               error_text, created_at, confirmed_at
        FROM anchor_receipt
        ORDER BY checkpoint_epoch DESC, id DESC
        """
    )

    by_epoch: dict[int, list[dict]] = {}
    for r in receipts:
        if r["checkpoint_epoch"] in wanted_epochs:
            by_epoch.setdefault(r["checkpoint_epoch"], []).append(r)

    for e in epochs:
        e["receipts"] = by_epoch.get(e["epoch"], [])

    total = fetch_scalar("SELECT COUNT(*) FROM merkle_checkpoint")
    return {"items": epochs, "total": int(total or 0)}


@router.post("/anchor")
def anchor(mode: str | None = None) -> dict:
    """Publish a new checkpoint over the current log and anchor it.

    ``mode`` defaults to ``Settings.anchor_mode`` (``replay`` unless
    configured otherwise). Requesting ``anvil``/``base-sepolia``/
    ``polygon-amoy`` explicitly in an environment with no live chain wired up
    fails with a 501 naming exactly why, rather than fabricating a receipt
    that looks live.
    """
    if mode is not None and mode not in VALID_MODES:
        raise HTTPException(422, f"mode must be one of {VALID_MODES}, got {mode!r}.")
    try:
        return publish_checkpoint(mode=mode)
    except AnchoringUnavailableError as exc:
        raise HTTPException(501, str(exc)) from exc
    except AnchoringError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/verify")
def verify() -> dict:
    """Run a full verification pass and return it.

    Always writes a ``verification_result`` row (see ``audit/verify.py``) so
    the history of checks accumulates even when this is called from an
    automated poll rather than a person clicking a button.
    """
    report = run_verification()
    return report.to_api()


@router.get("/verify/history")
def verify_history(limit: int = Query(20, ge=1, le=200)) -> list[dict]:
    """Past verification runs, most recent first."""
    rows = fetch_all(
        """
        SELECT id, checked_at, entries_checked, chain_intact, first_divergent_seq,
               anchor_epoch, anchor_matched, inclusion_proof_ok, consistency_proof_ok,
               tamper_window_seconds, detail
        FROM verification_result
        ORDER BY id DESC LIMIT :limit
        """,
        {"limit": limit},
    )
    return rows


def _floatify(row: dict) -> dict:
    """DECIMAL columns arrive as ``Decimal``, which is not JSON-serialisable."""
    from decimal import Decimal

    return {k: (float(v) if isinstance(v, Decimal) else v) for k, v in row.items()}
