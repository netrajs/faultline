"""Blast radius endpoints.

Two operations, and the split between them is deliberate. ``POST`` computes a
radius and writes it; ``GET`` reads one back. A result that could only be seen
once, at the moment it was produced, is not a result anyone can be asked to
review — so every run lands in ``blast_radius_run`` and ``blast_reached_node``
and stays addressable by id.

Unlike discovery, this runs inside the request. Discovery searches from every
entry node towards every crown jewel and is rightly kept out of band; a blast
radius starts from one node under a hop cap, and on the demo graph it completes
in tens of milliseconds. The snapshot load is the expensive part, so it is
cached per graph version — the snapshot is immutable by construction, and a new
graph version is a new cache key.

A run is attached to the latest completed baseline ``analysis_run`` rather than
opening one of its own. That is what the ``ix_blast_origin (analysis_run_id,
origin_node_id)`` index in ``004_analysis_results.sql`` is shaped for, and it is
also the honest arrangement: it pins every radius to the same graph version and
scoring version the displayed paths were computed against, so the two sets of
numbers on screen are comparable.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from decimal import Decimal
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.db import fetch_all, fetch_one, mysql_engine
from engine.blast_radius import (
    DEFAULT_MAX_DEPTH,
    DIRECTIONS,
    BlastLimits,
    BlastRadius,
    BlastRadiusError,
    BlastRadiusResult,
    summarise_by_depth,
)
from engine.rules import load_ruleset
from engine.scoring import Scorer, load_scoring_config
from engine.snapshot import load_snapshot

router = APIRouter(prefix="/api/blast-radius", tags=["blast radius"])

#: Hard ceiling on the hop cap a caller may ask for. Past this the search stops
#: being a blast radius and becomes an enumeration of the graph, and the tail it
#: adds is chains whose probability has already collapsed.
MAX_DEPTH_CEILING = 10

#: Same floor the discovered_path columns use: DECIMAL(12,11) cannot hold a
#: smaller positive number, and storing zero would report a real chain as
#: impossible.
_MIN_STORED_P = 1e-11


class BlastRadiusRequest(BaseModel):
    origin_node_id: str = Field(min_length=1, max_length=64)
    direction: str = Field(default="outbound")
    max_depth: int = Field(default=DEFAULT_MAX_DEPTH, ge=1, le=MAX_DEPTH_CEILING)


@lru_cache(maxsize=4)
def _engine_for(graph_version: int, scoring_version: str, max_depth: int) -> BlastRadius:
    """A configured engine, cached per (graph version, scoring version, depth).

    Safe to cache because a snapshot is immutable once built and a regenerated
    graph is a new version id, so a stale entry cannot be served for a graph
    that has changed underneath it.
    """
    return BlastRadius(
        load_snapshot(graph_version),
        load_ruleset(),
        Scorer(load_scoring_config(scoring_version)),
        BlastLimits(max_depth=max_depth),
    )


def _baseline_run() -> dict:
    run = fetch_one(
        """
        SELECT r.id, r.graph_version_id, r.scoring_version, r.threat_model_code
        FROM analysis_run r
        JOIN graph_version g ON g.id = r.graph_version_id AND g.is_active = 1
        WHERE r.purpose = 'baseline' AND r.status = 'complete'
        ORDER BY r.id DESC LIMIT 1
        """
    )
    if not run:
        raise HTTPException(
            404,
            "No completed discovery run for the active graph, so there is no "
            "graph and scoring version to compute a blast radius against. "
            "Run: python -m engine.discover --threat-model external_phish",
        )
    return run


@router.post("")
def compute(request: BlastRadiusRequest) -> dict:
    """Compute, persist and return one blast radius."""
    if request.direction not in DIRECTIONS:
        raise HTTPException(
            422,
            f"Unknown direction {request.direction!r}; expected one of "
            f"{', '.join(DIRECTIONS)}.",
        )

    run = _baseline_run()
    engine = _engine_for(
        int(run["graph_version_id"]), str(run["scoring_version"]), request.max_depth
    )

    started = time.perf_counter()
    try:
        result = engine.run(request.origin_node_id, request.direction)
    except BlastRadiusError as exc:
        raise HTTPException(404, str(exc)) from exc
    duration_ms = int((time.perf_counter() - started) * 1000)

    blast_run_id = _persist(int(run["id"]), result)
    return {
        **_envelope(run, blast_run_id, result_summary(result)),
        "origin": _node_row(int(run["graph_version_id"]), result.origin_node_id),
        "items": [
            {
                "node_id": node.node_id,
                "kind": node.kind,
                "name": node.name,
                "depth": node.depth,
                "p_reach": node.p_reach,
                "is_crown_jewel": 1 if node.is_crown_jewel else 0,
                "witness_path_id": node.witness_path_id,
            }
            for node in result.reached
        ],
        "duration_ms": duration_ms,
        "expansions": result.expansions,
        "truncated": result.truncated,
    }


@router.get("/{blast_run_id}")
def detail(blast_run_id: int = Path(ge=1)) -> dict:
    """Re-read a previously computed run, without recomputing it."""
    stored = fetch_one(
        """
        SELECT b.id, b.analysis_run_id, b.origin_node_id, b.direction, b.max_depth,
               b.nodes_reached, b.crown_jewels_reached, b.severity_score, b.created_at,
               r.graph_version_id, r.scoring_version
        FROM blast_radius_run b
        JOIN analysis_run r ON r.id = b.analysis_run_id
        WHERE b.id = :id
        """,
        {"id": blast_run_id},
    )
    if not stored:
        raise HTTPException(404, f"No blast radius run {blast_run_id}.")

    graph_version = int(stored["graph_version_id"])
    items = [
        _floatify(row)
        for row in fetch_all(
            """
            SELECT r.node_id, n.kind_code AS kind,
                   COALESCE(n.display_name, n.name, r.node_id) AS name,
                   r.depth, r.p_reach, r.is_crown_jewel, r.witness_path_id
            FROM blast_reached_node r
            LEFT JOIN node n
              ON n.node_id = r.node_id AND n.graph_version_id = :gv
            WHERE r.blast_run_id = :id
            ORDER BY r.depth, r.p_reach DESC, r.node_id
            """,
            {"id": blast_run_id, "gv": graph_version},
        )
    ]

    by_depth: dict[int, int] = {}
    for item in items:
        by_depth[item["depth"]] = by_depth.get(item["depth"], 0) + 1

    severity = stored["severity_score"]
    return {
        **_envelope(
            {
                "id": stored["analysis_run_id"],
                "graph_version_id": graph_version,
                "scoring_version": stored["scoring_version"],
            },
            blast_run_id,
            {
                "origin_node_id": stored["origin_node_id"],
                "direction": stored["direction"],
                "max_depth": stored["max_depth"],
                "nodes_reached": stored["nodes_reached"],
                "crown_jewels_reached": stored["crown_jewels_reached"],
                "severity_score": None if severity is None else float(severity),
                # The tier is derived from the stored score against the active
                # bands rather than duplicated in a column, so a retuned tier
                # table cannot leave a stored radius labelled with a band that
                # no longer exists.
                "severity_tier_code": _tier_for(severity),
                "by_depth": [
                    {"depth": depth, "count": count} for depth, count in sorted(by_depth.items())
                ],
            },
        ),
        "origin": _node_row(graph_version, str(stored["origin_node_id"])),
        "items": items,
        "created_at": stored["created_at"],
        "duration_ms": None,
        "expansions": None,
        "truncated": False,
    }


# ── Shaping ──────────────────────────────────────────────────────────────────


def result_summary(result: BlastRadiusResult) -> dict[str, Any]:
    return {
        "origin_node_id": result.origin_node_id,
        "direction": result.direction,
        "max_depth": result.max_depth,
        "nodes_reached": result.nodes_reached,
        "crown_jewels_reached": len(result.crown_jewels_reached),
        "severity_score": result.severity_score,
        "severity_tier_code": result.severity_tier_code,
        "by_depth": [
            {"depth": depth, "count": count}
            for depth, count in summarise_by_depth(result.reached)
        ],
    }


def _envelope(run: dict, blast_run_id: int, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "blast_run_id": blast_run_id,
        "analysis_run_id": run["id"],
        "graph_version_id": run["graph_version_id"],
        "scoring_version": run["scoring_version"],
        **summary,
    }


def _node_row(graph_version: int, node_id: str) -> dict | None:
    return fetch_one(
        """
        SELECT node_id, kind_code AS kind, name, display_name, is_crown_jewel,
               criticality_code
        FROM node WHERE graph_version_id = :gv AND node_id = :id
        """,
        {"gv": graph_version, "id": node_id},
    )


def _tier_for(score: Any) -> str | None:
    if score is None:
        return None
    row = fetch_one(
        """
        SELECT t.code FROM risk_tier t
        JOIN scoring_config c ON c.version = t.scoring_version AND c.is_active = 1
        WHERE :s BETWEEN t.min_score AND t.max_score
        ORDER BY t.sort_order LIMIT 1
        """,
        {"s": float(score)},
    )
    return None if row is None else str(row["code"])


# ── Persistence ──────────────────────────────────────────────────────────────


def _persist(analysis_run_id: int, result: BlastRadiusResult) -> int:
    """Write the run and its reached nodes in one transaction.

    One transaction because a run row whose reached nodes never landed renders
    as "47 nodes reached" above an empty table, which is worse than no run at
    all: the reader has no way to tell a write failure from a genuine result.
    """
    created = datetime.now(timezone.utc).replace(tzinfo=None)
    severity = (
        None if result.severity_score is None else round(float(result.severity_score), 2)
    )

    with mysql_engine().begin() as conn:
        blast_run_id = int(
            conn.execute(
                text(
                    """
                    INSERT INTO blast_radius_run
                      (analysis_run_id, origin_node_id, direction, max_depth,
                       nodes_reached, crown_jewels_reached, severity_score, created_at)
                    VALUES
                      (:run, :origin, :direction, :depth, :nodes, :crown, :severity, :created)
                    """
                ),
                {
                    "run": analysis_run_id,
                    "origin": result.origin_node_id,
                    "direction": result.direction,
                    "depth": result.max_depth,
                    "nodes": result.nodes_reached,
                    "crown": len(result.crown_jewels_reached),
                    "severity": severity,
                    "created": created,
                },
            ).lastrowid
        )

        rows = [
            {
                "run": blast_run_id,
                "node": node.node_id,
                "depth": node.depth,
                # Rounded to the column's width here and only here: the engine
                # works in float64, the column is fixed-point, and this is the
                # one place the two representations meet.
                "p": max(round(min(max(node.p_reach, 0.0), 1.0), 11), _MIN_STORED_P),
                "crown": 1 if node.is_crown_jewel else 0,
                "witness": node.witness_path_id,
            }
            for node in result.reached
        ]
        if rows:
            conn.execute(
                text(
                    """
                    INSERT INTO blast_reached_node
                      (blast_run_id, node_id, depth, p_reach, is_crown_jewel,
                       witness_path_id)
                    VALUES (:run, :node, :depth, :p, :crown, :witness)
                    """
                ),
                rows,
            )

    return blast_run_id


def _floatify(row: dict) -> dict:
    return {k: (float(v) if isinstance(v, Decimal) else v) for k, v in row.items()}
