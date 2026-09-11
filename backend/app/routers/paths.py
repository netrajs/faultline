"""Attack path and risk endpoints.

Reads what the engine wrote. Discovery itself runs out of band — a full run
against a two-thousand-node graph is not something to do inside a request, and
tying it to an HTTP timeout would make the most important operation in the
product the most fragile one.

Every response carries the ``analysis_run_id`` it came from. Results are only
comparable within a run: they were computed against one graph version under one
scoring version, and mixing runs silently compares numbers that were never
meant to be compared.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.db import fetch_all, fetch_one

router = APIRouter(prefix="/api", tags=["paths"])


def _latest_run(purpose: str = "baseline") -> dict:
    run = fetch_one(
        """
        SELECT r.id, r.graph_version_id, r.scoring_version, r.threat_model_code,
               r.purpose, r.max_hops, r.top_k_per_pair, r.path_count, r.rejected_count,
               r.crown_jewels_reached, r.max_risk_score, r.duration_ms,
               r.started_at, r.finished_at
        FROM analysis_run r
        JOIN graph_version g ON g.id = r.graph_version_id AND g.is_active = 1
        WHERE r.purpose = :p AND r.status = 'complete'
        ORDER BY r.id DESC LIMIT 1
        """,
        {"p": purpose},
    )
    if not run:
        raise HTTPException(
            404,
            "No completed discovery run for the active graph. "
            "Run: python -m engine.discover --threat-model external_phish",
        )
    return run


@router.get("/runs")
def runs(limit: int = Query(20, ge=1, le=100)) -> list[dict]:
    return fetch_all(
        """
        SELECT id, graph_version_id, scoring_version, threat_model_code, purpose,
               path_count, rejected_count, crown_jewels_reached, max_risk_score,
               duration_ms, status, started_at, finished_at
        FROM analysis_run ORDER BY id DESC LIMIT :limit
        """,
        {"limit": limit},
    )


@router.get("/paths")
def list_paths(
    tier: str | None = None,
    crown_jewels_only: bool = False,
    source: str | None = None,
    target: str | None = None,
    max_hops: int | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    run_id: int | None = None,
) -> dict:
    run = fetch_one("SELECT * FROM analysis_run WHERE id = :i", {"i": run_id}) if run_id else _latest_run()
    if not run:
        raise HTTPException(404, f"No analysis run {run_id}.")

    filters = ["p.analysis_run_id = :run"]
    params: dict = {"run": run["id"], "limit": limit, "offset": offset}
    if tier:
        filters.append("p.risk_tier_code = :tier")
        params["tier"] = tier
    if crown_jewels_only:
        filters.append("p.target_is_crown_jewel = 1")
    if source:
        filters.append("p.source_node_id = :source")
        params["source"] = source
    if target:
        filters.append("p.target_node_id = :target")
        params["target"] = target
    if max_hops:
        filters.append("p.hop_count <= :max_hops")
        params["max_hops"] = max_hops

    where = " AND ".join(filters)
    items = fetch_all(
        f"""
        SELECT p.path_id, p.source_node_id, p.target_node_id, p.hop_count,
               p.p_success, p.neg_log_success, p.p_undetected, p.bottleneck_p,
               p.bottleneck_hop, p.impact_score, p.risk_score, p.risk_tier_code,
               p.target_is_crown_jewel, p.rank_in_run
        FROM discovered_path p
        WHERE {where}
        ORDER BY p.rank_in_run
        LIMIT :limit OFFSET :offset
        """,
        params,
    )
    total = fetch_one(f"SELECT COUNT(*) AS c FROM discovered_path p WHERE {where}", params)
    return {
        "items": [_floatify(i) for i in items],
        "total": total["c"] if total else 0,
        "analysis_run_id": run["id"],
        "graph_version_id": run["graph_version_id"],
        "scoring_version": run["scoring_version"],
    }


@router.get("/paths/{path_id}")
def path_detail(path_id: str, run_id: int | None = None) -> dict:
    run = fetch_one("SELECT * FROM analysis_run WHERE id = :i", {"i": run_id}) if run_id else _latest_run()
    if not run:
        raise HTTPException(404, f"No analysis run {run_id}.")

    path = fetch_one(
        """
        SELECT path_id, source_node_id, target_node_id, hop_count, p_success,
               neg_log_success, p_undetected, bottleneck_p, bottleneck_hop,
               impact_score, risk_score, risk_tier_code, target_is_crown_jewel, rank_in_run
        FROM discovered_path WHERE analysis_run_id = :run AND path_id = :pid
        """,
        {"run": run["id"], "pid": path_id},
    )
    if not path:
        raise HTTPException(404, f"Path {path_id} not found in run {run['id']}.")

    hops = fetch_all(
        """
        SELECT h.hop_no, h.src_node_id, h.dst_node_id, h.edge_id, h.technique_code,
               t.name AS technique_name, t.attack_id, t.attack_name, t.attack_url, t.phase,
               h.rule_id, r.code AS rule_code, r.description AS rule_description,
               h.p_succ, h.detectability, h.neg_log_contribution
        FROM path_hop h
        JOIN technique t ON t.code = h.technique_code
        JOIN rule r ON r.id = h.rule_id
        WHERE h.analysis_run_id = :run AND h.path_id = :pid
        ORDER BY h.hop_no
        """,
        {"run": run["id"], "pid": path_id},
    )

    # The factor rows are the "why this score" panel. Because the score is a sum
    # of log-odds terms, each factor's contribution is exactly its own term
    # rather than an estimate of it -- the attribution falls out of the
    # arithmetic, so nothing here is approximated for display.
    factors = fetch_all(
        """
        SELECT hop_no, seq, factor_kind, factor_code, factor_label,
               observed_value, beta, p_after
        FROM path_score_factor
        WHERE analysis_run_id = :run AND path_id = :pid
        ORDER BY hop_no, seq
        """,
        {"run": run["id"], "pid": path_id},
    )

    # The capability trace answers "why was this step possible" with the actual
    # accumulated state rather than a plausible story, and it is what the
    # narration hallucination gate checks generated text against.
    capabilities = fetch_all(
        """
        SELECT hop_no, capability_code, about_node_id, is_newly_gained
        FROM path_hop_capability
        WHERE analysis_run_id = :run AND path_id = :pid
        ORDER BY hop_no, capability_code
        """,
        {"run": run["id"], "pid": path_id},
    )

    factors_by_hop: dict[int, list[dict]] = {}
    for factor in factors:
        factors_by_hop.setdefault(factor["hop_no"], []).append(_floatify(factor))
    caps_by_hop: dict[int, list[dict]] = {}
    for cap in capabilities:
        caps_by_hop.setdefault(cap["hop_no"], []).append(cap)

    for hop in hops:
        hop.update(_floatify(hop))
        hop["factors"] = factors_by_hop.get(hop["hop_no"], [])
        hop["capabilities"] = caps_by_hop.get(hop["hop_no"], [])

    return {
        "path": _floatify(path),
        "hops": hops,
        "analysis_run_id": run["id"],
        "graph_version_id": run["graph_version_id"],
        "scoring_version": run["scoring_version"],
    }


@router.get("/paths/{path_id}/nodes")
def path_nodes(path_id: str, run_id: int | None = None) -> list[dict]:
    """Node names for a path, so the interface can label hops without N lookups."""
    run = fetch_one("SELECT * FROM analysis_run WHERE id = :i", {"i": run_id}) if run_id else _latest_run()
    return fetch_all(
        """
        SELECT DISTINCT n.node_id, n.kind_code, n.name, n.display_name,
               n.is_crown_jewel, n.criticality_code
        FROM node n
        WHERE n.graph_version_id = :gv
          AND n.node_id IN (
            SELECT src_node_id FROM path_hop WHERE analysis_run_id = :run AND path_id = :pid
            UNION
            SELECT dst_node_id FROM path_hop WHERE analysis_run_id = :run AND path_id = :pid
          )
        """,
        {"gv": run["graph_version_id"], "run": run["id"], "pid": path_id},
    )


@router.get("/rejections")
def rejections(
    reason_code: str | None = None,
    decoy_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    """Candidates the search reached and refused.

    Not diagnostics. Anything can report paths; what a tool declines to report,
    and whether it can say why, is the harder claim — and it is the one that
    separates precondition-aware search from reachability. Each row names the
    rule that could have fired, the precondition that did not hold, and the
    attribute value responsible.
    """
    run = _latest_run()
    filters = ["r.analysis_run_id = :run"]
    params: dict = {"run": run["id"], "limit": limit, "offset": offset}
    if reason_code:
        filters.append("r.reason_code = :reason")
        params["reason"] = reason_code
    if decoy_only:
        filters.append("r.decoy_code IS NOT NULL")

    where = " AND ".join(filters)
    items = fetch_all(
        f"""
        SELECT r.id, r.src_node_id, r.dst_node_id, r.edge_id, r.rule_id,
               ru.code AS rule_code, r.precondition_seq, r.reason_code,
               r.reason_text, r.observed_value, r.decoy_code, r.hop_depth
        FROM rejected_candidate r
        JOIN rule ru ON ru.id = r.rule_id
        WHERE {where}
        ORDER BY r.hop_depth, r.id
        LIMIT :limit OFFSET :offset
        """,
        params,
    )
    total = fetch_one(f"SELECT COUNT(*) AS c FROM rejected_candidate r WHERE {where}", params)
    by_reason = fetch_all(
        """
        SELECT reason_code, COUNT(*) AS count, MIN(reason_text) AS example
        FROM rejected_candidate WHERE analysis_run_id = :run
        GROUP BY reason_code ORDER BY count DESC
        """,
        {"run": run["id"]},
    )
    return {
        "items": items,
        "total": total["c"] if total else 0,
        "by_reason": by_reason,
        "analysis_run_id": run["id"],
    }


@router.get("/chokepoints")
def chokepoints(limit: int = Query(20, ge=1, le=100)) -> dict:
    """Ranked cut candidates.

    Computed as a greedy set cover over path coverage, not as betweenness
    centrality — betweenness answers which node is topologically central, which
    is a different question from what to fix first.

    ``optimality_bound`` is served alongside each row because path coverage is
    submodular, so greedy carries a (1 - 1/e) approximation guarantee. Stating
    the gap is more honest than implying the selection is optimal, and a
    reviewer who knows the result will ask.
    """
    run = _latest_run()
    items = fetch_all(
        """
        SELECT rank_in_run, kind, target_id, paths_covered, coverage_fraction,
               cumulative_fraction, optimality_bound
        FROM chokepoint WHERE analysis_run_id = :run
        ORDER BY rank_in_run LIMIT :limit
        """,
        {"run": run["id"], "limit": limit},
    )
    return {
        "items": [_floatify(i) for i in items],
        "analysis_run_id": run["id"],
        "total_paths": run["path_count"],
    }


@router.get("/risk/summary")
def risk_summary() -> dict:
    run = _latest_run()
    by_tier = fetch_all(
        """
        SELECT t.code, t.label, t.ui_color, t.sort_order,
               COALESCE(COUNT(p.path_id), 0) AS count
        FROM risk_tier t
        JOIN scoring_config c ON c.version = t.scoring_version AND c.is_active = 1
        LEFT JOIN discovered_path p
          ON p.risk_tier_code = t.code AND p.analysis_run_id = :run
        GROUP BY t.code, t.label, t.ui_color, t.sort_order
        ORDER BY t.sort_order
        """,
        {"run": run["id"]},
    )
    crown = fetch_all(
        """
        SELECT p.target_node_id, n.name, COUNT(*) AS path_count,
               MAX(p.risk_score) AS max_risk
        FROM discovered_path p
        JOIN node n ON n.node_id = p.target_node_id AND n.graph_version_id = :gv
        WHERE p.analysis_run_id = :run AND p.target_is_crown_jewel = 1
        GROUP BY p.target_node_id, n.name
        ORDER BY max_risk DESC
        """,
        {"run": run["id"], "gv": run["graph_version_id"]},
    )
    return {
        "analysis_run_id": run["id"],
        "graph_version_id": run["graph_version_id"],
        "scoring_version": run["scoring_version"],
        "threat_model": run["threat_model_code"],
        "total_paths": run["path_count"],
        "rejected_count": run["rejected_count"],
        "max_risk": float(run["max_risk_score"]) if run["max_risk_score"] is not None else None,
        "crown_jewels_reached": run["crown_jewels_reached"],
        "discovery_ms": run["duration_ms"],
        "by_tier": by_tier,
        "crown_jewel_exposure": [_floatify(c) for c in crown],
    }


@router.get("/risk/top")
def top_risks(n: int = Query(5, ge=1, le=50)) -> list[dict]:
    run = _latest_run()
    return [
        _floatify(r)
        for r in fetch_all(
            """
            SELECT p.path_id, p.source_node_id, sn.name AS source_name,
                   p.target_node_id, tn.name AS target_name, p.hop_count,
                   p.p_success, p.risk_score, p.risk_tier_code, p.target_is_crown_jewel
            FROM discovered_path p
            LEFT JOIN node sn ON sn.node_id = p.source_node_id AND sn.graph_version_id = :gv
            LEFT JOIN node tn ON tn.node_id = p.target_node_id AND tn.graph_version_id = :gv
            WHERE p.analysis_run_id = :run
            ORDER BY p.rank_in_run LIMIT :n
            """,
            {"run": run["id"], "gv": run["graph_version_id"], "n": n},
        )
    ]


def _floatify(row: dict) -> dict:
    """Convert DECIMAL columns to float for JSON.

    MySQL DECIMAL arrives as Decimal, which is not JSON-serialisable. Converting
    at the boundary keeps the precision decision in one place: the database
    stores exact values, and only the transport rounds.
    """
    from decimal import Decimal

    return {k: (float(v) if isinstance(v, Decimal) else v) for k, v in row.items()}
