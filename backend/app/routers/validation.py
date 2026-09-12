"""Validation endpoints: the three ways this product's correctness is checked.

``docs/SCOPE.md`` D9 calls the Validation screen the demo weapon, on the grounds
that every other tool in this space *asserts* correctness and the point here is
to *measure* it. Three measurements, and they catch different faults, which is
why they are three endpoints rather than one number:

``/differential`` runs the fast engine and the exhaustive reference oracle over
the same graphs and reports every path exactly one of them found. It catches the
two implementations disagreeing about what the rules mean.

``/metrics`` scores a completed discovery run against the generator's manifest.
It catches the engine being wrong about the world -- missed plants, walked
decoys, a ranking that buries the dangerous paths, a probability that does not
happen as often as it claims.

``/invariants`` runs the property suite over ``docs/RULES.md`` §7. It catches the
engine contradicting itself, which neither of the other two can see: an engine
consistently wrong in the same way agrees with nothing and still passes a
differential.

None of these is cheap, and none of them is faked when it cannot run. Every
endpoint that depends on a completed run or a manifest says so with a 404
naming the command that would produce one, rather than returning zeroes that
render as a perfect score.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.db import fetch_all, fetch_one
from engine.snapshot import load_snapshot
from validation import differential, invariants, metrics

router = APIRouter(prefix="/api/validation", tags=["validation"])

#: Bound on the seeded-graph differential case. The reference oracle prunes
#: nothing, so its cost grows the way an unpruned depth-first search does:
#: measured on the active graph, ninety nodes at four hops is around a second
#: and a hundred and twenty is around half a minute. Ninety is therefore the
#: default a request can wait for, and the ceiling exists so a caller cannot ask
#: for something that will time out in front of them.
DEFAULT_SEEDED_NODE_CAP = 90
MAX_SEEDED_NODE_CAP = 140

#: The property suite's answer depends only on the rule and scoring rows, not on
#: the graph, so it is the same for every caller until those rows change. It
#: takes a few seconds, which is too long to repeat on every page load and far
#: too short to be worth a background job.
_suite_cache: dict[str, Any] = {}


# ── Differential testing ─────────────────────────────────────────────────────


@router.get("/differential")
def differential_report(
    include_seeded_graph: bool = Query(
        False,
        description=(
            "Also run the bounded neighbourhood of the real generated graph. Costs "
            "roughly a second; the hand-built worlds alone cost tens of milliseconds."
        ),
    ),
    node_cap: int = Query(DEFAULT_SEEDED_NODE_CAP, ge=10, le=MAX_SEEDED_NODE_CAP),
    max_hops: int = Query(differential.DEFAULT_REAL_GRAPH_HOPS, ge=1, le=6),
) -> dict:
    """Run both implementations over the same graphs and report what they made of them."""
    real_graph = None
    seeds: list[str] = []
    threat_model: str | None = None

    if include_seeded_graph:
        run = _latest_baseline_run()
        if run is None:
            raise HTTPException(
                404,
                "No completed discovery run for the active graph, so there is no "
                "graph version to run the seeded-graph comparison against. Run: "
                "python -m engine.discover --threat-model external_phish",
            )
        graph_version = int(run["graph_version_id"])
        real_graph = load_snapshot(graph_version)
        threat_model = str(run["threat_model_code"])
        # Crown jewels first, then the planted entry points: the neighbourhood is
        # grown breadth-first from the seeds in order, so this keeps the material
        # the ground truth is actually about when the cap bites.
        seeds = sorted(real_graph.crown_jewels) + [
            str(row["entry_node_id"])
            for row in fetch_all(
                "SELECT entry_node_id FROM plant_log WHERE graph_version_id = :gv ORDER BY id",
                {"gv": graph_version},
            )
        ]

    report = differential.run_report(
        real_graph=real_graph,
        real_graph_seeds=seeds,
        real_graph_threat_model=threat_model,
        node_cap=node_cap,
        max_hops=max_hops,
    )
    return {
        "model_origin": report.model_origin,
        "model_detail": report.model_detail,
        "duration_ms": report.duration_ms,
        "cases_total": len(report.cases),
        "cases_agreeing": report.cases_agreeing,
        "agreed_total": report.agreed_total,
        "comparable_total": report.comparable_total,
        "agreement_rate": report.agreement_rate,
        "disagreement_count": report.disagreement_count,
        "seeded_graph_case": report.real_graph_case,
        "seeded_graph_bound": report.real_graph_bound,
        "cases": [_case(case) for case in report.cases],
    }


def _case(case: differential.CaseReport) -> dict:
    return {
        "code": case.code,
        "title": case.title,
        "mechanism": case.mechanism,
        "threat_model_code": case.threat_model_code,
        "node_count": case.node_count,
        "edge_count": case.edge_count,
        "max_hops": case.max_hops,
        "engine_path_count": case.engine_path_count,
        "reference_path_count": case.reference_path_count,
        "reference_comparable_count": case.reference_comparable_count,
        "agreed_count": case.agreed_count,
        "label_only_count": case.label_only_count,
        "engine_ms": case.engine_ms,
        "reference_ms": case.reference_ms,
        "reference_states_expanded": case.reference_states_expanded,
        "engine_truncated": case.engine_truncated,
        "error": case.error,
        "agrees": case.agrees,
        "engine_only": [_disagreement(d) for d in case.engine_only],
        "reference_only": [_disagreement(d) for d in case.reference_only],
    }


def _disagreement(item: differential.Disagreement) -> dict:
    return {
        "found_by": item.found_by,
        "target_node_id": item.target_node_id,
        "hop_count": item.hop_count,
        "steps": list(item.steps),
    }


# ── Accuracy against the manifest ────────────────────────────────────────────


@router.get("/metrics")
def metrics_report(
    run: int | None = Query(
        None, ge=1, description="Score this analysis run instead of the latest baseline."
    ),
) -> dict:
    """Precision, recall, ranking and calibration against the generator's ground truth."""
    try:
        report = metrics.load_report(run)
    except metrics.MetricsUnavailable as exc:
        raise HTTPException(404, str(exc)) from exc

    return {
        "analysis_run_id": report.analysis_run_id,
        "graph_version_id": report.graph_version_id,
        "threat_model_code": report.threat_model_code,
        "scoring_version": report.scoring_version,
        "seed": report.seed,
        "generator_version": report.generator_version,
        "paths_reported": report.paths_reported,
        "duration_ms": report.duration_ms,
        "levels": [_level(level) for level in report.levels],
        "ranking": {
            "paths_ranked": report.ranking.paths_ranked,
            "paths_unscoreable": report.ranking.paths_unscoreable,
            "concordant": report.ranking.concordant,
            "discordant": report.ranking.discordant,
            "kendall_tau": report.ranking.kendall_tau,
            "ndcg_at_k": report.ranking.ndcg_at_k,
            "k": report.ranking.k,
        },
        "calibration": {
            "samples": report.calibration.samples,
            "hops_unscoreable": report.calibration.hops_unscoreable,
            "expected_calibration_error": report.calibration.expected_calibration_error,
            "brier_score": report.calibration.brier_score,
            "bins": [
                {
                    "lower": b.lower,
                    "upper": b.upper,
                    "count": b.count,
                    "mean_predicted": b.mean_predicted,
                    "mean_true": b.mean_true,
                }
                for b in report.calibration.bins
            ],
        },
        # Labels, interpretations and formats come from `metric_definition`
        # rather than being spelled out in the frontend, for the reason
        # ``docs/SCOPE.md`` D12 gives: a metric's meaning is data, and a metric
        # a viewer cannot interpret is decoration.
        "definitions": fetch_all(
            "SELECT code, label, description, interpretation, family, "
            "higher_is_better, format, sort_order FROM metric_definition ORDER BY sort_order"
        ),
    }


def _level(level: metrics.LevelScore) -> dict:
    return {
        "match_level": level.match_level,
        "precision": level.precision,
        "recall": level.recall,
        "f1": level.f1,
        "decoy_rejection": level.decoy_rejection,
        "twin_acceptance": level.twin_acceptance,
        "reported_findings": level.reported_findings,
        "unlabelled_findings": level.unlabelled_findings,
        "true_positives": level.true_positives,
        "false_positives": level.false_positives,
        "true_negatives": level.true_negatives,
        "false_negatives": level.false_negatives,
        "not_evaluated": level.not_evaluated,
        "scenarios_recovered": level.scenarios_recovered,
        "scenarios_total": level.scenarios_total,
        "decoy_counts": level.kind_counts("decoy"),
        "twin_counts": level.kind_counts("twin"),
        "cases": [
            {
                "kind": case.kind,
                "reference_code": case.reference_code,
                "outcome": case.outcome,
                "matched_path_id": case.matched_path_id,
                "detail": case.detail,
            }
            for case in level.cases
        ],
    }


# ── The property suite ───────────────────────────────────────────────────────


@router.get("/invariants")
def invariants_report(
    refresh: bool = Query(
        False, description="Re-run the suite rather than returning the cached result."
    ),
) -> dict:
    """Run ``docs/RULES.md`` §7 as a property suite and report every invariant's verdict."""
    cached = _suite_cache.get("report")
    if cached is None or refresh:
        started = time.perf_counter()
        report = invariants.run_suite()
        cached = {
            "passing": report.passing,
            "failing": report.failing,
            "total": len(report.outcomes),
            "total_cases": report.total_cases,
            "duration_ms": report.duration_ms,
            "model_origin": report.model_origin,
            "model_detail": report.model_detail,
            "graph_nodes": report.graph_nodes,
            "graph_edges": report.graph_edges,
            "max_hops": report.max_hops,
            "threat_model_code": report.threat_model_code,
            "perturbations": list(report.perturbations),
            "outcomes": [
                {
                    "number": outcome.number,
                    "code": outcome.code,
                    "statement": outcome.statement,
                    "method": outcome.method,
                    "status": outcome.status,
                    "cases_checked": outcome.cases_checked,
                    "failures": list(outcome.failures),
                    "duration_ms": outcome.duration_ms,
                }
                for outcome in report.outcomes
            ],
            "ran_at_ms": int(time.perf_counter() - started),
            "from_cache": False,
        }
        _suite_cache["report"] = cached
        return cached
    return {**cached, "from_cache": True}


def _latest_baseline_run() -> dict | None:
    return fetch_one(
        """
        SELECT r.id, r.graph_version_id, r.scoring_version, r.threat_model_code
        FROM analysis_run r
        JOIN graph_version g ON g.id = r.graph_version_id AND g.is_active = 1
        WHERE r.purpose = 'baseline' AND r.status = 'complete'
        ORDER BY r.id DESC LIMIT 1
        """
    )
