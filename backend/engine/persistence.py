"""Writing a discovery run to MySQL.

One transaction for the whole run. A half-written run is worse than no run at
all: the endpoints read ``analysis_run`` first and then join to its children, so
a run row whose paths never landed renders as an empty result with no
explanation. Either everything is visible or nothing is.

Rounding happens here and only here, at the width of the column being written.
The engine works in float64 and the database stores fixed-point, so this is the
one place the two representations meet — and the ordering column
``neg_log_success`` is stored alongside the probability rather than re-derived
from it, because re-deriving from a rounded probability reorders ties.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import text

from core.model import AttackPath, Capability, Rejection
from engine.search import DiscoveryResult, SearchLimits

#: Smallest probability a DECIMAL(12,11) column can hold. A long chain can
#: underflow the column while remaining a genuine path, and storing 0 would
#: report it as impossible — invariant 6 says every path probability is strictly
#: positive, so the floor is applied rather than the value truncated.
_MIN_STORED_P = 1e-11


@dataclass(frozen=True, slots=True)
class RunMetadata:
    graph_version_id: int
    scoring_version: str
    threat_model_code: str
    purpose: str = "baseline"
    baseline_run_id: int | None = None


def persist_run(
    metadata: RunMetadata,
    limits: SearchLimits,
    result: DiscoveryResult,
    *,
    duration_ms: int,
    started_at: datetime | None = None,
) -> int:
    """Write one run and everything it produced. Returns the run id."""
    from app.db import mysql_engine

    started = started_at or datetime.now(timezone.utc)
    finished = datetime.now(timezone.utc)
    crown_jewels = len({p.target_node_id for p in result.paths if p.target_is_crown_jewel})
    max_risk = max((p.risk_score for p in result.paths), default=None)

    with mysql_engine().begin() as conn:
        run_id = int(
            conn.execute(
                text(
                    """
                    INSERT INTO analysis_run
                      (graph_version_id, scoring_version, threat_model_code, purpose,
                       baseline_run_id, max_hops, top_k_per_pair, path_count,
                       rejected_count, crown_jewels_reached, max_risk_score,
                       duration_ms, status, started_at, finished_at)
                    VALUES
                      (:gv, :sv, :tm, :purpose, :baseline, :max_hops, :top_k, :paths,
                       :rejected, :crown, :max_risk, :duration, 'complete', :started,
                       :finished)
                    """
                ),
                {
                    "gv": metadata.graph_version_id,
                    "sv": metadata.scoring_version,
                    "tm": metadata.threat_model_code,
                    "purpose": metadata.purpose,
                    "baseline": metadata.baseline_run_id,
                    "max_hops": limits.max_hops,
                    "top_k": limits.top_k,
                    "paths": len(result.paths),
                    "rejected": len(result.rejections),
                    "crown": crown_jewels,
                    "max_risk": None if max_risk is None else round(max_risk, 2),
                    "duration": duration_ms,
                    "started": started.replace(tzinfo=None),
                    "finished": finished.replace(tzinfo=None),
                },
            ).lastrowid
        )

        _insert(
            conn,
            """
            INSERT INTO discovered_path
              (path_id, analysis_run_id, source_node_id, target_node_id, hop_count,
               p_success, neg_log_success, p_undetected, bottleneck_p, bottleneck_hop,
               impact_score, risk_score, risk_tier_code, target_is_crown_jewel,
               rank_in_run)
            VALUES
              (:path_id, :run, :source, :target, :hops, :p_success, :neg_log,
               :p_undetected, :bottleneck_p, :bottleneck_hop, :impact, :risk, :tier,
               :crown, :rank)
            """,
            list(_path_rows(run_id, result.paths)),
        )
        _insert(
            conn,
            """
            INSERT INTO path_hop
              (analysis_run_id, path_id, hop_no, src_node_id, dst_node_id, edge_id,
               technique_code, rule_id, p_succ, detectability, neg_log_contribution)
            VALUES
              (:run, :path_id, :hop_no, :src, :dst, :edge, :technique, :rule,
               :p_succ, :detectability, :neg_log)
            """,
            list(_hop_rows(run_id, result.paths)),
        )
        _insert(
            conn,
            """
            INSERT INTO path_hop_capability
              (analysis_run_id, path_id, hop_no, capability_code, about_node_id,
               is_newly_gained)
            VALUES (:run, :path_id, :hop_no, :code, :about, :gained)
            """,
            list(_capability_rows(run_id, result)),
        )
        _insert(
            conn,
            """
            INSERT INTO path_score_factor
              (analysis_run_id, path_id, hop_no, seq, factor_kind, factor_code,
               factor_label, observed_value, beta, p_after)
            VALUES
              (:run, :path_id, :hop_no, :seq, :kind, :code, :label, :observed,
               :beta, :p_after)
            """,
            list(_factor_rows(run_id, result.paths)),
        )
        _insert(
            conn,
            """
            INSERT INTO rejected_candidate
              (analysis_run_id, signature, src_node_id, dst_node_id, edge_id, rule_id,
               precondition_seq, reason_code, reason_text, observed_value, hop_depth)
            VALUES
              (:run, :signature, :src, :dst, :edge, :rule, :seq, :reason_code,
               :reason_text, :observed, :depth)
            """,
            list(_rejection_rows(run_id, result.rejections)),
        )

    return run_id


def _insert(conn: Any, sql: str, rows: Sequence[dict[str, Any]]) -> None:
    if rows:
        conn.execute(text(sql), rows)


def _path_rows(run_id: int, paths: Sequence[AttackPath]) -> Iterable[dict[str, Any]]:
    for rank, path in enumerate(paths, start=1):
        yield {
            "path_id": path.path_id,
            "run": run_id,
            "source": path.source_node_id,
            "target": path.target_node_id,
            "hops": path.hop_count,
            "p_success": _probability(path.p_success),
            "neg_log": round(path.neg_log_success, 6),
            "p_undetected": _probability(path.p_undetected),
            "bottleneck_p": _probability(path.bottleneck_p),
            "bottleneck_hop": path.bottleneck_hop,
            "impact": round(path.impact_score, 4),
            "risk": round(path.risk_score, 2),
            "tier": path.risk_tier_code,
            "crown": 1 if path.target_is_crown_jewel else 0,
            "rank": rank,
        }


def _hop_rows(run_id: int, paths: Sequence[AttackPath]) -> Iterable[dict[str, Any]]:
    for path in paths:
        for hop in path.hops:
            yield {
                "run": run_id,
                "path_id": path.path_id,
                "hop_no": hop.hop_no,
                "src": hop.src_node_id,
                "dst": hop.dst_node_id,
                "edge": hop.edge_id,
                "technique": hop.technique_code,
                "rule": hop.rule_id,
                "p_succ": _probability(hop.p_succ),
                "detectability": _probability(hop.detectability),
                "neg_log": round(hop.neg_log_contribution, 6),
            }


def _capability_rows(run_id: int, result: DiscoveryResult) -> Iterable[dict[str, Any]]:
    """The state after each hop: what was just gained, and what was already held.

    Written in full per hop rather than as a delta, because this is the proof
    trace the interface answers "why was this step possible" from, and the
    narration gate checks generated text against. A delta would make both of
    them reconstruct the state, and a reconstruction is a second implementation
    of the search's bookkeeping.
    """
    for path in result.paths:
        held: set[Capability] = set(result.initial_capabilities.get(path.path_id, ()))
        for hop in path.hops:
            gained = set(hop.gained) - held
            held |= gained
            for capability in sorted(
                held, key=lambda c: (c.code, c.about or "")
            ):
                yield {
                    "run": run_id,
                    "path_id": path.path_id,
                    "hop_no": hop.hop_no,
                    "code": capability.code,
                    "about": capability.about or "",
                    "gained": 1 if capability in gained else 0,
                }


def _factor_rows(run_id: int, paths: Sequence[AttackPath]) -> Iterable[dict[str, Any]]:
    for path in paths:
        for hop in path.hops:
            for factor in hop.factors:
                yield {
                    "run": run_id,
                    "path_id": path.path_id,
                    "hop_no": hop.hop_no,
                    "seq": factor.seq,
                    "kind": factor.factor_kind,
                    "code": factor.factor_code[:64],
                    "label": factor.factor_label[:128],
                    "observed": _truncate(factor.observed_value, 255),
                    "beta": None if factor.beta is None else round(factor.beta, 4),
                    "p_after": _probability(factor.p_after),
                }


def _rejection_rows(
    run_id: int, rejections: Sequence[Rejection]
) -> Iterable[dict[str, Any]]:
    for rejection in rejections:
        yield {
            "run": run_id,
            "signature": rejection.signature,
            "src": rejection.src_node_id,
            "dst": rejection.dst_node_id,
            "edge": rejection.edge_id,
            "rule": rejection.rule_id,
            "seq": rejection.precondition_seq,
            "reason_code": rejection.reason_code[:64],
            "reason_text": rejection.reason_text[:512],
            "observed": _truncate(rejection.observed_value, 255),
            "depth": rejection.hop_depth,
        }


def _probability(value: float) -> float:
    if not math.isfinite(value):
        raise ValueError(f"probability {value!r} is not finite")
    return max(round(min(max(value, 0.0), 1.0), 11), _MIN_STORED_P)


def _truncate(value: str | None, width: int) -> str | None:
    return None if value is None else value[:width]
