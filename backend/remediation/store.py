"""MySQL reads and writes for the remediation tables.

Kept apart from the algorithms so that set cover, the max-flow cut and the
priority formula are all pure functions over plain values and can be tested
without either store running — the same reason ``engine.rules.build_ruleset``
takes rows rather than reading them itself.

Rounding happens here, at the width of the column being written, for the same
reason ``engine.persistence`` does it: the algorithms work in float64 and the
database stores fixed point, and this is the one place the two meet.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable, Mapping, Sequence

from sqlalchemy import text

from remediation.chokepoints import Chokepoint, PathCoverage
from remediation.overlay import Mutation


class RemediationDataError(RuntimeError):
    """Data the remediation layer needs is absent or inconsistent."""


# ── Fix catalogue ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FixType:
    """One row of ``fix_type``.

    Effort and disruption are read, never computed. They are organisational
    facts — how expensive a manual change is depends on the team — and the seed
    file says so explicitly, so the ranking formula consumes them as inputs.
    """

    code: str
    label: str
    description: str
    mutation_kind: str
    mutation_target_attr: str | None
    mutation_value: Any
    effort_value: float
    effort_label: str
    disruption_value: float
    disruption_label: str
    requires_approval: bool
    d3fend_id: str | None
    sort_order: int

    def mutation_for(self, target_kind: str, target_id: str) -> Mutation:
        return Mutation(
            kind=self.mutation_kind,
            target_kind=target_kind,
            target_id=target_id,
            attr=self.mutation_target_attr,
            value=self.mutation_value,
        )


def load_fix_types() -> dict[str, FixType]:
    from app.db import fetch_all
    from engine.rules import decode_json

    rows = fetch_all(
        """
        SELECT code, label, description, mutation_kind, mutation_target_attr,
               mutation_value, effort_value, effort_label, disruption_value,
               disruption_label, requires_approval, d3fend_id, sort_order
        FROM fix_type ORDER BY sort_order
        """
    )
    if not rows:
        raise RemediationDataError(
            "fix_type is empty; run the seed files under backend/db/seed"
        )
    return {
        str(row["code"]): FixType(
            code=str(row["code"]),
            label=str(row["label"]),
            description=str(row["description"]),
            mutation_kind=str(row["mutation_kind"]),
            mutation_target_attr=row["mutation_target_attr"] or None,
            mutation_value=decode_json(row["mutation_value"]),
            effort_value=float(row["effort_value"]),
            effort_label=str(row["effort_label"]),
            disruption_value=float(row["disruption_value"]),
            disruption_label=str(row["disruption_label"]),
            requires_approval=bool(int(row["requires_approval"])),
            d3fend_id=row["d3fend_id"] or None,
            sort_order=int(row["sort_order"]),
        )
        for row in rows
    }


# ── Runs and paths ───────────────────────────────────────────────────────────


def latest_run(purpose: str = "baseline", graph_version: int | None = None) -> dict | None:
    """The newest complete run, by default against the active graph version."""
    from app.db import fetch_one

    if graph_version is None:
        return fetch_one(
            """
            SELECT r.* FROM analysis_run r
            JOIN graph_version g ON g.id = r.graph_version_id AND g.is_active = 1
            WHERE r.purpose = :p AND r.status = 'complete'
            ORDER BY r.id DESC LIMIT 1
            """,
            {"p": purpose},
        )
    return fetch_one(
        """
        SELECT * FROM analysis_run
        WHERE purpose = :p AND status = 'complete' AND graph_version_id = :gv
        ORDER BY id DESC LIMIT 1
        """,
        {"p": purpose, "gv": graph_version},
    )


def load_run(run_id: int) -> dict | None:
    from app.db import fetch_one

    return fetch_one("SELECT * FROM analysis_run WHERE id = :i", {"i": run_id})


def load_path_coverage(run_id: int) -> list[PathCoverage]:
    """Every path of one run, as the hop list set cover and the cut need it."""
    from app.db import fetch_all

    paths = fetch_all(
        """
        SELECT path_id, source_node_id, target_node_id, risk_score
        FROM discovered_path WHERE analysis_run_id = :r ORDER BY rank_in_run
        """,
        {"r": run_id},
    )
    hops: dict[str, list[tuple[str, str, str | None]]] = {}
    for row in fetch_all(
        """
        SELECT path_id, hop_no, src_node_id, dst_node_id, edge_id
        FROM path_hop WHERE analysis_run_id = :r ORDER BY path_id, hop_no
        """,
        {"r": run_id},
    ):
        hops.setdefault(str(row["path_id"]), []).append(
            (str(row["src_node_id"]), str(row["dst_node_id"]), row["edge_id"] or None)
        )
    return [
        PathCoverage(
            path_id=str(row["path_id"]),
            source_node_id=str(row["source_node_id"]),
            target_node_id=str(row["target_node_id"]),
            hops=tuple(hops.get(str(row["path_id"]), ())),
            risk_score=float(row["risk_score"]),
        )
        for row in paths
    ]


def load_path_risks(run_id: int) -> dict[str, float]:
    from app.db import fetch_all

    return {
        str(row["path_id"]): float(row["risk_score"])
        for row in fetch_all(
            "SELECT path_id, risk_score FROM discovered_path WHERE analysis_run_id = :r",
            {"r": run_id},
        )
    }


def crown_jewels_reached(run_id: int) -> int:
    from app.db import fetch_scalar

    return int(
        fetch_scalar(
            "SELECT COUNT(DISTINCT target_node_id) FROM discovered_path "
            "WHERE analysis_run_id = :r AND target_is_crown_jewel = 1",
            {"r": run_id},
        )
        or 0
    )


# ── Chokepoints ──────────────────────────────────────────────────────────────


def replace_chokepoints(run_id: int, chokepoints: Sequence[Chokepoint]) -> None:
    """Rewrite one run's chokepoint ranking.

    Replaced wholesale rather than appended: a ranking is only meaningful as a
    complete ordering, and a half-refreshed one would interleave two different
    selections under one set of rank numbers.
    """
    from app.db import mysql_engine

    with mysql_engine().begin() as conn:
        conn.execute(
            text("DELETE FROM chokepoint WHERE analysis_run_id = :r"), {"r": run_id}
        )
        if not chokepoints:
            return
        conn.execute(
            text(
                """
                INSERT INTO chokepoint
                  (analysis_run_id, rank_in_run, kind, target_id, paths_covered,
                   coverage_fraction, cumulative_fraction, optimality_bound)
                VALUES
                  (:run, :rank, :kind, :target, :covered, :coverage, :cumulative, :bound)
                """
            ),
            [
                {
                    "run": run_id,
                    "rank": c.rank_in_run,
                    "kind": c.kind,
                    "target": c.target_id,
                    "covered": c.paths_covered,
                    "coverage": round(c.coverage_fraction, 5),
                    "cumulative": round(c.cumulative_fraction, 5),
                    "bound": round(c.optimality_bound, 5),
                }
                for c in chokepoints
            ],
        )


def load_chokepoints(run_id: int, limit: int = 20) -> list[dict]:
    from app.db import fetch_all

    return fetch_all(
        """
        SELECT rank_in_run, kind, target_id, paths_covered, coverage_fraction,
               cumulative_fraction, optimality_bound
        FROM chokepoint WHERE analysis_run_id = :r
        ORDER BY rank_in_run LIMIT :limit
        """,
        {"r": run_id, "limit": limit},
    )


# ── Recommendations ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RecommendationRow:
    """A recommendation as it is written, before it has an id."""

    fix_type_code: str
    target_kind: str
    target_id: str
    title: str
    rationale: str
    risk_before: float
    risk_after: float | None
    paths_eliminated: int | None
    total_paths: int
    path_coverage: float | None
    effort_value: float
    disruption_value: float
    priority_score: float | None
    is_measured: bool
    dependencies: tuple["DependencyRow", ...] = ()


@dataclass(frozen=True, slots=True)
class DependencyRow:
    kind: str
    affected_node_id: str | None
    description: str
    severity: str


def replace_recommendations(
    run_id: int,
    rows: Sequence[RecommendationRow],
    *,
    initial_state: str,
) -> list[int]:
    """Rewrite one run's recommendations, returning the new ids in order.

    Rows already past ``recommended`` are left alone: a recommendation that has
    been simulated, approved or applied has results and an audit trail hanging
    off it, and regenerating the ranking must not delete the record of something
    somebody did.
    """
    from app.db import mysql_engine

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ids: list[int] = []
    with mysql_engine().begin() as conn:
        conn.execute(
            text(
                "DELETE FROM recommendation "
                "WHERE analysis_run_id = :r AND state_code = :s"
            ),
            {"r": run_id, "s": initial_state},
        )
        existing = {
            (str(row.fix_type_code), str(row.target_id))
            for row in conn.execute(
                text(
                    "SELECT fix_type_code, target_id FROM recommendation "
                    "WHERE analysis_run_id = :r"
                ),
                {"r": run_id},
            ).mappings()
        }
        for row in rows:
            if (row.fix_type_code, row.target_id) in existing:
                continue
            result = conn.execute(
                text(
                    """
                    INSERT INTO recommendation
                      (analysis_run_id, fix_type_code, target_kind, target_id, title,
                       rationale, risk_before, risk_after, paths_eliminated,
                       total_paths, path_coverage, effort_value, disruption_value,
                       priority_score, is_measured, state_code, created_at)
                    VALUES
                      (:run, :fix, :target_kind, :target_id, :title, :rationale,
                       :risk_before, :risk_after, :eliminated, :total, :coverage,
                       :effort, :disruption, :priority, :measured, :state, :now)
                    """
                ),
                {
                    "run": run_id,
                    "fix": row.fix_type_code,
                    "target_kind": row.target_kind,
                    "target_id": row.target_id,
                    "title": row.title[:255],
                    "rationale": row.rationale,
                    "risk_before": round(row.risk_before, 2),
                    "risk_after": None if row.risk_after is None else round(row.risk_after, 2),
                    "eliminated": row.paths_eliminated,
                    "total": row.total_paths,
                    "coverage": None if row.path_coverage is None else round(row.path_coverage, 5),
                    "effort": round(row.effort_value, 3),
                    "disruption": round(row.disruption_value, 3),
                    "priority": None if row.priority_score is None else round(row.priority_score, 4),
                    "measured": 1 if row.is_measured else 0,
                    "state": initial_state,
                    "now": now,
                },
            )
            recommendation_id = int(result.lastrowid)
            ids.append(recommendation_id)
            if row.dependencies:
                conn.execute(
                    text(
                        """
                        INSERT INTO recommendation_dependency
                          (recommendation_id, seq, kind, affected_node_id,
                           description, severity)
                        VALUES (:rec, :seq, :kind, :node, :description, :severity)
                        """
                    ),
                    [
                        {
                            "rec": recommendation_id,
                            "seq": seq,
                            "kind": dependency.kind,
                            "node": dependency.affected_node_id,
                            "description": dependency.description[:512],
                            "severity": dependency.severity,
                        }
                        for seq, dependency in enumerate(row.dependencies, start=1)
                    ],
                )
    return ids


def load_recommendations(run_id: int, limit: int = 100) -> list[dict]:
    from app.db import fetch_all

    return fetch_all(
        """
        SELECT r.id, r.analysis_run_id, r.fix_type_code, f.label AS fix_label,
               f.description AS fix_description, f.mutation_kind,
               f.mutation_target_attr, f.effort_label, f.disruption_label,
               f.requires_approval, f.d3fend_id,
               r.target_kind, r.target_id, r.title, r.rationale, r.risk_before,
               r.risk_after, r.paths_eliminated, r.total_paths, r.path_coverage,
               r.effort_value, r.disruption_value, r.priority_score, r.is_measured,
               r.state_code, s.label AS state_label, s.ui_color AS state_color,
               s.is_terminal, r.created_at,
               (SELECT COUNT(*) FROM recommendation_dependency d
                 WHERE d.recommendation_id = r.id) AS dependency_count,
               (SELECT MAX(sim.id) FROM simulation sim
                 WHERE sim.recommendation_id = r.id) AS simulation_id
        FROM recommendation r
        JOIN fix_type f ON f.code = r.fix_type_code
        JOIN remediation_state s ON s.code = r.state_code
        WHERE r.analysis_run_id = :r
        ORDER BY r.priority_score DESC, r.id
        LIMIT :limit
        """,
        {"r": run_id, "limit": limit},
    )


def load_recommendation(recommendation_id: int) -> dict | None:
    from app.db import fetch_one

    return fetch_one(
        """
        SELECT r.*, f.label AS fix_label, f.description AS fix_description,
               f.mutation_kind, f.mutation_target_attr, f.mutation_value,
               f.effort_label, f.disruption_label, f.requires_approval,
               f.d3fend_id, s.label AS state_label, s.ui_color AS state_color,
               s.is_terminal, a.graph_version_id, a.threat_model_code,
               a.scoring_version, a.max_hops, a.top_k_per_pair
        FROM recommendation r
        JOIN fix_type f ON f.code = r.fix_type_code
        JOIN remediation_state s ON s.code = r.state_code
        JOIN analysis_run a ON a.id = r.analysis_run_id
        WHERE r.id = :i
        """,
        {"i": recommendation_id},
    )


def load_dependencies(recommendation_id: int) -> list[dict]:
    from app.db import fetch_all

    return fetch_all(
        """
        SELECT seq, kind, affected_node_id, description, severity
        FROM recommendation_dependency
        WHERE recommendation_id = :i ORDER BY seq
        """,
        {"i": recommendation_id},
    )


def set_recommendation_state(recommendation_id: int, state_code: str) -> None:
    from app.db import execute

    execute(
        "UPDATE recommendation SET state_code = :s WHERE id = :i",
        {"s": state_code, "i": recommendation_id},
    )


def record_measurement(
    recommendation_id: int,
    *,
    risk_after: float,
    paths_eliminated: int,
    path_coverage: float,
    priority_score: float,
) -> None:
    """Replace a recommendation's estimates with what a simulation measured.

    ``is_measured`` flips here and nowhere else, which is what keeps the
    interface from ever presenting an estimate as a measurement.
    """
    from app.db import execute

    execute(
        """
        UPDATE recommendation
        SET risk_after = :risk_after, paths_eliminated = :eliminated,
            path_coverage = :coverage, priority_score = :priority, is_measured = 1
        WHERE id = :i
        """,
        {
            "risk_after": round(risk_after, 2),
            "eliminated": paths_eliminated,
            "coverage": round(path_coverage, 5),
            "priority": round(priority_score, 4),
            "i": recommendation_id,
        },
    )


# ── Simulations ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PathDelta:
    path_id: str
    change_kind: str
    risk_before: float | None
    risk_after: float | None


def insert_simulation(
    *,
    recommendation_id: int,
    baseline_run_id: int,
    simulated_run_id: int,
    paths_removed: int,
    paths_added: int,
    paths_rescored: int,
    risk_before: float,
    risk_after: float,
    crown_jewels_before: int,
    crown_jewels_after: int,
    prediction_hash: str,
    deltas: Sequence[PathDelta],
) -> int:
    from app.db import mysql_engine

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with mysql_engine().begin() as conn:
        simulation_id = int(
            conn.execute(
                text(
                    """
                    INSERT INTO simulation
                      (recommendation_id, baseline_run_id, simulated_run_id,
                       paths_removed, paths_added, paths_rescored, risk_before,
                       risk_after, crown_jewels_before, crown_jewels_after,
                       prediction_hash, created_at)
                    VALUES
                      (:rec, :baseline, :simulated, :removed, :added, :rescored,
                       :risk_before, :risk_after, :crown_before, :crown_after,
                       :hash, :now)
                    """
                ),
                {
                    "rec": recommendation_id,
                    "baseline": baseline_run_id,
                    "simulated": simulated_run_id,
                    "removed": paths_removed,
                    "added": paths_added,
                    "rescored": paths_rescored,
                    "risk_before": round(risk_before, 2),
                    "risk_after": round(risk_after, 2),
                    "crown_before": crown_jewels_before,
                    "crown_after": crown_jewels_after,
                    "hash": prediction_hash,
                    "now": now,
                },
            ).lastrowid
        )
        if deltas:
            conn.execute(
                text(
                    """
                    INSERT INTO simulation_path_delta
                      (simulation_id, path_id, change_kind, risk_before, risk_after)
                    VALUES (:sim, :path, :kind, :before, :after)
                    """
                ),
                [
                    {
                        "sim": simulation_id,
                        "path": delta.path_id,
                        "kind": delta.change_kind,
                        "before": None if delta.risk_before is None else round(delta.risk_before, 2),
                        "after": None if delta.risk_after is None else round(delta.risk_after, 2),
                    }
                    for delta in deltas
                ],
            )
    return simulation_id


def load_simulation(simulation_id: int) -> dict | None:
    from app.db import fetch_one

    return fetch_one("SELECT * FROM simulation WHERE id = :i", {"i": simulation_id})


def latest_simulation(recommendation_id: int) -> dict | None:
    from app.db import fetch_one

    return fetch_one(
        "SELECT * FROM simulation WHERE recommendation_id = :i ORDER BY id DESC LIMIT 1",
        {"i": recommendation_id},
    )


def load_simulation_deltas(simulation_id: int) -> list[dict]:
    from app.db import fetch_all

    return fetch_all(
        """
        SELECT path_id, change_kind, risk_before, risk_after
        FROM simulation_path_delta WHERE simulation_id = :i
        ORDER BY change_kind, path_id
        """,
        {"i": simulation_id},
    )


# ── Applied fixes ────────────────────────────────────────────────────────────


def insert_applied_fix(
    *,
    recommendation_id: int,
    simulation_id: int | None,
    applied_by: str,
    graph_version_before: int,
    graph_version_after: int,
    rollback_payload: str,
    state_code: str,
) -> int:
    from app.db import mysql_engine

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with mysql_engine().begin() as conn:
        return int(
            conn.execute(
                text(
                    """
                    INSERT INTO applied_fix
                      (recommendation_id, simulation_id, applied_by,
                       graph_version_before, graph_version_after, rollback_payload,
                       state_code, applied_at)
                    VALUES
                      (:rec, :sim, :by, :before, :after, :payload, :state, :now)
                    """
                ),
                {
                    "rec": recommendation_id,
                    "sim": simulation_id,
                    "by": applied_by[:191],
                    "before": graph_version_before,
                    "after": graph_version_after,
                    "payload": rollback_payload,
                    "state": state_code,
                    "now": now,
                },
            ).lastrowid
        )


def record_verification(
    applied_fix_id: int,
    *,
    verification_run_id: int,
    fidelity_exact_match: bool,
    fidelity_jaccard: float,
    unexpected_paths: int,
    state_code: str,
) -> None:
    from app.db import execute

    execute(
        """
        UPDATE applied_fix
        SET verification_run_id = :run, fidelity_exact_match = :exact,
            fidelity_jaccard = :jaccard, unexpected_paths = :unexpected,
            state_code = :state, verified_at = :now
        WHERE id = :i
        """,
        {
            "run": verification_run_id,
            "exact": 1 if fidelity_exact_match else 0,
            "jaccard": round(fidelity_jaccard, 5),
            "unexpected": unexpected_paths,
            "state": state_code,
            "now": datetime.now(timezone.utc).replace(tzinfo=None),
            "i": applied_fix_id,
        },
    )


def load_applied_fixes(run_id: int) -> list[dict]:
    from app.db import fetch_all

    return fetch_all(
        """
        SELECT a.id, a.recommendation_id, a.simulation_id, a.applied_by,
               a.graph_version_before, a.graph_version_after,
               a.verification_run_id, a.fidelity_exact_match, a.fidelity_jaccard,
               a.unexpected_paths, a.state_code, a.applied_at, a.verified_at,
               r.title, r.fix_type_code
        FROM applied_fix a
        JOIN recommendation r ON r.id = a.recommendation_id
        WHERE r.analysis_run_id = :r
        ORDER BY a.id DESC
        """,
        {"r": run_id},
    )


def load_applied_fix(applied_fix_id: int) -> dict | None:
    from app.db import fetch_one

    return fetch_one("SELECT * FROM applied_fix WHERE id = :i", {"i": applied_fix_id})


# ── Graph versions ───────────────────────────────────────────────────────────


def insert_graph_version(
    *,
    label: str,
    parent_id: int,
    canonical_hash: str,
    node_count: int,
    edge_count: int,
    notes: str,
) -> int:
    """A child version produced by a mutation.

    Never activated. ``is_active`` marks the graph the rest of the product
    measures against, and flipping it here would retarget every screen at a
    graph no baseline run has been computed for.
    """
    from app.db import mysql_engine

    with mysql_engine().begin() as conn:
        return int(
            conn.execute(
                text(
                    """
                    INSERT INTO graph_version
                      (label, origin, seed, generator_version, parent_id,
                       canonical_hash, node_count, edge_count, is_active, notes,
                       created_at)
                    VALUES
                      (:label, 'mutation', NULL, NULL, :parent, :hash, :nodes,
                       :edges, 0, :notes, :now)
                    """
                ),
                {
                    "label": label[:128],
                    "parent": parent_id,
                    "hash": canonical_hash,
                    "nodes": node_count,
                    "edges": edge_count,
                    "notes": notes[:1024],
                    "now": datetime.now(timezone.utc).replace(tzinfo=None),
                },
            ).lastrowid
        )


def materialise_graph_version(
    graph_version_id: int,
    node_rows: Sequence[Mapping[str, Any]],
    edge_rows: Sequence[Mapping[str, Any]],
) -> None:
    """Write a mutated graph into both stores so it genuinely exists.

    A simulation's child version stays a row and a hash — the whole point is
    that the graph never existed. An *applied* fix is different: verification
    re-derives against the post-apply graph, and re-reading it from the store is
    what proves the mutation actually landed rather than re-running against the
    same in-memory object that produced the prediction.
    """
    import json

    from app.db import cypher, mysql_engine

    with mysql_engine().begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO node
                  (graph_version_id, node_id, kind_code, name, display_name,
                   is_crown_jewel, criticality_code, classification_code, attrs)
                VALUES
                  (:gv, :node_id, :kind, :name, :display_name, :crown,
                   :criticality, :classification, :attrs)
                """
            ),
            [
                {
                    "gv": graph_version_id,
                    "node_id": row["node_id"],
                    "kind": row["kind"],
                    "name": row["name"],
                    "display_name": row["display_name"],
                    "crown": 1 if row["is_crown_jewel"] else 0,
                    "criticality": row["criticality"],
                    "classification": row["classification"],
                    "attrs": json.dumps(row["attrs"], sort_keys=True),
                }
                for row in node_rows
            ],
        )
        conn.execute(
            text(
                """
                INSERT INTO edge
                  (graph_version_id, edge_id, src_id, dst_id, type_code, attrs)
                VALUES (:gv, :edge_id, :src, :dst, :type, :attrs)
                """
            ),
            [
                {
                    "gv": graph_version_id,
                    "edge_id": row["edge_id"],
                    "src": row["src_id"],
                    "dst": row["dst_id"],
                    "type": row["edge_type"],
                    "attrs": json.dumps(row["attrs"], sort_keys=True),
                }
                for row in edge_rows
            ],
        )

    by_kind: dict[str, list[dict]] = {}
    for row in node_rows:
        by_kind.setdefault(str(row["kind"]), []).append(
            {
                "node_id": row["node_id"],
                "props": {
                    "name": row["name"],
                    "display_name": row["display_name"],
                    "is_crown_jewel": bool(row["is_crown_jewel"]),
                    "criticality": row["criticality"],
                    "classification": row["classification"],
                    **{k: v for k, v in dict(row["attrs"]).items() if v is not None},
                },
            }
        )
    for kind, rows in sorted(by_kind.items()):
        cypher(
            f"""
            UNWIND $rows AS row
            MERGE (n:Entity:`{kind}` {{graph_version: $v, node_id: row.node_id}})
            SET n += row.props
            """,
            {"v": graph_version_id, "rows": rows},
        )

    by_type: dict[str, list[dict]] = {}
    for row in edge_rows:
        by_type.setdefault(str(row["edge_type"]), []).append(
            {
                "edge_id": row["edge_id"],
                "src_id": row["src_id"],
                "dst_id": row["dst_id"],
                "props": {k: v for k, v in dict(row["attrs"]).items() if v is not None},
            }
        )
    for edge_type, rows in sorted(by_type.items()):
        cypher(
            f"""
            UNWIND $rows AS row
            MATCH (a:Entity {{graph_version: $v, node_id: row.src_id}})
            MATCH (b:Entity {{graph_version: $v, node_id: row.dst_id}})
            MERGE (a)-[r:`{edge_type}` {{graph_version: $v, edge_id: row.edge_id}}]->(b)
            SET r += row.props
            """,
            {"v": graph_version_id, "rows": rows},
        )


# ── Lifecycle rows ───────────────────────────────────────────────────────────


def load_states() -> list[dict]:
    from app.db import fetch_all

    return fetch_all(
        "SELECT code, label, description, is_terminal, ui_color, sort_order "
        "FROM remediation_state ORDER BY sort_order"
    )


def load_transitions() -> list[dict]:
    from app.db import fetch_all

    return fetch_all(
        "SELECT from_state, to_state, label, needs_approval "
        "FROM remediation_transition ORDER BY from_state, to_state"
    )


def floatify(row: Mapping[str, Any]) -> dict[str, Any]:
    """DECIMAL columns to float, for JSON.

    Same conversion ``app.routers.paths`` does, and for the same reason: the
    database stores exact values and only the transport rounds.
    """
    return {k: (float(v) if isinstance(v, Decimal) else v) for k, v in row.items()}


def floatify_all(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [floatify(row) for row in rows]
