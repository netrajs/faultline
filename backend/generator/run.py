"""Ties the generator together: ``python -m generator.run --seed <n> --scenarios <n>``.

``generate()`` builds one graph entirely in memory -- background population,
planted scenarios, planted decoys -- and returns a
:class:`~generator.manifest.GeneratedGraph`. Nothing in that function touches
a database, which is deliberate: it is what the test suite uses, and it is
what the engine or frontend teams can use to sanity-check the generator
without either store running.

``write_to_stores()`` is the only place a live database is required. It
writes the graph to Neo4j and everything else -- the manifest, the plant log,
the decoy/twin registry, the true edge probabilities -- to MySQL, following
the store split in ``docs/SCOPE.md`` D12: Neo4j holds the graph, MySQL holds
the record of what the generator knows about it.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from core.ids import SeedBundle

from . import GENERATOR_VERSION
from .decoys import plant_decoys
from .graph import BackgroundSizes, GraphBuilder, build_background
from .manifest import GeneratedGraph, build_manifest, compute_true_probabilities
from .scenarios import plant_scenarios


def generate(
    seed: int,
    *,
    scenario_count: int = 8,
    sizes: BackgroundSizes | None = None,
) -> GeneratedGraph:
    """Build one graph, entirely in memory. Deterministic in ``seed``.

    Call order is fixed -- background, then scenarios, then decoys -- because
    id assignment is by insertion order (``core.ids.node_id``/``edge_id`` key
    on a per-kind counter, not on content). Two calls with the same
    ``(seed, scenario_count, sizes)`` therefore produce byte-identical output,
    including tie ordering, which is the determinism contract in
    ``docs/SCOPE.md`` D10.
    """
    sizes = sizes or BackgroundSizes()
    bundle = SeedBundle(seed)
    builder = GraphBuilder(bundle)

    background = build_background(builder, sizes)
    scenarios = plant_scenarios(builder, background, bundle, scenario_count)
    decoys = plant_decoys(builder, bundle)

    true_probabilities = compute_true_probabilities(builder.nodes, builder.edges)

    parameters = {
        "sizes": {
            "users": sizes.users,
            "groups": sizes.groups,
            "service_accounts": sizes.service_accounts,
            "hosts": sizes.hosts,
            "databases": sizes.databases,
            "cloud_resources": sizes.cloud_resources,
            "applications": sizes.applications,
            "group_nesting_depth": sizes.group_nesting_depth,
        }
    }
    manifest = build_manifest(
        seed=seed,
        scenario_count=scenario_count,
        parameters=parameters,
        nodes=builder.nodes,
        edges=builder.edges,
    )

    return GeneratedGraph(
        nodes=builder.nodes,
        edges=builder.edges,
        manifest=manifest,
        scenarios=tuple(scenarios),
        decoys=tuple(decoys),
        true_probabilities=tuple(true_probabilities),
    )


# ── Persistence ───────────────────────────────────────────────────────────────


def write_to_stores(generated: GeneratedGraph, *, label: str | None = None, notes: str | None = None) -> int:
    """Write the graph to Neo4j and everything else to MySQL.

    Returns the new ``graph_version.id``. Requires a live MySQL and Neo4j --
    imported lazily so that ``generate()`` above never needs either.
    """
    from sqlalchemy import text

    from app.db import cypher, execute, mysql_engine

    now = datetime.now(timezone.utc)
    label = label or f"generated seed={generated.manifest.seed}"

    with mysql_engine().begin() as conn:
        conn.execute(
            text(
                """
                UPDATE graph_version SET is_active = 0 WHERE is_active = 1
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO graph_version
                    (label, origin, seed, generator_version, parent_id, canonical_hash,
                     node_count, edge_count, is_active, notes, created_at)
                VALUES
                    (:label, 'generated', :seed, :generator_version, NULL, :canonical_hash,
                     :node_count, :edge_count, 1, :notes, :created_at)
                """
            ),
            {
                "label": label,
                "seed": generated.manifest.seed,
                "generator_version": GENERATOR_VERSION,
                "canonical_hash": generated.graph_hash,
                "node_count": generated.node_count(),
                "edge_count": generated.edge_count(),
                "notes": notes,
                "created_at": now,
            },
        )
        graph_version_id = conn.execute(text("SELECT LAST_INSERT_ID()")).scalar_one()

    _write_neo4j(generated, graph_version_id)
    _write_mysql_ground_truth(generated, graph_version_id, now)
    return int(graph_version_id)


def _write_neo4j(generated: GeneratedGraph, graph_version_id: int) -> None:
    from app.db import cypher

    by_kind: dict[str, list[dict]] = {}
    for node in generated.nodes.values():
        by_kind.setdefault(node.kind, []).append(
            {
                "node_id": node.node_id,
                "props": {
                    "name": node.name,
                    "display_name": node.display_name,
                    "is_crown_jewel": node.is_crown_jewel,
                    "criticality": node.criticality,
                    "classification": node.classification,
                    **{k: v for k, v in node.attrs.items() if v is not None},
                },
            }
        )
    for kind, rows in by_kind.items():
        cypher(
            f"""
            UNWIND $rows AS row
            MERGE (n:Entity:`{kind}` {{graph_version: $v, node_id: row.node_id}})
            SET n += row.props
            """,
            {"v": graph_version_id, "rows": rows},
        )

    by_type: dict[str, list[dict]] = {}
    for edge in generated.edges.values():
        by_type.setdefault(edge.edge_type, []).append(
            {
                "edge_id": edge.edge_id,
                "src_id": edge.src_id,
                "dst_id": edge.dst_id,
                "props": {k: v for k, v in edge.attrs.items() if v is not None},
            }
        )
    for edge_type, rows in by_type.items():
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


def _write_mysql_ground_truth(generated: GeneratedGraph, graph_version_id: int, now: datetime) -> None:
    from app.db import execute

    node_rows = [
        {
            "gv": graph_version_id,
            "node_id": n.node_id,
            "kind_code": n.kind,
            "name": n.name,
            "display_name": n.display_name,
            "is_crown_jewel": int(n.is_crown_jewel),
            "criticality_code": n.criticality,
            "classification_code": n.classification,
            "attrs": json.dumps(n.attrs, sort_keys=True),
        }
        for n in generated.nodes.values()
    ]
    execute(
        """
        INSERT INTO node
            (graph_version_id, node_id, kind_code, name, display_name,
             is_crown_jewel, criticality_code, classification_code, attrs)
        VALUES
            (:gv, :node_id, :kind_code, :name, :display_name,
             :is_crown_jewel, :criticality_code, :classification_code, :attrs)
        """,
        node_rows,
    )

    edge_rows = [
        {
            "gv": graph_version_id,
            "edge_id": e.edge_id,
            "src_id": e.src_id,
            "dst_id": e.dst_id,
            "type_code": e.edge_type,
            "attrs": json.dumps(e.attrs, sort_keys=True),
        }
        for e in generated.edges.values()
    ]
    execute(
        """
        INSERT INTO edge (graph_version_id, edge_id, src_id, dst_id, type_code, attrs)
        VALUES (:gv, :edge_id, :src_id, :dst_id, :type_code, :attrs)
        """,
        edge_rows,
    )

    execute(
        """
        INSERT INTO generation_manifest
            (graph_version_id, seed, generator_version, scenario_count, facts_hash, parameters, created_at)
        VALUES
            (:gv, :seed, :generator_version, :scenario_count, :facts_hash, :parameters, :created_at)
        """,
        {
            "gv": graph_version_id,
            "seed": generated.manifest.seed,
            "generator_version": generated.manifest.generator_version,
            "scenario_count": generated.manifest.scenario_count,
            "facts_hash": generated.manifest.facts_hash,
            "parameters": json.dumps(generated.manifest.parameters, sort_keys=True),
            "created_at": now,
        },
    )

    if generated.scenarios:
        execute(
            """
            INSERT INTO plant_log (graph_version_id, scenario_code, entry_node_id, goal_node_id, notes)
            VALUES (:gv, :scenario_code, :entry_node_id, :goal_node_id, :notes)
            """,
            [
                {
                    "gv": graph_version_id,
                    "scenario_code": s.scenario_code,
                    "entry_node_id": s.entry_node_id,
                    "goal_node_id": s.goal_node_id,
                    "notes": s.notes,
                }
                for s in generated.scenarios
            ],
        )

    if generated.decoys:
        execute(
            """
            INSERT INTO decoy_instance
                (graph_version_id, decoy_code, role, edge_id, node_id, expected_outcome, deciding_value)
            VALUES
                (:gv, :decoy_code, :role, :edge_id, :node_id, :expected_outcome, :deciding_value)
            """,
            [
                {
                    "gv": graph_version_id,
                    "decoy_code": d.decoy_code,
                    "role": d.role,
                    "edge_id": d.edge_id,
                    "node_id": d.node_id,
                    "expected_outcome": d.expected_outcome,
                    "deciding_value": d.deciding_value,
                }
                for d in generated.decoys
            ],
        )

    if generated.true_probabilities:
        execute(
            """
            INSERT INTO true_edge_probability (graph_version_id, edge_id, p_true, detectability_true)
            VALUES (:gv, :edge_id, :p_true, :detectability_true)
            """,
            [
                {
                    "gv": graph_version_id,
                    "edge_id": t.edge_id,
                    "p_true": t.p_true,
                    "detectability_true": t.detectability_true,
                }
                for t in generated.true_probabilities
            ],
        )


# ── CLI ───────────────────────────────────────────────────────────────────────


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a synthetic faultline graph.")
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--scenarios", type=int, default=8, help="Number of planted opportunities.")
    parser.add_argument("--label", type=str, default=None)
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Build the graph in memory and print a summary without touching either store.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    generated = generate(args.seed, scenario_count=args.scenarios)

    if args.no_db:
        print(
            f"seed={args.seed} scenarios={len(generated.scenarios)} decoys={len(generated.decoys)} "
            f"nodes={generated.node_count()} edges={generated.edge_count()} hash={generated.graph_hash}"
        )
        return 0

    graph_version_id = write_to_stores(generated, label=args.label)
    print(
        f"graph_version={graph_version_id} nodes={generated.node_count()} edges={generated.edge_count()} "
        f"scenarios={len(generated.scenarios)} decoys={len(generated.decoys)} hash={generated.graph_hash}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
