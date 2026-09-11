"""Loading one graph version into memory.

Two bulk reads, then everything else happens in process. Neo4j is the system of
record and the exploration surface; it is never on the analysis hot path,
because no query language can express a precondition satisfied by a side
excursion (``docs/SCOPE.md`` D1, D12).

The snapshot is keyed by graph version and immutable once built. That is what
lets a simulated fix and its baseline be resident at the same time and diffed
against each other, and it is what makes every stored result attributable to the
exact graph it was computed against.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from core.model import Edge, GraphSnapshot, Node

#: Node properties promoted to typed fields on ``Node``, plus the two that carry
#: identity. Everything else on the node becomes an attribute, because attribute
#: names are rule data and the loader must not need to know them.
_NODE_RESERVED = frozenset(
    {
        "graph_version",
        "node_id",
        "name",
        "display_name",
        "is_crown_jewel",
        "criticality",
        "classification",
    }
)

_EDGE_RESERVED = frozenset({"graph_version", "edge_id", "src_id", "dst_id"})

_NODES_CYPHER = """
MATCH (n {graph_version: $version})
RETURN n.node_id          AS node_id,
       labels(n)          AS labels,
       n.name             AS name,
       n.display_name     AS display_name,
       n.is_crown_jewel   AS is_crown_jewel,
       n.criticality      AS criticality,
       n.classification   AS classification,
       properties(n)      AS props
ORDER BY n.node_id
"""

_EDGES_CYPHER = """
MATCH (a {graph_version: $version})-[r]->(b {graph_version: $version})
RETURN r.edge_id   AS edge_id,
       type(r)     AS edge_type,
       a.node_id   AS src_id,
       b.node_id   AS dst_id,
       properties(r) AS props
ORDER BY r.edge_id
"""


def active_graph_version() -> int:
    """The graph version every analysis run is measured against."""
    from app.db import fetch_scalar

    version = fetch_scalar("SELECT id FROM graph_version WHERE is_active = 1")
    if version is None:
        raise RuntimeError(
            "No active graph version. Generate one with: "
            "python -m generator.generate --seed 42"
        )
    return int(version)


def load_snapshot(graph_version: int | None = None) -> GraphSnapshot:
    """Bulk-read one graph version out of Neo4j."""
    from app.db import cypher

    version = active_graph_version() if graph_version is None else graph_version
    node_rows = cypher(_NODES_CYPHER, {"version": version})
    edge_rows = cypher(_EDGES_CYPHER, {"version": version})
    return snapshot_from_rows(version, node_rows, edge_rows)


def snapshot_from_rows(
    graph_version: int,
    node_rows: Iterable[Mapping[str, Any]],
    edge_rows: Iterable[Mapping[str, Any]],
) -> GraphSnapshot:
    """Build a snapshot from loader rows.

    Separated from the read so the same construction path is exercised by tests
    that build a graph by hand, with no store running.
    """
    nodes = [_node(row) for row in node_rows]
    edges = [_edge(row) for row in edge_rows]

    seen: set[str] = set()
    for edge in edges:
        if edge.edge_id in seen:
            raise ValueError(
                f"duplicate edge id {edge.edge_id} in graph version {graph_version}; "
                "path identity is keyed on edge ids and would collide"
            )
        seen.add(edge.edge_id)

    return GraphSnapshot(graph_version=graph_version, nodes=nodes, edges=edges)


def _node(row: Mapping[str, Any]) -> Node:
    props = dict(row.get("props") or {})
    labels = [str(label) for label in (row.get("labels") or ()) if label != "Entity"]
    return Node(
        node_id=str(row["node_id"]),
        # Sorted rather than first-as-returned: label order is not guaranteed by
        # the driver, and an arbitrary kind would make two loads of one graph
        # disagree about what a node is.
        kind=str(row.get("kind") or (sorted(labels)[0] if labels else "")),
        name=str(row.get("name") or row["node_id"]),
        display_name=_opt_str(row.get("display_name")),
        is_crown_jewel=bool(row.get("is_crown_jewel")),
        criticality=_opt_str(row.get("criticality")),
        classification=_opt_str(row.get("classification")),
        attrs=_attrs(props, _NODE_RESERVED, row.get("attrs")),
    )


def _edge(row: Mapping[str, Any]) -> Edge:
    props = dict(row.get("props") or {})
    return Edge(
        edge_id=str(row["edge_id"]),
        src_id=str(row["src_id"]),
        dst_id=str(row["dst_id"]),
        edge_type=str(row["edge_type"]),
        attrs=_attrs(props, _EDGE_RESERVED, row.get("attrs")),
    )


def _attrs(
    props: dict[str, Any], reserved: frozenset[str], explicit: Any
) -> Mapping[str, Any]:
    """Attributes as everything that is not structure.

    An explicit ``attrs`` map wins when one is supplied — MySQL stores the JSON
    document intact, while Neo4j cannot hold a nested map and so flattens it
    onto the node. Both shapes reach this loader.
    """
    if isinstance(explicit, Mapping):
        return dict(explicit)
    return {k: v for k, v in props.items() if k not in reserved}


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None
