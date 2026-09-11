"""Graph endpoints.

Reads the identity and asset graph from Neo4j for the Explorer, and runs the
saved queries.

One of those saved queries is deliberately wrong, and it is the most important
thing in this file. See ``run_saved_query`` and ``contrast``.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.db import cypher, fetch_all, fetch_one, fetch_scalar

router = APIRouter(prefix="/api/graph", tags=["graph"])


def _active_graph_version() -> int:
    version = fetch_scalar("SELECT id FROM graph_version WHERE is_active = 1")
    if version is None:
        raise HTTPException(
            404,
            "No active graph version. Generate one with: python -m generator.generate --seed 42",
        )
    return int(version)


@router.get("/version")
def active_version() -> dict:
    row = fetch_one(
        """
        SELECT id, label, origin, seed, generator_version, canonical_hash,
               node_count, edge_count, created_at
        FROM graph_version WHERE is_active = 1
        """
    )
    if not row:
        raise HTTPException(404, "No active graph version.")
    return row


@router.get("/versions")
def all_versions() -> list[dict]:
    return fetch_all(
        """
        SELECT id, label, origin, seed, parent_id, canonical_hash,
               node_count, edge_count, is_active, created_at
        FROM graph_version ORDER BY id DESC LIMIT 50
        """
    )


@router.get("/stats")
def stats() -> dict:
    version = _active_graph_version()
    by_kind = cypher(
        """
        MATCH (n {graph_version: $v})
        RETURN labels(n)[0] AS kind, count(n) AS count
        ORDER BY count DESC
        """,
        {"v": version},
    )
    by_type = cypher(
        """
        MATCH ({graph_version: $v})-[r]->({graph_version: $v})
        RETURN type(r) AS edge_type, count(r) AS count
        ORDER BY count DESC
        """,
        {"v": version},
    )
    crown = cypher(
        "MATCH (n {graph_version: $v, is_crown_jewel: true}) RETURN count(n) AS c",
        {"v": version},
    )
    return {
        "graph_version": version,
        "node_count": sum(r["count"] for r in by_kind),
        "edge_count": sum(r["count"] for r in by_type),
        "crown_jewels": crown[0]["c"] if crown else 0,
        "by_kind": {r["kind"]: r["count"] for r in by_kind},
        "by_edge_type": {r["edge_type"]: r["count"] for r in by_type},
    }


@router.get("/nodes")
def nodes(
    kind: str | None = None,
    q: str | None = None,
    crown_jewels_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    version = _active_graph_version()

    filters = ["n.graph_version = $v"]
    params: dict = {"v": version, "limit": limit, "offset": offset}
    if kind:
        filters.append("labels(n)[0] = $kind")
        params["kind"] = kind
    if crown_jewels_only:
        filters.append("n.is_crown_jewel = true")
    if q:
        # CONTAINS rather than a full-text index so partial matches work while
        # the user is still typing. At this graph size the scan is cheap.
        filters.append("(toLower(n.name) CONTAINS toLower($q) OR toLower(coalesce(n.display_name, '')) CONTAINS toLower($q))")
        params["q"] = q

    where = " AND ".join(filters)
    items = cypher(
        f"""
        MATCH (n) WHERE {where}
        RETURN n.node_id AS node_id, labels(n)[0] AS kind, n.name AS name,
               n.display_name AS display_name, n.is_crown_jewel AS is_crown_jewel,
               n.criticality AS criticality, n.classification AS classification,
               properties(n) AS attrs
        ORDER BY n.node_id SKIP $offset LIMIT $limit
        """,
        params,
    )
    total = cypher(f"MATCH (n) WHERE {where} RETURN count(n) AS c", params)
    return {"items": items, "total": total[0]["c"] if total else 0, "graph_version": version}


@router.get("/node/{node_id}")
def node_detail(node_id: str) -> dict:
    version = _active_graph_version()
    found = cypher(
        """
        MATCH (n {graph_version: $v, node_id: $id})
        RETURN n.node_id AS node_id, labels(n)[0] AS kind, n.name AS name,
               n.display_name AS display_name, n.is_crown_jewel AS is_crown_jewel,
               n.criticality AS criticality, n.classification AS classification,
               properties(n) AS attrs
        """,
        {"v": version, "id": node_id},
    )
    if not found:
        raise HTTPException(404, f"Node {node_id} not found in graph version {version}.")

    edges = cypher(
        """
        MATCH (n {graph_version: $v, node_id: $id})-[r]-(m {graph_version: $v})
        RETURN r.edge_id AS edge_id, type(r) AS edge_type,
               startNode(r).node_id AS src_id, endNode(r).node_id AS dst_id,
               properties(r) AS attrs,
               m.node_id AS neighbour_id, m.name AS neighbour_name,
               labels(m)[0] AS neighbour_kind, m.is_crown_jewel AS neighbour_crown_jewel
        ORDER BY type(r), r.edge_id
        """,
        {"v": version, "id": node_id},
    )
    return {"node": found[0], "edges": edges, "graph_version": version}


@router.get("/subgraph")
def subgraph(
    center: str,
    depth: int = Query(1, ge=1, le=3),
    limit: int = Query(300, ge=1, le=2000),
) -> dict:
    """A neighbourhood around one node, for progressive Explorer expansion.

    Bounded hard. Rendering an unbounded neighbourhood of a densely connected
    node is how a graph interface stops responding, and the resulting hang is
    indistinguishable from a crash to whoever is watching.
    """
    version = _active_graph_version()
    rows = cypher(
        f"""
        MATCH path = (c {{graph_version: $v, node_id: $center}})-[*1..{depth}]-(m {{graph_version: $v}})
        WITH nodes(path) AS ns, relationships(path) AS rs
        UNWIND ns AS n
        WITH collect(DISTINCT n) AS allNodes, collect(rs) AS allRels
        RETURN
          [n IN allNodes[..$limit] | {{
              node_id: n.node_id, kind: labels(n)[0], name: n.name,
              is_crown_jewel: n.is_crown_jewel, criticality: n.criticality
          }}] AS nodes,
          [r IN apoc.coll.toSet(apoc.coll.flatten(allRels)) | {{
              edge_id: r.edge_id, edge_type: type(r),
              src_id: startNode(r).node_id, dst_id: endNode(r).node_id
          }}] AS edges
        """,
        {"v": version, "center": center, "limit": limit},
    ) if _apoc_available() else _subgraph_without_apoc(version, center, depth, limit)

    if not rows:
        raise HTTPException(404, f"Node {center} not found in graph version {version}.")
    return {**rows[0], "graph_version": version, "center": center, "depth": depth}


def _apoc_available() -> bool:
    """Whether the APOC plugin is installed.

    It is not bundled with a plain Neo4j download, so the subgraph query has a
    plugin-free fallback. Checked rather than assumed, because the failure
    otherwise appears as an unhelpful Cypher error at request time.
    """
    try:
        result = cypher("SHOW PROCEDURES YIELD name WHERE name STARTS WITH 'apoc.coll' RETURN count(*) AS c")
        return bool(result and result[0]["c"] > 0)
    except Exception:  # noqa: BLE001 - absence is the expected case, not an error
        return False


def _subgraph_without_apoc(version: int, center: str, depth: int, limit: int) -> list[dict]:
    nodes = cypher(
        f"""
        MATCH (c {{graph_version: $v, node_id: $center}})-[*1..{depth}]-(m {{graph_version: $v}})
        WITH DISTINCT m LIMIT $limit
        RETURN collect({{
            node_id: m.node_id, kind: labels(m)[0], name: m.name,
            is_crown_jewel: m.is_crown_jewel, criticality: m.criticality
        }}) AS nodes
        """,
        {"v": version, "center": center, "limit": limit},
    )
    if not nodes:
        return []
    ids = [n["node_id"] for n in nodes[0]["nodes"]] + [center]
    edges = cypher(
        """
        MATCH (a {graph_version: $v})-[r]->(b {graph_version: $v})
        WHERE a.node_id IN $ids AND b.node_id IN $ids
        RETURN collect({
            edge_id: r.edge_id, edge_type: type(r),
            src_id: a.node_id, dst_id: b.node_id
        }) AS edges
        """,
        {"v": version, "ids": ids},
    )
    return [{"nodes": nodes[0]["nodes"], "edges": edges[0]["edges"] if edges else []}]


@router.get("/saved-queries")
def saved_queries() -> list[dict]:
    return fetch_all(
        """
        SELECT code, label, description, cypher, purpose, parameters, sort_order
        FROM saved_query WHERE is_enabled = 1 ORDER BY sort_order
        """
    )


@router.post("/saved-queries/{code}/run")
def run_saved_query(code: str, limit: int = Query(200, ge=1, le=1000)) -> dict:
    """Run one saved query against the live graph.

    Only queries stored in the database can be run; arbitrary Cypher from the
    client is not accepted. The Explorer is a read surface, and accepting
    caller-supplied Cypher would make it a write surface with full database
    authority -- an unusually bad thing to build into a tool whose subject is
    privilege escalation.
    """
    query = fetch_one(
        "SELECT code, label, description, cypher, purpose, parameters FROM saved_query WHERE code = :c AND is_enabled = 1",
        {"c": code},
    )
    if not query:
        raise HTTPException(404, f"No saved query named {code}.")

    version = _active_graph_version()
    rows = cypher(query["cypher"], {"graph_version": version})
    return {
        "code": query["code"],
        "label": query["label"],
        "purpose": query["purpose"],
        "graph_version": version,
        "rows": rows[:limit],
        "row_count": len(rows),
        "truncated": len(rows) > limit,
    }


@router.get("/contrast")
def contrast() -> dict:
    """Naive reachability compared against what the engine actually reports.

    This is the product's central claim, executed live against the same
    database, and it is worth being precise about what it shows.

    The naive query is what a reachability tool computes and calls an attack
    path list: variable-length matching from any user to any crown jewel, with
    no notion of what the attacker holds. It returns every route the graph
    permits.

    The engine returns fewer, because a route is not an attack. Reading a
    credential out of a configuration file requires administrative control of
    the host holding it; a phishing-resistant second factor cannot be satisfied
    by replaying a stolen secret; a one-way trust does not work backwards; a
    disabled account's rights assignments do not authenticate. None of those
    conditions are visible to a path query, and every candidate the engine
    refused is recorded in ``rejected_candidate`` with the rule and the specific
    precondition that failed.

    The difference between the two counts is the false positives a reachability
    tool would have handed an analyst. That is the whole argument.
    """
    version = _active_graph_version()

    naive = fetch_one(
        "SELECT cypher FROM saved_query WHERE code = 'naive_reachability' AND is_enabled = 1"
    )
    if not naive:
        raise HTTPException(500, "The naive_reachability saved query is missing. Run the seed migrations.")

    naive_rows = cypher(naive["cypher"], {"graph_version": version})
    naive_count = naive_rows[0].get("candidate_count", 0) if naive_rows else 0

    run = fetch_one(
        """
        SELECT id, path_count, rejected_count, crown_jewels_reached, duration_ms
        FROM analysis_run
        WHERE graph_version_id = :v AND purpose = 'baseline' AND status = 'complete'
        ORDER BY id DESC LIMIT 1
        """,
        {"v": version},
    )

    if not run:
        return {
            "graph_version": version,
            "naive_candidate_count": naive_count,
            "engine_path_count": None,
            "message": "No completed discovery run yet. Run: python -m engine.discover",
        }

    reasons = fetch_all(
        """
        SELECT reason_code, COUNT(*) AS count, MIN(reason_text) AS example
        FROM rejected_candidate WHERE analysis_run_id = :r
        GROUP BY reason_code ORDER BY count DESC LIMIT 20
        """,
        {"r": run["id"]},
    )

    return {
        "graph_version": version,
        "analysis_run_id": run["id"],
        "naive_candidate_count": naive_count,
        "engine_path_count": run["path_count"],
        "rejected_count": run["rejected_count"],
        "crown_jewels_reached": run["crown_jewels_reached"],
        "discovery_ms": run["duration_ms"],
        "rejection_reasons": reasons,
    }
