"""Neo4j constraints and indexes for the graph store.

Neo4j holds the identity and asset graph: it is the system of record for facts
and the surface the Graph Explorer queries. It is deliberately not where path
discovery happens -- no query language can express a precondition satisfied by a
side excursion, so an engine built on variable-length matching would report
reachability and call it attack paths. See ``docs/SCOPE.md`` D1.

What Neo4j does earn its place for: storing a graph as a graph keeps the fact
model honest, it is the substrate practitioners already associate with this
problem, and it makes the naive-reachability contrast in the Explorer a real
query against real data rather than a staged number.

Every statement here is idempotent, so this can run on every startup.
"""

from __future__ import annotations

from neo4j import Driver, GraphDatabase

from app.core.settings import Settings, load_settings

# Node labels mirror node_kind.code in MySQL. The two are kept in step by a test
# that reads both and fails on divergence -- a label present in one store and
# absent from the other is the kind of drift that produces an empty screen and a
# confusing afternoon.
NODE_LABELS = (
    "User",
    "Group",
    "ServiceAccount",
    "Host",
    "Database",
    "CloudResource",
    "Application",
    "Credential",
    "Vulnerability",
)

CONSTRAINTS = [
    # Node identity is (graph_version, node_id). Versioning lives in the graph
    # itself rather than in separate databases, because a simulation needs the
    # baseline and the mutated child resident at the same time to diff them.
    f"CREATE CONSTRAINT {label.lower()}_identity IF NOT EXISTS "
    f"FOR (n:{label}) REQUIRE (n.graph_version, n.node_id) IS UNIQUE"
    for label in NODE_LABELS
]

INDEXES = [
    # Bulk load reads every node of a version in one pass.
    "CREATE INDEX node_by_version IF NOT EXISTS FOR (n:Entity) ON (n.graph_version)",
    # Crown jewels are the goal set for every discovery run.
    "CREATE INDEX node_crown_jewel IF NOT EXISTS FOR (n:Entity) ON (n.graph_version, n.is_crown_jewel)",
    # Explorer search-as-you-type.
    "CREATE INDEX node_name IF NOT EXISTS FOR (n:Entity) ON (n.graph_version, n.name)",
    "CREATE FULLTEXT INDEX node_search IF NOT EXISTS FOR (n:Entity) ON EACH [n.name, n.display_name]",
]

# Relationship types mirror edge_type.code. Nothing resembling CAN_ESCALATE_TO
# appears, and that omission is the point: escalation is what the engine derives,
# and storing it as a fact would make discovery circular and leave remediation
# computing deltas against a graph that still asserts the escalation it removed.
RELATIONSHIP_TYPES = (
    "MEMBER_OF",
    "HAS_CREDENTIAL",
    "AUTHENTICATES_TO",
    "ADMIN_TO",
    "HAS_ACCESS_TO",
    "HAS_PERMISSION",
    "TRUSTS",
    "CONNECTED_TO",
    "HAS_VULNERABILITY",
    "EXPOSES_CREDENTIAL",
)

RELATIONSHIP_INDEXES = [
    f"CREATE INDEX rel_{rel.lower()}_version IF NOT EXISTS "
    f"FOR ()-[r:{rel}]-() ON (r.graph_version)"
    for rel in RELATIONSHIP_TYPES
]


def get_driver(settings: Settings | None = None) -> Driver:
    settings = settings or load_settings()
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )


def apply_schema(driver: Driver, database: str) -> dict[str, int]:
    """Create every constraint and index. Safe to call repeatedly."""
    counts = {"constraints": 0, "indexes": 0, "relationship_indexes": 0}
    groups = (
        ("constraints", CONSTRAINTS),
        ("indexes", INDEXES),
        ("relationship_indexes", RELATIONSHIP_INDEXES),
    )
    with driver.session(database=database) as session:
        for key, statements in groups:
            for statement in statements:
                session.run(statement)
                counts[key] += 1
    return counts


def describe(driver: Driver, database: str) -> dict[str, object]:
    """Current state of the graph store, for the health endpoint."""
    with driver.session(database=database) as session:
        version = session.run(
            "CALL dbms.components() YIELD name, versions, edition "
            "RETURN versions[0] AS version, edition AS edition"
        ).single()
        nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        rels = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        constraints = session.run("SHOW CONSTRAINTS YIELD name RETURN count(*) AS c").single()["c"]
        indexes = session.run("SHOW INDEXES YIELD name RETURN count(*) AS c").single()["c"]
    return {
        "version": version["version"],
        "edition": version["edition"],
        "nodes": nodes,
        "relationships": rels,
        "constraints": constraints,
        "indexes": indexes,
    }


def main() -> int:
    settings = load_settings()
    driver = get_driver(settings)
    try:
        driver.verify_connectivity()
        counts = apply_schema(driver, settings.neo4j_database)
        state = describe(driver, settings.neo4j_database)
        print(
            f"  applied {counts['constraints']} constraints, "
            f"{counts['indexes']} node indexes, "
            f"{counts['relationship_indexes']} relationship indexes"
        )
        print(
            f"  neo4j {state['version']} {state['edition']}: "
            f"{state['nodes']} nodes, {state['relationships']} relationships"
        )
        return 0
    finally:
        driver.close()


if __name__ == "__main__":
    raise SystemExit(main())
