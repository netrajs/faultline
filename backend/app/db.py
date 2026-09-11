"""Store access.

Two stores, split by the shape of the data. Neo4j holds the identity and asset
graph; MySQL holds rules, scoring, results, remediation state, ground truth and
the audit ledger. See ``docs/SCOPE.md`` D12.

Neither store is on the analysis hot path. The engine loads a snapshot into
memory once per graph version and searches that, because no query language can
express a precondition satisfied by a side excursion (D1). What these
connections serve is reads for the interface, writes of results, and the Graph
Explorer's ad-hoc Cypher.

Both are lazily initialised and cached, so importing this module does not
require a running database — which matters because the test suite builds graphs
by hand and should not need either store.
"""

from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from typing import Any, Iterator, Sequence

from neo4j import Driver, GraphDatabase
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import Row

from app.core.settings import Settings, load_settings


@lru_cache(maxsize=1)
def mysql_engine() -> Engine:
    settings = load_settings()
    return create_engine(
        settings.sqlalchemy_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        # A stale pooled connection surfaces as an error on the first query of a
        # request rather than at connect time, which is confusing to diagnose.
        # pool_pre_ping costs one round trip and removes the class of bug.
        future=True,
    )


@lru_cache(maxsize=1)
def neo4j_driver() -> Driver:
    settings = load_settings()
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
        max_connection_pool_size=20,
    )


@contextmanager
def mysql_connection() -> Iterator[Any]:
    with mysql_engine().connect() as conn:
        yield conn


def fetch_all(sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Run a query and return plain dictionaries.

    Returning dicts rather than Row objects keeps SQLAlchemy out of the router
    signatures, so a router reads as "shape this data for the client" without
    also being a place where the ORM leaks into the response model.
    """
    with mysql_engine().connect() as conn:
        result = conn.execute(text(sql), params or {})
        return [dict(row) for row in result.mappings()]


def fetch_one(sql: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    rows = fetch_all(sql, params)
    return rows[0] if rows else None


def fetch_scalar(sql: str, params: dict[str, Any] | None = None) -> Any:
    with mysql_engine().connect() as conn:
        return conn.execute(text(sql), params or {}).scalar()


def execute(sql: str, params: dict[str, Any] | Sequence[dict[str, Any]] | None = None) -> int:
    """Run a write and commit. Returns affected row count."""
    with mysql_engine().begin() as conn:
        result = conn.execute(text(sql), params or {})
        return result.rowcount


def cypher(query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    settings = load_settings()
    with neo4j_driver().session(database=settings.neo4j_database) as session:
        return [record.data() for record in session.run(query, params or {})]


def store_health() -> dict[str, Any]:
    """Reachability of both stores, for the health endpoint.

    Reported independently rather than as one boolean, because the two failure
    modes have very different consequences. MySQL down means nothing works.
    Neo4j down degrades the Graph Explorer only — analysis runs from the
    in-memory snapshot and MySQL, so the core of the product survives it. An
    interface that cannot tell those apart sends someone debugging the wrong
    thing.
    """
    health: dict[str, Any] = {"mysql": False, "neo4j": False, "errors": {}}

    try:
        fetch_scalar("SELECT 1")
        health["mysql"] = True
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller, not swallowed
        health["errors"]["mysql"] = str(exc)[:200]

    try:
        cypher("RETURN 1 AS ok")
        health["neo4j"] = True
    except Exception as exc:  # noqa: BLE001
        health["errors"]["neo4j"] = str(exc)[:200]

    return health


def close_all() -> None:
    """Release pooled connections. Called on application shutdown."""
    if neo4j_driver.cache_info().currsize:
        neo4j_driver().close()
    if mysql_engine.cache_info().currsize:
        mysql_engine().dispose()
