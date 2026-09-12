"""faultline API.

Serves the interface and the analysis results. The engine itself does not live
behind these endpoints -- it runs against an in-memory snapshot and writes its
results to MySQL, which is what these routes read. See ``docs/SCOPE.md`` D1 for
why pathfinding cannot be a database query.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.settings import ConfigError, load_settings
from app.db import close_all, fetch_one, store_health
from app.routers import audit as audit_router
from app.routers import blast_radius as blast_radius_router
from app.routers import config as config_router
from app.routers import graph as graph_router
from app.routers import paths as paths_router
from app.routers import remediation as remediation_router
from app.routers import settings as settings_router
from app.routers import validation as validation_router

log = logging.getLogger("faultline")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    health = store_health()

    # Report store state at startup rather than failing outright. MySQL down
    # means nothing works and should be loud; Neo4j down degrades the Explorer
    # only, and refusing to start over it would take the whole product offline
    # for a partial outage.
    if not health["mysql"]:
        log.error("MySQL unreachable: %s", health["errors"].get("mysql"))
    if not health["neo4j"]:
        log.warning(
            "Neo4j unreachable: %s -- the Graph Explorer will be unavailable, "
            "analysis is unaffected", health["errors"].get("neo4j")
        )
    log.info("anchoring mode: %s", settings.anchor_mode)
    if not settings.narration_available:
        log.info("no model API key configured; narration will use the offline renderer")

    yield
    close_all()


def create_app() -> FastAPI:
    app = FastAPI(
        title="faultline",
        description="Attack path and identity privilege graph analyzer.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # The frontend runs on a different port in development. Origins are
    # explicit rather than a wildcard: this service can eventually apply graph
    # mutations, and a wildcard CORS policy on a mutating API is a gift to
    # anyone who can get a browser to visit a page.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    app.include_router(config_router.router)
    app.include_router(graph_router.router)
    app.include_router(paths_router.router)
    app.include_router(settings_router.router)
    app.include_router(blast_radius_router.router)
    app.include_router(remediation_router.router)
    app.include_router(audit_router.router)
    app.include_router(validation_router.router)

    @app.exception_handler(ConfigError)
    async def config_error_handler(_: Request, exc: ConfigError) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc), "kind": "configuration"})

    @app.get("/api/health", tags=["health"])
    def health() -> dict:
        """Store reachability and current data state.

        Reports the two stores separately because their failure modes differ in
        consequence, and an interface that cannot tell them apart sends someone
        to debug the wrong thing.
        """
        stores = store_health()
        version = None
        if stores["mysql"]:
            version = fetch_one(
                "SELECT id, label, node_count, edge_count, canonical_hash "
                "FROM graph_version WHERE is_active = 1"
            )
        return {
            "status": "ok" if stores["mysql"] else "degraded",
            "stores": {"mysql": stores["mysql"], "neo4j": stores["neo4j"]},
            "errors": stores["errors"],
            "graph_version": version,
        }

    return app


app = create_app()
