"""Tests for /api/settings/*.

``overview`` is read-only and is exercised against the live seeded database --
it just recombines what ``/api/config`` and ``/api/graph`` already serve, so
the meaningful thing to check is that the aggregation actually lines up with
the real schema, not a mock of it. Skipped when the database is unreachable,
same as the rest of the suite has no other precedent for doing (this is the
first router test file), because a store-connectivity failure is not this
endpoint's bug.

``regenerate`` triggers a real subprocess that mutates the shared demo
database (deactivates the current graph version, writes a new one) and can
take a couple of minutes at "large" scale, so it is never actually invoked
here. Its request-validation and subprocess-failure-handling paths are
exercised instead, with ``subprocess.run`` monkeypatched so the test is both
fast and side-effect-free.
"""

from __future__ import annotations

import subprocess

import pytest
from fastapi.testclient import TestClient

from app.db import store_health
from app.main import app
from app.routers import settings as settings_router

client = TestClient(app)


def _db_available() -> bool:
    health = store_health()
    return bool(health["mysql"])


requires_db = pytest.mark.skipif(not _db_available(), reason="MySQL is not reachable in this environment")


@requires_db
def test_overview_shape():
    response = client.get("/api/settings/overview")
    assert response.status_code == 200
    body = response.json()

    assert set(body) == {"graph_version", "scoring", "threat_models", "anchor_mode", "narration_available"}

    version = body["graph_version"]
    for key in ("id", "label", "origin", "seed", "generator_version", "canonical_hash", "node_count", "edge_count", "created_at"):
        assert key in version
    assert version["node_count"] > 0
    assert version["edge_count"] > 0

    scoring = body["scoring"]
    assert set(scoring) == {"config", "baselines", "modifiers", "impact_weights"}
    assert scoring["config"]["version"]
    assert len(scoring["baselines"]) > 0
    for baseline in scoring["baselines"]:
        assert "technique_code" in baseline
        assert "base_p_succ" in baseline
        assert "base_detectability" in baseline

    threat_models = body["threat_models"]
    assert len(threat_models) > 0
    for model in threat_models:
        assert "code" in model
        assert "grants" in model
        assert isinstance(model["grants"], list)

    assert isinstance(body["narration_available"], bool)
    assert body["anchor_mode"] in {"anvil", "base-sepolia", "replay"}


@requires_db
def test_overview_matches_graph_version_endpoint():
    """The graph_version block should describe the same active version /api/graph/version does."""
    overview = client.get("/api/settings/overview").json()
    graph_version = client.get("/api/graph/version").json()
    assert overview["graph_version"]["id"] == graph_version["id"]
    assert overview["graph_version"]["canonical_hash"] == graph_version["canonical_hash"]


def test_regenerate_rejects_unknown_scale():
    response = client.post("/api/settings/regenerate", json={"scale": "huge"})
    assert response.status_code == 422
    assert "scale" in response.json()["detail"]


def test_regenerate_accepts_empty_body(monkeypatch: pytest.MonkeyPatch):
    """No body at all should fall back to the medium-scale, random-seed defaults, not error."""
    captured_cmd: list[str] = []

    def fake_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="graph_version=99 nodes=1 edges=1", stderr="")

    monkeypatch.setattr(settings_router.subprocess, "run", fake_run)
    monkeypatch.setattr(settings_router, "fetch_one", lambda *a, **k: {"id": 99, "label": "regenerated"})

    response = client.post("/api/settings/regenerate")
    assert response.status_code == 200
    body = response.json()
    assert body["scale"] == "medium"
    assert body["scenario_count"] == 8
    assert isinstance(body["seed"], int)
    assert body["graph_version"] == {"id": 99, "label": "regenerated"}

    assert "-m" in captured_cmd and "generator.run" in captured_cmd
    assert "--seed" in captured_cmd
    assert str(body["seed"]) in captured_cmd
    assert "--scenarios" in captured_cmd
    assert "8" in captured_cmd


def test_regenerate_honors_seed_and_scale(monkeypatch: pytest.MonkeyPatch):
    captured_cmd: list[str] = []

    def fake_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(settings_router.subprocess, "run", fake_run)
    monkeypatch.setattr(settings_router, "fetch_one", lambda *a, **k: {"id": 7})

    response = client.post("/api/settings/regenerate", json={"seed": 4242, "scale": "large"})
    assert response.status_code == 200
    body = response.json()
    assert body["seed"] == 4242
    assert body["scale"] == "large"
    assert body["scenario_count"] == 16
    assert "4242" in captured_cmd
    assert "16" in captured_cmd


def test_regenerate_reports_generator_failure(monkeypatch: pytest.MonkeyPatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="ValueError: seed already in use")

    monkeypatch.setattr(settings_router.subprocess, "run", fake_run)

    response = client.post("/api/settings/regenerate", json={"seed": 1})
    assert response.status_code == 502
    assert "ValueError: seed already in use" in response.json()["detail"]


def test_regenerate_reports_timeout(monkeypatch: pytest.MonkeyPatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 300))

    monkeypatch.setattr(settings_router.subprocess, "run", fake_run)

    response = client.post("/api/settings/regenerate", json={"seed": 1})
    assert response.status_code == 504
    assert "timed out" in response.json()["detail"].lower()
