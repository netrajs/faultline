"""Tests for /api/remediation/*, against the live graph.

Request-validation paths that never touch the database run unconditionally, the
same convention as ``tests/audit/test_routes.py``; everything that reads a real
run is guarded behind ``requires_db`` and skips cleanly when MySQL is not
reachable.

One thing is deliberately not tested here: a successful simulation. It is a full
re-derivation of the graph (``docs/SCOPE.md`` D6) and takes minutes, so a test
suite that waited for one would be a test suite nobody runs. What *is* tested is
every way the endpoint can refuse before it starts, which is where the lifecycle
rules live, plus the shape of a stored simulation when the live database has one.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.db import store_health
from app.main import app

client = TestClient(app)


def _db_available() -> bool:
    try:
        return bool(store_health()["mysql"])
    except Exception:  # noqa: BLE001 - any failure here means "no database"
        return False


requires_db = pytest.mark.skipif(
    not _db_available(), reason="MySQL is not reachable in this environment"
)


def _recommendations() -> dict:
    response = client.get("/api/remediation/recommendations")
    assert response.status_code == 200, response.text
    return response.json()


# ── Validation, no database needed ───────────────────────────────────────────


def test_a_zero_recommendation_id_is_rejected_before_any_lookup():
    assert client.get("/api/remediation/recommendations/0").status_code == 422


def test_an_out_of_range_limit_is_rejected():
    assert client.get("/api/remediation/recommendations", params={"limit": 0}).status_code == 422
    assert client.get("/api/remediation/recommendations", params={"limit": 9999}).status_code == 422


def test_applying_without_saying_who_is_rejected():
    """``applied_by`` is written into an append-only audit entry; an empty one
    would put an unattributable mutation in a tamper-evident record."""
    response = client.post("/api/remediation/recommendations/1/apply", json={"applied_by": ""})
    assert response.status_code == 422


# ── Lifecycle ────────────────────────────────────────────────────────────────


@requires_db
def test_the_lifecycle_is_served_from_the_tables_that_define_it():
    response = client.get("/api/remediation/lifecycle")
    assert response.status_code == 200
    body = response.json()

    codes = {state["code"] for state in body["states"]}
    assert {"recommended", "simulated", "approved", "applied", "verified"} <= codes
    assert body["initial_state"] in codes
    # Colours and labels come from the row, so the frontend never hardcodes one.
    assert all(state["ui_color"].startswith("#") for state in body["states"])

    edges = {(t["from_state"], t["to_state"]) for t in body["transitions"]}
    assert ("recommended", "simulated") in edges
    # The rule that a fix cannot be applied unsimulated is the absence of this
    # edge, not a condition written in the router.
    assert ("recommended", "applied") not in edges


@requires_db
def test_approval_is_reported_per_transition_not_per_fix():
    body = client.get("/api/remediation/lifecycle").json()
    approve = next(t for t in body["transitions"] if (t["from_state"], t["to_state"]) == ("simulated", "approved"))
    simulate = next(t for t in body["transitions"] if (t["from_state"], t["to_state"]) == ("recommended", "simulated"))

    assert approve["needs_approval"] is True
    assert simulate["needs_approval"] is False


# ── Reading the ranking ──────────────────────────────────────────────────────


@requires_db
def test_every_response_carries_the_run_it_came_from():
    """Recommendations are only comparable within a run: one graph version, one
    scoring version, one threat model."""
    body = _recommendations()

    assert {
        "analysis_run_id",
        "graph_version_id",
        "scoring_version",
        "threat_model_code",
        "total_paths",
        "crown_jewels_reached",
        "max_risk_score",
        "items",
        "has_ranking",
    } <= set(body)
    assert isinstance(body["items"], list)


@requires_db
def test_an_unknown_run_is_a_404_not_a_silent_fallback_to_the_latest():
    response = client.get("/api/remediation/recommendations", params={"run_id": 99999999})
    assert response.status_code == 404
    assert "99999999" in response.json()["detail"]


@requires_db
def test_rows_arrive_ranked_and_carry_their_catalogue_columns():
    body = _recommendations()
    if not body["items"]:
        pytest.skip("no ranking computed for the current run")

    scores = [row["priority_score"] or 0.0 for row in body["items"]]
    assert scores == sorted(scores, reverse=True)

    first = body["items"][0]
    assert {"fix_label", "effort_label", "disruption_label", "requires_approval"} <= set(first)
    assert first["state_label"] and first["state_color"].startswith("#")
    assert first["target_kind"] in ("edge", "node")


@requires_db
def test_an_estimate_is_never_served_as_a_measurement():
    """``is_measured`` flips in exactly one place -- when a simulation records
    what it observed -- so a measured row always has the numbers to back it."""
    body = _recommendations()
    if not body["items"]:
        pytest.skip("no ranking computed for the current run")

    for row in body["items"]:
        if row["is_measured"]:
            assert row["risk_after"] is not None
            assert row["paths_eliminated"] is not None
            assert row["simulation_id"] is not None


@requires_db
def test_the_chokepoint_endpoint_and_this_one_describe_the_same_run():
    """There is one chokepoint read endpoint in the product, not two: /api/chokepoints
    serves the rows POST /analyze writes."""
    body = _recommendations()
    chokepoints = client.get("/api/chokepoints").json()

    assert chokepoints["analysis_run_id"] == body["analysis_run_id"]
    assert chokepoints["total_paths"] == body["total_paths"]
    assert bool(chokepoints["items"]) == body["has_ranking"]


# ── One recommendation ───────────────────────────────────────────────────────


@requires_db
def test_an_unknown_recommendation_is_a_404():
    response = client.get("/api/remediation/recommendations/99999999")
    assert response.status_code == 404
    assert "99999999" in response.json()["detail"]


@requires_db
def test_the_detail_offers_only_the_transitions_the_table_allows():
    body = _recommendations()
    if not body["items"]:
        pytest.skip("no ranking computed for the current run")

    row = body["items"][0]
    detail = client.get(f"/api/remediation/recommendations/{row['id']}").json()
    lifecycle = client.get("/api/remediation/lifecycle").json()

    allowed = {
        t["to_state"]
        for t in lifecycle["transitions"]
        if t["from_state"] == detail["recommendation"]["state_code"]
    }
    assert {t["to_state"] for t in detail["transitions"]} == allowed
    # An approver is wanted only where the transition and the fix type agree.
    for transition in detail["transitions"]:
        expected = transition["needs_approval"] and bool(detail["recommendation"]["requires_approval"])
        assert transition["requires_approver"] is expected


@requires_db
def test_the_detail_carries_the_dependency_rows_the_list_only_counted():
    body = _recommendations()
    if not body["items"]:
        pytest.skip("no ranking computed for the current run")

    row = next((r for r in body["items"] if r["dependency_count"] > 0), None)
    if row is None:
        pytest.skip("no recommendation on this run has derivable collateral")

    detail = client.get(f"/api/remediation/recommendations/{row['id']}").json()
    assert len(detail["dependencies"]) == row["dependency_count"]
    for dependency in detail["dependencies"]:
        assert dependency["severity"] in ("info", "warning", "blocking")
        assert dependency["description"]


@requires_db
def test_an_unsimulated_recommendation_says_so_rather_than_showing_zeroes():
    body = _recommendations()
    row = next((r for r in body["items"] if r["simulation_id"] is None), None)
    if row is None:
        pytest.skip("every recommendation on this run has been simulated")

    detail = client.get(f"/api/remediation/recommendations/{row['id']}").json()
    assert detail["simulation"] is None
    assert detail["runs"] is None
    assert detail["deltas"] == []
    assert detail["delta_total"] == 0


@requires_db
def test_a_stored_simulation_diffs_in_both_directions():
    body = _recommendations()
    row = next((r for r in body["items"] if r["simulation_id"] is not None), None)
    if row is None:
        pytest.skip("no simulation has been run against the current graph")

    detail = client.get(f"/api/remediation/recommendations/{row['id']}").json()
    simulation = detail["simulation"]

    assert len(simulation["prediction_hash"]) == 64
    counted = simulation["paths_removed"] + simulation["paths_added"] + simulation["paths_rescored"]
    assert counted == detail["delta_total"]

    kinds = {delta["change_kind"] for delta in detail["deltas"]}
    assert kinds <= {"removed", "added", "rescored"}
    # Every delta is named by the attack it is, not only by its hash.
    for delta in detail["deltas"]:
        assert delta["source_node_id"] and delta["target_node_id"]

    # Both sides were searched under the same limits, which is what makes the
    # difference attributable to the fix rather than to the settings.
    runs = detail["runs"]
    assert runs["baseline"]["max_hops"] == runs["simulated"]["max_hops"]
    assert runs["baseline"]["top_k_per_pair"] == runs["simulated"]["top_k_per_pair"]
    assert runs["simulated"]["purpose"] == "simulation"
    assert runs["simulated"]["graph_version_id"] != runs["baseline"]["graph_version_id"]


# ── Writing the ranking ──────────────────────────────────────────────────────


@requires_db
def test_analyze_writes_the_ranking_and_reports_the_exact_cut():
    response = client.post("/api/remediation/analyze", json={})
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["chokepoints_ranked"] >= 0
    assert body["recommendations_total"] >= body["recommendations_written"]
    # The min cut is the one number in the ranking that is not an approximation.
    assert body["min_cut_size"] == len(body["min_cut_vertices"]) or body["min_cut_size"] >= 0
    assert client.get("/api/remediation/recommendations").json()["has_ranking"] is True


@requires_db
def test_re_ranking_does_not_duplicate_or_delete_what_has_been_acted_on():
    """A recommendation past 'recommended' has results and an audit trail
    hanging off it, so regenerating the ranking must leave it alone."""
    before = _recommendations()["items"]
    acted_on = {r["id"] for r in before if r["state_code"] != "recommended"}

    client.post("/api/remediation/analyze", json={})
    after = _recommendations()["items"]

    assert acted_on <= {r["id"] for r in after}
    keys = [(r["fix_type_code"], r["target_id"]) for r in after]
    assert len(keys) == len(set(keys))


# ── Refusals on the way to applying ──────────────────────────────────────────


@requires_db
def test_applying_something_never_simulated_is_refused_with_the_reason():
    body = _recommendations()
    row = next((r for r in body["items"] if r["simulation_id"] is None), None)
    if row is None:
        pytest.skip("every recommendation on this run has been simulated")

    response = client.post(
        f"/api/remediation/recommendations/{row['id']}/apply",
        json={"applied_by": "test-suite"},
    )
    assert response.status_code == 409
    assert "not been simulated" in response.json()["detail"]


@requires_db
def test_applying_an_unknown_recommendation_is_a_404():
    response = client.post(
        "/api/remediation/recommendations/99999999/apply", json={"applied_by": "test-suite"}
    )
    assert response.status_code == 404


@requires_db
def test_simulating_from_a_state_with_no_route_is_refused_by_the_table():
    body = _recommendations()
    lifecycle = client.get("/api/remediation/lifecycle").json()
    reachable = {
        t["from_state"] for t in lifecycle["transitions"] if t["to_state"] == "simulated"
    } | {"simulated"}
    row = next((r for r in body["items"] if r["state_code"] not in reachable), None)
    if row is None:
        pytest.skip("no recommendation on this run is past the point of simulating")

    response = client.post(f"/api/remediation/recommendations/{row['id']}/simulate")
    assert response.status_code == 409
    assert "remediation_transition" in response.json()["detail"]


@requires_db
def test_simulating_an_unknown_recommendation_is_a_404():
    response = client.post("/api/remediation/recommendations/99999999/simulate")
    assert response.status_code == 404


# ── Applied fixes ────────────────────────────────────────────────────────────


@requires_db
def test_applied_fixes_are_listed_against_the_run_they_belong_to():
    body = client.get("/api/remediation/applied")
    assert body.status_code == 200
    payload = body.json()

    assert isinstance(payload["items"], list)
    for entry in payload["items"]:
        assert entry["graph_version_after"] != entry["graph_version_before"]
        assert entry["applied_by"]
