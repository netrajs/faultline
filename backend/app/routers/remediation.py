"""Remediation endpoints: rank fixes, simulate one, apply one.

Thin on purpose. Everything that decides anything lives under
``backend/remediation`` -- the greedy set cover and the Dinic min-cut
(``chokepoints``, ``cuts``), the priority formula and the dependency analysis
(``recommend``), the copy-on-write counterfactual and its re-derivation
(``overlay``, ``simulate``), and the state machine read out of
``remediation_state``/``remediation_transition`` (``lifecycle``). This module
resolves which analysis run is being talked about, calls into those, and shapes
the result for the wire. No ranking, no thresholds and no state rules are
restated here, because a second copy of a rule is a second thing to get wrong.

Three arrangements are worth stating outright.

**Ranking is a write, and it is explicit.** ``POST /analyze`` is what produces
the ``chokepoint`` and ``recommendation`` rows for a run; the ``GET`` endpoints
only read them back. A ``GET`` that quietly computed and inserted when it found
nothing would make an empty screen indistinguishable from a screen that had
just silently rewritten the ranking underneath somebody's open simulation.

**Simulation is started, not awaited.** ``docs/SCOPE.md`` D6 requires
re-derivation from scratch against the mutated graph under the baseline run's
own search limits, and on this graph that is the same three minutes the baseline
run took -- far past any proxy's patience, which is why ``POST .../simulate``
returns ``202`` with a job and the detail endpoint reports its progress.

The obvious way to make it fast is to re-search only the entry-to-target pairs
the mutation "must" have affected. That is precisely the shortcut D6 exists to
forbid, and the first real run on this graph shows why: downgrading one
permission removed four paths and *created eight*, from sources with no
relationship to the edge that changed -- a new starter reaching a domain
controller, a cloud engineer reaching a secrets store. A pair-scoped re-run finds
none of those and reports the fix as a clean win. ``Discovery.run`` takes a
threat model and derives its own entries and crown jewels for the same reason.

So the cost is paid, and it is paid out of band. The job lives in this process
rather than in a table: it is a fact about what this server is doing right now,
not a result, and a restart that loses it leaves a recommendation that was never
simulated -- which is true, and is what the interface then shows.

**Chokepoints are not served from here.** ``GET /api/chokepoints`` in
``app.routers.paths`` already reads the ``chokepoint`` table for the latest run
and is what the frontend consumes; ``POST /analyze`` below is the writer that
fills it. Adding a second read endpoint under this prefix would leave two routes
answering the same question from the same table.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

from app.db import fetch_all
from audit.log import append_entry
from core.ids import graph_hash
from engine.snapshot import load_snapshot
from remediation import store
from remediation.lifecycle import (
    ApprovalRequired,
    Lifecycle,
    LifecycleError,
    advance,
    load_lifecycle,
    path_between,
)
from remediation.overlay import MutationError
from remediation.recommend import recommend
from remediation.simulate import counterfactual, simulate

log = logging.getLogger("faultline.remediation")

router = APIRouter(prefix="/api/remediation", tags=["remediation"])

#: How many chokepoints the ranking pass considers. Every one of them is offered
#: to every applicable fix, so this is a ceiling on candidates rather than on
#: recommendations -- a chokepoint no fix applies to produces no row at all.
_RANKING_LIMIT = 20

#: Delta rows returned with a simulation. A run over twenty paths cannot exceed
#: it; a large one can, and the response says how many were left out rather than
#: truncating silently.
_DELTA_LIMIT = 200

_NO_RUN = (
    "No completed discovery run for the active graph, so there is nothing to "
    "recommend against. Run: python -m engine.discover --threat-model external_phish"
)

#: How long a finished job stays readable before it is forgotten. Long enough
#: that a browser which was closed mid-run still finds the outcome when it comes
#: back; the result itself is in ``simulation`` either way, so this only governs
#: whether the *failure* of a run is still explainable.
_JOB_RETENTION_SECONDS = 3600


@dataclass
class _SimulationJob:
    """One in-flight or recently finished re-derivation, as this process sees it."""

    recommendation_id: int
    status: str
    """'queued' | 'running' | 'complete' | 'failed'."""

    started_at: datetime
    finished_at: datetime | None = None
    error: str | None = None
    simulation_id: int | None = None

    def payload(self) -> dict[str, Any]:
        end = self.finished_at or datetime.now(timezone.utc)
        return {
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "finished_at": None if self.finished_at is None else self.finished_at.isoformat(),
            "elapsed_ms": int((end - self.started_at).total_seconds() * 1000),
            "error": self.error,
            "simulation_id": self.simulation_id,
        }


#: One worker on purpose. A re-derivation is CPU-bound for minutes, and running
#: two at once makes both slower without finishing either sooner; a second
#: request queues behind the first and is told so.
_SIMULATION_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="remediation-sim")
_JOBS: dict[int, _SimulationJob] = {}
_JOBS_LOCK = threading.Lock()


def _job_for(recommendation_id: int) -> _SimulationJob | None:
    now = datetime.now(timezone.utc)
    with _JOBS_LOCK:
        for key, job in list(_JOBS.items()):
            if (
                job.finished_at is not None
                and (now - job.finished_at).total_seconds() > _JOB_RETENTION_SECONDS
            ):
                del _JOBS[key]
        return _JOBS.get(recommendation_id)


def _run_simulation_job(recommendation_id: int) -> None:
    """The worker body. Owns its own failures: nothing above it is waiting."""
    with _JOBS_LOCK:
        job = _JOBS.get(recommendation_id)
        if job is None:
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)

    try:
        outcome = simulate(recommendation_id)
    except Exception as exc:  # noqa: BLE001 - recorded and served, not swallowed
        log.exception("simulation failed for recommendation %s", recommendation_id)
        with _JOBS_LOCK:
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = datetime.now(timezone.utc)
        return

    recommendation = store.load_recommendation(recommendation_id)
    if recommendation is not None:
        append_entry(
            "fix_simulated",
            _actor(),
            {
                "recommendation_id": recommendation_id,
                "fix_type_code": recommendation["fix_type_code"],
                "target_kind": recommendation["target_kind"],
                "target_id": recommendation["target_id"],
                "simulation_id": outcome.simulation_id,
                "simulated_run_id": outcome.simulated_run_id,
                "paths_removed": len(outcome.diff.removed),
                "paths_added": len(outcome.diff.added),
                "paths_rescored": len(outcome.diff.rescored),
                "truncated": outcome.truncated,
                # Committed to before reality is consulted, so a later
                # verification cannot be retro-fitted to whatever the apply step
                # produced.
                "prediction_hash": outcome.diff.prediction_hash,
            },
            target_kind="recommendation",
            target_id=str(recommendation_id),
            graph_version_id=outcome.child_graph_version,
            scoring_version=str(recommendation["scoring_version"]),
            risk_before=outcome.risk_before,
            risk_after=outcome.risk_after,
        )

    with _JOBS_LOCK:
        job.status = "complete"
        job.simulation_id = outcome.simulation_id
        job.finished_at = datetime.now(timezone.utc)


class AnalyzeRequest(BaseModel):
    run_id: int | None = Field(default=None, ge=1)
    limit: int = Field(default=_RANKING_LIMIT, ge=1, le=100)


class ApplyRequest(BaseModel):
    """Who is applying, and who signed for it.

    ``approved_by`` stands in for the EIP-712 signature ``docs/SCOPE.md`` D7
    describes and is recorded as a name, not presented as an authorisation it is
    not. ``lifecycle.check`` is what decides whether one is required here, from
    ``remediation_transition.needs_approval`` and ``fix_type.requires_approval``
    -- this endpoint never makes that call itself.
    """

    applied_by: str = Field(min_length=1, max_length=191)
    approved_by: str | None = Field(default=None, max_length=191)


# ── Run resolution ───────────────────────────────────────────────────────────


def _run_for(run_id: int | None) -> dict:
    """The run under discussion: the one asked for, or the current baseline."""
    if run_id is not None:
        run = store.load_run(run_id)
        if not run:
            raise HTTPException(404, f"No analysis run {run_id}.")
        return run
    run = store.latest_run()
    if not run:
        raise HTTPException(404, _NO_RUN)
    return run


def _envelope(run: dict) -> dict[str, Any]:
    """The provenance every response carries.

    Recommendations are only comparable within a run -- they were ranked against
    one graph version, one scoring version and one threat model -- so the numbers
    on screen always arrive with the run that produced them.
    """
    return {
        "analysis_run_id": run["id"],
        "graph_version_id": run["graph_version_id"],
        "scoring_version": run["scoring_version"],
        "threat_model_code": run["threat_model_code"],
        "total_paths": run["path_count"],
        "crown_jewels_reached": run["crown_jewels_reached"],
        "max_risk_score": (
            None if run["max_risk_score"] is None else float(run["max_risk_score"])
        ),
    }


# ── Ranking ──────────────────────────────────────────────────────────────────


@router.post("/analyze")
def analyze(request: AnalyzeRequest | None = None) -> dict:
    """Rank the run's chokepoints, cost them, and write the recommendations.

    Rewrites both rankings wholesale for this run. ``replace_recommendations``
    leaves anything past ``recommended`` alone, so regenerating cannot delete a
    recommendation somebody has already simulated, approved or applied -- those
    have results and an audit trail hanging off them.
    """
    request = request or AnalyzeRequest()
    run = _run_for(request.run_id)
    run_id = int(run["id"])

    paths = store.load_path_coverage(run_id)
    if not paths:
        raise HTTPException(
            409,
            f"Analysis run {run_id} discovered no paths, so there are no "
            "chokepoints to cut and nothing to recommend.",
        )

    try:
        fix_types = store.load_fix_types()
    except store.RemediationDataError as exc:
        raise HTTPException(409, str(exc)) from exc

    snapshot = load_snapshot(int(run["graph_version_id"]))
    rows, analysis = recommend(snapshot, paths, fix_types, limit=request.limit)

    try:
        lifecycle = load_lifecycle()
    except LifecycleError as exc:
        raise HTTPException(409, str(exc)) from exc

    store.replace_chokepoints(run_id, analysis.chokepoints)
    inserted = store.replace_recommendations(
        run_id, rows, initial_state=lifecycle.initial_state
    )

    return {
        **_envelope(run),
        "chokepoints_ranked": len(analysis.chokepoints),
        "recommendations_written": len(inserted),
        "recommendations_total": len(store.load_recommendations(run_id)),
        # The one exact number in the ranking: how many nodes it would take to
        # sever every discovered path. A greedy node selection larger than this
        # is visibly leaving something on the table, which is why it is served
        # next to the approximate one rather than kept internal.
        "min_cut_size": analysis.min_cut.size,
        "min_cut_vertices": list(analysis.min_cut.vertices),
    }


@router.get("/recommendations")
def recommendations(
    run_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """The ranked list for one run, highest priority first.

    An empty ``items`` means exactly that: either the ranking has never been
    computed for this run, or no fix in ``fix_type`` applies to any of its
    chokepoints. ``has_ranking`` separates the two so the interface can say
    which, instead of showing one blank panel for both.
    """
    run = _run_for(run_id)
    run_id_int = int(run["id"])
    items = store.floatify_all(store.load_recommendations(run_id_int, limit=limit))
    return {
        **_envelope(run),
        "items": items,
        "has_ranking": bool(store.load_chokepoints(run_id_int, limit=1)),
    }


@router.get("/lifecycle")
def lifecycle() -> dict:
    """The states and the transitions between them, as rows.

    Served so the interface labels and colours a state from the table that
    defines it rather than from a map hardcoded in the frontend (D12), and so
    the actions it offers on a recommendation are the ones the table actually
    allows.
    """
    try:
        loaded = load_lifecycle()
    except LifecycleError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {
        "states": [
            {
                "code": state.code,
                "label": state.label,
                "description": state.description,
                "is_terminal": state.is_terminal,
                "ui_color": state.ui_color,
                "sort_order": state.sort_order,
            }
            for state in sorted(loaded.states.values(), key=lambda s: s.sort_order)
        ],
        "transitions": [
            {
                "from_state": transition.from_state,
                "to_state": transition.to_state,
                "label": transition.label,
                "needs_approval": transition.needs_approval,
            }
            for _, transition in sorted(loaded.transitions.items())
        ],
        "initial_state": loaded.initial_state,
    }


# ── One recommendation ───────────────────────────────────────────────────────


@router.get("/recommendations/{recommendation_id}")
def detail(recommendation_id: int = Path(ge=1)) -> dict:
    """One recommendation with its collateral, its simulation and what it can do next."""
    recommendation = store.load_recommendation(recommendation_id)
    if recommendation is None:
        raise HTTPException(404, f"No recommendation {recommendation_id}.")
    try:
        loaded = load_lifecycle()
    except LifecycleError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _detail_payload(recommendation, loaded)


@router.post("/recommendations/{recommendation_id}/simulate", status_code=202)
def run_simulation(recommendation_id: int = Path(ge=1)) -> dict:
    """Start a re-derivation and return the job, not the result.

    Every refusal is decided here, before anything is queued, so a caller that
    is going to be told no is told no immediately rather than minutes later by a
    background worker it cannot see. The expensive part then runs off-request and
    is followed through the ``simulation_run`` block on the detail endpoint.
    """
    recommendation = store.load_recommendation(recommendation_id)
    if recommendation is None:
        raise HTTPException(404, f"No recommendation {recommendation_id}.")

    try:
        loaded = load_lifecycle()
    except LifecycleError as exc:
        raise HTTPException(409, str(exc)) from exc

    current = str(recommendation["state_code"])
    route = path_between(loaded, current, "simulated")
    if not route:
        raise HTTPException(
            409,
            f"This recommendation is {current}, and remediation_transition offers "
            f"no route from there to simulated. From {current} the table allows: "
            f"{', '.join(t.to_state for t in loaded.allowed_from(current)) or '(nothing)'}.",
        )
    try:
        advance(loaded, recommendation, route)
    except ApprovalRequired as exc:
        raise HTTPException(403, str(exc)) from exc
    except LifecycleError as exc:
        raise HTTPException(409, str(exc)) from exc

    # Built here rather than in the worker so that a mutation this fix could
    # never make is a 422 on the request that asked for it.
    try:
        fix_types = store.load_fix_types()
        fix = fix_types.get(str(recommendation["fix_type_code"]))
        if fix is not None:
            fix.mutation_for(
                str(recommendation["target_kind"]), str(recommendation["target_id"])
            )
    except MutationError as exc:
        raise HTTPException(
            422,
            f"This fix cannot be applied to {recommendation['target_id']}: {exc}",
        ) from exc
    except store.RemediationDataError as exc:
        raise HTTPException(409, str(exc)) from exc

    with _JOBS_LOCK:
        existing = _JOBS.get(recommendation_id)
        if existing is not None and existing.status in ("queued", "running"):
            raise HTTPException(
                409,
                f"A simulation of recommendation {recommendation_id} is already "
                f"{existing.status}. Wait for it rather than starting a second "
                "re-derivation of the same fix.",
            )
        job = _SimulationJob(
            recommendation_id=recommendation_id,
            status="queued",
            started_at=datetime.now(timezone.utc),
        )
        _JOBS[recommendation_id] = job

    _SIMULATION_POOL.submit(_run_simulation_job, recommendation_id)
    return {
        "recommendation_id": recommendation_id,
        "simulation_run": job.payload(),
        "note": (
            "The whole graph is being searched again with this change applied, "
            "under the baseline run's own limits. Follow it on the "
            "recommendation's detail endpoint."
        ),
    }


@router.post("/recommendations/{recommendation_id}/apply")
def apply_fix(request: ApplyRequest, recommendation_id: int = Path(ge=1)) -> dict:
    """Perform the mutation against a new graph version, recording how to undo it.

    Every refusal on the way in comes from data rather than from a condition
    written here: whether the route exists at all and whether it needs a
    signature are both read out of ``remediation_transition``, and the rule that
    an unsimulated fix cannot be applied is enforced by the absence of a
    ``recommended -> applied`` edge in that table -- this endpoint only explains
    it.

    The mutated graph is written as a *new, inactive* version. Activating it
    would retarget every screen in the product at a graph no baseline run has
    been computed against; the honest sequence is apply, then re-derive against
    the new version, then compare. ``applied_fix.rollback_payload`` carries the
    exact prior state of whatever was touched, so reverting restores rather than
    reconstructs.
    """
    recommendation = store.load_recommendation(recommendation_id)
    if recommendation is None:
        raise HTTPException(404, f"No recommendation {recommendation_id}.")

    try:
        loaded = load_lifecycle()
    except LifecycleError as exc:
        raise HTTPException(409, str(exc)) from exc

    current = str(recommendation["state_code"])
    route = path_between(loaded, current, "applied")
    if not route:
        raise HTTPException(
            409,
            f"This recommendation is {current}, and remediation_transition offers "
            f"no route from there to applied. From {current} the table allows: "
            f"{', '.join(t.to_state for t in loaded.allowed_from(current)) or '(nothing)'}.",
        )

    simulation = store.latest_simulation(recommendation_id)
    if simulation is None:
        raise HTTPException(
            409,
            "This fix has not been simulated. Applying an unsimulated change "
            "leaves no prediction to verify the result against, which removes "
            "the one check that would catch a wrong simulation.",
        )

    try:
        advance(loaded, recommendation, route, approved_by=request.approved_by)
    except ApprovalRequired as exc:
        raise HTTPException(403, str(exc)) from exc
    except LifecycleError as exc:
        raise HTTPException(409, str(exc)) from exc

    try:
        mutated, mutation = counterfactual(recommendation)
    except MutationError as exc:
        raise HTTPException(
            422,
            f"This fix cannot be applied to {recommendation['target_id']}: {exc}",
        ) from exc

    import json

    node_rows = mutated.node_rows()
    edge_rows = mutated.edge_rows()
    version_before = int(recommendation["graph_version_id"])
    version_after = store.insert_graph_version(
        label=f"applied: {mutation.description}"[:128],
        parent_id=version_before,
        canonical_hash=graph_hash(node_rows, edge_rows),
        node_count=len(node_rows),
        edge_count=len(edge_rows),
        notes=(
            f"Graph after applying recommendation {recommendation_id} "
            f"({recommendation['fix_type_code']}). Materialised in both stores, "
            "unlike a simulation's child version, because verification has to "
            "re-derive against a graph read back from storage rather than "
            "against the object that produced the prediction."
        ),
    )
    store.materialise_graph_version(version_after, node_rows, edge_rows)

    applied_fix_id = store.insert_applied_fix(
        recommendation_id=recommendation_id,
        simulation_id=int(simulation["id"]),
        applied_by=request.applied_by,
        graph_version_before=version_before,
        graph_version_after=version_after,
        rollback_payload=json.dumps(mutated.rollback_payload(), sort_keys=True),
        state_code="applied",
    )
    store.set_recommendation_state(recommendation_id, "applied")

    risk_before = _as_float(simulation["risk_before"])
    risk_after = _as_float(simulation["risk_after"])
    append_entry(
        "fix_applied",
        request.applied_by,
        {
            "recommendation_id": recommendation_id,
            "applied_fix_id": applied_fix_id,
            "fix_type_code": recommendation["fix_type_code"],
            "mutation": mutation.description,
            "route": list(route),
            "approved_by": request.approved_by,
            "simulation_id": int(simulation["id"]),
            "prediction_hash": simulation["prediction_hash"],
            "graph_version_before": version_before,
            "graph_version_after": version_after,
        },
        target_kind="recommendation",
        target_id=str(recommendation_id),
        graph_version_id=version_after,
        scoring_version=str(recommendation["scoring_version"]),
        risk_before=risk_before,
        risk_after=risk_after,
    )

    refreshed = store.load_recommendation(recommendation_id)
    payload = _detail_payload(refreshed or recommendation, loaded)
    payload["applied"] = {
        "applied_fix_id": applied_fix_id,
        "applied_by": request.applied_by,
        "approved_by": request.approved_by,
        "route": list(route),
        "mutation": mutation.description,
        "graph_version_before": version_before,
        "graph_version_after": version_after,
        "graph_version_after_is_active": False,
        "node_count": len(node_rows),
        "edge_count": len(edge_rows),
    }
    return payload


@router.get("/applied")
def applied(run_id: int | None = Query(default=None, ge=1)) -> dict:
    """Fixes applied against one run's recommendations, newest first."""
    run = _run_for(run_id)
    return {
        **_envelope(run),
        "items": store.floatify_all(store.load_applied_fixes(int(run["id"]))),
    }


# ── Shaping ──────────────────────────────────────────────────────────────────


def _detail_payload(recommendation: dict, loaded: Lifecycle) -> dict[str, Any]:
    recommendation_id = int(recommendation["id"])
    state = str(recommendation["state_code"])
    requires_approval = bool(recommendation.get("requires_approval"))

    job = _job_for(recommendation_id)
    simulation = store.latest_simulation(recommendation_id)
    deltas: list[dict] = []
    delta_total = 0
    runs: dict[str, Any] | None = None
    if simulation is not None:
        rows = store.load_simulation_deltas(int(simulation["id"]))
        delta_total = len(rows)
        deltas = _describe_deltas(
            store.floatify_all(rows[:_DELTA_LIMIT]),
            baseline_run_id=int(simulation["baseline_run_id"]),
            simulated_run_id=int(simulation["simulated_run_id"]),
            graph_version_id=int(recommendation["graph_version_id"]),
        )
        # Both runs' own rows, so the interface can state that the counterfactual
        # was searched under the baseline's limits rather than asking the reader
        # to take it on trust. A re-derivation under a different hop cap would
        # produce removals and additions that are artefacts of the cap.
        runs = {
            "baseline": _run_summary(int(simulation["baseline_run_id"])),
            "simulated": _run_summary(int(simulation["simulated_run_id"])),
        }

    return {
        "recommendation": store.floatify(recommendation),
        "dependencies": store.load_dependencies(recommendation_id),
        "simulation": None if simulation is None else store.floatify(simulation),
        # Whether this server is re-deriving right now, which is not the same
        # question as whether a simulation exists. Null means no run has been
        # started from this process -- including after a restart, when the
        # honest answer is that nothing is in flight here.
        "simulation_run": None if job is None else job.payload(),
        "runs": runs,
        "deltas": deltas,
        "delta_total": delta_total,
        "delta_limit": _DELTA_LIMIT,
        "transitions": [
            {
                "to_state": transition.to_state,
                "label": transition.label,
                "needs_approval": transition.needs_approval,
                # Both halves matter: the transition decides whether an approval
                # belongs on this step at all, the fix type decides whether it
                # has to be a real signature.
                "requires_approver": transition.needs_approval and requires_approval,
            }
            for transition in loaded.allowed_from(state)
        ],
        "applied_fix": store.floatify_all(
            fetch_all(
                """
                SELECT id, simulation_id, applied_by, graph_version_before,
                       graph_version_after, verification_run_id,
                       fidelity_exact_match, fidelity_jaccard, unexpected_paths,
                       state_code, applied_at, verified_at
                FROM applied_fix WHERE recommendation_id = :i ORDER BY id DESC
                """,
                {"i": recommendation_id},
            )
        ),
    }


def _run_summary(run_id: int) -> dict | None:
    row = fetch_all(
        """
        SELECT id, graph_version_id, purpose, max_hops, top_k_per_pair, path_count,
               rejected_count, crown_jewels_reached, max_risk_score, duration_ms,
               status, started_at
        FROM analysis_run WHERE id = :i
        """,
        {"i": run_id},
    )
    return store.floatify(row[0]) if row else None


def _describe_deltas(
    rows: list[dict],
    *,
    baseline_run_id: int,
    simulated_run_id: int,
    graph_version_id: int,
) -> list[dict]:
    """Attach each changed path's endpoints, so the diff reads as attacks, not ids.

    A removed path exists only in the baseline run and an added one only in the
    simulated run, so both runs are consulted. Names come from the baseline graph
    version: it is the one the reader is looking at, and every node the mutation
    did not touch carries the same name in both.
    """
    wanted = {row["path_id"] for row in rows}
    if not wanted:
        return rows

    paths: dict[str, dict] = {}
    for path in fetch_all(
        """
        SELECT p.path_id, p.analysis_run_id, p.source_node_id, p.target_node_id,
               p.hop_count, p.risk_tier_code, p.target_is_crown_jewel,
               COALESCE(sn.display_name, sn.name, p.source_node_id) AS source_name,
               COALESCE(tn.display_name, tn.name, p.target_node_id) AS target_name
        FROM discovered_path p
        LEFT JOIN node sn ON sn.node_id = p.source_node_id AND sn.graph_version_id = :gv
        LEFT JOIN node tn ON tn.node_id = p.target_node_id AND tn.graph_version_id = :gv
        WHERE p.analysis_run_id IN (:baseline, :simulated)
        """,
        {"gv": graph_version_id, "baseline": baseline_run_id, "simulated": simulated_run_id},
    ):
        path_id = str(path["path_id"])
        if path_id not in wanted:
            continue
        # Baseline first: a rescored path is in both runs, and the endpoints are
        # the same either way, so whichever lands first is the same fact.
        if path_id not in paths or int(path["analysis_run_id"]) == baseline_run_id:
            paths[path_id] = path

    for row in rows:
        path = paths.get(str(row["path_id"]))
        row["source_node_id"] = None if path is None else path["source_node_id"]
        row["target_node_id"] = None if path is None else path["target_node_id"]
        row["source_name"] = None if path is None else path["source_name"]
        row["target_name"] = None if path is None else path["target_name"]
        row["hop_count"] = None if path is None else path["hop_count"]
        row["risk_tier_code"] = None if path is None else path["risk_tier_code"]
        row["target_is_crown_jewel"] = (
            None if path is None else path["target_is_crown_jewel"]
        )
    return rows


def _as_float(value: Any) -> float | None:
    return None if value is None else float(value)


def _actor() -> str:
    """Who the audit log records for an action with no authenticated user.

    There is no authentication in front of this API, so inventing a person's
    name here would put a fiction in a tamper-evident record. The service names
    itself instead.
    """
    return "faultline-api"
