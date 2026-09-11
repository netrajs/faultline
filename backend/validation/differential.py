"""Differential testing: the fast engine against the reference oracle.

``docs/RULES.md`` §7 invariant 8 -- "the engine and the reference oracle return
identical path sets on any graph small enough for the oracle to finish" -- is
the only invariant that cannot be checked by looking at one implementation.
This module checks it.

The two searches are independent readings of the same specification.
``backend/engine/search.py`` is best-first with dominance pruning, a hop cap and
a k-best allowance; ``backend/oracle/search.py`` is unpruned depth-first and
enumerates every candidate the model permits. They share the rule rows and
nothing else, which is what makes their agreement evidence rather than a
tautology.

Three things have to be said precisely, because a comparison of two different
algorithms is only as honest as its matching rule.

**What identity means.** Paths are compared on the sequence of
``(edge id, rule id, src, dst)`` per hop -- ``oracle.search.canonical_path_key``
-- with one normalisation: for a hop that consumes no edge, ``src`` is dropped.
A rule with no edge has no source. The oracle records the node the attacker was
standing on, the engine records the node the rule acted on, and the rule loader
refuses to bind such a rule's preconditions to ``src`` at all, so the field
carries no meaning for those hops and comparing it would report a labelling
convention as a disagreement. Those cases are counted separately as
``label_only_count`` rather than dropped silently.

**The two directions are not the same claim.** *Engine ⊆ reference* is
soundness: every path the engine reports was also found by an exhaustive
enumeration under the same rules, so the engine invents nothing. It is checked
against the oracle's raw output with no filter, and it is the load-bearing
half. *Reference ⊆ engine* is completeness, and it is checked against a
filtered subset of the oracle's output, because the oracle deliberately
enumerates things the engine deliberately does not report: paths carrying a hop
that contributed nothing to the arrival (the engine's minimal-proof filter
removes them, since an attack path is a proof and a proof has no spare steps),
and paths whose last hop granted only reachability, which ``docs/RULES.md`` R15
says is not arrival.

**Disagreements are reported, not resolved.** When the two differ, this module
says so and shows the path. ``docs/RULES.md`` decides which implementation is
wrong, and that is a judgement for a person reading the specification.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from core.model import AttackPath, GraphSnapshot
from engine.scoring import Scorer
from engine.search import Discovery, SearchLimits, is_minimal_proof
from oracle.search import (
    OracleBudgetExceeded,
    OracleConfig,
    canonical_path_key,
    discover,
)
from validation.world import WORLDS, ModelSource, World, load_model

__all__ = [
    "CaseReport",
    "DEFAULT_REAL_GRAPH_HOPS",
    "DEFAULT_REAL_GRAPH_NODE_CAP",
    "Disagreement",
    "DifferentialReport",
    "bounded_subgraph",
    "comparison_key",
    "run_case",
    "run_report",
    "run_snapshot_case",
]

#: Enough head-room that the k-best allowance is never what decides whether the
#: engine reported a path. The comparison is about the rules, not about a
#: display budget, and a truncated engine result would show up as a
#: completeness failure that is really a configuration choice.
COMPARISON_TOP_K = 64

#: Bounds for the case run against the real seeded graph.
#:
#: The oracle is exhaustive by design and its cost grows with the hop cap the
#: way an unpruned depth-first search does. Measured on the seeded 691-node
#: graph: 7 seconds at 2 hops, 71 seconds at 3, and beyond that it stops being
#: something a request can wait for. So the real-graph case is bounded on nodes
#: instead -- a breadth-first neighbourhood of the crown jewels and the planted
#: entry points, which keeps the graph's own structure and the material the
#: ground truth is about, rather than a random sample that would keep neither.
DEFAULT_REAL_GRAPH_NODE_CAP = 120
DEFAULT_REAL_GRAPH_HOPS = 4

#: The oracle raises rather than truncating, and the harness lets it: a
#: reference implementation that silently returns part of the answer is worse
#: than one that refuses. Raised well above the oracle's own default so the
#: bounded real-graph case is not refused for being denser than a hand-built one.
REFERENCE_STATE_BUDGET = 3_000_000

type ComparisonKey = tuple[tuple[str, int, str, str], ...]


def comparison_key(path: AttackPath) -> ComparisonKey:
    """Cross-implementation path identity. See the module docstring."""
    return tuple(
        (hop.edge_id or "", hop.rule_id, hop.src_node_id if hop.edge_id else "", hop.dst_node_id)
        for hop in path.hops
    )


@dataclass(frozen=True, slots=True)
class Disagreement:
    """One path exactly one of the two implementations found."""

    found_by: str
    """``'engine'`` or ``'reference'``."""

    target_node_id: str
    hop_count: int
    steps: tuple[str, ...]
    """One readable line per hop: where it went, over what, by which rule."""


@dataclass(frozen=True, slots=True)
class CaseReport:
    """What both implementations made of one graph."""

    code: str
    title: str
    mechanism: str
    threat_model_code: str
    node_count: int
    edge_count: int
    max_hops: int

    engine_path_count: int
    reference_path_count: int
    reference_comparable_count: int
    """Reference paths that are minimal proofs ending in a capability that counts
    as arrival -- the subset the engine is expected to report."""

    agreed_count: int
    engine_only: tuple[Disagreement, ...]
    reference_only: tuple[Disagreement, ...]
    label_only_count: int
    """Paths both found that differ only in a non-traversal hop's recorded source."""

    engine_ms: int
    reference_ms: int
    reference_states_expanded: int
    engine_truncated: bool
    error: str | None = None
    """Set when the case could not be run at all, e.g. the oracle refused the graph."""

    @property
    def agrees(self) -> bool:
        return self.error is None and not self.engine_only and not self.reference_only

    @property
    def comparable_total(self) -> int:
        """Union of what the engine reported and what it was expected to report."""
        return self.agreed_count + len(self.engine_only) + len(self.reference_only)


@dataclass(frozen=True, slots=True)
class DifferentialReport:
    cases: tuple[CaseReport, ...]
    model_origin: str
    model_detail: str
    duration_ms: int
    real_graph_case: str | None
    """The code of the case run against the seeded graph, if one was."""

    real_graph_bound: str | None
    """Plain-language statement of the bound that case was run under."""

    @property
    def agreed_total(self) -> int:
        return sum(c.agreed_count for c in self.cases)

    @property
    def comparable_total(self) -> int:
        return sum(c.comparable_total for c in self.cases)

    @property
    def disagreement_count(self) -> int:
        return sum(len(c.engine_only) + len(c.reference_only) for c in self.cases)

    @property
    def agreement_rate(self) -> float | None:
        """Agreed paths over the union of both implementations' comparable sets.

        ``None`` rather than 1.0 when nothing was comparable: a harness that
        found no paths at all has not demonstrated agreement, and reporting
        perfect agreement over an empty set is the most misleading number this
        module could produce.
        """
        total = self.comparable_total
        return self.agreed_total / total if total else None

    @property
    def cases_agreeing(self) -> int:
        return sum(1 for c in self.cases if c.agrees)


# ── Running one case ─────────────────────────────────────────────────────────


def run_snapshot_case(
    *,
    code: str,
    title: str,
    mechanism: str,
    snapshot: GraphSnapshot,
    threat_model_code: str,
    max_hops: int,
    model: ModelSource,
) -> CaseReport:
    """Run both implementations over one graph and compare what they found."""
    engine = Discovery(
        snapshot,
        model.engine_ruleset,
        Scorer(model.scoring),
        SearchLimits(max_hops=max_hops, top_k=COMPARISON_TOP_K),
    )

    started = time.perf_counter()
    engine_result = engine.run(threat_model_code)
    engine_ms = int((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    try:
        reference = discover(
            snapshot,
            model.oracle_ruleset,
            OracleConfig(
                threat_model_code=threat_model_code,
                max_hops=max_hops,
                max_states=REFERENCE_STATE_BUDGET,
            ),
        )
    except OracleBudgetExceeded as exc:
        return CaseReport(
            code=code,
            title=title,
            mechanism=mechanism,
            threat_model_code=threat_model_code,
            node_count=len(snapshot),
            edge_count=len(list(snapshot.all_edges)),
            max_hops=max_hops,
            engine_path_count=len(engine_result.paths),
            reference_path_count=0,
            reference_comparable_count=0,
            agreed_count=0,
            engine_only=(),
            reference_only=(),
            label_only_count=0,
            engine_ms=engine_ms,
            reference_ms=int((time.perf_counter() - started) * 1000),
            reference_states_expanded=0,
            engine_truncated=engine_result.truncated,
            error=str(exc),
        )
    reference_ms = int((time.perf_counter() - started) * 1000)

    rule_codes = {rule.rule_id: rule.code for rule in model.engine_ruleset.rules}
    engine_keys = {comparison_key(p): p for p in engine_result.paths}
    reference_keys = {comparison_key(p): p for p in reference.paths}
    comparable = {
        key: path
        for key, path in reference_keys.items()
        if _is_comparable(path, engine, model)
    }

    agreed = engine_keys.keys() & comparable.keys()
    engine_only = sorted(engine_keys.keys() - reference_keys.keys())
    reference_only = sorted(comparable.keys() - engine_keys.keys())

    # Raw keys, before the non-traversal source is normalised away. The
    # difference between the two counts is how many paths both implementations
    # found and labelled differently, which is worth stating rather than hiding
    # inside the normalisation.
    raw_engine = {canonical_path_key(p) for p in engine_result.paths}
    raw_reference = {canonical_path_key(p) for p in reference.paths}
    label_only = len(agreed) - len(raw_engine & raw_reference)

    return CaseReport(
        code=code,
        title=title,
        mechanism=mechanism,
        threat_model_code=threat_model_code,
        node_count=len(snapshot),
        edge_count=len(list(snapshot.all_edges)),
        max_hops=max_hops,
        engine_path_count=len(engine_result.paths),
        reference_path_count=len(reference.paths),
        reference_comparable_count=len(comparable),
        agreed_count=len(agreed),
        engine_only=tuple(
            _disagreement("engine", engine_keys[key], rule_codes) for key in engine_only
        ),
        reference_only=tuple(
            _disagreement("reference", comparable[key], rule_codes) for key in reference_only
        ),
        label_only_count=max(0, label_only),
        engine_ms=engine_ms,
        reference_ms=reference_ms,
        reference_states_expanded=reference.states_expanded,
        engine_truncated=engine_result.truncated,
    )


def run_case(world: World, model: ModelSource) -> CaseReport:
    return run_snapshot_case(
        code=world.code,
        title=world.title,
        mechanism=world.mechanism,
        snapshot=world.build(),
        threat_model_code=world.threat_model_code,
        max_hops=world.max_hops,
        model=model,
    )


def _is_comparable(path: AttackPath, engine: Discovery, model: ModelSource) -> bool:
    """Whether the engine is expected to report this reference path.

    Two exclusions, both of them things the engine declines to report on
    purpose. A path whose last hop granted nothing that counts as arrival never
    arrived: ``docs/RULES.md`` R15 is explicit that network adjacency grants
    reachability and not access, so standing next to a crown jewel is not
    reaching it. And a path with a hop that supplied nothing the arrival
    depended on is a side excursion that happened to be affordable rather than
    a step the attack needed -- the oracle enumerates those because it prunes
    nothing, which is the point of it.
    """
    last = path.hops[-1]
    arrival = frozenset(
        cap
        for cap in last.gained
        if cap.about == path.target_node_id and cap.code in engine.goal_codes
    )
    if not arrival:
        return False
    return is_minimal_proof(path.hops, arrival, model.engine_ruleset)


def _disagreement(
    found_by: str, path: AttackPath, rule_codes: Mapping[int, str]
) -> Disagreement:
    steps = []
    for hop in path.hops:
        rule = rule_codes.get(hop.rule_id, f"rule {hop.rule_id}")
        if hop.edge_id:
            steps.append(f"{hop.src_node_id} -> {hop.dst_node_id} via {hop.edge_id} ({rule})")
        else:
            steps.append(f"{hop.dst_node_id} with no edge ({rule})")
    return Disagreement(
        found_by=found_by,
        target_node_id=path.target_node_id,
        hop_count=len(path.hops),
        steps=tuple(steps),
    )


# ── The bounded real-graph case ──────────────────────────────────────────────


def bounded_subgraph(
    snapshot: GraphSnapshot, seeds: Sequence[str], node_cap: int
) -> GraphSnapshot:
    """A breadth-first neighbourhood of *seeds*, capped at *node_cap* nodes.

    Grown in both directions. Backwards reaches the principals and groups a
    target is reachable from; forwards keeps the credentials and vulnerabilities
    hanging off a host, which are part of the mechanism even though they point
    away from the goal. Neighbours are taken in id order and the seeds are used
    in the order given, so the same graph and the same cap always produce the
    same subgraph.
    """
    if node_cap < 1:
        raise ValueError(f"node_cap must be at least 1, got {node_cap}")

    kept: set[str] = set()
    frontier: deque[str] = deque()
    for seed in seeds:
        if seed in kept or snapshot.get_node(seed) is None:
            continue
        kept.add(seed)
        frontier.append(seed)

    while frontier and len(kept) < node_cap:
        current = frontier.popleft()
        neighbours = {e.src_id for e in snapshot.in_edges(current)}
        neighbours |= {e.dst_id for e in snapshot.out_edges(current)}
        for neighbour in sorted(neighbours):
            if neighbour in kept:
                continue
            if len(kept) >= node_cap:
                break
            kept.add(neighbour)
            frontier.append(neighbour)

    return GraphSnapshot(
        snapshot.graph_version,
        [snapshot.node(node_id) for node_id in sorted(kept)],
        [e for e in snapshot.all_edges if e.src_id in kept and e.dst_id in kept],
    )


# ── The whole report ─────────────────────────────────────────────────────────


def run_report(
    *,
    model: ModelSource | None = None,
    real_graph: GraphSnapshot | None = None,
    real_graph_seeds: Iterable[str] = (),
    real_graph_threat_model: str | None = None,
    node_cap: int = DEFAULT_REAL_GRAPH_NODE_CAP,
    max_hops: int = DEFAULT_REAL_GRAPH_HOPS,
) -> DifferentialReport:
    """Run every hand-built case, and the seeded graph too when one is supplied."""
    model = model or load_model()
    started = time.perf_counter()

    cases = [run_case(world, model) for world in WORLDS]

    real_case_code: str | None = None
    bound: str | None = None
    if real_graph is not None:
        seeds = list(real_graph_seeds) or sorted(real_graph.crown_jewels)
        subgraph = bounded_subgraph(real_graph, seeds, node_cap)
        threat_model_code = (
            real_graph_threat_model
            or model.oracle_ruleset.default_threat_model().code
        )
        real_case_code = f"seeded_graph_v{real_graph.graph_version}"
        bound = (
            f"{len(subgraph)} of {len(real_graph)} nodes -- a breadth-first neighbourhood "
            f"of the crown jewels and the planted entry points, capped at {node_cap} nodes "
            f"and {max_hops} hops. The reference oracle enumerates every candidate without "
            f"pruning, which on the full graph is minutes rather than seconds."
        )
        cases.append(
            run_snapshot_case(
                code=real_case_code,
                title=f"Seeded graph, bounded (version {real_graph.graph_version})",
                mechanism=(
                    "The real generated graph rather than a hand-built one, bounded so the "
                    "unpruned reference search can finish."
                ),
                snapshot=subgraph,
                threat_model_code=threat_model_code,
                max_hops=max_hops,
                model=model,
            )
        )

    return DifferentialReport(
        cases=tuple(cases),
        model_origin=model.origin,
        model_detail=model.detail,
        duration_ms=int((time.perf_counter() - started) * 1000),
        real_graph_case=real_case_code,
        real_graph_bound=bound,
    )
