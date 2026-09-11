"""Blast radius: probability-weighted reachability from one compromised node.

Same attacker model as discovery — the rule rows, the precondition evaluator and
the log-space scorer are all the ones in ``engine.rules``,
``engine.preconditions`` and ``engine.scoring``. What differs is the question.

Discovery asks "what is the best way in to *this* crown jewel", so it is a
best-first search with a goal set and it can stop when the goals are covered.
Blast radius asks "assume this one node is already lost — what else follows",
which has no goal at all. The search therefore runs to exhaustion within a hop
cap, and instead of emitting ranked paths it keeps, for every node it ever
touches, the single most probable way of getting there.

Three consequences shape the implementation.

**It is Dijkstra, not shortest-path-to-a-target.** The hop weight is
``-ln p_succ``, non-negative and additive, so the cost of a chain is the
negative log of the product of its per-hop probabilities and minimising the sum
maximises the product. Every node encountered records the lowest cost seen for
it, which is the highest ``p_reach``. A node reachable three ways keeps the best
one, and its recorded depth is the length of *that* witness rather than the
shortest chain that happens to arrive — depth and probability have to describe
the same path or the pair is meaningless.

**Without dominance pruning this does not terminate usefully.** The state space
is a DAG only because capabilities are never lost (``docs/RULES.md`` §1.2), so a
transition that grants nothing new is dropped outright and a state whose
capability set is a subset of one already expanded at no greater cost is
dropped too (§1.3). That is what stops the trust cycles in a real graph from
becoming search cycles.

**Origin state is "this node, wholly lost", derived rather than named.** The
attacker is granted every node-scoped capability atom in ``capability_atom``
about the origin, so nothing here needs to know which atom means "compromised"
for a Host as opposed to a Database — that list is data (``docs/SCOPE.md`` D12).
Globally-scoped atoms are deliberately *not* granted: ``authenticated`` is held
by anyone with any directory identity, so folding it in would put every
weak-SPN service account in the kerberoasting range of every origin, and the
result would stop being attributable to the origin. For the same reason, rules
with no capability precondition at all are not offered. R8 — a credential in a
public repository — fires from the empty state, so it belongs to every node's
blast radius equally, which is to say it belongs to none of them; it is
discovery's business, not this one's.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Iterator, Mapping, Sequence

from core.ids import path_id
from core.model import (
    AttackerState,
    Binding,
    Capability,
    Edge,
    GraphSnapshot,
    Hop,
    Node,
    PreconditionKind,
    Rule,
)
from engine.preconditions import first_failure
from engine.rules import RuleSet
from engine.scoring import Scorer
from engine.search import DOMINANCE_HISTORY, REACHABILITY_ONLY

#: Hop cap when the caller names none. Discovery's own cap is eight
#: (``SearchLimits.max_hops``), and it can afford it because a goal set bounds
#: the useful frontier. Blast radius has no goal, so the frontier is bounded
#: only by this number — and past six hops on a graph of this density the tail
#: is chains whose probability has already collapsed below anything worth
#: showing. The value is a parameter on every entry point; this is only what a
#: caller gets for not choosing.
DEFAULT_MAX_DEPTH = 6

OUTBOUND = "outbound"
INBOUND = "inbound"
BOTH = "both"
DIRECTIONS = (OUTBOUND, INBOUND, BOTH)


class BlastRadiusError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BlastLimits:
    max_depth: int = DEFAULT_MAX_DEPTH
    max_expansions: int = 200_000


@dataclass(frozen=True, slots=True)
class ReachedNode:
    """One node the origin's compromise leads to, and the best way there.

    ``p_reach`` is the product of the per-hop success probabilities along the
    witness — the probability the whole chain works, not a distance. ``depth``
    is that witness's hop count, so the two always describe the same path.
    """

    node_id: str
    kind: str
    name: str
    depth: int
    p_reach: float
    neg_log_reach: float
    p_undetected: float
    bottleneck_p: float
    is_crown_jewel: bool
    impact_score: float
    risk_score: float
    risk_tier_code: str
    witness_path_id: str
    witness_hops: tuple[Hop, ...]


@dataclass(frozen=True, slots=True)
class BlastRadiusResult:
    origin_node_id: str
    direction: str
    max_depth: int
    reached: tuple[ReachedNode, ...]
    crown_jewels_reached: tuple[str, ...]
    severity_score: float | None
    severity_tier_code: str | None
    severity_node_id: str | None
    expansions: int
    truncated: bool

    @property
    def nodes_reached(self) -> int:
        return len(self.reached)


@dataclass(slots=True)
class _Frontier:
    state: AttackerState
    hops: tuple[Hop, ...]
    cost: float

    @property
    def depth(self) -> int:
        return len(self.hops)


@dataclass(slots=True)
class _Candidate:
    rule: Rule
    src_id: str
    dst_id: str
    edge: Edge | None


@dataclass(slots=True)
class _Witness:
    cost: float
    hops: tuple[Hop, ...]

    def beats(self, other: "_Witness") -> bool:
        """Whether this witness is the better record for a node.

        Cheaper first, because cost is the whole point. Then shorter, so a
        chain that detours for no probability cost does not become the story
        told about a node. Then the edge sequence, so two runs over one graph
        never disagree about which of two identical-cost witnesses was kept.
        """
        return self._key() < other._key()

    def _key(self) -> tuple[float, int, tuple[str, ...]]:
        return (
            round(self.cost, 12),
            len(self.hops),
            tuple(f"{h.edge_id or '-'}#{h.rule_id}" for h in self.hops),
        )


class BlastRadius:
    """One configured blast-radius engine: a snapshot, a ruleset and a scorer."""

    def __init__(
        self,
        snapshot: GraphSnapshot,
        ruleset: RuleSet,
        scorer: Scorer,
        limits: BlastLimits | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.ruleset = ruleset
        self.scorer = scorer
        self.limits = limits or BlastLimits()
        if self.limits.max_depth < 1:
            raise BlastRadiusError("max_depth must be at least one hop")

        node_scoped = tuple(
            sorted(
                code
                for code, binding in ruleset.capability_bindings.items()
                if binding == "node"
            )
        )
        if not node_scoped:
            raise BlastRadiusError(
                "no node-scoped capability atoms, so 'this node is compromised' "
                "cannot be expressed as a state"
            )
        #: What full control of the origin means, taken from the capability
        #: table rather than named here.
        self.origin_capabilities = node_scoped
        #: Gaining one of these about a node is what counts as reaching it.
        #: ``network_reach`` is excluded for the reason ``docs/RULES.md`` R15
        #: gives: network adjacency is reachability, not access, and counting it
        #: as arrival reports a segmentation fact as a compromise.
        self.arrival_capabilities = frozenset(
            code for code in node_scoped if code not in REACHABILITY_ONLY
        )

        self._unconditional_ids = frozenset(r.rule_id for r in ruleset.unconditional)
        self._live_rules = self._prune_unobtainable(ruleset)
        self._non_traversal_targets = self._index_non_traversal_targets()

    # ── Public entry point ──────────────────────────────────────────────────

    def run(self, origin_node_id: str, direction: str = OUTBOUND) -> BlastRadiusResult:
        if direction not in DIRECTIONS:
            raise BlastRadiusError(
                f"unknown direction {direction!r}; expected one of {', '.join(DIRECTIONS)}"
            )
        if self.snapshot.get_node(origin_node_id) is None:
            raise BlastRadiusError(
                f"node {origin_node_id!r} is absent from graph version "
                f"{self.snapshot.graph_version}"
            )

        expansions = 0
        truncated = False
        witnesses: dict[str, _Witness] = {}

        for graph in self._legs(direction):
            found, used, hit_cap = self._search(graph, origin_node_id)
            expansions += used
            truncated = truncated or hit_cap
            for node_id, witness in found.items():
                current = witnesses.get(node_id)
                if current is None or witness.beats(current):
                    witnesses[node_id] = witness

        reached = tuple(
            sorted(
                (self._describe(node_id, witness) for node_id, witness in witnesses.items()),
                key=lambda r: (r.depth, -r.p_reach, r.node_id),
            )
        )
        worst = max(reached, key=lambda r: (r.risk_score, r.p_reach, r.node_id), default=None)

        return BlastRadiusResult(
            origin_node_id=origin_node_id,
            direction=direction,
            max_depth=self.limits.max_depth,
            reached=reached,
            crown_jewels_reached=tuple(r.node_id for r in reached if r.is_crown_jewel),
            severity_score=None if worst is None else worst.risk_score,
            severity_tier_code=None if worst is None else worst.risk_tier_code,
            severity_node_id=None if worst is None else worst.node_id,
            expansions=expansions,
            truncated=truncated,
        )

    def _legs(self, direction: str) -> tuple[GraphSnapshot, ...]:
        """The graphs one run searches, and what each of them answers.

        Outbound is the snapshot as it stands: what control of the origin leads
        to. Inbound is the same search over the snapshot with every edge
        reversed, which answers the converse — which nodes an attack on the
        origin could have arrived from. Reversing the graph rather than the
        search is what keeps one implementation: the rule rows, the precondition
        evaluator and the scorer are untouched, and only the adjacency changes.

        The approximation that buys is worth stating. A precondition binds to
        the traversed edge's endpoints, so on a reversed edge ``src`` and ``dst``
        are exchanged and a rule is evaluated against the opposite ends from the
        ones it was written for. The inbound set is therefore the set of nodes
        structurally upstream of the origin under the same rules, not a proof
        that each of them can in fact reach it. The exact answer is "run the
        outbound search from every node and keep those whose result contains the
        origin", which is one search per node in the graph and not something to
        do inside a request.
        """
        if direction == OUTBOUND:
            return (self.snapshot,)
        if direction == INBOUND:
            return (self._reversed(),)
        return (self.snapshot, self._reversed())

    def _reversed(self) -> GraphSnapshot:
        return GraphSnapshot(
            graph_version=self.snapshot.graph_version,
            nodes=list(self.snapshot.all_nodes),
            edges=[
                Edge(
                    edge_id=edge.edge_id,
                    src_id=edge.dst_id,
                    dst_id=edge.src_id,
                    edge_type=edge.edge_type,
                    attrs=edge.attrs,
                )
                for edge in self.snapshot.all_edges
            ],
        )

    # ── Search ──────────────────────────────────────────────────────────────

    def _search(
        self, graph: GraphSnapshot, origin_node_id: str
    ) -> tuple[dict[str, _Witness], int, bool]:
        limits = self.limits
        start = AttackerState(
            origin_node_id,
            frozenset(Capability(code, origin_node_id) for code in self.origin_capabilities),
        )

        witnesses: dict[str, _Witness] = {}
        # Cheapest cost each capability set has been popped at, and a bounded
        # per-node history for the subset test. Both are pruning only: forgetting
        # an entry costs work, never correctness.
        seen: dict[frozenset[Capability], float] = {}
        history: dict[str, list[tuple[frozenset[Capability], float]]] = {}

        counter = 0
        heap: list[tuple[float, int, tuple[tuple[str, int], ...], int, _Frontier]] = [
            (0.0, 0, (), counter, _Frontier(state=start, hops=(), cost=0.0))
        ]
        expansions = 0
        truncated = False

        while heap:
            if expansions >= limits.max_expansions:
                truncated = True
                break
            _, _, _, _, frontier = heapq.heappop(heap)
            state = frontier.state

            previous = seen.get(state.capabilities)
            if previous is not None and previous <= frontier.cost:
                continue
            if self._dominated(history, state, frontier.cost):
                continue
            seen[state.capabilities] = frontier.cost
            at_node = history.setdefault(state.node_id, [])
            at_node.append((state.capabilities, frontier.cost))
            if len(at_node) > DOMINANCE_HISTORY:
                del at_node[0]
            expansions += 1

            if frontier.depth >= limits.max_depth:
                continue

            for candidate in self._candidates(graph, state):
                applied = self._attempt(graph, state, frontier.depth, candidate)
                if applied is None:
                    continue
                gained, hop = applied

                hops = frontier.hops + (hop,)
                cost = frontier.cost + hop.neg_log_contribution
                witness = _Witness(cost=cost, hops=hops)

                for capability in sorted(gained, key=_capability_key):
                    node_id = capability.about
                    if (
                        node_id is None
                        or node_id == origin_node_id
                        or capability.code not in self.arrival_capabilities
                    ):
                        continue
                    current = witnesses.get(node_id)
                    if current is None or witness.beats(current):
                        witnesses[node_id] = witness

                counter += 1
                successor = _Frontier(
                    state=state.moved_to(
                        candidate.dst_id if candidate.rule.is_traversal else state.node_id,
                        gained,
                    ),
                    hops=hops,
                    cost=cost,
                )
                heapq.heappush(
                    heap,
                    (
                        cost,
                        successor.depth,
                        tuple((h.edge_id or "", h.rule_id) for h in hops),
                        counter,
                        successor,
                    ),
                )

        return witnesses, expansions, truncated

    def _candidates(
        self, graph: GraphSnapshot, state: AttackerState
    ) -> Iterator[_Candidate]:
        """Every rule application worth evaluating from one state.

        Sources are every node the attacker holds a capability about, not just
        wherever they last moved — no precondition in ``docs/RULES.md`` says
        "the attacker is standing at src", and a position-gated frontier would
        strand them on a Vulnerability node between R12 and R13.
        """
        seen: set[tuple[int, str]] = set()
        sources = sorted({state.node_id} | {c.about for c in state.capabilities if c.about})

        for src_id in sources:
            for edge in graph.out_edges(src_id):
                for rule in self.ruleset.traversal_by_edge_type.get(edge.edge_type, ()):
                    if rule.rule_id not in self._live_rules:
                        continue
                    key = (rule.rule_id, edge.edge_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield _Candidate(rule, edge.src_id, edge.dst_id, edge)

        for rule in self.ruleset.non_traversal:
            if rule.rule_id not in self._live_rules:
                continue
            for dst_id in self._non_traversal_targets.get(rule.rule_id, ()):
                yield _Candidate(rule, dst_id, dst_id, None)

    def _attempt(
        self,
        graph: GraphSnapshot,
        state: AttackerState,
        depth: int,
        candidate: _Candidate,
    ) -> tuple[frozenset[Capability], Hop] | None:
        rule = candidate.rule
        src_node = graph.get_node(candidate.src_id)
        dst_node = graph.get_node(candidate.dst_id)

        if first_failure(
            rule,
            state=state,
            src_node=src_node,
            dst_node=dst_node,
            edge=candidate.edge,
        ) is not None:
            return None

        effects = self._effects(rule, candidate.src_id, candidate.dst_id)
        # Monotonicity: a transition that grants nothing new cannot help, and
        # dropping it here is what keeps a cycle in the graph from becoming a
        # cycle in the search.
        if effects <= state.capabilities:
            return None
        gained = effects - state.capabilities

        score = self.scorer.score_hop(
            technique_code=rule.technique_code,
            src_node=src_node,
            dst_node=dst_node,
            edge=candidate.edge,
        )
        if score.blocked_by is not None:
            return None

        hop = Hop(
            hop_no=depth + 1,
            src_node_id=candidate.src_id,
            dst_node_id=candidate.dst_id,
            edge_id=candidate.edge.edge_id if candidate.edge is not None else None,
            technique_code=rule.technique_code,
            rule_id=rule.rule_id,
            p_succ=score.p_succ,
            detectability=score.detectability,
            neg_log_contribution=score.neg_log_contribution,
            gained=tuple(sorted(gained, key=_capability_key)),
            factors=score.factors,
        )
        return gained, hop

    def _effects(self, rule: Rule, src_id: str, dst_id: str) -> frozenset[Capability]:
        gained: set[Capability] = set()
        for effect in rule.effects:
            if effect.binding is Binding.SRC:
                gained.add(Capability(effect.capability_code, src_id))
            elif effect.binding is Binding.DST:
                gained.add(Capability(effect.capability_code, dst_id))
            else:
                gained.add(Capability(effect.capability_code, None))
        return frozenset(gained)

    def _dominated(
        self,
        history: Mapping[str, list[tuple[frozenset[Capability], float]]],
        state: AttackerState,
        cost: float,
    ) -> bool:
        """Whether an already-expanded state strictly dominates this one.

        ``docs/RULES.md`` §1.3: holding a superset of the capabilities at no
        greater cost means everything the dominated state could do is already
        available at least as cheaply, so expanding it can only re-derive what
        is known. Note that a node is recorded when the hop granting it is
        applied, so pruning here never loses a reached node — only the
        extensions past it, which the dominating state will produce anyway.
        """
        for caps, other_cost in history.get(state.node_id, ()):
            if caps == state.capabilities or other_cost > cost:
                continue
            if AttackerState(state.node_id, caps).dominates(state):
                return True
        return False

    # ── Indexes ─────────────────────────────────────────────────────────────

    def _prune_unobtainable(self, ruleset: RuleSet) -> frozenset[int]:
        """Rules that could conceivably fire from a single-node origin.

        Two classes are dropped, both because they say nothing about the origin.

        A rule with no capability precondition fires from the empty state — R8,
        a credential published in a public repository, is the whole reason that
        category exists. It is reachable with no identity at all, so it is in
        every node's blast radius identically and attributing it to any one of
        them overstates that node while telling the reader nothing.

        A rule requiring a globally-scoped capability the origin does not hold
        and no rule's effects can grant is unsatisfiable, so evaluating it once
        per state is work with a known answer. Kerberoasting is the case here:
        it needs ``authenticated``, which is a threat model's grant rather than
        anything a single compromised node confers.
        """
        obtainable_globals = {
            effect.capability_code
            for rule in ruleset.rules
            for effect in rule.effects
            if effect.binding is Binding.GLOBAL
        }

        live: set[int] = set()
        for rule in ruleset.rules:
            if rule.rule_id in self._unconditional_ids:
                continue
            if any(
                pre.kind is PreconditionKind.CAPABILITY
                and not pre.is_negated
                and pre.binding is Binding.GLOBAL
                and (pre.capability_code or "") not in obtainable_globals
                for pre in rule.preconditions
            ):
                continue
            live.add(rule.rule_id)
        return frozenset(live)

    def _index_non_traversal_targets(self) -> Mapping[int, tuple[str, ...]]:
        """Candidate targets for each rule that consumes no edge.

        Such a rule is anchored to nothing — that is R10's point — so its target
        ranges over the graph. Restricting the range to nodes that actually
        record every attribute the rule inspects keeps it from being a full scan
        at every state; a node recording none of them could only ever produce
        the same uninformative refusal.
        """
        index: dict[int, tuple[str, ...]] = {}
        for rule in self.ruleset.non_traversal:
            paths = [
                p.attr_path
                for p in rule.preconditions
                if p.attr_path and p.binding is Binding.DST
            ]
            index[rule.rule_id] = tuple(
                node.node_id
                for node in sorted(self.snapshot.all_nodes, key=lambda n: n.node_id)
                if all(path in node.attrs for path in paths)
            )
        return index

    # ── Reporting ───────────────────────────────────────────────────────────

    def _describe(self, node_id: str, witness: _Witness) -> ReachedNode:
        node: Node = self.snapshot.node(node_id)
        score = self.scorer.score_path(witness.hops, node)
        return ReachedNode(
            node_id=node_id,
            kind=node.kind,
            name=node.display_name or node.name,
            depth=len(witness.hops),
            p_reach=score.p_success,
            neg_log_reach=score.neg_log_success,
            p_undetected=score.p_undetected,
            bottleneck_p=score.bottleneck_p,
            is_crown_jewel=node.is_crown_jewel,
            impact_score=score.impact_score,
            risk_score=score.risk_score,
            risk_tier_code=score.risk_tier.code,
            # The content hash of this hop sequence, computed the way every
            # other path id in the system is. It identifies the witness rather
            # than pointing at a stored row: blast radius does not write
            # discovered_path rows, so the id resolves to one only when the
            # baseline run happened to find the same sequence.
            witness_path_id=path_id(
                [hop.edge_id for hop in witness.hops],
                [hop.rule_id for hop in witness.hops],
            ),
            witness_hops=witness.hops,
        )


def summarise_by_depth(reached: Sequence[ReachedNode]) -> tuple[tuple[int, int], ...]:
    """(depth, node count) pairs, ascending. Used by the run summary."""
    counts: dict[int, int] = {}
    for node in reached:
        counts[node.depth] = counts.get(node.depth, 0) + 1
    return tuple(sorted(counts.items()))


def _capability_key(capability: Capability) -> tuple[str, str]:
    return capability.code, capability.about or ""
