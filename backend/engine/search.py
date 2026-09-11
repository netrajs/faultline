"""Precondition-aware discovery.

The search is over states, not over nodes. That is the single most important
sentence in ``docs/RULES.md``, and it is the whole difference between this and a
reachability tool: searching nodes answers "is there a route through the graph",
searching states answers "is there a sequence of actions an attacker could
actually perform", and those are different questions with different answers.

Three consequences shape everything here.

**Position does not gate anything.** Read the rules and notice what is absent:
no precondition says "the attacker is standing at src". Every one of them asks
about a held capability or a graph attribute. So a transition is available
whenever the attacker holds the required capability *about* the source node —
wherever they happen to be. That matters concretely. R12 grants
``code_exec_on(host)`` while the edge it traverses points at the vulnerability;
R13 then needs ``code_exec_on`` on that same host. A position-gated search
strands the attacker on the vulnerability node and never finds the pair of hops
``docs/RULES.md`` describes as the reason the two capabilities are separate.
Kerberoasting is the same story: it grants control of a service account nothing
in the graph connects the attacker to. So the frontier is expanded from every
node the attacker holds a capability about, and ``AttackerState.node_id`` is the
last node touched — presentation, not a constraint.

**Monotonicity makes it a DAG.** Capabilities are never lost, so every useful
transition strictly grows the held set. A transition that grants nothing new is
dropped outright, which is what dissolves the cycle problem: host A trusting B
trusting A is a cycle in the graph, but the second traversal grants nothing and
is pruned here rather than needing cycle detection.

**Best-first is exact for the ranking.** The hop weight is ``-ln p_succ``, which
is non-negative and additive, so Dijkstra's optimality argument applies
unchanged: the first time a target is reached, it is reached by its
highest-probability path. K-best then allows each capability set to be expanded
up to ``top_k`` times.

No A* heuristic is used. The admissible backward-Dijkstra heuristic in
``docs/SCOPE.md`` D4 is defined over positions on a relaxed graph, and in a
search where position is not what makes progress it is not admissible without a
separate argument. Correct exhaustive best-first is the bar; an inadmissible
heuristic would silently trade it away.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Iterable, Iterator, Mapping, Sequence

from core.ids import path_id, rejection_signature
from core.model import (
    AttackerState,
    AttackPath,
    Binding,
    Capability,
    Edge,
    GraphSnapshot,
    Hop,
    PreconditionKind,
    Rejection,
    Rule,
    ThreatModel,
)
from engine.preconditions import first_failure
from engine.rules import RuleSet
from engine.scoring import Scorer

#: Node-scoped capabilities that do not, on their own, constitute reaching a
#: target. ``docs/RULES.md`` R15 is explicit: network adjacency grants
#: reachability, not access, and ``network_reach`` does nothing until another
#: rule consumes it. Counting it as arrival would report a segmentation fact as
#: a completed attack — exactly the conflation of reachability with authorisation
#: the rule exists to prevent.
REACHABILITY_ONLY = frozenset({"network_reach"})

#: Cap on how many popped states one node keeps for dominance comparison.
#: Dominance checking is linear in that history, so an unbounded list turns a
#: dense node quadratic. Forgetting entries only ever prunes less, never wrongly.
DOMINANCE_HISTORY = 128


class SearchError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SearchLimits:
    max_hops: int = 8
    top_k: int = 5
    max_expansions: int = 250_000
    max_rejections: int = 50_000


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    paths: tuple[AttackPath, ...]
    rejections: tuple[Rejection, ...]
    initial_capabilities: Mapping[str, tuple[Capability, ...]]
    """path_id -> the capabilities the threat model granted before hop 1.

    Carried alongside the paths because the stored capability trace is "what the
    attacker holds after each hop", and the grants are the only part of that not
    derivable from the hops themselves.
    """
    entry_nodes: tuple[str, ...]
    targets: tuple[str, ...]
    expansions: int
    truncated: bool


@dataclass(slots=True)
class _SearchNode:
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


class Discovery:
    """One configured engine: a snapshot, a ruleset and a scorer."""

    def __init__(
        self,
        snapshot: GraphSnapshot,
        ruleset: RuleSet,
        scorer: Scorer,
        limits: SearchLimits | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.ruleset = ruleset
        self.scorer = scorer
        self.limits = limits or SearchLimits()

        self.goal_codes = frozenset(
            code
            for code, binding in ruleset.capability_bindings.items()
            if binding == "node" and code not in REACHABILITY_ONLY
        )
        if not self.goal_codes:
            raise SearchError("no node-scoped capability counts as reaching a target")

        self._unconditional_ids = frozenset(r.rule_id for r in ruleset.unconditional)
        self._non_traversal_targets = self._index_non_traversal_targets()
        self._rejections: dict[str, Rejection] = {}
        self._expansions = 0
        self._truncated = False

    # ── Entry points ────────────────────────────────────────────────────────

    def entry_states(self, threat_model: ThreatModel) -> tuple[AttackerState, ...]:
        """The states the attacker starts in under one threat model.

        Grants come in three shapes, and the shape says how to read them. A
        grant with neither a kind nor a node is held outright. A grant naming a
        specific node is held about that node. A grant naming a *kind* is the
        interesting one, because the same shape carries two different intents:
        ``insider_standard`` grants ``controls_principal`` over User and
        ``network_reach`` over Host, and ``docs/RULES.md`` §3 describes those as
        "their own account" and "internal assets" — one node versus all of them.

        Nothing distinguishes them except order, so order decides: the
        lowest-numbered kind grant is the entry variable and is enumerated one
        node at a time; every later kind grant is ambient and is held about every
        node of its kind. That reproduces all four shipped threat models,
        including ``public_only``, whose only grant is the entry.
        """
        base: set[Capability] = set()
        entry_grant: tuple[str, str] | None = None
        pinned: list[str] = []

        for code, kind, node_id in threat_model.grants:
            binding = self.ruleset.capability_bindings.get(code)
            if binding is None:
                raise SearchError(
                    f"threat model {threat_model.code} grants unknown capability {code!r}"
                )
            if binding == "global":
                if kind or node_id:
                    raise SearchError(
                        f"threat model {threat_model.code} scopes globally-bound "
                        f"capability {code!r} to {kind or node_id!r}"
                    )
                base.add(Capability(code, None))
                continue

            if node_id:
                if self.snapshot.get_node(node_id) is None:
                    raise SearchError(
                        f"threat model {threat_model.code} grants {code!r} over "
                        f"{node_id!r}, which is absent from graph version "
                        f"{self.snapshot.graph_version}"
                    )
                base.add(Capability(code, node_id))
                pinned.append(node_id)
                continue

            if not kind:
                raise SearchError(
                    f"threat model {threat_model.code} grants node-scoped {code!r} "
                    "with neither a kind nor a node, so it is about nothing"
                )
            if entry_grant is None:
                entry_grant = (code, kind)
                continue
            for node in self.snapshot.nodes_of_kind(kind):
                base.add(Capability(code, node.node_id))

        frozen_base = frozenset(base)
        if entry_grant is not None:
            code, kind = entry_grant
            return tuple(
                AttackerState(node.node_id, frozen_base | {Capability(code, node.node_id)})
                for node in sorted(
                    self.snapshot.nodes_of_kind(kind), key=lambda n: n.node_id
                )
            )
        if pinned:
            return tuple(
                AttackerState(node_id, frozen_base) for node_id in sorted(set(pinned))
            )
        raise SearchError(
            f"threat model {threat_model.code} grants no node-scoped capability, "
            "so it has no entry point"
        )

    # ── Discovery ───────────────────────────────────────────────────────────

    def run(self, threat_model_code: str) -> DiscoveryResult:
        threat_model = self.ruleset.threat_model(threat_model_code)
        entries = self.entry_states(threat_model)
        targets = tuple(sorted(self.snapshot.crown_jewels))

        self._rejections = {}
        self._expansions = 0
        self._truncated = False

        # Rules with no capability precondition can fire from any state, so they
        # are evaluated once against the graph rather than re-evaluated at every
        # state. Their verdict cannot depend on what the attacker holds, which is
        # exactly what makes R8 the rule that stays reachable with no identity.
        static = self._static_firings()

        found: dict[str, AttackPath] = {}
        grants: dict[str, tuple[Capability, ...]] = {}
        # Shared across every entry's own search, not reset per entry: top_k is
        # "how many paths one target keeps" for the run, and entries are
        # independent searches only because the frontier is easier to reason
        # about that way. Without sharing this, a target reachable from several
        # entries would keep top_k paths *per entry* instead of top_k overall —
        # visible whenever a rule does not gate on which entry reached it, as
        # kerberoasting deliberately does not.
        target_counts: dict[str, int] = {}
        # An even share of the budget per entry, not a shared pool spent
        # first-come-first-served. A real graph's entries are wildly uneven —
        # one privileged user's reachable state space can be enormous — and
        # without a per-entry share the first entry alone can exhaust the whole
        # budget before any other user is even attempted, silently reporting
        # "160 entries searched" when 159 of them never ran. The share is
        # computed once against the entry count, not decremented as entries are
        # skipped, so it stays a stable, explainable number rather than growing
        # unpredictably as the run proceeds.
        entry_share = max(1, self.limits.max_expansions // max(1, len(entries)))
        for entry in entries:
            if self._expansions >= self.limits.max_expansions:
                self._truncated = True
                break
            entry_cap = min(self.limits.max_expansions, self._expansions + entry_share)
            for path in self._search(entry, targets, static, target_counts, entry_cap):
                if path.path_id not in found:
                    found[path.path_id] = path
                    grants[path.path_id] = tuple(
                        sorted(entry.capabilities, key=_capability_key)
                    )
                    target_counts[path.target_node_id] = (
                        target_counts.get(path.target_node_id, 0) + 1
                    )

        paths = tuple(sorted(found.values(), key=_path_rank_key))
        rejections = tuple(
            sorted(
                self._rejections.values(),
                key=lambda r: (r.hop_depth, r.rule_id, r.src_node_id, r.dst_node_id, r.signature),
            )
        )
        return DiscoveryResult(
            paths=paths,
            rejections=rejections,
            initial_capabilities=grants,
            entry_nodes=tuple(state.node_id for state in entries),
            targets=targets,
            expansions=self._expansions,
            truncated=self._truncated,
        )

    def _search(
        self,
        start: AttackerState,
        targets: Sequence[str],
        static: Sequence[_Candidate],
        target_counts: dict[str, int],
        expansion_cap: int,
    ) -> list[AttackPath]:
        limits = self.limits
        goal_targets = frozenset(targets)
        emitted: dict[str, list[AttackPath]] = {}

        def slots_left(target: str) -> int:
            return limits.top_k - target_counts.get(target, 0) - len(emitted.get(target, ()))

        counter = 0
        heap: list[tuple[float, int, tuple[tuple[str, int], ...], int, _SearchNode]] = [
            (0.0, 0, (), counter, _SearchNode(state=start, hops=(), cost=0.0))
        ]
        expansions: dict[frozenset[Capability], int] = {}
        history: dict[str, list[tuple[frozenset[Capability], float]]] = {}

        while heap:
            if self._expansions >= expansion_cap:
                self._truncated = True
                break
            _, _, _, _, node = heapq.heappop(heap)
            state = node.state
            caps = state.capabilities

            if expansions.get(caps, 0) >= limits.top_k:
                continue
            if self._dominated(history, state, node.cost):
                continue
            expansions[caps] = expansions.get(caps, 0) + 1
            at_node = history.setdefault(state.node_id, [])
            at_node.append((caps, node.cost))
            if len(at_node) > DOMINANCE_HISTORY:
                del at_node[0]
            self._expansions += 1

            if node.depth >= limits.max_hops:
                continue
            if all(slots_left(t) <= 0 for t in targets):
                break

            for candidate in self._candidates(state, static):
                applied = self._attempt(state, node.depth, candidate)
                if applied is None:
                    continue
                gained, hop = applied

                hops = node.hops + (hop,)
                for target in sorted({c.about for c in gained if c.about in goal_targets}):
                    arrival = frozenset(
                        c for c in gained if c.about == target and c.code in self.goal_codes
                    )
                    if not arrival:
                        continue
                    reached = emitted.setdefault(str(target), [])
                    if slots_left(str(target)) <= 0:
                        continue
                    if not self._is_minimal(hops, arrival):
                        continue
                    reached.append(self._build_path(start, str(target), hops))

                successor = _SearchNode(
                    state=state.moved_to(
                        candidate.dst_id if candidate.rule.is_traversal else state.node_id,
                        gained,
                    ),
                    hops=hops,
                    cost=node.cost + hop.neg_log_contribution,
                )
                counter += 1
                heapq.heappush(
                    heap,
                    (
                        successor.cost,
                        successor.depth,
                        tuple((h.edge_id or "", h.rule_id) for h in hops),
                        counter,
                        successor,
                    ),
                )

        return [path for paths in emitted.values() for path in paths]

    # ── Transitions ─────────────────────────────────────────────────────────

    def _candidates(
        self, state: AttackerState, static: Sequence[_Candidate]
    ) -> Iterator[_Candidate]:
        """Every rule application worth evaluating from one state.

        Sources are the nodes the attacker holds a capability about, plus the
        node they last touched. Sorted, and each (rule, edge) offered once, so
        the order a state is expanded in is a property of the graph rather than
        of dictionary iteration.
        """
        seen: set[tuple[int, str]] = set()
        sources = sorted({state.node_id} | {c.about for c in state.capabilities if c.about})

        for src_id in sources:
            for edge in self.snapshot.out_edges(src_id):
                for rule in self.ruleset.traversal_by_edge_type.get(edge.edge_type, ()):
                    if rule.rule_id in self._unconditional_ids:
                        continue
                    key = (rule.rule_id, edge.edge_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield _Candidate(rule, edge.src_id, edge.dst_id, edge)

        yield from static

        # A rule that consumes no edge has no source: nothing in the graph joins
        # the attacker to the node it acts on, which is the whole point of R10.
        # So the hop is recorded as being about that one node rather than about
        # wherever the attacker happened to be standing — which also stops one
        # refusal being recorded once per position the attacker could refuse it
        # from.
        for rule in self.ruleset.non_traversal:
            for dst_id in self._non_traversal_targets.get(rule.rule_id, ()):
                yield _Candidate(rule, dst_id, dst_id, None)

    def _attempt(
        self, state: AttackerState, depth: int, candidate: _Candidate
    ) -> tuple[frozenset[Capability], Hop] | None:
        rule = candidate.rule
        src_node = self.snapshot.get_node(candidate.src_id)
        dst_node = self.snapshot.get_node(candidate.dst_id)

        refusal = first_failure(
            rule,
            state=state,
            src_node=src_node,
            dst_node=dst_node,
            edge=candidate.edge,
        )
        if refusal is not None:
            self._reject(
                candidate,
                depth + 1,
                precondition_seq=refusal.precondition_seq,
                reason_code=refusal.reason_code,
                reason_text=refusal.reason_text,
                observed_value=refusal.observed_value,
            )
            return None

        effects = self._effects(rule, candidate.src_id, candidate.dst_id)
        # Monotonicity: a transition granting nothing new cannot help, and
        # pruning it here is what keeps graph cycles from becoming search cycles.
        if effects <= state.capabilities:
            return None
        # The hop records what it actually added, not everything the rule
        # nominally grants. A rule re-granting something already held would
        # otherwise appear to be the provider of it, and the proof trace would
        # name the wrong hop.
        gained = effects - state.capabilities

        score = self.scorer.score_hop(
            technique_code=rule.technique_code,
            src_node=src_node,
            dst_node=dst_node,
            edge=candidate.edge,
        )
        if score.blocked_by is not None:
            self._reject(
                candidate,
                depth + 1,
                precondition_seq=None,
                reason_code=f"hard_block:{score.blocked_by.code}",
                reason_text=score.blocked_by.label,
                observed_value=None,
            )
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

    def _is_minimal(self, hops: Sequence[Hop], arrival: frozenset[Capability]) -> bool:
        """Whether every hop is part of the proof that the last one succeeded.

        Delegates to :func:`is_minimal_proof`, which is kept as a standalone
        function so the same backward-closure check can be run again from
        outside the search — the same reason ``verify_path`` is a function and
        not a method.
        """
        return is_minimal_proof(hops, arrival, self.ruleset)

    def _effects(self, rule: Rule, src_id: str, dst_id: str) -> frozenset[Capability]:
        gained: set[Capability] = set()
        for effect in rule.effects:
            if effect.binding.value == "src":
                gained.add(Capability(effect.capability_code, src_id))
            elif effect.binding.value == "dst":
                gained.add(Capability(effect.capability_code, dst_id))
            else:
                gained.add(Capability(effect.capability_code, None))
        return frozenset(gained)

    def _build_path(
        self, start: AttackerState, target_id: str, hops: tuple[Hop, ...]
    ) -> AttackPath:
        target = self.snapshot.node(target_id)
        score = self.scorer.score_path(hops, target)
        return AttackPath(
            path_id=path_id(
                [hop.edge_id for hop in hops], [hop.rule_id for hop in hops]
            ),
            source_node_id=start.node_id,
            target_node_id=target_id,
            hops=hops,
            p_success=score.p_success,
            neg_log_success=score.neg_log_success,
            p_undetected=score.p_undetected,
            bottleneck_p=score.bottleneck_p,
            bottleneck_hop=score.bottleneck_hop,
            impact_score=score.impact_score,
            risk_score=score.risk_score,
            risk_tier_code=score.risk_tier.code,
            target_is_crown_jewel=target.is_crown_jewel,
        )

    # ── Pruning and indexes ─────────────────────────────────────────────────

    def _dominated(
        self,
        history: Mapping[str, list[tuple[frozenset[Capability], float]]],
        state: AttackerState,
        cost: float,
    ) -> bool:
        """Whether an already-expanded state strictly dominates this one.

        ``docs/RULES.md`` §1.3: a state dominates another when it holds a
        superset of its capabilities and the path reaching it is at least as
        probable. The dominated one can do nothing the dominating one cannot do
        at least as cheaply, so expanding it only re-derives what is already
        known. Note that this prunes *extensions* only — a path that has already
        reached a target was emitted when its final hop was applied.
        """
        for caps, other_cost in history.get(state.node_id, ()):
            if caps == state.capabilities or other_cost > cost:
                continue
            if AttackerState(state.node_id, caps).dominates(state):
                return True
        return False

    def _static_firings(self) -> tuple[_Candidate, ...]:
        firings: list[_Candidate] = []
        for rule in self.ruleset.unconditional:
            for edge in self._edges_of_type(str(rule.edge_type)):
                candidate = _Candidate(rule, edge.src_id, edge.dst_id, edge)
                refusal = first_failure(
                    rule,
                    state=AttackerState(edge.src_id, frozenset()),
                    src_node=self.snapshot.get_node(edge.src_id),
                    dst_node=self.snapshot.get_node(edge.dst_id),
                    edge=edge,
                )
                if refusal is None:
                    firings.append(candidate)
                else:
                    self._reject(
                        candidate,
                        1,
                        precondition_seq=refusal.precondition_seq,
                        reason_code=refusal.reason_code,
                        reason_text=refusal.reason_text,
                        observed_value=refusal.observed_value,
                    )
        return tuple(firings)

    def _edges_of_type(self, edge_type: str) -> list[Edge]:
        return sorted(
            (e for e in self.snapshot.all_edges if e.edge_type == edge_type),
            key=lambda e: e.edge_id,
        )

    def _index_non_traversal_targets(self) -> Mapping[int, tuple[str, ...]]:
        """Candidate targets for each rule that consumes no edge.

        A non-traversal rule is anchored to nothing, so its target ranges over
        the graph — that is the point of R10: nothing connects the attacker to
        the service account, and the capability arrives from a property of the
        directory itself. Restricting the range to nodes that actually record
        every attribute the rule asks about is what keeps that from being a full
        scan at every state. A node recording none of them could only ever
        produce the same uninformative refusal.
        """
        index: dict[int, tuple[str, ...]] = {}
        for rule in self.ruleset.non_traversal:
            paths = [
                p.attr_path
                for p in rule.preconditions
                if p.attr_path and p.binding.value == "dst"
            ]
            index[rule.rule_id] = tuple(
                node.node_id
                for node in sorted(self.snapshot.all_nodes, key=lambda n: n.node_id)
                if all(path in node.attrs for path in paths)
            )
        return index

    def _reject(
        self,
        candidate: _Candidate,
        depth: int,
        *,
        precondition_seq: int | None,
        reason_code: str,
        reason_text: str,
        observed_value: str | None,
    ) -> None:
        if len(self._rejections) >= self.limits.max_rejections:
            self._truncated = True
            return
        edge_id = candidate.edge.edge_id if candidate.edge is not None else None
        signature = rejection_signature(
            candidate.src_id, candidate.dst_id, edge_id, candidate.rule.rule_id, depth
        )
        if signature in self._rejections:
            return
        self._rejections[signature] = Rejection(
            signature=signature,
            src_node_id=candidate.src_id,
            dst_node_id=candidate.dst_id,
            edge_id=edge_id,
            rule_id=candidate.rule.rule_id,
            precondition_seq=precondition_seq,
            reason_code=reason_code,
            reason_text=reason_text,
            observed_value=observed_value,
            hop_depth=depth,
        )


def is_minimal_proof(
    hops: Sequence[Hop], arrival: frozenset[Capability], ruleset: RuleSet
) -> bool:
    """Whether every hop is part of the proof that the last one succeeded.

    An attack path is a proof, and a proof has no spare steps. Walk the hops
    backwards from the capability that constitutes arrival, keeping a set of
    capabilities still to be accounted for: a hop is part of the proof when it
    supplied one of them, and it then adds its own capability preconditions to
    the set. A hop that supplied nothing is a side excursion that happened to
    be affordable, not a step the attack needed.

    This is the proof DAG ``docs/SCOPE.md`` D1 describes, used as a filter. It
    matters for two reasons. Reported precision: a four-hop attack with an
    irrelevant fifth hop is a distinct edge sequence and therefore a distinct
    path identity, so it is counted as a false positive against a ground truth
    that planted the four. And K-best capacity: n affordable irrelevant hops
    can be interleaved n! ways at identical cost, which fills every slot with
    reorderings of one attack and crowds out the genuinely different ones the
    ranking exists to show. Note that a side excursion that is genuinely
    *required* — the group membership R7's ``admin_on`` depends on — is in the
    backward closure and survives, which is the whole reason the closure is
    computed rather than the path being required to be a simple chain.
    """
    by_id = {rule.rule_id: rule for rule in ruleset.rules}
    needed = set(arrival)

    for hop in reversed(hops):
        supplied = needed & set(hop.gained)
        if not supplied:
            return False
        needed -= supplied
        rule = by_id.get(hop.rule_id)
        if rule is None:  # pragma: no cover - hops are built from these rules
            return False
        for pre in rule.preconditions:
            if pre.kind is not PreconditionKind.CAPABILITY or pre.is_negated:
                continue
            code = pre.capability_code or ""
            if pre.binding is Binding.SRC:
                needed.add(Capability(code, hop.src_node_id))
            elif pre.binding is Binding.DST:
                needed.add(Capability(code, hop.dst_node_id))
            else:
                needed.add(Capability(code, None))
    return True


def verify_path(
    path: AttackPath,
    *,
    snapshot: GraphSnapshot,
    ruleset: RuleSet,
    initial_capabilities: Iterable[Capability],
) -> str | None:
    """Re-check a discovered path against the rules, independently of the search.

    ``docs/RULES.md`` invariant 5 asks that every hop satisfy its rule's
    preconditions given the state accumulated by the preceding hops, "checkable
    independently of the search that produced it". This is that check: it replays
    the path from the initial grants using nothing but the rule rows, so a bug in
    the frontier, the queue or the pruning cannot hide inside it. Returns None
    when the path holds, or a sentence naming the first hop that does not.
    """
    by_id = {rule.rule_id: rule for rule in ruleset.rules}
    state = AttackerState(path.source_node_id, frozenset(initial_capabilities))

    for hop in path.hops:
        rule = by_id.get(hop.rule_id)
        if rule is None:
            return f"hop {hop.hop_no} cites unknown rule {hop.rule_id}"
        edge = snapshot.edge(hop.edge_id) if hop.edge_id else None
        if edge is not None and (
            edge.src_id != hop.src_node_id or edge.dst_id != hop.dst_node_id
        ):
            return f"hop {hop.hop_no} edge {edge.edge_id} does not join its endpoints"
        refusal = first_failure(
            rule,
            state=state,
            src_node=snapshot.get_node(hop.src_node_id),
            dst_node=snapshot.get_node(hop.dst_node_id),
            edge=edge,
        )
        if refusal is not None:
            return (
                f"hop {hop.hop_no} ({rule.code}) fails precondition "
                f"{refusal.precondition_seq}: {refusal.reason_text}"
            )
        state = state.moved_to(
            hop.dst_node_id if rule.is_traversal else state.node_id, hop.gained
        )
    return None


def _capability_key(capability: Capability) -> tuple[str, str]:
    return capability.code, capability.about or ""


def _path_rank_key(path: AttackPath) -> tuple[float, float, int, str]:
    # Risk descending, then the log-probability the search actually minimised,
    # then length, then the content hash. Every tie is broken by something
    # derived from the path itself, so ranking is reproducible rather than
    # stable only up to insertion order.
    return (-path.risk_score, path.neg_log_success, path.hop_count, path.path_id)
