"""Exhaustive depth-first search over ``(node, held-capability-set)``.

This is the reference oracle's search. It is written to be read and checked by
eye, not to be fast. Every candidate the model permits is enumerated: every
rule against every applicable edge out of the current node, plus every
non-traversal rule against every node in the graph. Nothing is pruned on
dominance, nothing is pruned on probability, and nothing is deduplicated. The
whole value of this artifact is that it cannot share a pruning bug with the
fast engine, because it has no pruning to share.

What it deliberately does *not* do:

**It does not score.** ``docs/RULES.md`` §6 defines probability composition, and
the engine implements it. Re-implementing it here would not make path
*existence* — the thing this oracle is a second opinion about — any better
checked, and the differential comparison is over path identity, which is the
edge/rule sequence. Every probability field on a returned path or hop carries
:data:`UNSCORED` and must not be read as a measurement.

**It does not memoise across branches.** The only thing that stops the search is
the hop cap and the fact that a branch which returns to a state it already
occupied cannot produce anything new. That second mechanism is the one
``docs/RULES.md`` §1.2 describes: capabilities are never lost, so every useful
transition strictly grows the held set, and a graph cycle traversed with nothing
gained lands on a state identical to one already on the branch. It is a
termination condition, not a cache — a state reached again down a *different*
branch is explored again, in full.


================================================================================
DECISION: how a threat model's node-kind grants are instantiated
================================================================================

``threat_model_grant`` says a capability applies to a node kind, or to a named
node, or globally. It does not say whether a kind-scoped grant means "one node
of this kind" or "every node of this kind", and ``docs/RULES.md`` §3 needs both:
``external_phish`` grants ``controls_principal`` over *one* standard user, while
``insider_standard`` grants ``network_reach`` to internal assets, plural.

The rule adopted here:

    The search runs once per entry node. For that run, a kind-scoped grant whose
    kind matches the entry node's kind is instantiated about the entry node
    alone; a kind-scoped grant of any other kind is instantiated about every
    node of that kind.

So ``external_phish`` starting at user ``u-0001`` holds ``authenticated`` and
``controls_principal(u-0001)`` and nothing else, which is §3 exactly; and
``insider_standard`` starting at the same user additionally holds
``network_reach`` on every host, which is also §3 exactly.

The cost is at ``public_only``, whose only grant is kind-scoped to the same kind
as its entry nodes: each run then models an attacker who has reached one
public-facing asset rather than all of them, and a path needing simultaneous
reach to two of them is not enumerated. Callers who want to model that pass it
explicitly through :attr:`OracleConfig.extra_capabilities`.

================================================================================
DECISION: where the attacker stands after a rule fires
================================================================================

A path is a sequence, so the attacker has a position, and the rule tables never
say what it becomes. Taking it to be the traversed edge's ``dst`` is wrong for
R12 and R13, whose effects land on ``src``: the attacker exploits a
vulnerability and ends up on the host, not standing on the CVE record.

The rule adopted here:

    The attacker moves to ``dst`` if any of the rule's effects bind to ``dst``,
    and otherwise stays at ``src``.

Which reads out as: you end up wherever the rule gave you something. It puts the
attacker on the group after R1, on the credential after R6 and R7, on the
service account after R10, and leaves them on the host after R12 and R13.

================================================================================
DECISION: rules that require no capability at all
================================================================================

A traversal rule with no capability precondition asks nothing of the attacker's
state, and R8 is the one in the shipped model: a credential in a public
repository requires no identity, no access and no position. Offering its edges
only from the node the attacker is standing on would make position a
precondition R8 does not have, and ``docs/RULES.md`` §4 lists its preconditions
as *none*.

The rule adopted here:

    A traversal rule with no capability precondition is offered against every
    edge of its type in the graph, from any position. Every other traversal rule
    is offered only against edges incident to the attacker's position.

The differential harness is what surfaced this: the engine indexes such rules
separately and fires them from every state, the oracle did not, and the two
disagreed on a public-repository exposure the engine was right about. Both now
read R8 the same way, which is §7 invariant 8 holding rather than being argued
about.

================================================================================
DECISION: bidirectional edges
================================================================================

R11 says the edge "is traversed in its stored direction unless
``E.bidirectional = true``". That is a statement about the search rather than a
precondition, so there is no row for it and it has to live here. It is applied
generically — any edge carrying ``bidirectional = true`` may also be consumed
from its ``dst`` end, with ``src`` and ``dst`` swapped for precondition and
effect binding — rather than being special-cased to ``TRUSTS``, because
"this edge is undirected" is a fact about the edge, not about one rule.

An edge without it is simply not a candidate from its far end. No rejection is
recorded for the attempt, for the same reason no rejection is recorded for an
edge that does not exist: refusing to invent an edge is not a refusal to fire a
rule.

================================================================================
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Mapping

from core.ids import path_id as content_path_id
from core.ids import rejection_signature
from core.model import (
    AttackerState,
    AttackPath,
    Binding,
    Capability,
    Edge,
    GraphSnapshot,
    Hop,
    Node,
    Precondition,
    PreconditionKind,
    Rejection,
    Rule,
    ThreatModel,
)
from oracle.loader import CapabilityAtom, RuleDataError, RuleSet
from oracle.preconditions import (
    PreconditionOutcome,
    evaluate_precondition,
    resolve_capability,
)

__all__ = [
    "BIDIRECTIONAL_ATTR",
    "DEFAULT_MAX_HOPS",
    "DEFAULT_MAX_STATES",
    "OracleBudgetExceeded",
    "OracleConfig",
    "OracleResult",
    "UNSCORED",
    "canonical_path_key",
    "discover",
    "entry_nodes_for",
    "materialise_grants",
    "verify_path",
]


#: Hop cap. Matches the value the engine records in ``analysis_run.max_hops``
#: for its own baseline runs, so the two enumerate over the same horizon and a
#: differential comparison is not measuring a difference in budget.
DEFAULT_MAX_HOPS = 8

#: Backstop against a graph that is simply too big for an unpruned search. The
#: oracle raises rather than truncating: a reference implementation that
#: silently returns a subset of the answer is worse than one that refuses.
DEFAULT_MAX_STATES = 400_000

#: Edge attribute that makes an edge traversable from either end.
BIDIRECTIONAL_ATTR = "bidirectional"

#: Placed in every probability field. The oracle decides reachability, not
#: likelihood; see the module docstring.
UNSCORED = 1.0


class OracleBudgetExceeded(RuntimeError):
    """The unpruned search hit its state budget before finishing.

    Raised, never swallowed. The oracle is only meaningful when it is
    exhaustive, so a partial enumeration must not be mistaken for a complete
    one.
    """


# ── Configuration and result ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class OracleConfig:
    """Everything the search needs beyond the graph and the rules."""

    threat_model_code: str | None = None
    """``None`` takes the ruleset's default threat model."""

    max_hops: int = DEFAULT_MAX_HOPS

    goal_node_ids: frozenset[str] | None = None
    """``None`` takes the snapshot's crown jewels."""

    entry_node_ids: tuple[str, ...] | None = None
    """``None`` derives entry nodes from the threat model's node-scoped grants."""

    extra_capabilities: frozenset[Capability] = frozenset()
    """Held in addition to the threat model's grants, at every entry node.

    The honest way to express `docs/RULES.md` §5's D8, whose decoy and twin are
    the same graph and differ only in what the attacker already holds.
    """

    max_states: int = DEFAULT_MAX_STATES

    def __post_init__(self) -> None:
        if self.max_hops < 1:
            raise ValueError(f"max_hops must be at least 1, got {self.max_hops}")
        if self.max_states < 1:
            raise ValueError(f"max_states must be at least 1, got {self.max_states}")


@dataclass(frozen=True, slots=True)
class OracleResult:
    """What one exhaustive run found."""

    paths: tuple[AttackPath, ...]
    rejections: tuple[Rejection, ...]
    threat_model_code: str
    entry_node_ids: tuple[str, ...]
    goal_node_ids: tuple[str, ...]
    states_expanded: int
    hop_cap_hits: int
    """Branches abandoned because they reached ``max_hops``, not because they ended."""

    duration_s: float


# ── Starting state ───────────────────────────────────────────────────────────


def _threat_model(ruleset: RuleSet, code: str | None) -> ThreatModel:
    if code is None:
        return ruleset.default_threat_model()
    try:
        return ruleset.threat_models[code]
    except KeyError:
        raise RuleDataError(f"no threat model {code!r} was loaded") from None


def entry_nodes_for(
    ruleset: RuleSet, threat_model: ThreatModel, snapshot: GraphSnapshot
) -> tuple[str, ...]:
    """Nodes the attacker could be starting from, in id order.

    Every node named by a node-scoped grant, either directly or through its
    kind. A global-only threat model has no entry node to stand at and is
    refused rather than silently searched from nowhere.
    """
    entries: set[str] = set()
    for code, kind, node_id in threat_model.grants:
        atom = ruleset.atoms[code]
        if atom.is_global:
            continue
        if node_id is not None:
            if snapshot.get_node(node_id) is not None:
                entries.add(node_id)
            continue
        entries.update(n.node_id for n in snapshot.all_nodes if n.kind == kind)
    if not entries:
        raise RuleDataError(
            f"threat model {threat_model.code!r} names no node the attacker could "
            f"start from in this graph"
        )
    return tuple(sorted(entries))


def materialise_grants(
    ruleset: RuleSet,
    threat_model: ThreatModel,
    snapshot: GraphSnapshot,
    entry_node_id: str,
) -> frozenset[Capability]:
    """The capabilities the attacker holds before taking a single hop.

    See the module docstring for how a kind-scoped grant is instantiated: about
    the entry node when the kinds match, about every node of the kind otherwise.
    """
    entry = snapshot.get_node(entry_node_id)
    if entry is None:
        raise ValueError(f"entry node {entry_node_id!r} is not in this snapshot")

    held: set[Capability] = set()
    for code, kind, node_id in threat_model.grants:
        atom = ruleset.atoms[code]
        if atom.is_global:
            held.add(Capability(code, None))
            continue
        if node_id is not None:
            if snapshot.get_node(node_id) is not None:
                held.add(Capability(code, node_id))
            continue
        if kind == entry.kind:
            held.add(Capability(code, entry_node_id))
        else:
            held.update(
                Capability(code, n.node_id) for n in snapshot.all_nodes if n.kind == kind
            )
    return frozenset(held)


# ── Candidates ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Candidate:
    """One rule applied at one place: the unit the search accepts or refuses."""

    rule: Rule
    src_id: str
    dst_id: str
    edge: Edge | None

    @property
    def edge_id(self) -> str | None:
        return self.edge.edge_id if self.edge is not None else None


def _candidates(
    snapshot: GraphSnapshot, ruleset: RuleSet, position: str
) -> Iterator[_Candidate]:
    """Every rule application the model permits from *position*.

    Deterministic: rules in id order, edges in edge-id order (the snapshot sorts
    its adjacency), non-traversal targets in node-id order. Two runs must
    enumerate in the same sequence, because the order rejections are recorded in
    is observable.
    """
    for rule in ruleset.rules:
        if rule.is_traversal:
            if _requires_no_capability(rule):
                # Position is not one of this rule's preconditions, so it must
                # not act as one. See the module docstring.
                for edge in sorted(snapshot.all_edges, key=lambda e: e.edge_id):
                    if edge.edge_type == rule.edge_type:
                        yield _Candidate(rule, edge.src_id, edge.dst_id, edge)
                continue
            for edge in snapshot.out_edges(position):
                if edge.edge_type == rule.edge_type:
                    yield _Candidate(rule, position, edge.dst_id, edge)
            for edge in snapshot.in_edges(position):
                if edge.edge_type == rule.edge_type and _is_bidirectional(edge):
                    yield _Candidate(rule, position, edge.src_id, edge)
        else:
            # A rule that consumes no edge is offered against every node in the
            # graph: nothing in the graph connects the attacker to a
            # kerberoastable account, so nothing in the graph can narrow the
            # candidate set either. Its preconditions do the narrowing.
            for node_id in sorted(snapshot.node_ids):
                yield _Candidate(rule, position, node_id, None)


def _is_bidirectional(edge: Edge) -> bool:
    return edge.attr(BIDIRECTIONAL_ATTR) is True


def _requires_no_capability(rule: Rule) -> bool:
    return not any(
        p.kind == PreconditionKind.CAPABILITY for p in rule.preconditions
    )


def _first_unmet(
    rule: Rule,
    capabilities: frozenset[Capability],
    edge: Edge | None,
    src_node: Node,
    dst_node: Node,
    global_capability_codes: frozenset[str],
) -> tuple[Precondition, PreconditionOutcome] | None:
    """The first precondition that does not hold, or ``None`` if all of them do.

    Conjunctive, and it stops at the first failure, so every refusal is
    attributable to exactly one row — which is what ``docs/RULES.md`` §4 asks
    for and what makes a rejection worth reporting.
    """
    for precondition in rule.preconditions:
        outcome = evaluate_precondition(
            precondition,
            capabilities=capabilities,
            edge=edge,
            src_node=src_node,
            dst_node=dst_node,
            global_capability_codes=global_capability_codes,
        )
        if not outcome.holds:
            return precondition, outcome
    return None


def _granted_by(
    rule: Rule, atoms: Mapping[str, CapabilityAtom], src_id: str, dst_id: str
) -> tuple[Capability, ...]:
    return tuple(
        resolve_capability(
            effect.capability_code,
            effect.binding,
            atom_is_global=atoms[effect.capability_code].is_global,
            src_id=src_id,
            dst_id=dst_id,
        )
        for effect in rule.effects
    )


def _position_after(rule: Rule, src_id: str, dst_id: str) -> str:
    """Where the attacker stands once *rule* has fired. See the module docstring."""
    if any(effect.binding == Binding.DST for effect in rule.effects):
        return dst_id
    return src_id


def _reason_code(precondition: Precondition) -> str:
    """A stable machine code for why a candidate was refused.

    The shape matches what already appears in ``rejected_candidate.reason_code``
    so the two implementations' refusals can be compared without a translation
    table.
    """
    if precondition.kind == PreconditionKind.CAPABILITY:
        prefix = "unexpected_capability" if precondition.is_negated else "missing_capability"
        return f"{prefix}:{precondition.capability_code}"
    suffix = ":not" if precondition.is_negated else ""
    if precondition.kind == PreconditionKind.EDGE_ATTR:
        return f"edge_attr:{precondition.attr_path}:{precondition.operator}{suffix}"
    return (
        f"node_attr:{precondition.binding.value}:{precondition.attr_path}:"
        f"{precondition.operator}{suffix}"
    )


# ── The search ───────────────────────────────────────────────────────────────


@dataclass(slots=True)
class _Run:
    """Mutable bookkeeping for one call to :func:`discover`. Not part of the API."""

    snapshot: GraphSnapshot
    ruleset: RuleSet
    config: OracleConfig
    goals: frozenset[str]
    global_capability_codes: frozenset[str]
    paths: list[AttackPath] = field(default_factory=list)
    rejections: dict[str, Rejection] = field(default_factory=dict)
    states_expanded: int = 0
    hop_cap_hits: int = 0


def discover(
    snapshot: GraphSnapshot,
    ruleset: RuleSet,
    config: OracleConfig | None = None,
) -> OracleResult:
    """Enumerate every attack path from the threat model's start to a goal node."""
    config = config or OracleConfig()
    threat_model = _threat_model(ruleset, config.threat_model_code)
    goals = (
        frozenset(config.goal_node_ids)
        if config.goal_node_ids is not None
        else snapshot.crown_jewels
    )
    entries = (
        tuple(config.entry_node_ids)
        if config.entry_node_ids is not None
        else entry_nodes_for(ruleset, threat_model, snapshot)
    )
    for entry in entries:
        if snapshot.get_node(entry) is None:
            raise ValueError(f"entry node {entry!r} is not in this snapshot")

    run = _Run(
        snapshot=snapshot,
        ruleset=ruleset,
        config=config,
        goals=goals,
        global_capability_codes=ruleset.global_capability_codes,
    )

    started = time.perf_counter()
    for entry in entries:
        held = materialise_grants(ruleset, threat_model, snapshot, entry)
        start = AttackerState(entry, held | config.extra_capabilities)
        _walk(run, entry, start, (), frozenset({start}))
    elapsed = time.perf_counter() - started

    return OracleResult(
        paths=tuple(sorted(run.paths, key=lambda p: (len(p.hops), canonical_path_key(p)))),
        rejections=tuple(
            sorted(
                run.rejections.values(),
                key=lambda r: (r.hop_depth, r.rule_id, r.src_node_id, r.dst_node_id, r.signature),
            )
        ),
        threat_model_code=threat_model.code,
        entry_node_ids=entries,
        goal_node_ids=tuple(sorted(goals)),
        states_expanded=run.states_expanded,
        hop_cap_hits=run.hop_cap_hits,
        duration_s=elapsed,
    )


def _walk(
    run: _Run,
    entry_node_id: str,
    state: AttackerState,
    hops: tuple[Hop, ...],
    on_branch: frozenset[AttackerState],
) -> None:
    """Expand one state, recording every path and every refusal it reaches."""
    run.states_expanded += 1
    if run.states_expanded > run.config.max_states:
        raise OracleBudgetExceeded(
            f"exhaustive search expanded more than {run.config.max_states} states; "
            f"this graph is too large for the oracle"
        )
    if len(hops) >= run.config.max_hops:
        run.hop_cap_hits += 1
        return

    for candidate in _candidates(run.snapshot, run.ruleset, state.node_id):
        src_node = run.snapshot.node(candidate.src_id)
        dst_node = run.snapshot.node(candidate.dst_id)
        unmet = _first_unmet(
            candidate.rule,
            state.capabilities,
            candidate.edge,
            src_node,
            dst_node,
            run.global_capability_codes,
        )
        if unmet is not None:
            _record_rejection(run, candidate, unmet, len(hops))
            continue

        granted = _granted_by(
            candidate.rule, run.ruleset.atoms, candidate.src_id, candidate.dst_id
        )
        gained = tuple(sorted(c for c in granted if c not in state.capabilities))
        position = _position_after(candidate.rule, candidate.src_id, candidate.dst_id)
        successor = AttackerState(position, state.capabilities | frozenset(granted))

        # Termination, not caching: this branch has already stood in exactly
        # this state, so everything reachable from here it has already tried.
        # A different branch reaching the same state still explores it in full.
        if successor in on_branch:
            continue

        hop = Hop(
            hop_no=len(hops) + 1,
            src_node_id=candidate.src_id,
            dst_node_id=candidate.dst_id,
            edge_id=candidate.edge_id,
            technique_code=candidate.rule.technique_code,
            rule_id=candidate.rule.rule_id,
            p_succ=UNSCORED,
            detectability=0.0,
            neg_log_contribution=0.0,
            gained=gained,
            factors=(),
        )
        extended = hops + (hop,)
        if position in run.goals:
            run.paths.append(_build_path(run, entry_node_id, position, extended))
        _walk(run, entry_node_id, successor, extended, on_branch | {successor})


def _record_rejection(
    run: _Run,
    candidate: _Candidate,
    unmet: tuple[Precondition, PreconditionOutcome],
    depth: int,
) -> None:
    precondition, outcome = unmet
    signature = rejection_signature(
        candidate.src_id, candidate.dst_id, candidate.edge_id, candidate.rule.rule_id, depth
    )
    # ``core.ids.rejection_signature`` exists to collapse the same dead end
    # reached from many prefixes into one record; the first refusal recorded for
    # a signature is the one kept.
    if signature in run.rejections:
        return
    run.rejections[signature] = Rejection(
        signature=signature,
        src_node_id=candidate.src_id,
        dst_node_id=candidate.dst_id,
        edge_id=candidate.edge_id,
        rule_id=candidate.rule.rule_id,
        precondition_seq=precondition.seq,
        reason_code=_reason_code(precondition),
        reason_text=precondition.failure_reason,
        observed_value=outcome.observed,
        hop_depth=depth,
    )


def _build_path(
    run: _Run, entry_node_id: str, target_node_id: str, hops: tuple[Hop, ...]
) -> AttackPath:
    target = run.snapshot.node(target_node_id)
    return AttackPath(
        path_id=content_path_id(
            [h.edge_id for h in hops], [h.rule_id for h in hops]
        ),
        source_node_id=entry_node_id,
        target_node_id=target_node_id,
        hops=hops,
        p_success=UNSCORED,
        neg_log_success=0.0,
        p_undetected=UNSCORED,
        bottleneck_p=UNSCORED,
        bottleneck_hop=hops[-1].hop_no,
        impact_score=0.0,
        risk_score=0.0,
        risk_tier_code="",
        target_is_crown_jewel=target.is_crown_jewel,
    )


# ── Identity and independent verification ────────────────────────────────────


def canonical_path_key(path: AttackPath) -> tuple[tuple[str, int, str, str], ...]:
    """Path identity for comparing two implementations' output.

    Finer than :func:`core.ids.path_id`, deliberately. ``path_id`` hashes only
    the (edge id, rule id) pairs, so two applications of the same non-traversal
    rule — which carry no edge id — collide even when they target different
    nodes: kerberoasting two different service accounts from the same position
    produces one id for two different attacks. Including the endpoints makes
    the key exact, and it is still purely structural, so it can be computed for
    a path produced by either implementation.
    """
    return tuple(
        (hop.edge_id or "", hop.rule_id, hop.src_node_id, hop.dst_node_id)
        for hop in path.hops
    )


def verify_path(
    path: AttackPath,
    *,
    snapshot: GraphSnapshot,
    ruleset: RuleSet,
    initial_capabilities: Iterable[Capability],
) -> tuple[str, ...]:
    """Re-check a path hop by hop, independently of the search that produced it.

    ``docs/RULES.md`` §7 invariant 5: every hop of a discovered path satisfies
    its rule's preconditions given the state the preceding hops accumulated,
    and that must be checkable without trusting the search. Returns one sentence
    per problem found; an empty tuple means the path holds up.
    """
    problems: list[str] = []
    held = frozenset(initial_capabilities)
    global_codes = ruleset.global_capability_codes

    for hop in path.hops:
        try:
            rule = ruleset.by_id(hop.rule_id)
        except KeyError:
            problems.append(f"hop {hop.hop_no} cites rule id {hop.rule_id}, which is not loaded")
            continue

        edge: Edge | None = None
        if hop.edge_id is not None:
            edge = snapshot.edge(hop.edge_id)
            if not rule.is_traversal:
                problems.append(
                    f"hop {hop.hop_no} uses non-traversal rule {rule.code!r} but names an edge"
                )
            elif edge.edge_type != rule.edge_type:
                problems.append(
                    f"hop {hop.hop_no} traverses a {edge.edge_type} edge with rule "
                    f"{rule.code!r}, which consumes {rule.edge_type}"
                )
            elif (edge.src_id, edge.dst_id) != (hop.src_node_id, hop.dst_node_id):
                if (edge.dst_id, edge.src_id) != (hop.src_node_id, hop.dst_node_id):
                    problems.append(
                        f"hop {hop.hop_no} claims {hop.src_node_id} -> {hop.dst_node_id} "
                        f"over an edge that runs {edge.src_id} -> {edge.dst_id}"
                    )
                elif not _is_bidirectional(edge):
                    problems.append(
                        f"hop {hop.hop_no} traverses edge {edge.edge_id} against its stored "
                        f"direction, but it is not bidirectional"
                    )
        elif rule.is_traversal:
            problems.append(
                f"hop {hop.hop_no} uses traversal rule {rule.code!r} but names no edge"
            )

        unmet = _first_unmet(
            rule,
            held,
            edge,
            snapshot.node(hop.src_node_id),
            snapshot.node(hop.dst_node_id),
            global_codes,
        )
        if unmet is not None:
            precondition, outcome = unmet
            problems.append(
                f"hop {hop.hop_no} ({rule.code}) does not satisfy precondition "
                f"seq {precondition.seq}: {precondition.failure_reason} "
                f"[observed {outcome.observed}]"
            )

        granted = _granted_by(rule, ruleset.atoms, hop.src_node_id, hop.dst_node_id)
        expected_gain = tuple(sorted(c for c in granted if c not in held))
        if tuple(sorted(hop.gained)) != expected_gain:
            problems.append(
                f"hop {hop.hop_no} records gaining {[str(c) for c in hop.gained]} but "
                f"{rule.code!r} grants {[str(c) for c in expected_gain]} from this state"
            )
        held = held | frozenset(granted)

    if path.hops:
        final = _position_after(
            ruleset.by_id(path.hops[-1].rule_id),
            path.hops[-1].src_node_id,
            path.hops[-1].dst_node_id,
        )
        if final != path.target_node_id:
            problems.append(
                f"path ends at {final} but is recorded as reaching {path.target_node_id}"
            )
    else:
        problems.append("path has no hops")

    return tuple(problems)
