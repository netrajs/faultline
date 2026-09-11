"""Shared domain model.

Everything that crosses a subsystem boundary is defined here: the generator
writes these types, the engine searches over them, the reference oracle
independently evaluates them, and the API serialises them. One definition, so
the three implementations cannot quietly disagree about what a capability is.

Two decisions in here carry most of the weight.

**A capability is a pair, not a flag.** ``Capability("admin_on", "h-014")`` is a
distinct thing from ``Capability("admin_on", "h-015")``. Modelling privilege as a
scalar level invites comparisons like ``level >= 2``, which silently makes every
high privilege imply every lower one — and that is false. Database
administrator does not imply host administrator, and an attacker holding one
does not hold the other.

**State is an immutable frozenset.** Search proceeds over ``(node, capabilities)``
rather than over nodes alone, so states are dictionary keys, compared by subset
for dominance, and shared freely between search branches without defensive
copying. Immutability is what makes that safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping


# ── Vocabulary ───────────────────────────────────────────────────────────────
#
# These mirror rows in node_kind and edge_type. They are named constants for
# readability at call sites, not a second source of truth: a startup check
# asserts the database agrees, and the database wins.


class NodeKind(str, Enum):
    USER = "User"
    GROUP = "Group"
    SERVICE_ACCOUNT = "ServiceAccount"
    HOST = "Host"
    DATABASE = "Database"
    CLOUD_RESOURCE = "CloudResource"
    APPLICATION = "Application"
    CREDENTIAL = "Credential"
    VULNERABILITY = "Vulnerability"


class EdgeType(str, Enum):
    MEMBER_OF = "MEMBER_OF"
    HAS_CREDENTIAL = "HAS_CREDENTIAL"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    ADMIN_TO = "ADMIN_TO"
    HAS_ACCESS_TO = "HAS_ACCESS_TO"
    HAS_PERMISSION = "HAS_PERMISSION"
    TRUSTS = "TRUSTS"
    CONNECTED_TO = "CONNECTED_TO"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    EXPOSES_CREDENTIAL = "EXPOSES_CREDENTIAL"


class Binding(str, Enum):
    """Which end of a transition a precondition or effect refers to."""

    SRC = "src"
    DST = "dst"
    GLOBAL = "global"


class PreconditionKind(str, Enum):
    CAPABILITY = "capability"
    EDGE_ATTR = "edge_attr"
    NODE_ATTR = "node_attr"


# ── Graph ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Node:
    node_id: str
    kind: str
    name: str
    display_name: str | None = None
    is_crown_jewel: bool = False
    criticality: str | None = None
    classification: str | None = None
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def attr(self, path: str, default: Any = None) -> Any:
        return self.attrs.get(path, default)


@dataclass(frozen=True, slots=True)
class Edge:
    edge_id: str
    src_id: str
    dst_id: str
    edge_type: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def attr(self, path: str, default: Any = None) -> Any:
        return self.attrs.get(path, default)


class GraphSnapshot:
    """Immutable in-memory view of one graph version.

    Built once from the store and never mutated. Simulation layers a
    copy-on-write overlay over a snapshot rather than editing it, so a baseline
    and a counterfactual can be resident simultaneously and diffed against each
    other — which is what makes simulation-by-re-derivation possible at all.

    Adjacency is materialised eagerly in both directions. Forward adjacency
    drives the search; reverse adjacency drives the backward Dijkstra that
    produces the A* heuristic, and the same array answers "best path through
    this edge" for chokepoint ranking and incremental invalidation.
    """

    __slots__ = ("graph_version", "_nodes", "_edges", "_out", "_in", "_crown_jewels")

    def __init__(
        self,
        graph_version: int,
        nodes: Iterable[Node],
        edges: Iterable[Edge],
    ) -> None:
        self.graph_version = graph_version
        self._nodes: dict[str, Node] = {n.node_id: n for n in nodes}
        self._edges: dict[str, Edge] = {}
        self._out: dict[str, list[str]] = {}
        self._in: dict[str, list[str]] = {}

        for edge in edges:
            if edge.src_id not in self._nodes or edge.dst_id not in self._nodes:
                raise ValueError(
                    f"edge {edge.edge_id} references a node absent from this snapshot "
                    f"({edge.src_id} -> {edge.dst_id})"
                )
            self._edges[edge.edge_id] = edge
            self._out.setdefault(edge.src_id, []).append(edge.edge_id)
            self._in.setdefault(edge.dst_id, []).append(edge.edge_id)

        # Sorting makes traversal order deterministic, which is what lets two
        # runs of the same graph produce byte-identical results including tie
        # ordering. Without it, ranking is stable only up to hash iteration.
        for adjacency in (self._out, self._in):
            for node_id in adjacency:
                adjacency[node_id].sort()

        self._crown_jewels: frozenset[str] = frozenset(
            n.node_id for n in self._nodes.values() if n.is_crown_jewel
        )

    def node(self, node_id: str) -> Node:
        return self._nodes[node_id]

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def edge(self, edge_id: str) -> Edge:
        return self._edges[edge_id]

    def out_edges(self, node_id: str) -> list[Edge]:
        return [self._edges[e] for e in self._out.get(node_id, ())]

    def in_edges(self, node_id: str) -> list[Edge]:
        return [self._edges[e] for e in self._in.get(node_id, ())]

    def nodes_of_kind(self, kind: str) -> list[Node]:
        return [n for n in self._nodes.values() if n.kind == kind]

    @property
    def crown_jewels(self) -> frozenset[str]:
        return self._crown_jewels

    @property
    def node_ids(self) -> Iterable[str]:
        return self._nodes.keys()

    @property
    def all_nodes(self) -> Iterable[Node]:
        return self._nodes.values()

    @property
    def all_edges(self) -> Iterable[Edge]:
        return self._edges.values()

    def __len__(self) -> int:
        return len(self._nodes)

    def __repr__(self) -> str:
        return (
            f"GraphSnapshot(version={self.graph_version}, "
            f"nodes={len(self._nodes)}, edges={len(self._edges)})"
        )


# ── Attacker state ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, order=True)
class Capability:
    """Something the attacker holds.

    ``about`` is the node the capability concerns, or None for globally-scoped
    capabilities such as holding any authenticated directory identity.
    """

    code: str
    about: str | None = None

    def __str__(self) -> str:
        return f"{self.code}({self.about})" if self.about else self.code


@dataclass(frozen=True, slots=True)
class AttackerState:
    """Where the attacker is and what they hold.

    Dominance: a state dominates another at the same node when it holds a
    superset of its capabilities. Under monotonicity every useful transition
    strictly grows the set, so the state space is acyclic even though the
    underlying graph is not — a cycle in the graph revisits a node holding
    nothing new, and is pruned here rather than needing cycle detection.
    """

    node_id: str
    capabilities: frozenset[Capability]

    def holds(self, code: str, about: str | None = None) -> bool:
        return Capability(code, about) in self.capabilities

    def holds_any(self, code: str) -> bool:
        return any(c.code == code for c in self.capabilities)

    def grant(self, new: Iterable[Capability]) -> frozenset[Capability]:
        return self.capabilities | frozenset(new)

    def dominates(self, other: AttackerState) -> bool:
        return (
            self.node_id == other.node_id
            and other.capabilities <= self.capabilities
        )

    def moved_to(self, node_id: str, gained: Iterable[Capability]) -> AttackerState:
        return AttackerState(node_id, self.grant(gained))


# ── Rules ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Precondition:
    seq: int
    kind: PreconditionKind
    binding: Binding
    capability_code: str | None
    attr_path: str | None
    operator: str | None
    value: Any
    is_negated: bool
    failure_reason: str


@dataclass(frozen=True, slots=True)
class Effect:
    seq: int
    capability_code: str
    binding: Binding


@dataclass(frozen=True, slots=True)
class Rule:
    """One derivation rule, loaded from the rule tables.

    Preconditions are conjunctive: all must hold. Disjunction is expressed as
    two rules sharing a technique, which keeps the evaluator trivial and — the
    reason that matters — keeps every refusal attributable to exactly one unmet
    condition, so a rejection can explain itself.

    ``edge_type`` is None for a rule that fires on state alone and consumes no
    edge. Kerberoasting is the canonical case: nothing in the graph connects the
    attacker to the service account, and the capability arrives from a property
    of the directory itself.
    """

    rule_id: int
    code: str
    technique_code: str
    edge_type: str | None
    description: str
    is_traversal: bool
    preconditions: tuple[Precondition, ...]
    effects: tuple[Effect, ...]


@dataclass(frozen=True, slots=True)
class Technique:
    code: str
    name: str
    description: str
    attack_id: str | None
    attack_name: str | None
    attack_url: str | None
    phase: str


@dataclass(frozen=True, slots=True)
class ThreatModel:
    code: str
    label: str
    description: str
    grants: tuple[tuple[str, str | None, str | None], ...]
    """(capability_code, applies_to_kind, applies_to_node) — kind or node may be None."""


# ── Scoring ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ScoringModifier:
    code: str
    label: str
    applies_to: str
    attr_path: str
    operator: str
    value: Any
    target: str
    beta: float
    is_hard_block: bool
    technique_scope: frozenset[str]
    """Empty means it applies to every technique."""


@dataclass(frozen=True, slots=True)
class RiskTier:
    code: str
    label: str
    min_score: float
    max_score: float
    ui_color: str
    ui_bg_color: str
    action_text: str


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    """The scoring constants, versioned so any displayed score is reproducible.

    ``raw_max`` is the negative log probability at which a path is treated as
    negligible — ``-ln(1e-4)``, roughly 9.21. The likelihood component is
    ``1 - min(neg_log / raw_max, 1)``, which puts likelihood on a log scale.
    That matters because path probabilities span orders of magnitude, and a
    linear scale would compress every multi-hop path into the bottom tier
    regardless of how much they differ from one another.

    The three weights sum to 1.0, which is what makes the full 0–10 range
    attainable and every tier boundary reachable.
    """

    version: str
    label: str
    p_clamp_min: float
    p_clamp_max: float
    raw_max: float
    w_likelihood: float
    w_impact: float
    w_stealth: float
    baselines: Mapping[str, tuple[float, float]]
    """technique_code -> (base_p_succ, base_detectability)"""
    modifiers: tuple[ScoringModifier, ...]
    impact_weights: Mapping[tuple[str, str], float]
    """(dimension, code) -> weight"""
    tiers: tuple[RiskTier, ...]

    def tier_for(self, score: float) -> RiskTier:
        for tier in self.tiers:
            if tier.min_score <= score <= tier.max_score:
                return tier
        raise ValueError(f"no tier covers score {score}")


# ── Results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ScoreFactor:
    """One line of a hop's probability derivation.

    Because the score is a sum of log-odds terms, a factor's contribution is
    exactly its own term rather than an approximation of it — the attribution
    falls out of the arithmetic instead of needing to be estimated.
    """

    seq: int
    factor_kind: str
    factor_code: str
    factor_label: str
    observed_value: str | None
    beta: float | None
    p_after: float


@dataclass(frozen=True, slots=True)
class Hop:
    hop_no: int
    src_node_id: str
    dst_node_id: str
    edge_id: str | None
    technique_code: str
    rule_id: int
    p_succ: float
    detectability: float
    neg_log_contribution: float
    gained: tuple[Capability, ...]
    factors: tuple[ScoreFactor, ...]


@dataclass(frozen=True, slots=True)
class AttackPath:
    """A discovered path.

    ``path_id`` is a content hash over the edge sequence — see ``core.ids``.
    Edge ids rather than node ids, because two different credentials between
    the same user and host are two genuinely different attacks that a
    node-keyed identity would merge.
    """

    path_id: str
    source_node_id: str
    target_node_id: str
    hops: tuple[Hop, ...]
    p_success: float
    neg_log_success: float
    p_undetected: float
    bottleneck_p: float
    bottleneck_hop: int
    impact_score: float
    risk_score: float
    risk_tier_code: str
    target_is_crown_jewel: bool

    @property
    def hop_count(self) -> int:
        return len(self.hops)


@dataclass(frozen=True, slots=True)
class Rejection:
    """A candidate the search reached and refused.

    Recorded rather than discarded. What a tool declines to report, and whether
    it can say why, is a harder claim than what it reports — and it is the claim
    that distinguishes precondition-aware search from reachability.
    """

    signature: str
    src_node_id: str
    dst_node_id: str
    edge_id: str | None
    rule_id: int
    precondition_seq: int | None
    reason_code: str
    reason_text: str
    observed_value: str | None
    hop_depth: int
