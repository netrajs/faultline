"""Greedy set cover over path coverage, with the optimality gap stated.

``docs/SCOPE.md`` D5: rank cut candidates by how many discovered attack paths
each one covers, select greedily, and *display the gap*. Path coverage is a
coverage function over sets, so it is monotone and submodular, and greedy
maximisation of a submodular function under a cardinality constraint is within
``1 - 1/e`` (about 63%) of optimal. That is a theorem, not an estimate, which is
why the bound is stored per rank rather than described in prose somewhere: a
reviewer who knows the result will ask, and "optimal" would be a false claim.

The bound is read in the direction that is actually useful. Greedy achieved
cumulative coverage ``g`` at rank ``k``; the best any selection of ``k``
candidates could achieve is therefore at most ``g / (1 - 1/e)``, capped at 1.0.
So a row reading "covers 0.85 of paths, bound 1.00" is saying *a perfect
selection of this size might reach everything*, and one reading "0.63, bound
1.00" is saying much less than it appears to.

Candidates are edges and *intermediate* nodes. A path's own source and target
are excluded on purpose: deleting the crown jewel is not a remediation, and
neither is deleting the identity the attacker phished.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from remediation.cuts import VertexCut, min_vertex_cut

#: The greedy approximation ratio for a monotone submodular coverage function
#: under a cardinality constraint. Named rather than inlined because it appears
#: in a number the interface displays.
GREEDY_RATIO = 1.0 - 1.0 / math.e


@dataclass(frozen=True, slots=True)
class PathCoverage:
    """One discovered path, reduced to what set cover needs from it.

    ``hops`` is ``(src, dst, edge_id)`` per hop in order, with ``edge_id`` None
    for a non-traversal rule that consumes no edge. The hop list rather than a
    node sequence, because a path is a proof DAG and not necessarily a chain:
    a required side excursion's hop does not continue from where the previous
    one ended, and reading adjacency off a flattened node list would invent
    edges that are not in the graph.
    """

    path_id: str
    source_node_id: str
    target_node_id: str
    hops: tuple[tuple[str, str, str | None], ...]
    risk_score: float

    @property
    def edge_ids(self) -> tuple[str, ...]:
        return tuple(edge for _, _, edge in self.hops if edge)

    @property
    def node_ids(self) -> tuple[str, ...]:
        ordered: list[str] = [self.source_node_id]
        for src, dst, _ in self.hops:
            ordered.extend((src, dst))
        seen: list[str] = []
        for node_id in ordered:
            if node_id not in seen:
                seen.append(node_id)
        return tuple(seen)

    @property
    def intermediate_node_ids(self) -> tuple[str, ...]:
        endpoints = {self.source_node_id, self.target_node_id}
        return tuple(n for n in self.node_ids if n not in endpoints)


@dataclass(frozen=True, slots=True)
class Candidate:
    """A cut candidate and the paths it sits on."""

    kind: str
    """'edge' or 'node'."""
    target_id: str
    path_ids: frozenset[str]

    @property
    def key(self) -> tuple[str, str]:
        return self.kind, self.target_id


@dataclass(frozen=True, slots=True)
class Chokepoint:
    rank_in_run: int
    kind: str
    target_id: str
    paths_covered: int
    """Paths this candidate sits on, in total — not only the ones it was the
    first to cover. Marginal gain is what greedy selects by; total coverage is
    what a reader wants to see next to a target id."""
    marginal_paths: int
    coverage_fraction: float
    cumulative_fraction: float
    optimality_bound: float


@dataclass(frozen=True, slots=True)
class ChokepointAnalysis:
    total_paths: int
    chokepoints: tuple[Chokepoint, ...]
    candidates: Mapping[tuple[str, str], frozenset[str]]
    """Every candidate's coverage, not just the selected ones — the
    recommendation pass needs coverage for targets greedy did not rank."""
    min_cut: VertexCut
    """Exact minimum vertex cut over the subgraph the paths induce. Reported
    beside the greedy selection because it is the one number in this module that
    is not an approximation: it says how many nodes it would take to sever every
    discovered path, so a greedy node selection larger than this is visibly
    leaving something on the table."""


def build_candidates(paths: Sequence[PathCoverage]) -> list[Candidate]:
    """Every edge and intermediate node that appears on at least one path."""
    by_edge: dict[str, set[str]] = {}
    by_node: dict[str, set[str]] = {}
    for path in paths:
        for edge_id in path.edge_ids:
            by_edge.setdefault(edge_id, set()).add(path.path_id)
        for node_id in path.intermediate_node_ids:
            by_node.setdefault(node_id, set()).add(path.path_id)

    candidates = [
        Candidate("edge", target, frozenset(covered))
        for target, covered in sorted(by_edge.items())
    ]
    candidates += [
        Candidate("node", target, frozenset(covered))
        for target, covered in sorted(by_node.items())
    ]
    return candidates


def greedy_cover(
    paths: Sequence[PathCoverage],
    *,
    limit: int = 20,
) -> tuple[Chokepoint, ...]:
    """Rank cut candidates by marginal path coverage, greedily.

    Ties are broken by total coverage, then kind, then id — all derived from the
    data rather than from dictionary order, so two runs over the same paths
    produce the same ranking including its ties.
    """
    total = len(paths)
    if total == 0:
        return ()

    # Pre-sorted into tie-break order, because ``max`` returns the first
    # maximal element: total coverage descending, then an edge ahead of a node
    # (severing one relationship is a smaller change than deleting a whole
    # principal or asset), then the id. Every key is derived from the data, so
    # two runs over the same paths rank identically including their ties.
    remaining = sorted(
        build_candidates(paths),
        key=lambda c: (-len(c.path_ids), c.kind != "edge", c.target_id),
    )
    uncovered = {path.path_id for path in paths}
    covered_so_far: set[str] = set()
    ranked: list[Chokepoint] = []

    while remaining and uncovered and len(ranked) < limit:
        best = max(remaining, key=lambda c: len(c.path_ids & uncovered))
        marginal = len(best.path_ids & uncovered)
        if marginal == 0:
            break
        remaining.remove(best)
        uncovered -= best.path_ids
        covered_so_far |= best.path_ids
        cumulative = len(covered_so_far) / total
        ranked.append(
            Chokepoint(
                rank_in_run=len(ranked) + 1,
                kind=best.kind,
                target_id=best.target_id,
                paths_covered=len(best.path_ids),
                marginal_paths=marginal,
                coverage_fraction=len(best.path_ids) / total,
                cumulative_fraction=cumulative,
                optimality_bound=min(1.0, cumulative / GREEDY_RATIO),
            )
        )

    return tuple(ranked)


def analyse(
    paths: Sequence[PathCoverage],
    *,
    limit: int = 20,
    adjacency: Mapping[str, Sequence[str]] | None = None,
) -> ChokepointAnalysis:
    """Greedy cover plus the exact minimum vertex cut over the same paths."""
    candidates = {c.key: c.path_ids for c in build_candidates(paths)}
    if adjacency is None:
        adjacency = path_adjacency(paths)
    cut = min_vertex_cut(
        adjacency,
        sources=sorted({p.source_node_id for p in paths}),
        sinks=sorted({p.target_node_id for p in paths}),
    )
    return ChokepointAnalysis(
        total_paths=len(paths),
        chokepoints=greedy_cover(paths, limit=limit),
        candidates=candidates,
        min_cut=cut,
    )


def path_adjacency(paths: Iterable[PathCoverage]) -> dict[str, list[str]]:
    """Node adjacency induced by the discovered paths only.

    The cut is computed over this subgraph rather than the whole graph on
    purpose. A cut of the full graph would answer "what disconnects everything
    from everything", including routes the engine already refused as
    unexploitable — and a remediation ranked against refused candidates is
    ranked against nothing.
    """
    adjacency: dict[str, set[str]] = {}
    for path in paths:
        for src, dst, _ in path.hops:
            if src == dst:
                continue
            adjacency.setdefault(src, set()).add(dst)
    return {src: sorted(dsts) for src, dsts in sorted(adjacency.items())}
