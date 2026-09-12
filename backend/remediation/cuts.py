"""Minimum vertex cut by node splitting and Dinic max-flow.

``docs/SCOPE.md`` D5 is explicit that a chokepoint is a *cut*, not a centrality.
Betweenness answers which node sits on many shortest paths, which is a fact
about topology; the question remediation asks is which set of nodes, if
unavailable, leaves the attacker with no route at all. Those are different
questions and they have different answers — a node can be maximally central and
be one of four parallel routes, so removing it changes nothing.

The construction is standard and is the reason this is a cut problem at all:
split every vertex ``v`` into ``v_in -> v_out`` with capacity 1 and give the
original edges infinite capacity. Any finite cut therefore consists only of
split edges, and a minimum cut of ``k`` split edges is a set of ``k`` vertices
whose removal disconnects the sources from the sinks. Menger's theorem gives the
other half: that minimum equals the maximum number of internally
vertex-disjoint source-to-sink paths, so the number is also a statement about how
much redundancy the attacker has.

Sources and sinks are protected by giving *their* split edges infinite capacity:
"cut the crown jewel" is not a remediation, and neither is deleting the user
whose account was phished.

Dinic rather than Edmonds-Karp because unit-capacity networks are where Dinic's
bound is strongest (O(E sqrt(V))), and hand-rolled because at this scale the
whole algorithm is shorter than the code it would take to marshal the graph into
a third-party library's own representation.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

#: The initial limit on an augmenting path, before any arc has narrowed it.
#: Infinity is safe *here* because every arc in the network carries a finite
#: capacity (see ``uncuttable_capacity`` in ``min_vertex_cut``), so the first arc
#: on any path bounds it; it is not safe as a capacity, which is what the comment
#: there is about.
_NO_LIMIT = float("inf")


@dataclass(frozen=True, slots=True)
class VertexCut:
    """A minimum set of vertices whose removal severs source from sink."""

    vertices: tuple[str, ...]
    size: int
    """Max-flow value. Equals ``len(vertices)`` and, by Menger, the number of
    internally vertex-disjoint routes the attacker has."""

    reachable: frozenset[str]
    """Vertices still reachable from the sources after the cut, for explaining
    which side of the cut a node fell on."""


class _Dinic:
    """Max-flow on a directed graph with a residual adjacency list."""

    __slots__ = ("_to", "_cap", "_head", "_level", "_iter", "size")

    def __init__(self, size: int) -> None:
        self.size = size
        self._to: list[int] = []
        self._cap: list[float] = []
        self._head: list[list[int]] = [[] for _ in range(size)]
        self._level: list[int] = []
        self._iter: list[int] = []

    def add_edge(self, src: int, dst: int, capacity: float) -> None:
        self._head[src].append(len(self._to))
        self._to.append(dst)
        self._cap.append(capacity)
        # The reverse arc carries zero capacity and exists so that pushing flow
        # can be undone. Without it the algorithm is a greedy augmenting walk
        # and is simply wrong, not merely slower.
        self._head[dst].append(len(self._to))
        self._to.append(src)
        self._cap.append(0.0)

    def max_flow(self, source: int, sink: int) -> float:
        flow = 0.0
        while True:
            self._level = self._bfs(source)
            if self._level[sink] < 0:
                return flow
            self._iter = [0] * self.size
            while True:
                pushed = self._dfs(source, sink, _NO_LIMIT)
                if pushed <= 0.0:
                    break
                flow += pushed

    def _bfs(self, source: int) -> list[int]:
        level = [-1] * self.size
        level[source] = 0
        queue = deque([source])
        while queue:
            node = queue.popleft()
            for arc in self._head[node]:
                if self._cap[arc] <= 0.0:
                    continue
                nxt = self._to[arc]
                if level[nxt] >= 0:
                    continue
                level[nxt] = level[node] + 1
                queue.append(nxt)
        return level

    def _dfs(self, node: int, sink: int, limit: float) -> float:
        if node == sink:
            return limit
        while self._iter[node] < len(self._head[node]):
            arc = self._head[node][self._iter[node]]
            nxt = self._to[arc]
            if self._cap[arc] > 0.0 and self._level[nxt] == self._level[node] + 1:
                pushed = self._dfs(nxt, sink, min(limit, self._cap[arc]))
                if pushed > 0.0:
                    self._cap[arc] -= pushed
                    self._cap[arc ^ 1] += pushed
                    return pushed
            # Only advance past an arc once it is exhausted for this phase.
            # Re-examining it would turn the blocking-flow pass quadratic.
            self._iter[node] += 1
        return 0.0

    def reachable_from(self, source: int) -> set[int]:
        """Vertices reachable in the residual graph — the source side of the cut."""
        seen = {source}
        queue = deque([source])
        while queue:
            node = queue.popleft()
            for arc in self._head[node]:
                if self._cap[arc] <= 0.0:
                    continue
                nxt = self._to[arc]
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen


def min_vertex_cut(
    adjacency: Mapping[str, Sequence[str]],
    sources: Iterable[str],
    sinks: Iterable[str],
    *,
    protected: Iterable[str] = (),
) -> VertexCut:
    """Smallest set of vertices separating ``sources`` from ``sinks``.

    ``adjacency`` is ``node -> successors`` over whatever subgraph the caller
    considers in scope. Sources, sinks and anything in ``protected`` are given
    uncuttable split edges, because removing the attacker's entry identity or the
    asset being protected is not a fix anyone would apply.

    Recursion depth is bounded by the number of split vertices on one
    augmenting path, which at this scale stays well inside the interpreter's
    limit; the subgraph passed in is the one induced by discovered paths, not the
    whole graph.
    """
    nodes = sorted(
        set(adjacency)
        | {dst for succ in adjacency.values() for dst in succ}
        | set(sources)
        | set(sinks)
    )
    index = {node: i for i, node in enumerate(nodes)}
    source_set = {s for s in sources if s in index}
    sink_set = {t for t in sinks if t in index}
    uncuttable = source_set | sink_set | {p for p in protected if p in index}

    if not source_set or not sink_set or source_set & sink_set:
        # Sharing a node means the attacker already starts at the goal, and no
        # vertex removal can separate a node from itself.
        return VertexCut(vertices=(), size=0, reachable=frozenset(source_set))

    # 0..n-1 are v_in, n..2n-1 are v_out, then the super source and sink.
    count = len(nodes)
    flow = _Dinic(2 * count + 2)
    super_source = 2 * count
    super_sink = 2 * count + 1

    # "Uncuttable" has to be a large finite number, not an infinite one. An
    # augmenting path made entirely of infinite arcs -- a source adjacent to a
    # sink is enough -- pushes infinite flow, and the residual update then
    # computes ``inf - inf``, which is NaN. NaN compares false against every
    # threshold in the search, so those arcs are neither usable nor exhausted
    # and the outer loop augments forever. The bound is the node count plus one
    # because every finite cut is a set of distinct split edges and so cannot
    # exceed the number of vertices; anything at or above it therefore means no
    # finite cut exists.
    uncuttable_capacity = float(count + 1)

    for node, i in index.items():
        flow.add_edge(i, count + i, uncuttable_capacity if node in uncuttable else 1.0)
    for src, successors in adjacency.items():
        if src not in index:
            continue
        for dst in successors:
            if dst in index:
                flow.add_edge(count + index[src], index[dst], uncuttable_capacity)
    for node in sorted(source_set):
        flow.add_edge(super_source, index[node], uncuttable_capacity)
    for node in sorted(sink_set):
        flow.add_edge(count + index[node], super_sink, uncuttable_capacity)

    value = flow.max_flow(super_source, super_sink)
    reached = flow.reachable_from(super_source)
    if value >= uncuttable_capacity:
        # Some route runs entirely through vertices nobody is allowed to remove
        # -- an entry identity adjacent to the crown jewel, or one reachable
        # only through protected nodes. There is no cut to propose, which is the
        # same answer this function already gives when a source is itself a
        # sink, and for the same reason.
        return VertexCut(
            vertices=(),
            size=0,
            reachable=frozenset(node for node, i in index.items() if i in reached),
        )
    # A split edge is in the cut exactly when its v_in is on the source side and
    # its v_out is not: that is the min-cut characterisation, read off the
    # residual graph rather than reconstructed by trying removals.
    cut = tuple(
        node
        for node, i in sorted(index.items())
        if i in reached and (count + i) not in reached
    )
    return VertexCut(
        vertices=cut,
        # Finite by the check above, and equal to ``len(cut)`` by the min-cut
        # theorem -- every unit of flow crosses exactly one cut split edge.
        size=int(value),
        reachable=frozenset(node for node, i in index.items() if i in reached),
    )
