"""Copy-on-write mutation overlay over an immutable snapshot.

A counterfactual needs the baseline to still exist. ``GraphSnapshot`` is
immutable precisely so that a simulated fix and the graph it was simulated
against can be resident at the same time and diffed against each other
(``docs/SCOPE.md`` D1, D6) — so a mutation cannot edit the snapshot, and
deep-copying six hundred nodes to change one attribute would make simulating a
dozen candidate fixes pointlessly expensive.

So this is an overlay: it exposes the same read surface the engine consumes and
answers from the base snapshot for everything the mutation did not touch. Only
the mutated node or edge is copied, and only the adjacency lists of the nodes an
edge removal actually affects are rebuilt. Everything else is the base object,
shared.

One structural rule is enforced here rather than left to the caller: removing a
node removes its incident edges too. A snapshot whose edge names an absent node
is rejected by ``GraphSnapshot.__init__``, and an overlay that quietly kept such
an edge would hand the search a source or target it cannot look up.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Iterator, Mapping

from core.model import Edge, GraphSnapshot, Node

#: ``mutation_kind`` values from ``fix_type``. Named here so a fix row carrying
#: an unknown kind fails when it is read rather than doing nothing visible.
MUTATION_KINDS = frozenset(
    {"remove_edge", "remove_node", "set_edge_attr", "set_node_attr"}
)

#: Node fields promoted out of ``attrs`` onto the dataclass. A fix writing one
#: of these names means the field, not a same-named entry in the attribute bag —
#: otherwise ``set_node_attr is_crown_jewel`` would add a shadow attribute
#: nothing reads and the mutation would appear to have been applied.
_NODE_FIELDS = frozenset(
    {"name", "display_name", "is_crown_jewel", "criticality", "classification"}
)

_EDGE_FIELDS = frozenset({"edge_type"})


class MutationError(ValueError):
    """A mutation that cannot be applied to this snapshot."""


@dataclass(frozen=True, slots=True)
class Mutation:
    """One graph change, as described by a ``fix_type`` row and a target.

    ``attr``/``value`` are used by the attribute kinds only. ``value`` is the
    already-decoded JSON from ``fix_type.mutation_value``, so ``'false'`` in the
    column arrives here as ``False``.
    """

    kind: str
    target_kind: str
    target_id: str
    attr: str | None = None
    value: Any = None

    def __post_init__(self) -> None:
        if self.kind not in MUTATION_KINDS:
            raise MutationError(
                f"unknown mutation kind {self.kind!r}; "
                f"fix_type.mutation_kind is one of {sorted(MUTATION_KINDS)}"
            )
        if self.target_kind not in ("edge", "node"):
            raise MutationError(
                f"target_kind must be 'edge' or 'node', got {self.target_kind!r}"
            )
        expected = "edge" if self.kind in ("remove_edge", "set_edge_attr") else "node"
        if self.target_kind != expected:
            raise MutationError(
                f"mutation {self.kind} acts on a {expected}, but its target is a "
                f"{self.target_kind}"
            )
        if self.kind.startswith("set_") and not self.attr:
            raise MutationError(
                f"mutation {self.kind} names no attribute to write; "
                "fix_type.mutation_target_attr is empty for this fix"
            )

    @property
    def description(self) -> str:
        if self.kind == "remove_edge":
            return f"remove edge {self.target_id}"
        if self.kind == "remove_node":
            return f"remove node {self.target_id}"
        return f"set {self.target_kind} {self.target_id}.{self.attr} = {self.value!r}"


class MutatedSnapshot:
    """A snapshot as it would be after one mutation, sharing the original.

    Implements the read surface ``engine.search.Discovery`` uses. It is not a
    subclass of ``GraphSnapshot``: the base class materialises adjacency in its
    constructor, and inheriting would mean either rebuilding all of it or
    leaving inherited methods reading stale private state. Composition keeps the
    copy-on-write property visible in the code rather than implied by it.
    """

    __slots__ = (
        "base",
        "mutation",
        "_removed_edges",
        "_removed_nodes",
        "_node_overrides",
        "_edge_overrides",
        "_out_cache",
        "_in_cache",
        "_crown_jewels",
    )

    def __init__(self, base: GraphSnapshot, mutation: Mutation) -> None:
        self.base = base
        self.mutation = mutation
        self._removed_edges: frozenset[str] = frozenset()
        self._removed_nodes: frozenset[str] = frozenset()
        self._node_overrides: dict[str, Node] = {}
        self._edge_overrides: dict[str, Edge] = {}
        self._out_cache: dict[str, list[Edge]] = {}
        self._in_cache: dict[str, list[Edge]] = {}

        if mutation.kind == "remove_edge":
            self._remove_edge(mutation.target_id)
        elif mutation.kind == "remove_node":
            self._remove_node(mutation.target_id)
        elif mutation.kind == "set_node_attr":
            self._set_node_attr(mutation.target_id, str(mutation.attr), mutation.value)
        else:
            self._set_edge_attr(mutation.target_id, str(mutation.attr), mutation.value)

        jewels = set(base.crown_jewels) - self._removed_nodes
        for node_id, node in self._node_overrides.items():
            if node.is_crown_jewel:
                jewels.add(node_id)
            else:
                jewels.discard(node_id)
        self._crown_jewels: frozenset[str] = frozenset(jewels)

    # ── Building the overlay ────────────────────────────────────────────────

    def _base_edge(self, edge_id: str) -> Edge:
        try:
            return self.base.edge(edge_id)
        except KeyError:
            raise MutationError(
                f"edge {edge_id} is absent from graph version {self.base.graph_version}"
            ) from None

    def _remove_edge(self, edge_id: str) -> None:
        edge = self._base_edge(edge_id)
        self._removed_edges = self._removed_edges | {edge_id}
        self._out_cache.pop(edge.src_id, None)
        self._in_cache.pop(edge.dst_id, None)

    def _remove_node(self, node_id: str) -> None:
        if self.base.get_node(node_id) is None:
            raise MutationError(
                f"node {node_id} is absent from graph version {self.base.graph_version}"
            )
        incident = [e.edge_id for e in self.base.out_edges(node_id)]
        incident += [e.edge_id for e in self.base.in_edges(node_id)]
        self._removed_nodes = self._removed_nodes | {node_id}
        self._removed_edges = self._removed_edges | frozenset(incident)
        # Every neighbour's adjacency changed, so their cached lists are stale.
        self._out_cache.clear()
        self._in_cache.clear()

    def _set_node_attr(self, node_id: str, attr: str, value: Any) -> None:
        node = self.base.get_node(node_id)
        if node is None:
            raise MutationError(
                f"node {node_id} is absent from graph version {self.base.graph_version}"
            )
        if attr in _NODE_FIELDS:
            self._node_overrides[node_id] = replace(node, **{attr: value})
            return
        self._node_overrides[node_id] = replace(
            node, attrs={**node.attrs, attr: value}
        )

    def _set_edge_attr(self, edge_id: str, attr: str, value: Any) -> None:
        edge = self._base_edge(edge_id)
        if attr in _EDGE_FIELDS:
            raise MutationError(
                f"{attr} is edge structure, not an attribute; changing it would "
                "make the edge a different fact rather than a modified one"
            )
        self._edge_overrides[edge_id] = replace(
            edge, attrs={**edge.attrs, attr: value}
        )
        self._out_cache.pop(edge.src_id, None)
        self._in_cache.pop(edge.dst_id, None)

    # ── Read surface ────────────────────────────────────────────────────────

    @property
    def graph_version(self) -> int:
        return self.base.graph_version

    def node(self, node_id: str) -> Node:
        node = self.get_node(node_id)
        if node is None:
            raise KeyError(node_id)
        return node

    def get_node(self, node_id: str) -> Node | None:
        if node_id in self._removed_nodes:
            return None
        override = self._node_overrides.get(node_id)
        return override if override is not None else self.base.get_node(node_id)

    def edge(self, edge_id: str) -> Edge:
        if edge_id in self._removed_edges:
            raise KeyError(edge_id)
        override = self._edge_overrides.get(edge_id)
        return override if override is not None else self.base.edge(edge_id)

    def out_edges(self, node_id: str) -> list[Edge]:
        if node_id in self._removed_nodes:
            return []
        cached = self._out_cache.get(node_id)
        if cached is None:
            cached = self._visible(self.base.out_edges(node_id))
            self._out_cache[node_id] = cached
        return cached

    def in_edges(self, node_id: str) -> list[Edge]:
        if node_id in self._removed_nodes:
            return []
        cached = self._in_cache.get(node_id)
        if cached is None:
            cached = self._visible(self.base.in_edges(node_id))
            self._in_cache[node_id] = cached
        return cached

    def nodes_of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.all_nodes if n.kind == kind]

    @property
    def crown_jewels(self) -> frozenset[str]:
        return self._crown_jewels

    @property
    def node_ids(self) -> Iterable[str]:
        return (n.node_id for n in self.all_nodes)

    @property
    def all_nodes(self) -> Iterator[Node]:
        for node in self.base.all_nodes:
            if node.node_id in self._removed_nodes:
                continue
            override = self._node_overrides.get(node.node_id)
            yield override if override is not None else node

    @property
    def all_edges(self) -> Iterator[Edge]:
        for edge in self.base.all_edges:
            if edge.edge_id in self._removed_edges:
                continue
            override = self._edge_overrides.get(edge.edge_id)
            yield override if override is not None else edge

    def __len__(self) -> int:
        return len(self.base) - len(self._removed_nodes)

    def __repr__(self) -> str:
        return (
            f"MutatedSnapshot(version={self.graph_version}, "
            f"{self.mutation.description}, nodes={len(self)})"
        )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _visible(self, edges: list[Edge]) -> list[Edge]:
        out: list[Edge] = []
        for edge in edges:
            if edge.edge_id in self._removed_edges:
                continue
            if edge.src_id in self._removed_nodes or edge.dst_id in self._removed_nodes:
                continue
            override = self._edge_overrides.get(edge.edge_id)
            out.append(override if override is not None else edge)
        return out

    # ── Serialisation ───────────────────────────────────────────────────────

    def node_rows(self) -> list[Mapping[str, Any]]:
        """The mutated graph as loader-shaped node rows.

        Used when a mutation stops being a counterfactual and becomes a child
        graph version that has to exist in both stores.
        """
        return [
            {
                "node_id": n.node_id,
                "kind": n.kind,
                "name": n.name,
                "display_name": n.display_name,
                "is_crown_jewel": n.is_crown_jewel,
                "criticality": n.criticality,
                "classification": n.classification,
                "attrs": dict(n.attrs),
            }
            for n in sorted(self.all_nodes, key=lambda n: n.node_id)
        ]

    def edge_rows(self) -> list[Mapping[str, Any]]:
        return [
            {
                "edge_id": e.edge_id,
                "src_id": e.src_id,
                "dst_id": e.dst_id,
                "edge_type": e.edge_type,
                "attrs": dict(e.attrs),
            }
            for e in sorted(self.all_edges, key=lambda e: e.edge_id)
        ]

    def rollback_payload(self) -> dict[str, Any]:
        """The exact prior state of whatever this mutation touched.

        ``applied_fix.rollback_payload`` is meant to let a rollback *restore*
        rather than reconstruct, so this records the whole prior row — for a node
        removal, its incident edges too, since restoring the node alone would
        leave it stranded.
        """
        mutation = self.mutation
        payload: dict[str, Any] = {
            "mutation": {
                "kind": mutation.kind,
                "target_kind": mutation.target_kind,
                "target_id": mutation.target_id,
                "attr": mutation.attr,
                "value": mutation.value,
            },
            "graph_version": self.base.graph_version,
        }
        if mutation.target_kind == "edge":
            edge = self.base.edge(mutation.target_id)
            payload["edge"] = {
                "edge_id": edge.edge_id,
                "src_id": edge.src_id,
                "dst_id": edge.dst_id,
                "edge_type": edge.edge_type,
                "attrs": dict(edge.attrs),
            }
            return payload

        node = self.base.node(mutation.target_id)
        payload["node"] = {
            "node_id": node.node_id,
            "kind": node.kind,
            "name": node.name,
            "display_name": node.display_name,
            "is_crown_jewel": node.is_crown_jewel,
            "criticality": node.criticality,
            "classification": node.classification,
            "attrs": dict(node.attrs),
        }
        if mutation.kind == "remove_node":
            payload["incident_edges"] = [
                {
                    "edge_id": e.edge_id,
                    "src_id": e.src_id,
                    "dst_id": e.dst_id,
                    "edge_type": e.edge_type,
                    "attrs": dict(e.attrs),
                }
                for e in sorted(
                    list(self.base.out_edges(mutation.target_id))
                    + list(self.base.in_edges(mutation.target_id)),
                    key=lambda e: e.edge_id,
                )
            ]
        return payload


def apply_mutation(base: GraphSnapshot, mutation: Mutation) -> MutatedSnapshot:
    """The counterfactual view of ``base`` under one mutation."""
    return MutatedSnapshot(base, mutation)
