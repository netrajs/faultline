"""Tests for the node-split minimum vertex cut.

The cases are hand-built so the right answer is known by inspection rather than
by running the thing under test. Two of them exist specifically to catch the
ways this is usually got wrong: a diamond, where the answer is 2 and a
centrality would say 1, and a graph where the only separating vertex is a source,
where the answer is "no cut" rather than "delete the attacker".
"""

from __future__ import annotations

from remediation.cuts import min_vertex_cut


def test_a_single_chain_is_cut_at_its_one_intermediate():
    cut = min_vertex_cut({"s": ["a"], "a": ["t"]}, sources=["s"], sinks=["t"])

    assert cut.vertices == ("a",)
    assert cut.size == 1


def test_two_disjoint_routes_need_two_removals():
    """Menger: the minimum cut equals the number of vertex-disjoint routes, so a
    diamond costs two. A betweenness ranking would name one node and claim the
    job was done."""
    cut = min_vertex_cut(
        {"s": ["a", "b"], "a": ["t"], "b": ["t"]}, sources=["s"], sinks=["t"]
    )

    assert cut.size == 2
    assert set(cut.vertices) == {"a", "b"}


def test_a_shared_waist_costs_one_however_wide_the_graph_is():
    cut = min_vertex_cut(
        {
            "s1": ["a", "b"],
            "s2": ["a", "b"],
            "a": ["w"],
            "b": ["w"],
            "w": ["x", "y"],
            "x": ["t"],
            "y": ["t"],
        },
        sources=["s1", "s2"],
        sinks=["t"],
    )

    assert cut.vertices == ("w",)
    assert cut.size == 1


def test_sources_and_sinks_are_never_cut():
    """Deleting the crown jewel is not a remediation, and neither is deleting
    the identity the attacker phished."""
    cut = min_vertex_cut({"s": ["t"]}, sources=["s"], sinks=["t"])

    assert cut.vertices == ()
    assert cut.size == 0


def test_a_protected_intermediate_is_routed_around_not_through():
    adjacency = {"s": ["a", "b"], "a": ["t"], "b": ["t"]}
    unprotected = min_vertex_cut(adjacency, sources=["s"], sinks=["t"])
    protected = min_vertex_cut(adjacency, sources=["s"], sinks=["t"], protected=["a"])

    assert unprotected.size == 2
    # With 'a' uncuttable there is no finite cut at all, so nothing is proposed.
    assert "a" not in protected.vertices


def test_an_unreachable_sink_needs_no_cut():
    cut = min_vertex_cut({"s": ["a"], "b": ["t"]}, sources=["s"], sinks=["t"])

    assert cut.size == 0
    assert cut.vertices == ()


def test_a_source_that_is_also_a_sink_cannot_be_separated_from_itself():
    cut = min_vertex_cut({"s": ["t"]}, sources=["s", "t"], sinks=["t"])

    assert cut.vertices == ()
    assert cut.size == 0


def test_the_reachable_set_names_the_source_side_of_the_cut():
    cut = min_vertex_cut({"s": ["a"], "a": ["b"], "b": ["t"]}, sources=["s"], sinks=["t"])

    assert cut.size == 1
    assert "s" in cut.reachable
    assert "t" not in cut.reachable


def test_a_vertex_absent_from_the_adjacency_is_still_placed():
    """Sources and sinks are added to the index even when nothing in
    ``adjacency`` mentions them, so a caller passing an isolated target gets a
    real answer rather than a KeyError."""
    cut = min_vertex_cut({"s": ["a"]}, sources=["s"], sinks=["isolated"])

    assert cut.size == 0
