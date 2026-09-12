"""Tests for greedy set cover over path coverage and its stated optimality gap.

The number the interface shows next to each rank is an approximation bound, not
a result, and the arithmetic behind it is asserted here rather than trusted:
greedy reached ``g`` at rank ``k``, so no selection of size ``k`` could have
exceeded ``g / (1 - 1/e)``.
"""

from __future__ import annotations

import math

from remediation.chokepoints import (
    GREEDY_RATIO,
    PathCoverage,
    analyse,
    build_candidates,
    greedy_cover,
    path_adjacency,
)


def test_a_path_lists_its_edges_and_its_nodes_in_order(paths):
    first = paths[0]

    assert first.edge_ids == ("e-has1", "e-auth")
    assert first.node_ids == ("u1", "cred1", "jewel")


def test_endpoints_are_never_offered_as_cut_candidates(paths):
    """Removing the source is deleting the phished user; removing the target is
    deleting the asset being protected. Neither is a remediation."""
    first = paths[0]

    assert first.intermediate_node_ids == ("cred1",)
    assert "u1" not in first.intermediate_node_ids
    assert "jewel" not in first.intermediate_node_ids


def test_a_hop_with_no_edge_contributes_no_edge_candidate():
    """A non-traversal rule grants a capability without moving, so it consumes
    no edge and there is nothing there to cut."""
    path = PathCoverage("p", "a", "c", (("a", "b", None), ("b", "c", "e1")), 5.0)

    assert path.edge_ids == ("e1",)
    assert path.node_ids == ("a", "b", "c")


def test_candidates_cover_every_edge_and_intermediate_node(paths):
    candidates = {c.key: c.path_ids for c in build_candidates(paths)}

    assert candidates[("edge", "e-auth")] == frozenset({"p1", "p2", "p3"})
    assert candidates[("node", "cred1")] == frozenset({"p1", "p2", "p3"})
    assert candidates[("edge", "e-grant")] == frozenset({"p4"})
    assert ("node", "jewel") not in candidates


def test_greedy_takes_the_widest_cover_first(paths):
    ranked = greedy_cover(paths)

    assert ranked[0].target_id == "e-auth"
    assert ranked[0].marginal_paths == 3
    assert ranked[0].paths_covered == 3
    assert ranked[0].coverage_fraction == 0.75
    assert ranked[0].cumulative_fraction == 0.75


def test_marginal_gain_is_what_the_next_rank_is_chosen_by(paths):
    ranked = greedy_cover(paths)

    # cred1 also covers three paths, but all three are already covered, so it
    # cannot be second -- the only uncovered path is p4.
    assert ranked[1].marginal_paths == 1
    assert ranked[1].target_id in {"e-member", "e-grant", "g1"}
    assert ranked[1].cumulative_fraction == 1.0


def test_the_ranking_stops_once_everything_is_covered(paths):
    ranked = greedy_cover(paths)

    assert len(ranked) == 2
    assert ranked[-1].cumulative_fraction == 1.0


def test_the_optimality_bound_is_the_stated_guarantee_read_back(paths):
    ranked = greedy_cover(paths)

    for chokepoint in ranked:
        expected = min(1.0, chokepoint.cumulative_fraction / GREEDY_RATIO)
        assert chokepoint.optimality_bound == expected
    assert math.isclose(GREEDY_RATIO, 1.0 - 1.0 / math.e)


def test_a_bound_below_one_says_the_selection_might_be_leaving_something():
    """0.5 cumulative over a (1 - 1/e) guarantee is 0.79, not 1.0: a reader is
    told the best possible selection of this size might have reached 79%."""
    paths = [
        PathCoverage("p1", "s", "t", (("s", "m", "e1"), ("m", "t", "e2")), 5.0),
        PathCoverage("p2", "s", "t", (("s", "n", "e3"), ("n", "t", "e4")), 5.0),
    ]
    ranked = greedy_cover(paths, limit=1)

    assert ranked[0].cumulative_fraction == 0.5
    assert math.isclose(ranked[0].optimality_bound, 0.5 / GREEDY_RATIO, rel_tol=1e-9)
    assert ranked[0].optimality_bound < 1.0


def test_the_ranking_is_the_same_every_time(paths):
    """Ties are broken on values derived from the data, never on dict order, so
    two runs over the same paths rank identically including their ties."""
    first = greedy_cover(paths)
    second = greedy_cover(list(reversed(paths)))

    assert [(c.kind, c.target_id) for c in first] == [(c.kind, c.target_id) for c in second]


def test_an_edge_wins_a_tie_against_a_node():
    """Severing one relationship is a smaller change than deleting a whole
    principal, so where coverage is equal the edge is offered first."""
    paths = [PathCoverage("p1", "s", "t", (("s", "m", "e1"), ("m", "t", "e2")), 5.0)]
    ranked = greedy_cover(paths)

    assert ranked[0].kind == "edge"


def test_no_paths_means_no_ranking():
    assert greedy_cover([]) == ()


def test_the_limit_caps_the_ranking_not_the_candidate_pool(paths):
    ranked = greedy_cover(paths, limit=1)

    assert len(ranked) == 1
    assert ranked[0].cumulative_fraction == 0.75


def test_adjacency_is_induced_by_the_paths_not_the_whole_graph(paths):
    """A cut of the full graph would be ranked against routes the engine already
    refused as unexploitable."""
    adjacency = path_adjacency(paths)

    assert adjacency["cred1"] == ["jewel"]
    assert sorted(adjacency["u1"]) == ["cred1", "g1"]
    assert "host1" in adjacency
    assert "jewel" not in adjacency


def test_analyse_reports_the_exact_cut_beside_the_greedy_one(paths):
    analysis = analyse(paths)

    assert analysis.total_paths == 4
    assert analysis.chokepoints[0].target_id == "e-auth"
    # Two independent routes into the jewel (via cred1 and via g1), so the exact
    # minimum vertex cut is two nodes.
    assert analysis.min_cut.size == 2
    assert set(analysis.min_cut.vertices) == {"cred1", "g1"}
    # Coverage for targets greedy never ranked is still available, because the
    # recommendation pass needs it.
    assert ("node", "cred1") in analysis.candidates
