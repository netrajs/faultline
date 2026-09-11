"""The core reproducibility promise: docs/SCOPE.md D10.

Same seed, same scenario count, same sizes -> byte-identical graph, including
tie ordering -- checked here via ``graph_hash``, which sorts nodes and edges
canonically before hashing, so insertion-order accidents cannot hide behind a
lucky dict ordering.
"""

from __future__ import annotations

from generator.graph import BackgroundSizes
from generator.run import generate

_SMALL_SIZES = BackgroundSizes(
    users=24,
    groups=8,
    service_accounts=8,
    hosts=16,
    databases=5,
    cloud_resources=6,
    applications=5,
    group_nesting_depth=2,
)


def test_same_seed_produces_identical_graph_hash():
    first = generate(42, scenario_count=8, sizes=_SMALL_SIZES)
    second = generate(42, scenario_count=8, sizes=_SMALL_SIZES)

    assert first.graph_hash == second.graph_hash
    assert first.node_count() == second.node_count()
    assert first.edge_count() == second.edge_count()
    assert first.manifest.facts_hash == second.manifest.facts_hash


def test_same_seed_produces_identical_node_and_edge_ids():
    first = generate(7, scenario_count=4, sizes=_SMALL_SIZES)
    second = generate(7, scenario_count=4, sizes=_SMALL_SIZES)

    assert set(first.nodes.keys()) == set(second.nodes.keys())
    assert set(first.edges.keys()) == set(second.edges.keys())
    for node_id, node in first.nodes.items():
        assert second.nodes[node_id].attrs == node.attrs


def test_different_seed_produces_different_graph_hash():
    a = generate(1, scenario_count=4, sizes=_SMALL_SIZES)
    b = generate(2, scenario_count=4, sizes=_SMALL_SIZES)

    assert a.graph_hash != b.graph_hash


def test_scenario_count_controls_planted_opportunity_count():
    generated = generate(3, scenario_count=11, sizes=_SMALL_SIZES)
    assert len(generated.scenarios) == 11


def test_all_fourteen_decoy_pairs_are_planted_every_run():
    generated = generate(9, scenario_count=0, sizes=_SMALL_SIZES)
    codes = {d.decoy_code for d in generated.decoys}
    assert len(codes) == 14
    for code in codes:
        roles = {d.role for d in generated.decoys if d.decoy_code == code}
        assert roles == {"decoy", "twin"}
