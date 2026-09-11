"""Blast radius over hand-built worlds whose answers are known in advance.

The graph in ``conftest`` is the primary fixture, because its reachable set from
``u-0001`` can be worked out on paper: one security-group membership, the three
assets that group has permissions on, the two credentials the admin-controlled
host exposes, and the one crown jewel those credentials authenticate to. Five
planted refusals sit inside that set and must stay out of the result, and each
of them turns on exactly one attribute — so a radius that swallowed them would
be caught here rather than looking merely large.

Two additional worlds are built inline where the fixture cannot express the
case: one where the most probable route to a node is longer than the shortest
one, and one where the only thing on offer is a publicly exposed credential
that has nothing to do with the origin.
"""

from __future__ import annotations

import math

import pytest

from core.ids import path_id
from engine.blast_radius import (
    BlastLimits,
    BlastRadius,
    BlastRadiusError,
    summarise_by_depth,
)
from engine.scoring import Scorer
from engine.snapshot import snapshot_from_rows
from tests.engine.conftest import (
    PRIMARY_EDGE_SEQUENCE,
    make_ruleset,
    make_scoring_config,
    make_snapshot,
)

ORIGIN = "u-0001"

#: Everything control of ``u-0001`` leads to in the fixture world, worked out by
#: hand from ``docs/RULES.md``: the security group they belong to (R1), the
#: three assets that group holds permissions on (R2/R3), the two readable
#: credentials the admin-controlled host exposes (R7), and the crown jewel one
#: of those credentials authenticates to (R9).
EXPECTED_OUTBOUND = {
    "g-0001",
    "h-0001",
    "h-0002",
    "db-0002",
    "cred-0001",
    "cred-0006",
    "db-0001",
}

EXPECTED_DEPTHS = {
    "g-0001": 1,
    "h-0001": 2,
    "h-0002": 2,
    "db-0002": 2,
    "cred-0001": 3,
    "cred-0006": 3,
    "db-0001": 4,
}


def make_blast(snapshot=None, *, max_depth: int = 6, ruleset=None, config=None) -> BlastRadius:
    return BlastRadius(
        snapshot if snapshot is not None else make_snapshot(),
        ruleset or make_ruleset(),
        Scorer(config or make_scoring_config()),
        BlastLimits(max_depth=max_depth),
    )


@pytest.fixture
def blast() -> BlastRadius:
    return make_blast()


@pytest.fixture
def outbound(blast: BlastRadius):
    return blast.run(ORIGIN)


def reached_ids(result) -> set[str]:
    return {node.node_id for node in result.reached}


def by_id(result) -> dict[str, object]:
    return {node.node_id: node for node in result.reached}


# ── The reachable set ────────────────────────────────────────────────────────


def test_reaches_exactly_the_hand_derived_set(outbound):
    assert reached_ids(outbound) == EXPECTED_OUTBOUND
    assert outbound.nodes_reached == len(EXPECTED_OUTBOUND)


def test_origin_is_not_inside_its_own_radius(outbound):
    assert ORIGIN not in reached_ids(outbound)


def test_depths_match_the_hand_derived_hop_counts(outbound):
    assert {node.node_id: node.depth for node in outbound.reached} == EXPECTED_DEPTHS


def test_depth_equals_the_length_of_the_witness_that_was_kept(outbound):
    for node in outbound.reached:
        assert node.depth == len(node.witness_hops)


def test_crown_jewel_is_reached_and_reported(outbound):
    assert outbound.crown_jewels_reached == ("db-0001",)
    assert by_id(outbound)["db-0001"].is_crown_jewel is True


def test_distribution_group_is_refused(outbound):
    """R1 requires a security group; a mailing list confers no authorisation."""
    assert "g-0002" not in reached_ids(outbound)


def test_credential_on_a_host_the_attacker_only_has_access_to_is_refused(outbound):
    """Decoy D8. h-0002 is reached, but only with ``access_to``, and reading a
    secret out of a host needs ``admin_on`` — so what it exposes stays out."""
    assert "h-0002" in reached_ids(outbound)
    assert "cred-0005" not in reached_ids(outbound)


def test_vault_stored_and_rotated_credentials_are_refused(outbound):
    """Decoys D2 and D10: a config pointer is not a secret, and rotated material
    no longer authenticates."""
    assert "cred-0002" not in reached_ids(outbound)
    assert "cred-0007" not in reached_ids(outbound)


def test_phishing_resistant_mfa_removes_the_crown_jewel(blast):
    """Decoy D1. Drop the replayable route (e-07) and the only remaining edge
    into the crown jewel demands FIDO2, which credential replay cannot defeat."""
    hardened = make_blast(make_snapshot(drop_edges=["e-07"]))
    assert "db-0001" not in reached_ids(hardened.run(ORIGIN))
    assert "db-0001" in reached_ids(blast.run(ORIGIN))


def test_kerberoasting_is_not_attributed_to_a_single_node(outbound):
    """R10 needs ``authenticated``, which any directory identity confers. It is
    not something losing one node grants, so the SPN accounts stay out."""
    assert "sa-0001" not in reached_ids(outbound)
    assert "sa-0002" not in reached_ids(outbound)


# ── Probability ──────────────────────────────────────────────────────────────


def test_probability_is_the_product_along_the_witness(outbound):
    for node in outbound.reached:
        expected = math.prod(hop.p_succ for hop in node.witness_hops)
        assert node.p_reach == pytest.approx(expected, rel=1e-12)
        assert node.neg_log_reach == pytest.approx(-math.log(expected), rel=1e-9)


def test_single_hop_probability_is_the_technique_baseline(outbound):
    """Inheriting a group membership carries no modifiers, so R1's 0.99 stands."""
    assert by_id(outbound)["g-0001"].p_reach == pytest.approx(0.99)


def test_two_hop_probability_is_the_product_of_two_baselines(outbound):
    assert by_id(outbound)["h-0001"].p_reach == pytest.approx(0.99 * 0.97)


def test_crown_jewel_probability_matches_the_hand_computed_chain(outbound):
    """0.99 (membership) x 0.97 (group admin) x the credential dump x 0.93
    (replay). The dump's baseline 0.85 is lifted in log-odds by +1.2 for
    plaintext storage, +0.4 for age over ninety days and +0.5 for a discoverable
    exposure."""
    dump = 1.0 / (1.0 + math.exp(-(math.log(0.85 / 0.15) + 1.2 + 0.4 + 0.5)))
    assert by_id(outbound)["db-0001"].p_reach == pytest.approx(0.99 * 0.97 * dump * 0.93)


def test_crown_jewel_witness_is_the_known_primary_chain(outbound):
    hops = by_id(outbound)["db-0001"].witness_hops
    assert tuple(hop.edge_id for hop in hops) == PRIMARY_EDGE_SEQUENCE


def test_witness_path_id_is_the_content_hash_of_its_hops(outbound):
    for node in outbound.reached:
        assert node.witness_path_id == path_id(
            [hop.edge_id for hop in node.witness_hops],
            [hop.rule_id for hop in node.witness_hops],
        )


def test_every_probability_is_a_probability(outbound):
    for node in outbound.reached:
        assert 0.0 < node.p_reach <= 1.0
        assert 0.0 <= node.risk_score <= 10.0


# ── Best, not shortest ───────────────────────────────────────────────────────

#: A world where the shortest route to ``h-target`` is not the most probable
#: one. The trust edge reaches it in one hop at 0.80; going the long way — read
#: the credential the origin exposes, then authenticate with it — takes two hops
#: but multiplies out to roughly 0.88. A search that recorded the first arrival
#: would report 0.80 at depth 1.
_TWO_ROUTE_NODES = (
    {"node_id": "h-origin", "kind": "Host", "name": "jump-01", "attrs": {"patch_level": "current"}},
    {"node_id": "h-target", "kind": "Host", "name": "app-01", "criticality": "high", "attrs": {}},
    {
        "node_id": "cred-k",
        "kind": "Credential",
        "name": "app-secret",
        "attrs": {"storage": "config_file", "is_active": True},
    },
)

_TWO_ROUTE_EDGES = (
    {"edge_id": "t-1", "src_id": "h-origin", "dst_id": "h-target", "edge_type": "TRUSTS", "attrs": {}},
    {
        "edge_id": "t-2",
        "src_id": "h-origin",
        "dst_id": "cred-k",
        "edge_type": "EXPOSES_CREDENTIAL",
        "attrs": {"location": "config_file"},
    },
    {
        "edge_id": "t-3",
        "src_id": "cred-k",
        "dst_id": "h-target",
        "edge_type": "AUTHENTICATES_TO",
        "attrs": {"scope": "admin"},
    },
)


@pytest.fixture
def two_route_result():
    snapshot = snapshot_from_rows(1, _TWO_ROUTE_NODES, _TWO_ROUTE_EDGES)
    return make_blast(snapshot).run("h-origin")


def test_the_more_probable_route_wins_over_the_shorter_one(two_route_result):
    target = by_id(two_route_result)["h-target"]
    dump = 1.0 / (1.0 + math.exp(-(math.log(0.85 / 0.15) + 1.2)))
    assert target.p_reach == pytest.approx(dump * 0.93)
    assert target.p_reach > 0.80


def test_the_recorded_depth_describes_the_route_that_was_kept(two_route_result):
    target = by_id(two_route_result)["h-target"]
    assert target.depth == 2
    assert tuple(hop.edge_id for hop in target.witness_hops) == ("t-2", "t-3")


# ── What does not count as arrival ───────────────────────────────────────────


def test_network_adjacency_alone_is_not_arrival():
    """R15 grants reachability, not access. A node the attacker can only route
    packets to has not been reached, and counting it would report a segmentation
    fact as a compromise."""
    nodes = (
        {"node_id": "cr-a", "kind": "CloudResource", "name": "vpc-a", "attrs": {}},
        {"node_id": "cr-b", "kind": "CloudResource", "name": "vpc-b", "attrs": {}},
    )
    edges = (
        {
            "edge_id": "n-1",
            "src_id": "cr-a",
            "dst_id": "cr-b",
            "edge_type": "CONNECTED_TO",
            "attrs": {"connection_type": "vpc_peering"},
        },
    )
    result = make_blast(snapshot_from_rows(1, nodes, edges)).run("cr-a")
    assert reached_ids(result) == set()


def test_a_publicly_exposed_credential_is_not_attributed_to_an_origin():
    """R8 fires from the empty state, so it belongs to every node's radius
    equally — which is to say to none of them. Attributing it to one origin
    would overstate that origin and tell the reader nothing."""
    nodes = (
        {"node_id": "u-x", "kind": "User", "name": "unrelated", "attrs": {"account_status": "active"}},
        {"node_id": "app-x", "kind": "Application", "name": "ci-runner", "attrs": {}},
        {
            "node_id": "cred-x",
            "kind": "Credential",
            "name": "leaked-token",
            "attrs": {"storage": "plaintext", "is_active": True},
        },
    )
    edges = (
        {
            "edge_id": "p-1",
            "src_id": "app-x",
            "dst_id": "cred-x",
            "edge_type": "EXPOSES_CREDENTIAL",
            "attrs": {"location": "public_repo"},
        },
    )
    result = make_blast(snapshot_from_rows(1, nodes, edges)).run("u-x")
    assert reached_ids(result) == set()


# ── The hop cap ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("cap", [1, 2, 3, 4])
def test_no_node_is_reported_beyond_the_hop_cap(cap):
    result = make_blast(max_depth=cap).run(ORIGIN)
    assert all(node.depth <= cap for node in result.reached)
    assert reached_ids(result) == {
        node_id for node_id, depth in EXPECTED_DEPTHS.items() if depth <= cap
    }


def test_raising_the_hop_cap_never_shrinks_the_radius():
    previous: set[str] = set()
    for cap in range(1, 7):
        current = reached_ids(make_blast(max_depth=cap).run(ORIGIN))
        assert previous <= current
        previous = current


def test_raising_the_hop_cap_never_lowers_a_probability():
    tight = by_id(make_blast(max_depth=3).run(ORIGIN))
    loose = by_id(make_blast(max_depth=6).run(ORIGIN))
    for node_id, node in tight.items():
        assert loose[node_id].p_reach >= node.p_reach - 1e-12


def test_removing_an_edge_never_grows_the_radius():
    """``docs/RULES.md`` invariant 7, in the direction this engine can check:
    less graph cannot mean more blast radius."""
    full = reached_ids(make_blast().run(ORIGIN))
    for edge_id in ("e-01", "e-03", "e-05", "e-07", "e-12"):
        pruned = reached_ids(make_blast(make_snapshot(drop_edges=[edge_id])).run(ORIGIN))
        assert pruned <= full


# ── Direction ────────────────────────────────────────────────────────────────


def test_inbound_finds_what_could_arrive_at_the_crown_jewel(blast):
    """Both credentials with an authentication edge into the ledger are upstream
    of it; nothing else is within one hop."""
    inbound = blast.run("db-0001", "inbound")
    assert reached_ids(inbound) == {"cred-0001", "cred-0003"}
    assert all(node.depth == 1 for node in inbound.reached)


def test_both_is_the_union_of_the_two_directions(blast):
    outbound = reached_ids(blast.run("h-0001", "outbound"))
    inbound = reached_ids(blast.run("h-0001", "inbound"))
    combined = reached_ids(blast.run("h-0001", "both"))
    assert combined == outbound | inbound
    assert outbound and inbound


def test_both_keeps_the_better_of_the_two_witnesses(blast):
    outbound = by_id(blast.run("h-0001", "outbound"))
    inbound = by_id(blast.run("h-0001", "inbound"))
    combined = by_id(blast.run("h-0001", "both"))
    for node_id, node in combined.items():
        candidates = [
            side[node_id].p_reach for side in (outbound, inbound) if node_id in side
        ]
        assert node.p_reach == pytest.approx(max(candidates))


# ── Severity ─────────────────────────────────────────────────────────────────


def test_severity_is_the_worst_reachable_outcome(outbound):
    """Severity reuses the 0-10 path score rather than inventing a scale: it is
    the risk score of the most damaging thing the compromise leads to."""
    worst = max(node.risk_score for node in outbound.reached)
    assert outbound.severity_score == pytest.approx(worst)
    assert outbound.severity_node_id == "db-0001"
    assert outbound.severity_tier_code == by_id(outbound)["db-0001"].risk_tier_code


def test_an_empty_radius_has_no_severity():
    nodes = ({"node_id": "u-lonely", "kind": "User", "name": "nobody", "attrs": {"account_status": "active"}},)
    result = make_blast(snapshot_from_rows(1, nodes, ())).run("u-lonely")
    assert result.nodes_reached == 0
    assert result.severity_score is None
    assert result.severity_tier_code is None


def test_crown_jewel_scores_above_a_plain_asset(outbound):
    lookup = by_id(outbound)
    assert lookup["db-0001"].risk_score > lookup["db-0002"].risk_score


# ── Reporting and contracts ──────────────────────────────────────────────────


def test_depth_summary_counts_every_reached_node(outbound):
    summary = summarise_by_depth(outbound.reached)
    assert summary == ((1, 1), (2, 3), (3, 2), (4, 1))
    assert sum(count for _, count in summary) == outbound.nodes_reached


def test_two_runs_of_one_graph_agree_exactly():
    first = make_blast().run(ORIGIN)
    second = make_blast().run(ORIGIN)
    assert [(n.node_id, n.depth, n.p_reach, n.witness_path_id) for n in first.reached] == [
        (n.node_id, n.depth, n.p_reach, n.witness_path_id) for n in second.reached
    ]


def test_results_are_ordered_by_depth_then_probability(outbound):
    keys = [(node.depth, -node.p_reach, node.node_id) for node in outbound.reached]
    assert keys == sorted(keys)


def test_an_unknown_origin_is_refused(blast):
    with pytest.raises(BlastRadiusError, match="absent from graph version"):
        blast.run("h-9999")


def test_an_unknown_direction_is_refused(blast):
    with pytest.raises(BlastRadiusError, match="unknown direction"):
        blast.run(ORIGIN, "sideways")


def test_a_hop_cap_below_one_is_refused():
    with pytest.raises(BlastRadiusError, match="at least one hop"):
        make_blast(max_depth=0)
