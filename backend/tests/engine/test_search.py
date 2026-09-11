"""Precondition-aware discovery.

The search is the part of the product the whole argument rests on, so these
tests ask for more than "a path came back". They ask that the *right* chain came
back, that the chains that must not come back are refused with a reason naming
the attribute responsible, that every discovered hop still holds when re-checked
without the search's own bookkeeping, and that two runs over one graph are
identical down to the order of tied results.

The graphs are hand-built and small enough to hold in your head. The shared
world in ``conftest`` carries the planted chain and the decoys; the two graphs
defined here are deliberately narrow, because a pruning rule and a tie-break are
easier to prove on a graph that contains one of each than on one that contains
everything.
"""

from __future__ import annotations

import math

import pytest

from core.ids import canonical_json
from core.model import Capability
from engine.scoring import Scorer
from engine.search import Discovery, SearchLimits, is_minimal_proof, verify_path
from engine.snapshot import snapshot_from_rows

from conftest import (
    PRIMARY_EDGE_SEQUENCE,
    make_discovery,
    make_ruleset,
    make_scoring_config,
    make_snapshot,
)


def edge_sequence(path) -> tuple[str | None, ...]:
    return tuple(hop.edge_id for hop in path.hops)


def rejection_for(result, edge_id: str, rule_id: int):
    """The shallowest refusal of one rule against one edge.

    Keyed on the rule as well as the edge because several rules share an edge
    type — R7 and R8 both read ``EXPOSES_CREDENTIAL`` — so an edge carries one
    refusal per rule that declined it, and only one of them is the interesting
    one. Shallowest, because the same dead end is reached again from every longer
    prefix and the first refusal is the one that says why.
    """
    matches = sorted(
        (r for r in result.rejections if r.edge_id == edge_id and r.rule_id == rule_id),
        key=lambda r: r.hop_depth,
    )
    return matches[0] if matches else None


# ── Multi-hop discovery ──────────────────────────────────────────────────────


def test_the_planted_four_hop_chain_is_discovered(result):
    """Inherit a membership, use it, dump what the host exposes, authenticate.

    Four hops, four different rules, and the third one is R7 — the rule that
    separates this from a reachability tool, because it needs ``admin_on`` on the
    host rather than merely an edge out of it.
    """
    found = [p for p in result.paths if edge_sequence(p) == PRIMARY_EDGE_SEQUENCE]
    assert len(found) == 1
    path = found[0]
    assert path.source_node_id == "u-0001"
    assert path.target_node_id == "db-0001"
    assert [hop.rule_id for hop in path.hops] == [1, 2, 7, 9]
    assert path.target_is_crown_jewel is True


def test_path_probability_is_the_product_of_its_hops(result):
    for path in result.paths:
        expected = math.prod(hop.p_succ for hop in path.hops)
        assert path.p_success == pytest.approx(expected)
        assert 0.0 < path.p_success <= 1.0
        assert 0.0 <= path.risk_score <= 10.0


def test_a_rule_that_consumes_no_edge_contributes_a_hop_with_no_edge(result):
    """R10: nothing in the graph joins the attacker to the service account.

    The capability arrives from a property of the directory, so the hop records
    no edge — and the second path in this world only exists because of it.
    """
    kerberoast = [p for p in result.paths if p.hops[0].edge_id is None]
    assert len(kerberoast) == 1
    first = kerberoast[0].hops[0]
    assert first.rule_id == 10
    assert first.src_node_id == first.dst_node_id == "sa-0001"
    assert Capability("controls_principal", "sa-0001") in first.gained


def test_every_hop_holds_when_re_checked_without_the_search(result, snapshot, ruleset):
    """``docs/RULES.md`` invariant 5, checked the way it is worded.

    ``verify_path`` replays each chain from the threat model's grants using
    nothing but the rule rows, so a bug in the frontier, the queue or the pruning
    cannot hide inside its own bookkeeping.
    """
    for path in result.paths:
        problem = verify_path(
            path,
            snapshot=snapshot,
            ruleset=ruleset,
            initial_capabilities=result.initial_capabilities[path.path_id],
        )
        assert problem is None, problem


def test_no_hop_re_grants_something_already_held(result):
    """A hop names what it added, so the proof trace credits the right step."""
    for path in result.paths:
        held = set(result.initial_capabilities[path.path_id])
        for hop in path.hops:
            assert hop.gained, f"hop {hop.hop_no} granted nothing"
            assert not set(hop.gained) & held
            held |= set(hop.gained)


def test_every_hop_is_part_of_the_proof_of_the_last_one(result, ruleset):
    """No spare steps: a path is a proof, and a proof has none.

    Checked with ``is_minimal_proof`` itself rather than a hand-rolled
    re-derivation, for the same reason ``verify_path`` is a standalone function:
    the backward closure over capability preconditions is exactly what decides
    which hops are part of the proof, so re-deriving it ad hoc here would only
    duplicate ``search.py`` and risk drifting from it instead of checking it.
    """
    for path in result.paths:
        arrival = frozenset(
            c for c in path.hops[-1].gained if c.about == path.target_node_id
        )
        assert arrival
        assert is_minimal_proof(path.hops, arrival, ruleset)


# ── Refusals ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("decoy", "edge_id", "rule_id", "reason_code"),
    [
        ("D1 phishing-resistant MFA", "e-15", 9, "edge_attr:mfa_type:not_in"),
        ("D2 vault-stored credential", "e-06", 7, "node_attr:dst:storage:not_in"),
        ("D3 read-only permission", "e-12", 2, "edge_attr:permission_level:eq"),
        ("D4 disabled account", "e-08", 4, "node_attr:src:account_status:eq"),
        ("D10 rotated credential", "e-16", 7, "node_attr:dst:is_active:ne"),
        ("D13 distribution group", "e-02", 1, "node_attr:dst:type:eq"),
    ],
)
def test_a_decoy_is_refused_and_names_the_attribute(result, decoy, edge_id, rule_id, reason_code):
    assert all(edge_id not in edge_sequence(p) for p in result.paths), decoy
    refusal = rejection_for(result, edge_id, rule_id)
    assert refusal is not None, decoy
    assert refusal.reason_code == reason_code
    assert refusal.reason_text


def test_the_state_decoy_is_refused_on_state_rather_than_on_an_attribute(result):
    """D8, the one no amount of graph inspection distinguishes.

    ``h-0002`` exposes a credential exactly as ``h-0001`` does, with the same
    location and the same storage. The only difference is that the group's
    permission on it is read-only, so the attacker arrives holding ``access_to``
    and not ``admin_on`` — and the refusal says so by naming what *is* held.
    """
    refusal = rejection_for(result, "e-13", 7)
    assert refusal is not None
    assert refusal.reason_code == "missing_capability:admin_on"
    assert refusal.observed_value == "access_to"
    assert all("e-13" not in edge_sequence(p) for p in result.paths)


def test_a_twin_differing_in_one_attribute_is_accepted(result):
    """The decoys above are only evidence if their twins get through.

    ``e-10`` carries SMS where ``e-15`` carries FIDO2, and it is the same rule
    against the same kind of target. A tool that refused anything with an
    ``mfa_required`` flag would pass every D1 case and learn nothing.
    """
    assert any("e-10" in edge_sequence(p) for p in result.paths)


def test_an_identical_refusal_is_recorded_once_per_depth(result):
    """The same dead end is reached from many prefixes; the table records one."""
    signatures = [r.signature for r in result.rejections]
    assert len(signatures) == len(set(signatures))


# ── Dominance ────────────────────────────────────────────────────────────────

#: One group with two permissions on one host: administrative over ``e-02``,
#: read-only over ``e-03``. Both are affordable from the same state at the same
#: cost, and the first grants a strict superset of the second — which is the
#: shape ``docs/RULES.md`` §1.3 describes, isolated so nothing else can account
#: for the branch disappearing.
FORK_NODES = (
    {"node_id": "u-1", "kind": "User", "name": "avery", "attrs": {"account_status": "active"}},
    {"node_id": "g-1", "kind": "Group", "name": "ops", "attrs": {"type": "security"}},
    {"node_id": "h-1", "kind": "Host", "name": "app-01", "attrs": {"patch_level": "current"}},
    {
        "node_id": "cred-1",
        "kind": "Credential",
        "name": "svc-secret",
        "attrs": {"storage": "config_file", "is_active": True},
    },
    {
        "node_id": "db-1",
        "kind": "Database",
        "name": "ledger",
        "is_crown_jewel": True,
        "criticality": "critical",
        "classification": "restricted",
        "attrs": {"status": "active"},
    },
)

FORK_EDGES = (
    {"edge_id": "e-01", "src_id": "u-1", "dst_id": "g-1", "edge_type": "MEMBER_OF", "attrs": {}},
    {
        "edge_id": "e-02",
        "src_id": "g-1",
        "dst_id": "h-1",
        "edge_type": "HAS_PERMISSION",
        "attrs": {"permission_level": "admin"},
    },
    {
        "edge_id": "e-03",
        "src_id": "g-1",
        "dst_id": "h-1",
        "edge_type": "HAS_PERMISSION",
        "attrs": {"permission_level": "read_write"},
    },
    {
        "edge_id": "e-04",
        "src_id": "h-1",
        "dst_id": "cred-1",
        "edge_type": "EXPOSES_CREDENTIAL",
        "attrs": {"location": "config_file"},
    },
    {
        "edge_id": "e-05",
        "src_id": "cred-1",
        "dst_id": "db-1",
        "edge_type": "AUTHENTICATES_TO",
        "attrs": {"scope": "admin"},
    },
)

#: Two memberships, two identical administrative permissions, one crown jewel.
#: Every number about the two chains is the same, so their order is decided by
#: the tie-break and by nothing else.
TIE_NODES = (
    {"node_id": "u-1", "kind": "User", "name": "avery", "attrs": {"account_status": "active"}},
    {"node_id": "g-1", "kind": "Group", "name": "ops-a", "attrs": {"type": "security"}},
    {"node_id": "g-2", "kind": "Group", "name": "ops-b", "attrs": {"type": "security"}},
    {
        "node_id": "db-1",
        "kind": "Database",
        "name": "ledger",
        "is_crown_jewel": True,
        "criticality": "critical",
        "classification": "restricted",
        "attrs": {"status": "active"},
    },
)

TIE_EDGES = (
    {"edge_id": "e-01", "src_id": "u-1", "dst_id": "g-1", "edge_type": "MEMBER_OF", "attrs": {}},
    {"edge_id": "e-02", "src_id": "u-1", "dst_id": "g-2", "edge_type": "MEMBER_OF", "attrs": {}},
    {
        "edge_id": "e-03",
        "src_id": "g-1",
        "dst_id": "db-1",
        "edge_type": "HAS_PERMISSION",
        "attrs": {"permission_level": "admin"},
    },
    {
        "edge_id": "e-04",
        "src_id": "g-2",
        "dst_id": "db-1",
        "edge_type": "HAS_PERMISSION",
        "attrs": {"permission_level": "admin"},
    },
)


def discovery_over(nodes, edges) -> Discovery:
    return Discovery(
        snapshot_from_rows(1, [dict(n) for n in nodes], [dict(e) for e in edges]),
        make_ruleset(),
        Scorer(make_scoring_config()),
        SearchLimits(max_hops=6, top_k=4),
    )


def without_dominance(discovery: Discovery) -> Discovery:
    discovery._dominated = lambda history, state, cost: False
    return discovery


def test_dominance_cuts_the_redundant_branch_of_a_fork():
    """The read-only arm can do nothing the administrative arm cannot.

    Both reach ``h-1`` at the same cost, and the administrative one holds
    everything the read-only one holds and ``admin_on`` besides. Expanding the
    poorer state only re-derives what is already known — and here it re-derives a
    refusal, since the credential dump it would try needs the capability it lacks.
    """
    pruned = discovery_over(FORK_NODES, FORK_EDGES).run("external_phish")
    unpruned = without_dominance(discovery_over(FORK_NODES, FORK_EDGES)).run("external_phish")

    assert pruned.expansions < unpruned.expansions
    assert [p.path_id for p in pruned.paths] == [p.path_id for p in unpruned.paths]
    assert edge_sequence(pruned.paths[0]) == ("e-01", "e-02", "e-04", "e-05")
    # The branch that disappeared is exactly the one that could only fail.
    assert rejection_for(unpruned, "e-04", 7) is not None
    assert rejection_for(pruned, "e-04", 7) is None


def test_dominance_never_changes_which_paths_are_found(snapshot, ruleset, scoring_config):
    """Pruning is a performance claim, so it has to be a no-op on the answer."""
    pruned = make_discovery(snapshot, ruleset=ruleset, config=scoring_config)
    unpruned = without_dominance(
        make_discovery(snapshot, ruleset=ruleset, config=scoring_config)
    )
    with_pruning = pruned.run("external_phish")
    without = unpruned.run("external_phish")

    assert with_pruning.expansions < without.expansions
    assert [p.path_id for p in with_pruning.paths] == [p.path_id for p in without.paths]


# ── Determinism ──────────────────────────────────────────────────────────────


def serialise(result) -> str:
    """Everything a stored run would carry, canonically.

    Compared as one string rather than field by field, because invariant 10 is
    about the whole output including the order of things that tie, and a
    field-by-field comparison is exactly the check that lets ordering drift
    through unnoticed.
    """
    return canonical_json(
        {
            "entry_nodes": list(result.entry_nodes),
            "targets": list(result.targets),
            "expansions": result.expansions,
            "paths": [
                {
                    "path_id": p.path_id,
                    "source": p.source_node_id,
                    "target": p.target_node_id,
                    "p_success": p.p_success,
                    "neg_log_success": p.neg_log_success,
                    "p_undetected": p.p_undetected,
                    "risk_score": p.risk_score,
                    "risk_tier": p.risk_tier_code,
                    "bottleneck_hop": p.bottleneck_hop,
                    "hops": [
                        {
                            "hop_no": h.hop_no,
                            "edge_id": h.edge_id,
                            "rule_id": h.rule_id,
                            "p_succ": h.p_succ,
                            "detectability": h.detectability,
                            "gained": [str(c) for c in h.gained],
                            "factors": [
                                [f.seq, f.factor_code, f.beta, f.p_after] for f in h.factors
                            ],
                        }
                        for h in p.hops
                    ],
                    "initial": [str(c) for c in result.initial_capabilities[p.path_id]],
                }
                for p in result.paths
            ],
            "rejections": [
                [r.signature, r.rule_id, r.reason_code, r.observed_value, r.hop_depth]
                for r in result.rejections
            ],
        }
    )


def test_two_runs_over_one_graph_are_byte_identical():
    """``docs/RULES.md`` invariant 10, taken literally."""
    first = serialise(make_discovery().run("external_phish"))
    second = serialise(make_discovery().run("external_phish"))
    assert first == second


def test_one_engine_run_twice_is_byte_identical():
    """Per-run state is reset, so a second run is not a continuation of the first."""
    engine = make_discovery()
    assert serialise(engine.run("external_phish")) == serialise(engine.run("external_phish"))


def test_tied_paths_are_ordered_by_their_content_hash():
    """Two identical chains to one target, so nothing but the tie-break decides.

    The break is a content hash of the path itself rather than insertion order,
    which is what makes the ranking survive a regeneration and a demo reset.
    """
    result = discovery_over(TIE_NODES, TIE_EDGES).run("external_phish")
    assert len(result.paths) == 2
    first, second = result.paths
    assert first.risk_score == second.risk_score
    assert first.neg_log_success == second.neg_log_success
    assert first.path_id < second.path_id


def test_a_rebuilt_snapshot_of_the_same_graph_ranks_identically():
    """Ordering must come from the graph, not from the order rows arrived in."""
    forward = make_discovery(make_snapshot()).run("external_phish")
    rebuilt = make_discovery(make_snapshot()).run("external_phish")
    assert [p.path_id for p in forward.paths] == [p.path_id for p in rebuilt.paths]


# ── Metamorphic invariants ───────────────────────────────────────────────────


def test_removing_an_edge_never_adds_a_path():
    """Invariant 1, over every edge the planted chain uses."""
    baseline = make_discovery().run("external_phish")
    for edge_id in PRIMARY_EDGE_SEQUENCE:
        reduced = make_discovery(make_snapshot(drop_edges=[edge_id])).run("external_phish")
        assert len(reduced.paths) <= len(baseline.paths), edge_id
        assert all(edge_id not in edge_sequence(p) for p in reduced.paths)


def test_removing_an_edge_never_raises_a_surviving_path_s_probability():
    """Invariant 2."""
    baseline = {p.path_id: p.p_success for p in make_discovery().run("external_phish").paths}
    reduced = make_discovery(make_snapshot(drop_edges=["e-05"])).run("external_phish")
    for path in reduced.paths:
        if path.path_id in baseline:
            assert path.p_success <= baseline[path.path_id] + 1e-12


def test_hardening_an_attribute_never_adds_a_path():
    """Invariant 3: a phishing-resistant factor can only take paths away."""
    baseline = make_discovery().run("external_phish")
    hardened = make_discovery(
        make_snapshot(edge_attrs={"e-10": {"mfa_type": "fido2"}})
    ).run("external_phish")
    assert len(hardened.paths) < len(baseline.paths)
    assert all("e-10" not in edge_sequence(p) for p in hardened.paths)


def test_vaulting_a_credential_removes_the_chain_that_dumped_it():
    """The other half of invariant 3, on the rule the product exists to show."""
    hardened = make_discovery(
        make_snapshot(node_attrs={"cred-0001": {"storage": "vault"}})
    ).run("external_phish")
    assert all(edge_sequence(p) != PRIMARY_EDGE_SEQUENCE for p in hardened.paths)


# ── Entry points and limits ──────────────────────────────────────────────────


def test_the_entry_grant_is_enumerated_one_node_at_a_time(ruleset, snapshot, scoring_config):
    """``external_phish`` phishes one user, not every user simultaneously."""
    engine = make_discovery(snapshot, ruleset=ruleset, config=scoring_config)
    states = engine.entry_states(ruleset.threat_model("external_phish"))
    assert [s.node_id for s in states] == ["u-0001", "u-0002"]
    for state in states:
        controlled = {c.about for c in state.capabilities if c.code == "controls_principal"}
        assert controlled == {state.node_id}
        assert state.holds("authenticated")


def test_a_later_kind_grant_is_ambient_rather_than_enumerated(ruleset, snapshot, scoring_config):
    """``insider_standard`` reaches internal assets, but is still one person."""
    engine = make_discovery(snapshot, ruleset=ruleset, config=scoring_config)
    states = engine.entry_states(ruleset.threat_model("insider_standard"))
    reach = {c.about for c in states[0].capabilities if c.code == "network_reach"}
    assert reach == {"h-0001", "h-0002"}


def test_network_reach_alone_does_not_count_as_reaching_a_target(ruleset, snapshot, scoring_config):
    """R15: adjacency is reachability, not access, and never completes a path."""
    engine = make_discovery(snapshot, ruleset=ruleset, config=scoring_config)
    assert "network_reach" not in engine.goal_codes


def test_top_k_caps_how_many_paths_one_target_keeps(snapshot, ruleset, scoring_config):
    engine = Discovery(
        snapshot, ruleset, Scorer(scoring_config), SearchLimits(max_hops=6, top_k=1)
    )
    result = engine.run("external_phish")
    assert len(result.paths) == 1


def test_a_hop_cap_below_the_chain_length_finds_nothing(snapshot, ruleset, scoring_config):
    engine = Discovery(
        snapshot, ruleset, Scorer(scoring_config), SearchLimits(max_hops=2, top_k=4)
    )
    assert engine.run("external_phish").paths == ()


def test_an_unknown_threat_model_names_the_ones_that_exist(discovery):
    with pytest.raises(KeyError, match="external_phish"):
        discovery.run("nation_state")
