"""Tests for applicability, the priority formula, and the dependency analysis.

The claim under test throughout is that nothing here is asserted: a fix is
offered because the graph says it would change something, its cost comes from
the catalogue, and every collateral row traces to an edge that exists.
"""

from __future__ import annotations

from remediation.recommend import (
    COVERAGE_WEIGHT,
    RISK_WEIGHT,
    applicable_fixes,
    dependencies_for,
    estimate_for,
    priority_score,
    recommend,
)


# ── Priority ─────────────────────────────────────────────────────────────────


def _score(**overrides):
    args = {
        "coverage": 0.5,
        "risk_before": 10.0,
        "risk_after": 5.0,
        "effort_value": 0.0,
        "disruption_value": 0.0,
        "max_effort": 8.0,
        "max_disruption": 3.0,
    }
    args.update(overrides)
    return priority_score(**args)


def test_a_free_fix_scores_its_benefit_undiscounted():
    """The ``1 +`` in the denominator is what stops a zero-cost fix dividing by
    zero and scoring infinitely."""
    expected = 100.0 * (COVERAGE_WEIGHT * 0.5 + RISK_WEIGHT * 0.5)

    assert _score() == expected


def test_cost_only_ever_discounts_a_benefit():
    free = _score()
    costly = _score(effort_value=8.0, disruption_value=3.0)

    assert 0.0 < costly < free


def test_disruption_counts_double_against_effort():
    """An afternoon of somebody's time is recoverable; an outage is not."""
    effort_only = _score(effort_value=8.0, max_effort=8.0, disruption_value=0.0)
    disruption_only = _score(effort_value=0.0, disruption_value=3.0, max_disruption=3.0)

    assert disruption_only < effort_only


def test_cost_is_normalised_against_the_catalogue_not_an_absolute_scale():
    """Retuning what 'manual' costs in ``fix_type`` reorders the ranking without
    touching the formula, which is the reason those columns are data."""
    same_relative_cost = _score(effort_value=4.0, max_effort=8.0)
    doubled_catalogue = _score(effort_value=8.0, max_effort=16.0)

    assert same_relative_cost == doubled_catalogue


def test_a_fix_that_raises_risk_is_not_credited_for_it():
    raised = _score(risk_before=5.0, risk_after=9.0)
    unchanged = _score(risk_before=5.0, risk_after=5.0)

    assert raised == unchanged


def test_coverage_outweighs_the_risk_drop():
    """A fix can remove nine of thirteen paths and leave the highest-scoring one
    standing; the nine are worth more than the number that did not move."""
    assert COVERAGE_WEIGHT > RISK_WEIGHT
    assert COVERAGE_WEIGHT + RISK_WEIGHT == 1.0
    all_paths = _score(coverage=1.0, risk_before=10.0, risk_after=10.0)
    all_risk = _score(coverage=0.0, risk_before=10.0, risk_after=0.0)
    assert all_paths > all_risk


def test_an_empty_catalogue_does_not_divide_by_zero():
    assert _score(max_effort=0.0, max_disruption=0.0) > 0.0


# ── Estimates ────────────────────────────────────────────────────────────────


def test_the_estimate_is_what_is_left_if_exactly_the_covered_paths_go(paths):
    estimate = estimate_for(frozenset({"p1", "p2", "p3"}), paths)

    assert estimate.paths_eliminated == 3
    assert estimate.coverage == 0.75
    assert estimate.risk_before == 9.0
    # p4 survives at 6.0, and that is the same quantity analysis_run.max_risk_score
    # reports -- before and after are one measurement taken twice.
    assert estimate.risk_after == 6.0


def test_covering_everything_leaves_nothing(paths):
    estimate = estimate_for(frozenset({"p1", "p2", "p3", "p4"}), paths)

    assert estimate.risk_after == 0.0
    assert estimate.coverage == 1.0


def test_covering_nothing_leaves_the_worst_path_standing(paths):
    estimate = estimate_for(frozenset(), paths)

    assert estimate.risk_after == estimate.risk_before == 9.0
    assert estimate.coverage == 0.0


# ── Applicability ────────────────────────────────────────────────────────────


def test_a_fix_is_offered_only_where_it_would_change_something(snapshot, fix_types):
    """cred1 is already active and already on plaintext disk, so revoking it and
    vaulting it both change a value; a fix writing what is already there is not
    offered at all."""
    offered = {f.code for f in applicable_fixes(snapshot, "node", "cred1", fix_types)}

    assert "revoke_credential" in offered
    assert "vault_credential" in offered


def test_a_fix_writing_the_value_already_held_is_not_offered(snapshot, fix_types):
    """cred2 is already vaulted. Offering it would produce a simulation with an
    empty delta and an apply step that changed nothing, which reads as a broken
    engine rather than a fix that never applied."""
    offered = {f.code for f in applicable_fixes(snapshot, "node", "cred2", fix_types)}

    assert "vault_credential" not in offered
    assert "revoke_credential" in offered


def test_a_fix_is_not_offered_where_the_attribute_is_not_recorded(snapshot, fix_types):
    """A host records no account_status, so disabling it is not a change the
    graph can express."""
    offered = {f.code for f in applicable_fixes(snapshot, "node", "host1", fix_types)}

    assert "disable_account" not in offered
    assert "revoke_credential" not in offered


def test_removing_an_edge_is_scoped_to_the_relationship_it_is_about(snapshot, fix_types):
    membership = {f.code for f in applicable_fixes(snapshot, "edge", "e-member", fix_types)}
    exposure = {f.code for f in applicable_fixes(snapshot, "edge", "e-expose", fix_types)}

    assert membership == {"remove_membership"}
    assert "remove_exposure" in exposure
    assert "remove_membership" not in exposure


def test_edge_attribute_fixes_read_the_edge_they_are_offered_on(snapshot, fix_types):
    auth = {f.code for f in applicable_fixes(snapshot, "edge", "e-auth", fix_types)}
    grant = {f.code for f in applicable_fixes(snapshot, "edge", "e-grant", fix_types)}

    assert "enforce_mfa" in auth
    assert "least_privilege" not in auth
    assert "least_privilege" in grant


def test_deleting_the_asset_being_protected_is_not_a_remediation(snapshot, fix_types, make_fix_type):
    catalogue = {
        **fix_types,
        "remove_node": make_fix_type(
            "remove_node", mutation_kind="remove_node", mutation_target_attr=None
        ),
    }

    assert "remove_node" not in {f.code for f in applicable_fixes(snapshot, "node", "jewel", catalogue)}
    assert "remove_node" in {f.code for f in applicable_fixes(snapshot, "node", "host1", catalogue)}


def test_an_absent_target_offers_nothing(snapshot, fix_types):
    assert applicable_fixes(snapshot, "node", "ghost", fix_types) == []
    assert applicable_fixes(snapshot, "edge", "e-ghost", fix_types) == []


# ── Dependencies ─────────────────────────────────────────────────────────────


def test_a_shared_credential_is_flagged_as_needing_coordination(snapshot, fix_types):
    rows = dependencies_for(snapshot, fix_types["revoke_credential"], "node", "cred1")
    kinds = {(r.kind, r.severity) for r in rows}

    assert ("shared_credential", "blocking") in kinds
    assert any("2 identities hold" in r.description for r in rows)


def test_a_holder_with_no_other_credential_blocks_a_revocation(snapshot, fix_types):
    """Ana holds only this one, so revoking it leaves her unable to authenticate
    at all; Ben holds another and only needs to pick up the replacement."""
    rows = dependencies_for(snapshot, fix_types["revoke_credential"], "node", "cred1")
    by_node = {r.affected_node_id: r for r in rows if r.affected_node_id in ("u1", "u2")}

    assert by_node["u1"].severity == "blocking"
    assert by_node["u2"].kind == "shared_credential"


def test_an_exposure_left_in_place_is_named(snapshot, fix_types):
    rows = dependencies_for(snapshot, fix_types["revoke_credential"], "node", "cred1")

    assert any(r.affected_node_id == "host1" and "still" in r.description for r in rows)


def test_what_a_service_loses_is_named_by_the_edge_that_grants_it(snapshot, fix_types):
    rows = dependencies_for(snapshot, fix_types["revoke_credential"], "node", "cred1")

    assert any(r.kind == "downstream_service" and r.affected_node_id == "jewel" for r in rows)


def test_removing_a_membership_expands_to_what_the_group_conferred(snapshot, fix_types):
    """The membership itself grants nothing. What is actually lost is the access
    the group confers, which is an edge away and would otherwise be invisible."""
    rows = dependencies_for(snapshot, fix_types["remove_membership"], "edge", "e-member")

    assert any(r.affected_node_id == "g1" for r in rows)
    conferred = [r for r in rows if r.affected_node_id == "jewel"]
    assert conferred and "admin" in conferred[0].description


def test_requiring_mfa_on_a_non_interactive_identity_is_blocking(fix_types, make_snapshot):
    """There is nobody present to produce a hardware factor, so requiring one
    locks the account out rather than hardening it."""
    graph = make_snapshot(
        [
            make_snapshot.node("sa1", "ServiceAccount", is_interactive=False),
            make_snapshot.node("cred1", "Credential", is_active=True),
            make_snapshot.node("asset1", "Database"),
        ],
        [
            make_snapshot.edge("e-has", "sa1", "cred1", "HAS_CREDENTIAL"),
            make_snapshot.edge("e-auth", "cred1", "asset1", "AUTHENTICATES_TO", mfa_type="none"),
        ],
    )
    rows = dependencies_for(graph, fix_types["enforce_mfa"], "edge", "e-auth")

    assert any(r.kind == "policy_conflict" and r.severity == "blocking" for r in rows)


def test_a_least_privilege_downgrade_names_both_levels(snapshot, fix_types):
    rows = dependencies_for(snapshot, fix_types["least_privilege"], "edge", "e-grant")

    assert len(rows) == 1
    assert "admin" in rows[0].description
    assert "read_only" in rows[0].description


def test_a_fix_with_nothing_derivable_gets_an_empty_list(snapshot, fix_types):
    """Honest, and more useful than a plausible warning nobody can check."""
    rows = dependencies_for(snapshot, fix_types["enforce_mfa"], "edge", "e-net")

    assert rows == ()


# ── Assembly ─────────────────────────────────────────────────────────────────


def test_recommendations_arrive_ranked_and_unmeasured(snapshot, paths, fix_types):
    rows, analysis = recommend(snapshot, paths, fix_types)

    assert rows
    assert analysis.total_paths == 4
    scores = [r.priority_score or 0.0 for r in rows]
    assert scores == sorted(scores, reverse=True)
    # Everything reaches the interface as an estimate; only a simulation flips it.
    assert all(r.is_measured is False for r in rows)
    assert all(r.total_paths == 4 for r in rows)


def test_a_recommendation_carries_the_chokepoints_own_coverage(snapshot, paths, fix_types):
    rows, _ = recommend(snapshot, paths, fix_types)
    mfa = next(r for r in rows if r.fix_type_code == "enforce_mfa")

    assert mfa.target_id == "e-auth"
    assert mfa.paths_eliminated == 3
    assert mfa.path_coverage == 0.75
    assert "chokepoint #1" in mfa.rationale
    assert "estimate from the coverage pass" in mfa.rationale


def test_a_title_names_both_ends_of_an_edge(snapshot, paths, fix_types):
    rows, _ = recommend(snapshot, paths, fix_types)
    mfa = next(r for r in rows if r.fix_type_code == "enforce_mfa")

    assert "shared-key" in mfa.title
    assert "prod-db" in mfa.title


def test_no_paths_means_no_recommendations(snapshot, fix_types):
    rows, analysis = recommend(snapshot, [], fix_types)

    assert rows == ()
    assert analysis.total_paths == 0
