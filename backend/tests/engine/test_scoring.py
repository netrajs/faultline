"""The log-space scorer.

The arithmetic is checked against an independently written closed form rather
than against the scorer's own output, because a test that recomputes the score
the same way the scorer does only proves the code is deterministic.
"""

from __future__ import annotations

import math

import pytest

from core.model import Edge, Hop, Node
from engine.scoring import Scorer, ScoringError

from conftest import make_scoring_config


def logit(p: float) -> float:
    return math.log(p / (1.0 - p))


HOST = Node("h-1", "Host", "host-one", criticality="high", attrs={"patch_level": "behind-2+", "has_edr": True})
CREDENTIAL = Node(
    "cred-1",
    "Credential",
    "cred-one",
    attrs={"storage": "config_file", "is_active": True, "age_days": 200, "is_shared": True},
)
DATABASE = Node(
    "db-1", "Database", "ledger", is_crown_jewel=True, criticality="critical",
    classification="restricted", attrs={"status": "active"},
)
EXPOSURE = Edge("e-1", "h-1", "cred-1", "EXPOSES_CREDENTIAL", attrs={"location": "config_file", "discoverable": 0.8})


@pytest.fixture
def scorer() -> Scorer:
    return Scorer(make_scoring_config())


# ── One hop ──────────────────────────────────────────────────────────────────


def test_modifiers_are_additive_in_log_odds(scorer):
    """``logit(p') = logit(p_base) + Σβ``, computed independently here."""
    score = scorer.score_hop(
        technique_code="credential_in_files",
        src_node=HOST,
        dst_node=CREDENTIAL,
        edge=EXPOSURE,
    )
    # age_days 200 > 90, is_shared, config_file storage, discoverable 0.8 >= 0.7.
    expected_betas = 0.4 + 0.7 + 1.2 + 0.5
    expected = 1.0 / (1.0 + math.exp(-(logit(0.85) + expected_betas)))
    assert score.p_succ == pytest.approx(expected)
    assert score.neg_log_contribution == pytest.approx(-math.log(expected))


def test_every_contribution_gets_its_own_factor(scorer):
    """One baseline row plus one row per modifier that fired, in order.

    ``host_monitored`` is in the list because it carries no technique scope, and
    an empty scope means the modifier applies everywhere: endpoint monitoring
    raises the chance of being noticed whatever the technique was. It moves
    detectability rather than success, which is why it appears here but not in
    the log-odds sum above.
    """
    score = scorer.score_hop(
        technique_code="credential_in_files",
        src_node=HOST,
        dst_node=CREDENTIAL,
        edge=EXPOSURE,
    )
    kinds = [factor.factor_kind for factor in score.factors]
    codes = [factor.factor_code for factor in score.factors]
    assert kinds[0] == "baseline"
    assert codes == [
        "credential_in_files",
        "cred_age_stale",
        "cred_shared",
        "cred_plaintext",
        "host_monitored",
        "exposure_discoverable",
    ]
    assert [factor.seq for factor in score.factors] == [1, 2, 3, 4, 5, 6]
    assert score.factors[0].p_after == pytest.approx(0.85)


def test_factor_betas_sum_to_the_applied_shift(scorer):
    """Log-additivity is what makes the attribution exactly Shapley.

    Only the factors aimed at ``p_succ`` enter the sum. Detection is a separate
    accumulator, and folding its betas in here would be the double-counting the
    two-axis model exists to prevent.
    """
    score = scorer.score_hop(
        technique_code="credential_in_files",
        src_node=HOST,
        dst_node=CREDENTIAL,
        edge=EXPOSURE,
    )
    targets = {m.code: m.target for m in scorer.config.modifiers}
    betas = sum(
        f.beta
        for f in score.factors
        if f.beta is not None
        and f.factor_kind == "modifier"
        and targets[f.factor_code] == "p_succ"
    )
    assert logit(score.p_succ) == pytest.approx(logit(0.85) + betas)


def test_a_modifier_out_of_technique_scope_does_not_fire(scorer):
    """Credential age is meaningless to a group membership.

    ``host_monitored`` still fires: it declares no scope, so it is in scope
    everywhere, and it is the control that keeps this test from passing for the
    wrong reason — a scorer that dropped every modifier would satisfy the
    exclusion below without ever consulting a scope.
    """
    score = scorer.score_hop(
        technique_code="group_membership", src_node=HOST, dst_node=CREDENTIAL, edge=EXPOSURE
    )
    assert [f.factor_code for f in score.factors] == ["group_membership", "host_monitored"]
    assert score.p_succ == pytest.approx(0.99)


def test_detectability_is_a_separate_accumulator(scorer):
    """A detectability modifier must not move the success probability."""
    edge = Edge("e-2", "cred-1", "db-1", "AUTHENTICATES_TO", attrs={"mfa_type": "sms"})
    score = scorer.score_hop(
        technique_code="credential_replay", src_node=CREDENTIAL, dst_node=DATABASE, edge=edge
    )
    assert score.p_succ == pytest.approx(1.0 / (1.0 + math.exp(-(logit(0.93) - 0.8))))
    assert score.detectability == pytest.approx(1.0 / (1.0 + math.exp(-(logit(0.15) + 0.6))))


def test_probabilities_are_clamped_into_the_configured_interval():
    config = make_scoring_config(
        modifier_overrides={"cred_plaintext": {"beta": 40.0}, "cred_vaulted": {"beta": -40.0}}
    )
    scorer = Scorer(config)
    high = scorer.score_hop(
        technique_code="credential_in_files", src_node=HOST, dst_node=CREDENTIAL, edge=EXPOSURE
    )
    assert high.p_succ == pytest.approx(config.p_clamp_max)

    vaulted = Node("cred-2", "Credential", "vaulted", attrs={"storage": "vault"})
    low = scorer.score_hop(
        technique_code="credential_in_files", src_node=HOST, dst_node=vaulted, edge=EXPOSURE
    )
    assert low.p_succ == pytest.approx(config.p_clamp_min)
    assert math.isfinite(low.neg_log_contribution)


def test_a_hard_block_refuses_the_hop_rather_than_penalising_it():
    config = make_scoring_config(modifier_overrides={"mfa_weak_factor": {"is_hard_block": 1}})
    edge = Edge("e-2", "cred-1", "db-1", "AUTHENTICATES_TO", attrs={"mfa_type": "sms"})
    score = Scorer(config).score_hop(
        technique_code="credential_replay", src_node=CREDENTIAL, dst_node=DATABASE, edge=edge
    )
    assert score.blocked_by is not None
    assert score.blocked_by.code == "mfa_weak_factor"


def test_epss_replaces_the_baseline_for_a_vulnerability_target(scorer):
    """R12: the probability is derived from EPSS, not from a constant."""
    vulnerability = Node(
        "vuln-1", "Vulnerability", "CVE-2024-0001",
        attrs={"impact": "RCE", "attack_vector": "network", "epss": 0.42, "cvss": 9.8},
    )
    edge = Edge("e-3", "h-1", "vuln-1", "HAS_VULNERABILITY", attrs={})
    score = scorer.score_hop(
        technique_code="exploit_remote", src_node=HOST, dst_node=vulnerability, edge=edge
    )
    # 0.42 from EPSS, then +0.6 for the host being two cycles behind.
    assert score.factors[0].factor_code == "epss:exploit_remote"
    assert score.p_succ == pytest.approx(1.0 / (1.0 + math.exp(-(logit(0.42) + 0.6))))


def test_a_vulnerability_without_epss_falls_back_to_the_baseline(scorer):
    vulnerability = Node("vuln-2", "Vulnerability", "CVE-2024-0002", attrs={"impact": "RCE"})
    edge = Edge("e-4", "h-1", "vuln-2", "HAS_VULNERABILITY", attrs={})
    score = scorer.score_hop(
        technique_code="exploit_remote", src_node=HOST, dst_node=vulnerability, edge=edge
    )
    assert score.factors[0].factor_code == "exploit_remote"


def test_a_technique_with_no_baseline_is_an_error(scorer):
    with pytest.raises(ScoringError, match="no baseline"):
        scorer.score_hop(
            technique_code="telepathy", src_node=HOST, dst_node=DATABASE, edge=None
        )


# ── One path ─────────────────────────────────────────────────────────────────


def hop(hop_no: int, p_succ: float, detectability: float) -> Hop:
    return Hop(
        hop_no=hop_no,
        src_node_id="a",
        dst_node_id="b",
        edge_id=f"e-{hop_no}",
        technique_code="group_membership",
        rule_id=1,
        p_succ=p_succ,
        detectability=detectability,
        neg_log_contribution=-math.log(p_succ),
        gained=(),
        factors=(),
    )


def test_path_probability_is_the_product_of_its_hops(scorer):
    hops = [hop(1, 0.99, 0.02), hop(2, 0.97, 0.05), hop(3, 0.85, 0.25)]
    score = scorer.score_path(hops, DATABASE)
    assert score.p_success == pytest.approx(0.99 * 0.97 * 0.85)
    assert score.neg_log_success == pytest.approx(-math.log(0.99 * 0.97 * 0.85))


def test_undetected_probability_accumulates_separately(scorer):
    hops = [hop(1, 0.99, 0.02), hop(2, 0.97, 0.05), hop(3, 0.85, 0.25)]
    score = scorer.score_path(hops, DATABASE)
    assert score.p_undetected == pytest.approx(0.98 * 0.95 * 0.75)
    assert score.p_undetected != pytest.approx(score.p_success)


def test_length_is_penalised_by_the_product_alone(scorer):
    """No hop-count decay term: appending a hop can only lower the product."""
    short = scorer.score_path([hop(1, 0.9, 0.1)], DATABASE)
    long = scorer.score_path([hop(1, 0.9, 0.1), hop(2, 0.995, 0.1)], DATABASE)
    assert long.p_success < short.p_success
    assert long.p_success == pytest.approx(short.p_success * 0.995)


def test_bottleneck_is_the_weakest_single_hop(scorer):
    hops = [hop(1, 0.99, 0.02), hop(2, 0.70, 0.30), hop(3, 0.85, 0.25)]
    score = scorer.score_path(hops, DATABASE)
    assert score.bottleneck_p == pytest.approx(0.70)
    assert score.bottleneck_hop == 2


def test_bottleneck_ties_resolve_to_the_earliest_hop(scorer):
    score = scorer.score_path([hop(1, 0.8, 0.1), hop(2, 0.8, 0.1)], DATABASE)
    assert score.bottleneck_hop == 1


def test_impact_is_the_strongest_dimension_that_applies(scorer):
    """Crown jewel 1.0 dominates criticality 0.85 and classification 0.90."""
    score = scorer.score_path([hop(1, 0.99, 0.02)], DATABASE)
    assert score.impact_score == pytest.approx(1.0)
    assert {f.factor_code for f in score.impact_factors} == {
        "crown_jewel:true",
        "criticality:critical",
        "classification:restricted",
    }


def test_a_non_crown_jewel_still_scores_its_own_criticality(scorer):
    warehouse = Node(
        "db-2", "Database", "warehouse", criticality="high", classification="internal", attrs={}
    )
    score = scorer.score_path([hop(1, 0.99, 0.02)], warehouse)
    assert score.impact_score == pytest.approx(0.65)


def test_impact_factors_are_recorded_as_impact_kind(scorer):
    score = scorer.score_path([hop(1, 0.99, 0.02)], DATABASE)
    assert all(f.factor_kind == "impact" for f in score.impact_factors)


def test_the_display_score_stays_inside_the_tier_range(scorer):
    score = scorer.score_path([hop(1, 0.99, 0.02)], DATABASE)
    assert 0.0 <= score.risk_score <= 10.0
    assert score.risk_tier.min_score <= score.risk_score <= score.risk_tier.max_score


def test_a_near_certain_path_to_a_crown_jewel_reaches_critical(scorer):
    """Every tier boundary has to be attainable by a constructible path."""
    score = scorer.score_path([hop(1, 0.995, 0.001)], DATABASE)
    assert score.risk_tier.code == "critical"


def test_a_hopeless_path_to_a_trivial_target_reaches_the_bottom_tier(scorer):
    public = Node("app-1", "Application", "status-page", criticality="low", classification="public", attrs={})
    hops = [hop(i, 0.001, 0.995) for i in range(1, 4)]
    score = scorer.score_path(hops, public)
    assert score.risk_score < 1.0
    assert score.risk_tier.code == "info"


def test_a_path_with_no_hops_has_no_probability(scorer):
    with pytest.raises(ScoringError, match="no hops"):
        scorer.score_path([], DATABASE)


def test_nonsense_clamp_bounds_are_rejected():
    config = make_scoring_config()
    broken = type(config)(**{**{f: getattr(config, f) for f in config.__slots__}, "p_clamp_min": 0.9, "p_clamp_max": 0.5})
    with pytest.raises(ScoringError, match="clamp bounds"):
        Scorer(broken)
