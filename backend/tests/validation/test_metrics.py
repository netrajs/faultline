"""Scoring against ground truth, on a ground truth small enough to check by hand.

Every case here is built in the file rather than read from MySQL. That is not
only about not needing a database: a metric checked against real data can only
be checked against whatever that data happens to contain, and the cases worth
testing -- a decoy that was walked, a twin that was never reached, a ranking
that is exactly backwards -- are the ones a healthy run does not contain.

The arithmetic is checked against values worked out independently of the
implementation: tau over three items with one inversion, NDCG where the answer
is the closed form, and a calibration set whose bins were counted by hand.
"""

from __future__ import annotations

import math

import pytest

from validation.metrics import (
    GroundTruth,
    PlantedOpportunity,
    Refusals,
    RegistryInstance,
    ReportedPath,
    compute_report,
    kendall_tau_b,
    ndcg_at_k,
)


def path(
    *,
    stored: str,
    source: str,
    target: str,
    hops,
    risk: float = 5.0,
    p_success: float = 0.5,
    probabilities=None,
) -> ReportedPath:
    """One reported path from a list of ``(edge_id, rule_id, src, dst)`` hops."""
    edge_ids = tuple(h[0] for h in hops)
    sequence: list[str] = []
    for _, _, src, dst in hops:
        for node_id in (src, dst):
            if not sequence or sequence[-1] != node_id:
                sequence.append(node_id)
    return ReportedPath(
        stored_path_id=stored,
        source_node_id=source,
        target_node_id=target,
        risk_score=risk,
        p_success=p_success,
        edge_ids=edge_ids,
        rule_ids=tuple(h[1] for h in hops),
        hop_probabilities=tuple(probabilities or [0.9] * len(hops)),
        node_sequence=tuple(sequence),
    )


def opportunity(code="intern_to_da", entry="u-1", goal="db-1", lo=2, hi=4) -> PlantedOpportunity:
    return PlantedOpportunity(
        plant_id=1,
        scenario_code=code,
        scenario_name="Intern to domain admin",
        entry_node_id=entry,
        goal_node_id=goal,
        expected_min_hops=lo,
        expected_max_hops=hi,
        expected_severity=9.5,
        notes="Three levels of nesting terminating in an administrative permission.",
    )


def instance(role: str, *, edge_id=None, node_id=None, instance_id=1) -> RegistryInstance:
    return RegistryInstance(
        instance_id=instance_id,
        decoy_code="d01_mfa_phishing_resistant",
        decoy_name="Phishing-resistant second factor",
        role=role,
        edge_id=edge_id,
        node_id=node_id,
        expected_outcome="reject" if role == "decoy" else "accept",
        deciding_attribute="AUTHENTICATES_TO.mfa_type",
        deciding_value="fido2" if role == "decoy" else "sms",
        rationale="A hardware-bound factor cannot be relayed.",
    )


def truth(*, opportunities=(), registry=(), probabilities=None, endpoints=None) -> GroundTruth:
    return GroundTruth(
        graph_version_id=1,
        seed=42,
        generator_version="1.0.0",
        scenario_count=len(opportunities),
        opportunities=tuple(opportunities),
        registry=tuple(registry),
        true_edge_probability=dict(probabilities or {}),
        edge_endpoints=dict(endpoints or {}),
    )


def score(ground_truth, paths, refusals=None, level="edge_sequence"):
    report = compute_report(
        graph_version_id=1,
        analysis_run_id=1,
        threat_model_code="external_phish",
        scoring_version="v1",
        ground_truth=ground_truth,
        paths=tuple(paths),
        refusals=refusals or Refusals({}, {}),
    )
    return report.level(level)


# ── Planted opportunities ────────────────────────────────────────────────────


def test_a_planted_opportunity_reached_within_its_hop_bounds_is_recovered():
    found = path(
        stored="p1",
        source="u-1",
        target="db-1",
        hops=[("e-1", 1, "u-1", "g-1"), ("e-2", 2, "g-1", "db-1")],
    )
    result = score(truth(opportunities=[opportunity()]), [found])
    assert result.scenarios_recovered == 1
    assert result.recall == 1.0


def test_the_same_opportunity_found_from_a_different_entry_still_counts():
    """R10 is the reason: kerberoasting needs no relationship to the attacker.

    The manifest names where the opportunity was created; the threat model
    decides where the attacker starts, and for a rule that consumes no edge the
    two have nothing to do with each other. Requiring the planted entry would
    report a recovered attack as a miss because the engine enumerated a
    different, equally valid user first.
    """
    found = path(
        stored="p1",
        source="u-9",
        target="db-1",
        hops=[(None, 10, "sa-1", "sa-1"), ("e-2", 5, "sa-1", "db-1")],
    )
    result = score(truth(opportunities=[opportunity()]), [found])
    assert result.scenarios_recovered == 1
    case = next(c for c in result.cases if c.kind == "scenario")
    assert "u-9" in case.detail and "u-1" in case.detail


def test_reaching_the_goal_outside_the_hop_bounds_is_a_miss_at_the_strict_level():
    """Six hops where the scenario plants two to four is a different route."""
    hops = [(f"e-{i}", i, f"n-{i}", f"n-{i + 1}") for i in range(1, 6)]
    hops.append(("e-6", 6, "n-6", "db-1"))
    found = path(stored="p1", source="n-1", target="db-1", hops=hops)

    strict = score(truth(opportunities=[opportunity()]), [found])
    assert strict.scenarios_recovered == 0
    assert "hops" in next(c for c in strict.cases if c.kind == "scenario").detail

    forgiving = score(truth(opportunities=[opportunity()]), [found], level="node_sequence")
    assert forgiving.scenarios_recovered == 1


def test_a_miss_says_how_far_the_engine_got():
    near = path(
        stored="p1", source="u-1", target="h-9", hops=[("e-1", 1, "u-1", "h-9")]
    )
    result = score(truth(opportunities=[opportunity()]), [near])
    case = next(c for c in result.cases if c.kind == "scenario")
    assert case.outcome == "false_negative"
    assert "u-1" in case.detail and "h-9" in case.detail


# ── Decoys and twins ─────────────────────────────────────────────────────────


def test_a_decoy_the_engine_walked_is_a_false_positive():
    walked = path(
        stored="p1", source="u-1", target="db-1", hops=[("e-decoy", 9, "cred-1", "db-1")]
    )
    result = score(truth(registry=[instance("decoy", edge_id="e-decoy")]), [walked])
    assert result.false_positives == 1
    assert result.precision == 0.0


def test_a_decoy_refused_with_a_recorded_reason_is_a_true_negative():
    refusals = Refusals({"e-decoy": ("edge_attr:mfa_type:not_in",)}, {})
    result = score(truth(registry=[instance("decoy", edge_id="e-decoy")]), [], refusals)
    assert result.true_negatives == 1
    assert result.decoy_rejection == 1.0
    assert "edge_attr:mfa_type:not_in" in result.cases[0].detail


def test_a_decoy_neither_walked_nor_refused_is_not_credited():
    """The failure mode D8 warns about: scoring well by never looking.

    A decoy the search never reached is not evidence that the engine refuses it,
    and counting it as a correct refusal would let an engine that reports
    nothing at all post a perfect decoy figure.
    """
    result = score(truth(registry=[instance("decoy", edge_id="e-decoy")]), [])
    assert result.cases[0].outcome == "not_evaluated"
    assert result.true_negatives == 0
    assert result.decoy_rejection is None


def test_a_twin_on_a_reported_path_is_a_true_positive():
    walked = path(
        stored="p1", source="u-1", target="db-1", hops=[("e-twin", 9, "cred-2", "db-1")]
    )
    result = score(truth(registry=[instance("twin", edge_id="e-twin")]), [walked])
    assert result.twin_acceptance == 1.0


def test_a_twin_nowhere_in_the_reported_set_is_untested_rather_than_failed():
    """The k-best allowance means most genuine paths are never reported."""
    result = score(truth(registry=[instance("twin", edge_id="e-twin")]), [])
    assert result.cases[0].outcome == "not_evaluated"
    assert result.twin_acceptance is None
    assert result.false_negatives == 0


def test_an_edge_matched_by_its_endpoints_is_forgiven_only_at_the_node_level():
    """A parallel edge between the same pair is a different attack at L2.

    ``core.ids.path_id`` is keyed on edge ids for exactly this reason: two
    credentials between one user and one host are two attacks. So a decoy edge
    the engine refused, whose endpoints it crossed by some other edge, is
    correctly refused strictly and counted as walked forgivingly -- and the gap
    between the two figures is what says so.
    """
    ground_truth = truth(
        registry=[instance("decoy", edge_id="e-decoy")],
        endpoints={"e-decoy": ("cred-1", "db-1")},
    )
    other = path(
        stored="p1", source="u-1", target="db-1", hops=[("e-other", 9, "cred-1", "db-1")]
    )
    refusals = Refusals({"e-decoy": ("edge_attr:mfa_type:not_in",)}, {})

    assert score(ground_truth, [other], refusals).true_negatives == 1
    assert score(ground_truth, [other], refusals, level="node_sequence").false_positives == 1


# ── Ranking ──────────────────────────────────────────────────────────────────


def test_kendall_tau_is_one_for_agreement_and_minus_one_for_reversal():
    assert kendall_tau_b([1, 2, 3], [1, 2, 3])[0] == pytest.approx(1.0)
    assert kendall_tau_b([1, 2, 3], [3, 2, 1])[0] == pytest.approx(-1.0)


def test_kendall_tau_counts_one_inversion_out_of_three_pairs():
    tau, concordant, discordant = kendall_tau_b([3, 2, 1], [3, 1, 2])
    assert (concordant, discordant) == (2, 1)
    assert tau == pytest.approx(1 / 3)


def test_kendall_tau_is_undefined_when_one_side_is_entirely_tied():
    """Not 0.0 -- an ordering nobody claimed is not an ordering that was wrong."""
    tau, _, _ = kendall_tau_b([1, 1, 1], [3, 2, 1])
    assert tau is None


def test_ndcg_is_one_when_the_engine_ordering_is_already_ideal():
    assert ndcg_at_k([0.9, 0.5, 0.1], 10) == pytest.approx(1.0)


def test_ndcg_penalises_burying_the_best_result():
    buried = ndcg_at_k([0.1, 0.5, 0.9], 10)
    expected_dcg = 0.1 + 0.5 / math.log2(3) + 0.9 / math.log2(4)
    ideal_dcg = 0.9 + 0.5 / math.log2(3) + 0.1 / math.log2(4)
    assert buried == pytest.approx(expected_dcg / ideal_dcg)
    assert buried < 1.0


def test_a_path_with_no_manifest_probability_is_excluded_rather_than_assumed():
    """A kerberoast hop has no synthesised probability; inventing 1.0 would lie."""
    kerberoast = path(stored="p1", source="u-1", target="db-1", hops=[(None, 10, "sa-1", "sa-1")])
    report = compute_report(
        graph_version_id=1,
        analysis_run_id=1,
        threat_model_code="external_phish",
        scoring_version="v1",
        ground_truth=truth(),
        paths=(kerberoast,),
        refusals=Refusals({}, {}),
    )
    assert report.ranking.paths_ranked == 0
    assert report.ranking.paths_unscoreable == 1
    assert report.ranking.kendall_tau is None


# ── Calibration ──────────────────────────────────────────────────────────────


def test_a_perfectly_calibrated_engine_scores_zero_on_both_measures():
    paths = [
        path(
            stored="p1",
            source="u-1",
            target="db-1",
            hops=[("e-1", 1, "u-1", "g-1"), ("e-2", 2, "g-1", "db-1")],
            probabilities=[0.9, 0.4],
        )
    ]
    report = compute_report(
        graph_version_id=1,
        analysis_run_id=1,
        threat_model_code="external_phish",
        scoring_version="v1",
        ground_truth=truth(probabilities={"e-1": 0.9, "e-2": 0.4}),
        paths=tuple(paths),
        refusals=Refusals({}, {}),
    )
    assert report.calibration.samples == 2
    assert report.calibration.expected_calibration_error == pytest.approx(0.0)
    assert report.calibration.brier_score == pytest.approx(0.0)


def test_calibration_reports_the_gap_where_the_engine_is_over_confident():
    paths = [
        path(
            stored="p1",
            source="u-1",
            target="db-1",
            hops=[("e-1", 1, "u-1", "db-1")],
            probabilities=[0.95],
        )
    ]
    report = compute_report(
        graph_version_id=1,
        analysis_run_id=1,
        threat_model_code="external_phish",
        scoring_version="v1",
        ground_truth=truth(probabilities={"e-1": 0.55}),
        paths=tuple(paths),
        refusals=Refusals({}, {}),
    )
    assert report.calibration.expected_calibration_error == pytest.approx(0.40)
    assert report.calibration.brier_score == pytest.approx(0.16)
    occupied = [b for b in report.calibration.bins if b.count]
    assert len(occupied) == 1
    assert occupied[0].lower == pytest.approx(0.9)


def test_one_edge_counts_once_however_many_paths_carry_it():
    """A popular edge must not get to vote repeatedly on the calibration curve."""
    shared = [
        path(
            stored=f"p{i}",
            source="u-1",
            target="db-1",
            hops=[("e-shared", 1, "u-1", "db-1")],
            probabilities=[0.8],
        )
        for i in range(5)
    ]
    report = compute_report(
        graph_version_id=1,
        analysis_run_id=1,
        threat_model_code="external_phish",
        scoring_version="v1",
        ground_truth=truth(probabilities={"e-shared": 0.6}),
        paths=tuple(shared),
        refusals=Refusals({}, {}),
    )
    assert report.calibration.samples == 1
