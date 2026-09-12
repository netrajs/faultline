"""Scoring the engine against the generator's ground truth.

``docs/SCOPE.md`` D8 is the claim this module has to make good on: the
environment is synthetic, so the denominator is known, so accuracy is
*measured* rather than asserted. Everything here reads the manifest tables
written by ``backend/generator`` and the run tables written by
``backend/engine/persistence.py``. Nothing is computed from anything the engine
also computed, and no number is produced for a quantity the ground truth does
not actually pin down.

Four things have to be said precisely, because a precision figure is only as
honest as the rule that decides what counts.

**What the ground truth contains, and what it does not.** ``plant_log`` records
endpoints and prose -- *intent* -- never a route, which is the whole point of
the three-layer separation in D8. ``decoy_instance`` records single graph
elements and what a correct engine must do with each: refuse the decoy, accept
its twin. ``true_edge_probability`` records the per-edge success probability the
generator actually used. So there is no ground-truth *path* to compare a
reported path against, and inventing one -- by running some second search over
the same graph and calling its output the answer -- would be scoring the engine
against another engine while claiming to score it against the manifest. The
comparison against a second implementation is a different claim and lives in
``validation/differential.py``.

**So every case is a labelled ground-truth item.** The confusion matrix is
built the way ``007_ground_truth.sql``'s ``evaluation_case`` table is shaped:
one case per planted opportunity (found it or missed it), one per decoy (refused
it or walked it), one per twin (walked it or missed it). Precision, recall and
F1 then come out of a matrix in which every cell counts something the generator
actually planted. A reported path that corresponds to no planted item is not
counted as a false positive -- the graph around the plants is organic, and
genuine paths through it exist that the manifest was never asked to know about.
Calling those errors would manufacture a precision figure out of ignorance.
The count of such paths is reported as ``unlabelled_findings`` rather than
hidden.

**The two match levels are two different questions.** D8 asks for both, and the
gap between them is the interesting part: it says how often the engine reaches
the right place by the wrong mechanism.

    *L2, edge sequence.* A finding is identified by ``core.ids.path_id`` over
    its (edge id, rule id) sequence. A planted opportunity is recovered only by
    a path whose own target is the planted goal and whose length falls inside
    the scenario's declared hop bounds. A registry instance is touched only when
    its own edge id -- that exact edge, not another one between the same pair --
    appears in a reported path.

    *L1, node sequence.* A finding is identified by
    ``core.ids.node_sequence_key`` over the nodes it passes through, so two
    routes over the same nodes by different edges are one finding. A planted
    opportunity is recovered by any path whose node sequence passes through the
    goal at all, whatever its length and whether or not it stopped there. A
    registry instance is touched when a reported path crosses its edge's two
    endpoints consecutively, by whatever edge.

**Neither level requires the planted entry node, and that is deliberate.** The
manifest names where the opportunity was *created*; the threat model decides
where an attacker actually starts, and for several of the shipped rules the two
have nothing to do with each other. ``docs/RULES.md`` R10 is the clearest case:
kerberoasting requires no relationship at all between the attacker and the
service account, so a scenario planted at ``u-0141`` is equally available to
every other authenticated user and the engine attributes it to whichever entry
it enumerates first. Insisting on the planted entry would score enumeration
order and report a recovered attack as a miss. The entry the engine did use is
stated in each case's detail, so the disagreement is visible rather than
assumed away.

**A ground-truth item the run never evaluated is not a result.** A decoy that no
reported path walked and no recorded refusal names was never reached, and
counting it as correctly refused would inflate the decoy figure with graph the
engine never looked at -- which is the exact failure mode D8 warns about, an
engine that scores well by reporting nothing. Those cases carry the outcome
``not_evaluated``, are excluded from every ratio, and are counted in the open.

**Ranking and calibration measure different things and must not be conflated.**
The ranking metrics compare the engine's ``risk_score`` ordering against the
ordering induced by the manifest's true edge probabilities. They will not reach
1.0 even on a perfect engine, and that is not a defect: ``docs/SCOPE.md`` D3
composes risk from likelihood *and* impact, while the manifest's true
probability is likelihood alone, so the two orderings genuinely differ wherever
a likely path leads somewhere unimportant. What a low value would mean is that
the engine's ordering carries no information about how achievable a path
actually is. Calibration is the direct comparison and is done per hop, where the
manifest and the engine describe exactly the same quantity: the generator's
``p_true`` for an edge against the engine's ``p_succ`` for the hop that
traversed it.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from core.ids import node_sequence_key, path_id

__all__ = [
    "CalibrationBin",
    "CalibrationScore",
    "Case",
    "DEFAULT_BIN_COUNT",
    "GroundTruth",
    "LevelScore",
    "MATCH_LEVELS",
    "MetricsReport",
    "MetricsUnavailable",
    "NDCG_K",
    "PlantedOpportunity",
    "RankingScore",
    "Refusals",
    "RegistryInstance",
    "ReportedPath",
    "compute_report",
    "kendall_tau_b",
    "load_ground_truth",
    "load_refusals",
    "load_report",
    "load_reported_paths",
    "ndcg_at_k",
]

#: The two identities a finding is scored under. Named exactly as the
#: ``evaluation_run.match_level`` enum names them, so a stored evaluation and a
#: live one cannot drift apart on a label.
MATCH_LEVELS: tuple[str, str] = ("edge_sequence", "node_sequence")

#: D8 names NDCG@k for the ranking family and the metric row seeded in
#: ``007_ground_truth.sql`` fixes k at ten.
NDCG_K = 10

#: Calibration bins. Ten of width 0.1 is the conventional choice and it is the
#: one the interface draws; a finer grid over a few hundred hops would report
#: sampling noise as miscalibration.
DEFAULT_BIN_COUNT = 10


class MetricsUnavailable(RuntimeError):
    """There is no completed run, or no manifest, to score.

    Raised rather than returning zeroes. A precision of 0.0 and "nothing has
    been generated yet" are different states and an interface that cannot tell
    them apart will show the first when it means the second.
    """


# ── What the engine reported ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ReportedPath:
    """One discovered path, reduced to what scoring needs."""

    stored_path_id: str
    source_node_id: str
    target_node_id: str
    risk_score: float
    p_success: float
    edge_ids: tuple[str | None, ...]
    rule_ids: tuple[int, ...]
    hop_probabilities: tuple[float, ...]
    """The engine's ``p_succ`` per hop, aligned with ``edge_ids``."""

    node_sequence: tuple[str, ...]
    """Every node the path passes through, in order, consecutive repeats collapsed.

    Built from each hop's ``(src, dst)`` rather than from ``dst`` alone, because
    the engine's frontier is not position-gated (see ``engine/search.py``): a hop
    may act on a node the previous hop did not leave the attacker standing on,
    and dropping the source would silently close that gap.
    """

    @property
    def hop_count(self) -> int:
        return len(self.rule_ids)

    @property
    def edge_key(self) -> str:
        """L2 identity: the content hash over the (edge, rule) sequence."""
        return path_id(self.edge_ids, self.rule_ids)

    @property
    def node_key(self) -> str:
        """L1 identity: the content hash over the node sequence."""
        return node_sequence_key(self.node_sequence)

    @property
    def edge_id_set(self) -> frozenset[str]:
        return frozenset(e for e in self.edge_ids if e)

    @property
    def node_pairs(self) -> frozenset[tuple[str, str]]:
        """Consecutive node pairs, for matching an edge by its endpoints at L1."""
        return frozenset(
            zip(self.node_sequence, self.node_sequence[1:])
        )


def _node_sequence(hops: Sequence[tuple[str, str]]) -> tuple[str, ...]:
    sequence: list[str] = []
    for src, dst in hops:
        for node_id in (src, dst):
            if not sequence or sequence[-1] != node_id:
                sequence.append(node_id)
    return tuple(sequence)


# ── What the generator planted ───────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PlantedOpportunity:
    """One row of ``plant_log``, with its scenario's expectations attached."""

    plant_id: int
    scenario_code: str
    scenario_name: str
    entry_node_id: str
    goal_node_id: str
    expected_min_hops: int
    expected_max_hops: int
    expected_severity: float
    notes: str


@dataclass(frozen=True, slots=True)
class RegistryInstance:
    """One row of ``decoy_instance``: a decoy, or the twin that makes it mean something."""

    instance_id: int
    decoy_code: str
    decoy_name: str
    role: str
    """``'decoy'`` or ``'twin'``."""

    edge_id: str | None
    node_id: str | None
    expected_outcome: str
    """``'reject'`` or ``'accept'``."""

    deciding_attribute: str
    deciding_value: str
    rationale: str

    @property
    def label(self) -> str:
        return f"{self.decoy_code}:{self.role}:{self.instance_id}"


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """Everything the manifest knows about one graph version."""

    graph_version_id: int
    seed: int
    generator_version: str
    scenario_count: int
    opportunities: tuple[PlantedOpportunity, ...]
    registry: tuple[RegistryInstance, ...]
    true_edge_probability: Mapping[str, float]
    edge_endpoints: Mapping[str, tuple[str, str]]
    """``edge_id -> (src, dst)``, needed to match a registry edge by its endpoints at L1."""

    @property
    def decoys(self) -> tuple[RegistryInstance, ...]:
        return tuple(i for i in self.registry if i.expected_outcome == "reject")

    @property
    def twins(self) -> tuple[RegistryInstance, ...]:
        return tuple(i for i in self.registry if i.expected_outcome == "accept")


# ── The confusion matrix ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Refusals:
    """Which graph elements the run recorded a refusal against.

    Read from ``rejected_candidate``, which -- unlike ``discovered_path`` -- is
    not subject to the k-best allowance: the engine records every candidate it
    declined, so this is the complete record of what the search actually looked
    at and said no to. That is what makes it usable as evidence that a decoy was
    refused rather than merely never reached.
    """

    reason_codes_by_edge: Mapping[str, tuple[str, ...]]
    reason_codes_by_node: Mapping[str, tuple[str, ...]]

    def for_edge(self, edge_id: str) -> tuple[str, ...]:
        return self.reason_codes_by_edge.get(edge_id, ())

    def for_node(self, node_id: str) -> tuple[str, ...]:
        return self.reason_codes_by_node.get(node_id, ())


@dataclass(frozen=True, slots=True)
class Case:
    """One labelled ground-truth item and what the engine did with it.

    Shaped to ``evaluation_case`` so a live evaluation and a stored one describe
    a miss in the same words, with one outcome the table does not have --
    ``not_evaluated``, for an item this run never reached. See the module
    docstring for why that is a fifth outcome rather than a quiet success.
    """

    kind: str
    """``'scenario'``, ``'decoy'`` or ``'twin'``."""

    reference_code: str
    outcome: str
    """``'true_positive'``, ``'false_positive'``, ``'true_negative'``,
    ``'false_negative'`` or ``'not_evaluated'``."""

    matched_path_id: str | None
    detail: str
    """Plain-language account of the outcome. For a miss: how far the engine got."""


@dataclass(frozen=True, slots=True)
class LevelScore:
    """The whole discovery family at one match level."""

    match_level: str
    cases: tuple[Case, ...]
    reported_findings: int
    """Distinct paths under this level's identity."""

    unlabelled_findings: int
    """Reported paths corresponding to no planted item. Not errors -- see the module docstring."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    not_evaluated: int

    @property
    def precision(self) -> float | None:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else None

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    @property
    def scenarios_recovered(self) -> int:
        return sum(1 for c in self.cases if c.kind == "scenario" and c.outcome == "true_positive")

    @property
    def scenarios_total(self) -> int:
        return sum(1 for c in self.cases if c.kind == "scenario")

    @property
    def decoy_rejection(self) -> float | None:
        """Refused decoys over decoys the run actually evaluated.

        ``None`` when none were evaluated. Reporting 1.0 over an empty set would
        be the single most flattering and least truthful number this module
        could produce.
        """
        return self._rate("decoy", "true_negative")

    @property
    def twin_acceptance(self) -> float | None:
        return self._rate("twin", "true_positive")

    def _rate(self, kind: str, good: str) -> float | None:
        evaluated = [c for c in self.cases if c.kind == kind and c.outcome != "not_evaluated"]
        if not evaluated:
            return None
        return sum(1 for c in evaluated if c.outcome == good) / len(evaluated)

    def kind_counts(self, kind: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            if case.kind == kind:
                counts[case.outcome] = counts.get(case.outcome, 0) + 1
        return counts


# ── Ranking ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RankingScore:
    paths_ranked: int
    paths_unscoreable: int
    """Reported paths carrying no edge the manifest recorded a probability for."""

    concordant: int
    discordant: int
    kendall_tau: float | None
    ndcg_at_k: float | None
    k: int


def kendall_tau_b(xs: Sequence[float], ys: Sequence[float]) -> tuple[float | None, int, int]:
    """Kendall's tau-b over two orderings of the same items.

    Tau-b rather than tau-a because both sequences tie: several paths share a
    risk score, and several share a true probability, and tau-a would charge the
    engine for an ordering it never claimed. Returns the coefficient and the
    concordant/discordant pair counts, because a coefficient over nine pairs and
    one over nine hundred deserve to be read differently.
    """
    if len(xs) != len(ys):
        raise ValueError(f"kendall_tau_b needs equal-length sequences, got {len(xs)} and {len(ys)}")
    n = len(xs)
    concordant = discordant = 0
    ties_x = ties_y = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx = xs[i] - xs[j]
            dy = ys[i] - ys[j]
            if dx == 0 and dy == 0:
                ties_x += 1
                ties_y += 1
                continue
            if dx == 0:
                ties_x += 1
                continue
            if dy == 0:
                ties_y += 1
                continue
            if dx * dy > 0:
                concordant += 1
            else:
                discordant += 1
    denominator = math.sqrt((concordant + discordant + ties_x) * (concordant + discordant + ties_y))
    if denominator == 0:
        return None, concordant, discordant
    return (concordant - discordant) / denominator, concordant, discordant


def ndcg_at_k(gains_in_predicted_order: Sequence[float], k: int) -> float | None:
    """Normalised discounted cumulative gain over the first *k* results.

    The gain is the manifest's true probability for the path the engine placed
    at that rank; the ideal ordering is the same gains sorted descending. So
    this asks whether the paths the engine put at the top are the ones an
    attacker would most likely actually manage, weighting an error at rank one
    far more heavily than one at rank ten -- which is how a list like this is
    really read.
    """
    if not gains_in_predicted_order:
        return None
    top = list(gains_in_predicted_order[:k])
    ideal = sorted(gains_in_predicted_order, reverse=True)[:k]

    def dcg(gains: Sequence[float]) -> float:
        return sum(gain / math.log2(rank + 1) for rank, gain in enumerate(gains, start=1))

    best = dcg(ideal)
    return dcg(top) / best if best > 0 else None


# ── Calibration ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CalibrationBin:
    lower: float
    upper: float
    count: int
    mean_predicted: float | None
    mean_true: float | None


@dataclass(frozen=True, slots=True)
class CalibrationScore:
    bins: tuple[CalibrationBin, ...]
    samples: int
    """Hops whose edge the manifest recorded a true probability for."""

    hops_unscoreable: int
    expected_calibration_error: float | None
    brier_score: float | None


def _calibration(
    pairs: Sequence[tuple[float, float]], bin_count: int = DEFAULT_BIN_COUNT
) -> tuple[tuple[CalibrationBin, ...], float | None, float | None]:
    """Bin (predicted, true) pairs, then summarise the gap two ways.

    Expected calibration error is the sample-weighted mean absolute gap between
    a bin's mean prediction and its mean truth, so it answers "when the engine
    says seventy percent, does it happen seventy percent of the time". The Brier
    score is the mean squared error over the same pairs and answers a different
    question -- how far off any individual estimate is -- which is why both are
    reported rather than one standing in for the other.
    """
    width = 1.0 / bin_count
    buckets: list[list[tuple[float, float]]] = [[] for _ in range(bin_count)]
    for predicted, true_p in pairs:
        index = min(bin_count - 1, max(0, int(predicted / width)))
        buckets[index].append((predicted, true_p))

    bins: list[CalibrationBin] = []
    for index, bucket in enumerate(buckets):
        bins.append(
            CalibrationBin(
                lower=round(index * width, 6),
                upper=round((index + 1) * width, 6),
                count=len(bucket),
                mean_predicted=(sum(p for p, _ in bucket) / len(bucket)) if bucket else None,
                mean_true=(sum(t for _, t in bucket) / len(bucket)) if bucket else None,
            )
        )

    if not pairs:
        return tuple(bins), None, None

    total = len(pairs)
    ece = sum(
        (b.count / total) * abs(b.mean_predicted - b.mean_true)
        for b in bins
        if b.count and b.mean_predicted is not None and b.mean_true is not None
    )
    brier = sum((predicted - true_p) ** 2 for predicted, true_p in pairs) / total
    return tuple(bins), ece, brier


# ── The whole report ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class MetricsReport:
    graph_version_id: int
    analysis_run_id: int
    threat_model_code: str
    scoring_version: str
    seed: int
    generator_version: str
    paths_reported: int
    levels: tuple[LevelScore, ...]
    ranking: RankingScore
    calibration: CalibrationScore
    duration_ms: int

    def level(self, match_level: str) -> LevelScore:
        for score in self.levels:
            if score.match_level == match_level:
                return score
        raise KeyError(f"no level {match_level!r} in this report")


def compute_report(
    *,
    graph_version_id: int,
    analysis_run_id: int,
    threat_model_code: str,
    scoring_version: str,
    ground_truth: GroundTruth,
    paths: Sequence[ReportedPath],
    refusals: Refusals,
    bin_count: int = DEFAULT_BIN_COUNT,
) -> MetricsReport:
    """Score one completed run against one graph version's manifest."""
    started = time.perf_counter()
    levels = tuple(
        _score_level(level, ground_truth, paths, refusals) for level in MATCH_LEVELS
    )
    return MetricsReport(
        graph_version_id=graph_version_id,
        analysis_run_id=analysis_run_id,
        threat_model_code=threat_model_code,
        scoring_version=scoring_version,
        seed=ground_truth.seed,
        generator_version=ground_truth.generator_version,
        paths_reported=len(paths),
        levels=levels,
        ranking=_score_ranking(ground_truth, paths),
        calibration=_score_calibration(ground_truth, paths, bin_count),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


def _score_level(
    match_level: str,
    truth: GroundTruth,
    paths: Sequence[ReportedPath],
    refusals: Refusals,
) -> LevelScore:
    strict = match_level == "edge_sequence"
    cases: list[Case] = []
    corroborated: set[str] = set()

    def identity(path: ReportedPath) -> str:
        return path.edge_key if strict else path.node_key

    for opportunity in truth.opportunities:
        match = _recovering_path(opportunity, paths, strict=strict)
        if match is not None:
            corroborated.add(identity(match))
            entry_note = (
                f"from the planted entry {opportunity.entry_node_id}"
                if match.source_node_id == opportunity.entry_node_id
                else (
                    f"from {match.source_node_id} rather than the planted entry "
                    f"{opportunity.entry_node_id}, which the rules make equivalent here"
                )
            )
            cases.append(
                Case(
                    kind="scenario",
                    reference_code=opportunity.scenario_code,
                    outcome="true_positive",
                    matched_path_id=match.stored_path_id,
                    detail=(
                        f"Reached {opportunity.goal_node_id} in {match.hop_count} hops "
                        f"({opportunity.expected_min_hops}-{opportunity.expected_max_hops} "
                        f"expected), {entry_note}."
                        if strict
                        else f"A reported path passes through {opportunity.goal_node_id}, "
                        f"{entry_note}."
                    ),
                )
            )
            continue
        cases.append(
            Case(
                kind="scenario",
                reference_code=opportunity.scenario_code,
                outcome="false_negative",
                matched_path_id=None,
                detail=_miss_detail(opportunity, paths),
            )
        )

    for instance in truth.registry:
        walked = _walked_path(instance, truth, paths, strict=strict)
        if walked is not None:
            corroborated.add(identity(walked))
        reasons = _refusal_reasons(instance, refusals)
        cases.append(_registry_case(instance, walked, reasons))

    findings = {identity(path) for path in paths}
    return LevelScore(
        match_level=match_level,
        cases=tuple(cases),
        reported_findings=len(findings),
        unlabelled_findings=len(findings - corroborated),
        true_positives=sum(1 for c in cases if c.outcome == "true_positive"),
        false_positives=sum(1 for c in cases if c.outcome == "false_positive"),
        true_negatives=sum(1 for c in cases if c.outcome == "true_negative"),
        false_negatives=sum(1 for c in cases if c.outcome == "false_negative"),
        not_evaluated=sum(1 for c in cases if c.outcome == "not_evaluated"),
    )


def _refusal_reasons(instance: RegistryInstance, refusals: Refusals) -> tuple[str, ...]:
    if instance.edge_id is not None:
        return refusals.for_edge(instance.edge_id)
    if instance.node_id is not None:
        return refusals.for_node(instance.node_id)
    return ()


def _registry_case(
    instance: RegistryInstance, walked: ReportedPath | None, reasons: Sequence[str]
) -> Case:
    """One decoy or twin, scored on the strongest evidence the run actually left.

    A decoy walked by a reported path is a false positive outright. A decoy not
    walked is only credited as correctly refused when the run also recorded a
    refusal naming it -- otherwise the search never reached it and there is
    nothing to credit.

    A twin is credited only when a reported path uses it. It is never charged as
    a false negative for being absent, and that restraint is deliberate: the
    k-best allowance means most genuine paths are never reported, and several
    rules share an edge type, so a refusal recorded against a twin's edge is as
    likely to be some other rule legitimately declining it as it is to be the
    engine wrongly blocking the twin. Charging on that evidence would be an
    accusation the data cannot support.
    """
    attribute = f"{instance.deciding_attribute} = {instance.deciding_value!r}"
    if instance.expected_outcome == "reject":
        if walked is not None:
            return Case(
                kind="decoy",
                reference_code=instance.label,
                outcome="false_positive",
                matched_path_id=walked.stored_path_id,
                detail=(
                    f"Walked despite {attribute}, which must refuse it. {instance.rationale}"
                ),
            )
        if reasons:
            return Case(
                kind="decoy",
                reference_code=instance.label,
                outcome="true_negative",
                matched_path_id=None,
                detail=(
                    f"Refused on {', '.join(sorted(set(reasons))[:3])}, with {attribute}. "
                    f"{instance.rationale}"
                ),
            )
        return Case(
            kind="decoy",
            reference_code=instance.label,
            outcome="not_evaluated",
            matched_path_id=None,
            detail=(
                f"Neither walked nor refused in this run, so the search never reached it "
                f"and its refusal is unproven. {attribute}."
            ),
        )

    if walked is not None:
        return Case(
            kind="twin",
            reference_code=instance.label,
            outcome="true_positive",
            matched_path_id=walked.stored_path_id,
            detail=(
                f"Accepted with {attribute} -- the one attribute separating it from its "
                f"decoy, so the decoy above was refused on the attribute and not on a pattern."
            ),
        )
    return Case(
        kind="twin",
        reference_code=instance.label,
        outcome="not_evaluated",
        matched_path_id=None,
        detail=(
            f"No reported path uses it, and the run keeps only its k best paths per target, "
            f"so its acceptance is untested rather than failed. {attribute}."
        ),
    )


def _recovering_path(
    opportunity: PlantedOpportunity, paths: Sequence[ReportedPath], *, strict: bool
) -> ReportedPath | None:
    """The reported path that recovers this opportunity, or ``None``.

    Strictly: the path's own target is the planted goal and its length is inside
    the scenario's declared bounds. Forgivingly: the path passes through the
    goal at all -- so arriving there partway along a longer chain still counts.
    Neither requires the planted entry; see the module docstring.

    Where several qualify, the shortest wins, then the highest risk score. That
    is a reporting choice about which path to name in the case detail, not a
    scoring one: the case is a true positive either way.
    """
    candidates: list[ReportedPath] = []
    for path in paths:
        if strict:
            if (
                path.target_node_id == opportunity.goal_node_id
                and opportunity.expected_min_hops <= path.hop_count <= opportunity.expected_max_hops
            ):
                candidates.append(path)
            continue
        if opportunity.goal_node_id in path.node_sequence:
            candidates.append(path)
    if not candidates:
        return None
    return min(candidates, key=lambda p: (p.hop_count, -p.risk_score, p.stored_path_id))


def _walked_path(
    instance: RegistryInstance,
    truth: GroundTruth,
    paths: Sequence[ReportedPath],
    *,
    strict: bool,
) -> ReportedPath | None:
    """The reported path that used this registry element, or ``None``.

    An instance carries an edge or a node, never both. A node instance is
    matched the same way at either level -- a node has no mechanism to be right
    or wrong about. An edge instance is matched by its own id at L2 and by its
    two endpoints at L1, which is exactly where the two levels can disagree: a
    decoy edge correctly refused, whose pair of nodes the engine crossed by a
    parallel edge instead, is refused at L2 and walked at L1.
    """
    for path in paths:
        if instance.edge_id is not None:
            if strict:
                if instance.edge_id in path.edge_id_set:
                    return path
                continue
            endpoints = truth.edge_endpoints.get(instance.edge_id)
            if endpoints is not None and endpoints in path.node_pairs:
                return path
            continue
        if instance.node_id is not None and instance.node_id in path.node_sequence:
            return path
    return None


def _miss_detail(opportunity: PlantedOpportunity, paths: Sequence[ReportedPath]) -> str:
    """How far the engine got before losing the thread."""
    to_goal = [p for p in paths if opportunity.goal_node_id in p.node_sequence]
    if to_goal:
        lengths = sorted({p.hop_count for p in to_goal})
        return (
            f"{opportunity.goal_node_id} is reached, but in "
            f"{', '.join(str(n) for n in lengths)} hops rather than the "
            f"{opportunity.expected_min_hops}-{opportunity.expected_max_hops} this "
            f"scenario plants, so the route found is not the one planted."
        )
    from_entry = [p for p in paths if opportunity.entry_node_id in p.node_sequence]
    if from_entry:
        reached = sorted({p.target_node_id for p in from_entry})
        return (
            f"{len(from_entry)} reported path(s) pass through "
            f"{opportunity.entry_node_id}, reaching {', '.join(reached[:4])}"
            f"{' and others' if len(reached) > 4 else ''}, but never "
            f"{opportunity.goal_node_id}."
        )
    return (
        f"No reported path touches either {opportunity.entry_node_id} or "
        f"{opportunity.goal_node_id}."
    )


def _score_ranking(truth: GroundTruth, paths: Sequence[ReportedPath]) -> RankingScore:
    scored: list[tuple[float, float]] = []
    unscoreable = 0
    for path in paths:
        true_p = _true_probability(truth, path)
        if true_p is None:
            unscoreable += 1
            continue
        scored.append((path.risk_score, true_p))

    if not scored:
        return RankingScore(
            paths_ranked=0,
            paths_unscoreable=unscoreable,
            concordant=0,
            discordant=0,
            kendall_tau=None,
            ndcg_at_k=None,
            k=NDCG_K,
        )

    tau, concordant, discordant = kendall_tau_b(
        [risk for risk, _ in scored], [true_p for _, true_p in scored]
    )
    # Ranked by the engine's own ordering -- highest risk first, ties broken the
    # way the stored run broke them, which is the order an analyst actually sees.
    by_engine = sorted(range(len(scored)), key=lambda i: -scored[i][0])
    return RankingScore(
        paths_ranked=len(scored),
        paths_unscoreable=unscoreable,
        concordant=concordant,
        discordant=discordant,
        kendall_tau=tau,
        ndcg_at_k=ndcg_at_k([scored[i][1] for i in by_engine], NDCG_K),
        k=NDCG_K,
    )


def _true_probability(truth: GroundTruth, path: ReportedPath) -> float | None:
    """The manifest's probability for a whole path: the product over its edges.

    ``None`` when the manifest recorded nothing for any edge on the path. A hop
    that consumes no edge -- kerberoasting -- has no manifest probability to
    contribute and is passed over rather than assigned one, because the
    generator never synthesised a number for it and inventing a 1.0 would
    quietly make every such path look certain.
    """
    product = 1.0
    matched = 0
    for edge_id in path.edge_ids:
        if edge_id is None:
            continue
        p_true = truth.true_edge_probability.get(edge_id)
        if p_true is None:
            continue
        product *= p_true
        matched += 1
    return product if matched else None


def _score_calibration(
    truth: GroundTruth, paths: Sequence[ReportedPath], bin_count: int
) -> CalibrationScore:
    pairs: list[tuple[float, float]] = []
    unscoreable = 0
    # One sample per distinct (edge, engine estimate) rather than per hop: the
    # same edge appears on many reported paths and the engine's estimate for it
    # does not change between them, so counting each occurrence would weight a
    # popular edge into dominating the curve.
    seen: set[tuple[str, float]] = set()
    for path in paths:
        for edge_id, predicted in zip(path.edge_ids, path.hop_probabilities, strict=True):
            if edge_id is None:
                unscoreable += 1
                continue
            p_true = truth.true_edge_probability.get(edge_id)
            if p_true is None:
                unscoreable += 1
                continue
            key = (edge_id, predicted)
            if key in seen:
                continue
            seen.add(key)
            pairs.append((predicted, p_true))

    bins, ece, brier = _calibration(pairs, bin_count)
    return CalibrationScore(
        bins=bins,
        samples=len(pairs),
        hops_unscoreable=unscoreable,
        expected_calibration_error=ece,
        brier_score=brier,
    )


# ── Reading it out of MySQL ──────────────────────────────────────────────────


def load_ground_truth(graph_version_id: int) -> GroundTruth:
    """Everything the manifest recorded for one graph version."""
    from app.db import fetch_all, fetch_one

    manifest = fetch_one(
        "SELECT graph_version_id, seed, generator_version, scenario_count "
        "FROM generation_manifest WHERE graph_version_id = :gv",
        {"gv": graph_version_id},
    )
    if not manifest:
        raise MetricsUnavailable(
            f"Graph version {graph_version_id} has no generation manifest, so there "
            f"is no ground truth to score against. Regenerate the graph with: "
            f"python -m generator.build"
        )

    plants = fetch_all(
        """
        SELECT p.id, p.scenario_code, p.entry_node_id, p.goal_node_id, p.notes,
               s.name, s.expected_min_hops, s.expected_max_hops, s.expected_severity
        FROM plant_log p
        JOIN scenario s ON s.code = p.scenario_code
        WHERE p.graph_version_id = :gv
        ORDER BY p.id
        """,
        {"gv": graph_version_id},
    )
    registry = fetch_all(
        """
        SELECT i.id, i.decoy_code, i.role, i.edge_id, i.node_id, i.expected_outcome,
               i.deciding_value, d.name, d.deciding_attribute, d.rejection_rationale
        FROM decoy_instance i
        JOIN decoy_pattern d ON d.code = i.decoy_code
        WHERE i.graph_version_id = :gv
        ORDER BY i.id
        """,
        {"gv": graph_version_id},
    )
    probabilities = fetch_all(
        "SELECT edge_id, p_true FROM true_edge_probability WHERE graph_version_id = :gv",
        {"gv": graph_version_id},
    )
    endpoints = fetch_all(
        "SELECT edge_id, src_id, dst_id FROM edge WHERE graph_version_id = :gv",
        {"gv": graph_version_id},
    )

    return GroundTruth(
        graph_version_id=graph_version_id,
        seed=int(manifest["seed"]),
        generator_version=str(manifest["generator_version"]),
        scenario_count=int(manifest["scenario_count"]),
        opportunities=tuple(
            PlantedOpportunity(
                plant_id=int(row["id"]),
                scenario_code=str(row["scenario_code"]),
                scenario_name=str(row["name"]),
                entry_node_id=str(row["entry_node_id"]),
                goal_node_id=str(row["goal_node_id"]),
                expected_min_hops=int(row["expected_min_hops"]),
                expected_max_hops=int(row["expected_max_hops"]),
                expected_severity=float(row["expected_severity"]),
                notes=str(row["notes"]),
            )
            for row in plants
        ),
        registry=tuple(
            RegistryInstance(
                instance_id=int(row["id"]),
                decoy_code=str(row["decoy_code"]),
                decoy_name=str(row["name"]),
                role=str(row["role"]),
                edge_id=_optional(row["edge_id"]),
                node_id=_optional(row["node_id"]),
                expected_outcome=str(row["expected_outcome"]),
                deciding_attribute=str(row["deciding_attribute"]),
                deciding_value=str(row["deciding_value"]),
                rationale=str(row["rejection_rationale"]),
            )
            for row in registry
        ),
        true_edge_probability={
            str(row["edge_id"]): float(row["p_true"]) for row in probabilities
        },
        edge_endpoints={
            str(row["edge_id"]): (str(row["src_id"]), str(row["dst_id"])) for row in endpoints
        },
    )


def load_reported_paths(analysis_run_id: int) -> tuple[ReportedPath, ...]:
    """The paths one completed run reported, with their hops attached."""
    from app.db import fetch_all

    paths = fetch_all(
        """
        SELECT path_id, source_node_id, target_node_id, risk_score, p_success
        FROM discovered_path WHERE analysis_run_id = :run
        ORDER BY rank_in_run
        """,
        {"run": analysis_run_id},
    )
    hops = fetch_all(
        """
        SELECT path_id, hop_no, src_node_id, dst_node_id, edge_id, rule_id, p_succ
        FROM path_hop WHERE analysis_run_id = :run
        ORDER BY path_id, hop_no
        """,
        {"run": analysis_run_id},
    )

    by_path: dict[str, list[dict[str, Any]]] = {}
    for hop in hops:
        by_path.setdefault(str(hop["path_id"]), []).append(hop)

    reported: list[ReportedPath] = []
    for row in paths:
        stored_id = str(row["path_id"])
        path_hops = by_path.get(stored_id, [])
        if not path_hops:
            # A stored path with no hops cannot be scored and must not be
            # silently treated as a zero-hop finding.
            continue
        reported.append(
            ReportedPath(
                stored_path_id=stored_id,
                source_node_id=str(row["source_node_id"]),
                target_node_id=str(row["target_node_id"]),
                risk_score=float(row["risk_score"]),
                p_success=float(row["p_success"]),
                edge_ids=tuple(_optional(h["edge_id"]) for h in path_hops),
                rule_ids=tuple(int(h["rule_id"]) for h in path_hops),
                hop_probabilities=tuple(float(h["p_succ"]) for h in path_hops),
                node_sequence=_node_sequence(
                    [(str(h["src_node_id"]), str(h["dst_node_id"])) for h in path_hops]
                ),
            )
        )
    return tuple(reported)


def load_refusals(analysis_run_id: int) -> Refusals:
    """Every element one run recorded a refusal against, with the reasons given."""
    from app.db import fetch_all

    rows = fetch_all(
        "SELECT DISTINCT edge_id, src_node_id, dst_node_id, reason_code "
        "FROM rejected_candidate WHERE analysis_run_id = :run",
        {"run": analysis_run_id},
    )
    by_edge: dict[str, set[str]] = {}
    by_node: dict[str, set[str]] = {}
    for row in rows:
        reason = str(row["reason_code"])
        edge_id = _optional(row["edge_id"])
        if edge_id is not None:
            by_edge.setdefault(edge_id, set()).add(reason)
        for column in ("src_node_id", "dst_node_id"):
            node_id = _optional(row[column])
            if node_id is not None:
                by_node.setdefault(node_id, set()).add(reason)
    return Refusals(
        reason_codes_by_edge={k: tuple(sorted(v)) for k, v in by_edge.items()},
        reason_codes_by_node={k: tuple(sorted(v)) for k, v in by_node.items()},
    )


def load_report(analysis_run_id: int | None = None) -> MetricsReport:
    """Score the given run, or the latest completed baseline on the active graph."""
    from app.db import fetch_one

    if analysis_run_id is None:
        run = fetch_one(
            """
            SELECT r.id, r.graph_version_id, r.scoring_version, r.threat_model_code
            FROM analysis_run r
            JOIN graph_version g ON g.id = r.graph_version_id AND g.is_active = 1
            WHERE r.purpose = 'baseline' AND r.status = 'complete'
            ORDER BY r.id DESC LIMIT 1
            """
        )
        if not run:
            raise MetricsUnavailable(
                "No completed discovery run for the active graph, so there is nothing "
                "to score. Run: python -m engine.discover --threat-model external_phish"
            )
    else:
        run = fetch_one(
            "SELECT id, graph_version_id, scoring_version, threat_model_code "
            "FROM analysis_run WHERE id = :id AND status = 'complete'",
            {"id": analysis_run_id},
        )
        if not run:
            raise MetricsUnavailable(f"No completed analysis run {analysis_run_id}.")

    graph_version_id = int(run["graph_version_id"])
    run_id = int(run["id"])
    return compute_report(
        graph_version_id=graph_version_id,
        analysis_run_id=run_id,
        threat_model_code=str(run["threat_model_code"]),
        scoring_version=str(run["scoring_version"]),
        ground_truth=load_ground_truth(graph_version_id),
        paths=load_reported_paths(run_id),
        refusals=load_refusals(run_id),
    )


def _optional(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None
