"""The log-space scorer.

Two axes, never blended inside the search (``docs/SCOPE.md`` D3).

**Likelihood** is the product of per-hop success probabilities, carried as
``-ln p`` so it is a sum. That is not a numerical convenience: a sum over hops
is decomposable over prefixes, which is exactly Bellman's condition, so a
best-first search minimising it is provably optimising the quantity the product
ranks by. A maximum over per-hop risks — the tempting simplification — has zero
partial derivative with respect to every hop but one, so a six-hop chain would
score identically to a one-hop version of its easiest step, and it is not
decomposable, so no shortest-path algorithm could optimise it.

**Impact** is a property of what the chain reaches, applied once, at the end,
when the target is known. Never inside the cost, because a target-dependent term
in the edge weight would destroy the prefix decomposition above.

Modifiers are additive in log-odds. Multiplying a probability by a penalty can
push it above 1, at which point ``-ln p`` goes negative, Dijkstra's guarantee is
void and a graph that deliberately contains trust cycles acquires negative
cycles. ``logit(p') = logit(p) + Σβ`` cannot leave ``(0,1)``, composes
commutatively, and hands back each β as that factor's own contribution — which
is why the "why this score" panel is exact rather than an attribution scheme we
invented. Because the total is a sum of per-factor terms, each term *is* that
factor's Shapley value.

Detection accumulates separately and is never folded into success. They answer
different questions — will this work, and will anyone notice — and a path with
high success and high detectability is a different problem from one with
moderate success and none.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from core.model import (
    Edge,
    Hop,
    Node,
    RiskTier,
    ScoreFactor,
    ScoringConfig,
    ScoringModifier,
)
from engine.preconditions import MISSING, compare, read_attr

#: Node kind whose EPSS score replaces the technique baseline. ``docs/RULES.md``
#: R12 is explicit that an exploit's probability is "derived from the
#: vulnerability's EPSS score, not a constant": EPSS estimates the probability of
#: exploitation in the wild, which is the likelihood axis, while CVSS measures
#: severity, which belongs to impact. Using CVSS as a probability is a category
#: error that inflates severe-but-unexploited weaknesses and buries the mundane
#: ones actually being used. Keyed on the target's kind rather than on a list of
#: technique codes, because any hop whose target is a vulnerability is by
#: construction an exploit.
VULNERABILITY_KIND = "Vulnerability"
EPSS_ATTR = "epss"


class ScoringError(ValueError):
    """A scoring configuration that cannot produce a reportable score."""


@dataclass(frozen=True, slots=True)
class HopScore:
    p_succ: float
    detectability: float
    neg_log_contribution: float
    factors: tuple[ScoreFactor, ...]
    blocked_by: ScoringModifier | None = None
    """Set when a hard-block modifier fired, which refuses the hop outright.

    Phishing-resistant MFA against credential replay is the canonical case, and
    it is a block rather than a penalty because replay genuinely cannot defeat
    it. Modelling it as a smooth multiplier would quietly report attacks that
    cannot happen — and would simultaneously understate SMS and push, which fall
    to relay and fatigue routinely. One multiplier cannot represent both.
    """


@dataclass(frozen=True, slots=True)
class PathScore:
    p_success: float
    neg_log_success: float
    p_undetected: float
    neg_log_undetected: float
    bottleneck_p: float
    bottleneck_hop: int
    impact_score: float
    risk_score: float
    risk_tier: RiskTier
    impact_factors: tuple[ScoreFactor, ...]


class Scorer:
    """Scores one hop, then one path, against a fixed scoring configuration."""

    __slots__ = ("config", "_modifiers")

    def __init__(self, config: ScoringConfig) -> None:
        if not config.baselines:
            raise ScoringError(f"scoring config {config.version} has no baselines")
        if not config.tiers:
            raise ScoringError(f"scoring config {config.version} has no risk tiers")
        if not 0.0 < config.p_clamp_min < config.p_clamp_max < 1.0:
            raise ScoringError(
                f"scoring config {config.version} clamp bounds must satisfy "
                f"0 < min < max < 1, got [{config.p_clamp_min}, {config.p_clamp_max}]"
            )
        if config.raw_max <= 0:
            raise ScoringError(f"scoring config {config.version} raw_max must be positive")
        self.config = config
        self._modifiers = config.modifiers

    def score_hop(
        self,
        *,
        technique_code: str,
        src_node: Node | None,
        dst_node: Node | None,
        edge: Edge | None,
    ) -> HopScore:
        config = self.config
        baseline = config.baselines.get(technique_code)
        if baseline is None:
            raise ScoringError(
                f"no baseline for technique {technique_code!r} under scoring version "
                f"{config.version}; every hop must be scorable or the path total is a guess"
            )

        p_base, d_base = baseline
        baseline_code, baseline_label = technique_code, "Technique baseline"
        observed: str | None = None

        epss = _epss(dst_node)
        if epss is not None:
            p_base = epss
            baseline_code = f"epss:{technique_code}"
            baseline_label = "EPSS exploitation probability"
            observed = repr(round(epss, 9))

        # Both accumulators are carried in log-odds and clamped only on the way
        # out. Clamping the running probability after every modifier would make
        # the result depend on the order the betas were applied in — a large
        # negative beta would pin the value to the floor and a later positive one
        # would lift it back off, so the total would no longer be `Σβ` and the
        # per-factor attribution would stop being exact. `docs/RULES.md` §6 puts
        # the clamp after the sum for that reason.
        logit_succ = _logit(self._clamp(p_base))
        logit_detect = _logit(self._clamp(d_base))

        factors: list[ScoreFactor] = [
            ScoreFactor(
                seq=1,
                factor_kind="baseline",
                factor_code=baseline_code,
                factor_label=baseline_label,
                observed_value=observed,
                beta=None,
                p_after=self._clamp(p_base),
            )
        ]

        seq = 1
        for modifier in self._modifiers:
            if modifier.technique_scope and technique_code not in modifier.technique_scope:
                continue
            value = _observed_for(modifier, src_node, dst_node, edge)
            if not compare(modifier.operator, value, modifier.value):
                continue

            rendered = None if value is MISSING else _render(value)
            if modifier.is_hard_block:
                p_succ = self._clamp(_expit(logit_succ))
                return HopScore(
                    p_succ=p_succ,
                    detectability=self._clamp(_expit(logit_detect)),
                    neg_log_contribution=-math.log(p_succ),
                    factors=tuple(factors),
                    blocked_by=modifier,
                )

            seq += 1
            if modifier.target == "detectability":
                logit_detect += float(modifier.beta)
                running = logit_detect
            else:
                logit_succ += float(modifier.beta)
                running = logit_succ
            factors.append(
                ScoreFactor(
                    seq=seq,
                    factor_kind="modifier",
                    factor_code=modifier.code,
                    factor_label=modifier.label,
                    observed_value=rendered,
                    beta=modifier.beta,
                    # p_after tracks whichever accumulator this factor moved, so
                    # a reader can follow one column down the breakdown and see
                    # the running value rather than having to recompute it. It is
                    # clamped for display only; the accumulator above is not.
                    p_after=self._clamp(_expit(running)),
                )
            )

        p_succ = self._clamp(_expit(logit_succ))
        return HopScore(
            p_succ=p_succ,
            detectability=self._clamp(_expit(logit_detect)),
            neg_log_contribution=-math.log(p_succ),
            factors=tuple(factors),
        )

    def score_path(self, hops: Sequence[Hop], target: Node) -> PathScore:
        if not hops:
            raise ScoringError("a path with no hops has no probability")

        config = self.config
        neg_log_success = math.fsum(hop.neg_log_contribution for hop in hops)
        neg_log_undetected = math.fsum(
            -math.log(1.0 - hop.detectability) for hop in hops
        )

        bottleneck = min(hops, key=lambda hop: (hop.p_succ, hop.hop_no))
        impact_score, impact_factors = self._impact(target, len(hops))

        likelihood = 1.0 - min(neg_log_success / config.raw_max, 1.0)
        stealth = 1.0 - min(neg_log_undetected / config.raw_max, 1.0)
        raw = (
            config.w_likelihood * likelihood
            + config.w_impact * impact_score
            + config.w_stealth * stealth
        )
        # Rounded before the tier lookup, not after: the tiers are stored as
        # two-decimal bands (0.00-0.99, 1.00-3.99, ...) so an unrounded 8.995
        # would fall between two bands and match none of them.
        risk_score = round(10.0 * min(max(raw, 0.0), 1.0), 2)

        return PathScore(
            p_success=math.exp(-neg_log_success),
            neg_log_success=neg_log_success,
            p_undetected=math.exp(-neg_log_undetected),
            neg_log_undetected=neg_log_undetected,
            bottleneck_p=bottleneck.p_succ,
            bottleneck_hop=bottleneck.hop_no,
            impact_score=impact_score,
            risk_score=risk_score,
            risk_tier=config.tier_for(risk_score),
            impact_factors=impact_factors,
        )

    def _impact(self, target: Node, hop_count: int) -> tuple[float, tuple[ScoreFactor, ...]]:
        """The target's impact weight, as the strongest dimension that applies.

        The maximum rather than a mean, because ``crown_jewel: false`` is stored
        as weight 0.0. Averaged in, that would drag every non-crown-jewel target
        down by a third of the axis and cap a crown jewel below 1.0 — the row is
        only meaningful as a floor under a maximum. Read the three dimensions as
        three claims about the same target, and the impact is the strongest claim
        that holds.
        """
        weights = self.config.impact_weights
        candidates = [
            ("crown_jewel", "true" if target.is_crown_jewel else "false"),
            ("criticality", target.criticality),
            ("classification", target.classification),
        ]

        factors: list[ScoreFactor] = []
        impact = 0.0
        # Impact is a property of the target, which is where the final hop
        # arrives, so its factors are recorded against that hop. The factor rows
        # are keyed by hop, and a score component with no hop would be invisible
        # to the breakdown that has to account for the whole number.
        seq = 0
        for dimension, code in candidates:
            if not code:
                continue
            weight = weights.get((dimension, str(code)))
            if weight is None:
                continue
            impact = max(impact, float(weight))
            seq += 1
            factors.append(
                ScoreFactor(
                    seq=seq,
                    factor_kind="impact",
                    factor_code=f"{dimension}:{code}",
                    factor_label=f"Target {dimension.replace('_', ' ')}: {code}",
                    observed_value=str(code),
                    beta=None,
                    p_after=float(weight),
                )
            )
        return impact, tuple(factors)

    def _clamp(self, p: float) -> float:
        return min(max(float(p), self.config.p_clamp_min), self.config.p_clamp_max)


# ── Configuration loading ────────────────────────────────────────────────────


def build_scoring_config(
    *,
    config_row: Mapping[str, Any],
    baseline_rows: Iterable[Mapping[str, Any]],
    modifier_rows: Iterable[Mapping[str, Any]],
    scope_rows: Iterable[Mapping[str, Any]],
    impact_rows: Iterable[Mapping[str, Any]],
    tier_rows: Iterable[Mapping[str, Any]],
) -> ScoringConfig:
    from engine.rules import decode_json

    scopes: dict[str, set[str]] = {}
    for row in scope_rows:
        scopes.setdefault(str(row["modifier_code"]), set()).add(
            str(row["technique_code"])
        )

    modifiers = tuple(
        ScoringModifier(
            code=str(row["code"]),
            label=str(row.get("label") or row["code"]),
            applies_to=str(row["applies_to"]),
            attr_path=str(row["attr_path"]),
            operator=str(row["operator"]),
            value=decode_json(row.get("value_json")),
            target=str(row.get("target") or "p_succ"),
            beta=float(row["beta"]),
            is_hard_block=bool(int(row.get("is_hard_block") or 0)),
            technique_scope=frozenset(scopes.get(str(row["code"]), ())),
        )
        # Modifier order is part of the output: the factor rows are numbered in
        # application order, and log-odds addition commutes so only the reported
        # sequence depends on it. Sorted explicitly rather than left to the
        # query, so two runs number the breakdown identically.
        for row in sorted(
            modifier_rows,
            key=lambda r: (int(r.get("sort_order") or 0), str(r["code"])),
        )
    )

    tiers = tuple(
        RiskTier(
            code=str(row["code"]),
            label=str(row.get("label") or row["code"]),
            min_score=float(row["min_score"]),
            max_score=float(row["max_score"]),
            ui_color=str(row.get("ui_color") or ""),
            ui_bg_color=str(row.get("ui_bg_color") or ""),
            action_text=str(row.get("action_text") or ""),
        )
        for row in sorted(
            tier_rows, key=lambda r: (int(r.get("sort_order") or 0), str(r["code"]))
        )
    )

    return ScoringConfig(
        version=str(config_row["version"]),
        label=str(config_row.get("label") or config_row["version"]),
        p_clamp_min=float(config_row["p_clamp_min"]),
        p_clamp_max=float(config_row["p_clamp_max"]),
        raw_max=float(config_row["raw_max"]),
        w_likelihood=float(config_row["w_likelihood"]),
        w_impact=float(config_row["w_impact"]),
        w_stealth=float(config_row["w_stealth"]),
        baselines={
            str(row["technique_code"]): (
                float(row["base_p_succ"]),
                float(row["base_detectability"]),
            )
            for row in baseline_rows
        },
        modifiers=modifiers,
        impact_weights={
            (str(row["dimension"]), str(row["code"])): float(row["weight"])
            for row in impact_rows
        },
        tiers=tiers,
    )


def load_scoring_config(version: str | None = None) -> ScoringConfig:
    """Read the active scoring configuration out of MySQL."""
    from app.db import fetch_all, fetch_one

    if version:
        config_row = fetch_one(
            "SELECT version, label, p_clamp_min, p_clamp_max, raw_max, w_likelihood, "
            "w_impact, w_stealth FROM scoring_config WHERE version = :v",
            {"v": version},
        )
    else:
        config_row = fetch_one(
            "SELECT version, label, p_clamp_min, p_clamp_max, raw_max, w_likelihood, "
            "w_impact, w_stealth FROM scoring_config WHERE is_active = 1"
        )
    if not config_row:
        raise ScoringError(
            f"no scoring config {version or '(active)'}; run the seed migrations"
        )

    resolved = str(config_row["version"])
    params = {"v": resolved}
    return build_scoring_config(
        config_row=config_row,
        baseline_rows=fetch_all(
            "SELECT technique_code, base_p_succ, base_detectability "
            "FROM technique_baseline WHERE scoring_version = :v",
            params,
        ),
        modifier_rows=fetch_all(
            "SELECT code, label, applies_to, attr_path, operator, value_json, target, "
            "beta, is_hard_block, sort_order FROM scoring_modifier "
            "WHERE scoring_version = :v",
            params,
        ),
        scope_rows=fetch_all(
            "SELECT modifier_code, technique_code FROM scoring_modifier_scope "
            "WHERE scoring_version = :v",
            params,
        ),
        impact_rows=fetch_all(
            "SELECT dimension, code, weight FROM impact_weight WHERE scoring_version = :v",
            params,
        ),
        tier_rows=fetch_all(
            "SELECT code, label, min_score, max_score, ui_color, ui_bg_color, "
            "action_text, sort_order FROM risk_tier WHERE scoring_version = :v",
            params,
        ),
    )


def _observed_for(
    modifier: ScoringModifier,
    src_node: Node | None,
    dst_node: Node | None,
    edge: Edge | None,
) -> Any:
    if modifier.applies_to == "edge":
        return read_attr(edge.attrs if edge is not None else None, modifier.attr_path)
    node = src_node if modifier.applies_to == "src_node" else dst_node
    return read_attr(node.attrs if node is not None else None, modifier.attr_path)


def _epss(dst_node: Node | None) -> float | None:
    if dst_node is None or dst_node.kind != VULNERABILITY_KIND:
        return None
    raw = read_attr(dst_node.attrs, EPSS_ATTR)
    if raw is MISSING or isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    value = float(raw)
    return value if 0.0 < value <= 1.0 else None


def _logit(p: float) -> float:
    return math.log(p / (1.0 - p))


def _expit(x: float) -> float:
    # Written in the numerically stable direction for each sign so a large beta
    # overflows to the clamp rather than raising.
    if x >= 0.0:
        return 1.0 / (1.0 + math.exp(-x)) if x < 709.0 else 1.0
    if x <= -709.0:
        return 0.0
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


def _render(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return repr(round(value, 9))
    return str(value)[:255]
