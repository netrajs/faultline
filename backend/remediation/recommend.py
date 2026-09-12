"""Turning cut candidates into ranked, costed recommendations.

Three things happen here, and each is deliberately separable.

**Applicability is derived from the graph, not asserted.** A fix that writes an
attribute is offered only where the target already records that attribute and
records a different value — so ``rotate_credential``, which resets
``age_days``, is simply not offered on a graph whose credentials do not record
an age, rather than being offered as a change that would do nothing. That rule
covers three of the four mutation kinds outright. ``remove_edge`` is the one the
schema cannot answer on its own, and the single association below says why.

**Estimates and measurements are different numbers.** A recommendation reaches
the interface with ``is_measured = 0`` and an estimate from the chokepoint pass:
*if removing this target removes exactly the paths through it, this is what is
left.* That is an assumption, and it is a good one for a removal and a weaker
one for an attribute change, which is exactly why simulation exists to replace
it. The column keeps the two apart so the interface never shows one as the
other.

**Dependencies are only what the graph can actually show.** Every row in
``recommendation_dependency`` traces to edges that are in the graph: other
principals holding the credential being revoked, the permissions a group
membership was conferring, the assets a credential authenticates to. No row is
produced by guessing at an organisation's operational reality, and a fix with
nothing derivable gets an empty list — which is honest, and is more useful than
a plausible warning nobody can check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from core.model import Edge, GraphSnapshot, Node

from remediation.chokepoints import ChokepointAnalysis, PathCoverage, analyse
from remediation.overlay import MutationError
from remediation.store import DependencyRow, FixType, RecommendationRow

#: Which edge types each edge-removal fix is about.
#:
#: Everything else a fix needs — the mutation kind, the attribute it writes, its
#: effort and disruption, whether it needs an approval — is a column on
#: ``fix_type`` and is read from there. This is the one association the table has
#: no column for: three fixes share ``mutation_kind = 'remove_edge'`` and are
#: distinguished only by which relationship they remove. Encoded here rather
#: than inferred from the description text, and it belongs in a
#: ``fix_type_scope`` table the first time a fourth removal fix is added.
_REMOVE_EDGE_SCOPE: Mapping[str, frozenset[str]] = {
    "remove_exposure": frozenset({"EXPOSES_CREDENTIAL"}),
    "remove_membership": frozenset({"MEMBER_OF"}),
    "segment_network": frozenset({"TRUSTS", "CONNECTED_TO"}),
}

#: Edge types that carry a grant worth naming when it is about to be removed.
_GRANT_EDGE_TYPES = frozenset(
    {"HAS_PERMISSION", "ADMIN_TO", "HAS_ACCESS_TO", "AUTHENTICATES_TO"}
)

#: Weights of the priority formula. The two benefit weights sum to 1.0, which is
#: what keeps ``priority_score`` inside 0-100 and makes two recommendations from
#: different runs comparable.
#:
#: Coverage carries more weight than the risk drop because coverage is the
#: quantity the set-cover selection is actually optimising and the quantity a
#: simulation can measure exactly, while a drop in the *maximum* path risk is a
#: coarser signal — a fix can remove nine of thirteen paths and leave the
#: highest-scoring one standing, which is worth knowing but is not worth as much
#: as the nine.
COVERAGE_WEIGHT = 0.6
RISK_WEIGHT = 0.4

#: Cost weights. Disruption counts double against effort on the grounds that an
#: afternoon of somebody's time is recoverable and an outage is not.
EFFORT_WEIGHT = 1.0
DISRUPTION_WEIGHT = 2.0

#: The 0-10 display scale risk scores are already normalised onto (D3).
RISK_SCALE = 10.0


@dataclass(frozen=True, slots=True)
class Estimate:
    """What the chokepoint pass predicts for one target, before simulation."""

    paths_eliminated: int
    coverage: float
    risk_before: float
    risk_after: float


def priority_score(
    *,
    coverage: float,
    risk_before: float,
    risk_after: float,
    effort_value: float,
    disruption_value: float,
    max_effort: float,
    max_disruption: float,
) -> float:
    """Benefit over cost, on a 0-100 scale.

        benefit = 0.6 * (paths eliminated / paths total)
                + 0.4 * (risk drop / 10)
        cost    = 1 + (effort / worst effort) + 2 * (disruption / worst disruption)
        score   = 100 * benefit / cost

    Both cost terms are normalised against the worst value present in
    ``fix_type``, so retuning what "manual" costs in the table reorders the
    ranking without touching this function — which is the reason those columns
    are data in the first place.

    The ``1 +`` in the denominator is what keeps a free, zero-disruption fix from
    dividing by zero and scoring infinitely; it also means the cost term only
    ever discounts a benefit, never inverts the sign of one.
    """
    benefit = COVERAGE_WEIGHT * _clamp01(coverage) + RISK_WEIGHT * _clamp01(
        max(0.0, risk_before - risk_after) / RISK_SCALE
    )
    effort_norm = effort_value / max_effort if max_effort > 0 else 0.0
    disruption_norm = disruption_value / max_disruption if max_disruption > 0 else 0.0
    cost = 1.0 + EFFORT_WEIGHT * effort_norm + DISRUPTION_WEIGHT * disruption_norm
    return 100.0 * benefit / cost


def estimate_for(
    covered: frozenset[str],
    paths: Sequence[PathCoverage],
) -> Estimate:
    """What is left if exactly the covered paths go away.

    ``risk_after`` is the highest risk among the paths that remain, which is the
    same quantity ``analysis_run.max_risk_score`` reports, so before and after
    are the same measurement taken twice rather than two different ones
    compared.
    """
    total = len(paths)
    risk_before = max((p.risk_score for p in paths), default=0.0)
    remaining = [p.risk_score for p in paths if p.path_id not in covered]
    return Estimate(
        paths_eliminated=len(covered),
        coverage=(len(covered) / total) if total else 0.0,
        risk_before=risk_before,
        risk_after=max(remaining, default=0.0),
    )


def applicable_fixes(
    snapshot: GraphSnapshot,
    target_kind: str,
    target_id: str,
    fix_types: Mapping[str, FixType],
) -> list[FixType]:
    """The fixes that would actually change this target.

    A fix whose mutation would write a value the target already holds is not
    offered: it would produce a simulation with an empty delta and an apply step
    that changed nothing, both of which look like a broken engine rather than a
    fix that was never applicable.
    """
    if target_kind == "edge":
        try:
            edge = snapshot.edge(target_id)
        except KeyError:
            return []
        return [
            fix
            for fix in sorted(fix_types.values(), key=lambda f: f.sort_order)
            if _applies_to_edge(fix, edge)
        ]

    node = snapshot.get_node(target_id)
    if node is None:
        return []
    return [
        fix
        for fix in sorted(fix_types.values(), key=lambda f: f.sort_order)
        if _applies_to_node(fix, node)
    ]


def _applies_to_edge(fix: FixType, edge: Edge) -> bool:
    if fix.mutation_kind == "remove_edge":
        return edge.edge_type in _REMOVE_EDGE_SCOPE.get(fix.code, frozenset())
    if fix.mutation_kind != "set_edge_attr" or not fix.mutation_target_attr:
        return False
    attr = fix.mutation_target_attr
    return attr in edge.attrs and edge.attrs[attr] != fix.mutation_value


def _applies_to_node(fix: FixType, node: Node) -> bool:
    if fix.mutation_kind == "remove_node":
        # Deleting the asset being protected is not a remediation of the risk
        # to it.
        return not node.is_crown_jewel
    if fix.mutation_kind != "set_node_attr" or not fix.mutation_target_attr:
        return False
    attr = fix.mutation_target_attr
    return attr in node.attrs and node.attrs[attr] != fix.mutation_value


# ── Dependency analysis ──────────────────────────────────────────────────────


def dependencies_for(
    snapshot: GraphSnapshot,
    fix: FixType,
    target_kind: str,
    target_id: str,
) -> tuple[DependencyRow, ...]:
    """Collateral this fix would cause, as far as the graph can show it."""
    if target_kind == "edge":
        try:
            edge = snapshot.edge(target_id)
        except KeyError:
            return ()
        return _edge_dependencies(snapshot, fix, edge)

    node = snapshot.get_node(target_id)
    if node is None:
        return ()
    return _node_dependencies(snapshot, fix, node)


def _edge_dependencies(
    snapshot: GraphSnapshot, fix: FixType, edge: Edge
) -> tuple[DependencyRow, ...]:
    rows: list[DependencyRow] = []
    src = snapshot.get_node(edge.src_id)
    dst = snapshot.get_node(edge.dst_id)
    src_name = _name(src, edge.src_id)
    dst_name = _name(dst, edge.dst_id)

    if fix.mutation_kind == "remove_edge":
        rows.append(
            DependencyRow(
                kind="access_lost",
                affected_node_id=edge.dst_id,
                description=(
                    f"{src_name} loses its {edge.edge_type} relationship to "
                    f"{dst_name}. Anything it does through that relationship "
                    "stops working."
                ),
                severity="warning",
            )
        )
        # A group membership is worth expanding: the membership itself grants
        # nothing, so what is actually lost is whatever the group confers.
        if edge.edge_type == "MEMBER_OF":
            for grant in snapshot.out_edges(edge.dst_id):
                if grant.edge_type not in _GRANT_EDGE_TYPES:
                    continue
                level = grant.attrs.get("permission_level")
                asset = _name(snapshot.get_node(grant.dst_id), grant.dst_id)
                rows.append(
                    DependencyRow(
                        kind="access_lost",
                        affected_node_id=grant.dst_id,
                        description=(
                            f"{src_name} also loses the "
                            f"{level or grant.edge_type.lower().replace('_', ' ')} "
                            f"access {dst_name} confers on {asset}."
                        ),
                        severity="warning",
                    )
                )

    if fix.code == "enforce_mfa":
        # The principal behind an AUTHENTICATES_TO edge is whoever holds the
        # credential at its source. A non-interactive identity has nobody to
        # present a hardware factor, so requiring one locks it out rather than
        # hardening it.
        for holder_edge in snapshot.in_edges(edge.src_id):
            if holder_edge.edge_type != "HAS_CREDENTIAL":
                continue
            holder = snapshot.get_node(holder_edge.src_id)
            if holder is None or holder.attrs.get("is_interactive") is not False:
                continue
            rows.append(
                DependencyRow(
                    kind="policy_conflict",
                    affected_node_id=holder.node_id,
                    description=(
                        f"{_name(holder, holder.node_id)} is non-interactive, so "
                        "there is no person present to produce a hardware factor. "
                        "Requiring one here stops the account authenticating at all."
                    ),
                    severity="blocking",
                )
            )

    if fix.code == "least_privilege":
        rows.append(
            DependencyRow(
                kind="access_lost",
                affected_node_id=edge.dst_id,
                description=(
                    f"{src_name} drops from "
                    f"{edge.attrs.get('permission_level', 'its current level')} to "
                    f"{fix.mutation_value} on {dst_name}. Any write or "
                    "administrative task it performs there will fail."
                ),
                severity="warning",
            )
        )
    return tuple(rows)


def _node_dependencies(
    snapshot: GraphSnapshot, fix: FixType, node: Node
) -> tuple[DependencyRow, ...]:
    rows: list[DependencyRow] = []
    node_name = _name(node, node.node_id)

    if node.kind == "Credential":
        holders = [
            e.src_id
            for e in snapshot.in_edges(node.node_id)
            if e.edge_type == "HAS_CREDENTIAL"
        ]
        exposures = [
            e.src_id
            for e in snapshot.in_edges(node.node_id)
            if e.edge_type == "EXPOSES_CREDENTIAL"
        ]
        for holder_id in sorted(holders):
            holder = snapshot.get_node(holder_id)
            others = [
                e.dst_id
                for e in snapshot.out_edges(holder_id)
                if e.edge_type == "HAS_CREDENTIAL" and e.dst_id != node.node_id
            ]
            if not others:
                rows.append(
                    DependencyRow(
                        kind="access_lost",
                        affected_node_id=holder_id,
                        description=(
                            f"{_name(holder, holder_id)} holds no other credential, "
                            f"so changing {node_name} leaves it with no way to "
                            "authenticate until a replacement is issued."
                        ),
                        severity="blocking" if fix.code == "revoke_credential" else "warning",
                    )
                )
            else:
                rows.append(
                    DependencyRow(
                        kind="shared_credential",
                        affected_node_id=holder_id,
                        description=(
                            f"{_name(holder, holder_id)} holds this credential and "
                            f"{len(others)} other(s); it will need to pick up the "
                            "replacement."
                        ),
                        severity="warning",
                    )
                )
        if len(holders) > 1:
            rows.append(
                DependencyRow(
                    kind="shared_credential",
                    affected_node_id=None,
                    description=(
                        f"{len(holders)} identities hold {node_name}. All of them "
                        "are affected at the same moment, so the change needs to be "
                        "coordinated rather than applied to one of them."
                    ),
                    severity="blocking",
                )
            )
        for exposure_id in sorted(exposures):
            rows.append(
                DependencyRow(
                    kind="shared_credential",
                    affected_node_id=exposure_id,
                    description=(
                        f"{_name(snapshot.get_node(exposure_id), exposure_id)} still "
                        f"exposes a copy of {node_name}. Changing the credential "
                        "without clearing that copy leaves the exposure in place."
                    ),
                    severity="warning",
                )
            )
        for served in snapshot.out_edges(node.node_id):
            if served.edge_type != "AUTHENTICATES_TO":
                continue
            rows.append(
                DependencyRow(
                    kind="downstream_service",
                    affected_node_id=served.dst_id,
                    description=(
                        f"{node_name} authenticates to "
                        f"{_name(snapshot.get_node(served.dst_id), served.dst_id)}. "
                        "Every legitimate session that uses it there breaks."
                    ),
                    severity="warning",
                )
            )

    if fix.code == "disable_account":
        for grant in snapshot.out_edges(node.node_id):
            if grant.edge_type not in _GRANT_EDGE_TYPES:
                continue
            rows.append(
                DependencyRow(
                    kind="downstream_service",
                    affected_node_id=grant.dst_id,
                    description=(
                        f"{node_name} currently reaches "
                        f"{_name(snapshot.get_node(grant.dst_id), grant.dst_id)} "
                        f"via {grant.edge_type}. Disabling the account removes that."
                    ),
                    severity="warning",
                )
            )

    if fix.code == "patch_vulnerability":
        vulnerabilities = [
            e.dst_id
            for e in snapshot.out_edges(node.node_id)
            if e.edge_type == "HAS_VULNERABILITY"
        ]
        if vulnerabilities:
            rows.append(
                DependencyRow(
                    kind="downstream_service",
                    affected_node_id=node.node_id,
                    description=(
                        f"{node_name} carries {len(vulnerabilities)} recorded "
                        "weakness(es); bringing it current means a maintenance "
                        "window on the asset itself."
                    ),
                    severity="info",
                )
            )
    return tuple(rows)


# ── Assembly ─────────────────────────────────────────────────────────────────


def recommend(
    snapshot: GraphSnapshot,
    paths: Sequence[PathCoverage],
    fix_types: Mapping[str, FixType],
    *,
    limit: int = 20,
) -> tuple[tuple[RecommendationRow, ...], ChokepointAnalysis]:
    """Rank the chokepoints, cost them, and describe their collateral."""
    analysis = analyse(paths, limit=limit)
    if not paths:
        return (), analysis

    max_effort = max((f.effort_value for f in fix_types.values()), default=0.0)
    max_disruption = max((f.disruption_value for f in fix_types.values()), default=0.0)
    total = len(paths)

    rows: list[RecommendationRow] = []
    for chokepoint in analysis.chokepoints:
        covered = analysis.candidates.get(
            (chokepoint.kind, chokepoint.target_id), frozenset()
        )
        estimate = estimate_for(covered, paths)
        for fix in applicable_fixes(
            snapshot, chokepoint.kind, chokepoint.target_id, fix_types
        ):
            try:
                fix.mutation_for(chokepoint.kind, chokepoint.target_id)
            except MutationError:
                # A fix row whose mutation cannot be constructed for this target
                # is a data problem, not a candidate. Skipped rather than
                # raised, so one malformed row does not take the whole ranking
                # down with it.
                continue
            score = priority_score(
                coverage=estimate.coverage,
                risk_before=estimate.risk_before,
                risk_after=estimate.risk_after,
                effort_value=fix.effort_value,
                disruption_value=fix.disruption_value,
                max_effort=max_effort,
                max_disruption=max_disruption,
            )
            rows.append(
                RecommendationRow(
                    fix_type_code=fix.code,
                    target_kind=chokepoint.kind,
                    target_id=chokepoint.target_id,
                    title=_title(snapshot, fix, chokepoint.kind, chokepoint.target_id),
                    rationale=_rationale(fix, chokepoint.rank_in_run, estimate, total),
                    risk_before=estimate.risk_before,
                    risk_after=estimate.risk_after,
                    paths_eliminated=estimate.paths_eliminated,
                    total_paths=total,
                    path_coverage=estimate.coverage,
                    effort_value=fix.effort_value,
                    disruption_value=fix.disruption_value,
                    priority_score=score,
                    is_measured=False,
                    dependencies=dependencies_for(
                        snapshot, fix, chokepoint.kind, chokepoint.target_id
                    ),
                )
            )

    rows.sort(key=lambda r: (-(r.priority_score or 0.0), r.fix_type_code, r.target_id))
    return tuple(rows), analysis


def _title(
    snapshot: GraphSnapshot, fix: FixType, target_kind: str, target_id: str
) -> str:
    if target_kind == "edge":
        try:
            edge = snapshot.edge(target_id)
        except KeyError:
            return f"{fix.label} on {target_id}"
        src = _name(snapshot.get_node(edge.src_id), edge.src_id)
        dst = _name(snapshot.get_node(edge.dst_id), edge.dst_id)
        return f"{fix.label}: {src} -> {dst}"
    return f"{fix.label}: {_name(snapshot.get_node(target_id), target_id)}"


def _rationale(
    fix: FixType, rank: int, estimate: Estimate, total: int
) -> str:
    defends = f" Defends with D3FEND {fix.d3fend_id}." if fix.d3fend_id else ""
    return (
        f"{fix.description} This target is chokepoint #{rank} for the run: it sits "
        f"on {estimate.paths_eliminated} of {total} discovered paths "
        f"({estimate.coverage * 100:.0f}%). If those paths go, the highest "
        f"remaining risk score is {estimate.risk_after:.2f}, down from "
        f"{estimate.risk_before:.2f}. Effort {fix.effort_label.lower()}, "
        f"disruption {fix.disruption_label.lower()}. That is an estimate from the "
        "coverage pass, not a measurement — simulate it to replace these numbers "
        f"with re-derived ones.{defends}"
    )


def _name(node: Node | None, fallback: str) -> str:
    if node is None:
        return fallback
    return node.display_name or node.name or fallback


def _clamp01(value: float) -> float:
    return min(max(value, 0.0), 1.0)
