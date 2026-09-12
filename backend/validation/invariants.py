"""The ten invariants of ``docs/RULES.md`` §7, as executable properties.

§7 opens by saying these hold "for any graph and any threat model", and that a
violation is a bug in the engine rather than in the test. That phrasing is what
makes them properties rather than examples: the right way to check a claim
quantified over every graph is to keep handing it graphs it has not seen.

**Where the graphs come from.** ``validation/world.py`` already builds the
perturbable world the differential harness uses -- a four-hop chain through a
security group, an administrative permission, an exposed credential and a
crown-jewel database, sharing its graph with a mailing list, a disabled account,
a vaulted credential and a strong-password service account that must all stay
refused. This module perturbs it: remove some subset of its edges, harden some
subset of its attributes, and assert that the answer only ever moves in the
direction §7 says it can. ``backend/tests/validation/test_invariants.py`` draws
those subsets with Hypothesis, which shrinks a counterexample to the smallest
graph that still fails; the API endpoint runs a fixed, ordered set of them
instead, so a request finishes in a few seconds and two requests agree.

**What a check is allowed to use.** The point of a property test on a search is
that it cannot be satisfied by the search's own bookkeeping, so where an
independent implementation exists it is the one used. Invariant 5 re-derives
each hop with ``oracle.search.verify_path``, not the engine's own
``verify_path``; invariant 8 is the differential comparison and delegates to
``validation/differential.py`` rather than opening a second one; invariant 9
re-evaluates the refused precondition with ``oracle.preconditions``. The
metamorphic invariants (1, 2, 3, 4, 7) need no second implementation because
they compare the engine against itself under a change whose direction the
specification fixes in advance.

**What is not covered, and why.** Invariant 7 is stated over remediation: blast
radius after applying a fix is a subset of blast radius before, *unless the fix
is one whose simulation predicted additions*. What is checked here is the
edge-removal class of fixes, where no addition can be predicted because nothing
is added -- removing an edge cannot create a capability. The exception clause is
about fixes that rewrite attributes, and checking it needs the simulation's own
prediction to compare against, which belongs with the simulator and not here.
Each outcome says which form of the invariant it checked, so nobody reads a
green row as more than it is.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from core.ids import canonical_json
from core.model import GraphSnapshot
from engine.blast_radius import BlastLimits, BlastRadius, BlastRadiusError
from engine.scoring import Scorer
from engine.search import Discovery, DiscoveryResult, SearchLimits
from oracle.preconditions import evaluate_precondition
from oracle.search import materialise_grants, verify_path
from validation.differential import run_snapshot_case
from validation.world import (
    CHAIN_EDGE_IDS,
    ModelSource,
    chain_snapshot,
    load_model,
    scoring_with_baseline,
)

__all__ = [
    "DEFAULT_PERTURBATIONS",
    "HARDENINGS",
    "Harness",
    "INVARIANTS",
    "Invariant",
    "InvariantOutcome",
    "InvariantReport",
    "Perturbation",
    "RAISED_TECHNIQUES",
    "invariant",
    "run_suite",
]

#: The threat model every check runs under. ``external_phish`` is the one the
#: perturbable world was built for: it enters at a user, which is where the
#: four-hop chain starts.
THREAT_MODEL = "external_phish"

#: Deep enough for the four-hop chain plus the two-hop kerberoast branch, with
#: room for a longer route to appear when a shorter one is removed -- which is
#: the case invariant 1 would otherwise never see.
MAX_HOPS = 6

#: Above the number of distinct paths this world contains, so the k-best
#: allowance never decides whether a path was reported. A truncated result would
#: show up as a monotonicity violation that is really a display budget.
TOP_K = 8

#: Where the blast-radius form of invariant 7 starts from: the entry the whole
#: world is built around.
BLAST_ORIGIN = "u-1"


@dataclass(frozen=True, slots=True)
class Perturbation:
    """One change to the world, and what it is a change *of*.

    Removals and hardenings are kept apart rather than merged into one "change"
    because §7 states them as two separate invariants against two separate
    causes, and an outcome that could not say which of the two it had applied
    would not be checking either.
    """

    label: str
    drop_edges: tuple[str, ...] = ()
    edge_attrs: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    node_attrs: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    @property
    def removes(self) -> bool:
        return bool(self.drop_edges)

    @property
    def hardens(self) -> bool:
        return bool(self.edge_attrs or self.node_attrs)

    def snapshot(self) -> GraphSnapshot:
        return chain_snapshot(
            drop_edges=self.drop_edges,
            edge_attrs=self.edge_attrs,
            node_attrs=self.node_attrs,
        )

    @property
    def key(self) -> str:
        """Content identity, and deliberately not the label.

        Two perturbations can carry the same human-readable label and describe
        different graphs -- a generated one naming its removals but not its
        hardenings, for instance. Keying a cache on the label would then serve
        one graph's result for another's, and the symptom is an invariant
        failing against a snapshot it was never run on.
        """
        return canonical_json(
            {
                "drop_edges": sorted(self.drop_edges),
                "edge_attrs": {k: dict(v) for k, v in self.edge_attrs.items()},
                "node_attrs": {k: dict(v) for k, v in self.node_attrs.items()},
            }
        )


#: Attribute changes that are hard blocks under ``docs/RULES.md`` §4 -- each one
#: is the deciding attribute of a decoy pattern in ``005_ground_truth`` and each
#: can only take an attack away. A "hardening" that merely changed a number
#: would not be testing invariant 3.
HARDENINGS: tuple[tuple[str, str, str, Mapping[str, Any]], ...] = (
    ("phishing-resistant second factor", "edge", "e-auth-1", {"mfa_required": True, "mfa_type": "fido2"}),
    ("device compliance required", "edge", "e-auth-1", {"requires_compliant_device": True}),
    ("permission downgraded to read-only", "edge", "e-perm-1", {"permission_level": "read_only"}),
    ("credential moved into a vault", "node", "cred-1", {"storage": "vault"}),
    ("credential rotated", "node", "cred-1", {"is_active": False}),
    ("host patched", "node", "h-1", {"patch_level": "current"}),
    ("security group made a mailing list", "node", "g-1", {"type": "distribution"}),
    ("service account password strengthened", "node", "sa-1", {"credential_strength": "strong"}),
)

#: Techniques the perturbable world actually uses, so raising one of their
#: baselines moves a path that exists. Raising a baseline nothing uses would
#: pass invariant 4 vacuously.
RAISED_TECHNIQUES: tuple[str, ...] = (
    "group_membership",
    "group_permission",
    "credential_in_files",
    "credential_replay",
    "kerberoasting",
    "cloud_account_use",
)


def hardening(index: int) -> Perturbation:
    """One entry of :data:`HARDENINGS` as a perturbation."""
    label, target, element_id, attrs = HARDENINGS[index % len(HARDENINGS)]
    if target == "edge":
        return Perturbation(label=label, edge_attrs={element_id: attrs})
    return Perturbation(label=label, node_attrs={element_id: attrs})


#: The fixed set the API endpoint runs: every hardening, plus a removal of each
#: edge of the planted chain and one of two edges at once. Ordered and explicit
#: so two requests return the same thing, which is itself invariant 10.
DEFAULT_PERTURBATIONS: tuple[Perturbation, ...] = (
    Perturbation(label="the world as generated"),
    *(hardening(i) for i in range(len(HARDENINGS))),
    *(
        Perturbation(label=f"edge {edge_id} removed", drop_edges=(edge_id,))
        for edge_id in CHAIN_EDGE_IDS
    ),
    Perturbation(
        label="the membership and the permission both removed",
        drop_edges=("e-mem-1", "e-perm-1"),
    ),
)


# ── The harness ──────────────────────────────────────────────────────────────


class Harness:
    """One configured world: the model, the baseline run, and the runs it is compared to.

    The baseline is computed once and reused, because every metamorphic
    invariant is a statement about a perturbed run *relative to* it and
    recomputing it per check would be most of the cost of the suite.
    """

    def __init__(
        self,
        model: ModelSource | None = None,
        *,
        threat_model_code: str = THREAT_MODEL,
        max_hops: int = MAX_HOPS,
        top_k: int = TOP_K,
    ) -> None:
        self.model = model or load_model()
        self.threat_model_code = threat_model_code
        self.limits = SearchLimits(max_hops=max_hops, top_k=top_k)
        self._baseline_snapshot = chain_snapshot()
        # Ten invariants over twenty perturbations means the same search is
        # asked for many times over. Cached on the perturbation's *content* and
        # the scoring variant, which together determine the answer -- invariant
        # 10 is the one check that must not read from here, and it does not.
        self._runs: dict[tuple[str, str], DiscoveryResult] = {}

    @property
    def baseline_snapshot(self) -> GraphSnapshot:
        return self._baseline_snapshot

    @property
    def baseline(self) -> DiscoveryResult:
        return self.result(Perturbation(label="the world as generated"))

    def result(
        self, perturbation: Perturbation, *, scoring_key: str = "as configured", scoring: Any = None
    ) -> DiscoveryResult:
        key = (perturbation.key, scoring_key)
        cached = self._runs.get(key)
        if cached is None:
            cached = self.discover(perturbation.snapshot(), scoring)
            self._runs[key] = cached
        return cached

    def discover(self, snapshot: GraphSnapshot, scoring: Any = None) -> DiscoveryResult:
        engine = Discovery(
            snapshot,
            self.model.engine_ruleset,
            Scorer(scoring or self.model.scoring),
            self.limits,
        )
        return engine.run(self.threat_model_code)

    def blast(self, snapshot: GraphSnapshot, origin: str = BLAST_ORIGIN) -> frozenset[str]:
        engine = BlastRadius(
            snapshot,
            self.model.engine_ruleset,
            Scorer(self.model.scoring),
            BlastLimits(max_depth=self.limits.max_hops),
        )
        return frozenset(node.node_id for node in engine.run(origin).reached)

    def initial_capabilities(self, snapshot: GraphSnapshot, entry_node_id: str):
        """The threat model's grants at one entry, materialised by the *oracle*.

        Used by invariant 5, which has to replay a path from a starting state
        the engine did not hand it -- otherwise the re-derivation inherits
        whatever the search believed the attacker started with.
        """
        return materialise_grants(
            self.model.oracle_ruleset,
            self.model.oracle_ruleset.threat_models[self.threat_model_code],
            snapshot,
            entry_node_id,
        )


# ── The invariants ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Invariant:
    number: int
    code: str
    statement: str
    """Verbatim from ``docs/RULES.md`` §7."""

    method: str
    """How this suite checks it, in plain words, including anything it does not check."""

    check: Callable[["Harness", Perturbation], tuple[str, ...]]
    """Returns one sentence per violation; an empty tuple means it held."""

    applies: Callable[[Perturbation], bool] = lambda _: True
    """Whether this perturbation is one the invariant has anything to say about."""


def _paths_by_id(result: DiscoveryResult) -> dict[str, Any]:
    return {path.path_id: path for path in result.paths}


def _check_removal_never_adds(harness: Harness, perturbation: Perturbation) -> tuple[str, ...]:
    baseline = harness.baseline
    reduced = harness.result(perturbation)
    problems: list[str] = []
    if len(reduced.paths) > len(baseline.paths):
        problems.append(
            f"removing {', '.join(perturbation.drop_edges)} raised the path count from "
            f"{len(baseline.paths)} to {len(reduced.paths)}"
        )
    dropped = set(perturbation.drop_edges)
    for path in reduced.paths:
        used = dropped & {hop.edge_id for hop in path.hops if hop.edge_id}
        if used:
            problems.append(f"path {path.path_id[:12]} still traverses removed edge(s) {sorted(used)}")
    return tuple(problems)


def _check_removal_never_raises_probability(
    harness: Harness, perturbation: Perturbation
) -> tuple[str, ...]:
    baseline = _paths_by_id(harness.baseline)
    reduced = harness.result(perturbation)
    problems: list[str] = []
    for path in reduced.paths:
        before = baseline.get(path.path_id)
        if before is None:
            continue
        # A tolerance, because the two runs reach the same product by the same
        # multiplications in the same order but through different queue
        # histories; anything above float noise is a real change.
        if path.p_success > before.p_success + 1e-12:
            problems.append(
                f"path {path.path_id[:12]} rose from {before.p_success:.9f} to "
                f"{path.p_success:.9f} when {', '.join(perturbation.drop_edges)} was removed"
            )
    return tuple(problems)


def _check_hardening_never_adds(harness: Harness, perturbation: Perturbation) -> tuple[str, ...]:
    baseline = _paths_by_id(harness.baseline)
    hardened = harness.result(perturbation)
    problems: list[str] = []
    if len(hardened.paths) > len(baseline):
        problems.append(
            f"{perturbation.label} raised the path count from {len(baseline)} to "
            f"{len(hardened.paths)}"
        )
    for path in hardened.paths:
        before = baseline.get(path.path_id)
        if before is not None and path.p_success > before.p_success + 1e-12:
            problems.append(
                f"{perturbation.label} raised path {path.path_id[:12]} from "
                f"{before.p_success:.9f} to {path.p_success:.9f}"
            )
    return tuple(problems)


def _check_raising_a_baseline_never_lowers(
    harness: Harness, perturbation: Perturbation
) -> tuple[str, ...]:
    """Invariant 4, one technique at a time, over the perturbed world.

    The baseline is raised rather than lowered because the invariant is stated
    that way, and it is raised towards 0.999 rather than to a fixed number so a
    technique already above the target is still moved upward instead of
    silently downward.
    """
    before = _paths_by_id(harness.result(perturbation))
    problems: list[str] = []
    for technique in RAISED_TECHNIQUES:
        current = harness.model.scoring.baselines.get(technique)
        if current is None:
            continue
        raised = min(0.999, current[0] + (1.0 - current[0]) / 2)
        if raised <= current[0]:
            continue
        after = _paths_by_id(
            harness.result(
                perturbation,
                scoring_key=f"{technique} raised",
                scoring=scoring_with_baseline(harness.model.scoring, technique, raised),
            )
        )
        for path_id, path in before.items():
            uplifted = after.get(path_id)
            if uplifted is None:
                continue
            if not any(hop.technique_code == technique for hop in path.hops):
                continue
            if uplifted.p_success < path.p_success - 1e-12:
                problems.append(
                    f"raising {technique} from {current[0]:.3f} to {raised:.3f} lowered path "
                    f"{path_id[:12]} from {path.p_success:.9f} to {uplifted.p_success:.9f}"
                )
    return tuple(problems)


def _check_every_hop_holds(harness: Harness, perturbation: Perturbation) -> tuple[str, ...]:
    """Invariant 5, re-derived by the reference implementation.

    ``oracle.search.verify_path`` walks the path from the threat model's grants
    using nothing but the rule rows, so a fault in the engine's frontier, queue
    or pruning cannot hide inside its own bookkeeping.
    """
    snapshot = perturbation.snapshot()
    result = harness.result(perturbation)
    problems: list[str] = []
    for path in result.paths:
        held = harness.initial_capabilities(snapshot, path.source_node_id)
        for problem in verify_path(
            path,
            snapshot=snapshot,
            ruleset=harness.model.oracle_ruleset,
            initial_capabilities=held,
        ):
            problems.append(f"path {path.path_id[:12]}: {problem}")
    return tuple(problems)


def _check_ranges(harness: Harness, perturbation: Perturbation) -> tuple[str, ...]:
    result = harness.result(perturbation)
    problems: list[str] = []
    for path in result.paths:
        if not 0.0 < path.p_success <= 1.0:
            problems.append(f"path {path.path_id[:12]} has p_success {path.p_success}")
        if not 0.0 <= path.risk_score <= 10.0:
            problems.append(f"path {path.path_id[:12]} has risk score {path.risk_score}")
        if not 0.0 < path.p_undetected <= 1.0:
            problems.append(f"path {path.path_id[:12]} has p_undetected {path.p_undetected}")
        for hop in path.hops:
            if not 0.0 < hop.p_succ <= 1.0:
                problems.append(
                    f"path {path.path_id[:12]} hop {hop.hop_no} has p_succ {hop.p_succ}"
                )
    return tuple(problems)


def _check_blast_radius_only_shrinks(
    harness: Harness, perturbation: Perturbation
) -> tuple[str, ...]:
    """Invariant 7, for the fixes that remove an edge. See the module docstring."""
    try:
        before = harness.blast(harness.baseline_snapshot)
        after = harness.blast(perturbation.snapshot())
    except BlastRadiusError as exc:
        return (f"blast radius could not be computed: {exc}",)
    added = sorted(after - before)
    if added:
        return (
            f"removing {', '.join(perturbation.drop_edges)} added "
            f"{', '.join(added)} to the blast radius of {BLAST_ORIGIN}",
        )
    return ()


def _check_agrees_with_the_oracle(
    harness: Harness, perturbation: Perturbation
) -> tuple[str, ...]:
    case = run_snapshot_case(
        code="property_suite",
        title=perturbation.label,
        mechanism="The perturbable world under one perturbation.",
        snapshot=perturbation.snapshot(),
        threat_model_code=harness.threat_model_code,
        max_hops=harness.limits.max_hops,
        model=harness.model,
    )
    if case.error:
        return (f"the reference oracle refused this graph: {case.error}",)
    problems = [
        f"only the engine found {' -> '.join(d.steps)}" for d in case.engine_only
    ]
    problems += [
        f"only the reference found {' -> '.join(d.steps)}" for d in case.reference_only
    ]
    return tuple(problems)


def _check_rejections_are_genuine(
    harness: Harness, perturbation: Perturbation
) -> tuple[str, ...]:
    """Invariant 9, re-evaluated with the reference implementation's checker.

    A refusal on a graph attribute is fully re-checkable: the precondition it
    names is read again, against the same two nodes and the same edge, by
    ``oracle.preconditions``, and it must still fail. A refusal on a held
    capability is not, because ``rejected_candidate`` records the observed
    capability rather than the whole state the search was in -- so what is
    checked for those is that the row names a capability precondition the rule
    genuinely has at that sequence number, which is the part the row does pin
    down. The two are counted separately in the outcome's detail rather than
    presented as one number.
    """
    snapshot = perturbation.snapshot()
    result = harness.result(perturbation)
    ruleset = harness.model.oracle_ruleset
    problems: list[str] = []

    for rejection in result.rejections:
        try:
            rule = ruleset.by_id(rejection.rule_id)
        except KeyError:
            problems.append(f"rejection {rejection.signature[:12]} names unknown rule {rejection.rule_id}")
            continue
        matching = [p for p in rule.preconditions if p.seq == rejection.precondition_seq]
        if not matching:
            problems.append(
                f"rejection {rejection.signature[:12]} names precondition seq "
                f"{rejection.precondition_seq}, which rule {rule.code!r} does not have"
            )
            continue
        precondition = matching[0]

        if precondition.capability_code is not None:
            if precondition.capability_code not in rejection.reason_code:
                problems.append(
                    f"rejection {rejection.signature[:12]} reports {rejection.reason_code!r} "
                    f"for a precondition on capability {precondition.capability_code!r}"
                )
            continue

        src = snapshot.get_node(rejection.src_node_id)
        dst = snapshot.get_node(rejection.dst_node_id)
        if src is None or dst is None:
            problems.append(
                f"rejection {rejection.signature[:12]} names a node absent from the graph"
            )
            continue
        edge = snapshot.edge(rejection.edge_id) if rejection.edge_id else None
        outcome = evaluate_precondition(
            precondition,
            capabilities=frozenset(),
            edge=edge,
            src_node=src,
            dst_node=dst,
            global_capability_codes=ruleset.global_capability_codes,
        )
        if outcome.holds:
            problems.append(
                f"rejection {rejection.signature[:12]} blames precondition seq "
                f"{precondition.seq} of {rule.code!r}, which holds when re-evaluated "
                f"(observed {outcome.observed})"
            )
    return tuple(problems)


def _serialise(result: DiscoveryResult) -> str:
    """Everything a stored run would carry, canonically -- including tie order."""
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
                    "risk_score": p.risk_score,
                    "risk_tier": p.risk_tier_code,
                    "hops": [
                        [h.hop_no, h.edge_id, h.rule_id, h.p_succ, [str(c) for c in h.gained]]
                        for h in p.hops
                    ],
                }
                for p in result.paths
            ],
            "rejections": [
                [r.signature, r.rule_id, r.reason_code, r.observed_value, r.hop_depth]
                for r in result.rejections
            ],
        }
    )


def _check_determinism(harness: Harness, perturbation: Perturbation) -> tuple[str, ...]:
    snapshot = perturbation.snapshot()
    first = _serialise(harness.discover(snapshot))
    second = _serialise(harness.discover(perturbation.snapshot()))
    if first != second:
        return ("two runs over the same graph produced different output, including tie order",)
    return ()


#: Every invariant §7 states, in its own numbering. The three that are not
#: checked here still appear, with ``check`` refusing rather than passing, so a
#: reader sees ten rows and is told which of them this suite can stand behind.
INVARIANTS: tuple[Invariant, ...] = (
    Invariant(
        number=1,
        code="removal_never_adds_a_path",
        statement="Removing an edge never increases the number of discovered paths.",
        method=(
            "Removes a subset of the world's edges and compares the path count against "
            "the unperturbed run, and checks no surviving path still traverses a removed edge."
        ),
        check=_check_removal_never_adds,
        applies=lambda p: p.removes,
    ),
    Invariant(
        number=2,
        code="removal_never_raises_probability",
        statement="Removing an edge never increases any path's probability.",
        method=(
            "For every path that survives the removal, compares its success probability "
            "against the same path's probability before it."
        ),
        check=_check_removal_never_raises_probability,
        applies=lambda p: p.removes,
    ),
    Invariant(
        number=3,
        code="hardening_never_adds",
        statement=(
            "Adding a hard-block attribute (phishing-resistant MFA, vault storage) never "
            "increases path count or probability."
        ),
        method=(
            "Applies one of eight hard blocks -- each the deciding attribute of a planted "
            "decoy -- and checks neither the count nor any surviving path's probability rose."
        ),
        check=_check_hardening_never_adds,
        applies=lambda p: p.hardens,
    ),
    Invariant(
        number=4,
        code="raising_a_baseline_never_lowers",
        statement=(
            "Increasing any base_p_succ never decreases the probability of a path using "
            "that technique."
        ),
        method=(
            "Raises each technique baseline the world actually uses halfway to certainty, "
            "then checks every path using that technique came back at least as likely."
        ),
        check=_check_raising_a_baseline_never_lowers,
    ),
    Invariant(
        number=5,
        code="every_hop_holds_on_replay",
        statement=(
            "Every discovered path's hops each satisfy their rule's preconditions given "
            "the state accumulated by the preceding hops."
        ),
        method=(
            "Replays each discovered path with the reference oracle's verifier from the "
            "threat model's grants, so the engine's own bookkeeping cannot satisfy it."
        ),
        check=_check_every_hop_holds,
    ),
    Invariant(
        number=6,
        code="probabilities_and_scores_in_range",
        statement="Every path probability lies in (0, 1]; every display score lies in [0, 10].",
        method=(
            "Checks path and hop success probabilities, the undetected probability and the "
            "display risk score of every discovered path."
        ),
        check=_check_ranges,
    ),
    Invariant(
        number=7,
        code="blast_radius_only_shrinks",
        statement=(
            "Blast radius after applying a fix is a subset of blast radius before, unless "
            "the fix is one whose simulation predicted additions."
        ),
        method=(
            "Checked for the edge-removal class of fixes only, where nothing can be added "
            "because nothing is added: the blast radius of the entry user after the removal "
            "must be a subset of its blast radius before. Attribute-rewriting fixes and the "
            "predicted-additions exception need the simulator's own prediction and are not "
            "covered here."
        ),
        check=_check_blast_radius_only_shrinks,
        applies=lambda p: p.removes and not p.hardens,
    ),
    Invariant(
        number=8,
        code="engine_agrees_with_the_oracle",
        statement=(
            "The engine and the reference oracle return identical path sets on any graph "
            "small enough for the oracle to finish."
        ),
        method=(
            "Runs the differential harness over the perturbed world and reports any path "
            "exactly one implementation found."
        ),
        check=_check_agrees_with_the_oracle,
    ),
    Invariant(
        number=9,
        code="rejections_name_a_failing_precondition",
        statement=(
            "Every rejected candidate names a precondition that genuinely fails under the "
            "state recorded with it."
        ),
        method=(
            "Re-evaluates every attribute-based refusal with the reference oracle's "
            "precondition checker and requires it to still fail. Capability refusals record "
            "the observed capability rather than the whole state, so for those the check is "
            "that the row names a capability precondition the rule genuinely has."
        ),
        check=_check_rejections_are_genuine,
    ),
    Invariant(
        number=10,
        code="discovery_is_deterministic",
        statement=(
            "Discovery is deterministic: the same graph, threat model and scoring version "
            "produce identical results, including tie ordering."
        ),
        method=(
            "Runs the search twice over a freshly rebuilt snapshot of the same graph and "
            "compares the canonical serialisation of everything a stored run would carry."
        ),
        check=_check_determinism,
    ),
)


def invariant(number: int) -> Invariant:
    for entry in INVARIANTS:
        if entry.number == number:
            return entry
    raise KeyError(f"docs/RULES.md §7 has no invariant {number}")


# ── Running the suite ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class InvariantOutcome:
    number: int
    code: str
    statement: str
    method: str
    cases_checked: int
    failures: tuple[str, ...]
    duration_ms: int

    @property
    def status(self) -> str:
        if self.failures:
            return "fail"
        return "pass" if self.cases_checked else "not_exercised"


@dataclass(frozen=True, slots=True)
class InvariantReport:
    outcomes: tuple[InvariantOutcome, ...]
    perturbations: tuple[str, ...]
    model_origin: str
    model_detail: str
    graph_nodes: int
    graph_edges: int
    max_hops: int
    threat_model_code: str
    duration_ms: int

    @property
    def passing(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "pass")

    @property
    def failing(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "fail")

    @property
    def total_cases(self) -> int:
        return sum(o.cases_checked for o in self.outcomes)


def run_suite(
    *,
    model: ModelSource | None = None,
    perturbations: Sequence[Perturbation] = DEFAULT_PERTURBATIONS,
) -> InvariantReport:
    """Run every invariant over every perturbation and collect what held."""
    harness = Harness(model)
    started = time.perf_counter()

    outcomes: list[InvariantOutcome] = []
    for entry in INVARIANTS:
        began = time.perf_counter()
        failures: list[str] = []
        checked = 0
        for perturbation in perturbations:
            if not entry.applies(perturbation):
                continue
            checked += 1
            for failure in entry.check(harness, perturbation):
                failures.append(f"{perturbation.label}: {failure}")
        outcomes.append(
            InvariantOutcome(
                number=entry.number,
                code=entry.code,
                statement=entry.statement,
                method=entry.method,
                cases_checked=checked,
                failures=tuple(failures),
                duration_ms=int((time.perf_counter() - began) * 1000),
            )
        )

    baseline = harness.baseline_snapshot
    return InvariantReport(
        outcomes=tuple(outcomes),
        perturbations=tuple(p.label for p in perturbations),
        model_origin=harness.model.origin,
        model_detail=harness.model.detail,
        graph_nodes=len(baseline),
        graph_edges=len(list(baseline.all_edges)),
        max_hops=harness.limits.max_hops,
        threat_model_code=harness.threat_model_code,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
