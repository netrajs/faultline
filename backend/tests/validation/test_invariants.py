"""``docs/RULES.md`` §7, as properties rather than examples.

``backend/tests/engine/test_search.py`` already checks several of these against
one hand-built graph apiece, and those tests stay: an example test names the
exact chain that must survive and the exact decoy that must not, which is
evidence a property test cannot give. What this file adds is the quantifier.
§7 says the invariants hold "for any graph and any threat model", and the
honest way to check a claim of that shape is to keep generating graphs until
one breaks it.

The generator is ``validation/invariants.Perturbation`` over the perturbable
world in ``validation/world.py``: draw a subset of its edges to remove and a
subset of the eight hard blocks to apply, and the result is a graph nobody wrote
down. Hypothesis then shrinks any counterexample to the smallest removal set
that still fails, which is the property this style is actually bought for --
a failure arrives as "remove e-perm-1 and vault cred-1", not as a stack trace
over a graph with nine changes in it.

The checks themselves live in ``validation/invariants.py`` rather than here,
because the API endpoint serves the same suite and two implementations of "does
invariant 3 hold" would eventually disagree about what invariant 3 is.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from validation.invariants import (
    DEFAULT_PERTURBATIONS,
    HARDENINGS,
    INVARIANTS,
    Harness,
    Perturbation,
    invariant,
    run_suite,
)
from validation.world import CHAIN_EDGE_IDS, load_model

# A search per example, so the example budget is spent deliberately. Twenty-five
# draws over ten edges and eight hardenings covers the space that matters
# without turning the suite into something nobody runs before pushing.
PROPERTY = settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

#: Fewer examples for the invariants whose check runs the exhaustive reference
#: oracle or several scoring variants -- those are seconds each, not milliseconds.
EXPENSIVE = settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


@pytest.fixture(scope="module")
def harness() -> Harness:
    """One harness for the whole module.

    The rule rows are loaded once and the baseline search is computed once;
    rebuilding either per example would dominate the runtime and measure the
    loader rather than the engine.
    """
    return Harness(load_model())


# ── Strategies ───────────────────────────────────────────────────────────────


removals = st.lists(
    st.sampled_from(CHAIN_EDGE_IDS), min_size=1, max_size=4, unique=True
).map(tuple)

hardening_indices = st.lists(
    st.integers(min_value=0, max_value=len(HARDENINGS) - 1), min_size=1, max_size=3, unique=True
)


def _hardening_perturbation(indices: list[int]) -> Perturbation:
    """Several hard blocks at once, merged into one perturbation.

    Merged rather than applied one at a time because invariant 3 is not only
    about a single attribute: two hard blocks on different elements must still
    only ever subtract, and a bug in how a second one composes with the first
    would be invisible to a one-at-a-time test.
    """
    edge_attrs: dict[str, dict[str, object]] = {}
    node_attrs: dict[str, dict[str, object]] = {}
    labels: list[str] = []
    for index in indices:
        label, target, element_id, attrs = HARDENINGS[index]
        labels.append(label)
        bucket = edge_attrs if target == "edge" else node_attrs
        bucket.setdefault(element_id, {}).update(attrs)
    return Perturbation(
        label=" and ".join(labels),
        edge_attrs={k: dict(v) for k, v in edge_attrs.items()},
        node_attrs={k: dict(v) for k, v in node_attrs.items()},
    )


perturbations = st.one_of(
    removals.map(lambda edges: Perturbation(label=f"removed {', '.join(edges)}", drop_edges=edges)),
    hardening_indices.map(_hardening_perturbation),
    st.tuples(removals, hardening_indices).map(
        lambda pair: Perturbation(
            label=f"removed {', '.join(pair[0])}, then hardened",
            drop_edges=pair[0],
            edge_attrs=_hardening_perturbation(pair[1]).edge_attrs,
            node_attrs=_hardening_perturbation(pair[1]).node_attrs,
        )
    ),
)


def assert_holds(number: int, harness: Harness, perturbation: Perturbation) -> None:
    failures = invariant(number).check(harness, perturbation)
    assert not failures, "\n".join(failures)


# ── The ten ──────────────────────────────────────────────────────────────────


@PROPERTY
@given(drop_edges=removals)
def test_removing_edges_never_adds_a_path(harness, drop_edges):
    """Invariant 1, over every subset of the world's edges up to four at a time."""
    assert_holds(1, harness, Perturbation(label=f"removed {drop_edges}", drop_edges=drop_edges))


@PROPERTY
@given(drop_edges=removals)
def test_removing_edges_never_raises_a_surviving_path(harness, drop_edges):
    """Invariant 2. Only paths that survive the removal are comparable at all."""
    assert_holds(2, harness, Perturbation(label=f"removed {drop_edges}", drop_edges=drop_edges))


@PROPERTY
@given(indices=hardening_indices)
def test_hardening_never_adds_a_path_or_raises_one(harness, indices):
    """Invariant 3, over every combination of up to three hard blocks."""
    assert_holds(3, harness, _hardening_perturbation(indices))


@EXPENSIVE
@given(perturbation=perturbations)
def test_raising_a_baseline_never_lowers_a_path_using_it(harness, perturbation):
    """Invariant 4. Each of six technique baselines is raised halfway to certainty."""
    assert_holds(4, harness, perturbation)


@PROPERTY
@given(perturbation=perturbations)
def test_every_discovered_hop_holds_when_the_oracle_replays_it(harness, perturbation):
    """Invariant 5, re-derived by the reference implementation rather than the engine."""
    assert_holds(5, harness, perturbation)


@PROPERTY
@given(perturbation=perturbations)
def test_probabilities_and_display_scores_stay_in_range(harness, perturbation):
    """Invariant 6."""
    assert_holds(6, harness, perturbation)


@PROPERTY
@given(drop_edges=removals)
def test_removing_an_edge_only_ever_shrinks_the_blast_radius(harness, drop_edges):
    """Invariant 7, for the class of fixes that remove an edge.

    The wider claim is about remediation generally and carries an exception for
    fixes whose simulation predicted additions; removal admits no such exception,
    because nothing is added.
    """
    assert_holds(7, harness, Perturbation(label=f"removed {drop_edges}", drop_edges=drop_edges))


@EXPENSIVE
@given(perturbation=perturbations)
def test_the_engine_and_the_reference_oracle_agree(harness, perturbation):
    """Invariant 8, on graphs neither implementation's author wrote down."""
    assert_holds(8, harness, perturbation)


@PROPERTY
@given(perturbation=perturbations)
def test_every_refusal_names_a_precondition_that_really_fails(harness, perturbation):
    """Invariant 9, for the attribute-based refusals -- see the check's own docstring."""
    assert_holds(9, harness, perturbation)


@PROPERTY
@given(perturbation=perturbations)
def test_discovery_is_deterministic_including_tie_order(harness, perturbation):
    """Invariant 10, taken literally: byte-identical, not merely equivalent."""
    assert_holds(10, harness, perturbation)


# ── The suite the API serves ─────────────────────────────────────────────────


def test_the_shipped_suite_covers_all_ten_invariants():
    """Ten rows, numbered one to ten, each naming what it checks.

    The endpoint renders a grid, and a grid that quietly omitted an invariant
    would read as a clean sweep. Whether one is exercised is a separate
    question, answered per row below.
    """
    assert [entry.number for entry in INVARIANTS] == list(range(1, 11))
    for entry in INVARIANTS:
        assert entry.statement.strip()
        assert entry.method.strip()


def test_the_shipped_suite_exercises_every_invariant_and_passes():
    """The fixed perturbation set the API runs, run here too.

    This is the one test that asserts on the shipped default rather than on a
    generated draw, because the endpoint's answer is what a reader is shown and
    "the endpoint is green" has to be something CI can fail on.
    """
    report = run_suite()
    assert len(report.outcomes) == 10
    for outcome in report.outcomes:
        assert outcome.cases_checked > 0, f"invariant {outcome.number} was never exercised"
        assert outcome.status == "pass", "\n".join(outcome.failures)
    assert report.failing == 0
    assert report.passing == 10


def test_the_default_perturbations_cover_both_kinds_of_change():
    """Removals and hardenings both, or four of the ten invariants never run."""
    assert any(p.removes for p in DEFAULT_PERTURBATIONS)
    assert any(p.hardens for p in DEFAULT_PERTURBATIONS)
    assert any(not p.removes and not p.hardens for p in DEFAULT_PERTURBATIONS)


def test_a_broken_engine_would_be_caught(harness):
    """The suite has to be able to fail, or its passing says nothing.

    Removing the edge the planted chain authenticates over must take that chain
    away. If the check below ever stops finding a difference, every monotonicity
    result above is being computed over a world nothing perturbs.
    """
    baseline = harness.baseline
    reduced = harness.result(Perturbation(label="probe", drop_edges=("e-auth-1",)))
    assert len(reduced.paths) < len(baseline.paths)
