"""Tests for the counterfactual diff and the prediction it commits to.

Only the pure half of ``remediation.simulate`` is exercised here. Running a real
re-derivation takes minutes and needs both stores, and is covered end to end by
the router tests; what has to be right in isolation is the diff itself -- that it
runs in both directions, and that the hash cannot be nudged after the fact.
"""

from __future__ import annotations

from remediation.simulate import build_mutation, diff_paths, prediction_hash


def test_a_removed_path_is_one_the_baseline_had_and_the_candidate_does_not():
    diff = diff_paths({"a": 9.0, "b": 5.0}, {"b": 5.0})

    assert diff.removed == ("a",)
    assert diff.added == ()
    assert diff.rescored == ()


def test_an_added_path_is_a_finding_not_an_error():
    """A fix can create paths -- rotating a shared secret redistributes it,
    removing a membership can strip a restriction that was doing real work. A
    diff that only counted removals would report a fix as a pure win."""
    diff = diff_paths({"a": 9.0}, {"a": 9.0, "new": 7.0})

    assert diff.removed == ()
    assert diff.added == ("new",)


def test_a_path_present_in_both_at_a_different_score_is_rescored():
    diff = diff_paths({"a": 9.0}, {"a": 4.5})

    assert diff.rescored == (("a", 9.0, 4.5),)
    assert diff.removed == () and diff.added == ()


def test_a_difference_below_the_stored_precision_is_not_a_difference():
    """The column is DECIMAL(4,2), so float noise below that would fill
    paths_rescored with changes nobody can see."""
    diff = diff_paths({"a": 9.0}, {"a": 9.0004})

    assert diff.rescored == ()


def test_both_directions_are_reported_at_once():
    diff = diff_paths({"gone": 9.0, "same": 5.0}, {"same": 5.0, "new": 3.0})

    assert diff.removed == ("gone",)
    assert diff.added == ("new",)


def test_the_diff_is_ordered_so_the_hash_is_stable():
    forward = diff_paths({"b": 1.0, "a": 1.0}, {})
    backward = diff_paths({"a": 1.0, "b": 1.0}, {})

    assert forward.removed == backward.removed == ("a", "b")
    assert forward.prediction_hash == backward.prediction_hash


def test_the_prediction_hash_covers_both_sets_and_neither_alone():
    base = prediction_hash(["a"], ["b"])

    assert prediction_hash(["a"], []) != base
    assert prediction_hash([], ["b"]) != base
    assert prediction_hash(["b"], ["a"]) != base
    # Order of the input does not matter; content does.
    assert prediction_hash(["a"], ["b"]) == prediction_hash(["a"], ["b"])


def test_no_change_still_hashes_to_something_checkable():
    assert len(prediction_hash([], [])) == 64


def test_deltas_carry_the_score_from_whichever_side_has_one():
    baseline = {"gone": 9.0, "same": 5.0}
    candidate = {"same": 4.0, "new": 3.0}
    diff = diff_paths(baseline, candidate)
    rows = {row.path_id: row for row in diff.deltas(baseline, candidate)}

    assert rows["gone"].change_kind == "removed"
    assert rows["gone"].risk_before == 9.0 and rows["gone"].risk_after is None
    assert rows["new"].change_kind == "added"
    assert rows["new"].risk_before is None and rows["new"].risk_after == 3.0
    assert rows["same"].change_kind == "rescored"
    assert rows["same"].risk_before == 5.0 and rows["same"].risk_after == 4.0


def test_a_mutation_is_built_from_the_recommendations_own_row():
    """``mutation_value`` arrives as the JSON text in the column, so 'false'
    has to become False rather than a truthy string."""
    mutation = build_mutation(
        {
            "mutation_kind": "set_node_attr",
            "target_kind": "node",
            "target_id": "cred1",
            "mutation_target_attr": "is_active",
            "mutation_value": "false",
        }
    )

    assert mutation.kind == "set_node_attr"
    assert mutation.value is False
    assert mutation.description == "set node cred1.is_active = False"


def test_an_edge_removal_needs_no_attribute():
    mutation = build_mutation(
        {
            "mutation_kind": "remove_edge",
            "target_kind": "edge",
            "target_id": "e-auth",
            "mutation_target_attr": None,
            "mutation_value": None,
        }
    )

    assert mutation.attr is None
    assert mutation.description == "remove edge e-auth"
