"""Tests for the state machine that is read out of the tables rather than coded.

Every assertion here is really about the same claim: adding a state or a
transition is an INSERT, not an edit to a chain of conditionals. So the tests
feed rows in and check the behaviour follows them, including rows that do not
match what the product ships.
"""

from __future__ import annotations

import pytest

from remediation.lifecycle import (
    ApprovalRequired,
    LifecycleError,
    advance,
    build_lifecycle,
    path_between,
)


def test_the_shipped_rows_build(lifecycle_rows):
    lifecycle = build_lifecycle(*lifecycle_rows)

    assert len(lifecycle.states) == 7
    assert lifecycle.state("verified").is_terminal is True
    assert lifecycle.state("recommended").is_terminal is False


def test_the_starting_state_is_derived_not_named(lifecycle_rows):
    """The code does not know that the first state happens to be called
    'recommended' -- it is the lowest-ordered non-terminal one."""
    states, transitions = lifecycle_rows
    assert build_lifecycle(states, transitions).initial_state == "recommended"

    renamed = [{**s, "code": "triaged"} if s["code"] == "recommended" else s for s in states]
    renamed_transitions = [
        {
            **t,
            "from_state": "triaged" if t["from_state"] == "recommended" else t["from_state"],
            "to_state": "triaged" if t["to_state"] == "recommended" else t["to_state"],
        }
        for t in transitions
    ]
    assert build_lifecycle(renamed, renamed_transitions).initial_state == "triaged"


def test_an_empty_state_table_says_to_run_the_seeds():
    with pytest.raises(LifecycleError, match="run the seed files"):
        build_lifecycle([], [])


def test_an_empty_transition_table_is_refused(lifecycle_rows):
    states, _ = lifecycle_rows
    with pytest.raises(LifecycleError, match="could ever leave the state"):
        build_lifecycle(states, [])


def test_a_transition_naming_an_unknown_state_is_refused(lifecycle_rows):
    states, transitions = lifecycle_rows
    broken = transitions + [
        {"from_state": "applied", "to_state": "archived", "label": "Archive", "needs_approval": 0}
    ]
    with pytest.raises(LifecycleError, match="unknown state 'archived'"):
        build_lifecycle(states, broken)


def test_a_terminal_state_may_still_have_an_exit(lifecycle_rows):
    """'verified -> rolled_back' ships on purpose: a fix can be reverted after
    it has been confirmed to work."""
    lifecycle = build_lifecycle(*lifecycle_rows)

    assert [t.to_state for t in lifecycle.allowed_from("verified")] == ["rolled_back"]


def test_an_illegal_transition_names_what_the_table_does_allow(lifecycle_rows):
    lifecycle = build_lifecycle(*lifecycle_rows)

    with pytest.raises(LifecycleError) as excinfo:
        lifecycle.transition("recommended", "applied")
    message = str(excinfo.value)
    assert "not a legal transition" in message
    assert "simulated" in message


def test_an_unknown_state_lists_the_known_ones(lifecycle_rows):
    lifecycle = build_lifecycle(*lifecycle_rows)

    with pytest.raises(LifecycleError, match="unknown state 'archived'"):
        lifecycle.state("archived")


def test_an_approval_is_required_only_where_both_halves_agree(lifecycle_rows):
    """The transition decides whether an approval belongs on this step; the fix
    type decides whether it has to be a real signature."""
    lifecycle = build_lifecycle(*lifecycle_rows)

    # Transition wants one, fix type does not: allowed.
    lifecycle.check("simulated", "approved", fix_requires_approval=False)
    # Fix type wants one, transition does not: allowed.
    lifecycle.check("recommended", "simulated", fix_requires_approval=True)
    # Both: refused without a name.
    with pytest.raises(ApprovalRequired, match="named approver"):
        lifecycle.check("simulated", "approved", fix_requires_approval=True)
    # And allowed with one.
    lifecycle.check("simulated", "approved", fix_requires_approval=True, approved_by="Ana")


def test_the_route_to_applied_goes_through_simulation(lifecycle_rows):
    """Applying an unsimulated change leaves no prediction to verify against,
    and the table is where that rule lives."""
    lifecycle = build_lifecycle(*lifecycle_rows)

    assert path_between(lifecycle, "recommended", "applied") == (
        "recommended",
        "simulated",
        "approved",
        "applied",
    )


def test_a_route_to_where_you_already_are_is_trivial(lifecycle_rows):
    lifecycle = build_lifecycle(*lifecycle_rows)

    assert path_between(lifecycle, "simulated", "simulated") == ("simulated",)


def test_there_is_no_route_out_of_a_dead_end(lifecycle_rows):
    lifecycle = build_lifecycle(*lifecycle_rows)

    assert path_between(lifecycle, "dismissed", "applied") == ()


def test_advance_validates_every_step_without_performing_any(lifecycle_rows):
    """Separated from the write so a caller about to materialise a graph version
    finds out first that the lifecycle would have refused."""
    lifecycle = build_lifecycle(*lifecycle_rows)
    recommendation = {"state_code": "recommended", "requires_approval": 1}
    route = path_between(lifecycle, "recommended", "applied")

    with pytest.raises(ApprovalRequired):
        advance(lifecycle, recommendation, route)

    taken = advance(lifecycle, recommendation, route, approved_by="Ana")
    assert [t.to_state for t in taken] == ["simulated", "approved", "applied"]
    # Nothing was written: the caller's row is untouched.
    assert recommendation["state_code"] == "recommended"


def test_advance_skips_the_step_it_is_already_on(lifecycle_rows):
    lifecycle = build_lifecycle(*lifecycle_rows)
    recommendation = {"state_code": "simulated", "requires_approval": 0}

    taken = advance(lifecycle, recommendation, ("simulated",))
    assert taken == ()
