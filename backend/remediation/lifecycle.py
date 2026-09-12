"""The remediation lifecycle, read from the table that defines it.

``remediation_transition`` exists so the lifecycle is inspectable rather than
buried in conditionals — the migration says so in a comment on the table. So
this module contains no list of state names and no chain of ``if state ==``: it
loads the rows and asks them. Adding a state or a transition is an INSERT, and
the refusal message names the transitions the table actually allows, which is
the same sentence a reader of the table would write.

One thing the rows cannot say on their own is who has to sign. The transition
carries ``needs_approval``, and ``fix_type.requires_approval`` says whether the
fix is disruptive enough to need a real one. Both are consulted: the transition
decides *whether an approval belongs on this step*, and the fix type decides
*whether it has to be a real signature*. Until the EIP-712 verifier of
``docs/SCOPE.md`` D7 exists, "real" means a named approver recorded with the
transition — which is a placeholder for a signature and is described as one
rather than being presented as authorisation it is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


class LifecycleError(RuntimeError):
    """A state change the transition table does not allow."""


class ApprovalRequired(LifecycleError):
    """A legal transition that this fix cannot take without an approval."""


@dataclass(frozen=True, slots=True)
class State:
    code: str
    label: str
    description: str
    is_terminal: bool
    ui_color: str
    sort_order: int


@dataclass(frozen=True, slots=True)
class Transition:
    from_state: str
    to_state: str
    label: str
    needs_approval: bool


@dataclass(frozen=True, slots=True)
class Lifecycle:
    """The states and the edges between them, as loaded."""

    states: Mapping[str, State]
    transitions: Mapping[tuple[str, str], Transition]

    @property
    def initial_state(self) -> str:
        """The lowest-ordered non-terminal state a recommendation starts in.

        Derived from ``sort_order`` and ``is_terminal`` rather than named, so
        the code does not have to know that the first state happens to be
        called ``recommended``.
        """
        candidates = sorted(
            (s for s in self.states.values() if not s.is_terminal),
            key=lambda s: (s.sort_order, s.code),
        )
        if not candidates:
            raise LifecycleError(
                "every remediation_state is terminal, so a recommendation has "
                "nowhere to start"
            )
        return candidates[0].code

    def state(self, code: str) -> State:
        try:
            return self.states[code]
        except KeyError:
            known = ", ".join(sorted(self.states))
            raise LifecycleError(f"unknown state {code!r}; known: {known}") from None

    def allowed_from(self, code: str) -> tuple[Transition, ...]:
        self.state(code)
        return tuple(
            transition
            for (from_state, _), transition in sorted(self.transitions.items())
            if from_state == code
        )

    def transition(self, from_state: str, to_state: str) -> Transition:
        self.state(from_state)
        self.state(to_state)
        found = self.transitions.get((from_state, to_state))
        if found is None:
            allowed = ", ".join(t.to_state for t in self.allowed_from(from_state))
            raise LifecycleError(
                f"{from_state} -> {to_state} is not a legal transition; "
                f"from {from_state} the table allows: {allowed or '(nothing)'}"
            )
        return found

    def check(
        self,
        from_state: str,
        to_state: str,
        *,
        fix_requires_approval: bool,
        approved_by: str | None = None,
    ) -> Transition:
        """Validate a state change, including whether it needs an approval."""
        transition = self.transition(from_state, to_state)
        if transition.needs_approval and fix_requires_approval and not approved_by:
            raise ApprovalRequired(
                f"{transition.label} on a fix marked requires_approval needs a "
                "named approver; this stands in for the EIP-712 signature the "
                "approval contract will verify"
            )
        return transition


def build_lifecycle(
    state_rows: Iterable[Mapping[str, object]],
    transition_rows: Iterable[Mapping[str, object]],
) -> Lifecycle:
    """Assemble a lifecycle from rows, validating that it is navigable.

    Pure, so the validation under test is the one the production path runs.
    """
    states = {
        str(row["code"]): State(
            code=str(row["code"]),
            label=str(row["label"]),
            description=str(row["description"]),
            is_terminal=bool(int(row["is_terminal"])),  # type: ignore[arg-type]
            ui_color=str(row["ui_color"]),
            sort_order=int(row["sort_order"]),  # type: ignore[arg-type]
        )
        for row in state_rows
    }
    if not states:
        raise LifecycleError(
            "remediation_state is empty; run the seed files under backend/db/seed"
        )

    transitions: dict[tuple[str, str], Transition] = {}
    for row in transition_rows:
        from_state, to_state = str(row["from_state"]), str(row["to_state"])
        for code in (from_state, to_state):
            if code not in states:
                raise LifecycleError(
                    f"transition {from_state} -> {to_state} names unknown state "
                    f"{code!r}"
                )
        # A terminal state is allowed an outgoing transition: 'verified ->
        # rolled_back' is in the shipped rows on purpose, because a fix can be
        # reverted after it has been confirmed to work.
        transitions[(from_state, to_state)] = Transition(
            from_state=from_state,
            to_state=to_state,
            label=str(row["label"]),
            needs_approval=bool(int(row["needs_approval"])),  # type: ignore[arg-type]
        )
    if not transitions:
        raise LifecycleError(
            "remediation_transition is empty, so no recommendation could ever "
            "leave the state it was created in"
        )
    return Lifecycle(states=states, transitions=transitions)


def load_lifecycle() -> Lifecycle:
    from remediation.store import load_states, load_transitions

    return build_lifecycle(load_states(), load_transitions())


def path_between(lifecycle: Lifecycle, from_state: str, to_state: str) -> tuple[str, ...]:
    """The shortest legal route between two states, or () if there is none.

    Used when a caller asks for an outcome rather than a step — "apply this" on
    a recommendation that has only been simulated has to pass through approval,
    and the route is read off the table instead of assumed.
    """
    if from_state == to_state:
        return (from_state,)
    frontier: list[tuple[str, ...]] = [(from_state,)]
    seen = {from_state}
    while frontier:
        route = frontier.pop(0)
        for transition in lifecycle.allowed_from(route[-1]):
            if transition.to_state in seen:
                continue
            extended = route + (transition.to_state,)
            if transition.to_state == to_state:
                return extended
            seen.add(transition.to_state)
            frontier.append(extended)
    return ()


def advance(
    lifecycle: Lifecycle,
    recommendation: Mapping[str, object],
    route: Sequence[str],
    *,
    approved_by: str | None = None,
) -> tuple[Transition, ...]:
    """Validate every step of a route without performing it.

    Separated from the write so that a caller about to do something expensive —
    materialise a graph version, re-run discovery — finds out first that the
    lifecycle would have refused it.
    """
    fix_requires_approval = bool(recommendation.get("requires_approval"))
    taken: list[Transition] = []
    current = str(recommendation["state_code"])
    for step in route:
        if step == current:
            continue
        taken.append(
            lifecycle.check(
                current,
                step,
                fix_requires_approval=fix_requires_approval,
                approved_by=approved_by,
            )
        )
        current = step
    return tuple(taken)
