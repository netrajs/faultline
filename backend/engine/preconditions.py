"""Per-precondition evaluation.

A rule's preconditions are a conjunction, and the caller stops at the first one
that fails. That is not an optimisation — it is what makes a refusal
attributable to exactly one condition, which is what lets a rejected candidate
explain itself in one sentence naming one attribute. ``docs/RULES.md`` §4 buys
that property by forbidding disjunction inside a rule: an "A or B" requirement
is written as two rules instead.

Absent attributes
-----------------

The operator set is closed, but the graph is not: most edges carry only a
handful of the attributes some rule somewhere inspects. So the semantics of an
*absent* attribute decide the behaviour of nearly every rule, and the spec fixes
them by example rather than by statement. Working through the cases in
``docs/RULES.md``:

* R9 requires ``mfa_type NOT IN ('fido2', 'webauthn', 'piv')``. Almost no
  authentication edge carries ``mfa_type`` at all, and those edges are the
  ordinary, traversable ones — the whole point of the rule is that
  phishing-resistant MFA is the exception that blocks it. So a missing attribute
  must *satisfy* a negative comparison.
* R7 requires ``storage NOT IN ('vault', 'hsm')`` on the credential. R7 is the
  rule the product exists to demonstrate; if a credential with no recorded
  storage were treated as vault-stored, the rule would refuse almost everything.
  Same conclusion.
* R1 requires ``dst.type = 'security'``, and R4 requires
  ``src.account_status = 'active'``. A group whose type is unrecorded is not
  known to be a security group, and an account whose status is unrecorded is not
  known to be active. Reporting a path through either would be exactly the false
  positive those conditions exist to prevent. So a missing attribute must *fail*
  a positive comparison.

One rule covers both: an absent attribute has no value, so it can never match a
positive comparison and it vacuously satisfies a negative one. ``eq``, ``in``
and the four orderings fail; ``ne`` and ``not_in`` hold.

A consequence worth stating, because it looks like a bug until it is named:
``ne`` is *not* the boolean negation of ``eq`` when the attribute is missing —
both are "safe". That is deliberate. The rule author chooses the direction that
expresses the requirement, and a condition written to block something (``ne
'true'``) does not start blocking everything the moment an attribute is
unrecorded. Where genuine negation is wanted, ``is_negated`` supplies it, and
``exists`` / ``absent`` test presence directly.

An explicit JSON ``null`` is treated as absent for the same reason: it carries
no value to compare against.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from core.model import (
    AttackerState,
    Binding,
    Capability,
    Edge,
    Node,
    Precondition,
    PreconditionKind,
    Rule,
)

OPERATORS = frozenset(
    {"eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "exists", "absent"}
)

#: Operators that need no ``value`` because they test presence alone.
PRESENCE_OPERATORS = frozenset({"exists", "absent"})

#: Operators whose ``value`` must be a sequence of alternatives.
MEMBERSHIP_OPERATORS = frozenset({"in", "not_in"})

#: Operators an absent attribute satisfies vacuously — see the module docstring.
NEGATIVE_OPERATORS = frozenset({"ne", "not_in"})


class _Missing:
    """Sentinel for "this attribute has no value"."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "<absent>"


MISSING = _Missing()


@dataclass(frozen=True, slots=True)
class Refusal:
    """Why one rule did not fire, naming one condition and one observed value."""

    precondition_seq: int
    reason_code: str
    reason_text: str
    observed_value: str | None


def read_attr(attrs: Mapping[str, Any] | None, path: str) -> Any:
    """Read one attribute, returning ``MISSING`` when it has no value.

    Flat lookup first: Neo4j cannot store a nested map on a node, so attributes
    arrive flattened and a dotted path is usually a literal key.
    """
    if not attrs:
        return MISSING
    if path in attrs:
        value = attrs[path]
        return MISSING if value is None else value
    if "." not in path:
        return MISSING

    current: Any = attrs
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return MISSING
        current = current[segment]
    return MISSING if current is None else current


def compare(operator: str, observed: Any, expected: Any) -> bool:
    """Apply one comparison operator, with absent-attribute semantics."""
    if operator not in OPERATORS:
        raise ValueError(f"unknown operator {operator!r}")

    if operator == "exists":
        return observed is not MISSING
    if operator == "absent":
        return observed is MISSING
    if observed is MISSING:
        return operator in NEGATIVE_OPERATORS

    if operator == "eq":
        return _equal(observed, expected)
    if operator == "ne":
        return not _equal(observed, expected)
    if operator == "in":
        return _in(observed, expected)
    if operator == "not_in":
        return not _in(observed, expected)
    return _ordered(operator, observed, expected)


def evaluate(
    precondition: Precondition,
    *,
    state: AttackerState,
    src_node: Node | None,
    dst_node: Node | None,
    edge: Edge | None,
) -> tuple[bool, str | None]:
    """Evaluate one precondition. Returns ``(holds, observed_value)``.

    The observed value is carried out even on success so that a caller can show
    what a condition matched, not only what it refused.
    """
    if precondition.kind is PreconditionKind.CAPABILITY:
        holds, observed = _evaluate_capability(precondition, state, src_node, dst_node)
    else:
        holds, observed = _evaluate_attribute(precondition, src_node, dst_node, edge)

    if precondition.is_negated:
        holds = not holds
    return holds, observed


def first_failure(
    rule: Rule,
    *,
    state: AttackerState,
    src_node: Node | None,
    dst_node: Node | None,
    edge: Edge | None,
) -> Refusal | None:
    """The first precondition of ``rule`` that does not hold, or None.

    Stopping at the first failure is what keeps a refusal attributable to one
    condition. Evaluating all of them and reporting the set would be no more
    correct and considerably less useful: an analyst asks which attribute to
    change, and that question has one answer only if the evaluator gives one.
    """
    for precondition in rule.preconditions:
        holds, observed = evaluate(
            precondition,
            state=state,
            src_node=src_node,
            dst_node=dst_node,
            edge=edge,
        )
        if not holds:
            return Refusal(
                precondition_seq=precondition.seq,
                reason_code=reason_code(precondition),
                reason_text=precondition.failure_reason,
                observed_value=observed,
            )
    return None


def reason_code(precondition: Precondition) -> str:
    """A stable machine code for one kind of refusal.

    Grouped on by the rejections endpoint, so it names the condition rather than
    the rule: "forty refusals turned on ``account_status``" is the useful
    summary, and it is lost if the code is per-rule.
    """
    if precondition.kind is PreconditionKind.CAPABILITY:
        prefix = "forbidden_capability" if precondition.is_negated else "missing_capability"
        return f"{prefix}:{precondition.capability_code}"

    negation = "not_" if precondition.is_negated else ""
    if precondition.kind is PreconditionKind.EDGE_ATTR:
        return f"{negation}edge_attr:{precondition.attr_path}:{precondition.operator}"
    return (
        f"{negation}node_attr:{precondition.binding.value}:"
        f"{precondition.attr_path}:{precondition.operator}"
    )


def bind_node(
    binding: Binding, src_node: Node | None, dst_node: Node | None
) -> Node | None:
    if binding is Binding.SRC:
        return src_node
    if binding is Binding.DST:
        return dst_node
    return None


def _evaluate_capability(
    precondition: Precondition,
    state: AttackerState,
    src_node: Node | None,
    dst_node: Node | None,
) -> tuple[bool, str | None]:
    code = precondition.capability_code or ""
    if precondition.binding is Binding.GLOBAL:
        return state.holds(code), None

    node = bind_node(precondition.binding, src_node, dst_node)
    if node is None:
        return False, None

    held = state.holds(code, node.node_id)
    # What the attacker does hold about that node is the useful thing to show
    # when they do not hold the required one. Decoy D8 turns on exactly this:
    # the decoy and its twin are structurally identical and differ only in
    # whether the state carries admin_on or merely access_to.
    observed = ",".join(
        sorted(c.code for c in state.capabilities if c.about == node.node_id)
    )
    return held, observed or "none"


def _evaluate_attribute(
    precondition: Precondition,
    src_node: Node | None,
    dst_node: Node | None,
    edge: Edge | None,
) -> tuple[bool, str | None]:
    path = precondition.attr_path or ""
    if precondition.kind is PreconditionKind.EDGE_ATTR:
        attrs = edge.attrs if edge is not None else None
    else:
        node = bind_node(precondition.binding, src_node, dst_node)
        attrs = node.attrs if node is not None else None

    observed = read_attr(attrs, path)
    holds = compare(precondition.operator or "", observed, precondition.value)
    return holds, None if observed is MISSING else _render(observed)


def _equal(observed: Any, expected: Any) -> bool:
    # Python makes True == 1, which would let a boolean attribute satisfy a
    # numeric comparison and vice versa. Booleans are a distinct domain here.
    if isinstance(observed, bool) != isinstance(expected, bool):
        return False
    if isinstance(observed, (int, float)) and isinstance(expected, (int, float)):
        return float(observed) == float(expected)
    return observed == expected


def _in(observed: Any, expected: Any) -> bool:
    if isinstance(expected, (list, tuple, set, frozenset)):
        return any(_equal(observed, candidate) for candidate in expected)
    return _equal(observed, expected)


def _ordered(operator: str, observed: Any, expected: Any) -> bool:
    numeric = (
        isinstance(observed, (int, float))
        and not isinstance(observed, bool)
        and isinstance(expected, (int, float))
        and not isinstance(expected, bool)
    )
    if numeric:
        left, right = float(observed), float(expected)
    elif isinstance(observed, str) and isinstance(expected, str):
        left, right = observed, expected
    else:
        # Incomparable operands are a failed comparison, not an exception. A
        # malformed attribute on one node must not abort a whole run.
        return False

    if operator == "lt":
        return left < right
    if operator == "lte":
        return left <= right
    if operator == "gt":
        return left > right
    return left >= right


def _render(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return repr(round(value, 9))
    return str(value)[:255]
