"""Generic evaluation of one ``rule_precondition`` row.

Three kinds (``capability``, ``edge_attr``, ``node_attr``), ten operators
(``eq``, ``ne``, ``lt``, ``lte``, ``gt``, ``gte``, ``in``, ``not_in``,
``exists``, ``absent``), three bindings (``src``, ``dst``, ``global``) and a
negation flag. Nothing here knows the name of any rule. If a change to this file
would be described as "make R7 work", it is the wrong change: the rules are
rows, and this module interprets rows.

Preconditions are conjunctive and the caller stops at the first failure, because
``docs/RULES.md`` §4 wants every refusal attributable to exactly one unmet
condition.


================================================================================
DECISION: what a MISSING attribute means
================================================================================

``docs/RULES.md`` never says what happens when an attribute a precondition names
is simply not present on the node or edge. This matters immediately and in both
directions, so the oracle has to pick something and be consistent.

The rule adopted here:

    An absent attribute has no value. A comparison that ASSERTS the attribute
    holds some particular value is FALSE; a comparison that asserts it does NOT
    hold some particular value is TRUE.

        eq, in, lt, lte, gt, gte, exists   ->  False when the attribute is absent
        ne, not_in, absent                 ->  True  when the attribute is absent

An explicit JSON ``null`` is treated identically to an absent key. A key present
with the value ``null`` carries no more information than a key that is not there.

**Why this assignment and not another.** It is the only one under which the
operator pairs stay exact complements over every input, absence included:

        ne      ==  NOT eq
        not_in  ==  NOT in
        absent  ==  NOT exists

That property is load-bearing, because ``rule_precondition.is_negated`` lets a
row negate any operator. If ``ne`` were not the exact complement of ``eq`` on
absent attributes, then ``eq`` with ``is_negated = 1`` and ``ne`` with
``is_negated = 0`` — two spellings a rule author would reasonably expect to mean
the same thing — would disagree, and which one a rule used would silently change
its meaning.

**Check it against the seeded rules.** The alternative (absent attribute fails
every comparison) breaks the model outright:

  * R9 requires ``mfa_type not_in ('fido2','webauthn','piv')``. An
    ``AUTHENTICATES_TO`` edge with no MFA at all carries no ``mfa_type`` key. No
    MFA is obviously not phishing-resistant MFA, so the rule must fire. Under
    the alternative, every unauthenticated-by-MFA login in the graph becomes
    unreachable and the engine reports almost nothing.
  * R7 requires ``location not_in ('vault','hsm')`` and
    ``storage not_in ('vault','hsm')``. Same argument.
  * R6, R7, R8 require ``is_active ne false``. A credential with no
    ``is_active`` key has not been rotated.

And in the other direction:

  * R10 requires ``has_spn eq true``. The oracle offers every node in the graph
    as a kerberoast target; ``has_spn`` is what filters that down to SPN-bearing
    service accounts. If an absent ``has_spn`` satisfied the row, every node in
    the graph would be kerberoastable.
  * R1 requires ``dst.type eq 'security'``. A group with no declared type is not
    evidence of a security group.

**The cost, stated plainly.** The rule is fail-open for negative assertions.
R12's ``patch_level ne 'current'`` means a host with no recorded patch level is
treated as unpatched and therefore exploitable — a false positive, which is the
failure mode this project is built to avoid. There is no assignment that avoids
both that and the R9 catastrophe above, so the burden falls on the graph
generator: emit ``patch_level`` explicitly on every host that can carry a
``HAS_VULNERABILITY`` edge. ``docs/RULES.md`` should say so.

================================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from core.model import Binding, Capability, Edge, Node, Precondition, PreconditionKind

__all__ = [
    "MISSING",
    "OPERATORS",
    "PreconditionOutcome",
    "PreconditionEvaluationError",
    "compare",
    "describe_capability",
    "evaluate_precondition",
    "resolve_capability",
]


class _Missing:
    """Sentinel for "this attribute is not present"."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING = _Missing()


class PreconditionEvaluationError(RuntimeError):
    """A precondition row cannot be evaluated at all.

    Raised rather than swallowed. A row that names a binding the transition does
    not have is a defect in the rule data, and an oracle that quietly returned
    ``False`` would turn that defect into a silently missing attack path.
    """


# ── Operators ────────────────────────────────────────────────────────────────
#
# Each entry is (needs_value, absent_result, comparator). ``absent_result`` is
# the value the operator takes when the observed attribute is missing — see the
# module docstring for why these are what they are. ``comparator`` is only ever
# called with a present observed value.


def _is_number(value: Any) -> bool:
    # bool is a subclass of int in Python. Treating True as the number 1 would
    # make `mfa_required gte 1` quietly true, so booleans are excluded here and
    # compared only against other booleans.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _equal(observed: Any, expected: Any) -> bool:
    """Equality that does not confuse booleans with numbers.

    ``True == 1`` in Python. JSON has both, the graph attributes carry both, and
    a rule that says ``mfa_required eq true`` must not be satisfied by the
    integer 1.
    """
    if isinstance(observed, bool) or isinstance(expected, bool):
        return isinstance(observed, bool) and isinstance(expected, bool) and observed == expected
    if _is_number(observed) and _is_number(expected):
        return float(observed) == float(expected)
    return bool(observed == expected)


def _ordered(observed: Any, expected: Any, which: str) -> bool:
    """Ordered comparison over two numbers or two strings, never across types.

    A mismatch returns False rather than raising. The observed value comes from
    graph data, so a type mismatch is bad data rather than a bad rule, and the
    rejection that results names the attribute and its actual value — which is
    more useful to whoever has to fix it than a traceback from inside the search.
    """
    both_numeric = _is_number(observed) and _is_number(expected)
    both_text = isinstance(observed, str) and isinstance(expected, str)
    if not (both_numeric or both_text):
        return False
    if which == "lt":
        return observed < expected
    if which == "lte":
        return observed <= expected
    if which == "gt":
        return observed > expected
    return observed >= expected


def _contains(observed: Any, expected: Any) -> bool:
    if not isinstance(expected, (list, tuple)):
        raise PreconditionEvaluationError(
            f"operator 'in'/'not_in' needs a list value, got {expected!r}"
        )
    return any(_equal(observed, candidate) for candidate in expected)


#: operator -> (requires a value_json, result when the attribute is absent, comparator)
OPERATORS: Mapping[str, tuple[bool, bool, Any]] = {
    "eq": (True, False, _equal),
    "ne": (True, True, lambda o, e: not _equal(o, e)),
    "lt": (True, False, lambda o, e: _ordered(o, e, "lt")),
    "lte": (True, False, lambda o, e: _ordered(o, e, "lte")),
    "gt": (True, False, lambda o, e: _ordered(o, e, "gt")),
    "gte": (True, False, lambda o, e: _ordered(o, e, "gte")),
    "in": (True, False, _contains),
    "not_in": (True, True, lambda o, e: not _contains(o, e)),
    "exists": (False, False, lambda o, e: True),
    "absent": (False, True, lambda o, e: False),
}


def compare(observed: Any, operator: str, expected: Any) -> bool:
    """Apply one operator. ``observed`` may be :data:`MISSING`."""
    try:
        _, absent_result, comparator = OPERATORS[operator]
    except KeyError:
        raise PreconditionEvaluationError(f"unknown operator {operator!r}") from None
    if observed is MISSING or observed is None:
        return absent_result
    return bool(comparator(observed, expected))


# ── Attribute lookup ─────────────────────────────────────────────────────────


def _read_attr(attrs: Mapping[str, Any] | None, path: str) -> Any:
    """Read a dotted path out of an attributes document.

    ``rule_precondition.attr_path`` is documented as a dotted path into the
    attrs JSON. Every seeded row is a single segment today, but the schema
    permits nesting, so nesting is supported rather than assumed away.
    """
    if attrs is None:
        return MISSING
    current: Any = attrs
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return MISSING
        current = current[segment]
    return MISSING if current is None else current


# ── Bindings ─────────────────────────────────────────────────────────────────


def resolve_capability(
    precondition_or_effect_code: str,
    binding: Binding,
    *,
    atom_is_global: bool,
    src_id: str | None,
    dst_id: str | None,
) -> Capability:
    """Turn a (capability code, binding) pair into the concrete capability.

    The atom's own ``binding_kind`` wins over the row's ``binding`` column. A
    globally-scoped atom such as ``authenticated`` is held outright and is never
    held "about" a node, whatever a row happens to say — one representation of
    it, so a global capability granted by a threat model and the same capability
    tested by a rule are the same object.
    """
    if atom_is_global:
        return Capability(precondition_or_effect_code, None)
    if binding == Binding.SRC:
        node_id = src_id
    elif binding == Binding.DST:
        node_id = dst_id
    else:
        raise PreconditionEvaluationError(
            f"capability {precondition_or_effect_code!r} is node-scoped but bound "
            f"'global'; there is no node for it to be about"
        )
    if node_id is None:
        raise PreconditionEvaluationError(
            f"capability {precondition_or_effect_code!r} is bound to "
            f"{binding.value!r}, which this transition does not have"
        )
    return Capability(precondition_or_effect_code, node_id)


def describe_capability(capability: Capability, held: bool) -> str:
    return f"{capability}={'held' if held else 'absent'}"


# ── Evaluation ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PreconditionOutcome:
    holds: bool
    observed: str | None
    """Human-readable rendering of what was actually found, for the rejection."""


def _render(value: Any) -> str:
    if value is MISSING:
        return "<absent>"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return repr(value)


def evaluate_precondition(
    precondition: Precondition,
    *,
    capabilities: frozenset[Capability],
    edge: Edge | None,
    src_node: Node | None,
    dst_node: Node | None,
    global_capability_codes: frozenset[str],
) -> PreconditionOutcome:
    """Evaluate one precondition row against one candidate transition.

    ``global_capability_codes`` is the set of ``capability_atom`` codes whose
    ``binding_kind`` is ``global``; it comes from the database, so this function
    does not need to know that ``authenticated`` is the global one.
    """
    kind = precondition.kind
    negate = precondition.is_negated

    if kind == PreconditionKind.CAPABILITY:
        if precondition.capability_code is None:
            raise PreconditionEvaluationError(
                f"precondition seq {precondition.seq} is kind 'capability' but names no "
                f"capability_code"
            )
        capability = resolve_capability(
            precondition.capability_code,
            precondition.binding,
            atom_is_global=precondition.capability_code in global_capability_codes,
            src_id=src_node.node_id if src_node else None,
            dst_id=dst_node.node_id if dst_node else None,
        )
        held = capability in capabilities
        result = held != negate
        return PreconditionOutcome(result, describe_capability(capability, held))

    if precondition.attr_path is None or precondition.operator is None:
        raise PreconditionEvaluationError(
            f"precondition seq {precondition.seq} is kind {kind} but names no "
            f"attr_path/operator"
        )

    if kind == PreconditionKind.EDGE_ATTR:
        if edge is None:
            # A non-traversal rule consumes no edge, so an edge_attr row on one
            # can never be satisfied. That is a rule-data defect, not a graph
            # fact, so it is loud.
            raise PreconditionEvaluationError(
                f"precondition seq {precondition.seq} reads edge attribute "
                f"{precondition.attr_path!r} but this transition traverses no edge"
            )
        # binding is documented as ignored for edge_attr: the attribute belongs
        # to the traversed edge, which has only one attrs document.
        observed = _read_attr(edge.attrs, precondition.attr_path)
        location = f"edge.{precondition.attr_path}"
    elif kind == PreconditionKind.NODE_ATTR:
        if precondition.binding == Binding.SRC:
            node = src_node
        elif precondition.binding == Binding.DST:
            node = dst_node
        else:
            raise PreconditionEvaluationError(
                f"precondition seq {precondition.seq} reads a node attribute bound "
                f"'global'; there is no node to read it from"
            )
        if node is None:
            raise PreconditionEvaluationError(
                f"precondition seq {precondition.seq} is bound to "
                f"{precondition.binding.value!r}, which this transition does not have"
            )
        observed = _read_attr(node.attrs, precondition.attr_path)
        location = f"{precondition.binding.value}.{precondition.attr_path}"
    else:  # pragma: no cover - PreconditionKind is closed
        raise PreconditionEvaluationError(f"unknown precondition kind {kind!r}")

    raw = compare(observed, precondition.operator, precondition.value)
    return PreconditionOutcome(raw != negate, f"{location}={_render(observed)}")


def validate_precondition(precondition: Precondition) -> None:
    """Reject a malformed row at load time rather than mid-search.

    A rule row with ``operator = 'in'`` and a scalar value would otherwise
    surface as an exception thrown from deep inside the search, at whichever
    graph happened to reach it first.
    """
    kind = precondition.kind
    if kind == PreconditionKind.CAPABILITY:
        if not precondition.capability_code:
            raise PreconditionEvaluationError(
                f"seq {precondition.seq}: kind 'capability' needs capability_code"
            )
        if precondition.operator or precondition.attr_path:
            raise PreconditionEvaluationError(
                f"seq {precondition.seq}: kind 'capability' must not carry an "
                f"operator or attr_path"
            )
        return

    if not precondition.attr_path:
        raise PreconditionEvaluationError(f"seq {precondition.seq}: {kind} needs attr_path")
    if precondition.operator not in OPERATORS:
        raise PreconditionEvaluationError(
            f"seq {precondition.seq}: unknown operator {precondition.operator!r}"
        )
    needs_value, _, _ = OPERATORS[precondition.operator]
    if needs_value and precondition.value is None:
        raise PreconditionEvaluationError(
            f"seq {precondition.seq}: operator {precondition.operator!r} needs a value_json"
        )
    if not needs_value and precondition.value is not None:
        raise PreconditionEvaluationError(
            f"seq {precondition.seq}: operator {precondition.operator!r} takes no value_json"
        )
    if precondition.operator in ("in", "not_in") and not isinstance(
        precondition.value, (list, tuple)
    ):
        raise PreconditionEvaluationError(
            f"seq {precondition.seq}: operator {precondition.operator!r} needs a list "
            f"value, got {precondition.value!r}"
        )
    if kind == PreconditionKind.NODE_ATTR and precondition.binding == Binding.GLOBAL:
        raise PreconditionEvaluationError(
            f"seq {precondition.seq}: node_attr cannot be bound 'global'"
        )


def sequence_of(preconditions: Sequence[Precondition]) -> tuple[Precondition, ...]:
    """Preconditions in evaluation order: ascending ``seq``.

    Order is observable, because the first failure is the one reported. Two runs
    must attribute a refusal to the same row.
    """
    return tuple(sorted(preconditions, key=lambda p: p.seq))
