"""The precondition evaluator.

Most of these are about absent attributes, because that is where the semantics
are decided by the specification's examples rather than stated outright, and
where getting it backwards makes the engine either refuse almost everything or
accept almost everything.
"""

from __future__ import annotations

import pytest

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
from engine.preconditions import MISSING, compare, evaluate, first_failure, read_attr


def cap_precondition(
    code: str, binding: Binding = Binding.SRC, *, seq: int = 1, negated: bool = False
) -> Precondition:
    return Precondition(
        seq=seq,
        kind=PreconditionKind.CAPABILITY,
        binding=binding,
        capability_code=code,
        attr_path=None,
        operator=None,
        value=None,
        is_negated=negated,
        failure_reason=f"needs {code}",
    )


def attr_precondition(
    kind: PreconditionKind,
    binding: Binding,
    path: str,
    operator: str,
    value=None,
    *,
    seq: int = 1,
    negated: bool = False,
) -> Precondition:
    return Precondition(
        seq=seq,
        kind=kind,
        binding=binding,
        capability_code=None,
        attr_path=path,
        operator=operator,
        value=value,
        is_negated=negated,
        failure_reason=f"{path} {operator} {value!r} does not hold",
    )


SRC = Node("h-1", "Host", "host-one", attrs={"patch_level": "behind-2+", "count": 3})
DST = Node("cred-1", "Credential", "cred-one", attrs={"storage": "config_file", "is_active": True})
EDGE = Edge("e-1", "h-1", "cred-1", "EXPOSES_CREDENTIAL", attrs={"location": "config_file", "discoverable": 0.8})
STATE = AttackerState("h-1", frozenset({Capability("admin_on", "h-1"), Capability("authenticated", None)}))


def evaluate_attr(precondition: Precondition) -> bool:
    holds, _ = evaluate(precondition, state=STATE, src_node=SRC, dst_node=DST, edge=EDGE)
    return holds


# ── Operators ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("operator", "observed", "expected", "result"),
    [
        ("eq", "admin", "admin", True),
        ("eq", "admin", "read_only", False),
        ("ne", "admin", "read_only", True),
        ("ne", "admin", "admin", False),
        ("lt", 3, 5, True),
        ("lt", 5, 3, False),
        ("lte", 5, 5, True),
        ("gt", 0.8, 0.7, True),
        ("gte", 0.7, 0.7, True),
        ("gte", 0.6, 0.7, False),
        ("in", "sms", ["sms", "push"], True),
        ("in", "fido2", ["sms", "push"], False),
        ("not_in", "config_file", ["vault", "hsm"], True),
        ("not_in", "vault", ["vault", "hsm"], False),
        ("exists", "anything", None, True),
        ("absent", "anything", None, False),
    ],
)
def test_every_operator(operator, observed, expected, result):
    assert compare(operator, observed, expected) is result


def test_unknown_operator_raises():
    with pytest.raises(ValueError, match="unknown operator"):
        compare("matches", "a", "a")


def test_booleans_are_not_numbers():
    """``True == 1`` in Python, and a boolean attribute is not a count."""
    assert compare("eq", True, 1) is False
    assert compare("eq", 1, True) is False
    assert compare("eq", True, True) is True


def test_integers_and_floats_compare_across_types():
    assert compare("eq", 90, 90.0) is True
    assert compare("gt", 200, 90) is True


def test_incomparable_operands_fail_rather_than_raise():
    """One malformed attribute must not abort a whole discovery run."""
    assert compare("gt", "behind-2+", 90) is False


# ── Absent attributes ────────────────────────────────────────────────────────


@pytest.mark.parametrize("operator", ["eq", "in", "lt", "lte", "gt", "gte"])
def test_absent_attribute_fails_a_positive_comparison(operator):
    """R1's ``type = 'security'`` and R4's ``account_status = 'active'``.

    A group whose type is unrecorded is not known to be a security group, so
    traversing it is the false positive the condition exists to prevent.
    """
    assert compare(operator, MISSING, "security") is False


@pytest.mark.parametrize("operator", ["ne", "not_in"])
def test_absent_attribute_satisfies_a_negative_comparison(operator):
    """R7's ``storage != 'vault'`` and R9's ``mfa_type NOT IN (...)``.

    Almost no authentication edge records an MFA type, and those edges are the
    traversable ones. Treating a missing attribute as a block would refuse
    nearly every path in the graph.
    """
    assert compare(operator, MISSING, ["vault", "hsm"]) is True


def test_ne_is_not_the_negation_of_eq_when_the_attribute_is_missing():
    """Both directions are safe, which is deliberate rather than inconsistent.

    A condition written to block something must not start blocking everything
    the moment an attribute goes unrecorded.
    """
    assert compare("eq", MISSING, "vault") is False
    assert compare("ne", MISSING, "vault") is True


def test_explicit_null_reads_as_absent():
    assert read_attr({"storage": None}, "storage") is MISSING
    assert compare("exists", read_attr({"storage": None}, "storage"), None) is False


def test_dotted_path_walks_a_nested_document():
    assert read_attr({"posture": {"patch_level": "current"}}, "posture.patch_level") == "current"
    assert read_attr({"posture": {}}, "posture.patch_level") is MISSING


def test_flat_key_wins_over_dotted_walk():
    """Neo4j cannot hold a nested map, so attributes arrive flattened."""
    assert read_attr({"posture.patch_level": "behind-2+"}, "posture.patch_level") == "behind-2+"


# ── Kinds, bindings and negation ─────────────────────────────────────────────


def test_capability_binding_resolves_to_the_bound_node():
    assert evaluate_attr(cap_precondition("admin_on", Binding.SRC)) is True
    assert evaluate_attr(cap_precondition("admin_on", Binding.DST)) is False


def test_global_capability_ignores_both_endpoints():
    assert evaluate_attr(cap_precondition("authenticated", Binding.GLOBAL)) is True
    assert evaluate_attr(cap_precondition("code_exec_on", Binding.GLOBAL)) is False


def test_capability_refusal_reports_what_is_held_instead():
    """Decoy D8 turns on state, not on any graph attribute."""
    state = AttackerState("h-1", frozenset({Capability("access_to", "h-1")}))
    holds, observed = evaluate(
        cap_precondition("admin_on"), state=state, src_node=SRC, dst_node=DST, edge=EDGE
    )
    assert holds is False
    assert observed == "access_to"


def test_edge_and_node_attribute_kinds_read_different_objects():
    assert evaluate_attr(
        attr_precondition(PreconditionKind.EDGE_ATTR, Binding.SRC, "location", "eq", "config_file")
    ) is True
    assert evaluate_attr(
        attr_precondition(PreconditionKind.NODE_ATTR, Binding.SRC, "location", "eq", "config_file")
    ) is False
    assert evaluate_attr(
        attr_precondition(PreconditionKind.NODE_ATTR, Binding.DST, "storage", "eq", "config_file")
    ) is True


def test_negation_inverts_the_condition():
    positive = attr_precondition(
        PreconditionKind.NODE_ATTR, Binding.SRC, "patch_level", "eq", "behind-2+"
    )
    negated = attr_precondition(
        PreconditionKind.NODE_ATTR, Binding.SRC, "patch_level", "eq", "behind-2+", negated=True
    )
    assert evaluate_attr(positive) is True
    assert evaluate_attr(negated) is False


# ── Attribution ──────────────────────────────────────────────────────────────


def rule_with(*preconditions: Precondition) -> Rule:
    return Rule(
        rule_id=99,
        code="test_rule",
        technique_code="credential_in_files",
        edge_type="EXPOSES_CREDENTIAL",
        description="",
        is_traversal=True,
        preconditions=preconditions,
        effects=(),
    )


def test_first_failure_stops_at_the_first_unmet_condition():
    """A refusal must be attributable to exactly one condition (RULES.md §4)."""
    rule = rule_with(
        cap_precondition("admin_on", seq=1),
        attr_precondition(
            PreconditionKind.NODE_ATTR, Binding.DST, "storage", "not_in", ["config_file"], seq=2
        ),
        attr_precondition(
            PreconditionKind.NODE_ATTR, Binding.DST, "is_active", "ne", False, seq=3
        ),
    )
    refusal = first_failure(rule, state=STATE, src_node=SRC, dst_node=DST, edge=EDGE)
    assert refusal is not None
    assert refusal.precondition_seq == 2
    assert refusal.observed_value == "config_file"
    assert refusal.reason_code == "node_attr:dst:storage:not_in"


def test_first_failure_returns_none_when_every_condition_holds():
    rule = rule_with(
        cap_precondition("admin_on", seq=1),
        attr_precondition(
            PreconditionKind.NODE_ATTR, Binding.DST, "storage", "not_in", ["vault", "hsm"], seq=2
        ),
    )
    assert first_failure(rule, state=STATE, src_node=SRC, dst_node=DST, edge=EDGE) is None


def test_reason_code_names_the_condition_not_the_rule():
    """The rejections view groups on this, so it has to aggregate across rules."""
    refusal = first_failure(
        rule_with(cap_precondition("code_exec_on")),
        state=STATE,
        src_node=SRC,
        dst_node=DST,
        edge=EDGE,
    )
    assert refusal is not None
    assert refusal.reason_code == "missing_capability:code_exec_on"
