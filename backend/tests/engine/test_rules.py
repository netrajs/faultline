"""The ruleset loader.

Rules are data, so they can be wrong in ways careful searching cannot survive.
Every test here is a malformed row set that must fail loudly at load rather than
quietly under-report at search time.
"""

from __future__ import annotations

import pytest

from core.model import Binding, PreconditionKind
from engine.rules import RulesetError, build_ruleset, decode_json

from conftest import (
    CAPABILITY_ROWS,
    EFFECT_ROWS,
    GRANT_ROWS,
    PRECONDITION_ROWS,
    RULE_ROWS,
    TECHNIQUE_ROWS,
    THREAT_MODEL_ROWS,
    make_ruleset,
)


def load(**overrides):
    rows = {
        "rule_rows": RULE_ROWS,
        "precondition_rows": PRECONDITION_ROWS,
        "effect_rows": EFFECT_ROWS,
        "technique_rows": TECHNIQUE_ROWS,
        "capability_rows": CAPABILITY_ROWS,
        "threat_model_rows": THREAT_MODEL_ROWS,
        "grant_rows": GRANT_ROWS,
    }
    rows.update(overrides)
    return build_ruleset(**rows)


def test_the_seeded_shape_loads():
    ruleset = make_ruleset()
    assert len(ruleset.rules) == len(RULE_ROWS)
    assert ruleset.rule_by_code("kerberoast").is_traversal is False
    assert ruleset.rule_by_code("credential_dump").edge_type == "EXPOSES_CREDENTIAL"


def test_rules_are_ordered_by_the_stored_sort_order():
    """Evaluation order is part of the output, so it cannot come from a dict."""
    ruleset = make_ruleset()
    assert [rule.code for rule in ruleset.rules[:3]] == [
        "group_membership",
        "group_permission_admin",
        "group_permission_access",
    ]


def test_preconditions_are_ordered_by_seq():
    rule = make_ruleset().rule_by_code("credential_dump")
    assert [p.seq for p in rule.preconditions] == [1, 2, 3, 4]
    assert rule.preconditions[0].kind is PreconditionKind.CAPABILITY


def test_indexes_separate_traversal_from_state_only_rules():
    ruleset = make_ruleset()
    assert [rule.code for rule in ruleset.non_traversal] == ["kerberoast"]
    assert {rule.code for rule in ruleset.traversal_by_edge_type["EXPOSES_CREDENTIAL"]} == {
        "credential_dump",
        "credential_public",
    }


def test_a_rule_with_no_capability_precondition_is_indexed_as_unconditional():
    """R8 is the one that must stay reachable with no identity at all."""
    assert [rule.code for rule in make_ruleset().unconditional] == ["credential_public"]


def test_disabled_rules_are_dropped():
    rows = [dict(row) for row in RULE_ROWS]
    rows[0]["is_enabled"] = 0
    ruleset = load(rule_rows=rows)
    assert all(rule.code != "group_membership" for rule in ruleset.rules)


def test_a_rule_with_no_effects_is_rejected():
    effects = [row for row in EFFECT_ROWS if row["rule_id"] != 7]
    with pytest.raises(RulesetError, match="no effects"):
        load(effect_rows=effects)


def test_a_traversal_rule_with_no_edge_type_is_rejected():
    rows = [dict(row) for row in RULE_ROWS]
    rows[0]["edge_type_code"] = None
    with pytest.raises(RulesetError, match="names no edge type"):
        load(rule_rows=rows)


def test_a_non_traversal_rule_naming_an_edge_type_is_rejected():
    rows = [dict(row) for row in RULE_ROWS]
    rows[9]["edge_type_code"] = "MEMBER_OF"
    with pytest.raises(RulesetError, match="marked non-traversal but names edge type"):
        load(rule_rows=rows)


def test_an_edge_attribute_precondition_on_a_non_traversal_rule_is_rejected():
    rows = list(PRECONDITION_ROWS) + [
        {
            "rule_id": 10,
            "seq": 4,
            "kind": "edge_attr",
            "binding": "src",
            "capability_code": None,
            "attr_path": "scope",
            "operator": "eq",
            "value_json": '"admin"',
            "is_negated": 0,
            "failure_reason": "no",
        }
    ]
    with pytest.raises(RulesetError, match="consumes no edge"):
        load(precondition_rows=rows)


def test_a_src_binding_on_a_non_traversal_rule_is_rejected():
    """A rule that traverses nothing has one node, and it is bound as dst."""
    rows = [dict(row) for row in EFFECT_ROWS]
    for row in rows:
        if row["rule_id"] == 10:
            row["binding"] = "src"
    with pytest.raises(RulesetError, match="has no source"):
        load(effect_rows=rows)


def test_a_node_scoped_capability_bound_globally_is_rejected():
    rows = [dict(row) for row in PRECONDITION_ROWS]
    rows[0]["binding"] = "global"
    with pytest.raises(RulesetError, match="bound globally"):
        load(precondition_rows=rows)


def test_a_global_capability_bound_to_an_endpoint_is_rejected():
    rows = [dict(row) for row in PRECONDITION_ROWS]
    for row in rows:
        if row["rule_id"] == 10 and row["seq"] == 1:
            row["binding"] = "dst"
    with pytest.raises(RulesetError, match="globally-scoped capability bound to dst"):
        load(precondition_rows=rows)


def test_a_membership_operator_without_a_list_is_rejected():
    rows = [dict(row) for row in PRECONDITION_ROWS]
    for row in rows:
        if row["rule_id"] == 7 and row["seq"] == 2:
            row["value_json"] = '"vault"'
    with pytest.raises(RulesetError, match="needs a list of alternatives"):
        load(precondition_rows=rows)


def test_a_comparison_without_a_value_is_rejected():
    rows = [dict(row) for row in PRECONDITION_ROWS]
    for row in rows:
        if row["rule_id"] == 1 and row["seq"] == 3:
            row["value_json"] = None
    with pytest.raises(RulesetError, match="needs a value"):
        load(precondition_rows=rows)


def test_an_unknown_operator_is_rejected():
    rows = [dict(row) for row in PRECONDITION_ROWS]
    for row in rows:
        if row["rule_id"] == 1 and row["seq"] == 3:
            row["operator"] = "matches"
    with pytest.raises(RulesetError, match="unknown operator"):
        load(precondition_rows=rows)


def test_a_refusal_with_no_explanation_is_rejected():
    rows = [dict(row) for row in PRECONDITION_ROWS]
    rows[0]["failure_reason"] = ""
    with pytest.raises(RulesetError, match="could not explain itself"):
        load(precondition_rows=rows)


def test_a_threat_model_granting_nothing_is_rejected():
    grants = [row for row in GRANT_ROWS if row["threat_model_code"] != "public_only"]
    with pytest.raises(RulesetError, match="grants nothing"):
        load(grant_rows=grants)


def test_an_unknown_threat_model_names_the_ones_that_exist():
    with pytest.raises(KeyError, match="external_phish"):
        make_ruleset().threat_model("nation_state")


def test_threat_model_grants_keep_their_declared_order():
    """Order distinguishes the entry grant from the ambient ones."""
    grants = make_ruleset().threat_model("insider_standard").grants
    assert [grant[0] for grant in grants] == [
        "authenticated",
        "controls_principal",
        "network_reach",
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('"admin"', "admin"),
        ("false", False),
        ("90", 90),
        ('["vault","hsm"]', ["vault", "hsm"]),
        (None, None),
        ("admin", "admin"),
        (b'"admin"', "admin"),
        (["already", "decoded"], ["already", "decoded"]),
    ],
)
def test_value_json_decoding_accepts_both_shapes(raw, expected):
    """Whether a JSON column arrives decoded depends on the driver."""
    assert decode_json(raw) == expected


def test_bindings_are_parsed_into_the_shared_enum():
    rule = make_ruleset().rule_by_code("kerberoast")
    assert rule.preconditions[0].binding is Binding.GLOBAL
    assert rule.effects[0].binding is Binding.DST
