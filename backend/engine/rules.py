"""Loading and validating the attacker model.

The rules are data. Adding a technique is an INSERT, and both this engine and
the reference oracle read the same rows — which is what lets them disagree
loudly in a test when one of them has misread the specification.

Because the rules are data, they can be malformed in ways no amount of careful
searching will survive: a rule with no effects grants nothing and silently
contributes nothing; a non-traversal rule carrying an edge-attribute
precondition asks about an edge that does not exist; a capability precondition
naming a node-scoped atom with a ``global`` binding is a category error. All of
those are validated at load, with the row named, rather than surfacing later as
a missing path nobody can account for. A ruleset that does not load is a far
cheaper failure than one that loads and quietly under-reports.

Written from ``docs/RULES.md`` and the migration DDL. It shares no code with
``backend/oracle``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from core.model import (
    Binding,
    Effect,
    Precondition,
    PreconditionKind,
    Rule,
    Technique,
    ThreatModel,
)
from engine.preconditions import (
    MEMBERSHIP_OPERATORS,
    OPERATORS,
    PRESENCE_OPERATORS,
)

Row = Mapping[str, Any]


class RulesetError(ValueError):
    """A rule row set that cannot be trusted to search with."""


@dataclass(frozen=True, slots=True)
class RuleSet:
    """The loaded attacker model, indexed the way the search consumes it."""

    rules: tuple[Rule, ...]
    techniques: Mapping[str, Technique]
    threat_models: Mapping[str, ThreatModel]
    capability_bindings: Mapping[str, str]
    """capability code -> 'node' or 'global'."""

    traversal_by_edge_type: Mapping[str, tuple[Rule, ...]]
    non_traversal: tuple[Rule, ...]
    unconditional: tuple[Rule, ...]
    """Traversal rules with no capability precondition at all.

    R8 is the only one in the shipped model, and it is deliberate: a secret in a
    public repository requires nothing whatsoever, which is precisely why it is
    catastrophic and why it must stay reachable from the ``public_only`` threat
    model. The search has to offer these from every state rather than only from
    nodes the attacker has already touched, so they are indexed separately.
    """

    def rule_by_code(self, code: str) -> Rule:
        for rule in self.rules:
            if rule.code == code:
                return rule
        raise KeyError(code)

    def threat_model(self, code: str) -> ThreatModel:
        try:
            return self.threat_models[code]
        except KeyError:
            known = ", ".join(sorted(self.threat_models))
            raise KeyError(f"unknown threat model {code!r}; known: {known}") from None


def build_ruleset(
    *,
    rule_rows: Iterable[Row],
    precondition_rows: Iterable[Row],
    effect_rows: Iterable[Row],
    technique_rows: Iterable[Row],
    capability_rows: Iterable[Row],
    threat_model_rows: Iterable[Row],
    grant_rows: Iterable[Row],
) -> RuleSet:
    """Assemble and validate a ruleset from raw rows.

    Pure, so the test suite exercises the same validation and indexing the
    production path uses without needing either store running.
    """
    capabilities = {
        str(row["code"]): str(row["binding_kind"]) for row in capability_rows
    }
    techniques = {
        str(row["code"]): Technique(
            code=str(row["code"]),
            name=str(row["name"]),
            description=str(row.get("description") or ""),
            attack_id=_opt_str(row.get("attack_id")),
            attack_name=_opt_str(row.get("attack_name")),
            attack_url=_opt_str(row.get("attack_url")),
            phase=str(row.get("phase") or ""),
        )
        for row in technique_rows
    }

    preconditions_by_rule: dict[int, list[Precondition]] = {}
    for row in precondition_rows:
        rule_id = int(row["rule_id"])
        preconditions_by_rule.setdefault(rule_id, []).append(_precondition(row))

    effects_by_rule: dict[int, list[Effect]] = {}
    for row in effect_rows:
        rule_id = int(row["rule_id"])
        effects_by_rule.setdefault(rule_id, []).append(
            Effect(
                seq=int(row["seq"]),
                capability_code=str(row["capability_code"]),
                binding=Binding(str(row.get("binding") or "dst")),
            )
        )

    rules: list[Rule] = []
    for row in sorted(
        (r for r in rule_rows if _truthy(r.get("is_enabled", 1))),
        key=lambda r: (int(r.get("sort_order") or 0), int(r["id"])),
    ):
        rule_id = int(row["id"])
        rule = Rule(
            rule_id=rule_id,
            code=str(row["code"]),
            technique_code=str(row["technique_code"]),
            edge_type=_opt_str(row.get("edge_type_code")),
            description=str(row.get("description") or ""),
            is_traversal=_truthy(row.get("is_traversal", 1)),
            preconditions=tuple(
                sorted(preconditions_by_rule.get(rule_id, ()), key=lambda p: p.seq)
            ),
            effects=tuple(sorted(effects_by_rule.get(rule_id, ()), key=lambda e: e.seq)),
        )
        _validate_rule(rule, techniques=techniques, capabilities=capabilities)
        rules.append(rule)

    if not rules:
        raise RulesetError("no enabled rules; discovery would report nothing")

    threat_models = _build_threat_models(threat_model_rows, grant_rows, capabilities)

    traversal: dict[str, list[Rule]] = {}
    non_traversal: list[Rule] = []
    unconditional: list[Rule] = []
    for rule in rules:
        if not rule.is_traversal:
            non_traversal.append(rule)
            continue
        traversal.setdefault(str(rule.edge_type), []).append(rule)
        if not any(
            p.kind is PreconditionKind.CAPABILITY for p in rule.preconditions
        ):
            unconditional.append(rule)

    return RuleSet(
        rules=tuple(rules),
        techniques=techniques,
        threat_models=threat_models,
        capability_bindings=capabilities,
        traversal_by_edge_type={k: tuple(v) for k, v in traversal.items()},
        non_traversal=tuple(non_traversal),
        unconditional=tuple(unconditional),
    )


def load_ruleset() -> RuleSet:
    """Read the attacker model out of MySQL."""
    from app.db import fetch_all

    return build_ruleset(
        rule_rows=fetch_all(
            "SELECT id, code, technique_code, edge_type_code, description, "
            "is_traversal, is_enabled, sort_order FROM rule"
        ),
        precondition_rows=fetch_all(
            "SELECT rule_id, seq, kind, binding, capability_code, attr_path, "
            "operator, value_json, is_negated, failure_reason FROM rule_precondition"
        ),
        effect_rows=fetch_all(
            "SELECT rule_id, seq, capability_code, binding FROM rule_effect"
        ),
        technique_rows=fetch_all(
            "SELECT code, name, description, attack_id, attack_name, attack_url, "
            "phase FROM technique"
        ),
        capability_rows=fetch_all("SELECT code, binding_kind FROM capability_atom"),
        threat_model_rows=fetch_all(
            "SELECT code, label, description, is_default, sort_order FROM threat_model"
        ),
        grant_rows=fetch_all(
            "SELECT threat_model_code, seq, capability_code, applies_to_kind, "
            "applies_to_node FROM threat_model_grant"
        ),
    )


def _precondition(row: Row) -> Precondition:
    operator = _opt_str(row.get("operator"))
    return Precondition(
        seq=int(row["seq"]),
        kind=PreconditionKind(str(row["kind"])),
        binding=Binding(str(row.get("binding") or "src")),
        capability_code=_opt_str(row.get("capability_code")),
        attr_path=_opt_str(row.get("attr_path")),
        operator=operator,
        value=decode_json(row.get("value_json")),
        is_negated=_truthy(row.get("is_negated", 0)),
        failure_reason=str(row.get("failure_reason") or ""),
    )


def _validate_rule(
    rule: Rule,
    *,
    techniques: Mapping[str, Technique],
    capabilities: Mapping[str, str],
) -> None:
    where = f"rule {rule.rule_id} ({rule.code})"

    if rule.technique_code not in techniques:
        raise RulesetError(f"{where}: unknown technique {rule.technique_code!r}")
    if not rule.effects:
        raise RulesetError(
            f"{where}: has no effects, so firing it would grant the attacker "
            "nothing and it could never contribute to a path"
        )
    if rule.is_traversal and not rule.edge_type:
        raise RulesetError(f"{where}: is a traversal rule but names no edge type")
    if not rule.is_traversal and rule.edge_type:
        raise RulesetError(
            f"{where}: is marked non-traversal but names edge type "
            f"{rule.edge_type!r}; a rule that consumes an edge is a traversal"
        )

    for effect in rule.effects:
        binding_kind = capabilities.get(effect.capability_code)
        if binding_kind is None:
            raise RulesetError(
                f"{where} effect {effect.seq}: unknown capability "
                f"{effect.capability_code!r}"
            )
        _check_binding(where, f"effect {effect.seq}", effect.binding, binding_kind)
        _check_traversal_binding(where, f"effect {effect.seq}", rule, effect.binding)

    seen: set[int] = set()
    for pre in rule.preconditions:
        label = f"precondition {pre.seq}"
        if pre.seq in seen:
            raise RulesetError(f"{where}: duplicate {label}")
        seen.add(pre.seq)

        # Checked ahead of the kind-specific validation because it applies to
        # every kind. A capability refusal needs a sentence as much as an
        # attribute one does — more, since "the attacker does not hold this"
        # is the refusal an analyst is least able to reconstruct from the row.
        if not pre.failure_reason:
            raise RulesetError(
                f"{where} {label}: has no failure_reason, so a refusal it causes "
                "could not explain itself"
            )

        if pre.kind is PreconditionKind.CAPABILITY:
            if not pre.capability_code:
                raise RulesetError(f"{where} {label}: capability kind names no capability")
            if pre.attr_path or pre.operator:
                raise RulesetError(
                    f"{where} {label}: capability kind carries an attribute "
                    "comparison, which it cannot use"
                )
            binding_kind = capabilities.get(pre.capability_code)
            if binding_kind is None:
                raise RulesetError(
                    f"{where} {label}: unknown capability {pre.capability_code!r}"
                )
            _check_binding(where, label, pre.binding, binding_kind)
            _check_traversal_binding(where, label, rule, pre.binding)
            continue

        if not pre.attr_path:
            raise RulesetError(f"{where} {label}: attribute kind names no attr_path")
        if pre.operator not in OPERATORS:
            raise RulesetError(f"{where} {label}: unknown operator {pre.operator!r}")
        if pre.operator in PRESENCE_OPERATORS:
            if pre.value is not None:
                raise RulesetError(
                    f"{where} {label}: operator {pre.operator} takes no value"
                )
        elif pre.value is None:
            raise RulesetError(
                f"{where} {label}: operator {pre.operator} needs a value to compare against"
            )
        elif pre.operator in MEMBERSHIP_OPERATORS and not isinstance(
            pre.value, (list, tuple)
        ):
            raise RulesetError(
                f"{where} {label}: operator {pre.operator} needs a list of alternatives, "
                f"got {type(pre.value).__name__}"
            )

        if pre.kind is PreconditionKind.EDGE_ATTR and not rule.is_traversal:
            raise RulesetError(
                f"{where} {label}: inspects an edge attribute, but the rule consumes "
                "no edge"
            )
        if pre.kind is PreconditionKind.NODE_ATTR and pre.binding is Binding.GLOBAL:
            raise RulesetError(
                f"{where} {label}: node attribute bound globally names no node"
            )
        _check_traversal_binding(where, label, rule, pre.binding)


def _check_traversal_binding(
    where: str, label: str, rule: Rule, binding: Binding
) -> None:
    """A rule with no edge has one node, and ``dst`` is how it is named.

    ``src`` and ``dst`` are the endpoints of a traversed edge, so a rule that
    traverses nothing has no pair to bind to — there is only the node it acts on.
    Nothing in the graph joins the attacker to that node, which is exactly why
    R10 exists. Fixing the convention at ``dst`` rather than accepting either
    keeps a ``src`` binding from silently resolving to the same node and looking
    like it meant something else.
    """
    if not rule.is_traversal and binding is Binding.SRC:
        raise RulesetError(
            f"{where} {label}: bound to src, but the rule consumes no edge and so "
            "has no source; a non-traversal rule binds the node it acts on as dst"
        )


def _check_binding(where: str, label: str, binding: Binding, binding_kind: str) -> None:
    if binding_kind == "global" and binding is not Binding.GLOBAL:
        raise RulesetError(
            f"{where} {label}: globally-scoped capability bound to {binding.value}"
        )
    if binding_kind == "node" and binding is Binding.GLOBAL:
        raise RulesetError(
            f"{where} {label}: node-scoped capability bound globally, so it is "
            "about no node"
        )


def _build_threat_models(
    threat_model_rows: Iterable[Row],
    grant_rows: Iterable[Row],
    capabilities: Mapping[str, str],
) -> Mapping[str, ThreatModel]:
    grants: dict[str, list[tuple[int, tuple[str, str | None, str | None]]]] = {}
    for row in grant_rows:
        code = str(row["capability_code"])
        if code not in capabilities:
            raise RulesetError(
                f"threat model {row['threat_model_code']!r} grants unknown "
                f"capability {code!r}"
            )
        grants.setdefault(str(row["threat_model_code"]), []).append(
            (
                int(row["seq"]),
                (
                    code,
                    _opt_str(row.get("applies_to_kind")),
                    _opt_str(row.get("applies_to_node")),
                ),
            )
        )

    models: dict[str, ThreatModel] = {}
    for row in threat_model_rows:
        code = str(row["code"])
        ordered = sorted(grants.get(code, []), key=lambda item: item[0])
        if not ordered:
            raise RulesetError(
                f"threat model {code!r} grants nothing, so an attacker under it "
                "could never take a first step"
            )
        models[code] = ThreatModel(
            code=code,
            label=str(row.get("label") or code),
            description=str(row.get("description") or ""),
            grants=tuple(grant for _, grant in ordered),
        )
    return models


def decode_json(value: Any) -> Any:
    """Decode a ``value_json`` column.

    Whether a JSON column arrives already decoded depends on the driver, and
    this module is fed both by SQLAlchemy and by hand-built rows in tests. A
    string that is not valid JSON is taken literally rather than rejected,
    because a bare ``admin`` in a hand-written seed row means the string.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value
    return value


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)
