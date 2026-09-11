"""Configuration endpoints.

Everything the interface needs in order to render itself: navigation, risk
tiers and their colours, the node and edge vocabularies with their shapes and
styles, layout presets, and the demo script.

These exist because of decision D12 — no value the interface displays or styles
with is written into the frontend. Three copies of a colour map across three
components is three chances for the legend to disagree with the graph, and a
risk threshold duplicated in TypeScript is a threshold that drifts from the one
the scorer actually used.

Everything here reflects the *active* scoring configuration. When the Settings
screen changes a weight, these responses change with it.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.db import fetch_all, fetch_one

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("/nav")
def navigation() -> list[dict]:
    return fetch_all(
        """
        SELECT code, label, route, icon, description, sort_order
        FROM nav_item
        WHERE is_enabled = 1
        ORDER BY sort_order
        """
    )


@router.get("/risk-tiers")
def risk_tiers() -> list[dict]:
    """Display bands for the 0-10 score, from the active scoring version.

    Served rather than hardcoded so the tier a score falls into is decided in
    exactly one place. The alternative -- a threshold table in the frontend --
    silently disagrees with the scorer the first time anyone retunes it.
    """
    rows = fetch_all(
        """
        SELECT t.code, t.label, t.min_score, t.max_score,
               t.ui_color, t.ui_bg_color, t.action_text, t.sort_order
        FROM risk_tier t
        JOIN scoring_config c ON c.version = t.scoring_version
        WHERE c.is_active = 1
        ORDER BY t.sort_order
        """
    )
    if not rows:
        raise HTTPException(500, "No active scoring configuration. Run the seed migrations.")
    return [{**r, "min_score": float(r["min_score"]), "max_score": float(r["max_score"])} for r in rows]


@router.get("/vocabularies")
def vocabularies() -> dict:
    """Node kinds, edge types and the classification vocabularies.

    Carries the rendering attributes -- colour, shape, size range, line style --
    so the legend, the node styling and the edge styling all read from one row
    and cannot drift apart.
    """
    return {
        "node_kinds": fetch_all(
            """
            SELECT code, label, description, category, ui_color, ui_shape,
                   ui_size_min, ui_size_max, ui_size_by, ui_icon, sort_order
            FROM node_kind ORDER BY sort_order
            """
        ),
        "edge_types": fetch_all(
            """
            SELECT code, label, description, is_directed, ui_color,
                   ui_line_style, ui_width, ui_animated, sort_order
            FROM edge_type ORDER BY sort_order
            """
        ),
        "criticality": fetch_all(
            "SELECT code, label, description, sort_order FROM criticality ORDER BY sort_order"
        ),
        "classifications": fetch_all(
            "SELECT code, label, description, sort_order FROM data_classification ORDER BY sort_order"
        ),
    }


@router.get("/layouts")
def layouts() -> list[dict]:
    """Graph layout presets.

    ``max_nodes`` lets the Explorer warn before attempting a layout that will
    not finish, rather than freezing and looking broken.
    """
    return fetch_all(
        """
        SELECT code, label, description, engine, params, max_nodes, is_default, sort_order
        FROM layout_preset ORDER BY sort_order
        """
    )


@router.get("/scoring")
def scoring() -> dict:
    """The active scoring configuration, with its constants exposed.

    Exposed deliberately. The product's claim is that its numbers are traceable,
    and a weight nobody can inspect is not traceable. The Settings screen reads
    this, and so can anyone curious about how a score was produced.
    """
    config = fetch_one(
        """
        SELECT version, label, description, p_clamp_min, p_clamp_max, raw_max,
               w_likelihood, w_impact, w_stealth
        FROM scoring_config WHERE is_active = 1
        """
    )
    if not config:
        raise HTTPException(500, "No active scoring configuration. Run the seed migrations.")

    version = config["version"]
    return {
        "config": {k: (float(v) if isinstance(v, (int, float)) and k.startswith(("p_", "raw_", "w_")) else v)
                   for k, v in config.items()},
        "baselines": fetch_all(
            """
            SELECT b.technique_code, t.name AS technique_name, b.base_p_succ,
                   b.base_detectability, b.rationale
            FROM technique_baseline b
            JOIN technique t ON t.code = b.technique_code
            WHERE b.scoring_version = :v
            ORDER BY t.sort_order
            """,
            {"v": version},
        ),
        "modifiers": fetch_all(
            """
            SELECT code, label, description, applies_to, attr_path, operator,
                   value_json, target, beta, is_hard_block, sort_order
            FROM scoring_modifier WHERE scoring_version = :v ORDER BY sort_order
            """,
            {"v": version},
        ),
        "impact_weights": fetch_all(
            "SELECT dimension, code, weight FROM impact_weight WHERE scoring_version = :v",
            {"v": version},
        ),
    }


@router.get("/threat-models")
def threat_models() -> list[dict]:
    """Assumed attacker starting positions.

    Held as data because the interesting comparison is between them: a path that
    is critical for an insider may be entirely unreachable for an outsider, and
    a tool that can only answer one of those questions is answering the wrong
    one half the time.
    """
    models = fetch_all(
        """
        SELECT code, label, description, is_default, sort_order
        FROM threat_model ORDER BY sort_order
        """
    )
    grants = fetch_all(
        """
        SELECT g.threat_model_code, g.seq, g.capability_code, a.label AS capability_label,
               g.applies_to_kind, g.applies_to_node
        FROM threat_model_grant g
        JOIN capability_atom a ON a.code = g.capability_code
        ORDER BY g.threat_model_code, g.seq
        """
    )
    by_model: dict[str, list[dict]] = {}
    for grant in grants:
        by_model.setdefault(grant["threat_model_code"], []).append(grant)
    for model in models:
        model["grants"] = by_model.get(model["code"], [])
    return models


@router.get("/techniques")
def techniques() -> list[dict]:
    """The technique catalogue with its MITRE ATT&CK mapping.

    The mapping is not decoration: every hop in a reported path cites the
    technique it used, which is a large part of how the output stays legible to
    a practitioner rather than being a set of numbers they have to trust.
    """
    return fetch_all(
        """
        SELECT code, name, description, attack_id, attack_name, attack_url, phase, sort_order
        FROM technique ORDER BY sort_order
        """
    )


@router.get("/rules")
def rules() -> list[dict]:
    """Derivation rules with their preconditions and effects.

    Exposed so the interface can show *why* a transition was or was not
    possible, in the same words the engine used to decide it.
    """
    rule_rows = fetch_all(
        """
        SELECT r.id, r.code, r.technique_code, t.name AS technique_name,
               r.edge_type_code, r.description, r.is_traversal, r.is_enabled, r.sort_order
        FROM rule r JOIN technique t ON t.code = r.technique_code
        ORDER BY r.sort_order
        """
    )
    preconditions = fetch_all(
        """
        SELECT rule_id, seq, kind, binding, capability_code, attr_path,
               operator, value_json, is_negated, failure_reason
        FROM rule_precondition ORDER BY rule_id, seq
        """
    )
    effects = fetch_all(
        "SELECT rule_id, seq, capability_code, binding FROM rule_effect ORDER BY rule_id, seq"
    )

    pre_by_rule: dict[int, list[dict]] = {}
    for row in preconditions:
        pre_by_rule.setdefault(row["rule_id"], []).append(row)
    eff_by_rule: dict[int, list[dict]] = {}
    for row in effects:
        eff_by_rule.setdefault(row["rule_id"], []).append(row)

    for rule in rule_rows:
        rule["preconditions"] = pre_by_rule.get(rule["id"], [])
        rule["effects"] = eff_by_rule.get(rule["id"], [])
    return rule_rows


@router.get("/demo-script")
def demo_script() -> list[dict]:
    """The walkthrough, as data.

    Drives an in-app guided mode, and means the demo sequence is something the
    team can edit rather than something one person remembers.
    """
    return fetch_all(
        """
        SELECT step_no, title, route, narration, criterion, expected_duration_seconds
        FROM demo_step ORDER BY step_no
        """
    )
