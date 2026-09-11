"""Where the harness gets the attacker model, and the worlds it runs against.

**The model comes from rows, from one of two places.** The database is the
source of truth and is tried first. The seed file the database was migrated
from is the fallback, and it exists for one reason: a property suite that needs
a running MySQL to tell you whether monotonicity holds is a property suite that
stops being run. ``backend/oracle/loader.py`` already established the pattern
and its parser is reused verbatim here, so both paths produce the same rows
through the same conversion.

Both rulesets are loaded from the same rows. That is deliberate and it is not
the same thing as the two implementations sharing code: ``engine.rules`` and
``oracle.loader`` each decide independently what a precondition row *means* and
each search consumes its own representation. Feeding them different rows would
turn a rule-data difference into an apparent engine disagreement, which is the
one failure mode a differential harness must not have.

**The graphs are hand-built.** Each is small enough that the right answer can be
worked out by reading it, which is the only kind of case worth handing to a
reference implementation: an oracle checked against a clever fixture is checked
against nothing. Every world mixes valid mechanisms with planted refusals whose
deciding attribute is the only thing separating them from something traversable
-- a world of only valid paths passes by accepting everything, and a world of
only decoys passes by refusing everything.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from core.model import Edge, GraphSnapshot, Node, ScoringConfig
from engine.rules import RuleSet as EngineRuleSet
from engine.rules import build_ruleset
from engine.scoring import build_scoring_config
from oracle.loader import SEED_DIR
from oracle.loader import RuleSet as OracleRuleSet
from oracle.loader import (
    MySQLRowSource,
    RowSource,
    SeedFileRowSource,
    load_ruleset,
    rule_seed_files,
)

__all__ = [
    "ModelSource",
    "SCORING_SEED",
    "WORLDS",
    "World",
    "chain_snapshot",
    "edge",
    "load_model",
    "node",
    "scoring_with_baseline",
    "snapshot",
]

SCORING_SEED = SEED_DIR / "030_scoring.sql"

#: ``NOW(6)`` and friends in a seed file's VALUES clause. The seed parser reads
#: literals, not expressions, so a timestamp function is blanked before parsing.
#: Nothing the scorer reads is a timestamp, so dropping them costs nothing.
_SQL_FUNCTION_CALL = re.compile(r"\bNOW\(\s*\d*\s*\)", re.IGNORECASE)


class _SanitisedSeedSource(SeedFileRowSource):
    """``SeedFileRowSource`` over a seed file that calls SQL functions.

    Bypasses the base ``__init__`` rather than editing the file: the scoring
    seed sets ``created_at`` with ``NOW(6)``, which is an expression and not a
    literal, and the parser is deliberately strict about the difference.
    """

    def __init__(self, path: Path | str) -> None:
        self.paths = (Path(path),)
        self.path = self.paths[0]
        self._tables = {}
        self._parse(_SQL_FUNCTION_CALL.sub("NULL", self.path.read_text(encoding="utf-8")))


@dataclass(frozen=True, slots=True)
class ModelSource:
    """The attacker model and the scoring configuration, plus where they came from."""

    engine_ruleset: EngineRuleSet
    oracle_ruleset: OracleRuleSet
    scoring: ScoringConfig
    origin: str
    """``'database'`` or ``'seed_file'`` -- reported, never inferred by a caller."""

    detail: str
    """Why this origin was used. Carries the connection error when one occurred."""


def load_model(*, prefer_database: bool = True) -> ModelSource:
    """Load rules and scoring, from MySQL if it answers and the seed file if not."""
    if prefer_database:
        try:
            return _from_database()
        except Exception as exc:  # noqa: BLE001 - reported in `detail`, never swallowed
            return _from_seed_files(
                detail=f"MySQL was unreachable, so the seed rows were used instead: {exc}"
            )
    return _from_seed_files(detail="the caller asked for the seed rows")


def _from_database() -> ModelSource:
    from app.db import mysql_engine
    from engine.rules import load_ruleset as load_engine_ruleset
    from engine.scoring import load_scoring_config

    engine_ruleset = load_engine_ruleset()
    scoring = load_scoring_config()
    raw = mysql_engine().raw_connection()
    try:
        oracle_ruleset = load_ruleset(MySQLRowSource(raw))
    finally:
        raw.close()
    return ModelSource(
        engine_ruleset=engine_ruleset,
        oracle_ruleset=oracle_ruleset,
        scoring=scoring,
        origin="database",
        detail=f"rule and scoring rows read from MySQL, scoring version {scoring.version}",
    )


def _from_seed_files(*, detail: str) -> ModelSource:
    # Every seed file carrying model rows, not just the first: a later file
    # fixing an earlier one's rules is how a fix reaches an already-migrated
    # database, and a fallback that read only 020 would compare the two
    # implementations against a model neither of them runs against in
    # production.
    attacker_model = SeedFileRowSource(rule_seed_files())
    return ModelSource(
        engine_ruleset=_engine_ruleset(attacker_model),
        oracle_ruleset=load_ruleset(attacker_model),
        scoring=_scoring_config(_SanitisedSeedSource(SCORING_SEED)),
        origin="seed_file",
        detail=detail,
    )


def _rows(source: RowSource, table: str, columns: Sequence[str]) -> list[dict[str, Any]]:
    return [dict(zip(columns, row, strict=True)) for row in source.fetch(table, columns)]


def _engine_ruleset(source: RowSource) -> EngineRuleSet:
    """The engine's ruleset, assembled from the same rows the oracle reads."""
    return build_ruleset(
        rule_rows=_rows(
            source,
            "rule",
            (
                "id",
                "code",
                "technique_code",
                "edge_type_code",
                "description",
                "is_traversal",
                "is_enabled",
                "sort_order",
            ),
        ),
        precondition_rows=_rows(
            source,
            "rule_precondition",
            (
                "rule_id",
                "seq",
                "kind",
                "binding",
                "capability_code",
                "attr_path",
                "operator",
                "value_json",
                "is_negated",
                "failure_reason",
            ),
        ),
        effect_rows=_rows(source, "rule_effect", ("rule_id", "seq", "capability_code", "binding")),
        technique_rows=_rows(
            source,
            "technique",
            ("code", "name", "description", "attack_id", "attack_name", "attack_url", "phase"),
        ),
        capability_rows=_rows(source, "capability_atom", ("code", "binding_kind")),
        threat_model_rows=_rows(
            source, "threat_model", ("code", "label", "description", "is_default", "sort_order")
        ),
        grant_rows=_rows(
            source,
            "threat_model_grant",
            ("threat_model_code", "seq", "capability_code", "applies_to_kind", "applies_to_node"),
        ),
    )


def _scoring_config(source: RowSource) -> ScoringConfig:
    configs = _rows(
        source,
        "scoring_config",
        (
            "version",
            "label",
            "p_clamp_min",
            "p_clamp_max",
            "raw_max",
            "w_likelihood",
            "w_impact",
            "w_stealth",
            "is_active",
        ),
    )
    active = [row for row in configs if row["is_active"]]
    if not active:
        raise RuntimeError(f"{SCORING_SEED.name} seeds no active scoring configuration")
    config_row = active[0]
    version = config_row["version"]

    def for_version(table: str, columns: Sequence[str]) -> list[dict[str, Any]]:
        return [r for r in _rows(source, table, columns) if r["scoring_version"] == version]

    return build_scoring_config(
        config_row=config_row,
        baseline_rows=for_version(
            "technique_baseline",
            ("scoring_version", "technique_code", "base_p_succ", "base_detectability"),
        ),
        modifier_rows=for_version(
            "scoring_modifier",
            (
                "scoring_version",
                "code",
                "label",
                "applies_to",
                "attr_path",
                "operator",
                "value_json",
                "target",
                "beta",
                "is_hard_block",
                "sort_order",
            ),
        ),
        scope_rows=for_version(
            "scoring_modifier_scope", ("scoring_version", "modifier_code", "technique_code")
        ),
        impact_rows=for_version("impact_weight", ("scoring_version", "dimension", "code", "weight")),
        tier_rows=for_version(
            "risk_tier",
            (
                "scoring_version",
                "code",
                "label",
                "min_score",
                "max_score",
                "ui_color",
                "ui_bg_color",
                "action_text",
                "sort_order",
            ),
        ),
    )


def scoring_with_baseline(
    scoring: ScoringConfig, technique_code: str, base_p_succ: float
) -> ScoringConfig:
    """The same configuration with one technique's baseline success replaced.

    ``docs/RULES.md`` §7 invariant 4 is about what happens when a baseline
    moves, so the harness has to be able to move one without reaching into the
    scoring table -- a property test whose result depends on a mutable row is
    not a property test.
    """
    existing = scoring.baselines.get(technique_code)
    if existing is None:
        raise KeyError(f"no baseline for technique {technique_code!r} to raise")
    patched = dict(scoring.baselines)
    patched[technique_code] = (base_p_succ, existing[1])
    return dataclasses.replace(scoring, baselines=patched)


# ── Graph construction ───────────────────────────────────────────────────────


def node(node_id: str, kind: str, *, crown_jewel: bool = False, **attrs: Any) -> Node:
    return Node(
        node_id=node_id,
        kind=kind,
        name=node_id,
        is_crown_jewel=crown_jewel,
        criticality="critical" if crown_jewel else None,
        classification="restricted" if crown_jewel else None,
        attrs=attrs,
    )


def edge(edge_id: str, src: str, dst: str, edge_type: str, **attrs: Any) -> Edge:
    return Edge(edge_id=edge_id, src_id=src, dst_id=dst, edge_type=edge_type, attrs=attrs)


def snapshot(nodes: Iterable[Node], edges: Iterable[Edge]) -> GraphSnapshot:
    return GraphSnapshot(1, nodes, edges)


# Attribute bundles used often enough that spelling them out every time hides
# what a given world is actually varying.
LIVE_HOST = {"status": "active", "patch_level": "current"}
UNPATCHED_HOST = {"status": "active", "patch_level": "behind-2+"}
LIVE_CREDENTIAL = {"is_active": True, "storage": "config_file"}
OPEN_LOGON = {"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": False}
NO_LOGON_CONTROLS = {
    "mfa_required": False,
    "mfa_type": "none",
    "requires_compliant_device": False,
    "scope": "admin",
}


@dataclass(frozen=True, slots=True)
class World:
    """One hand-built graph, the threat model to search it under, and why it exists."""

    code: str
    title: str
    mechanism: str
    """The rules this world is built to exercise, in plain words."""

    threat_model_code: str
    build: Callable[[], GraphSnapshot]
    max_hops: int = 6


def _credential_replay() -> GraphSnapshot:
    """A user, their credentials, and what those credentials open.

    One route works: ``cred-1`` is live and ``h-1`` accepts a replayable second
    factor. ``cred-2`` has been rotated, ``h-2`` is decommissioned, and
    ``u-2``'s administrative assignment outlived their account.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("u-2", "User", account_status="disabled"),
            node("cred-1", "Credential", **LIVE_CREDENTIAL),
            node("cred-2", "Credential", is_active=False, storage="config_file"),
            node("h-1", "Host", crown_jewel=True, **LIVE_HOST),
            node("h-2", "Host", status="decommissioned", patch_level="current"),
        ],
        [
            edge("e1", "u-1", "cred-1", "HAS_CREDENTIAL"),
            edge("e2", "u-1", "cred-2", "HAS_CREDENTIAL"),
            edge("e3", "cred-1", "h-1", "AUTHENTICATES_TO", **OPEN_LOGON),
            edge("e4", "cred-1", "h-2", "AUTHENTICATES_TO", **OPEN_LOGON),
            edge("e5", "u-2", "h-1", "ADMIN_TO"),
        ],
    )


def _group_permission() -> GraphSnapshot:
    """Group-conferred rights, and what a read-only grant does not buy.

    ``g-admin`` administers two hosts and both leak the same credential, so
    there are two genuinely different routes to one target. ``g-ro`` reaches one
    of those hosts read-only and cannot dump anything; ``g-dist`` is a mailing
    list.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("g-admin", "Group", type="security"),
            node("g-ro", "Group", type="security"),
            node("g-dist", "Group", type="distribution"),
            node("h-1", "Host", **LIVE_HOST),
            node("h-2", "Host", **LIVE_HOST),
            node("cred-1", "Credential", crown_jewel=True, **LIVE_CREDENTIAL),
        ],
        [
            edge("e1", "u-1", "g-admin", "MEMBER_OF"),
            edge("e2", "u-1", "g-ro", "MEMBER_OF"),
            edge("e3", "u-1", "g-dist", "MEMBER_OF"),
            edge("e4", "g-admin", "h-1", "HAS_PERMISSION", permission_level="admin"),
            edge("e5", "g-ro", "h-1", "HAS_PERMISSION", permission_level="read_only"),
            edge("e6", "g-dist", "h-1", "HAS_PERMISSION", permission_level="admin"),
            edge("e7", "h-1", "cred-1", "EXPOSES_CREDENTIAL", location="config_file"),
            edge("e8", "g-admin", "h-2", "HAS_PERMISSION", permission_level="admin"),
            edge("e9", "h-2", "cred-1", "EXPOSES_CREDENTIAL", location="config_file"),
        ],
    )


def _nested_groups() -> GraphSnapshot:
    """Three levels of nesting, with a distribution group interrupting one branch.

    Membership is the rule that applies to itself, so this is where a fixpoint
    bug shows up: the live branch has to be followed to depth three, and the
    branch through the mailing list has to stop at depth one.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("g-1", "Group", type="security"),
            node("g-2", "Group", type="security"),
            node("g-3", "Group", type="security"),
            node("g-dist", "Group", type="distribution"),
            node("g-beyond", "Group", type="security"),
            node("db-1", "Database", crown_jewel=True, status="active"),
            node("db-2", "Database", status="active"),
        ],
        [
            edge("e1", "u-1", "g-1", "MEMBER_OF"),
            edge("e2", "g-1", "g-2", "MEMBER_OF"),
            edge("e3", "g-2", "g-3", "MEMBER_OF"),
            edge("e4", "g-3", "db-1", "HAS_PERMISSION", permission_level="admin"),
            edge("e5", "u-1", "g-dist", "MEMBER_OF"),
            edge("e6", "g-dist", "g-beyond", "MEMBER_OF"),
            edge("e7", "g-beyond", "db-2", "HAS_PERMISSION", permission_level="admin"),
        ],
    )


def _kerberoast() -> GraphSnapshot:
    """Two SPN-bearing service accounts; only one has a crackable password.

    Nothing in this graph connects the attacker to either account, which is the
    case a rule consuming no edge exists for.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node(
                "sa-weak",
                "ServiceAccount",
                account_status="active",
                has_spn=True,
                credential_strength="weak",
            ),
            node(
                "sa-strong",
                "ServiceAccount",
                account_status="active",
                has_spn=True,
                credential_strength="strong",
            ),
            node("db-1", "Database", crown_jewel=True, status="active"),
            node("db-2", "Database", status="active"),
        ],
        [
            edge("e1", "sa-weak", "db-1", "HAS_ACCESS_TO", permission_level="admin"),
            edge("e2", "sa-strong", "db-2", "HAS_ACCESS_TO", permission_level="admin"),
        ],
    )


def _exploit_chain() -> GraphSnapshot:
    """Remote exploit, then local escalation, then a credential dump.

    The pair of exploit rules is why code execution and administrative control
    are separate capabilities: an RCE yields the first, and the second is its
    own step. Collapsing them would let the dump fire a hop early.
    """
    return snapshot(
        [
            node("h-1", "Host", **UNPATCHED_HOST),
            node("h-2", "Host", **LIVE_HOST),
            node("v-rce", "Vulnerability", impact="RCE", attack_vector="network", epss=0.6),
            node(
                "v-privesc",
                "Vulnerability",
                impact="privilege_escalation",
                attack_vector="local",
                epss=0.4,
            ),
            node(
                "v-dos",
                "Vulnerability",
                impact="denial_of_service",
                attack_vector="network",
                epss=0.5,
            ),
            node("v-rce-2", "Vulnerability", impact="RCE", attack_vector="network", epss=0.6),
            node("cred-1", "Credential", crown_jewel=True, **LIVE_CREDENTIAL),
        ],
        [
            edge("e1", "h-1", "v-rce", "HAS_VULNERABILITY"),
            edge("e2", "h-1", "v-privesc", "HAS_VULNERABILITY"),
            edge("e3", "h-1", "v-dos", "HAS_VULNERABILITY"),
            edge("e4", "h-1", "cred-1", "EXPOSES_CREDENTIAL", location="config_file"),
            edge("e5", "h-2", "v-rce-2", "HAS_VULNERABILITY"),
        ],
    )


def _trust_cycle() -> GraphSnapshot:
    """``h-a`` trusts ``h-b`` trusts ``h-a``, and both can be escalated on.

    A cycle in the graph is not a cycle in the state space, and this is where
    that claim is checked rather than argued.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("h-a", "Host", **UNPATCHED_HOST),
            node("h-b", "Host", crown_jewel=True, **UNPATCHED_HOST),
            node(
                "v-a",
                "Vulnerability",
                impact="privilege_escalation",
                attack_vector="local",
                epss=0.4,
            ),
            node(
                "v-b",
                "Vulnerability",
                impact="privilege_escalation",
                attack_vector="local",
                epss=0.4,
            ),
        ],
        [
            edge("e1", "u-1", "h-a", "ADMIN_TO"),
            edge("e2", "h-a", "h-b", "TRUSTS", trust_type="ssh_key_trust"),
            edge("e3", "h-b", "h-a", "TRUSTS", trust_type="ssh_key_trust"),
            edge("e4", "h-a", "v-a", "HAS_VULNERABILITY"),
            edge("e5", "h-b", "v-b", "HAS_VULNERABILITY"),
        ],
    )


def _public_exposure() -> GraphSnapshot:
    """A secret in a public repository, and the same secret in a config file.

    The public exposure requires nothing at all -- no identity, no access, no
    position -- which is exactly why it is catastrophic. The config-file
    exposure next to it requires administrative control of the host holding it,
    and nothing in this graph grants that, so it must stay refused.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("app-1", "Application", status="active"),
            node("app-2", "Application", status="active"),
            node("cred-public", "Credential", **LIVE_CREDENTIAL),
            node("cred-private", "Credential", **LIVE_CREDENTIAL),
            node("db-1", "Database", crown_jewel=True, status="active"),
            node("db-2", "Database", crown_jewel=True, status="active"),
        ],
        [
            edge("e1", "app-1", "cred-public", "EXPOSES_CREDENTIAL", location="public_repo"),
            edge("e2", "cred-public", "db-1", "AUTHENTICATES_TO", **NO_LOGON_CONTROLS),
            edge("e3", "app-2", "cred-private", "EXPOSES_CREDENTIAL", location="config_file"),
            edge("e4", "cred-private", "db-2", "AUTHENTICATES_TO", **NO_LOGON_CONTROLS),
        ],
    )


def _cloud_pivot() -> GraphSnapshot:
    """Role assumption versus network adjacency, which are not the same thing.

    ``cr-1`` can assume a role on ``cr-2``, and that is access. It is merely
    network-adjacent to ``cr-3``, and that is not: adjacency grants
    reachability, which does nothing until some other rule consumes it, so
    ``cr-3`` must stay unreached even though it is one edge away from a resource
    the attacker administers. ``h-1`` carries a remotely exploitable weakness
    and is unreachable too, because this threat model grants no network reach.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("g-1", "Group", type="security"),
            node("cr-1", "CloudResource", status="active"),
            node("cr-2", "CloudResource", crown_jewel=True, status="active"),
            node("cr-3", "CloudResource", crown_jewel=True, status="active"),
            node("h-1", "Host", **UNPATCHED_HOST),
            node("v-rce", "Vulnerability", impact="RCE", attack_vector="network", epss=0.7),
        ],
        [
            edge("e1", "u-1", "g-1", "MEMBER_OF"),
            edge("e2", "g-1", "cr-1", "HAS_PERMISSION", permission_level="admin"),
            edge(
                "e3",
                "cr-1",
                "cr-2",
                "CONNECTED_TO",
                connection_type="iam_assume_role",
                grants_admin=True,
            ),
            edge("e4", "cr-1", "cr-3", "CONNECTED_TO", connection_type="vpc_peering"),
            edge("e5", "h-1", "v-rce", "HAS_VULNERABILITY"),
        ],
    )


#: The hand-built worlds, in the order they are reported.
WORLDS: tuple[World, ...] = (
    World(
        code="credential_replay",
        title="Credential replay",
        mechanism="A principal's own credential, presented to what it opens (R6, R9).",
        threat_model_code="external_phish",
        build=_credential_replay,
    ),
    World(
        code="group_permission",
        title="Group-conferred rights",
        mechanism="Membership, an administrative permission, and a credential dump (R1, R2, R7).",
        threat_model_code="external_phish",
        build=_group_permission,
    ),
    World(
        code="nested_groups",
        title="Nested group membership",
        mechanism="Membership applying to itself, to depth three (R1, R2).",
        threat_model_code="external_phish",
        build=_nested_groups,
    ),
    World(
        code="kerberoast",
        title="Kerberoasting",
        mechanism="A rule that consumes no edge, then the account's own grant (R10, R5).",
        threat_model_code="external_phish",
        build=_kerberoast,
    ),
    World(
        code="exploit_chain",
        title="Exploit then escalate",
        mechanism="Remote code execution, local escalation, then a dump (R12, R13, R7).",
        threat_model_code="public_only",
        build=_exploit_chain,
    ),
    World(
        code="trust_cycle",
        title="Host trust cycle",
        mechanism="A graph cycle that is not a state-space cycle (R4, R11, R13).",
        threat_model_code="external_phish",
        build=_trust_cycle,
    ),
    World(
        code="public_exposure",
        title="Publicly exposed secret",
        mechanism="The rule with no preconditions at all, beside one that needs admin (R8, R7, R9).",
        threat_model_code="external_phish",
        build=_public_exposure,
    ),
    World(
        code="cloud_pivot",
        title="Cloud role assumption",
        mechanism="Role assumption, and adjacency that is reachability only (R14, R15, R12).",
        threat_model_code="insider_standard",
        build=_cloud_pivot,
    ),
)


# ── The perturbable world the property suite uses ────────────────────────────

_CHAIN_NODES: tuple[dict[str, Any], ...] = (
    {"node_id": "u-1", "kind": "User", "attrs": {"account_status": "active"}},
    # A disabled account whose administrative assignment outlived it.
    {"node_id": "u-2", "kind": "User", "attrs": {"account_status": "disabled"}},
    {"node_id": "g-1", "kind": "Group", "attrs": {"type": "security"}},
    # A mailing list, which conveys no authorisation.
    {"node_id": "g-2", "kind": "Group", "attrs": {"type": "distribution"}},
    {"node_id": "h-1", "kind": "Host", "attrs": dict(UNPATCHED_HOST)},
    {
        "node_id": "cred-1",
        "kind": "Credential",
        "attrs": {"is_active": True, "storage": "config_file", "strength": "weak", "age_days": 200},
    },
    # The config references this one but a vault holds it, so it cannot be read
    # out of the config.
    {"node_id": "cred-2", "kind": "Credential", "attrs": {"is_active": True, "storage": "vault"}},
    {"node_id": "db-1", "kind": "Database", "crown_jewel": True, "attrs": {"status": "active"}},
    {"node_id": "db-2", "kind": "Database", "attrs": {"status": "active"}},
    {
        "node_id": "sa-1",
        "kind": "ServiceAccount",
        "attrs": {"account_status": "active", "has_spn": True, "credential_strength": "weak"},
    },
    # An SPN account with strong material is not crackable, so reporting it
    # would be a false positive.
    {
        "node_id": "sa-2",
        "kind": "ServiceAccount",
        "attrs": {"account_status": "active", "has_spn": True, "credential_strength": "strong"},
    },
)

_CHAIN_EDGES: tuple[dict[str, Any], ...] = (
    {"edge_id": "e-mem-1", "src_id": "u-1", "dst_id": "g-1", "edge_type": "MEMBER_OF", "attrs": {}},
    {"edge_id": "e-mem-2", "src_id": "u-1", "dst_id": "g-2", "edge_type": "MEMBER_OF", "attrs": {}},
    {
        "edge_id": "e-perm-1",
        "src_id": "g-1",
        "dst_id": "h-1",
        "edge_type": "HAS_PERMISSION",
        "attrs": {"permission_level": "admin"},
    },
    {
        "edge_id": "e-perm-2",
        "src_id": "g-1",
        "dst_id": "db-2",
        "edge_type": "HAS_PERMISSION",
        "attrs": {"permission_level": "read_only"},
    },
    {
        "edge_id": "e-exp-1",
        "src_id": "h-1",
        "dst_id": "cred-1",
        "edge_type": "EXPOSES_CREDENTIAL",
        "attrs": {"location": "config_file", "discoverable": 0.8},
    },
    {
        "edge_id": "e-exp-2",
        "src_id": "h-1",
        "dst_id": "cred-2",
        "edge_type": "EXPOSES_CREDENTIAL",
        "attrs": {"location": "config_file"},
    },
    {
        "edge_id": "e-auth-1",
        "src_id": "cred-1",
        "dst_id": "db-1",
        "edge_type": "AUTHENTICATES_TO",
        "attrs": dict(NO_LOGON_CONTROLS),
    },
    {"edge_id": "e-admin-1", "src_id": "u-2", "dst_id": "db-2", "edge_type": "ADMIN_TO", "attrs": {}},
    {
        "edge_id": "e-sa-1",
        "src_id": "sa-1",
        "dst_id": "db-1",
        "edge_type": "HAS_ACCESS_TO",
        "attrs": {"permission_level": "admin"},
    },
    {
        "edge_id": "e-sa-2",
        "src_id": "sa-2",
        "dst_id": "db-2",
        "edge_type": "HAS_ACCESS_TO",
        "attrs": {"permission_level": "admin"},
    },
)

#: The four-hop chain the perturbable world is built around: inherit a security
#: group's membership, use its administrative permission on a host, dump the
#: credential the host exposes, present it to the crown-jewel database.
CHAIN_EDGE_SEQUENCE: tuple[str, ...] = ("e-mem-1", "e-perm-1", "e-exp-1", "e-auth-1")

#: Every edge of the perturbable world, in id order. The property suite draws
#: subsets of these to remove.
CHAIN_EDGE_IDS: tuple[str, ...] = tuple(sorted(row["edge_id"] for row in _CHAIN_EDGES))


def chain_snapshot(
    *,
    drop_edges: Iterable[str] = (),
    edge_attrs: Mapping[str, Mapping[str, Any]] | None = None,
    node_attrs: Mapping[str, Mapping[str, Any]] | None = None,
) -> GraphSnapshot:
    """The perturbable world, optionally with edges removed or attributes hardened.

    Perturbation is how the metamorphic invariants are checked: take something
    away, assert the answer only ever moves in one direction.
    """
    dropped = set(drop_edges)
    nodes = [
        node(
            row["node_id"],
            row["kind"],
            crown_jewel=bool(row.get("crown_jewel")),
            **{**row["attrs"], **(node_attrs or {}).get(row["node_id"], {})},
        )
        for row in _CHAIN_NODES
    ]
    edges = [
        edge(
            row["edge_id"],
            row["src_id"],
            row["dst_id"],
            row["edge_type"],
            **{**row["attrs"], **(edge_attrs or {}).get(row["edge_id"], {})},
        )
        for row in _CHAIN_EDGES
        if row["edge_id"] not in dropped
    ]
    return snapshot(nodes, edges)
