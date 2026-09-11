"""Tests for the reference oracle's exhaustive search.

The graphs here are hand-built and small enough that the correct answer can be
worked out by reading them, which is the only kind of test worth writing for an
oracle: a reference implementation checked against a clever fixture is checked
against nothing.

The fourteen decoy/twin pairs from ``docs/RULES.md`` §5 are the centre of the
file. Two of them cannot pass against the seeded rule rows and are marked as
expected failures with the reason spelled out on the case itself, rather than
being quietly reshaped until they agree.
"""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass

import pytest

from core.model import Capability, Edge, GraphSnapshot, Node, PreconditionKind
from oracle.loader import RuleSet, load_from_seed_file
from oracle.preconditions import evaluate_precondition
from oracle.search import (
    OracleConfig,
    OracleResult,
    canonical_path_key,
    discover,
    entry_nodes_for,
    materialise_grants,
    verify_path,
)


@pytest.fixture(scope="module")
def ruleset() -> RuleSet:
    """The attacker model, read from the seed file so no database is needed."""
    return load_from_seed_file()


# ── Construction helpers ─────────────────────────────────────────────────────


def node(node_id: str, kind: str, *, crown_jewel: bool = False, **attrs) -> Node:
    return Node(
        node_id=node_id,
        kind=kind,
        name=node_id,
        is_crown_jewel=crown_jewel,
        attrs=attrs,
    )


def edge(edge_id: str, src: str, dst: str, edge_type: str, **attrs) -> Edge:
    return Edge(edge_id=edge_id, src_id=src, dst_id=dst, edge_type=edge_type, attrs=attrs)


def snapshot(nodes, edges) -> GraphSnapshot:
    return GraphSnapshot(1, nodes, edges)


def run(
    ruleset: RuleSet, graph: GraphSnapshot, threat_model: str, **kwargs
) -> OracleResult:
    return discover(graph, ruleset, OracleConfig(threat_model_code=threat_model, **kwargs))


def path_shapes(result: OracleResult) -> set[tuple[tuple[str, int], ...]]:
    """Each path as its (edge id, rule id) sequence — readable in a failure message."""
    return {
        tuple((hop.edge_id or "<no edge>", hop.rule_id) for hop in path.hops)
        for path in result.paths
    }


def rejections_for(result: OracleResult, ruleset: RuleSet, rule_code: str, seq: int):
    rule_id = ruleset.rule(rule_code).rule_id
    return [
        r for r in result.rejections if r.rule_id == rule_id and r.precondition_seq == seq
    ]


# Attribute values used often enough that spelling them out every time obscures
# what a given fixture is actually varying.
LIVE_HOST = {"status": "active", "patch_level": "current"}
LIVE_CREDENTIAL = {"is_active": True, "storage": "config_file"}
OPEN_LOGON = {"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": False}


# ── Four hand-built graphs with enumerable answers ───────────────────────────


def credential_replay_graph() -> GraphSnapshot:
    """A user, their credentials, and what those credentials open.

    Only one route works: ``cred-1`` is live and ``h-1`` accepts SMS. ``cred-2``
    has been rotated, ``h-2`` is decommissioned, and ``u-2``'s administrative
    assignment outlived their account.
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


def group_permission_graph() -> GraphSnapshot:
    """Group-conferred rights, and what a read-only grant does not buy.

    ``g-admin`` administers two hosts, both of which leak the same credential.
    ``g-ro`` reaches one of those hosts but only read-only, so it cannot dump
    anything. ``g-dist`` is a mailing list.
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


def kerberoast_graph() -> GraphSnapshot:
    """Two SPN-bearing service accounts; only one has a crackable password."""
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


def exploit_chain_graph() -> GraphSnapshot:
    """Remote exploit, then local escalation, then a credential dump.

    ``h-1`` is two patch cycles behind and carries both an RCE and a local
    escalation. ``h-2`` carries the same class of RCE but is current.
    """
    return snapshot(
        [
            node("h-1", "Host", status="active", patch_level="behind-2+"),
            node("h-2", "Host", **LIVE_HOST),
            node("v-rce", "Vulnerability", impact="RCE", attack_vector="network"),
            node("v-privesc", "Vulnerability", impact="privilege_escalation", attack_vector="local"),
            node("v-dos", "Vulnerability", impact="denial_of_service", attack_vector="network"),
            node("v-rce-2", "Vulnerability", impact="RCE", attack_vector="network"),
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


def test_credential_replay_finds_exactly_the_live_route(ruleset: RuleSet) -> None:
    result = run(ruleset, credential_replay_graph(), "external_phish")

    assert result.entry_node_ids == ("u-1", "u-2")
    assert path_shapes(result) == {
        (
            ("e1", ruleset.rule("credential_from_principal").rule_id),
            ("e3", ruleset.rule("credential_authenticate").rule_id),
        )
    }
    # The three ways it could have gone wrong, each named by its own refusal.
    assert rejections_for(result, ruleset, "credential_from_principal", 2)
    assert rejections_for(result, ruleset, "credential_authenticate", 4)
    assert rejections_for(result, ruleset, "direct_admin", 2)


def test_group_permission_finds_both_admin_routes_and_no_read_only_route(
    ruleset: RuleSet,
) -> None:
    result = run(ruleset, group_permission_graph(), "external_phish")

    membership = ruleset.rule("group_membership").rule_id
    admin_permission = ruleset.rule("group_permission_admin").rule_id
    dump = ruleset.rule("credential_dump").rule_id
    assert path_shapes(result) == {
        (("e1", membership), ("e4", admin_permission), ("e7", dump)),
        (("e1", membership), ("e8", admin_permission), ("e9", dump)),
    }
    # The read-only group reaches the host and stops there; the distribution
    # group never confers membership at all.
    assert rejections_for(result, ruleset, "credential_dump", 1)
    assert rejections_for(result, ruleset, "group_membership", 3)


def test_kerberoast_reaches_the_database_only_through_the_weak_account(
    ruleset: RuleSet,
) -> None:
    result = run(ruleset, kerberoast_graph(), "external_phish")

    assert path_shapes(result) == {
        (
            ("<no edge>", ruleset.rule("kerberoast").rule_id),
            ("e1", ruleset.rule("service_account_access").rule_id),
        )
    }
    strength_refusals = rejections_for(result, ruleset, "kerberoast", 3)
    assert {r.dst_node_id for r in strength_refusals} == {"sa-strong"}


def test_exploit_chain_needs_all_three_steps_and_a_host_behind_on_patches(
    ruleset: RuleSet,
) -> None:
    result = run(ruleset, exploit_chain_graph(), "public_only")

    assert result.entry_node_ids == ("h-1", "h-2")
    assert path_shapes(result) == {
        (
            ("e1", ruleset.rule("remote_exploit").rule_id),
            ("e2", ruleset.rule("local_privesc").rule_id),
            ("e4", ruleset.rule("credential_dump").rule_id),
        )
    }
    patched = rejections_for(result, ruleset, "remote_exploit", 4)
    assert {r.src_node_id for r in patched} == {"h-2"}


# ── Cycles ───────────────────────────────────────────────────────────────────


def trust_cycle_graph() -> GraphSnapshot:
    """``h-a`` trusts ``h-b`` trusts ``h-a``, and both can be escalated on."""
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("h-a", "Host", status="active", patch_level="behind-2+"),
            node("h-b", "Host", crown_jewel=True, status="active", patch_level="behind-2+"),
            node("v-a", "Vulnerability", impact="privilege_escalation", attack_vector="local"),
            node("v-b", "Vulnerability", impact="privilege_escalation", attack_vector="local"),
        ],
        [
            edge("e1", "u-1", "h-a", "ADMIN_TO"),
            edge("e2", "h-a", "h-b", "TRUSTS", trust_type="ssh_key_trust"),
            edge("e3", "h-b", "h-a", "TRUSTS", trust_type="ssh_key_trust"),
            edge("e4", "h-a", "v-a", "HAS_VULNERABILITY"),
            edge("e5", "h-b", "v-b", "HAS_VULNERABILITY"),
        ],
    )


def test_trust_cycle_terminates_without_the_hop_cap(ruleset: RuleSet) -> None:
    result = run(ruleset, trust_cycle_graph(), "external_phish")

    # Nothing was cut short by the depth backstop: the search stopped because
    # going round the cycle again reproduced a state the branch already held.
    assert result.hop_cap_hits == 0
    assert all(path.target_node_id == "h-b" for path in result.paths)
    assert len(result.paths) == 3
    assert max(len(path.hops) for path in result.paths) == 5


def test_no_two_discovered_paths_are_the_same_path(ruleset: RuleSet) -> None:
    for graph in (
        trust_cycle_graph(),
        group_permission_graph(),
        credential_replay_graph(),
    ):
        result = run(ruleset, graph, "external_phish")
        keys = [canonical_path_key(p) for p in result.paths]
        assert len(keys) == len(set(keys))


def test_hop_cap_bounds_the_search(ruleset: RuleSet) -> None:
    result = run(ruleset, trust_cycle_graph(), "external_phish", max_hops=2)

    assert result.hop_cap_hits > 0
    assert all(len(path.hops) <= 2 for path in result.paths)


# ── Bidirectional edges ──────────────────────────────────────────────────────


def test_a_bidirectional_edge_is_traversable_from_either_end(ruleset: RuleSet) -> None:
    graph = snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("h-near", "Host", **LIVE_HOST),
            node("h-far", "Host", crown_jewel=True, **LIVE_HOST),
        ],
        [
            edge("e1", "u-1", "h-near", "ADMIN_TO"),
            edge("e2", "h-far", "h-near", "TRUSTS", bidirectional=True, trust_type="rdp"),
        ],
    )

    result = run(ruleset, graph, "external_phish")

    assert len(result.paths) == 1
    reverse_hop = result.paths[0].hops[-1]
    assert (reverse_hop.src_node_id, reverse_hop.dst_node_id) == ("h-near", "h-far")
    assert reverse_hop.edge_id == "e2"


# ── The fourteen negative controls ───────────────────────────────────────────


@dataclass(frozen=True)
class DecoyCase:
    """One decoy/twin pair, its graphs, and the row that must do the refusing."""

    code: str
    deciding_attribute: str
    decoy: GraphSnapshot
    twin: GraphSnapshot
    threat_model: str = "external_phish"
    decoy_kwargs: dict = dataclasses.field(default_factory=dict)
    twin_kwargs: dict = dataclasses.field(default_factory=dict)
    rejecting_rule: str | None = None
    rejecting_seq: int | None = None
    note: str = ""


def _authenticates_pair(decoy_logon: dict, twin_logon: dict) -> tuple[GraphSnapshot, GraphSnapshot]:
    """A user, their credential, and one host reached by presenting it."""

    def build(logon: dict) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node("cred-1", "Credential", **LIVE_CREDENTIAL),
                node("h-goal", "Host", crown_jewel=True, **LIVE_HOST),
            ],
            [
                edge("e1", "u-1", "cred-1", "HAS_CREDENTIAL"),
                edge("e2", "cred-1", "h-goal", "AUTHENTICATES_TO", **logon),
            ],
        )

    return build(decoy_logon), build(twin_logon)


def _d01() -> DecoyCase:
    decoy, twin = _authenticates_pair(
        {"mfa_required": True, "mfa_type": "fido2", "requires_compliant_device": False},
        {"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": False},
    )
    return DecoyCase(
        "d01_mfa_phishing_resistant",
        "AUTHENTICATES_TO.mfa_type",
        decoy,
        twin,
        rejecting_rule="credential_authenticate",
        rejecting_seq=2,
    )


def _d02() -> DecoyCase:
    def build(storage: str) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node("h-1", "Host", **LIVE_HOST),
                node("cred-goal", "Credential", crown_jewel=True, is_active=True, storage=storage),
            ],
            [
                edge("e1", "u-1", "h-1", "ADMIN_TO"),
                edge("e2", "h-1", "cred-goal", "EXPOSES_CREDENTIAL", location="config_file"),
            ],
        )

    return DecoyCase(
        "d02_vaulted_credential",
        "Credential.storage",
        build("vault"),
        build("config_file"),
        rejecting_rule="credential_dump",
        rejecting_seq=3,
    )


def _d03() -> DecoyCase:
    def build(permission_level: str) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node("g-1", "Group", type="security"),
                node("h-1", "Host", **LIVE_HOST),
                node("cred-goal", "Credential", crown_jewel=True, **LIVE_CREDENTIAL),
            ],
            [
                edge("e1", "u-1", "g-1", "MEMBER_OF"),
                edge("e2", "g-1", "h-1", "HAS_PERMISSION", permission_level=permission_level),
                edge("e3", "h-1", "cred-goal", "EXPOSES_CREDENTIAL", location="config_file"),
            ],
        )

    return DecoyCase(
        "d03_read_only_permission",
        "HAS_PERMISSION.permission_level",
        build("read_only"),
        build("admin"),
        rejecting_rule="group_permission_admin",
        rejecting_seq=2,
        note="Read-only still reaches the host; what it cannot do is read the secret on it.",
    )


def _d04() -> DecoyCase:
    def build(account_status: str) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status=account_status),
                node("h-goal", "Host", crown_jewel=True, **LIVE_HOST),
            ],
            [edge("e1", "u-1", "h-goal", "ADMIN_TO")],
        )

    return DecoyCase(
        "d04_disabled_account",
        "User.account_status",
        build("disabled"),
        build("active"),
        rejecting_rule="direct_admin",
        rejecting_seq=2,
    )


def _d05() -> DecoyCase:
    def build(bidirectional: bool) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node("h-near", "Host", **LIVE_HOST),
                node("h-far", "Host", crown_jewel=True, **LIVE_HOST),
            ],
            [
                edge("e1", "u-1", "h-near", "ADMIN_TO"),
                edge(
                    "e2",
                    "h-far",
                    "h-near",
                    "TRUSTS",
                    bidirectional=bidirectional,
                    trust_type="ssh_key_trust",
                ),
            ],
        )

    return DecoyCase(
        "d05_one_way_trust",
        "TRUSTS.bidirectional",
        build(False),
        build(True),
        note=(
            "A one-way trust offers no edge from the far end, so there is no candidate "
            "to refuse and no rejection is recorded."
        ),
    )


def _d06() -> DecoyCase:
    def build(strength: str) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node(
                    "sa-goal",
                    "ServiceAccount",
                    crown_jewel=True,
                    account_status="active",
                    has_spn=True,
                    credential_strength=strength,
                ),
            ],
            [],
        )

    return DecoyCase(
        "d06_strong_spn_password",
        "ServiceAccount.credential_strength",
        build("strong"),
        build("weak"),
        rejecting_rule="kerberoast",
        rejecting_seq=3,
    )


def _d07() -> DecoyCase:
    def build(patch_level: str) -> GraphSnapshot:
        return snapshot(
            [
                node("h-1", "Host", status="active", patch_level=patch_level),
                node("v-rce", "Vulnerability", impact="RCE", attack_vector="network"),
                node(
                    "v-privesc",
                    "Vulnerability",
                    impact="privilege_escalation",
                    attack_vector="local",
                ),
                node("cred-goal", "Credential", crown_jewel=True, **LIVE_CREDENTIAL),
            ],
            [
                edge("e1", "h-1", "v-rce", "HAS_VULNERABILITY"),
                edge("e2", "h-1", "v-privesc", "HAS_VULNERABILITY"),
                edge("e3", "h-1", "cred-goal", "EXPOSES_CREDENTIAL", location="config_file"),
            ],
        )

    return DecoyCase(
        "d07_patched_host",
        "Host.patch_level",
        build("current"),
        build("behind-2+"),
        threat_model="public_only",
        decoy_kwargs={"entry_node_ids": ("h-1",)},
        twin_kwargs={"entry_node_ids": ("h-1",)},
        rejecting_rule="remote_exploit",
        rejecting_seq=4,
    )


def _d08() -> DecoyCase:
    """The pair whose deciding factor is not in the graph at all.

    Same nodes, same edge, same attributes. Only what the attacker walked in
    holding differs, which is why no amount of graph inspection separates them.
    """
    graph = snapshot(
        [
            node("h-1", "Host", **LIVE_HOST),
            node("cred-goal", "Credential", crown_jewel=True, **LIVE_CREDENTIAL),
        ],
        [edge("e1", "h-1", "cred-goal", "EXPOSES_CREDENTIAL", location="config_file")],
    )
    return DecoyCase(
        "d08_no_admin_for_dump",
        "held capability",
        graph,
        graph,
        threat_model="public_only",
        decoy_kwargs={
            "entry_node_ids": ("h-1",),
            "extra_capabilities": frozenset({Capability("access_to", "h-1")}),
        },
        twin_kwargs={
            "entry_node_ids": ("h-1",),
            "extra_capabilities": frozenset({Capability("admin_on", "h-1")}),
        },
        rejecting_rule="credential_dump",
        rejecting_seq=1,
    )


def _d09() -> DecoyCase:
    def build(connected: bool) -> GraphSnapshot:
        edges = [edge("e2", "cr-dst", "v-rce", "HAS_VULNERABILITY")]
        if connected:
            edges.insert(
                0,
                edge("e1", "cr-src", "cr-dst", "CONNECTED_TO", connection_type="vpc_peering"),
            )
        return snapshot(
            [
                node("cr-src", "CloudResource", status="active", patch_level="behind-2+"),
                node(
                    "cr-dst",
                    "CloudResource",
                    crown_jewel=True,
                    status="active",
                    patch_level="behind-2+",
                ),
                node("v-rce", "Vulnerability", impact="RCE", attack_vector="network"),
            ],
            edges,
        )

    reached_the_source = {
        "entry_node_ids": ("cr-src",),
        "extra_capabilities": frozenset({Capability("code_exec_on", "cr-src")}),
    }
    return DecoyCase(
        "d09_segmented_network",
        "CONNECTED_TO presence",
        build(False),
        build(True),
        threat_model="public_only",
        decoy_kwargs=dict(reached_the_source),
        twin_kwargs=dict(reached_the_source),
        note=(
            "An absent edge is not a candidate, so as with D5 there is nothing to "
            "refuse and no rejection is recorded. Code execution on the source is "
            "supplied directly: no seeded rule can confer it on a CloudResource."
        ),
    )


def _d10() -> DecoyCase:
    def build(is_active: bool) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node("cred-1", "Credential", is_active=is_active, storage="config_file"),
                node("h-goal", "Host", crown_jewel=True, **LIVE_HOST),
            ],
            [
                edge("e1", "u-1", "cred-1", "HAS_CREDENTIAL"),
                edge("e2", "cred-1", "h-goal", "AUTHENTICATES_TO", **OPEN_LOGON),
            ],
        )

    return DecoyCase(
        "d10_rotated_credential",
        "Credential.is_active",
        build(False),
        build(True),
        rejecting_rule="credential_from_principal",
        rejecting_seq=2,
    )


def _d11() -> DecoyCase:
    def build(is_interactive: bool) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node(
                    "sa-1",
                    "ServiceAccount",
                    account_status="active",
                    has_spn=True,
                    credential_strength="weak",
                    is_interactive=is_interactive,
                ),
                node("cred-1", "Credential", **LIVE_CREDENTIAL),
                node("h-goal", "Host", crown_jewel=True, **LIVE_HOST),
            ],
            [
                edge("e1", "sa-1", "cred-1", "HAS_CREDENTIAL"),
                edge("e2", "cred-1", "h-goal", "AUTHENTICATES_TO", **OPEN_LOGON),
            ],
        )

    return DecoyCase(
        "d11_non_interactive_sa",
        "ServiceAccount.is_interactive",
        build(False),
        build(True),
        note=(
            "No seeded rule reads is_interactive, and R9 structurally cannot: its src "
            "is the credential and its dst the target asset, so the service account is "
            "not bound to the transition at all."
        ),
    )


def _d12() -> DecoyCase:
    def build(requires_separate_key: bool) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node(
                    "sa-1",
                    "ServiceAccount",
                    account_status="active",
                    has_spn=True,
                    credential_strength="weak",
                ),
                node(
                    "db-goal",
                    "Database",
                    crown_jewel=True,
                    status="active",
                    requires_separate_key=requires_separate_key,
                ),
            ],
            [edge("e1", "sa-1", "db-goal", "HAS_ACCESS_TO", permission_level="admin")],
        )

    return DecoyCase(
        "d12_separate_key_required",
        "Database.requires_separate_key",
        build(True),
        build(False),
        note=(
            "No seeded rule reads requires_separate_key. Unlike D11 this one is "
            "expressible: R5's dst is the database, so a single rule_precondition row "
            "would decide it."
        ),
    )


def _d13() -> DecoyCase:
    def build(group_type: str) -> GraphSnapshot:
        return snapshot(
            [
                node("u-1", "User", account_status="active"),
                node("g-1", "Group", type=group_type),
                node("h-goal", "Host", crown_jewel=True, **LIVE_HOST),
            ],
            [
                edge("e1", "u-1", "g-1", "MEMBER_OF"),
                edge("e2", "g-1", "h-goal", "HAS_PERMISSION", permission_level="admin"),
            ],
        )

    return DecoyCase(
        "d13_distribution_group",
        "Group.type",
        build("distribution"),
        build("security"),
        rejecting_rule="group_membership",
        rejecting_seq=3,
    )


def _d14() -> DecoyCase:
    decoy, twin = _authenticates_pair(
        {"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": True},
        {"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": False},
    )
    return DecoyCase(
        "d14_device_compliance",
        "AUTHENTICATES_TO.requires_compliant_device",
        decoy,
        twin,
        rejecting_rule="credential_authenticate",
        rejecting_seq=3,
    )


#: The rule rows do not encode these two, so the oracle cannot decide them. The
#: cases are kept and marked rather than dropped: they are the measurement.
UNDECIDABLE_ON_SEEDED_RULES = {
    "d11_non_interactive_sa": (
        "no rule_precondition row reads ServiceAccount.is_interactive, and R9 cannot "
        "reach the service account from an AUTHENTICATES_TO edge"
    ),
    "d12_separate_key_required": (
        "no rule_precondition row reads Database.requires_separate_key"
    ),
}


def decoy_cases() -> list[DecoyCase]:
    return [
        _d01(), _d02(), _d03(), _d04(), _d05(), _d06(), _d07(),
        _d08(), _d09(), _d10(), _d11(), _d12(), _d13(), _d14(),
    ]


def _parametrised_cases():
    for case in decoy_cases():
        reason = UNDECIDABLE_ON_SEEDED_RULES.get(case.code)
        marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
        yield pytest.param(case, id=case.code, marks=marks)


@pytest.mark.parametrize("case", list(_parametrised_cases()))
def test_decoy_is_refused_and_its_twin_is_accepted(ruleset: RuleSet, case: DecoyCase) -> None:
    decoy = run(ruleset, case.decoy, case.threat_model, **case.decoy_kwargs)
    twin = run(ruleset, case.twin, case.threat_model, **case.twin_kwargs)

    assert twin.paths, f"{case.code}: the twin is a genuine path and must be found"
    assert not decoy.paths, (
        f"{case.code}: the decoy must be refused, but the oracle found "
        f"{path_shapes(decoy)}"
    )

    if case.rejecting_rule is None:
        return
    refusals = rejections_for(ruleset=ruleset, result=decoy, rule_code=case.rejecting_rule, seq=case.rejecting_seq)
    assert refusals, (
        f"{case.code}: expected {case.rejecting_rule} seq {case.rejecting_seq} to be "
        f"the reason, got {[(r.rule_id, r.precondition_seq) for r in decoy.rejections]}"
    )
    for refusal in refusals:
        assert refusal.reason_text.strip()
        assert refusal.observed_value


def test_every_decoy_pattern_in_the_spec_has_a_case() -> None:
    assert len(decoy_cases()) == 14
    assert len({case.code for case in decoy_cases()}) == 14


# ── Rejections say something true ────────────────────────────────────────────


def test_every_rejection_names_a_precondition_that_genuinely_does_not_hold(
    ruleset: RuleSet,
) -> None:
    """`docs/RULES.md` §7 invariant 9, checked without trusting the search.

    Attribute preconditions do not depend on the attacker's state, so they can
    be re-evaluated here from the graph alone and must still fail. A capability
    precondition does depend on state, and the state is not carried on the
    rejection row — what is checked instead is that the evaluator recorded the
    capability as absent, which is the observation the refusal rests on.
    """
    graphs = [
        (credential_replay_graph(), "external_phish"),
        (group_permission_graph(), "external_phish"),
        (kerberoast_graph(), "external_phish"),
        (exploit_chain_graph(), "public_only"),
        (trust_cycle_graph(), "external_phish"),
    ]
    checked = 0
    for graph, threat_model in graphs:
        result = run(ruleset, graph, threat_model)
        for rejection in result.rejections:
            rule = ruleset.by_id(rejection.rule_id)
            precondition = next(
                p for p in rule.preconditions if p.seq == rejection.precondition_seq
            )
            assert rejection.reason_text == precondition.failure_reason
            assert rejection.reason_text.strip()

            if precondition.kind == PreconditionKind.CAPABILITY:
                assert rejection.observed_value.endswith("=absent")
            else:
                outcome = evaluate_precondition(
                    precondition,
                    capabilities=frozenset(),
                    edge=graph.edge(rejection.edge_id) if rejection.edge_id else None,
                    src_node=graph.node(rejection.src_node_id),
                    dst_node=graph.node(rejection.dst_node_id),
                    global_capability_codes=ruleset.global_capability_codes,
                )
                assert not outcome.holds, (
                    f"{rule.code} seq {precondition.seq} was reported as failing on "
                    f"{rejection.src_node_id} -> {rejection.dst_node_id} but holds"
                )
            checked += 1
    assert checked > 50


def test_every_discovered_path_re_verifies_hop_by_hop(ruleset: RuleSet) -> None:
    """`docs/RULES.md` §7 invariant 5."""
    graphs = [
        (credential_replay_graph(), "external_phish"),
        (group_permission_graph(), "external_phish"),
        (kerberoast_graph(), "external_phish"),
        (exploit_chain_graph(), "public_only"),
        (trust_cycle_graph(), "external_phish"),
    ]
    verified = 0
    for graph, threat_model_code in graphs:
        threat_model = ruleset.threat_models[threat_model_code]
        result = run(ruleset, graph, threat_model_code)
        for path in result.paths:
            problems = verify_path(
                path,
                snapshot=graph,
                ruleset=ruleset,
                initial_capabilities=materialise_grants(
                    ruleset, threat_model, graph, path.source_node_id
                ),
            )
            assert problems == (), f"{path.path_id}: {problems}"
            verified += 1
    assert verified >= 8


def test_the_verifier_rejects_a_path_that_did_not_happen(ruleset: RuleSet) -> None:
    """The verifier is only evidence if it can fail. Hand it a forged hop."""
    graph = credential_replay_graph()
    threat_model = ruleset.threat_models["external_phish"]
    path = run(ruleset, graph, "external_phish").paths[0]

    forged = dataclasses.replace(
        path,
        hops=(
            dataclasses.replace(
                path.hops[0], rule_id=ruleset.rule("credential_dump").rule_id
            ),
        )
        + path.hops[1:],
    )
    problems = verify_path(
        forged,
        snapshot=graph,
        ruleset=ruleset,
        initial_capabilities=materialise_grants(ruleset, threat_model, graph, "u-1"),
    )
    assert problems


# ── Goals and entry points are parameters, not assumptions ───────────────────


def test_the_goal_set_can_be_something_other_than_the_crown_jewels(
    ruleset: RuleSet,
) -> None:
    graph = group_permission_graph()

    default_run = run(ruleset, graph, "external_phish")
    assert {p.target_node_id for p in default_run.paths} == {"cred-1"}

    host_run = run(ruleset, graph, "external_phish", goal_node_ids=frozenset({"h-1", "h-2"}))
    assert {p.target_node_id for p in host_run.paths} == {"h-1", "h-2"}
    assert all(not p.target_is_crown_jewel for p in host_run.paths)


def test_a_kind_scoped_grant_lands_on_the_entry_node_it_matches(ruleset: RuleSet) -> None:
    graph = credential_replay_graph()
    insider = ruleset.threat_models["insider_standard"]

    held = materialise_grants(ruleset, insider, graph, "u-1")

    # One principal, per docs/RULES.md §3 -- not every user in the directory.
    assert Capability("controls_principal", "u-1") in held
    assert Capability("controls_principal", "u-2") not in held
    # Network reach, however, is to internal assets plural.
    assert Capability("network_reach", "h-1") in held
    assert Capability("network_reach", "h-2") in held
    assert Capability("authenticated", None) in held

    assert entry_nodes_for(ruleset, insider, graph) == ("h-1", "h-2", "u-1", "u-2")


# ── Determinism and scale ────────────────────────────────────────────────────


def thirty_node_graph() -> GraphSnapshot:
    """A synthetic graph of exactly thirty nodes, built without randomness.

    Five users in five groups holding permissions over five hosts; the hosts
    leak five credentials, which authenticate back to other hosts; two
    kerberoastable service accounts reach three databases; two hosts are behind
    on patches and carry vulnerabilities.
    """
    nodes: list[Node] = []
    edges: list[Edge] = []

    for i in range(5):
        nodes.append(node(f"u-{i}", "User", account_status="active"))
        nodes.append(node(f"g-{i}", "Group", type="security" if i % 2 == 0 else "distribution"))
        nodes.append(
            node(
                f"h-{i}",
                "Host",
                status="active",
                patch_level="behind-2+" if i < 2 else "current",
            )
        )
        nodes.append(node(f"cred-{i}", "Credential", **LIVE_CREDENTIAL))
    for i in range(5):
        nodes.append(
            node(
                f"sa-{i}",
                "ServiceAccount",
                account_status="active",
                has_spn=i < 2,
                credential_strength="weak" if i < 2 else "strong",
            )
        )
    for i in range(3):
        nodes.append(node(f"db-{i}", "Database", crown_jewel=i == 0, status="active"))
    nodes.append(node("v-rce", "Vulnerability", impact="RCE", attack_vector="network"))
    nodes.append(node("v-privesc", "Vulnerability", impact="privilege_escalation", attack_vector="local"))
    assert len(nodes) == 30

    for i in range(5):
        edges.append(edge(f"e-mem-{i}", f"u-{i}", f"g-{i}", "MEMBER_OF"))
        edges.append(
            edge(
                f"e-perm-{i}",
                f"g-{i}",
                f"h-{i}",
                "HAS_PERMISSION",
                permission_level="admin" if i % 2 == 0 else "read_only",
            )
        )
        edges.append(
            edge(f"e-exp-{i}", f"h-{i}", f"cred-{i}", "EXPOSES_CREDENTIAL", location="config_file")
        )
        edges.append(
            edge(
                f"e-auth-{i}",
                f"cred-{i}",
                f"h-{(i + 1) % 5}",
                "AUTHENTICATES_TO",
                **OPEN_LOGON,
            )
        )
        edges.append(edge(f"e-own-{i}", f"u-{i}", f"cred-{i}", "HAS_CREDENTIAL"))
    for i in range(5):
        edges.append(
            edge(
                f"e-sa-{i}",
                f"sa-{i}",
                f"db-{i % 3}",
                "HAS_ACCESS_TO",
                permission_level="admin",
            )
        )
    for i in range(2):
        edges.append(edge(f"e-vuln-rce-{i}", f"h-{i}", "v-rce", "HAS_VULNERABILITY"))
        edges.append(edge(f"e-vuln-pe-{i}", f"h-{i}", "v-privesc", "HAS_VULNERABILITY"))
    for i in range(5):
        # A second permission per group and a ring of trusts, so the search has
        # branching to do rather than five independent chains.
        edges.append(
            edge(
                f"e-perm2-{i}",
                f"g-{i}",
                f"h-{(i + 2) % 5}",
                "HAS_PERMISSION",
                permission_level="admin",
            )
        )
        edges.append(
            edge(f"e-trust-{i}", f"h-{i}", f"h-{(i + 1) % 5}", "TRUSTS", trust_type="rdp")
        )

    return snapshot(nodes, edges)


def test_thirty_node_graph_finishes_and_is_timed(ruleset: RuleSet) -> None:
    graph = thirty_node_graph()
    assert len(graph) == 30

    started = time.perf_counter()
    result = run(ruleset, graph, "external_phish")
    elapsed = time.perf_counter() - started

    print(
        f"\n30 nodes / {len(list(graph.all_edges))} edges: {elapsed:.3f}s wall clock, "
        f"{result.states_expanded} states expanded, {len(result.paths)} paths, "
        f"{len(result.rejections)} distinct rejections"
    )
    assert result.paths
    assert elapsed < 120


def test_two_runs_of_the_same_graph_are_identical(ruleset: RuleSet) -> None:
    """`docs/RULES.md` §7 invariant 10, including tie ordering."""
    graph = thirty_node_graph()

    first = run(ruleset, graph, "external_phish")
    second = run(ruleset, graph, "external_phish")

    assert [p.path_id for p in first.paths] == [p.path_id for p in second.paths]
    assert [canonical_path_key(p) for p in first.paths] == [
        canonical_path_key(p) for p in second.paths
    ]
    assert [r.signature for r in first.rejections] == [r.signature for r in second.rejections]
    assert first.states_expanded == second.states_expanded
