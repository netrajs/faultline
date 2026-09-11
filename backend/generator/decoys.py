"""The fourteen paired negative controls.

``docs/RULES.md`` SS5 names fourteen decoy patterns, each with a twin that is a
genuine attack path differing in exactly one attribute. This module builds
both instances of every pair as ordinary primitive facts -- nothing here is
tagged in the graph itself as a decoy; the only place that information lives
is the registry rows returned alongside the graph, which mirror
``decoy_pattern`` / ``decoy_instance`` in
``backend/db/migrations/007_ground_truth.sql``.

Two design rules, applied uniformly:

  Isolation. Every pair gets its own small, dedicated set of nodes rather than
  reusing background or scenario nodes, so a later change to the background
  generator can never accidentally shift a decoy's deciding attribute.

  Exactly one difference. Where the deciding attribute lives on an edge or a
  node, the decoy and twin share every other attribute value; only the named
  one differs. Two pairs cannot do this literally: D8's deciding factor is the
  attacker's own held capability rather than anything in the graph, so decoy
  and twin reference the very same edge and node; D9's deciding factor is
  whether a ``CONNECTED_TO`` edge exists at all, so decoy and twin necessarily
  involve different node pairs -- one connected, one not.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.ids import SeedBundle
from core.model import EdgeType, NodeKind

from .graph import GraphBuilder

DECOY_CODES: tuple[str, ...] = (
    "d01_mfa_phishing_resistant",
    "d02_vaulted_credential",
    "d03_read_only_permission",
    "d04_disabled_account",
    "d05_one_way_trust",
    "d06_strong_spn_password",
    "d07_patched_host",
    "d08_no_admin_for_dump",
    "d09_segmented_network",
    "d10_rotated_credential",
    "d11_non_interactive_sa",
    "d12_separate_key_required",
    "d13_distribution_group",
    "d14_device_compliance",
)


@dataclass(frozen=True, slots=True)
class DecoyInstance:
    decoy_code: str
    role: str
    """'decoy' or 'twin'."""
    expected_outcome: str
    """'reject' or 'accept'."""
    deciding_value: str
    edge_id: str | None = None
    node_id: str | None = None


def plant_decoys(builder: GraphBuilder, bundle: SeedBundle) -> list[DecoyInstance]:
    rng = bundle.stream("decoys.attrs")
    out: list[DecoyInstance] = []
    out += _d01_mfa(builder)
    out += _d02_vault(builder)
    out += _d03_permission_level(builder)
    out += _d04_account_status(builder)
    out += _d05_trust_direction(builder)
    out += _d06_spn_password(builder)
    out += _d07_patch_level(builder)
    out += _d08_capability(builder)
    out += _d09_segmentation(builder)
    out += _d10_rotated(builder)
    out += _d11_non_interactive(builder)
    out += _d12_separate_key(builder)
    out += _d13_distribution_group(builder)
    out += _d14_device_compliance(builder)
    return out


# ── D1 -- AUTHENTICATES_TO.mfa_type ──────────────────────────────────────────


def _shared_credential(builder: GraphBuilder, tag: str):
    user = builder.add_node(
        NodeKind.USER.value,
        name=f"decoy-user-{tag}",
        attrs={"department": "Decoy Fixtures", "account_status": "active", "mfa_enabled": True},
    )
    cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name=f"decoy-cred-{tag}",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": True, "strength": "medium"},
    )
    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, user, cred, attrs={})
    return user, cred


def _d01_mfa(builder: GraphBuilder) -> list[DecoyInstance]:
    _, cred = _shared_credential(builder, "d01")
    decoy_target = builder.add_node(
        NodeKind.HOST.value, name="d01-decoy-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_target = builder.add_node(
        NodeKind.HOST.value, name="d01-twin-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    decoy_edge = builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        cred,
        decoy_target,
        attrs={"mfa_required": True, "mfa_type": "fido2", "requires_compliant_device": False, "scope": "standard"},
    )
    twin_edge = builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        cred,
        twin_target,
        attrs={"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": False, "scope": "standard"},
    )
    return [
        DecoyInstance("d01_mfa_phishing_resistant", "decoy", "reject", "fido2", edge_id=decoy_edge.edge_id),
        DecoyInstance("d01_mfa_phishing_resistant", "twin", "accept", "sms", edge_id=twin_edge.edge_id),
    ]


# ── D2 -- Credential.storage ─────────────────────────────────────────────────


def _d02_vault(builder: GraphBuilder) -> list[DecoyInstance]:
    admin_user = builder.add_node(
        NodeKind.USER.value, name="d02-admin-user", attrs={"account_status": "active", "mfa_enabled": True}
    )
    host = builder.add_node(
        NodeKind.HOST.value, name="d02-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    builder.add_edge(EdgeType.ADMIN_TO.value, admin_user, host, attrs={})

    decoy_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name="d02-decoy-cred",
        attrs={"credential_type": "password", "storage": "vault", "is_active": True, "strength": "medium"},
    )
    twin_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name="d02-twin-cred",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": True, "strength": "medium"},
    )
    decoy_edge = builder.add_edge(
        EdgeType.EXPOSES_CREDENTIAL.value, host, decoy_cred, attrs={"location": "config_file"}
    )
    twin_edge = builder.add_edge(
        EdgeType.EXPOSES_CREDENTIAL.value, host, twin_cred, attrs={"location": "config_file"}
    )
    return [
        DecoyInstance("d02_vaulted_credential", "decoy", "reject", "vault", edge_id=decoy_edge.edge_id, node_id=decoy_cred.node_id),
        DecoyInstance("d02_vaulted_credential", "twin", "accept", "config_file", edge_id=twin_edge.edge_id, node_id=twin_cred.node_id),
    ]


# ── D3 -- HAS_PERMISSION.permission_level ────────────────────────────────────


def _d03_permission_level(builder: GraphBuilder) -> list[DecoyInstance]:
    user = builder.add_node(NodeKind.USER.value, name="d03-user", attrs={"account_status": "active", "mfa_enabled": True})
    group = builder.add_node(NodeKind.GROUP.value, name="d03-group", attrs={"type": "security"})
    builder.add_edge(EdgeType.MEMBER_OF.value, user, group, attrs={})

    decoy_target = builder.add_node(
        NodeKind.HOST.value, name="d03-decoy-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_target = builder.add_node(
        NodeKind.HOST.value, name="d03-twin-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    decoy_edge = builder.add_edge(
        EdgeType.HAS_PERMISSION.value, group, decoy_target, attrs={"permission_level": "read_only"}
    )
    twin_edge = builder.add_edge(
        EdgeType.HAS_PERMISSION.value, group, twin_target, attrs={"permission_level": "admin"}
    )
    return [
        DecoyInstance("d03_read_only_permission", "decoy", "reject", "read_only", edge_id=decoy_edge.edge_id),
        DecoyInstance("d03_read_only_permission", "twin", "accept", "admin", edge_id=twin_edge.edge_id),
    ]


# ── D4 -- User.account_status ────────────────────────────────────────────────


def _d04_account_status(builder: GraphBuilder) -> list[DecoyInstance]:
    decoy_user = builder.add_node(
        NodeKind.USER.value, name="d04-decoy-user", attrs={"account_status": "disabled", "mfa_enabled": True}
    )
    twin_user = builder.add_node(
        NodeKind.USER.value, name="d04-twin-user", attrs={"account_status": "active", "mfa_enabled": True}
    )
    decoy_target = builder.add_node(
        NodeKind.HOST.value, name="d04-decoy-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_target = builder.add_node(
        NodeKind.HOST.value, name="d04-twin-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    decoy_edge = builder.add_edge(EdgeType.ADMIN_TO.value, decoy_user, decoy_target, attrs={})
    twin_edge = builder.add_edge(EdgeType.ADMIN_TO.value, twin_user, twin_target, attrs={})
    return [
        DecoyInstance("d04_disabled_account", "decoy", "reject", "disabled", edge_id=decoy_edge.edge_id, node_id=decoy_user.node_id),
        DecoyInstance("d04_disabled_account", "twin", "accept", "active", edge_id=twin_edge.edge_id, node_id=twin_user.node_id),
    ]


# ── D5 -- TRUSTS.bidirectional ───────────────────────────────────────────────


def _d05_trust_direction(builder: GraphBuilder) -> list[DecoyInstance]:
    decoy_far = builder.add_node(
        NodeKind.HOST.value, name="d05-decoy-far", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    decoy_near = builder.add_node(
        NodeKind.HOST.value, name="d05-decoy-near", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    decoy_admin = builder.add_node(NodeKind.USER.value, name="d05-decoy-admin", attrs={"account_status": "active", "mfa_enabled": True})
    builder.add_edge(EdgeType.ADMIN_TO.value, decoy_admin, decoy_near, attrs={})
    decoy_edge = builder.add_edge(
        EdgeType.TRUSTS.value, decoy_far, decoy_near, attrs={"bidirectional": False, "trust_type": "ssh_key_trust"}
    )

    twin_far = builder.add_node(
        NodeKind.HOST.value, name="d05-twin-far", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_near = builder.add_node(
        NodeKind.HOST.value, name="d05-twin-near", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_admin = builder.add_node(NodeKind.USER.value, name="d05-twin-admin", attrs={"account_status": "active", "mfa_enabled": True})
    builder.add_edge(EdgeType.ADMIN_TO.value, twin_admin, twin_near, attrs={})
    twin_edge = builder.add_edge(
        EdgeType.TRUSTS.value, twin_far, twin_near, attrs={"bidirectional": True, "trust_type": "ssh_key_trust"}
    )

    return [
        DecoyInstance("d05_one_way_trust", "decoy", "reject", "false", edge_id=decoy_edge.edge_id),
        DecoyInstance("d05_one_way_trust", "twin", "accept", "true", edge_id=twin_edge.edge_id),
    ]


# ── D6 -- Credential.strength (read by the engine as ServiceAccount.credential_strength) ──


def _d06_spn_password(builder: GraphBuilder) -> list[DecoyInstance]:
    decoy_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name="d06-decoy-sa",
        attrs={"account_status": "active", "has_spn": True, "credential_strength": "strong", "is_interactive": False},
    )
    twin_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name="d06-twin-sa",
        attrs={"account_status": "active", "has_spn": True, "credential_strength": "weak", "is_interactive": False},
    )
    return [
        DecoyInstance("d06_strong_spn_password", "decoy", "reject", "strong", node_id=decoy_sa.node_id),
        DecoyInstance("d06_strong_spn_password", "twin", "accept", "weak", node_id=twin_sa.node_id),
    ]


# ── D7 -- Host.patch_level ────────────────────────────────────────────────────


def _d07_patch_level(builder: GraphBuilder) -> list[DecoyInstance]:
    decoy_host = builder.add_node(
        NodeKind.HOST.value, name="d07-decoy-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_host = builder.add_node(
        NodeKind.HOST.value, name="d07-twin-host", attrs={"os": "linux", "patch_level": "behind-2+", "status": "active"}
    )
    vuln_attrs = {"impact": "RCE", "attack_vector": "network", "epss": 0.6, "cvss": 8.0}
    decoy_vuln = builder.add_node(NodeKind.VULNERABILITY.value, name="CVE-2022-90001", attrs=dict(vuln_attrs))
    twin_vuln = builder.add_node(NodeKind.VULNERABILITY.value, name="CVE-2022-90002", attrs=dict(vuln_attrs))
    builder.add_edge(EdgeType.HAS_VULNERABILITY.value, decoy_host, decoy_vuln, attrs={})
    builder.add_edge(EdgeType.HAS_VULNERABILITY.value, twin_host, twin_vuln, attrs={})
    return [
        DecoyInstance("d07_patched_host", "decoy", "reject", "current", node_id=decoy_host.node_id),
        DecoyInstance("d07_patched_host", "twin", "accept", "behind-2+", node_id=twin_host.node_id),
    ]


# ── D8 -- held capability, not a graph attribute ─────────────────────────────


def _d08_capability(builder: GraphBuilder) -> list[DecoyInstance]:
    host = builder.add_node(
        NodeKind.HOST.value, name="d08-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name="d08-cred",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": True, "strength": "medium"},
    )
    edge = builder.add_edge(EdgeType.EXPOSES_CREDENTIAL.value, host, cred, attrs={"location": "config_file"})
    # Decoy and twin are the identical fact: same host, same edge, same
    # credential. What must differ is the attacker's held capability, which
    # is not a graph attribute at all -- see docs/RULES.md SS5.
    return [
        DecoyInstance("d08_no_admin_for_dump", "decoy", "reject", "access_to", edge_id=edge.edge_id, node_id=host.node_id),
        DecoyInstance("d08_no_admin_for_dump", "twin", "accept", "admin_on", edge_id=edge.edge_id, node_id=host.node_id),
    ]


# ── D9 -- CONNECTED_TO presence ──────────────────────────────────────────────


def _d09_segmentation(builder: GraphBuilder) -> list[DecoyInstance]:
    decoy_admin = builder.add_node(NodeKind.USER.value, name="d09-decoy-admin", attrs={"account_status": "active", "mfa_enabled": True})
    decoy_src = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value, name="d09-decoy-src", attrs={"resource_type": "workload", "status": "active"}
    )
    decoy_dst = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value, name="d09-decoy-dst", attrs={"resource_type": "workload", "status": "active"}
    )
    builder.add_edge(EdgeType.ADMIN_TO.value, decoy_admin, decoy_src, attrs={})
    # No CONNECTED_TO edge between decoy_src and decoy_dst: that absence is
    # the entire point of this pair.

    twin_admin = builder.add_node(NodeKind.USER.value, name="d09-twin-admin", attrs={"account_status": "active", "mfa_enabled": True})
    twin_src = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value, name="d09-twin-src", attrs={"resource_type": "workload", "status": "active"}
    )
    twin_dst = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value, name="d09-twin-dst", attrs={"resource_type": "workload", "status": "active"}
    )
    builder.add_edge(EdgeType.ADMIN_TO.value, twin_admin, twin_src, attrs={})
    twin_edge = builder.add_edge(
        EdgeType.CONNECTED_TO.value, twin_src, twin_dst, attrs={"connection_type": "vpc_peering", "grants_admin": False}
    )

    return [
        DecoyInstance("d09_segmented_network", "decoy", "reject", "absent", node_id=decoy_src.node_id),
        DecoyInstance("d09_segmented_network", "twin", "accept", "present", edge_id=twin_edge.edge_id, node_id=twin_src.node_id),
    ]


# ── D10 -- Credential.is_active ──────────────────────────────────────────────


def _d10_rotated(builder: GraphBuilder) -> list[DecoyInstance]:
    user = builder.add_node(NodeKind.USER.value, name="d10-user", attrs={"account_status": "active", "mfa_enabled": True})
    decoy_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name="d10-decoy-cred",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": False, "strength": "medium"},
    )
    twin_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name="d10-twin-cred",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": True, "strength": "medium"},
    )
    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, user, decoy_cred, attrs={})
    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, user, twin_cred, attrs={})
    return [
        DecoyInstance("d10_rotated_credential", "decoy", "reject", "false", node_id=decoy_cred.node_id),
        DecoyInstance("d10_rotated_credential", "twin", "accept", "true", node_id=twin_cred.node_id),
    ]


# ── D11 -- ServiceAccount.is_interactive ─────────────────────────────────────


def _d11_non_interactive(builder: GraphBuilder) -> list[DecoyInstance]:
    decoy_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name="d11-decoy-sa",
        attrs={"account_status": "active", "has_spn": False, "credential_strength": "strong", "is_interactive": False},
    )
    twin_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name="d11-twin-sa",
        attrs={"account_status": "active", "has_spn": False, "credential_strength": "strong", "is_interactive": True},
    )
    decoy_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name="d11-decoy-cred",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": True, "strength": "strong"},
    )
    twin_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name="d11-twin-cred",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": True, "strength": "strong"},
    )
    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, decoy_sa, decoy_cred, attrs={})
    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, twin_sa, twin_cred, attrs={})
    return [
        DecoyInstance("d11_non_interactive_sa", "decoy", "reject", "false", node_id=decoy_sa.node_id),
        DecoyInstance("d11_non_interactive_sa", "twin", "accept", "true", node_id=twin_sa.node_id),
    ]


# ── D12 -- Database.requires_separate_key ────────────────────────────────────


def _d12_separate_key(builder: GraphBuilder) -> list[DecoyInstance]:
    decoy_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name="d12-decoy-sa",
        attrs={"account_status": "active", "has_spn": False, "credential_strength": "strong", "is_interactive": False},
    )
    twin_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name="d12-twin-sa",
        attrs={"account_status": "active", "has_spn": False, "credential_strength": "strong", "is_interactive": False},
    )
    decoy_db = builder.add_node(
        NodeKind.DATABASE.value,
        name="d12-decoy-db",
        criticality="high",
        classification="restricted",
        attrs={"engine": "postgres", "requires_separate_key": True, "status": "active"},
    )
    twin_db = builder.add_node(
        NodeKind.DATABASE.value,
        name="d12-twin-db",
        criticality="high",
        classification="restricted",
        attrs={"engine": "postgres", "requires_separate_key": False, "status": "active"},
    )
    builder.add_edge(EdgeType.HAS_ACCESS_TO.value, decoy_sa, decoy_db, attrs={"permission_level": "admin"})
    builder.add_edge(EdgeType.HAS_ACCESS_TO.value, twin_sa, twin_db, attrs={"permission_level": "admin"})
    return [
        DecoyInstance("d12_separate_key_required", "decoy", "reject", "true", node_id=decoy_db.node_id),
        DecoyInstance("d12_separate_key_required", "twin", "accept", "false", node_id=twin_db.node_id),
    ]


# ── D13 -- Group.type ─────────────────────────────────────────────────────────


def _d13_distribution_group(builder: GraphBuilder) -> list[DecoyInstance]:
    user = builder.add_node(NodeKind.USER.value, name="d13-user", attrs={"account_status": "active", "mfa_enabled": True})
    decoy_group = builder.add_node(NodeKind.GROUP.value, name="d13-decoy-group", attrs={"type": "distribution"})
    twin_group = builder.add_node(NodeKind.GROUP.value, name="d13-twin-group", attrs={"type": "security"})
    decoy_edge = builder.add_edge(EdgeType.MEMBER_OF.value, user, decoy_group, attrs={})
    twin_edge = builder.add_edge(EdgeType.MEMBER_OF.value, user, twin_group, attrs={})
    decoy_target = builder.add_node(
        NodeKind.HOST.value, name="d13-decoy-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_target = builder.add_node(
        NodeKind.HOST.value, name="d13-twin-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    builder.add_edge(EdgeType.HAS_PERMISSION.value, decoy_group, decoy_target, attrs={"permission_level": "admin"})
    builder.add_edge(EdgeType.HAS_PERMISSION.value, twin_group, twin_target, attrs={"permission_level": "admin"})
    return [
        DecoyInstance("d13_distribution_group", "decoy", "reject", "distribution", edge_id=decoy_edge.edge_id, node_id=decoy_group.node_id),
        DecoyInstance("d13_distribution_group", "twin", "accept", "security", edge_id=twin_edge.edge_id, node_id=twin_group.node_id),
    ]


# ── D14 -- AUTHENTICATES_TO.requires_compliant_device ────────────────────────


def _d14_device_compliance(builder: GraphBuilder) -> list[DecoyInstance]:
    _, cred = _shared_credential(builder, "d14")
    decoy_target = builder.add_node(
        NodeKind.HOST.value, name="d14-decoy-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    twin_target = builder.add_node(
        NodeKind.HOST.value, name="d14-twin-host", attrs={"os": "linux", "patch_level": "current", "status": "active"}
    )
    decoy_edge = builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        cred,
        decoy_target,
        attrs={"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": True, "scope": "standard"},
    )
    twin_edge = builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        cred,
        twin_target,
        attrs={"mfa_required": True, "mfa_type": "sms", "requires_compliant_device": False, "scope": "standard"},
    )
    return [
        DecoyInstance("d14_device_compliance", "decoy", "reject", "true", edge_id=decoy_edge.edge_id),
        DecoyInstance("d14_device_compliance", "twin", "accept", "false", edge_id=twin_edge.edge_id),
    ]
