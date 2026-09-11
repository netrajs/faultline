"""Planted escalation opportunities.

Each function here constructs the primitive edges that make one named
opportunity possible -- nested group memberships, a shared credential, a
trust relationship -- and returns only the *intent*: which scenario, where it
starts, where it ends, and a sentence of prose. Never the route between the
two. ``docs/SCOPE.md`` D8 is explicit about why: recording the path would let
the evaluation harness check that the engine can read rather than that it can
discover.

The scenario codes and their intent text are already seeded in
``backend/db/seed/050_ground_truth.sql`` (table ``scenario``); the codes here
must match those rows exactly, because ``plant_log.scenario_code`` is a
foreign key into it.

Every opportunity is built entirely from rule-satisfying primitive facts --
active accounts, security groups, admin permission levels, admin-granting
trust types -- so that whether the engine actually finds it is a real
question and not a foregone conclusion baked in by a missing attribute.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from core.ids import SeedBundle
from core.model import EdgeType, NodeKind

from . import attributes as attr
from .graph import Background, GraphBuilder

SCENARIO_CODES: tuple[str, ...] = (
    "intern_to_domain_admin",
    "leaked_key_to_data",
    "kerberoast_to_app",
    "stale_vendor_vpn",
    "nested_group_cloud",
    "unpatched_edge_pivot",
    "shared_cred_sprawl",
    "ci_pipeline_to_prod",
)


@dataclass(frozen=True, slots=True)
class PlantedScenario:
    scenario_code: str
    entry_node_id: str
    goal_node_id: str
    notes: str


def plant_scenarios(
    builder: GraphBuilder,
    background: Background,
    bundle: SeedBundle,
    count: int,
) -> list[PlantedScenario]:
    """Plant ``count`` opportunities, cycling through the eight scenario codes.

    Cycling rather than refusing past eight means the count parameter genuinely
    controls how many opportunities exist, which is what the eval harness
    needs to vary across seeds (``docs/SCOPE.md`` D8: "five planted paths
    cannot support any of this").
    """
    if count < 0:
        raise ValueError("scenario count must not be negative")

    rng = bundle.stream("scenarios.topology")
    planted: list[PlantedScenario] = []
    for i in range(count):
        code = SCENARIO_CODES[i % len(SCENARIO_CODES)]
        instance = i // len(SCENARIO_CODES)
        planter = _PLANTERS[code]
        entry, goal, notes = planter(builder, background, rng, instance)
        planted.append(
            PlantedScenario(
                scenario_code=code,
                entry_node_id=entry.node_id,
                goal_node_id=goal.node_id,
                notes=notes,
            )
        )
    return planted


# ── Individual planters ──────────────────────────────────────────────────────
#
# Each returns (entry_node, goal_node, notes). Depth and fan-out follow the
# expected_min_hops/expected_max_hops recorded for the scenario in the seed
# table, so a planted instance actually falls in the range the manifest
# claims for it.


def _tag(instance: int) -> str:
    return f"-{instance:02d}" if instance else ""


def _plant_intern_to_domain_admin(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    intern = builder.add_node(
        NodeKind.USER.value,
        name=f"intern.hire{tag}",
        display_name=f"New Intern{tag}",
        attrs={"department": "Engineering Internship", "account_status": "active", "mfa_enabled": True},
    )
    da_host = builder.add_node(
        NodeKind.HOST.value,
        name=f"dc-tier0{tag}",
        display_name=f"Tier-0 Domain Controller{tag}",
        is_crown_jewel=True,
        criticality="critical",
        classification="restricted",
        attrs={"os": "windows_server", "patch_level": "current", "status": "active"},
    )
    # Three nested security groups between the intern and admin rights, so the
    # composition -- not any single grant -- is what makes the path work.
    g1 = builder.add_node(NodeKind.GROUP.value, name=f"grp-onboarding{tag}", attrs={"type": "security"})
    g2 = builder.add_node(NodeKind.GROUP.value, name=f"grp-eng-fullaccess{tag}", attrs={"type": "security"})
    g3 = builder.add_node(NodeKind.GROUP.value, name=f"grp-tier0-admins{tag}", attrs={"type": "security"})

    builder.add_edge(EdgeType.MEMBER_OF.value, intern, g1, attrs={})
    builder.add_edge(EdgeType.MEMBER_OF.value, g1, g2, attrs={})
    builder.add_edge(EdgeType.MEMBER_OF.value, g2, g3, attrs={})
    builder.add_edge(EdgeType.HAS_PERMISSION.value, g3, da_host, attrs={"permission_level": "admin"})

    notes = (
        "Intern account placed in an onboarding group whose three-level nesting "
        "terminates in an administrative permission on a tier-zero domain "
        "controller; no single membership grant looks wrong in isolation."
    )
    return intern, da_host, notes


def _plant_leaked_key_to_data(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    repo_app = builder.add_node(
        NodeKind.APPLICATION.value,
        name=f"public-source-mirror{tag}",
        criticality="low",
        classification="public",
        attrs={"status": "active"},
    )
    key = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name=f"leaked-access-key{tag}",
        attrs={"credential_type": "api_key", "storage": "plaintext_disk", "is_active": True, "strength": "strong"},
    )
    data_store = builder.add_node(
        NodeKind.DATABASE.value,
        name=f"regulated-data-store{tag}",
        is_crown_jewel=True,
        criticality="critical",
        classification="restricted",
        attrs={"engine": "postgres", "requires_separate_key": False, "status": "active"},
    )

    builder.add_edge(EdgeType.EXPOSES_CREDENTIAL.value, repo_app, key, attrs={"location": "public_repo"})
    builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        key,
        data_store,
        attrs={"mfa_required": False, "mfa_type": "none", "requires_compliant_device": False, "scope": "admin"},
    )

    notes = (
        "An access key committed to a publicly readable repository authenticates "
        "directly, with no second factor, to a database holding regulated data."
    )
    return repo_app, data_store, notes


def _plant_kerberoast_to_app(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    any_user = builder.add_node(
        NodeKind.USER.value,
        name=f"standard.user{tag}",
        attrs={"department": "Support", "account_status": "active", "mfa_enabled": True},
    )
    spn_account = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name=f"svc-legacy-app{tag}",
        attrs={"account_status": "active", "has_spn": True, "credential_strength": "weak", "is_interactive": False},
    )
    app_server = builder.add_node(
        NodeKind.HOST.value,
        name=f"appsrv-legacy{tag}",
        criticality="high",
        classification="confidential",
        attrs={"os": "windows_server", "patch_level": "current", "status": "active"},
    )
    db_host = builder.add_node(
        NodeKind.HOST.value,
        name=f"dbhost-legacy{tag}",
        is_crown_jewel=True,
        criticality="critical",
        classification="restricted",
        attrs={"os": "linux", "patch_level": "current", "status": "active"},
    )

    builder.add_edge(EdgeType.ADMIN_TO.value, spn_account, app_server, attrs={})
    builder.add_edge(
        EdgeType.TRUSTS.value,
        app_server,
        db_host,
        attrs={"bidirectional": False, "trust_type": "kerberos_delegation"},
    )

    notes = (
        "A service account carries a service principal name and a crackable "
        "password, and holds administrative rights on an application server "
        "with unconstrained delegation into a database host."
    )
    return any_user, db_host, notes


def _plant_stale_vendor_vpn(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    vendor = builder.add_node(
        NodeKind.USER.value,
        name=f"vendor.contractor{tag}",
        attrs={"department": "External Vendor", "account_status": "active", "mfa_enabled": False},
    )
    vendor_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name=f"vendor-vpn-cred{tag}",
        attrs={"credential_type": "password", "storage": "config_file", "is_active": True, "strength": "medium"},
    )
    vpn_host = builder.add_node(
        NodeKind.HOST.value,
        name=f"vpn-concentrator{tag}",
        criticality="high",
        classification="internal",
        attrs={"os": "linux", "patch_level": "behind-1", "status": "active"},
    )
    internal_host = builder.add_node(
        NodeKind.HOST.value,
        name=f"internal-fileserver{tag}",
        is_crown_jewel=True,
        criticality="high",
        classification="confidential",
        attrs={"os": "windows_server", "patch_level": "current", "status": "active"},
    )

    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, vendor, vendor_cred, attrs={})
    builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        vendor_cred,
        vpn_host,
        attrs={"mfa_required": False, "mfa_type": "sms", "requires_compliant_device": False, "scope": "admin"},
    )
    builder.add_edge(
        EdgeType.TRUSTS.value,
        vpn_host,
        internal_host,
        attrs={"bidirectional": False, "trust_type": "ssh_key_trust"},
    )

    notes = (
        "A vendor account nobody has reviewed retains a live credential that "
        "authenticates to a VPN concentrator with a trust relationship into "
        "internal infrastructure."
    )
    return vendor, internal_host, notes


def _plant_nested_group_cloud(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    user = builder.add_node(
        NodeKind.USER.value,
        name=f"cloud.eng{tag}",
        attrs={"department": "Platform Engineering", "account_status": "active", "mfa_enabled": True},
    )
    g1 = builder.add_node(NodeKind.GROUP.value, name=f"grp-cloud-l1{tag}", attrs={"type": "security"})
    g2 = builder.add_node(NodeKind.GROUP.value, name=f"grp-cloud-l2{tag}", attrs={"type": "security"})
    g3 = builder.add_node(NodeKind.GROUP.value, name=f"grp-cloud-l3{tag}", attrs={"type": "security"})
    staging_resource = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value,
        name=f"staging-workload{tag}",
        criticality="medium",
        classification="internal",
        attrs={"resource_type": "workload", "status": "active"},
    )
    prod_resource = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value,
        name=f"prod-secrets-store{tag}",
        is_crown_jewel=True,
        criticality="critical",
        classification="restricted",
        attrs={"resource_type": "bucket", "status": "active"},
    )

    builder.add_edge(EdgeType.MEMBER_OF.value, user, g1, attrs={})
    builder.add_edge(EdgeType.MEMBER_OF.value, g1, g2, attrs={})
    builder.add_edge(EdgeType.MEMBER_OF.value, g2, g3, attrs={})
    builder.add_edge(EdgeType.HAS_PERMISSION.value, g3, staging_resource, attrs={"permission_level": "read_write"})
    builder.add_edge(
        EdgeType.CONNECTED_TO.value,
        staging_resource,
        prod_resource,
        attrs={"connection_type": "iam_assume_role", "grants_admin": True},
    )

    notes = (
        "Three levels of group nesting terminate in a permission on a staging "
        "cloud resource that can assume a role granting administrative access "
        "on a production secrets store."
    )
    return user, prod_resource, notes


def _plant_unpatched_edge_pivot(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    edge_host = builder.add_node(
        NodeKind.HOST.value,
        name=f"edge-webgateway{tag}",
        criticality="high",
        classification="internal",
        attrs={"os": "linux", "patch_level": "behind-2+", "status": "active"},
    )
    remote_vuln = builder.add_node(
        NodeKind.VULNERABILITY.value,
        name=f"CVE-2024-{9000 + instance}",
        attrs={"impact": "RCE", "attack_vector": "network", "epss": 0.82, "cvss": 9.1},
    )
    local_vuln = builder.add_node(
        NodeKind.VULNERABILITY.value,
        name=f"CVE-2024-{9100 + instance}",
        attrs={"impact": "privilege_escalation", "attack_vector": "local", "epss": 0.55, "cvss": 7.4},
    )
    internal_host = builder.add_node(
        NodeKind.HOST.value,
        name=f"internal-core{tag}",
        is_crown_jewel=True,
        criticality="critical",
        classification="confidential",
        attrs={"os": "linux", "patch_level": "current", "status": "active"},
    )

    builder.add_edge(EdgeType.HAS_VULNERABILITY.value, edge_host, remote_vuln, attrs={})
    builder.add_edge(EdgeType.HAS_VULNERABILITY.value, edge_host, local_vuln, attrs={})
    builder.add_edge(
        EdgeType.TRUSTS.value,
        edge_host,
        internal_host,
        attrs={"bidirectional": False, "trust_type": "kerberos_delegation"},
    )

    notes = (
        "An internet-facing edge host is two patch cycles behind on a remotely "
        "exploitable, network-reachable weakness, escalates locally, and trusts "
        "an internal host."
    )
    return edge_host, internal_host, notes


def _plant_shared_cred_sprawl(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    # The narrative starts from any authenticated identity: kerberoasting
    # (R10) fires on held state alone and consumes no edge, so the weak
    # service account below is the first hop's target, not the entry.
    any_user = builder.add_node(
        NodeKind.USER.value,
        name=f"standard.user.sprawl{tag}",
        attrs={"department": "Operations", "account_status": "active", "mfa_enabled": True},
    )
    weak_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name=f"svc-shared-weak{tag}",
        attrs={"account_status": "active", "has_spn": True, "credential_strength": "weak", "is_interactive": False},
    )
    other_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name=f"svc-shared-other{tag}",
        attrs={"account_status": "active", "has_spn": False, "credential_strength": "strong", "is_interactive": False},
    )
    shared_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name=f"shared-secret{tag}",
        attrs={"credential_type": "password", "storage": "env_var", "is_active": True, "strength": "weak"},
    )
    target = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value,
        name=f"shared-cred-target{tag}",
        is_crown_jewel=True,
        criticality="critical",
        classification="confidential",
        attrs={"resource_type": "workload", "status": "active"},
    )

    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, weak_sa, shared_cred, attrs={})
    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, other_sa, shared_cred, attrs={})
    builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        shared_cred,
        target,
        attrs={"mfa_required": False, "mfa_type": "none", "requires_compliant_device": False, "scope": "admin"},
    )

    notes = (
        "One secret is reused by two service accounts of very different "
        "strength; the weaker one is kerberoastable, and compromising it "
        "confers the union of everything the shared secret reaches."
    )
    return any_user, target, notes


def _plant_ci_pipeline_to_prod(builder: GraphBuilder, background: Background, rng: random.Random, instance: int):
    tag = _tag(instance)
    staging_host = builder.add_node(
        NodeKind.HOST.value,
        name=f"ci-staging-runner{tag}",
        criticality="low",
        classification="internal",
        attrs={"os": "linux", "patch_level": "behind-2+", "status": "active"},
    )
    # Weak controls means the staging host is itself remotely exploitable, so
    # reaching administrative control of it -- and so of the credential it
    # exposes -- does not require any capability beyond the network reach a
    # public or insider threat model grants for free.
    remote_vuln = builder.add_node(
        NodeKind.VULNERABILITY.value,
        name=f"CVE-2023-{4000 + instance}",
        attrs={"impact": "RCE", "attack_vector": "network", "epss": 0.77, "cvss": 8.6},
    )
    local_vuln = builder.add_node(
        NodeKind.VULNERABILITY.value,
        name=f"CVE-2023-{4100 + instance}",
        attrs={"impact": "privilege_escalation", "attack_vector": "local", "epss": 0.61, "cvss": 7.8},
    )
    deploy_sa = builder.add_node(
        NodeKind.SERVICE_ACCOUNT.value,
        name=f"svc-ci-deploy{tag}",
        attrs={"account_status": "active", "has_spn": False, "credential_strength": "strong", "is_interactive": False},
    )
    deploy_cred = builder.add_node(
        NodeKind.CREDENTIAL.value,
        name=f"ci-deploy-cred{tag}",
        attrs={"credential_type": "token", "storage": "config_file", "is_active": True, "strength": "strong"},
    )
    prod_resource = builder.add_node(
        NodeKind.CLOUD_RESOURCE.value,
        name=f"prod-workload{tag}",
        is_crown_jewel=True,
        criticality="critical",
        classification="restricted",
        attrs={"resource_type": "workload", "status": "active"},
    )

    builder.add_edge(EdgeType.HAS_VULNERABILITY.value, staging_host, remote_vuln, attrs={})
    builder.add_edge(EdgeType.HAS_VULNERABILITY.value, staging_host, local_vuln, attrs={})
    builder.add_edge(EdgeType.EXPOSES_CREDENTIAL.value, staging_host, deploy_cred, attrs={"location": "config_file"})
    builder.add_edge(EdgeType.HAS_CREDENTIAL.value, deploy_sa, deploy_cred, attrs={})
    builder.add_edge(
        EdgeType.AUTHENTICATES_TO.value,
        deploy_cred,
        prod_resource,
        attrs={"mfa_required": False, "mfa_type": "none", "requires_compliant_device": False, "scope": "admin"},
    )

    notes = (
        "A deployment credential is readable from a staging host that is "
        "itself remotely exploitable, and the credential authenticates "
        "directly, with administrative scope, to production."
    )
    return staging_host, prod_resource, notes


_PLANTERS = {
    "intern_to_domain_admin": _plant_intern_to_domain_admin,
    "leaked_key_to_data": _plant_leaked_key_to_data,
    "kerberoast_to_app": _plant_kerberoast_to_app,
    "stale_vendor_vpn": _plant_stale_vendor_vpn,
    "nested_group_cloud": _plant_nested_group_cloud,
    "unpatched_edge_pivot": _plant_unpatched_edge_pivot,
    "shared_cred_sprawl": _plant_shared_cred_sprawl,
    "ci_pipeline_to_prod": _plant_ci_pipeline_to_prod,
}
