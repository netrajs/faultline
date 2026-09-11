"""A small world, built by hand.

No store runs during these tests. The rule, technique, capability, threat-model
and scoring rows below are the same shapes ``backend/db/seed`` inserts, fed
through the same loaders the production path uses, so the validation and the
indexing under test are the real ones rather than a simplified stand-in.

The graph is deliberately small and deliberately mixed: two genuine paths to one
crown jewel, reached by different mechanisms, alongside five planted refusals
whose deciding attribute is the only thing separating them from something
traversable. A graph containing only valid paths would let a broken engine pass
by accepting everything, and a graph containing only decoys would let one pass by
refusing everything.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

import pytest

from engine.rules import RuleSet, build_ruleset
from engine.scoring import Scorer, build_scoring_config
from engine.search import Discovery, SearchLimits
from engine.snapshot import snapshot_from_rows

# ── Attacker model rows ──────────────────────────────────────────────────────

CAPABILITY_ROWS = [
    {"code": "authenticated", "binding_kind": "global"},
    {"code": "controls_principal", "binding_kind": "node"},
    {"code": "holds_credential", "binding_kind": "node"},
    {"code": "member_effective", "binding_kind": "node"},
    {"code": "network_reach", "binding_kind": "node"},
    {"code": "access_to", "binding_kind": "node"},
    {"code": "admin_on", "binding_kind": "node"},
    {"code": "code_exec_on", "binding_kind": "node"},
    {"code": "can_read_secret", "binding_kind": "node"},
]

TECHNIQUE_ROWS = [
    {"code": "group_membership", "name": "Group membership inheritance", "attack_id": "T1078", "phase": "privilege_escalation"},
    {"code": "group_permission", "name": "Group-conferred permission", "attack_id": "T1078.002", "phase": "privilege_escalation"},
    {"code": "direct_assignment", "name": "Direct rights assignment", "attack_id": "T1078", "phase": "privilege_escalation"},
    {"code": "cloud_account_use", "name": "Cloud account use", "attack_id": "T1078.004", "phase": "lateral_movement"},
    {"code": "credential_in_files", "name": "Credentials in files", "attack_id": "T1552.001", "phase": "credential_access"},
    {"code": "unsecured_credentials", "name": "Unsecured credentials", "attack_id": "T1552", "phase": "credential_access"},
    {"code": "credential_replay", "name": "Credential replay", "attack_id": "T1550", "phase": "lateral_movement"},
    {"code": "kerberoasting", "name": "Kerberoasting", "attack_id": "T1558.003", "phase": "credential_access"},
    {"code": "trusted_relationship", "name": "Trusted relationship", "attack_id": "T1199", "phase": "lateral_movement"},
    {"code": "remote_services", "name": "Remote services", "attack_id": "T1021", "phase": "lateral_movement"},
    {"code": "exploit_remote", "name": "Exploit remote service", "attack_id": "T1210", "phase": "initial_access"},
    {"code": "exploit_privesc", "name": "Exploit for privilege escalation", "attack_id": "T1068", "phase": "privilege_escalation"},
    {"code": "assume_role", "name": "Assume cloud role", "attack_id": "T1548", "phase": "privilege_escalation"},
]

RULE_ROWS = [
    {"id": 1, "code": "group_membership", "technique_code": "group_membership", "edge_type_code": "MEMBER_OF", "is_traversal": 1, "sort_order": 1},
    {"id": 2, "code": "group_permission_admin", "technique_code": "group_permission", "edge_type_code": "HAS_PERMISSION", "is_traversal": 1, "sort_order": 2},
    {"id": 3, "code": "group_permission_access", "technique_code": "group_permission", "edge_type_code": "HAS_PERMISSION", "is_traversal": 1, "sort_order": 3},
    {"id": 4, "code": "direct_admin", "technique_code": "direct_assignment", "edge_type_code": "ADMIN_TO", "is_traversal": 1, "sort_order": 4},
    {"id": 5, "code": "service_account_access", "technique_code": "cloud_account_use", "edge_type_code": "HAS_ACCESS_TO", "is_traversal": 1, "sort_order": 5},
    {"id": 6, "code": "credential_from_principal", "technique_code": "group_membership", "edge_type_code": "HAS_CREDENTIAL", "is_traversal": 1, "sort_order": 6},
    {"id": 7, "code": "credential_dump", "technique_code": "credential_in_files", "edge_type_code": "EXPOSES_CREDENTIAL", "is_traversal": 1, "sort_order": 7},
    {"id": 8, "code": "credential_public", "technique_code": "unsecured_credentials", "edge_type_code": "EXPOSES_CREDENTIAL", "is_traversal": 1, "sort_order": 8},
    {"id": 9, "code": "credential_authenticate", "technique_code": "credential_replay", "edge_type_code": "AUTHENTICATES_TO", "is_traversal": 1, "sort_order": 9},
    {"id": 10, "code": "kerberoast", "technique_code": "kerberoasting", "edge_type_code": None, "is_traversal": 0, "sort_order": 10},
    {"id": 11, "code": "host_trust", "technique_code": "trusted_relationship", "edge_type_code": "TRUSTS", "is_traversal": 1, "sort_order": 11},
    {"id": 12, "code": "remote_exploit", "technique_code": "exploit_remote", "edge_type_code": "HAS_VULNERABILITY", "is_traversal": 1, "sort_order": 12},
    {"id": 13, "code": "local_privesc", "technique_code": "exploit_privesc", "edge_type_code": "HAS_VULNERABILITY", "is_traversal": 1, "sort_order": 13},
    {"id": 14, "code": "cloud_role_assumption", "technique_code": "assume_role", "edge_type_code": "CONNECTED_TO", "is_traversal": 1, "sort_order": 14},
    {"id": 15, "code": "network_pivot", "technique_code": "remote_services", "edge_type_code": "CONNECTED_TO", "is_traversal": 1, "sort_order": 15},
]

# (rule_id, seq, kind, binding, capability, attr_path, operator, value_json, reason)
_PRECONDITIONS: tuple[tuple[Any, ...], ...] = (
    (1, 1, "capability", "src", "controls_principal", None, None, None, "The attacker does not control this principal."),
    (1, 2, "node_attr", "src", None, "account_status", "ne", '"disabled"', "The account is disabled, so its group memberships confer nothing."),
    (1, 3, "node_attr", "dst", None, "type", "eq", '"security"', "This is a distribution group; distribution groups do not confer authorisation."),
    (2, 1, "capability", "src", "member_effective", None, None, None, "The attacker is not an effective member of this group."),
    (2, 2, "edge_attr", "src", None, "permission_level", "eq", '"admin"', "The group's permission on this asset is not administrative."),
    (3, 1, "capability", "src", "member_effective", None, None, None, "The attacker is not an effective member of this group."),
    (3, 2, "edge_attr", "src", None, "permission_level", "in", '["read_write","read_only","execute"]', "The group holds no usable permission on this asset."),
    (4, 1, "capability", "src", "controls_principal", None, None, None, "The attacker does not control this principal."),
    (4, 2, "node_attr", "src", None, "account_status", "eq", '"active"', "The account is not active; its rights assignments are stale."),
    (5, 1, "capability", "src", "controls_principal", None, None, None, "The attacker does not control this service account."),
    (5, 2, "node_attr", "src", None, "account_status", "eq", '"active"', "The service account is not active."),
    (6, 1, "capability", "src", "controls_principal", None, None, None, "The attacker does not control the principal owning this credential."),
    (6, 2, "node_attr", "dst", None, "is_active", "ne", "false", "The credential has been rotated or revoked and no longer authenticates."),
    (7, 1, "capability", "src", "admin_on", None, None, None, "Reading a secret from this asset requires administrative control of it."),
    (7, 2, "edge_attr", "src", None, "location", "not_in", '["vault","hsm"]', "The asset references the secret but does not hold it."),
    (7, 3, "node_attr", "dst", None, "storage", "not_in", '["vault","hsm"]', "The credential is vault-stored and cannot be recovered from this asset."),
    (7, 4, "node_attr", "dst", None, "is_active", "ne", "false", "The credential has been rotated and no longer authenticates."),
    (8, 1, "edge_attr", "src", None, "location", "in", '["public_repo","public_bucket","paste_site"]', "The exposure is not publicly accessible."),
    (8, 2, "node_attr", "dst", None, "is_active", "ne", "false", "The credential has been rotated and no longer authenticates."),
    (9, 1, "capability", "src", "holds_credential", None, None, None, "The attacker does not hold this credential."),
    (9, 2, "edge_attr", "src", None, "mfa_type", "not_in", '["fido2","webauthn","piv"]', "Authentication requires a phishing-resistant second factor."),
    (9, 3, "edge_attr", "src", None, "requires_compliant_device", "ne", "true", "Conditional access requires a compliant enrolled device."),
    (9, 4, "node_attr", "dst", None, "status", "ne", '"decommissioned"', "The target asset is decommissioned."),
    (10, 1, "capability", "global", "authenticated", None, None, None, "Requesting a service ticket requires an authenticated directory identity."),
    (10, 2, "node_attr", "dst", None, "has_spn", "eq", "true", "The account has no service principal name."),
    (10, 3, "node_attr", "dst", None, "credential_strength", "ne", '"strong"', "The account's password is strong; the ticket is not crackable in practical time."),
    (11, 1, "capability", "src", "admin_on", None, None, None, "Abusing this trust requires administrative control of the trusting host."),
    (12, 1, "capability", "src", "network_reach", None, None, None, "The attacker cannot reach this asset over the network."),
    (12, 2, "node_attr", "dst", None, "impact", "eq", '"RCE"', "This vulnerability does not yield code execution."),
    (12, 3, "node_attr", "dst", None, "attack_vector", "eq", '"network"', "This vulnerability is not remotely exploitable."),
    (12, 4, "node_attr", "src", None, "patch_level", "ne", '"current"', "The asset is fully patched against this vulnerability."),
    (13, 1, "capability", "src", "code_exec_on", None, None, None, "Local escalation requires existing code execution on the host."),
    (13, 2, "node_attr", "dst", None, "impact", "eq", '"privilege_escalation"', "This vulnerability does not yield privilege escalation."),
    (13, 3, "node_attr", "src", None, "patch_level", "ne", '"current"', "The asset is fully patched against this vulnerability."),
    (14, 1, "capability", "src", "access_to", None, None, None, "The attacker has no access to the source resource."),
    (14, 2, "edge_attr", "src", None, "connection_type", "eq", '"iam_assume_role"', "This connection carries network traffic only."),
    (15, 1, "capability", "src", "code_exec_on", None, None, None, "Pivoting requires code execution on the source resource."),
    (15, 2, "edge_attr", "src", None, "connection_type", "in", '["vpc_peering","security_group","service_mesh"]', "These resources are not network-adjacent."),
)

PRECONDITION_ROWS = [
    {
        "rule_id": rule_id,
        "seq": seq,
        "kind": kind,
        "binding": binding,
        "capability_code": capability,
        "attr_path": attr_path,
        "operator": operator,
        "value_json": value,
        "is_negated": 0,
        "failure_reason": reason,
    }
    for rule_id, seq, kind, binding, capability, attr_path, operator, value, reason in _PRECONDITIONS
]

_EFFECTS: tuple[tuple[int, int, str, str], ...] = (
    (1, 1, "member_effective", "dst"),
    (2, 1, "admin_on", "dst"),
    (2, 2, "access_to", "dst"),
    (3, 1, "access_to", "dst"),
    (4, 1, "admin_on", "dst"),
    (4, 2, "access_to", "dst"),
    (4, 3, "can_read_secret", "dst"),
    (5, 1, "access_to", "dst"),
    (6, 1, "holds_credential", "dst"),
    (7, 1, "holds_credential", "dst"),
    (7, 2, "can_read_secret", "src"),
    (8, 1, "holds_credential", "dst"),
    (9, 1, "access_to", "dst"),
    (10, 1, "controls_principal", "dst"),
    (11, 1, "code_exec_on", "dst"),
    (12, 1, "code_exec_on", "src"),
    (12, 2, "access_to", "src"),
    (13, 1, "admin_on", "src"),
    (13, 2, "can_read_secret", "src"),
    (14, 1, "access_to", "dst"),
    (15, 1, "network_reach", "dst"),
)

EFFECT_ROWS = [
    {"rule_id": rule_id, "seq": seq, "capability_code": code, "binding": binding}
    for rule_id, seq, code, binding in _EFFECTS
]

THREAT_MODEL_ROWS = [
    {"code": "external_phish", "label": "External attacker (phished user)", "is_default": 1, "sort_order": 1},
    {"code": "insider_standard", "label": "Insider (standard employee)", "is_default": 0, "sort_order": 2},
    {"code": "public_only", "label": "Unauthenticated internet", "is_default": 0, "sort_order": 4},
]

GRANT_ROWS = [
    {"threat_model_code": "external_phish", "seq": 1, "capability_code": "authenticated", "applies_to_kind": None, "applies_to_node": None},
    {"threat_model_code": "external_phish", "seq": 2, "capability_code": "controls_principal", "applies_to_kind": "User", "applies_to_node": None},
    # Two kind grants, and the order is what separates "their own account" from
    # "internal assets": the lowest-numbered one is the entry variable, the rest
    # are ambient.
    {"threat_model_code": "insider_standard", "seq": 1, "capability_code": "authenticated", "applies_to_kind": None, "applies_to_node": None},
    {"threat_model_code": "insider_standard", "seq": 2, "capability_code": "controls_principal", "applies_to_kind": "User", "applies_to_node": None},
    {"threat_model_code": "insider_standard", "seq": 3, "capability_code": "network_reach", "applies_to_kind": "Host", "applies_to_node": None},
    {"threat_model_code": "public_only", "seq": 1, "capability_code": "network_reach", "applies_to_kind": "Host", "applies_to_node": None},
]

# ── Scoring rows ─────────────────────────────────────────────────────────────

SCORING_CONFIG_ROW = {
    "version": "v1",
    "label": "Baseline log-odds model",
    "p_clamp_min": 0.001,
    "p_clamp_max": 0.995,
    "raw_max": 9.210340,
    "w_likelihood": 0.55,
    "w_impact": 0.35,
    "w_stealth": 0.10,
}

BASELINE_ROWS = [
    {"technique_code": "group_membership", "base_p_succ": 0.99, "base_detectability": 0.02},
    {"technique_code": "group_permission", "base_p_succ": 0.97, "base_detectability": 0.05},
    {"technique_code": "direct_assignment", "base_p_succ": 0.98, "base_detectability": 0.05},
    {"technique_code": "cloud_account_use", "base_p_succ": 0.97, "base_detectability": 0.12},
    {"technique_code": "credential_in_files", "base_p_succ": 0.85, "base_detectability": 0.25},
    {"technique_code": "unsecured_credentials", "base_p_succ": 0.95, "base_detectability": 0.05},
    {"technique_code": "credential_replay", "base_p_succ": 0.93, "base_detectability": 0.15},
    {"technique_code": "kerberoasting", "base_p_succ": 0.70, "base_detectability": 0.30},
    {"technique_code": "trusted_relationship", "base_p_succ": 0.80, "base_detectability": 0.20},
    {"technique_code": "remote_services", "base_p_succ": 0.95, "base_detectability": 0.10},
    {"technique_code": "exploit_remote", "base_p_succ": 0.50, "base_detectability": 0.45},
    {"technique_code": "exploit_privesc", "base_p_succ": 0.55, "base_detectability": 0.40},
    {"technique_code": "assume_role", "base_p_succ": 0.90, "base_detectability": 0.15},
]

# (code, label, applies_to, attr_path, operator, value_json, target, beta, hard_block, order)
_MODIFIERS: tuple[tuple[Any, ...], ...] = (
    ("cred_age_stale", "Credential over 90 days old", "dst_node", "age_days", "gt", "90", "p_succ", 0.4, 0, 1),
    ("cred_age_ancient", "Credential over 365 days old", "dst_node", "age_days", "gt", "365", "p_succ", 0.5, 0, 2),
    ("cred_shared", "Credential shared", "dst_node", "is_shared", "eq", "true", "p_succ", 0.7, 0, 3),
    ("cred_plaintext", "Credential stored in plaintext", "dst_node", "storage", "in", '["plaintext","config_file","env_var"]', "p_succ", 1.2, 0, 4),
    ("cred_weak", "Weak credential", "dst_node", "strength", "eq", '"weak"', "p_succ", 0.9, 0, 5),
    ("cred_vaulted", "Credential vault-managed", "dst_node", "storage", "eq", '"vault"', "p_succ", -1.5, 0, 6),
    ("mfa_weak_factor", "Weak second factor required", "edge", "mfa_type", "in", '["sms","push","totp"]', "p_succ", -0.8, 0, 7),
    ("mfa_weak_detect", "Weak second factor is noisy", "edge", "mfa_type", "in", '["sms","push"]', "detectability", 0.6, 0, 8),
    ("host_public_facing", "Asset is internet-facing", "dst_node", "public_facing", "eq", "true", "p_succ", 0.5, 0, 9),
    ("host_unpatched", "Asset badly out of date", "src_node", "patch_level", "eq", '"behind-2+"', "p_succ", 0.6, 0, 10),
    ("host_monitored", "Asset has endpoint monitoring", "src_node", "has_edr", "eq", "true", "detectability", 1.0, 0, 11),
    ("exposure_discoverable", "Exposure easy to find", "edge", "discoverable", "gte", "0.7", "p_succ", 0.5, 0, 12),
    ("account_dormant", "Account dormant", "src_node", "account_status", "eq", '"dormant"', "detectability", -0.8, 0, 13),
    ("account_vendor", "Third-party account", "src_node", "account_type", "in", '["vendor","contractor"]', "p_succ", 0.3, 0, 14),
    ("sa_non_interactive", "Service account, non-interactive", "src_node", "is_interactive", "eq", "false", "detectability", 0.9, 0, 15),
)

MODIFIER_ROWS = [
    {
        "code": code,
        "label": label,
        "applies_to": applies_to,
        "attr_path": attr_path,
        "operator": operator,
        "value_json": value,
        "target": target,
        "beta": beta,
        "is_hard_block": hard_block,
        "sort_order": order,
    }
    for code, label, applies_to, attr_path, operator, value, target, beta, hard_block, order in _MODIFIERS
]

SCOPE_ROWS = [
    {"modifier_code": code, "technique_code": technique}
    for code, technique in (
        ("cred_age_stale", "credential_replay"),
        ("cred_age_stale", "credential_in_files"),
        ("cred_age_ancient", "credential_replay"),
        ("cred_age_ancient", "credential_in_files"),
        ("cred_shared", "credential_replay"),
        ("cred_shared", "credential_in_files"),
        ("cred_plaintext", "credential_in_files"),
        ("cred_plaintext", "unsecured_credentials"),
        ("cred_weak", "kerberoasting"),
        ("cred_weak", "credential_replay"),
        ("cred_vaulted", "credential_in_files"),
        ("mfa_weak_factor", "credential_replay"),
        ("mfa_weak_detect", "credential_replay"),
        ("host_unpatched", "exploit_remote"),
        ("host_unpatched", "exploit_privesc"),
        ("exposure_discoverable", "credential_in_files"),
        ("exposure_discoverable", "unsecured_credentials"),
        ("sa_non_interactive", "credential_replay"),
    )
]

IMPACT_ROWS = [
    {"dimension": "crown_jewel", "code": "true", "weight": 1.0},
    {"dimension": "crown_jewel", "code": "false", "weight": 0.0},
    {"dimension": "criticality", "code": "critical", "weight": 0.85},
    {"dimension": "criticality", "code": "high", "weight": 0.65},
    {"dimension": "criticality", "code": "medium", "weight": 0.40},
    {"dimension": "criticality", "code": "low", "weight": 0.20},
    {"dimension": "classification", "code": "restricted", "weight": 0.90},
    {"dimension": "classification", "code": "confidential", "weight": 0.70},
    {"dimension": "classification", "code": "internal", "weight": 0.40},
    {"dimension": "classification", "code": "public", "weight": 0.10},
]

TIER_ROWS = [
    {"code": "critical", "label": "Critical", "min_score": 9.00, "max_score": 10.00, "sort_order": 1},
    {"code": "high", "label": "High", "min_score": 7.00, "max_score": 8.99, "sort_order": 2},
    {"code": "medium", "label": "Medium", "min_score": 4.00, "max_score": 6.99, "sort_order": 3},
    {"code": "low", "label": "Low", "min_score": 1.00, "max_score": 3.99, "sort_order": 4},
    {"code": "info", "label": "Info", "min_score": 0.00, "max_score": 0.99, "sort_order": 5},
]

# ── Graph rows ───────────────────────────────────────────────────────────────

NODE_ROWS: tuple[dict[str, Any], ...] = (
    {
        "node_id": "u-0001",
        "kind": "User",
        "name": "avery.cole",
        "attrs": {"account_status": "active", "department": "finance"},
    },
    {
        # Decoy D4: the rights assignment below is real and stale. A disabled
        # account's assignments persist in the directory long after it stops
        # working.
        "node_id": "u-0002",
        "kind": "User",
        "name": "former.employee",
        "attrs": {"account_status": "disabled"},
    },
    {"node_id": "g-0001", "kind": "Group", "name": "finance-admins", "attrs": {"type": "security"}},
    {
        # Decoy D13: a mailing list conveys no authorisation.
        "node_id": "g-0002",
        "kind": "Group",
        "name": "all-finance",
        "attrs": {"type": "distribution"},
    },
    {
        "node_id": "h-0001",
        "kind": "Host",
        "name": "fin-app-01",
        "criticality": "high",
        "attrs": {"patch_level": "behind-2+", "has_edr": False, "os": "linux"},
    },
    {
        # Decoy D8's host. Structurally identical to h-0001 — same exposure edge,
        # same credential storage — and the group's permission on it is the only
        # difference, so the attacker arrives holding access_to rather than
        # admin_on and cannot read what the host exposes. The deciding factor is
        # the attacker's own state, which no amount of graph inspection reveals.
        "node_id": "h-0002",
        "kind": "Host",
        "name": "audit-log-01",
        "criticality": "medium",
        "attrs": {"patch_level": "current", "has_edr": True, "os": "linux"},
    },
    {
        "node_id": "cred-0001",
        "kind": "Credential",
        "name": "svc-reporting-secret",
        "attrs": {"storage": "config_file", "is_active": True, "strength": "weak", "age_days": 200, "is_shared": False},
    },
    {
        # Decoy D2: the config holds a pointer, not the secret.
        "node_id": "cred-0002",
        "kind": "Credential",
        "name": "svc-payments-secret",
        "attrs": {"storage": "vault", "is_active": True},
    },
    {"node_id": "cred-0003", "kind": "Credential", "name": "svc-etl-secret", "attrs": {"storage": "config_file", "is_active": True}},
    {"node_id": "cred-0004", "kind": "Credential", "name": "svc-hsm-secret", "attrs": {"storage": "hsm", "is_active": True}},
    {"node_id": "cred-0005", "kind": "Credential", "name": "svc-audit-secret", "attrs": {"storage": "config_file", "is_active": True}},
    {"node_id": "cred-0006", "kind": "Credential", "name": "svc-treasury-secret", "attrs": {"storage": "config_file", "is_active": True}},
    {
        # Decoy D10: already rotated, so the material no longer authenticates.
        "node_id": "cred-0007",
        "kind": "Credential",
        "name": "svc-retired-secret",
        "attrs": {"storage": "config_file", "is_active": False},
    },
    {
        "node_id": "db-0001",
        "kind": "Database",
        "name": "finance-ledger",
        "is_crown_jewel": True,
        "criticality": "critical",
        "classification": "restricted",
        "attrs": {"status": "active", "engine": "mysql"},
    },
    {
        "node_id": "db-0002",
        "kind": "Database",
        "name": "reporting-warehouse",
        "criticality": "high",
        "classification": "internal",
        "attrs": {"status": "active"},
    },
    {
        "node_id": "sa-0001",
        "kind": "ServiceAccount",
        "name": "svc-etl",
        "attrs": {"account_status": "active", "has_spn": True, "credential_strength": "weak", "is_interactive": False},
    },
    {
        # Decoy D6: an SPN account with strong material is not crackable, so
        # reporting it as a path is a false positive.
        "node_id": "sa-0002",
        "kind": "ServiceAccount",
        "name": "svc-payments",
        "attrs": {"account_status": "active", "has_spn": True, "credential_strength": "strong"},
    },
)

EDGE_ROWS: tuple[dict[str, Any], ...] = (
    {"edge_id": "e-01", "src_id": "u-0001", "dst_id": "g-0001", "edge_type": "MEMBER_OF", "attrs": {}},
    {"edge_id": "e-02", "src_id": "u-0001", "dst_id": "g-0002", "edge_type": "MEMBER_OF", "attrs": {}},
    {"edge_id": "e-03", "src_id": "g-0001", "dst_id": "h-0001", "edge_type": "HAS_PERMISSION", "attrs": {"permission_level": "admin"}},
    {"edge_id": "e-04", "src_id": "g-0001", "dst_id": "db-0002", "edge_type": "HAS_PERMISSION", "attrs": {"permission_level": "read_only"}},
    {"edge_id": "e-05", "src_id": "h-0001", "dst_id": "cred-0001", "edge_type": "EXPOSES_CREDENTIAL", "attrs": {"location": "config_file", "discoverable": 0.8}},
    {"edge_id": "e-06", "src_id": "h-0001", "dst_id": "cred-0002", "edge_type": "EXPOSES_CREDENTIAL", "attrs": {"location": "config_file"}},
    {"edge_id": "e-07", "src_id": "cred-0001", "dst_id": "db-0001", "edge_type": "AUTHENTICATES_TO", "attrs": {"scope": "admin"}},
    {"edge_id": "e-08", "src_id": "u-0002", "dst_id": "db-0002", "edge_type": "ADMIN_TO", "attrs": {}},
    {"edge_id": "e-09", "src_id": "sa-0001", "dst_id": "cred-0003", "edge_type": "HAS_CREDENTIAL", "attrs": {}},
    {"edge_id": "e-10", "src_id": "cred-0003", "dst_id": "db-0001", "edge_type": "AUTHENTICATES_TO", "attrs": {"mfa_required": True, "mfa_type": "sms"}},
    {"edge_id": "e-11", "src_id": "sa-0002", "dst_id": "cred-0004", "edge_type": "HAS_CREDENTIAL", "attrs": {}},
    {"edge_id": "e-12", "src_id": "g-0001", "dst_id": "h-0002", "edge_type": "HAS_PERMISSION", "attrs": {"permission_level": "read_only"}},
    {"edge_id": "e-13", "src_id": "h-0002", "dst_id": "cred-0005", "edge_type": "EXPOSES_CREDENTIAL", "attrs": {"location": "config_file"}},
    {"edge_id": "e-14", "src_id": "h-0001", "dst_id": "cred-0006", "edge_type": "EXPOSES_CREDENTIAL", "attrs": {"location": "config_file"}},
    # Decoy D1 against the twin at e-07: same technique, same held credential,
    # differing in one attribute. A phishing-resistant factor cannot be defeated
    # by replaying captured material, so the rule is blocked rather than
    # penalised.
    {"edge_id": "e-15", "src_id": "cred-0006", "dst_id": "db-0001", "edge_type": "AUTHENTICATES_TO", "attrs": {"mfa_required": True, "mfa_type": "fido2"}},
    {"edge_id": "e-16", "src_id": "h-0001", "dst_id": "cred-0007", "edge_type": "EXPOSES_CREDENTIAL", "attrs": {"location": "config_file"}},
)

#: The four-hop chain the world is built around: inherit a security-group
#: membership, use the group's admin permission on a host, dump a credential the
#: host exposes, authenticate to the crown-jewel database with it.
PRIMARY_EDGE_SEQUENCE = ("e-01", "e-03", "e-05", "e-07")


# ── Builders ─────────────────────────────────────────────────────────────────


def make_ruleset() -> RuleSet:
    return build_ruleset(
        rule_rows=RULE_ROWS,
        precondition_rows=PRECONDITION_ROWS,
        effect_rows=EFFECT_ROWS,
        technique_rows=TECHNIQUE_ROWS,
        capability_rows=CAPABILITY_ROWS,
        threat_model_rows=THREAT_MODEL_ROWS,
        grant_rows=GRANT_ROWS,
    )


def make_scoring_config(
    *,
    baseline_overrides: Mapping[str, tuple[float, float]] | None = None,
    modifier_overrides: Mapping[str, Mapping[str, Any]] | None = None,
):
    baselines = [dict(row) for row in BASELINE_ROWS]
    for row in baselines:
        override = (baseline_overrides or {}).get(row["technique_code"])
        if override:
            row["base_p_succ"], row["base_detectability"] = override

    modifiers = []
    for row in MODIFIER_ROWS:
        patched = dict(row)
        patched.update((modifier_overrides or {}).get(row["code"], {}))
        modifiers.append(patched)

    return build_scoring_config(
        config_row=SCORING_CONFIG_ROW,
        baseline_rows=baselines,
        modifier_rows=modifiers,
        scope_rows=SCOPE_ROWS,
        impact_rows=IMPACT_ROWS,
        tier_rows=TIER_ROWS,
    )


def make_snapshot(
    *,
    drop_edges: Iterable[str] = (),
    edge_attrs: Mapping[str, Mapping[str, Any]] | None = None,
    node_attrs: Mapping[str, Mapping[str, Any]] | None = None,
    drop_nodes: Iterable[str] = (),
    graph_version: int = 1,
):
    """The world, optionally perturbed.

    Perturbation is how the metamorphic invariants are tested: remove an edge,
    harden an attribute, raise a baseline, and assert the direction the result
    moves in.
    """
    dropped_nodes = set(drop_nodes)
    nodes = []
    for row in NODE_ROWS:
        if row["node_id"] in dropped_nodes:
            continue
        patched = dict(row)
        patch = (node_attrs or {}).get(row["node_id"])
        if patch:
            patched["attrs"] = {**row.get("attrs", {}), **patch}
        nodes.append(patched)

    dropped_edges = set(drop_edges)
    edges = []
    for row in EDGE_ROWS:
        if row["edge_id"] in dropped_edges:
            continue
        if row["src_id"] in dropped_nodes or row["dst_id"] in dropped_nodes:
            continue
        patched = dict(row)
        patch = (edge_attrs or {}).get(row["edge_id"])
        if patch:
            patched["attrs"] = {**row.get("attrs", {}), **patch}
        edges.append(patched)

    return snapshot_from_rows(graph_version, nodes, edges)


def make_discovery(
    snapshot=None,
    *,
    ruleset: RuleSet | None = None,
    config=None,
    limits: SearchLimits | None = None,
) -> Discovery:
    return Discovery(
        snapshot if snapshot is not None else make_snapshot(),
        ruleset or make_ruleset(),
        Scorer(config or make_scoring_config()),
        limits or SearchLimits(max_hops=6, top_k=4),
    )


@pytest.fixture
def ruleset() -> RuleSet:
    return make_ruleset()


@pytest.fixture
def scoring_config():
    return make_scoring_config()


@pytest.fixture
def snapshot():
    return make_snapshot()


@pytest.fixture
def discovery(snapshot, ruleset, scoring_config) -> Discovery:
    return make_discovery(snapshot, ruleset=ruleset, config=scoring_config)


@pytest.fixture
def result(discovery: Discovery):
    return discovery.run("external_phish")
