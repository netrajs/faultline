"""Attribute distributions.

Every value drawn here lands on a node or edge that at least one rule in
``docs/RULES.md`` reads as a precondition -- ``account_status``, ``mfa_type``,
``patch_level``, ``permission_level``, ``is_active``, ``has_spn``,
``credential_strength`` and the rest. A generator that leaves those fields
empty or constant produces a graph where every rule either always fires or
never does, which is a graph that cannot exercise the engine it exists to
feed.

Distributions are hand-picked to be plausible rather than measured from a real
environment -- there is no real environment here. Where a rule cares about a
threshold (``account_status = 'disabled'``, MFA type, patch level), the
distribution puts meaningful mass on both sides of it, because a rule that
never sees its failing case is a rule nobody has tested.

Every draw takes an explicit ``random.Random`` from a ``SeedBundle`` stream.
Nothing here touches the global ``random`` module or Faker's global state.
"""

from __future__ import annotations

import random
from typing import Sequence, TypeVar

T = TypeVar("T")


def weighted_choice(rng: random.Random, options: Sequence[tuple[T, float]]) -> T:
    """Pick one of ``(value, weight)`` pairs. Weights need not sum to 1."""
    total = sum(w for _, w in options)
    draw = rng.random() * total
    upto = 0.0
    for value, weight in options:
        upto += weight
        if draw <= upto:
            return value
    return options[-1][0]


def chance(rng: random.Random, p: float) -> bool:
    return rng.random() < p


# ── Identity ─────────────────────────────────────────────────────────────────

ACCOUNT_STATUS = [("active", 0.80), ("disabled", 0.13), ("locked", 0.07)]

MFA_TYPE = [
    ("none", 0.20),
    ("sms", 0.22),
    ("push", 0.18),
    ("otp_app", 0.15),
    ("fido2", 0.13),
    ("webauthn", 0.07),
    ("piv", 0.05),
]

PHISHING_RESISTANT_MFA = frozenset({"fido2", "webauthn", "piv"})

CREDENTIAL_STRENGTH = [("weak", 0.32), ("medium", 0.38), ("strong", 0.30)]

GROUP_TYPE = [("security", 0.85), ("distribution", 0.15)]

ASSET_STATUS = [("active", 0.94), ("decommissioned", 0.06)]


def account_status(rng: random.Random) -> str:
    return weighted_choice(rng, ACCOUNT_STATUS)


def mfa_type(rng: random.Random) -> str:
    return weighted_choice(rng, MFA_TYPE)


def credential_strength(rng: random.Random) -> str:
    return weighted_choice(rng, CREDENTIAL_STRENGTH)


def group_type(rng: random.Random) -> str:
    return weighted_choice(rng, GROUP_TYPE)


def asset_status(rng: random.Random) -> str:
    return weighted_choice(rng, ASSET_STATUS)


# ── Assets ───────────────────────────────────────────────────────────────────

PATCH_LEVEL = [("current", 0.50), ("behind-1", 0.30), ("behind-2+", 0.20)]

PERMISSION_LEVEL = [
    ("read_only", 0.40),
    ("read_write", 0.28),
    ("execute", 0.17),
    ("admin", 0.15),
]

TRUST_TYPE = [
    ("kerberos_delegation", 0.28),
    ("ssh_key_trust", 0.22),
    ("rdp", 0.30),
    ("generic", 0.20),
]

CONNECTION_TYPE = [
    ("iam_assume_role", 0.28),
    ("vpc_peering", 0.24),
    ("security_group", 0.22),
    ("service_mesh", 0.14),
    ("public_endpoint", 0.12),
]

CREDENTIAL_LOCATION = [
    ("config_file", 0.30),
    ("env_var", 0.20),
    ("memory_dump", 0.12),
    ("vault", 0.16),
    ("hsm", 0.06),
    ("public_repo", 0.08),
    ("public_bucket", 0.05),
    ("paste_site", 0.03),
]

CREDENTIAL_STORAGE = [
    ("config_file", 0.34),
    ("env_var", 0.20),
    ("plaintext_disk", 0.10),
    ("vault", 0.26),
    ("hsm", 0.10),
]

VULN_IMPACT = [
    ("RCE", 0.35),
    ("privilege_escalation", 0.25),
    ("DoS", 0.20),
    ("info_disclosure", 0.20),
]

VULN_ATTACK_VECTOR = [("network", 0.55), ("adjacent", 0.20), ("local", 0.25)]


def patch_level(rng: random.Random) -> str:
    return weighted_choice(rng, PATCH_LEVEL)


def permission_level(rng: random.Random) -> str:
    return weighted_choice(rng, PERMISSION_LEVEL)


def trust_type(rng: random.Random) -> str:
    return weighted_choice(rng, TRUST_TYPE)


def connection_type(rng: random.Random) -> str:
    return weighted_choice(rng, CONNECTION_TYPE)


def credential_location(rng: random.Random) -> str:
    return weighted_choice(rng, CREDENTIAL_LOCATION)


def credential_storage(rng: random.Random) -> str:
    return weighted_choice(rng, CREDENTIAL_STORAGE)


def vuln_impact(rng: random.Random) -> str:
    return weighted_choice(rng, VULN_IMPACT)


def vuln_attack_vector(rng: random.Random) -> str:
    return weighted_choice(rng, VULN_ATTACK_VECTOR)


def epss(rng: random.Random) -> float:
    """Skewed toward low values -- most CVEs are never exploited in the wild."""
    return round(rng.random() ** 2.2, 4)


def cvss(rng: random.Random) -> float:
    return round(rng.uniform(2.0, 10.0), 1)


CRITICALITY = [("critical", 0.10), ("high", 0.25), ("medium", 0.40), ("low", 0.25)]
CLASSIFICATION = [
    ("restricted", 0.15),
    ("confidential", 0.30),
    ("internal", 0.40),
    ("public", 0.15),
]


def criticality(rng: random.Random) -> str:
    return weighted_choice(rng, CRITICALITY)


def classification(rng: random.Random) -> str:
    return weighted_choice(rng, CLASSIFICATION)
