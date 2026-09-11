"""Table-driven cross-check against docs/RULES.md SS5.

The table below mirrors the fourteen-row decoy/twin table in the rules
specification exactly -- same codes, same deciding attribute, same kind of
element it lives on. Keeping it structurally parallel means a future edit to
the spec table is a one-line diff to check against here, rather than a
re-derivation.

For every pair this asserts two things docs/SCOPE.md D8 both require:

  * the decoy and twin values for the named attribute are exactly what the
    spec says (and they differ from each other);
  * every *other* attribute the pair's carrier holds is identical between
    decoy and twin -- otherwise a difference in some unrelated attribute could
    be doing the rejecting instead of the one attribute the pair claims to
    test, and the pair would not be testing what it says it tests.
"""

from __future__ import annotations

import pytest

from generator.decoys import DECOY_CODES
from generator.graph import BackgroundSizes
from generator.run import generate

_SMALL_SIZES = BackgroundSizes(
    users=10, groups=4, service_accounts=4, hosts=8, databases=3, cloud_resources=4, applications=3
)

# code -> (kind, attr_path, decoy_value, twin_value)
#   kind 'node'/'edge'   -- attr_path is a key into that element's .attrs
#   kind 'capability'    -- D8: same node/edge in both rows; only the
#                           attacker's assumed held capability differs
#   kind 'presence'      -- D9: the deciding fact is whether a CONNECTED_TO
#                           edge exists at all between the two elements
DECOY_TABLE: dict[str, tuple[str, str, object, object]] = {
    "d01_mfa_phishing_resistant": ("edge", "mfa_type", "fido2", "sms"),
    "d02_vaulted_credential": ("node", "storage", "vault", "config_file"),
    "d03_read_only_permission": ("edge", "permission_level", "read_only", "admin"),
    "d04_disabled_account": ("node", "account_status", "disabled", "active"),
    "d05_one_way_trust": ("edge", "bidirectional", False, True),
    "d06_strong_spn_password": ("node", "credential_strength", "strong", "weak"),
    "d07_patched_host": ("node", "patch_level", "current", "behind-2+"),
    "d08_no_admin_for_dump": ("capability", None, "access_to", "admin_on"),
    "d09_segmented_network": ("presence", None, "absent", "present"),
    "d10_rotated_credential": ("node", "is_active", False, True),
    "d11_non_interactive_sa": ("node", "is_interactive", False, True),
    "d12_separate_key_required": ("node", "requires_separate_key", True, False),
    "d13_distribution_group": ("node", "type", "distribution", "security"),
    "d14_device_compliance": ("edge", "requires_compliant_device", True, False),
}


@pytest.fixture(scope="module")
def generated():
    return generate(21, scenario_count=0, sizes=_SMALL_SIZES)


def test_decoy_table_covers_exactly_the_fourteen_spec_codes():
    assert set(DECOY_TABLE) == set(DECOY_CODES)
    assert len(DECOY_TABLE) == 14


def _instances(generated, code):
    rows = [d for d in generated.decoys if d.decoy_code == code]
    decoy = next(d for d in rows if d.role == "decoy")
    twin = next(d for d in rows if d.role == "twin")
    return decoy, twin


@pytest.mark.parametrize("code", sorted(DECOY_TABLE))
def test_pair_differs_in_exactly_the_named_attribute(generated, code):
    kind, attr_path, expected_decoy, expected_twin = DECOY_TABLE[code]
    decoy, twin = _instances(generated, code)

    assert decoy.expected_outcome == "reject"
    assert twin.expected_outcome == "accept"

    if kind == "capability":
        # D8: literally the same graph fact in both rows -- only the
        # attacker's assumed held capability differs, which is not an
        # attribute of the graph at all.
        assert decoy.edge_id == twin.edge_id
        assert decoy.node_id == twin.node_id
        assert decoy.deciding_value == expected_decoy
        assert twin.deciding_value == expected_twin
        return

    if kind == "presence":
        # D9: the decoy has no connecting edge at all; the twin does.
        assert decoy.edge_id is None
        assert twin.edge_id is not None
        assert decoy.node_id != twin.node_id
        return

    if kind == "node":
        decoy_obj = generated.nodes[decoy.node_id]
        twin_obj = generated.nodes[twin.node_id]
    else:
        decoy_obj = generated.edges[decoy.edge_id]
        twin_obj = generated.edges[twin.edge_id]

    decoy_attrs = dict(decoy_obj.attrs)
    twin_attrs = dict(twin_obj.attrs)

    assert decoy_attrs[attr_path] == expected_decoy
    assert twin_attrs[attr_path] == expected_twin
    assert decoy_attrs[attr_path] != twin_attrs[attr_path]

    # Every other attribute the pair's carrier holds must match: the named
    # attribute must be the only thing distinguishing decoy from twin.
    other_decoy = {k: v for k, v in decoy_attrs.items() if k != attr_path}
    other_twin = {k: v for k, v in twin_attrs.items() if k != attr_path}
    assert other_decoy == other_twin
