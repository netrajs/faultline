"""The five preconditions ``docs/RULES.md`` §4 states as "A **or** B".

Section 4 writes a disjunction as two rules with the same technique and edge,
and ``020_attacker_model.sql`` seeded only the first disjunct of five of them.
``080_rule_disjunctions.sql`` adds the second. Each test here is the same shape:
a graph that can only be traversed by way of the alternate precondition, run
twice — once against the rules as 020 alone states them and once against the
whole seed directory, which is what a migrated database holds.

Running both is the point. A test that only asserts the path is found now would
pass just as well if the path had always been findable, and would therefore be
evidence of nothing about the fix.
"""

from __future__ import annotations

import pytest

from core.model import Capability, Edge, GraphSnapshot, Node
from oracle.loader import RuleSet, load_from_seed_file, load_from_seed_files
from oracle.search import OracleConfig, OracleResult, discover


@pytest.fixture(scope="module")
def ruleset() -> RuleSet:
    """The attacker model as the whole seed directory states it."""
    return load_from_seed_files()


@pytest.fixture(scope="module")
def before_the_fix() -> RuleSet:
    """The model as ``020_attacker_model.sql`` alone stated it: fifteen rules.

    Not a historical curiosity. It is the control: every test below asserts that
    the same graph yields nothing under these rules, so what it yields under the
    full set is attributable to the rows this change added and not to the graph
    having been built agreeably.
    """
    return load_from_seed_file()


# ── Construction helpers ─────────────────────────────────────────────────────


def node(node_id: str, kind: str, *, crown_jewel: bool = False, **attrs) -> Node:
    return Node(
        node_id=node_id, kind=kind, name=node_id, is_crown_jewel=crown_jewel, attrs=attrs
    )


def edge(edge_id: str, src: str, dst: str, edge_type: str, **attrs) -> Edge:
    return Edge(edge_id=edge_id, src_id=src, dst_id=dst, edge_type=edge_type, attrs=attrs)


def snapshot(nodes, edges) -> GraphSnapshot:
    return GraphSnapshot(1, nodes, edges)


def run(ruleset: RuleSet, graph: GraphSnapshot, threat_model: str, **kwargs) -> OracleResult:
    return discover(graph, ruleset, OracleConfig(threat_model_code=threat_model, **kwargs))


def rule_sequence(result: OracleResult, ruleset: RuleSet) -> set[tuple[tuple[str, str], ...]]:
    """Each path as its (edge id, rule code) sequence — readable in a failure."""
    codes = {rule.rule_id: rule.code for rule in ruleset.rules}
    return {
        tuple((hop.edge_id or "<no edge>", codes[hop.rule_id]) for hop in path.hops)
        for path in result.paths
    }


LIVE_HOST = {"status": "active", "patch_level": "current"}
UNPATCHED_HOST = {"status": "active", "patch_level": "behind-2+"}
LIVE_CREDENTIAL = {"is_active": True, "storage": "config_file"}


# ── R1 · nested group membership ─────────────────────────────────────────────


def nested_group_graph() -> GraphSnapshot:
    """A user in a group, that group in another, and the outer one holds admin.

    The planted nested-group escalation, at its smallest: three hops, and the
    middle one is a ``MEMBER_OF`` edge whose source is a Group. Every real
    directory is shaped like this — groups are nested precisely so that a
    permission can be granted once and inherited — which is why R1 says the rule
    applies to itself.

    ``g-dist`` is the control on the control: a distribution group nested the
    same way must still confer nothing, so the new rule cannot be passing by
    having dropped R1's group-type check.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("g-inner", "Group", type="security"),
            node("g-outer", "Group", type="security"),
            node("g-dist", "Group", type="distribution"),
            node("g-beyond", "Group", type="security"),
            node("h-goal", "Host", crown_jewel=True, **LIVE_HOST),
            node("h-other", "Host", **LIVE_HOST),
        ],
        [
            edge("e1", "u-1", "g-inner", "MEMBER_OF"),
            edge("e2", "g-inner", "g-outer", "MEMBER_OF"),
            edge("e3", "g-outer", "h-goal", "HAS_PERMISSION", permission_level="admin"),
            edge("e4", "u-1", "g-dist", "MEMBER_OF"),
            edge("e5", "g-dist", "g-beyond", "MEMBER_OF"),
            edge("e6", "g-beyond", "h-other", "HAS_PERMISSION", permission_level="admin"),
        ],
    )


def test_nested_group_escalation_was_unreachable_before_the_fix(
    before_the_fix: RuleSet,
) -> None:
    """Why the row was missing rather than merely absent.

    R1's only seeded precondition was ``controls_principal(src)``. On a
    Group → Group edge the source is a group, and nothing in the model grants
    ``controls_principal`` about a group — not a threat model, not any rule — so
    the second hop could never fire and the nesting R1 describes could not
    happen at any depth.
    """
    result = run(before_the_fix, nested_group_graph(), "external_phish")

    assert not result.paths
    membership = before_the_fix.rule("group_membership").rule_id
    refusals = [
        r
        for r in result.rejections
        if r.rule_id == membership and r.src_node_id == "g-inner"
    ]
    assert refusals, "the Group -> Group hop should have been offered and refused"
    assert all(r.precondition_seq == 1 for r in refusals)
    assert all(r.reason_code == "missing_capability:controls_principal" for r in refusals)


def test_nested_group_escalation_is_found_once_both_disjuncts_are_seeded(
    ruleset: RuleSet,
) -> None:
    result = run(ruleset, nested_group_graph(), "external_phish")

    assert rule_sequence(result, ruleset) == {
        (
            ("e1", "group_membership"),
            ("e2", "group_membership_nested"),
            ("e3", "group_permission_admin"),
        )
    }
    assert all(path.target_node_id == "h-goal" for path in result.paths)


def test_a_distribution_group_still_confers_nothing_when_nested(ruleset: RuleSet) -> None:
    """D13's decoy, one level deeper. The new rule kept R1's group-type check."""
    result = run(ruleset, nested_group_graph(), "external_phish")

    assert not any(
        hop.dst_node_id in {"g-dist", "g-beyond", "h-other"}
        for path in result.paths
        for hop in path.hops
    )


def test_nesting_still_terminates_at_arbitrary_depth(ruleset: RuleSet) -> None:
    """A membership chain long enough that a fixpoint bug would not terminate.

    R1 applying to itself is the one rule in the model whose effect satisfies its
    own precondition, so it is the one place a search can loop. It does not: the
    chain is finite and each hop grants a capability about a different group.
    """
    depth = 6
    nodes = [node("u-1", "User", account_status="active")]
    nodes += [node(f"g-{i}", "Group", type="security") for i in range(depth)]
    nodes.append(node("db-goal", "Database", crown_jewel=True, status="active"))
    edges = [edge("e-0", "u-1", "g-0", "MEMBER_OF")]
    edges += [edge(f"e-{i}", f"g-{i - 1}", f"g-{i}", "MEMBER_OF") for i in range(1, depth)]
    edges.append(
        edge("e-perm", f"g-{depth - 1}", "db-goal", "HAS_PERMISSION", permission_level="admin")
    )

    result = run(ruleset, snapshot(nodes, edges), "external_phish", max_hops=depth + 2)

    assert len(result.paths) == 1
    assert len(result.paths[0].hops) == depth + 1
    assert result.hop_cap_hits == 0


# ── R7 · dumping a credential with can_read_secret rather than admin ─────────


def exposed_credential_graph() -> GraphSnapshot:
    return snapshot(
        [
            node("h-1", "Host", **LIVE_HOST),
            node("cred-goal", "Credential", crown_jewel=True, **LIVE_CREDENTIAL),
        ],
        [edge("e1", "h-1", "cred-goal", "EXPOSES_CREDENTIAL", location="config_file")],
    )


#: The attacker can read this host's secrets but does not administer it — the
#: state R4, R7 and R13 all grant and which, before this change, nothing
#: consumed. Supplied directly for the same reason D8 supplies its pair's
#: difference directly: it is a fact about the attacker, not about the graph.
CAN_READ_ONLY = {
    "entry_node_ids": ("h-1",),
    "extra_capabilities": frozenset({Capability("can_read_secret", "h-1")}),
}


def test_can_read_secret_could_not_dump_a_credential_before_the_fix(
    before_the_fix: RuleSet,
) -> None:
    result = run(before_the_fix, exposed_credential_graph(), "public_only", **CAN_READ_ONLY)

    assert not result.paths
    dump = before_the_fix.rule("credential_dump").rule_id
    assert [r.reason_code for r in result.rejections if r.rule_id == dump] == [
        "missing_capability:admin_on"
    ]


def test_can_read_secret_now_dumps_the_credential(ruleset: RuleSet) -> None:
    result = run(ruleset, exposed_credential_graph(), "public_only", **CAN_READ_ONLY)

    assert rule_sequence(result, ruleset) == {(("e1", "credential_dump_secret_read"),)}


def test_a_vaulted_credential_is_still_refused_to_a_secret_reader(ruleset: RuleSet) -> None:
    """D2's decoy against the new disjunct. Reading secrets on an asset is not
    reading a secret the asset only points at."""
    graph = snapshot(
        [
            node("h-1", "Host", **LIVE_HOST),
            node("cred-goal", "Credential", crown_jewel=True, is_active=True, storage="vault"),
        ],
        [edge("e1", "h-1", "cred-goal", "EXPOSES_CREDENTIAL", location="config_file")],
    )

    result = run(ruleset, graph, "public_only", **CAN_READ_ONLY)

    assert not result.paths
    alternate = ruleset.rule("credential_dump_secret_read").rule_id
    assert [r.precondition_seq for r in result.rejections if r.rule_id == alternate] == [3]


# ── R11 · pivoting across a trust with code execution rather than admin ──────


def post_exploit_trust_graph() -> GraphSnapshot:
    """The ordinary position an RCE leaves an attacker in, and the trust out of it.

    R12 grants ``code_exec_on`` and not ``admin_on`` — that separation is the
    whole reason R13 exists as its own step. So a host reached by remote exploit
    is exactly the case R11's second disjunct is for, and with only the first
    seeded, every such attacker was stranded.
    """
    return snapshot(
        [
            node("h-1", "Host", **UNPATCHED_HOST),
            node("h-goal", "Host", crown_jewel=True, **LIVE_HOST),
            node("v-rce", "Vulnerability", impact="RCE", attack_vector="network"),
        ],
        [
            edge("e1", "h-1", "v-rce", "HAS_VULNERABILITY"),
            edge("e2", "h-1", "h-goal", "TRUSTS", trust_type="rdp"),
        ],
    )


def test_code_execution_could_not_cross_a_trust_before_the_fix(
    before_the_fix: RuleSet,
) -> None:
    result = run(before_the_fix, post_exploit_trust_graph(), "public_only")

    assert not result.paths
    trust = before_the_fix.rule("host_trust").rule_id
    refusals = [r for r in result.rejections if r.rule_id == trust]
    assert refusals
    assert {r.reason_code for r in refusals} == {"missing_capability:admin_on"}


def test_code_execution_now_crosses_the_trust(ruleset: RuleSet) -> None:
    result = run(ruleset, post_exploit_trust_graph(), "public_only")

    assert rule_sequence(result, ruleset) == {
        (("e1", "remote_exploit"), ("e2", "host_trust_code_exec"))
    }


# ── R14 · assuming a role from a resource held as admin rather than access ───


def role_assumption_graph() -> GraphSnapshot:
    return snapshot(
        [
            node("cr-1", "CloudResource", status="active"),
            node("cr-goal", "CloudResource", crown_jewel=True, status="active"),
        ],
        [
            edge(
                "e1",
                "cr-1",
                "cr-goal",
                "CONNECTED_TO",
                connection_type="iam_assume_role",
                grants_admin=True,
            )
        ],
    )


#: Administrative control without ``access_to``. R2 and R4 grant the two
#: together, but R13 grants ``admin_on`` alone, so the state is reachable and
#: the disjunct is not decoration.
ADMIN_ONLY = {
    "entry_node_ids": ("cr-1",),
    "extra_capabilities": frozenset({Capability("admin_on", "cr-1")}),
}


def test_administering_a_resource_could_not_assume_its_role_before_the_fix(
    before_the_fix: RuleSet,
) -> None:
    result = run(before_the_fix, role_assumption_graph(), "public_only", **ADMIN_ONLY)

    assert not result.paths
    assume = before_the_fix.rule("cloud_role_assumption").rule_id
    assert [r.reason_code for r in result.rejections if r.rule_id == assume] == [
        "missing_capability:access_to"
    ]


def test_administering_a_resource_now_assumes_its_role(ruleset: RuleSet) -> None:
    result = run(ruleset, role_assumption_graph(), "public_only", **ADMIN_ONLY)

    assert rule_sequence(result, ruleset) == {(("e1", "cloud_role_assumption_admin"),)}


# ── R15 · pivoting to an adjacent resource from one held as admin ────────────


def cloud_pivot_graph() -> GraphSnapshot:
    """Admin on one resource, network adjacency to another, an RCE on that one.

    R15's seeded conjunct was ``code_exec_on(src)`` and no rule grants that about
    a ``CloudResource``, so the rule was not merely narrow — it was unsatisfiable
    on any graph this model produces, and the reachability it exists to confer
    was never conferred.
    """
    return snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("g-1", "Group", type="security"),
            node("cr-1", "CloudResource", status="active"),
            node(
                "cr-goal",
                "CloudResource",
                crown_jewel=True,
                status="active",
                patch_level="behind-2+",
            ),
            node("v-rce", "Vulnerability", impact="RCE", attack_vector="network"),
        ],
        [
            edge("e1", "u-1", "g-1", "MEMBER_OF"),
            edge("e2", "g-1", "cr-1", "HAS_PERMISSION", permission_level="admin"),
            edge("e3", "cr-1", "cr-goal", "CONNECTED_TO", connection_type="vpc_peering"),
            edge("e4", "cr-goal", "v-rce", "HAS_VULNERABILITY"),
        ],
    )


def test_network_pivot_could_not_fire_at_all_before_the_fix(before_the_fix: RuleSet) -> None:
    result = run(before_the_fix, cloud_pivot_graph(), "external_phish")

    assert not result.paths
    pivot = before_the_fix.rule("network_pivot").rule_id
    assert {r.reason_code for r in result.rejections if r.rule_id == pivot} == {
        "missing_capability:code_exec_on"
    }


def test_network_pivot_now_confers_the_reach_a_remote_exploit_needs(
    ruleset: RuleSet,
) -> None:
    result = run(ruleset, cloud_pivot_graph(), "external_phish")

    # Two, and the shorter one is not an attack. The oracle records a path
    # whenever the attacker's position is a goal node, so the pivot itself is
    # enumerated even though all it gained was reachability -- which is the
    # oracle prunes-nothing contract, and why the differential harness filters
    # reference paths on what their last hop granted before comparing.
    assert rule_sequence(result, ruleset) == {
        (
            ("e1", "group_membership"),
            ("e2", "group_permission_admin"),
            ("e3", "network_pivot_admin"),
        ),
        (
            ("e1", "group_membership"),
            ("e2", "group_permission_admin"),
            ("e3", "network_pivot_admin"),
            ("e4", "remote_exploit"),
        ),
    }


def test_adjacency_alone_is_still_not_arrival(ruleset: RuleSet) -> None:
    """R15 grants reachability, and reachability is not access.

    Without a vulnerability on the far resource there is nothing for
    ``network_reach`` to feed. The new disjunct must not quietly widen what R15
    confers: after the pivot the attacker is adjacent to the crown jewel and
    holds nothing about it but reach.
    """
    graph = snapshot(
        [
            node("u-1", "User", account_status="active"),
            node("g-1", "Group", type="security"),
            node("cr-1", "CloudResource", status="active"),
            node("cr-goal", "CloudResource", crown_jewel=True, status="active"),
        ],
        [
            edge("e1", "u-1", "g-1", "MEMBER_OF"),
            edge("e2", "g-1", "cr-1", "HAS_PERMISSION", permission_level="admin"),
            edge("e3", "cr-1", "cr-goal", "CONNECTED_TO", connection_type="vpc_peering"),
        ],
    )

    result = run(ruleset, graph, "external_phish")

    assert rule_sequence(result, ruleset) == {
        (("e1", "group_membership"), ("e2", "group_permission_admin"), ("e3", "network_pivot_admin"))
    }
    held_about_the_goal = {
        capability.code
        for path in result.paths
        for hop in path.hops
        for capability in hop.gained
        if capability.about == "cr-goal"
    }
    assert held_about_the_goal == {"network_reach"}


# ── The seeded rows and the migrated database say the same thing ─────────────


def test_every_new_rule_matches_the_rule_it_completes(
    ruleset: RuleSet, before_the_fix: RuleSet
) -> None:
    """A disjunct differs in its capability row and in nothing else.

    Checked rather than asserted in a comment, because "same rule, alternate
    precondition" is the entire claim these five rows make. A drifted effect or
    a dropped attribute check would turn one of them into a second, weaker rule
    firing under the first one's name.
    """
    pairs = {
        "group_membership_nested": "group_membership",
        "credential_dump_secret_read": "credential_dump",
        "host_trust_code_exec": "host_trust",
        "cloud_role_assumption_admin": "cloud_role_assumption",
        "network_pivot_admin": "network_pivot",
    }
    for alternate_code, original_code in pairs.items():
        alternate = ruleset.rule(alternate_code)
        original = before_the_fix.rule(original_code)

        assert alternate.technique_code == original.technique_code
        assert alternate.edge_type == original.edge_type
        assert alternate.is_traversal == original.is_traversal
        assert [(e.seq, e.capability_code, e.binding) for e in alternate.effects] == [
            (e.seq, e.capability_code, e.binding) for e in original.effects
        ]

        def attribute_rows(rule):
            return [
                (p.seq, p.kind, p.binding, p.attr_path, p.operator, p.value, p.is_negated)
                for p in rule.preconditions
                if p.attr_path is not None
            ]

        assert attribute_rows(alternate) == attribute_rows(original)

        capability_rows = [p for p in alternate.preconditions if p.attr_path is None]
        assert len(capability_rows) == 1
        assert capability_rows[0].capability_code != (
            [p for p in original.preconditions if p.attr_path is None][0].capability_code
        )
        assert capability_rows[0].failure_reason.strip()
