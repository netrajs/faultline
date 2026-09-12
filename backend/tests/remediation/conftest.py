"""Shared fixtures for the remediation tests.

Two halves, and the split matters. The algorithms -- the overlay, the min cut,
the set cover, the priority formula, the lifecycle -- are pure functions over
plain values, and their tests build their own graphs and their own rows and need
no store at all. Only the router tests need MySQL, and they skip cleanly when it
is not reachable, the same way ``tests/audit/test_routes.py`` does.

Nothing here truncates a remediation table. The audit tests reset theirs because
an append-only log's ``seq`` would otherwise carry state between runs; these
tests read the live ranking and the live recommendations instead, because the
thing under test is the wiring between a real run's results and the API, and a
fixture-built recommendation would not exercise it.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.model import Edge, GraphSnapshot, Node
from remediation.chokepoints import PathCoverage
from remediation.store import FixType


def node(node_id: str, kind: str = "Host", **attrs: Any) -> Node:
    """A node with the promoted fields defaulted and everything else in ``attrs``."""
    return Node(
        node_id=node_id,
        kind=kind,
        name=attrs.pop("name", node_id),
        display_name=attrs.pop("display_name", None),
        is_crown_jewel=bool(attrs.pop("is_crown_jewel", False)),
        criticality=attrs.pop("criticality", None),
        classification=attrs.pop("classification", None),
        attrs=dict(attrs),
    )


def edge(edge_id: str, src: str, dst: str, edge_type: str = "CONNECTED_TO", **attrs: Any) -> Edge:
    return Edge(edge_id=edge_id, src_id=src, dst_id=dst, edge_type=edge_type, attrs=dict(attrs))


@pytest.fixture
def snapshot() -> GraphSnapshot:
    """A small graph with one of every shape the remediation code reasons about.

    An identity holding a credential that authenticates to an asset, a second
    holder of the same credential, an asset exposing it, a group membership that
    confers a grant, and a crown jewel. Small enough to assert exact answers
    against, and wide enough that a fix's applicability and its collateral are
    both derivable from it.
    """
    return GraphSnapshot(
        graph_version=99,
        nodes=[
            node("u1", "User", name="Ana"),
            node("u2", "User", name="Ben"),
            node("sa1", "ServiceAccount", name="svc-batch", is_interactive=False, account_status="active"),
            node("cred1", "Credential", name="shared-key", is_active=True, storage="plaintext_disk", age_days=400),
            node("cred2", "Credential", name="ben-only", is_active=True, storage="vault", age_days=10),
            node("host1", "Host", name="app-01", patch_level="stale"),
            node("g1", "Group", name="admins"),
            node("jewel", "Database", name="prod-db", is_crown_jewel=True, criticality="critical"),
        ],
        edges=[
            edge("e-has1", "u1", "cred1", "HAS_CREDENTIAL"),
            edge("e-has2", "u2", "cred1", "HAS_CREDENTIAL"),
            edge("e-has3", "u2", "cred2", "HAS_CREDENTIAL"),
            edge("e-expose", "host1", "cred1", "EXPOSES_CREDENTIAL", location="/etc/app.conf"),
            edge("e-auth", "cred1", "jewel", "AUTHENTICATES_TO", mfa_type="none"),
            edge("e-member", "u1", "g1", "MEMBER_OF"),
            edge("e-grant", "g1", "jewel", "HAS_PERMISSION", permission_level="admin"),
            edge("e-net", "host1", "jewel", "CONNECTED_TO"),
        ],
    )


@pytest.fixture
def paths() -> list[PathCoverage]:
    """Four paths over the fixture graph, deliberately overlapping.

    ``e-auth`` is on three of the four, which makes it the unambiguous first
    greedy pick and gives the cover something to be right about.
    """
    return [
        PathCoverage(
            path_id="p1",
            source_node_id="u1",
            target_node_id="jewel",
            hops=(("u1", "cred1", "e-has1"), ("cred1", "jewel", "e-auth")),
            risk_score=9.0,
        ),
        PathCoverage(
            path_id="p2",
            source_node_id="u2",
            target_node_id="jewel",
            hops=(("u2", "cred1", "e-has2"), ("cred1", "jewel", "e-auth")),
            risk_score=8.0,
        ),
        PathCoverage(
            path_id="p3",
            source_node_id="host1",
            target_node_id="jewel",
            hops=(("host1", "cred1", "e-expose"), ("cred1", "jewel", "e-auth")),
            risk_score=7.0,
        ),
        PathCoverage(
            path_id="p4",
            source_node_id="u1",
            target_node_id="jewel",
            hops=(("u1", "g1", "e-member"), ("g1", "jewel", "e-grant")),
            risk_score=6.0,
        ),
    ]


def fix_type(code: str, **overrides: Any) -> FixType:
    """A ``fix_type`` row with the shape the seed file uses."""
    defaults: dict[str, Any] = {
        "code": code,
        "label": code.replace("_", " ").title(),
        "description": f"{code} description.",
        "mutation_kind": "set_node_attr",
        "mutation_target_attr": "is_active",
        "mutation_value": False,
        "effort_value": 1.0,
        "effort_label": "Automated",
        "disruption_value": 1.0,
        "disruption_label": "Moderate",
        "requires_approval": False,
        "d3fend_id": None,
        "sort_order": 1,
    }
    defaults.update(overrides)
    return FixType(**defaults)


@pytest.fixture
def fix_types() -> dict[str, FixType]:
    """The shipped catalogue's shapes, trimmed to what these tests exercise."""
    return {
        "revoke_credential": fix_type(
            "revoke_credential",
            mutation_kind="set_node_attr",
            mutation_target_attr="is_active",
            mutation_value=False,
            effort_value=1.0,
            disruption_value=1.0,
            sort_order=1,
        ),
        "vault_credential": fix_type(
            "vault_credential",
            mutation_kind="set_node_attr",
            mutation_target_attr="storage",
            mutation_value="vault",
            effort_value=2.0,
            disruption_value=0.5,
            sort_order=3,
        ),
        "remove_exposure": fix_type(
            "remove_exposure",
            mutation_kind="remove_edge",
            mutation_target_attr=None,
            mutation_value=None,
            effort_value=2.0,
            disruption_value=0.5,
            sort_order=4,
        ),
        "remove_membership": fix_type(
            "remove_membership",
            mutation_kind="remove_edge",
            mutation_target_attr=None,
            mutation_value=None,
            effort_value=5.0,
            disruption_value=1.0,
            sort_order=5,
        ),
        "enforce_mfa": fix_type(
            "enforce_mfa",
            mutation_kind="set_edge_attr",
            mutation_target_attr="mfa_type",
            mutation_value="fido2",
            effort_value=5.0,
            disruption_value=0.5,
            sort_order=6,
        ),
        "least_privilege": fix_type(
            "least_privilege",
            mutation_kind="set_edge_attr",
            mutation_target_attr="permission_level",
            mutation_value="read_only",
            effort_value=5.0,
            disruption_value=1.0,
            requires_approval=True,
            sort_order=7,
        ),
        "disable_account": fix_type(
            "disable_account",
            mutation_kind="set_node_attr",
            mutation_target_attr="account_status",
            mutation_value="disabled",
            effort_value=5.0,
            disruption_value=1.0,
            requires_approval=True,
            sort_order=10,
        ),
    }


@pytest.fixture
def make_snapshot():
    """Build a one-off graph, for the cases the shared fixture cannot express."""

    def build(nodes: list[Node], edges: list[Edge], graph_version: int = 1) -> GraphSnapshot:
        return GraphSnapshot(graph_version=graph_version, nodes=nodes, edges=edges)

    build.node = node  # type: ignore[attr-defined]
    build.edge = edge  # type: ignore[attr-defined]
    return build


@pytest.fixture
def make_fix_type():
    """A ``fix_type`` row builder, for catalogue entries a test needs to add."""
    return fix_type


@pytest.fixture
def lifecycle_rows() -> tuple[list[dict], list[dict]]:
    """The shipped states and transitions, as ``build_lifecycle`` consumes them."""
    states = [
        {"code": "recommended", "label": "Recommended", "description": "", "is_terminal": 0, "ui_color": "#64748b", "sort_order": 1},
        {"code": "simulated", "label": "Simulated", "description": "", "is_terminal": 0, "ui_color": "#38bdf8", "sort_order": 2},
        {"code": "approved", "label": "Approved", "description": "", "is_terminal": 0, "ui_color": "#8b5cf6", "sort_order": 3},
        {"code": "applied", "label": "Applied", "description": "", "is_terminal": 0, "ui_color": "#f59e0b", "sort_order": 4},
        {"code": "verified", "label": "Verified", "description": "", "is_terminal": 1, "ui_color": "#10b981", "sort_order": 5},
        {"code": "rolled_back", "label": "Rolled back", "description": "", "is_terminal": 1, "ui_color": "#ef4444", "sort_order": 6},
        {"code": "dismissed", "label": "Dismissed", "description": "", "is_terminal": 1, "ui_color": "#64748b", "sort_order": 7},
    ]
    transitions = [
        {"from_state": "recommended", "to_state": "simulated", "label": "Simulate", "needs_approval": 0},
        {"from_state": "recommended", "to_state": "dismissed", "label": "Dismiss", "needs_approval": 0},
        {"from_state": "simulated", "to_state": "approved", "label": "Approve", "needs_approval": 1},
        {"from_state": "simulated", "to_state": "dismissed", "label": "Dismiss", "needs_approval": 0},
        {"from_state": "simulated", "to_state": "recommended", "label": "Re-evaluate", "needs_approval": 0},
        {"from_state": "approved", "to_state": "applied", "label": "Apply", "needs_approval": 0},
        {"from_state": "approved", "to_state": "dismissed", "label": "Dismiss", "needs_approval": 0},
        {"from_state": "applied", "to_state": "verified", "label": "Verify", "needs_approval": 0},
        {"from_state": "applied", "to_state": "rolled_back", "label": "Roll back", "needs_approval": 0},
        {"from_state": "verified", "to_state": "rolled_back", "label": "Roll back", "needs_approval": 1},
    ]
    return states, transitions
