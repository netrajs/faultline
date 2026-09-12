"""Tests for the copy-on-write mutation overlay.

Two properties carry the whole module and neither is visible from the outside
unless it is asserted: the base snapshot is never touched, and a node removal
takes its incident edges with it. Everything else is read-through.
"""

from __future__ import annotations

import pytest

from remediation.overlay import MutationError, Mutation, apply_mutation


def test_mutation_rejects_an_unknown_kind():
    with pytest.raises(MutationError, match="unknown mutation kind"):
        Mutation(kind="delete_everything", target_kind="node", target_id="u1")


def test_mutation_rejects_a_kind_pointed_at_the_wrong_target():
    """``remove_edge`` acting on a node is a data error, not a no-op."""
    with pytest.raises(MutationError, match="acts on a edge"):
        Mutation(kind="remove_edge", target_kind="node", target_id="u1")


def test_setting_an_attribute_with_no_attribute_named_is_refused():
    with pytest.raises(MutationError, match="names no attribute"):
        Mutation(kind="set_node_attr", target_kind="node", target_id="u1")


def test_absent_target_names_the_graph_version(snapshot):
    with pytest.raises(MutationError, match="absent from graph version 99"):
        apply_mutation(snapshot, Mutation("remove_edge", "edge", "e-nope"))


def test_removing_an_edge_leaves_the_base_snapshot_alone(snapshot):
    mutated = apply_mutation(snapshot, Mutation("remove_edge", "edge", "e-auth"))

    with pytest.raises(KeyError):
        mutated.edge("e-auth")
    assert snapshot.edge("e-auth").edge_type == "AUTHENTICATES_TO"
    assert [e.edge_id for e in mutated.out_edges("cred1")] == []
    assert [e.edge_id for e in snapshot.out_edges("cred1")] == ["e-auth"]


def test_removing_a_node_removes_its_incident_edges(snapshot):
    """A snapshot whose edge names an absent node is rejected on construction,
    so an overlay that kept one would hand the search an endpoint it cannot
    look up."""
    mutated = apply_mutation(snapshot, Mutation("remove_node", "node", "cred1"))

    assert mutated.get_node("cred1") is None
    remaining = {e.edge_id for e in mutated.all_edges}
    assert "e-has1" not in remaining
    assert "e-has2" not in remaining
    assert "e-expose" not in remaining
    assert "e-auth" not in remaining
    # Untouched edges survive, and so does everything about the base.
    assert "e-grant" in remaining
    assert snapshot.get_node("cred1") is not None
    assert len(mutated) == len(snapshot) - 1


def test_setting_a_promoted_field_writes_the_field_not_the_attribute_bag(snapshot):
    """``is_crown_jewel`` is a dataclass field. Writing it into ``attrs``
    instead would add a shadow value nothing reads, and the mutation would look
    applied while changing nothing."""
    mutated = apply_mutation(
        snapshot, Mutation("set_node_attr", "node", "jewel", attr="is_crown_jewel", value=False)
    )

    assert mutated.node("jewel").is_crown_jewel is False
    assert "is_crown_jewel" not in mutated.node("jewel").attrs
    assert mutated.crown_jewels == frozenset()
    assert snapshot.crown_jewels == frozenset({"jewel"})


def test_setting_an_ordinary_attribute_keeps_the_others(snapshot):
    mutated = apply_mutation(
        snapshot, Mutation("set_node_attr", "node", "cred1", attr="is_active", value=False)
    )

    assert mutated.node("cred1").attrs["is_active"] is False
    assert mutated.node("cred1").attrs["storage"] == "plaintext_disk"
    assert snapshot.node("cred1").attrs["is_active"] is True


def test_edge_structure_cannot_be_rewritten_as_an_attribute(snapshot):
    with pytest.raises(MutationError, match="edge structure, not an attribute"):
        apply_mutation(
            snapshot, Mutation("set_edge_attr", "edge", "e-auth", attr="edge_type", value="TRUSTS")
        )


def test_rows_are_ordered_so_the_graph_hash_is_stable(snapshot):
    mutated = apply_mutation(
        snapshot, Mutation("set_edge_attr", "edge", "e-auth", attr="mfa_type", value="fido2")
    )

    node_ids = [row["node_id"] for row in mutated.node_rows()]
    edge_ids = [row["edge_id"] for row in mutated.edge_rows()]
    assert node_ids == sorted(node_ids)
    assert edge_ids == sorted(edge_ids)
    changed = next(row for row in mutated.edge_rows() if row["edge_id"] == "e-auth")
    assert changed["attrs"]["mfa_type"] == "fido2"


def test_rollback_payload_for_an_edge_records_the_whole_prior_row(snapshot):
    mutated = apply_mutation(
        snapshot, Mutation("set_edge_attr", "edge", "e-auth", attr="mfa_type", value="fido2")
    )
    payload = mutated.rollback_payload()

    assert payload["graph_version"] == 99
    assert payload["edge"]["edge_id"] == "e-auth"
    # The value recorded is the one from *before* the mutation, which is the
    # only thing a rollback can restore from.
    assert payload["edge"]["attrs"]["mfa_type"] == "none"
    assert payload["mutation"]["kind"] == "set_edge_attr"


def test_rollback_payload_for_a_node_removal_includes_its_incident_edges(snapshot):
    """Restoring the node alone would leave it stranded with no relationships."""
    mutated = apply_mutation(snapshot, Mutation("remove_node", "node", "cred1"))
    payload = mutated.rollback_payload()

    assert payload["node"]["node_id"] == "cred1"
    recorded = {e["edge_id"] for e in payload["incident_edges"]}
    assert recorded == {"e-has1", "e-has2", "e-expose", "e-auth"}
