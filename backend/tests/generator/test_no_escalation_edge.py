"""docs/SCOPE.md D2: the generator must never emit CAN_ESCALATE_TO, or
anything else outside the ten primitive, collector-shaped edge types.

Escalation is the conclusion the engine derives. A generator that plants a
derived fact would let the engine read the answer back instead of finding it,
which is precisely the failure mode D2 exists to rule out.
"""

from __future__ import annotations

from core.model import EdgeType
from generator.graph import BackgroundSizes
from generator.run import generate

_SMALL_SIZES = BackgroundSizes(
    users=20, groups=8, service_accounts=8, hosts=14, databases=5, cloud_resources=6, applications=5
)

_ALLOWED_EDGE_TYPES = frozenset(e.value for e in EdgeType)


def test_no_can_escalate_to_edge_is_ever_emitted():
    generated = generate(11, scenario_count=8, sizes=_SMALL_SIZES)
    edge_types = {e.edge_type for e in generated.edges.values()}
    assert "CAN_ESCALATE_TO" not in edge_types


def test_every_edge_is_one_of_the_ten_primitive_types():
    generated = generate(11, scenario_count=8, sizes=_SMALL_SIZES)
    edge_types = {e.edge_type for e in generated.edges.values()}
    assert edge_types <= _ALLOWED_EDGE_TYPES
    assert len(_ALLOWED_EDGE_TYPES) == 10


def test_manifest_records_intent_never_a_path():
    generated = generate(11, scenario_count=8, sizes=_SMALL_SIZES)
    for scenario in generated.scenarios:
        # Only endpoints and prose. No hop list, no edge sequence anywhere on
        # the scenario record.
        assert hasattr(scenario, "entry_node_id")
        assert hasattr(scenario, "goal_node_id")
        assert not hasattr(scenario, "hops")
        assert not hasattr(scenario, "path")
        assert not hasattr(scenario, "edges")
