"""Ground truth: the manifest, the true edge probabilities, and the bundle
that ties a generation run together.

Per ``docs/SCOPE.md`` D8, the manifest records intent -- never a path. What
lives here is exactly the three things the manifest is allowed to know: the
per-edge probability actually used to synthesise it (for the calibration
metric), the scenario plant log (endpoints and prose, not routes), and the
decoy/twin registry (which element carries the deciding attribute, and what a
correct engine must do with it).
"""

from __future__ import annotations

from dataclasses import dataclass

from core.ids import canonical_json, graph_hash, sha256_hex
from core.model import Edge, Node

from . import GENERATOR_VERSION
from .decoys import DecoyInstance
from .scenarios import PlantedScenario

# Baseline (p_succ, detectability) per technique, used only to synthesise the
# "true" probability recorded for calibration -- the engine never reads this
# table, it derives its own estimate from observable attributes. Numbers
# mirror the base probabilities docs/RULES.md SS4 states per rule; detectability
# has no equivalent stated constant in the spec, so these are a plausible
# generator-side guess, not a value pulled from the rules document.
TECHNIQUE_BASELINE: dict[str, tuple[float, float]] = {
    "group_membership": (0.99, 0.03),
    "group_permission": (0.97, 0.05),
    "direct_assignment": (0.98, 0.04),
    "cloud_account_use": (0.97, 0.05),
    "credential_in_files": (0.85, 0.40),
    "unsecured_credentials": (0.95, 0.10),
    "credential_replay": (0.93, 0.30),
    "kerberoasting": (0.70, 0.50),
    "trusted_relationship": (0.80, 0.35),
    "assume_role": (0.90, 0.20),
    "remote_services": (0.95, 0.10),
}


@dataclass(frozen=True, slots=True)
class TrueEdgeProbability:
    edge_id: str
    p_true: float
    detectability_true: float


def _clamp(value: float, lo: float = 1e-4, hi: float = 0.999) -> float:
    return max(lo, min(hi, value))


def _true_probability_for_edge(edge: Edge, nodes: dict[str, Node]) -> tuple[float, float] | None:
    """The (p_true, detectability_true) the generator used for one edge.

    Maps each traversable edge type back to the technique baseline that
    governs it, mirroring the rule -> technique mapping in
    ``backend/db/seed/020_attacker_model.sql`` exactly, including the
    permission-level and location branches that select between two rules
    sharing one edge type. Returns ``None`` for edge types no rule ever
    consumes as a probability-bearing traversal on their own (there are none
    among the ten primitive types, but the mapping stays defensive).
    """
    et = edge.edge_type
    if et == "MEMBER_OF":
        return TECHNIQUE_BASELINE["group_membership"]
    if et == "HAS_CREDENTIAL":
        # credential_from_principal shares the group_membership technique
        # code in the seeded rule table.
        return TECHNIQUE_BASELINE["group_membership"]
    if et == "HAS_PERMISSION":
        return TECHNIQUE_BASELINE["group_permission"]
    if et == "ADMIN_TO":
        return TECHNIQUE_BASELINE["direct_assignment"]
    if et == "HAS_ACCESS_TO":
        return TECHNIQUE_BASELINE["cloud_account_use"]
    if et == "AUTHENTICATES_TO":
        return TECHNIQUE_BASELINE["credential_replay"]
    if et == "TRUSTS":
        return TECHNIQUE_BASELINE["trusted_relationship"]
    if et == "EXPOSES_CREDENTIAL":
        location = edge.attr("location")
        if location in ("public_repo", "public_bucket", "paste_site"):
            return TECHNIQUE_BASELINE["unsecured_credentials"]
        return TECHNIQUE_BASELINE["credential_in_files"]
    if et == "CONNECTED_TO":
        if edge.attr("connection_type") == "iam_assume_role":
            return TECHNIQUE_BASELINE["assume_role"]
        return TECHNIQUE_BASELINE["remote_services"]
    if et == "HAS_VULNERABILITY":
        vuln = nodes.get(edge.dst_id)
        epss = float(vuln.attr("epss", 0.5)) if vuln else 0.5
        # EPSS is the success probability directly (docs/RULES.md R12/R13);
        # detectability for an exploit is tracked as a fixed, technique-level
        # constant rather than derived from EPSS, which measures exploitation
        # likelihood, not stealth.
        return (_clamp(epss, 1e-4, 0.995), 0.30)
    return None


def compute_true_probabilities(nodes: dict[str, Node], edges: dict[str, Edge]) -> list[TrueEdgeProbability]:
    out: list[TrueEdgeProbability] = []
    for edge in edges.values():
        baseline = _true_probability_for_edge(edge, nodes)
        if baseline is None:
            continue
        p_base, detect_base = baseline
        out.append(
            TrueEdgeProbability(
                edge_id=edge.edge_id,
                p_true=round(_clamp(p_base), 9),
                detectability_true=round(_clamp(detect_base, 0.0, 0.999), 9),
            )
        )
    return out


@dataclass(frozen=True, slots=True)
class GenerationManifest:
    seed: int
    generator_version: str
    scenario_count: int
    parameters: dict
    facts_hash: str


@dataclass(frozen=True, slots=True)
class GeneratedGraph:
    """Everything one generation run produces, entirely in memory.

    This is the no-database surface the task description asks for: the
    engine, the frontend, and this package's own tests can all sanity-check a
    generation run against this object without either store running.
    """

    nodes: dict[str, Node]
    edges: dict[str, Edge]
    manifest: GenerationManifest
    scenarios: tuple[PlantedScenario, ...]
    decoys: tuple[DecoyInstance, ...]
    true_probabilities: tuple[TrueEdgeProbability, ...]

    @property
    def graph_hash(self) -> str:
        return graph_hash(
            ({"node_id": n.node_id, **_node_payload(n)} for n in self.nodes.values()),
            ({"edge_id": e.edge_id, **_edge_payload(e)} for e in self.edges.values()),
        )

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return len(self.edges)


def _node_payload(node: Node) -> dict:
    return {
        "kind": node.kind,
        "name": node.name,
        "display_name": node.display_name,
        "is_crown_jewel": node.is_crown_jewel,
        "criticality": node.criticality,
        "classification": node.classification,
        "attrs": dict(node.attrs),
    }


def _edge_payload(edge: Edge) -> dict:
    return {
        "src_id": edge.src_id,
        "dst_id": edge.dst_id,
        "edge_type": edge.edge_type,
        "attrs": dict(edge.attrs),
    }


def build_manifest(
    *,
    seed: int,
    scenario_count: int,
    parameters: dict,
    nodes: dict[str, Node],
    edges: dict[str, Edge],
) -> GenerationManifest:
    facts_hash = sha256_hex(
        canonical_json(
            {
                "nodes": sorted((n.node_id for n in nodes.values())),
                "node_payloads": {n.node_id: _node_payload(n) for n in nodes.values()},
                "edges": sorted((e.edge_id for e in edges.values())),
                "edge_payloads": {e.edge_id: _edge_payload(e) for e in edges.values()},
            }
        )
    )
    return GenerationManifest(
        seed=seed,
        generator_version=GENERATOR_VERSION,
        scenario_count=scenario_count,
        parameters=parameters,
        facts_hash=facts_hash,
    )
