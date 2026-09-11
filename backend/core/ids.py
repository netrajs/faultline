"""Deterministic identifiers, canonical serialisation and content hashing.

Reproducibility is a product feature here, not a testing convenience. The demo
resets mid-run; deep links have to survive it; the narration cache is keyed by
path identity and a cache miss means a live model call at the worst possible
moment. All of that requires that regenerating from the same seed produces
byte-identical output, including tie ordering.

Three rules make that hold, and each has a way of being violated by accident:

**Never touch the global random module.** A ``SeedBundle`` is threaded through
explicitly. Global state means an unrelated import that happens to call
``random.seed`` changes your graph.

**Never call ``uuid4``.** Identifiers come from ``uuid5`` over a stable
namespace and a deterministic name. A lint test greps the source tree for
``uuid4(`` and fails the build, because this is the single easiest way to
reintroduce nondeterminism and the symptom — a demo reset that quietly changes
every id — appears far from the cause.

**Serialise canonically.** Sorted keys, fixed float formatting, no whitespace.
Two structurally identical graphs must hash identically, and ``0.1 + 0.2``
must not hash differently from ``0.3`` because one repr carried more digits.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

# Fixed namespace. Changing this value changes every identifier the generator
# has ever produced, so it is a constant and not configuration.
NAMESPACE = uuid.UUID("6f2a1c84-3d5e-5b7a-9e41-8c0d2f6b4a13")

# Floats are rounded before formatting so that accumulated arithmetic noise
# below this precision cannot change a hash. Nine places is well beyond any
# probability we display and well inside float64's reliable range.
FLOAT_PRECISION = 9


@dataclass(frozen=True, slots=True)
class SeedBundle:
    """Every source of randomness for one generation run, derived from one seed.

    Each consumer gets its own stream rather than sharing one, so adding a
    generation step does not shift the numbers every later step draws. Without
    that, inserting one node kind reshuffles the entire graph and no previously
    recorded scenario reproduces.
    """

    seed: int

    def stream(self, purpose: str) -> random.Random:
        """A dedicated, reproducible random stream for one purpose."""
        derived = hashlib.sha256(f"{self.seed}:{purpose}".encode()).digest()
        return random.Random(int.from_bytes(derived[:8], "big"))

    def namespace_for(self, purpose: str) -> uuid.UUID:
        return uuid.uuid5(NAMESPACE, f"{self.seed}:{purpose}")


def node_id(seed: SeedBundle, kind: str, index: int) -> str:
    """A stable, readable node identifier.

    Readable matters more than it sounds: these appear in demo narration, in
    rejection messages, and in the graph explorer. An opaque UUID would be
    correct and unusable.
    """
    prefix = _KIND_PREFIX.get(kind, kind[:3].lower())
    return f"{prefix}-{index:04d}"


def edge_id(seed: SeedBundle, edge_type: str, src: str, dst: str, discriminator: int = 0) -> str:
    """A stable edge identifier.

    The discriminator distinguishes parallel edges of the same type between the
    same pair, which is not a hypothetical: two separate credentials can both
    authenticate the same principal to the same host, and they are two different
    attacks with two different probabilities.
    """
    name = f"{edge_type}:{src}:{dst}:{discriminator}"
    digest = uuid.uuid5(seed.namespace_for("edge"), name).hex[:12]
    return f"e-{digest}"


_KIND_PREFIX = {
    "User": "u",
    "Group": "g",
    "ServiceAccount": "sa",
    "Host": "h",
    "Database": "db",
    "CloudResource": "cr",
    "Application": "app",
    "Credential": "cred",
    "Vulnerability": "vuln",
}


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace, fixed floats."""
    return json.dumps(
        _canonicalise(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _canonicalise(value: Any) -> Any:
    if isinstance(value, float):
        rounded = round(value, FLOAT_PRECISION)
        # Normalise negative zero, which formats differently but compares equal.
        return 0.0 if rounded == 0 else rounded
    if isinstance(value, Mapping):
        return {str(k): _canonicalise(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonicalise(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_canonicalise(v) for v in value)
    return value


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def path_id(edge_sequence: Sequence[str | None], rule_sequence: Sequence[int]) -> str:
    """Content hash identifying a path.

    Keyed on the edge sequence rather than the node sequence, because two
    distinct credentials between the same pair of nodes are two genuinely
    different attacks and a node-keyed identity would merge them into one.

    The rule sequence is included because a non-traversal rule consumes no edge
    — kerberoasting, for instance — so two different techniques applied at the
    same point would otherwise collide on an identical edge sequence.
    """
    parts = [f"{e or '-'}#{r}" for e, r in zip(edge_sequence, rule_sequence, strict=True)]
    return sha256_hex("|".join(parts))


def node_sequence_key(node_ids: Sequence[str]) -> str:
    """Looser path identity, keyed on nodes only.

    Reported alongside the strict edge-sequence key during evaluation. The gap
    between the two says how often the engine reaches the right places by the
    wrong mechanism, which a single matching level hides.
    """
    return sha256_hex("|".join(node_ids))


def rejection_signature(
    src_id: str, dst_id: str, edge_id_value: str | None, rule_id: int, depth: int
) -> str:
    """Collapses repeated refusals of the same candidate into one record.

    The same dead end is reached many times from different prefixes during
    search. Without collapsing, the rejection table would be dominated by
    duplicates and the decoy-rejection metric would count the same refusal
    repeatedly.
    """
    return sha256_hex(f"{src_id}|{dst_id}|{edge_id_value or '-'}|{rule_id}|{depth}")


def graph_hash(nodes: Iterable[Mapping[str, Any]], edges: Iterable[Mapping[str, Any]]) -> str:
    """Canonical hash over a whole graph version.

    Two generation runs from the same seed must produce the same value; a test
    asserts exactly that. Nodes sort by id and edges by the tuple that makes
    parallel edges distinguishable, so ordering from the store never leaks into
    the hash.
    """
    sorted_nodes = sorted(nodes, key=lambda n: str(n.get("node_id", "")))
    sorted_edges = sorted(
        edges,
        key=lambda e: (
            str(e.get("src_id", "")),
            str(e.get("edge_type", "")),
            str(e.get("dst_id", "")),
            str(e.get("edge_id", "")),
        ),
    )
    return sha256_hex(canonical_json({"nodes": sorted_nodes, "edges": sorted_edges}))


def audit_leaf_hash(salt: bytes, entry: Mapping[str, Any]) -> bytes:
    """RFC 6962 leaf hash over a salted, canonically serialised audit entry.

    The ``0x00`` prefix is domain separation: interior nodes hash with ``0x01``,
    and without the distinction an attacker can present an interior node as a
    leaf, which is a second-preimage attack on the tree.

    The salt is not decoration either. Audit entries are low-entropy and
    guessable — an action code, a target id, a timestamp — so publishing a root
    over unsalted leaves would let anyone confirm a suspected entry by
    recomputing its hash, leaking graph contents through a structure whose
    purpose is to commit to data without revealing it. Sixteen random bytes per
    leaf removes the guess-and-confirm attack while preserving selective
    disclosure: releasing one salt proves one entry and exposes no other.
    """
    if len(salt) != 16:
        raise ValueError(f"audit leaf salt must be 16 bytes, got {len(salt)}")
    payload = b"\x00" + salt + canonical_json(entry).encode("utf-8")
    return hashlib.sha256(payload).digest()


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash."""
    return hashlib.sha256(b"\x01" + left + right).digest()
