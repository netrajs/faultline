"""RFC 6962 Merkle tree with inclusion and consistency proofs.

Implemented to RFC 6962 (Certificate Transparency) rather than to a
hand-rolled scheme, for two reasons. The construction is well analysed, and the
Solidity verifier in ``contracts/`` can be differentially fuzzed against this
implementation using shared test vectors — two independent implementations of a
published spec disagreeing is a real signal, whereas two implementations of an
invented scheme disagreeing usually just means the scheme was underspecified.

**Domain separation is load-bearing.** Leaves hash as ``sha256(0x00 || data)``
and interior nodes as ``sha256(0x01 || left || right)``. Without the distinct
prefixes an attacker can present an interior node's hash as though it were a
leaf, which is a second-preimage attack: they would be able to claim an entry
was logged that never was.

**The right spine is where implementations break.** RFC 6962 splits at the
largest power of two strictly less than the node count, which produces a
left-complete tree. Odd sizes exercise the unbalanced right edge, and a naive
implementation that pads to a power of two, or that promotes a lone node
unhashed, produces different roots for the same data. The tests cover every
index for every size from one to thirty-three for exactly this reason.

Consistency proofs are what make anchoring meaningful. An inclusion proof shows
an entry is in the tree the root commits to; a consistency proof shows the
earlier tree is a *prefix* of the later one. Without the second, a log could
publish a root, rewrite its history, and publish another perfectly valid root
over the rewritten version.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# The hash of the empty tree is the hash of the empty string, per RFC 6962.
EMPTY_ROOT = hashlib.sha256(b"").digest()


def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than n, for n > 1.

    This is the RFC 6962 split point. It makes the left subtree complete, which
    is what allows a tree to be extended without rehashing anything already
    committed to -- the property the whole append-only structure depends on.
    """
    if n < 2:
        raise ValueError(f"split point undefined for n={n}")
    return 1 << (n - 1).bit_length() - 1


def merkle_root(leaves: list[bytes]) -> bytes:
    """Root over a list of already-hashed leaves."""
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_power_of_two_below(len(leaves))
    return hash_node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Audit path proving the leaf at *index* is in the tree."""
    if not 0 <= index < len(leaves):
        raise IndexError(f"index {index} out of range for {len(leaves)} leaves")
    if len(leaves) == 1:
        return []
    k = _largest_power_of_two_below(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes) -> bool:
    """Recompute the root from a leaf and its audit path.

    Note that ``index`` and ``tree_size`` together determine which side each
    proof element sits on. A verifier that only takes the proof and infers sides
    from index parity is wrong on unbalanced trees, and wrong in a way that
    passes on every power-of-two size.
    """
    if not 0 <= index < tree_size:
        return False
    if tree_size == 1:
        return not proof and leaf == root

    computed = leaf
    node_index, last_index = index, tree_size - 1

    for sibling in proof:
        if node_index % 2 == 1:
            computed = hash_node(sibling, computed)
        elif node_index < last_index:
            computed = hash_node(computed, sibling)
        else:
            # A right-edge node with no sibling at this level is promoted
            # unchanged. Hashing it against itself here is the classic bug.
            node_index //= 2
            last_index //= 2
            continue
        node_index //= 2
        last_index //= 2

    return computed == root and node_index == 0


def consistency_proof(leaves: list[bytes], old_size: int) -> list[bytes]:
    """Proof that the tree of ``old_size`` leaves is a prefix of this one."""
    new_size = len(leaves)
    if not 0 < old_size <= new_size:
        raise ValueError(f"old_size {old_size} invalid for tree of {new_size}")
    if old_size == new_size:
        return []
    return _consistency(leaves, old_size, True)


def _consistency(leaves: list[bytes], m: int, is_complete_subtree: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        # The old tree is exactly this subtree. Its root is only needed when
        # this subtree is not already known to the verifier.
        return [] if is_complete_subtree else [merkle_root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _consistency(leaves[:k], m, is_complete_subtree) + [merkle_root(leaves[k:])]
    return _consistency(leaves[k:], m - k, False) + [merkle_root(leaves[:k])]


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    """Verify the old tree is a prefix of the new one.

    This is the property that makes a published checkpoint mean anything. Given
    only inclusion proofs, a log operator could rewrite history and publish a
    new root that verifies perfectly against the rewritten entries. Consistency
    is what rules that out: it shows the new tree contains the old one intact,
    in order, with nothing changed.
    """
    if old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and not proof
    if old_size == 0:
        return True
    if not proof:
        return False

    # A proof for a complete-subtree old tree omits the old root, since the
    # verifier already has it.
    is_power_of_two = old_size & (old_size - 1) == 0
    path = list(proof)
    if is_power_of_two:
        path.insert(0, old_root)

    node, last = old_size - 1, new_size - 1
    while node % 2 == 1:
        node //= 2
        last //= 2

    old_computed = path[0]
    new_computed = path[0]

    for sibling in path[1:]:
        if last == 0:
            return False
        if node % 2 == 1 or node == last:
            old_computed = hash_node(sibling, old_computed)
            new_computed = hash_node(sibling, new_computed)
            while node % 2 == 0 and node != 0:
                node //= 2
                last //= 2
        else:
            new_computed = hash_node(new_computed, sibling)
        node //= 2
        last //= 2

    return old_computed == old_root and new_computed == new_root and last == 0


@dataclass(frozen=True, slots=True)
class Checkpoint:
    epoch: int
    tree_size: int
    root: bytes

    @property
    def root_hex(self) -> str:
        return self.root.hex()


class MerkleLog:
    """An append-only log of already-hashed leaves.

    Holds the leaf hashes rather than the entries. Leaf salting happens at the
    boundary in ``core.ids.audit_leaf_hash``, so this class never sees entry
    content and cannot leak it.
    """

    __slots__ = ("_leaves",)

    def __init__(self, leaves: list[bytes] | None = None) -> None:
        self._leaves: list[bytes] = list(leaves or [])

    def append(self, leaf_hash: bytes) -> int:
        if len(leaf_hash) != 32:
            raise ValueError(f"leaf hash must be 32 bytes, got {len(leaf_hash)}")
        self._leaves.append(leaf_hash)
        return len(self._leaves) - 1

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def root(self) -> bytes:
        return merkle_root(self._leaves)

    def prove_inclusion(self, index: int) -> list[bytes]:
        return inclusion_proof(self._leaves, index)

    def prove_consistency(self, old_size: int) -> list[bytes]:
        return consistency_proof(self._leaves, old_size)

    def root_at(self, size: int) -> bytes:
        if not 0 <= size <= len(self._leaves):
            raise ValueError(f"size {size} out of range for {len(self._leaves)} leaves")
        return merkle_root(self._leaves[:size])
