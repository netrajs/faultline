// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CheckpointRegistry
/// @notice Append-only registry of Merkle roots committing to the faultline audit log.
///
/// # What this contract is for
///
/// faultline keeps a SHA-256 hash chain of every recorded action in MySQL. On its own that
/// chain proves very little. An attacker who can write to the database can recompute every
/// leaf and every link, and a verification routine that recomputes the chain from the same
/// database and reports "valid" is checking a structure against itself: it returns green for
/// a log that was rewritten wholesale. Self-consistency is not evidence.
///
/// Publishing the Merkle root somewhere the attacker does not control is what converts
/// self-consistency into evidence. Once a root is here, everything committed before it is
/// immutable — altering any earlier entry changes the root, and the root on this chain does
/// not change. Only the window since the last published checkpoint stays malleable, and the
/// length of that window in seconds is the actual security property faultline can claim.
/// `/api/audit/verify` reports it as a number rather than a boolean for exactly that reason.
///
/// # Why the ordering rules are strict
///
/// `submitCheckpoint` accepts an epoch only if it is exactly the previous epoch plus one, and
/// a tree size only if it is strictly greater than the previous one. Both rules exist to stop
/// history being replaced rather than extended. An out-of-order epoch would let a later
/// checkpoint be backfilled over an earlier gap, and a shrinking tree size would let the
/// publisher commit to a shorter log that drops entries — a rewrite dressed up as an append.
/// With these two invariants the on-chain sequence is a monotone prefix chain: checkpoint N+1
/// commits to a log that contains everything checkpoint N committed to, and a consistency
/// proof between the two roots can be checked off-chain to confirm it.
///
/// A consequence worth noting: because epochs start at 1 and increase by exactly one, the
/// number of checkpoints is always equal to the latest epoch. `checkpointCount()` returns it
/// under that name because the invariant, not a separate counter, is what guarantees the
/// equality. Epoch numbering matches `merkle_checkpoint.epoch` in MySQL, which is an
/// `AUTO_INCREMENT` column and therefore also starts at 1.
///
/// # Hashing: RFC 6962, with SHA-256, and the prefixes are not decoration
///
/// Leaves hash as `sha256(0x00 || leafData)` and interior nodes as `sha256(0x01 || left || right)`.
/// The one-byte prefixes are domain separation and they are load-bearing. Without them the
/// hash of an interior node is indistinguishable from the hash of a leaf whose data happens to
/// be the concatenation of two child hashes, so an attacker holding a valid proof for some
/// leaf can present an interior node as a leaf and obtain a second valid preimage for the same
/// root. That is the classic Merkle second-preimage attack, and the prefixes are the standard
/// fix. Do not remove them, and do not "optimise" the leaf hash into a bare `sha256(leafData)`.
///
/// The leaf preimage is salted off-chain: `leafData = salt || canonical(entry)`, with 16 bytes
/// from a CSPRNG stored beside the entry and released only alongside a proof. Audit entries are
/// low-entropy and guessable — an action code, a target id, a timestamp, a scope — so an
/// unsalted commitment would let anyone confirm a suspected entry by recomputation, leaking the
/// contents of the identity graph through a structure whose whole purpose is to commit to data
/// without revealing it. The salt removes the guess-and-confirm attack while preserving
/// selective disclosure: releasing one salt proves one entry and exposes no other. This
/// contract never sees the salt or the entry; it sees only the finished leaf hash.
///
/// `sha256` is used rather than `keccak256` so that the Python log implementation and this
/// verifier agree byte for byte. Python has SHA-256 in the standard library and Keccak-256 not
/// at all; picking Keccak here would have meant an extra dependency on the side of the system
/// that must be trivially auditable.
///
/// # Dependencies
///
/// Deliberately none. This contract is the root of the audit trust story, so it should be
/// readable end to end without following imports into a library. `RemediationApproval` does
/// depend on OpenZeppelin, because hand-rolling EIP-712 and ECDSA recovery would be a worse
/// trade.
contract CheckpointRegistry {
    /// @param root      RFC 6962 Merkle tree head over the log as of `treeSize` leaves.
    /// @param treeSize  Number of leaves committed to. Mirrors `merkle_checkpoint.tree_size`.
    /// @param publishedAt Block timestamp at which the checkpoint was accepted.
    struct Checkpoint {
        bytes32 root;
        uint64 treeSize;
        uint64 publishedAt;
    }

    /// @dev RFC 6962 domain separation prefixes. See the contract-level note above.
    bytes1 internal constant LEAF_PREFIX = 0x00;
    bytes1 internal constant NODE_PREFIX = 0x01;

    /// @dev A uint64 tree size can have at most 64 levels above a leaf, so no honest inclusion
    ///      proof is longer than that. Bounding it keeps a caller from handing a contract
    ///      integrator an unbounded loop.
    uint256 internal constant MAX_PROOF_LENGTH = 64;

    /// @notice The only address permitted to submit checkpoints.
    address public publisher;

    /// @notice Address that has been proposed as the next publisher but has not accepted yet.
    address public pendingPublisher;

    uint64 private _latestEpoch;
    mapping(uint64 => Checkpoint) private _checkpoints;

    event CheckpointSubmitted(uint64 indexed epoch, bytes32 indexed root, uint64 treeSize, uint64 publishedAt);
    event PublisherTransferProposed(address indexed currentPublisher, address indexed proposedPublisher);
    event PublisherTransferCancelled(address indexed currentPublisher, address indexed cancelledPublisher);
    event PublisherTransferred(address indexed previousPublisher, address indexed newPublisher);

    error NotPublisher(address caller);
    error NotPendingPublisher(address caller);
    error ZeroAddress();
    error EpochOutOfOrder(uint64 expected, uint64 supplied);
    error TreeSizeNotMonotonic(uint64 previous, uint64 supplied);
    error EmptyRoot();
    error UnknownEpoch(uint64 epoch);
    error NoPendingTransfer();

    modifier onlyPublisher() {
        if (msg.sender != publisher) revert NotPublisher(msg.sender);
        _;
    }

    constructor(address initialPublisher) {
        if (initialPublisher == address(0)) revert ZeroAddress();
        publisher = initialPublisher;
        emit PublisherTransferred(address(0), initialPublisher);
    }

    // -------------------------------------------------------------------------------------
    // Publication
    // -------------------------------------------------------------------------------------

    /// @notice Publish a Merkle root committing to the audit log as of `treeSize` leaves.
    /// @dev Reverts unless `epoch == latestEpoch() + 1` and `treeSize > ` the previous tree
    ///      size. See the contract-level note on why both are strict.
    /// @param epoch    Sequential checkpoint number, starting at 1.
    /// @param root     RFC 6962 tree head. A zero root is rejected so that zero can be used
    ///                 unambiguously as "no checkpoint stored" in the views below.
    /// @param treeSize Number of leaves the root commits to.
    function submitCheckpoint(uint64 epoch, bytes32 root, uint64 treeSize) external onlyPublisher {
        if (root == bytes32(0)) revert EmptyRoot();

        uint64 previousEpoch = _latestEpoch;
        uint64 expectedEpoch = previousEpoch + 1;
        if (epoch != expectedEpoch) revert EpochOutOfOrder(expectedEpoch, epoch);

        // The genesis case is not special-cased away: with no prior checkpoint the previous
        // size is zero, so the strict-increase rule already forces the first tree size to be
        // at least 1. An empty log can never be anchored, which is the behaviour we want.
        uint64 previousTreeSize = previousEpoch == 0 ? 0 : _checkpoints[previousEpoch].treeSize;
        if (treeSize <= previousTreeSize) revert TreeSizeNotMonotonic(previousTreeSize, treeSize);

        uint64 publishedAt = uint64(block.timestamp);
        _checkpoints[epoch] = Checkpoint({root: root, treeSize: treeSize, publishedAt: publishedAt});
        _latestEpoch = epoch;

        emit CheckpointSubmitted(epoch, root, treeSize, publishedAt);
    }

    // -------------------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------------------

    /// @notice Read a stored checkpoint.
    /// @dev Reverts on an unknown epoch rather than returning zeros. The caller named a
    ///      specific epoch, so "there is nothing there" is a caller error worth surfacing, not
    ///      a value to be silently confused with a real checkpoint.
    function getCheckpoint(uint64 epoch)
        external
        view
        returns (bytes32 root, uint64 treeSize, uint64 publishedAt)
    {
        Checkpoint storage checkpoint = _checkpoints[epoch];
        if (checkpoint.root == bytes32(0)) revert UnknownEpoch(epoch);
        return (checkpoint.root, checkpoint.treeSize, checkpoint.publishedAt);
    }

    /// @notice Highest epoch published so far, or 0 if none.
    function latestEpoch() external view returns (uint64) {
        return _latestEpoch;
    }

    /// @notice Root of the most recent checkpoint, or `bytes32(0)` if none has been published.
    /// @dev Zero is an unambiguous sentinel here because `submitCheckpoint` rejects zero roots.
    ///      Unlike `getCheckpoint`, this does not revert: a dashboard polling a freshly deployed
    ///      registry should render an empty state, not an error.
    function latestRoot() external view returns (bytes32) {
        return _checkpoints[_latestEpoch].root;
    }

    /// @notice Number of checkpoints published.
    /// @dev Equal to `latestEpoch()` by the sequencing invariant, not by a separate counter.
    function checkpointCount() external view returns (uint256) {
        return uint256(_latestEpoch);
    }

    /// @notice Tree size of the most recent checkpoint, or 0 if none.
    /// @dev The audit verifier needs this to know which leaves are already immutable: any
    ///      entry with `seq <= latestTreeSize()` is covered by a published root.
    function latestTreeSize() external view returns (uint64) {
        return _checkpoints[_latestEpoch].treeSize;
    }

    // -------------------------------------------------------------------------------------
    // Inclusion proofs
    // -------------------------------------------------------------------------------------

    /// @notice Verify an RFC 6962 inclusion proof for `leaf` at `index` against the root stored
    ///         for `epoch`.
    /// @dev Reverts if the epoch has no checkpoint — that is a lookup failure, distinct from a
    ///      proof failure, and collapsing the two into `false` would let a typo in the epoch
    ///      read as "the log has been tampered with". An index outside the committed tree does
    ///      return `false`, because that genuinely is a bad proof.
    /// @param leaf  Leaf hash, i.e. `sha256(0x00 || salt || canonical(entry))`, computed off-chain.
    /// @param proof Sibling hashes bottom-up, as produced by RFC 6962 PATH.
    /// @param index Zero-based leaf index, equal to `audit_entry.seq - 1`.
    /// @param epoch Checkpoint to verify against.
    function verifyInclusion(bytes32 leaf, bytes32[] calldata proof, uint256 index, uint64 epoch)
        external
        view
        returns (bool)
    {
        Checkpoint storage checkpoint = _checkpoints[epoch];
        bytes32 root = checkpoint.root;
        if (root == bytes32(0)) revert UnknownEpoch(epoch);
        return verifyInclusionAgainstRoot(leaf, proof, index, checkpoint.treeSize, root);
    }

    /// @notice Verify an RFC 6962 inclusion proof against a caller-supplied root.
    /// @dev Exposed separately from `verifyInclusion` so the Python Merkle implementation can be
    ///      differentially tested against this verifier over arbitrary fixture trees without
    ///      first anchoring each one. Pure, so it costs nothing over `eth_call`.
    ///
    ///      This is the verification algorithm from RFC 6962-bis section 2.1.3.2, transcribed
    ///      directly. `fn` tracks the index within the current level and `sn` tracks the index
    ///      of the last node at that level; the `fn == sn` case is what handles the unbalanced
    ///      right spine of a tree whose size is not a power of two, and it is the case most
    ///      implementations get wrong.
    function verifyInclusionAgainstRoot(
        bytes32 leaf,
        bytes32[] memory proof,
        uint256 index,
        uint64 treeSize,
        bytes32 root
    ) public pure returns (bool) {
        if (treeSize == 0) return false;
        if (index >= treeSize) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;

        uint256 fn = index;
        uint256 sn = uint256(treeSize) - 1;
        bytes32 computed = leaf;

        for (uint256 i = 0; i < proof.length; ++i) {
            // A proof longer than the tree's depth can justify. Rejecting here rather than
            // ignoring the surplus stops a prover appending junk that still lands on the root.
            if (sn == 0) return false;

            if ((fn & 1) == 1 || fn == sn) {
                computed = hashNode(proof[i], computed);
                if ((fn & 1) == 0) {
                    // Climb past the levels where this subtree is a lone right child.
                    while ((fn & 1) == 0 && fn != 0) {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                computed = hashNode(computed, proof[i]);
            }

            fn >>= 1;
            sn >>= 1;
        }

        // `sn != 0` means the proof stopped short of the root.
        return sn == 0 && computed == root;
    }

    /// @notice RFC 6962 leaf hash: `sha256(0x00 || leafData)`.
    /// @dev `leafData` is the salted, canonically serialised audit entry. Public so the off-chain
    ///      implementation can be checked against this one directly.
    function hashLeaf(bytes memory leafData) public pure returns (bytes32) {
        return sha256(abi.encodePacked(LEAF_PREFIX, leafData));
    }

    /// @notice RFC 6962 interior node hash: `sha256(0x01 || left || right)`.
    function hashNode(bytes32 left, bytes32 right) public pure returns (bytes32) {
        return sha256(abi.encodePacked(NODE_PREFIX, left, right));
    }

    // -------------------------------------------------------------------------------------
    // Publisher custody
    // -------------------------------------------------------------------------------------

    /// @notice Propose a new publisher. Takes effect only when the proposed address accepts.
    /// @dev Two-step on purpose. A one-step transfer to a mistyped or uncontrolled address is
    ///      unrecoverable: the registry would keep accepting reads but could never be extended
    ///      again, which quietly freezes the tamper window open forever. Requiring the incoming
    ///      key to sign a transaction proves it exists and is controlled before anything moves.
    ///      This contract is meant to model good custody, not merely to depend on it.
    function proposePublisher(address newPublisher) external onlyPublisher {
        if (newPublisher == address(0)) revert ZeroAddress();
        pendingPublisher = newPublisher;
        emit PublisherTransferProposed(publisher, newPublisher);
    }

    /// @notice Withdraw a pending publisher proposal.
    function cancelPublisherTransfer() external onlyPublisher {
        address cancelled = pendingPublisher;
        if (cancelled == address(0)) revert NoPendingTransfer();
        pendingPublisher = address(0);
        emit PublisherTransferCancelled(publisher, cancelled);
    }

    /// @notice Accept a pending publisher proposal. Callable only by the proposed address.
    function acceptPublisher() external {
        if (msg.sender != pendingPublisher) revert NotPendingPublisher(msg.sender);
        address previous = publisher;
        publisher = msg.sender;
        pendingPublisher = address(0);
        emit PublisherTransferred(previous, msg.sender);
    }
}
