// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CheckpointRegistry} from "../src/CheckpointRegistry.sol";
import {RFC6962} from "./RFC6962.sol";

contract CheckpointRegistryTest is Test {
    CheckpointRegistry internal registry;

    address internal publisher = makeAddr("publisher");
    address internal outsider = makeAddr("outsider");
    address internal successor = makeAddr("successor");

    /// @dev Trees of size 1 through this bound are exercised leaf by leaf. Odd sizes are the
    ///      point: a power-of-two tree is perfectly balanced and hides every mistake in the
    ///      handling of the unbalanced right spine, which is where RFC 6962 implementations
    ///      actually break. 33 crosses two power-of-two boundaries and leaves a single leaf
    ///      hanging off the top level.
    uint256 internal constant MAX_TREE_SIZE = 33;

    function setUp() public {
        vm.warp(1_700_000_000);
        registry = new CheckpointRegistry(publisher);
    }

    // -------------------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------------------

    /// @dev Mirrors the off-chain leaf preimage: 16 bytes of salt followed by the canonical
    ///      serialisation of the entry.
    function _leafData(uint256 i) internal pure returns (bytes memory) {
        bytes16 salt = bytes16(keccak256(abi.encodePacked("faultline-salt", i)));
        bytes32 body = keccak256(abi.encodePacked("audit-entry", i));
        return abi.encodePacked(salt, body);
    }

    function _leaves(uint256 n) internal pure returns (bytes32[] memory leaves) {
        leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            leaves[i] = RFC6962.leafHash(_leafData(i));
        }
    }

    function _submit(uint64 epoch, bytes32 root, uint64 treeSize) internal {
        vm.prank(publisher);
        registry.submitCheckpoint(epoch, root, treeSize);
    }

    // -------------------------------------------------------------------------------------
    // Deployment and basic publication
    // -------------------------------------------------------------------------------------

    function test_initialState() public view {
        assertEq(registry.publisher(), publisher);
        assertEq(registry.pendingPublisher(), address(0));
        assertEq(registry.latestEpoch(), 0);
        assertEq(registry.latestRoot(), bytes32(0));
        assertEq(registry.latestTreeSize(), 0);
        assertEq(registry.checkpointCount(), 0);
    }

    function test_revert_constructorZeroPublisher() public {
        vm.expectRevert(CheckpointRegistry.ZeroAddress.selector);
        new CheckpointRegistry(address(0));
    }

    function test_submitFirstCheckpoint() public {
        bytes32[] memory leaves = _leaves(4);
        bytes32 root = RFC6962.root(leaves);

        vm.expectEmit(true, true, true, true);
        emit CheckpointRegistry.CheckpointSubmitted(1, root, 4, uint64(block.timestamp));
        _submit(1, root, 4);

        (bytes32 storedRoot, uint64 treeSize, uint64 publishedAt) = registry.getCheckpoint(1);
        assertEq(storedRoot, root);
        assertEq(treeSize, 4);
        assertEq(publishedAt, uint64(block.timestamp));
        assertEq(registry.latestEpoch(), 1);
        assertEq(registry.latestRoot(), root);
        assertEq(registry.latestTreeSize(), 4);
        assertEq(registry.checkpointCount(), 1);
    }

    function test_submitSequenceOfCheckpoints() public {
        for (uint64 epoch = 1; epoch <= 5; ++epoch) {
            uint256 n = uint256(epoch) * 3;
            _submit(epoch, RFC6962.root(_leaves(n)), uint64(n));
            vm.warp(block.timestamp + 600);
        }
        assertEq(registry.latestEpoch(), 5);
        assertEq(registry.latestTreeSize(), 15);
        assertEq(registry.checkpointCount(), 5);
    }

    function test_revert_notPublisher() public {
        bytes32 root = RFC6962.root(_leaves(2));
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPublisher.selector, outsider));
        registry.submitCheckpoint(1, root, 2);
    }

    function test_revert_zeroRoot() public {
        vm.prank(publisher);
        vm.expectRevert(CheckpointRegistry.EmptyRoot.selector);
        registry.submitCheckpoint(1, bytes32(0), 1);
    }

    function test_revert_unknownEpoch() public {
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.UnknownEpoch.selector, uint64(7)));
        registry.getCheckpoint(7);
    }

    // -------------------------------------------------------------------------------------
    // Monotonicity
    // -------------------------------------------------------------------------------------

    function test_revert_epochSkip() public {
        bytes32 root = RFC6962.root(_leaves(2));
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.EpochOutOfOrder.selector, uint64(1), uint64(2)));
        registry.submitCheckpoint(2, root, 2);
    }

    function test_revert_epochRegression() public {
        _submit(1, RFC6962.root(_leaves(4)), 4);
        _submit(2, RFC6962.root(_leaves(8)), 8);

        // Re-publishing epoch 2, which is what overwriting an anchored root would look like.
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.EpochOutOfOrder.selector, uint64(3), uint64(2)));
        registry.submitCheckpoint(2, RFC6962.root(_leaves(9)), 9);

        // And reaching further back.
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.EpochOutOfOrder.selector, uint64(3), uint64(1)));
        registry.submitCheckpoint(1, RFC6962.root(_leaves(5)), 5);
    }

    function test_revert_treeSizeRegression() public {
        _submit(1, RFC6962.root(_leaves(10)), 10);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.TreeSizeNotMonotonic.selector, uint64(10), uint64(6)));
        registry.submitCheckpoint(2, RFC6962.root(_leaves(6)), 6);
    }

    function test_revert_treeSizeUnchanged() public {
        _submit(1, RFC6962.root(_leaves(10)), 10);

        // Equal is not "strictly greater". Allowing it would let a second root be published for
        // the same log length, which is precisely two conflicting histories of the same size.
        vm.prank(publisher);
        vm.expectRevert(
            abi.encodeWithSelector(CheckpointRegistry.TreeSizeNotMonotonic.selector, uint64(10), uint64(10))
        );
        registry.submitCheckpoint(2, keccak256("some other root"), 10);
    }

    function test_revert_emptyTreeCannotBeAnchored() public {
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.TreeSizeNotMonotonic.selector, uint64(0), uint64(0)));
        registry.submitCheckpoint(1, keccak256("empty"), 0);
    }

    // -------------------------------------------------------------------------------------
    // Inclusion proofs
    // -------------------------------------------------------------------------------------

    /// @dev Every leaf of every tree from 1 to MAX_TREE_SIZE. Each size is published as its own
    ///      epoch, which also exercises a long monotone sequence of checkpoints.
    function test_inclusionProof_everyIndex_sizes1To33() public {
        for (uint256 n = 1; n <= MAX_TREE_SIZE; ++n) {
            bytes32[] memory leaves = _leaves(n);
            bytes32 root = RFC6962.root(leaves);
            uint64 epoch = uint64(n);
            _submit(epoch, root, uint64(n));

            for (uint256 index = 0; index < n; ++index) {
                bytes32[] memory proof = RFC6962.proof(leaves, index);
                assertTrue(
                    registry.verifyInclusion(leaves[index], proof, index, epoch),
                    "inclusion proof rejected for a valid leaf"
                );
            }
        }
    }

    function test_inclusionProof_singleLeafTreeHasEmptyProof() public {
        bytes32[] memory leaves = _leaves(1);
        bytes32 root = RFC6962.root(leaves);

        // MTH of a one-leaf tree is the leaf hash itself.
        assertEq(root, leaves[0]);

        _submit(1, root, 1);
        assertTrue(registry.verifyInclusion(leaves[0], new bytes32[](0), 0, 1));
    }

    function test_inclusionProof_tamperedLeafFails() public {
        bytes32[] memory leaves = _leaves(8);
        _submit(1, RFC6962.root(leaves), 8);

        bytes32[] memory proof = RFC6962.proof(leaves, 3);
        bytes32 tampered = leaves[3] ^ bytes32(uint256(1));

        assertTrue(registry.verifyInclusion(leaves[3], proof, 3, 1));
        assertFalse(registry.verifyInclusion(tampered, proof, 3, 1));
    }

    function test_inclusionProof_tamperedProofElementFails() public {
        bytes32[] memory leaves = _leaves(11);
        _submit(1, RFC6962.root(leaves), 11);

        uint256 index = 6;
        bytes32[] memory proof = RFC6962.proof(leaves, index);
        assertTrue(registry.verifyInclusion(leaves[index], proof, index, 1));

        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32[] memory corrupted = RFC6962.proof(leaves, index);
            corrupted[i] = corrupted[i] ^ bytes32(uint256(1));
            assertFalse(
                registry.verifyInclusion(leaves[index], corrupted, index, 1), "corrupted proof element accepted"
            );
        }
    }

    function test_inclusionProof_wrongIndexFails() public {
        bytes32[] memory leaves = _leaves(9);
        _submit(1, RFC6962.root(leaves), 9);

        uint256 index = 2;
        bytes32[] memory proof = RFC6962.proof(leaves, index);
        assertTrue(registry.verifyInclusion(leaves[index], proof, index, 1));

        for (uint256 claimed = 0; claimed < 9; ++claimed) {
            if (claimed == index) continue;
            assertFalse(registry.verifyInclusion(leaves[index], proof, claimed, 1), "proof verified at a wrong index");
        }
    }

    function test_inclusionProof_indexOutsideTreeFails() public {
        bytes32[] memory leaves = _leaves(5);
        _submit(1, RFC6962.root(leaves), 5);

        bytes32[] memory proof = RFC6962.proof(leaves, 4);
        assertFalse(registry.verifyInclusion(leaves[4], proof, 5, 1));
        assertFalse(registry.verifyInclusion(leaves[4], proof, type(uint256).max, 1));
    }

    function test_inclusionProof_truncatedAndPaddedProofsFail() public {
        bytes32[] memory leaves = _leaves(13);
        _submit(1, RFC6962.root(leaves), 13);

        uint256 index = 5;
        bytes32[] memory proof = RFC6962.proof(leaves, index);
        assertTrue(proof.length >= 2);

        bytes32[] memory truncated = new bytes32[](proof.length - 1);
        for (uint256 i = 0; i < truncated.length; ++i) {
            truncated[i] = proof[i];
        }
        assertFalse(registry.verifyInclusion(leaves[index], truncated, index, 1), "short proof accepted");

        bytes32[] memory padded = new bytes32[](proof.length + 1);
        for (uint256 i = 0; i < proof.length; ++i) {
            padded[i] = proof[i];
        }
        padded[proof.length] = keccak256("junk");
        assertFalse(registry.verifyInclusion(leaves[index], padded, index, 1), "over-long proof accepted");
    }

    function test_inclusionProof_proofFromAnotherTreeFails() public {
        bytes32[] memory leaves = _leaves(16);
        bytes32[] memory otherLeaves = _leaves(15);
        _submit(1, RFC6962.root(leaves), 16);

        bytes32[] memory foreignProof = RFC6962.proof(otherLeaves, 4);
        assertFalse(registry.verifyInclusion(leaves[4], foreignProof, 4, 1));
    }

    function test_revert_verifyInclusionAgainstUnknownEpoch() public {
        bytes32[] memory leaves = _leaves(4);
        bytes32[] memory proof = RFC6962.proof(leaves, 1);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.UnknownEpoch.selector, uint64(1)));
        registry.verifyInclusion(leaves[1], proof, 1, 1);
    }

    /// @dev Domain separation. An interior node presented as a leaf must not verify: without the
    ///      0x00 / 0x01 prefixes this is the second-preimage attack.
    function test_domainSeparation_interiorNodeIsNotALeaf() public view {
        bytes32 left = keccak256("left");
        bytes32 right = keccak256("right");

        bytes32 asNode = registry.hashNode(left, right);
        bytes32 asLeaf = registry.hashLeaf(abi.encodePacked(left, right));
        assertTrue(asNode != asLeaf, "prefix domain separation is missing");

        // And the leaf prefix is really 0x00, the node prefix really 0x01.
        assertEq(asLeaf, sha256(abi.encodePacked(bytes1(0x00), left, right)));
        assertEq(asNode, sha256(abi.encodePacked(bytes1(0x01), left, right)));
    }

    function test_hashHelpersMatchTheReferenceImplementation() public view {
        bytes memory data = _leafData(42);
        assertEq(registry.hashLeaf(data), RFC6962.leafHash(data));
        assertEq(registry.hashNode(keccak256("a"), keccak256("b")), RFC6962.nodeHash(keccak256("a"), keccak256("b")));
    }

    function test_verifyInclusionAgainstRoot_rejectsEmptyTree() public view {
        assertFalse(registry.verifyInclusionAgainstRoot(keccak256("leaf"), new bytes32[](0), 0, 0, keccak256("root")));
    }

    // -------------------------------------------------------------------------------------
    // Fuzz
    // -------------------------------------------------------------------------------------

    function testFuzz_inclusionProof(uint8 rawSize, uint256 rawIndex) public {
        uint256 n = (uint256(rawSize) % 64) + 1;
        uint256 index = rawIndex % n;

        bytes32[] memory leaves = _leaves(n);
        bytes32 root = RFC6962.root(leaves);
        bytes32[] memory proof = RFC6962.proof(leaves, index);

        _submit(1, root, uint64(n));
        assertTrue(registry.verifyInclusion(leaves[index], proof, index, 1));

        // The proof length is exactly the number of levels the leaf climbs.
        assertTrue(proof.length <= 6, "proof longer than the tree is deep");
    }

    function testFuzz_inclusionProofRejectsWrongLeaf(uint8 rawSize, uint256 rawIndex, bytes32 forged) public {
        uint256 n = (uint256(rawSize) % 64) + 1;
        uint256 index = rawIndex % n;

        bytes32[] memory leaves = _leaves(n);
        vm.assume(forged != leaves[index]);

        bytes32 root = RFC6962.root(leaves);
        bytes32[] memory proof = RFC6962.proof(leaves, index);

        _submit(1, root, uint64(n));
        assertFalse(registry.verifyInclusion(forged, proof, index, 1));
    }

    function testFuzz_epochMustBeExactlyNext(uint64 epoch) public {
        vm.assume(epoch != 1);
        bytes32 root = RFC6962.root(_leaves(3));

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.EpochOutOfOrder.selector, uint64(1), epoch));
        registry.submitCheckpoint(epoch, root, 3);
    }

    function testFuzz_treeSizeMustGrow(uint64 first, uint64 second) public {
        first = uint64(bound(first, 1, type(uint64).max - 1));
        second = uint64(bound(second, 0, first));

        _submit(1, RFC6962.root(_leaves(4)), first);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.TreeSizeNotMonotonic.selector, first, second));
        registry.submitCheckpoint(2, RFC6962.root(_leaves(5)), second);
    }

    // -------------------------------------------------------------------------------------
    // Two-step publisher transfer
    // -------------------------------------------------------------------------------------

    function test_twoStepPublisherTransfer() public {
        vm.prank(publisher);
        vm.expectEmit(true, true, true, true);
        emit CheckpointRegistry.PublisherTransferProposed(publisher, successor);
        registry.proposePublisher(successor);

        // Nothing has moved yet.
        assertEq(registry.publisher(), publisher);
        assertEq(registry.pendingPublisher(), successor);

        // The proposed publisher cannot act before accepting.
        vm.prank(successor);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPublisher.selector, successor));
        registry.submitCheckpoint(1, RFC6962.root(_leaves(2)), 2);

        // The incumbent still can.
        _submit(1, RFC6962.root(_leaves(2)), 2);

        vm.prank(successor);
        vm.expectEmit(true, true, true, true);
        emit CheckpointRegistry.PublisherTransferred(publisher, successor);
        registry.acceptPublisher();

        assertEq(registry.publisher(), successor);
        assertEq(registry.pendingPublisher(), address(0));

        // Roles have swapped.
        vm.prank(successor);
        registry.submitCheckpoint(2, RFC6962.root(_leaves(4)), 4);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPublisher.selector, publisher));
        registry.submitCheckpoint(3, RFC6962.root(_leaves(6)), 6);
    }

    function test_revert_transferCannotBeSkipped() public {
        // Nobody can accept when nothing is pending.
        vm.prank(successor);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPendingPublisher.selector, successor));
        registry.acceptPublisher();

        vm.prank(publisher);
        registry.proposePublisher(successor);

        // A third party cannot accept somebody else's proposal.
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPendingPublisher.selector, outsider));
        registry.acceptPublisher();

        // And the incumbent cannot self-accept to force the handover through.
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPendingPublisher.selector, publisher));
        registry.acceptPublisher();

        assertEq(registry.publisher(), publisher);
    }

    function test_revert_proposeByNonPublisher() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPublisher.selector, outsider));
        registry.proposePublisher(outsider);
    }

    function test_revert_proposeZeroAddress() public {
        vm.prank(publisher);
        vm.expectRevert(CheckpointRegistry.ZeroAddress.selector);
        registry.proposePublisher(address(0));
    }

    function test_cancelPublisherTransfer() public {
        vm.prank(publisher);
        registry.proposePublisher(successor);

        vm.prank(publisher);
        vm.expectEmit(true, true, true, true);
        emit CheckpointRegistry.PublisherTransferCancelled(publisher, successor);
        registry.cancelPublisherTransfer();

        assertEq(registry.pendingPublisher(), address(0));

        vm.prank(successor);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPendingPublisher.selector, successor));
        registry.acceptPublisher();
    }

    function test_revert_cancelWithNothingPending() public {
        vm.prank(publisher);
        vm.expectRevert(CheckpointRegistry.NoPendingTransfer.selector);
        registry.cancelPublisherTransfer();
    }

    function test_proposalCanBeReplaced() public {
        vm.prank(publisher);
        registry.proposePublisher(outsider);
        vm.prank(publisher);
        registry.proposePublisher(successor);

        assertEq(registry.pendingPublisher(), successor);

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CheckpointRegistry.NotPendingPublisher.selector, outsider));
        registry.acceptPublisher();
    }
}
