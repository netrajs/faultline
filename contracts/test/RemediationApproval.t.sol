// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {RemediationApproval} from "../src/RemediationApproval.sol";

contract RemediationApprovalTest is Test {
    RemediationApproval internal approvals;

    address internal owner;
    address internal alice;
    address internal bob;
    address internal carol;
    address internal mallory;

    uint256 internal alicePk;
    uint256 internal bobPk;
    uint256 internal carolPk;
    uint256 internal malloryPk;

    /// @dev Order of the secp256k1 group. A signature with `s` above N/2 is the malleable twin
    ///      of a canonical one and must be rejected.
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 internal constant GRAPH_ROOT = keccak256("graph-version-41");
    bytes32 internal constant OTHER_GRAPH_ROOT = keccak256("graph-version-42");

    uint8 internal constant TIER_LOW = 1;
    uint8 internal constant TIER_MEDIUM = 2;
    uint8 internal constant TIER_HIGH = 3;

    function setUp() public {
        vm.warp(1_700_000_000);

        owner = address(this);
        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        (carol, carolPk) = makeAddrAndKey("carol");
        (mallory, malloryPk) = makeAddrAndKey("mallory");

        address[] memory initialApprovers = new address[](3);
        initialApprovers[0] = alice;
        initialApprovers[1] = bob;
        initialApprovers[2] = carol;

        uint8[] memory tiers = new uint8[](3);
        tiers[0] = TIER_LOW;
        tiers[1] = TIER_MEDIUM;
        tiers[2] = TIER_HIGH;

        uint8[] memory thresholds = new uint8[](3);
        thresholds[0] = 1;
        thresholds[1] = 1;
        thresholds[2] = 2;

        approvals = new RemediationApproval(owner, initialApprovers, tiers, thresholds);
    }

    // -------------------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------------------

    function _approvalWith(
        uint256 fixId,
        uint8 tier,
        uint256 nonce,
        bytes32 graphStateRoot,
        bytes32 simulationHash,
        uint64 validAfter,
        uint64 validUntil
    ) internal pure returns (RemediationApproval.FixApproval memory) {
        return RemediationApproval.FixApproval({
            fixId: fixId,
            targetNodeHash: keccak256(abi.encodePacked("node", fixId)),
            graphStateRoot: graphStateRoot,
            simulationHash: simulationHash,
            disruptionTier: tier,
            validAfter: validAfter,
            validUntil: validUntil,
            nonce: nonce
        });
    }

    function _approval(uint256 fixId, uint8 tier, uint256 nonce)
        internal
        view
        returns (RemediationApproval.FixApproval memory)
    {
        return _approvalWith(
            fixId,
            tier,
            nonce,
            GRAPH_ROOT,
            keccak256(abi.encodePacked("simulation", fixId)),
            uint64(block.timestamp - 60),
            uint64(block.timestamp + 3600)
        );
    }

    function _sign(uint256 pk, RemediationApproval.FixApproval memory approval) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, approvals.hashApproval(approval));
        return abi.encodePacked(r, s, v);
    }

    function _one(bytes memory a) internal pure returns (bytes[] memory out) {
        out = new bytes[](1);
        out[0] = a;
    }

    function _two(bytes memory a, bytes memory b) internal pure returns (bytes[] memory out) {
        out = new bytes[](2);
        out[0] = a;
        out[1] = b;
    }

    // -------------------------------------------------------------------------------------
    // Typed-data construction
    // -------------------------------------------------------------------------------------

    /// @dev Rebuilds the EIP-712 digest by hand from the specification rather than from the
    ///      contract's own helpers. This is the contract the Python signer has to satisfy: if
    ///      this test drifts, `web3.py`'s `sign_typed_data` will produce signatures the chain
    ///      rejects, and the failure would otherwise only show up at demo time.
    function test_hashApproval_matchesManualEIP712Construction() public view {
        bytes32 typeHash = keccak256(
            "FixApproval(uint256 fixId,bytes32 targetNodeHash,bytes32 graphStateRoot,bytes32 simulationHash,uint8 disruptionTier,uint64 validAfter,uint64 validUntil,uint256 nonce)"
        );
        assertEq(approvals.FIX_APPROVAL_TYPEHASH(), typeHash, "typehash drifted");

        bytes32 expectedDomain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("faultline")),
                keccak256(bytes("1")),
                block.chainid,
                address(approvals)
            )
        );
        assertEq(approvals.domainSeparator(), expectedDomain, "domain separator drifted");

        RemediationApproval.FixApproval memory approval = _approval(101, TIER_LOW, 1);
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                approval.fixId,
                approval.targetNodeHash,
                approval.graphStateRoot,
                approval.simulationHash,
                approval.disruptionTier,
                approval.validAfter,
                approval.validUntil,
                approval.nonce
            )
        );
        bytes32 expectedDigest = keccak256(abi.encodePacked(hex"1901", expectedDomain, structHash));
        assertEq(approvals.hashApproval(approval), expectedDigest);
    }

    function test_eip712DomainIsReadableOnChain() public view {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            approvals.eip712Domain();
        assertEq(name, "faultline");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(approvals));
    }

    // -------------------------------------------------------------------------------------
    // Verification
    // -------------------------------------------------------------------------------------

    function test_verifyApproval_recoversTheExpectedSigner() public view {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        assertEq(approvals.verifyApproval(approval, _sign(alicePk, approval)), alice);
        assertEq(approvals.verifyApproval(approval, _sign(bobPk, approval)), bob);
    }

    /// @dev The binding that stops an approval reviewed against one graph version being applied
    ///      to another.
    function test_verifyApproval_differentGraphStateRootDoesNotVerify() public {
        RemediationApproval.FixApproval memory reviewed = _approval(7, TIER_LOW, 1);
        bytes memory signature = _sign(alicePk, reviewed);

        RemediationApproval.FixApproval memory substituted = _approvalWith(
            7,
            TIER_LOW,
            1,
            OTHER_GRAPH_ROOT,
            reviewed.simulationHash,
            reviewed.validAfter,
            reviewed.validUntil
        );

        address recovered = approvals.verifyApproval(substituted, signature);
        assertTrue(recovered != alice, "signature verified against a different graph state root");

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.NotAnApprover.selector, recovered));
        approvals.consumeApproval(substituted, _one(signature));
    }

    /// @dev The binding that stops a signer being shown one simulated outcome and a different
    ///      change being applied.
    function test_verifyApproval_differentSimulationHashDoesNotVerify() public {
        RemediationApproval.FixApproval memory reviewed = _approval(8, TIER_LOW, 1);
        bytes memory signature = _sign(alicePk, reviewed);

        RemediationApproval.FixApproval memory substituted = _approvalWith(
            8, TIER_LOW, 1, GRAPH_ROOT, keccak256("a different outcome"), reviewed.validAfter, reviewed.validUntil
        );

        assertTrue(approvals.verifyApproval(substituted, signature) != alice);
    }

    function test_verifyApproval_differentTargetDoesNotVerify() public view {
        RemediationApproval.FixApproval memory reviewed = _approval(9, TIER_LOW, 1);
        bytes memory signature = _sign(alicePk, reviewed);

        RemediationApproval.FixApproval memory substituted = _approvalWith(
            10, TIER_LOW, 1, GRAPH_ROOT, reviewed.simulationHash, reviewed.validAfter, reviewed.validUntil
        );
        assertTrue(approvals.verifyApproval(substituted, signature) != alice);
    }

    function test_domainSeparatorBindsTheChainId() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes32 before = approvals.hashApproval(approval);

        vm.chainId(999);
        assertTrue(approvals.hashApproval(approval) != before, "digest is not bound to the chain id");
    }

    function test_domainSeparatorBindsTheVerifyingContract() public {
        address[] memory initialApprovers = new address[](1);
        initialApprovers[0] = alice;
        uint8[] memory tiers = new uint8[](1);
        tiers[0] = TIER_LOW;
        uint8[] memory thresholds = new uint8[](1);
        thresholds[0] = 1;

        RemediationApproval second = new RemediationApproval(owner, initialApprovers, tiers, thresholds);

        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes memory signature = _sign(alicePk, approval);

        assertTrue(second.hashApproval(approval) != approvals.hashApproval(approval));
        assertEq(approvals.verifyApproval(approval, signature), alice);
        assertTrue(second.verifyApproval(approval, signature) != alice, "signature replayed to another deployment");
    }

    // -------------------------------------------------------------------------------------
    // Signature hygiene
    // -------------------------------------------------------------------------------------

    function test_revert_upperHalfOrderSignatureRejected() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes32 digest = approvals.hashApproval(approval);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);

        bytes32 flippedS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;

        // The twin is a genuinely valid signature for the same signer, which is exactly why it
        // has to be rejected rather than merely discouraged.
        assertEq(ecrecover(digest, flippedV, r, flippedS), alice, "the malleable twin should recover the same signer");

        bytes memory malleable = abi.encodePacked(r, flippedS, flippedV);
        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.MalleableSignature.selector, flippedS));
        approvals.verifyApproval(approval, malleable);
    }

    function test_revert_wrongSignatureLength() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes memory truncated = new bytes(64);

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.InvalidSignatureLength.selector, uint256(64)));
        approvals.verifyApproval(approval, truncated);
    }

    function test_revert_unrecoverableSignature() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        (, bytes32 r, bytes32 s) = vm.sign(alicePk, approvals.hashApproval(approval));

        // v outside {27, 28} makes ecrecover return the zero address.
        bytes memory broken = abi.encodePacked(r, s, uint8(1));
        vm.expectRevert(RemediationApproval.InvalidSignature.selector);
        approvals.verifyApproval(approval, broken);
    }

    // -------------------------------------------------------------------------------------
    // Consumption
    // -------------------------------------------------------------------------------------

    function test_consumeApproval_singleApproverTier() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 11);
        bytes memory signature = _sign(alicePk, approval);
        bytes32 digest = approvals.hashApproval(approval);

        assertFalse(approvals.nonceUsed(alice, 11));
        assertFalse(approvals.isConsumed(digest));

        address[] memory signers = approvals.consumeApproval(approval, _one(signature));

        assertEq(signers.length, 1);
        assertEq(signers[0], alice);
        assertTrue(approvals.nonceUsed(alice, 11));
        assertTrue(approvals.isConsumed(digest));
    }

    function test_revert_replayOfAConsumedApproval() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 11);
        bytes memory signature = _sign(alicePk, approval);
        approvals.consumeApproval(approval, _one(signature));

        vm.expectRevert(
            abi.encodeWithSelector(RemediationApproval.AlreadyConsumed.selector, approvals.hashApproval(approval))
        );
        approvals.consumeApproval(approval, _one(signature));
    }

    /// @dev The nonce is scoped to the signer, not to the approval, so it also blocks a second
    ///      approval that a signer happened to number the same way.
    function test_revert_nonceReuseAcrossDifferentApprovals() public {
        RemediationApproval.FixApproval memory first = _approval(1, TIER_LOW, 11);
        approvals.consumeApproval(first, _one(_sign(alicePk, first)));

        RemediationApproval.FixApproval memory second = _approval(2, TIER_LOW, 11);
        bytes memory signature = _sign(alicePk, second);

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.NonceAlreadyUsed.selector, alice, uint256(11)));
        approvals.consumeApproval(second, _one(signature));
    }

    function test_nonceIsScopedPerSigner() public {
        RemediationApproval.FixApproval memory first = _approval(1, TIER_LOW, 11);
        approvals.consumeApproval(first, _one(_sign(alicePk, first)));

        // Bob's nonce 11 is untouched.
        RemediationApproval.FixApproval memory second = _approval(2, TIER_LOW, 11);
        approvals.consumeApproval(second, _one(_sign(bobPk, second)));

        assertTrue(approvals.nonceUsed(alice, 11));
        assertTrue(approvals.nonceUsed(bob, 11));
    }

    function test_revert_expiredApproval() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes memory signature = _sign(alicePk, approval);

        vm.warp(uint256(approval.validUntil) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RemediationApproval.Expired.selector, approval.validUntil, uint64(block.timestamp)
            )
        );
        approvals.consumeApproval(approval, _one(signature));
    }

    function test_approvalIsUsableOnTheFinalSecondOfItsWindow() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes memory signature = _sign(alicePk, approval);

        vm.warp(uint256(approval.validUntil));
        approvals.consumeApproval(approval, _one(signature));
        assertTrue(approvals.isConsumed(approvals.hashApproval(approval)));
    }

    function test_revert_notYetValidApproval() public {
        RemediationApproval.FixApproval memory approval = _approvalWith(
            1,
            TIER_LOW,
            1,
            GRAPH_ROOT,
            keccak256("sim"),
            uint64(block.timestamp + 3600),
            uint64(block.timestamp + 7200)
        );
        bytes memory signature = _sign(alicePk, approval);

        vm.expectRevert(
            abi.encodeWithSelector(
                RemediationApproval.NotYetValid.selector, approval.validAfter, uint64(block.timestamp)
            )
        );
        approvals.consumeApproval(approval, _one(signature));
    }

    function test_revert_invertedValidityWindow() public {
        RemediationApproval.FixApproval memory approval = _approvalWith(
            1,
            TIER_LOW,
            1,
            GRAPH_ROOT,
            keccak256("sim"),
            uint64(block.timestamp + 7200),
            uint64(block.timestamp + 3600)
        );
        bytes memory signature = _sign(alicePk, approval);

        vm.expectRevert(
            abi.encodeWithSelector(
                RemediationApproval.InvalidWindow.selector, approval.validAfter, approval.validUntil
            )
        );
        approvals.consumeApproval(approval, _one(signature));
    }

    function test_revert_signerIsNotAnApprover() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes memory signature = _sign(malloryPk, approval);

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.NotAnApprover.selector, mallory));
        approvals.consumeApproval(approval, _one(signature));
    }

    function test_revert_removedApproverCanNoLongerAuthorise() public {
        approvals.removeApprover(carol);

        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.NotAnApprover.selector, carol));
        approvals.consumeApproval(approval, _one(_sign(carolPk, approval)));
    }

    /// @dev An unconfigured tier must fail closed. If it did not, an attacker would simply put
    ///      an unused tier number in the struct and walk past the threshold check.
    function test_revert_unconfiguredTierFailsClosed() public {
        RemediationApproval.FixApproval memory approval = _approval(1, 200, 1);
        bytes memory signature = _sign(alicePk, approval);

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.TierNotConfigured.selector, uint8(200)));
        approvals.consumeApproval(approval, _one(signature));

        // Tier 0 is deliberately not configured either: fixes below the approval bar are applied
        // without one, they do not get a free pass through this contract.
        RemediationApproval.FixApproval memory tierZero = _approval(2, 0, 2);
        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.TierNotConfigured.selector, uint8(0)));
        approvals.consumeApproval(tierZero, _one(_sign(alicePk, tierZero)));
    }

    function test_revert_noSignatures() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        vm.expectRevert(RemediationApproval.NoSignatures.selector);
        approvals.consumeApproval(approval, new bytes[](0));
    }

    // -------------------------------------------------------------------------------------
    // Multi-signature collection for the highest tier
    // -------------------------------------------------------------------------------------

    function test_tier3_singleSignatureIsNotEnough() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);
        bytes memory signature = _sign(alicePk, approval);

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.ThresholdNotMet.selector, uint256(2), uint256(1)));
        approvals.consumeApproval(approval, _one(signature));

        // The failed attempt is atomic: alice's nonce is untouched.
        assertFalse(approvals.nonceUsed(alice, 21));
    }

    function test_tier3_twoDistinctApproversSucceed() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);
        bytes32 digest = approvals.hashApproval(approval);

        address[] memory signers = approvals.consumeApproval(
            approval, _two(_sign(alicePk, approval), _sign(bobPk, approval))
        );

        assertEq(signers.length, 2);
        assertEq(signers[0], alice);
        assertEq(signers[1], bob);
        assertTrue(approvals.isConsumed(digest));
        assertTrue(approvals.nonceUsed(alice, 21));
        assertTrue(approvals.nonceUsed(bob, 21));
    }

    function test_revert_tier3_sameSignerTwice() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);
        bytes memory signature = _sign(alicePk, approval);

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.DuplicateSigner.selector, alice));
        approvals.consumeApproval(approval, _two(signature, signature));
    }

    function test_tier3_incrementalCollection() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);
        bytes32 digest = approvals.hashApproval(approval);

        (uint256 collected, uint256 required) = approvals.collectSignature(approval, _sign(alicePk, approval));
        assertEq(collected, 1);
        assertEq(required, 2);
        assertFalse(approvals.isConsumed(digest));
        assertTrue(approvals.nonceUsed(alice, 21), "a submitted signature is spent immediately");

        // A different approver, at a later time, from a different machine.
        vm.warp(block.timestamp + 300);
        (collected, required) = approvals.collectSignature(approval, _sign(bobPk, approval));
        assertEq(collected, 2);
        assertTrue(approvals.isConsumed(digest));

        address[] memory signers = approvals.collectedSigners(digest);
        assertEq(signers.length, 2);
        assertEq(signers[0], alice);
        assertEq(signers[1], bob);
    }

    function test_revert_collectingAfterConsumption() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);
        approvals.collectSignature(approval, _sign(alicePk, approval));
        approvals.collectSignature(approval, _sign(bobPk, approval));

        vm.expectRevert(
            abi.encodeWithSelector(RemediationApproval.AlreadyConsumed.selector, approvals.hashApproval(approval))
        );
        approvals.collectSignature(approval, _sign(carolPk, approval));
    }

    function test_revert_collectingTheSameSignerTwice() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);
        approvals.collectSignature(approval, _sign(alicePk, approval));

        // Caught by the nonce first, which is the stricter of the two guards.
        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.NonceAlreadyUsed.selector, alice, uint256(21)));
        approvals.collectSignature(approval, _sign(alicePk, approval));
    }

    function test_revert_partialCollectionExpiresWithTheWindow() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);
        approvals.collectSignature(approval, _sign(alicePk, approval));

        vm.warp(uint256(approval.validUntil) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RemediationApproval.Expired.selector, approval.validUntil, uint64(block.timestamp)
            )
        );
        approvals.collectSignature(approval, _sign(bobPk, approval));

        assertFalse(approvals.isConsumed(approvals.hashApproval(approval)));
    }

    function test_approvalStatusReportsProgress() public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 21);

        (bytes32 digest, uint256 collected, uint256 required, bool consumed) = approvals.approvalStatus(approval);
        assertEq(digest, approvals.hashApproval(approval));
        assertEq(collected, 0);
        assertEq(required, 2);
        assertFalse(consumed);

        approvals.collectSignature(approval, _sign(alicePk, approval));
        (, collected,, consumed) = approvals.approvalStatus(approval);
        assertEq(collected, 1);
        assertFalse(consumed);
    }

    // -------------------------------------------------------------------------------------
    // Administration
    // -------------------------------------------------------------------------------------

    function test_addAndRemoveApprovers() public {
        assertEq(approvals.approverCount(), 3);

        approvals.addApprover(mallory);
        assertTrue(approvals.isApprover(mallory));
        assertEq(approvals.approverCount(), 4);

        approvals.removeApprover(mallory);
        assertFalse(approvals.isApprover(mallory));
        assertEq(approvals.approverCount(), 3);
    }

    function test_revert_addingAnExistingApprover() public {
        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.AlreadyAnApprover.selector, alice));
        approvals.addApprover(alice);
    }

    function test_revert_addingTheZeroAddress() public {
        vm.expectRevert(RemediationApproval.ZeroAddress.selector);
        approvals.addApprover(address(0));
    }

    /// @dev A threshold nobody can reach is an outage, not a stricter policy.
    function test_revert_removalThatWouldStrandATier() public {
        approvals.removeApprover(carol); // 3 -> 2, tier 3 still needs 2. Fine.
        assertEq(approvals.approverCount(), 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                RemediationApproval.ThresholdUnsatisfiable.selector, TIER_HIGH, uint8(2), uint256(1)
            )
        );
        approvals.removeApprover(bob);
    }

    function test_revert_thresholdAboveApproverCount() public {
        vm.expectRevert(
            abi.encodeWithSelector(RemediationApproval.ThresholdExceedsApprovers.selector, uint8(4), uint256(3))
        );
        approvals.setTierThreshold(TIER_HIGH, 4);
    }

    function test_setTierThresholdRaisesTheBar() public {
        approvals.setTierThreshold(TIER_HIGH, 3);

        RemediationApproval.FixApproval memory approval = _approval(1, TIER_HIGH, 31);
        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.ThresholdNotMet.selector, uint256(3), uint256(2)));
        approvals.consumeApproval(approval, _two(_sign(alicePk, approval), _sign(bobPk, approval)));
    }

    function test_unconfiguringATierRemovesItFromTheList() public {
        assertEq(approvals.configuredTiers().length, 3);

        approvals.setTierThreshold(TIER_MEDIUM, 0);
        assertEq(approvals.configuredTiers().length, 2);
        assertEq(approvals.tierThreshold(TIER_MEDIUM), 0);

        RemediationApproval.FixApproval memory approval = _approval(1, TIER_MEDIUM, 41);
        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.TierNotConfigured.selector, TIER_MEDIUM));
        approvals.consumeApproval(approval, _one(_sign(alicePk, approval)));
    }

    function test_revert_administrationRequiresOwnership() public {
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, mallory));
        approvals.addApprover(mallory);

        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, mallory));
        approvals.setTierThreshold(TIER_HIGH, 1);
    }

    function test_ownershipTransferIsTwoStep() public {
        address successor = makeAddr("successor");

        approvals.transferOwnership(successor);
        assertEq(approvals.owner(), owner, "ownership moved before acceptance");
        assertEq(approvals.pendingOwner(), successor);

        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, mallory));
        approvals.acceptOwnership();

        vm.prank(successor);
        approvals.acceptOwnership();
        assertEq(approvals.owner(), successor);
        assertEq(approvals.pendingOwner(), address(0));
    }

    // -------------------------------------------------------------------------------------
    // Fuzz
    // -------------------------------------------------------------------------------------

    function testFuzz_nonceIsSingleUse(uint256 nonce, uint256 fixId) public {
        RemediationApproval.FixApproval memory approval = _approvalWith(
            fixId,
            TIER_LOW,
            nonce,
            GRAPH_ROOT,
            keccak256(abi.encodePacked("simulation", fixId)),
            uint64(block.timestamp - 60),
            uint64(block.timestamp + 3600)
        );
        approvals.consumeApproval(approval, _one(_sign(alicePk, approval)));
        assertTrue(approvals.nonceUsed(alice, nonce));

        vm.expectRevert(
            abi.encodeWithSelector(RemediationApproval.AlreadyConsumed.selector, approvals.hashApproval(approval))
        );
        approvals.consumeApproval(approval, _one(_sign(alicePk, approval)));
    }

    function testFuzz_approvalOutsideItsWindowIsRejected(uint64 offset) public {
        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        bytes memory signature = _sign(alicePk, approval);

        uint256 target = bound(uint256(offset), uint256(approval.validUntil) + 1, uint256(approval.validUntil) + 1e6);
        vm.warp(target);

        vm.expectRevert(
            abi.encodeWithSelector(
                RemediationApproval.Expired.selector, approval.validUntil, uint64(block.timestamp)
            )
        );
        approvals.consumeApproval(approval, _one(signature));
    }

    function testFuzz_onlyRegisteredApproversCanAuthorise(uint256 pkSeed) public {
        uint256 pk = bound(pkSeed, 1, SECP256K1_N - 1);
        address signer = vm.addr(pk);
        vm.assume(!approvals.isApprover(signer));

        RemediationApproval.FixApproval memory approval = _approval(1, TIER_LOW, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, approvals.hashApproval(approval));

        vm.expectRevert(abi.encodeWithSelector(RemediationApproval.NotAnApprover.selector, signer));
        approvals.consumeApproval(approval, _one(abi.encodePacked(r, s, v)));
    }
}
