// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title RemediationApproval
/// @notice EIP-712 typed-data authorisation for high-disruption faultline remediations.
///
/// # Why a tool that finds privilege escalation must not be one
///
/// faultline can revoke credentials, strip group memberships and disable accounts. That is
/// domain-admin-equivalent power reachable through an HTTP API. An attacker who compromises the
/// faultline server without this contract in the path gets mass account disable as an
/// enterprise-wide denial of service, and gets it from the one system the security team trusts
/// to tell them where their privilege-escalation paths are.
///
/// So high-disruption fixes require a signature from a key the faultline server never holds.
/// The server can propose a fix, simulate it, and present it for review; it cannot authorise it.
/// Compromising the server is then not sufficient to execute a destructive change.
///
/// # Every field in the signed struct is load-bearing
///
/// - `fixId`           — which recommendation. Maps to `recommendation.id` in MySQL.
/// - `targetNodeHash`  — which node or edge the mutation lands on. Hashed rather than named so
///                       that identity-graph identifiers do not end up in public calldata. The
///                       guess-and-confirm caveat that motivates salting the audit leaves
///                       applies here too: an observer holding a candidate list of node ids can
///                       test them against this hash. We accept that, because the signer must be
///                       able to reproduce the hash from the fix record alone in order to check
///                       what they are signing, and a salt would have to travel with the
///                       approval anyway. The tradeoff is deliberate, not an oversight.
/// - `graphStateRoot`  — the graph version the fix was reviewed against. Without it, an approval
///                       reviewed against yesterday's graph applies to today's, and "remove this
///                       group membership" can mean something entirely different once the
///                       membership set has changed underneath it.
/// - `simulationHash`  — the predicted outcome that was shown to the signer. Without it, a signer
///                       can be shown one simulation and a different change applied. That is not
///                       a hypothetical: it is the shape of the large multisig incidents of
///                       recent years, where the signing device displayed something other than
///                       what the transaction did.
/// - `disruptionTier`  — how much collateral the fix causes, which selects the signature
///                       threshold below.
/// - `validAfter` /
///   `validUntil`      — the window in which the approval is usable. Without it an approval is a
///                       permanent bearer token for a destructive action.
/// - `nonce`           — single use, scoped per signer. Without it an approval replays.
///
/// The EIP-712 domain separator additionally binds every signature to this contract address and
/// this chain id, so an approval collected on a testnet deployment cannot be replayed against a
/// mainnet one, and vice versa.
///
/// # What this contract does not check
///
/// Freshness. It cannot: it has no way to know the current graph state root, and giving it an
/// owner-settable "current root" would reintroduce exactly the server trust the contract exists
/// to remove. Binding is on-chain, freshness is checked by the party that already knows the
/// current root — the applier compares `graphStateRoot` against the live graph version before
/// executing, and refuses if they differ. The contract's job is to make the binding
/// unforgeable, not to be the source of truth for what the graph currently looks like.
///
/// # Signature hygiene
///
/// Recovery goes through OpenZeppelin's `ECDSA`, which rejects `s` values in the upper half of
/// the curve order. Both `(r, s, v)` and `(r, n - s, v ^ 1)` recover the same address, so
/// without that rule every signature has a twin with a different hash — enough to defeat any
/// replay guard keyed on the signature bytes, and enough to produce two distinct database rows
/// for one authorisation. We surface the failure as `MalleableSignature` rather than a generic
/// error so that the reason is visible in a revert trace.
contract RemediationApproval is EIP712, Ownable2Step {
    /// @dev Mirrors the signed columns of `remediation_approval` in MySQL. Field order here is
    ///      the EIP-712 encoding order and must not be changed without changing the typehash,
    ///      the Python signer and every stored signature.
    struct FixApproval {
        uint256 fixId;
        bytes32 targetNodeHash;
        bytes32 graphStateRoot;
        bytes32 simulationHash;
        uint8 disruptionTier;
        uint64 validAfter;
        uint64 validUntil;
        uint256 nonce;
    }

    /// @notice EIP-712 struct typehash. Reproduce this exactly on the signing side.
    bytes32 public constant FIX_APPROVAL_TYPEHASH = keccak256(
        "FixApproval(uint256 fixId,bytes32 targetNodeHash,bytes32 graphStateRoot,bytes32 simulationHash,uint8 disruptionTier,uint64 validAfter,uint64 validUntil,uint256 nonce)"
    );

    /// @notice Addresses whose signatures count towards a threshold.
    mapping(address => bool) public isApprover;

    /// @notice Number of registered approvers.
    uint256 public approverCount;

    /// @notice Distinct approver signatures required for a given disruption tier.
    /// @dev Zero means the tier is not configured, and an approval carrying it is rejected. That
    ///      is intentional: an unconfigured tier must fail closed, or an attacker picks tier 200
    ///      and walks past the threshold check entirely.
    mapping(uint8 => uint8) public tierThreshold;

    /// @notice Per-signer nonce consumption. Mirrors `uq_approval_nonce (signer_address, nonce)`.
    mapping(address => mapping(uint256 => bool)) public nonceUsed;

    /// @notice Whether an approval digest has reached its threshold and been spent.
    mapping(bytes32 => bool) public isConsumed;

    uint8[] private _configuredTiers;
    mapping(bytes32 => address[]) private _collectedSigners;
    mapping(bytes32 => mapping(address => bool)) private _hasSigned;

    event ApproverAdded(address indexed approver);
    event ApproverRemoved(address indexed approver);
    event TierThresholdSet(uint8 indexed disruptionTier, uint8 threshold);
    event SignatureCollected(
        bytes32 indexed digest, uint256 indexed fixId, address indexed signer, uint256 collected, uint256 required
    );
    event ApprovalConsumed(bytes32 indexed digest, uint256 indexed fixId, uint8 disruptionTier, address[] signers);

    error ZeroAddress();
    error InvalidSignature();
    error InvalidSignatureLength(uint256 length);
    error MalleableSignature(bytes32 s);
    error NotAnApprover(address signer);
    error AlreadyAnApprover(address approver);
    error DuplicateSigner(address signer);
    error NonceAlreadyUsed(address signer, uint256 nonce);
    error AlreadyConsumed(bytes32 digest);
    error NotYetValid(uint64 validAfter, uint64 nowTimestamp);
    error Expired(uint64 validUntil, uint64 nowTimestamp);
    error InvalidWindow(uint64 validAfter, uint64 validUntil);
    error TierNotConfigured(uint8 disruptionTier);
    error ThresholdNotMet(uint256 required, uint256 collected);
    error ThresholdExceedsApprovers(uint8 threshold, uint256 approvers);
    error ThresholdUnsatisfiable(uint8 disruptionTier, uint8 threshold, uint256 approvers);
    error NoSignatures();
    error LengthMismatch();

    /// @param initialOwner      Administers the approver registry and the tier thresholds. This is
    ///                          a custody role, not an approval role: the owner cannot authorise a
    ///                          fix unless it is also a registered approver holding a signing key.
    /// @param initialApprovers  Addresses whose signatures count. Keys held off the faultline host.
    /// @param tiers             Disruption tiers to configure.
    /// @param thresholds        Required distinct signatures per tier, index-aligned with `tiers`.
    constructor(
        address initialOwner,
        address[] memory initialApprovers,
        uint8[] memory tiers,
        uint8[] memory thresholds
    ) EIP712("faultline", "1") Ownable(initialOwner) {
        if (tiers.length != thresholds.length) revert LengthMismatch();

        for (uint256 i = 0; i < initialApprovers.length; ++i) {
            _addApprover(initialApprovers[i]);
        }
        for (uint256 i = 0; i < tiers.length; ++i) {
            _setTierThreshold(tiers[i], thresholds[i]);
        }
    }

    // -------------------------------------------------------------------------------------
    // Digest construction
    // -------------------------------------------------------------------------------------

    /// @notice EIP-712 digest for an approval, i.e. what a signer's wallet actually signs.
    function hashApproval(FixApproval calldata approval) public view returns (bytes32) {
        return _hashTypedDataV4(_structHash(approval));
    }

    /// @notice The EIP-712 domain separator for this deployment.
    /// @dev Stored per approval in `remediation_approval` so a verifier can reconstruct the digest
    ///      exactly, including after a redeployment changes the verifying contract address.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _structHash(FixApproval calldata approval) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                FIX_APPROVAL_TYPEHASH,
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
    }

    // -------------------------------------------------------------------------------------
    // Verification
    // -------------------------------------------------------------------------------------

    /// @notice Recover the address that signed `approval`.
    /// @dev Read-only and stateless: it says who signed, not whether the signature may be acted
    ///      on. It deliberately does not check the validity window, the approver registry or the
    ///      nonce, so that the API can show "signed by 0xabc..., expired 40 minutes ago" instead
    ///      of a bare failure. Authorisation is `consumeApproval`.
    function verifyApproval(FixApproval calldata approval, bytes calldata signature)
        public
        view
        returns (address signer)
    {
        return _recover(hashApproval(approval), signature);
    }

    /// @notice Digest, progress and status for an approval.
    function approvalStatus(FixApproval calldata approval)
        external
        view
        returns (bytes32 digest, uint256 collected, uint256 required, bool consumed)
    {
        digest = hashApproval(approval);
        return (digest, _collectedSigners[digest].length, tierThreshold[approval.disruptionTier], isConsumed[digest]);
    }

    /// @notice Signers who have contributed a signature towards a given approval digest.
    function collectedSigners(bytes32 digest) external view returns (address[] memory) {
        return _collectedSigners[digest];
    }

    /// @notice Disruption tiers with a non-zero threshold configured.
    function configuredTiers() external view returns (uint8[] memory) {
        return _configuredTiers;
    }

    function _recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        (address recovered, ECDSA.RecoverError err, bytes32 errArg) = ECDSA.tryRecover(digest, signature);
        if (err == ECDSA.RecoverError.InvalidSignatureS) revert MalleableSignature(errArg);
        if (err == ECDSA.RecoverError.InvalidSignatureLength) revert InvalidSignatureLength(uint256(errArg));
        if (err != ECDSA.RecoverError.NoError) revert InvalidSignature();
        return recovered;
    }

    // -------------------------------------------------------------------------------------
    // Consumption
    // -------------------------------------------------------------------------------------

    /// @notice Spend an approval atomically, supplying every signature at once.
    /// @dev All-or-nothing: if the tier's threshold is not reached by the end of the call, the
    ///      whole transaction reverts and no nonce is burned. Use `collectSignature` when
    ///      approvers sign at different times.
    /// @return signers The distinct approvers whose signatures spent this approval.
    function consumeApproval(FixApproval calldata approval, bytes[] calldata signatures)
        external
        returns (address[] memory signers)
    {
        if (signatures.length == 0) revert NoSignatures();

        bytes32 digest = _validateWindowAndTier(approval);
        for (uint256 i = 0; i < signatures.length; ++i) {
            _collect(approval, digest, signatures[i]);
        }

        uint256 required = tierThreshold[approval.disruptionTier];
        if (!isConsumed[digest]) revert ThresholdNotMet(required, _collectedSigners[digest].length);

        return _collectedSigners[digest];
    }

    /// @notice Contribute one signature towards an approval, spending it once the tier's
    ///         threshold is reached.
    /// @dev The incremental path, for tier 3 fixes where approvers sign from separate machines at
    ///      separate times. A signature is spent the moment it is submitted — the signer's nonce
    ///      is burned here rather than at finalisation — so the same signer's nonce cannot be
    ///      parked against two competing approvals waiting to be completed.
    /// @return collected Signatures gathered for this digest so far.
    /// @return required  Signatures the tier requires.
    function collectSignature(FixApproval calldata approval, bytes calldata signature)
        external
        returns (uint256 collected, uint256 required)
    {
        bytes32 digest = _validateWindowAndTier(approval);
        _collect(approval, digest, signature);
        return (_collectedSigners[digest].length, tierThreshold[approval.disruptionTier]);
    }

    function _validateWindowAndTier(FixApproval calldata approval) internal view returns (bytes32 digest) {
        if (tierThreshold[approval.disruptionTier] == 0) revert TierNotConfigured(approval.disruptionTier);
        if (approval.validAfter > approval.validUntil) revert InvalidWindow(approval.validAfter, approval.validUntil);

        uint64 nowTimestamp = uint64(block.timestamp);
        if (nowTimestamp < approval.validAfter) revert NotYetValid(approval.validAfter, nowTimestamp);
        if (nowTimestamp > approval.validUntil) revert Expired(approval.validUntil, nowTimestamp);

        return hashApproval(approval);
    }

    function _collect(FixApproval calldata approval, bytes32 digest, bytes calldata signature)
        internal
        returns (address signer)
    {
        if (isConsumed[digest]) revert AlreadyConsumed(digest);

        signer = _recover(digest, signature);
        if (!isApprover[signer]) revert NotAnApprover(signer);
        if (_hasSigned[digest][signer]) revert DuplicateSigner(signer);
        if (nonceUsed[signer][approval.nonce]) revert NonceAlreadyUsed(signer, approval.nonce);

        _hasSigned[digest][signer] = true;
        nonceUsed[signer][approval.nonce] = true;
        _collectedSigners[digest].push(signer);

        uint256 collected = _collectedSigners[digest].length;
        uint256 required = tierThreshold[approval.disruptionTier];
        emit SignatureCollected(digest, approval.fixId, signer, collected, required);

        if (collected >= required) {
            isConsumed[digest] = true;
            address[] memory signers = _collectedSigners[digest];
            emit ApprovalConsumed(digest, approval.fixId, approval.disruptionTier, signers);
        }
    }

    // -------------------------------------------------------------------------------------
    // Administration
    // -------------------------------------------------------------------------------------

    /// @notice Register an approver.
    function addApprover(address approver) external onlyOwner {
        _addApprover(approver);
    }

    /// @notice Deregister an approver.
    /// @dev Refuses if the removal would leave a configured tier with fewer approvers than its
    ///      threshold. A threshold nobody can reach is not a stricter policy, it is an outage:
    ///      every tier-3 fix becomes unappliable and the operator's only recourse is to lower the
    ///      threshold under pressure, which is the moment such decisions are made worst.
    function removeApprover(address approver) external onlyOwner {
        if (!isApprover[approver]) revert NotAnApprover(approver);

        uint256 remaining = approverCount - 1;
        for (uint256 i = 0; i < _configuredTiers.length; ++i) {
            uint8 tier = _configuredTiers[i];
            uint8 threshold = tierThreshold[tier];
            if (threshold > remaining) revert ThresholdUnsatisfiable(tier, threshold, remaining);
        }

        isApprover[approver] = false;
        approverCount = remaining;
        emit ApproverRemoved(approver);
    }

    /// @notice Set the number of distinct approver signatures a disruption tier requires.
    /// @dev A threshold of zero unconfigures the tier, which makes approvals carrying it
    ///      unusable rather than free.
    function setTierThreshold(uint8 disruptionTier, uint8 threshold) external onlyOwner {
        _setTierThreshold(disruptionTier, threshold);
    }

    function _addApprover(address approver) private {
        if (approver == address(0)) revert ZeroAddress();
        if (isApprover[approver]) revert AlreadyAnApprover(approver);

        isApprover[approver] = true;
        approverCount += 1;
        emit ApproverAdded(approver);
    }

    function _setTierThreshold(uint8 disruptionTier, uint8 threshold) private {
        if (threshold > approverCount) revert ThresholdExceedsApprovers(threshold, approverCount);

        uint8 previous = tierThreshold[disruptionTier];
        tierThreshold[disruptionTier] = threshold;

        if (previous == 0 && threshold != 0) {
            _configuredTiers.push(disruptionTier);
        } else if (previous != 0 && threshold == 0) {
            _removeConfiguredTier(disruptionTier);
        }

        emit TierThresholdSet(disruptionTier, threshold);
    }

    function _removeConfiguredTier(uint8 disruptionTier) private {
        uint256 length = _configuredTiers.length;
        for (uint256 i = 0; i < length; ++i) {
            if (_configuredTiers[i] == disruptionTier) {
                _configuredTiers[i] = _configuredTiers[length - 1];
                _configuredTiers.pop();
                return;
            }
        }
    }
}
