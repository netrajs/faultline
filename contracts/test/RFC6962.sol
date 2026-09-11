// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RFC6962
/// @notice Test-only reference implementation of the RFC 6962 Merkle tree head and inclusion path.
///
/// This exists so the tests have something independent to check `CheckpointRegistry` against.
/// The registry implements the *iterative* verification algorithm from RFC 6962-bis section
/// 2.1.3.2, which walks a proof upwards tracking two indices. This library implements the
/// *recursive* definitions MTH and PATH from RFC 6962 section 2.1 directly, splitting each
/// subtree at the largest power of two strictly below its size. They are different algorithms
/// derived from different halves of the specification, so agreement between them is evidence,
/// not tautology. Checking a verifier against a prover that shares its code proves only that
/// the code is self-consistent — the same mistake the on-chain anchoring exists to correct.
///
/// Deliberately naive: recursion, repeated subtree recomputation, array copies. It runs only in
/// the test VM over trees of a few dozen leaves.
library RFC6962 {
    /// @notice `MTH({}) = SHA-256()`, `MTH({d}) = SHA-256(0x00 || d)`, and for n > 1
    ///         `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` with k the largest
    ///         power of two strictly less than n.
    /// @param leaves Already-hashed leaves, i.e. the output of `leafHash`.
    function root(bytes32[] memory leaves) internal pure returns (bytes32) {
        return _mth(leaves, 0, leaves.length);
    }

    /// @notice RFC 6962 PATH(m, D[n]): the audit path for leaf `index`, bottom-up.
    function proof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory) {
        return _path(leaves, 0, leaves.length, index);
    }

    /// @notice `sha256(0x00 || leafData)`. `leafData` is the salted canonical entry.
    function leafHash(bytes memory leafData) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x00), leafData));
    }

    /// @notice `sha256(0x01 || left || right)`.
    function nodeHash(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function _mth(bytes32[] memory leaves, uint256 lo, uint256 hi) private pure returns (bytes32) {
        uint256 n = hi - lo;
        if (n == 0) {
            bytes memory empty;
            return sha256(empty);
        }
        if (n == 1) {
            return leaves[lo];
        }
        uint256 k = _split(n);
        return nodeHash(_mth(leaves, lo, lo + k), _mth(leaves, lo + k, hi));
    }

    function _path(bytes32[] memory leaves, uint256 lo, uint256 hi, uint256 m)
        private
        pure
        returns (bytes32[] memory)
    {
        uint256 n = hi - lo;
        if (n == 1) {
            return new bytes32[](0);
        }
        uint256 k = _split(n);
        if (m < k) {
            return _append(_path(leaves, lo, lo + k, m), _mth(leaves, lo + k, hi));
        }
        return _append(_path(leaves, lo + k, hi, m - k), _mth(leaves, lo, lo + k));
    }

    /// @dev Largest power of two strictly less than `n`, for `n >= 2`.
    function _split(uint256 n) private pure returns (uint256 k) {
        k = 1;
        while (k * 2 < n) {
            k *= 2;
        }
    }

    function _append(bytes32[] memory arr, bytes32 value) private pure returns (bytes32[] memory out) {
        out = new bytes32[](arr.length + 1);
        for (uint256 i = 0; i < arr.length; ++i) {
            out[i] = arr[i];
        }
        out[arr.length] = value;
    }
}
