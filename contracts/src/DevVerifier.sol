// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title DevVerifier
/// @notice A mock attestation verifier that accepts all attestations.
///         Use ONLY for local development and testing.
///         NEVER deploy this alongside a production AgentRegistry.
contract DevVerifier {
    /// @notice Always returns true — every attestation is considered valid.
    /// @param teePublicKey The public key generated inside the TEE (ignored).
    /// @param attestationQuote The TEE attestation quote (ignored).
    /// @return true Always.
    function verify(
        bytes calldata teePublicKey,
        bytes calldata attestationQuote
    ) external pure returns (bool) {
        return true;
    }
}
