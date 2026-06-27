// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AgentRegistry
/// @notice Registry for agents running inside TEEs on EigenCloud. Agents
///         register their public keys along with an attestation quote proving
///         they are running inside a valid TEE.
contract AgentRegistry {
    // =========================================================
    //  Types
    // =========================================================

    struct Agent {
        address agentAddress;
        bytes teePublicKey; // Public key generated inside the TEE
        bytes attestationQuote; // EigenCloud TEE attestation quote
        string metadataURI; // Optional: IPFS URI with agent metadata
        uint256 registeredAt;
        bool active;
    }

    // =========================================================
    //  State
    // =========================================================

    /// @notice agent address → Agent
    mapping(address => Agent) public agents;

    /// @notice List of all agent addresses (for enumeration).
    address[] public agentList;

    /// @notice Address of the EigenCloud attestation verifier contract.
    address public attestationVerifier;

    // =========================================================
    //  Events
    // =========================================================

    event AgentRegistered(
        address indexed agent,
        bytes teePublicKey,
        string metadataURI,
        uint256 timestamp
    );

    event AgentDeregistered(address indexed agent, uint256 timestamp);

    event AgentPublicKeyUpdated(
        address indexed agent,
        bytes newPublicKey,
        bytes newAttestationQuote,
        uint256 timestamp
    );

    event AttestationVerifierSet(address indexed verifier, uint256 timestamp);

    // =========================================================
    //  Errors
    // =========================================================

    error AgentRegistry__AlreadyRegistered();
    error AgentRegistry__NotRegistered();
    error AgentRegistry__AgentInactive();
    error AgentRegistry__EmptyPublicKey();
    error AgentRegistry__EmptyAttestation();
    error AgentRegistry__AttestationVerificationFailed();
    error AgentRegistry__AttestationVerifierAlreadySet();
    error AgentRegistry__InvalidAttestationVerifier();

    // =========================================================
    //  Modifiers
    // =========================================================

    modifier onlyRegistered() {
        if (!agents[msg.sender].active) revert AgentRegistry__NotRegistered();
        _;
    }

    // =========================================================
    //  Admin
    // =========================================================

    /// @notice Set the EigenCloud attestation verifier contract. Can only be set once.
    function setAttestationVerifier(address _verifier) external {
        if (attestationVerifier != address(0)) {
            revert AgentRegistry__AttestationVerifierAlreadySet();
        }
        if (_verifier == address(0))
            revert AgentRegistry__InvalidAttestationVerifier();
        attestationVerifier = _verifier;
        emit AttestationVerifierSet(_verifier, block.timestamp);
    }

    // =========================================================
    //  Registration
    // =========================================================

    /// @notice Register as a new agent.
    /// @param teePublicKey The public key generated inside the TEE.
    /// @param attestationQuote The EigenCloud TEE attestation quote.
    /// @param metadataURI Optional URI pointing to agent metadata (e.g. IPFS).
    function register(
        bytes calldata teePublicKey,
        bytes calldata attestationQuote,
        string calldata metadataURI
    ) external {
        if (agents[msg.sender].active)
            revert AgentRegistry__AlreadyRegistered();
        if (teePublicKey.length == 0) revert AgentRegistry__EmptyPublicKey();
        if (attestationQuote.length == 0)
            revert AgentRegistry__EmptyAttestation();

        // Verify the attestation quote against EigenCloud's verifier.
        _verifyAttestation(teePublicKey, attestationQuote);

        // If the agent was previously registered and deactivated, update in place.
        if (agents[msg.sender].agentAddress == address(0)) {
            agentList.push(msg.sender);
        }

        agents[msg.sender] = Agent({
            agentAddress: msg.sender,
            teePublicKey: teePublicKey,
            attestationQuote: attestationQuote,
            metadataURI: metadataURI,
            registeredAt: block.timestamp,
            active: true
        });

        emit AgentRegistered(
            msg.sender,
            teePublicKey,
            metadataURI,
            block.timestamp
        );
    }

    /// @notice Deregister the calling agent.
    function deregister() external onlyRegistered {
        agents[msg.sender].active = false;
        emit AgentDeregistered(msg.sender, block.timestamp);
    }

    /// @notice Update the agent's TEE public key (requires a fresh attestation).
    function updatePublicKey(
        bytes calldata newPublicKey,
        bytes calldata newAttestationQuote
    ) external onlyRegistered {
        if (newPublicKey.length == 0) revert AgentRegistry__EmptyPublicKey();
        if (newAttestationQuote.length == 0)
            revert AgentRegistry__EmptyAttestation();

        _verifyAttestation(newPublicKey, newAttestationQuote);

        Agent storage agent = agents[msg.sender];
        agent.teePublicKey = newPublicKey;
        agent.attestationQuote = newAttestationQuote;

        emit AgentPublicKeyUpdated(
            msg.sender,
            newPublicKey,
            newAttestationQuote,
            block.timestamp
        );
    }

    // =========================================================
    //  Internal
    // =========================================================

    /// @notice Verify the TEE attestation quote. If no attestation verifier is
    ///         set, this is a no-op (useful for local development).
    function _verifyAttestation(
        bytes calldata teePublicKey,
        bytes calldata attestationQuote
    ) internal view {
        if (attestationVerifier == address(0)) {
            return;
        }

        (bool success, bytes memory result) = attestationVerifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes,bytes)",
                teePublicKey,
                attestationQuote
            )
        );

        if (!success || result.length != 32 || !abi.decode(result, (bool))) {
            revert AgentRegistry__AttestationVerificationFailed();
        }
    }

    // =========================================================
    //  View Functions
    // =========================================================

    /// @notice Check if an address is a registered, active agent.
    function isRegistered(address agent) external view returns (bool) {
        return agents[agent].active;
    }

    /// @notice Get full agent info.
    function getAgent(address agent) external view returns (Agent memory) {
        return agents[agent];
    }

    /// @notice Get the TEE public key for an agent.
    function getTeePublicKey(
        address agent
    ) external view returns (bytes memory) {
        return agents[agent].teePublicKey;
    }

    /// @notice Get total number of registered agents (including inactive).
    function getAgentCount() external view returns (uint256) {
        return agentList.length;
    }

    /// @notice Get a paginated list of agent addresses.
    function getAgentList(
        uint256 offset,
        uint256 limit
    ) external view returns (address[] memory result) {
        uint256 total = agentList.length;
        if (offset >= total) return new address[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        result = new address[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = agentList[i];
        }
    }
}
