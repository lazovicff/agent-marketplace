// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {DevVerifier} from "../src/DevVerifier.sol";

contract AgentRegistryTest is Test {
    AgentRegistry public registry;

    bytes public constant PUBKEY =
        hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    bytes public constant ATTESTATION =
        hex"cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
    string public constant METADATA = "ipfs://QmTest";

    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    function setUp() public {
        registry = new AgentRegistry();

        // Deploy and set the DevVerifier so attestation verification
        // is actually exercised during tests.
        DevVerifier devVerifier = new DevVerifier();
        registry.setAttestationVerifier(address(devVerifier));
    }

    // =========================================================
    //  register
    // =========================================================

    function test_Register() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        assertTrue(registry.isRegistered(alice));
        assertEq(registry.getAgentCount(), 1);

        AgentRegistry.Agent memory agent = registry.getAgent(alice);
        assertEq(agent.agentAddress, alice);
        assertEq(agent.teePublicKey, PUBKEY);
        assertEq(agent.attestationQuote, ATTESTATION);
        assertEq(agent.metadataURI, METADATA);
        assertTrue(agent.active);
        assertEq(agent.registeredAt, block.timestamp);
    }

    function test_RegisterMultiple() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(bob);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        assertEq(registry.getAgentCount(), 2);
        assertTrue(registry.isRegistered(alice));
        assertTrue(registry.isRegistered(bob));
    }

    function test_RevertWhen_AlreadyRegistered() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(alice);
        vm.expectRevert(
            AgentRegistry.AgentRegistry__AlreadyRegistered.selector
        );
        registry.register(PUBKEY, ATTESTATION, METADATA);
    }

    function test_RevertWhen_EmptyPublicKey() public {
        vm.prank(alice);
        vm.expectRevert(AgentRegistry.AgentRegistry__EmptyPublicKey.selector);
        registry.register("", ATTESTATION, METADATA);
    }

    function test_RevertWhen_EmptyAttestation() public {
        vm.prank(alice);
        vm.expectRevert(AgentRegistry.AgentRegistry__EmptyAttestation.selector);
        registry.register(PUBKEY, "", METADATA);
    }

    // =========================================================
    //  deregister
    // =========================================================

    function test_Deregister() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(alice);
        registry.deregister();

        assertFalse(registry.isRegistered(alice));

        // Agent struct still exists but inactive
        AgentRegistry.Agent memory agent = registry.getAgent(alice);
        assertFalse(agent.active);
    }

    function test_RevertWhen_NotRegisteredDeregister() public {
        vm.prank(alice);
        vm.expectRevert(AgentRegistry.AgentRegistry__NotRegistered.selector);
        registry.deregister();
    }

    function test_RevertWhen_DeregisterTwice() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(alice);
        registry.deregister();

        vm.prank(alice);
        vm.expectRevert(AgentRegistry.AgentRegistry__NotRegistered.selector);
        registry.deregister();
    }

    // =========================================================
    //  Re-register after deregister
    // =========================================================

    function test_ReRegisterAfterDeregister() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(alice);
        registry.deregister();

        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        assertTrue(registry.isRegistered(alice));
        assertEq(registry.getAgentCount(), 1); // Same slot reused
    }

    // =========================================================
    //  updatePublicKey
    // =========================================================

    function test_UpdatePublicKey() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        bytes
            memory newKey = hex"1111111111111111111111111111111111111111111111111111111111111111";
        bytes
            memory newAttest = hex"2222222222222222222222222222222222222222222222222222222222222222";

        vm.prank(alice);
        registry.updatePublicKey(newKey, newAttest);

        AgentRegistry.Agent memory agent = registry.getAgent(alice);
        assertEq(agent.teePublicKey, newKey);
        assertEq(agent.attestationQuote, newAttest);
    }

    function test_RevertWhen_NotRegisteredUpdateKey() public {
        vm.prank(alice);
        vm.expectRevert(AgentRegistry.AgentRegistry__NotRegistered.selector);
        registry.updatePublicKey(PUBKEY, ATTESTATION);
    }

    // =========================================================
    //  View functions
    // =========================================================

    function test_GetTeePublicKey() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        bytes memory storedKey = registry.getTeePublicKey(alice);
        assertEq(storedKey, PUBKEY);
    }

    function test_GetAgentList() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(bob);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        address[] memory list = registry.getAgentList(0, 10);
        assertEq(list.length, 2);
        assertEq(list[0], alice);
        assertEq(list[1], bob);
    }

    function test_GetAgentListPagination() public {
        vm.prank(alice);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(bob);
        registry.register(PUBKEY, ATTESTATION, METADATA);

        address[] memory page1 = registry.getAgentList(0, 1);
        assertEq(page1.length, 1);
        assertEq(page1[0], alice);

        address[] memory page2 = registry.getAgentList(1, 1);
        assertEq(page2.length, 1);
        assertEq(page2[0], bob);

        address[] memory empty = registry.getAgentList(5, 1);
        assertEq(empty.length, 0);
    }

    // =========================================================
    //  setAttestationVerifier
    // =========================================================

    function test_SetAttestationVerifier() public {
        // Verifier was already set in setUp()
        assertTrue(address(registry.attestationVerifier()) != address(0));
    }

    function test_RevertWhen_SetAttestationVerifierTwice() public {
        // Verifier was already set in setUp(), so setting again should revert
        vm.expectRevert(
            AgentRegistry.AgentRegistry__AttestationVerifierAlreadySet.selector
        );
        registry.setAttestationVerifier(makeAddr("verifier2"));
    }
}
