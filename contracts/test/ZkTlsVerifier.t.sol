// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkTlsVerifier} from "../src/ZkTlsVerifier.sol";

contract ZkTlsVerifierTest is Test {
    ZkTlsVerifier public verifier;

    bytes public constant VK_448 =
        hex"000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000d000000000000000000000000000000000000000000000000000000000000000e";

    bytes public constant VK_512 =
        hex"000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000d000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000f0000000000000000000000000000000000000000000000000000000000000010";

    address public taskContract = makeAddr("taskContract");
    address public stranger = makeAddr("stranger");

    function setUp() public {
        verifier = new ZkTlsVerifier();
        verifier.setTaskContract(taskContract);
    }

    // =========================================================
    //  setVerificationKey
    // =========================================================

    function test_SetVerificationKey() public {
        verifier.setVerificationKey(VK_448);
        assertTrue(verifier.vkSet());
        assertEq(verifier.verificationKey(), VK_448);
    }

    function test_RevertWhen_SetVKTwice() public {
        verifier.setVerificationKey(VK_448);
        vm.expectRevert(ZkTlsVerifier.ZkTlsVerifier__VKAlreadySet.selector);
        verifier.setVerificationKey(VK_512);
    }

    function test_RevertWhen_InvalidVKLength() public {
        vm.expectRevert(ZkTlsVerifier.ZkTlsVerifier__InvalidVKLength.selector);
        verifier.setVerificationKey(hex"00");
    }

    // =========================================================
    //  verify — error cases
    // =========================================================

    function test_RevertWhen_NotTaskContract() public {
        verifier.setVerificationKey(VK_448);

        vm.prank(stranger);
        vm.expectRevert(ZkTlsVerifier.ZkTlsVerifier__NotTaskContract.selector);
        verifier.verify(hex"00", hex"00");
    }

    function test_RevertWhen_VKNotSet() public {
        vm.prank(taskContract);
        vm.expectRevert(ZkTlsVerifier.ZkTlsVerifier__VKNotSet.selector);
        verifier.verify(hex"00", hex"00");
    }

    function test_RevertWhen_InvalidProofLength() public {
        verifier.setVerificationKey(VK_448);

        vm.prank(taskContract);
        vm.expectRevert(
            ZkTlsVerifier.ZkTlsVerifier__InvalidProofLength.selector
        );
        verifier.verify(hex"00", hex"00");
    }

    function test_RevertWhen_InvalidPublicInputs() public {
        verifier.setVerificationKey(VK_448);

        bytes memory proof = new bytes(256);

        vm.prank(taskContract);
        vm.expectRevert(
            ZkTlsVerifier.ZkTlsVerifier__InvalidPublicInputs.selector
        );
        verifier.verify(proof, abi.encode(new uint256[](1)));
    }

    // =========================================================
    //  Replay protection
    // =========================================================

    function test_ReplayProtection() public {
        verifier.setVerificationKey(VK_448);

        bytes memory proof = new bytes(256);
        bytes32 proofHash = keccak256(proof);
        assertFalse(verifier.isProofVerified(proofHash));
    }

    // =========================================================
    //  setTaskContract
    // =========================================================

    function test_SetTaskContract() public {
        assertEq(verifier.taskContract(), taskContract);
    }

    function test_RevertWhen_SetTaskContractTwice() public {
        vm.expectRevert(
            ZkTlsVerifier.ZkTlsVerifier__TaskContractAlreadySet.selector
        );
        verifier.setTaskContract(makeAddr("other"));
    }

    // =========================================================
    //  Verify with invalid proof
    // =========================================================

    function test_VerifyInvalidProof() public {
        verifier.setVerificationKey(VK_448);

        bytes memory proof = new bytes(256);
        bytes memory publicInputs = abi.encode(new uint256[](0));

        vm.prank(taskContract);
        vm.expectRevert();
        verifier.verify(proof, publicInputs);
    }
}
