// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {ZkTlsVerifier} from "../src/ZkTlsVerifier.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {TaskContract} from "../src/TaskContract.sol";
import {DevVerifier} from "../src/DevVerifier.sol";

/// @title Deploy
/// @notice Deploys all Agent Marketplace contracts.
///
/// Dev mode (DEV_MODE=true):
///   - Deploys DevVerifier so attestations are always accepted.
contract Deploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        bool devMode = vm.envOr("DEV_MODE", false);

        console.log("Deployer:", deployer);
        if (devMode) console.log("DEV MODE: enabled");

        vm.startBroadcast(deployerPrivateKey);

        // ---- 1. SchemaRegistry ----
        SchemaRegistry schemaRegistry = new SchemaRegistry();
        console.log("SchemaRegistry deployed at:", address(schemaRegistry));

        // ---- 2. ZkTlsVerifier ----
        ZkTlsVerifier verifier = new ZkTlsVerifier();
        console.log("ZkTlsVerifier deployed at:", address(verifier));

        // ---- 3. AgentRegistry ----
        AgentRegistry agentRegistry = new AgentRegistry();
        console.log("AgentRegistry deployed at:", address(agentRegistry));

        // ---- 3b. DevVerifier (dev mode only) ----
        if (devMode) {
            DevVerifier devAttestVerifier = new DevVerifier();
            console.log("DevVerifier deployed at:", address(devAttestVerifier));
            agentRegistry.setAttestationVerifier(address(devAttestVerifier));
            console.log("AgentRegistry.attestationVerifier set to DevVerifier");
        }

        // ---- 4. TaskContract ----
        TaskContract taskContract = new TaskContract(
            address(agentRegistry),
            address(schemaRegistry),
            address(verifier)
        );
        console.log("TaskContract deployed at:", address(taskContract));

        // ---- Post-deployment wiring ----
        verifier.setTaskContract(address(taskContract));
        console.log(
            "ZkTlsVerifier.taskContract set to:",
            address(taskContract)
        );

        vm.stopBroadcast();

        console.log("=== Deployment Complete ===");
        console.log("SchemaRegistry:  ", address(schemaRegistry));
        console.log("ZkTlsVerifier:   ", address(verifier));
        console.log("AgentRegistry:   ", address(agentRegistry));
        console.log("TaskContract:    ", address(taskContract));
        console.log("");
        console.log("Next: set the universal zkTLS verification key:");
        console.log(
            "  cast send",
            address(verifier),
            '"setVerificationKey(bytes)" <VK_HEX>'
        );
    }
}
