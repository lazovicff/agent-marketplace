// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {ZkTlsVerifier} from "../src/ZkTlsVerifier.sol";
import {TaskContract} from "../src/TaskContract.sol";
import {DevVerifier} from "../src/DevVerifier.sol";

contract TaskContractTest is Test {
    AgentRegistry public agentRegistry;
    SchemaRegistry public schemaRegistry;
    ZkTlsVerifier public verifier;
    TaskContract public taskContract;

    bytes public constant PUBKEY =
        hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    bytes public constant ATTESTATION =
        hex"cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
    string public constant METADATA = "ipfs://QmTest";

    bytes public constant VK =
        hex"000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000d000000000000000000000000000000000000000000000000000000000000000e";

    string constant SCHEMA_NAME = "github-stars";
    string constant SCHEMA_DESC = "Proves a GitHub repo has at least N stars";
    string constant SCHEMA_HOST = "api.github.com";
    string constant REQ_SCHEMA = '{"method":"GET","path":"/repos/owner/repo"}';
    string constant RES_SCHEMA =
        '{"type":"object","properties":{"stargazers_count":{"type":"integer"}}}';

    address public poster = makeAddr("poster");
    address public executor = makeAddr("executor");
    address public stranger = makeAddr("stranger");

    uint256 public schemaId;
    uint256 public constant REWARD = 1 ether;
    uint256 public constant DEADLINE = 7 days;

    function setUp() public {
        agentRegistry = new AgentRegistry();
        schemaRegistry = new SchemaRegistry();
        verifier = new ZkTlsVerifier();
        taskContract = new TaskContract(
            address(agentRegistry),
            address(schemaRegistry),
            address(verifier)
        );

        // Wire up
        verifier.setTaskContract(address(taskContract));

        // DevVerifier for attestations
        DevVerifier devVerifier = new DevVerifier();
        agentRegistry.setAttestationVerifier(address(devVerifier));

        // Fund poster
        vm.deal(poster, 100 ether);
        vm.deal(stranger, 100 ether);

        // Register agents
        vm.prank(poster);
        agentRegistry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(executor);
        agentRegistry.register(PUBKEY, ATTESTATION, METADATA);

        // Add a schema (no VK needed — universal circuit)
        vm.prank(poster);
        schemaId = schemaRegistry.addSchema(
            SCHEMA_NAME,
            SCHEMA_DESC,
            SCHEMA_HOST,
            REQ_SCHEMA,
            RES_SCHEMA
        );
    }

    // =========================================================
    //  createTask
    // =========================================================

    function test_CreateTask() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Get the star count of repo",
            schemaId,
            block.timestamp + DEADLINE
        );

        assertEq(taskId, 1);
        assertEq(taskContract.taskCount(), 1);

        TaskContract.Task memory task = taskContract.getTask(taskId);
        assertEq(task.id, 1);
        assertEq(task.poster, poster);
        assertEq(task.description, "Get the star count of repo");
        assertEq(task.reward, REWARD);
        assertEq(task.schemaId, schemaId);
        assertEq(task.deadline, block.timestamp + DEADLINE);
        assertEq(uint256(task.status), uint256(TaskContract.TaskStatus.Open));
        assertEq(task.executor, address(0));
    }

    function test_CreateTaskMultiple() public {
        vm.prank(poster);
        taskContract.createTask{value: REWARD}(
            "Task 1",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(poster);
        taskContract.createTask{value: REWARD}(
            "Task 2",
            schemaId,
            block.timestamp + DEADLINE
        );

        assertEq(taskContract.taskCount(), 2);
    }

    function test_RevertWhen_NotRegisteredCreateTask() public {
        vm.prank(stranger);
        vm.expectRevert(TaskContract.TaskContract__NotRegisteredAgent.selector);
        taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );
    }

    function test_RevertWhen_NoReward() public {
        vm.prank(poster);
        vm.expectRevert(TaskContract.TaskContract__NoReward.selector);
        taskContract.createTask{value: 0}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );
    }

    function test_RevertWhen_DeadlineInPast() public {
        vm.prank(poster);
        vm.expectRevert(TaskContract.TaskContract__DeadlineInPast.selector);
        taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp - 1
        );
    }

    function test_RevertWhen_SchemaInactive() public {
        vm.prank(poster);
        schemaRegistry.deactivateSchema(schemaId);

        vm.prank(poster);
        vm.expectRevert(TaskContract.TaskContract__SchemaInactive.selector);
        taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );
    }

    // =========================================================
    //  applyForTask
    // =========================================================

    function test_ApplyForTask() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        TaskContract.Task memory task = taskContract.getTask(taskId);
        assertEq(task.executor, executor);
        assertEq(
            uint256(task.status),
            uint256(TaskContract.TaskStatus.InProgress)
        );
    }

    function test_RevertWhen_NotRegisteredApply() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(stranger);
        vm.expectRevert(TaskContract.TaskContract__NotRegisteredAgent.selector);
        taskContract.applyForTask(taskId);
    }

    function test_RevertWhen_PosterApplies() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(poster);
        vm.expectRevert(
            TaskContract.TaskContract__ExecutorCannotBePoster.selector
        );
        taskContract.applyForTask(taskId);
    }

    function test_RevertWhen_ApplyToNonOpenTask() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        address executor2 = makeAddr("executor2");
        vm.prank(executor2);
        agentRegistry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(executor2);
        vm.expectRevert(TaskContract.TaskContract__TaskNotOpen.selector);
        taskContract.applyForTask(taskId);
    }

    function test_RevertWhen_ApplyAfterDeadline() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.warp(block.timestamp + DEADLINE + 1);

        vm.prank(executor);
        vm.expectRevert(TaskContract.TaskContract__TaskExpired.selector);
        taskContract.applyForTask(taskId);
    }

    // =========================================================
    //  cancelTask
    // =========================================================

    function test_CancelTask() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        uint256 posterBalanceBefore = address(poster).balance;

        vm.prank(poster);
        taskContract.cancelTask(taskId);

        TaskContract.Task memory task = taskContract.getTask(taskId);
        assertEq(
            uint256(task.status),
            uint256(TaskContract.TaskStatus.Cancelled)
        );
        assertEq(task.reward, 0);

        uint256 posterBalanceAfter = address(poster).balance;
        assertEq(posterBalanceAfter - posterBalanceBefore, REWARD);
    }

    function test_RevertWhen_NotPosterCancel() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        vm.expectRevert(TaskContract.TaskContract__NotPoster.selector);
        taskContract.cancelTask(taskId);
    }

    function test_RevertWhen_CancelAfterApplication() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        vm.prank(poster);
        vm.expectRevert(TaskContract.TaskContract__TaskNotOpen.selector);
        taskContract.cancelTask(taskId);
    }

    // =========================================================
    //  submitProof — failure cases
    // =========================================================

    function test_RevertWhen_NotExecutorSubmitProof() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        address executor2 = makeAddr("executor2");
        vm.prank(executor2);
        agentRegistry.register(PUBKEY, ATTESTATION, METADATA);

        vm.prank(executor2);
        vm.expectRevert(TaskContract.TaskContract__NotExecutor.selector);
        taskContract.submitProof(taskId, hex"00", hex"00");
    }

    function test_RevertWhen_SubmitProofOnOpenTask() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        vm.expectRevert(TaskContract.TaskContract__NotExecutor.selector);
        taskContract.submitProof(taskId, hex"00", hex"00");
    }

    // =========================================================
    //  claimBack
    // =========================================================

    function test_ClaimBackAfterDeadline() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        vm.warp(block.timestamp + DEADLINE + 1);

        uint256 posterBalanceBefore = address(poster).balance;

        vm.prank(poster);
        taskContract.claimBack(taskId);

        TaskContract.Task memory task = taskContract.getTask(taskId);
        assertEq(
            uint256(task.status),
            uint256(TaskContract.TaskStatus.Expired)
        );
        assertEq(task.reward, 0);

        uint256 posterBalanceAfter = address(poster).balance;
        assertEq(posterBalanceAfter - posterBalanceBefore, REWARD);
    }

    function test_RevertWhen_ClaimBackBeforeDeadline() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        vm.prank(poster);
        vm.expectRevert(TaskContract.TaskContract__TaskExpired.selector);
        taskContract.claimBack(taskId);
    }

    // =========================================================
    //  View functions
    // =========================================================

    function test_GetOpenTasks() public {
        vm.prank(poster);
        taskContract.createTask{value: REWARD}(
            "Task 1",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(poster);
        taskContract.createTask{value: REWARD}(
            "Task 2",
            schemaId,
            block.timestamp + DEADLINE
        );

        uint256[] memory openTasks = taskContract.getOpenTasks(0, 10);
        assertEq(openTasks.length, 2);
        assertEq(openTasks[0], 1);
        assertEq(openTasks[1], 2);
    }

    function test_GetOpenTasksAfterApplication() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task 1",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(poster);
        taskContract.createTask{value: REWARD}(
            "Task 2",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        uint256[] memory openTasks = taskContract.getOpenTasks(0, 10);
        assertEq(openTasks.length, 1);
        assertEq(openTasks[0], 2);
    }

    function test_GetTasksByPoster() public {
        vm.prank(poster);
        taskContract.createTask{value: REWARD}(
            "Task 1",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(poster);
        taskContract.createTask{value: REWARD}(
            "Task 2",
            schemaId,
            block.timestamp + DEADLINE
        );

        uint256[] memory posterTasks = taskContract.getTasksByPoster(poster);
        assertEq(posterTasks.length, 2);
    }

    function test_GetTasksByExecutor() public {
        vm.prank(poster);
        uint256 taskId = taskContract.createTask{value: REWARD}(
            "Task",
            schemaId,
            block.timestamp + DEADLINE
        );

        vm.prank(executor);
        taskContract.applyForTask(taskId);

        uint256[] memory executorTasks = taskContract.getTasksByExecutor(
            executor
        );
        assertEq(executorTasks.length, 1);
        assertEq(executorTasks[0], taskId);
    }
}
