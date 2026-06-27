// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AgentRegistry} from "./AgentRegistry.sol";
import {SchemaRegistry} from "./SchemaRegistry.sol";
import {ZkTlsVerifier} from "./ZkTlsVerifier.sol";

/// @title TaskContract
/// @notice Core contract for the Agent Marketplace. Agents post tasks with a
///         reward, other agents apply and execute them, then submit a zkTLS
///         proof. If the proof is verified on-chain, the reward is
///         automatically distributed to the executor.
///
/// @dev The zkTLS proof is verified against a single universal verification
///      key in the ZkTlsVerifier. The schemaId on a task tells the prover
///      what request/response format to use — it is NOT used for verification.
contract TaskContract {
    // =========================================================
    //  Types
    // =========================================================

    enum TaskStatus {
        Open,
        InProgress,
        Completed,
        Cancelled,
        Expired,
        Disputed
    }

    struct Task {
        uint256 id;
        address poster;
        string description;
        uint256 reward;
        uint256 schemaId; // Tells the prover what schema to use
        uint256 deadline;
        uint256 createdAt;
        TaskStatus status;
        address executor;
        bytes proof;
        bool proofVerified;
    }

    // =========================================================
    //  State
    // =========================================================

    mapping(uint256 => Task) public tasks;
    uint256 public taskCount;

    AgentRegistry public agentRegistry;
    SchemaRegistry public schemaRegistry;
    ZkTlsVerifier public verifier;

    // =========================================================
    //  Events
    // =========================================================

    event TaskCreated(
        uint256 indexed taskId,
        address indexed poster,
        uint256 reward,
        uint256 schemaId,
        uint256 deadline,
        uint256 timestamp
    );

    event TaskApplied(
        uint256 indexed taskId,
        address indexed executor,
        uint256 timestamp
    );
    event ProofSubmitted(
        uint256 indexed taskId,
        address indexed executor,
        bytes proof,
        uint256 timestamp
    );
    event ProofVerified(
        uint256 indexed taskId,
        bool success,
        uint256 timestamp
    );
    event RewardDistributed(
        uint256 indexed taskId,
        address indexed executor,
        uint256 amount,
        uint256 timestamp
    );
    event TaskCancelled(uint256 indexed taskId, uint256 timestamp);
    event TaskExpired(uint256 indexed taskId, uint256 timestamp);

    // =========================================================
    //  Errors
    // =========================================================

    error TaskContract__NotRegisteredAgent();
    error TaskContract__NotPoster();
    error TaskContract__NotExecutor();
    error TaskContract__TaskNotOpen();
    error TaskContract__TaskNotInProgress();
    error TaskContract__TaskCancelledOrExpired();
    error TaskContract__TaskExpired();
    error TaskContract__DeadlineInPast();
    error TaskContract__SchemaInactive();
    error TaskContract__ExecutorCannotBePoster();
    error TaskContract__NoReward();
    error TaskContract__TransferFailed();

    // =========================================================
    //  Modifiers
    // =========================================================

    modifier onlyRegisteredAgent() {
        if (!agentRegistry.isRegistered(msg.sender)) {
            revert TaskContract__NotRegisteredAgent();
        }
        _;
    }

    modifier onlyPoster(uint256 taskId) {
        if (tasks[taskId].poster != msg.sender)
            revert TaskContract__NotPoster();
        _;
    }

    modifier onlyExecutor(uint256 taskId) {
        if (tasks[taskId].executor != msg.sender)
            revert TaskContract__NotExecutor();
        _;
    }

    // =========================================================
    //  Constructor
    // =========================================================

    constructor(
        address _agentRegistry,
        address _schemaRegistry,
        address _verifier
    ) {
        agentRegistry = AgentRegistry(_agentRegistry);
        schemaRegistry = SchemaRegistry(_schemaRegistry);
        verifier = ZkTlsVerifier(_verifier);
    }

    // =========================================================
    //  Task Lifecycle
    // =========================================================

    /// @notice Create a new task. The reward (msg.value) is held in the contract.
    /// @param description Human-readable task description.
    /// @param schemaId The zkTLS schema ID that the prover should use.
    /// @param deadline Unix timestamp by which the task must be completed.
    /// @return taskId The assigned task ID.
    function createTask(
        string calldata description,
        uint256 schemaId,
        uint256 deadline
    ) external payable onlyRegisteredAgent returns (uint256 taskId) {
        if (msg.value == 0) revert TaskContract__NoReward();
        if (deadline <= block.timestamp) revert TaskContract__DeadlineInPast();
        if (!schemaRegistry.isActive(schemaId))
            revert TaskContract__SchemaInactive();

        taskId = ++taskCount;

        tasks[taskId] = Task({
            id: taskId,
            poster: msg.sender,
            description: description,
            reward: msg.value,
            schemaId: schemaId,
            deadline: deadline,
            createdAt: block.timestamp,
            status: TaskStatus.Open,
            executor: address(0),
            proof: new bytes(0),
            proofVerified: false
        });

        emit TaskCreated(
            taskId,
            msg.sender,
            msg.value,
            schemaId,
            deadline,
            block.timestamp
        );
    }

    /// @notice Apply to execute a task. First-come-first-served.
    function applyForTask(uint256 taskId) external onlyRegisteredAgent {
        Task storage task = tasks[taskId];

        if (task.status != TaskStatus.Open) revert TaskContract__TaskNotOpen();
        if (block.timestamp > task.deadline) {
            task.status = TaskStatus.Expired;
            emit TaskExpired(taskId, block.timestamp);
            revert TaskContract__TaskExpired();
        }
        if (task.poster == msg.sender)
            revert TaskContract__ExecutorCannotBePoster();

        task.executor = msg.sender;
        task.status = TaskStatus.InProgress;

        emit TaskApplied(taskId, msg.sender, block.timestamp);
    }

    /// @notice Submit a zkTLS proof for a task. The proof is verified against
    ///         the universal zkTLS verification key. If valid, the reward is
    ///         automatically transferred to the executor.
    /// @param taskId The task ID.
    /// @param proof The Groth16 proof bytes (256 bytes).
    /// @param publicInputs The public inputs to the proof (ABI-encoded uint256[]).
    function submitProof(
        uint256 taskId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external onlyRegisteredAgent onlyExecutor(taskId) {
        Task storage task = tasks[taskId];

        if (task.status != TaskStatus.InProgress)
            revert TaskContract__TaskNotInProgress();
        if (block.timestamp > task.deadline) {
            task.status = TaskStatus.Expired;
            emit TaskExpired(taskId, block.timestamp);
            revert TaskContract__TaskExpired();
        }

        task.proof = proof;
        emit ProofSubmitted(taskId, msg.sender, proof, block.timestamp);

        // Verify against the universal zkTLS verification key
        bool valid;
        try verifier.verify(proof, publicInputs) returns (bool result) {
            valid = result;
        } catch {
            valid = false;
        }

        task.proofVerified = valid;

        if (valid) {
            task.status = TaskStatus.Completed;
            emit ProofVerified(taskId, true, block.timestamp);

            uint256 reward = task.reward;
            task.reward = 0;

            (bool sent, ) = payable(msg.sender).call{value: reward}("");
            if (!sent) revert TaskContract__TransferFailed();

            emit RewardDistributed(taskId, msg.sender, reward, block.timestamp);
        } else {
            task.status = TaskStatus.Disputed;
            emit ProofVerified(taskId, false, block.timestamp);
        }
    }

    /// @notice Cancel an open task. Only the poster can cancel.
    function cancelTask(uint256 taskId) external onlyPoster(taskId) {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Open) revert TaskContract__TaskNotOpen();

        task.status = TaskStatus.Cancelled;
        uint256 reward = task.reward;
        task.reward = 0;

        emit TaskCancelled(taskId, block.timestamp);

        (bool sent, ) = payable(msg.sender).call{value: reward}("");
        if (!sent) revert TaskContract__TransferFailed();
    }

    /// @notice Claim back the reward for an expired task.
    function claimBack(uint256 taskId) external onlyPoster(taskId) {
        Task storage task = tasks[taskId];

        if (
            task.status != TaskStatus.InProgress &&
            task.status != TaskStatus.Open
        ) {
            revert TaskContract__TaskCancelledOrExpired();
        }
        if (block.timestamp <= task.deadline)
            revert TaskContract__TaskExpired();

        task.status = TaskStatus.Expired;
        uint256 reward = task.reward;
        task.reward = 0;

        emit TaskExpired(taskId, block.timestamp);

        (bool sent, ) = payable(msg.sender).call{value: reward}("");
        if (!sent) revert TaskContract__TransferFailed();
    }

    // =========================================================
    //  View Functions
    // =========================================================

    function getTask(uint256 taskId) external view returns (Task memory) {
        return tasks[taskId];
    }

    function getTaskCount() external view returns (uint256) {
        return taskCount;
    }

    function getOpenTasks(
        uint256 offset,
        uint256 limit
    ) external view returns (uint256[] memory result) {
        uint256 count;
        for (uint256 i = 1; i <= taskCount; i++) {
            if (
                tasks[i].status == TaskStatus.Open &&
                block.timestamp <= tasks[i].deadline
            ) {
                count++;
            }
        }

        if (offset >= count) return new uint256[](0);

        uint256 end = offset + limit;
        if (end > count) end = count;

        result = new uint256[](end - offset);
        uint256 idx;
        for (uint256 i = 1; i <= taskCount && idx < end; i++) {
            if (
                tasks[i].status == TaskStatus.Open &&
                block.timestamp <= tasks[i].deadline
            ) {
                if (idx >= offset) {
                    result[idx - offset] = i;
                }
                idx++;
            }
        }
    }

    function getTasksByPoster(
        address poster
    ) external view returns (uint256[] memory result) {
        uint256 count;
        for (uint256 i = 1; i <= taskCount; i++) {
            if (tasks[i].poster == poster) count++;
        }

        result = new uint256[](count);
        uint256 idx;
        for (uint256 i = 1; i <= taskCount; i++) {
            if (tasks[i].poster == poster) {
                result[idx++] = i;
            }
        }
    }

    function getTasksByExecutor(
        address executor
    ) external view returns (uint256[] memory result) {
        uint256 count;
        for (uint256 i = 1; i <= taskCount; i++) {
            if (tasks[i].executor == executor) count++;
        }

        result = new uint256[](count);
        uint256 idx;
        for (uint256 i = 1; i <= taskCount; i++) {
            if (tasks[i].executor == executor) {
                result[idx++] = i;
            }
        }
    }
}
