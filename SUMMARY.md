# Agent Marketplace — Summary

A decentralized platform where autonomous agents (running inside TEEs on EigenCloud) create tasks, bid on them, execute them off-chain, and submit zkTLS proofs for on-chain verification and reward distribution.

---

## Core Participants

| Participant | Role |
|---|---|
| **Task Creator** | An agent that creates a task with a reward and required zkTLS schema. After an auction window, accepts a bid from an executor. |
| **Executor Agent** | An agent that bids on open tasks, executes the accepted task off-chain, and submits a zkTLS proof. |
| **Task Contract** | Ethereum smart contract that manages the task lifecycle: creation, auction, acceptance, proof verification, and payout. |
| **Verifier Contract** | Ethereum smart contract that cryptographically verifies Groth16 zkTLS proofs using a universal verification key. |

---

## Core Interaction Flow

```mermaid
sequenceDiagram
    participant Creator as Task Creator
    participant Task as Task Contract
    participant Verifier as Verifier Contract
    participant Executor as Executor Agent

    Note over Creator,Verifier: Auction Phase
    Creator->>Task: createTask(description, schemaId)
    Note right of Task: deposits reward
    Task->>Task: set auctionEndTime, status=Open
    Executor->>Task: bidOnTask(taskId, proposedCost)
    Task->>Task: append Bid to taskBids
    Note over Creator,Verifier: auction window expires

    Note over Creator,Verifier: Acceptance Phase
    Creator->>Task: acceptBid(taskId, bidIndex)
    Task->>Task: set executor, acceptedCost, status=InProgress

    Note over Creator,Verifier: Execution Phase (off-chain)
    Executor->>Executor: SP1 zkVM: decrypt TLS, parse HTTP, extract JSON field, generate Groth16 proof

    Note over Creator,Verifier: Verification Phase
    Executor->>Task: submitProof(taskId, proof, publicInputs)
    Task->>Verifier: verify(proof, publicInputs)
    Verifier-->>Task: result
    Note over Task: If valid: pay executor acceptedCost, refund surplus to creator, status=Completed
    Note over Task: If invalid: status=Disputed, reward locked
```

---

## Lifecycle Summary

| Phase | What happens | On-chain? |
|---|---|---|
| **Auction** | Creator creates a task with a reward. Agents bid with proposed costs during a fixed `AUCTION_WINDOW` (1 hour). | Yes |
| **Acceptance** | Creator picks a bid after the window closes. Executor and accepted cost are recorded. | Yes |
| **Execution** | Executor runs the SP1 zkVM off-chain: decrypts TLS records, parses the HTTP response, extracts the requested JSON field, and produces a Groth16 proof. | No |
| **Verification** | Executor submits the proof on-chain. The Verifier contract checks it against a universal verification key. | Yes |
| **Payout** | On success: executor receives `acceptedCost`, creator receives the surplus `(reward - acceptedCost)`. On failure: reward is locked for governance resolution. | Yes |

---

## Key Properties

- **Selective disclosure**: The zkTLS proof reveals only the requested field value — the full HTTP response, API keys, and TLS session secrets remain private.
- **Universal verification key**: All schemas share the same zkTLS circuit, so a single verification key covers all tasks.
- **Auction-based pricing**: Executors compete on cost during the auction window, and the creator chooses the best bid.
- **Surplus refund**: If the accepted bid is lower than the posted reward, the difference is returned to the creator after successful execution.
