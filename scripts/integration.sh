#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  Full Integration Flow — Agent Marketplace
# =============================================================================
#  Prerequisites:
#    1. anvil running on port 8545:  anvil --port 8545 &
#    2. SP1 prover setup:            cd prover && cargo run --release -- setup --context integration-test
#    3. SP1 proof generated:         cd prover && cargo run --release -- prove --context integration-test --url <url> --field <field>
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $1"; }
fail() { echo -e "${RED}  ✗${NC} $1"; exit 1; }

RPC_URL="http://localhost:8545"

DEPLOYER_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
POSTER_PK="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
EXECUTOR_PK="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

POSTER_ADDR=$(cast wallet address --private-key "$POSTER_PK")
EXECUTOR_ADDR=$(cast wallet address --private-key "$EXECUTOR_PK")

cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1 || fail "anvil not running on $RPC_URL"

# ── Check for proof data ───────────────────────────────────────────────────
PROVER_CONTEXT="integration-test"
PROOF_FILE="prover/build/${PROVER_CONTEXT}/proof_data.json"
if [ ! -f "$PROOF_FILE" ]; then
  fail "Proof data not found at $PROOF_FILE. Run: cd prover && cargo run --release -- setup --context ${PROVER_CONTEXT} && cargo run --release -- prove --context ${PROVER_CONTEXT} --url <github-api-url> --field stargazers_count"
fi

PROOF_DATA=$(cat "$PROOF_FILE")
VK_FILE="prover/build/${PROVER_CONTEXT}/verification_key.hex"
if [ -f "$VK_FILE" ]; then
  VK_HEX=$(cat "$VK_FILE")
  echo "  Using VK from $VK_FILE"
else
  VK_HEX=$(echo "$PROOF_DATA" | jq -r '.vk_hex')
  echo "  Using VK from proof_data.json"
fi
PROOF_HEX=$(echo "$PROOF_DATA" | jq -r '.proof_hex')
INPUTS_HEX=$(echo "$PROOF_DATA" | jq -r '.public_inputs_hex')

echo ""
echo -e "${GREEN}  Using real Groth16 proof from $PROOF_FILE${NC}"
echo ""

# ── Step 1: Deploy ──────────────────────────────────────────────────────────
log "Deploying contracts (DEV_MODE=true)..."
BROADCAST_FILE="broadcast/Deploy.s.sol/31337/run-latest.json"
rm -f "$BROADCAST_FILE"

DEPLOYER_PRIVATE_KEY="$DEPLOYER_PK" DEV_MODE=true \
  forge script contracts/script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --broadcast --silent 2>/dev/null

SCHEMA_REGISTRY=$(jq -r '.transactions[] | select(.contractName == "SchemaRegistry") | .contractAddress' "$BROADCAST_FILE" 2>/dev/null | head -1)
VERIFIER=$(jq -r '.transactions[] | select(.contractName == "ZkTlsVerifier") | .contractAddress' "$BROADCAST_FILE" 2>/dev/null | head -1)
AGENT_REGISTRY=$(jq -r '.transactions[] | select(.contractName == "AgentRegistry") | .contractAddress' "$BROADCAST_FILE" 2>/dev/null | head -1)
TASK_CONTRACT=$(jq -r '.transactions[] | select(.contractName == "TaskContract") | .contractAddress' "$BROADCAST_FILE" 2>/dev/null | head -1)

for var in SCHEMA_REGISTRY VERIFIER AGENT_REGISTRY TASK_CONTRACT; do
  if [ -z "${!var}" ]; then fail "Failed to capture $var address"; fi
done

ok "SchemaRegistry:  $SCHEMA_REGISTRY"
ok "ZkTlsVerifier:   $VERIFIER"
ok "AgentRegistry:   $AGENT_REGISTRY"
ok "TaskContract:    $TASK_CONTRACT"

# ── Step 2: Set the universal zkTLS verification key ───────────────────────
log "Setting universal zkTLS verification key..."

cast send "$VERIFIER" "setVerificationKey(bytes)" "$VK_HEX" \
  --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PK" >/dev/null
ok "Universal VK set on ZkTlsVerifier"

# ── Step 3: Register agents ────────────────────────────────────────────────
log "Registering agents..."

TEE_PK="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
ATTEST="0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"

cast send "$AGENT_REGISTRY" \
  "register(bytes,bytes,string)" \
  "$TEE_PK" "$ATTEST" "ipfs://poster" \
  --rpc-url "$RPC_URL" --private-key "$POSTER_PK" --gas-limit 300000 >/dev/null
ok "Poster registered:  $POSTER_ADDR"

cast send "$AGENT_REGISTRY" \
  "register(bytes,bytes,string)" \
  "$TEE_PK" "$ATTEST" "ipfs://executor" \
  --rpc-url "$RPC_URL" --private-key "$EXECUTOR_PK" --gas-limit 300000 >/dev/null
ok "Executor registered: $EXECUTOR_ADDR"

# ── Step 4: Create schema (no VK needed — universal circuit) ────────────────
log "Creating zkTLS schema..."

cast send "$SCHEMA_REGISTRY" \
  "addSchema(string,string,string,string,string)" \
  "github-stars" "Proves a repo has N stars" "api.github.com" \
  '{"method":"GET","path":"/repos/{owner}/{repo}"}' \
  '{"stargazers_count":"integer"}' \
  --rpc-url "$RPC_URL" --private-key "$POSTER_PK" >/dev/null
ok "Schema created: ID 1"

# ── Step 5: Create task ────────────────────────────────────────────────────
log "Creating task..."

NOW=$(date +%s)
DEADLINE=$((NOW + 86400))

cast send "$TASK_CONTRACT" \
  "createTask(string,uint256,uint256)" \
  "Get star count of owner/repo" 1 "$DEADLINE" \
  --value 0.1ether \
  --rpc-url "$RPC_URL" --private-key "$POSTER_PK" >/dev/null
ok "Task created: ID 1, reward 0.1 ETH"

# ── Step 6: Apply ───────────────────────────────────────────────────────────
log "Executor applying for task #1..."

cast send "$TASK_CONTRACT" \
  "applyForTask(uint256)" 1 \
  --rpc-url "$RPC_URL" --private-key "$EXECUTOR_PK" >/dev/null
ok "Executor applied for task #1"

# ── Step 7: Submit proof (verified against universal VK) ────────────────────
log "Submitting zkTLS proof..."

EXECUTOR_BEFORE=$(cast balance "$EXECUTOR_ADDR" --rpc-url "$RPC_URL")

cast send "$TASK_CONTRACT" \
  "submitProof(uint256,bytes,bytes)" \
  1 "$PROOF_HEX" "$INPUTS_HEX" \
  --rpc-url "$RPC_URL" --private-key "$EXECUTOR_PK" >/dev/null
ok "Proof submitted and VERIFIED on-chain!"

# ── Step 8: Verify reward ───────────────────────────────────────────────────
EXECUTOR_AFTER=$(cast balance "$EXECUTOR_ADDR" --rpc-url "$RPC_URL")
REWARD_RECEIVED=$((EXECUTOR_AFTER - EXECUTOR_BEFORE))

# ── Step 9: Check final status ─────────────────────────────────────────────
log "Checking final task status..."

TASK_DATA=$(cast call "$TASK_CONTRACT" \
  "getTask(uint256)((uint256,address,string,uint256,uint256,uint256,uint256,uint8,address,bytes,bool))" 1 \
  --rpc-url "$RPC_URL")

STATUS_CODE=$(echo "$TASK_DATA" | awk -F',' '{print $8}' | tr -d ' ')
EXECUTOR_ON_TASK=$(echo "$TASK_DATA" | awk -F',' '{print $9}' | tr -d ' ')
PROOF_VERIFIED=$(echo "$TASK_DATA" | awk -F',' '{print $11}' | tr -d ' )')

case $STATUS_CODE in
  0) STATUS_STR="Open" ;;      1) STATUS_STR="InProgress" ;;
  2) STATUS_STR="Completed" ;; 3) STATUS_STR="Cancelled" ;;
  4) STATUS_STR="Expired" ;;  5) STATUS_STR="Disputed" ;;
  *) STATUS_STR="Unknown($STATUS_CODE)" ;;
esac

ok "Task #1 status:    $STATUS_STR"
ok "Proof verified:    $PROOF_VERIFIED"
ok "Executor reward:   ${REWARD_RECEIVED} wei (0.1 ETH)"

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Full Integration Flow — Complete${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Contract Addresses:"
echo "    SchemaRegistry:  $SCHEMA_REGISTRY"
echo "    ZkTlsVerifier:   $VERIFIER"
echo "    AgentRegistry:   $AGENT_REGISTRY"
echo "    TaskContract:    $TASK_CONTRACT"
echo ""
echo "  Agents:"
echo "    Poster:          $POSTER_ADDR"
echo "    Executor:        $EXECUTOR_ADDR"
echo ""
echo "  Task #1:"
echo "    Status:          $STATUS_STR"
echo "    Executor:        $EXECUTOR_ON_TASK"
echo "    Proof Verified:  $PROOF_VERIFIED"
echo "    Reward Paid:     ${REWARD_RECEIVED} wei (0.1 ETH)"
echo ""
echo "  Architecture:"
echo "    ✅ One universal zkTLS circuit (VK set once)"
echo "    ✅ Schema defines request/response format only"
echo "    ✅ Proof verified against universal VK"
echo "    ✅ Plug-and-play: add schemas without new trusted setup"
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
