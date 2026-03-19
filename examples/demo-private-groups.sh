#!/usr/bin/env bash
# =============================================================================
# Private Groups Demo — Manual REST walkthrough
# =============================================================================
#
# Writes local config and walks the REST flow once two x0xd daemons are
# already running. Each daemon must use isolated identity storage (see
# the HOME override in startup instructions below) so they get distinct
# Agent IDs.
#
# Run from the repo root after building: cargo build --all-features
#
# Usage:
#   1. Open three terminal tabs
#   2. Tab 1: Start daemon A with isolated HOME (see instructions below)
#   3. Tab 2: Start daemon B with isolated HOME (see instructions below)
#   4. Tab 3: Run this script   (./examples/demo-private-groups.sh)
#
# Prerequisites:
#   - Two config files (created below if missing)
#   - x0xd binary built (cargo build --all-features)
#   - curl and jq installed
#
# =============================================================================

set -euo pipefail

API_A="http://127.0.0.1:12700"
API_B="http://127.0.0.1:12701"

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${GREEN}=== $1 ===${NC}"; }
info() { echo -e "${YELLOW}  → $1${NC}"; }
fail() { echo -e "${RED}  ✗ $1${NC}"; exit 1; }

# ---------------------------------------------------------------------------
# Setup: create minimal configs if they don't exist
# ---------------------------------------------------------------------------

mkdir -p /tmp/x0x-demo-a /tmp/x0x-demo-b

cat > /tmp/x0x-demo-a/config.toml <<'EOF'
bind_address = "127.0.0.1:12800"
api_address = "127.0.0.1:12700"
data_dir = "/tmp/x0x-demo-a/data"
bootstrap_peers = []
rendezvous_enabled = false
update_enabled = false
log_level = "info"
EOF

cat > /tmp/x0x-demo-b/config.toml <<'EOF'
bind_address = "127.0.0.1:12801"
api_address = "127.0.0.1:12701"
data_dir = "/tmp/x0x-demo-b/data"
bootstrap_peers = ["127.0.0.1:12800"]
rendezvous_enabled = false
update_enabled = false
log_level = "info"
EOF

echo "Config files written to /tmp/x0x-demo-{a,b}/config.toml"
echo ""
echo "Each daemon needs its own identity storage so they get distinct Agent IDs."
echo "Use the HOME override below to isolate key material per daemon."
echo ""
echo "Before running this script, start the daemons in separate terminals:"
echo ""
echo "  Terminal 1:  HOME=/tmp/x0x-demo-a cargo run --bin x0xd -- --config /tmp/x0x-demo-a/config.toml"
echo "  Terminal 2:  HOME=/tmp/x0x-demo-b cargo run --bin x0xd -- --config /tmp/x0x-demo-b/config.toml"
echo ""
read -p "Press Enter when both daemons are running..."

# ---------------------------------------------------------------------------
# Step 1: Health check
# ---------------------------------------------------------------------------
step "1. Health check"

HEALTH_A=$(curl -s "$API_A/health" | jq -r '.status // empty' 2>/dev/null || true)
HEALTH_B=$(curl -s "$API_B/health" | jq -r '.status // empty' 2>/dev/null || true)

if [ -z "$HEALTH_A" ]; then fail "Daemon A not responding at $API_A"; fi
if [ -z "$HEALTH_B" ]; then fail "Daemon B not responding at $API_B"; fi
info "Daemon A: healthy"
info "Daemon B: healthy"

# Get agent IDs
AGENT_A=$(curl -s "$API_A/agent" | jq -r '.agent_id')
AGENT_B=$(curl -s "$API_B/agent" | jq -r '.agent_id')
info "Agent A: ${AGENT_A:0:16}..."
info "Agent B: ${AGENT_B:0:16}..."

# ---------------------------------------------------------------------------
# Step 2: A creates a private group
# ---------------------------------------------------------------------------
step "2. Agent A creates a private group"

RESP=$(curl -s -X POST "$API_A/groups" \
  -H "Content-Type: application/json" \
  -d '{"name": "demo-collaboration"}')

echo "$RESP" | jq .

GROUP_ID=$(echo "$RESP" | jq -r '.group.group_id')
if [ "$GROUP_ID" = "null" ] || [ -z "$GROUP_ID" ]; then fail "Group creation failed"; fi
info "Group ID: ${GROUP_ID:0:16}..."

# ---------------------------------------------------------------------------
# Step 3: A invites B
# ---------------------------------------------------------------------------
step "3. Agent A invites Agent B"

RESP=$(curl -s -X POST "$API_A/groups/$GROUP_ID/invite" \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\": \"$AGENT_B\"}")

echo "$RESP" | jq .
info "Invite sent"

# ---------------------------------------------------------------------------
# Step 4: B checks for invites (poll until arrival)
# ---------------------------------------------------------------------------
step "4. Agent B checks for pending invites"

FOUND=false
for i in $(seq 1 15); do
  RESP=$(curl -s "$API_B/invites")
  COUNT=$(echo "$RESP" | jq '.invites | length')
  if [ "$COUNT" -gt 0 ]; then
    echo "$RESP" | jq .
    FOUND=true
    break
  fi
  info "Waiting for invite... ($i/15)"
  sleep 1
done

if [ "$FOUND" = false ]; then fail "Invite did not arrive at B within 15s"; fi
info "Invite received!"

# ---------------------------------------------------------------------------
# Step 5: B accepts the invite
# ---------------------------------------------------------------------------
step "5. Agent B accepts the invite"

RESP=$(curl -s -X POST "$API_B/invites/$GROUP_ID/accept" \
  -H "Content-Type: application/json" \
  -d "{\"sender\": \"$AGENT_A\"}")

echo "$RESP" | jq .
info "Invite accepted — B is now a group member"

# ---------------------------------------------------------------------------
# Step 6: Verify both agents see the group
# ---------------------------------------------------------------------------
step "6. Both agents list their groups"

info "Agent A's groups:"
curl -s "$API_A/groups" | jq '.groups'

info "Agent B's groups:"
curl -s "$API_B/groups" | jq '.groups'

# ---------------------------------------------------------------------------
# Step 7: A adds a task
# ---------------------------------------------------------------------------
step "7. Agent A adds a task to the group"

RESP=$(curl -s -X POST "$API_A/groups/$GROUP_ID/tasks" \
  -H "Content-Type: application/json" \
  -d '{"title": "Investigate quantum gossip", "description": "Research post-quantum gossip protocol improvements"}')

echo "$RESP" | jq .
TASK_ID=$(echo "$RESP" | jq -r '.task_id')
info "Task created: ${TASK_ID:0:16}..."

# ---------------------------------------------------------------------------
# Step 8: A sees the task
# ---------------------------------------------------------------------------
step "8. Agent A views group tasks"

curl -s "$API_A/groups/$GROUP_ID/tasks" | jq '.tasks'

# ---------------------------------------------------------------------------
# Step 9: B adds a task
# ---------------------------------------------------------------------------
step "9. Agent B adds a task to the group"

RESP=$(curl -s -X POST "$API_B/groups/$GROUP_ID/tasks" \
  -H "Content-Type: application/json" \
  -d '{"title": "Write documentation", "description": "Document the private groups API"}')

echo "$RESP" | jq .
B_TASK_ID=$(echo "$RESP" | jq -r '.task_id')
info "Task created: ${B_TASK_ID:0:16}..."

# ---------------------------------------------------------------------------
# Step 10: B claims and completes its task
# ---------------------------------------------------------------------------
step "10. Agent B claims and completes its task"

info "Claiming..."
curl -s -X PATCH "$API_B/groups/$GROUP_ID/tasks/$B_TASK_ID" \
  -H "Content-Type: application/json" \
  -d '{"action": "claim"}' | jq .

info "Completing..."
curl -s -X PATCH "$API_B/groups/$GROUP_ID/tasks/$B_TASK_ID" \
  -H "Content-Type: application/json" \
  -d '{"action": "complete"}' | jq .

# ---------------------------------------------------------------------------
# Step 11: B views final task state
# ---------------------------------------------------------------------------
step "11. Final task state on Agent B"

curl -s "$API_B/groups/$GROUP_ID/tasks" | jq '.tasks'

# ---------------------------------------------------------------------------
# Step 12: A views final task state
# ---------------------------------------------------------------------------
step "12. Final task state on Agent A"

curl -s "$API_A/groups/$GROUP_ID/tasks" | jq '.tasks'

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}=== Demo complete ===${NC}"
echo ""
echo "Summary:"
echo "  - Two agents created an MLS-encrypted private group"
echo "  - Invites were delivered and accepted via gossip"
echo "  - Both agents added, claimed, and completed tasks"
echo "  - All task data is encrypted with ChaCha20-Poly1305"
echo "  - Non-members cannot decrypt task content; gossip-visible data is ciphertext plus observable metadata"
