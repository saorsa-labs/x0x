#!/usr/bin/env bash
#
# Testnet Identity & Presence Tests
# ==================================
# Automated checks for identity discovery and presence against live
# DigitalOcean droplets running x0xd. Uses SSH + curl to exercise the REST API.
#
# Usage:
#   ./tests/testnet/run_test_plan.sh <HOST_A> <HOST_B> <HOST_C>
#
# Each HOST is an SSH-accessible address (e.g. root@1.2.3.4).
# x0xd must already be running on each droplet (port 12700).
#
# Droplets A and B have user_key_path configured (same key).
# Droplet C has no user key.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST_A="${1:?Usage: $0 <HOST_A> <HOST_B> <HOST_C>}"
HOST_B="${2:?Usage: $0 <HOST_A> <HOST_B> <HOST_C>}"
HOST_C="${3:?Usage: $0 <HOST_A> <HOST_B> <HOST_C>}"

API_PORT=12700
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5"

PASS=0
FAIL=0
SKIP=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
api() {
    local host="$1" method="$2" path="$3"
    shift 3
    ssh $SSH_OPTS "$host" "curl -sf -X $method http://localhost:${API_PORT}${path} $*" 2>/dev/null
}

api_json() {
    local host="$1" method="$2" path="$3"
    shift 3
    ssh $SSH_OPTS "$host" "curl -sf -X $method -H 'Content-Type: application/json' http://localhost:${API_PORT}${path} $*" 2>/dev/null
}

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$desc"
    else
        fail "$desc (expected='$expected', actual='$actual')"
    fi
}

assert_not_empty() {
    local desc="$1" val="$2"
    if [[ -n "$val" && "$val" != "null" ]]; then
        pass "$desc"
    else
        fail "$desc (was empty/null)"
    fi
}

assert_empty_or_null() {
    local desc="$1" val="$2"
    if [[ -z "$val" || "$val" == "null" ]]; then
        pass "$desc"
    else
        fail "$desc (expected empty/null, got '$val')"
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        pass "$desc"
    else
        fail "$desc (needle='$needle' not in haystack)"
    fi
}

assert_not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        fail "$desc (needle='$needle' found but should not be)"
    else
        pass "$desc"
    fi
}

jq_field() {
    echo "$1" | jq -r "$2" 2>/dev/null
}

separator() {
    echo ""
    echo "================================================================"
    echo "$1"
    echo "================================================================"
}

# ---------------------------------------------------------------------------
# Pre-flight: check connectivity
# ---------------------------------------------------------------------------
separator "Pre-flight: checking SSH + x0xd connectivity"

for host_var in HOST_A HOST_B HOST_C; do
    host="${!host_var}"
    result=$(api "$host" GET /health 2>/dev/null || echo "FAIL")
    ok=$(jq_field "$result" '.ok')
    if [[ "$ok" == "true" ]]; then
        version=$(jq_field "$result" '.version')
        peers=$(jq_field "$result" '.peers')
        echo "  $host_var ($host): healthy, version=$version, peers=$peers"
    else
        echo "  $host_var ($host): UNREACHABLE - aborting"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Step 1: Check identities
# ---------------------------------------------------------------------------
separator "Step 1: Check identities"

AGENT_A_JSON=$(api "$HOST_A" GET /agent)
AGENT_B_JSON=$(api "$HOST_B" GET /agent)
AGENT_C_JSON=$(api "$HOST_C" GET /agent)

AGENT_A_ID=$(jq_field "$AGENT_A_JSON" '.agent_id')
AGENT_B_ID=$(jq_field "$AGENT_B_JSON" '.agent_id')
AGENT_C_ID=$(jq_field "$AGENT_C_JSON" '.agent_id')

MACHINE_A_ID=$(jq_field "$AGENT_A_JSON" '.machine_id')
MACHINE_B_ID=$(jq_field "$AGENT_B_JSON" '.machine_id')
MACHINE_C_ID=$(jq_field "$AGENT_C_JSON" '.machine_id')

USER_A_ID=$(jq_field "$AGENT_A_JSON" '.user_id')
USER_B_ID=$(jq_field "$AGENT_B_JSON" '.user_id')
USER_C_ID=$(jq_field "$AGENT_C_JSON" '.user_id')

echo "  Agent A: agent=$AGENT_A_ID machine=$MACHINE_A_ID user=$USER_A_ID"
echo "  Agent B: agent=$AGENT_B_ID machine=$MACHINE_B_ID user=$USER_B_ID"
echo "  Agent C: agent=$AGENT_C_ID machine=$MACHINE_C_ID user=$USER_C_ID"

# Each agent has a unique agent_id and machine_id
assert_not_empty "A has agent_id" "$AGENT_A_ID"
assert_not_empty "B has agent_id" "$AGENT_B_ID"
assert_not_empty "C has agent_id" "$AGENT_C_ID"

if [[ "$AGENT_A_ID" != "$AGENT_B_ID" && "$AGENT_A_ID" != "$AGENT_C_ID" && "$AGENT_B_ID" != "$AGENT_C_ID" ]]; then
    pass "All agent_ids are unique"
else
    fail "Agent IDs are not all unique"
fi

# A and B share user_id, C has none
assert_not_empty "A has user_id" "$USER_A_ID"
assert_not_empty "B has user_id" "$USER_B_ID"
assert_eq "A and B share the same user_id" "$USER_A_ID" "$USER_B_ID"
assert_empty_or_null "C has no user_id" "$USER_C_ID"

# ---------------------------------------------------------------------------
# Step 2: Announce identities
# ---------------------------------------------------------------------------
separator "Step 2: Announce identities"

# A and B announce with user identity
ANNOUNCE_A=$(api_json "$HOST_A" POST /announce "-d '{\"include_user_identity\": true, \"human_consent\": true}'")
ANNOUNCE_B=$(api_json "$HOST_B" POST /announce "-d '{\"include_user_identity\": true, \"human_consent\": true}'")
ANNOUNCE_C=$(api_json "$HOST_C" POST /announce "-d '{\"include_user_identity\": false, \"human_consent\": false}'")

assert_eq "A announced with user identity" "true" "$(jq_field "$ANNOUNCE_A" '.include_user_identity')"
assert_eq "B announced with user identity" "true" "$(jq_field "$ANNOUNCE_B" '.include_user_identity')"
assert_eq "C announced ok" "true" "$(jq_field "$ANNOUNCE_C" '.ok')"

echo "  Waiting 30s for gossip propagation..."
sleep 30

# ---------------------------------------------------------------------------
# Step 3: Check discovery
# ---------------------------------------------------------------------------
separator "Step 3: Check discovery"

DISCOVERED_A=$(api "$HOST_A" GET /agents/discovered)
DISCOVERED_B=$(api "$HOST_B" GET /agents/discovered)
DISCOVERED_C=$(api "$HOST_C" GET /agents/discovered)

DISCOVERED_A_IDS=$(jq_field "$DISCOVERED_A" '[.agents[].agent_id] | join(",")')
DISCOVERED_B_IDS=$(jq_field "$DISCOVERED_B" '[.agents[].agent_id] | join(",")')
DISCOVERED_C_IDS=$(jq_field "$DISCOVERED_C" '[.agents[].agent_id] | join(",")')

echo "  A discovered: $DISCOVERED_A_IDS"
echo "  B discovered: $DISCOVERED_B_IDS"
echo "  C discovered: $DISCOVERED_C_IDS"

# A sees B and C
assert_contains "A sees B" "$DISCOVERED_A_IDS" "$AGENT_B_ID"
assert_contains "A sees C" "$DISCOVERED_A_IDS" "$AGENT_C_ID"

# B sees A and C
assert_contains "B sees A" "$DISCOVERED_B_IDS" "$AGENT_A_ID"
assert_contains "B sees C" "$DISCOVERED_B_IDS" "$AGENT_C_ID"

# C sees A and B
assert_contains "C sees A" "$DISCOVERED_C_IDS" "$AGENT_A_ID"
assert_contains "C sees B" "$DISCOVERED_C_IDS" "$AGENT_B_ID"

# Check user_id fields in discovered entries
A_SEES_B_USER=$(jq_field "$DISCOVERED_A" ".agents[] | select(.agent_id==\"$AGENT_B_ID\") | .user_id")
A_SEES_C_USER=$(jq_field "$DISCOVERED_A" ".agents[] | select(.agent_id==\"$AGENT_C_ID\") | .user_id")

assert_eq "A sees B's user_id" "$USER_B_ID" "$A_SEES_B_USER"
assert_empty_or_null "A sees C has no user_id" "$A_SEES_C_USER"

# ---------------------------------------------------------------------------
# Step 4: Check presence
# ---------------------------------------------------------------------------
separator "Step 4: Check presence (TTL-filtered)"

PRESENCE_A=$(api "$HOST_A" GET /presence)
PRESENCE_IDS=$(jq_field "$PRESENCE_A" '.agents | join(",")')
echo "  Presence from A: $PRESENCE_IDS"

assert_contains "Presence includes A" "$PRESENCE_IDS" "${AGENT_A_ID:0:8}"
assert_contains "Presence includes B" "$PRESENCE_IDS" "${AGENT_B_ID:0:8}"
assert_contains "Presence includes C" "$PRESENCE_IDS" "${AGENT_C_ID:0:8}"

# ---------------------------------------------------------------------------
# Step 5: Look up a specific agent (3-stage find_agent)
# ---------------------------------------------------------------------------
separator "Step 5: Find specific agent (3-stage lookup)"

FIND_C_FROM_A=$(api "$HOST_A" GET "/agents/discovered/${AGENT_C_ID}?wait=true")
FIND_OK=$(jq_field "$FIND_C_FROM_A" '.ok')
FIND_AGENT_ID=$(jq_field "$FIND_C_FROM_A" '.agent.agent_id')

echo "  A looked up C: ok=$FIND_OK agent_id=$FIND_AGENT_ID"
assert_eq "find_agent returned ok" "true" "$FIND_OK"
assert_eq "find_agent returned correct agent" "$AGENT_C_ID" "$FIND_AGENT_ID"

# ---------------------------------------------------------------------------
# Step 6: Find all agents belonging to a user
# ---------------------------------------------------------------------------
separator "Step 6: Find agents by user"

# From C (anonymous) — look up the shared user_id
USER_AGENTS_FROM_C=$(api "$HOST_C" GET "/users/${USER_A_ID}/agents")
USER_AGENT_IDS=$(jq_field "$USER_AGENTS_FROM_C" '[.agents[].agent_id] | join(",")')
echo "  C queried user $USER_A_ID: found agents=$USER_AGENT_IDS"

assert_contains "User lookup includes A" "$USER_AGENT_IDS" "$AGENT_A_ID"
assert_contains "User lookup includes B" "$USER_AGENT_IDS" "$AGENT_B_ID"
assert_not_contains "User lookup excludes C" "$USER_AGENT_IDS" "$AGENT_C_ID"

# From A — "find my own user's agents"
USER_AGENTS_FROM_A=$(api "$HOST_A" GET "/users/${USER_A_ID}/agents")
USER_AGENT_IDS_A=$(jq_field "$USER_AGENTS_FROM_A" '[.agents[].agent_id] | join(",")')
echo "  A queried own user: found agents=$USER_AGENT_IDS_A"

assert_contains "A's user lookup includes A" "$USER_AGENT_IDS_A" "$AGENT_A_ID"
assert_contains "A's user lookup includes B" "$USER_AGENT_IDS_A" "$AGENT_B_ID"

# ---------------------------------------------------------------------------
# Step 7: Verify user ID configuration
# ---------------------------------------------------------------------------
separator "Step 7: Verify user ID endpoints"

USER_ID_A=$(jq_field "$(api "$HOST_A" GET /agent/user-id)" '.user_id')
USER_ID_B=$(jq_field "$(api "$HOST_B" GET /agent/user-id)" '.user_id')
USER_ID_C=$(jq_field "$(api "$HOST_C" GET /agent/user-id)" '.user_id')

assert_not_empty "A reports user_id" "$USER_ID_A"
assert_not_empty "B reports user_id" "$USER_ID_B"
assert_eq "A and B report same user_id" "$USER_ID_A" "$USER_ID_B"
assert_empty_or_null "C reports no user_id" "$USER_ID_C"

# ---------------------------------------------------------------------------
# Step 8: TTL expiry — stop agent B and wait
# ---------------------------------------------------------------------------
separator "Step 8: TTL expiry (stopping agent B)"

echo "  Stopping x0xd on B..."
ssh $SSH_OPTS "$HOST_B" "sudo systemctl stop x0xd" 2>/dev/null

echo "  Waiting 75s for TTL expiry (60s TTL + 15s buffer)..."
sleep 75

PRESENCE_AFTER=$(api "$HOST_A" GET /presence)
PRESENCE_AFTER_IDS=$(jq_field "$PRESENCE_AFTER" '.agents | join(",")')
echo "  Presence from A after B stopped: $PRESENCE_AFTER_IDS"

assert_not_contains "B is no longer present" "$PRESENCE_AFTER_IDS" "${AGENT_B_ID:0:8}"
assert_contains "A is still present" "$PRESENCE_AFTER_IDS" "${AGENT_A_ID:0:8}"
assert_contains "C is still present" "$PRESENCE_AFTER_IDS" "${AGENT_C_ID:0:8}"

# Also check find_agents_by_user — B should have dropped
USER_AGENTS_AFTER=$(api "$HOST_A" GET "/users/${USER_A_ID}/agents")
USER_AGENT_IDS_AFTER=$(jq_field "$USER_AGENTS_AFTER" '[.agents[].agent_id] | join(",")')
echo "  User agents after B stopped: $USER_AGENT_IDS_AFTER"

assert_contains "User lookup still includes A" "$USER_AGENT_IDS_AFTER" "$AGENT_A_ID"
assert_not_contains "User lookup no longer includes B" "$USER_AGENT_IDS_AFTER" "$AGENT_B_ID"

# ---------------------------------------------------------------------------
# Step 9: Late-join heartbeat discovery (restart B)
# ---------------------------------------------------------------------------
separator "Step 9: Late-join heartbeat discovery (restarting B)"

echo "  Restarting x0xd on B..."
ssh $SSH_OPTS "$HOST_B" "sudo systemctl start x0xd" 2>/dev/null

echo "  Waiting 45s for heartbeat propagation..."
sleep 45

DISCOVERED_B_AFTER=$(api "$HOST_B" GET /agents/discovered)
DISCOVERED_B_AFTER_IDS=$(jq_field "$DISCOVERED_B_AFTER" '[.agents[].agent_id] | join(",")')
echo "  B discovered after restart: $DISCOVERED_B_AFTER_IDS"

assert_contains "B rediscovers A" "$DISCOVERED_B_AFTER_IDS" "$AGENT_A_ID"
assert_contains "B rediscovers C" "$DISCOVERED_B_AFTER_IDS" "$AGENT_C_ID"

# Check B reappears in A's presence
PRESENCE_FINAL=$(api "$HOST_A" GET /presence)
PRESENCE_FINAL_IDS=$(jq_field "$PRESENCE_FINAL" '.agents | join(",")')
echo "  Final presence from A: $PRESENCE_FINAL_IDS"

assert_contains "B reappears in A's presence" "$PRESENCE_FINAL_IDS" "${AGENT_B_ID:0:8}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
separator "Results"

TOTAL=$((PASS + FAIL))
echo ""
echo "  Passed: $PASS / $TOTAL"
echo "  Failed: $FAIL / $TOTAL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "  TEST PLAN: FAILED"
    exit 1
else
    echo "  TEST PLAN: PASSED"
    exit 0
fi
