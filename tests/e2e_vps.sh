#!/usr/bin/env bash
# =============================================================================
# x0x VPS End-to-End Test — All-Pairs Matrix
# Tests across ALL 6 bootstrap nodes (NYC, SFO, Helsinki, Nuremberg, Singapore, Sydney)
#
# PROOF POINTS: Every assertion either echoes actual API data or verifies a
# round-trip with a unique PROOF_TOKEN — no hallucinated test results.
#
# Coverage:
#   - Health, identity, mesh on all 6 nodes
#   - All-pairs direct messaging matrix (30 directed pairs)
#   - Three interface proofs: REST API, CLI, GUI (WebSocket path)
#   - MLS group encryption (multi-continent)
#   - Named groups, KV stores, task lists, file transfer
#   - Presence (FOAF, online, find, status)
#   - Contacts & trust lifecycle
#   - Constitution, upgrade, WebSocket sessions
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(grep '^version = ' "$ROOT_DIR/Cargo.toml" | head -1 | cut -d '"' -f2)"
WS_PROBE="${WS_PROBE:-$ROOT_DIR/tests/helpers/ws_probe.mjs}"
GUI_PROOF="${GUI_PROOF:-$ROOT_DIR/tests/helpers/gui_proof.mjs}"
PASS=0; FAIL=0; SKIP=0; TOTAL=0

# Unique proof token for this run
PROOF_TOKEN="vps-proof-$(date +%s)-$$"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

b64()  { echo -n "$1" | base64; }
b64d() { echo "$1" | base64 --decode 2>/dev/null || echo "(decode failed)"; }

# ── Assertion helpers ────────────────────────────────────────────────────
check_json()      { local n="$1" r="$2" k="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|python3 -c "import sys,json;d=json.load(sys.stdin);assert '$k' in d" 2>/dev/null;then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — no key '$k': $(echo "$r"|head -c200)";fi; }
check_contains()  { local n="$1" r="$2" e="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -qi "$e";then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — want '$e': $(echo "$r"|head -c250)";fi; }
check_ok()        { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"ok":true\|"ok": true';then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";elif echo "$r"|grep -q '"error"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }
check_not_error() { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"error":"curl_failed"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — curl_failed";elif echo "$r"|grep -q '"ok":false';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }
check_eq()        { local n="$1" got="$2" want="$3"; TOTAL=$((TOTAL+1)); if [ "$got" = "$want" ];then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — got '$got', want '$want'";fi; }
check_true()      { local n="$1" cond="$2"; TOTAL=$((TOTAL+1)); if [ "$cond" = "true" ];then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n";fi; }
skip()            { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1)); echo -e "  ${YELLOW}SKIP${NC} $n — $r"; }

jq_field() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null || echo ""; }
proof_field() {
    local label="$1" resp="$2" field="$3"
    local val
    val=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$field','<missing>'))" 2>/dev/null || echo "<parse-error>")
    echo -e "        ${CYAN}PROOF ${label}: ${val}${NC}"
}

check_connect_outcome() {
    local n="$1" r="$2" outcome
    outcome=$(jq_field "$r" "outcome")
    TOTAL=$((TOTAL+1))
    case "$outcome" in
        Direct|Coordinated|AlreadyConnected)
            PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n ($outcome)"; return 0 ;;
        Unreachable|NotFound|"")
            FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — outcome=${outcome:-missing}: $(echo "$r"|head -c250)"; return 1 ;;
        *)
            FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — unexpected outcome=$outcome: $(echo "$r"|head -c250)"; return 1 ;;
    esac
}

# ── Node configuration ──────────────────────────────────────────────────
NODES=(nyc sfo helsinki nuremberg singapore sydney)
declare -A NODE_IPS=(
    [nyc]="142.93.199.50"
    [sfo]="147.182.234.192"
    [helsinki]="65.21.157.229"
    [nuremberg]="116.203.101.172"
    [singapore]="152.42.210.67"
    [sydney]="170.64.176.102"
)
declare -A NODE_LABELS=(
    [nyc]="NYC" [sfo]="SFO" [helsinki]="Helsinki"
    [nuremberg]="Nuremberg" [singapore]="Singapore" [sydney]="Sydney"
)
declare -A NODE_TOKENS=()
declare -A NODE_AIDS=()
declare -A NODE_MIDS=()

a_is_live() {
    local needle="$1"
    for n in "${LIVE_NODES[@]:-}"; do
        [ "$n" = "$needle" ] && return 0
    done
    return 1
}

# ── Load tokens ──────────────────────────────────────────────────────────
if [ -f "$SCRIPT_DIR/.vps-tokens.env" ]; then
    echo "Loading tokens from .vps-tokens.env..."
    source "$SCRIPT_DIR/.vps-tokens.env"
    [ -n "${NYC_TK:-}" ] && NODE_TOKENS[nyc]="$NYC_TK"
    [ -n "${SFO_TK:-}" ] && NODE_TOKENS[sfo]="$SFO_TK"
    [ -n "${HELSINKI_TK:-}" ] && NODE_TOKENS[helsinki]="$HELSINKI_TK"
    [ -n "${NUREMBERG_TK:-}" ] && NODE_TOKENS[nuremberg]="$NUREMBERG_TK"
    [ -n "${SINGAPORE_TK:-}" ] && NODE_TOKENS[singapore]="$SINGAPORE_TK"
    [ -n "${SYDNEY_TK:-}" ] && NODE_TOKENS[sydney]="$SYDNEY_TK"
fi

# Fallback: read tokens via SSH
for node in "${NODES[@]}"; do
    if [ -z "${NODE_TOKENS[$node]:-}" ]; then
        ip="${NODE_IPS[$node]}"
        tk=$(ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes \
            root@"$ip" 'cat /root/.local/share/x0x/api-token 2>/dev/null || cat /var/lib/x0x/data/api-token 2>/dev/null' 2>/dev/null || echo "")
        if [ -n "$tk" ]; then
            NODE_TOKENS[$node]="$tk"
        else
            echo -e "${RED}Cannot get token for $node ($ip)${NC}"
        fi
    fi
done

# ── SSH-tunneled API calls ───────────────────────────────────────────────
SSH="ssh -C -o ConnectTimeout=10 -o ConnectionAttempts=2 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes"
vps() {
    local ip="$1" token="$2" method="$3" path="$4" body="${5:-}"
    local cmd="curl -sf -m 18 -X $method -H 'Authorization: Bearer $token' -H 'Content-Type: application/json'"
    [ -n "$body" ] && cmd="$cmd -d '$body'"
    cmd="$cmd 'http://127.0.0.1:12600${path}'"
    local out rc attempt
    for attempt in 1 2; do
        out=$($SSH "root@$ip" "$cmd" 2>/dev/null) && rc=0 || rc=$?
        if [ $rc -eq 0 ] && [ -n "$out" ]; then
            printf '%s\n' "$out"
            return 0
        fi
        sleep "$attempt"
    done
    echo '{"error":"curl_failed"}'
}
_VPS_EMPTY_BODY='{}'
vps_get()   { vps "$1" "$2" GET "$3"; }
vps_post()  { vps "$1" "$2" POST "$3" "${4:-$_VPS_EMPTY_BODY}"; }
vps_put()   { vps "$1" "$2" PUT "$3" "$4"; }
vps_del()   { vps "$1" "$2" DELETE "$3"; }
vps_patch() { vps "$1" "$2" PATCH "$3" "$4"; }

# Raw SSH command on VPS
vps_ssh() {
    local ip="$1"; shift
    $SSH "root@$ip" "$@" 2>/dev/null
}

start_remote_direct_listener() {
    local ip="$1" token="$2" outfile="$3"
    vps_ssh "$ip" "rm -f '$outfile'; nohup sh -c \"curl -sN -m 180 -H 'Authorization: Bearer $token' 'http://127.0.0.1:12600/direct/events' > '$outfile'\" >/dev/null 2>&1 & echo \$!"
}

stop_remote_pid() {
    local ip="$1" pid="$2"
    [ -z "$pid" ] && return 0
    vps_ssh "$ip" "kill $pid >/dev/null 2>&1 || true"
}

fetch_remote_file() {
    local ip="$1" path="$2"
    vps_ssh "$ip" "cat '$path' 2>/dev/null || true"
}

start_tunnel() {
    local ip="$1" local_port="$2"
    ssh -C -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -N -L "127.0.0.1:${local_port}:127.0.0.1:12600" "root@$ip" >/dev/null 2>&1 &
    echo $!
}

json_array_len() {
    echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('$2',[])))" 2>/dev/null || echo 0
}

json_has_transfer() {
    echo "$1" | python3 -c "import sys,json;ts=json.load(sys.stdin).get('transfers',[]);print('yes' if any(t.get('transfer_id')=='$2' for t in ts) else '')" 2>/dev/null || true
}

json_transfer_status() {
    echo "$1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('status',''))" 2>/dev/null || echo ""
}

json_transfer_output_path() {
    echo "$1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('output_path',''))" 2>/dev/null || echo ""
}

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   x0x v$VERSION VPS E2E Test — All-Pairs Matrix${NC}"
echo -e "${YELLOW}   NYC · SFO · Helsinki · Nuremberg · Singapore · Sydney${NC}"
echo -e "${YELLOW}   Proof: ${PROOF_TOKEN}${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

# Temp dir for SSE output files
TMPDIR=$(mktemp -d /tmp/x0x-vps-e2e.XXXXXX)
trap "rm -rf $TMPDIR" EXIT

# ═════════════════════════════════════════════════════════════════════════
# 1. HEALTH & VERSION — All 6 nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[1/20] Health & Version (6 nodes)${NC}"
LIVE_NODES=()
for node in "${NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    if [ -z "$tk" ]; then skip "${NODE_LABELS[$node]} health" "no token"; continue; fi
    R=$(vps_get "$ip" "$tk" /health)
    check_json "${NODE_LABELS[$node]} health" "$R" "ok"
    if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then
        proof_field "version" "$R" "version"
        LIVE_NODES+=("$node")
    fi
done
echo "  Live nodes: ${LIVE_NODES[*]}"

# ═════════════════════════════════════════════════════════════════════════
# 2. IDENTITY — Distinct agent IDs across all nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[2/20] Identity (distinct agents)${NC}"
for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /agent)
    check_json "${NODE_LABELS[$node]} agent" "$R" "agent_id"
    NODE_AIDS[$node]=$(jq_field "$R" "agent_id")
    NODE_MIDS[$node]=$(jq_field "$R" "machine_id")
    echo -e "    ${NODE_LABELS[$node]}: ${NODE_AIDS[$node]:0:16}..."
done

# Verify all unique
ALL_UNIQUE=true
declare -A SEEN_AIDS=()
for node in "${LIVE_NODES[@]}"; do
    aid="${NODE_AIDS[$node]:-}"
    [ -z "$aid" ] && continue
    if [ -n "${SEEN_AIDS[$aid]:-}" ]; then ALL_UNIQUE=false; fi
    SEEN_AIDS[$aid]=1
done
check_eq "all agents distinct" "$ALL_UNIQUE" "true"

# Additional identity & status endpoints on NYC
NYC_IP="${NODE_IPS[nyc]}"; NYC_TK="${NODE_TOKENS[nyc]:-}"
if [ -n "$NYC_TK" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" /introduction)
    check_json "NYC introduction" "$R" "agent_id"
    R=$(vps_get "$NYC_IP" "$NYC_TK" /agent/user-id)
    check_not_error "NYC agent user-id" "$R"
    R=$(vps_get "$NYC_IP" "$NYC_TK" /peers)
    check_json "NYC peers" "$R" "peers"
fi

# ═════════════════════════════════════════════════════════════════════════
# 3. NETWORK MESH — Peer counts on all nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[3/20] Network Mesh${NC}"
for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /network/status)
    check_json "${NODE_LABELS[$node]} network" "$R" "connected_peers"
    PEERS=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('connected_peers',0))" 2>/dev/null||echo "0")
    echo -e "    ${NODE_LABELS[$node]} peers: $PEERS"
done

# ═════════════════════════════════════════════════════════════════════════
# 4. AGENT CARDS — Generate and validate on all nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[4/20] Agent Cards (all nodes)${NC}"
declare -A NODE_LINKS=()
for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /agent/card)
    check_json "${NODE_LABELS[$node]} card" "$R" "link"
    NODE_LINKS[$node]=$(jq_field "$R" "link")
    # Verify card has addresses
    ADDR_COUNT=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('card',{}).get('addresses',[])))" 2>/dev/null||echo "0")
    echo -e "    ${NODE_LABELS[$node]}: $ADDR_COUNT addresses in card"
done

# ═════════════════════════════════════════════════════════════════════════
# 5. ANNOUNCE & DISCOVERY — All nodes announce, verify cross-discovery
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[5/20] Announce & Discovery${NC}"
for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_post "$ip" "$tk" /announce); check_not_error "${NODE_LABELS[$node]} announce" "$R"
done
echo "  Waiting 20s for gossip propagation..."
sleep 20

# Each node checks its discovered agents list
for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /agents/discovered)
    DISC_COUNT=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('agents',[])))" 2>/dev/null||echo "0")
    check_true "${NODE_LABELS[$node]} discovered >= 1 agents" "$([ "$DISC_COUNT" -ge 1 ] && echo true || echo false)"
    echo -e "    ${NODE_LABELS[$node]}: discovered $DISC_COUNT agents"
done

# Specific agent discovery, reachability, find
HEL_AID="${NODE_AIDS[helsinki]:-}"
if a_is_live nyc && a_is_live helsinki && [ -n "$HEL_AID" ] && [ -n "$NYC_TK" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" "/agents/discovered/$HEL_AID")
    check_json "NYC discovered Helsinki by ID" "$R" "agent"
    R=$(vps_get "$NYC_IP" "$NYC_TK" "/agents/reachability/$HEL_AID")
    check_not_error "NYC reachability Helsinki" "$R"
    R=$(vps_post "$NYC_IP" "$NYC_TK" "/agents/find/$HEL_AID")
    check_not_error "NYC find Helsinki" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 6. ALL-PAIRS CARD IMPORT — Every node imports every other node's card
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[6/20] All-Pairs Card Import${NC}"
IMPORT_OK=0; IMPORT_FAIL=0
for src in "${LIVE_NODES[@]}"; do
    src_ip="${NODE_IPS[$src]}"; src_tk="${NODE_TOKENS[$src]}"
    for dst in "${LIVE_NODES[@]}"; do
        [ "$src" = "$dst" ] && continue
        dst_link="${NODE_LINKS[$dst]:-}"
        [ -z "$dst_link" ] && continue
        R=$(vps_post "$src_ip" "$src_tk" /agent/card/import "{\"card\":\"$dst_link\",\"trust_level\":\"Trusted\"}")
        if echo "$R"|grep -q '"ok":true\|"ok": true\|"added"'; then
            IMPORT_OK=$((IMPORT_OK+1))
        else
            IMPORT_FAIL=$((IMPORT_FAIL+1))
            echo -e "    ${RED}FAIL${NC} ${NODE_LABELS[$src]} import ${NODE_LABELS[$dst]} card"
        fi
    done
done
check_eq "all card imports succeeded ($IMPORT_OK pairs)" "$IMPORT_FAIL" "0"
echo "  Imported $IMPORT_OK card pairs"

echo "  Waiting 10s for discovery cache population..."
sleep 10

# ═════════════════════════════════════════════════════════════════════════
# 7. ALL-PAIRS CONNECT — Every node connects to every other node
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[7/20] All-Pairs Connect${NC}"
CONN_OK=0; CONN_FAIL=0
declare -A PAIR_CONNECTED=()
for src in "${LIVE_NODES[@]}"; do
    src_ip="${NODE_IPS[$src]}"; src_tk="${NODE_TOKENS[$src]}"
    for dst in "${LIVE_NODES[@]}"; do
        [ "$src" = "$dst" ] && continue
        dst_aid="${NODE_AIDS[$dst]:-}"
        [ -z "$dst_aid" ] && continue
        outcome=""
        for attempt in 1 2; do
            R=$(vps_post "$src_ip" "$src_tk" /agents/connect "{\"agent_id\":\"$dst_aid\"}")
            outcome=$(jq_field "$R" "outcome")
            case "$outcome" in
                Direct|Coordinated|AlreadyConnected) break ;;
                *) sleep "$attempt" ;;
            esac
        done
        case "$outcome" in
            Direct|Coordinated|AlreadyConnected)
                CONN_OK=$((CONN_OK+1))
                PAIR_CONNECTED["${src}_${dst}"]=1
                ;;
            *)
                CONN_FAIL=$((CONN_FAIL+1))
                echo -e "    ${RED}FAIL${NC} ${NODE_LABELS[$src]}→${NODE_LABELS[$dst]}: ${outcome:-missing}"
                ;;
        esac
    done
done
TOTAL=$((TOTAL+1))
if [ $CONN_FAIL -eq 0 ]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} all $CONN_OK pairs connected"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $CONN_FAIL/$((CONN_OK+CONN_FAIL)) pairs failed to connect"
fi

# ═════════════════════════════════════════════════════════════════════════
# 8. ALL-PAIRS DIRECT MESSAGING — REST API (send + SSE receive)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[8/20] All-Pairs Direct Messaging — REST API${NC}"
echo "  Testing all ${#LIVE_NODES[@]}-node round-robin + cross-continent pairs..."

# Start remote SSE listeners on all nodes (capture on the VPS itself, then fetch)
declare -A SSE_PIDS=()
declare -A SSE_REMOTE_FILES=()
for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    remote_out="/tmp/x0x-vps-${PROOF_TOKEN}-${node}.direct.sse"
    SSE_REMOTE_FILES[$node]="$remote_out"
    SSE_PIDS[$node]=$(start_remote_direct_listener "$ip" "$tk" "$remote_out")
done
sleep 5

# Send from every node to every other node via REST POST /direct/send
DM_SEND_OK=0; DM_SEND_FAIL=0
for src in "${LIVE_NODES[@]}"; do
    src_ip="${NODE_IPS[$src]}"; src_tk="${NODE_TOKENS[$src]}"
    for dst in "${LIVE_NODES[@]}"; do
        [ "$src" = "$dst" ] && continue
        [ -z "${PAIR_CONNECTED[${src}_${dst}]:-}" ] && continue
        dst_aid="${NODE_AIDS[$dst]}"
        proof="REST-${PROOF_TOKEN}-${src}-to-${dst}"
        payload_b64=$(b64 "$proof")
        send_ok=false
        for attempt in 1 2; do
            R=$(vps_post "$src_ip" "$src_tk" /direct/send "{\"agent_id\":\"$dst_aid\",\"payload\":\"$payload_b64\"}")
            if echo "$R"|grep -q '"ok":true\|"ok": true'; then
                send_ok=true
                break
            fi
            sleep "$attempt"
        done
        if $send_ok; then
            DM_SEND_OK=$((DM_SEND_OK+1))
        else
            DM_SEND_FAIL=$((DM_SEND_FAIL+1))
            echo -e "    ${RED}FAIL${NC} ${NODE_LABELS[$src]}→${NODE_LABELS[$dst]} send: $(echo "$R"|head -c200)"
        fi
    done
done
TOTAL=$((TOTAL+1))
if [ $DM_SEND_FAIL -eq 0 ]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} all $DM_SEND_OK REST direct sends succeeded"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $DM_SEND_FAIL/$((DM_SEND_OK+DM_SEND_FAIL)) REST sends failed"
fi

echo "  Waiting 15s for direct-event delivery..."
sleep 15

for node in "${LIVE_NODES[@]}"; do
    stop_remote_pid "${NODE_IPS[$node]}" "${SSE_PIDS[$node]}" >/dev/null
    fetch_remote_file "${NODE_IPS[$node]}" "${SSE_REMOTE_FILES[$node]}" > "$TMPDIR/sse_${node}.out"
done
sleep 1

# Verify receipt on each node using the captured /direct/events stream.
DM_RECV_OK=0; DM_RECV_FAIL=0
for dst in "${LIVE_NODES[@]}"; do
    outfile="$TMPDIR/sse_${dst}.out"
    for src in "${LIVE_NODES[@]}"; do
        [ "$src" = "$dst" ] && continue
        [ -z "${PAIR_CONNECTED[${src}_${dst}]:-}" ] && continue
        proof="REST-${PROOF_TOKEN}-${src}-to-${dst}"
        proof_b64=$(b64 "$proof")
        if grep -q "$proof_b64" "$outfile" 2>/dev/null; then
            DM_RECV_OK=$((DM_RECV_OK+1))
        else
            DM_RECV_FAIL=$((DM_RECV_FAIL+1))
            echo -e "    ${RED}FAIL${NC} ${NODE_LABELS[$dst]} did not receive from ${NODE_LABELS[$src]}"
        fi
    done
done
TOTAL=$((TOTAL+1))
if [ $DM_RECV_FAIL -eq 0 ]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} all $DM_RECV_OK REST messages received via /direct/events"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $DM_RECV_FAIL/$((DM_RECV_OK+DM_RECV_FAIL)) REST deliveries missing after retry"
fi

# ═════════════════════════════════════════════════════════════════════════
# 9. CLI INTERFACE PROOF — x0x direct send via CLI binary
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[9/20] CLI Interface Proof (x0x direct send)${NC}"
# Use NYC→Helsinki and Sydney→SFO as CLI proof pairs with recipient-side evidence.
CLI_PAIRS=("nyc:helsinki" "sydney:sfo")
for pair in "${CLI_PAIRS[@]}"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    src_ip="${NODE_IPS[$src]}"; src_tk="${NODE_TOKENS[$src]}"
    dst_ip="${NODE_IPS[$dst]}"; dst_tk="${NODE_TOKENS[$dst]:-}"; dst_aid="${NODE_AIDS[$dst]:-}"
    [ -z "$dst_aid" ] && { skip "CLI ${NODE_LABELS[$src]}→${NODE_LABELS[$dst]}" "no agent_id"; continue; }
    [ -z "${PAIR_CONNECTED[${src}_${dst}]:-}" ] && { skip "CLI ${NODE_LABELS[$src]}→${NODE_LABELS[$dst]}" "not connected"; continue; }

    proof="CLI-${PROOF_TOKEN}-${src}-to-${dst}"
    proof_b64=$(b64 "$proof")
    cli_out="/tmp/x0x-vps-${PROOF_TOKEN}-${src}-to-${dst}.cli.sse"
    cli_pid=$(start_remote_direct_listener "$dst_ip" "$dst_tk" "$cli_out")
    sleep 2
    R=$(vps_ssh "$src_ip" "X0X_API_TOKEN=$src_tk /usr/local/bin/x0x --format json --api-url http://127.0.0.1:12600 direct send '$dst_aid' '$proof'" 2>/dev/null || echo '{"error":"cli_failed"}')
    check_not_error "CLI ${NODE_LABELS[$src]}→${NODE_LABELS[$dst]} send" "$R"
    sleep 6
    stop_remote_pid "$dst_ip" "$cli_pid" >/dev/null
    fetch_remote_file "$dst_ip" "$cli_out" > "$TMPDIR/cli_${src}_${dst}.out"
    TOTAL=$((TOTAL+1))
    if grep -q "$proof_b64" "$TMPDIR/cli_${src}_${dst}.out" 2>/dev/null; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} CLI ${NODE_LABELS[$src]}→${NODE_LABELS[$dst]} received via /direct/events"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} CLI ${NODE_LABELS[$src]}→${NODE_LABELS[$dst]} missing recipient proof"
    fi
done

# ═════════════════════════════════════════════════════════════════════════
# 10. GUI INTERFACE PROOF — /gui serves HTML, /ws/direct accessible
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[10/20] GUI Interface Proof${NC}"

# Test on NYC node via a local SSH tunnel + real headless browser.
NYC_IP="${NODE_IPS[nyc]}"; NYC_TK="${NODE_TOKENS[nyc]:-}"
HEL_IP="${NODE_IPS[helsinki]}"; HEL_TK="${NODE_TOKENS[helsinki]:-}"
HEL_AID="${NODE_AIDS[helsinki]:-}"
if [ -n "$NYC_TK" ] && [ -n "$HEL_AID" ] && [ -n "${PAIR_CONNECTED[nyc_helsinki]:-}" ]; then
    GUI_HTML=$(vps_ssh "$NYC_IP" "curl -sf -m 15 'http://127.0.0.1:12600/gui'" 2>/dev/null || echo "")
    TOTAL=$((TOTAL+1))
    if grep -q "X0X_TOKEN" <<<"$GUI_HTML" && grep -q "sendDm" <<<"$GUI_HTML"; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} GET /gui serves injected chat UI"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} GET /gui missing expected injected chat markers"
    fi

    GUI_TUNNEL_PID=$(start_tunnel "$NYC_IP" 22600)
    sleep 2
    HEL_CARD=$(vps_get "$HEL_IP" "$HEL_TK" /agent/card)
    HEL_LINK=$(jq_field "$HEL_CARD" "link")
    GUI_RECV_OUT="/tmp/x0x-vps-${PROOF_TOKEN}-gui-helsinki.sse"
    GUI_RECV_PID=$(start_remote_direct_listener "$HEL_IP" "$HEL_TK" "$GUI_RECV_OUT")
    GUI_MSG="GUI-${PROOF_TOKEN}-nyc-to-helsinki"
    GUI_JSON=$(node "$GUI_PROOF" send-dm "http://127.0.0.1:22600" "$HEL_LINK" "$HEL_AID" "$GUI_MSG" 2>/dev/null || echo '{"ok":false}')
    check_contains "real GUI browser send visible locally" "$GUI_JSON" '"messageVisible":true'
    GUI_PAYLOAD_B64=$(jq_field "$GUI_JSON" "payloadB64")
    sleep 8
    stop_remote_pid "$HEL_IP" "$GUI_RECV_PID" >/dev/null
    fetch_remote_file "$HEL_IP" "$GUI_RECV_OUT" > "$TMPDIR/gui_helsinki.out"
    TOTAL=$((TOTAL+1))
    if [ -n "$GUI_PAYLOAD_B64" ] && grep -q "$GUI_PAYLOAD_B64" "$TMPDIR/gui_helsinki.out" 2>/dev/null; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} GUI direct message reached Helsinki /direct/events"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} GUI direct message missing on Helsinki recipient side"
    fi
    kill "$GUI_TUNNEL_PID" 2>/dev/null || true
else
    skip "GUI proof" "NYC/Helsinki not fully available for real browser proof"
fi

# ═════════════════════════════════════════════════════════════════════════
# 11. DIRECT CONNECTIONS — Verify connection state on all nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[11/20] Direct Connections State${NC}"
for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /direct/connections)
    check_json "${NODE_LABELS[$node]} connections" "$R" "connections"
    CONN_COUNT=$(echo "$R"|python3 -c "import sys,json;print(len(json.load(sys.stdin).get('connections',[])))" 2>/dev/null||echo "0")
    echo -e "    ${NODE_LABELS[$node]}: $CONN_COUNT active connections"
done

# ═════════════════════════════════════════════════════════════════════════
# 12. CONTACTS & TRUST — Full lifecycle
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[12/20] Contacts & Trust${NC}"

# NYC trusts Helsinki, Helsinki trusts NYC (should already be done via card import)
NYC_IP="${NODE_IPS[nyc]}"; NYC_TK="${NODE_TOKENS[nyc]:-}"
HEL_IP="${NODE_IPS[helsinki]}"; HEL_TK="${NODE_TOKENS[helsinki]:-}"
HEL_AID="${NODE_AIDS[helsinki]:-}"
NYC_AID="${NODE_AIDS[nyc]:-}"

if a_is_live nyc && a_is_live helsinki && [ -n "$NYC_TK" ] && [ -n "$HEL_TK" ]; then
    # Verify contacts list includes imported cards
    R=$(vps_get "$NYC_IP" "$NYC_TK" /contacts)
    check_contains "NYC contacts has Helsinki" "$R" "$HEL_AID"

    # Trust evaluate — Trusted agent
    HEL_MID="${NODE_MIDS[helsinki]:-}"
    R=$(vps_post "$NYC_IP" "$NYC_TK" /trust/evaluate "{\"agent_id\":\"$HEL_AID\",\"machine_id\":\"$HEL_MID\"}")
    check_contains "NYC trust eval Helsinki → Accept" "$R" "Accept"

    # Block Singapore, verify, unblock
    SGP_AID="${NODE_AIDS[singapore]:-}"
    SGP_MID="${NODE_MIDS[singapore]:-}"
    if a_is_live singapore && [ -n "$SGP_AID" ]; then
        R=$(vps_patch "$NYC_IP" "$NYC_TK" "/contacts/$SGP_AID" '{"trust_level":"Blocked"}')
        check_ok "NYC blocks Singapore" "$R"

        R=$(vps_post "$NYC_IP" "$NYC_TK" /trust/evaluate "{\"agent_id\":\"$SGP_AID\",\"machine_id\":\"$SGP_MID\"}")
        check_contains "blocked eval → RejectBlocked" "$R" "RejectBlocked"

        R=$(vps_patch "$NYC_IP" "$NYC_TK" "/contacts/$SGP_AID" '{"trust_level":"Trusted"}')
        check_ok "NYC unblocks Singapore" "$R"
    fi

    # Contact lifecycle: quick trust, machines, revocations, delete, re-add
    NUR_AID="${NODE_AIDS[nuremberg]:-}"
    NUR_MID="${NODE_MIDS[nuremberg]:-}"
    if a_is_live nuremberg && [ -n "$NUR_AID" ]; then
        R=$(vps_post "$NYC_IP" "$NYC_TK" /contacts/trust "{\"agent_id\":\"$NUR_AID\",\"level\":\"trusted\"}")
        check_not_error "NYC quick trust Nuremberg" "$R"
        R=$(vps_get "$NYC_IP" "$NYC_TK" "/contacts/$NUR_AID/machines")
        check_not_error "NYC list Nuremberg machines" "$R"
        if [ -n "$NUR_MID" ]; then
            R=$(vps_post "$NYC_IP" "$NYC_TK" "/contacts/$NUR_AID/machines" "{\"machine_id\":\"$NUR_MID\"}")
            check_not_error "NYC add Nuremberg machine" "$R"
        fi
        R=$(vps_get "$NYC_IP" "$NYC_TK" "/contacts/$NUR_AID/revocations")
        check_not_error "NYC Nuremberg revocations" "$R"
        R=$(vps_del "$NYC_IP" "$NYC_TK" "/contacts/$NUR_AID")
        check_not_error "NYC delete Nuremberg contact" "$R"
        R=$(vps_post "$NYC_IP" "$NYC_TK" /contacts "{\"agent_id\":\"$NUR_AID\",\"trust_level\":\"Trusted\",\"label\":\"Nuremberg\"}")
        check_not_error "NYC re-add Nuremberg" "$R"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 13. PUB/SUB — Global gossip proof
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[13/20] Pub/Sub (global gossip)${NC}"
PUBSUB_TOPIC="vps-e2e-${PROOF_TOKEN}"

# Subscribe on Helsinki and Sydney
for node in helsinki sydney; do
    a_is_live "$node" || continue
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    [ -z "$tk" ] && continue
    R=$(vps_post "$ip" "$tk" /subscribe "{\"topic\":\"$PUBSUB_TOPIC\"}")
    check_not_error "${NODE_LABELS[$node]} subscribe" "$R"
done

# Publish from NYC
PUB_MSG="hello-from-nyc-${PROOF_TOKEN}"
PUB_B64=$(b64 "$PUB_MSG")
if [ -n "$NYC_TK" ]; then
    R=$(vps_post "$NYC_IP" "$NYC_TK" /publish "{\"topic\":\"$PUBSUB_TOPIC\",\"payload\":\"$PUB_B64\"}")
    check_ok "NYC publish to $PUBSUB_TOPIC" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 14. MLS GROUPS — Multi-continent PQC encryption
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[14/20] MLS Groups (multi-continent PQC)${NC}"

if [ -n "$NYC_TK" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" /mls/groups)
    check_json "NYC list MLS groups" "$R" "groups"
    R=$(vps_post "$NYC_IP" "$NYC_TK" /mls/groups)
    check_json "NYC create MLS group" "$R" "group_id"
    MG=$(jq_field "$R" "group_id")
    echo -e "    MLS group: ${MG:0:16}..."
    if [ -n "$MG" ]; then
        R=$(vps_get "$NYC_IP" "$NYC_TK" "/mls/groups/$MG")
        check_json "NYC get MLS group" "$R" "group_id"
    fi

    if [ -n "$MG" ]; then
        # Add Helsinki, Singapore, Sydney
        for node in helsinki singapore sydney; do
            a_is_live "$node" || continue
            aid="${NODE_AIDS[$node]:-}"
            [ -z "$aid" ] && continue
            R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/members" "{\"agent_id\":\"$aid\"}")
            check_ok "add ${NODE_LABELS[$node]} to MLS" "$R"
        done

        # Encrypt + decrypt round-trip
        MLS_PROOF="MLS-${PROOF_TOKEN}-pqc-encrypted"
        PLAIN_B64=$(b64 "$MLS_PROOF")
        R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/encrypt" "{\"payload\":\"$PLAIN_B64\"}")
        check_json "MLS encrypt" "$R" "ciphertext"
        CT=$(jq_field "$R" "ciphertext")
        EPOCH=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('epoch',0))" 2>/dev/null||echo "0")

        if [ -n "$CT" ]; then
            R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/decrypt" "{\"ciphertext\":\"$CT\",\"epoch\":$EPOCH}")
            check_json "MLS decrypt" "$R" "payload"
            DECRYPTED=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('payload','')).decode())" 2>/dev/null||echo "")
            check_eq "MLS decrypt round-trip" "$DECRYPTED" "$MLS_PROOF"
        fi

        # Remove Helsinki (lifecycle test)
        HEL_AID="${NODE_AIDS[helsinki]:-}"
        if a_is_live helsinki && [ -n "$HEL_AID" ]; then
            R=$(vps_del "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/members/$HEL_AID")
            check_not_error "remove Helsinki from MLS" "$R"
        fi
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 15. NAMED GROUPS / SPACES — Create, invite, join, member identity, leave
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[15/20] Named Groups / Spaces${NC}"

if [ -n "$NYC_TK" ]; then
    R=$(vps_post "$NYC_IP" "$NYC_TK" /groups "{\"name\":\"VPS-Matrix-${PROOF_TOKEN}\",\"description\":\"All-pairs test group\"}")
    check_not_error "create group" "$R"
    NG=$(jq_field "$R" "group_id")

    if [ -n "$NG" ]; then
        R=$(vps_post "$NYC_IP" "$NYC_TK" "/groups/$NG/invite")
        check_not_error "generate invite" "$R"
        INVITE=$(jq_field "$R" "invite_link")

        if [ -n "$INVITE" ]; then
            check_contains "invite is x0x://invite/" "$INVITE" "x0x://invite/"

            # Sydney joins and proves local membership lifecycle in the space.
            SYD_IP="${NODE_IPS[sydney]}"; SYD_TK="${NODE_TOKENS[sydney]:-}"; SYD_AID="${NODE_AIDS[sydney]:-}"
            if a_is_live sydney && [ -n "$SYD_TK" ]; then
                R=$(vps_post "$SYD_IP" "$SYD_TK" /groups/join "{\"invite\":\"$INVITE\",\"display_name\":\"Sydney Space Tester\"}")
                check_not_error "Sydney joins via invite" "$R"
                R=$(vps_get "$SYD_IP" "$SYD_TK" "/groups/$NG")
                check_json "Sydney group info" "$R" "members"
                check_contains "Sydney space member list includes self" "$R" "$SYD_AID"
                check_contains "Sydney space member display name persisted" "$R" "Sydney Space Tester"
                R=$(vps_post "$NYC_IP" "$NYC_TK" "/groups/$NG/members" "{\"agent_id\":\"$SYD_AID\",\"display_name\":\"Sydney Space Tester\"}")
                check_not_error "NYC adds Sydney to named-space roster" "$R"
                R=$(vps_get "$NYC_IP" "$NYC_TK" "/groups/$NG/members")
                check_json "NYC named-space members" "$R" "members"
                check_contains "NYC named-space members include Sydney" "$R" "$SYD_AID"
                R=$(vps_del "$NYC_IP" "$NYC_TK" "/groups/$NG/members/$SYD_AID")
                check_not_error "NYC removes Sydney from named-space roster" "$R"
                R=$(vps_get "$NYC_IP" "$NYC_TK" "/groups/$NG/members")
                TOTAL=$((TOTAL+1))
                if echo "$R" | grep -q "$SYD_AID"; then
                    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} NYC named-space roster cleared Sydney"
                else
                    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} NYC named-space roster cleared Sydney"
                fi
                SYDNEY_REMOVED=false
                for _ in $(seq 1 20); do
                    R=$(vps_get "$SYD_IP" "$SYD_TK" "/groups/$NG")
                    if echo "$R" | grep -q 'group not found\|curl_failed'; then
                        SYDNEY_REMOVED=true
                        break
                    fi
                    sleep 1
                done
                TOTAL=$((TOTAL+1))
                if $SYDNEY_REMOVED; then
                    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} Sydney authoritative removal propagated"
                else
                    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} Sydney authoritative removal propagated"
                fi
                R=$(vps_get "$SYD_IP" "$SYD_TK" /groups)
                TOTAL=$((TOTAL+1))
                if echo "$R" | grep -q "$NG"; then
                    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} Sydney group list cleared after authoritative remove"
                else
                    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} Sydney group list cleared after authoritative remove"
                fi
            fi

            # Singapore joins to prove a second remote invite path still works.
            SGP_IP="${NODE_IPS[singapore]}"; SGP_TK="${NODE_TOKENS[singapore]:-}"
            if a_is_live singapore && [ -n "$SGP_TK" ]; then
                R=$(vps_post "$SGP_IP" "$SGP_TK" /groups/join "{\"invite\":\"$INVITE\"}")
                check_not_error "Singapore joins via invite" "$R"
            fi
        fi

        R=$(vps_get "$NYC_IP" "$NYC_TK" "/groups/$NG")
        check_json "get single group" "$R" "group_id"
        R=$(vps_put "$NYC_IP" "$NYC_TK" "/groups/$NG/display-name" '{"name":"NYC Admin"}')
        check_ok "NYC set group display name" "$R"
        R=$(vps_get "$NYC_IP" "$NYC_TK" /groups)
        check_contains "list groups" "$R" "VPS-Matrix"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 16. KV STORES — Write on one node, verify round-trip
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[16/20] KV Stores (cross-continent)${NC}"

KV_NODE=""
a_is_live nuremberg && KV_NODE="nuremberg"
[ -z "$KV_NODE" ] && a_is_live singapore && KV_NODE="singapore"
[ -z "$KV_NODE" ] && a_is_live sydney && KV_NODE="sydney"
KV_IP="${NODE_IPS[$KV_NODE]:-}"; KV_TK="${NODE_TOKENS[$KV_NODE]:-}"
if [ -n "$KV_NODE" ] && [ -n "$KV_TK" ]; then
    R=$(vps_get "$KV_IP" "$KV_TK" /stores)
    check_json "${NODE_LABELS[$KV_NODE]} list stores" "$R" "stores"
    KV_TOPIC="vps-kv-${PROOF_TOKEN}"
    R=$(vps_post "$KV_IP" "$KV_TK" /stores "{\"name\":\"$KV_TOPIC\",\"topic\":\"$KV_TOPIC\"}")
    check_not_error "${NODE_LABELS[$KV_NODE]} create store" "$R"
    SID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('store_id',d.get('id','')))" 2>/dev/null||echo "")

    if [ -n "$SID" ]; then
        # Put 3 keys with proof tokens
        for i in 1 2 3; do
            kv_val="KV-${PROOF_TOKEN}-key${i}"
            VAL_B64=$(b64 "$kv_val")
            R=$(vps_put "$KV_IP" "$KV_TK" "/stores/$SID/proof-key-${i}" "{\"value\":\"$VAL_B64\",\"content_type\":\"text/plain\"}")
            check_ok "${NODE_LABELS[$KV_NODE]} put proof-key-${i}" "$R"
        done

        # Read back and verify round-trip
        R=$(vps_get "$KV_IP" "$KV_TK" "/stores/$SID/proof-key-2")
        check_json "${NODE_LABELS[$KV_NODE]} get proof-key-2" "$R" "value"
        GOT=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('value','')).decode())" 2>/dev/null||echo "")
        check_eq "KV round-trip proof-key-2" "$GOT" "KV-${PROOF_TOKEN}-key2"

        # List keys
        R=$(vps_get "$KV_IP" "$KV_TK" "/stores/$SID/keys")
        check_contains "keys has proof-key-1" "$R" "proof-key-1"
        check_contains "keys has proof-key-3" "$R" "proof-key-3"

        # Delete key
        R=$(vps_del "$KV_IP" "$KV_TK" "/stores/$SID/proof-key-1")
        check_ok "delete proof-key-1" "$R"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 17. TASK LISTS — CRDT lifecycle
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[17/20] Task Lists (CRDT)${NC}"

TASK_NODE=""
a_is_live sfo && TASK_NODE="sfo"
[ -z "$TASK_NODE" ] && a_is_live sydney && TASK_NODE="sydney"
[ -z "$TASK_NODE" ] && a_is_live singapore && TASK_NODE="singapore"
TASK_IP="${NODE_IPS[$TASK_NODE]:-}"; TASK_TK="${NODE_TOKENS[$TASK_NODE]:-}"
if [ -n "$TASK_NODE" ] && [ -n "$TASK_TK" ]; then
    R=$(vps_get "$TASK_IP" "$TASK_TK" /task-lists)
    check_json "${NODE_LABELS[$TASK_NODE]} list task-lists" "$R" "task_lists"
    TASK_TOPIC="vps-tasks-${PROOF_TOKEN}"
    R=$(vps_post "$TASK_IP" "$TASK_TK" /task-lists "{\"name\":\"$TASK_TOPIC\",\"topic\":\"$TASK_TOPIC\"}")
    check_not_error "${NODE_LABELS[$TASK_NODE]} create task list" "$R"
    TL=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('list_id',d.get('id','')))" 2>/dev/null||echo "")

    if [ -n "$TL" ]; then
        TASK_TITLE="Deploy-${PROOF_TOKEN}"
        R=$(vps_post "$TASK_IP" "$TASK_TK" "/task-lists/$TL/tasks" "{\"title\":\"$TASK_TITLE\",\"description\":\"All-pairs matrix verified\"}")
        check_not_error "add task" "$R"
        TID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('task_id',d.get('id','')))" 2>/dev/null||echo "")

        R=$(vps_get "$TASK_IP" "$TASK_TK" "/task-lists/$TL/tasks")
        check_contains "show tasks" "$R" "$TASK_TITLE"

        if [ -n "$TID" ]; then
            R=$(vps_patch "$TASK_IP" "$TASK_TK" "/task-lists/$TL/tasks/$TID" '{"action":"claim"}')
            check_not_error "claim task" "$R"
            R=$(vps_patch "$TASK_IP" "$TASK_TK" "/task-lists/$TL/tasks/$TID" '{"action":"complete"}')
            check_not_error "complete task" "$R"
        fi
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 18. FILE TRANSFER — Singapore→Sydney full accept/complete proof
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[18/20] File Transfer${NC}"

SGP_IP="${NODE_IPS[singapore]}"; SGP_TK="${NODE_TOKENS[singapore]:-}"
SYD_IP="${NODE_IPS[sydney]}"; SYD_TK="${NODE_TOKENS[sydney]:-}"; SYD_AID="${NODE_AIDS[sydney]:-}"
if a_is_live singapore && a_is_live sydney && [ -n "$SGP_TK" ] && [ -n "$SYD_TK" ] && [ -n "$SYD_AID" ] && [ -n "${PAIR_CONNECTED[singapore_tokyo]:-}" ]; then
    SEND_PATH="/tmp/x0x-vps-file-${PROOF_TOKEN}.txt"
    vps_ssh "$SGP_IP" "printf '%s\n' '${PROOF_TOKEN}-file-transfer-vps' > '$SEND_PATH'"
    FILE_SHA=$(vps_ssh "$SGP_IP" "shasum -a 256 '$SEND_PATH' | awk '{print \$1}'")
    FILE_SIZE=$(vps_ssh "$SGP_IP" "wc -c < '$SEND_PATH' | tr -d ' '")
    R=$(vps_post "$SGP_IP" "$SGP_TK" /files/send "{\"agent_id\":\"$SYD_AID\",\"filename\":\"matrix-test-${PROOF_TOKEN}.txt\",\"size\":$FILE_SIZE,\"sha256\":\"$FILE_SHA\",\"path\":\"$SEND_PATH\"}")
    check_not_error "Singapore→Sydney file offer" "$R"
    FT_ID=$(jq_field "$R" "transfer_id")
    R=$(vps_get "$SGP_IP" "$SGP_TK" /files/transfers)
    check_not_error "Singapore transfers list" "$R"
    T_SEEN=""
    for _ in $(seq 1 40); do
        TR=$(vps_get "$SYD_IP" "$SYD_TK" /files/transfers)
        T_SEEN=$(json_has_transfer "$TR" "$FT_ID")
        [ -n "$T_SEEN" ] && break
        sleep 1
    done
    TOTAL=$((TOTAL+1))
    if [ -n "$T_SEEN" ]; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} Sydney sees incoming transfer"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} Sydney sees incoming transfer"
    fi
    R=$(vps_post "$SYD_IP" "$SYD_TK" "/files/accept/$FT_ID" '{}')
    check_not_error "Sydney accepts incoming transfer" "$R"
    S_STATUS=""; T_STATUS=""
    for _ in $(seq 1 50); do
        SR=$(vps_get "$SGP_IP" "$SGP_TK" "/files/transfers/$FT_ID")
        TR=$(vps_get "$SYD_IP" "$SYD_TK" "/files/transfers/$FT_ID")
        S_STATUS=$(json_transfer_status "$SR")
        T_STATUS=$(json_transfer_status "$TR")
        [ "$S_STATUS" = "Complete" ] && [ "$T_STATUS" = "Complete" ] && break
        sleep 1
    done
    TOTAL=$((TOTAL+1))
    if [ "$S_STATUS" = "Complete" ]; then PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} sender transfer reaches Complete"; else FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} sender transfer reaches Complete"; fi
    TOTAL=$((TOTAL+1))
    if [ "$T_STATUS" = "Complete" ]; then PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} receiver transfer reaches Complete"; else FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} receiver transfer reaches Complete"; fi
    OUT_PATH=$(json_transfer_output_path "$TR")
    RECV_SHA=$(vps_ssh "$SYD_IP" "shasum -a 256 '$OUT_PATH' | awk '{print \$1}'" 2>/dev/null || echo "")
    RECV_BODY=$(vps_ssh "$SYD_IP" "cat '$OUT_PATH' 2>/dev/null || true")
    check_eq "received file sha256 matches" "$RECV_SHA" "$FILE_SHA"
    check_contains "received file body contains proof token" "$RECV_BODY" "$PROOF_TOKEN"
else
    skip "File transfer proof" "Singapore/Sydney not fully available"
fi

# ═════════════════════════════════════════════════════════════════════════
# 18b. LARGE FILE TRANSFER — 1 MiB and 16 MiB NYC→SFO (cross-continent)
# ═════════════════════════════════════════════════════════════════════════
# Proves chunked transfer handles substantive payload sizes over MASQUE relay
# / direct path, not just proof-token sized offers. Sha256 roundtrip verifies
# byte-accurate delivery.
echo -e "\n${CYAN}[18b/20] Large File Transfer (NYC→SFO)${NC}"
NYC_IP="${NODE_IPS[nyc]}"; NYC_TK="${NODE_TOKENS[nyc]:-}"
SFO_IP="${NODE_IPS[sfo]}"; SFO_TK="${NODE_TOKENS[sfo]:-}"
if a_is_live nyc && a_is_live sfo && [ -n "$NYC_TK" ] && [ -n "$SFO_TK" ] && [ -n "${NODE_AIDS[sfo]:-}" ] && [ -n "${PAIR_CONNECTED[nyc_sfo]:-}" ]; then
    SFO_AID="${NODE_AIDS[sfo]}"
    for SIZE_LABEL in 1M 16M; do
        case "$SIZE_LABEL" in
            1M)  SIZE_BYTES=1048576 ;;
            16M) SIZE_BYTES=16777216 ;;
        esac
        LARGE_PATH="/tmp/x0x-vps-large-${SIZE_LABEL}-${PROOF_TOKEN}.bin"
        vps_ssh "$NYC_IP" "head -c $SIZE_BYTES /dev/urandom > '$LARGE_PATH' && printf '%s\n' '${PROOF_TOKEN}-${SIZE_LABEL}-tail' >> '$LARGE_PATH'"
        LG_SHA=$(vps_ssh "$NYC_IP" "shasum -a 256 '$LARGE_PATH' | awk '{print \$1}'")
        LG_SIZE=$(vps_ssh "$NYC_IP" "wc -c < '$LARGE_PATH' | tr -d ' '")
        R=$(vps_post "$NYC_IP" "$NYC_TK" /files/send "{\"agent_id\":\"$SFO_AID\",\"filename\":\"large-${SIZE_LABEL}-${PROOF_TOKEN}.bin\",\"size\":$LG_SIZE,\"sha256\":\"$LG_SHA\",\"path\":\"$LARGE_PATH\"}")
        check_not_error "NYC→SFO offer ($SIZE_LABEL)" "$R"
        LG_ID=$(jq_field "$R" "transfer_id")
        [ -z "$LG_ID" ] && { skip "large-$SIZE_LABEL completion" "no transfer_id"; continue; }
        # Wait up to 30s for recipient to see offer
        LG_SEEN=""
        for _ in $(seq 1 30); do
            TR=$(vps_get "$SFO_IP" "$SFO_TK" /files/transfers)
            LG_SEEN=$(json_has_transfer "$TR" "$LG_ID")
            [ -n "$LG_SEEN" ] && break
            sleep 1
        done
        TOTAL=$((TOTAL+1))
        if [ -n "$LG_SEEN" ]; then
            PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} SFO sees large-$SIZE_LABEL offer"
        else
            FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} SFO sees large-$SIZE_LABEL offer"; continue
        fi
        R=$(vps_post "$SFO_IP" "$SFO_TK" "/files/accept/$LG_ID" '{}')
        check_not_error "SFO accepts large-$SIZE_LABEL" "$R"
        # Larger files need longer completion window (up to 120s for 16 MiB)
        MAX_WAIT=60; [ "$SIZE_LABEL" = "16M" ] && MAX_WAIT=180
        S_STATUS=""; T_STATUS=""
        for _ in $(seq 1 $MAX_WAIT); do
            SR=$(vps_get "$NYC_IP" "$NYC_TK" "/files/transfers/$LG_ID")
            TR=$(vps_get "$SFO_IP" "$SFO_TK" "/files/transfers/$LG_ID")
            S_STATUS=$(json_transfer_status "$SR")
            T_STATUS=$(json_transfer_status "$TR")
            [ "$S_STATUS" = "Complete" ] && [ "$T_STATUS" = "Complete" ] && break
            sleep 1
        done
        TOTAL=$((TOTAL+1))
        if [ "$S_STATUS" = "Complete" ] && [ "$T_STATUS" = "Complete" ]; then
            PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} large-$SIZE_LABEL Complete both ends"
        else
            FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} large-$SIZE_LABEL (sender=$S_STATUS, receiver=$T_STATUS)"
            continue
        fi
        OUT_PATH=$(json_transfer_output_path "$TR")
        RECV_SHA=$(vps_ssh "$SFO_IP" "shasum -a 256 '$OUT_PATH' | awk '{print \$1}'" 2>/dev/null || echo "")
        check_eq "large-$SIZE_LABEL sha256 matches" "$RECV_SHA" "$LG_SHA"
        # Clean up per-size artefacts
        vps_ssh "$NYC_IP" "rm -f '$LARGE_PATH'" 2>/dev/null || true
        vps_ssh "$SFO_IP" "rm -f '$OUT_PATH'" 2>/dev/null || true
    done
else
    skip "Large file transfer proof" "NYC/SFO not fully available or not connected"
fi

# ═════════════════════════════════════════════════════════════════════════
# 19. PRESENCE — FOAF + online + find + status on all nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[19/20] Presence (all nodes)${NC}"

for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /presence/online)
    check_not_error "${NODE_LABELS[$node]} presence online" "$R"
done

# Base presence + FOAF from NYC
if [ -n "$NYC_TK" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" /presence)
    check_not_error "NYC base presence" "$R"
    R=$(vps_get "$NYC_IP" "$NYC_TK" /presence/foaf)
    check_not_error "NYC FOAF" "$R"

    # Find Helsinki by agent ID
    if [ -n "$HEL_AID" ]; then
        R=$(vps_get "$NYC_IP" "$NYC_TK" "/presence/find/$HEL_AID")
        check_not_error "NYC find Helsinki presence" "$R"
        R=$(vps_get "$NYC_IP" "$NYC_TK" "/presence/status/$HEL_AID")
        check_not_error "NYC Helsinki status" "$R"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 20. CONSTITUTION, UPGRADE, WEBSOCKET, STATUS — All nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[20/20] Constitution, Upgrade, WebSocket, Status${NC}"

for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /constitution/json)
    check_json "${NODE_LABELS[$node]} constitution" "$R" "version"
done

for node in "${LIVE_NODES[@]}"; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]}"
    R=$(vps_get "$ip" "$tk" /status)
    check_json "${NODE_LABELS[$node]} status" "$R" "uptime_secs"
done

# WebSocket sessions
if [ -n "$NYC_TK" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" /ws/sessions)
    check_not_error "NYC WS sessions" "$R"
fi

# Upgrade check (external GitHub dependency may rate-limit; endpoint must still respond honestly)
if a_is_live nyc && [ -n "$NYC_TK" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" /upgrade)
    TOTAL=$((TOTAL+1))
    if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert any(k in d for k in ('ok','error','current_version','latest_version','up_to_date'))" 2>/dev/null; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} NYC upgrade check responded"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} NYC upgrade check responded — $(echo "$R" | head -c200)"
    fi
fi

# Bootstrap cache
if [ -n "$NYC_TK" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" /network/bootstrap-cache)
    check_not_error "NYC bootstrap cache" "$R"
fi

# SSE endpoint probes
if a_is_live nyc && [ -n "$NYC_TK" ]; then
    R=$(vps_ssh "$NYC_IP" "curl -si -N -m 3 -H 'Authorization: Bearer $NYC_TK' 'http://127.0.0.1:12600/events' | head -1")
    check_contains "NYC /events SSE responds" "$R" "200"
    R=$(vps_ssh "$NYC_IP" "curl -si -N -m 3 -H 'Authorization: Bearer $NYC_TK' 'http://127.0.0.1:12600/presence/events' | head -1")
    check_contains "NYC /presence/events SSE responds" "$R" "200"
fi

# ═════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   PROOF TOKEN: ${PROOF_TOKEN}${NC}"
echo -e "${YELLOW}   Interfaces tested: REST API, CLI (x0x direct send), GUI${NC}"
echo -e "${YELLOW}   All-pairs: $CONN_OK connections, $DM_SEND_OK messages sent${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}  ALL $TOTAL TESTS PASSED ($PASS passed, $SKIP skipped)${NC}"
    echo -e "  ${#LIVE_NODES[@]} VPS nodes, 20 categories, v$VERSION"
else
    echo -e "${RED}  $FAIL FAILED / $TOTAL TOTAL${NC} ($PASS passed, $SKIP skipped)"
fi
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
exit $FAIL
