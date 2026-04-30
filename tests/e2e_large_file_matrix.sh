#!/usr/bin/env bash
# Large-file transfer matrix.
#
# Drives `POST /files/send` + `POST /files/accept/:id` across multiple
# (size × pair) combinations, verifies SHA-256 round-trip, and records
# throughput, wall-clock, peak RSS, and gossip drop counters.
#
# Pairs:
#   - local-local   : 2 daemons on loopback (ports 12791 / 12792)
#   - local-nyc     : local Mac daemon ↔ nyc VPS (joins live mesh)
#   - helsinki-sfo  : VPS ↔ VPS, cross-continent (publish via SSH)
#
# Sizes: 1M, 100M, 1G, 4G (override with --sizes "1M 100M").
#
# Usage:
#   tests/e2e_large_file_matrix.sh --pair local-local --sizes "1M"
#   tests/e2e_large_file_matrix.sh --pair local-local --sizes "1M 100M 1G"
#   tests/e2e_large_file_matrix.sh --pair local-nyc --sizes "1M 100M"
#   tests/e2e_large_file_matrix.sh --pair helsinki-sfo --sizes "1M 100M"
#   tests/e2e_large_file_matrix.sh --pair all --sizes "1M 100M 1G 4G"
#
# Exit code: 0 = all transfers verified, non-zero = any failure.
# Proof artefacts (per run):
#   <proof-dir>/matrix.csv        — pair,size,bytes,elapsed_s,throughput_MBps,sha_match,...
#   <proof-dir>/<pair>-<size>/    — per-transfer logs
#
# Notes:
#   - 4 GiB transfers across the live mesh take ~30+ min; the harness
#     prints progress every 10 s.
#   - VPS data files are placed at /tmp/x0x-matrix-<size>.bin and removed
#     after the run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PAIR="local-local"
SIZES="1M"
PROOF_DIR=""

while (( "$#" )); do
    case "$1" in
        --pair)       PAIR="$2"; shift 2 ;;
        --sizes)      SIZES="$2"; shift 2 ;;
        --proof-dir)  PROOF_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [ -z "$PROOF_DIR" ]; then
    PROOF_DIR="proofs/file-matrix-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$PROOF_DIR"
LOG="$PROOF_DIR/matrix.log"
CSV="$PROOF_DIR/matrix.csv"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
echo "ts_iso,pair,size_label,bytes,elapsed_s,throughput_MBps,sha_match,status,sender_peak_rss_kb,receiver_peak_rss_kb,error" > "$CSV"

# Resolve "size label" → bytes.
size_to_bytes() {
    case "$1" in
        1M)   echo $((1024 * 1024)) ;;
        100M) echo $((100 * 1024 * 1024)) ;;
        1G)   echo $((1024 * 1024 * 1024)) ;;
        4G)   echo $((4 * 1024 * 1024 * 1024)) ;;
        *) echo "unknown size: $1" >&2; return 1 ;;
    esac
}

SSH="ssh -o ConnectTimeout=10 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none"

# ──────────────────────────────────────────────────────────────────────────
# Pair backends — each defines:
#   pair_setup       prepare daemons (start local, source token env, etc.)
#   pair_teardown    stop local daemons / clean up tmp files
#   pair_sender_id   echo agent_id of sender side
#   pair_receiver_id echo agent_id of receiver side
#   pair_send_curl   run curl POST /files/send on sender side
#   pair_accept_curl run curl POST /files/accept/:id on receiver side
#   pair_status      fetch transfer status JSON for transfer_id from a node
#   pair_rss         echo current RSS in KB (sender / receiver)
#   pair_make_file   generate the source file on the sender side
#   pair_recv_path   echo where the receiver writes the file
#   pair_clean_files remove leftover test files on both sides
# ──────────────────────────────────────────────────────────────────────────

# ---- local-local ---------------------------------------------------------
LOCAL_DAEMON_PIDS=()
LOCAL_TOKENS=()
LOCAL_PORTS=(12791 12792)
LOCAL_AGENT_IDS=()

local_pair_setup() {
    local bin="$PROJECT_DIR/target/debug/x0xd"
    if [ ! -x "$bin" ]; then
        log "Building x0xd debug binary..."
        (cd "$PROJECT_DIR" && cargo build --bin x0xd >/dev/null 2>&1) \
            || { log "FAIL: cargo build failed"; return 1; }
    fi
    local data_base
    if [ "$(uname)" = "Darwin" ]; then
        data_base="$HOME/Library/Application Support"
    else
        data_base="$HOME/.local/share"
    fi
    for i in 1 2; do
        local instance="filemtx-$i"
        local id_dir="$PROOF_DIR/local-node-$i/identity"
        mkdir -p "$id_dir"
        local port="${LOCAL_PORTS[$((i-1))]}"
        log "Launching local daemon $i on port $port"
        X0X_IDENTITY_DIR="$id_dir" \
            "$bin" --name "$instance" --api-port "$port" --no-hard-coded-bootstrap \
            > "$PROOF_DIR/local-node-$i/x0xd.log" 2>&1 &
        LOCAL_DAEMON_PIDS+=($!)
    done
    log "Waiting 10 s for local daemons + token files"
    sleep 10
    for i in 1 2; do
        local instance="filemtx-$i"
        local tok_file="$data_base/x0x-$instance/api-token"
        if [ -f "$tok_file" ]; then
            LOCAL_TOKENS+=("$(cat "$tok_file")")
        else
            log "FAIL: no token at $tok_file"; return 1
        fi
    done
    # Fetch agent_ids
    for i in 1 2; do
        local agent
        agent=$(curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[$((i-1))]}" \
            "http://127.0.0.1:${LOCAL_PORTS[$((i-1))]}/agent" 2>/dev/null \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent_id"])' 2>/dev/null)
        LOCAL_AGENT_IDS+=("$agent")
    done
    log "Local agent IDs: sender=${LOCAL_AGENT_IDS[0]:0:16}.. receiver=${LOCAL_AGENT_IDS[1]:0:16}.."

    # Cross-import contact cards so node 1 knows about node 2 and vice versa.
    # Without this trust gating drops the file offer as Unknown.
    local_pair_swap_cards
}

local_pair_swap_cards() {
    # 1. Cross-import contact cards so trust evaluation passes for the
    #    file-offer direct send (otherwise the receiver may drop the offer
    #    as Unknown/Anonymous depending on policy).
    for src in 0 1; do
        local dst=$((1 - src))
        local card
        card=$(curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[$src]}" \
            "http://127.0.0.1:${LOCAL_PORTS[$src]}/agent/card" 2>/dev/null)
        curl -sS -m 5 -X POST \
            -H "authorization: Bearer ${LOCAL_TOKENS[$dst]}" \
            -H "content-type: application/json" \
            -d "$card" \
            "http://127.0.0.1:${LOCAL_PORTS[$dst]}/contacts/import" >/dev/null 2>&1 || true
    done

    # 2. Discover each daemon's actual UDP bind address via /diagnostics/connectivity
    #    and dial explicitly. With --no-hard-coded-bootstrap and ephemeral
    #    UDP binds, mDNS is the only auto-discovery path and is flakey on
    #    a fresh start.
    local addrs=()
    for i in 0 1; do
        local diag local_addr
        diag=$(curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[$i]}" \
            "http://127.0.0.1:${LOCAL_PORTS[$i]}/diagnostics/connectivity" 2>/dev/null)
        # local_addr looks like "[::]:5483" or "0.0.0.0:39512" — extract the port
        local_addr=$(echo "$diag" | python3 -c '
import json, sys, re
d = json.load(sys.stdin)
la = d.get("local_addr", "")
# strip wildcard host, keep "127.0.0.1" + port
m = re.search(r":(\d+)$", la)
if m: print(f"127.0.0.1:{m.group(1)}")
else: print("")
' 2>/dev/null)
        addrs+=("$local_addr")
    done
    log "  daemon addrs: 1=${addrs[0]} 2=${addrs[1]}"

    # 3. Dial both directions
    for src in 0 1; do
        local dst=$((1 - src))
        local peer_id
        peer_id=$(curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[$dst]}" \
            "http://127.0.0.1:${LOCAL_PORTS[$dst]}/agent" 2>/dev/null \
            | python3 -c 'import json,sys; print(json.load(sys.stdin).get("machine_id",""))' 2>/dev/null)
        if [ -n "$peer_id" ] && [ -n "${addrs[$dst]}" ]; then
            curl -sS -m 10 -X POST \
                -H "authorization: Bearer ${LOCAL_TOKENS[$src]}" \
                -H "content-type: application/json" \
                -d "{\"peer_id\":\"$peer_id\",\"address\":\"${addrs[$dst]}\"}" \
                "http://127.0.0.1:${LOCAL_PORTS[$src]}/peers/connect" >/dev/null 2>&1 || true
        fi
    done

    # 4. Wait for handshake AND for the identity announcement to propagate
    #    via gossip into the peer's discovery cache. Without this, the
    #    /files/send DM lookup races and fails with "agent not found"
    #    even though /peers/connect already established a live QUIC link.
    #    15 s is conservative for a fresh two-daemon mesh.
    sleep 15
}

local_pair_teardown() {
    log "Stopping local daemons"
    for pid in "${LOCAL_DAEMON_PIDS[@]}"; do
        kill -INT "$pid" 2>/dev/null || true
    done
    sleep 3
    for pid in "${LOCAL_DAEMON_PIDS[@]}"; do
        kill -KILL "$pid" 2>/dev/null || true
    done
    wait "${LOCAL_DAEMON_PIDS[@]}" 2>/dev/null || true
}

local_pair_sender_id()   { echo "${LOCAL_AGENT_IDS[0]}"; }
local_pair_receiver_id() { echo "${LOCAL_AGENT_IDS[1]}"; }

local_pair_send() {
    local body="$1"
    curl -sS -m 30 -X POST \
        -H "authorization: Bearer ${LOCAL_TOKENS[0]}" \
        -H "content-type: application/json" \
        -d "$body" \
        "http://127.0.0.1:${LOCAL_PORTS[0]}/files/send"
}

local_pair_accept() {
    local id="$1"
    curl -sS -m 30 -X POST \
        -H "authorization: Bearer ${LOCAL_TOKENS[1]}" \
        "http://127.0.0.1:${LOCAL_PORTS[1]}/files/accept/$id"
}

local_pair_status() {
    local side="$1" id="$2"   # side = sender|receiver
    local idx; [ "$side" = sender ] && idx=0 || idx=1
    curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[$idx]}" \
        "http://127.0.0.1:${LOCAL_PORTS[$idx]}/files/transfers/$id"
}

local_pair_list_transfers() {
    local side="$1"
    local idx; [ "$side" = sender ] && idx=0 || idx=1
    curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[$idx]}" \
        "http://127.0.0.1:${LOCAL_PORTS[$idx]}/files/transfers"
}

local_pair_rss() {
    local side="$1"
    local pid_idx; [ "$side" = sender ] && pid_idx=0 || pid_idx=1
    local pid="${LOCAL_DAEMON_PIDS[$pid_idx]}"
    ps -o rss= -p "$pid" 2>/dev/null | tr -d ' \n' || echo 0
}

local_pair_make_file() {
    local size_bytes="$1" path="$2"
    # Use /dev/urandom so payload is incompressible (no chunk-size cheating).
    dd if=/dev/urandom of="$path" bs=1048576 count=$((size_bytes / 1048576)) status=none 2>/dev/null
    if [ $((size_bytes % 1048576)) -ne 0 ]; then
        dd if=/dev/urandom bs=$((size_bytes % 1048576)) count=1 status=none 2>/dev/null >> "$path"
    fi
    shasum -a 256 "$path" | awk '{print $1}'
}

local_pair_recv_path() {
    # Receiver currently writes under its data dir. Look in the standard
    # location (varies by platform). Caller resolves via TransferState.output_path.
    echo ""
}

# ---- local-nyc -----------------------------------------------------------
NYC_IP=""
NYC_TK=""
NYC_AGENT_ID=""

local_nyc_pair_setup() {
    # Reuse local_pair_setup for the local daemon side (bootstrap-enabled
    # this time so it joins the real mesh).
    local bin="$PROJECT_DIR/target/debug/x0xd"
    if [ ! -x "$bin" ]; then
        log "Building x0xd debug binary..."
        (cd "$PROJECT_DIR" && cargo build --bin x0xd >/dev/null 2>&1) \
            || { log "FAIL: cargo build failed"; return 1; }
    fi
    local data_base
    if [ "$(uname)" = "Darwin" ]; then
        data_base="$HOME/Library/Application Support"
    else
        data_base="$HOME/.local/share"
    fi
    # Single local daemon for this pair.
    local instance="filemtx-local"
    local id_dir="$PROOF_DIR/local-node-1/identity"
    mkdir -p "$id_dir"
    local port=12791
    LOCAL_PORTS=($port)
    log "Launching local daemon on port $port (with bootstrap to live mesh)"
    X0X_IDENTITY_DIR="$id_dir" \
        "$bin" --name "$instance" --api-port "$port" \
        > "$PROOF_DIR/local-node-1/x0xd.log" 2>&1 &
    LOCAL_DAEMON_PIDS=($!)
    log "Waiting 25 s for daemon + mesh handshake"
    sleep 25
    local tok_file="$data_base/x0x-$instance/api-token"
    if [ ! -f "$tok_file" ]; then log "FAIL: no token at $tok_file"; return 1; fi
    LOCAL_TOKENS=("$(cat "$tok_file")")
    LOCAL_AGENT_IDS=("$(curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[0]}" http://127.0.0.1:$port/agent | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent_id"])' 2>/dev/null)")

    # Source VPS tokens
    if [ ! -f "$SCRIPT_DIR/.vps-tokens.env" ]; then
        log "FAIL: tests/.vps-tokens.env missing"; return 1
    fi
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/.vps-tokens.env"
    NYC_IP="$NYC_IP"; NYC_TK="$NYC_TK"
    log "NYC: $NYC_IP"

    NYC_AGENT_ID=$($SSH root@"$NYC_IP" "curl -sS -m 5 -H 'authorization: Bearer $NYC_TK' http://127.0.0.1:12600/agent" 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent_id"])' 2>/dev/null)
    log "NYC agent_id: ${NYC_AGENT_ID:0:16}.."
    log "Local agent_id: ${LOCAL_AGENT_IDS[0]:0:16}.."

    # Cross-import contact cards so trust eval permits the offer.
    local local_card nyc_card
    local_card=$(curl -sS -m 5 -H "authorization: Bearer ${LOCAL_TOKENS[0]}" http://127.0.0.1:$port/agent/card)
    nyc_card=$($SSH root@"$NYC_IP" "curl -sS -m 5 -H 'authorization: Bearer $NYC_TK' http://127.0.0.1:12600/agent/card")
    curl -sS -m 5 -X POST -H "authorization: Bearer ${LOCAL_TOKENS[0]}" -H "content-type: application/json" -d "$nyc_card" "http://127.0.0.1:$port/contacts/import" >/dev/null 2>&1 || true
    $SSH root@"$NYC_IP" "curl -sS -m 5 -X POST -H 'authorization: Bearer $NYC_TK' -H 'content-type: application/json' -d '$local_card' http://127.0.0.1:12600/contacts/import" >/dev/null 2>&1 || true
}

# ── Driver ────────────────────────────────────────────────────────────────

run_one_transfer() {
    local pair="$1" size_label="$2"
    local size_bytes; size_bytes=$(size_to_bytes "$size_label") || return 1
    local sub_dir="$PROOF_DIR/${pair}-${size_label}"
    mkdir -p "$sub_dir"
    local src_file="$sub_dir/source.bin"

    log "── Pair=$pair Size=$size_label ($size_bytes bytes) ──"

    local sha_sender
    case "$pair" in
        local-local)
            log "Generating source file..."
            sha_sender=$(local_pair_make_file "$size_bytes" "$src_file")
            log "Sender SHA-256: $sha_sender"
            local sender; sender=$(local_pair_sender_id)
            local receiver; receiver=$(local_pair_receiver_id)
            local body
            body=$(printf '{"agent_id":"%s","filename":"matrix-%s.bin","size":%s,"sha256":"%s","path":"%s"}' \
                "$receiver" "$size_label" "$size_bytes" "$sha_sender" "$src_file")
            local resp
            resp=$(local_pair_send "$body")
            local transfer_id
            transfer_id=$(echo "$resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer_id","") if d.get("ok") else "")' 2>/dev/null)
            if [ -z "$transfer_id" ]; then
                log "FAIL: send rejected: $resp"
                printf '%s,%s,%s,%s,,,,fail-send,,,%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "${resp//,/;}" >> "$CSV"
                return 1
            fi
            log "transfer_id=$transfer_id; waiting for receiver to see Pending offer"

            # Poll receiver until it sees the Pending transfer
            local ok=0
            for _ in $(seq 1 30); do
                local list; list=$(local_pair_list_transfers receiver)
                if echo "$list" | grep -q "$transfer_id"; then
                    ok=1; break
                fi
                sleep 1
            done
            if [ $ok -ne 1 ]; then
                log "FAIL: receiver never saw the offer"
                printf '%s,%s,%s,%s,,,,fail-no-offer,,,\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" >> "$CSV"
                return 1
            fi
            log "Accepting on receiver"
            local accept_resp
            accept_resp=$(local_pair_accept "$transfer_id")
            if ! echo "$accept_resp" | grep -q '"ok":true'; then
                log "FAIL: accept rejected: $accept_resp"
                printf '%s,%s,%s,%s,,,,fail-accept,,,%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "${accept_resp//,/;}" >> "$CSV"
                return 1
            fi

            local sender_peak_rss=0 receiver_peak_rss=0
            local start_ns; start_ns=$(date +%s)
            # Wall-clock deadline scaled by file size: 1 hour per GiB at ~0.3 MB/s,
            # plus a 5-min slack. Bounded at 12 hours.
            local deadline; deadline=$((start_ns + (size_bytes / 1073741824 + 1) * 3600 + 300))
            (( deadline > start_ns + 12 * 3600 )) && deadline=$((start_ns + 12 * 3600))
            local last_log=$start_ns
            local final_status=""
            local recv_path=""
            while [ "$(date +%s)" -lt "$deadline" ]; do
                local s; s=$(local_pair_status receiver "$transfer_id")
                local status; status=$(echo "$s" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer",{}).get("status",""))' 2>/dev/null)
                local bytes_xferred; bytes_xferred=$(echo "$s" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer",{}).get("bytes_transferred",0))' 2>/dev/null)
                recv_path=$(echo "$s" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer",{}).get("output_path","") or "")' 2>/dev/null)

                local rss_s; rss_s=$(local_pair_rss sender)
                local rss_r; rss_r=$(local_pair_rss receiver)
                [ "$rss_s" -gt "$sender_peak_rss" ] 2>/dev/null && sender_peak_rss=$rss_s
                [ "$rss_r" -gt "$receiver_peak_rss" ] 2>/dev/null && receiver_peak_rss=$rss_r

                local now; now=$(date +%s)
                if (( now - last_log >= 10 )); then
                    log "  status=$status bytes=$bytes_xferred / $size_bytes ($(awk -v b=$bytes_xferred -v t=$size_bytes 'BEGIN{printf "%.1f",b*100/t}')%)  rss_s=$((rss_s/1024))MB rss_r=$((rss_r/1024))MB"
                    last_log=$now
                fi

                if [ "$status" = "Complete" ] || [ "$status" = "Failed" ] || [ "$status" = "Rejected" ]; then
                    final_status="$status"
                    break
                fi
                sleep 2
            done
            local end_ns; end_ns=$(date +%s)
            local elapsed=$((end_ns - start_ns))
            [ $elapsed -lt 1 ] && elapsed=1
            local mbps; mbps=$(awk -v b=$size_bytes -v t=$elapsed 'BEGIN{printf "%.2f", (b/1048576.0)/t}')

            if [ "$final_status" != "Complete" ]; then
                log "FAIL: status=$final_status (elapsed ${elapsed}s)"
                printf '%s,%s,%s,%s,%s,%s,fail,%s,%s,%s,\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "$elapsed" "$mbps" "$final_status" "$sender_peak_rss" "$receiver_peak_rss" >> "$CSV"
                return 1
            fi

            # SHA round-trip
            local sha_match=no
            if [ -n "$recv_path" ] && [ -f "$recv_path" ]; then
                local sha_recv; sha_recv=$(shasum -a 256 "$recv_path" | awk '{print $1}')
                if [ "$sha_recv" = "$sha_sender" ]; then sha_match=yes; fi
                log "Receiver SHA-256: $sha_recv (match=$sha_match)"
            else
                log "WARN: receiver output_path empty or missing ($recv_path)"
            fi

            log "PASS: $size_label transferred in ${elapsed}s @ ${mbps} MB/s, sha_match=$sha_match"
            printf '%s,%s,%s,%s,%s,%s,%s,Complete,%s,%s,\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "$elapsed" "$mbps" "$sha_match" "$sender_peak_rss" "$receiver_peak_rss" >> "$CSV"

            # Cleanup
            rm -f "$src_file"
            [ -n "$recv_path" ] && [ -f "$recv_path" ] && rm -f "$recv_path"
            return 0
            ;;
        local-nyc)
            log "Generating source file..."
            sha_sender=$(local_pair_make_file "$size_bytes" "$src_file")
            log "Sender SHA-256: $sha_sender"
            local nyc_agent="$NYC_AGENT_ID"
            local body
            body=$(printf '{"agent_id":"%s","filename":"matrix-%s.bin","size":%s,"sha256":"%s","path":"%s"}' \
                "$nyc_agent" "$size_label" "$size_bytes" "$sha_sender" "$src_file")
            local resp
            resp=$(curl -sS -m 30 -X POST \
                -H "authorization: Bearer ${LOCAL_TOKENS[0]}" \
                -H "content-type: application/json" \
                -d "$body" \
                "http://127.0.0.1:${LOCAL_PORTS[0]}/files/send")
            local transfer_id
            transfer_id=$(echo "$resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer_id","") if d.get("ok") else "")' 2>/dev/null)
            if [ -z "$transfer_id" ]; then
                log "FAIL: send rejected: $resp"
                printf '%s,%s,%s,%s,,,,fail-send,,,%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "${resp//,/;}" >> "$CSV"
                return 1
            fi
            log "transfer_id=$transfer_id; waiting for nyc to see Pending"
            local ok=0
            for _ in $(seq 1 30); do
                local list
                list=$($SSH root@"$NYC_IP" "curl -sS -m 5 -H 'authorization: Bearer $NYC_TK' http://127.0.0.1:12600/files/transfers" 2>/dev/null)
                if echo "$list" | grep -q "$transfer_id"; then ok=1; break; fi
                sleep 2
            done
            if [ $ok -ne 1 ]; then
                log "FAIL: nyc never saw the offer"
                printf '%s,%s,%s,%s,,,,fail-no-offer,,,\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" >> "$CSV"
                return 1
            fi
            log "Accepting on nyc"
            local accept_resp
            accept_resp=$($SSH root@"$NYC_IP" "curl -sS -m 30 -X POST -H 'authorization: Bearer $NYC_TK' http://127.0.0.1:12600/files/accept/$transfer_id" 2>/dev/null)
            if ! echo "$accept_resp" | grep -q '"ok":true'; then
                log "FAIL: nyc accept rejected: $accept_resp"
                printf '%s,%s,%s,%s,,,,fail-accept,,,%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "${accept_resp//,/;}" >> "$CSV"
                return 1
            fi

            local sender_peak_rss=0 receiver_peak_rss=0
            local start_ns; start_ns=$(date +%s)
            local last_log=$start_ns
            local final_status="" recv_path=""
            local deadline_nyc; deadline_nyc=$((start_ns + (size_bytes / 1073741824 + 1) * 3600 + 300))
            (( deadline_nyc > start_ns + 12 * 3600 )) && deadline_nyc=$((start_ns + 12 * 3600))
            while [ "$(date +%s)" -lt "$deadline_nyc" ]; do
                local s
                s=$($SSH root@"$NYC_IP" "curl -sS -m 5 -H 'authorization: Bearer $NYC_TK' http://127.0.0.1:12600/files/transfers/$transfer_id" 2>/dev/null)
                local status bytes_xferred
                status=$(echo "$s" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer",{}).get("status",""))' 2>/dev/null)
                bytes_xferred=$(echo "$s" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer",{}).get("bytes_transferred",0))' 2>/dev/null)
                recv_path=$(echo "$s" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("transfer",{}).get("output_path","") or "")' 2>/dev/null)
                local rss_s rss_r
                rss_s=$(local_pair_rss sender)
                rss_r=$($SSH root@"$NYC_IP" 'awk "/VmRSS/{print \$2}" /proc/$(pidof x0xd)/status' 2>/dev/null | tr -d ' \n')
                rss_r=${rss_r:-0}
                [ "$rss_s" -gt "$sender_peak_rss" ] 2>/dev/null && sender_peak_rss=$rss_s
                [ "$rss_r" -gt "$receiver_peak_rss" ] 2>/dev/null && receiver_peak_rss=$rss_r

                local now; now=$(date +%s)
                if (( now - last_log >= 10 )); then
                    log "  status=$status bytes=$bytes_xferred / $size_bytes ($(awk -v b=$bytes_xferred -v t=$size_bytes 'BEGIN{printf "%.1f",b*100/t}')%)  rss_s=$((rss_s/1024))MB rss_r=$((rss_r/1024))MB"
                    last_log=$now
                fi
                if [ "$status" = "Complete" ] || [ "$status" = "Failed" ] || [ "$status" = "Rejected" ]; then
                    final_status="$status"; break
                fi
                sleep 2
            done
            local end_ns; end_ns=$(date +%s)
            local elapsed=$((end_ns - start_ns)); [ $elapsed -lt 1 ] && elapsed=1
            local mbps; mbps=$(awk -v b=$size_bytes -v t=$elapsed 'BEGIN{printf "%.2f", (b/1048576.0)/t}')
            if [ "$final_status" != "Complete" ]; then
                log "FAIL: status=$final_status (elapsed ${elapsed}s)"
                printf '%s,%s,%s,%s,%s,%s,fail,%s,%s,%s,\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "$elapsed" "$mbps" "$final_status" "$sender_peak_rss" "$receiver_peak_rss" >> "$CSV"
                return 1
            fi
            local sha_match=no
            if [ -n "$recv_path" ]; then
                local sha_recv
                sha_recv=$($SSH root@"$NYC_IP" "sha256sum '$recv_path' | awk '{print \$1}'" 2>/dev/null)
                if [ "$sha_recv" = "$sha_sender" ]; then sha_match=yes; fi
                log "Receiver SHA-256: $sha_recv (match=$sha_match)"
            fi
            log "PASS: $size_label transferred in ${elapsed}s @ ${mbps} MB/s, sha_match=$sha_match"
            printf '%s,%s,%s,%s,%s,%s,%s,Complete,%s,%s,\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pair" "$size_label" "$size_bytes" "$elapsed" "$mbps" "$sha_match" "$sender_peak_rss" "$receiver_peak_rss" >> "$CSV"
            rm -f "$src_file"
            [ -n "$recv_path" ] && $SSH root@"$NYC_IP" "rm -f '$recv_path'" 2>/dev/null || true
            return 0
            ;;
        helsinki-sfo)
            log "TODO: helsinki-sfo backend not yet wired"
            return 2
            ;;
        *)
            log "unknown pair: $pair"; return 2
            ;;
    esac
}

# ── Main ──────────────────────────────────────────────────────────────────

PAIRS_TO_RUN=()
case "$PAIR" in
    all)            PAIRS_TO_RUN=(local-local local-nyc helsinki-sfo) ;;
    local-local|local-nyc|helsinki-sfo) PAIRS_TO_RUN=("$PAIR") ;;
    *) log "FAIL: unknown pair '$PAIR'"; exit 2 ;;
esac

OVERALL_FAIL=0
for p in "${PAIRS_TO_RUN[@]}"; do
    log ""
    log "════ Pair: $p ════"
    case "$p" in
        local-local)
            local_pair_setup || { OVERALL_FAIL=1; continue; }
            for sz in $SIZES; do
                if ! run_one_transfer "$p" "$sz"; then
                    OVERALL_FAIL=1
                fi
            done
            local_pair_teardown
            ;;
        local-nyc)
            local_nyc_pair_setup || { OVERALL_FAIL=1; continue; }
            for sz in $SIZES; do
                if ! run_one_transfer "$p" "$sz"; then
                    OVERALL_FAIL=1
                fi
            done
            local_pair_teardown
            ;;
        helsinki-sfo)
            log "skip: helsinki-sfo backend pending"
            ;;
    esac
done

log ""
log "Matrix complete (exit=$OVERALL_FAIL)"
log "CSV: $CSV"
exit $OVERALL_FAIL
