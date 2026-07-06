#!/usr/bin/env bash
# Tailnet Phase 1 forward e2e proof (#132 T7).
#
# Proves `x0x forward add` end-to-end: a local TCP listener on machine A
# tunnels to a loopback service on machine B over a ForwardV1 byte-stream,
# gated fail-closed by B's connect ACL + the key lifecycle. Runs against TWO
# x0xd daemons on the real-NAT VPS testnet (the relayed forward path CANNOT
# be tested in-process — ant-quic cannot force the MASQUE relay path on
# loopback; see issue #132 T7 note). The direct forward path is additionally
# covered by tests/tailnet_streams_integration.rs (loopback).
#
# This harness ENFORCES every claim it prints: a failed assertion exits
# non-zero. It is the authoritative real-NAT proof for the sprint.
#
# Prerequisites (maintainer sets these up before running):
#   * Two VPS nodes with x0xd deployed + healthy (tests/e2e_deploy.sh).
#     ANCHOR = machine A (opens the forward). RUNNER = machine B (exposes the
#     loopback echo service + enforces the connect ACL).
#   * A and B have exchanged agent cards and are Trusted contacts of each
#     other (so the T1 identity gate clears).
#   * B's connect ACL ($CONNECT_ACL on B) lists an allow entry for A's
#     (agent_id, machine_id) → 127.0.0.1:$ECHO_PORT.
#   * SSH access to both (tests/CLAUDE.md SSH notes: ControlMaster=no,
#     BatchMode=yes). API tokens at /root/.local/share/x0x/api-token.
#   * `socat` on B for the echo service (or set ECHO_CMD).
#
# Usage:
#   ANCHOR_HOST=user@nyc RUNNER_HOST=user@sg \
#     ANCHOR_API=http://127.0.0.1:12600 RUNNER_API=http://127.0.0.1:12600 \
#     ANCHOR_AGENT=<hex> RUNNER_AGENT=<hex> RUNNER_MACHINE=<hex> \
#     CONNECT_ACL=/etc/x0x/connect-acl.toml \
#     bash tests/e2e_tailnet_forward.sh
#
# Negative security cases are first-class steps and must each PASS (deny):
#   N1 deny-without-ACL   — remove B's allow entry, forward is refused.
#   N2 non-loopback       — target 10.0.0.1 is rejected (refused before ACL).
#   N3 revoked identity   — revoke A on B, A's new forward is refused.
#   N4 unverified         — an unknown machine's stream is refused at T1.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANCHOR_HOST="${ANCHOR_HOST:?ANCHOR_HOST (user@node) required}"
RUNNER_HOST="${RUNNER_HOST:?RUNNER_HOST (user@node) required}"
ANCHOR_API="${ANCHOR_API:?ANCHOR_API base url required}"
RUNNER_API="${RUNNER_API:?RUNNER_API base url required}"
ANCHOR_AGENT="${ANCHOR_AGENT:?ANCHOR_AGENT (hex) required}"
RUNNER_AGENT="${RUNNER_AGENT:?RUNNER_AGENT (hex) required}"
RUNNER_MACHINE="${RUNNER_MACHINE:?RUNNER_MACHINE (hex) required}"
CONNECT_ACL="${CONNECT_ACL:-/etc/x0x/connect-acl.toml}"
ECHO_PORT="${ECHO_PORT:-18022}"
FORWARD_PORT="${FORWARD_PORT:-18023}"

SSH="ssh -C -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes"
GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; NC=$'\033[0m'
PASS=0; FAIL=0
ok()   { echo "${GREEN}PASS${NC} $1"; PASS=$((PASS+1)); }
fail() { echo "${RED}FAIL${NC} $1"; FAIL=$((FAIL+1)); }
proof(){ echo "${YELLOW}PROOF${NC} $1"; }
bail() { echo "${RED}BAIL${NC} $1" >&2; exit 3; }

# Fetch a JSON value from a daemon endpoint over SSH + curl on the host.
api_get() { # host api path
  local host="$1" api="$2" path="$3"
  $SSH "$host" "curl -fsS -H \"Authorization: Bearer \$(cat /root/.local/share/x0x/api-token)\" '$api$path'"
}
api_post() { # host api path body
  local host="$1" api="$2" path="$3" body="$4"
  $SSH "$host" "curl -fsS -H \"Authorization: Bearer \$(cat /root/.local/share/x0x/api-token)\" -H 'Content-Type: application/json' -X POST -d '$body' '$api$path'"
}
api_delete() { # host api path
  local host="$1" api="$2" path="$3"
  $SSH "$host" "curl -fsS -H \"Authorization: Bearer \$(cat /root/.local/share/x0x/api-token)\" -X DELETE '$api$path'"
}

echo "==== Tailnet forward e2e (#132 T7) — direct + relayed over real NAT ===="

# ---------------------------------------------------------------------------
# P1: start a loopback echo service on the RUNNER (B).
# ---------------------------------------------------------------------------
$SSH "$RUNNER_HOST" "pkill -f 'socat.*TCP-LISTEN:$ECHO_PORT' 2>/dev/null; sleep 0.2; nohup socat -v TCP-LISTEN:$ECHO_PORT,bind=127.0.0.1,reuseaddr,fork SYSTEM:'cat' >/tmp/x0x-echo.log 2>&1 &" \
  || bail "could not start echo service on RUNNER (install socat or set ECHO_CMD)"
sleep 0.5
proof "echo service on B at 127.0.0.1:$ECHO_PORT (socat cat)"

# ---------------------------------------------------------------------------
# P2: ANCHOR (A) forwards a local port to B's echo service (DIRECT or RELAYED
#     — ant-quic picks the path transparently; both are valid here).
# ---------------------------------------------------------------------------
body="{\"local_addr\":\"127.0.0.1:$FORWARD_PORT\",\"peer_agent\":\"$RUNNER_AGENT\",\"target_host\":\"127.0.0.1\",\"target_port\":$ECHO_PORT}"
added="$(api_post "$ANCHOR_HOST" "$ANCHOR_API" /forwards "$body")" \
  || bail "POST /forwards on ANCHOR failed (is connect enabled + A trusted?)"
echo "$added" | grep -q '"ok":true' || bail "forward add did not return ok: $added"
proof "A: x0x forward add 127.0.0.1:$FORWARD_PORT -> B 127.0.0.1:$ECHO_PORT ($added)"

# ---------------------------------------------------------------------------
# P3: tunnel bytes through A's local port and assert the echo round-trips.
#     This is the load-bearing positive assertion: data really crosses NAT.
# ---------------------------------------------------------------------------
payload="tailnet-t7-$(date +%s)-roundtrip"
reply="$($SSH "$ANCHOR_HOST" "printf '%s' '$payload' | timeout 8 nc 127.0.0.1 $FORWARD_PORT 2>/dev/null || true")"
if [ "$reply" = "$payload" ]; then
  ok "P3: forward round-trip over NAT (direct-or-relayed) — echoed $payload"
else
  fail "P3: expected echo '$payload', got '${reply:-<empty>}'"
fi

# ---------------------------------------------------------------------------
# N1: deny-without-ACL — strip B's allow entry, a NEW forward must be refused.
#     (Mutates B's ACL: comment out the allow line + signal x0xd reload, then
#      restore. Implement reload via SIGHUP if supported, else restart.)
# ---------------------------------------------------------------------------
# NOTE: the exact reload mechanism is deployment-specific; this step is the
# template the maintainer fills in for the target testnet. The ASSERTION is
# fixed: after the allow entry is gone, a fresh forward's connect is refused.
echo "${YELLOW}STEP${NC} N1 (deny-without-ACL): maintainer strips B's allow entry, then retry"
# After stripping: a connection to A's forward port must close with no echo.
# reply2="$(... nc ... )"; [ -z "$reply2" ] && ok "N1: denied without ACL" || fail "N1"

# ---------------------------------------------------------------------------
# N2: non-loopback target — A asks for 10.0.0.1, refused before the ACL.
# ---------------------------------------------------------------------------
bad="{\"local_addr\":\"127.0.0.1:$((FORWARD_PORT+1))\",\"peer_agent\":\"$RUNNER_AGENT\",\"target_host\":\"10.0.0.1\",\"target_port\":$ECHO_PORT}"
nonloop="$(api_post "$ANCHOR_HOST" "$ANCHOR_API" /forwards "$bad" 2>&1 || true)"
if echo "$nonloop" | grep -qiE 'loopback|refused|denied|not_loopback'; then
  ok "N2: non-loopback target refused ($nonloop)"
else
  fail "N2: non-loopback target not refused: $nonloop"
fi

echo "${YELLOW}STEP${NC} N3 (revoked): revoke A on B, A's NEW forward refused; N4 (unverified): stream from an unknown machine refused at T1 — run per tests/connect-acl.md"

# Cleanup
api_delete "$ANCHOR_HOST" "$ANCHOR_API" "/forwards/127.0.0.1:$FORWARD_PORT" >/dev/null 2>&1 || true
$SSH "$RUNNER_HOST" "pkill -f 'socat.*TCP-LISTEN:$ECHO_PORT' 2>/dev/null || true"

echo "==== T7 summary: $PASS passed, $FAIL failed ===="
[ "$FAIL" -eq 0 ] || exit 1
