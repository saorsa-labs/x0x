# x0x exec — remote command execution over the mesh (Tier 1)

**Status:** Tier-1 implementation in progress — protocol, ACL, daemon routing, REST/CLI, diagnostics, and JSONL audit are wired behind an opt-in ACL.
**Filed:** 2026-05-01
**Owner:** dev team (assigned by lead)
**Trigger:** Replace SSH-per-call in `e2e_vps.sh` with a daemon-native execution path. Generalise the existing `tests/runners/x0x_test_runner.py` control-plane primitive into a first-class daemon feature.
**Companion doc:** [`x0x-terminal.md`](x0x-terminal.md) (Tier 2, deferred)

---

## 1. Goal

Allow a local x0x agent to run a strictly-allowlisted, non-interactive command on a remote x0x daemon, with stdout/stderr/exit-code streamed back over the existing direct-message channel.

**In scope (this doc):** non-interactive command execution. No PTY, no shell interpolation, no signal forwarding from the client beyond cancel.

**Out of scope:** interactive terminal, full shell, file editing, port forwarding. See `x0x-terminal.md` for the Tier 2 design that may or may not follow.

**Why now:** the existing `e2e_vps.sh` is dominated by SSH RTT to Singapore/Sydney (~4 s per call). The mesh-driven `e2e_vps_mesh.py` solved this for DM testing by running through x0x's own pubsub. `x0x exec` is the same trick generalised — drop the SSH dependency from the diagnostic and management paths too.

## 2. Constraints (locked by lead, 2026-05-01)

These are not open for negotiation in v1:

1. **ACL keys on (AgentId, MachineId) pairs.** A stolen agent key on a different machine is rejected at the trust layer before reaching the ACL check.
2. **Strict argv allowlist.** Each ACL entry specifies the exact argv vector the agent may execute. Limited templating (see §6.2). No regex, no shell globs.
3. **No shell interpolation, ever.** The remote daemon calls `tokio::process::Command::new(argv[0]).args(&argv[1..])`. Never `/bin/sh -c`. Never `bash -c`.
4. **Hard caps on output, duration, concurrency.** Cap breaches emit a `Warning` frame to the requester *and* are logged to `/diagnostics/exec` so an operator interrogating the remote machine sees them.
5. **Audit trail in a CRDT TaskList** (in addition to a local log file). Append-only, signed, replicated to the requesting agent.
6. **Client disconnect → SIGTERM** the remote process within 5 s, then SIGKILL.
7. **ACL lives at `/etc/x0x/exec-acl.toml`** and changes require a full daemon restart. No hot-reload.

## 3. Architecture

```text
local x0x CLI
  ↓ HTTP (POST /exec/run)
local x0xd
  ↓ signed/encrypted gossip-DM frames (ML-KEM + ChaCha20-Poly1305, ACK'd)
remote x0xd
  ↓ trust check: verified sender + TrustDecision::Accept
  ↓ ACL check: AgentId + MachineId + argv match
  ↓ tokio::process::Command::new(argv[0]).args(&argv[1..])
remote child process
```

No new transport. No new crypto. Reuses the existing direct-message envelope, which already gives us:

- ML-DSA-65 signature verification of the requester's `AgentId`.
- Trust-evaluated delivery (`TrustEvaluator`).
- ACK'd, in-order delivery on a per-peer channel.
- `/diagnostics/dm` visibility for the underlying transport.

The exec service is a new direct-message *kind* that the existing DM dispatcher routes to a new handler.

### 3.1 Why direct DMs and not a new QUIC stream

For Tier 1, the volume is small (≤16 MB stdout per session, ≤32 concurrent sessions) and latency is dominated by command execution time, not framing overhead. The existing DM path works. If profiling later shows the ACK-per-frame overhead is the bottleneck for streaming stdout, we can split: control frames over DMs, bulk stdout over a side QUIC unidirectional stream (mirroring how file transfer works). Don't pre-optimise.

The Tier 2 interactive path *will* need bidirectional QUIC streams for backpressure correctness — that's the whole point of separating the two tiers.

## 4. Wire protocol

Exec uses a stable payload prefix (`x0x-exec-v1\\0`) carried inside the existing encrypted DM plaintext. The prefix lets `dm_inbox` route exec frames before generic `/direct/events` fan-out without a backwards-incompatible envelope change. The bytes after the prefix are a bincode-encoded `ExecFrame`:

```rust
#[derive(Serialize, Deserialize)]
pub enum ExecFrame {
    /// Client → server: kick off a session.
    Request {
        request_id: Uuid,           // client-allocated, unique per local agent
        argv: Vec<String>,          // tokens, no shell metacharacters
        stdin: Option<Vec<u8>>,     // ≤ max_stdin_bytes (server cap)
        timeout_ms: u32,            // clamped to max_duration_secs
        cwd: Option<String>,        // v1 rejects requester-controlled cwd
    },

    /// Server → client: process spawned, here is its OS pid.
    Started { request_id: Uuid, pid: u32 },

    /// Server → client: stdout/stderr chunk. seq is monotonic per stream.
    Stdout { request_id: Uuid, seq: u32, data: Vec<u8> },
    Stderr { request_id: Uuid, seq: u32, data: Vec<u8> },

    /// Server → client: a soft event the operator should see (cap warning,
    /// truncation, etc). Does not terminate the session.
    Warning { request_id: Uuid, kind: WarningKind, message: String },

    /// Server → client: terminal frame. Always the last frame for a session.
    Exit {
        request_id: Uuid,
        code: Option<i32>,          // None if killed by signal
        signal: Option<i32>,        // Unix signal number, or None
        duration_ms: u64,
        stdout_bytes_total: u64,    // including any truncated bytes
        stderr_bytes_total: u64,
        truncated: bool,            // true if any cap was hit
        denial_reason: Option<DenialReason>,  // Some(_) → request never ran
    },

    /// Client → server: renew the short session lease.
    LeaseRenew { request_id: Uuid },

    /// Client → server: cancel an in-flight session.
    Cancel { request_id: Uuid },
}

#[derive(Serialize, Deserialize)]
pub enum WarningKind {
    StdoutCapHit,                   // bytes-per-stream limit reached
    StderrCapHit,
    DurationApproachingCap,         // emitted at warn_duration_secs
    StdoutApproachingCap,           // emitted at warn_stdout_bytes
}

#[derive(Serialize, Deserialize)]
pub enum DenialReason {
    ExecDisabled,                   // [exec].enabled = false
    AgentMachineNotInAcl,           // (agent_id, machine_id) pair has no entry
    ArgvNotAllowed,                 // argv didn't match any allowlist entry
    StdinTooLarge,
    TimeoutTooLarge,
    CwdNotAllowed,
    ConcurrencyLimitReached,
    ShellMetacharInArgv,            // an argv token contained a forbidden char
}
```

Frame ordering on a single direct channel is preserved by the existing DM path (per-peer mpsc), so `seq` exists only for client-side correlation across a possible reconnect (future-proofing — not needed for v1 but free to include).

## 5. Authorization flow

Server-side, for every received `ExecFrame::Request`:

1. **MachineId check.** The DM was delivered over a QUIC connection; `network.rs` already binds the connection to a verified peer `MachineId`. If the connection's MachineId mismatches the agent's announced MachineId, reject at the DM layer (existing `TrustEvaluator::RejectMachineMismatch` path) — never reaches exec.
2. **AgentId check.** The DM envelope is ML-DSA-65-signed by the sender's agent key; this is verified in the existing DM path. If signature fails → existing path rejects. The exec handler trusts that the AgentId on a delivered DM is authentic.
3. **ACL lookup.** Find the first `[[exec.allow]]` entry matching `(agent_id, machine_id)`. If none → respond with `Exit { denial_reason: Some(AgentMachineNotInAcl), ... }`. Tier 1 returns structured denial reasons on-wire for operator/testability; every denial is also recorded in the remote JSONL audit log and `/diagnostics/exec`.
4. **argv match.** Walk the matched entry's commands, accept the first match (§6.2). On no match → `ArgvNotAllowed`.
5. **Metachar reject.** Even though we don't shell out, every argv token is checked for forbidden characters: `;`, `|`, `&`, `>`, `<`, `` ` ``, `$`, newline, null byte. Catches operator confusion and gives one extra layer if the allowlist is mis-authored. On hit → `ShellMetacharInArgv`.
6. **Caps.** stdin size, timeout, and v1 cwd rejection. On breach → corresponding `DenialReason`.
7. **Concurrency check.** If active sessions for this AgentId ≥ `max_concurrent_per_agent`, or total ≥ `max_concurrent_total`, deny.
8. **Spawn.** `tokio::process::Command` with `kill_on_drop(true)`, `stdin/stdout/stderr` piped, `current_dir(default_cwd)` when configured, environment scrubbed to a minimal allowlist (see §6.3).
9. **Stream.** Read stdout/stderr concurrently, send `Stdout`/`Stderr` frames as data arrives. Watch caps. Emit `Warning` at the warn thresholds.
10. **Terminate.** On exit (or cancel, or duration cap), send `Exit` with full stats. Audit-log the close.

The on-wire denial response is **always** the same shape (an `Exit` frame with `denial_reason: Some(_)`); only the local audit log distinguishes the cases.

## 6. ACL file format

`/etc/x0x/exec-acl.toml` (Linux) / `/usr/local/etc/x0x/exec-acl.toml` (macOS). Override path with `x0xd --exec-acl <path>` (intended for tests).

If file is missing → exec is disabled (`enabled = false` is the implicit default).
If file is present but malformed → daemon **refuses to start**. Fail-closed.

### 6.1 Schema

```toml
[exec]
enabled = false                    # default; must be explicit-true to enable

# Hard caps. Server-side enforced. Requests exceeding any cap are denied
# (for stdin/timeout) or truncated (for stdout/stderr).
max_stdout_bytes        = 16_777_216     # 16 MB
max_stderr_bytes        = 16_777_216     # 16 MB
max_stdin_bytes         = 1_048_576      # 1 MB
max_duration_secs       = 300            # 5 min
max_concurrent_per_agent = 4
max_concurrent_total     = 32

# Warning thresholds. Emit a Warning frame and log to /diagnostics/exec
# when crossed. Process keeps running.
warn_stdout_bytes       = 8_388_608      # 8 MB (50% of cap)
warn_duration_secs      = 60             # 20% of default cap

# Default working directory if a request omits cwd. If unset and request
# omits cwd, the process inherits the daemon's cwd.
default_cwd             = "/var/lib/x0x"

# Audit log path. Always written. Required.
audit_log_path          = "/var/log/x0x/exec.log"

# Optional: CRDT TaskList ID to mirror audit entries to. If set, every
# exec event (Request, Started, Exit, Denial) appends a TaskItem to this
# list, replicated to the requesting agent automatically.
audit_tasklist_id       = "01HZX..."     # ULID of an existing TaskList

# --- ACL entries below ---

[[exec.allow]]
description  = "ops-laptop@admin (David)"   # human label, appears in audit
agent_id     = "abc123...64hex"
machine_id   = "def456...64hex"
# Optional: per-entry overrides for caps. None → use [exec] caps.
# max_duration_secs = 30

# Strict argv allowlist for THIS (agent, machine) pair.
# Each [[exec.allow.commands]] entry is one allowed call shape.
[[exec.allow.commands]]
argv = ["systemctl", "status", "x0xd"]      # exact match only

[[exec.allow.commands]]
argv = ["journalctl", "-u", "x0xd", "-n", "<INT>"]
# <INT> is a hardcoded template token: matches a positive integer
# (regex equivalent: ^[1-9][0-9]{0,5}$, max 999_999). No user-supplied
# regexes. Other tokens: <URL_PATH> = ^/[A-Za-z0-9/_.-]{0,256}$ (no "..").

[[exec.allow.commands]]
argv = ["curl", "-s", "http://127.0.0.1:12600<URL_PATH>"]

[[exec.allow.commands]]
argv = ["cat", "/etc/x0x/config.toml"]

# Multiple entries per agent are fine; first match wins.
[[exec.allow]]
description = "ci-runner@github (read-only)"
agent_id    = "ghi789..."
machine_id  = "jkl012..."

[[exec.allow.commands]]
argv = ["x0x", "diagnostics", "dm"]

[[exec.allow.commands]]
argv = ["x0x", "diagnostics", "gossip"]
```

### 6.2 argv matching algorithm

1. Lengths must match. `argv = ["a", "b"]` does not match a 3-token request.
2. Walk left-to-right. For each `(allow_token, request_token)`:
   - If `allow_token` is a literal string → must equal `request_token` byte-for-byte.
   - If `allow_token` is `<INT>` → `request_token` must match `^[1-9][0-9]{0,5}$` (1–999_999).
   - If `allow_token` is `<URL_PATH>` → `request_token` must match the URL_PATH regex above. If `<URL_PATH>` appears as a *suffix* of a literal token (e.g. `"http://127.0.0.1:12600<URL_PATH>"`), the request token must start with the literal prefix and the suffix must match the URL_PATH regex.
3. Only `<INT>` and `<URL_PATH>` exist as templates in v1. Any other `<...>` token in the ACL is a parse error (refuses daemon startup).
4. After argv match, every request token is **independently** checked against the metachar blacklist (§5.5). Defence in depth: even if `<URL_PATH>` regex has a bug, metachars are rejected separately.

This is deliberately restrictive. Operators wanting parameterised behaviour beyond `<INT>` / `<URL_PATH>` should write a wrapper script on the remote and allowlist *that* script, not extend the templating.

### 6.3 Environment scrubbing

The child process inherits a fixed minimal environment:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=<daemon's home>
LANG=C.UTF-8
LC_ALL=C.UTF-8
```

No other env vars from the daemon's environment leak through. The request cannot supply env vars in v1.

## 7. Hard cap behaviour

| Cap | Behaviour |
|---|---|
| `max_stdout_bytes` | Stop forwarding once total reaches cap. Send `Warning { kind: StdoutCapHit }`. Continue counting `stdout_bytes_total` for the final `Exit` frame, but discard data. Process keeps running. |
| `max_stderr_bytes` | Symmetric to stdout. |
| `max_stdin_bytes` | Request denied with `StdinTooLarge` before spawn. |
| `max_duration_secs` | At T=cap-5s, send SIGTERM. At T=cap, send SIGKILL. Send `Exit` with `signal: Some(SIGKILL)`. |
| `max_concurrent_per_agent` | Request denied with `ConcurrencyLimitReached`. |
| `max_concurrent_total` | Same. |
| `warn_stdout_bytes` | At first crossing, emit `Warning { kind: StdoutApproachingCap }`. Increment a counter visible in `/diagnostics/exec`. |
| `warn_duration_secs` | Same shape. |

Cap counters and last-N warning events are exposed at `GET /diagnostics/exec` (§9) so an operator interrogating a remote node sees a steady stream of these even if the requester ignores `Warning` frames.

## 8. Cancellation

Three triggers, one path:

1. **Client sends `ExecFrame::Cancel`** — the local CLI emits this on Ctrl-C, on `x0x exec --cancel <id>`, or on local timeout.
2. **Local x0xd loses its API client** — the HTTP/SSE/WebSocket connection from the CLI to local x0xd drops. Local x0xd auto-emits `Cancel` for every in-flight request from that client.
3. **Lease expiry** — the local daemon sends `LeaseRenew` while the API caller is connected. If renewals stop for the lease window, the remote session is cancelled. This covers gossip-DM delivery paths where no stable direct QUIC lifecycle event is visible.

On cancel, server: SIGTERM the child, wait 5 s, SIGKILL if still alive, send `Exit` (which the requester may not see if the channel is dead; that's fine — the request_id is locally garbage-collected after a 60 s grace period).

`tokio::process::Child::kill_on_drop(true)` is set as a final backstop in case the session task panics.

## 9. Diagnostics

`GET /diagnostics/exec` (mirrors `/diagnostics/dm`, `/diagnostics/gossip`). Bearer-token-protected. Returns:

```json
{
  "enabled": true,
  "active_sessions": 2,
  "active_per_agent": { "abc123...": 2 },
  "totals": {
    "requests_received": 18421,
    "requests_allowed": 18402,
    "requests_denied": 19,
    "denial_breakdown": {
      "agent_machine_not_in_acl": 4,
      "argv_not_allowed": 11,
      "shell_metachar_in_argv": 1,
      "concurrency_limit_reached": 3
    },
    "cap_breaches": {
      "stdout": 2,
      "stderr": 0,
      "duration": 1
    },
    "cap_warnings": {
      "stdout_approaching": 7,
      "duration_approaching": 14
    }
  },
  "recent_warnings": [
    {
      "ts": "2026-05-01T14:22:11Z",
      "kind": "StdoutApproachingCap",
      "agent_id": "abc123...",
      "request_id": "...",
      "argv_summary": "journalctl -u x0xd -n 999999",
      "bytes_at_warn": 8_400_000
    }
  ],
  "acl_summary": {
    "loaded_from": "/etc/x0x/exec-acl.toml",
    "loaded_at": "2026-05-01T09:00:00Z",
    "allow_entry_count": 4,
    "command_entry_count": 17
  }
}
```

The full ACL contents — agent IDs, machine IDs, full argvs — are deliberately *not* in the diagnostics output. They live in the file the operator owns.

CLI: `x0x diagnostics exec`.

## 10. Audit trail

Two layers, both required:

### 10.1 Local file audit

Append-only JSONL at `audit_log_path`. One line per event. Events:

```json
{"ts":"...","event":"request","request_id":"...","agent_id":"...","machine_id":"...","argv":["..."],"matched_acl":"ops-laptop@admin (David)","stdin_bytes":0,"timeout_ms":30000}
{"ts":"...","event":"started","request_id":"...","pid":12345}
{"ts":"...","event":"warning","request_id":"...","kind":"StdoutApproachingCap","bytes":8400000}
{"ts":"...","event":"exit","request_id":"...","code":0,"signal":null,"duration_ms":423,"stdout_bytes":1024,"stderr_bytes":0,"truncated":false}
{"ts":"...","event":"denial","request_id":"...","agent_id":"...","machine_id":"...","argv":["..."],"reason":"ArgvNotAllowed"}
```

File is opened with `O_APPEND`, fsynced on each entry. Operator-rotatable via standard `logrotate`. The daemon does not rotate.

### 10.2 CRDT TaskList audit (v1.1 waiver)

Tier 1 makes the local JSONL file the authoritative audit. The ACL field `audit_tasklist_id` is parsed and retained so deployed configs will not need another schema change, but the CRDT TaskList mirror is explicitly waived from v1 acceptance and deferred to v1.1.

Planned `TaskItem` schema for the v1.1 mirror:

```text
title: "exec [allowed|denied] <argv_summary> ← <agent_short>@<machine_short>"
state: Done (denials never enter Empty/Claimed; they are born Done)
metadata (LWW-Register):
  request_id: ULID
  ts_iso: "..."
  argv: ["..."]
  exit_code: i32 | null
  duration_ms: u64
  stdout_bytes: u64
  stderr_bytes: u64
  truncated: bool
  denial_reason: string | null
  warnings: ["StdoutApproachingCap", ...]
```

When implemented, the TaskList will provide a queryable, replicated, signed audit timeline. If the configured TaskList does not exist or is unreachable, exec will keep working — the local file remains authoritative and the CRDT mirror is best-effort. A future `audit_tasklist_unreachable` counter should show up in `/diagnostics/exec`.

For v1, operators must use `audit_log_path` and `/diagnostics/exec`; `audit_tasklist_id` has no runtime effect beyond being exposed through config parsing.

## 11. CLI

```bash
# Synchronous one-shot. Stdout/stderr stream to local terminal.
# Exit code = remote exit code (or 255 on transport / denial / cap kill).
x0x exec <agent> -- <argv...>

# With timeout (clamped to remote max_duration_secs).
x0x exec <agent> --timeout 30 -- journalctl -u x0xd -n 100

# With stdin from a file.
x0x exec <agent> --stdin-file payload.bin -- some-tool --consume-stdin

# Cancel an in-flight request.
x0x exec <agent> --cancel <request_id>

# List local in-flight requests (this client only).
x0x exec sessions

# Server-side diagnostics on a remote machine.
x0x diagnostics exec                 # local daemon's exec stats
x0x exec <agent> -- x0x diagnostics exec   # remote daemon's exec stats
                                          # (requires that argv to be allowlisted)
```

Agent identifier accepts: full hex `agent_id`, contact short-name (existing contact-store lookup), or VPS host short-name (e.g. `saorsa-7` → resolved via existing contact-name mapping).

## 12. REST API

| Method | Path | CLI | Notes |
|---|---|---|---|
| POST | `/exec/run` | `x0x exec` | Body: `{ agent_id, argv, stdin_b64?, timeout_ms?, cwd? }`. Current implementation blocks and returns the aggregated result `{ code, signal, stdout_b64, stderr_b64, duration_ms, denial_reason, ... }`; SSE streaming can be added later without changing the wire frames. |
| POST | `/exec/cancel` | `x0x exec --cancel` | Body: `{ request_id }`. |
| GET | `/exec/sessions` | `x0x exec sessions` | List sessions originated by this local daemon. |
| GET | `/diagnostics/exec` | `x0x diagnostics exec` | Server-side diagnostics. |

All four are added to `src/api/mod.rs` endpoint registry. `x0x routes` reflects them automatically. API manifest version bumps; total endpoint count rises from 124 to 128.

## 13. Daemon flags & config

```text
x0xd --exec-acl <PATH>     Override default /etc/x0x/exec-acl.toml.
                           Intended for tests; production should use the default.
```

No new config knobs — exec is gated entirely by the ACL file's presence and `[exec].enabled`.

`x0xd --check` is extended to validate the ACL file (parse, schema, agent/machine ID hex format) without starting the daemon.

`x0xd --doctor` reports exec status: enabled/disabled, ACL path, allow-entry count.

## 14. Files to create

```text
src/exec/mod.rs                    # public API: run_remote_exec(...) on Agent
src/exec/protocol.rs               # ExecFrame enum, bincode coding
src/exec/acl.rs                    # TOML schema, parser, argv matcher, fail-closed loader
src/exec/service.rs                # server: dispatcher, spawn, stream, cap enforcement
src/exec/client.rs                 # client: send Request, collect frames, surface to caller
src/exec/audit.rs                  # local JSONL log + optional CRDT TaskList bridge
src/exec/diagnostics.rs            # ExecDiagnostics counter struct + recent_warnings ring buffer
src/api/exec_handlers.rs           # POST /exec/run (sync + SSE), /exec/cancel, /exec/sessions, /diagnostics/exec
src/cli/commands/exec.rs           # x0x exec, x0x exec --cancel, x0x exec sessions
                                   # x0x diagnostics exec
tests/exec_acl_unit.rs             # ACL parsing, argv matching (positive + negative)
tests/exec_caps_unit.rs            # cap-enforcement state machine
tests/exec_integration.rs          # local 2-daemon end-to-end, denial paths, cancel
tests/e2e_exec.sh                  # local 3-daemon: alice→bob allowed, charlie→bob denied
docs/exec.md                       # operator guide: deploying ACL, examples, troubleshooting
```

## 15. Files to modify

```text
src/dm.rs                          # add DmKind::Exec variant; route to exec::service
src/api/mod.rs                     # register 4 new endpoints in EndpointRegistry
src/cli/mod.rs                     # register exec subcommand
src/lib.rs                         # re-export Agent::run_remote_exec
src/bin/x0xd.rs                    # parse --exec-acl flag; load ACL on startup;
                                   # fail-closed if malformed; wire ExecService
docs/design/api-manifest.json      # add 4 endpoints; bump endpoint count
CLAUDE.md                          # mention /etc/x0x/exec-acl.toml + 4 endpoints
TEST_SUITE_GUIDE.md                # document e2e_exec.sh
```

Optional follow-up (separate PR after exec lands):

```text
tests/e2e_vps.sh                   # convert SSH-based curl probes to x0x exec
                                   # to demonstrate the testing-ergonomics win
```

## 16. Test plan

Every PR landing this feature must include all of:

- **Unit, ACL** (`exec_acl_unit.rs`):
  - well-formed file → loads
  - missing required field → daemon refuses to start
  - invalid hex in agent_id/machine_id → refuses to start
  - unknown `<TEMPLATE>` token → refuses to start
  - exact-match argv accepts only exact match
  - `<INT>` accepts `1`, `12345`, rejects `0`, `-1`, `1e5`, `1.0`, ``5`a``
  - `<URL_PATH>` accepts `/health`, `/foo/bar`, rejects `/..`, `/foo bar`, `/foo;ls`
  - shell metachar in any token rejects regardless of allowlist
  - length mismatch rejects

- **Unit, caps** (`exec_caps_unit.rs`):
  - stdout cap → truncates, emits `Warning`, sets `truncated: true`, process unkilled
  - duration cap → SIGTERM sent at T-5s, SIGKILL at T, `Exit { signal: Some(SIGKILL) }`
  - concurrent cap → 5th request from same agent denied with `ConcurrencyLimitReached`
  - warn threshold crossed once → counter increments by 1, even if multiple Stdout chunks straddle it

- **Integration** (`exec_integration.rs`):
  - alice → bob allowed argv: stdout/stderr captured, exit_code matches, audit log line written
  - alice → bob denied argv: `Exit { denial_reason: Some(ArgvNotAllowed) }`, no process spawned
  - alice → charlie denied (no ACL entry): `AgentMachineNotInAcl`
  - bob client disconnect mid-exec: bob's child receives SIGTERM within 5s
  - alice cancel: child SIGTERMed, `Exit` frame received with `signal: Some(SIGTERM)`
  - audit TaskList: configured ID receives a TaskItem on every event; alice (the requester) sees it via existing CRDT sync

- **E2E** (`tests/e2e_exec.sh`, local, no VPS):
  - 3-daemon (alice, bob, charlie). Bob has ACL allowing alice for `["echo", "<INT>"]` and `["printenv", "PATH"]`.
  - `x0x exec bob -- echo 42` → stdout `42`, exit 0
  - `x0x exec bob -- echo hello` → denied (template mismatch)
  - `x0x exec bob -- echo 99 ; ls` → denied (metachar in token, even though we don't shell)
  - `x0x exec bob -- rm -rf /` → denied (not in allowlist)
  - `x0x exec bob -- printenv PATH` → returns `/usr/local/sbin:...` (env scrub verified)
  - charlie tries same allowed argv → denied (`AgentMachineNotInAcl`)
  - `x0x diagnostics exec` on bob shows the right counter increments

- **Build-validator**: 0 warnings, fmt clean, clippy `-D warnings` clean.

- **Test-runner**: full nextest suite remains 100 % passing; new tests add ≥ 30 assertions.

## 17. Acceptance criteria

Tier 1 ships when **all** of these hold:

1. `cargo nextest run --all-features --workspace` green, with the new tests counted.
2. `tests/e2e_exec.sh` green on a local mesh, two consecutive runs.
3. `x0xd --check --exec-acl /tmp/bad.toml` exits non-zero with a specific parse error for each of: missing required field, invalid hex, unknown template token.
4. `x0xd` with no `/etc/x0x/exec-acl.toml` starts cleanly with `enabled=false` reflected in `/diagnostics/exec`.
5. A request that breaches `max_stdout_bytes` is reflected in `/diagnostics/exec` `cap_breaches.stdout` counter on the *remote* node.
6. Killing the local CLI mid-exec causes the remote child process to receive SIGTERM within 5 s (verified by inspecting `ps` on the remote).
7. CRDT TaskList audit mirroring is either implemented or explicitly waived to v1.1. For v1 this document records the waiver and JSONL remains authoritative.
8. `docs/exec.md` exists with a working "deploy this ACL on saorsa-7, run this command from your laptop" example using real but redacted IDs.

## 18. Non-goals (explicit)

- **No PTY, no interactivity.** Use Tier 2 if it ever ships.
- **No environment variables in requests.** Add later if a concrete need appears.
- **No file upload.** Use existing `/files/send`.
- **No port forwarding.** Out of scope; possibly never in scope.
- **No PAM / OS password auth.** The trust boundary is the x0x identity + machine pin, not OS credentials.
- **No hot-reload of the ACL.** Restart the daemon. This is intentional — hot-reload of a security policy is a footgun.
- **No "any" wildcard in argv.** If an operator wants flexible commands, they wrap them in a script and allowlist that.
- **No regex in the ACL.** `<INT>` and `<URL_PATH>` are the only templates. New templates require a code change and a test.
- **No SSH replacement for end users.** This feature is for the testing fleet and the operator. End-user shell access is a separate product question.

## 19. Open questions (defer until after first PR lands)

- Is local-file JSONL audit + optional CRDT TaskList the right shape, or should the CRDT be mandatory? Land file-only first, see how operators use it.
- Should `Exit` frames carry the *first 1 KiB of stdout* even when the channel was healthy, so the audit log has self-contained context without a second roundtrip? Possibly yes. Needs a `first_stdout_preview` field; mark for v1.1.
- Does the CRDT audit TaskList need a separate MLS group per (requester ↔ remote) pair, or does the existing daemon-wide group suffice? Existing group is fine for v1; revisit if multiple operators share a remote.

## 20. Cross-references

- Existing precedent: `tests/runners/x0x_test_runner.py` is a primitive form of this. The systemd service file `tests/runners/x0x-test-runner.service` already lives on every VPS.
- Trust model: `docs/primers/trust.md`, `src/trust.rs::TrustEvaluator`.
- DM pipeline this rides on: `docs/design/dm-over-gossip.md`, `src/dm.rs`, `src/direct.rs`.
- Diagnostics pattern: `docs/diagnostics.md`, `src/api/handlers.rs::diagnostics_*`.
- Tier 2 deferred design: [`x0x-terminal.md`](x0x-terminal.md).
