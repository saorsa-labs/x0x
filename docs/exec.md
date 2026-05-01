# x0x exec — constrained remote command execution

`x0x exec` is a Tier-1 operator/testing primitive for running a **non-interactive, strictly allowlisted** command on a remote `x0xd` over the existing x0x mesh.

It is intentionally not SSH:

- no PTY and no interactive shell;
- no `/bin/sh -c`, `bash -c`, globs, or regex allowlists;
- authorization is the signed x0x `(AgentId, MachineId)` pair plus the local contact/trust store;
- every command must match an ACL argv vector exactly, except for the built-in `<INT>` and `<URL_PATH>` templates.

## Transport and security model

Exec frames are carried inside the existing signed/encrypted gossip-DM envelope. The client forces the gossip-DM path (`require_gossip = true`) and does not use the legacy raw-QUIC direct-message fallback.

The daemon routes payloads with the stable `x0x-exec-v1\0` prefix to the exec service before generic `/direct/events` fan-out, so exec frames do not appear as normal direct messages.

Remote execution is processed only when all of the following are true:

1. the DM envelope signature verifies the requester `AgentId`;
2. the sender's `AgentId → MachineId` binding is verified;
3. the local trust evaluator returns `Accept`;
4. the ACL contains the exact `(agent_id, machine_id)` pair;
5. the argv vector matches an allowed command;
6. stdin, timeout, concurrency, and output caps pass.

## ACL location

Default path:

- Linux: `/etc/x0x/exec-acl.toml`
- macOS: `/usr/local/etc/x0x/exec-acl.toml`

Override for tests:

```bash
x0xd --exec-acl ./exec-acl.toml
```

Missing default ACL means exec is disabled and the daemon still starts. A missing path supplied with `--exec-acl` is an error. A malformed ACL always fails closed and prevents daemon startup or `x0xd --check` success.

## Minimal ACL

```toml
[exec]
enabled = true
max_stdout_bytes = 16777216
max_stderr_bytes = 16777216
max_stdin_bytes = 1048576
max_duration_secs = 300
max_concurrent_per_agent = 4
max_concurrent_total = 32
warn_stdout_bytes = 8388608
warn_stderr_bytes = 8388608
warn_duration_secs = 60
audit_log_path = "/var/log/x0x/exec.log"

[[exec.allow]]
description = "ops-laptop"
agent_id = "<64-hex-agent-id>"
machine_id = "<64-hex-machine-id>"

[[exec.allow.commands]]
argv = ["systemctl", "status", "x0xd"]

[[exec.allow.commands]]
argv = ["journalctl", "-u", "x0xd", "-n", "<INT>"]

[[exec.allow.commands]]
argv = ["curl", "-s", "http://127.0.0.1:12600<URL_PATH>"]
```

Supported templates:

- `<INT>`: positive integer `1..999999`;
- `<URL_PATH>`: absolute path using only `A-Za-z0-9/_.-`, no `..`, max 257 chars including leading `/`;
- a literal prefix ending in `<URL_PATH>`, e.g. `http://127.0.0.1:12600<URL_PATH>`.

Any other `<...>` token is a parse error.

Every request argv token is also checked for shell metacharacters (`;`, `|`, `&`, `>`, `<`, backtick, `$`, newline, and NUL). This is defence in depth; commands are still spawned without a shell.

## CLI

```bash
# Run an allowlisted command.
x0x exec <agent_id> -- systemctl status x0xd

# Timeout in seconds; remote ACL caps still apply.
x0x exec <agent_id> --timeout 30 -- journalctl -u x0xd -n 100

# Send stdin from a local file.
x0x exec <agent_id> --stdin-file payload.bin -- some-tool --consume-stdin

# Cancel a local in-flight request.
x0x exec <agent_id> --cancel <request_id>

# List local pending and remote active sessions.
x0x exec sessions

# Local exec diagnostics.
x0x diagnostics exec
```

For binary output, use `--json` and decode `stdout_b64` / `stderr_b64`.

## REST API

All endpoints require the normal local daemon bearer token.

### `POST /exec/run`

Request:

```json
{
  "agent_id": "<64-hex-agent-id>",
  "argv": ["journalctl", "-u", "x0xd", "-n", "100"],
  "timeout_ms": 30000,
  "stdin_b64": null
}
```

Response:

```json
{
  "ok": true,
  "request_id": "<32-hex-request-id>",
  "code": 0,
  "signal": null,
  "duration_ms": 421,
  "stdout_b64": "...",
  "stderr_b64": "",
  "stdout_bytes_total": 1024,
  "stderr_bytes_total": 0,
  "truncated": false,
  "denial_reason": null,
  "warnings": []
}
```

Denials are returned as a normal terminal result with `denial_reason` set, for example `"argv_not_allowed"`.

### `POST /exec/cancel`

```json
{ "request_id": "<32-hex-request-id>", "agent_id": "<optional-target-agent-id>" }
```

### `GET /exec/sessions`

Lists local pending client requests and remote child sessions.

### `GET /diagnostics/exec`

Reports whether exec is enabled, active session counts, denial/cap counters, recent warnings, and a safe ACL summary. Full ACL contents are deliberately not exposed.

## Runtime behaviour

- Environment is scrubbed to `PATH`, `HOME`, `LANG=C.UTF-8`, and `LC_ALL=C.UTF-8`.
- Requester-controlled `cwd` is rejected in v1; use `default_cwd` in the ACL if needed.
- Output caps stop forwarding but continue draining and counting child pipes, preventing child deadlock.
- The client renews a short exec lease while waiting. If renewals stop, the remote child is terminated.
- Cancellation and lease expiry send SIGTERM first, then SIGKILL after the grace window.
- Audit events are appended to `audit_log_path` as JSONL and fsynced per entry.

## Audit mirror v1.1 waiver

Tier 1 treats the local JSONL file as the authoritative audit record. The ACL field `audit_tasklist_id` is parsed and preserved for forward compatibility, but CRDT TaskList mirroring is explicitly deferred to v1.1. Operators should not rely on TaskList audit replication until that follow-up lands; use `audit_log_path` plus `/diagnostics/exec` for v1 acceptance and incident review.

## Pre-flight validation

```bash
x0xd --check --exec-acl ./exec-acl.toml
```

This validates TOML syntax, required fields, ID hex lengths, caps, and allowed templates without starting the daemon.
