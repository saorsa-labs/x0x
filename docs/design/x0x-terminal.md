# x0x terminal — interactive remote sessions (Tier 2, deferred)

**Status:** Design exploration — explicitly deferred until Tier 1 (`x0x-exec.md`) ships and we have data on what `exec` cannot cover.
**Filed:** 2026-05-01
**Owner:** dev team (decision pending)
**Companion doc:** [`x0x-exec.md`](x0x-exec.md) (Tier 1, in flight)

---

## 1. Why this is deferred

A general PTY/SSH-replacement is a far larger blast radius than non-interactive exec. Tier 1 alone is expected to cover ~95 % of the testing-fleet use case (every `ssh root@saorsa-N "curl http://127.0.0.1:12600/..."` in `e2e_vps.sh`, plus journalctl/systemctl probes). Before committing to Tier 2, we want to see:

- **What does Tier 1 fail to cover in practice?** A list of real operator tasks that needed an interactive session. If that list is short, Tier 2 may never need to ship.
- **Is the right shape "PTY" or something narrower?** Steering from lead, 2026-05-01: *"Tier 2 should be not a general PTY but an x0x specific type case."*
- **What does the threat model look like once `exec` is widely used?** Audit-log review will surface common abuses (or lack thereof) and inform what extra rails Tier 2 needs.

This doc captures the design space and the open questions so we can return to it informed, not from a blank page.

## 2. The three candidate shapes

In rough order of decreasing scariness:

### 2.1 Constrained PTY

Spawn a real PTY, but the shell binary is hard-pinned by the ACL — typically *not* `/bin/bash`. Examples:

- `journalctl -f -u x0xd` (a real interactive program, no shell escape)
- `htop`, `top`, `iotop`
- A bespoke `x0x-debug-shell` binary that reads stdin lines and dispatches to a closed set of commands (`gossip-stats`, `peers`, `flush-cache`, etc.) without ever invoking `exec()`

**Pros:** Familiar UX. Real terminal redrawing, key handling, signals.
**Cons:** Every TUI program is a potential escape vector. `journalctl -f` followed by `!` in less can drop you into a shell. `vim`'s `:!sh`. Operator must audit every allowed binary for "shell escape" features. The ACL ends up encoding "this binary is non-escapable" — easy to get wrong.

### 2.2 Structured RPC session ("kernel" model)

Not a TTY at all. A long-lived bidirectional QUIC stream where both sides exchange typed records: command frames in, structured response frames out. Closer to a Jupyter kernel or LSP server than to SSH.

```text
client → server: { type: "command", name: "gossip-stats" }
server → client: { type: "result", data: { ... } }
client → server: { type: "command", name: "peers", filter: "eu" }
server → client: { type: "stream-start", id: 1 }
server → client: { type: "stream-row", id: 1, row: {...} }
server → client: { type: "stream-end", id: 1 }
client → server: { type: "command", name: "subscribe-events", topic: "..." }
server → client: { type: "event", topic: "...", payload: ... }
...
```

**Pros:** No escape sequences, no PTY surface, no "what does Ctrl-C do" ambiguity, structured output that GUIs can render. Authorization at the per-command level is natural (extends the Tier 1 ACL with `[[allow.commands.kernel]]`).
**Cons:** Not "SSH-like". Operators expecting a `htop` view do not get one. Implementation cost — every operator command needs an explicit handler, no `exec` shortcut.

### 2.3 Skip Tier 2 entirely

If Tier 1 + the structured-RPC commands we'd add anyway under Tier 2.2 cover the operator workload, there is no third tier. The "interactive" story becomes:

- For one-shot diagnostics → `x0x exec`
- For live event streaming → existing SSE (`/peers/events`, `/dm/events`, `/exec/run` SSE form)
- For dashboards → the existing GUI / external tooling driven by REST + SSE

**Pros:** No new attack surface. No new code. No new ACL.
**Cons:** No `htop`-equivalent. Some operators will dislike this and SSH around it.

## 3. Lead's steer (2026-05-01)

> Tier 2 is something to consider security of and perhaps it should be not a general PTY but an x0x specific type case.

This pushes us toward §2.1 (constrained PTY with hard-pinned binary list) or §2.2 (structured RPC). It explicitly *rules out* a general "give me bash on the remote" feature.

## 4. Transport, if and when we build this

If Tier 2 ships, the transport is **not** the Tier 1 direct-DM path. Direct DMs are message-oriented with per-frame ACKs; that's correct for `exec` and wrong for an interactive session, where:

- Per-keystroke ACK overhead is unacceptable for typing latency.
- Backpressure must be expressed at the byte stream level, not the message level — the existing DM mpsc would buffer or drop, both bad for terminals.
- Resize and signal frames need a clean out-of-band channel, not interleaved with stdout bytes.

The right transport is a dedicated bidirectional QUIC stream on the existing ant-quic connection:

- `Connection::open_bi()` / `accept_bi()` (already exposed by `ant-quic`).
- New stream type prefix byte, e.g. `0x20`, distinguishing terminal sessions from any other future stream-typed protocol on the same connection.
- Length-prefixed framing on each direction:
  - `0x01 stdin <bytes>`
  - `0x02 stdout <bytes>`
  - `0x03 stderr <bytes>`
  - `0x04 resize <rows: u16> <cols: u16>`
  - `0x05 signal <signo: u8>` (client → server, restricted to SIGINT/SIGTERM/SIGHUP)
  - `0x06 exit <code: i32> <signal: i32>`
  - `0x07 keepalive`
  - `0x08 close`

QUIC's per-stream flow control gives correct backpressure for free. The Tier 1 `ExecFrame::Request` shape is irrelevant here — terminals are session-oriented and need a handshake before any process is spawned.

## 5. Authorization (extends Tier 1 ACL)

Same `(agent_id, machine_id)` pair gating, same ACL file, but a separate section. Sketch:

```toml
[[exec.allow]]
agent_id   = "..."
machine_id = "..."

# Tier 1 commands as before.
[[exec.allow.commands]]
argv = ["systemctl", "status", "x0xd"]

# NEW: Tier 2 terminal sessions.
# Disabled by default (no [[allow.terminal]] block = no terminal access).
[[exec.allow.terminal]]
mode = "constrained-pty"           # or "kernel"
binary = "/usr/local/bin/x0x-debug-shell"
# Optional: max session duration, idle timeout, output cap (separate from exec caps).
max_session_secs   = 1800
idle_timeout_secs  = 300
max_output_bytes   = 67_108_864    # 64 MB
require_user_certificate = true     # require AgentCertificate signed by a User key
```

Two non-trivial extra rails compared to Tier 1:

- **`require_user_certificate`** — only honour terminal requests from agents whose `AgentCertificate` is signed by an explicitly-configured `UserId`. Promotes the trust requirement from "this agent has the right key" to "a human approved this agent on our infra". Existing identity machinery supports this (see `src/identity.rs::AgentCertificate`).
- **Session recording (optional).** A flag `record_session = true` writes the full stdin/stdout transcript to a file under `audit_log_path`. Asciinema-compatible format would let us replay sessions verbatim during incident review.

## 6. Open questions to answer before any code

These are the questions Tier 1 operational data should inform:

1. **Is §2.1, §2.2, or §2.3 the right shape?** The decision is data-driven; collect 4–6 weeks of `/diagnostics/exec` usage from the testing fleet and operator interviews before committing.
2. **If §2.1, what is the binary allowlist?** Likely tiny (`x0x-debug-shell` and maybe `journalctl -f`) — and `journalctl` needs a hard policy decision about its escape vectors.
3. **If §2.2, what is the command set?** Probably starts as a wrapper over existing REST endpoints. Risk: it becomes a thin shim with no new value. Reward: a single auth boundary for an entire class of operator tasks.
4. **Should `x0x-debug-shell` be a separate crate or live in this repo?** If it stays in-repo, there's a circular dependency between "the daemon hosts it" and "the daemon spawns it". Probably its own bin target under `src/bin/x0x-debug-shell.rs`, like `x0x-keygen`.
5. **What does `Ctrl-C` mean?** Cancel the session, or pass through SIGINT to the remote process? Different in §2.1 vs §2.2. Constrained PTY: pass-through. Kernel RPC: cancel current command.
6. **Does Tier 2 need its own diagnostics endpoint, or extend `/diagnostics/exec`?** Probably extend, with a `terminal:` sub-section. One mental model, one place to look.
7. **What is the audit trail format for an interactive session?** A summary in the same JSONL as Tier 1 (start, end, exit code, byte counts), plus the optional asciinema recording behind a flag. Replicating an entire keystroke transcript via the CRDT TaskList is the wrong shape — too large, too noisy.

## 7. Decision gate

We commit to one of §2.1 / §2.2 / §2.3 only after:

- Tier 1 has been deployed to the VPS fleet for at least 4 weeks.
- `/diagnostics/exec` has been queried by operators in real workflows (not just CI).
- A short retro doc lists every "I had to SSH because exec couldn't do X" event.
- Lead reviews and picks a shape.

Until that gate passes, this doc remains a parking lot. New entries to §6 are welcome; new code is not.

## 8. Cross-references

- Tier 1: [`x0x-exec.md`](x0x-exec.md)
- ant-quic bidi streams: `Connection::open_bi`, `accept_bi` (see `../ant-quic/src/high_level.rs`)
- Identity & cert chain: `src/identity.rs`, `docs/primers/trust.md`
- Existing diagnostics pattern: `docs/diagnostics.md`
