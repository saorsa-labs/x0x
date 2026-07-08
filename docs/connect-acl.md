# x0x connect ACL — default-closed connectivity policy

The connect ACL controls which remote agents may request an outbound TCP connection through the local `x0xd` daemon. It is the policy engine for the Tailnet forwarder — the forwarder shipped in v0.29.0 (#183), so an enabled ACL authorizes live TCP forwards at runtime (inbound loopback targets only).

**Scope:** policy engine, startup validation, diagnostics, and runtime enforcement. An enabled ACL authorizes per-flow TCP forwards; a disabled or absent ACL denies every forward request at the gate.

## Default behaviour

No connect ACL configured → connect is **disabled** for all agents. `ConnectPolicy::default()` is `Disabled`, so an embedder that builds `ServeOptions` without supplying a connect policy gets default-deny for free.

## ACL location

Default path:

- Linux: `/etc/x0x/connect-acl.toml`
- macOS: `/usr/local/etc/x0x/connect-acl.toml`

> **Named instances get their own default ACL path.** A daemon started with `--name <plane>` (for example `--name testnet`) resolves its default connect ACL from `connect-acl-<plane>.toml` (e.g. `/etc/x0x/connect-acl-testnet.toml`), not the shared `/etc/x0x/connect-acl.toml`, so co-located prod / testnet / `:443` daemons no longer silently arm each other from one policy file (#189). An unnamed daemon still uses the shared default — give it an explicit `--connect-acl` if you run more than one unnamed instance. `x0xd` logs the resolved connect-ACL path at startup.

Override for tests or non-default installs:

```bash
x0xd --connect-acl ./connect-acl.toml
```

Missing default ACL → connect is disabled, daemon starts normally.
A missing path supplied with `--connect-acl` → hard error, daemon exits.
A malformed ACL or any non-loopback target → hard error, daemon exits (or `--check` fails).

## Minimal ACL

```toml
[connect]
enabled = true

[[connect.allow]]
description = "ops-laptop"
agent_id = "<64-hex-agent-id>"
machine_id = "<64-hex-machine-id>"
targets = [
    "127.0.0.1:22",
    "127.0.0.1:5900",
    "[::1]:8080",
]
```

Each `[[connect.allow]]` entry grants the `(agent_id, machine_id)` pair access to the listed loopback targets. Matching is **exact**: `127.0.0.1:22` does not grant `[::1]:22`.

## Target validation rules

Every target is validated at **load time** — a bad target is a hard error that blocks daemon startup and fails `--check`. The rules:

1. **Numeric IP:port literals only.** `localhost:22` is rejected — name resolution is ambiguous and removes the resolver from the trusted computing base. Write `127.0.0.1:22` or `[::1]:22`.
2. **Port 0 is not a connectable target.**
3. **Loopback only.** `Ipv4Addr::is_loopback()` covers all of `127.0.0.0/8`; `Ipv6Addr::is_loopback()` covers exactly `::1`. Any other address (LAN, Internet, link-local) is rejected.
4. **IPv4-mapped IPv6** (`[::ffff:127.0.0.1]:22`) is rejected with an actionable message: write it as `127.0.0.1:PORT`.
5. **No port ranges or CIDR.** Exact host:port literals only. Use multiple entries for multiple targets.

## Security model

- The gate evaluates checks in this order: unverified sender → trust rejected → connect disabled → target not loopback (runtime defense-in-depth) → pair not in ACL → target not in entry. An unverified or untrusted peer learns nothing about whether connect is enabled or which targets exist.
- `deny_unknown_fields` is applied to `[connect]` and `[[connect.allow]]`: a misspelled key (`taregts`, `enable`) fails loudly rather than silently yielding a permissive policy.
- The `[connect]` section lives **inside the ACL file**, not in the daemon config TOML. The daemon config knows nothing about connect. This mirrors the exec ACL design.

## Agent identity granularity (#192)

The ACL is keyed on the exact `(agent_id, machine_id)` pair, but the inbound forward path receives the stream over a QUIC connection that cryptographically authenticates only the **machine** (the ant-quic `PeerId` == `MachineId`). The opener's `agent_id` is **not** transmitted on the wire — the `ForwardHeader` carries only `target_host` and `target_port`.

The inbound accept loop resolves the opener's agent identity from the identity discovery cache: it collects **every** `AgentId` whose `machine_id` matches the transport-authenticated peer. The connect gate then checks the ACL for **all** resolved agents and fails-closed if any is unauthorized:

- **Single agent on the machine (the common case):** the resolved set has one agent; the ACL enforces agent-granular authorization exactly as written.
- **Multiple agents on the machine:** the QUIC transport cannot prove which agent opened the stream, so the gate requires **every announced agent** on the machine to be authorized for the target. If any announced agent lacks authorization the forward is **denied** — see [Limitations](#limitations-announced-agents-only) for the residual window this leaves.

This is fail-closed by design. If you co-locate multiple agents on one machine and need forwards to work, authorize every agent for the same targets, or do not co-locate agents with different ACL requirements. Full per-agent cryptographic authentication (signed agent attestation in the forward header) is a documented future enhancement that would lift the multi-agent restriction without changing the ACL model.

### Limitations: announced agents only

The agent set checked by the gate comes from the identity **discovery cache**, which is populated from machine-signed `IdentityAnnouncement`s propagated via gossip. An agent that has started but whose announcement has not yet propagated (gossip lag after `join_network`, before the first heartbeat re-announce reaches this peer) is **absent** from the cache and therefore **not checked**. Threat scenario: a hostile agent starts on a machine, and an inbound forward arrives before its announcement propagates — the gate runs only against the benign, already-announced agents and may authorize the forward.

The QUIC transport authenticates the **machine**, not the agent; the discovery cache is best-effort, not a real-time membership oracle. Eliminating this residual window requires cryptographic agent attestation in the forward header — the deferred option discussed in PR #201's design note. Until then, the guarantee is: *every agent known to this peer at accept time must be authorized*, not *every agent on the machine*.

## CLI

```bash
# Pre-flight validation (does not start the daemon).
x0xd --check --connect-acl ./connect-acl.toml

# View connect-ACL policy summary and allow/deny counters.
x0x diagnostics connect
```

## REST API

### `GET /diagnostics/connect`

Returns the [`ConnectDiagnosticsSnapshot`](../src/connect/diagnostics.rs):

```json
{
  "streams_allowed": 0,
  "streams_denied": 0,
  "denial_breakdown": {},
  "acl_summary": {
    "enabled": false,
    "loaded_from": "/usr/local/etc/x0x/connect-acl.toml",
    "loaded_at_unix_ms": 0,
    "allow_entry_count": 0,
    "target_entry_count": 0,
    "disabled_reason": "acl_missing"
  }
}
```

When connect is enabled, `acl_summary.enabled` is `true`, the entry counts are populated, and `disabled_reason` is absent. The `streams_allowed` / `streams_denied` counters increment on each authorized or denied forward.

The `denial_breakdown` map is keyed by `ConnectDenialReason` in `snake_case`:

| Key | Meaning |
|-----|---------|
| `unverified_sender` | Peer not cryptographically verified |
| `trust_rejected` | Trust decision was not Accept |
| `connect_disabled` | No connect ACL / policy Disabled |
| `target_not_loopback` | Requested target is not loopback (runtime defense-in-depth) |
| `agent_machine_not_in_acl` | (agent, machine) pair not in the ACL |
| `target_not_allowed` | Pair is in the ACL but target is not in its entry |

## Pre-flight validation

```bash
x0xd --check --connect-acl ./connect-acl.toml
```

This validates TOML syntax, `deny_unknown_fields` constraints, agent/machine ID hex lengths, and the loopback-only target invariant — without starting the daemon.

Example output (valid ACL):

```
Configuration is valid
...
Connect ACL summary: ConnectAclSummary {
    enabled: true,
    loaded_from: "/path/to/connect-acl.toml",
    loaded_at_unix_ms: 1751500000000,
    allow_entry_count: 1,
    target_entry_count: 3,
    disabled_reason: None,
}
```

## See also

- ADR-0019: `docs/adr/0019-connect-acl-default-closed.md`
- T4 forwarder (runtime enforcement): issue #132
- Exec ACL (design precedent): `docs/exec.md`
