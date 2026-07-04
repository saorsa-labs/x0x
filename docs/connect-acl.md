# x0x connect ACL — default-closed connectivity policy

The connect ACL controls which remote agents may request an outbound TCP connection through the local `x0xd` daemon. It is the policy engine for the Tailnet T4 forwarder (issue #132); the forwarder wires up runtime enforcement but the policy engine, validation surface, and diagnostics endpoint are delivered ahead of it in v1.

**v1 scope:** policy engine, startup validation, diagnostics. There is no runtime forwarder yet. All connection-forwarding requests are denied at the gate until T4 ships.

## Default behaviour

No connect ACL configured → connect is **disabled** for all agents. `ConnectPolicy::default()` is `Disabled`, so an embedder that builds `ServeOptions` without supplying a connect policy gets default-deny for free.

## ACL location

Default path:

- Linux: `/etc/x0x/connect-acl.toml`
- macOS: `/usr/local/etc/x0x/connect-acl.toml`

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

When connect is enabled, `acl_summary.enabled` is `true`, the entry counts are populated, and `disabled_reason` is absent. Counters read `0` until the T4 forwarder (issue #132) is wired.

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
