# Diagnostics

> Back to [SKILL.md](https://github.com/saorsa-labs/x0x/blob/main/SKILL.md)

## Health Check

```bash
curl http://127.0.0.1:12700/health
# {"ok":true,"status":"healthy","version":"<current_version>","peers":4,"uptime_secs":300}
```

## Rich Status

```bash
curl http://127.0.0.1:12700/status
# {
#   "ok": true,
#   "status": "connected",        // connected | connecting | isolated | degraded
#   "version": "<current_version>",
#   "uptime_secs": 300,
#   "api_address": "127.0.0.1:12700",
#   "external_addrs": ["203.0.113.5:5483"],
#   "agent_id": "8a3f...",
#   "peers": 4,
#   "warnings": []
# }
```

## Network Details

```bash
curl http://127.0.0.1:12700/network/status
# NAT type, external addresses, direct/relayed connection counts,
# hole punch success rate, relay/coordinator state, RTT
```

## Doctor (Pre-flight Diagnostics)

Human-friendly CLI path:

```bash
x0x doctor
```

Daemon-native path:

```bash
x0xd doctor
# x0xd doctor
# -----------
# PASS  binary: /home/user/.local/bin/x0xd
# PASS  x0xd found on PATH
# PASS  configuration loaded
# PASS  daemon reachable at 127.0.0.1:12700
# PASS  /health ok=true
# PASS  /agent returned agent_id
# PASS  /status connectivity: connected
# -----------
# PASS  all checks passed
```

## WebSocket outbound-queue health (WS1.1 / #122)

```bash
curl http://127.0.0.1:12700/diagnostics/ws
# {
#   "ok": true,
#   "ws_outbound_capacity": 1024,
#   "ws_outbound_dropped": 0,
#   "ws_slow_consumer_closes": 0
# }
```

Each WebSocket session has a **bounded** outbound queue (`ws_outbound_capacity`, default `1024`).
Two feeder policies are distinguished when the queue fills:

- **`ws_outbound_dropped`** — topic/control/error frames dropped on a full queue.
  Topic data is re-obtainable via gossip, so dropping is safe and the session stays alive.
- **`ws_slow_consumer_closes`** — sessions closed with WebSocket close code `1013`
  ("try again later"). A full queue on the direct-message or keepalive feeder means the
  client reader is stalled; the daemon fails loud (closes the session) rather than
  silently dropping DMs. Counted at most once per session. The keepalive pinger (30 s)
  is the reliable detector: a stalled reader is closed within ~one keepalive interval.

A persistently rising `ws_outbound_dropped` (without a corresponding `ws_slow_consumer_closes`)
points to a client that reads topic frames slowly but never fully stalls; investigate the
client. Any non-zero `ws_slow_consumer_closes` indicates a client that stopped reading entirely.

`GET /ws/sessions` (unchanged) lists active sessions and shared topic subscriptions.

## Durable send stage timers (#336 phase 1)

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12700/diagnostics/dm
# {
#   "ok": true,
#   "stats": { ... },
#   "last_durable_send": {
#     "strict_gate_ms": 120,
#     "publish_ms": 45,
#     "ack_wait_ms": 180,
#     "elapsed_ms": 345,
#     "budget_stage": "ack_wait_ms"
#   },
#   "last_ack_publish_ms": 12
# }
```

`last_durable_send` is the sender's last durable gossip-inbox send. The three
named stages are a partition of `elapsed_ms` (daemon-side wall). `budget_stage`
is the largest of the three, so a slow send names which stage consumed the
budget. A send-timeout **504** from `POST /direct/send` exports the same
fields on the error body; `error` remains `timeout` and `detail` stays the
existing Display string.

`last_ack_publish_ms` is the receiver's last durable (v2) ACK publish
duration. Compare it with the sender's `ack_wait_ms` to see whether the ACK
publish itself or the reverse path held the waiter.

`stats.ack_publish_route_failed` increments when the ACK never left this
recipient: both first-success hedge routes failed, or the bounded publisher
could not schedule the job (full queue / stopped worker). Read the pair as:

| `last_ack_publish_ms` | `ack_publish_route_failed` | Meaning |
|---|---|---|
| absent | unchanged | ACK was never scheduled (no durable v2 ACK publish on this daemon yet) |
| present | incremented | ACK publish was attempted and both routes failed |
| present | unchanged | ACK was handed to PlumTree; a sender 504 is a reverse-path / waiter miss |

These fields are measurement only. They are not a latency SLA. HTTP status
codes and sender 504 stage timer field names are unchanged.

## API-unserved watchdog (#384)

The daemon arms a self-probe watchdog at startup: a dedicated OS thread
(outside the async runtime, so it survives a wedged runtime) issues a bare
`GET /health HTTP/1.0` over loopback every `probe_interval_secs` (default
10). If the probe is unserved — TCP accepted but HTTP never answered — for
`miss_threshold` consecutive probes (default 3) past `startup_grace_secs`
(default 90), the watchdog logs an `ERROR` with everything reachable without
tokio (PubSub dispatcher counters, the platform thread list, agent/machine
IDs) and then, when `abort_on_stall` resolves true, calls
`std::process::abort()` so a supervisor restarts the daemon and a core
dump/backtrace exists.

```toml
# x0xd.toml — all keys optional; section shows the defaults
[api_watchdog]
enabled = true            # master switch (default true)
probe_interval_secs = 10  # /health self-probe cadence
probe_timeout_secs = 3    # per-probe connect+read timeout
miss_threshold = 3        # consecutive misses (past grace) to trip
startup_grace_secs = 90   # failures before this never count
abort_on_stall = true     # default: auto — see below
```

`abort_on_stall` defaults to **auto**: resolved at arm time from the same
supervision detection the upgrade path uses — `true` when the daemon runs
under a supervisor (`INVOCATION_ID` set, parent process `systemd`, or
`X0X_SUPERVISED=1`), `false` for terminal-launched daemons. A supervised
`Restart=always` unit therefore self-heals the #384 wedge shape (process
"active", `/health` accepts TCP and never answers, gossip producer 0/s);
an unsupervised daemon only logs. The watchdog disarms itself the moment
shutdown begins, and one probe success resets the miss count.

Every missed probe also emits a `WARN` (`x0x::api_watchdog` target) with the
miss count and probe outcome, so a developing wedge is visible in the
journal before the trip fires.
