# Diagnostics

> Back to [SKILL.md](https://github.com/saorsa-labs/x0x/blob/main/SKILL.md)

## Fleet CPU metrics

On multi-daemon bootstrap hosts, co-tenant `%CPU` is **not** a valid acceptance
metric. See [runbooks/fleet-cpu-metrics.md](runbooks/fleet-cpu-metrics.md)
(issue [#656](https://github.com/saorsa-labs/x0x/issues/656); envelope fix:
[saorsa-gossip#76](https://github.com/saorsa-labs/saorsa-gossip/issues/76)).

## Health Check

```bash
curl http://127.0.0.1:12700/health
# {"ok":true,"status":"healthy","version":"<current_version>","peers":4,"send_ready_peers":4,"uptime_secs":300}
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
#   "send_ready_peers": 4,
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
publish itself or the reverse path held the waiter. The field is always
present (`null` until a v2 ACK has been published). `ack_publish_route_failed`
is the same counter as `stats.ack_publish_route_failed` and is also present
at the top level so a Tester can capture both keys on every durable 200/504.

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

## Inbound-by-topic counters (#674)

`GET /diagnostics/gossip` carries an `inbound_by_topic` object that attributes
inbound PubSub frames and bytes to a topic class, counted off the already-
decoded PlumTree header before any signature work — so refused and later-
discarded frames still count. Before this, inbound verify cost could only be
inferred from per-topic message-cache eviction rates.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12700/diagnostics/gossip
# "inbound_by_topic": {
#   "caps":          { "eager": { "frames": 4312, "bytes": 98211304 } },
#   "announce_blob": { "eager": { "frames": 2864, "bytes": 49132896 } }
# }
```

Shape: `{ class: { kind: { "frames": n, "bytes": n } } }`. Untouched
class/kind pairs are omitted, so a fresh daemon renders `{}`.

Stable class keys:

| Key | Topics |
|---|---|
| `announce_blob` | `x0x/announce/v3/blob` |
| `caps` | `x0x/caps/v1`, `x0x/caps/v1/request/targeted-v2`, `x0x/caps/v1/response/targeted-v2`, `x0x/caps/v2/digest` |
| `dm_bus` | `x0x/dm/v1/bus` |
| `presence` | `x0x.presence.global` |
| `other` | every other topic id |

Stable kind keys (matching the lowercase naming of `pubsub_stages`
`outbound_by_kind`): `eager`, `ihave`, `iwant`, `ping`, `ack`, `find`,
`presence`, `anti_entropy`, `shuffle`. Frames whose header does not decode
are unclassifiable and are not counted.

The companion `/diagnostics/dm` counter `caps_advert_prefiltered_stale`
counts capability adverts and digest extensions that were dropped by the
freshness pre-check (#674) without an ML-DSA-65 verify because the store
already held state at least as new.

## Soak instrumentation (#288)

All fields below are on `GET /diagnostics/gossip`. Every counter is cumulative
and monotonic for the life of the process, so a rate needs two samples and the
clock: always record `uptime_secs` with a baseline, and discard a pair whose
`uptime_secs` went backwards (the daemon restarted, e.g. a self-update).
Use these rates, not host `%CPU`, for fleet acceptance — co-tenant `%CPU` is
invalid evidence (#656).

| JSON path | Meaning |
|---|---|
| `uptime_secs` | Seconds since this daemon started. |
| `inner_envelope_verify.count` | x0x inner-envelope (V2/V3 signed pub/sub message) ML-DSA-65 verifies executed, successful and failed. |
| `inner_envelope_verify.failed` | Subset of `count` whose signature did not verify. |
| `inner_envelope_verify.total_ns` | Cumulative wall-clock nanoseconds inside those verify calls. |
| `pubsub_stages.verify.count`, `.total_ns`, `.max_ns` | saorsa-gossip outer-frame verify stage (header ML-DSA-65 verify plus the ADR-012 payload-hash check), successful and failed. Duplicates dropped before verify are in `pubsub_stages.eager_duplicate_dropped_pre_verify`. |
| `dispatcher.<lane>.received`, `.completed`, `.timed_out` | Per-lane handler counts; `<lane>` is `pubsub`, `membership` or `bulk`. |
| `dispatcher.<lane>.total_elapsed_ns`, `.max_elapsed_ms` | Cumulative and worst handler wall-clock time. Mean = `total_elapsed_ns / (completed + timed_out)`. |
| `dispatcher.<lane>.over_100ms_count`, `.over_1s_count`, `.over_5s_count`, `.over_30s_count` | Cumulative (not disjoint) counts of handler invocations at or above each threshold. |
| `dispatcher.recv_depth.<lane>.latest`, `.max`, `.capacity` | Receive-queue depth sampled at dequeue. |

Combined observed-stage call rate =
Δ(`inner_envelope_verify.count` + `pubsub_stages.verify.count`) / Δ`uptime_secs`.

The `inner_envelope_verify` fields are independent lock-free counters, not an
atomic tuple snapshot. A verification in progress while the endpoint is read
can appear in `count` before its `failed` or `total_ns` update appears. Treat
failure ratios and mean verify time from small sample deltas as approximate;
use a sufficiently large window or combine adjacent windows. Do not require
the fields from one response, or one low-volume delta, to satisfy an exact
ratio invariant.

That combined rate is an **upper-bound proxy for cryptographic operations in
these two observed stages**, not an exact operation count and not a bound on
daemon-wide ML-DSA work. The two counters draw the line differently: the outer
`pubsub_stages.verify` stage times the whole saorsa-gossip verify call, so its
`count` INCLUDES frames whose public key or signature is malformed and fail
before any cryptography runs, whereas `inner_envelope_verify.count` excludes
those. Conversely, outer frames rejected on the header version / payload-hash
shape check return before the stage timer is recorded and are counted nowhere.

`inner_envelope_verify` counts one observation per call that reaches the
cryptographic verify. Envelopes rejected earlier (malformed key or signature,
agent-id/public-key mismatch) cost no ML-DSA work and are not counted. The
counters are process-wide, so they include every caller of the decode entry
points, not only gossip delivery.

The proxy can still be lower than total daemon verification work because it
does not include the paths below.

**Not covered by either verify counter:** presence-beacon verifies inside
`saorsa-gossip-presence` (Bulk lane); application-layer verifies that run after
delivery (e.g., not exhaustive: identity announcements, agent/group cards, DM
envelopes, revocations, KV and group state commits, CRDT provenance, forward
attestations, delegation and owner-mandate certificates); and QUIC handshake
verifies in `ant-quic`. Queue
*age* is not measured — only depth.

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
