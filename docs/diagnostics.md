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
