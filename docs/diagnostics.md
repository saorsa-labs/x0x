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
