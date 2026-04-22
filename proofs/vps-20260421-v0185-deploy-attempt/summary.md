# VPS deploy attempt — 2026-04-21

- Source build deployed: local workspace `x0x v0.18.5`
- Command run: `bash tests/e2e_deploy.sh`
- Outcome: **partial success / blocked**

## Deployment results

Succeeded:
- NYC (`142.93.199.50`)
- SFO (`147.182.234.192`)
- Helsinki (`65.21.157.229`)
- Nuremberg (`116.203.101.172`)
- Tokyo (`45.77.176.184`)

Failed:
- Singapore (`149.28.156.231`) — SSH connection failed during deploy

## Post-deploy verification from `tests/e2e_deploy.sh`

- NYC: service active, `/health` OK, version `0.18.5`, `connected_peers = 6`
- SFO: service active, `/health` OK, version `0.18.5`, `connected_peers = 6`
- Helsinki: service active, `/health` OK, version `0.18.5`, **`connected_peers = 0`**
- Nuremberg: service active, `/health` OK, version `0.18.5`, `connected_peers = 6`
- Tokyo: service active, `/health` OK, version `0.18.5`, `connected_peers = 5`
- Singapore: service not active / unreachable via SSH during the deploy run

## Why this matters

This blocks a clean multi-host NAT / relay proof run: the intended 6-node public mesh was not healthy after deploy, so the VPS proof for:
- `is_relaying=true` on at least one coordinator
- `relay_sessions > 0`
- `hole_punch_success_rate > 0` for a behind-NAT client path

is **still open**.

## Related files

- `tests/.vps-tokens.env` — tokens collected for the reachable nodes during this deploy run
- `proofs/full-20260421-v0185-live-bootstrap-local2/` — local daemon run against the live bootstrap mesh after deploy (captured relay activity but did not yet produce the desired non-zero hole-punch metric)
