# Live bootstrap mesh snapshot summary

This run used:

- `USE_HARD_CODED_BOOTSTRAP=1`
- `SETTLE_SECS=30`
- `tests/e2e_full_measurement.sh --nodes 2 --messages 20`

The run later aborted during the local node-to-node DM/file phase, but it **did** capture the first non-zero live-mesh relay evidence in the connectivity snapshots before the abort.

## Key evidence from `logs/node-1/connectivity-*.json`

### `connectivity-pre.json`
- `nat_type = "FullCone"`
- `can_receive_direct = true`
- `relay.is_relaying = true`
- `relay.sessions = 1`
- `relay.bytes_forwarded = 4800`
- `connections.connected_peers = 1`
- `connections.direct = 2`
- `connections.hole_punch_success_rate = 0.0`

### `connectivity-mid.json`
- `relay.is_relaying = true`
- `relay.sessions = 1`
- `relay.bytes_forwarded = 9600`
- `connections.hole_punch_success_rate = 0.0`

## Interpretation

This is **partial progress** on the VPS / live-bootstrap NAT-relay item:

- We captured non-zero live-mesh relay state (`is_relaying=true`, `relay_sessions=1`, `bytes_forwarded>0`).
- We did **not** yet capture a non-zero `hole_punch_success_rate`.
- The run is not a full end-to-end NAT proof because the later local DM/file phase failed and the deployed VPS mesh itself was not fully healthy (`proofs/vps-20260421-v0185-deploy-attempt/summary.md`).
