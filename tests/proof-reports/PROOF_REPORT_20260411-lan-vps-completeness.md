# LAN + VPS completeness rerun (2026-04-11)

## Scope
Applied the stronger local-full proof style to the LAN and VPS suites where feasible:
- more receive-side / lifecycle checks
- named-group/space join+leave lifecycle proof
- stronger LAN file-transfer completion proof
- stricter VPS direct-message receive-side accounting
- archived raw logs from these reruns in this directory

## Evidence files
- LAN: `tests/proof-reports/suite_lan_20260411-advanced-rerun.log`
- VPS: `tests/proof-reports/suite_vps_20260411-advanced-rerun.log`

## LAN result
- Command: `STUDIO1_HOST=studio1.local STUDIO2_HOST=studio2.local STUDIO1_SSH_TARGET=studio1@studio1.local STUDIO2_SSH_TARGET=studio2@studio2.local bash tests/e2e_lan.sh`
- Result: **117 passed / 6 failed / 0 skipped**

### Newly strengthened LAN proofs that passed
- named group / space join via invite
- joiner group info lookup
- joiner member self-presence in space
- joiner display-name persistence in space
- leave-space lifecycle and disappearance from group list
- file transfer incoming visibility
- file transfer accept
- sender complete
- receiver complete
- receiver sha256 match
- receiver body match

### Remaining LAN failures
All remaining LAN failures are still the zero-bootstrap discovery block:
- studio1 did not discover studio2 within 90s
- studio2 did not discover studio1 within 90s
- studio1 get discovered studio2
- studio1 reachability of studio2
- studio2-b did not discover studio1 within 60s
- swarm: studio2-b missing studio1

Interpretation: direct/imported-card connectivity and cross-node functional flows are strong; pure mDNS/seedless LAN discovery remains unproven/failing on this environment.

## VPS result
- Command: `bash tests/e2e_vps.sh`
- Result: **106 passed / 32 failed / 1 skipped**

### Newly strengthened VPS proofs that passed
- real browser GUI send was visible locally on tunneled NYC GUI
- named group / space join on Tokyo
- Tokyo group info
- Tokyo member self-presence in space
- Tokyo display-name persistence in space
- Tokyo leave-space lifecycle and disappearance from group list
- Singapore second join path
- Singapore→Tokyo file offer initiation

### What still fails on VPS
The current VPS network still does **not** honestly prove all-node/all-pairs delivery:
- intermittent node/API instability on SFO/Nuremberg/NYC endpoints in this run
- all-pairs connect matrix still had failed directed pairs
- all-pairs direct sends had failures
- recipient-side direct-message proof still failed for many/most directed pairs
- CLI send lacked recipient-side proof
- GUI recipient-side proof failed
- file-transfer receive/accept/complete proof failed on VPS
- some presence/FOAF/constitution/status/upgrade/SSE probe checks were unstable in this run

Interpretation: VPS remains useful as a partial live-network audit, but it still does **not** justify a claim of 100% all-pairs connectability or universal send/receive proof across all bootstrap nodes.

## Bottom line
- **LAN**: strengthened substantially; only pure mDNS/seedless discovery remains failing.
- **VPS**: strengthened in honesty and lifecycle depth, including spaces coverage, but still fails as a true 100% all-pairs proof.
