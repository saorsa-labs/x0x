# Phase 3.1: Testnet Deployment

**Milestone**: 3 - VPS Testnet & Production Release
**Phase**: 3.1 - Testnet Deployment
**Estimated Tasks**: 10
**Goal**: Deploy x0x bootstrap/coordinator nodes to 6 global VPS locations

---

## Overview

Deploy production-ready x0x nodes to Saorsa Labs VPS infrastructure. These nodes act as coordinators with reflector/relay roles, providing bootstrap endpoints and rendezvous infrastructure for the x0x network.

**Port Allocation**: 12000 (UDP QUIC) + 12600 (HTTP health/metrics)

**Target VPS Nodes**:
- saorsa-2 (142.93.199.50, NYC) - US East
- saorsa-3 (147.182.234.192, SFO) - US West
- saorsa-6 (65.21.157.229, Helsinki) - EU North
- saorsa-7 (116.203.101.172, Nuremberg) - EU Central
- saorsa-8 (149.28.156.231, Singapore) - Asia SE
- saorsa-9 (45.77.176.184, Tokyo) - Asia East

---

## Task 1: Create Bootstrap Node Binary

**Goal**: Create x0x-bootstrap binary with coordinator/reflector capabilities

**Files**:
- `crates/x0x-bootstrap/Cargo.toml` (new)
- `crates/x0x-bootstrap/src/main.rs` (new)
- `crates/x0x-bootstrap/src/config.rs` (new)

**Requirements**:
1. Binary accepts `--config` flag for TOML config file
2. Config includes:
   - Bind address (0.0.0.0:12000)
   - Health endpoint (127.0.0.1:12600)
   - Coordinator role (true)
   - Reflector role (true)
   - Relay role (true)
   - Known peers (other 5 VPS nodes)
3. Initialize Agent with machine identity
4. Join x0x network as coordinator
5. Run HTTP health server on 12600 with `/health` endpoint
6. Structured logging (JSON) to stdout
7. Graceful shutdown on SIGTERM

**Tests**:
- Unit test: config parsing
- Integration test: binary starts and binds ports

**Validation**:
- `cargo check --all-features`
- `cargo clippy -- -D warnings`
- `cargo nextest run`

---

## Task 2: Create Configuration Files

**Goal**: Generate TOML config for each VPS node

**Files**:
- `.deployment/bootstrap-nyc.toml` (new)
- `.deployment/bootstrap-sfo.toml` (new)
- `.deployment/bootstrap-helsinki.toml` (new)
- `.deployment/bootstrap-nuremberg.toml` (new)
- `.deployment/bootstrap-singapore.toml` (new)
- `.deployment/bootstrap-tokyo.toml` (new)

**Requirements**:
1. Each config specifies its bind address (IP:12000)
2. Each config lists other 5 nodes as known peers
3. Health endpoint at 127.0.0.1:12600
4. Log level: info
5. Machine key path: `/var/lib/x0x/machine.key`
6. Data directory: `/var/lib/x0x/data`

**Tests**:
- Parse all 6 configs successfully
- Validate peer lists are complete

**Validation**:
- `cargo run --bin x0x-bootstrap -- --config .deployment/bootstrap-nyc.toml --check`

---

## Task 3: Create Systemd Service Unit

**Goal**: Create systemd service for x0x-bootstrap

**Files**:
- `.deployment/x0x-bootstrap.service` (new)
- `.deployment/install.sh` (new)

**Requirements**:
1. Service runs as `x0x` user
2. Binary at `/opt/x0x/x0x-bootstrap`
3. Config at `/etc/x0x/bootstrap.toml`
4. Working directory: `/var/lib/x0x`
5. Restart policy: always (with backoff)
6. Standard output/error to journal
7. Kill mode: process (graceful shutdown)
8. Timeout stop: 30s

**install.sh**:
- Create `x0x` user if doesn't exist
- Create directories: `/opt/x0x`, `/etc/x0x`, `/var/lib/x0x`
- Copy binary to `/opt/x0x/x0x-bootstrap`
- Copy config to `/etc/x0x/bootstrap.toml`
- Install systemd service
- Enable and start service

**Tests**:
- Manual: run install.sh on test VM
- Verify service starts and stays running

**Validation**:
- shellcheck install.sh
- Test on local systemd environment

---

## Task 4: Cross-Compile for Linux x64

**Goal**: Build x0x-bootstrap for Linux x64 (VPS target)

**Files**:
- `.github/workflows/build-bootstrap.yml` (new)
- `scripts/build-linux.sh` (new)

**Requirements**:
1. Use `cargo zigbuild --target x86_64-unknown-linux-gnu --release`
2. Binary output: `target/x86_64-unknown-linux-gnu/release/x0x-bootstrap`
3. Strip debug symbols
4. Verify binary is statically linked (check ldd)
5. GitHub workflow for automated builds on push to main

**Tests**:
- Verify binary runs on Linux (via Docker or VM)
- Check binary size (should be <30MB stripped)

**Validation**:
- `cargo zigbuild --target x86_64-unknown-linux-gnu --release -p x0x-bootstrap`
- `file target/x86_64-unknown-linux-gnu/release/x0x-bootstrap` (ELF 64-bit)

---

## Task 5: Deploy to saorsa-2 (NYC)

**Goal**: Deploy bootstrap node to NYC VPS

**Files**:
- `scripts/deploy-single.sh` (new)

**Requirements**:
1. SCP binary to saorsa-2:/opt/x0x/x0x-bootstrap
2. SCP config to saorsa-2:/etc/x0x/bootstrap.toml (bootstrap-nyc.toml)
3. SCP service to saorsa-2:/etc/systemd/system/x0x-bootstrap.service
4. SSH run install.sh
5. Verify service is running: `systemctl status x0x-bootstrap`
6. Verify health endpoint: `curl http://127.0.0.1:12600/health`
7. Check logs: `journalctl -u x0x-bootstrap -n 50 --no-pager`

**Tests**:
- Connect to health endpoint returns 200
- Logs show "Network initialized" and "Coordinator role enabled"

**Validation**:
- Manual SSH verification
- Health check returns `{"status":"healthy","peers":0}` (0 initially)

---

## Task 6: Deploy to saorsa-3 (SFO)

**Goal**: Deploy bootstrap node to SFO VPS

**Requirements**:
- Same as Task 5, but for saorsa-3 (147.182.234.192)
- Use bootstrap-sfo.toml config

**Validation**:
- Health check returns 200
- Logs show connection to saorsa-2 (NYC peer)

---

## Task 7: Deploy to saorsa-6 and saorsa-7 (EU)

**Goal**: Deploy bootstrap nodes to Helsinki and Nuremberg

**Requirements**:
- Deploy to saorsa-6 (65.21.157.229) with bootstrap-helsinki.toml
- Deploy to saorsa-7 (116.203.101.172) with bootstrap-nuremberg.toml

**Validation**:
- Both nodes healthy
- Logs show connections to NYC and SFO peers

---

## Task 8: Deploy to saorsa-8 and saorsa-9 (Asia)

**Goal**: Deploy bootstrap nodes to Singapore and Tokyo

**Requirements**:
- Deploy to saorsa-8 (149.28.156.231) with bootstrap-singapore.toml
- Deploy to saorsa-9 (45.77.176.184) with bootstrap-tokyo.toml

**Validation**:
- Both nodes healthy
- Logs show mesh connections to all peers

---

## Task 9: Verify Full Mesh Connectivity

**Goal**: Verify all 6 nodes form a connected mesh

**Files**:
- `scripts/check-mesh.sh` (new)

**Requirements**:
1. Query health endpoint on all 6 nodes
2. Verify each node reports 5 connected peers
3. Check membership state via metrics endpoint
4. Verify rendezvous shards are distributed across nodes

**Tests**:
- Run check-mesh.sh
- Output shows all nodes connected
- No error logs in journalctl

**Validation**:
- Each node's `/health` shows `{"status":"healthy","peers":5}`
- Logs show HyParView active view size = 5

---

## Task 10: Embed Bootstrap Addresses in SDK

**Goal**: Hardcode VPS addresses as default bootstrap peers

**Files**:
- `crates/x0x/src/config.rs`
- `crates/x0x-node/src/config.rs`
- `x0x-javascript/src/config.ts`
- `x0x-python/src/config.rs`

**Requirements**:
1. Add `DEFAULT_BOOTSTRAP_PEERS` constant with all 6 addresses
2. Format: `[IP]:[PORT]` (e.g., "142.93.199.50:12000")
3. Agent::builder() uses these by default unless overridden
4. Document in rustdoc and SDK docs

**Tests**:
- Unit test: Agent::builder().build() connects to default peers
- Integration test: Create agent without explicit peers, verify connection

**Validation**:
- `cargo nextest run`
- All 3 SDK tests pass
- Documentation shows bootstrap addresses

---

## Completion Criteria

- [ ] All 6 VPS nodes running x0x-bootstrap
- [ ] Full mesh connectivity (each node has 5 peers)
- [ ] Health endpoints responding
- [ ] No errors in journalctl logs
- [ ] Bootstrap addresses embedded in SDK
- [ ] Zero compilation warnings
- [ ] All tests passing

---

## Rollback Plan

If deployment fails:
1. Stop services: `ssh root@<IP> 'systemctl stop x0x-bootstrap'`
2. Remove binaries: `ssh root@<IP> 'rm -rf /opt/x0x/*'`
3. Clean logs: `ssh root@<IP> 'journalctl --vacuum-time=1d'`

---

## Notes

- NEVER compile on VPS - always build locally with cargo zigbuild
- Clean old binaries before deploying new versions
- Monitor logs during initial deployment for connection issues
- NAT traversal should work automatically via ant-quic hole punching
