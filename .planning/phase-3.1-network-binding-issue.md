# Phase 3.1: Network Binding Issue - Investigation Needed

**Date**: 2026-02-06
**Status**: BLOCKED (Technical Issue)
**Phase Progress**: 10/10 tasks complete, but mesh not forming

---

## Executive Summary

Phase 3.1 deployment infrastructure is complete and all 6 bootstrap nodes are deployed and running. However, the nodes are **not forming mesh connections** because the QUIC transport is not binding to port 12000/UDP.

**Critical Finding**: Bootstrap nodes only listen on health port (12600/TCP), not on QUIC transport port (12000/UDP).

---

## Completed Work

### 1. CI/CD Pipeline Fixed ✅

**Iterations**:
1. First failure: Missing sibling repositories (ant-quic, saorsa-gossip)
2. Second failure: OpenSSL development headers missing
3. Third failure: cargo-zigbuild OpenSSL resolution issues
4. Fourth failure: Artifact path (actions/upload-artifact doesn't respect working-directory)
5. **SUCCESS**: Native cargo build with correct paths

**Final Solution**:
- Install OpenSSL dev packages: `pkg-config libssl-dev`
- Use native `cargo build` instead of `cargo zigbuild`
- Artifact path: `x0x/target/release/x0x-bootstrap`

**Binary**: 2.5MB (stripped), ELF 64-bit LSB pie executable

**Workflow**: `.github/workflows/build-bootstrap.yml`
**Artifacts**: Retained for 30 days on GitHub

### 2. Configuration Files Fixed ✅

**Issue**: Initial configs used nested TOML sections, but BootstrapConfig expects flat structure.

**Fixed configs** (all 6 nodes):
- `.deployment/bootstrap-nyc.toml` (142.93.199.50)
- `.deployment/bootstrap-sfo.toml` (147.182.234.192)
- `.deployment/bootstrap-helsinki.toml` (65.21.157.229)
- `.deployment/bootstrap-nuremberg.toml` (116.203.101.172)
- `.deployment/bootstrap-singapore.toml` (149.28.156.231)
- `.deployment/bootstrap-tokyo.toml` (45.77.176.184)

**Format**:
```toml
bind_address = "147.182.234.192:12000"
health_address = "127.0.0.1:12600"
machine_key_path = "/var/lib/x0x/machine.key"
data_dir = "/var/lib/x0x/data"
coordinator = true
reflector = true
relay = true
known_peers = ["...", "..."]
log_level = "info"
```

### 3. VPS Deployment Complete ✅

**All 6 nodes deployed**:

| Node | Location | IP Address | Status |
|------|----------|------------|--------|
| saorsa-2 | NYC, US | 142.93.199.50 | ✅ Active |
| saorsa-3 | SFO, US | 147.182.234.192 | ✅ Active |
| saorsa-6 | Helsinki, FI | 65.21.157.229 | ✅ Active |
| saorsa-7 | Nuremberg, DE | 116.203.101.172 | ✅ Active |
| saorsa-8 | Singapore, SG | 149.28.156.231 | ✅ Active |
| saorsa-9 | Tokyo, JP | 45.77.176.184 | ✅ Active |

**Deployment artifacts**:
- Binary: `/opt/x0x/x0x-bootstrap` (2.5MB)
- Config: `/etc/x0x/bootstrap.toml`
- Systemd: `/etc/systemd/system/x0x-bootstrap.service`
- Data: `/var/lib/x0x/` (machine.key, peers.cache)

**All services**: `systemctl status x0x-bootstrap` → **active (running)**

---

## Critical Issue: QUIC Transport Not Binding

### Symptoms

**Health Check**:
```bash
curl http://127.0.0.1:12600/health
→ {"status":"healthy","peers":0}  # All nodes show 0 peers
```

**Network Ports** (SFO example):
```bash
lsof -p $(pgrep x0x-bootstrap) -a -i
→ COMMAND    PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
→ x0x-boots  1559370 root    9u  IPv4 18686696      0t0  TCP localhost:12600 (LISTEN)
```

**Missing**: No UDP listener on port 12000 (QUIC transport)

**Expected**: Should see:
```
UDP *:12000 (QUIC)
TCP 127.0.0.1:12600 (Health)
```

### Logs Analysis

**SFO logs** (`journalctl -u x0x-bootstrap`):
```json
{"timestamp":"2026-02-06T14:31:31.426635Z","level":"INFO","message":"Starting x0x bootstrap node v0.1.0"}
{"timestamp":"2026-02-06T14:31:31.627499Z","level":"INFO","message":"Bind address: 147.182.234.192:12000"}
{"timestamp":"2026-02-06T14:31:31.702519Z","level":"INFO","message":"Health endpoint: 127.0.0.1:12600"}
{"timestamp":"2026-02-06T14:31:32.892715Z","level":"INFO","message":"Agent initialized"}
{"timestamp":"2026-02-06T14:31:33.233427Z","level":"INFO","message":"Network joined successfully"}
{"timestamp":"2026-02-06T14:31:33.390736Z","level":"INFO","message":"Health server listening on 127.0.0.1:12600"}
```

**Observations**:
- Config loaded correctly (`Bind address: 147.182.234.192:12000`)
- Agent initialized
- **"Network joined successfully"** logged
- Health server started
- **No errors**
- **But no QUIC bind logs** (e.g., "QUIC listening on 0.0.0.0:12000")

### Code Review

**src/bin/x0x-bootstrap.rs:138-166**:
```rust
let network_config = NetworkConfig {
    bind_addr: Some(config.bind_address),
    bootstrap_nodes: config.known_peers.clone(),
    max_connections: 100,
    connection_timeout: std::time::Duration::from_secs(30),
    stats_interval: std::time::Duration::from_secs(60),
    peer_cache_path: Some(config.data_dir.join("peers.cache")),
};

let agent = Agent::builder()
    .with_machine_key(&config.machine_key_path)
    .with_network_config(network_config)
    .build()
    .await?;

agent.join_network().await?;
```

**Analysis**:
- NetworkConfig created with bind_addr
- Agent built with network config
- `join_network()` called and returns Ok
- **But QUIC transport never binds to port 12000**

**Hypothesis**: The issue is in one of:
1. `Agent::builder()` - not passing network config to Network component
2. `Agent::build()` - not initializing Network transport
3. `Agent::join_network()` - not starting QUIC listener
4. `Network` implementation - not binding QUIC transport

---

## Investigation Tasks

### 1. Check Network Component Initialization

**File**: `src/network.rs` or `src/agent.rs`

**Questions**:
- Does `Agent::build()` create a Network instance?
- Does Network::new() start the QUIC transport?
- Is `join_network()` supposed to bind the transport or just connect to peers?

### 2. Check QUIC Transport Binding

**Dependencies**: Uses `ant-quic` crate

**Questions**:
- Does ant-quic QuicTransport::bind() get called?
- What bind address is passed to ant-quic?
- Are there any silent failures in transport initialization?

### 3. Add Debug Logging

**Suggestion**: Add trace logs in:
- `Agent::build()` → "Network transport initialized on {bind_addr}"
- `Network::new()` → "QUIC binding to {addr}"
- `QuicTransport::bind()` → "QUIC listener started on {addr}"

### 4. Check if Issue is macOS Binary on Linux

**Note**: Binary was built on Linux (GitHub Actions ubuntu-latest), so this should not be the issue. But worth verifying binary is dynamically linked correctly:

```bash
ssh root@147.182.234.192 'ldd /opt/x0x/x0x-bootstrap'
```

---

## Workarounds Attempted

1. **Firewall**: Checked UFW - not active, not blocking
2. **Bind address**: Tried public IP (147.182.234.192) - IP is assigned to eth0, should work
3. **Config format**: Fixed from nested to flat TOML structure
4. **Wait time**: Waited 5+ minutes for mesh to form - no connections
5. **Manual restart**: `systemctl restart x0x-bootstrap` on all nodes - no change

---

## Next Steps

### Option A: Local Debugging

**Setup**:
```bash
# Build locally
cargo build --release --bin x0x-bootstrap

# Run with trace logging
RUST_LOG=trace ./target/release/x0x-bootstrap --config test-config.toml

# Check if QUIC binds
sudo lsof -i :12000
```

**Expected**: Should see QUIC binding attempt or error

### Option B: Add Instrumentation

**Modify** `src/bin/x0x-bootstrap.rs`:
```rust
// After join_network()
tracing::info!("Network stats: {:#?}", agent.network().unwrap().stats());
tracing::info!("Listening addresses: {:#?}", agent.network().unwrap().local_addrs());
```

Rebuild, redeploy, check logs.

### Option C: Check ant-quic Integration

**Verify** that `Agent::join_network()` actually calls `QuicTransport::start()` or equivalent.

**Read**: `src/network.rs`, `src/agent.rs`, look for where QUIC transport is initialized.

---

## Files Modified This Session

### CI/CD
- `.github/workflows/build-bootstrap.yml` (fixed OpenSSL, native build, artifact path)

### Configuration
- `.deployment/bootstrap-*.toml` (all 6 nodes, corrected to flat format)
- `.deployment/deploy.sh` (fixed binary path resolution)

### State Tracking
- `.planning/STATE.json` (updated with Phase 3.1 progress and blocker)

### New Documentation
- `.planning/phase-3.1-network-binding-issue.md` (this file)

### Commits
```
a33bdbc fix(ci): correct artifact path for upload
5773cce fix(ci): use native cargo build instead of zigbuild
fb2f812 fix(ci): install OpenSSL dev headers for build
0e68fe9 fix(ci): checkout sibling dependencies for build
173b038 feat(phase-3.1): complete VPS deployment with QUIC binding issue
```

---

## Quality Status

- ✅ **265/265 tests passing**
- ✅ **Zero compilation errors**
- ✅ **Zero compilation warnings**
- ✅ **Zero clippy violations**
- ✅ **All 6 VPS nodes deployed**
- ⚠️  **Mesh not forming (0 peers on all nodes)**

---

## Conclusion

**Phase 3.1 is functionally complete** in terms of deployment infrastructure, but the bootstrap network is **not operational** due to the QUIC binding issue.

**Root cause**: The Agent/Network component is not starting the QUIC transport listener, despite logging "Network joined successfully".

**Recommendation**: Debug locally with trace logging, or add instrumentation to confirm where QUIC binding should happen and why it's not occurring.

**ETA to resolve**: 1-2 hours (depends on complexity of issue)

**Blocking**: Phase 3.2 (Integration Testing) cannot proceed until nodes form mesh.
