# x0x Comprehensive Test Suite Guide

## Overview

This document describes the comprehensive test suites created for the x0x production network across 6 global VPS nodes.

## Test Suite Structure

### 1. Network Features Test Suite (READY NOW)

**Location:** `/tmp/test-network-simple.sh`

**Status:** ✅ Ready to run - tests currently implemented features

**What it tests:**
- Service Health (systemd x0x-bootstrap.service status)
- Health API Endpoints (GET /health on port 12600)
- QUIC Port Binding (UDP port 12000)
- Peer Discovery & Connections (connection events in logs)
- Cryptographic Identity (MachineID & AgentID extraction and uniqueness)
- NAT Traversal (address discovery events)
- Resource Usage (memory, CPU)
- Error Detection (scanning for ERROR-level logs)
- Log Continuity (checking for unexpected restarts)
- Cross-Node Connectivity Matrix

**Dependencies:** bash, ssh, jq, curl (all pre-installed on VPS nodes)

**Usage:**
```bash
chmod +x /tmp/test-network-simple.sh
./tmp/test-network-simple.sh
```

**Expected output:**
```
════════════════════════════════════════════════════════════════
  x0x Network Features Test Suite
  Testing 6 nodes
════════════════════════════════════════════════════════════════

Test 1: Service Health
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ PASS: NYC (142.93.199.50): Service running
✓ PASS: SFO (147.182.234.192): Service running
... (all nodes)

Test 2: Health Endpoints
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ PASS: NYC (142.93.199.50): Health OK (peers: 0)
... (all nodes)

...

════════════════════════════════════════════════════════════════
Test Summary
════════════════════════════════════════════════════════════════
Passed: 42
Failed: 0
Success Rate: 100%
✓ ALL TESTS PASSED
```

---

### 2. Gossip Features Test Suite (FUTURE - When Implemented)

**Location:** `/tmp/test-gossip-features.py`

**Status:** ⚠️ Waiting for gossip implementation - will skip most tests

**What it will test:**
- Pub/Sub Messaging
  - Subscribe to topics
  - Publish messages
  - Epidemic broadcast verification
  - Message delivery across all subscribers

- CRDT Task List Synchronization
  - Create task lists
  - Join task lists from multiple nodes
  - Add tasks concurrently from different nodes
  - Verify CRDT convergence
  - Test conflict resolution (LWW-Register tie-breaking)

- Concurrent Operations
  - Race conditions (multiple nodes claiming same task)
  - Concurrent metadata updates
  - Partition tolerance
  - Anti-entropy sync

- Presence & FOAF Discovery
  - Presence announcements
  - Peer discovery
  - Friend-of-a-Friend (2-hop) discovery
  - Network topology mapping

- MLS Group Encryption
  - Create encrypted groups
  - Invite members
  - Send encrypted messages
  - Verify end-to-end encryption

**Dependencies:** Python 3.8+, aiohttp

**Installation:**
```bash
# On VPS nodes:
apt-get install python3 python3-aiohttp

# On macOS:
pip3 install aiohttp
```

**Usage:**
```bash
python3 /tmp/test-gossip-features.py
```

**Current expected output:**
```
════════════════════════════════════════════════════════════════
x0x Gossip Feature Test Suite (FUTURE)
════════════════════════════════════════════════════════════════

⚠️  NOTE: Most tests will be skipped until gossip features are implemented

...

Test 1: Pub/Sub Messaging
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⊘ SKIP: NYC: Subscribe - API not available
...

════════════════════════════════════════════════════════════════
Test Summary
════════════════════════════════════════════════════════════════
Passed:  0
Failed:  0
Skipped: 25 (features not implemented)
════════════════════════════════════════════════════════════════

⚠️  25 tests skipped - gossip features not yet implemented
   Run this script again after saorsa-gossip integration is complete
```

---

### 3. Python Async Test Suite (Advanced)

**Location:** `/tmp/test-network-features.py`

**Status:** ✅ Ready but requires aiohttp

**Features:**
- Parallel test execution (all nodes tested simultaneously)
- Async/await for performance
- JSON output for CI/CD integration
- Detailed connectivity matrix
- Identity extraction and uniqueness validation

**Dependencies:**
```bash
pip3 install aiohttp  # or: apt install python3-aiohttp
```

**Usage:**
```bash
python3 /tmp/test-network-features.py
```

---

## VPS Node Inventory

All test scripts target these 6 global nodes:

| Node | IP | Location | Provider |
|------|-------------|----------|----------|
| NYC | 142.93.199.50 | New York, US | DigitalOcean |
| SFO | 147.182.234.192 | San Francisco, US | DigitalOcean |
| Helsinki | 65.21.157.229 | Helsinki, FI | Hetzner |
| Nuremberg | 116.203.101.172 | Nuremberg, DE | Hetzner |
| Singapore | 149.28.156.231 | Singapore, SG | Vultr |
| Tokyo | 45.77.176.184 | Tokyo, JP | Vultr |

---

## Test Execution Workflow

### Quick Test (Bash - No Dependencies)
```bash
./tmp/test-network-simple.sh
```

### Full Test with Python
```bash
# Install dependencies first
pip3 install aiohttp

# Run tests
python3 /tmp/test-network-features.py
```

### Deploy to All VPS Nodes
```bash
./tmp/deploy-and-run-tests.sh
```

This will:
1. Install Python dependencies on all nodes
2. Deploy test scripts to `/opt/x0x/tests/`
3. Run network features test
4. Show summary

---

## Currently Implemented Features (Tested)

✅ **Network Layer:**
- QUIC transport (ant-quic 0.21.5)
- Post-quantum crypto (ML-DSA-65, ML-KEM-768)
- NAT traversal (draft-seemann-quic-nat-traversal-02)
- MASQUE relay (RFC 9484)
- Address discovery (QUIC extension frames)

✅ **Identity:**
- MachineID (machine-bound, for QUIC auth)
- AgentID (portable, for agent persistence)
- Cryptographic uniqueness

✅ **Bootstrap:**
- Multi-peer connection
- Exponential backoff retry
- Peer caching

✅ **Health API:**
- GET /health endpoint
- Status monitoring

---

## Not Yet Implemented (Future Tests)

⚠️ **Gossip Layer:**
- Pub/sub messaging (subscribe/publish are placeholders)
- CRDT task list synchronization (create_task_list/join_task_list not implemented)
- Presence announcements
- FOAF discovery
- Anti-entropy sync

⚠️ **MLS Encryption:**
- Group creation (module exists, needs integration)
- Member invites
- Encrypted messaging

⚠️ **Advanced Features:**
- File sharing
- Agent discovery by capability
- Rendezvous coordination

---

## Integration with CI/CD

### GitHub Actions Integration

Add to `.github/workflows/network-test.yml`:

```yaml
name: Network Integration Test

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Network Test
        env:
          SSH_PRIVATE_KEY: ${{ secrets.VPS_SSH_KEY }}
        run: |
          mkdir -p ~/.ssh
          echo "$SSH_PRIVATE_KEY" > ~/.ssh/id_rsa
          chmod 600 ~/.ssh/id_rsa
          ./tests/test-network-simple.sh

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: /tmp/test-results.txt
```

---

## Test Output Files

After running tests, the following files are generated:

| File | Content |
|------|---------|
| `/tmp/test-results.txt` | Full test execution log |
| `/tmp/x0x-node-identities.json` | Extracted node identities (MachineID, AgentID) |
| `NETWORK_TEST_REPORT.txt` | Initial deployment test report |

---

## Troubleshooting

### Test Failures

**Service not running:**
```bash
ssh root@<IP> 'systemctl status x0x-bootstrap'
ssh root@<IP> 'journalctl -u x0x-bootstrap -n 50'
```

**Health endpoint unreachable:**
```bash
ssh root@<IP> 'curl http://127.0.0.1:12600/health'
ssh root@<IP> 'ss -tlpn | grep 12600'
```

**QUIC port not bound:**
```bash
ssh root@<IP> 'ss -ulpn | grep 12000'
ssh root@<IP> 'journalctl -u x0x-bootstrap | grep "Bind address"'
```

**No peer connections:**
```bash
ssh root@<IP> 'journalctl -u x0x-bootstrap --since "10 minutes ago" | grep -i connect'
```

### Manual Test Execution

Run individual tests on a specific node:

```bash
# Service health
ssh root@142.93.199.50 'systemctl is-active x0x-bootstrap'

# Health API
ssh root@142.93.199.50 'curl -s http://127.0.0.1:12600/health | jq .'

# Connection logs
ssh root@142.93.199.50 'journalctl -u x0x-bootstrap --since "5 min ago" | grep -i connected'

# Identity
ssh root@142.93.199.50 'journalctl -u x0x-bootstrap | grep -E "Machine ID:|Agent ID:"'
```

---

## Future Enhancements

### Planned Test Additions

1. **Performance Benchmarks:**
   - Message throughput (messages/sec)
   - Latency measurements (cross-continent)
   - CRDT convergence time
   - Memory usage under load

2. **Stress Testing:**
   - Rapid task creation (1000s of tasks)
   - Concurrent operations (100s of agents)
   - Network partition simulation
   - Byzantine fault injection

3. **Security Testing:**
   - ML-DSA signature verification
   - ML-KEM encryption validation
   - Replay attack prevention
   - Sybil attack resistance

4. **Chaos Engineering:**
   - Random node failures
   - Network latency injection
   - Packet loss simulation
   - Clock skew testing

---

## Contributing

To add new tests:

1. Add test function to appropriate suite
2. Follow naming convention: `test_<feature_name>()`
3. Use consistent pass/fail/skip reporting
4. Document expected behavior
5. Test locally before deploying to VPS

---

## Support

For issues or questions:
- GitHub: https://github.com/saorsa-labs/x0x
- Email: david@saorsalabs.com
- Docs: https://x0x.dev (coming soon)

---

**Last Updated:** 2026-02-07
**x0x Version:** 0.1.0
**Test Suite Version:** 1.0.0
