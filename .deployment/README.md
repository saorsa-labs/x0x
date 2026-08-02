# x0x Bootstrap Network Deployment

This directory contains configuration files and deployment scripts for running x0x bootstrap nodes on the Saorsa Labs VPS infrastructure.

## Bootstrap Network Topology

6 nodes in a fully-connected mesh:

| Node | Location | Provider | IP Address | Config File |
|------|----------|----------|------------|-------------|
| saorsa-2 | NYC, US | DigitalOcean | 142.93.199.50 | bootstrap-nyc.toml |
| saorsa-3 | SFO, US | DigitalOcean | 147.182.234.192 | bootstrap-sfo.toml |
| saorsa-6 | Helsinki, FI | Hetzner | 65.21.157.229 | bootstrap-helsinki.toml |
| saorsa-7 | Nuremberg, DE | Hetzner | 116.203.101.172 | bootstrap-nuremberg.toml |
| saorsa-8 | Singapore, SG | DigitalOcean | 152.42.210.67 | bootstrap-singapore.toml |
| saorsa-9 | Sydney, AU | DigitalOcean | 170.64.176.102 | bootstrap-sydney.toml |

## Port Allocation

- **5483/UDP**: QUIC transport (x0x network)
- **12600/TCP**: Health and metrics endpoint (localhost only)

## Prerequisites

1. **Build the binary** (must be done locally, never on VPS):
```bash
# Install cross-compilation tools (one-time)
cargo install cargo-zigbuild
brew install zig  # macOS

# Build for Linux
cd ../..  # Go to project root
cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd
```

2. **SSH access** to VPS nodes:
```bash
ssh root@saorsa-2.saorsalabs.com  # Or use IP directly
```

## Deployment Scripts

### install.sh
Authoritative installer for the production `x0xd` instance (ADR 0026). Installs
the tracked `systemd/x0xd.service` unit and the production config generated from
`config/bootstrap-config.toml` to the same paths the unit reads, so a fresh host
is brought up identically to the live fleet.

Run **on the target host** as root:

```bash
# Unit + config from the tracked sources
./install.sh

# Also install a freshly cross-compiled binary
./install.sh --binary ../../target/x86_64-unknown-linux-gnu/release/x0xd
```

**What it does:**
1. Installs the binary (with `--binary`) to `/opt/x0x/x0xd`
2. Installs the production config to `/etc/x0x/config.toml`
3. Installs the tracked `systemd/x0xd.service` to `/etc/systemd/system/`
4. Reloads systemd and enables `x0xd`

The installer does **not** start the service; starting is a managed transition
(`systemctl start x0xd`). The legacy `deploy.sh` (which uploaded a config path
its own installed unit never read) and the contradictory top-level `x0xd.service`
have been retired, leaving one tracked deployment authority.

### health-check.sh
Check health status of nodes.

```bash
# Check all nodes
./health-check.sh

# Check single node
./health-check.sh sydney
```

**Output example:**
```
NODE            IP                STATUS
----            --                ------
nyc             142.93.199.50     OK - healthy
sfo             147.182.234.192   OK - healthy
helsinki        65.21.157.229     OK - healthy
```

### scripts/check-mesh.sh
Verify full mesh connectivity across all bootstrap nodes.

```bash
# Check mesh connectivity
./scripts/check-mesh.sh
```

**What it does:**
1. Queries health endpoint on all 6 nodes
2. Verifies each node reports correct peer count (5 peers each)
3. Checks service status if unhealthy
4. Shows recent logs for troubleshooting
5. Returns exit code 0 if all healthy, 1 if any issues

**Output example:**
```
=========================================
x0x Bootstrap Mesh Health Check
=========================================

Checking saorsa-2 (142.93.199.50)... HEALTHY (peers: 5)
Checking saorsa-3 (147.182.234.192)... HEALTHY (peers: 5)
Checking saorsa-6 (65.21.157.229)... HEALTHY (peers: 5)
Checking saorsa-7 (116.203.101.172)... HEALTHY (peers: 5)
Checking saorsa-8 (152.42.210.67)... HEALTHY (peers: 5)
Checking saorsa-9 (170.64.176.102)... HEALTHY (peers: 5)

=========================================
Summary
=========================================
Total nodes: 6
Healthy: 6
Unhealthy: 0

✓ All bootstrap nodes are healthy!
```

### logs.sh
View logs from a node.

```bash
# View last 50 lines (default)
./logs.sh helsinki

# View last 200 lines
./logs.sh singapore 200
```

### cleanup.sh
Remove x0x deployment from nodes.

```bash
# Clean single node
./cleanup.sh nyc

# Clean all nodes (requires confirmation)
./cleanup.sh all
```

**WARNING:** This removes ALL data including machine keys. Nodes will get new identities if redeployed.

## Configuration Files

Each node has a TOML configuration file specifying:

- **Bind address**: Public IP + port 5483
- **Known peers**: The other 5 bootstrap nodes
- **Machine key**: `/var/lib/x0x/machine.key` (auto-generated on first run)
- **Data directory**: `/var/lib/x0x/data`
- **Health endpoint**: `127.0.0.1:12600`
- **Log level**: `info`

## Service Management

### Manual Service Control

```bash
# SSH to a node
ssh root@142.93.199.50

# Check status
systemctl status x0xd

# View logs
journalctl -u x0xd -f

# Restart
systemctl restart x0xd

# Stop
systemctl stop x0xd

# Start
systemctl start x0xd
```

### Health Endpoint

```bash
# Check health (from the node itself)
curl http://127.0.0.1:12600/health

# View metrics
curl http://127.0.0.1:12600/metrics
```

## Directory Structure on VPS

```
/opt/x0x/
  x0xd              # Binary (uploaded by deploy script)

/etc/x0x/
  config.toml                # Configuration (uploaded by deploy script)
                             # Legacy bootstrap.toml from pre-2026-04 era
                             # is removed by .deployment/harden-bootstrap-nodes.sh

/var/lib/x0x/
  machine.key                # Machine identity (auto-generated)
  data/                      # Runtime data

/etc/systemd/system/
  x0xd.service      # Systemd service (uploaded by deploy script)
```

## Troubleshooting

### Service won't start
```bash
# Check logs for errors
ssh root@<IP> 'journalctl -u x0xd -n 100 --no-pager'

# Check if binary is executable
ssh root@<IP> 'ls -la /opt/x0x/x0xd'

# Check if config is valid
ssh root@<IP> 'cat /etc/x0x/config.toml'
```

### Network connectivity issues
```bash
# Test QUIC port is open
ssh root@<IP> 'ss -tulpn | grep 5483'

# Check firewall (should allow UDP 5483)
ssh root@<IP> 'ufw status'
```

### Node can't reach peers
```bash
# Verify bootstrap_peers in config
ssh root@<IP> 'grep bootstrap_peers /etc/x0x/config.toml'

# Test UDP connectivity to peer
ssh root@<IP> 'nc -vzu <peer_ip> 5483'
```

### Clean slate restart
```bash
# Complete cleanup, then bring the host up with the authoritative installer
./cleanup.sh <node_name>
# then on the host: .deployment/install.sh --binary <built-x0xd>
```

## Security Notes

1. **Never compile on VPS** - always build locally with `cargo zigbuild`
2. **Health endpoint is localhost-only** - not exposed to public internet
3. **Machine keys are generated once** - backup if needed before cleanup
4. **Firewall rules** - ensure UDP 5483 is allowed
5. **Service runs as root** - required for port binding (consider dedicated user later)

## Monitoring

### Quick health check of all nodes
```bash
./health-check.sh
```

### Monitor logs in real-time
```bash
# On a specific node
ssh root@<IP> 'journalctl -u x0xd -f'
```

### Check resource usage
```bash
ssh root@<IP> 'systemctl status x0xd'
```

## Next Steps

After successful deployment:

1. Verify all nodes are healthy: `./health-check.sh`
2. Monitor network formation in logs
3. Test agent connections to bootstrap network
4. Monitor metrics endpoints for network statistics

## Hardening

Run `harden-bootstrap-nodes.sh` periodically (or after any deploy) to
keep the fleet "rock solid":

```bash
DRY_RUN=1 bash .deployment/harden-bootstrap-nodes.sh   # preview
DRY_RUN=0 bash .deployment/harden-bootstrap-nodes.sh   # apply
```

What it does (idempotent):
1. `systemctl enable x0xd` on every node — auto-start on boot.
2. Removes leaked `/opt/x0x/.x0x-upgrade-*` working directories.
   Auto-upgrade has a known leak (saorsa-3 had 216 stale dirs as of
   2026-04-28). Tracked separately — fix is in `src/upgrade/apply.rs`.
3. Removes legacy `/etc/x0x/bootstrap.toml{,.bak}` and
   `x0xd-test.toml` from the pre-2026-04 era.
4. Removes stale binaries (`/opt/x0x/x0x`, `x0xd-dhat-old`,
   `x0xd.backup`, `x0xd.bak`).

## Reproducible bring-up

`systemd/x0xd.service` and `config/bootstrap-config.toml` mirror
what's installed on the live fleet so a fresh node can be brought up
identically.

To promote a new node to canonical bootstrap (added to
`x0x::network::DEFAULT_BOOTSTRAP_PEERS`):

1. Open a PR adding its IPv4 + IPv6 to `src/network.rs`.
2. Update the `bootstrap_peers` list in `config/bootstrap-config.toml`.
3. Update `~/.claude/docs/infrastructure.md`.
4. Re-tag x0x and roll the release out — the new IP becomes a
   hardcoded entry point only after a binary upgrade across the network.

## Support

- Project: https://github.com/saorsa-labs/x0x
- Contact: david@saorsalabs.com
