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
| saorsa-8 | Singapore, SG | Vultr | 149.28.156.231 | bootstrap-singapore.toml |
| saorsa-9 | Tokyo, JP | Vultr | 45.77.176.184 | bootstrap-tokyo.toml |

## Port Allocation

- **12000/UDP**: QUIC transport (x0x network)
- **12600/TCP**: Health and metrics endpoint (localhost only)

## Prerequisites

1. **Build the binary** (must be done locally, never on VPS):
```bash
# Install cross-compilation tools (one-time)
cargo install cargo-zigbuild
brew install zig  # macOS

# Build for Linux
cd ../..  # Go to project root
cargo zigbuild --release --target x86_64-unknown-linux-gnu -p x0x-bootstrap
```

2. **SSH access** to VPS nodes:
```bash
ssh root@saorsa-2.saorsalabs.com  # Or use IP directly
```

## Deployment Scripts

### deploy.sh
Deploy binary and configuration to nodes.

```bash
# Deploy to single node
./deploy.sh nyc

# Deploy to all nodes
./deploy.sh all
```

**What it does:**
1. Uploads binary to `/opt/x0x/x0x-bootstrap`
2. Uploads config to `/etc/x0x/bootstrap.toml`
3. Installs systemd service
4. Starts and enables service
5. Verifies health

### health-check.sh
Check health status of nodes.

```bash
# Check all nodes
./health-check.sh

# Check single node
./health-check.sh tokyo
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
Checking saorsa-8 (149.28.156.231)... HEALTHY (peers: 5)
Checking saorsa-9 (45.77.176.184)... HEALTHY (peers: 5)

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

- **Bind address**: Public IP + port 12000
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
systemctl status x0x-bootstrap

# View logs
journalctl -u x0x-bootstrap -f

# Restart
systemctl restart x0x-bootstrap

# Stop
systemctl stop x0x-bootstrap

# Start
systemctl start x0x-bootstrap
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
  x0x-bootstrap              # Binary (uploaded by deploy script)

/etc/x0x/
  bootstrap.toml             # Configuration (uploaded by deploy script)

/var/lib/x0x/
  machine.key                # Machine identity (auto-generated)
  data/                      # Runtime data

/etc/systemd/system/
  x0x-bootstrap.service      # Systemd service (uploaded by deploy script)
```

## Troubleshooting

### Service won't start
```bash
# Check logs for errors
ssh root@<IP> 'journalctl -u x0x-bootstrap -n 100 --no-pager'

# Check if binary is executable
ssh root@<IP> 'ls -la /opt/x0x/x0x-bootstrap'

# Check if config is valid
ssh root@<IP> 'cat /etc/x0x/bootstrap.toml'
```

### Network connectivity issues
```bash
# Test QUIC port is open
ssh root@<IP> 'ss -tulpn | grep 12000'

# Check firewall (should allow UDP 12000)
ssh root@<IP> 'ufw status'
```

### Node can't reach peers
```bash
# Verify known_peers in config
ssh root@<IP> 'grep known_peers /etc/x0x/bootstrap.toml'

# Test UDP connectivity to peer
ssh root@<IP> 'nc -vzu <peer_ip> 12000'
```

### Clean slate restart
```bash
# Complete cleanup and redeploy
./cleanup.sh <node_name>
./deploy.sh <node_name>
```

## Security Notes

1. **Never compile on VPS** - always build locally with `cargo zigbuild`
2. **Health endpoint is localhost-only** - not exposed to public internet
3. **Machine keys are generated once** - backup if needed before cleanup
4. **Firewall rules** - ensure UDP 12000 is allowed
5. **Service runs as root** - required for port binding (consider dedicated user later)

## Monitoring

### Quick health check of all nodes
```bash
./health-check.sh
```

### Monitor logs in real-time
```bash
# On a specific node
ssh root@<IP> 'journalctl -u x0x-bootstrap -f'
```

### Check resource usage
```bash
ssh root@<IP> 'systemctl status x0x-bootstrap'
```

## Next Steps

After successful deployment:

1. Verify all nodes are healthy: `./health-check.sh`
2. Monitor network formation in logs
3. Test agent connections to bootstrap network
4. Monitor metrics endpoints for network statistics

## Support

- Project: https://github.com/saorsa-labs/x0x
- Contact: david@saorsalabs.com
