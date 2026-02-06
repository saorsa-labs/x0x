#!/usr/bin/env bash
#
# check-mesh.sh - Verify x0x bootstrap mesh connectivity
# Usage: ./check-mesh.sh
#
# Checks:
# - All 6 nodes are responding
# - Each node reports correct peer count
# - Health endpoints functional

set -euo pipefail

# VPS bootstrap nodes
declare -A NODES=(
    ["saorsa-2"]="142.93.199.50"
    ["saorsa-3"]="147.182.234.192"
    ["saorsa-6"]="65.21.157.229"
    ["saorsa-7"]="116.203.101.172"
    ["saorsa-8"]="149.28.156.231"
    ["saorsa-9"]="45.77.176.184"
)

HEALTH_PORT=12600
QUIC_PORT=12000
EXPECTED_PEERS=5  # Each node should have 5 peers (6 total - self)

echo "========================================="
echo "x0x Bootstrap Mesh Health Check"
echo "========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

total_nodes=0
healthy_nodes=0
unhealthy_nodes=0

for node in "${!NODES[@]}"; do
    ip="${NODES[$node]}"
    total_nodes=$((total_nodes + 1))
    
    echo -n "Checking $node ($ip)... "
    
    # Check if node is reachable via SSH
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes root@"$ip" 'exit' 2>/dev/null; then
        echo -e "${RED}UNREACHABLE${NC} (SSH failed)"
        unhealthy_nodes=$((unhealthy_nodes + 1))
        continue
    fi
    
    # Check health endpoint
    health_response=$(ssh -o ConnectTimeout=5 root@"$ip" "curl -s -m 5 http://127.0.0.1:$HEALTH_PORT/health 2>/dev/null" || echo "FAILED")
    
    if [[ "$health_response" == "FAILED" ]]; then
        echo -e "${RED}UNHEALTHY${NC} (health endpoint not responding)"
        
        # Check if service is running
        service_status=$(ssh root@"$ip" "systemctl is-active x0x-bootstrap 2>/dev/null" || echo "unknown")
        echo "  Service status: $service_status"
        
        # Show last 5 log lines
        echo "  Recent logs:"
        ssh root@"$ip" "journalctl -u x0x-bootstrap -n 5 --no-pager 2>/dev/null" | sed 's/^/    /' || echo "    (no logs available)"
        
        unhealthy_nodes=$((unhealthy_nodes + 1))
        continue
    fi
    
    # Parse peer count from response
    # Expected format: {"status":"healthy","peers":5} or similar
    peer_count=$(echo "$health_response" | grep -o '"peers":[0-9]*' | cut -d: -f2 || echo "0")
    status=$(echo "$health_response" | grep -o '"status":"[^"]*"' | cut -d\" -f4 || echo "unknown")
    
    if [[ "$status" == "healthy" ]] && [[ "$peer_count" -eq "$EXPECTED_PEERS" ]]; then
        echo -e "${GREEN}HEALTHY${NC} (peers: $peer_count)"
        healthy_nodes=$((healthy_nodes + 1))
    elif [[ "$status" == "healthy" ]] && [[ "$peer_count" -lt "$EXPECTED_PEERS" ]]; then
        echo -e "${YELLOW}PARTIAL${NC} (peers: $peer_count/$EXPECTED_PEERS)"
        healthy_nodes=$((healthy_nodes + 1))
        echo "  Note: Still connecting to peers (this is normal during startup)"
    else
        echo -e "${RED}UNHEALTHY${NC} (status: $status, peers: $peer_count)"
        unhealthy_nodes=$((unhealthy_nodes + 1))
        
        # Show last 5 log lines
        echo "  Recent logs:"
        ssh root@"$ip" "journalctl -u x0x-bootstrap -n 5 --no-pager 2>/dev/null" | sed 's/^/    /' || echo "    (no logs available)"
    fi
done

echo ""
echo "========================================="
echo "Summary"
echo "========================================="
echo "Total nodes: $total_nodes"
echo -e "Healthy: ${GREEN}$healthy_nodes${NC}"
echo -e "Unhealthy: ${RED}$unhealthy_nodes${NC}"

if [[ "$unhealthy_nodes" -eq 0 ]]; then
    echo -e "\n${GREEN}✓ All bootstrap nodes are healthy!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ $unhealthy_nodes node(s) need attention${NC}"
    exit 1
fi
