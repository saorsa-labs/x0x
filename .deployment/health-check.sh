#!/bin/bash
# Health check for x0x bootstrap network
# Usage: ./health-check.sh [node_name]
#   node_name: nyc, sfo, helsinki, nuremberg, singapore, tokyo, or 'all' (default)

set -euo pipefail

# Node definitions
declare -A NODES=(
    ["nyc"]="142.93.199.50"
    ["sfo"]="147.182.234.192"
    ["helsinki"]="65.21.157.229"
    ["nuremberg"]="116.203.101.172"
    ["singapore"]="149.28.156.231"
    ["tokyo"]="45.77.176.184"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_node() {
    local node_name=$1
    local ip=${NODES[$node_name]}

    printf "%-15s %-17s " "$node_name" "$ip"

    # Check SSH connectivity
    if ! ssh -o ConnectTimeout=5 root@"$ip" 'true' 2>/dev/null; then
        echo -e "${RED}SSH FAILED${NC}"
        return 1
    fi

    # Check service status
    local status
    status=$(ssh root@"$ip" 'systemctl is-active x0x-bootstrap' 2>/dev/null || echo "inactive")

    if [[ "$status" != "active" ]]; then
        echo -e "${RED}SERVICE $status${NC}"
        return 1
    fi

    # Check health endpoint
    local health
    health=$(ssh root@"$ip" 'curl -s -w "\n" http://127.0.0.1:12600/health' 2>/dev/null || echo "FAILED")

    if [[ "$health" == "FAILED" ]]; then
        echo -e "${RED}HEALTH FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}OK${NC} - $health"
        return 0
    fi
}

main() {
    local target=${1:-all}

    echo "x0x Bootstrap Network Health Check"
    echo "===================================="
    echo
    printf "%-15s %-17s %s\n" "NODE" "IP" "STATUS"
    printf "%-15s %-17s %s\n" "----" "--" "------"

    if [[ "$target" == "all" ]]; then
        local total=0
        local healthy=0

        for node in "${!NODES[@]}"; do
            if check_node "$node"; then
                ((healthy++))
            fi
            ((total++))
        done

        echo
        echo "Summary: $healthy/$total nodes healthy"

        if [[ $healthy -eq $total ]]; then
            echo -e "${GREEN}All nodes operational${NC}"
            exit 0
        else
            echo -e "${YELLOW}Some nodes have issues${NC}"
            exit 1
        fi
    else
        if [[ ! -v "NODES[$target]" ]]; then
            echo "Unknown node: $target"
            echo "Available nodes: ${!NODES[@]}"
            exit 1
        fi

        check_node "$target"
    fi
}

main "$@"
