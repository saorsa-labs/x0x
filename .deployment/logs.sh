#!/bin/bash
# View logs from x0x bootstrap nodes
# Usage: ./logs.sh [node_name] [lines]
#   node_name: nyc, sfo, singapore, sydney
#   lines: number of lines to show (default: 50)

set -euo pipefail

# Node definitions
declare -A NODES=(
    ["nyc"]="142.93.199.50"
    ["sfo"]="147.182.234.192"
    ["singapore"]="152.42.210.67"
    ["sydney"]="170.64.176.102"
)

main() {
    local node_name=${1:-}
    local lines=${2:-50}

    if [[ -z "$node_name" ]]; then
        echo "Usage: $0 [node_name] [lines]"
        echo "Available nodes: ${!NODES[@]}"
        exit 1
    fi

    if [[ ! -v "NODES[$node_name]" ]]; then
        echo "Unknown node: $node_name"
        echo "Available nodes: ${!NODES[@]}"
        exit 1
    fi

    local ip=${NODES[$node_name]}

    echo "Logs from $node_name ($ip) - last $lines lines:"
    echo "================================================"
    echo

    ssh root@"$ip" "journalctl -u x0xd -n $lines --no-pager"
}

main "$@"
