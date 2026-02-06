#!/bin/bash
# View logs from x0x bootstrap nodes
# Usage: ./logs.sh [node_name] [lines]
#   node_name: nyc, sfo, helsinki, nuremberg, singapore, tokyo
#   lines: number of lines to show (default: 50)

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

    ssh root@"$ip" "journalctl -u x0x-bootstrap -n $lines --no-pager"
}

main "$@"
