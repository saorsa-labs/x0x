#!/bin/bash
# Clean up x0x bootstrap deployment from VPS nodes
# Usage: ./cleanup.sh [node_name]
#   node_name: nyc, sfo, helsinki, nuremberg, singapore, tokyo, or 'all'
# WARNING: This removes all x0x data from the specified nodes

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

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup_node() {
    local node_name=$1
    local ip=${NODES[$node_name]}

    log_info "Cleaning up $node_name ($ip)..."

    # Stop service
    log_info "  Stopping service..."
    ssh root@"$ip" 'systemctl stop x0x-bootstrap || true' 2>/dev/null || true

    # Disable service
    log_info "  Disabling service..."
    ssh root@"$ip" 'systemctl disable x0x-bootstrap || true' 2>/dev/null || true

    # Remove files
    log_info "  Removing files..."
    ssh root@"$ip" '
        rm -rf /opt/x0x
        rm -rf /etc/x0x
        rm -rf /var/lib/x0x
        rm -f /etc/systemd/system/x0x-bootstrap.service
    ' || {
        log_error "Failed to remove files from $node_name"
        return 1
    }

    # Reload systemd
    ssh root@"$ip" 'systemctl daemon-reload' || true

    # Clean logs (keep last 1 day)
    log_info "  Cleaning logs..."
    ssh root@"$ip" 'journalctl --vacuum-time=1d' || true

    log_info "  Cleanup of $node_name complete"
    return 0
}

main() {
    local target=${1:-}

    if [[ -z "$target" ]]; then
        log_error "Usage: $0 [node_name|all]"
        log_info "Available nodes: ${!NODES[@]}"
        exit 1
    fi

    log_warn "This will remove ALL x0x data from the specified nodes"
    read -p "Are you sure? (yes/no): " -r confirm

    if [[ "$confirm" != "yes" ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi

    if [[ "$target" == "all" ]]; then
        log_info "Cleaning up all nodes..."

        for node in "${!NODES[@]}"; do
            cleanup_node "$node" || true
        done

        log_info "Cleanup complete for all nodes"
    else
        if [[ ! -v "NODES[$target]" ]]; then
            log_error "Unknown node: $target"
            log_info "Available nodes: ${!NODES[@]}"
            exit 1
        fi

        cleanup_node "$target" || exit 1
        log_info "Cleanup complete"
    fi
}

main "$@"
