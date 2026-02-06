#!/bin/bash
# Deploy x0x bootstrap nodes to VPS infrastructure
# Usage: ./deploy.sh [node_name]
#   node_name: nyc, sfo, helsinki, nuremberg, singapore, tokyo, or 'all'

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="$SCRIPT_DIR/../target/release/x0x-bootstrap"

# Node definitions
declare -A NODES=(
    ["nyc"]="142.93.199.50"
    ["sfo"]="147.182.234.192"
    ["helsinki"]="65.21.157.229"
    ["nuremberg"]="116.203.101.172"
    ["singapore"]="149.28.156.231"
    ["tokyo"]="45.77.176.184"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if binary exists
check_binary() {
    if [[ ! -f "$BINARY_PATH" ]]; then
        log_error "Binary not found at $BINARY_PATH"
        log_info "Build it with: cargo zigbuild --release --target x86_64-unknown-linux-gnu -p x0x-bootstrap"
        exit 1
    fi
    log_info "Binary found: $BINARY_PATH"
}

# Deploy to a single node
deploy_node() {
    local node_name=$1
    local ip=${NODES[$node_name]}

    log_info "Deploying to $node_name ($ip)..."

    # Create directories
    ssh root@"$ip" 'mkdir -p /opt/x0x /etc/x0x /var/lib/x0x/data /var/log/x0x' || {
        log_error "Failed to create directories on $node_name"
        return 1
    }

    # Copy binary
    log_info "  Uploading binary..."
    scp "$BINARY_PATH" root@"$ip":/opt/x0x/x0x-bootstrap || {
        log_error "Failed to upload binary to $node_name"
        return 1
    }

    # Set executable permissions
    ssh root@"$ip" 'chmod +x /opt/x0x/x0x-bootstrap' || {
        log_error "Failed to set permissions on $node_name"
        return 1
    }

    # Copy configuration
    log_info "  Uploading configuration..."
    scp "$SCRIPT_DIR/bootstrap-${node_name}.toml" root@"$ip":/etc/x0x/bootstrap.toml || {
        log_error "Failed to upload config to $node_name"
        return 1
    }

    # Copy systemd service
    log_info "  Installing systemd service..."
    scp "$SCRIPT_DIR/x0x-bootstrap.service" root@"$ip":/etc/systemd/system/ || {
        log_error "Failed to upload service file to $node_name"
        return 1
    }

    # Reload systemd and enable service
    ssh root@"$ip" 'systemctl daemon-reload && systemctl enable x0x-bootstrap' || {
        log_error "Failed to enable service on $node_name"
        return 1
    }

    log_info "  Deployment to $node_name complete"
    return 0
}

# Start service on a node
start_node() {
    local node_name=$1
    local ip=${NODES[$node_name]}

    log_info "Starting x0x-bootstrap on $node_name..."
    ssh root@"$ip" 'systemctl restart x0x-bootstrap' || {
        log_error "Failed to start service on $node_name"
        return 1
    }

    # Wait a moment for startup
    sleep 2

    # Check status
    local status
    status=$(ssh root@"$ip" 'systemctl is-active x0x-bootstrap' || echo "failed")

    if [[ "$status" == "active" ]]; then
        log_info "  Service active on $node_name"
        return 0
    else
        log_error "  Service failed to start on $node_name"
        ssh root@"$ip" 'journalctl -u x0x-bootstrap -n 20 --no-pager'
        return 1
    fi
}

# Check health of a node
check_health() {
    local node_name=$1
    local ip=${NODES[$node_name]}

    local health
    health=$(ssh root@"$ip" 'curl -s http://127.0.0.1:12600/health' 2>/dev/null || echo "FAILED")

    if [[ "$health" == "FAILED" ]]; then
        log_error "$node_name: UNREACHABLE"
        return 1
    else
        log_info "$node_name: $health"
        return 0
    fi
}

# Main deployment flow
main() {
    local target=${1:-}

    if [[ -z "$target" ]]; then
        log_error "Usage: $0 [node_name|all]"
        log_info "Available nodes: ${!NODES[@]}"
        exit 1
    fi

    check_binary

    if [[ "$target" == "all" ]]; then
        log_info "Deploying to all nodes..."
        local failed_nodes=()

        # Deploy to all nodes
        for node in "${!NODES[@]}"; do
            if ! deploy_node "$node"; then
                failed_nodes+=("$node")
            fi
        done

        if [[ ${#failed_nodes[@]} -gt 0 ]]; then
            log_error "Deployment failed on: ${failed_nodes[*]}"
            exit 1
        fi

        log_info "All deployments complete. Starting services..."

        # Start all services
        for node in "${!NODES[@]}"; do
            start_node "$node" || true  # Continue even if one fails
        done

        log_info "Waiting 10 seconds for network formation..."
        sleep 10

        # Check health of all nodes
        log_info "Health check results:"
        for node in "${!NODES[@]}"; do
            check_health "$node" || true
        done

    else
        # Deploy to single node
        if [[ ! -v "NODES[$target]" ]]; then
            log_error "Unknown node: $target"
            log_info "Available nodes: ${!NODES[@]}"
            exit 1
        fi

        deploy_node "$target" || exit 1
        start_node "$target" || exit 1

        log_info "Waiting 5 seconds..."
        sleep 5

        check_health "$target" || exit 1
    fi

    log_info "Deployment complete!"
}

main "$@"
