#!/bin/bash
# Installation script for x0x-bootstrap on VPS nodes
# Usage: ./install.sh [--binary path/to/binary] [--config path/to/config.toml]
# Default: Uses /tmp/x0x-bootstrap and /tmp/bootstrap.toml if not specified

set -euo pipefail

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

# Parse arguments
BINARY_PATH="${1:-/tmp/x0x-bootstrap}"
CONFIG_PATH="${2:-/tmp/bootstrap.toml}"

if [[ ! -f "$BINARY_PATH" ]]; then
    log_error "Binary not found: $BINARY_PATH"
    exit 1
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
    log_error "Config not found: $CONFIG_PATH"
    exit 1
fi

log_info "Installing x0x-bootstrap..."
log_info "Binary: $BINARY_PATH"
log_info "Config: $CONFIG_PATH"

# Create x0x user if doesn't exist
if ! id -u x0x >/dev/null 2>&1; then
    log_info "Creating x0x user..."
    useradd --system --no-create-home --shell /bin/false x0x
else
    log_info "User x0x already exists"
fi

# Create directories
log_info "Creating directories..."
mkdir -p /opt/x0x
mkdir -p /etc/x0x
mkdir -p /var/lib/x0x/data
chown -R x0x:x0x /var/lib/x0x

# Copy binary
log_info "Installing binary..."
cp "$BINARY_PATH" /opt/x0x/x0x-bootstrap
chmod +x /opt/x0x/x0x-bootstrap
chown root:root /opt/x0x/x0x-bootstrap

# Copy config
log_info "Installing config..."
cp "$CONFIG_PATH" /etc/x0x/bootstrap.toml
chmod 644 /etc/x0x/bootstrap.toml
chown root:root /etc/x0x/bootstrap.toml

# Install systemd service
log_info "Installing systemd service..."
if [[ -f "/tmp/x0x-bootstrap.service" ]]; then
    cp /tmp/x0x-bootstrap.service /etc/systemd/system/x0x-bootstrap.service
    chmod 644 /etc/systemd/system/x0x-bootstrap.service
else
    log_warn "Service file not found at /tmp/x0x-bootstrap.service"
    log_warn "Please install manually or run this script after uploading service file"
fi

# Reload systemd
log_info "Reloading systemd..."
systemctl daemon-reload

# Enable service
log_info "Enabling x0x-bootstrap service..."
systemctl enable x0x-bootstrap

# Start service
log_info "Starting x0x-bootstrap service..."
systemctl start x0x-bootstrap

# Wait a moment for service to start
sleep 2

# Check status
if systemctl is-active --quiet x0x-bootstrap; then
    log_info "Service is running"

    # Check health endpoint
    if command -v curl >/dev/null 2>&1; then
        log_info "Checking health endpoint..."
        if curl -s -f http://127.0.0.1:12600/health >/dev/null; then
            log_info "Health check: OK"
        else
            log_warn "Health check failed - service may still be initializing"
        fi
    fi

    log_info "Installation complete!"
    log_info ""
    log_info "Commands:"
    log_info "  Status:  systemctl status x0x-bootstrap"
    log_info "  Logs:    journalctl -u x0x-bootstrap -f"
    log_info "  Restart: systemctl restart x0x-bootstrap"
    log_info "  Stop:    systemctl stop x0x-bootstrap"
    log_info "  Health:  curl http://127.0.0.1:12600/health"
else
    log_error "Service failed to start"
    log_error "Check logs: journalctl -u x0x-bootstrap -n 50 --no-pager"
    exit 1
fi
