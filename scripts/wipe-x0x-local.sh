#!/usr/bin/env bash
# wipe-x0x-local.sh — reproducible local teardown of x0x/x0xd.
#
# Used by Phase 3.1 of the GUI-coverage + communitas-parity plan to verify
# that each desktop app can install x0x from scratch. Removes every known
# install path, data directory, key store, launch agent and cached config so
# the next run starts from nothing.
#
# The script is intentionally conservative: it backs up ~/.x0x to a
# timestamped tarball before deleting anything so you can restore your agent
# keypair afterwards. Pass --force to skip the backup prompt.
#
# Usage:
#   scripts/wipe-x0x-local.sh            # interactive, prompts + backs up
#   scripts/wipe-x0x-local.sh --force    # non-interactive, still backs up
#   scripts/wipe-x0x-local.sh --dry-run  # print what would be removed

set -euo pipefail

FORCE=0
DRYRUN=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --dry-run) DRYRUN=1 ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *) echo "Unknown flag: $arg" >&2; exit 2 ;;
    esac
done

HOME_DIR="${HOME}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${HOME_DIR}/.x0x-wipe-backup-${TIMESTAMP}.tar.gz"

say() { printf '\033[36m→\033[0m %s\n' "$*"; }
do_cmd() {
    if [ "$DRYRUN" = "1" ]; then
        printf '\033[33m[dry]\033[0m %s\n' "$*"
    else
        eval "$@"
    fi
}

# ── Running processes ─────────────────────────────────────────────────────
say "Stopping x0xd if running"
do_cmd "pkill -f '(^| )x0xd( |$)' 2>/dev/null || true"

# ── Autostart (macOS LaunchAgent / Linux systemd user unit) ──────────────
if [ -d "${HOME_DIR}/Library/LaunchAgents" ]; then
    for plist in \
        "${HOME_DIR}/Library/LaunchAgents/com.saorsa-labs.x0xd.plist" \
        "${HOME_DIR}/Library/LaunchAgents/com.saorsalabs.x0xd.plist"; do
        if [ -f "$plist" ]; then
            say "Unloading LaunchAgent: $plist"
            do_cmd "launchctl unload '$plist' 2>/dev/null || true"
            do_cmd "rm -f '$plist'"
        fi
    done
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user list-unit-files 2>/dev/null | grep -q '^x0xd\.service'; then
        say "Stopping and disabling user systemd unit x0xd.service"
        do_cmd "systemctl --user stop x0xd 2>/dev/null || true"
        do_cmd "systemctl --user disable x0xd 2>/dev/null || true"
        do_cmd "rm -f '${HOME_DIR}/.config/systemd/user/x0xd.service'"
    fi
fi

# ── Backup ~/.x0x before deletion (unless dry-run) ───────────────────────
if [ -d "${HOME_DIR}/.x0x" ] && [ "$DRYRUN" = "0" ]; then
    if [ "$FORCE" = "0" ]; then
        printf 'Backup ~/.x0x to %s? [Y/n] ' "$BACKUP"
        read -r reply
        reply="${reply:-Y}"
        case "$reply" in
            Y|y|yes) ;;
            *) echo "Skipping backup"; BACKUP="" ;;
        esac
    fi
    if [ -n "$BACKUP" ]; then
        say "Backing up ~/.x0x → $BACKUP"
        tar -czf "$BACKUP" -C "$HOME_DIR" .x0x
    fi
fi

# ── Binaries ─────────────────────────────────────────────────────────────
BIN_PATHS=(
    "/usr/local/bin/x0x"
    "/usr/local/bin/x0xd"
    "/opt/homebrew/bin/x0x"
    "/opt/homebrew/bin/x0xd"
    "${HOME_DIR}/.local/bin/x0x"
    "${HOME_DIR}/.local/bin/x0xd"
    "${HOME_DIR}/bin/x0x"
    "${HOME_DIR}/bin/x0xd"
    "${HOME_DIR}/.cargo/bin/x0x"
    "${HOME_DIR}/.cargo/bin/x0xd"
)
for bin in "${BIN_PATHS[@]}"; do
    if [ -e "$bin" ] || [ -L "$bin" ]; then
        say "Removing $bin"
        do_cmd "rm -f '$bin'"
    fi
done

# Anything else on PATH
for name in x0x x0xd; do
    if path="$(command -v "$name" 2>/dev/null)"; then
        say "Removing $path (found on PATH)"
        do_cmd "rm -f '$path'"
    fi
done

# ── Data, config, keys ───────────────────────────────────────────────────
DATA_DIRS=(
    "${HOME_DIR}/.x0x"
    "${HOME_DIR}/.config/x0x"
    "${HOME_DIR}/.local/share/x0x"
    "${HOME_DIR}/Library/Application Support/x0x"
    "${HOME_DIR}/Library/Preferences/com.saorsa-labs.x0xd.plist"
)
for d in "${DATA_DIRS[@]}"; do
    if [ -e "$d" ]; then
        say "Removing $d"
        do_cmd "rm -rf '$d'"
    fi
done

# ── Confirm ──────────────────────────────────────────────────────────────
say "Verifying x0x is gone"
if command -v x0x >/dev/null 2>&1 || command -v x0xd >/dev/null 2>&1; then
    echo "warning: x0x or x0xd still on PATH:" >&2
    command -v x0x 2>/dev/null || true
    command -v x0xd 2>/dev/null || true
    exit 1
else
    echo "x0x cleanly removed."
fi

if [ -n "${BACKUP:-}" ] && [ -f "$BACKUP" ]; then
    echo "Backup available: $BACKUP"
    echo "Restore with: tar -xzf '$BACKUP' -C '$HOME_DIR'"
fi
