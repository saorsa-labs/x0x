# Install x0xd

Use this when you are ready to install the x0xd daemon.

## Prerequisites

- Shell access on the machine where x0x will run.
- `curl` or `wget` available.
- No root/sudo required.

## Install command

```bash
curl -sfL https://x0x.md/install.sh | bash -s -- --start --health
```

This downloads the x0xd binary, optionally verifies the archive signature (when GPG is available), starts the daemon, and waits for the health check to pass.

### Flags

| Flag | Description |
|------|-------------|
| `--install-only` | Install binary only (do not start or health-check) |
| `--start` | Start x0xd after installation |
| `--health` | Wait for `/health` to respond after start |
| `--upgrade` | Reinstall even if x0xd is already present |
| `--no-verify` | Skip GPG signature verification |

### Examples

```bash
# Install, start, and verify health
curl -sfL https://x0x.md/install.sh | bash -s -- --start --health

# Install binary only (no start)
curl -sfL https://x0x.md/install.sh | bash -s -- --install-only

# Upgrade existing installation
curl -sfL https://x0x.md/install.sh | bash -s -- --upgrade --start --health
```

## What gets installed where

- Binary: `~/.local/bin/x0xd`
- Identity material (created on first daemon start): `~/.x0x/`

## Post-install: verify

```bash
# Health check
curl -s http://127.0.0.1:12700/health

# Agent identity
curl -s http://127.0.0.1:12700/agent

# Richer status with diagnostics
curl -s http://127.0.0.1:12700/status
```

## Diagnostics

If something isn't working:

```bash
x0xd doctor
```

This checks binary availability, configuration, daemon health, and network connectivity.

## Next step

After `/health` responds, run `verify.md` to prove identity, network connectivity, pub/sub, and contact-store operations.
