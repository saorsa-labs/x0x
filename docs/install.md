# Install x0x

Use this when you are ready to install the `x0x` CLI and the `x0xd` daemon.

## Requirements

- Linux or macOS
- `sh`
- `curl` or `wget`
- `tar`
- outbound HTTPS access to GitHub releases

No root or sudo is required.

## Install

Primary install command:

```bash
curl -sfL https://x0x.md | sh
```

GitHub fallback:

```bash
curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh
```

## Useful install modes

Install and immediately start the daemon:

```bash
curl -sfL https://x0x.md | sh -s -- --start
```

Install, start, and configure autostart:

```bash
curl -sfL https://x0x.md | sh -s -- --autostart
```

Install for a named instance:

```bash
curl -sfL https://x0x.md | sh -s -- --name alice --start
```

## What the installer does

The current installer:

1. Detects platform (`linux-x64-gnu`, `linux-arm64-gnu`, `macos-x64`, `macos-arm64`)
2. Downloads the latest release archive from GitHub
3. Installs both `x0x` and `x0xd` into `~/.local/bin`
4. Ensures the shared x0x data directory exists
5. Optionally starts the daemon (`--start`)
6. Optionally configures autostart (`--autostart`)

## Installed locations

### Binaries

- `~/.local/bin/x0x`
- `~/.local/bin/x0xd`

### Daemon data directories

Default instance:

- macOS: `~/Library/Application Support/x0x/`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/x0x/`

Named instance `alice`:

- macOS: `~/Library/Application Support/x0x-alice/`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/x0x-alice/`

These directories may contain:

- `api.port` — the daemon's bound local API address
- `x0xd.log` — installer-started daemon log output
- daemon-managed state such as contacts, groups, and caches

### Identity material

By default, x0x identity keys are stored in:

- `~/.x0x/machine.key`
- `~/.x0x/agent.key`
- `~/.x0x/user.key` (optional, opt-in)
- `~/.x0x/agent.cert` (optional, only when user identity is configured)

Named daemon instances can override identity paths internally, but the library defaults above remain the standard storage layout.

## PATH note

If `~/.local/bin` is not already on your `PATH`, the installer prints a command to add it:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Add that to `~/.bashrc`, `~/.zshrc`, or your shell profile if needed.

## Starting after install

Start the default daemon:

```bash
x0x start
```

Or run the daemon directly:

```bash
x0xd
```

Start a named instance:

```bash
x0x start --name alice
# or
x0xd --name alice
```

## Verify readiness

Health check:

```bash
x0x health
```

Or directly:

```bash
curl -sf http://127.0.0.1:12700/health
```

For the full verification flow, see [verify.md](verify.md).

## Autostart behavior

`--autostart` configures a user-level service:

- Linux: systemd user service
- macOS: launchd user agent

You can also configure this later with:

```bash
x0x autostart
```

Remove autostart with:

```bash
x0x autostart --remove
```

## Named instances

You can run multiple independent local daemons on one machine.

Example:

```bash
x0x start --name alice
x0x start --name bob

x0x --name alice health
x0x --name bob status
x0x instances
```

## Next step

After installation, run:

- [verify.md](verify.md) for step-by-step validation
- [api.md](api.md) for the quick endpoint map
- [api-reference.md](api-reference.md) for the full REST and WebSocket reference
