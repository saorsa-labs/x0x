# Install x0xd

Use this when you are ready to install the local daemon.

## Canonical command

```bash
curl -sfL https://x0x.md/install.sh | bash -s -- --start --health
```

This installs `x0xd`, starts it, and waits for a successful local health check.

## Installer scope

The install script is daemon-only.

- Installs `x0xd` to `~/.local/bin/x0xd`
- Optionally starts `x0xd`
- Optionally waits for `/health`
- Does **not** install or place `SKILL.md`

## Flags

| Flag | Behavior |
|---|---|
| `--install-only` | Install binary only (do not start / health-check) |
| `--start` | Start daemon after install |
| `--health` | Wait for successful `GET /health` |
| `--upgrade` | Reinstall from latest release even if already installed |
| `--no-verify` | Skip archive signature verification |

## Verify quickly

```bash
curl -sf http://127.0.0.1:12700/health
curl -sf http://127.0.0.1:12700/agent
curl -sf http://127.0.0.1:12700/status
```

## Diagnose

```bash
x0xd doctor
```

`x0xd doctor` is useful both when the daemon is running and when it is down.

## Next step

After installation succeeds, run the first-success verification path in `verify.md`.
