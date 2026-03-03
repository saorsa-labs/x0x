# Install x0x

Use this when you are ready to install `x0xd`.

## Prerequisites

- Shell access on the machine where x0x will run.
- `curl` or `wget` available.
- No root/sudo required.

## Install command

```bash
curl -sfL https://x0x.md/install.sh | bash
```

Interactive mode for humans:

```bash
curl -sfL https://x0x.md/install.sh | bash -s -- --interactive
```

- `--interactive` mode switch is not implemented yet in current scripts; this invocation is planned for Phase 02 plan `02-01`. [planned]

## Current behavior now

- `scripts/install.sh` and `scripts/install.py` are interactive by default today. [working]
- Default runs may prompt for input and are not yet safe for unattended agent execution. [working]
- No stable JSON stdout schema is emitted today. [working]

## Planned Phase 02 behavior (plan `02-01`)

- No prompts (`read`/`input`) in default mode. [planned]
- Progress and warnings go to stderr. [planned]
- Final machine-readable status goes to stdout as JSON. [planned]
- If GPG is unavailable, installation continues and reports `"gpg_verified": false`. [planned]
- If GPG verification fails, platform is unsupported, downloads fail, or writes fail, installation exits non-zero and emits error JSON. [planned]

## Planned JSON output schema (Phase 02)

Success (stdout):

```json
{
  "status": "ok",
  "x0xd_path": "/home/user/.local/bin/x0xd",
  "skill_path": "/home/user/.local/share/x0x/SKILL.md",
  "gpg_verified": true,
  "platform": "macos-arm64",
  "version": "0.2.0"
}
```

Failure (stdout):

```json
{
  "status": "error",
  "error": "GPG signature verification failed",
  "code": "gpg_verification_failed"
}
```

`code` values:

| Code | Meaning |
|---|---|
| `ok` | Installation succeeded |
| `gpg_verification_failed` | SKILL.md signature did not verify |
| `unsupported_platform` | No binary available for this OS/arch |
| `download_failed` | Could not download from GitHub releases |
| `permission_denied` | Cannot write to install directory |
| `already_installed` | `x0xd` already exists at the install path |

## What gets installed where

- Binary: `~/.local/bin/x0xd` [working]
- Data root: `~/.local/share/x0x/` [working]
- Identity material (created on first daemon start): `~/.local/share/x0x/identity/` [working]

## Post-install: start and wait for readiness

Start daemon:

```bash
x0xd &
```

Wait for health endpoint before continuing:

```bash
until curl -sf http://127.0.0.1:12700/health >/dev/null; do sleep 1; done
```

If readiness does not arrive, go to `troubleshooting.md` for startup diagnostics.

## Next step

After `/health` responds, run `verify.md` to prove identity, network connectivity, pub/sub, and contact-store operations.
