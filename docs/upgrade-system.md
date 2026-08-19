# Self-Update System (`upgrade/`)

Manifest-based decentralized self-update with symmetric gossip propagation.

## Components

- **`manifest.rs`**: `ReleaseManifest` and `PlatformAsset` types, length-prefixed wire format (`[4-byte BE len][JSON][ML-DSA-65 sig]`), platform target detection (including musl vs glibc)
- **`signature.rs`**: ML-DSA-65 signing/verification for archives and manifests. Embedded release public key.
- **`monitor.rs`**: `UpgradeMonitor` polls GitHub releases, `fetch_verified_manifest()` downloads and verifies manifest+signature, returns `VerifiedRelease` with pre-encoded gossip payload
- **`apply.rs`**: `apply_upgrade_from_manifest()` — downloads archive, verifies SHA-256 hash, extracts binary, performs atomic replacement with rollback. A `TempDirGuard` (RAII) removes the per-attempt `.x0x-upgrade-*` temp dir on every exit path, including early-return errors, so a failed apply never leaks the downloaded archive.
- **`restart.rs`**: the #261 restart transaction — supervision classification (`RestartMode`), the `upgrade-handoff.json` intent record, the detached handoff helper, and the loud `UPGRADE_FAILED` artifact.
- **`rollout.rs`**: Staged rollout with deterministic delay based on machine ID hash (configurable window)

### Binary replacement (`mod.rs`)

`Upgrader::atomic_replace` is platform-split:

- **Unix**: `fs::rename(new, target)` — atomic on the same filesystem, valid even when `target` is the running executable.
- **Windows / non-Unix**: a running executable is locked and cannot be renamed over in place. `replace_via_sideline` moves the live binary aside to `<name>.x0xold-<nanos>` (allowed even while locked), moves the new binary into place, and rolls the sideline back if the second move fails. The sidelined file stays locked until the old process exits and is reclaimed on the next launch.

`sweep_stale_upgrade_artifacts(dir, min_age)` runs once at `x0xd` startup. It removes leftover `.x0x-upgrade-*` temp dirs older than `min_age` (1h — never disturbs an in-flight apply) and `*.x0xold-*` sidelined binaries that clear the same age gate (issue #261: a handoff still in flight must not lose its rollback bytes). This reclaims debris from previously-interrupted attempts.

## Restart after swap (#261 — transactional handoff)

After the swap commits, the daemon classifies supervision **before** anything
destructive runs (`upgrade::restart::plan_restart_mode`):

- `SupervisedExit` — only when `[update] stop_on_upgrade = true` (the default)
  **and** one of three real signals is present: `INVOCATION_ID` is set
  (systemd unit), the parent's `comm` is `systemd`, or `X0X_SUPERVISED=1`
  (explicit opt-in: launchd plist, Windows service). The daemon writes the
  intent file, then exits 0 (100 on Windows) for the supervisor to re-exec the
  new bytes. A *missing TTY* is **not** supervision — nohup/background/detached
  stdin never qualifies, and neither does "some ancestor is launchd" (every
  macOS process has that).
- `TransactionalHandoff` — everything else, including unsupervised runs with
  the default `stop_on_upgrade = true` (the macOS terminal incident) and every
  `stop_on_upgrade = false` run. The old `exec()` path is gone: it could not
  roll back.

The handoff transaction (`upgrade::restart`):

1. The old daemon writes `data_dir/upgrade-handoff.json` (from/to versions,
   target/backup paths, argv, cwd, env whitelist, old pid, API address,
   timestamp) — captured before any exit, and also on the supervised path so a
   crash loop is diagnosable.
2. It spawns a detached helper in a new session — the same `x0xd` binary,
   preferring the known-good backup bytes — as `x0xd --upgrade-handoff <file>`.
3. It triggers the graceful-shutdown hook with a **5s bound** (never waits
   unbounded; the macOS SIGTERM-hang incident), then `_exit(0)`.
4. The helper waits (30s bound) for the old pid to die and the API port to
   free — **never SIGKILLs** it. If the old process hangs past the bound, the
   helper aborts the spawn, restores the backup over the target, leaves the
   old process running, and writes `UPGRADE_FAILED`.
5. The helper spawns the new binary with the captured argv/cwd (appending
   `--skip-update-check` only if not already present) and waits for
   `GET /health` 200 on the pre-upgrade API address (or the fresh
   `<data_dir>/api.port` when the bind is ephemeral) within 30s.
6. Health OK ⇒ restart committed: the handoff file is deleted and the helper
   exits 0. Health fail/spawn fail ⇒ the backup is restored over the target
   and the previous binary is respawned with the same argv/cwd, then
   health-checked again.
7. If the rollback respawn also fails, the helper writes
   `data_dir/UPGRADE_FAILED` (reason, versions, paths, timestamps), eprints,
   and exits **nonzero** — never a silent exit 0. The invariant: after any
   apply, either a process answers `/health` or `UPGRADE_FAILED` exists and
   the last exit is nonzero.

The helper's wait bounds are operator-tunable via
`X0X_UPGRADE_HANDOFF_RELEASE_TIMEOUT_SECS` and
`X0X_UPGRADE_HANDOFF_HEALTH_TIMEOUT_SECS` (both default 30). The helper joins
no gossip, binds nothing, and takes no instance lock.

## Update Flow (for x0xd)

1. **Startup**: Check GitHub for new release, broadcast manifest to gossip if found
2. **Gossip listener**: Receive manifests on `x0x/releases` topic, verify signature, rebroadcast, apply if newer
3. **GitHub poller**: Periodic fallback poll, broadcast discovered manifests to gossip

Both apply paths back off versions that fail to apply: a failed version is recorded and skipped for 30 minutes before retrying (a newer release supersedes the skip immediately). This prevents a release that can never apply in a given environment from re-downloading and re-extracting on every gossip receipt.

`x0xd --skip-update-check` disables self-update for that process invocation. It
suppresses the startup GitHub check, gossip-delivered apply, manifest broadcast,
fallback polling, and manual `/upgrade/apply`. The setting is not persisted;
launching the daemon normally later restores the configured updater behavior.

All nodes verify and rebroadcast manifests (symmetric propagation — no privileged bootstrap role).

## CI Integration

`release.yml` generates `release-manifest.json` and `release-manifest.json.sig` via `x0x-keygen manifest` during the release signing job.
