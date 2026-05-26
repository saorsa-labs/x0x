# Self-Update System (`upgrade/`)

Manifest-based decentralized self-update with symmetric gossip propagation.

## Components

- **`manifest.rs`**: `ReleaseManifest` and `PlatformAsset` types, length-prefixed wire format (`[4-byte BE len][JSON][ML-DSA-65 sig]`), platform target detection (including musl vs glibc)
- **`signature.rs`**: ML-DSA-65 signing/verification for archives and manifests. Embedded release public key.
- **`monitor.rs`**: `UpgradeMonitor` polls GitHub releases, `fetch_verified_manifest()` downloads and verifies manifest+signature, returns `VerifiedRelease` with pre-encoded gossip payload
- **`apply.rs`**: `apply_upgrade_from_manifest()` — downloads archive, verifies SHA-256 hash, extracts binary, performs atomic replacement with rollback. A `TempDirGuard` (RAII) removes the per-attempt `.x0x-upgrade-*` temp dir on every exit path, including early-return errors, so a failed apply never leaks the downloaded archive.
- **`rollout.rs`**: Staged rollout with deterministic delay based on machine ID hash (configurable window)

### Binary replacement (`mod.rs`)

`Upgrader::atomic_replace` is platform-split:

- **Unix**: `fs::rename(new, target)` — atomic on the same filesystem, valid even when `target` is the running executable.
- **Windows / non-Unix**: a running executable is locked and cannot be renamed over in place. `replace_via_sideline` moves the live binary aside to `<name>.x0xold-<nanos>` (allowed even while locked), moves the new binary into place, and rolls the sideline back if the second move fails. The sidelined file stays locked until the old process exits and is reclaimed on the next launch.

`sweep_stale_upgrade_artifacts(dir, min_age)` runs once at `x0xd` startup. It removes leftover `.x0x-upgrade-*` temp dirs older than `min_age` (1h — never disturbs an in-flight apply) and best-effort deletes `*.x0xold-*` sidelined binaries. This reclaims debris from previously-interrupted attempts.

## Update Flow (for x0xd)

1. **Startup**: Check GitHub for new release, broadcast manifest to gossip if found
2. **Gossip listener**: Receive manifests on `x0x/releases` topic, verify signature, rebroadcast, apply if newer
3. **GitHub poller**: Periodic fallback poll, broadcast discovered manifests to gossip

Both apply paths back off versions that fail to apply: a failed version is recorded and skipped for 30 minutes before retrying (a newer release supersedes the skip immediately). This prevents a release that can never apply in a given environment from re-downloading and re-extracting on every gossip receipt.

All nodes verify and rebroadcast manifests (symmetric propagation — no privileged bootstrap role).

## CI Integration

`release.yml` generates `release-manifest.json` and `release-manifest.json.sig` via `x0x-keygen manifest` during the release signing job.
