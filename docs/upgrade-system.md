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

## Restart ownership is resolved before mutation (ADR-0061, #493)

The daemon resolves and validates the whole restart contract **before it
downloads or replaces anything** (`upgrade::restart::resolve_restart_plan`,
called from `apply_upgrade_from_manifest` before the swap). The resulting
`RestartPlan` pins the restart owner, the intended exit behaviour, the
executable/argv, the cwd and the effective data root, and is then *carried*
through replacement and restart — never re-derived once the bytes on disk no
longer match the running image.

If the contract cannot be resolved, the apply returns
`UpgradeError::RestartOwnership` with the current process still serving and
the installed binaries untouched.

`upgrade::restart::plan_restart_mode` decides the owner:

- `SupervisedExit` — only when `[update] stop_on_upgrade = true` (the default)
  **and** one of three real signals is present: `INVOCATION_ID` is set
  (systemd unit), the parent's `comm` is `systemd`, or `X0X_SUPERVISED=1`
  (explicit opt-in: launchd plist, Windows service). On macOS the marker
  alone is **not** enough: the resolver also reads back the **loaded**
  launchd job policy for this instance (`launchctl print`, never the plist
  alone — a loaded job can differ from its file) and requires an
  unconditional `KeepAlive` on it (ADR-0061 §3, #615). A marker whose
  loaded policy cannot be confirmed — `KeepAlive` removed or made
  conditional after `x0x autostart --repair`, a job that is not loaded, no
  job matching this instance's arguments — **refuses** the apply before
  replacement, because exiting 0 into an unconfirmed policy is the
  silent-service-disappearance failure. The refusal names what was found
  and points at the manual recovery procedure below. The daemon then exits
  0 (100 on Windows) for the supervisor to re-exec the new bytes, and
  launches **no** helper. A *missing TTY* is **not** supervision —
  nohup/background/detached stdin never qualifies, and neither does "some
  ancestor is launchd" (every macOS process has that).
- **Refused** — recognized supervision **and** `stop_on_upgrade = false`. That
  combination names two restart owners for one data root: the supervisor
  respawns its child while the handoff helper starts another (#493). Since
  x0xd cannot know the supervisor's policy, it refuses before replacement and
  tells the operator which signal made the instance managed and which setting
  to correct. **This replaced the pre-ADR-0061 behaviour, where
  `stop_on_upgrade = false` always meant a transactional handoff.** Affected
  installs stop applying updates until the config is corrected.
- `TransactionalHandoff` — genuinely unsupervised runs, including the default
  `stop_on_upgrade = true` terminal launch (the macOS terminal incident) and
  unsupervised `stop_on_upgrade = false`. The old `exec()` path is gone: it
  could not roll back.

### What a successful apply does and does not prove

Installed bytes, a pending restart, observed readiness and recovery are four
distinct facts, and the apply logs report them separately. A supervised exit
is a **restart request** to the service manager — not health acceptance, and
not an automatic rollback. Recovery on the supervised path is the operator's
[manual recovery procedure](#manual-recovery-after-a-failed-supervised-upgrade-adr-0061-6);
only the transactional handoff observes
`/health` and restores the backup itself.

### Manual recovery after a failed supervised upgrade (ADR-0061 §6)

On the supervised path a successful apply installs the new bytes, writes the
intent record, and exits 0 for the service manager. x0xd **never** rolls
back automatically on this path — recovery is this manual procedure, run by
the operator who owns the service manager. That is deliberate: a second,
self-appointed restarter beside the manager is the #493 duplicate-daemon
bug this design exists to prevent.

The scenario: a migrated/supervised job took the supervised exit, the
replacement failed to start, and the daemon is now down. Two artifacts
survive the attempt and are all you need:

- `<target>.backup` — the exact bytes that were serving before the swap,
  written beside the installed binary (`<target>`).
- `<data_dir>/upgrade-handoff.json` — the intent record: from/to versions,
  `target_path`, `backup_path`, argv, cwd, old pid, API address. It is a
  *diagnosis record*, not state the daemon needs to boot.

`<data_dir>` is the instance's data directory —
`~/Library/Application Support/x0x` on macOS (`x0x-<name>` for named
instances), `~/.local/share/x0x` on Linux. Read both paths out of the
intent file if you are unsure. Note that `UPGRADE_FAILED` is **never**
written on this path — that artifact belongs to the transactional helper
below; its absence is expected here.

Work through the steps in order and stop as soon as `/health` answers.

#### 1. Diagnose which stage failed

macOS (launchd):

```bash
label=com.saorsalabs.x0xd   # adjust to your job's Label
launchctl print "gui/$(id -u)/$label" | grep -E 'state =|last exit code|program =|properties ='
cat "$HOME/Library/Application Support/x0x/upgrade-handoff.json"
tail -n 100 "$HOME/Library/Logs/x0xd.log"        # the job's StandardErrorPath
```

Read it like this:

- `state = running` and `/health` answers — the replacement came up late;
  nothing to recover. Delete a stale intent file (step 3) and stop.
- `last exit code` nonzero, repeatedly — the replacement starts but fails;
  go to step 2.
- `state = not running` with no respawn and no `keepalive` in `properties`
  — the loaded job no longer holds an unconditional `KeepAlive` (removed or
  made conditional since `x0x autostart --repair` verified it). Restore
  `KeepAlive: true` in the plist and reload it first (`launchctl unload`
  then `launchctl load`, the pair `--repair` prints), then go to step 2.
  Until then every apply is refused with the loaded-policy diagnostic (#615).

systemd (Linux, user unit as generated by `x0x autostart`):

```bash
systemctl --user status x0xd            # names the exit status, shows restart loop or not
journalctl --user -u x0xd -n 100 --no-pager
cat ~/.local/share/x0x/upgrade-handoff.json
```

For a system-level unit drop `--user` and read `sudo journalctl -u x0xd`.
`Restart=no`/`on-failure` on a unit that exits 0 for upgrades is the same
dead-job state as the missing-`KeepAlive` case above: fix the unit
(`Restart=always`, `systemctl daemon-reload`) before restoring service.

#### 2. Restore the known-good binary

Only needed when the replacement will not start. On Unix a rename over the
installed path is safe even if a copy is still running:

```bash
# <target> is the intent file's target_path (the job's program/ExecStart)
mv <target>.backup <target>
```

There is no intent file and no backup to restore (the daemon died before
writing them)? The installed bytes are the replacement — reinstall the
previous release's binary at `<target>` by your usual means, then continue.

#### 3. Reconcile the intent file and re-enter under the supervisor

Delete the intent record once the running version is settled, so the next
apply does not look like an in-flight attempt:

```bash
rm <data_dir>/upgrade-handoff.json
```

Then restart **through the manager** — never launch x0xd by hand beside the
job; a manually started daemon plus a respawning job is two restart owners
on one data root (#493):

```bash
# macOS (launchd) — restart the job now:
launchctl kickstart -k "gui/$(id -u)/$label"
# ...or, if you edited the plist (e.g. restoring KeepAlive), reload it:
launchctl unload "$HOME/Library/LaunchAgents/$label.plist"
launchctl load "$HOME/Library/LaunchAgents/$label.plist"

# Linux (systemd, user unit; drop --user for a system unit):
systemctl --user restart x0xd
```

#### 4. Verify, then retry the upgrade deliberately

```bash
curl -fsS http://127.0.0.1:12700/health | head -c 300; echo
```

`ok: true` with the expected `version` ⇒ recovered. Re-attempt the upgrade
only after fixing whatever step 1 identified (a broken release will fail
the same way again; a refused apply means the loaded policy still does not
guarantee a respawn).


### Migrating an existing launchd job

> **An existing hand-written launchd job is not fixed by upgrading x0x.**
> A job with no `X0X_SUPERVISED=1` marker keeps taking the transactional
> handoff path, so launchd still respawns its own child while the helper
> starts another — the #493 duplicate daemon. Detection cannot prove an
> arbitrary custom job is supervised (ADR-0061 §4); migration is the fix.
> Run `x0x autostart --repair`, then reload the job with the `launchctl`
> pair it prints.

`x0x autostart --repair` inspects the LaunchAgents in `~/Library/LaunchAgents`
without changing service state, and adds only
`EnvironmentVariables.X0X_SUPERVISED = "1"` to an existing x0xd job, after
backing the plist up and verifying the readback. It preserves the job's label,
executable, arguments, roots and other environment; it never installs a
default job beside a running custom one. It **refuses** a job that is not
x0xd, and a job without `KeepAlive: true` (a one-shot or conditional job is
not a guaranteed respawn, so declaring it supervised would leave the daemon
down after the upgrade exit). The change takes effect on the job's next load —
`--repair` prints the `launchctl unload`/`load` commands rather than stopping
a running daemon itself. The repair-time check is not the last word: every
apply re-verifies the **loaded** job policy (#615 above), so a `KeepAlive`
removed after repair refuses further upgrades instead of exiting into a job
that will not restart.

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

## Downgrade safety (#451) — Home-Suite group state

v0.40.4 crash-looped on data dirs holding a Home: its decoder rejects the
`owner_certified` admission **variant** (an unknown enum variant is a hard
serde error, unlike an unknown struct field, which is ignored) and exits 1 on
every start — including the upgrade helper's rollback respawn after a failed
health check. The rollback path (steps 5–7 above) could therefore brick an
owned install.

Since #451 the durable group store is split so a pre-Home-Suite binary never
sees a shape it cannot parse:

- **`named_groups.json`** — the legacy-safe view. Every entry whose
  admission is `OwnerCertified` (the auto-provisioned Home and any manually
  created owner-certified group) is written here as an inert PLACEHOLDER:
  default (invite-only) policy, empty roster, GSS plane (so an old binary
  restores no TreeKEM snapshot for it), no secrets — but the identity and
  state-commit chain head (stable group id, genesis, revision/hash) are
  preserved so the id stays reserved and forged lower-revision commits are
  still rejected.
- **`home-suite-groups.json`** — the authoritative sidecar holding the REAL
  owner-certified state (roster with embedded certificates, Home metadata,
  TreeKEM binding). Written before the matching `named_groups.json`
  replacement in every save path, so a crash between writes never leaves a
  Home-Suite entry without authoritative backing. Old binaries do not know
  the file exists.
- **`treekem/<group>.hsjournal`** — crash-recovery journal for the sidecar,
  written BEFORE the sidecar changes inside the atomic TreeKEM persist
  transaction (review r2). A crash between the sidecar write and the
  snapshot/roster writes is healed at startup by replaying it (and the
  legacy journal) — without it, the merged roster could be authoritative
  with a stale/absent TreeKEM snapshot and nothing could repair it. The
  extension is invisible to v0.40.x, whose recovery scan only reads
  `*.journal`; the postcard shape of the legacy journal itself is unchanged
  because old binaries decode the FULL struct before checking its version.
- **Quarantined journals (`<group>.journal.quarantined-<ms>-<seq>` /
  `<group>.hsjournal.quarantined-<ms>-<seq>`)** — the daemon quarantines a
  group's journals aside (never aborts startup, applies nothing, live
  state stands) in these cases, each with its OWN operator procedure:
  1. **Equal-revision fork** — the live merged state and the retained
     journal pair disagree at the same `state_revision` with different
     `state_hash`. To RESOLVE you must pick a side: to keep the LIVE
     state, delete both quarantined files. To keep the JOURNAL state
     instead, stop the daemon, delete the group's live files
     (`named_groups.json` entry, the Home-Suite sidecar entry, the
     `<group>.snap`), rename BOTH quarantined files back to their live
     names (`<group>.journal` / `<group>.hsjournal`), and start — the pair
     then replays (the live state it forked against is gone).
  2. **Mismatched transaction tag** — the `.hsjournal`'s v2 tag
     (group, revision, hash) disagrees with the retained legacy journal's
     record (a retry race). The halves belong to DIFFERENT transactions:
     pick the LEGACY half (it is the commit point) by deleting the
     quarantined `.hsjournal.*` file and renaming only the
     `.journal.quarantined-*` file back to `<group>.journal`; or accept
     the live state by deleting both.
  3. **Undecodable** (`.hsjournal` or legacy `.journal` garbage, or a
     valid envelope with a malformed sidecar body) — this binary can
     never replay these bytes: DELETE the quarantined files to accept
     the live state (renaming them back re-enters the same branch).
  3b. **Body/tag mismatch** (log: "BODY/TAG MISMATCH") — the `.hsjournal`
     body's target record disagrees with its envelope tag (revision,
     hash, or the Home-Suite/plain classification; a retry race or a
     spoofed tag). Renaming back re-enters the same branch: DELETE the
     quarantined files to accept the live state.
  4. **Legacy-only** — no `.hsjournal` exists (the shape every released
     v0.40.x leaves); only the legacy journal is quarantined. SINGLE-HALF
     procedure: to accept the live state, delete the one quarantined
     `.journal.quarantined-*` file. To replay the legacy journal instead,
     delete the group's live state (`named_groups.json` entry + sidecar
     entry + `<group>.snap`) and rename that one file back to
     `<group>.journal` — there is NO second half to restore.
  5. **Split pair** (log: "SPLIT pair"; files: `<group>.journal.
     quarantined-…` plus `<group>.hsjournal.split-<ms>-<seq>`, or — when
     the marker rename itself failed — an UNMARKED live `.hsjournal`
     beside the quarantined legacy, which the daemon PRESERVES as
     split-uncertain) — a quarantine partially completed. To ACCEPT THE LIVE STATE: delete
     both aside files. To RETRY the transaction: delete the group's live
     state files, rename the quarantined `.journal.quarantined-*` file
     back to `<group>.journal`, rename the `.hsjournal.split-*` file back
     to `<group>.hsjournal`, and restart — the paired pass re-runs the
     verdict on the restored pair. (Deleting the aside legacy and leaving
     the `.split-*` file is NOT a retry: the next boot sees no live
     journals and simply keeps the live state.)
  6. **Durability-uncertain** (log: "durability uncertain") — both halves
     are renamed aside but the directory fsync failed; they may revert on
     power loss. Treat as (1)/(2) per the triggering cause.
  A quarantine never REPLACES an existing quarantine file (destinations
  are reserved exclusively). Stale journals (older revision than live)
  are consumed automatically. A v1 (pre-tag) `.hsjournal` with a
  consistent pair — or whose sidecar body simply has no record for a
  plain (non-Home-Suite) group — is REPLAYED, never quarantined.
- **Migration**: a store written by a pre-#451 Home-Suite binary (real
  owner-certified entries directly in `named_groups.json`) is migrated to
  the split layout automatically on the first post-#451 start — no
  unrelated mutation needed — so the downgrade safety below applies to
  existing data dirs from that start onward.

What each binary does on the same data dir:

- **v0.40.x** parses `named_groups.json` (placeholders only — clean parse),
  parses and may replay leftover `treekem/*.journal` bodies (the embedded
  roster is the legacy-safe view), skips snapshots for GSS-plane entries,
  and never reads the sidecar or `home.json`. No exit-1 path remains, so the
  helper's rollback respawn (§5–7) cannot crash-loop.
- **A Home-Suite binary** loads both files and lets each sidecar entry
  REPLACE its placeholder (the sidecar wins); restored owner-certified state
  is quarantined until an evidence-bearing seal re-verifies it.

Downgrade-window semantics: an old binary may rewrite or drop the
placeholder (its map has no Home entry); that is harmless — the sidecar is
authoritative and the re-upgraded daemon restores the real Home, adopting
the same group id rather than duplicating. Changes an old binary makes to
the placeholder are intentionally discarded.

Recovery: a present-but-corrupt sidecar is a hard startup error (never a
silent downgrade of Home security to the invite-only placeholder). Restore
it from backup, or delete it to lose Home-Suite group state and re-provision.

**Release-note caveat (v0.41):** data dirs written by v0.41 open safely in
v0.40.x (the group-store downgrade trap is closed); the old binary merely
sees owner-certified groups as inert unnamed-member shells. Wire-format
caveats from #448/#450 still recommend short mixed-fleet windows.

## CI Integration

`release.yml` generates `release-manifest.json` and `release-manifest.json.sig` via `x0x-keygen manifest` during the release signing job.
