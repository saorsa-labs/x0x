# Self-Update System (`upgrade/`)

Manifest-based decentralized self-update with symmetric gossip propagation.

## Components

- **`manifest.rs`**: `ReleaseManifest` and `PlatformAsset` types, length-prefixed wire format (`[4-byte BE len][JSON][ML-DSA-65 sig]`), platform target detection (including musl vs glibc)
- **`signature.rs`**: ML-DSA-65 signing/verification for archives and manifests. Embedded release public key.
- **`monitor.rs`**: `UpgradeMonitor` polls GitHub releases, `fetch_verified_manifest()` downloads and verifies manifest+signature, returns `VerifiedRelease` with pre-encoded gossip payload
- **`apply.rs`**: `apply_upgrade_from_manifest()` — downloads archive, verifies SHA-256 hash, extracts binary, performs atomic replacement with rollback. Extraction accepts only a regular file whose final path component is exactly the binary name, refuses archives holding more than one such entry, and requires the extracted file to carry the platform's native executable magic (ELF/Mach-O/MZ) (#1144). A `TempDirGuard` (RAII) removes the per-attempt `.x0x-upgrade-*` temp dir on every exit path, including early-return errors, so a failed apply never leaks the downloaded archive.

- **`restart.rs`**: the #261 restart transaction — supervision classification (`RestartMode`), the `upgrade-handoff.json` intent record, the detached handoff helper, and the loud `UPGRADE_FAILED` artifact.
- **`rollout.rs`**: Staged rollout (ADR 0094 §1, #1106): the per-node delay `SHA-256(MachineId ‖ version)` × window, and the persisted wait per release (`<data_dir>/upgrade-rollout.json`). See [Staged rollout](#staged-rollout-1106-adr-0094-1).

### Binary replacement (`mod.rs`)

`Upgrader::atomic_replace` is platform-split:

- **Unix**: `fs::rename(new, target)` — atomic on the same filesystem, valid even when `target` is the running executable.
- **Windows / non-Unix**: a running executable is locked and cannot be renamed over in place. `replace_via_sideline` moves the live binary aside to `<name>.x0xold-<nanos>` (allowed even while locked), moves the new binary into place, and rolls the sideline back if the second move fails. The sidelined file stays locked until the old process exits and is reclaimed on the next launch.

### One binary writer per host (#1106)

Two daemons can share one executable. Every fleet host runs `x0xd` and
`x0xd-443` from `/opt/x0x/x0xd`. Before 0.48.1 both applied the same release
independently, and the second one copied the already-new bytes over the single
`x0xd.backup`, so no copy of the old release was left.

- **Host lock.** The apply takes an OS file lock on
  `<install dir>/.<binary>.upgrade-lock` (for example `/opt/x0x/.x0xd.upgrade-lock`)
  after the restart plan resolves and before the download. It holds the lock
  through the swap and the restart; the OS releases it when the process exits.
  `POST /upgrade/apply` carries the lock, the pre-swap restart plan and the
  backup path into its deferred restart, so no other writer can swap during the
  response window. A second writer waits at most 10 minutes and then fails before
  any change. The lock file is never deleted.
- **Installed-release check.** Under the lock, the writer names the installed
  release of each binary from hash-bound evidence only:
  - the install record `<install dir>/.<binary>.installed.json` (release +
    SHA-256, written after each swap of bytes this updater verified), when its
    hash matches the installed bytes; or
  - the hash of this process's running image: `/proc/self/exe` on Linux;
    elsewhere the executable `x0xd` opens first in `main` (a descriptor keeps
    naming the started image after a rename).

  When these disagree, the bytes are unknown. The release marker that every x0x
  binary from 0.48.1 on embeds (`X0X-RELEASE-MARKER:<version>:END`) is only a
  cross-check: alone it is no evidence, and a marker that disagrees with the
  hash-bound release makes the bytes unknown. Partial or changed bytes match no
  hash, so they are unknown. The companion `x0x` CLI needs its own evidence; the
  daemon's release is never assumed for it. An installed release that is not older than the target is
  refused (`InstalledReleaseNotOlder`): another writer installed it, so there is
  no on-disk downgrade. Unknown bytes (for example a pre-0.48.1 hand copy) are
  refused (`InstalledReleaseUnknown`). The daemon decision runs before either
  binary changes; a refused CLI is left as it is with a WARN.
- **Skip when installed.** Under the lock, when the installed bytes already
  equal the verified binary, the writer does not swap. Another writer on the host
  installed them, so this daemon only restarts onto them.
- **Versioned backup.** The previous bytes are copied to
  `<binary>.backup-<their release>-<first 8 hex of their SHA-256>`, for example
  `/opt/x0x/x0xd.backup-0.48.0-f9149f65`. The release comes from the bytes being
  saved, not from the running version. The copy is fsynced and renamed into place.
  A different file under that name is never overwritten. The companion `x0x` CLI
  uses the same rule (`x0x.backup-<release>-<sha8>`).
- **Retention (D194).** After a swap, each binary keeps: this swap's backup, every
  backup of the release this daemon runs and of the release it ran before it (the
  known-good pair, from the handoff record or the reported upgrade), and the newest
  3 versioned backups. Only older `<binary>.backup-<release>-<sha8>` files are
  deleted; there is no age rule. The legacy `<binary>.backup`, unparseable names and
  operator copies such as `x0xd.v0480-pre0481` are not touched.
- **Disk reserve (D194).** Before the download, the apply estimates its peak space
  (archive, extracted binaries and their backups: 3 × the installed daemon + CLI
  size). It refuses with `insufficient_disk` when staging would leave less than
  1 GiB free on the install filesystem. That is not a failure: the daemon logs it at
  WARN and checks again every 10 minutes; `POST /upgrade/apply` answers
  `insufficient_disk: true`.
- The handoff/intent record `upgrade-handoff.json` names the versioned backup in
  `backup_path`. The daemon no longer writes `<binary>.backup`. A file with that
  name is left from an older release and may be very old: do not restore it.

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

- `<target>.backup-<from_version>-<sha8>` — the exact bytes that were
  serving before the swap, written beside the installed binary (`<target>`).
  The intent file's `backup_path` names it. (Releases before 0.48.1 wrote a
  single `<target>.backup`; see "One binary writer per host" above.)
- `<data_dir>/upgrade-handoff.json` — the intent record: from/to versions,
  `target_path`, `backup_path`, argv, cwd, old pid, API address. On the
  supervised path it also carries `launchd_verified` — the launchd label and
  the per-user session domain (`gui` or `user`) whose **loaded** policy the
  apply-time readback verified; it is `null`/absent on every other path
  (unsupervised, systemd, pre-upgrade intent files). The two launchd domains
  are disjoint, so `domain` tells you which `launchctl print` probe below
  will actually answer for this job — probe that one first. It is a
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
# a job loaded in the per-user domain answers "Could not find service" above;
# probe it there too (the readback itself tries both):
launchctl print "user/$(id -u)/$label" | grep -E 'state =|last exit code|program =|properties ='
cat "$HOME/Library/Application Support/x0x/upgrade-handoff.json"
tail -n 100 "$HOME/Library/Application Support/x0x/x0xd.log"
```

The log line above is the path the `x0x autostart` plist generates: both
`StandardOutPath` and `StandardErrorPath` point at `<data_dir>/x0xd.log`
(`~/Library/Application Support/x0x/x0xd.log`; `x0x-<name>/x0xd.log` for
named instances). A hand-migrated job logs wherever its own plist declares
— read `StandardErrorPath` out of the plist if it differs.

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

systemd (Linux). Two shapes exist:

**Desktop — user unit** (what `x0x autostart` generates):

```bash
systemctl --user status x0xd            # names the exit status, shows restart loop or not
journalctl --user -u x0xd -n 100 --no-pager
cat ~/.local/share/x0x/upgrade-handoff.json
```

**Fleet bootstrap hosts — system units, two per host** (ADR-0011/ADR-0032):
`x0xd.service` (UDP 5483, `ExecStart=/opt/x0x/x0xd --config
/etc/x0x/config.toml`) and `x0xd-443.service` (UDP 443, `--config
/etc/x0x/x0xd-443.toml`, own `data_dir=/var/lib/x0x-443/data` and
`identity_dir=/var/lib/x0x-443/identity`, API on 127.0.0.1:12643 where the
5483 instance uses 12600). Both are `Restart=always` and log to the journal:

```bash
sudo systemctl status x0xd x0xd-443
sudo journalctl -u x0xd -u x0xd-443 -n 100 --no-pager
sudo cat /root/.local/share/x0x/upgrade-handoff.json        # 5483 instance
sudo cat /var/lib/x0x-443/data/upgrade-handoff.json         # 443 instance
```

`Restart=no`/`on-failure` on a unit that exits 0 for upgrades is the same
dead-job state as the missing-`KeepAlive` case above: fix the unit
(`Restart=always`, `sudo systemctl daemon-reload`) before restoring
service. Fleet caveat (ADR-0011): each listener restarts itself at its own
staged-rollout due time (#1106). The first one swaps the shared binary; the
second one finds the bytes installed and only restarts. Until its due time,
`x0xd-443` keeps serving the old image. After a manual restore, restart both
listeners (step 3).

#### 2. Restore the known-good binary

Only needed when the replacement will not start. On Unix a rename over the
installed path is safe even if a copy is still running:

```bash
# <target> is the intent file's target_path (the job's program/ExecStart);
# <backup> is its backup_path, for example /opt/x0x/x0xd.backup-0.48.0-f9149f65
cp -p <backup> <target>.restore && mv <target>.restore <target>
```

Copy, then rename: the backup stays for a second attempt, and a rename over
the target is safe while a copy is still running.

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
# macOS (launchd) — restart the job now (user domain if that is where it lives):
launchctl kickstart -k "gui/$(id -u)/$label"
# ...or, if you edited the plist (e.g. restoring KeepAlive), reload it:
launchctl unload "$HOME/Library/LaunchAgents/$label.plist"
launchctl load "$HOME/Library/LaunchAgents/$label.plist"

# Linux (systemd) — desktop user unit:
systemctl --user restart x0xd
# Fleet hosts: restart BOTH listeners after restoring the binary —
# each listener otherwise restarts only at its own staged-rollout due time:
sudo systemctl restart x0xd x0xd-443
```

#### 4. Verify, then retry the upgrade deliberately

```bash
# desktop (default API address; named instances read <data_dir>/api.port):
curl -fsS http://127.0.0.1:12700/health | head -c 300; echo
# fleet hosts: 5483 instance on 12600, the 443 listener on 12643:
sudo curl -fsS http://127.0.0.1:12600/health | head -c 300; echo
sudo curl -fsS http://127.0.0.1:12643/health | head -c 300; echo
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
   timestamp, and — when the supervision signal was the launchd marker and
   the apply-time readback verified its loaded policy — `launchd_verified`
   with the job's label and the matched `gui`/`user` domain) — captured
   before any exit, and also on the supervised path so a crash loop is
   diagnosable.
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

1. **Startup (background, post-bind)**: after the API listener is bound — and as a non-blocking background task, so an unreachable GitHub never delays API readiness (#1086) — check GitHub for a new release and stage it if found (the startup manifest broadcast is a separate task, run by `broadcast_current_manifest`)
2. **Gossip listener**: Receive manifests on `x0x/releases` topic, verify signature, rebroadcast, stage if newer
3. **GitHub poller**: Periodic fallback poll, broadcast discovered manifests to gossip, stage
4. **`POST /upgrade/apply`** (CLI `x0x upgrade --apply`): authenticated manual request; it stages the release like the other paths, and `?now=true` (`--now`) skips the wait for this host (D185)

Every path verifies a release first and then offers it to the staged rollout below. A release applies only when this node's wait is served.

Every automatic path backs off versions that fail to apply: a failed version is recorded and skipped for 30 minutes before retrying (a newer release supersedes the skip immediately). This prevents a release that can never apply in a given environment from re-downloading and re-extracting on every gossip receipt.

`x0xd --check-updates` is report-only (ADR 0094 §1): it prints whether a newer verified release exists and installs nothing (no binary, no SKILL.md).

## Staged rollout (#1106, ADR 0094 §1)

A node does not apply a verified release at first receipt. It waits:

```text
delay = SHA-256(MachineId ‖ version)[0..8] as u64 × window_secs / 2^64     (in [0, window))
```

- `window` is `[update] rollout_window_minutes`. The compiled default is **60**
  (D183). The fleet default and minimum are 60 (D184); the fleet inventory check
  enforces that minimum, not the daemon. Private rehearsal hosts may set `0`,
  which applies on first receipt.
- Different nodes get different delays for one release, and the version salt
  changes the order for each release. A permanent early ring is M4 work.
- The wait starts at this node's first eligible receipt, so discovery lag adds to
  the window (#1169).
- `<data_dir>/upgrade-rollout.json` keeps, per release: the first trigger and
  receipt time (diagnostic), the window, the chosen delay, the served wait and
  any `now=true` bypass (who asked, when). The file is versioned JSON
  (`"format": "x0x.upgrade-rollout"`, `"version": 1`) and is written with a record
  barrier (temp file, fsync, rename, directory fsync). A duplicate receipt or a
  restart keeps the delay and the served wait. The delay is a pure function, so
  it cannot re-roll. The wait is counted on the monotonic clock while the daemon
  runs and checkpointed every 30 s; time while the daemon is stopped does not
  count, and the wall clock never decides the due time. A changed window gives the
  delay for the new window and keeps the served wait.
- **Unreadable state fails closed (ADR 0094 §6).** When the file cannot be read or
  parsed, or has another format or a newer version, the daemon starts and serves
  normally but applies nothing: every trigger, `now=true` included, answers
  "blocked", and the file is kept byte for byte (one WARN at start; the HTTP answer
  says `blocked: true`). Repair: run a binary that reads that format, or move the
  file away (`mv <data_dir>/upgrade-rollout.json <data_dir>/upgrade-rollout.json.bad`)
  and restart; the wait then starts again.
- While a node waits it downloads and replaces nothing. A waiter task applies
  the release when the wait is served. A newer release supersedes a waiting one,
  also after a restart: the newest staged release in the file is the active one,
  and an older manifest that arrives first is not staged.
- `POST /upgrade/apply` (CLI `x0x upgrade --apply`) also waits. While the node
  waits it answers `{"ok": true, "applied": false, "staged": true, "reason": …,
  "version": …, "delay_secs": …, "remaining_secs": …, "window_minutes": …}`, and
  the daemon applies the release when the wait is served.
- **`now=true` (D185).** `POST /upgrade/apply?now=true` (CLI `x0x upgrade --apply
  --now`) skips the wait for this host only. It keeps eligibility (signature, age,
  newer), holds and every install check (host lock, installed release). On a shared
  install it also skips the other participants' waits, so it moves every daemon on
  that install early. A configured hold always wins: a participant with
  self-update off or a blocked rollout state, an unreadable record, and an
  unregistered live daemon still stop the swap. When such a hold makes the request
  wait, the retry keeps the bypass. The rollout state and the WARN summary line
  record the bypass and who asked.
- A due apply keeps the #1196 behaviour on every trigger: when the only refusal
  is an unaged systemd start-rate window, it waits that window out and retries
  once. Each attempt rechecks, under the in-process apply lock and before any
  download, that its release is still staged, due, not superseded by a newer
  staged release and not blocked; otherwise it is cancelled.
- **Shared installs wait for every participant (ADR 0094 §1).** Each daemon that runs
  from the install keeps a record in `<install dir>/.<binary>.participants/<key>.json`
  (key = first 16 hex of SHA-256 of its data dir): MachineId, data dir, pid,
  running version, whether its self-update is on, the active staged release with
  its delay, remaining wait and due flag, and any blocked state. Records are
  written, refreshed (every 5 minutes and at each stage and checkpoint) and removed
  only under the host lock, so the set cannot change while a writer holds the lock;
  a daemon that starts during another daemon's transaction registers when that
  transaction ends. Under the host lock, a due daemon swaps the shared binary only
  when every live participant runs the release or has staged it with its wait
  served. Otherwise it waits (`ParticipantsNotDue`, not a failure) and checks again
  every 30 s; the HTTP answer lists `pending_participants`.
  - *Self-update off.* A daemon with self-update off (`--skip-update-check`,
    `[update] enabled = false`) stays a participant (with its rollout-state block,
    if any). That is a configured hold: the shared swap waits while it runs, and
    `now=true` does not skip it. Turn its updates on and restart it, or stop it.
  - *Stale participant.* A record not refreshed for 30 minutes (a removed or
    long-stopped daemon) does not block; the writer logs it at WARN before the swap.
    Delete the file of a daemon that is gone.
  - *Not established.* Until its record is written, a daemon holds a shared lock on
    `<install dir>/.<binary>.unregistered-lock`; a daemon whose registration keeps
    failing holds it for its whole life (and logs WARN). While any daemon holds it,
    or while this daemon's own record is missing, no writer swaps, in any mode. When
    the directory or a record cannot be read, or a record is of another format, the
    swap is refused (`ParticipantsUnknown`, WARN).
  - *Shared accounts.* Registry files get the install directory's sharing,
    independent of the umask: on a group-writable install 0o2775 directories and
    0o664 files with the install directory's group (also an existing participants
    directory, when its owner writes next), else 0o755 and 0o644. The host lock
    also works through a read-only lock file.

### Upgrade log lines

Fleet units run `RUST_LOG=warn`. Two WARN lines record a self-update:

- Before the restart: `x0xd self-update applied: <from> -> <to> via
  <startup|gossip|poll|manual> (sender <agent hex | local API (durable token) |
  unknown>, staged delay <n>s <served|bypassed by now=true>, swap
  <performed|already_installed>, backup <path>, exit
  <supervised_exit(code=0)|transactional_handoff|deferred_restart(…)>)`.
- At the next start: `x0xd upgraded from <from> to <to>`, from the existing
  `upgrade-handoff.json`. It is written once per handoff transaction (the reported
  transaction is kept in `upgrade-rollout.json`), so a crash loop does not repeat it.

Every other upgrade step stays at INFO or DEBUG.

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

### Contributor fixtures (ADR 0094)

`upgrade-test-signing` is a test-only feature, off by default. It replaces the
compiled release public key in debug builds and is a compile error without
`debug_assertions`. It never adds a second trusted key or accepts a runtime key
override. The signing context, gossip framing and verification of the original
manifest/archive bytes remain unchanged.

For each private rehearsal, generate a fresh throwaway keypair with
`x0x-keygen generate` on the isolated Linux test plane. Set
`X0X_UPGRADE_TEST_PUBLIC_KEY` to its public-key file **at build time**, and build
the debug candidate and companion with `--features upgrade-test-signing`.
The build script validates and copies that public key into `OUT_DIR`; compiled
binaries do not read this environment variable. Without a supplied public key,
an all-features lint/doc build generates a fresh key and discards its secret.
`--all-features` explicitly enables the seam; ordinary `just build` and
`just build-release` list the existing application features and keep the
production key.
Keep private keys and fixture binaries on the isolated test plane; never
publish them or gossip their manifests to production.

Both `x0xd` and `x0x` support the inert contributor check
`--verify-release-manifest MANIFEST SIGNATURE`. It reads the two files and
verifies their original bytes with the compiled key, before runtime, identity,
configuration, logging or network initialization. Success exits 0; rejection
exits nonzero. It neither installs an update nor selects a different key.

Systemd acceptance fixtures require a private loopback-only network namespace,
non-root identity, empty capability sets and `no_new_privs`. Each child and
respawn samples and validates these facts before fixture work; runners also
validate each child's receipt. A missing or unsafe observation fails the gate.
