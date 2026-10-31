# Self-Update System (`upgrade/`)

Manifest-based decentralized self-update with symmetric gossip propagation.

## Components

- **`manifest.rs`**: `ReleaseManifest` and `PlatformAsset` types, length-prefixed wire format (`[4-byte BE len][JSON][ML-DSA-65 sig]`), platform target detection (including musl vs glibc)
- **`signature.rs`**: ML-DSA-65 signing/verification for archives and manifests. Embedded release public key.
- **`monitor.rs`**: `UpgradeMonitor` polls GitHub releases, `fetch_verified_manifest()` downloads and verifies manifest+signature, returns `VerifiedRelease` with pre-encoded gossip payload
- **`apply.rs`**: `apply_upgrade_from_manifest()` — downloads archive, verifies SHA-256 hash, extracts binary, performs atomic replacement with rollback. Extraction accepts only a regular file whose final path component is exactly the binary name, refuses archives holding more than one such entry, and requires the extracted file to carry the platform's native executable magic (ELF/Mach-O/MZ) (#1144). A `TempDirGuard` (RAII) removes the per-attempt `.x0x-upgrade-*` temp dir on every exit path, including early-return errors, so a failed apply never leaks the downloaded archive.

- **`restart.rs`**: the #261 restart transaction — supervision classification (`RestartMode`), the `upgrade-handoff.json` intent record, the detached handoff helper, and the loud `UPGRADE_FAILED` artifact.
- **`journal.rs`**: private M2 record formats, bounded readers and record barriers. Unknown, corrupt or pending M2 records block apply and preserve recovery material. Reading a record does not authorize recovery.
- **`probe.rs` / `probe_retry.rs`**: candidate execution checks, install-scoped release holds and bounded interrupted retries before replacement.
- **`rollout.rs`**: Deterministic delay calculator salted with the MachineId and release version.

### Rollout defaults and delay bounds (M2 S2b)

The compiled daemon configuration defaults to a 60-minute rollout window
(D183). An omitted update section or window has the same default. The
calculator selects a whole-second delay strictly below a positive window,
using the leading 64 bits of the hash and integer arithmetic. It preserves
the zero-window calculator behavior. A minute value too large to represent
in whole seconds uses `u64::MAX` seconds as the effective bound.

The Unix startup, gossip, fallback and HTTP apply paths record the first
eligible release beside the canonical installed binary. The private
`upgrade-rollout-<digest>.json`
receipt binds the actual data and identity roots, MachineId, release version,
verified manifest digest and archive digest. Duplicate delivery, restart and
later window changes retain the first choice. Monotonic elapsed time reduces
the wait; a reboot keeps the last durable remainder and starts a new clock
epoch. Wall-clock changes do not supply elapsed time.

Each waiting operation releases the apply mutex and install lock.
It waits before writing release content or starting candidate probes, and
rechecks the receipt and unresolved upgrade records under the install lock.
Each observation requires a successful record barrier, including a receipt
that already says the delay is complete. Unknown or damaged records remain
in place and refuse this apply; they do not block normal daemon startup.
Shutdown or loss of the task cancels work before mutation admission.

After a guide download, startup resolves the install again and rechecks the
current staging and probe state under that install's lock. It holds the lock
through the guide write and rename. A hold recorded before this admission
keeps the prior guide. This does not defer an admitted guide update to host
commit; transaction-bound guide promotion remains separate work.

The compiled deployment inventory sets a minimum 60-minute window for a
known or ambiguous production fleet install. An existing receipt below that
minimum refuses apply and remains intact. Ordinary installs retain an
explicit zero window. Only the compiled debug test key permits the fleet
rehearsal exception.

For an undersized fleet receipt, keep the configured binary in normal
operation. Preserve the receipt and any selection or pending records, with
their hashes. Changing the window or restarting does not reset the receipt.
Do not edit or delete it to remove the refusal.

To continue, use the normal verified Unix startup update path when a strictly
newer eligible stable release is available. That release must pass all current
guards and must not have its own undersized or conflicting receipt. A new
receipt records a window of at least 60 minutes; its calculated delay can be
zero. The old receipt remains unchanged. This is progression to another
release, not repair of the refused release. If no eligible release is
available, or unresolved selection, journal, pair or probe state still blocks
apply, keep the current binary running and retain the evidence for supported
recovery. This slice provides no command to clear these records.

Selecting a newer eligible release requires a durable supersession record.
An older waiter cannot then apply its release. The previous receipt remains
intact; supersession does not delete it or reset the selected release's wait.

This staging gate accepts canonical stable versions only. Setting
`include_prereleases` does not allow a prerelease through the gate.
The private `upgrade-selection-<digest>.json` record and its `.pending`
marker retain the selected release and evidence of an incomplete write.
An unresolved marker or damaged record refuses apply. The configured binary
still starts normally.

If this refusal occurs, preserve the selection record, pending marker and
bound rollout receipt, with their hashes. Check the recorded participant
roots, release version and digests. Investigate any storage or sync error
before attempting recovery. Keep the configured binary in normal operation
while apply remains refused. This slice provides no selection-record repair
command. Do not delete records or edit their fields to bypass the refusal.
Complete transaction recovery remains separate M2 work.

Gossip and fallback discovery share one bounded pending release and continue
to receive announcements during a wait. The worker drains a superseded
operation before starting the newer release. Cancellation is checked after
the install lock is acquired, before queued work can write records.
An admitted replacement retains its restart continuation.

If staging identity initialization fails, background apply stays disabled
for that process. Configured release discovery and verified rebroadcast
continue without an apply owner.
The background owner updates the guide only after staging permits the release.
Without that owner, these sources leave the installed guide unchanged.

HTTP allows one waiting request and retains its deferred restart owner after
mutation admission. Dropping a waiting request cancels its permit. Queued or
running blocking work, including service-manager readback, retains that
request's capacity slot until the worker exits.
Each request keeps the release and verified manifest found before its staging
wait. Later policy checks can refuse that release. The request does not select
a newer release during the wait.

`x0x upgrade --apply --now` sends authenticated
`POST /upgrade/apply?now=true` (D185). It skips only the staging component of
the wait. Receipt barriers, fleet history, supersession, eligibility, holds,
mandatory probe retry waits and transaction checks still apply, including
the final check under the install lock. It does not write a zero-window
replacement receipt. The CLI uses no total apply-request timeout, with
connection setup bounded to 30 seconds.

Shutdown closes background intake and withdraws pre-admission writes; it does
not claim every blocking operation is reaped before shutdown returns.
Complete host inventory and transaction-bound guide installation remain
separate M2 work. These staging controls do not establish a protected host
transaction or authorize guide promotion at host commit.

### CLI check and a split install (#1104)

`x0x upgrade --check` prints this CLI version. It calls `GET /health` on
the local daemon selected by `--api`, or by `--name`, or on the default
instance when neither is set. The address is the same discovery other CLI
commands use, including `127.0.0.1:12700` when no port file exists. The
request stays on loopback and does not use a proxy. `--check` still completes
when no daemon answers. `--check --force` fetches the current release and
compares semver. It prints "Update available" only when that release is
strictly newer than this CLI. An equal, older or unparseable release is not
an update.

The check compares this CLI with the executable of that running daemon.
It canonicalizes both paths, so a symlink to the CLI is not a split install.
A CLI in `~/.cargo/bin` is reported when the running `x0xd` is in another
directory, even if `~/.cargo/bin` also contains `x0xd`. The executable is
read from that instance's process. The daemon does not report its path.
When the executable cannot be read, the check says that it cannot tell.
It does not warn in that case.

The daemon apply replaces `x0x` only when that file is in the same directory
as the running `x0xd`. After `x0x upgrade --apply`, this CLI prints
"CLI not upgraded" and a reinstall hint when its own file is not beside that
daemon and its version is older than the version the daemon applied. The CLI
prints that notice on stderr, after the unchanged apply response. The hint is:

```text
cargo install x0x --bin x0x --force
```

That command installs only the `x0x` CLI. It does not replace `x0xd`.
`scripts/install.sh` has no CLI-only mode, so the hint does not call it.
The same check prints that hint only for an older CLI that is apart from the
running daemon. It does not also print `x0x upgrade --apply`. A CLI beside
that daemon at a different version does not get the hint. Apply still
replaces that sibling. `x0x --name <instance>` and `x0x --api <address>`
select that daemon for `--check` and `--apply`.

A daemon apply that finds no sibling `x0x` records that the file is missing
at debug level. It does not warn. `POST /upgrade/apply` and `x0x doctor` do
not carry a companion status field. The CLI does not replace itself.

### Candidate execution probes (M2 S2d)

Both packaged binaries accept `--upgrade-probe` as their first argument.
The command prints JSON with the compiled `version` and `platform`, then exits.
It runs before profiling and normal application initialization. It reads no
configuration, takes no application lock, opens no store or socket, creates
no identity, runs no artifact sweep and increments no boot counter.

On Unix, automatic apply probes both extracted binaries before either
installed binary changes. This includes the packaged CLI when the installed
CLI is outside the managed install. A missing packaged executable refuses
the apply. Each staged file and its parent directory must complete their
sync barriers before either child starts. The child uses the captured working
directory and environment and inherits the old process's service account.
The check requires exit zero and the exact release version and platform.
It limits each execution to 90 seconds, bounds output and kills and reaps a
failed or timed-out child. A passing probe proves execution in that context;
it does not prove later health or a successful pair transaction.

The canonical installed daemon has a private adjacent record, normally
`x0xd.upgrade-probe.json`. Different instance data roots share this install
record and its lock. A loader error, nonzero exit, malformed response,
version/platform mismatch or changed candidate bytes holds that release.
Another archive for the same version cannot bypass the hold. A newer release
can clear a known failed-release hold; it cannot clear recovery-failed or
unknown state.

A durably recorded timeout or host fault permits at most three fresh retry
transactions, after 30, 60 and 120 minutes. Retry timers release the apply
mutex, observe daemon shutdown and reread the record before each attempt.
HTTP apply includes an existing interrupted retry wait in its staging gate,
even with `now=true`. A new probe failure still returns its refusal and leaves
retry ownership with the daemon. Startup and background discovery can resume
a pending wait after verifying the release manifest again. Boot identity and
monotonic time prevent a wall-clock change or daemon restart from shortening
the recorded wait.

Before a terminal record write, a durable
`x0xd.upgrade-probe.json.pending` marker retains the prior record. It is removed
only after the outcome's record barrier succeeds. A retained marker, an
unknown/corrupt record, or a `running` record without a durable outcome refuses
further apply, including a newer release. The last case cannot distinguish a
lost failed-hold write from an interrupted probe, so it requires manual
inspection instead of an automatic retry. Preserve both files and their
hashes, investigate the storage fault and use a supported repair procedure;
do not delete the marker or edit a phase to bypass the refusal. The configured
binary still starts normally.

Managed Windows apply remains refused by the restart planner. Unmanaged
Windows keeps its released legacy apply behavior and does not claim these
Unix M2 durability/probe guarantees. The inert flag works on both binaries
on Windows as well.

### Binary replacement (`mod.rs`)

`Upgrader::atomic_replace` is platform-split:

- **Unix**: `fs::rename(new, target)` — atomic on the same filesystem, valid even when `target` is the running executable.
- **Windows / non-Unix**: a running executable is locked and cannot be renamed over in place. `replace_via_sideline` moves the live binary aside to `<name>.x0xold-<nanos>` (allowed even while locked), moves the new binary into place, and rolls the sideline back if the second move fails. The sidelined file stays locked until the old process exits and is reclaimed on the next launch.

At startup, `x0xd` checks recovery records before it calls
`sweep_stale_upgrade_artifacts(dir, min_age)`. Unknown, unreadable, corrupt or
pending M2 records suppress the sweep. A valid legacy-only handoff permits
the sweep unless its target or backup path matches a cleanup pattern.
The sweep removes `.x0x-upgrade-*` directories and `*.x0xold-*` sidelined
binaries only after the same age gate (`min_age`, normally one hour).
It must not remove retained recovery material to make startup succeed.

### Recovery-record diagnosis (M2 S2a)

The reader checks these three names in the effective instance data directory:
`upgrade-journal.json`, `upgrade-handoff.json` and `upgrade-boot.json`.
M2 records carry `schema_version: 1` and a `record_kind` of `journal`,
`handoff` or `boot`. They record transaction state for later M2 slices.
S2a does not activate launcher recovery or turn a parsed record into authority
to swap, restore or start a child.

On Unix, a new legacy handoff keeps all released fields and adds
`schema_version: 1` and `record_kind: "legacy_handoff"`. Released readers
ignore those additional fields. Both the old unversioned form and this
marked form remain diagnostic intent. The unmanaged Windows helper keeps the
unversioned form; this compatibility path makes no M2 directory-durability
claim. The existing Windows managed refusal is unchanged.

Unix record writes require a file sync, replacement rename and parent
directory sync. A failed barrier is a refusal, not an acknowledgement.
The applying daemon checks directory-sync support before download or swap.
If the filesystem rejects it, use an operator-managed update after resolving
the storage fault; do not bypass the failed barrier. Configured startup still
works.

For an unknown or damaged record, the configured daemon starts normally.
It reports `unprotected/degraded` through the existing `/health` upgrade
input and reasons. Apply and automatic recovery take no action, and cleanup
keeps the artifacts. Restarting alone does not clear this condition.

Use this procedure to investigate and resolve the condition:

1. Find the effective data directory, executable paths and roots from the
   loaded job and configuration. Inspect `/health` and the local startup log.
   A record can contain old or invalid paths; do not use it as the authority
   for a restore or a command to execute.
2. Keep the original records and candidate/backup files. Save byte-for-byte
   copies and hashes in an operator-owned private evidence directory before
   making changes. Record contents can include launch arguments and environment.
   Keep automatic apply disabled during maintenance.
3. For an unknown schema, use a release or repair tool that supports that
   schema. Do not change the version marker, truncate the record or delete it
   to permit another apply. If no supported reader is available, retain the
   degraded state and pass the evidence to the release owner.
4. For corruption, reconcile every job sharing the install, including stopped
   jobs, against independent service inventory. Check the actual daemon and
   CLI hashes against trusted release or backup bytes. The operator must
   repair the failed action and establish a consistent installed pair before
   resolving intent. S2a provides no automatic record-repair or clear command.
   Preserve the damaged bytes and record the repair and verified hashes.
5. Only a known, resolved legacy-only handoff can use the manual procedure
   below. Keep an evidence copy before clearing that stale diagnostic.
   Unknown or M2 records require their supported repair procedure. After
   repair, check the configured roots, running versions and `/health` upgrade
   reason before deliberately enabling apply again.

### Dormant pair transaction (M2 S2e)

The private pair engine is implemented and tested, but no live apply path calls
it yet. Activation requires the S2c host inventory and the S3a acknowledged
flush, whose daemon-side owner and arm-and-flush control listener now exist
(see [Acknowledged shutdown flush](#acknowledged-shutdown-flush-supervised-exit)
below); launcher-coordinated host transactions remain the missing piece.
The current apply path still uses its existing single-binary replacement flow.
Do not infer pair rollback or launcher protection from this dormant module.

The engine checks a verified release plan and durable passing probes under the
existing daemon and managed-CLI install locks. It checks the installed hashes
again before mutation. It copies each old binary beside its target, using that
binary's prior version and a transaction ID in the backup name. It keeps every
referenced backup and reserves the copy/restore space plus 1 GiB per filesystem.

Each daemon and CLI swap has separate intent, file and progress barriers. A
healthy OLD process can restore both members after a failed swap. Restoration
copies the backup and retains the original rollback bytes. A separate writer
cannot start another transaction while the first remains unresolved.

Private records use `<daemon>.upgrade-pair.json` and
`<daemon>.upgrade-pair.pending`. Resolved predecessor records are retained under
their transaction IDs. Every archive retry repeats its durability barriers.
Unknown or corrupt records and uncertain barriers preserve all evidence and
refuse pair actions. These records alone do not authorize process recovery,
child start, host commit or a storage-format change.

A split CLI remains untouched and is reported with a reinstall hint. Signed
SKILL content is copied to a transaction-specific staging file. The active
SKILL remains unchanged. A later installer must enforce the applicable gate:
host commit on protected paths, or matching candidate bytes and stable local
health on unprotected paths under D195. It must retain the prior guide.

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
  and points at the manual recovery procedure below. After a successful
  replacement, the daemon must commit an acknowledged shutdown receipt before
  it exits 0 (100 on Windows) for the supervisor to re-exec the new bytes.
  It launches **no** helper. A *missing TTY* is **not** supervision —
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

### Acknowledged shutdown before supervised exit

A supervised apply needs a live shutdown-flush owner before it downloads or
replaces bytes. If the owner is unavailable, the apply fails closed. The exit
and owner slices of the #1374 stack must land together before a release; an
intermediate build without the owner cannot perform a supervised update.

Before replacement, the apply reserves shutdown admission under the same lock
that ordinary shutdown uses. If replacement fails or rolls back before an
acknowledgement starts, the unused reservation is released. Later upgrades can
try again. An ordinary shutdown already waiting on that reservation can finish,
and its admission stays closed. A started acknowledgement keeps recovery custody
if it fails; an unused reservation cannot release that custody.

After successful replacement, the daemon writes the handoff intent and requests
a bounded shutdown flush. The owner drains producers and completes the store,
cache and log barriers before the receipt is committed. HTTP connections that
miss the 2 s drain bound are aborted, not waited on: an abort does not join
request-owned blocking writes (ADR 0094 §4), so the flush receipt is refused
while the ordinary-shutdown exit stays 0 (#261/#363). The persisted record contains the
restart-plan binding, boot ID and fixed deadline. The log barrier keeps admission open
so a failed flush does not close the old process's log sinks. A transient dropped
line fails its barrier window; it does not poison every later barrier.

The instance data directory retains three private diagnostic records:

- `upgrade-flush.json` records the intent and, on success, the receipt ID.
- `upgrade-flush-rollback.json` records a flush that stopped the daemon and
  then failed. A late worker cannot erase this separate failure record by
  writing a receipt.
- `upgrade-flush-hold.json` holds the release whose started flush failed, so
  the restart loop after `EX_TEMPFAIL` cannot re-apply it.

A flush timeout, receipt-write failure or binding failure does not authorize
the supervised exit. A flush that started — the daemon actually stopped
behind the hook — and then failed or overran restores every binary the
transaction swapped and exits
`EX_TEMPFAIL` (75) for a service-manager restart on the old version.
A refusal before the stop keeps the daemon serving. It restores only when
this call owned admission; a duplicate or competing request changes nothing.
The ownership and recovery rules are described under
[Acknowledged shutdown flush (supervised exit)](#acknowledged-shutdown-flush-supervised-exit)
below, together with the startup cleanup that clears a receipt-less record or
rollback marker whose owning process is gone. Do not apply the legacy
handoff deletion procedure below to flush records while the daemon runs; the
documented manual fallback stops the daemon first.

### What a successful apply does and does not prove

Installed bytes, a pending restart, observed readiness and recovery are four
distinct facts, and the apply logs report them separately. A supervised exit
is a **restart request** to the service manager — not health acceptance, and
not an automatic rollback. Recovery on the supervised path is the operator's
[manual recovery procedure](#manual-recovery-after-a-failed-supervised-upgrade-adr-0061-6);
only the transactional handoff observes
`/health` and restores the backup itself.

### Manual recovery after a failed supervised upgrade (ADR-0061 §6)

On the supervised path, the daemon installs the new bytes, writes the intent
record and commits the acknowledged shutdown receipt before it requests the
service-manager restart. A failed flush restores the previous binary and
exits `EX_TEMPFAIL`, as described above. After the supervised exit, x0xd
**never** rolls the installed bytes back automatically — recovery is this
manual procedure, run by
the operator who owns the service manager. That is deliberate: a second,
self-appointed restarter beside the manager is the #493 duplicate-daemon
bug this design exists to prevent.

The scenario: a migrated/supervised job took the supervised exit, the
replacement failed to start, and the daemon is now down. Keep the flush records
above with these two recovery artifacts:

- `<target>.backup` — the exact bytes that were serving before the swap,
  written beside the installed binary (`<target>`).
- `<data_dir>/upgrade-handoff.json` — the intent record: from/to versions,
  `target_path`, `backup_path`, argv, cwd, old pid, API address. On the
  supervised path it also carries `launchd_verified` — the launchd label and
  the per-user session domain (`gui` or `user`) whose **loaded** policy the
  apply-time readback verified; it is `null`/absent on every other path
  (unsupervised, systemd, pre-upgrade intent files). The two launchd domains
  are disjoint, so `domain` tells you which `launchctl print` probe below
  will actually answer for this job — probe that one first. It is a
  *diagnosis record*, not state the daemon needs to boot.

These steps apply to a valid legacy handoff, including the Unix
`schema_version: 1`, `record_kind: "legacy_handoff"` form. For an unreadable,
unknown or M2 record, use [recovery-record diagnosis](#recovery-record-diagnosis-m2-s2a)
above. Do not apply the stale-legacy deletion step to those records.

`<data_dir>` is the instance's data directory —
`~/Library/Application Support/x0x` on macOS (`x0x-<name>` for named
instances), `~/.local/share/x0x` on Linux. Confirm the target and backup paths
against the loaded job and the actual installed files. Note that `UPGRADE_FAILED` is **never**
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
service. Fleet caveat (ADR-0011): the self-updater restarts only
`x0xd.service` — after any upgrade, restored or successful, restart
`x0xd-443` too or it keeps serving the old image.

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

After verifying the running version and resolving the legacy attempt, keep an
evidence copy and remove the stale legacy diagnostic from its active name.
Do not use this command for an unknown, corrupt or M2 record:

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
# x0xd-443 is not in the updater's restart set (ADR-0011):
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


### Acknowledged shutdown flush (supervised exit)

Before a supervised exit requests its restart, the daemon waits for an
acknowledged flush of its durable state: the flush owner stops the API and
the Agent, joins every server producer, walks and fsyncs the data and
identity roots, flushes the captured logs, and only then publishes a receipt
(`upgrade-flush.json` with a `receipt_id`). A fired shutdown hook,
cancellation or a port release is never proof of flush (ADR 0094 §4).

The flush budget is fixed at 30 seconds (engineer ruling, 23 Oct 2026). It
is an internal constant, not configuration; only tests override it. A
follow-up issue proposes making it operator-configurable — the public
config surface needs David's go. When the budget expires, the daemon's
`EX_TEMPFAIL` exit can cut the flush worker mid-write (inside a store's
`sync_tree` or the log flush), so every durable store the flush walks must
already be crash-safe: a torn or missing final write must recover to a
consistent state at the next start.

Failure behaviour (engineer ruling, 23 Oct 2026, refusal handling revised
24 Oct 2026): a flush that started and then failed or overran its budget
must not leave the daemon running with no API and no network. "Started"
means the daemon actually stopped behind the hook — the recovery begins at
the moment the hook commits the daemon to stopping, nothing earlier. The
daemon persists a per-release failed-upgrade hold
(`upgrade-flush-hold.json`, below), restores every binary the transaction
swapped, logs the cause, and exits `EX_TEMPFAIL` (75). Every backup is
verified before the first rename, and a missing backup restores nothing; a
rename that fails after an earlier rename succeeded can still leave the
daemon and the `x0x` CLI on mixed versions — that state is logged for
manual recovery, not silently accepted. After the renames, every directory
that received a restored binary is synced, so the old version is back on
disk even after a power loss immediately following the exit. After a
complete restore, the service manager restarts the daemon on the old
version. A partial restore needs manual recovery. An error after the flush
completed (for example a receipt that fails authorization) also ends in
`EX_TEMPFAIL`; nothing is restored because the new bytes are already
durable.

Both started-failure exits are immediate. The supervised-exit path calls
the exit directly after its recovery. On the local arm-and-flush path, the
control listener writes the error reply to the launcher first, then exits
`EX_TEMPFAIL` from its own loop (issue #1595, Claude #1566 finding 1): it
no longer waits for the server shutdown tail to reach the flush finish, so
a shutdown that hangs behind an already-stopped daemon cannot park the
process with the supervisor waiting forever.

A started failure caused **only** by unfinished producers at the drain
bound — the receipt refusal `finish` reports when an HTTP request, a grace
straggler or a shielded apply missed its bound — is transient, so it draws
a fixed bounded retry budget before the per-release hold (issue #1595,
Claude #1565 finding 4): two retries per release, counted in
`<data_dir>/upgrade-flush-producer-retries.json`, a constant, not
configuration. Each such failure still restores and exits `EX_TEMPFAIL`;
the difference is that no hold is written for the first two, so the
service-manager restart retries the release instead of parking the host on
one slow request. The third failure of the same release writes the hold.
A failure of a different release resets the count; any other failure
cause never touches the budget and holds immediately, as does a count
that cannot be persisted.

Before either exit, the flush waits one short fixed window (2 s) for the
flush worker's completion message after a started failure: receiving it
proves the worker's last durable write finished (issue #1595, bounded
rollback-writer join). The exit continues when the window expires — a
stalled worker must never park a daemon that already stopped. The rollback
record itself is written on the calling thread, before this wait, so the
exit can never lose it.

For a started failure on the local arm-and-flush path, the host journal
first records `rolling_back` with a flush-failure cause. Only then does the
daemon restore bytes. A complete restore records `restored`, clears each
restored artifact's `swapped` flag, sets its `restored` flag, removes
`upgrade-handoff.json`, and archives the journal as `upgrade-failed-<uuid>.json`.
After the exit-75 restart, the active journal no longer blocks apply. The
failed-release hold stays: the same or older release is refused, but a newer
release can apply (Engineer ruling, 24 Oct 2026 05:17/05:18 BST).
If restore fails, including a part-way rename failure, the active journal
stays at `rolling_back`; apply remains blocked for manual recovery. A
cleanup failure also retains active recovery records and blocks apply.
Failure exits allow up to one additional second to flush the log worker;
a failed log barrier is reported to stderr before exit.

A request that does not own flush admission never restores binaries, clears
intent, or disarms another request. This includes a missing flush owner,
`already armed`, `already started`, and a reservation that does not own
admission. A duplicate arm after a receipt leaves the installed bytes and
receipt unchanged (engineer ruling, 24 Oct 2026).

An owned refusal before the stop commit point (an unresolved predecessor,
a failed intent or handoff write, or a deadline overrun before the hook
commits the stop) is not a failed start. The daemon keeps serving. The arm
handler holds admission while it marks its host journal `rolling_back`, restores the swapped files,
and records `restored` with the swapped flags cleared. It removes only the
handoff this attempt wrote, then retains the resolved journal under
`upgrade-refused-<uuid>.json`. The active journal path is cleared so a later
apply can run; replaying the old arm cannot acknowledge the restored bytes.
An existing handoff is preserved and refuses preparation. A restore or
cleanup error retains the active journal and blocks apply for manual
recovery. A rename failure can still leave a mixed pair, as described above.

After an owned refusal, the flush clears its own receipt-less intent and
releases admission. No failed-release hold is written: a resolved refusal
permits retry on the next normal update cycle. An ordinary shutdown after a
refusal uses its normal exit code. The production hook marks the stop commit
point before sending either shutdown signal. The deadline check and stop
commit share the waiter's cancellation lock. A timed-out refusal cannot
stop later or publish a late receipt-less intent record.

The flush walk refuses any symlink under the data root or the identity
root (`~/.x0x` by default): a symlink is not a verified store root, and its
target is not walked or fsynced. The refusal names the offending path, in
the flush error and in the logs, so the operator can find and remove it
(issue #1595). The same refusal surfaces **before** an upgrade is
attempted: flush admission runs the same walk — metadata only, no fsync —
over the exact roots the flush will walk, and a supervised apply is
refused with the offending path before any byte changes. A symlink an
operator put there therefore stops the next upgrade attempt up front,
loudly, instead of failing the flush after the daemon already stopped; the
failed-upgrade hold keeps the restart loop from re-applying a release
whose flush did fail that way. `x0xd --doctor` does not yet run this
check; the admission refusal is the diagnostic surface today.

The local control listener is a Unix socket, `upgrade-flush.sock` in the
data directory, mode `0600`. It accepts one JSON request line carrying the
API token, the transaction ID, generation, instance ID and frozen plan, and
answers `{"receipt": …}` or `{"error": …}`. The daemon-side listener exists
and is authenticated; the client that drives it belongs to later stack
work. David approved this local control API on 23 Oct 2026 at 16:52 BST;
its API and framing remain as approved. Permissions are set on the socket
path before the listener accepts requests, without a process-wide umask
change. The API token is checked even for a connection queued during bind.
A very long data-directory path can exceed the Unix socket path limit (104 bytes on macOS); the bind then fails and supervised
apply is disabled with a WARN in the log.

#### Stale flush records

If the daemon is killed mid-flush (for example SIGTERM during the flush
window trips the 5 s exit watchdog), `upgrade-flush.json` may survive
without a receipt, and `upgrade-flush-rollback.json` may survive from the
failed attempt. At the next startup — after the new process holds the
instance data-root lock, which proves the flush's owning process is gone —
the daemon clears this debris, logs the recorded cause, and treats that
upgrade as failed; a later apply is not refused by these records. A record
that carries a receipt proves a completed flush and is preserved. Like the
failed-upgrade hold, the producer-drain retry count
(`upgrade-flush-producer-retries.json`) is not debris: it survives the
restarts that spend it.

#### Failed-upgrade hold

A flush that started (the daemon stopped behind the hook) and then failed
writes `<data_dir>/upgrade-flush-hold.json` before it restores and exits
`EX_TEMPFAIL`. The record names the held release and the failure cause.
Without it, every service-manager restart would re-apply the same release
and fail the same way — the endless exit loop ADR 0094 §4 forbids. The one
exception is the producers-only drain failure above, which retries its
release twice (counted in
`<data_dir>/upgrade-flush-producer-retries.json`) before this hold
applies.

The hold is deliberately **not** debris: the startup stale-record cleanup
above never removes it, and every apply path — the startup check, the
gossip release listener, the fallback poll and a manual `/upgrade/apply` —
refuses the held release (and anything older), loudly, before downloading
anything. A strictly newer release applies normally, which is the automatic
way past the hold. The manual way is:

1. Stop the daemon.
2. Remove `<data_dir>/upgrade-flush-hold.json` (keep an evidence copy).
3. Start the daemon again.

There is no CLI or API for this. An unreadable hold file refuses every
apply the same way; remove the file to recover.

Manual fallback, if the debris somehow survives or the record cannot be
parsed: stop the daemon, keep an evidence copy, then delete
`<data_dir>/upgrade-flush.json` (only if it has no `receipt_id`) and
`<data_dir>/upgrade-flush-rollback.json`, and start the daemon again. There
is no CLI or API for this.

#### Windows

Supervised self-update needs the acknowledged flush, and the flush owner
exists only on Unix (it needs the suspend-inclusive boot clock and the Unix
control socket). On Windows, a supervised apply (`X0X_SUPERVISED=1`) is
refused with "acknowledged shutdown owner unavailable" before any byte is
replaced — it fails safe. This is accepted until a later slice covers
Windows; a follow-up issue tracks the Windows flush owner.

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

1. **Startup (background, post-bind)**: after the API listener is bound — and as a non-blocking background task, so an unreachable GitHub never delays API readiness (#1086) — check GitHub for a new release and apply it if found (the startup manifest broadcast is a separate task, run by `broadcast_current_manifest`)
2. **Gossip listener**: Receive manifests on `x0x/releases` topic, verify signature, rebroadcast, apply if newer
3. **GitHub poller**: Periodic fallback poll, broadcast discovered manifests to gossip
4. **Authenticated HTTP apply**: Verify the release and wait for staging, then
   recheck admission under the install lock before replacement. The CLI
   `upgrade --apply` uses this route; `--now` skips only the staging delay.

Gossip and polling retain a 30-minute in-memory backoff for other apply errors.
Unix candidate-probe failures additionally use the durable release holds and
interrupted retry policy above. An expired in-memory backoff cannot bypass a
durable hold.

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

### Signed manifest eligibility (M2 S1a, #1369)

Schema 1 requires a signed `channel` (`stable` or `prerelease`). Verification
uses the original JSON bytes. Missing, empty, unknown or mismatched channels
are refused. A stable channel requires a version without a prerelease suffix;
a prerelease channel requires that suffix. The prerelease ban remains in force
(D186): neither `include_prereleases` nor an HTTP request can lift it.

Every ingestion and forwarding path uses the same eligibility rules. The
manifest timestamp must be present and nonzero, no more than 30 days old, and
no more than five minutes in the future. Excess future skew returns the typed
`ManifestTimestampInFuture` cause (D182). Recheck eligibility before apply or
forwarding after a wait. The manifest generator signs `channel: "stable"` and
refuses prerelease versions.

The compatibility fixture is **test-key-signed**. Its old-format verifier is
built from released code with a test key as its trusted key. The production-key
path uses the same parse, signature-verify and eligibility functions; only the
trusted key differs. This control does not claim acceptance by an unchanged
production-key executable. David approved the test-key fixture on 22 Oct 2026
18:31 BST. The transition in ADR 0094 lines 345–348 remains a release-time
action for David/ops: publish a channel-bearing stable manifest before new
daemons enforce this requirement. This change does not publish a manifest.

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
exits nonzero. This signature-only diagnostic does not establish manifest
eligibility. It neither installs an update nor selects a different key.

Systemd acceptance fixtures require a private loopback-only network namespace,
non-root identity, empty capability sets and `no_new_privs`. Each child and
respawn samples and validates these facts before fixture work; runners also
validate each child's receipt. A missing or unsafe observation fails the gate.
