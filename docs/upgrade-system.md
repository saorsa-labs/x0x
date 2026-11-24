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
instance when neither is set. The address comes from the same discovery as
the other CLI commands. That includes `127.0.0.1:12700` when no port file
exists. `localhost` and `127.0.0.1` are the same endpoint. The request stays
on loopback, does not follow a redirect, and does not use a proxy. `--check` still completes when no
daemon answers. A normal check prints the published release version from the
release tag even when that release is not newer than this CLI. `--check
--force` fetches the current release manifest and compares versions. It
prints "Update available" only when that release is strictly newer than this
CLI. An equal, older or unparseable release is not an update.

The check compares this CLI with the executable of that running daemon.
It resolves both paths to their real directories, so a symlink to the CLI
is not a split install. It prints "CLI not upgraded" only when this CLI is
apart from that daemon and older than it. A CLI in `~/.cargo/bin` gets that
report when the running `x0xd` is in another directory and this CLI is older,
even if `~/.cargo/bin` also contains `x0xd`. The executable is read from that
instance's process. The daemon does not report its path. The process matches
`--name <instance>` and `--name=<instance>`. With no `--name`, the check
reads top-level `instance_name` from that process's `--config` file, or from
the default config file when `--config` is absent. A lock file whose process
id now belongs to a different `x0xd` is ignored. That includes a pid that
started more than two seconds after the lock file was written. When the
executable cannot be read and this CLI is not older than the daemon, the
check says that it cannot tell and does not print the reinstall hint. When
the executable cannot be read and `/health` shows this CLI is older than the
daemon, the check still says that it cannot tell, and it prints the version
gap and the reinstall hint. It does not print "CLI not upgraded" in that
case, because it has not shown that the directories differ. When an update
is available and the result is unknown, the check still says to run
`x0x upgrade --apply`.

The daemon apply replaces `x0x` only when that file is in the same directory
as the `x0xd` path it is replacing. It does not resolve a symlink before that
lookup. A symlinked `x0xd` with a real `x0x` beside the link replaces that
`x0x`. The CLI in the symlink target's directory is left in place. After
`x0x upgrade --apply`, this CLI prints "CLI not upgraded" and the reinstall
hint when its own file is not beside that daemon and its version is older
than the version the daemon applied. The notice reads the daemon path again
through the deferred restart window before it says the path cannot be read,
so a service restart in that window is not reported as "Cannot tell" when
the new process is readable. On Linux, a replaced CLI path can end in
` (deleted)`. The check removes that suffix before it compares directories.
The CLI prints that notice on stderr, after the unchanged apply response.
Control characters in a printed path are replaced, so the path stays on one
line. When the CLI cannot read the path, it prints "Cannot tell" only if
this CLI is older than the applied version. The hint is:

```text
cargo install x0x --bin x0x --force
```

That command installs only the `x0x` CLI. It does not replace `x0xd`.
`scripts/install.sh` has no CLI-only mode, so the hint does not call it.
For an apart CLI, the check prints the hint when this CLI is older than the
daemon. It also prints the hint when a newer release exists and this CLI is
not older than the daemon, including when the daemon version is unavailable.
It does not also print `x0x upgrade --apply` for that apart CLI. A CLI beside
that daemon at a different version does not get the hint. Apply still
replaces that sibling. `x0x --name <instance>` and `x0x --api <address>`
select that daemon for `--check` and `--apply`.

**Pair order and lock custody (#2012).** An apply that replaces the sibling
`x0x` replaces `x0xd` first, then `x0x`: the order the host journal records
(`SwappedDaemon`, then `SwappedCli`). A sibling `x0x` that cannot be locked
fails the apply before any file changes. A sibling `x0x` whose swap fails
(an error, or a replace that rolled itself back) makes the apply restore the
`x0xd` it swapped and fail; no restart is requested. If that restore also
fails, the apply fails with an error that says the pair is mixed and needs
manual recovery. On Windows a release archive without a usable `x0x.exe`
fails the apply too (nothing is replaced): an unattended host then keeps a
matching pair instead of a new daemon beside an old CLI, and the failure is
reported as below. In 0.49.1 and earlier a failed companion only logged a
warning, and the daemon was upgraded alone.

A companion failure is recorded in `<data_root>/upgrade-companion-failure.json`
(mode 0600, synced; release, the error naming the `x0x` path, the count, the
time, and whether the pair was left mixed). The recorded failures are the
companion's lock and swap failures and, on Windows, an archive without a
usable `x0x.exe`; on Unix an archive without `x0x` fails earlier, at the probe
extraction, and is not recorded. `/health` (`inputs.upgrade.companion_failure`,
loopback or owner only; the redacted reason names neither the release nor the
count), `GET /diagnostics/upgrade` (`companion_failure`) and `x0x doctor` show
it while its release is newer than the running daemon, with the remedy: make
the file readable and `x0x.backup` and `x0x.upgrade.lock` beside it writable by
the daemon's account, or reinstall `x0x`. The same release is not applied
again, by any apply including an operator's `POST /upgrade/apply`, for 30
minutes after the first such failure, doubling per further failure up to 24
hours; a newer release is tried at once, removing the record allows a retry at
once, and a wait more than 24 hours ahead (a clock stepped back) is ignored. A
successful apply removes the record. A record that cannot be read is reported
(`{"record": "unreadable"}`, a degraded `/health` reason, a doctor warning) and
never holds a release.

Crash window: the two renames are separate steps. A power loss or kill
between them leaves the new `x0xd` beside the old `x0x`. Nothing repairs this
until the next release is applied (with 0.49.1's order it was the old `x0xd`
beside the new `x0x`, which the next update cycle replaced).

The apply worker hands both install locks (`<x0x>.upgrade.lock`,
`<x0xd>.upgrade.lock`) to the restart owner. The immediate owner keeps them
until the process exits. The HTTP apply's deferred owner keeps them through
its 750 ms delay and the restart. While they are held, no other process that
takes these locks swaps the install between the swap and the exit. Not every
reader takes them: `install.sh --binary` does not, and the dormant launcher
takes no lock. On Unix, inside the daemon, every wait for these locks (a
second apply, `x0x upgrade --clear-hold`, a skill update, the probe-retry loop)
fails with "restart in progress" instead of waiting, at once or at its next
20 ms poll, so it cannot hold up the restart's shutdown drain. On Windows only
a wait that starts after the restart owner took the locks fails at once; one
that already started still blocks. A restart that is refused (and restores the
binaries) releases the locks when it returns.

A daemon apply that finds no sibling `x0x` records that the file is missing
at debug level. It does not warn. `POST /upgrade/apply` and `x0x doctor` do
not carry a companion status field. A14 plans a `cli_status` value of
`CannotApply` on `GET /diagnostics/upgrade` and `GET /owner/machines`.
This issue does not add that field. The CLI does not replace itself.

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

On Windows, the restart planner resolves `SupervisedExit` only when
`X0X_SUPERVISED=1` comes from a verified version-2 wrapper (see
[Windows](#windows) below). Otherwise it refuses managed apply. Supervised
Windows apply checks the record barrier before download or replacement.
The candidate probe stays Unix-only. Unmanaged Windows keeps its released
legacy apply behavior and does not claim these M2 durability/probe
guarantees. The inert flag works on both binaries on Windows as well.

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
claim. Supervised Windows apply uses the same record barrier; the Windows
directory sync is described under [Windows](#windows).

Record writes require a file sync, replacement rename and parent
directory sync. On Windows the directory sync is `FlushFileBuffers` on a
directory handle. A failed barrier is a refusal, not an acknowledgement.
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
below). The launcher-side flush receipt, reap check and pair restore code
now exists too, but it is switched off (`ENABLED = false`) and no apply path
calls it; activation of launcher-coordinated host transactions is what
remains. The current apply path still uses its existing single-binary
replacement flow. Do not infer pair rollback or launcher protection from this
dormant module.

The dormant launcher trial (`src/upgrade/launcher/run.rs`) bounds a candidate
start. It reserves each attempt durably before exec, so a failed exec still
counts. The limits are at most 3 attempts, 120 s to readiness per attempt,
60 s of stable health and a 660 s total trial, with 10 s between attempts.
These values are provisional until David rules on them. When the attempts
or the total budget run out, the cause is Failed, and a later service stop
does not change it. Exhausted attempts also stay Failed after a reboot; this
reading of ADR 0094 is provisional until David rules on it. A
reboot before the launcher sees the run-out total budget is Interrupted,
because the launcher cannot tell when the deadline passed. A changed boot, a launcher restart during exec or
rollback, or a service stop while attempts remain is Interrupted. The
launcher then restores the previous pair and starts the restored daemon. For
a service stop, the restore happens on the next launcher start; the candidate
bytes stay installed until then. A restarted launcher resumes an interrupted
rollback and starts only a missing restored child, at most 3 times. The
trial keeps its first rollback cause. Until the host journal reaches
Restored, a Failed cause there replaces an Interrupted one, so the journal
cause, which decides the hold, can differ from the trial cause. After
Restored, the journal cause does not change. A failed reap or a failed restored start stops automatic
recovery (`RecoveryFailed`) until an operator repairs the host.

The `x0x-launcher` binary builds only with the non-default `m2-launcher`
cargo feature. Default builds and `cargo install` of the published crate do
not build it until the activation slice. The launcher gives a candidate its boot
permit as one JSON line on descriptor 3 (`X0X_M2_BOOT_FD=3`). This contract is
provisional and dormant; it is frozen before `ENABLED = true`.

While activation is held, the dormant launcher child cannot brick a daemon
start. `x0xd` reads `X0X_M2_BOOT_FD` before runtime creation; a marker with
no launcher permit behind it (an unrelated or missing descriptor 3) is
dropped with one warning line and the daemon starts normally. ADR 0094 §6
itself governs unknown or corrupt recovery records. The held-boot path
applies that rule to the boot marker by analogy: fail closed means "start
the configured binary normally and report degraded", never brick startup.
The degraded report in the code is one warning line on stderr. The refusal
covers only a permit present on descriptor 3: one that fails its checks,
or one the process cannot verify. On Linux and macOS the process-custody
identity is observed (`/proc` on Linux, libproc on macOS, #1379), so a
permit reaches its field checks. On any other Unix host, every well-formed
permit refuses the boot today, because no identity can be observed. When activation turns the engine on, the full boot
barrier applies as specified: permit checks, boot record write, then the
barrier ack.

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

#### Prepare producer (#2012, gated and dormant)

`upgrade::prepare` writes the prepared host journal
(`<data_root>/upgrade-journal.json`) that the launcher-side issuer, the
launcher's `Host::new` and the arm handler read. The daemon's apply worker
calls it only through `upgrade::producer`, behind a gate that is closed in
this build.

**The gate.** An `x0xd` apply evaluates it after the restart plan and the
download, and records the decision (`GET /diagnostics/upgrade`
`launcher_gate`: `open`, `reason`, `plan_anchor`). It is open only when all
of these hold, in this order:

1. `launcher_contract::LAUNCHER_ENABLED` is true. It is false, so the gate
   is closed on every host and no launcher is run;
2. the restart plan is `SupervisedExit`;
3. the systemd readback of this instance found a loaded `ExecStart` that runs
   `x0x-launcher` in the trial form with `--plan-anchor`, whose `--host-root`
   is this daemon's data root;
4. systemd reports `NeedDaemonReload=no` and exactly one loaded drop-in named
   `30-x0x-launcher.conf`, a regular file whose last `ExecStart=` is the
   loaded command. A drop-in removed or edited by hand closes the gate even
   while the anchor still names the unit;
5. the plan anchor passes the launcher's checks, names this install, and
   names exactly one participant: this instance with this data root. A host
   whose anchor names more than one participant (`x0xd` and `x0xd-443` from
   one install) has no protected apply yet;
6. `x0x-launcher --capabilities` (empty environment, no input, 5 s bound)
   exits 0 and prints `trial-v1`. The launcher prints nothing for it while it
   is dormant, and a launcher older than the flag exits 64.

A closed gate is the unprotected apply described above, unchanged. macOS has
no gate input yet (launchd), so its gate is always closed.

**The transaction.** With the gate open, the worker holds both install
locks and has passed admission and the probes. Then it:

1. writes `<x0xd>.backup` and `<x0x>.backup` durably (a synced temporary file,
   renamed, then the directory synced);
2. freezes the plan (one participant: this daemon, observed live; the
   captured environment leaves out the per-start variables in
   `prepare_live::PER_START_ENV`: `X0X_M2_BOOT_FD`, `INVOCATION_ID`,
   `JOURNAL_STREAM`, `NOTIFY_SOCKET`, `LISTEN_PID`, `LISTEN_FDS`,
   `LISTEN_FDNAMES`, `MAINPID`, `MANAGERPID`, `SYSTEMD_EXEC_PID`,
   `WATCHDOG_PID`, `WATCHDOG_USEC`, `TRIGGER_UNIT`, `TRIGGER_PATH`,
   `TRIGGER_TIMER_REALTIME_USEC`, `TRIGGER_TIMER_MONOTONIC_USEC` and the five
   `MONITOR_*` variables systemd sets for `OnFailure=`/`OnSuccess=` units);
3. adopts the two locks as the `HostLock` and stages: the anchor is read
   while the data root's stage lock is held, then the binding and the Staged
   journal are written;
4. writes Prepared;
5. puts the daemon candidate in place (mode 0755, synced, renamed, directory
   synced), then writes SwappedDaemon;
6. does the same for the CLI, then writes SwappedCli;
7. hands the host lock and the journal to the restart owner, which exits by
   `SupervisedExit` as on the unprotected path.

A failure in steps 4 to 6 restores every target it swapped from its backup
(a copy; the backup stays), then writes `Superseded`. A restart that is
refused before the daemon stops restores the binaries and writes
`Superseded` too. What the launcher does after `SwappedCli` (arming the
old daemon, the trial) is not exercised end to end yet: that is the
lifecycle test of the enable step.

- `freeze_plan` checks the plan before anything is written:
  - the daemon's and the CLI's target and backup paths exist and are
    canonical;
  - each participant has a valid, unique instance id (the launcher's
    rule);
  - each participant's executable and `argv[0]` are the plan's daemon
    target;
  - each participant's data root, identity root and working directory are
    canonical;
  - a running participant carries its pid and process start;
  - the journal's own validation accepts the record.
- `Prepared::stage` and `Prepared::advance` require a `HostLock`, by
  type. `HostLock` holds the advisory locks on
  `<cli target>.upgrade.lock`, then `<daemon target>.upgrade.lock`, in
  the order the pair writer and the launcher take them, and it must be
  the lock of the plan's install pair.
  - **Two runs at once.** The check of an earlier journal and the write
    are both under the lock. So of two concurrent runs, the second waits,
    then finds the first's journal in flight and is refused.
- `Prepared::stage` writes the journal in `Staged` with
  `journal::write_record` (mode 0600, owned by the writing account,
  atomic, file and directory fsync). It writes only into a participant's
  data root that passes the issuer's root check (canonical, this
  account's, no group or other write). An earlier journal is replaced
  only when it is settled (`HostCommitted`, `Restored`, `Idle`,
  `Superseded`).
- `Prepared::advance` moves the journal through `Probed` (optional),
  `Prepared`, `SwappedDaemon` and `SwappedCli`.
  - It first re-reads the journal under the lock and refuses one that is
    not exactly the record this run last wrote: same transaction, same
    sequence, same fields.
  - A swap phase is written only after its target hashes to the planned
    candidate and its backup to the planned previous release.
- `upgrade::prepare_live::observe_this_daemon` reads the running daemon's
  own participant entry. The executable is canonical, and the pid,
  process start and boot ID come from the same functions the arm handler
  compares against. The entry also holds the process environment without
  `X0X_M2_BOOT_FD`, since the launcher starts the candidate with exactly
  that environment.
- **Taking the host lock.** `HostLock::adopt` takes over the install
  locks that a caller already holds, as the apply path takes them with
  `acquire_host_upgrade_lock`, so the producer never waits on its own
  caller. It takes `InstallLock` guards, which `acquire_install_lock`
  returns (`acquire_host_upgrade_lock` is the same lock as a plain file,
  for the existing callers). A guard exists only once its lock
  was taken, so the type proves the caller holds it. `adopt` checks that
  each guard is on the plan pair's lock file. A refusal hands both guards
  back, still held. `HostLock::acquire_within` gives up after a bounded
  wait and never holds one lock while it waits for the other.
- **Arming (MUST).** The caller that arms an old daemon MUST release the
  host lock before it sends the arm request, and MUST NOT take it again
  until the reply arrives. The arm handler (`admit`) checks this: while
  the host lock is held, it refuses the arm with `WouldBlock`, before it
  owns anything, so nothing is restored and the journal is unchanged. The
  launcher, the only arming caller today, releases the lock after it
  saves the trial and before it connects.
- **The arm handler's restore.** `restore_arm` (a refused or failed arm)
  writes the journal and restores the swapped pair under the host lock.
  Another holder may still have the lock, so it waits at most 5 s. Past
  the wait it changes nothing, and the launcher's recovery, which takes
  the lock, restores the pair. The launcher waits 30 s for the arm reply,
  and that is not always enough: a refused arm can reply only after the
  30 s flush limit, the 2 s worker join and the 5 s lock wait, about 37 s.
  On that path the launcher's read times out first. It then stops and
  reaps the old daemon, and its recovery restores the pair under the host
  lock. The outcome is the same restore, done by the launcher.
- **Unix only.** The host lock is taken on Unix only. On Windows (the
  named-pipe arm) the admission check and the restore's lock are absent:
  the restore writes without the host lock. This is an open gap (#2012).
- **Which side checks what.** The producer checks only that a running
  participant has a pid and a process start. The arm handler
  (`server::upgrade_flush::admit`) refuses a journal whose participant
  names another boot, another pid, another process start, another
  identity root (another host) or another executable. It compares the
  canonical running executable, so a daemon started through a symlink is
  compared by the file it runs.

#### Plan binding (#2012, B4, dormant)

The journal's own shape cannot change (`JournalRecord` refuses unknown
fields), so two more records bind it (`upgrade::plan_binding`):

- **Plan anchor.** A JSON file that root writes when it installs the
  launcher. It names the approved install:

  ```json
  {"schema": 1, "record_kind": "plan_anchor",
   "daemon_target": "/opt/x0x/x0xd", "cli_target": "/opt/x0x/x0x",
   "participants": [{"instance_id": "x0xd", "data_root": "/var/lib/x0x"}]}
  ```

  The launcher argv names it with `--plan-anchor <absolute path>`. The
  drop-in installer (`.deployment/install.sh --launcher`) writes it; see
  "The installer's plan anchor" below.
- **Plan binding.** One per transaction:
  `<data_root>/upgrade-plan-binding.<key>.json`, mode 0600, beside the
  journal, where `<key>` is the lowercase hex SHA-256 of the transaction id
  (any id names one fixed-length file in the data root). It holds `{schema: 1, record_kind: "plan_binding",
  transaction_id, generation, plan_sha256, anchor_sha256}`. `plan_sha256`
  is the SHA-256 of the frozen plan's JSON (the digest the trial binding
  uses); `anchor_sha256` is the SHA-256 of the anchor file's bytes.

`Prepared::stage` takes the read anchor by type. It holds the data root's
stage lock (`<data_root>/upgrade-stage.lock`, mode 0600) from its journal
read to its last binding removal, after the host lock, so two stages in
one data root never interleave, whatever install pair each is for. Without
it, two pairs that stage for the first time in a data root with no journal
would hold different install locks, and each could remove the other's new
binding. It refuses a plan whose
daemon target, CLI target, or set of (instance id, data root) is not
exactly the anchor's, before it writes anything. It writes the new
transaction's binding, then the Staged journal. The binding stays the same
for the whole transaction.

A HostCommitted or Restored journal is settled for the producer, but its
launcher still owns a trial there and reads its binding on every start. So
`stage` never writes or removes the binding the current journal names until
the new journal is durable, and it refuses a transaction id equal to the
current journal's. It also refuses a plan for another install pair (other
daemon or CLI target) over a settled journal in the same data root, since
the launcher reads that data root under the lock of the journal's own
daemon target. A crash, or a failed journal write, after the new binding
leaves one of two startable states: before the journal's rename, the
current journal and its binding as they were, plus an orphan binding that
no journal names; after the rename (a failure at the directory sync), the
new Staged journal with its own binding.

Orphans (bindings of neither the current nor the new transaction) are
removed under the host lock before the new binding is written, and every
binding but the new one after the new journal is written. Each removal is
best effort: when all succeed at most two binding files exist; a removal
that fails leaves a harmless leftover that the next stage retries. At the new transaction's own path, a
leftover the strict writer would refuse to replace is removed first: any
regular file it cannot read as a binding (corrupt, a later schema, or a
read that fails, EACCES or EIO included) or a symlink (removed as a link;
its target is not touched). A directory there refuses the stage.

The issuer checks both only where it would give a trial. Each failure is a
typed refusal (78):

- the argv names no `--plan-anchor`;
- the anchor path is not absolute and canonical, or an ancestor is not a
  directory of root that no group or other account can write (a sticky
  directory is allowed);
- the anchor, opened once without following a symlink, is not a regular
  file of root that no group or other account can write, is over 64 KiB,
  or does not parse as schema 1;
- the binding named by the journal's transaction id, opened through the
  checked host root without following a symlink, is missing, cannot be
  opened by the launcher's account, or is not a 0600 regular file of that
  account. The journal and the binding are both read under the install
  lock of the journal plan's daemon target, taken beside that target even
  when the binary is missing (a lock that cannot be taken is a failed
  read, 75). When the start does not already hold that lock it takes it,
  reads the journal again under it, and a journal that changed in between
  is a failed read (75). A stage that writes in this data root while this
  journal exists is for the same install pair (a stage for another pair is
  refused), so it holds that same lock and cannot change the binding
  between the two reads. A lock file that is the start's own daemon lock
  through another path (a plan target under a symlinked directory) is the
  lock already held; the start does not wait on it;
- the binding names another transaction, generation, plan or anchor, or
  the plan names another install pair or other participants than the
  anchor. The install pair is checked against the anchor before the start
  creates or takes any lock file at the plan's daemon target, so a lock
  file is created only beside the anchored daemon.

A missing anchor, or one the launcher's account cannot read, is a typed
refusal (78) too, not a failed read: root writes it in a root directory,
so it does not appear by itself. Only another I/O error while reading
either file is a failed read (75). The mode checks read permission bits
only; an access control list is not read (only root can set one on a
root-owned anchor or directory). A
passthrough needs neither file, so a unit without `--plan-anchor` (one an
older installer wrote) still starts, but can never own a trial.

#### The installer's plan anchor (#2012, dormant)

`.deployment/install.sh --launcher` writes the plan anchor through
`.deployment/launcher-dropin.py` and adds `--plan-anchor <path>` to the
drop-in's `ExecStart`:

- **One anchor per install.** The file is
  `/etc/x0x/launcher/install-<key>.anchor.json`, where `<key>` is the first
  16 hex digits of the SHA-256 of the canonical daemon target. Every unit
  that runs that install names the same file. Each unit's install adds or
  replaces its own participant (instance id, data root). A binding carries
  one anchor digest and a plan must name every participant of the
  install, so units that share one install must name byte-identical
  anchors; one shared file makes that so. A file there for another daemon
  target is refused.
- **Canonical form.** The file is written with sorted keys, participants
  sorted by instance id, a two-space indent and a final newline, so a rerun
  that changes nothing writes the same bytes. The CLI target is the `x0x`
  beside the daemon (resolved if it is a link); the daemon target is the
  installed binary's canonical path. `tests/fixtures/plan-anchor-installer.json`
  is checked against both this writer and the launcher's reader.
- **Owner and place.** Root writes it (`install.sh` runs as root), mode
  0644, through a 0700 temporary file, fsync, rename and a directory fsync.
  The directory is created 0755 whatever the umask. It and every directory
  above it must be root's and not writable by group or others (a sticky
  directory is allowed), as the launcher checks. The path in the drop-in is
  canonical: on macOS `/etc` is `/private/etc`.
- **Checks before changes.** The journal check runs before the first change
  and again after systemd is asked (against the data root systemd's answer
  gives). The first change, taking the unit out of the anchor, and the
  removal of the drop-in come before systemd is asked; nothing else changes
  before the second check. The launcher, its drop-in and the anchor change only when no data
  root the anchor names, before or after, and no data root of this unit
  holds a host journal other than an `idle` or `superseded` one. A
  HostCommitted or Restored journal holds them too, since its launcher may
  still run a trial and reads the anchor on every start. A journal that is
  unreadable, a symlink or not a regular file counts as a journal; it is
  opened without following a symlink or blocking on a FIFO. A refusal
  exits with "the launcher step changed nothing": the launcher, the drop-in
  and the anchor are as they were. Any other error before the first change
  also changes nothing. A refusal found after systemd was asked restores
  the drop-in, then the anchor, and reloads systemd, and `install.sh`
  reloads systemd again. If that restore itself fails, the error says so
  (`RestoreFailed`): the unit is then out of the anchor and its drop-in may
  be missing, which keeps the rule below. The unit file, the config and any
  `--binary` that `install.sh` wrote before the launcher step stay
  installed; the message says so.
- **Steady state.** A committed update's journal becomes Idle once every
  instance's launcher has retired its trial, and an interrupted one becomes
  Superseded at the next start (see "Journal end of life"); the installer
  then runs again. A Restored or RecoveryFailed journal is not settled by any
  code: every `install.sh` run for that install, with or without
  `--launcher`, is refused until the journal is moved aside by hand (stop the
  install's units, move `upgrade-journal.json` and its
  `upgrade-plan-binding.*.json` files aside). The refusal message says this.
- **The anchor names a unit only while its drop-in is in place.** The unit
  leaves the anchor first, then the launcher and the drop-in are written,
  and the unit enters the anchor last. A power loss at any step therefore
  never leaves the anchor naming a unit without its drop-in (a test crashes
  after each change). An install that fails after its first change takes
  the unit out of the anchor first, whatever the journals say (a launcher
  that then refuses a binding fails closed), and only then removes the
  drop-in. If taking it out of the anchor fails, the drop-in stays and the
  installer exits loudly (status 4). The drop-in's header says to remove
  it with `install.sh` without `--launcher`; a drop-in deleted by hand
  still leaves the anchor naming that unit.
- **One run at a time.** A run holds an exclusive lock on
  `<anchor dir>/.install.lock`, so two runs for units of one install never
  rewrite the shared anchor at once. A run that waits longer than 120 s
  (`X0X_INSTALL_LOCK_WAIT`) changes nothing.
- **Launcher replacement.** The installed launcher must be a regular file
  (a symlink there is refused, not followed). A different launcher is
  installed under the journal rule above; the old one is kept as
  `x0x-launcher.previous`.
- **Removal.** `install.sh` without `--launcher` takes this unit out of the
  anchor (the file goes with its last participant), then removes the
  drop-in, under the same rule.
- **Fleet hosts have no trial today.** A plan names every running
  participant of an install, and the anchor names only launcher-bound
  units. The fleet's `x0xd-443` unit has a generated config
  (`deploy-443.sh`), and `install.sh` refuses such an instance, so no
  shipped tool can bind it: the producer refuses those plans.
- **Limits.** Anchor membership alone does not prove a unit is bound now:
  before the launcher is enabled, the producer must check that every
  anchored unit is launcher-bound and that its launcher reads the journal
  format (the `--capabilities` gate). The installer does not take the data
  root's stage lock, so an anchor change at the same moment as a stage
  that read the old anchor can leave a binding the launcher refuses (78);
  the producer must read the anchor under the stage lock. The fleet units
  run as root, so there the root-owned anchor is the daemon's own account:
  tamper-evidence only, as on macOS.

`install.sh --launcher` with no path fetches the release asset
`x0x-launcher-<platform>.tar.gz` for the installed x0xd's own version
(`x0xd --version`; Linux x86_64 and aarch64), its `.sha256`, its GPG
signature (`.asc`) and `SAORSA_PUBLIC_KEY.asc`. It needs curl and gpg. The
`.sha256` must hold 64 hex digits that match, the key must have the pinned
fingerprint and the signature must be a `VALIDSIG` of it, checked in a
throwaway GnuPG home. A failure leaves the launcher, its drop-in and the
anchor as they were. The asset is produced only once the separate release
workflow PR (#2190, for David to merge) lands; until a release carries it,
`--launcher` with no path fails closed and `--launcher PATH` is the way to
install. That PR builds `x0x-launcher`
(`--features m2-launcher`) for linux-x64-gnu, linux-arm64-gnu, macos-x64 and
macos-arm64 and ships it as that archive, signed with ML-DSA-65 (`.sig`,
context `x0x-launcher-v1`) and GPG (`.asc`). It is not in the signed release
manifest or the release custody set: self-update never replaces the
launcher. Not yet done (open before the launcher is enabled):
`--launcher PATH` verifies nothing about the given file; a signature covers
the archive's bytes only, so an older validly signed launcher is accepted
(no version binding, no rollback protection); the launcher binary has no
build-provenance record; and the release does not run the packaged
launcher before shipping it.

#### Journal end of life (#2012)

A journal is settled when it is `Idle` or `Superseded`. A settled journal
does not refuse a later apply, opens the host-commit gate, is a passthrough
for the launcher, and lets the installer change the launcher and its anchor.

- **Idle.** The launcher's retire (under the host lock, CLI lock then daemon
  lock) saves its trial `Committed` and, in the same locked step, writes
  `Idle` when every participant's trial record of the transaction is
  `Committed`. A crash before the write leaves `HostCommitted`, which the
  next start's retire settles. A retire on a host already `Idle` for a
  `Committed` trial is still a retire.
- **Superseded.** The producer writes it when it gives up before the
  hand-off. A launcher start that finds `Staged`, `Probed`, `Prepared` or
  `SwappedDaemon` writes it too: the producer is gone, since it keeps the
  install locks until it exits. Under the host lock, with the journal read
  again and its binding checked against the anchor, the start restores every
  target that holds the candidate from its backup, writes `Superseded`, and
  exits 75 so that the next start reads the settled journal. A target that
  holds neither release, a backup that is not the previous release, a
  missing anchor or binding, or an unfinished trial is a typed refusal (78)
  and nothing changes. This closes the crash between the daemon swap and the
  SwappedDaemon record, which before left a Prepared journal over swapped
  bytes and a passthrough to the candidate, and the crash between the CLI
  swap and its record, which before was a refusal (78) with the daemon down.
- `Restored` and `RecoveryFailed` are not settled by any code: the cause
  they keep decides the hold. The installer still refuses while they are
  there.

The installer takes the stage lock of every data root the anchor names,
before and after its change, from its journal check to its last anchor
write, so a stage either finished before the check (and the check refuses
on its journal) or reads the new anchor. It opens the data root as a
directory without following a symlink and opens or creates the lock file
relative to that handle (0600, given to the data root's owner); anything but
a regular file is refused.

#### Moving a data root to another install (#2012)

A host journal names its install pair. A launcher whose daemon is not that
journal's install, over that data root, refuses to start (78) with the
reason `other-install-journal: ...`, and the producer refuses to stage
another pair there. This happens when a data root moves to another install
(a new daemon path) or two installs share one data root. `x0x doctor`, with
the daemon down, shows it as its own state (`refusal_kind:
"other-install-journal"`) with the journal's phase, transaction and install
targets, and gives the remedy:

- **Settled journal** (`host_committed`, `restored`, `idle`,
  `superseded`) of an install that no longer runs on this data root: stop
  the unit, move `upgrade-journal.json` and every
  `upgrade-plan-binding.*.json` in the data root aside, then start the
  unit. If the other install still runs on this data root, do not move the
  journal (its launcher may still need it for a trial): give each install
  its own data root.
- **Any other phase:** an update of the other install is still in
  progress. Do not remove the journal. Run the other install until its
  update settles (or its launcher restores it), then move the settled
  journal as above.

There is no command for this yet; it is a manual step.

**Limit.** The binding fixes which install a plan can name: the install
pair, the participants and their data roots. The daemon's account cannot
change those. It does not authenticate the artifact hashes, versions,
arguments or environment inside the plan: anything that runs as the
daemon's account, the candidate included, can still write a journal and a
matching binding for the anchored install. On macOS the launchd plist is
the user's own file, so an anchor there could only be tamper-evidence; the
launcher accepts only a root-owned anchor on every platform for now
(#1379).

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

**Stable launcher (dormant).** `x0x-launcher` becomes the stable
recovery actor that ADR 0094 §5 requires when M2 activation is on. M2
trial ownership is held, so the binary is dormant and recovers nothing.
Its passthrough mode is a provisional interim mode that ADR 0094 does not
describe: it does not own a child, so it cannot meet the ADR's manager ->
launcher -> child readback. Run as `x0x-launcher /absolute/path/x0xd [args]`, it becomes
`x0xd` by `exec` and keeps the direct job's one-process signal and exit
semantics. The daemon path must be absolute. The launcher never searches
`PATH`. A missing or relative daemon path exits 64 (`EX_USAGE`). A failed
`exec` exits 75 (`EX_TEMPFAIL`); `Restart=always` retries it as for a
direct unit. On macOS a daemon path that does not exist is waited for
instead (see "Missing daemon" below). `Restart=always` also restarts on exit 64, so a unit that
binds the launcher must set `RestartPreventExitStatus=64`: a wrong
`ExecStart` then stops the job and does not restart it every 5 s. The
argv contract and the exit codes are provisional and dormant. They are
frozen before `ENABLED = true`, like the fd 3 boot contract. The main
loop (`start.rs`, #1378) owns the trial only when the engine is enabled
and the issuer gives it a host. Only the trial form of the argv,
`x0x-launcher --host-root /abs/data-root --instance ID [--plan-anchor /abs/anchor] -- /abs/x0xd [args]`,
consults the issuer (`issuer.rs`): it opens `<host-root>/upgrade-journal.json`
once without following a symlink and requires, on that descriptor, a
regular file of the launcher's account with mode exactly 0600, in a
canonical root that no other account can write. No journal, or one before
the swap or settled (`staged`, `probed`, `prepared`, `idle`, `superseded`),
is an ordinary start, unless an unfinished trial (not Committed or
Restored) is on disk, which refuses the start. An in-flight journal must
name the instance, with that participant's data root equal to the host
root, its executable equal to the daemon path and its arguments
(`argv[1..]`) equal to the daemon's. A refusal no restart can change
(mismatch, mixed pair, wrong owner, mode or type, corrupt journal, unknown
schema, unfinished trial, a non-canonical plan path, a symlinked,
non-regular or oversized trial record) exits 78; a failed read exits 75,
and so does a plan path that is missing, since it may appear by itself (a
volume not yet mounted at boot). Only the issuer's typed refusal exits 78;
an untyped I/O error is a failed read. The journal
has no hash or signature of its own. A trial also needs the plan anchor
and the plan binding (see [Plan binding](#plan-binding-2012-b4-dormant)):
without `--plan-anchor`, or with an anchor or binding that does not check,
an in-flight journal is a typed refusal (78), never a trial. The writer of
that journal is the M2 prepare producer (#2012), which the apply path calls
only behind a gate that is closed while `LAUNCHER_ENABLED` is false, so with
the engine held every start is still the passthrough. An owned start installs its SIGTERM and
SIGINT handler only then, and exits 0 after a stop, 75 when the daemon
exits or a step can be retried (an issuer error never falls back to the
passthrough), and 78 (`EX_CONFIG`) when no automatic start is allowed
(`RecoveryFailed`, a final host phase, a participant missing from the
plan or stopped, or a prior child that still runs after a 45 s wait for it
to end). A unit that binds the owned launcher must also set
`RestartPreventExitStatus=78`. A trial-form launcher records each final
refusal in `<host-root>/launcher-refusal.json` (reason, launcher pid and
process start time, time; mode 0600). Each trial-form start removes the
earlier record before it starts, so a start that supervises the daemon
leaves none. `x0x doctor` reports the record while the daemon is
unreachable, and shows the launcher as holding only when a process with
the recorded pid and start time still exists. A retired trial on a
committed host is an ordinary start: the passthrough. The launcher strips a stray `X0X_M2_BOOT_FD` from the daemon's
environment before the `exec`. While activation is held, `x0xd` ignores a
stray `X0X_M2_BOOT_FD` with one warning. It refuses to start only for a
permit present on descriptor 3 that fails its checks or cannot be
verified (see
[Dormant pair transaction](#dormant-pair-transaction-m2-s2e)). The
launcher sits outside the daemon/CLI swap set. The daemon updater never
replaces it.

The issuer opens the host root once as a directory (`O_DIRECTORY`,
`O_NOFOLLOW`) and reads the journal and the trial record relative to that
descriptor (`openat`), so a rename of the path after the checks cannot
redirect the reads (#2012). Every ancestor of the host root must be a
directory owned by root or the launcher's account that no other account can
write; a sticky ancestor such as `/tmp` is allowed, since only an entry's
owner may rename it there.

The host root must also be the data directory of the daemon in the argv
(#1378; it runs only once the launcher is turned on). Records read from
another directory say nothing about this
daemon: with no journal there, the start would pass through to a candidate
swapped in under the daemon's own journal. The issuer derives that
directory as x0xd does at startup, from the daemon arguments and the
environment the launcher passes on to x0xd: the `data_dir` of the config
file (`--config`, else the instance's default config file when it exists),
else the default, renamed `x0x-<name>` for a named instance (`--name`, else
the file's `instance_name`). The directory's parent is resolved but its
last component is not followed, so a data directory that is a symlink does
not match, even one that points at the host root. A mismatch is refused
(78), as is a data directory that cannot be known from the argv: a
relative one, a config file that is not valid TOML, an instance name x0xd
would refuse, a repeated `--config` or `--name`, or the `--config=`
spelling, which x0xd does not read. A config file that cannot be read is a
failed read (75). The check runs before the records are read, and again
when a passthrough that holds no install lock reads them again before its
`exec`. `tests/launcher_data_dir_parity.rs` checks the derivation against
`x0xd --check`.

The issuer reads both records under the daemon install lock: the
`.upgrade.lock` file beside the daemon's canonical path, the same file the
prepare producer, the CLI self-update and the daemon's routes lock, so a
unit that names the daemon through a symlink takes the same lock. It waits
for the lock at most 30 s, then exits 75. When a journal exists, a
passthrough whose canonical daemon is not the journal's daemon target is
refused (78). A start that becomes the passthrough keeps the lock until
its `exec`, which closes it, so nothing can swap the pair between the read
and the `exec`. A trial start releases it, since the trial takes the CLI
and daemon locks itself.

- **Missing daemon.** When the daemon or its directory does not exist,
  there is nothing to swap and no one can lock there, so the start goes on
  to the passthrough without the lock: on macOS the missing-daemon wait
  (#1379), elsewhere the `exec` error (75). Before each `exec` attempt it
  takes the lock and reads the records again; while the daemon is still
  missing it does not `exec` at all, so it never becomes the daemon
  without the lock. An `exec` that finds the daemon missing releases the
  lock, so a producer or a CLI apply never waits for the missing-daemon
  wait. After the lock is taken the daemon path is resolved again; a path
  that now names another file, or none, is a failed read (75). If a trial
  is in flight by the time the daemon is back, the launcher exits 75 and
  the next start owns the trial.
- **Retired trial.** A start that retires its trial on a committed host
  released the lock for the trial, so before its `exec` it takes the lock
  and reads the records again. When the journal is HostCommitted and this
  instance's trial record is Committed, it checks that its canonical
  daemon is the journal's daemon target and `exec`s under the lock;
  another daemon is refused (78). Any other trial is left to the next
  start (75). A trial is saved Committed only under the host lock while
  the journal is HostCommitted, and only a new producer transaction moves
  the journal on, so this is the steady state after every committed
  upgrade.
- **Lock file it cannot use.** When this account cannot create or open
  the lock file (EACCES, EPERM, EROFS), the start is refused (78) with the
  remedy: let the launcher's account write the daemon's directory, or use
  the plain launcher form. A lock file that root created (an upgrade run
  under `sudo`, for example) is a common cause. While no upgrade runs, give
  it to the launcher's account
  (`sudo chown <account> <daemon>.upgrade.lock`, keeping mode 0600) or
  remove it (`sudo rm <daemon>.upgrade.lock`) when the launcher's account
  can write the daemon's directory, so the launcher creates it again; then
  restart the unit. A passthrough without the lock is not safe
  there, because the CLI self-update can lock and swap as another account
  (root under `sudo`, for example). A symlink, a directory or another
  non-regular file at the lock path is refused (78) too.

A typed refusal found by the re-read just before an `exec` is final as at
the start: exit 78 (the hold under launchd) with the refusal record. Every
other `exec` failure exits 75; the launcher logs "did not exec" when it
stopped before trying (a lock wait that ran out, a trial in flight, a
missing daemon) and "cannot exec" when the `exec` itself failed.

The lock scheme rests on one invariant: only an account that is allowed to
replace the daemon can write the daemon's directory. Such an account can
replace the daemon, or remove or replace its lock file, without the lock,
so the lock orders the swaps of the producer, the CLI self-update and the
daemon's routes; it does not protect against an account that ignores it.
Every opener of the lock (the launcher, the producer, the CLI self-update
and the daemon's routes) creates it with mode 0600 and does not follow a
symlink at its path.

Still open under #2012: wiring the producer into the apply path, the
multi-instance journal copies, the installer that writes the plan anchor
(the binding itself is in [Plan binding](#plan-binding-2012-b4-dormant)),
and leaving an old `INVOCATION_ID` out of a trial child's captured
environment.

No tracked unit binds the launcher yet, and default builds do not build it
(it needs the `m2-launcher` feature). ADR 0094 §5 preconditions for
binding a fleet unit include: the separately signed launcher artifact in
the release payload, verified for hash, version, account rights and journal-reader support;
`install.sh` or `x0x autostart --repair` shipping it beside `x0xd`; an
M2-capable daemon installed first under the existing direct job; the
authority-inventory check accepting a launcher-owned `ExecStart`; and the
`KillMode` and restart readbacks accepting launcher-owned jobs. Until
these hold, a launcher-bound unit would refuse every self-update. The unit
switch also needs David's approval because it changes production hosts.

**Launcher-bound systemd unit (#1378).** The systemd restart readback
accepts a unit whose `ExecStart` runs the stable launcher, in the plain or
the trial form. It reads the daemon and its arguments from the launcher's
argv with the launcher's own parser, and they must be this daemon and its
arguments; the launcher must be the one installed next to this x0xd
(compared by canonical path). The unit's main process must then be either
this daemon, when the launcher passed through and became the daemon by
`exec` (always, while the launcher is dormant), or this daemon's parent
when that parent's executable is the launcher. Anything else is refused;
for any other unit the main process must be this daemon. A launcher-bound
unit must also have `Restart=always`: a launcher that owns the daemon exits
75 after the daemon ends, which `Restart=on-success` does not restart. For
the same reason its `RestartPreventExitStatus` must not cover 75 (a number
or a range); the drop-in below lists only `64 78`. The start-rate window is
unchanged.

The readback checks only what decides the restart. The launcher's own
`--host-root` and `--instance` select its journal, so the readback does not
bind them; the installer takes them from x0xd itself.

`.deployment/install.sh --launcher /path/to/x0x-launcher` (off by default;
with no path it fetches the signed release asset) installs the launcher
next to the instance's `x0xd`, writes the install's plan anchor ("The
installer's plan anchor" above) and writes
`<unit>.service.d/30-x0x-launcher.conf` (by a temporary file and a rename):

```ini
# Installed by .deployment/install.sh --launcher (#1378). To return to the
# direct job, run .deployment/install.sh without --launcher: it also takes
# this unit out of the plan anchor. Do not just delete this file.
[Service]
ExecStart=
ExecStart=/opt/x0x/x0x-launcher --host-root <data root> --instance <id> --plan-anchor /etc/x0x/launcher/install-<key>.anchor.json -- /opt/x0x/x0xd <unit args>
Restart=always
RestartPreventExitStatus=64 78
KillMode=mixed
TimeoutStopSec=60
```

- The data root is the one x0xd reports for the unit's own arguments
  (`x0xd <args> --check`, run as the unit's user with that user's `HOME`;
  it reads the config and writes nothing), with its parent resolved
  through symlinks. A data root that is itself a symlink is refused,
  because the launcher does not follow it. As root, the check runs through
  `runuser` (looked up in `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`). The
  data root must exist, so x0xd must have started once, and it must be
  owned by the unit's user and not writable by group or others.
- The unit's user and `ExecStart` are the effective ones, read as systemd
  reads them: the unit file, then every drop-in that systemd applies to it
  (`<unit>.d/`, the dash-prefix directories such as `x0xd-.service.d/`,
  and `service.d/`, under `/etc`, `/run` and `/usr/lib`), in file-name
  order. The last `User=` wins (`root` when none, or an empty one, is
  set); an empty `ExecStart=` clears the earlier ones, and exactly one
  must be left. The launcher drop-in itself is removed first and not read.
  The installer then asks systemd as well (`systemctl daemon-reload`, then
  `systemctl show -p LoadState -p FragmentPath -p DropInPaths -p User -p
  ExecStart`), and refuses when systemd's answer differs from the files,
  systemd does not load the unit, or the reload or the query fails while
  systemd runs (`/run/systemd/system` exists). Only without a running
  systemd does it use the files alone, and it says so. A search directory
  that resolves to one already read (`/lib` on a merged-`/usr` host) is
  read once.
- The installer's `--check` runs with only `HOME` and `PATH`, so it refuses
  a unit whose environment could move the data directory: `HOME`,
  `XDG_CONFIG_HOME` or `XDG_DATA_HOME` in `Environment=`, any
  `EnvironmentFile=`, a relative `--config` (the unit's
  `WorkingDirectory=` is not used), and the `--config=` spelling.
- The installer refuses ambiguity: a unit file of the same name earlier in
  systemd's search path (for example `/run/systemd/transient`), two
  drop-ins with the same file name, another `30-x0x-launcher.conf` in any
  drop-in directory, and a drop-in that sorts after the launcher drop-in
  and sets `ExecStart`, `Restart`, `RestartPreventExitStatus`, `KillMode`,
  `TimeoutStopSec` or `TimeoutSec`, which would undo it.
- The launcher and the drop-in are each written as a new temporary file in
  the target directory (`O_EXCL`, mode 0700, whatever the umask), given
  their mode (0755 and 0644), synced, renamed over the target, and the
  directory is synced. A failed directory sync is reported after the
  rename, when the target is already the new file.
- The instance is the manifest instance id.
- An `ExecStart` token that needs systemd quoting (spaces, quotes, `$` or
  `%`), or an `ExecStart` that cannot be split, is refused; such a unit is
  migrated by hand.
- Any failure leaves no launcher drop-in: the installer removes an earlier
  one, reloads systemd so the unit runs x0xd directly, and exits 1 with the
  reason.
- `KillMode=mixed` sends the stop signal to the launcher only, which stops
  x0xd within its own 45 s window; `TimeoutStopSec=60` is above that window.
- An install without `--launcher` removes the drop-in, so the tracked unit
  runs x0xd directly again.

The helper is `.deployment/launcher-dropin.py`. `tests/test_launcher_dropin.py`
tests it and runs `install.sh --launcher` from a scratch copy of the
deployment tree (fresh host, rerun, `User=` drop-ins, a failed rerun, an
answer from systemd that agrees and one that does not), with the drop-in
lookup over a scratch search path. Not done yet: a trial of a
launcher-bound unit on a real systemd host, and an exit test of the
supervised upgrade exit on a launcher-bound host, which needs a private
testnet host and the launcher turned on.

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
attempted: flush admission runs the same walk — no writes and no fsync
(on Windows it opens each file with write access, as the flush will) —
over the exact roots the flush will walk, and a supervised apply is
refused with the offending path before any byte changes. A symlink an
operator put there therefore stops the next upgrade attempt up front,
loudly, instead of failing the flush after the daemon already stopped; the
failed-upgrade hold keeps the restart loop from re-applying a release
whose flush did fail that way. `x0xd --doctor` does not yet run this
check; the admission refusal is the diagnostic surface today.

On Unix, the local control listener is a Unix socket, `upgrade-flush.sock`
in the data directory, mode `0600`. Windows uses a named pipe with the same
protocol (see [Windows](#windows) below). It accepts one JSON request line carrying the
API token, the transaction ID, generation, instance ID and frozen plan, and
answers `{"receipt": …}` or `{"error": …}`. The daemon-side listener exists
and is authenticated; the client that drives it belongs to later stack
work. David approved this local control API on 23 Oct 2026 at 16:52 BST;
its API and framing remain as approved. Permissions are set on the socket
path before the listener accepts requests, without a process-wide umask
change. The API token is checked even for a connection queued during bind.
A very long data-directory path can exceed the Unix socket path limit (104 bytes on macOS); the bind then fails and supervised
apply is disabled with a WARN in the log.

An arm request for a participant whose frozen restart mode is
`TransactionalHandoff` is refused before the shutdown (issue #1670). The
error reply says that no restart-capable owner is established. The daemon
keeps serving. A completed flush ends the old participant with exit 0, and
no supervisor restarts it. The durable receipt proves the flush only.
Reaping the old participant and starting the candidate need an owner
outside the stopped process. No such owner exists today: the arm-and-flush
path spawns no helper, and the launcher is not implemented. Supervised-exit
arm requests are not affected. The ordinary in-process transactional
handoff, which spawns the detached helper, is not affected. The
transactional socket flush may be activated only when a restart owner is
established and retained. The daemon must verify that owner against the
frozen transaction, generation, participant identity and restart binding.
That owner arrives with the #1375 launcher and #1376 recovery work.

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

Windows has the same acknowledged flush owner and contract as Unix (#1588).
The platform parts are:

- **Clock**: `GetTickCount64` gives milliseconds since boot. It includes
  sleep and hibernation and ignores wall-clock changes. The boot identity is
  `windows-boot-<n>`, from the kernel `BootId` registry value
  (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\BootId`).
  A missing `BootId` is a clock error. The flush is then refused before the
  stop, and the daemon keeps serving.
- **Record barrier**: `journal::open_for_sync` opens files with write access
  and directories with `FILE_FLAG_BACKUP_SEMANTICS`. `sync_all`
  (`FlushFileBuffers`) is the directory barrier. If the file system refuses
  the flush, the barrier is refused. The flush walk needs write access, so
  a read-only-attribute file in the data or identity root refuses the
  upgrade at admission, before any byte changes. Clear the attribute.
- **Control channel**: the daemon serves the same newline-delimited JSON
  arm-and-flush protocol on the local named pipe
  `\\.\pipe\x0x-upgrade-flush-<hex>`. `<hex>` is the first 32 hex
  characters of the SHA-256 of the lowercased canonical data root. The pipe
  DACL is `D:P(A;;GA;;;OW)` (owner rights only). The daemon creates the pipe
  with `first_pipe_instance` against squatting and rejects remote clients.
  It creates the next pipe instance before it hands out the connected one.
  It still checks the API token on each request.
- **Requirements for a future arm client** (no Windows client exists yet):
  the pipe name is in the machine-wide named-pipe namespace and anyone can
  derive it, so another local user can create it first. The daemon then
  fails safe: it does not serve. A client must not treat a successful
  connect to the derived name as proof that it reached the daemon. Before
  it sends the API token, it must verify the server, for example with
  `GetNamedPipeServerProcessId` and a check that the server process owner
  SID is the expected daemon user. On Unix the socket is in the `0600`
  data directory, so this exposure does not exist there. A second
  concurrent client can get `ERROR_PIPE_BUSY`; the client must retry with
  `WaitNamedPipe` or a backoff.
- The failed-upgrade hold and the startup stale-record cleanup also run on
  Windows.

The generated wrapper (`src/cli/commands/windows-wrapper.ps1`, template
version 2) restarts `x0xd` after exit 100 and after exit 75. Exit 75
(`EX_TEMPFAIL`) follows a failed flush that restored the old binary. The
wrapper propagates every other exit status. The readback accepts only
version 2. A version-1 wrapper refuses supervised self-update; run
`x0x autostart` to regenerate it. Before #1588, Windows refused every
supervised apply, so no working setup loses self-update.

CI (`Test Suite (Windows)`, `windows-latest`, in `ci-full.yml`) runs the
pipe, clock, record-barrier and foreground exit-status tests
(`cargo test --lib windows_exec_regressions`,
`cargo test --test upgrade_journal`). It then runs the flush-owner
acceptance (#1764, `scripts/ci/windows-flush-acceptance.ps1`): the real
`x0xd` under a wrapper made by `x0x autostart`, with no peers and with
self-update on but its release sources off. The flush owner starts only
when self-update is on (`[update] enabled = true`).
It checks the owner start and pipe name, the token checks, a refusal for a
second non-admin local user, the wrapper restart rule with a stub child,
and the directory barrier on NTFS (see [`cicd.md`](cicd.md)).

Owed: a supervised self-update run on Windows (#1764 items 2 and 3): a
real apply that exits 100 and restarts on the new version, and an injected
flush failure that restores the old binary and exits 75. The hosted run
does not do this: it has no signed test release to download.

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
down after the upgrade exit). It also reports and refuses a job that sets
`AbandonProcessGroup: true`, even one that already has the marker: launchd
then leaves x0xd's process group running when the job stops, so an orphaned
daemon can outlive its replacement (ADR 0094, #1379). Remove that key by
hand. The change takes effect on the job's next load —
`--repair` prints the `launchctl unload`/`load` commands rather than stopping
a running daemon itself. The repair-time check is not the last word: every
apply re-verifies the **loaded** job policy (#615 above), so a `KeepAlive`
removed after repair refuses further upgrades instead of exiting into a job
that will not restart.

A job whose program is the stable launcher (`x0x-launcher /abs/x0xd ...`,
or the trial form `x0x-launcher --host-root R --instance I -- /abs/x0xd ...`)
is treated as the x0xd job it runs: `--repair` and the upgrade-time
readback both look through the launcher's own arguments to the daemon
(#1379). The program is the executable launchd runs: `Program` when the
job sets it, else `ProgramArguments[0]`. The launcher's arguments are
checked with the launcher's own parser, so `--repair` refuses a relative
host root or an invalid instance that the launcher would refuse. Such a job also needs `ExitTimeOut` above 45 s (the launcher's
worst-case stop of a committed daemon); `--repair` refuses one without it.
Under launchd an unconditional `KeepAlive` restarts every exit, so a
launcher that reaches a final refusal (exit 78 elsewhere) holds until it is
stopped instead of exiting. launchd then shows the job running with no
daemon; `x0x doctor` shows the launcher's refusal reason.

`x0x autostart --launcher` (hidden, macOS only, opt-in while the launcher
is dormant) installs the job in the trial form:
- the `x0x-launcher` next to `x0xd` as found, made absolute but not
  resolved through symlinks, so a package manager's stable link is kept;
- `--host-root` is the canonical data directory, and `--instance` is the
  `--name`, or `default`;
- the canonical `x0xd`, because the journal names the canonical install
  path;
- `ExitTimeOut` 60 s.

The whole launcher argv is checked with the launcher's own parser before
anything is written, so a job the launcher would refuse (a relative
daemon, an invalid instance) is never installed. A package-manager
upgrade that moves the canonical `x0xd` needs `x0x autostart --launcher`
again. A daemon inside a versioned Homebrew keg is refused (see
"Homebrew keg paths" below): a Homebrew install keeps the direct job and
updates with `brew upgrade`.

One label (`com.saorsalabs.x0xd`) serves one instance. `x0x autostart`
refuses to replace a job under that label that starts another `--name`;
remove it first with `x0x autostart --remove`.

Every `x0x autostart` on macOS writes the plist in one step (a new
temporary file, mode 0644, fsync, rename, directory fsync). It then loads
the plist with `launchctl bootout` and `launchctl bootstrap gui/<uid>`.
The previous plist is kept until the new job loads:
- if `bootout` leaves the old job loaded, the old file is restored and
  nothing changes;
- if `bootstrap` fails, the old file is restored, and it is loaded again
  only if it was loaded before; when there was no old file, the new file
  is removed.

If the restore itself fails, the error reports both failures.

`--remove` uses `bootout`.

`x0x autostart --repair --launcher` moves each existing x0xd job onto the
launcher. It moves only a job that the plain repair accepts (`KeepAlive`
true, no `AbandonProcessGroup`), and keeps its label, environment, log
paths and every other key. It writes the trial-form `ProgramArguments`
(the launcher next to the job's daemon path, the host root, the canonical
daemon, and the job's own arguments), removes `Program`, and sets
`ExitTimeOut` to 60 s when it is absent or 45 s or less. It also adds the
supervision marker if it is missing.

`x0x autostart --repair --dry-run` (with or without `--launcher`) checks
and prints each change, the planned `ProgramArguments` for the launcher
and the `X0X_SUPERVISED=1` marker included, and writes nothing.

The host root is the data directory that x0xd uses for that job, found
the way x0xd finds it:
- the home is the job's own `EnvironmentVariables.HOME`, else the home of
  the user running the repair;
- the instance's default config file
  (`<home>/Library/Application Support/x0x[-<name>]/config.toml`) may set
  `data_dir`; otherwise it is `<home>/Library/Application Support/x0x`,
  or `x0x-<name>` for a named instance.

The directory must exist: the planning step creates nothing. A job that
passes `--config`, a config file that is not valid TOML, a relative
`data_dir`, or a config `instance_name` that the job does not pass is
refused, because the host root is then not known from the job.

The repair builds the whole new job file first, checks that it converts
back to exactly the planned job, and writes it in one atomic step (a
temporary file, fsync, rename, directory fsync). A crash therefore leaves
either the old job or the new one, never a mix. A copy of the old file is
kept as `<plist>.x0x-backup`. If the readback is not the planned job, the
old file is written back. The repair does not reload the job; it prints
the `bootout` and `bootstrap` commands. It exits non-zero and names each
job that it did not move.

`scripts/ci/macos-launchd-acceptance.sh /abs/x0x-launcher` is the isolated
launchd acceptance. It loads a throwaway job (its own label and roots in
a temporary directory) into the user's GUI domain, running the launcher
in the trial form over a fake daemon. The run of 18 Nov 2026 (macOS 27,
the dormant launcher) found:
- a daemon that ends on SIGTERM stops at once on `bootout`;
- a daemon that ignores SIGTERM is SIGKILLed at the job's `ExitTimeOut`
  (25 s in the test, not launchd's 20 s default);
- when the launcher is SIGKILLed, launchd ends the rest of its process
  group.

**Limit:** launchd's process-group cleanup sends SIGTERM only. A group
member that ignores SIGTERM, or hangs in its shutdown, outlives both
`bootout` and a crash of the launcher. Once `ENABLED` is true, the
launcher's next start finds the prior child still running, waits 45 s,
and holds (a final refusal) instead of starting a second daemon. While the
launcher is dormant it execs the daemon at once, so that wait and the
hold are not yet measured through launchd. The launcher's unit tests
cover them.

**Missing daemon.** The job names the canonical daemon, which a
package-manager upgrade can remove. (A job migrated before the keg check
of #1379 can name a versioned Homebrew Cellar path, which `brew upgrade`
removes.) Before 19 Nov 2026 the dormant launcher then failed the `exec`
and exited 75 at once, and launchd started it again after each throttle
interval (3 starts in 30 s): a restart loop. On macOS the launcher now
waits instead. It writes one line to the job's standard error, tries the
`exec` again after 1 s, doubles the pause up to 60 s, and becomes the
daemon at the first try after the path is back (at most 60 s later). A
stop ends the wait; any other `exec` error still exits 75. On Linux the
exit stays, because systemd's start limit ends the restarts. The
acceptance script checks the wait (`missing-daemon-waits`): one launcher
start in 30 s, then the daemon runs once its path exists.

**Homebrew keg paths (#1379).** `x0x autostart --launcher` and
`--repair --launcher` refuse a daemon whose canonical path is inside a
versioned Homebrew keg (`<prefix>/Cellar/<formula>/<version>/...`). The
trial form needs the canonical daemon, and `brew upgrade` removes the old
keg, so such a job would wait for a daemon that never comes back. Keep the
direct job for a Homebrew install, or install x0xd outside Homebrew.
`--repair --launcher` also refuses a job that already runs the launcher
with a daemon path inside a keg, instead of counting it as compliant. Both
refusals name the command that puts the direct job back for the instance:
`x0x autostart`, or `x0x autostart --name <name>` for a named instance. A job
that already names a missing daemon is reported by `x0x doctor` while the
daemon is unreachable: the upgrade check fails and names the job, the
missing path and whether the launcher is waiting for it. Run
`x0x autostart` again to point the job at the installed x0xd.

The keg path is not replaced by the `<prefix>/opt/<formula>` link, and
this is the decision, not a gap (#2111, A14 of 20 Nov 2026). The launcher
compares the journal's canonical executable with the daemon path in its
arguments byte for byte, and a trial swap would write into a keg that
Homebrew owns. Homebrew owns a Homebrew install's upgrades: `brew upgrade`
is its update path, so that install never uses the launcher's trial form.

**Who may change a job.** On macOS every autostart command (install,
`--repair`, `--remove`) refuses to run as root or under `sudo`: the agent
belongs to the user who runs it, and a root-owned file in that user's
LaunchAgents is one their `launchctl` cannot load. Install and `--repair`
also refuse a job file that is not owned by the user or that group or
others can write, which launchd does not load. `--repair` reports such a
job as refused and leaves it unchanged.

**Not done yet:** the acceptance script runs by hand only.

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

1. **Startup (background, post-bind)**: after the API listener is bound,
   check GitHub for a new release and apply it if found. This check runs
   as a non-blocking background task, so an unreachable GitHub never
   delays API readiness (#1086). The check itself announces nothing
   (#1169). A boot-time discovery is announced by the separate
   every-launch manifest broadcast task, `broadcast_current_manifest`.
   That broadcast runs under the same gates and with the byte-identical
   payload; both paths build it through the same monitor funnel. It is
   best effort: the broadcast task does its own fetch, and a failed
   fetch announces nothing — such a discovery is announced only when a
   later publish point (fallback poll, gossip relay) sees the release.
2. **Gossip listener**: Receive manifests on `x0x/release` topic, verify signature, rebroadcast, apply if newer
3. **GitHub poller**: Periodic fallback poll, broadcast discovered manifests to gossip
4. **Announce on first observation** (#1169): a node announces a release
   at four publish points:

   - the startup manifest broadcast (`broadcast_current_manifest`, on
     every launch)
   - the fallback poll
   - the gossip relay
   - a manual `/upgrade/apply`
   - a manual `/upgrade/announce` (see below)

   The startup check and the read-only `/upgrade` check announce
   nothing. The startup check's discovery is covered by the manifest
   broadcast on a best-effort basis: the broadcast fetches independently,
   and a failed broadcast fetch announces nothing. For the read-only
   check, gossip self-delivery would feed this node's own apply owner —
   a background install triggered by a read (Engineer ruling 3 Nov 2026
   17:40 GMT).

   `/upgrade/apply` applies the release it announces. It records its
   payload as apply-route-owned in the shared self-published tracker
   before publishing. While the tracker holds that claim, any gossip
   copy of those bytes — the announcing node's own echo or a peer's —
   neither rebroadcasts nor queues a second apply on the background
   owner.

   Echoes of the node's non-apply-route publishes — the boot broadcast,
   the fallback poll, the gossip relay — are not rebroadcast either.
   They still reach the owner, and the owner's version dedup absorbs
   them.

   The tracker entry that holds the claim expires 30 minutes after its
   latest record. A later record of the same bytes — the boot
   broadcast, a fallback publish or a repeat `/upgrade/apply` of those
   bytes — restarts that clock; a gossip driver rebroadcast never does,
   because self-published bytes are skipped before any record is
   written. The default rollout window is 60 minutes, so the entry
   can expire while the apply still waits. A gossip copy of the payload
   is then treated like a peer's copy and can queue a background apply
   again.

   The handler's drop releases the claim only when the apply was never
   admitted and nothing will resume the install. These drops release
   it, and gossip copies reach the owner again:

   - a failed apply that leaves no live probe retry owning the install
     — including a failure before any attempt (staging wait, identity
     readback, permit or manifest-timestamp checks): its cancelled
     release permit disqualifies it from the hand-off, so it schedules
     no retry
   - a no-op apply
   - a client disconnect during the apply wait — unless a live probe
     retry owns the install for that version
   - a panic — same unless

   A failed apply that leaves a live probe retry owning the install
   keeps the claim. It keeps the claim whether this request scheduled
   the retry or an earlier failed apply in the same process already
   left it in place. A second failed `/upgrade/apply` of the same bytes
   must not release the first failure's live retry claim — and neither
   may a later request that is dropped before admission (disconnect or
   panic) or fails without scheduling anything: such a request's guard
   kept nothing, but its drop checks the process-local retry ownership
   first and clears a claim only when no live retry is left. A poisoned
   ownership map counts as owned, so it keeps the claim too.

   Every admitted apply keeps the claim. Once the apply's blocking
   worker is admitted — host locks held, replacement and restart owned
   by the worker — no handler exit releases the claim. A dropped
   handler keeps it: the install still runs. `RolledBack` keeps it: a
   real rollback runs after admission, so a rolled-back apply is always
   on this post-admission side. `NoUpgrade` keeps it, and so do errors
   that resume nothing. A successful apply keeps it as well.

   The motivating case is a gossip copy arriving in the seconds before
   the restart. Such a copy must not queue a second apply of that
   install. That case is not the whole rule. The keep is bounded by the
   tracker TTL — a sliding bound, because every later record of the
   same bytes restarts it: the claim ages out with the entry even when
   the worker has finished and the handler is alive, but fresh echoes
   keep extending it.

   After a fast failure, the node's own gossip echo can still arrive
   after the claim is released and queue a background-owner attempt of
   the same release. The owner's 30-minute `failed_at` backoff bounds
   the rate of those attempts, not their count: at most one new attempt
   per 30 minutes.

   The GitHub poll cadence does not change (A14 / ADR 0045): gossip is
   the fast path. The announcement is bounded (10 s) and best effort;
   peer rebroadcast limiting and the apply owner's dedup handle repeats.
5. **Authenticated HTTP apply**: Verify the release and wait for staging, then
   recheck admission under the install lock before replacement. The CLI
   `upgrade --apply` uses this route; `--now` skips only the staging delay.

Gossip and polling retain a 30-minute in-memory backoff for other apply errors.
Unix candidate-probe failures additionally use the durable release holds and
interrupted retry policy above. An expired in-memory backoff cannot bypass a
durable hold.

`x0xd --skip-update-check` disables self-update for that process invocation. It
suppresses the startup GitHub check, gossip-delivered apply, manifest broadcast,
fallback polling, and manual `/upgrade/apply`. The `/upgrade` check keeps
answering; it is read-only and never announces, with or without the flag. The
setting is not persisted; launching the daemon normally later restores the
configured updater behavior.

All nodes verify and rebroadcast manifests (symmetric propagation — no privileged bootstrap role).

### Announcing a release at promotion (#1169)

David decided on 19 Nov 2026 that a release is announced at promotion.
`POST /upgrade/announce` (CLI `x0x upgrade --announce`) is the local,
authenticated way to do it. It needs no signing key: peers accept a
manifest only with a valid ML-DSA-65 signature, a newer version and a
fresh timestamp, so the announcer only relays bytes CI already signed.

1. A successful announce in the last 300 s answers `already_announced`
   at once, before any GitHub request.
2. With an empty body it fetches the latest release manifest with
   `fetch_current_manifest`, the same verified fetch as the boot
   broadcast, and checks the manifest timestamp. With a JSON body
   `{"manifest_b64": ..., "signature_b64": ...}` (base64 of the release's
   `release-manifest.json` and `release-manifest.json.sig`; CLI
   `x0x upgrade --announce --manifest-file <f> --signature-file <f>`) it
   makes no GitHub request and runs the same checks on those bytes
   (`verify_eligible_manifest`: signature, channel, timestamp). The
   published payload is byte-identical to a fetched one. Only one of the
   two fields, bad base64 or an unknown field answers `400`
   (`invalid_request`, or the generic invalid-JSON error), and a body
   without `Content-Type: application/json` answers `415`; nothing falls
   back to a fetch.
3. It decides the result:

   | `result` | Status | When |
   |---|---|---|
   | `announced` | 200 | Published on `x0x/release`. |
   | `already_announced` | 200 | This node announced within 300 s, or published the same bytes within 300 s by another path (boot broadcast, fallback poll, relay). Nothing is published. |
   | `nothing_newer` | 200 | This node runs a version newer than the latest release. Nothing is published. A node on the release's own version does announce it. |
   | `fetch_failed` | 502 | The GitHub release or its manifest assets could not be fetched. Nothing is published or recorded. |
   | `verification_failed` | 502 (400 for a manifest in the body) | The signature or the manifest checks failed. Nothing is published or recorded. |
   | `invalid_request` | 400 | The body has only one of `manifest_b64` and `signature_b64`, or a value is not base64. Nothing is published or recorded. |
   | `publish_failed` | 502 | The publish failed or did not finish within 10 s. The announce's record is undone, so a retry is not refused. |

4. Before it publishes, it records the payload in the self-published
   tracker, so the gossip driver does not rebroadcast this node's echo.
   If the publish fails, or the request is dropped mid-publish, a guard
   undoes only that record. A record made meanwhile, such as an
   `/upgrade/apply` claim on the same bytes, stays.

The announcing node is on the same footing as a node that received the
manifest by gossip. The announce never installs at once and never
bypasses the node's own policy. Its record carries no apply-route
claim, so the gossip driver submits the echo (or a peer's copy) to the
node's background owner like any gossip copy: same staggered install,
same version dedup, same updates-enabled and channel gates. With updates
off, no gossip driver runs and nothing is queued.

The route does not depend on `update.enabled`: a node with updates off
can announce. A node that published the same bytes at boot (the boot
broadcast) within the last 300 s answers `already_announced`.

Accepted trade-off: after an announce, every node applies within the
60-minute stagger window, the announcer included. There is no
network-wide halt today.

#### The promotion job

When a release is promoted (the `release: published` event), the
`announce-release` job in `.github/workflows/publish-promoted-release.yml`
runs the announce from a short-lived node:

1. It downloads the promoted `x0x-linux-x64-gnu.tar.gz` and checks it
   against the release's `.sha256` asset. The same authenticated
   download fetches `release-manifest.json` and its `.sig`; the token is
   not in the environment of the step that runs `x0xd`.
2. `.github/scripts/announce_promoted_release.py` starts that `x0xd` with
   a fresh identity in a temporary directory, on the `x0x.prod` plane, with
   `[update] enabled = false`, `--skip-update-check` and mDNS off. It holds
   no secret.
3. It waits up to 180 s for at least one send-ready peer (`send_ready_peers`
   in `/health`), then
   20 s more for topic membership, and calls `POST /upgrade/announce`
   with the downloaded manifest and signature in the body, so `x0xd`
   makes no GitHub API request. On the v0.49.0 promotion (22 Nov 2026)
   the route's own unauthenticated fetch from the runner's shared IP got
   `403 rate limit exceeded` on all three attempts (#1169). An `x0xd`
   older than the body ignores it and fetches as before.
4. Success is `announced` or `already_announced` **with `version` equal to
   the promoted version**. The result alone is not enough: the 300 s
   refusal of a repeat is keyed on time, so `already_announced` can carry
   an earlier version. `fetch_failed`, `nothing_newer`, `publish_failed`
   and a wrong version are tried again after 305 s (past the 300 s
   refusal), three attempts in all. Without a body, GitHub's latest
   release can point at the previous release for a short time after
   promotion.
5. After a success the node stays up 60 s so that peers can pull the
   payload, then stops.

The job passes, and announces nothing, when the release has no announce
script or its `x0xd` has no announce route (404). It fails when the node
finds no send-ready peers (hosted runners may not reach the network over UDP) or the
promoted version is not announced; the error names the fallback, `x0x
upgrade --announce` on a node that can reach the network. The job is
independent of the crates.io and ClawHub jobs. Its outcome is an annotation
and a line in the job summary.

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
