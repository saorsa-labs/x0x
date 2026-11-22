//! The launcher main loop (#1378): one start of the installed launcher.
//!
//! While `ENABLED` is false, or when no issuer gives this launcher a host,
//! the launcher has no trial authority and becomes the daemon by `exec`
//! (`forward`). With a host from the complete inventory issuer it owns the
//! participant's trial: `supervise` runs it to a host commit, a stop, a
//! restored child or a final state, and `keep` holds a committed or
//! restored daemon as an ordinary service. There is no production issuer
//! yet (a later #1378 slice), so the passthrough is still the only live
//! path.
use super::*;
use supervise::{Kept, Supervised};

/// 75 is `EX_TEMPFAIL`: the manager restarts the job (the daemon exited,
/// or a step failed that a later start can retry).
pub(crate) const EXIT_TEMPFAIL: u8 = 75;
/// 78 is `EX_CONFIG`: no automatic step is allowed (`RecoveryFailed`, or a
/// final host phase). The unit must not restart on it; an operator acts.
pub(crate) const EXIT_FINAL: u8 = 78;

/// A refusal no restart can change (a mixed pair, an argv that does not
/// match its journal, a record of the wrong owner or mode): the main loop
/// exits 78. Any other issuer error, such as a failed read, exits 75.
#[derive(Debug)]
pub(super) struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

pub(super) fn refused(reason: impl Into<String>) -> io::Error {
    io::Error::other(Refused(reason.into()))
}

/// An error from before the `exec`: the launcher never tried to become the
/// daemon (a lock wait that ran out, a trial in flight, a missing daemon).
#[derive(Debug)]
struct NotExecuted(String);

impl std::fmt::Display for NotExecuted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotExecuted {}

fn not_executed(kind: io::ErrorKind, reason: impl Into<String>) -> io::Error {
    io::Error::new(kind, NotExecuted(reason.into()))
}

pub(super) fn is_refusal(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Refused>())
}

/// Hold after a final refusal instead of exiting, until a stop (#1379).
/// launchd has no "do not restart on this status": the `KeepAlive: true`
/// the supervised upgrade exit needs would restart a 78 every
/// `ThrottleInterval` (10 s) for ever. Holding keeps one quiet process;
/// a stop (SIGTERM when armed, else its default action) ends it. systemd
/// does not need this: `RestartPreventExitStatus=78` stops the job.
pub(crate) fn hold_final(mut stop: impl FnMut() -> bool, mut pause: impl FnMut()) {
    while !stop() {
        pause();
    }
}

/// What one launcher start decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Start {
    /// No trial authority: become the daemon by `exec`.
    Passthrough,
    /// The launcher owned the start and now exits with this status.
    Exit(u8),
    /// No automatic start is allowed, for this reason: exit 78 (or, on
    /// macOS, hold until a stop). A trial-form start records the reason in
    /// its host root for `x0x doctor` (`contract::REFUSAL_FILE_NAME`).
    Final(String),
}

/// A final refusal: report it and return it.
fn final_start(reason: impl Into<String>) -> Start {
    let reason = reason.into();
    eprintln!("x0x-launcher: no automatic start: {reason}");
    Start::Final(reason)
}

/// How long a start waits for a prior child that still exists before it
/// refuses (#2016 review). The prior child's group gets the same window as
/// the launcher's own stop of a daemon (graceful window plus reap): a
/// launcher that the manager killed leaves a child that the manager's
/// process-group cleanup is still ending.
const PRIOR_CHILD_WAIT_MS: u64 = STOP_MS + REAP_MS;

/// A host journal and this launcher's participant in it. Only the
/// complete inventory issuer may make one (`recovery::Host::new`).
pub(super) struct Issued {
    pub(super) host: recovery::Host,
    pub(super) instance: String,
}

/// The source of trial authority for one start.
pub(super) trait Issuer {
    /// `Ok(None)`: no launcher-owned trial is in flight for this daemon.
    fn issue(&self, command: &forward::DaemonCommand) -> io::Result<Option<Issued>>;
}

/// The production issuer until the complete inventory issuer lands: it
/// never issues a host, so every start is a passthrough.
pub(super) struct NoIssuer;

impl Issuer for NoIssuer {
    fn issue(&self, _command: &forward::DaemonCommand) -> io::Result<Option<Issued>> {
        Ok(None)
    }
}

/// One start of the installed launcher. `arm` installs the stop handler;
/// it runs only once an issuer gives this launcher a trial. A passthrough
/// never catches a signal, so a stop before the `exec` still ends the
/// launcher as it ends a direct job. `stop` reads the stop flag. Only the
/// argv's trial form (`--host-root ... --instance ...`) consults the
/// journal issuer; the plain form is always a passthrough.
/// After a passthrough of the trial form, `held` holds the daemon install
/// lock: the caller keeps it until the `exec`, which closes it (#2012).
pub(crate) fn start(
    args: &issuer::LauncherArgs,
    held: &mut Option<std::fs::File>,
    arm: impl FnOnce(),
    stop: impl FnMut() -> bool,
) -> Start {
    if !ENABLED {
        return Start::Passthrough;
    }
    let pause = || std::thread::sleep(std::time::Duration::from_millis(100));
    match &args.trial {
        None => start_with(&NoIssuer, &args.command, arm, Clock::now, stop, pause),
        Some(trial) => with_refusal_record(&trial.host_root, || {
            let issuer = issuer::JournalIssuer {
                args: trial,
                held: std::cell::RefCell::new(None),
            };
            let started = start_with(&issuer, &args.command, arm, Clock::now, stop, pause);
            if started == Start::Passthrough {
                *held = issuer.held.into_inner();
            }
            started
        }),
    }
}

/// One passthrough `exec` attempt (#2118 review). A trial-form start takes
/// the daemon install lock and reads the records again before it becomes
/// the daemon; while the daemon is missing it holds no lock and does not
/// `exec` at all, but returns `NotFound`, so the missing-daemon wait
/// (#1379) tries again later. An `exec` that finds the daemon missing
/// releases the lock, so no producer or CLI apply waits on that wait.
/// Nothing changes while the engine is held.
pub(crate) fn exec_locked(
    args: &issuer::LauncherArgs,
    held: &mut Option<std::fs::File>,
    exec: impl FnMut(&forward::DaemonCommand) -> io::Error,
) -> io::Error {
    exec_locked_with(ENABLED, args, held, exec)
}

pub(super) fn exec_locked_with(
    enabled: bool,
    args: &issuer::LauncherArgs,
    held: &mut Option<std::fs::File>,
    mut exec: impl FnMut(&forward::DaemonCommand) -> io::Error,
) -> io::Error {
    if let (true, Some(trial)) = (enabled, &args.trial) {
        if let Err(error) = issuer::relock(trial, &args.command, held) {
            if is_refusal(&error) {
                return error;
            }
            return not_executed(error.kind(), error.to_string());
        }
        if held.is_none() {
            return not_executed(
                io::ErrorKind::NotFound,
                "the daemon is missing; no install lock is held",
            );
        }
    }
    let error = exec(&args.command);
    if forward::is_missing(&error) {
        *held = None;
    }
    error
}

/// How the launcher ends after its passthrough `exec` failed. A typed
/// refusal from the re-read under the install lock (`relock`) is final, as
/// it is at the start, and leaves the refusal record; every other error is
/// a failed read (75) (#2118 review).
pub(crate) fn exec_failed(args: &issuer::LauncherArgs, error: &io::Error) -> Start {
    if !is_refusal(error) {
        let tried = !error
            .get_ref()
            .is_some_and(|inner| inner.is::<NotExecuted>());
        eprintln!(
            "x0x-launcher: {} {}: {error}",
            if tried { "cannot exec" } else { "did not exec" },
            args.command.executable.display()
        );
        return Start::Exit(EXIT_TEMPFAIL);
    }
    let started = final_start(error.to_string());
    if let (Some(trial), Start::Final(reason)) = (&args.trial, &started) {
        record_refusal(&trial.host_root, reason);
    }
    started
}

/// Run one trial-form start between the two refusal-record steps: remove
/// the record an earlier start left before the start, since a start that
/// supervises the daemon returns only when the daemon ends (#2019 review);
/// leave a new one after a final refusal. `x0x doctor` then shows only a
/// refusal that holds now.
fn with_refusal_record(root: &Path, start: impl FnOnce() -> Start) -> Start {
    clear_refusal_record(root);
    let started = start();
    if let Start::Final(reason) = &started {
        record_refusal(root, reason);
    }
    started
}

/// Remove the refusal record an earlier start left. A failure only leaves
/// a stale report.
fn clear_refusal_record(root: &Path) {
    let path = root.join(contract::REFUSAL_FILE_NAME);
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            eprintln!("x0x-launcher: refusal record {}: {error}", path.display());
        }
        _ => {}
    }
}

/// Leave the refusal record in the host root after a final refusal. It is
/// written only into a host root that passes the issuer's root check,
/// through a 0600 temporary file and a rename; a failure only loses the
/// report.
fn record_refusal(root: &Path, reason: &str) {
    let path = root.join(contract::REFUSAL_FILE_NAME);
    if let Err(error) = issuer::check_root(root, issuer::effective_uid())
        .and_then(|()| write_refusal_record(&path, reason))
    {
        eprintln!("x0x-launcher: refusal record {}: {error}", path.display());
    }
}

fn write_refusal_record(path: &Path, reason: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let record = contract::LauncherRefusal {
        schema: contract::REFUSAL_SCHEMA,
        reason: reason.to_owned(),
        pid: std::process::id(),
        process_start: contract::process_start(std::process::id())?,
        at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis()
            .try_into()
            .map_err(io::Error::other)?,
    };
    let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    match std::fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)
}

pub(super) fn start_with(
    issuer: &impl Issuer,
    command: &forward::DaemonCommand,
    arm: impl FnOnce(),
    now: impl FnMut() -> io::Result<Clock>,
    mut stop: impl FnMut() -> bool,
    pause: impl FnMut(),
) -> Start {
    let issued = match issuer.issue(command) {
        Ok(Some(issued)) => issued,
        Ok(None) => return Start::Passthrough,
        // Without a verified inventory the launcher must not guess custody,
        // and a passthrough could start a candidate outside its trial.
        Err(error) if is_refusal(&error) => {
            return final_start(format!("inventory issuer: {error}"));
        }
        Err(error) => {
            eprintln!("x0x-launcher: inventory issuer: {error}");
            return Start::Exit(EXIT_TEMPFAIL);
        }
    };
    arm();
    drive(&issued, now, &mut stop, pause)
}

/// Own this participant's trial for one start.
fn drive(
    issued: &Issued,
    mut now: impl FnMut() -> io::Result<Clock>,
    stop: &mut impl FnMut() -> bool,
    mut pause: impl FnMut(),
) -> Start {
    let (path, mut trial) = match load(issued, &mut now, stop, &mut pause) {
        Ok(loaded) => loaded,
        Err(Refusal::Final(reason)) => return final_start(reason),
        Err(Refusal::Stopped) => return Start::Exit(0),
        Err(Refusal::Retry(error)) => {
            eprintln!("x0x-launcher: trial: {error}");
            return Start::Exit(EXIT_TEMPFAIL);
        }
    };
    let supervised = supervise::supervise_with(&issued.host, &path, &mut trial, now, &mut *stop);
    match supervised {
        Ok(Supervised::Committed { child, retired }) => {
            // The next start retires a Provisional trial on a committed
            // host, so a failed retire only needs reporting.
            if let Err(error) = retired {
                eprintln!("x0x-launcher: retire after host commit: {error}");
            }
            kept(supervise::keep(child, stop, pause))
        }
        Ok(Supervised::Restored(child)) => kept(supervise::keep(child, stop, pause)),
        // A stop caught after the trial's own stop check would be lost at
        // the `exec`: check once more (#2006 review).
        Ok(Supervised::Retired) if stop() => Start::Exit(0),
        // The trial is retired on a committed host: an ordinary start.
        Ok(Supervised::Retired) => Start::Passthrough,
        Ok(Supervised::Stopped) => Start::Exit(0),
        Ok(Supervised::Final(phase)) => final_start(format!("host is {phase:?}")),
        Err(error) => {
            eprintln!("x0x-launcher: trial: {error}");
            // A RecoveryFailed trial forbids every automatic start; a
            // restart would only repeat the refusal.
            let final_trial = Trial::load(&path, &trial.binding, &issued.instance)
                .map(|on_disk| on_disk.phase == Phase::RecoveryFailed)
                .unwrap_or(trial.phase == Phase::RecoveryFailed);
            if final_trial {
                final_start("trial is RecoveryFailed")
            } else {
                Start::Exit(EXIT_TEMPFAIL)
            }
        }
    }
}

/// Why a start cannot load its trial.
enum Refusal {
    /// A restart would refuse the same way: no automatic start.
    Final(&'static str),
    /// A later start may succeed (an I/O error, a trial not yet written).
    Retry(io::Error),
    /// The manager asked for a stop while the start waited.
    Stopped,
}

/// Load this participant's trial, after the refusals that no restart can
/// change (#2006 review): a participant missing from the plan, a stopped
/// participant (it stays stopped), and a prior child that still runs after
/// `PRIOR_CHILD_WAIT_MS` (the manager must remove the old process group
/// before any start; restarting until the start limit would not change
/// that). The wait lets a prior child that is still ending clear by itself
/// before the refusal, which on macOS holds until a stop (#2016 review).
fn load(
    issued: &Issued,
    now: &mut impl FnMut() -> io::Result<Clock>,
    stop: &mut impl FnMut() -> bool,
    pause: &mut impl FnMut(),
) -> Result<(PathBuf, Trial), Refusal> {
    let participant = issued
        .host
        .plan()
        .participants
        .iter()
        .find(|p| p.instance_id == issued.instance)
        .ok_or(Refusal::Final("participant missing"))?;
    if !participant.was_running {
        return Err(Refusal::Final("stopped participant must remain stopped"));
    }
    let path = coordinator::trial_path(participant);
    let binding = issued.host.binding().map_err(Refusal::Retry)?;
    let trial = Trial::load(&path, &binding, &issued.instance).map_err(Refusal::Retry)?;
    if let Some(identity) = &trial.child {
        let deadline = now()
            .map_err(Refusal::Retry)?
            .ms
            .saturating_add(PRIOR_CHILD_WAIT_MS);
        while !child::absent(identity).map_err(Refusal::Retry)? {
            if stop() {
                return Err(Refusal::Stopped);
            }
            if now().map_err(Refusal::Retry)?.ms >= deadline {
                return Err(Refusal::Final("prior child still exists"));
            }
            pause();
        }
    }
    Ok((path, trial))
}

fn kept(result: io::Result<Kept>) -> Start {
    match result {
        Ok(Kept::Stopped) => Start::Exit(0),
        // The manager's restart policy applies to the daemon's exit.
        Ok(Kept::Exited) => Start::Exit(EXIT_TEMPFAIL),
        Err(error) => {
            eprintln!("x0x-launcher: daemon custody: {error}");
            Start::Exit(EXIT_TEMPFAIL)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use testkit::*;

    struct Fixed(std::cell::RefCell<Option<io::Result<Option<Issued>>>>);

    impl Issuer for Fixed {
        fn issue(&self, _: &forward::DaemonCommand) -> io::Result<Option<Issued>> {
            self.0
                .borrow_mut()
                .take()
                .unwrap_or_else(|| Err(invalid("issued twice")))
        }
    }

    fn command() -> forward::DaemonCommand {
        forward::DaemonCommand {
            executable: "/usr/bin/x0xd".into(),
            args: Vec::new(),
        }
    }

    fn issued(host: recovery::Host) -> Fixed {
        Fixed(std::cell::RefCell::new(Some(Ok(Some(Issued {
            host,
            instance: "alice".into(),
        })))))
    }

    /// Save a trial through `phases` in order (the save guard checks each
    /// step).
    fn trial_at(host: &recovery::Host, phases: &[Phase]) -> PathBuf {
        let path = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        for phase in phases {
            // The record rules: a Provisional trial has an attempt, a
            // child and a ready instant; a Committed one has an attempt.
            match phase {
                Phase::Provisional => {
                    trial.attempts = 1;
                    trial.ready_since_ms = Some(trial.started_ms);
                    trial.child = Some(Identity {
                        pid: 1,
                        start: 1,
                        boot: trial.boot.clone(),
                    });
                }
                _ => trial.child = None,
            }
            trial.phase = phase.clone();
            trial.save(&path).unwrap();
        }
        path
    }

    #[test]
    fn the_held_engine_is_a_passthrough() {
        // `forward::dormant_passthrough_requires_the_held_engine` pins
        // ENABLED = false; the held engine never consults an issuer or
        // installs a stop handler.
        let mut armed = false;
        let args = issuer::LauncherArgs {
            trial: Some(issuer::TrialArgs {
                host_root: "/nonexistent".into(),
                instance: "alice".into(),
                plan_anchor: None,
            }),
            command: command(),
        };
        assert_eq!(
            start(&args, &mut None, || armed = true, || false),
            Start::Passthrough
        );
        assert!(!armed);
    }

    #[test]
    fn no_issued_host_is_a_passthrough() {
        let none = Fixed(std::cell::RefCell::new(Some(Ok(None))));
        let mut armed = false;
        assert_eq!(
            start_with(
                &none,
                &command(),
                || armed = true,
                Clock::now,
                || false,
                || {}
            ),
            Start::Passthrough
        );
        assert!(!armed, "a passthrough never catches a signal");
        assert_eq!(
            start_with(&NoIssuer, &command(), || {}, Clock::now, || false, || {}),
            Start::Passthrough
        );
    }

    /// An issuer error never falls back to a passthrough: the daemon could
    /// be a candidate outside its trial.
    #[test]
    fn an_issuer_error_is_a_retryable_exit() {
        let broken = Fixed(std::cell::RefCell::new(Some(Err(invalid("no inventory")))));
        assert_eq!(
            start_with(&broken, &command(), || {}, Clock::now, || false, || {}),
            Start::Exit(EXIT_TEMPFAIL)
        );
    }

    /// A stop before the first attempt saves the trial Stopped and exits 0.
    #[test]
    fn a_stop_before_the_first_attempt_exits_cleanly() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = trial_at(&host, &[Phase::Authorized]);
        let binding = host.binding().unwrap();
        let mut armed = false;
        assert_eq!(
            start_with(
                &issued(host),
                &command(),
                || armed = true,
                Clock::now,
                || true,
                || {}
            ),
            Start::Exit(0)
        );
        assert!(armed, "an issued trial installs the stop handler");
        let on_disk = Trial::load(&path, &binding, "alice").unwrap();
        assert_eq!(on_disk.phase, Phase::Stopped);
        assert_eq!(on_disk.attempts, 0);
    }

    /// A retired trial (committed host) is an ordinary start.
    #[test]
    fn a_committed_trial_is_a_passthrough() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::HostCommitted);
        trial_at(
            &host,
            &[Phase::Authorized, Phase::Provisional, Phase::Committed],
        );
        assert_eq!(
            start_with(
                &issued(host),
                &command(),
                || {},
                Clock::now,
                || false,
                || {}
            ),
            Start::Passthrough
        );
    }

    /// A RecoveryFailed trial forbids every automatic start: the exit tells
    /// the manager not to restart.
    #[test]
    fn a_recovery_failed_trial_is_a_final_exit() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        trial_at(&host, &[Phase::Authorized, Phase::RecoveryFailed]);
        assert!(matches!(
            start_with(
                &issued(host),
                &command(),
                || {},
                Clock::now,
                || false,
                || {}
            ),
            Start::Final(_)
        ));
    }

    #[test]
    fn a_missing_trial_is_a_retryable_exit() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        assert_eq!(
            start_with(
                &issued(host),
                &command(),
                || {},
                Clock::now,
                || false,
                || {}
            ),
            Start::Exit(EXIT_TEMPFAIL)
        );
    }

    fn journal_cause(root: &Path) -> journal::Cause {
        match journal::read_boot_records(root).journal {
            journal::RecordRead::Journal(record) => record.cause.unwrap(),
            _ => panic!("journal record missing"),
        }
    }

    /// #2006 review item 1: the clock fails after the last attempt's
    /// failure, through the main loop. The attempt count needs no clock, so
    /// the launcher rolls back as Failed at once and the release is held.
    /// Before, `now()?` left the trial Booting and exited 75; the restart
    /// rolled back as lost custody (Interrupted).
    #[test]
    fn a_clock_error_after_the_last_attempt_records_failed() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        trial.phase = Phase::Authorized;
        trial.save(&path).unwrap();
        trial.attempts = MAX_ATTEMPTS - 1;
        trial.save(&path).unwrap();
        let binding = trial.binding.clone();
        let clock = || {
            // The fixture's candidate cannot exec; once the attempt is
            // reserved (Booting on disk) the clock fails.
            let on_disk = Trial::load(&path, &binding, "alice").unwrap();
            if on_disk.phase == Phase::Booting {
                return Err(io::Error::other("clock lost"));
            }
            Clock::now()
        };
        let exit = start_with(&issued(host), &command(), || {}, clock, || false, || {});
        // The restored start fails on the fixture's unexecutable bytes.
        assert!(matches!(exit, Start::Final(_)), "{exit:?}");
        let cause = journal_cause(&root);
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("launch attempts exhausted"),
            "{cause:?}"
        );
        let on_disk = Trial::load(&path, &binding, "alice").unwrap();
        assert_eq!(on_disk.attempts, MAX_ATTEMPTS);
        assert_ne!(on_disk.phase, Phase::Booting, "{on_disk:?}");
    }

    /// #2006 review item 2: a stop caught after the retired trial's own
    /// stop check exits 0 and never reaches the `exec`.
    #[test]
    fn a_stop_after_the_retire_check_is_not_lost() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::HostCommitted);
        trial_at(
            &host,
            &[Phase::Authorized, Phase::Provisional, Phase::Committed],
        );
        let mut calls = 0;
        let stop = || {
            calls += 1;
            calls > 1
        };
        assert_eq!(
            start_with(&issued(host), &command(), || {}, Clock::now, stop, || {}),
            Start::Exit(0)
        );
    }

    /// #2006 review item 3: refusals no restart can change exit 78, not 75.
    #[test]
    fn a_stopped_participant_is_a_final_exit() {
        let (_dir, _root, host, _record) = fixture_with(journal::Phase::SwappedCli, |record| {
            record.plan.participants[0].was_running = false;
        });
        trial_at(&host, &[Phase::Authorized]);
        assert!(matches!(
            start_with(
                &issued(host),
                &command(),
                || {},
                Clock::now,
                || false,
                || {}
            ),
            Start::Final(_)
        ));
    }

    #[test]
    fn a_missing_participant_is_a_final_exit() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let other = Fixed(std::cell::RefCell::new(Some(Ok(Some(Issued {
            host,
            instance: "nobody".into(),
        })))));
        assert!(matches!(
            start_with(&other, &command(), || {}, Clock::now, || false, || {}),
            Start::Final(_)
        ));
    }

    /// A clock that moves one second per reading, so the prior-child wait
    /// ends without real time passing.
    fn advancing_clock() -> impl FnMut() -> io::Result<Clock> {
        let base = Clock::now().unwrap();
        let mut readings = 0;
        move || {
            readings += 1;
            Ok(Clock {
                boot: base.boot.clone(),
                ms: base.ms + readings * 1_000,
            })
        }
    }

    /// Save a Booting trial whose child is `pid`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn booting_with_child(host: &recovery::Host, pid: u32) {
        let path = trial_at(host, &[Phase::Authorized]);
        let binding = host.binding().unwrap();
        let mut trial = Trial::load(&path, &binding, "alice").unwrap();
        trial.attempts = 1;
        trial.child = Some(child::identity(pid).unwrap());
        trial.phase = Phase::Booting;
        trial.save(&path).unwrap();
    }

    /// A prior child that still runs (here: this test process) after the
    /// whole wait is final. Process identity needs Linux procfs or macOS
    /// proc_pidinfo.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_surviving_prior_child_is_a_final_exit() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        booting_with_child(&host, std::process::id());
        let mut pauses = 0;
        let exit = start_with(
            &issued(host),
            &command(),
            || {},
            advancing_clock(),
            || false,
            || pauses += 1,
        );
        assert_eq!(exit, Start::Final("prior child still exists".into()));
        // One reading sets the deadline; one more per check.
        assert_eq!(pauses, PRIOR_CHILD_WAIT_MS / 1_000 - 1);
    }

    /// #2016 review item 1: a prior child that ends during the wait does
    /// not stop the start (on macOS that refusal would hold until a stop).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_prior_child_that_ends_during_the_wait_is_not_a_refusal() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let mut prior = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        booting_with_child(&host, prior.id());
        let mut pauses = 0;
        let exit = start_with(
            &issued(host),
            &command(),
            || {},
            advancing_clock(),
            || false,
            || {
                pauses += 1;
                if pauses == 2 {
                    prior.kill().unwrap();
                    prior.wait().unwrap();
                }
            },
        );
        // Reaped in the pause; a second wait is a no-op error-free reap.
        let _ = prior.kill();
        let _ = prior.wait();
        assert_ne!(exit, Start::Final("prior child still exists".into()));
        assert!(pauses >= 2, "the start waited for the prior child");
    }

    /// A stop while the start waits for a prior child exits 0.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_stop_during_the_prior_child_wait_exits_0() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        booting_with_child(&host, std::process::id());
        let mut checks = 0;
        let exit = start_with(
            &issued(host),
            &command(),
            || {},
            advancing_clock(),
            || {
                checks += 1;
                checks > 2
            },
            || {},
        );
        assert_eq!(exit, Start::Exit(0));
    }

    /// #2016 review item 1: a final refusal leaves its reason in the host
    /// root for `x0x doctor` (0600, this process), and any later start that
    /// is not final removes it.
    #[test]
    fn a_final_refusal_is_recorded_until_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join(contract::REFUSAL_FILE_NAME);
        let refused = || Start::Final("prior child still exists".into());
        assert!(matches!(
            with_refusal_record(&root, refused),
            Start::Final(_)
        ));
        let record: contract::LauncherRefusal =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(record.reason, "prior child still exists");
        assert_eq!(record.pid, std::process::id());
        assert_eq!(
            record.process_start,
            contract::process_start(std::process::id()).unwrap()
        );
        assert_eq!(record.schema, contract::REFUSAL_SCHEMA);
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // The next start removes the record before it starts (and so
        // before it supervises a daemon), not when it returns.
        let started = with_refusal_record(&root, || {
            assert!(!path.exists(), "stale record while the daemon runs");
            Start::Exit(EXIT_TEMPFAIL)
        });
        assert!(matches!(started, Start::Exit(EXIT_TEMPFAIL)));
        assert!(!path.exists());
        // A root another account could write gets no record.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o772)).unwrap();
        with_refusal_record(&root, || Start::Final("x".into()));
        assert!(!path.exists());
    }

    #[test]
    fn a_final_hold_lasts_until_a_stop() {
        let mut checks = 0;
        let mut pauses = 0;
        hold_final(
            || {
                checks += 1;
                checks > 3
            },
            || pauses += 1,
        );
        assert_eq!(pauses, 3);
    }
}
