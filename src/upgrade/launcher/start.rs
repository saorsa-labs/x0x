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

/// What one launcher start decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Start {
    /// No trial authority: become the daemon by `exec`.
    Passthrough,
    /// The launcher owned the start and now exits with this status.
    Exit(u8),
}

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
pub(crate) fn start(
    args: &issuer::LauncherArgs,
    arm: impl FnOnce(),
    stop: impl FnMut() -> bool,
) -> Start {
    if !ENABLED {
        return Start::Passthrough;
    }
    let pause = || std::thread::sleep(std::time::Duration::from_millis(100));
    match &args.trial {
        None => start_with(&NoIssuer, &args.command, arm, Clock::now, stop, pause),
        Some(trial) => start_with(
            &issuer::JournalIssuer(trial),
            &args.command,
            arm,
            Clock::now,
            stop,
            pause,
        ),
    }
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
    now: impl FnMut() -> io::Result<Clock>,
    stop: &mut impl FnMut() -> bool,
    pause: impl FnMut(),
) -> Start {
    let (path, mut trial) = match load(issued) {
        Ok(loaded) => loaded,
        Err(Refusal::Final(reason)) => {
            eprintln!("x0x-launcher: no automatic start: {reason}");
            return Start::Exit(EXIT_FINAL);
        }
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
        Ok(Supervised::Final(phase)) => {
            eprintln!("x0x-launcher: no automatic start: host is {phase:?}");
            Start::Exit(EXIT_FINAL)
        }
        Err(error) => {
            eprintln!("x0x-launcher: trial: {error}");
            // A RecoveryFailed trial forbids every automatic start; a
            // restart would only repeat the refusal.
            let final_trial = Trial::load(&path, &trial.binding, &issued.instance)
                .map(|on_disk| on_disk.phase == Phase::RecoveryFailed)
                .unwrap_or(trial.phase == Phase::RecoveryFailed);
            Start::Exit(if final_trial {
                EXIT_FINAL
            } else {
                EXIT_TEMPFAIL
            })
        }
    }
}

/// Why a start cannot load its trial.
enum Refusal {
    /// A restart would refuse the same way: no automatic start.
    Final(&'static str),
    /// A later start may succeed (an I/O error, a trial not yet written).
    Retry(io::Error),
}

/// Load this participant's trial, after the refusals that no restart can
/// change (#2006 review): a participant missing from the plan, a stopped
/// participant (it stays stopped), and a prior child that still runs (the
/// manager must remove the old process group before any start; restarting
/// until the start limit would not change that).
fn load(issued: &Issued) -> Result<(PathBuf, Trial), Refusal> {
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
        if !child::absent(identity).map_err(Refusal::Retry)? {
            return Err(Refusal::Final("prior child still exists"));
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
            }),
            command: command(),
        };
        assert_eq!(start(&args, || armed = true, || false), Start::Passthrough);
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
        assert_eq!(
            start_with(
                &issued(host),
                &command(),
                || {},
                Clock::now,
                || false,
                || {}
            ),
            Start::Exit(EXIT_FINAL)
        );
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
        assert_eq!(exit, Start::Exit(EXIT_FINAL));
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
        assert_eq!(
            start_with(
                &issued(host),
                &command(),
                || {},
                Clock::now,
                || false,
                || {}
            ),
            Start::Exit(EXIT_FINAL)
        );
    }

    #[test]
    fn a_missing_participant_is_a_final_exit() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let other = Fixed(std::cell::RefCell::new(Some(Ok(Some(Issued {
            host,
            instance: "nobody".into(),
        })))));
        assert_eq!(
            start_with(&other, &command(), || {}, Clock::now, || false, || {}),
            Start::Exit(EXIT_FINAL)
        );
    }

    /// A prior child that still runs (here: this test process) is final.
    /// Process identity needs Linux procfs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_surviving_prior_child_is_a_final_exit() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = trial_at(&host, &[Phase::Authorized]);
        let binding = host.binding().unwrap();
        let mut trial = Trial::load(&path, &binding, "alice").unwrap();
        trial.attempts = 1;
        trial.child = Some(child::identity(std::process::id()).unwrap());
        trial.phase = Phase::Booting;
        trial.save(&path).unwrap();
        assert_eq!(
            start_with(
                &issued(host),
                &command(),
                || {},
                Clock::now,
                || false,
                || {}
            ),
            Start::Exit(EXIT_FINAL)
        );
    }
}
