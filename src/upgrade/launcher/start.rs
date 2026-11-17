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
/// launcher as it ends a direct job. `stop` reads the stop flag.
pub(crate) fn start(
    command: &forward::DaemonCommand,
    arm: impl FnOnce(),
    stop: impl FnMut() -> bool,
) -> Start {
    if !ENABLED {
        return Start::Passthrough;
    }
    start_with(&NoIssuer, command, arm, stop, || {
        std::thread::sleep(std::time::Duration::from_millis(100))
    })
}

fn start_with(
    issuer: &impl Issuer,
    command: &forward::DaemonCommand,
    arm: impl FnOnce(),
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
    drive(&issued, &mut stop, pause)
}

/// Own this participant's trial for one start.
fn drive(issued: &Issued, stop: &mut impl FnMut() -> bool, pause: impl FnMut()) -> Start {
    let (path, mut trial) = match load(issued) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("x0x-launcher: trial: {error}");
            return Start::Exit(EXIT_TEMPFAIL);
        }
    };
    let supervised = supervise::supervise(&issued.host, &path, &mut trial, &mut *stop);
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

fn load(issued: &Issued) -> io::Result<(PathBuf, Trial)> {
    let participant = issued
        .host
        .plan()
        .participants
        .iter()
        .find(|p| p.instance_id == issued.instance)
        .ok_or_else(|| invalid("participant missing"))?;
    let path = coordinator::trial_path(participant);
    let trial = Trial::load(&path, &issued.host.binding()?, &issued.instance)?;
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
        assert_eq!(
            start(&command(), || armed = true, || false),
            Start::Passthrough
        );
        assert!(!armed);
    }

    #[test]
    fn no_issued_host_is_a_passthrough() {
        let none = Fixed(std::cell::RefCell::new(Some(Ok(None))));
        let mut armed = false;
        assert_eq!(
            start_with(&none, &command(), || armed = true, || false, || {}),
            Start::Passthrough
        );
        assert!(!armed, "a passthrough never catches a signal");
        assert_eq!(
            start_with(&NoIssuer, &command(), || {}, || false, || {}),
            Start::Passthrough
        );
    }

    /// An issuer error never falls back to a passthrough: the daemon could
    /// be a candidate outside its trial.
    #[test]
    fn an_issuer_error_is_a_retryable_exit() {
        let broken = Fixed(std::cell::RefCell::new(Some(Err(invalid("no inventory")))));
        assert_eq!(
            start_with(&broken, &command(), || {}, || false, || {}),
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
            start_with(&issued(host), &command(), || armed = true, || true, || {}),
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
            start_with(&issued(host), &command(), || {}, || false, || {}),
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
            start_with(&issued(host), &command(), || {}, || false, || {}),
            Start::Exit(EXIT_FINAL)
        );
    }

    #[test]
    fn a_missing_trial_is_a_retryable_exit() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        assert_eq!(
            start_with(&issued(host), &command(), || {}, || false, || {}),
            Start::Exit(EXIT_TEMPFAIL)
        );
    }
}
