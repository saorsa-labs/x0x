//! Stable launcher (ADR 0094 §5). M2 trial ownership is held. In this
//! dormant mode the launcher becomes the daemon by `exec`, so a unit that
//! binds it keeps one process with direct-job signal and exit semantics.
//! No tracked unit binds it yet (see docs/upgrade-system.md).

#[cfg(unix)]
#[path = "../upgrade/launcher/mod.rs"]
mod launcher;

/// 64 is `EX_USAGE`: the unit supplied no daemon to run.
#[cfg(unix)]
const EXIT_USAGE: u8 = 64;
/// 75 is `EX_TEMPFAIL`: the manager restarts the job, as it does for a
/// direct unit whose daemon cannot exec.
#[cfg(unix)]
const EXIT_TEMPFAIL: u8 = launcher::start::EXIT_TEMPFAIL;

/// Set by SIGTERM or SIGINT: the manager asked for a stop.
#[cfg(unix)]
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
use std::sync::atomic::Ordering;

#[cfg(unix)]
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// 69 is `EX_UNAVAILABLE`: this host cannot run process custody.
#[cfg(not(unix))]
const EXIT_UNAVAILABLE: u8 = 69;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        let args = match launcher::issuer::launcher_argv(&argv) {
            Ok(args) => args,
            Err(error) => {
                eprintln!("x0x-launcher: {error}");
                return std::process::ExitCode::from(EXIT_USAGE);
            }
        };
        // SAFETY: the handler only stores a lock-free atomic flag.
        let arm = || unsafe {
            libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        };
        // The daemon install lock a trial-form passthrough read its records
        // under; the `exec` below closes it (#2012).
        let mut held = None;
        match launcher::start::start(&args, &mut held, arm, || STOP.load(Ordering::Relaxed)) {
            // launchd restarts every exit of a KeepAlive job, so a final
            // refusal holds until a stop instead (#1379). Its reason is in
            // the host root for `x0x doctor`.
            #[cfg(target_os = "macos")]
            launcher::start::Start::Final(_) => {
                eprintln!("x0x-launcher: holding until stopped (launchd would restart an exit)");
                launcher::start::hold_final(
                    || STOP.load(Ordering::Relaxed),
                    || std::thread::sleep(std::time::Duration::from_secs(1)),
                );
                return std::process::ExitCode::from(0);
            }
            #[cfg(not(target_os = "macos"))]
            launcher::start::Start::Final(_) => {
                return std::process::ExitCode::from(launcher::start::EXIT_FINAL);
            }
            launcher::start::Start::Exit(status) => return std::process::ExitCode::from(status),
            launcher::start::Start::Passthrough => {}
        }
        // launchd restarts every exit of a KeepAlive job, so a missing
        // daemon is waited for instead (#1379). systemd's start limit ends
        // its restarts, so there the exit stays.
        // Each `exec` happens under the install lock: a start that found no
        // daemon takes it first. While the daemon is missing the lock is
        // not held, so a producer or CLI apply never waits for this wait.
        let exec = |command: &launcher::forward::DaemonCommand| {
            if let Err(error) = launcher::start::relock(&args, &mut held) {
                return error;
            }
            let error = launcher::forward::exec_daemon(command);
            if launcher::forward::is_missing(&error) {
                held = None;
            }
            error
        };
        #[cfg(target_os = "macos")]
        let error = launcher::forward::exec_daemon_when_present(
            &args.command,
            exec,
            || STOP.load(Ordering::Relaxed),
            std::thread::sleep,
        );
        #[cfg(not(target_os = "macos"))]
        let error = {
            let mut exec = exec;
            exec(&args.command)
        };
        eprintln!(
            "x0x-launcher: cannot exec {}: {error}",
            args.command.executable.display()
        );
        std::process::ExitCode::from(EXIT_TEMPFAIL)
    }
    #[cfg(not(unix))]
    {
        eprintln!("x0x-launcher: process custody requires Unix");
        std::process::ExitCode::from(EXIT_UNAVAILABLE)
    }
}
