//! Stable launcher (ADR 0094 §5). M2 trial ownership is held. In this
//! dormant mode the launcher becomes the daemon by `exec`, so a unit that
//! binds it keeps one process with direct-job signal and exit semantics.
//! No tracked unit binds it yet (see docs/upgrade-system.md).

#[cfg(unix)]
#[path = "../upgrade/launcher/mod.rs"]
mod launcher;

/// 64 is `EX_USAGE`: the unit supplied no daemon to run.
const EXIT_USAGE: u8 = 64;
/// 75 is `EX_TEMPFAIL`: the manager restarts the job, as it does for a
/// direct unit whose daemon cannot exec.
const EXIT_TEMPFAIL: u8 = 75;
/// 69 is `EX_UNAVAILABLE`: this host cannot run process custody.
#[cfg(not(unix))]
const EXIT_UNAVAILABLE: u8 = 69;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        let command = match launcher::forward::daemon_argv(&argv) {
            Ok(command) => command,
            Err(error) => {
                eprintln!("x0x-launcher: {error}");
                return std::process::ExitCode::from(EXIT_USAGE);
            }
        };
        let error = launcher::forward::exec_daemon(&command);
        eprintln!(
            "x0x-launcher: cannot exec {}: {error}",
            command.executable.display()
        );
        std::process::ExitCode::from(EXIT_TEMPFAIL)
    }
    #[cfg(not(unix))]
    {
        eprintln!("x0x-launcher: process custody requires Unix");
        std::process::ExitCode::from(EXIT_UNAVAILABLE)
    }
}
