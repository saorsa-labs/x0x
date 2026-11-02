//! x0xd collects argv as OS strings (#1375): a non-UTF-8 argument must be
//! refused by the flag that consumes it, a `--config` value that is not
//! UTF-8 must name the file it names, and the daemon must survive argv
//! bytes that no flag consumes. Every test here spawns the real binary, so
//! every run is isolated (private `HOME`, no hard-coded bootstrap) and
//! bounded by a deadline: a regression must not join the live network, and
//! a hung daemon must not hang the test.
#![cfg(unix)]

use std::ffi::OsString;
use std::fs::File;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// How one run of the x0xd test binary ended.
struct X0xdRun {
    /// The child's exit status. At the deadline this is the status of the
    /// kill inside the helper, not a voluntary exit.
    status: ExitStatus,
    /// Whether the child was still alive at the deadline. For a survival
    /// test this is the expected shape: the daemon is serving.
    survived: bool,
    /// The child's stderr, read from the capture file after exit.
    stderr: String,
}

/// Run the x0xd test binary once: isolated, and with a deadline.
///
/// Isolation holds by construction, not by runner accident (#609): the
/// hard-coded bootstrap seeds are off, self-update is off, and `HOME` and
/// the XDG dirs point inside `home`, so a regression can read no operator
/// state and dial no peer. stdout and stderr go to files under `home`
/// (`<tag>.stdout` / `<tag>.stderr`), never pipes: a pipe fills, and then
/// the daemon blocks on its own log output.
fn run_x0xd(home: &Path, tag: &str, args: &[OsString]) -> X0xdRun {
    const DEADLINE_SECS: u64 = 30;
    const POLL_MILLIS: u64 = 100;

    let stderr_path = home.join(format!("{tag}.stderr"));
    let stdout = File::create(home.join(format!("{tag}.stdout"))).expect("create stdout file");
    let stderr = File::create(&stderr_path).expect("create stderr file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_x0xd"))
        .arg("--no-hard-coded-bootstrap")
        .arg("--skip-update-check")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("RUST_LOG")
        .spawn()
        .expect("spawn x0xd");

    // Poll, never block on wait: at the deadline a serving daemon is still
    // alive, so the helper kills it, collects its status, and reports that
    // it survived. The deadline is what keeps a hung daemon from hanging
    // the test.
    let deadline = Instant::now() + Duration::from_secs(DEADLINE_SECS);
    let (status, survived) = loop {
        if let Some(status) = child.try_wait().expect("poll x0xd") {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait().expect("reap the killed x0xd"), true);
        }
        std::thread::sleep(Duration::from_millis(POLL_MILLIS));
    };
    let stderr = std::fs::read(&stderr_path).expect("read the captured stderr");
    X0xdRun {
        status,
        survived,
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

#[test]
fn x0xd_refuses_a_non_utf8_instance_name_without_panicking() {
    let home = tempfile::tempdir().expect("tempdir");
    let raw = OsString::from_vec(b"alice\xff".to_vec());
    let run = run_x0xd(home.path(), "name", &["--name".into(), raw]);
    assert!(
        !run.status.success(),
        "the invalid name must be refused; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("panicked"),
        "argv collection must not panic; stderr: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("UTF-8"),
        "the refusal must name the encoding; stderr: {}",
        run.stderr
    );
}

/// #1375, review item 1: the old code silently fell back to the system
/// config when `--config` was not UTF-8, so the operator's named file was
/// never read. The fixed contract: the flag's raw value names the file it
/// names, losslessly, all the way into the operator-visible error.
#[test]
fn x0xd_loads_the_config_file_a_non_utf8_flag_names() {
    let home = tempfile::tempdir().expect("tempdir");
    let config = home
        .path()
        .join(OsString::from_vec(b"config\xff.toml".to_vec()));
    let argv = [
        "--config".into(),
        config.clone().into_os_string(),
        "--check".into(),
    ];

    // Linux can create the file, so its content is what refuses the boot
    // (ADR-0074 §3: a non-loopback `[socks]` listen). APFS refuses to
    // create a name that is not UTF-8, so off Linux the read fails and the
    // refusal must name the flag's own path. Either way the refusal can
    // only come from the file the flag named.
    #[cfg(target_os = "linux")]
    std::fs::write(&config, "[socks]\nlisten = \"0.0.0.0:1080\"\n").expect("write config");
    let run = run_x0xd(home.path(), "config", &argv);
    assert!(
        !run.status.success(),
        "the named file must decide the outcome; stderr: {}",
        run.stderr
    );
    #[cfg(target_os = "linux")]
    assert!(
        run.stderr.to_ascii_lowercase().contains("loopback"),
        "refused for the wrong reason; stderr: {}",
        run.stderr
    );
    #[cfg(not(target_os = "linux"))]
    assert!(
        run.stderr.contains("failed to read config file")
            && run.stderr.contains(config.display().to_string().as_str()),
        "the refusal must name the file the flag named, losslessly; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("/etc/x0x/config.toml"),
        "no silent fallback to the system config; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("panicked"),
        "a non-UTF-8 path must be refused, not panic; stderr: {}",
        run.stderr
    );
}

/// #1375, review item 2: an unknown argument is consumed by no flag parser,
/// so its raw bytes ride in argv for the whole process life. The first
/// identity announcement, built during `join_network`, reached
/// `relay_opt_in_explicit()`, which read argv with `std::env::args()` — a
/// panic on non-UTF-8 bytes at startup. With `args_os()` the daemon must
/// serve as if the unknown flag were absent: still alive at the deadline,
/// no panic on stderr. Red until the lib.rs fix lands.
#[test]
fn x0xd_survives_an_unknown_argument_that_is_not_utf8() {
    let home = tempfile::tempdir().expect("tempdir");
    let config = home.path().join("config.toml");
    // Inert config: off mDNS, no dials, ephemeral ports, and state inside
    // the run's own dir (#609: identity must not resolve under an inherited
    // home).
    std::fs::write(
        &config,
        format!(
            "mdns_enabled = false\n\
             bootstrap_peers = []\n\
             bind_address = \"0.0.0.0:0\"\n\
             api_address = \"127.0.0.1:0\"\n\
             data_dir = \"{}\"\n\
             identity_dir = \"{}\"\n",
            home.path().join("data").display(),
            home.path().join("identity").display(),
        ),
    )
    .expect("write config");
    let argv = [
        "--config".into(),
        config.into_os_string(),
        OsString::from_vec(b"--future-flag\xff".to_vec()),
    ];
    let run = run_x0xd(home.path(), "unknown-flag", &argv);
    assert!(
        run.survived,
        "the daemon must still be serving at the deadline; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("panicked"),
        "a non-UTF-8 argv must not panic during startup; stderr: {}",
        run.stderr
    );
}
