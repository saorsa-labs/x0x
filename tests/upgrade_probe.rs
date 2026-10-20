#![allow(clippy::unwrap_used, clippy::expect_used)]

//! M2 S2d execution-probe regressions. These commands never start a daemon:
//! `--version` keeps the old daemon's missing-probe case on its early exit path.
//! Never remove that guard when testing a binary that may predate this feature.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

struct ProbeFixture {
    _root: TempDir,
    application_dirs: Vec<PathBuf>,
    profiles: PathBuf,
}

impl ProbeFixture {
    fn new() -> Self {
        // The nextest wrapper replaces HOME with /tmp/x0x-nextest-home.
        // Use the explicitly owned evidence root or the allowed repo scratch
        // directory, never that synthetic HOME or the system temp directory.
        let evidence = std::env::var_os("X0X_UPGRADE_PROBE_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join(".planning/upgrade-probe-fixtures")
            });
        std::fs::create_dir_all(&evidence).expect("probe evidence directory");
        let root = tempfile::Builder::new()
            .prefix("packaged-probe-")
            .tempdir_in(evidence)
            .expect("private probe fixture");
        let application_dirs = ["cwd", "home", "config", "data", "cache", "tmp", "heap"]
            .into_iter()
            .map(|name| {
                let path = root.path().join(name);
                std::fs::create_dir(&path).expect("empty application directory");
                path
            })
            .collect();
        let profiles = root.path().join("profiles");
        std::fs::create_dir(&profiles).expect("coverage output directory");
        Self {
            _root: root,
            application_dirs,
            profiles,
        }
    }

    fn command(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(&self.application_dirs[0])
            .env("HOME", &self.application_dirs[1])
            .env("X0X_HOME", &self.application_dirs[1])
            .env("USERPROFILE", &self.application_dirs[1])
            .env("XDG_CONFIG_HOME", &self.application_dirs[2])
            .env("APPDATA", &self.application_dirs[2])
            .env("XDG_DATA_HOME", &self.application_dirs[3])
            .env("LOCALAPPDATA", &self.application_dirs[3])
            .env("XDG_CACHE_HOME", &self.application_dirs[4])
            .env("TMPDIR", &self.application_dirs[5])
            .env("TMP", &self.application_dirs[5])
            .env("TEMP", &self.application_dirs[5])
            .env("DHAT_OUT_DIR", &self.application_dirs[6])
            // Instrumentation output belongs to the harness, not application
            // state. The upgrade probe must still bypass the heap profiler.
            .env(
                "LLVM_PROFILE_FILE",
                self.profiles.join("probe-%p-%m.profraw"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn assert_no_application_state(&self) {
        for directory in &self.application_dirs {
            assert_eq!(
                std::fs::read_dir(directory)
                    .expect("application state")
                    .count(),
                0,
                "inert probe created state under {}",
                directory.display()
            );
        }
    }
}

struct ReapedChild(Option<Child>);

impl Drop for ReapedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_inert(mut command: Command) -> Output {
    let mut child = ReapedChild(Some(command.spawn().expect("spawn inert command")));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child
            .0
            .as_mut()
            .unwrap()
            .try_wait()
            .expect("observe inert command")
            .is_some()
        {
            return child
                .0
                .take()
                .unwrap()
                .wait_with_output()
                .expect("collect inert command output");
        }
        assert!(
            Instant::now() < deadline,
            "inert command did not exit within 30 seconds"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_packaged_probe(binary: &str) {
    let fixture = ProbeFixture::new();
    let mut command = fixture.command(Path::new(binary));
    // Main lacks --upgrade-probe. The daemon nevertheless exits at --version,
    // before config, identity, stores, sockets, cleanup, or normal startup.
    command.args(["--upgrade-probe", "--version"]);
    let output = run_inert(command);
    assert!(
        output.status.success(),
        "{binary} probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("upgrade probe must return a structured version/platform response");
    assert_eq!(response["version"], x0x::VERSION);
    assert_eq!(
        response["platform"],
        x0x::upgrade::manifest::current_platform_target().expect("supported binary platform")
    );
    assert!(
        output.stderr.is_empty(),
        "probe initialized logging or profiling: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_no_application_state();
}

#[test]
fn packaged_daemon_upgrade_probe_reports_version_and_platform_without_state() {
    assert_packaged_probe(env!("CARGO_BIN_EXE_x0xd"));
}

#[test]
fn packaged_cli_upgrade_probe_reports_version_and_platform_without_state() {
    assert_packaged_probe(env!("CARGO_BIN_EXE_x0x"));
}

#[test]
fn packaged_version_mode_remains_an_inert_text_control() {
    for binary in [env!("CARGO_BIN_EXE_x0xd"), env!("CARGO_BIN_EXE_x0x")] {
        let fixture = ProbeFixture::new();
        let mut command = fixture.command(Path::new(binary));
        command.arg("--version");
        let output = run_inert(command);
        assert!(
            output.status.success(),
            "{binary} version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(x0x::VERSION));
        assert!(serde_json::from_slice::<serde_json::Value>(&output.stdout).is_err());
        // Existing --version may create a heap profile in all-features builds.
        // It must not create any configuration, identity, or store state.
        for directory in &fixture.application_dirs[..6] {
            assert_eq!(std::fs::read_dir(directory).unwrap().count(), 0);
        }
    }
}
