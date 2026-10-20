#![allow(clippy::expect_used)]

//! #1370: execute the production report-only decision with inert dependencies.
//!
//! The harness copies the exact reporter function, then instruments its two
//! dependencies: the monitor only returns an available version; the legacy
//! startup installer overwrites binary and SKILL sentinels. This checks the
//! reporter's writer decision without downloading or replacing any executable.
//! It does not claim to test manifest verification or the install transaction.

use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn reporter_source() -> &'static str {
    let source = include_str!("../src/server/mod.rs");
    let start = source
        .find("pub async fn run_update_check_and_report(")
        .expect("production reporter entry point");
    let function = &source[start..];
    let end = function.find("\n}\n").expect("reporter function end") + 2;
    &function[..end]
}

fn run_reporter_fixture(enabled: bool, skip: bool, prereleases: bool, outcome: &str) {
    let scratch = TempDir::new().expect("reporter fixture scratch");
    let binary = scratch.path().join("x0xd-sentinel");
    let skill = scratch.path().join("SKILL.md");
    std::fs::write(&binary, b"installed daemon bytes").expect("binary sentinel");
    std::fs::write(&skill, b"installed guide bytes").expect("SKILL sentinel");
    let source = scratch.path().join("reporter.rs");
    std::fs::write(
        &source,
        format!(
            "{}\n{}\n{}",
            FIXTURE_BEFORE,
            reporter_source(),
            FIXTURE_AFTER
        ),
    )
    .expect("write reporter fixture source");
    let executable = scratch.path().join("reporter-fixture");
    let compiled = Command::new("rustc")
        .args(["--edition=2021", "--crate-name", "upgrade_reporter_fixture"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile actual reporter function");
    assert!(
        compiled.status.success(),
        "reporter fixture must compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = Command::new(&executable)
        .arg(scratch.path())
        .arg(enabled.to_string())
        .arg(skip.to_string())
        .arg(prereleases.to_string())
        .arg(outcome)
        .output()
        .expect("execute production reporter decision");
    assert!(
        output.status.success() != (enabled && !skip && outcome == "error"),
        "reporter execution failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_unchanged(&binary, b"installed daemon bytes");
    assert_unchanged(&skill, b"installed guide bytes");
    let monitor_calls =
        std::fs::read_to_string(scratch.path().join("monitor-calls")).unwrap_or_default();
    if enabled && !skip {
        assert_eq!(monitor_calls, prereleases.to_string());
        match outcome {
            "available" => assert!(String::from_utf8_lossy(&output.stdout).contains("9.9.9")),
            "current" => assert!(String::from_utf8_lossy(&output.stdout).contains("up to date")),
            "error" => {
                assert!(String::from_utf8_lossy(&output.stderr).contains("monitor fixture failure"))
            }
            _ => unreachable!(),
        }
    } else {
        assert!(
            monitor_calls.is_empty(),
            "disabled/skipped check must not fetch"
        );
    }
}

fn assert_unchanged(path: &Path, expected: &[u8]) {
    assert_eq!(
        std::fs::read(path).expect("read sentinel after reporting"),
        expected,
        "--check-updates must not install {}",
        path.display()
    );
}

#[test]
fn daemon_check_updates_preserves_binary_and_skill_sentinels() {
    run_reporter_fixture(true, false, false, "available");
}

#[test]
fn daemon_check_updates_preserves_prerelease_selection_without_installing() {
    run_reporter_fixture(true, false, true, "available");
}

#[test]
fn daemon_check_updates_disabled_and_skip_do_not_fetch_or_write() {
    run_reporter_fixture(false, false, false, "available");
    run_reporter_fixture(true, true, false, "available");
}

#[test]
fn daemon_check_updates_current_and_error_do_not_install() {
    run_reporter_fixture(true, false, false, "current");
    run_reporter_fixture(true, false, false, "error");
}

const FIXTURE_BEFORE: &str = r#"
#![allow(dead_code, private_interfaces, unused_imports)]
use anyhow::Context;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, Wake, Waker};

mod anyhow {
    #[derive(Debug)]
    pub struct Error(String);
    impl Error {
        pub fn msg(message: impl std::fmt::Display) -> Self { Self(message.to_string()) }
    }
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
    }
    impl std::error::Error for Error {}
    pub type Result<T> = std::result::Result<T, Error>;
    pub trait Context<T> {
        fn context(self, message: &str) -> Result<T>;
    }
    impl<T> Context<T> for Result<T> {
        fn context(self, message: &str) -> Result<T> {
            self.map_err(|error| Error::msg(format!("{message}: {error}")))
        }
    }
}

struct UpdateConfig { enabled: bool, include_prereleases: bool, repo: String }
struct DaemonConfig { update: UpdateConfig }

fn scratch() -> PathBuf { std::env::args().nth(1).expect("scratch directory").into() }

async fn run_startup_update_check(
    config: &DaemonConfig,
    _: Option<()>,
    _: Option<()>,
) -> anyhow::Result<Option<String>> {
    let checked = x0x::upgrade::monitor::UpgradeMonitor::new(
        &config.update.repo, "x0xd", x0x::VERSION,
    ).map_err(anyhow::Error::msg)?.with_include_prereleases(config.update.include_prereleases)
        .check_for_updates().await?;
    if checked.is_none() { return Ok(None); }
    std::fs::write(scratch().join("x0xd-sentinel"), b"replacement daemon").expect("install spy");
    std::fs::write(scratch().join("SKILL.md"), b"replacement guide").expect("SKILL spy");
    Ok(Some("9.9.9".into()))
}

mod x0x {
    pub const VERSION: &str = "1.0.0";
    pub mod upgrade {
        pub mod monitor {
            pub struct UpgradeMonitor { prereleases: bool }
            pub struct Manifest { pub version: String }
            pub struct VerifiedRelease { pub manifest: Manifest }
            impl UpgradeMonitor {
                pub fn new(repo: &str, binary: &str, current: &str) -> Result<Self, String> {
                    assert_eq!(repo, "fixture/repository");
                    assert_eq!(binary, "x0xd");
                    assert_eq!(current, crate::x0x::VERSION);
                    Ok(Self { prereleases: false })
                }
                pub fn with_include_prereleases(mut self, value: bool) -> Self {
                    self.prereleases = value;
                    self
                }
                pub async fn check_for_updates(&self) -> crate::anyhow::Result<Option<VerifiedRelease>> {
                    std::fs::write(crate::scratch().join("monitor-calls"), self.prereleases.to_string())
                        .expect("read-only monitor call receipt");
                    match std::env::args().nth(5).expect("outcome").as_str() {
                        "current" => Ok(None),
                        "error" => Err(crate::anyhow::Error::msg("monitor fixture failure")),
                        "available" => Ok(Some(VerifiedRelease {
                            manifest: Manifest { version: "9.9.9".into() },
                        })),
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
}
"#;

const FIXTURE_AFTER: &str = r#"
struct NoopWake;
impl Wake for NoopWake { fn wake(self: Arc<Self>) {} }
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = DaemonConfig {
        update: UpdateConfig {
            enabled: args[2].parse().expect("enabled"),
            repo: "fixture/repository".into(),
            include_prereleases: args[4].parse().expect("prereleases"),
        },
    };
    let skip = args[3].parse().expect("skip");
    let future = run_update_check_and_report(&config, skip);
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = TaskContext::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(Ok(())) => {},
        Poll::Ready(Err(error)) => {
            eprintln!("{error}");
            std::process::exit(1);
        },
        Poll::Pending => panic!("inert reporter fixture unexpectedly needs I/O"),
    }
}
"#;
