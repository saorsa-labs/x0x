//! Read-only GitHub release checks. Installation belongs to the daemon.
//!
//! The CLI dispatch sends apply requests through the authenticated daemon
//! client. This helper never installs. A CLI that is not beside `x0xd` is
//! outside that apply (#1104): the check reports it as not upgraded and
//! prints the reinstall hint. `--force` still compares versions before it
//! claims an update.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::upgrade::apply::{self, CLI_REINSTALL_HINT};
use crate::upgrade::monitor::UpgradeMonitor;
use crate::upgrade::UpgradeError;

const REPO: &str = "saorsa-labs/x0x";

/// Facts `x0x upgrade --check` can state without installing anything.
pub(crate) struct CheckFacts<'a> {
    pub cli_version: &'a str,
    pub cli_path: Option<&'a Path>,
    pub daemon_version: Option<&'a str>,
    pub release_version: Option<&'a str>,
    pub force: bool,
    /// Set when the release list has nothing newer and the release version was not fetched.
    pub already_current: bool,
}

/// Text of `x0x upgrade --check`, including a split-install report.
pub(crate) fn check_report(facts: &CheckFacts<'_>) -> String {
    let mut lines = Vec::new();
    lines.push(format!("x0x v{}", facts.cli_version));
    match facts.daemon_version {
        Some(version) => lines.push(format!("Daemon v{version}")),
        None => lines.push("Daemon version unavailable".to_string()),
    }
    if let Some(release) = facts.release_version {
        lines.push(format!("Release v{release}"));
    }

    let split_path = facts
        .cli_path
        .filter(|path| apply::cli_installed_apart_from_daemon(path));
    let version_differs = facts
        .daemon_version
        .filter(|daemon| *daemon != facts.cli_version);
    if split_path.is_some() || version_differs.is_some() {
        lines.push("CLI not upgraded".to_string());
        if let Some(path) = split_path {
            lines.push(format!(
                "{} is not beside {}.",
                path.display(),
                apply::daemon_file_name()
            ));
        }
        if let Some(daemon) = version_differs {
            lines.push(format!(
                "CLI v{} differs from daemon v{daemon}.",
                facts.cli_version
            ));
        }
        lines.push(CLI_REINSTALL_HINT.to_string());
    }

    if let Some(release) = facts.release_version {
        if release_is_newer(facts.cli_version, release) {
            lines.push(format!(
                "Update available: v{} → v{release}",
                facts.cli_version
            ));
            if split_path.is_some() {
                lines.push(
                    "The daemon apply does not upgrade a CLI installed apart from x0xd."
                        .to_string(),
                );
            } else {
                lines.push(
                    "Use `x0x upgrade --apply` to install through the running daemon.".to_string(),
                );
            }
        } else {
            lines.push(format!(
                "Already on the latest version (v{}).",
                facts.cli_version
            ));
            if facts.force {
                lines.push(format!(
                    "Release v{release} is not newer than v{}.",
                    facts.cli_version
                ));
            }
        }
    } else if facts.already_current {
        lines.push(format!(
            "Already on the latest version (v{}).",
            facts.cli_version
        ));
    }

    lines.join("\n")
}

/// True when `release` is a strictly newer semver than `current`.
/// An unparseable version is not an update (#1104).
pub(crate) fn release_is_newer(current: &str, release: &str) -> bool {
    match (
        semver::Version::parse(current),
        semver::Version::parse(release),
    ) {
        (Ok(current), Ok(release)) => release > current,
        _ => false,
    }
}

/// Check releases without a daemon; refuse standalone installation.
pub async fn run(check_only: bool, force: bool) -> Result<()> {
    if !check_only {
        anyhow::bail!(
            "Standalone upgrade installation is disabled to avoid replacing a live daemon. \
             Use authenticated POST /upgrade/apply on the running daemon \
             (Authorization: Bearer <api-token>); use `x0x upgrade --check` for a read-only check."
        );
    }

    let current = crate::VERSION;
    eprintln!("Checking for updates...");

    let cli_path = std::env::current_exe().ok();
    // The dispatch calls this helper before it builds a named-instance client.
    // The version here is the default instance only.
    let daemon_version = running_default_daemon_version().await;

    let monitor = UpgradeMonitor::new(REPO, "x0x", current)
        .map_err(|e| anyhow::anyhow!("failed to create upgrade monitor: {e}"))?;

    let mut release_version = None;
    let mut already_current = false;
    let mut missing_release = false;
    let mut fetch_error = None;

    if force {
        match monitor.fetch_current_manifest().await {
            Ok(Some(verified)) => release_version = Some(verified.manifest.version),
            Ok(None) => missing_release = true,
            Err(e) => fetch_error = Some(e),
        }
    } else {
        match monitor.check_for_updates().await {
            Ok(Some(verified)) => release_version = Some(verified.manifest.version),
            Ok(None) => already_current = true,
            Err(e) => fetch_error = Some(e),
        }
    }

    let report = check_report(&CheckFacts {
        cli_version: current,
        cli_path: cli_path.as_deref(),
        daemon_version: daemon_version.as_deref(),
        release_version: release_version.as_deref(),
        force,
        already_current,
    });
    eprintln!("{report}");
    if missing_release {
        eprintln!("No release found on GitHub.");
    }
    if let Some(error) = fetch_error {
        print_signature_recovery_hint(&error, current);
        return Err(if force {
            anyhow::anyhow!("failed to fetch release from GitHub: {error}")
        } else {
            anyhow::anyhow!("failed to check for updates: {error}")
        });
    }
    Ok(())
}

/// Read the default daemon version from loopback `/health`.
///
/// A missing port file or a daemon that does not answer is `None`. The check
/// still reports a split install. The request times out after 2 seconds.
async fn running_default_daemon_version() -> Option<String> {
    let port_path = dirs::data_dir()?.join("x0x").join("api.port");
    let addr = std::fs::read_to_string(port_path).ok()?;
    let addr = addr.trim();
    if addr.is_empty() || addr.len() > 128 || addr.contains(['/', ' ', '\\']) {
        return None;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let body: serde_json::Value = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    body.get("version")?.as_str().map(str::to_string)
}

/// If the error is a signature verification failure, print recovery instructions
/// so users on older builds with a mismatched signing key can still upgrade.
fn print_signature_recovery_hint(err: &UpgradeError, current: &str) {
    if !matches!(err, UpgradeError::ManifestSignatureInvalid) {
        return;
    }
    eprintln!();
    eprintln!("The release signature could not be verified with this binary's");
    eprintln!("embedded signing key. This typically means your x0x installation");
    eprintln!("(v{current}) predates a signing key update.");
    eprintln!();
    eprintln!("To update manually, run:");
    eprintln!();
    eprintln!(
        "  curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh"
    );
    eprintln!();
    eprintln!("Or install via cargo:");
    eprintln!();
    eprintln!("  cargo install x0x --force");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upgrade::UpgradeError;
    use std::path::PathBuf;

    #[test]
    fn print_signature_recovery_hint_prints_for_signature_error() {
        // Should not panic
        print_signature_recovery_hint(&UpgradeError::ManifestSignatureInvalid, "0.19.42");
    }

    #[test]
    fn print_signature_recovery_hint_skips_for_other_errors() {
        // Should not panic for non-signature errors
        print_signature_recovery_hint(
            &UpgradeError::ManifestFetchFailed("network error".to_string()),
            "0.19.42",
        );
    }

    // Inert architectural regression: installation must belong to the daemon's
    // authenticated upgrade transaction, never this standalone CLI module.
    #[test]
    fn standalone_upgrade_cannot_replace_or_restart_daemon() {
        let source = include_str!("upgrade.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [".perform_upgrade(", ".spawn(", "/shutdown"] {
            assert!(
                !production.contains(forbidden),
                "standalone upgrade must use POST /upgrade/apply, found {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn standalone_apply_refuses_before_io_even_with_force() {
        // No server, sockets, daemon, credentials, or release download needed.
        for force in [false, true] {
            let error = run(false, force).await.expect_err("apply must refuse");
            let message = error.to_string();
            assert!(message.contains("authenticated POST /upgrade/apply"));
            assert!(message.contains("api-token"));
            assert!(message.contains("x0x upgrade --check"));
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/issue-1104-tests");
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn split_cli_check_reports_not_upgraded_and_reinstall_hint() {
        let root = scratch("split-check");
        let dir_a = root.join("A");
        let dir_b = root.join("B");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        let daemon = dir_a.join(apply::daemon_file_name());
        let cli = dir_b.join(apply::cli_file_name());
        std::fs::write(&daemon, b"daemon").unwrap();
        std::fs::write(&cli, b"cli").unwrap();

        let report = check_report(&CheckFacts {
            cli_version: "1.2.0",
            cli_path: Some(&cli),
            daemon_version: Some("1.3.0"),
            release_version: Some("1.2.0"),
            force: true,
            already_current: false,
        });
        assert!(
            report.contains("CLI not upgraded"),
            "check must report the CLI as not upgraded: {report}"
        );
        assert!(
            report.contains(CLI_REINSTALL_HINT),
            "check must print the reinstall hint: {report}"
        );
        assert!(
            report.contains("is not beside"),
            "check must name the split install: {report}"
        );
        assert!(report.contains("x0x v1.2.0"), "{report}");
        assert!(report.contains("Daemon v1.3.0"), "{report}");
        assert!(report.contains("Release v1.2.0"), "{report}");
        assert!(
            report.contains("CLI v1.2.0 differs from daemon v1.3.0."),
            "{report}"
        );
        assert!(
            !report.contains("Update available"),
            "the release is not newer than this CLI: {report}"
        );
        assert!(
            report.contains("not newer"),
            "--force must compare versions: {report}"
        );
    }

    #[test]
    fn force_compares_versions_before_claiming_an_update() {
        let same = check_report(&CheckFacts {
            cli_version: "1.2.3",
            cli_path: None,
            daemon_version: Some("1.2.3"),
            release_version: Some("1.2.3"),
            force: true,
            already_current: false,
        });
        assert!(
            !same.contains("Update available"),
            "--force must not claim an update when the release is not newer: {same}"
        );
        assert!(
            same.contains("Already on the latest version (v1.2.3)."),
            "{same}"
        );
        assert!(
            same.contains("Release v1.2.3 is not newer than v1.2.3."),
            "{same}"
        );
        assert!(!same.contains("CLI not upgraded"), "{same}");

        let newer = check_report(&CheckFacts {
            cli_version: "1.0.0",
            cli_path: None,
            daemon_version: Some("1.0.0"),
            release_version: Some("1.1.0"),
            force: true,
            already_current: false,
        });
        assert!(
            newer.contains("Update available: v1.0.0 → v1.1.0"),
            "{newer}"
        );
        assert!(
            newer.contains("Use `x0x upgrade --apply` to install through the running daemon."),
            "{newer}"
        );
    }
}
