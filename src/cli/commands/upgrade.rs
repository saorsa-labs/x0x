//! Read-only GitHub release checks. Installation belongs to the daemon.
//!
//! The CLI dispatch sends apply requests through the authenticated daemon
//! client. This helper never installs. After apply, and on `--check`, a CLI
//! that is not beside `x0xd` and is older than that daemon prints
//! "CLI not upgraded" and a CLI-only reinstall hint (#1104). `--name` selects
//! that instance's daemon. `--force` compares semver before it claims an update.

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
    // The hint is only for a split CLI that is older than the selected daemon.
    // A CLI beside x0xd is replaced by apply, so it must not see this hint.
    // A newer CLI must not be described as "CLI not upgraded".
    let cli_older_than_daemon = facts
        .daemon_version
        .filter(|daemon| release_is_newer(facts.cli_version, daemon));
    if let (Some(path), Some(daemon)) = (split_path, cli_older_than_daemon) {
        lines.extend(cli_not_upgraded_lines(path, facts.cli_version, daemon));
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

fn cli_not_upgraded_lines(cli_path: &Path, cli_version: &str, daemon_version: &str) -> Vec<String> {
    vec![
        "CLI not upgraded".to_string(),
        format!(
            "{} is not beside {}.",
            cli_path.display(),
            apply::daemon_file_name()
        ),
        format!("CLI v{cli_version} is older than daemon v{daemon_version}."),
        CLI_REINSTALL_HINT.to_string(),
    ]
}

/// Notice after apply when this CLI is apart from `x0xd` and older than the
/// applied `version`. The response body is unchanged (#1104).
pub fn split_cli_notice_after_apply(response: &serde_json::Value) -> Option<String> {
    let applied_version = applied_release_version(response)?;
    let cli_path = std::env::current_exe().ok()?;
    split_cli_notice(Some(cli_path.as_path()), crate::VERSION, applied_version)
}

pub(crate) fn split_cli_notice(
    cli_path: Option<&Path>,
    cli_version: &str,
    applied_version: &str,
) -> Option<String> {
    let path = cli_path.filter(|path| apply::cli_installed_apart_from_daemon(path))?;
    if !release_is_newer(cli_version, applied_version) {
        return None;
    }
    Some(cli_not_upgraded_lines(path, cli_version, applied_version).join("\n"))
}

fn applied_release_version(response: &serde_json::Value) -> Option<&str> {
    if response.get("applied").and_then(|value| value.as_bool()) != Some(true) {
        return None;
    }
    response.get("version").and_then(|value| value.as_str())
}

/// True when `release` is a strictly newer semver than `current`.
/// An unparseable version is not an update (#1104).
pub(crate) fn release_is_newer(current: &str, release: &str) -> bool {
    crate::upgrade::manifest::is_newer(release, current)
}

/// Check releases without installing; refuse standalone installation.
///
/// `instance` is the global `--name` value. The daemon version comes from
/// that instance's `api.port`, not the default instance.
pub async fn run(check_only: bool, force: bool, instance: Option<&str>) -> Result<()> {
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
    let daemon_version = running_daemon_version(instance).await;

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

pub(crate) fn api_port_file(data_dir: &Path, instance: Option<&str>) -> std::path::PathBuf {
    let dir_name = match instance {
        Some(name) => format!("x0x-{name}"),
        None => "x0x".to_string(),
    };
    data_dir.join(dir_name).join("api.port")
}

pub(crate) fn health_addr_allowed(addr: &str) -> bool {
    !addr.is_empty() && addr.len() <= 128 && !addr.contains(['/', ' ', '\\'])
}

pub(crate) fn version_from_health_body(bytes: &[u8]) -> Option<String> {
    const HEALTH_BODY_CAP: usize = 16 * 1024;
    if bytes.len() > HEALTH_BODY_CAP {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let version = body.get("version")?.as_str()?;
    if version.is_empty() || version.len() > 128 || version.chars().any(char::is_control) {
        return None;
    }
    Some(version.to_string())
}

/// Read one daemon's version from its `api.port` and loopback `/health`.
///
/// A missing port file or a daemon that does not answer is `None`. The
/// request carries no token and times out after 2 seconds.
async fn running_daemon_version(instance: Option<&str>) -> Option<String> {
    let port_path = api_port_file(&dirs::data_dir()?, instance);
    let addr = std::fs::read_to_string(port_path).ok()?;
    let addr = addr.trim();
    if !health_addr_allowed(addr) {
        return None;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let bytes = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .bytes()
        .await
        .ok()?;
    version_from_health_body(&bytes)
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

    fn layout(root: &std::path::Path, split: bool) -> PathBuf {
        let daemon_dir = root.join("A");
        let cli_dir = if split {
            root.join("B")
        } else {
            daemon_dir.clone()
        };
        std::fs::create_dir_all(&daemon_dir).unwrap();
        std::fs::create_dir_all(&cli_dir).unwrap();
        std::fs::write(daemon_dir.join(apply::daemon_file_name()), b"d").unwrap();
        let cli = cli_dir.join(apply::cli_file_name());
        std::fs::write(&cli, b"c").unwrap();
        cli
    }

    fn report(
        cli_path: Option<&std::path::Path>,
        cli: &str,
        daemon: &str,
        release: &str,
        force: bool,
    ) -> String {
        check_report(&CheckFacts {
            cli_version: cli,
            cli_path,
            daemon_version: Some(daemon),
            release_version: Some(release),
            force,
            already_current: false,
        })
    }
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
            let error = run(false, force, None)
                .await
                .expect_err("apply must refuse");
            let message = error.to_string();
            assert!(message.contains("authenticated POST /upgrade/apply"));
            assert!(message.contains("api-token"));
            assert!(message.contains("x0x upgrade --check"));
        }
    }

    #[test]
    fn issue1104_split_cli_check_reports_not_upgraded_and_reinstall_hint() {
        let root = tempfile::tempdir().unwrap();
        let cli = layout(root.path(), true);
        let report = report(Some(&cli), "1.2.0", "1.3.0", "1.2.0", true);
        assert!(
            report.contains("CLI not upgraded") && report.contains("is not beside"),
            "{report}"
        );
        assert!(
            report.contains(CLI_REINSTALL_HINT) && !report.contains("install.sh"),
            "{report}"
        );
        assert!(
            report.contains("x0x v1.2.0") && report.contains("Daemon v1.3.0"),
            "{report}"
        );
        assert!(report.contains("Release v1.2.0"), "{report}");
        assert!(
            report.contains("CLI v1.2.0 is older than daemon v1.3.0."),
            "{report}"
        );
        assert!(
            !report.contains("Update available") && report.contains("not newer"),
            "{report}"
        );
        assert!(!report.contains("Use `x0x upgrade --apply`"), "{report}");
    }

    #[test]
    fn issue1104_split_install_with_update_available_omits_apply_command() {
        let root = tempfile::tempdir().unwrap();
        let cli = layout(root.path(), true);
        let report = report(Some(&cli), "1.0.0", "1.2.0", "1.3.0", false);
        assert!(
            report.contains("CLI not upgraded") && report.contains(CLI_REINSTALL_HINT),
            "{report}"
        );
        assert!(
            report.contains("Update available: v1.0.0 → v1.3.0"),
            "{report}"
        );
        assert!(
            report.contains("The daemon apply does not upgrade a CLI installed apart from x0xd."),
            "{report}"
        );
        assert!(!report.contains("Use `x0x upgrade --apply`"), "{report}");
    }

    #[test]
    fn issue1104_beside_daemon_version_mismatch_has_no_reinstall_hint() {
        let root = tempfile::tempdir().unwrap();
        let cli = layout(root.path(), false);
        let older = report(Some(&cli), "1.0.0", "1.5.0", "1.5.0", false);
        assert!(
            !older.contains("CLI not upgraded") && !older.contains(CLI_REINSTALL_HINT),
            "{older}"
        );
        assert!(
            older.contains("Use `x0x upgrade --apply` to install through the running daemon."),
            "{older}"
        );
        let newer_cli = report(Some(&cli), "2.0.0", "1.0.0", "2.0.0", true);
        assert!(
            !newer_cli.contains("CLI not upgraded") && !newer_cli.contains(CLI_REINSTALL_HINT),
            "{newer_cli}"
        );
        assert!(
            !newer_cli.contains("Use `x0x upgrade --apply`"),
            "{newer_cli}"
        );
    }

    #[test]
    fn issue1104_apply_notice_when_split_cli_is_older() {
        let root = tempfile::tempdir().unwrap();
        let cli = layout(root.path(), true);
        let response = serde_json::json!({"applied": true, "version": "1.4.0"});
        let applied = applied_release_version(&response).expect("version");
        let notice = split_cli_notice(Some(&cli), "1.0.0", applied).expect("notice");
        assert!(notice.contains("CLI not upgraded"), "{notice}");
        assert!(
            notice.contains("cargo install x0x --bin x0x --force"),
            "{notice}"
        );
        assert!(
            !notice.contains("install.sh") && !notice.contains("cargo install x0x --force"),
            "{notice}"
        );
        assert!(split_cli_notice(Some(&cli), "1.4.0", applied).is_none());
        assert!(split_cli_notice(Some(&cli), "2.0.0", applied).is_none());
        let beside = layout(root.path(), false);
        assert!(split_cli_notice(Some(&beside), "1.0.0", applied).is_none());
        assert!(applied_release_version(&serde_json::json!({"applied": false})).is_none());
    }

    #[test]
    fn issue1104_named_instance_port_file_is_not_the_default() {
        let root = tempfile::tempdir().unwrap();
        let default_port = api_port_file(root.path(), None);
        let named_port = api_port_file(root.path(), Some("alice"));
        assert_eq!(
            default_port,
            root.path().join("x0x").join("api.port"),
            "{default_port:?}"
        );
        assert_eq!(
            named_port,
            root.path().join("x0x-alice").join("api.port"),
            "{named_port:?}"
        );
        assert_ne!(default_port, named_port);
    }

    #[test]
    fn issue1104_health_body_yields_version_and_rejects_bad_input() {
        assert!(health_addr_allowed("127.0.0.1:12700"));
        assert!(!health_addr_allowed(""));
        assert!(!health_addr_allowed("127.0.0.1:12700/health"));
        assert_eq!(
            version_from_health_body(br#"{"ok":true,"version":"1.2.3"}"#).as_deref(),
            Some("1.2.3")
        );
        assert!(version_from_health_body(br#"{"version":"1.2.3\n"}"#).is_none());
        let huge = vec![b'{'; 16 * 1024 + 1];
        assert!(version_from_health_body(&huge).is_none());
    }

    #[test]
    fn issue1104_force_compares_versions_before_claiming_an_update() {
        let same = report(None, "1.2.3", "1.2.3", "1.2.3", true);
        assert!(
            !same.contains("Update available") && !same.contains("CLI not upgraded"),
            "{same}"
        );
        assert!(
            same.contains("Already on the latest version (v1.2.3)."),
            "{same}"
        );
        assert!(
            same.contains("Release v1.2.3 is not newer than v1.2.3."),
            "{same}"
        );
        let newer = report(None, "1.0.0", "1.0.0", "1.1.0", true);
        assert!(
            newer.contains("Update available: v1.0.0 → v1.1.0"),
            "{newer}"
        );
        assert!(
            newer.contains("Use `x0x upgrade --apply` to install through the running daemon."),
            "{newer}"
        );
        assert!(!newer.contains(CLI_REINSTALL_HINT), "{newer}");
    }
}
