//! Read-only GitHub release checks. Installation belongs to the daemon.
//!
//! Standalone applies are refused before any I/O: daemon discovery cannot
//! prove that no instance is using the installed binary. `x0x upgrade
//! --apply [--now]` delegates to the running daemon's authenticated
//! `POST /upgrade/apply` (ADR 0094 §1); it never writes a binary itself.

use anyhow::Result;

use crate::cli::{print_value, DaemonClient};
use crate::upgrade::monitor::UpgradeMonitor;
use crate::upgrade::UpgradeError;

const REPO: &str = "saorsa-labs/x0x";

/// Check releases without a daemon; refuse standalone installation.
pub async fn run(check_only: bool, force: bool) -> Result<()> {
    if !check_only {
        anyhow::bail!(
            "Standalone upgrade installation is disabled to avoid replacing a live daemon. \
             Use `x0x upgrade --apply` (authenticated POST /upgrade/apply on the running daemon, \
             Authorization: Bearer <api-token>); use `x0x upgrade --check` for a read-only check."
        );
    }

    let current = crate::VERSION;
    eprintln!("x0x v{current}");
    eprintln!("Checking for updates...");

    let monitor = UpgradeMonitor::new(REPO, "x0x", current)
        .map_err(|e| anyhow::anyhow!("failed to create upgrade monitor: {e}"))?;

    // If --force, we fetch the current manifest regardless of version comparison.
    let verified = if force {
        match monitor.fetch_current_manifest().await {
            Ok(v) => v,
            Err(e) => {
                print_signature_recovery_hint(&e, current);
                return Err(anyhow::anyhow!("failed to fetch release from GitHub: {e}"));
            }
        }
    } else {
        match monitor.check_for_updates().await {
            Ok(Some(v)) => Some(v),
            Ok(None) => {
                eprintln!("Already on the latest version (v{current}).");
                return Ok(());
            }
            Err(e) => {
                print_signature_recovery_hint(&e, current);
                return Err(anyhow::anyhow!("failed to check for updates: {e}"));
            }
        }
    };

    let verified = match verified {
        Some(v) => v,
        None => {
            eprintln!("No release found on GitHub.");
            return Ok(());
        }
    };

    let new_version = &verified.manifest.version;

    eprintln!("Update available: v{current} → v{new_version}");
    eprintln!("Use authenticated POST /upgrade/apply on the running daemon to install.");

    Ok(())
}

/// `x0x upgrade --apply [--now]`: ask the running daemon to apply the latest
/// verified release through its authenticated `POST /upgrade/apply`. The
/// daemon applies after its staged-rollout wait; `now` sends `now=true`
/// (D185), which skips the wait for this host only.
pub async fn apply_via_daemon(client: &DaemonClient, now: bool) -> Result<()> {
    let path = if now {
        "/upgrade/apply?now=true"
    } else {
        "/upgrade/apply"
    };
    let resp = client.post_empty(path).await?;
    print_value(client.format(), &resp);
    Ok(())
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
    eprintln!("  curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh");
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
}
