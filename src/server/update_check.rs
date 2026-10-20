//! Report signed-release availability without entering the installer.

use super::{x0x, DaemonConfig};
use anyhow::Context;

/// CLI `--check-updates`: check the signed release, print its availability, and
/// return without serving. This path never installs binaries or SKILL.md;
/// installation belongs to the serving daemon's authenticated apply route.
pub async fn run_update_check_and_report(
    config: &DaemonConfig,
    skip_update_check: bool,
) -> anyhow::Result<()> {
    if config.update.enabled && !skip_update_check {
        let monitor =
            x0x::upgrade::monitor::UpgradeMonitor::new(&config.update.repo, "x0xd", x0x::VERSION)
                .map_err(anyhow::Error::msg)?
                .with_include_prereleases(config.update.include_prereleases);
        match monitor.check_for_updates().await {
            Ok(Some(release)) => {
                println!("x0xd update available: {}", release.manifest.version);
                println!("Use `x0x upgrade --apply` to install through the running daemon.");
            }
            Ok(None) => println!("x0xd is up to date ({})", x0x::VERSION),
            Err(e) => return Err(e).context("self-update check failed"),
        }
    } else if !config.update.enabled {
        println!("self-update checks are disabled by configuration");
    } else {
        println!("self-update check skipped by --skip-update-check");
    }
    Ok(())
}
