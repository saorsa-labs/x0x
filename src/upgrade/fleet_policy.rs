//! D184 rollout policy, derived from the tracked deployment authority.
//!
//! The caller supplies the independently resolved install and restart plan.
//! This policy does not discover the host's participants or grant apply
//! authority. Apply the receipt check before accepting an existing due receipt;
//! changing policy must not silently reset its frozen first-receipt history.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::restart::{RestartPlan, SystemdVerifiedUnit};

const FLEET_MINIMUM_MINUTES: u64 = 60;
const AUTHORITY: &str = include_str!("../../.deployment/authority-inventory.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Classification {
    Ordinary,
    Fleet,
    AmbiguousFleet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowPolicy {
    pub(crate) window_minutes: u64,
    pub(crate) minimum_window_minutes: u64,
    pub(crate) classification: Classification,
}

impl WindowPolicy {
    /// Compare the frozen window, not the chosen delay: a valid fleet delay
    /// can be zero. An older undersized window needs explicit handling, never
    /// an automatic receipt rewrite. D185's authenticated `now` is separate.
    pub(crate) fn check_receipt_window(self, recorded_window_minutes: u64) -> io::Result<()> {
        if recorded_window_minutes < self.minimum_window_minutes {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the recorded rollout window is below the current fleet minimum",
            ));
        }
        Ok(())
    }
}

/// Call with the same independently resolved plan/install used for admission.
/// A runtime argument or environment variable cannot select the rehearsal key.
pub(crate) fn effective_window(
    configured_minutes: u64,
    canonical_install: &Path,
    plan: &RestartPlan,
) -> io::Result<WindowPolicy> {
    effective_window_for_binding(
        configured_minutes,
        canonical_install,
        &plan.executable,
        plan.systemd_verified.as_ref(),
    )
}

/// Staging can identify a verified unit before its restart rate window ends.
/// This identity is never a grant to restart or replace an installed binary.
#[cfg(unix)]
pub(crate) fn effective_staging_window(
    configured_minutes: u64,
    canonical_install: &Path,
    identity: &super::restart::StagingIdentity,
) -> io::Result<WindowPolicy> {
    effective_window_for_binding(
        configured_minutes,
        canonical_install,
        &identity.executable,
        identity.systemd_verified.as_ref(),
    )
}

fn effective_window_for_binding(
    configured_minutes: u64,
    canonical_install: &Path,
    executable: &Path,
    service: Option<&SystemdVerifiedUnit>,
) -> io::Result<WindowPolicy> {
    if std::fs::canonicalize(canonical_install)? != canonical_install
        || std::fs::canonicalize(executable)? != canonical_install
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fleet policy requires the canonical install bound to the restart plan",
        ));
    }
    let authority = parse_authority(AUTHORITY)?;
    // These are Unix deployment destinations. Do not reinterpret `/opt` as a
    // current-drive path in the existing unmanaged Windows apply flow.
    #[cfg(unix)]
    let authority = resolve_authority(authority)?;

    let classification = classify(canonical_install, service, &authority);
    let window = policy(
        configured_minutes,
        classification,
        cfg!(all(feature = "upgrade-test-signing", debug_assertions)),
    );
    tracing::debug!(
        classification = ?window.classification,
        configured_minutes,
        effective_minutes = window.window_minutes,
        "Resolved rollout fleet policy"
    );
    Ok(window)
}

#[cfg(unix)]
fn resolve_authority(mut authority: Vec<FleetAuthority>) -> io::Result<Vec<FleetAuthority>> {
    for entry in &mut authority {
        entry.resolved_binary = match std::fs::canonicalize(&entry.binary) {
            Ok(path) => Some(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
    }
    Ok(authority)
}

fn policy(configured: u64, classification: Classification, rehearsal_key: bool) -> WindowPolicy {
    let minimum = if classification != Classification::Ordinary && !rehearsal_key {
        FLEET_MINIMUM_MINUTES
    } else {
        0
    };
    WindowPolicy {
        window_minutes: configured.max(minimum),
        minimum_window_minutes: minimum,
        classification,
    }
}

struct FleetAuthority {
    binary: PathBuf,
    resolved_binary: Option<PathBuf>,
    unit: String,
}

fn classify(
    install: &Path,
    service: Option<&SystemdVerifiedUnit>,
    authority: &[FleetAuthority],
) -> Classification {
    let mut positive = false;
    for entry in authority {
        let install_matches =
            install == entry.binary || entry.resolved_binary.as_deref() == Some(install);
        let unit_matches = service.is_some_and(|service| service.unit == entry.unit);
        if install_matches && unit_matches && service.is_some_and(|service| !service.user_manager) {
            return Classification::Fleet;
        }
        positive |= install_matches || unit_matches;
    }
    if positive {
        Classification::AmbiguousFleet
    } else {
        Classification::Ordinary
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u32,
    instances: Vec<Instance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    id: String,
    unit: Unit,
    config: Config,
    binary: Binary,
    installation: Installation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unit {
    source: String,
    destination: String,
    dropins: Vec<SourceDestination>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDestination {
    source: String,
    destination: String,
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Config {
    Tracked {
        destination: String,
        source: String,
    },
    Generated {
        destination: String,
        generator: String,
        input_instances: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binary {
    destination: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    entrypoint: String,
    selector_args: Vec<String>,
}

// The deployment-authority gate validates referenced repository artifacts.
// Recheck the embedded schema and the policy inputs here; do not maintain a
// second hard-coded list or require a source checkout on the running host.
fn parse_authority(bytes: &str) -> io::Result<Vec<FleetAuthority>> {
    let inventory: Inventory = serde_json::from_str(bytes).map_err(|_| invalid_authority())?;
    if inventory.schema_version != 1 || inventory.instances.is_empty() {
        return Err(invalid_authority());
    }
    let mut ids = BTreeSet::new();
    let mut units = BTreeSet::new();
    let mut result = Vec::new();
    for entry in &inventory.instances {
        let Some(unit) = entry.unit.destination.strip_prefix("/etc/systemd/system/") else {
            return Err(invalid_authority());
        };
        if entry.id.is_empty()
            || !ids.insert(entry.id.as_str())
            || !units.insert(unit)
            || !unit.ends_with(".service")
            || unit.len() <= ".service".len()
            || unit.contains('/')
            || !relative_path(unit)
            || !relative_path(&entry.unit.source)
            || !absolute_path(&entry.binary.destination)
            || !relative_path(&entry.installation.entrypoint)
            || !(entry.installation.selector_args.is_empty()
                || entry.installation.selector_args == ["--instance", entry.id.as_str()])
        {
            return Err(invalid_authority());
        }
        for dropin in &entry.unit.dropins {
            if !relative_path(&dropin.source)
                || !absolute_path(&dropin.destination)
                || !dropin
                    .destination
                    .starts_with(&format!("{}.d/", entry.unit.destination))
            {
                return Err(invalid_authority());
            }
        }
        match &entry.config {
            Config::Tracked {
                destination,
                source,
            } if absolute_path(destination) && relative_path(source) => {}
            Config::Generated {
                destination,
                generator,
                input_instances,
            } if absolute_path(destination)
                && relative_path(generator)
                && !input_instances.is_empty()
                && input_instances.iter().all(|id| {
                    inventory
                        .instances
                        .iter()
                        .any(|instance| instance.id == *id && instance.id != entry.id)
                }) => {}
            _ => return Err(invalid_authority()),
        }
        result.push(FleetAuthority {
            binary: PathBuf::from(&entry.binary.destination),
            resolved_binary: None,
            unit: unit.to_owned(),
        });
    }
    Ok(result)
}

fn absolute_path(path: &str) -> bool {
    path.starts_with('/') && relative_path(&path[1..])
}

fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\0'])
        && path
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
}

fn invalid_authority() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid embedded deployment authority for fleet rollout",
    )
}

#[cfg(test)]
include!("../../tests/upgrade_fleet.rs");
#[cfg(test)]
fleet_policy_regression_tests!();
