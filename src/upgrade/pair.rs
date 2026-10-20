//! Test-only facade over the released single-binary replacement primitives.
//!
//! This establishes the S2e regression contract without wiring a new installer.
//! The legacy path has neither a pair journal nor protected versioned backups.
//! Replace this facade with the dormant pair engine only after hosted RED.
#![cfg(test)]
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use x0x::upgrade::{UpgradeResult, Upgrader};

#[derive(Debug, Clone)]
pub(crate) struct BinaryInput {
    pub target: PathBuf,
    pub staged: PathBuf,
    pub previous_version: String,
    pub previous_sha256: [u8; 32],
    pub candidate_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub(crate) enum CliInput {
    Managed(BinaryInput),
    Split {
        path: Option<PathBuf>,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct SkillInput {
    pub target: PathBuf,
    pub staged: PathBuf,
    pub candidate_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeBinding {
    pub transaction_id: String,
    pub daemon_sha256: [u8; 32],
    pub cli_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub(crate) struct PairRequest {
    pub install: PathBuf,
    pub candidate_version: String,
    pub manifest_sha256: [u8; 32],
    pub daemon: BinaryInput,
    pub cli: CliInput,
    pub skill: Option<SkillInput>,
    pub probe: ProbeBinding,
}

#[derive(Debug, Clone)]
pub(crate) struct PairReceipt {
    pub transaction_id: String,
    pub journal_path: PathBuf,
    pub daemon_backup: PathBuf,
    pub cli_backup: Option<PathBuf>,
    pub staged_skill: Option<PathBuf>,
    pub cli_untouched: bool,
}

#[derive(Debug)]
pub(crate) enum PairOutcome {
    Swapped(PairReceipt),
    Restored {
        receipt: PairReceipt,
        reason: String,
    },
    AlreadyCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairRefusal {
    InsufficientDisk,
    InstalledChanged,
    CandidateChanged,
    Unresolved,
    InvalidPlan,
    Cancelled,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PairError {
    #[error("pair refused ({cause:?}): {reason}")]
    Refused { cause: PairRefusal, reason: String },
    #[error("pair recovery-failed for {transaction_id}: {reason}")]
    RecoveryFailed {
        transaction_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairRole {
    Daemon,
    Cli,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairStep {
    BeforeSwap(PairRole),
    AfterSwapRename(PairRole),
    BeforeRestore(PairRole),
    AfterRestoreRename(PairRole),
    BeforePreparedRecord,
    BeforeRestoredRecord,
}

#[derive(Debug, Default)]
pub(crate) struct PairOptions {
    pub available_bytes: Option<u64>,
    pub cli_first: bool,
    pub fail_at: Option<PairStep>,
}

pub(crate) fn pair_record_path(install: &Path) -> std::io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(install)?;
    let mut name = canonical
        .file_name()
        .ok_or_else(|| std::io::Error::other("install has no filename"))?
        .to_os_string();
    name.push(".upgrade-pair.json");
    Ok(canonical.with_file_name(name))
}

pub(crate) fn execute_pair(
    request: &PairRequest,
    caller_alive: &AtomicBool,
) -> Result<PairOutcome, PairError> {
    execute_pair_with_options(request, caller_alive, &PairOptions::default())
}

pub(crate) fn execute_pair_with_options(
    request: &PairRequest,
    caller_alive: &AtomicBool,
    options: &PairOptions,
) -> Result<PairOutcome, PairError> {
    if !caller_alive.load(Ordering::Acquire) {
        return Err(PairError::Refused {
            cause: PairRefusal::Cancelled,
            reason: "caller cancelled".into(),
        });
    }
    let target_version =
        semver::Version::parse(&request.candidate_version).map_err(legacy_error)?;
    let receipt = PairReceipt {
        transaction_id: uuid::Uuid::new_v4().to_string(),
        journal_path: pair_record_path(&request.install).map_err(legacy_error)?,
        daemon_backup: request.daemon.target.with_extension("backup"),
        cli_backup: match &request.cli {
            CliInput::Managed(cli) => Some(cli.target.with_extension("backup")),
            CliInput::Split { .. } => None,
        },
        staged_skill: None,
        cli_untouched: matches!(request.cli, CliInput::Split { .. }),
    };

    // Mirror the released auto-apply ordering: CLI first; its error does not
    // prevent the daemon attempt. No pair-wide rollback is performed here.
    if let CliInput::Managed(cli) = &request.cli {
        let _ = legacy_replace(cli, PairRole::Cli, &target_version, options);
    }
    match legacy_replace(&request.daemon, PairRole::Daemon, &target_version, options)? {
        UpgradeResult::Success { .. } => Ok(PairOutcome::Swapped(receipt)),
        UpgradeResult::RolledBack { reason } => Ok(PairOutcome::Restored { receipt, reason }),
        UpgradeResult::NoUpgrade => Ok(PairOutcome::AlreadyCandidate),
    }
}

fn legacy_replace(
    input: &BinaryInput,
    role: PairRole,
    version: &semver::Version,
    options: &PairOptions,
) -> Result<UpgradeResult, PairError> {
    let previous = semver::Version::parse(&input.previous_version).map_err(legacy_error)?;
    if options.fail_at == Some(PairStep::BeforeSwap(role)) {
        // Remove the real staged input at this boundary. The released
        // primitive itself must encounter and report the filesystem failure;
        // the facade does not synthesize a failed upgrade result.
        std::fs::remove_file(&input.staged).map_err(legacy_error)?;
    }
    Upgrader::new(input.target.clone(), previous)
        .perform_upgrade(&input.staged, version)
        .map_err(legacy_error)
}

fn legacy_error(error: impl std::fmt::Display) -> PairError {
    PairError::Refused {
        cause: PairRefusal::InvalidPlan,
        reason: error.to_string(),
    }
}
