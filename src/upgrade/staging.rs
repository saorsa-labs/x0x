//! Durable rollout receipts for one participant and release (ADR 0094 §1).
//!
//! The caller verifies release eligibility and holds the existing canonical
//! install lock throughout each observation. It releases that lock while
//! waiting. A receipt does not prove host inventory completeness or authorize
//! a swap: every participant, hold and transaction check still applies.
#![cfg(unix)]

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::journal;
use super::probe::ProbeClock;
use super::rollout::StagedRollout;

const SCHEMA_VERSION: u32 = 1;
const RECORD_KIND: &str = "rollout_receipt";

/// Paths come from the running process, never from a persisted record.
#[derive(Debug, Clone)]
pub(crate) struct StagingRequest {
    pub install: PathBuf,
    pub data_root: PathBuf,
    pub identity_root: PathBuf,
    pub machine_id: [u8; 32],
    pub version: String,
    /// Digest of the original signature-verified JSON bytes.
    pub manifest_sha256: [u8; 32],
    pub archive_sha256: [u8; 32],
    pub window_minutes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    Due,
    Waiting(Duration),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub schema_version: u32,
    pub record_kind: String,
    pub install: PathBuf,
    pub data_root: PathBuf,
    pub identity_root: PathBuf,
    pub machine_id: [u8; 32],
    pub version: String,
    pub manifest_sha256: [u8; 32],
    pub archive_sha256: [u8; 32],
    pub window_minutes: u64,
    #[serde(with = "duration")]
    pub chosen_delay: Duration,
    pub first_boot_id: String,
    pub first_receipt_ms: u64,
    pub boot_id: String,
    pub epoch_anchor_ms: u64,
    #[serde(with = "duration")]
    pub epoch_remaining: Duration,
    pub anchor_ms: u64,
    #[serde(with = "duration")]
    pub remaining: Duration,
}

/// Each observation reestablishes the record barrier, even when already due.
/// A failed prior directory sync cannot become admission merely by parsing.
/// A failed write may retain old or new elapsed progress. Reusing valid
/// progress after a successful barrier is safe; losing progress only adds wait.
pub(crate) fn observe(request: &StagingRequest, clock: &ProbeClock) -> io::Result<Decision> {
    observe_inner(request, clock, None)
}

#[cfg(test)]
pub(crate) fn observe_with_failure(
    request: &StagingRequest,
    clock: &ProbeClock,
    failure: journal::BarrierStep,
) -> io::Result<Decision> {
    observe_inner(request, clock, Some(failure))
}

fn observe_inner(
    request: &StagingRequest,
    clock: &ProbeClock,
    failure: Option<journal::BarrierStep>,
) -> io::Result<Decision> {
    validate_boot_id(&clock.boot_id)?;
    let path = receipt_path(request)?;
    let mut receipt = match read_at(request, &path)? {
        Some(receipt) => receipt,
        None => {
            let chosen_delay = StagedRollout::new(&request.machine_id, request.window_minutes)
                .calculate_delay_for_version(&request.version);
            Receipt {
                schema_version: SCHEMA_VERSION,
                record_kind: RECORD_KIND.into(),
                install: request.install.clone(),
                data_root: request.data_root.clone(),
                identity_root: request.identity_root.clone(),
                machine_id: request.machine_id,
                version: request.version.clone(),
                manifest_sha256: request.manifest_sha256,
                archive_sha256: request.archive_sha256,
                window_minutes: request.window_minutes,
                chosen_delay,
                first_boot_id: clock.boot_id.clone(),
                first_receipt_ms: clock.monotonic_ms,
                boot_id: clock.boot_id.clone(),
                epoch_anchor_ms: clock.monotonic_ms,
                epoch_remaining: chosen_delay,
                anchor_ms: clock.monotonic_ms,
                remaining: chosen_delay,
            }
        }
    };
    if receipt.boot_id == clock.boot_id {
        let elapsed = clock
            .monotonic_ms
            .checked_sub(receipt.anchor_ms)
            .ok_or_else(|| invalid("rollout monotonic clock moved backwards"))?;
        receipt.remaining = receipt
            .remaining
            .saturating_sub(Duration::from_millis(elapsed));
    } else {
        // Across reboot only the last durable remaining wait is known.
        // Neither downtime nor a wall-clock step supplies elapsed evidence.
        receipt.boot_id.clone_from(&clock.boot_id);
        receipt.epoch_anchor_ms = clock.monotonic_ms;
        receipt.epoch_remaining = receipt.remaining;
    }
    receipt.anchor_ms = clock.monotonic_ms;
    #[cfg(test)]
    if let Some(step) = failure {
        journal::write_auxiliary_record_with_failure(&path, &receipt, validate_receipt, step)?;
    } else {
        journal::write_auxiliary_record(&path, &receipt, validate_receipt)?;
    }
    #[cfg(not(test))]
    {
        let _ = failure;
        journal::write_auxiliary_record(&path, &receipt, validate_receipt)?;
    }
    Ok(if receipt.remaining.is_zero() {
        Decision::Due
    } else {
        Decision::Waiting(receipt.remaining)
    })
}

/// Fixed digest-based name beside the installed binary. Config changes and
/// conflicting payloads for the same release cannot select a fresh receipt.
/// The name does not match any upgrade artifact sweep pattern.
pub(crate) fn receipt_path(request: &StagingRequest) -> io::Result<PathBuf> {
    validate_version(&request.version)?;
    canonical_path(&request.install, false)?;
    canonical_path(&request.data_root, true)?;
    canonical_path(&request.identity_root, true)?;
    let mut hash = Sha256::new();
    for field in [
        request.install.as_os_str().as_encoded_bytes(),
        request.data_root.as_os_str().as_encoded_bytes(),
        request.identity_root.as_os_str().as_encoded_bytes(),
        request.machine_id.as_slice(),
        request.version.as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    let parent = request
        .install
        .parent()
        .ok_or_else(|| invalid("rollout install has no parent"))?;
    Ok(parent.join(format!(
        "upgrade-rollout-{}.json",
        hex::encode(hash.finalize())
    )))
}

/// Diagnostic read only; callers must use observe for a durable due decision.
#[allow(dead_code)]
pub(crate) fn read_receipt(request: &StagingRequest) -> io::Result<Option<Receipt>> {
    read_at(request, &receipt_path(request)?)
}

fn read_at(request: &StagingRequest, path: &Path) -> io::Result<Option<Receipt>> {
    let bytes = match journal::read_auxiliary_record(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let receipt = decode(&bytes)?;
    if receipt.install != request.install
        || receipt.data_root != request.data_root
        || receipt.identity_root != request.identity_root
        || receipt.machine_id != request.machine_id
        || receipt.version != request.version
        || receipt.manifest_sha256 != request.manifest_sha256
        || receipt.archive_sha256 != request.archive_sha256
    {
        return Err(invalid(
            "rollout receipt conflicts with the eligible release or participant",
        ));
    }
    // window_minutes is deliberately not compared: the first choice survives
    // duplicate delivery, process restart and later configuration changes.
    Ok(Some(receipt))
}

fn validate_receipt(bytes: &[u8]) -> io::Result<()> {
    decode(bytes).map(|_| ())
}

fn decode(bytes: &[u8]) -> io::Result<Receipt> {
    let receipt: Receipt = serde_json::from_slice(bytes).map_err(invalid)?;
    if receipt.schema_version != SCHEMA_VERSION || receipt.record_kind != RECORD_KIND {
        return Err(invalid("unknown rollout receipt schema or kind"));
    }
    validate_version(&receipt.version)?;
    validate_boot_id(&receipt.first_boot_id)?;
    validate_boot_id(&receipt.boot_id)?;
    if !receipt.install.is_absolute()
        || !receipt.data_root.is_absolute()
        || !receipt.identity_root.is_absolute()
        || receipt.chosen_delay
            != StagedRollout::new(&receipt.machine_id, receipt.window_minutes)
                .calculate_delay_for_version(&receipt.version)
        || receipt.remaining > receipt.chosen_delay
    {
        return Err(invalid("invalid rollout receipt identity or elapsed state"));
    }
    let elapsed = receipt
        .anchor_ms
        .checked_sub(receipt.epoch_anchor_ms)
        .ok_or_else(|| invalid("rollout anchor precedes its boot epoch"))?;
    if receipt.epoch_remaining > receipt.chosen_delay
        || receipt.remaining
            != receipt
                .epoch_remaining
                .saturating_sub(Duration::from_millis(elapsed))
        || (receipt.boot_id == receipt.first_boot_id
            && (receipt.epoch_anchor_ms != receipt.first_receipt_ms
                || receipt.epoch_remaining != receipt.chosen_delay))
    {
        return Err(invalid(
            "rollout wait conflicts with its observed boot-epoch elapsed time",
        ));
    }
    Ok(receipt)
}

fn canonical_path(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    let expected_type = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !expected_type
        || std::fs::canonicalize(path)? != path
    {
        return Err(invalid(
            "rollout path must identify an existing canonical file or root",
        ));
    }
    Ok(())
}

fn validate_version(version: &str) -> io::Result<()> {
    if version.len() > 256
        || semver::Version::parse(version)
            .map_err(invalid)?
            .to_string()
            != version
    {
        return Err(invalid("invalid rollout release version"));
    }
    Ok(())
}

fn validate_boot_id(boot_id: &str) -> io::Result<()> {
    if boot_id.is_empty() || boot_id.len() > 128 || boot_id.chars().any(char::is_control) {
        return Err(invalid("invalid rollout boot identity"));
    }
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

/// Keep the complete Duration range without millisecond multiplication, and
/// reject malformed or unknown nested fields instead of normalizing them.
mod duration {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Parts {
        secs: u64,
        nanos: u32,
    }

    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        Parts {
            secs: value.as_secs(),
            nanos: value.subsec_nanos(),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let parts = Parts::deserialize(deserializer)?;
        if parts.nanos >= 1_000_000_000 {
            return Err(serde::de::Error::custom(
                "invalid rollout duration nanoseconds",
            ));
        }
        Ok(Duration::new(parts.secs, parts.nanos))
    }
}

#[cfg(test)]
include!("../../tests/upgrade_staging_core.rs");
#[cfg(test)]
staging_core_regression_tests!();
