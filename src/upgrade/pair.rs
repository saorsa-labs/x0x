//! Dormant daemon/managed-CLI pair transaction (ADR 0094 section 3).
//!
//! The caller supplies the verified release and independent install plan while
//! the OLD owner is healthy and has not begun shutdown. This engine does not
//! inventory participants, arm a handoff, start a child or commit host health.
//! A future coordinator must establish those authorities before wiring it in.
//! Unknown records are preserved and never authorize recovery.
#![cfg(unix)]
#![allow(dead_code)]

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{journal, manifest, probe};

const RESERVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 200 * 1024 * 1024;
const MAX_SKILL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BinaryInput {
    pub target: PathBuf,
    pub staged: PathBuf,
    pub previous_version: String,
    pub previous_sha256: [u8; 32],
    pub candidate_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) enum CliInput {
    Managed(BinaryInput),
    Split {
        path: Option<PathBuf>,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SkillInput {
    pub target: PathBuf,
    pub staged: PathBuf,
    pub candidate_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeBinding {
    pub transaction_id: String,
    pub platform: String,
    pub daemon_sha256: [u8; 32],
    pub cli_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairRequest {
    pub install: PathBuf,
    pub candidate_version: String,
    pub manifest_sha256: [u8; 32],
    pub archive_sha256: [u8; 32],
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
    pub cli_untouched_reason: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    BackupFileSync(PairRole),
    BackupDirectorySync(PairRole),
    CandidateFileSync(PairRole),
    CandidateDirectorySync(PairRole),
    SwapDirectorySync(PairRole),
    RestoreFileSync(PairRole),
    RestoreCopyDirectorySync(PairRole),
    RestoreDirectorySync(PairRole),
    BeforeSwapProgress(PairRole),
    BeforeRollbackRecord,
    BeforeRestoreProgress(PairRole),
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct PairOptions {
    pub available_bytes: Option<u64>,
    pub cli_first: bool,
    pub fail_at: Option<PairStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PairPhase {
    Prepared,
    Swapping,
    Swapped,
    RollingBack,
    Restoring,
    Restored,
    RecoveryFailed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairProgress {
    pub swap_started: bool,
    pub swapped: bool,
    pub restore_started: bool,
    pub restored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedBinary {
    pub input: BinaryInput,
    pub backup: PathBuf,
    pub candidate: PathBuf,
    pub restore: PathBuf,
    pub previous_mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairPlan {
    pub request: PairRequest,
    pub daemon: PreparedBinary,
    pub cli: Option<PreparedBinary>,
    pub staged_skill: Option<PathBuf>,
    /// The immediately preceding resolved record retains its own predecessor.
    pub previous_record: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairRecord {
    pub schema_version: u32,
    pub record_kind: String,
    pub transaction_id: String,
    pub sequence: u64,
    pub phase: PairPhase,
    pub plan_sha256: [u8; 32],
    pub plan: PairPlan,
    pub daemon_progress: PairProgress,
    pub cli_progress: Option<PairProgress>,
    pub cause: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairPending {
    schema_version: u32,
    record_kind: String,
    install: PathBuf,
    transaction_id: String,
    plan_sha256: [u8; 32],
}

#[derive(Default)]
struct RunOptions {
    #[cfg(test)]
    available_bytes: Option<u64>,
    #[cfg(test)]
    cli_first: bool,
    #[cfg(test)]
    failures: Vec<PairStep>,
    #[cfg(test)]
    record_failure: Option<(PairPhase, journal::BarrierStep)>,
    #[cfg(test)]
    archive_failure: Option<journal::BarrierStep>,
    #[cfg(test)]
    observer: Option<Box<dyn Fn(PairStep)>>,
}

impl RunOptions {
    fn before(&self, step: PairStep) -> io::Result<()> {
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(step);
        }
        #[cfg(test)]
        if self.failures.contains(&step) {
            return Err(io::Error::other(format!(
                "injected pair boundary: {step:?}"
            )));
        }
        let _ = step;
        Ok(())
    }

    fn order(&self, has_cli: bool) -> Vec<PairRole> {
        let mut order = vec![PairRole::Daemon];
        if has_cli {
            order.push(PairRole::Cli);
        }
        #[cfg(test)]
        if self.cli_first {
            order.reverse();
        }
        order
    }
}

pub(crate) fn pair_record_path(install: &Path) -> io::Result<PathBuf> {
    suffixed(&std::fs::canonicalize(install)?, ".upgrade-pair.json")
}

pub(crate) fn pair_pending_path(install: &Path) -> io::Result<PathBuf> {
    suffixed(&std::fs::canonicalize(install)?, ".upgrade-pair.pending")
}

pub(crate) fn read_pair_record(install: &Path) -> io::Result<Option<PairRecord>> {
    let install = std::fs::canonicalize(install)?;
    let path = pair_record_path(&install)?;
    match journal::read_auxiliary_record(&path) {
        Ok(bytes) => {
            let record = decode_record(&bytes)?;
            if record.plan.request.install != install {
                return Err(invalid("pair record belongs to another install"));
            }
            Ok(Some(record))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn execute_pair(
    request: &PairRequest,
    caller_alive: &AtomicBool,
) -> Result<PairOutcome, PairError> {
    execute_inner(request, caller_alive, &RunOptions::default())
}

#[cfg(test)]
pub(crate) fn execute_pair_with_options(
    request: &PairRequest,
    caller_alive: &AtomicBool,
    options: &PairOptions,
) -> Result<PairOutcome, PairError> {
    execute_pair_with_failures(request, caller_alive, options, &[])
}

#[cfg(test)]
fn test_options(options: &PairOptions) -> RunOptions {
    RunOptions {
        available_bytes: options.available_bytes,
        cli_first: options.cli_first,
        failures: options.fail_at.into_iter().collect(),
        record_failure: None,
        archive_failure: None,
        observer: None,
    }
}

#[cfg(test)]
pub(crate) fn execute_pair_with_failures(
    request: &PairRequest,
    caller_alive: &AtomicBool,
    options: &PairOptions,
    failures: &[PairStep],
) -> Result<PairOutcome, PairError> {
    let mut run = test_options(options);
    run.failures.extend_from_slice(failures);
    execute_inner(request, caller_alive, &run)
}

#[cfg(test)]
pub(crate) fn execute_pair_with_record_failure(
    request: &PairRequest,
    caller_alive: &AtomicBool,
    options: &PairOptions,
    phase: PairPhase,
    step: journal::BarrierStep,
) -> Result<PairOutcome, PairError> {
    let mut run = test_options(options);
    run.record_failure = Some((phase, step));
    execute_inner(request, caller_alive, &run)
}

#[cfg(test)]
pub(crate) fn execute_pair_with_observer(
    request: &PairRequest,
    caller_alive: &AtomicBool,
    options: &PairOptions,
    observer: impl Fn(PairStep) + 'static,
) -> Result<PairOutcome, PairError> {
    let mut run = test_options(options);
    run.observer = Some(Box::new(observer));
    execute_inner(request, caller_alive, &run)
}

#[cfg(test)]
pub(crate) fn execute_pair_with_archive_failure(
    request: &PairRequest,
    caller_alive: &AtomicBool,
    options: &PairOptions,
    step: journal::BarrierStep,
) -> Result<PairOutcome, PairError> {
    let mut run = test_options(options);
    run.archive_failure = Some(step);
    execute_inner(request, caller_alive, &run)
}

fn execute_inner(
    supplied: &PairRequest,
    caller_alive: &AtomicBool,
    options: &RunOptions,
) -> Result<PairOutcome, PairError> {
    check_alive(caller_alive)?;
    let request = normalize_request(supplied)?;
    // Match the released apply worker's CLI-then-daemon lock order. Reject
    // aliased targets before locking, otherwise a pair could deadlock itself.
    let cli_lock = match &request.cli {
        CliInput::Managed(cli) => Some(open_lock(&cli.target).map_err(unresolved)?),
        CliInput::Split { .. } => None,
    };
    let daemon_lock = open_lock(&request.install).map_err(unresolved)?;
    if let Some(cli_lock) = &cli_lock {
        let cli_metadata = cli_lock.metadata().map_err(unresolved)?;
        let daemon_metadata = daemon_lock.metadata().map_err(unresolved)?;
        if cli_metadata.dev() == daemon_metadata.dev()
            && cli_metadata.ino() == daemon_metadata.ino()
        {
            return Err(invalid_plan("daemon and CLI upgrade lock files alias"));
        }
        cli_lock.lock().map_err(unresolved)?;
    }
    daemon_lock.lock().map_err(unresolved)?;
    check_alive(caller_alive)?;
    reject_pending(&request.install)?;
    let previous = read_pair_record(&request.install).map_err(unresolved)?;
    if let Some(record) = &previous {
        if record.phase != PairPhase::Restored {
            return Err(refused(
                PairRefusal::Unresolved,
                "an unresolved pair owns this install",
            ));
        }
        verify_restored_record(record, &request)?;
    }
    validate_probe(&request)?;
    verify_inputs(&request)?;
    let transaction_id = uuid::Uuid::new_v4().to_string();
    let mut record =
        make_record(request, transaction_id, previous.as_ref()).map_err(invalid_plan)?;
    reserve_space(&record.plan, options)?;
    check_alive(caller_alive)?;
    prepare_files(&record.plan, options).map_err(invalid_plan)?;
    // Copying can take time. Recheck the probe and installed/staged hashes
    // under the same host locks immediately before durable prepared intent.
    validate_probe(&record.plan.request)?;
    verify_inputs(&record.plan.request)?;
    check_alive(caller_alive)?;
    if let Some(previous) = previous {
        archive_record(&previous, options).map_err(unresolved)?;
    }
    let pending_path = pair_pending_path(&record.plan.request.install).map_err(unresolved)?;
    let pending = PairPending {
        schema_version: 1,
        record_kind: "pair_pending".into(),
        install: record.plan.request.install.clone(),
        transaction_id: record.transaction_id.clone(),
        plan_sha256: record.plan_sha256,
    };
    // This marker remains until a durable Restored record. Swapped is still
    // unresolved; parsing it must never admit another writer or host commit.
    journal::write_auxiliary_record(&pending_path, &pending, validate_pending)
        .map_err(|error| recovery(&record, error))?;
    options
        .before(PairStep::BeforePreparedRecord)
        .and_then(|()| persist(&record, options))
        .map_err(|error| recovery(&record, error))?;

    let order = options.order(record.plan.cli.is_some());
    for &role in &order {
        let result = (|| {
            if !caller_alive.load(Ordering::Acquire) {
                return Err(io::Error::other("caller cancelled after prepared intent"));
            }
            swap_one(&mut record, role, options)
        })();
        if let Err(error) = result {
            return rollback(record, &order, error.to_string(), options);
        }
    }
    if !caller_alive.load(Ordering::Acquire) {
        return rollback(
            record,
            &order,
            "caller cancelled after pair swap".into(),
            options,
        );
    }
    if let Err(error) = verify_candidate_pair(&record.plan) {
        return rollback(record, &order, error.to_string(), options);
    }
    record.phase = PairPhase::Swapped;
    advance(&mut record).map_err(|error| recovery(&record, error))?;
    if let Err(error) = persist(&record, options) {
        return rollback(record, &order, error.to_string(), options);
    }
    Ok(PairOutcome::Swapped(
        receipt(&record).map_err(|error| recovery(&record, error))?,
    ))
}

fn validate_probe(request: &PairRequest) -> Result<(), PairError> {
    // Admission includes terminalization markers and the writer's in-memory
    // barrier latch; a raw Passed JSON object alone is not sufficient.
    if probe::inspect_admission(&request.install, &request.candidate_version).map_err(unresolved)?
        != probe::Admission::Ready
    {
        return Err(refused(PairRefusal::Unresolved, "probe retry is not due"));
    }
    let state = probe::read_state(&request.install)
        .map_err(unresolved)?
        .ok_or_else(|| refused(PairRefusal::Unresolved, "durable probe evidence is missing"))?;
    if state.phase != probe::ProbePhase::Passed
        || state.version != request.candidate_version
        || state.platform != request.probe.platform
        || Some(state.platform.as_str()) != manifest::current_platform_target()
        || state.archive_sha256 != request.archive_sha256
        || state.transaction_id != request.probe.transaction_id
        || state.daemon_sha256 != Some(request.probe.daemon_sha256)
        || state.cli_sha256 != Some(request.probe.cli_sha256)
        || request.daemon.candidate_sha256 != request.probe.daemon_sha256
        || matches!(&request.cli, CliInput::Managed(cli) if cli.candidate_sha256 != request.probe.cli_sha256)
    {
        return Err(refused(
            PairRefusal::Unresolved,
            "probe evidence does not bind this pair plan",
        ));
    }
    Ok(())
}

fn normalize_request(request: &PairRequest) -> Result<PairRequest, PairError> {
    validate_request_shape(request).map_err(invalid_plan)?;
    let mut request = request.clone();
    request.install = canonical_file(&request.install).map_err(invalid_plan)?;
    request.daemon.target = canonical_file(&request.daemon.target).map_err(invalid_plan)?;
    request.daemon.staged = canonical_file(&request.daemon.staged).map_err(invalid_plan)?;
    if request.install != request.daemon.target {
        return Err(refused(
            PairRefusal::InvalidPlan,
            "install identity does not match daemon target",
        ));
    }
    if let CliInput::Managed(cli) = &mut request.cli {
        cli.target = canonical_file(&cli.target).map_err(invalid_plan)?;
        cli.staged = canonical_file(&cli.staged).map_err(invalid_plan)?;
        if cli.target.parent() != request.install.parent()
            || same_file(&cli.target, &request.install).map_err(invalid_plan)?
        {
            return Err(refused(
                PairRefusal::InvalidPlan,
                "managed CLI target is outside or aliases the install",
            ));
        }
    }
    if let Some(skill) = &mut request.skill {
        skill.staged = canonical_file(&skill.staged).map_err(invalid_plan)?;
        let parent = skill
            .target
            .parent()
            .ok_or_else(|| invalid_plan("SKILL target has no parent"))?;
        let parent = std::fs::canonicalize(parent).map_err(invalid_plan)?;
        let name = skill
            .target
            .file_name()
            .ok_or_else(|| invalid_plan("SKILL target has no name"))?;
        skill.target = parent.join(name);
        // The existing guide is never opened or changed here. Its destination
        // is frozen for the later authenticated host-commit installer.
        if skill.target == request.install
            || matches!(&request.cli, CliInput::Managed(cli) if cli.target == skill.target)
        {
            return Err(invalid_plan("SKILL destination aliases a binary target"));
        }
    }
    Ok(request)
}

fn validate_request_shape(request: &PairRequest) -> io::Result<()> {
    absolute_path(&request.install)?;
    if request.candidate_version.len() > 128 {
        return Err(invalid("candidate version exceeds record bound"));
    }
    let candidate = semver::Version::parse(&request.candidate_version).map_err(invalid)?;
    if !candidate.pre.is_empty() {
        return Err(invalid("prerelease pair is not eligible"));
    }
    uuid::Uuid::parse_str(&request.probe.transaction_id).map_err(invalid)?;
    if request.probe.platform.is_empty() || request.probe.platform.len() > 128 {
        return Err(invalid("invalid probe platform"));
    }
    let mut binaries = vec![&request.daemon];
    if let CliInput::Managed(cli) = &request.cli {
        binaries.push(cli);
    }
    for binary in binaries {
        absolute_path(&binary.target)?;
        absolute_path(&binary.staged)?;
        if binary.previous_version.len() > 128
            || binary.target == binary.staged
            || candidate <= semver::Version::parse(&binary.previous_version).map_err(invalid)?
        {
            return Err(invalid(
                "pair does not advance its declared previous version",
            ));
        }
    }
    if let CliInput::Split { path, reason } = &request.cli {
        if reason.is_empty() || reason.len() > 1024 {
            return Err(invalid("split CLI requires a bounded untouched reason"));
        }
        if let Some(path) = path {
            absolute_path(path)?;
        }
    }
    if let Some(skill) = &request.skill {
        absolute_path(&skill.target)?;
        absolute_path(&skill.staged)?;
        if skill.target == skill.staged {
            return Err(invalid("SKILL stage aliases its active destination"));
        }
    }
    Ok(())
}

fn verify_inputs(request: &PairRequest) -> Result<(), PairError> {
    for input in std::iter::once(&request.daemon).chain(match &request.cli {
        CliInput::Managed(cli) => Some(cli),
        CliInput::Split { .. } => None,
    }) {
        if input.previous_sha256 == input.candidate_sha256 {
            return Err(refused(
                PairRefusal::InstalledChanged,
                "already-candidate bytes cannot be recorded as the old rollback copy",
            ));
        }
        if digest_file(&input.target, MAX_BINARY_BYTES).map_err(invalid_plan)?
            != input.previous_sha256
        {
            return Err(refused(
                PairRefusal::InstalledChanged,
                "installed binary changed before pair preparation",
            ));
        }
        if digest_file(&input.staged, MAX_BINARY_BYTES).map_err(invalid_plan)?
            != input.candidate_sha256
        {
            return Err(refused(
                PairRefusal::CandidateChanged,
                "candidate binary changed after its probe",
            ));
        }
    }
    if let Some(skill) = &request.skill
        && digest_file(&skill.staged, MAX_SKILL_BYTES).map_err(invalid_plan)?
            != skill.candidate_sha256
    {
        return Err(refused(
            PairRefusal::CandidateChanged,
            "staged SKILL does not match the signed artifact hash",
        ));
    }
    Ok(())
}

fn make_record(
    request: PairRequest,
    transaction: String,
    previous: Option<&PairRecord>,
) -> io::Result<PairRecord> {
    let daemon = prepared_binary(&request.daemon, &request.candidate_version, &transaction)?;
    let cli = match &request.cli {
        CliInput::Managed(cli) => Some(prepared_binary(
            cli,
            &request.candidate_version,
            &transaction,
        )?),
        CliInput::Split { .. } => None,
    };
    let staged_skill = request
        .skill
        .as_ref()
        .map(|skill| suffixed(&skill.target, &format!(".upgrade-staged-{transaction}")))
        .transpose()?;
    let plan = PairPlan {
        request,
        daemon,
        cli,
        staged_skill,
        previous_record: previous.map(archive_path).transpose()?,
    };
    validate_protected_paths(&plan)?;
    let plan_sha256 = plan_digest(&plan)?;
    Ok(PairRecord {
        schema_version: 1,
        record_kind: "pair".into(),
        transaction_id: transaction,
        sequence: 1,
        phase: PairPhase::Prepared,
        plan_sha256,
        cli_progress: plan.cli.as_ref().map(|_| PairProgress::default()),
        plan,
        daemon_progress: PairProgress::default(),
        cause: None,
    })
}

fn validate_protected_paths(plan: &PairPlan) -> io::Result<()> {
    // The released startup sweep owns these marker names. Retained pair
    // records and rollback copies must remain outside that namespace, even
    // when an unusual install name or version contributes the marker.
    for binary in std::iter::once(&plan.daemon).chain(plan.cli.iter()) {
        for path in [
            &binary.input.target,
            &binary.backup,
            &binary.candidate,
            &binary.restore,
        ] {
            reject_cleanup_path(path)?;
        }
    }
    for path in plan.staged_skill.iter().chain(plan.previous_record.iter()) {
        reject_cleanup_path(path)?;
    }
    Ok(())
}

fn reject_cleanup_path(path: &Path) -> io::Result<()> {
    if path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        name.starts_with(".x0x-upgrade-") || name.contains(".x0xold-")
    }) {
        return Err(invalid(
            "protected pair artifact overlaps the legacy cleanup namespace",
        ));
    }
    Ok(())
}

fn prepared_binary(
    input: &BinaryInput,
    version: &str,
    transaction: &str,
) -> io::Result<PreparedBinary> {
    Ok(PreparedBinary {
        input: input.clone(),
        backup: suffixed(
            &input.target,
            &format!(".backup-{}-{transaction}", input.previous_version),
        )?,
        candidate: suffixed(
            &input.target,
            &format!(".candidate-{version}-{transaction}"),
        )?,
        restore: suffixed(&input.target, &format!(".restore-{transaction}"))?,
        previous_mode: open_regular(&input.target, MAX_BINARY_BYTES)?
            .metadata()?
            .permissions()
            .mode()
            & 0o777,
    })
}

fn reserve_space(plan: &PairPlan, options: &RunOptions) -> Result<(), PairError> {
    let mut required = std::collections::BTreeMap::<PathBuf, u64>::new();
    for binary in std::iter::once(&plan.daemon).chain(plan.cli.iter()) {
        let old = open_regular(&binary.input.target, MAX_BINARY_BYTES)
            .map_err(invalid_plan)?
            .metadata()
            .map_err(invalid_plan)?
            .len();
        let new = open_regular(&binary.input.staged, MAX_BINARY_BYTES)
            .map_err(invalid_plan)?
            .metadata()
            .map_err(invalid_plan)?
            .len();
        // Backup + candidate copy + a possible restore copy. Prior retained
        // backups already consume free space and are never removed to pass.
        let bytes = old
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(new))
            .ok_or_else(|| invalid_plan("pair copy size overflow"))?;
        add_required(&mut required, &binary.input.target, bytes).map_err(invalid_plan)?;
    }
    if let Some(skill) = &plan.request.skill {
        let bytes = open_regular(&skill.staged, MAX_SKILL_BYTES)
            .map_err(invalid_plan)?
            .metadata()
            .map_err(invalid_plan)?
            .len();
        add_required(&mut required, &skill.target, bytes).map_err(invalid_plan)?;
    }
    // Aggregate by device, not directory: two destinations on the same volume
    // must reserve the combined writes, including the later rollback copy.
    let mut devices = std::collections::BTreeMap::<u64, (PathBuf, u64)>::new();
    for (directory, bytes) in required {
        let device = std::fs::metadata(&directory).map_err(invalid_plan)?.dev();
        let entry = devices.entry(device).or_insert((directory, 0));
        entry.1 = entry
            .1
            .checked_add(bytes)
            .ok_or_else(|| invalid_plan("pair reserve overflow"))?;
    }
    for (_, (directory, bytes)) in devices {
        #[cfg(test)]
        let available = options
            .available_bytes
            .map(Ok)
            .unwrap_or_else(|| available_bytes(&directory));
        #[cfg(not(test))]
        let available = {
            let _ = options;
            available_bytes(&directory)
        };
        let needed = RESERVE_BYTES
            .checked_add(bytes)
            .and_then(|n| n.checked_add(4 * 1024 * 1024))
            .ok_or_else(|| invalid_plan("pair reserve overflow"))?;
        if available.map_err(invalid_plan)? < needed {
            return Err(refused(
                PairRefusal::InsufficientDisk,
                "insufficient_disk: pair copies must leave 1 GiB free",
            ));
        }
        sync_directory(&directory).map_err(invalid_plan)?;
    }
    Ok(())
}

fn add_required(
    required: &mut std::collections::BTreeMap<PathBuf, u64>,
    target: &Path,
    bytes: u64,
) -> io::Result<()> {
    let entry = required.entry(parent(target)?.to_path_buf()).or_default();
    *entry = entry
        .checked_add(bytes)
        .ok_or_else(|| invalid("pair copy reserve overflow"))?;
    Ok(())
}

fn available_bytes(directory: &Path) -> io::Result<u64> {
    let path = CString::new(directory.as_os_str().as_bytes()).map_err(invalid)?;
    // SAFETY: statvfs receives a valid C path and an owned writable result.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(u128::from(stat.f_bavail) * u128::from(stat.f_frsize)).map_err(invalid)
}

fn prepare_files(plan: &PairPlan, options: &RunOptions) -> io::Result<()> {
    for role in [PairRole::Daemon, PairRole::Cli] {
        let Some(binary) = binary(plan, role) else {
            continue;
        };
        copy_barrier(
            &binary.input.target,
            &binary.backup,
            binary.input.previous_sha256,
            binary.previous_mode,
            MAX_BINARY_BYTES,
            || options.before(PairStep::BackupFileSync(role)),
            || options.before(PairStep::BackupDirectorySync(role)),
        )?;
        copy_barrier(
            &binary.input.staged,
            &binary.candidate,
            binary.input.candidate_sha256,
            0o755,
            MAX_BINARY_BYTES,
            || options.before(PairStep::CandidateFileSync(role)),
            || options.before(PairStep::CandidateDirectorySync(role)),
        )?;
    }
    if let (Some(skill), Some(staged)) = (&plan.request.skill, &plan.staged_skill) {
        copy_barrier(
            &skill.staged,
            staged,
            skill.candidate_sha256,
            0o644,
            MAX_SKILL_BYTES,
            || Ok(()),
            || Ok(()),
        )?;
    }
    Ok(())
}

fn swap_one(record: &mut PairRecord, role: PairRole, options: &RunOptions) -> io::Result<()> {
    let binary = binary(&record.plan, role)
        .cloned()
        .ok_or_else(|| invalid("missing pair member"))?;
    options.before(PairStep::BeforeSwap(role))?;
    if digest_file(&binary.input.target, MAX_BINARY_BYTES)? != binary.input.previous_sha256
        || digest_file(&binary.backup, MAX_BINARY_BYTES)? != binary.input.previous_sha256
        || digest_file(&binary.candidate, MAX_BINARY_BYTES)? != binary.input.candidate_sha256
    {
        return Err(invalid("pair bytes changed at the swap boundary"));
    }
    record.phase = PairPhase::Swapping;
    progress(record, role)?.swap_started = true;
    advance(record)?;
    persist(record, options)?;
    // Both inputs are copied and fsynced in this target directory. The rename
    // does not consume the protected backup or depend on archive filesystem.
    std::fs::rename(&binary.candidate, &binary.input.target)?;
    options.before(PairStep::AfterSwapRename(role))?;
    options.before(PairStep::SwapDirectorySync(role))?;
    sync_directory(parent(&binary.input.target)?)?;
    if digest_file(&binary.input.target, MAX_BINARY_BYTES)? != binary.input.candidate_sha256 {
        return Err(invalid("installed candidate hash changed after rename"));
    }
    progress(record, role)?.swapped = true;
    advance(record)?;
    options.before(PairStep::BeforeSwapProgress(role))?;
    persist(record, options)
}

fn rollback(
    mut record: PairRecord,
    order: &[PairRole],
    reason: String,
    options: &RunOptions,
) -> Result<PairOutcome, PairError> {
    record.phase = PairPhase::RollingBack;
    record.cause = Some(reason.chars().take(2048).collect());
    let result = (|| {
        advance(&mut record)?;
        options.before(PairStep::BeforeRollbackRecord)?;
        persist(&record, options)?;
        for &role in order.iter().rev() {
            restore_one(&mut record, role, options)?;
        }
        verify_previous_pair(&record.plan)?;
        record.phase = PairPhase::Restored;
        advance(&mut record)?;
        options.before(PairStep::BeforeRestoredRecord)?;
        persist(&record, options)?;
        remove_pending(&record)?;
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = result {
        // Preserve the pending marker even if this best-effort record fails.
        // A rename followed by failed directory sync can expose complete JSON
        // without granting a durable terminal transition.
        record.phase = PairPhase::RecoveryFailed;
        record.cause = Some(
            format!("pair restore failed: {error}")
                .chars()
                .take(2048)
                .collect(),
        );
        if advance(&mut record).is_ok() {
            let _ = persist(&record, options);
        }
        return Err(recovery(&record, error));
    }
    Ok(PairOutcome::Restored {
        receipt: receipt(&record).map_err(|error| recovery(&record, error))?,
        reason: record
            .cause
            .clone()
            .ok_or_else(|| recovery(&record, "restore cause missing"))?,
    })
}

fn restore_one(record: &mut PairRecord, role: PairRole, options: &RunOptions) -> io::Result<()> {
    let binary = binary(&record.plan, role)
        .cloned()
        .ok_or_else(|| invalid("missing pair member"))?;
    options.before(PairStep::BeforeRestore(role))?;
    // Reconcile the real file against both immutable hashes. Never overwrite
    // unrelated bytes merely because a stale progress flag says "swapped".
    let observed = digest_file(&binary.input.target, MAX_BINARY_BYTES)?;
    if observed != binary.input.previous_sha256 && observed != binary.input.candidate_sha256 {
        return Err(invalid("restore target has unrelated bytes"));
    }
    if digest_file(&binary.backup, MAX_BINARY_BYTES)? != binary.input.previous_sha256 {
        return Err(invalid("protected rollback copy changed"));
    }
    record.phase = PairPhase::Restoring;
    progress(record, role)?.restore_started = true;
    advance(record)?;
    persist(record, options)?;
    if observed != binary.input.previous_sha256 {
        copy_barrier(
            &binary.backup,
            &binary.restore,
            binary.input.previous_sha256,
            binary.previous_mode,
            MAX_BINARY_BYTES,
            || options.before(PairStep::RestoreFileSync(role)),
            || options.before(PairStep::RestoreCopyDirectorySync(role)),
        )?;
        std::fs::rename(&binary.restore, &binary.input.target)?;
        options.before(PairStep::AfterRestoreRename(role))?;
        options.before(PairStep::RestoreDirectorySync(role))?;
        sync_directory(parent(&binary.input.target)?)?;
    }
    if digest_file(&binary.input.target, MAX_BINARY_BYTES)? != binary.input.previous_sha256 {
        return Err(invalid("restored binary hash mismatch"));
    }
    progress(record, role)?.restored = true;
    advance(record)?;
    options.before(PairStep::BeforeRestoreProgress(role))?;
    persist(record, options)
}

fn verify_candidate_pair(plan: &PairPlan) -> io::Result<()> {
    for binary in std::iter::once(&plan.daemon).chain(plan.cli.iter()) {
        if digest_file(&binary.input.target, MAX_BINARY_BYTES)? != binary.input.candidate_sha256 {
            return Err(invalid("candidate pair hash mismatch"));
        }
    }
    Ok(())
}

fn verify_previous_pair(plan: &PairPlan) -> io::Result<()> {
    for binary in std::iter::once(&plan.daemon).chain(plan.cli.iter()) {
        if digest_file(&binary.input.target, MAX_BINARY_BYTES)? != binary.input.previous_sha256
            || digest_file(&binary.backup, MAX_BINARY_BYTES)? != binary.input.previous_sha256
        {
            return Err(invalid(
                "restored pair or retained rollback copy hash mismatch",
            ));
        }
    }
    Ok(())
}

fn binary(plan: &PairPlan, role: PairRole) -> Option<&PreparedBinary> {
    match role {
        PairRole::Daemon => Some(&plan.daemon),
        PairRole::Cli => plan.cli.as_ref(),
    }
}

fn progress(record: &mut PairRecord, role: PairRole) -> io::Result<&mut PairProgress> {
    match role {
        PairRole::Daemon => Ok(&mut record.daemon_progress),
        PairRole::Cli => record
            .cli_progress
            .as_mut()
            .ok_or_else(|| invalid("missing CLI progress")),
    }
}

fn receipt(record: &PairRecord) -> io::Result<PairReceipt> {
    Ok(PairReceipt {
        transaction_id: record.transaction_id.clone(),
        journal_path: suffixed(&record.plan.request.install, ".upgrade-pair.json")?,
        daemon_backup: record.plan.daemon.backup.clone(),
        cli_backup: record.plan.cli.as_ref().map(|cli| cli.backup.clone()),
        staged_skill: record.plan.staged_skill.clone(),
        cli_untouched: record.plan.cli.is_none(),
        cli_untouched_reason: match &record.plan.request.cli {
            CliInput::Split { reason, .. } => Some(format!(
                "{reason}; reinstall the CLI through its package/install owner"
            )),
            CliInput::Managed(_) => None,
        },
    })
}

fn advance(record: &mut PairRecord) -> io::Result<()> {
    record.sequence = record
        .sequence
        .checked_add(1)
        .ok_or_else(|| invalid("pair sequence exhausted"))?;
    Ok(())
}

fn persist(record: &PairRecord, options: &RunOptions) -> io::Result<()> {
    let path = suffixed(&record.plan.request.install, ".upgrade-pair.json")?;
    match journal::read_auxiliary_record(&path) {
        Ok(bytes) => {
            let old = decode_record(&bytes)?;
            let same = old.transaction_id == record.transaction_id
                && old.plan_sha256 == record.plan_sha256
                && old.sequence <= record.sequence;
            let resolved_predecessor = record.phase == PairPhase::Prepared
                && record.sequence == 1
                && old.phase == PairPhase::Restored
                && record.plan.previous_record.as_ref() == Some(&archive_path(&old)?);
            if !same && !resolved_predecessor {
                return Err(invalid("pair journal changed ownership or immutable plan"));
            }
        }
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && record.phase == PairPhase::Prepared
                && record.sequence == 1 => {}
        Err(error) => return Err(error),
    }
    #[cfg(test)]
    if let Some((phase, step)) = options.record_failure
        && phase == record.phase
    {
        return journal::write_auxiliary_record_with_failure(&path, record, validate_record, step);
    }
    let _ = options;
    journal::write_auxiliary_record(&path, record, validate_record)
}

fn reject_pending(install: &Path) -> Result<(), PairError> {
    let path = pair_pending_path(install).map_err(unresolved)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(refused(
            PairRefusal::Unresolved,
            "pair intent or terminal record barrier remains unresolved",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(unresolved(error)),
    }
}

fn remove_pending(record: &PairRecord) -> io::Result<()> {
    let path = pair_pending_path(&record.plan.request.install)?;
    let bytes = journal::read_auxiliary_record(&path)?;
    validate_pending(&bytes)?;
    let pending: PairPending = serde_json::from_slice(&bytes).map_err(invalid)?;
    if pending.install != record.plan.request.install
        || pending.transaction_id != record.transaction_id
        || pending.plan_sha256 != record.plan_sha256
    {
        return Err(invalid(
            "pair pending marker belongs to another transaction",
        ));
    }
    std::fs::remove_file(&path)?;
    // A durable Restored record precedes removal. A lost unlink merely brings
    // back a conservative blocker; absence cannot authorize an unsafe state.
    let _ = sync_directory(parent(&path)?);
    Ok(())
}

fn archive_path(record: &PairRecord) -> io::Result<PathBuf> {
    suffixed(
        &record.plan.request.install,
        &format!(".upgrade-pair-{}.json", record.transaction_id),
    )
}

fn archive_record(record: &PairRecord, options: &RunOptions) -> io::Result<()> {
    let path = archive_path(record)?;
    let encoded = serde_json::to_vec_pretty(record).map_err(invalid)?;
    match journal::read_auxiliary_record(&path) {
        Ok(existing) if existing == encoded => {
            // A prior rename can leave equal, readable bytes after its parent
            // sync failed. Re-establish both barriers before allowing the
            // current record to stop referencing this predecessor's backups.
            let file = open_regular(&path, 1024 * 1024)?;
            #[cfg(test)]
            fail_archive_barrier(options, journal::BarrierStep::FileSync)?;
            file.sync_all()?;
            #[cfg(test)]
            fail_archive_barrier(options, journal::BarrierStep::DirectorySync)?;
            return sync_directory(parent(&path)?);
        }
        Ok(_) => return Err(invalid("retained pair record already has different bytes")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    #[cfg(test)]
    if let Some(step) = options.archive_failure {
        return journal::write_auxiliary_record_with_failure(&path, record, validate_record, step);
    }
    let _ = options;
    journal::write_auxiliary_record(&path, record, validate_record)
}

#[cfg(test)]
fn fail_archive_barrier(options: &RunOptions, step: journal::BarrierStep) -> io::Result<()> {
    if options.archive_failure == Some(step) {
        Err(io::Error::other(
            "injected retained pair record barrier failure",
        ))
    } else {
        Ok(())
    }
}

fn verify_restored_record(record: &PairRecord, supplied: &PairRequest) -> Result<(), PairError> {
    // The supplied install paths are the independent authority. A parsed
    // record cannot redirect this admission check to a different target.
    if record.plan.request.install != supplied.install
        || record.plan.daemon.input.target != supplied.daemon.target
        || record.plan.daemon.input.previous_sha256 != supplied.daemon.previous_sha256
        || record.plan.daemon.input.previous_version != supplied.daemon.previous_version
        || match (&record.plan.cli, &supplied.cli) {
            (Some(old), CliInput::Managed(new)) => {
                old.input.target != new.target
                    || old.input.previous_sha256 != new.previous_sha256
                    || old.input.previous_version != new.previous_version
            }
            (None, CliInput::Split { .. }) => false,
            _ => true,
        }
    {
        return Err(refused(
            PairRefusal::Unresolved,
            "resolved pair does not match independent install identity",
        ));
    }
    verify_previous_pair(&record.plan).map_err(unresolved)
}

fn validate_pending(bytes: &[u8]) -> io::Result<()> {
    let value: PairPending = serde_json::from_slice(bytes).map_err(invalid)?;
    if value.schema_version != 1 || value.record_kind != "pair_pending" {
        return Err(invalid("unsupported pair pending record"));
    }
    absolute_path(&value.install)?;
    uuid::Uuid::parse_str(&value.transaction_id).map_err(invalid)?;
    Ok(())
}

fn validate_record(bytes: &[u8]) -> io::Result<()> {
    decode_record(bytes).map(|_| ())
}

fn decode_record(bytes: &[u8]) -> io::Result<PairRecord> {
    let record: PairRecord = serde_json::from_slice(bytes).map_err(invalid)?;
    if record.schema_version != 1
        || record.record_kind != "pair"
        || record.sequence == 0
        || record
            .cause
            .as_ref()
            .is_some_and(|reason| reason.is_empty() || reason.len() > 8192)
    {
        return Err(invalid("unsupported or invalid pair record"));
    }
    uuid::Uuid::parse_str(&record.transaction_id).map_err(invalid)?;
    validate_request_shape(&record.plan.request)?;
    validate_protected_paths(&record.plan)?;
    if record.plan.request.install != record.plan.request.daemon.target
        || matches!(&record.plan.request.cli, CliInput::Managed(cli)
            if cli.target.parent() != record.plan.request.install.parent()
                || cli.target == record.plan.request.install)
    {
        return Err(invalid(
            "pair record has inconsistent canonical install targets",
        ));
    }
    if record.plan_sha256 != plan_digest(&record.plan)? {
        return Err(invalid("immutable pair plan digest mismatch"));
    }
    validate_plan_artifact(&record.plan.daemon, &record.plan.request.daemon, &record)?;
    match (
        &record.plan.cli,
        &record.plan.request.cli,
        &record.cli_progress,
    ) {
        (Some(binary), CliInput::Managed(input), Some(_)) => {
            validate_plan_artifact(binary, input, &record)?
        }
        (None, CliInput::Split { .. }, None) => {}
        _ => return Err(invalid("pair CLI plan and progress disagree")),
    }
    let expected_skill = record
        .plan
        .request
        .skill
        .as_ref()
        .map(|skill| {
            suffixed(
                &skill.target,
                &format!(".upgrade-staged-{}", record.transaction_id),
            )
        })
        .transpose()?;
    if record.plan.staged_skill != expected_skill {
        return Err(invalid("staged SKILL path does not match its transaction"));
    }
    if let Some(previous) = &record.plan.previous_record {
        absolute_path(previous)?;
        if previous.parent() != record.plan.request.install.parent() {
            return Err(invalid("retained record is outside the install directory"));
        }
    }
    let entries = std::iter::once(&record.daemon_progress).chain(record.cli_progress.iter());
    for progress in entries {
        if (progress.swapped && !progress.swap_started)
            || (progress.restored && !progress.restore_started)
            || (record.phase == PairPhase::Swapped && !progress.swapped)
            || (record.phase == PairPhase::Restored && !progress.restored)
        {
            return Err(invalid("pair phase and artifact progress disagree"));
        }
    }
    if matches!(
        record.phase,
        PairPhase::RollingBack
            | PairPhase::Restoring
            | PairPhase::Restored
            | PairPhase::RecoveryFailed
    ) && record.cause.is_none()
    {
        return Err(invalid("pair rollback has no cause"));
    }
    Ok(record)
}

fn validate_plan_artifact(
    binary: &PreparedBinary,
    input: &BinaryInput,
    record: &PairRecord,
) -> io::Result<()> {
    if binary.input != *input
        || binary.backup
            != suffixed(
                &input.target,
                &format!(
                    ".backup-{}-{}",
                    input.previous_version, record.transaction_id
                ),
            )?
        || binary.candidate
            != suffixed(
                &input.target,
                &format!(
                    ".candidate-{}-{}",
                    record.plan.request.candidate_version, record.transaction_id
                ),
            )?
        || binary.restore
            != suffixed(
                &input.target,
                &format!(".restore-{}", record.transaction_id),
            )?
        || binary.previous_mode > 0o777
    {
        return Err(invalid(
            "pair artifact paths or identity do not match the immutable plan",
        ));
    }
    Ok(())
}

fn plan_digest(plan: &PairPlan) -> io::Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(plan).map_err(invalid)?).into())
}

fn copy_barrier(
    source: &Path,
    destination: &Path,
    expected: [u8; 32],
    mode: u32,
    limit: u64,
    before_file_sync: impl FnOnce() -> io::Result<()>,
    before_directory_sync: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let mut input = open_regular(source, limit)?;
    // create_new protects both current and historical rollback copies.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(destination)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("artifact size overflow"))?;
        if total > limit {
            return Err(invalid("artifact exceeds size limit"));
        }
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != expected {
        return Err(invalid("artifact changed during its protected copy"));
    }
    output.set_permissions(std::fs::Permissions::from_mode(mode))?;
    before_file_sync()?;
    output.sync_all()?;
    before_directory_sync()?;
    sync_directory(parent(destination)?)
}

fn open_regular(path: &Path, limit: u64) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err(invalid("artifact is not a bounded, nonempty regular file"));
    }
    Ok(file)
}

fn digest_file(path: &Path, limit: u64) -> io::Result<[u8; 32]> {
    let mut input = open_regular(path, limit)?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        if bytes > limit {
            return Err(invalid("artifact grew beyond its size limit"));
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

fn canonical_file(path: &Path) -> io::Result<PathBuf> {
    absolute_path(path)?;
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid("pair artifact is a symbolic link"));
    }
    let canonical = std::fs::canonicalize(path)?;
    open_regular(&canonical, MAX_BINARY_BYTES)?;
    Ok(canonical)
}

fn same_file(first: &Path, second: &Path) -> io::Result<bool> {
    let first = std::fs::metadata(first)?;
    let second = std::fs::metadata(second)?;
    Ok(first.dev() == second.dev() && first.ino() == second.ino())
}

fn open_lock(target: &Path) -> io::Result<File> {
    // Same persistent filename and File::lock protocol as
    // upgrade::acquire_host_upgrade_lock; never unlink, truncate or replace
    // the lock. This private dormant engine adds O_NOFOLLOW to the same lock.
    let path = suffixed(target, ".upgrade.lock")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("upgrade lock is not a regular file"));
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?
        .sync_all()
}

fn suffixed(target: &Path, suffix: &str) -> io::Result<PathBuf> {
    let mut name = target
        .file_name()
        .ok_or_else(|| invalid("target has no filename"))?
        .to_os_string();
    name.push(suffix);
    Ok(target.with_file_name(name))
}

fn parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| invalid("artifact has no parent directory"))
}

fn absolute_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(invalid("pair path is not an absolute normalized file path"));
    }
    Ok(())
}

fn check_alive(alive: &AtomicBool) -> Result<(), PairError> {
    if alive.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(refused(
            PairRefusal::Cancelled,
            "pair caller cancelled before admission",
        ))
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn refused(cause: PairRefusal, reason: impl std::fmt::Display) -> PairError {
    PairError::Refused {
        cause,
        reason: reason.to_string(),
    }
}

fn invalid_plan(error: impl std::fmt::Display) -> PairError {
    refused(PairRefusal::InvalidPlan, error)
}

fn unresolved(error: impl std::fmt::Display) -> PairError {
    refused(PairRefusal::Unresolved, error)
}

fn recovery(record: &PairRecord, error: impl std::fmt::Display) -> PairError {
    PairError::RecoveryFailed {
        transaction_id: record.transaction_id.clone(),
        reason: error.to_string(),
    }
}
