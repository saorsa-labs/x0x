//! Durable release selection for one rollout participant (ADR 0094, staged).
//!
//! Callers verify release eligibility and hold the existing canonical install
//! lock across each call. No selection grants swap or host-commit authority.
//! Receipt acknowledgement precedes selection intent; unresolved intent blocks
//! every release. Old rollout receipts and invalid evidence are never removed.
#![cfg(unix)]

use std::cmp::Ordering;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::journal::{self, BarrierStep};
use super::probe::ProbeClock;
use super::staging::{self, Decision, StagingRequest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseBinding {
    pub version: String,
    pub manifest_sha256: [u8; 32],
    pub archive_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub schema_version: u32,
    pub record_kind: String,
    pub install: PathBuf,
    pub data_root: PathBuf,
    pub identity_root: PathBuf,
    pub machine_id: [u8; 32],
    pub release: ReleaseBinding,
    /// The immediately superseded eligible release, without unbounded history.
    pub supersedes: Option<ReleaseBinding>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema_version: u32,
    record_kind: String,
    previous: Option<Selection>,
    next: Selection,
}

/// A read-only preflight, also repeated by observe_selected. In particular an
/// older waiter must refuse before it changes any receipt or probe retry state.
pub(crate) fn check_request(request: &StagingRequest) -> io::Result<()> {
    check_version(request, read_selection(request)?.as_ref())
}

/// Receipt, intent, selection, then intent removal: each required barrier must
/// acknowledge before returning even a Waiting decision. A failed selection
/// barrier leaves intent, so a fresh reader cannot admit either old or new.
pub(crate) fn observe_selected(
    request: &StagingRequest,
    clock: &ProbeClock,
) -> io::Result<Decision> {
    observe_inner(request, clock, None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum SelectionFailure {
    ReceiptBarrier(BarrierStep),
    IntentBarrier(BarrierStep),
    SelectionBarrier(BarrierStep),
    RemoveIntent,
    RemovalDirectorySync,
}

#[cfg(test)]
pub(crate) fn observe_with_failure(
    request: &StagingRequest,
    clock: &ProbeClock,
    failure: SelectionFailure,
) -> io::Result<Decision> {
    observe_inner(request, clock, Some(failure))
}

fn observe_inner(
    request: &StagingRequest,
    clock: &ProbeClock,
    failure: Option<SelectionFailure>,
) -> io::Result<Decision> {
    let path = selection_path(request)?;
    let previous = read_selection(request)?;
    check_version(request, previous.as_ref())?;
    // This is the actual rollout writer, not a caller-supplied durability flag.
    #[cfg(test)]
    let decision = if let Some(SelectionFailure::ReceiptBarrier(step)) = failure {
        staging::observe_with_failure(request, clock, step)?
    } else {
        staging::observe(request, clock)?
    };
    #[cfg(not(test))]
    let decision = staging::observe(request, clock)?;

    if let Some(selected) = previous
        .as_ref()
        .filter(|selected| selected.release.version == request.version)
    {
        // Reestablish the selection and directory barrier on every observation.
        // This also acknowledges an absent intent after a prior failed removal
        // directory sync; parsing the selected record alone never grants Due.
        write_selection(&path, selected, failure)?;
        return Ok(decision);
    }

    let next = Selection {
        schema_version: 1,
        record_kind: "rollout_selection".into(),
        install: request.install.clone(),
        data_root: request.data_root.clone(),
        identity_root: request.identity_root.clone(),
        machine_id: request.machine_id,
        release: binding(request),
        supersedes: previous.as_ref().map(|selected| selected.release.clone()),
    };
    let intent = Intent {
        schema_version: 1,
        record_kind: "rollout_selecting".into(),
        previous,
        next,
    };
    let pending = pending_path(request)?;
    #[cfg(test)]
    if let Some(SelectionFailure::IntentBarrier(step)) = failure {
        journal::write_auxiliary_record_with_failure(&pending, &intent, validate_intent, step)?;
    } else {
        journal::write_auxiliary_record(&pending, &intent, validate_intent)?;
    }
    #[cfg(not(test))]
    journal::write_auxiliary_record(&pending, &intent, validate_intent)?;

    write_selection(&path, &intent.next, failure)?;
    // Preserve unexpected evidence even if another writer ignored the lock.
    let observed: Intent =
        serde_json::from_slice(&journal::read_auxiliary_record(&pending)?).map_err(invalid)?;
    if observed != intent {
        return Err(invalid(
            "rollout selection intent changed; records preserved",
        ));
    }
    inject_cleanup_failure(failure, SelectionFailure::RemoveIntent)?;
    std::fs::remove_file(&pending)?;
    inject_cleanup_failure(failure, SelectionFailure::RemovalDirectorySync)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("selection has no parent"))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(decision)
}

fn write_selection(
    path: &Path,
    selection: &Selection,
    failure: Option<SelectionFailure>,
) -> io::Result<()> {
    #[cfg(test)]
    if let Some(SelectionFailure::SelectionBarrier(step)) = failure {
        return journal::write_auxiliary_record_with_failure(
            path,
            selection,
            validate_selection,
            step,
        );
    }
    let _ = failure;
    journal::write_auxiliary_record(path, selection, validate_selection)
}

fn inject_cleanup_failure(
    failure: Option<SelectionFailure>,
    at: SelectionFailure,
) -> io::Result<()> {
    #[cfg(test)]
    if failure == Some(at) {
        return Err(io::Error::other(
            "injected selection cleanup barrier failure",
        ));
    }
    let _ = (failure, at);
    Ok(())
}

/// Participant-only name: a new version cannot hide the prior selection by
/// choosing another filename. All paths are independently supplied and checked.
pub(crate) fn selection_path(request: &StagingRequest) -> io::Result<PathBuf> {
    stable_version(&request.version)?;
    // Reuse canonical existing-file/root validation from the receipt writer.
    staging::receipt_path(request)?;
    let mut hash = Sha256::new();
    for field in [
        request.install.as_os_str().as_encoded_bytes(),
        request.data_root.as_os_str().as_encoded_bytes(),
        request.identity_root.as_os_str().as_encoded_bytes(),
        request.machine_id.as_slice(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    let parent = request
        .install
        .parent()
        .ok_or_else(|| invalid("install has no parent"))?;
    Ok(parent.join(format!(
        "upgrade-selection-{}.json",
        hex::encode(hash.finalize())
    )))
}

pub(crate) fn pending_path(request: &StagingRequest) -> io::Result<PathBuf> {
    let path = selection_path(request)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(".pending");
    Ok(PathBuf::from(name))
}

/// Diagnostic read, never an acknowledgement of a selection or due receipt.
/// Any present/unreadable intent is unresolved, including an unknown schema.
pub(crate) fn read_selection(request: &StagingRequest) -> io::Result<Option<Selection>> {
    let path = selection_path(request)?;
    match journal::read_auxiliary_record(&pending_path(request)?) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => {
            return Err(invalid(
                "rollout selection intent is unresolved; records preserved",
            ))
        }
    }
    let bytes = match journal::read_auxiliary_record(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let selected: Selection = serde_json::from_slice(&bytes).map_err(invalid)?;
    validate_selected(&selected)?;
    if selected.install != request.install
        || selected.data_root != request.data_root
        || selected.identity_root != request.identity_root
        || selected.machine_id != request.machine_id
    {
        return Err(invalid(
            "rollout selection participant changed; records preserved",
        ));
    }
    Ok(Some(selected))
}

fn check_version(request: &StagingRequest, selected: Option<&Selection>) -> io::Result<()> {
    let requested = stable_version(&request.version)?;
    if let Some(selected) = selected {
        match requested.cmp_precedence(&stable_version(&selected.release.version)?) {
            Ordering::Less => {
                return Err(invalid("rollout release was superseded; receipt preserved"))
            }
            Ordering::Equal if selected.release != binding(request) => {
                return Err(invalid(
                    "equal-precedence rollout releases conflict; records preserved",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn binding(request: &StagingRequest) -> ReleaseBinding {
    ReleaseBinding {
        version: request.version.clone(),
        manifest_sha256: request.manifest_sha256,
        archive_sha256: request.archive_sha256,
    }
}

fn validate_selection(bytes: &[u8]) -> io::Result<()> {
    validate_selected(&serde_json::from_slice(bytes).map_err(invalid)?)
}

fn validate_selected(selected: &Selection) -> io::Result<()> {
    if selected.schema_version != 1 || selected.record_kind != "rollout_selection" {
        return Err(invalid("unknown rollout selection schema or kind"));
    }
    for path in [
        &selected.install,
        &selected.data_root,
        &selected.identity_root,
    ] {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(invalid("invalid rollout selection participant path"));
        }
    }
    let current = stable_version(&selected.release.version)?;
    if let Some(previous) = &selected.supersedes {
        if current.cmp_precedence(&stable_version(&previous.version)?) != Ordering::Greater {
            return Err(invalid("invalid rollout supersession relation"));
        }
    }
    Ok(())
}

fn validate_intent(bytes: &[u8]) -> io::Result<()> {
    let intent: Intent = serde_json::from_slice(bytes).map_err(invalid)?;
    if intent.schema_version != 1 || intent.record_kind != "rollout_selecting" {
        return Err(invalid("unknown rollout selection intent schema or kind"));
    }
    validate_selected(&intent.next)?;
    if let Some(previous) = &intent.previous {
        validate_selected(previous)?;
        if previous.install != intent.next.install
            || previous.data_root != intent.next.data_root
            || previous.identity_root != intent.next.identity_root
            || previous.machine_id != intent.next.machine_id
        {
            return Err(invalid("selection intent changes participant identity"));
        }
    }
    if intent.next.supersedes != intent.previous.map(|previous| previous.release) {
        return Err(invalid(
            "selection intent has no matching superseded release",
        ));
    }
    Ok(())
}

fn stable_version(version: &str) -> io::Result<semver::Version> {
    if version.len() > 256 {
        return Err(invalid("rollout selection version exceeds the size limit"));
    }
    let parsed = semver::Version::parse(version).map_err(invalid)?;
    if parsed.to_string() != version || !parsed.pre.is_empty() {
        return Err(invalid(
            "rollout selection requires a canonical stable version",
        ));
    }
    Ok(parsed)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
