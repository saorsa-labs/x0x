//! The approved local arm-and-flush control plane stays alive while HTTP drains.
//! Unix serves it on `<data_root>/upgrade-flush.sock` (mode 0600). Windows
//! serves the same newline-delimited JSON protocol on a local named pipe
//! whose DACL admits only the pipe owner (#1588); see `pipe_name`.

use super::state::AppState;
use crate::upgrade::{journal, log_flush, shutdown_flush};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[cfg(unix)]
const SOCKET: &str = "upgrade-flush.sock";
const MAX_REQUEST: usize = 1024 * 1024;

pub(super) struct FlushOwner {
    _registration: shutdown_flush::Registration,
    complete: mpsc::SyncSender<io::Result<()>>,
    control: tokio::task::JoinHandle<()>,
    #[cfg(unix)]
    socket: PathBuf,
    /// Process exit after a completed socket flush or a started failure.
    /// Tests capture the carried status instead of ending the test process.
    exit: Arc<dyn Fn(i32) + Send + Sync>,
    /// Set (with a stored permit) by the control loop after a started flush
    /// failed and its recovery finished; `finish` exits EX_TEMPFAIL on it.
    flush_failed: Arc<tokio::sync::Notify>,
    logs: Option<log_flush::FlushCallback>,
}

/// Result of an arm-and-flush request. `FlushFailed` means the
/// acknowledged flush started in this process and then failed or overran:
/// the daemon is stopped behind the hook, recovery has been attempted,
/// and the process must exit EX_TEMPFAIL (engineer ruling
/// 23 Oct 2026) so the service manager restarts the old version.
#[derive(Debug)]
enum ArmFailure {
    /// Refused before any flush started; the daemon keeps serving.
    Refused(io::Error),
    /// The started flush failed; recovery ran inside `arm`.
    FlushFailed(shutdown_flush::FlushFailure),
}
impl ArmFailure {
    #[cfg(all(test, unix))]
    fn kind(&self) -> io::ErrorKind {
        match self {
            ArmFailure::Refused(error) => error.kind(),
            ArmFailure::FlushFailed(failure) => failure.kind(),
        }
    }
}

impl std::fmt::Display for ArmFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArmFailure::Refused(error) => error.fmt(formatter),
            ArmFailure::FlushFailed(failure) => failure.fmt(formatter),
        }
    }
}

impl Drop for FlushOwner {
    fn drop(&mut self) {
        self.control.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl FlushOwner {
    pub(super) fn start(
        state: &Arc<AppState>,
        data_root: &Path,
        identity_root: &Path,
        exit: Arc<dyn Fn(i32) + Send + Sync>,
    ) -> io::Result<Self> {
        // An unreadable suspend-inclusive clock (for example a missing
        // Windows `BootId`) disables supervised apply here, at startup,
        // instead of at the first arm.
        shutdown_flush::boot_identity()?;
        let root = data_root.canonicalize()?;
        let identity_root = identity_root.canonicalize()?;
        let roots = vec![root.clone(), identity_root.clone()];
        #[cfg(unix)]
        let socket = root.join(SOCKET);
        #[cfg(unix)]
        let listener = {
            use std::os::unix::fs::{FileTypeExt, PermissionsExt};
            match std::fs::symlink_metadata(&socket) {
                Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(&socket)?,
                Ok(_) => return Err(io::Error::other("upgrade control path is not a socket")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            // Restrict this path before accepting requests. Authentication
            // still checks the API token for a connection queued between bind
            // and chmod. Do not change the process-wide umask while other
            // threads create files.
            let listener = tokio::net::UnixListener::bind(&socket)?;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
            listener
        };
        // The owner-only DACL applies from the first instance, before any
        // client can connect; the API token is still checked per request.
        #[cfg(windows)]
        let mut listener = windows_pipe::PipeListener::bind(&pipe_name(&root))?;
        let logs = log_flush::capture(&tracing::dispatcher::get_default(Clone::clone))?;
        let hook_logs = Arc::clone(&logs);
        let stop = super::routes::daemon_shutdown_hook(&state.shutdown_notify, &state.shutdown_tx);
        let (complete, receive) = mpsc::sync_channel(1);
        let receive = Mutex::new(receive);
        let preflight_roots = roots.clone();
        let registration = shutdown_flush::register_with_preflight(
            root.clone(),
            Arc::new(move |deadline, stopped| {
                // The deadline decision and stop marker share the waiter's
                // cancellation lock. A timed-out refusal cannot stop later.
                deadline.commit_stop(stopped)?;
                stop();
                receive
                    .lock()
                    .map_err(|_| io::Error::other("shutdown acknowledgement poisoned"))?
                    .recv_timeout(deadline.instant.saturating_duration_since(Instant::now()))
                    .map_err(io::Error::other)??;
                for root in &roots {
                    sync_tree(root, &deadline)?;
                }
                deadline.check()?;
                log_flush::flush_captured(&hook_logs, deadline.instant)
            }),
            Arc::new(move || scan_flush_state(&preflight_roots)),
        )?;
        let state = Arc::new(ControlContext {
            api_token: state.api_token.clone(),
            api_address: state.api_address,
            identity_root,
        });
        let flush_failed = Arc::new(tokio::sync::Notify::new());
        let failure_signal = Arc::clone(&flush_failed);
        let control_exit = Arc::clone(&exit);
        let control_logs = Arc::clone(&logs);
        let control = tokio::spawn(async move {
            loop {
                #[cfg(unix)]
                let accepted = listener.accept().await.map(|(stream, _)| stream);
                #[cfg(windows)]
                let accepted = listener.accept().await;
                let Ok(mut stream) = accepted else { break };
                let mut bytes = Vec::new();
                let read = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut reader = tokio::io::BufReader::new(&mut stream);
                    tokio::io::AsyncReadExt::take(&mut reader, (MAX_REQUEST + 1) as u64)
                        .read_until(b'\n', &mut bytes)
                        .await
                })
                .await;
                let response = if matches!(read, Ok(Ok(_))) && bytes.len() <= MAX_REQUEST {
                    let state = Arc::clone(&state);
                    let root = root.clone();
                    tokio::task::spawn_blocking(move || arm(&state, &root, &bytes))
                        .await
                        .map_err(|error| ArmFailure::Refused(io::Error::other(error)))
                        .and_then(|result| result)
                } else {
                    Err(ArmFailure::Refused(io::Error::other(
                        "invalid or incomplete arm-and-flush request",
                    )))
                };
                let started_flush_failed = matches!(response, Err(ArmFailure::FlushFailed(_)));
                let success_exit = response.as_ref().ok().map(|armed| armed.exit_code);
                let value = match response {
                    Ok(armed) => serde_json::json!({"receipt": armed.receipt}),
                    Err(error) => serde_json::json!({"error": error.to_string()}),
                };
                if let Ok(mut bytes) = serde_json::to_vec(&value) {
                    bytes.push(b'\n');
                    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(&bytes))
                        .await;
                }
                if let Some(code) = success_exit {
                    // The live receipt proves the barriers completed. End the
                    // old participant after the existing bounded reply attempt,
                    // even if the requester disconnected or `finish` is parked.
                    // Do not log or wait for another shutdown notification after
                    // the acknowledged log barrier. The frozen owner retains
                    // restart/reap/start authority; this only ends this process.
                    // A transactional arm without an established restart-capable
                    // owner is refused at admission and never reaches this
                    // exit (#1670).
                    (control_exit)(code);
                }
                // Only after the reply is written does the failed flush end
                // this process. `arm` completed its recovery (the hold, the
                // restore, the journal archive), so the daemon behind the
                // hook is stopped with no API and no network. Exit
                // EX_TEMPFAIL from the control loop itself (issue #1595,
                // Claude #1566 finding 1): waiting for the shutdown tail to
                // reach `finish` would park that stopped daemon forever if
                // the Agent shutdown hangs, the exact state the 23 Oct 2026
                // ruling forbids. The stored permit still lets an already
                // parked `finish` exit first; either path ends the process.
                if started_flush_failed {
                    failure_signal.notify_one();
                    tracing::error!(
                        exit_code = crate::upgrade::restart::flush_failure_exit_code(),
                        "acknowledged shutdown flush failed; exiting EX_TEMPFAIL \
                         for a service-manager restart on the previous binary"
                    );
                    log_flush::flush_before_exit(Some(&control_logs));
                    (control_exit)(crate::upgrade::restart::flush_failure_exit_code());
                }
            }
        });
        Ok(Self {
            _registration: registration,
            complete,
            control,
            #[cfg(unix)]
            socket,
            exit,
            flush_failed,
            logs: Some(logs),
        })
    }

    pub(super) async fn finish(
        &self,
        result: &anyhow::Result<()>,
        producers_finished: bool,
        cancel: &tokio_util::sync::CancellationToken,
    ) {
        if self._registration.seal_admission() {
            let result = result
                .as_ref()
                .map(|_| ())
                .map_err(|error| io::Error::other(error.to_string()));
            let result = result.and_then(|()| {
                if producers_finished {
                    Ok(())
                } else {
                    // The shared marker names the one transient started-flush
                    // cause that draws the bounded retry budget instead of an
                    // immediate hold (issue #1595).
                    Err(io::Error::other(shutdown_flush::PRODUCERS_UNFINISHED))
                }
            });
            let _ = self.complete.try_send(result);
            // An unused replacement releases an ordinary shutdown that yielded
            // to it. A started receipt keeps recovery custody after failure;
            // only its owner or explicit cancellation may end that wait.
            tokio::select! {
                _ = cancel.cancelled() => {},
                _ = self._registration.wait_for_unused_release() => {},
                _ = self.flush_failed.notified() => {
                    // Engineer ruling 23 Oct 2026: a started flush that
                    // failed or overran must not leave this daemon running
                    // with no API and no network. Recovery already attempted
                    // the restore and marked the upgrade failed;
                    // exit EX_TEMPFAIL so the service manager restarts the
                    // daemon on the old version.
                    tracing::error!(
                        exit_code = crate::upgrade::restart::flush_failure_exit_code(),
                        "acknowledged shutdown flush failed; exiting EX_TEMPFAIL \
                         for a service-manager restart on the previous binary"
                    );
                    log_flush::flush_before_exit(self.logs.as_ref());
                    (self.exit)(crate::upgrade::restart::flush_failure_exit_code());
                },
            }
        }
    }
}

struct ControlContext {
    api_token: String,
    api_address: std::net::SocketAddr,
    identity_root: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    token: String,
    transaction_id: String,
    generation: u64,
    instance_id: String,
    plan: journal::FrozenPlan,
}

/// An authenticated arm request that matched the frozen transaction.
struct AdmittedArm {
    plan: journal::FrozenPlan,
    binding: shutdown_flush::Binding,
    handoff: journal::M2HandoffRecord,
    /// `(target, backup)` for exactly the artifacts the transaction swapped.
    /// Recovery verifies every backup before starting the restore.
    restore_set: Vec<(PathBuf, PathBuf)>,
    journal: Box<journal::JournalRecord>,
    /// Completion status from this participant's frozen restart owner.
    exit_code: i32,
}

/// Only the live acknowledgement creates successful completion authority.
/// The socket still serializes the receipt alone; this status stays local.
#[derive(Debug)]
struct ArmedFlush {
    receipt: shutdown_flush::Receipt,
    exit_code: i32,
}

fn admit(state: &ControlContext, root: &Path, bytes: &[u8]) -> io::Result<AdmittedArm> {
    let request: Request = serde_json::from_slice(bytes)?;
    if !bool::from(
        Sha256::digest(request.token.as_bytes()).ct_eq(&Sha256::digest(state.api_token.as_bytes())),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid control credential",
        ));
    }
    let journal::RecordRead::Journal(record) = journal::read_boot_records(root).journal else {
        return Err(io::Error::other("no prepared host transaction"));
    };
    if record.transaction_id != request.transaction_id
        || record.generation != request.generation
        || !matches!(
            record.phase,
            journal::Phase::SwappedCli | journal::Phase::HandoffArmed
        )
        || serde_json::to_vec(&record.plan)? != serde_json::to_vec(&request.plan)?
    {
        return Err(io::Error::other(
            "arm request does not match the frozen transaction",
        ));
    }
    let participant = request
        .plan
        .participants
        .iter()
        .find(|p| p.instance_id == request.instance_id)
        .ok_or_else(|| io::Error::other("participant absent from frozen plan"))?;
    if participant.data_root.canonicalize()? != root
        || participant.identity_root.canonicalize()? != state.identity_root
        || !participant.was_running
        || participant.process_start != Some(process_start()?)
        || participant.old_pid != Some(std::process::id())
        || participant.boot_id != shutdown_flush::boot_identity()?
        || participant.executable
            != crate::upgrade::apply::current_binary_path().map_err(io::Error::other)?
    {
        return Err(io::Error::other(
            "arm request names a different old participant",
        ));
    }
    let exit_code = match participant.restart.mode {
        journal::RestartOwner::SupervisedExit => participant
            .restart
            .supervised_exit_code
            .unwrap_or_else(crate::upgrade::restart::supervised_exit_code),
        // The participant stops cleanly only for an established external
        // handoff owner that can reap it and start the candidate. No owner
        // can be established yet (#1670), so refuse before the shutdown;
        // the daemon keeps serving. This path neither requests a supervisor
        // restart nor starts a helper/candidate.
        journal::RestartOwner::TransactionalHandoff => {
            crate::upgrade::restart::transactional_flush_owner(&participant.restart)
                .map_err(|reason| io::Error::new(io::ErrorKind::Unsupported, reason))?;
            0
        }
        journal::RestartOwner::LauncherChild => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "launcher-child handoff ownership is not implemented",
            ));
        }
    };
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    let legacy = serde_json::json!({
        "from_version": request.plan.previous_version, "to_version": request.plan.candidate_version,
        "target_path": request.plan.daemon.target_path, "backup_path": request.plan.daemon.backup_path,
        "argv": participant.argv, "cwd": participant.cwd, "env": participant.env,
        "old_pid": participant.old_pid, "api_addr": state.api_address.to_string(), "started_at": started_at,
        "mode": participant.restart.mode, "launchd_verified": participant.restart.launchd_verified,
        "systemd_verified": participant.restart.systemd_verified,
    });
    let handoff = journal::M2HandoffRecord {
        schema_version: journal::SCHEMA_VERSION,
        record_kind: "handoff".into(),
        transaction_id: request.transaction_id.clone(),
        generation: request.generation,
        instance_id: request.instance_id.clone(),
        legacy: serde_json::from_value(legacy)?,
    };
    let plan = request.plan.clone();
    let binding = shutdown_flush::Binding::new(
        request.transaction_id,
        request.generation,
        &(request.instance_id, request.plan),
    )?;
    let restore_set = [
        (record.daemon_progress.swapped, &plan.daemon),
        (record.cli_progress.swapped, &plan.cli),
    ]
    .into_iter()
    .filter(|(swapped, _)| *swapped)
    .map(|(_, artifact)| (artifact.target_path.clone(), artifact.backup_path.clone()))
    .collect();
    Ok(AdmittedArm {
        plan,
        binding,
        handoff,
        restore_set,
        journal: record,
        exit_code,
    })
}

#[derive(Default)]
struct ArmPreparation {
    cancelled: bool,
    wrote_handoff: bool,
}

fn arm(state: &ControlContext, root: &Path, bytes: &[u8]) -> Result<ArmedFlush, ArmFailure> {
    let admitted = match admit(state, root, bytes) {
        Ok(admitted) => admitted,
        Err(error) => return Err(ArmFailure::Refused(error)),
    };
    // Retain the reservation through refusal recovery. A competing socket
    // arm or auto-apply cannot see the restored bytes with the old journal.
    let reservation = shutdown_flush::reserve(root).map_err(ArmFailure::Refused)?;
    reservation.activate().map_err(ArmFailure::Refused)?;
    // Admission may have changed since authentication read the journal.
    let current = admit(state, root, bytes).map_err(ArmFailure::Refused)?;
    if serde_json::to_vec(&current.journal)
        .map_err(io::Error::from)
        .map_err(ArmFailure::Refused)?
        != serde_json::to_vec(&admitted.journal)
            .map_err(io::Error::from)
            .map_err(ArmFailure::Refused)?
    {
        return Err(ArmFailure::Refused(io::Error::other(
            "host transaction changed before admission",
        )));
    }
    let AdmittedArm {
        plan,
        binding,
        handoff,
        restore_set,
        journal,
        exit_code,
    } = current;
    let handoff_path = root.join(journal::HANDOFF_FILE_NAME);
    // Serialize a late prepare with refusal cleanup, including a timed-out
    // worker. A cancelled prepare can never leave a handoff after cleanup.
    let preparation = Arc::new(Mutex::new(ArmPreparation::default()));
    let worker_preparation = Arc::clone(&preparation);
    let worker_handoff = handoff.clone();
    let flush = shutdown_flush::acknowledge_reserved(
        root,
        binding,
        move || {
            let mut state = worker_preparation
                .lock()
                .map_err(|_| io::Error::other("arm preparation poisoned"))?;
            if state.cancelled {
                return Err(io::Error::other("arm preparation cancelled"));
            }
            match std::fs::symlink_metadata(&handoff_path) {
                Ok(_) => return Err(io::Error::other("handoff already exists")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            // A failed final directory sync can still leave the written record.
            state.wrote_handoff = true;
            journal::write_record(&handoff_path, &worker_handoff)
        },
        &reservation,
    );
    match flush {
        Ok(receipt) => Ok(ArmedFlush { receipt, exit_code }),
        Err(shutdown_flush::FlushFailure::NotOwned(error)) => Err(ArmFailure::Refused(error)),
        Err(failure @ shutdown_flush::FlushFailure::Started(_)) => {
            // The flush started and the daemon stopped behind the hook. Hold
            // the failed release first — or spend one of the bounded
            // producer-drain retries (engineer ruling, 23 Oct 2026;
            // issue #1595) — so the restart this exit creates cannot
            // re-apply a release that fails deterministically, then restore
            // every binary the transaction swapped and leave the EX_TEMPFAIL
            // exit to the control loop after its reply.
            shutdown_flush::hold_or_retry_started_failure(root, &plan.candidate_version, &failure);
            let recovery_complete = match restore_arm(
                root,
                *journal,
                &handoff,
                true,
                &restore_set,
                journal::Cause {
                    class: journal::CauseClass::Failed,
                    reason: format!("shutdown flush failure: {failure}"),
                },
            ) {
                Ok(()) => true,
                Err(error) => {
                    tracing::error!(
                        %error,
                        restore_set = ?restore_set
                            .iter()
                            .map(|(target, _)| target.display().to_string())
                            .collect::<Vec<_>>(),
                        "cannot resolve the failed arm; active records retained, manual recovery applies"
                    );
                    false
                }
            };
            tracing::error!(
                error = %failure,
                installed_bytes = true,
                recovery_complete,
                restart = "not_started",
                recovery = "exited_tempfail",
                "acknowledged shutdown flush failed after the daemon stopped; \
                 release {} is held and the process exits EX_TEMPFAIL",
                plan.candidate_version
            );
            Err(ArmFailure::FlushFailed(failure))
        }
        Err(shutdown_flush::FlushFailure::Refused(error)) => {
            let recovery = (|| {
                let mut state = preparation
                    .lock()
                    .map_err(|_| io::Error::other("arm preparation poisoned"))?;
                state.cancelled = true;
                restore_arm(
                    root,
                    *journal,
                    &handoff,
                    state.wrote_handoff,
                    &restore_set,
                    journal::Cause {
                        class: journal::CauseClass::Interrupted,
                        reason: error.to_string(),
                    },
                )
            })();
            if let Err(recovery_error) = recovery {
                tracing::error!(%error, %recovery_error,
                    "owned arm refused; recovery incomplete, active records retained for manual recovery");
            } else {
                tracing::warn!(%error,
                    "owned arm refused; swapped bytes restored, journal archived, daemon keeps serving");
            }
            Err(ArmFailure::Refused(error))
        }
    }
}

/// This call owns admission until recovery finishes. Mark rollback before
/// touching installed bytes, so a partial restore can never admit a retry.
fn restore_arm(
    root: &Path,
    mut record: journal::JournalRecord,
    handoff: &journal::M2HandoffRecord,
    wrote_handoff: bool,
    restore_set: &[(PathBuf, PathBuf)],
    cause: journal::Cause,
) -> io::Result<()> {
    let journal_path = root.join(journal::JOURNAL_FILE_NAME);
    let journal::RecordRead::Journal(current) = journal::read_boot_records(root).journal else {
        return Err(io::Error::other("arm recovery journal unavailable"));
    };
    if serde_json::to_vec(&current)? != serde_json::to_vec(&record)? {
        return Err(io::Error::other("arm recovery journal changed"));
    }
    record.sequence = record
        .sequence
        .checked_add(1)
        .ok_or_else(|| io::Error::other("journal sequence exhausted"))?;
    record.phase = journal::Phase::RollingBack;
    let archive_kind = match cause.class {
        journal::CauseClass::Failed => "failed",
        journal::CauseClass::Interrupted => "refused",
    };
    record.cause = Some(cause);
    journal::write_record(&journal_path, &record)?;
    crate::upgrade::restore_swapped_binaries(restore_set).map_err(io::Error::other)?;
    for progress in [&mut record.daemon_progress, &mut record.cli_progress] {
        if progress.swapped {
            progress.swapped = false;
            progress.restored = true;
            // No hash was observed by the rename-based restore.
            progress.observed_sha256 = None;
        }
    }
    record.sequence = record
        .sequence
        .checked_add(1)
        .ok_or_else(|| io::Error::other("journal sequence exhausted"))?;
    record.phase = journal::Phase::Restored;
    journal::write_record(&journal_path, &record)?;
    if wrote_handoff {
        match journal::read_boot_records(root).handoff {
            journal::RecordRead::Missing => {}
            journal::RecordRead::Handoff(current)
                if serde_json::to_vec(&current)? == serde_json::to_vec(handoff)? =>
            {
                std::fs::remove_file(root.join(journal::HANDOFF_FILE_NAME))?;
                journal::open_for_sync(root, true)?.sync_all()?;
            }
            _ => return Err(io::Error::other("arm recovery handoff changed; preserved")),
        }
    }
    // Keep the resolved evidence without weakening blocks_apply's rule for
    // active M2 journals. A replay has no active swapped plan to acknowledge.
    let archive = root.join(format!(
        "upgrade-{archive_kind}-{}.json",
        uuid::Uuid::new_v4()
    ));
    std::fs::rename(&journal_path, &archive)?;
    journal::open_for_sync(root, true)?.sync_all()
}

fn sync_tree(path: &Path, deadline: &shutdown_flush::Deadline) -> io::Result<()> {
    sync_tree_with(path, deadline, &mut std::fs::File::sync_all)
}

/// Metadata-only walk of the flush roots with the flush's own refusal
/// rules (issue #1595). No fsync runs, so a long clock ceiling bounds only
/// the walk. Sockets — including this control plane's own — are accepted
/// exactly as at flush time; the first refused path is named in the error
/// so admission can surface it before an upgrade changes any byte.
pub(super) fn scan_flush_state(roots: &[PathBuf]) -> io::Result<()> {
    let deadline = shutdown_flush::Deadline::preflight()?;
    for root in roots {
        sync_tree_with(root, &deadline, &mut |_| Ok(()))?;
    }
    Ok(())
}

// All producers are drained before this barrier. A symlink is not a verified
// store root; refuse it — naming the path — rather than silently omit
// storage from the receipt. A path that vanishes mid-walk (the CLI deletes
// a scratch file under the shared identity root between read_dir and open)
// has nothing left to sync: skip it instead of failing the flush.
fn sync_tree_with(
    path: &Path,
    deadline: &shutdown_flush::Deadline,
    sync: &mut impl FnMut(&std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    deadline.check()?;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    deadline.check()?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "unverified symlink in shutdown state: {}",
            path.display()
        )));
    }
    if meta.is_dir() {
        deadline.check()?;
        let mut entries = std::fs::read_dir(path)?;
        loop {
            deadline.check()?;
            let entry = entries.next();
            deadline.check()?;
            let Some(entry) = entry else { break };
            match entry {
                Ok(entry) => sync_tree_with(&entry.path(), deadline, sync)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
        }
    }
    if meta.is_dir() || meta.is_file() {
        deadline.check()?;
        // Windows opens with write access for FlushFileBuffers, so a
        // read-only-attribute file refuses here. The admission preflight
        // runs this same open, so that refusal comes before any byte changes.
        let file = match journal::open_for_sync(path, meta.is_dir()) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("cannot open shutdown state {}: {error}", path.display()),
                ))
            }
        };
        deadline.check()?;
        sync(&file)?;
        deadline.check()?;
    } else {
        // Only the Unix control socket is accepted. The Windows control pipe
        // lives in the pipe namespace, not in the data root.
        #[cfg(unix)]
        let accepted = {
            use std::os::unix::fs::FileTypeExt;
            meta.file_type().is_socket()
        };
        #[cfg(not(unix))]
        let accepted = false;
        if !accepted {
            return Err(io::Error::other(format!(
                "unsupported shutdown state file type: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

// Native start identity: Linux /proc start ticks, Darwin start microseconds,
// Windows creation time in 100 ns FILETIME units.
fn process_start() -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let fields = stat
            .rsplit_once(')')
            .ok_or_else(|| io::Error::other("invalid process stat"))?
            .1;
        fields
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| io::Error::other("missing process start"))?
            .parse()
            .map_err(io::Error::other)
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: proc_bsdinfo contains integer fields and fixed byte arrays;
        // zero is a valid initial value for each field.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        // SAFETY: proc_pidinfo writes at most `size` bytes into the owned,
        // sized `info` buffer and reads only the pid and arguments passed.
        let received = unsafe {
            libc::proc_pidinfo(
                std::process::id() as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if received != size {
            return Err(io::Error::other("cannot read process start identity"));
        }
        info.pbi_start_tvsec
            .checked_mul(1_000_000)
            .and_then(|n| n.checked_add(info.pbi_start_tvusec))
            .ok_or_else(|| io::Error::other("process start identity overflow"))
    }
    #[cfg(windows)]
    {
        windows_pipe::process_creation_time()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process identity unsupported",
        ))
    }
}

/// Windows control pipe for one data root (#1588): a local requester derives
/// it from the canonical data root, as a Unix requester derives
/// `<data_root>/upgrade-flush.sock`. Windows paths are case-insensitive, so
/// the root is lowercased before hashing.
#[cfg(any(windows, test))]
pub(super) fn pipe_name(root: &Path) -> String {
    let digest = Sha256::digest(root.to_string_lossy().to_lowercase().as_bytes());
    let hex: String = digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(r"\\.\pipe\x0x-upgrade-flush-{hex}")
}

/// Owner-only pipe DACL: protected (no inherited ACEs), full access for the
/// `OWNER RIGHTS` SID only. Other local users cannot open the pipe, and
/// `reject_remote_clients` refuses network clients.
#[cfg(windows)]
const PIPE_SDDL: &str = "D:P(A;;GA;;;OW)";

#[cfg(windows)]
mod windows_pipe {
    use std::{ffi::c_void, io, os::windows::ffi::OsStrExt};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetCurrentProcess() -> isize;
        fn GetProcessTimes(
            process: isize,
            creation: *mut u64,
            exit: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
    }

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }

    /// A self-relative security descriptor owned by `LocalFree`.
    struct Descriptor(*mut c_void);
    // SAFETY: the descriptor is immutable after creation and only read by
    // CreateNamedPipeW; LocalFree runs once, in Drop.
    unsafe impl Send for Descriptor {}
    unsafe impl Sync for Descriptor {}
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: the pointer came from the SDDL conversion and is freed once.
            unsafe { LocalFree(self.0) };
        }
    }

    pub(super) struct PipeListener {
        name: String,
        descriptor: Descriptor,
        server: NamedPipeServer,
    }

    impl PipeListener {
        pub(super) fn bind(name: &str) -> io::Result<Self> {
            let sddl: Vec<u16> = std::ffi::OsStr::new(super::PIPE_SDDL)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let mut descriptor = std::ptr::null_mut();
            // SAFETY: `sddl` is a nul-terminated UTF-16 buffer that outlives
            // the call; the output pointer is owned by `Descriptor` on success.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let descriptor = Descriptor(descriptor);
            // The first instance refuses a name another process already
            // holds, so a squatter cannot receive the owner's requests.
            let server = create(name, &descriptor, true)?;
            Ok(Self {
                name: name.to_owned(),
                descriptor,
                server,
            })
        }

        /// Wait for one client. The next instance is created before the
        /// connected one is handed out, so the name is never unowned.
        pub(super) async fn accept(&mut self) -> io::Result<NamedPipeServer> {
            self.server.connect().await?;
            let next = create(&self.name, &self.descriptor, false)?;
            Ok(std::mem::replace(&mut self.server, next))
        }
    }

    fn create(name: &str, descriptor: &Descriptor, first: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.0,
            inherit: 0,
        };
        // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor
        // stays alive in the listener for every instance it creates.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    name,
                    (&mut attributes as *mut SecurityAttributes).cast(),
                )
        }
    }

    pub(super) fn process_creation_time() -> io::Result<u64> {
        let (mut creation, mut exit, mut kernel, mut user) = (0_u64, 0_u64, 0_u64, 0_u64);
        // SAFETY: the pseudo-handle needs no close; each output is an owned,
        // 8-byte FILETIME-sized buffer.
        if unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(creation)
    }
}

#[cfg(all(test, unix))]
include!("../../tests/upgrade_arm_flush.rs");
#[cfg(all(test, unix))]
arm_flush_regression_tests!();
#[cfg(all(test, unix))]
mod arm_flush_regressions_unused_reservation {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio_util::sync::CancellationToken;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let root = std::env::var_os("X0X_UPGRADE_FLUSH_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/upgrade-flush-fixtures")
            });
        std::fs::create_dir_all(&root).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("unused-waiter-")
            .tempdir_in(root)
            .unwrap();
        let root = dir.path().canonicalize().unwrap();
        (dir, root)
    }

    /// What the fixture hook does: succeed, fail after committing the stop
    /// (a started failure), or fail before it (an ordinary refusal).
    #[derive(Clone, Copy, PartialEq)]
    enum HookOutcome {
        Ok,
        StartedFailure,
        PreStopRefusal,
    }

    fn owner(
        root: &Path,
        outcome: HookOutcome,
    ) -> (
        FlushOwner,
        mpsc::Receiver<io::Result<()>>,
        Arc<AtomicBool>,
        Arc<std::sync::atomic::AtomicI32>,
    ) {
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        let registration = shutdown_flush::register(
            root.to_path_buf(),
            Arc::new(move |_, stopped| {
                observed.store(true, Ordering::SeqCst);
                match outcome {
                    HookOutcome::Ok => Ok(()),
                    HookOutcome::StartedFailure => {
                        stopped.store(true, Ordering::SeqCst);
                        Err(io::Error::other("injected started flush failure"))
                    }
                    HookOutcome::PreStopRefusal => {
                        Err(io::Error::other("injected pre-stop flush refusal"))
                    }
                }
            }),
        )
        .unwrap();
        let (complete, receive) = mpsc::sync_channel(1);
        let exit_code = Arc::new(std::sync::atomic::AtomicI32::new(-1));
        let observed_exit = Arc::clone(&exit_code);
        (
            FlushOwner {
                _registration: registration,
                complete,
                control: tokio::spawn(std::future::pending()),
                // This fixture creates no socket and no Agent or network runtime.
                socket: root.join("never-bound.sock"),
                exit: Arc::new(move |code| {
                    observed_exit.store(code, Ordering::SeqCst);
                }),
                flush_failed: Arc::new(tokio::sync::Notify::new()),
                logs: None,
            },
            receive,
            called,
            exit_code,
        )
    }

    async fn finish_observed_armed(receive: mpsc::Receiver<io::Result<()>>) {
        tokio::task::spawn_blocking(move || receive.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_finish_wakes_when_unused_reservation_is_released() {
        let (_dir, root) = fixture();
        let (owner, receive, _called, _exit_code) = owner(&root, HookOutcome::Ok);
        let reservation = shutdown_flush::reserve(&root).unwrap();
        reservation.activate().unwrap();
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let mut finish = tokio::spawn(async move {
            owner.finish(&Ok(()), true, &worker_cancel).await;
        });
        // Receipt of complete proves finish observed armed=true before release.
        finish_observed_armed(receive).await;
        drop(reservation);
        assert!(shutdown_flush::ensure_ready(&root).is_err());
        assert!(shutdown_flush::reserve(&root).is_err());
        let outcome = tokio::time::timeout(Duration::from_secs(2), &mut finish).await;
        let resumed_without_cancel = outcome.is_ok();
        cancel.cancel();
        match outcome {
            Ok(result) => result.unwrap(),
            Err(_) => finish.await.unwrap(),
        }
        assert!(
            resumed_without_cancel,
            "ordinary shutdown remained parked after unused release"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_finish_keeps_started_acknowledgment_custody_until_cancelled() {
        let (_dir, root) = fixture();
        let (owner, receive, called, _exit_code) = owner(&root, HookOutcome::StartedFailure);
        let reservation = shutdown_flush::reserve(&root).unwrap();
        reservation.activate().unwrap();
        let binding =
            shutdown_flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
        assert!(
            shutdown_flush::acknowledge_reserved(&root, binding, || Ok(()), &reservation,).is_err()
        );
        owner._registration.join_workers();
        assert!(called.load(Ordering::SeqCst));
        drop(reservation);
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let mut finish = tokio::spawn(async move {
            owner.finish(&Ok(()), true, &worker_cancel).await;
        });
        finish_observed_armed(receive).await;
        let outcome = tokio::time::timeout(Duration::from_millis(100), &mut finish).await;
        let retained_custody = outcome.is_err();
        cancel.cancel();
        match outcome {
            Ok(result) => result.unwrap(),
            Err(_) => finish.await.unwrap(),
        }
        assert!(
            retained_custody,
            "started acknowledgment must retain recovery custody"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_finish_refuses_the_receipt_when_producers_are_unfinished() {
        let (_dir, root) = fixture();
        let (owner, receive, _called, _exit_code) = owner(&root, HookOutcome::Ok);
        let reservation = shutdown_flush::reserve(&root).unwrap();
        reservation.activate().unwrap();
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let mut finish = tokio::spawn(async move {
            owner.finish(&Ok(()), false, &worker_cancel).await;
        });
        // A clean process result cannot authorize a receipt while a producer
        // (an aborted HTTP drain or background straggler) remains unfinished.
        let refusal =
            tokio::task::spawn_blocking(move || receive.recv_timeout(Duration::from_secs(5)))
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
        assert_eq!(refusal.to_string(), "shutdown producers remain unfinished");
        // The unused reservation releases the parked ordinary shutdown.
        drop(reservation);
        match tokio::time::timeout(Duration::from_secs(2), &mut finish).await {
            Ok(result) => result.unwrap(),
            Err(_) => {
                cancel.cancel();
                finish.await.unwrap();
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_finish_exits_tempfail_after_a_failed_started_flush() {
        let (_dir, root) = fixture();
        let (mut owner, receive, _called, exit_code) = owner(&root, HookOutcome::StartedFailure);
        let flushed = Arc::new(AtomicBool::new(false));
        let observed_flush = flushed.clone();
        owner.logs = Some(Arc::new(move |_| {
            observed_flush.store(true, Ordering::Release);
            let (send, receive) = mpsc::channel();
            send.send(Ok(())).unwrap();
            vec![receive]
        }));
        let previous_exit = owner.exit.clone();
        owner.exit = Arc::new(move |code| {
            assert!(
                flushed.load(Ordering::Acquire),
                "finish exited before its log barrier"
            );
            previous_exit(code);
        });
        let reservation = shutdown_flush::reserve(&root).unwrap();
        reservation.activate().unwrap();
        let binding =
            shutdown_flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
        assert!(
            shutdown_flush::acknowledge_reserved(&root, binding, || Ok(()), &reservation).is_err()
        );
        owner._registration.join_workers();
        drop(reservation);
        let failed_signal = Arc::clone(&owner.flush_failed);
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let mut finish = tokio::spawn(async move {
            owner.finish(&Ok(()), true, &worker_cancel).await;
        });
        finish_observed_armed(receive).await;
        // Engineer ruling 23 Oct 2026: the failed started flush must not
        // park this daemon with no API and no network. The failure signal
        // alone ends the wait with EX_TEMPFAIL, without cancellation.
        failed_signal.notify_one();
        tokio::time::timeout(Duration::from_secs(2), &mut finish)
            .await
            .expect("finish must end on the failure signal")
            .unwrap();
        assert_eq!(
            exit_code.load(Ordering::SeqCst),
            crate::upgrade::restart::flush_failure_exit_code()
        );
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_finish_completes_promptly_after_a_refused_flush() {
        // Engineer ruling, 24 Oct 2026: a flush refused before the daemon
        // stopped is not a failed start. Once its unused reservation is
        // released, an ordinary shutdown that yielded to the flush must
        // resume on its own — without cancellation and without the
        // EX_TEMPFAIL exit, which belongs only to a started failure.
        let (_dir, root) = fixture();
        let (owner, _receive, _called, exit_code) = owner(&root, HookOutcome::PreStopRefusal);
        let reservation = shutdown_flush::reserve(&root).unwrap();
        reservation.activate().unwrap();
        let binding =
            shutdown_flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
        let refused = tokio::task::spawn_blocking(move || {
            let outcome =
                shutdown_flush::acknowledge_reserved(&root, binding, || Ok(()), &reservation);
            // The refused reservation's last owner releases admission here.
            drop(reservation);
            outcome
        })
        .await
        .unwrap();
        assert!(refused.is_err());
        assert!(!refused.unwrap_err().started());
        owner._registration.join_workers();
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let finish = tokio::spawn(async move {
            owner.finish(&Ok(()), true, &worker_cancel).await;
        });
        tokio::time::timeout(Duration::from_secs(2), finish)
            .await
            .expect("finish must resume without cancellation after a refusal")
            .unwrap();
        assert_eq!(
            exit_code.load(Ordering::SeqCst),
            -1,
            "a refusal must not exit EX_TEMPFAIL"
        );
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn later_ordinary_shutdown_after_a_pre_stop_deadline_overrun_exits_normally() {
        // Engineer ruling, 24 Oct 2026: when the 30 s deadline passes before
        // the hook calls stop(), the daemon never stopped, so the overrun is
        // a refusal. No "flush failed" permit is stored and admission is
        // released, so a later ordinary SIGTERM finishes normally (exit 0),
        // never EX_TEMPFAIL — exit 75 belongs only to a flush that started
        // (the daemon stopped) and then failed or overran.
        let (_dir, root) = fixture();
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let registration = shutdown_flush::register_with_limit(
            root.clone(),
            Arc::new(move |deadline, _| {
                let _ = entered.send(());
                // Hold past the deadline without ever committing the stop,
                // then concede the deadline like the production hook's
                // entry check would.
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(io::Error::other)?;
                deadline.check()
            }),
            Duration::from_millis(300),
        )
        .unwrap();
        let (complete, _receive) = mpsc::sync_channel(1);
        let exit_code = Arc::new(std::sync::atomic::AtomicI32::new(-1));
        let observed_exit = Arc::clone(&exit_code);
        let owner = FlushOwner {
            _registration: registration,
            complete,
            control: tokio::spawn(std::future::pending()),
            // This fixture creates no socket and no Agent or network runtime.
            socket: root.join("never-bound.sock"),
            exit: Arc::new(move |code| {
                observed_exit.store(code, Ordering::SeqCst);
            }),
            flush_failed: Arc::new(tokio::sync::Notify::new()),
            logs: None,
        };
        let overrun_root = root.clone();
        let overrun = tokio::task::spawn_blocking(move || {
            let binding =
                shutdown_flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
            shutdown_flush::acknowledge(&overrun_root, binding, || Ok(()))
        });
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let failure = overrun.await.unwrap().unwrap_err();
        assert!(
            !failure.started(),
            "the daemon never stopped behind the hook"
        );
        let _ = release.send(());
        owner._registration.join_workers();
        let cancel = tokio_util::sync::CancellationToken::new();
        let worker_cancel = cancel.clone();
        let finish = tokio::spawn(async move { owner.finish(&Ok(()), true, &worker_cancel).await });
        tokio::time::timeout(Duration::from_secs(2), finish)
            .await
            .expect("an ordinary shutdown after the overrun must not wait")
            .unwrap();
        assert_eq!(
            exit_code.load(Ordering::SeqCst),
            -1,
            "an overrun before the stop must not exit EX_TEMPFAIL"
        );
        assert!(!cancel.is_cancelled());
    }
}

#[cfg(test)]
mod windows_control_channel_regressions {
    use super::*;

    #[test]
    fn pipe_name_is_local_stable_per_root_and_case_insensitive() {
        let root = Path::new(r"\\?\C:\Users\Alice\AppData\Roaming\x0x");
        let name = pipe_name(root);
        assert!(name.starts_with(r"\\.\pipe\x0x-upgrade-flush-"));
        assert_eq!(name.len(), r"\\.\pipe\x0x-upgrade-flush-".len() + 32);
        assert_eq!(name, pipe_name(root));
        assert_eq!(
            name,
            pipe_name(Path::new(r"\\?\c:\users\alice\appdata\roaming\x0x"))
        );
        assert_ne!(name, pipe_name(Path::new(r"\\?\C:\Users\Bob\x0x")));
    }
}
