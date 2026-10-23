//! The approved local arm-and-flush control plane stays alive while HTTP drains.
#![cfg(unix)]

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

const SOCKET: &str = "upgrade-flush.sock";
const MAX_REQUEST: usize = 1024 * 1024;

pub(super) struct FlushOwner {
    _registration: shutdown_flush::Registration,
    complete: mpsc::SyncSender<io::Result<()>>,
    control: tokio::task::JoinHandle<()>,
    socket: PathBuf,
    /// Process exit used after a started flush failed. A seam so tests can
    /// observe the EX_TEMPFAIL code instead of ending the test process.
    exit: Arc<dyn Fn(i32) + Send + Sync>,
    /// Set (with a stored permit) by the control loop after a started flush
    /// failed and its recovery finished; `finish` exits EX_TEMPFAIL on it.
    flush_failed: Arc<tokio::sync::Notify>,
}

/// Result of an arm-and-flush request. `FlushFailed` means the
/// acknowledged flush started in this process and then failed or overran:
/// the daemon is stopped behind the hook, the previous binary has been
/// restored, and the process must exit EX_TEMPFAIL (engineer ruling
/// 23 Oct 2026) so the service manager restarts the old version.
#[derive(Debug)]
enum ArmFailure {
    /// Refused before any flush started; the daemon keeps serving.
    Refused(io::Error),
    /// The started flush failed; recovery ran inside `arm`.
    FlushFailed(shutdown_flush::FlushFailure),
}
impl ArmFailure {
    #[cfg(test)]
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
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let root = data_root.canonicalize()?;
        let identity_root = identity_root.canonicalize()?;
        let roots = vec![root.clone(), identity_root.clone()];
        let socket = root.join(SOCKET);
        match std::fs::symlink_metadata(&socket) {
            Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(&socket)?,
            Ok(_) => return Err(io::Error::other("upgrade control path is not a socket")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Create the socket with 0600 from the first byte: a umask-widened
        // window between bind and chmod is closed at the source.
        let previous_umask = unsafe { libc::umask(0o077) };
        let bound = tokio::net::UnixListener::bind(&socket);
        unsafe { libc::umask(previous_umask) };
        let listener = bound?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let logs = log_flush::capture(&tracing::dispatcher::get_default(Clone::clone))?;
        let stop = super::routes::daemon_shutdown_hook(&state.shutdown_notify, &state.shutdown_tx);
        let (complete, receive) = mpsc::sync_channel(1);
        let receive = Mutex::new(receive);
        let registration = shutdown_flush::register(
            root.clone(),
            Arc::new(move |deadline, stopped| {
                deadline.check()?;
                stop();
                // The daemon is committed to stopping behind this hook from
                // here: mark the point every later failure recovers from.
                stopped.store(true, std::sync::atomic::Ordering::Release);
                receive
                    .lock()
                    .map_err(|_| io::Error::other("shutdown acknowledgement poisoned"))?
                    .recv_timeout(deadline.instant.saturating_duration_since(Instant::now()))
                    .map_err(io::Error::other)??;
                for root in &roots {
                    sync_tree(root, &deadline)?;
                }
                deadline.check()?;
                log_flush::flush_captured(&logs, deadline.instant)
            }),
        )?;
        let state = Arc::new(ControlContext {
            api_token: state.api_token.clone(),
            api_address: state.api_address,
            identity_root,
        });
        let flush_failed = Arc::new(tokio::sync::Notify::new());
        let failure_signal = Arc::clone(&flush_failed);
        let control = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
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
                let value = match response {
                    Ok(receipt) => serde_json::json!({"receipt": receipt}),
                    Err(error) => serde_json::json!({"error": error.to_string()}),
                };
                if let Ok(mut bytes) = serde_json::to_vec(&value) {
                    bytes.push(b'\n');
                    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(&bytes))
                        .await;
                }
                // Only after the reply is written does the failed flush end
                // this process: the recovery inside `arm` has already
                // restored the previous binary, and `finish` exits
                // EX_TEMPFAIL for a service-manager restart on it.
                if started_flush_failed {
                    failure_signal.notify_one();
                }
            }
        });
        Ok(Self {
            _registration: registration,
            complete,
            control,
            socket,
            exit,
            flush_failed,
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
                    Err(io::Error::other("shutdown producers remain unfinished"))
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
                    // with no API and no network. Recovery already restored
                    // the previous binary and marked the upgrade failed;
                    // exit EX_TEMPFAIL so the service manager restarts the
                    // daemon on the old version.
                    tracing::error!(
                        exit_code = crate::upgrade::restart::flush_failure_exit_code(),
                        "acknowledged shutdown flush failed; exiting EX_TEMPFAIL \
                         for a service-manager restart on the previous binary"
                    );
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
    /// A failed flush restores these together or not at all.
    restore_set: Vec<(PathBuf, PathBuf)>,
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
        || participant.boot_id != crate::upgrade::probe::ProbeClock::now()?.boot_id
        || participant.executable
            != crate::upgrade::apply::current_binary_path().map_err(io::Error::other)?
    {
        return Err(io::Error::other(
            "arm request names a different old participant",
        ));
    }
    if participant.restart.mode == journal::RestartOwner::LauncherChild {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "launcher-child handoff ownership is not implemented",
        ));
    }
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
    })
}

fn arm(
    state: &ControlContext,
    root: &Path,
    bytes: &[u8],
) -> Result<shutdown_flush::Receipt, ArmFailure> {
    let admitted = match admit(state, root, bytes) {
        Ok(admitted) => admitted,
        Err(error) => return Err(ArmFailure::Refused(error)),
    };
    let AdmittedArm {
        plan,
        binding,
        handoff,
        restore_set,
    } = admitted;
    let handoff_path = root.join(journal::HANDOFF_FILE_NAME);
    let flush = shutdown_flush::acknowledge(root, binding, move || {
        journal::write_record(&handoff_path, &handoff)
    });
    match flush {
        Ok(receipt) => Ok(receipt),
        Err(failure) if failure.started => {
            // The flush started and the daemon stopped behind the hook. Hold
            // the failed release first (engineer ruling, 23 Oct 2026) so the
            // restart this exit creates cannot re-apply it, then restore
            // every binary the transaction swapped and leave the EX_TEMPFAIL
            // exit to `finish`.
            if let Err(error) = shutdown_flush::hold_failed_release(
                root,
                &plan.candidate_version,
                &failure.to_string(),
            ) {
                tracing::error!(
                    %error,
                    "cannot persist the failed-upgrade hold; the next automatic \
                     check may retry this release once more"
                );
            }
            let restored_bytes = match crate::upgrade::restore_swapped_binaries(&restore_set) {
                Ok(()) => true,
                Err(error) => {
                    tracing::error!(
                        %error,
                        restore_set = ?restore_set
                            .iter()
                            .map(|(target, _)| target.display().to_string())
                            .collect::<Vec<_>>(),
                        "cannot restore the swapped binaries; manual recovery applies"
                    );
                    false
                }
            };
            tracing::error!(
                error = %failure,
                installed_bytes = true,
                restored_bytes = restored_bytes,
                restart = "not_started",
                recovery = "exited_tempfail",
                "acknowledged shutdown flush failed after the daemon stopped; \
                 release {} is held and the process exits EX_TEMPFAIL",
                plan.candidate_version
            );
            Err(ArmFailure::FlushFailed(failure))
        }
        Err(failure) => Err(ArmFailure::Refused(failure.error)),
    }
}

fn sync_tree(path: &Path, deadline: &shutdown_flush::Deadline) -> io::Result<()> {
    sync_tree_with(path, deadline, &mut std::fs::File::sync_all)
}

// All producers are drained before this barrier. A symlink is not a verified
// store root; refuse it rather than silently omit storage from the receipt.
// A path that vanishes mid-walk (the CLI deletes a scratch file under the
// shared identity root between read_dir and open) has nothing left to sync:
// skip it instead of failing the flush.
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
        return Err(io::Error::other("unverified symlink in shutdown state"));
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
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        deadline.check()?;
        sync(&file)?;
        deadline.check()?;
    } else {
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            return Err(io::Error::other("unsupported shutdown state file type"));
        }
    }
    Ok(())
}

// Native start identity: Linux /proc start ticks, Darwin start microseconds.
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
        // SAFETY: libproc writes exactly the owned, sized output buffer.
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process identity unsupported",
        ))
    }
}

#[cfg(test)]
include!("../../tests/upgrade_arm_flush.rs");
#[cfg(test)]
arm_flush_regression_tests!();
#[cfg(test)]
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

    fn owner(
        root: &Path,
        fail: bool,
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
                if fail {
                    stopped.store(true, Ordering::SeqCst);
                    Err(io::Error::other("injected started flush failure"))
                } else {
                    Ok(())
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
        let (owner, receive, _called, _exit_code) = owner(&root, false);
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
        let (owner, receive, called, _exit_code) = owner(&root, true);
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
        let (owner, receive, _called, _exit_code) = owner(&root, false);
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
        let (owner, receive, _called, exit_code) = owner(&root, true);
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
}
