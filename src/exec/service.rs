//! Exec runtime: inbound frame dispatcher, remote client aggregation, and local child runner.

use super::acl::{argv_has_shell_metachar, ExecAcl, ExecCaps, ExecPolicy};
use super::audit::ExecAudit;
use super::diagnostics::{ExecDiagnostics, ExecDiagnosticsSnapshot};
use super::protocol::{
    decode_frame_payload, encode_frame_payload, DenialReason, ExecFrame, ExecRequestId,
    ExecRunResult, StreamKind, WarningKind,
};
use crate::dm::{DmError, DmSendConfig};
use crate::dm_inbox::DmTypedPayload;
use crate::identity::{AgentId, MachineId};
use crate::trust::TrustDecision;
use crate::Agent;
use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, watch, Mutex};

const EXEC_FRAME_CHANNEL: usize = 256;
const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(2);
// Keep below the 5s SLA; peer lifecycle events are the fast path, lease expiry is the backstop.
const LEASE_TIMEOUT: Duration = Duration::from_secs(4);
const CANCEL_GRACE: Duration = Duration::from_secs(5);
// Server-side idle guard: unlike the 4s client lease, this tracks child
// stdout/stderr/exit progress so a renewing but stuck/silent session cannot
// live forever if lifecycle disconnect events are missed.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SESSION_IDLE_SCAN_INTERVAL: Duration = Duration::from_secs(30);

/// Options for a remote exec run originated by this daemon.
#[derive(Debug, Clone)]
pub struct ExecRunOptions {
    pub argv: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout_ms: Option<u32>,
    pub cwd: Option<String>,
}

/// Tier-1 exec service.
pub struct ExecService {
    agent: Arc<Agent>,
    policy: Arc<ExecPolicy>,
    diagnostics: Arc<ExecDiagnostics>,
    audit: ExecAudit,
    pending_clients: Mutex<HashMap<ExecRequestId, PendingClient>>,
    active_servers: Mutex<HashMap<ExecRequestId, ActiveServerSession>>,
    active_counts: Mutex<ActiveCounts>,
    /// Cancellation token driving deterministic teardown of the three
    /// long-lived loops below (inbound dispatch, peer lifecycle, session idle)
    /// and of per-request handler tasks (issue #118).
    cancellation_token: tokio_util::sync::CancellationToken,
    /// Handles for the three spawned loops, drained by `shutdown()`.
    task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Per-request handler task handles, drained by `shutdown()` (issue #118).
    /// A handler removes its own entry on completion; `shutdown()` aborts any
    /// that are still alive after the grace window.
    request_task_handles: Mutex<HashMap<ExecRequestId, tokio::task::JoinHandle<()>>>,
    /// Serializes concurrent `shutdown()` calls (issue #118): without it a
    /// second caller could observe a half-cleared state, complete
    /// `join_all(empty)` immediately, clear bookkeeping, and return while the
    /// first caller is still aborting stragglers.
    shutdown_lock: tokio::sync::Mutex<()>,
}

struct PendingClient {
    target: AgentId,
    tx: mpsc::Sender<ExecFrame>,
    argv_summary: String,
    started_at: Instant,
}

#[derive(Clone)]
struct ActiveServerSession {
    agent_id: AgentId,
    machine_id: MachineId,
    cancel_tx: watch::Sender<CancelReason>,
    lease_deadline: Arc<Mutex<Instant>>,
    /// Last observed server-side child activity (stdout/stderr/exit), not
    /// client lease renewals. This makes the idle timeout an orthogonal
    /// backstop instead of a slower duplicate of lease expiry.
    last_activity: Arc<Mutex<Instant>>,
    argv_summary: String,
    started_at: Instant,
    /// PID of the spawned child (0 until `cmd.spawn()` succeeds). Stored so
    /// `shutdown()` can SIGKILL out-of-band without waiting for the handler
    /// task to observe its cancel signal (issue #118).
    child_pid: Arc<AtomicU32>,
}

#[derive(Default)]
struct ActiveCounts {
    total: u32,
    per_agent: HashMap<AgentId, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelReason {
    ExplicitCancel,
    LeaseExpired,
    PeerDisconnected,
    DurationCap,
    IdleTimeout,
    /// Service-wide shutdown: skip the normal CANCEL_GRACE and terminate the
    /// child immediately. Sent by `shutdown()` to every active session.
    Shutdown,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecServiceError {
    #[error("exec protocol error: {0}")]
    Protocol(String),
    #[error("exec transport error: {0}")]
    Transport(String),
    #[error("exec request timed out waiting for remote exit")]
    Timeout,
    #[error("exec request was denied: {0}")]
    Denied(&'static str),
    #[error("exec response channel closed")]
    ResponseChannelClosed,
}

impl ExecService {
    /// Spawn the exec service inbound loop.
    #[must_use]
    pub fn spawn(
        agent: Arc<Agent>,
        policy: ExecPolicy,
        inbound_rx: mpsc::Receiver<DmTypedPayload>,
    ) -> Arc<Self> {
        let policy = Arc::new(policy);
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        let audit = ExecAudit::new(&policy, Arc::clone(&diagnostics));
        let service = Arc::new(Self {
            agent,
            policy,
            diagnostics,
            audit,
            pending_clients: Mutex::new(HashMap::new()),
            active_servers: Mutex::new(HashMap::new()),
            active_counts: Mutex::new(ActiveCounts::default()),
            cancellation_token: tokio_util::sync::CancellationToken::new(),
            task_handles: Mutex::new(Vec::new()),
            request_task_handles: Mutex::new(HashMap::new()),
            shutdown_lock: tokio::sync::Mutex::new(()),
        });
        let loop_service = Arc::clone(&service);
        let inbound_handle = tokio::spawn(async move {
            loop_service.run_inbound_loop(inbound_rx).await;
        });
        let lifecycle_service = Arc::clone(&service);
        let lifecycle_handle = tokio::spawn(async move {
            lifecycle_service.run_peer_lifecycle_loop().await;
        });
        let idle_service = Arc::clone(&service);
        let idle_handle = tokio::spawn(async move {
            idle_service.run_session_idle_loop().await;
        });
        // Stash the handles so `shutdown()` can grace-await then abort them.
        // `try_lock` always succeeds here: this is the only access before the
        // service is shared, and the lock is uncontended at construction.
        if let Ok(mut guard) = service.task_handles.try_lock() {
            guard.extend([inbound_handle, lifecycle_handle, idle_handle]);
        }
        service
    }

    /// Stop the three background loops AND any in-flight per-request exec
    /// handler tasks deterministically, killing their child processes.
    /// Idempotent.
    ///
    /// Steps (issue #118):
    /// 1. Cancel the service token (stops the loops; newly-arriving requests
    ///    are declined; in-flight `handle_request` tasks that have not yet
    ///    spawned a child bail out).
    /// 2. Snapshot active sessions, send `CancelReason::Shutdown` to each
    ///    (sets `kill_at = now` in `run_child` so it SIGKILLs this iteration),
    ///    and collect every nonzero `child_pid`.
    /// 3. SIGKILL those PIDs **out-of-band** as a hard guarantee that does not
    ///    depend on the handler task observing the cancel in time.
    /// 4. Drain and grace-await the three loop handles plus every in-flight
    ///    request handler handle, under a single bounded budget.
    /// 5. On timeout, re-snapshot currently-active `child_pid`s (not the
    ///    initial list, which may now be stale/reused) and SIGKILL them, then
    ///    abort+await stragglers.
    /// 6. Clear `active_servers` / `active_counts` — aborted handler tasks may
    ///    not have run their cleanup, so reset the bookkeeping explicitly.
    ///
    /// A cancelled/aborted task yields `Err(JoinError)`; that is expected and
    /// never unwrapped.
    pub async fn shutdown(&self) {
        // Issue #118: serialize concurrent shutdown() calls so a second caller
        // can't race the first into a half-cleared state.
        let _shutdown_guard = self.shutdown_lock.lock().await;
        self.cancellation_token.cancel();

        // (2) Snapshot active sessions and signal shutdown. Record whether any
        // sessions existed (even with pid==0) so the bookkeeping reset below
        // runs even when no child PID has been published yet.
        let mut pids: Vec<u32> = Vec::new();
        let had_active_sessions = {
            let active = self.active_servers.lock().await;
            if active.is_empty() {
                false
            } else {
                for session in active.values() {
                    // Watch sender: ok if the handler already dropped its receiver.
                    let _ = session.cancel_tx.send(CancelReason::Shutdown);
                    let pid = session.child_pid.load(Ordering::Acquire);
                    if pid != 0 {
                        pids.push(pid);
                    }
                }
                true
            }
        };

        // (3) Out-of-band SIGKILL guarantee. `kill_on_drop(true)` will also
        // fire when the handler task is dropped/aborted, but we do not rely on
        // it here: a reaped PID is the acceptance bar for #118.
        for &pid in &pids {
            send_signal(pid, TermSignal::Kill);
        }

        // (4) Drain loop handles and request handler handles.
        let loop_handles = {
            let mut guard = self.task_handles.lock().await;
            std::mem::take(&mut *guard)
        };
        let request_handles = {
            let mut guard = self.request_task_handles.lock().await;
            std::mem::take(&mut *guard)
        };
        let any_work =
            had_active_sessions || !loop_handles.is_empty() || !request_handles.is_empty();
        if !any_work {
            return;
        }

        let mut handles: Vec<tokio::task::JoinHandle<()>> = loop_handles;
        handles.extend(request_handles.into_values());
        let abort_handles: Vec<tokio::task::AbortHandle> =
            handles.iter().map(|h| h.abort_handle()).collect();
        let mut join = futures::future::join_all(handles);
        tokio::select! {
            _results = &mut join => {}
            _ = tokio::time::sleep(Duration::from_secs(3)) => {
                tracing::warn!(
                    active = pids.len(),
                    "exec tasks did not stop within grace; re-killing children and aborting stragglers"
                );
                // (5) Hard guarantee. Kill only CURRENTLY-active children from
                // a fresh snapshot, not the initial `pids` list: a handler may
                // have completed and reaped its child during the grace window,
                // and after ~3s the OS could hand that PID to an unrelated
                // process. A fresh snapshot also catches PIDs published after
                // our initial snapshot (shutdown began between the
                // active_session insert and `child_pid.store`).
                let live_pids: Vec<u32> = {
                    let active = self.active_servers.lock().await;
                    active
                        .values()
                        .map(|s| s.child_pid.load(Ordering::Acquire))
                        .filter(|&p| p != 0)
                        .collect()
                };
                for pid in live_pids {
                    send_signal(pid, TermSignal::Kill);
                }
                for handle in &abort_handles {
                    handle.abort();
                }
                let _results: Vec<Result<(), tokio::task::JoinError>> = join.await;
            }
        }

        // (6) Reset bookkeeping that aborted handlers may not have cleaned up.
        // This runs whenever shutdown observed any work (sessions or handles),
        // including sessions whose child PID was never published.
        {
            let mut active = self.active_servers.lock().await;
            active.clear();
        }
        {
            let mut counts = self.active_counts.lock().await;
            counts.total = 0;
            counts.per_agent.clear();
        }
    }

    /// Whether exec is enabled on this daemon.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.policy.enabled()
    }

    /// Diagnostics snapshot for `/diagnostics/exec`.
    pub async fn diagnostics_snapshot(&self) -> ExecDiagnosticsSnapshot {
        let active = self.active_servers.lock().await;
        let mut per_agent: HashMap<String, usize> = HashMap::new();
        for session in active.values() {
            *per_agent
                .entry(hex::encode(session.agent_id.as_bytes()))
                .or_insert(0) += 1;
        }
        self.diagnostics
            .snapshot(self.enabled(), active.len(), per_agent)
    }

    /// Sessions known to this daemon, both local client requests and remote child runs.
    pub async fn sessions_snapshot(&self) -> ExecSessionsSnapshot {
        let pending = self.pending_clients.lock().await;
        let active = self.active_servers.lock().await;
        ExecSessionsSnapshot {
            ok: true,
            pending_clients: pending
                .iter()
                .map(|(request_id, pending)| ExecClientSessionSnapshot {
                    request_id: request_id.to_hex(),
                    target_agent_id: hex::encode(pending.target.as_bytes()),
                    argv_summary: pending.argv_summary.clone(),
                    age_ms: pending
                        .started_at
                        .elapsed()
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                })
                .collect(),
            active_servers: active
                .iter()
                .map(|(request_id, session)| ExecServerSessionSnapshot {
                    request_id: request_id.to_hex(),
                    agent_id: hex::encode(session.agent_id.as_bytes()),
                    machine_id: hex::encode(session.machine_id.as_bytes()),
                    argv_summary: session.argv_summary.clone(),
                    age_ms: session
                        .started_at
                        .elapsed()
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                })
                .collect(),
        }
    }

    /// Run a command on a remote agent and aggregate stdout/stderr until Exit.
    pub async fn run_remote(
        self: &Arc<Self>,
        target: AgentId,
        options: ExecRunOptions,
    ) -> Result<ExecRunResult, ExecServiceError> {
        if options.argv.is_empty() {
            return Err(ExecServiceError::Protocol(
                "argv must not be empty".to_string(),
            ));
        }
        let request_id = ExecRequestId::new_random();
        let timeout_ms = options.timeout_ms.unwrap_or(30_000);
        let (tx, mut rx) = mpsc::channel(EXEC_FRAME_CHANNEL);
        let argv_summary = argv_summary(&options.argv);
        self.pending_clients.lock().await.insert(
            request_id,
            PendingClient {
                target,
                tx,
                argv_summary,
                started_at: Instant::now(),
            },
        );

        let cancel_guard = ClientCancelGuard::new(Arc::clone(self), target, request_id);
        let request = ExecFrame::Request {
            request_id,
            argv: options.argv.clone(),
            stdin: options.stdin,
            timeout_ms,
            cwd: options.cwd,
        };
        if let Err(e) = self.send_frame(&target, &request).await {
            self.pending_clients.lock().await.remove(&request_id);
            return Err(e);
        }

        let lease_service = Arc::clone(self);
        let (lease_stop_tx, mut lease_stop_rx) = watch::channel(false);
        let lease_target = target;
        let lease_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = lease_stop_rx.changed() => {
                        if changed.is_err() || *lease_stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(LEASE_RENEW_INTERVAL) => {
                        let frame = ExecFrame::LeaseRenew { request_id };
                        if let Err(e) = lease_service.send_frame(&lease_target, &frame).await {
                            tracing::debug!(request_id = %request_id, error = %e, "exec lease renewal failed");
                        }
                    }
                }
            }
        });

        let wait_budget =
            Duration::from_millis(u64::from(timeout_ms)).saturating_add(Duration::from_secs(70));
        let result = tokio::time::timeout(wait_budget, async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut warnings = Vec::new();
            while let Some(frame) = rx.recv().await {
                match frame {
                    ExecFrame::Started { .. } => {}
                    ExecFrame::Stdout { data, .. } => stdout.extend_from_slice(&data),
                    ExecFrame::Stderr { data, .. } => stderr.extend_from_slice(&data),
                    ExecFrame::Warning { kind, .. } => warnings.push(kind),
                    ExecFrame::Exit {
                        request_id,
                        code,
                        signal,
                        duration_ms,
                        stdout_bytes_total,
                        stderr_bytes_total,
                        truncated,
                        denial_reason,
                    } => {
                        return Ok(ExecRunResult {
                            request_id,
                            code,
                            signal,
                            duration_ms,
                            stdout,
                            stderr,
                            stdout_bytes_total,
                            stderr_bytes_total,
                            truncated,
                            denial_reason,
                            warnings,
                        });
                    }
                    ExecFrame::Request { .. }
                    | ExecFrame::LeaseRenew { .. }
                    | ExecFrame::Cancel { .. } => {}
                }
            }
            Err(ExecServiceError::ResponseChannelClosed)
        })
        .await
        .map_err(|_| ExecServiceError::Timeout)?;

        let _ = lease_stop_tx.send(true);
        lease_task.abort();
        self.pending_clients.lock().await.remove(&request_id);
        cancel_guard.disarm();
        result
    }

    /// Cancel an in-flight local request. If `target` is omitted, the pending
    /// session table is used to find the remote agent.
    pub async fn cancel_remote(
        self: &Arc<Self>,
        request_id: ExecRequestId,
        target: Option<AgentId>,
    ) -> Result<(), ExecServiceError> {
        let target = match target {
            Some(target) => target,
            None => {
                let pending = self.pending_clients.lock().await;
                pending
                    .get(&request_id)
                    .map(|p| p.target)
                    .ok_or(ExecServiceError::ResponseChannelClosed)?
            }
        };
        self.send_frame(&target, &ExecFrame::Cancel { request_id })
            .await
    }

    async fn run_peer_lifecycle_loop(self: Arc<Self>) {
        let Some(network) = self.agent.network().cloned() else {
            return;
        };
        let Some(mut rx) = network.subscribe_all_peer_events().await else {
            tracing::debug!(
                "exec peer lifecycle watcher unavailable: network node not initialised"
            );
            return;
        };
        tracing::info!("exec peer lifecycle watcher started");
        loop {
            let (peer_id, event) = tokio::select! {
                _ = self.cancellation_token.cancelled() => break,
                recv = rx.recv() => match recv {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "exec peer lifecycle watcher lagged");
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            };
            let disconnect_reason = match event {
                ant_quic::PeerLifecycleEvent::Closed { reason, .. }
                    if reason != ant_quic::ConnectionCloseReason::Superseded =>
                {
                    Some(reason)
                }
                // ReaderExited is emitted before ant-quic classifies the exit,
                // and Closing is pre-terminal. Do not cancel exec sessions until
                // a non-superseded Closed event is observed and no replacement
                // connection is live.
                _ => None,
            };
            if let Some(reason) = disconnect_reason {
                if network.is_connected(&peer_id).await {
                    tracing::debug!(
                        peer_id = %hex::encode(peer_id.0),
                        ?reason,
                        "ignoring exec lifecycle close because peer is still connected"
                    );
                    continue;
                }
                let machine_id = MachineId(peer_id.0);
                let cancelled = self
                    .cancel_sessions_for_machine(machine_id, CancelReason::PeerDisconnected)
                    .await;
                if cancelled > 0 {
                    tracing::info!(
                        machine_id = %hex::encode(machine_id.as_bytes()),
                        ?reason,
                        cancelled,
                        "cancelled exec sessions for disconnected peer"
                    );
                }
            }
        }
    }

    async fn run_session_idle_loop(self: Arc<Self>) {
        loop {
            // This loop is a pure timer — it never self-terminates, so the
            // token is the ONLY thing that stops it. Without this arm it leaked
            // for the lifetime of the process.
            tokio::select! {
                _ = tokio::time::sleep(SESSION_IDLE_SCAN_INTERVAL) => {}
                _ = self.cancellation_token.cancelled() => break,
            }
            let sessions: Vec<(ExecRequestId, ActiveServerSession)> = {
                let active = self.active_servers.lock().await;
                active
                    .iter()
                    .map(|(request_id, session)| (*request_id, session.clone()))
                    .collect()
            };
            let now = Instant::now();
            for (request_id, session) in sessions {
                let last_activity = *session.last_activity.lock().await;
                if now.duration_since(last_activity) < SESSION_IDLE_TIMEOUT {
                    continue;
                }
                if session.cancel_tx.send(CancelReason::IdleTimeout).is_ok() {
                    tracing::warn!(
                        request_id = %request_id,
                        agent_id = %crate::logging::LogAgentId::from(&session.agent_id),
                        machine_id = %crate::logging::LogMachineId::from(&session.machine_id),
                        idle_ms = now.duration_since(last_activity).as_millis() as u64,
                        "exec session idle timeout; cancelling remote child"
                    );
                }
            }
        }
    }

    async fn record_session_activity(last_activity: &Arc<Mutex<Instant>>) {
        let mut guard = last_activity.lock().await;
        *guard = Instant::now();
    }

    async fn cancel_sessions_for_machine(
        &self,
        machine_id: MachineId,
        reason: CancelReason,
    ) -> usize {
        let sessions: Vec<ActiveServerSession> = {
            let active = self.active_servers.lock().await;
            active
                .values()
                .filter(|session| session.machine_id == machine_id)
                .cloned()
                .collect()
        };
        let mut cancelled = 0_usize;
        for session in sessions {
            if session.cancel_tx.send(reason).is_ok() {
                cancelled = cancelled.saturating_add(1);
            }
        }
        cancelled
    }

    async fn run_inbound_loop(self: Arc<Self>, mut inbound_rx: mpsc::Receiver<DmTypedPayload>) {
        loop {
            let inbound = tokio::select! {
                _ = self.cancellation_token.cancelled() => break,
                recv = inbound_rx.recv() => match recv {
                    Some(inbound) => inbound,
                    None => break,
                },
            };
            let frame = match decode_frame_payload(&inbound.payload) {
                Ok(frame) => frame,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to decode routed exec frame");
                    self.diagnostics.record_denied(DenialReason::MalformedFrame);
                    continue;
                }
            };
            match frame {
                ExecFrame::Request {
                    request_id,
                    argv,
                    stdin,
                    timeout_ms,
                    cwd,
                } => {
                    let service = Arc::clone(&self);
                    service
                        .spawn_request_handler(inbound, request_id, argv, stdin, timeout_ms, cwd)
                        .await;
                }
                ExecFrame::LeaseRenew { request_id } => {
                    self.handle_lease_renew(inbound.sender, inbound.machine_id, request_id)
                        .await;
                }
                ExecFrame::Cancel { request_id } => {
                    self.handle_cancel(inbound.sender, inbound.machine_id, request_id)
                        .await;
                }
                ExecFrame::Started { request_id, .. }
                | ExecFrame::Stdout { request_id, .. }
                | ExecFrame::Stderr { request_id, .. }
                | ExecFrame::Warning { request_id, .. }
                | ExecFrame::Exit { request_id, .. } => {
                    self.forward_to_pending_client(request_id, frame).await;
                }
            }
        }
    }

    async fn forward_to_pending_client(&self, request_id: ExecRequestId, frame: ExecFrame) {
        let tx = {
            let pending = self.pending_clients.lock().await;
            pending.get(&request_id).map(|p| p.tx.clone())
        };
        if let Some(tx) = tx {
            let _ = tx.send(frame).await;
        }
    }

    async fn handle_lease_renew(
        &self,
        sender: AgentId,
        machine_id: MachineId,
        request_id: ExecRequestId,
    ) {
        let session = {
            let active = self.active_servers.lock().await;
            active.get(&request_id).cloned()
        };
        let Some(session) = session else {
            return;
        };
        if session.agent_id != sender || session.machine_id != machine_id {
            return;
        }
        let mut deadline = session.lease_deadline.lock().await;
        *deadline = Instant::now() + LEASE_TIMEOUT;
    }

    async fn handle_cancel(
        &self,
        sender: AgentId,
        machine_id: MachineId,
        request_id: ExecRequestId,
    ) {
        let session = {
            let active = self.active_servers.lock().await;
            active.get(&request_id).cloned()
        };
        let Some(session) = session else {
            return;
        };
        if session.agent_id != sender || session.machine_id != machine_id {
            return;
        }
        let _ = session.cancel_tx.send(CancelReason::ExplicitCancel);
    }

    /// Spawn a per-request handler task for an inbound `ExecFrame::Request`,
    /// recording its `JoinHandle` under `request_task_handles` so `shutdown()`
    /// can abort it (issue #118). Race-safe: the handle is inserted while
    /// holding the lock, and the spawned wrapper removes its own entry on
    /// completion, so `shutdown()` never aborts an already-finished task or
    /// misses one that is about to start. If the service is already shutting
    /// down, no task is spawned.
    async fn spawn_request_handler(
        self: &Arc<Self>,
        inbound: DmTypedPayload,
        request_id: ExecRequestId,
        argv: Vec<String>,
        stdin: Option<Vec<u8>>,
        timeout_ms: u32,
        cwd: Option<String>,
    ) {
        // Hold the lock across spawn + insert so `shutdown()` draining the map
        // observes a consistent set: either this handle is present (and will be
        // awaited/aborted) or the token was already cancelled and we decline.
        let mut handles = self.request_task_handles.lock().await;
        if self.cancellation_token.is_cancelled() {
            tracing::debug!(
                request_id = %request_id,
                "dropping inbound exec request: service shutting down"
            );
            return;
        }
        let service = Arc::clone(self);
        let cleanup_service = Arc::clone(self);
        let handle = tokio::spawn(async move {
            service
                .handle_request(inbound, request_id, argv, stdin, timeout_ms, cwd)
                .await;
            // Self-remove on completion. Race-free: `shutdown()` uses
            // `std::mem::take` to move all handles out under the lock, so once
            // it has run the map is empty and a late remove here is a harmless
            // no-op. We use the awaited lock (not `try_lock`) so that a handler
            // which finishes while its parent holds the map lock during insert
            // cannot leak a stale finished `JoinHandle`.
            let mut guard = cleanup_service.request_task_handles.lock().await;
            guard.remove(&request_id);
        });
        // Issue #118: request IDs are client-allocated, so a reused id would
        // otherwise orphan the earlier handler — `insert` drops its `JoinHandle`
        // without aborting, leaving its child running past shutdown. Abort the
        // displaced handler so its `Child` drops and `kill_on_drop` reaps it.
        if let Some(previous) = handles.insert(request_id, handle) {
            previous.abort();
        }
    }

    async fn handle_request(
        self: Arc<Self>,
        inbound: DmTypedPayload,
        request_id: ExecRequestId,
        argv: Vec<String>,
        stdin: Option<Vec<u8>>,
        timeout_ms: u32,
        cwd: Option<String>,
    ) {
        self.diagnostics.record_request_received();

        if !inbound.verified {
            self.deny(
                inbound.sender,
                inbound.machine_id,
                request_id,
                &argv,
                DenialReason::UnverifiedSender,
            )
            .await;
            return;
        }
        if inbound.trust_decision != Some(TrustDecision::Accept) {
            self.deny(
                inbound.sender,
                inbound.machine_id,
                request_id,
                &argv,
                DenialReason::TrustRejected,
            )
            .await;
            return;
        }

        let acl = match self.policy.as_ref() {
            ExecPolicy::Enabled(acl) => acl,
            ExecPolicy::Disabled { .. } => {
                self.deny(
                    inbound.sender,
                    inbound.machine_id,
                    request_id,
                    &argv,
                    DenialReason::ExecDisabled,
                )
                .await;
                return;
            }
        };

        let checked = match self.check_request(
            acl,
            inbound.sender,
            inbound.machine_id,
            &argv,
            stdin.as_ref(),
            timeout_ms,
            cwd.as_ref(),
        ) {
            Ok(checked) => checked,
            Err(reason) => {
                self.deny(
                    inbound.sender,
                    inbound.machine_id,
                    request_id,
                    &argv,
                    reason,
                )
                .await;
                return;
            }
        };

        let Some(_slot) = self.try_acquire_slot(inbound.sender, &checked.caps).await else {
            self.deny(
                inbound.sender,
                inbound.machine_id,
                request_id,
                &argv,
                DenialReason::ConcurrencyLimitReached,
            )
            .await;
            return;
        };

        // If shutdown began while this request was waiting on a lock / slot,
        // decline to spawn a child rather than racing teardown (issue #118).
        if self.cancellation_token.is_cancelled() {
            tracing::debug!(
                request_id = %request_id,
                "declining exec request after slot acquire: service shutting down"
            );
            self.release_slot(inbound.sender).await;
            return;
        }

        self.diagnostics.record_allowed();
        self.audit
            .request(
                request_id,
                inbound.sender,
                inbound.machine_id,
                &argv,
                checked.description.as_deref(),
                stdin.as_ref().map(Vec::len).unwrap_or(0),
                timeout_ms,
            )
            .await;

        let (cancel_tx, cancel_rx) = watch::channel(CancelReason::DurationCap);
        let now = Instant::now();
        let lease_deadline = Arc::new(Mutex::new(now + LEASE_TIMEOUT));
        let last_activity = Arc::new(Mutex::new(now));
        let child_pid = Arc::new(AtomicU32::new(0));
        let active_session = ActiveServerSession {
            agent_id: inbound.sender,
            machine_id: inbound.machine_id,
            cancel_tx,
            lease_deadline: Arc::clone(&lease_deadline),
            last_activity: Arc::clone(&last_activity),
            argv_summary: argv_summary(&argv),
            started_at: now,
            child_pid: Arc::clone(&child_pid),
        };
        self.active_servers
            .lock()
            .await
            .insert(request_id, active_session);

        self.run_child(
            inbound.sender,
            request_id,
            argv,
            stdin,
            checked,
            cancel_rx,
            lease_deadline,
            last_activity,
            child_pid,
        )
        .await;

        self.active_servers.lock().await.remove(&request_id);
        self.release_slot(inbound.sender).await;
    }

    #[allow(clippy::too_many_arguments)]
    fn check_request(
        &self,
        acl: &ExecAcl,
        agent_id: AgentId,
        machine_id: MachineId,
        argv: &[String],
        stdin: Option<&Vec<u8>>,
        timeout_ms: u32,
        cwd: Option<&String>,
    ) -> Result<CheckedRequest, DenialReason> {
        if argv.is_empty() {
            return Err(DenialReason::ArgvNotAllowed);
        }
        if cwd.is_some() {
            return Err(DenialReason::CwdNotAllowed);
        }
        if argv_has_shell_metachar(argv) {
            return Err(DenialReason::ShellMetacharInArgv);
        }
        if !acl.has_agent_machine(&agent_id, &machine_id) {
            return Err(DenialReason::AgentMachineNotInAcl);
        }
        let Some(matched) = acl.match_command(&agent_id, &machine_id, argv) else {
            return Err(DenialReason::ArgvNotAllowed);
        };
        let stdin_len = stdin.map(Vec::len).unwrap_or(0) as u64;
        if stdin_len > acl.caps.max_stdin_bytes {
            return Err(DenialReason::StdinTooLarge);
        }
        let requested_secs = u64::from(timeout_ms).saturating_add(999) / 1000;
        if requested_secs > matched.effective_max_duration_secs {
            return Err(DenialReason::TimeoutTooLarge);
        }
        Ok(CheckedRequest {
            caps: acl.caps.clone(),
            max_duration: Duration::from_secs(requested_secs.max(1)),
            cwd: acl.caps.default_cwd.clone(),
            description: matched.entry.description.clone(),
        })
    }

    async fn try_acquire_slot(&self, agent_id: AgentId, caps: &ExecCaps) -> Option<()> {
        let mut counts = self.active_counts.lock().await;
        let per_agent = counts.per_agent.get(&agent_id).copied().unwrap_or(0);
        if counts.total >= caps.max_concurrent_total || per_agent >= caps.max_concurrent_per_agent {
            return None;
        }
        counts.total = counts.total.saturating_add(1);
        counts
            .per_agent
            .insert(agent_id, per_agent.saturating_add(1));
        Some(())
    }

    async fn release_slot(&self, agent_id: AgentId) {
        let mut counts = self.active_counts.lock().await;
        counts.total = counts.total.saturating_sub(1);
        if let Some(current) = counts.per_agent.get_mut(&agent_id) {
            *current = current.saturating_sub(1);
            if *current == 0 {
                counts.per_agent.remove(&agent_id);
            }
        }
    }

    async fn deny(
        &self,
        to: AgentId,
        machine_id: MachineId,
        request_id: ExecRequestId,
        argv: &[String],
        reason: DenialReason,
    ) {
        self.diagnostics.record_denied(reason);
        self.audit
            .denial(request_id, to, machine_id, argv, reason)
            .await;
        let frame = ExecFrame::Exit {
            request_id,
            code: None,
            signal: None,
            duration_ms: 0,
            stdout_bytes_total: 0,
            stderr_bytes_total: 0,
            truncated: false,
            denial_reason: Some(reason),
        };
        if let Err(e) = self.send_frame(&to, &frame).await {
            tracing::debug!(request_id = %request_id, error = %e, "failed to send exec denial frame");
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_child(
        self: &Arc<Self>,
        to: AgentId,
        request_id: ExecRequestId,
        argv: Vec<String>,
        stdin: Option<Vec<u8>>,
        checked: CheckedRequest,
        mut cancel_rx: watch::Receiver<CancelReason>,
        lease_deadline: Arc<Mutex<Instant>>,
        last_activity: Arc<Mutex<Instant>>,
        child_pid: Arc<AtomicU32>,
    ) {
        let started = Instant::now();
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8");
        if let Some(home) = std::env::var_os("HOME") {
            cmd.env("HOME", home);
        }
        if let Some(cwd) = checked.cwd.as_ref() {
            cmd.current_dir(cwd);
        }

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(request_id = %request_id, error = %e, "exec spawn failed");
                self.deny(
                    to,
                    self.agent.machine_id(),
                    request_id,
                    &argv,
                    DenialReason::SpawnFailed,
                )
                .await;
                return;
            }
        };

        let pid = child.id().unwrap_or(0);
        // Publish the PID so `shutdown()` can SIGKILL out-of-band without
        // waiting for this loop to observe its cancel signal (issue #118).
        if pid != 0 {
            child_pid.store(pid, Ordering::Release);
        }
        self.diagnostics.record_started();
        self.audit.started(request_id, pid).await;
        if let Err(e) = self
            .send_frame(&to, &ExecFrame::Started { request_id, pid })
            .await
        {
            tracing::debug!(request_id = %request_id, error = %e, "failed to send exec started frame");
        }

        if let Some(mut child_stdin) = child.stdin.take() {
            if let Some(stdin) = stdin {
                tokio::spawn(async move {
                    let _ = child_stdin.write_all(&stdin).await;
                    let _ = child_stdin.shutdown().await;
                });
            }
        }

        let stdout_total = Arc::new(AtomicU64::new(0));
        let stderr_total = Arc::new(AtomicU64::new(0));
        let truncated = Arc::new(AtomicBool::new(false));
        let stdout_seq = Arc::new(AtomicU32::new(0));
        let stderr_seq = Arc::new(AtomicU32::new(0));

        let stdout_task = child.stdout.take().map(|stdout| {
            let service = Arc::clone(self);
            let total = Arc::clone(&stdout_total);
            let truncated = Arc::clone(&truncated);
            let seq = Arc::clone(&stdout_seq);
            let activity = Arc::clone(&last_activity);
            let caps = checked.caps.clone();
            let argv_summary = argv_summary(&argv);
            tokio::spawn(async move {
                service
                    .stream_output(
                        stdout,
                        to,
                        request_id,
                        StreamKind::Stdout,
                        caps,
                        total,
                        truncated,
                        seq,
                        activity,
                        argv_summary,
                    )
                    .await;
            })
        });
        let stderr_task = child.stderr.take().map(|stderr| {
            let service = Arc::clone(self);
            let total = Arc::clone(&stderr_total);
            let truncated = Arc::clone(&truncated);
            let seq = Arc::clone(&stderr_seq);
            let activity = Arc::clone(&last_activity);
            let caps = checked.caps.clone();
            let argv_summary = argv_summary(&argv);
            tokio::spawn(async move {
                service
                    .stream_output(
                        stderr,
                        to,
                        request_id,
                        StreamKind::Stderr,
                        caps,
                        total,
                        truncated,
                        seq,
                        activity,
                        argv_summary,
                    )
                    .await;
            })
        });

        let mut duration_warned = false;
        let mut term_sent = false;
        let mut kill_sent = false;
        let mut cancel_reason: Option<CancelReason> = None;
        let term_at = if checked.max_duration > CANCEL_GRACE {
            started + checked.max_duration - CANCEL_GRACE
        } else {
            started + checked.max_duration
        };
        let warn_duration = Duration::from_secs(
            checked
                .caps
                .warn_duration_secs
                .min(checked.max_duration.as_secs()),
        );
        let warn_at = started + warn_duration;
        let mut kill_at = started + checked.max_duration;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Issue #118: the child has exited (and been reaped) — clear
                    // the published PID immediately, before any further await, so
                    // `shutdown()` can never SIGKILL a PID the OS may have
                    // recycled to an unrelated process.
                    child_pid.store(0, Ordering::Release);
                    break Some(status);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(request_id = %request_id, error = %e, "exec wait failed");
                    break None;
                }
            }

            let now = Instant::now();
            if cancel_reason.is_none() {
                let deadline = *lease_deadline.lock().await;
                if now >= deadline {
                    cancel_reason = Some(CancelReason::LeaseExpired);
                    self.diagnostics.record_cancelled();
                    self.emit_warning(
                        to,
                        request_id,
                        WarningKind::LeaseExpired,
                        "request lease expired; terminating remote child".to_string(),
                        to,
                        argv_summary(&argv),
                        None,
                    )
                    .await;
                    kill_at = now + CANCEL_GRACE;
                }
            }

            if cancel_reason.is_none() {
                match cancel_rx.has_changed() {
                    Ok(true) => {
                        let reason = *cancel_rx.borrow_and_update();
                        cancel_reason = Some(reason);
                        self.diagnostics.record_cancelled();
                        let kind = match reason {
                            CancelReason::ExplicitCancel => WarningKind::Cancelled,
                            CancelReason::LeaseExpired => WarningKind::LeaseExpired,
                            CancelReason::PeerDisconnected => WarningKind::PeerDisconnected,
                            CancelReason::DurationCap => WarningKind::DurationApproachingCap,
                            CancelReason::IdleTimeout => WarningKind::LeaseExpired,
                            // Service-wide shutdown: report as cancelled.
                            CancelReason::Shutdown => WarningKind::Cancelled,
                        };
                        self.emit_warning(
                            to,
                            request_id,
                            kind,
                            "exec session cancelled; terminating remote child".to_string(),
                            to,
                            argv_summary(&argv),
                            None,
                        )
                        .await;
                        // Shutdown terminates immediately (no grace); the
                        // service is going away and the embedder needs the
                        // child dead before `shutdown()` returns. Other reasons
                        // keep the normal grace window.
                        kill_at = if reason == CancelReason::Shutdown {
                            now
                        } else {
                            now + CANCEL_GRACE
                        };
                    }
                    Ok(false) => {}
                    Err(_) => {}
                }
            }

            if !duration_warned && cancel_reason.is_none() && now >= warn_at && now < term_at {
                duration_warned = true;
                self.emit_warning(
                    to,
                    request_id,
                    WarningKind::DurationApproachingCap,
                    "duration warning threshold reached".to_string(),
                    to,
                    argv_summary(&argv),
                    None,
                )
                .await;
            }

            if !term_sent && (cancel_reason.is_some() || now >= term_at) {
                term_sent = true;
                if cancel_reason.is_none() {
                    cancel_reason = Some(CancelReason::DurationCap);
                    self.emit_warning(
                        to,
                        request_id,
                        WarningKind::DurationApproachingCap,
                        "duration cap reached; sent SIGTERM".to_string(),
                        to,
                        argv_summary(&argv),
                        None,
                    )
                    .await;
                }
                if pid != 0 {
                    send_signal(pid, TermSignal::Term);
                }
            }

            if term_sent && !kill_sent && now >= kill_at {
                kill_sent = true;
                if pid != 0 {
                    send_signal(pid, TermSignal::Kill);
                } else if let Err(e) = child.start_kill() {
                    tracing::debug!(request_id = %request_id, error = %e, "failed to kill exec child");
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        if let Some(task) = stdout_task {
            let _ = task.await;
        }
        if let Some(task) = stderr_task {
            let _ = task.await;
        }

        let code = status.as_ref().and_then(std::process::ExitStatus::code);
        let mut signal = status_signal(status.as_ref());
        if kill_sent && signal.is_none() {
            signal = Some(signal_number(TermSignal::Kill));
        } else if term_sent && signal.is_none() && code.is_none() {
            signal = Some(signal_number(TermSignal::Term));
        }
        let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let stdout_bytes_total = stdout_total.load(Ordering::Relaxed);
        let stderr_bytes_total = stderr_total.load(Ordering::Relaxed);
        let truncated = truncated.load(Ordering::Relaxed);
        self.diagnostics.record_completed();
        self.audit
            .exit(
                request_id,
                code,
                signal,
                duration_ms,
                stdout_bytes_total,
                stderr_bytes_total,
                truncated,
            )
            .await;
        Self::record_session_activity(&last_activity).await;
        let frame = ExecFrame::Exit {
            request_id,
            code,
            signal,
            duration_ms,
            stdout_bytes_total,
            stderr_bytes_total,
            truncated,
            denial_reason: None,
        };
        if let Err(e) = self.send_frame(&to, &frame).await {
            tracing::debug!(request_id = %request_id, error = %e, "failed to send exec exit frame");
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn stream_output<R>(
        &self,
        mut reader: R,
        to: AgentId,
        request_id: ExecRequestId,
        kind: StreamKind,
        caps: ExecCaps,
        total: Arc<AtomicU64>,
        truncated: Arc<AtomicBool>,
        seq: Arc<AtomicU32>,
        last_activity: Arc<Mutex<Instant>>,
        argv_summary: String,
    ) where
        R: AsyncRead + Unpin,
    {
        let (cap, warn, cap_kind, warn_kind, breach_key) = match kind {
            StreamKind::Stdout => (
                caps.max_stdout_bytes,
                caps.warn_stdout_bytes,
                WarningKind::StdoutCapHit,
                WarningKind::StdoutApproachingCap,
                "stdout",
            ),
            StreamKind::Stderr => (
                caps.max_stderr_bytes,
                caps.warn_stderr_bytes,
                WarningKind::StderrCapHit,
                WarningKind::StderrApproachingCap,
                "stderr",
            ),
        };
        let mut warned = false;
        let mut cap_hit = false;
        let mut forwarded = 0_u64;
        let mut buf = vec![0_u8; OUTPUT_CHUNK_BYTES];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(request_id = %request_id, error = %e, "exec output read failed");
                    break;
                }
            };
            Self::record_session_activity(&last_activity).await;
            let n_u64 = n as u64;
            let new_total = total
                .fetch_add(n_u64, Ordering::Relaxed)
                .saturating_add(n_u64);
            if !warned && warn > 0 && new_total >= warn {
                warned = true;
                self.emit_warning(
                    to,
                    request_id,
                    warn_kind,
                    format!("{} warning threshold reached", stream_name(kind)),
                    to,
                    argv_summary.clone(),
                    Some(new_total),
                )
                .await;
            }
            if forwarded < cap {
                let remaining = cap.saturating_sub(forwarded) as usize;
                let send_len = remaining.min(n);
                if send_len > 0 {
                    let data = buf[..send_len].to_vec();
                    let next_seq = seq.fetch_add(1, Ordering::Relaxed);
                    let frame = match kind {
                        StreamKind::Stdout => ExecFrame::Stdout {
                            request_id,
                            seq: next_seq,
                            data,
                        },
                        StreamKind::Stderr => ExecFrame::Stderr {
                            request_id,
                            seq: next_seq,
                            data,
                        },
                    };
                    if let Err(e) = self.send_frame(&to, &frame).await {
                        tracing::debug!(request_id = %request_id, error = %e, "failed to send exec output frame");
                    }
                    forwarded = forwarded.saturating_add(send_len as u64);
                }
            }
            if !cap_hit && new_total >= cap {
                cap_hit = true;
                truncated.store(true, Ordering::Relaxed);
                self.diagnostics.record_cap_breach(breach_key);
                self.emit_warning(
                    to,
                    request_id,
                    cap_kind,
                    format!("{} cap hit; further bytes discarded", stream_name(kind)),
                    to,
                    argv_summary.clone(),
                    Some(new_total),
                )
                .await;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn emit_warning(
        &self,
        to: AgentId,
        request_id: ExecRequestId,
        kind: WarningKind,
        message: String,
        agent_id_for_diag: AgentId,
        argv_summary: String,
        bytes_at_warn: Option<u64>,
    ) {
        self.diagnostics.record_warning(
            kind,
            agent_id_for_diag,
            request_id,
            argv_summary,
            bytes_at_warn,
        );
        self.audit.warning(request_id, kind, bytes_at_warn).await;
        let frame = ExecFrame::Warning {
            request_id,
            kind,
            message,
        };
        if let Err(e) = self.send_frame(&to, &frame).await {
            tracing::debug!(request_id = %request_id, error = %e, "failed to send exec warning frame");
        }
    }

    async fn send_frame(&self, to: &AgentId, frame: &ExecFrame) -> Result<(), ExecServiceError> {
        let payload =
            encode_frame_payload(frame).map_err(|e| ExecServiceError::Protocol(e.to_string()))?;
        let config = exec_frame_send_config(frame);
        self.agent
            .send_direct_with_config(to, payload, config)
            .await
            .map(|_| ())
            .map_err(map_dm_error)
    }
}

#[derive(Clone)]
struct CheckedRequest {
    caps: ExecCaps,
    max_duration: Duration,
    cwd: Option<std::path::PathBuf>,
    description: Option<String>,
}

struct ClientCancelGuard {
    service: Arc<ExecService>,
    target: AgentId,
    request_id: ExecRequestId,
    armed: AtomicBool,
}

impl ClientCancelGuard {
    fn new(service: Arc<ExecService>, target: AgentId, request_id: ExecRequestId) -> Self {
        Self {
            service,
            target,
            request_id,
            armed: AtomicBool::new(true),
        }
    }

    fn disarm(&self) {
        self.armed.store(false, Ordering::Relaxed);
    }
}

impl Drop for ClientCancelGuard {
    fn drop(&mut self) {
        if !self.armed.load(Ordering::Relaxed) {
            return;
        }
        let service = Arc::clone(&self.service);
        let target = self.target;
        let request_id = self.request_id;
        tokio::spawn(async move {
            let _ = service.cancel_remote(request_id, Some(target)).await;
            service.pending_clients.lock().await.remove(&request_id);
        });
    }
}

fn map_dm_error(error: DmError) -> ExecServiceError {
    ExecServiceError::Transport(error.to_string())
}

fn exec_frame_send_config(_frame: &ExecFrame) -> DmSendConfig {
    DmSendConfig {
        timeout_per_attempt: Duration::from_secs(8),
        require_gossip: true,
        prefer_raw_quic_if_connected: false,
        require_gossip_ack: false,
        ..DmSendConfig::default()
    }
}

fn argv_summary(argv: &[String]) -> String {
    const MAX: usize = 160;
    let joined = argv.join(" ");
    if joined.len() <= MAX {
        joined
    } else {
        let mut out = joined
            .chars()
            .take(MAX.saturating_sub(1))
            .collect::<String>();
        out.push('…');
        out
    }
}

fn stream_name(kind: StreamKind) -> &'static str {
    match kind {
        StreamKind::Stdout => "stdout",
        StreamKind::Stderr => "stderr",
    }
}

#[derive(Debug, Clone, Copy)]
enum TermSignal {
    Term,
    Kill,
}

fn signal_number(signal: TermSignal) -> i32 {
    match signal {
        TermSignal::Term => 15,
        TermSignal::Kill => 9,
    }
}

fn send_signal(pid: u32, signal: TermSignal) {
    #[cfg(unix)]
    {
        let sig = match signal {
            TermSignal::Term => libc::SIGTERM,
            TermSignal::Kill => libc::SIGKILL,
        };
        // SAFETY: `libc::kill` is called with a child PID returned by
        // `tokio::process::Child::id` and a constant signal number.
        let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
        if rc != 0 {
            tracing::debug!(
                pid,
                signal = signal_number(signal),
                "failed to signal exec child"
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        let _ = signal;
    }
}

fn status_signal(status: Option<&std::process::ExitStatus>) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status.and_then(std::process::ExitStatus::signal)
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

/// `/exec/sessions` snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ExecSessionsSnapshot {
    pub ok: bool,
    pub pending_clients: Vec<ExecClientSessionSnapshot>,
    pub active_servers: Vec<ExecServerSessionSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecClientSessionSnapshot {
    pub request_id: String,
    pub target_agent_id: String,
    pub argv_summary: String,
    pub age_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecServerSessionSnapshot {
    pub request_id: String,
    pub agent_id: String,
    pub machine_id: String,
    pub argv_summary: String,
    pub age_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::acl::{AllowEntry, AllowedCommand, AllowedToken};
    use std::path::{Path, PathBuf};

    fn test_acl(agent_id: AgentId, machine_id: MachineId) -> ExecAcl {
        ExecAcl {
            loaded_from: PathBuf::from("exec-acl.toml"),
            loaded_at_unix_ms: 1,
            caps: ExecCaps {
                max_stdin_bytes: 4,
                max_duration_secs: 5,
                default_cwd: Some(PathBuf::from("/tmp")),
                ..ExecCaps::default()
            },
            audit_log_path: PathBuf::from("audit.jsonl"),
            audit_tasklist_id: None,
            allow: vec![AllowEntry {
                description: Some("test command".to_string()),
                agent_id,
                machine_id,
                max_duration_secs: Some(3),
                commands: vec![AllowedCommand {
                    argv: vec![
                        AllowedToken::Literal("echo".to_string()),
                        AllowedToken::Literal("ok".to_string()),
                    ],
                }],
            }],
        }
    }

    async fn build_test_service(policy: ExecPolicy, dir: &Path) -> Arc<ExecService> {
        let agent = Agent::builder()
            .with_machine_key(dir.join("machine.key"))
            .with_agent_key_path(dir.join("agent.key"))
            .with_contact_store_path(dir.join("contacts.json"))
            .with_peer_cache_disabled()
            .build()
            .await
            .expect("agent");
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        Arc::new(ExecService {
            agent: Arc::new(agent),
            policy: Arc::new(policy.clone()),
            audit: ExecAudit::new(&policy, Arc::clone(&diagnostics)),
            diagnostics,
            pending_clients: Mutex::new(HashMap::new()),
            active_servers: Mutex::new(HashMap::new()),
            active_counts: Mutex::new(ActiveCounts::default()),
            cancellation_token: tokio_util::sync::CancellationToken::new(),
            task_handles: Mutex::new(Vec::new()),
            request_task_handles: Mutex::new(HashMap::new()),
            shutdown_lock: tokio::sync::Mutex::new(()),
        })
    }

    async fn test_service() -> Arc<ExecService> {
        let dir = tempfile::tempdir().expect("tmpdir");
        let policy = ExecPolicy::Disabled {
            path: dir.path().join("exec-acl.toml"),
            reason: "test".to_string(),
            loaded_at_unix_ms: 1,
        };
        build_test_service(policy, dir.path()).await
    }

    async fn enabled_test_service(acl: ExecAcl) -> (Arc<ExecService>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let service = build_test_service(ExecPolicy::Enabled(acl), dir.path()).await;
        (service, dir)
    }

    #[tokio::test]
    async fn concurrency_slots_enforce_total_and_per_agent_caps() {
        let service = test_service().await;
        let agent = AgentId([7; 32]);
        let caps = ExecCaps {
            max_concurrent_per_agent: 1,
            max_concurrent_total: 1,
            ..ExecCaps::default()
        };

        assert!(service.try_acquire_slot(agent, &caps).await.is_some());
        assert!(service.try_acquire_slot(agent, &caps).await.is_none());
        service.release_slot(agent).await;
        assert!(service.try_acquire_slot(agent, &caps).await.is_some());
    }

    #[tokio::test]
    async fn lease_renew_extends_deadline_without_touching_idle_activity() {
        let service = test_service().await;
        let request_id = ExecRequestId([2; 16]);
        let agent_id = AgentId([6; 32]);
        let machine_id = MachineId([7; 32]);
        let (cancel_tx, _cancel_rx) = watch::channel(CancelReason::DurationCap);
        let lease_deadline = Arc::new(Mutex::new(Instant::now() - Duration::from_secs(1)));
        let activity_before_renew = Instant::now() - Duration::from_secs(60);
        let last_activity = Arc::new(Mutex::new(activity_before_renew));

        service.active_servers.lock().await.insert(
            request_id,
            ActiveServerSession {
                agent_id,
                machine_id,
                cancel_tx,
                lease_deadline: Arc::clone(&lease_deadline),
                last_activity: Arc::clone(&last_activity),
                argv_summary: "lease-test".to_string(),
                started_at: Instant::now(),
                child_pid: Arc::new(AtomicU32::new(0)),
            },
        );

        service
            .handle_lease_renew(agent_id, machine_id, request_id)
            .await;

        assert!(*lease_deadline.lock().await > Instant::now());
        assert_eq!(*last_activity.lock().await, activity_before_renew);
    }

    #[tokio::test]
    async fn output_caps_warn_truncate_and_keep_draining() {
        let service = test_service().await;
        let request_id = ExecRequestId([3; 16]);
        let target = AgentId([8; 32]);
        let caps = ExecCaps {
            max_stdout_bytes: 10,
            warn_stdout_bytes: 5,
            ..ExecCaps::default()
        };
        let total = Arc::new(AtomicU64::new(0));
        let truncated = Arc::new(AtomicBool::new(false));
        let seq = Arc::new(AtomicU32::new(0));
        let activity_before_output = Instant::now() - Duration::from_secs(10);
        let last_activity = Arc::new(Mutex::new(activity_before_output));
        let data = vec![b'x'; 64];

        service
            .stream_output(
                data.as_slice(),
                target,
                request_id,
                StreamKind::Stdout,
                caps,
                Arc::clone(&total),
                Arc::clone(&truncated),
                Arc::clone(&seq),
                Arc::clone(&last_activity),
                "cap-test".to_string(),
            )
            .await;

        assert_eq!(total.load(Ordering::Relaxed), data.len() as u64);
        assert!(truncated.load(Ordering::Relaxed));
        assert!(*last_activity.lock().await > activity_before_output);
        let snapshot = service.diagnostics_snapshot().await;
        assert_eq!(snapshot.totals.cap_breaches.get("stdout"), Some(&1));
        assert_eq!(
            snapshot.totals.cap_warnings.get("stdout_approaching_cap"),
            Some(&1)
        );
        assert_eq!(snapshot.totals.cap_warnings.get("stdout_cap_hit"), Some(&1));
    }

    #[tokio::test]
    async fn stderr_output_caps_warn_truncate_and_keep_draining() {
        let service = test_service().await;
        let request_id = ExecRequestId([45; 16]);
        let target = AgentId([46; 32]);
        let caps = ExecCaps {
            max_stderr_bytes: 8,
            warn_stderr_bytes: 4,
            ..ExecCaps::default()
        };
        let total = Arc::new(AtomicU64::new(0));
        let truncated = Arc::new(AtomicBool::new(false));
        let seq = Arc::new(AtomicU32::new(0));
        let last_activity = Arc::new(Mutex::new(Instant::now() - Duration::from_secs(5)));
        let data = vec![b'e'; 32];

        service
            .stream_output(
                data.as_slice(),
                target,
                request_id,
                StreamKind::Stderr,
                caps,
                Arc::clone(&total),
                Arc::clone(&truncated),
                Arc::clone(&seq),
                Arc::clone(&last_activity),
                "stderr-test".to_string(),
            )
            .await;

        assert_eq!(total.load(Ordering::Relaxed), data.len() as u64);
        assert!(truncated.load(Ordering::Relaxed));
        let snapshot = service.diagnostics_snapshot().await;
        assert_eq!(snapshot.totals.cap_breaches.get("stderr"), Some(&1));
        assert_eq!(
            snapshot.totals.cap_warnings.get("stderr_approaching_cap"),
            Some(&1)
        );
        assert_eq!(snapshot.totals.cap_warnings.get("stderr_cap_hit"), Some(&1));
    }

    #[tokio::test]
    async fn stream_output_below_threshold_records_bytes_without_warning() {
        let service = test_service().await;
        let total = Arc::new(AtomicU64::new(0));
        let truncated = Arc::new(AtomicBool::new(false));
        let seq = Arc::new(AtomicU32::new(0));
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let caps = ExecCaps {
            max_stdout_bytes: 100,
            warn_stdout_bytes: 90,
            ..ExecCaps::default()
        };

        service
            .stream_output(
                b"small".as_slice(),
                AgentId([47; 32]),
                ExecRequestId([48; 16]),
                StreamKind::Stdout,
                caps,
                Arc::clone(&total),
                Arc::clone(&truncated),
                Arc::clone(&seq),
                Arc::clone(&last_activity),
                "small-output".to_string(),
            )
            .await;

        assert_eq!(total.load(Ordering::Relaxed), 5);
        assert!(!truncated.load(Ordering::Relaxed));
        assert_eq!(seq.load(Ordering::Relaxed), 1);
        let snapshot = service.diagnostics_snapshot().await;
        assert!(snapshot.totals.cap_breaches.is_empty());
        assert!(snapshot.totals.cap_warnings.is_empty());
    }

    #[tokio::test]
    async fn lease_renew_ignores_wrong_sender_or_machine() {
        let service = test_service().await;
        let request_id = ExecRequestId([49; 16]);
        let agent = AgentId([50; 32]);
        let machine = MachineId([51; 32]);
        let (cancel_tx, _cancel_rx) = watch::channel(CancelReason::DurationCap);
        let original_deadline = Instant::now() - Duration::from_secs(1);
        let lease_deadline = Arc::new(Mutex::new(original_deadline));
        service.active_servers.lock().await.insert(
            request_id,
            ActiveServerSession {
                agent_id: agent,
                machine_id: machine,
                cancel_tx,
                lease_deadline: Arc::clone(&lease_deadline),
                last_activity: Arc::new(Mutex::new(Instant::now())),
                argv_summary: "lease mismatch".to_string(),
                started_at: Instant::now(),
                child_pid: Arc::new(AtomicU32::new(0)),
            },
        );

        service
            .handle_lease_renew(AgentId([99; 32]), machine, request_id)
            .await;
        assert_eq!(*lease_deadline.lock().await, original_deadline);
        service
            .handle_lease_renew(agent, MachineId([98; 32]), request_id)
            .await;
        assert_eq!(*lease_deadline.lock().await, original_deadline);
    }

    #[tokio::test]
    async fn record_session_activity_updates_timestamp() {
        let last_activity = Arc::new(Mutex::new(Instant::now() - Duration::from_secs(10)));
        let before = *last_activity.lock().await;
        ExecService::record_session_activity(&last_activity).await;
        assert!(*last_activity.lock().await > before);
    }

    #[tokio::test]
    async fn release_slot_without_existing_count_is_noop() {
        let service = test_service().await;
        let agent = AgentId([52; 32]);
        service.release_slot(agent).await;
        let counts = service.active_counts.lock().await;
        assert_eq!(counts.total, 0);
        assert!(!counts.per_agent.contains_key(&agent));
    }

    #[tokio::test]
    async fn duration_cap_terminates_child_promptly() {
        if !Path::new("/bin/sleep").exists() {
            return;
        }
        let service = test_service().await;
        let request_id = ExecRequestId([4; 16]);
        let target = AgentId([9; 32]);
        let checked = CheckedRequest {
            caps: ExecCaps {
                warn_duration_secs: 1,
                ..ExecCaps::default()
            },
            max_duration: Duration::from_secs(1),
            cwd: None,
            description: None,
        };
        let (_cancel_tx, cancel_rx) = watch::channel(CancelReason::DurationCap);
        let lease_deadline = Arc::new(Mutex::new(Instant::now() + Duration::from_secs(30)));
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let child_pid = Arc::new(AtomicU32::new(0));
        let started = Instant::now();

        service
            .run_child(
                target,
                request_id,
                vec!["/bin/sleep".to_string(), "10".to_string()],
                None,
                checked,
                cancel_rx,
                lease_deadline,
                last_activity,
                child_pid,
            )
            .await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "duration cap should terminate well before the child sleep completes"
        );
        let snapshot = service.diagnostics_snapshot().await;
        assert_eq!(snapshot.totals.sessions_completed, 1);
        assert_eq!(
            snapshot.totals.cap_warnings.get("duration_approaching_cap"),
            Some(&1)
        );
    }

    /// Issue #118 regression: an in-flight exec child must be killed by
    /// `shutdown()`, and the request handler task must not outlive it.
    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_kills_in_flight_exec_child_and_aborts_handler() {
        if !Path::new("/bin/sleep").exists() {
            return;
        }
        let inbound = inbound_payload(true, Some(TrustDecision::Accept));
        // ACL allowing a long sleep so the child would otherwise outlive the test.
        let acl = ExecAcl {
            loaded_from: PathBuf::from("exec-acl.toml"),
            loaded_at_unix_ms: 1,
            caps: ExecCaps {
                max_duration_secs: 300,
                warn_duration_secs: 290,
                ..ExecCaps::default()
            },
            audit_log_path: PathBuf::from("audit.jsonl"),
            audit_tasklist_id: None,
            allow: vec![AllowEntry {
                description: Some("long sleep".to_string()),
                agent_id: inbound.sender,
                machine_id: inbound.machine_id,
                max_duration_secs: Some(300),
                commands: vec![AllowedCommand {
                    argv: vec![
                        AllowedToken::Literal("/bin/sleep".to_string()),
                        AllowedToken::Literal("60".to_string()),
                    ],
                }],
            }],
        };
        let (service, _dir) = enabled_test_service(acl).await;
        let request_id = ExecRequestId([77; 16]);

        // Drive the request through the real handler-spawn path so the task is
        // tracked in `request_task_handles` (the path #118 adds).
        Arc::clone(&service)
            .spawn_request_handler(
                inbound,
                request_id,
                vec!["/bin/sleep".to_string(), "60".to_string()],
                None,
                60_000,
                None,
            )
            .await;

        // Wait for the child to be spawned and published.
        let pid = {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let guard = service.active_servers.lock().await;
                if let Some(session) = guard.get(&request_id) {
                    let pid = session.child_pid.load(Ordering::Acquire);
                    if pid != 0 {
                        break pid;
                    }
                }
                drop(guard);
                if Instant::now() >= deadline {
                    panic!("exec child never started");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };

        // Sanity: the child is alive right now.
        assert!(
            process_alive(pid),
            "child {pid} should be alive before shutdown"
        );

        service.shutdown().await;

        // The child must be gone: shutdown SIGKILLed it out-of-band and/or
        // aborted the handler (which drops the Child, firing kill_on_drop).
        let mut gone = false;
        for _ in 0..50 {
            if !process_alive(pid) {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(gone, "child {pid} should be dead after shutdown");
        assert!(
            service.active_servers.lock().await.is_empty(),
            "active_servers should be cleared after shutdown"
        );
        assert!(
            service.request_task_handles.lock().await.is_empty(),
            "request_task_handles should be drained after shutdown"
        );
    }

    #[tokio::test]
    async fn enabled_returns_false_for_disabled_policy() {
        let service = test_service().await;
        assert!(!service.enabled(), "disabled policy should return false");
    }

    #[tokio::test]
    async fn diagnostics_snapshot_returns_valid_data() {
        let service = test_service().await;
        let snap = service.diagnostics_snapshot().await;
        assert!(snap.ok);
        assert!(!snap.enabled);
        assert_eq!(snap.active_sessions, 0);
        assert!(snap.active_per_agent.is_empty());
        assert_eq!(snap.totals.requests_received, 0);
        assert_eq!(snap.totals.requests_allowed, 0);
        assert_eq!(snap.totals.requests_denied, 0);
    }

    #[tokio::test]
    async fn sessions_snapshot_returns_empty_for_fresh_service() {
        let service = test_service().await;
        let snap = service.sessions_snapshot().await;
        assert!(snap.ok);
        assert!(snap.pending_clients.is_empty());
        assert!(snap.active_servers.is_empty());
    }

    #[tokio::test]
    async fn sessions_snapshot_includes_pending_and_active_sessions() {
        let service = test_service().await;
        let request_id = ExecRequestId([21; 16]);
        let target = AgentId([22; 32]);
        let (tx, _rx) = mpsc::channel(1);
        service.pending_clients.lock().await.insert(
            request_id,
            PendingClient {
                target,
                tx,
                argv_summary: "echo pending".to_string(),
                started_at: Instant::now() - Duration::from_millis(10),
            },
        );

        let (cancel_tx, _cancel_rx) = watch::channel(CancelReason::ExplicitCancel);
        service.active_servers.lock().await.insert(
            ExecRequestId([23; 16]),
            ActiveServerSession {
                agent_id: AgentId([24; 32]),
                machine_id: MachineId([25; 32]),
                cancel_tx,
                lease_deadline: Arc::new(Mutex::new(Instant::now() + Duration::from_secs(10))),
                last_activity: Arc::new(Mutex::new(Instant::now())),
                argv_summary: "echo active".to_string(),
                started_at: Instant::now() - Duration::from_millis(20),
                child_pid: Arc::new(AtomicU32::new(0)),
            },
        );

        let snap = service.sessions_snapshot().await;
        assert_eq!(snap.pending_clients.len(), 1);
        assert_eq!(
            snap.pending_clients[0].request_id,
            hex::encode(request_id.0)
        );
        assert_eq!(
            snap.pending_clients[0].target_agent_id,
            hex::encode(target.0)
        );
        assert_eq!(snap.pending_clients[0].argv_summary, "echo pending");
        assert_eq!(snap.active_servers.len(), 1);
        assert_eq!(snap.active_servers[0].argv_summary, "echo active");
        assert!(snap.active_servers[0].age_ms <= 1_000);
    }

    #[test]
    fn argv_summary_returns_short_commands_unchanged() {
        let argv = vec!["echo".to_string(), "hello".to_string()];
        assert_eq!(argv_summary(&argv), "echo hello");
    }

    #[test]
    fn argv_summary_truncates_long_commands_with_ellipsis() {
        let argv = vec!["x".repeat(200)];
        let summary = argv_summary(&argv);
        assert_eq!(summary.chars().count(), 160);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn stream_name_and_signal_number_are_stable() {
        assert_eq!(stream_name(StreamKind::Stdout), "stdout");
        assert_eq!(stream_name(StreamKind::Stderr), "stderr");
        assert_eq!(signal_number(TermSignal::Term), 15);
        assert_eq!(signal_number(TermSignal::Kill), 9);
    }

    #[test]
    fn status_signal_none_returns_none() {
        assert_eq!(status_signal(None), None);
    }

    #[test]
    fn exec_frames_use_verified_gossip_publish_only_delivery() {
        let request_id = ExecRequestId([53; 16]);
        let frames = [
            ExecFrame::Request {
                request_id,
                argv: vec!["/bin/echo".to_string(), "ok".to_string()],
                stdin: None,
                timeout_ms: 1_000,
                cwd: None,
            },
            ExecFrame::Started {
                request_id,
                pid: 123,
            },
            ExecFrame::Stdout {
                request_id,
                seq: 0,
                data: b"out".to_vec(),
            },
            ExecFrame::Stderr {
                request_id,
                seq: 1,
                data: b"err".to_vec(),
            },
            ExecFrame::Warning {
                request_id,
                kind: WarningKind::StdoutCapHit,
                message: "cap hit".to_string(),
            },
            ExecFrame::LeaseRenew { request_id },
            ExecFrame::Cancel { request_id },
            ExecFrame::Exit {
                request_id,
                code: Some(0),
                signal: None,
                duration_ms: 1,
                stdout_bytes_total: 0,
                stderr_bytes_total: 0,
                truncated: false,
                denial_reason: None,
            },
        ];

        for frame in frames {
            let config = exec_frame_send_config(&frame);
            assert!(config.require_gossip);
            assert!(!config.prefer_raw_quic_if_connected);
            assert!(!config.require_gossip_ack);
            assert_eq!(config.timeout_per_attempt, Duration::from_secs(8));
        }
    }

    fn denied(result: Result<CheckedRequest, DenialReason>) -> DenialReason {
        match result {
            Ok(_) => panic!("request unexpectedly allowed"),
            Err(reason) => reason,
        }
    }

    #[tokio::test]
    async fn check_request_accepts_matching_acl_entry() {
        let service = test_service().await;
        let agent = AgentId([31; 32]);
        let machine = MachineId([32; 32]);
        let acl = test_acl(agent, machine);
        let argv = vec!["echo".to_string(), "ok".to_string()];

        let checked = service
            .check_request(
                &acl,
                agent,
                machine,
                &argv,
                Some(&b"in".to_vec()),
                2_500,
                None,
            )
            .expect("request should be allowed");
        assert_eq!(checked.max_duration, Duration::from_secs(3));
        assert_eq!(checked.cwd, Some(PathBuf::from("/tmp")));
        assert_eq!(checked.description.as_deref(), Some("test command"));
    }

    #[tokio::test]
    async fn check_request_rejects_empty_argv_and_cwd() {
        let service = test_service().await;
        let agent = AgentId([33; 32]);
        let machine = MachineId([34; 32]);
        let acl = test_acl(agent, machine);
        assert_eq!(
            denied(service.check_request(&acl, agent, machine, &[], None, 1_000, None)),
            DenialReason::ArgvNotAllowed
        );
        assert_eq!(
            denied(service.check_request(
                &acl,
                agent,
                machine,
                &["echo".to_string(), "ok".to_string()],
                None,
                1_000,
                Some(&"/tmp".to_string()),
            )),
            DenialReason::CwdNotAllowed
        );
    }

    #[tokio::test]
    async fn check_request_rejects_shell_meta_and_unknown_pair() {
        let service = test_service().await;
        let agent = AgentId([35; 32]);
        let machine = MachineId([36; 32]);
        let acl = test_acl(agent, machine);
        assert_eq!(
            denied(service.check_request(
                &acl,
                agent,
                machine,
                &["echo".to_string(), "ok;rm".to_string()],
                None,
                1_000,
                None,
            )),
            DenialReason::ShellMetacharInArgv
        );
        assert_eq!(
            denied(service.check_request(
                &acl,
                AgentId([99; 32]),
                machine,
                &["echo".to_string(), "ok".to_string()],
                None,
                1_000,
                None,
            )),
            DenialReason::AgentMachineNotInAcl
        );
    }

    #[tokio::test]
    async fn check_request_rejects_unmatched_argv_stdin_and_timeout() {
        let service = test_service().await;
        let agent = AgentId([37; 32]);
        let machine = MachineId([38; 32]);
        let acl = test_acl(agent, machine);
        assert_eq!(
            denied(service.check_request(
                &acl,
                agent,
                machine,
                &["echo".to_string(), "nope".to_string()],
                None,
                1_000,
                None,
            )),
            DenialReason::ArgvNotAllowed
        );
        assert_eq!(
            denied(service.check_request(
                &acl,
                agent,
                machine,
                &["echo".to_string(), "ok".to_string()],
                Some(&b"too long".to_vec()),
                1_000,
                None,
            )),
            DenialReason::StdinTooLarge
        );
        assert_eq!(
            denied(service.check_request(
                &acl,
                agent,
                machine,
                &["echo".to_string(), "ok".to_string()],
                None,
                4_000,
                None,
            )),
            DenialReason::TimeoutTooLarge
        );
    }

    #[tokio::test]
    async fn forward_to_pending_client_delivers_frame_and_ignores_missing_client() {
        let service = test_service().await;
        let request_id = ExecRequestId([39; 16]);
        let target = AgentId([40; 32]);
        let (tx, mut rx) = mpsc::channel(1);
        service.pending_clients.lock().await.insert(
            request_id,
            PendingClient {
                target,
                tx,
                argv_summary: "echo frame".to_string(),
                started_at: Instant::now(),
            },
        );

        let frame = ExecFrame::Warning {
            request_id,
            kind: WarningKind::StdoutApproachingCap,
            message: "near cap".to_string(),
        };
        service.forward_to_pending_client(request_id, frame).await;
        assert!(matches!(rx.recv().await, Some(ExecFrame::Warning { .. })));
        service
            .forward_to_pending_client(ExecRequestId([41; 16]), ExecFrame::Cancel { request_id })
            .await;
    }

    #[tokio::test]
    async fn handle_cancel_sends_explicit_cancel_for_matching_session_only() {
        let service = test_service().await;
        let request_id = ExecRequestId([42; 16]);
        let agent = AgentId([43; 32]);
        let machine = MachineId([44; 32]);
        let (cancel_tx, mut cancel_rx) = watch::channel(CancelReason::DurationCap);
        service.active_servers.lock().await.insert(
            request_id,
            ActiveServerSession {
                agent_id: agent,
                machine_id: machine,
                cancel_tx,
                lease_deadline: Arc::new(Mutex::new(Instant::now() + Duration::from_secs(10))),
                last_activity: Arc::new(Mutex::new(Instant::now())),
                argv_summary: "cancel".to_string(),
                started_at: Instant::now(),
                child_pid: Arc::new(AtomicU32::new(0)),
            },
        );

        service
            .handle_cancel(AgentId([99; 32]), machine, request_id)
            .await;
        assert_eq!(*cancel_rx.borrow(), CancelReason::DurationCap);
        service.handle_cancel(agent, machine, request_id).await;
        cancel_rx.changed().await.expect("cancel update");
        assert_eq!(*cancel_rx.borrow(), CancelReason::ExplicitCancel);
    }

    fn inbound_payload(verified: bool, trust_decision: Option<TrustDecision>) -> DmTypedPayload {
        DmTypedPayload {
            sender: AgentId([53; 32]),
            machine_id: MachineId([54; 32]),
            payload: Vec::new(),
            verified,
            trust_decision,
            received_at_unix_ms: 1,
        }
    }

    async fn assert_single_denial(service: &Arc<ExecService>, reason: DenialReason) {
        let snap = service.diagnostics_snapshot().await;
        assert_eq!(snap.totals.requests_received, 1);
        assert_eq!(snap.totals.requests_denied, 1);
        assert_eq!(snap.totals.denial_breakdown.get(reason.as_str()), Some(&1));
        assert!(service.active_servers.lock().await.is_empty());
    }

    /// Whether a Unix process is still alive (signal 0 succeeds). EPERM (exists
    /// but not ours) is treated as alive; ESRCH (no such process) as gone.
    #[cfg(unix)]
    fn process_alive(pid: u32) -> bool {
        // SAFETY: `libc::kill` with signal 0 is a standard liveness probe and
        // takes no action on the target.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // ESRCH: no such process. EPERM: exists but not ours (treat as alive).
        errno != libc::ESRCH
    }

    #[tokio::test]
    async fn handle_request_denies_unverified_sender_before_policy() {
        let service = test_service().await;
        Arc::clone(&service)
            .handle_request(
                inbound_payload(false, Some(TrustDecision::Accept)),
                ExecRequestId([55; 16]),
                vec!["echo".to_string(), "ok".to_string()],
                None,
                1_000,
                None,
            )
            .await;

        assert_single_denial(&service, DenialReason::UnverifiedSender).await;
    }

    #[tokio::test]
    async fn handle_request_denies_non_accept_trust_decision() {
        let service = test_service().await;
        Arc::clone(&service)
            .handle_request(
                inbound_payload(true, Some(TrustDecision::AcceptWithFlag)),
                ExecRequestId([56; 16]),
                vec!["echo".to_string(), "ok".to_string()],
                None,
                1_000,
                None,
            )
            .await;

        assert_single_denial(&service, DenialReason::TrustRejected).await;
    }

    #[tokio::test]
    async fn handle_request_denies_when_exec_policy_disabled() {
        let service = test_service().await;
        Arc::clone(&service)
            .handle_request(
                inbound_payload(true, Some(TrustDecision::Accept)),
                ExecRequestId([57; 16]),
                vec!["echo".to_string(), "ok".to_string()],
                None,
                1_000,
                None,
            )
            .await;

        assert_single_denial(&service, DenialReason::ExecDisabled).await;
    }

    #[tokio::test]
    async fn handle_request_enabled_policy_denies_unmatched_argv() {
        let inbound = inbound_payload(true, Some(TrustDecision::Accept));
        let acl = test_acl(inbound.sender, inbound.machine_id);
        let (service, _dir) = enabled_test_service(acl).await;
        Arc::clone(&service)
            .handle_request(
                inbound,
                ExecRequestId([58; 16]),
                vec!["echo".to_string(), "nope".to_string()],
                None,
                1_000,
                None,
            )
            .await;
        assert_single_denial(&service, DenialReason::ArgvNotAllowed).await;
    }

    #[tokio::test]
    async fn handle_request_enabled_policy_denies_stdin_too_large() {
        let inbound = inbound_payload(true, Some(TrustDecision::Accept));
        let acl = test_acl(inbound.sender, inbound.machine_id);
        let (service, _dir) = enabled_test_service(acl).await;
        Arc::clone(&service)
            .handle_request(
                inbound,
                ExecRequestId([59; 16]),
                vec!["echo".to_string(), "ok".to_string()],
                Some(b"too long".to_vec()),
                1_000,
                None,
            )
            .await;
        assert_single_denial(&service, DenialReason::StdinTooLarge).await;
    }

    #[tokio::test]
    async fn handle_request_enabled_policy_denies_timeout_too_large() {
        let inbound = inbound_payload(true, Some(TrustDecision::Accept));
        let acl = test_acl(inbound.sender, inbound.machine_id);
        let (service, _dir) = enabled_test_service(acl).await;
        Arc::clone(&service)
            .handle_request(
                inbound,
                ExecRequestId([60; 16]),
                vec!["echo".to_string(), "ok".to_string()],
                None,
                4_000,
                None,
            )
            .await;
        assert_single_denial(&service, DenialReason::TimeoutTooLarge).await;
    }

    #[tokio::test]
    async fn handle_request_enabled_policy_denies_concurrency_limit() {
        let inbound = inbound_payload(true, Some(TrustDecision::Accept));
        let mut acl = test_acl(inbound.sender, inbound.machine_id);
        acl.caps.max_concurrent_total = 0;
        let (service, _dir) = enabled_test_service(acl).await;
        Arc::clone(&service)
            .handle_request(
                inbound,
                ExecRequestId([61; 16]),
                vec!["echo".to_string(), "ok".to_string()],
                None,
                1_000,
                None,
            )
            .await;
        assert_single_denial(&service, DenialReason::ConcurrencyLimitReached).await;
    }

    #[tokio::test]
    async fn try_acquire_slot_returns_some_when_available() {
        let service = test_service().await;
        let agent = AgentId([9; 32]);
        let caps = ExecCaps {
            max_concurrent_per_agent: 5,
            max_concurrent_total: 10,
            ..ExecCaps::default()
        };
        let slot = service.try_acquire_slot(agent, &caps).await;
        assert!(slot.is_some(), "should acquire slot when under caps");
    }

    #[tokio::test]
    async fn try_acquire_slot_respects_total_cap() {
        let service = test_service().await;
        let agent_a = AgentId([10; 32]);
        let agent_b = AgentId([11; 32]);
        let caps = ExecCaps {
            max_concurrent_per_agent: 5,
            max_concurrent_total: 1,
            ..ExecCaps::default()
        };
        assert!(service.try_acquire_slot(agent_a, &caps).await.is_some());
        assert!(
            service.try_acquire_slot(agent_b, &caps).await.is_none(),
            "total cap should block second agent"
        );
    }

    #[tokio::test]
    async fn try_acquire_slot_respects_per_agent_cap() {
        let service = test_service().await;
        let agent = AgentId([12; 32]);
        let caps = ExecCaps {
            max_concurrent_per_agent: 2,
            max_concurrent_total: 10,
            ..ExecCaps::default()
        };
        assert!(service.try_acquire_slot(agent, &caps).await.is_some());
        assert!(service.try_acquire_slot(agent, &caps).await.is_some());
        assert!(
            service.try_acquire_slot(agent, &caps).await.is_none(),
            "per-agent cap should block third slot"
        );
    }

    #[tokio::test]
    async fn release_slot_frees_capacity() {
        let service = test_service().await;
        let agent = AgentId([13; 32]);
        let caps = ExecCaps {
            max_concurrent_per_agent: 1,
            max_concurrent_total: 1,
            ..ExecCaps::default()
        };
        assert!(service.try_acquire_slot(agent, &caps).await.is_some());
        service.release_slot(agent).await;
        assert!(
            service.try_acquire_slot(agent, &caps).await.is_some(),
            "should re-acquire after release"
        );
    }

    #[tokio::test]
    async fn handle_lease_renew_returns_ok_for_unknown_session() {
        let service = test_service().await;
        let agent = AgentId([14; 32]);
        let machine = MachineId([15; 32]);
        let request_id = ExecRequestId([99; 16]);
        service.handle_lease_renew(agent, machine, request_id).await;
    }

    #[tokio::test]
    async fn handle_cancel_returns_ok_for_unknown_session() {
        let service = test_service().await;
        let agent = AgentId([16; 32]);
        let machine = MachineId([17; 32]);
        let request_id = ExecRequestId([98; 16]);
        service.handle_cancel(agent, machine, request_id).await;
    }
}
