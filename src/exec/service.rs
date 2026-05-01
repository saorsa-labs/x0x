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
    argv_summary: String,
    started_at: Instant,
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
        });
        let loop_service = Arc::clone(&service);
        tokio::spawn(async move {
            loop_service.run_inbound_loop(inbound_rx).await;
        });
        let lifecycle_service = Arc::clone(&service);
        tokio::spawn(async move {
            lifecycle_service.run_peer_lifecycle_loop().await;
        });
        service
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
            let (peer_id, event) = match rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "exec peer lifecycle watcher lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let should_cancel = matches!(
                event,
                ant_quic::PeerLifecycleEvent::Closing { .. }
                    | ant_quic::PeerLifecycleEvent::Closed { .. }
                    | ant_quic::PeerLifecycleEvent::ReaderExited { .. }
            );
            if should_cancel {
                let machine_id = MachineId(peer_id.0);
                let cancelled = self
                    .cancel_sessions_for_machine(machine_id, CancelReason::PeerDisconnected)
                    .await;
                if cancelled > 0 {
                    tracing::info!(
                        machine_id = %hex::encode(machine_id.as_bytes()),
                        cancelled,
                        "cancelled exec sessions for disconnected peer"
                    );
                }
            }
        }
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
        while let Some(inbound) = inbound_rx.recv().await {
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
                    tokio::spawn(async move {
                        service
                            .handle_request(inbound, request_id, argv, stdin, timeout_ms, cwd)
                            .await;
                    });
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
        let lease_deadline = Arc::new(Mutex::new(Instant::now() + LEASE_TIMEOUT));
        let active_session = ActiveServerSession {
            agent_id: inbound.sender,
            machine_id: inbound.machine_id,
            cancel_tx,
            lease_deadline: Arc::clone(&lease_deadline),
            argv_summary: argv_summary(&argv),
            started_at: Instant::now(),
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
                Ok(Some(status)) => break Some(status),
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
                        kill_at = now + CANCEL_GRACE;
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
        let config = DmSendConfig {
            require_gossip: true,
            prefer_raw_quic_if_connected: false,
            ..DmSendConfig::default()
        };
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
    use std::path::Path;

    async fn test_service() -> Arc<ExecService> {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .build()
            .await
            .expect("agent");
        let policy = ExecPolicy::Disabled {
            path: dir.path().join("exec-acl.toml"),
            reason: "test".to_string(),
            loaded_at_unix_ms: 1,
        };
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        Arc::new(ExecService {
            agent: Arc::new(agent),
            policy: Arc::new(policy.clone()),
            audit: ExecAudit::new(&policy, Arc::clone(&diagnostics)),
            diagnostics,
            pending_clients: Mutex::new(HashMap::new()),
            active_servers: Mutex::new(HashMap::new()),
            active_counts: Mutex::new(ActiveCounts::default()),
        })
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
                "cap-test".to_string(),
            )
            .await;

        assert_eq!(total.load(Ordering::Relaxed), data.len() as u64);
        assert!(truncated.load(Ordering::Relaxed));
        let snapshot = service.diagnostics_snapshot().await;
        assert_eq!(snapshot.totals.cap_breaches.get("stdout"), Some(&1));
        assert_eq!(
            snapshot.totals.cap_warnings.get("stdout_approaching_cap"),
            Some(&1)
        );
        assert_eq!(snapshot.totals.cap_warnings.get("stdout_cap_hit"), Some(&1));
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
}
