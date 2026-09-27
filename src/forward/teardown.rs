//! Open-stream teardown on revocation, loss of trust and grant expiry
//! (ADR-0074 §4).
//!
//! Every bridged forward stream, inbound and outbound, is registered in
//! a live-stream registry with the inputs its gate was evaluated on and the
//! authority it was admitted under ([`StreamAuthority`]). A re-check pass
//! re-runs the same gates on every live stream; a stream a fresh admission
//! would now refuse is torn down. That covers every trigger in §4 (a
//! revocation-set insert, a grant revocation or expiry, an ACL reload, a
//! contact downgrade or `Blocked`, an owner enrollment removal) without the
//! re-check having to know which one fired. It also cannot widen anything:
//! a stream survives only while its admission gate still passes.
//!
//! ## When a pass runs
//!
//! - **On an event**: the agent's re-check signal is woken by every
//!   revocation-set change, every contact-store change and every connect-ACL
//!   reload ([`crate::Agent::set_connect_policy`]). The pass starts at most
//!   [`REAUTH_MIN_SPACING`] later.
//! - **On a sweep**: every [`REAUTH_SWEEP_INTERVAL`]. This backstop bounds
//!   the triggers that raise no event (grant and certificate expiry, an
//!   owner enrollment removal, a discovery-cache change) and any change made
//!   through a path that does not signal.
//!
//! The ADR bounds are ≤5 s after the exposing daemon applies an event and
//! ≤35 s after a grant's expiry. Both are met by the sweep alone (2 s plus a
//! pass), so a missed event can delay a teardown but never past the bound.
//!
//! ## What a teardown does
//!
//! The stream's cancellation token fires. The bridge then resets both QUIC
//! halves (never a FIN, so the peer sees an abort rather than a short but
//! well-formed stream), closes the local TCP socket with an RST, and counts
//! the teardown in `torn_down_reauth` with its reason.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use super::{AttestationVerifyCtx, AuthzDenial, ForwardDiagnostics};
use crate::connect::gate::ConnectDenialReason;
use crate::connect::{evaluate_connect_gate, ConnectPolicy};
use crate::error::NetworkError;
use crate::identity::{AgentId, MachineId};
use crate::trust::TrustDecision;

/// Backstop sweep period. Keeps every §4 bound even for a trigger that
/// raises no event: 2 s plus one pass is well inside 5 s, and far inside
/// the 35 s grant-expiry bound.
pub const REAUTH_SWEEP_INTERVAL: Duration = Duration::from_secs(2);

/// Minimum gap between two passes, so a burst of events (a revocation
/// flood, many contact writes) costs one pass per gap rather than one per
/// event.
pub const REAUTH_MIN_SPACING: Duration = Duration::from_millis(250);

/// QUIC application error code sent when a live stream is torn down
/// because its authority is gone.
pub const REAUTH_RESET_CODE: u32 = 0x5244;

/// The authority a live stream holds (ADR-0074 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "principal", rename_all = "snake_case")]
pub enum StreamAuthority {
    /// Outbound: the peer cleared the identity gate (contact or owner trust)
    /// when the stream was opened.
    PeerTrust,
    /// Inbound: an exact `(agent, machine)` connect-ACL entry lists the
    /// target.
    AclEntry,
    /// Inbound: a `principal = "owner"` entry lists the target and the pair
    /// is owner-trusted (ADR-0070 §1).
    OwnerTrust,
    /// Inbound: a `principal = "grant"` entry lists the target and these
    /// ShareGrants' `Connect` ports cover it (ADR-0070 §2).
    Grant {
        /// Hex ids of the covering grants.
        grant_ids: Vec<String>,
    },
}

impl StreamAuthority {
    /// Which principal admitted an inbound stream that has just passed the
    /// connect gate. Exact entries win over owner entries, which win over
    /// grant entries, mirroring the order the ACL matches in.
    pub(crate) fn classify(
        policy: &ConnectPolicy,
        agent: &AgentId,
        machine: &MachineId,
        owner_trusted: bool,
        target: &SocketAddr,
        connect_grant_ids: &BTreeSet<[u8; 32]>,
    ) -> Self {
        let ConnectPolicy::Enabled(acl) = policy else {
            // Unreachable after a passing gate (a Disabled policy denies).
            // The re-check re-runs the gate anyway, so the label is only
            // descriptive.
            return Self::AclEntry;
        };
        if acl.is_allowed_for_principals(agent, machine, false, false, target) {
            Self::AclEntry
        } else if owner_trusted
            && acl.is_allowed_for_principals(agent, machine, true, false, target)
        {
            Self::OwnerTrust
        } else {
            Self::Grant {
                grant_ids: connect_grant_ids.iter().map(hex::encode).collect(),
            }
        }
    }
}

/// The inputs a live stream's gate is re-run on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum StreamGate {
    /// Inbound `ForwardV2`: the attested opener on its transport machine.
    InboundAttested {
        opener: AgentId,
        machine: MachineId,
        target: SocketAddr,
    },
    /// Inbound `ForwardV1` (only when attestation is not required): every
    /// agent on the machine must stay authorized.
    InboundLegacy {
        machine: MachineId,
        target: SocketAddr,
    },
    /// Outbound: the peer agent this daemon opened the stream to, and the
    /// machine it reached.
    Outbound {
        peer_agent: AgentId,
        machine: MachineId,
    },
}

/// One live stream as `GET /streams` reports it.
#[derive(Debug, Clone, Serialize)]
pub struct LiveStreamView {
    /// `inbound` or `outbound`.
    pub direction: &'static str,
    /// The peer agent (hex): the attested opener, or the outbound target.
    /// `None` for a legacy inbound stream, which is authorized per machine.
    pub peer_agent: Option<String>,
    /// The peer machine (hex).
    pub peer_machine: String,
    /// The local loopback target, for inbound streams.
    pub target: Option<String>,
    /// The authority the stream currently holds.
    pub authority: StreamAuthority,
}

struct LiveEntry {
    gate: StreamGate,
    authority: StreamAuthority,
    cancel: CancellationToken,
}

/// Registry of live forward streams.
pub(crate) struct LiveStreams {
    next_id: AtomicU64,
    streams: std::sync::Mutex<HashMap<u64, LiveEntry>>,
    diag: Arc<ForwardDiagnostics>,
}

/// Registration of one live stream. Its token fires on teardown; dropping
/// it (the stream ended) removes the entry.
pub(crate) struct LiveStreamGuard {
    id: u64,
    cancel: CancellationToken,
    registry: Arc<LiveStreams>,
}

impl LiveStreamGuard {
    /// Fires when the stream must be torn down.
    pub(crate) fn token(&self) -> &CancellationToken {
        &self.cancel
    }
}

impl Drop for LiveStreamGuard {
    fn drop(&mut self) {
        self.registry.lock().remove(&self.id);
    }
}

impl LiveStreams {
    /// An empty registry counting teardowns into `diag`.
    pub(crate) fn new(diag: Arc<ForwardDiagnostics>) -> Self {
        Self {
            next_id: AtomicU64::new(0),
            streams: std::sync::Mutex::new(HashMap::new()),
            diag,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, LiveEntry>> {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a stream admitted under `authority` by a gate run on `gate`.
    pub(crate) fn register(
        self: &Arc<Self>,
        gate: StreamGate,
        authority: StreamAuthority,
    ) -> LiveStreamGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        self.lock().insert(
            id,
            LiveEntry {
                gate,
                authority,
                cancel: cancel.clone(),
            },
        );
        LiveStreamGuard {
            id,
            cancel,
            registry: Arc::clone(self),
        }
    }

    /// Number of live streams.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    fn gates(&self) -> Vec<(u64, StreamGate)> {
        self.lock()
            .iter()
            .map(|(id, entry)| (*id, entry.gate.clone()))
            .collect()
    }

    fn set_authority(&self, id: u64, authority: StreamAuthority) {
        if let Some(entry) = self.lock().get_mut(&id) {
            entry.authority = authority;
        }
    }

    /// Remove stream `id`, fire its token and count the teardown. `false`
    /// when the stream had already ended.
    fn tear_down(&self, id: u64, reason: &'static str) -> bool {
        let Some(entry) = self.lock().remove(&id) else {
            return false;
        };
        entry.cancel.cancel();
        self.diag.record_torn_down(reason);
        true
    }

    /// Snapshot for `GET /streams`.
    pub(crate) fn views(&self) -> Vec<LiveStreamView> {
        let mut views: Vec<(u64, LiveStreamView)> = self
            .lock()
            .iter()
            .map(|(id, entry)| {
                let view = match &entry.gate {
                    StreamGate::InboundAttested {
                        opener,
                        machine,
                        target,
                    } => LiveStreamView {
                        direction: "inbound",
                        peer_agent: Some(hex::encode(opener.as_bytes())),
                        peer_machine: hex::encode(machine.as_bytes()),
                        target: Some(target.to_string()),
                        authority: entry.authority.clone(),
                    },
                    StreamGate::InboundLegacy { machine, target } => LiveStreamView {
                        direction: "inbound",
                        peer_agent: None,
                        peer_machine: hex::encode(machine.as_bytes()),
                        target: Some(target.to_string()),
                        authority: entry.authority.clone(),
                    },
                    StreamGate::Outbound {
                        peer_agent,
                        machine,
                    } => LiveStreamView {
                        direction: "outbound",
                        peer_agent: Some(hex::encode(peer_agent.as_bytes())),
                        peer_machine: hex::encode(machine.as_bytes()),
                        target: None,
                        authority: entry.authority.clone(),
                    },
                };
                (*id, view)
            })
            .collect();
        views.sort_by_key(|(id, _)| *id);
        views.into_iter().map(|(_, view)| view).collect()
    }
}

/// Unix milliseconds.
pub(crate) type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock (unix ms; 0 if unreadable, which grants nothing).
pub(crate) fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    })
}

/// Everything the re-check reads: the agent's shared gate state.
pub(crate) struct ReauthCtx {
    pub discovery_cache: Arc<tokio::sync::RwLock<HashMap<AgentId, crate::DiscoveredAgent>>>,
    pub contact_store: Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    pub revocation_set: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    pub move_state: Arc<tokio::sync::RwLock<crate::key_move::MoveState>>,
    pub connect_policy: Arc<std::sync::RwLock<Arc<ConnectPolicy>>>,
    pub owner_trust: crate::owner_trust::OwnerTrust,
    pub own_machine_id: MachineId,
    pub clock: Clock,
}

fn network_reason(e: &NetworkError) -> &'static str {
    match e {
        NetworkError::PeerRevoked { .. } => "revoked",
        NetworkError::PeerNotVerified { .. } => "not_verified",
        NetworkError::PeerTrustRejected { .. } => "trust_rejected",
        NetworkError::PeerNotInConnectAcl { .. } => "agent_machine_not_in_acl",
        _ => "gate_error",
    }
}

fn connect_reason(reason: ConnectDenialReason) -> &'static str {
    match reason {
        ConnectDenialReason::UnverifiedSender => "unverified_sender",
        ConnectDenialReason::TrustRejected => "trust_rejected",
        ConnectDenialReason::ConnectDisabled => "connect_disabled",
        ConnectDenialReason::TargetNotLoopback => "target_not_loopback",
        ConnectDenialReason::AgentMachineNotInAcl => "agent_machine_not_in_acl",
        ConnectDenialReason::TargetNotAllowed => "target_not_allowed",
        ConnectDenialReason::AttestationFailed => "attestation_failed",
        ConnectDenialReason::AgentNotOnMachine => "agent_not_on_machine",
    }
}

fn denial_reason(denial: AuthzDenial) -> &'static str {
    match denial {
        AuthzDenial::Gate(reason) => connect_reason(reason),
        AuthzDenial::AgentUnknown => "not_verified",
        AuthzDenial::AgentNotOnMachine => "agent_not_on_machine",
        AuthzDenial::Revoked => "revoked",
        AuthzDenial::CertExpired => "not_verified",
        AuthzDenial::TrustRejected => "trust_rejected",
        AuthzDenial::PairingRetired => "pairing_retired",
    }
}

/// Re-run `gate` against current state. `Ok` carries the authority the
/// stream now holds; `Err` the teardown reason.
async fn reevaluate(
    gate: &StreamGate,
    ctx: &ReauthCtx,
    verify: &AttestationVerifyCtx,
    policy: &ConnectPolicy,
) -> Result<StreamAuthority, &'static str> {
    let now_secs = verify.now_ms / 1000;
    match gate {
        StreamGate::Outbound {
            peer_agent,
            machine,
        } => {
            let resolved = crate::Agent::gate_peer_outbound_at(
                &ctx.discovery_cache,
                &ctx.contact_store,
                &ctx.revocation_set,
                &ctx.move_state,
                &ctx.owner_trust,
                peer_agent,
                now_secs,
            )
            .await
            .map_err(|e| network_reason(&e))?;
            if resolved != *machine {
                return Err("machine_changed");
            }
            Ok(StreamAuthority::PeerTrust)
        }
        StreamGate::InboundAttested {
            opener,
            machine,
            target,
        } => {
            // The accept-loop gate first (every agent on the machine), then
            // the forwarder's gate for the attested opener — the same two
            // layers the stream cleared at admission.
            crate::Agent::gate_peer_machine_inbound_at(
                &ctx.discovery_cache,
                &ctx.contact_store,
                &ctx.revocation_set,
                &ctx.move_state,
                &ctx.connect_policy,
                &ctx.owner_trust,
                machine,
                now_secs,
            )
            .await
            .map_err(|e| network_reason(&e))?;
            super::authorize_attested_opener(opener, machine, target, policy, verify)
                .await
                .map_err(denial_reason)
        }
        StreamGate::InboundLegacy { machine, target } => {
            let agents = crate::Agent::gate_peer_machine_inbound_at(
                &ctx.discovery_cache,
                &ctx.contact_store,
                &ctx.revocation_set,
                &ctx.move_state,
                &ctx.connect_policy,
                &ctx.owner_trust,
                machine,
                now_secs,
            )
            .await
            .map_err(|e| network_reason(&e))?;
            for agent in &agents {
                evaluate_connect_gate(
                    true,
                    Some(TrustDecision::Accept),
                    policy,
                    agent,
                    machine,
                    target,
                )
                .map_err(connect_reason)?;
            }
            Ok(StreamAuthority::AclEntry)
        }
    }
}

/// The policy and gate context one pass evaluates against: one policy
/// snapshot and one clock reading for every stream.
fn pass_inputs(ctx: &ReauthCtx) -> (Arc<ConnectPolicy>, AttestationVerifyCtx) {
    let policy = {
        let guard = ctx
            .connect_policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&guard)
    };
    let verify = AttestationVerifyCtx {
        discovery_cache: Arc::clone(&ctx.discovery_cache),
        contact_store: Arc::clone(&ctx.contact_store),
        own_machine_id: ctx.own_machine_id,
        now_ms: (ctx.clock)(),
        revocation_set: Arc::clone(&ctx.revocation_set),
        move_state: Arc::clone(&ctx.move_state),
        owner_trust: ctx.owner_trust.clone(),
    };
    (policy, verify)
}

/// Run `gate` once against current state, as a pass would.
#[cfg(test)]
pub(crate) async fn check_gate(
    gate: &StreamGate,
    ctx: &ReauthCtx,
) -> Result<StreamAuthority, &'static str> {
    let (policy, verify) = pass_inputs(ctx);
    reevaluate(gate, ctx, &verify, &policy).await
}

/// One re-check pass over every live stream. Returns how many were torn
/// down. Streams sharing gate inputs (many connections through one forward)
/// are evaluated once per pass.
pub(crate) async fn reauth_pass(live: &LiveStreams, ctx: &ReauthCtx) -> usize {
    let entries = live.gates();
    if entries.is_empty() {
        return 0;
    }
    let (policy, verify) = pass_inputs(ctx);
    let mut verdicts: HashMap<StreamGate, Result<StreamAuthority, &'static str>> = HashMap::new();
    let mut torn_down = 0;
    for (id, gate) in entries {
        let verdict = match verdicts.get(&gate) {
            Some(verdict) => verdict.clone(),
            None => {
                let verdict = reevaluate(&gate, ctx, &verify, &policy).await;
                verdicts.insert(gate.clone(), verdict.clone());
                verdict
            }
        };
        match verdict {
            Ok(authority) => live.set_authority(id, authority),
            Err(reason) => {
                if live.tear_down(id, reason) {
                    torn_down += 1;
                    tracing::info!(
                        target: "x0x::forward",
                        ?gate,
                        reason,
                        outcome = "torn_down_reauth",
                        "live forward stream torn down: its authority is gone (ADR-0074 §4)"
                    );
                }
            }
        }
    }
    torn_down
}

/// Run re-check passes on every `kick` and every [`REAUTH_SWEEP_INTERVAL`]
/// until `stop` fires.
pub(crate) fn spawn_reauth_loop(
    live: Arc<LiveStreams>,
    ctx: ReauthCtx,
    kick: Arc<tokio::sync::Notify>,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(REAUTH_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                () = kick.notified() => {}
                _ = sweep.tick() => {}
            }
            reauth_pass(&live, &ctx).await;
            tokio::select! {
                () = stop.cancelled() => break,
                () = tokio::time::sleep(REAUTH_MIN_SPACING) => {}
            }
        }
    })
}

/// Copy both directions between a local socket's halves and a peer
/// stream's halves until both close (#961 half-close semantics), or until
/// `cancel` fires. Returns `true` when cancelled (the caller resets), `false`
/// when the bridge ended on its own.
pub(crate) async fn bridge_io<TR, TW, QR, QS>(
    tcp_read: &mut TR,
    tcp_write: &mut TW,
    recv: &mut QR,
    send: &mut QS,
    cancel: &CancellationToken,
) -> bool
where
    TR: AsyncRead + Unpin,
    TW: AsyncWrite + Unpin,
    QR: AsyncRead + Unpin,
    QS: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let to_stream = async move {
        if tokio::io::copy(tcp_read, send).await.is_ok() {
            // `SendStream::poll_shutdown` is `finish()`: queues a FIN; the
            // connection retransmits buffered data even after drop.
            let _ = send.shutdown().await;
        }
    };
    let from_stream = async move {
        if tokio::io::copy(recv, tcp_write).await.is_ok() {
            let _ = tcp_write.shutdown().await;
        }
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => true,
        _ = async { tokio::join!(to_stream, from_stream) } => false,
    }
}

/// Reset both QUIC halves of a torn-down stream.
pub(crate) fn reset_quic(
    send: &mut ant_quic::HighLevelSendStream,
    recv: &mut ant_quic::HighLevelRecvStream,
) {
    let code = ant_quic::VarInt::from_u32(REAUTH_RESET_CODE);
    // Either half may already be closed; that is not an error here.
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

/// Arrange for a torn-down local TCP socket to close with an RST.
///
/// A zero linger makes the close abortive. Tokio deprecates `set_linger`
/// because a NON-zero linger blocks the thread on drop; a zero linger never
/// blocks, it discards unsent data and sends RST.
pub(crate) fn reset_tcp(tcp: &tokio::net::TcpStream) {
    #[allow(deprecated)]
    let _ = tcp.set_linger(Some(Duration::ZERO));
}

#[cfg(test)]
mod tests;
