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
//! Local-authority re-checks use non-blocking evidence reads (`try_usable`).
//! Lock contention is not an authority deny: the pass retries with a short
//! backoff until a fresh allow/deny or the event deadline, then fail-closes
//! as `reauth_deadline` (never keeps a stale allow past the budget).
//!
//! ## When a pass runs
//!
//! **On an event** (bound ≤5 s from the triggering event). After a pass,
//! the loop waits up to [`REAUTH_MIN_SPACING`], clipped so a pending event's
//! next pass still starts by `event_at + `[`REAUTH_PASS_BUDGET`]. Each pass's
//! deadline is still `event_at + `[`REAUTH_PASS_BUDGET`]. The agent's
//! re-check signal is woken by every change to a gate input:
//!
//! | Trigger | Where the event is raised |
//! |---|---|
//! | revocation (agent, machine, binding, grant; ADR-0018/0070 v3) | `RevocationSet` on every change |
//! | ADR-0043 move (retired binding, placement record) | `RevocationSet` (tombstones), `MoveState::cache_placement` |
//! | contact trust change, `Blocked`, machine pin | `ContactStore` on every persisted change, and on every [`crate::contacts::ContactStore::get_mut`] (wakes reauth) |
//! | connect-ACL reload | [`crate::Agent::set_connect_policy`] |
//! | owner enrollment added or removed | `OwnerSyncStore::enroll` / `unenroll` |
//! | peer machine binding or certificate changed | `AuthenticatedMachineBindingCache::set_change_notify` on every retained-machine / expiry / clear mutation (DM attestation `record_authenticated_machine_binding`, announcement ingest, cert-landed); discovery also kicks via `upsert_discovered_agent` |
//!
//! **On a sweep** every [`REAUTH_SWEEP_INTERVAL`] (30 s), for the
//! triggers that are only the passage of time: grant expiry (bound ≤35 s),
//! certificate expiry, enrollment expiry and discovery-cache TTL eviction.
//! Nothing else depends on the sweep.
//!
//! ## What a teardown does
//!
//! The stream's cancellation token fires. The bridge then resets both QUIC
//! halves with [`ant_quic::high_level::DROPPED_UNFINISHED_ERROR_CODE`] (never
//! a FIN; same code as unfinished-half drops on main), closes the local TCP
//! socket with an RST, and counts the teardown in `torn_down_reauth` with
//! its reason. Reauth is distinguished locally via that counter/logs only.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use super::{
    gate_peer_machine_inbound_outcome, gate_peer_outbound_outcome, AttestationVerifyCtx,
    AuthzDenial, ForwardDiagnostics, LocalAuthorityOutcome,
};
use crate::connect::gate::ConnectDenialReason;
use crate::connect::{evaluate_connect_gate, ConnectPolicy};
use crate::error::NetworkError;
use crate::identity::{AgentId, MachineId};
use crate::trust::TrustDecision;

/// Expiry sweep period (ADR-0074 §4: "30 s sweep plus slack"). One period
/// plus [`REAUTH_MIN_SPACING`] and a pass stays inside the 35 s grant-expiry
/// bound. Only time-driven triggers rely on it; every other trigger is an
/// event.
pub(crate) const REAUTH_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum gap between two passes, so a burst of events (a revocation
/// flood, many contact writes) costs one pass per gap rather than one per
/// event.
pub(crate) const REAUTH_MIN_SPACING: Duration = Duration::from_millis(250);

/// Hard budget for one reauth pass (ADR-0074 §4 five-second bound). Local
/// authority reads should finish well under this; the deadline fail-closes
/// any stream still unchecked when it expires.
pub(crate) const REAUTH_PASS_BUDGET: Duration = Duration::from_secs(5);

/// Short pause between busy-store re-checks inside one pass. Contention
/// alone must not tear down a live stream; the pass retries until a fresh
/// verdict or [`REAUTH_PASS_BUDGET`] (engineer ruling RC7 / #1488).
const REAUTH_BUSY_BACKOFF: Duration = Duration::from_millis(25);

/// The authority a live stream holds (ADR-0074 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "principal", rename_all = "snake_case")]
pub(crate) enum StreamAuthority {
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

/// Internal snapshot of one live stream for reauth/debug (not an HTTP API).
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)] // Reserved for diagnostics; no route exposes it yet.
pub(crate) struct LiveStreamView {
    /// `inbound` or `outbound`.
    pub(crate) direction: &'static str,
    /// The peer agent (hex): the attested opener, or the outbound target.
    /// `None` for a legacy inbound stream, which is authorized per machine.
    pub(crate) peer_agent: Option<String>,
    /// The peer machine (hex).
    pub(crate) peer_machine: String,
    /// The local loopback target, for inbound streams.
    pub(crate) target: Option<String>,
    /// The authority the stream currently holds.
    pub(crate) authority: StreamAuthority,
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

    /// Snapshot of live streams for internal reauth/debug (no HTTP route).
    #[allow(dead_code)] // Reserved for diagnostics; no route exposes it yet.
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
    /// ADR 0115 announced-binding store (same Arc admission reads).
    pub announced_bindings: crate::dm_inbox::AuthenticatedMachineBindings,
    /// ADR 0115 authenticated-binding store (same Arc admission reads).
    pub authenticated_bindings: crate::dm_inbox::AuthenticatedMachineBindings,
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

/// One local-authority re-check outcome. `Busy` is lock contention on a
/// store the non-blocking path needs — not an authority deny. Busy comes
/// from the gate/authorize [`LocalAuthorityOutcome`], never from teardown
/// probing which agent might be contended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReauthCheck {
    Allow(StreamAuthority),
    Deny(&'static str),
    Busy,
}

fn map_gate_outcome<T>(outcome: LocalAuthorityOutcome<T, NetworkError>) -> Result<T, ReauthCheck> {
    match outcome {
        LocalAuthorityOutcome::Allow(v) => Ok(v),
        LocalAuthorityOutcome::Deny(e) => Err(ReauthCheck::Deny(network_reason(&e))),
        LocalAuthorityOutcome::Busy => Err(ReauthCheck::Busy),
    }
}

/// Re-run `gate` against current state once. Distinguishes authority deny
/// from evidence-store lock contention via the gate/authorize outcome.
async fn reevaluate(
    gate: &StreamGate,
    ctx: &ReauthCtx,
    verify: &AttestationVerifyCtx,
    policy: &ConnectPolicy,
) -> ReauthCheck {
    match gate {
        StreamGate::Outbound {
            peer_agent,
            machine,
        } => {
            let resolved = match map_gate_outcome(gate_peer_outbound_outcome(ctx, peer_agent).await)
            {
                Ok(resolved) => resolved,
                Err(check) => return check,
            };
            if resolved != *machine {
                return ReauthCheck::Deny("machine_changed");
            }
            ReauthCheck::Allow(StreamAuthority::PeerTrust)
        }
        StreamGate::InboundAttested {
            opener,
            machine,
            target,
        } => {
            // The accept-loop gate first (every agent on the machine), then
            // the forwarder's gate for the attested opener — the same two
            // layers the stream cleared at admission.
            // ADR-0074 §4: same local-only bound as outbound / AttestationVerifyCtx.
            if let Err(check) =
                map_gate_outcome(gate_peer_machine_inbound_outcome(ctx, machine).await)
            {
                return check;
            }
            match super::authorize_attested_opener(opener, machine, target, policy, verify).await {
                LocalAuthorityOutcome::Allow(authority) => ReauthCheck::Allow(authority),
                LocalAuthorityOutcome::Deny(denial) => ReauthCheck::Deny(denial_reason(denial)),
                LocalAuthorityOutcome::Busy => ReauthCheck::Busy,
            }
        }
        StreamGate::InboundLegacy { machine, target } => {
            let agents =
                match map_gate_outcome(gate_peer_machine_inbound_outcome(ctx, machine).await) {
                    Ok(agents) => agents,
                    Err(check) => return check,
                };
            for agent in &agents {
                if let Err(reason) = evaluate_connect_gate(
                    true,
                    Some(TrustDecision::Accept),
                    policy,
                    agent,
                    machine,
                    target,
                ) {
                    // ACL deny after a successful gate eval is a real deny
                    // (gate already returned Allow; contention would be Busy).
                    return ReauthCheck::Deny(connect_reason(reason));
                }
            }
            ReauthCheck::Allow(StreamAuthority::AclEntry)
        }
    }
}

/// Re-check until a fresh allow/deny, or the pass deadline (busy → short
/// backoff; never keep a stale allow past the deadline).
async fn reevaluate_until(
    gate: &StreamGate,
    ctx: &ReauthCtx,
    verify: &AttestationVerifyCtx,
    policy: &ConnectPolicy,
    deadline: tokio::time::Instant,
) -> Result<StreamAuthority, &'static str> {
    loop {
        match reevaluate(gate, ctx, verify, policy).await {
            ReauthCheck::Allow(authority) => return Ok(authority),
            ReauthCheck::Deny(reason) => return Err(reason),
            ReauthCheck::Busy => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err("reauth_deadline");
                }
                // No useful retry left inside the budget: fail closed now
                // rather than sleeping onto the deadline Instant (races
                // observers that use a strict EVENT_BOUND timeout).
                let remaining = deadline.saturating_duration_since(now);
                if remaining <= REAUTH_BUSY_BACKOFF {
                    return Err("reauth_deadline");
                }
                tokio::time::sleep(REAUTH_BUSY_BACKOFF).await;
            }
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
        clock: Arc::clone(&ctx.clock),
        revocation_set: Arc::clone(&ctx.revocation_set),
        move_state: Arc::clone(&ctx.move_state),
        owner_trust: ctx.owner_trust.clone(),
        // ADR-0074 §4: re-checks stay inside the five-second bound — local
        // authority only, no EvidenceV1 wait/lookup.
        local_authority_only: true,
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
    match reevaluate(gate, ctx, &verify, &policy).await {
        ReauthCheck::Allow(authority) => Ok(authority),
        ReauthCheck::Deny(reason) => Err(reason),
        // Single-shot checks have no busy retry budget.
        ReauthCheck::Busy => Err("evidence_busy"),
    }
}

/// Keep the earliest pending reauth trigger time.
fn note_reauth_event(pending: &mut Option<tokio::time::Instant>, at: tokio::time::Instant) {
    *pending = Some(match *pending {
        Some(earliest) => earliest.min(at),
        None => at,
    });
}

/// One re-check pass over every live stream. Returns how many were torn
/// down. Streams sharing gate inputs (many connections through one forward)
/// are evaluated once per pass. `deadline` is the absolute fail-closed cut-off
/// (normally the triggering event's time plus [`REAUTH_PASS_BUDGET`]); streams
/// still unchecked when it expires are torn down.
///
/// Store lock contention (`Busy`) retries with [`REAUTH_BUSY_BACKOFF`] until
/// a fresh allow/deny or the deadline — contention alone does not tear down.
pub(crate) async fn reauth_pass(
    live: &LiveStreams,
    ctx: &ReauthCtx,
    deadline: tokio::time::Instant,
) -> usize {
    let entries = live.gates();
    if entries.is_empty() {
        return 0;
    }
    let (policy, verify) = pass_inputs(ctx);
    let mut verdicts: HashMap<StreamGate, Result<StreamAuthority, &'static str>> = HashMap::new();
    let mut torn_down = 0;
    for (id, gate) in entries {
        // Cache hit always wins; the pass deadline only fails closed gates
        // that have not yet been evaluated in this pass.
        let verdict = match verdicts.get(&gate) {
            Some(verdict) => verdict.clone(),
            None if tokio::time::Instant::now() >= deadline => Err("reauth_deadline"),
            None => {
                // timeout_at still covers a blocked await (e.g. discovery
                // cache write held); Busy retries run inside and also stop
                // at `deadline` without keeping a stale allow.
                let verdict = match tokio::time::timeout_at(
                    deadline,
                    reevaluate_until(&gate, ctx, &verify, &policy, deadline),
                )
                .await
                {
                    Ok(verdict) => verdict,
                    Err(_) => Err("reauth_deadline"),
                };
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
                        torn_down_total = live.diag.torn_down_reauth(),
                        reasons = ?live.diag.torn_down_reasons(),
                        outcome = "torn_down_reauth",
                        "live forward stream torn down: its authority is gone (ADR-0074 §4)"
                    );
                }
            }
        }
    }
    torn_down
}

/// Run re-check passes on every `kick` and, when `sweep` is set, every
/// `sweep` period, until `stop` fires. Production passes
/// `Some(REAUTH_SWEEP_INTERVAL)`; `None` (tests) leaves only the events.
///
/// Each pass's deadline is measured from the earliest pending trigger
/// (`event_at + `[`REAUTH_PASS_BUDGET`]), not from pass start. Kicks that
/// arrive during an in-flight pass or the [`REAUTH_MIN_SPACING`] cooldown
/// coalesce into the earliest pending `event_at` for the next pass. The
/// post-pass cooldown is itself bounded by that pending deadline so spacing
/// cannot push the follow-up past the five-second event bound.
pub(crate) fn spawn_reauth_loop(
    live: Arc<LiveStreams>,
    ctx: ReauthCtx,
    kick: Arc<tokio::sync::Notify>,
    stop: CancellationToken,
    sweep: Option<Duration>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sweep = sweep.map(|period| {
            let mut sweep = tokio::time::interval(period);
            sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            sweep
        });
        let mut pending_event: Option<tokio::time::Instant> = None;
        loop {
            if pending_event.is_none() {
                let tick = async {
                    match sweep.as_mut() {
                        Some(sweep) => {
                            sweep.tick().await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    () = stop.cancelled() => break,
                    () = kick.notified() => {
                        note_reauth_event(&mut pending_event, tokio::time::Instant::now());
                    }
                    () = tick => {
                        note_reauth_event(&mut pending_event, tokio::time::Instant::now());
                    }
                }
            }
            let Some(event_at) = pending_event.take() else {
                break;
            };
            let deadline = event_at + REAUTH_PASS_BUDGET;
            {
                let pass = reauth_pass(&live, &ctx, deadline);
                tokio::pin!(pass);
                loop {
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => return,
                        () = kick.notified() => {
                            note_reauth_event(
                                &mut pending_event,
                                tokio::time::Instant::now(),
                            );
                        }
                        _ = &mut pass => break,
                    }
                }
            }
            {
                // Bound cooldown by the earliest pending event deadline so
                // pass_remainder + REAUTH_MIN_SPACING cannot exceed the
                // ADR-0074 5 s bound measured from that event.
                let now = tokio::time::Instant::now();
                let spacing_deadline = pending_event
                    .map(|event_at| event_at + REAUTH_PASS_BUDGET)
                    .unwrap_or_else(|| now + REAUTH_MIN_SPACING);
                let spacing_until = spacing_deadline.min(now + REAUTH_MIN_SPACING);
                let spacing = tokio::time::sleep_until(spacing_until);
                tokio::pin!(spacing);
                loop {
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => return,
                        () = kick.notified() => {
                            note_reauth_event(
                                &mut pending_event,
                                tokio::time::Instant::now(),
                            );
                        }
                        () = &mut spacing => break,
                    }
                }
            }
        }
    })
}

/// Copy both directions between a local socket's halves and a peer
/// stream's halves until both close (#961 half-close semantics), or until
/// `cancel` fires or a copy/shutdown errors.
///
/// Returns `true` when cancelled or when either direction fails (the caller
/// resets both halves — ADR-0074 teardown bound for remote reauth). Returns
/// `false` when both directions complete cleanly. A clean EOF on one side
/// still finishes that writer and lets the other direction keep flowing
/// until it also completes or errors.
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
        tokio::io::copy(tcp_read, send).await?;
        // `SendStream::poll_shutdown` is `finish()`: queues a FIN; the
        // connection retransmits buffered data even after drop.
        send.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };
    let from_stream = async move {
        tokio::io::copy(recv, tcp_write).await?;
        tcp_write.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => true,
        // try_join: first Err cancels/drops the other future so both halves
        // tear down instead of join! waiting on an idle peer forever.
        result = async { tokio::try_join!(to_stream, from_stream) } => {
            // Ok = both halves clean; Err = copy/shutdown failed → tear down.
            result.is_err()
        }
    }
}

/// Reset both QUIC halves of a torn-down stream.
///
/// Uses the same application error as main's forward deny path when dropping
/// unfinished halves ([`ant_quic::high_level::DROPPED_UNFINISHED_ERROR_CODE`],
/// ADR 0022). Reauth teardowns are distinguished locally via
/// `torn_down_reauth` counters/logs only — no new wire-visible code.
pub(crate) fn reset_quic(
    send: &mut crate::network::StreamSend,
    recv: &mut crate::network::StreamRecv,
) {
    let code = ant_quic::high_level::DROPPED_UNFINISHED_ERROR_CODE;
    // Either half may already be closed; that is not an error here.
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

/// Arrange for a torn-down local TCP socket to close with an RST.
///
/// A zero linger makes the close abortive. Tokio deprecates `set_linger`
/// because a NON-zero linger blocks the thread on drop; a zero linger never
/// blocks, it discards unsent data and sends RST. Accepts a full stream or
/// an owned half (`AsRef<TcpStream>`).
pub(crate) fn reset_tcp(tcp: &impl AsRef<tokio::net::TcpStream>) {
    #[allow(deprecated)]
    let _ = tcp.as_ref().set_linger(Some(Duration::ZERO));
}

/// A pre-bridge wait that lost the race against reauth cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cancelled;

/// Race `fut` against `cancel` (ADR-0074 §4). Used for every pre-bridge
/// wait — header write, response read, local connect, response write — so
/// a stalled peer cannot keep sockets and permits alive after teardown.
pub(crate) async fn wait_cancellable<T, F>(
    cancel: &CancellationToken,
    fut: F,
) -> Result<T, Cancelled>
where
    F: std::future::Future<Output = T>,
{
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Cancelled),
        result = fut => Ok(result),
    }
}

/// ADR-0074 §4 deny during the connect/header/response window: reset both
/// QUIC halves with [`ant_quic::high_level::DROPPED_UNFINISHED_ERROR_CODE`]
/// (same code as unfinished-half drops on main) and RST the local TCP when
/// present. Reauth vs other denies is local-only (`torn_down_reauth`).
///
/// Takes [`PeerStream`] so the send and recv borrows are sequential (not
/// overlapping in one call expression).
pub(crate) fn deny_pre_bridge(
    stream: &mut crate::streams::PeerStream,
    tcp: Option<&tokio::net::TcpStream>,
) {
    let code = ant_quic::high_level::DROPPED_UNFINISHED_ERROR_CODE;
    let _ = stream.send_mut().reset(code);
    let _ = stream.recv_mut().stop(code);
    if let Some(tcp) = tcp {
        reset_tcp(tcp);
    }
}

#[cfg(test)]
mod tests;
