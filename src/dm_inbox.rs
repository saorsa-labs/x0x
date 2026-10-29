//! Runtime service that consumes this agent's inbox topic, runs the
//! signature-first pipeline from `docs/design/dm-over-gossip.md`, and
//! bridges decrypted payloads into [`crate::direct::DirectMessaging`].

use crate::contacts::ContactStore;
use crate::direct::DirectMessaging;
use crate::dm::{
    decrypt_payload, dm_inbox_topic, now_unix_ms, validate_timestamp_window, DmAckOutcome, DmBody,
    DmEnvelope, DmOriginAttestation, DmPayload, EnvelopeBuilder, InFlightAcks, RecentDeliveryCache,
    DM_PROTOCOL_DURABLE_ACK, DM_PROTOCOL_V1, DM_PROTOCOL_VERSION, MAX_ENVELOPE_BYTES,
};
use crate::error::{NetworkError, NetworkResult};
use crate::gossip::{PubSubManager, PubSubMessage, SigningContext, Subscription};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::identity::{AgentId, MachineId, MachineKeypair};
use crate::network::NetworkNode;
use crate::revocation::RevocationSet;
use crate::trust::{TrustContext, TrustDecision, TrustEvaluator};
use async_trait::async_trait;
use bytes::Bytes;
use saorsa_gossip_types::TopicId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::{JoinHandle, JoinSet};

const ACK_ENVELOPE_LIFETIME_MS: u64 = 60_000;
/// The pinned pubsub Critical-priority contract permits ten seconds waiting
/// at its FIFO gate plus ten seconds for the send itself. Keep each durable
/// ACK route alive for that complete healthy-congestion budget plus slack.
const DURABLE_ACK_ROUTE_TIMEOUT: Duration = Duration::from_secs(22);
/// ACK envelopes are small, but the queue is bounded so a disconnected mesh
/// cannot turn sender retries into unbounded retained work.
const DURABLE_ACK_QUEUE_CAPACITY: usize = 256;
/// Bound the number of ACK jobs simultaneously holding pubsub fan-out work.
const DURABLE_ACK_MAX_CONCURRENT: usize = 32;
/// Shared with the daemon's predecessor listener. A literal prefix alone is
/// ordinary DM text until the suffix is a verified signed pubsub envelope.
pub const GROUP_PREDECESSOR_RELAY_DM_PREFIX: &[u8] = b"X0X-GROUP-PREDECESSOR-RELAY-V1\n";

/// The byte prefixes production registers as typed-DM routes when the DM
/// inbox starts (`start_dm_inbox_when_gossip_ready`). The raw-QUIC dispatch
/// consults this table for UNVERIFIED frames even BEFORE the inbox exists
/// (N12: the raw listener starts earlier and passes an empty route list —
/// without this, the startup window would re-open the user-DM leak).
///
/// `PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX` is defined in the server layer; its
/// literal is repeated here and pinned equal by a server-side test.
pub(crate) const PRODUCTION_TYPED_DM_PREFIXES: [&[u8]; 9] = [
    crate::exec::EXEC_DM_PREFIX,
    GROUP_PREDECESSOR_RELAY_DM_PREFIX,
    crate::share_grant::SHARE_GRANT_DM_PREFIX,
    crate::history::classify::GROUP_PUBLIC_MESSAGE_DM_PREFIX,
    crate::history::classify::KV_STORE_DELTA_DM_PREFIX,
    b"X0X-PUBLIC-GROUP-BOOTSTRAP-V2\n",
    crate::gui::remote::SHOW_REQUEST_PREFIX,
    crate::gui::remote::SHOW_RESULT_PREFIX,
    crate::gui::remote::ACTIVITY_PREFIX,
];

/// Whether these bytes claim one of the production typed-DM protocols
/// (prefix match only — recognition, not validation).
pub(crate) fn recognized_production_typed_prefix(payload: &[u8]) -> bool {
    PRODUCTION_TYPED_DM_PREFIXES
        .iter()
        .any(|prefix| payload.starts_with(prefix))
}
const PREDECESSOR_RELAY_MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// Outcome of the C5 live Direct/typed ACK hedge.
///
/// Direct send-ok is never a sender receipt. The waiter completes only when
/// the same v2 envelope arrives and matches `acks_request_id`. Missing Direct
/// is fail-open so the inbox + compatibility-bus gossip hedges still count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectAckHedgeOutcome {
    Sent,
    SkippedNoDirect,
    Failed,
}

/// Send the already-committed v2 ACK envelope on a live Direct/typed path.
///
/// Implementations must not treat a successful send as waiter completion and
/// must not fail the durable ACK when no Direct connection exists.
#[async_trait]
pub(crate) trait DirectAckHedge: Send + Sync {
    async fn hedge(&self, recipient: AgentId, encoded: Bytes) -> DirectAckHedgeOutcome;
}

/// Production C5 hedge: send the same v2 ACK envelope on live Direct/typed.
pub(crate) struct LiveDirectAckHedge {
    pub network: Arc<NetworkNode>,
    pub dm: Arc<DirectMessaging>,
    pub sender_agent_id: AgentId,
}

#[async_trait]
impl DirectAckHedge for LiveDirectAckHedge {
    async fn hedge(&self, recipient: AgentId, encoded: Bytes) -> DirectAckHedgeOutcome {
        let Some(machine) = self.dm.get_machine_id(&recipient).await else {
            return DirectAckHedgeOutcome::SkippedNoDirect;
        };
        let peer = ant_quic::PeerId(machine.0);
        if !self.network.is_connected(&peer).await {
            return DirectAckHedgeOutcome::SkippedNoDirect;
        }
        match self
            .network
            .send_direct(&peer, self.sender_agent_id.as_bytes(), encoded.as_ref())
            .await
        {
            Ok(()) => DirectAckHedgeOutcome::Sent,
            Err(_) => DirectAckHedgeOutcome::Failed,
        }
    }
}

/// How long the durable path waits for a typed-route handler to report
/// completion before withholding the ACK (ADR 0030 §7).
///
/// Deliberately shorter than the sender's per-attempt budget
/// (`DM_TIMEOUT_MAX_MS`, 30 s): waiting longer than the sender will wait can
/// only pin this receiver on an ACK nobody is still listening for. The
/// campaign draft instead waited out the envelope's remaining lifetime — up
/// to 120 s — inline on the serial inbox loop, which would stall every later
/// DM and ACK behind one slow handler. The budget is a receiver-side
/// liveness bound, not a correctness one: timing out withholds the ACK, and
/// the sender retries.
const DURABLE_TYPED_COMPLETION_TIMEOUT: Duration = Duration::from_secs(20);

const AUTHENTICATED_MACHINE_BINDING_CAPACITY: usize = 65_536;
/// #1659: verified machines remembered for one agent. One more marks that
/// agent overflowed and does not grow the set.
const ACCEPTED_MACHINES_PER_AGENT: usize = 8;
/// #1659: (agent, machine) pairs in one cache. The cap is three shares:
/// Trusted or Known contacts, protected non-contacts, and strangers.
const ACCEPTED_MACHINE_PAIR_CAPACITY: usize = 65_536;
/// Stranger share of [`ACCEPTED_MACHINE_PAIR_CAPACITY`]. A new stranger
/// pair evicts the least-recently used stranger pair that is not pinned.
/// A revoked machine is pinned, up to 2 per agent. The share also caps
/// those pins at [`STRANGER_REVOKED_PIN_CAP`], so a flood of self-issued
/// revocations cannot pin every slot. Eviction pins a revoked pair that
/// is not yet a pin when the cap and the per-agent limit both have room,
/// including a pair recorded clean and revoked later. A later revoked
/// pair does not replace a pin already held. A pin is never evicted to
/// make room. Leaving the stranger share releases that agent's pins.
/// A revoked pair that does not fit is remembered, up to this share's
/// size and 8 machines for one agent. The oldest of those records is
/// forgotten. A clean stranger pair can still be evicted. Those losses
/// are residuals. An unknown revocation answer is not evicted. It does
/// not evict a contact pair or a protected non-contact pair. This share
/// stays reserved when the other shares are full.
const ACCEPTED_MACHINE_STRANGER_PAIRS: usize = 4_096;
/// Confirmed revoked pairs that stay pinned in the stranger share.
/// Half of [`ACCEPTED_MACHINE_STRANGER_PAIRS`]. A smaller stranger share
/// uses half of that share. A revoked pair is pinned when this cap and
/// the per-agent limit both have room. The inbox never evicts a pin.
/// When the cap is full, an unattested DM or ACK is refused only for an
/// agent who still has a dropped or unpinned revoked pair. A sender with
/// no such record keeps ADR 0021 policy. A contact or a protected
/// non-contact is not refused for the cap. The pins and those records
/// are process memory. A restart drops them.
const STRANGER_REVOKED_PIN_CAP: usize = ACCEPTED_MACHINE_STRANGER_PAIRS / 2;
/// Protected non-contact share of [`ACCEPTED_MACHINE_PAIR_CAPACITY`].
/// A member of a group whose admission needs an invite or approval, or a
/// verified grantor or grantee, uses this share when that peer is not a
/// Trusted or Known contact. OpenJoin membership does not. An agent that
/// is only listed in a received grant does not. A new pair past this share
/// evicts the least-recently used pair in this share that is not a pinned
/// revoked machine. One protected agent can pin 2 revoked machines. It does not take
/// a contact pair.
const ACCEPTED_MACHINE_PROTECTED_PAIRS: usize = 16_384;
/// #1659: agents that can be named as overflowed. A further agent is
/// counted and is not a reason to refuse any other sender.
const ACCEPTED_MACHINE_OVERFLOW_AGENTS: usize = 4_096;
/// Minimum gap between unattested-drop and attribution-cap warnings.
/// A flood must not emit one `warn!` per DM. The gap is per sender, so
/// one sender cannot mask the warning for another. A sender past
/// [`UNATTESTED_WARN_SENDERS`] shares one interval.
const UNATTESTED_DROP_WARN_INTERVAL_MS: u64 = 60_000;
/// Senders remembered for that per-sender gap. A further sender shares
/// one interval while every remembered interval is still open. A slot
/// whose interval has expired is reused. A live slot is not taken.
const UNATTESTED_WARN_SENDERS: usize = 256;
/// Agents whose standing epoch is remembered. Each standing write takes
/// the next value from a process-wide clock. Eviction does not reuse that
/// generation. A further agent evicts the oldest stranger epoch, then the
/// oldest protected epoch. A contact epoch is evicted only when no other
/// epoch remains. Evicting an epoch does not drop machine attribution.
const RELATIONSHIP_EPOCH_CAPACITY: usize = 8_192;
/// Revoked machines one agent can pin in the protected share, the stranger
/// share, or a contact promotion. Eviction takes a non-revoked pair first
/// and does not drop a pinned pair. A further revoked machine for that
/// agent can be evicted. Two covers the machine just revoked and one
/// earlier revocation. The pin needs the revocation probe `x0xd` installs.
const PINNED_REVOKED_MACHINES_PER_AGENT: usize = 2;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticatedMachineBinding {
    pub(crate) machine_id: MachineId,
    pub(crate) announced_at: u64,
    pub(crate) cert_not_after: Option<u64>,
    /// x0x #1150 (r7e): the certificate digest the recorded announcement
    /// committed to, in the announced-binding store; `cert_not_after` is that
    /// certificate's expiry. Always `None` in the authenticated-binding store.
    pub(crate) cert_digest: Option<[u8; 32]>,
    last_used: (std::time::Instant, u64),
}

/// Group, grant, or contact check for attribution.
///
/// `Some(true)` means the peer is a protected non-contact: a member of a
/// group whose admission needs an invite or approval, or a grant party.
/// OpenJoin membership is not protection. `Some(false)` means the peer is
/// a stranger unless the caller also has a Trusted or Known contact.
/// `None` means the check could not run; callers keep the standing already
/// stored. The closure must not lock this cache.
#[derive(Clone)]
pub(crate) struct AttributionRelationshipProbe {
    inner: std::sync::Arc<dyn Fn(AgentId) -> Option<bool> + Send + Sync>,
}

impl std::fmt::Debug for AttributionRelationshipProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttributionRelationshipProbe")
    }
}

impl AttributionRelationshipProbe {
    /// Test probe that always answers. Production installs [`Self::from_answer`].
    #[cfg(test)]
    pub(crate) fn from_fn(probe: impl Fn(AgentId) -> bool + Send + Sync + 'static) -> Self {
        Self::from_answer(move |agent_id| Some(probe(agent_id)))
    }

    pub(crate) fn from_answer(
        probe: impl Fn(AgentId) -> Option<bool> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(probe),
        }
    }

    fn answer(&self, agent_id: AgentId) -> Option<bool> {
        (self.inner)(agent_id)
    }
}

/// Whether a machine is revoked. Used only to pin protected-share pairs.
/// The closure must not lock this cache. `x0xd` installs it.
///
/// `Some(true)` is a confirmed revocation and counts toward the per-agent
/// pin. `Some(false)` is a confirmed clean machine and can be evicted.
/// `None` is an unknown answer, including a busy revocation lock. An
/// unknown pair cannot be evicted, and it does not count as a confirmed
/// newer revocation.
#[derive(Clone)]
struct RevokedMachineProbe {
    inner: std::sync::Arc<dyn Fn(MachineId) -> Option<bool> + Send + Sync>,
}

impl std::fmt::Debug for RevokedMachineProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RevokedMachineProbe")
    }
}

/// Pin decision for one accepted pair.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RevocationPin {
    /// Confirmed revoked. Counts toward the two newer pins for this agent.
    Revoked,
    /// Confirmed not revoked. Eviction may drop the pair.
    Clean,
    /// The probe could not answer. Eviction must leave the pair in place,
    /// and the pair must not count as a confirmed revocation.
    Unknown,
}

impl RevokedMachineProbe {
    fn from_fn(probe: impl Fn(MachineId) -> Option<bool> + Send + Sync + 'static) -> Self {
        Self {
            inner: std::sync::Arc::new(probe),
        }
    }

    fn answer(&self, machine_id: &MachineId) -> Option<bool> {
        (self.inner)(*machine_id)
    }
}

/// Who pays for an attributed pair inside the 65,536 cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributionStanding {
    /// Trusted or Known contact. Pairs use the contact share.
    Contact,
    /// Invite-or-approval group member, or a grant party, who is not a contact.
    /// Pairs use the protected share.
    Protected,
    /// Everyone else, including an OpenJoin co-member. Pairs use the stranger share.
    Stranger,
}

/// What the relationship probe returned before a standing is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributionProbeView {
    /// No probe is installed. A library embedder without `x0xd` is this case.
    /// Only a Trusted or Known contact is protected.
    Absent,
    /// The probe could not answer. Keep the standing already stored.
    Unknown,
    /// Group admission needs an invite or approval, or a grant is live.
    Related,
    /// The probe ran and the peer is not a protected non-contact.
    Unrelated,
}

/// Contact trust wins. A definite probe answer is next. An unknown answer
/// keeps `current`, including contact protection that a busy lock must not clear.
pub(crate) fn standing_from_probe(
    contact: bool,
    probe: AttributionProbeView,
    current: AttributionStanding,
) -> AttributionStanding {
    if contact {
        return AttributionStanding::Contact;
    }
    match probe {
        AttributionProbeView::Related => AttributionStanding::Protected,
        AttributionProbeView::Unrelated | AttributionProbeView::Absent => {
            AttributionStanding::Stranger
        }
        AttributionProbeView::Unknown => current,
    }
}

pub(crate) fn probe_view(
    probe: Option<&AttributionRelationshipProbe>,
    agent_id: AgentId,
) -> AttributionProbeView {
    match probe {
        None => AttributionProbeView::Absent,
        Some(probe) => match probe.answer(agent_id) {
            Some(true) => AttributionProbeView::Related,
            Some(false) => AttributionProbeView::Unrelated,
            None => AttributionProbeView::Unknown,
        },
    }
}

/// Bounded LRU cache of authenticated agent→machine bindings.
///
/// Bindings survive reachability-cache eviction and are refreshed by accepted
/// identity announcements and inbound DMs. At the generous capacity ceiling,
/// the least-recently-used binding is evicted and every eviction is logged;
/// subsequent DMs from that agent degrade to the observable claim fallback.
///
/// When `set_change_notify` is installed, every mutation that changes
/// a retained machine, its expiry metadata, or drops a binding (clear /
/// eviction) wakes ADR-0074 §4 stream reauth — including the DM attestation
/// writer `record_authenticated_machine_binding`.
///
/// `accepted_machines` is the #1659 attribution memory. An identity
/// announcement records its machine when the announcement is accepted. A
/// DM records its machine only after decryption succeeds. An ACK records
/// its machine only after the trust check admits it and a waiter matches.
/// The set includes the retained binding, a machine a later binding
/// replaced, and a verified machine that lost timestamp selection. Evicting
/// a retained binding does not drop the set. The 65,536 pairs are three
/// shares. Trusted or Known contacts use the remainder after the other two
/// shares. Protected non-contacts (a group whose admission needs an invite
/// or approval, or a grant party) use 16,384 pairs. Strangers, including
/// OpenJoin co-members, use 4,096 pairs. A new pair past a non-contact
/// share evicts the least-recently used pair in that share. It does not
/// evict a contact pair. The stranger share stays reserved when the other
/// shares are full. A stranger flood that evicts a clean stranger pair, or
/// a revoked pair past the share pin cap, or a dropped-pair record past
/// the stranger share, is a residual. A revoked stranger pin stays, up to
/// 2 per agent and up to half the stranger share. Eviction pins a revoked
/// pair when both limits have room. Dropped-pair records are capped at
/// the stranger share, at most 8 machines for one agent.
/// Standing is chosen again on every record and on every contact
/// change. Dropping or downgrading a contact keeps protection that still
/// comes from a qualifying group or a grant. One agent can record 8
/// machines. A further machine is not recorded while the agent is at that
/// cap. After an eviction frees a slot, a later admitted machine is
/// recorded again. A machine past the per-agent cap is not recorded. That
/// loss of attribution is a residual. The set is process memory. A restart,
/// including a self-update restart, drops it. An undecryptable DM can move
/// the retained binding and does not admit that machine. A later DM or
/// ACK that is admitted through that retained binding records it.
/// Relationship epochs are capped at 8,192 agents. Each standing write
/// takes the next process-wide generation. Eviction does not reuse it.
/// A missing epoch reads the stored high-water mark of evicted epochs,
/// not the live clock. That mark is 0 until an epoch is evicted. A
/// protected peer is removed when its last accepted machine is gone and
/// its relationship epoch is gone. A protected agent's revoked machines
/// are pinned, up to 2 per agent, when the revocation probe confirms the
/// revocation. A stranger agent's revoked machines use the same per-agent
/// limit and a share cap of half the stranger share. A pin is never
/// evicted. Eviction pins a revoked pair when both limits have room.
/// A later revoked pair does not replace a pin. Leaving the stranger
/// share releases that agent's pins. A revoked pair that does not fit
/// is remembered only up to the stranger share size, and that agent is
/// refused only while the cap stays full and the record remains. A
/// restart drops the pins and those records. Contact
/// promotion and demotion keep the 2 newest revoked machines that fit.
/// An unknown answer does not evict
/// that pair and does not count as a confirmed revocation. Unknown pairs
/// that do not fit a contact promotion are dropped. A move into the
/// protected share that cannot fit those pairs is refused, and the pairs
/// stay in the share they already use.
#[derive(Debug)]
pub struct AuthenticatedMachineBindingCache {
    entries: std::collections::HashMap<AgentId, AuthenticatedMachineBinding>,
    by_machine: std::collections::BTreeSet<([u8; 32], [u8; 32])>,
    /// Machines accepted for each agent, including machines a later binding
    /// replaced (#1659). Not removed by LRU eviction. Bounded.
    accepted_machines: std::collections::HashMap<AgentId, std::collections::HashSet<MachineId>>,
    /// Agents whose verified history did not fit in the per-agent or pair cap.
    /// A machine past the cap is not in `accepted_machines`.
    overflowed_agents: std::collections::HashSet<AgentId>,
    /// Trusted or Known contacts. Their pairs use the contact share.
    contact_peers: std::collections::HashSet<AgentId>,
    /// Protected non-contacts. Their pairs use the protected share.
    protected_peers: std::collections::HashSet<AgentId>,
    /// Process-wide standing generation. A stale resolve does not overwrite it.
    /// A missing agent reads [`Self::evicted_epoch_high_water`], which is 0
    /// until an epoch is evicted. Bounded at 8,192 agents.
    relationship_epochs: std::collections::HashMap<AgentId, u64>,
    relationship_epoch_order: std::collections::BTreeSet<(u64, [u8; 32])>,
    relationship_epoch_index: std::collections::HashMap<AgentId, u64>,
    relationship_epoch_clock: u64,
    /// Clock value at the last epoch eviction. A missing epoch reads this,
    /// not [`Self::relationship_epoch_clock`]. It stays 0 until an eviction.
    evicted_epoch_high_water: u64,
    relationship_epoch_cap: usize,
    /// Group and grant check. Absent means only a contact is protected.
    relationship_probe: Option<AttributionRelationshipProbe>,
    /// `Some` when `x0xd` has installed the revocation check used to pin
    /// revoked machines in the protected share. Absent means nothing is pinned.
    revoked_machine_probe: Option<RevokedMachineProbe>,
    attribution_pairs_len: usize,
    attribution_stranger_pairs_len: usize,
    attribution_protected_pairs_len: usize,
    attribution_per_agent: usize,
    attribution_pairs: usize,
    attribution_stranger_pairs: usize,
    attribution_protected_pairs: usize,
    attribution_overflow_agents: usize,
    /// Agents that overflowed after the name list was full.
    attribution_unnamed_overflows: u64,
    /// Stranger pairs the LRU dropped, plus an insert refused when no
    /// stranger pair could be dropped.
    attribution_stranger_overflows: u64,
    /// Last attribution-cap warning, monotonic milliseconds. One cache.
    attribution_overflow_warn_ms: u64,
    /// Least-recently used stranger pairs. Contacts and protected peers are not in this order.
    stranger_order: std::collections::BTreeSet<(u64, [u8; 32], [u8; 32])>,
    stranger_index: std::collections::HashMap<([u8; 32], [u8; 32]), u64>,
    stranger_clock: u64,
    /// Revoked stranger pairs that stay. Eviction does not remove one.
    stranger_revoked_pins: std::collections::HashSet<([u8; 32], [u8; 32])>,
    /// Pins grouped by agent. At most [`PINNED_REVOKED_MACHINES_PER_AGENT`].
    /// A count does not scan [`Self::stranger_revoked_pins`].
    stranger_pins_by_agent:
        std::collections::HashMap<AgentId, std::collections::HashSet<MachineId>>,
    /// Oldest-first records of revoked pairs that were dropped or could not
    /// be pinned. Capped at the stranger share size.
    revoked_unpinned_order: std::collections::BTreeSet<(u64, [u8; 32], [u8; 32])>,
    /// `(agent, machine)` to its order clock. Removal is one lookup.
    revoked_unpinned_index: std::collections::HashMap<([u8; 32], [u8; 32]), u64>,
    /// Machines in [`Self::revoked_unpinned_index`], grouped by agent.
    /// At most [`ACCEPTED_MACHINES_PER_AGENT`] per agent. An empty set is
    /// removed. The refusal check does not scan the whole index.
    revoked_unpinned_by_agent:
        std::collections::HashMap<AgentId, std::collections::HashSet<MachineId>>,
    revoked_unpinned_clock: u64,
    /// Accept order for every share, including contacts. Demotion and
    /// promotion use it so the newest revoked pairs stay.
    pair_recency: std::collections::HashMap<([u8; 32], [u8; 32]), u64>,
    pair_recency_clock: u64,
    /// Least-recently used protected non-contact pairs.
    protected_order: std::collections::BTreeSet<(u64, [u8; 32], [u8; 32])>,
    protected_index: std::collections::HashMap<([u8; 32], [u8; 32]), u64>,
    protected_clock: u64,
    capacity: usize,
    recency: std::collections::BTreeSet<(std::time::Instant, u64, [u8; 32])>,
    clock: u64,
    /// ADR-0074 §4: wake open-stream reauth after a retained-machine change.
    change_notify: Option<std::sync::Arc<tokio::sync::Notify>>,
}

impl Default for AuthenticatedMachineBindingCache {
    fn default() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            by_machine: Default::default(),
            accepted_machines: std::collections::HashMap::new(),
            overflowed_agents: std::collections::HashSet::new(),
            contact_peers: std::collections::HashSet::new(),
            protected_peers: std::collections::HashSet::new(),
            relationship_epochs: std::collections::HashMap::new(),
            relationship_epoch_order: std::collections::BTreeSet::new(),
            relationship_epoch_index: std::collections::HashMap::new(),
            relationship_epoch_clock: 0,
            evicted_epoch_high_water: 0,
            relationship_epoch_cap: RELATIONSHIP_EPOCH_CAPACITY,
            relationship_probe: None,
            revoked_machine_probe: None,
            attribution_pairs_len: 0,
            attribution_stranger_pairs_len: 0,
            attribution_protected_pairs_len: 0,
            attribution_per_agent: ACCEPTED_MACHINES_PER_AGENT,
            attribution_pairs: ACCEPTED_MACHINE_PAIR_CAPACITY,
            attribution_stranger_pairs: ACCEPTED_MACHINE_STRANGER_PAIRS,
            attribution_protected_pairs: ACCEPTED_MACHINE_PROTECTED_PAIRS,
            attribution_overflow_agents: ACCEPTED_MACHINE_OVERFLOW_AGENTS,
            attribution_unnamed_overflows: 0,
            attribution_stranger_overflows: 0,
            attribution_overflow_warn_ms: 0,
            stranger_order: std::collections::BTreeSet::new(),
            stranger_index: std::collections::HashMap::new(),
            stranger_clock: 0,
            stranger_revoked_pins: std::collections::HashSet::new(),
            stranger_pins_by_agent: std::collections::HashMap::new(),
            revoked_unpinned_order: std::collections::BTreeSet::new(),
            revoked_unpinned_index: std::collections::HashMap::new(),
            revoked_unpinned_by_agent: std::collections::HashMap::new(),
            revoked_unpinned_clock: 0,
            pair_recency: std::collections::HashMap::new(),
            pair_recency_clock: 0,
            protected_order: std::collections::BTreeSet::new(),
            protected_index: std::collections::HashMap::new(),
            protected_clock: 0,
            recency: std::collections::BTreeSet::new(),
            capacity: AUTHENTICATED_MACHINE_BINDING_CAPACITY,
            clock: 0,
            change_notify: None,
        }
    }
}

impl AuthenticatedMachineBindingCache {
    /// Indexed routing candidates only; authority is rechecked at point of use.
    pub(crate) fn agents_on_machine(&self, machine: MachineId, limit: usize) -> Vec<AgentId> {
        self.by_machine
            .range((machine.0, [0; 32])..=(machine.0, [255; 32]))
            .take(limit)
            .map(|(_, agent)| AgentId(*agent))
            .collect()
    }

    #[cfg(test)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            by_machine: Default::default(),
            accepted_machines: std::collections::HashMap::new(),
            overflowed_agents: std::collections::HashSet::new(),
            contact_peers: std::collections::HashSet::new(),
            protected_peers: std::collections::HashSet::new(),
            relationship_epochs: std::collections::HashMap::new(),
            relationship_epoch_order: std::collections::BTreeSet::new(),
            relationship_epoch_index: std::collections::HashMap::new(),
            relationship_epoch_clock: 0,
            evicted_epoch_high_water: 0,
            relationship_epoch_cap: RELATIONSHIP_EPOCH_CAPACITY,
            relationship_probe: None,
            revoked_machine_probe: None,
            attribution_pairs_len: 0,
            attribution_stranger_pairs_len: 0,
            attribution_protected_pairs_len: 0,
            attribution_per_agent: ACCEPTED_MACHINES_PER_AGENT,
            attribution_pairs: ACCEPTED_MACHINE_PAIR_CAPACITY,
            attribution_stranger_pairs: ACCEPTED_MACHINE_STRANGER_PAIRS,
            attribution_protected_pairs: ACCEPTED_MACHINE_PROTECTED_PAIRS,
            attribution_overflow_agents: ACCEPTED_MACHINE_OVERFLOW_AGENTS,
            attribution_unnamed_overflows: 0,
            attribution_stranger_overflows: 0,
            attribution_overflow_warn_ms: 0,
            stranger_order: std::collections::BTreeSet::new(),
            stranger_index: std::collections::HashMap::new(),
            stranger_clock: 0,
            stranger_revoked_pins: std::collections::HashSet::new(),
            stranger_pins_by_agent: std::collections::HashMap::new(),
            revoked_unpinned_order: std::collections::BTreeSet::new(),
            revoked_unpinned_index: std::collections::HashMap::new(),
            revoked_unpinned_by_agent: std::collections::HashMap::new(),
            revoked_unpinned_clock: 0,
            pair_recency: std::collections::HashMap::new(),
            pair_recency_clock: 0,
            protected_order: std::collections::BTreeSet::new(),
            protected_index: std::collections::HashMap::new(),
            protected_clock: 0,
            recency: std::collections::BTreeSet::new(),
            capacity: capacity.max(1),
            clock: 0,
            change_notify: None,
        }
    }

    #[cfg(test)]
    fn with_attribution_limits(
        mut self,
        per_agent: usize,
        pairs: usize,
        overflow_agents: usize,
    ) -> Self {
        self.set_attribution_limits_for_test(per_agent, pairs, overflow_agents);
        self
    }

    /// Lower the #1659 caps. Call this before any `record`. Limits below 1
    /// become 1.
    #[cfg(test)]
    pub(crate) fn set_attribution_limits_for_test(
        &mut self,
        per_agent: usize,
        pairs: usize,
        overflow_agents: usize,
    ) {
        self.attribution_per_agent = per_agent.max(1);
        self.attribution_pairs = pairs.max(1);
        self.attribution_overflow_agents = overflow_agents.max(1);
        // A lowered pair cap in tests is a contact-and-stranger budget.
        // The protected share is set with its own helper so it does not
        // consume the contact remainder.
        self.attribution_protected_pairs = 0;
    }

    /// Machines this cache has accepted for `agent_id`.
    ///
    /// The retained binding is one of them. A machine a later update replaced
    /// stays in the list. #1659 uses the list so a machine revocation remains
    /// attributable after the retained binding moves.
    pub(crate) fn machines_accepted_for(&self, agent_id: &AgentId) -> Vec<MachineId> {
        self.accepted_machines
            .get(agent_id)
            .map(|machines| machines.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Whether this agent's per-agent or pair cap refused another machine.
    ///
    /// A `true` result does not by itself refuse an unattested DM. Machines
    /// past the cap are absent from [`Self::machines_accepted_for`].
    pub(crate) fn attribution_requires_attestation(&self, agent_id: &AgentId) -> bool {
        self.overflowed_agents.contains(agent_id)
    }

    /// Mark or clear contact protection for `agent_id`.
    ///
    /// `true` is the contact share. `false` moves that agent's pairs into
    /// the stranger share, which may evict the least-recently used stranger
    /// pair. A group or grant that should survive a contact downgrade uses
    /// [`with_contact_standing`].
    pub(crate) fn set_relationship_peer(&mut self, agent_id: AgentId, relationship: bool) {
        self.set_standing(
            agent_id,
            if relationship {
                AttributionStanding::Contact
            } else {
                AttributionStanding::Stranger
            },
        );
    }

    pub(crate) fn standing_of(&self, agent_id: AgentId) -> AttributionStanding {
        if self.contact_peers.contains(&agent_id) {
            AttributionStanding::Contact
        } else if self.protected_peers.contains(&agent_id) {
            AttributionStanding::Protected
        } else {
            AttributionStanding::Stranger
        }
    }

    /// Standing generation for `agent_id`.
    ///
    /// A stored generation starts at 1. Eviction removes the entry and does
    /// not reset the clock. A missing entry reads
    /// [`Self::evicted_epoch_high_water`], not the live clock. That mark
    /// moves only when an epoch is evicted. A resolve that read an earlier
    /// value cannot match after a later write, including one that eviction
    /// then forgot. A standing write that does not evict leaves the mark
    /// unchanged, so a new contact can still be stored.
    pub(crate) fn relationship_epoch(&self, agent_id: AgentId) -> u64 {
        self.relationship_epochs
            .get(&agent_id)
            .copied()
            .unwrap_or(self.evicted_epoch_high_water)
    }

    /// Apply `standing` and mint a generation so an older resolve cannot overwrite it.
    pub(crate) fn set_standing(&mut self, agent_id: AgentId, standing: AttributionStanding) {
        self.apply_standing(agent_id, standing);
        self.mint_relationship_epoch(agent_id);
    }

    /// Apply `standing` only when no later write has bumped the epoch.
    pub(crate) fn set_standing_if_epoch(
        &mut self,
        agent_id: AgentId,
        standing: AttributionStanding,
        epoch: u64,
    ) -> bool {
        if self.relationship_epoch(agent_id) != epoch {
            return false;
        }
        self.set_standing(agent_id, standing);
        true
    }

    fn mint_relationship_epoch(&mut self, agent_id: AgentId) {
        if let Some(seq) = self.relationship_epoch_index.remove(&agent_id) {
            self.relationship_epoch_order.remove(&(seq, agent_id.0));
        }
        self.relationship_epoch_clock = self.relationship_epoch_clock.saturating_add(1);
        let generation = self.relationship_epoch_clock;
        self.relationship_epochs.insert(agent_id, generation);
        self.relationship_epoch_order
            .insert((generation, agent_id.0));
        self.relationship_epoch_index.insert(agent_id, generation);
        while self.relationship_epochs.len() > self.relationship_epoch_cap {
            if !self.evict_relationship_epoch(agent_id) {
                break;
            }
        }
    }

    /// Drop one epoch that is not `keep` when another candidate exists.
    /// Strangers go first, then protected peers, then contacts.
    fn evict_relationship_epoch(&mut self, keep: AgentId) -> bool {
        let victim = self
            .oldest_epoch(AttributionStanding::Stranger, Some(keep))
            .or_else(|| self.oldest_epoch(AttributionStanding::Stranger, None))
            .or_else(|| self.oldest_epoch(AttributionStanding::Protected, Some(keep)))
            .or_else(|| self.oldest_epoch(AttributionStanding::Protected, None))
            .or_else(|| self.oldest_epoch(AttributionStanding::Contact, Some(keep)))
            .or_else(|| self.oldest_epoch(AttributionStanding::Contact, None));
        let Some(agent_id) = victim else {
            return false;
        };
        self.forget_relationship_epoch(agent_id);
        self.release_idle_protected_peer(agent_id);
        true
    }

    fn oldest_epoch(
        &self,
        standing: AttributionStanding,
        skip: Option<AgentId>,
    ) -> Option<AgentId> {
        self.relationship_epoch_order.iter().find_map(|(_, agent)| {
            let agent_id = AgentId(*agent);
            if skip == Some(agent_id) || self.standing_of(agent_id) != standing {
                None
            } else {
                Some(agent_id)
            }
        })
    }

    fn forget_relationship_epoch(&mut self, agent_id: AgentId) {
        let removed = self.relationship_epochs.remove(&agent_id).is_some();
        if let Some(seq) = self.relationship_epoch_index.remove(&agent_id) {
            self.relationship_epoch_order.remove(&(seq, agent_id.0));
        }
        if removed {
            self.evicted_epoch_high_water = self
                .evicted_epoch_high_water
                .max(self.relationship_epoch_clock);
        }
    }

    /// Lower the epoch map cap. Call this before the writes under test.
    #[cfg(test)]
    pub(crate) fn set_relationship_epoch_limit_for_test(&mut self, agents: usize) {
        self.relationship_epoch_cap = agents.max(1);
    }

    fn apply_standing(&mut self, agent_id: AgentId, standing: AttributionStanding) {
        let current = self.standing_of(agent_id);
        if current == standing {
            return;
        }
        if standing == AttributionStanding::Protected {
            self.move_to_protected(agent_id, current);
            return;
        }
        let recency = self.machine_recency(agent_id);
        self.detach_pairs(agent_id, current);
        if standing == AttributionStanding::Contact {
            self.contact_peers.insert(agent_id);
            self.trim_contact_share(agent_id, &recency);
        } else {
            self.attach_stranger_pairs(agent_id, &recency);
        }
    }

    /// Move `agent_id` into the protected share without passing its cap.
    ///
    /// Confirmed revoked pairs and unknown pairs have to fit before the
    /// move. When they do not, the move is refused and the pairs stay in
    /// `current`. Clean pairs that still do not fit are dropped. They are
    /// not left outside a share, and they do not raise the protected count.
    fn move_to_protected(&mut self, agent_id: AgentId, current: AttributionStanding) {
        let machines = self.machines_accepted_for(&agent_id);
        let snapshot = self.snapshot_revocations(machines.iter().copied());
        let classified: Vec<(MachineId, RevocationPin)> = machines
            .into_iter()
            .map(|machine| {
                (
                    machine,
                    snapshot
                        .get(&machine)
                        .copied()
                        .unwrap_or(RevocationPin::Unknown),
                )
            })
            .collect();
        let (_, protected_cap, _) = self.share_caps();
        let must_keep = classified
            .iter()
            .filter(|(_, pin)| *pin != RevocationPin::Clean)
            .count();
        while self.attribution_protected_pairs_len + must_keep > protected_cap {
            if !self.evict_lru_protected() {
                return;
            }
        }
        self.detach_pairs(agent_id, current);
        self.protected_peers.insert(agent_id);
        let room = protected_cap.saturating_sub(self.attribution_protected_pairs_len);
        let mut ordered = Vec::with_capacity(classified.len());
        for (machine, pin) in &classified {
            if *pin != RevocationPin::Clean {
                ordered.push(*machine);
            }
        }
        for (machine, pin) in &classified {
            if *pin == RevocationPin::Clean {
                ordered.push(*machine);
            }
        }
        for (index, machine) in ordered.into_iter().enumerate() {
            if index >= room {
                self.drop_accepted_pair(agent_id, machine);
                continue;
            }
            self.touch_protected(agent_id, machine);
            self.attribution_protected_pairs_len += 1;
        }
    }

    fn detach_pairs(&mut self, agent_id: AgentId, current: AttributionStanding) {
        match current {
            AttributionStanding::Contact => {
                self.contact_peers.remove(&agent_id);
            }
            AttributionStanding::Protected => {
                self.protected_peers.remove(&agent_id);
                self.forget_protected(agent_id);
            }
            AttributionStanding::Stranger => self.forget_stranger(agent_id),
        }
    }

    fn machine_recency(&self, agent_id: AgentId) -> std::collections::HashMap<MachineId, u64> {
        let mut recency = std::collections::HashMap::new();
        for machine in self.machines_accepted_for(&agent_id) {
            let seq = self
                .pair_recency
                .get(&(agent_id.0, machine.0))
                .copied()
                .unwrap_or(0);
            recency.insert(machine, seq);
        }
        recency
    }

    fn note_pair_recency(&mut self, agent_id: AgentId, machine_id: MachineId) {
        self.pair_recency_clock = self.pair_recency_clock.saturating_add(1);
        self.pair_recency
            .insert((agent_id.0, machine_id.0), self.pair_recency_clock);
    }

    fn attach_stranger_pairs(
        &mut self,
        agent_id: AgentId,
        recency: &std::collections::HashMap<MachineId, u64>,
    ) {
        let (_, _, stranger_cap) = self.share_caps();
        let mut machines = self.machines_accepted_for(&agent_id);
        let mut probe_ids = machines.clone();
        probe_ids.extend(
            self.stranger_order
                .iter()
                .map(|(_, _, machine)| MachineId(*machine)),
        );
        let snapshot = self.snapshot_revocations(probe_ids);
        self.release_clean_stranger_pins(&snapshot);
        machines.sort_by_key(|machine| {
            let pinned = self
                .stranger_revoked_pins
                .contains(&(agent_id.0, machine.0));
            let class = if pinned {
                0u8
            } else {
                match snapshot
                    .get(machine)
                    .copied()
                    .unwrap_or(RevocationPin::Unknown)
                {
                    RevocationPin::Revoked => 1,
                    RevocationPin::Unknown => 2,
                    RevocationPin::Clean => 3,
                }
            };
            let newest = std::cmp::Reverse(recency.get(machine).copied().unwrap_or(0));
            (class, newest)
        });
        let incoming = machines.len();
        while self.attribution_stranger_pairs_len.saturating_add(incoming) > stranger_cap {
            if !self.evict_lru_stranger_with(&snapshot) {
                break;
            }
            self.warn_attribution_pressure(agent_id);
        }
        let mut room = stranger_cap.saturating_sub(self.attribution_stranger_pairs_len);
        for machine in machines {
            let key = (agent_id.0, machine.0);
            let pin = snapshot
                .get(&machine)
                .copied()
                .unwrap_or(RevocationPin::Unknown);
            let already_pinned = self.stranger_revoked_pins.contains(&key);
            if room == 0 && !already_pinned {
                if pin == RevocationPin::Revoked {
                    self.mark_revoked_unpinned(agent_id, machine);
                }
                self.drop_accepted_pair(agent_id, machine);
                self.mark_attribution_overflow(agent_id);
                continue;
            }
            self.touch_stranger(agent_id, machine);
            self.attribution_stranger_pairs_len += 1;
            if room > 0 {
                room = room.saturating_sub(1);
            }
            self.note_stranger_revocation(agent_id, machine, pin);
        }
    }

    /// Drop this agent's clean and unknown pairs until the contact remainder
    /// can hold them. Keep the 2 newest confirmed revoked machines. Those
    /// pins can sit above the remainder. An unknown answer that does not
    /// fit is dropped, so it cannot fill the global pair cap.
    fn trim_contact_share(
        &mut self,
        agent_id: AgentId,
        recency: &std::collections::HashMap<MachineId, u64>,
    ) {
        let (contact_cap, _, _) = self.share_caps();
        let mut machines = self.machines_accepted_for(&agent_id);
        let snapshot = self.snapshot_revocations(machines.iter().copied());
        machines.sort_by_key(|machine| recency.get(machine).copied().unwrap_or(0));
        let mut clean = Vec::new();
        let mut unknown = Vec::new();
        let mut revoked = Vec::new();
        for machine in machines {
            match snapshot
                .get(&machine)
                .copied()
                .unwrap_or(RevocationPin::Unknown)
            {
                RevocationPin::Clean => clean.push(machine),
                RevocationPin::Unknown => unknown.push(machine),
                RevocationPin::Revoked => revoked.push(machine),
            }
        }
        while self.contact_pairs_len() > contact_cap {
            let Some(machine) = clean.first().copied() else {
                break;
            };
            clean.remove(0);
            self.drop_accepted_pair(agent_id, machine);
        }
        while self.contact_pairs_len() > contact_cap {
            let Some(machine) = unknown.first().copied() else {
                break;
            };
            unknown.remove(0);
            self.drop_accepted_pair(agent_id, machine);
        }
        while self.contact_pairs_len() > contact_cap
            && revoked.len() > PINNED_REVOKED_MACHINES_PER_AGENT
        {
            let machine = revoked.remove(0);
            self.drop_accepted_pair(agent_id, machine);
        }
    }

    fn drop_accepted_pair(&mut self, agent_id: AgentId, machine_id: MachineId) {
        if self
            .stranger_revoked_pins
            .contains(&(agent_id.0, machine_id.0))
        {
            return;
        }
        let removed = self
            .accepted_machines
            .get_mut(&agent_id)
            .is_some_and(|machines| machines.remove(&machine_id));
        if self
            .accepted_machines
            .get(&agent_id)
            .is_some_and(|machines| machines.is_empty())
        {
            self.accepted_machines.remove(&agent_id);
        }
        if !removed {
            return;
        }
        self.pair_recency.remove(&(agent_id.0, machine_id.0));
        self.attribution_pairs_len = self.attribution_pairs_len.saturating_sub(1);
        let key = (agent_id.0, machine_id.0);
        if let Some(seq) = self.stranger_index.remove(&key) {
            self.stranger_order.remove(&(seq, key.0, key.1));
            self.attribution_stranger_pairs_len =
                self.attribution_stranger_pairs_len.saturating_sub(1);
        }
        if let Some(seq) = self.protected_index.remove(&key) {
            self.protected_order.remove(&(seq, key.0, key.1));
            self.attribution_protected_pairs_len =
                self.attribution_protected_pairs_len.saturating_sub(1);
        }
    }

    fn forget_stranger(&mut self, agent_id: AgentId) {
        for machine in self.machines_accepted_for(&agent_id) {
            let key = (agent_id.0, machine.0);
            if let Some(seq) = self.stranger_index.remove(&key) {
                self.stranger_order.remove(&(seq, key.0, key.1));
                self.attribution_stranger_pairs_len =
                    self.attribution_stranger_pairs_len.saturating_sub(1);
            }
        }
        self.release_agent_stranger_pins(agent_id);
        self.clear_revoked_unpinned_agent(agent_id);
    }

    fn forget_protected(&mut self, agent_id: AgentId) {
        for machine in self.machines_accepted_for(&agent_id) {
            let key = (agent_id.0, machine.0);
            if let Some(seq) = self.protected_index.remove(&key) {
                self.protected_order.remove(&(seq, key.0, key.1));
                self.attribution_protected_pairs_len =
                    self.attribution_protected_pairs_len.saturating_sub(1);
            }
        }
    }

    /// Contact remainder, protected limit, and stranger limit.
    ///
    /// The protected and stranger numbers are the class limits. A full class
    /// evicts inside itself. The contact number is what remains of the pair
    /// cap after those two shares are reserved, so a full contact share still
    /// leaves the stranger share available.
    ///
    /// A class limit larger than the pair cap is a test budget. It does not
    /// reserve the whole cap, so contacts still fit. The global pair cap
    /// refuses the extra pairs, and that class does not evict until it
    /// reaches its own limit.
    fn share_caps(&self) -> (usize, usize, usize) {
        let total = self.attribution_pairs.max(1);
        let stranger_limit = self.attribution_stranger_pairs.max(1);
        let protected_limit = self.attribution_protected_pairs;
        let shares_fit = stranger_limit.saturating_add(protected_limit) <= total;
        let stranger_reserved = if shares_fit { stranger_limit } else { 0 };
        let protected_reserved = if shares_fit { protected_limit } else { 0 };
        let contact = total
            .saturating_sub(stranger_reserved)
            .saturating_sub(protected_reserved);
        (contact, protected_limit, stranger_limit)
    }

    fn contact_pairs_len(&self) -> usize {
        self.attribution_pairs_len
            .saturating_sub(self.attribution_stranger_pairs_len)
            .saturating_sub(self.attribution_protected_pairs_len)
    }

    /// Lower the stranger-pair budget. Call this before any stranger `record`.
    #[cfg(test)]
    pub(crate) fn set_stranger_pair_limit_for_test(&mut self, pairs: usize) {
        self.attribution_stranger_pairs = pairs.max(1);
    }

    /// Lower the protected non-contact budget. Call this before any protected `record`.
    #[cfg(test)]
    pub(crate) fn set_protected_pair_limit_for_test(&mut self, pairs: usize) {
        self.attribution_protected_pairs = pairs;
    }

    /// Overflowed agents that could not be named because the name list was full.
    #[cfg(test)]
    pub(crate) fn attribution_unnamed_overflows(&self) -> u64 {
        self.attribution_unnamed_overflows
    }

    /// Stranger LRU evictions, plus inserts refused because nothing could be evicted.
    #[cfg(test)]
    pub(crate) fn attribution_stranger_overflows(&self) -> u64 {
        self.attribution_stranger_overflows
    }

    /// Stranger pairs currently stored.
    #[cfg(test)]
    pub(crate) fn attribution_stranger_pairs_len(&self) -> usize {
        self.attribution_stranger_pairs_len
    }

    /// Dropped or unpinned revoked pairs still remembered.
    #[cfg(test)]
    pub(crate) fn revoked_unpinned_len(&self) -> usize {
        self.revoked_unpinned_index.len()
    }

    /// True when this agent still has a dropped or unpinned revoked pair.
    #[cfg(test)]
    pub(crate) fn revoked_unpinned_contains(&self, agent_id: AgentId) -> bool {
        self.revoked_unpinned_by_agent.contains_key(&agent_id)
    }

    /// Apply a clean probe answer to this agent's dropped-pair records.
    #[cfg(test)]
    pub(crate) fn refresh_unpinned_agent_for_test(&mut self, agent_id: AgentId) {
        self.refresh_unpinned_agent(agent_id);
    }

    /// Install the group-member and grant-party check. Replaces any
    /// previous probe. The probe does not by itself move stored pairs.
    /// The next record, a contact change, or [`Self::reclassify_attribution`]
    /// applies it.
    pub(crate) fn install_relationship_probe(&mut self, probe: AttributionRelationshipProbe) {
        self.relationship_probe = Some(probe);
    }

    /// Install the revocation check that pins protected-share pairs.
    /// Replaces any previous probe. A missing probe pins nothing.
    ///
    /// `Some(true)` is confirmed revoked. `Some(false)` is confirmed clean.
    /// `None` is unknown: the pair stays, and it is not a confirmed revocation.
    pub(crate) fn install_revoked_machine_probe(
        &mut self,
        probe: impl Fn(MachineId) -> Option<bool> + Send + Sync + 'static,
    ) {
        self.revoked_machine_probe = Some(RevokedMachineProbe::from_fn(probe));
    }

    /// Agents that already have attribution standing or an accepted machine.
    pub(crate) fn attribution_agents(&self) -> Vec<AgentId> {
        let mut agents = std::collections::HashSet::new();
        agents.extend(self.accepted_machines.keys().copied());
        agents.extend(self.contact_peers.iter().copied());
        agents.extend(self.protected_peers.iter().copied());
        agents.into_iter().collect()
    }

    /// Apply the installed probe to agents already in this cache.
    ///
    /// Records made before the probe was installed resolved as strangers.
    /// `is_contact` is the Trusted or Known bit. The closure must not lock
    /// this cache.
    pub(crate) fn reclassify_attribution(&mut self, is_contact: impl Fn(AgentId) -> bool) {
        let agents = self.attribution_agents();
        for agent_id in agents {
            let standing = standing_from_probe(
                is_contact(agent_id),
                probe_view(self.relationship_probe.as_ref(), agent_id),
                self.standing_of(agent_id),
            );
            self.set_standing(agent_id, standing);
        }
    }

    /// Contact trust, or the probe, or the standing already stored when the
    /// probe cannot answer. A busy lock must not clear protection.
    #[cfg(test)]
    pub(crate) fn resolve_relationship(&self, agent_id: AgentId, contact: bool) -> bool {
        !matches!(
            self.resolve_standing(agent_id, contact),
            AttributionStanding::Stranger
        )
    }

    #[cfg(test)]
    pub(crate) fn resolve_standing(&self, agent_id: AgentId, contact: bool) -> AttributionStanding {
        standing_from_probe(
            contact,
            probe_view(self.relationship_probe.as_ref(), agent_id),
            self.standing_of(agent_id),
        )
    }

    fn remember_accepted_machine(&mut self, agent_id: AgentId, machine_id: MachineId) {
        let standing = self.standing_of(agent_id);
        if self
            .accepted_machines
            .get(&agent_id)
            .is_some_and(|machines| machines.contains(&machine_id))
        {
            self.note_pair_recency(agent_id, machine_id);
            self.touch_class(agent_id, machine_id, standing);
            if standing == AttributionStanding::Stranger {
                let snapshot = self.snapshot_revocations(std::iter::once(machine_id));
                let pin = snapshot
                    .get(&machine_id)
                    .copied()
                    .unwrap_or(RevocationPin::Unknown);
                self.note_stranger_revocation(agent_id, machine_id, pin);
            }
            return;
        }
        if self.agent_accepted_len(&agent_id) >= self.attribution_per_agent {
            self.mark_attribution_overflow(agent_id);
            return;
        }
        let (contact_cap, protected_cap, stranger_cap) = self.share_caps();
        let class_full = match standing {
            AttributionStanding::Contact => self.contact_pairs_len() >= contact_cap,
            AttributionStanding::Protected => self.attribution_protected_pairs_len >= protected_cap,
            AttributionStanding::Stranger => self.attribution_stranger_pairs_len >= stranger_cap,
        };
        if class_full {
            let freed = match standing {
                AttributionStanding::Stranger => self.evict_lru_stranger(),
                AttributionStanding::Protected => self.evict_lru_protected(),
                AttributionStanding::Contact => false,
            };
            if !freed {
                if standing == AttributionStanding::Stranger {
                    self.attribution_stranger_overflows =
                        self.attribution_stranger_overflows.saturating_add(1);
                    let snapshot = self.snapshot_revocations(std::iter::once(machine_id));
                    if snapshot.get(&machine_id).copied() == Some(RevocationPin::Revoked) {
                        self.mark_revoked_unpinned(agent_id, machine_id);
                    }
                }
                self.warn_attribution_pressure(agent_id);
                self.mark_attribution_overflow(agent_id);
                return;
            }
            self.warn_attribution_pressure(agent_id);
        }
        if self.agent_accepted_len(&agent_id) >= self.attribution_per_agent
            || self.attribution_pairs_len >= self.attribution_pairs
        {
            self.mark_attribution_overflow(agent_id);
            return;
        }
        self.accepted_machines
            .entry(agent_id)
            .or_default()
            .insert(machine_id);
        self.attribution_pairs_len += 1;
        self.touch_class(agent_id, machine_id, standing);
        self.note_pair_recency(agent_id, machine_id);
        match standing {
            AttributionStanding::Stranger => {
                self.attribution_stranger_pairs_len += 1;
                let snapshot = self.snapshot_revocations(std::iter::once(machine_id));
                let pin = snapshot
                    .get(&machine_id)
                    .copied()
                    .unwrap_or(RevocationPin::Unknown);
                self.note_stranger_revocation(agent_id, machine_id, pin);
            }
            AttributionStanding::Protected => self.attribution_protected_pairs_len += 1,
            AttributionStanding::Contact => {}
        }
        // A slot was free, so this agent can record again. The next
        // machine past the cap sets the overflow flag once more.
        self.overflowed_agents.remove(&agent_id);
    }

    fn touch_class(
        &mut self,
        agent_id: AgentId,
        machine_id: MachineId,
        standing: AttributionStanding,
    ) {
        match standing {
            AttributionStanding::Stranger => self.touch_stranger(agent_id, machine_id),
            AttributionStanding::Protected => self.touch_protected(agent_id, machine_id),
            AttributionStanding::Contact => {}
        }
    }

    fn agent_accepted_len(&self, agent_id: &AgentId) -> usize {
        self.accepted_machines
            .get(agent_id)
            .map(|machines| machines.len())
            .unwrap_or(0)
    }

    fn touch_stranger(&mut self, agent_id: AgentId, machine_id: MachineId) {
        let key = (agent_id.0, machine_id.0);
        if let Some(seq) = self.stranger_index.get(&key).copied() {
            self.stranger_order.remove(&(seq, key.0, key.1));
        }
        self.stranger_clock = self.stranger_clock.saturating_add(1);
        let seq = self.stranger_clock;
        self.stranger_order.insert((seq, key.0, key.1));
        self.stranger_index.insert(key, seq);
    }

    /// Drop the least-recently used stranger pair that is not a revoked pin.
    ///
    /// The revocation probe is read once into `snapshot` when the caller did
    /// not already take one. A pin is never evicted. An unknown answer is
    /// not evicted. A revoked pair is pinned when the share cap and the
    /// per-agent limit both have room, and is then skipped. A revoked pair
    /// that still does not fit is dropped, and that agent is remembered so
    /// a full pin cap can refuse them. The snapshot covers the stranger
    /// share only.
    fn evict_lru_stranger(&mut self) -> bool {
        let machines: Vec<MachineId> = self
            .stranger_order
            .iter()
            .map(|(_, _, machine)| MachineId(*machine))
            .collect();
        let snapshot = self.snapshot_revocations(machines);
        self.evict_lru_stranger_with(&snapshot)
    }

    fn evict_lru_stranger_with(
        &mut self,
        snapshot: &std::collections::HashMap<MachineId, RevocationPin>,
    ) -> bool {
        self.release_clean_stranger_pins(snapshot);
        let order: Vec<(u64, [u8; 32], [u8; 32])> = self.stranger_order.iter().copied().collect();
        for (_, agent, machine) in order {
            if self.stranger_revoked_pins.contains(&(agent, machine)) {
                continue;
            }
            let agent_id = AgentId(agent);
            let machine_id = MachineId(machine);
            match snapshot
                .get(&machine_id)
                .copied()
                .unwrap_or(RevocationPin::Unknown)
            {
                RevocationPin::Clean => {
                    self.drop_accepted_pair(agent_id, machine_id);
                    self.attribution_stranger_overflows =
                        self.attribution_stranger_overflows.saturating_add(1);
                    return true;
                }
                RevocationPin::Unknown => continue,
                RevocationPin::Revoked => {
                    if self.try_pin_revoked_stranger(agent_id, machine_id) {
                        continue;
                    }
                    self.mark_revoked_unpinned(agent_id, machine_id);
                    self.drop_accepted_pair(agent_id, machine_id);
                    self.attribution_stranger_overflows =
                        self.attribution_stranger_overflows.saturating_add(1);
                    return true;
                }
            }
        }
        false
    }

    fn touch_protected(&mut self, agent_id: AgentId, machine_id: MachineId) {
        let key = (agent_id.0, machine_id.0);
        if let Some(seq) = self.protected_index.get(&key).copied() {
            self.protected_order.remove(&(seq, key.0, key.1));
        }
        self.protected_clock = self.protected_clock.saturating_add(1);
        let seq = self.protected_clock;
        self.protected_order.insert((seq, key.0, key.1));
        self.protected_index.insert(key, seq);
    }

    /// Drop the least-recently used protected pair that is not pinned.
    ///
    /// A confirmed revoked machine of a protected agent is pinned, up to 2
    /// of the most recently touched revoked pairs for that agent. An unknown
    /// answer is not evicted and does not count as a revocation. Eviction
    /// takes a clean pair first. When every remaining pair is pinned, this
    /// returns false and the caller does not record the new pair.
    fn evict_lru_protected(&mut self) -> bool {
        let machines: Vec<MachineId> = self
            .protected_order
            .iter()
            .map(|(_, _, machine)| MachineId(*machine))
            .collect();
        let snapshot = self.snapshot_revocations(machines);
        let Some((_, agent, machine)) =
            self.protected_order
                .iter()
                .copied()
                .find(|(seq, agent, machine)| {
                    self.protected_pair_evictable(*seq, *agent, *machine, &snapshot)
                })
        else {
            return false;
        };
        let agent_id = AgentId(agent);
        let machine_id = MachineId(machine);
        self.drop_accepted_pair(agent_id, machine_id);
        self.release_idle_protected_peer(agent_id);
        true
    }

    /// A clean pair can be evicted. An unknown pair cannot. A confirmed
    /// revoked pair can be evicted only when this agent already has 2 newer
    /// confirmed revocations. The count uses this agent's accepted machines
    /// (at most 8), not the whole protected share. Every answer comes from
    /// `snapshot`.
    fn protected_pair_evictable(
        &self,
        seq: u64,
        agent: [u8; 32],
        machine: [u8; 32],
        snapshot: &std::collections::HashMap<MachineId, RevocationPin>,
    ) -> bool {
        self.pinned_pair_evictable(seq, agent, machine, snapshot, |other| {
            self.protected_index.get(&(agent, other)).copied()
        })
    }

    fn stranger_pin_cap(&self) -> usize {
        if self.attribution_stranger_pairs == ACCEPTED_MACHINE_STRANGER_PAIRS {
            STRANGER_REVOKED_PIN_CAP
        } else {
            self.attribution_stranger_pairs / 2
        }
    }

    fn stranger_pin_cap_full(&self) -> bool {
        let cap = self.stranger_pin_cap();
        cap > 0 && self.stranger_revoked_pins.len() >= cap
    }

    /// Full pin cap, and this agent has a revoked pair that was dropped or
    /// could not be pinned. An agent with no such pair is not refused.
    fn stranger_pin_cap_refuses_unattested(&self, agent_id: AgentId) -> bool {
        self.stranger_pin_cap_full() && self.revoked_unpinned_by_agent.contains_key(&agent_id)
    }

    /// A clean pair can be evicted. An unknown pair cannot. A confirmed
    /// revoked pair can be evicted only when this agent already has 2 newer
    /// confirmed revocations in `index_of`. Answers come from `snapshot`.
    fn pinned_pair_evictable(
        &self,
        seq: u64,
        agent: [u8; 32],
        machine: [u8; 32],
        snapshot: &std::collections::HashMap<MachineId, RevocationPin>,
        index_of: impl Fn([u8; 32]) -> Option<u64>,
    ) -> bool {
        match snapshot
            .get(&MachineId(machine))
            .copied()
            .unwrap_or(RevocationPin::Unknown)
        {
            RevocationPin::Clean => return true,
            RevocationPin::Unknown => return false,
            RevocationPin::Revoked => {}
        }
        let newer_revoked = self
            .accepted_machines
            .get(&AgentId(agent))
            .map(|machines| {
                machines
                    .iter()
                    .filter(|other| {
                        if other.0 == machine {
                            return false;
                        }
                        let Some(other_seq) = index_of(other.0) else {
                            return false;
                        };
                        other_seq > seq
                            && snapshot.get(other).copied() == Some(RevocationPin::Revoked)
                    })
                    .take(PINNED_REVOKED_MACHINES_PER_AGENT)
                    .count()
            })
            .unwrap_or(0);
        newer_revoked >= PINNED_REVOKED_MACHINES_PER_AGENT
    }

    /// One probe call per machine. Later decisions in the same operation
    /// read the map. A machine that is absent reads as unknown.
    fn snapshot_revocations(
        &self,
        machines: impl IntoIterator<Item = MachineId>,
    ) -> std::collections::HashMap<MachineId, RevocationPin> {
        let mut snapshot = std::collections::HashMap::new();
        for machine in machines {
            snapshot
                .entry(machine)
                .or_insert_with(|| self.revocation_pin(&machine));
        }
        snapshot
    }

    fn release_clean_stranger_pins(
        &mut self,
        snapshot: &std::collections::HashMap<MachineId, RevocationPin>,
    ) {
        let expired_pins: Vec<([u8; 32], [u8; 32])> = self
            .stranger_revoked_pins
            .iter()
            .copied()
            .filter(|(_, machine)| {
                snapshot.get(&MachineId(*machine)).copied() == Some(RevocationPin::Clean)
            })
            .collect();
        for (agent, machine) in expired_pins {
            self.release_stranger_pin(AgentId(agent), MachineId(machine));
        }
        let expired_unpinned: Vec<([u8; 32], [u8; 32])> = self
            .stranger_index
            .keys()
            .copied()
            .filter(|(agent, machine)| {
                snapshot.get(&MachineId(*machine)).copied() == Some(RevocationPin::Clean)
                    && self
                        .revoked_unpinned_index
                        .contains_key(&(*agent, *machine))
            })
            .collect();
        for (agent, machine) in expired_unpinned {
            self.clear_revoked_unpinned_machine(AgentId(agent), MachineId(machine));
        }
    }

    fn unpinned_record_cap(&self) -> usize {
        self.attribution_stranger_pairs.max(1)
    }

    fn mark_revoked_unpinned(&mut self, agent_id: AgentId, machine_id: MachineId) {
        let key = (agent_id.0, machine_id.0);
        if self.revoked_unpinned_index.contains_key(&key) {
            return;
        }
        if self
            .revoked_unpinned_by_agent
            .get(&agent_id)
            .is_some_and(|machines| machines.len() >= ACCEPTED_MACHINES_PER_AGENT)
        {
            return;
        }
        let cap = self.unpinned_record_cap();
        while self.revoked_unpinned_index.len() >= cap {
            if !self.forget_oldest_unpinned() {
                return;
            }
        }
        self.revoked_unpinned_clock = self.revoked_unpinned_clock.saturating_add(1);
        let seq = self.revoked_unpinned_clock;
        self.revoked_unpinned_order.insert((seq, key.0, key.1));
        self.revoked_unpinned_index.insert(key, seq);
        self.revoked_unpinned_by_agent
            .entry(agent_id)
            .or_default()
            .insert(machine_id);
    }

    fn forget_oldest_unpinned(&mut self) -> bool {
        let Some(&(seq, agent, machine)) = self.revoked_unpinned_order.iter().next() else {
            return false;
        };
        self.remove_unpinned_entry(AgentId(agent), MachineId(machine), seq);
        true
    }

    fn clear_revoked_unpinned_machine(&mut self, agent_id: AgentId, machine_id: MachineId) {
        let key = (agent_id.0, machine_id.0);
        let Some(seq) = self.revoked_unpinned_index.get(&key).copied() else {
            return;
        };
        self.remove_unpinned_entry(agent_id, machine_id, seq);
    }

    fn remove_unpinned_entry(&mut self, agent_id: AgentId, machine_id: MachineId, seq: u64) {
        let key = (agent_id.0, machine_id.0);
        self.revoked_unpinned_index.remove(&key);
        self.revoked_unpinned_order.remove(&(seq, key.0, key.1));
        if let Some(machines) = self.revoked_unpinned_by_agent.get_mut(&agent_id) {
            machines.remove(&machine_id);
            if machines.is_empty() {
                self.revoked_unpinned_by_agent.remove(&agent_id);
            }
        }
    }

    fn clear_revoked_unpinned_agent(&mut self, agent_id: AgentId) {
        let Some(machines) = self.revoked_unpinned_by_agent.get(&agent_id).cloned() else {
            return;
        };
        for machine in machines {
            self.clear_revoked_unpinned_machine(agent_id, machine);
        }
    }

    /// Apply a clean probe answer for this agent's remembered machines.
    /// A missing probe is not a clean answer. At most 8 machines are read.
    fn refresh_unpinned_agent(&mut self, agent_id: AgentId) {
        if self.revoked_machine_probe.is_none() {
            return;
        }
        let Some(machines) = self.revoked_unpinned_by_agent.get(&agent_id).cloned() else {
            return;
        };
        let clean: Vec<MachineId> = machines
            .into_iter()
            .filter(|machine| self.revocation_pin(machine) == RevocationPin::Clean)
            .collect();
        for machine in clean {
            self.clear_revoked_unpinned_machine(agent_id, machine);
        }
    }

    fn release_stranger_pin(&mut self, agent_id: AgentId, machine_id: MachineId) {
        let key = (agent_id.0, machine_id.0);
        if !self.stranger_revoked_pins.remove(&key) {
            return;
        }
        if let Some(pins) = self.stranger_pins_by_agent.get_mut(&agent_id) {
            pins.remove(&machine_id);
            if pins.is_empty() {
                self.stranger_pins_by_agent.remove(&agent_id);
            }
        }
    }

    fn release_agent_stranger_pins(&mut self, agent_id: AgentId) {
        let Some(pins) = self.stranger_pins_by_agent.remove(&agent_id) else {
            return;
        };
        for machine in pins {
            self.stranger_revoked_pins.remove(&(agent_id.0, machine.0));
        }
    }

    /// Pin when the share cap and the per-agent limit both have room.
    /// An existing pin stays. A later revoked pair does not replace one.
    /// Another agent's pin is never removed. A pair that does not fit is
    /// remembered on the agent.
    fn note_stranger_revocation(
        &mut self,
        agent_id: AgentId,
        machine_id: MachineId,
        pin: RevocationPin,
    ) {
        match pin {
            RevocationPin::Clean => {
                self.release_stranger_pin(agent_id, machine_id);
                self.clear_revoked_unpinned_machine(agent_id, machine_id);
            }
            RevocationPin::Unknown => {}
            RevocationPin::Revoked => {
                if !self.try_pin_revoked_stranger(agent_id, machine_id) {
                    self.mark_revoked_unpinned(agent_id, machine_id);
                }
            }
        }
    }

    /// Returns true when `machine_id` is a pin after this call.
    fn try_pin_revoked_stranger(&mut self, agent_id: AgentId, machine_id: MachineId) -> bool {
        let key = (agent_id.0, machine_id.0);
        if self.stranger_revoked_pins.contains(&key) {
            self.clear_revoked_unpinned_machine(agent_id, machine_id);
            return true;
        }
        let owned = self
            .stranger_pins_by_agent
            .get(&agent_id)
            .map(|pins| pins.len())
            .unwrap_or(0);
        if owned >= PINNED_REVOKED_MACHINES_PER_AGENT
            || self.stranger_revoked_pins.len() >= self.stranger_pin_cap()
        {
            return false;
        }
        self.stranger_revoked_pins.insert(key);
        self.stranger_pins_by_agent
            .entry(agent_id)
            .or_default()
            .insert(machine_id);
        self.clear_revoked_unpinned_machine(agent_id, machine_id);
        true
    }

    fn revocation_pin(&self, machine_id: &MachineId) -> RevocationPin {
        match self.revoked_machine_probe.as_ref() {
            None => RevocationPin::Clean,
            Some(probe) => match probe.answer(machine_id) {
                Some(true) => RevocationPin::Revoked,
                Some(false) => RevocationPin::Clean,
                None => RevocationPin::Unknown,
            },
        }
    }

    /// Drop protected-peer metadata once nothing keeps this agent in the share.
    fn release_idle_protected_peer(&mut self, agent_id: AgentId) {
        if self.standing_of(agent_id) != AttributionStanding::Protected {
            return;
        }
        if self.agent_accepted_len(&agent_id) > 0 {
            return;
        }
        if self.relationship_epochs.contains_key(&agent_id) {
            return;
        }
        self.protected_peers.remove(&agent_id);
    }

    fn warn_attribution_pressure(&mut self, agent_id: AgentId) {
        let now = monotonic_ms();
        if !warn_interval_open(self.attribution_overflow_warn_ms, now) {
            return;
        }
        self.attribution_overflow_warn_ms = now.max(1);
        tracing::warn!(
            agent = %hex::encode(agent_id.as_bytes()),
            unnamed = self.attribution_unnamed_overflows,
            stranger_overflows = self.attribution_stranger_overflows,
            stranger_pairs = self.attribution_stranger_pairs_len,
            pairs = self.attribution_pairs_len,
            "attribution cap reached; a machine past the per-agent cap is not recorded, and an evicted stranger machine is no longer attributed"
        );
    }

    fn mark_attribution_overflow(&mut self, agent_id: AgentId) {
        if self.overflowed_agents.contains(&agent_id) {
            return;
        }
        if self.overflowed_agents.len() >= self.attribution_overflow_agents {
            // The new agent cannot be named. Other senders keep their pairs.
            self.attribution_unnamed_overflows =
                self.attribution_unnamed_overflows.saturating_add(1);
            self.warn_attribution_pressure(agent_id);
            return;
        }
        self.overflowed_agents.insert(agent_id);
        self.warn_attribution_pressure(agent_id);
    }

    /// Wake `notify` on every future retained-machine / expiry / clear /
    /// eviction mutation (ADR-0074 §4). Replaces any previously installed
    /// notifier.
    pub(crate) fn set_change_notify(&mut self, notify: std::sync::Arc<tokio::sync::Notify>) {
        self.change_notify = Some(notify);
    }

    fn notify_changed(&self) {
        if let Some(notify) = &self.change_notify {
            notify.notify_one();
        }
    }

    fn next_tick(&mut self) -> (std::time::Instant, u64) {
        self.clock = self.clock.wrapping_add(1);
        (std::time::Instant::now(), self.clock)
    }

    fn record(&mut self, agent_id: AgentId, machine_id: MachineId, announced_at: u64) {
        // ADR-0021 attestations carry no user certificate. Preserve any known
        // certificate expiry: a new machine attestation cannot renew a cert.
        let cert_not_after = self.entries.get(&agent_id).and_then(|b| b.cert_not_after);
        self.record_with_expiry(agent_id, machine_id, announced_at, cert_not_after);
    }

    fn record_with_expiry(
        &mut self,
        agent_id: AgentId,
        machine_id: MachineId,
        announced_at: u64,
        cert_not_after: Option<u64>,
    ) {
        let cert_digest = self.entries.get(&agent_id).and_then(|b| b.cert_digest);
        self.upsert_binding(
            agent_id,
            machine_id,
            announced_at,
            cert_digest,
            cert_not_after,
            true,
        );
    }

    /// Move the retained binding to a freshly verified origin without taking
    /// a new attribution slot. Grant evaluation reads this binding. The slot
    /// is recorded only after decryption succeeds.
    fn refresh_retained_origin(
        &mut self,
        agent_id: AgentId,
        machine_id: MachineId,
        announced_at: u64,
    ) {
        let existing = self.entries.get(&agent_id).copied();
        self.upsert_binding(
            agent_id,
            machine_id,
            announced_at,
            existing.and_then(|binding| binding.cert_digest),
            existing.and_then(|binding| binding.cert_not_after),
            false,
        );
    }

    /// x0x #1150 (r7e): the announced-binding store's write for one verified
    /// identity announcement (`cert_digest` is the digest it committed to,
    /// `cert_not_after` the expiry of an inline or already-landed
    /// certificate). The expiry stays coupled to its digest here, whether
    /// or not the discovery entry survives:
    /// - a certificate's known expiry is recorded with its digest;
    /// - an unchanged digest without a certificate keeps the known expiry;
    /// - a different (verified, signed) digest clears it until its
    ///   certificate lands ([`Self::record_certificate_landed`]);
    /// - a digest-less legacy announcement keeps what is known.
    ///
    /// An older announcement never rolls the binding back.
    pub(crate) fn record_announcement(
        &mut self,
        agent_id: AgentId,
        machine_id: MachineId,
        announced_at: u64,
        cert_digest: Option<[u8; 32]>,
        cert_not_after: Option<u64>,
    ) {
        let existing = self.entries.get(&agent_id).copied();
        let known_digest = existing.and_then(|b| b.cert_digest);
        let (digest, not_after) = match (cert_digest, cert_not_after) {
            (digest, Some(not_after)) => (digest.or(known_digest), Some(not_after)),
            (Some(digest), None) if known_digest == Some(digest) => {
                (Some(digest), existing.and_then(|b| b.cert_not_after))
            }
            (Some(digest), None) => (Some(digest), None),
            (None, None) => (known_digest, existing.and_then(|b| b.cert_not_after)),
        };
        // The announced-binding store uses this writer. It keeps the
        // retained binding and does not take an attribution slot. The
        // authenticated store records a slot through `record`.
        self.upsert_binding(agent_id, machine_id, announced_at, digest, not_after, false);
    }

    /// x0x #1150 (r7e): a verified certificate blob for `digest` landed for
    /// `agent_id`. The binding whose announcement committed to that digest
    /// learns the certificate's expiry. The update is keyed on the digest
    /// only, not on the discovery entry (which may be gone). A binding for
    /// another digest is untouched. Returns whether it updated.
    pub(crate) fn record_certificate_landed(
        &mut self,
        agent_id: &AgentId,
        digest: [u8; 32],
        cert_not_after: Option<u64>,
    ) -> bool {
        match self.entries.get_mut(agent_id) {
            Some(binding) if binding.cert_digest == Some(digest) => {
                let changed = binding.cert_not_after != cert_not_after;
                binding.cert_not_after = cert_not_after;
                if changed {
                    self.notify_changed();
                }
                true
            }
            _ => false,
        }
    }

    fn upsert_binding(
        &mut self,
        agent_id: AgentId,
        machine_id: MachineId,
        announced_at: u64,
        cert_digest: Option<[u8; 32]>,
        cert_not_after: Option<u64>,
        remember_new: bool,
    ) {
        let tick = self.next_tick();
        if let Some(mut existing) = self.entries.get(&agent_id).copied() {
            self.recency
                .remove(&(existing.last_used.0, existing.last_used.1, agent_id.0));
            existing.last_used = tick;
            let mut authority_changed = false;
            if announced_at >= existing.announced_at {
                authority_changed = existing.machine_id != machine_id
                    || existing.cert_not_after != cert_not_after
                    || existing.cert_digest != cert_digest
                    || existing.announced_at != announced_at;
                // #1659: keep a machine this binding is about to replace
                // only when that machine was already admitted. A retained
                // binding left by an undecryptable DM is not admitted.
                // This write records the new machine only when the caller
                // is recording. A DM refresh does not take a slot until
                // decryption succeeds.
                let replaced_already = self
                    .accepted_machines
                    .get(&agent_id)
                    .is_some_and(|machines| machines.contains(&existing.machine_id));
                if replaced_already {
                    self.remember_accepted_machine(agent_id, existing.machine_id);
                }
                if remember_new {
                    self.remember_accepted_machine(agent_id, machine_id);
                }
                self.by_machine.remove(&(existing.machine_id.0, agent_id.0));
                self.by_machine.insert((machine_id.0, agent_id.0));
                existing.machine_id = machine_id;
                existing.announced_at = announced_at;
                existing.cert_not_after = cert_not_after;
                existing.cert_digest = cert_digest;
            } else {
                // Verified, and older than the retained binding. The retained
                // machine stays. #1659 attributes this machine when the
                // caller is recording, not when a DM is only refreshing
                // the retained binding ahead of decryption.
                if remember_new {
                    self.remember_accepted_machine(agent_id, machine_id);
                }
            }
            self.entries.insert(agent_id, existing);
            self.recency.insert((tick.0, tick.1, agent_id.0));
            if authority_changed {
                self.notify_changed();
            }
            return;
        }

        if self.entries.len() >= self.capacity {
            let oldest = self.recency.first().copied();
            if let Some(oldest_key) = oldest {
                self.recency.remove(&oldest_key);
                let evicted_agent = AgentId(oldest_key.2);
                if let Some(evicted_binding) = self.entries.remove(&evicted_agent) {
                    self.by_machine
                        .remove(&(evicted_binding.machine_id.0, evicted_agent.0));
                    tracing::warn!(
                        agent = %hex::encode(evicted_agent.as_bytes()),
                        machine = %hex::encode(evicted_binding.machine_id.as_bytes()),
                        capacity = self.capacity,
                        "authenticated machine binding evicted; future DMs degrade to claimed-machine fallback"
                    );
                }
            }
        }

        self.by_machine.insert((machine_id.0, agent_id.0));
        if remember_new {
            self.remember_accepted_machine(agent_id, machine_id);
        }
        self.entries.insert(
            agent_id,
            AuthenticatedMachineBinding {
                machine_id,
                announced_at,
                cert_not_after,
                cert_digest,
                last_used: tick,
            },
        );
        self.recency.insert((tick.0, tick.1, agent_id.0));
        // New retained binding (and any capacity eviction above) wakes reauth.
        self.notify_changed();
    }

    /// The retained binding for `agent_id`, without touching its recency
    /// (x0x #1150 r7b: the pinned send's point-of-use reads).
    pub(crate) fn peek(&self, agent_id: &AgentId) -> Option<AuthenticatedMachineBinding> {
        self.entries.get(agent_id).copied()
    }

    fn resolve(&mut self, agent_id: &AgentId) -> Option<MachineId> {
        self.resolve_evidence(agent_id)
            .map(|binding| binding.machine_id)
    }

    /// Drop every retained binding and the accepted-machine set. A process
    /// restart does this by exiting. Tests use it to empty the registry
    /// while a transport connection stays up.
    #[cfg(test)]
    pub(crate) fn clear_for_test(&mut self) {
        let had_state = !self.entries.is_empty() || !self.accepted_machines.is_empty();
        self.entries.clear();
        self.by_machine.clear();
        self.accepted_machines.clear();
        self.overflowed_agents.clear();
        self.contact_peers.clear();
        self.protected_peers.clear();
        self.relationship_epochs.clear();
        self.relationship_epoch_order.clear();
        self.relationship_epoch_index.clear();
        self.relationship_epoch_clock = 0;
        self.evicted_epoch_high_water = 0;
        self.attribution_pairs_len = 0;
        self.attribution_stranger_pairs_len = 0;
        self.attribution_protected_pairs_len = 0;
        self.attribution_unnamed_overflows = 0;
        self.attribution_stranger_overflows = 0;
        self.attribution_overflow_warn_ms = 0;
        self.stranger_order.clear();
        self.stranger_index.clear();
        self.stranger_clock = 0;
        self.stranger_revoked_pins.clear();
        self.stranger_pins_by_agent.clear();
        self.revoked_unpinned_order.clear();
        self.revoked_unpinned_index.clear();
        self.revoked_unpinned_by_agent.clear();
        self.revoked_unpinned_clock = 0;
        self.pair_recency.clear();
        self.pair_recency_clock = 0;
        self.protected_order.clear();
        self.protected_index.clear();
        self.protected_clock = 0;
        self.recency.clear();
        if had_state {
            self.notify_changed();
        }
    }

    fn resolve_evidence(&mut self, agent_id: &AgentId) -> Option<AuthenticatedMachineBinding> {
        let tick = self.next_tick();
        let mut binding = self.entries.get(agent_id).copied()?;
        self.recency
            .remove(&(binding.last_used.0, binding.last_used.1, agent_id.0));
        binding.last_used = tick;
        self.entries.insert(*agent_id, binding);
        self.recency.insert((tick.0, tick.1, agent_id.0));
        Some(binding)
    }
}

/// Shared retained cache of authenticated agent→machine bindings.
pub type AuthenticatedMachineBindings = Arc<RwLock<AuthenticatedMachineBindingCache>>;

/// Move `agent_id` into or out of the contact attribution pool.
///
/// `false` clears protection, including group and grant protection. Revocation
/// and quarantine reblock use that. A contact downgrade that must keep a
/// group or grant uses [`with_contact_standing`].
pub(crate) async fn set_attribution_relationship(
    bindings: &AuthenticatedMachineBindings,
    agent_id: AgentId,
    relationship: bool,
) {
    bindings
        .write()
        .await
        .set_relationship_peer(agent_id, relationship);
}

/// Re-evaluate contact trust and the relationship probe, then store the standing.
///
/// The probe runs before the bindings write lock and without the contacts
/// lock. `contact` is the Trusted or Known bit the caller already read.
/// A concurrent resolve retries so an older snapshot does not keep the
/// standing. After four misses the newer standing stays and `body` still runs.
#[cfg(test)]
pub(crate) async fn set_resolved_attribution_standing(
    bindings: &AuthenticatedMachineBindings,
    agent_id: AgentId,
    contact: bool,
) {
    with_resolved_standing(bindings, agent_id, contact, |_| ()).await;
}

/// [`set_resolved_attribution_standing`], then `body` under the same write lock.
#[cfg(test)]
pub(crate) async fn with_resolved_standing<T>(
    bindings: &AuthenticatedMachineBindings,
    agent_id: AgentId,
    contact: bool,
    body: impl FnOnce(&mut AuthenticatedMachineBindingCache) -> T,
) -> T {
    for _ in 0..4 {
        let (probe, current, epoch) = {
            let cache = bindings.read().await;
            (
                cache.relationship_probe.clone(),
                cache.standing_of(agent_id),
                cache.relationship_epoch(agent_id),
            )
        };
        let standing = standing_from_probe(contact, probe_view(probe.as_ref(), agent_id), current);
        let mut cache = bindings.write().await;
        if cache.set_standing_if_epoch(agent_id, standing, epoch) {
            return body(&mut cache);
        }
    }
    let mut cache = bindings.write().await;
    body(&mut cache)
}

/// Trusted or Known contact bit. The contacts lock is not held across the probe.
fn contact_is_protected(store: &crate::contacts::ContactStore, agent_id: AgentId) -> bool {
    store.get(&agent_id).is_some_and(|contact| {
        matches!(
            contact.trust_level,
            crate::contacts::TrustLevel::Trusted | crate::contacts::TrustLevel::Known
        )
    })
}

/// Re-read the contact bit on each attempt, then run the probe without that lock.
///
/// The relationship epoch is read before and after the contact bit. The two
/// epochs must match, so a promotion that lands between them cannot pair a
/// stale contact bit with the new epoch.
pub(crate) async fn with_contact_standing<T>(
    bindings: &AuthenticatedMachineBindings,
    contacts: &RwLock<crate::contacts::ContactStore>,
    agent_id: AgentId,
    body: impl FnOnce(&mut AuthenticatedMachineBindingCache) -> T,
) -> T {
    for _ in 0..4 {
        let epoch_before = bindings.read().await.relationship_epoch(agent_id);
        let contact = {
            let store = contacts.read().await;
            contact_is_protected(&store, agent_id)
        };
        #[cfg(test)]
        pause_after_contact_snapshot(agent_id).await;
        let (probe, current, epoch) = {
            let cache = bindings.read().await;
            (
                cache.relationship_probe.clone(),
                cache.standing_of(agent_id),
                cache.relationship_epoch(agent_id),
            )
        };
        if epoch_before != epoch {
            continue;
        }
        let standing = standing_from_probe(contact, probe_view(probe.as_ref(), agent_id), current);
        let mut cache = bindings.write().await;
        if cache.set_standing_if_epoch(agent_id, standing, epoch) {
            return body(&mut cache);
        }
    }
    let mut cache = bindings.write().await;
    body(&mut cache)
}

/// Test gate between the contact snapshot and the second epoch read.
/// Only `agent` pauses, so other tests are unaffected.
#[cfg(test)]
struct ContactSnapshotGate {
    agent: AgentId,
    armed: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
static CONTACT_SNAPSHOT_GATE: std::sync::Mutex<Option<std::sync::Arc<ContactSnapshotGate>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
async fn pause_after_contact_snapshot(agent_id: AgentId) {
    let gate = CONTACT_SNAPSHOT_GATE
        .lock()
        .expect("contact snapshot gate")
        .clone();
    if let Some(gate) = gate {
        if gate.agent == agent_id && gate.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
    }
}

/// Install the group-member and grant-party check on the authenticated
/// binding cache. The announced-binding store does not use it.
pub(crate) async fn install_attribution_relationship_probe(
    bindings: &AuthenticatedMachineBindings,
    probe: AttributionRelationshipProbe,
) {
    bindings.write().await.install_relationship_probe(probe);
}

/// Retain the freshest accepted, authenticated agent→machine announcement.
///
/// This security binding intentionally outlives discovery/reachability cache
/// eviction. A later authenticated announcement can still move a portable
/// agent, while a replayed older announcement cannot roll the binding back.
pub(crate) async fn record_authenticated_machine_binding(
    bindings: &AuthenticatedMachineBindings,
    agent_id: AgentId,
    machine_id: MachineId,
    announced_at: u64,
) {
    bindings
        .write()
        .await
        .record(agent_id, machine_id, announced_at);
}

/// Record the certificate lifetime from a verified identity announcement.
pub(crate) async fn record_authenticated_machine_binding_with_expiry(
    bindings: &AuthenticatedMachineBindings,
    agent_id: AgentId,
    machine_id: MachineId,
    announced_at: u64,
    cert_not_after: Option<u64>,
) {
    bindings
        .write()
        .await
        .record_with_expiry(agent_id, machine_id, announced_at, cert_not_after);
}

pub(crate) async fn authenticated_machine_binding_evidence(
    bindings: &AuthenticatedMachineBindings,
    agent_id: &AgentId,
) -> Option<AuthenticatedMachineBinding> {
    bindings.write().await.resolve_evidence(agent_id)
}

pub(crate) async fn authenticated_machine_binding(
    bindings: &AuthenticatedMachineBindings,
    agent_id: &AgentId,
) -> Option<MachineId> {
    bindings.write().await.resolve(agent_id)
}

#[cfg(test)]
pub(crate) async fn authenticated_machine_binding_for_testing(
    bindings: &AuthenticatedMachineBindings,
    agent_id: &AgentId,
) -> Option<MachineId> {
    authenticated_machine_binding(bindings, agent_id).await
}

#[derive(Clone, Default)]
pub struct DmInboxConfig {
    /// If true, trust-policy rejections do NOT emit an ACK.
    pub silent_reject: bool,
    /// Prefix-routed payloads that should bypass generic DirectMessaging fan-out.
    pub typed_payload_routes: Vec<DmTypedPayloadRoute>,
    /// ADR-0070 §2 DM-acceptance input: a sender holding a current `Dm`
    /// ShareGrant for this agent is promoted to `Accept`. `None` ⇒ no grants.
    pub share_grant_gate: Option<crate::share_grant::ShareGrantDmGate>,
}

impl std::fmt::Debug for DmInboxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmInboxConfig")
            .field("silent_reject", &self.silent_reject)
            .field("typed_payload_routes", &self.typed_payload_routes.len())
            .field("share_grant_gate", &self.share_grant_gate.is_some())
            .finish()
    }
}

impl DmInboxConfig {
    /// Install the ADR-0070 §2 share-grant DM-acceptance gate.
    #[must_use]
    pub fn with_share_grant_gate(mut self, gate: crate::share_grant::ShareGrantDmGate) -> Self {
        self.share_grant_gate = Some(gate);
        self
    }

    /// Add a typed-payload route. Matching payloads are delivered to `sender`
    /// and are not emitted to generic `/direct/events` consumers.
    ///
    /// Routes registered this way cannot satisfy a durable (v2) receipt — see
    /// [`Self::with_durable_typed_payload_route`].
    #[must_use]
    pub fn with_typed_payload_route(
        mut self,
        prefix: impl Into<Vec<u8>>,
        sender: mpsc::Sender<DmTypedPayload>,
    ) -> Self {
        self.typed_payload_routes.push(DmTypedPayloadRoute {
            prefix: prefix.into(),
            sender,
            durable_completion: false,
            validator: None,
        });
        self
    }

    /// Add a typed-payload route whose handler reports durable completion
    /// (ADR 0030 §7).
    ///
    /// Opting in is a promise: the handler must resolve the payload's
    /// [`DmTypedPayload::completion`] channel once the payload is durably
    /// recorded in *its own* store, and only then. The inbox emits a v2 ACK
    /// solely on that signal, so a route that resolves optimistically converts
    /// a durable receipt into a lie. Routes that do not opt in never receive a
    /// v2 ACK — that withholding is stated policy, not an oversight.
    #[must_use]
    pub fn with_durable_typed_payload_route(
        mut self,
        prefix: impl Into<Vec<u8>>,
        sender: mpsc::Sender<DmTypedPayload>,
    ) -> Self {
        self.typed_payload_routes.push(DmTypedPayloadRoute {
            prefix: prefix.into(),
            sender,
            durable_completion: true,
            validator: None,
        });
        self
    }

    /// Add a typed route whose wire parser can distinguish a real protocol
    /// frame from an ordinary DM that begins with the same bytes.
    #[must_use]
    pub fn with_validated_typed_payload_route(
        mut self,
        prefix: impl Into<Vec<u8>>,
        sender: mpsc::Sender<DmTypedPayload>,
        validator: fn(&[u8]) -> bool,
    ) -> Self {
        self.typed_payload_routes.push(DmTypedPayloadRoute {
            prefix: prefix.into(),
            sender,
            durable_completion: false,
            validator: Some(validator),
        });
        self
    }

    /// Validated route with the same durable completion contract as
    /// [`Self::with_durable_typed_payload_route`].
    #[must_use]
    pub fn with_validated_durable_typed_payload_route(
        mut self,
        prefix: impl Into<Vec<u8>>,
        sender: mpsc::Sender<DmTypedPayload>,
        validator: fn(&[u8]) -> bool,
    ) -> Self {
        self.typed_payload_routes.push(DmTypedPayloadRoute {
            prefix: prefix.into(),
            sender,
            durable_completion: true,
            validator: Some(validator),
        });
        self
    }
}

/// Prefix route for decrypted DM payloads.
#[derive(Clone)]
pub struct DmTypedPayloadRoute {
    pub prefix: Vec<u8>,
    pub sender: mpsc::Sender<DmTypedPayload>,
    /// Whether this route's handler resolves [`DmTypedPayload::completion`],
    /// and may therefore back a durable v2 ACK (ADR 0030 §7).
    pub durable_completion: bool,
    /// Parser for this route's complete payload, including the prefix.
    /// Returning false leaves the bytes on the generic DM path.
    pub validator: Option<fn(&[u8]) -> bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypedRouteOutcome {
    Recognized,
    RejectedPrefix,
    NoPrefix,
}

/// What a typed-route handler reports once it has durably recorded a payload.
///
/// Mirrors the history store's own vocabulary deliberately: these are the two
/// outcomes that prove exactly one durable record exists for the request, and
/// they are the only two that let the inbox emit a v2 ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmTypedPayloadCompletion {
    /// Newly recorded in the handler's durable store.
    Inserted,
    /// Already present — an idempotent replay of the same logical request.
    Duplicate,
}

/// Outcome a handler sends back on [`DmTypedPayload::completion`]. `Err`
/// carries a reason for the trace; it withholds the ACK exactly like a
/// dropped channel does.
pub type DmTypedPayloadCompletionResult = Result<DmTypedPayloadCompletion, String>;

/// A decrypted, verified DM payload routed before generic direct-message fan-out.
///
/// Deliberately NOT `Clone`: `completion` holds a `oneshot::Sender`, which has
/// no meaningful copy — two clones could not both answer the receiver, and
/// cloning would silently drop one caller's receipt.
#[derive(Debug)]
pub struct DmTypedPayload {
    pub sender: AgentId,
    pub machine_id: MachineId,
    pub payload: Vec<u8>,
    pub verified: bool,
    pub trust_decision: Option<TrustDecision>,
    pub received_at_unix_ms: u64,
    /// Logical request id of the envelope that carried this payload, so a
    /// handler can dedupe on `(sender, request_id)` across restart.
    pub request_id: [u8; 16],
    /// Present only for a durable (v2) payload on a route that opted in.
    /// Resolving it with `Inserted`/`Duplicate` is what releases the v2 ACK;
    /// dropping it withholds the ACK, which is the safe default on any
    /// handler path that returns early.
    pub completion: Option<oneshot::Sender<DmTypedPayloadCompletionResult>>,
}

pub struct DmInboxService {
    handles: Vec<JoinHandle<()>>,
    topic: String,
    pipeline: InboxPipeline,
}

/// One durable (v2) ACK envelope awaiting publication on both routes.
struct AckPublishJob {
    recipient: AgentId,
    acked_request_id: [u8; 16],
    protocol_version: u16,
    encoded: Bytes,
}

#[derive(Clone)]
struct AckPublisherHandle {
    sender: mpsc::Sender<AckPublishJob>,
}

impl AckPublisherHandle {
    /// Hand a job to the worker without ever blocking the inbox loop. A full
    /// queue is reported, never awaited: the receiver has already committed
    /// and the sender will time out, which is the documented safe failure —
    /// whereas blocking here would stall every later DM behind one wedged ACK.
    fn try_publish(&self, job: AckPublishJob) -> NetworkResult<()> {
        self.sender.try_send(job).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => NetworkError::RemoteReceiveBackpressured(
                "durable ACK publisher queue is full".to_string(),
            ),
            mpsc::error::TrySendError::Closed(_) => {
                NetworkError::ChannelClosed("durable ACK publisher stopped".to_string())
            }
        })
    }
}

/// Legacy shared DM transport topic. New sends use per-recipient inbox
/// topics; this listener remains so rolling upgrades can still receive
/// envelopes from older daemons.
pub const DM_BUS_TOPIC: &str = "x0x/dm/v1/bus";
const DM_INBOX_TOPIC_NAME_PREFIX: &str = "x0x/dm/v1/inbox/";

/// Topic ids that may receive one Full/bootstrap eager prefer (C5b).
///
/// C0 stays: this list is inbox plus (unless opted out) the compatibility bus.
/// Unsubscribed pass-through / GRAFT piggyback is not re-enabled here.
pub(crate) fn ack_publish_eager_topics(recipient: &AgentId, skip_legacy_bus: bool) -> Vec<TopicId> {
    let mut topics = vec![dm_inbox_topic(recipient)];
    if !skip_legacy_bus {
        topics.push(TopicId::from_entity(DM_BUS_TOPIC.as_bytes()));
    }
    topics
}

impl DmInboxService {
    /// Human-readable name for the agent's raw derived DM inbox topic.
    #[must_use]
    pub fn inbox_topic_name(agent_id: &AgentId) -> String {
        format!(
            "{DM_INBOX_TOPIC_NAME_PREFIX}{}",
            hex::encode(dm_inbox_topic(agent_id).to_bytes())
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        machine_keypair: Arc<MachineKeypair>,
        kem_keypair: Arc<AgentKemKeypair>,
        dm: Arc<DirectMessaging>,
        contacts: Arc<RwLock<ContactStore>>,
        inflight: Arc<InFlightAcks>,
        cache: Arc<RecentDeliveryCache>,
        config: DmInboxConfig,
        revocation_set: Arc<RwLock<RevocationSet>>,
        move_state: Arc<RwLock<crate::key_move::MoveState>>,
        authenticated_machine_bindings: AuthenticatedMachineBindings,
        history: Option<crate::history::HistoryHandle>,
    ) -> NetworkResult<Self> {
        Self::spawn_with_hedge(
            pubsub,
            signing,
            self_agent_id,
            self_machine_id,
            machine_keypair,
            kem_keypair,
            dm,
            contacts,
            inflight,
            cache,
            config,
            revocation_set,
            move_state,
            authenticated_machine_bindings,
            history,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn spawn_with_hedge(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        machine_keypair: Arc<MachineKeypair>,
        kem_keypair: Arc<AgentKemKeypair>,
        dm: Arc<DirectMessaging>,
        contacts: Arc<RwLock<ContactStore>>,
        inflight: Arc<InFlightAcks>,
        cache: Arc<RecentDeliveryCache>,
        config: DmInboxConfig,
        revocation_set: Arc<RwLock<RevocationSet>>,
        move_state: Arc<RwLock<crate::key_move::MoveState>>,
        authenticated_machine_bindings: AuthenticatedMachineBindings,
        history: Option<crate::history::HistoryHandle>,
        direct_hedge: Option<Arc<dyn DirectAckHedge>>,
    ) -> NetworkResult<Self> {
        Self::spawn_with_hedge_options(
            pubsub,
            signing,
            self_agent_id,
            self_machine_id,
            machine_keypair,
            kem_keypair,
            dm,
            contacts,
            inflight,
            cache,
            config,
            revocation_set,
            move_state,
            authenticated_machine_bindings,
            history,
            direct_hedge,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn spawn_with_hedge_options(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        machine_keypair: Arc<MachineKeypair>,
        kem_keypair: Arc<AgentKemKeypair>,
        dm: Arc<DirectMessaging>,
        contacts: Arc<RwLock<ContactStore>>,
        inflight: Arc<InFlightAcks>,
        cache: Arc<RecentDeliveryCache>,
        config: DmInboxConfig,
        revocation_set: Arc<RwLock<RevocationSet>>,
        move_state: Arc<RwLock<crate::key_move::MoveState>>,
        authenticated_machine_bindings: AuthenticatedMachineBindings,
        history: Option<crate::history::HistoryHandle>,
        direct_hedge: Option<Arc<dyn DirectAckHedge>>,
        skip_legacy_bus: bool,
    ) -> NetworkResult<Self> {
        let topic = Self::inbox_topic_name(&self_agent_id);
        let subscription = pubsub
            .subscribe_topic_id(topic.clone(), dm_inbox_topic(&self_agent_id))
            .await;
        pubsub.set_skip_legacy_dm_bus(skip_legacy_bus);
        let legacy_subscription = if skip_legacy_bus {
            None
        } else {
            Some(pubsub.subscribe(DM_BUS_TOPIC.to_string()).await)
        };
        let (ack_publisher, ack_worker) = spawn_durable_ack_publisher(
            Arc::clone(&pubsub),
            Arc::clone(&dm),
            direct_hedge,
            skip_legacy_bus,
        );

        let pipeline = InboxPipeline {
            pubsub: Arc::clone(&pubsub),
            signing,
            self_agent_id,
            self_machine_id,
            machine_keypair,
            kem_keypair,
            dm,
            contacts,
            inflight,
            cache,
            silent_reject: config.silent_reject,
            typed_payload_routes: config.typed_payload_routes,
            share_grant_gate: config.share_grant_gate,
            revocation_set,
            move_state,
            authenticated_machine_bindings,
            history,
            ack_publisher,
            unattested_revocation_warn: std::sync::Arc::new(std::sync::Mutex::new(
                UnattestedWarnLog::default(),
            )),
            unattested_overflow_warn: std::sync::Arc::new(std::sync::Mutex::new(
                UnattestedWarnLog::default(),
            )),
        };

        let mut handles = vec![spawn_subscription_loop(
            topic.clone(),
            false,
            subscription,
            pipeline.clone(),
        )];
        if let Some(legacy_subscription) = legacy_subscription {
            handles.push(spawn_subscription_loop(
                DM_BUS_TOPIC.to_string(),
                true,
                legacy_subscription,
                pipeline.clone(),
            ));
        }

        Ok(Self {
            // Aborting the worker drops its JoinSet, which aborts all owned
            // route publications. A graceful channel close drains them.
            handles: {
                handles.push(ack_worker);
                handles
            },
            topic,
            pipeline,
        })
    }

    /// Ingest a Direct/typed payload if it is the same v2 ACK envelope.
    ///
    /// Returns `true` when the bytes decoded as an ACK (whether or not a
    /// waiter was still registered). Direct send-ok is not a receipt; this
    /// is the request_id path the sender waiter actually completes on.
    pub async fn try_ingest_direct_ack(
        &self,
        sender: AgentId,
        sender_public_key: Vec<u8>,
        payload: Bytes,
    ) -> bool {
        self.pipeline
            .ingest_direct_ack_envelope(sender, sender_public_key, payload)
            .await
    }

    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub(crate) fn typed_payload_routes(&self) -> &[DmTypedPayloadRoute] {
        &self.pipeline.typed_payload_routes
    }

    pub fn abort(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

impl Drop for DmInboxService {
    fn drop(&mut self) {
        self.abort();
    }
}

/// #461: production dispatch for a subscription-delivered message. The
/// ingress label is selected HERE, by production code — `spawn_subscription_loop`
/// and the #461 controls drive this same seam; callers never choose the
/// label, so a loop-label regression cannot hide behind a test-supplied one.
async fn dispatch_subscription_message(
    pipeline: &InboxPipeline,
    message: PubSubMessage,
    ack_legacy_bus: bool,
) {
    pipeline
        .handle_incoming(
            message,
            ack_legacy_bus,
            crate::dm::DmAckIngress::Subscription,
        )
        .await
}

fn spawn_subscription_loop(
    topic_for_task: String,
    ack_legacy_bus: bool,
    mut subscription: Subscription,
    pipeline: InboxPipeline,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(topic = %topic_for_task, "DM inbox service subscribed");
        while let Some(message) = subscription.recv().await {
            dispatch_subscription_message(&pipeline, message, ack_legacy_bus).await;
        }
        tracing::debug!(topic = %topic_for_task, "DM inbox subscription closed");
    })
}

fn spawn_durable_ack_publisher(
    pubsub: Arc<PubSubManager>,
    dm: Arc<DirectMessaging>,
    direct_hedge: Option<Arc<dyn DirectAckHedge>>,
    skip_legacy_bus: bool,
) -> (AckPublisherHandle, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel(DURABLE_ACK_QUEUE_CAPACITY);
    let worker = spawn_ack_publish_worker(receiver, move |job| {
        let pubsub = Arc::clone(&pubsub);
        let dm = Arc::clone(&dm);
        let direct_hedge = direct_hedge.clone();
        async move {
            publish_durable_ack_job(pubsub, dm, direct_hedge, skip_legacy_bus, job).await;
        }
    });
    (AckPublisherHandle { sender }, worker)
}

/// Generic over the publish closure so the worker's queue and concurrency
/// behaviour can be tested without a live pubsub mesh.
fn spawn_ack_publish_worker<Publish, PublishFuture>(
    mut receiver: mpsc::Receiver<AckPublishJob>,
    publish: Publish,
) -> JoinHandle<()>
where
    Publish: Fn(AckPublishJob) -> PublishFuture + Send + Sync + 'static,
    PublishFuture: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let publish = Arc::new(publish);
        let mut in_flight = JoinSet::new();

        loop {
            if in_flight.len() >= DURABLE_ACK_MAX_CONCURRENT {
                if let Some(result) = in_flight.join_next().await {
                    log_ack_publish_join_result(result);
                }
                continue;
            }

            tokio::select! {
                biased;
                Some(result) = in_flight.join_next(), if !in_flight.is_empty() => {
                    log_ack_publish_join_result(result);
                }
                job = receiver.recv() => {
                    let Some(job) = job else {
                        break;
                    };
                    let publish = Arc::clone(&publish);
                    in_flight.spawn(async move {
                        publish(job).await;
                    });
                }
            }
        }

        // Graceful closure drains accepted jobs. DmInboxService::abort aborts
        // this owner task; dropping JoinSet then aborts every child promptly.
        while let Some(result) = in_flight.join_next().await {
            log_ack_publish_join_result(result);
        }
    })
}

fn log_ack_publish_join_result(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        tracing::warn!(
            target: "dm.trace",
            stage = "ack_publish_worker_failed",
            %error,
            "durable ACK publisher task failed"
        );
    }
}

async fn publish_durable_ack_job(
    pubsub: Arc<PubSubManager>,
    dm: Arc<DirectMessaging>,
    direct_hedge: Option<Arc<dyn DirectAckHedge>>,
    skip_legacy_bus: bool,
    job: AckPublishJob,
) {
    // C5b: prefer one Full/bootstrap eager on inbox+bus only. Does not
    // re-enable unsubscribed pass-through / GRAFT piggyback (C0).
    pubsub
        .prefer_one_full_bootstrap_eager(&ack_publish_eager_topics(&job.recipient, skip_legacy_bus))
        .await;

    let topic = DmInboxService::inbox_topic_name(&job.recipient);
    let topic_id = dm_inbox_topic(&job.recipient);
    let encoded_primary = Bytes::clone(&job.encoded);
    let encoded_legacy = Bytes::clone(&job.encoded);
    let primary_pubsub = Arc::clone(&pubsub);
    let legacy_pubsub = Arc::clone(&pubsub);
    // Owned clones so each route can be spawned independently. First-success
    // must detach the sibling, not cancel it — otherwise a healthy second
    // publish is dropped before it delivers.
    let primary = async move {
        primary_pubsub
            .publish_topic_id(topic, topic_id, encoded_primary)
            .await
    };
    // The default durable path hedges onto the compatibility bus, even when
    // the payload did not arrive there. A v2 sender has already been promised
    // a committed row; a second route costs one small publish and removes a
    // whole class of "committed but never acked" outcomes. Opt-out keeps only
    // the targeted route here so this node does not rejoin the bus.
    let legacy = async move {
        legacy_pubsub
            .publish(DM_BUS_TOPIC.to_string(), encoded_legacy)
            .await
    };
    // C5: same v2 ACK envelope on live Direct/typed as a third hedge.
    // Detached from gossip: missing Direct is fail-open, and Direct send-ok
    // is not a sender receipt. Do not abort sibling gossip routes.
    // `direct_hedge_was_sent` distinguishes Sent from SkippedNoDirect for
    // the (c) outcome counters.
    let direct_hedge_was_sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let direct = {
        let sent_flag = Arc::clone(&direct_hedge_was_sent);
        let hedge = direct_hedge.clone();
        let recipient = job.recipient;
        let encoded = Bytes::clone(&job.encoded);
        async move {
            let Some(hedge) = hedge else {
                return Ok(());
            };
            match hedge.hedge(recipient, encoded).await {
                DirectAckHedgeOutcome::Sent => {
                    sent_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                }
                DirectAckHedgeOutcome::SkippedNoDirect => Ok(()),
                DirectAckHedgeOutcome::Failed => Err(NetworkError::ConnectionFailed(
                    "direct ACK hedge failed".to_string(),
                )),
            }
        }
    };
    let publish_started = Instant::now();
    let gossip_routes = async {
        if skip_legacy_bus {
            publish_ack_route_with_timeout("targeted", DURABLE_ACK_ROUTE_TIMEOUT, primary).await
        } else {
            publish_durable_ack_routes(DURABLE_ACK_ROUTE_TIMEOUT, primary, legacy).await
        }
    };
    let (gossip, direct_outcome) = tokio::join!(
        gossip_routes,
        publish_ack_route_with_timeout("direct-typed", DURABLE_ACK_ROUTE_TIMEOUT, direct),
    );
    dm.record_ack_publish_ms(crate::dm::millis_since(publish_started));
    // #380 leaf-reverse-ACK fix (c): count gossip and Direct hedge outcomes
    // SEPARATELY so /diagnostics/dm distinguishes "gossip routes dead,
    // Direct saved it" from "all dead". The old code incremented the same
    // ack_publish_route_failed counter for gossip failure AND direct
    // failure, and warned "ACK never left" even when Direct had Sent —
    // the 3/3 fleet reading was ambiguous.
    let direct_sent = matches!(direct_outcome, Ok(()))
        && direct_hedge_was_sent.load(std::sync::atomic::Ordering::Relaxed);
    match (gossip, direct_outcome) {
        (Ok(()), _) => {
            dm.record_ack_gossip_route_succeeded();
            if direct_sent {
                dm.record_ack_direct_hedge(crate::direct::AckDirectHedgeOutcomeRecord::Sent);
            }
        }
        (Err(error), Ok(())) => {
            // Gossip failed but the Direct hedge fired — the ACK still had a
            // route. Count the gossip failure for visibility; Direct carries
            // the receipt.
            dm.record_ack_gossip_route_failed();
            if direct_sent {
                dm.record_ack_direct_hedge(
                    crate::direct::AckDirectHedgeOutcomeRecord::SavedFailure,
                );
            } else {
                dm.record_ack_direct_hedge(
                    crate::direct::AckDirectHedgeOutcomeRecord::SkippedOrNoDirect,
                );
            }
            tracing::warn!(
                target: "dm.trace",
                stage = "ack_gossip_routes_failed_direct_hedge",
                acked_request_id = %hex::encode(job.acked_request_id),
                recipient = %hex::encode(job.recipient.as_bytes()),
                direct_sent,
                %error,
                "gossip ACK routes failed; Direct hedge state recorded separately"
            );
        }
        (Err(error), Err(direct_error)) => {
            // All routes dead — the ACK genuinely never left.
            dm.record_ack_gossip_route_failed();
            dm.record_ack_direct_hedge(crate::direct::AckDirectHedgeOutcomeRecord::Failed);
            tracing::warn!(
                target: "dm.trace",
                stage = "ack_publish_all_routes_failed",
                acked_request_id = %hex::encode(job.acked_request_id),
                recipient = %hex::encode(job.recipient.as_bytes()),
                protocol_version = job.protocol_version,
                gossip_error = %error,
                direct_error = %direct_error,
                "both gossip routes AND the Direct hedge failed; ACK never left this recipient"
            );
        }
    }
}

/// Choose Direct/typed hedge outcome without treating send-ok as a receipt.
#[cfg(test)]
pub(crate) fn direct_ack_hedge_outcome(
    connected: bool,
    send_ok: Option<bool>,
) -> DirectAckHedgeOutcome {
    match (connected, send_ok) {
        (false, _) => DirectAckHedgeOutcome::SkippedNoDirect,
        (true, Some(true)) => DirectAckHedgeOutcome::Sent,
        (true, _) => DirectAckHedgeOutcome::Failed,
    }
}

/// Pre-warm PlumTree membership for the reverse-ACK topics used by a
/// durable send to `peer`.
///
/// Joins (1) this agent's inbox (where ACKs land), (2) the peer's inbox,
/// and (unless the manager opted out) (3) the compatibility bus. C2 refreshes
/// those topic ids on the subscribed path. C4 also pre-subscribes the peer
/// inbox so the first durable POST is not a cold `publish_topic_id` join.
/// Does not walk pass-through topics (Leaf-safe; C0/#395 hygiene).
pub(crate) async fn warm_reverse_ack_topics(
    pubsub: &PubSubManager,
    self_agent: &AgentId,
    peer: &AgentId,
) {
    if !should_warm_reverse_ack(true, self_agent, peer) {
        return;
    }
    pubsub
        .ensure_subscribed_topic_id(
            &DmInboxService::inbox_topic_name(self_agent),
            dm_inbox_topic(self_agent),
        )
        .await;
    // C4: peer inbox must be subscribed, not merely initialized, before
    // the first durable publish_topic_id.
    pubsub
        .ensure_subscribed_topic_id(
            &DmInboxService::inbox_topic_name(peer),
            dm_inbox_topic(peer),
        )
        .await;
    if pubsub.skip_legacy_dm_bus() {
        return;
    }
    pubsub
        .ensure_subscribed_topic_id(
            DM_BUS_TOPIC,
            saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes()),
        )
        .await;
}

/// Reverse-ACK pre-warm is for a Trusted *other* peer. Self and untrusted
/// peers must not join extra inbox topics on connect.
pub(crate) fn should_warm_reverse_ack(trusted: bool, self_agent: &AgentId, peer: &AgentId) -> bool {
    trusted && self_agent != peer
}

async fn publish_durable_ack_routes<Primary, Legacy>(
    route_timeout: Duration,
    primary: Primary,
    legacy: Legacy,
) -> NetworkResult<()>
where
    Primary: std::future::Future<Output = NetworkResult<()>>,
    Legacy: std::future::Future<Output = NetworkResult<()>>,
{
    // #396 rework: C1 (first-success hedge) was removed — the joint review
    // decided the post-commit Direct/typed hedge (C5, PR #408) supersedes
    // it. This restores main's join!-both semantics unchanged: a targeted
    // inbox publish can deliver remotely yet remain pending under
    // per-topic fan-out backpressure, so both routes are polled with their
    // own deadlines and BOTH must succeed (a wedged sibling fails at its
    // deadline instead of pinning this serial inbox loop). The residual
    // 504 `budget_stage=ack_wait_ms` pressure is addressed by C2/C4
    // pre-warm (below) plus the C5 direct hedge in #408.
    let (primary, legacy) = tokio::join!(
        publish_ack_route_with_timeout("targeted", route_timeout, primary),
        publish_ack_route_with_timeout("legacy-bus", route_timeout, legacy),
    );
    primary.and(legacy)
}

async fn publish_ack_route_with_timeout<Route>(
    route: &'static str,
    route_timeout: Duration,
    publish: Route,
) -> NetworkResult<()>
where
    Route: std::future::Future<Output = NetworkResult<()>>,
{
    match tokio::time::timeout(route_timeout, publish).await {
        Ok(result) => result,
        Err(_) => Err(NetworkError::BroadcastError(format!(
            "ACK {route} publish timed out after {route_timeout:?}"
        ))),
    }
}

#[derive(Clone)]
pub(crate) struct InboxPipeline {
    pubsub: Arc<PubSubManager>,
    signing: Arc<SigningContext>,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    /// This machine's keypair — signs the #213 origin attestation embedded
    /// in outbound ACK envelopes, so ACK receivers authenticate the
    /// acking machine exactly like payload-DM receivers do.
    machine_keypair: Arc<MachineKeypair>,
    kem_keypair: Arc<AgentKemKeypair>,
    dm: Arc<DirectMessaging>,
    contacts: Arc<RwLock<ContactStore>>,
    inflight: Arc<InFlightAcks>,
    cache: Arc<RecentDeliveryCache>,
    silent_reject: bool,
    typed_payload_routes: Vec<DmTypedPayloadRoute>,
    /// ADR-0070 §2 share-grant DM-acceptance gate (`None` ⇒ no grants).
    share_grant_gate: Option<crate::share_grant::ShareGrantDmGate>,
    /// Shared revocation set for enforcement point 3.
    revocation_set: Arc<RwLock<RevocationSet>>,
    /// ADR-0043 derived move state — the B/P pairing gate reads the
    /// placement view beside the revocation set.
    move_state: Arc<RwLock<crate::key_move::MoveState>>,
    /// Authenticated origin-machine bindings retained across discovery eviction.
    authenticated_machine_bindings: AuthenticatedMachineBindings,
    /// ADR-0023 history handle. Recording is `try_send`-only — this loop
    /// must never block (see the typed-route comment below).
    history: Option<crate::history::HistoryHandle>,
    /// Bounded background publisher for durable (v2) ACK envelopes.
    ack_publisher: AckPublisherHandle,
    /// Per-sender rate limit for unattested revocation warnings.
    unattested_revocation_warn: std::sync::Arc<std::sync::Mutex<UnattestedWarnLog>>,
    /// Per-sender rate limit for unattested overflow warnings.
    unattested_overflow_warn: std::sync::Arc<std::sync::Mutex<UnattestedWarnLog>>,
}

impl InboxPipeline {
    /// Ingest a Direct/typed payload only when it is an ACK envelope.
    ///
    /// Reuses the gossip ACK path so the waiter still keys on
    /// `acks_request_id`. Returns `true` iff the payload decoded as an ACK
    /// (callers must not fan it out as a user DM).
    async fn ingest_direct_ack_envelope(
        &self,
        sender: AgentId,
        sender_public_key: Vec<u8>,
        payload: Bytes,
    ) -> bool {
        let Ok(envelope) = DmEnvelope::from_wire_bytes(&payload) else {
            return false;
        };
        if !matches!(envelope.body, DmBody::Ack(_)) {
            return false;
        }
        if envelope.sender_agent_id != *sender.as_bytes() {
            return false;
        }
        let message = PubSubMessage {
            topic: String::from("direct-typed-ack-hedge"),
            payload,
            sender: Some(sender),
            sender_public_key: Some(sender_public_key),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        self.handle_incoming(message, false, crate::dm::DmAckIngress::DirectTyped)
            .await;
        true
    }
}

/// Re-ACK semantics for a logical request that already completed.
///
/// ADR 0030 §2: a request completed under weaker semantics is answered
/// `AckSemanticsUnavailable`, never re-ACKed as durable — otherwise a v2
/// sender racing a v1 delivery of the same request would be handed a durable
/// receipt nobody made.
fn cached_ack_for_protocol(
    cached: &crate::dm::CachedOutcome,
    requested_protocol: u16,
) -> DmAckOutcome {
    if cached.protocol_version >= requested_protocol {
        cached.outcome.clone()
    } else {
        DmAckOutcome::AckSemanticsUnavailable {
            reason: format!(
                "logical request already completed under v{} semantics",
                cached.protocol_version
            ),
        }
    }
}

/// Whether `handle_incoming`'s fast replay re-ACK must stand aside and let the
/// durable path decide.
///
/// True only for a v2 payload envelope replaying a completion that carries a
/// durable binding — the one case where the correct answer depends on bytes
/// this stage has not decrypted yet. Everything else (v1 replays, ACK
/// envelopes, completions with no binding) keeps the cheap path, so the cost
/// of a signature verification and a decrypt is paid only where it buys the
/// ADR 0030 §1 conflict check.
fn cached_completion_needs_binding_check(
    cached: Option<&crate::dm::CachedOutcome>,
    envelope: &DmEnvelope,
) -> bool {
    matches!(envelope.body, DmBody::Payload(_))
        && envelope.protocol_version >= DM_PROTOCOL_DURABLE_ACK
        && cached.is_some_and(|cached| cached.durable_binding.is_some())
}

/// A commit outcome that proves exactly one durable row exists for this
/// record. `Inserted` is the first commit; `Duplicate` is the idempotent
/// replay of an identical record (ADR 0030 validation: "exactly one durable
/// history row (`Duplicate` re-ACK)"). Anything else means the row we
/// promised is not the row that is there, so the ACK must be withheld.
fn exact_durable_history_outcome(outcome: crate::history::InsertOutcome) -> bool {
    matches!(
        outcome,
        crate::history::InsertOutcome::Inserted | crate::history::InsertOutcome::Duplicate
    )
}

/// Build the ADR-0023 history row for a verified inbound DM.
///
/// `Ok(None)` means the payload classifies `Ephemeral` — protocol plumbing
/// whose durable effect lives in its own store, never in DM history.
///
/// Schema v4 (`ingress_sender_agent`, `logical_request_id`) is populated here:
/// together they key the ADR 0030 §1 durable-history lookup, which is what
/// lets a receiver recognise a logical request it has already committed.
fn inbound_dm_history_record(
    envelope: &DmEnvelope,
    application_payload: &[u8],
    sender_machine_id: MachineId,
    sender_pubkey: &[u8],
    rejected_typed_prefix: bool,
) -> Result<Option<crate::history::HistoryRecord>, String> {
    let class = if rejected_typed_prefix {
        crate::history::classify::classify_ordinary_dm_payload(application_payload)
    } else {
        crate::history::classify::classify_dm_payload(application_payload)
    };
    let crate::history::classify::DmPayloadClass::Durable(content_type) = class else {
        return Ok(None);
    };
    let artifact = envelope.to_wire_bytes().map_err(|e| e.to_string())?;
    Ok(Some(crate::history::HistoryRecord {
        msg_id: crate::history::HistoryRecord::compute_msg_id(Some(&artifact), application_payload),
        scope: crate::history::Scope::Dm(hex::encode(envelope.sender_agent_id)),
        author_agent: Some(hex::encode(envelope.sender_agent_id)),
        author_machine: Some(hex::encode(sender_machine_id.as_bytes())),
        author_pubkey: Some(sender_pubkey.to_vec()),
        sent_at_ms: i64::try_from(envelope.created_at_unix_ms).unwrap_or(i64::MAX),
        seen_at_ms: i64::try_from(now_unix_ms()).unwrap_or(i64::MAX),
        direction: crate::history::Direction::Inbound,
        content_type: content_type.to_string(),
        payload: application_payload.to_vec(),
        signed_artifact: Some(artifact),
        signature: Some(envelope.signature.clone()),
        // Mirrors `DM_SIGN_DOMAIN` in `dm.rs`.
        sig_context: Some("x0x-dm-v1".to_string()),
        provenance: crate::history::Provenance::VerifiedEnvelope,
        replace_key: None,
        thread_root: None,
        thread_parent: None,
        ingress_sender_agent: Some(hex::encode(envelope.sender_agent_id)),
        logical_request_id: Some(envelope.request_id),
    }))
}

/// What the receiver durable path decided for one v2 envelope.
///
/// Returned rather than inferred from side effects so the commit-before-ACK
/// ordering is directly assertable: "no ACK when the commit fails" is the
/// central promise of ADR 0030 §1 and must not be tested by proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableAckDecision {
    /// An ACK was emitted with these semantics. `accepted` distinguishes a
    /// delivery receipt from a refusal; a refusal never claims durability.
    Acked {
        protocol_version: u16,
        accepted: bool,
    },
    /// No ACK was emitted — the sender times out. The stage names why.
    Withheld(&'static str),
}

/// Result of the ADR 0030 §1 durable-history lookup for one logical request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableLogicalRequestLookup {
    /// No durable row for this `(sender, request_id)` yet.
    Missing,
    /// A durable row exists and binds exactly the bytes now being accepted.
    Exact,
    /// A durable row exists under this logical request but binds different
    /// bytes — the sender reused a request id for different content.
    Conflict,
}

/// Durable-history lookup keyed on the schema v4 columns this path writes.
///
/// Runs on `spawn_blocking`: `Store` is synchronous SQLite and this is called
/// from the inbox task.
async fn durable_history_logical_request(
    history: &crate::history::HistoryHandle,
    sender: AgentId,
    request_id: [u8; 16],
    accepted_payload: Vec<u8>,
) -> crate::error::HistoryResult<DurableLogicalRequestLookup> {
    let store = Arc::clone(history.store());
    let ingress = hex::encode(sender.as_bytes());
    crate::history::run_blocking(move || {
        let rows = store.find_by_logical_request(&ingress, request_id)?;
        if rows.is_empty() {
            return Ok(DurableLogicalRequestLookup::Missing);
        }
        if rows
            .iter()
            .any(|row| row.record.payload != accepted_payload)
        {
            return Ok(DurableLogicalRequestLookup::Conflict);
        }
        Ok(DurableLogicalRequestLookup::Exact)
    })
    .await
    .map_err(|error| {
        crate::error::HistoryError::Database(format!("logical request lookup task failed: {error}"))
    })?
}

impl InboxPipeline {
    /// Hold no contacts lock across the probe. Re-read the contact bit if a
    /// concurrent resolve wins the epoch.
    async fn with_sender_standing<T>(
        &self,
        agent: AgentId,
        body: impl FnOnce(&mut AuthenticatedMachineBindingCache) -> T,
    ) -> T {
        with_contact_standing(
            &self.authenticated_machine_bindings,
            &self.contacts,
            agent,
            body,
        )
        .await
    }

    /// Move the retained binding so a share-grant check sees this origin.
    /// Does not take an attribution slot.
    async fn refresh_admitted_origin(&self, agent: AgentId, machine: MachineId, announced_at: u64) {
        self.with_sender_standing(agent, |cache| {
            cache.refresh_retained_origin(agent, machine, announced_at);
        })
        .await;
    }

    /// Record attribution after decryption succeeded, or after an admitted
    /// ACK matched a waiter. A refused or undecryptable DM does not take a slot.
    /// A retained origin that this call admits does take a slot.
    async fn remember_admitted_origin(&self, agent: AgentId, machine: MachineId) {
        self.with_sender_standing(agent, |cache| {
            cache.remember_accepted_machine(agent, machine);
        })
        .await;
    }

    /// Record a machine whose standing was resolved earlier in this DM.
    /// Does not run the relationship probe again.
    async fn remember_resolved_origin(&self, agent: AgentId, machine: MachineId) {
        self.authenticated_machine_bindings
            .write()
            .await
            .remember_accepted_machine(agent, machine);
    }

    /// Record the retained binding and attribution together. Used for an
    /// admitted ACK, which has no ciphertext of its own.
    async fn attribute_admitted_origin(
        &self,
        agent: AgentId,
        machine: MachineId,
        announced_at: u64,
    ) {
        self.with_sender_standing(agent, |cache| {
            cache.record(agent, machine, announced_at);
        })
        .await;
    }

    /// #1659: how an unattested DM from `agent` is treated.
    ///
    /// Attribution is every machine the authenticated-binding cache has
    /// accepted for the sender (the retained binding and any machine a
    /// later binding replaced), a contact machine, a binding tombstone, or
    /// the machine the envelope claims. Locks are taken one at a time.
    /// Overflow refuses only when this agent already holds a machine
    /// revocation. It does not refuse a sender with none.
    async fn unattested_sender_attribution(
        &self,
        agent: AgentId,
        retained: Option<MachineId>,
        claimed: MachineId,
    ) -> UnattestedAttribution {
        let refresh = {
            let cache = self.authenticated_machine_bindings.read().await;
            cache.stranger_pin_cap_full() && cache.revoked_unpinned_by_agent.contains_key(&agent)
        };
        if refresh {
            let mut cache = self.authenticated_machine_bindings.write().await;
            cache.refresh_unpinned_agent(agent);
        }
        let (
            accepted_machines,
            attribution_overflowed,
            stored_standing,
            dropped_or_unpinned,
            probe,
        ) = {
            let cache = self.authenticated_machine_bindings.read().await;
            (
                cache.machines_accepted_for(&agent),
                cache.attribution_requires_attestation(&agent),
                cache.standing_of(agent),
                cache.stranger_pin_cap_refuses_unattested(agent),
                cache.relationship_probe.clone(),
            )
        };
        let (contact, contact_machines): (bool, Vec<MachineId>) = {
            let store = self.contacts.read().await;
            let contact = contact_is_protected(&store, agent);
            let machines = store
                .machines(&agent)
                .iter()
                .map(|record| record.machine_id)
                .collect();
            (contact, machines)
        };
        let standing =
            standing_from_probe(contact, probe_view(probe.as_ref(), agent), stored_standing);
        let revoked = self.revocation_set.read().await;
        let decision = sender_unattested_attribution(
            &revoked,
            &agent,
            retained,
            claimed,
            &contact_machines,
            &accepted_machines,
            attribution_overflowed,
        );
        if standing == AttributionStanding::Stranger
            && dropped_or_unpinned
            && decision == UnattestedAttribution::Allow
        {
            UnattestedAttribution::DroppedRevokedPair
        } else {
            decision
        }
    }

    async fn handle_incoming(
        &self,
        msg: PubSubMessage,
        ack_legacy_bus: bool,
        ack_ingress: crate::dm::DmAckIngress,
    ) {
        let (pubsub_sender, sender_pubkey) = match (msg.sender, msg.sender_public_key.as_deref()) {
            (Some(s), Some(pk)) if msg.verified => (s, pk.to_vec()),
            _ => {
                // Real unverified-drop site (issue #296): count here before
                // discarding so the server-layer typed-payload handler never
                // sees these messages and does not need its own copy of this
                // check.
                self.dm.record_incoming_signature_failed();
                tracing::debug!(
                    target: "dm.trace",
                    stage = "inbound_unverified_drop",
                    "dropped unverified pubsub message before envelope decode"
                );
                return;
            }
        };

        if msg.payload.len() > MAX_ENVELOPE_BYTES {
            self.dm.record_incoming_decode_failed();
            return;
        }

        let envelope = match DmEnvelope::from_wire_bytes(&msg.payload) {
            Ok(e) => e,
            Err(_) => {
                self.dm.record_incoming_decode_failed();
                return;
            }
        };

        // ADR 0030 §2 receiver ceiling: an envelope above what this build
        // understands is dropped WITHOUT an ACK, so the sender times out
        // rather than being handed a receipt for semantics we cannot honour.
        if envelope.protocol_version > DM_PROTOCOL_VERSION {
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_protocol_above_ceiling_dropped",
                sender = %hex::encode(envelope.sender_agent_id),
                protocol_version = envelope.protocol_version,
                ceiling = DM_PROTOCOL_VERSION,
                "DM dropped without ACK: envelope protocol version exceeds local ceiling"
            );
            return;
        }

        let now = now_unix_ms();
        if validate_timestamp_window(
            envelope.created_at_unix_ms,
            envelope.expires_at_unix_ms,
            now,
        )
        .is_err()
        {
            return;
        }

        if envelope.recipient_agent_id != *self.self_agent_id.as_bytes() {
            return;
        }

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_envelope_received",
            request_id = %hex::encode(envelope.request_id),
            sender = %hex::encode(envelope.sender_agent_id),
            bytes = msg.payload.len(),
        );

        let dedupe = envelope.dedupe_key();
        // A v2 envelope replaying a logical request that already completed
        // durably must have its bytes compared against the committed binding
        // before anything is re-ACKed — otherwise a caller that reused a
        // `logical_id` for *different* content is told `Accepted` for bytes
        // nobody stored. That comparison needs the plaintext, which this fast
        // path does not have, so the durable path owns the whole replay
        // decision for these envelopes (it re-ACKs from the same cache entry
        // at step 2 without re-dispatching).
        let needs_durable_binding_check =
            cached_completion_needs_binding_check(self.cache.lookup(&dedupe).as_ref(), &envelope);
        if let Some(cached) = self
            .cache
            .lookup(&dedupe)
            .filter(|_| !needs_durable_binding_check)
        {
            if matches!(envelope.body, DmBody::Payload(_)) {
                // ADR 0030 §2: re-ACK under the semantics the completion was
                // actually made with. A v1 completion answers a v2 request
                // with a refusal, never with a durable-looking receipt.
                let outcome = cached_ack_for_protocol(&cached, envelope.protocol_version);
                // Accepted re-ACKs carry the semantics actually honoured;
                // refusals carry the requested version so they reach the
                // sender's exact-protocol waiter instead of timing out.
                let ack_protocol = if matches!(outcome, DmAckOutcome::Accepted) {
                    cached
                        .protocol_version
                        .min(envelope.protocol_version)
                        .max(DM_PROTOCOL_V1)
                } else {
                    envelope.protocol_version
                };
                let _ = self
                    .publish_ack_for_protocol(
                        AgentId(envelope.sender_agent_id),
                        envelope.request_id,
                        outcome,
                        ack_protocol,
                        ack_legacy_bus,
                    )
                    .await;
            }
            return;
        }

        if !verify_envelope_signature(&envelope, &sender_pubkey) {
            self.dm.record_incoming_signature_failed();
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_signature_failed",
                request_id = %hex::encode(envelope.request_id),
                sender = %hex::encode(envelope.sender_agent_id),
            );
            return;
        }

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_signature_verified",
            request_id = %hex::encode(envelope.request_id),
            sender = %hex::encode(envelope.sender_agent_id),
        );

        if envelope.sender_agent_id != *pubsub_sender.as_bytes() {
            self.dm.record_incoming_signature_failed();
            tracing::debug!(
                target: "dm.trace",
                stage = "inbound_sender_id_mismatch",
                "dropped DM: envelope sender_agent_id does not match gossip-layer sender"
            );
            return;
        }

        // Enforcement point 3 — authenticated-origin revocation gate.
        //
        // Issue #213: prefer the fresh per-DM origin-machine attestation —
        // a machine-key signature covering this envelope, verifiable with
        // ZERO prior cache state. When present and valid, and the later
        // checks admit the DM, it supersedes (and refreshes) the retained
        // binding. When present but invalid the DM is a hard drop (never
        // fall back — a bad attestation is an attack signal, not a legacy
        // peer). Only when the attestation is ABSENT
        // (pre-#213 peer) do we degrade to the #184 retained-binding check,
        // where the envelope machine claim is sender-controlled: prefer the
        // retained machine from an accepted, verified identity announcement;
        // the claim is only a best-effort fallback for agents with no
        // authenticated binding. See docs/design/adr-0021-mechanics.md.
        //
        // #1659 (David, 28 Oct 2026, 02:08 GMT, D283): when this receiver
        // can attribute a revoked machine to the sender, an absent
        // attestation is a refusal. The same rule covers an unattested
        // ACK on this lane. An ACK is delivery evidence. It is not
        // accepted from a device this receiver would refuse a DM from.
        // The trigger is the same for both: only once the agent has a
        // machine revocation. A DM records that machine only after
        // decryption succeeds. An announcement records it when the
        // announcement is accepted. An admitted ACK records it when a
        // waiter matches. A machine past the per-agent cap is not
        // recorded. Revoking that machine does not attribute it, so an
        // unattested DM or ACK that claims a different, clean machine
        // can still be accepted. A revoked stranger pin is never evicted.
        // When the stranger pin cap is full, an unattested DM or ACK is
        // refused only for an agent whose revoked pair was dropped or
        // could not be pinned. A sender this receiver cannot link to a
        // revoked machine keeps ADR 0021 policy. Stranger pairs are an
        // LRU of the pairs that are not pins. A Trusted or Known contact,
        // a group member, and a grant party are not evicted by that insert.
        let sender_agent_id = AgentId(envelope.sender_agent_id);
        let claimed_machine_id = MachineId(envelope.sender_machine_id);
        let mut fresh_attestation = false;
        //
        // #927: `origin_authenticated` records whether the resolved machine
        // came from an attestation or an authenticated binding. A bare
        // sender claim is still delivered (annotated unverified) but may
        // never mark connected or rebind DirectMessaging routing.
        let (sender_machine_id, origin_authenticated) = match envelope.verify_origin_attestation() {
            Ok(Some(attested_machine)) => {
                tracing::info!(
                    target: "dm.trace",
                    stage = "inbound_origin_attested",
                    sender = %hex::encode(envelope.sender_agent_id),
                    machine = %hex::encode(attested_machine.as_bytes()),
                    "DM origin machine authenticated by fresh machine-key attestation"
                );
                // The retained binding and the attribution set are updated
                // only after revocation, pairing, and trust checks admit
                // this DM. A refused attestation does not take a slot.
                fresh_attestation = true;
                (attested_machine, true)
            }
            Err(rejection) => {
                self.dm.record_incoming_trust_rejected(sender_agent_id);
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_origin_attestation_invalid",
                    sender = %hex::encode(envelope.sender_agent_id),
                    claimed_machine = %hex::encode(claimed_machine_id.as_bytes()),
                    rejection = %rejection,
                    "DM dropped: origin-machine attestation invalid"
                );
                return;
            }
            Ok(None) => {
                let authenticated_machine_id = self
                    .authenticated_machine_bindings
                    .write()
                    .await
                    .resolve(&sender_agent_id);
                // A claim that disagrees with the retained binding is already
                // a drop below. The refusal applies when this path would
                // otherwise accept the DM (credit the binding, or take the
                // claim fallback).
                let accepts_unattested = !matches!(
                    authenticated_machine_id,
                    Some(authenticated) if authenticated != claimed_machine_id
                );
                if accepts_unattested {
                    match self
                        .unattested_sender_attribution(
                            sender_agent_id,
                            authenticated_machine_id,
                            claimed_machine_id,
                        )
                        .await
                    {
                        UnattestedAttribution::Allow => {}
                        UnattestedAttribution::Revoked => {
                            self.dm.record_incoming_dropped_revoked();
                            warn_unattested_drop(
                                &self.unattested_revocation_warn,
                                "inbound_unattested_after_machine_revocation",
                                &envelope.sender_agent_id,
                                claimed_machine_id.as_bytes(),
                                "DM dropped: unattested after a machine revocation for this agent",
                            );
                            return;
                        }
                        UnattestedAttribution::Overflow => {
                            self.dm.record_incoming_dropped_revoked();
                            self.dm.record_incoming_dropped_attribution_overflow();
                            warn_unattested_drop(
                                &self.unattested_overflow_warn,
                                "inbound_unattested_attribution_overflow",
                                &envelope.sender_agent_id,
                                claimed_machine_id.as_bytes(),
                                "DM dropped: unattested sender has an attributed machine revocation and an overflowed attribution set",
                            );
                            return;
                        }
                        UnattestedAttribution::DroppedRevokedPair => {
                            self.dm.record_incoming_dropped_revoked();
                            self.dm.record_incoming_dropped_attribution_overflow();
                            warn_unattested_drop(
                                &self.unattested_overflow_warn,
                                "inbound_unattested_dropped_revoked_pair",
                                &envelope.sender_agent_id,
                                claimed_machine_id.as_bytes(),
                                "DM dropped: stranger pin cap is full and this sender's revoked pair was dropped or could not be pinned",
                            );
                            return;
                        }
                    }
                }
                match authenticated_machine_id {
                    Some(authenticated) if authenticated != claimed_machine_id => {
                        self.dm.record_incoming_trust_rejected(sender_agent_id);
                        tracing::warn!(
                            target: "dm.trace",
                            stage = "inbound_origin_machine_mismatch",
                            sender = %hex::encode(envelope.sender_agent_id),
                            claimed_machine = %hex::encode(claimed_machine_id.as_bytes()),
                            authenticated_machine = %hex::encode(authenticated.as_bytes()),
                            "DM dropped: envelope machine does not match authenticated origin"
                        );
                        return;
                    }
                    Some(authenticated) => (authenticated, true),
                    None => {
                        tracing::info!(
                            target: "dm.trace",
                            stage = "inbound_origin_machine_claim_fallback",
                            sender = %hex::encode(envelope.sender_agent_id),
                            claimed_machine = %hex::encode(claimed_machine_id.as_bytes()),
                            "DM origin has no attestation and no authenticated binding; checking sender claim only"
                        );
                        (claimed_machine_id, false)
                    }
                }
            }
        };

        {
            let revoked = self.revocation_set.read().await;
            if revoked.revocation_resync_required() {
                // Drop the frame. Do not queue it for delivery after resync.
                tracing::info!(
                    target: "dm.trace",
                    stage = "inbound_revocation_resync_withheld",
                    sender = %hex::encode(envelope.sender_agent_id),
                    "DM dropped during revocation resync"
                );
                return;
            }
            if drop_if_sender_revoked(&self.dm, &revoked, &sender_agent_id, &sender_machine_id) {
                tracing::info!(
                    target: "dm.trace",
                    stage = "inbound_revoked_sender_dropped",
                    sender = %hex::encode(envelope.sender_agent_id),
                    machine = %hex::encode(sender_machine_id.as_bytes()),
                    "DM dropped: sender is revoked"
                );
                return;
            }
        }

        // ADR-0043 §9: B and P on (sender, attested machine) — a moved
        // agent's late DM from the retired source pairing dies here even
        // with a fresh, valid attestation.
        {
            let revoked = self.revocation_set.read().await;
            let placements = self.move_state.read().await;
            if let Some(denial) = crate::key_move::enforce_pairing(
                &revoked,
                placements.placement_view(),
                &sender_agent_id,
                &sender_machine_id,
            ) {
                tracing::info!(
                    target: "dm.trace",
                    stage = "inbound_pairing_denied",
                    sender = %hex::encode(envelope.sender_agent_id),
                    machine = %hex::encode(sender_machine_id.as_bytes()),
                    reason = ?denial,
                    "DM dropped: ADR-0043 B/P pairing gate"
                );
                return;
            }
        }

        let admitted_at = envelope.created_at_unix_ms / 1000;
        match envelope.body.clone() {
            DmBody::Ack(ack) => {
                // The ACK's own `protocol_version` names the receipt semantics
                // the recipient is claiming; the waiter accepts it only if
                // that matches what the send negotiated (ADR 0030 §2).
                // #461: stamp the ingress of the transport that actually
                // carried this authenticated ACK (first-valid winner only).
                let resolved = self.inflight.resolve_for_ingress(
                    &ack.acks_request_id,
                    envelope.protocol_version,
                    sender_agent_id,
                    sender_machine_id,
                    ack.outcome,
                    ack_ingress,
                );
                // An unsolicited ACK, or one the trust check rejects, does
                // not take an attribution slot. There is no ciphertext to
                // wait for: a matching admitted ACK records immediately.
                let trust_admits = {
                    let store = self.contacts.read().await;
                    !matches!(
                        TrustEvaluator::new(&store).evaluate(&TrustContext {
                            agent_id: &sender_agent_id,
                            machine_id: &sender_machine_id,
                        }),
                        TrustDecision::RejectBlocked | TrustDecision::RejectMachineMismatch
                    )
                };
                if resolved && trust_admits {
                    if fresh_attestation {
                        self.attribute_admitted_origin(
                            sender_agent_id,
                            sender_machine_id,
                            admitted_at,
                        )
                        .await;
                    } else if origin_authenticated {
                        self.remember_admitted_origin(sender_agent_id, sender_machine_id)
                            .await;
                    }
                }
                tracing::debug!(
                    acked = %hex::encode(ack.acks_request_id),
                    protocol_version = envelope.protocol_version,
                    resolved,
                    "DM ACK received"
                );
            }
            DmBody::Payload(payload) => {
                let origin = if fresh_attestation {
                    PayloadOrigin::FreshAttestation
                } else if origin_authenticated {
                    PayloadOrigin::Retained
                } else {
                    PayloadOrigin::Claim
                };
                self.handle_payload(
                    envelope,
                    payload,
                    sender_machine_id,
                    origin,
                    sender_pubkey,
                    ack_legacy_bus,
                )
                .await;
            }
        }
    }

    async fn handle_payload(
        &self,
        envelope: DmEnvelope,
        payload: DmPayload,
        sender_machine_id: MachineId,
        origin: PayloadOrigin,
        sender_pubkey: Vec<u8>,
        ack_legacy_bus: bool,
    ) {
        let origin_authenticated = origin.authenticated();
        let sender_agent_id = AgentId(envelope.sender_agent_id);
        let admitted_at = envelope.created_at_unix_ms / 1000;
        let mut decision = {
            let store = self.contacts.read().await;
            TrustEvaluator::new(&store).evaluate(&TrustContext {
                agent_id: &sender_agent_id,
                machine_id: &sender_machine_id,
            })
        };
        // Explicit denials win before the binding moves and before a
        // ShareGrant can promote the decision (ADR-0070 §2).
        if matches!(
            decision,
            TrustDecision::RejectBlocked | TrustDecision::RejectMachineMismatch
        ) {
            self.dm.record_incoming_trust_rejected(sender_agent_id);
            let outcome = DmAckOutcome::RejectedByPolicy {
                reason: decision.to_string(),
            };
            self.cache.insert_for_protocol(
                envelope.dedupe_key(),
                outcome.clone(),
                envelope.protocol_version,
            );
            if !self.silent_reject {
                // A refusal makes no durability claim, so it is stamped
                // with the requested version rather than downgraded to v1:
                // a strict v2 sender must learn it was rejected instead of
                // waiting out its ACK budget on a receipt it would ignore
                // (ADR 0030 drivers — no black hole, bounded latency).
                let _ = self
                    .publish_ack_for_protocol(
                        sender_agent_id,
                        envelope.request_id,
                        outcome,
                        envelope.protocol_version,
                        ack_legacy_bus,
                    )
                    .await;
            }
            return;
        }

        if matches!(origin, PayloadOrigin::FreshAttestation) {
            self.refresh_admitted_origin(sender_agent_id, sender_machine_id, admitted_at)
                .await;
        }

        // ADR-0070 §2: a current `Dm` ShareGrant promotes Unknown or
        // AcceptWithFlag to Accept. The grant reads the retained binding,
        // which now names this DM's verified origin.
        if matches!(
            decision,
            TrustDecision::Unknown | TrustDecision::AcceptWithFlag
        ) {
            if let Some(gate) = &self.share_grant_gate {
                if gate
                    .dm_allowed(
                        &self.contacts,
                        &self.revocation_set,
                        &sender_agent_id,
                        &sender_machine_id,
                    )
                    .await
                {
                    decision = TrustDecision::Accept;
                }
            }
        }

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_trust_evaluated",
            request_id = %hex::encode(envelope.request_id),
            sender = %hex::encode(sender_agent_id.as_bytes()),
            decision = %decision,
        );

        let aad = envelope.aead_aad();
        let plaintext = match decrypt_payload(&self.kem_keypair, &payload, &aad) {
            Ok(p) => p,
            Err(_) => {
                self.dm.record_incoming_decode_failed();
                return;
            }
        };
        if plaintext.request_id != envelope.request_id {
            self.dm.record_incoming_decode_failed();
            return;
        }
        if matches!(origin, PayloadOrigin::FreshAttestation) {
            self.remember_resolved_origin(sender_agent_id, sender_machine_id)
                .await;
        } else if matches!(origin, PayloadOrigin::Retained) {
            self.remember_admitted_origin(sender_agent_id, sender_machine_id)
                .await;
        }

        // ADR 0030 §1/§2: a v2 envelope is answered by the durable path or not
        // at all. There is no silent v1 downgrade of a v2 request — if durable
        // history is unavailable the ACK is withheld and the sender times out,
        // which can only happen against a peer that believed a false v2
        // capability advert (this daemon advertises v2 iff history is on).
        if envelope.protocol_version >= DM_PROTOCOL_DURABLE_ACK {
            // #380 leaf-reverse-ACK fix (a): a signature-verified durable
            // envelope just arrived — this is the authoritative moment the
            // receiver owes a reverse route. On a Leaf receiver, the
            // sender's inbox topic is not in the subscribed set (C2/C4
            // pre-warm only fires on connect events with a resolvable
            // agent_id and a trusted contact — neither is guaranteed on a
            // fresh daemon or a first-ever message). Without a subscription
            // the targeted-inbox ACK publish finds zero peers and fails;
            // the compat bus has the same zero-peer problem in Leaf mode.
            // Subscribe the SENDER's inbox topic right now so the ACK that
            // follows has a gossip route. No trust gate and no
            // commit-success gate: the sender just delivered a
            // signature-verified envelope addressed to us — we owe them the
            // receipt, and the route must exist even if the commit below
            // withholds (the sender will retry).
            {
                let sender_agent = AgentId(envelope.sender_agent_id);
                crate::dm_inbox::warm_reverse_ack_topics(
                    self.pubsub.as_ref(),
                    &self.self_agent_id,
                    &sender_agent,
                )
                .await;
            }

            // #380 leaf-reverse-ACK fix (b): register the sender's
            // agent→machine mapping from the verified envelope itself. The
            // C5 Direct hedge's `get_machine_id` lookup was SkippedNoDirect
            // whenever the connected_agents map lacked the entry — which
            // happens on inbound connections where the PeerConnected
            // handler could not resolve the agent_id from the machine_id
            // (fresh cache, no DM history yet). The envelope carries both
            // identities and just passed signature verification. #927: the
            // agent signature does NOT cover the machine claim, so only an
            // attested origin or an authenticated binding may register it;
            // an unattested claim would let an agent rebind its own routing
            // entry (which `connect_to_agent` copies into discovery) to any
            // machine it names.
            mark_gossip_dm_sender_connected(
                &self.dm,
                sender_agent_id,
                sender_machine_id,
                origin_authenticated,
            )
            .await;

            let _decision = self
                .handle_payload_durable(
                    envelope,
                    plaintext.payload,
                    decision,
                    sender_machine_id,
                    origin_authenticated,
                    sender_pubkey,
                    ack_legacy_bus,
                )
                .await;
            return;
        }

        // Reserve bounded typed-route capacity before claiming dedupe. A full
        // predecessor channel cannot justify an Accepted ACK: the sender's
        // obligation must remain pending so it can retry. The permit makes
        // capacity admission atomic with the claim across the primary inbox
        // and legacy-bus subscription loops.
        let (typed_route, typed_route_outcome) =
            Self::matching_typed_route(&self.typed_payload_routes, &plaintext.payload);
        let typed_permit = if let Some(route) = typed_route {
            match route.sender.try_reserve() {
                Ok(permit) => Some(permit),
                Err(error) => {
                    self.dm.record_incoming_typed_route_dropped();
                    tracing::warn!(
                        target: "dm.trace",
                        request_id = %hex::encode(envelope.request_id),
                        sender = %crate::logging::LogAgentId::from(&sender_agent_id),
                        "v1 ACK withheld: typed route could not reserve capacity ({error})"
                    );
                    return;
                }
            }
        } else {
            None
        };

        // Atomic dedupe claim BEFORE delivery. The same envelope can arrive
        // twice — once on the primary per-recipient inbox and once on the
        // legacy bus (during a rolling upgrade), driven by two independent
        // subscription loops. The earlier `cache.lookup` in `handle_incoming`
        // is not sufficient: both tasks can miss it before either delivers.
        // Claiming the dedupe slot here (insert returns `true` only for the
        // task that inserted it) ensures exactly one task delivers to the
        // application; the loser re-ACKs the accepted outcome and returns.
        // The claim happens only after a successful decrypt, so a decrypt
        // failure above still leaves the slot unclaimed for a genuine retry.
        if !self
            .cache
            .insert(envelope.dedupe_key(), DmAckOutcome::Accepted)
        {
            drop(typed_permit);
            let _ = self
                .publish_ack(
                    sender_agent_id,
                    envelope.request_id,
                    DmAckOutcome::Accepted,
                    ack_legacy_bus,
                )
                .await;
            return;
        }

        let is_typed_payload = typed_permit.is_some();
        if let Some(permit) = typed_permit {
            permit.send(DmTypedPayload {
                sender: sender_agent_id,
                machine_id: sender_machine_id,
                payload: plaintext.payload.clone(),
                verified: origin_authenticated,
                trust_decision: Some(decision),
                received_at_unix_ms: now_unix_ms(),
                request_id: envelope.request_id,
                completion: None,
            });
        }

        if !is_typed_payload {
            // ADR-0023 §4: record durable DM communication after every
            // signature/trust/revocation gate has passed. Non-blocking
            // (`HistoryHandle::record` is try_send); plumbing payload
            // families classify Ephemeral and are skipped.
            if self.history.is_some() {
                match inbound_dm_history_record(
                    &envelope,
                    &plaintext.payload,
                    sender_machine_id,
                    &sender_pubkey,
                    typed_route_outcome == TypedRouteOutcome::RejectedPrefix,
                ) {
                    Ok(Some(record)) => {
                        if let Some(history) = self.history.as_ref() {
                            history.record(record);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            "history: DM envelope wire encode failed, row skipped: {e}"
                        );
                    }
                }
            }
            self.dm
                .handle_incoming(
                    sender_machine_id,
                    sender_agent_id,
                    plaintext.payload,
                    origin_authenticated,
                    Some(decision),
                    // Gossip-inbox deliveries carry no point-to-point
                    // transport observation (issue #120).
                    None,
                )
                .await;

            tracing::info!(
                target: "dm.trace",
                stage = "inbound_broadcast_published",
                request_id = %hex::encode(envelope.request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
            );
        }

        let _ = self
            .publish_ack(
                sender_agent_id,
                envelope.request_id,
                DmAckOutcome::Accepted,
                ack_legacy_bus,
            )
            .await;
    }

    /// Receiver durable path for a v2 envelope (ADR 0030 §1).
    ///
    /// Ordering is normative and implemented in exactly this order:
    /// per-logical-request lock → replay-cache binding check →
    /// durable-history lookup → dispatch → `record_committed` awaited → ACK.
    ///
    /// Every failure below withholds the ACK. A withheld ACK costs the sender
    /// a timeout; a premature ACK costs it a lost message it was told had
    /// arrived, which is the defect this protocol exists to remove. No branch
    /// here may fall back to a v1 ACK: that would answer a durable request
    /// with a weaker receipt the sender cannot distinguish (ADR 0030 §2).
    #[allow(clippy::too_many_arguments)]
    async fn handle_payload_durable(
        &self,
        envelope: DmEnvelope,
        application_payload: Vec<u8>,
        decision: TrustDecision,
        sender_machine_id: MachineId,
        origin_authenticated: bool,
        sender_pubkey: Vec<u8>,
        ack_legacy_bus: bool,
    ) -> DurableAckDecision {
        let sender_agent_id = AgentId(envelope.sender_agent_id);
        let request_id = envelope.request_id;
        let dedupe = envelope.dedupe_key();

        let Some(history) = self.history.clone() else {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_history_unavailable",
                request_id = %hex::encode(request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
                "v2 DM withheld: durable history is not enabled on this daemon"
            );
            return DurableAckDecision::Withheld("history_unavailable");
        };

        // ADR 0030 §7 — typed-route obligation, now discharged by the handler.
        //
        // Typed-prefix families classify `Ephemeral`: their durable effect
        // lives in their own store, not in DM history, so a DM-history commit
        // could never honestly back their receipt. Slice 2 therefore withheld
        // every v2 ACK on a typed route. Slice 3 replaces that blanket refusal
        // with a completion signal — the handler tells us when the payload is
        // durably recorded on ITS surface, and that signal, not a history row,
        // is what releases the ACK.
        //
        // Routes opt in via `with_durable_typed_payload_route`. A route that
        // has not opted in still gets no v2 ACK: this daemon will not certify
        // durability for a handler that has not promised it. That withholding
        // is stated policy (see the PR/design doc), not an oversight.
        let typed_route_durable = self
            .typed_payload_routes
            .iter()
            .find(|route| Self::typed_route_matches(route, &application_payload))
            .map(|route| route.durable_completion);
        if typed_route_durable == Some(false) {
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_durable_typed_route_not_opted_in",
                request_id = %hex::encode(request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
                "v2 DM matched a typed route that does not report durable completion; ACK withheld by policy (ADR 0030 §7)"
            );
            return DurableAckDecision::Withheld("typed_route_not_durable");
        }
        let is_durable_typed_route = typed_route_durable == Some(true);

        // 1. Per-logical-request lock. Serializes the primary inbox and the
        //    legacy-bus copy of the same envelope so neither can observe a
        //    provisional success from the other.
        let Some(lock) = self.cache.delivery_lock(dedupe) else {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_lock_unavailable",
                request_id = %hex::encode(request_id),
                "v2 DM withheld: no durable delivery lock slot available"
            );
            return DurableAckDecision::Withheld("lock_unavailable");
        };
        let _guard = lock.lock().await;

        // 2. Replay-cache binding check. A completion already exists ⇒ re-ACK
        //    it under its own semantics, never re-dispatch.
        let binding = crate::dm::DmDurableBindingDigest::accepted(
            envelope.protocol_version,
            &application_payload,
        );
        if let Some(cached) = self.cache.lookup(&dedupe) {
            let outcome = match cached.durable_binding {
                Some(stored) if stored == binding => {
                    cached_ack_for_protocol(&cached, envelope.protocol_version)
                }
                // ADR 0030 slice 4: the id is bound to other bytes, which is a
                // caller-side idempotency-key reuse, not a peer-capability
                // gap. It answered `AckSemanticsUnavailable` until the typed
                // error existed (#329 review).
                Some(_) => DmAckOutcome::IdempotencyConflict {
                    reason: "logical request already completed with different content".to_string(),
                },
                None => cached_ack_for_protocol(&cached, envelope.protocol_version),
            };
            let accepted_replay = matches!(outcome, DmAckOutcome::Accepted);
            // An accepted re-ACK is stamped with the semantics actually
            // honoured (never above what this request asked for). A refusal
            // makes no durability claim and is stamped with the requested
            // version instead, so it reaches the sender's exact-protocol
            // waiter and is answered rather than waited out.
            let ack_protocol = if accepted_replay {
                cached
                    .protocol_version
                    .min(envelope.protocol_version)
                    .max(DM_PROTOCOL_V1)
            } else {
                envelope.protocol_version
            };
            let _ = self
                .publish_ack_for_protocol(
                    sender_agent_id,
                    request_id,
                    outcome,
                    ack_protocol,
                    ack_legacy_bus,
                )
                .await;
            return DurableAckDecision::Acked {
                protocol_version: ack_protocol,
                accepted: accepted_replay,
            };
        }

        // 3a. Durable typed route: the handler's own store is the durable
        //     surface, so steps 3–5 are replaced by dispatch-and-await. The
        //     handler reports `Inserted | Duplicate` only once the payload is
        //     recorded, which is the same "exactly one durable record" proof
        //     `record_committed` gives the generic path.
        if is_durable_typed_route {
            let decision = self
                .dispatch_durable_typed_route(
                    sender_agent_id,
                    sender_machine_id,
                    origin_authenticated,
                    request_id,
                    application_payload,
                    Some(decision),
                )
                .await;
            let completion = match decision {
                Ok(completion) => completion,
                Err(stage) => return DurableAckDecision::Withheld(stage),
            };
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_durable_typed_completed",
                request_id = %hex::encode(request_id),
                ?completion,
            );
            if let Err(error) = self.cache.complete_durable(
                dedupe,
                DmAckOutcome::Accepted,
                envelope.protocol_version,
                binding,
            ) {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_replay_publish_failed",
                    request_id = %hex::encode(request_id),
                    ?error,
                    "v2 ACK withheld: durable typed completion could not be made replay-safe"
                );
                return DurableAckDecision::Withheld("replay_publish_failed");
            }
            let _ = self
                .publish_ack_for_protocol(
                    sender_agent_id,
                    request_id,
                    DmAckOutcome::Accepted,
                    envelope.protocol_version,
                    ack_legacy_bus,
                )
                .await;
            return DurableAckDecision::Acked {
                protocol_version: envelope.protocol_version,
                accepted: true,
            };
        }

        // 3. Durable-history lookup. Survives restart, where the in-memory
        //    replay cache above does not.
        let Ok(Some(record)) = inbound_dm_history_record(
            &envelope,
            &application_payload,
            sender_machine_id,
            &sender_pubkey,
            Self::matching_typed_route(&self.typed_payload_routes, &application_payload).1
                == TypedRouteOutcome::RejectedPrefix,
        ) else {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_record_unbuildable",
                request_id = %hex::encode(request_id),
                "v2 DM withheld: payload has no durable history representation"
            );
            return DurableAckDecision::Withheld("no_durable_representation");
        };
        let lookup = match durable_history_logical_request(
            &history,
            sender_agent_id,
            request_id,
            application_payload.clone(),
        )
        .await
        {
            Ok(
                found @ (DurableLogicalRequestLookup::Missing | DurableLogicalRequestLookup::Exact),
            ) => found,
            Ok(DurableLogicalRequestLookup::Conflict) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_logical_request_conflict",
                    request_id = %hex::encode(request_id),
                    sender = %hex::encode(sender_agent_id.as_bytes()),
                    "v2 DM rejected: logical request already committed with different content"
                );
                let _ = self
                    .publish_ack_for_protocol(
                        sender_agent_id,
                        request_id,
                        DmAckOutcome::IdempotencyConflict {
                            reason: "logical request already committed with different content"
                                .to_string(),
                        },
                        envelope.protocol_version,
                        ack_legacy_bus,
                    )
                    .await;
                return DurableAckDecision::Acked {
                    protocol_version: envelope.protocol_version,
                    accepted: false,
                };
            }
            Err(error) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_history_lookup_failed",
                    request_id = %hex::encode(request_id),
                    %error,
                    "v2 DM withheld: durable history lookup failed"
                );
                return DurableAckDecision::Withheld("history_lookup_failed");
            }
        };

        // ADR 0116 §3 / ADR 0030 §1: a generic durable DM is never
        // acknowledged without its commit. Under `dm_recording =
        // "ephemeral"` the commit is suppressed, so a request with no
        // committed row (`Missing`) is withheld here, BEFORE dispatch. The
        // reason is counted locally only. No typed refusal is sent (no
        // `AckSemanticsUnavailable`), no weaker ACK, and the v2 advert
        // stays; the sender sees its ordinary bounded retry or timeout.
        //
        // Ruling Q4 (an interpretation of the Validation "pre-policy
        // committed duplicate" cell): an `Exact` lookup means the commit
        // was made before the policy, so the request is not suppressed. It
        // takes main's path below: re-dispatch (at-least-once) and a v2
        // ACK from the existing row, with no new commit attempted.
        let policy_suppresses_commit = history.policy().suppresses_ordinary_dms();
        if policy_suppresses_commit && lookup == DurableLogicalRequestLookup::Missing {
            history
                .counters()
                .policy_durable_receipt_withheld_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_durable_policy_ephemeral",
                request_id = %hex::encode(request_id),
                "v2 ACK withheld before dispatch: the local history policy does not record ordinary DMs (ADR 0116 §3)"
            );
            return DurableAckDecision::Withheld("history_policy_ephemeral");
        }

        // 4. Dispatch.
        self.dm
            .handle_incoming(
                sender_machine_id,
                sender_agent_id,
                application_payload.clone(),
                origin_authenticated,
                Some(decision),
                // Gossip-inbox deliveries carry no point-to-point transport
                // observation (issue #120).
                None,
            )
            .await;

        // 5. Commit awaited. This is the step the v2 receipt is actually
        //    about: the ACK below may not exist unless this returned.
        //    ADR 0116 §3 (ruling Q4): under an ephemeral DM policy only an
        //    `Exact` lookup reaches this point. Its pre-policy row is the
        //    commit the receipt needs, so no new commit is attempted; the
        //    handle would refuse one, and none is fabricated.
        if !policy_suppresses_commit {
            match history.record_committed(record).await {
                Ok(outcome) if exact_durable_history_outcome(outcome) => {}
                Ok(outcome) => {
                    tracing::warn!(
                        target: "dm.trace",
                        stage = "inbound_durable_commit_inexact",
                        request_id = %hex::encode(request_id),
                        ?outcome,
                        "v2 ACK withheld: history commit did not yield exactly one durable row"
                    );
                    return DurableAckDecision::Withheld("commit_inexact");
                }
                Err(error) => {
                    tracing::warn!(
                        target: "dm.trace",
                        stage = "inbound_durable_commit_failed",
                        request_id = %hex::encode(request_id),
                        %error,
                        "v2 ACK withheld: durable history commit failed"
                    );
                    return DurableAckDecision::Withheld("commit_failed");
                }
            }
        }

        // Publish the completion into the replay cache before acknowledging,
        // so a concurrent copy of this envelope can never be dispatched twice
        // by a peer that has already been told the request completed.
        if let Err(error) = self.cache.complete_durable(
            dedupe,
            DmAckOutcome::Accepted,
            envelope.protocol_version,
            binding,
        ) {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_replay_publish_failed",
                request_id = %hex::encode(request_id),
                ?error,
                "v2 ACK withheld: durable completion could not be made replay-safe"
            );
            return DurableAckDecision::Withheld("replay_publish_failed");
        }

        // 6. ACK, stamped with the semantics actually honoured.
        let _ = self
            .publish_ack_for_protocol(
                sender_agent_id,
                request_id,
                DmAckOutcome::Accepted,
                envelope.protocol_version,
                ack_legacy_bus,
            )
            .await;

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_durable_ack_published",
            request_id = %hex::encode(request_id),
            sender = %hex::encode(sender_agent_id.as_bytes()),
            protocol_version = envelope.protocol_version,
        );

        DurableAckDecision::Acked {
            protocol_version: envelope.protocol_version,
            accepted: true,
        }
    }

    /// Hand a durable (v2) payload to its typed route and wait for the
    /// handler's completion signal (ADR 0030 §7).
    ///
    /// `Err(stage)` names the reason the ACK must be withheld. Every failure
    /// mode lands there deliberately, because each one means the durable
    /// receipt would be unbacked:
    ///
    /// - the channel is full or closed — the handler never saw the payload;
    /// - the handler dropped the completion sender — including by returning
    ///   early on its own error path, so "forgot to answer" fails safe;
    /// - the handler reported an error;
    /// - the handler did not answer inside the budget.
    ///
    /// Only `Inserted | Duplicate` returns `Ok`.
    async fn dispatch_durable_typed_route(
        &self,
        sender_agent_id: AgentId,
        sender_machine_id: MachineId,
        origin_authenticated: bool,
        request_id: [u8; 16],
        payload: Vec<u8>,
        trust_decision: Option<TrustDecision>,
    ) -> Result<DmTypedPayloadCompletion, &'static str> {
        let Some(route) = self
            .typed_payload_routes
            .iter()
            .find(|route| Self::typed_route_matches(route, &payload))
        else {
            return Err("typed_route_vanished");
        };
        let (completion_tx, completion_rx) = oneshot::channel();
        let typed = DmTypedPayload {
            sender: sender_agent_id,
            machine_id: sender_machine_id,
            payload,
            verified: origin_authenticated,
            trust_decision,
            received_at_unix_ms: now_unix_ms(),
            request_id,
            completion: Some(completion_tx),
        };
        // Still `try_send`, still non-blocking: this runs inline on the serial
        // inbox loop, so a full channel must not stall unrelated DMs. The
        // difference from the v1 path is what a drop means — there it was a
        // tolerable loss of a redundant fallback, here it withholds the ACK
        // and the sender retries.
        if let Err(error) = route.sender.try_send(typed) {
            self.dm.record_incoming_typed_route_dropped();
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_typed_route_unavailable",
                request_id = %hex::encode(request_id),
                sender = %crate::logging::LogAgentId::from(&sender_agent_id),
                "v2 ACK withheld: typed route could not accept the payload ({error})"
            );
            return Err("typed_route_unavailable");
        }

        match tokio::time::timeout(DURABLE_TYPED_COMPLETION_TIMEOUT, completion_rx).await {
            Ok(Ok(Ok(completion))) => Ok(completion),
            Ok(Ok(Err(reason))) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_handler_failed",
                    request_id = %hex::encode(request_id),
                    %reason,
                    "v2 ACK withheld: typed-route handler reported failure"
                );
                Err("typed_handler_failed")
            }
            Ok(Err(_)) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_completion_dropped",
                    request_id = %hex::encode(request_id),
                    "v2 ACK withheld: typed-route handler dropped the completion channel"
                );
                Err("typed_completion_dropped")
            }
            Err(_) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_completion_timeout",
                    request_id = %hex::encode(request_id),
                    timeout_secs = DURABLE_TYPED_COMPLETION_TIMEOUT.as_secs(),
                    "v2 ACK withheld: typed-route handler did not report completion in budget"
                );
                Err("typed_completion_timeout")
            }
        }
    }

    fn typed_route_matches(route: &DmTypedPayloadRoute, payload: &[u8]) -> bool {
        let Some(suffix) = payload.strip_prefix(route.prefix.as_slice()) else {
            return false;
        };
        if route.prefix == GROUP_PREDECESSOR_RELAY_DM_PREFIX && route.validator.is_none() {
            if suffix.len() > PREDECESSOR_RELAY_MAX_ENVELOPE_BYTES || suffix.first() != Some(&2) {
                return false;
            }
            let Ok(message) = crate::gossip::pubsub::decode_auto(Bytes::copy_from_slice(suffix))
            else {
                return false;
            };
            if !message.verified || message.sender.is_none() {
                return false;
            }
            // A direct caller can build this route without the daemon's full
            // parser. Keep that legacy registration safe as well; production
            // uses its own validator below and avoids duplicate verification.
            if !serde_json::from_slice::<serde_json::Value>(&message.payload)
                .ok()
                .is_some_and(|event| {
                    event.get("event").and_then(serde_json::Value::as_str)
                        == Some("join_request_created")
                })
            {
                return false;
            }
        }
        route.validator.is_none_or(|validator| validator(payload))
    }

    fn matching_typed_route<'a>(
        routes: &'a [DmTypedPayloadRoute],
        payload: &[u8],
    ) -> (Option<&'a DmTypedPayloadRoute>, TypedRouteOutcome) {
        let mut rejected_prefix = false;
        for route in routes {
            if !payload.starts_with(&route.prefix) {
                continue;
            }
            if Self::typed_route_matches(route, payload) {
                return (Some(route), TypedRouteOutcome::Recognized);
            }
            rejected_prefix = true;
        }
        if rejected_prefix {
            (None, TypedRouteOutcome::RejectedPrefix)
        } else {
            (None, TypedRouteOutcome::NoPrefix)
        }
    }

    /// Whether these bytes are a COMPLETE match for a registered typed
    /// route (prefix and validator): a protocol frame, not a user DM.
    /// Non-consuming - the caller decides what to do with it (N12: an
    /// unverified typed frame must not fall through to the generic bus).
    pub(crate) fn typed_route_recognizes(routes: &[DmTypedPayloadRoute], payload: &[u8]) -> bool {
        Self::matching_typed_route(routes, payload).0.is_some()
    }

    /// Shared prefix dispatch for verified gossip and post-validation raw direct
    /// payloads. Recognition suppresses generic fan-out even if the bounded
    /// channel is unavailable; it does not establish handler acceptance.
    pub(crate) fn try_route_typed_payload(
        routes: &[DmTypedPayloadRoute],
        dm: &DirectMessaging,
        typed: DmTypedPayload,
    ) -> TypedRouteOutcome {
        let (route, outcome) = Self::matching_typed_route(routes, &typed.payload);
        let Some(route) = route else {
            return outcome;
        };
        let sender_agent_id = typed.sender;
        // Best-effort, NON-BLOCKING hand-off. Some routes have other delivery
        // paths; others, including predecessor relay, depend on this channel.
        // We must not `send().await`: this runs inline in the single DM-inbox
        // subscription loop that also publishes ACKs, so a slow or
        // lock-contended route consumer filling the bounded channel would block
        // ACK delivery for unrelated senders (surfacing as 504s now that
        // `require_gossip_ack` defaults true). Drop on a full channel and count
        // it rather than stalling the pipeline.
        match route.sender.try_send(typed) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                dm.record_incoming_typed_route_dropped();
                tracing::warn!(
                    sender = %crate::logging::LogAgentId::from(&sender_agent_id),
                    "typed DM payload route channel full; dropping payload"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    sender = %crate::logging::LogAgentId::from(&sender_agent_id),
                    "typed DM payload route receiver is closed; dropping payload"
                );
            }
        }
        TypedRouteOutcome::Recognized
    }

    /// Emit a v1 ACK: verified and locally enqueued (receipt level 2).
    async fn publish_ack(
        &self,
        to: AgentId,
        acks_request_id: [u8; 16],
        outcome: DmAckOutcome,
        ack_legacy_bus: bool,
    ) -> NetworkResult<()> {
        self.publish_ack_for_protocol(to, acks_request_id, outcome, DM_PROTOCOL_V1, ack_legacy_bus)
            .await
    }

    /// Emit an ACK stamped with the semantics this receiver actually honoured.
    ///
    /// ADR 0030: `protocol_version` names the receipt the recipient is
    /// claiming, and the sender's waiter matches it exactly. Callers must pass
    /// [`DM_PROTOCOL_DURABLE_ACK`] only from the durable path, after
    /// `record_committed` has returned — never as an optimistic stamp.
    async fn publish_ack_for_protocol(
        &self,
        to: AgentId,
        acks_request_id: [u8; 16],
        outcome: DmAckOutcome,
        protocol_version: u16,
        ack_legacy_bus: bool,
    ) -> NetworkResult<()> {
        let body = EnvelopeBuilder::build_ack_body(acks_request_id, outcome);
        let created = now_unix_ms();
        let expires = created + ACK_ENVELOPE_LIFETIME_MS;
        let mut ack_rid = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut ack_rid);

        let mut envelope = DmEnvelope {
            // ADR 0030: an ACK is stamped with the semantics this receiver
            // actually honoured, not with the local ceiling. Only the durable
            // path passes v2, and only once the history commit has returned;
            // everything else stays v1 so a v2 waiter times out rather than
            // being handed a receipt no one made.
            protocol_version,
            request_id: ack_rid,
            sender_agent_id: *self.self_agent_id.as_bytes(),
            sender_machine_id: *self.self_machine_id.as_bytes(),
            recipient_agent_id: *to.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: expires,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        let signed = envelope
            .signed_bytes()
            .map_err(|e| NetworkError::SerializationError(format!("ack sign-bytes: {e}")))?;
        envelope.signature = self.signing.sign(&signed)?;
        // #213: attest the acking machine too — a fake `Accepted` ACK from
        // a revoked machine would otherwise forge a delivery receipt.
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            self.machine_keypair.public_key().as_bytes().to_vec(),
        );
        attestation.sign(&self.machine_keypair).map_err(|e| {
            NetworkError::SerializationError(format!("ack origin attestation: {e}"))
        })?;
        envelope.origin_attestation = Some(attestation);
        let encoded = envelope
            .to_wire_bytes()
            .map_err(|e| NetworkError::SerializationError(format!("ack encode: {e}")))?;
        let result = if protocol_version >= DM_PROTOCOL_DURABLE_ACK {
            // Durable v2 owns both publications in the bounded background
            // worker. The inbox loop can immediately process a subsequent DM
            // while the target and compatibility-bus routes retain their full
            // healthy-congestion budgets. Ordering is unaffected: the history
            // commit is already awaited before we get here, so this only makes
            // the *publication* asynchronous, never the promise behind it.
            self.ack_publisher.try_publish(AckPublishJob {
                recipient: to,
                acked_request_id: acks_request_id,
                protocol_version,
                encoded: Bytes::from(encoded),
            })
        } else {
            // Preserve v1 exactly: target first, and only publish back on the
            // compatibility bus when this payload itself arrived there. No
            // new deadline or background ownership changes legacy behavior.
            let topic = DmInboxService::inbox_topic_name(&to);
            let primary = self
                .pubsub
                .publish_topic_id(topic, dm_inbox_topic(&to), Bytes::from(encoded.clone()))
                .await;
            let legacy = if ack_legacy_bus {
                self.pubsub
                    .publish(DM_BUS_TOPIC.to_string(), Bytes::from(encoded))
                    .await
            } else {
                Ok(())
            };
            primary.and(legacy)
        };
        if let Err(error) = &result {
            self.dm.record_ack_publish_route_failed();
            tracing::warn!(
                target: "dm.trace",
                stage = "ack_publish_route_failed",
                acked_request_id = %hex::encode(acks_request_id),
                recipient = %hex::encode(to.as_bytes()),
                protocol_version,
                %error,
                "ACK publication could not be scheduled or completed"
            );
        }
        result
    }
}

/// Enforcement point 3 decision (issue #130): if `sender` is revoked, record
/// the `incoming_dropped_revoked` counter and return `true` (the caller must
/// drop the DM). Returns `false` for a non-revoked sender without touching the
/// counter.
///
/// Pure revocation-gate predicate for the gossip DM path (EP3).
///
/// Drops (and counts) a DM whose sender agent OR originating machine is in
/// the local revocation set — matching the raw-QUIC direct path
/// (`direct::inbound_peer_revoked`) and EP1/EP2, so both DM paths are
/// fail-closed on a machine revocation even when the agent-id is clean
/// (issue #184). Extracted as a pure function of
/// `(DirectMessaging, RevocationSet, AgentId, MachineId)` so the gate can be
/// unit-tested without a live inbox pipeline, and so a future refactor of
/// `handle_incoming` cannot silently drop the counter side-effect.
fn drop_if_sender_revoked(
    dm: &DirectMessaging,
    revoked: &RevocationSet,
    sender: &AgentId,
    machine: &MachineId,
) -> bool {
    if revoked.is_agent_revoked(sender) || revoked.is_machine_revoked(machine) {
        dm.record_incoming_dropped_revoked();
        true
    } else {
        false
    }
}

/// How `handle_payload` should treat the machine it was given.
#[derive(Clone, Copy)]
enum PayloadOrigin {
    /// Sender claim only. Do not record attribution.
    Claim,
    /// Already authenticated by the retained binding. Record it when this
    /// DM is admitted.
    Retained,
    /// Fresh attestation. The retained binding moves before grant
    /// evaluation. Attribution waits until decryption succeeds.
    FreshAttestation,
}

impl PayloadOrigin {
    fn authenticated(self) -> bool {
        !matches!(self, Self::Claim)
    }
}

/// Why an unattested DM or ACK is dropped, or that it may continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnattestedAttribution {
    /// No machine revocation is held for this sender. Overflow does not refuse.
    Allow,
    /// An attributed machine is revoked, and this sender's history still fits.
    Revoked,
    /// This sender overflowed, and a machine revocation for them is held.
    Overflow,
    /// The stranger pin cap is full and a revoked pair for this sender was
    /// dropped or could not be pinned. The sender is not linked to a
    /// revoked machine that this cache still holds.
    DroppedRevokedPair,
}

/// #1659: classify an unattested DM from `agent`.
///
/// A machine revocation counts when the inbox can attribute that machine to
/// the sender. Attribution is the claimed machine, the retained binding,
/// every machine the authenticated-binding cache has accepted for the
/// sender, a contact machine, or a binding tombstone. An unrelated machine
/// revocation does not count. A machine past the attribution cap is not in
/// the accepted set. Revoking that machine does not refuse an unattested
/// DM that claims a different clean machine. When an attributed machine is
/// revoked and the sender's set has also overflowed, the result is
/// [`UnattestedAttribution::Overflow`]. The caller counts that refusal in
/// `incoming_dropped_revoked` and in the internal overflow counter. A full
/// stranger pin cap refuses only a stranger whose revoked pair was dropped
/// or could not be pinned. That refusal is
/// [`UnattestedAttribution::DroppedRevokedPair`]. A sender this receiver
/// cannot link to a revoked machine, and who has no such dropped pair,
/// stays [`UnattestedAttribution::Allow`].
fn sender_unattested_attribution(
    revoked: &RevocationSet,
    agent: &AgentId,
    retained: Option<MachineId>,
    claimed: MachineId,
    contact_machines: &[MachineId],
    accepted_machines: &[MachineId],
    attribution_overflowed: bool,
) -> UnattestedAttribution {
    let holds = revoked.is_machine_revoked(&claimed)
        || retained.is_some_and(|machine| revoked.is_machine_revoked(&machine))
        || accepted_machines
            .iter()
            .any(|machine| revoked.is_machine_revoked(machine))
        || contact_machines
            .iter()
            .any(|machine| revoked.is_machine_revoked(machine))
        || revoked.any_tombstone_machine_revoked(agent);
    if !holds {
        return UnattestedAttribution::Allow;
    }
    if attribution_overflowed {
        return UnattestedAttribution::Overflow;
    }
    UnattestedAttribution::Revoked
}

/// Monotonic milliseconds since the first call in this process.
///
/// Rate limits use this clock. A step backwards in the wall clock must not
/// silence the next warning, and a step forwards must not emit one per DM.
fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// True when a rate-limited warning may be emitted.
///
/// A stored timestamp of 0 means no warning has been emitted yet. The
/// first event in the process must not be dropped.
fn warn_interval_open(last_ms: u64, now: u64) -> bool {
    last_ms == 0 || now.saturating_sub(last_ms) >= UNATTESTED_DROP_WARN_INTERVAL_MS
}

/// One sender's warning clock. Bounded so a flood of senders cannot grow it.
#[derive(Debug, Default)]
struct UnattestedWarnLog {
    last_ms: std::collections::HashMap<[u8; 32], u64>,
    /// Shared interval for senders that do not fit in `last_ms`.
    overflow_warn_ms: u64,
}

impl UnattestedWarnLog {
    /// True when this sender may emit a warning now.
    fn allow(&mut self, sender: &[u8], now: u64) -> bool {
        let mut key = [0u8; 32];
        let len = sender.len().min(32);
        key[..len].copy_from_slice(&sender[..len]);
        if let Some(prev) = self.last_ms.get(&key).copied() {
            if !warn_interval_open(prev, now) {
                return false;
            }
            self.last_ms.insert(key, now.max(1));
            return true;
        }
        if self.last_ms.len() >= UNATTESTED_WARN_SENDERS {
            let expired = self
                .last_ms
                .iter()
                .find(|(_, prev)| warn_interval_open(**prev, now))
                .map(|(slot, _)| *slot);
            if let Some(expired) = expired {
                self.last_ms.remove(&expired);
            } else if !warn_interval_open(self.overflow_warn_ms, now) {
                return false;
            } else {
                // Do not take a slot whose interval is still open.
                self.overflow_warn_ms = now.max(1);
                return true;
            }
        }
        self.last_ms.insert(key, now.max(1));
        true
    }
}

/// Emit one unattested-drop warning per remembered sender per interval.
/// A sender past the remembered cap shares one interval while every
/// remembered interval is still open. An expired slot is reused. Later DMs
/// from that sender still increment their counter. A remembered sender is
/// not masked by another.
fn warn_unattested_drop(
    log: &std::sync::Mutex<UnattestedWarnLog>,
    stage: &'static str,
    sender: &[u8],
    claimed_machine: &[u8],
    message: &'static str,
) {
    let now = monotonic_ms();
    let allowed = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .allow(sender, now);
    if !allowed {
        return;
    }
    tracing::warn!(
        target: "dm.trace",
        stage,
        sender = %hex::encode(sender),
        claimed_machine = %hex::encode(claimed_machine),
        "{message}"
    );
}

/// Register a gossip-DM sender's agent→machine pairing in DirectMessaging —
/// but only when the machine was AUTHENTICATED (#927, mirroring #898).
///
/// `origin_authenticated` is true only for a fresh origin-machine
/// attestation or an `AuthenticatedMachineBindings` entry. A bare envelope
/// `sender_machine_id` claim is not covered by the agent signature's proof
/// of machine ownership, so recording it would let an agent rebind its own
/// connected-machine entry (which `connect_to_agent` copies into the
/// discovery cache) to any machine it names. Returns whether it marked.
async fn mark_gossip_dm_sender_connected(
    dm: &DirectMessaging,
    agent_id: AgentId,
    machine_id: MachineId,
    origin_authenticated: bool,
) -> bool {
    if !origin_authenticated {
        tracing::debug!(
            target: "dm.trace",
            stage = "inbound_unattested_machine_not_bound",
            sender = %hex::encode(agent_id.as_bytes()),
            claimed_machine = %hex::encode(machine_id.as_bytes()),
            "unattested gossip DM machine claim: routing left unchanged (#927)"
        );
        return false;
    }
    dm.mark_connected(agent_id, machine_id).await;
    true
}

pub fn verify_envelope_signature(envelope: &DmEnvelope, public_key_bytes: &[u8]) -> bool {
    let signed = match envelope.signed_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let public_key = match ant_quic::MlDsaPublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let derived = AgentId::from_public_key(&public_key);
    if derived.0 != envelope.sender_agent_id {
        return false;
    }
    let signature = match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
        &envelope.signature,
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &signed, &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::TrustLevel;
    use crate::dm::MAX_ENVELOPE_BYTES;
    use crate::identity::{AgentKeypair, MachineKeypair};
    use crate::network::{NetworkConfig, NetworkNode};
    use std::time::Duration;

    /// Explicit test-only network config (#417/#337): loopback bind, no
    /// seeds, discovery/port-mapping off. Still a real socket constructor.
    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..NetworkConfig::default()
        }
    }

    fn test_keypair() -> AgentKeypair {
        AgentKeypair::generate().expect("keygen")
    }

    fn make_unsigned_envelope(sender_kp: &AgentKeypair, recipient_id: &[u8; 32]) -> DmEnvelope {
        let now = now_unix_ms();
        DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: [1u8; 16],
            sender_agent_id: *sender_kp.agent_id().as_bytes(),
            sender_machine_id: [2u8; 32],
            recipient_agent_id: *recipient_id,
            created_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            body: DmBody::Ack(crate::dm::DmAckBody {
                acks_request_id: [3u8; 16],
                outcome: crate::dm::DmAckOutcome::Accepted,
            }),
            signature: Vec::new(),
            origin_attestation: None,
        }
    }

    fn sign_envelope(envelope: &mut DmEnvelope, sender_kp: &AgentKeypair) {
        let signed = envelope.signed_bytes().expect("signed_bytes");
        let sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            sender_kp.secret_key(),
            &signed,
        )
        .expect("sign");
        envelope.signature = sig.as_bytes().to_vec();
    }

    struct InboxHarness {
        /// Keeps the durable-ACK worker alive for the harness's lifetime.
        /// Dropping it closes the queue and every v2 ACK would fail to
        /// schedule, which would look like a protocol bug in every test.
        _ack_worker: JoinHandle<()>,
        pipeline: InboxPipeline,
        recipient_agent_id: AgentId,
        recipient_kem: Arc<AgentKemKeypair>,
        receiver: crate::direct::DirectMessageReceiver,
        _tempdir: tempfile::TempDir,
    }

    async fn make_inbox_harness(
        sender: &AgentKeypair,
        authenticated_machine: Option<MachineId>,
        revoked_machine: Option<&MachineKeypair>,
    ) -> InboxHarness {
        make_inbox_harness_with_hedge(sender, authenticated_machine, revoked_machine, None).await
    }

    async fn make_inbox_harness_with_hedge(
        sender: &AgentKeypair,
        authenticated_machine: Option<MachineId>,
        revoked_machine: Option<&MachineKeypair>,
        direct_hedge: Option<Arc<dyn DirectAckHedge>>,
    ) -> InboxHarness {
        make_inbox_harness_with_hedge_options(
            sender,
            authenticated_machine,
            revoked_machine,
            direct_hedge,
            false,
        )
        .await
    }

    async fn make_inbox_harness_with_hedge_options(
        sender: &AgentKeypair,
        authenticated_machine: Option<MachineId>,
        revoked_machine: Option<&MachineKeypair>,
        direct_hedge: Option<Arc<dyn DirectAckHedge>>,
        skip_legacy_bus: bool,
    ) -> InboxHarness {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut contacts = ContactStore::new(tempdir.path().join("contacts.json"));
        contacts.set_trust(&sender.agent_id(), TrustLevel::Trusted);

        let recipient = AgentKeypair::generate().expect("recipient keygen");
        let recipient_agent_id = recipient.agent_id();
        let recipient_machine_id = MachineId([0xCC; 32]);
        let recipient_kem = Arc::new(AgentKemKeypair::generate().expect("recipient KEM"));
        let dm = Arc::new(DirectMessaging::new());
        let receiver = dm.subscribe();
        let node = Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        );
        // Production shape: the pubsub signs with the same agent key the
        // pipeline signs ACK envelopes with. The ACK-route tests read back
        // publications through the same verified sender path.
        let signing = Arc::new(SigningContext::from_keypair(&recipient));
        let pubsub = Arc::new(PubSubManager::new(node, Arc::clone(&signing)).expect("pubsub"));
        let authenticated_machine_bindings =
            Arc::new(RwLock::new(AuthenticatedMachineBindingCache::default()));
        if let Some(machine_id) = authenticated_machine {
            record_authenticated_machine_binding(
                &authenticated_machine_bindings,
                sender.agent_id(),
                machine_id,
                100,
            )
            .await;
        }

        let mut revocation_set = RevocationSet::new();
        if let Some(machine) = revoked_machine {
            let record = crate::revocation::RevocationRecord::sign(
                crate::revocation::RevokedSubject::Machine(machine.machine_id()),
                machine.public_key(),
                machine.secret_key(),
                now_unix_ms() / 1000,
                Some("compromised machine".to_string()),
            )
            .expect("sign machine revocation");
            revocation_set
                .verify_and_insert(record, None)
                .expect("insert machine revocation");
        }

        let (ack_publisher, ack_worker) = spawn_durable_ack_publisher(
            Arc::clone(&pubsub),
            Arc::clone(&dm),
            direct_hedge,
            skip_legacy_bus,
        );
        let pipeline = InboxPipeline {
            pubsub,
            signing,
            self_agent_id: recipient_agent_id,
            self_machine_id: recipient_machine_id,
            machine_keypair: Arc::new(
                MachineKeypair::generate().expect("recipient machine keygen"),
            ),
            kem_keypair: Arc::clone(&recipient_kem),
            dm,
            contacts: Arc::new(RwLock::new(contacts)),
            inflight: Arc::new(InFlightAcks::new()),
            cache: Arc::new(RecentDeliveryCache::with_defaults()),
            silent_reject: true,
            typed_payload_routes: Vec::new(),
            share_grant_gate: None,
            revocation_set: Arc::new(RwLock::new(revocation_set)),
            move_state: Arc::new(RwLock::new(crate::key_move::MoveState::new())),
            authenticated_machine_bindings,
            history: None,
            ack_publisher,
            unattested_revocation_warn: std::sync::Arc::new(std::sync::Mutex::new(
                UnattestedWarnLog::default(),
            )),
            unattested_overflow_warn: std::sync::Arc::new(std::sync::Mutex::new(
                UnattestedWarnLog::default(),
            )),
        };

        InboxHarness {
            _ack_worker: ack_worker,
            pipeline,
            recipient_agent_id,
            recipient_kem,
            receiver,
            _tempdir: tempdir,
        }
    }

    struct SpawnedInboxService {
        pubsub: Arc<PubSubManager>,
        self_agent_id: AgentId,
        service: DmInboxService,
        _tempdir: tempfile::TempDir,
    }

    async fn spawn_inbox_service_for_bus_control(skip_legacy_bus: bool) -> SpawnedInboxService {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let recipient = AgentKeypair::generate().expect("recipient keygen");
        let self_agent_id = recipient.agent_id();
        let node = Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        );
        let signing = Arc::new(SigningContext::from_keypair(&recipient));
        let pubsub = Arc::new(PubSubManager::new(node, Arc::clone(&signing)).expect("pubsub"));
        let service = DmInboxService::spawn_with_hedge_options(
            Arc::clone(&pubsub),
            signing,
            self_agent_id,
            MachineId([0xEE; 32]),
            Arc::new(MachineKeypair::generate().expect("machine keygen")),
            Arc::new(AgentKemKeypair::generate().expect("recipient KEM")),
            Arc::new(DirectMessaging::new()),
            Arc::new(RwLock::new(ContactStore::new(
                tempdir.path().join("contacts.json"),
            ))),
            Arc::new(InFlightAcks::new()),
            Arc::new(RecentDeliveryCache::with_defaults()),
            DmInboxConfig::default(),
            Arc::new(RwLock::new(RevocationSet::new())),
            Arc::new(RwLock::new(crate::key_move::MoveState::new())),
            Arc::new(RwLock::new(AuthenticatedMachineBindingCache::default())),
            None,
            None,
            skip_legacy_bus,
        )
        .await
        .expect("inbox service spawns");
        SpawnedInboxService {
            pubsub,
            self_agent_id,
            service,
            _tempdir: tempdir,
        }
    }

    /// Build a signed-but-unattested payload envelope, simulating a
    /// pre-#213 (legacy) sender: agent signature only, no origin attestation.
    /// The trust/origin/revocation regression suite below is about the gates
    /// that run before any protocol version matters, so it builds v1
    /// envelopes: these tests predate DM v2 and only became v2 incidentally
    /// when slice 1 raised `DM_PROTOCOL_VERSION` to the durable-ACK ceiling.
    /// The durable path has its own envelopes via `durable_payload_message`.
    fn craft_unsigned_payload_envelope(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
    ) -> DmEnvelope {
        craft_unsigned_payload_envelope_versioned(
            harness,
            sender,
            claimed_machine,
            request_byte,
            DM_PROTOCOL_V1,
            b"security regression payload".to_vec(),
        )
    }

    fn craft_unsigned_payload_envelope_versioned(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
        protocol_version: u16,
        application_payload: Vec<u8>,
    ) -> DmEnvelope {
        let created_at = now_unix_ms();
        let body = EnvelopeBuilder::build_payload_body(
            &[request_byte; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created_at,
            application_payload,
            None,
            &harness.recipient_kem.public_bytes,
        )
        .expect("build payload body");
        DmEnvelope {
            protocol_version,
            request_id: [request_byte; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *claimed_machine.as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created_at,
            expires_at_unix_ms: created_at + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        }
    }

    fn sign_envelope_with_agent(envelope: &mut DmEnvelope, sender: &AgentKeypair) {
        let signed = envelope.signed_bytes().expect("signed_bytes");
        let sig =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(sender.secret_key(), &signed)
                .expect("agent sign");
        envelope.signature = sig.as_bytes().to_vec();
    }

    fn wrap_in_pubsub(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        envelope: &DmEnvelope,
    ) -> PubSubMessage {
        PubSubMessage {
            topic: DmInboxService::inbox_topic_name(&harness.recipient_agent_id),
            payload: Bytes::from(envelope.to_wire_bytes().expect("encode envelope")),
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: Some(TrustLevel::Trusted),
            raw_envelope: None,
        }
    }

    /// Legacy (pre-#213) sender: signed envelope, NO origin attestation.
    fn payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
    ) -> PubSubMessage {
        let mut envelope =
            craft_unsigned_payload_envelope(harness, sender, claimed_machine, request_byte);
        sign_envelope_with_agent(&mut envelope, sender);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    /// Legacy ACK: agent-signed, no origin attestation.
    fn unattested_ack_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
    ) -> PubSubMessage {
        let created_at_unix_ms = now_unix_ms();
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_V1,
            request_id: [request_byte; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *claimed_machine.as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms,
            expires_at_unix_ms: created_at_unix_ms + 60_000,
            body: DmBody::Ack(crate::dm::DmAckBody {
                acks_request_id: [request_byte; 16],
                outcome: DmAckOutcome::Accepted,
            }),
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, sender);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    /// Attested ACK. `machine` signs the origin. No waiter is registered here.
    fn attested_ack_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: &MachineKeypair,
        request_byte: u8,
    ) -> PubSubMessage {
        let created_at_unix_ms = now_unix_ms();
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_V1,
            request_id: [request_byte; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms,
            expires_at_unix_ms: created_at_unix_ms + 60_000,
            body: DmBody::Ack(crate::dm::DmAckBody {
                acks_request_id: [request_byte; 16],
                outcome: DmAckOutcome::Accepted,
            }),
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(machine).expect("machine attest");
        envelope.origin_attestation = Some(attestation);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    /// #213 sender: signed envelope WITH a valid origin attestation from
    /// `machine` (which therefore owns `sender_machine_id`).
    fn attested_payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: &MachineKeypair,
        request_byte: u8,
    ) -> PubSubMessage {
        attested_payload_message_at(harness, sender, machine, request_byte, now_unix_ms())
    }

    /// Same as [`attested_payload_message`], with an explicit `created_at`.
    /// The binding cache orders updates by `created_at / 1000`.
    fn attested_payload_message_at(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: &MachineKeypair,
        request_byte: u8,
        created_at_unix_ms: u64,
    ) -> PubSubMessage {
        let body = EnvelopeBuilder::build_payload_body(
            &[request_byte; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms,
            b"security regression payload".to_vec(),
            None,
            &harness.recipient_kem.public_bytes,
        )
        .expect("build payload body");
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_V1,
            request_id: [request_byte; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms,
            expires_at_unix_ms: created_at_unix_ms + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(machine).expect("machine attest");
        envelope.origin_attestation = Some(attestation);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    // ── ADR 0030 §1 receiver durable path ─────────────────────────────

    /// Start a real history service in the harness tempdir and attach its
    /// handle to the pipeline. The service is returned so a test can shut the
    /// writer down mid-flight to force a commit failure.
    fn attach_history(harness: &mut InboxHarness) -> crate::history::HistoryService {
        let config = crate::history::HistoryConfig {
            db_path: Some(harness._tempdir.path().join("history.db")),
            ..crate::history::HistoryConfig::daemon_default()
        };
        let service = crate::history::HistoryService::start(&config, harness._tempdir.path())
            .expect("history service");
        harness.pipeline.history = Some(service.handle());
        service
    }

    /// A signed v2 (durable) payload envelope carrying `application_payload`.
    fn durable_payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
        application_payload: &[u8],
    ) -> PubSubMessage {
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            harness,
            sender,
            claimed_machine,
            request_byte,
            DM_PROTOCOL_DURABLE_ACK,
            application_payload.to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, sender);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    fn committed_rows(
        history: &crate::history::HistoryHandle,
        sender: &AgentKeypair,
        request_byte: u8,
    ) -> Vec<crate::history::StoredRecord> {
        history
            .store()
            .find_by_logical_request(
                &hex::encode(sender.agent_id().as_bytes()),
                [request_byte; 16],
            )
            .expect("logical request lookup")
    }

    /// ADR 0030 §1: the ACK exists only because the commit succeeded. With the
    /// writer stopped the commit cannot succeed, so no ACK may be emitted —
    /// and crucially it must NOT degrade to a v1 ACK, which would hand the
    /// sender a weaker receipt it cannot tell apart from the durable one.
    #[tokio::test]
    async fn durable_ack_is_withheld_when_history_commit_fails() {
        let sender = test_keypair();
        let machine = MachineId([0xD1; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        // Stop the writer thread; the retained handle now fails every commit.
        service.shutdown().await;

        let message = durable_payload_message(&harness, &sender, machine, 0x51, b"durable hello");
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert!(
            committed_rows(&history, &sender, 0x51).is_empty(),
            "a failed commit must leave no durable row"
        );
        assert!(
            harness
                .pipeline
                .cache
                .lookup(&crate::dm::DedupeKey::new(
                    *sender.agent_id().as_bytes(),
                    [0x51; 16]
                ))
                .is_none(),
            "a withheld ACK must not publish a completion into the replay cache"
        );
    }

    /// The same ordering asserted directly on the durable path's decision, so
    /// "no ACK" is a checked outcome rather than an absence inferred from
    /// side effects.
    #[tokio::test]
    async fn durable_path_reports_withheld_ack_on_commit_failure() {
        let sender = test_keypair();
        let machine = MachineId([0xD2; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let service = attach_history(&mut harness);
        service.shutdown().await;

        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x52,
            DM_PROTOCOL_DURABLE_ACK,
            b"durable hello".to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);

        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                b"durable hello".to_vec(),
                TrustDecision::Accept,
                machine,
                true,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;

        assert_eq!(decision, DurableAckDecision::Withheld("commit_failed"));
    }

    /// Happy path: commit lands first, then a v2-stamped ACK, and the schema
    /// v4 columns are populated — they are what makes the restart-spanning
    /// lookup in step 3 possible at all.
    #[tokio::test]
    async fn durable_path_commits_before_acking_and_stamps_v2() {
        let sender = test_keypair();
        let machine = MachineId([0xD3; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x53,
            DM_PROTOCOL_DURABLE_ACK,
            b"durable hello".to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);

        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                b"durable hello".to_vec(),
                TrustDecision::Accept,
                machine,
                true,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;

        assert_eq!(
            decision,
            DurableAckDecision::Acked {
                protocol_version: DM_PROTOCOL_DURABLE_ACK,
                accepted: true,
            }
        );

        let rows = committed_rows(&history, &sender, 0x53);
        assert_eq!(rows.len(), 1, "exactly one durable row per logical request");
        assert_eq!(rows[0].record.payload, b"durable hello".to_vec());
        assert_eq!(
            rows[0].record.ingress_sender_agent.as_deref(),
            Some(hex::encode(sender.agent_id().as_bytes()).as_str()),
            "schema v4 ingress_sender_agent must be written"
        );
        assert_eq!(
            rows[0].record.logical_request_id,
            Some([0x53; 16]),
            "schema v4 logical_request_id must be written"
        );
    }

    /// ADR 0030 §1 step 2: a replayed logical request is re-ACKed from the
    /// binding, never dispatched or committed a second time.
    #[tokio::test]
    async fn durable_replay_rebinds_instead_of_committing_twice() {
        let sender = test_keypair();
        let machine = MachineId([0xD4; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        for _ in 0..2 {
            let message =
                durable_payload_message(&harness, &sender, machine, 0x54, b"durable hello");
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;
        }

        let rows = committed_rows(&history, &sender, 0x54);
        assert_eq!(
            rows.len(),
            1,
            "a replayed logical request must not commit a second durable row"
        );
    }

    /// ADR 0030 §1 step 2: the binding is over the accepted bytes, so the
    /// same request id carrying different content is refused rather than
    /// re-ACKed as the original delivery.
    #[tokio::test]
    async fn durable_replay_with_different_bytes_is_refused() {
        let sender = test_keypair();
        let machine = MachineId([0xD5; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);

        let first = durable_payload_message(&harness, &sender, machine, 0x55, b"original bytes");
        harness
            .pipeline
            .handle_incoming(first, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x55,
            DM_PROTOCOL_DURABLE_ACK,
            b"different bytes".to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);
        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                b"different bytes".to_vec(),
                TrustDecision::Accept,
                machine,
                true,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;

        assert_eq!(
            decision,
            DurableAckDecision::Acked {
                protocol_version: DM_PROTOCOL_DURABLE_ACK,
                accepted: false,
            },
            "a rebound logical request must be refused, not accepted"
        );
    }

    /// Subscribe to the topic ACKs for `sender` land on, so a test can assert
    /// the outcome the receiver actually put on the wire. `DurableAckDecision`
    /// records only *that* a refusal was ACKed; which refusal it was is the
    /// whole product contract, and it is only observable here.
    async fn watch_acks_to(harness: &InboxHarness, sender: &AgentKeypair) -> Subscription {
        harness
            .pipeline
            .pubsub
            .subscribe_topic_id(
                DmInboxService::inbox_topic_name(&sender.agent_id()),
                dm_inbox_topic(&sender.agent_id()),
            )
            .await
    }

    async fn next_ack_outcome(subscription: &mut Subscription) -> DmAckOutcome {
        let message = tokio::time::timeout(Duration::from_secs(5), subscription.recv())
            .await
            .expect("an ACK must be published within the timeout")
            .expect("ACK subscription closed before an ACK arrived");
        let envelope =
            DmEnvelope::from_wire_bytes(&message.payload).expect("ACK envelope should decode");
        match envelope.body {
            DmBody::Ack(ack) => ack.outcome,
            other => panic!("expected an ACK envelope, got {other:?}"),
        }
    }

    /// ADR 0030 slice 4 rebind. Both binding-conflict sites answered
    /// `AckSemanticsUnavailable` until `IdempotencyConflict` existed, which
    /// told a product "the peer needs upgrading" when the truth was "your
    /// client reused an idempotency key for different bytes". The two errors
    /// prescribe opposite repairs — retry-later versus never-retry-these-bytes
    /// — so conflating them is a user-visible defect, not a naming quibble.
    #[tokio::test]
    async fn a_rebound_logical_request_is_answered_idempotency_conflict() {
        let sender = test_keypair();
        let machine = MachineId([0xD6; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let mut acks = watch_acks_to(&harness, &sender).await;

        let first = durable_payload_message(&harness, &sender, machine, 0x56, b"original bytes");
        harness
            .pipeline
            .handle_incoming(first, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_eq!(
            next_ack_outcome(&mut acks).await,
            DmAckOutcome::Accepted,
            "the first delivery is a normal durable acceptance"
        );

        // Replay-cache binding check: the id is still hot in memory.
        let rebound = durable_payload_message(&harness, &sender, machine, 0x56, b"different bytes");
        harness
            .pipeline
            .handle_incoming(rebound, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let hot = next_ack_outcome(&mut acks).await;
        assert!(
            matches!(hot, DmAckOutcome::IdempotencyConflict { .. }),
            "a hot rebind must be an idempotency conflict, not a capability gap: {hot:?}"
        );

        // Restart: the replay cache is memory-only (ADR 0030 §1), so the same
        // rebind must now be caught by the durable-history lookup instead —
        // the site that has to reach the same verdict for the guarantee to
        // survive a crash.
        harness.pipeline.cache = Arc::new(RecentDeliveryCache::with_defaults());
        let after_restart =
            durable_payload_message(&harness, &sender, machine, 0x56, b"different bytes");
        harness
            .pipeline
            .handle_incoming(after_restart, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert!(
            matches!(
                next_ack_outcome(&mut acks).await,
                DmAckOutcome::IdempotencyConflict { .. }
            ),
            "the durable-history conflict path must agree with the replay-cache path"
        );
    }

    /// ADR 0030 §2 mixed version: a 0.37 peer's v1 envelope keeps exactly its
    /// old behaviour on a durable-capable receiver — delivered, and ACKed with
    /// v1 semantics. Enabling durable history must not silently upgrade the
    /// receipt an old sender is handed.
    #[tokio::test]
    async fn v1_envelope_receives_v1_ack_even_with_durable_history_enabled() {
        let sender = test_keypair();
        let machine = MachineId([0xD6; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);

        let message = payload_message(&harness, &sender, machine, 0x56);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("v1 delivery timeout")
            .expect("v1 delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());

        let cached = harness
            .pipeline
            .cache
            .lookup(&crate::dm::DedupeKey::new(
                *sender.agent_id().as_bytes(),
                [0x56; 16],
            ))
            .expect("v1 completion is cached");
        assert_eq!(
            cached.protocol_version, DM_PROTOCOL_V1,
            "a v1 envelope must complete under v1 semantics"
        );
        assert!(
            cached.durable_binding.is_none(),
            "the v1 path must not publish a durable binding"
        );
    }

    /// ADR 0030 §2: a v2 request is never silently downgraded. Without a
    /// history handle there is nothing to commit to, so the ACK is withheld
    /// rather than answered at v1.
    #[tokio::test]
    async fn v2_envelope_without_history_is_never_downgraded_to_v1() {
        let sender = test_keypair();
        let machine = MachineId([0xD7; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        assert!(harness.pipeline.history.is_none());

        let message = durable_payload_message(&harness, &sender, machine, 0x57, b"durable hello");
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .cache
                .lookup(&crate::dm::DedupeKey::new(
                    *sender.agent_id().as_bytes(),
                    [0x57; 16]
                ))
                .is_none(),
            "a withheld v2 request must leave no completion behind"
        );
    }

    /// Drive one v2 typed payload through the durable path with `route`
    /// installed, returning the decision. `respond` receives the payload the
    /// handler would see and decides what (if anything) to report back.
    async fn durable_typed_decision<F>(
        request_byte: u8,
        durable_completion: bool,
        respond: F,
    ) -> DurableAckDecision
    where
        F: FnOnce(DmTypedPayload) + Send + 'static,
    {
        let sender = test_keypair();
        let machine = MachineId([0xD8; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let (tx, mut rx) = mpsc::channel::<DmTypedPayload>(8);
        harness.pipeline.typed_payload_routes = vec![DmTypedPayloadRoute {
            durable_completion,
            prefix: b"X0X-KV-DELTA-V1\n".to_vec(),
            sender: tx,
            validator: None,
        }];
        let handler = tokio::spawn(async move {
            if let Some(typed) = rx.recv().await {
                respond(typed);
            }
        });

        let mut payload = b"X0X-KV-DELTA-V1\n".to_vec();
        payload.extend_from_slice(b"{\"k\":1}");
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            request_byte,
            DM_PROTOCOL_DURABLE_ACK,
            payload.clone(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);

        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                payload,
                TrustDecision::Accept,
                machine,
                true,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;
        handler.abort();
        decision
    }

    /// ADR 0030 §7 obligation upgrade — this is the slice-2 lock, deliberately
    /// changed. Slice 2 withheld every v2 ACK on a typed route; slice 3 lets a
    /// handler earn one by reporting that the payload is durably recorded on
    /// its own surface. `Inserted` and `Duplicate` are the only signals that
    /// release the ACK, mirroring the history store's proof that exactly one
    /// durable record exists.
    #[tokio::test]
    async fn durable_typed_route_acks_on_handler_completion() {
        for completion in [
            DmTypedPayloadCompletion::Inserted,
            DmTypedPayloadCompletion::Duplicate,
        ] {
            let decision = durable_typed_decision(0x58, true, move |typed| {
                assert_eq!(
                    typed.request_id, [0x58; 16],
                    "handler must receive the logical request id it dedupes on"
                );
                if let Some(tx) = typed.completion {
                    let _ = tx.send(Ok(completion));
                }
            })
            .await;
            assert_eq!(
                decision,
                DurableAckDecision::Acked {
                    protocol_version: DM_PROTOCOL_DURABLE_ACK,
                    accepted: true,
                },
                "{completion:?} must release the durable ACK"
            );
        }
    }

    /// A route that has not opted in still gets no v2 ACK. This daemon will
    /// not certify durability for a handler that never promised it — stated
    /// policy, which is why it has its own distinct stage.
    #[tokio::test]
    async fn durable_typed_route_without_opt_in_is_withheld_by_policy() {
        let decision = durable_typed_decision(0x59, false, |_typed| {}).await;
        assert_eq!(
            decision,
            DurableAckDecision::Withheld("typed_route_not_durable")
        );
    }

    /// Every way a handler can fail to confirm withholds the ACK. Each of
    /// these would otherwise hand the sender a durable receipt for a payload
    /// that was never durably recorded.
    #[tokio::test]
    async fn durable_typed_route_withholds_on_every_non_completion() {
        // Handler reports failure.
        assert_eq!(
            durable_typed_decision(0x5A, true, |typed| {
                if let Some(tx) = typed.completion {
                    let _ = tx.send(Err("store write failed".to_string()));
                }
            })
            .await,
            DurableAckDecision::Withheld("typed_handler_failed")
        );

        // Handler drops the completion sender — the "forgot to answer" case,
        // including any early return on the handler's own error path.
        assert_eq!(
            durable_typed_decision(0x5B, true, |typed| {
                drop(typed.completion);
            })
            .await,
            DurableAckDecision::Withheld("typed_completion_dropped")
        );
    }

    #[test]
    fn cached_v1_completion_refuses_a_v2_request() {
        let cached = crate::dm::CachedOutcome {
            outcome: DmAckOutcome::Accepted,
            protocol_version: DM_PROTOCOL_V1,
            durable_binding: None,
            first_seen: std::time::Instant::now(),
        };
        // ADR 0030 §2 names this outcome explicitly. It must NOT be
        // `RejectedByPolicy`: nothing about the trust relationship failed,
        // and the sender maps that variant to `RecipientRejected`, which
        // would tell a product UI "peer blocked you" instead of "you cannot
        // have a durable receipt for this request".
        assert!(matches!(
            cached_ack_for_protocol(&cached, DM_PROTOCOL_DURABLE_ACK),
            DmAckOutcome::AckSemanticsUnavailable { .. }
        ));
        assert!(matches!(
            cached_ack_for_protocol(&cached, DM_PROTOCOL_V1),
            DmAckOutcome::Accepted
        ));
    }

    /// Wire safety for the appended `AckSemanticsUnavailable` variant: a
    /// v1-only 0.37 peer can never be sent it, because it asks for at most v1
    /// and any cached completion is at least v1. If this ever regresses, an
    /// 0.37 receiver would fail to postcard-decode the ACK and the send would
    /// degrade to a timeout.
    #[test]
    fn a_v1_request_is_never_answered_with_the_new_ack_variant() {
        for cached_version in [DM_PROTOCOL_V1, DM_PROTOCOL_DURABLE_ACK] {
            for outcome in [
                DmAckOutcome::Accepted,
                DmAckOutcome::RejectedByPolicy {
                    reason: "blocked".to_string(),
                },
            ] {
                let cached = crate::dm::CachedOutcome {
                    outcome,
                    protocol_version: cached_version,
                    durable_binding: None,
                    first_seen: std::time::Instant::now(),
                };
                assert!(
                    !matches!(
                        cached_ack_for_protocol(&cached, DM_PROTOCOL_V1),
                        DmAckOutcome::AckSemanticsUnavailable { .. }
                    ),
                    "a v1 request must never be answered with a variant 0.37 cannot decode"
                );
            }
        }
    }

    /// ADR 0030 ACK liveness: the durable publisher must never make the inbox
    /// loop wait. A saturated queue is reported to the caller rather than
    /// awaited — the receiver has already committed, so the sender timing out
    /// is the documented safe failure, whereas blocking here would stall every
    /// later DM behind one wedged ACK route.
    #[tokio::test]
    async fn a_saturated_ack_queue_is_reported_rather_than_awaited() {
        let (sender, mut receiver) = mpsc::channel(DURABLE_ACK_QUEUE_CAPACITY);
        let handle = AckPublisherHandle { sender };
        let job = || AckPublishJob {
            recipient: AgentId([7; 32]),
            acked_request_id: [1; 16],
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            encoded: Bytes::from_static(b"ack"),
        };

        for _ in 0..DURABLE_ACK_QUEUE_CAPACITY {
            handle
                .try_publish(job())
                .expect("queue accepts up to its capacity");
        }
        assert!(
            matches!(
                handle.try_publish(job()),
                Err(NetworkError::RemoteReceiveBackpressured(_))
            ),
            "the job past capacity must be refused, not block the inbox loop"
        );

        receiver.close();
        while receiver.try_recv().is_ok() {}
        assert!(
            matches!(
                handle.try_publish(job()),
                Err(NetworkError::ChannelClosed(_))
            ),
            "a stopped worker must surface as an error, never a silent drop"
        );
    }

    /// Both routes failing is still an error; the caller records
    /// `ack_publish_route_failed` so gates can tell ACK never left.
    #[tokio::test]
    async fn both_failed_ack_routes_are_an_error() {
        let primary = async { Err(NetworkError::BroadcastError("targeted".into())) };
        let legacy = async { Err(NetworkError::BroadcastError("legacy-bus".into())) };
        let result = publish_durable_ack_routes(DURABLE_ACK_ROUTE_TIMEOUT, primary, legacy).await;
        assert!(
            matches!(result, Err(NetworkError::BroadcastError(_))),
            "both-fail must remain Err + ack_publish_route_failed at the caller: {result:?}"
        );
    }

    #[test]
    fn reverse_ack_prewarm_is_only_for_a_trusted_other_peer() {
        let self_id = AgentId([1; 32]);
        let peer = AgentId([2; 32]);
        assert!(
            should_warm_reverse_ack(true, &self_id, &peer),
            "a Trusted other peer is the Direct-connect pre-warm case"
        );
        assert!(
            !should_warm_reverse_ack(false, &self_id, &peer),
            "untrusted peers must not join extra inbox topics on connect"
        );
        assert!(
            !should_warm_reverse_ack(true, &self_id, &self_id),
            "self-connect must not pre-warm"
        );
    }

    /// Invariant: first durable send to a Direct-connected peer must not be
    /// the event that joins self inbox, peer inbox, or the compatibility bus.
    /// Warm uses the real inbox `TopicId`s (Leaf-safe subscribed path), not
    /// the name-derived ids `refresh_topic_peers` would invent.
    #[tokio::test]
    async fn reverse_ack_prewarm_joins_inbox_and_bus_before_any_publish() {
        let node = Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub =
            PubSubManager::new(node, crate::gossip::pubsub::test_support::signing_context())
                .expect("pubsub");
        let self_id = AgentId([0xA1; 32]);
        let peer = AgentId([0xB2; 32]);
        let self_inbox = dm_inbox_topic(&self_id);
        let peer_inbox = dm_inbox_topic(&peer);
        let bus = saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes());
        let name_derived = saorsa_gossip_types::TopicId::from_entity(
            DmInboxService::inbox_topic_name(&self_id).as_bytes(),
        );
        assert_ne!(
            self_inbox, name_derived,
            "inbox TopicId is domain-separated; a name-derived id is the pass-through trap"
        );

        let before = pubsub.plumtree_topic_ids().await;
        assert!(
            !before.contains(&self_inbox)
                && !before.contains(&peer_inbox)
                && !before.contains(&bus),
            "pre-warm must be what joins these topics, not PubSubManager construction"
        );

        warm_reverse_ack_topics(&pubsub, &self_id, &peer).await;

        let warmed = pubsub.plumtree_topic_ids().await;
        assert!(
            warmed.contains(&self_inbox),
            "self inbox (where ACKs land) must be joined before first durable POST: {warmed:?}"
        );
        assert!(
            warmed.contains(&peer_inbox),
            "peer inbox must be joined before first durable POST: {warmed:?}"
        );
        assert!(
            warmed.contains(&bus),
            "compatibility bus must be joined before first durable POST: {warmed:?}"
        );
        assert!(
            !warmed.contains(&name_derived),
            "must not create a name-derived pass-through topic id (Leaf hygiene)"
        );

        pubsub
            .publish_topic_id(
                DmInboxService::inbox_topic_name(&peer),
                peer_inbox,
                Bytes::from_static(b"not-the-join"),
            )
            .await
            .expect("publish after pre-warm");
        let after_publish = pubsub.plumtree_topic_ids().await;
        assert!(
            after_publish.contains(&peer_inbox),
            "publish must reuse the pre-warmed peer inbox membership"
        );
    }

    /// #396 race regression: concurrent warmers (outbound Direct connect vs
    /// inbound PeerConnected) must converge to exactly ONE membership hold
    /// per topic. The original check-then-insert read the refcount, then
    /// subscribed, then inserted the hold under three separate lock
    /// acquisitions — both warmers observed "not subscribed", both spawned
    /// permanent drain holds, leaking a duplicate subscription per topic
    /// forever. The fix linearizes creation under the holds write guard.
    #[tokio::test]
    async fn concurrent_reverse_ack_warmers_create_a_single_membership_hold() {
        let node = Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub = Arc::new(
            PubSubManager::new(node, crate::gossip::pubsub::test_support::signing_context())
                .expect("pubsub"),
        );
        let peer = AgentId([0xC4; 32]);
        let peer_inbox_topic_id = dm_inbox_topic(&peer);
        let peer_inbox_name = DmInboxService::inbox_topic_name(&peer);

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut warmers = Vec::new();
        for _ in 0..2 {
            let pubsub = Arc::clone(&pubsub);
            let barrier = Arc::clone(&barrier);
            let name = peer_inbox_name.clone();
            warmers.push(tokio::spawn(async move {
                barrier.wait().await;
                pubsub
                    .ensure_subscribed_topic_id(&name, peer_inbox_topic_id)
                    .await;
            }));
        }
        for warmer in warmers {
            warmer.await.expect("concurrent warmers must not panic");
        }

        let holds = pubsub.membership_hold_count().await;
        assert_eq!(
            holds, 1,
            "two concurrent warmers for one topic must create exactly one hold, got {holds}"
        );
        assert!(
            pubsub.is_topic_subscribed(&peer_inbox_name).await,
            "the winning warmer's subscription must be live"
        );
    }

    /// C4: Direct-connect pre-warm must pre-subscribe the peer inbox so the
    /// first durable POST is not the cold `publish_topic_id` that joins it.
    #[tokio::test]
    async fn reverse_ack_prewarm_presubscribes_peer_inbox_before_first_publish() {
        let node = Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub =
            PubSubManager::new(node, crate::gossip::pubsub::test_support::signing_context())
                .expect("pubsub");
        let self_id = AgentId([0xC3; 32]);
        let peer = AgentId([0xD4; 32]);
        let peer_name = DmInboxService::inbox_topic_name(&peer);
        let peer_inbox = dm_inbox_topic(&peer);

        assert!(
            !pubsub.is_topic_subscribed(&peer_name).await,
            "peer inbox must be unsubscribed before Direct-connect pre-warm"
        );

        warm_reverse_ack_topics(&pubsub, &self_id, &peer).await;

        assert!(
            pubsub.is_topic_subscribed(&peer_name).await,
            "C4: peer inbox must be subscribed before the first durable POST"
        );
        assert!(
            pubsub.plumtree_topic_ids().await.contains(&peer_inbox),
            "C4 pre-subscribe must join the real inbox TopicId, not wait for publish"
        );

        let subscribed_before_publish = pubsub.subscription_count().await;
        pubsub
            .publish_topic_id(
                peer_name.clone(),
                peer_inbox,
                Bytes::from_static(b"first-durable-must-not-join"),
            )
            .await
            .expect("publish after C4 pre-subscribe");
        assert_eq!(
            pubsub.subscription_count().await,
            subscribed_before_publish,
            "first publish_topic_id must not be the subscribe/join event"
        );
        assert!(
            pubsub.is_topic_subscribed(&peer_name).await,
            "peer inbox membership hold must survive the first durable publish"
        );
    }

    /// The v1 publish path must be untouched by the hedging work: a v1 ACK
    /// still goes to the targeted topic only, and reaches the compatibility
    /// bus only when the payload itself arrived there. Hedging every v1 ACK
    /// onto the shared bus would add gossip traffic for every 0.37 peer in the
    /// mesh, which is not what this change is for.
    #[tokio::test]
    async fn a_v1_ack_is_not_hedged_onto_the_compatibility_bus() {
        let sender = test_keypair();
        let machine = MachineId([0xD8; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let mut bus = harness
            .pipeline
            .pubsub
            .subscribe(DM_BUS_TOPIC.to_string())
            .await;

        harness
            .pipeline
            .publish_ack_for_protocol(
                sender.agent_id(),
                [0x59; 16],
                DmAckOutcome::Accepted,
                DM_PROTOCOL_V1,
                false,
            )
            .await
            .expect("v1 ACK publishes");

        assert!(
            tokio::time::timeout(Duration::from_millis(300), bus.recv())
                .await
                .is_err(),
            "a v1 ACK with ack_legacy_bus=false must not reach the shared bus"
        );
    }

    /// The other half of the hedge contract: a durable v2 ACK reaches the
    /// compatibility bus even when the payload itself never arrived there
    /// (`ack_legacy_bus = false`). The bus route is what rescues a sender
    /// whose targeted-topic delivery is wedged — the "committed but never
    /// acked" 504 — so if v2 ever stops hedging onto the bus, the failure
    /// this worker exists to remove comes back silently.
    #[tokio::test]
    async fn a_v2_ack_is_always_hedged_onto_the_compatibility_bus() {
        let sender = test_keypair();
        let machine = MachineId([0xD9; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let mut bus = harness
            .pipeline
            .pubsub
            .subscribe(DM_BUS_TOPIC.to_string())
            .await;

        harness
            .pipeline
            .publish_ack_for_protocol(
                sender.agent_id(),
                [0x60; 16],
                DmAckOutcome::Accepted,
                DM_PROTOCOL_DURABLE_ACK,
                false,
            )
            .await
            .expect("v2 ACK schedules in the background publisher");

        let message = tokio::time::timeout(Duration::from_secs(5), bus.recv())
            .await
            .expect("a v2 ACK must reach the shared bus even with ack_legacy_bus=false")
            .expect("bus subscription stays open");
        let envelope = DmEnvelope::from_wire_bytes(&message.payload)
            .expect("bus payload decodes as a DM envelope");
        assert_eq!(envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
        assert_eq!(envelope.recipient_agent_id, *sender.agent_id().as_bytes());
    }

    struct RecordingDirectHedge {
        tx: mpsc::UnboundedSender<(AgentId, Bytes)>,
        outcome: DirectAckHedgeOutcome,
    }

    #[async_trait]
    impl DirectAckHedge for RecordingDirectHedge {
        async fn hedge(&self, recipient: AgentId, encoded: Bytes) -> DirectAckHedgeOutcome {
            let _ = self.tx.send((recipient, encoded));
            self.outcome
        }
    }

    /// C5: after history commit the same v2 ACK envelope is handed to a live
    /// Direct/typed hedge. This is not prefer_raw_quic on the durable SEND
    /// path — the payload remains the gossip_inbox ACK envelope.
    #[tokio::test]
    async fn durable_ack_is_hedged_on_direct_typed_after_history_commit() {
        let sender = test_keypair();
        let machine = MachineId([0xC5; 32]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let hedge = Arc::new(RecordingDirectHedge {
            tx,
            outcome: DirectAckHedgeOutcome::Sent,
        });
        let mut harness =
            make_inbox_harness_with_hedge(&sender, Some(machine), None, Some(hedge)).await;
        let _service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        let message = durable_payload_message(&harness, &sender, machine, 0xC5, b"c5 hedge");
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let rows = committed_rows(&history, &sender, 0xC5);
        assert_eq!(
            rows.len(),
            1,
            "Direct hedge must run only after the durable row exists"
        );

        let (recipient, encoded) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("C5 Direct hedge must fire after commit")
            .expect("hedge channel stays open");
        assert_eq!(recipient, sender.agent_id());
        let envelope =
            DmEnvelope::from_wire_bytes(&encoded).expect("Direct hedge carries the ACK envelope");
        assert_eq!(envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
        match envelope.body {
            DmBody::Ack(ack) => assert_eq!(ack.acks_request_id, [0xC5; 16]),
            other => panic!("Direct hedge must carry the ACK envelope, got {other:?}"),
        }
    }

    /// C5 fail-open: missing Direct must not fail the ACK. Gossip hedges
    /// still publish the same envelope.
    #[tokio::test]
    async fn durable_ack_fail_opens_when_direct_is_missing() {
        let sender = test_keypair();
        let machine = MachineId([0xC6; 32]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let hedge = Arc::new(RecordingDirectHedge {
            tx,
            outcome: DirectAckHedgeOutcome::SkippedNoDirect,
        });
        let mut harness =
            make_inbox_harness_with_hedge(&sender, Some(machine), None, Some(hedge)).await;
        let _service = attach_history(&mut harness);
        let mut bus = harness
            .pipeline
            .pubsub
            .subscribe(DM_BUS_TOPIC.to_string())
            .await;

        harness
            .pipeline
            .publish_ack_for_protocol(
                sender.agent_id(),
                [0xC6; 16],
                DmAckOutcome::Accepted,
                DM_PROTOCOL_DURABLE_ACK,
                false,
            )
            .await
            .expect("missing Direct must not fail the ACK schedule");

        let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("fail-open hedge is still invoked")
            .expect("hedge channel stays open");
        let message = tokio::time::timeout(Duration::from_secs(5), bus.recv())
            .await
            .expect("gossip compatibility-bus hedge must still deliver")
            .expect("bus subscription stays open");
        let envelope = DmEnvelope::from_wire_bytes(&message.payload).expect("bus ACK decodes");
        assert_eq!(envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
    }

    /// C5: the sender waiter completes on the envelope request_id only.
    /// Direct send-ok is not a receipt.
    #[tokio::test]
    async fn waiter_completes_on_envelope_request_id_not_direct_send_ok() {
        let inflight = InFlightAcks::new();
        let request_id = [0xC7; 16];
        let ack_sender = AgentId([0x11; 32]);
        let ack_machine = MachineId([0x22; 32]);
        let mut rx = inflight.register_for_protocol(
            request_id,
            DM_PROTOCOL_DURABLE_ACK,
            ack_sender,
            Some(ack_machine),
        );

        assert_eq!(
            direct_ack_hedge_outcome(true, Some(true)),
            DirectAckHedgeOutcome::Sent,
            "a live Direct send-ok is only a hedge, not a receipt"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut rx)
                .await
                .is_err(),
            "Direct send-ok must not complete the waiter"
        );

        assert!(
            inflight.resolve_for_protocol(
                &request_id,
                DM_PROTOCOL_DURABLE_ACK,
                ack_sender,
                ack_machine,
                DmAckOutcome::Accepted,
            ),
            "the waiter is keyed on the ACK envelope request_id"
        );
        assert_eq!(
            rx.await.expect("oneshot"),
            DmAckOutcome::Accepted,
            "only the matching request_id envelope completes the waiter"
        );
    }

    /// #380 leaf-reverse-ACK: the failing fleet case, end-to-end at the
    /// PubSubManager level. A Leaf receiver with ZERO prior subscription
    /// state (no C2/C4 connect-event warm) receives a durable DM. The fix
    /// pre-subscribes the sender's inbox topic ON RECEIPT (the authoritative
    /// moment), so the ACK publish that follows has a gossip route. Also
    /// verifies the agent→machine registration for the C5 Direct hedge.
    #[tokio::test]
    async fn leaf_receiver_of_durable_dm_pre_subscribes_sender_inbox_on_receipt() {
        let sender = test_keypair();
        let machine_kp = MachineKeypair::generate().expect("machine");
        let machine = machine_kp.machine_id();
        let harness = make_inbox_harness(&sender, Some(machine), None).await;

        // Zero prior subscription state: prove the sender's inbox topic is
        // NOT in PlumTree before the DM arrives (the leaf fleet condition).
        let sender_inbox_topic_id = dm_inbox_topic(&sender.agent_id());
        let sender_inbox_name = DmInboxService::inbox_topic_name(&sender.agent_id());
        let before = harness.pipeline.pubsub.plumtree_topic_ids().await;
        assert!(
            !before.contains(&sender_inbox_topic_id),
            "precondition: sender inbox topic NOT subscribed (the leaf zero-state case)"
        );

        // Build a real durable v2 envelope using the production builder.
        let request_id = [0xE1; 16];
        let created = now_unix_ms();
        let envelope = EnvelopeBuilder::build_payload_envelope_with_version(
            DM_PROTOCOL_DURABLE_ACK,
            request_id,
            &sender.agent_id(),
            &machine,
            &machine_kp,
            &harness.recipient_agent_id,
            &harness.recipient_kem.public_bytes,
            created,
            created + ACK_ENVELOPE_LIFETIME_MS,
            b"leaf-reverse-ack-proof".to_vec(),
            |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(sender.secret_key(), bytes)
                    .map(|sig| sig.as_bytes().to_vec())
                    .map_err(|e| e.to_string())
            },
        )
        .expect("build durable envelope");
        let encoded = Bytes::from(envelope.to_wire_bytes().expect("encode"));

        let msg = PubSubMessage {
            topic: sender_inbox_name.clone(),
            payload: encoded,
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        harness
            .pipeline
            .handle_incoming(msg, false, crate::dm::DmAckIngress::Subscription)
            .await;

        // The fix: the sender's inbox topic is now subscribed (the receipt
        // is the trigger), so the ACK publish has peers.
        let after = harness.pipeline.pubsub.plumtree_topic_ids().await;
        assert!(
            after.contains(&sender_inbox_topic_id),
            "receipt of a durable DM must pre-subscribe the sender's inbox for the reverse ACK: {after:?}"
        );
        assert!(
            harness
                .pipeline
                .pubsub
                .is_topic_subscribed(&sender_inbox_name)
                .await,
            "the subscription must be live (membership hold), not a one-shot refresh"
        );

        // The agent→machine mapping is registered from the envelope (fix b),
        // so the C5 Direct hedge can look up the sender.
        assert_eq!(
            harness.pipeline.dm.get_machine_id(&sender.agent_id()).await,
            Some(machine),
            "the verified envelope must register the sender's agent→machine binding for the C5 Direct hedge"
        );
    }

    fn signed_v1_ack_envelope_bytes(
        sender: &AgentKeypair,
        machine_kp: &MachineKeypair,
        recipient_agent_id: &AgentId,
        request_id: [u8; 16],
    ) -> Bytes {
        let created = now_unix_ms();
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_V1,
            request_id,
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine_kp.machine_id().as_bytes(),
            recipient_agent_id: *recipient_agent_id.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: created + ACK_ENVELOPE_LIFETIME_MS,
            body: EnvelopeBuilder::build_ack_body(request_id, DmAckOutcome::Accepted),
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope(&mut envelope, sender);
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            machine_kp.public_key().as_bytes().to_vec(),
        );
        attestation.sign(machine_kp).expect("attest v1 ACK");
        envelope.origin_attestation = Some(attestation);
        Bytes::from(envelope.to_wire_bytes().expect("encode v1 ACK"))
    }

    fn signed_ack_envelope_bytes(
        sender: &AgentKeypair,
        machine_kp: &MachineKeypair,
        recipient_agent_id: &AgentId,
        request_id: [u8; 16],
    ) -> Bytes {
        let created = now_unix_ms();
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            request_id,
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine_kp.machine_id().as_bytes(),
            recipient_agent_id: *recipient_agent_id.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: created + ACK_ENVELOPE_LIFETIME_MS,
            body: EnvelopeBuilder::build_ack_body(request_id, DmAckOutcome::Accepted),
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope(&mut envelope, sender);
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            machine_kp.public_key().as_bytes().to_vec(),
        );
        attestation.sign(machine_kp).expect("attest ACK");
        envelope.origin_attestation = Some(attestation);
        Bytes::from(envelope.to_wire_bytes().expect("encode ACK"))
    }

    /// C5 receive path: ingesting the same ACK envelope via Direct/typed
    /// completes the waiter. Fan-out as a user DM must not happen.
    #[tokio::test]
    async fn direct_typed_ack_envelope_completes_waiter_on_request_id() {
        let sender = test_keypair();
        let machine_kp = MachineKeypair::generate().expect("machine");
        let machine = machine_kp.machine_id();
        let harness = make_inbox_harness(&sender, Some(machine), None).await;
        let request_id = [0xC8; 16];
        let (waiter, ingress_cell) = harness
            .pipeline
            .inflight
            .register_for_protocol_with_provenance(
                request_id,
                DM_PROTOCOL_DURABLE_ACK,
                sender.agent_id(),
                Some(machine),
            );

        let created = now_unix_ms();
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            request_id: [0xC8; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: created + ACK_ENVELOPE_LIFETIME_MS,
            body: EnvelopeBuilder::build_ack_body(request_id, DmAckOutcome::Accepted),
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope(&mut envelope, &sender);
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            machine_kp.public_key().as_bytes().to_vec(),
        );
        attestation.sign(&machine_kp).expect("attest ACK");
        envelope.origin_attestation = Some(attestation);
        let encoded = Bytes::from(envelope.to_wire_bytes().expect("encode ACK"));

        assert!(
            harness
                .pipeline
                .ingest_direct_ack_envelope(
                    sender.agent_id(),
                    sender.public_key().as_bytes().to_vec(),
                    encoded,
                )
                .await,
            "the Direct/typed payload is the ACK envelope"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("waiter must complete from the Direct-ingested envelope")
                .expect("oneshot"),
            DmAckOutcome::Accepted
        );
        assert_eq!(
            *ingress_cell.lock().expect("cell"),
            Some(crate::dm::DmAckIngress::DirectTyped),
            "#461: the direct-typed hedge that carried the winning ACK must be reported"
        );
    }

    /// #563 P2: an authenticated V1 (non-durable) ACK resolves its v1 waiter
    /// NORMALLY — no failure, no negotiation change — but must NOT stamp
    /// provenance: `observed_ack_ingress` describes the DURABLE-ACK
    /// transport, and the HTTP mapper omits the field when it is None. The
    /// envelope is fully signed/attested and flows through the REAL
    /// subscription dispatch seam, exactly like a v1 gossip ACK would.
    #[tokio::test]
    async fn v1_ack_resolves_waiter_but_stamps_no_durable_ingress() {
        let sender = test_keypair();
        let machine_kp = MachineKeypair::generate().expect("machine");
        let machine = machine_kp.machine_id();
        let harness = make_inbox_harness(&sender, Some(machine), None).await;
        let request_id = [0xCB; 16];
        let (waiter, ingress_cell) = harness
            .pipeline
            .inflight
            .register_for_protocol_with_provenance(
                request_id,
                DM_PROTOCOL_V1,
                sender.agent_id(),
                Some(machine),
            );
        let encoded = signed_v1_ack_envelope_bytes(
            &sender,
            &machine_kp,
            &harness.recipient_agent_id,
            request_id,
        );
        let message = PubSubMessage {
            topic: String::from("dm-inbox"),
            payload: encoded,
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        dispatch_subscription_message(&harness.pipeline, message, false).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("v1 waiter must complete NORMALLY (no v1 failure)")
                .expect("oneshot"),
            DmAckOutcome::Accepted,
            "v1 ACKs keep their existing semantics"
        );
        assert_eq!(
            *ingress_cell.lock().expect("cell"),
            None,
            "#563: a v1 ACK must not populate durable-ACK provenance; the HTTP mapper omits the field on None"
        );
    }

    /// #461: an authenticated ACK delivered through the subscription-labelled
    /// ingress (the exact `handle_incoming` call `spawn_subscription_loop`
    /// makes) stamps `Subscription`. The literal loop wrapper itself needs
    /// transport-signed gossip frames and is not hermetically drivable; this
    /// exercises its precise stamping call site.
    #[tokio::test]
    async fn subscription_labelled_ack_stamps_subscription_ingress() {
        let sender = test_keypair();
        let machine_kp = MachineKeypair::generate().expect("machine");
        let machine = machine_kp.machine_id();
        let harness = make_inbox_harness(&sender, Some(machine), None).await;
        let request_id = [0xC9; 16];
        let (waiter, ingress_cell) = harness
            .pipeline
            .inflight
            .register_for_protocol_with_provenance(
                request_id,
                DM_PROTOCOL_DURABLE_ACK,
                sender.agent_id(),
                Some(machine),
            );
        let encoded = signed_ack_envelope_bytes(
            &sender,
            &machine_kp,
            &harness.recipient_agent_id,
            request_id,
        );
        let message = PubSubMessage {
            topic: String::from("dm-inbox"),
            payload: encoded,
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        // Production-selected label: the test drives the SAME dispatch seam
        // the subscription loop uses and cannot choose the ingress itself.
        dispatch_subscription_message(&harness.pipeline, message, false).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("waiter must complete from the subscription-labelled ACK")
                .expect("oneshot"),
            DmAckOutcome::Accepted
        );
        assert_eq!(
            *ingress_cell.lock().expect("cell"),
            Some(crate::dm::DmAckIngress::Subscription)
        );
    }

    /// #461: an INVALID-signature ACK leaves the waiter pending and the
    /// provenance cell `None`; the subsequent VALID ACK wins and stamps its
    /// own ingress. Unknown is never fabricated.
    #[tokio::test]
    async fn invalid_signature_ack_leaves_none_then_valid_wins() {
        let sender = test_keypair();
        let machine_kp = MachineKeypair::generate().expect("machine");
        let machine = machine_kp.machine_id();
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let request_id = [0xCA; 16];
        let (mut waiter, ingress_cell) = harness
            .pipeline
            .inflight
            .register_for_protocol_with_provenance(
                request_id,
                DM_PROTOCOL_DURABLE_ACK,
                sender.agent_id(),
                Some(machine),
            );
        let mut corrupted = signed_ack_envelope_bytes(
            &sender,
            &machine_kp,
            &harness.recipient_agent_id,
            request_id,
        )
        .to_vec();
        // Corrupt the trailing signature bytes.
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;
        let bad = Bytes::from(corrupted);
        let bad_message = PubSubMessage {
            topic: String::from("dm-inbox"),
            payload: bad,
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        dispatch_subscription_message(&harness.pipeline, bad_message, false).await;
        assert_eq!(*ingress_cell.lock().expect("cell"), None);
        assert!(
            waiter.try_recv().is_err(),
            "an invalid-signature ACK must not resolve the waiter"
        );

        let valid = signed_ack_envelope_bytes(
            &sender,
            &machine_kp,
            &harness.recipient_agent_id,
            request_id,
        );
        let good_message = PubSubMessage {
            topic: String::from("dm-inbox"),
            payload: valid,
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        dispatch_subscription_message(&harness.pipeline, good_message, false).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("valid ACK must resolve the waiter after the invalid one")
                .expect("oneshot"),
            DmAckOutcome::Accepted
        );
        assert_eq!(
            *ingress_cell.lock().expect("cell"),
            Some(crate::dm::DmAckIngress::Subscription),
            "the winner's ingress is the SEAM-selected label, not a test-supplied one"
        );
        assert_no_delivery(&mut harness.receiver).await;
    }

    #[test]
    fn ack_publish_eager_topics_are_inbox_and_bus_only() {
        let recipient = AgentId([0xC5; 32]);
        let topics = ack_publish_eager_topics(&recipient, false);
        assert_eq!(topics[0], dm_inbox_topic(&recipient));
        assert_eq!(topics[1], TopicId::from_entity(DM_BUS_TOPIC.as_bytes()));
        assert_eq!(
            topics.len(),
            2,
            "C5b must not prefer eager on any topic except inbox+bus"
        );
    }

    #[test]
    fn ack_publish_eager_topics_leave_only_targeted_inbox_when_opted_out() {
        let recipient = AgentId([0xC6; 32]);
        let topics = ack_publish_eager_topics(&recipient, true);
        assert_eq!(topics, vec![dm_inbox_topic(&recipient)]);
    }

    #[test]
    fn missing_direct_is_skipped_not_failed() {
        assert_eq!(
            direct_ack_hedge_outcome(false, None),
            DirectAckHedgeOutcome::SkippedNoDirect
        );
        assert_eq!(
            direct_ack_hedge_outcome(false, Some(true)),
            DirectAckHedgeOutcome::SkippedNoDirect
        );
    }

    /// The two pre-existing variants must keep their postcard discriminants,
    /// or every 0.37 peer stops decoding our ACKs.
    #[test]
    fn appending_the_new_ack_variant_preserves_legacy_discriminants() {
        let accepted = postcard::to_stdvec(&DmAckOutcome::Accepted).expect("encode accepted");
        assert_eq!(accepted.first(), Some(&0u8), "Accepted must stay variant 0");
        let rejected = postcard::to_stdvec(&DmAckOutcome::RejectedByPolicy {
            reason: String::new(),
        })
        .expect("encode rejected");
        assert_eq!(
            rejected.first(),
            Some(&1u8),
            "RejectedByPolicy must stay variant 1"
        );
        let unavailable = postcard::to_stdvec(&DmAckOutcome::AckSemanticsUnavailable {
            reason: String::new(),
        })
        .expect("encode unavailable");
        assert_eq!(
            unavailable.first(),
            Some(&2u8),
            "AckSemanticsUnavailable must keep the index slice 1 assigned it"
        );
        let conflict = postcard::to_stdvec(&DmAckOutcome::IdempotencyConflict {
            reason: String::new(),
        })
        .expect("encode conflict");
        assert_eq!(
            conflict.first(),
            Some(&3u8),
            "IdempotencyConflict must be appended last"
        );
    }

    async fn assert_no_delivery(receiver: &mut crate::direct::DirectMessageReceiver) {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), receiver.recv())
                .await
                .is_err(),
            "inbox unexpectedly delivered a rejected message"
        );
    }

    // ── Signature verification ────────────────────────────────────────

    #[test]
    fn verify_envelope_signature_accepts_valid_signature() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        assert!(verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_empty_signature() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let envelope = make_unsigned_envelope(&sender_kp, &recipient_id);

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_wrong_key() {
        let sender_kp = test_keypair();
        let wrong_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Verify with a different public key — must fail because the
        // derived AgentId won't match sender_agent_id in the envelope.
        assert!(!verify_envelope_signature(
            &envelope,
            wrong_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_tampered_body() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Tamper with the body after signing
        envelope.body = DmBody::Ack(crate::dm::DmAckBody {
            acks_request_id: [99u8; 16],
            outcome: crate::dm::DmAckOutcome::Accepted,
        });

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_tampered_timestamp() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Tamper with timestamp after signing
        envelope.created_at_unix_ms = 0;

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_garbage_public_key() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        let garbage_key = [0xFFu8; 3200]; // ML-DSA-65 public keys are 807 bytes
        assert!(!verify_envelope_signature(&envelope, &garbage_key));
    }

    #[test]
    fn verify_envelope_signature_rejects_empty_public_key() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        assert!(!verify_envelope_signature(&envelope, &[]));
    }

    #[test]
    fn verify_envelope_signature_rejects_tampered_sender_id() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Tamper with sender_agent_id after signing
        envelope.sender_agent_id = [0xFFu8; 32];

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    // ── Enforcement point 3: revocation gate ──────────────────────────

    /// A DM from a revoked sender MUST be dropped and counted in
    /// `incoming_dropped_revoked` (issue #130, EP3). The revocation is applied
    /// via the real `verify_and_insert` receive path with a valid
    /// self-revocation, and the assertion reads the real production counter —
    /// so this fails if the drop or the counter side-effect regresses.
    #[test]
    fn revoked_sender_dm_is_dropped_and_counted() {
        let dm = DirectMessaging::new();
        // A machine that is NOT revoked — isolates the drop to the agent revocation.
        let clean_machine = MachineId([0xAB; 32]);

        // A foreign sender self-revokes its own agent-id (valid authority).
        let sender_kp = test_keypair();
        let sender = sender_kp.agent_id();
        let now = now_unix_ms() / 1000;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(sender),
            sender_kp.public_key(),
            sender_kp.secret_key(),
            now,
            Some("compromised".to_string()),
        )
        .expect("sign self-revocation");
        let mut set = RevocationSet::new();
        set.verify_and_insert(record, None)
            .expect("self-revocation verifies and inserts");

        // A revoked sender's DM is dropped and increments the counter.
        let before = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert!(
            drop_if_sender_revoked(&dm, &set, &sender, &clean_machine),
            "a DM from a revoked sender must be dropped"
        );
        let after = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert_eq!(
            after,
            before + 1,
            "dropping a revoked DM must increment incoming_dropped_revoked"
        );

        // A non-revoked sender is NOT dropped and does NOT move the counter —
        // proving the gate is precise, not a blanket drop.
        let other = test_keypair().agent_id();
        assert!(
            !drop_if_sender_revoked(&dm, &set, &other, &clean_machine),
            "a DM from a non-revoked sender must pass the gate"
        );
        assert_eq!(
            dm.diagnostics_snapshot().stats.incoming_dropped_revoked,
            after,
            "a passing DM must not touch incoming_dropped_revoked"
        );
    }

    #[tokio::test]
    async fn trusted_sender_cannot_bypass_revoked_authenticated_machine_with_clean_claim() {
        let sender = test_keypair();
        let revoked_machine = MachineKeypair::generate().expect("revoked machine keygen");
        let clean_claim = MachineId([0xB2; 32]);
        let mut harness = make_inbox_harness(
            &sender,
            Some(revoked_machine.machine_id()),
            Some(&revoked_machine),
        )
        .await;

        let message = payload_message(&harness, &sender, clean_claim, 0x11);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1,
            "authenticated-machine mismatch must be an observable policy rejection"
        );
    }

    #[tokio::test]
    async fn trusted_sender_matching_clean_authenticated_machine_is_delivered() {
        let sender = test_keypair();
        let clean_machine = MachineId([0xC3; 32]);
        let mut harness = make_inbox_harness(&sender, Some(clean_machine), None).await;

        let message = payload_message(&harness, &sender, clean_machine, 0x22);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());
        assert_eq!(delivered.machine_id, clean_machine);
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
    }

    #[tokio::test]
    async fn unknown_binding_fallback_checks_claimed_machine_revocation() {
        let sender = test_keypair();
        let revoked_machine = MachineKeypair::generate().expect("revoked machine keygen");
        let mut harness = make_inbox_harness(&sender, None, Some(&revoked_machine)).await;

        let message = payload_message(&harness, &sender, revoked_machine.machine_id(), 0x33);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1
        );
    }

    #[tokio::test]
    async fn unknown_binding_fallback_allows_clean_claimed_machine() {
        let sender = test_keypair();
        let clean_claim = MachineId([0xD4; 32]);
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let message = payload_message(&harness, &sender, clean_claim, 0x44);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(delivered.machine_id, clean_claim);
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
    }

    // ── Issue #213: origin-machine attestation acceptance tests ─────────────

    /// #213 SPOOF: an attacker holding the agent key (but NOT machine B's
    /// key) claims unrevoked machine B in the envelope. The attestation they
    /// can produce (signed by their own machine A's key) fails the
    /// key↔machine-id hash binding — hard drop, even with NO retained
    /// binding and B unrevoked. This is the core #213 acceptance criterion:
    /// a revoked origin cannot hide behind an unrevoked claim.
    #[tokio::test]
    async fn spoof_agent_key_holder_claiming_unrevoked_machine_is_rejected() {
        let sender = test_keypair();
        let attacker_machine = MachineKeypair::generate().expect("attacker machine keygen");
        let unrevoked_b = MachineId([0xB9; 32]);
        // No retained binding, no revocations: ONLY the attestation gate can
        // catch this (the #184 fallback alone would accept the claim).
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let mut envelope = craft_unsigned_payload_envelope(&harness, &sender, unrevoked_b, 0x51);
        sign_envelope_with_agent(&mut envelope, &sender);
        // Attacker attaches the best attestation they can mint: their OWN
        // machine key over fields claiming machine B.
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            attacker_machine.public_key().as_bytes().to_vec(),
        );
        attestation
            .sign(&attacker_machine)
            .expect("attacker attest");
        envelope.origin_attestation = Some(attestation);
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(crate::dm::OriginAttestationError::KeyBindingMismatch)
        );

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1,
            "an invalid attestation must be an observable hard rejection"
        );
    }

    /// #213 SPOOF (variant): a forged/garbage attestation signature is a
    /// hard drop, never a fallback to the claimed machine.
    #[tokio::test]
    async fn spoof_forged_attestation_signature_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let mut envelope =
            craft_unsigned_payload_envelope(&harness, &sender, machine.machine_id(), 0x52);
        sign_envelope_with_agent(&mut envelope, &sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        // Garbage signature of the right length class: parses or not, it
        // must never verify.
        attestation.signature = vec![0xAB; 3309];
        envelope.origin_attestation = Some(attestation);

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1
        );
    }

    /// #213 strip residual, after #1659. The receiver has no retained binding
    /// and does not attribute revoked origin A to the sender: A is not a
    /// contact machine and not a binding tombstone. ADR 0021 still accepts
    /// the clean claim of B. #1659 refuses the same strip once a machine
    /// revocation is known for the sender
    /// (`issue1659_unattested_pre213_claim_is_refused_when_agent_machine_is_revoked`).
    #[tokio::test]
    async fn strip_downgrade_residual_delivered_under_transition_policy() {
        let sender = test_keypair();
        let true_origin_a = MachineKeypair::generate().expect("origin machine keygen");
        let unrevoked_b = MachineId([0xB8; 32]);
        // Cold receiver: NO retained binding. True origin A IS revoked.
        let mut harness = make_inbox_harness(&sender, None, Some(&true_origin_a)).await;

        // Stripped envelope: agent-signed, no attestation, claims B.
        let stripped = payload_message(&harness, &sender, unrevoked_b, 0x53);
        harness
            .pipeline
            .handle_incoming(stripped, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("ADR 0021 still accepts this unattributed strip")
            .expect("delivery stream closed");
        assert_eq!(
            delivered.machine_id, unrevoked_b,
            "strip residual: the unattested claim of B is accepted (ADR 0021 residual)"
        );
    }

    async fn record_contact_machine(harness: &InboxHarness, agent: &AgentId, machine: MachineId) {
        harness
            .pipeline
            .contacts
            .write()
            .await
            .add_machine(agent, crate::contacts::MachineRecord::new(machine, None));
    }

    async fn insert_machine_revocation(harness: &InboxHarness, machine: &MachineKeypair) {
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(machine.machine_id()),
            machine.public_key(),
            machine.secret_key(),
            now_unix_ms() / 1000,
            Some("compromised machine".to_string()),
        )
        .expect("sign machine revocation");
        harness
            .pipeline
            .revocation_set
            .write()
            .await
            .verify_and_insert(record, None)
            .expect("insert machine revocation");
    }

    /// #1659: the absent-attestation path credits a DM to the retained clean
    /// binding. A second machine of the same agent is revoked and still
    /// recorded on the contact (announcements keep that record). An
    /// unattested DM that names the clean binding must be refused on both
    /// subscription loops (per-agent inbox topic and the compatibility bus).
    /// Both loops call `handle_incoming`; `ack_legacy_bus` is the only
    /// difference between them.
    #[tokio::test]
    async fn issue1659_unattested_dm_naming_clean_binding_is_refused() {
        let sender = test_keypair();
        let clean = MachineKeypair::generate().expect("clean machine keygen");
        let revoked = MachineKeypair::generate().expect("revoked machine keygen");
        let mut harness = make_inbox_harness(&sender, Some(clean.machine_id()), None).await;
        record_contact_machine(&harness, &sender.agent_id(), revoked.machine_id()).await;
        insert_machine_revocation(&harness, &revoked).await;

        for (ack_legacy_bus, request_byte) in [(false, 0x71u8), (true, 0x72u8)] {
            let message = payload_message(&harness, &sender, clean.machine_id(), request_byte);
            harness
                .pipeline
                .handle_incoming(
                    message,
                    ack_legacy_bus,
                    crate::dm::DmAckIngress::Subscription,
                )
                .await;
        }

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            2,
            "each unattested DM must hit the machine-revocation refusal"
        );
    }

    /// #1659, pre-#213 peer: no retained binding, so today's code accepts the
    /// clean claim. The sender's contact still names a revoked machine, so
    /// the unattested DM is refused.
    #[tokio::test]
    async fn issue1659_unattested_pre213_claim_is_refused_when_agent_machine_is_revoked() {
        let sender = test_keypair();
        let revoked = MachineKeypair::generate().expect("revoked machine keygen");
        let clean_claim = MachineId([0xE5; 32]);
        let mut harness = make_inbox_harness(&sender, None, None).await;
        record_contact_machine(&harness, &sender.agent_id(), revoked.machine_id()).await;
        insert_machine_revocation(&harness, &revoked).await;

        let message = payload_message(&harness, &sender, clean_claim, 0x73);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1
        );
    }

    /// #1659 control: a machine revocation for some other device does not
    /// belong to this agent. The absent-attestation path still delivers.
    #[tokio::test]
    async fn issue1659_unattested_dm_accepted_when_agent_has_no_machine_revocation() {
        let sender = test_keypair();
        let clean = MachineId([0xC6; 32]);
        let unrelated = MachineKeypair::generate().expect("unrelated machine keygen");
        let mut harness = make_inbox_harness(&sender, Some(clean), None).await;
        record_contact_machine(&harness, &sender.agent_id(), clean).await;
        insert_machine_revocation(&harness, &unrelated).await;

        let message = payload_message(&harness, &sender, clean, 0x74);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("an agent with no machine revocation still accepts an unattested DM")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());
        assert_eq!(delivered.machine_id, clean);
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            0
        );
    }

    /// #1659: a fresh origin attestation still authenticates the current
    /// machine after another machine of the same agent was revoked.
    #[tokio::test]
    async fn issue1659_attested_dm_accepted_when_another_machine_is_revoked() {
        let sender = test_keypair();
        let clean = MachineKeypair::generate().expect("clean machine keygen");
        let revoked = MachineKeypair::generate().expect("revoked machine keygen");
        let mut harness = make_inbox_harness(&sender, Some(clean.machine_id()), None).await;
        record_contact_machine(&harness, &sender.agent_id(), revoked.machine_id()).await;
        insert_machine_revocation(&harness, &revoked).await;

        let message = attested_payload_message(&harness, &sender, &clean, 0x75);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("a valid origin attestation is still accepted")
            .expect("delivery stream closed");
        assert_eq!(delivered.machine_id, clean.machine_id());
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
    }

    /// #1659: machine A is known only through a DM attestation. Revoking A
    /// blocks an unattested DM. A valid attested DM from clean machine B
    /// then replaces the retained binding. The sender has no contact-machine
    /// entry and no binding tombstone for A. An unattested DM that claims B
    /// is still refused: the origin-attestation requirement stays after the
    /// binding update.
    #[tokio::test]
    async fn issue1659_revocation_survives_binding_update_without_contact() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A keygen");
        let machine_b = MachineKeypair::generate().expect("machine B keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let attested_a = attested_payload_message(&harness, &sender, &machine_a, 0x81);
        harness
            .pipeline
            .handle_incoming(attested_a, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered_a = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("the attested DM from A must be delivered")
            .expect("delivery stream closed");
        assert_eq!(delivered_a.machine_id, machine_a.machine_id());

        insert_machine_revocation(&harness, &machine_a).await;
        assert!(
            harness
                .pipeline
                .contacts
                .read()
                .await
                .machines(&sender.agent_id())
                .is_empty(),
            "A must be known only through the DM attestation, not a contact"
        );
        assert!(
            harness
                .pipeline
                .revocation_set
                .read()
                .await
                .binding_tombstone_machines(&sender.agent_id())
                .is_empty(),
            "this sequence has no binding tombstone for A"
        );

        let unattested_a = payload_message(&harness, &sender, machine_a.machine_id(), 0x82);
        harness
            .pipeline
            .handle_incoming(unattested_a, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "revoking A must block an unattested DM while the binding still names A"
        );

        let attested_b = attested_payload_message(&harness, &sender, &machine_b, 0x83);
        harness
            .pipeline
            .handle_incoming(attested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered_b = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("a valid attestation from clean machine B must be accepted")
            .expect("delivery stream closed");
        assert_eq!(delivered_b.machine_id, machine_b.machine_id());
        assert_eq!(
            authenticated_machine_binding_for_testing(
                &harness.pipeline.authenticated_machine_bindings,
                &sender.agent_id(),
            )
            .await,
            Some(machine_b.machine_id()),
            "B's attestation must replace the retained binding"
        );
        assert!(harness
            .pipeline
            .contacts
            .read()
            .await
            .machines(&sender.agent_id())
            .is_empty());
        assert!(harness
            .pipeline
            .revocation_set
            .read()
            .await
            .binding_tombstone_machines(&sender.agent_id())
            .is_empty());

        let unattested_b = payload_message(&harness, &sender, machine_b.machine_id(), 0x84);
        harness
            .pipeline
            .handle_incoming(unattested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            2,
            "an unattested DM claiming B must stay refused after the binding leaves revoked A"
        );
        assert_no_delivery(&mut harness.receiver).await;
    }

    /// #1659: binding B at time t2 is retained before a valid A attestation
    /// at t1 arrives. A must still be attributed. Revoking A then refuses an
    /// unattested DM that claims B. There is no contact and no tombstone.
    #[tokio::test]
    async fn issue1659_older_attestation_attributes_when_newer_binding_arrived_first() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A keygen");
        let machine_b = MachineKeypair::generate().expect("machine B keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let now = now_unix_ms();
        let newer_at = now.saturating_sub(2_000);
        let older_at = now.saturating_sub(8_000);

        let attested_b = attested_payload_message_at(&harness, &sender, &machine_b, 0x85, newer_at);
        harness
            .pipeline
            .handle_incoming(attested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered_b = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("the newer attested DM from B must be delivered")
            .expect("delivery stream closed");
        assert_eq!(delivered_b.machine_id, machine_b.machine_id());

        let attested_a = attested_payload_message_at(&harness, &sender, &machine_a, 0x86, older_at);
        harness
            .pipeline
            .handle_incoming(attested_a, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered_a = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("the older attested DM from A must still be delivered")
            .expect("delivery stream closed");
        assert_eq!(delivered_a.machine_id, machine_a.machine_id());
        assert_eq!(
            authenticated_machine_binding_for_testing(
                &harness.pipeline.authenticated_machine_bindings,
                &sender.agent_id(),
            )
            .await,
            Some(machine_b.machine_id()),
            "the older attestation must not roll the retained binding back to A"
        );

        insert_machine_revocation(&harness, &machine_a).await;
        let unattested_b = payload_message(&harness, &sender, machine_b.machine_id(), 0x87);
        harness
            .pipeline
            .handle_incoming(unattested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "revoking A must refuse an unattested DM that claims B"
        );
        assert_no_delivery(&mut harness.receiver).await;
    }

    /// #1659: a real binding tombstone attributes revoked machine A. The
    /// sender has no contact and no retained binding. An unattested DM that
    /// claims clean machine B is refused.
    #[tokio::test]
    async fn issue1659_binding_tombstone_attributes_revoked_machine() {
        let owner = crate::identity::UserKeypair::generate().expect("owner keygen");
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A keygen");
        let claim_b = MachineId([0xB4; 32]);
        let cert = crate::identity::AgentCertificate::issue(&owner, &sender).expect("cert");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let binding = crate::revocation::AgentMachineBinding {
            agent: sender.agent_id(),
            machine: machine_a.machine_id(),
            move_epoch: 1,
        };
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::AgentMachineBinding(binding),
            owner.public_key(),
            owner.secret_key(),
            now_unix_ms() / 1000,
            Some("retired pairing".to_string()),
        )
        .expect("sign binding tombstone");
        assert!(harness
            .pipeline
            .revocation_set
            .write()
            .await
            .verify_and_insert(record, Some(&cert))
            .expect("insert binding tombstone"));
        insert_machine_revocation(&harness, &machine_a).await;
        assert!(
            harness
                .pipeline
                .revocation_set
                .read()
                .await
                .binding_tombstone_machines(&sender.agent_id())
                .contains(&machine_a.machine_id()),
            "the inserted tombstone must name A"
        );
        assert!(harness
            .pipeline
            .contacts
            .read()
            .await
            .machines(&sender.agent_id())
            .is_empty());

        let message = payload_message(&harness, &sender, claim_b, 0x91);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "a tombstone for revoked A must refuse an unattested claim of B"
        );
        assert_no_delivery(&mut harness.receiver).await;
    }

    /// A claim that disagrees with the retained binding stays
    /// `incoming_trust_rejected`. It is not counted as a revocation drop.
    #[tokio::test]
    async fn binding_claim_mismatch_is_trust_rejected() {
        let sender = test_keypair();
        let bound = MachineId([0xA1; 32]);
        let claimed = MachineId([0xB2; 32]);
        let mut harness = make_inbox_harness(&sender, Some(bound), None).await;
        let message = payload_message(&harness, &sender, claimed, 0x93);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        let stats = harness.pipeline.dm.diagnostics_snapshot().stats;
        assert_eq!(stats.incoming_trust_rejected, 1);
        assert_eq!(stats.incoming_dropped_revoked, 0);
    }

    /// #1659: a machine past the per-agent cap is not recorded. Revoking that
    /// machine does not refuse an unattested DM that claims a later clean
    /// machine. Overflow does not add a refusal.
    #[tokio::test]
    async fn issue1659_past_cap_machine_revocation_does_not_block_clean_claim() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A keygen");
        let machine_b = MachineKeypair::generate().expect("machine B keygen");
        let machine_c = MachineKeypair::generate().expect("machine C keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        harness
            .pipeline
            .authenticated_machine_bindings
            .write()
            .await
            .set_attribution_limits_for_test(1, 64, 8);
        let now = now_unix_ms();

        for (machine, byte, at) in [
            (&machine_a, 0x94_u8, now),
            (&machine_b, 0x95, now.saturating_add(5_000)),
            (&machine_c, 0x96, now.saturating_add(10_000)),
        ] {
            let message = attested_payload_message_at(&harness, &sender, machine, byte, at);
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;
            let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("a valid attestation is delivered even past the cap")
                .expect("delivery stream closed");
            assert_eq!(delivered.machine_id, machine.machine_id());
        }

        let accepted = harness
            .pipeline
            .authenticated_machine_bindings
            .read()
            .await
            .machines_accepted_for(&sender.agent_id());
        assert!(accepted.contains(&machine_a.machine_id()));
        assert!(
            !accepted.contains(&machine_b.machine_id()),
            "the machine past the per-agent cap must stay unrecorded"
        );
        assert!(!accepted.contains(&machine_c.machine_id()));

        insert_machine_revocation(&harness, &machine_b).await;
        let unattested = payload_message(&harness, &sender, machine_c.machine_id(), 0x97);
        harness
            .pipeline
            .handle_incoming(unattested, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("an unrecorded machine revocation must not block the clean claim")
            .expect("delivery stream closed");
        assert_eq!(delivered.machine_id, machine_c.machine_id());
        let stats = harness.pipeline.dm.diagnostics_snapshot().stats;
        assert_eq!(stats.incoming_dropped_revoked, 0);
        assert_eq!(
            harness
                .pipeline
                .dm
                .incoming_dropped_attribution_overflow_for_test(),
            0
        );
    }

    /// #1659: attacker overflow must not refuse an unrelated sender who holds
    /// no machine revocation. A sender who holds one stays refused. The
    /// unrelated ACK takes the same unattested gate.
    #[tokio::test]
    async fn issue1659_attacker_overflow_keeps_unrelated_legacy_dm() {
        let unrelated = test_keypair();
        let clean = MachineId([0x44; 32]);
        let mut harness = make_inbox_harness(&unrelated, Some(clean), None).await;
        harness
            .pipeline
            .authenticated_machine_bindings
            .write()
            .await
            .set_attribution_limits_for_test(1, 1, 1);

        let attacker_a = test_keypair();
        let attacker_b = test_keypair();
        let machine_a = MachineKeypair::generate().expect("attacker machine A");
        let machine_b = MachineKeypair::generate().expect("attacker machine B");
        for (sender, machine, byte) in [
            (&attacker_a, &machine_a, 0xA1_u8),
            (&attacker_b, &machine_b, 0xA2_u8),
        ] {
            let message = attested_payload_message(&harness, sender, machine, byte);
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;
            let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("an attested attacker DM still delivers")
                .expect("delivery stream closed");
            assert_eq!(delivered.sender, sender.agent_id());
        }
        {
            let cache = harness.pipeline.authenticated_machine_bindings.read().await;
            assert!(cache.attribution_requires_attestation(&attacker_a.agent_id()));
            assert!(!cache.attribution_requires_attestation(&attacker_b.agent_id()));
            assert!(!cache.attribution_requires_attestation(&unrelated.agent_id()));
            assert!(cache.attribution_unnamed_overflows() >= 1);
        }

        let ack = unattested_ack_message(&harness, &unrelated, clean, 0xA3);
        harness
            .pipeline
            .handle_incoming(ack, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let stats = harness.pipeline.dm.diagnostics_snapshot().stats;
        assert_eq!(stats.incoming_dropped_revoked, 0);
        assert_eq!(
            harness
                .pipeline
                .dm
                .incoming_dropped_attribution_overflow_for_test(),
            0
        );

        let legacy = payload_message(&harness, &unrelated, clean, 0xA4);
        harness
            .pipeline
            .handle_incoming(legacy, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("an unrelated unattested DM must be accepted after overflow")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, unrelated.agent_id());
        assert_eq!(delivered.machine_id, clean);

        insert_machine_revocation(&harness, &machine_a).await;
        let overflowed = payload_message(&harness, &attacker_a, machine_a.machine_id(), 0xA5);
        harness
            .pipeline
            .handle_incoming(overflowed, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        let stats = harness.pipeline.dm.diagnostics_snapshot().stats;
        assert_eq!(
            stats.incoming_dropped_revoked, 1,
            "an overflow refusal with a revoked machine counts as incoming_dropped_revoked"
        );
        assert_eq!(
            harness
                .pipeline
                .dm
                .incoming_dropped_attribution_overflow_for_test(),
            1
        );

        let revoked_sender = test_keypair();
        let revoked_machine = MachineKeypair::generate().expect("revoked sender machine");
        insert_machine_revocation(&harness, &revoked_machine).await;
        let refused = payload_message(
            &harness,
            &revoked_sender,
            revoked_machine.machine_id(),
            0xA6,
        );
        harness
            .pipeline
            .handle_incoming(refused, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        let stats = harness.pipeline.dm.diagnostics_snapshot().stats;
        assert_eq!(
            stats.incoming_dropped_revoked, 2,
            "a sender with a revoked machine stays refused after attacker overflow"
        );
        assert_eq!(
            harness
                .pipeline
                .dm
                .incoming_dropped_attribution_overflow_for_test(),
            1
        );
    }

    /// A DM that the revocation check refuses does not take an attribution
    /// slot. Machine A is revoked before any admitted attestation, so the
    /// dropped attestation does not link A to the sender. A later admitted
    /// attestation from clean machine B is recorded. An unattested claim of
    /// B is accepted: A was never attributed.
    #[tokio::test]
    async fn issue1659_refused_attestation_does_not_take_an_attribution_slot() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A keygen");
        let machine_b = MachineKeypair::generate().expect("machine B keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        insert_machine_revocation(&harness, &machine_a).await;

        let attested = attested_payload_message(&harness, &sender, &machine_a, 0xB1);
        harness
            .pipeline
            .handle_incoming(attested, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .authenticated_machine_bindings
                .read()
                .await
                .machines_accepted_for(&sender.agent_id())
                .is_empty(),
            "a refused attestation must not enter the attribution set"
        );

        let attested_b = attested_payload_message_at(
            &harness,
            &sender,
            &machine_b,
            0xB2,
            now_unix_ms().saturating_add(5_000),
        );
        harness
            .pipeline
            .handle_incoming(attested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("a valid attestation from clean machine B must be accepted")
            .expect("delivery stream closed");
        assert_eq!(delivered.machine_id, machine_b.machine_id());

        let unattested = payload_message(&harness, &sender, machine_b.machine_id(), 0xB3);
        harness
            .pipeline
            .handle_incoming(unattested, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered_b = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("B was admitted and A was never attributed")
            .expect("delivery stream closed");
        assert_eq!(delivered_b.machine_id, machine_b.machine_id());
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "only the refused attestation of revoked machine A is counted"
        );
    }

    /// Strangers share a small pair budget. A Trusted contact still records
    /// after that budget is full. A blocked sender does not take a slot.
    #[tokio::test]
    async fn issue1659_strangers_cannot_exhaust_relationship_attribution() {
        let contact = test_keypair();
        let mut harness = make_inbox_harness(&contact, None, None).await;
        {
            let mut cache = harness
                .pipeline
                .authenticated_machine_bindings
                .write()
                .await;
            cache.set_attribution_limits_for_test(8, 64, 8);
            cache.set_stranger_pair_limit_for_test(1);
        }

        let blocked = test_keypair();
        harness
            .pipeline
            .contacts
            .write()
            .await
            .set_trust(&blocked.agent_id(), TrustLevel::Blocked);
        let blocked_machine = MachineKeypair::generate().expect("blocked machine");
        let blocked_dm = attested_payload_message(&harness, &blocked, &blocked_machine, 0xC1);
        harness
            .pipeline
            .handle_incoming(blocked_dm, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        {
            let cache = harness.pipeline.authenticated_machine_bindings.read().await;
            assert!(cache.machines_accepted_for(&blocked.agent_id()).is_empty());
            assert_eq!(cache.attribution_stranger_pairs_len(), 0);
        }

        let stranger_a = test_keypair();
        let stranger_b = test_keypair();
        let machine_a = MachineKeypair::generate().expect("stranger A machine");
        let machine_b = MachineKeypair::generate().expect("stranger B machine");
        for (sender, machine, byte) in [
            (&stranger_a, &machine_a, 0xC2_u8),
            (&stranger_b, &machine_b, 0xC3),
        ] {
            let message = attested_payload_message(&harness, sender, machine, byte);
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;
            let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("an attested stranger DM is still delivered")
                .expect("delivery stream closed");
            assert_eq!(delivered.sender, sender.agent_id());
        }
        {
            let cache = harness.pipeline.authenticated_machine_bindings.read().await;
            assert!(cache
                .machines_accepted_for(&stranger_a.agent_id())
                .is_empty());
            assert!(
                cache
                    .machines_accepted_for(&stranger_b.agent_id())
                    .contains(&machine_b.machine_id()),
                "a later stranger evicts the least-recent stranger pair"
            );
            assert!(cache.attribution_stranger_overflows() >= 1);
            assert_eq!(cache.attribution_stranger_pairs_len(), 1);
        }

        let contact_a = MachineKeypair::generate().expect("contact machine A");
        let contact_b = MachineKeypair::generate().expect("contact machine B");
        for (machine, byte, at) in [
            (&contact_a, 0xC4_u8, now_unix_ms()),
            (&contact_b, 0xC5, now_unix_ms().saturating_add(5_000)),
        ] {
            let message = attested_payload_message_at(&harness, &contact, machine, byte, at);
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;
            let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("a Trusted contact still records after the stranger budget fills")
                .expect("delivery stream closed");
            assert_eq!(delivered.machine_id, machine.machine_id());
        }
        let accepted = harness
            .pipeline
            .authenticated_machine_bindings
            .read()
            .await
            .machines_accepted_for(&contact.agent_id());
        assert!(accepted.contains(&contact_a.machine_id()));
        assert!(accepted.contains(&contact_b.machine_id()));
    }

    /// Throwaway announcements fill the stranger LRU. A later stranger still
    /// has a slot, so revoking that machine refuses an unattested clean claim.
    /// A contact recorded first is still attributed.
    #[tokio::test]
    async fn issue1659_announcements_do_not_switch_off_later_stranger_protection() {
        let later = test_keypair();
        let mut harness = make_inbox_harness(&later, None, None).await;
        harness
            .pipeline
            .contacts
            .write()
            .await
            .remove(&later.agent_id());
        let contact = AgentId([0xC4; 32]);
        let contact_machine = MachineId([0xC4; 32]);
        let bindings = Arc::clone(&harness.pipeline.authenticated_machine_bindings);
        {
            let mut cache = bindings.write().await;
            cache.set_stranger_pair_limit_for_test(2);
            cache.set_relationship_peer(contact, true);
            cache.record(contact, contact_machine, 1);
        }
        let early_a = AgentId([0x11; 32]);
        let early_b = AgentId([0x22; 32]);
        record_authenticated_machine_binding_with_expiry(
            &bindings,
            early_a,
            MachineId([0x11; 32]),
            2,
            None,
        )
        .await;
        record_authenticated_machine_binding_with_expiry(
            &bindings,
            early_b,
            MachineId([0x22; 32]),
            3,
            None,
        )
        .await;
        let machine_r = MachineKeypair::generate().expect("revoked machine");
        let machine_c = MachineKeypair::generate().expect("clean machine");
        record_authenticated_machine_binding_with_expiry(
            &bindings,
            later.agent_id(),
            machine_r.machine_id(),
            10,
            None,
        )
        .await;
        record_authenticated_machine_binding_with_expiry(
            &bindings,
            later.agent_id(),
            machine_c.machine_id(),
            11,
            None,
        )
        .await;
        {
            let cache = bindings.read().await;
            let accepted = cache.machines_accepted_for(&later.agent_id());
            assert!(accepted.contains(&machine_r.machine_id()));
            assert!(accepted.contains(&machine_c.machine_id()));
            assert!(cache.machines_accepted_for(&early_a).is_empty());
            assert!(cache
                .machines_accepted_for(&contact)
                .contains(&contact_machine));
        }
        insert_machine_revocation(&harness, &machine_r).await;
        let unattested = payload_message(&harness, &later, machine_c.machine_id(), 0xE1);
        harness
            .pipeline
            .handle_incoming(unattested, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked
                >= 1,
            "the later stranger stays protected after the announcement flood"
        );
    }

    /// An undecryptable attested DM moves no attribution slot.
    #[tokio::test]
    async fn issue1659_undecryptable_dm_does_not_take_an_attribution_slot() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let wrong_kem = AgentKemKeypair::generate().expect("wrong kem");
        let created_at = now_unix_ms();
        let body = EnvelopeBuilder::build_payload_body(
            &[0xE2; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created_at,
            b"not for this recipient".to_vec(),
            None,
            &wrong_kem.public_bytes,
        )
        .expect("build body");
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_V1,
            request_id: [0xE2; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created_at,
            expires_at_unix_ms: created_at + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, &sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(&machine).expect("attest");
        envelope.origin_attestation = Some(attestation);
        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        let cache = harness.pipeline.authenticated_machine_bindings.read().await;
        assert!(
            cache.machines_accepted_for(&sender.agent_id()).is_empty(),
            "decryption failure must not take an attribution slot"
        );
        assert_eq!(
            cache
                .peek(&sender.agent_id())
                .map(|binding| binding.machine_id),
            Some(machine.machine_id()),
            "the retained binding still moves so a later grant check can see it"
        );
    }

    /// Undecryptable attested DM leaves A retained and unrecorded. A later
    /// valid unattested DM through that binding records A. After a move to
    /// B and a revocation of A, an unattested DM from B is refused. No
    /// contact machine and no tombstone name A.
    #[tokio::test]
    async fn issue1659_admitted_retained_origin_survives_a_later_move() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A");
        let machine_b = MachineKeypair::generate().expect("machine B");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let wrong_kem = AgentKemKeypair::generate().expect("wrong kem");
        let created_at = now_unix_ms();
        let body = EnvelopeBuilder::build_payload_body(
            &[0xE5; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created_at,
            b"not for this recipient".to_vec(),
            None,
            &wrong_kem.public_bytes,
        )
        .expect("build body");
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_V1,
            request_id: [0xE5; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine_a.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created_at,
            expires_at_unix_ms: created_at + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, &sender);
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            machine_a.public_key().as_bytes().to_vec(),
        );
        attestation.sign(&machine_a).expect("attest");
        envelope.origin_attestation = Some(attestation);
        harness
            .pipeline
            .handle_incoming(
                wrap_in_pubsub(&harness, &sender, &envelope),
                false,
                crate::dm::DmAckIngress::Subscription,
            )
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        {
            let cache = harness.pipeline.authenticated_machine_bindings.read().await;
            assert!(
                cache.machines_accepted_for(&sender.agent_id()).is_empty(),
                "an undecryptable DM must not record A"
            );
            assert_eq!(
                cache
                    .peek(&sender.agent_id())
                    .map(|binding| binding.machine_id),
                Some(machine_a.machine_id())
            );
        }

        let unattested_a = payload_message(&harness, &sender, machine_a.machine_id(), 0xE6);
        harness
            .pipeline
            .handle_incoming(unattested_a, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered_a = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("the unattested DM through the retained binding is delivered")
            .expect("delivery stream closed");
        assert_eq!(delivered_a.machine_id, machine_a.machine_id());
        assert!(
            harness
                .pipeline
                .authenticated_machine_bindings
                .read()
                .await
                .machines_accepted_for(&sender.agent_id())
                .contains(&machine_a.machine_id()),
            "an admitted retained origin must be recorded"
        );

        let attested_b = attested_payload_message(&harness, &sender, &machine_b, 0xE7);
        harness
            .pipeline
            .handle_incoming(attested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered_b = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("the move to B is delivered")
            .expect("delivery stream closed");
        assert_eq!(delivered_b.machine_id, machine_b.machine_id());
        insert_machine_revocation(&harness, &machine_a).await;
        assert!(
            harness
                .pipeline
                .contacts
                .read()
                .await
                .machines(&sender.agent_id())
                .is_empty(),
            "this sequence has no contact machine"
        );
        assert!(
            harness
                .pipeline
                .revocation_set
                .read()
                .await
                .binding_tombstone_machines(&sender.agent_id())
                .is_empty(),
            "this sequence has no binding tombstone"
        );
        let unattested_b = payload_message(&harness, &sender, machine_b.machine_id(), 0xE8);
        harness
            .pipeline
            .handle_incoming(unattested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked
                >= 1,
            "revoking A must still refuse an unattested DM from B"
        );
    }

    /// A protected-share flood after a revocation must not drop the revoked
    /// machine. The next unattested DM stays refused.
    #[tokio::test]
    async fn issue1659_protected_flood_after_revocation_still_refuses_unattested() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A");
        let machine_b = MachineKeypair::generate().expect("machine B");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        harness
            .pipeline
            .contacts
            .write()
            .await
            .remove(&sender.agent_id());
        let sender_id = sender.agent_id();
        let revoked_set = Arc::clone(&harness.pipeline.revocation_set);
        let bindings = Arc::clone(&harness.pipeline.authenticated_machine_bindings);
        {
            let mut cache = bindings.write().await;
            cache.set_protected_pair_limit_for_test(2);
            cache.install_relationship_probe(AttributionRelationshipProbe::from_fn(move |agent| {
                agent == sender_id
            }));
            cache.install_revoked_machine_probe(move |machine| match revoked_set.try_read() {
                Ok(set) => Some(set.is_machine_revoked(&machine)),
                Err(_) => None,
            });
        }

        let attested_a = attested_payload_message(&harness, &sender, &machine_a, 0xE9);
        harness
            .pipeline
            .handle_incoming(attested_a, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("attested A is delivered")
            .expect("delivery stream closed");
        insert_machine_revocation(&harness, &machine_a).await;
        let attested_b = attested_payload_message(&harness, &sender, &machine_b, 0xEA);
        harness
            .pipeline
            .handle_incoming(attested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("attested B is delivered")
            .expect("delivery stream closed");

        for offset in 1..6u8 {
            let mut bytes = [0xA0; 32];
            bytes[1] = offset;
            let agent = AgentId(bytes);
            let machine = MachineId(bytes);
            {
                let mut cache = bindings.write().await;
                cache.set_standing(agent, AttributionStanding::Protected);
            }
            record_authenticated_machine_binding(&bindings, agent, machine, u64::from(offset) + 30)
                .await;
        }
        assert!(
            harness
                .pipeline
                .authenticated_machine_bindings
                .read()
                .await
                .machines_accepted_for(&sender.agent_id())
                .contains(&machine_a.machine_id()),
            "the revoked machine stays attributed"
        );
        let unattested_b = payload_message(&harness, &sender, machine_b.machine_id(), 0xEB);
        harness
            .pipeline
            .handle_incoming(unattested_b, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked
                >= 1,
            "an unattested DM stays refused after the protected-share flood"
        );
    }

    /// Revoked machine A, then newer clean B and C. A busy revocation lock
    /// answers unknown for B and C. That unknown must not count as two newer
    /// revocations, so A stays attributed. An unattested DM that claims C
    /// stays refused.
    #[tokio::test]
    async fn issue1659_unknown_revocation_does_not_evict_revoked_machine_for_clean_claim() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A");
        let machine_b = MachineKeypair::generate().expect("machine B");
        let machine_c = MachineKeypair::generate().expect("machine C");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        harness
            .pipeline
            .contacts
            .write()
            .await
            .remove(&sender.agent_id());
        let sender_id = sender.agent_id();
        let id_a = machine_a.machine_id();
        let id_b = machine_b.machine_id();
        let id_c = machine_c.machine_id();
        let bindings = Arc::clone(&harness.pipeline.authenticated_machine_bindings);
        {
            let mut cache = bindings.write().await;
            cache.set_protected_pair_limit_for_test(3);
            cache.install_relationship_probe(AttributionRelationshipProbe::from_fn(move |agent| {
                agent == sender_id
            }));
            cache.install_revoked_machine_probe(move |machine| {
                if machine == id_a {
                    Some(true)
                } else if machine == id_b || machine == id_c {
                    None
                } else {
                    Some(false)
                }
            });
        }

        let attested_a = attested_payload_message(&harness, &sender, &machine_a, 0xF1);
        harness
            .pipeline
            .handle_incoming(attested_a, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("attested A is delivered")
            .expect("delivery stream closed");
        insert_machine_revocation(&harness, &machine_a).await;
        for (machine, marker) in [(&machine_b, 0xF2), (&machine_c, 0xF3)] {
            let attested = attested_payload_message(&harness, &sender, machine, marker);
            harness
                .pipeline
                .handle_incoming(attested, false, crate::dm::DmAckIngress::Subscription)
                .await;
            let _ = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("attested clean machine is delivered")
                .expect("delivery stream closed");
        }

        for offset in 1..5u8 {
            let mut bytes = [0xB0; 32];
            bytes[1] = offset;
            let agent = AgentId(bytes);
            let machine = MachineId(bytes);
            {
                let mut cache = bindings.write().await;
                cache.set_standing(agent, AttributionStanding::Protected);
            }
            record_authenticated_machine_binding(&bindings, agent, machine, u64::from(offset) + 40)
                .await;
        }

        let accepted = harness
            .pipeline
            .authenticated_machine_bindings
            .read()
            .await
            .machines_accepted_for(&sender.agent_id());
        assert!(
            accepted.contains(&id_a),
            "unknown status on B and C must not evict revoked machine A"
        );
        assert!(accepted.contains(&id_b));
        assert!(accepted.contains(&id_c));
        let unattested_c = payload_message(&harness, &sender, id_c, 0xF4);
        harness
            .pipeline
            .handle_incoming(unattested_c, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked
                >= 1,
            "unattested traffic claiming C must stay refused while A is attributed"
        );
    }

    /// An unsolicited attested ACK, and a blocked attested ACK, take no slot.
    #[tokio::test]
    async fn issue1659_unsolicited_or_blocked_ack_takes_no_attribution_slot() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine");
        let harness = make_inbox_harness(&sender, None, None).await;
        let unsolicited = attested_ack_message(&harness, &sender, &machine, 0xE3);
        harness
            .pipeline
            .handle_incoming(unsolicited, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert!(harness
            .pipeline
            .authenticated_machine_bindings
            .read()
            .await
            .machines_accepted_for(&sender.agent_id())
            .is_empty());

        harness
            .pipeline
            .contacts
            .write()
            .await
            .set_trust(&sender.agent_id(), TrustLevel::Blocked);
        let request_id = [0xE4; 16];
        let _waiter = harness.pipeline.inflight.register(
            request_id,
            sender.agent_id(),
            Some(machine.machine_id()),
        );
        let blocked = attested_ack_message(&harness, &sender, &machine, 0xE4);
        harness
            .pipeline
            .handle_incoming(blocked, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert!(
            harness
                .pipeline
                .authenticated_machine_bindings
                .read()
                .await
                .machines_accepted_for(&sender.agent_id())
                .is_empty(),
            "a blocked ACK must not take an attribution slot"
        );
    }

    /// A legitimate A→B move with a live `Dm` grant is delivered as Accept.
    /// The grant reads the binding after it moves. The harness gate starts off.
    #[tokio::test]
    async fn issue1659_share_grant_sees_machine_after_move() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A");
        let machine_b = MachineKeypair::generate().expect("machine B");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        harness
            .pipeline
            .contacts
            .write()
            .await
            .remove(&sender.agent_id());
        let bindings = Arc::clone(&harness.pipeline.authenticated_machine_bindings);
        record_authenticated_machine_binding(
            &bindings,
            sender.agent_id(),
            machine_a.machine_id(),
            1,
        )
        .await;

        let owner = crate::identity::UserKeypair::generate().expect("owner");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
            .max(2);
        let store = Arc::new(crate::share_grant::ShareGrantStore::in_memory(
            harness.recipient_agent_id,
            Some(owner.user_id()),
        ));
        let grant = crate::share_grant::ShareGrant::sign(
            &owner,
            [0x71; 32],
            crate::share_grant::Grantee::Agent(sender.agent_id()),
            vec![harness.recipient_agent_id],
            vec![crate::share_grant::ShareCap::Dm],
            now.saturating_sub(1),
            now.saturating_add(3_600),
        )
        .expect("sign grant");
        store.accept(grant, now).await.expect("store grant");
        let owner_trust =
            crate::owner_trust::OwnerTrust::new(Some(owner.user_id()), Arc::clone(&bindings));
        owner_trust.install_share_grant_store(store);
        harness.pipeline.share_grant_gate = Some(crate::share_grant::ShareGrantDmGate::new(
            owner_trust,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
        ));

        let message = attested_payload_message_at(
            &harness,
            &sender,
            &machine_b,
            0xE5,
            now_unix_ms().saturating_add(5_000),
        );
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("the granted move must be delivered")
            .expect("delivery stream closed");
        assert_eq!(delivered.machine_id, machine_b.machine_id());
        assert_eq!(
            delivered.trust_decision,
            Some(TrustDecision::Accept),
            "the Dm grant must see machine B, not the stale binding A"
        );
    }

    /// An unattested ACK from a sender with a revoked machine must not
    /// resolve a waiter. A counter staying at zero is not that proof.
    #[tokio::test]
    async fn issue1659_unattested_ack_stays_pending_when_machine_is_revoked() {
        let sender = test_keypair();
        let clean = MachineId([0xC6; 32]);
        let revoked = MachineKeypair::generate().expect("revoked machine");
        let harness = make_inbox_harness(&sender, Some(clean), None).await;
        record_contact_machine(&harness, &sender.agent_id(), revoked.machine_id()).await;
        insert_machine_revocation(&harness, &revoked).await;
        let request_id = [0xA7; 16];
        let mut waiter =
            harness
                .pipeline
                .inflight
                .register(request_id, sender.agent_id(), Some(clean));
        let ack = unattested_ack_message(&harness, &sender, clean, 0xA7);
        harness
            .pipeline
            .handle_incoming(ack, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert!(
            matches!(
                waiter.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "the unattested ACK must leave the waiter pending"
        );
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1
        );
    }

    /// #1659: a present but invalid attestation is a hard drop. It must not
    /// fall through to the absent-attestation path, even when a machine
    /// revocation is held for the sender.
    #[tokio::test]
    async fn issue1659_invalid_attestation_is_a_hard_drop() {
        let sender = test_keypair();
        let clean = MachineKeypair::generate().expect("clean machine");
        let revoked = MachineKeypair::generate().expect("revoked machine");
        let mut harness = make_inbox_harness(&sender, Some(clean.machine_id()), None).await;
        record_contact_machine(&harness, &sender.agent_id(), revoked.machine_id()).await;
        insert_machine_revocation(&harness, &revoked).await;

        let first = attested_payload_message(&harness, &sender, &clean, 0xD1);
        let first_envelope = DmEnvelope::from_wire_bytes(&first.payload).expect("decode");
        let captured = first_envelope
            .origin_attestation
            .clone()
            .expect("attestation");
        let mut envelope =
            craft_unsigned_payload_envelope(&harness, &sender, clean.machine_id(), 0xD2);
        sign_envelope_with_agent(&mut envelope, &sender);
        envelope.origin_attestation = Some(captured);
        assert!(envelope.verify_origin_attestation().is_err());
        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        let stats = harness.pipeline.dm.diagnostics_snapshot().stats;
        assert_eq!(stats.incoming_trust_rejected, 1);
        assert_eq!(stats.incoming_dropped_revoked, 0);
        assert_eq!(
            harness
                .pipeline
                .dm
                .incoming_dropped_attribution_overflow_for_test(),
            0
        );
    }

    /// #213 REPLAY: an attestation captured from DM-1 (request R1) is
    /// re-presented inside DM-2 (request R2) — the attacker re-signs the
    /// envelope with the (stolen) agent key but cannot mint a fresh machine
    /// attestation. The request-id field match fails → hard drop.
    #[tokio::test]
    async fn replay_captured_attestation_with_new_request_id_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        // Capture: a valid attested DM (request 0x61).
        let first = attested_payload_message(&harness, &sender, &machine, 0x61);
        let first_envelope =
            DmEnvelope::from_wire_bytes(&first.payload).expect("decode first envelope");
        let captured = first_envelope
            .origin_attestation
            .clone()
            .expect("first envelope attested");

        // Replay: same agent, NEW request id, envelope re-signed by the
        // agent key — but the captured attestation still names request 0x61.
        let mut envelope =
            craft_unsigned_payload_envelope(&harness, &sender, machine.machine_id(), 0x62);
        sign_envelope_with_agent(&mut envelope, &sender);
        envelope.origin_attestation = Some(captured);
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(crate::dm::OriginAttestationError::EnvelopeMismatch)
        );

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1
        );
    }

    /// #213 REPLAY (variant): an attestation re-presented past its expiry
    /// window is dropped — the envelope timestamp window covers the
    /// attestation because the fields must match exactly.
    #[tokio::test]
    async fn replay_expired_attestation_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        // Build an honestly-signed envelope + attestation whose window
        // already closed (created 10 min ago, 60 s lifetime).
        let created = now_unix_ms().saturating_sub(600_000);
        let body = EnvelopeBuilder::build_payload_body(
            &[0x63; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created,
            b"stale replay".to_vec(),
            None,
            &harness.recipient_kem.public_bytes,
        )
        .expect("build payload body");
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: [0x63; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: created + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, &sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(&machine).expect("machine attest");
        envelope.origin_attestation = Some(attestation);
        // The attestation itself verifies — only the expiry window rejects.
        assert!(envelope.verify_origin_attestation().is_ok());

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
    }

    /// #213 REVOCATION: the origin machine is revoked mid-flight — the
    /// envelope + attestation are both honestly signed by machine A, but A
    /// enters the receiver's revocation set before the DM arrives. EP3 drops
    /// on the ATTESTED machine id (not the claim).
    #[tokio::test]
    async fn revocation_of_origin_machine_mid_flight_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        // Harness revocation set already holds machine A's self-revocation.
        let mut harness = make_inbox_harness(&sender, None, Some(&machine)).await;

        let message = attested_payload_message(&harness, &sender, &machine, 0x64);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "a validly-attested DM from a revoked origin machine must hit EP3"
        );
    }

    /// #213 OFFLINE RECEIVER: a completely cold receiver — no retained
    /// binding, no discovery cache, nothing — authenticates the DM's origin
    /// machine purely from envelope-carried material and delivers.
    #[tokio::test]
    async fn offline_cold_receiver_authenticates_origin_with_zero_cache_state() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let message = attested_payload_message(&harness, &sender, &machine, 0x65);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());
        assert_eq!(
            delivered.machine_id,
            machine.machine_id(),
            "delivery must carry the ATTESTED machine, not just the claim"
        );
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
    }

    /// #213 A→B MOVE: the agent legitimately moves from machine A to
    /// machine B. The retained binding still says A, but B's fresh
    /// attestation supersedes it — the DM is delivered with machine B and
    /// the binding refreshes. A later A-attested DM (stale origin, A now
    /// revoked) is rejected. Revoking A does NOT block the valid move.
    #[tokio::test]
    async fn portable_move_fresh_b_attestation_accepted_stale_revoked_a_rejected() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A keygen");
        let machine_b = MachineKeypair::generate().expect("machine B keygen");
        // Retained binding says A (stale announcement); A is then revoked
        // (compromised) — the move to B must still authenticate.
        let mut harness =
            make_inbox_harness(&sender, Some(machine_a.machine_id()), Some(&machine_a)).await;

        // 1. Fresh B attestation: accepted even though the binding says A.
        let message = attested_payload_message(&harness, &sender, &machine_b, 0x66);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(
            delivered.machine_id,
            machine_b.machine_id(),
            "a valid fresh attestation from B supersedes the stale A binding"
        );

        // 2. The retained binding refreshes to B (seconds-granularity
        //    ordering: the fresh attestation outranks the old announcement).
        assert_eq!(
            authenticated_machine_binding_for_testing(
                &harness.pipeline.authenticated_machine_bindings,
                &sender.agent_id(),
            )
            .await,
            Some(machine_b.machine_id()),
            "the attested move must refresh the retained binding to B"
        );

        // 3. Stale A attestation: A is revoked → EP3 rejects.
        let stale = attested_payload_message(&harness, &sender, &machine_a, 0x67);
        harness
            .pipeline
            .handle_incoming(stale, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "a stale attestation from revoked machine A must hit EP3"
        );
        assert_no_delivery(&mut harness.receiver).await;
    }

    #[tokio::test]
    async fn authenticated_binding_allows_portable_move_and_rejects_stale_replay() {
        let sender = test_keypair().agent_id();
        let machine_a = MachineId([0xA5; 32]);
        let machine_b = MachineId([0xB6; 32]);
        let bindings = Arc::new(RwLock::new(AuthenticatedMachineBindingCache::default()));

        record_authenticated_machine_binding(&bindings, sender, machine_a, 100).await;
        record_authenticated_machine_binding(&bindings, sender, machine_b, 200).await;
        record_authenticated_machine_binding(&bindings, sender, machine_a, 150).await;

        let binding = bindings.write().await.resolve(&sender).expect("binding");
        assert_eq!(binding, machine_b);
        assert!(bindings
            .read()
            .await
            .agents_on_machine(machine_a, 16)
            .is_empty());
        assert_eq!(
            bindings.read().await.agents_on_machine(machine_b, 16),
            vec![sender]
        );
    }

    #[test]
    fn authenticated_binding_cache_evicts_least_recently_used_at_capacity() {
        let mut bindings = AuthenticatedMachineBindingCache::with_capacity(2);
        let agent_a = AgentId([0xA1; 32]);
        let agent_b = AgentId([0xB2; 32]);
        let agent_c = AgentId([0xC3; 32]);

        bindings.record(agent_a, MachineId([0x01; 32]), 1);
        bindings.record(agent_b, MachineId([0x02; 32]), 2);
        assert!(bindings.resolve(&agent_a).is_some());
        bindings.record(agent_c, MachineId([0x03; 32]), 3);

        assert!(bindings.resolve(&agent_a).is_some());
        assert!(bindings.resolve(&agent_b).is_none());
        assert!(bindings.resolve(&agent_c).is_some());
        assert!(bindings
            .agents_on_machine(MachineId([0x02; 32]), 16)
            .is_empty());
        assert_eq!(
            bindings.agents_on_machine(MachineId([0x01; 32]), 16),
            vec![agent_a]
        );
    }

    /// #1659: LRU eviction drops the retained entry and keeps attribution.
    #[test]
    fn accepted_machine_attribution_survives_lru_eviction() {
        let mut bindings = AuthenticatedMachineBindingCache::with_capacity(1);
        let agent = AgentId([0xA1; 32]);
        let replaced = MachineId([0x11; 32]);
        let current = MachineId([0x22; 32]);
        bindings.record(agent, replaced, 1);
        bindings.record(agent, current, 2);
        bindings.record(AgentId([0xB2; 32]), MachineId([0x33; 32]), 3);

        assert!(bindings.peek(&agent).is_none());
        let machines = bindings.machines_accepted_for(&agent);
        assert!(machines.contains(&replaced));
        assert!(machines.contains(&current));
    }

    /// A verified machine that loses timestamp selection is still attributed
    /// when the caller is recording. `record` is that writer. An
    /// announced-binding `record_announcement` moves the retained binding
    /// and does not take a slot.
    #[test]
    fn older_verified_machine_stays_attributed_when_newer_binding_wins() {
        let mut bindings = AuthenticatedMachineBindingCache::default();
        let agent = AgentId([0xA5; 32]);
        let newer = MachineId([0xB6; 32]);
        let older = MachineId([0xC7; 32]);
        bindings.record(agent, newer, 200);
        bindings.record(agent, older, 100);
        assert_eq!(
            bindings.peek(&agent).map(|binding| binding.machine_id),
            Some(newer)
        );
        let machines = bindings.machines_accepted_for(&agent);
        assert!(machines.contains(&older));
        assert!(machines.contains(&newer));

        let mut announced = AuthenticatedMachineBindingCache::default();
        announced.record_announcement(agent, older, 100, None, None);
        assert!(
            announced.machines_accepted_for(&agent).is_empty(),
            "the announced-binding store does not take an attribution slot"
        );
        assert_eq!(
            announced.peek(&agent).map(|binding| binding.machine_id),
            Some(older)
        );
    }

    /// The pair cap refuses one more agent and does not drop a stored pair.
    #[test]
    fn accepted_machine_pair_cap_keeps_stored_pairs() {
        let mut bindings =
            AuthenticatedMachineBindingCache::with_capacity(8).with_attribution_limits(8, 2, 4);
        let agent_a = AgentId([0xA1; 32]);
        let agent_b = AgentId([0xB2; 32]);
        let agent_c = AgentId([0xC3; 32]);
        let machine_a = MachineId([0x01; 32]);
        let machine_b = MachineId([0x02; 32]);
        bindings.record(agent_a, machine_a, 1);
        bindings.record(agent_b, machine_b, 1);
        bindings.record(agent_c, MachineId([0x03; 32]), 1);

        assert!(bindings
            .machines_accepted_for(&agent_a)
            .contains(&machine_a));
        assert!(bindings
            .machines_accepted_for(&agent_b)
            .contains(&machine_b));
        assert!(bindings.machines_accepted_for(&agent_c).is_empty());
        assert!(!bindings.attribution_requires_attestation(&agent_a));
        assert!(bindings.attribution_requires_attestation(&agent_c));
        assert!(!bindings.attribution_requires_attestation(&AgentId([0xD4; 32])));
    }

    /// One agent cannot grow its set past the per-agent cap. The extra
    /// machine is not recorded. That is not a refusal of a later DM.
    #[test]
    fn accepted_machine_per_agent_cap_stops_recording() {
        let mut bindings =
            AuthenticatedMachineBindingCache::default().with_attribution_limits(2, 100, 10);
        let agent = AgentId([0x11; 32]);
        bindings.record(agent, MachineId([1; 32]), 10);
        bindings.record(agent, MachineId([2; 32]), 20);
        bindings.record(agent, MachineId([3; 32]), 30);
        assert_eq!(bindings.machines_accepted_for(&agent).len(), 2);
        assert!(bindings.attribution_requires_attestation(&agent));
        assert!(!bindings.attribution_requires_attestation(&AgentId([0x22; 32])));
    }

    /// A full overflow-name list does not mark every agent. The stored pair
    /// stays. The unnamed agent is counted.
    #[test]
    fn accepted_machine_overflow_name_list_does_not_mark_every_agent() {
        let mut bindings =
            AuthenticatedMachineBindingCache::with_capacity(8).with_attribution_limits(1, 1, 1);
        let agent_a = AgentId([0xA1; 32]);
        let agent_b = AgentId([0xB2; 32]);
        let agent_c = AgentId([0xC3; 32]);
        let machine_a = MachineId([1; 32]);
        bindings.record(agent_a, machine_a, 1);
        assert!(!bindings.attribution_requires_attestation(&agent_a));
        bindings.record(agent_b, MachineId([2; 32]), 1);
        assert!(bindings.attribution_requires_attestation(&agent_b));
        assert!(!bindings.attribution_requires_attestation(&agent_a));
        bindings.record(agent_c, MachineId([3; 32]), 1);
        assert!(!bindings.attribution_requires_attestation(&agent_a));
        assert!(!bindings.attribution_requires_attestation(&agent_c));
        assert_eq!(bindings.attribution_unnamed_overflows(), 1);
        assert!(bindings
            .machines_accepted_for(&agent_a)
            .contains(&machine_a));
    }

    /// The production caps are 8, 65,536 and 4,096. Filling the stranger LRU
    /// through `record` (the authenticated announcement writer) leaves a
    /// later stranger protected and a contact in place. The check passes a
    /// clean retained machine, so it fails if the revoked machine was
    /// evicted from the accepted set.
    #[test]
    fn issue1659_real_caps_keep_a_later_stranger_after_announcements() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        assert_eq!(cache.attribution_per_agent, ACCEPTED_MACHINES_PER_AGENT);
        assert_eq!(ACCEPTED_MACHINES_PER_AGENT, 8);
        assert_eq!(cache.attribution_pairs, ACCEPTED_MACHINE_PAIR_CAPACITY);
        assert_eq!(ACCEPTED_MACHINE_PAIR_CAPACITY, 65_536);
        assert_eq!(
            cache.attribution_stranger_pairs,
            ACCEPTED_MACHINE_STRANGER_PAIRS
        );
        assert_eq!(ACCEPTED_MACHINE_STRANGER_PAIRS, 4_096);

        let contact = AgentId([0xC0; 32]);
        let contact_machine = MachineId([0xC0; 32]);
        cache.set_relationship_peer(contact, true);
        cache.record(contact, contact_machine, 1);

        let capped = AgentId([0xCA; 32]);
        cache.set_relationship_peer(capped, true);
        for i in 0..8u8 {
            cache.record(capped, MachineId([i; 32]), u64::from(i) + 1);
        }
        let ninth = MachineId([0xFF; 32]);
        cache.record(capped, ninth, 100);
        assert_eq!(cache.machines_accepted_for(&capped).len(), 8);
        assert!(!cache.machines_accepted_for(&capped).contains(&ninth));
        assert!(cache.attribution_requires_attestation(&capped));

        for i in 0..ACCEPTED_MACHINE_STRANGER_PAIRS {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            let mut agent = [0xA1; 32];
            let mut machine = [0xB1; 32];
            agent[..4].copy_from_slice(&index.to_le_bytes());
            machine[..4].copy_from_slice(&index.to_le_bytes());
            cache.record(AgentId(agent), MachineId(machine), 1);
        }
        assert_eq!(
            cache.attribution_stranger_pairs_len(),
            ACCEPTED_MACHINE_STRANGER_PAIRS
        );
        assert!(cache
            .machines_accepted_for(&contact)
            .contains(&contact_machine));

        let later = AgentId([0xD2; 32]);
        let machine_r_kp = MachineKeypair::generate().expect("machine R");
        let machine_r = machine_r_kp.machine_id();
        let machine_c = MachineId([0xD3; 32]);
        cache.record(later, machine_r, 2);
        assert!(cache.machines_accepted_for(&later).contains(&machine_r));
        assert_eq!(
            cache.attribution_stranger_pairs_len(),
            ACCEPTED_MACHINE_STRANGER_PAIRS
        );
        let mut first = [0xA1; 32];
        first[..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(cache.machines_accepted_for(&AgentId(first)).is_empty());
        assert!(cache
            .machines_accepted_for(&contact)
            .contains(&contact_machine));

        let now = now_unix_ms() / 1000;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(machine_r),
            machine_r_kp.public_key(),
            machine_r_kp.secret_key(),
            now,
            Some("revoked".to_string()),
        )
        .expect("sign machine revocation");
        let mut revoked = RevocationSet::new();
        revoked
            .verify_and_insert(record, None)
            .expect("insert machine revocation");
        let accepted = cache.machines_accepted_for(&later);
        assert_eq!(
            sender_unattested_attribution(
                &revoked,
                &later,
                Some(machine_c),
                machine_c,
                &[],
                &accepted,
                false,
            ),
            UnattestedAttribution::Revoked,
            "a later stranger is still protected after the announcement flood"
        );
    }

    /// Downgrading a contact moves its pairs into the stranger LRU. A later
    /// stranger can evict them. A contact that stays Trusted cannot.
    #[test]
    fn issue1659_contact_downgrade_returns_pairs_to_the_stranger_pool() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(1);
        let former = AgentId([0x11; 32]);
        let kept = AgentId([0x22; 32]);
        let former_machine = MachineId([0x01; 32]);
        let kept_machine = MachineId([0x02; 32]);
        cache.set_relationship_peer(former, true);
        cache.set_relationship_peer(kept, true);
        cache.record(former, former_machine, 1);
        cache.record(kept, kept_machine, 1);
        assert_eq!(cache.attribution_stranger_pairs_len(), 0);

        cache.set_relationship_peer(former, false);
        assert_eq!(cache.attribution_stranger_pairs_len(), 1);
        cache.record(AgentId([0x33; 32]), MachineId([0x03; 32]), 2);
        assert!(cache.machines_accepted_for(&former).is_empty());
        assert!(cache.machines_accepted_for(&kept).contains(&kept_machine));
        assert_eq!(cache.attribution_stranger_pairs_len(), 1);
    }

    /// A new empty cache models a process restart of this set. It does not
    /// reload contacts or tombstones. Those records are separate. This
    /// shows only that a machine known solely from the previous accepted
    /// set is absent, so an unattested claim of a different clean machine
    /// is accepted.
    #[test]
    fn issue1659_restart_drops_cache_only_machine_attribution() {
        let agent = AgentId([0xA1; 32]);
        let machine_b = MachineId([0x22; 32]);
        let machine_kp = MachineKeypair::generate().expect("machine keygen");
        let machine_a = machine_kp.machine_id();
        let mut live = AuthenticatedMachineBindingCache::default();
        live.set_relationship_peer(agent, true);
        live.record(agent, machine_a, 1);
        live.record(agent, machine_b, 2);
        let now = now_unix_ms() / 1000;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(machine_a),
            machine_kp.public_key(),
            machine_kp.secret_key(),
            now,
            Some("compromised hardware".to_string()),
        )
        .expect("sign machine self-revocation");
        let mut revoked = RevocationSet::new();
        revoked
            .verify_and_insert(record, None)
            .expect("machine self-revocation verifies and inserts");
        let accepted = live.machines_accepted_for(&agent);
        assert_eq!(
            sender_unattested_attribution(
                &revoked,
                &agent,
                Some(machine_b),
                machine_b,
                &[],
                &accepted,
                false,
            ),
            UnattestedAttribution::Revoked,
            "before restart the live cache attributes revoked machine A"
        );
        let restarted = AuthenticatedMachineBindingCache::default();
        assert!(restarted.machines_accepted_for(&agent).is_empty());
        assert!(restarted.peek(&agent).is_none());
        assert_eq!(
            sender_unattested_attribution(&revoked, &agent, None, machine_b, &[], &[], false),
            UnattestedAttribution::Allow,
            "after restart a machine known only from the previous cache is not attributed"
        );
    }

    /// After the per-agent cap, a stranger eviction frees a slot and a later
    /// admitted machine is recorded. The overflow flag does not stick.
    #[test]
    fn issue1659_overflow_then_eviction_readmits() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(8);
        let agent = AgentId([0xA9; 32]);
        for index in 0..8u8 {
            cache.record(agent, MachineId([index; 32]), u64::from(index) + 1);
        }
        let refused = MachineId([0x09; 32]);
        cache.record(agent, refused, 20);
        assert!(!cache.machines_accepted_for(&agent).contains(&refused));
        assert!(cache.attribution_requires_attestation(&agent));
        assert_eq!(cache.machines_accepted_for(&agent).len(), 8);

        let refreshed = MachineId([0x00; 32]);
        cache.remember_accepted_machine(agent, refreshed);
        assert!(cache.attribution_requires_attestation(&agent));

        let other = AgentId([0xB9; 32]);
        cache.record(other, MachineId([0xB9; 32]), 30);
        let admitted = MachineId([0x0A; 32]);
        cache.record(agent, admitted, 40);
        let accepted = cache.machines_accepted_for(&agent);
        assert!(
            accepted.contains(&admitted),
            "a freed slot records the next admitted machine"
        );
        assert!(
            accepted.contains(&refreshed),
            "a refreshed pair is not the first stranger evicted"
        );
        assert!(!accepted.contains(&MachineId([0x01; 32])));
        assert!(!cache.attribution_requires_attestation(&agent));
    }

    /// An undecryptable DM leaves machine A in the retained binding only.
    /// A later matching ACK from machine B records B and does not record A.
    #[tokio::test]
    async fn issue1659_undecryptable_dm_then_ack_records_only_the_admitted_machine() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A");
        let machine_b = MachineKeypair::generate().expect("machine B");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let wrong_kem = AgentKemKeypair::generate().expect("wrong kem");
        let created_at = now_unix_ms();
        let body = EnvelopeBuilder::build_payload_body(
            &[0xE4; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created_at,
            b"not for this recipient".to_vec(),
            None,
            &wrong_kem.public_bytes,
        )
        .expect("build body");
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_V1,
            request_id: [0xE4; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine_a.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created_at,
            expires_at_unix_ms: created_at + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, &sender);
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            machine_a.public_key().as_bytes().to_vec(),
        );
        attestation.sign(&machine_a).expect("attest A");
        envelope.origin_attestation = Some(attestation);
        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;

        let request_id = [0xE6; 16];
        let _waiter = harness.pipeline.inflight.register(
            request_id,
            sender.agent_id(),
            Some(machine_b.machine_id()),
        );
        let ack = attested_ack_message(&harness, &sender, &machine_b, 0xE6);
        harness
            .pipeline
            .handle_incoming(ack, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let accepted = harness
            .pipeline
            .authenticated_machine_bindings
            .read()
            .await
            .machines_accepted_for(&sender.agent_id());
        assert!(
            accepted.contains(&machine_b.machine_id()),
            "a matched admitted ACK records its machine"
        );
        assert!(
            !accepted.contains(&machine_a.machine_id()),
            "the undecryptable machine must not take a slot when B is admitted"
        );
    }

    /// A group member and a grant party stay attributed when strangers fill
    /// the LRU. Neither peer is a Trusted or Known contact.
    #[tokio::test]
    async fn issue1659_group_member_and_grant_party_survive_stranger_flood() {
        let harness_sender = test_keypair();
        let member = test_keypair();
        let party = test_keypair();
        let member_id = member.agent_id();
        let party_id = party.agent_id();
        let member_machine = MachineKeypair::generate().expect("member machine");
        let party_machine = MachineKeypair::generate().expect("party machine");
        let mut harness = make_inbox_harness(&harness_sender, None, None).await;
        {
            let mut cache = harness
                .pipeline
                .authenticated_machine_bindings
                .write()
                .await;
            cache.set_stranger_pair_limit_for_test(1);
            cache.install_relationship_probe(AttributionRelationshipProbe::from_fn(move |agent| {
                agent == member_id || agent == party_id
            }));
        }
        for (sender, machine, byte) in [
            (&member, &member_machine, 0x71_u8),
            (&party, &party_machine, 0x72),
        ] {
            let message = attested_payload_message(&harness, sender, machine, byte);
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;
            let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("a protected peer DM is delivered")
                .expect("delivery stream closed");
            assert_eq!(delivered.sender, sender.agent_id());
        }
        let stranger_a = test_keypair();
        let stranger_b = test_keypair();
        let machine_a = MachineKeypair::generate().expect("stranger A");
        let machine_b = MachineKeypair::generate().expect("stranger B");
        for (sender, machine, byte) in [
            (&stranger_a, &machine_a, 0x73_u8),
            (&stranger_b, &machine_b, 0x74),
        ] {
            let message = attested_payload_message(&harness, sender, machine, byte);
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;
            let _delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("an attested stranger DM is delivered")
                .expect("delivery stream closed");
        }
        let cache = harness.pipeline.authenticated_machine_bindings.read().await;
        assert!(cache
            .machines_accepted_for(&member_id)
            .contains(&member_machine.machine_id()));
        assert!(cache
            .machines_accepted_for(&party_id)
            .contains(&party_machine.machine_id()));
        assert_eq!(cache.attribution_stranger_pairs_len(), 1);
        assert!(cache
            .machines_accepted_for(&stranger_a.agent_id())
            .is_empty());
        assert!(cache
            .machines_accepted_for(&stranger_b.agent_id())
            .contains(&machine_b.machine_id()));
    }

    #[test]
    fn issue1659_unknown_relationship_probe_keeps_protection() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        let agent = AgentId([0xC1; 32]);
        let machine = MachineId([0xC2; 32]);
        cache.set_relationship_peer(agent, true);
        cache.record(agent, machine, 1);
        cache.install_relationship_probe(AttributionRelationshipProbe::from_answer(|_| None));
        let keep = cache.resolve_relationship(agent, false);
        assert!(keep, "a probe that cannot answer must not clear protection");
        cache.set_relationship_peer(agent, keep);
        cache.set_stranger_pair_limit_for_test(1);
        let stranger = AgentId([0xC3; 32]);
        cache.record(stranger, MachineId([0xC4; 32]), 2);
        cache.record(stranger, MachineId([0xC5; 32]), 3);
        assert!(
            cache.machines_accepted_for(&agent).contains(&machine),
            "a protected pair survives a stranger flood while the probe is unknown"
        );
        cache.install_relationship_probe(AttributionRelationshipProbe::from_fn(|_| false));
        assert!(
            !cache.resolve_relationship(agent, false),
            "a definite negative answer clears protection"
        );
    }

    /// Dropping contact trust keeps a probe that still says the peer is protected.
    /// A later stranger flood does not evict that pair.
    #[tokio::test]
    async fn issue1659_contact_downgrade_keeps_probe_protection_through_stranger_flood() {
        let member = AgentId([0x51; 32]);
        let machine = MachineId([0x52; 32]);
        let bindings = Arc::new(tokio::sync::RwLock::new(
            AuthenticatedMachineBindingCache::default(),
        ));
        {
            let mut cache = bindings.write().await;
            cache.set_stranger_pair_limit_for_test(1);
            cache.install_relationship_probe(AttributionRelationshipProbe::from_fn(move |agent| {
                agent == member
            }));
        }
        set_resolved_attribution_standing(&bindings, member, true).await;
        record_authenticated_machine_binding(&bindings, member, machine, 1).await;
        set_resolved_attribution_standing(&bindings, member, false).await;
        record_authenticated_machine_binding(
            &bindings,
            AgentId([0x53; 32]),
            MachineId([0x53; 32]),
            2,
        )
        .await;
        record_authenticated_machine_binding(
            &bindings,
            AgentId([0x54; 32]),
            MachineId([0x54; 32]),
            3,
        )
        .await;
        let cache = bindings.read().await;
        assert_eq!(cache.standing_of(member), AttributionStanding::Protected);
        assert!(
            cache.machines_accepted_for(&member).contains(&machine),
            "group or grant protection survives a contact downgrade and a stranger flood"
        );
    }

    /// Protected non-contacts have their own share. Filling it does not drop a contact.
    /// The stranger share still accepts a pair after the contact share is full.
    #[test]
    fn issue1659_protected_share_cannot_take_contact_slots() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_attribution_limits_for_test(8, 4, 4);
        cache.set_stranger_pair_limit_for_test(1);
        cache.set_protected_pair_limit_for_test(1);
        let contact = AgentId([0x11; 32]);
        cache.set_relationship_peer(contact, true);
        cache.record(contact, MachineId([0x11; 32]), 1);
        cache.record(contact, MachineId([0x12; 32]), 2);
        let protected = AgentId([0x21; 32]);
        cache.set_standing(protected, AttributionStanding::Protected);
        cache.record(protected, MachineId([0x21; 32]), 3);
        let sybil = AgentId([0x31; 32]);
        cache.set_standing(sybil, AttributionStanding::Protected);
        cache.record(sybil, MachineId([0x31; 32]), 4);
        assert!(cache
            .machines_accepted_for(&contact)
            .contains(&MachineId([0x11; 32])));
        assert!(cache
            .machines_accepted_for(&contact)
            .contains(&MachineId([0x12; 32])));
        assert_eq!(cache.machines_accepted_for(&contact).len(), 2);
        let stranger = AgentId([0x41; 32]);
        cache.record(stranger, MachineId([0x41; 32]), 5);
        assert!(
            cache
                .machines_accepted_for(&stranger)
                .contains(&MachineId([0x41; 32])),
            "the stranger share stays available when the contact share is full"
        );
        assert_eq!(cache.machines_accepted_for(&contact).len(), 2);
        assert!(
            cache.machines_accepted_for(&protected).is_empty(),
            "the protected share evicts its own pair"
        );
        assert!(cache
            .machines_accepted_for(&sybil)
            .contains(&MachineId([0x31; 32])));
        assert_eq!(cache.attribution_protected_pairs_len, 1);
        assert_eq!(cache.machines_accepted_for(&contact).len(), 2);
    }

    /// A full contact share must not drop a revoked machine while the clean
    /// machine stays the retained binding.
    #[test]
    fn issue1659_contact_promotion_keeps_revoked_machine_when_share_is_full() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_attribution_limits_for_test(8, 4, 4);
        cache.set_stranger_pair_limit_for_test(2);
        cache.install_revoked_machine_probe(|machine| Some(machine.0[0] == 0xA1));
        let filler = AgentId([0x01; 32]);
        cache.set_relationship_peer(filler, true);
        cache.record(filler, MachineId([0x01; 32]), 1);
        cache.record(filler, MachineId([0x02; 32]), 2);
        assert_eq!(cache.contact_pairs_len(), 2);
        let peer = AgentId([0x10; 32]);
        let revoked = MachineId([0xA1; 32]);
        let clean = MachineId([0xB1; 32]);
        cache.record(peer, revoked, 3);
        cache.record(peer, clean, 4);
        cache.set_relationship_peer(peer, true);
        assert_eq!(
            cache.entries.get(&peer).map(|binding| binding.machine_id),
            Some(clean),
            "the clean machine stays the retained binding"
        );
        assert!(
            cache.machines_accepted_for(&peer).contains(&revoked),
            "promotion must keep the revoked machine when the contact share is full"
        );
        assert!(
            !cache.machines_accepted_for(&peer).contains(&clean),
            "a clean pair is the one promotion drops"
        );
        assert_eq!(cache.machines_accepted_for(&filler).len(), 2);
    }

    /// Sybil identity churn must not evict a stranger's revoked pair.
    #[test]
    fn issue1659_stranger_revocation_pin_survives_identity_churn() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(2);
        cache.install_revoked_machine_probe(|machine| Some(machine.0[0] == 0x11));
        let victim = AgentId([0x21; 32]);
        let revoked = MachineId([0x11; 32]);
        let clean = MachineId([0x12; 32]);
        cache.record(victim, revoked, 1);
        cache.record(victim, clean, 2);
        for offset in 1..8u8 {
            let agent = AgentId([0x30 + offset; 32]);
            cache.record(
                agent,
                MachineId([0x40 + offset; 32]),
                u64::from(offset) + 10,
            );
        }
        assert!(
            cache.machines_accepted_for(&victim).contains(&revoked),
            "a revoked stranger pair stays attributed through identity churn"
        );
        assert!(
            !cache.machines_accepted_for(&victim).contains(&clean),
            "a clean stranger pair is evicted before a pinned revocation"
        );
    }

    /// A one-time flood of self-issued revocations must not pin every
    /// stranger slot. Later strangers stay recordable. The oldest pins stay.
    #[test]
    fn issue1659_stranger_pin_cap_keeps_room_for_a_later_stranger() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(4);
        cache.install_revoked_machine_probe(|_| Some(true));
        let mut flood = Vec::new();
        for index in 0..4u8 {
            let agent = AgentId([0x10 + index; 32]);
            let machine = MachineId([0x40 + index; 32]);
            cache.record(agent, machine, u64::from(index) + 1);
            flood.push((agent, machine));
        }
        assert_eq!(cache.attribution_stranger_pairs_len(), 4);
        let later = AgentId([0x90; 32]);
        let later_machine = MachineId([0x90; 32]);
        cache.record(later, later_machine, 10);
        assert!(
            cache.machines_accepted_for(&later).contains(&later_machine),
            "a share-level pin cap must leave a slot for a later stranger"
        );
        assert_eq!(cache.attribution_stranger_pairs_len(), 4);
        assert!(
            cache
                .machines_accepted_for(&flood[0].0)
                .contains(&flood[0].1),
            "eviction must not drop a revoked pin to make room"
        );
        assert!(
            cache
                .machines_accepted_for(&flood[1].0)
                .contains(&flood[1].1),
            "the oldest revoked pins stay"
        );
    }

    /// Contact promotion keeps the newest revoked pairs, not HashSet order.
    #[test]
    fn issue1659_contact_promotion_keeps_the_newest_revoked_pairs() {
        for pattern in 0..12u8 {
            let mut cache = AuthenticatedMachineBindingCache::default();
            cache.set_attribution_limits_for_test(8, 8, 8);
            cache.set_stranger_pair_limit_for_test(4);
            let oldest = MachineId(tagged_id(0xA0, pattern, 1));
            let middle = MachineId(tagged_id(0xA0, pattern, 2));
            let newest = MachineId(tagged_id(0xA0, pattern, 3));
            cache.install_revoked_machine_probe(move |machine| {
                Some(machine == oldest || machine == middle || machine == newest)
            });
            let filler = AgentId(tagged_id(0x01, pattern, 0));
            cache.set_relationship_peer(filler, true);
            for index in 0..4u8 {
                cache.record(
                    filler,
                    MachineId(tagged_id(0x10, pattern, index)),
                    u64::from(index) + 1,
                );
            }
            let peer = AgentId(tagged_id(0x50, pattern, 0));
            cache.record(peer, oldest, 10);
            cache.record(peer, middle, 11);
            cache.record(peer, newest, 12);
            cache.set_relationship_peer(peer, true);
            let kept = cache.machines_accepted_for(&peer);
            assert!(
                kept.contains(&middle) && kept.contains(&newest),
                "pattern {pattern} must keep the newest revoked pairs"
            );
            assert!(
                !kept.contains(&oldest),
                "pattern {pattern} must drop the oldest revoked pair"
            );
        }
    }

    /// Unknown revocation answers must not sit above the contact remainder.
    /// That overshoot fills the global pair cap and refuses a later stranger.
    #[test]
    fn issue1659_contact_promotion_drops_unknown_pairs_that_do_not_fit() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_attribution_limits_for_test(8, 6, 8);
        cache.set_stranger_pair_limit_for_test(3);
        cache.install_revoked_machine_probe(|_| None);
        let filler = AgentId([0x01; 32]);
        cache.set_relationship_peer(filler, true);
        for index in 0..3u8 {
            cache.record(filler, MachineId([0x10 + index; 32]), u64::from(index) + 1);
        }
        let peer = AgentId([0x02; 32]);
        for index in 0..3u8 {
            cache.record(peer, MachineId([0x20 + index; 32]), 10 + u64::from(index));
        }
        cache.set_relationship_peer(peer, true);
        assert!(
            cache.contact_pairs_len() <= 3,
            "unknown pairs must fit the contact remainder"
        );
        let stranger = AgentId([0x03; 32]);
        let stranger_machine = MachineId([0x30; 32]);
        cache.record(stranger, stranger_machine, 20);
        assert!(
            cache
                .machines_accepted_for(&stranger)
                .contains(&stranger_machine),
            "unknown pairs must not consume the reserved stranger slot"
        );
    }

    /// Demotion must not push the stranger share past its cap when every
    /// stored pair is unevictable.
    #[test]
    fn issue1659_demotion_does_not_pass_the_stranger_cap() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(2);
        cache.install_revoked_machine_probe(|_| Some(true));
        let oldest = AgentId([0x01; 32]);
        let oldest_machine = MachineId([0x11; 32]);
        cache.record(oldest, oldest_machine, 1);
        cache.record(AgentId([0x02; 32]), MachineId([0x22; 32]), 2);
        assert_eq!(cache.attribution_stranger_pairs_len(), 2);
        let contact = AgentId([0x03; 32]);
        cache.set_relationship_peer(contact, true);
        cache.record(contact, MachineId([0x33; 32]), 3);
        cache.set_relationship_peer(contact, false);
        assert!(
            cache.attribution_stranger_pairs_len() <= 2,
            "demotion must not push the stranger share past its cap"
        );
        assert!(
            cache
                .machines_accepted_for(&oldest)
                .contains(&oldest_machine),
            "demotion must not evict a revoked pin to make room"
        );

        let mut unknowns = AuthenticatedMachineBindingCache::default();
        unknowns.set_stranger_pair_limit_for_test(2);
        unknowns.install_revoked_machine_probe(|machine| {
            if machine.0[0] == 0x33 {
                Some(true)
            } else {
                None
            }
        });
        unknowns.record(AgentId([0x11; 32]), MachineId([0x21; 32]), 1);
        unknowns.record(AgentId([0x12; 32]), MachineId([0x22; 32]), 2);
        let revoked_contact = AgentId([0x13; 32]);
        unknowns.set_relationship_peer(revoked_contact, true);
        unknowns.record(revoked_contact, MachineId([0x33; 32]), 3);
        unknowns.set_relationship_peer(revoked_contact, false);
        assert!(
            unknowns.attribution_stranger_pairs_len() <= 2,
            "demotion onto unevictable pairs must not pass the stranger cap"
        );
    }

    /// A forgotten removal epoch must not compare equal to generation 0.
    /// Stranger churn that evicts the removal would otherwise let a resolve
    /// which read 0, with contact true, promote the removed contact again.
    #[test]
    fn issue1659_evicted_removal_epoch_does_not_match_a_generation_zero_resolve() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_relationship_epoch_limit_for_test(2);
        let agent = AgentId([0x11; 32]);
        assert_eq!(cache.relationship_epoch(agent), 0);
        cache.set_standing(agent, AttributionStanding::Contact);
        cache.set_standing(agent, AttributionStanding::Stranger);
        cache.set_standing(AgentId([0x21; 32]), AttributionStanding::Stranger);
        cache.set_standing(AgentId([0x22; 32]), AttributionStanding::Stranger);
        cache.set_standing(AgentId([0x23; 32]), AttributionStanding::Stranger);
        assert!(
            !cache.set_standing_if_epoch(agent, AttributionStanding::Contact, 0),
            "a resolve that read generation 0 must not undo the contact removal"
        );
        assert_eq!(cache.standing_of(agent), AttributionStanding::Stranger);
    }

    #[test]
    fn issue1659_stale_epoch_does_not_overwrite_standing() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        let agent = AgentId([0x71; 32]);
        cache.set_standing(agent, AttributionStanding::Stranger);
        let epoch = cache.relationship_epoch(agent);
        cache.set_standing(agent, AttributionStanding::Contact);
        assert!(
            !cache.set_standing_if_epoch(agent, AttributionStanding::Stranger, epoch),
            "a resolve that read the old epoch must not apply"
        );
        assert_eq!(cache.standing_of(agent), AttributionStanding::Contact);
    }

    #[test]
    fn issue1659_relationship_epochs_evict_cycling_strangers() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_relationship_epoch_limit_for_test(2);
        let contact = AgentId([0x11; 32]);
        cache.set_standing(contact, AttributionStanding::Contact);
        let contact_epoch = cache.relationship_epoch(contact);
        let first = AgentId([0x21; 32]);
        let second = AgentId([0x22; 32]);
        cache.set_standing(first, AttributionStanding::Stranger);
        let first_epoch = cache.relationship_epoch(first);
        cache.set_standing(second, AttributionStanding::Stranger);
        assert_eq!(
            cache.relationship_epoch(contact),
            contact_epoch,
            "a contact epoch stays while stranger epochs cycle"
        );
        assert_ne!(
            cache.relationship_epoch(first),
            first_epoch,
            "the oldest stranger epoch is evicted"
        );
        let second_epoch = cache.relationship_epoch(second);
        assert_ne!(second_epoch, 0);
        assert_ne!(
            second_epoch, first_epoch,
            "the stored stranger epoch is the one just written"
        );
    }

    /// A missing epoch is the stored high-water mark of evicted epochs.
    /// Another standing write that does not evict must not move it, or
    /// `with_contact_standing` retries until it gives up and skips the write.
    #[test]
    fn issue1659_missing_epoch_reads_the_evicted_high_water_mark() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        let missing = AgentId([0x91; 32]);
        assert_eq!(cache.relationship_epoch(missing), 0);
        cache.set_standing(AgentId([0x92; 32]), AttributionStanding::Stranger);
        assert_eq!(
            cache.relationship_epoch(missing),
            0,
            "a missing epoch does not follow the live clock"
        );

        cache.set_relationship_epoch_limit_for_test(1);
        cache.set_standing(AgentId([0x93; 32]), AttributionStanding::Stranger);
        let after_eviction = cache.relationship_epoch(missing);
        assert_ne!(after_eviction, 0, "eviction publishes a high-water mark");
        cache.set_relationship_epoch_limit_for_test(8);
        cache.set_standing(AgentId([0x94; 32]), AttributionStanding::Stranger);
        assert_eq!(
            cache.relationship_epoch(missing),
            after_eviction,
            "a later standing write must not move the evicted-epoch high-water mark"
        );
    }

    #[test]
    fn issue1659_attach_pairs_evicts_down_to_the_protected_cap() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_protected_pair_limit_for_test(1);
        cache.set_stranger_pair_limit_for_test(4);
        let agent = AgentId([0x81; 32]);
        cache.record(agent, MachineId([1; 32]), 1);
        cache.record(agent, MachineId([2; 32]), 2);
        cache.record(agent, MachineId([3; 32]), 3);
        cache.set_standing(agent, AttributionStanding::Protected);
        assert_eq!(cache.machines_accepted_for(&agent).len(), 1);
        assert_eq!(cache.attribution_protected_pairs_len, 1);
    }

    #[test]
    fn issue1659_contact_promotion_leaves_the_stranger_share() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_attribution_limits_for_test(8, 4, 4);
        cache.set_stranger_pair_limit_for_test(1);
        let contact = AgentId([1; 32]);
        cache.set_relationship_peer(contact, true);
        cache.record(contact, MachineId([1; 32]), 1);
        cache.record(contact, MachineId([2; 32]), 2);
        cache.record(contact, MachineId([3; 32]), 3);
        let promoted = AgentId([4; 32]);
        cache.record(promoted, MachineId([4; 32]), 4);
        cache.set_relationship_peer(promoted, true);
        let stranger = AgentId([5; 32]);
        cache.record(stranger, MachineId([5; 32]), 5);
        assert!(
            cache
                .machines_accepted_for(&stranger)
                .contains(&MachineId([5; 32])),
            "a contact promotion must not consume the stranger share"
        );
    }

    #[test]
    fn issue1659_revoked_protected_pair_survives_a_share_flood() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_protected_pair_limit_for_test(2);
        cache.install_revoked_machine_probe(|machine| Some(machine.0[0] == 0x11));
        let victim = AgentId([0x21; 32]);
        let revoked = MachineId([0x11; 32]);
        let clean = MachineId([0x12; 32]);
        cache.set_standing(victim, AttributionStanding::Protected);
        cache.record(victim, revoked, 1);
        cache.record(victim, clean, 2);
        for offset in 1..6u8 {
            let agent = AgentId([0x30 + offset; 32]);
            cache.set_standing(agent, AttributionStanding::Protected);
            cache.record(
                agent,
                MachineId([0x40 + offset; 32]),
                u64::from(offset) + 10,
            );
        }
        assert!(
            cache.machines_accepted_for(&victim).contains(&revoked),
            "a revoked protected pair stays attributed through a share flood"
        );
        assert!(
            !cache.machines_accepted_for(&victim).contains(&clean),
            "a non-revoked pair in the same share is evicted first"
        );
    }

    #[test]
    fn issue1659_pin_cap_lets_an_older_revoked_machine_be_evicted() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_protected_pair_limit_for_test(4);
        cache.install_revoked_machine_probe(|_| Some(true));
        let agent = AgentId([0x91; 32]);
        cache.set_standing(agent, AttributionStanding::Protected);
        let oldest = MachineId([1; 32]);
        cache.record(agent, oldest, 1);
        cache.record(agent, MachineId([2; 32]), 2);
        cache.record(agent, MachineId([3; 32]), 3);
        cache.record(agent, MachineId([4; 32]), 4);
        cache.record(agent, MachineId([5; 32]), 5);
        assert!(
            !cache.machines_accepted_for(&agent).contains(&oldest),
            "a third revoked machine is past the per-agent pin cap"
        );
        assert!(cache
            .machines_accepted_for(&agent)
            .contains(&MachineId([2; 32])));
        assert!(cache
            .machines_accepted_for(&agent)
            .contains(&MachineId([4; 32])));
    }

    #[test]
    fn issue1659_unknown_revocation_does_not_count_toward_the_pin() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_protected_pair_limit_for_test(3);
        let agent = AgentId([0xA1; 32]);
        let revoked = MachineId([0x11; 32]);
        let clean_b = MachineId([0x12; 32]);
        let clean_c = MachineId([0x13; 32]);
        cache.install_revoked_machine_probe(move |machine| {
            if machine == revoked {
                Some(true)
            } else if machine == clean_b || machine == clean_c {
                None
            } else {
                Some(false)
            }
        });
        cache.set_standing(agent, AttributionStanding::Protected);
        cache.record(agent, revoked, 1);
        cache.record(agent, clean_b, 2);
        cache.record(agent, clean_c, 3);
        for offset in 1..5u8 {
            let other = AgentId([0xB0 + offset; 32]);
            cache.set_standing(other, AttributionStanding::Protected);
            cache.record(
                other,
                MachineId([0xC0 + offset; 32]),
                u64::from(offset) + 10,
            );
        }
        assert!(
            cache.machines_accepted_for(&agent).contains(&revoked),
            "unknown newer machines must not make the revoked machine evictable"
        );
        assert!(cache.machines_accepted_for(&agent).contains(&clean_b));
        assert!(cache.machines_accepted_for(&agent).contains(&clean_c));
        assert_eq!(cache.attribution_protected_pairs_len, 3);
    }

    #[test]
    fn issue1659_pinned_reclassification_does_not_pass_the_protected_cap() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_protected_pair_limit_for_test(2);
        cache.install_revoked_machine_probe(|_| Some(true));
        let first = AgentId([0x11; 32]);
        let second = AgentId([0x12; 32]);
        cache.set_standing(first, AttributionStanding::Protected);
        cache.record(first, MachineId([0x11; 32]), 1);
        cache.set_standing(second, AttributionStanding::Protected);
        cache.record(second, MachineId([0x12; 32]), 2);
        let incoming = AgentId([0x13; 32]);
        cache.record(incoming, MachineId([0x13; 32]), 3);
        cache.record(incoming, MachineId([0x14; 32]), 4);
        cache.set_standing(incoming, AttributionStanding::Protected);
        assert_eq!(cache.attribution_protected_pairs_len, 2);
        assert_eq!(cache.standing_of(incoming), AttributionStanding::Stranger);
        assert_eq!(cache.machines_accepted_for(&incoming).len(), 2);
        for offset in 1..5u8 {
            let agent = AgentId([0x30 + offset; 32]);
            cache.record(
                agent,
                MachineId([0x40 + offset; 32]),
                20 + u64::from(offset),
            );
            cache.set_standing(agent, AttributionStanding::Protected);
        }
        assert_eq!(cache.attribution_protected_pairs_len, 2);
        let stranger = AgentId([0x21; 32]);
        cache.record(stranger, MachineId([0x21; 32]), 30);
        assert!(
            cache
                .machines_accepted_for(&stranger)
                .contains(&MachineId([0x21; 32])),
            "a refused protected transfer must leave the stranger share available"
        );
        assert!(cache
            .machines_accepted_for(&first)
            .contains(&MachineId([0x11; 32])));
        assert!(cache
            .machines_accepted_for(&second)
            .contains(&MachineId([0x12; 32])));
    }

    #[test]
    fn issue1659_protected_peer_metadata_leaves_with_the_last_machine_and_epoch() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_relationship_epoch_limit_for_test(1);
        cache.set_protected_pair_limit_for_test(1);
        let churned = AgentId([0x51; 32]);
        cache.set_standing(churned, AttributionStanding::Protected);
        cache.record(churned, MachineId([0x51; 32]), 1);
        let keeper = AgentId([0x52; 32]);
        cache.set_standing(keeper, AttributionStanding::Protected);
        assert_eq!(
            cache.standing_of(churned),
            AttributionStanding::Protected,
            "a protected peer with a machine stays after its epoch is evicted"
        );
        cache.record(keeper, MachineId([0x52; 32]), 2);
        assert!(
            !cache
                .machines_accepted_for(&churned)
                .contains(&MachineId([0x51; 32])),
            "the keeper takes the only protected slot"
        );
        assert_eq!(
            cache.standing_of(churned),
            AttributionStanding::Stranger,
            "a protected peer leaves when its last machine and its epoch are gone"
        );
        assert_eq!(cache.standing_of(keeper), AttributionStanding::Protected);

        cache.set_relationship_epoch_limit_for_test(1);
        let mut previous = None;
        for offset in 0..4u8 {
            let agent = AgentId([0x60 + offset; 32]);
            cache.set_standing(agent, AttributionStanding::Protected);
            if let Some(old) = previous {
                assert_eq!(
                    cache.standing_of(old),
                    AttributionStanding::Stranger,
                    "epoch churn must drop a protected peer that has no machine"
                );
            }
            previous = Some(agent);
        }
        assert_eq!(
            cache.standing_of(previous.expect("last agent")),
            AttributionStanding::Protected
        );
    }

    #[tokio::test]
    async fn issue1659_stale_contact_snapshot_cannot_demote_a_promoted_contact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let contacts = Arc::new(RwLock::new(ContactStore::new(
            dir.path().join("contacts.json"),
        )));
        let bindings = Arc::new(RwLock::new(AuthenticatedMachineBindingCache::default()));
        let agent = AgentId([0xA9; 32]);
        bindings
            .write()
            .await
            .set_standing(agent, AttributionStanding::Stranger);
        let gate = Arc::new(ContactSnapshotGate {
            agent,
            armed: std::sync::atomic::AtomicBool::new(true),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        *CONTACT_SNAPSHOT_GATE.lock().expect("gate") = Some(Arc::clone(&gate));
        struct ClearGate;
        impl Drop for ClearGate {
            fn drop(&mut self) {
                if let Ok(mut slot) = CONTACT_SNAPSHOT_GATE.lock() {
                    *slot = None;
                }
            }
        }
        let _clear = ClearGate;
        let contacts_task = Arc::clone(&contacts);
        let bindings_task = Arc::clone(&bindings);
        let task = tokio::spawn(async move {
            with_contact_standing(&bindings_task, &contacts_task, agent, |_| ()).await;
        });
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("the contact snapshot must pause");
        contacts
            .write()
            .await
            .set_trust(&agent, TrustLevel::Trusted);
        {
            let mut cache = bindings.write().await;
            let held = cache.relationship_epoch(agent);
            cache.set_relationship_epoch_limit_for_test(1);
            cache.set_standing(AgentId([0xB1; 32]), AttributionStanding::Stranger);
            assert_ne!(
                cache.relationship_epoch(agent),
                held,
                "epoch eviction must not leave the generation the paused resolve holds"
            );
            cache.set_standing(agent, AttributionStanding::Contact);
            let promoted = cache.relationship_epoch(agent);
            assert_ne!(
                promoted, held,
                "a promotion after eviction must not reuse the generation the resolve holds"
            );
            assert_ne!(promoted, 0);
        }
        gate.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("standing resolve finishes")
            .expect("standing task");
        assert_eq!(
            bindings.read().await.standing_of(agent),
            AttributionStanding::Contact,
            "a stale contact snapshot must not demote a promotion that already bumped the epoch"
        );
    }

    #[test]
    fn issue1659_probe_install_reclassifies_existing_pairs() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(1);
        let member = AgentId([0x51; 32]);
        let machine = MachineId([0x52; 32]);
        cache.record(member, machine, 1);
        assert_eq!(cache.standing_of(member), AttributionStanding::Stranger);
        cache.install_relationship_probe(AttributionRelationshipProbe::from_fn(move |agent| {
            agent == member
        }));
        cache.reclassify_attribution(|_| false);
        assert_eq!(cache.standing_of(member), AttributionStanding::Protected);
        cache.record(AgentId([0x53; 32]), MachineId([0x53; 32]), 2);
        cache.record(AgentId([0x54; 32]), MachineId([0x54; 32]), 3);
        assert!(
            cache.machines_accepted_for(&member).contains(&machine),
            "a pair recorded before the probe is installed moves out of the stranger share"
        );
    }

    #[test]
    fn issue1659_unattested_warning_is_per_sender() {
        let log = std::sync::Mutex::new(UnattestedWarnLog::default());
        let now = monotonic_ms();
        assert!(log.lock().expect("warn log").allow(&[1; 32], now));
        assert!(!log.lock().expect("warn log").allow(&[1; 32], now));
        assert!(
            log.lock().expect("warn log").allow(&[2; 32], now),
            "one sender must not mask another sender's warning"
        );
    }

    /// Senders past the remembered cap share one interval. A new identity
    /// must not take a slot and warn on every DM.
    #[test]
    fn issue1659_warn_limiter_shares_one_interval_past_the_cap() {
        let mut log = UnattestedWarnLog::default();
        let now = monotonic_ms();
        for index in 0..UNATTESTED_WARN_SENDERS {
            assert!(
                log.allow(&warn_sender(index), now),
                "each remembered sender may warn once"
            );
        }
        let first = warn_sender(0);
        assert!(
            log.allow(&warn_sender(UNATTESTED_WARN_SENDERS), now),
            "the first sender past the cap may warn once in the interval"
        );
        assert!(
            !log.allow(&warn_sender(UNATTESTED_WARN_SENDERS + 1), now),
            "a further sender in the same interval must not warn"
        );
        assert!(
            !log.allow(&first, now),
            "a remembered sender keeps its interval when new senders arrive"
        );
    }

    /// A full limiter reuses a slot whose interval has expired. It does not
    /// keep every later sender on one shared interval for the process life.
    #[test]
    fn issue1659_warn_limiter_reuses_an_expired_slot() {
        let mut log = UnattestedWarnLog::default();
        let now = 5_000u64;
        for index in 0..UNATTESTED_WARN_SENDERS {
            assert!(log.allow(&warn_sender(index), now));
        }
        assert!(log.allow(&warn_sender(UNATTESTED_WARN_SENDERS), now));
        let later = now + UNATTESTED_DROP_WARN_INTERVAL_MS;
        let reused = warn_sender(UNATTESTED_WARN_SENDERS + 1);
        assert!(
            log.allow(&reused, later),
            "an expired remembered slot must be free for a new sender"
        );
        assert!(
            !log.allow(&reused, later),
            "the reused slot keeps its own interval"
        );
        let another = warn_sender(UNATTESTED_WARN_SENDERS + 2);
        assert!(
            log.allow(&another, later),
            "a second new sender must reuse another expired slot in the same interval"
        );
    }

    fn tagged_id(tag: u8, pattern: u8, slot: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes[1] = pattern;
        bytes[2] = slot;
        bytes
    }

    fn warn_sender(index: usize) -> [u8; 32] {
        let mut sender = [0u8; 32];
        let value = u16::try_from(index).expect("sender index");
        sender[30] = u8::try_from(value >> 8).expect("high byte");
        sender[31] = u8::try_from(value & 0xff).expect("low byte");
        sender
    }

    #[test]
    fn issue1659_stranger_share_stays_when_the_contact_share_is_full() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_attribution_limits_for_test(8, 3, 4);
        cache.set_stranger_pair_limit_for_test(1);
        let contact = AgentId([0x61; 32]);
        cache.set_relationship_peer(contact, true);
        cache.record(contact, MachineId([1; 32]), 1);
        cache.record(contact, MachineId([2; 32]), 2);
        cache.record(contact, MachineId([3; 32]), 3);
        assert_eq!(cache.machines_accepted_for(&contact).len(), 2);
        let stranger = AgentId([0x62; 32]);
        cache.record(stranger, MachineId([4; 32]), 4);
        assert!(cache
            .machines_accepted_for(&stranger)
            .contains(&MachineId([4; 32])));
        assert_eq!(cache.attribution_stranger_pairs_len(), 1);
        assert!(cache
            .machines_accepted_for(&contact)
            .contains(&MachineId([1; 32])));
    }

    /// A full stranger pin cap does not refuse an unlinked stranger. It
    /// refuses a stranger whose revoked pair was dropped, and that refusal
    /// is counted exactly once. While the cap is not full, neither sender
    /// is refused for the cap.
    #[test]
    fn issue1659_full_pin_cap_refuses_only_a_dropped_revoked_pair() {
        let mut open = AuthenticatedMachineBindingCache::default();
        open.set_stranger_pair_limit_for_test(4);
        open.install_revoked_machine_probe(|_| Some(true));
        open.record(AgentId([0x01; 32]), MachineId([0x01; 32]), 1);
        let unlinked = AgentId([0x44; 32]);
        assert!(
            !open.stranger_pin_cap_full(),
            "one revoked pair must leave the pin cap open"
        );
        assert!(
            !open.stranger_pin_cap_refuses_unattested(unlinked),
            "an open pin cap must not refuse an unlinked stranger"
        );

        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(2);
        let pinned_agent = AgentId([0x11; 32]);
        let pinned_machine = MachineId([0xA1; 32]);
        let dropped_agent = AgentId([0x22; 32]);
        let dropped_machine = MachineId([0xA2; 32]);
        cache.install_revoked_machine_probe(move |machine| {
            Some(machine == pinned_machine || machine == dropped_machine)
        });
        cache.record(pinned_agent, pinned_machine, 1);
        cache.record(dropped_agent, dropped_machine, 2);
        cache.record(AgentId([0x33; 32]), MachineId([0x33; 32]), 3);
        assert!(
            cache.stranger_pin_cap_full(),
            "the first revoked pair fills a cap of one"
        );
        assert!(
            cache
                .machines_accepted_for(&pinned_agent)
                .contains(&pinned_machine),
            "a revoked pin stays when a later stranger needs a slot"
        );
        assert!(
            !cache
                .machines_accepted_for(&dropped_agent)
                .contains(&dropped_machine),
            "a revoked pair that could not be pinned is the one eviction drops"
        );
        assert!(
            cache.stranger_pin_cap_refuses_unattested(dropped_agent),
            "a dropped revoked pair is refused while the pin cap is full"
        );
        assert!(
            !cache.stranger_pin_cap_refuses_unattested(unlinked),
            "an unlinked stranger is accepted while the pin cap is full"
        );
    }

    /// Seen while clean, revoked later, then a stranger flood. The pair
    /// must be pinned when eviction reaches it and the pin cap still has
    /// room. It must not be dropped first.
    #[test]
    fn issue1659_late_revocation_stays_pinned_while_the_cap_has_room() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(4);
        let victim = AgentId([0x21; 32]);
        let revoked = MachineId([0x11; 32]);
        let clean = MachineId([0x12; 32]);
        let revoked_now = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&revoked_now);
        cache.install_revoked_machine_probe(move |machine| {
            if machine == revoked {
                Some(flag.load(std::sync::atomic::Ordering::SeqCst))
            } else {
                Some(false)
            }
        });
        cache.record(victim, revoked, 1);
        cache.record(victim, clean, 2);
        revoked_now.store(true, std::sync::atomic::Ordering::SeqCst);
        for offset in 0..8u8 {
            cache.record(
                AgentId([0x30 + offset; 32]),
                MachineId([0x40 + offset; 32]),
                10 + u64::from(offset),
            );
        }
        assert!(
            cache.machines_accepted_for(&victim).contains(&revoked),
            "a pair seen clean and revoked later stays while the pin cap has room"
        );
        assert!(
            !cache.stranger_pin_cap_refuses_unattested(victim),
            "a late revocation that fit the pin cap is not a dropped pair"
        );
        assert!(
            !cache.stranger_pin_cap_full(),
            "one late pin must leave a cap of two open"
        );
    }

    /// Dropped-pair records stay within the stranger share. The oldest
    /// record is forgotten. A later dropped agent is still refused while
    /// the pin cap is full.
    #[test]
    fn issue1659_revoked_unpinned_records_stay_within_the_stranger_share() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(2);
        cache.install_revoked_machine_probe(|_| Some(true));
        let pinned = AgentId([0x01; 32]);
        cache.record(pinned, MachineId([0x01; 32]), 1);
        let mut dropped = Vec::new();
        for index in 0..6u8 {
            let agent = AgentId([0x50 + index; 32]);
            cache.record(agent, MachineId([0x80 + index; 32]), 10 + u64::from(index));
            dropped.push(agent);
        }
        assert!(cache.stranger_pin_cap_full());
        assert!(
            cache
                .machines_accepted_for(&pinned)
                .contains(&MachineId([0x01; 32])),
            "the pin stays while later revoked pairs are dropped"
        );
        assert!(
            !cache.stranger_pin_cap_refuses_unattested(dropped[0]),
            "an unpinned record past the stranger share is forgotten"
        );
        assert!(!cache.stranger_pin_cap_refuses_unattested(dropped[3]));
        assert!(cache.stranger_pin_cap_refuses_unattested(dropped[4]));
        assert!(cache.stranger_pin_cap_refuses_unattested(dropped[5]));
        assert!(cache.revoked_unpinned_len() <= 2);
    }

    /// Promoting an agent out of the stranger share releases that agent's
    /// pin. A clean pair that no longer fits is dropped, not left accepted
    /// outside every share.
    #[test]
    fn issue1659_leaving_the_stranger_share_releases_the_pin() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(2);
        cache.set_protected_pair_limit_for_test(0);
        let agent = AgentId([0x21; 32]);
        let machine = MachineId([0x11; 32]);
        let revoked_now = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flag = std::sync::Arc::clone(&revoked_now);
        cache.install_revoked_machine_probe(move |_| {
            Some(flag.load(std::sync::atomic::Ordering::SeqCst))
        });
        cache.record(agent, machine, 1);
        assert!(
            cache.stranger_pin_cap_full(),
            "one revoked pair fills a pin cap of one"
        );
        revoked_now.store(false, std::sync::atomic::Ordering::SeqCst);
        cache.set_standing(agent, AttributionStanding::Protected);
        assert!(
            cache.machines_accepted_for(&agent).is_empty(),
            "a clean pair that does not fit the protected share is dropped"
        );
        assert!(
            !cache.stranger_pin_cap_full(),
            "leaving the stranger share releases the pin"
        );
        assert_eq!(cache.attribution_protected_pairs_len, 0);
        assert_eq!(cache.attribution_stranger_pairs_len(), 0);
    }

    /// A clean probe answer removes the agent from the refused set while the
    /// pin cap stays full. Freeing the cap stops the refusal and leaves the
    /// dropped-pair record in place.
    #[test]
    fn issue1659_clean_answer_and_a_free_cap_leave_the_refused_set() {
        let mut clean_cache = AuthenticatedMachineBindingCache::default();
        clean_cache.set_stranger_pair_limit_for_test(2);
        let pinned_agent = AgentId([0x11; 32]);
        let pinned_machine = MachineId([0xA1; 32]);
        let dropped_agent = AgentId([0x22; 32]);
        let dropped_machine = MachineId([0xA2; 32]);
        let mode = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let mode_probe = std::sync::Arc::clone(&mode);
        clean_cache.install_revoked_machine_probe(move |machine| {
            match mode_probe.load(std::sync::atomic::Ordering::SeqCst) {
                0 => Some(machine == pinned_machine || machine == dropped_machine),
                _ => Some(machine == pinned_machine),
            }
        });
        clean_cache.record(pinned_agent, pinned_machine, 1);
        clean_cache.record(dropped_agent, dropped_machine, 2);
        clean_cache.record(AgentId([0x33; 32]), MachineId([0x33; 32]), 3);
        assert!(clean_cache.stranger_pin_cap_refuses_unattested(dropped_agent));
        mode.store(1, std::sync::atomic::Ordering::SeqCst);
        clean_cache.refresh_unpinned_agent_for_test(dropped_agent);
        assert!(
            clean_cache.stranger_pin_cap_full(),
            "a clean answer does not have to free the pin cap"
        );
        assert!(
            !clean_cache.revoked_unpinned_contains(dropped_agent),
            "a clean answer removes the dropped-pair record"
        );
        assert!(
            !clean_cache.stranger_pin_cap_refuses_unattested(dropped_agent),
            "a clean answer leaves the refused set while the cap is full"
        );

        let mut open_cache = AuthenticatedMachineBindingCache::default();
        open_cache.set_stranger_pair_limit_for_test(2);
        let open_mode = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let open_probe = std::sync::Arc::clone(&open_mode);
        open_cache.install_revoked_machine_probe(move |machine| {
            match open_probe.load(std::sync::atomic::Ordering::SeqCst) {
                0 => Some(machine == pinned_machine || machine == dropped_machine),
                _ => Some(false),
            }
        });
        open_cache.record(pinned_agent, pinned_machine, 1);
        open_cache.record(dropped_agent, dropped_machine, 2);
        open_cache.record(AgentId([0x33; 32]), MachineId([0x33; 32]), 3);
        assert!(open_cache.stranger_pin_cap_refuses_unattested(dropped_agent));
        open_mode.store(1, std::sync::atomic::Ordering::SeqCst);
        open_cache.record(AgentId([0x44; 32]), MachineId([0x44; 32]), 4);
        assert!(
            !open_cache.stranger_pin_cap_full(),
            "a clean pin is released and the cap opens"
        );
        assert!(
            open_cache.revoked_unpinned_contains(dropped_agent),
            "opening the cap does not delete the dropped-pair record"
        );
        assert!(
            !open_cache.stranger_pin_cap_refuses_unattested(dropped_agent),
            "an open pin cap does not refuse a remembered dropped pair"
        );
    }

    /// Demotion keeps the newest revoked pairs. Contact recency is the
    /// accept order, not HashSet order.
    #[test]
    fn issue1659_demotion_keeps_the_newest_revoked_pairs() {
        for pattern in 0..12u8 {
            let mut cache = AuthenticatedMachineBindingCache::default();
            cache.set_stranger_pair_limit_for_test(2);
            let oldest = MachineId(tagged_id(0xA0, pattern, 1));
            let middle = MachineId(tagged_id(0xA0, pattern, 2));
            let newest = MachineId(tagged_id(0xA0, pattern, 3));
            cache.install_revoked_machine_probe(move |machine| {
                Some(machine == oldest || machine == middle || machine == newest)
            });
            let peer = AgentId(tagged_id(0x50, pattern, 0));
            cache.set_relationship_peer(peer, true);
            cache.record(peer, oldest, 1);
            cache.record(peer, middle, 2);
            cache.record(peer, newest, 3);
            cache.set_relationship_peer(peer, false);
            let kept = cache.machines_accepted_for(&peer);
            assert!(
                kept.contains(&middle) && kept.contains(&newest),
                "pattern {pattern} must keep the newest revoked pairs on demotion"
            );
            assert!(
                !kept.contains(&oldest),
                "pattern {pattern} must drop the oldest revoked pair on demotion"
            );
            assert!(
                cache.attribution_stranger_pairs_len() <= 2,
                "demotion must not pass the stranger cap"
            );
        }
    }

    /// One revocation snapshot per eviction. A probe that answers unknown
    /// and then revoked must not evict the pair on the second answer.
    #[test]
    fn issue1659_eviction_uses_one_revocation_snapshot() {
        let mut cache = AuthenticatedMachineBindingCache::default();
        cache.set_stranger_pair_limit_for_test(2);
        let target = MachineId([0x11; 32]);
        let victim = AgentId([0x21; 32]);
        cache.record(victim, target, 1);
        cache.record(AgentId([0x22; 32]), MachineId([0x22; 32]), 2);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_probe = std::sync::Arc::clone(&calls);
        cache.install_revoked_machine_probe(move |machine| {
            if machine != target {
                return Some(false);
            }
            let seen = calls_probe.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if seen == 0 {
                None
            } else {
                Some(true)
            }
        });
        cache.record(AgentId([0x23; 32]), MachineId([0x23; 32]), 3);
        assert!(
            cache.machines_accepted_for(&victim).contains(&target),
            "an unknown answer in the eviction snapshot must keep the pair"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "eviction probes each machine once"
        );
    }

    /// When the stranger pin cap is full, an unlinked stranger DM is still
    /// accepted. A stranger whose revoked pair was dropped is refused and
    /// counted, and that sender's unattested ACK leaves a registered waiter
    /// pending. An unattested ACK from an unlinked stranger completes its
    /// waiter. A Trusted contact who has a revoked pair that could not be
    /// pinned is still accepted.
    #[tokio::test]
    async fn issue1659_full_stranger_pin_cap_refuses_unattested_stranger() {
        let contact = test_keypair();
        let mut harness = make_inbox_harness(&contact, None, None).await;
        let unlinked = test_keypair();
        let open = payload_message(&harness, &unlinked, MachineId([0xE0; 32]), 0xE0);
        harness
            .pipeline
            .handle_incoming(open, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("an unlinked stranger is accepted while the pin cap is open")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, unlinked.agent_id());
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            0,
            "an open pin cap must not count a refusal"
        );

        let dropped = test_keypair();
        let pinned_machine = MachineId([0xA0; 32]);
        let dropped_machine = MachineId([0xB0; 32]);
        {
            let mut cache = harness
                .pipeline
                .authenticated_machine_bindings
                .write()
                .await;
            cache.set_stranger_pair_limit_for_test(2);
            let dropped_id = dropped.agent_id();
            cache.install_revoked_machine_probe(move |machine| {
                Some(machine == pinned_machine || machine == dropped_machine)
            });
            cache.record(AgentId([0x40; 32]), pinned_machine, 1);
            cache.record(dropped_id, dropped_machine, 2);
            cache.record(AgentId([0x41; 32]), MachineId([0x41; 32]), 3);
            assert!(
                cache.stranger_pin_cap_refuses_unattested(dropped_id),
                "the dropped revoked pair must be the refusal"
            );
            assert!(!cache.stranger_pin_cap_refuses_unattested(unlinked.agent_id()));
        }
        let again = payload_message(&harness, &unlinked, MachineId([0xE1; 32]), 0xE1);
        harness
            .pipeline
            .handle_incoming(again, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("an unlinked stranger is accepted when the pin cap is full")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, unlinked.agent_id());
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            0,
            "an unlinked stranger must not move incoming_dropped_revoked"
        );
        {
            let mut cache = harness
                .pipeline
                .authenticated_machine_bindings
                .write()
                .await;
            cache.record(dropped.agent_id(), MachineId([0xEE; 32]), 40);
            assert!(
                cache.stranger_pin_cap_refuses_unattested(dropped.agent_id()),
                "a clean retained machine must not clear the dropped revoked pair"
            );
        }
        let dropped_message = payload_message(&harness, &dropped, MachineId([0xEE; 32]), 0xE2);
        harness
            .pipeline
            .handle_incoming(
                dropped_message,
                false,
                crate::dm::DmAckIngress::Subscription,
            )
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "a dropped revoked pair must count one unattested refusal"
        );
        assert_eq!(
            harness
                .pipeline
                .dm
                .incoming_dropped_attribution_overflow_for_test(),
            1,
            "the refusal also increments the internal overflow counter"
        );
        let mut dropped_waiter = harness.pipeline.inflight.register(
            [0xE3; 16],
            dropped.agent_id(),
            Some(MachineId([0xEE; 32])),
        );
        let dropped_ack = unattested_ack_message(&harness, &dropped, MachineId([0xEE; 32]), 0xE3);
        harness
            .pipeline
            .handle_incoming(dropped_ack, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert!(
            matches!(
                dropped_waiter.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "a full-cap ACK from the dropped pair must leave the waiter pending"
        );
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            2,
            "an unattested ACK from the dropped pair is counted the same way"
        );
        let mut unlinked_waiter = harness.pipeline.inflight.register(
            [0xE5; 16],
            unlinked.agent_id(),
            Some(MachineId([0xE5; 32])),
        );
        let unlinked_ack = unattested_ack_message(&harness, &unlinked, MachineId([0xE5; 32]), 0xE5);
        harness
            .pipeline
            .handle_incoming(unlinked_ack, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert!(
            unlinked_waiter.try_recv().is_ok(),
            "an unattested ACK from an unlinked stranger completes its waiter while the cap is full"
        );
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            2,
            "an unlinked stranger ACK must not move incoming_dropped_revoked"
        );
        let contact_revoked = MachineId([0xC0; 32]);
        let contact_claim = MachineId([0xC1; 32]);
        {
            let mut cache = harness
                .pipeline
                .authenticated_machine_bindings
                .write()
                .await;
            cache.install_revoked_machine_probe(move |machine| {
                Some(
                    machine == pinned_machine
                        || machine == dropped_machine
                        || machine == contact_revoked,
                )
            });
            cache.record(contact.agent_id(), contact_revoked, 50);
            cache.record(contact.agent_id(), contact_claim, 51);
            assert!(
                cache.stranger_pin_cap_full(),
                "the contact's revoked pair must not open the pin cap"
            );
            assert!(
                cache.revoked_unpinned_contains(contact.agent_id()),
                "the trusted contact has a revoked pair that could not be pinned"
            );
            assert_eq!(
                cache
                    .peek(&contact.agent_id())
                    .map(|binding| binding.machine_id),
                Some(contact_claim),
                "the contact DM claims the retained clean machine"
            );
        }
        let contact_message = payload_message(&harness, &contact, contact_claim, 0xE4);
        harness
            .pipeline
            .handle_incoming(
                contact_message,
                false,
                crate::dm::DmAckIngress::Subscription,
            )
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("a contact unattested DM is still accepted")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, contact.agent_id());
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            2,
            "a trusted contact with a revoked pair is not refused for the pin cap"
        );
    }

    /// A DM whose originating MACHINE is revoked (but whose agent-id is clean)
    /// MUST be dropped and counted — issue #184, bringing EP3 to machine-id
    /// parity with the raw-QUIC direct path (`direct::inbound_peer_revoked`)
    /// and EP1/EP2. The revocation is applied via the real `verify_and_insert`
    /// receive path with a valid machine self-revocation, so this fails if the
    /// machine-revocation half of the EP3 gate regresses.
    #[test]
    fn machine_revoked_sender_dm_is_dropped_and_counted() {
        let dm = DirectMessaging::new();

        // A foreign machine self-revokes its own machine-id (valid authority).
        let machine_kp = MachineKeypair::generate().expect("machine keygen");
        let revoked_machine = machine_kp.machine_id();
        let now = now_unix_ms() / 1000;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(revoked_machine),
            machine_kp.public_key(),
            machine_kp.secret_key(),
            now,
            Some("compromised hardware".to_string()),
        )
        .expect("sign machine self-revocation");
        let mut set = RevocationSet::new();
        set.verify_and_insert(record, None)
            .expect("machine self-revocation verifies and inserts");

        // A clean (non-revoked) agent on the revoked machine is still dropped —
        // the machine revocation is decisive, not the agent revocation.
        let clean_agent = test_keypair().agent_id();
        let before = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert!(
            drop_if_sender_revoked(&dm, &set, &clean_agent, &revoked_machine),
            "a DM from a machine-revoked (agent-clean) sender must be dropped (#184)"
        );
        let after = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert_eq!(
            after,
            before + 1,
            "dropping a machine-revoked DM must increment incoming_dropped_revoked"
        );
    }

    // ── Envelope size limits ──────────────────────────────────────────

    #[test]
    fn envelope_from_wire_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        let result = DmEnvelope::from_wire_bytes(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn envelope_from_wire_bytes_rejects_garbage() {
        let garbage = vec![0xFF, 0xFE, 0xFD];
        let result = DmEnvelope::from_wire_bytes(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn envelope_from_wire_bytes_rejects_empty() {
        let result = DmEnvelope::from_wire_bytes(&[]);
        assert!(result.is_err());
    }

    // ── Wire round-trip ───────────────────────────────────────────────

    #[test]
    fn envelope_wire_roundtrip() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        let wire = envelope.to_wire_bytes().expect("to_wire_bytes");
        let decoded = DmEnvelope::from_wire_bytes(&wire).expect("from_wire_bytes");
        assert_eq!(decoded.sender_agent_id, envelope.sender_agent_id);
        assert_eq!(decoded.recipient_agent_id, envelope.recipient_agent_id);
        assert_eq!(decoded.request_id, envelope.request_id);
        assert_eq!(decoded.protocol_version, envelope.protocol_version);
    }

    // ── Dedupe key uniqueness ─────────────────────────────────────────

    #[test]
    fn dedupe_key_differs_for_different_request_ids() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let e1 = make_unsigned_envelope(&sender_kp, &recipient_id);
        let mut e2 = make_unsigned_envelope(&sender_kp, &recipient_id);
        e2.request_id = [99u8; 16];

        assert_ne!(e1.dedupe_key(), e2.dedupe_key());
    }

    #[test]
    fn dedupe_key_same_for_same_request_id() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let e1 = make_unsigned_envelope(&sender_kp, &recipient_id);
        let e2 = make_unsigned_envelope(&sender_kp, &recipient_id);

        assert_eq!(e1.dedupe_key(), e2.dedupe_key());
    }

    #[test]
    fn dedupe_key_differs_for_different_senders() {
        let sender1 = test_keypair();
        let sender2 = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let e1 = make_unsigned_envelope(&sender1, &recipient_id);
        let e2 = make_unsigned_envelope(&sender2, &recipient_id);

        assert_ne!(e1.dedupe_key(), e2.dedupe_key());
    }

    // ── Protocol version enforcement ──────────────────────────────────

    #[test]
    fn envelope_future_version_detected() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        envelope.protocol_version = DM_PROTOCOL_VERSION + 10;

        assert!(envelope.protocol_version > DM_PROTOCOL_VERSION);
    }

    // ── Inbox topic name consistency ──────────────────────────────────

    #[test]
    fn inbox_topic_is_agent_specific_and_matches_raw_topic_id() {
        let id1: [u8; 32] = [1u8; 32];
        let id2: [u8; 32] = [2u8; 32];
        let agent1 = AgentId(id1);
        let agent2 = AgentId(id2);

        let topic1 = DmInboxService::inbox_topic_name(&agent1);
        let topic2 = DmInboxService::inbox_topic_name(&agent2);

        assert_ne!(topic1, topic2);
        assert!(topic1.starts_with(DM_INBOX_TOPIC_NAME_PREFIX));
        assert_eq!(
            topic1,
            format!(
                "{DM_INBOX_TOPIC_NAME_PREFIX}{}",
                hex::encode(dm_inbox_topic(&agent1).to_bytes())
            )
        );
    }

    // ── Typed payload route matching ──────────────────────────────────

    #[test]
    fn typed_payload_route_matches_prefix() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<DmTypedPayload>(1);
        let route = DmTypedPayloadRoute {
            durable_completion: false,
            prefix: b"x0x-exec-v1\0".to_vec(),
            sender: tx,
            validator: None,
        };
        let payload = b"x0x-exec-v1\0some-command".to_vec();
        assert!(payload.starts_with(&route.prefix));
    }

    #[test]
    fn typed_payload_route_no_match_for_different_prefix() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<DmTypedPayload>(1);
        let route = DmTypedPayloadRoute {
            durable_completion: false,
            prefix: b"x0x-exec-v1\0".to_vec(),
            sender: tx,
            validator: None,
        };
        let payload = b"x0x-other-stuff".to_vec();
        assert!(!payload.starts_with(&route.prefix));
    }

    #[tokio::test]
    async fn full_typed_route_leaves_v1_request_unclaimed_for_retry() {
        let sender = test_keypair();
        let machine = MachineId([0xD9; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let (tx, mut rx) = mpsc::channel::<DmTypedPayload>(1);
        harness.pipeline.typed_payload_routes = vec![DmTypedPayloadRoute {
            durable_completion: false,
            prefix: b"test-route\n".to_vec(),
            sender: tx.clone(),
            validator: None,
        }];
        tx.try_send(DmTypedPayload {
            sender: sender.agent_id(),
            machine_id: machine,
            payload: b"occupied".to_vec(),
            verified: true,
            trust_decision: Some(TrustDecision::Accept),
            received_at_unix_ms: now_unix_ms(),
            request_id: [0; 16],
            completion: None,
        })
        .expect("fill route");

        let payload = b"test-route\npredecessor".to_vec();
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x73,
            DM_PROTOCOL_V1,
            payload.clone(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);
        let key = envelope.dedupe_key();
        let mut ack_subscription = watch_acks_to(&harness, &sender).await;
        harness
            .pipeline
            .handle_payload(
                envelope.clone(),
                match envelope.body.clone() {
                    DmBody::Payload(p) => p,
                    _ => panic!("payload"),
                },
                machine,
                PayloadOrigin::Retained,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;
        assert!(
            harness.pipeline.cache.lookup(&key).is_none(),
            "a full route must not be cached as Accepted or ACKed"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), ack_subscription.recv())
                .await
                .is_err(),
            "a full route must withhold its application ACK"
        );
        assert_eq!(rx.try_recv().expect("occupied slot").request_id, [0; 16]);
        harness
            .pipeline
            .handle_payload(
                envelope.clone(),
                match envelope.body {
                    DmBody::Payload(p) => p,
                    _ => panic!("payload"),
                },
                machine,
                PayloadOrigin::Retained,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;
        assert_eq!(rx.try_recv().expect("retry delivered").payload, payload);
        assert!(harness.pipeline.cache.lookup(&key).is_some());
        assert!(matches!(
            next_ack_outcome(&mut ack_subscription).await,
            DmAckOutcome::Accepted
        ));
    }

    #[tokio::test]
    async fn signed_predecessor_envelope_still_matches_typed_route() {
        let signer = test_keypair();
        let node = Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub = PubSubManager::new(node, Arc::new(SigningContext::from_keypair(&signer)))
            .expect("signed pubsub");
        let event = serde_json::json!({
            "event": "join_request_created",
            "group_id": "g",
            "request_id": "r",
            "requester_agent_id": hex::encode(signer.agent_id().as_bytes()),
            "message": null,
            "ts": 1,
        });
        let wire = pubsub
            .publish_and_get_envelope(
                "x0x.test.predecessor".to_string(),
                Bytes::from(serde_json::to_vec(&event).expect("event JSON")),
            )
            .await
            .expect("publish signed envelope")
            .expect("v2 wire bytes");
        let mut payload = GROUP_PREDECESSOR_RELAY_DM_PREFIX.to_vec();
        payload.extend_from_slice(&wire);
        let (tx, mut rx) = mpsc::channel(1);
        let routes = vec![DmTypedPayloadRoute {
            prefix: GROUP_PREDECESSOR_RELAY_DM_PREFIX.to_vec(),
            sender: tx,
            durable_completion: false,
            validator: Some(crate::server::valid_predecessor_relay_typed_dm),
        }];
        assert_eq!(
            InboxPipeline::try_route_typed_payload(
                &routes,
                &DirectMessaging::new(),
                DmTypedPayload {
                    sender: signer.agent_id(),
                    machine_id: MachineId([0x74; 32]),
                    payload: payload.clone(),
                    verified: true,
                    trust_decision: Some(TrustDecision::Accept),
                    received_at_unix_ms: now_unix_ms(),
                    request_id: [0x74; 16],
                    completion: None,
                },
            ),
            TypedRouteOutcome::Recognized
        );
        assert_eq!(
            rx.try_recv().expect("signed predecessor routed").payload,
            payload
        );

        let wrong_event = pubsub
            .publish_and_get_envelope(
                "x0x.test.predecessor".to_string(),
                Bytes::from_static(br#"{"event":"member_added","group_id":"g","revision":1,"actor":"a","agent_id":"b","display_name":null}"#),
            )
            .await
            .expect("publish signed non-predecessor")
            .expect("v2 wire bytes");
        let mut ordinary = GROUP_PREDECESSOR_RELAY_DM_PREFIX.to_vec();
        ordinary.extend_from_slice(&wrong_event);
        assert_eq!(
            InboxPipeline::try_route_typed_payload(
                &routes,
                &DirectMessaging::new(),
                DmTypedPayload {
                    sender: signer.agent_id(),
                    machine_id: MachineId([0x74; 32]),
                    payload: ordinary,
                    verified: true,
                    trust_decision: Some(TrustDecision::Accept),
                    received_at_unix_ms: now_unix_ms(),
                    request_id: [0x75; 16],
                    completion: None,
                },
            ),
            TypedRouteOutcome::RejectedPrefix,
            "signed non-predecessor event must remain an ordinary DM"
        );
        assert!(rx.try_recv().is_err());
    }

    // ── DmInboxConfig ─────────────────────────────────────────────────

    #[test]
    fn dm_inbox_config_default_has_empty_routes() {
        let config = DmInboxConfig::default();
        assert!(!config.silent_reject, "silent_reject defaults to false");
        assert!(config.typed_payload_routes.is_empty());
    }

    #[test]
    fn dm_inbox_config_with_route_adds_entry() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let config = DmInboxConfig::default().with_typed_payload_route(b"x0x-exec-v1\x00", tx);
        assert_eq!(config.typed_payload_routes.len(), 1);
        assert_eq!(config.typed_payload_routes[0].prefix, b"x0x-exec-v1\x00");
    }

    #[test]
    fn dm_inbox_config_with_multiple_routes() {
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let config = DmInboxConfig::default()
            .with_typed_payload_route(b"prefix-a\x00", tx1)
            .with_typed_payload_route(b"prefix-b\x00", tx2);
        assert_eq!(config.typed_payload_routes.len(), 2);
    }

    #[test]
    fn dm_inbox_config_debug_does_not_panic() {
        let config = DmInboxConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("silent_reject"));
        assert!(debug.contains("typed_payload_routes"));
    }

    #[tokio::test]
    async fn production_optout_service_joins_inbox_but_not_legacy_bus() {
        let inbox = spawn_inbox_service_for_bus_control(true).await;
        assert!(
            inbox
                .pubsub
                .is_topic_subscribed(inbox.service.topic())
                .await
        );
        assert!(!inbox.pubsub.is_topic_subscribed(DM_BUS_TOPIC).await);
        assert!(inbox.pubsub.skip_legacy_dm_bus());
    }

    #[tokio::test]
    async fn production_default_service_keeps_legacy_bus_subscription() {
        let inbox = spawn_inbox_service_for_bus_control(false).await;
        assert!(
            inbox
                .pubsub
                .is_topic_subscribed(inbox.service.topic())
                .await
        );
        assert!(inbox.pubsub.is_topic_subscribed(DM_BUS_TOPIC).await);
        assert!(!inbox.pubsub.skip_legacy_dm_bus());
    }

    #[tokio::test]
    async fn production_optout_reverse_ack_prewarm_keeps_bus_unsubscribed() {
        let inbox = spawn_inbox_service_for_bus_control(true).await;
        let peer = AgentId([0xAB; 32]);
        warm_reverse_ack_topics(&inbox.pubsub, &inbox.self_agent_id, &peer).await;
        assert!(
            inbox
                .pubsub
                .is_topic_subscribed(&DmInboxService::inbox_topic_name(&peer))
                .await
        );
        assert!(!inbox.pubsub.is_topic_subscribed(DM_BUS_TOPIC).await);
    }

    #[tokio::test]
    async fn production_optout_durable_ack_keeps_targeted_and_direct_routes() {
        let sender = test_keypair();
        let machine = MachineId([0xDB; 32]);
        let (tx, mut direct_rx) = mpsc::unbounded_channel();
        let hedge = Arc::new(RecordingDirectHedge {
            tx,
            outcome: DirectAckHedgeOutcome::Sent,
        });
        let mut harness =
            make_inbox_harness_with_hedge_options(&sender, Some(machine), None, Some(hedge), true)
                .await;
        let _history = attach_history(&mut harness);
        let mut bus = harness
            .pipeline
            .pubsub
            .subscribe(DM_BUS_TOPIC.to_string())
            .await;
        let mut targeted = harness
            .pipeline
            .pubsub
            .subscribe_topic_id(
                DmInboxService::inbox_topic_name(&sender.agent_id()),
                dm_inbox_topic(&sender.agent_id()),
            )
            .await;

        harness
            .pipeline
            .publish_ack_for_protocol(
                sender.agent_id(),
                [0xDB; 16],
                DmAckOutcome::Accepted,
                DM_PROTOCOL_DURABLE_ACK,
                false,
            )
            .await
            .expect("optout durable ACK schedules");

        let targeted_message = tokio::time::timeout(Duration::from_secs(5), targeted.recv())
            .await
            .expect("targeted ACK route must receive the envelope")
            .expect("targeted subscription stays open");
        let targeted_envelope = DmEnvelope::from_wire_bytes(&targeted_message.payload)
            .expect("targeted payload decodes");
        assert_eq!(targeted_envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
        let (_, direct_bytes) = tokio::time::timeout(Duration::from_secs(5), direct_rx.recv())
            .await
            .expect("Direct hedge must be called")
            .expect("Direct hedge channel stays open");
        let direct_envelope =
            DmEnvelope::from_wire_bytes(&direct_bytes).expect("Direct payload decodes");
        assert_eq!(direct_envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), bus.recv())
                .await
                .is_err(),
            "optout durable ACK must not publish on the compatibility bus"
        );
    }

    // ── Unverified drop path instrumentation (issue #296) ─────────────

    /// The REAL drop site for unverified pubsub messages is dm_inbox.rs, NOT
    /// server/mod.rs. The typed-payload handler in server/mod.rs only fires
    /// after the inbox pipeline has already verified and dispatched the message
    /// — typed.verified is hardcoded to true there, so any !typed.verified
    /// check in server/mod.rs is unreachable dead code. This test is the
    /// revert-guard: if the counter call is removed from handle_incoming the
    /// test fails even though the dead server-layer check is still in place.
    #[tokio::test]
    async fn unverified_pubsub_message_increments_signature_failed_counter() {
        let sender = test_keypair();
        let harness = make_inbox_harness(&sender, None, None).await;
        let dm = Arc::clone(&harness.pipeline.dm);

        let msg = PubSubMessage {
            topic: "test-inbox-topic".to_string(),
            payload: bytes::Bytes::new(),
            sender: None,
            sender_public_key: None,
            verified: false,
            trust_level: None,
            raw_envelope: None,
        };

        let before = dm.diagnostics_snapshot().stats.incoming_signature_failed;
        harness
            .pipeline
            .handle_incoming(msg, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let after = dm.diagnostics_snapshot().stats.incoming_signature_failed;

        assert_eq!(
            after - before,
            1,
            "unverified PubSubMessage must increment incoming_signature_failed \
             at the real drop site in dm_inbox (issue #296)"
        );
    }

    // ── #927: an unattested gossip DM machine claim never rebinds ─────────

    /// A signed v2 envelope WITH a valid origin attestation from `machine`.
    fn attested_durable_payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: &MachineKeypair,
        request_byte: u8,
    ) -> PubSubMessage {
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            harness,
            sender,
            machine.machine_id(),
            request_byte,
            DM_PROTOCOL_DURABLE_ACK,
            b"927 attested".to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(machine).expect("machine attest");
        envelope.origin_attestation = Some(attestation);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    /// #927: agent A (holding its own key, no attestation, no authenticated
    /// binding) claims machine M2. The v2 path is the one that registers the
    /// sender in DirectMessaging, which `connect_to_agent` copies into the
    /// discovery cache — so the claim must leave A's connected machine
    /// exactly as it was, whether A was bound to M1 or not bound at all.
    /// The message itself is still delivered, annotated unverified, so a
    /// legacy (pre-#213) sender is not black-holed.
    #[tokio::test]
    async fn unattested_claim_never_rebinds_but_is_delivered_unverified() {
        let m1 = MachineId([0x91; 32]);
        let m2 = MachineId([0x92; 32]);
        for bound_to_m1 in [true, false] {
            let sender = test_keypair();
            // No authenticated binding: only the sender claim is available.
            let mut harness = make_inbox_harness(&sender, None, None).await;
            let _service = attach_history(&mut harness);
            if bound_to_m1 {
                harness
                    .pipeline
                    .dm
                    .mark_connected(sender.agent_id(), m1)
                    .await;
            }
            let before = harness.pipeline.dm.get_machine_id(&sender.agent_id()).await;
            assert_eq!(before, bound_to_m1.then_some(m1));

            let message = durable_payload_message(&harness, &sender, m2, 0x27, b"927 claim");
            harness
                .pipeline
                .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
                .await;

            let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("unattested DM must still be delivered")
                .expect("delivery stream closed");
            assert_eq!(delivered.sender, sender.agent_id());
            assert_eq!(delivered.payload, b"927 claim".to_vec());
            assert!(
                !delivered.verified,
                "an unattested machine claim must be annotated unverified"
            );
            assert_eq!(
                harness.pipeline.dm.get_machine_id(&sender.agent_id()).await,
                before,
                "an unattested claim must not move A's connected machine \
                 (bound_to_m1 = {bound_to_m1})"
            );
            assert_eq!(
                harness.pipeline.dm.lookup_agent(&m2).await,
                None,
                "the claimed machine must not be mapped to A"
            );
        }
    }

    /// #927 counterpart: an ATTESTED move from M1 to M2 still updates A's
    /// connected machine, and is delivered verified. Without this the gate
    /// could pass by never registering anyone.
    #[tokio::test]
    async fn attested_move_still_rebinds_and_is_delivered_verified() {
        let sender = test_keypair();
        let m1 = MachineId([0x93; 32]);
        let m2 = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let _service = attach_history(&mut harness);
        harness
            .pipeline
            .dm
            .mark_connected(sender.agent_id(), m1)
            .await;

        let message = attested_durable_payload_message(&harness, &sender, &m2, 0x28);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("attested DM delivery timeout")
            .expect("delivery stream closed");
        assert!(delivered.verified, "an attested origin is verified");
        assert_eq!(
            harness.pipeline.dm.get_machine_id(&sender.agent_id()).await,
            Some(m2.machine_id()),
            "an attested move must update A's connected machine"
        );
    }

    // ── ADR 0116 slice C: the ADR 0030 receipt rule under dm_recording ────

    use crate::history::DmRecording;

    fn attach_history_with(
        harness: &mut InboxHarness,
        dm_recording: DmRecording,
    ) -> crate::history::HistoryService {
        let config = crate::history::HistoryConfig {
            db_path: Some(harness._tempdir.path().join("history.db")),
            dm_recording,
            ..crate::history::HistoryConfig::daemon_default()
        };
        let service = crate::history::HistoryService::start(&config, harness._tempdir.path())
            .expect("history service");
        harness.pipeline.history = Some(service.handle());
        service
    }

    /// An inbox process restart: the in-memory replay cache is lost and
    /// history reopens over the same database, under `dm_recording`.
    async fn restart_inbox(
        harness: &mut InboxHarness,
        service: crate::history::HistoryService,
        dm_recording: DmRecording,
    ) -> crate::history::HistoryService {
        harness.pipeline.history = None;
        service.shutdown().await;
        harness.pipeline.cache = Arc::new(crate::dm::RecentDeliveryCache::with_defaults());
        attach_history_with(harness, dm_recording)
    }

    /// One signed v2 envelope, reused for every retry so the retry carries
    /// the same bytes, as a real sender's resend does.
    fn signed_durable_envelope(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: MachineId,
        request_byte: u8,
        payload: &[u8],
    ) -> DmEnvelope {
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            harness,
            sender,
            machine,
            request_byte,
            DM_PROTOCOL_DURABLE_ACK,
            payload.to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, sender);
        envelope
    }

    async fn deliver_durable(
        harness: &InboxHarness,
        envelope: DmEnvelope,
        payload: &[u8],
        machine: MachineId,
        sender: &AgentKeypair,
    ) -> DurableAckDecision {
        harness
            .pipeline
            .handle_payload_durable(
                envelope,
                payload.to_vec(),
                TrustDecision::Accept,
                machine,
                true,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await
    }

    async fn assert_no_ack(acks: &mut Subscription) {
        assert!(
            tokio::time::timeout(Duration::from_millis(300), acks.recv())
                .await
                .is_err(),
            "no ACK of any kind (durable, downgraded v1 or typed refusal) may be published"
        );
    }

    fn counter(harness: &InboxHarness, pick: fn(&crate::history::HistoryCounters) -> u64) -> u64 {
        pick(
            &harness
                .pipeline
                .history
                .as_ref()
                .expect("history handle")
                .counters(),
        )
    }

    fn receipts_withheld(c: &crate::history::HistoryCounters) -> u64 {
        c.policy_durable_receipt_withheld_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn dms_suppressed(c: &crate::history::HistoryCounters) -> u64 {
        c.policy_suppressed_dm_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// ADR 0116 §3 / ADR 0030 (Validation "Receipts"): with `dm_recording =
    /// "ephemeral"` a NEW generic durable DM gets no durable ACK, no
    /// downgraded v1 ACK and no typed refusal, and it is not dispatched.
    /// The local reason is counted and nothing is committed or cached.
    #[tokio::test]
    async fn adr0116_c_new_durable_dm_is_withheld_before_dispatch() {
        let sender = test_keypair();
        let machine = MachineId([0xE1; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history_with(&mut harness, DmRecording::Ephemeral);
        let mut acks = watch_acks_to(&harness, &sender).await;
        let envelope = signed_durable_envelope(&harness, &sender, machine, 0xE1, b"durable hello");

        let decision =
            deliver_durable(&harness, envelope, b"durable hello", machine, &sender).await;

        assert_eq!(
            decision,
            DurableAckDecision::Withheld("history_policy_ephemeral")
        );
        assert_no_delivery(&mut harness.receiver).await;
        assert_no_ack(&mut acks).await;
        let history = harness.pipeline.history.clone().expect("history handle");
        assert!(committed_rows(&history, &sender, 0xE1).is_empty());
        assert_eq!(counter(&harness, receipts_withheld), 1);
        assert!(
            harness
                .pipeline
                .cache
                .lookup(&crate::dm::DedupeKey::new(
                    *sender.agent_id().as_bytes(),
                    [0xE1; 16]
                ))
                .is_none(),
            "a withheld request leaves no completion behind"
        );
    }

    /// The same, through the full inbox entry point: no other branch of the
    /// pipeline delivers or acknowledges the suppressed DM.
    #[tokio::test]
    async fn adr0116_c_full_inbox_path_withholds_a_new_durable_dm() {
        let sender = test_keypair();
        let machine = MachineId([0xE2; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history_with(&mut harness, DmRecording::Ephemeral);
        let mut acks = watch_acks_to(&harness, &sender).await;
        let message = durable_payload_message(&harness, &sender, machine, 0xE2, b"durable hello");
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert_no_ack(&mut acks).await;
        assert_eq!(counter(&harness, receipts_withheld), 1);
    }

    /// Validation "Receipts": retries and a restart do not turn a
    /// suppressed DM into a receipt or a dispatch.
    #[tokio::test]
    async fn adr0116_c_withheld_dm_stays_withheld_on_retry_and_restart() {
        let sender = test_keypair();
        let machine = MachineId([0xE3; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let service = attach_history_with(&mut harness, DmRecording::Ephemeral);
        let envelope = signed_durable_envelope(&harness, &sender, machine, 0xE3, b"durable hello");
        for attempt in 0..2 {
            let decision = deliver_durable(
                &harness,
                envelope.clone(),
                b"durable hello",
                machine,
                &sender,
            )
            .await;
            assert_eq!(
                decision,
                DurableAckDecision::Withheld("history_policy_ephemeral"),
                "attempt {attempt}"
            );
        }
        assert_eq!(counter(&harness, receipts_withheld), 2);
        let _service = restart_inbox(&mut harness, service, DmRecording::Ephemeral).await;
        let decision =
            deliver_durable(&harness, envelope, b"durable hello", machine, &sender).await;
        assert_eq!(
            decision,
            DurableAckDecision::Withheld("history_policy_ephemeral"),
            "after restart"
        );
        assert_no_delivery(&mut harness.receiver).await;
        let history = harness.pipeline.history.clone().expect("history handle");
        assert!(committed_rows(&history, &sender, 0xE3).is_empty());
    }

    /// Ruling Q4, an interpretation of the Validation cell "a pre-policy
    /// committed duplicate without fabricating a new commit". A DM
    /// committed before the policy was set already has its required commit,
    /// so it is not "suppressed". After a restart under `ephemeral`, its
    /// retry takes main's Exact path: re-dispatched (at-least-once, ADR 0030
    /// §1) and re-ACKed v2 from the existing row. No new row is written and
    /// no commit is attempted.
    #[tokio::test]
    async fn adr0116_c_pre_policy_committed_duplicate_keeps_mains_exact_path() {
        let sender = test_keypair();
        let machine = MachineId([0xE4; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let service = attach_history_with(&mut harness, DmRecording::Inherit);
        let envelope = signed_durable_envelope(&harness, &sender, machine, 0xE4, b"durable hello");
        let acked = DurableAckDecision::Acked {
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            accepted: true,
        };
        assert_eq!(
            deliver_durable(
                &harness,
                envelope.clone(),
                b"durable hello",
                machine,
                &sender
            )
            .await,
            acked,
            "committed before the policy"
        );
        tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("first dispatch")
            .expect("delivery stream");

        let _service = restart_inbox(&mut harness, service, DmRecording::Ephemeral).await;
        let mut acks = watch_acks_to(&harness, &sender).await;
        assert_eq!(
            deliver_durable(&harness, envelope, b"durable hello", machine, &sender).await,
            acked,
            "the pre-policy commit still backs a v2 receipt"
        );
        tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("Exact re-dispatch")
            .expect("delivery stream");
        assert_eq!(next_ack_outcome(&mut acks).await, DmAckOutcome::Accepted);
        let history = harness.pipeline.history.clone().expect("history handle");
        assert_eq!(
            committed_rows(&history, &sender, 0xE4).len(),
            1,
            "no new row"
        );
        assert_eq!(counter(&harness, receipts_withheld), 0);
        assert_eq!(
            counter(&harness, dms_suppressed),
            0,
            "no commit was attempted"
        );
    }

    /// Validation "Receipts": a typed durable route keeps its own receipt
    /// contract under the policy. Its durable effect lives in its own store.
    #[tokio::test]
    async fn adr0116_c_typed_durable_route_keeps_its_own_receipt() {
        let sender = test_keypair();
        let machine = MachineId([0xE5; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history_with(&mut harness, DmRecording::Ephemeral);
        let (tx, mut rx) = mpsc::channel::<DmTypedPayload>(8);
        harness.pipeline.typed_payload_routes = vec![DmTypedPayloadRoute {
            durable_completion: true,
            prefix: b"X0X-KV-DELTA-V1\n".to_vec(),
            sender: tx,
            validator: None,
        }];
        let handler = tokio::spawn(async move {
            if let Some(typed) = rx.recv().await {
                if let Some(done) = typed.completion {
                    let _ = done.send(Ok(DmTypedPayloadCompletion::Inserted));
                }
            }
        });
        let mut payload = b"X0X-KV-DELTA-V1\n".to_vec();
        payload.extend_from_slice(b"{\"k\":1}");
        let envelope = signed_durable_envelope(&harness, &sender, machine, 0xE5, &payload);
        let decision = deliver_durable(&harness, envelope, &payload, machine, &sender).await;
        handler.abort();
        assert_eq!(
            decision,
            DurableAckDecision::Acked {
                protocol_version: DM_PROTOCOL_DURABLE_ACK,
                accepted: true,
            }
        );
        assert_eq!(counter(&harness, receipts_withheld), 0);
    }

    /// Validation "Ephemeral paths": a non-durable (v1) DM is still
    /// delivered live and completes under v1, but nothing reaches history:
    /// no row, no FTS document and no projection after a restart.
    #[tokio::test]
    async fn adr0116_c_v1_dm_is_delivered_live_without_a_history_row() {
        let sender = test_keypair();
        let machine = MachineId([0xE6; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let service = attach_history_with(&mut harness, DmRecording::Ephemeral);
        let message = payload_message(&harness, &sender, machine, 0xE6);
        harness
            .pipeline
            .handle_incoming(message, false, crate::dm::DmAckIngress::Subscription)
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("v1 delivery timeout")
            .expect("v1 delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());
        assert!(harness
            .pipeline
            .cache
            .lookup(&crate::dm::DedupeKey::new(
                *sender.agent_id().as_bytes(),
                [0xE6; 16]
            ))
            .is_some_and(|cached| cached.protocol_version == DM_PROTOCOL_V1));
        let suppressed = counter(&harness, dms_suppressed);
        let _service = restart_inbox(&mut harness, service, DmRecording::Ephemeral).await;
        let history = harness.pipeline.history.clone().expect("history handle");
        assert_eq!(history.store().table_counts_for_tests(), (0, 0, 0));
        assert_eq!(suppressed, 1, "the suppressed DM is counted");
    }

    /// ADR 0116 §3: the ADR 0030 capability advert is unchanged. A node with
    /// history enabled advertises durable-ACK v2 even while its policy
    /// suppresses generic durable commits, so a strict v2 sender sees a
    /// timeout, not the 409 `recipient_ack_semantics_unavailable` refusal.
    #[tokio::test]
    async fn adr0116_c_v2_advert_is_unchanged_under_dm_ephemeral() {
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = crate::Agent::builder()
            .with_machine_key(dir.path().join("machine"))
            .with_agent_key_path(dir.path().join("agent"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
                bootstrap_nodes: vec![],
                port_mapping_enabled: false,
                mdns_enabled: false,
                ..Default::default()
            })
            .with_history(crate::history::HistoryConfig {
                enabled: true,
                db_path: Some(dir.path().join("history.db")),
                dm_recording: DmRecording::Ephemeral,
                ..crate::history::HistoryConfig::default()
            })
            .build()
            .await
            .expect("agent with an ephemeral DM policy");
        agent
            .start_dm_inbox(
                Arc::new(AgentKemKeypair::generate().expect("kem")),
                DmInboxConfig::default(),
            )
            .await
            .expect("inbox");
        let caps = agent.current_dm_capabilities();
        agent.shutdown().await;
        assert!(caps.gossip_inbox);
        assert_eq!(caps.max_protocol_version, DM_PROTOCOL_DURABLE_ACK);
    }
}
