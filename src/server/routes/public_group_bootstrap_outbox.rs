//! Durable signed-public group bootstrap outbox (ADR 0030 §5).
//!
//! When an authority adds a member to a SignedPublic group, that member needs
//! the committed roster snapshot before it can participate. Before this module
//! the snapshot was direct-sent fire-and-forget: a disconnected recipient
//! simply never got it, and nothing on the authority remembered that it owed
//! one.
//!
//! Here the send becomes an *obligation*. Adding the member writes a durable
//! obligation next to the roster commit, a background worker retries it on
//! exponential backoff, and the obligation is discharged only when the
//! recipient returns a v2 application ACK for that exact frontier. Restarting
//! the authority does not lose the debt, and — because the DM logical request
//! id is derived from the obligation key — a post-restart retry is the *same*
//! logical request, so the recipient re-ACKs rather than re-installing.
//!
//! ## Why the key is what it is
//!
//! An obligation is keyed by `(recipient, group, frontier, payload-digest)`,
//! realised as one blake3 binding digest. Every component is load-bearing:
//! dropping the recipient would let one member's ACK discharge another's debt;
//! dropping the frontier would let an ACK for an old snapshot silently satisfy
//! a newer one; dropping the payload digest would let the stored bytes drift
//! from the frontier they claim to carry.
//!
//! ## Structure
//!
//! The `save_` / `load_` / `replace_*_unlocked` shape and the dedicated
//! persistence lock deliberately mirror the ADR 0028 predecessor-relay outbox
//! in `named_groups.rs`. The two outboxes are unrelated in purpose; the
//! symmetry is so a reader who knows one can read the other.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate as x0x;
use crate::logging::LogHexId;
use crate::server::parse_agent_id_hex;
use crate::server::state::AppState;
use x0x::identity::AgentId;

use super::named_groups::{
    confirm_named_groups_durability, ensure_named_group_listeners, group_membership_lock,
    named_group_direct_delivery_config, now_millis_u64, persist_named_group_info,
    persist_named_groups_mutation, signed_public_bootstrap_snapshot,
    validate_public_group_bootstrap, write_named_groups_json_atomic, AtomicWriteOutcome,
    PublicGroupBootstrap, MAX_BOOTSTRAP_INSTALLED_GROUPS,
};

/// Strict typed-DM framing for a signed-public group bootstrap. The legacy
/// unprefixed JSON listener remains active for mixed-version inbound traffic;
/// this prefix is what opts a new sender into the durable application-ACK
/// boundary.
pub(in crate::server) const PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX: &[u8] =
    b"X0X-PUBLIC-GROUP-BOOTSTRAP-V2\n";

const PUBLIC_GROUP_BOOTSTRAP_OUTBOX_VERSION: u32 = 1;
const PUBLIC_GROUP_BOOTSTRAP_OUTBOX_MAX_ENTRIES: usize = 1024;
const PUBLIC_GROUP_BOOTSTRAP_RETRY_MAX_DELAY_MS: u64 = 60_000;
/// Key prefix shared by the obligation key and its DM logical request id.
const PUBLIC_GROUP_BOOTSTRAP_KEY_PREFIX: &str = "public-group-bootstrap:";

/// Directory-durable delivery obligation for one exact signed-public
/// membership frontier. `payload_digest` covers the canonical typed bytes,
/// while `key` additionally binds the intended recipient and that frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::server) struct PublicGroupBootstrapObligation {
    pub(in crate::server) key: String,
    recipient_hex: String,
    group_id: String,
    state_revision: u64,
    state_hash: String,
    payload_digest: String,
    payload: Vec<u8>,
    created_at_ms: u64,
    next_attempt_at_ms: u64,
    attempt_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicGroupBootstrapOutboxSidecar {
    version: u32,
    entries: Vec<PublicGroupBootstrapObligation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicGroupBootstrapWireVersion {
    StrictV2,
    LegacyV1,
}

/// Outcome of one delivery attempt.
///
/// The two variants are deliberately not interchangeable: only
/// `V2ApplicationAck` proves the recipient durably installed this frontier.
/// `LegacyV1Sent` is a transport receipt from a peer that cannot speak v2 at
/// all, so it reschedules — it is never completion.
#[derive(Debug)]
enum PublicGroupBootstrapDelivery {
    V2ApplicationAck(x0x::dm::DmReceipt),
    LegacyV1Sent(x0x::dm::DmReceipt),
}

// ---------------------------------------------------------------------------
// Key derivation and payload encoding
// ---------------------------------------------------------------------------

fn public_group_bootstrap_binding_digest(
    recipient_hex: &str,
    group_id: &str,
    state_revision: u64,
    state_hash: &str,
    payload_digest: &str,
) -> Result<String, String> {
    let binding = serde_json::to_vec(&(
        "public_group_bootstrap",
        recipient_hex,
        group_id,
        state_revision,
        state_hash,
        payload_digest,
    ))
    .map_err(|error| format!("failed to encode bootstrap delivery binding: {error}"))?;
    Ok(blake3::hash(&binding).to_hex().to_string())
}

/// The DM logical request id for an obligation: the first 16 bytes of the very
/// same binding digest the obligation is keyed by.
///
/// Same bytes, not merely derived from them — the obligation and the wire
/// request are one identity. That is what lets a v2 ACK be matched back to the
/// exact obligation it discharges, and what makes a retry after restart a
/// replay of one logical request rather than a second delivery.
fn public_group_bootstrap_request_id(
    obligation: &PublicGroupBootstrapObligation,
) -> Result<[u8; 16], String> {
    let digest = public_group_bootstrap_binding_digest(
        &obligation.recipient_hex,
        &obligation.group_id,
        obligation.state_revision,
        &obligation.state_hash,
        &obligation.payload_digest,
    )?;
    let bytes = hex::decode(&digest)
        .map_err(|error| format!("bootstrap binding digest is not hex: {error}"))?;
    let head = bytes
        .get(..16)
        .ok_or_else(|| "bootstrap binding digest is too short".to_string())?;
    let mut request_id = [0u8; 16];
    request_id.copy_from_slice(head);
    Ok(request_id)
}

/// Message-type tag carried inside the JSON body, shared with the legacy
/// unprefixed wire form so one decoder serves both.
const PUBLIC_GROUP_BOOTSTRAP_MESSAGE_TYPE: &str = "public_group_bootstrap";

fn encode_public_group_bootstrap_typed_payload(
    group: x0x::groups::GroupInfo,
) -> Result<Vec<u8>, String> {
    let encoded = serde_json::to_vec(&PublicGroupBootstrap {
        message_type: PUBLIC_GROUP_BOOTSTRAP_MESSAGE_TYPE.to_string(),
        group: Box::new(group),
    })
    .map_err(|error| format!("failed to serialize public-group bootstrap: {error}"))?;
    let mut payload = Vec::with_capacity(PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX.len() + encoded.len());
    payload.extend_from_slice(PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX);
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

/// Build the obligation for delivering `group`'s committed frontier to
/// `recipient`. `group` must already be a sanitized bootstrap snapshot.
pub(in crate::server) fn prepare_public_group_bootstrap_obligation(
    recipient: AgentId,
    group: x0x::groups::GroupInfo,
) -> Result<PublicGroupBootstrapObligation, String> {
    let recipient_hex = hex::encode(recipient.as_bytes());
    let group_id = group.stable_group_id().to_string();
    let state_revision = group.state_revision;
    let state_hash = group.state_hash.clone();
    let payload = encode_public_group_bootstrap_typed_payload(group)?;
    let payload_digest = blake3::hash(&payload).to_hex().to_string();
    let binding_digest = public_group_bootstrap_binding_digest(
        &recipient_hex,
        &group_id,
        state_revision,
        &state_hash,
        &payload_digest,
    )?;
    let now_ms = now_millis_u64();
    Ok(PublicGroupBootstrapObligation {
        key: format!("{PUBLIC_GROUP_BOOTSTRAP_KEY_PREFIX}{binding_digest}"),
        recipient_hex,
        group_id,
        state_revision,
        state_hash,
        payload_digest,
        payload,
        created_at_ms: now_ms,
        next_attempt_at_ms: now_ms,
        attempt_count: 0,
    })
}

/// The obligation a membership add owes its new member, or `None` when the
/// group's confidentiality does not use bootstrap delivery at all.
///
/// The SignedPublic test lives here rather than at the call site so the roster
/// handler cannot accidentally disagree with the reconciler about which groups
/// carry bootstrap debt.
pub(in crate::server) fn public_group_bootstrap_obligation_for_add(
    recipient: AgentId,
    group: &x0x::groups::GroupInfo,
) -> Result<Option<PublicGroupBootstrapObligation>, String> {
    if group.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic {
        return Ok(None);
    }
    let snapshot = signed_public_bootstrap_snapshot(group.clone()).ok_or_else(|| {
        "failed to construct a signed public-group bootstrap snapshot".to_string()
    })?;
    prepare_public_group_bootstrap_obligation(recipient, snapshot).map(Some)
}

fn decode_public_group_bootstrap(encoded: &[u8]) -> Result<PublicGroupBootstrap, String> {
    let bootstrap: PublicGroupBootstrap = serde_json::from_slice(encoded)
        .map_err(|error| format!("bootstrap payload decode failed: {error}"))?;
    if bootstrap.message_type != PUBLIC_GROUP_BOOTSTRAP_MESSAGE_TYPE {
        return Err("unsupported public-group bootstrap message type".to_string());
    }
    Ok(bootstrap)
}

fn public_group_bootstrap_group_from_payload(
    payload: &[u8],
) -> Result<x0x::groups::GroupInfo, String> {
    let encoded = payload
        .strip_prefix(PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX)
        .ok_or_else(|| "bootstrap typed prefix is missing".to_string())?;
    decode_public_group_bootstrap(encoded).map(|bootstrap| *bootstrap.group)
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

fn public_group_bootstrap_delivery_config(
    obligation: &PublicGroupBootstrapObligation,
) -> Result<x0x::dm::DmSendConfig, String> {
    let mut config = named_group_direct_delivery_config();
    // A transport receipt is not enough: the recipient may still refuse the
    // snapshot at its consent gate. Only the typed handler's completion — the
    // v2 application ACK — proves the frontier was durably installed.
    config.require_durable_app_ack = true;
    config.prefer_raw_quic_if_connected = false;
    // The outbox owns retry scheduling and persists it; a send-layer retry
    // would burn attempts inside one worker pass without a durable record.
    config.max_retries = 0;
    config.logical_request_id = Some(public_group_bootstrap_request_id(obligation)?);
    Ok(config)
}

fn public_group_bootstrap_legacy_delivery_config() -> x0x::dm::DmSendConfig {
    let mut config = named_group_direct_delivery_config();
    config.require_durable_app_ack = false;
    config.max_retries = 0;
    config
}

/// The v1 wire form is the same JSON without the typed prefix — the shape the
/// pre-0.38 unprefixed listener understands.
fn public_group_bootstrap_legacy_payload(
    obligation: &PublicGroupBootstrapObligation,
) -> Result<Vec<u8>, x0x::dm::DmError> {
    obligation
        .payload
        .strip_prefix(PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            x0x::dm::DmError::EnvelopeConstruction(
                "bootstrap outbox payload is missing the v2 typed prefix".to_string(),
            )
        })
}

async fn public_group_bootstrap_wire_version(
    state: &AppState,
    recipient: &AgentId,
) -> PublicGroupBootstrapWireVersion {
    if let Some(binding) = state.agent.capability_store().lookup_binding(recipient) {
        return if binding.capabilities.max_protocol_version < 2 {
            PublicGroupBootstrapWireVersion::LegacyV1
        } else {
            PublicGroupBootstrapWireVersion::StrictV2
        };
    }
    let card_reports_v1 = state
        .contacts
        .read()
        .await
        .get(recipient)
        .and_then(|contact| contact.dm_capabilities.as_ref())
        .is_some_and(|capabilities| capabilities.max_protocol_version < 2);
    if card_reports_v1 {
        PublicGroupBootstrapWireVersion::LegacyV1
    } else {
        // Missing capability information is not permission to downgrade. Keep
        // the obligation pending until a current v2 advert, or an explicit
        // verified v1 advert/card binding, is available.
        PublicGroupBootstrapWireVersion::StrictV2
    }
}

async fn deliver_public_group_bootstrap(
    state: &AppState,
    obligation: &PublicGroupBootstrapObligation,
) -> Result<PublicGroupBootstrapDelivery, x0x::dm::DmError> {
    let recipient = parse_agent_id_hex(&obligation.recipient_hex)
        .map_err(x0x::dm::DmError::EnvelopeConstruction)?;
    if public_group_bootstrap_wire_version(state, &recipient).await
        == PublicGroupBootstrapWireVersion::LegacyV1
    {
        let payload = public_group_bootstrap_legacy_payload(obligation)?;
        return state
            .agent
            .send_direct_with_config(
                &recipient,
                payload,
                public_group_bootstrap_legacy_delivery_config(),
            )
            .await
            .map(PublicGroupBootstrapDelivery::LegacyV1Sent);
    }

    let config = public_group_bootstrap_delivery_config(obligation)
        .map_err(x0x::dm::DmError::EnvelopeConstruction)?;
    state
        .agent
        .send_direct_with_config(&recipient, obligation.payload.clone(), config)
        .await
        .map(PublicGroupBootstrapDelivery::V2ApplicationAck)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn invalid_bootstrap_outbox(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

/// Every internal consistency claim an obligation makes, re-checked.
///
/// This runs on load as well as on write, and on load a failure aborts daemon
/// startup. That is deliberate: an obligation whose payload no longer matches
/// the frontier it claims would send one snapshot while waiting for an ACK
/// that can only ever describe a different one — a silent permanent stall.
/// Refusing to start is louder and easier to diagnose.
fn validate_public_group_bootstrap_obligation(
    obligation: &PublicGroupBootstrapObligation,
) -> std::io::Result<()> {
    if obligation.payload.len() > x0x::direct::MAX_DIRECT_PAYLOAD_SIZE {
        return Err(invalid_bootstrap_outbox(
            "public-group bootstrap outbox payload exceeds the DM limit",
        ));
    }
    let payload_digest = blake3::hash(&obligation.payload).to_hex().to_string();
    if payload_digest != obligation.payload_digest {
        return Err(invalid_bootstrap_outbox(
            "public-group bootstrap outbox payload digest mismatch",
        ));
    }
    let binding_digest = public_group_bootstrap_binding_digest(
        &obligation.recipient_hex,
        &obligation.group_id,
        obligation.state_revision,
        &obligation.state_hash,
        &obligation.payload_digest,
    )
    .map_err(invalid_bootstrap_outbox)?;
    if obligation.key != format!("{PUBLIC_GROUP_BOOTSTRAP_KEY_PREFIX}{binding_digest}") {
        return Err(invalid_bootstrap_outbox(
            "public-group bootstrap outbox key mismatch",
        ));
    }
    let group = public_group_bootstrap_group_from_payload(&obligation.payload)
        .map_err(invalid_bootstrap_outbox)?;
    if group.stable_group_id() != obligation.group_id
        || group.state_revision != obligation.state_revision
        || group.state_hash != obligation.state_hash
        || group.withdrawn
        // ADR-0066 §3c row 21: a fork-quarantine marker must NEVER ride an
        // outbound payload — `signed_public_bootstrap_snapshot` strips it
        // because containment is strictly per-node state. This is the
        // structural half of the row: it makes "the marker leaked into a
        // stored obligation" a refusal to write and a refusal to start,
        // rather than something a future refactor of the stripping list
        // could quietly re-enable. The LIVE half — this daemon declining to
        // publish a group it currently holds a marker for — cannot live
        // here, because this validator sees only the payload's own snapshot
        // and by construction that snapshot never carries the marker; it is
        // enforced at the two sites that consult the live roster
        // (`reconcile_public_group_bootstrap_outbox`, and the worker step).
        || group.fork_quarantine.is_some()
        || group.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic
        // A bootstrap snapshot retains exactly its head commit; the receiver's
        // validator refuses anything else, so storing it would be dead weight.
        || group.commit_log.len() != 1
    {
        return Err(invalid_bootstrap_outbox(
            "public-group bootstrap outbox frontier does not match its payload",
        ));
    }
    Ok(())
}

/// Callers must hold `public_group_bootstrap_outbox_persistence_lock`.
async fn save_public_group_bootstrap_outbox_unlocked(
    state: &AppState,
) -> std::io::Result<AtomicWriteOutcome> {
    let mut entries: Vec<PublicGroupBootstrapObligation> = state
        .public_group_bootstrap_outbox
        .read()
        .await
        .values()
        .cloned()
        .collect();
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let json = serde_json::to_string(&PublicGroupBootstrapOutboxSidecar {
        version: PUBLIC_GROUP_BOOTSTRAP_OUTBOX_VERSION,
        entries,
    })
    .map_err(|error| std::io::Error::other(format!("serialize bootstrap outbox: {error}")))?;
    write_named_groups_json_atomic(&state.public_group_bootstrap_outbox_path, &json).await
}

/// Swap the whole outbox, keeping memory and disk in agreement: anything short
/// of a durable write puts the previous map back, so an obligation is never
/// live in memory while absent from the sidecar.
async fn replace_public_group_bootstrap_outbox_unlocked(
    state: &AppState,
    next: HashMap<String, PublicGroupBootstrapObligation>,
) -> std::io::Result<AtomicWriteOutcome> {
    let previous = {
        let mut outbox = state.public_group_bootstrap_outbox.write().await;
        if *outbox == next {
            return Ok(AtomicWriteOutcome::NotReplaced);
        }
        std::mem::replace(&mut *outbox, next)
    };
    let outcome = save_public_group_bootstrap_outbox_unlocked(state).await;
    if !matches!(outcome, Ok(AtomicWriteOutcome::Durable)) {
        *state.public_group_bootstrap_outbox.write().await = previous;
    }
    outcome
}

async fn upsert_public_group_bootstrap_obligation_unlocked(
    state: &AppState,
    obligation: PublicGroupBootstrapObligation,
) -> std::io::Result<AtomicWriteOutcome> {
    validate_public_group_bootstrap_obligation(&obligation)?;
    let mut next = state.public_group_bootstrap_outbox.read().await.clone();
    // One obligation per (recipient, group): a newer frontier supersedes the
    // older debt to the same member rather than queueing behind it.
    next.retain(|_, existing| {
        existing.recipient_hex != obligation.recipient_hex
            || existing.group_id != obligation.group_id
    });
    if next.len() >= PUBLIC_GROUP_BOOTSTRAP_OUTBOX_MAX_ENTRIES {
        return Err(std::io::Error::other(
            "public-group bootstrap outbox capacity reached",
        ));
    }
    next.insert(obligation.key.clone(), obligation);
    replace_public_group_bootstrap_outbox_unlocked(state, next).await
}

/// Commit the obligation and the roster that created it as one step.
///
/// Outbox first: an obligation with no roster entry is dropped by the next
/// reconciliation, whereas a roster entry with no obligation is a member the
/// authority has silently forgotten to bootstrap. On roster failure the outbox
/// is rolled back, so the two cannot disagree about who is owed a snapshot.
pub(in crate::server) async fn persist_named_group_info_with_bootstrap_obligation(
    state: &Arc<AppState>,
    group_key: &str,
    next_group: x0x::groups::GroupInfo,
    obligation: PublicGroupBootstrapObligation,
) -> std::io::Result<AtomicWriteOutcome> {
    let _outbox_guard = state
        .public_group_bootstrap_outbox_persistence_lock
        .lock()
        .await;
    let previous_outbox = state.public_group_bootstrap_outbox.read().await.clone();
    match upsert_public_group_bootstrap_obligation_unlocked(state, obligation).await {
        Ok(AtomicWriteOutcome::Durable) => {}
        Ok(AtomicWriteOutcome::ReplacedNotDurable) => {
            return Ok(AtomicWriteOutcome::ReplacedNotDurable);
        }
        Ok(AtomicWriteOutcome::NotReplaced) => return Ok(AtomicWriteOutcome::NotReplaced),
        Err(error) => return Err(error),
    }

    let roster_outcome = persist_named_group_info(state, group_key, next_group).await;
    if matches!(
        roster_outcome,
        Ok(AtomicWriteOutcome::Durable | AtomicWriteOutcome::ReplacedNotDurable)
    ) {
        // A post-rename durability failure can still leave the roster visible
        // and recoverable. Keep its equally-visible outbox sidecar so startup
        // either confirms both or drops the obligation when the roster did not
        // survive.
        return roster_outcome;
    }

    match replace_public_group_bootstrap_outbox_unlocked(state, previous_outbox).await {
        Ok(AtomicWriteOutcome::Durable | AtomicWriteOutcome::NotReplaced) => {}
        Ok(AtomicWriteOutcome::ReplacedNotDurable) => {
            tracing::error!("bootstrap outbox rollback replacement was not directory-durable");
        }
        Err(error) => {
            tracing::error!(
                %error,
                "failed to roll back bootstrap outbox after roster persistence failure"
            );
        }
    }
    roster_outcome
}

/// Drop every obligation owed to `recipient_hex` for `group_id`. Called when a
/// committed membership change means the debt no longer exists.
pub(in crate::server) async fn cancel_public_group_bootstrap_obligations(
    state: &AppState,
    recipient_hex: &str,
    group_id: &str,
) -> std::io::Result<AtomicWriteOutcome> {
    let _guard = state
        .public_group_bootstrap_outbox_persistence_lock
        .lock()
        .await;
    let mut next = state.public_group_bootstrap_outbox.read().await.clone();
    next.retain(|_, obligation| {
        obligation.recipient_hex != recipient_hex || obligation.group_id != group_id
    });
    replace_public_group_bootstrap_outbox_unlocked(state, next).await
}

/// Cancel the bootstrap debt a committed removal has just extinguished.
///
/// Best-effort by design: reconciliation drops obligations to non-members on
/// every worker pass, so this is a latency optimisation over that sweep rather
/// than the guarantee. A failure is therefore logged, not propagated — the
/// removal itself is already committed and must not be unwound.
pub(in crate::server) async fn cancel_public_group_bootstrap_obligations_for_removal(
    state: &AppState,
    recipient_hex: &str,
    group: &x0x::groups::GroupInfo,
) {
    if group.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic {
        return;
    }
    let group_id = group.stable_group_id();
    match cancel_public_group_bootstrap_obligations(state, recipient_hex, group_id).await {
        Ok(AtomicWriteOutcome::Durable | AtomicWriteOutcome::NotReplaced) => {}
        Ok(AtomicWriteOutcome::ReplacedNotDurable) => tracing::warn!(
            group_id = %LogHexId::group(group_id),
            recipient = %LogHexId::agent(recipient_hex),
            "bootstrap cancellation replacement was not directory-durable; reconciliation will keep the removed member suppressed"
        ),
        Err(error) => tracing::warn!(
            group_id = %LogHexId::group(group_id),
            recipient = %LogHexId::agent(recipient_hex),
            %error,
            "failed to persist bootstrap cancellation; reconciliation will keep the removed member suppressed"
        ),
    }
}

// ---------------------------------------------------------------------------
// Retry engine
// ---------------------------------------------------------------------------

/// Groups whose ADR-0066 row-21 publication refusal has already been
/// recorded, keyed by `(group id, evidence revision, observed_at_ms)`.
/// Process-local
/// and advisory, exactly like slice 3's `LOGGED_INDEX_REFUSALS`
/// (`src/server/delegations.rs`): losing it costs one extra log line and one
/// extra counter increment, never a missed suppression — the suppression
/// itself never consults this.
///
/// WHY dedupe at all here, when slice 3 deduped only its log line: this row
/// is driven by a POLLING worker, so an undeduped record would emit one WARN
/// and one `fork_quarantine_refusals` increment per poll for as long as the
/// marker stands, which for a `no_anchor` marker is "until a human
/// intervenes". That turns the fleet-health signal the ADR's Consequences
/// ask operators to alert on into a counter that measures uptime. One record
/// per (group, fork observation) is the honest unit.
///
/// WHY `observed_at_ms` is part of the key and not just the revision (review
/// r1): an operator who clears a marker and then meets the SAME revision again
/// is looking at a NEW fork observation and must see it. Keying on the
/// revision alone would suppress that second WARN until the daemon restarted —
/// a re-quarantine that looks, in the log, exactly like nothing happening.
/// `observed_at_ms` is the local install time, so the re-quarantine carries a
/// different key while a poll of the SAME marker carries the same one, which
/// is precisely the distinction wanted. This keeps the reset inside this
/// module rather than coupling the clear handler to a log cache.
static LOGGED_PUBLICATION_REFUSALS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<(String, u64, u64)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// Is this the first publication refusal to record for this group at this
/// fork observation?
///
/// Fails OPEN to recording: a poisoned lock records rather than going quiet,
/// because the failure mode of this cache is noise and the failure mode of
/// silence is an unexplained suppression.
fn first_publication_refusal_for(group_id: &str, marker: &x0x::groups::ForkQuarantine) -> bool {
    let Ok(mut seen) = LOGGED_PUBLICATION_REFUSALS.lock() else {
        return true;
    };
    if seen.len() >= 1024 {
        seen.clear();
    }
    seen.insert((group_id.to_string(), marker.revision, marker.observed_at_ms))
}

/// Every group this node currently holds a fork-quarantine marker for, under
/// BOTH its roster map key and its stable id, with the marker itself.
///
/// One roster read and one scan per worker pass — the same cost class as the
/// candidate selection it feeds, and deliberately NOT a lock per withheld
/// obligation. Slice 3's `quarantined_group_ids` (`src/server/delegations.rs`)
/// is the precedent for the both-spellings discipline; this returns the marker
/// rather than just the id because the recording path needs it to build the §5
/// sentence, and fetching it again would reintroduce the per-item lock.
async fn quarantined_markers(
    state: &AppState,
) -> std::collections::HashMap<String, x0x::groups::ForkQuarantine> {
    let groups = state.named_groups.read().await;
    let mut out = std::collections::HashMap::new();
    for (key, info) in groups.iter() {
        if let Some(marker) = info.fork_quarantine.as_ref() {
            out.insert(key.clone(), marker.clone());
            out.insert(info.stable_group_id().to_string(), marker.clone());
        }
    }
    out
}

/// ADR-0066 §3c row 21: must this group's signed-public bootstrap snapshot be
/// withheld because the group is fork-quarantined on this node?
///
/// This is the highest-severity row in the §1 census after §2, because it is
/// the one ungated path that EXPORTS contested state to other nodes: a
/// bootstrap snapshot is a whole roster/state frontier installed verbatim by
/// its recipient. A background worker publishing one while the local daemon
/// holds authenticated fork evidence would propagate one branch of a
/// contested chain to a peer that has no evidence of the fork at all, and it
/// would do so with nobody watching.
///
/// The marker is resolved through
/// [`crate::server::delegations::fork_quarantine_marker`], which tries BOTH
/// the roster map key and the stable id. That matters concretely here rather
/// than theoretically: an obligation records `group.stable_group_id()`, while
/// the roster map is keyed by whichever alias this daemon learned the group
/// under, so a single-spelling lookup would publish exactly the groups whose
/// two names differ.
///
/// Suppression is NON-DESTRUCTIVE by design. The obligation and its retry
/// schedule are left untouched, so the debt survives (a member on the roster
/// that nobody remembers to bootstrap is the failure this outbox exists to
/// prevent) and delivery resumes on its own after `POST
/// /groups/:id/quarantine/clear`.
async fn withhold_bootstrap_publication(state: &Arc<AppState>, group_id: &str) -> bool {
    let Some(marker) = crate::server::delegations::fork_quarantine_marker(state, group_id).await
    else {
        return false;
    };
    record_withheld_publication(state, group_id, &marker);
    true
}

/// The recording half of the withholding, shared by the lock-ordered gate and
/// the selection filter so the two can never drift in what an operator sees.
fn record_withheld_publication(
    state: &AppState,
    group_id: &str,
    marker: &x0x::groups::ForkQuarantine,
) {
    if first_publication_refusal_for(group_id, marker) {
        // The shared slice-1 helper: one `fork_quarantine_refusals`
        // increment and the §5 sentence, so the operator reading the log
        // learns the condition, the cause and the manual remedy (§3e) — the
        // same words the REST refusals use.
        let reason = crate::server::routes::named_groups::fork_quarantine_refusal_reason(
            state, group_id, marker,
        );
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            "signed-public bootstrap publication withheld: {reason}"
        );
    } else {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            revision = marker.revision,
            "signed-public bootstrap publication still withheld under fork quarantine"
        );
    }
}

/// `1s << min(attempts, 6)`, clamped to 60 s.
fn public_group_bootstrap_retry_delay_ms(attempt_count: u32) -> u64 {
    let shift = attempt_count.min(6);
    1_000_u64
        .checked_shl(shift)
        .unwrap_or(PUBLIC_GROUP_BOOTSTRAP_RETRY_MAX_DELAY_MS)
        .min(PUBLIC_GROUP_BOOTSTRAP_RETRY_MAX_DELAY_MS)
}

/// Re-target an obligation at the group's current committed frontier, or
/// `None` when it already carries it.
///
/// Without this an obligation written at revision N would be retried forever
/// after the group advanced to N+1: the recipient installs N and then tracks
/// the group through the ordinary metadata-commit path, so no ACK matching
/// frontier N can ever arrive again once the authority has moved on.
fn public_group_bootstrap_refreshed_snapshot(
    obligation: &PublicGroupBootstrapObligation,
    current: &x0x::groups::GroupInfo,
) -> Option<x0x::groups::GroupInfo> {
    if current.state_revision == obligation.state_revision
        && current.state_hash == obligation.state_hash
    {
        return None;
    }
    signed_public_bootstrap_snapshot(current.clone())
}

/// Drop obligations the roster no longer justifies and refresh the rest to the
/// live frontier. The roster is the authority on who is owed a bootstrap; the
/// outbox only records the debt.
async fn reconcile_public_group_bootstrap_outbox(
    state: &AppState,
) -> std::io::Result<AtomicWriteOutcome> {
    let _guard = state
        .public_group_bootstrap_outbox_persistence_lock
        .lock()
        .await;
    let current = state.public_group_bootstrap_outbox.read().await.clone();
    let groups = state.named_groups.read().await.clone();
    let mut next = HashMap::new();
    for obligation in current.values() {
        let Ok(recipient) = parse_agent_id_hex(&obligation.recipient_hex) else {
            continue;
        };
        let Some(group) = groups
            .values()
            .find(|group| group.stable_group_id() == obligation.group_id)
        else {
            continue;
        };
        if !group.has_active_member(&obligation.recipient_hex)
            || group.withdrawn
            || group.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic
        {
            continue;
        }
        // ADR-0066 §3c row 21, at the predicate the ADR anchors the row to —
        // but RETAINED, not dropped. `continue` here would delete the debt,
        // and the marker on an ordinary group never auto-clears, so the
        // member would be silently and permanently forgotten: the exact
        // "roster entry with no obligation" failure this module's doc comment
        // names. What is withheld is the REFRESH: re-deriving the stored
        // payload from a contested frontier would rewrite a durable
        // obligation with a snapshot of disputed state. The obligation stands
        // as written and the worker below declines to send it.
        if group.is_fork_quarantined() {
            next.insert(obligation.key.clone(), obligation.clone());
            continue;
        }
        let mut replacement = match public_group_bootstrap_refreshed_snapshot(obligation, group) {
            Some(snapshot) => prepare_public_group_bootstrap_obligation(recipient, snapshot)
                .map_err(invalid_bootstrap_outbox)?,
            None => obligation.clone(),
        };
        replacement.created_at_ms = obligation.created_at_ms;
        if replacement.key == obligation.key {
            replacement.next_attempt_at_ms = obligation.next_attempt_at_ms;
            replacement.attempt_count = obligation.attempt_count;
        }
        validate_public_group_bootstrap_obligation(&replacement)?;
        next.insert(replacement.key.clone(), replacement);
    }
    replace_public_group_bootstrap_outbox_unlocked(state, next).await
}

/// Load the sidecar at startup, fail-closed.
///
/// Version mismatch, over-cap, duplicate key, or any per-entry validation
/// failure returns `Err`, and the caller in `serve_with_options` turns that
/// into a refusal to start. A daemon that started with a silently truncated
/// outbox would look healthy while permanently owing bootstraps it no longer
/// remembers.
pub(in crate::server) async fn load_public_group_bootstrap_outbox(
    state: &AppState,
) -> std::io::Result<()> {
    let bytes = match tokio::fs::read(&state.public_group_bootstrap_outbox_path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            state.public_group_bootstrap_outbox.write().await.clear();
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let sidecar: PublicGroupBootstrapOutboxSidecar = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_bootstrap_outbox(error.to_string()))?;
    if sidecar.version != PUBLIC_GROUP_BOOTSTRAP_OUTBOX_VERSION {
        return Err(invalid_bootstrap_outbox(format!(
            "unsupported public-group bootstrap outbox version {}",
            sidecar.version
        )));
    }
    if sidecar.entries.len() > PUBLIC_GROUP_BOOTSTRAP_OUTBOX_MAX_ENTRIES {
        return Err(invalid_bootstrap_outbox(
            "public-group bootstrap outbox capacity exceeded",
        ));
    }
    let mut loaded = HashMap::new();
    for obligation in sidecar.entries {
        validate_public_group_bootstrap_obligation(&obligation)?;
        if loaded.insert(obligation.key.clone(), obligation).is_some() {
            return Err(invalid_bootstrap_outbox(
                "duplicate public-group bootstrap outbox key",
            ));
        }
    }
    *state.public_group_bootstrap_outbox.write().await = loaded;
    match reconcile_public_group_bootstrap_outbox(state).await? {
        AtomicWriteOutcome::Durable | AtomicWriteOutcome::NotReplaced => Ok(()),
        AtomicWriteOutcome::ReplacedNotDurable => Err(std::io::Error::other(
            "public-group bootstrap outbox reconciliation was not directory-durable",
        )),
    }
}

async fn reschedule_public_group_bootstrap_obligation(
    state: &AppState,
    key: &str,
) -> std::io::Result<AtomicWriteOutcome> {
    let _guard = state
        .public_group_bootstrap_outbox_persistence_lock
        .lock()
        .await;
    let mut next = state.public_group_bootstrap_outbox.read().await.clone();
    let Some(obligation) = next.get_mut(key) else {
        return Ok(AtomicWriteOutcome::NotReplaced);
    };
    obligation.attempt_count = obligation.attempt_count.saturating_add(1);
    obligation.next_attempt_at_ms = now_millis_u64().saturating_add(
        public_group_bootstrap_retry_delay_ms(obligation.attempt_count),
    );
    replace_public_group_bootstrap_outbox_unlocked(state, next).await
}

async fn clear_public_group_bootstrap_obligation_after_ack(
    state: &AppState,
    key: &str,
) -> std::io::Result<AtomicWriteOutcome> {
    let _guard = state
        .public_group_bootstrap_outbox_persistence_lock
        .lock()
        .await;
    let mut next = state.public_group_bootstrap_outbox.read().await.clone();
    next.remove(key);
    replace_public_group_bootstrap_outbox_unlocked(state, next).await
}

/// Discharge an obligation whose recipient returned a v2 application ACK — but
/// only if the ACKed frontier is still the group's current one.
///
/// If the group advanced while the send was in flight, the ACK proves an
/// ancestor was installed, not the frontier the authority now owes. Clearing on
/// it would silently downgrade the obligation to a stale snapshot, so instead
/// reconciliation re-targets it and the worker tries again.
async fn finish_public_group_bootstrap_obligation_after_ack(
    state: &AppState,
    obligation: &PublicGroupBootstrapObligation,
) -> std::io::Result<AtomicWriteOutcome> {
    match reconcile_public_group_bootstrap_outbox(state).await? {
        AtomicWriteOutcome::ReplacedNotDurable => {
            return Ok(AtomicWriteOutcome::ReplacedNotDurable);
        }
        AtomicWriteOutcome::Durable | AtomicWriteOutcome::NotReplaced => {}
    }
    let exact_obligation_remains = state
        .public_group_bootstrap_outbox
        .read()
        .await
        .contains_key(&obligation.key);
    if !exact_obligation_remains {
        // Reconciliation already replaced or cancelled the ACKed obligation.
        // Whatever it left behind is durable and belongs to the next pass.
        return Ok(AtomicWriteOutcome::Durable);
    }
    let current_matches_ack = state
        .named_groups
        .read()
        .await
        .values()
        .find(|group| group.stable_group_id() == obligation.group_id)
        .is_some_and(|group| {
            group.state_revision == obligation.state_revision
                && group.state_hash == obligation.state_hash
        });
    if current_matches_ack {
        clear_public_group_bootstrap_obligation_after_ack(state, &obligation.key).await
    } else {
        reschedule_public_group_bootstrap_obligation(state, &obligation.key).await
    }
}

/// One worker pass: send at most one due obligation and persist its outcome.
///
/// At most one, deliberately — a disconnected peer must not turn the outbox
/// into a hot send loop, and each attempt's backoff has to reach disk before
/// the next is considered.
pub(in crate::server) async fn public_group_bootstrap_outbox_step(state: &Arc<AppState>) {
    if state
        .named_groups_requires_durability_confirmation
        .load(Ordering::Acquire)
    {
        tracing::debug!(
            "deferring public-group bootstrap delivery until roster durability is confirmed"
        );
        return;
    }
    let now_ms = now_millis_u64();
    // ADR-0066 §3c row 21, review r1 — HEAD-OF-LINE BLOCKING. A pass delivers
    // AT MOST ONE obligation, chosen as the minimum `(next_attempt_at_ms,
    // created_at_ms)` among the due ones, and a withheld obligation is
    // deliberately never rescheduled (that is what makes the suppression
    // non-destructive). Those two facts compose badly: once a quarantined
    // group's obligation is the minimum it stays the minimum forever, so a
    // gate applied only AFTER selection would re-pick it every tick and
    // starve every OTHER group's bootstrap for as long as the marker stands —
    // indefinitely for a `no_anchor` marker, and silently.
    //
    // So quarantined groups are excluded during SELECTION: the healthy
    // minimum is chosen instead and delivered on this very tick. Containment
    // is unchanged (nothing contested is sent either way); what changes is
    // that containment of one group is no longer an outage for all the
    // others.
    //
    // Resumption stays automatic and prompt. The filter is re-evaluated from
    // live roster state on every pass, and a withheld obligation's schedule
    // was never advanced, so it is still due: the pass after the manual clear
    // selects it. No backoff to wait out, and well inside the "delivery
    // resumes within the normal retry backoff" the runbook promises.
    let quarantined = quarantined_markers(state).await;
    let Some(candidate_group_id) = state
        .public_group_bootstrap_outbox
        .read()
        .await
        .values()
        .filter(|obligation| obligation.next_attempt_at_ms <= now_ms)
        .filter(|obligation| {
            match quarantined.get(&obligation.group_id) {
                None => true,
                Some(marker) => {
                    // Recorded here rather than silently skipped: a suppressed
                    // publication an operator cannot see is the unexplained
                    // outage R5 forbids. The dedupe makes this at most one
                    // WARN and one counter increment per fork observation,
                    // not one per tick, and it costs a hash lookup — the
                    // marker is already in hand from the single roster scan
                    // above, so no lock is taken per withheld obligation.
                    record_withheld_publication(state, &obligation.group_id, marker);
                    false
                }
            }
        })
        .min_by_key(|obligation| (obligation.next_attempt_at_ms, obligation.created_at_ms))
        .map(|obligation| obligation.group_id.clone())
    else {
        return;
    };

    // Every signed-public frontier mutation takes this same stable per-group
    // lock. Holding it from reconciliation through the application ACK and the
    // durable outbox transition makes the ordering unambiguous: either this
    // snapshot installs before a concurrent mutation, or the mutation wins and
    // this worker never sends a stale clone.
    let membership_lock = group_membership_lock(state, &candidate_group_id).await;
    let _membership_guard = membership_lock.lock().await;
    // ADR-0066 §3c row 21: the single chokepoint for outbound publication.
    // Both publishers funnel here — the periodic worker in
    // `serve_with_options` and the REST nudge
    // `spawn_public_group_bootstrap_delivery` that a member-add fires — so
    // one gate closes the row for the background job and the REST surface
    // alike, and neither can publish a contested group's snapshot.
    //
    // Placed inside the membership lock and BEFORE reconciliation: the lock
    // is the one every signed-public frontier mutation takes, so a marker
    // install either lands before this read (and we withhold) or after we
    // release (and the snapshot we sent was uncontested when we sent it).
    // Before reconciliation, because reconciliation is where a stored
    // obligation would be refreshed from the live frontier, and R5 allows no
    // grace: the FIRST due obligation after the marker installs is withheld.
    //
    // This is the CORRECTNESS gate and the selection filter above is the
    // SCHEDULING fix; both are needed and neither subsumes the other. The
    // filter reads the roster before this lock is taken, so a marker that
    // installs in that window is invisible to it — this check, ordered under
    // the same lock as the frontier mutation that installed the marker, is
    // what closes that race. It therefore fires rarely, not never.
    if withhold_bootstrap_publication(state, &candidate_group_id).await {
        return;
    }
    match reconcile_public_group_bootstrap_outbox(state).await {
        Ok(AtomicWriteOutcome::Durable | AtomicWriteOutcome::NotReplaced) => {}
        Ok(AtomicWriteOutcome::ReplacedNotDurable) => {
            tracing::warn!(
                "public-group bootstrap reconciliation was not directory-durable; delivery deferred"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "failed to reconcile public-group bootstrap outbox");
            return;
        }
    }
    let due = state
        .public_group_bootstrap_outbox
        .read()
        .await
        .values()
        .filter(|obligation| {
            obligation.group_id == candidate_group_id && obligation.next_attempt_at_ms <= now_ms
        })
        .min_by_key(|obligation| (obligation.next_attempt_at_ms, obligation.created_at_ms))
        .cloned();
    let Some(obligation) = due else {
        return;
    };
    let attempt = deliver_public_group_bootstrap(state, &obligation).await;
    settle_public_group_bootstrap_attempt(state, &obligation, attempt).await;
}

/// Apply one delivery attempt's outcome to the outbox.
///
/// Split out from the worker so the rule that decides whether an obligation
/// survives is testable without a live peer: only a v2 application ACK for the
/// current frontier discharges it, and a legacy v1 transport receipt — which
/// says the bytes were accepted, not that the snapshot was installed — never
/// does.
async fn settle_public_group_bootstrap_attempt(
    state: &AppState,
    obligation: &PublicGroupBootstrapObligation,
    attempt: Result<PublicGroupBootstrapDelivery, x0x::dm::DmError>,
) {
    match attempt {
        Ok(PublicGroupBootstrapDelivery::V2ApplicationAck(receipt)) => {
            tracing::debug!(
                group_id = %LogHexId::group(&obligation.group_id),
                recipient = %LogHexId::agent(&obligation.recipient_hex),
                path = ?receipt.path,
                "public-group bootstrap received durable application ACK"
            );
            match finish_public_group_bootstrap_obligation_after_ack(state, obligation).await {
                Ok(AtomicWriteOutcome::Durable | AtomicWriteOutcome::NotReplaced) => {}
                Ok(AtomicWriteOutcome::ReplacedNotDurable) => tracing::warn!(
                    "public-group bootstrap ACK completion was not directory-durable"
                ),
                Err(error) => {
                    tracing::warn!(%error, "failed to persist public-group bootstrap ACK completion");
                }
            }
        }
        Ok(PublicGroupBootstrapDelivery::LegacyV1Sent(receipt)) => {
            tracing::debug!(
                group_id = %LogHexId::group(&obligation.group_id),
                recipient = %LogHexId::agent(&obligation.recipient_hex),
                path = ?receipt.path,
                "sent explicit verified-v1 public-group bootstrap fallback; retaining obligation until a v2 ACK"
            );
            if let Err(error) =
                reschedule_public_group_bootstrap_obligation(state, &obligation.key).await
            {
                tracing::warn!(%error, "failed to persist v1 bootstrap retry schedule");
            }
        }
        Err(error) => {
            tracing::warn!(
                group_id = %LogHexId::group(&obligation.group_id),
                recipient = %LogHexId::agent(&obligation.recipient_hex),
                %error,
                "public-group bootstrap delivery attempt failed"
            );
            if let Err(schedule_error) =
                reschedule_public_group_bootstrap_obligation(state, &obligation.key).await
            {
                tracing::warn!(%schedule_error, "failed to persist bootstrap retry schedule");
            }
        }
    }
}

/// Nudge the worker so a freshly enqueued obligation does not wait out the
/// poll interval.
pub(in crate::server) fn spawn_public_group_bootstrap_delivery(state: &Arc<AppState>) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        public_group_bootstrap_outbox_step(&state).await;
    });
}

// ---------------------------------------------------------------------------
// Receiving side
// ---------------------------------------------------------------------------

/// Validate and install a signed-public bootstrap received over the
/// authenticated direct channel. Existing local state is never overwritten;
/// normal metadata commits remain the only update path after bootstrap.
///
/// The legacy unprefixed listener discards the outcome; the strict v2 typed
/// route reports it as the DM completion signal (ADR 0030 §7). Every exit here
/// therefore has to say honestly whether a **directory-durable** record now
/// exists for this exact frontier — an in-memory roster entry is not enough,
/// because a v2 ACK certifies durability and the sender deletes its obligation
/// on the strength of it.
pub(in crate::server) async fn admit_public_group_bootstrap(
    state: &Arc<AppState>,
    sender: AgentId,
    bootstrap: PublicGroupBootstrap,
) -> x0x::dm_inbox::DmTypedPayloadCompletionResult {
    use x0x::dm_inbox::DmTypedPayloadCompletion;

    if bootstrap.message_type != PUBLIC_GROUP_BOOTSTRAP_MESSAGE_TYPE {
        return Err("unsupported public-group bootstrap message type".to_string());
    }
    let sender_hex = hex::encode(sender.as_bytes());
    {
        let revoked = state.agent.revocation_set();
        if revoked.read().await.is_agent_revoked(&sender) {
            return Err("public-group bootstrap sender is revoked".to_string());
        }
    }
    // Consent gate: a bootstrap persists a group and spawns listener tasks,
    // so an unsolicited one from a stranger is a spam/resource vector. The
    // roster inside the bootstrap is sender-controlled and cannot carry the
    // consent decision; only senders the local agent already knows may seed
    // groups (mirrors the pending-welcome convention for encrypted groups).
    {
        let contacts = state.contacts.read().await;
        if contacts.trust_level(&sender).rank() < crate::contacts::TrustLevel::Known.rank() {
            tracing::debug!(
                sender = %LogHexId::agent(&sender_hex),
                "ignoring public-group bootstrap from unknown or blocked sender"
            );
            return Err("public-group bootstrap sender is not a known contact".to_string());
        }
    }
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group = *bootstrap.group;
    if !validate_public_group_bootstrap(&group, &sender_hex, &local_agent_hex) {
        tracing::warn!(sender = %LogHexId::agent(&sender_hex), "rejected invalid public-group bootstrap");
        return Err("public-group bootstrap failed signed frontier validation".to_string());
    }
    let group_id = group.stable_group_id().to_string();
    let frontier = (group.state_revision, group.state_hash.clone());

    let installed_frontier_matches = {
        let groups = state.named_groups.read().await;
        match groups.get(&group_id).or_else(|| {
            groups
                .values()
                .find(|existing| existing.stable_group_id() == group_id)
        }) {
            Some(installed) => {
                Some((installed.state_revision, installed.state_hash.clone()) == frontier)
            }
            None => {
                if groups.len() >= MAX_BOOTSTRAP_INSTALLED_GROUPS {
                    tracing::warn!(
                        sender = %LogHexId::agent(&sender_hex),
                        "refusing public-group bootstrap: named-group capacity reached"
                    );
                    return Err("public-group bootstrap capacity reached".to_string());
                }
                None
            }
        }
    };

    if let Some(frontier_matches) = installed_frontier_matches {
        // Bootstrap seeds a group; it never overwrites one. Reporting the
        // installed frontier honestly is what keeps the sender's outbox
        // correct: only an exact match may discharge its obligation, and a
        // receiver that still trails the authority withholds the ACK so the
        // obligation survives until it catches up through the ordinary
        // metadata-commit path.
        if !frontier_matches {
            return Err("public-group bootstrap frontier is not the installed one".to_string());
        }
        // `Duplicate` certifies that a durable record already exists, so it may
        // not be answered off the in-memory roster alone. A previous write that
        // renamed into place but failed its parent-directory fsync leaves the
        // group visible in memory with the confirmation flag raised; answering
        // `Duplicate` there would let the sender delete an obligation whose
        // only evidence might not survive a power loss. Re-establish durability
        // first, and withhold if it cannot be re-established.
        if !confirm_named_groups_durability(state).await {
            return Err("public-group bootstrap duplicate is not directory-durable".to_string());
        }
        return Ok(DmTypedPayloadCompletion::Duplicate);
    }

    let outcome = persist_named_groups_mutation(state, |groups| {
        if groups.len() >= MAX_BOOTSTRAP_INSTALLED_GROUPS
            || groups.contains_key(&group_id)
            || groups
                .values()
                .any(|existing| existing.stable_group_id() == group_id)
        {
            return false;
        }
        groups.insert(group_id.clone(), group);
        true
    })
    .await;
    // Only `Durable` — rename plus parent-directory fsync — earns `Inserted`.
    // `ReplacedNotDurable` is visible but not yet proven to survive a crash, so
    // it withholds the ACK and the sender retries.
    if matches!(outcome, Ok(AtomicWriteOutcome::Durable)) {
        ensure_named_group_listeners(Arc::clone(state), &group_id).await;
        tracing::info!(group_id = %LogHexId::group(&group_id), sender = %LogHexId::agent(&sender_hex), "installed signed-public group bootstrap");
        Ok(DmTypedPayloadCompletion::Inserted)
    } else {
        tracing::warn!(group_id = %LogHexId::group(&group_id), "public-group bootstrap was not durably installed");
        Err("public-group bootstrap was not durably installed".to_string())
    }
}

/// Strict typed-DM bootstrap admission (ADR 0030 §7).
///
/// The completion channel is resolved only after the consent gate, signed
/// frontier validation, and a directory-durable install have all succeeded —
/// that signal is what releases the sender's v2 ACK. Every other path drops
/// the channel, which withholds the ACK and leaves the sender's obligation in
/// place, which is the honest outcome.
pub(in crate::server) async fn handle_public_group_bootstrap_typed_payload(
    state: &Arc<AppState>,
    typed: x0x::dm_inbox::DmTypedPayload,
) {
    let x0x::dm_inbox::DmTypedPayload {
        sender,
        payload,
        verified,
        completion,
        ..
    } = typed;
    let result = if verified {
        match payload.strip_prefix(PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX) {
            Some(encoded) => match decode_public_group_bootstrap(encoded) {
                Ok(bootstrap) => admit_public_group_bootstrap(state, sender, bootstrap).await,
                Err(error) => Err(error),
            },
            None => Err("typed public-group bootstrap prefix is missing".to_string()),
        }
    } else {
        Err("typed public-group bootstrap is not verified".to_string())
    };
    if let Some(completion) = completion {
        let _ = completion.send(result);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use anyhow::{Context, Result};

    use super::super::named_groups::tests::secure_endpoint_test_state;

    /// A committed SignedPublic group with `recipient` on its roster, in the
    /// exact shape the add-member path hands to the outbox.
    fn signed_public_group(
        authority: &x0x::identity::AgentKeypair,
        recipient_hex: &str,
    ) -> Result<x0x::groups::GroupInfo> {
        signed_public_group_with_id(authority, recipient_hex, &"cd".repeat(32))
    }

    /// The same, for a caller that needs TWO distinct groups — the
    /// head-of-line-blocking fixture cannot be written with one.
    fn signed_public_group_with_id(
        authority: &x0x::identity::AgentKeypair,
        recipient_hex: &str,
        mls_group_id: &str,
    ) -> Result<x0x::groups::GroupInfo> {
        let authority_hex = hex::encode(authority.agent_id().as_bytes());
        let recipient_hex = recipient_hex.to_string();
        let mut group = x0x::groups::GroupInfo::with_policy(
            "Outbox".to_string(),
            String::new(),
            authority.agent_id(),
            mls_group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        group.roster_revision = 1;
        group.add_member(
            recipient_hex,
            x0x::groups::GroupRole::Member,
            Some(authority_hex),
            None,
        );
        group.seal_commit(authority, now_millis_u64())?;
        signed_public_bootstrap_snapshot(group).context("signed-public snapshot")
    }

    fn test_obligation() -> Result<PublicGroupBootstrapObligation> {
        let authority = x0x::identity::AgentKeypair::generate()?;
        let recipient = x0x::identity::AgentKeypair::generate()?;
        let group = signed_public_group(&authority, &hex::encode(recipient.agent_id().as_bytes()))?;
        prepare_public_group_bootstrap_obligation(recipient.agent_id(), group)
            .map_err(|error| anyhow::anyhow!(error))
    }

    /// Prepare an obligation AND put its group on the roster.
    ///
    /// Reconciliation treats the roster as the authority on who is owed a
    /// bootstrap, so an obligation whose group is absent is deliberately
    /// dropped — a fixture that skips this models a state the daemon never
    /// reaches.
    async fn seeded_obligation(state: &AppState) -> Result<PublicGroupBootstrapObligation> {
        seeded_obligation_for(state, &"cd".repeat(32)).await
    }

    /// The same, for a named group id — so one fixture can hold a contested
    /// group and a healthy one at once.
    async fn seeded_obligation_for(
        state: &AppState,
        mls_group_id: &str,
    ) -> Result<PublicGroupBootstrapObligation> {
        let authority = x0x::identity::AgentKeypair::generate()?;
        let recipient = x0x::identity::AgentKeypair::generate()?;
        let group = signed_public_group_with_id(
            &authority,
            &hex::encode(recipient.agent_id().as_bytes()),
            mls_group_id,
        )?;
        state
            .named_groups
            .write()
            .await
            .insert(group.stable_group_id().to_string(), group.clone());
        prepare_public_group_bootstrap_obligation(recipient.agent_id(), group)
            .map_err(|error| anyhow::anyhow!(error))
    }

    fn receipt(request_id: [u8; 16]) -> x0x::dm::DmReceipt {
        x0x::dm::DmReceipt {
            request_id,
            accepted_at: std::time::Instant::now(),
            retries_used: 0,
            path: x0x::dm::DmPath::GossipInbox,
        }
    }

    /// Why: the obligation key is the ACK-matching identity. If any of the
    /// four bound components could change without changing the key, an ACK
    /// could discharge a debt it does not describe — the exact failure the
    /// durable receipt exists to prevent.
    #[test]
    fn obligation_key_binds_recipient_group_frontier_and_payload() -> Result<()> {
        let authority = x0x::identity::AgentKeypair::generate()?;
        let recipient = x0x::identity::AgentKeypair::generate()?;
        let other = x0x::identity::AgentKeypair::generate()?;
        let group = signed_public_group(&authority, &hex::encode(recipient.agent_id().as_bytes()))?;

        let base = prepare_public_group_bootstrap_obligation(recipient.agent_id(), group.clone())
            .map_err(|e| anyhow::anyhow!(e))?;
        let same = prepare_public_group_bootstrap_obligation(recipient.agent_id(), group.clone())
            .map_err(|e| anyhow::anyhow!(e))?;
        assert_eq!(
            base.key, same.key,
            "same inputs must be the same obligation"
        );

        let other_recipient =
            prepare_public_group_bootstrap_obligation(other.agent_id(), group.clone())
                .map_err(|e| anyhow::anyhow!(e))?;
        assert_ne!(base.key, other_recipient.key, "recipient must be bound");

        let mut advanced = group;
        advanced.state_revision = advanced.state_revision.saturating_add(1);
        let advanced_frontier =
            prepare_public_group_bootstrap_obligation(recipient.agent_id(), advanced)
                .map_err(|e| anyhow::anyhow!(e))?;
        assert_ne!(base.key, advanced_frontier.key, "frontier must be bound");
        Ok(())
    }

    /// Why: a retry after restart must be the SAME logical request, or the
    /// recipient re-delivers instead of re-ACKing and the obligation can never
    /// be matched to its ACK.
    #[test]
    fn request_id_is_the_obligation_identity_and_is_stable() -> Result<()> {
        let obligation = test_obligation()?;
        let first =
            public_group_bootstrap_request_id(&obligation).map_err(|e| anyhow::anyhow!(e))?;
        let second =
            public_group_bootstrap_request_id(&obligation).map_err(|e| anyhow::anyhow!(e))?;
        assert_eq!(first, second, "request id must be derived, not drawn");

        let key_digest = obligation
            .key
            .strip_prefix(PUBLIC_GROUP_BOOTSTRAP_KEY_PREFIX)
            .context("obligation key prefix")?;
        assert!(
            key_digest.starts_with(&hex::encode(first)),
            "the request id must be the head of the obligation key, not a separate identity"
        );

        let config =
            public_group_bootstrap_delivery_config(&obligation).map_err(|e| anyhow::anyhow!(e))?;
        assert_eq!(
            config.logical_request_id,
            Some(first),
            "the send must carry the obligation identity, not a fresh random id"
        );
        assert!(
            config.require_durable_app_ack,
            "bootstrap delivery must demand a v2 application ACK"
        );
        Ok(())
    }

    /// Why: ADR 0030 §5 fixes the schedule at `1s << min(attempts, 6)` capped
    /// at 60 s. A disconnected member must not become a hot send loop, and the
    /// cap must not be reachable by shift overflow.
    #[test]
    fn retry_backoff_doubles_then_clamps_at_sixty_seconds() {
        assert_eq!(public_group_bootstrap_retry_delay_ms(0), 1_000);
        assert_eq!(public_group_bootstrap_retry_delay_ms(1), 2_000);
        assert_eq!(public_group_bootstrap_retry_delay_ms(6), 60_000);
        assert_eq!(public_group_bootstrap_retry_delay_ms(7), 60_000);
        assert_eq!(public_group_bootstrap_retry_delay_ms(u32::MAX), 60_000);
    }

    /// Why: the outbox is the authority's memory of what it owes. If it did
    /// not survive a restart, a member added while offline would be stranded
    /// with no roster and nothing would ever retry.
    #[tokio::test]
    async fn obligation_survives_restart_through_the_sidecar() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let obligation = seeded_obligation(&state).await?;
        let key = obligation.key.clone();

        {
            let _guard = state
                .public_group_bootstrap_outbox_persistence_lock
                .lock()
                .await;
            assert_eq!(
                upsert_public_group_bootstrap_obligation_unlocked(&state, obligation.clone())
                    .await?,
                AtomicWriteOutcome::Durable
            );
        }

        // Simulate the restart: drop the in-memory map, then load the sidecar
        // the way `serve_with_options` does.
        state.public_group_bootstrap_outbox.write().await.clear();
        load_public_group_bootstrap_outbox(&state).await?;

        let reloaded = state.public_group_bootstrap_outbox.read().await;
        let restored = reloaded.get(&key).context("obligation after restart")?;
        assert_eq!(
            restored, &obligation,
            "the reloaded obligation must be byte-identical, so the retry is the same logical request"
        );
        Ok(())
    }

    /// Why: fail-closed on load. A daemon that started with a silently dropped
    /// obligation would look healthy while permanently owing a bootstrap it no
    /// longer remembers, so every rejection path must abort startup instead.
    #[tokio::test]
    async fn malformed_sidecar_is_rejected_rather_than_silently_dropped() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let path = state.public_group_bootstrap_outbox_path.clone();
        let obligation = test_obligation()?;

        let write_sidecar = |json: String| {
            let path = path.clone();
            async move { tokio::fs::write(&path, json).await }
        };

        // 1. Unsupported version.
        write_sidecar(serde_json::to_string(&PublicGroupBootstrapOutboxSidecar {
            version: PUBLIC_GROUP_BOOTSTRAP_OUTBOX_VERSION + 1,
            entries: vec![obligation.clone()],
        })?)
        .await?;
        assert!(
            load_public_group_bootstrap_outbox(&state).await.is_err(),
            "a future sidecar version must abort startup"
        );

        // 2. Over the 1024-entry cap.
        let mut over_cap = Vec::new();
        for index in 0..=PUBLIC_GROUP_BOOTSTRAP_OUTBOX_MAX_ENTRIES {
            let mut entry = obligation.clone();
            entry.key = format!("{}-{index}", obligation.key);
            over_cap.push(entry);
        }
        write_sidecar(serde_json::to_string(&PublicGroupBootstrapOutboxSidecar {
            version: PUBLIC_GROUP_BOOTSTRAP_OUTBOX_VERSION,
            entries: over_cap,
        })?)
        .await?;
        assert!(
            load_public_group_bootstrap_outbox(&state).await.is_err(),
            "an over-cap sidecar must abort startup"
        );

        // 3. Duplicate key.
        write_sidecar(serde_json::to_string(&PublicGroupBootstrapOutboxSidecar {
            version: PUBLIC_GROUP_BOOTSTRAP_OUTBOX_VERSION,
            entries: vec![obligation.clone(), obligation.clone()],
        })?)
        .await?;
        assert!(
            load_public_group_bootstrap_outbox(&state).await.is_err(),
            "a duplicate obligation key must abort startup"
        );

        // 4. Payload that no longer matches the frontier it claims.
        let mut tampered = obligation;
        tampered.state_revision = tampered.state_revision.saturating_add(1);
        write_sidecar(serde_json::to_string(&PublicGroupBootstrapOutboxSidecar {
            version: PUBLIC_GROUP_BOOTSTRAP_OUTBOX_VERSION,
            entries: vec![tampered],
        })?)
        .await?;
        assert!(
            load_public_group_bootstrap_outbox(&state).await.is_err(),
            "an obligation whose payload contradicts its frontier must abort startup"
        );
        Ok(())
    }

    /// Why: the cap bounds attacker- or bug-driven growth of a file the daemon
    /// must fully load before it will start.
    #[tokio::test]
    async fn upsert_refuses_to_exceed_the_entry_cap() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        {
            let mut outbox = state.public_group_bootstrap_outbox.write().await;
            let filler = test_obligation()?;
            for index in 0..PUBLIC_GROUP_BOOTSTRAP_OUTBOX_MAX_ENTRIES {
                let mut entry = filler.clone();
                entry.key = format!("filler-{index}");
                outbox.insert(entry.key.clone(), entry);
            }
        }
        let _guard = state
            .public_group_bootstrap_outbox_persistence_lock
            .lock()
            .await;
        let error = upsert_public_group_bootstrap_obligation_unlocked(&state, test_obligation()?)
            .await
            .expect_err("a full outbox must refuse a new obligation");
        assert!(
            error.to_string().contains("capacity"),
            "the refusal must name the cap: {error}"
        );
        Ok(())
    }

    /// Why: this is the headline invariant of ADR 0030 §5. A legacy v1 send
    /// proves only that bytes were accepted by a peer that cannot report
    /// installation, so treating it as completion would drop the obligation
    /// for a member who may hold nothing. It must reschedule instead.
    #[tokio::test]
    async fn legacy_v1_send_reschedules_and_never_completes() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let obligation = test_obligation()?;
        let key = obligation.key.clone();
        {
            let _guard = state
                .public_group_bootstrap_outbox_persistence_lock
                .lock()
                .await;
            upsert_public_group_bootstrap_obligation_unlocked(&state, obligation.clone()).await?;
        }

        let request_id =
            public_group_bootstrap_request_id(&obligation).map_err(|e| anyhow::anyhow!(e))?;
        settle_public_group_bootstrap_attempt(
            &state,
            &obligation,
            Ok(PublicGroupBootstrapDelivery::LegacyV1Sent(receipt(
                request_id,
            ))),
        )
        .await;

        let outbox = state.public_group_bootstrap_outbox.read().await;
        let retained = outbox
            .get(&key)
            .context("a v1 send must not discharge the obligation")?;
        assert_eq!(retained.attempt_count, 1, "the attempt must be recorded");
        assert!(
            retained.next_attempt_at_ms > obligation.next_attempt_at_ms,
            "the retry must be pushed out by the backoff"
        );
        Ok(())
    }

    /// Why: the mirror of the test above — a transport failure must also leave
    /// the debt in place, and only ever reschedule it.
    #[tokio::test]
    async fn failed_send_reschedules_and_never_completes() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let obligation = test_obligation()?;
        let key = obligation.key.clone();
        {
            let _guard = state
                .public_group_bootstrap_outbox_persistence_lock
                .lock()
                .await;
            upsert_public_group_bootstrap_obligation_unlocked(&state, obligation.clone()).await?;
        }

        settle_public_group_bootstrap_attempt(
            &state,
            &obligation,
            Err(x0x::dm::DmError::EnvelopeConstruction(
                "offline".to_string(),
            )),
        )
        .await;

        let outbox = state.public_group_bootstrap_outbox.read().await;
        let retained = outbox
            .get(&key)
            .context("a failed send must not discharge the obligation")?;
        assert_eq!(retained.attempt_count, 1);
        Ok(())
    }

    /// Why: a v2 ACK certifies durability, and the sender **deletes its
    /// obligation** on the strength of it. `Duplicate` therefore may not be
    /// answered off the in-memory roster: a previous write that renamed into
    /// place but failed its parent-directory fsync leaves the group visible in
    /// memory with `named_groups_requires_durability_confirmation` raised, and
    /// answering `Duplicate` there would trade the last durable record of the
    /// obligation for evidence that might not survive a power loss.
    ///
    /// Asserting the flag is cleared is what makes this a real guard: it can
    /// only be false if admission actually forced the durability confirmation
    /// before it answered.
    #[tokio::test]
    async fn duplicate_completion_requires_confirmed_durability() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let authority = x0x::identity::AgentKeypair::generate()?;
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let group = signed_public_group(&authority, &local_hex)?;
        let group_id = group.stable_group_id().to_string();

        state
            .contacts
            .write()
            .await
            .set_trust(&authority.agent_id(), x0x::contacts::TrustLevel::Trusted);

        let installed = group.clone();
        assert_eq!(
            persist_named_groups_mutation(&state, |groups| {
                groups.insert(group_id.clone(), installed);
                true
            })
            .await?,
            AtomicWriteOutcome::Durable
        );

        // Stand in for a prior rename-visible-but-not-fsynced roster write.
        state
            .named_groups_requires_durability_confirmation
            .store(true, Ordering::Release);

        let completion = admit_public_group_bootstrap(
            &state,
            authority.agent_id(),
            PublicGroupBootstrap {
                message_type: PUBLIC_GROUP_BOOTSTRAP_MESSAGE_TYPE.to_string(),
                group: Box::new(group),
            },
        )
        .await;

        assert_eq!(
            completion,
            Ok(x0x::dm_inbox::DmTypedPayloadCompletion::Duplicate),
            "a matching frontier that is durably present must answer Duplicate"
        );
        assert!(
            !state
                .named_groups_requires_durability_confirmation
                .load(Ordering::Acquire),
            "Duplicate must not be answered until durability has been re-confirmed"
        );
        Ok(())
    }

    /// Why: the roster, not the sidecar, decides who is owed a bootstrap. An
    /// obligation for a group this daemon no longer holds — or for someone no
    /// longer on its roster — would otherwise be retried forever against a
    /// debt that no longer exists.
    #[tokio::test]
    async fn reconciliation_drops_obligations_the_roster_no_longer_justifies() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let seeded = seeded_obligation(&state).await?;
        let orphan = test_obligation()?;
        {
            let mut outbox = state.public_group_bootstrap_outbox.write().await;
            outbox.insert(seeded.key.clone(), seeded.clone());
            outbox.insert(orphan.key.clone(), orphan.clone());
        }

        reconcile_public_group_bootstrap_outbox(&state).await?;

        let outbox = state.public_group_bootstrap_outbox.read().await;
        assert!(
            outbox.contains_key(&seeded.key),
            "an obligation whose group is on the roster must survive"
        );
        assert!(
            !outbox.contains_key(&orphan.key),
            "an obligation for an unknown group must be dropped, not retried forever"
        );
        Ok(())
    }

    /// The `fork_quarantine_refusals` counter for one group, read the way
    /// `GET /diagnostics/groups` builds it.
    async fn refusals_for(state: &AppState, group_id: &str) -> u64 {
        let groups_snapshot = state.named_groups.read().await.clone();
        state
            .groups_diagnostics
            .snapshot(
                &groups_snapshot,
                &std::collections::HashSet::new(),
                &std::collections::HashSet::new(),
                &std::collections::HashMap::new(),
                state.groups_config.mandate_grace_days,
            )
            .groups
            .into_iter()
            .find(|g| g.group_id == group_id)
            .map_or(0, |g| g.counters.fork_quarantine_refusals)
    }

    /// ADR-0066 §3c row 21 — the marker must NEVER ride an outbound payload.
    ///
    /// WHY as a validation failure rather than a filter: this is the one
    /// census path that EXPORTS state to another node, and a bootstrap
    /// snapshot is installed verbatim by its recipient. Containment is
    /// per-node by ADR-0064's design, so a marker on the wire would both leak
    /// local forensic state and quarantine a group on a peer that has no
    /// evidence of the fork. `signed_public_bootstrap_snapshot` strips it
    /// today; this assertion is what makes a future refactor of that
    /// stripping list a refusal to write and a refusal to start, instead of a
    /// silent leak.
    #[test]
    fn adr0066_row21_an_obligation_payload_may_never_carry_the_marker() -> Result<()> {
        let authority = x0x::identity::AgentKeypair::generate()?;
        let recipient = x0x::identity::AgentKeypair::generate()?;
        let mut group =
            signed_public_group(&authority, &hex::encode(recipient.agent_id().as_bytes()))?;
        // Control: the honestly-prepared obligation validates.
        let clean = prepare_public_group_bootstrap_obligation(recipient.agent_id(), group.clone())
            .map_err(|error| anyhow::anyhow!(error))?;
        validate_public_group_bootstrap_obligation(&clean)
            .context("control: a stripped snapshot validates")?;

        // Now smuggle a marker into the payload, re-deriving every digest so
        // the ONLY thing left for the validator to object to is the marker.
        group.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: group.state_revision,
            state_hash: group.state_hash.clone(),
            committed_by: "9e".repeat(32),
            observed_at_ms: 1_726_000_000_000,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: group.terminal_commit_header(),
                conflicting_commit: group.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        });
        let smuggled = prepare_public_group_bootstrap_obligation(recipient.agent_id(), group)
            .map_err(|error| anyhow::anyhow!(error))?;
        let refused = validate_public_group_bootstrap_obligation(&smuggled);
        assert!(
            refused.is_err(),
            "a payload carrying the fork-quarantine marker must never be \
             storable or sendable"
        );
        Ok(())
    }

    /// ADR-0066 §3c row 21 — the worker withholds a contested group's
    /// snapshot, and does so WITHOUT destroying the debt.
    ///
    /// WHY both halves matter. Withholding is the containment: this is the
    /// highest-severity ungated path in the §1 census after §2, because a
    /// background job publishing one branch of a contested chain propagates
    /// the fork to a peer with nobody watching. Retaining is the
    /// availability: an ordinary group's marker never auto-clears, so
    /// dropping the obligation would leave a member permanently on the
    /// roster with nobody remembering to bootstrap them — the failure this
    /// outbox exists to prevent. The control arm is what proves the
    /// withholding is real: with no marker the SAME call attempts delivery
    /// and records the attempt in the obligation's retry state.
    /// A marker in whichever branch the caller wants, at an explicit
    /// revision.
    ///
    /// WHY the revision is a parameter rather than a constant: the row-21
    /// dedupe (`LOGGED_PUBLICATION_REFUSALS`) is process-global and keyed by
    /// `(group id, revision)`, and every fixture here shares one mls group id,
    /// so two tests at the same revision would have the second one's counter
    /// assertion silently absorbed by the first one's dedupe entry. Each test
    /// in this file owns a revision.
    fn quarantine_marker(
        info: &x0x::groups::GroupInfo,
        revision: u64,
    ) -> x0x::groups::ForkQuarantine {
        x0x::groups::ForkQuarantine {
            revision,
            state_hash: info.state_hash.clone(),
            committed_by: "9e".repeat(32),
            observed_at_ms: 1_726_000_000_000,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        }
    }

    /// Install (or clear) the marker on whichever roster entry holds the group
    /// with this stable id, whatever key it is filed under.
    async fn set_marker(state: &AppState, stable_id: &str, revision: Option<u64>) {
        let mut groups = state.named_groups.write().await;
        for info in groups.values_mut() {
            if info.stable_group_id() == stable_id {
                info.fork_quarantine = revision.map(|r| quarantine_marker(info, r));
            }
        }
    }

    #[tokio::test]
    async fn adr0066_row21_worker_withholds_a_contested_snapshot_and_keeps_the_debt() -> Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let obligation = seeded_obligation(&state).await?;
        state
            .public_group_bootstrap_outbox
            .write()
            .await
            .insert(obligation.key.clone(), obligation.clone());
        let group_id = obligation.group_id.clone();
        assert!(
            !state
                .named_groups_requires_durability_confirmation
                .load(Ordering::Acquire),
            "fixture precondition: the worker must not be deferring for an \
             unrelated reason, or 'nothing was sent' proves nothing"
        );

        // The quarantined arm runs FIRST, on an untouched obligation: R5's
        // no-grace rule is about the FIRST due obligation after the marker
        // installs, so the evidence must not come from one that has already
        // been through a retry cycle.
        set_marker(&state, &group_id, Some(31)).await;
        let refusals_before = refusals_for(&state, &group_id).await;

        public_group_bootstrap_outbox_step(&state).await;

        let withheld = state
            .public_group_bootstrap_outbox
            .read()
            .await
            .get(&obligation.key)
            .cloned()
            .context(
                "the debt must SURVIVE the suppression — a dropped obligation \
                 is a member nobody remembers to bootstrap, and a no_anchor \
                 marker never clears itself",
            )?;
        assert_eq!(
            withheld.attempt_count, obligation.attempt_count,
            "no delivery was attempted: the attempt counter did not move"
        );
        assert_eq!(
            withheld.next_attempt_at_ms, obligation.next_attempt_at_ms,
            "and the schedule was not touched, so delivery resumes by itself \
             once the marker is cleared"
        );
        assert_eq!(
            withheld.payload, obligation.payload,
            "nor was the stored payload refreshed from the contested frontier"
        );
        let refusals_after = refusals_for(&state, &group_id).await;
        assert_eq!(
            refusals_after,
            refusals_before + 1,
            "§3e: one `fork_quarantine_refusals` increment for the withheld \
             publication — the shared helper's, not a per-route counter"
        );

        // The dedupe: a POLLING worker must not turn a fleet-health counter
        // into a measure of uptime. A second pass at the same marker revision
        // withholds again and records nothing new.
        public_group_bootstrap_outbox_step(&state).await;
        assert_eq!(
            refusals_for(&state, &group_id).await,
            refusals_after,
            "one record per (group, fork observation), not one per poll"
        );

        // CONTROL, in the other direction: after the manual clear the SAME
        // worker pass attempts delivery. There is no peer, so the attempt
        // fails and is rescheduled — and that movement is precisely the
        // observable whose ABSENCE above proved the snapshot was withheld.
        set_marker(&state, &group_id, None).await;
        public_group_bootstrap_outbox_step(&state).await;
        let resumed = state
            .public_group_bootstrap_outbox
            .read()
            .await
            .values()
            .find(|entry| entry.group_id == group_id)
            .cloned()
            .context("control: the obligation survives a failed attempt")?;
        assert!(
            resumed.attempt_count > obligation.attempt_count,
            "control: with no marker the worker attempts delivery and records \
             the attempt — the manual clear is the exit for row 21 too"
        );
        Ok(())
    }

    /// ADR-0066 §3c row 21, review r1 — a contested group must not starve a
    /// healthy one.
    ///
    /// WHY this fixture exists and why every other row-21 test missed the
    /// defect: a worker pass delivers at most ONE obligation, chosen as the
    /// minimum `(next_attempt_at_ms, created_at_ms)` among the due ones, and a
    /// withheld obligation is deliberately never rescheduled. Gate the
    /// publication only AFTER selection and those two properties compose into
    /// permanent head-of-line blocking: the contested obligation is the
    /// minimum, is re-picked every tick, is withheld, and no other group's
    /// bootstrap is ever delivered — for a `no_anchor` marker, until a human
    /// intervenes, with nothing but a per-tick `debug!` to show for it.
    /// Containment turning into a fleet-wide bootstrap outage is a worse
    /// availability failure than the one the row was closing. Every earlier
    /// row-21 fixture used a single group, so none of them could see it.
    ///
    /// The NEGATIVE CONTROL is inline and explicit: the test re-computes the
    /// pre-fix selection (the same `min_by_key` without the quarantine filter)
    /// and asserts it picks the CONTESTED group — so the healthy delivery
    /// asserted afterwards is attributable to the filter and to nothing else.
    #[tokio::test]
    async fn adr0066_row21_a_contested_group_does_not_starve_a_healthy_one() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let mut contested = seeded_obligation_for(&state, &"ab".repeat(32)).await?;
        let mut healthy = seeded_obligation_for(&state, &"ef".repeat(32)).await?;
        assert_ne!(
            contested.group_id, healthy.group_id,
            "fixture precondition: two DISTINCT groups, which is the whole point"
        );
        // Both due; the contested one sorts first, so it owns the head of the
        // line.
        contested.next_attempt_at_ms = 0;
        contested.created_at_ms = 1;
        healthy.next_attempt_at_ms = 0;
        healthy.created_at_ms = 2;
        {
            let mut outbox = state.public_group_bootstrap_outbox.write().await;
            outbox.insert(contested.key.clone(), contested.clone());
            outbox.insert(healthy.key.clone(), healthy.clone());
        }
        set_marker(&state, &contested.group_id, Some(34)).await;

        // NEGATIVE CONTROL: the pre-fix selection, recomputed here.
        let unfiltered_pick = state
            .public_group_bootstrap_outbox
            .read()
            .await
            .values()
            .filter(|o| o.next_attempt_at_ms <= now_millis_u64())
            .min_by_key(|o| (o.next_attempt_at_ms, o.created_at_ms))
            .map(|o| o.group_id.clone());
        assert_eq!(
            unfiltered_pick.as_deref(),
            Some(contested.group_id.as_str()),
            "control: selecting without the quarantine filter picks the CONTESTED \
             group — which it would then withhold and return from, delivering \
             nothing, on this tick and every tick after it"
        );

        public_group_bootstrap_outbox_step(&state).await;

        let outbox = state.public_group_bootstrap_outbox.read().await;
        let healthy_now = outbox
            .get(&healthy.key)
            .context("the healthy obligation is still owed")?;
        assert!(
            healthy_now.attempt_count > healthy.attempt_count,
            "the HEALTHY group was attempted on this very tick: one group's \
             containment must not be an outage for every other group"
        );
        let contested_now = outbox
            .get(&contested.key)
            .context("and the contested debt still stands")?;
        assert_eq!(
            contested_now.attempt_count, contested.attempt_count,
            "while the contested group was still not published"
        );
        assert_eq!(
            contested_now.next_attempt_at_ms, contested.next_attempt_at_ms,
            "and its schedule is still frozen, so it resumes the moment the \
             marker is cleared"
        );
        Ok(())
    }

    /// ADR-0066 §3c row 21, review r1 — the withheld obligation delivers on
    /// the FIRST pass after the manual clear.
    ///
    /// WHY as a separate test from the starvation one: the runbook promises an
    /// operator that clearing the marker is the whole remedy and that delivery
    /// resumes by itself. That promise rests on the filter being re-evaluated
    /// from live roster state every pass AND on the withheld obligation's
    /// schedule never having been advanced — if the fix had instead
    /// rescheduled with backoff, resumption would lag by up to the clamp and
    /// the promise would need re-wording. This test is what makes "the next
    /// pass" true rather than hoped, with no sleeping and no wall-clock
    /// dependence.
    #[tokio::test]
    async fn adr0066_row21_clearing_the_marker_delivers_on_the_next_pass() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let obligation = seeded_obligation(&state).await?;
        state
            .public_group_bootstrap_outbox
            .write()
            .await
            .insert(obligation.key.clone(), obligation.clone());
        set_marker(&state, &obligation.group_id, Some(35)).await;

        // Several passes while quarantined change nothing at all.
        for _ in 0..3 {
            public_group_bootstrap_outbox_step(&state).await;
        }
        let still = state
            .public_group_bootstrap_outbox
            .read()
            .await
            .get(&obligation.key)
            .cloned()
            .context("the debt survives every withheld pass")?;
        assert_eq!(
            (still.attempt_count, still.next_attempt_at_ms),
            (obligation.attempt_count, obligation.next_attempt_at_ms),
            "no pass moved it — so it is still due the instant the marker goes"
        );

        set_marker(&state, &obligation.group_id, None).await;
        public_group_bootstrap_outbox_step(&state).await;

        let resumed = state
            .public_group_bootstrap_outbox
            .read()
            .await
            .values()
            .find(|entry| entry.group_id == obligation.group_id)
            .cloned()
            .context("still owed after a failed attempt")?;
        assert!(
            resumed.attempt_count > obligation.attempt_count,
            "the FIRST pass after the clear attempts delivery — no backoff to \
             wait out, which is what the runbook's 'resumes by itself' means"
        );
        Ok(())
    }

    /// ADR-0066 §3c row 21, review r1 — a RE-quarantine at the same revision
    /// is a new fork observation and must be recorded again.
    ///
    /// WHY: keying the log/counter dedupe on `(group, revision)` alone means
    /// an operator who clears a marker and then meets the same revision again
    /// sees nothing in the log until the daemon restarts — a second incident
    /// that looks exactly like no incident. Adding the marker's
    /// `observed_at_ms` to the key distinguishes "the same marker, polled
    /// again" (suppress) from "quarantined again" (record), which is the
    /// distinction the operator actually cares about.
    #[tokio::test]
    async fn adr0066_row21_requarantine_at_the_same_revision_is_recorded_again() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let obligation = seeded_obligation(&state).await?;
        let group_id = obligation.group_id.clone();
        let mut marker = {
            let groups = state.named_groups.read().await;
            let info = groups
                .values()
                .find(|info| info.stable_group_id() == group_id)
                .context("fixture group")?;
            quarantine_marker(info, 36)
        };

        set_marker(&state, &group_id, Some(36)).await;
        let first = refusals_for(&state, &group_id).await;
        record_withheld_publication(&state, &group_id, &marker);
        let after_first = refusals_for(&state, &group_id).await;
        assert_eq!(after_first, first + 1, "the first observation records");
        record_withheld_publication(&state, &group_id, &marker);
        assert_eq!(
            refusals_for(&state, &group_id).await,
            after_first,
            "polling the SAME observation does not record again"
        );

        // Cleared, then quarantined again at the same revision: a different
        // local observation time, so the operator hears about it.
        marker.observed_at_ms += 1;
        record_withheld_publication(&state, &group_id, &marker);
        assert_eq!(
            refusals_for(&state, &group_id).await,
            after_first + 1,
            "a re-quarantine at the same revision is a NEW fork observation and \
             must not be swallowed by the dedupe"
        );
        Ok(())
    }

    /// ADR-0066 §3c row 21 — reconciliation RETAINS a contested group's
    /// obligation instead of dropping it, and declines to refresh it.
    ///
    /// WHY this is not `continue` like the `withdrawn` arm beside it: a
    /// withdrawn group is gone and its debt is void, whereas a fork is a
    /// dispute that a human is expected to resolve with the manual clear. The
    /// contrast is asserted in one test so a future edit that "tidies" the
    /// two arms into one has to break a test that explains the difference.
    #[tokio::test]
    async fn adr0066_row21_reconciliation_retains_rather_than_drops_a_contested_debt() -> Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let seeded = seeded_obligation(&state).await?;
        state
            .public_group_bootstrap_outbox
            .write()
            .await
            .insert(seeded.key.clone(), seeded.clone());

        // Advance the group's frontier so reconciliation WOULD refresh the
        // stored payload, then quarantine it. Both effects are then visible:
        // retained, and not refreshed.
        {
            let mut groups = state.named_groups.write().await;
            for info in groups.values_mut() {
                if info.stable_group_id() == seeded.group_id {
                    info.state_revision = info.state_revision.saturating_add(1);
                    info.fork_quarantine = Some(quarantine_marker(info, 32));
                }
            }
        }

        reconcile_public_group_bootstrap_outbox(&state).await?;

        let after = state.public_group_bootstrap_outbox.read().await;
        let kept = after.get(&seeded.key).context(
            "a contested group's debt must be RETAINED under its \
                      original key, not dropped and not re-keyed",
        )?;
        assert_eq!(
            kept.payload, seeded.payload,
            "and not re-derived from the contested frontier"
        );
        assert_eq!(
            kept.state_revision, seeded.state_revision,
            "the stored frontier is the one that was committed before the fork \
             evidence arrived"
        );
        Ok(())
    }

    /// ADR-0066 §3c row 21 — the alias-key regression, with its negative
    /// control.
    ///
    /// WHY this shape is mandatory here specifically: an obligation records
    /// `group.stable_group_id()`, while the roster map is keyed by whichever
    /// alias this daemon learned the group under. So the worker arrives at the
    /// gate holding the STABLE id while the marker sits under the ALIAS — the
    /// two-spelling case is the normal case for this row, not an exotic one.
    /// The first assertion is the negative control: the single-spelling read a
    /// gate must not use provably misses, which is what makes the rest of the
    /// test evidence about the resolver rather than about luck.
    #[tokio::test]
    async fn adr0066_row21_gate_resolves_a_group_keyed_by_an_alias() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let authority = x0x::identity::AgentKeypair::generate()?;
        let recipient = x0x::identity::AgentKeypair::generate()?;
        let mut group =
            signed_public_group(&authority, &hex::encode(recipient.agent_id().as_bytes()))?;
        let stable_id = group.stable_group_id().to_string();
        let alias_key = format!("alias-{}", "7c".repeat(8));
        assert_ne!(
            alias_key, stable_id,
            "fixture precondition: the map key is NOT the stable id"
        );
        group.fork_quarantine = Some(quarantine_marker(&group, 33));
        state
            .named_groups
            .write()
            .await
            .insert(alias_key.clone(), group);

        // NEGATIVE CONTROL: the single-spelling lookup misses entirely.
        assert!(
            state.named_groups.read().await.get(&stable_id).is_none(),
            "control: `groups.get(stable_id)` misses an alias-keyed group — a \
             gate built on it would publish exactly the contested groups whose \
             two names differ"
        );

        assert!(
            withhold_bootstrap_publication(&state, &stable_id).await,
            "the gate must withhold when handed the STABLE id the obligation \
             carries, with the marker filed under the alias"
        );
        assert!(
            withhold_bootstrap_publication(&state, &alias_key).await,
            "and the direct key hit still works — the fallback is additive"
        );

        // Control in the other direction: a clean group is published. Without
        // this, a gate that withheld unconditionally would pass everything
        // above.
        assert!(
            !withhold_bootstrap_publication(&state, &"e5".repeat(16)).await,
            "a group this daemon holds no marker for is never withheld"
        );
        Ok(())
    }

    /// Why: cancellation on removal must be exact. Dropping obligations for
    /// other members or other groups would strand them exactly as the
    /// fire-and-forget path did.
    #[tokio::test]
    async fn cancellation_removes_only_the_matching_recipient_and_group() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let removed = test_obligation()?;
        let survivor = test_obligation()?;
        {
            let mut outbox = state.public_group_bootstrap_outbox.write().await;
            outbox.insert(removed.key.clone(), removed.clone());
            outbox.insert(survivor.key.clone(), survivor.clone());
        }

        cancel_public_group_bootstrap_obligations(
            &state,
            &removed.recipient_hex,
            &removed.group_id,
        )
        .await?;

        let outbox = state.public_group_bootstrap_outbox.read().await;
        assert!(!outbox.contains_key(&removed.key), "the debt was cancelled");
        assert!(
            outbox.contains_key(&survivor.key),
            "an unrelated member's obligation must be untouched"
        );
        Ok(())
    }
}
