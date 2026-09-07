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
    let Some(candidate_group_id) = state
        .public_group_bootstrap_outbox
        .read()
        .await
        .values()
        .filter(|obligation| obligation.next_attempt_at_ms <= now_ms)
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
        let authority_hex = hex::encode(authority.agent_id().as_bytes());
        let recipient_hex = recipient_hex.to_string();
        let mut group = x0x::groups::GroupInfo::with_policy(
            "Outbox".to_string(),
            String::new(),
            authority.agent_id(),
            "cd".repeat(32),
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
        let authority = x0x::identity::AgentKeypair::generate()?;
        let recipient = x0x::identity::AgentKeypair::generate()?;
        let group = signed_public_group(&authority, &hex::encode(recipient.agent_id().as_bytes()))?;
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
