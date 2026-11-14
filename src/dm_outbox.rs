//! #1109: durable `deliver_until` direct messages.
//!
//! `POST /direct/send` with `deliver_until` admits a [`DmObligation`] and
//! answers 202 at once. The obligation is the first direct-message user of
//! the generic [`Outbox`] (#1365): it is written to a private sidecar
//! (`<data_dir>/dm_obligations.json`, 0600) before the 202, survives a
//! restart, and a worker sends it again with the same logical id until:
//!
//! - a send succeeds (the recipient's v2 ACK, or a loopback send): the
//!   obligation leaves the outbox and the receipt ledger records
//!   `delivered`;
//! - the deadline passes: the obligation leaves the outbox and the ledger
//!   records `expired`;
//! - the recipient refuses in a way a retry cannot change (trust
//!   rejection, pairing denial, idempotency conflict, payload too large):
//!   the ledger records `failed`.
//!
//! Every other error is a retry. That includes the cold recipient: no
//! verified v2 capability advert yet (`recipient_ack_semantics_unavailable`,
//! `recipient_capability_pending`, `recipient_key_unavailable`). The
//! obligation is held, and the #1158 advert signal makes it due as soon as
//! the recipient's verified advert arrives.
//!
//! The same logical id on every attempt means the recipient stores one
//! copy and ACKs a repeat (ADR 0030 §1), so a retry never delivers twice.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::dm::{DmError, DmLogicalId, DmReceiptStatus, DmSendConfig, InFlightAcks};
use crate::identity::AgentId;
use crate::storage::outbox::{Outbox, OutboxCaps, OutboxMap, OutboxRecord, Settled};

/// Sidecar file name under the daemon data directory.
pub(crate) const DM_OBLIGATION_FILE: &str = "dm_obligations.json";

/// Sidecar format version.
const DM_OBLIGATION_VERSION: u32 = 1;

/// The longest `deliver_until` the daemon accepts, from now.
pub const DM_DELIVER_UNTIL_MAX_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Caps. One partition is one recipient. A local caller at the cap is
/// refused (`dm_outbox_full`), never allowed to evict another obligation.
pub(crate) const DM_OBLIGATION_CAPS: OutboxCaps = OutboxCaps {
    per_partition: 256,
    per_partition_bytes: 4 * 1024 * 1024,
    total: 2_048,
    total_bytes: 32 * 1024 * 1024,
};

/// Retry offsets in seconds after each failed attempt; the last repeats.
/// The #1158 advert signal cuts a wait short for a cold recipient.
pub(crate) const DM_OBLIGATION_RETRY_SECS: &[u64] = &[2, 5, 15, 30, 60, 120];

/// Most sends one worker pass starts. The rest wait for the next pass.
pub(crate) const DM_OBLIGATION_SENDS_PER_PASS: usize = 16;

/// One durable `deliver_until` direct message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmObligation {
    /// Recipient agent id (hex). The partition.
    pub recipient_agent_id: String,
    /// The caller's (or the daemon's) logical id. The id in the partition.
    pub logical_id: String,
    /// The wire request id the logical id derives for this pair (hex).
    pub request_id: String,
    /// The payload bytes, sent unchanged on every attempt.
    pub payload: Vec<u8>,
    /// Unix-epoch millis after which nothing more is sent.
    pub deliver_until_ms: u64,
    /// Unix-epoch millis when the obligation was admitted.
    pub first_seen_ms: u64,
    /// Unix-epoch millis of the next attempt.
    pub next_retry_at_ms: u64,
    /// Attempts completed so far.
    pub retry_count: u32,
    /// The API error code of the last failed attempt, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl DmObligation {
    /// A new obligation from `self_agent` to `recipient`, first due at
    /// `now_ms`. The request id is the one `logical_id` derives for this
    /// directed pair, the same id a synchronous send would use.
    #[must_use]
    pub fn new(
        self_agent: AgentId,
        recipient: AgentId,
        logical_id: &DmLogicalId,
        payload: Vec<u8>,
        deliver_until_ms: u64,
        now_ms: u64,
    ) -> Self {
        Self {
            recipient_agent_id: hex::encode(recipient.as_bytes()),
            logical_id: logical_id.as_str().to_string(),
            request_id: hex::encode(logical_id.request_id(self_agent, recipient)),
            payload,
            deliver_until_ms,
            first_seen_ms: now_ms,
            next_retry_at_ms: now_ms,
            retry_count: 0,
            last_error: None,
        }
    }

    /// The recipient as an [`AgentId`], when the stored hex is valid.
    fn recipient(&self) -> Option<AgentId> {
        let bytes = hex::decode(&self.recipient_agent_id).ok()?;
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        Some(AgentId(bytes))
    }

    /// The request id as bytes, when the stored hex is valid.
    fn request_id_bytes(&self) -> Option<[u8; 16]> {
        let bytes = hex::decode(&self.request_id).ok()?;
        bytes.try_into().ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DmObligationFile {
    version: u32,
    #[serde(default)]
    by_recipient: OutboxMap<DmObligation>,
}

impl OutboxRecord for DmObligation {
    const LABEL: &'static str = "dm obligation outbox";

    fn partition(&self) -> &str {
        &self.recipient_agent_id
    }

    fn id(&self) -> &str {
        &self.logical_id
    }

    fn first_seen_ms(&self) -> u64 {
        self.first_seen_ms
    }

    fn byte_size(&self) -> usize {
        self.payload.len()
    }

    fn next_retry_at_ms(&self) -> u64 {
        self.next_retry_at_ms
    }

    fn retry_count(&self) -> u32 {
        self.retry_count
    }

    fn set_schedule(&mut self, retry_count: u32, next_retry_at_ms: u64) {
        self.retry_count = retry_count;
        self.next_retry_at_ms = next_retry_at_ms;
    }

    /// The stored request id must be the one the logical id derives for
    /// this pair's recipient; the sender half is checked at send time.
    fn check(&self) -> Result<(), String> {
        if self.recipient().is_none() {
            return Err(format!("bad recipient on {}", self.logical_id));
        }
        if DmLogicalId::parse(&self.logical_id).is_err() {
            return Err(format!("bad logical id {:?}", self.logical_id));
        }
        if self.request_id_bytes().is_none() {
            return Err(format!("bad request id on {}", self.logical_id));
        }
        if self.payload.len() > crate::dm::MAX_PAYLOAD_BYTES {
            return Err(format!("payload too large on {}", self.logical_id));
        }
        Ok(())
    }

    fn encode(map: &OutboxMap<Self>) -> Result<Vec<u8>, String> {
        let file = DmObligationFile {
            version: DM_OBLIGATION_VERSION,
            by_recipient: map.clone(),
        };
        serde_json::to_vec(&file).map_err(|e| format!("failed to encode dm obligation outbox: {e}"))
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<OutboxMap<Self>, String> {
        let file: DmObligationFile = serde_json::from_slice(bytes)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
        if file.version != DM_OBLIGATION_VERSION {
            return Err(format!(
                "{}: unsupported dm obligation outbox version {} (expected {DM_OBLIGATION_VERSION})",
                path.display(),
                file.version
            ));
        }
        Ok(file.by_recipient)
    }
}

/// Why an obligation was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmObligationRefusal {
    /// The same logical id to the same recipient is held with other bytes.
    IdempotencyConflict,
    /// The outbox is at its count or byte cap.
    Full,
    /// The durable write failed; nothing was admitted.
    Storage(String),
}

/// What one admission did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmObligationAdmission {
    /// A new obligation was stored.
    Admitted,
    /// The same obligation (same bytes) was already held.
    AlreadyHeld,
}

/// How an attempt ended, as the worker classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptOutcome {
    /// Delivered: remove and record `delivered`.
    Delivered,
    /// A retry cannot change this: remove and record `failed`.
    Refused,
    /// Keep and retry later.
    Retry,
}

/// Classify a send error for an obligation. Only refusals that a retry with
/// the same bytes cannot change are final; every other error, the cold
/// recipient included, is a retry.
pub(crate) fn classify(result: &Result<(), DmError>) -> AttemptOutcome {
    match result {
        Ok(()) => AttemptOutcome::Delivered,
        Err(
            DmError::RecipientRejected { .. }
            | DmError::RecipientPairingDenied { .. }
            | DmError::IdempotencyConflict(_)
            | DmError::PayloadTooLarge { .. },
        ) => AttemptOutcome::Refused,
        Err(_) => AttemptOutcome::Retry,
    }
}

/// The API error code of a failed attempt (as `POST /direct/send` names
/// it), stored on the obligation for the receipt query.
pub(crate) fn error_code(error: &DmError) -> &'static str {
    match error {
        DmError::RecipientRejected { .. } => "recipient_rejected",
        DmError::RecipientPairingDenied { .. } => "recipient_pairing_denied",
        DmError::RecipientKeyUnavailable(_) => "recipient_key_unavailable",
        DmError::RecipientKeyInvalid(_) => "recipient_key_invalid",
        DmError::RecipientUndiscovered(_) => "recipient_undiscovered",
        DmError::RecipientUpgradeRequired { .. } => "recipient_upgrade_required",
        DmError::RecipientCapabilityPending { .. } => "recipient_capability_pending",
        DmError::RecipientCapabilityUnavailable { .. } => "recipient_capability_unavailable",
        DmError::AckSemanticsUnavailable(_) => "recipient_ack_semantics_unavailable",
        DmError::IdempotencyConflict(_) => "idempotency_conflict",
        DmError::Timeout { .. } => "timeout",
        DmError::PeerLikelyOffline { .. } => "peer_likely_offline",
        DmError::PeerDisconnected { .. } => "peer_disconnected",
        DmError::ReceiverBackpressured { .. } => "receiver_backpressured",
        DmError::LocalGossipUnavailable(_) => "local_gossip_unavailable",
        DmError::EnvelopeConstruction(_) => "envelope_construction",
        DmError::PayloadTooLarge { .. } => "payload_too_large",
        DmError::NoConnectivity(_) => "no_connectivity",
        DmError::PublishFailed(_) => "publish_failed",
        DmError::NoRelayCandidate => "no_relay_candidate",
        DmError::RelayBuildFailed(_) => "relay_build_failed",
    }
}

/// The send one obligation attempt makes. The daemon sends through the
/// [`crate::Agent`]; tests supply a scripted sender.
pub(crate) trait ObligationSender {
    /// Send `payload` to `to` with `config`.
    fn send(
        &self,
        to: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
    ) -> impl std::future::Future<Output = Result<(), DmError>> + Send;
}

impl ObligationSender for crate::Agent {
    async fn send(
        &self,
        to: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
    ) -> Result<(), DmError> {
        self.send_direct_with_config(&to, payload, config)
            .await
            .map(|_receipt| ())
    }
}

/// What one worker pass did (for logs and tests).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DmObligationPass {
    /// Logical ids delivered in this pass.
    pub delivered: Vec<String>,
    /// Logical ids that reached their deadline.
    pub expired: Vec<String>,
    /// Logical ids refused for good.
    pub failed: Vec<String>,
    /// Logical ids kept for a later attempt.
    pub retried: Vec<String>,
}

/// The daemon's `deliver_until` obligations: the storage the generic
/// [`Outbox`] is a view over.
pub struct DmObligationStore {
    entries: RwLock<OutboxMap<DmObligation>>,
    path: PathBuf,
    persist_lock: Mutex<()>,
}

impl DmObligationStore {
    /// A store whose sidecar is `<data_dir>/dm_obligations.json`. Call
    /// [`Self::load`] at boot.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            entries: RwLock::new(OutboxMap::new()),
            path: data_dir.join(DM_OBLIGATION_FILE),
            persist_lock: Mutex::new(()),
        }
    }

    fn outbox(&self) -> Outbox<'_, DmObligation> {
        Outbox::new(
            &self.entries,
            &self.path,
            &self.persist_lock,
            DM_OBLIGATION_CAPS,
        )
    }

    /// Load the sidecar at boot. Missing is empty; a file that fails a
    /// check is moved aside and the store starts empty (the error is
    /// returned).
    pub async fn load(&self, now_ms: u64) -> Result<(), String> {
        self.outbox().load(now_ms).await
    }

    /// The held obligation for `(recipient, logical_id)`, if any.
    pub async fn find(&self, recipient: &AgentId, logical_id: &str) -> Option<DmObligation> {
        let recipient_hex = hex::encode(recipient.as_bytes());
        self.entries
            .read()
            .await
            .get(&recipient_hex)
            .and_then(|list| list.iter().find(|o| o.logical_id == logical_id))
            .cloned()
    }

    /// Number of held obligations.
    pub async fn len(&self) -> usize {
        self.entries.read().await.values().map(Vec::len).sum()
    }

    /// True when no obligation is held.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Admit `obligation` durably. A repeat with the same bytes is
    /// [`DmObligationAdmission::AlreadyHeld`]; other bytes under the same
    /// logical id are refused; at a cap the caller is refused, so a local
    /// caller cannot evict other obligations.
    pub async fn admit(
        &self,
        obligation: DmObligation,
    ) -> Result<DmObligationAdmission, DmObligationRefusal> {
        {
            let entries = self.entries.read().await;
            let held = entries
                .get(&obligation.recipient_agent_id)
                .and_then(|list| list.iter().find(|o| o.logical_id == obligation.logical_id));
            if let Some(held) = held {
                return if held.payload == obligation.payload {
                    Ok(DmObligationAdmission::AlreadyHeld)
                } else {
                    Err(DmObligationRefusal::IdempotencyConflict)
                };
            }
            let partition = entries.get(&obligation.recipient_agent_id);
            let partition_count = partition.map_or(0, Vec::len);
            let partition_bytes: usize = partition
                .map(|list| list.iter().map(OutboxRecord::byte_size).sum())
                .unwrap_or(0);
            let total: usize = entries.values().map(Vec::len).sum();
            let total_bytes: usize = entries
                .values()
                .flatten()
                .map(OutboxRecord::byte_size)
                .sum();
            let size = obligation.payload.len();
            if partition_count >= DM_OBLIGATION_CAPS.per_partition
                || partition_bytes.saturating_add(size) > DM_OBLIGATION_CAPS.per_partition_bytes
                || total >= DM_OBLIGATION_CAPS.total
                || total_bytes.saturating_add(size) > DM_OBLIGATION_CAPS.total_bytes
            {
                return Err(DmObligationRefusal::Full);
            }
        }
        match self.outbox().insert(obligation).await {
            Ok(()) => Ok(DmObligationAdmission::Admitted),
            // After the rename the obligation is on disk and in memory
            // (#1101); only the directory fsync is unconfirmed.
            Err(e) if e.crossed_rename() => Ok(DmObligationAdmission::Admitted),
            Err(e) => Err(DmObligationRefusal::Storage(e.to_string())),
        }
    }

    /// #1158: `recipient`'s verified capability advert arrived. Make its
    /// held obligations due now. True when any matched.
    pub async fn nudge_for(&self, recipient: &AgentId, now_ms: u64) -> bool {
        let recipient_hex = hex::encode(recipient.as_bytes());
        self.outbox()
            .nudge(now_ms, |o| o.recipient_agent_id == recipient_hex)
            .await
    }

    /// One worker pass at `now_ms`: expire obligations past their deadline,
    /// send up to [`DM_OBLIGATION_SENDS_PER_PASS`] due ones with
    /// `base_config` plus the obligation's logical request id, record final
    /// outcomes in `acks`, and persist the new schedule.
    pub(crate) async fn step<S: ObligationSender + Sync>(
        &self,
        sender: &S,
        self_agent: AgentId,
        base_config: &DmSendConfig,
        acks: &InFlightAcks,
        now_ms: u64,
    ) -> DmObligationPass {
        let due = self.outbox().due(now_ms).await;
        if due.is_empty() {
            return DmObligationPass::default();
        }
        let mut pass = DmObligationPass::default();
        let mut resolved: Vec<DmObligation> = Vec::new();
        let mut attempts: Vec<(DmObligation, bool)> = Vec::new();
        let mut to_send: Vec<(DmObligation, AgentId, [u8; 16])> = Vec::new();
        for obligation in due {
            let (Some(recipient), Some(request_id), Ok(logical_id)) = (
                obligation.recipient(),
                obligation.request_id_bytes(),
                DmLogicalId::parse(&obligation.logical_id),
            ) else {
                // `check` refuses these at load; keep the store clean anyway.
                pass.failed.push(obligation.logical_id.clone());
                resolved.push(obligation);
                continue;
            };
            if logical_id.request_id(self_agent, recipient) != request_id {
                // Admitted under another agent identity: the recipient would
                // dedupe a different id, so sending it would not be a retry.
                acks.record_outcome(request_id, recipient, DmReceiptStatus::Failed);
                pass.failed.push(obligation.logical_id.clone());
                resolved.push(obligation);
                continue;
            }
            if now_ms >= obligation.deliver_until_ms {
                acks.record_outcome(request_id, recipient, DmReceiptStatus::Expired);
                pass.expired.push(obligation.logical_id.clone());
                resolved.push(obligation);
                continue;
            }
            if to_send.len() < DM_OBLIGATION_SENDS_PER_PASS {
                to_send.push((obligation, recipient, request_id));
            }
        }
        let sends = to_send.iter().map(|(obligation, recipient, request_id)| {
            let mut config = base_config.clone();
            config.require_durable_app_ack = true;
            config.logical_request_id = Some(*request_id);
            sender.send(*recipient, obligation.payload.clone(), config)
        });
        let results = futures::future::join_all(sends).await;
        // (recipient hex, logical id, error code) of each retried attempt.
        let mut errors: Vec<(String, String, Option<String>)> = Vec::new();
        for ((obligation, recipient, request_id), result) in to_send.into_iter().zip(results) {
            match classify(&result) {
                AttemptOutcome::Delivered => {
                    acks.record_outcome(request_id, recipient, DmReceiptStatus::Delivered);
                    pass.delivered.push(obligation.logical_id.clone());
                    attempts.push((obligation, true));
                }
                AttemptOutcome::Refused => {
                    acks.record_outcome(request_id, recipient, DmReceiptStatus::Failed);
                    pass.failed.push(obligation.logical_id.clone());
                    resolved.push(obligation);
                }
                AttemptOutcome::Retry => {
                    let code = result.err().as_ref().map(error_code).map(str::to_string);
                    errors.push((
                        obligation.recipient_agent_id.clone(),
                        obligation.logical_id.clone(),
                        code,
                    ));
                    pass.retried.push(obligation.logical_id.clone());
                    attempts.push((obligation, false));
                }
            }
        }
        match self
            .outbox()
            .settle(now_ms, &resolved, &attempts, DM_OBLIGATION_RETRY_SECS)
            .await
        {
            Settled::Committed { .. } | Settled::Unconfirmed(_) => {}
            Settled::RolledBack(error) => {
                tracing::warn!(
                    target: "x0x::direct",
                    %error,
                    "dm obligation outbox: worker pass not persisted; the pass repeats"
                );
                return pass;
            }
        }
        // The error code is informational; it is kept in memory only and
        // persisted with the next schedule change.
        if !errors.is_empty() {
            let mut entries = self.entries.write().await;
            for (recipient, logical_id, code) in errors {
                let held = entries
                    .get_mut(&recipient)
                    .and_then(|list| list.iter_mut().find(|o| o.logical_id == logical_id));
                if let Some(entry) = held {
                    entry.last_error = code;
                }
            }
        }
        pass
    }
}

#[cfg(test)]
#[path = "dm_outbox_tests.rs"]
mod tests;
