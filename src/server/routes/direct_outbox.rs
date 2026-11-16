//! #1109 slice S1: the durable `POST /direct/send` outbox.
//!
//! A send with `deliver_until_ms` is not attempted inside the HTTP call.
//! The route checks the request, writes an obligation to
//! `<data_dir>/direct_send_outbox.json` and answers 202. A worker then
//! sends the obligation with the durable (v2) config under its
//! `logical_id`, until one of these occurs:
//!
//! - the send returns `Ok` (the recipient's durable ACK): delivered;
//! - the receipt ledger already shows `delivered` or `delivered_late` for
//!   the request id (a late ACK of an earlier attempt): delivered, and
//!   nothing is sent again;
//! - the deadline passes: dropped as `expired`;
//! - the send fails with an error that a retry cannot repair: dropped as
//!   `failed` with the route's error code.
//!
//! A retryable error (a cold recipient with no v2 advert yet, a timeout, a
//! peer that is offline) keeps the obligation and schedules the next
//! attempt. The store survives a restart. The commit, caps, retry schedule
//! and boot load are the generic [`Outbox`].
//!
//! The terminal outcomes (`delivered`, `expired`, `failed`) are kept in
//! memory with the same TTL and cap as the DM receipt ledger, so
//! `GET /direct/receipts/{logical_id}` can report them.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::dm::{DmError, DmReceiptStatus, DmSendConfig, RECEIPT_LEDGER_CAP, RECEIPT_LEDGER_TTL};
use crate::identity::AgentId;
use crate::storage::outbox::{Outbox, OutboxCaps, OutboxMap, OutboxRecord, Settled};

/// Sidecar file name in the daemon data dir.
pub(in crate::server) const DIRECT_SEND_OUTBOX_FILE: &str = "direct_send_outbox.json";

/// Sidecar format version.
const DIRECT_SEND_OUTBOX_VERSION: u32 = 1;

/// Caps: 64 entries / 4 MiB per recipient, 1024 entries / 32 MiB in all.
pub(in crate::server) const DIRECT_SEND_OUTBOX_CAPS: OutboxCaps = OutboxCaps {
    per_partition: 64,
    per_partition_bytes: 4 * 1024 * 1024,
    total: 1024,
    total_bytes: 32 * 1024 * 1024,
};

/// Retry offsets (seconds) after a retryable failure; the last repeats.
pub(in crate::server) const DIRECT_SEND_RETRY_SECS: &[u64] = &[2, 5, 10, 30, 60];

/// How often the worker runs a pass.
pub(in crate::server) const DIRECT_SEND_TICK: Duration = Duration::from_secs(2);

/// The latest `deliver_until_ms` the route accepts, relative to now.
pub(in crate::server) const DIRECT_SEND_MAX_HORIZON_MS: u64 = 24 * 60 * 60 * 1000;

/// The longest one worker attempt may take. The deadline can shorten it.
const DIRECT_SEND_ATTEMPT_BUDGET: Duration = Duration::from_secs(10);

/// The most sends one worker pass starts. The others stay due.
const DIRECT_SEND_PASS_BUDGET: usize = 16;

/// Unix time in ms (0 if the clock is before the epoch).
pub(in crate::server) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// The request options of `POST /direct/send` that shape the send config.
/// The worker builds the same config the route would build from them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::server) struct DirectSendOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::server) prefer_raw_quic_if_connected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::server) raw_quic_receive_ack_ms: Option<u64>,
    #[serde(default)]
    pub(in crate::server) stop_fallback_on_raw_error: bool,
    #[serde(default)]
    pub(in crate::server) require_gossip: bool,
}

/// One durable send obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::server) struct DirectSendObligation {
    /// Recipient agent id (64 hex). The outbox partition.
    pub(in crate::server) recipient: String,
    /// The caller's `logical_id`.
    pub(in crate::server) logical_id: String,
    /// The derived DM request id (32 hex). The entry id.
    pub(in crate::server) request_id: String,
    /// The payload bytes (base64 in the sidecar).
    #[serde(with = "payload_b64")]
    pub(in crate::server) payload: Vec<u8>,
    /// Unix ms after which the obligation is dropped as `expired`.
    pub(in crate::server) deliver_until_ms: u64,
    /// Unix ms when the obligation was accepted.
    pub(in crate::server) first_seen_ms: u64,
    /// Attempts completed so far.
    pub(in crate::server) retry_count: u32,
    /// Unix ms when the next attempt is due.
    pub(in crate::server) next_retry_at_ms: u64,
    /// The route error code of the last failed attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::server) last_error: Option<String>,
    /// Request options that shape the send config.
    #[serde(default)]
    pub(in crate::server) options: DirectSendOptions,
}

impl DirectSendObligation {
    /// The request id as bytes, if the stored hex is valid.
    pub(in crate::server) fn request_id_bytes(&self) -> Option<[u8; 16]> {
        let bytes = hex::decode(&self.request_id).ok()?;
        bytes.try_into().ok()
    }
}

mod payload_b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

/// Sidecar shape: version + obligations grouped by recipient.
#[derive(Debug, Serialize, Deserialize)]
struct DirectSendOutboxFile {
    version: u32,
    #[serde(default)]
    by_recipient: HashMap<String, Vec<DirectSendObligation>>,
}

impl OutboxRecord for DirectSendObligation {
    const LABEL: &'static str = "direct send outbox";

    fn partition(&self) -> &str {
        &self.recipient
    }

    fn id(&self) -> &str {
        &self.request_id
    }

    fn first_seen_ms(&self) -> u64 {
        self.first_seen_ms
    }

    fn byte_size(&self) -> usize {
        self.payload.len()
    }

    /// An obligation is also due at its deadline, so a pass drops it as
    /// `expired` then, not at a later retry time.
    fn next_retry_at_ms(&self) -> u64 {
        self.next_retry_at_ms.min(self.deliver_until_ms)
    }

    fn retry_count(&self) -> u32 {
        self.retry_count
    }

    fn set_schedule(&mut self, retry_count: u32, next_retry_at_ms: u64) {
        self.retry_count = retry_count;
        self.next_retry_at_ms = next_retry_at_ms;
    }

    fn record_attempt(&mut self, attempted: &Self) {
        self.last_error.clone_from(&attempted.last_error);
    }

    fn check(&self) -> Result<(), String> {
        if self.request_id_bytes().is_none() {
            return Err(format!("invalid request_id {}", self.request_id));
        }
        if crate::server::parse_agent_id_hex(&self.recipient).is_err() {
            return Err(format!("invalid recipient on {}", self.request_id));
        }
        if crate::dm::DmLogicalId::parse(&self.logical_id).is_err() {
            return Err(format!("invalid logical_id on {}", self.request_id));
        }
        if self.payload.len() > crate::dm::MAX_PAYLOAD_BYTES {
            return Err(format!("payload over the DM limit on {}", self.request_id));
        }
        Ok(())
    }

    fn encode(map: &OutboxMap<Self>) -> Result<Vec<u8>, String> {
        let file = DirectSendOutboxFile {
            version: DIRECT_SEND_OUTBOX_VERSION,
            by_recipient: map.clone(),
        };
        serde_json::to_vec(&file).map_err(|e| format!("failed to encode direct send outbox: {e}"))
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<OutboxMap<Self>, String> {
        let file: DirectSendOutboxFile = serde_json::from_slice(bytes)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
        if file.version != DIRECT_SEND_OUTBOX_VERSION {
            return Err(format!(
                "{}: unsupported direct send outbox version {} (expected {DIRECT_SEND_OUTBOX_VERSION})",
                path.display(),
                file.version
            ));
        }
        Ok(file.by_recipient)
    }
}

/// What became of an obligation that left the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) enum DirectSendTerminal {
    /// A send returned `Ok`, or the receipt ledger showed a delivery.
    Delivered,
    /// The deadline passed before a delivery.
    Expired,
    /// A send failed with an error a retry cannot repair (route code).
    Failed(String),
}

impl DirectSendTerminal {
    /// The receipt this outcome reads as.
    fn receipt(self) -> DirectSendReceipt {
        let (status, error) = match self {
            Self::Delivered => ("delivered", None),
            Self::Expired => ("expired", None),
            Self::Failed(code) => ("failed", Some(code)),
        };
        DirectSendReceipt { status, error }
    }
}

#[derive(Debug)]
struct TerminalEntry {
    outcome: DirectSendTerminal,
    expires: Instant,
    seq: u64,
}

/// Terminal outcomes, bounded by [`RECEIPT_LEDGER_TTL`] and
/// [`RECEIPT_LEDGER_CAP`]. The order queue is capped too: a stale pair
/// (an entry rewritten or removed since) still counts against the cap.
#[derive(Debug, Default)]
struct TerminalLedger {
    entries: HashMap<[u8; 16], TerminalEntry>,
    order: VecDeque<([u8; 16], u64)>,
    next_seq: u64,
}

impl TerminalLedger {
    fn prune(&mut self, now: Instant) {
        while let Some(&(id, seq)) = self.order.front() {
            if let Some(entry) = self.entries.get(&id).filter(|e| e.seq == seq) {
                if entry.expires > now {
                    break;
                }
                self.entries.remove(&id);
            }
            self.order.pop_front();
        }
    }

    fn record(&mut self, request_id: [u8; 16], outcome: DirectSendTerminal, now: Instant) {
        self.prune(now);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.entries.insert(
            request_id,
            TerminalEntry {
                outcome,
                expires: now + RECEIPT_LEDGER_TTL,
                seq,
            },
        );
        self.order.push_back((request_id, seq));
        while self.order.len() > RECEIPT_LEDGER_CAP {
            let Some((id, old_seq)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&id).is_some_and(|e| e.seq == old_seq) {
                self.entries.remove(&id);
            }
        }
    }

    fn forget(&mut self, request_id: &[u8; 16]) {
        self.entries.remove(request_id);
    }

    fn get(&mut self, request_id: &[u8; 16], now: Instant) -> Option<DirectSendTerminal> {
        self.prune(now);
        self.entries
            .get(request_id)
            .filter(|e| e.expires > now)
            .map(|e| e.outcome.clone())
    }
}

/// The send a worker pass makes. Production sends through the agent;
/// tests count calls and script the results.
pub(in crate::server) trait DirectSendTransport: Send + Sync {
    /// Send `payload` to `recipient` once with `config`, taking no longer
    /// than `budget`.
    fn send<'a>(
        &'a self,
        recipient: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), DmError>> + Send + 'a>>;
}

/// The production transport: the agent's durable DM send, the call the
/// route makes.
pub(in crate::server) struct AgentDirectSendTransport<'a>(pub(in crate::server) &'a crate::Agent);

impl DirectSendTransport for AgentDirectSendTransport<'_> {
    fn send<'a>(
        &'a self,
        recipient: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), DmError>> + Send + 'a>> {
        Box::pin(async move {
            match tokio::time::timeout(
                budget,
                self.0
                    .send_direct_with_config_with_provenance(&recipient, payload, config),
            )
            .await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(DmError::Timeout {
                    retries: 0,
                    elapsed: budget,
                }),
            }
        })
    }
}

/// Errors after which the worker keeps the obligation and tries again.
pub(in crate::server) fn is_retryable(error: &DmError) -> bool {
    matches!(
        error,
        DmError::Timeout { .. }
            | DmError::PeerLikelyOffline { .. }
            | DmError::PeerDisconnected { .. }
            | DmError::ReceiverBackpressured { .. }
            | DmError::LocalGossipUnavailable(_)
            | DmError::RecipientUndiscovered(_)
            | DmError::AckSemanticsUnavailable(_)
            | DmError::RecipientKeyUnavailable(_)
            | DmError::RecipientKeyInvalid(_)
            | DmError::RecipientCapabilityPending { .. }
    )
}

/// The answer to one enqueue.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::server) enum EnqueueOutcome {
    /// A new obligation is stored.
    Queued,
    /// The same `logical_id`, recipient and payload is already held; its
    /// stored deadline is returned and nothing new is stored.
    AlreadyQueued { deliver_until_ms: u64 },
    /// The same `logical_id` and recipient is held with other bytes.
    Conflict,
    /// The recipient's or the daemon's caps are full.
    Full,
    /// The durable write failed; nothing is stored.
    WriteFailed(String),
}

/// What a receipt lookup reports for one request id.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::server) struct DirectSendReceipt {
    pub(in crate::server) status: &'static str,
    pub(in crate::server) error: Option<String>,
}

/// The durable send outbox: the store, its sidecar path, the locks and
/// the terminal-outcome ledger.
pub(in crate::server) struct DirectSendOutbox {
    entries: RwLock<OutboxMap<DirectSendObligation>>,
    path: PathBuf,
    persist_lock: Mutex<()>,
    /// Serializes enqueue: the idempotency and cap checks and the insert
    /// are one step, so the generic insert never evicts an entry.
    admission: Mutex<()>,
    terminal: std::sync::Mutex<TerminalLedger>,
}

impl DirectSendOutbox {
    /// An empty outbox whose sidecar is `path`.
    pub(in crate::server) fn new(path: PathBuf) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            path,
            persist_lock: Mutex::new(()),
            admission: Mutex::new(()),
            terminal: std::sync::Mutex::new(TerminalLedger::default()),
        }
    }

    fn outbox(&self) -> Outbox<'_, DirectSendObligation> {
        Outbox::new(
            &self.entries,
            &self.path,
            &self.persist_lock,
            DIRECT_SEND_OUTBOX_CAPS,
        )
    }

    fn terminal(&self) -> std::sync::MutexGuard<'_, TerminalLedger> {
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Load the sidecar at boot. Missing means empty; a bad file is moved
    /// aside and the outbox starts empty (the error is returned).
    pub(in crate::server) async fn load(&self, aside_stamp_ms: u64) -> Result<(), String> {
        self.outbox().load(aside_stamp_ms).await
    }

    /// All held obligations (test view).
    #[cfg(test)]
    pub(in crate::server) async fn snapshot(&self) -> Vec<DirectSendObligation> {
        self.outbox().snapshot().await
    }

    /// Store `obligation` unless the same request is already held.
    pub(in crate::server) async fn enqueue(
        &self,
        obligation: DirectSendObligation,
    ) -> EnqueueOutcome {
        let _admission = self.admission.lock().await;
        {
            let entries = self.entries.read().await;
            if let Some(held) = entries
                .get(&obligation.recipient)
                .and_then(|list| list.iter().find(|o| o.request_id == obligation.request_id))
            {
                return if held.payload == obligation.payload {
                    EnqueueOutcome::AlreadyQueued {
                        deliver_until_ms: held.deliver_until_ms,
                    }
                } else {
                    EnqueueOutcome::Conflict
                };
            }
            // The same caps `Outbox::validate` checks at load, applied to the
            // store with this entry added.
            let caps = DIRECT_SEND_OUTBOX_CAPS;
            let size = obligation.byte_size();
            let (part_count, part_bytes) = entries
                .get(&obligation.recipient)
                .map(|list| (list.len(), list.iter().map(OutboxRecord::byte_size).sum()))
                .unwrap_or((0, 0usize));
            let total_count: usize = entries.values().map(Vec::len).sum();
            let total_bytes: usize = entries
                .values()
                .flatten()
                .map(OutboxRecord::byte_size)
                .sum();
            if part_count >= caps.per_partition
                || part_bytes.saturating_add(size) > caps.per_partition_bytes
                || total_count >= caps.total
                || total_bytes.saturating_add(size) > caps.total_bytes
            {
                return EnqueueOutcome::Full;
            }
        }
        let request_id = obligation.request_id_bytes();
        let written = self.outbox().insert(obligation).await;
        match written {
            Ok(()) => {}
            Err(e) if e.crossed_rename() => {
                tracing::error!(
                    error = %e,
                    "#1109: direct send obligation stored, but durability is not confirmed \
                     (directory fsync failed)"
                );
            }
            Err(e) => return EnqueueOutcome::WriteFailed(e.to_string()),
        }
        if let Some(request_id) = request_id {
            self.terminal().forget(&request_id);
        }
        EnqueueOutcome::Queued
    }

    async fn held(&self, recipient_hex: &str, request_id_hex: &str) -> bool {
        self.entries
            .read()
            .await
            .get(recipient_hex)
            .is_some_and(|list| list.iter().any(|o| o.request_id == request_id_hex))
    }

    /// The receipt status of `request_id` to `recipient`. A delivery in the
    /// DM ledger wins; then a held obligation reads `queued`; then a
    /// terminal outcome; then the DM ledger's own answer.
    pub(in crate::server) async fn receipt(
        &self,
        recipient: &AgentId,
        request_id: &[u8; 16],
        ledger: DmReceiptStatus,
    ) -> DirectSendReceipt {
        if matches!(
            ledger,
            DmReceiptStatus::Delivered | DmReceiptStatus::DeliveredLate
        ) {
            return DirectSendReceipt {
                status: ledger.as_str(),
                error: None,
            };
        }
        if self
            .held(&hex::encode(recipient.as_bytes()), &hex::encode(request_id))
            .await
        {
            return DirectSendReceipt {
                status: "queued",
                error: None,
            };
        }
        match self.terminal().get(request_id, Instant::now()) {
            Some(outcome) => outcome.receipt(),
            None => DirectSendReceipt {
                status: ledger.as_str(),
                error: None,
            },
        }
    }

    /// One worker pass at `now_ms`. `ledger` is the DM receipt ledger
    /// lookup; `transport` makes the sends.
    pub(in crate::server) async fn step(
        &self,
        now_ms: u64,
        ledger: &(dyn Fn(&[u8; 16]) -> DmReceiptStatus + Sync),
        transport: &dyn DirectSendTransport,
    ) {
        let due = self.outbox().due(now_ms).await;
        if due.is_empty() {
            return;
        }
        let mut resolved: Vec<DirectSendObligation> = Vec::new();
        let mut outcomes: Vec<([u8; 16], DirectSendTerminal)> = Vec::new();
        let mut to_send: Vec<(DirectSendObligation, [u8; 16], AgentId)> = Vec::new();
        for obligation in due {
            let parsed = obligation
                .request_id_bytes()
                .zip(crate::server::parse_agent_id_hex(&obligation.recipient).ok());
            let Some((request_id, recipient)) = parsed else {
                // `check` refuses this at load; keep the pass total anyway.
                resolved.push(obligation);
                continue;
            };
            if matches!(
                ledger(&request_id),
                DmReceiptStatus::Delivered | DmReceiptStatus::DeliveredLate
            ) {
                outcomes.push((request_id, DirectSendTerminal::Delivered));
                resolved.push(obligation);
            } else if now_ms >= obligation.deliver_until_ms {
                outcomes.push((request_id, DirectSendTerminal::Expired));
                resolved.push(obligation);
            } else if to_send.len() < DIRECT_SEND_PASS_BUDGET {
                to_send.push((obligation, request_id, recipient));
            }
        }

        let sends = to_send
            .into_iter()
            .map(|(obligation, request_id, recipient)| {
                let left =
                    Duration::from_millis(obligation.deliver_until_ms.saturating_sub(now_ms));
                let budget = left.min(DIRECT_SEND_ATTEMPT_BUDGET);
                let mut config = super::direct::send_config_from_options(&obligation.options, true);
                config.logical_request_id = Some(request_id);
                config.timeout_per_attempt = budget;
                config.max_retries = 0;
                let payload = obligation.payload.clone();
                async move {
                    let result = transport.send(recipient, payload, config, budget).await;
                    (obligation, request_id, result)
                }
            });
        let results = futures::future::join_all(sends).await;

        let mut attempts: Vec<(DirectSendObligation, bool)> = Vec::new();
        for (mut obligation, request_id, result) in results {
            match result {
                Ok(()) => {
                    outcomes.push((request_id, DirectSendTerminal::Delivered));
                    attempts.push((obligation, true));
                }
                Err(error) => {
                    let (_, code) = super::direct::dm_error_status_code(&error);
                    if is_retryable(&error) {
                        tracing::debug!(
                            request_id = %obligation.request_id,
                            "#1109: queued direct send not delivered yet ({code}); retrying"
                        );
                        obligation.last_error = Some(code.to_string());
                        attempts.push((obligation, false));
                    } else {
                        tracing::warn!(
                            request_id = %obligation.request_id,
                            "#1109: queued direct send failed ({code}): {error}"
                        );
                        outcomes.push((request_id, DirectSendTerminal::Failed(code.to_string())));
                        resolved.push(obligation);
                    }
                }
            }
        }

        match self
            .outbox()
            .settle(now_ms, &resolved, &attempts, DIRECT_SEND_RETRY_SECS)
            .await
        {
            Settled::Committed { .. } => {}
            Settled::Unconfirmed(e) => {
                tracing::error!(
                    error = %e,
                    "#1109: direct send outbox applied, but durability is not confirmed \
                     (directory fsync failed)"
                );
            }
            Settled::RolledBack(e) => {
                // The obligations are still held; the next pass repeats them.
                tracing::error!(error = %e, "#1109: failed to persist direct send outbox");
                return;
            }
        }
        let now = Instant::now();
        let mut terminal = self.terminal();
        for (request_id, outcome) in outcomes {
            terminal.record(request_id, outcome, now);
        }
    }
}

#[cfg(test)]
#[path = "direct_outbox_tests.rs"]
mod tests;
