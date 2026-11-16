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
//! The terminal outcomes (`delivered`, `expired`, `failed`, `cancelled`)
//! are kept in memory with the same TTL and cap as the DM receipt ledger,
//! so `GET /direct/receipts/{logical_id}` can report them. Every receipt
//! names the BLAKE3 digest of the bytes it proves delivered: a receipt for
//! other bytes under the same `logical_id` never settles an obligation.
//!
//! Before each attempt the worker checks the recipient again: a blocked or
//! revoked contact ends the obligation as `failed` (`recipient_blocked`).
//!
//! The retry schedule runs on a monotonic clock in memory; only the
//! deadline and `first_seen_ms` use the wall clock. At load every held
//! obligation is due at once.
//!
//! The sidecar holds the payloads unsealed (base64), written with
//! owner-only permissions (0600) like the daemon's other sidecars.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::dm::{DmError, DmReceiptStatus, DmSendConfig, RECEIPT_LEDGER_CAP};
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

/// The two clocks a worker pass reads.
#[derive(Debug, Clone, Copy)]
pub(in crate::server) struct DirectSendNow {
    /// Unix ms: compared with `deliver_until_ms`.
    pub(in crate::server) wall_ms: u64,
    /// Monotonic ms since this process first read it: the retry schedule.
    pub(in crate::server) mono_ms: u64,
}

impl DirectSendNow {
    /// The current wall and monotonic time.
    pub(in crate::server) fn current() -> Self {
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = START.get_or_init(Instant::now);
        Self {
            wall_ms: now_unix_ms(),
            mono_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// What the DM receipt ledger knows about one request id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) struct LedgerReceipt {
    pub(in crate::server) status: DmReceiptStatus,
    /// BLAKE3 of the bytes the recorded send carried, when known.
    pub(in crate::server) digest: Option<[u8; 32]>,
}

impl LedgerReceipt {
    /// Read the agent's ledger for `request_id`.
    pub(in crate::server) fn of(acks: &crate::dm::InFlightAcks, request_id: &[u8; 16]) -> Self {
        Self {
            status: acks.receipt_status(request_id),
            digest: acks.receipt_digest(request_id),
        }
    }

    fn delivered(&self) -> bool {
        matches!(
            self.status,
            DmReceiptStatus::Delivered | DmReceiptStatus::DeliveredLate
        )
    }

    /// The ledger proves delivery of exactly the bytes with `digest`.
    fn delivered_bytes(&self, digest: &[u8; 32]) -> bool {
        self.delivered() && self.digest.as_ref() == Some(digest)
    }

    /// The ledger proves delivery of other bytes than `digest`.
    fn delivered_other_bytes(&self, digest: &[u8; 32]) -> bool {
        self.delivered() && self.digest.is_some_and(|d| d != *digest)
    }
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
    /// When the next attempt is due, in ms of this process's monotonic
    /// clock ([`DirectSendNow::mono_ms`]). Reset to 0 (due) at load.
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

    /// BLAKE3 of the payload: the bytes a receipt must name.
    pub(in crate::server) fn payload_digest(&self) -> [u8; 32] {
        blake3::hash(&self.payload).into()
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

    /// A logical id can be queued again with other bytes after the first
    /// obligation left; an attempt's outcome belongs only to the bytes it
    /// sent.
    fn same_entry(&self, other: &Self) -> bool {
        self.request_id == other.request_id && self.payload == other.payload
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
    /// A send returned `Ok`, or the receipt ledger showed a delivery of
    /// the same bytes.
    Delivered,
    /// The deadline passed before a delivery.
    Expired,
    /// A send failed with an error a retry cannot repair, or the recipient
    /// is blocked (route code).
    Failed(String),
    /// The caller cancelled the queued send.
    Cancelled,
}

impl DirectSendTerminal {
    /// The receipt this outcome reads as.
    fn receipt(self, payload_digest: [u8; 32]) -> DirectSendReceipt {
        let (status, error) = match self {
            Self::Delivered => ("delivered", None),
            Self::Expired => ("expired", None),
            Self::Failed(code) => ("failed", Some(code)),
            Self::Cancelled => ("cancelled", None),
        };
        DirectSendReceipt {
            status,
            error,
            payload_digest: Some(payload_digest),
        }
    }
}

/// Sidecar file name of the persisted terminal outcomes (#1109 S2).
pub(in crate::server) const DIRECT_SEND_OUTCOMES_FILE: &str = "direct_send_outcomes.json";

/// Outcomes sidecar format version.
const DIRECT_SEND_OUTCOMES_VERSION: u32 = 1;

/// How long a terminal outcome is kept (wall clock), across restarts.
pub(in crate::server) const DIRECT_SEND_OUTCOMES_KEEP_MS: u64 = 24 * 60 * 60 * 1000;

/// The most terminal outcomes kept; the oldest goes first.
pub(in crate::server) const DIRECT_SEND_OUTCOMES_CAP: usize = RECEIPT_LEDGER_CAP;

/// A sidecar over this size is corrupt (an entry is well under 300 bytes).
const DIRECT_SEND_OUTCOMES_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
struct TerminalEntry {
    outcome: DirectSendTerminal,
    /// BLAKE3 of the obligation's payload.
    digest: [u8; 32],
    /// Unix ms when the outcome was recorded.
    recorded_at_ms: u64,
    seq: u64,
}

/// One persisted outcome.
#[derive(Debug, Serialize, Deserialize)]
struct OutcomeRecord {
    request_id: String,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    payload_digest: String,
    recorded_at_ms: u64,
}

/// Outcomes sidecar shape: version + outcomes, oldest first.
#[derive(Debug, Serialize, Deserialize)]
struct OutcomesFile {
    version: u32,
    #[serde(default)]
    outcomes: Vec<OutcomeRecord>,
}

/// Terminal outcomes, bounded by [`DIRECT_SEND_OUTCOMES_KEEP_MS`] and
/// [`DIRECT_SEND_OUTCOMES_CAP`], persisted so a receipt answers the same
/// after a restart. The order queue is capped too: a stale pair (an entry
/// rewritten or removed since) still counts against the cap.
#[derive(Debug, Default)]
struct TerminalLedger {
    entries: HashMap<[u8; 16], TerminalEntry>,
    order: VecDeque<([u8; 16], u64)>,
    next_seq: u64,
}

fn decode_hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    hex::decode(text).ok()?.try_into().ok()
}

impl TerminalLedger {
    fn prune(&mut self, now_ms: u64) {
        while let Some(&(id, seq)) = self.order.front() {
            if let Some(entry) = self.entries.get(&id).filter(|e| e.seq == seq) {
                if entry
                    .recorded_at_ms
                    .saturating_add(DIRECT_SEND_OUTCOMES_KEEP_MS)
                    > now_ms
                {
                    break;
                }
                self.entries.remove(&id);
            }
            self.order.pop_front();
        }
    }

    fn record(
        &mut self,
        request_id: [u8; 16],
        outcome: DirectSendTerminal,
        digest: [u8; 32],
        now_ms: u64,
    ) {
        self.prune(now_ms);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.entries.insert(
            request_id,
            TerminalEntry {
                outcome,
                digest,
                recorded_at_ms: now_ms,
                seq,
            },
        );
        self.order.push_back((request_id, seq));
        while self.order.len() > DIRECT_SEND_OUTCOMES_CAP {
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

    fn get(
        &mut self,
        request_id: &[u8; 16],
        now_ms: u64,
    ) -> Option<(DirectSendTerminal, [u8; 32])> {
        self.prune(now_ms);
        self.entries
            .get(request_id)
            .filter(|e| {
                e.recorded_at_ms
                    .saturating_add(DIRECT_SEND_OUTCOMES_KEEP_MS)
                    > now_ms
            })
            .map(|e| (e.outcome.clone(), e.digest))
    }

    /// The live outcomes, oldest first, as the sidecar holds them.
    fn to_file(&self) -> OutcomesFile {
        let outcomes = self
            .order
            .iter()
            .filter_map(|(id, seq)| {
                let entry = self.entries.get(id).filter(|e| e.seq == *seq)?;
                let (status, error) = match &entry.outcome {
                    DirectSendTerminal::Delivered => ("delivered", None),
                    DirectSendTerminal::Expired => ("expired", None),
                    DirectSendTerminal::Failed(code) => ("failed", Some(code.clone())),
                    DirectSendTerminal::Cancelled => ("cancelled", None),
                };
                Some(OutcomeRecord {
                    request_id: hex::encode(id),
                    status: status.to_string(),
                    error,
                    payload_digest: hex::encode(entry.digest),
                    recorded_at_ms: entry.recorded_at_ms,
                })
            })
            .collect();
        OutcomesFile {
            version: DIRECT_SEND_OUTCOMES_VERSION,
            outcomes,
        }
    }

    /// Rebuild from sidecar bytes. Any malformed record fails the whole
    /// file; expired records are dropped.
    fn from_bytes(bytes: &[u8], now_ms: u64) -> Result<Self, String> {
        if bytes.len() > DIRECT_SEND_OUTCOMES_MAX_BYTES {
            return Err(format!(
                "outcomes file is {} bytes, over the guard",
                bytes.len()
            ));
        }
        let file: OutcomesFile =
            serde_json::from_slice(bytes).map_err(|e| format!("failed to parse: {e}"))?;
        if file.version != DIRECT_SEND_OUTCOMES_VERSION {
            return Err(format!("unsupported outcomes version {}", file.version));
        }
        if file.outcomes.len() > DIRECT_SEND_OUTCOMES_CAP {
            return Err(format!("{} outcomes, over the cap", file.outcomes.len()));
        }
        let mut ledger = Self::default();
        for record in file.outcomes {
            let request_id = decode_hex_array::<16>(&record.request_id)
                .ok_or_else(|| format!("invalid request_id {}", record.request_id))?;
            let digest = decode_hex_array::<32>(&record.payload_digest)
                .ok_or_else(|| format!("invalid payload_digest on {}", record.request_id))?;
            let outcome = match (record.status.as_str(), record.error) {
                ("delivered", None) => DirectSendTerminal::Delivered,
                ("expired", None) => DirectSendTerminal::Expired,
                ("cancelled", None) => DirectSendTerminal::Cancelled,
                ("failed", Some(code)) => DirectSendTerminal::Failed(code),
                (status, _) => {
                    return Err(format!("invalid status {status} on {}", record.request_id))
                }
            };
            if record
                .recorded_at_ms
                .saturating_add(DIRECT_SEND_OUTCOMES_KEEP_MS)
                > now_ms
            {
                // Keep the file's order; `record` stamps the original time.
                ledger.record(request_id, outcome, digest, record.recorded_at_ms);
            }
        }
        ledger.prune(now_ms);
        Ok(ledger)
    }
}

/// A boxed future the transport returns.
pub(in crate::server) type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The send a worker pass makes, and the recipient check before it.
/// Production uses the daemon; tests count calls and script the results.
pub(in crate::server) trait DirectSendTransport: Send + Sync {
    /// Is `recipient` blocked or revoked now? Checked before each attempt,
    /// as the route checks it at accept.
    fn recipient_blocked(&self, recipient: AgentId) -> TransportFuture<'_, bool>;

    /// Send `payload` to `recipient` once with `config`, taking no longer
    /// than `budget`.
    fn send(
        &self,
        recipient: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> TransportFuture<'_, Result<(), DmError>>;
}

/// The production transport: the daemon's contact store and the agent's
/// durable DM send, the call the route makes.
pub(in crate::server) struct AgentDirectSendTransport<'a>(
    pub(in crate::server) &'a crate::server::state::AppState,
);

impl DirectSendTransport for AgentDirectSendTransport<'_> {
    fn recipient_blocked(&self, recipient: AgentId) -> TransportFuture<'_, bool> {
        Box::pin(async move {
            let contacts = self.0.contacts.read().await;
            contacts.trust_level(&recipient) == crate::contacts::TrustLevel::Blocked
                || contacts.is_revoked(&recipient)
        })
    }

    fn send(
        &self,
        recipient: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> TransportFuture<'_, Result<(), DmError>> {
        Box::pin(async move {
            match tokio::time::timeout(
                budget,
                self.0
                    .agent
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

/// The terminal code of an obligation whose recipient is blocked.
pub(in crate::server) const RECIPIENT_BLOCKED: &str = "recipient_blocked";

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
    /// A new obligation is stored durably.
    Queued,
    /// The same `logical_id`, recipient and payload is already held; its
    /// stored deadline is returned and nothing new is stored.
    AlreadyQueued { deliver_until_ms: u64 },
    /// The same `logical_id` and recipient is held, or was delivered, with
    /// other bytes.
    Conflict,
    /// The recipient's or the daemon's caps are full.
    Full,
    /// The file was renamed into place but the directory fsync failed: the
    /// obligation is held and may be sent, but may not survive a crash.
    NotDurable(String),
    /// The durable write failed; nothing is stored.
    WriteFailed(String),
    /// An attempt for this request id is in flight; retry after it ends.
    InFlight,
}

/// The answer to one cancel.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::server) enum CancelOutcome {
    /// The held obligation was removed.
    Cancelled,
    /// No obligation is held under this key.
    NotHeld,
    /// The write failed before the rename; the obligation is still held.
    WriteFailed(String),
    /// An attempt is in flight and cannot be recalled; retry after it ends.
    InFlight,
}

/// What a receipt lookup reports for one request id.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::server) struct DirectSendReceipt {
    pub(in crate::server) status: &'static str,
    pub(in crate::server) error: Option<String>,
    /// BLAKE3 of the bytes this status is about, when known. A caller
    /// matches it against the bytes it sent.
    pub(in crate::server) payload_digest: Option<[u8; 32]>,
}

impl DirectSendReceipt {
    fn plain(status: &'static str, payload_digest: Option<[u8; 32]>) -> Self {
        Self {
            status,
            error: None,
            payload_digest,
        }
    }
}

/// The durable send outbox: the store, its sidecar path, the locks and
/// the terminal-outcome ledger.
pub(in crate::server) struct DirectSendOutbox {
    entries: RwLock<OutboxMap<DirectSendObligation>>,
    path: PathBuf,
    persist_lock: Mutex<()>,
    /// Serializes enqueue, cancel and drop: the checks and the write are
    /// one step, so the generic insert never evicts an entry.
    admission: Mutex<()>,
    terminal: std::sync::Mutex<TerminalLedger>,
    /// #1109 S2: sidecar of the terminal outcomes, and the lock that keeps
    /// its writes in order.
    outcomes_path: PathBuf,
    outcomes_lock: Mutex<()>,
    /// Request ids with an attempt in flight. The value is the terminal
    /// code to record if the recipient was blocked during the attempt
    /// (then the obligation is not sent again).
    in_flight: std::sync::Mutex<HashMap<[u8; 16], Option<String>>>,
}

impl DirectSendOutbox {
    /// An empty outbox whose sidecar is `path`.
    /// The terminal outcomes are kept in [`DIRECT_SEND_OUTCOMES_FILE`] in
    /// the same directory.
    pub(in crate::server) fn new(path: PathBuf) -> Self {
        let outcomes_path = path.with_file_name(DIRECT_SEND_OUTCOMES_FILE);
        Self {
            entries: RwLock::new(HashMap::new()),
            path,
            outcomes_path,
            outcomes_lock: Mutex::new(()),
            persist_lock: Mutex::new(()),
            admission: Mutex::new(()),
            terminal: std::sync::Mutex::new(TerminalLedger::default()),
            in_flight: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn in_flight(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], Option<String>>> {
        self.in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn is_in_flight(&self, request_id: Option<[u8; 16]>) -> bool {
        request_id.is_some_and(|id| self.in_flight().contains_key(&id))
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

    /// Record terminal outcomes in memory, then write the outcomes sidecar
    /// (owner-only, durable). A failed write is logged; memory keeps the
    /// outcome.
    async fn record_terminal(&self, outcomes: Vec<([u8; 16], DirectSendTerminal, [u8; 32])>) {
        if outcomes.is_empty() {
            return;
        }
        let _ordered = self.outcomes_lock.lock().await;
        let encoded = {
            let now_ms = now_unix_ms();
            let mut terminal = self.terminal();
            for (request_id, outcome, digest) in outcomes {
                terminal.record(request_id, outcome, digest, now_ms);
            }
            serde_json::to_vec(&terminal.to_file())
        };
        let written = match encoded {
            Ok(bytes) => {
                crate::storage::write_private_bytes_durable_typed(&self.outcomes_path, bytes)
                    .await
                    .map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        };
        if let Err(error) = written {
            tracing::error!("#1109: failed to write the direct send outcomes sidecar: {error}");
        }
    }

    /// Load the sidecars at boot. Missing means empty; a bad file is moved
    /// aside, that part starts empty, and the error is returned (the daemon
    /// still starts). Every loaded obligation is due at once: the persisted
    /// schedule belongs to the previous process's monotonic clock.
    pub(in crate::server) async fn load(&self, aside_stamp_ms: u64) -> Result<(), String> {
        let loaded = self.outbox().load(aside_stamp_ms).await;
        for obligation in self.entries.write().await.values_mut().flatten() {
            obligation.next_retry_at_ms = 0;
        }
        let outcomes = self.load_outcomes(aside_stamp_ms).await;
        match (loaded, outcomes) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(a), Err(b)) => Err(format!("{a}; {b}")),
        }
    }

    async fn load_outcomes(&self, aside_stamp_ms: u64) -> Result<(), String> {
        let path = &self.outcomes_path;
        let bytes = match crate::w3h_inline::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("failed to read {}: {e}", path.display())),
        };
        match TerminalLedger::from_bytes(&bytes, now_unix_ms()) {
            Ok(ledger) => {
                *self.terminal() = ledger;
                Ok(())
            }
            Err(error) => {
                let aside = path.with_extension(format!("corrupt-{aside_stamp_ms}"));
                let _ = crate::w3h_inline::fs::rename(path, &aside).await;
                Err(format!(
                    "{}: direct send outcomes {error} (file moved aside to {})",
                    path.display(),
                    aside.display()
                ))
            }
        }
    }

    /// #1109 S2: an accepted v2 ACK for `request_id` arrived with no waiter
    /// and no tombstone (for example after a restart). When a held
    /// obligation has that request id and `sender` is its recipient, it is
    /// settled delivered without another send. Returns whether it was.
    pub(in crate::server) async fn settle_late_ack(
        &self,
        request_id: &[u8; 16],
        sender: &AgentId,
    ) -> bool {
        let _admission = self.admission.lock().await;
        if self.is_in_flight(Some(*request_id)) {
            // The attempt's own waiter takes the ACK.
            return false;
        }
        let held = self
            .entries
            .read()
            .await
            .get(&hex::encode(sender.as_bytes()))
            .and_then(|list| {
                list.iter()
                    .find(|o| o.request_id == hex::encode(request_id))
                    .cloned()
            });
        let Some(held) = held else {
            return false;
        };
        let digest = held.payload_digest();
        match self.remove(vec![held]).await {
            Ok(()) => {
                tracing::info!(
                    request_id = %hex::encode(request_id),
                    "#1109: a late durable ACK settled a queued direct send"
                );
                self.record_terminal(vec![(*request_id, DirectSendTerminal::Delivered, digest)])
                    .await;
                true
            }
            Err(e) => {
                tracing::error!("#1109: failed to settle a late ACK: {e}");
                false
            }
        }
    }

    /// #1109 S2: `recipient`'s durable-capable advert arrived. Its held
    /// obligations become due at `now` (in memory; the retry count is
    /// unchanged). Returns whether any matched.
    pub(in crate::server) async fn nudge_recipient(
        &self,
        recipient: &AgentId,
        now: DirectSendNow,
    ) -> bool {
        let recipient_hex = hex::encode(recipient.as_bytes());
        self.outbox()
            .nudge(now.mono_ms, |o| o.recipient == recipient_hex)
            .await
    }

    /// All held obligations (test view).
    #[cfg(test)]
    pub(in crate::server) async fn snapshot(&self) -> Vec<DirectSendObligation> {
        self.outbox().snapshot().await
    }

    /// Store `obligation` unless the same request is already held. `ledger`
    /// is what the DM receipt ledger knows about its request id.
    pub(in crate::server) async fn enqueue(
        &self,
        mut obligation: DirectSendObligation,
        ledger: LedgerReceipt,
    ) -> EnqueueOutcome {
        let _admission = self.admission.lock().await;
        let digest = obligation.payload_digest();
        let request_id = obligation.request_id_bytes();
        {
            let entries = self.entries.read().await;
            if let Some(held) = entries
                .get(&obligation.recipient)
                .and_then(|list| list.iter().find(|o| o.request_id == obligation.request_id))
            {
                if held.payload == obligation.payload {
                    return EnqueueOutcome::AlreadyQueued {
                        deliver_until_ms: held.deliver_until_ms,
                    };
                }
                if !self.is_in_flight(request_id) {
                    return EnqueueOutcome::Conflict;
                }
            }
            if self.is_in_flight(request_id) {
                return EnqueueOutcome::InFlight;
            }
            // A delivery of other bytes under this key: the recipient holds
            // them, so these bytes can never be delivered under it.
            let delivered_other = request_id
                .and_then(|id| self.terminal().get(&id, now_unix_ms()))
                .is_some_and(|(outcome, d)| {
                    outcome == DirectSendTerminal::Delivered && d != digest
                });
            if delivered_other || ledger.delivered_other_bytes(&digest) {
                return EnqueueOutcome::Conflict;
            }
            // The caps `Outbox::validate` checks at load, applied to the
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
        // Due at once on this process's monotonic clock.
        obligation.next_retry_at_ms = 0;
        let outcome = match self.outbox().insert(obligation).await {
            Ok(()) => EnqueueOutcome::Queued,
            Err(e) if e.crossed_rename() => {
                tracing::error!(
                    error = %e,
                    "#1109: direct send obligation stored, but durability is not confirmed \
                     (directory fsync failed)"
                );
                EnqueueOutcome::NotDurable(e.to_string())
            }
            Err(e) => return EnqueueOutcome::WriteFailed(e.to_string()),
        };
        if let Some(request_id) = request_id {
            self.terminal().forget(&request_id);
        }
        outcome
    }

    /// Remove the held obligation `request_id` to `recipient` and record it
    /// as `cancelled`. While an attempt is in flight the answer is
    /// [`CancelOutcome::InFlight`]: the attempt cannot be recalled.
    pub(in crate::server) async fn cancel(
        &self,
        recipient: &AgentId,
        request_id: &[u8; 16],
    ) -> CancelOutcome {
        let _admission = self.admission.lock().await;
        let recipient_hex = hex::encode(recipient.as_bytes());
        let request_hex = hex::encode(request_id);
        let held = self
            .entries
            .read()
            .await
            .get(&recipient_hex)
            .and_then(|list| list.iter().find(|o| o.request_id == request_hex).cloned());
        let Some(held) = held else {
            return CancelOutcome::NotHeld;
        };
        if self.is_in_flight(Some(*request_id)) {
            return CancelOutcome::InFlight;
        }
        let digest = held.payload_digest();
        match self.remove(vec![held]).await {
            Ok(()) => {
                self.record_terminal(vec![(*request_id, DirectSendTerminal::Cancelled, digest)])
                    .await;
                CancelOutcome::Cancelled
            }
            Err(e) => CancelOutcome::WriteFailed(e),
        }
    }

    /// Remove every obligation held for `recipient` and record each as
    /// `failed` with `code` (a contact was blocked). An obligation with an
    /// attempt in flight is marked instead: the attempt's outcome is
    /// recorded and it is not sent again. Returns how many.
    pub(in crate::server) async fn drop_recipient(&self, recipient: &AgentId, code: &str) -> usize {
        let _admission = self.admission.lock().await;
        let mut held: Vec<DirectSendObligation> = self
            .entries
            .read()
            .await
            .get(&hex::encode(recipient.as_bytes()))
            .cloned()
            .unwrap_or_default();
        let mut marked = 0;
        {
            let mut in_flight = self.in_flight();
            held.retain(|o| {
                let mark = o.request_id_bytes().and_then(|id| in_flight.get_mut(&id));
                match mark {
                    Some(mark) => {
                        *mark = Some(code.to_string());
                        marked += 1;
                        false
                    }
                    None => true,
                }
            });
        }
        if held.is_empty() {
            return marked;
        }
        let outcomes: Vec<_> = held
            .iter()
            .filter_map(|o| {
                o.request_id_bytes().map(|id| {
                    (
                        id,
                        DirectSendTerminal::Failed(code.to_string()),
                        o.payload_digest(),
                    )
                })
            })
            .collect();
        let count = held.len();
        match self.remove(held).await {
            Ok(()) => {
                self.record_terminal(outcomes).await;
                count + marked
            }
            Err(e) => {
                tracing::error!("#1109: failed to drop queued sends to a blocked contact: {e}");
                marked
            }
        }
    }

    /// Remove `entries` durably. A failure after the rename counts as
    /// removed (memory and disk hold the new set).
    async fn remove(&self, entries: Vec<DirectSendObligation>) -> Result<(), String> {
        match self
            .outbox()
            .settle(0, &entries, &[], DIRECT_SEND_RETRY_SECS)
            .await
        {
            Settled::Committed { .. } => Ok(()),
            Settled::Unconfirmed(e) => {
                tracing::error!(
                    error = %e,
                    "#1109: direct send outbox applied, but durability is not confirmed"
                );
                Ok(())
            }
            Settled::RolledBack(e) => Err(e.to_string()),
        }
    }

    async fn held(&self, recipient_hex: &str, request_id_hex: &str) -> Option<[u8; 32]> {
        self.entries
            .read()
            .await
            .get(recipient_hex)
            .and_then(|list| list.iter().find(|o| o.request_id == request_id_hex))
            .map(DirectSendObligation::payload_digest)
    }

    /// The receipt status of `request_id` to `recipient`. A held obligation
    /// reads `queued`, unless the DM ledger already proves delivery of its
    /// bytes; then a DM ledger delivery; then a terminal outcome; then the
    /// DM ledger's own answer.
    pub(in crate::server) async fn receipt(
        &self,
        recipient: &AgentId,
        request_id: &[u8; 16],
        ledger: LedgerReceipt,
    ) -> DirectSendReceipt {
        let held = self
            .held(&hex::encode(recipient.as_bytes()), &hex::encode(request_id))
            .await;
        match held {
            Some(digest) if ledger.delivered_bytes(&digest) => {
                return DirectSendReceipt::plain(ledger.status.as_str(), Some(digest));
            }
            Some(digest) => return DirectSendReceipt::plain("queued", Some(digest)),
            None => {}
        }
        // Nothing held: the answer names the bytes it is about, so a caller
        // can tell a receipt for other bytes under this key from its own.
        if ledger.delivered() {
            return DirectSendReceipt::plain(ledger.status.as_str(), ledger.digest);
        }
        let terminal = self.terminal().get(request_id, now_unix_ms());
        match terminal {
            Some((outcome, digest)) => outcome.receipt(digest),
            None => DirectSendReceipt::plain(ledger.status.as_str(), ledger.digest),
        }
    }

    fn clear_in_flight(&self, request_ids: &[[u8; 16]]) {
        let mut in_flight = self.in_flight();
        for request_id in request_ids {
            in_flight.remove(request_id);
        }
    }

    /// Obligations due at `now`: the retry time has come on the monotonic
    /// clock, or the deadline on the wall clock. First attempts first.
    async fn due(&self, now: DirectSendNow) -> Vec<DirectSendObligation> {
        let mut due: Vec<DirectSendObligation> = self
            .entries
            .read()
            .await
            .values()
            .flatten()
            .filter(|o| o.next_retry_at_ms <= now.mono_ms || o.deliver_until_ms <= now.wall_ms)
            .cloned()
            .collect();
        due.sort_by_key(|o| (o.retry_count > 0, o.next_retry_at_ms));
        due
    }

    /// One worker pass at `now`. `ledger` reads the DM receipt ledger;
    /// `transport` checks the recipient and makes the sends.
    pub(in crate::server) async fn step(
        &self,
        now: DirectSendNow,
        ledger: &(dyn Fn(&[u8; 16]) -> LedgerReceipt + Sync),
        transport: &dyn DirectSendTransport,
    ) {
        // Selection runs under the admission lock and marks each chosen
        // send in flight, so a cancel, block or enqueue sees the attempt.
        let admission = self.admission.lock().await;
        let due = self.due(now).await;
        if due.is_empty() {
            return;
        }
        let mut resolved: Vec<DirectSendObligation> = Vec::new();
        let mut outcomes: Vec<([u8; 16], DirectSendTerminal, [u8; 32])> = Vec::new();
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
            let digest = obligation.payload_digest();
            if ledger(&request_id).delivered_bytes(&digest) {
                outcomes.push((request_id, DirectSendTerminal::Delivered, digest));
                resolved.push(obligation);
            } else if now.wall_ms >= obligation.deliver_until_ms {
                outcomes.push((request_id, DirectSendTerminal::Expired, digest));
                resolved.push(obligation);
            } else if to_send.len() >= DIRECT_SEND_PASS_BUDGET {
                // Stays due for the next pass.
            } else if transport.recipient_blocked(recipient).await {
                tracing::warn!(
                    request_id = %obligation.request_id,
                    "#1109: queued direct send dropped: the recipient is blocked"
                );
                outcomes.push((
                    request_id,
                    DirectSendTerminal::Failed(RECIPIENT_BLOCKED.to_string()),
                    digest,
                ));
                resolved.push(obligation);
            } else {
                to_send.push((obligation, request_id, recipient));
            }
        }
        {
            let mut in_flight = self.in_flight();
            for (_, request_id, _) in &to_send {
                in_flight.insert(*request_id, None);
            }
        }
        let sent_ids: Vec<[u8; 16]> = to_send.iter().map(|(_, id, _)| *id).collect();
        drop(admission);

        let sends = to_send
            .into_iter()
            .map(|(obligation, request_id, recipient)| {
                let left =
                    Duration::from_millis(obligation.deliver_until_ms.saturating_sub(now.wall_ms));
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
            let digest = obligation.payload_digest();
            // The recipient was blocked during the attempt: record what the
            // attempt did, and never send it again.
            let blocked = self.in_flight().get(&request_id).cloned().flatten();
            match result {
                Err(_) if blocked.is_some() => {
                    let code = blocked.unwrap_or_default();
                    outcomes.push((request_id, DirectSendTerminal::Failed(code), digest));
                    resolved.push(obligation);
                }
                Ok(()) => {
                    outcomes.push((request_id, DirectSendTerminal::Delivered, digest));
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
                        outcomes.push((
                            request_id,
                            DirectSendTerminal::Failed(code.to_string()),
                            digest,
                        ));
                        resolved.push(obligation);
                    }
                }
            }
        }

        match self
            .outbox()
            .settle(now.mono_ms, &resolved, &attempts, DIRECT_SEND_RETRY_SECS)
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
                self.clear_in_flight(&sent_ids);
                return;
            }
        }
        self.record_terminal(outcomes).await;
        self.clear_in_flight(&sent_ids);
    }
}

#[cfg(test)]
#[path = "direct_outbox_tests.rs"]
mod tests;
