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

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::dm::{DmError, DmReceiptStatus, DmSendConfig, RECEIPT_LEDGER_CAP};
use crate::identity::{AgentId, MachineId};
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

/// The shortest time between two advert nudges for one recipient
/// (monotonic ms). A flood of adverts runs at most one extra pass per
/// recipient in this time, and never resends faster than the first retry.
pub(in crate::server) const DIRECT_SEND_NUDGE_MIN_MS: u64 = 2_000;

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
    /// #2007: the recipient machine the recorded send was pinned to, when
    /// known.
    pub(in crate::server) machine: Option<MachineId>,
}

impl LedgerReceipt {
    /// Read the agent's ledger for `request_id`.
    pub(in crate::server) fn of(acks: &crate::dm::InFlightAcks, request_id: &[u8; 16]) -> Self {
        Self {
            status: acks.receipt_status(request_id),
            digest: acks.receipt_digest(request_id),
            machine: acks.receipt_machine(request_id),
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
    /// A send returned `Ok`, or an ACK proved delivery of the same bytes.
    Delivered,
    /// The deadline passed before a delivery.
    Expired,
    /// A send failed with an error a retry cannot repair, or the recipient
    /// is blocked (route code).
    Failed(String),
    /// The caller cancelled the queued send.
    Cancelled,
    /// A recipient ACK for the only bytes ever attempted arrived after the
    /// send ended as `expired`, `failed` or `cancelled` (#1109 S2).
    DeliveredLate,
}

impl DirectSendTerminal {
    fn wire(&self) -> (&'static str, Option<String>) {
        match self {
            Self::Delivered => ("delivered", None),
            Self::Expired => ("expired", None),
            Self::Failed(code) => ("failed", Some(code.clone())),
            Self::Cancelled => ("cancelled", None),
            Self::DeliveredLate => ("delivered_late", None),
        }
    }

    fn from_wire(status: &str, error: Option<String>) -> Option<Self> {
        match (status, error) {
            ("delivered", None) => Some(Self::Delivered),
            ("expired", None) => Some(Self::Expired),
            ("cancelled", None) => Some(Self::Cancelled),
            ("delivered_late", None) => Some(Self::DeliveredLate),
            ("failed", Some(code)) => Some(Self::Failed(code)),
            _ => None,
        }
    }

    fn delivered(&self) -> bool {
        matches!(self, Self::Delivered | Self::DeliveredLate)
    }

    /// The receipt this outcome reads as.
    fn receipt(self, payload_digest: [u8; 32]) -> DirectSendReceipt {
        let (status, error) = self.wire();
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

/// How long a terminal outcome or attempt record is kept (wall clock),
/// across restarts.
pub(in crate::server) const DIRECT_SEND_OUTCOMES_KEEP_MS: u64 = 24 * 60 * 60 * 1000;

/// The most terminal outcomes (and, separately, attempt records) kept; the
/// oldest goes first.
pub(in crate::server) const DIRECT_SEND_OUTCOMES_CAP: usize = RECEIPT_LEDGER_CAP;

/// The most distinct payload digests remembered for one request id. The
/// enqueue rules keep it at one; more only means "not exactly one".
const DIRECT_SEND_ATTEMPT_DIGESTS_CAP: usize = 4;

/// #2007: the most distinct recipient machines remembered for one request
/// id. An attempt pinned to a machine past the cap is not remembered, so a
/// late ACK from that machine changes nothing.
const DIRECT_SEND_ATTEMPT_MACHINES_CAP: usize = 4;

/// A sidecar over this size is corrupt (an entry is well under 300 bytes).
const DIRECT_SEND_OUTCOMES_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct TerminalEntry {
    outcome: DirectSendTerminal,
    /// BLAKE3 of the obligation's payload.
    digest: [u8; 32],
    /// Unix ms when the outcome was recorded.
    recorded_at_ms: u64,
    seq: u64,
}

/// The payloads ever attempted under one request id (#1109 S2). Written
/// before the send, so a late ACK after a restart can be matched to the
/// only bytes it can acknowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttemptEntry {
    /// Recipient agent id (64 hex).
    recipient: String,
    /// Distinct payload digests attempted, oldest first.
    digests: Vec<[u8; 32]>,
    /// #2007: distinct recipient machines the attempts were pinned to,
    /// oldest first. Written after each attempt from the DM receipt
    /// ledger; empty means no machine is known.
    machines: Vec<MachineId>,
    /// Unix ms of the latest attempt.
    last_ms: u64,
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

/// One persisted attempt record.
#[derive(Debug, Serialize, Deserialize)]
struct AttemptRecord {
    request_id: String,
    recipient: String,
    digests: Vec<String>,
    /// #2007: absent in records written before #2007; read as empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    machines: Vec<String>,
    last_ms: u64,
}

/// Outcomes sidecar shape: version, outcomes oldest first, attempts.
#[derive(Debug, Serialize, Deserialize)]
struct OutcomesFile {
    version: u32,
    #[serde(default)]
    outcomes: Vec<OutcomeRecord>,
    #[serde(default)]
    attempts: Vec<AttemptRecord>,
}

/// Terminal outcomes and attempt records, bounded by
/// [`DIRECT_SEND_OUTCOMES_KEEP_MS`] and [`DIRECT_SEND_OUTCOMES_CAP`],
/// persisted so a receipt answers the same after a restart. The order
/// queue is capped too: a stale pair (an entry rewritten or removed since)
/// still counts against the cap.
#[derive(Debug, Default, Clone)]
struct TerminalLedger {
    entries: HashMap<[u8; 16], TerminalEntry>,
    order: VecDeque<([u8; 16], u64)>,
    next_seq: u64,
    attempts: HashMap<[u8; 16], AttemptEntry>,
}

fn decode_hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    hex::decode(text).ok()?.try_into().ok()
}

fn kept(recorded_ms: u64, now_ms: u64) -> bool {
    recorded_ms.saturating_add(DIRECT_SEND_OUTCOMES_KEEP_MS) > now_ms
}

impl TerminalLedger {
    fn prune(&mut self, now_ms: u64) {
        while let Some(&(id, seq)) = self.order.front() {
            if let Some(entry) = self.entries.get(&id).filter(|e| e.seq == seq) {
                if kept(entry.recorded_at_ms, now_ms) {
                    break;
                }
                self.entries.remove(&id);
            }
            self.order.pop_front();
        }
        self.attempts.retain(|_, a| kept(a.last_ms, now_ms));
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

    /// Note that `digest` is about to be sent under `request_id` to
    /// `recipient`.
    fn note_attempt(
        &mut self,
        request_id: [u8; 16],
        recipient: &str,
        digest: [u8; 32],
        now_ms: u64,
    ) {
        let entry = self
            .attempts
            .entry(request_id)
            .or_insert_with(|| AttemptEntry {
                recipient: recipient.to_string(),
                digests: Vec::new(),
                machines: Vec::new(),
                last_ms: now_ms,
            });
        entry.last_ms = now_ms;
        if !entry.digests.contains(&digest) && entry.digests.len() < DIRECT_SEND_ATTEMPT_DIGESTS_CAP
        {
            entry.digests.push(digest);
        }
        while self.attempts.len() > DIRECT_SEND_OUTCOMES_CAP {
            let oldest = self
                .attempts
                .iter()
                .min_by_key(|(_, a)| a.last_ms)
                .map(|(id, _)| *id);
            match oldest {
                Some(id) => {
                    self.attempts.remove(&id);
                }
                None => break,
            }
        }
    }

    /// #2007: note that an attempt under `request_id` was pinned to
    /// `machine`. Changes nothing when no attempt is recorded.
    fn note_machine(&mut self, request_id: &[u8; 16], machine: MachineId) {
        if let Some(entry) = self.attempts.get_mut(request_id) {
            if !entry.machines.contains(&machine)
                && entry.machines.len() < DIRECT_SEND_ATTEMPT_MACHINES_CAP
            {
                entry.machines.push(machine);
            }
        }
    }

    /// The single digest ever attempted under `request_id` to `recipient`
    /// on `machine`, or `None` when there is no record, another recipient,
    /// more than one digest, or no attempt pinned to `machine` (#2007).
    fn only_attempted(
        &self,
        request_id: &[u8; 16],
        recipient: &str,
        machine: &MachineId,
    ) -> Option<[u8; 32]> {
        let entry = self.attempts.get(request_id)?;
        match entry.digests.as_slice() {
            [digest] if entry.recipient == recipient && entry.machines.contains(machine) => {
                Some(*digest)
            }
            _ => None,
        }
    }

    /// Was a digest other than `digest` ever attempted under `request_id`?
    fn attempted_other(&self, request_id: &[u8; 16], digest: &[u8; 32]) -> bool {
        self.attempts
            .get(request_id)
            .is_some_and(|a| a.digests.iter().any(|d| d != digest))
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
            .filter(|e| kept(e.recorded_at_ms, now_ms))
            .map(|e| (e.outcome.clone(), e.digest))
    }

    /// The live records, as the sidecar holds them.
    fn to_file(&self) -> OutcomesFile {
        let outcomes = self
            .order
            .iter()
            .filter_map(|(id, seq)| {
                let entry = self.entries.get(id).filter(|e| e.seq == *seq)?;
                let (status, error) = entry.outcome.wire();
                Some(OutcomeRecord {
                    request_id: hex::encode(id),
                    status: status.to_string(),
                    error,
                    payload_digest: hex::encode(entry.digest),
                    recorded_at_ms: entry.recorded_at_ms,
                })
            })
            .collect();
        let mut attempts: Vec<AttemptRecord> = self
            .attempts
            .iter()
            .map(|(id, a)| AttemptRecord {
                request_id: hex::encode(id),
                recipient: a.recipient.clone(),
                digests: a.digests.iter().map(hex::encode).collect(),
                machines: a.machines.iter().map(|m| hex::encode(m.0)).collect(),
                last_ms: a.last_ms,
            })
            .collect();
        attempts.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        OutcomesFile {
            version: DIRECT_SEND_OUTCOMES_VERSION,
            outcomes,
            attempts,
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
        if file.outcomes.len() > DIRECT_SEND_OUTCOMES_CAP
            || file.attempts.len() > DIRECT_SEND_OUTCOMES_CAP
        {
            return Err("over the record cap".to_string());
        }
        let mut ledger = Self::default();
        for record in file.outcomes {
            let request_id = decode_hex_array::<16>(&record.request_id)
                .ok_or_else(|| format!("invalid request_id {}", record.request_id))?;
            let digest = decode_hex_array::<32>(&record.payload_digest)
                .ok_or_else(|| format!("invalid payload_digest on {}", record.request_id))?;
            let outcome =
                DirectSendTerminal::from_wire(&record.status, record.error).ok_or_else(|| {
                    format!("invalid status {} on {}", record.status, record.request_id)
                })?;
            if kept(record.recorded_at_ms, now_ms) {
                // Keep the file's order; `record` stamps the original time.
                ledger.record(request_id, outcome, digest, record.recorded_at_ms);
            }
        }
        for record in file.attempts {
            let request_id = decode_hex_array::<16>(&record.request_id)
                .ok_or_else(|| format!("invalid attempt request_id {}", record.request_id))?;
            if decode_hex_array::<32>(&record.recipient).is_none() {
                return Err(format!(
                    "invalid attempt recipient on {}",
                    record.request_id
                ));
            }
            let digests = record
                .digests
                .iter()
                .map(|d| decode_hex_array::<32>(d))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("invalid attempt digest on {}", record.request_id))?;
            if digests.is_empty() || digests.len() > DIRECT_SEND_ATTEMPT_DIGESTS_CAP {
                return Err(format!("invalid attempt digests on {}", record.request_id));
            }
            let machines = record
                .machines
                .iter()
                .map(|m| decode_hex_array::<32>(m).map(MachineId))
                .collect::<Option<Vec<_>>>()
                .filter(|m| m.len() <= DIRECT_SEND_ATTEMPT_MACHINES_CAP)
                .ok_or_else(|| format!("invalid attempt machines on {}", record.request_id))?;
            if kept(record.last_ms, now_ms) {
                ledger.attempts.insert(
                    request_id,
                    AttemptEntry {
                        recipient: record.recipient,
                        digests,
                        machines,
                        last_ms: record.last_ms,
                    },
                );
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
    /// The same `logical_id` and recipient is held, was delivered, or was
    /// attempted (outcome unknown) with other bytes.
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
    /// The outcome `cancelled` is durable and the obligation was removed.
    Cancelled,
    /// No obligation is held under this key.
    NotHeld,
    /// The outcome could not be written durably; the send is still held.
    NotDurable(String),
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

/// A terminal outcome to record: request id, outcome, payload digest.
type Outcome = ([u8; 16], DirectSendTerminal, [u8; 32]);

/// Outcomes decided but not yet written, by request id: the outcome and
/// the digest of the bytes it is about.
type UnwrittenOutcomes = HashMap<[u8; 16], (DirectSendTerminal, [u8; 32])>;

/// The durable send outbox: the store, its sidecar path, the locks and
/// the terminal-outcome ledger.
///
/// Every transition that ends an obligation writes its outcome durably
/// FIRST and removes the obligation after. A failed outcome write fails
/// the transition (the send stays held). At load, an obligation that also
/// has an outcome is removed: the outcome wins.
pub(in crate::server) struct DirectSendOutbox {
    entries: RwLock<OutboxMap<DirectSendObligation>>,
    path: PathBuf,
    persist_lock: Mutex<()>,
    /// Serializes enqueue, cancel and drop: the checks and the write are
    /// one step, so the generic insert never evicts an entry.
    admission: Mutex<()>,
    terminal: std::sync::Mutex<TerminalLedger>,
    /// #1109 S2: sidecar of the terminal outcomes and attempt records, and
    /// the lock that keeps its writes in order.
    outcomes_path: PathBuf,
    outcomes_lock: Mutex<()>,
    /// Request ids with an attempt in flight. The value is the terminal
    /// code to record if the recipient was blocked during the attempt
    /// (then the obligation is not sent again).
    in_flight: std::sync::Mutex<HashMap<[u8; 16], Option<String>>>,
    /// Outcomes a pass decided but could not write, by request id, with the
    /// digest they are about. The next pass writes them again and makes no
    /// attempt for those bytes. In memory only: after a restart the send is
    /// decided again.
    unwritten: std::sync::Mutex<UnwrittenOutcomes>,
    /// Recipient (64 hex) to the monotonic ms of its latest advert nudge.
    nudged: std::sync::Mutex<HashMap<String, u64>>,
}

impl DirectSendOutbox {
    /// An empty outbox whose sidecar is `path`. The terminal outcomes are
    /// kept in [`DIRECT_SEND_OUTCOMES_FILE`] in the same directory.
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
            unwritten: std::sync::Mutex::new(HashMap::new()),
            nudged: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn unwritten(&self) -> std::sync::MutexGuard<'_, UnwrittenOutcomes> {
        self.unwritten
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn nudged(&self) -> std::sync::MutexGuard<'_, HashMap<String, u64>> {
        self.nudged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    /// Apply `change` to a copy of the ledger, write the copy to the
    /// outcomes sidecar (owner-only, durable), and only then make it the
    /// ledger in memory. On error nothing changes in memory.
    async fn commit_ledger(
        &self,
        change: impl FnOnce(&mut TerminalLedger, u64),
    ) -> Result<(), String> {
        let _ordered = self.outcomes_lock.lock().await;
        let mut next = self.terminal().clone();
        change(&mut next, now_unix_ms());
        let bytes = serde_json::to_vec(&next.to_file()).map_err(|e| e.to_string())?;
        match crate::storage::write_private_bytes_durable_typed(&self.outcomes_path, bytes).await {
            Ok(()) => {}
            // After the rename the file holds `next`: memory follows it.
            Err(e) if e.crossed_rename() => {
                *self.terminal() = next;
                return Err(e.to_string());
            }
            Err(e) => return Err(e.to_string()),
        }
        *self.terminal() = next;
        Ok(())
    }

    /// Write `outcomes` durably. See [`Self::commit_ledger`].
    async fn record_terminal(&self, outcomes: Vec<Outcome>) -> Result<(), String> {
        if outcomes.is_empty() {
            return Ok(());
        }
        self.commit_ledger(|ledger, now_ms| {
            for (request_id, outcome, digest) in outcomes {
                ledger.record(request_id, outcome, digest, now_ms);
            }
        })
        .await
    }

    /// Write a pass's `outcomes` and the machines its attempts were pinned
    /// to (#2007) in one durable write. See [`Self::commit_ledger`].
    async fn record_pass(
        &self,
        outcomes: Vec<Outcome>,
        pinned: Vec<([u8; 16], MachineId)>,
    ) -> Result<(), String> {
        if outcomes.is_empty() && pinned.is_empty() {
            return Ok(());
        }
        self.commit_ledger(|ledger, now_ms| {
            for (request_id, machine) in pinned {
                ledger.note_machine(&request_id, machine);
            }
            for (request_id, outcome, digest) in outcomes {
                ledger.record(request_id, outcome, digest, now_ms);
            }
        })
        .await
    }

    /// Test seam: write outcomes durably without touching the outbox (a
    /// crash between the two writes).
    #[cfg(test)]
    pub(in crate::server) async fn record_outcomes_only(
        &self,
        outcomes: Vec<Outcome>,
    ) -> Result<(), String> {
        self.record_terminal(outcomes).await
    }

    /// Test seam: note attempted digests, and the machine each attempt was
    /// pinned to, durably.
    #[cfg(test)]
    pub(in crate::server) async fn note_attempts(
        &self,
        attempts: Vec<([u8; 16], String, [u8; 32], MachineId)>,
    ) -> Result<(), String> {
        self.commit_ledger(|ledger, now_ms| {
            for (request_id, recipient, digest, machine) in attempts {
                ledger.note_attempt(request_id, &recipient, digest, now_ms);
                ledger.note_machine(&request_id, machine);
            }
        })
        .await
    }

    /// Load the sidecars at boot. Missing means empty; a bad file is moved
    /// aside, that part starts empty, and the error is returned (the daemon
    /// still starts). Every loaded obligation is due at once: the persisted
    /// schedule belongs to the previous process's monotonic clock. An
    /// obligation that also has an outcome is removed: the outcome was
    /// written first, so the removal is what a crash interrupted.
    pub(in crate::server) async fn load(&self, aside_stamp_ms: u64) -> Result<(), String> {
        let loaded = self.outbox().load(aside_stamp_ms).await;
        for obligation in self.entries.write().await.values_mut().flatten() {
            obligation.next_retry_at_ms = 0;
        }
        let outcomes = self.load_outcomes(aside_stamp_ms).await;
        let held: Vec<DirectSendObligation> = self
            .entries
            .read()
            .await
            .values()
            .flatten()
            .cloned()
            .collect();
        let finished: Vec<DirectSendObligation> = {
            let now_ms = now_unix_ms();
            let mut terminal = self.terminal();
            held.into_iter()
                .filter(|o| {
                    o.request_id_bytes()
                        .is_some_and(|id| terminal.get(&id, now_ms).is_some())
                })
                .collect()
        };
        let reconciled = if finished.is_empty() {
            Ok(())
        } else {
            tracing::info!(
                count = finished.len(),
                "#1109: removing queued sends whose outcome was already recorded"
            );
            self.remove(finished).await
        };
        let errors: Vec<String> = [loaded, outcomes, reconciled]
            .into_iter()
            .filter_map(Result::err)
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
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

    /// #1109 S2: an accepted v2 ACK for `request_id` arrived from `sender`
    /// on `machine` with no waiter and no tombstone (for example after a
    /// restart). It proves delivery only of the bytes ever attempted under
    /// that id, so it counts only when exactly one digest was attempted, to
    /// `sender`, and an attempt was pinned to `machine` (#2007; an attempt
    /// record with no machine, such as one written before #2007, matches no
    /// ACK):
    ///
    /// - a held obligation with that digest is settled `delivered` (no
    ///   further send);
    /// - with nothing held, an `expired`, `failed` or `cancelled` outcome
    ///   with that digest becomes `delivered_late`.
    ///
    /// Anything else changes nothing. Returns whether something changed.
    pub(in crate::server) async fn settle_late_ack(
        &self,
        request_id: &[u8; 16],
        sender: &AgentId,
        machine: &MachineId,
    ) -> bool {
        let _admission = self.admission.lock().await;
        if self.is_in_flight(Some(*request_id)) {
            // The attempt's own waiter takes the ACK.
            return false;
        }
        let sender_hex = hex::encode(sender.as_bytes());
        let attempted = self
            .terminal()
            .only_attempted(request_id, &sender_hex, machine);
        let Some(attempted) = attempted else {
            tracing::info!(
                request_id = %hex::encode(request_id),
                "#1109: late ACK ignored: no single attempted payload to this sender and machine"
            );
            return false;
        };
        let held = self.entries.read().await.get(&sender_hex).and_then(|list| {
            list.iter()
                .find(|o| o.request_id == hex::encode(request_id))
                .cloned()
        });
        if let Some(held) = held {
            if held.payload_digest() != attempted {
                tracing::info!(
                    request_id = %hex::encode(request_id),
                    "#1109: late ACK ignored: the held payload was never attempted"
                );
                return false;
            }
            let outcome = vec![(*request_id, DirectSendTerminal::Delivered, attempted)];
            if let Err(e) = self.record_terminal(outcome).await {
                tracing::error!("#1109: failed to record a late ACK: {e}");
                return false;
            }
            if let Err(e) = self.remove(vec![held]).await {
                // The outcome is durable; the next pass or load removes it.
                tracing::error!("#1109: late ACK recorded, removal failed: {e}");
            }
            tracing::info!(
                request_id = %hex::encode(request_id),
                "#1109: a late durable ACK settled a queued direct send"
            );
            return true;
        }
        let ended = self.terminal().get(request_id, now_unix_ms());
        match ended {
            Some((outcome, digest)) if !outcome.delivered() && digest == attempted => {
                let late = vec![(*request_id, DirectSendTerminal::DeliveredLate, digest)];
                match self.record_terminal(late).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::error!("#1109: failed to record a late ACK: {e}");
                        false
                    }
                }
            }
            _ => false,
        }
    }

    /// #1109 S2: `recipient`'s durable-capable advert arrived. Its held
    /// obligations become due at `now` (in memory; the retry count is
    /// unchanged). Returns whether any matched. A recipient nudged less
    /// than [`DIRECT_SEND_NUDGE_MIN_MS`] ago is not nudged again.
    pub(in crate::server) async fn nudge_recipient(
        &self,
        recipient: &AgentId,
        now: DirectSendNow,
    ) -> bool {
        let recipient_hex = hex::encode(recipient.as_bytes());
        {
            let mut nudged = self.nudged();
            let nudged_recently =
                |at: u64| at.saturating_add(DIRECT_SEND_NUDGE_MIN_MS) > now.mono_ms;
            if nudged
                .get(&recipient_hex)
                .is_some_and(|&at| nudged_recently(at))
            {
                return false;
            }
            // Only recent nudges are kept, so the map stays small.
            nudged.retain(|_, at| nudged_recently(*at));
        }
        let matched = self
            .outbox()
            .nudge(now.mono_ms, |o| o.recipient == recipient_hex)
            .await;
        if matched {
            self.nudged().insert(recipient_hex, now.mono_ms);
        }
        matched
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
        let has_outcome = {
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
            // Other bytes were delivered, or attempted with an unknown
            // outcome, under this key: the recipient may hold them, so these
            // bytes can never be delivered under it.
            let (delivered_other, attempted_other, has_outcome) = match request_id {
                Some(id) => {
                    let mut terminal = self.terminal();
                    let ended = terminal.get(&id, now_unix_ms());
                    (
                        ended
                            .as_ref()
                            .is_some_and(|(outcome, d)| outcome.delivered() && *d != digest),
                        terminal.attempted_other(&id, &digest),
                        ended.is_some(),
                    )
                }
                None => (false, false, false),
            };
            if delivered_other || attempted_other || ledger.delivered_other_bytes(&digest) {
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
                || !self.attempt_room(&entries, request_id)
            {
                return EnqueueOutcome::Full;
            }
            has_outcome
        };
        // The earlier outcome under this key is forgotten durably BEFORE the
        // obligation is stored, or a load would let it win over the new one.
        if let (true, Some(id)) = (has_outcome, request_id) {
            if let Err(e) = self.commit_ledger(|ledger, _| ledger.forget(&id)).await {
                return EnqueueOutcome::WriteFailed(e);
            }
        }
        // A new send under this key: an outcome an earlier pass could not
        // write was about a send that is gone.
        if let Some(id) = request_id {
            self.unwritten().remove(&id);
        }
        // Due at once on this process's monotonic clock.
        obligation.next_retry_at_ms = 0;
        match self.outbox().insert(obligation).await {
            Ok(()) => EnqueueOutcome::Queued,
            Err(e) if e.crossed_rename() => {
                tracing::error!(
                    error = %e,
                    "#1109: direct send obligation stored, but durability is not confirmed \
                     (directory fsync failed)"
                );
                EnqueueOutcome::NotDurable(e.to_string())
            }
            Err(e) => EnqueueOutcome::WriteFailed(e.to_string()),
        }
    }

    /// Is there room in the attempt memory for one more request id? Every
    /// held send without an attempt record will need one, so they count
    /// too. Refusing here keeps the promise that an attempt record lasts
    /// [`DIRECT_SEND_OUTCOMES_KEEP_MS`]: [`TerminalLedger::note_attempt`]
    /// then never evicts one by count.
    fn attempt_room(
        &self,
        entries: &OutboxMap<DirectSendObligation>,
        request_id: Option<[u8; 16]>,
    ) -> bool {
        let mut terminal = self.terminal();
        terminal.prune(now_unix_ms());
        if request_id.is_some_and(|id| terminal.attempts.contains_key(&id)) {
            return true;
        }
        let pending = entries
            .values()
            .flatten()
            .filter_map(DirectSendObligation::request_id_bytes)
            .filter(|id| !terminal.attempts.contains_key(id))
            .count();
        terminal.attempts.len().saturating_add(pending) < DIRECT_SEND_OUTCOMES_CAP
    }

    /// Record `cancelled` durably for the held obligation `request_id` to
    /// `recipient`, then remove it. While an attempt is in flight the
    /// answer is [`CancelOutcome::InFlight`]: the attempt cannot be
    /// recalled. When the outcome cannot be written the send stays held
    /// ([`CancelOutcome::NotDurable`]).
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
        let outcome = vec![(
            *request_id,
            DirectSendTerminal::Cancelled,
            held.payload_digest(),
        )];
        if let Err(e) = self.record_terminal(outcome).await {
            return CancelOutcome::NotDurable(e);
        }
        if let Err(e) = self.remove(vec![held]).await {
            // The outcome is durable; the next pass or load removes it.
            tracing::error!("#1109: cancel recorded, removal failed: {e}");
        }
        CancelOutcome::Cancelled
    }

    /// Record `failed` with `code` durably for every obligation held for
    /// `recipient` (a contact was blocked), then remove them. An obligation
    /// with an attempt in flight is marked instead: the attempt's outcome
    /// is recorded and it is not sent again. Returns how many.
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
        let outcomes: Vec<Outcome> = held
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
        if let Err(e) = self.record_terminal(outcomes).await {
            // Still held; the worker's per-attempt check drops them.
            tracing::error!("#1109: failed to record dropped sends to a blocked contact: {e}");
            return marked;
        }
        let count = held.len();
        if let Err(e) = self.remove(held).await {
            tracing::error!("#1109: dropped sends recorded, removal failed: {e}");
        }
        count + marked
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

    /// The receipt status of `request_id` to `recipient`. A recorded
    /// outcome for the held bytes wins (its removal is pending); then a
    /// held obligation reads `queued`, unless the DM ledger already proves
    /// delivery of its bytes; then a DM ledger delivery; then a terminal
    /// outcome; then the DM ledger's own answer.
    pub(in crate::server) async fn receipt(
        &self,
        recipient: &AgentId,
        request_id: &[u8; 16],
        ledger: LedgerReceipt,
    ) -> DirectSendReceipt {
        let held = self
            .held(&hex::encode(recipient.as_bytes()), &hex::encode(request_id))
            .await;
        let terminal = self.terminal().get(request_id, now_unix_ms());
        match (held, terminal) {
            (Some(digest), Some((outcome, ended))) if ended == digest => outcome.receipt(digest),
            (Some(digest), _) if ledger.delivered_bytes(&digest) => {
                DirectSendReceipt::plain(ledger.status.as_str(), Some(digest))
            }
            (Some(digest), _) => DirectSendReceipt::plain("queued", Some(digest)),
            (None, terminal) => {
                // Nothing held: the answer names the bytes it is about, so a
                // caller can tell a receipt for other bytes from its own.
                if ledger.delivered() {
                    return DirectSendReceipt::plain(ledger.status.as_str(), ledger.digest);
                }
                match terminal {
                    Some((outcome, digest)) => outcome.receipt(digest),
                    None => DirectSendReceipt::plain(ledger.status.as_str(), ledger.digest),
                }
            }
        }
    }

    /// Drop unwritten outcomes whose send is no longer held (cancelled or
    /// dropped since), so a later send under the same key starts fresh.
    async fn forget_unwritten_not_held(&self) {
        if self.unwritten().is_empty() {
            return;
        }
        let held: HashSet<[u8; 16]> = self
            .entries
            .read()
            .await
            .values()
            .flatten()
            .filter_map(DirectSendObligation::request_id_bytes)
            .collect();
        self.unwritten().retain(|id, _| held.contains(id));
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
        self.forget_unwritten_not_held().await;
        let due = self.due(now).await;
        if due.is_empty() {
            return;
        }
        // Obligations whose outcome is already durable (an interrupted
        // removal): removed with no new outcome.
        let mut finished: Vec<DirectSendObligation> = Vec::new();
        // Obligations that end in this pass, with their outcome.
        let mut ending: Vec<(DirectSendObligation, Outcome)> = Vec::new();
        let mut to_send: Vec<(DirectSendObligation, [u8; 16], AgentId)> = Vec::new();
        for obligation in due {
            let parsed = obligation
                .request_id_bytes()
                .zip(crate::server::parse_agent_id_hex(&obligation.recipient).ok());
            let Some((request_id, recipient)) = parsed else {
                // `check` refuses this at load; keep the pass total anyway.
                finished.push(obligation);
                continue;
            };
            let digest = obligation.payload_digest();
            // The ledger runs on the wall clock it records with.
            let recorded = self.terminal().get(&request_id, now_unix_ms());
            let unwritten_outcome = self
                .unwritten()
                .get(&request_id)
                .filter(|(_, d)| *d == digest)
                .map(|(outcome, _)| outcome.clone());
            if recorded.is_some_and(|(_, ended)| ended == digest) {
                finished.push(obligation);
            } else if ledger(&request_id).delivered_bytes(&digest) {
                ending.push((
                    obligation,
                    (request_id, DirectSendTerminal::Delivered, digest),
                ));
            } else if let Some(outcome) = unwritten_outcome {
                // An earlier pass decided this send but could not write the
                // outcome: write it again, send nothing.
                ending.push((obligation, (request_id, outcome, digest)));
            } else if now.wall_ms >= obligation.deliver_until_ms {
                ending.push((
                    obligation,
                    (request_id, DirectSendTerminal::Expired, digest),
                ));
            } else if to_send.len() >= DIRECT_SEND_PASS_BUDGET {
                // Stays due for the next pass.
            } else if transport.recipient_blocked(recipient).await {
                tracing::warn!(
                    request_id = %obligation.request_id,
                    "#1109: queued direct send dropped: the recipient is blocked"
                );
                let failed = DirectSendTerminal::Failed(RECIPIENT_BLOCKED.to_string());
                ending.push((obligation, (request_id, failed, digest)));
            } else {
                to_send.push((obligation, request_id, recipient));
            }
        }
        // The attempted digests are durable before any byte goes out, so a
        // late ACK after a restart can only settle the bytes it can prove.
        if !to_send.is_empty() {
            let noted: Vec<([u8; 16], String, [u8; 32])> = to_send
                .iter()
                .map(|(o, id, _)| (*id, o.recipient.clone(), o.payload_digest()))
                .collect();
            let written = self
                .commit_ledger(|ledger, now_ms| {
                    for (request_id, recipient, digest) in noted {
                        ledger.note_attempt(request_id, &recipient, digest, now_ms);
                    }
                })
                .await;
            if let Err(e) = written {
                tracing::error!("#1109: attempts not recorded; no sends this pass: {e}");
                to_send.clear();
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

        let mut retries: Vec<(DirectSendObligation, bool)> = Vec::new();
        for (mut obligation, request_id, result) in results {
            let digest = obligation.payload_digest();
            // The recipient was blocked during the attempt: record what the
            // attempt did, and never send it again.
            let blocked = self.in_flight().get(&request_id).cloned().flatten();
            match result {
                Err(_) if blocked.is_some() => {
                    let code = blocked.unwrap_or_default();
                    let failed = DirectSendTerminal::Failed(code);
                    ending.push((obligation, (request_id, failed, digest)));
                }
                Ok(()) => {
                    ending.push((
                        obligation,
                        (request_id, DirectSendTerminal::Delivered, digest),
                    ));
                }
                Err(error) => {
                    let (_, code) = super::direct::dm_error_status_code(&error);
                    if is_retryable(&error) {
                        tracing::debug!(
                            request_id = %obligation.request_id,
                            "#1109: queued direct send not delivered yet ({code}); retrying"
                        );
                        obligation.last_error = Some(code.to_string());
                        retries.push((obligation, false));
                    } else {
                        tracing::warn!(
                            request_id = %obligation.request_id,
                            "#1109: queued direct send failed ({code}): {error}"
                        );
                        let failed = DirectSendTerminal::Failed(code.to_string());
                        ending.push((obligation, (request_id, failed, digest)));
                    }
                }
            }
        }

        // Outcomes first: an obligation leaves the outbox only once its
        // outcome is durable. A failed write keeps them all held, and the
        // outcomes are kept in memory: the next pass writes them again and
        // sends none of those bytes.
        let outcomes: Vec<Outcome> = ending.iter().map(|(_, outcome)| outcome.clone()).collect();
        // #2007: the machine each attempt was pinned to, as the DM receipt
        // ledger names it, is written with the outcomes. A late ACK after a
        // restart is matched against it. If this write fails the machine
        // stays unknown, and a late ACK changes nothing (fail closed).
        let pinned: Vec<([u8; 16], MachineId)> = sent_ids
            .iter()
            .filter_map(|id| ledger(id).machine.map(|machine| (*id, machine)))
            .collect();
        let mut resolved = finished;
        match self.record_pass(outcomes.clone(), pinned).await {
            Ok(()) => {
                {
                    let mut unwritten = self.unwritten();
                    for (request_id, _, _) in &outcomes {
                        unwritten.remove(request_id);
                    }
                }
                resolved.extend(ending.into_iter().map(|(o, _)| o));
            }
            Err(e) => {
                tracing::error!("#1109: outcomes not recorded; sends stay held: {e}");
                self.unwritten().extend(
                    outcomes
                        .into_iter()
                        .map(|(request_id, outcome, digest)| (request_id, (outcome, digest))),
                );
            }
        }
        match self
            .outbox()
            .settle(now.mono_ms, &resolved, &retries, DIRECT_SEND_RETRY_SECS)
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
                // The obligations are still held; the next pass removes the
                // ones whose outcome is recorded and repeats the rest.
                tracing::error!(error = %e, "#1109: failed to persist direct send outbox");
            }
        }
        self.clear_in_flight(&sent_ids);
    }
}

/// What wakes the worker between ticks.
#[derive(Debug, Clone, Copy)]
pub(in crate::server) enum DirectSendWake {
    /// An accepted v2 ACK matched no waiter and no tombstone.
    LateAck(crate::dm::OrphanDurableAck),
    /// A recipient's durable-capable advert arrived.
    Advert(AgentId),
}

/// #1109: the worker loop. One interval drives the passes: it is kept
/// across iterations (missed ticks delay, never burst), so a stream of
/// wake-ups can run extra passes but never delays the scheduled one. The
/// loop ends when `shutdown` completes.
pub(in crate::server) async fn run_direct_send_worker(
    outbox: &DirectSendOutbox,
    ledger: &(dyn Fn(&[u8; 16]) -> LedgerReceipt + Sync),
    transport: &dyn DirectSendTransport,
    clock: &(dyn Fn() -> DirectSendNow + Sync),
    mut wakes: tokio::sync::mpsc::Receiver<DirectSendWake>,
    shutdown: impl Future<Output = ()>,
) {
    let mut tick = tokio::time::interval(DIRECT_SEND_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    let mut wakes_open = true;
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            _ = tick.tick() => {
                outbox.step(clock(), ledger, transport).await;
            }
            wake = wakes.recv(), if wakes_open => match wake {
                Some(DirectSendWake::LateAck(ack)) => {
                    outbox
                        .settle_late_ack(&ack.request_id, &ack.sender, &ack.machine)
                        .await;
                }
                Some(DirectSendWake::Advert(recipient)) => {
                    let now = clock();
                    if outbox.nudge_recipient(&recipient, now).await {
                        outbox.step(now, ledger, transport).await;
                    }
                }
                None => wakes_open = false,
            },
        }
    }
}

#[cfg(test)]
#[path = "direct_outbox_tests.rs"]
mod tests;
