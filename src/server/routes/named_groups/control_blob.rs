//! Process-local, authenticated exact-byte pull for control JSON too large for
//! one direct message. The reference and chunks carry no authority: after
//! reassembly, the original signed event/result follows its existing handler.

use super::*;
use std::sync::Mutex as StdMutex;
use tokio::sync::Semaphore;

const CHUNK_BYTES: usize = x0x::files::DEFAULT_CHUNK_SIZE;
// The existing TreeKEM recovery-control cache has an 8 MiB encoded-JSON
// budget. Use that explicit control-plane precedent for one exact blob and
// one peer's outstanding bytes. Larger (even otherwise legal) historical
// chains are refused visibly until they have a streaming-chain protocol.
const MAX_BLOB_BYTES: u64 = TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_BYTES as u64;
const STAGED_GLOBAL_BYTES: u64 = 4 * MAX_BLOB_BYTES;
const INCOMING_GLOBAL_BYTES: u64 = 2 * MAX_BLOB_BYTES;
const STAGED_ENTRY_CAP: usize = 64;
const PER_PEER_ENTRY_CAP: usize = 4;
const ACTIVE_FETCH_CAP: usize = 4;
const CHUNK_SEND_CAP: usize = 16;
const FETCH_TIMEOUT: Duration = WELCOME_FETCH_TIMEOUT;
const CHUNK_RETRIES: usize = 3;
const CHUNK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum ControlBlobKind {
    NamedGroupEvent,
    JoinResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(in crate::server) struct ControlBlobRef {
    kind: ControlBlobKind,
    group_id: String,
    source: String,
    recipient: String,
    digest: String,
    byte_len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    join_attempt_id: Option<String>,
}

/// Distinct `type` names prevent older Welcome/file listeners from treating
/// a control chunk as their own. Legacy small event/result JSON is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(in crate::server) enum ControlBlobMessage {
    #[serde(rename = "control_blob_ref")]
    Reference { reference: ControlBlobRef },
    #[serde(rename = "control_blob_fetch")]
    Fetch {
        reference: ControlBlobRef,
        sequence: u32,
    },
    #[serde(rename = "control_blob_chunk")]
    Chunk {
        reference: ControlBlobRef,
        sequence: u32,
        data_b64: String,
    },
    /// #876: the recipient completed its pull — the source may release the
    /// staged copy now instead of holding it to the TTL. Mixed fleet: an
    /// older source does not know this type and keeps TTL semantics; an
    /// older recipient never sends it.
    #[serde(rename = "control_blob_release")]
    Release { reference: ControlBlobRef },
}

struct StagedBlob {
    bytes: Arc<Vec<u8>>,
    created_at: Instant,
}

struct IncomingBlob {
    generation: u64,
    created_at: Instant,
    next_sequence: u32,
    waiter: Option<oneshot::Sender<Vec<u8>>>,
}

#[derive(Default)]
struct Registry {
    staged: HashMap<ControlBlobRef, StagedBlob>,
    incoming: HashMap<ControlBlobRef, IncomingBlob>,
    /// Declared incoming bytes admitted and not yet released by the owning
    /// fetch task's [`IncomingLease`]. Cancellation and expiry remove the
    /// ROUTING entry but never release these bytes: a cancelled task can
    /// still hold a near-`MAX_BLOB_BYTES` reassembly Vec and sit in a
    /// 30-second chunk-send await, so without lease-owned accounting four
    /// fetch slots could legitimately hold 32 MiB despite the 16 MiB
    /// incoming budget.
    incoming_bytes_held: u64,
    incoming_bytes_held_per_source: HashMap<String, u64>,
    next_generation: u64,
}

impl Registry {
    fn prune_expired(&mut self) {
        self.staged
            .retain(|_, entry| entry.created_at.elapsed() < PENDING_JOIN_RESULT_TTL);
        // Expiry removes routing only; the owning lease keeps the declared
        // bytes accounted until its task actually ends.
        self.incoming
            .retain(|_, entry| entry.created_at.elapsed() < FETCH_TIMEOUT);
    }

    fn staged_bytes_for_recipient(&self, peer: &str) -> u64 {
        self.staged
            .iter()
            .filter(|(reference, _)| reference.recipient == peer)
            .map(|(_, entry)| entry.bytes.len() as u64)
            .sum()
    }
}

struct ControlBlobInner {
    registry: StdMutex<Registry>,
    fetch_slots: Arc<Semaphore>,
    chunk_slots: Arc<Semaphore>,
}

#[derive(Clone)]
pub(in crate::server) struct ControlBlobState(Arc<ControlBlobInner>);

impl Default for ControlBlobState {
    fn default() -> Self {
        Self(Arc::new(ControlBlobInner {
            registry: StdMutex::new(Registry::default()),
            fetch_slots: Arc::new(Semaphore::new(ACTIVE_FETCH_CAP)),
            chunk_slots: Arc::new(Semaphore::new(CHUNK_SEND_CAP)),
        }))
    }
}

impl ControlBlobState {
    fn with_registry<R>(&self, f: impl FnOnce(&mut Registry) -> R) -> R {
        let mut guard = self
            .0
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.prune_expired();
        f(&mut guard)
    }

    pub(super) fn stage(
        &self,
        reference: ControlBlobRef,
        bytes: Vec<u8>,
    ) -> Result<(), &'static str> {
        if bytes.len() as u64 != reference.byte_len
            || reference.byte_len <= x0x::dm::MAX_PAYLOAD_BYTES as u64
            || reference.byte_len > MAX_BLOB_BYTES
            || hex::encode(blake3::hash(&bytes).as_bytes()) != reference.digest
        {
            return Err("invalid control blob length or digest");
        }
        self.with_registry(|registry| {
            if let Some(existing) = registry.staged.get_mut(&reference) {
                if existing.bytes.as_slice() != bytes.as_slice() {
                    return Err("conflicting control blob digest");
                }
                existing.created_at = Instant::now();
                return Ok(());
            }
            let peer_count = registry
                .staged
                .keys()
                .filter(|entry| entry.recipient == reference.recipient)
                .count();
            let total_bytes: u64 = registry
                .staged
                .values()
                .map(|entry| entry.bytes.len() as u64)
                .sum();
            if registry.staged.len() >= STAGED_ENTRY_CAP
                || peer_count >= PER_PEER_ENTRY_CAP
                || total_bytes.saturating_add(reference.byte_len) > STAGED_GLOBAL_BYTES
                || registry
                    .staged_bytes_for_recipient(&reference.recipient)
                    .saturating_add(reference.byte_len)
                    > MAX_BLOB_BYTES
            {
                return Err("control blob staging budget exhausted");
            }
            registry.staged.insert(
                reference,
                StagedBlob {
                    bytes: Arc::new(bytes),
                    created_at: Instant::now(),
                },
            );
            Ok(())
        })
    }

    fn staged_chunk(&self, reference: &ControlBlobRef, sequence: u32) -> Option<Vec<u8>> {
        self.with_registry(|registry| {
            let bytes = &registry.staged.get(reference)?.bytes;
            let start = (sequence as usize).checked_mul(CHUNK_BYTES)?;
            let end = start.checked_add(CHUNK_BYTES)?.min(bytes.len());
            (start < end).then(|| bytes[start..end].to_vec())
        })
    }

    /// Admit one incoming fetch and return its byte-owning lease. `None` on
    /// any bound: an ACTIVE routing entry already exists, the active-entry
    /// caps are hit, or the global/per-source incoming byte budget — measured
    /// against ALL bytes still held by live leases, including
    /// cancelled-but-running tasks — would be exceeded.
    fn reserve_incoming(&self, reference: &ControlBlobRef) -> Option<IncomingLease> {
        self.with_registry(|registry| {
            if registry.incoming.contains_key(reference) {
                return None;
            }
            let active_for_source = registry
                .incoming
                .keys()
                .filter(|entry| entry.source == reference.source)
                .count();
            let held_for_source = registry
                .incoming_bytes_held_per_source
                .get(&reference.source)
                .copied()
                .unwrap_or(0);
            if registry.incoming.len() >= ACTIVE_FETCH_CAP
                || active_for_source >= PER_PEER_ENTRY_CAP
                || registry
                    .incoming_bytes_held
                    .saturating_add(reference.byte_len)
                    > INCOMING_GLOBAL_BYTES
                || held_for_source.saturating_add(reference.byte_len) > MAX_BLOB_BYTES
            {
                return None;
            }
            registry.next_generation = registry.next_generation.saturating_add(1);
            let generation = registry.next_generation;
            registry.incoming_bytes_held = registry
                .incoming_bytes_held
                .saturating_add(reference.byte_len);
            *registry
                .incoming_bytes_held_per_source
                .entry(reference.source.clone())
                .or_insert(0) += reference.byte_len;
            registry.incoming.insert(
                reference.clone(),
                IncomingBlob {
                    generation,
                    created_at: Instant::now(),
                    next_sequence: 0,
                    waiter: None,
                },
            );
            Some(IncomingLease {
                store: self.clone(),
                reference: reference.clone(),
                byte_len: reference.byte_len,
                source: reference.source.clone(),
                generation,
            })
        })
    }

    /// Register the waiter for `generation`'s reservation. A cancelled old
    /// task must never steal a newer reservation's waiter slot.
    fn set_waiter(
        &self,
        reference: &ControlBlobRef,
        generation: u64,
        sequence: u32,
        waiter: oneshot::Sender<Vec<u8>>,
    ) -> bool {
        self.with_registry(|registry| {
            let Some(incoming) = registry.incoming.get_mut(reference) else {
                return false;
            };
            if incoming.generation != generation {
                return false;
            }
            incoming.next_sequence = sequence;
            incoming.waiter = Some(waiter);
            true
        })
    }

    /// Hand a wire chunk to whichever reservation currently routes this
    /// reference. Chunks are digest-bound to the identical reference bytes,
    /// so a late chunk from a cancelled fetch of the same reference carries
    /// identical content and cannot corrupt a newer reservation; a chunk for
    /// a different blob cannot match the reference at all.
    fn deliver_chunk(&self, reference: &ControlBlobRef, sequence: u32, chunk: Vec<u8>) {
        self.with_registry(|registry| {
            if let Some(incoming) = registry.incoming.get_mut(reference) {
                if incoming.next_sequence == sequence {
                    if let Some(waiter) = incoming.waiter.take() {
                        let _ = waiter.send(chunk);
                    }
                }
            }
        });
    }

    /// Test/inspection helper: bytes still held by live leases.
    #[cfg(test)]
    fn incoming_bytes_held(&self) -> u64 {
        self.with_registry(|registry| registry.incoming_bytes_held)
    }

    /// Test/inspection helper: the sequence the CURRENT reservation's
    /// fetch loop is waiting for, when its waiter is installed. `None`
    /// when the entry is absent or between retries.
    #[cfg(test)]
    fn incoming_waiter_sequence(&self, reference: &ControlBlobRef) -> Option<u32> {
        self.with_registry(|registry| {
            registry
                .incoming
                .get(reference)
                .and_then(|incoming| incoming.waiter.as_ref().map(|_| incoming.next_sequence))
        })
    }

    pub(super) fn prune_groups(&self, aliases: &HashSet<String>) {
        self.with_registry(|registry| {
            registry
                .staged
                .retain(|reference, _| !aliases.contains(&reference.group_id));
            registry
                .incoming
                .retain(|reference, _| !aliases.contains(&reference.group_id));
        });
    }

    /// #876: the blob's own RECIPIENT completed its pull — remove the
    /// staged entry (and free its entry/byte budget) now instead of
    /// holding it to `PENDING_JOIN_RESULT_TTL`. The caller has already
    /// validated the sender IS the reference's recipient, so the remove
    /// is keyed by the exact reference alone.
    pub(super) fn release_staged(&self, reference: &ControlBlobRef) {
        self.with_registry(|registry| {
            if registry.staged.remove(reference).is_some() {
                tracing::debug!(
                    kind = ?reference.kind,
                    byte_len = reference.byte_len,
                    "staged control blob released by its recipient (#876)"
                );
            }
        });
    }

    /// #878 r3 (review 4a): test inspection — entries still staged.
    #[cfg(test)]
    pub(super) fn staged_len(&self) -> usize {
        self.with_registry(|registry| registry.staged.len())
    }

    pub(super) fn cancel_attempt(&self, group_id: &str, recipient: &str, attempt_id: &str) {
        // Removes ROUTING only. The cancelled task's lease keeps its
        // declared bytes accounted until the task itself ends, so a
        // replacement reservation cannot be admitted on freed-by-cancel
        // accounting.
        self.with_registry(|registry| {
            registry.incoming.retain(|reference, _| {
                reference.group_id != group_id
                    || reference.recipient != recipient
                    || reference.join_attempt_id.as_deref() != Some(attempt_id)
            });
        });
    }
}

/// Owned incoming reservation. `Drop` releases the declared bytes — exactly
/// when the owning fetch task finishes, whether by completion, deadline,
/// error, or cancellation — and removes the routing entry only while it
/// still belongs to this generation, so an old task can never delete a
/// newer reservation of the identical reference.
struct IncomingLease {
    store: ControlBlobState,
    reference: ControlBlobRef,
    byte_len: u64,
    source: String,
    generation: u64,
}

impl Drop for IncomingLease {
    fn drop(&mut self) {
        self.store.with_registry(|registry| {
            registry.incoming_bytes_held =
                registry.incoming_bytes_held.saturating_sub(self.byte_len);
            let remaining = registry
                .incoming_bytes_held_per_source
                .get(&self.source)
                .copied()
                .unwrap_or(0)
                .saturating_sub(self.byte_len);
            if remaining == 0 {
                registry.incoming_bytes_held_per_source.remove(&self.source);
            } else {
                registry
                    .incoming_bytes_held_per_source
                    .insert(self.source.clone(), remaining);
            }
            if registry
                .incoming
                .get(&self.reference)
                .is_some_and(|entry| entry.generation == self.generation)
            {
                registry.incoming.remove(&self.reference);
            }
        });
    }
}
fn control_config(message: &ControlBlobMessage) -> x0x::dm::DmSendConfig {
    match message {
        ControlBlobMessage::Chunk { .. } => file_transfer_send_config(),
        ControlBlobMessage::Reference { .. } | ControlBlobMessage::Fetch { .. } => {
            x0x::dm::DmSendConfig {
                prefer_raw_quic_if_connected: false,
                ..direct_message_send_config()
            }
        }
        ControlBlobMessage::Release { .. } => x0x::dm::DmSendConfig {
            prefer_raw_quic_if_connected: false,
            ..direct_message_send_config()
        },
    }
}

async fn send_message(
    agent: &Agent,
    recipient: &AgentId,
    message: &ControlBlobMessage,
) -> std::result::Result<(), String> {
    let bytes = serde_json::to_vec(message).map_err(|e| e.to_string())?;
    if bytes.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return Err("control blob frame exceeds direct-message limit".to_string());
    }
    agent
        .send_direct_with_config(recipient, bytes, control_config(message))
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Stage the exact original JSON and send only its bounded reference.
///
/// Retention, stated honestly: a successfully staged blob is released by
/// its recipient's `control_blob_release` notice once the pull completes
/// and verifies (#876), or — for peers that do not send the notice, or
/// when the notice is lost — by `PENDING_JOIN_RESULT_TTL` / group
/// teardown / re-stage refresh, whichever comes first. A staging-budget
/// refusal is retried briefly before this returns an error (the caller
/// still logs on final failure). The bounds above (entry cap, global and
/// per-recipient byte budgets, per-blob maximum) keep retention finite.
pub(super) async fn send_reference(
    store: &ControlBlobState,
    agent: &Agent,
    recipient: &AgentId,
    kind: ControlBlobKind,

    group_id: &str,
    join_attempt_id: Option<&str>,
    bytes: Vec<u8>,
) -> std::result::Result<(), String> {
    let reference = ControlBlobRef {
        kind,
        group_id: group_id.to_string(),
        source: hex::encode(agent.agent_id().as_bytes()),
        recipient: hex::encode(recipient.as_bytes()),
        digest: hex::encode(blake3::hash(&bytes).as_bytes()),
        byte_len: bytes.len() as u64,
        join_attempt_id: join_attempt_id.map(str::to_string),
    };
    // #876 (issue item 2): a budget-exhausted refusal is TRANSIENT once
    // recipients release their completed pulls — retry it briefly before
    // giving up, instead of dropping the event on the floor. Any other
    // refusal (invalid blob, digest conflict) returns immediately.
    const BUDGET_RETRIES: usize = 6;
    const BUDGET_RETRY_DELAY: Duration = Duration::from_secs(2);
    for attempt in 0..=BUDGET_RETRIES {
        match store.stage(reference.clone(), bytes.clone()) {
            Ok(()) => break,
            Err("control blob staging budget exhausted") if attempt < BUDGET_RETRIES => {
                tracing::warn!(
                    kind = ?reference.kind,
                    group_id = %reference.group_id,
                    recipient = %LogHexId::agent(&reference.recipient),
                    attempt,
                    "control blob staging budget exhausted; retrying (#876)"
                );
                tokio::time::sleep(BUDGET_RETRY_DELAY).await;
            }
            Err(other) => return Err(other.to_string()),
        }
    }
    send_message(
        agent,
        recipient,
        &ControlBlobMessage::Reference { reference },
    )
    .await
}

fn basic_reference_valid(reference: &ControlBlobRef) -> bool {
    reference.byte_len > x0x::dm::MAX_PAYLOAD_BYTES as u64
        && reference.byte_len <= MAX_BLOB_BYTES
        && hex::decode(&reference.digest).is_ok_and(|digest| digest.len() == 32)
        && parse_agent_id_hex(&reference.source).is_ok()
        && parse_agent_id_hex(&reference.recipient).is_ok()
        && !reference.group_id.is_empty()
        && match reference.kind {
            ControlBlobKind::NamedGroupEvent => reference.join_attempt_id.is_none(),
            ControlBlobKind::JoinResult => reference.join_attempt_id.is_some(),
        }
}

fn incoming_reference_header_valid(
    reference: &ControlBlobRef,
    sender_hex: &str,
    local_hex: &str,
    verified: bool,
) -> bool {
    verified
        && basic_reference_valid(reference)
        && sender_hex == reference.source
        && local_hex == reference.recipient
}

fn incoming_fetch_header_valid(
    reference: &ControlBlobRef,
    sender_hex: &str,
    local_hex: &str,
    verified: bool,
) -> bool {
    verified
        && basic_reference_valid(reference)
        && sender_hex == reference.recipient
        && local_hex == reference.source
}

fn exact_blob_matches_ref(reference: &ControlBlobRef, bytes: &[u8]) -> bool {
    bytes.len() as u64 == reference.byte_len
        && hex::encode(blake3::hash(bytes).as_bytes()) == reference.digest
}

async fn reference_admitted(state: &AppState, reference: &ControlBlobRef) -> bool {
    let known_group = {
        let groups = state.named_groups.read().await;
        groups.contains_key(&reference.group_id)
            || groups
                .values()
                .any(|info| info.stable_group_id() == reference.group_id)
    };
    if !known_group {
        return false;
    }
    if reference.kind == ControlBlobKind::JoinResult {
        let key = join_result_key(&reference.group_id, &reference.recipient);
        let current = state
            .pending_join_attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .is_some_and(|attempt| {
                Some(attempt.attempt_id.as_str()) == reference.join_attempt_id.as_deref()
            });
        current
            && expected_join_result_inviter(state, &key).as_deref()
                == Some(reference.source.as_str())
    } else {
        true
    }
}

pub(in crate::server) async fn handle_control_blob_message(
    state: &Arc<AppState>,
    sender: &AgentId,
    verified: bool,
    message: ControlBlobMessage,
) {
    let sender_hex = hex::encode(sender.as_bytes());
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let revoked = {
        let revocation_set = state.agent.revocation_set();
        let guard = revocation_set.read().await;
        guard.is_agent_revoked(sender)
    };
    if revoked {
        return;
    }
    match message {
        ControlBlobMessage::Reference { reference } => {
            if !incoming_reference_header_valid(&reference, &sender_hex, &local_hex, verified)
                || !reference_admitted(state, &reference).await
            {
                return;
            }
            let Ok(permit) = Arc::clone(&state.control_blobs.0.fetch_slots).try_acquire_owned()
            else {
                tracing::warn!(kind = ?reference.kind, "control blob fetch slots exhausted");
                return;
            };
            // The lease owns the declared-byte accounting for the whole
            // task lifetime: cancellation or expiry elsewhere cannot free
            // these bytes while this task still runs.
            let Some(lease) = state.control_blobs.reserve_incoming(&reference) else {
                return;
            };
            let generation = lease.generation;
            let state = Arc::clone(state);
            tokio::spawn(async move {
                let _permit = permit;
                let _lease = lease;
                if let Err(reason) = fetch_and_apply(&state, &reference, generation).await {
                    tracing::warn!(kind = ?reference.kind, byte_len = reference.byte_len, reason, "control blob pull failed");
                }
            });
        }
        ControlBlobMessage::Fetch {
            reference,
            sequence,
        } => {
            if !incoming_fetch_header_valid(&reference, &sender_hex, &local_hex, verified) {
                return;
            }
            let Some(chunk) = state.control_blobs.staged_chunk(&reference, sequence) else {
                return;
            };
            let Ok(permit) = Arc::clone(&state.control_blobs.0.chunk_slots).try_acquire_owned()
            else {
                tracing::warn!("control blob chunk send slots exhausted");
                return;
            };
            let agent = Arc::clone(&state.agent);
            let recipient = *sender;
            tokio::spawn(async move {
                let _permit = permit;
                let message = ControlBlobMessage::Chunk {
                    reference,
                    sequence,
                    data_b64: BASE64.encode(chunk),
                };
                if let Err(reason) = send_message(&agent, &recipient, &message).await {
                    tracing::warn!(reason, "control blob chunk send failed");
                }
            });
        }
        ControlBlobMessage::Chunk {
            reference,
            sequence,
            data_b64,
        } => {
            if !incoming_reference_header_valid(&reference, &sender_hex, &local_hex, verified)
                || data_b64.len() > CHUNK_BYTES.div_ceil(3) * 4
            {
                return;
            }
            let Ok(chunk) = BASE64.decode(data_b64) else {
                return;
            };
            let Some(start) = (sequence as usize).checked_mul(CHUNK_BYTES) else {
                return;
            };
            let Some(expected_len) = (reference.byte_len as usize)
                .checked_sub(start)
                .map(|remaining| remaining.min(CHUNK_BYTES))
            else {
                return;
            };
            if chunk.len() != expected_len {
                return;
            }
            state
                .control_blobs
                .deliver_chunk(&reference, sequence, chunk);
        }
        ControlBlobMessage::Release { reference } => {
            // #876: only the staged blob's own RECIPIENT may release it —
            // the fetch header check enforces sender == reference.recipient
            // and local == reference.source, and the exact reference
            // (digest + length) keys the removal.
            if !incoming_fetch_header_valid(&reference, &sender_hex, &local_hex, verified) {
                return;
            }
            state.control_blobs.release_staged(&reference);
        }
    }
}

async fn fetch_and_apply(
    state: &Arc<AppState>,
    reference: &ControlBlobRef,
    generation: u64,
) -> std::result::Result<(), &'static str> {
    let source = parse_agent_id_hex(&reference.source).map_err(|_| "invalid source")?;
    let deadline = tokio::time::Instant::now() + FETCH_TIMEOUT;
    let total_chunks = reference.byte_len.div_ceil(CHUNK_BYTES as u64);
    let mut bytes = Vec::new();
    for sequence in 0..total_chunks {
        let sequence = u32::try_from(sequence).map_err(|_| "too many control chunks")?;
        let mut received = None;
        for _ in 0..CHUNK_RETRIES {
            if tokio::time::Instant::now() >= deadline {
                return Err("control blob fetch deadline");
            }
            let attempt_deadline =
                (tokio::time::Instant::now() + CHUNK_ATTEMPT_TIMEOUT).min(deadline);
            let (tx, rx) = oneshot::channel();
            if !state
                .control_blobs
                .set_waiter(reference, generation, sequence, tx)
            {
                return Err("control blob fetch cancelled");
            }
            let fetch = ControlBlobMessage::Fetch {
                reference: reference.clone(),
                sequence,
            };
            if !matches!(
                tokio::time::timeout_at(
                    attempt_deadline,
                    send_message(&state.agent, &source, &fetch)
                )
                .await,
                Ok(Ok(()))
            ) {
                continue;
            }
            match tokio::time::timeout_at(attempt_deadline, rx).await {
                Ok(Ok(chunk)) => {
                    received = Some(chunk);
                    break;
                }
                Ok(Err(_)) => return Err("control blob fetch cancelled"),
                Err(_) => continue,
            }
        }
        let Some(chunk) = received else {
            return Err("control blob chunk unavailable");
        };
        bytes.extend_from_slice(&chunk);
        if bytes.len() as u64 > reference.byte_len {
            return Err("control blob length exceeded");
        }
    }
    if !exact_blob_matches_ref(reference, &bytes) {
        return Err("control blob length or digest mismatch");
    }
    // #876: the pull is complete and digest-verified — tell the source it
    // can free the staged copy now instead of holding it to the TTL (the
    // per-peer staging cap then bounds IN-FLIGHT blobs, not TTL-held
    // ones). Best-effort: an older source ignores the unknown message
    // type and keeps TTL semantics; a failure here never fails the fetch.
    // #876 r2 (review minor): best-effort on a TASK — a slow transport
    // must never delay the fetched payload's dispatch to its handler.
    let release_state = Arc::clone(state);
    let release_source = source;
    let release_reference = reference.clone();
    tokio::spawn(async move {
        let release = ControlBlobMessage::Release {
            reference: release_reference,
        };
        if let Err(reason) = send_message(&release_state.agent, &release_source, &release).await {
            tracing::debug!(
                reason,
                "control blob release notice failed (TTL still applies)"
            );
        }
    });
    if !reference_admitted(state, reference).await {
        return Err("control blob binding no longer current");
    }
    match reference.kind {
        ControlBlobKind::NamedGroupEvent => {
            let event: NamedGroupMetadataEvent =
                serde_json::from_slice(&bytes).map_err(|_| "invalid named-group event")?;
            if named_group_metadata_event_group_id(&event) != reference.group_id {
                return Err("control blob event group mismatch");
            }
            log_validated_for_handler(named_group_event_witness_kind(&event), reference);
            let _ = apply_named_group_metadata_event(state, event, source, true, None).await;
        }
        ControlBlobKind::JoinResult => {
            let result: JoinResultMessage =
                serde_json::from_slice(&bytes).map_err(|_| "invalid join result")?;
            let JoinResultMessage::Result { event, chain, .. } = &result else {
                return Err("control blob not a join result response");
            };
            if chain.len() > x0x::groups::COMMIT_LOG_CAP {
                return Err("control blob result chain exceeds retained commit cap");
            }
            let NamedGroupMetadataEvent::MemberAdded {
                group_id, agent_id, ..
            } = event.as_ref()
            else {
                return Err("control blob result not a member add");
            };
            if group_id != &reference.group_id || agent_id != &reference.recipient {
                return Err("control blob result binding mismatch");
            }
            log_validated_for_handler("join_result", reference);
            handle_join_result_message_bound(
                state,
                &source,
                true,
                result,
                reference.join_attempt_id.as_deref(),
            )
            .await;
        }
    }
    Ok(())
}

/// Stage named by the runtime witness: exact length/digest, reference
/// binding and payload shape all passed, and the bytes are about to go to the
/// original handler. That handler may still reject them, so this is never an
/// "applied" receipt.
const WITNESS_STAGE: &str = "reassembled_validated_for_handler";

fn named_group_event_witness_kind(event: &NamedGroupMetadataEvent) -> &'static str {
    if matches!(event, NamedGroupMetadataEvent::MemberAdded { .. }) {
        "member_added"
    } else {
        "named_group_event"
    }
}

fn witness_line(kind: &str, reference: &ControlBlobRef) -> String {
    format!(
        "x0x_control_blob_witness stage={WITNESS_STAGE} kind={kind} byte_len={} digest={}",
        reference.byte_len, reference.digest
    )
}

/// Metadata-only runtime evidence for the Home oversize fixture
/// (`tests/e2e_home_fixture.py` parses this exact line). Never logs payload,
/// keys or invites: the digest was already verified against the bytes.
fn log_validated_for_handler(kind: &'static str, reference: &ControlBlobRef) {
    tracing::info!("{}", witness_line(kind, reference));
}

/// #878 r3: build a fully-valid reference (digest/length bound) for a
/// would-be transfer, for tests that stage it directly.
#[cfg(test)]
pub(in crate::server) fn test_reference(
    bytes: &[u8],
    group_id: &str,
    source_hex: &str,
    recipient_hex: &str,
) -> ControlBlobRef {
    ControlBlobRef {
        kind: ControlBlobKind::NamedGroupEvent,
        group_id: group_id.to_string(),
        source: source_hex.to_string(),
        recipient: recipient_hex.to_string(),
        digest: hex::encode(blake3::hash(bytes).as_bytes()),
        byte_len: bytes.len() as u64,
        join_attempt_id: None,
    }
}

/// Drives the actual stage/chunk/frame/incoming/digest functions without a
/// direct-message socket. Used with signed Home bytes by the route fixture.
#[cfg(test)]
pub(super) fn socket_free_roundtrip(
    kind: ControlBlobKind,
    group_id: &str,
    source: &AgentId,
    recipient: &AgentId,
    join_attempt_id: Option<&str>,
    bytes: Vec<u8>,
) -> Vec<u8> {
    let reference = ControlBlobRef {
        kind,
        group_id: group_id.to_string(),
        source: hex::encode(source.as_bytes()),
        recipient: hex::encode(recipient.as_bytes()),
        digest: hex::encode(blake3::hash(&bytes).as_bytes()),
        byte_len: bytes.len() as u64,
        join_attempt_id: join_attempt_id.map(str::to_string),
    };
    let store = ControlBlobState::default();
    assert!(incoming_reference_header_valid(
        &reference,
        &reference.source,
        &reference.recipient,
        true
    ));
    store
        .stage(reference.clone(), bytes.clone())
        .expect("stage");
    let lease = store
        .reserve_incoming(&reference)
        .expect("reserve incoming lease");
    let mut received = Vec::new();
    for sequence in 0..reference.byte_len.div_ceil(CHUNK_BYTES as u64) {
        let sequence = sequence as u32;
        let chunk = store.staged_chunk(&reference, sequence).expect("chunk");
        let frame = ControlBlobMessage::Chunk {
            reference: reference.clone(),
            sequence,
            data_b64: BASE64.encode(chunk),
        };
        let wire = serde_json::to_vec(&frame).expect("frame serializes");
        assert!(wire.len() <= x0x::dm::MAX_PAYLOAD_BYTES);
        let (tx, mut rx) = oneshot::channel();
        let parsed: ControlBlobMessage = serde_json::from_slice(&wire).expect("frame parses");
        assert!(store.set_waiter(&reference, lease.generation, sequence, tx));

        let ControlBlobMessage::Chunk {
            reference: received_ref,
            sequence: received_seq,
            data_b64,
        } = parsed
        else {
            panic!("chunk frame changed kind");
        };
        assert!(incoming_reference_header_valid(
            &received_ref,
            &received_ref.source,
            &received_ref.recipient,
            true
        ));
        store.deliver_chunk(
            &received_ref,
            received_seq,
            BASE64.decode(data_b64).expect("chunk data"),
        );
        received.extend_from_slice(&rx.try_recv().expect("chunk delivered"));
    }
    drop(lease);
    assert!(exact_blob_matches_ref(&reference, &received));
    assert_eq!(received, bytes);
    received
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(bytes: &[u8]) -> ControlBlobRef {
        ControlBlobRef {
            kind: ControlBlobKind::NamedGroupEvent,
            group_id: "ab".repeat(32),
            source: "11".repeat(32),
            recipient: "22".repeat(32),
            digest: hex::encode(blake3::hash(bytes).as_bytes()),
            byte_len: bytes.len() as u64,
            join_attempt_id: None,
        }
    }

    /// The Home oversize fixture fails unless it parses this exact line, and the
    /// line must never carry routing identities or payload bytes.
    #[test]
    fn witness_line_is_metadata_only_and_matches_fixture_contract() {
        let bytes = vec![7u8; x0x::dm::MAX_PAYLOAD_BYTES + 1];
        let reference = reference(&bytes);
        let line = witness_line("member_added", &reference);
        assert_eq!(
            line,
            format!(
                "x0x_control_blob_witness stage=reassembled_validated_for_handler \
                 kind=member_added byte_len={} digest={}",
                bytes.len(),
                reference.digest
            )
        );
        for identity in [&reference.group_id, &reference.source, &reference.recipient] {
            assert!(!line.contains(identity.as_str()));
        }
    }

    /// #876 (issue item 1): the per-peer staging cap bounds IN-FLIGHT
    /// blobs, not TTL-held ones. A completed pull RELEASES its staged copy
    /// on the source, so a later blob for the same recipient stages. On
    /// the pre-fix head the fifth blob is refused with "staging budget
    /// exhausted" (the fail-before: `release_staged` is a no-op there).
    #[test]
    fn release_on_completed_fetch_frees_the_per_peer_staging_budget() {
        let store = ControlBlobState::default();
        let mut staged = Vec::new();
        for i in 0..PER_PEER_ENTRY_CAP {
            // Distinct payloads => distinct digests => distinct references.
            let bytes = vec![i as u8; x0x::dm::MAX_PAYLOAD_BYTES + 64 + i];
            let reference = reference(&bytes);
            store
                .stage(reference.clone(), bytes)
                .expect("within the per-peer cap");
            staged.push(reference);
        }
        // The cap is real: one more blob for the same recipient is refused.
        let extra = vec![0xEE; x0x::dm::MAX_PAYLOAD_BYTES + 128];
        let extra_reference = reference(&extra);
        assert_eq!(
            store.stage(extra_reference.clone(), extra.clone()),
            Err("control blob staging budget exhausted"),
            "the per-peer cap still bounds in-flight blobs"
        );
        // The recipient completed its pull of the FIRST blob: released.
        store.release_staged(&staged[0]);
        // The next blob for the SAME recipient stages in the freed slot.
        store
            .stage(extra_reference, extra)
            .expect("#876: a released slot is reusable by the same recipient");
    }

    /// #876 r2 (review item 4a, WIRE-LEVEL): three sequential joins, each
    /// staging two oversized events for the SAME recipient; every
    /// completed pull sends its Release THROUGH the source's message
    /// handler (serde round-trip included), freeing the slot for the next
    /// join. With the release path disabled (the fail-before) the third
    /// join's first stage — the FIFTH blob for this recipient — is
    /// refused with "staging budget exhausted" and the event is dropped:
    /// the R15 failure.
    #[tokio::test]
    async fn three_sequential_joins_release_slots_through_the_handler() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state = super::super::super::home::tests::owned_state(dir.path(), [0x73; 32]).await?;
        super::super::super::home::provision_home(&state).await;
        let owner = state.agent.identity().user_keypair().expect("owned Home");
        let (_, info) = super::super::super::home::find_home(&state, &owner.user_id())
            .await
            .expect("Home group");
        let group_id = info.stable_group_id().to_string();
        let recipient = x0x::identity::AgentKeypair::generate()?.agent_id();
        let source_hex = hex::encode(state.agent.agent_id().as_bytes());

        for join in 0..3u32 {
            for event_index in 0..2u32 {
                let bytes = vec![
                    u8::try_from(join * 2 + event_index).unwrap_or(0x7A);
                    x0x::dm::MAX_PAYLOAD_BYTES + 64
                ];
                let reference = ControlBlobRef {
                    kind: ControlBlobKind::NamedGroupEvent,
                    group_id: group_id.clone(),
                    source: source_hex.clone(),
                    recipient: hex::encode(recipient.as_bytes()),
                    digest: hex::encode(blake3::hash(&bytes).as_bytes()),
                    byte_len: bytes.len() as u64,
                    join_attempt_id: None,
                };
                state
                    .control_blobs
                    .stage(reference.clone(), bytes)
                    .unwrap_or_else(|e| panic!("join {join} event {event_index} must stage: {e}"));
                // The completed pull: the recipient's Release goes over
                // the wire (serialized + reparsed) and through the
                // SOURCE's production handler.
                let wire = serde_json::to_vec(&ControlBlobMessage::Release {
                    reference: reference.clone(),
                })?;
                let message: ControlBlobMessage = serde_json::from_slice(&wire)?;
                handle_control_blob_message(&state, &recipient, true, message).await;
            }
        }
        Ok(())
    }
    #[test]
    fn control_ref_rejects_wrong_identity_kind_digest_length_and_expiry() {
        let bytes = vec![0x5a; x0x::dm::MAX_PAYLOAD_BYTES + 1];
        let reference = reference(&bytes);
        assert!(incoming_reference_header_valid(
            &reference,
            &reference.source,
            &reference.recipient,
            true
        ));
        assert!(!incoming_reference_header_valid(
            &reference,
            &reference.recipient,
            &reference.recipient,
            true
        ));
        assert!(!incoming_reference_header_valid(
            &reference,
            &reference.source,
            &reference.source,
            true
        ));
        assert!(!incoming_reference_header_valid(
            &reference,
            &reference.source,
            &reference.recipient,
            false
        ));
        let mut wrong_kind = reference.clone();
        wrong_kind.kind = ControlBlobKind::JoinResult;
        assert!(!basic_reference_valid(&wrong_kind));
        let store = ControlBlobState::default();
        assert!(store.stage(reference.clone(), bytes.clone()).is_ok());
        // Documented bounded retention: a staged blob stays servable until
        // its TTL even when no reference/chunk send ever follows (failed
        // sends do NOT release the stage early).
        assert!(store.staged_chunk(&reference, 0).is_some());
        assert!(store.staged_chunk(&wrong_kind, 0).is_none());
        let mut wrong_group = reference.clone();
        wrong_group.group_id = "cd".repeat(32);
        assert!(store.staged_chunk(&wrong_group, 0).is_none());
        let mut wrong_digest = reference.clone();
        wrong_digest.digest = "00".repeat(32);
        assert!(store.stage(wrong_digest.clone(), bytes.clone()).is_err());
        assert!(!exact_blob_matches_ref(&wrong_digest, &bytes));
        let mut wrong_len = reference.clone();
        wrong_len.byte_len += 1;
        assert!(store.stage(wrong_len.clone(), bytes.clone()).is_err());
        assert!(!exact_blob_matches_ref(&wrong_len, &bytes));
        let mut damaged = bytes.clone();
        damaged[0] ^= 1;
        assert!(!exact_blob_matches_ref(&reference, &damaged));
        assert!(!exact_blob_matches_ref(
            &reference,
            &bytes[..bytes.len() - 1]
        ));
        store.with_registry(|registry| {
            registry
                .staged
                .get_mut(&reference)
                .expect("entry")
                .created_at = Instant::now() - PENDING_JOIN_RESULT_TTL;
        });
        assert!(store.staged_chunk(&reference, 0).is_none());
        let held = store
            .reserve_incoming(&reference)
            .expect("first reservation");
        store.with_registry(|registry| {
            registry
                .incoming
                .get_mut(&reference)
                .expect("incoming entry")
                .created_at = Instant::now() - FETCH_TIMEOUT;
        });
        // Expired ROUTING frees the duplicate check, and the old lease's
        // tiny declared bytes cannot breach the incoming budget.
        assert!(
            store.reserve_incoming(&reference).is_some(),
            "expired incoming slot released"
        );
        drop(held);
    }

    #[test]
    fn control_incoming_dedupes_and_staging_limits_per_recipient() {
        let store = ControlBlobState::default();
        let mut leases = Vec::new();
        for i in 0..PER_PEER_ENTRY_CAP {
            let bytes = vec![i as u8; x0x::dm::MAX_PAYLOAD_BYTES + 1];
            let reference = reference(&bytes);
            assert!(store.stage(reference.clone(), bytes).is_ok());
            leases.push(store.reserve_incoming(&reference).expect("reserve"));
            assert!(store.reserve_incoming(&reference).is_none());
        }
        let overflow = vec![0xff; x0x::dm::MAX_PAYLOAD_BYTES + 1];
        let overflow_ref = reference(&overflow);
        assert_eq!(
            store.stage(overflow_ref.clone(), overflow).unwrap_err(),
            "control blob staging budget exhausted"
        );
        assert!(store.reserve_incoming(&overflow_ref).is_none());
        store.cancel_attempt(&overflow_ref.group_id, &overflow_ref.recipient, "unrelated");
        let spare = reference(&vec![0; x0x::dm::MAX_PAYLOAD_BYTES + 1]);
        assert!(
            store.reserve_incoming(&spare).is_none(),
            "active routing slots stay taken while leases live"
        );
        drop(leases);
    }

    #[test]
    fn control_chunk_order_cancellation_and_group_cleanup_release_reservations() {
        let bytes = vec![0x41; x0x::dm::MAX_PAYLOAD_BYTES + 1];
        let mut reference = reference(&bytes);
        reference.kind = ControlBlobKind::JoinResult;
        reference.join_attempt_id = Some("current-attempt".to_string());
        let store = ControlBlobState::default();
        store.stage(reference.clone(), bytes).expect("stage result");
        let lease = store.reserve_incoming(&reference).expect("reserve");
        assert!(store.reserve_incoming(&reference).is_none());
        let (tx, mut rx) = oneshot::channel();
        assert!(store.set_waiter(&reference, lease.generation, 0, tx));
        store.deliver_chunk(&reference, 1, vec![0x41]);
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        store.deliver_chunk(&reference, 0, vec![0x41]);
        assert_eq!(rx.try_recv().expect("ordered chunk"), vec![0x41]);
        let (tx, mut rx) = oneshot::channel();
        assert!(store.set_waiter(&reference, lease.generation, 1, tx));
        store.cancel_attempt(&reference.group_id, &reference.recipient, "other-attempt");
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        store.cancel_attempt(&reference.group_id, &reference.recipient, "current-attempt");
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        drop(lease);
        assert!(store.reserve_incoming(&reference).is_some());
        let aliases = HashSet::from([reference.group_id.clone()]);
        store.prune_groups(&aliases);
        assert!(store.staged_chunk(&reference, 0).is_none());
        assert!(store.reserve_incoming(&reference).is_some());
    }

    #[test]
    fn control_global_byte_budgets_reject_pressure_without_widening_dm_limit() {
        let incoming = ControlBlobState::default();
        let mut leases = Vec::new();
        for i in 1..=3u8 {
            let bytes = vec![i; MAX_BLOB_BYTES as usize];
            let mut candidate = reference(&bytes);
            candidate.source = format!("{i:02x}").repeat(32);
            assert!(basic_reference_valid(&candidate));
            match incoming.reserve_incoming(&candidate) {
                Some(lease) => {
                    assert!(
                        i <= 2,
                        "third 8 MiB reservation must breach the 16 MiB budget"
                    );
                    leases.push(lease);
                }
                None => assert!(i == 3, "first two reservations must be admitted"),
            }
        }
        assert_eq!(incoming.incoming_bytes_held(), 2 * MAX_BLOB_BYTES);
        drop(leases);
        assert_eq!(incoming.incoming_bytes_held(), 0);
        let bytes = vec![1u8; MAX_BLOB_BYTES as usize];
        let mut candidate = reference(&bytes);
        candidate.source = "01".repeat(32);
        assert!(incoming.reserve_incoming(&candidate).is_some());

        let staged = ControlBlobState::default();
        for i in 1..=5u8 {
            let bytes = vec![i; MAX_BLOB_BYTES as usize];
            let mut candidate = reference(&bytes);
            candidate.recipient = format!("{i:02x}").repeat(32);
            assert_eq!(staged.stage(candidate, bytes).is_ok(), i <= 4);
        }
    }

    #[test]
    fn incoming_bytes_stay_held_until_lease_drop_and_generations_guard_rerouting() {
        let store = ControlBlobState::default();
        let bytes = vec![0x33; x0x::dm::MAX_PAYLOAD_BYTES + 1];
        let mut big = reference(&bytes);
        big.kind = ControlBlobKind::JoinResult;
        big.join_attempt_id = Some("attempt-a".to_string());
        // Declared length only: reservation never allocates for it. Half
        // the per-source cap so a same-source replacement still fits.
        big.byte_len = MAX_BLOB_BYTES / 2;
        let lease_a = store.reserve_incoming(&big).expect("first lease");
        assert_eq!(store.incoming_bytes_held(), MAX_BLOB_BYTES / 2);

        // Cancellation removes ROUTING but never releases the bytes: the
        // cancelled task can still own a reassembly Vec inside a
        // 30-second chunk-send await.
        store.cancel_attempt(&big.group_id, &big.recipient, "attempt-a");
        let (stale_tx, _stale_rx) = oneshot::channel();
        assert!(!store.set_waiter(&big, lease_a.generation, 0, stale_tx));

        // The replacement is admitted only because lease_a's 4 MiB plus
        // the new 4 MiB still fits BOTH budgets — not because cancel
        // freed lease_a's bytes (they remain held).
        let lease_b = store.reserve_incoming(&big).expect("replacement lease");
        assert!(lease_b.generation > lease_a.generation);
        assert_eq!(store.incoming_bytes_held(), MAX_BLOB_BYTES);

        // The old task must not steal the new reservation's waiter. Its
        // rejected sender drops without a value, so the stale channel
        // closes EMPTY — never delivering a chunk.
        let (stale_tx, mut stale_rx) = oneshot::channel();
        assert!(!store.set_waiter(&big, lease_a.generation, 0, stale_tx));
        assert!(matches!(
            stale_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        let (tx, mut rx) = oneshot::channel();
        assert!(store.set_waiter(&big, lease_b.generation, 0, tx));

        // A third same-source reservation is blocked while both leases
        // live: 12 MiB held for this source breaches the 8 MiB per-source
        // cap even though the 16 MiB global budget would allow it.
        assert!(
            store.reserve_incoming(&big).is_none(),
            "held-but-cancelled bytes must still constrain admission"
        );

        // The old lease's drop must not delete the newer routing entry.
        drop(lease_a);
        assert_eq!(store.incoming_bytes_held(), MAX_BLOB_BYTES / 2);
        store.deliver_chunk(&big, 0, vec![0x33]);
        assert_eq!(rx.try_recv().expect("current waiter served"), vec![0x33]);

        drop(lease_b);
        assert_eq!(store.incoming_bytes_held(), 0);
        assert!(store.reserve_incoming(&big).is_some());
    }

    /// Bounded teardown, executed rather than asserted from caps — and the
    /// deadline itself is proven to BIND. All three phases drive the REAL
    /// `fetch_and_apply` loop under a paused clock with chunks delivered
    /// through the same `deliver_chunk` ingress the wire handler uses; the
    /// only replaced element is the transport. No socket is involved.
    #[tokio::test(start_paused = true)]
    async fn fetch_task_deadline_binds_and_cancel_exits_promptly() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state = super::super::super::home::tests::owned_state(dir.path(), [0x73; 32]).await?;
        let store = state.control_blobs.clone();
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());

        // NamedGroupEvent kind: admission only requires a locally known
        // group, which the test seeds directly (no join attempt needed).
        let group_key = "77".repeat(32);
        state.named_groups.write().await.insert(group_key.clone(), {
            // stable_group_id() falls back to mls_group_id when no
            // genesis exists, so admission matches the reference group.
            x0x::groups::GroupInfo::with_policy(
                group_key.clone(),
                String::new(),
                state.agent.agent_id(),
                group_key.clone(),
                x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
            )
        });
        let build_reference =
            |kind: ControlBlobKind, group_hex: &str, bytes: &[u8]| ControlBlobRef {
                kind,
                group_id: group_hex.to_string(),
                source: local_hex.clone(),
                recipient: local_hex.clone(),
                digest: hex::encode(blake3::hash(bytes).as_bytes()),
                byte_len: bytes.len() as u64,
                join_attempt_id: (kind == ControlBlobKind::JoinResult)
                    .then(|| "attempt".to_string()),
            };
        // Enough chunks (4) that two can succeed before a stalled third.
        // stage() enforces digest and length consistency; build the staged
        // payload first, then the reference from its exact bytes.
        let staged: Vec<u8> = vec![0x5a; 3 * CHUNK_BYTES + 1];
        let mut reference = build_reference(ControlBlobKind::NamedGroupEvent, &group_key, &staged);
        reference.byte_len = reference
            .byte_len
            .max(x0x::dm::MAX_PAYLOAD_BYTES as u64 + 1);
        let staged = vec![0x5a; reference.byte_len as usize];
        reference.digest = hex::encode(blake3::hash(&staged).as_bytes());
        store
            .stage(reference.clone(), staged)
            .expect("stage controlled blob");

        async fn wait_for_sequence(
            store: &ControlBlobState,
            reference: &ControlBlobRef,
            sequence: u32,
        ) -> bool {
            let _ = tokio::time::timeout(FETCH_TIMEOUT, async {
                loop {
                    if store.incoming_waiter_sequence(reference) == Some(sequence) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
            store.incoming_waiter_sequence(reference) == Some(sequence)
        }

        // Phase 1 — positive control: with every chunk served, the REAL
        // loop completes and returns the exact staged bytes.
        {
            let lease = store.reserve_incoming(&reference).expect("lease");
            let state = std::sync::Arc::clone(&state);
            let task_reference = reference.clone();
            let fetch = tokio::spawn(async move {
                fetch_and_apply(&state, &task_reference, lease.generation).await
            });
            let total = reference.byte_len.div_ceil(CHUNK_BYTES as u64) as u32;
            for sequence in 0..total {
                assert!(
                    wait_for_sequence(&store, &reference, sequence).await,
                    "fetch loop must request chunk {sequence}"
                );
                let chunk = store
                    .staged_chunk(&reference, sequence)
                    .expect("staged chunk");
                store.deliver_chunk(&reference, sequence, chunk);
            }
            // Transport-completion positive control: with every chunk
            // served, the loop finishes reassembly and enters the
            // POST-transfer stage. The 0x5a payload is not valid event
            // JSON, so the deterministic terminal error is the parse-stage
            // rejection ("invalid named-group event") — or, if admission
            // raced, its binding error. Either proves bytes+digest+length
            // completed; a transport failure ("chunk unavailable" /
            // "deadline" / "cancelled") would FAIL this assertion. Real
            // crypto apply success is proven separately by the route
            // fixture; production auth is untouched.
            let outcome = fetch.await.expect("fetch task");
            assert!(
                matches!(
                    outcome,
                    Err("invalid named-group event")
                        | Err("control blob binding no longer current")
                ),
                "all-chunks-served control must reach a post-transfer error, got {outcome:?}"
            );
            drop(lease);
            assert_eq!(store.incoming_bytes_held(), 0);
        }

        // Phase 2 — the deadline BINDS. Two earlier chunks succeed after
        // deliberate delay (consuming ~56 s of the 90 s window); the third
        // stalls. Retry exhaustion alone would run to ~146 s, so only the
        // overall deadline check can end the loop at ~90 s with its exact
        // reason. Removing the check flips the reason to `chunk
        // unavailable`; extending FETCH_TIMEOUT pushes elapsed past the
        // bound below.
        {
            let lease = store.reserve_incoming(&reference).expect("lease");
            let started = tokio::time::Instant::now();
            let state = std::sync::Arc::clone(&state);
            let task_reference = reference.clone();
            let fetch = tokio::spawn(async move {
                fetch_and_apply(&state, &task_reference, lease.generation).await
            });
            for sequence in 0..2u32 {
                assert!(
                    wait_for_sequence(&store, &reference, sequence).await,
                    "fetch loop must request chunk {sequence}"
                );
                // Advance the paused clock so the stalled tail cannot fit
                // its full retry budget inside the deadline.
                tokio::time::sleep(Duration::from_secs(28)).await;
                let chunk = store
                    .staged_chunk(&reference, sequence)
                    .expect("staged chunk");
                store.deliver_chunk(&reference, sequence, chunk);
            }
            assert!(
                wait_for_sequence(&store, &reference, 2).await,
                "stalled tail must be requested"
            );
            let outcome = fetch.await.expect("fetch task");
            let elapsed = tokio::time::Instant::now() - started;
            assert_eq!(
                outcome.expect_err("stalled tail must fail"),
                "control blob fetch deadline",
                "the overall deadline — not retry exhaustion — must end the loop"
            );
            assert!(
                elapsed >= FETCH_TIMEOUT && elapsed < FETCH_TIMEOUT + Duration::from_secs(1),
                "deadline must bind at FETCH_TIMEOUT, took {elapsed:?}"
            );
            drop(lease);
            assert_eq!(store.incoming_bytes_held(), 0);
        }

        // Phase 3 — cancellation exits at the first waiter registration
        // and releases the lease bytes. Uses a JoinResult-kind reference so
        // cancel_attempt's attempt binding matches, exactly like the join
        // finalization teardown path.
        {
            let mut cancel_reference = reference.clone();
            cancel_reference.kind = ControlBlobKind::JoinResult;
            cancel_reference.join_attempt_id = Some("attempt".to_string());
            let lease = store.reserve_incoming(&cancel_reference).expect("lease");
            store.cancel_attempt(
                &cancel_reference.group_id,
                &cancel_reference.recipient,
                "attempt",
            );
            let started = tokio::time::Instant::now();
            let reason = fetch_and_apply(&state, &cancel_reference, lease.generation)
                .await
                .expect_err("cancelled reservation must fail");
            assert_eq!(reason, "control blob fetch cancelled");
            assert!(tokio::time::Instant::now() - started < FETCH_TIMEOUT);
            drop(lease);
            assert_eq!(store.incoming_bytes_held(), 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn join_result_reference_requires_current_attempt_and_expected_inviter() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state = super::super::super::home::tests::owned_state(dir.path(), [0x71; 32]).await?;
        super::super::super::home::provision_home(&state).await;
        let owner = state.agent.identity().user_keypair().expect("owned Home");
        let (_, info) = super::super::super::home::find_home(&state, &owner.user_id())
            .await
            .expect("Home group");
        let group_id = info.stable_group_id().to_string();
        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        let source = hex::encode(
            x0x::identity::AgentKeypair::generate()?
                .agent_id()
                .as_bytes(),
        );
        let bytes = vec![0x71; x0x::dm::MAX_PAYLOAD_BYTES + 1];
        let mut reference = reference(&bytes);
        reference.kind = ControlBlobKind::JoinResult;
        reference.group_id = group_id.clone();
        reference.source = source.clone();
        reference.recipient = recipient.clone();
        reference.join_attempt_id = Some("current".to_string());
        let key = join_result_key(&group_id, &recipient);
        state
            .pending_join_attempts
            .lock()
            .expect("attempt registry")
            .insert(
                key.clone(),
                PendingJoinAttempt {
                    attempt_id: "current".to_string(),
                    local_group_key: info.mls_group_id.clone(),
                    invite_fingerprint: "test".to_string(),
                    invite_group_id: group_id.clone(),
                    inviter_public_key_b64: String::new(),
                    stored_resend: None,
                    polls: Vec::new(),
                    tasks: Vec::new(),
                    listener_token: None,
                },
            );
        record_expected_join_result_inviter(&state, key.clone(), source.clone());
        assert!(reference_admitted(&state, &reference).await);
        let mut stale = reference.clone();
        stale.join_attempt_id = Some("superseded".to_string());
        assert!(!reference_admitted(&state, &stale).await);
        let mut wrong_source = reference.clone();
        wrong_source.source = hex::encode(
            x0x::identity::AgentKeypair::generate()?
                .agent_id()
                .as_bytes(),
        );
        assert!(!reference_admitted(&state, &wrong_source).await);
        let mut wrong_group = reference.clone();
        wrong_group.group_id = "ff".repeat(32);
        assert!(!reference_admitted(&state, &wrong_group).await);
        state
            .pending_join_attempts
            .lock()
            .expect("attempt registry")
            .remove(&key);
        assert!(!reference_admitted(&state, &reference).await);
        Ok(())
    }
}
