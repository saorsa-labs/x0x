//! Direct push of one signed share-grant revocation record (#1003).
//!
//! Design: ADR 0080 (archived, `docs/adr-archive/0080-grant-revocation-direct-push.md`)
//! under consolidated slot A03. `DELETE /grants/:id` makes the revocation
//! durable and publishes it on the `x0x.revocation.v3` gossip carrier as
//! before. This module adds a best-effort accelerator: the ONE new record
//! is also pushed, as a typed DM, to each recipient of the revoked grant
//! whose current verified capability advert sets
//! [`crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1`]. Gossip
//! stays the backstop; a missed push costs only latency.
//!
//! # Wire format
//!
//! `x0x-grant-revocation-push-v1\0` ‖ `bincode(RevocationRecord)` —
//! exactly one record, never a `Vec`, at most
//! `MAX_GRANT_REVOCATION_PUSH_BYTES` bytes with the prefix. The record's
//! bytes equal its encoding inside a v3 gossip batch, and the record
//! carries its own authority (the owner's ML-DSA-65 signature). The DM
//! envelope's sender gives none; it is used only for the rate limit.
//!
//! # Gate (positive evidence)
//!
//! Unlike `share_grant_v1`-style holds, the sender pushes only when a
//! current verified advert HAS the bit. Unknown, expired and card-only
//! state means "no push": an old receiver would show the payload as an
//! ordinary DM. On unknown capability the sender asks for one targeted
//! advert refresh and waits up to `UNKNOWN_CAPABILITY_WAIT`; gossip runs
//! during the wait, so the revocation is never held back.
//!
//! # Receiver
//!
//! Prefix ownership is unconditional: the payload never reaches DM
//! history or DM subscribers, verified or not, before and after the inbox
//! is ready, on the raw direct path AND the gossip DM path. The registered
//! typed route covers a running x0xd inbox. On the raw path a verified
//! push with no route is dropped and logged `not_ready` in
//! `dispatch_raw_direct_after_gates`, an unverified one by the static
//! production-prefix table. On the gossip v1 and v2-durable paths a
//! push-prefixed payload that no route claims is dropped before the
//! dedupe claim / withheld before dispatch, so a daemon that never wires
//! the route (a library embedder) leaks nothing either; every other
//! prefix, and any frame a route's validator refused, keeps its
//! documented generic path. The bit itself is
//! ROUTE-GATED (`CapabilityRegistry::advertised`): such a daemon never
//! advertises `grant_revocation_push_v1`, so a conforming sender never
//! pushes to it and gossip stays its only carrier.
//!
//! The handler stops at the first
//! failure — decode, subject, stale, known-record (no verify), rate
//! limit — then hands the one record to the SAME ingest as the v3 gossip
//! carrier (`crate::ingest_share_grant_revocation_records`): one verify
//! path, one revocation barrier, one store. A push can arrive before the
//! grant DM it revokes; the stored revocation then refuses the late grant
//! ([`crate::share_grant::handle_share_grant_dm_checked`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::identity::AgentId;
use crate::revocation::{RevocationRecord, RevocationSet, RevokedSubject};

/// Versioned, NUL-terminated DM prefix of a grant-revocation push.
pub const GRANT_REVOCATION_PUSH_PREFIX: &[u8] = b"x0x-grant-revocation-push-v1\0";

/// Upper bound on one encoded push, prefix included. A real record is
/// about 5.4 KB (an ML-DSA-65 public key, a signature and ~100 B of
/// fields, no reason text); the bound leaves room for a bounded reason.
pub const MAX_GRANT_REVOCATION_PUSH_BYTES: usize = 8 * 1024;

/// Retries after the first send attempt (total attempts = 1 + retries).
/// ADR 0080 §3: the sender retries ONLY on a local send error and waits
/// for no ACK — a send that returns success ends the push, so the send
/// layer itself runs with `max_retries: 0` (it would republish even after
/// a successful publish) and the retry loop lives in this module.
pub const GRANT_REVOCATION_PUSH_SEND_RETRIES: u8 = 2;

/// At most this many pushes may be pending in memory at a time; one over
/// the bound is skipped and counted. A restart drops pending pushes —
/// gossip still carries the record.
pub const MAX_PENDING_PUSHES: usize = 1024;

/// How long a push waits for a current verified advert from a peer of
/// unknown capability, after one targeted refresh (one ADR 0093 advert
/// period).
pub const UNKNOWN_CAPABILITY_WAIT: Duration = Duration::from_secs(600);

/// How often the capability wait re-reads the advert cache.
const UNKNOWN_CAPABILITY_POLL: Duration = Duration::from_secs(10);

/// Receiver-side rate limit: pushes per minute accepted from one sending
/// agent.
pub const PUSH_RATE_PER_SENDER_PER_MINUTE: u32 = 16;

/// Receiver-side rate limit: pushes per minute accepted in total.
pub const PUSH_RATE_TOTAL_PER_MINUTE: u32 = 256;

/// Why a received push was dropped before the shared ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushDrop {
    /// Not one strictly decoded `RevocationRecord` within the bound.
    Malformed,
    /// Not a `ShareGrant` subject with a finite `grant_expiry`.
    WrongSubject,
    /// Past the record's GC horizon: the grant can no longer be honoured.
    Stale,
    /// The record's hash is already in the set (verified when it entered).
    Duplicate,
    /// Over the per-sender or total rate limit.
    RateLimited,
}

impl PushDrop {
    /// Counter label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::WrongSubject => "wrong_subject",
            Self::Stale => "stale",
            Self::Duplicate => "duplicate",
            Self::RateLimited => "rate_limited",
        }
    }
}

/// Outcome of handling one received push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The record reached the shared v3 ingest. `inserted` is false when
    /// the ingest's own verify refused it (counted with the forged-v3
    /// counter there) or a concurrent carrier inserted it first.
    Ingested {
        /// A new record entered the set (and was persisted).
        inserted: bool,
    },
    /// Dropped before the ingest; no verify ran.
    Dropped(PushDrop),
}

/// Encode one push payload.
///
/// # Errors
/// The subject is not a `ShareGrant`, its `grant_expiry` is `u64::MAX`
/// (an unknown grant travels by gossip only), the record does not encode,
/// or the payload exceeds [`MAX_GRANT_REVOCATION_PUSH_BYTES`].
pub fn encode_grant_revocation_push(record: &RevocationRecord) -> Result<Vec<u8>, String> {
    let RevokedSubject::ShareGrant(subject) = &record.subject else {
        return Err("only ShareGrant revocations are pushed".to_string());
    };
    if subject.grant_expiry == u64::MAX {
        return Err("a record for an unknown grant is never pushed".to_string());
    }
    let body = bincode::serialize(record).map_err(|e| format!("encode: {e}"))?;
    let mut out = Vec::with_capacity(GRANT_REVOCATION_PUSH_PREFIX.len() + body.len());
    out.extend_from_slice(GRANT_REVOCATION_PUSH_PREFIX);
    out.extend_from_slice(&body);
    if out.len() > MAX_GRANT_REVOCATION_PUSH_BYTES {
        return Err("push payload over bound".to_string());
    }
    Ok(out)
}

/// Strictly decode one push payload: the prefix, the size bound, exactly
/// one record with every byte consumed, and a `ShareGrant` subject with a
/// finite `grant_expiry`.
///
/// # Errors
/// [`PushDrop::Malformed`] or [`PushDrop::WrongSubject`].
pub fn decode_grant_revocation_push(payload: &[u8]) -> Result<RevocationRecord, PushDrop> {
    let body = payload
        .strip_prefix(GRANT_REVOCATION_PUSH_PREFIX)
        .ok_or(PushDrop::Malformed)?;
    if payload.len() > MAX_GRANT_REVOCATION_PUSH_BYTES {
        return Err(PushDrop::Malformed);
    }
    use bincode::Options;
    let record: RevocationRecord = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_GRANT_REVOCATION_PUSH_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(body)
        .map_err(|_| PushDrop::Malformed)?;
    match &record.subject {
        RevokedSubject::ShareGrant(subject) if subject.grant_expiry != u64::MAX => Ok(record),
        _ => Err(PushDrop::WrongSubject),
    }
}

/// Receiver-side sliding-minute rate limiter (step 5 of the handler).
#[derive(Debug)]
pub struct PushRateLimiter {
    window_started: std::time::Instant,
    per_sender: HashMap<[u8; 32], u32>,
    total: u32,
}

impl Default for PushRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PushRateLimiter {
    /// An empty window starting now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            window_started: std::time::Instant::now(),
            per_sender: HashMap::new(),
            total: 0,
        }
    }

    /// Whether a push from `sender` is admitted at `now`.
    pub fn admit(&mut self, sender: &AgentId, now: std::time::Instant) -> bool {
        if now.duration_since(self.window_started) >= Duration::from_secs(60) {
            self.window_started = now;
            self.per_sender.clear();
            self.total = 0;
        }
        if self.total >= PUSH_RATE_TOTAL_PER_MINUTE {
            return false;
        }
        let count = self.per_sender.entry(*sender.as_bytes()).or_insert(0);
        if *count >= PUSH_RATE_PER_SENDER_PER_MINUTE {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
}

/// Handle one received push (the typed route's handler).
///
/// Steps 1 to 5 use no signature verify; the shared ingest does the only
/// verify (the owner's signature over the record's canonical bytes).
pub(crate) async fn handle_grant_revocation_push(
    owner_trust: &crate::owner_trust::OwnerTrust,
    revocation_set: &tokio::sync::RwLock<RevocationSet>,
    identity_dir: Option<&std::path::Path>,
    limiter: &tokio::sync::Mutex<PushRateLimiter>,
    sender: AgentId,
    payload: &[u8],
    now_unix: u64,
) -> PushOutcome {
    // 1 + 2: decode and subject.
    let record = match decode_grant_revocation_push(payload) {
        Ok(record) => record,
        Err(drop) => return PushOutcome::Dropped(drop),
    };
    let RevokedSubject::ShareGrant(subject) = &record.subject else {
        return PushOutcome::Dropped(PushDrop::WrongSubject);
    };
    // 3: stale — past the GC horizon the grant can no longer be honoured.
    if subject.gc_eligible_at(now_unix) {
        return PushOutcome::Dropped(PushDrop::Stale);
    }
    // 4: known record, by record hash; no verify for a duplicate.
    if revocation_set
        .read()
        .await
        .contains_hash(&record.record_hash())
    {
        return PushOutcome::Dropped(PushDrop::Duplicate);
    }
    // 5: rate limit, keyed by the sending agent (which gives no authority).
    if !limiter
        .lock()
        .await
        .admit(&sender, std::time::Instant::now())
    {
        return PushOutcome::Dropped(PushDrop::RateLimited);
    }
    // 6: the shared v3 ingest — barrier, one verify, insert, persist.
    let inserted = crate::ingest_share_grant_revocation_records(
        owner_trust,
        revocation_set,
        identity_dir,
        vec![record],
    )
    .await;
    PushOutcome::Ingested { inserted }
}

/// Report of the pushes `DELETE /grants/:id` scheduled. Pushes run in the
/// background; the DELETE does not wait for them. The counts are what was
/// scheduled or skipped at revoke time, not what arrived (there is no ACK).
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct GrantRevocationPushReport {
    /// Recipients of the revoked grant computed at revoke time.
    pub recipients: usize,
    /// Pushes scheduled (sent now, or awaiting one capability refresh).
    pub scheduled: usize,
    /// Recipients whose current verified advert lacks the bit.
    pub skipped_not_capable: usize,
    /// Pushes skipped because [`MAX_PENDING_PUSHES`] was reached.
    pub skipped_bound: usize,
}

/// In-memory pending-push count (ADR 0080 §3: at most
/// [`MAX_PENDING_PUSHES`], a restart drops them all).
static PENDING_PUSHES: AtomicUsize = AtomicUsize::new(0);

/// RAII slot in the pending-push bound.
struct PendingSlot;

impl PendingSlot {
    fn try_take() -> Option<Self> {
        let mut current = PENDING_PUSHES.load(Ordering::Relaxed);
        loop {
            if current >= MAX_PENDING_PUSHES {
                return None;
            }
            match PENDING_PUSHES.compare_exchange(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self),
                Err(seen) => current = seen,
            }
        }
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        PENDING_PUSHES.fetch_sub(1, Ordering::Relaxed);
    }
}

impl crate::Agent {
    /// Handle one delivered push (the daemon's typed-DM route): the
    /// receiver steps above against this daemon's revocation set, then the
    /// shared v3 ingest. A `completion` on the typed payload is resolved
    /// (`Err` on a drop), but the sender never waits for it.
    pub async fn handle_grant_revocation_push_delivery(
        &self,
        limiter: &tokio::sync::Mutex<PushRateLimiter>,
        typed: crate::dm_inbox::DmTypedPayload,
    ) -> PushOutcome {
        let sender = typed.sender;
        let outcome = handle_grant_revocation_push(
            self.owner_trust(),
            &self.revocation_set,
            self.identity_dir.as_deref(),
            limiter,
            sender,
            &typed.payload,
            Self::unix_timestamp_secs(),
        )
        .await;
        match outcome {
            PushOutcome::Ingested { inserted } => tracing::info!(
                sender = %hex::encode(sender.as_bytes()),
                inserted,
                "grant revocation push ingested"
            ),
            PushOutcome::Dropped(drop) => tracing::debug!(
                sender = %hex::encode(sender.as_bytes()),
                reason = drop.as_str(),
                "grant revocation push dropped"
            ),
        }
        if let Some(completion) = typed.completion {
            let _ = completion.send(match outcome {
                PushOutcome::Ingested { .. } => {
                    Ok(crate::dm_inbox::DmTypedPayloadCompletion::Inserted)
                }
                PushOutcome::Dropped(drop) => Err(drop.as_str().to_string()),
            });
        }
        outcome
    }
}

/// Schedule the best-effort pushes for one just-revoked grant: compute the
/// delivery recipient set (the shared agents' daemons and the grantee's
/// known agents), gate each on positive capability evidence, and send in
/// background tasks. Returns at once with what was scheduled. Call only
/// after the revocation is durable.
pub(crate) async fn schedule_share_grant_revocation_push(
    agent: &std::sync::Arc<crate::Agent>,
    record: &RevocationRecord,
    grant: &crate::share_grant::ShareGrant,
) -> GrantRevocationPushReport {
    let mut report = GrantRevocationPushReport::default();
    let payload = match encode_grant_revocation_push(record) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!("grant revocation push not encodable: {e}");
            return report;
        }
    };
    let recipients = agent.share_grant_recipients(grant, &[]).await;
    report.recipients = recipients.len();
    let bit = crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1;
    for recipient in recipients {
        match agent
            .capability_store()
            .verified_registry_supports(&recipient, bit)
        {
            Some(false) => report.skipped_not_capable += 1,
            known => {
                let Some(slot) = PendingSlot::try_take() else {
                    report.skipped_bound += 1;
                    continue;
                };
                report.scheduled += 1;
                let agent = std::sync::Arc::clone(agent);
                let payload = payload.clone();
                let known_capable = known == Some(true);
                tokio::spawn(async move {
                    let _slot = slot;
                    push_grant_revocation_to(&agent, recipient, payload, known_capable).await;
                });
            }
        }
    }
    report
}

/// One push: resolve unknown capability (one targeted refresh, then a
/// bounded wait; D113 — positive evidence only), then send the typed DM
/// with no ACK wait.
async fn push_grant_revocation_to(
    agent: &crate::Agent,
    recipient: AgentId,
    payload: Vec<u8>,
    known_capable: bool,
) {
    let bit = crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1;
    if !known_capable {
        agent.refresh_application_capability(recipient, bit).await;
        let deadline = tokio::time::Instant::now() + UNKNOWN_CAPABILITY_WAIT;
        loop {
            match agent
                .capability_store()
                .verified_registry_supports(&recipient, bit)
            {
                Some(true) => break,
                Some(false) => {
                    tracing::debug!(
                        recipient = %hex::encode(recipient.as_bytes()),
                        "grant revocation push skipped: advert lacks the bit"
                    );
                    return;
                }
                None => {
                    if tokio::time::Instant::now() >= deadline {
                        tracing::debug!(
                            recipient = %hex::encode(recipient.as_bytes()),
                            "grant revocation push skipped: capability unknown after wait"
                        );
                        return;
                    }
                    tokio::time::sleep(UNKNOWN_CAPABILITY_POLL).await;
                }
            }
        }
    }
    let config = crate::dm::DmSendConfig {
        // ADR 0080 §3: no ACK of any kind is waited for, and a send that
        // returns success ends this push. The send layer's own retry loop
        // republishes even after a successful publish when no ACK is
        // required, so it is OFF here; local-error retries run below.
        max_retries: 0,
        require_gossip_ack: false,
        require_durable_app_ack: false,
        prefer_raw_quic_if_connected: true,
        ..crate::dm::DmSendConfig::default()
    };
    let sent = send_push_with_local_retries(|attempt| {
        let payload = payload.clone();
        let config = config.clone();
        async move {
            if attempt > 0 {
                tracing::debug!(
                    recipient = %hex::encode(recipient.as_bytes()),
                    attempt,
                    "grant revocation push retrying after a local send error"
                );
            }
            agent
                .send_direct_with_config(&recipient, payload, config)
                .await
        }
    })
    .await;
    match sent {
        Ok(_) => tracing::info!(
            recipient = %hex::encode(recipient.as_bytes()),
            "grant revocation pushed"
        ),
        Err(e) => tracing::info!(
            recipient = %hex::encode(recipient.as_bytes()),
            "grant revocation push send failed (gossip remains the backstop): {e}"
        ),
    }
}

/// Run `send` until it returns `Ok`, retrying ONLY on an error, at most
/// `1 + GRANT_REVOCATION_PUSH_SEND_RETRIES` attempts in total (ADR 0080
/// §3: one successful send ends the push — it is never republished).
/// `send` receives the 0-based attempt number.
async fn send_push_with_local_retries<F, Fut, T, E>(mut send: F) -> Result<T, E>
where
    F: FnMut(u8) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut attempt: u8 = 0;
    loop {
        match send(attempt).await {
            Ok(value) => return Ok(value),
            Err(e) if attempt >= GRANT_REVOCATION_PUSH_SEND_RETRIES => return Err(e),
            Err(_) => attempt += 1,
        }
    }
}

#[cfg(test)]
mod tests;
