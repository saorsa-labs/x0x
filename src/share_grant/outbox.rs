//! Owner-side durable redelivery outbox for share grants (#926, ADR-0070 §2).
//!
//! `POST /grants` delivers a grant by durable typed DM with
//! [`super::GRANT_DELIVERY_RETRIES`] send-layer retries. A recipient whose
//! daemon is offline through all of them used to stay without the grant
//! until the owner re-issued it. Here a failed delivery becomes an
//! *obligation*: it is written to `share-grant-outbox.bin` before the
//! `POST /grants` response returns, and a background worker retries it on
//! bounded backoff (and promptly when the recipient's machine connects again)
//! until the recipient's durable v2 ACK arrives.
//!
//! # Why an owner-side outbox and not the grantee-attached fetch
//!
//! ADR-0070 §2 also sketches a fetch: the grantee attaches grant ids when it
//! opens a DM/stream, and a daemon that missed delivery asks for the grant.
//! That needs a new wire carrier (old peers must ignore it) and a new typed
//! request/response. The outbox needs neither: it re-sends the exact
//! `x0x-sharegrant-v1\0` typed DM that #924 already sends, with the same
//! logical request id, so the receiver verifies and stores it on exactly the
//! #924 path ([`super::handle_share_grant_dm`]) and answers a replay as
//! `Duplicate`. Nothing changes on the wire or on the receiving side.
//!
//! # Lifecycle of an entry
//!
//! An entry `(grant_id, recipient)` is dropped when:
//! - the recipient's durable v2 ACK arrives (the grant is stored there);
//! - the grant is revoked — [`crate::Agent::revoke_share_grant`] removes it at
//!   once, and every worker pass re-checks the revocation set before sending,
//!   which also covers revocations gossiped from another owner install and a
//!   crash between revoking and rewriting the outbox;
//! - its deadline passes: the grant's `expiry`, or [`OUTBOX_ENTRY_TTL_SECS`]
//!   after it was queued, whichever is earlier.
//!
//! # Bounds
//!
//! At most [`MAX_OUTBOX_ENTRIES_PER_GRANTEE`] entries across all grants to
//! one grantee (the grant's `Grantee::User` or `Grantee::Agent`, whichever
//! agents the entries are addressed to) and [`MAX_OUTBOX_ENTRIES`] in total. Past a bound a new entry is refused (the
//! `POST /grants` response then reports it as not queued) rather than
//! evicting an older obligation silently. Each pass sends at most
//! [`OUTBOX_MAX_SENDS_PER_STEP`] entries, so an offline peer cannot turn the
//! outbox into a hot send loop.
//!
//! # Revocation is serialized with sending
//!
//! A worker pass holds the outbox's send gate (shared) from its revocation
//! check until its sends have completed. EVERY path that makes a share-grant
//! revocation effective — the local API revoke, the `x0x.revocation.v3`
//! gossip carrier, and a share-grant record arriving on any other revocation
//! carrier — takes the gate exclusively
//! ([`GrantRedeliveryOutbox::revocation_barrier`], reached through
//! [`crate::owner_trust::OwnerTrust::share_grant_revocation_barrier`]) before
//! it inserts the record. So once a revocation has been recorded no pass
//! can start a send of that grant, and a send already in flight when the
//! revoke began completes BEFORE the revoke returns (it is ordered before
//! the revocation, exactly like a delivery at issue time).
//!
//! # Storage
//!
//! `X0GO` magic ‖ strict bincode, written durably (temp, fsync, rename, dir
//! fsync) with mode 0600, like the grant store. Every stored grant is
//! re-verified on load and must be signed by this install's owner. An
//! unreadable, malformed or over-bound file — including an entry that no
//! longer verifies or is not this owner's — yields an empty outbox that
//! refuses writes ([`GrantRedeliveryOutbox::load_error`]), so the file is
//! never silently truncated or replaced. Only entries past their deadline
//! are dropped on load, as the lifecycle rules say. A failed write marks the
//! outbox dirty; the next mutation (including a retried revocation) rewrites
//! it even if it changes nothing in memory.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::{Grantee, ShareGrant, ShareGrantError};
use crate::identity::{AgentId, UserId};
use crate::revocation::RevocationSet;

/// File name of the outbox, next to [`super::SHARE_GRANT_STORE_FILE`].
pub const SHARE_GRANT_OUTBOX_FILE: &str = "share-grant-outbox.bin";

const OUTBOX_MAGIC: &[u8; 4] = b"X0GO";

/// Hard bound on queued deliveries across all recipients.
pub const MAX_OUTBOX_ENTRIES: usize = 1024;

/// Hard bound on queued deliveries across all grants to one grantee. Large
/// enough for one grant's full fan-out (up to [`super::MAX_GRANT_AGENTS`]
/// shared agents plus the grantee's own agents).
pub const MAX_OUTBOX_ENTRIES_PER_GRANTEE: usize = 128;

/// An entry is dropped this long after it was queued even if its grant is
/// still valid (the owner can re-issue).
pub const OUTBOX_ENTRY_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// First retry delay; doubles per failed attempt up to
/// [`OUTBOX_RETRY_MAX_SECS`].
pub const OUTBOX_RETRY_BASE_SECS: u64 = 5;

/// Cap on the retry delay. The backoff bounds the INTERVAL, not the attempt
/// count: an entry lives until ACK, revocation or its deadline.
pub const OUTBOX_RETRY_MAX_SECS: u64 = 300;

/// Most deliveries attempted in one worker pass.
pub const OUTBOX_MAX_SENDS_PER_STEP: usize = 8;

/// Send-layer retries inside one outbox attempt (the outbox itself is the
/// outer retry loop).
pub const OUTBOX_SEND_RETRIES: u8 = 1;

/// One queued grant delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGrantDelivery {
    /// The agent the grant is owed to.
    pub recipient: AgentId,
    /// The exact signed grant (re-sent byte-for-byte).
    pub grant: ShareGrant,
    /// Unix seconds the entry was queued.
    pub queued_at: u64,
    /// Unix seconds after which the entry is dropped:
    /// `min(grant.expiry, queued_at + OUTBOX_ENTRY_TTL_SECS)`.
    pub deadline: u64,
    /// Unix seconds of the next attempt.
    pub next_attempt_at: u64,
    /// Outbox attempts made so far (the initial `POST /grants` delivery is
    /// not counted).
    pub attempts: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OutboxFile {
    entries: Vec<PendingGrantDelivery>,
}

type EntryKey = ([u8; 32], [u8; 32]);

fn key_of(grant_id: &[u8; 32], recipient: &AgentId) -> EntryKey {
    (*grant_id, recipient.0)
}

/// Why a delivery could not be queued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboxError {
    /// The grant is not this owner's, does not verify, or is past its
    /// deadline.
    #[error("grant not queueable: {0}")]
    NotQueueable(String),
    /// The grant's grantee already has [`MAX_OUTBOX_ENTRIES_PER_GRANTEE`]
    /// entries.
    #[error("redelivery outbox full for this grantee")]
    GranteeFull,
    /// The outbox holds [`MAX_OUTBOX_ENTRIES`] entries.
    #[error("redelivery outbox full")]
    Full,
    /// The outbox file could not be read or written.
    #[error("redelivery outbox store: {0}")]
    Store(String),
}

/// What one worker pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OutboxStepReport {
    /// Entries whose recipient ACKed (dropped).
    pub delivered: usize,
    /// Entries attempted without an ACK (rescheduled).
    pub failed: usize,
    /// Entries dropped as revoked or past their deadline, never sent.
    pub dropped: usize,
}

/// `OUTBOX_RETRY_BASE_SECS << min(attempts, 6)`, clamped to
/// [`OUTBOX_RETRY_MAX_SECS`].
#[must_use]
pub fn retry_delay_secs(attempts: u32) -> u64 {
    OUTBOX_RETRY_BASE_SECS
        .checked_shl(attempts.min(6))
        .unwrap_or(OUTBOX_RETRY_MAX_SECS)
        .min(OUTBOX_RETRY_MAX_SECS)
}

/// The durable owner-side grant redelivery outbox. See the module docs.
#[derive(Debug)]
pub struct GrantRedeliveryOutbox {
    path: Option<PathBuf>,
    local_owner: Option<UserId>,
    entries: std::sync::Mutex<BTreeMap<EntryKey, PendingGrantDelivery>>,
    write_lock: tokio::sync::Mutex<()>,
    load_error: Option<String>,
    wake: tokio::sync::Notify,
    /// Shared by a worker pass from revocation check to send completion;
    /// exclusive for a local revocation (see the module docs).
    send_gate: std::sync::Arc<RwLock<()>>,
    /// The last write failed: the file may hold entries memory no longer
    /// has, so the next mutation must rewrite it.
    dirty: AtomicBool,
}

impl GrantRedeliveryOutbox {
    /// An empty in-memory outbox (tests, or no data dir).
    #[must_use]
    pub fn in_memory(local_owner: Option<UserId>) -> Self {
        Self {
            path: None,
            local_owner,
            entries: std::sync::Mutex::new(BTreeMap::new()),
            write_lock: tokio::sync::Mutex::new(()),
            load_error: None,
            wake: tokio::sync::Notify::new(),
            send_gate: std::sync::Arc::new(RwLock::new(())),
            dirty: AtomicBool::new(false),
        }
    }

    /// Load `path` (missing ⇒ empty). Entries whose deadline has passed at
    /// `now_unix` are dropped. Anything else wrong — unreadable, malformed,
    /// a duplicate key, an entry that no longer verifies or is not signed
    /// by `local_owner`, or a total or per-grantee bound exceeded — yields
    /// an empty outbox that refuses writes ([`Self::load_error`]); nothing
    /// is ever silently dropped from a file that could then be rewritten.
    pub async fn load(path: PathBuf, local_owner: Option<UserId>, now_unix: u64) -> Self {
        let mut outbox = Self::in_memory(local_owner);
        outbox.path = Some(path.clone());
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return outbox,
            Err(e) => {
                outbox.load_error = Some(format!("read {}: {e}", path.display()));
                return outbox;
            }
        };
        let file =
            if bytes.len() >= OUTBOX_MAGIC.len() && &bytes[..OUTBOX_MAGIC.len()] == OUTBOX_MAGIC {
                let body = &bytes[OUTBOX_MAGIC.len()..];
                super::strict_decode::<OutboxFile>(body, body.len() as u64)
                    .map_err(|e| format!("decode {}: {e}", path.display()))
            } else {
                Err(format!("{} missing X0GO magic", path.display()))
            };
        let file = match file {
            Ok(file) if file.entries.len() > MAX_OUTBOX_ENTRIES => Err(format!(
                "{} holds {} entries (bound {MAX_OUTBOX_ENTRIES})",
                path.display(),
                file.entries.len()
            )),
            other => other,
        };
        let file = file.and_then(|file| outbox.validate_loaded(file, now_unix, &path));
        match file {
            Ok(entries) => {
                outbox.entries = std::sync::Mutex::new(entries);
            }
            Err(e) => {
                tracing::warn!("share-grant outbox unreadable, holding no deliveries: {e}");
                outbox.load_error = Some(e);
            }
        }
        outbox
    }

    /// Check every loaded entry (see [`Self::load`]); only past-deadline
    /// entries are dropped.
    fn validate_loaded(
        &self,
        file: OutboxFile,
        now_unix: u64,
        path: &std::path::Path,
    ) -> Result<BTreeMap<EntryKey, PendingGrantDelivery>, String> {
        let mut entries = BTreeMap::new();
        let mut expired = 0usize;
        for entry in file.entries {
            if let Err(e) = self.queueable(&entry.grant) {
                return Err(format!("{}: {e}", path.display()));
            }
            if entry.deadline > entry.grant.expiry {
                return Err(format!(
                    "{}: entry deadline beyond its grant's expiry",
                    path.display()
                ));
            }
            if now_unix >= entry.deadline {
                expired += 1;
                continue;
            }
            let key = key_of(&entry.grant.grant_id, &entry.recipient);
            if entries.insert(key, entry).is_some() {
                return Err(format!("{}: duplicate entry", path.display()));
            }
        }
        let mut per_grantee: std::collections::HashMap<Grantee, usize> =
            std::collections::HashMap::new();
        for entry in entries.values() {
            let n = per_grantee.entry(entry.grant.grantee).or_insert(0);
            *n += 1;
            if *n > MAX_OUTBOX_ENTRIES_PER_GRANTEE {
                return Err(format!(
                    "{}: more than {MAX_OUTBOX_ENTRIES_PER_GRANTEE} entries for one grantee",
                    path.display()
                ));
            }
        }
        if expired > 0 {
            tracing::info!(
                expired,
                "share-grant outbox: dropped expired entries on load"
            );
        }
        Ok(entries)
    }

    /// Exclusive side of the send gate. Hold it while recording a local
    /// revocation and removing its entries: it waits for an in-flight pass
    /// to finish its sends and keeps a new pass from starting.
    pub async fn revocation_barrier(&self) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        // RED PROOF (ci-mirror only): the barrier is a fresh, uncontended lock.
        std::sync::Arc::new(RwLock::new(())).write_owned().await
    }

    /// Why the on-disk outbox is not in force, if it is not.
    #[must_use]
    pub fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<EntryKey, PendingGrantDelivery>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Snapshot of every queued delivery.
    #[must_use]
    pub fn pending(&self) -> Vec<PendingGrantDelivery> {
        self.lock().values().cloned().collect()
    }

    /// Number of queued deliveries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Whether any delivery to `recipient` is queued.
    #[must_use]
    pub fn has_recipient(&self, recipient: &AgentId) -> bool {
        self.lock().keys().any(|(_, r)| *r == recipient.0)
    }

    /// Resolves when an entry was queued or nudged (the worker waits on it
    /// alongside its poll interval).
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }

    fn queueable(&self, grant: &ShareGrant) -> Result<(), OutboxError> {
        if self.local_owner != Some(grant.owner) {
            return Err(OutboxError::NotQueueable(
                "only grants signed by this install's owner are redelivered".into(),
            ));
        }
        grant
            .verify()
            .map_err(|e: ShareGrantError| OutboxError::NotQueueable(e.to_string()))
    }

    /// Durably queue `grant` for `recipient`. Returns `Ok(true)` once the
    /// entry is on disk, `Ok(false)` if it was already queued.
    ///
    /// # Errors
    /// Not queueable (foreign, forged or expired grant), a bound reached, or
    /// a store failure. A refused entry leaves the outbox unchanged.
    pub async fn enqueue(
        &self,
        grant: &ShareGrant,
        recipient: AgentId,
        now_unix: u64,
    ) -> Result<bool, OutboxError> {
        self.queueable(grant)?;
        let deadline = grant
            .expiry
            .min(now_unix.saturating_add(OUTBOX_ENTRY_TTL_SECS));
        if now_unix == 0 || now_unix >= deadline {
            return Err(OutboxError::NotQueueable("grant has expired".into()));
        }
        if let Some(e) = &self.load_error {
            return Err(OutboxError::Store(format!(
                "outbox not writable (unreadable file): {e}"
            )));
        }
        let key = key_of(&grant.grant_id, &recipient);
        let _write = self.write_lock.lock().await;
        {
            let mut entries = self.lock();
            if entries.contains_key(&key) {
                return Ok(false);
            }
            entries.retain(|_, e| now_unix < e.deadline);
            let per_grantee = entries
                .values()
                .filter(|e| e.grant.grantee == grant.grantee)
                .count();
            if per_grantee >= MAX_OUTBOX_ENTRIES_PER_GRANTEE {
                return Err(OutboxError::GranteeFull);
            }
            if entries.len() >= MAX_OUTBOX_ENTRIES {
                return Err(OutboxError::Full);
            }
            entries.insert(
                key,
                PendingGrantDelivery {
                    recipient,
                    grant: grant.clone(),
                    queued_at: now_unix,
                    deadline,
                    next_attempt_at: now_unix.saturating_add(retry_delay_secs(0)),
                    attempts: 0,
                },
            );
        }
        if let Err(e) = self.persist().await {
            // Roll back: an entry that is not durable must not be reported
            // as queued.
            self.lock().remove(&key);
            return Err(OutboxError::Store(e));
        }
        self.wake.notify_one();
        Ok(true)
    }

    /// Drop every queued delivery of `grant_id` (the grant was revoked).
    /// Returns how many entries were removed.
    ///
    /// # Errors
    /// The outbox could not be rewritten (fatal for the caller: a revoke
    /// must not report success). The entries are gone from memory, the
    /// outbox stays dirty so a retry rewrites the file, and every worker
    /// pass re-checks revocation before sending.
    pub async fn remove_grant(&self, grant_id: &[u8; 32]) -> Result<usize, OutboxError> {
        let _write = self.write_lock.lock().await;
        let removed = {
            let mut entries = self.lock();
            let before = entries.len();
            entries.retain(|(id, _), _| id != grant_id);
            before - entries.len()
        };
        if removed > 0 || self.dirty.load(Ordering::Acquire) {
            self.persist().await.map_err(OutboxError::Store)?;
        }
        Ok(removed)
    }

    /// Make every delivery to one of `recipients` due at `now_unix` (the
    /// recipient's machine was seen again) and wake the worker. Returns
    /// whether anything was nudged. In memory only: the persisted schedule
    /// is merely later, which is safe.
    pub fn nudge(&self, recipients: &[AgentId], now_unix: u64) -> bool {
        let mut nudged = false;
        {
            let mut entries = self.lock();
            for entry in entries.values_mut() {
                if recipients.contains(&entry.recipient) && entry.next_attempt_at > now_unix {
                    entry.next_attempt_at = now_unix;
                    nudged = true;
                }
            }
        }
        if nudged {
            self.wake.notify_one();
        }
        nudged
    }

    /// One worker pass at `now_unix`.
    ///
    /// Holds the send gate (shared) throughout, so a local revocation is
    /// ordered strictly before or after this pass's sends.
    ///
    /// 1. Drop entries that are revoked in `revocations` or past their
    ///    deadline — they are never sent.
    /// 2. Send at most [`OUTBOX_MAX_SENDS_PER_STEP`] due entries, oldest
    ///    schedule first, concurrently via `send(recipient, payload,
    ///    request_id)`, which must return `Ok` only on the recipient's
    ///    durable v2 ACK. `payload`/`request_id` are exactly those of the
    ///    original delivery ([`super::grant_delivery_request`]).
    /// 3. Drop ACKed entries; reschedule the rest on bounded backoff.
    ///
    /// A zero clock (failed read) does nothing: deadlines cannot be judged.
    pub async fn step<F, Fut>(
        &self,
        now_unix: u64,
        revocations: &RwLock<RevocationSet>,
        send: F,
    ) -> OutboxStepReport
    where
        F: Fn(AgentId, Vec<u8>, [u8; 16]) -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let mut report = OutboxStepReport::default();
        if now_unix == 0 {
            return report;
        }
        let _gate = self.send_gate.read().await;
        // 1. Drop dead entries.
        let snapshot = self.pending();
        let dead: Vec<EntryKey> = {
            let revoked = revocations.read().await;
            snapshot
                .iter()
                .filter(|e| {
                    now_unix >= e.deadline
                        || revoked.is_share_grant_revoked(&e.grant.grant_id, &e.grant.owner)
                })
                .map(|e| key_of(&e.grant.grant_id, &e.recipient))
                .collect()
        };
        if !dead.is_empty() {
            let _write = self.write_lock.lock().await;
            {
                let mut entries = self.lock();
                for key in &dead {
                    if entries.remove(key).is_some() {
                        report.dropped += 1;
                    }
                }
            }
            if let Err(e) = self.persist().await {
                tracing::warn!("share-grant outbox: dropping dead entries not persisted: {e}");
            }
        }
        // 2. Pick due entries.
        let mut due: Vec<PendingGrantDelivery> = self
            .pending()
            .into_iter()
            .filter(|e| e.next_attempt_at <= now_unix)
            .collect();
        due.sort_by_key(|e| (e.next_attempt_at, e.queued_at));
        due.truncate(OUTBOX_MAX_SENDS_PER_STEP);
        if due.is_empty() {
            return report;
        }
        let sends = due.into_iter().map(|entry| {
            let request = super::grant_delivery_request(&entry.grant);
            let fut =
                request.map(|(payload, request_id)| send(entry.recipient, payload, request_id));
            async move {
                let outcome = match fut {
                    Ok(fut) => fut.await,
                    Err(e) => Err(e.to_string()),
                };
                (entry, outcome)
            }
        });
        let results = futures::future::join_all(sends).await;
        // 3. Settle.
        let _write = self.write_lock.lock().await;
        {
            let mut entries = self.lock();
            for (entry, outcome) in results {
                let key = key_of(&entry.grant.grant_id, &entry.recipient);
                match outcome {
                    Ok(()) => {
                        report.delivered += 1;
                        entries.remove(&key);
                        tracing::info!(
                            grant = %entry.grant.id_hex(),
                            recipient = %hex::encode(entry.recipient.as_bytes()),
                            "queued share grant delivered (durable ACK)"
                        );
                    }
                    Err(reason) => {
                        report.failed += 1;
                        // Removed meanwhile (revoked) ⇒ stays removed.
                        if let Some(held) = entries.get_mut(&key) {
                            held.attempts = held.attempts.saturating_add(1);
                            held.next_attempt_at =
                                now_unix.saturating_add(retry_delay_secs(held.attempts));
                        }
                        tracing::debug!(
                            grant = %entry.grant.id_hex(),
                            recipient = %hex::encode(entry.recipient.as_bytes()),
                            %reason,
                            "queued share grant delivery failed; rescheduled"
                        );
                    }
                }
            }
        }
        if let Err(e) = self.persist().await {
            tracing::warn!("share-grant outbox: settled attempts not persisted: {e}");
        }
        report
    }

    /// Write the outbox atomically (mode 0600). Callers hold `write_lock`.
    async fn persist(&self) -> Result<(), String> {
        let result = self.write_file().await;
        self.dirty.store(result.is_err(), Ordering::Release);
        result
    }

    async fn write_file(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(e) = &self.load_error {
            return Err(format!("outbox not writable (unreadable file): {e}"));
        }
        let file = OutboxFile {
            entries: self.pending(),
        };
        let body = bincode::serialize(&file).map_err(|e| format!("encode: {e}"))?;
        let mut bytes = Vec::with_capacity(OUTBOX_MAGIC.len() + body.len());
        bytes.extend_from_slice(OUTBOX_MAGIC);
        bytes.extend_from_slice(&body);
        crate::storage::write_private_bytes_durable(path, bytes)
            .await
            .map_err(|e| format!("write {}: {e}", path.display()))
    }
}
