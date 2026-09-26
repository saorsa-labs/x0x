//! #926 owner-side grant redelivery outbox. The "network" here is a switch
//! in front of the receiving daemon's REAL #924 delivery path
//! ([`handle_share_grant_dm`] into its [`ShareGrantStore`]): a send succeeds
//! only when that handler verified and stored the grant, exactly as the
//! durable v2 ACK does in production. Each negative case would pass (and so
//! fail its assertion) if the check it guards were removed.

use super::super::outbox::{
    retry_delay_secs, GrantRedeliveryOutbox, OutboxError, PendingGrantDelivery, MAX_OUTBOX_ENTRIES,
    MAX_OUTBOX_ENTRIES_PER_GRANTEE, OUTBOX_ENTRY_TTL_SECS,
};
use super::*;
use crate::identity::{AgentKeypair, MachineId, UserKeypair};
use crate::revocation::{RevocationRecord, RevokedSubject, ShareGrantRevocation};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The shared agent's daemon (A1) behind an on/off link.
struct Receiver {
    store: ShareGrantStore,
    online: AtomicBool,
    sends: AtomicUsize,
    request_ids: std::sync::Mutex<Vec<[u8; 16]>>,
}

impl Receiver {
    fn new(local: AgentId, owner: &UserKeypair) -> Self {
        Self {
            store: ShareGrantStore::in_memory(local, Some(owner.user_id())),
            online: AtomicBool::new(false),
            sends: AtomicUsize::new(0),
            request_ids: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// One durable typed-DM send: `Ok` only on the receiver's ACK, which
    /// `handle_share_grant_dm` releases once the grant is stored.
    async fn send(
        &self,
        _to: AgentId,
        payload: Vec<u8>,
        request_id: [u8; 16],
    ) -> Result<(), String> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        self.request_ids.lock().unwrap().push(request_id);
        if !self.online.load(Ordering::SeqCst) {
            return Err("recipient offline".into());
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let typed = DmTypedPayload {
            sender: AgentId([0xA0; 32]),
            machine_id: MachineId([0xA1; 32]),
            payload,
            verified: true,
            trust_decision: None,
            received_at_unix_ms: 0,
            request_id,
            completion: Some(tx),
        };
        let _ = handle_share_grant_dm(Some(&self.store), typed).await;
        match rx.await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("no completion".into()),
        }
    }
}

struct World {
    dir: tempfile::TempDir,
    owner: UserKeypair,
    a1: AgentId,
    b1: AgentId,
    mb: MachineId,
    bindings: AuthenticatedMachineBindings,
    cache: RwLock<HashMap<AgentId, DiscoveredAgent>>,
    revocations: RwLock<RevocationSet>,
    now: u64,
}

impl World {
    async fn new() -> Self {
        let now = real_now();
        let b1 = AgentKeypair::generate().unwrap().agent_id();
        let mb = MachineId([0xB0; 32]);
        let bindings = AuthenticatedMachineBindings::default();
        crate::dm_inbox::record_authenticated_machine_binding(&bindings, b1, mb, now).await;
        Self {
            dir: tempfile::tempdir().unwrap(),
            owner: UserKeypair::generate().unwrap(),
            a1: AgentKeypair::generate().unwrap().agent_id(),
            b1,
            mb,
            bindings,
            cache: RwLock::new(HashMap::new()),
            revocations: RwLock::new(RevocationSet::new()),
            now,
        }
    }

    /// Owner's grant to agent B1 over A1, valid `[now-60, now+ttl)`.
    fn grant(&self, id: u8, ttl: u64) -> ShareGrant {
        ShareGrant::sign(
            &self.owner,
            [id; 32],
            Grantee::Agent(self.b1),
            vec![self.a1],
            vec![ShareCap::Dm],
            self.now - 60,
            self.now + ttl,
        )
        .unwrap()
    }

    fn grant_to(&self, id: u8, grantee: Grantee) -> ShareGrant {
        ShareGrant::sign(
            &self.owner,
            [id; 32],
            grantee,
            vec![self.a1],
            vec![ShareCap::Dm],
            self.now - 60,
            self.now + 3_600,
        )
        .unwrap()
    }

    fn outbox_path(&self) -> std::path::PathBuf {
        self.dir
            .path()
            .join(super::super::outbox::SHARE_GRANT_OUTBOX_FILE)
    }

    async fn outbox(&self, now: u64) -> GrantRedeliveryOutbox {
        GrantRedeliveryOutbox::load(self.outbox_path(), Some(self.owner.user_id()), now).await
    }

    /// Does B1 (on its authenticated machine) reach A1 with DM rights?
    async fn b1_has_dm_on(&self, receiver: &Receiver) -> bool {
        evaluate_grant_access(
            &receiver.store,
            &self.bindings,
            &self.cache,
            &self.revocations,
            &self.b1,
            &self.mb,
            self.now,
        )
        .await
        .dm
    }

    /// The owner's revocation record for `grant` (what
    /// `revoke_share_grant` signs).
    fn revocation_record(&self, grant: &ShareGrant) -> RevocationRecord {
        RevocationRecord::sign(
            RevokedSubject::ShareGrant(ShareGrantRevocation {
                grant_id: grant.grant_id,
                owner: self.owner.user_id(),
                grant_expiry: grant.expiry,
            }),
            self.owner.public_key(),
            self.owner.secret_key(),
            self.now,
            None,
        )
        .unwrap()
    }

    /// A revocation recorded in memory only (as a gossiped revocation, or a
    /// crash before the outbox was rewritten, leaves it).
    async fn revoke_in_memory_only(&self, grant: &ShareGrant) {
        self.revocations
            .write()
            .await
            .verify_and_insert(self.revocation_record(grant), None)
            .unwrap();
    }

    /// The real local revocation path (`Agent::revoke_share_grant`'s core).
    async fn revoke(
        &self,
        grant: &ShareGrant,
        identity_dir: &std::path::Path,
        outbox: &GrantRedeliveryOutbox,
    ) -> Result<(), ShareGrantError> {
        record_local_share_grant_revocation(
            self.revocation_record(grant),
            &self.revocations,
            Some(identity_dir),
            Some(outbox),
        )
        .await
    }

    fn identity_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("identity")
    }
}

fn recipient(i: usize) -> AgentId {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
    id[31] = 0x5A;
    AgentId(id)
}

/// Issue-time delivery to A1 through the real queueing entry point.
async fn issue_to(
    world: &World,
    grant: &ShareGrant,
    outbox: &GrantRedeliveryOutbox,
    receiver: &Receiver,
) -> GrantDelivery {
    let mut out = deliver_grant_via(grant, &[world.a1], Some(outbox), world.now, |r, p, id| {
        receiver.send(r, p, id)
    })
    .await;
    assert_eq!(out.len(), 1);
    out.remove(0)
}

/// WHY (#926 test a): a shared agent's daemon that was offline through every
/// issue-time attempt must gain the grant — and so the grantee's access —
/// once it is reachable again, WITHOUT the owner re-issuing. Before #926 the
/// failed delivery was only reported; nothing ever retried it.
#[tokio::test]
async fn offline_daemon_gains_the_grant_later_without_reissue() {
    let world = World::new().await;
    let outbox = world.outbox(world.now).await;
    let receiver = Receiver::new(world.a1, &world.owner);
    let grant = world.grant(1, 3_600);

    let delivery = issue_to(&world, &grant, &outbox, &receiver).await;
    assert!(!delivery.delivered, "A1 is offline at issue time");
    assert!(
        delivery.queued,
        "a failed delivery must be queued: {delivery:?}"
    );
    assert!(
        !world.b1_has_dm_on(&receiver).await,
        "control: no grant yet"
    );

    // Still offline at the first retry: rescheduled, not dropped.
    let first_retry = world.now + retry_delay_secs(0);
    let report = outbox
        .step(first_retry, &world.revocations, |r, p, id| {
            receiver.send(r, p, id)
        })
        .await;
    assert_eq!((report.delivered, report.failed), (0, 1));
    assert_eq!(outbox.len(), 1, "an unACKed entry stays queued");
    let backoff_until = outbox.pending()[0].next_attempt_at;
    assert!(backoff_until > first_retry, "failed attempt backs off");
    let before = receiver.sends.load(Ordering::SeqCst);
    outbox
        .step(first_retry, &world.revocations, |r, p, id| {
            receiver.send(r, p, id)
        })
        .await;
    assert_eq!(
        receiver.sends.load(Ordering::SeqCst),
        before,
        "nothing is sent before the backoff elapses"
    );

    // A1 comes back; its machine connecting nudges the entry due at once.
    receiver.online.store(true, Ordering::SeqCst);
    assert!(outbox.nudge(&[world.a1], first_retry));
    let report = outbox
        .step(first_retry, &world.revocations, |r, p, id| {
            receiver.send(r, p, id)
        })
        .await;
    assert_eq!(report.delivered, 1, "{report:?}");
    assert!(outbox.is_empty(), "the ACK discharges the entry");
    assert!(
        receiver.store.issued(&grant.grant_id).is_some(),
        "stored via the #924 handler"
    );
    assert!(
        world.b1_has_dm_on(&receiver).await,
        "the grantee now reaches A1"
    );

    // Every attempt was the SAME logical request (idempotent at the receiver).
    let ids = receiver.request_ids.lock().unwrap().clone();
    assert!(
        ids.len() >= 3 && ids.iter().all(|id| *id == ids[0]),
        "{ids:?}"
    );
}

/// WHY (#926 test b): the obligation must survive a daemon restart — an
/// owner daemon restarted while A1 is offline must still deliver later.
#[tokio::test]
async fn queued_delivery_survives_restart() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    let grant = world.grant(2, 3_600);
    {
        let outbox = world.outbox(world.now).await;
        assert!(issue_to(&world, &grant, &outbox, &receiver).await.queued);
    }
    let reloaded = world.outbox(world.now).await;
    assert!(reloaded.load_error().is_none());
    let pending = reloaded.pending();
    assert_eq!(pending.len(), 1, "the entry is on disk");
    assert_eq!(pending[0].grant, grant, "the exact signed grant");
    assert_eq!(pending[0].recipient, world.a1);

    receiver.online.store(true, Ordering::SeqCst);
    let report = reloaded
        .step(
            world.now + retry_delay_secs(0),
            &world.revocations,
            |r, p, id| receiver.send(r, p, id),
        )
        .await;
    assert_eq!(report.delivered, 1);
    assert!(world.b1_has_dm_on(&receiver).await);
    // The discharge itself is durable.
    assert!(world.outbox(world.now).await.is_empty());
}

/// WHY: a corrupt outbox must fail closed (nothing queued, writes refused)
/// rather than be silently replaced by an empty one.
#[tokio::test]
async fn corrupt_outbox_fails_closed() {
    let world = World::new().await;
    std::fs::write(world.outbox_path(), b"X0GOgarbage").unwrap();
    let outbox = world.outbox(world.now).await;
    assert!(outbox.load_error().is_some());
    assert!(outbox.is_empty());
    let err = outbox
        .enqueue(&world.grant(3, 3_600), world.a1, world.now)
        .await
        .unwrap_err();
    assert!(matches!(err, OutboxError::Store(_)), "{err:?}");
    assert_eq!(std::fs::read(world.outbox_path()).unwrap(), b"X0GOgarbage");
}

/// WHY (#926 test c): revoking a queued grant removes the entry and nothing
/// is ever delivered — including after a restart.
#[tokio::test]
async fn revocation_removes_the_entry_and_nothing_is_delivered() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    let grant = world.grant(4, 3_600);
    let outbox = world.outbox(world.now).await;
    assert!(issue_to(&world, &grant, &outbox, &receiver).await.queued);
    let sends_at_issue = receiver.sends.load(Ordering::SeqCst);

    world
        .revoke(&grant, &world.identity_dir(), &outbox)
        .await
        .unwrap();
    assert!(outbox.is_empty());
    assert!(
        world.outbox(world.now).await.is_empty(),
        "the removal is durable across restart"
    );

    receiver.online.store(true, Ordering::SeqCst);
    outbox
        .step(
            world.now + retry_delay_secs(0),
            &world.revocations,
            |r, p, id| receiver.send(r, p, id),
        )
        .await;
    assert_eq!(receiver.sends.load(Ordering::SeqCst), sends_at_issue);
    assert!(receiver.store.issued(&grant.grant_id).is_none());
    assert!(!world.b1_has_dm_on(&receiver).await);
}

/// WHY (coordinator b): a grant revoked WHILE queued must never be
/// redelivered even when the outbox file still holds it after a restart —
/// a crash between revoking and rewriting the outbox, or a revocation that
/// arrived by gossip from another owner install. The worker re-checks the
/// revocation set before every send and drops the entry durably.
#[tokio::test]
async fn revoked_while_queued_is_never_redelivered_across_restart() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    let grant = world.grant(5, 3_600);
    {
        let outbox = world.outbox(world.now).await;
        assert!(issue_to(&world, &grant, &outbox, &receiver).await.queued);
    }
    // Revoked, but the outbox file was never rewritten.
    world.revoke_in_memory_only(&grant).await;
    let restarted = world.outbox(world.now).await;
    assert_eq!(restarted.len(), 1, "control: the stale entry is on disk");
    let sends_before = receiver.sends.load(Ordering::SeqCst);

    receiver.online.store(true, Ordering::SeqCst);
    assert!(restarted.nudge(&[world.a1], world.now));
    let report = restarted
        .step(world.now, &world.revocations, |r, p, id| {
            receiver.send(r, p, id)
        })
        .await;
    assert_eq!(report.dropped, 1, "{report:?}");
    assert_eq!(report.delivered, 0);
    assert_eq!(
        receiver.sends.load(Ordering::SeqCst),
        sends_before,
        "a revoked grant is never sent"
    );
    assert!(receiver.store.issued(&grant.grant_id).is_none());
    assert!(
        world.outbox(world.now).await.is_empty(),
        "the drop is durable: a second restart holds nothing"
    );
}

/// WHY (#926 test d): one grantee cannot fill the outbox — the cap is per
/// GRANTEE (the grant's `Grantee`), counted across every recipient agent its
/// entries are addressed to; a different grantee still queues.
#[tokio::test]
async fn per_grantee_bound_is_enforced() {
    let world = World::new().await;
    let outbox = GrantRedeliveryOutbox::in_memory(Some(world.owner.user_id()));
    let grant = world.grant(1, 3_600);
    for i in 0..MAX_OUTBOX_ENTRIES_PER_GRANTEE {
        // Each entry goes to a DIFFERENT recipient agent: a per-recipient
        // cap would never trip here.
        assert_eq!(
            outbox.enqueue(&grant, recipient(i), world.now).await,
            Ok(true)
        );
    }
    let second_grant_same_grantee = world.grant(2, 3_600);
    assert_eq!(
        outbox
            .enqueue(
                &second_grant_same_grantee,
                recipient(MAX_OUTBOX_ENTRIES_PER_GRANTEE),
                world.now
            )
            .await,
        Err(OutboxError::GranteeFull)
    );
    assert_eq!(outbox.len(), MAX_OUTBOX_ENTRIES_PER_GRANTEE);
    let other_grantee = world.grant_to(3, Grantee::Agent(AgentId([0x77; 32])));
    assert_eq!(
        outbox.enqueue(&other_grantee, world.a1, world.now).await,
        Ok(true)
    );
    // Re-queueing the same (grant, recipient) is a no-op, not a new entry.
    assert_eq!(
        outbox.enqueue(&other_grantee, world.a1, world.now).await,
        Ok(false)
    );
}

/// WHY (#926 test d): the outbox as a whole is bounded, and past the bound a
/// new entry is refused and reported (never a silent eviction).
#[tokio::test]
async fn total_bound_is_enforced_and_reported() {
    let world = World::new().await;
    let outbox = GrantRedeliveryOutbox::in_memory(Some(world.owner.user_id()));
    let grantees = MAX_OUTBOX_ENTRIES / MAX_OUTBOX_ENTRIES_PER_GRANTEE;
    let mut n = 0;
    for g in 0..grantees {
        let grant = world.grant_to(
            u8::try_from(g).unwrap(),
            Grantee::Agent(AgentId([0xD0 + u8::try_from(g).unwrap(); 32])),
        );
        for _ in 0..MAX_OUTBOX_ENTRIES_PER_GRANTEE {
            assert_eq!(
                outbox.enqueue(&grant, recipient(n), world.now).await,
                Ok(true)
            );
            n += 1;
        }
    }
    assert_eq!(n, MAX_OUTBOX_ENTRIES);
    let grant = world.grant(0xEE, 3_600);
    assert_eq!(
        outbox.enqueue(&grant, world.a1, world.now).await,
        Err(OutboxError::Full)
    );
    // The issue path reports the refusal to the owner.
    let receiver = Receiver::new(world.a1, &world.owner);
    let delivery = issue_to(&world, &grant, &outbox, &receiver).await;
    assert!(!delivery.delivered && !delivery.queued);
    assert!(
        delivery
            .error
            .as_deref()
            .is_some_and(|e| e.contains("not queued for redelivery")),
        "{delivery:?}"
    );
    assert_eq!(outbox.len(), MAX_OUTBOX_ENTRIES, "nothing was evicted");
}

/// Write `entries` as an outbox file, bypassing `enqueue`'s checks.
fn write_raw_outbox(path: &std::path::Path, entries: &[PendingGrantDelivery]) {
    let mut bytes = b"X0GO".to_vec();
    bytes.extend_from_slice(&bincode::serialize(&entries.to_vec()).unwrap());
    std::fs::write(path, bytes).unwrap();
}

fn raw_entry(grant: &ShareGrant, to: AgentId, now: u64) -> PendingGrantDelivery {
    PendingGrantDelivery {
        recipient: to,
        grant: grant.clone(),
        queued_at: now,
        deadline: grant.expiry,
        next_attempt_at: now,
        attempts: 0,
    }
}

/// WHY (review P2): an over-bound file must NOT be silently truncated to
/// the bound and then rewritten — it loads as empty with `load_error`, and
/// refuses writes so the file on disk is left exactly as found.
#[tokio::test]
async fn over_bound_file_fails_closed_and_is_never_truncated() {
    let world = World::new().await;
    let grant = world.grant(1, 3_600);
    let entries: Vec<_> = (0..=MAX_OUTBOX_ENTRIES_PER_GRANTEE)
        .map(|i| raw_entry(&grant, recipient(i), world.now))
        .collect();
    write_raw_outbox(&world.outbox_path(), &entries);
    let before = std::fs::read(world.outbox_path()).unwrap();

    let outbox = world.outbox(world.now).await;
    assert!(
        outbox
            .load_error()
            .is_some_and(|e| e.contains("one grantee")),
        "{:?}",
        outbox.load_error()
    );
    assert!(outbox.is_empty(), "nothing partial is held");
    assert!(matches!(
        outbox
            .enqueue(&world.grant(2, 3_600), world.a1, world.now)
            .await,
        Err(OutboxError::Store(_))
    ));
    assert_eq!(std::fs::read(world.outbox_path()).unwrap(), before);

    // Control: exactly at the bound loads fine.
    write_raw_outbox(
        &world.outbox_path(),
        &entries[..MAX_OUTBOX_ENTRIES_PER_GRANTEE],
    );
    let at_bound = world.outbox(world.now).await;
    assert!(at_bound.load_error().is_none());
    assert_eq!(at_bound.len(), MAX_OUTBOX_ENTRIES_PER_GRANTEE);

    // A foreign-owner entry is also refused, not skipped.
    let stranger = UserKeypair::generate().unwrap();
    let foreign = ShareGrant::sign(
        &stranger,
        [9; 32],
        Grantee::Agent(world.b1),
        vec![world.a1],
        vec![ShareCap::Dm],
        world.now - 60,
        world.now + 3_600,
    )
    .unwrap();
    write_raw_outbox(
        &world.outbox_path(),
        &[
            raw_entry(&grant, world.a1, world.now),
            raw_entry(&foreign, world.a1, world.now),
        ],
    );
    let mixed = world.outbox(world.now).await;
    assert!(mixed.load_error().is_some());
    assert!(mixed.is_empty());
}

/// WHY (TTL): an entry lives at most `OUTBOX_ENTRY_TTL_SECS`, and never past
/// its grant's expiry — a dead entry is dropped, never sent, and frees its
/// slot.
#[tokio::test]
async fn entries_expire_at_ttl_or_grant_expiry() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    receiver.online.store(true, Ordering::SeqCst);
    let outbox = world.outbox(world.now).await;

    // Long-lived grant: the outbox TTL is the deadline.
    let long = world.grant(7, 30 * 24 * 3_600);
    assert!(outbox.enqueue(&long, world.a1, world.now).await.unwrap());
    assert_eq!(
        outbox.pending()[0].deadline,
        world.now + OUTBOX_ENTRY_TTL_SECS
    );
    // Short grant: its expiry is the deadline.
    let short = world.grant(8, 600);
    assert!(outbox.enqueue(&short, world.a1, world.now).await.unwrap());

    // A restart after the short grant expired drops it on load.
    let after_short = world.now + 600;
    let reloaded = world.outbox(after_short).await;
    assert_eq!(reloaded.len(), 1, "expired entry dropped on load");
    assert_eq!(reloaded.pending()[0].grant.grant_id, long.grant_id);

    // Past the TTL, the step drops it without sending.
    let sends_before = receiver.sends.load(Ordering::SeqCst);
    let report = outbox
        .step(
            world.now + OUTBOX_ENTRY_TTL_SECS,
            &world.revocations,
            |r, p, id| receiver.send(r, p, id),
        )
        .await;
    assert_eq!(report.dropped, 2, "{report:?}");
    assert_eq!(receiver.sends.load(Ordering::SeqCst), sends_before);
    assert!(outbox.is_empty());
    assert!(world.outbox(world.now).await.is_empty(), "drop is durable");

    // An expired grant is never queued.
    let expired = world.grant(9, 1);
    assert!(matches!(
        outbox.enqueue(&expired, world.a1, world.now + 1).await,
        Err(OutboxError::NotQueueable(_))
    ));
}

/// WHY: only grants signed by THIS install's owner are redelivered; the
/// outbox is not a relay for anyone else's grants.
#[tokio::test]
async fn foreign_grants_are_not_queued() {
    let world = World::new().await;
    let stranger = UserKeypair::generate().unwrap();
    let outbox = GrantRedeliveryOutbox::in_memory(Some(stranger.user_id()));
    assert!(matches!(
        outbox
            .enqueue(&world.grant(10, 3_600), world.a1, world.now)
            .await,
        Err(OutboxError::NotQueueable(_))
    ));
}

/// A redelivery pass of `outbox` whose single send is paused in flight:
/// `entered` is set once the send started; it proceeds when `release` fires.
struct PausedSend {
    entered: AtomicBool,
    release: tokio::sync::Notify,
}

impl PausedSend {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
        }
    }

    async fn send(
        &self,
        receiver: &Receiver,
        to: AgentId,
        payload: Vec<u8>,
        request_id: [u8; 16],
    ) -> Result<(), String> {
        self.entered.store(true, Ordering::SeqCst);
        self.release.notified().await;
        receiver.send(to, payload, request_id).await
    }
}

/// Shared body of the two race tests: with a send of `grant` paused in
/// flight, `revoke` (polled exactly once) must NOT be able to make the
/// revocation effective — it must wait at the barrier until the pass has
/// finished. Deterministic: a single `now_or_never` poll, no timers. With
/// the barrier removed, that one poll inserts the revocation synchronously
/// (before any I/O await) and the assertion fails.
async fn assert_revoke_waits_for_in_flight_send<R>(
    world: &World,
    outbox: &GrantRedeliveryOutbox,
    receiver: &Receiver,
    grant: &ShareGrant,
    revoke: R,
) where
    R: std::future::Future<Output = ()>,
{
    use futures::FutureExt;
    let due = world.now + retry_delay_secs(0);
    let paused = PausedSend::new();
    let step = outbox.step(due, &world.revocations, |r, p, id| {
        paused.send(receiver, r, p, id)
    });
    tokio::pin!(step);
    assert!(step.as_mut().now_or_never().is_none());
    assert!(
        paused.entered.load(Ordering::SeqCst),
        "control: the send is in flight"
    );

    tokio::pin!(revoke);
    assert!(revoke.as_mut().now_or_never().is_none());
    assert!(
        !world
            .revocations
            .read()
            .await
            .is_share_grant_revoked(&grant.grant_id, &grant.owner),
        "a revocation took effect while a send of the grant was in flight"
    );

    paused.release.notify_one();
    let report = step.await;
    assert_eq!(report.delivered, 1, "the in-flight send is ordered first");
    revoke.await;
    assert!(world
        .revocations
        .read()
        .await
        .is_share_grant_revoked(&grant.grant_id, &grant.owner));

    // From here on nothing of this grant is ever sent.
    let sends = receiver.sends.load(Ordering::SeqCst);
    let other = AgentId([0x42; 32]);
    assert_eq!(outbox.enqueue(grant, other, world.now).await, Ok(true));
    outbox.nudge(&[other], due);
    let report = outbox
        .step(due, &world.revocations, |r, p, id| receiver.send(r, p, id))
        .await;
    assert_eq!((report.delivered, report.dropped), (0, 1), "{report:?}");
    assert_eq!(receiver.sends.load(Ordering::SeqCst), sends);
}

/// WHY (review P1, race; r2 P2 deterministic): a LOCAL revoke that begins
/// while a redelivery of the grant is in flight must not take effect (and
/// so cannot return) until that send has completed, and no send may start
/// after it — otherwise `DELETE /grants/:id` could answer "revoked" and the
/// grant still be delivered afterwards.
#[tokio::test]
async fn local_revoke_is_ordered_after_an_in_flight_send() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    receiver.online.store(true, Ordering::SeqCst);
    let outbox = GrantRedeliveryOutbox::in_memory(Some(world.owner.user_id()));
    let grant = world.grant(1, 3_600);
    assert!(outbox.enqueue(&grant, world.a1, world.now).await.unwrap());
    let identity_dir = world.identity_dir();
    let revoke = async {
        world.revoke(&grant, &identity_dir, &outbox).await.unwrap();
    };
    assert_revoke_waits_for_in_flight_send(&world, &outbox, &receiver, &grant, revoke).await;
}

/// WHY (review r2 P1): a revocation delivered by GOSSIP (the
/// `x0x.revocation.v3` carrier) must be ordered against redelivery exactly
/// like a local one — it takes the same barrier through `OwnerTrust`, so a
/// queued send cannot slip out after it took effect.
#[tokio::test]
#[ignore = "red-proof: isolate local barrier test"]
async fn gossiped_revoke_is_ordered_after_an_in_flight_send() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    receiver.online.store(true, Ordering::SeqCst);
    let outbox = Arc::new(GrantRedeliveryOutbox::in_memory(Some(
        world.owner.user_id(),
    )));
    let grant = world.grant(1, 3_600);
    assert!(outbox.enqueue(&grant, world.a1, world.now).await.unwrap());
    let trust = OwnerTrust::new(
        Some(world.owner.user_id()),
        AuthenticatedMachineBindings::default(),
    );
    trust.install_share_grant_outbox(Arc::clone(&outbox));
    let payload = bincode::serialize(&vec![world.revocation_record(&grant)]).unwrap();
    let identity_dir = world.identity_dir();
    let revoke = async {
        assert!(
            crate::ingest_share_grant_revocations(
                &trust,
                &world.revocations,
                Some(identity_dir.clone()),
                &payload,
            )
            .await
        );
    };
    assert_revoke_waits_for_in_flight_send(&world, &outbox, &receiver, &grant, revoke).await;
    // The gossiped revocation is durable too.
    let bytes = std::fs::read(identity_dir.join(crate::SHARE_GRANT_REVOCATIONS_FILE)).unwrap();
    assert!(RevocationSet::from_bytes_v3(&bytes)
        .unwrap()
        .is_share_grant_revoked(&grant.grant_id, &grant.owner));
}

fn v3_bytes_revoking(world: &World, grants: &[&ShareGrant]) -> Vec<u8> {
    let mut set = RevocationSet::new();
    for grant in grants {
        set.verify_and_insert(world.revocation_record(grant), None)
            .unwrap();
    }
    set.to_bytes_v3().unwrap()
}

fn reload_v3(path: &std::path::Path) -> RevocationSet {
    RevocationSet::from_bytes_v3(&std::fs::read(path).unwrap()).unwrap()
}

/// WHY (review r2/r3 P1, lost update across daemons): two writers with
/// INDEPENDENT views — two daemons sharing one identity dir, each with its
/// own process-local state — must not lose each other's revocation. Each
/// writer here takes its own OS lock handle (no shared mutex; the
/// process-local mutex is bypassed by calling the core directly). Writer A
/// reads the file and pauses; writer B is released only once it has either
/// been refused the lock (correct) or already read the same stale file (no
/// lock). Without the cross-process lock both read the empty file and the
/// later rename erases the other's revoke — deterministically, whichever
/// order the renames land in.
#[tokio::test]
async fn concurrent_v3_writers_with_separate_lock_handles_both_survive() {
    let world = World::new().await;
    let path = world
        .identity_dir()
        .join(crate::SHARE_GRANT_REVOCATIONS_FILE);
    let (g1, g2) = (world.grant(1, 3_600), world.grant(2, 3_600));
    let (a_bytes, b_bytes) = (
        v3_bytes_revoking(&world, &[&g1]),
        v3_bytes_revoking(&world, &[&g2]),
    );
    let a_has_read_for_b = tokio::sync::Notify::new();
    let a_has_read_for_driver = tokio::sync::Notify::new();
    let a_go = tokio::sync::Notify::new();
    let b_progress = tokio::sync::Notify::new();

    let writer_a = crate::merge_write_share_grant_revocations(
        &path,
        &a_bytes,
        world.now,
        || {},
        || async {
            a_has_read_for_b.notify_one();
            a_has_read_for_driver.notify_one();
            a_go.notified().await;
        },
    );
    let writer_b = async {
        a_has_read_for_b.notified().await;
        crate::merge_write_share_grant_revocations(
            &path,
            &b_bytes,
            world.now,
            || b_progress.notify_one(),
            || async { b_progress.notify_one() },
        )
        .await
    };
    let driver = async {
        a_has_read_for_driver.notified().await;
        b_progress.notified().await; // B is blocked on the lock, or read stale
        a_go.notify_one();
    };
    let (a, b, ()) = tokio::join!(writer_a, writer_b, driver);
    a.unwrap();
    b.unwrap();

    let reloaded = reload_v3(&path);
    assert!(
        reloaded.is_share_grant_revoked(&g1.grant_id, &g1.owner),
        "A's revoke survives"
    );
    assert!(
        reloaded.is_share_grant_revoked(&g2.grant_id, &g2.owner),
        "B's revoke survives"
    );
}

/// WHY (review r3 P2): the disk union must not resurrect records the
/// retention rule has collected — a share-grant revocation is dropped once
/// its grant is past its GC horizon, in memory AND on the next write, while
/// live revocations are kept.
#[tokio::test]
async fn v3_merge_applies_the_gc_horizon() {
    let world = World::new().await;
    let path = world
        .identity_dir()
        .join(crate::SHARE_GRANT_REVOCATIONS_FILE);
    let dead_grant = ShareGrant::sign(
        &world.owner,
        [0xDD; 32],
        Grantee::Agent(world.b1),
        vec![world.a1],
        vec![ShareCap::Dm],
        1_000,
        2_000,
    )
    .unwrap();
    let live_grant = world.grant(1, 3_600);
    std::fs::create_dir_all(world.identity_dir()).unwrap();
    std::fs::write(&path, v3_bytes_revoking(&world, &[&dead_grant])).unwrap();
    assert!(
        reload_v3(&path).is_share_grant_revoked(&dead_grant.grant_id, &dead_grant.owner),
        "control: the long-dead revocation is on disk"
    );

    crate::merge_write_share_grant_revocations(
        &path,
        &v3_bytes_revoking(&world, &[&live_grant]),
        world.now,
        || {},
        || async {},
    )
    .await
    .unwrap();
    let reloaded = reload_v3(&path);
    assert!(
        !reloaded.is_share_grant_revoked(&dead_grant.grant_id, &dead_grant.owner),
        "a collected revocation is not resurrected by the union"
    );
    assert!(reloaded.is_share_grant_revoked(&live_grant.grant_id, &live_grant.owner));
}

/// WHY (review r3 P2): a share-grant revocation that arrives ONLY on a
/// legacy carrier (v1 `x0x.revocation`, v2 bindings) is enforced in memory,
/// but the legacy files cannot hold it — so it must also be written to
/// `revocations-v3.bin`, or a restart forgets it and the outbox could
/// redeliver the grant. Functional half: the v3 writer persists a record
/// inserted the way the legacy handlers insert it, and it survives a reload
/// while the legacy encodings drop it. Wiring half: both legacy handlers
/// call the v3 writer (they are inline in the gossip listener and cannot be
/// driven without a network, so this half is a source check).
#[tokio::test]
async fn share_grant_revocation_from_a_legacy_carrier_survives_restart() {
    let world = World::new().await;
    let grant = world.grant(1, 3_600);
    world.revoke_in_memory_only(&grant).await; // as the v1/v2 handler inserts
    {
        let set = world.revocations.read().await;
        for reloaded in [
            RevocationSet::from_bytes(&set.to_bytes().unwrap()).unwrap(),
            RevocationSet::from_bytes_v2(&set.to_bytes_v2().unwrap()).unwrap(),
        ] {
            assert!(
                !reloaded.is_share_grant_revoked(&grant.grant_id, &grant.owner),
                "control: the legacy files cannot carry it"
            );
        }
    }
    let identity_dir = world.identity_dir();
    crate::persist_share_grant_revocations(&world.revocations, Some(&identity_dir)).await;
    let path = identity_dir.join(crate::SHARE_GRANT_REVOCATIONS_FILE);
    assert!(reload_v3(&path).is_share_grant_revoked(&grant.grant_id, &grant.owner));

    let lib = include_str!("../../lib.rs");
    for (arm, next) in [
        (
            "DiscoveryMessage::Revocation(msg) => {",
            "DiscoveryMessage::RevocationV2(msg) => {",
        ),
        (
            "DiscoveryMessage::RevocationV2(msg) => {",
            "DiscoveryMessage::RevocationV3(msg) => {",
        ),
    ] {
        let body = lib
            .split(arm)
            .nth(1)
            .and_then(|rest| rest.split(next).next())
            .unwrap_or_default();
        assert!(
            body.contains("persist_share_grant_revocations("),
            "{arm} must persist share-grant revocations to v3"
        );
    }
}

/// WHY (review P1, fail loud): if `revocations-v3.bin` cannot be written
/// durably the revoke must fail (5xx), never report success that a restart
/// would forget — after which the reloaded outbox would redeliver the
/// grant. A retry once the disk is writable succeeds and is durable.
#[tokio::test]
async fn revoke_fails_when_the_revocation_is_not_durable() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    let grant = world.grant(1, 3_600);
    let outbox = world.outbox(world.now).await;
    assert!(issue_to(&world, &grant, &outbox, &receiver).await.queued);

    // The identity dir cannot be created: a file sits where it should be.
    let blocked = world.dir.path().join("blocked");
    std::fs::write(&blocked, b"not a dir").unwrap();
    let err = world
        .revoke(&grant, &blocked.join("identity"), &outbox)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ShareGrantError::Store(ref m) if m.contains("revocations-v3")),
        "{err:?}"
    );
    // In force for this run (fail closed) even though not durable.
    assert!(world
        .revocations
        .read()
        .await
        .is_share_grant_revoked(&grant.grant_id, &grant.owner));

    // Retry with a writable identity dir: durable on disk.
    world
        .revoke(&grant, &world.identity_dir(), &outbox)
        .await
        .unwrap();
    let bytes = std::fs::read(
        world
            .identity_dir()
            .join(crate::SHARE_GRANT_REVOCATIONS_FILE),
    )
    .unwrap();
    assert!(RevocationSet::from_bytes_v3(&bytes)
        .unwrap()
        .is_share_grant_revoked(&grant.grant_id, &grant.owner));
    assert!(world.outbox(world.now).await.is_empty());
}

/// WHY (review P1, fail loud): if the outbox removal cannot be written the
/// revoke must fail too — and a retry must REWRITE the outbox even though
/// the entry is already gone from memory, or a restart would reload it.
#[tokio::test]
async fn revoke_fails_when_the_outbox_removal_is_not_durable() {
    let world = World::new().await;
    let receiver = Receiver::new(world.a1, &world.owner);
    let grant = world.grant(1, 3_600);
    let dir = world.dir.path().join("o");
    let path = dir.join(super::super::outbox::SHARE_GRANT_OUTBOX_FILE);
    let outbox =
        GrantRedeliveryOutbox::load(path.clone(), Some(world.owner.user_id()), world.now).await;
    assert!(issue_to(&world, &grant, &outbox, &receiver).await.queued);

    // Make the outbox directory unwritable by swapping a file in its place.
    let parked = world.dir.path().join("o.parked");
    std::fs::rename(&dir, &parked).unwrap();
    std::fs::write(&dir, b"not a dir").unwrap();
    let err = world
        .revoke(&grant, &world.identity_dir(), &outbox)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ShareGrantError::Store(ref m) if m.contains("outbox")),
        "{err:?}"
    );

    // The disk comes back holding the stale entry.
    std::fs::remove_file(&dir).unwrap();
    std::fs::rename(&parked, &dir).unwrap();
    assert_eq!(
        GrantRedeliveryOutbox::load(path.clone(), Some(world.owner.user_id()), world.now)
            .await
            .len(),
        1,
        "control: the file still holds the revoked entry"
    );
    world
        .revoke(&grant, &world.identity_dir(), &outbox)
        .await
        .unwrap();
    assert!(
        GrantRedeliveryOutbox::load(path, Some(world.owner.user_id()), world.now)
            .await
            .is_empty(),
        "the retry rewrote the outbox"
    );
}
