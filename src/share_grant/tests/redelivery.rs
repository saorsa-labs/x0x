//! #926 owner-side grant redelivery outbox. The "network" here is a switch
//! in front of the receiving daemon's REAL #924 delivery path
//! ([`handle_share_grant_dm`] into its [`ShareGrantStore`]): a send succeeds
//! only when that handler verified and stored the grant, exactly as the
//! durable v2 ACK does in production. Each negative case would pass (and so
//! fail its assertion) if the check it guards were removed.

use super::super::outbox::{
    retry_delay_secs, GrantRedeliveryOutbox, OutboxError, MAX_OUTBOX_ENTRIES,
    MAX_OUTBOX_ENTRIES_PER_RECIPIENT, OUTBOX_ENTRY_TTL_SECS,
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

    /// The owner's revocation of `grant` (what `revoke_share_grant` signs).
    async fn revoke(&self, grant: &ShareGrant) {
        let record = RevocationRecord::sign(
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
        .unwrap();
        self.revocations
            .write()
            .await
            .verify_and_insert(record, None)
            .unwrap();
    }
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

    // What `Agent::revoke_share_grant` does: record the revocation, drop
    // the grant's queued deliveries.
    world.revoke(&grant).await;
    assert_eq!(outbox.remove_grant(&grant.grant_id).await.unwrap(), 1);
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
    world.revoke(&grant).await;
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

/// WHY (#926 test d): one peer cannot fill the outbox — each recipient is
/// capped, and other recipients still queue.
#[tokio::test]
async fn per_recipient_bound_is_enforced() {
    let world = World::new().await;
    let outbox = GrantRedeliveryOutbox::in_memory(Some(world.owner.user_id()));
    for i in 0..MAX_OUTBOX_ENTRIES_PER_RECIPIENT {
        let grant = world.grant(u8::try_from(i).unwrap(), 3_600);
        assert!(outbox.enqueue(&grant, world.a1, world.now).await.unwrap());
    }
    let over = world.grant(0xFE, 3_600);
    assert_eq!(
        outbox.enqueue(&over, world.a1, world.now).await,
        Err(OutboxError::RecipientFull)
    );
    assert_eq!(outbox.len(), MAX_OUTBOX_ENTRIES_PER_RECIPIENT);
    let other = AgentId([0x77; 32]);
    assert_eq!(outbox.enqueue(&over, other, world.now).await, Ok(true));
    // Re-queueing the same (grant, recipient) is a no-op, not a new entry.
    assert_eq!(outbox.enqueue(&over, other, world.now).await, Ok(false));
}

/// WHY (#926 test d): the outbox as a whole is bounded, and past the bound a
/// new entry is refused and reported (never a silent eviction).
#[tokio::test]
async fn total_bound_is_enforced_and_reported() {
    let world = World::new().await;
    let outbox = GrantRedeliveryOutbox::in_memory(Some(world.owner.user_id()));
    let grant = world.grant(6, 3_600);
    for i in 0..MAX_OUTBOX_ENTRIES {
        let mut recipient = [0u8; 32];
        recipient[..8].copy_from_slice(&(i as u64).to_le_bytes());
        assert_eq!(
            outbox.enqueue(&grant, AgentId(recipient), world.now).await,
            Ok(true)
        );
    }
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
