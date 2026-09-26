//! ADR-0070 slice 3 intent tests for the ShareGrant model, wire and store.
//! Each negative case would pass (and so fail its assertion) if the check it
//! guards were loosened or removed.

use super::*;
use crate::identity::{AgentKeypair, UserKeypair};
use tokio::sync::oneshot;

const NOW: u64 = 1_800_000_000;

fn agent(byte: u8) -> AgentId {
    AgentId([byte; 32])
}

fn grant_by(owner: &UserKeypair, grantee: Grantee, agents: Vec<AgentId>) -> ShareGrant {
    ShareGrant::sign(
        owner,
        [0x42; 32],
        grantee,
        agents,
        vec![ShareCap::Dm, ShareCap::Connect { ports: vec![22] }],
        NOW - 60,
        NOW + 3_600,
    )
    .expect("sign grant")
}

fn typed(
    payload: Vec<u8>,
) -> (
    DmTypedPayload,
    oneshot::Receiver<DmTypedPayloadCompletionResult>,
) {
    let (tx, rx) = oneshot::channel();
    (
        DmTypedPayload {
            sender: agent(0xEE),
            machine_id: crate::identity::MachineId([0xEF; 32]),
            payload,
            verified: true,
            trust_decision: None,
            received_at_unix_ms: 0,
            request_id: [0; 16],
            completion: Some(tx),
        },
        rx,
    )
}

/// WHY: the grant is the authority; its signature must bind every field.
#[test]
fn signed_grant_verifies_and_any_field_change_breaks_it() {
    let owner = UserKeypair::generate().unwrap();
    let grant = grant_by(
        &owner,
        Grantee::User(UserId([9; 32])),
        vec![agent(2), agent(1)],
    );
    grant.verify().expect("fresh grant verifies");
    assert_eq!(
        grant.agents,
        vec![agent(1), agent(2)],
        "agents canonicalised"
    );

    let mut widened = grant.clone();
    widened.caps.insert(ShareCap::Exec);
    assert!(matches!(
        widened.verify(),
        Err(ShareGrantError::BadSignature(_))
    ));

    let mut extended = grant.clone();
    extended.expiry += 1;
    assert!(extended.verify().is_err());

    let mut more_agents = grant.clone();
    more_agents.agents.push(agent(3));
    assert!(more_agents.verify().is_err());

    let mut regrantee = grant;
    regrantee.grantee = Grantee::User(UserId([8; 32]));
    assert!(regrantee.verify().is_err());
}

/// WHY: authority is the owner key only. A grant naming owner A but signed
/// by B (with B's key embedded, or with A's key and B's signature) is
/// rejected.
#[test]
fn non_owner_signature_is_rejected() {
    let owner = UserKeypair::generate().unwrap();
    let impostor = UserKeypair::generate().unwrap();
    let by_impostor = grant_by(&impostor, Grantee::Agent(agent(7)), vec![agent(1)]);

    let mut claims_owner = by_impostor.clone();
    claims_owner.owner = owner.user_id();
    assert!(
        matches!(claims_owner.verify(), Err(ShareGrantError::BadSignature(_))),
        "owner id must hash from the embedded key"
    );

    let mut owner_key_impostor_sig = by_impostor;
    owner_key_impostor_sig.owner = owner.user_id();
    owner_key_impostor_sig.owner_public_key = owner.public_key().as_bytes().to_vec();
    assert!(matches!(
        owner_key_impostor_sig.verify(),
        Err(ShareGrantError::BadSignature(_))
    ));
}

/// WHY: structurally meaningless grants are refused before signing.
#[test]
fn invalid_grants_are_refused() {
    let owner = UserKeypair::generate().unwrap();
    let sign = |agents: Vec<AgentId>, caps: Vec<ShareCap>, nb: u64, exp: u64, grantee| {
        ShareGrant::sign(&owner, [1; 32], grantee, agents, caps, nb, exp)
    };
    let stranger = Grantee::User(UserId([5; 32]));
    assert!(sign(vec![], vec![ShareCap::Dm], 0, 10, stranger).is_err());
    assert!(sign(vec![agent(1)], vec![], 0, 10, stranger).is_err());
    assert!(sign(vec![agent(1)], vec![ShareCap::Dm], 10, 10, stranger).is_err());
    assert!(sign(
        vec![agent(1)],
        vec![ShareCap::Connect { ports: vec![0] }],
        0,
        10,
        stranger
    )
    .is_err());
    assert!(sign(
        vec![agent(1)],
        vec![ShareCap::Dm],
        0,
        10,
        Grantee::User(owner.user_id())
    )
    .is_err());
    assert!(sign(
        vec![agent(1)],
        vec![ShareCap::Dm],
        0,
        10,
        Grantee::Agent(agent(1))
    )
    .is_err());
    // Two Connect caps merge into one sorted set.
    let merged = sign(
        vec![agent(1)],
        vec![
            ShareCap::Connect {
                ports: vec![443, 22],
            },
            ShareCap::Connect {
                ports: vec![22, 80],
            },
        ],
        0,
        10,
        stranger,
    )
    .unwrap();
    assert!(merged.caps.contains(&ShareCap::Connect {
        ports: vec![22, 80, 443]
    }));
}

/// WHY: the wire decoder is strict — no prefix, junk, truncation or
/// trailing bytes ever yields a grant.
#[test]
fn wire_decoding_is_strict() {
    let owner = UserKeypair::generate().unwrap();
    let grant = grant_by(&owner, Grantee::Agent(agent(7)), vec![agent(1)]);
    let payload = grant.to_dm_payload().unwrap();
    assert_eq!(ShareGrant::from_dm_payload(&payload).unwrap(), grant);

    let body = &payload[SHARE_GRANT_DM_PREFIX.len()..];
    assert!(
        ShareGrant::from_dm_payload(body).is_err(),
        "prefix required"
    );
    let mut trailing = payload.clone();
    trailing.push(0);
    assert!(ShareGrant::from_dm_payload(&trailing).is_err());
    assert!(ShareGrant::from_dm_payload(&payload[..payload.len() - 3]).is_err());
    let mut junk = SHARE_GRANT_DM_PREFIX.to_vec();
    junk.extend_from_slice(b"not a grant");
    assert!(ShareGrant::from_dm_payload(&junk).is_err());
}

/// WHY (decision 3): a malformed grant completes with Err — the durable ACK
/// is withheld — and nothing is stored.
#[tokio::test]
async fn malformed_grant_withholds_ack_and_is_not_stored() {
    let owner = UserKeypair::generate().unwrap();
    let store = ShareGrantStore::in_memory(agent(1), Some(owner.user_id()));
    let mut payload = SHARE_GRANT_DM_PREFIX.to_vec();
    payload.extend_from_slice(&[0xFF; 40]);
    let (t, rx) = typed(payload);
    assert!(handle_share_grant_dm(Some(&store), t).await.is_err());
    assert!(
        rx.await.expect("completion resolved").is_err(),
        "ACK withheld"
    );
    assert!(store.grants(GrantRole::Issued).is_empty());
    assert!(store.grants(GrantRole::Received).is_empty());

    // A forged (bad-signature) grant is refused the same way.
    let mut forged = grant_by(&owner, Grantee::Agent(agent(7)), vec![agent(1)]);
    forged.caps.insert(ShareCap::Exec);
    let (t, rx) = typed(forged.to_dm_payload().unwrap());
    assert!(handle_share_grant_dm(Some(&store), t).await.is_err());
    assert!(rx.await.unwrap().is_err());
    assert!(store.grants(GrantRole::Issued).is_empty());
}

/// WHY: a valid grant is stored in the right role and only then acked;
/// replays are idempotent; an unrelated grant is refused.
#[tokio::test]
async fn valid_grant_is_stored_then_acked_and_replays_are_duplicates() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_owner = UserKeypair::generate().unwrap();
    let grant = grant_by(
        &owner,
        Grantee::User(grantee_owner.user_id()),
        vec![agent(1)],
    );

    // Shared-agent daemon (same owner): issued role.
    let shared_side = ShareGrantStore::in_memory(agent(1), Some(owner.user_id()));
    let (t, rx) = typed(grant.to_dm_payload().unwrap());
    assert_eq!(
        handle_share_grant_dm(Some(&shared_side), t).await,
        Ok(DmTypedPayloadCompletion::Inserted)
    );
    assert_eq!(rx.await.unwrap(), Ok(DmTypedPayloadCompletion::Inserted));
    assert_eq!(shared_side.grants(GrantRole::Issued), vec![grant.clone()]);
    let (t, _rx) = typed(grant.to_dm_payload().unwrap());
    assert_eq!(
        handle_share_grant_dm(Some(&shared_side), t).await,
        Ok(DmTypedPayloadCompletion::Duplicate)
    );

    // Grantee daemon: received role.
    let grantee_side = ShareGrantStore::in_memory(agent(9), Some(grantee_owner.user_id()));
    let (t, _rx) = typed(grant.to_dm_payload().unwrap());
    assert!(handle_share_grant_dm(Some(&grantee_side), t).await.is_ok());
    assert_eq!(grantee_side.grants(GrantRole::Received).len(), 1);
    assert!(grantee_side.grants(GrantRole::Issued).is_empty());

    // A third install: not for us, refused, nothing stored.
    let third = ShareGrantStore::in_memory(agent(5), Some(UserId([3; 32])));
    let (t, rx) = typed(grant.to_dm_payload().unwrap());
    assert!(handle_share_grant_dm(Some(&third), t).await.is_err());
    assert!(rx.await.unwrap().is_err());
    assert!(third.grants(GrantRole::Received).is_empty());

    // No store installed: refused, ACK withheld.
    let (t, rx) = typed(grant.to_dm_payload().unwrap());
    assert!(handle_share_grant_dm(None, t).await.is_err());
    assert!(rx.await.unwrap().is_err());
}

/// WHY: an already-expired grant is never stored; a same-id grant with
/// different content is a conflict, not an overwrite.
#[tokio::test]
async fn expired_and_conflicting_grants_are_refused() {
    let owner = UserKeypair::generate().unwrap();
    let store = ShareGrantStore::in_memory(agent(1), Some(owner.user_id()));
    let grant = grant_by(&owner, Grantee::Agent(agent(7)), vec![agent(1)]);
    assert_eq!(
        store.accept(grant.clone(), grant.expiry).await,
        Err(ShareGrantError::Expired)
    );
    assert!(store.grants(GrantRole::Issued).is_empty());

    store.accept(grant.clone(), NOW).await.unwrap();
    let other = ShareGrant::sign(
        &owner,
        grant.grant_id,
        Grantee::Agent(agent(8)),
        vec![agent(1)],
        vec![ShareCap::Dm],
        NOW - 60,
        NOW + 60,
    )
    .unwrap();
    assert_eq!(
        store.accept(other, NOW).await,
        Err(ShareGrantError::Conflict)
    );
    assert_eq!(store.grants(GrantRole::Issued), vec![grant]);
}

/// WHY: grants survive restart, the file is private (0600), and a corrupt
/// file is never silently replaced (writes refused, nothing held).
#[tokio::test]
async fn store_persists_privately_and_refuses_writes_over_a_corrupt_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SHARE_GRANT_STORE_FILE);
    let owner = UserKeypair::generate().unwrap();
    let grant = grant_by(&owner, Grantee::Agent(agent(7)), vec![agent(1)]);

    let store = ShareGrantStore::load(path.clone(), agent(1), Some(owner.user_id())).await;
    store.accept(grant.clone(), NOW).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let reloaded = ShareGrantStore::load(path.clone(), agent(1), Some(owner.user_id())).await;
    assert_eq!(reloaded.grants(GrantRole::Issued), vec![grant.clone()]);

    std::fs::write(&path, b"garbage").unwrap();
    let corrupt = ShareGrantStore::load(path.clone(), agent(1), Some(owner.user_id())).await;
    assert!(corrupt.load_error().is_some());
    assert!(corrupt.grants(GrantRole::Issued).is_empty());
    assert!(matches!(
        corrupt.accept(grant, NOW).await,
        Err(ShareGrantError::Store(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"garbage");
}

/// WHY: a grant's agents must be the signer's own. A key pair that is not
/// the owner cannot produce a grant a same-owner daemon accepts as issued.
#[tokio::test]
async fn grant_signed_by_grantee_over_owner_agent_is_not_issued_here() {
    let owner_a = UserKeypair::generate().unwrap();
    let user_b = UserKeypair::generate().unwrap();
    let a1 = AgentKeypair::generate().unwrap().agent_id();
    // B "grants" itself access to A's agent A1.
    let by_b = ShareGrant::sign(
        &user_b,
        [7; 32],
        Grantee::User(UserId([0xCC; 32])),
        vec![a1],
        vec![ShareCap::Dm],
        NOW - 1,
        NOW + 60,
    )
    .unwrap();
    let a1_daemon = ShareGrantStore::in_memory(a1, Some(owner_a.user_id()));
    assert_eq!(a1_daemon.classify(&by_b), None);
    assert_eq!(
        a1_daemon.accept(by_b, NOW).await,
        Err(ShareGrantError::NotForUs)
    );
}

/// WHY (omp #924 finding 2): `X0SG || valid body || garbage` is corruption.
/// It must fail closed into `load_error` — no grant honoured, no write that
/// would erase the evidence — exactly like any other unreadable file.
#[tokio::test]
async fn store_with_trailing_garbage_fails_closed_and_is_left_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SHARE_GRANT_STORE_FILE);
    let owner = UserKeypair::generate().unwrap();
    let grant = grant_by(&owner, Grantee::Agent(agent(7)), vec![agent(1)]);
    let store = ShareGrantStore::load(path.clone(), agent(1), Some(owner.user_id())).await;
    store.accept(grant.clone(), NOW).await.unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(b"trailing-garbage");
    std::fs::write(&path, &bytes).unwrap();

    let reloaded = ShareGrantStore::load(path.clone(), agent(1), Some(owner.user_id())).await;
    assert!(
        reloaded.load_error().is_some(),
        "trailing bytes are corruption"
    );
    assert!(reloaded.grants(GrantRole::Issued).is_empty());
    assert!(reloaded.candidates_for_local_agent(NOW).is_empty());
    assert!(matches!(
        reloaded.accept(grant, NOW).await,
        Err(ShareGrantError::Store(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "file left untouched");
}

/// WHY (omp #924 finding 3): the store's write releases a v2 ACK meaning
/// "stored", so it must go through the fsyncing durable writer, not the
/// rename-only one. Source guard: fails if the store is switched back.
#[test]
fn grant_store_persists_through_the_durable_writer() {
    let src = include_str!("../share_grant.rs");
    let persist = src
        .split("async fn persist(&self)")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("persist() present");
    assert!(persist.contains("write_private_bytes_durable("));
    assert!(!persist.contains("save_private_bytes_to("));
}

/// WHY (omp #924 note 5a): a failed clock read maps to 0; a grant whose
/// window contains 0 must not come back to life — evaluation fails closed.
#[tokio::test]
async fn zero_clock_yields_no_access() {
    let owner = UserKeypair::generate().unwrap();
    let store = ShareGrantStore::in_memory(agent(1), Some(owner.user_id()));
    let grant = ShareGrant::sign(
        &owner,
        [9; 32],
        Grantee::Agent(agent(7)),
        vec![agent(1)],
        vec![ShareCap::Dm],
        0,
        10,
    )
    .unwrap();
    store.accept(grant, 5).await.unwrap();
    let bindings = AuthenticatedMachineBindings::default();
    let machine = crate::identity::MachineId([7; 32]);
    crate::dm_inbox::record_authenticated_machine_binding(&bindings, agent(7), machine, 5).await;
    let cache = RwLock::new(HashMap::new());
    let revocations = RwLock::new(RevocationSet::new());
    let requester = agent(7);
    assert!(
        evaluate_grant_access(
            &store,
            &bindings,
            &cache,
            &revocations,
            &requester,
            &machine,
            5
        )
        .await
        .dm,
        "control: live inside its window"
    );
    assert!(
        evaluate_grant_access(
            &store,
            &bindings,
            &cache,
            &revocations,
            &requester,
            &machine,
            0
        )
        .await
        .is_empty(),
        "clock failure fails closed"
    );
}

mod enforcement;

// ── #926: the grantee-attached grant fetch (ADR-0070 §2) ────────────────

fn fetch_payload(grant_id: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(SHARE_GRANT_FETCH_DM_PREFIX.len() + 32);
    p.extend_from_slice(SHARE_GRANT_FETCH_DM_PREFIX);
    p.extend_from_slice(grant_id);
    p
}

fn fetch_response_payload(grant: &ShareGrant) -> Vec<u8> {
    let wire = grant.to_dm_payload().expect("grant wire form");
    let mut p = Vec::with_capacity(SHARE_GRANT_FETCH_RESPONSE_DM_PREFIX.len() + wire.len());
    p.extend_from_slice(SHARE_GRANT_FETCH_RESPONSE_DM_PREFIX);
    p.extend_from_slice(&wire);
    p
}

fn typed_from(sender: AgentId, payload: Vec<u8>) -> DmTypedPayload {
    DmTypedPayload {
        sender,
        machine_id: crate::identity::MachineId([0xEF; 32]),
        payload,
        verified: true,
        trust_decision: None,
        received_at_unix_ms: 0,
        request_id: [0; 16],
        completion: None,
    }
}

/// WHY (#926 Rule 9, main arm): a daemon that MISSED the grant delivery
/// (the shared agent's install) must be able to fetch it from a holder
/// (the grantee), and the fetched grant must land through the same
/// fail-closed accept path exactly ONCE — a replay is a Duplicate that
/// stores nothing.
#[tokio::test]
async fn fetch_serves_a_subject_and_applies_exactly_once() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let grantee_agent = agent(0x22);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);

    // An OWNER install holds the grant (Issued role — only owner installs
    // serve fetches, r3 design b); the SHARED AGENT's install (same owner,
    // missed the delivery) starts empty.
    let responder = ShareGrantStore::in_memory(grantee_agent, Some(owner.user_id()));
    responder.accept(grant.clone(), NOW).await.unwrap();
    let fetcher = ShareGrantStore::in_memory(shared, Some(owner.user_id()));
    assert!(fetcher.by_id(&grant.grant_id).is_none(), "starts empty");

    // The fetcher asks; the responder serves ONLY subjects of the grant.
    assert!(fetcher.note_fetch(&grant.grant_id), "a fresh fetch window");
    assert!(
        !fetcher.note_fetch(&grant.grant_id),
        "a repeat inside the TTL is suppressed"
    );
    let (req, rx) = typed(fetch_payload(&grant.grant_id));
    let mut req = req;
    req.sender = shared;
    let outcome = handle_share_grant_fetch(Some(&responder), None, NOW, req).await;
    assert!(outcome.result.is_ok(), "a subject's fetch is answered");
    let reply = outcome.reply.expect("the signed grant bytes come back");
    assert_eq!(reply, grant.to_dm_payload().unwrap());

    // The response lands through the fail-closed accept path.
    let resp = reply_from(&fetch_response_payload(&grant), grantee_agent);
    drop(rx);
    let result = handle_share_grant_fetch_response(Some(&fetcher), None, NOW, resp).await;
    assert!(matches!(result, Ok(DmTypedPayloadCompletion::Inserted)));
    assert_eq!(
        fetcher.by_id(&grant.grant_id),
        Some(grant.clone()),
        "the fetched grant is held (issued role: same owner)"
    );

    // EXACTLY ONCE: a replay of the same response is a Duplicate.
    let replay = reply_from(&fetch_response_payload(&grant), grantee_agent);
    let replayed = handle_share_grant_fetch_response(Some(&fetcher), None, NOW, replay).await;
    assert!(replayed.is_err(), "the window closed on success");
}

fn reply_from(payload: &[u8], sender: AgentId) -> DmTypedPayload {
    typed_from(sender, payload.to_vec())
}

/// WHY: a stranger — an agent the grant does NOT name — must get nothing:
/// no reply bytes, no ACK. This is the serve-authorization pin.
#[tokio::test]
async fn fetch_refuses_a_non_subject_and_leaks_nothing() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let stranger = agent(0x99);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);
    let responder = ShareGrantStore::in_memory(
        grantee_agent_of(&grantee_user),
        Some(grantee_user.user_id()),
    );
    responder.accept(grant.clone(), NOW).await.unwrap();

    let outcome = handle_share_grant_fetch(
        Some(&responder),
        None,
        NOW,
        typed_from(stranger, fetch_payload(&grant.grant_id)),
    )
    .await;
    assert!(outcome.result.is_err(), "a non-subject's fetch is refused");
    assert!(outcome.reply.is_none(), "and leaks no grant bytes");
}

fn grantee_agent_of(_user: &UserKeypair) -> AgentId {
    agent(0x22)
}

/// WHY: an unprompted response (no fetch in flight) must be dropped — a
/// push pretending to be an answer stores nothing.
#[tokio::test]
async fn fetch_response_for_unrequested_id_is_dropped() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);
    let fetcher = ShareGrantStore::in_memory(shared, Some(owner.user_id()));
    // NO note_fetch: the id was never requested here.
    let resp = typed_from(agent(0x22), fetch_response_payload(&grant));
    let result = handle_share_grant_fetch_response(Some(&fetcher), None, NOW, resp).await;
    assert!(result.is_err(), "an unprompted grant response is dropped");
    assert!(fetcher.by_id(&grant.grant_id).is_none(), "nothing stored");
}

/// WHY: a fetch for a grant the responder does not hold is a RETRY (Err,
/// ACK withheld) — the owner's delivery may still arrive there.
#[tokio::test]
async fn fetch_for_unheld_grant_is_a_retry() {
    let owner = UserKeypair::generate().unwrap();
    // An OWNER install (local_owner == grant.owner) — only these serve fetches.
    let responder = ShareGrantStore::in_memory(agent(0x22), Some(owner.user_id()));
    let outcome = handle_share_grant_fetch(
        Some(&responder),
        None,
        NOW,
        typed_from(agent(0x11), fetch_payload(&[7; 32])),
    )
    .await;
    assert!(outcome.result.is_err(), "an unheld grant is a retry");
    assert!(outcome.reply.is_none());
}

// ── #967 r2: revocation both sides, rate limit, size bound, e2e trigger ──

fn revoked_ids(ids: &[[u8; 32]]) -> impl Fn(&ShareGrant) -> bool + '_ {
    move |grant: &ShareGrant| ids.contains(&grant.grant_id)
}

/// WHY (#967 B1, responder side): a REVOKED grant must never be served —
/// a grantee that missed the revocation gossip cannot resurrect access by
/// fetching from a daemon that holds the (stale) bytes.
#[tokio::test]
async fn fetch_never_serves_a_revoked_grant() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);
    // An OWNER install (local_owner == grant.owner) — only these serve fetches.
    let responder = ShareGrantStore::in_memory(agent(0x22), Some(owner.user_id()));
    responder.accept(grant.clone(), NOW).await.unwrap();
    // The responder's owner has revoked exactly this grant.
    let revoked_list = [grant.grant_id];
    let is_revoked = revoked_ids(&revoked_list);
    let outcome = handle_share_grant_fetch(
        Some(&responder),
        Some(&is_revoked),
        NOW,
        typed_from(shared, fetch_payload(&grant.grant_id)),
    )
    .await;
    assert!(outcome.result.is_err(), "a revoked grant is never served");
    assert!(outcome.reply.is_none(), "and no bytes leave the responder");
}

/// WHY (#967 B1, requester side): a fetched grant revoked HERE (the
/// revocation landed while our fetch was in flight) is refused, not
/// stored.
#[tokio::test]
async fn fetch_response_revoked_here_is_not_stored() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);
    let fetcher = ShareGrantStore::in_memory(shared, Some(owner.user_id()));
    assert!(fetcher.note_fetch(&grant.grant_id));
    let revoked_list = [grant.grant_id];
    let is_revoked = revoked_ids(&revoked_list);
    let result = handle_share_grant_fetch_response(
        Some(&fetcher),
        Some(&is_revoked),
        NOW,
        typed_from(agent(0x22), fetch_response_payload(&grant)),
    )
    .await;
    assert!(result.is_err(), "a revoked grant is refused at the door");
    assert!(fetcher.by_id(&grant.grant_id).is_none(), "nothing stored");
}

/// WHY (#967 B2): one served fetch per peer per window — a stranger
/// cannot hammer the responder's store scan.
#[tokio::test]
async fn fetch_is_rate_limited_per_peer() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);
    // An OWNER install (local_owner == grant.owner) — only these serve fetches.
    let responder = ShareGrantStore::in_memory(agent(0x22), Some(owner.user_id()));
    responder.accept(grant.clone(), NOW).await.unwrap();
    let first = handle_share_grant_fetch(
        Some(&responder),
        None,
        NOW,
        typed_from(shared, fetch_payload(&grant.grant_id)),
    )
    .await;
    assert!(first.result.is_ok(), "the first fetch is served");
    let second = handle_share_grant_fetch(
        Some(&responder),
        None,
        NOW,
        typed_from(shared, fetch_payload(&grant.grant_id)),
    )
    .await;
    assert!(
        second.result.is_err(),
        "the second fetch inside the window is rate-limited"
    );
    assert!(second.reply.is_none());
    // A DIFFERENT peer is not rate-limited by the first one.
    let other = agent(0x33);
    // other must be a subject too: issue a DISTINCT grant for it.
    let grant2 = ShareGrant::sign(
        &owner,
        [0x43; 32],
        Grantee::User(grantee_user.user_id()),
        vec![other],
        vec![ShareCap::Dm],
        NOW - 60,
        NOW + 3_600,
    )
    .expect("sign grant2");
    responder.accept(grant2.clone(), NOW).await.unwrap();
    let theirs = handle_share_grant_fetch(
        Some(&responder),
        None,
        NOW,
        typed_from(other, fetch_payload(&grant2.grant_id)),
    )
    .await;
    assert!(theirs.result.is_ok(), "a different peer is served");
}

/// WHY (#967 B1): a forged or foreign-owner grant never passes the
/// response door — the store's own accept verifies the signature against
/// THIS install's owner, so bytes signed by anyone else are inert.
#[tokio::test]
async fn fetch_response_with_a_foreign_owner_grant_is_refused() {
    let owner = UserKeypair::generate().unwrap();
    let impostor = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let forged = grant_by(
        &impostor,
        Grantee::User(grantee_user.user_id()),
        vec![shared],
    );
    let fetcher = ShareGrantStore::in_memory(shared, Some(owner.user_id()));
    assert!(fetcher.note_fetch(&forged.grant_id));
    let result = handle_share_grant_fetch_response(
        Some(&fetcher),
        None,
        NOW,
        typed_from(agent(0x22), fetch_response_payload(&forged)),
    )
    .await;
    assert!(result.is_err(), "a foreign-owner grant is refused");
    assert!(fetcher.by_id(&forged.grant_id).is_none(), "nothing stored");
}

/// WHY (#967 B3, the end-to-end arm): a daemon OFFLINE through the
/// issuance later gains access — the trigger (request_share_grant_fetch
/// semantics: note the window, then ask), the holder's gated serve, and
/// the response door land the grant exactly once, and access evaluation
/// flips from empty to the grant's caps.
#[tokio::test]
async fn offline_daemon_later_gains_access_end_to_end() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let grantee_agent = agent(0x22);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);
    // An OWNER install holds it (only owner installs serve fetches);
    // the shared daemon was offline at issuance.
    let responder = ShareGrantStore::in_memory(grantee_agent, Some(owner.user_id()));
    responder.accept(grant.clone(), NOW).await.unwrap();
    let fetcher = ShareGrantStore::in_memory(shared, Some(owner.user_id()));

    // The trigger's store half: open the window ONLY for an unheld id.
    assert!(fetcher.note_fetch(&grant.grant_id));
    // The wire half happens off-test (send_direct); here the fetch frame
    // arrives at the holder, whose serve path is gated, and the reply
    // comes back through the response door.
    let served = handle_share_grant_fetch(
        Some(&responder),
        None,
        NOW,
        typed_from(shared, fetch_payload(&grant.grant_id)),
    )
    .await;
    assert!(served.result.is_ok());
    let mut reply = Vec::with_capacity(SHARE_GRANT_FETCH_RESPONSE_DM_PREFIX.len());
    reply.extend_from_slice(SHARE_GRANT_FETCH_RESPONSE_DM_PREFIX);
    reply.extend_from_slice(&served.reply.expect("signed bytes"));
    let landed = handle_share_grant_fetch_response(
        Some(&fetcher),
        None,
        NOW,
        typed_from(grantee_agent, reply),
    )
    .await;
    assert!(matches!(landed, Ok(DmTypedPayloadCompletion::Inserted)));
    // Access flipped: the fetched grant is now an enforcement candidate
    // for this daemon's agent (the caps evaluation reads exactly these).
    let candidates = fetcher.candidates_for_local_agent(NOW);
    assert!(
        candidates.iter().any(|g| g.grant_id == grant.grant_id),
        "the offline daemon now enforces the fetched grant"
    );
    assert!(candidates
        .iter()
        .any(|g| g.caps.contains(&ShareCap::Connect { ports: vec![22] })));
    // EXACTLY ONCE: the window closed, a replay is refused.
    let replay = handle_share_grant_fetch_response(
        Some(&fetcher),
        None,
        NOW,
        typed_from(grantee_agent, fetch_response_payload(&grant)),
    )
    .await;
    assert!(replay.is_err(), "the window closed on success");
}

// ── #967 r3: design (b), bounds, TTLs, and the trigger ─────────────────

/// WHY (B1 design b, the offline-through-revocation closure): a GRANTEE
/// install (Received role) must NEVER serve a fetch — a hostile or stale
/// grantee is exactly the peer that must not push grants to a daemon
/// that missed a revocation. Only owner installs (the revocation source)
/// serve, bounding the window to the owner's own v3 propagation.
#[tokio::test]
async fn a_grantee_install_never_serves_a_fetch() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    let grant = grant_by(&owner, Grantee::User(grantee_user.user_id()), vec![shared]);
    let grantee_store = ShareGrantStore::in_memory(agent(0x22), Some(grantee_user.user_id()));
    grantee_store.accept(grant.clone(), NOW).await.unwrap();
    assert!(
        grantee_store.by_id(&grant.grant_id).is_some(),
        "fixture: the grantee holds it"
    );
    let outcome = handle_share_grant_fetch(
        Some(&grantee_store),
        None,
        NOW,
        typed_from(shared, fetch_payload(&grant.grant_id)),
    )
    .await;
    assert!(outcome.result.is_err(), "a grantee install never serves");
    assert!(outcome.reply.is_none(), "and no bytes leave it");
}

/// WHY (responder expiry pin): an expired grant is never served.
#[tokio::test]
async fn an_expired_grant_is_never_served() {
    let owner = UserKeypair::generate().unwrap();
    let grantee_user = UserKeypair::generate().unwrap();
    let shared = agent(0x11);
    // Expiry BEFORE the evaluation time.
    let grant = ShareGrant::sign(
        &owner,
        [0x51; 32],
        Grantee::User(grantee_user.user_id()),
        vec![shared],
        vec![ShareCap::Dm],
        NOW - 3_600,
        NOW - 60,
    )
    .expect("sign expired grant");
    let responder = ShareGrantStore::in_memory(agent(0x22), Some(owner.user_id()));
    // accept would refuse (expired) — install it as held via the issued
    // map by accepting BEFORE expiry semantics: use accept at a time it
    // was valid, then evaluate the fetch AFTER.
    responder.accept(grant.clone(), NOW - 3_700).await.unwrap();
    let outcome = handle_share_grant_fetch(
        Some(&responder),
        None,
        NOW,
        typed_from(shared, fetch_payload(&grant.grant_id)),
    )
    .await;
    assert!(outcome.result.is_err(), "an expired grant is never served");
    assert!(outcome.reply.is_none());
}

/// WHY (TTL bounds): the in-flight window EXPIRES — an old entry no
/// longer suppresses a re-fetch, and a response after expiry is dropped.
#[tokio::test]
async fn the_fetch_window_expires_and_reopens() {
    let owner = UserKeypair::generate().unwrap();
    let fetcher = ShareGrantStore::in_memory(agent(0x11), Some(owner.user_id()));
    let id = [0x61; 32];
    assert!(fetcher.note_fetch(&id));
    assert!(!fetcher.note_fetch(&id), "suppressed inside the TTL");
    // Age the entry past the TTL (tests are a child module: direct map
    // access models the passage of time without sleeping).
    fetcher.fetch_in_flight.lock().unwrap().insert(
        id,
        std::time::Instant::now() - std::time::Duration::from_millis(GRANT_FETCH_TTL_MS + 1),
    );
    assert!(
        fetcher.note_fetch(&id),
        "an expired window reopens (a fresh fetch may start)"
    );
    // And a response for a fully-expired id is dropped.
    fetcher.fetch_in_flight.lock().unwrap().insert(
        id,
        std::time::Instant::now() - std::time::Duration::from_millis(GRANT_FETCH_TTL_MS + 1),
    );
    assert!(!fetcher.is_fetch_in_flight(&id));
}

/// WHY (cap bounds): both peer-keyed maps evict oldest at the cap.
#[tokio::test]
async fn the_peer_maps_evict_at_the_cap() {
    let owner = UserKeypair::generate().unwrap();
    let store = ShareGrantStore::in_memory(agent(0x11), Some(owner.user_id()));
    let id_of = |i: usize| {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&(i as u32).to_be_bytes());
        AgentId(b)
    };
    for i in 0..=GRANT_FETCH_MAX_ENTRIES {
        let _ = store.note_peer_fetch(&id_of(i));
        let _ = store.note_hint_sent(&id_of(i));
    }
    let peers = store.fetch_peer_served.lock().unwrap();
    let hints = store.hint_sent.lock().unwrap();
    assert_eq!(peers.len(), GRANT_FETCH_MAX_ENTRIES, "capped");
    assert_eq!(hints.len(), GRANT_FETCH_MAX_ENTRIES, "capped");
    assert!(!peers.contains_key(&id_of(0)), "the oldest was evicted");
    assert!(!hints.contains_key(&id_of(0)), "the oldest was evicted");
}

/// WHY (peer-window expiry): an aged entry no longer rate-limits the peer.
#[tokio::test]
async fn the_peer_window_expires() {
    let owner = UserKeypair::generate().unwrap();
    let store = ShareGrantStore::in_memory(agent(0x11), Some(owner.user_id()));
    let peer = agent(0x77);
    assert!(store.note_peer_fetch(&peer));
    assert!(
        !store.note_peer_fetch(&peer),
        "rate-limited inside the window"
    );
    store.fetch_peer_served.lock().unwrap().insert(
        peer,
        std::time::Instant::now()
            - std::time::Duration::from_millis(GRANT_FETCH_PEER_INTERVAL_MS + 1),
    );
    assert!(
        store.note_peer_fetch(&peer),
        "the window expired — served again"
    );
}

/// WHY (B3, the trigger): the DM-open attachment and the hint→fetch path
/// exist as PRODUCTION surface — held ids attach (rate-limited), and a
/// hint for an unheld id opens a real fetch window on the receiver.
#[tokio::test]
async fn hint_round_trip_opens_a_real_fetch_window() {
    // Payload encode/decode round-trips within the cap.
    let ids: Vec<[u8; 32]> = (0..SHARE_GRANT_HINT_MAX_IDS as u16 + 5)
        .map(|i| [i as u8; 32])
        .collect();
    let payload = share_grant_hint_payload(&ids);
    assert!(payload.starts_with(SHARE_GRANT_HINT_DM_PREFIX));
    let decoded = decode_share_grant_hint(&payload[SHARE_GRANT_HINT_DM_PREFIX.len()..]);
    assert_eq!(decoded.len(), SHARE_GRANT_HINT_MAX_IDS, "the cap trims");

    // The receiver side: a hint for an id this store does NOT hold opens
    // the fetch window (request_share_grant_fetch's store half; the wire
    // half needs a live peer and is exercised by the daemon wiring).
    let owner = UserKeypair::generate().unwrap();
    let store = ShareGrantStore::in_memory(agent(0x33), Some(owner.user_id()));
    let id = [0x71; 32];
    assert!(store.by_id(&id).is_none());
    assert!(
        store.note_fetch(&id),
        "the trigger's window opens for an unheld id"
    );
    assert!(store.is_fetch_in_flight(&id));
    // Held id: no window.
    let grantee_user = UserKeypair::generate().unwrap();
    let grant = grant_by(
        &owner,
        Grantee::User(grantee_user.user_id()),
        vec![agent(0x33)],
    );
    store.accept(grant.clone(), NOW).await.unwrap();
    let held = grant.grant_id;
    // The TRIGGER checks by_id first (request_share_grant_fetch returns
    // early for held ids), so no window is opened for them.
    assert!(store.by_id(&held).is_some());
    assert!(!store.is_fetch_in_flight(&held));
}
