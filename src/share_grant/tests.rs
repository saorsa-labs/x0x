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

mod redelivery;
