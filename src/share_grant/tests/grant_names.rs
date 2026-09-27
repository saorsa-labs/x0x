//! ADR-0079 intent tests: the `x0x-sharegrant-v2\0` envelope, its
//! owner-signed names section, envelope choice (capability gating), v1/v2
//! duplicate detection, the decode bounds, and outbox byte-identical
//! redelivery. Deterministic: fixed keys and times, no network. Each
//! negative case goes red if the check it guards is removed.

use super::super::outbox::{GrantRedeliveryOutbox, OutboxError};
use super::*;
use crate::identity::{AgentKeypair, MachineId, UserKeypair};
use std::sync::Mutex;

/// Every send a test observed: `(recipient, payload, logical request id)`.
type Sent = Mutex<Vec<(AgentId, Vec<u8>, [u8; 16])>>;

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn machine(byte: u8) -> MachineId {
    MachineId([byte; 32])
}

fn names_with(owner_name: &str, machines: &[(u8, &str)]) -> GrantNames {
    GrantNames {
        owner_name: Some(owner_name.to_string()),
        machines: machines
            .iter()
            .map(|(b, n)| GrantMachineName {
                machine_id: machine(*b),
                machine_name: (*n).to_string(),
            })
            .collect(),
    }
}

/// Owner, grantee agent, shared agent, and a grant between them valid
/// around the real clock (the store judges expiry by the wall clock).
struct Fixture {
    owner: UserKeypair,
    grantee: AgentId,
    shared: AgentId,
    grant: ShareGrant,
    signed: SignedGrantNames,
}

impl Fixture {
    fn new(grant_id: u8) -> Self {
        let owner = UserKeypair::generate().unwrap();
        let grantee = AgentKeypair::generate().unwrap().agent_id();
        let shared = AgentKeypair::generate().unwrap().agent_id();
        let now = real_now();
        let grant = ShareGrant::sign(
            &owner,
            [grant_id; 32],
            Grantee::Agent(grantee),
            vec![shared],
            vec![ShareCap::Dm],
            now - 60,
            now + 3_600,
        )
        .unwrap();
        let signed = SignedGrantNames::sign(
            &owner,
            &grant,
            names_with("Bob Smith", &[(1, "Studio"), (2, "Laptop")]),
        )
        .unwrap();
        Self {
            owner,
            grantee,
            shared,
            grant,
            signed,
        }
    }

    fn v2_payload(&self) -> Vec<u8> {
        ShareGrantEnvelopeV2::new(&self.grant, &self.signed)
            .to_dm_payload()
            .unwrap()
    }

    /// The grantee's store (the grant classifies as `Received` there).
    fn grantee_store(&self) -> ShareGrantStore {
        ShareGrantStore::in_memory(self.grantee, None)
    }
}

/// WHY (ADR-0079 §1): a v2 envelope must round-trip to exactly the v1 grant
/// plus names that verify under the grant's owner key.
#[test]
fn v2_envelope_round_trips_and_verifies() {
    let f = Fixture::new(1);
    let payload = f.v2_payload();
    assert!(payload.starts_with(SHARE_GRANT_V2_DM_PREFIX));
    let (grant, names) = decode_grant_delivery(&payload).expect("v2 decodes and verifies");
    assert_eq!(
        grant, f.grant,
        "the carried grant is the unchanged v1 grant"
    );
    assert_eq!(
        grant.to_dm_payload().unwrap(),
        f.grant.to_dm_payload().unwrap()
    );
    assert_eq!(names.as_ref(), Some(&f.signed.names));
    f.signed
        .verify(&f.grant)
        .expect("names verify for their grant");

    // A v1 delivery decodes to the same grant and no names.
    let (v1, none) = decode_grant_delivery(&f.grant.to_dm_payload().unwrap()).unwrap();
    assert_eq!(v1, f.grant);
    assert!(none.is_none());
}

/// WHY (ADR-0079 §1 Validation): a tampered, swapped or foreign-signed
/// names section must refuse the WHOLE envelope — nothing stored, ACK
/// withheld — so names can never be attributed to a user who did not sign
/// them, nor moved to another grant.
#[tokio::test]
async fn forged_or_foreign_names_are_refused() {
    let f = Fixture::new(2);
    let refuse = |envelope: ShareGrantEnvelopeV2, why: &str| {
        let payload = envelope.to_dm_payload().unwrap();
        let err = decode_grant_delivery(&payload).expect_err(why);
        assert!(
            matches!(err, ShareGrantError::Malformed(ref m) if m.starts_with("names section")),
            "{why}: {err:?}"
        );
    };
    // Tampered owner name.
    let mut tampered = ShareGrantEnvelopeV2::new(&f.grant, &f.signed);
    tampered.names.owner_name = Some("Mallory".into());
    refuse(tampered, "tampered owner_name");
    // Tampered machine name.
    let mut tampered = ShareGrantEnvelopeV2::new(&f.grant, &f.signed);
    tampered.names.machines[0].machine_name = "Evil".into();
    refuse(tampered, "tampered machine name");
    // Names signed for another grant by the same owner (swapped).
    let other = ShareGrant::sign(
        &f.owner,
        [0x77; 32],
        f.grant.grantee,
        f.grant.agents.clone(),
        vec![ShareCap::Dm],
        f.grant.not_before,
        f.grant.expiry,
    )
    .unwrap();
    let other_names = SignedGrantNames::sign(&f.owner, &other, f.signed.names.clone()).unwrap();
    refuse(
        ShareGrantEnvelopeV2::new(&f.grant, &other_names),
        "names moved from another grant",
    );
    // Names signed by a different user over this grant's digest.
    let mallory = UserKeypair::generate().unwrap();
    let forged = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        mallory.secret_key(),
        &f.signed.names.signed_bytes(&f.grant),
    )
    .unwrap();
    refuse(
        ShareGrantEnvelopeV2::new(
            &f.grant,
            &SignedGrantNames {
                names: f.signed.names.clone(),
                names_signature: forged.as_bytes().to_vec(),
            },
        ),
        "names signed by a foreign key",
    );
    assert!(
        SignedGrantNames::sign(&mallory, &f.grant, f.signed.names.clone()).is_err(),
        "only the grant's owner may sign its names"
    );

    // The receiver stores nothing for a forged envelope.
    let store = f.grantee_store();
    let mut tampered = ShareGrantEnvelopeV2::new(&f.grant, &f.signed);
    tampered.names.owner_name = Some("Mallory".into());
    let (typed, rx) = typed(tampered.to_dm_payload().unwrap());
    assert!(handle_share_grant_dm(Some(&store), typed).await.is_err());
    assert!(rx.await.unwrap().is_err(), "ACK withheld");
    assert!(
        store.grants(GrantRole::Received).is_empty(),
        "nothing stored"
    );

    // A forged GRANT inside a well-signed names section is refused too.
    let mut bad_grant = f.grant.clone();
    bad_grant.expiry += 1;
    let envelope = ShareGrantEnvelopeV2::new(&bad_grant, &f.signed);
    assert!(decode_grant_delivery(&envelope.to_dm_payload().unwrap()).is_err());
}

/// WHY (ADR-0079 Context): an old peer routes only `x0x-sharegrant-v1\0`;
/// it must be sent v1, and v2 bytes must never parse as a v1 grant (an old
/// daemon then junks them rather than storing something half-understood).
#[test]
fn old_peer_gets_v1_and_a_v1_decoder_refuses_v2() {
    let f = Fixture::new(3);
    assert_eq!(
        choose_grant_envelope(&f.grant, &f.grantee, true, false, Some(&f.signed)),
        GrantEnvelope::V1,
        "a grantee without the capability gets v1"
    );
    assert!(
        ShareGrant::from_dm_payload(&f.v2_payload()).is_err(),
        "the v1 decoder refuses v2 bytes"
    );
    assert!(!SHARE_GRANT_V2_DM_PREFIX.starts_with(SHARE_GRANT_DM_PREFIX));
    assert!(!SHARE_GRANT_DM_PREFIX.starts_with(SHARE_GRANT_V2_DM_PREFIX));
    assert!(
        ShareGrantEnvelopeV2::from_dm_payload(&f.grant.to_dm_payload().unwrap()).is_err(),
        "the v2 decoder refuses v1 bytes"
    );
}

/// WHY (ADR-0079 §1 "Who gets v2"): only a grantee agent that advertises the
/// capability gets v2; the shared agents' daemons enforce the grant and
/// always get v1, as does any other recipient or a names-less grant.
#[test]
fn capability_gating_chooses_the_envelope() {
    let f = Fixture::new(4);
    let v2 = choose_grant_envelope(&f.grant, &f.grantee, true, true, Some(&f.signed));
    assert_eq!(v2, GrantEnvelope::V2(f.signed.clone()));
    assert_eq!(
        choose_grant_envelope(&f.grant, &f.shared, true, true, Some(&f.signed)),
        GrantEnvelope::V1,
        "a shared agent's daemon always gets v1"
    );
    assert_eq!(
        choose_grant_envelope(&f.grant, &f.grantee, false, true, Some(&f.signed)),
        GrantEnvelope::V1,
        "a recipient not proven to be the grantee gets v1"
    );
    assert_eq!(
        choose_grant_envelope(&f.grant, &f.grantee, true, true, None),
        GrantEnvelope::V1,
        "no names (or --no-names) sends v1"
    );
}

/// WHY (ADR-0079 §1 Receiver): the grant is stored byte-identical to v1, so
/// a v1 and a v2 copy of one grant are one idempotent `Duplicate` in either
/// order — never a `Conflict`, never two entries.
#[tokio::test]
async fn v1_and_v2_copies_of_one_grant_are_a_duplicate() {
    let f = Fixture::new(5);
    let v1 = f.grant.to_dm_payload().unwrap();
    for (first, second) in [(v1.clone(), f.v2_payload()), (f.v2_payload(), v1.clone())] {
        let store = f.grantee_store();
        let a = receive_share_grant_payload(Some(&store), None, &first)
            .await
            .unwrap();
        assert_eq!(a.outcome, DmTypedPayloadCompletion::Inserted);
        let b = receive_share_grant_payload(Some(&store), None, &second)
            .await
            .unwrap();
        assert_eq!(b.outcome, DmTypedPayloadCompletion::Duplicate);
        let held = store.grants(GrantRole::Received);
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].to_dm_payload().unwrap(),
            v1,
            "stored byte-identical to v1"
        );
        let names_seen = a.names.is_some() || b.names.is_some();
        assert!(names_seen, "the v2 copy surfaces its verified names");
        assert_eq!(a.role, Some(GrantRole::Received));
    }
}

/// WHY (ADR-0079 §1 bounds): 1–128-byte trimmed names without control
/// characters, at most 64 sorted unique machines, and a 48 KiB decode bound
/// for this prefix only — the worst legal envelope fits, and anything past
/// the bounds or non-canonical is refused.
#[test]
fn decode_bounds_hold() {
    let f = Fixture::new(6);
    assert!(validate_grant_name_ok(&"a".repeat(128)));
    assert!(!validate_grant_name_ok(&"a".repeat(129)), "129 bytes");
    assert!(!validate_grant_name_ok(""), "empty");
    assert!(!validate_grant_name_ok(" padded"), "untrimmed");
    assert!(!validate_grant_name_ok("bad\u{7}name"), "control character");

    let too_many = GrantNames {
        owner_name: None,
        machines: (0..=64u8)
            .map(|i| GrantMachineName {
                machine_id: machine(i),
                machine_name: "m".into(),
            })
            .collect(),
    };
    assert!(too_many.validate().is_err(), "65 machine entries");
    assert!(SignedGrantNames::sign(&f.owner, &f.grant, too_many).is_err());
    let unsorted = names_with("Bob", &[(2, "b"), (1, "a")]);
    assert!(unsorted.validate().is_err(), "unsorted machine ids");
    let dup = names_with("Bob", &[(1, "a"), (1, "b")]);
    assert!(dup.validate().is_err(), "duplicate machine ids");

    // Worst legal envelope: 64 agents, 64 machines × 128-byte names and a
    // 128-byte owner name must decode under the 48 KiB bound.
    let owner = UserKeypair::generate().unwrap();
    let now = real_now();
    let agents: Vec<AgentId> = (0..64u8).map(|i| AgentId([i; 32])).collect();
    let big = ShareGrant::sign(
        &owner,
        [7; 32],
        Grantee::User(UserId([0xEE; 32])),
        agents,
        vec![
            ShareCap::Dm,
            ShareCap::Connect {
                ports: (1..=64).collect(),
            },
        ],
        now - 60,
        now + 60,
    )
    .unwrap();
    let worst = GrantNames {
        owner_name: Some("o".repeat(128)),
        machines: (0..64u8)
            .map(|i| GrantMachineName {
                machine_id: machine(i),
                machine_name: "n".repeat(128),
            })
            .collect(),
    };
    let signed = SignedGrantNames::sign(&owner, &big, worst).unwrap();
    let payload = ShareGrantEnvelopeV2::new(&big, &signed)
        .to_dm_payload()
        .unwrap();
    let body_len = payload.len() - SHARE_GRANT_V2_DM_PREFIX.len();
    assert!(body_len <= MAX_SHARE_GRANT_V2_BYTES, "worst case fits");
    assert!(
        body_len <= crate::dm::MAX_PAYLOAD_BYTES,
        "and fits one DM payload"
    );
    decode_grant_delivery(&payload).expect("the worst legal envelope decodes");

    // Over the 48 KiB bound: refused before decoding.
    let mut oversized = SHARE_GRANT_V2_DM_PREFIX.to_vec();
    oversized.extend(vec![0u8; MAX_SHARE_GRANT_V2_BYTES + 1]);
    assert!(matches!(
        ShareGrantEnvelopeV2::from_dm_payload(&oversized),
        Err(ShareGrantError::Malformed(ref m)) if m == "oversized"
    ));
    // Trailing bytes: not canonical.
    let mut trailing = f.v2_payload();
    trailing.push(0);
    assert!(ShareGrantEnvelopeV2::from_dm_payload(&trailing).is_err());
    // The v1 bound is unchanged.
    let mut v1_big = SHARE_GRANT_DM_PREFIX.to_vec();
    v1_big.extend(vec![0u8; MAX_SHARE_GRANT_BYTES + 1]);
    assert!(matches!(
        ShareGrant::from_dm_payload(&v1_big),
        Err(ShareGrantError::Malformed(ref m)) if m == "oversized"
    ));
}

fn validate_grant_name_ok(name: &str) -> bool {
    super::super::names::validate_grant_name("name", name).is_ok()
}

/// WHY (ADR-0079 §1 "Who gets v2", ADR-0077): each recipient is sent exactly
/// its envelope's bytes, and a failed delivery is queued WITH its envelope
/// so the outbox resends the identical bytes and logical request id — across
/// a restart too. A legacy `X0GO` outbox still loads, as v1 deliveries.
#[tokio::test]
async fn outbox_resends_identical_bytes_for_each_envelope() {
    let f = Fixture::new(8);
    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join(super::super::outbox::SHARE_GRANT_OUTBOX_FILE);
    let now = real_now();
    let revocations = RwLock::new(RevocationSet::new());
    let outbox = GrantRedeliveryOutbox::load(path.clone(), Some(f.owner.user_id()), now).await;

    let sent: Sent = Mutex::new(Vec::new());
    let offline = |to: AgentId, payload: Vec<u8>, id: [u8; 16]| {
        sent.lock().unwrap().push((to, payload, id));
        async { Err::<(), String>("offline".into()) }
    };
    let recipients = vec![
        (f.shared, GrantEnvelope::V1),
        (f.grantee, GrantEnvelope::V2(f.signed.clone())),
    ];
    let report = deliver_grant_envelopes_via(
        &f.grant,
        &recipients,
        Some(&outbox),
        &revocations,
        || now,
        offline,
    )
    .await;
    assert!(report.iter().all(|d| d.queued), "{report:?}");
    assert_eq!(report[0].envelope, "v1");
    assert_eq!(report[1].envelope, "v2");
    let first: Vec<_> = sent.lock().unwrap().drain(..).collect();
    let (v1_payload, v1_id) = grant_delivery_request(&f.grant).unwrap();
    let (v2_payload, v2_id) =
        envelope_delivery_request(&f.grant, &GrantEnvelope::V2(f.signed.clone())).unwrap();
    assert_eq!(first[0], (f.shared, v1_payload.clone(), v1_id));
    assert_eq!(first[1], (f.grantee, v2_payload.clone(), v2_id));
    assert!(v2_payload.starts_with(SHARE_GRANT_V2_DM_PREFIX));

    let expect_resend = |sent: &Sent| {
        let mut got: Vec<_> = sent.lock().unwrap().drain(..).collect();
        got.sort_by_key(|(to, _, _)| to.0);
        let mut want = vec![
            (f.shared, v1_payload.clone(), v1_id),
            (f.grantee, v2_payload.clone(), v2_id),
        ];
        want.sort_by_key(|(to, _, _)| to.0);
        assert_eq!(got, want, "retries resend the exact original bytes");
    };
    // Inside the grant's hour and past each retry's backoff.
    let later = now + 60;
    let step = outbox.step(later, &revocations, offline).await;
    assert_eq!(step.failed, 2);
    expect_resend(&sent);

    // Across a restart: the recorded envelope survives on disk.
    drop(outbox);
    assert_eq!(&std::fs::read(&path).unwrap()[..4], b"X0G2");
    let reloaded = GrantRedeliveryOutbox::load(path.clone(), Some(f.owner.user_id()), now).await;
    assert!(reloaded.load_error().is_none());
    let envelopes: Vec<_> = reloaded.pending().into_iter().map(|e| e.envelope).collect();
    assert!(envelopes.contains(&GrantEnvelope::V2(f.signed.clone())));
    let step = reloaded.step(later + 600, &revocations, offline).await;
    assert_eq!(step.failed, 2);
    expect_resend(&sent);

    // A forged names section is never queued.
    let mut forged = f.signed.clone();
    forged.names.owner_name = Some("Mallory".into());
    let other = AgentId([0x99; 32]);
    assert!(matches!(
        reloaded
            .enqueue_envelope(
                &f.grant,
                GrantEnvelope::V2(forged),
                other,
                now,
                &revocations
            )
            .await,
        Err(OutboxError::NotQueueable(_))
    ));

    // A pre-ADR-0079 `X0GO` file (entries without an envelope) loads as v1.
    #[derive(serde::Serialize)]
    struct Legacy {
        recipient: AgentId,
        grant: ShareGrant,
        queued_at: u64,
        deadline: u64,
        next_attempt_at: u64,
        attempts: u32,
    }
    let legacy_path = dir.path().join("legacy.bin");
    let mut bytes = b"X0GO".to_vec();
    bytes.extend(
        bincode::serialize(&vec![Legacy {
            recipient: f.shared,
            grant: f.grant.clone(),
            queued_at: now,
            deadline: f.grant.expiry,
            next_attempt_at: now,
            attempts: 0,
        }])
        .unwrap(),
    );
    std::fs::write(&legacy_path, bytes).unwrap();
    let legacy = GrantRedeliveryOutbox::load(legacy_path, Some(f.owner.user_id()), now).await;
    assert!(legacy.load_error().is_none(), "{:?}", legacy.load_error());
    let pending = legacy.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelope, GrantEnvelope::V1);
}

/// WHY (ADR-0079 §2 contact gate): a stranger can grant anyone, so only a
/// Known/Trusted contact certified by the owner lets defaults apply
/// directly; an Unknown contact does not, and a Blocked one vetoes.
#[test]
fn contact_gate_needs_a_known_or_trusted_certified_contact() {
    use crate::contacts::TrustLevel;
    use crate::identity::AgentCertificate;
    let owner = UserKeypair::generate().unwrap();
    let kp = AgentKeypair::generate().unwrap();
    let cert = AgentCertificate::issue(&owner, &kp).unwrap();
    let now = real_now();
    let seen = |trust, certificate: Option<AgentCertificate>| names::ContactObservation {
        agent: kp.agent_id(),
        trust,
        certificate,
        revoked: false,
    };
    let gate = |contacts: &[names::ContactObservation]| {
        names::owner_contact_gate(&owner.user_id(), contacts, now)
    };
    assert!(gate(&[seen(TrustLevel::Known, Some(cert.clone()))]));
    assert!(gate(&[seen(TrustLevel::Trusted, Some(cert.clone()))]));
    assert!(!gate(&[]), "no contact: stranger");
    assert!(!gate(&[seen(TrustLevel::Unknown, Some(cert.clone()))]));
    assert!(
        !gate(&[seen(TrustLevel::Trusted, None)]),
        "a contact not certified by the owner vouches for nothing"
    );
    let other = UserKeypair::generate().unwrap();
    assert!(
        !names::owner_contact_gate(
            &other.user_id(),
            &[seen(TrustLevel::Trusted, Some(cert.clone()))],
            now
        ),
        "a certificate for another owner does not count"
    );
    let mut revoked = seen(TrustLevel::Trusted, Some(cert.clone()));
    revoked.revoked = true;
    assert!(!gate(&[revoked]), "a revoked agent vouches for nothing");
    let blocked_kp = AgentKeypair::generate().unwrap();
    let blocked = names::ContactObservation {
        agent: blocked_kp.agent_id(),
        trust: TrustLevel::Blocked,
        certificate: Some(AgentCertificate::issue(&owner, &blocked_kp).unwrap()),
        revoked: false,
    };
    assert!(
        !gate(&[seen(TrustLevel::Trusted, Some(cert)), blocked]),
        "a blocked agent of the owner vetoes"
    );
}

/// WHY (ADR-0079 §1): the owner lists a machine only if it is enrolled AND
/// hosts a shared agent; bad names are dropped, not sent.
#[test]
fn owner_side_names_list_only_enrolled_hosting_machines() {
    let enrolled: BTreeSet<[u8; 32]> = [[1; 32], [2; 32], [3; 32]].into();
    let hosting: BTreeSet<[u8; 32]> = [[2; 32], [3; 32], [4; 32]].into();
    let named = vec![
        (machine(3), " Studio ".to_string()),
        (machine(1), "Not hosting".to_string()),
        (machine(4), "Not enrolled".to_string()),
        (machine(2), "bad\u{0}name".to_string()),
    ];
    let names = build_grant_names(Some("  Bob Smith "), &named, &enrolled, &hosting).unwrap();
    assert_eq!(names.owner_name.as_deref(), Some("Bob Smith"), "trimmed");
    assert_eq!(
        names.machines,
        vec![GrantMachineName {
            machine_id: machine(3),
            machine_name: "Studio".into()
        }]
    );
    names.validate().unwrap();
    assert!(
        build_grant_names(None, &[], &enrolled, &hosting).is_none(),
        "nothing to send: v1"
    );
}

/// WHY (ADR-0079 capability): the `share_grant_names` bit counts only when
/// a fresh signed extension is machine-bound to a live base advert; a digest
/// decoder must drop the names record (and vice versa) before verifying.
#[test]
fn share_grant_names_capability_is_machine_bound() {
    use crate::dm_capability::{CapabilityStore, DigestSupportExtension, ShareGrantNamesExtension};
    let store = CapabilityStore::new();
    let agent = AgentKeypair::generate().unwrap().agent_id();
    let now_ms = crate::dm_capability::now_unix_ms();
    let caps = crate::dm::DmCapabilities::v1_gossip_ready(vec![0u8; 1184]);
    assert!(!store.supports_share_grant_names(&agent), "nothing cached");
    assert!(store.apply_share_grant_names_extension(agent, machine(1), true, now_ms));
    assert!(
        !store.supports_share_grant_names(&agent),
        "no live base advert yet"
    );
    assert!(store.insert(agent, machine(2), caps.clone(), now_ms));
    assert!(
        !store.supports_share_grant_names(&agent),
        "extension from another machine"
    );
    assert!(store.apply_share_grant_names_extension(agent, machine(2), true, now_ms + 1));
    assert!(store.supports_share_grant_names(&agent));
    assert!(
        !store.apply_share_grant_names_extension(agent, machine(2), true, now_ms),
        "a stale replay is ignored"
    );

    let names_ext = ShareGrantNamesExtension {
        protocol_version: crate::dm_capability::SHARE_GRANT_NAMES_EXTENSION_TAG,
        agent_id: agent.0,
        machine_id: [2; 32],
        created_at_unix_ms: now_ms,
        share_grant_names: true,
        signature: vec![1, 2, 3],
    };
    let bytes = postcard::to_stdvec(&names_ext).unwrap();
    if let Ok(as_digest) = DigestSupportExtension::from_postcard(&bytes) {
        assert_ne!(
            as_digest.protocol_version,
            crate::dm_capability::DIGEST_EXTENSION_PROTOCOL_VERSION,
            "a digest decoder drops the names record at its version check"
        );
    }
    assert_ne!(
        crate::dm_capability::SHARE_GRANT_NAMES_EXTENSION_TAG,
        crate::dm_capability::DIGEST_EXTENSION_PROTOCOL_VERSION
    );
}
