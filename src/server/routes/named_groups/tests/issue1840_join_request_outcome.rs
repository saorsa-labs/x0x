//! Issue #1840 (ask 4): a join request that the authority's validation
//! refuses travels back to the requester as a typed DM outcome.
//!
//! Two in-process daemons: the authority `O` and the requester `R`. The
//! tests drive the real listener handler on both sides
//! (`handle_predecessor_relay_typed_payload`). The DM transport between
//! them is the test: the payload `O` hands to its send task is read from
//! the send seam and delivered to `R`'s handler as a verified typed DM.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::pr291_restart_marker_matrix::{
    bound_join_request, build_relay_entry_with_commit, group_topic, install_group_with_policy,
    listener_admission_is_none, local_hex, offer_via_handler, s_state, save_roster,
    signed_request_join_commit, stale_request_entry, unix_ms, RelayEntry, StaleCommit,
};
use super::*;
use crate::dm::CapabilityRegistry;
use crate::dm_inbox::DmTypedPayload;
use crate::groups::join_outcome::{JoinRequestOutcome, JoinRequestRefusalReason};
use crate::identity::{AgentId, MachineId};
use crate::server::handle_predecessor_relay_typed_payload;
use crate::server::routes::named_groups::join_request_outcome::test_seam::sent_by;
use crate::server::routes::named_groups::requester_offer::{
    find_requester_offer, RequesterOfferRefusal,
};

const REQUEST_ID: &str = "req-1840-outcome";

struct Pair {
    owner: Arc<AppState>,
    requester: Arc<AppState>,
    gk: String,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// `O` owns a request-access group with two more members. `R` is a
/// separate daemon with its own agent key.
async fn pair(tag: u32) -> Pair {
    let (owner, owner_dir) = s_state().await;
    let (requester, requester_dir) = s_state().await;
    let gk = format!("{tag:032x}");
    install_group_with_policy(
        &owner,
        &gk,
        2,
        crate::groups::GroupPolicyPreset::PublicRequestSecure,
    )
    .await;
    assert_eq!(
        save_roster(&owner).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    Pair {
        owner,
        requester,
        gk,
        _dirs: (owner_dir, requester_dir),
    }
}

/// `O` holds a current verified advert of `R` with these registry bits.
fn advertise_requester(pair: &Pair, bits: u64) {
    let mut caps = crate::dm::DmCapabilities::v2_durable_gossip_ready(
        pair.requester.agent_kem_keypair.public_bytes.clone(),
    );
    caps.application_registry = CapabilityRegistry { version: 1, bits };
    assert!(pair.owner.agent.capability_store().insert(
        pair.requester.agent.agent_id(),
        pair.requester.agent.machine_id(),
        caps,
        crate::dm_capability::now_unix_ms(),
    ));
}

/// What `create_join_request` leaves on `R`: the group with its own
/// pending request, and the durable offer obligation for `entry`.
async fn requester_holds_offer(pair: &Pair, entry: &RelayEntry) {
    let r_hex = local_hex(&pair.requester);
    let mut stub = pair
        .owner
        .named_groups
        .read()
        .await
        .get(&pair.gk)
        .expect("owner group")
        .clone();
    assert_eq!(stub.stable_group_id(), pair.gk, "fixture: one group id");
    stub.join_requests.insert(
        entry.request_id.clone(),
        bound_join_request(entry, &pair.gk, &r_hex, unix_ms()),
    );
    pair.requester
        .named_groups
        .write()
        .await
        .insert(pair.gk.clone(), stub);
    let now_ms = unix_ms();
    insert_requester_offer_obligation(
        &pair.requester,
        RequesterOfferObligation {
            group_id: pair.gk.clone(),
            request_id: entry.request_id.clone(),
            requester_agent_id: r_hex,
            authority_agent_id: local_hex(&pair.owner),
            envelope_bytes: entry.envelope.clone(),
            digest: entry.digest,
            byte_size: entry.byte_size,
            first_seen_ms: now_ms,
            // Not due: these tests never start a network send.
            next_retry_at_ms: now_ms + 3_600_000,
            retry_count: 0,
            refusal: None,
        },
    )
    .await
    .expect("offer obligation persisted");
}

/// `R` offers `entry` to `O` through `O`'s real listener handler.
async fn offer(pair: &Pair, entry: &RelayEntry) {
    let kp = pair.requester.agent.identity().agent_keypair();
    offer_via_handler(&pair.owner, &local_hex(&pair.owner), entry, kp, unix_ms()).await;
}

/// Deliver one typed DM to `R`'s real listener handler.
async fn deliver_to_requester(pair: &Pair, sender: AgentId, payload: Vec<u8>, verified: bool) {
    let dm = DmTypedPayload {
        sender,
        machine_id: MachineId([0u8; 32]),
        payload,
        verified,
        trust_decision: None,
        received_at_unix_ms: unix_ms(),
        request_id: [0u8; 16],
        completion: None,
    };
    handle_predecessor_relay_typed_payload(&pair.requester, &local_hex(&pair.requester), dm).await;
}

async fn recorded_refusal(pair: &Pair) -> Option<RequesterOfferRefusal> {
    find_requester_offer(&pair.requester, &pair.gk, REQUEST_ID)
        .await
        .expect("the offer obligation is kept")
        .refusal
}

/// `own_join_request` of `GET /groups/:id` on `R` (the real handler).
async fn own_join_request(pair: &Pair) -> serde_json::Value {
    let (status, body) = response_json(
        get_named_group(
            State(Arc::clone(&pair.requester)),
            Path(pair.gk.clone()),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        )
        .await
        .into_response(),
    )
    .await
    .expect("response");
    assert_eq!(status, StatusCode::OK, "{body}");
    body["own_join_request"].clone()
}

/// A refused offer and the one outcome payload `O` sent for it.
async fn refused_offer(pair: &Pair, kind: StaleCommit) -> (RelayEntry, Vec<u8>) {
    advertise_requester(pair, CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1);
    let kp = pair.requester.agent.identity().agent_keypair();
    let entry = stale_request_entry(&pair.owner, &pair.gk, REQUEST_ID, kp, kind).await;
    requester_holds_offer(pair, &entry).await;
    offer(pair, &entry).await;
    assert!(listener_admission_is_none(&pair.owner).await);
    let sent = sent_by(&pair.owner);
    assert_eq!(
        sent.len(),
        1,
        "{kind:?}: the authority must send one outcome for the refused envelope"
    );
    assert_eq!(sent[0].0, pair.requester.agent.agent_id());
    (entry, sent[0].1.clone())
}

/// The main row. RED before the fix: the authority sends nothing, so the
/// requester has no refused state. GREEN: the requester's request reads
/// `refused` with the reason, and the envelope is not offered again.
#[tokio::test]
async fn issue1840_refused_offer_reaches_requester_as_typed_outcome() {
    for (tag, kind, reason) in [
        (
            0x1840_0401u32,
            StaleCommit::StubRoster,
            JoinRequestRefusalReason::StateMismatch,
        ),
        (
            0x1840_0402u32,
            StaleCommit::AuthorityMovedOn,
            JoinRequestRefusalReason::StaleHead,
        ),
    ] {
        let pair = pair(tag).await;
        let (entry, payload) = refused_offer(&pair, kind).await;
        let outcome = JoinRequestOutcome::decode(&payload).expect("outcome payload");
        assert_eq!(
            outcome,
            JoinRequestOutcome {
                group_id: pair.gk.clone(),
                request_id: REQUEST_ID.to_string(),
                envelope_digest: hex::encode(entry.digest),
                reason,
            },
            "{kind:?}"
        );

        assert_eq!(own_join_request(&pair).await["status"], "pending");
        deliver_to_requester(&pair, pair.owner.agent.agent_id(), payload.clone(), true).await;

        let refusal = recorded_refusal(&pair).await.expect("refusal recorded");
        assert_eq!(refusal.reason, reason.as_str(), "{kind:?}");
        assert!(refusal.retryable, "{kind:?}: a stale-class refusal");
        let shown = own_join_request(&pair).await;
        assert_eq!(shown["request_id"], REQUEST_ID);
        assert_eq!(shown["status"], "refused", "{kind:?}: {shown}");
        assert_eq!(shown["refusal"]["reason"], reason.as_str());
        assert_eq!(shown["refusal"]["retryable"], true);

        // No further offer of this envelope: make it due and run the
        // worker. The obligation is kept, unsent and unchanged.
        {
            let mut outbox = pair.requester.requester_offer_outbox.write().await;
            outbox.get_mut(&pair.gk).expect("group")[0].next_retry_at_ms = 0;
        }
        requester_offer_step(&pair.requester).await;
        let kept = find_requester_offer(&pair.requester, &pair.gk, REQUEST_ID)
            .await
            .expect("a refused obligation stays while the request is pending");
        assert_eq!(kept.retry_count, 0, "{kind:?}: no offer attempt");
        assert_eq!(kept.refusal, Some(refusal.clone()));
        // The record is durable: a restart of the outbox loads it.
        pair.requester.requester_offer_outbox.write().await.clear();
        load_requester_offer_outbox(&pair.requester)
            .await
            .expect("outbox loads");
        assert_eq!(recorded_refusal(&pair).await, Some(refusal.clone()));

        // A replay of the outcome changes nothing.
        deliver_to_requester(&pair, pair.owner.agent.agent_id(), payload, true).await;
        assert_eq!(recorded_refusal(&pair).await, Some(refusal));

        // Bounded: a re-offer of the same envelope is refused again, and
        // the authority sends no second outcome inside the interval.
        offer(&pair, &entry).await;
        assert!(listener_admission_is_none(&pair.owner).await);
        assert_eq!(sent_by(&pair.owner).len(), 1, "{kind:?}: one per digest");
    }
}

/// A forged or replayed outcome cannot refuse a request. Each variant is
/// ignored; the genuine outcome is then accepted, so the fixture is valid.
#[tokio::test]
async fn issue1840_forged_outcome_is_ignored() {
    let pair = pair(0x1840_0403).await;
    let (entry, payload) = refused_offer(&pair, StaleCommit::StubRoster).await;
    let owner_id = pair.owner.agent.agent_id();
    let genuine = JoinRequestOutcome::decode(&payload).expect("outcome payload");
    let encode = |edit: &dyn Fn(&mut JoinRequestOutcome)| {
        let mut forged = genuine.clone();
        edit(&mut forged);
        forged.encode().expect("encode")
    };
    let third_party = AgentId([0x77; 32]);
    let other_admin = AgentId({
        let mut id = [0u8; 32];
        hex::decode_to_slice(format!("{:064x}", 0x2001u64), &mut id).expect("member id");
        id
    });
    let variants: Vec<(&str, AgentId, Vec<u8>, bool)> = vec![
        ("wrong sender", third_party, payload.clone(), true),
        (
            "another member as sender",
            other_admin,
            payload.clone(),
            true,
        ),
        (
            "requester as sender",
            pair.requester.agent.agent_id(),
            payload.clone(),
            true,
        ),
        ("unverified DM", owner_id, payload.clone(), false),
        (
            "wrong request id",
            owner_id,
            encode(&|o| o.request_id = "req-1840-other".to_string()),
            true,
        ),
        (
            "wrong digest",
            owner_id,
            encode(&|o| o.envelope_digest = hex::encode([0x5a; 32])),
            true,
        ),
        (
            "wrong group",
            owner_id,
            encode(&|o| o.group_id = format!("{:032x}", 0x1840_04ffu32)),
            true,
        ),
        (
            "not an outcome body",
            owner_id,
            [
                crate::groups::join_outcome::JOIN_REQUEST_OUTCOME_DM_PREFIX,
                b"{}".as_slice(),
            ]
            .concat(),
            true,
        ),
    ];
    for (name, sender, forged, verified) in variants {
        deliver_to_requester(&pair, sender, forged, verified).await;
        assert_eq!(recorded_refusal(&pair).await, None, "{name}");
        assert_eq!(own_join_request(&pair).await["status"], "pending", "{name}");
    }

    // Control for the "no further offer" check of the main row: the worker
    // DOES attempt a due obligation that has no refusal.
    {
        let mut outbox = pair.requester.requester_offer_outbox.write().await;
        outbox.get_mut(&pair.gk).expect("group")[0].next_retry_at_ms = 0;
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        requester_offer_step(&pair.requester),
    )
    .await
    .expect("the offer pass ends");
    let attempted = find_requester_offer(&pair.requester, &pair.gk, REQUEST_ID)
        .await
        .expect("an unacknowledged offer stays");
    assert_eq!(attempted.retry_count, 1, "an unrefused offer is attempted");

    // An outcome for an envelope this daemon no longer offers (the request
    // was re-sealed: same request id, new digest) is ignored too.
    {
        let mut outbox = pair.requester.requester_offer_outbox.write().await;
        outbox.get_mut(&pair.gk).expect("group")[0].digest = [0x11; 32];
    }
    deliver_to_requester(&pair, owner_id, payload.clone(), true).await;
    assert_eq!(recorded_refusal(&pair).await, None, "stale digest");
    {
        let mut outbox = pair.requester.requester_offer_outbox.write().await;
        outbox.get_mut(&pair.gk).expect("group")[0].digest = entry.digest;
    }

    deliver_to_requester(&pair, owner_id, payload, true).await;
    assert_eq!(
        recorded_refusal(&pair).await.map(|r| r.reason),
        Some("state_mismatch".to_string()),
        "the genuine outcome is accepted"
    );
}

/// A durability failure is not a validation refusal: the journal marker
/// stays (as in #1842) and no outcome is sent, so the requester re-offers.
#[tokio::test]
async fn issue1840_durability_failure_sends_no_outcome() {
    let pair = pair(0x1840_0404).await;
    advertise_requester(&pair, CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1);
    let kp = pair.requester.agent.identity().agent_keypair();
    let topic = group_topic(&pair.owner, &pair.gk).await;
    let commit = {
        let groups = pair.owner.named_groups.read().await;
        signed_request_join_commit(groups.get(&pair.gk).expect("group"), kp)
    };
    let entry = build_relay_entry_with_commit(
        kp,
        &topic,
        &pair.gk,
        REQUEST_ID,
        &local_hex(&pair.requester),
        0,
        commit,
    );
    // The roster replacement fails: a non-empty directory is at its path.
    let roster = &pair.owner.named_groups_path;
    tokio::fs::remove_file(roster).await.expect("remove roster");
    tokio::fs::create_dir(roster).await.expect("block roster");
    tokio::fs::write(roster.join("blocker"), b"x")
        .await
        .expect("blocker file");

    offer(&pair, &entry).await;

    assert!(
        !listener_admission_is_none(&pair.owner).await,
        "fixture: the durability failure keeps the journal marker"
    );
    assert!(
        sent_by(&pair.owner).is_empty(),
        "a durability failure must not be reported as a refusal"
    );
}

/// Mixed version. A requester with no verified advert, or with an advert
/// that lacks `join_request_outcome_v1`, gets no outcome DM. The #1842
/// journal release is unchanged.
#[tokio::test]
async fn issue1840_no_outcome_without_the_capability_bit() {
    for (tag, advert) in [(0x1840_0405u32, None), (0x1840_0406u32, Some(0u64))] {
        let pair = pair(tag).await;
        if let Some(bits) = advert {
            advertise_requester(&pair, CapabilityRegistry::current().bits | bits);
        }
        let kp = pair.requester.agent.identity().agent_keypair();
        let entry = stale_request_entry(
            &pair.owner,
            &pair.gk,
            REQUEST_ID,
            kp,
            StaleCommit::StubRoster,
        )
        .await;
        offer(&pair, &entry).await;
        assert!(listener_admission_is_none(&pair.owner).await, "{advert:?}");
        assert!(sent_by(&pair.owner).is_empty(), "{advert:?}");
    }
    // The bit is route-gated: advertised only with the typed route.
    let bit = CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1;
    assert!(!CapabilityRegistry::current().supports(bit));
    assert!(CapabilityRegistry::advertised([
        crate::groups::join_outcome::JOIN_REQUEST_OUTCOME_DM_PREFIX
    ])
    .supports(bit));
}
