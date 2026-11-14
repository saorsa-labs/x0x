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
    bound_join_request, build_relay_entry, build_relay_entry_with_commit, group_topic,
    install_group_with_policy, listener_admission_is_none, local_hex, offer_via_handler, s_state,
    save_roster, signed_request_join_commit, stale_request_entry, unix_ms, RelayEntry, StaleCommit,
};
use super::*;
use crate::dm::CapabilityRegistry;
use crate::dm_inbox::DmTypedPayload;
use crate::groups::join_outcome::{JoinRequestOutcome, JoinRequestRefusalReason};
use crate::identity::{AgentId, MachineId};
use crate::server::handle_predecessor_relay_typed_payload;
use crate::server::routes::named_groups::join_request_outcome::test_seam::sent_by;
use crate::server::routes::named_groups::join_request_outcome::{
    OUTCOME_RESEND_MIN_MS, OUTCOME_SEND_MEMORY_CAP, OUTCOME_SEND_PER_REQUESTER_CAP,
};
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
    // A requester's own daemon holds at most its own request.
    stub.join_requests.clear();
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

/// `R` holds the offer of `entry` and offers it; `O` refuses it. Returns
/// the one outcome payload `O` sent for it.
async fn refused_entry(pair: &Pair, entry: &RelayEntry, row: &str) -> Vec<u8> {
    advertise_requester(pair, CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1);
    let before = sent_by(&pair.owner).len();
    requester_holds_offer(pair, entry).await;
    offer(pair, entry).await;
    assert!(listener_admission_is_none(&pair.owner).await, "{row}");
    assert!(
        !pair.owner.named_groups.read().await[&pair.gk]
            .join_requests
            .values()
            .any(|r| r.predecessor_envelope_digest == Some(entry.digest)),
        "{row}: fixture: the authority must refuse this envelope"
    );
    let sent = sent_by(&pair.owner);
    assert_eq!(
        sent.len(),
        before + 1,
        "{row}: the authority must send one outcome for the refused envelope"
    );
    assert_eq!(sent[before].0, pair.requester.agent.agent_id());
    sent[before].1.clone()
}

/// A refused stale offer and the one outcome payload `O` sent for it.
async fn refused_offer(pair: &Pair, kind: StaleCommit) -> (RelayEntry, Vec<u8>) {
    let kp = pair.requester.agent.identity().agent_keypair();
    let entry = stale_request_entry(&pair.owner, &pair.gk, REQUEST_ID, kp, kind).await;
    let payload = refused_entry(pair, &entry, &format!("{kind:?}")).await;
    (entry, payload)
}

/// An offer of `R` with a commit that is valid over `O`'s current state.
async fn current_head_entry(pair: &Pair, request_id: &str) -> RelayEntry {
    let kp = pair.requester.agent.identity().agent_keypair();
    let topic = group_topic(&pair.owner, &pair.gk).await;
    let commit = {
        let groups = pair.owner.named_groups.read().await;
        signed_request_join_commit(groups.get(&pair.gk).expect("group"), kp)
    };
    build_relay_entry_with_commit(
        kp,
        &topic,
        &pair.gk,
        request_id,
        &local_hex(&pair.requester),
        0,
        commit,
    )
}

/// Change `O`'s group in place and re-hash it.
async fn edit_owner_group(pair: &Pair, edit: impl FnOnce(&mut crate::groups::GroupInfo)) {
    let mut groups = pair.owner.named_groups.write().await;
    let group = groups.get_mut(&pair.gk).expect("group");
    edit(group);
    group.recompute_state_hash();
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
            JoinRequestRefusalReason::Stale,
        ),
        (
            0x1840_0402u32,
            StaleCommit::AuthorityMovedOn,
            JoinRequestRefusalReason::Stale,
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
        Some("stale".to_string()),
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
        // Not vacuous: the same kind of offer on the same path does get an
        // outcome when the requester's advert has the bit.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let second = stale_request_entry(
            &pair.owner,
            &pair.gk,
            "req-1840-second",
            kp,
            StaleCommit::StubRoster,
        )
        .await;
        advertise_requester(&pair, CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1);
        offer(&pair, &second).await;
        assert_eq!(sent_by(&pair.owner).len(), 1, "{advert:?}: control");
    }
    // The bit is route-gated: advertised only with the typed route.
    let bit = CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1;
    assert!(!CapabilityRegistry::current().supports(bit));
    assert!(CapabilityRegistry::advertised([
        crate::groups::join_outcome::JOIN_REQUEST_OUTCOME_DM_PREFIX
    ])
    .supports(bit));
}

/// Every wire reason, end to end: the authority's refusal, the outcome,
/// and the state the requester shows. Only `stale` is retryable.
#[tokio::test]
async fn issue1840_each_wire_reason_reaches_the_requester() {
    use JoinRequestRefusalReason as Reason;
    for (tag, row, reason) in [
        (
            0x1840_0410u32,
            "policy is not request access",
            Reason::Stale,
        ),
        (0x1840_0411u32, "already a member", Reason::AlreadyMember),
        (0x1840_0412u32, "banned", Reason::Banned),
        (
            0x1840_0413u32,
            "pending request exists",
            Reason::PendingExists,
        ),
        (0x1840_0414u32, "envelope without a commit", Reason::Invalid),
    ] {
        let pair = pair(tag).await;
        let r_hex = local_hex(&pair.requester);
        let o_hex = local_hex(&pair.owner);
        match reason {
            Reason::Stale => {
                edit_owner_group(&pair, |g| {
                    g.policy = crate::groups::GroupPolicyPreset::PrivateSecure.to_policy();
                })
                .await;
            }
            Reason::AlreadyMember => {
                edit_owner_group(&pair, |g| {
                    g.add_member(
                        r_hex.clone(),
                        crate::groups::GroupRole::Member,
                        Some(o_hex),
                        None,
                    );
                })
                .await;
            }
            Reason::Banned => {
                edit_owner_group(&pair, |g| g.ban_member(&r_hex, Some(o_hex))).await;
            }
            Reason::PendingExists => {
                let earlier = current_head_entry(&pair, "req-1840-earlier").await;
                let request = bound_join_request(&earlier, &pair.gk, &r_hex, unix_ms());
                edit_owner_group(&pair, |g| {
                    g.join_requests.insert(request.request_id.clone(), request);
                })
                .await;
            }
            _ => {}
        }
        let entry = if reason == Reason::Invalid {
            let kp = pair.requester.agent.identity().agent_keypair();
            let topic = group_topic(&pair.owner, &pair.gk).await;
            build_relay_entry(kp, &topic, &pair.gk, REQUEST_ID, &r_hex, 0)
        } else {
            current_head_entry(&pair, REQUEST_ID).await
        };
        let payload = refused_entry(&pair, &entry, row).await;
        let outcome = JoinRequestOutcome::decode(&payload).expect("outcome payload");
        assert_eq!(outcome.reason, reason, "{row}");
        assert_eq!(outcome.envelope_digest, hex::encode(entry.digest), "{row}");

        deliver_to_requester(&pair, pair.owner.agent.agent_id(), payload, true).await;
        let refusal = recorded_refusal(&pair).await.expect("refusal recorded");
        assert_eq!(refusal.reason, reason.as_str(), "{row}");
        assert_eq!(refusal.retryable, reason == Reason::Stale, "{row}");
        let shown = own_join_request(&pair).await;
        assert_eq!(shown["status"], "refused", "{row}: {shown}");
        assert_eq!(shown["refusal"]["reason"], reason.as_str(), "{row}");
        assert_eq!(shown["refusal"]["retryable"], reason == Reason::Stale);
    }
}

/// Disclosure invariant (PR #1850 review r1). An agent that knows only the
/// group id can sign any commit. Its outcomes must not show the
/// authority's revision, chain head, roster or admission policy: every
/// probe below gets the same bytes apart from the request id and digest.
#[tokio::test]
async fn issue1840_owner_state_probes_get_the_same_outcome() {
    let pair = pair(0x1840_0420).await;
    advertise_requester(&pair, CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1);
    edit_owner_group(&pair, |g| g.state_revision = 5).await;
    let kp = pair.requester.agent.identity().agent_keypair();
    let r_hex = local_hex(&pair.requester);
    let topic = group_topic(&pair.owner, &pair.gk).await;
    let head = pair.owner.named_groups.read().await[&pair.gk].clone();
    let wrong_prev = "5a".repeat(32);
    let probe = |revision: u64, prev: &str| {
        crate::groups::GroupStateCommit::sign(
            head.stable_group_id().to_string(),
            revision,
            Some(prev.to_string()),
            crate::groups::state_commit::compute_roster_root(&head.members_v2),
            crate::groups::state_commit::compute_policy_hash(&head.policy),
            crate::groups::state_commit::compute_public_meta_hash(&head.public_meta()),
            head.security_binding.clone(),
            false,
            revision,
            kp,
        )
        .expect("sign probe commit")
    };
    let mut probes = vec![
        ("behind the revision, wrong chain", probe(2, &wrong_prev)),
        ("at the revision, right hash", probe(5, &head.state_hash)),
        ("next revision, wrong chain", probe(6, &wrong_prev)),
        ("far ahead, wrong chain", probe(900, &wrong_prev)),
        ("next revision, right chain, stub roster", {
            let mut stub = head.clone();
            let o_hex = local_hex(&pair.owner);
            stub.members_v2.retain(|id, _| *id == o_hex);
            signed_request_join_commit(&stub, kp)
        }),
    ];
    // The same probe after the group stopped admitting by request.
    let policy_probe = probe(6, &wrong_prev);
    let mut normalised = Vec::new();
    let offer_probe = |name: &'static str, commit, index: usize| {
        let entry = build_relay_entry_with_commit(
            kp,
            &topic,
            &pair.gk,
            &format!("req-1840-probe-{index}"),
            &r_hex,
            0,
            commit,
        );
        (name, entry)
    };
    let entries: Vec<_> = probes
        .drain(..)
        .enumerate()
        .map(|(i, (name, commit))| offer_probe(name, commit, i))
        .collect();
    for (name, entry) in &entries {
        offer(&pair, entry).await;
        assert!(listener_admission_is_none(&pair.owner).await, "{name}");
    }
    edit_owner_group(&pair, |g| {
        g.policy = crate::groups::GroupPolicyPreset::PrivateSecure.to_policy();
    })
    .await;
    let (policy_name, policy_entry) = offer_probe("policy is not request access", policy_probe, 99);
    offer(&pair, &policy_entry).await;

    let sent = sent_by(&pair.owner);
    assert_eq!(sent.len(), entries.len() + 1, "one outcome per probe");
    let names = entries.iter().map(|(name, _)| *name).chain([policy_name]);
    for ((_, payload), name) in sent.iter().zip(names) {
        let mut outcome = JoinRequestOutcome::decode(payload).expect("outcome");
        assert_eq!(outcome.reason, JoinRequestRefusalReason::Stale, "{name}");
        outcome.request_id = String::new();
        outcome.envelope_digest = String::new();
        normalised.push((name, outcome.encode().expect("encode")));
    }
    for (name, bytes) in &normalised {
        assert_eq!(
            bytes, &normalised[0].1,
            "{name}: same bytes as every other probe"
        );
    }

    // The requester's own facts win over the policy check, so the policy
    // is not shown to a banned requester either.
    for policy in [
        crate::groups::GroupPolicyPreset::PrivateSecure,
        crate::groups::GroupPolicyPreset::PublicRequestSecure,
    ] {
        let o_hex = local_hex(&pair.owner);
        edit_owner_group(&pair, |g| {
            g.policy = policy.to_policy();
            g.ban_member(&r_hex, Some(o_hex));
        })
        .await;
        let before = sent_by(&pair.owner).len();
        let (_, entry) = offer_probe("banned", probe(6, &wrong_prev), 200 + before);
        offer(&pair, &entry).await;
        let sent = sent_by(&pair.owner);
        assert_eq!(sent.len(), before + 1);
        let outcome = JoinRequestOutcome::decode(&sent[before].1).expect("outcome");
        assert_eq!(outcome.reason, JoinRequestRefusalReason::Banned);
    }
}

/// The send limits: one outcome per digest per interval, a cap per
/// requester, a total cap, and expiry of the memory after the interval.
#[tokio::test]
async fn issue1840_outcome_send_limits() {
    let pair = pair(0x1840_0430).await;
    advertise_requester(&pair, CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1);
    let requester = pair.requester.agent.agent_id();
    let send = |to: AgentId, digest: [u8; 32]| {
        send_join_request_refusal(
            &pair.owner,
            &pair.gk,
            REQUEST_ID,
            to,
            digest,
            JoinRequestRefusalReason::Stale,
        );
        sent_by(&pair.owner).len()
    };
    assert_eq!(send(requester, [1; 32]), 1);
    assert_eq!(send(requester, [1; 32]), 1, "one per digest per interval");
    for i in 2..=OUTCOME_SEND_PER_REQUESTER_CAP {
        assert_eq!(send(requester, [i as u8; 32]), i);
    }
    assert_eq!(
        send(requester, [0xee; 32]),
        OUTCOME_SEND_PER_REQUESTER_CAP,
        "the per-requester cap stops one agent"
    );

    // Another requester is not affected by the first one's cap.
    let other = AgentId([0x42; 32]);
    let mut caps = crate::dm::DmCapabilities::v2_durable_gossip_ready(
        pair.requester.agent_kem_keypair.public_bytes.clone(),
    );
    caps.application_registry = CapabilityRegistry {
        version: 1,
        bits: CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1,
    };
    assert!(pair.owner.agent.capability_store().insert(
        other,
        MachineId([0x43; 32]),
        caps,
        crate::dm_capability::now_unix_ms(),
    ));
    let count = OUTCOME_SEND_PER_REQUESTER_CAP + 1;
    assert_eq!(send(other, [0xa0; 32]), count);

    // Total cap: with the memory full, no outcome is sent.
    let now_ms = unix_ms();
    {
        let mut sent = pair.owner.join_request_outcome_sends.lock().unwrap();
        for i in 0..OUTCOME_SEND_MEMORY_CAP as u32 {
            let mut key = [0xf0u8; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            let mut agent = [0xf1u8; 32];
            agent[..4].copy_from_slice(&i.to_be_bytes());
            sent.insert(key, (now_ms, AgentId(agent)));
        }
    }
    assert_eq!(send(other, [0xa1; 32]), count, "memory full: no send");

    // After the interval the memory is pruned and the same digest is sent
    // again (a lost outcome is repeated on a later offer).
    {
        let mut sent = pair.owner.join_request_outcome_sends.lock().unwrap();
        for (at, _) in sent.values_mut() {
            *at = now_ms.saturating_sub(OUTCOME_RESEND_MIN_MS + 1);
        }
    }
    assert_eq!(
        send(requester, [1; 32]),
        count + 1,
        "resend after the interval"
    );
    assert_eq!(
        pair.owner.join_request_outcome_sends.lock().unwrap().len(),
        1
    );
}

/// A reason that a later daemon adds. The requester stores it as
/// `unknown`, which is terminal, and does not offer the envelope again.
#[tokio::test]
async fn issue1840_unknown_reason_is_stored_as_terminal() {
    let pair = pair(0x1840_0450).await;
    let (entry, payload) = refused_offer(&pair, StaleCommit::StubRoster).await;
    let body = String::from_utf8(payload).expect("utf-8 outcome");
    assert!(body.contains(r#""reason":"stale""#), "fixture: {body}");
    let later = body
        .replace(r#""reason":"stale""#, r#""reason":"from_the_future""#)
        .into_bytes();
    deliver_to_requester(&pair, pair.owner.agent.agent_id(), later, true).await;

    let refusal = recorded_refusal(&pair).await.expect("refusal recorded");
    assert_eq!(refusal.reason, "unknown");
    assert!(!refusal.retryable);
    let shown = own_join_request(&pair).await;
    assert_eq!(shown["status"], "refused", "{shown}");
    assert_eq!(shown["refusal"]["reason"], "unknown");
    assert_eq!(shown["refusal"]["retryable"], false);
    assert_eq!(
        find_requester_offer(&pair.requester, &pair.gk, REQUEST_ID)
            .await
            .expect("the offer obligation is kept")
            .digest,
        entry.digest
    );
}

/// After a refusal the client cancels the request and files a new one.
/// The refused obligation is dropped and the new request starts clean.
#[tokio::test]
async fn issue1840_cancel_then_new_request_after_refusal() {
    let pair = pair(0x1840_0440).await;
    let (_entry, payload) = refused_offer(&pair, StaleCommit::StubRoster).await;
    deliver_to_requester(&pair, pair.owner.agent.agent_id(), payload, true).await;
    assert_eq!(own_join_request(&pair).await["status"], "refused");

    let owner_actor = crate::server::rider_auth::ActorContext::Owner { durable: true };
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        cancel_join_request(
            State(Arc::clone(&pair.requester)),
            Extension(owner_actor),
            Path((pair.gk.clone(), REQUEST_ID.to_string())),
        ),
    )
    .await
    .expect("cancel ends")
    .into_response();
    assert_eq!(cancelled.status(), StatusCode::OK);
    assert_eq!(own_join_request(&pair).await, serde_json::Value::Null);

    // The worker drops the refused obligation of the cancelled request.
    {
        let mut outbox = pair.requester.requester_offer_outbox.write().await;
        outbox.get_mut(&pair.gk).expect("group")[0].next_retry_at_ms = 0;
    }
    requester_offer_step(&pair.requester).await;
    assert!(find_requester_offer(&pair.requester, &pair.gk, REQUEST_ID)
        .await
        .is_none());

    let created = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        create_join_request(
            State(Arc::clone(&pair.requester)),
            Path(pair.gk.clone()),
            None,
        ),
    )
    .await
    .expect("create ends")
    .into_response();
    let (status, body) = response_json(created).await.expect("response");
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let new_id = body["request_id"].as_str().expect("request id").to_string();
    assert_ne!(new_id, REQUEST_ID);
    let shown = own_join_request(&pair).await;
    assert_eq!(shown["request_id"], new_id.as_str());
    assert_eq!(shown["status"], "pending", "{shown}");
}
