//! #1664: an answer that an authenticated request earned goes to the
//! MACHINE that asked — the DM's QUIC-authenticated sender — never to
//! "whichever device currently resolves for the agent", which a revoked
//! device that still holds the portable agent key can occupy (discovery
//! cache, capability binding, newest connection). The catch-up page and
//! the control-blob chunk now ride the machine-addressed raw-QUIC reply
//! lane (the #1657 refusal lane's delivery shape for data), the JoinResult
//! chunk exchange pins the same machine, and a machine- or
//! binding-revoked control-blob fetcher gets NO answer — the blob is
//! withheld and no frame is sent: bit 13 (`treekem_catchup_refusal_v1`)
//! stays TreeKEM catch-up only, as on main since #1714, unreleased
//! (Engineer ruling, 31 Oct 2026 03:40 GMT). The seat-cert lane rides the gossip topic,
//! which carries no authenticated requester machine: its ladder is the
//! envelope's agent only — a binding-based refusal there would be a
//! revoked device's denial-of-service lever over the clean device of the
//! same agent (review round 1). Every addressing decision is recorded at
//! the send seam (`machine_reply_egress`), so a test cannot pass on an
//! answer that never left or went to the wrong device.

use super::*;
use x0x::identity::AgentKeypair;

/// Every machine-addressed data reply this node decided on, with its
/// destination — the egress observation point of the reply lane.
fn machine_reply_egress(state: &AppState) -> Vec<(MachineId, Vec<u8>)> {
    state
        .agent
        .machine_reply_egress
        .lock()
        .expect("machine reply egress recorder")
        .clone()
}

/// Every typed refusal the serve decided on, decoded (the #1657 catch-up
/// decision recorder; the control-blob test observes it EMPTY — bit 13
/// never answers a control-blob fetch).
fn recorded_refusals(state: &AppState) -> Vec<TreeKemCatchupRefusal> {
    state
        .named_group_test_recorders
        .catchup_refusals
        .lock()
        .expect("refusal recorder")
        .iter()
        .map(|payload| serde_json::from_slice(payload).expect("recorded refusal decodes"))
        .collect()
}

/// Advertise bit 13 for `(agent, machine)` as a verified capability
/// advert, exactly as the gossip advert service would ingest it (the
/// gate every refusal send checks). The signed timestamp is bumped per
/// call so a later advert for the same agent always supersedes.
fn advertise_refusal_bit(state: &AppState, agent: &AgentId, machine: &MachineId) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_BUMP: AtomicU64 = AtomicU64::new(0);
    let mut caps = x0x::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
    caps.application_registry = x0x::dm::CapabilityRegistry {
        version: 1,
        bits: x0x::dm::CapabilityRegistry::TREEKEM_CATCHUP_REFUSAL_V1,
    };
    let bump = NEXT_BUMP.fetch_add(1, Ordering::Relaxed);
    assert!(
        state.agent.capability_store.insert(
            *agent,
            *machine,
            caps,
            x0x::dm_capability::now_unix_ms() + bump
        ),
        "the verified advert inserts"
    );
}

/// Insert a verified self-revocation of `device`'s machine (the #1616
/// fabric). D70: this denies the machine only.
async fn revoke_machine(state: &AppState, device: &x0x::identity::MachineKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Machine(device.machine_id()),
        device.public_key(),
        device.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign machine revocation");
    let revocation_set = state.agent.revocation_set();
    let mut set = revocation_set.write().await;
    assert!(set
        .verify_and_insert(record, None)
        .expect("machine self-revocation verifies"));
    assert!(set.is_machine_revoked(&device.machine_id()));
    assert!(!set.revocation_resync_required());
}

/// Insert a verified self-revocation of `subject`'s agent (the #1577
/// fabric).
async fn revoke_agent(state: &AppState, subject: &AgentKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(subject.agent_id()),
        subject.public_key(),
        subject.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign revocation");
    let revocation_set = state.agent.revocation_set();
    assert!(revocation_set
        .write()
        .await
        .verify_and_insert(record, None)
        .expect("self-revocation verifies"));
}

/// Retire the `(agent, machine)` pairing with an owner-signed ADR-0043
/// tombstone (the #1622 fabric). D70: this kills the pairing only.
async fn retire_binding(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    agent: &AgentKeypair,
    machine: &x0x::identity::MachineId,
) {
    let cert =
        x0x::identity::AgentCertificate::issue(owner, agent).expect("owner certificate for agent");
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::AgentMachineBinding(
            x0x::revocation::AgentMachineBinding {
                agent: agent.agent_id(),
                machine: *machine,
                move_epoch: 1,
            },
        ),
        owner.public_key(),
        owner.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign binding revocation");
    let revocation_set = state.agent.revocation_set();
    let mut set = revocation_set.write().await;
    assert!(set
        .verify_and_insert(record, Some(&cert))
        .expect("binding revocation verifies"));
    assert!(set.is_binding_revoked(&agent.agent_id(), machine));
    assert!(!set.revocation_resync_required());
}

/// Seat `members` as Active members of a fresh group owned by the local
/// admin, as the #1577 test fabric does.
async fn seat_members(state: &AppState, group_id: &str, members: &[&AgentKeypair]) {
    let admin = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::new(
        "issue1664".to_string(),
        String::new(),
        admin,
        group_id.to_string(),
    );
    for member in members {
        info.add_member(
            hex::encode(member.agent_id().as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
    }
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
}

fn catchup_request(group_id: &str, requester: &AgentId) -> TreeKemCatchupRequest {
    TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.to_string(),
        requester_agent_id: hex::encode(requester.as_bytes()),
        from_revision: 0,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
    }
}

fn recorded_pages(state: &AppState) -> usize {
    state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len()
}

/// The catch-up handler: a page a clean device asked for is addressed to
/// THAT machine at the send seam, and a machine-revoked device that asks
/// for the same group gets the #1657 typed refusal and no page — so the
/// page meant for the clean device is never handed to the revoked device
/// by an agent-level resolution.
#[tokio::test]
async fn a_catchup_page_goes_to_the_requesting_machine_and_a_revoked_asker_gets_nothing(
) -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "64".repeat(32);
    let active = AgentKeypair::generate()?;
    let device_agent = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&active, &device_agent]).await;

    // The clean device asks; the page decision is recorded AND the reply
    // lane addressed it to the asking machine.
    handle_treekem_catchup_request(
        &state,
        &active.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &active.agent_id()),
    )
    .await;
    assert_eq!(recorded_pages(&state), 1, "the clean asker is served");
    let egress = machine_reply_egress(&state);
    assert_eq!(egress.len(), 1, "exactly one machine-addressed reply left");
    assert_eq!(
        egress[0].0,
        clean_sender_machine(),
        "the page is addressed to the machine that asked"
    );
    let page: TreeKemCatchupResponse =
        serde_json::from_slice(&egress[0].1).expect("the egress payload is a catch-up page");
    assert_eq!(page.group_id, group_id);

    // A device is revoked but keeps the portable agent key of ANOTHER
    // member; it is the machine the next block's newest advert names.
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;

    // Review round 1, the attack itself: the revoked device holds the
    // agent key, so it can publish the NEWEST advert for the clean asker's
    // agent, naming ITSELF — every agent-level resolution (discovery
    // cache, capability binding, newest connection) then points at the
    // revoked device. The clean machine asks again and its page is STILL
    // addressed to the clean machine: the reply lane ignores the binding.
    advertise_refusal_bit(&state, &active.agent_id(), &device.machine_id());
    handle_treekem_catchup_request(
        &state,
        &active.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &active.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        2,
        "the clean asker is served even while a revoked device holds its agent's newest advert"
    );
    let egress = machine_reply_egress(&state);
    assert_eq!(egress.len(), 2, "exactly one more machine-addressed reply");
    assert_eq!(
        egress[1].0,
        clean_sender_machine(),
        "the page still goes to the machine that asked, never to the revoked device the newest advert names"
    );

    // The revoked device asks in its own name: the #1657 refusal answers
    // it and no further page egress exists — the revoked machine never
    // receives an answer it can read.
    advertise_refusal_bit(&state, &device_agent.agent_id(), &device.machine_id());
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        2,
        "a machine-revoked asker gets no further page"
    );
    assert_eq!(
        machine_reply_egress(&state).len(),
        2,
        "no data reply is addressed to the revoked machine"
    );
    let refusals = recorded_refusals(&state);
    assert_eq!(
        refusals.len(),
        1,
        "the revoked asker gets the typed refusal"
    );
    assert_eq!(
        refusals[0].reason,
        TreeKemCatchupRefusalReason::MachineRevoked
    );
    assert_eq!(refusals[0].group_id(), group_id);
    // The refusal's DESTINATION: the machine-addressed refusal lane carries
    // it to the revoked device that asked (the send-seam recorder, after
    // every gate).
    let refusal_egress = state
        .agent
        .treekem_refusal_replies
        .egress
        .lock()
        .expect("refusal egress recorder")
        .clone();
    assert!(
        refusal_egress
            .iter()
            .any(|(machine, _)| *machine == device.machine_id()),
        "the refusal is addressed to the revoked device's machine"
    );
    Ok(())
}

/// Review round 2, finding 1: a revocation that lands BETWEEN the
/// handler's ladder decision and the send still closes the send. The
/// serve's test seam parks the page send after the decision; the machine
/// is revoked while parked; the released send egresses nothing.
#[tokio::test]
async fn a_revocation_landing_during_a_parked_page_serve_still_closes_the_send() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "69".repeat(32);
    let member = AgentKeypair::generate()?;
    let device = x0x::identity::MachineKeypair::generate()?;
    seat_members(&state, &group_id, &[&member]).await;

    let sender_hex = hex::encode(member.agent_id().as_bytes());
    let pause = detached_send_test_seam::arm(&format!("treekem-catchup-serve:{sender_hex}"));
    let parked_state = Arc::clone(&state);
    let parked_member = member.agent_id();
    let parked_device = device.machine_id();
    let serve = tokio::spawn(async move {
        handle_treekem_catchup_request(
            &parked_state,
            &parked_member,
            &parked_device,
            true,
            catchup_request(&group_id, &parked_member),
        )
        .await;
    });
    // The serve reached its send (the ladder passed: the machine was clean
    // when the handler read it) and parked there.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !pause.reached() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the parked serve never reached its send"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The revocation lands mid-serve, then the send is released.
    revoke_machine(&state, &device).await;
    drop(pause);
    serve.await.expect("the parked serve completes");
    assert_eq!(
        recorded_pages(&state),
        1,
        "the page DECISION was recorded before the park (the asker was clean when the ladder read it)"
    );
    assert!(
        !machine_reply_egress(&state)
            .iter()
            .any(|(machine, _)| *machine == device.machine_id()),
        "the released send is closed by the revocation that landed while it was parked: no egress to the now-revoked machine"
    );
    Ok(())
}

/// Stage an oversized named-group-event blob whose recipient is
/// `fetcher_hex` and source is the local daemon, then build the fetcher's
/// `Fetch` frame for chunk 0.
fn staged_fetch(
    state: &AppState,
    group_id: &str,
    fetcher_hex: &str,
) -> Result<control_blob::ControlBlobMessage> {
    let bytes = vec![0xA7u8; x0x::dm::MAX_PAYLOAD_BYTES + 512];
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let reference = control_blob::test_reference(&bytes, group_id, &local_hex, fetcher_hex);
    state
        .control_blobs
        .stage(reference.clone(), bytes)
        .map_err(|e| anyhow::anyhow!("stage: {e}"))?;
    Ok(control_blob::ControlBlobMessage::Fetch {
        reference,
        sequence: 0,
    })
}

/// Poll until `f` returns Some, up to `budget`.
async fn eventually<T>(budget: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Some(value) = f() {
            return Some(value);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The control-blob handler: a fetch from a machine- or binding-revoked
/// device gets NO answer — the blob is withheld and no frame is sent (the
/// bit-13 widening was ruled out 31 Oct 2026 03:40 GMT; the revoked
/// fetchers below DO advertise bit 13, so the test stays red if the frame
/// ever widens back to this lane) — while a clean device's chunk is
/// addressed to ITS machine at the send seam.
#[tokio::test]
async fn control_blob_answers_go_to_the_requesting_machine_and_revoked_fetchers_get_no_frame(
) -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "66".repeat(32);
    let fetcher = AgentKeypair::generate()?;

    // A machine-revoked fetcher: no answer at all — no chunk, and no
    // refusal frame on any lane (the fetcher advertises bit 13, so a
    // re-widening of the catch-up refusal to this lane would show here).
    let fetch = staged_fetch(
        &state,
        &group_id,
        &hex::encode(fetcher.agent_id().as_bytes()),
    )?;
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
    advertise_refusal_bit(&state, &fetcher.agent_id(), &device.machine_id());
    control_blob::handle_control_blob_message(
        &state,
        &fetcher.agent_id(),
        &device.machine_id(),
        true,
        fetch,
    )
    .await;
    assert!(
        machine_reply_egress(&state).is_empty(),
        "no chunk is addressed to the machine-revoked fetcher"
    );
    assert!(
        recorded_refusals(&state).is_empty(),
        "no refusal decision exists for the machine-revoked fetcher: the blob is withheld and no frame is sent"
    );

    // A binding-revoked fetcher (a different fetcher agent, so the first
    // fetch's reference cannot answer for it): the same silent drop.
    let other = AgentKeypair::generate()?;
    let fetch = staged_fetch(&state, &group_id, &hex::encode(other.agent_id().as_bytes()))?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let retired_machine = x0x::identity::MachineKeypair::generate()?.machine_id();
    retire_binding(&state, &owner, &other, &retired_machine).await;
    advertise_refusal_bit(&state, &other.agent_id(), &retired_machine);
    control_blob::handle_control_blob_message(
        &state,
        &other.agent_id(),
        &retired_machine,
        true,
        fetch,
    )
    .await;
    assert!(
        machine_reply_egress(&state).is_empty(),
        "no chunk is addressed to the binding-revoked pairing"
    );
    assert!(
        recorded_refusals(&state).is_empty(),
        "no refusal decision exists for the binding-revoked pairing either"
    );

    // The agent-revoked gate keeps main's silent drop: no chunk.
    let third = AgentKeypair::generate()?;
    let fetch = staged_fetch(&state, &group_id, &hex::encode(third.agent_id().as_bytes()))?;
    revoke_agent(&state, &third).await;
    control_blob::handle_control_blob_message(
        &state,
        &third.agent_id(),
        &clean_sender_machine(),
        true,
        fetch,
    )
    .await;
    assert!(
        machine_reply_egress(&state).is_empty(),
        "the agent-revocation gate keeps the silent drop"
    );
    assert!(recorded_refusals(&state).is_empty());

    // CONTROL: a clean fetcher's chunk is served and addressed to ITS
    // machine. The serve runs on a detached task, so poll the seam.
    let clean = AgentKeypair::generate()?;
    let fetch = staged_fetch(&state, &group_id, &hex::encode(clean.agent_id().as_bytes()))?;
    control_blob::handle_control_blob_message(
        &state,
        &clean.agent_id(),
        &clean_sender_machine(),
        true,
        fetch,
    )
    .await;
    let egress = eventually(Duration::from_secs(5), || {
        (!machine_reply_egress(&state).is_empty()).then(|| machine_reply_egress(&state))
    })
    .await
    .expect("the clean fetcher's chunk egress is decided");
    assert_eq!(egress.len(), 1, "exactly one chunk reply left");
    assert_eq!(
        egress[0].0,
        clean_sender_machine(),
        "the chunk is addressed to the machine that fetched"
    );
    let chunk = crate::wire_compat::decode_json::<control_blob::ControlBlobMessage>(
        "ControlBlobMessage",
        "control_blob_",
        &egress[0].1,
    )
    .expect("the egress payload is a control-blob frame");
    assert!(matches!(
        chunk,
        control_blob::ControlBlobMessage::Chunk { .. }
    ));
    // After the clean serve's polling window, the revoked fetchers still
    // hold no frame: re-check the refusal surfaces so a detached refusal
    // send (the shape the widening used) cannot land after the asserts
    // above and slip through.
    assert!(
        recorded_refusals(&state).is_empty(),
        "no refusal frame was ever decided for a control-blob fetch (bit 13 stays TreeKEM catch-up only)"
    );
    assert!(state
        .agent
        .treekem_refusal_replies
        .egress
        .lock()
        .expect("refusal egress recorder")
        .is_empty());
    Ok(())
}

/// The seat-cert handler: the ask rides the gossip topic, which carries no
/// authenticated requester machine, so the lane's whole revocation ladder
/// is the envelope's agent. An agent-revoked ROSTER MEMBER gets the silent
/// drop (the roster itself would still admit it — a revoked target keeps
/// its Active seat until the S4 eviction commits), while a clean requester
/// is answered exactly as before. Review round 1 also pins that a revoked
/// device holding the portable agent key CANNOT weaponise the lane: a
/// newest advert naming a machine-revoked device changes nothing — the
/// clean requester of the same agent is still answered (a binding-based
/// refusal would be that device's denial-of-service lever over the clean
/// device, and the topic broadcast leaks nothing it protects).
#[tokio::test]
async fn seat_cert_drops_an_agent_revoked_member_and_cannot_be_weaponised_by_adverts() -> Result<()>
{
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let remote = AgentKeypair::generate()?;
    let remote_cert = x0x::identity::AgentCertificate::issue(&owner, &remote)?;
    let remote_hex = hex::encode(remote.agent_id().as_bytes());
    let remote_digest = {
        let bytes = bincode::serialize(&remote_cert).unwrap_or_default();
        hex::encode(blake3::hash(&bytes).as_bytes())
    };
    // The R17 shape: an OwnerCertified group whose roster holds the local
    // admin and the remote member digest-only, with the remote pair
    // cached so the serve can answer.
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut info = x0x::groups::GroupInfo::with_policy(
        "issue1664".to_string(),
        String::new(),
        state.agent.agent_id(),
        format!("issue1664-{remote_hex}"),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
    info.metadata_topic = format!("x0x/group/issue1664-{remote_hex}");
    info.members_v2.clear();
    info.add_member(local_hex.clone(), x0x::groups::GroupRole::Admin, None, None);
    info.add_member(
        remote_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    if let Some(seat) = info.members_v2.get_mut(&remote_hex) {
        seat.certificate = None;
        seat.certificate_digest = Some(remote_digest.clone());
    }
    let group_key = format!("local-{remote_hex}");
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    let pair_digest =
        x0x::announce_v3::cert_digest(&Some(owner.user_id()), &Some(remote_cert.clone()));
    state
        .agent
        .announce_blob_cache
        .insert_verified(x0x::announce_blob::CachedBlob {
            digest: pair_digest,
            payload_version: 1,
            user_id: Some(owner.user_id()),
            agent_certificate: Some(remote_cert.clone()),
            fetched_at_unix: 0,
        })
        .await;
    let request = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchRequest {
        group_id: group_key.clone(),
        cert_digest: remote_digest.clone(),
        requester: remote_hex.clone(),
    })?;

    // Review round 1, the weaponisation attempt, run FIRST so the C5
    // answer slot is free: a revoked device holds the remote agent's key
    // and publishes the NEWEST advert for it, naming the machine-revoked
    // device. The clean requester of that same agent is STILL answered —
    // the lane keeps no binding-based refusal such an advert could turn
    // against the clean device.
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
    advertise_refusal_bit(&state, &remote.agent_id(), &device.machine_id());
    assert!(
        seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&remote.agent_id()),
            true,
            &group_key
        )
        .await,
        "a clean requester is still answered while a revoked device holds its agent's newest advert"
    );

    // Review round 2, finding 3: the agent-revoked drop must be provable
    // on its own — a SECOND group with the same digest-only remote seat
    // (a fresh C5 answer slot) and the revoked member on ITS roster, so
    // with the gate neutered this exact ask would be ANSWERED (roster
    // hit, cache hit, fresh slot). With the gate it gets the silent
    // drop — no answer and no refusal, exactly as the control-blob
    // lane's agent gate.
    let revoked_member = AgentKeypair::generate()?;
    let revoked_member_hex = hex::encode(revoked_member.agent_id().as_bytes());
    let second_key = format!("local2-{revoked_member_hex}");
    {
        let mut second = x0x::groups::GroupInfo::with_policy(
            "issue1664".to_string(),
            String::new(),
            state.agent.agent_id(),
            format!("issue1664-two-{revoked_member_hex}"),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        second.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
        second.metadata_topic = format!("x0x/group/issue1664-two-{revoked_member_hex}");
        second.members_v2.clear();
        second.add_member(local_hex.clone(), x0x::groups::GroupRole::Admin, None, None);
        second.add_member(
            remote_hex.clone(),
            x0x::groups::GroupRole::Admin,
            None,
            None,
        );
        second.add_member(
            revoked_member_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        if let Some(seat) = second.members_v2.get_mut(&remote_hex) {
            seat.certificate = None;
            seat.certificate_digest = Some(remote_digest.clone());
        }
        state
            .named_groups
            .write()
            .await
            .insert(second_key.clone(), second);
    }
    let second_request = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchRequest {
        group_id: second_key.clone(),
        cert_digest: remote_digest.clone(),
        requester: revoked_member_hex.clone(),
    })?;
    revoke_agent(&state, &revoked_member).await;
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &second_request,
            Some(&revoked_member.agent_id()),
            true,
            &second_key
        )
        .await,
        "an agent-revoked roster member gets no answer on a fresh slot it would otherwise be answered on"
    );
    assert!(
        recorded_refusals(&state).is_empty(),
        "the agent-revocation refusal stays a silent drop"
    );
    Ok(())
}

/// Review round 1, finding 2: the machine-pinned JoinResult chunk
/// exchange addresses the chunk to the requesting machine. An admitted
/// exchange egresses to that machine (offline: the in-process stand-in
/// runs both admission phases exactly where the transport runs them), and
/// an admission that withholds records NO egress — a withheld chunk is no
/// answer, wherever it was addressed.
#[tokio::test]
async fn a_join_result_chunk_exchange_targets_the_requesting_machine() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let machine = clean_sender_machine();
    let admitted: x0x::dm::ArtifactAdmission = std::sync::Arc::new(|| {
        Box::pin(async { Some(Box::new(|| true) as x0x::dm::SeamAdmission) })
    });
    let payload = b"join-result-chunk-frame".to_vec();
    let group_id = "68".repeat(32);
    let deadline = Instant::now() + Duration::from_secs(10);
    let outcome = send_join_artifact_to_machine(
        &state,
        &joiner.agent_id(),
        machine,
        &payload,
        &group_id,
        "join_result_chunk",
        admitted,
        deadline,
    )
    .await;
    assert!(
        outcome.is_err(),
        "the offline stand-in reports an admitted exchange through its marker error"
    );
    let egress = machine_reply_egress(&state);
    assert_eq!(egress.len(), 1, "the admitted chunk exchange egressed");
    assert_eq!(
        egress[0].0, machine,
        "the chunk targets the requesting machine, not a binding resolution"
    );
    assert_eq!(egress[0].1, payload);

    // An admission whose pre-phase refuses records no egress at all.
    let withheld: x0x::dm::ArtifactAdmission = std::sync::Arc::new(|| Box::pin(async { None }));
    let outcome = send_join_artifact_to_machine(
        &state,
        &joiner.agent_id(),
        machine,
        &payload,
        &group_id,
        "join_result_chunk",
        withheld,
        deadline,
    )
    .await;
    assert!(
        outcome.is_err(),
        "a withheld admission refuses the exchange"
    );
    assert_eq!(
        machine_reply_egress(&state).len(),
        1,
        "a withheld admission is no egress"
    );
    Ok(())
}
