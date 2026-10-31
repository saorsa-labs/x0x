//! #1664: an answer that an authenticated request earned goes to the
//! MACHINE that asked — the DM's QUIC-authenticated sender — never to
//! "whichever device currently resolves for the agent", which a revoked
//! device that still holds the portable agent key can occupy (discovery
//! cache, capability binding, newest connection). The catch-up page and
//! the control-blob chunk now ride the machine-addressed raw-QUIC reply
//! lane (the #1657 refusal lane's delivery shape for data), and the
//! control-blob and seat-cert serves refuse a machine- or
//! binding-revoked requester with the #1657 typed refusal. The seat-cert
//! lane carries no machine identity, so its machine check resolves the
//! requester's own capability binding (ADR-0043 §9 evidence semantics:
//! present fails closed, absent fails open). Every addressing decision
//! is recorded at the send seam (`machine_reply_egress`), so a test
//! cannot pass on an answer that never left or went to the wrong device.

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

/// Every typed refusal the serve decided on, decoded (the #1657 decision
/// recorder, reused by the control-blob and seat-cert refusals).
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

    // The revoked device of the SAME agent key holder asks: the #1657
    // refusal answers it and no second page egress exists — the revoked
    // machine never receives an answer it can read.
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
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
        1,
        "a machine-revoked asker gets no second page"
    );
    assert_eq!(
        machine_reply_egress(&state).len(),
        1,
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

/// Poll until at least `count` refusal decisions are recorded (the
/// control-blob and seat-cert refusal sends run detached, so the decision
/// lands shortly after the handler returns).
async fn await_refusal_count(state: &AppState, count: usize) -> Vec<TreeKemCatchupRefusal> {
    eventually(Duration::from_secs(5), || {
        (recorded_refusals(state).len() >= count).then(|| recorded_refusals(state))
    })
    .await
    .expect("the refusal decision is recorded")
}

/// The control-blob handler: a fetch from a machine- or binding-revoked
/// device is answered with the #1657 typed refusal and no chunk, while a
/// clean device's chunk is addressed to ITS machine at the send seam.
#[tokio::test]
async fn control_blob_answers_go_to_the_requesting_machine_and_revoked_fetchers_are_refused(
) -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "66".repeat(32);
    let fetcher = AgentKeypair::generate()?;

    // A machine-revoked fetcher: the typed refusal names the machine, and
    // no chunk egress exists for it.
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
    let refusals = await_refusal_count(&state, 1).await;
    assert_eq!(refusals.len(), 1, "the machine-revoked fetcher is refused");
    assert_eq!(
        refusals[0].reason,
        TreeKemCatchupRefusalReason::MachineRevoked
    );
    assert_eq!(refusals[0].group_id(), group_id);
    assert!(
        machine_reply_egress(&state).is_empty(),
        "no chunk is addressed to the machine-revoked fetcher"
    );

    // A binding-revoked fetcher (a different fetcher agent, so the first
    // refusal's dedupe does not answer for it): the refusal names the
    // binding.
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
    let refusals = await_refusal_count(&state, 2).await;
    assert_eq!(refusals.len(), 2, "the binding-revoked fetcher is refused");
    assert_eq!(
        refusals[1].reason,
        TreeKemCatchupRefusalReason::BindingRevoked
    );
    assert!(
        machine_reply_egress(&state).is_empty(),
        "no chunk is addressed to the binding-revoked pairing"
    );

    // The agent-revoked gate keeps main's silent drop: no refusal, no
    // chunk.
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
    assert_eq!(
        recorded_refusals(&state).len(),
        2,
        "the agent-revocation refusal stays a silent drop"
    );
    assert!(machine_reply_egress(&state).is_empty());

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
    Ok(())
}

/// The seat-cert handler: the ask rides the gossip topic, so the machine
/// identity is the requester's own capability binding. A binding that
/// names a machine- or binding-revoked device gets the typed refusal and
/// no answer; an agent-revoked requester keeps the silent drop; a clean
/// requester (no advert held: absent evidence fails open, ADR-0043 §9.3)
/// is still answered.
#[tokio::test]
async fn seat_cert_refuses_a_binding_resolved_revoked_requester_and_serves_a_clean_one(
) -> Result<()> {
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
    info.add_member(local_hex, x0x::groups::GroupRole::Admin, None, None);
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

    // CONTROL: a clean requester with no advert this node holds keeps
    // main's answer (absent evidence fails open).
    assert!(
        seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&remote.agent_id()),
            true,
            &group_key
        )
        .await,
        "a clean requester with no binding evidence is still answered"
    );

    // An agent-revoked requester: the silent drop (no answer, no refusal).
    let revoked_agent = AgentKeypair::generate()?;
    revoke_agent(&state, &revoked_agent).await;
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&revoked_agent.agent_id()),
            true,
            &group_key
        )
        .await,
        "an agent-revoked requester gets no answer"
    );
    assert!(
        recorded_refusals(&state).is_empty(),
        "the agent-revocation refusal stays a silent drop"
    );

    // A requester whose own capability binding names a machine-revoked
    // device: the typed refusal answers that machine, and no answer is
    // published for the ask.
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
    advertise_refusal_bit(&state, &remote.agent_id(), &device.machine_id());
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&remote.agent_id()),
            true,
            &group_key
        )
        .await,
        "a requester whose binding names a machine-revoked device is not answered"
    );
    let refusals = await_refusal_count(&state, 1).await;
    assert_eq!(refusals.len(), 1, "the refusal decision is recorded");
    assert_eq!(
        refusals[0].reason,
        TreeKemCatchupRefusalReason::MachineRevoked
    );
    assert_eq!(
        refusals[0].group_id(),
        state
            .named_groups
            .read()
            .await
            .get(&group_key)
            .expect("fixture")
            .stable_group_id()
    );

    // A binding-revoked pairing of the same shape is refused the same way.
    let holder = AgentKeypair::generate()?;
    let owner_two = x0x::identity::UserKeypair::generate()?;
    let retired = x0x::identity::MachineKeypair::generate()?.machine_id();
    retire_binding(&state, &owner_two, &holder, &retired).await;
    advertise_refusal_bit(&state, &holder.agent_id(), &retired);
    // The holder must be an active roster member for the serve to reach
    // the machine check; seat it on the same group.
    {
        let mut groups = state.named_groups.write().await;
        groups.get_mut(&group_key).expect("fixture").add_member(
            hex::encode(holder.agent_id().as_bytes()),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
    }
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&holder.agent_id()),
            true,
            &group_key
        )
        .await,
        "a requester whose binding names a binding-revoked pairing is not answered"
    );
    let refusals = await_refusal_count(&state, 2).await;
    assert_eq!(refusals.len(), 2);
    assert_eq!(
        refusals[1].reason,
        TreeKemCatchupRefusalReason::BindingRevoked
    );
    Ok(())
}
