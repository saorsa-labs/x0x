//! #1657 (ADR 0110 §3; David's approval, 28 Oct 02:08 GMT): a catch-up
//! request from a machine-revoked or binding-revoked device gets the
//! typed refusal naming which revocation applies, instead of the interim
//! silent drop of #1577/#1616/#1622. The requester can stop re-asking and
//! surface the reason; non-revoked peers are served exactly as before, and
//! the agent-revocation and resync refusals keep the silent drop the
//! approval scoped this change away from. The decision is recorded at the
//! serve (before egress, as the page recorder is); the EGRESS is recorded
//! at the send seam on the agent, after the capability, signing and
//! dedupe gates — so a test cannot pass on a refusal that never left
//! (review round 3, finding 2). Every refusal send requires the
//! requester machine's verified advert to carry
//! `treekem_catchup_refusal_v1` (bit 13, Engineer rulings 29 Oct 22:14
//! and 22:52 GMT); a peer without it keeps main's silent drop.

use super::*;
use x0x::identity::AgentKeypair;

/// Advertise bit 13 for `(agent, machine)` as a verified capability
/// advert, exactly as the gossip advert service would ingest it — the
/// gate every refusal send now checks. The signed timestamp is bumped
/// per call so a later advert for the same agent always supersedes.
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

/// Every refusal that passed every gate and reached the send seam,
/// decoded — the egress observation point of the refusal-only reply
/// path (never the ordinary DM egress, whose pairing preflight denies
/// the revoked pairing the refusal answers).
fn refusal_egress(state: &AppState) -> Vec<(MachineId, TreeKemCatchupRefusal)> {
    state
        .agent
        .treekem_refusal_replies
        .egress
        .lock()
        .expect("refusal egress recorder")
        .iter()
        .map(|(machine, payload)| {
            (
                *machine,
                serde_json::from_slice(payload).expect("egress refusal decodes"),
            )
        })
        .collect()
}

/// Insert a verified self-revocation of `subject` (as the #1577 test does).
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

/// Insert a verified self-revocation of `device` (the device's own key, as
/// the #1616 test does). D70: this denies the machine only.
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

/// Retire the `(agent, machine)` pairing with an owner-signed ADR-0043
/// tombstone, the only legal authority for a binding subject, as the
/// #1622 test does. D70: this kills the pairing only.
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

/// Every typed refusal the serve decided on, decoded.
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

/// Seat `members` as Active members of a fresh group owned by the local
/// admin, as the #1577 test fabric does.
async fn seat_members(state: &AppState, group_id: &str, members: &[&AgentKeypair]) {
    let admin = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::new(
        "issue1657".to_string(),
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

#[tokio::test]
async fn a_machine_revoked_requester_gets_a_typed_refusal_naming_the_machine() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "57".repeat(32);
    let device_agent = AgentKeypair::generate()?;
    let active = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&device_agent, &active]).await;

    // CONTROL: an active member on a clean machine is served, and no
    // refusal exists to send it.
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
        1,
        "an active member on a clean machine is served"
    );
    assert!(
        recorded_refusals(&state).is_empty(),
        "CONTROL: a non-revoked requester gets no refusal"
    );

    // D70: the device is revoked, the agent is not. The serve refuses the
    // machine and answers with the typed refusal naming it — the silent
    // drop is gone. The refusal leaves through the refusal-only reply
    // path (the requester machine's advert carries bit 13), recorded at
    // the EGRESS seam — this is the "revoked before the queued handler
    // runs" ordering: the handler observes the revocation at run time,
    // and ordinary DM egress could never answer it (its ADR-0043 B/P
    // preflight denies this pairing).
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
    advertise_refusal_bit(&state, &device_agent.agent_id(), &device.machine_id());
    assert!(
        !state
            .agent
            .revocation_set()
            .read()
            .await
            .is_agent_revoked(&device_agent.agent_id()),
        "CONTROL: the device's agent is not revoked"
    );
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
        "a machine-revoked requester still gets no catch-up page"
    );
    let refusals = recorded_refusals(&state);
    assert_eq!(
        refusals.len(),
        1,
        "a machine-revoked requester gets exactly one typed refusal"
    );
    assert_eq!(
        refusals[0].message_type,
        TreeKemCatchupRefusal::MESSAGE_TYPE
    );
    assert_eq!(refusals[0].group_id(), group_id);
    assert_eq!(
        refusals[0].requester_agent_id(),
        hex::encode(device_agent.agent_id().as_bytes())
    );
    assert_eq!(
        refusals[0].reason,
        TreeKemCatchupRefusalReason::MachineRevoked,
        "the refusal names the machine revocation"
    );
    let egress = refusal_egress(&state);
    assert_eq!(
        egress.len(),
        1,
        "the refusal reached the send seam (egress): the refusal-only reply path answered the revoked device"
    );
    assert_eq!(
        egress[0].0,
        device.machine_id(),
        "the egress refusal is addressed to the revoked device's machine"
    );
    assert_eq!(
        egress[0].1.reason,
        TreeKemCatchupRefusalReason::MachineRevoked
    );

    // The agent-only gate (#1577) keeps the silent drop the approval
    // scoped this change away from: no page, and no new refusal — the
    // clean machine advertises bit 13, so the drop is the revocation
    // gate, not a missing capability.
    revoke_agent(&state, &device_agent).await;
    advertise_refusal_bit(&state, &device_agent.agent_id(), &clean_sender_machine());
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "an agent-revoked requester is still refused"
    );
    assert_eq!(
        recorded_refusals(&state).len(),
        1,
        "the agent-revocation refusal stays a silent drop"
    );
    assert_eq!(
        refusal_egress(&state).len(),
        1,
        "the agent-revocation refusal never reaches the egress seam"
    );

    // A non-revoked requester is still served after the refusal.
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
        "a non-revoked requester is still served after the refusal"
    );
    Ok(())
}

#[tokio::test]
async fn a_binding_revoked_requester_gets_a_typed_refusal_naming_the_binding() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "58".repeat(32);
    let moved = AgentKeypair::generate()?;
    let active = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&moved, &active]).await;

    // D70: the pairing alone is dead — agent and device each stay clean.
    // The serve refuses the pairing and answers with the typed refusal
    // naming the binding revocation. The refusal reaches the EGRESS seam
    // through the refusal-only reply path: ordinary DM egress denies
    // exactly this (agent, machine) pairing at its ADR-0043 B/P
    // preflight, so under the round-2 send this refusal never left.
    let owner = x0x::identity::UserKeypair::generate()?;
    let retired_machine = x0x::identity::MachineKeypair::generate()?.machine_id();
    retire_binding(&state, &owner, &moved, &retired_machine).await;
    advertise_refusal_bit(&state, &moved.agent_id(), &retired_machine);
    handle_treekem_catchup_request(
        &state,
        &moved.agent_id(),
        &retired_machine,
        true,
        catchup_request(&group_id, &moved.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        0,
        "a binding-revoked requester gets no catch-up page"
    );
    let refusals = recorded_refusals(&state);
    assert_eq!(
        refusals.len(),
        1,
        "a binding-revoked requester gets exactly one typed refusal"
    );
    assert_eq!(
        refusals[0].message_type,
        TreeKemCatchupRefusal::MESSAGE_TYPE
    );
    assert_eq!(refusals[0].group_id(), group_id);
    assert_eq!(
        refusals[0].reason,
        TreeKemCatchupRefusalReason::BindingRevoked,
        "the refusal names the binding revocation"
    );
    let egress = refusal_egress(&state);
    assert_eq!(
        egress.len(),
        1,
        "the binding-revoked refusal reached the send seam: the refusal-only reply path answers the pairing ordinary egress denies"
    );
    assert_eq!(egress[0].0, retired_machine);

    // Pairing-scope control: the same agent on a clean machine is still
    // an Active member in good standing and is served, with no refusal.
    handle_treekem_catchup_request(
        &state,
        &moved.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &moved.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "the same agent on a clean machine is still served"
    );
    assert_eq!(
        recorded_refusals(&state).len(),
        1,
        "the clean pairing of the same agent gets no refusal"
    );
    Ok(())
}

/// The capability gate (Engineer rulings, 29 Oct 22:14 and 22:52 GMT):
/// a machine whose verified advert lacks bit 13 — and a machine with no
/// verified advert at all — keeps main's silent drop. Only the advert
/// carrying the bit is answered. Older peers persist an ungated
/// refusal as a durable DM-history row; the bit is what prevents that.
#[tokio::test]
async fn a_requester_without_the_refusal_bit_keeps_the_silent_drop() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "59".repeat(32);
    let device_agent = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&device_agent]).await;
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;

    // No verified advert at all (an unknown peer): silent drop.
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_refusals(&state).len(),
        1,
        "the DECISION to refuse is still recorded (the requester is refused)"
    );
    assert!(
        refusal_egress(&state).is_empty(),
        "an unknown requester machine (no verified advert) keeps the silent drop"
    );

    // A verified advert WITHOUT bit 13 (an older peer): silent drop. The
    // signed timestamp sits one second back, so the with-bit advert
    // below always supersedes it in the store.
    let mut caps = x0x::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
    caps.application_registry = x0x::dm::CapabilityRegistry {
        version: 1,
        bits: x0x::dm::CapabilityRegistry::GUI_SHOW_V1,
    };
    assert!(state.agent.capability_store.insert(
        device_agent.agent_id(),
        device.machine_id(),
        caps,
        x0x::dm_capability::now_unix_ms().saturating_sub(1_000)
    ));
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_refusals(&state).len(),
        2,
        "the second refusal decision is recorded"
    );
    assert!(
        refusal_egress(&state).is_empty(),
        "a requester machine whose advert lacks bit 13 keeps the silent drop"
    );

    // The advert carrying bit 13 (this release): the refusal is sent.
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
        refusal_egress(&state).len(),
        1,
        "a requester machine whose advert carries bit 13 is answered"
    );
    Ok(())
}

/// The registry contract of the new bit (ADR 0093): bit 13, advertised
/// by this release, not colliding with any allocated bit.
#[test]
fn treekem_catchup_refusal_v1_is_registry_bit_13() {
    use x0x::dm::CapabilityRegistry;
    assert_eq!(CapabilityRegistry::TREEKEM_CATCHUP_REFUSAL_V1, 1 << 13);
    assert!(
        CapabilityRegistry::current().supports(CapabilityRegistry::TREEKEM_CATCHUP_REFUSAL_V1),
        "this release advertises the refusal bit"
    );
    for (name, bit) in [
        ("share_grant_v1", CapabilityRegistry::SHARE_GRANT_V1),
        (
            "predecessor_offer_v1",
            CapabilityRegistry::PREDECESSOR_OFFER_V1,
        ),
        ("peer_evidence_v1", CapabilityRegistry::PEER_EVIDENCE_V1),
        (
            "file_control_ack_v1",
            CapabilityRegistry::FILE_CONTROL_ACK_V1,
        ),
        (
            "eviction_handoff_v1",
            CapabilityRegistry::EVICTION_HANDOFF_V1,
        ),
        (
            "crypto_exclusion_v1",
            CapabilityRegistry::CRYPTO_EXCLUSION_V1,
        ),
        (
            "certificate_rebind_v1",
            CapabilityRegistry::CERTIFICATE_REBIND_V1,
        ),
        ("owner_recovery_v1", CapabilityRegistry::OWNER_RECOVERY_V1),
        (
            "group_terminal_attest_v1",
            CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1,
        ),
        (
            "group_reseat_mandate_v1",
            CapabilityRegistry::GROUP_RESEAT_MANDATE_V1,
        ),
        ("gui_show_v1", CapabilityRegistry::GUI_SHOW_V1),
        (
            "join_pending_notice_v1",
            CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
        ),
    ] {
        assert_ne!(
            CapabilityRegistry::TREEKEM_CATCHUP_REFUSAL_V1,
            bit,
            "the refusal bit collides with {name}"
        );
    }
}

/// Review round 1, finding 2 (test gap): a request whose claimed
/// requester is not the authenticated sender gets NO reply — not a
/// refusal, not a page, not a note.
#[tokio::test]
async fn a_request_claiming_another_requester_gets_no_refusal() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "5a".repeat(32);
    let device_agent = AgentKeypair::generate()?;
    let impostor_target = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&device_agent, &impostor_target]).await;
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
    advertise_refusal_bit(&state, &device_agent.agent_id(), &device.machine_id());

    // The request claims the impostor_target as its requester, but the
    // authenticated sender is device_agent: no reply at all.
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &impostor_target.agent_id()),
    )
    .await;
    assert!(
        recorded_refusals(&state).is_empty(),
        "a request naming another requester gets no refusal decision"
    );
    assert!(
        refusal_egress(&state).is_empty(),
        "a request naming another requester gets no egress"
    );
    assert_eq!(
        recorded_pages(&state),
        0,
        "a machine-revoked requester is not served either"
    );
    Ok(())
}

/// The per-(machine, group) dedupe (Engineer ruling, 29 Oct 22:14 GMT):
/// one answer stands for the window — a revoked device re-sending the
/// same request is answered once, a different group is answered
/// independently, and an expired window answers again.
#[tokio::test]
async fn a_repeat_request_is_answered_once_per_machine_and_group_window() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "5b".repeat(32);
    let other_group = "5c".repeat(32);
    let device_agent = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&device_agent]).await;
    seat_members(&state, &other_group, &[&device_agent]).await;
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
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_refusals(&state).len(),
        2,
        "each refused request records its decision"
    );
    assert_eq!(
        refusal_egress(&state).len(),
        1,
        "the same (machine, group) pair is sent once inside the window"
    );

    // Another group of the same machine is answered independently.
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&other_group, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        refusal_egress(&state).len(),
        2,
        "another group of the same machine is answered"
    );

    // An expired window answers again.
    state
        .agent
        .treekem_refusal_replies
        .expire_for_test(device.machine_id(), &group_id);
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        refusal_egress(&state).len(),
        3,
        "an expired dedupe window answers the pair again"
    );
    Ok(())
}

/// Review round 3, finding 3: the asker surfaces the reason for a
/// refusal that answers ANY ask kind. A gap/page catch-up ask never
/// writes a head round, so the strict asked-peer check must not gate
/// the surfacing — only the head-round re-ask stop.
#[tokio::test]
async fn a_refusal_for_a_gap_ask_is_surfaced_without_stopping_a_reask() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "5d".repeat(32);
    let refuser = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&refuser]).await;
    // No head round exists for the group (a gap/page ask) and the
    // refuser was never asked this round.
    let refusal = TreeKemCatchupRefusal::new(
        group_id.clone(),
        hex::encode(state.agent.agent_id().as_bytes()),
        TreeKemCatchupRefusalReason::MachineRevoked,
    );
    handle_treekem_catchup_refusal(
        &state,
        &refuser.agent_id(),
        &clean_sender_machine(),
        true,
        refusal,
    )
    .await;
    assert_eq!(
        state
            .treekem_catchup_refusals
            .lock()
            .expect("notes")
            .get(&group_id)
            .expect("a refusal answering a gap ask is surfaced with a note")
            .reason,
        TreeKemCatchupRefusalReason::MachineRevoked
    );
    assert_eq!(
        state
            .treekem_catchup_refusals
            .lock()
            .expect("notes")
            .get(&group_id)
            .expect("the surfaced note names the refusing peer")
            .peer,
        *refuser.agent_id().as_bytes()
    );
    // The refusal changes no ask cadence: no head round exists, so
    // nothing was stopped — and a second, identical refusal refreshes
    // the note without re-warning (the note map stays at one row).
    let refusal = TreeKemCatchupRefusal::new(
        group_id.clone(),
        hex::encode(state.agent.agent_id().as_bytes()),
        TreeKemCatchupRefusalReason::MachineRevoked,
    );
    handle_treekem_catchup_refusal(
        &state,
        &refuser.agent_id(),
        &clean_sender_machine(),
        true,
        refusal,
    )
    .await;
    assert_eq!(
        state.treekem_catchup_refusals.lock().expect("notes").len(),
        1,
        "the note map holds one row per group"
    );
    Ok(())
}
