// Change set A (RED). This file and its test-only seams compile on main.
// Tests call the existing owner route/event sender, never a new cold-wait API.

fn removal_deliveries(from: &AppState, to: &AppState) -> Vec<Vec<u8>> {
    from.agent
        .general_raw_standin_deliveries_for_testing()
        .into_iter()
        .filter(|(recipient, ..)| *recipient == to.agent.agent_id())
        .map(|(_, _, payload)| payload)
        .collect()
}

fn removal_payload(state: &AppState, payload: &[u8]) -> bool {
    if matches!(
        serde_json::from_slice::<NamedGroupMetadataEvent>(payload),
        Ok(NamedGroupMetadataEvent::MemberRemoved { .. })
    ) {
        return true;
    }
    match serde_json::from_slice::<super::super::control_blob::ControlBlobMessage>(payload) {
        Ok(super::super::control_blob::ControlBlobMessage::Reference { reference }) => state
            .control_blobs
            .staged_chunk(&reference, 0)
            .is_some_and(|chunk| chunk.starts_with(br#"{"event":"member_removed""#)),
        _ => false,
    }
}

async fn removal_resolution_entered(gate: &x0x::general_cold_barrier::Gate) {
    let entered = tokio::time::timeout(Duration::from_secs(4), gate.reached.acquire()).await;
    assert!(
        matches!(entered, Ok(Ok(_))),
        "removal never reached cold resolution"
    );
}

// Inject only an authenticated binding. Main's general resolver cannot use
// this retained source after its cache/registry lookup found nothing.
async fn removal_bind(authority: &AppState, recipient: &AppState) {
    authority
        .agent
        .record_authenticated_binding_with_expiry_for_testing(
            recipient.agent.agent_id(),
            recipient.agent.machine_id(),
            unix_secs_now(),
            None,
        )
        .await;
}

fn removal_notice(
    authority: &AppState,
    recipient: &AppState,
    group: &str,
    large: bool,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberRemoved {
        group_id: group.to_owned(),
        revision: 3,
        actor: hex_of(authority),
        agent_id: hex_of(recipient),
        treekem_commit_b64: large.then(|| "a".repeat(x0x::dm::MAX_PAYLOAD_BYTES + 1)),
        treekem_epoch: None,
        secret_epoch: None,
        commit: None,
    }
}

/// RED on main: the real owner route commits removal, but the initial
/// direct leg cannot consume the binding learned after restart. The window
/// ends before the +6 s/+8 s redelivery legs. Covers the real TreeKEM notice.
#[tokio::test]
async fn s1217_owner_route_delivers_removal_to_restart_cold_member() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.authority, &s.j2, &s.stable).await;
    let gate = x0x::general_cold_barrier::arm(s.authority_id, s.j2.agent.agent_id(), None);
    let response = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), hex_of(&s.j2))),
    )
    .await
    .into_response();
    assert!(
        response.status().is_success(),
        "owner removal: {}",
        response.status()
    );
    removal_resolution_entered(&gate).await;
    // A slow resolution task must not retain the membership lock.
    let membership = super::super::group_membership_lock(&s.authority, &s.group_key).await;
    let unlocked = tokio::time::timeout(Duration::from_millis(500), membership.lock()).await;
    assert!(unlocked.is_ok(), "removal wait held membership lock");
    drop(unlocked);
    removal_bind(&s.authority, &s.j2).await;
    gate.release();
    let delivered = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if removal_deliveries(&s.authority, &s.j2)
                .iter()
                .any(|p| removal_payload(&s.authority, p))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    x0x::general_cold_barrier::disarm(s.authority_id, s.j2.agent.agent_id());
    assert!(
        delivered.is_ok(),
        "owner MemberRemoved did not reach the removed member"
    );
    Ok(())
}

/// RED on main for both inline and oversized notices. Exercise one exact
/// initial delivery future so a later retry cannot supply a false pass.
#[tokio::test]
async fn s1217_inline_and_reference_removal_consume_a_late_binding() -> anyhow::Result<()> {
    for large in [false, true] {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        restart_cold(&g.authority, &g.joiner, &g.stable).await;
        let gate = x0x::general_cold_barrier::arm(
            g.authority.agent.agent_id(),
            g.joiner.agent.agent_id(),
            None,
        );
        let event = removal_notice(&g.authority, &g.joiner, &g.stable, large);
        let delivery = super::super::named_group_event_delivery_future(
            &g.authority,
            &hex_of(&g.joiner),
            &event,
            "test",
        )
        .unwrap();
        let send = tokio::spawn(delivery);
        removal_resolution_entered(&gate).await;
        gate.release();
        tokio::time::sleep(Duration::from_millis(150)).await;
        removal_bind(&g.authority, &g.joiner).await;
        let ended = tokio::time::timeout(Duration::from_secs(3), send).await?;
        ended?;
        x0x::general_cold_barrier::disarm(g.authority.agent.agent_id(), g.joiner.agent.agent_id());
        assert!(
            removal_deliveries(&g.authority, &g.joiner)
                .iter()
                .any(|p| removal_payload(&g.authority, p)),
            "initial removal leg failed (large={large})"
        );
    }
    Ok(())
}

/// Security controls also compile on main. Repair cases must reach the
/// actual production repair (main fails that assertion); a silent early
/// failure cannot masquerade as successful final-machine re-validation.
#[tokio::test]
async fn s1217_removal_revalidates_binding_and_revocation_after_repair() -> anyhow::Result<()> {
    for change in [
        "clean",
        "revoked_before",
        "revoked_during",
        "expired",
        "changed",
    ] {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        restart_cold(&g.authority, &g.joiner, &g.stable).await;
        let gate = x0x::general_cold_barrier::arm(
            g.authority.agent.agent_id(),
            g.joiner.agent.agent_id(),
            None,
        );
        let repair = x0x::PinnedRepairGate::new();
        g.authority
            .agent
            .script_pinned_standin_transport_for_testing(
                x0x::PinnedTransportScript::connected_only(&[], true)
                    .with_repair_gate(Arc::clone(&repair)),
            );
        let event = removal_notice(&g.authority, &g.joiner, &g.stable, false);
        let send = tokio::spawn(
            super::super::named_group_event_delivery_future(
                &g.authority,
                &hex_of(&g.joiner),
                &event,
                "test",
            )
            .unwrap(),
        );
        removal_resolution_entered(&gate).await;
        removal_bind(&g.authority, &g.joiner).await;
        if change == "revoked_before" {
            revoke_machine(&g.authority, &g.joiner).await?;
        }
        gate.release();
        if change != "revoked_before" {
            let entered =
                tokio::time::timeout(Duration::from_secs(2), repair.reached.acquire()).await;
            assert!(
                matches!(entered, Ok(Ok(_))),
                "{change}: did not reach repair"
            );
            match change {
                "revoked_during" => revoke_machine(&g.authority, &g.joiner).await?,
                "expired" | "changed" => {
                    let now = unix_secs_now();
                    let machine = if change == "changed" {
                        x0x::identity::MachineId([0xa9; 32])
                    } else {
                        g.joiner.agent.machine_id()
                    };
                    g.authority
                        .agent
                        .record_authenticated_binding_with_expiry_for_testing(
                            g.joiner.agent.agent_id(),
                            machine,
                            now + 1,
                            (change == "expired").then_some(now - 86_400),
                        )
                        .await;
                }
                _ => {}
            }
        }
        repair.release();
        tokio::time::timeout(Duration::from_secs(3), send).await??;
        if change == "revoked_before" {
            assert!(
                repair.reached.try_acquire().is_err(),
                "revoked_before: reached repair despite pre-repair revocation"
            );
        }
        x0x::general_cold_barrier::disarm(g.authority.agent.agent_id(), g.joiner.agent.agent_id());
        let delivered = removal_deliveries(&g.authority, &g.joiner)
            .iter()
            .any(|p| removal_payload(&g.authority, p));
        assert_eq!(
            delivered,
            change == "clean",
            "{change}: incorrect removal delivery"
        );
    }
    Ok(())
}

/// Public sends, other event types and relayed/self-leave MemberRemoved
/// notices must retain the ordinary failure path. No join/Welcome opt-in.
#[tokio::test]
async fn s1217_only_local_author_removal_notices_opt_in() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    removal_bind(&g.authority, &g.joiner).await;
    let started = std::time::Instant::now();
    let result = g
        .authority
        .agent
        .send_direct_with_config(
            &g.joiner.agent.agent_id(),
            b"ordinary public send".to_vec(),
            direct_message_send_config(),
        )
        .await;
    assert!(
        matches!(result, Err(x0x::dm::DmError::RecipientUndiscovered(_))),
        "{result:?}"
    );
    let mut self_leave = removal_notice(&g.authority, &g.authority, &g.stable, false);
    let mut relayed = removal_notice(&g.authority, &g.joiner, &g.stable, true);
    if let NamedGroupMetadataEvent::MemberRemoved { actor, .. } = &mut relayed {
        *actor = hex::encode([0x5a; 32]);
    }
    let mut deleted = NamedGroupMetadataEvent::GroupDeleted {
        group_id: g.stable.clone(),
        revision: 4,
        actor: hex_of(&g.authority),
        commit: None,
    };
    for event in [&mut self_leave, &mut relayed, &mut deleted] {
        super::super::named_group_event_delivery_future(
            &g.authority,
            &hex_of(&g.joiner),
            event,
            "test",
        )
        .unwrap()
        .await;
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "ordinary sends acquired a cold wait"
    );
    assert!(removal_deliveries(&g.authority, &g.joiner).is_empty());
    Ok(())
}

/// RED on main: an unknown removal recipient fails immediately. The fix
/// spends one five-second resolution budget and does not start another.
#[tokio::test]
async fn s1217_unknown_removal_recipient_uses_one_bounded_wait() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    let event = removal_notice(&g.authority, &g.joiner, &g.stable, false);
    let started = std::time::Instant::now();
    let delivery = super::super::named_group_event_delivery_future(
        &g.authority,
        &hex_of(&g.joiner),
        &event,
        "test",
    )
    .unwrap();
    tokio::time::timeout(Duration::from_millis(6500), delivery).await?;
    assert!(
        started.elapsed() >= Duration::from_millis(4500),
        "no bounded wait"
    );
    assert!(removal_deliveries(&g.authority, &g.joiner).is_empty());
    Ok(())
}
