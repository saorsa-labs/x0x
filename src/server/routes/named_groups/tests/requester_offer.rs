//! #908 intent tests: the requester's predecessor offer is a DURABLE
//! obligation, not a one-shot spawn.

use super::*;

/// A pending join request fixture for `group_id`, created by
/// `requester_agent_hex`, pending at `now`.
async fn pending_join_request(
    state: &AppState,
    group_id: &str,
    request_id: &str,
    requester_agent_hex: &str,
) {
    let mut groups = state.named_groups.write().await;
    let info = groups.get_mut(group_id).expect("group fixture exists");
    let mut request =
        x0x::groups::JoinRequest::new(String::new(), requester_agent_hex.to_string(), None, 0);
    request.request_id = request_id.to_string();
    info.join_requests.insert(request_id.to_string(), request);
}

fn obligation_for(
    group_id: &str,
    request_id: &str,
    requester_hex: &str,
    authority_hex: &str,
    envelope: Vec<u8>,
) -> RequesterOfferObligation {
    let now_ms = now_millis_u64();
    RequesterOfferObligation {
        group_id: group_id.to_string(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_hex.to_string(),
        authority_agent_id: authority_hex.to_string(),
        digest: blake3::hash(&envelope).into(),
        byte_size: envelope.len(),
        envelope_bytes: envelope,
        first_seen_ms: now_ms,
        next_retry_at_ms: now_ms,
        retry_count: 0,
    }
}

/// Rule 9 (failure arm): a send that fails leaves the obligation DURABLY
/// in the store with a scheduled retry — the pre-#908 one-shot spawn
/// would have logged and dropped it. The outbox is the only reason the
/// envelope still exists for the recovery test below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_offer_send_keeps_the_durable_obligation() -> Result<()> {
    let plane = format!("req-offer-fail-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let group_id = insert_local_public_group(&state, &"c1".repeat(16)).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    pending_join_request(&state, &group_id, "req-1", &local_hex).await;
    // The authority is an UNRESOLVABLE agent: the gossip-DM send fails.
    let dead_authority = "ff".repeat(32);
    let envelope = vec![0xA5u8; 96];
    let obligation = obligation_for(
        &group_id,
        "req-1",
        &local_hex,
        &dead_authority,
        envelope.clone(),
    );
    insert_requester_offer_obligation(&state, obligation.clone())
        .await
        .expect("obligation persisted");
    // The sidecar is on disk BEFORE any send: durability precedes delivery.
    let raw = tokio::fs::read(&state.requester_offer_outbox_path)
        .await
        .expect("outbox sidecar exists");
    let sidecar: serde_json::Value = serde_json::from_slice(&raw).expect("sidecar is JSON");
    let found_envelope = sidecar
        .get("by_group")
        .and_then(|g| g.get(&group_id))
        .and_then(|l| l.as_array())
        .is_some_and(|entries| {
            entries.iter().any(|e| {
                e.get("envelope_bytes")
                    .and_then(|b| b.as_array())
                    .is_some_and(|arr| {
                        arr.len() == envelope.len()
                            && arr
                                .iter()
                                .zip(&envelope)
                                .all(|(v, b)| v.as_u64() == Some(*b as u64))
                    })
            })
        });
    assert!(found_envelope, "the exact envelope bytes are persisted");

    requester_offer_step(&state).await;
    let snapshot =
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&state)
            .await;
    assert_eq!(snapshot.len(), 1, "a failed send KEEPS the obligation");
    assert_eq!(snapshot[0].retry_count, 1, "the attempt was counted");
    // The ADR 0028 schedule's first offset is 0s (immediate retry), so
    // the invariant is: the obligation is KEPT with its attempt counted
    // and a scheduled next attempt, not that it is in the future yet.
    assert!(
        snapshot[0].next_retry_at_ms >= snapshot[0].first_seen_ms,
        "a next attempt is scheduled"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// Rule 9 (recovery + restart arm): after a failure, the SAME state
/// rebuilt from disk (restart) still delivers the exact envelope over the
/// wire exactly once when the send then succeeds. Without the outbox a
/// restart loses the offer entirely — that is the #908 defect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_still_delivers_the_offer_once() -> Result<()> {
    let plane = format!("req-offer-restart-{}", rand::random::<u32>());
    let (state, dir) = networked_test_state(&plane).await?;
    let group_id = insert_local_public_group(&state, &"c2".repeat(16)).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    pending_join_request(&state, &group_id, "req-2", &local_hex).await;
    // A Trusted self-contact with our KEM so the self-loop gossip DM
    // delivers (the release-test shape).
    state
        .agent
        .contacts()
        .write()
        .await
        .add(crate::contacts::Contact {
            agent_id: state.agent.agent_id(),
            trust_level: crate::contacts::TrustLevel::Trusted,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: crate::contacts::IdentityType::Known,
            machines: Vec::new(),
            dm_capabilities: Some(crate::dm::DmCapabilities::v1_gossip_ready(
                state.agent_kem_keypair.public_bytes.clone(),
            )),
        });
    let envelope = vec![0x5Au8; 128];
    let obligation = obligation_for(&group_id, "req-2", &local_hex, &local_hex, envelope.clone());
    insert_requester_offer_obligation(&state, obligation)
        .await
        .expect("obligation persisted");
    // Captured outbound DMs on the self-loop (the transport the offer
    // rides); the production dispatch is what would process them.
    let captured: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let mut rx = state.agent.subscribe_direct();
        let sink = std::sync::Arc::clone(&captured);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                sink.lock().expect("sink").push(msg.payload.to_vec());
            }
        });
    }
    // RESTART: drop the live state, rebuild on the same data dir (the
    // obligation must come back from the sidecar), then deliver.
    state.agent.shutdown().await;
    drop(state);
    let data_dir = dir.path();
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .with_network_config(isolated_loopback_config(&plane))
            .build()
            .await?,
    );
    agent.join_network().await.context("join network")?;
    let restarted = secure_endpoint_test_state_at(data_dir, agent).await?;
    load_requester_offer_outbox(&restarted)
        .await
        .expect("sidecar loads");
    let snapshot =
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&restarted)
            .await;
    assert_eq!(snapshot.len(), 1, "the obligation SURVIVED the restart");
    assert_eq!(
        snapshot[0].envelope_bytes, envelope,
        "the exact bytes survived"
    );
    // The restarted agent has a fresh key but the SELF-loop delivery only
    // needs the self-contact shape; re-add it for this agent's identity.
    let restarted_hex = hex::encode(restarted.agent.agent_id().as_bytes());
    let _group_id = insert_local_public_group(&restarted, &"c2".repeat(16)).await;
    {
        let mut groups = restarted.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group fixture");
        let mut request =
            x0x::groups::JoinRequest::new(String::new(), restarted_hex.clone(), None, 0);
        request.request_id = "req-2".to_string();
        info.join_requests.insert("req-2".to_string(), request);
    }
    let mut snapshot =
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&restarted)
            .await;
    snapshot[0].requester_agent_id = restarted_hex.clone();
    snapshot[0].authority_agent_id = restarted_hex;
    // Re-point the live obligation at the restarted agent's identity.
    {
        let mut by_group = restarted.requester_offer_outbox.write().await;
        for o in by_group.get_mut(&group_id).expect("obligation group") {
            o.requester_agent_id = snapshot[0].requester_agent_id.clone();
            o.authority_agent_id = snapshot[0].authority_agent_id.clone();
        }
    }
    restarted
        .agent
        .contacts()
        .write()
        .await
        .add(crate::contacts::Contact {
            agent_id: restarted.agent.agent_id(),
            trust_level: crate::contacts::TrustLevel::Trusted,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: crate::contacts::IdentityType::Known,
            machines: Vec::new(),
            dm_capabilities: Some(crate::dm::DmCapabilities::v1_gossip_ready(
                restarted.agent_kem_keypair.public_bytes.clone(),
            )),
        });
    let mut rx2 = restarted.agent.subscribe_direct();
    let sink2 = std::sync::Arc::clone(&captured);
    let sink_reader = std::sync::Arc::clone(&captured);
    tokio::spawn(async move {
        while let Some(msg) = rx2.recv().await {
            sink2.lock().expect("sink").push(msg.payload.to_vec());
        }
    });
    requester_offer_step(&restarted).await;
    // The obligation is discharged and the wire saw the EXACT payload once.
    let after =
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&restarted)
            .await;
    assert!(after.is_empty(), "delivery discharges the obligation");
    let expected_prefix = GROUP_PREDECESSOR_RELAY_DM_PREFIX;
    let sink_read = sink_reader;
    let offer_count = sink_read
        .lock()
        .expect("sink")
        .iter()
        .filter(|p| p.starts_with(expected_prefix))
        .count();
    assert_eq!(offer_count, 1, "exactly one offer went over the wire");
    let exact = sink_read
        .lock()
        .expect("sink")
        .iter()
        .any(|p| p.starts_with(expected_prefix) && p[expected_prefix.len()..] == envelope[..]);
    assert!(exact, "the wire carried the exact envelope bytes");
    restarted.agent.shutdown().await;
    Ok(())
}

/// The resolution arm: an obligation whose join request already resolved
/// is dropped without a send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resolved_join_drops_the_obligation_without_sending() -> Result<()> {
    let plane = format!("req-offer-resolved-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let group_id = insert_local_public_group(&state, &"c3".repeat(16)).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    // NO pending join request — the group never had one (resolved/gone).
    let obligation = obligation_for(&group_id, "req-3", &local_hex, &local_hex, vec![1; 64]);
    insert_requester_offer_obligation(&state, obligation)
        .await
        .expect("obligation persisted");
    requester_offer_step(&state).await;
    let after =
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&state)
            .await;
    assert!(after.is_empty(), "a resolved join drops the obligation");
    state.agent.shutdown().await;
    Ok(())
}
