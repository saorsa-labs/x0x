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

/// Real requester-signed V2 pub/sub envelope (the pr291 construction) —
/// the shape the predecessor typed-route validator demands.
fn sign_v2_envelope_b2(
    kp: &x0x::identity::AgentKeypair,
    topic: &str,
    event: &NamedGroupMetadataEvent,
) -> Vec<u8> {
    use ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa;
    let payload = serde_json::to_vec(event).expect("serialize event");
    let agent_id = kp.agent_id();
    let pub_bytes = kp.public_key().as_bytes();
    let mut signing = Vec::new();
    signing.extend_from_slice(b"x0x-msg-v2");
    signing.extend_from_slice(agent_id.as_bytes());
    signing.extend_from_slice(topic.as_bytes());
    signing.extend_from_slice(&payload);
    let sig = sign_with_ml_dsa(kp.secret_key(), &signing).expect("ml-dsa sign");
    let sig_bytes = sig.as_bytes();
    let topic_bytes = topic.as_bytes();
    let mut buf = Vec::with_capacity(
        1 + 32 + 2 + pub_bytes.len() + 2 + sig_bytes.len() + 2 + topic_bytes.len() + payload.len(),
    );
    buf.push(0x02u8);
    buf.extend_from_slice(agent_id.as_bytes());
    buf.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(pub_bytes);
    buf.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(sig_bytes);
    buf.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(topic_bytes);
    buf.extend_from_slice(&payload);
    buf
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
    // A REAL requester-signed envelope — the predecessor typed-route
    // validator rejects anything else, and the strict send now rides that
    // route instead of the loopback fan-out.
    let remote_kp = x0x::identity::AgentKeypair::generate()?;
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let (topic, commit) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group fixture");
        let commit = x0x::groups::GroupStateCommit::sign(
            info.stable_group_id().to_string(),
            info.state_revision + 1,
            Some(info.state_hash.clone()),
            x0x::groups::state_commit::compute_roster_root(&info.members_v2),
            x0x::groups::state_commit::compute_policy_hash(&info.policy),
            x0x::groups::state_commit::compute_public_meta_hash(&info.public_meta()),
            info.security_binding.clone(),
            false,
            info.state_revision + 1,
            &remote_kp,
        )
        .expect("sign commit");
        (info.metadata_topic.clone(), commit)
    };
    let envelope = sign_v2_envelope_b2(
        &remote_kp,
        &topic,
        &NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: group_id.clone(),
            request_id: "req-2".to_string(),
            requester_agent_id: remote_hex.clone(),
            message: None,
            ts: 0,
            requester_kem_public_key_b64: None,
            treekem_key_package_b64: None,
            commit: Some(commit),
        },
    );
    let obligation = obligation_for(
        &group_id,
        "req-2",
        &remote_hex,
        &local_hex,
        envelope.clone(),
    );
    insert_requester_offer_obligation(&state, obligation)
        .await
        .expect("obligation persisted");
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
            .with_history(x0x::history::HistoryConfig {
                // Fresh DB: the first agent's handle may still hold the
                // original; history here is only v2-ACK plumbing, the
                // outbox sidecar is the state under test.
                db_path: Some(data_dir.join("history-restarted.db")),
                ..x0x::history::HistoryConfig::daemon_default()
            })
            .build()
            .await?,
    );
    agent.join_network().await.context("join network")?;
    let restarted = secure_endpoint_test_state_at(data_dir, agent).await?;
    load_requester_offer_outbox(&restarted)
        .await
        .expect("sidecar loads");
    // The failed attempt scheduled a backoff; the drain scenario needs the
    // retry due NOW (the worker's own cadence is covered by the schedule).
    restarted
        .requester_offer_outbox
        .write()
        .await
        .values_mut()
        .for_each(|list| {
            list.iter_mut().for_each(|o| {
                o.next_retry_at_ms = now_millis_u64();
            })
        });
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
    // #942 B2: the strict send rides the DURABLE typed route (the
    // loopback shortcut no longer satisfies it). Register the route with
    // a consumer that resolves completions like the production handler
    // and records every delivered payload — this is the wire.
    let captured: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(4);
        restarted
            .agent
            .start_dm_inbox(
                std::sync::Arc::clone(&restarted.agent_kem_keypair),
                x0x::dm_inbox::DmInboxConfig::default().with_validated_durable_typed_payload_route(
                    GROUP_PREDECESSOR_RELAY_DM_PREFIX,
                    tx,
                    crate::server::valid_predecessor_relay_typed_dm,
                ),
            )
            .await
            .expect("restarted inbox with the durable predecessor route");
        restarted.agent.capability_store().insert(
            restarted.agent.agent_id(),
            restarted.agent.machine_id(),
            crate::dm::DmCapabilities::v2_durable_gossip_ready(
                restarted.agent_kem_keypair.public_bytes.clone(),
            ),
            crate::dm_capability::now_unix_ms(),
        );
        let sink = std::sync::Arc::clone(&captured);
        tokio::spawn(async move {
            while let Some(mut typed) = rx.recv().await {
                if let Some(send) = typed.completion.take() {
                    let _ = send.send(Ok(x0x::dm_inbox::DmTypedPayloadCompletion::Inserted));
                }
                sink.lock().expect("sink").push(typed.payload);
            }
        });
    }
    requester_offer_step(&restarted).await;
    // The durable ACK is resolved by the consumer, so the discharge is
    // observable only after the inbox processed the payload.
    for _ in 0..100 {
        if crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(
            &restarted,
        )
        .await
        .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // The obligation is discharged and the wire saw the EXACT payload once.
    let after =
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&restarted)
            .await;
    assert!(after.is_empty(), "delivery discharges the obligation");
    let expected_prefix = GROUP_PREDECESSOR_RELAY_DM_PREFIX;
    for _ in 0..100 {
        if !captured.lock().expect("sink").is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let offer_count = captured
        .lock()
        .expect("sink")
        .iter()
        .filter(|p| p.starts_with(expected_prefix))
        .count();
    assert_eq!(offer_count, 1, "exactly one offer went over the wire");
    let exact = captured
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

/// #942 B2 (Claude's Rule-9 shape): the AUTHORITY's typed channel is the
/// failure point. A FULL channel fails the offer send → the obligation is
/// KEPT durably; the requester daemon RESTARTS with the SAME agent key and
/// the obligation comes back from the sidecar alone (without the load, the
/// restarted daemon has nothing — the pre-#908 shape); after the channel
/// drains, the next pass delivers the EXACT envelope exactly once and the
/// obligation discharges; and a DUPLICATE offer drives the real authority
/// handler to apply the join request EXACTLY ONCE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_channel_failure_restart_drain_and_exactly_once() -> Result<()> {
    let plane = format!("req-offer-b2-{}", rand::random::<u32>());
    let (state, dir) = networked_test_state_with_history(&plane).await?;
    let group_id = insert_local_public_group(&state, &"c3".repeat(16)).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Self-contact with our KEM so the self-loop gossip DM delivers.
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
    // A REAL requester-signed JoinRequestCreated envelope on the group's
    // metadata topic, with a valid state commit so the authority handler
    // can apply it.
    let requester_kp = x0x::identity::AgentKeypair::generate()?;
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let (topic, commit) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group fixture");
        let commit = x0x::groups::GroupStateCommit::sign(
            info.stable_group_id().to_string(),
            info.state_revision + 1,
            Some(info.state_hash.clone()),
            x0x::groups::state_commit::compute_roster_root(&info.members_v2),
            x0x::groups::state_commit::compute_policy_hash(&info.policy),
            x0x::groups::state_commit::compute_public_meta_hash(&info.public_meta()),
            info.security_binding.clone(),
            false,
            info.state_revision + 1,
            &requester_kp,
        )
        .expect("sign commit");
        (info.metadata_topic.clone(), commit)
    };
    let event = NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: group_id.clone(),
        request_id: "req-b2".to_string(),
        requester_agent_id: requester_hex.clone(),
        message: None,
        ts: 0,
        requester_kem_public_key_b64: None,
        treekem_key_package_b64: None,
        commit: Some(commit),
    };
    let envelope = sign_v2_envelope_b2(&requester_kp, &topic, &event);
    pending_join_request(&state, &group_id, "req-b2", &requester_hex).await;
    // The AUTHORITY's typed route with capacity 1 — then FILL it, so the
    // offer's enqueue fails exactly as a full authority channel would.
    let (route_tx, _route_rx) = tokio::sync::mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1);
    let fill_tx = route_tx.clone();
    state
        .agent
        .start_dm_inbox(
            std::sync::Arc::clone(&state.agent_kem_keypair),
            x0x::dm_inbox::DmInboxConfig::default().with_validated_durable_typed_payload_route(
                GROUP_PREDECESSOR_RELAY_DM_PREFIX,
                route_tx,
                crate::server::valid_predecessor_relay_typed_dm,
            ),
        )
        .await
        .expect("inbox with the predecessor route");
    // The strict send's capability source: the daemon's OWN current v2
    // advert (self-loop recipient).
    state.agent.capability_store().insert(
        state.agent.agent_id(),
        state.agent.machine_id(),
        crate::dm::DmCapabilities::v2_durable_gossip_ready(
            state.agent_kem_keypair.public_bytes.clone(),
        ),
        crate::dm_capability::now_unix_ms(),
    );

    fill_tx
        .send(x0x::dm_inbox::DmTypedPayload {
            sender: state.agent.agent_id(),
            machine_id: crate::identity::MachineId([0u8; 32]),
            payload: Vec::new(),
            verified: true,
            trust_decision: None,
            received_at_unix_ms: 0,
            request_id: [0u8; 16],
            completion: None,
        })
        .await
        .expect("fill the authority's typed channel");
    let obligation = obligation_for(
        &group_id,
        "req-b2",
        &requester_hex,
        &local_hex,
        envelope.clone(),
    );
    insert_requester_offer_obligation(&state, obligation)
        .await
        .expect("obligation persisted");
    requester_offer_step(&state).await;
    let kept =
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&state)
            .await;
    assert_eq!(kept.len(), 1, "full authority channel → obligation KEPT");
    assert_eq!(kept[0].retry_count, 1, "the failed attempt was counted");

    // DUPLICATE arm: drive the REAL authority handler with the same offer
    // twice — the join request is applied EXACTLY ONCE.
    let dm_payload = {
        let mut p = Vec::with_capacity(GROUP_PREDECESSOR_RELAY_DM_PREFIX.len() + envelope.len());
        p.extend_from_slice(GROUP_PREDECESSOR_RELAY_DM_PREFIX);
        p.extend_from_slice(&envelope);
        p
    };
    let dm = || x0x::dm_inbox::DmTypedPayload {
        sender: requester_kp.agent_id(),
        machine_id: crate::identity::MachineId([0u8; 32]),
        payload: dm_payload.clone(),
        verified: true,
        trust_decision: None,
        received_at_unix_ms: 0,
        request_id: [0u8; 16],
        completion: None,
    };
    crate::server::handle_predecessor_relay_typed_payload(&state, &local_hex, dm()).await;
    crate::server::handle_predecessor_relay_typed_payload(&state, &local_hex, dm()).await;
    {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group");
        let matches: Vec<&x0x::groups::JoinRequest> = info
            .join_requests
            .values()
            .filter(|r| r.request_id == "req-b2")
            .collect();
        assert_eq!(matches.len(), 1, "duplicate offer applied EXACTLY ONCE");
        assert!(
            matches[0].is_pending(),
            "the applied request is pending for the authority"
        );
    }

    // RESTART the requester daemon with the SAME agent key.
    let (kp_pub, kp_sec) = state.agent.identity.agent_keypair().to_bytes();
    state.agent.shutdown().await;
    drop(state);
    let data_dir = dir.path();
    let agent = std::sync::Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::from_bytes(&kp_pub, &kp_sec)?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .with_network_config(isolated_loopback_config(&plane))
            .with_history(x0x::history::HistoryConfig {
                // Fresh DB: the first agent's handle may still hold the
                // original; history here is only v2-ACK plumbing, the
                // outbox sidecar is the state under test.
                db_path: Some(data_dir.join("history-restarted.db")),
                ..x0x::history::HistoryConfig::daemon_default()
            })
            .build()
            .await?,
    );
    agent.join_network().await.context("join network")?;
    let restarted = secure_endpoint_test_state_at(data_dir, agent).await?;
    let restarted_hex = hex::encode(restarted.agent.agent_id().as_bytes());
    assert_eq!(restarted_hex, local_hex, "the SAME agent key restarted");
    // Without loading the sidecar the restarted daemon has NOTHING — the
    // outbox file is the sole carrier (the pre-#908 shape loses the offer).
    assert!(
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&restarted)
            .await
            .is_empty(),
        "no sidecar load → no offer (pre-#908 shape)"
    );
    load_requester_offer_outbox(&restarted)
        .await
        .expect("sidecar loads");
    // Re-fixture the group, the pending join, the self-contact, and a
    // FRESH (empty, capacity-1) typed route — the authority drained.
    let _ = insert_local_public_group(&restarted, &"c3".repeat(16)).await;
    pending_join_request(&restarted, &group_id, "req-b2", &requester_hex).await;
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
    let (route_tx2, route_rx2) = tokio::sync::mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1);
    restarted
        .agent
        .start_dm_inbox(
            std::sync::Arc::clone(&restarted.agent_kem_keypair),
            x0x::dm_inbox::DmInboxConfig::default().with_validated_durable_typed_payload_route(
                GROUP_PREDECESSOR_RELAY_DM_PREFIX,
                route_tx2,
                crate::server::valid_predecessor_relay_typed_dm,
            ),
        )
        .await
        .expect("restarted inbox with the DURABLE predecessor route");
    restarted.agent.capability_store().insert(
        restarted.agent.agent_id(),
        restarted.agent.machine_id(),
        crate::dm::DmCapabilities::v2_durable_gossip_ready(
            restarted.agent_kem_keypair.public_bytes.clone(),
        ),
        crate::dm_capability::now_unix_ms(),
    );
    // The authority-side consumer: resolve the durable completion (the
    // real handler's disposition) and record every delivered payload.
    let delivered: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let sink = std::sync::Arc::clone(&delivered);
        let mut rx = route_rx2;
        tokio::spawn(async move {
            while let Some(mut typed) = rx.recv().await {
                if let Some(tx) = typed.completion.take() {
                    let _ = tx.send(Ok(x0x::dm_inbox::DmTypedPayloadCompletion::Inserted));
                }
                sink.lock().expect("sink").push(typed.payload);
            }
        });
    }
    requester_offer_step(&restarted).await;
    assert!(
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&restarted)
            .await
            .is_empty(),
        "delivery after restart+drain discharges the obligation"
    );
    // The drained authority received the EXACT envelope exactly once.
    for _ in 0..50 {
        if !delivered.lock().expect("sink").is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let seen = delivered.lock().expect("sink").clone();
    assert_eq!(
        seen.len(),
        1,
        "exactly one delivery across failure + restart + drain"
    );
    assert_eq!(
        &seen[0][GROUP_PREDECESSOR_RELAY_DM_PREFIX.len()..],
        &envelope[..],
        "the authority's route received the exact envelope bytes"
    );
    restarted.agent.shutdown().await;
    Ok(())
}
