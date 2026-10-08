//! #1266: a surviving member must keep its encrypted group store across the
//! metadata-first gap of a GSS removal rotation.
//!
//! ADR 0024 delivers the signed `MemberRemoved` and the survivor's
//! `SecureShareDelivered` independently. When the removal lands first, the
//! survivor sits at the rotated epoch with no shared secret until the share
//! arrives. Any store activity in that window (a GET, an inbound record) runs
//! the store's GSS refresh hook. The hook must treat the transient missing
//! secret as "key pending", not as lifecycle ineligibility: it must not retire
//! and unregister the handle, because nothing re-opens it when the share
//! installs.
//!
//! The survivor here holds a real store handle, so its agent needs a gossip
//! runtime: loopback bind, no seeds, no discovery or port mapping, peer cache
//! off and a private network id. Run it only inside the loopback sandbox or
//! the isolated test harness.

use super::*;

async fn loopback_survivor_state() -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let mut config = isolated_loopback_config("issue1266-survivor");
    config.port_mapping_enabled = false;
    let agent = Arc::new(
        Agent::builder()
            .with_identity_dir(data_dir)
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .with_network_config(config)
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(data_dir, agent).await?;
    Ok((state, dir))
}

async fn open_group_store(
    state: &Arc<AppState>,
    group_id: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let request = serde_json::from_value(serde_json::json!({ "name": "ws" }))?;
    let (status, body) = crate::server::routes::create_group_kv_store(
        State(Arc::clone(state)),
        Path(group_id.to_string()),
        Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        axum::Json(request),
    )
    .await;
    Ok((status, body.0))
}

async fn get_value(
    state: &Arc<AppState>,
    topic: &str,
    key: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        crate::server::routes::get_kv_value(
            State(Arc::clone(state)),
            Path((topic.to_string(), key.to_string())),
        ),
    )
    .await
    .context("GET /stores/:id/:key must not hang")?
    .into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Ok((status, body))
}

#[tokio::test]
async fn issue1266_removal_first_rekey_gap_keeps_survivor_store() -> Result<()> {
    let (state, dir) = loopback_survivor_state().await?;
    let f = f1_gss_rotation_fixture_on(state, dir, "issue1266").await?;
    let admin = f.admin_kp.agent_id();
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());

    // The survivor opens the group store and holds content before the
    // removal, exactly as Bob does in the #1266 integration test.
    let (status, created) = open_group_store(&f.state, &f.group_id).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "open survivor store: {created}"
    );
    let topic = created["topic"]
        .as_str()
        .context("store topic")?
        .to_string();
    let handle = f
        .state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .cloned()
        .context("store handle registered")?;
    handle
        .put(
            "pre".to_string(),
            b"pre-value".to_vec(),
            "text/plain".to_string(),
        )
        .await?;
    let (status, body) = get_value(&f.state, &topic, "pre").await?;
    assert_eq!(status, StatusCode::OK, "pre-removal read: {body}");

    // Metadata-first: the signed removal lands, advances the epoch and
    // fail-closes the shared secret. The survivor is still an active member.
    let removed =
        apply_named_group_metadata_event(&f.state, f.remove_event.clone(), admin, true, None).await;
    assert!(removed.should_exit, "signed MemberRemoved must apply");
    {
        let groups = f.state.named_groups.read().await;
        let info = groups.get(&f.group_id).context("group after removal")?;
        assert_eq!(info.secret_epoch, f.new_epoch);
        assert!(info.shared_secret.is_none(), "removal-first gap is keyless");
        assert!(info.has_active_member(&local_hex), "survivor stays active");
    }

    // Store activity inside the gap runs the refresh hook.
    let (gap_status, gap_body) = get_value(&f.state, &topic, "pre").await?;
    let registered_in_gap = f.state.kv_stores.read().await.contains_key(&topic);
    // Fail closed for confidentiality: the removed member still holds the
    // old secret, so nothing may be sealed in the gap (neither under the old
    // epoch nor without a key).
    let gap_write = handle
        .put(
            "gap".to_string(),
            b"gap-value".to_vec(),
            "text/plain".to_string(),
        )
        .await;
    assert!(
        matches!(gap_write, Err(x0x::error::IdentityError::Unauthorized(_))),
        "a keyless survivor must refuse local writes in the gap: {gap_write:?}"
    );

    // The envelope lands and installs the rotated secret.
    let delivered =
        apply_named_group_metadata_event(&f.state, f.envelope_event.clone(), admin, true, None)
            .await;
    assert!(!delivered.should_exit);
    {
        let groups = f.state.named_groups.read().await;
        let info = groups.get(&f.group_id).context("group after share")?;
        assert_eq!(info.secret_epoch, f.new_epoch);
        assert!(
            info.shared_secret.as_deref() == Some(f.new_secret.as_slice()),
            "the share must install the rotated secret"
        );
    }

    // The survivor's store must work again: same handle, readable, and
    // writable at the rotated epoch.
    let (status, body) = get_value(&f.state, &topic, "pre").await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "post-share GET: {body}; gap GET was {gap_status} {gap_body}; \
         handle registered in gap: {registered_in_gap}"
    );
    assert_eq!(body["value"], BASE64.encode(b"pre-value"));
    assert!(
        registered_in_gap,
        "a transient missing secret must not unregister the store"
    );
    assert_eq!(
        gap_status,
        StatusCode::OK,
        "an active member keeps reading its replica in the gap: {gap_body}"
    );
    handle
        .put(
            "post".to_string(),
            b"post-value".to_vec(),
            "text/plain".to_string(),
        )
        .await?;
    let (status, reopened) = open_group_store(&f.state, &f.group_id).await?;
    assert_eq!(status, StatusCode::OK, "reuse the live handle: {reopened}");
    assert_eq!(reopened["epoch"].as_u64(), Some(f.new_epoch));
    Ok(())
}

async fn wait_for_value(
    state: &Arc<AppState>,
    topic: &str,
    key: &str,
    deadline: Duration,
) -> Result<(StatusCode, serde_json::Value)> {
    let until = tokio::time::Instant::now() + deadline;
    loop {
        let (status, body) = get_value(state, topic, key).await?;
        if status == StatusCode::OK || tokio::time::Instant::now() >= until {
            return Ok((status, body));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// #1266 follow-up (a): a sealed record that reaches the survivor inside the
/// keyless gap cannot be opened and is dropped, not queued. When the share
/// installs and the store re-arms, the survivor must ask the group for
/// current state, so the dropped record comes back without a restart. Here
/// the first request is answered; the single retry is due only after the
/// holders' response cooldown.
///
/// Alice is a second encrypted sync on the survivor's own pub/sub (loopback
/// node, no peers), holding the admin identity and its own GSS context. Both
/// bootstrap requesters are silenced, as after convergence, so the only
/// state request on the side topic is the one the re-arm sends.
#[tokio::test]
async fn issue1266_record_dropped_in_rekey_gap_is_repaired_once() -> Result<()> {
    use x0x::kv::encrypted::KvSecureContext as _;
    let (state, dir) = loopback_survivor_state().await?;
    let f = f1_gss_rotation_fixture_on(state, dir, "issue1266repair").await?;
    let admin = f.admin_kp.agent_id();
    let (status, created) = open_group_store(&f.state, &f.group_id).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "open survivor store: {created}"
    );
    let topic = created["topic"]
        .as_str()
        .context("store topic")?
        .to_string();
    let bob = f
        .state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .cloned()
        .context("store handle registered")?;
    bob.silence_bootstrap_for_test();
    let baseline_requests = bob.state_sync_snapshot().requests_sent;

    // Alice's replica of the same store, at the pre-removal epoch.
    let parent = f
        .state
        .named_groups
        .read()
        .await
        .get(&f.group_id)
        .cloned()
        .context("parent group")?;
    let stable = parent.stable_group_id().to_string();
    let (store_id, alice_topic) = x0x::kv::encrypted::group_store_identity(&stable, "ws");
    assert_eq!(alice_topic, topic);
    let alice_ctx =
        Arc::new(x0x::groups::GssKvSecureContext::from_group(&parent).context("alice context")?);
    let alice_store = x0x::kv::KvStore::new_encrypted(
        store_id,
        "ws".to_string(),
        admin,
        stable.as_bytes().to_vec(),
        Arc::clone(&alice_ctx) as Arc<dyn x0x::kv::encrypted::KvSecureContext>,
    )?;
    let alice_peer = saorsa_gossip_types::PeerId::new([0xA1; 32]);
    let mut alice = x0x::kv::KvStoreSync::new(
        alice_store,
        f.state.agent.pubsub().context("survivor pubsub")?,
        topic.clone(),
        alice_peer,
        Some(admin),
    )?;
    alice.set_secure_context(
        Arc::clone(&alice_ctx) as Arc<dyn x0x::kv::encrypted::KvSecureContext>,
        None,
    );
    alice.set_author_signing(x0x::kv::encrypted::AuthorSigning::from_keypair(
        &f.admin_kp,
    )?);
    alice.silence_bootstrap();
    alice.start().await?;

    // Metadata-first removal: the survivor is keyless at the new epoch.
    let removed =
        apply_named_group_metadata_event(&f.state, f.remove_event.clone(), admin, true, None).await;
    assert!(removed.should_exit, "signed MemberRemoved must apply");
    let mut rotated = f
        .state
        .named_groups
        .read()
        .await
        .get(&f.group_id)
        .cloned()
        .context("group after removal")?;
    assert!(
        rotated.shared_secret.is_none(),
        "removal-first gap is keyless"
    );
    rotated.shared_secret = Some(f.new_secret.to_vec());
    alice_ctx.update_from_group(&rotated);
    assert_eq!(alice_ctx.current_epoch(), f.new_epoch);

    // Alice writes at the rotated epoch; the sealed record reaches the
    // keyless survivor, which must drop it.
    let delta = {
        let mut s = alice.write().await;
        s.put(
            "gap".to_string(),
            b"gap-value".to_vec(),
            "text/plain".to_string(),
            alice_peer,
        )?;
        let entry = s.get("gap").cloned().context("alice gap entry")?;
        x0x::kv::KvStoreDelta::for_put(
            "gap".to_string(),
            entry,
            (alice_peer, s.next_seq()?),
            s.current_version(),
        )
    };
    alice.publish_delta(alice_peer, delta).await?;
    tokio::time::timeout(
        Duration::from_secs(10),
        bob.wait_receive_rejected_for_test(),
    )
    .await
    .context("the survivor must receive and drop the gap record")?;
    let (status, body) = get_value(&f.state, &topic, "gap").await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "dropped in the gap: {body}");
    assert_eq!(body["error"], "key not found", "store stays bound: {body}");

    // The share installs; the next refresh re-arms the store.
    let delivered =
        apply_named_group_metadata_event(&f.state, f.envelope_event.clone(), admin, true, None)
            .await;
    assert!(!delivered.should_exit);
    let (status, body) = wait_for_value(&f.state, &topic, "gap", Duration::from_secs(15)).await?;
    let requests = bob.state_sync_snapshot().requests_sent - baseline_requests;
    let served = alice.state_sync_snapshot();
    assert_eq!(
        status,
        StatusCode::OK,
        "the gap record must be repaired without a restart: {body}; survivor \
         repair requests {requests}; responder received {} answered {}",
        served.requests_received,
        served.requests_answered
    );
    assert_eq!(body["value"], BASE64.encode(b"gap-value"));
    assert_eq!(requests, 1, "the first repair request recovered the record");
    assert_eq!(served.requests_received, 1);
    assert_eq!(served.requests_answered, 1);

    // Later refreshes at the same keyed epoch start no new repair; the
    // single retry waits out the cooldown.
    let (status, _) = get_value(&f.state, &topic, "gap").await?;
    assert_eq!(status, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        bob.state_sync_snapshot().requests_sent - baseline_requests,
        1,
        "no new repair without a new gap, and no early retry"
    );
    alice.cancel_sync();
    Ok(())
}

/// Alice's replica of the survivor's store: a second encrypted sync on the
/// survivor's own pub/sub (loopback node, no peers), signed by the F1 admin,
/// with its own GSS context. Its bootstrap requester is silenced.
struct AliceReplica {
    sync: x0x::kv::KvStoreSync,
    ctx: Arc<x0x::groups::GssKvSecureContext>,
    peer: saorsa_gossip_types::PeerId,
}

impl AliceReplica {
    async fn start(
        state: &Arc<AppState>,
        group_id: &str,
        admin_kp: &crate::identity::AgentKeypair,
        topic: &str,
    ) -> Result<Self> {
        let replica = Self::build(state, group_id, admin_kp, topic, 0xA1).await?;
        replica.sync.start().await?;
        Ok(replica)
    }

    /// The replica without its background loops (it can still publish).
    async fn build(
        state: &Arc<AppState>,
        group_id: &str,
        admin_kp: &crate::identity::AgentKeypair,
        topic: &str,
        peer_byte: u8,
    ) -> Result<Self> {
        let current = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .cloned()
            .context("group for Alice")?;
        let stable = current.stable_group_id().to_string();
        let (store_id, alice_topic) = x0x::kv::encrypted::group_store_identity(&stable, "ws");
        assert_eq!(alice_topic, topic);
        let ctx = Arc::new(
            x0x::groups::GssKvSecureContext::from_group(&current).context("alice context")?,
        );
        let store = x0x::kv::KvStore::new_encrypted(
            store_id,
            "ws".to_string(),
            admin_kp.agent_id(),
            stable.as_bytes().to_vec(),
            Arc::clone(&ctx) as Arc<dyn x0x::kv::encrypted::KvSecureContext>,
        )?;
        let peer = saorsa_gossip_types::PeerId::new([peer_byte; 32]);
        let mut sync = x0x::kv::KvStoreSync::new(
            store,
            state.agent.pubsub().context("survivor pubsub")?,
            topic.to_string(),
            peer,
            Some(admin_kp.agent_id()),
        )?;
        sync.set_secure_context(
            Arc::clone(&ctx) as Arc<dyn x0x::kv::encrypted::KvSecureContext>,
            None,
        );
        sync.set_author_signing(x0x::kv::encrypted::AuthorSigning::from_keypair(admin_kp)?);
        sync.silence_bootstrap();
        Ok(Self { sync, ctx, peer })
    }

    /// Move Alice to the rotated epoch: the survivor's post-removal view
    /// plus the rotated secret.
    async fn rotate(&self, state: &Arc<AppState>, group_id: &str, secret: &[u8; 32]) -> Result<()> {
        let mut rotated = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .cloned()
            .context("group after removal")?;
        rotated.shared_secret = Some(secret.to_vec());
        self.ctx.update_from_group(&rotated);
        Ok(())
    }

    async fn publish(&self, key: &str, value: &[u8]) -> Result<()> {
        let delta = {
            let mut s = self.sync.write().await;
            s.put(
                key.to_string(),
                value.to_vec(),
                "text/plain".to_string(),
                self.peer,
            )?;
            let entry = s.get(key).cloned().context("alice entry")?;
            x0x::kv::KvStoreDelta::for_put(
                key.to_string(),
                entry,
                (self.peer, s.next_seq()?),
                s.current_version(),
            )
        };
        self.sync.publish_delta(self.peer, delta).await?;
        Ok(())
    }
}

async fn wait_for_count(mut read: impl FnMut() -> u64, at_least: u64, deadline: Duration) -> u64 {
    let until = tokio::time::Instant::now() + deadline;
    loop {
        let value = read();
        if value >= at_least || tokio::time::Instant::now() >= until {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// #1266 review r2 (P2, sync.rs): the holder served a full state shortly
/// before the gap ended, so it suppresses the first repair request inside
/// its 15 s response cooldown and sends no evidence. The survivor must retry
/// exactly once after the cooldown, freshly authorized and sealed, and the
/// dropped record must come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1266_repair_retries_once_after_responder_cooldown() -> Result<()> {
    let (state, dir) = loopback_survivor_state().await?;
    let f = f1_gss_rotation_fixture_on(state, dir, "issue1266cooldown").await?;
    let admin = f.admin_kp.agent_id();
    let (status, created) = open_group_store(&f.state, &f.group_id).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "open survivor store: {created}"
    );
    let topic = created["topic"]
        .as_str()
        .context("store topic")?
        .to_string();
    let bob = f
        .state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .cloned()
        .context("store handle registered")?;
    bob.silence_bootstrap_for_test();
    let alice = AliceReplica::start(&f.state, &f.group_id, &f.admin_kp, &topic).await?;

    // Pre-gap: Alice holds content, and serves a full state now.
    alice.publish("seed", b"seed-value").await?;
    let (status, body) = wait_for_value(&f.state, &topic, "seed", Duration::from_secs(10)).await?;
    assert_eq!(status, StatusCode::OK, "seed replicated: {body}");
    // Only the first request is wanted here: drop the repair before its
    // retry is due.
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.request_state_repair()).await;
    let answered = wait_for_count(
        || alice.sync.state_sync_snapshot().requests_answered,
        1,
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(answered, 1, "Alice served a full state before the gap");
    let baseline_requests = bob.state_sync_snapshot().requests_sent;

    // The gap: a record at the rotated epoch is dropped.
    let removed =
        apply_named_group_metadata_event(&f.state, f.remove_event.clone(), admin, true, None).await;
    assert!(removed.should_exit, "signed MemberRemoved must apply");
    alice.rotate(&f.state, &f.group_id, &f.new_secret).await?;
    alice.publish("gap", b"gap-value").await?;
    tokio::time::timeout(
        Duration::from_secs(10),
        bob.wait_receive_rejected_for_test(),
    )
    .await
    .context("the survivor must receive and drop the gap record")?;
    let (status, body) = get_value(&f.state, &topic, "gap").await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "dropped in the gap: {body}");

    // The share installs well inside Alice's cooldown.
    let delivered =
        apply_named_group_metadata_event(&f.state, f.envelope_event.clone(), admin, true, None)
            .await;
    assert!(!delivered.should_exit);
    let (status, body) = wait_for_value(&f.state, &topic, "gap", Duration::from_secs(40)).await?;
    let served = alice.sync.state_sync_snapshot();
    let requests = bob.state_sync_snapshot().requests_sent - baseline_requests;
    assert_eq!(
        status,
        StatusCode::OK,
        "the retry must repair the gap record: {body}; survivor requests {requests}; \
         responder cooldown rejections {} answered {}",
        served.rejected_cooldown,
        served.requests_answered
    );
    assert_eq!(body["value"], BASE64.encode(b"gap-value"));
    assert_eq!(
        served.rejected_cooldown, 1,
        "the first repair request fell in the cooldown"
    );
    assert_eq!(requests, 2, "one repair request plus exactly one retry");
    assert_eq!(served.requests_answered, 2);
    alice.sync.cancel_sync();
    Ok(())
}

/// #1266 review r2 (P3): refreshes that race the share install must start
/// exactly one repair per key gap. A stale refresh observes `KeyPending` and
/// is paused before its latch decision while the share installs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1266_concurrent_refreshes_start_one_repair_per_gap() -> Result<()> {
    use crate::server::routes::stores::key_gap_test_seam as seam;
    let (state, dir) = loopback_survivor_state().await?;
    let f = f1_gss_rotation_fixture_on(state, dir, "issue1266latch").await?;
    let admin = f.admin_kp.agent_id();
    let (status, created) = open_group_store(&f.state, &f.group_id).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "open survivor store: {created}"
    );
    let topic = created["topic"]
        .as_str()
        .context("store topic")?
        .to_string();
    f.state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .context("store handle registered")?
        .silence_bootstrap_for_test();

    let removed =
        apply_named_group_metadata_event(&f.state, f.remove_event.clone(), admin, true, None).await;
    assert!(removed.should_exit, "signed MemberRemoved must apply");
    // One refresh in the gap latches KeyPending.
    let (status, _) = get_value(&f.state, &topic, "absent").await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A second, stale KeyPending refresh pauses before its latch decision.
    let pause = seam::arm(&topic);
    let stale = tokio::spawn({
        let state = Arc::clone(&f.state);
        let topic = topic.clone();
        async move { get_value(&state, &topic, "absent").await }
    });
    tokio::time::timeout(Duration::from_secs(10), pause.reached.notified())
        .await
        .context("the stale refresh reached the pause")?;
    let mut install = tokio::spawn({
        let state = Arc::clone(&f.state);
        let envelope = f.envelope_event.clone();
        async move {
            apply_named_group_metadata_event(&state, envelope, admin, true, None)
                .await
                .should_exit
        }
    });
    let installed_while_paused = tokio::time::timeout(Duration::from_secs(2), &mut install)
        .await
        .is_ok();
    if installed_while_paused {
        // The share installed under the paused refresh: a Current refresh
        // takes the latch before the stale one resumes.
        let _ = get_value(&f.state, &topic, "absent").await?;
        pause.release.notify_one();
        let _ = stale.await??;
    } else {
        pause.release.notify_one();
        let _ = stale.await??;
        let should_exit = tokio::time::timeout(Duration::from_secs(10), install)
            .await
            .context("the share installs after the paused refresh")??;
        assert!(!should_exit);
    }
    for _ in 0..3 {
        let _ = get_value(&f.state, &topic, "absent").await?;
    }
    assert_eq!(
        seam::repairs(&topic),
        1,
        "exactly one repair per key gap (share installed while the stale refresh \
         was paused: {installed_while_paused})"
    );
    assert!(
        !installed_while_paused,
        "the latch decision must hold the group read guard, so the share waits for it"
    );
    Ok(())
}

fn loopback_daemon_config(
    root: &std::path::Path,
    tag: &str,
) -> Result<crate::server::DaemonConfig> {
    Ok(serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": root.join("data"),
        "identity_dir": root.join("identity"),
        "bootstrap_peers": [],
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": format!("x0x.test.1266.{tag}.{}", std::process::id())
    }))?)
}

fn loopback_daemon_options() -> crate::server::ServeOptions {
    crate::server::ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..crate::server::ServeOptions::default()
    }
}

fn tracked_task_count(state: &AppState) -> usize {
    state
        .agent
        .tracked_tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .handles
        .len()
}

fn unfinished_tracked_since(state: &AppState, from: usize) -> usize {
    state
        .agent
        .tracked_tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .handles
        .iter()
        .skip(from)
        .filter(|handle| !handle.is_finished())
        .count()
}

/// #1266 review r2 (P2, stores.rs): a real daemon shuts down while a GSS
/// store is open (and, with `repair_in_flight`, while a key-gap repair is
/// parked on the GSS publication gate). Shutdown must return, release the
/// daemon state, the Agent (and with it history.db) and the store's sync,
/// and a relaunch on the same directories must succeed.
async fn daemon_shutdown_releases_gss_store(repair_in_flight: bool) -> Result<()> {
    use crate::server::routes::stores::key_gap_test_seam as seam;
    let root = tempfile::tempdir()?;
    let tag = if repair_in_flight { "repair" } else { "store" };
    let config = loopback_daemon_config(root.path(), tag)?;
    let handle =
        crate::server::serve_with_options(config.clone(), loopback_daemon_options()).await?;
    let state = handle.test_state.upgrade().context("live daemon state")?;
    let state_weak = Arc::downgrade(&state);
    let agent_weak = Arc::downgrade(&state.agent);
    let F1GssRotationFixture {
        state,
        admin_kp,
        group_id,
        remove_event,
        envelope_event,
        ..
    } = f1_gss_rotation_fixture_on(state, tempfile::tempdir()?, "issue1266shutdown").await?;
    let admin = admin_kp.agent_id();
    let (status, created) = open_group_store(&state, &group_id).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "open survivor store: {created}"
    );
    let topic = created["topic"]
        .as_str()
        .context("store topic")?
        .to_string();
    let bob = state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .cloned()
        .context("store handle registered")?;
    bob.silence_bootstrap_for_test();
    let sync_weak = bob.sync_weak_for_test();
    let mut gate = None;
    if repair_in_flight {
        let baseline_requests = bob.state_sync_snapshot().requests_sent;
        let removed =
            apply_named_group_metadata_event(&state, remove_event, admin, true, None).await;
        assert!(removed.should_exit, "signed MemberRemoved must apply");
        let (status, _) = get_value(&state, &topic, "absent").await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let delivered =
            apply_named_group_metadata_event(&state, envelope_event, admin, true, None).await;
        assert!(!delivered.should_exit);
        // Hold the publication gate so the repair parks on it.
        gate = Some(Arc::clone(&state.gss_publication_gate).write_owned().await);
        let tracked_before = tracked_task_count(&state);
        let (status, _) = get_value(&state, &topic, "absent").await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Exactly one repair for this store. Other daemon work may also be
        // tracked in this window (seen on Linux CI), so the tracked-task
        // check only requires the repair to be among the unfinished tasks.
        assert_eq!(seam::repairs(&topic), 1, "exactly one repair starts");
        assert!(
            unfinished_tracked_since(&state, tracked_before) >= 1,
            "the repair runs as a tracked Agent task"
        );
        assert_eq!(
            bob.state_sync_snapshot().requests_sent,
            baseline_requests,
            "the repair is parked on the publication gate"
        );
        // Shutdown begins: the Agent's shutdown token must end the parked
        // wait itself, while the gate is still held, not the drain's abort.
        state.agent.begin_shutdown();
        // Every tracked task honours the shutdown token; allow the other
        // tracked work a short margin to observe it too.
        let parked = wait_for_count(
            || u64::from(unfinished_tracked_since(&state, tracked_before) == 0),
            1,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(parked, 1, "the shutdown token ends the parked repair");
    }
    drop(bob);
    drop(state);

    let result = tokio::time::timeout(Duration::from_secs(60), handle.shutdown_and_wait())
        .await
        .context("shutdown returns within 60 s")?;
    assert!(result.is_ok(), "shutdown: {result:?}");
    let released = wait_for_count(
        || {
            u64::from(
                state_weak.strong_count() == 0
                    && agent_weak.strong_count() == 0
                    && sync_weak.strong_count() == 0,
            )
        },
        1,
        Duration::from_secs(10),
    )
    .await
        == 1;
    assert!(
        released,
        "shutdown must release the daemon state ({}), the Agent ({}) and the store sync ({})",
        state_weak.strong_count(),
        agent_weak.strong_count(),
        sync_weak.strong_count()
    );
    drop(gate);
    // The same data and identity directories: the instance locks and
    // history.db must be free.
    let relaunched = tokio::time::timeout(
        Duration::from_secs(60),
        crate::server::serve_with_options(config, loopback_daemon_options()),
    )
    .await
    .context("relaunch returns within 60 s")?
    .context("relaunch on the same directories")?;
    tokio::time::timeout(Duration::from_secs(60), relaunched.shutdown_and_wait())
        .await
        .context("relaunched daemon shuts down")??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1266_daemon_shutdown_releases_open_gss_store() -> Result<()> {
    daemon_shutdown_releases_gss_store(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1266_daemon_shutdown_with_repair_in_flight_releases_state() -> Result<()> {
    daemon_shutdown_releases_gss_store(true).await
}

/// #1266 review r3: a serve marker is not proof that the survivor holds the
/// state. Alice serves her current-epoch state to another requester while
/// the survivor is keyless, so the survivor drops it. When the survivor's
/// first repair request falls in Alice's cooldown, that serve's marker
/// arrives late and is valid at the survivor's epoch. The repair must still
/// send its single retry, and the dropped record must come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1266_delayed_marker_does_not_cancel_the_repair_retry() -> Result<()> {
    let (state, dir) = loopback_survivor_state().await?;
    let f = f1_gss_rotation_fixture_on(state, dir, "issue1266marker").await?;
    let admin = f.admin_kp.agent_id();
    let (status, created) = open_group_store(&f.state, &f.group_id).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "open survivor store: {created}"
    );
    let topic = created["topic"]
        .as_str()
        .context("store topic")?
        .to_string();
    let bob = f
        .state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .cloned()
        .context("store handle registered")?;
    bob.silence_bootstrap_for_test();
    let alice = AliceReplica::start(&f.state, &f.group_id, &f.admin_kp, &topic).await?;
    alice.publish("seed", b"seed-value").await?;
    let (status, body) = wait_for_value(&f.state, &topic, "seed", Duration::from_secs(10)).await?;
    assert_eq!(status, StatusCode::OK, "seed replicated: {body}");
    // Another requester: Alice's identity on a second peer id, with no
    // background loops, so it never answers anything itself.
    let other = AliceReplica::build(&f.state, &f.group_id, &f.admin_kp, &topic, 0xA2).await?;

    // The gap. Alice writes at the rotated epoch without publishing, then
    // serves her full state to another requester (her own identity on a
    // second peer id). The keyless survivor drops that serve.
    let removed =
        apply_named_group_metadata_event(&f.state, f.remove_event.clone(), admin, true, None).await;
    assert!(removed.should_exit, "signed MemberRemoved must apply");
    alice.rotate(&f.state, &f.group_id, &f.new_secret).await?;
    {
        let mut s = alice.sync.write().await;
        s.put(
            "gap".to_string(),
            b"gap-value".to_vec(),
            "text/plain".to_string(),
            alice.peer,
        )?;
    }
    other.rotate(&f.state, &f.group_id, &f.new_secret).await?;
    let _ = tokio::time::timeout(Duration::from_secs(2), other.sync.request_state_repair()).await;
    let answered = wait_for_count(
        || alice.sync.state_sync_snapshot().requests_answered,
        1,
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        answered, 1,
        "Alice served her current-epoch state in the gap"
    );
    tokio::time::timeout(
        Duration::from_secs(10),
        bob.wait_receive_rejected_for_test(),
    )
    .await
    .context("the survivor must receive and drop the served state")?;
    let (status, body) = get_value(&f.state, &topic, "gap").await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "dropped in the gap: {body}");
    let baseline_requests = bob.state_sync_snapshot().requests_sent;

    // The share installs inside Alice's cooldown: the first repair request
    // is suppressed.
    let delivered =
        apply_named_group_metadata_event(&f.state, f.envelope_event.clone(), admin, true, None)
            .await;
    assert!(!delivered.should_exit);
    let (status, _) = get_value(&f.state, &topic, "gap").await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let suppressed = wait_for_count(
        || alice.sync.state_sync_snapshot().rejected_cooldown,
        1,
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        suppressed, 1,
        "the first repair request fell in the cooldown"
    );

    // The serve's marker arrives late, valid at the survivor's epoch.
    alice.sync.publish_served_marker_for_test().await?;

    let (status, body) = wait_for_value(&f.state, &topic, "gap", Duration::from_secs(40)).await?;
    let served = alice.sync.state_sync_snapshot();
    let requests = bob.state_sync_snapshot().requests_sent - baseline_requests;
    assert_eq!(
        status,
        StatusCode::OK,
        "a late marker must not cancel the retry: {body}; survivor requests {requests}; \
         responder cooldown rejections {} answered {}",
        served.rejected_cooldown,
        served.requests_answered
    );
    assert_eq!(body["value"], BASE64.encode(b"gap-value"));
    assert_eq!(requests, 2, "one repair request plus exactly one retry");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        bob.state_sync_snapshot().requests_sent - baseline_requests,
        2,
        "the repair is capped at two requests"
    );
    alice.sync.cancel_sync();
    Ok(())
}
