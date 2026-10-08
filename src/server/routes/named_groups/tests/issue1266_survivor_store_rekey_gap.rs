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
