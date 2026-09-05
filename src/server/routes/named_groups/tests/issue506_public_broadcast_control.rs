//! #506 wire-level negative control: a subscribed PEER must observe no public
//! discovery broadcast when a Hidden group is withdrawn — proven against a
//! PublicDirectory tombstone positive control on the SAME topic and the SAME
//! subscription, so the negative observation cannot be vacuous.
//!
//! Two real agents on loopback networking (the `hs_f2_membership_cluster`
//! harness pattern): the owner drives the REAL `POST /groups/:id/state/withdraw`
//! endpoint for a Hidden group first and a PublicDirectory group second. The
//! observer subscribes to `GLOBAL_GROUP_DISCOVERY_TOPIC` before either
//! withdrawal. The public tombstone's arrival closes the observation window:
//! by then any Hidden broadcast (published earlier, same topic, same fan-out
//! path) would have been observed. A residual quiet-window drain follows.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribed_peer_sees_no_public_broadcast_for_hidden_withdrawal() -> Result<()> {
    let owner_dir = tempfile::tempdir()?;
    let observer_dir = tempfile::tempdir()?;

    let loopback_cfg = || x0x::network::NetworkConfig {
        bind_addr: Some(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("loopback addr"),
        ),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..x0x::network::NetworkConfig::default()
    };

    async fn build_agent(
        dir: &tempfile::TempDir,
        net_cfg: x0x::network::NetworkConfig,
    ) -> x0x::error::Result<x0x::Agent> {
        {
            Agent::builder()
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_peer_cache_disabled()
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_network_config(net_cfg)
                .build()
                .await
        }
    }

    let owner_agent = Arc::new(build_agent(&owner_dir, loopback_cfg()).await?);
    let observer_agent = Arc::new(build_agent(&observer_dir, loopback_cfg()).await?);
    owner_agent.join_network().await?;
    observer_agent.join_network().await?;

    let owner_net = owner_agent.network().expect("owner network").clone();
    let observer_net = observer_agent.network().expect("observer network").clone();
    let observer_addr = {
        let a = observer_net.bound_addr().await.expect("observer bound");
        if a.ip().is_unspecified() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                a.port(),
            )
        } else {
            a
        }
    };
    owner_net.connect_addr(observer_addr).await?;
    let observer_peer = ant_quic::PeerId(observer_agent.machine_id().0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if owner_net.is_connected(&observer_peer).await {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if !owner_net.is_connected(&observer_peer).await {
        eprintln!("SKIP: loopback connect unavailable in this environment");
        return Ok(());
    }

    // Pubsub readiness barrier (the hs_f2 `await_restart_gossip_ready`
    // pattern): `is_connected` proves only the QUIC transport. Both sides
    // publish FRESH nonce-tagged probes on the exact topic under observation
    // and each awaits the REMOTE probe, so bidirectional gossip routing on
    // `GLOBAL_GROUP_DISCOVERY_TOPIC` is proven live BEFORE the withdrawals.
    // Probe payloads are not valid metadata-event JSON; the classifiers below
    // skip them, and a real peer's DirectoryMessage decoder drops them.
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);
        let base = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut owner_probe_sub = owner_agent.subscribe(GLOBAL_GROUP_DISCOVERY_TOPIC).await?;
        let mut observer_probe_sub = observer_agent
            .subscribe(GLOBAL_GROUP_DISCOVERY_TOPIC)
            .await?;
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let mut round = 0u64;
            loop {
                let owner_probe =
                    format!("issue506/discovery-route-probe/{base}.{round}/owner").into_bytes();
                let observer_probe =
                    format!("issue506/discovery-route-probe/{base}.{round}/observer").into_bytes();
                owner_agent
                    .publish(GLOBAL_GROUP_DISCOVERY_TOPIC, owner_probe.clone())
                    .await?;
                observer_agent
                    .publish(GLOBAL_GROUP_DISCOVERY_TOPIC, observer_probe.clone())
                    .await?;
                let mut owner_got = false;
                let mut observer_got = false;
                let quiet = tokio::time::sleep(std::time::Duration::from_secs(1));
                tokio::pin!(quiet);
                while !(owner_got && observer_got) {
                    tokio::select! {
                        _ = &mut quiet => break,
                        message = owner_probe_sub.recv() => {
                            let Some(message) = message else {
                                anyhow::bail!("owner discovery subscription closed");
                            };
                            if message.payload.as_ref() == observer_probe.as_slice() {
                                owner_got = true;
                            }
                        }
                        message = observer_probe_sub.recv() => {
                            let Some(message) = message else {
                                anyhow::bail!("observer discovery subscription closed");
                            };
                            if message.payload.as_ref() == owner_probe.as_slice() {
                                observer_got = true;
                            }
                        }
                    }
                }
                if owner_got && observer_got {
                    return Ok(());
                }
                round += 1;
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "gossip delivery on the global discovery topic never became \
                 bidirectionally ready within 20 s"
            )
        })??;
    }

    // Subscribe BEFORE any withdrawal so no broadcast can slip past.
    let mut discovery_sub = observer_agent
        .subscribe(GLOBAL_GROUP_DISCOVERY_TOPIC)
        .await?;

    let owner_state =
        secure_endpoint_test_state_at(owner_dir.path(), Arc::clone(&owner_agent)).await?;
    let hidden_id = "e1".repeat(16);
    let public_id = "f2".repeat(16);
    let group = |name: &str, id: &str, discoverability: x0x::groups::GroupDiscoverability| {
        let policy = x0x::groups::GroupPolicy {
            discoverability,
            ..Default::default()
        };
        x0x::groups::GroupInfo::with_policy(
            name.to_string(),
            "issue506 wire control fixture".to_string(),
            owner_agent.agent_id(),
            id.to_string(),
            policy,
        )
    };
    let hidden = group(
        "Issue506WireHidden",
        &hidden_id,
        x0x::groups::GroupDiscoverability::Hidden,
    );
    let public = group(
        "Issue506WirePublic",
        &public_id,
        x0x::groups::GroupDiscoverability::PublicDirectory,
    );
    let hidden_stable = hidden.stable_group_id().to_string();
    let public_stable = public.stable_group_id().to_string();
    {
        let mut groups = owner_state.named_groups.write().await;
        groups.insert(hidden_id.clone(), hidden);
        groups.insert(public_id.clone(), public);
    }

    let withdraw_via_real_endpoint = |id: String| {
        let state = Arc::clone(&owner_state);
        async move {
            let resp = withdraw_group_state(
                State(state),
                axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                    durable: true,
                }),
                Path(id.clone()),
            )
            .await
            .into_response();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
            anyhow::Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
        }
    };

    // Hidden FIRST: any public broadcast for it would be in flight before the
    // public tombstone is even published.
    let (status, body) = withdraw_via_real_endpoint(hidden_id.clone()).await?;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "hidden withdraw failed: {body}"
    );
    let (status, body) = withdraw_via_real_endpoint(public_id.clone()).await?;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "public withdraw failed: {body}"
    );

    // Classify every message seen on the public discovery topic. The wire
    // shape is internally tagged — {"event": "group_card_published", ...} —
    // per `#[serde(tag = "event", rename_all = "snake_case")]`.
    fn is_card_publish(value: &serde_json::Value) -> bool {
        value["event"].as_str() == Some("group_card_published")
    }

    fn references_hidden(value: &serde_json::Value, hidden_stable: &str) -> bool {
        is_card_publish(value)
            && (value["group_id"].as_str() == Some(hidden_stable)
                || value["card"]["name"].as_str() == Some("Issue506WireHidden"))
    }

    let mut hidden_violations: Vec<String> = Vec::new();
    let mut public_tombstone: Option<serde_json::Value> = None;
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        // Returns Ok(()) once the PublicDirectory tombstone is observed.
        loop {
            match discovery_sub.recv().await {
                Some(message) => {
                    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&message.payload)
                    else {
                        continue;
                    };
                    let is_public_tombstone = is_card_publish(&value)
                        && value["group_id"].as_str() == Some(public_stable.as_str());
                    if is_public_tombstone {
                        public_tombstone = Some(value);
                        return Ok(());
                    }
                }
                None => anyhow::bail!("public discovery subscription closed unexpectedly"),
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "positive control failed: the PublicDirectory tombstone never reached the \
             subscribed peer within 45 s — the observation channel is not proven live, \
             so the negative result would be vacuous"
        )
    })??;

    let tombstone = public_tombstone.expect("positive control observed");
    assert_eq!(
        tombstone["card"]["withdrawn"],
        serde_json::json!(true),
        "the observed public event must be the withdrawal tombstone"
    );

    // Residual quiet window after the tombstone: drain anything still in
    // flight and re-check for Hidden references.
    let quiet = tokio::time::sleep(std::time::Duration::from_secs(3));
    tokio::pin!(quiet);
    loop {
        tokio::select! {
            _ = &mut quiet => break,
            message = discovery_sub.recv() => {
                let Some(message) = message else { break };
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&message.payload) {
                    if references_hidden(&value, &hidden_stable) {
                        hidden_violations.push(value.to_string());
                    }
                }
            }
        }
    }

    assert!(
        hidden_violations.is_empty(),
        "#506 wire-level: subscribed peer observed public discovery broadcast(s) for \
         the withdrawn Hidden group: {hidden_violations:?}"
    );
    Ok(())
}
