//! #506 wire-level negative control: a subscribed PEER must observe no public
//! discovery broadcast when a Hidden group is withdrawn — proven against a
//! PublicDirectory tombstone positive control on the SAME topic and the SAME
//! subscription, so the negative observation cannot be vacuous.
//!
//! Two real agents on loopback networking (the `hs_f2_membership_cluster`
//! harness pattern), hermetically isolated: mDNS disabled and a network_id
//! unique to this test process, so the cluster can never touch the public
//! mesh or another test's plane. The owner drives the REAL
//! `POST /groups/:id/state/withdraw` endpoint for a Hidden group first and a
//! PublicDirectory group second. The public tombstone's arrival closes the
//! main observation window; a residual quiet-window drain follows. BOTH
//! windows classify every payload through the same
//! [`DiscoveryTopicScanner`], so a Hidden event is flagged whether it arrives
//! before or after the tombstone.
//!
//! Detection power is proven OFFLINE (no network) by
//! `discovery_scanner_flags_hidden_in_both_orderings`, which injects a valid
//! Hidden card-publish event into both orderings — [hidden, pub] and
//! [pub, hidden] — and requires the scanner to flag it. If the online
//! classification wiring ever regresses to "parse and discard", that test
//! fails first.

use super::*;

/// Shared classifier for EVERY window that observes the public discovery
/// topic. The wire shape is internally tagged —
/// `{"event": "group_card_published", ...}` — per
/// `#[serde(tag = "event", rename_all = "snake_case")]` on
/// `NamedGroupMetadataEvent`.
struct DiscoveryTopicScanner {
    hidden_stable: String,
    hidden_name: String,
    public_stable: String,
    hidden_violations: Vec<String>,
    public_tombstone: Option<serde_json::Value>,
}

impl DiscoveryTopicScanner {
    fn new(hidden_stable: String, hidden_name: &str, public_stable: String) -> Self {
        Self {
            hidden_stable,
            hidden_name: hidden_name.to_string(),
            public_stable,
            hidden_violations: Vec::new(),
            public_tombstone: None,
        }
    }

    fn is_card_publish(value: &serde_json::Value) -> bool {
        value["event"].as_str() == Some("group_card_published")
    }

    /// Classify ONE parsed payload. Returns `true` when the PublicDirectory
    /// tombstone positive control has been observed (closing the main
    /// window). Hidden references are recorded in BOTH windows — this is the
    /// #509-review fix: the previous main loop parsed and discarded.
    fn observe(&mut self, value: &serde_json::Value) -> bool {
        if !Self::is_card_publish(value) {
            return false; // probe payloads and other event kinds never carry cards
        }
        let group_id = value["group_id"].as_str().unwrap_or_default();
        if group_id == self.hidden_stable
            || value["card"]["name"].as_str() == Some(self.hidden_name.as_str())
        {
            self.hidden_violations.push(value.to_string());
        }
        if group_id == self.public_stable {
            self.public_tombstone = Some(value.clone());
            return true;
        }
        false
    }

    /// Parse and classify one raw payload; non-JSON payloads (readiness
    /// probes) are inert for classification.
    fn observe_payload(&mut self, payload: &[u8]) -> bool {
        match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(value) => self.observe(&value),
            Err(_) => false,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribed_peer_sees_no_public_broadcast_for_hidden_withdrawal() -> Result<()> {
    let owner_dir = tempfile::tempdir()?;
    let observer_dir = tempfile::tempdir()?;

    // Hermetic plane: no mDNS discovery (defaults ON — #337/#417 class) and a
    // network_id unique to this process, shared by both agents so they can
    // gossip with each other and nothing else.
    let network_id = format!("issue506-broadcast-control-{}", std::process::id());
    let loopback_cfg = || x0x::network::NetworkConfig {
        bind_addr: Some(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("loopback addr"),
        ),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        mdns_enabled: false,
        network_id: Some(network_id.clone()),
        ..x0x::network::NetworkConfig::default()
    };

    async fn build_agent(
        dir: &tempfile::TempDir,
        net_cfg: x0x::network::NetworkConfig,
    ) -> x0x::error::Result<x0x::Agent> {
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
        // This is a release acceptance control: a dead observation channel is
        // a real failure, never a skip-shaped pass.
        anyhow::bail!("loopback connect unavailable: the acceptance control cannot run");
    }

    // Pubsub readiness barrier (the hs_f2 `await_restart_gossip_ready`
    // pattern): `is_connected` proves only the QUIC transport. Both sides
    // publish FRESH nonce-tagged probes on the exact topic under observation
    // and each awaits the REMOTE probe, so bidirectional gossip routing on
    // `GLOBAL_GROUP_DISCOVERY_TOPIC` is proven live BEFORE the withdrawals.
    // Probe payloads are not valid metadata-event JSON; the scanner skips
    // them, and a real peer's DirectoryMessage decoder drops them.
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

    let mut scanner = DiscoveryTopicScanner::new(
        hidden_stable.clone(),
        "Issue506WireHidden",
        public_stable.clone(),
    );

    // Main window: EVERY parsed payload is classified (Hidden references are
    // recorded here too — the #509-review P2 fix); the window closes when the
    // PublicDirectory tombstone positive control is observed.
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            match discovery_sub.recv().await {
                Some(message) => {
                    if scanner.observe_payload(&message.payload) {
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

    let tombstone = scanner
        .public_tombstone
        .clone()
        .expect("positive control observed");
    assert_eq!(
        tombstone["card"]["withdrawn"],
        serde_json::json!(true),
        "the observed public event must be the withdrawal tombstone"
    );

    // Residual quiet window after the tombstone: drain anything still in
    // flight — classified through the SAME scanner — and re-check.
    let quiet = tokio::time::sleep(std::time::Duration::from_secs(3));
    tokio::pin!(quiet);
    loop {
        tokio::select! {
            _ = &mut quiet => break,
            message = discovery_sub.recv() => {
                let Some(message) = message else { break };
                scanner.observe_payload(&message.payload);
            }
        }
    }

    assert!(
        scanner.hidden_violations.is_empty(),
        "#506 wire-level: subscribed peer observed public discovery broadcast(s) for \
         the withdrawn Hidden group: {:?}",
        scanner.hidden_violations
    );
    Ok(())
}

/// Offline sequence/mutation control (no network): the scanner must flag an
/// injected VALID Hidden card-publish event in BOTH orderings — before the
/// public tombstone (main window) and after it (residual window). If the
/// online classification wiring ever regresses to "parse and discard", this
/// test fails first, so the wire control cannot silently pass through the
/// exact regression it exists to catch.
#[test]
fn discovery_scanner_flags_hidden_in_both_orderings() {
    let hidden_stable = "e1".repeat(16);
    let public_stable = "f2".repeat(16);
    let card_publish = |group_id: &str, name: &str, withdrawn: bool| {
        serde_json::json!({
            "event": "group_card_published",
            "group_id": group_id,
            "card": {
                "group_id": group_id,
                "name": name,
                "withdrawn": withdrawn,
            },
        })
    };
    let hidden_event = card_publish(&hidden_stable, "Issue506WireHidden", true);
    let public_event = card_publish(&public_stable, "Issue506WirePublic", true);
    let unrelated_event = serde_json::json!({
        "event": "member_added",
        "group_id": public_stable,
    });

    // [hidden, pub] — the exact production ordering under test: the Hidden
    // event arrives BEFORE the tombstone closes the main window.
    let mut scanner = DiscoveryTopicScanner::new(
        hidden_stable.clone(),
        "Issue506WireHidden",
        public_stable.clone(),
    );
    assert!(
        !scanner.observe(&hidden_event),
        "a Hidden card-publish must NOT close the main window"
    );
    assert!(
        scanner.observe(&public_event),
        "the PublicDirectory tombstone must close the main window"
    );
    assert_eq!(
        scanner.hidden_violations.len(),
        1,
        "#509-review P2: a valid Hidden card-publish before the tombstone MUST be flagged: {:?}",
        scanner.hidden_violations
    );
    assert!(scanner.public_tombstone.is_some());

    // [pub, hidden] — a late Hidden event lands in the residual window.
    let mut late = DiscoveryTopicScanner::new(
        hidden_stable.clone(),
        "Issue506WireHidden",
        public_stable.clone(),
    );
    assert!(late.observe(&public_event));
    assert!(!late.observe(&hidden_event));
    assert_eq!(
        late.hidden_violations.len(),
        1,
        "a valid Hidden card-publish after the tombstone MUST be flagged: {:?}",
        late.hidden_violations
    );

    // Green side: unrelated events and non-card kinds never produce
    // violations and never close the window.
    let mut clean = DiscoveryTopicScanner::new(hidden_stable, "Issue506WireHidden", public_stable);
    assert!(!clean.observe(&unrelated_event));
    assert!(!clean.observe_payload(b"issue506/discovery-route-probe/0.0/owner"));
    assert!(clean.hidden_violations.is_empty());
    assert!(clean.public_tombstone.is_none());
}
