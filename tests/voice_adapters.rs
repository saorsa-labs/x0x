//! Voice adapters integration proof (saorsa-webrtc V1.1/V1.2, `voice`
//! feature).
//!
//! Two in-process agents on loopback complete the QUIC-native signaling
//! flow (`CapabilityExchange → ConnectionConfirm → ConnectionReady`) over
//! real DMs via [`x0x::voice::X0xSignaling`], then exchange audio-sized
//! frames over [`x0x::voice::X0xLinkTransport`]
//! (`StreamProtocol::WebRtcV1`, inner `StreamType::Audio` lane), plus the
//! connect-ACL negative path.
//!
//! Network-bound tests are `#[ignore]` (integration tier, like
//! `tailnet_streams_integration.rs`): they bind real UDP sockets and wait
//! on loopback convergence.

#![cfg(feature = "voice")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use saorsa_webrtc_core::link_transport::{LinkTransport, StreamType};
use saorsa_webrtc_core::signaling::{SignalingMessage, SignalingTransport};
use tempfile::TempDir;
use x0x::network::NetworkConfig;
use x0x::voice::{X0xLinkTransport, X0xSignaling};
use x0x::DiscoveredAgent;

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        ..NetworkConfig::default()
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

async fn build_agent(dir: &TempDir, name: &str) -> Option<x0x::Agent> {
    match x0x::Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config())
        .build()
        .await
    {
        Ok(agent) => Some(agent),
        Err(e) if is_network_bind_permission_error(&e) => None,
        Err(e) => panic!("agent build failed: {e}"),
    }
}

fn normalize_loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    if addr.ip().is_unspecified() {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )
    } else {
        addr
    }
}

fn discovered_agent(
    agent: &x0x::Agent,
    addr: std::net::SocketAddr,
    now_secs: u64,
) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: None,
        addresses: vec![addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

/// Build a connected, mutually trusted alice/bob pair (tailnet harness
/// pattern). Returns None when the sandbox forbids UDP binds.
async fn trusted_pair(dir: &TempDir) -> Option<(Arc<x0x::Agent>, Arc<x0x::Agent>)> {
    let alice = Arc::new(build_agent(dir, "alice").await?);
    let bob = Arc::new(build_agent(dir, "bob").await?);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.expect("alice bound"));

    let connected = alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    assert_eq!(connected.0, bob.machine_id().0);

    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
    let alice_peer = ant_quic::PeerId(alice.machine_id().0);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network.is_connected(&alice_peer).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    Some((alice, bob))
}

/// Full V1 proof: three-message QUIC-native signaling over real DMs, then
/// 50 byte-identical audio frames over the `WebRtcV1` Audio lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback voice proof; binds UDP + waits on convergence. Integration tier."]
async fn signaling_flow_then_audio_frames_over_webrtc_lane() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    let alice_sig = X0xSignaling::new(Arc::clone(&alice));
    let bob_sig = X0xSignaling::new(Arc::clone(&bob));
    let bob_voice_id = alice_sig.local_peer_id(); // silence unused warnings symmetrically
    let _ = bob_voice_id;

    // CapabilityExchange: alice → bob.
    alice_sig
        .send_message(
            &x0x::voice::VoicePeerId(bob.agent_id()),
            SignalingMessage::CapabilityExchange {
                session_id: "call-1".into(),
                audio: true,
                video: false,
                data_channel: false,
                max_bandwidth_kbps: 64,
                quic_endpoint: None,
            },
        )
        .await
        .expect("send capability exchange");
    let (from, msg) = tokio::time::timeout(Duration::from_secs(20), bob_sig.receive_message())
        .await
        .expect("bob receives within deadline")
        .expect("bob receive ok");
    assert_eq!(from.0, alice.agent_id(), "sender attribution");
    assert!(
        matches!(msg, SignalingMessage::CapabilityExchange { ref session_id, audio: true, .. } if session_id == "call-1"),
        "unexpected first message: {msg:?}"
    );

    // ConnectionConfirm: bob → alice.
    bob_sig
        .send_message(
            &from,
            SignalingMessage::ConnectionConfirm {
                session_id: "call-1".into(),
                audio: true,
                video: false,
                data_channel: false,
                max_bandwidth_kbps: 64,
                quic_endpoint: None,
            },
        )
        .await
        .expect("send connection confirm");
    let (_, msg) = tokio::time::timeout(Duration::from_secs(20), alice_sig.receive_message())
        .await
        .expect("alice receives within deadline")
        .expect("alice receive ok");
    assert!(
        matches!(msg, SignalingMessage::ConnectionConfirm { ref session_id, .. } if session_id == "call-1")
    );

    // ConnectionReady: alice → bob.
    alice_sig
        .send_message(
            &x0x::voice::VoicePeerId(bob.agent_id()),
            SignalingMessage::ConnectionReady {
                session_id: "call-1".into(),
            },
        )
        .await
        .expect("send connection ready");
    let (_, msg) = tokio::time::timeout(Duration::from_secs(20), bob_sig.receive_message())
        .await
        .expect("bob receives ready")
        .expect("bob receive ok");
    assert!(matches!(msg, SignalingMessage::ConnectionReady { .. }));

    // Media: 50 audio-sized frames alice → bob on the Audio lane.
    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id());
    let mut bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id());
    bob_link.start().await.expect("bob link starts");
    alice_link.start().await.expect("alice link starts");

    let frames: Vec<Vec<u8>> = (0u8..50)
        .map(|i| {
            let mut f = vec![i; 200]; // opus-frame-sized
            f[0] = i; // sequence marker
            f
        })
        .collect();
    let peer = alice_link.default_peer().expect("default peer");
    for frame in &frames {
        alice_link
            .send(&peer, StreamType::Audio, frame)
            .await
            .expect("send audio frame");
    }

    let mut received = Vec::with_capacity(frames.len());
    let deadline = Instant::now() + Duration::from_secs(30);
    while received.len() < frames.len() && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, bob_link.receive()).await {
            Ok(Ok((_, ty, data))) => {
                assert_eq!(ty, StreamType::Audio);
                received.push(data);
            }
            Ok(Err(e)) => panic!("bob receive failed: {e}"),
            Err(_) => break,
        }
    }
    assert_eq!(received.len(), frames.len(), "all frames delivered");
    // Single ordered QUIC stream per lane ⇒ order and bytes both hold.
    assert_eq!(received, frames, "byte-identical, in order");

    alice_link.stop().await.expect("alice stop");
    bob_link.stop().await.expect("bob stop");
    alice.shutdown().await;
    bob.shutdown().await;
}

/// Connect-ACL negative path: the pair gate is an **inbound** gate
/// (`stream_acl_gate`, #131 — outbound relies on the identity gate). With
/// an Enabled policy on bob that does not list alice, bob's accept loop
/// rejects the `WebRtcV1` stream — no lane surfaces, no frame is
/// delivered. The voice protocol gets no ACL bypass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback ACL denial; binds UDP + waits on convergence. Integration tier."]
async fn connect_acl_denies_unlisted_voice_peer() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    // Bob enables a policy listing a random pair that is NOT
    // (alice, alice-machine) — alice becomes an unlisted peer inbound.
    let stranger_agent = x0x::identity::AgentId([0x55; 32]);
    let stranger_machine = x0x::identity::MachineId([0x66; 32]);
    bob.set_connect_policy(Arc::new(x0x::connect::ConnectPolicy::Enabled(
        x0x::connect::ConnectAcl {
            loaded_from: std::path::Path::new("/test").to_path_buf(),
            loaded_at_unix_ms: 0,
            allow: vec![x0x::connect::ConnectAllowEntry {
                description: None,
                agent_id: stranger_agent,
                machine_id: stranger_machine,
                targets: vec!["127.0.0.1:22".parse().expect("loopback literal")],
            }],
        },
    )));

    let mut bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id());
    bob_link.start().await.expect("bob link starts");
    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id());
    alice_link.start().await.expect("alice link starts");

    // Alice's open/first-write may succeed locally (the reset races the
    // handshake); what MUST hold is that bob never surfaces the lane.
    let peer = alice_link.default_peer().expect("default peer");
    let _ = alice_link.send(&peer, StreamType::Audio, &[0u8; 200]).await;

    let nothing = tokio::time::timeout(Duration::from_secs(5), bob_link.receive()).await;
    assert!(
        nothing.is_err(),
        "bob must not receive frames from an ACL-unlisted peer: {nothing:?}"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
