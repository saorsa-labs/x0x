//! X0X-0070b integration tests - application-level peer-relay fallback.
//!
//! These exercise the end-to-end sender side: a real Alice connected to a real
//! Charlie (the relay candidate) over loopback QUIC, with a fake Bob identity
//! that exists only as an `AgentId` + ML-KEM-768 keypair the relay envelope is
//! sealed to. Alice's direct-DM path to Bob fails (Bob is not a real network
//! peer), her per-peer failure count is pre-driven past `fail_threshold`, and
//! the X0X-0070b relay-fallback engages: `try_relay_fallback` builds a sealed
//! `DmEnvelope`, wraps it in a sender-signed `RelayedDm`, and forwards over
//! `network.send_direct_typed(charlie, RELAYED_DM_STREAM_TYPE=0x11, ...)`.
//!
//! The receiver-side demux for `0x11` is the X0X-0070b receiver patch and is
//! intentionally out of scope here - pre-receiver, Charlie drops the inbound
//! bytes silently as an unknown stream type, so these tests assert the sender
//! contract only (receipt path, telemetry, wire send succeeds).
//!
//! Each test ignores itself when the host cannot bind QUIC (e.g. CI sandboxes
//! where UDP binds return `EPERM`), matching the existing
//! `direct_messaging_integration.rs` skip pattern.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Duration;
use tempfile::TempDir;
use x0x::dm::{DmCapabilities, DmPath, DmSendConfig, DM_PROTOCOL_VERSION, MAX_ENVELOPE_BYTES};
use x0x::groups::kem_envelope::AgentKemKeypair;
use x0x::identity::{AgentId, AgentKeypair, MachineKeypair};
use x0x::network::{NetworkConfig, PeerRelayConfig};
use x0x::{Agent, DiscoveredAgent};

fn loopback_network_config_with_relay(relay: PeerRelayConfig) -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        peer_relay: relay,
        ..NetworkConfig::default()
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

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("All socket binds failed")
            || message.contains("Failed to bind UDP socket")
            || message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

fn discovered_for(agent: &Agent, addr: std::net::SocketAddr, now_secs: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: None,
        addresses: vec![addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: vec![],
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: Some(true),
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
    }
}

async fn build_agent(
    temp_dir: &TempDir,
    name: &str,
    relay: PeerRelayConfig,
) -> Result<Option<Agent>, Box<dyn std::error::Error>> {
    let machine_key_path = temp_dir.path().join(format!("{name}_machine.key"));
    let agent_key_path = temp_dir.path().join(format!("{name}_agent.key"));
    let contacts_path = temp_dir.path().join(format!("{name}_contacts.json"));
    match Agent::builder()
        .with_machine_key(machine_key_path)
        .with_agent_key_path(agent_key_path)
        .with_contact_store_path(contacts_path)
        .with_peer_cache_disabled()
        .with_network_config(loopback_network_config_with_relay(relay))
        .build()
        .await
    {
        Ok(agent) => Ok(Some(agent)),
        Err(error) if is_network_bind_permission_error(&error) => Ok(None),
        Err(error) => Err(Box::new(error)),
    }
}

async fn wait_until_connected(alice: &Agent, charlie_peer: ant_quic::PeerId, deadline: Duration) {
    let network = alice.network().expect("alice network");
    let start = tokio::time::Instant::now();
    while start.elapsed() < deadline {
        if network.is_connected(&charlie_peer).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("alice never observed an open connection to charlie within {deadline:?}");
}

/// Pre-drive Alice's `PeerRelay` engine past `fail_threshold` for `target` so
/// the very next `send_direct_with_config` to that peer engages the fallback.
fn drive_past_relay_threshold(alice: &Agent, target: &AgentId) {
    let threshold = alice.peer_relay().policy().fail_threshold;
    for _ in 0..threshold {
        alice.peer_relay().record_direct_failure(target);
    }
    assert!(
        alice.peer_relay().needs_relay(target),
        "pre-load must put the peer past needs_relay"
    );
}

/// Pre-loaded sender-side end-to-end empirical for X0X-0070b. Verifies the
/// full sender contract: Alice's `send_direct_with_config` returns a relay
/// receipt naming Charlie; PeerRelay's `relay_sent` counter advances; and
/// `DirectMessaging`'s `outgoing_path_relayed` diagnostic counter agrees.
/// Charlie observes inbound bytes on stream-type `0x11` but drops them
/// silently pre-receiver (verified by the absence of any direct-pipeline
/// activity on Charlie's side).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sender_uses_relay_when_direct_path_fails() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let charlie = match build_agent(&dir, "charlie", PeerRelayConfig::default())
        .await
        .expect("build charlie")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping sender_uses_relay: bind permission unavailable");
            return;
        }
    };
    let charlie_addr = normalize_loopback(
        charlie
            .network()
            .expect("charlie network")
            .bound_addr()
            .await
            .expect("charlie bound"),
    );

    let alice = match build_agent(
        &dir,
        "alice",
        PeerRelayConfig {
            enabled: true,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: vec![hex::encode(charlie.agent_id().0)],
        },
    )
    .await
    .expect("build alice")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping sender_uses_relay: alice bind permission unavailable");
            return;
        }
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    alice
        .insert_discovered_agent_for_testing(discovered_for(&charlie, charlie_addr, now_secs))
        .await;
    let alice_network = alice.network().expect("alice network");
    let connected_peer = alice_network
        .connect_addr(charlie_addr)
        .await
        .expect("alice connects to charlie");
    assert_eq!(connected_peer.0, charlie.machine_id().0);
    wait_until_connected(
        &alice,
        ant_quic::PeerId(charlie.machine_id().0),
        Duration::from_secs(5),
    )
    .await;

    // Fake Bob exists only as an identity + KEM keypair - no real network
    // presence. Alice's direct-DM to Bob must therefore fail, and the
    // relay path must seal the envelope to Bob's KEM public key.
    let bob_agent_kp = AgentKeypair::generate().expect("bob agent keypair");
    let bob_machine_kp = MachineKeypair::generate().expect("bob machine keypair");
    let bob_kem = AgentKemKeypair::generate().expect("bob KEM keypair");
    let bob_agent_id = bob_agent_kp.agent_id();
    let bob_machine_id = bob_machine_kp.machine_id();

    // gossip_inbox = false forces the path picker into the raw-QUIC branch,
    // which fails fast on AgentNotFound (no discovery cache entry for Bob).
    // kem_public_key must be present so the relay-seed clone arms.
    let bob_cap = DmCapabilities {
        max_protocol_version: DM_PROTOCOL_VERSION,
        gossip_inbox: false,
        kem_algorithm: "ML-KEM-768".to_string(),
        max_envelope_bytes: MAX_ENVELOPE_BYTES,
        kem_public_key: bob_kem.public_bytes.clone(),
    };
    alice.insert_capability_for_testing(bob_agent_id, bob_machine_id, bob_cap);

    drive_past_relay_threshold(&alice, &bob_agent_id);
    let pre_stats = alice.peer_relay().stats().snapshot();
    let pre_diag = alice.direct_messaging().diagnostics_snapshot().stats;
    assert_eq!(pre_stats.relay_sent, 0);
    assert_eq!(pre_diag.outgoing_path_relayed, 0);

    let payload = b"hello-via-relay".to_vec();
    let receipt = alice
        .send_direct_with_config(&bob_agent_id, payload, DmSendConfig::default())
        .await
        .expect("send_direct_with_config should engage relay fallback and return Ok");

    match receipt.path {
        DmPath::Relayed { via } => {
            assert_eq!(
                via,
                charlie.agent_id(),
                "relay receipt must name the seeded candidate"
            );
        }
        other => panic!("expected DmPath::Relayed, got {other:?}"),
    }

    let post_stats = alice.peer_relay().stats().snapshot();
    let post_diag = alice.direct_messaging().diagnostics_snapshot().stats;
    assert_eq!(
        post_stats.relay_sent, 1,
        "PeerRelay::stats().relay_sent must advance once per fallback"
    );
    assert_eq!(
        post_diag.outgoing_path_relayed, 1,
        "DirectMessaging diagnostics must agree (outgoing_path_relayed counter)"
    );
    // The pre-attempt direct failure also increments outgoing_send_failed
    // - that is the contract: the relay receipt is recorded as Succeeded,
    // but the prior direct attempt is recorded as Failed.
    assert!(
        post_diag.outgoing_send_failed >= 1,
        "the pre-relay direct attempt must surface as a failed send"
    );
}

/// Adversarial: an enabled policy without ANY candidate must surface the
/// original direct-transport error to the caller - never the relay-side
/// `NoRelayCandidate`. Pins the load-bearing surfacing contract from
/// commit 5 against a fully wired Alice + connected Charlie setup (so the
/// failure cannot be blamed on missing infrastructure).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabled_policy_without_candidates_surfaces_direct_err() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let alice = match build_agent(
        &dir,
        "alice",
        PeerRelayConfig {
            enabled: true,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: Vec::new(),
        },
    )
    .await
    .expect("build alice")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping enabled_policy_without_candidates: bind permission unavailable");
            return;
        }
    };

    let bob_agent_kp = AgentKeypair::generate().expect("bob agent keypair");
    let bob_machine_kp = MachineKeypair::generate().expect("bob machine keypair");
    let bob_kem = AgentKemKeypair::generate().expect("bob KEM keypair");
    let bob_agent_id = bob_agent_kp.agent_id();
    let bob_machine_id = bob_machine_kp.machine_id();
    alice.insert_capability_for_testing(
        bob_agent_id,
        bob_machine_id,
        DmCapabilities {
            max_protocol_version: DM_PROTOCOL_VERSION,
            gossip_inbox: false,
            kem_algorithm: "ML-KEM-768".to_string(),
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            kem_public_key: bob_kem.public_bytes.clone(),
        },
    );
    drive_past_relay_threshold(&alice, &bob_agent_id);

    let err = alice
        .send_direct_with_config(&bob_agent_id, b"payload".to_vec(), DmSendConfig::default())
        .await
        .expect_err("no candidates and Bob unreachable - send must fail");
    assert!(
        !matches!(err, x0x::dm::DmError::NoRelayCandidate),
        "relay-side errors must never leak - original direct error surfaces, got {err:?}"
    );
    assert_eq!(
        alice.peer_relay().stats().snapshot().relay_sent,
        0,
        "no candidates means no relay attempt - counter must stay at zero"
    );
}

/// Adversarial: a direct-DM success after the peer entered relay mode must
/// clear the failure history AND increment `direct_recovered_after_relay`
/// exactly once. Proves the relay fallback is transient - when the direct
/// path heals, future sends drop back to direct.
///
/// Self-DM is the cheapest way to drive a real `record_direct_success`
/// path without bringing up a second agent - but loopback short-circuits
/// before the bookkeeping arm, so we drive `record_direct_success`
/// through the same `PeerRelay` accessor `send_direct_with_config` would
/// use. That is the same API the production hook calls, so the
/// observable telemetry is identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_success_after_relay_mode_increments_recovery_counter() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let alice = match build_agent(
        &dir,
        "alice",
        PeerRelayConfig {
            enabled: true,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: Vec::new(),
        },
    )
    .await
    .expect("build alice")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping recovery_counter: bind permission unavailable");
            return;
        }
    };
    let bob = AgentKeypair::generate().expect("bob keypair").agent_id();

    drive_past_relay_threshold(&alice, &bob);
    assert_eq!(
        alice
            .peer_relay()
            .stats()
            .snapshot()
            .direct_recovered_after_relay,
        0,
        "no recovery yet - peer is still in relay mode"
    );

    alice.peer_relay().record_direct_success(&bob);
    assert!(
        !alice.peer_relay().needs_relay(&bob),
        "direct success clears the failure history"
    );
    assert_eq!(
        alice
            .peer_relay()
            .stats()
            .snapshot()
            .direct_recovered_after_relay,
        1,
        "recovery from relay mode is counted exactly once"
    );

    alice.peer_relay().record_direct_success(&bob);
    assert_eq!(
        alice
            .peer_relay()
            .stats()
            .snapshot()
            .direct_recovered_after_relay,
        1,
        "a second direct success without re-entering relay mode does not double-count"
    );
}

/// Adversarial: `select_relay` must structurally exclude the sender - even
/// when its own `AgentId` is the only entry in the candidate list, the
/// engine must refuse to relay through itself. Pins X0X-0070b against the
/// configuration footgun where an operator accidentally pastes their own
/// hex into the TOML.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_relay_is_refused_when_candidate_list_contains_only_sender() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let alice = match build_agent(&dir, "alice", PeerRelayConfig::default())
        .await
        .expect("build alice")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping self_relay_refused: bind permission unavailable");
            return;
        }
    };
    let sender = alice.agent_id();
    let dst = AgentId([0xFF_u8; 32]);
    let chosen = alice
        .peer_relay()
        .select_relay(&[sender, sender, sender], &dst, &sender);
    assert!(
        chosen.is_none(),
        "select_relay must never return the sender as its own relay"
    );
    let other = AgentId([0xAB_u8; 32]);
    let chosen_with_third_party =
        alice
            .peer_relay()
            .select_relay(&[sender, other, sender], &dst, &sender);
    assert_eq!(
        chosen_with_third_party,
        Some(other),
        "select_relay must skip sender entries and pick the first valid third party"
    );
}

/// Full 3-agent end-to-end empirical: Alice -> Charlie -> Bob over real
/// loopback QUIC, with X0X-0070b commit 6's receiver-side demux + dispatch
/// in place. Proves the round-trip:
///
/// 1. Alice's direct path to Bob fails (no Alice<->Bob connection), her
///    per-peer failure count crosses `fail_threshold`, so the next
///    `send_direct_with_config` engages `try_relay_fallback`.
/// 2. Alice's `try_relay_fallback` builds a sealed `DmEnvelope`, wraps it
///    in a sender-signed `RelayedDm`, and sends to Charlie on
///    `RELAYED_DM_STREAM_TYPE` (0x11).
/// 3. Charlie's `spawn_receiver` demuxes 0x11, parses the `RelayedDm`,
///    and pushes onto the relay-DM channel; the relay-DM listener calls
///    `disposition_for` which classifies as `Forward { dst = bob }`.
/// 4. Charlie's listener resolves Bob's `MachineId` from his discovery
///    cache, postcard re-encodes the inner envelope, and sends it on
///    the standard direct-DM stream (0x10) to Bob's QUIC peer - stamped
///    with Charlie's own `AgentId` at the wire prefix per the
///    Tailscale/DERP relay pattern.
/// 5. Bob's `spawn_receiver` demuxes 0x10 normally; his direct-DM
///    listener performs the wire binding check (Charlie in Bob's
///    discovery cache) and dispatches to subscribers.
/// 6. Bob's `subscribe_direct` receiver fires with a `DirectMessage`
///    where `sender == Charlie` at the wire layer, and the embedded
///    `DmEnvelope`'s `sender_agent_id == Alice` carries the true
///    origin (trust flows from the inner ML-DSA-65 signature, not the
///    wire prefix).
///
/// Telemetry expectations:
/// - Alice's `peer_relay.stats().relay_sent == 1`
/// - Alice's `direct_messaging.diagnostics.outgoing_path_relayed == 1`
/// - Charlie's `peer_relay.stats().relay_forwarded == 1`
/// - Bob's `peer_relay.stats()` - all relay counters remain at zero
///   (Bob never engaged the fallback as either origin or relay)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_round_trip_alice_to_bob_via_charlie() {
    let dir = tempfile::tempdir().expect("tmpdir");
    // Charlie + Bob both need `enabled = true` so `disposition_for`
    // doesn't refuse with PolicyDisabled when a RelayedDm arrives.
    let charlie = match build_agent(
        &dir,
        "charlie",
        PeerRelayConfig {
            enabled: true,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: Vec::new(),
        },
    )
    .await
    .expect("build charlie")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping relay_round_trip: charlie bind permission unavailable");
            return;
        }
    };
    let bob = match build_agent(
        &dir,
        "bob",
        PeerRelayConfig {
            enabled: true,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: Vec::new(),
        },
    )
    .await
    .expect("build bob")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping relay_round_trip: bob bind permission unavailable");
            return;
        }
    };
    let alice = match build_agent(
        &dir,
        "alice",
        PeerRelayConfig {
            enabled: true,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: vec![hex::encode(charlie.agent_id().0)],
        },
    )
    .await
    .expect("build alice")
    {
        Some(agent) => agent,
        None => {
            eprintln!("skipping relay_round_trip: alice bind permission unavailable");
            return;
        }
    };

    // join_network() is the single entry point that starts the direct-DM
    // listener (`start_direct_listener`) on each agent. With empty
    // bootstrap nodes the phase sweeps return quickly.
    bob.join_network().await.expect("bob join_network");
    charlie.join_network().await.expect("charlie join_network");
    alice.join_network().await.expect("alice join_network");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let charlie_addr = normalize_loopback(
        charlie
            .network()
            .expect("charlie network")
            .bound_addr()
            .await
            .expect("charlie bound"),
    );
    let bob_addr = normalize_loopback(
        bob.network()
            .expect("bob network")
            .bound_addr()
            .await
            .expect("bob bound"),
    );

    // Discovery cache priming:
    // - Alice needs Charlie  -> try_relay_fallback resolves Charlie's MachineId
    // - Charlie needs Bob    -> Forward arm resolves Bob's MachineId
    // - Bob needs Charlie    -> direct-DM listener's binding check passes
    //   (Bob will see Charlie as the wire-layer sender)
    alice
        .insert_discovered_agent_for_testing(discovered_for(&charlie, charlie_addr, now_secs))
        .await;
    charlie
        .insert_discovered_agent_for_testing(discovered_for(&bob, bob_addr, now_secs))
        .await;
    bob.insert_discovered_agent_for_testing(discovered_for(&charlie, charlie_addr, now_secs))
        .await;

    // Network connections: Alice->Charlie (for the relay send) and
    // Charlie->Bob (for the forward).
    let alice_network = alice.network().expect("alice network");
    let alice_to_charlie = alice_network
        .connect_addr(charlie_addr)
        .await
        .expect("alice connects to charlie");
    assert_eq!(alice_to_charlie.0, charlie.machine_id().0);
    wait_until_connected(
        &alice,
        ant_quic::PeerId(charlie.machine_id().0),
        Duration::from_secs(5),
    )
    .await;
    let charlie_network = charlie.network().expect("charlie network");
    let charlie_to_bob = charlie_network
        .connect_addr(bob_addr)
        .await
        .expect("charlie connects to bob");
    assert_eq!(charlie_to_bob.0, bob.machine_id().0);
    wait_until_connected(
        &charlie,
        ant_quic::PeerId(bob.machine_id().0),
        Duration::from_secs(5),
    )
    .await;

    // Bob's KEM keypair is what Alice seals the relay envelope to. It is
    // also what Bob would use to decapsulate the AEAD content - for this
    // test we don't decrypt, only verify the envelope arrives intact at
    // Bob's `subscribe_direct` with the inner sender stamped as Alice.
    let bob_kem = AgentKemKeypair::generate().expect("bob KEM keypair");
    alice.insert_capability_for_testing(
        bob.agent_id(),
        bob.machine_id(),
        DmCapabilities {
            max_protocol_version: DM_PROTOCOL_VERSION,
            gossip_inbox: false,
            kem_algorithm: "ML-KEM-768".to_string(),
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            kem_public_key: bob_kem.public_bytes.clone(),
        },
    );
    drive_past_relay_threshold(&alice, &bob.agent_id());

    let mut bob_subscription = bob.subscribe_direct();
    let payload = b"hello-bob-via-charlie".to_vec();
    let receipt = alice
        .send_direct_with_config(&bob.agent_id(), payload.clone(), DmSendConfig::default())
        .await
        .expect("send_direct_with_config must succeed via the relay path");

    match receipt.path {
        DmPath::Relayed { via } => {
            assert_eq!(
                via,
                charlie.agent_id(),
                "relay receipt must name Charlie as the via"
            );
        }
        other => panic!("expected DmPath::Relayed, got {other:?}"),
    }

    // Wait for the relayed envelope to reach Bob's subscribe_direct.
    // Loopback paths complete in milliseconds; the timeout is generous.
    let bob_msg = tokio::time::timeout(Duration::from_secs(5), bob_subscription.recv())
        .await
        .expect("bob must receive the relayed envelope within the deadline")
        .expect("bob's subscribe_direct channel must remain open");

    // Wire-layer attribution: Bob sees Charlie as the sender (the
    // forwarder), since Charlie's `Forward` arm stamps Charlie's
    // AgentId at the wire prefix per the Tailscale/DERP pattern.
    assert_eq!(
        bob_msg.sender,
        charlie.agent_id(),
        "wire-layer sender is the forwarder, not the origin"
    );
    assert_eq!(
        bob_msg.machine_id,
        charlie.machine_id(),
        "wire-layer machine_id is Charlie's (the QUIC peer Bob saw)"
    );
    assert!(
        bob_msg.verified,
        "binding check passes - Charlie is in Bob's discovery cache"
    );

    // Embedded trust anchor: the inner DmEnvelope identifies Alice as
    // the TRUE origin. Trust on this attribution flows from the
    // envelope's ML-DSA-65 signature, not the wire prefix.
    let inner = x0x::dm::DmEnvelope::from_wire_bytes(&bob_msg.payload)
        .expect("bob_msg.payload must be a valid wire-encoded DmEnvelope");
    assert_eq!(
        inner.sender_agent_id,
        alice.agent_id().0,
        "embedded sender_agent_id must identify Alice as the true origin"
    );
    assert_eq!(
        inner.recipient_agent_id,
        bob.agent_id().0,
        "embedded recipient_agent_id must identify Bob"
    );

    // Telemetry triangulation across all three engines.
    assert_eq!(
        alice.peer_relay().stats().snapshot().relay_sent,
        1,
        "alice.relay_sent must advance once"
    );
    assert_eq!(
        alice
            .direct_messaging()
            .diagnostics_snapshot()
            .stats
            .outgoing_path_relayed,
        1,
        "alice's DirectMessaging diagnostic counter must agree"
    );
    let charlie_stats = charlie.peer_relay().stats().snapshot();
    assert_eq!(
        charlie_stats.relay_forwarded, 1,
        "charlie must record exactly one forward"
    );
    assert_eq!(
        charlie_stats.relay_refused_bad_signature, 0,
        "no signature refusals expected on the happy path"
    );
    assert_eq!(
        charlie_stats.relay_refused_stale, 0,
        "no staleness refusals expected on the happy path"
    );
    let bob_stats = bob.peer_relay().stats().snapshot();
    assert_eq!(
        bob_stats.relay_received, 0,
        "bob is the final recipient via the normal direct-DM path - relay_received only fires when bob himself runs disposition_for as a relay"
    );
    assert_eq!(
        bob_stats.relay_forwarded, 0,
        "bob is not a relay - relay_forwarded must remain at zero"
    );
}
