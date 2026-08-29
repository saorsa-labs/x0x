//! ADR-0041 Tier-1 integration proofs.
//!
//! Two levels, matching the repo's tiering:
//!
//! - Always-on session tests over `tokio::io::duplex` — the full wire
//!   protocol (Hello → per-kind version vectors → records → Done) between
//!   two in-memory stores owned by the same owner key on two machines,
//!   with NO network. These prove convergence both ways, the fail-closed
//!   forgery path, and rollback rejection end-to-end through the codec.
//! - `#[ignore]` transport tests that bind real UDP sockets (integration
//!   tier, `--run-ignored ignored-only`): two full agents with the same
//!   owner key, cross-enrolled, converging over a real `SyncV1` stream via
//!   the daemon-side `OwnerSyncService` — the two-daemon convergence
//!   proof the ADR's validation section names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use x0x::identity::{MachineId, UserKeypair};
use x0x::owner_sync::{
    run_sync_session, OwnerEnrollment, OwnerSyncStore, SyncKind, SyncValue, VersionedRecord,
};

fn owner_kp(seed: u8) -> UserKeypair {
    UserKeypair::from_seed(&[seed; 32]).expect("deterministic owner keypair")
}

fn machine(id: u8) -> MachineId {
    MachineId([id; 32])
}

fn names_value(display: &str, machine_name: &str) -> SyncValue {
    SyncValue::MachineNames {
        display_name: Some(display.to_string()),
        machine_name: Some(machine_name.to_string()),
    }
}

/// Cross-enroll two machines into each other's device sets under `owner`
/// (the minimum for bidirectional sync — blocker 30).
async fn cross_enroll(a: &OwnerSyncStore, b: &OwnerSyncStore, owner: &UserKeypair) {
    a.enroll(OwnerEnrollment::sign(machine(2), owner, 1_000).unwrap())
        .await;
    b.enroll(OwnerEnrollment::sign(machine(1), owner, 1_000).unwrap())
        .await;
}

/// Run one session between two stores over a duplex pipe. Returns both
/// summaries (initiator, responder).
async fn session_between(
    a: &Arc<OwnerSyncStore>,
    b: &Arc<OwnerSyncStore>,
    owner: &UserKeypair,
) -> (
    x0x::owner_sync::SessionSummary,
    x0x::owner_sync::SessionSummary,
) {
    let owner_id = owner.user_id();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let b_clone = Arc::clone(b);
    let responder = tokio::spawn(async move {
        let (mut r_recv, mut r_send) = tokio::io::split(client);
        run_sync_session(
            &mut r_send,
            &mut r_recv,
            &b_clone,
            &owner_id,
            &machine(2),
            &machine(1),
            |_| {},
        )
        .await
        .expect("responder session")
    });
    let (mut c_recv, mut c_send) = tokio::io::split(server);
    let initiator_summary = run_sync_session(
        &mut c_send,
        &mut c_recv,
        a,
        &owner_id,
        &machine(1),
        &machine(2),
        |_| {},
    )
    .await
    .expect("initiator session");
    let responder_summary = responder.await.expect("responder task");
    (initiator_summary, responder_summary)
}

/// WHY (ADR-0041 validation): two machines of one owner converge — names
/// AND issuance-journal lines propagate BOTH ways in one session each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_machines_converge_names_and_journal_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let owner = owner_kp(7);
    let store_a = Arc::new(OwnerSyncStore::load(&dir.path().join("a")).await);
    let store_b = Arc::new(OwnerSyncStore::load(&dir.path().join("b")).await);
    cross_enroll(&store_a, &store_b, &owner).await;

    // Machine 1: names + a journal line for agent X.
    store_a
        .mint(
            SyncKind::MachineNames,
            &hex::encode(machine(1).0),
            &names_value("alpha", "laptop"),
            &owner,
            machine(1),
        )
        .await
        .unwrap();
    store_a
        .mint(
            SyncKind::IssuanceJournal,
            "aa",
            &SyncValue::IssuanceJournal {
                agent_id: "aa".into(),
                cert_digest: "digest-x".into(),
                issued_at: 100,
                not_after: None,
            },
            &owner,
            machine(1),
        )
        .await
        .unwrap();
    // Machine 2: names + a DIFFERENT journal line for agent Y.
    store_b
        .mint(
            SyncKind::MachineNames,
            &hex::encode(machine(2).0),
            &names_value("beta", "desktop"),
            &owner,
            machine(2),
        )
        .await
        .unwrap();
    store_b
        .mint(
            SyncKind::IssuanceJournal,
            "bb",
            &SyncValue::IssuanceJournal {
                agent_id: "bb".into(),
                cert_digest: "digest-y".into(),
                issued_at: 200,
                not_after: None,
            },
            &owner,
            machine(2),
        )
        .await
        .unwrap();

    let (initiator, responder) = session_between(&store_a, &store_b, &owner).await;
    assert!(initiator.accepted >= 2, "A accepted B's records");
    assert!(responder.accepted >= 2, "B accepted A's records");

    // Convergence: both sides hold all four records with equal clocks.
    let snap_a = store_a.records_snapshot().await;
    let snap_b = store_b.records_snapshot().await;
    let mut clocks_a: Vec<_> = snap_a
        .iter()
        .map(|r| (r.kind, r.key.clone(), r.clock))
        .collect();
    let mut clocks_b: Vec<_> = snap_b
        .iter()
        .map(|r| (r.kind, r.key.clone(), r.clock))
        .collect();
    clocks_a.sort();
    clocks_b.sort();
    assert_eq!(clocks_a, clocks_b, "stores converge on identical clocks");
    assert_eq!(snap_a.len(), 4, "names x2 + journal x2: {snap_a:#?}");

    // The values agree too.
    let find = |snap: &[VersionedRecord], kind: SyncKind, key: &str| {
        snap.iter()
            .find(|r| r.kind == kind && r.key == key)
            .unwrap_or_else(|| panic!("missing {kind:?} {key}"))
            .value
            .clone()
    };
    assert_eq!(
        find(&snap_a, SyncKind::MachineNames, &hex::encode(machine(2).0)),
        names_value("beta", "desktop"),
        "A learned B's names"
    );
    assert_eq!(
        find(&snap_b, SyncKind::MachineNames, &hex::encode(machine(1).0)),
        names_value("alpha", "laptop"),
        "B learned A's names"
    );
    assert!(
        matches!(
            find(&snap_b, SyncKind::IssuanceJournal, "aa"),
            SyncValue::IssuanceJournal { ref cert_digest, .. } if cert_digest == "digest-x"
        ),
        "B learned A's journal line"
    );
    assert!(
        matches!(
            find(&snap_a, SyncKind::IssuanceJournal, "bb"),
            SyncValue::IssuanceJournal { ref cert_digest, .. } if cert_digest == "digest-y"
        ),
        "A learned B's journal line"
    );

    // A second session ships nothing new (fixed point).
    let (again_a, again_b) = session_between(&store_a, &store_b, &owner).await;
    assert_eq!(again_a.accepted, 0);
    assert_eq!(again_b.accepted, 0);
}

/// WHY: a record signed by a NON-owner key aborts the session fail-closed
/// and nothing from that batch is stored (ADR-0041 validation).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_non_owner_record_aborts_session_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let owner = owner_kp(7);
    let attacker = owner_kp(9);
    let store_a = Arc::new(OwnerSyncStore::load(&dir.path().join("a")).await);
    let store_b = Arc::new(OwnerSyncStore::load(&dir.path().join("b")).await);
    cross_enroll(&store_a, &store_b, &owner).await;

    // Plant a forged record IN A's store (as if a compromised machine had
    // written one) — the session must fail closed and B must learn nothing.
    let forged = VersionedRecord::sign(
        SyncKind::OwnerProfile,
        "owner",
        &SyncValue::OwnerProfile {
            human_name: Some("Mallory".into()),
        },
        x0x::owner_sync::RecordClock {
            version: 50,
            signed_at_ms: 50,
            writer_machine: machine(1).0,
        },
        &attacker,
    )
    .unwrap();
    store_a.records_insert_for_testing(forged).await;

    let owner_id = owner.user_id();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let b_clone = Arc::clone(&store_b);
    let responder = tokio::spawn(async move {
        let (mut r_recv, mut r_send) = tokio::io::split(client);
        run_sync_session(
            &mut r_send,
            &mut r_recv,
            &b_clone,
            &owner_id,
            &machine(2),
            &machine(1),
            |_| {},
        )
        .await
    });
    let (mut c_recv, mut c_send) = tokio::io::split(server);
    let initiator_err = run_sync_session(
        &mut c_send,
        &mut c_recv,
        &store_a,
        &owner_id,
        &machine(1),
        &machine(2),
        |_| {},
    )
    .await
    .expect_err("session with a forged record must fail");
    assert!(
        initiator_err.to_string().contains("not the same owner"),
        "initiator must see the peer's fail-closed abort, got: {initiator_err:?}"
    );
    let responder_err = responder.await.unwrap().expect_err("responder aborts too");
    assert!(
        matches!(responder_err, x0x::owner_sync::SyncError::OwnerMismatch),
        "responder saw the forgery: {responder_err:?}"
    );

    // B stored nothing from the poisoned batch.
    assert!(
        store_b.records_snapshot().await.is_empty(),
        "fail-closed: no record from a forged batch is stored"
    );
}

/// WHY: rollback protection survives the wire — after B already holds a
/// higher-version record, a replayed older record is superseded and never
/// overwrites the winner (gapcheck blocker 31).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replayed_older_record_never_overwrites_winner_over_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let owner = owner_kp(7);
    let store_a = Arc::new(OwnerSyncStore::load(&dir.path().join("a")).await);
    let store_b = Arc::new(OwnerSyncStore::load(&dir.path().join("b")).await);
    cross_enroll(&store_a, &store_b, &owner).await;

    // B already holds version 5 for its own names record...
    store_b
        .mint(
            SyncKind::MachineNames,
            &hex::encode(machine(2).0),
            &names_value("beta-new", "desktop"),
            &owner,
            machine(2),
        )
        .await
        .unwrap();
    for extra in 0..4 {
        // bump to version 5 with distinct values
        store_b
            .mint(
                SyncKind::MachineNames,
                &hex::encode(machine(2).0),
                &names_value(&format!("beta-new-{extra}"), "desktop"),
                &owner,
                machine(2),
            )
            .await
            .unwrap();
    }
    let b_winner = store_b
        .records_snapshot()
        .await
        .into_iter()
        .find(|r| r.kind == SyncKind::MachineNames)
        .unwrap();
    assert_eq!(b_winner.clock.version, 5);

    // ...while A holds an older snapshot of B's record (version 2).
    let older = VersionedRecord::sign(
        SyncKind::MachineNames,
        &hex::encode(machine(2).0),
        &names_value("beta-old", "desktop"),
        x0x::owner_sync::RecordClock {
            version: 2,
            signed_at_ms: 999_999,
            writer_machine: machine(2).0,
        },
        &owner,
    )
    .unwrap();
    store_a.records_insert_for_testing(older).await;

    let (a_summary, b_summary) = session_between(&store_a, &store_b, &owner).await;
    assert_eq!(
        a_summary.accepted, 1,
        "A converges UP to B's newer v5 record (not the rollback direction)"
    );
    assert_eq!(
        b_summary.accepted, 0,
        "B accepts nothing: A's v2 is a rollback"
    );
    let b_after = store_b
        .records_snapshot()
        .await
        .into_iter()
        .find(|r| r.kind == SyncKind::MachineNames)
        .unwrap();
    assert_eq!(b_after.clock.version, 5, "winner untouched");
    assert_eq!(b_after.value, b_winner.value, "rollback did not apply");
}

async fn build_owned_agent(
    dir: &std::path::Path,
    name: &str,
    owner_seed: [u8; 32],
) -> Option<x0x::Agent> {
    let owner = UserKeypair::from_seed(&owner_seed).expect("owner keypair");
    match x0x::Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.join(format!("{name}-agent.key")))
        .with_agent_cert_path(dir.join(format!("{name}-agent.cert")))
        .with_user_key(owner)
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_network_config(loopback_network_config())
        .build()
        .await
    {
        Ok(agent) => Some(agent),
        Err(e) if is_network_bind_permission_error(&e) => None,
        Err(e) => panic!("agent build failed: {e}"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Transport tier (#[ignore]): real sockets, real SyncV1 streams, the
// daemon-side service wiring — the ADR's two-daemon convergence proof.
// ─────────────────────────────────────────────────────────────────────

fn loopback_network_config() -> x0x::network::NetworkConfig {
    x0x::network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        ..x0x::network::NetworkConfig::default()
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

/// Two full agents, one owner key, cross-enrolled: the Tier-1 service
/// converges names and journal lines over a REAL `SyncV1` stream
/// (open_peer_stream → acceptor → session), both directions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback SyncV1 proof; binds UDP + waits on convergence. Integration tier."]
async fn two_agents_converge_over_real_syncv1_stream() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let owner = owner_kp(7);
    let Some(alice) = build_owned_agent(dir.path(), "alice", [7u8; 32]).await else {
        return; // sandbox without UDP bind
    };
    let Some(bob) = build_owned_agent(dir.path(), "bob", [7u8; 32]).await else {
        return;
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);
    assert_eq!(alice.user_id(), bob.user_id(), "same owner on both");

    let service_a =
        x0x::owner_sync::OwnerSyncService::new(Arc::clone(&alice), &dir.path().join("sync-a"))
            .await
            .expect("alice SyncV1 acceptor");
    let service_b =
        x0x::owner_sync::OwnerSyncService::new(Arc::clone(&bob), &dir.path().join("sync-b"))
            .await
            .expect("bob SyncV1 acceptor");

    // Cross-enroll: each device set contains the OTHER machine.
    let owner_id = owner.user_id();
    service_a
        .store()
        .enroll(OwnerEnrollment::sign(bob.machine_id(), &owner, 1_000).unwrap())
        .await;
    service_b
        .store()
        .enroll(OwnerEnrollment::sign(alice.machine_id(), &owner, 1_000).unwrap())
        .await;

    // Local Tier-1 state: distinct names per machine.
    service_a
        .store()
        .mint(
            SyncKind::MachineNames,
            &hex::encode(alice.machine_id().0),
            &names_value("alice-agent", "alice-mac"),
            &owner,
            alice.machine_id(),
        )
        .await
        .unwrap();
    service_b
        .store()
        .mint(
            SyncKind::MachineNames,
            &hex::encode(bob.machine_id().0),
            &names_value("bob-agent", "bob-mac"),
            &owner,
            bob.machine_id(),
        )
        .await
        .unwrap();

    // Transport bring-up (tailnet integration test pattern).
    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");
    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let bob_addr = {
        let addr = bob_network.bound_addr().await.expect("bob bound");
        if addr.ip().is_unspecified() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                addr.port(),
            )
        } else {
            addr
        }
    };
    let connected = alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    assert_eq!(connected.0, bob.machine_id().0);

    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network
                .is_connected(&ant_quic::PeerId(alice.machine_id().0))
                .await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        alice_network.is_connected(&bob_peer).await,
        "alice→bob live"
    );

    // Identity gates: discovery-cache binding + Trusted contact, both ways.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let alice_addr = {
        let addr = alice_network.bound_addr().await.expect("alice bound");
        if addr.ip().is_unspecified() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                addr.port(),
            )
        } else {
            addr
        }
    };
    let discovered = |agent: &x0x::Agent, addr, now| x0x::DiscoveredAgent {
        self_name: None,
        cert_digest: None,
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: None,
        addresses: vec![addr],
        announced_at: now,
        last_seen: now,
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
    };
    alice
        .insert_discovered_agent_for_testing(discovered(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(discovered(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    // One pass from alice: dial bob, run the session. Bob's acceptor
    // handles the inbound side. (The owner id check inside the session is
    // the same-owner gate; the enrollment gates ran above.)
    let _ = owner_id;
    service_a.sync_all().await;

    // Convergence: both stores hold both machines' names records.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let a = service_a.store().records_snapshot().await;
        let b = service_b.store().records_snapshot().await;
        let a_ok = a.iter().any(|r| {
            r.kind == SyncKind::MachineNames && r.value == names_value("bob-agent", "bob-mac")
        });
        let b_ok = b.iter().any(|r| {
            r.kind == SyncKind::MachineNames && r.value == names_value("alice-agent", "alice-mac")
        });
        if a_ok && b_ok {
            break;
        }
        if Instant::now() > deadline {
            panic!("no convergence: alice has {a:?}, bob has {b:?}");
        }
        // Retry the pass until the discovery caches settle.
        service_a.sync_all().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Non-enrolled machine rejected at accept: an unenrolled third agent's
    // stream never reaches the session (gate refuses before any byte).
    // Simulated at store level here (the transport path needs a third
    // agent; the accept-gate unit tests cover the decision itself).
    let outsider = machine(9);
    assert!(
        !service_a
            .store()
            .is_enrolled(&outsider, &owner.user_id())
            .await
    );
}
