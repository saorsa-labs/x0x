#![cfg(test)]

//! Own-announce order: a rename that is announced while a heartbeat-style
//! beat is in flight must win, and stay. One loopback agent, no peers.
//!
//! The beat reads `announced_at` and the self-name early and writes late.
//! `upsert_discovered_agent` accepts an equal `announced_at`, so a beat that
//! read the old name and wrote after the announce of the rename put the old
//! name back until the next heartbeat. `OwnAnnounceOrder` makes the two
//! builders take turns.

use super::*;
use announced_record_barrier as barrier;
use std::sync::Arc;
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn loopback_agent(dir: &std::path::Path) -> error::Result<Arc<Agent>> {
    let config = network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        network_id: Some(format!("announce-order-{}", rand::random::<u32>())),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..network::NetworkConfig::default()
    };
    Agent::builder()
        .with_identity_dir(dir)
        .with_machine_key(dir.join("machine.key"))
        .with_agent_key_path(dir.join("agent.key"))
        .with_agent_cert_path(dir.join("agent.cert"))
        .with_user_key_path(dir.join("absent-user.key"))
        .with_contact_store_path(dir.join("contacts.json"))
        .with_peer_cache_disabled()
        .with_network_config(config)
        .build()
        .await
        .map(Arc::new)
}

async fn own_name(agent: &Agent) -> error::Result<Option<String>> {
    Ok(agent
        .discovered_agent(agent.agent_id())
        .await?
        .and_then(|entry| entry.self_name))
}

/// Wait until discovery shows `name` for this agent and keeps it for
/// `hold`. The listener ingests each own beat after the self-write, so a
/// short change back to an older name is possible; the last word must be
/// `name`.
async fn own_name_settles_on(agent: &Agent, name: &str, hold: Duration) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut since: Option<Instant> = None;
    loop {
        let shown = own_name(agent).await?;
        if shown.as_deref() == Some(name) {
            if since.get_or_insert_with(Instant::now).elapsed() >= hold {
                return Ok(());
            }
        } else {
            since = None;
        }
        if Instant::now() >= deadline {
            return Err(format!("discovery must settle on {name:?}; it shows {shown:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The forced order. A beat is parked after it read `announced_at` and the
/// old name. The rename announce must wait for that beat, so it is built,
/// published and written last, and the new name stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_announced_during_a_heartbeat_beat_wins() -> TestResult {
    let dir = tempfile::tempdir()?;
    let agent = loopback_agent(dir.path()).await?;
    let local = agent.agent_id();
    agent.set_self_name(Some("old-name".to_string()));
    agent.announce_identity(false, false).await?;
    own_name_settles_on(&agent, "old-name", Duration::ZERO).await?;

    let gate = barrier::arm(local, barrier::HEARTBEAT_AFTER_NAME_READ);
    let beat = tokio::spawn({
        let agent = Arc::clone(&agent);
        async move { agent.reannounce_identity().await }
    });
    tokio::time::timeout(Duration::from_secs(10), gate.reached.acquire())
        .await??
        .forget();

    // The beat holds its `announced_at` and the old name, and the order lock.
    let beat_holds_order = agent.own_announce_order.try_lock().is_err();
    // Rename and announce.
    agent.set_self_name(Some("new-name".to_string()));
    let mut rename = tokio::spawn({
        let agent = Arc::clone(&agent);
        async move { agent.announce_identity(false, false).await }
    });
    let early = tokio::time::timeout(Duration::from_millis(300), &mut rename).await;
    let rename_waited = early.is_err();

    gate.release.add_permits(64);
    beat.await??;
    match early {
        Ok(done) => done??,
        Err(_) => rename.await??,
    }
    barrier::disarm(&local, barrier::HEARTBEAT_AFTER_NAME_READ);

    own_name_settles_on(&agent, "new-name", Duration::from_millis(500)).await?;
    assert!(
        beat_holds_order,
        "a beat in flight must hold the order lock"
    );
    assert!(
        rename_waited,
        "the rename announce must wait for the beat that is in flight"
    );
    agent.shutdown().await;
    Ok(())
}

/// No barrier: each round starts a beat and a rename announce together.
/// After both end, the name of that round must show and stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_beats_never_revert_a_rename() -> TestResult {
    let dir = tempfile::tempdir()?;
    let agent = loopback_agent(dir.path()).await?;
    agent.set_self_name(Some("round-start".to_string()));
    agent.announce_identity(false, false).await?;

    for round in 0..20 {
        let name = format!("round-{round}");
        let beat = tokio::spawn({
            let agent = Arc::clone(&agent);
            async move { agent.reannounce_identity().await }
        });
        tokio::task::yield_now().await;
        agent.set_self_name(Some(name.clone()));
        agent.announce_identity(false, false).await?;
        beat.await??;
        own_name_settles_on(&agent, &name, Duration::from_millis(50)).await?;
    }
    own_name_settles_on(&agent, "round-19", Duration::from_millis(500)).await?;
    agent.shutdown().await;
    Ok(())
}
