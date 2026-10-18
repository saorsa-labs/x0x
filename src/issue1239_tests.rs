//! Direct-send lock contention regressions. No network is configured.

use super::*;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

async fn agent_in(dir: &std::path::Path) -> error::Result<Agent> {
    Agent::builder()
        .with_machine_key(dir.join("machine.key"))
        .with_agent_key_path(dir.join("agent.key"))
        .with_agent_cert_path(dir.join("agent.cert"))
        .with_user_key_path(dir.join("user.key"))
        .with_identity_dir(dir)
        .with_contact_store_path(dir.join("contacts.json"))
        .with_peer_cache_disabled()
        .build()
        .await
}

#[tokio::test]
async fn issue1239_discovery_lock_ends_ordinary_and_waiting_sends_at_the_bound(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let agent = agent_in(dir.path()).await?;
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x39; 32]);
    let budget = Duration::from_secs(2);
    tokio::time::pause();

    for waiting in [false, true] {
        let held = agent.identity_discovery_cache.write().await;
        let config = dm::DmSendConfig {
            timeout_per_attempt: budget,
            ..Default::default()
        };
        let send = async {
            if waiting {
                agent
                    .send_direct_with_config_cold_wait(
                        &recipient,
                        vec![1],
                        config,
                        Duration::from_secs(30),
                    )
                    .await
            } else {
                agent
                    .send_direct_with_config(&recipient, vec![1], config)
                    .await
            }
        };
        tokio::pin!(send);
        assert!(futures::poll!(&mut send).is_pending());
        // Advance the clock without releasing the writer. One millisecond
        // accounts for Tokio's timer resolution; no wall-clock sleep is used.
        tokio::time::advance(budget + Duration::from_millis(1)).await;
        let result = futures::poll!(&mut send);
        assert!(
            matches!(result, Poll::Ready(Err(dm::DmError::RecipientUndiscovered(ref reason)))
                if reason.contains("discovery")),
            "waiting={waiting}: a held discovery writer must return the retryable bound error: {result:?}"
        );
        let diagnostics = agent.direct_messaging.diagnostics_snapshot();
        let failures = if waiting { 2 } else { 1 };
        assert_eq!(diagnostics.stats.outgoing_send_failed, failures);
        assert_eq!(
            diagnostics.per_peer[&hex::encode(recipient.0)].send_failed,
            failures
        );
        drop(held);
    }
    agent.shutdown().await;
    Ok(())
}

fn install_evidence(
    agent: &mut Agent,
    dir: &std::path::Path,
) -> Result<
    (
        Arc<peer_evidence::PeerEvidenceStore>,
        tokio_util::sync::CancellationToken,
    ),
    Box<dyn std::error::Error>,
> {
    let policy = Arc::new(peer_evidence::RuntimePolicy::new(
        agent.agent_id(),
        agent.owner_trust.clone(),
        Arc::clone(&agent.revocation_set),
    ));
    let store = Arc::new(peer_evidence::PeerEvidenceStore::open(
        dir,
        Default::default(),
        policy,
        dm_capability::now_unix_ms(),
    )?);
    let (runtime, ready) =
        peer_evidence::EvidenceRuntime::loading_store_for_test(Arc::clone(&store));
    let mut caps = dm_capability::CapabilityStore::new();
    caps.evidence = runtime;
    agent.capability_store = Arc::new(caps);
    Ok((store, ready))
}

#[tokio::test]
async fn issue1239_evidence_load_shares_discovery_budget_and_counts_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut agent = agent_in(dir.path()).await?;
    let (_store, _ready) = install_evidence(&mut agent, dir.path())?;
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x39; 32]);
    let budget = Duration::from_secs(2);
    tokio::time::pause();
    for waiting in [false, true] {
        let held = agent.identity_discovery_cache.write().await;
        let config = dm::DmSendConfig {
            timeout_per_attempt: budget,
            ..Default::default()
        };
        let send = async {
            if waiting {
                agent
                    .send_direct_with_config_cold_wait(
                        &recipient,
                        vec![1],
                        config,
                        Duration::from_secs(30),
                    )
                    .await
            } else {
                agent
                    .send_direct_with_config(&recipient, vec![1], config)
                    .await
            }
        };
        tokio::pin!(send);
        assert!(futures::poll!(&mut send).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        drop(held);
        assert!(futures::poll!(&mut send).is_pending());
        tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
        let result = futures::poll!(&mut send);
        assert!(
            matches!(
                result,
                Poll::Ready(Err(dm::DmError::RecipientUndiscovered(_)))
            ),
            "waiting={waiting}: load must use the remaining send budget: {result:?}"
        );
        let diagnostics = agent.direct_messaging.diagnostics_snapshot();
        let failures = if waiting { 2 } else { 1 };
        assert_eq!(diagnostics.stats.outgoing_send_failed, failures);
        assert_eq!(
            diagnostics.per_peer[&hex::encode(recipient.0)].send_failed,
            failures
        );
    }
    agent.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1239_held_evidence_store_ends_sends_and_counts_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut agent = agent_in(dir.path()).await?;
    let (store, ready) = install_evidence(&mut agent, dir.path())?;
    ready.cancel();
    assert!(agent.network.is_none());
    let agent = Arc::new(agent);
    let recipient = identity::AgentId([0x39; 32]);
    let budget = Duration::from_millis(200);
    for waiting in [false, true] {
        let held = store.hold_state_for_testing();
        let sender = Arc::clone(&agent);
        let mut send = tokio::spawn(async move {
            let config = dm::DmSendConfig {
                timeout_per_attempt: budget,
                ..Default::default()
            };
            let started = std::time::Instant::now();
            let result = if waiting {
                sender
                    .send_direct_with_config_cold_wait(
                        &recipient,
                        vec![1],
                        config,
                        Duration::from_secs(30),
                    )
                    .await
            } else {
                sender
                    .send_direct_with_config(&recipient, vec![1], config)
                    .await
            };
            (started.elapsed(), result)
        });
        // The observer runs separately from the sender. A synchronous store
        // wait on main cannot stop this watchdog or release its own lock.
        let observed = tokio::time::timeout(budget + Duration::from_millis(100), &mut send).await;
        let diagnostics = agent.direct_messaging.diagnostics_snapshot();
        drop(held);
        // Clean up the pre-fix blocked task before asserting the red result.
        if observed.is_err() {
            let _ = send.await;
        }
        assert!(
            observed.is_ok(),
            "waiting={waiting}: send outlived its deadline while the evidence store stayed locked"
        );
        let (elapsed, result) = observed??;
        assert!(
            matches!(result, Err(dm::DmError::RecipientUndiscovered(_))),
            "waiting={waiting}: {result:?}"
        );
        assert!(
            elapsed <= budget + Duration::from_millis(100),
            "waiting={waiting}: elapsed={elapsed:?}"
        );
        let failures = if waiting { 2 } else { 1 };
        assert_eq!(diagnostics.stats.outgoing_send_failed, failures);
        assert_eq!(
            diagnostics.per_peer[&hex::encode(recipient.0)].send_failed,
            failures
        );
    }
    agent.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn issue1239_discovery_lock_released_before_bound_preserves_loopback(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let agent = agent_in(dir.path()).await?;
    assert!(agent.network.is_none());
    let recipient = agent.agent_id();
    let held = agent.identity_discovery_cache.write().await;
    let config = dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(2),
        ..Default::default()
    };
    let send = agent.send_direct_with_config(&recipient, vec![1], config);
    tokio::pin!(send);
    assert!(futures::poll!(&mut send).is_pending());
    drop(held);
    let receipt = send.await?;
    assert_eq!(receipt.path, dm::DmPath::Loopback);
    agent.shutdown().await;
    Ok(())
}
