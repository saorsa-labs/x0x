//! Direct-send lock contention regressions. No network is configured.

use super::*;
use std::task::Poll;
use std::time::Duration;

async fn agent_in(dir: &std::path::Path) -> Agent {
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
        .unwrap()
}

#[tokio::test]
async fn issue1239_discovery_lock_ends_ordinary_and_waiting_sends_at_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent_in(dir.path()).await;
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
        drop(held);
    }
    agent.shutdown().await;
}

#[tokio::test]
async fn issue1239_discovery_lock_released_before_bound_preserves_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent_in(dir.path()).await;
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
    let receipt = send.await.unwrap();
    assert_eq!(receipt.path, dm::DmPath::Loopback);
    agent.shutdown().await;
}
