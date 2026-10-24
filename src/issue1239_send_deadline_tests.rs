#![cfg(test)]

//! #1239: one absolute deadline across an ENTIRE ordinary send. The evidence
//! budget of #1590/#1598 bounds the early discovery/evidence reads; the later
//! revocation, registry, contact and transport waits had no common bound, so
//! a held lock or stacked slow stages could keep a send open indefinitely.
//! No sockets: the agent fixture builds no network node.

use super::*;
use std::task::Poll;
use std::time::Duration;

/// The absolute budget of one ordinary send under the test config
/// (`timeout_per_attempt` = 2 s, default retries/backoff/raw knobs), from
/// `dm_evidence::ordinary_send_budget`:
///
/// evidence 2, refresh 3, evidence dial 3, preferred raw 2×2 plus 0.25,
/// gossip 2 plus (2, 2 backoff, 0.25 republish), raw fallback 2×2 plus
/// 0.25 — 22.75 s in total.
const TWO_SECOND_ATTEMPT_BUDGET: Duration = Duration::from_millis(22_750);

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

/// Seed the discovery cache so an ordinary send resolves the recipient's
/// machine from the cache and reaches the pairing check.
async fn seed_discovered_recipient(agent: &Agent, recipient: identity::AgentId) {
    let now_secs = dm::now_unix_ms() / 1000;
    let mut discovered = discovered_agent_fixture(1, now_secs, &[], None);
    discovered.agent_id = recipient;
    discovered.machine_id = identity::MachineId([0x3b; 32]);
    agent
        .identity_discovery_cache
        .write()
        .await
        .insert(recipient, discovered);
}

#[tokio::test]
async fn held_revocation_wait_ends_the_entire_send_at_one_absolute_deadline(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let agent = agent_in(dir.path()).await?;
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x3a; 32]);
    seed_discovered_recipient(&agent, recipient).await;
    let config = dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(2),
        ..Default::default()
    };
    tokio::time::pause();

    // A held revocation writer stalls the outbound pairing check (ADR-0043
    // §9) — a later revocation wait that no per-stage deadline bounds.
    let held = agent.revocation_set.write().await;
    let send = agent.send_direct_with_config(&recipient, vec![1], config);
    tokio::pin!(send);
    assert!(futures::poll!(&mut send).is_pending());

    // The deadline must not fire early: the send is still open one tick
    // before the absolute budget.
    tokio::time::advance(TWO_SECOND_ATTEMPT_BUDGET - Duration::from_millis(1)).await;
    assert!(
        futures::poll!(&mut send).is_pending(),
        "the absolute deadline fired before the send's budget elapsed"
    );
    tokio::time::advance(Duration::from_millis(2)).await;
    let result = futures::poll!(&mut send);
    assert!(
        matches!(result, Poll::Ready(Err(dm::DmError::Timeout { .. }))),
        "one absolute deadline must end the entire send past its budget: {result:?}"
    );
    let diagnostics = agent.direct_messaging.diagnostics_snapshot();
    assert_eq!(diagnostics.stats.outgoing_send_failed, 1);
    drop(held);
    agent.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn uncontended_send_keeps_its_existing_typed_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let agent = agent_in(dir.path()).await?;
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x3a; 32]);
    seed_discovered_recipient(&agent, recipient).await;
    let config = dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(2),
        ..Default::default()
    };
    // Control: without contention the wrap must not preempt the send's own
    // typed failure (no network) and must not fire early.
    let result = agent
        .send_direct_with_config(&recipient, vec![1], config)
        .await;
    assert!(
        matches!(result, Err(dm::DmError::NoConnectivity(_))),
        "uncontended send must keep its typed failure: {result:?}"
    );
    agent.shutdown().await;
    Ok(())
}
