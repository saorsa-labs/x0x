#![cfg(test)]

//! #1158: an obligation-carrying typed send (share grant, predecessor
//! relay, requester offer) to a recipient with a usable ADR 0089
//! peer-evidence view but NO current verified capability advert must not
//! leave this node. No sockets: the sim fabric and a real evidence store.

use super::*;

/// The stored advert of a 0.45-style peer: v2 durable transport, no
/// application registry bits.
fn legacy_v2(kem: Vec<u8>) -> dm::DmCapabilities {
    let mut caps = dm::DmCapabilities::v2_durable_gossip_ready(kem);
    caps.application_registry = dm::CapabilityRegistry::default();
    caps
}

async fn nothing_published(inbox: &mut gossip::Subscription) -> bool {
    tokio::time::timeout(Duration::from_millis(300), inbox.recv())
        .await
        .is_err()
}

/// The recipient's current verified advert arrives, with every bit of
/// this release, bound to the machine its evidence view names.
fn advert_arrives(agent: &Agent, recipient: identity::AgentId) {
    let now = dm_capability::now_unix_ms();
    let view = agent.peer_evidence().usable_agent(recipient, now).unwrap();
    assert!(agent.capability_store.insert(
        recipient,
        view.announcement.machine_id,
        dm::DmCapabilities::v2_durable_gossip_ready(
            view.advert.capabilities.kem_public_key.clone()
        ),
        now,
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn issue1158_grant_is_held_with_evidence_view_and_sent_when_the_advert_arrives(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (agent, recipient, _store, mut inbox, _fabric) =
        gossip_fixture_with(dir.path(), legacy_v2).await?;
    assert!(agent.capability_store.lookup_binding(&recipient).is_none());

    // Control: an ordinary DM to the same recipient is sent as before.
    let receipt = agent
        .send_direct_with_config(&recipient, vec![0x39], publish_config())
        .await?;
    assert_published(&agent, recipient, receipt, &mut inbox).await;

    let owner = identity::UserKeypair::generate()?;
    let now = dm_capability::now_unix_ms() / 1000;
    let grant = share_grant::ShareGrant::sign(
        &owner,
        [1; 32],
        share_grant::Grantee::Agent(recipient),
        vec![identity::AgentId([4; 32])],
        vec![share_grant::ShareCap::Dm],
        now - 1,
        now + 3600,
    )?;
    let outbox = Arc::new(
        share_grant::outbox::GrantRedeliveryOutbox::load(
            dir.path().join("grant-outbox"),
            Some(owner.user_id()),
            now,
        )
        .await,
    );
    agent.install_share_grant_outbox(Arc::clone(&outbox));
    let mut adverts = agent.capability_store().subscribe_obligation_adverts();

    let results = agent.deliver_share_grant(&grant, &[recipient]).await;
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].delivered && results[0].queued,
        "{:?}",
        results[0]
    );
    assert_eq!(
        results[0].error.as_deref(),
        Some("recipient_capability_pending: share_grant_v1")
    );
    assert!(
        nothing_published(&mut inbox).await,
        "a held grant must not reach the recipient's inbox topic"
    );
    assert_eq!(outbox.len(), 1, "the obligation is kept");
    assert!(adverts.try_recv().is_err());

    advert_arrives(&agent, recipient);
    assert_eq!(adverts.try_recv()?, recipient);
    assert!(agent.nudge_share_grant_outbox_for_agent(&recipient));
    // No receiver runs here, so no ACK comes back: prove only that the
    // retry now leaves this node, then stop the pass.
    let agent = Arc::new(agent);
    let step = {
        let agent = Arc::clone(&agent);
        tokio::spawn(async move { agent.share_grant_outbox_step().await })
    };
    let message = tokio::time::timeout(Duration::from_secs(20), inbox.recv())
        .await?
        .ok_or("inbox closed")?;
    let envelope = dm::DmEnvelope::from_wire_bytes(&message.payload)?;
    assert_eq!(envelope.recipient_agent_id, recipient.0);
    step.abort();
    let _ = step.await;
    agent.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn issue1158_offer_is_held_with_evidence_view_and_sent_when_the_advert_arrives(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (agent, recipient, _store, mut inbox, _fabric) =
        gossip_fixture_with(dir.path(), legacy_v2).await?;
    let mut offer = dm_inbox::GROUP_PREDECESSOR_RELAY_DM_PREFIX.to_vec();
    offer.extend_from_slice(&[0xa5; 96]);

    // The requester-offer and relay workers use this prefix on both of
    // their wires; the legacy (non-strict gossip) wire is the one that
    // reached a peer through its evidence view before this fix.
    let error = agent
        .send_direct_with_config(&recipient, offer.clone(), publish_config())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            dm::DmError::RecipientCapabilityPending {
                capability: "predecessor_offer_v1"
            }
        ),
        "{error:?}"
    );
    assert!(
        nothing_published(&mut inbox).await,
        "a held offer must not reach the authority's inbox topic"
    );

    advert_arrives(&agent, recipient);
    let receipt = agent
        .send_direct_with_config(&recipient, offer, publish_config())
        .await?;
    assert_eq!(receipt.path, dm::DmPath::GossipInbox);
    let message = tokio::time::timeout(Duration::from_secs(1), inbox.recv())
        .await?
        .ok_or("inbox closed")?;
    let envelope = dm::DmEnvelope::from_wire_bytes(&message.payload)?;
    assert_eq!(envelope.request_id, receipt.request_id);
    agent.shutdown().await;
    Ok(())
}
