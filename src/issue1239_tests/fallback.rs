//! Budget expiry cannot remove the ordinary contact-card delivery path.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

async fn contact_fixture(
    dir: &std::path::Path,
) -> Result<
    (
        Agent,
        identity::AgentId,
        Arc<peer_evidence::PeerEvidenceStore>,
        tokio_util::sync::CancellationToken,
        gossip::Subscription,
        Arc<network::sim::SimFabric>,
    ),
    Box<dyn std::error::Error>,
> {
    let (mut agent, recipient, populated, inbox, fabric) = gossip_fixture(dir).await?;
    let capabilities = populated
        .usable_agent(recipient, dm_capability::now_unix_ms())
        .unwrap()
        .advert
        .capabilities
        .clone();
    agent.contacts().write().await.add(contacts::Contact {
        agent_id: recipient,
        trust_level: contacts::TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: contacts::IdentityType::Known,
        machines: Vec::new(),
        dm_capabilities: Some(capabilities),
    });
    // Replace the fixture's evidence with an empty, independent store. Only
    // the contact card can supply the recipient's gossip capability/KEM key.
    let empty = dir.join("empty-evidence");
    std::fs::create_dir(&empty)?;
    let (store, ready) = install_evidence(&mut agent, &empty)?;
    assert!(agent.capability_store.lookup_binding(&recipient).is_none());
    assert!(store
        .usable_agent(recipient, dm_capability::now_unix_ms())
        .is_none());
    Ok((agent, recipient, store, ready, inbox, fabric))
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_lookup_preserves_contact_card_publication(
) -> Result<(), Box<dyn std::error::Error>> {
    contact_card_after_stall("lookup", false).await
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_load_preserves_contact_card_publication() -> Result<(), Box<dyn std::error::Error>>
{
    contact_card_after_stall("load", false).await
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_read_preserves_contact_card_publication() -> Result<(), Box<dyn std::error::Error>>
{
    contact_card_after_stall("read", false).await
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_lookup_keeps_strict_failure() -> Result<(), Box<dyn std::error::Error>> {
    contact_card_after_stall("lookup", true).await
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_load_keeps_strict_failure() -> Result<(), Box<dyn std::error::Error>> {
    contact_card_after_stall("load", true).await
}

#[tokio::test(flavor = "current_thread")]
async fn expired_post_dial_read_uses_contact_card() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (agent, recipient, store, mut inbox, _fabric) = gossip_fixture(dir.path()).await?;
    let kem = groups::kem_envelope::AgentKemKeypair::generate()?;
    agent.contacts().write().await.add(contacts::Contact {
        agent_id: recipient,
        trust_level: contacts::TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: contacts::IdentityType::Known,
        machines: Vec::new(),
        dm_capabilities: Some(dm::DmCapabilities::v1_gossip_ready(kem.public_bytes)),
    });
    let hold_taken = Arc::new(AtomicBool::new(false));
    let hold_flag = Arc::clone(&hold_taken);
    let dial_started = Arc::new(AtomicBool::new(false));
    let dial_flag = Arc::clone(&dial_started);
    let (hold, hold_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        if hold_rx.recv().is_ok() {
            // The delayed writer is part of the test: the handshake below
            // must not depend on this thread winning any race.
            std::thread::sleep(Duration::from_millis(50));
            let _held = store.hold_state_for_testing();
            hold_flag.store(true, Ordering::SeqCst);
            let _ = release_rx.recv();
        }
    });
    assert!(agent
        .peer_evidence()
        .evidence_dial
        .set(Arc::new(move |_| {
            let hold = hold.clone();
            let dial_flag = Arc::clone(&dial_flag);
            Box::pin(async move {
                dial_flag.store(true, Ordering::SeqCst);
                hold.send(()).unwrap();
                std::future::pending::<()>().await;
            })
        }))
        .is_ok());
    tokio::time::pause();
    let send = agent.send_direct_with_config(&recipient, vec![0x39], publish_config());
    tokio::pin!(send);
    loop {
        match futures::poll!(&mut send) {
            Poll::Pending => {}
            Poll::Ready(result) => panic!("send ended before the dial/store stall: {result:?}"),
        }
        if dial_started.load(Ordering::SeqCst) {
            break;
        }
        // The pre-dial evidence stages may still need worker replies, so
        // keep polling `send` until the dial hook fires. The 1 ms virtual
        // watchdog bounds each park: time creeps 1 ms per idle cycle, which
        // no evidence budget (2 s or more) can notice.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    // The dial now stalls inside the hook; only the writer thread's hold
    // handshake remains, and nothing may re-poll `send` while it happens.
    // The handshake must also keep the runtime out of park: a parked
    // current-thread runtime auto-advances paused time through every
    // registered timer (the 3 s dial cap, then the whole-send deadline)
    // while the delayed writer makes progress, and the first poll below
    // then finds the send already expired. A task that yields in a loop is
    // always runnable, so the runtime never parks: virtual time freezes
    // for the whole handshake while real time lets the writer take the
    // hold.
    while !hold_taken.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(3) + Duration::from_millis(1)).await;
    assert!(futures::poll!(&mut send).is_pending());
    tokio::time::advance(publish_config().timeout_per_attempt + Duration::from_millis(1)).await;
    let result = futures::poll!(&mut send);
    release.send(())?;
    writer.join().unwrap();
    assert!(
        result.is_ready(),
        "post-dial read outlived the evidence budget: {result:?}"
    );
    let Poll::Ready(result) = result else {
        unreachable!()
    };
    let receipt = result.expect("expired evidence must fall back to the contact card after a dial");
    assert_published(&agent, recipient, receipt, &mut inbox).await;
    assert_eq!(
        agent
            .peer_evidence()
            .evidence_barrier_timeout
            .load(Ordering::Relaxed),
        1
    );
    agent.shutdown().await;
    Ok(())
}

async fn contact_card_after_stall(
    stage: &str,
    strict: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (agent, recipient, store, ready, mut inbox, _fabric) = contact_fixture(dir.path()).await?;
    if stage != "load" {
        ready.cancel();
    }
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&entered);
    assert!(agent
        .peer_evidence()
        .lookup_responder
        .set(Arc::new(move |_| {
            let signal = Arc::clone(&signal);
            Box::pin(async move {
                signal.notify_one();
                std::future::pending::<()>().await;
            })
        }))
        .is_ok());
    // Skip Lookup only for the read case, so it stalls at usable_agent.
    let _lookups: Vec<_> = if stage == "read" {
        (0..16)
            .map(|_| {
                agent
                    .peer_evidence()
                    .wire_limits
                    .try_lookup_permit()
                    .unwrap()
            })
            .collect()
    } else {
        Vec::new()
    };
    let held = (stage == "read").then(|| store.hold_state_for_testing());
    let mut config = publish_config();
    config.require_durable_app_ack = strict;
    let budget = config.timeout_per_attempt;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let send = agent.send_direct_with_config(&recipient, vec![0x39], config);
    tokio::pin!(send);
    if stage == "lookup" {
        tokio::select! {
            _ = entered.notified() => {},
            result = &mut send => panic!("send ended before Lookup stalled: {result:?}"),
        }
    } else {
        assert!(futures::poll!(&mut send).is_pending());
        if stage == "load" {
            assert_eq!(
                agent
                    .peer_evidence()
                    .evidence_load_barrier_waits
                    .load(Ordering::Relaxed),
                1
            );
        }
    }
    // Only advance virtual time; leave the blocked source unavailable. A
    // millisecond covers timer resolution, not an extra send attempt budget.
    tokio::time::advance(budget + Duration::from_millis(1)).await;
    let result = futures::poll!(&mut send);
    drop(held);
    assert!(
        result.is_ready(),
        "{stage}: send exceeded its evidence budget: {result:?}"
    );
    assert!(started.elapsed() <= budget + Duration::from_millis(1));
    let Poll::Ready(result) = result else {
        unreachable!()
    };
    if strict {
        let expected = if stage == "lookup" {
            "evidence Lookup"
        } else {
            "evidence load"
        };
        assert!(
            matches!(result, Err(dm::DmError::RecipientUndiscovered(ref reason))
            if reason == &format!("direct-send binding source unavailable within the send budget ({expected})")),
            "strict {stage}: {result:?}"
        );
        let diagnostics = agent.direct_messaging.diagnostics_snapshot();
        assert_eq!(diagnostics.stats.outgoing_send_failed, 1);
        assert_eq!(
            diagnostics.per_peer[&hex::encode(recipient.0)].send_failed,
            1
        );
        let receive = inbox.recv();
        tokio::pin!(receive);
        assert!(futures::poll!(&mut receive).is_pending());
    } else {
        let receipt = result.expect("ordinary send must publish through its usable contact card");
        assert_published(&agent, recipient, receipt, &mut inbox).await;
        assert_eq!(
            agent
                .peer_evidence()
                .evidence_barrier_timeout
                .load(Ordering::Relaxed),
            1
        );
    }
    agent.shutdown().await;
    Ok(())
}
