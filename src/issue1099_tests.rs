//! Inert regressions: memory, synthetic publish futures and temporary local storage.
//! No network configuration, sockets, gossip runtime or daemon is started.
//! Run with a temporary X0X_HOME for the shared route fixture defaults.
use super::*;
use dm::{CapabilityRegistry, DmCapabilities, DmError};
use dm_capability::{now_unix_ms, CapabilityStore};
use identity::{AgentId, MachineId};
use std::sync::Arc;
use std::time::Duration;

fn legacy() -> DmCapabilities {
    let mut caps = DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]);
    caps.application_registry = CapabilityRegistry::default();
    caps
}

fn assert_held(store: &CapabilityStore, recipient: AgentId) {
    assert!(matches!(
        store.require_payload_capability(&recipient, share_grant::SHARE_GRANT_DM_PREFIX),
        Err(DmError::RecipientUpgradeRequired {
            capability: "share_grant_v1"
        })
    ));
}

#[test]
fn issue1099_newer_card_preserves_verified_lacks_bit_and_advert_lifetime() {
    let store = CapabilityStore::new();
    let recipient = AgentId([3; 32]);
    let machine = MachineId([2; 32]);
    let before = std::time::Instant::now();
    let stamp = now_unix_ms() - 600_000;
    assert!(store.insert(recipient, machine, legacy(), stamp));
    assert_held(&store, recipient);
    assert!(store.insert_from_card(
        recipient,
        machine,
        DmCapabilities::v2_durable_gossip_ready(vec![2; 1184]),
        now_unix_ms()
    ));
    assert_held(&store, recipient);
    let binding = store.lookup_binding(&recipient).unwrap();
    assert_eq!(binding.machine_id, machine);
    assert_eq!(binding.capabilities.kem_public_key, vec![2; 1184]);
    assert!(binding.capabilities.supports_durable_app_ack());
    assert!(store.would_accept_advert(&recipient, stamp + 1));
    assert!(
        store
            .lookup_binding_at(&recipient, before + Duration::from_secs(301))
            .is_none(),
        "a card must not extend the verified advert lifetime"
    );
    // A card must not advance advert ordering and suppress a signed upgrade.
    assert!(store.insert(
        recipient,
        machine,
        DmCapabilities::v2_durable_gossip_ready(vec![3; 1184]),
        stamp + 1
    ));
    store
        .require_payload_capability(&recipient, share_grant::SHARE_GRANT_DM_PREFIX)
        .unwrap();
}

#[test]
fn issue1099_equal_timestamp_card_cannot_clear_verified_advert() {
    let store = CapabilityStore::new();
    let recipient = AgentId([3; 32]);
    let machine = MachineId([2; 32]);
    let stamp = now_unix_ms();
    assert!(store.insert(recipient, machine, legacy(), stamp));
    assert!(!store.insert_from_card(
        recipient,
        machine,
        DmCapabilities::v2_durable_gossip_ready(vec![2; 1184]),
        stamp
    ));
    assert_held(&store, recipient);
    assert_eq!(
        store.lookup(&recipient).unwrap().kem_public_key,
        vec![1; 1184]
    );
}

#[test]
fn issue1099_card_kem_replay_cannot_revert_newer_material() {
    let store = CapabilityStore::new();
    let recipient = AgentId([3; 32]);
    let machine = MachineId([2; 32]);
    let stamp = now_unix_ms() - 3_000;
    assert!(store.insert(recipient, machine, legacy(), stamp));
    assert!(store.insert_from_card(
        recipient,
        machine,
        DmCapabilities::v2_durable_gossip_ready(vec![2; 1184]),
        stamp + 2_000
    ));
    for card_stamp in [stamp + 1_000, stamp + 2_000] {
        assert!(!store.insert_from_card(
            recipient,
            machine,
            DmCapabilities::v2_durable_gossip_ready(vec![3; 1184]),
            card_stamp
        ));
        assert_eq!(
            store.lookup(&recipient).unwrap().kem_public_key,
            vec![2; 1184]
        );
    }
    assert_held(&store, recipient);
}

#[test]
fn issue1099_card_keeps_supported_bits_but_cannot_transfer_them_between_machines() {
    let store = CapabilityStore::new();
    let recipient = AgentId([3; 32]);
    let machine = MachineId([2; 32]);
    let stamp = now_unix_ms() - 3_000;
    let caps = DmCapabilities::v2_durable_gossip_ready(vec![1; 1184]);
    assert!(store.insert(recipient, machine, caps.clone(), stamp));
    assert!(store.insert_from_card(recipient, machine, caps.clone(), stamp + 1_000));
    assert_eq!(
        store.lookup(&recipient).unwrap().application_registry,
        CapabilityRegistry::current()
    );
    assert!(store.insert_from_card(recipient, MachineId([4; 32]), caps, stamp + 2_000));
    assert_eq!(
        store.lookup(&recipient).unwrap().application_registry,
        CapabilityRegistry::default()
    );
    // #1158: a card from another machine is not a current verified advert,
    // so the capability is unknown and the grant is held, not sent.
    assert!(matches!(
        store.require_payload_capability(&recipient, share_grant::SHARE_GRANT_DM_PREFIX),
        Err(DmError::RecipientCapabilityPending {
            capability: "share_grant_v1"
        })
    ));
    // An ordinary DM is not held.
    store
        .require_payload_capability(&recipient, b"hello")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn issue1099_refresh_requests_missing_application_despite_durable_ack() {
    for bit in [
        CapabilityRegistry::SHARE_GRANT_V1,
        CapabilityRegistry::PREDECESSOR_OFFER_V1,
    ] {
        let store = Arc::new(CapabilityStore::new());
        let recipient = AgentId([3; 32]);
        let machine = MachineId([2; 32]);
        let stamp = now_unix_ms();
        assert!(store.insert(recipient, machine, legacy(), stamp));
        let published = std::sync::atomic::AtomicBool::new(false);
        let start = tokio::time::Instant::now();
        let update_store = Arc::clone(&store);
        let update = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut caps = legacy();
            // Only the requested bit arrives; unrelated bits must not delay readiness.
            caps.application_registry = CapabilityRegistry {
                version: 1,
                bits: bit,
            };
            assert!(update_store.insert(recipient, machine, caps, stamp + 1));
        });
        run_strict_capability_refresh(
            recipient,
            Some(bit),
            true,
            Arc::clone(&store),
            tokio_util::sync::CancellationToken::new(),
            start + Duration::from_secs(1),
            async {
                published.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            },
        )
        .await;
        assert!(
            published.load(std::sync::atomic::Ordering::Relaxed),
            "must request the upgraded application advert"
        );
        assert!(
            store
                .lookup(&recipient)
                .unwrap()
                .application_registry
                .supports(bit),
            "must wait for the application bit, not just transport ACK support"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        update.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn issue1099_refresh_missing_application_is_bounded() {
    let store = Arc::new(CapabilityStore::new());
    let recipient = AgentId([3; 32]);
    assert!(store.insert(recipient, MachineId([2; 32]), legacy(), now_unix_ms()));
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(1);
    let published = std::sync::atomic::AtomicUsize::new(0);
    run_strict_capability_refresh(
        recipient,
        Some(CapabilityRegistry::SHARE_GRANT_V1),
        true,
        store,
        tokio_util::sync::CancellationToken::new(),
        deadline,
        async {
            published.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        },
    )
    .await;
    assert_eq!(published.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(tokio::time::Instant::now(), deadline);
}
