//! #1224: an unsigned or unverifiable GroupCard must not be listed.

use super::*;

/// The refusal counter is process-wide. These tests read it, so they take
/// this lock for the whole body. Plain `cargo test` runs them on parallel
/// threads; without the lock the delta asserts race.
fn refusal_counter_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn public_card(
    name: &str,
    mls_id: &str,
    keypair: &x0x::identity::AgentKeypair,
    sign: bool,
) -> x0x::groups::GroupCard {
    let mut info = x0x::groups::GroupInfo::new(
        name.to_string(),
        "desc".to_string(),
        keypair.agent_id(),
        mls_id.to_string(),
    );
    info.policy.discoverability = x0x::groups::GroupDiscoverability::PublicDirectory;
    let mut card = info.to_group_card().expect("a public group yields a card");
    if sign {
        card.sign(keypair).expect("card sign");
    }
    card
}

fn listed_ids(body: &serde_json::Value) -> Vec<String> {
    body["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .filter_map(|card| card["group_id"].as_str().map(str::to_string))
        .collect()
}

/// An unsigned card planted in the discovery cache is absent from
/// `GET /groups/discover`. A signed card for another group is listed.
/// Listing does not re-verify, so the refusal counter stays put.
#[tokio::test]
async fn unsigned_group_card_is_absent_from_discovery_listing() -> Result<()> {
    let _guard = refusal_counter_lock().lock().await;
    let (state, _dir) = secure_endpoint_test_state().await?;
    let keypair = state.agent.identity().agent_keypair();
    let unsigned = public_card("Unsigned", &"aa".repeat(32), keypair, false);
    let signed = public_card("Signed", &"bb".repeat(32), keypair, true);
    assert!(
        unsigned.signature.is_empty(),
        "the unsigned fixture must have an empty signature"
    );
    assert!(
        !signed.signature.is_empty() && signed.verify_signature().is_ok(),
        "the signed fixture must verify"
    );

    let before = super::super::unsigned_group_cards_refused();
    {
        let mut cache = state.group_card_cache.write().await;
        cache.insert(unsigned.group_id.clone(), unsigned.clone());
        cache.insert(signed.group_id.clone(), signed.clone());
    }
    let response = discover_groups(State(Arc::clone(&state)), Query(HashMap::new()))
        .await
        .into_response();
    let status = response.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids = listed_ids(&body);
    assert!(
        !ids.iter().any(|id| id == &unsigned.group_id),
        "unsigned card {ids:?} was listed: {body}"
    );
    assert!(
        ids.iter().any(|id| id == &signed.group_id),
        "signed card missing from {ids:?}: {body}"
    );
    assert_eq!(
        super::super::unsigned_group_cards_refused(),
        before,
        "listing must not re-verify; ingress owns the refusal counter"
    );

    let single = get_group_card(State(Arc::clone(&state)), Path(unsigned.group_id.clone()))
        .await
        .into_response();
    assert_eq!(
        single.status(),
        StatusCode::NOT_FOUND,
        "GET /groups/cards/:id served the unsigned card"
    );
    Ok(())
}

enum CardShape {
    Unsigned,
    Damaged,
    Signed,
}

fn shaped_card(
    name: &str,
    mls_id: &str,
    keypair: &x0x::identity::AgentKeypair,
    discoverability: x0x::groups::GroupDiscoverability,
    shape: CardShape,
) -> x0x::groups::GroupCard {
    let mut info = x0x::groups::GroupInfo::new(
        name.to_string(),
        "desc".to_string(),
        keypair.agent_id(),
        mls_id.to_string(),
    );
    info.policy.discoverability = discoverability;
    let mut card = info
        .to_group_card()
        .expect("a listable group yields a card");
    match shape {
        CardShape::Unsigned => {}
        CardShape::Signed | CardShape::Damaged => {
            card.sign(keypair).expect("card sign");
        }
    }
    if matches!(shape, CardShape::Damaged) {
        let mut signature = card.signature.into_bytes();
        let last = signature.len() - 1;
        signature[last] = if signature[last] == b'a' { b'b' } else { b'a' };
        card.signature = String::from_utf8(signature).expect("signature stays text");
        assert!(
            card.verify_signature().is_err(),
            "the damaged fixture must not verify"
        );
    }
    card
}

async fn caches_contain(state: &Arc<AppState>, group_id: &str) -> (bool, bool) {
    let in_cards = state.group_card_cache.read().await.contains_key(group_id);
    let in_directory = state.directory_cache.read().await.get(group_id).is_some();
    (in_cards, in_directory)
}

fn discovery_payload(card: &x0x::groups::GroupCard) -> Vec<u8> {
    serde_json::to_vec(&NamedGroupMetadataEvent::GroupCardPublished {
        group_id: card.group_id.clone(),
        card: card.clone(),
    })
    .expect("event json")
}

fn ltc_frame(card: &x0x::groups::GroupCard) -> Vec<u8> {
    let json = serde_json::to_vec(card).expect("card json");
    let mut frame = Vec::with_capacity(super::super::LTC_CARD_FRAME_PREFIX.len() + json.len());
    frame.extend_from_slice(super::super::LTC_CARD_FRAME_PREFIX);
    frame.extend_from_slice(&json);
    frame
}

/// Global discovery refuses an unsigned card and a card with a damaged
/// signature. Neither reaches a cache, and each refusal is counted. A
/// signed card is cached.
#[tokio::test]
async fn global_discovery_refuses_unsigned_and_damaged_cards() -> Result<()> {
    let _guard = refusal_counter_lock().lock().await;
    let (state, _dir) = secure_endpoint_test_state().await?;
    let keypair = state.agent.identity().agent_keypair();
    let public = x0x::groups::GroupDiscoverability::PublicDirectory;
    let unsigned = shaped_card("U", &"11".repeat(32), keypair, public, CardShape::Unsigned);
    let damaged = shaped_card("D", &"22".repeat(32), keypair, public, CardShape::Damaged);
    let signed = shaped_card("S", &"33".repeat(32), keypair, public, CardShape::Signed);
    let before = super::super::unsigned_group_cards_refused();

    super::super::apply_global_discovery_payload(&state, &discovery_payload(&unsigned)).await;
    super::super::apply_global_discovery_payload(&state, &discovery_payload(&damaged)).await;
    let refused = super::super::unsigned_group_cards_refused();
    assert!(
        refused >= before + 2,
        "global discovery counted {refused} from {before}"
    );
    for card in [&unsigned, &damaged] {
        let (in_cards, in_directory) = caches_contain(&state, &card.group_id).await;
        assert!(!in_cards && !in_directory, "refused card entered a cache");
    }

    super::super::apply_global_discovery_payload(&state, &discovery_payload(&signed)).await;
    let (in_cards, in_directory) = caches_contain(&state, &signed.group_id).await;
    assert!(in_cards, "signed discovery card was not cached");
    assert!(!in_directory, "global discovery wrote the shard cache");
    assert_eq!(super::super::unsigned_group_cards_refused(), refused);
    Ok(())
}

/// A shard Card message refuses an unsigned card and a damaged signature.
/// Neither cache is written. A signed card lands in both caches.
#[tokio::test]
async fn shard_delivery_refuses_unsigned_and_damaged_cards() -> Result<()> {
    let _guard = refusal_counter_lock().lock().await;
    let (state, _dir) = secure_endpoint_test_state().await?;
    let keypair = state.agent.identity().agent_keypair();
    let public = x0x::groups::GroupDiscoverability::PublicDirectory;
    let unsigned = shaped_card("U", &"44".repeat(32), keypair, public, CardShape::Unsigned);
    let damaged = shaped_card("D", &"55".repeat(32), keypair, public, CardShape::Damaged);
    let signed = shaped_card("S", &"66".repeat(32), keypair, public, CardShape::Signed);
    let before = super::super::unsigned_group_cards_refused();

    for card in [&unsigned, &damaged] {
        let message = x0x::groups::DirectoryMessage::Card {
            card: Box::new(card.clone()),
        };
        super::super::handle_directory_message(
            &state,
            x0x::groups::ShardKind::Id,
            0,
            &message.encode(),
        )
        .await;
        let (in_cards, in_directory) = caches_contain(&state, &card.group_id).await;
        assert!(
            !in_cards && !in_directory,
            "refused shard card entered a cache"
        );
    }
    let refused = super::super::unsigned_group_cards_refused();
    assert!(
        refused >= before + 2,
        "shard delivery counted {refused} from {before}"
    );

    let message = x0x::groups::DirectoryMessage::Card {
        card: Box::new(signed.clone()),
    };
    super::super::handle_directory_message(
        &state,
        x0x::groups::ShardKind::Id,
        0,
        &message.encode(),
    )
    .await;
    let (in_cards, in_directory) = caches_contain(&state, &signed.group_id).await;
    assert!(in_cards && in_directory, "signed shard card was not cached");
    assert_eq!(super::super::unsigned_group_cards_refused(), refused);
    Ok(())
}

/// A ListedToContacts frame refuses an unsigned card and a damaged
/// signature before the contact cache. A signed contact card is cached
/// and does not enter the public shard cache.
#[tokio::test]
async fn contact_delivery_refuses_unsigned_and_damaged_cards() -> Result<()> {
    let _guard = refusal_counter_lock().lock().await;
    let (state, _dir) = secure_endpoint_test_state().await?;
    let keypair = state.agent.identity().agent_keypair();
    let contacts = x0x::groups::GroupDiscoverability::ListedToContacts;
    let unsigned = shaped_card(
        "U",
        &"77".repeat(32),
        keypair,
        contacts,
        CardShape::Unsigned,
    );
    let damaged = shaped_card("D", &"88".repeat(32), keypair, contacts, CardShape::Damaged);
    let signed = shaped_card("S", &"99".repeat(32), keypair, contacts, CardShape::Signed);
    let before = super::super::unsigned_group_cards_refused();

    super::super::apply_listed_to_contacts_frame(&state, "peer", &ltc_frame(&unsigned)).await;
    super::super::apply_listed_to_contacts_frame(&state, "peer", &ltc_frame(&damaged)).await;
    let refused = super::super::unsigned_group_cards_refused();
    assert!(
        refused >= before + 2,
        "contact delivery counted {refused} from {before}"
    );
    for card in [&unsigned, &damaged] {
        let (in_cards, in_directory) = caches_contain(&state, &card.group_id).await;
        assert!(
            !in_cards && !in_directory,
            "refused contact card entered a cache"
        );
    }

    super::super::apply_listed_to_contacts_frame(&state, "peer", &ltc_frame(&signed)).await;
    let (in_cards, in_directory) = caches_contain(&state, &signed.group_id).await;
    assert!(in_cards, "signed contact card was not cached");
    assert!(!in_directory, "contact delivery wrote the shard cache");
    assert_eq!(super::super::unsigned_group_cards_refused(), refused);
    Ok(())
}

/// Metadata `GroupCardPublished` from an admin refuses an unsigned card
/// and a damaged signature. A signed card for the same local group is
/// cached. The group id on the card matches the local stable id.
#[tokio::test]
async fn metadata_apply_refuses_unsigned_and_damaged_cards() -> Result<()> {
    let _guard = refusal_counter_lock().lock().await;
    let (state, _dir) = secure_endpoint_test_state().await?;
    let keypair = state.agent.identity().agent_keypair();
    let sender = state.agent.agent_id();
    let public = x0x::groups::GroupDiscoverability::PublicDirectory;
    let mut info = x0x::groups::GroupInfo::new(
        "Local".to_string(),
        "desc".to_string(),
        sender,
        "ab".repeat(32),
    );
    info.policy.discoverability = public;
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), info.clone());

    let unsigned = info.to_group_card().expect("card");
    let mut damaged = info.to_group_card().expect("card");
    damaged.sign(keypair).expect("sign");
    let mut signature = damaged.signature.into_bytes();
    let last = signature.len() - 1;
    signature[last] = if signature[last] == b'a' { b'b' } else { b'a' };
    damaged.signature = String::from_utf8(signature).expect("signature stays text");
    let mut signed = info.to_group_card().expect("card");
    signed.sign(keypair).expect("sign");
    assert_eq!(unsigned.group_id, stable);
    let before = super::super::unsigned_group_cards_refused();

    for card in [&unsigned, &damaged] {
        let applied = apply_named_group_metadata_event(
            &state,
            NamedGroupMetadataEvent::GroupCardPublished {
                group_id: stable.clone(),
                card: card.clone(),
            },
            sender,
            true,
            None,
        )
        .await;
        assert!(!applied.accepted, "a bad card was applied");
        let (in_cards, in_directory) = caches_contain(&state, &stable).await;
        assert!(
            !in_cards && !in_directory,
            "refused metadata card entered a cache"
        );
    }
    let refused = super::super::unsigned_group_cards_refused();
    assert!(
        refused >= before + 2,
        "metadata apply counted {refused} from {before}"
    );

    let applied = apply_named_group_metadata_event(
        &state,
        NamedGroupMetadataEvent::GroupCardPublished {
            group_id: stable.clone(),
            card: signed,
        },
        sender,
        true,
        None,
    )
    .await;
    assert!(applied.accepted, "the signed card was refused");
    let (in_cards, _) = caches_contain(&state, &stable).await;
    assert!(in_cards, "signed metadata card was not cached");
    assert_eq!(super::super::unsigned_group_cards_refused(), refused);
    Ok(())
}
