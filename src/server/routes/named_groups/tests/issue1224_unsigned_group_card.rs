//! #1224: an unsigned or unverifiable GroupCard must not be listed.

use super::*;

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
/// The refusal counter moves.
#[tokio::test]
async fn unsigned_group_card_is_absent_from_discovery_listing() -> Result<()> {
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
    assert!(
        super::super::unsigned_group_cards_refused() > before,
        "the refusal counter did not move"
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
