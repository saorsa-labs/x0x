//! #1570 follow-up on PR #1646, ZCode exact-head review MINOR (local card
//! routes): a held-back group's live record is ahead of its durable form,
//! so no local card route signs a fresh card from it; the cached card is
//! served, as for a group this node does not own. RED (on main, without
//! the route checks): `GET /groups/discover` synthesized a fresh card from
//! the live record, and `GET /groups/cards/:id` signed one at its
//! fallback. GREEN: with an empty cache, discovery lists no card for the
//! group and card-by-id answers the `not_found` shape; with a cached card,
//! both routes serve the card of the last durable form. The state-change
//! hook's cache refresh and the discovery publish sign from the same live
//! map, so both are held to the same rule. Parts 8–9 pin the 29 Oct 2026
//! rulings: a group whose un-placeholdering write has not landed stays
//! held back for the card routes and its owed card is published once a
//! Durable write lands, and `POST /groups/:id/state/seal` keeps main's
//! behaviour (the reseal may itself end the hold and succeed).
//! Local temp state only: no network config, sockets or bootstrap.

use super::*;

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use x0x::groups::recovery as s3;

/// Drive `GET /groups/discover` and collect its status and JSON body.
async fn discover_body(
    state: &std::sync::Arc<crate::server::AppState>,
) -> anyhow::Result<(axum::http::StatusCode, serde_json::Value)> {
    let resp = discover_groups(State(state.clone()), Query(HashMap::new()))
        .await
        .into_response();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// Drive `GET /groups/cards/:id` and collect its status and JSON body.
async fn card_body(
    state: &std::sync::Arc<crate::server::AppState>,
    id: &str,
) -> anyhow::Result<(axum::http::StatusCode, serde_json::Value)> {
    let resp = get_group_card(State(state.clone()), Path(id.to_string()))
        .await
        .into_response();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// Drive `POST /groups/:id/state/seal` as the durable local owner and
/// collect its status and JSON body.
async fn seal_body(
    state: &std::sync::Arc<crate::server::AppState>,
    id: &str,
) -> anyhow::Result<(axum::http::StatusCode, serde_json::Value)> {
    let resp = seal_group_state(
        State(state.clone()),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(id.to_string()),
    )
    .await
    .into_response();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// Await the detached card publishes the worker pass spawned, so the
/// assertions below see the published card deterministically.
async fn drain_detached_cards(state: &std::sync::Arc<crate::server::AppState>) {
    let pending: Vec<tokio::task::JoinHandle<()>> = {
        let mut guard = state
            .detached_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_mut().map(std::mem::take).unwrap_or_default()
    };
    for task in pending {
        let _ = task.await;
    }
}

/// A plain listable group owned by this node. The routes' listing gate
/// needs a non-Hidden discoverability, so the fixture uses
/// `PublicDirectory`, not the Hidden TreeKEM fixture group.
fn local_group(
    state: &crate::server::AppState,
    name: &str,
    id_hex: &str,
) -> x0x::groups::GroupInfo {
    let policy = x0x::groups::GroupPolicy {
        discoverability: x0x::groups::GroupDiscoverability::PublicDirectory,
        ..Default::default()
    };
    x0x::groups::GroupInfo::with_policy(
        name.to_string(),
        "issue1570 held-back card fixture".to_string(),
        state.agent.agent_id(),
        id_hex.to_string(),
        policy,
    )
}

/// The two LOCAL card routes must not sign a fresh card from a held-back
/// group. Group A is placeheld, then renamed while its sidecar cannot be
/// written: the rename stays in memory only, so A's live record runs ahead
/// of its durable form. Group B is the healthy control. With an empty
/// cache, discovery lists no card for A and card-by-id answers the
/// `not_found` shape; once the durable form's card is cached, both routes
/// and the state-change hook serve it, never the uncommitted name.
#[tokio::test]
async fn local_card_routes_sign_no_card_from_a_held_back_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;

    // Group A, held back below. `with_policy` pins the genesis id to the
    // MLS id, so both spellings coincide; the routes resolve either, so
    // every card lookup is driven under both.
    let key = "7c".repeat(16);
    let a = local_group(&state, "Issue1570HeldBack", &key);
    let stable = a.stable_group_id().to_string();
    assert_eq!(stable, key, "the fixture's two id spellings coincide");
    // Group B, the healthy control: never placeheld.
    let b_key = "8d".repeat(16);
    let b = local_group(&state, "Issue1570Healthy", &b_key);
    let b_stable = b.stable_group_id().to_string();
    {
        let mut groups = state.named_groups.write().await;
        groups.insert(key.clone(), a);
        groups.insert(b_key.clone(), b);
    }

    // Seed A's durable record, then read it back as its last committed
    // form.
    let seed = state
        .named_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group A"))?;
    let outcome = persist_named_group_info(&state, &key, seed).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "seed persist must be durable: {outcome:?}"
    );
    let durable = state
        .named_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("seeded group A"))?;

    // Placehold A: its authoritative record goes to the sidecar, durably.
    group_recovery::begin_placehold(&state, &key, &durable);
    let outcome = save_named_groups_checked(&state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "placehold save must be durable: {outcome:?}"
    );
    assert!(!group_recovery::is_held_back(&state, &stable));

    // The sidecar cannot be written: a non-empty directory holds its name.
    let sidecar = state
        .data_dir
        .join(s3::GROUP_RECOVERY_DIR)
        .join(s3::sidecar_file_name(&stable));
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;

    // The uncommitted change: a rename, sealed at the next revision like
    // the rebind fixture (the seal also raises the card revision, which
    // `GroupCard::supersedes` compares). Its persist is held back.
    let mut renamed = durable.clone();
    renamed.name = "renamed while held back".to_string();
    renamed.roster_revision = renamed.roster_revision.saturating_add(1);
    renamed.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(&state, &key, renamed).await;
    assert!(
        !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the rename is held back: {outcome:?}"
    );
    assert!(group_recovery::is_held_back(&state, &stable));

    // Part 1: empty cache. No route may sign a fresh card from the live
    // record, so A contributes no card at all.
    {
        let cache = state.group_card_cache.read().await;
        assert!(
            !cache.contains_key(&key) && !cache.contains_key(&stable),
            "the cache starts empty for the held-back group"
        );
    }
    let (status, body) = discover_body(&state).await?;
    assert_eq!(status, StatusCode::OK);
    let cards = body["groups"].as_array().cloned().unwrap_or_default();
    let names: Vec<&str> = cards.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(
        !names.contains(&"renamed while held back"),
        "#1570: discovery must not list a card signed from the rename"
    );
    assert!(
        !cards
            .iter()
            .any(|c| c["group_id"].as_str() == Some(stable.as_str())),
        "#1570: with an empty cache a held-back group contributes no card"
    );
    assert!(
        names.contains(&"Issue1570Healthy"),
        "positive control: the healthy group stays listed"
    );
    for spelling in [&key, &stable] {
        let (status, _) = card_body(&state, spelling).await?;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "#1570: card-by-id for {spelling} answers the not-found shape"
        );
    }
    let (status, body) = card_body(&state, &b_stable).await?;
    assert_eq!(status, StatusCode::OK, "the healthy control serves a card");
    assert_eq!(body["name"].as_str(), Some("Issue1570Healthy"));

    // Part 2: cached-card fallback. The card is signed from the DURABLE
    // record and cached under both spellings, as the routes' writers do.
    let card = durable
        .to_signed_group_card(state.agent.identity().agent_keypair())?
        .ok_or_else(|| anyhow::anyhow!("durable record yields a card"))?;
    {
        let mut cache = state.group_card_cache.write().await;
        prune_expired_group_cards(&mut cache, now_millis_u64());
        cache_local_group_card(&mut cache, key.clone(), card.clone());
        cache_local_group_card(&mut cache, stable.clone(), card);
    }
    for spelling in [&key, &stable] {
        let (status, body) = card_body(&state, spelling).await?;
        assert_eq!(status, StatusCode::OK, "the cached card serves {spelling}");
        assert_eq!(
            body["name"].as_str(),
            Some("Issue1570HeldBack"),
            "card-by-id keeps the durable name"
        );
    }
    // Discovery keeps the cached durable card: no fresh card is signed on
    // top of it. (On main the renamed card superseded it, revision win.)
    let (status, body) = discover_body(&state).await?;
    assert_eq!(status, StatusCode::OK);
    let cards = body["groups"].as_array().cloned().unwrap_or_default();
    let served = cards
        .iter()
        .find(|c| c["group_id"].as_str() == Some(stable.as_str()))
        .ok_or_else(|| anyhow::anyhow!("the cached card stays listed"))?;
    assert_eq!(
        served["name"].as_str(),
        Some("Issue1570HeldBack"),
        "#1570: discovery serves the cached durable card, not the live record"
    );

    // Part 3: the state-change hook. It refreshes the card cache from the
    // live record and then republishes; neither step may touch a held-back
    // group, or the uncommitted card would reach the routes through the
    // cache they still serve.
    maybe_publish_group_card_after_state_change(&state, &key).await;
    let (status, body) = card_body(&state, &stable).await?;
    assert_eq!(status, StatusCode::OK, "the cached card survives the hook");
    assert_eq!(
        body["name"].as_str(),
        Some("Issue1570HeldBack"),
        "#1570: the hook signs no card from the live record into the cache"
    );

    // Part 4: the discovery publish choke point. The republish worker and
    // the create fan-out sign from the same live map. While A is held back
    // the publish must contribute no card to the shard cache either, or the
    // uncommitted card would re-enter the listing through the shard merge.
    publish_group_card_to_discovery(&state, &key).await;
    assert!(
        state.directory_cache.read().await.get(&stable).is_none(),
        "#1570: the discovery publish signs no card from a held-back group"
    );
    let (status, body) = discover_body(&state).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body["groups"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .any(|c| c["name"].as_str() == Some("renamed while held back")),
        "the shard cache holds no uncommitted card either"
    );

    // Part 5: the hold ends. The fixture's group has no armed ATA, so the
    // pass ends the hold by un-placeholdering the group: its real record
    // is written durably, and the pass then publishes the owed card —
    // card-by-id serves the committed rename, and the discovery publish
    // put the card in the shard cache.
    tokio::fs::remove_dir_all(&sidecar).await?;
    group_recovery::ensure_placeholders(&state).await;
    drain_detached_cards(&state).await;
    assert!(
        !group_recovery::is_held_back(&state, &stable),
        "the worker's pass ended the hold"
    );
    let (status, body) = card_body(&state, &stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed while held back"),
        "#1570: card-by-id serves the commit that ended the hold"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&stable)
            .ok_or_else(|| anyhow::anyhow!("the owed card was published"))?;
        assert_eq!(
            published.name, "renamed while held back",
            "#1570: the publish put the committed card in the shard cache"
        );
    }

    // Part 6: a second hold, ended by an UNRELATED group's save. Every
    // encode retries the sidecar write, so group B's persist can end A's
    // hold outside the worker pass. B's save refreshes no card of A, so
    // card-by-id stays on A's last committed card until the next worker
    // pass publishes the owed card.
    let current = state
        .named_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group A after part 5"))?;
    group_recovery::begin_placehold(&state, &key, &current);
    let outcome = save_named_groups_checked(&state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "re-placehold save must be durable: {outcome:?}"
    );
    // The sidecar cannot be written again: a non-empty directory holds
    // its name.
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
    let mut renamed_again = current.clone();
    renamed_again.name = "renamed again while held back".to_string();
    renamed_again.roster_revision = renamed_again.roster_revision.saturating_add(1);
    renamed_again.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(&state, &key, renamed_again).await;
    assert!(
        !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the second rename is held back: {outcome:?}"
    );
    assert!(group_recovery::is_held_back(&state, &stable));
    // Unblocked, and B's durable save ends A's hold in its own encode.
    tokio::fs::remove_dir_all(&sidecar).await?;
    let mut b_changed = state
        .named_groups
        .read()
        .await
        .get(&b_key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group B"))?;
    b_changed.roster_revision = b_changed.roster_revision.saturating_add(1);
    b_changed.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(&state, &b_key, b_changed).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "group B's save must be durable: {outcome:?}"
    );
    assert!(
        !group_recovery::is_held_back(&state, &stable),
        "group B's save ended group A's hold"
    );
    let (status, body) = card_body(&state, &stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed while held back"),
        "#1570: no card of A is refreshed by group B's save"
    );
    // The next worker pass publishes the owed card.
    group_recovery::ensure_placeholders(&state).await;
    drain_detached_cards(&state).await;
    let (status, body) = card_body(&state, &stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed again while held back"),
        "#1570: card-by-id serves the commit that group B's save ended"
    );

    // Part 7: the negative control of the same pass. A third hold is
    // un-placeheld by a pass whose own legacy write fails, so the real
    // record is NOT committed. No owed card may be published from the
    // uncommitted rename: the routes keep the last committed card.
    let current = state
        .named_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group A after part 6"))?;
    group_recovery::begin_placehold(&state, &key, &current);
    let outcome = save_named_groups_checked(&state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "second re-placehold save must be durable: {outcome:?}"
    );
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
    let mut renamed_thrice = current.clone();
    renamed_thrice.name = "renamed thrice while held back".to_string();
    renamed_thrice.roster_revision = renamed_thrice.roster_revision.saturating_add(1);
    renamed_thrice.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(&state, &key, renamed_thrice).await;
    assert!(
        !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the third rename is held back: {outcome:?}"
    );
    assert!(group_recovery::is_held_back(&state, &stable));
    // The sidecar is writable again, but the LEGACY file is not: a
    // non-empty directory holds its name, so the pass that un-placeholds
    // the group cannot commit the real record.
    tokio::fs::remove_dir_all(&sidecar).await?;
    let legacy = state.data_dir.join("named_groups.json");
    tokio::fs::remove_file(&legacy).await?;
    tokio::fs::create_dir_all(legacy.join("blocked")).await?;
    group_recovery::ensure_placeholders(&state).await;
    drain_detached_cards(&state).await;
    assert!(
        !group_recovery::is_held_back(&state, &stable),
        "the pass ended the sidecar hold"
    );
    // 29 Oct 2026 ruling: the un-placeholdering write has not landed, so
    // the group stays held back for the card routes — the entry (and its
    // owed flag) survives the pass.
    assert!(
        group_recovery::is_card_held_back(&state, &stable),
        "#1570: a group whose un-placeholdering write has not landed stays held back for the card routes"
    );
    let (status, body) = card_body(&state, &stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed again while held back"),
        "#1570: a pass whose legacy write failed publishes no uncommitted card"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory.get(&stable);
        assert_ne!(
            published.map(|card| card.name.as_str()),
            Some("renamed thrice while held back"),
            "#1570: the shard cache holds no uncommitted card either"
        );
    }

    // Part 8: the same state with the cached card evicted. The live
    // fallback must refuse to sign the uncommitted record (card-by-id
    // answers the not-found shape), and once ANY durable write lands the
    // real record, the next pass publishes the owed card that survived
    // on the entry. Red on main for the first half (the fallback signed
    // the rename); red at c4a788f5 for the second (the owed flag died
    // with the removed entry, so no later pass published).
    {
        let mut cache = state.group_card_cache.write().await;
        cache.remove(&key);
        cache.remove(&stable);
    }
    let (status, _) = card_body(&state, &stable).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#1570: no card is signed from a record whose un-placeholdering write has not landed"
    );
    // The legacy file is writable again; group B's durable save lands
    // group A's real record in its own encode, but the entry (and the
    // owed flag) stays until the worker pass.
    tokio::fs::remove_dir_all(&legacy).await?;
    let mut b_changed = state
        .named_groups
        .read()
        .await
        .get(&b_key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group B for part 8"))?;
    b_changed.roster_revision = b_changed.roster_revision.saturating_add(1);
    b_changed.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(&state, &b_key, b_changed).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "group B's part-8 save must be durable: {outcome:?}"
    );
    group_recovery::ensure_placeholders(&state).await;
    drain_detached_cards(&state).await;
    assert!(!group_recovery::is_held_back(&state, &stable));
    assert!(
        !group_recovery::is_card_held_back(&state, &stable),
        "the un-placeholdering completed with the durable write"
    );
    let (status, body) = card_body(&state, &stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed thrice while held back"),
        "#1570: the owed card is published once a durable write lands"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&stable)
            .ok_or_else(|| anyhow::anyhow!("the owed card was published"))?;
        assert_eq!(
            published.name, "renamed thrice while held back",
            "#1570: the publish put the committed card in the shard cache"
        );
    }

    // Part 9 (Engineer ruling, 29 Oct 19:56): `POST /groups/:id/state/seal`
    // keeps main's behaviour on a held-back group. While the sidecar is
    // unwritable the seal answers the existing 500 "seal failed" (its own
    // persist cannot land); once the sidecar is writable the same seal's
    // encode retries the sidecar, ends the hold itself, and succeeds. Red
    // at c4a788f5: the publish gate refused the reseal outright, so the
    // second seal also answered 500 and published nothing. The held-back
    // change bumps the revision only (no rename), so the published card
    // supersedes the previous one in the same shards and the shard cache
    // can be asserted on the revision it committed.
    let current = state
        .named_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group A after part 8"))?;
    group_recovery::begin_placehold(&state, &key, &current);
    let outcome = save_named_groups_checked(&state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "part-9 re-placehold save must be durable: {outcome:?}"
    );
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
    let mut bumped = current.clone();
    bumped.roster_revision = bumped.roster_revision.saturating_add(1);
    bumped.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(&state, &key, bumped).await;
    assert!(
        !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the fourth change is held back: {outcome:?}"
    );
    assert!(group_recovery::is_held_back(&state, &stable));
    let published_before = {
        let directory = state.directory_cache.read().await;
        directory
            .get(&stable)
            .map(|card| card.revision)
            .ok_or_else(|| anyhow::anyhow!("part-8 card in the shard cache"))?
    };
    let (status, body) = seal_body(&state, &key).await?;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "seal on a held-back group whose sidecar still cannot be written answers the existing 500"
    );
    assert_eq!(body["error"].as_str(), Some("seal failed"));
    {
        let directory = state.directory_cache.read().await;
        assert_eq!(
            directory.get(&stable).map(|card| card.revision),
            Some(published_before),
            "#1570: the failed seal published nothing"
        );
    }
    // The sidecar is writable again: the seal's own persist retries it,
    // ends the hold, commits the reseal and publishes the card.
    tokio::fs::remove_dir_all(&sidecar).await?;
    let (status, body) = seal_body(&state, &key).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1570: a seal whose persist lands ends the hold itself and succeeds, as on main"
    );
    assert_eq!(body["ok"].as_bool(), Some(true));
    assert!(
        body["commit"].is_object(),
        "the seal returns its commit: {}",
        body["commit"]
    );
    assert!(
        !group_recovery::is_held_back(&state, &stable),
        "the seal's encode ended the hold"
    );
    let committed_revision = state
        .named_groups
        .read()
        .await
        .get(&key)
        .map(|info| info.state_revision)
        .ok_or_else(|| anyhow::anyhow!("group A after the seal"))?;
    assert!(
        committed_revision > published_before,
        "the seal committed a new revision: {committed_revision} > {published_before}"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&stable)
            .ok_or_else(|| anyhow::anyhow!("the reseal published its card"))?;
        assert_eq!(
            published.revision, committed_revision,
            "#1570: the reseal published the card of the record it committed"
        );
    }
    Ok(())
}
