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
//! map, so both are held to the same rule. The 29 Oct 2026 rulings are
//! pinned by their own tests: a group whose un-placeholdering write has
//! not landed stays held back for the card routes and its owed card is
//! published once a Durable write lands, and `POST /groups/:id/state/seal`
//! keeps main's behaviour (the reseal may itself end the hold and
//! succeed) in both held-back states. Each test runs on its own state and
//! group history; `held_back_fixture` builds the shared starting point.
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

/// The shared starting point of the tests below: group A held back, group
/// B the healthy control.
struct HeldBackFixture {
    state: std::sync::Arc<crate::server::AppState>,
    /// Keeps the temp data dir alive for the test's duration.
    _dir: tempfile::TempDir,
    /// Group A's map key and stable id; the two spellings coincide.
    key: String,
    stable: String,
    /// Group B, the healthy control: never placeheld.
    b_key: String,
    b_stable: String,
    /// A's sidecar path, blocked by a non-empty directory.
    sidecar: std::path::PathBuf,
    /// A's last durable record, the form the cached card is signed from.
    durable: x0x::groups::GroupInfo,
}

/// Build the held-back fixture. Group A is placeheld with a durable
/// authoritative record, then renamed while its sidecar cannot be
/// written: the rename stays in memory only, so A's live record runs
/// ahead of its durable form. Group B is the healthy control, never
/// placeheld.
async fn held_back_fixture() -> anyhow::Result<HeldBackFixture> {
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
    Ok(HeldBackFixture {
        state,
        _dir,
        key,
        stable,
        b_key,
        b_stable,
        sidecar,
        durable,
    })
}

/// Re-arm the hold on group A: placehold its current record, block the
/// sidecar again, and apply another change whose persist is held back.
/// `new_name` renames the group; `None` bumps the revision only.
async fn rearm_held_back_change(
    state: &std::sync::Arc<crate::server::AppState>,
    key: &str,
    stable: &str,
    sidecar: &std::path::Path,
    new_name: Option<&str>,
) -> anyhow::Result<()> {
    let current = state
        .named_groups
        .read()
        .await
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group A's current record"))?;
    group_recovery::begin_placehold(state, key, &current);
    let outcome = save_named_groups_checked(state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "re-placehold save must be durable: {outcome:?}"
    );
    // The sidecar cannot be written again: a non-empty directory holds
    // its name.
    tokio::fs::remove_file(sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
    let mut changed = current;
    if let Some(new_name) = new_name {
        changed.name = new_name.to_string();
    }
    changed.roster_revision = changed.roster_revision.saturating_add(1);
    changed.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(state, key, changed).await;
    assert!(
        !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the re-armed change is held back: {outcome:?}"
    );
    assert!(group_recovery::is_held_back(state, stable));
    Ok(())
}

/// Sign the card of the DURABLE record and cache it under both spellings,
/// as the routes' writers do.
async fn cache_durable_card(
    state: &std::sync::Arc<crate::server::AppState>,
    key: &str,
    stable: &str,
    durable: &x0x::groups::GroupInfo,
) -> anyhow::Result<()> {
    let card = durable
        .to_signed_group_card(state.agent.identity().agent_keypair())?
        .ok_or_else(|| anyhow::anyhow!("durable record yields a card"))?;
    let mut cache = state.group_card_cache.write().await;
    prune_expired_group_cards(&mut cache, now_millis_u64());
    cache_local_group_card(&mut cache, key.to_string(), card.clone());
    cache_local_group_card(&mut cache, stable.to_string(), card);
    Ok(())
}

/// Advance group B (the healthy control) by one sealed revision and land
/// it Durable. Every encode retries A's sidecar write, so B's save can end
/// A's hold or land A's real record in its own encode.
async fn save_group_b_revision(
    state: &std::sync::Arc<crate::server::AppState>,
    b_key: &str,
) -> anyhow::Result<()> {
    let mut b_changed = state
        .named_groups
        .read()
        .await
        .get(b_key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("group B"))?;
    b_changed.roster_revision = b_changed.roster_revision.saturating_add(1);
    b_changed.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let outcome = persist_named_group_info(state, b_key, b_changed).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "group B's save must be durable: {outcome:?}"
    );
    Ok(())
}

/// The two LOCAL card routes must not sign a fresh card from a held-back
/// group. Group A is placeheld, then renamed while its sidecar cannot be
/// written: the rename stays in memory only, so A's live record runs ahead
/// of its durable form. Group B is the healthy control. With an empty
/// cache, discovery lists no card for A and card-by-id answers the
/// `not_found` shape; once the durable form's card is cached, both routes
/// serve it, never the uncommitted name.
#[tokio::test]
async fn empty_cache_serves_no_card_and_the_cached_card_keeps_the_durable_form() -> Result<()> {
    let fx = held_back_fixture().await?;
    let state = &fx.state;

    // Empty cache. No route may sign a fresh card from the live record,
    // so A contributes no card at all.
    {
        let cache = state.group_card_cache.read().await;
        assert!(
            !cache.contains_key(&fx.key) && !cache.contains_key(&fx.stable),
            "the cache starts empty for the held-back group"
        );
    }
    let (status, body) = discover_body(state).await?;
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
            .any(|c| c["group_id"].as_str() == Some(fx.stable.as_str())),
        "#1570: with an empty cache a held-back group contributes no card"
    );
    assert!(
        names.contains(&"Issue1570Healthy"),
        "positive control: the healthy group stays listed"
    );
    for spelling in [&fx.key, &fx.stable] {
        let (status, _) = card_body(state, spelling).await?;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "#1570: card-by-id for {spelling} answers the not-found shape"
        );
    }
    let (status, body) = card_body(state, &fx.b_stable).await?;
    assert_eq!(status, StatusCode::OK, "the healthy control serves a card");
    assert_eq!(body["name"].as_str(), Some("Issue1570Healthy"));

    // Cached-card fallback. The card is signed from the DURABLE record
    // and cached under both spellings, as the routes' writers do.
    cache_durable_card(state, &fx.key, &fx.stable, &fx.durable).await?;
    for spelling in [&fx.key, &fx.stable] {
        let (status, body) = card_body(state, spelling).await?;
        assert_eq!(status, StatusCode::OK, "the cached card serves {spelling}");
        assert_eq!(
            body["name"].as_str(),
            Some("Issue1570HeldBack"),
            "card-by-id keeps the durable name"
        );
    }
    // Discovery keeps the cached durable card: no fresh card is signed on
    // top of it. (On main the renamed card superseded it, revision win.)
    let (status, body) = discover_body(state).await?;
    assert_eq!(status, StatusCode::OK);
    let cards = body["groups"].as_array().cloned().unwrap_or_default();
    let served = cards
        .iter()
        .find(|c| c["group_id"].as_str() == Some(fx.stable.as_str()))
        .ok_or_else(|| anyhow::anyhow!("the cached card stays listed"))?;
    assert_eq!(
        served["name"].as_str(),
        Some("Issue1570HeldBack"),
        "#1570: discovery serves the cached durable card, not the live record"
    );
    Ok(())
}

/// The state-change hook and the discovery publish choke point. The hook
/// refreshes the card cache from the live record and then republishes;
/// the republish worker and the create fan-out sign from the same live
/// map. While A is held back neither step may touch its card, or the
/// uncommitted card would reach the routes through the cache they still
/// serve: the cached durable card survives the hook, and the shard cache
/// holds no uncommitted card.
#[tokio::test]
async fn state_change_hook_and_discovery_publish_sign_no_held_back_card() -> Result<()> {
    let fx = held_back_fixture().await?;
    let state = &fx.state;

    // The cached durable card, as the routes' writers leave it. The hook
    // and the publish below must not replace it with the live record.
    cache_durable_card(state, &fx.key, &fx.stable, &fx.durable).await?;

    // The state-change hook. It refreshes the card cache from the live
    // record and then republishes; neither step may touch a held-back
    // group, or the uncommitted card would reach the routes through the
    // cache they still serve.
    maybe_publish_group_card_after_state_change(state, &fx.key).await;
    let (status, body) = card_body(state, &fx.stable).await?;
    assert_eq!(status, StatusCode::OK, "the cached card survives the hook");
    assert_eq!(
        body["name"].as_str(),
        Some("Issue1570HeldBack"),
        "#1570: the hook signs no card from the live record into the cache"
    );

    // The discovery publish choke point. The republish worker and the
    // create fan-out sign from the same live map. While A is held back
    // the publish must contribute no card to the shard cache either, or
    // the uncommitted card would re-enter the listing through the shard
    // merge.
    publish_group_card_to_discovery(state, &fx.key).await;
    assert!(
        state.directory_cache.read().await.get(&fx.stable).is_none(),
        "#1570: the discovery publish signs no card from a held-back group"
    );
    let (status, body) = discover_body(state).await?;
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
    Ok(())
}

/// How the hold ends. The fixture's group has no armed ATA, so the
/// worker's pass ends the hold by un-placeholdering the group: its real
/// record is written durably, and the pass then publishes the owed card.
/// A second hold ends in an UNRELATED group's save, whose encode retries
/// the sidecar write; that save refreshes no card of A, so card-by-id
/// stays on A's last committed card until the next pass publishes the
/// owed card.
#[tokio::test]
async fn the_hold_ends_by_the_worker_pass_and_by_another_groups_save() -> Result<()> {
    let fx = held_back_fixture().await?;
    let state = &fx.state;

    // The hold ends by the worker's pass. Card-by-id serves the committed
    // rename, and the discovery publish put the card in the shard cache.
    tokio::fs::remove_dir_all(&fx.sidecar).await?;
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    assert!(
        !group_recovery::is_held_back(state, &fx.stable),
        "the worker's pass ended the hold"
    );
    let (status, body) = card_body(state, &fx.stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed while held back"),
        "#1570: card-by-id serves the commit that ended the hold"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&fx.stable)
            .ok_or_else(|| anyhow::anyhow!("the owed card was published"))?;
        assert_eq!(
            published.name, "renamed while held back",
            "#1570: the publish put the committed card in the shard cache"
        );
    }

    // A second hold, ended by an UNRELATED group's save. Every encode
    // retries the sidecar write, so group B's persist can end A's hold
    // outside the worker pass. B's save refreshes no card of A, so
    // card-by-id stays on A's last committed card until the next worker
    // pass publishes the owed card.
    rearm_held_back_change(
        state,
        &fx.key,
        &fx.stable,
        &fx.sidecar,
        Some("renamed again while held back"),
    )
    .await?;
    // Unblocked, and B's durable save ends A's hold in its own encode.
    tokio::fs::remove_dir_all(&fx.sidecar).await?;
    save_group_b_revision(state, &fx.b_key).await?;
    assert!(
        !group_recovery::is_held_back(state, &fx.stable),
        "group B's save ended group A's hold"
    );
    let (status, body) = card_body(state, &fx.stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed while held back"),
        "#1570: no card of A is refreshed by group B's save"
    );
    // The next worker pass publishes the owed card.
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    let (status, body) = card_body(state, &fx.stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed again while held back"),
        "#1570: card-by-id serves the commit that group B's save ended"
    );
    Ok(())
}

/// The negative control of the worker pass, and the owed card's survival.
/// A pass whose own legacy write fails un-placeholds the group but
/// commits nothing. No owed card may be published from the uncommitted
/// rename: the routes keep the last committed card, and with the cached
/// card evicted the live fallback refuses to sign. Once ANY durable write
/// lands the real record, the next pass publishes the owed card that
/// survived on the entry.
#[tokio::test]
async fn a_pass_whose_legacy_write_fails_publishes_no_uncommitted_card() -> Result<()> {
    let fx = held_back_fixture().await?;
    let state = &fx.state;

    // End the first hold, so the fixture's rename is the committed form
    // on disk and its card is served and published.
    tokio::fs::remove_dir_all(&fx.sidecar).await?;
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    assert!(!group_recovery::is_held_back(state, &fx.stable));

    // A second hold is un-placeheld by a pass whose own legacy write
    // fails, so the real record is NOT committed.
    rearm_held_back_change(
        state,
        &fx.key,
        &fx.stable,
        &fx.sidecar,
        Some("renamed again while held back"),
    )
    .await?;
    // The sidecar is writable again, but the LEGACY file is not: a
    // non-empty directory holds its name, so the pass that un-placeholds
    // the group cannot commit the real record.
    tokio::fs::remove_dir_all(&fx.sidecar).await?;
    let legacy = state.data_dir.join("named_groups.json");
    tokio::fs::remove_file(&legacy).await?;
    tokio::fs::create_dir_all(legacy.join("blocked")).await?;
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    assert!(
        !group_recovery::is_held_back(state, &fx.stable),
        "the pass ended the sidecar hold"
    );
    // 29 Oct 2026 ruling: the un-placeholdering write has not landed, so
    // the group stays held back for the card routes. The entry (and its
    // owed flag) survives the pass.
    assert!(
        group_recovery::is_card_held_back(state, &fx.stable),
        "#1570: a group whose un-placeholdering write has not landed stays held back for the card routes"
    );
    let (status, body) = card_body(state, &fx.stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed while held back"),
        "#1570: a pass whose legacy write failed publishes no uncommitted card"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory.get(&fx.stable);
        assert_ne!(
            published.map(|card| card.name.as_str()),
            Some("renamed again while held back"),
            "#1570: the shard cache holds no uncommitted card either"
        );
    }

    // The same state with the cached card evicted. The live fallback must
    // refuse to sign the uncommitted record (card-by-id answers the
    // not-found shape), and once ANY durable write lands the real record,
    // the next pass publishes the owed card that survived on the entry.
    // Red on main for the first half (the fallback signed the rename);
    // red at c4a788f5 for the second (the owed flag died with the removed
    // entry, so no later pass published).
    {
        let mut cache = state.group_card_cache.write().await;
        cache.remove(&fx.key);
        cache.remove(&fx.stable);
    }
    let (status, _) = card_body(state, &fx.stable).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#1570: no card is signed from a record whose un-placeholdering write has not landed"
    );
    // The legacy file is writable again; group B's durable save lands
    // group A's real record in its own encode, but the entry (and the
    // owed flag) stays until the worker pass.
    tokio::fs::remove_dir_all(&legacy).await?;
    save_group_b_revision(state, &fx.b_key).await?;
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    assert!(!group_recovery::is_held_back(state, &fx.stable));
    assert!(
        !group_recovery::is_card_held_back(state, &fx.stable),
        "the un-placeholdering completed with the durable write"
    );
    let (status, body) = card_body(state, &fx.stable).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["name"].as_str(),
        Some("renamed again while held back"),
        "#1570: the owed card is published once a durable write lands"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&fx.stable)
            .ok_or_else(|| anyhow::anyhow!("the owed card was published"))?;
        assert_eq!(
            published.name, "renamed again while held back",
            "#1570: the publish put the committed card in the shard cache"
        );
    }
    Ok(())
}

/// Engineer ruling, 29 Oct 19:56: `POST /groups/:id/state/seal` keeps
/// main's behaviour on a held-back group. While the sidecar is unwritable
/// the seal answers the existing 500 "seal failed" (its own persist
/// cannot land); once the sidecar is writable the same seal's encode
/// retries the sidecar, ends the hold itself, and succeeds.
#[tokio::test]
async fn a_seal_on_a_held_back_group_keeps_mains_behaviour() -> Result<()> {
    let fx = held_back_fixture().await?;
    let state = &fx.state;

    // End the first hold and publish the committed card, so the reseal
    // below supersedes a published card in the same shards.
    tokio::fs::remove_dir_all(&fx.sidecar).await?;
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    assert!(!group_recovery::is_held_back(state, &fx.stable));

    // The held-back change bumps the revision only (no rename), so the
    // published card supersedes the previous one in the same shards and
    // the shard cache can be asserted on the revision it committed. Red
    // at c4a788f5: the publish gate refused the reseal outright, so the
    // second seal also answered 500 and published nothing.
    rearm_held_back_change(state, &fx.key, &fx.stable, &fx.sidecar, None).await?;
    let published_before = {
        let directory = state.directory_cache.read().await;
        directory
            .get(&fx.stable)
            .map(|card| card.revision)
            .ok_or_else(|| anyhow::anyhow!("the committed card is in the shard cache"))?
    };
    let (status, body) = seal_body(state, &fx.key).await?;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "seal on a held-back group whose sidecar still cannot be written answers the existing 500"
    );
    assert_eq!(body["error"].as_str(), Some("seal failed"));
    {
        let directory = state.directory_cache.read().await;
        assert_eq!(
            directory.get(&fx.stable).map(|card| card.revision),
            Some(published_before),
            "#1570: the failed seal published nothing"
        );
    }
    // The sidecar is writable again: the seal's own persist retries it,
    // ends the hold, commits the reseal and publishes the card.
    tokio::fs::remove_dir_all(&fx.sidecar).await?;
    let (status, body) = seal_body(state, &fx.key).await?;
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
        !group_recovery::is_held_back(state, &fx.stable),
        "the seal's encode ended the hold"
    );
    let committed_revision = state
        .named_groups
        .read()
        .await
        .get(&fx.key)
        .map(|info| info.state_revision)
        .ok_or_else(|| anyhow::anyhow!("group A after the seal"))?;
    assert!(
        committed_revision > published_before,
        "the seal committed a new revision: {committed_revision} > {published_before}"
    );
    {
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&fx.stable)
            .ok_or_else(|| anyhow::anyhow!("the reseal published its card"))?;
        assert_eq!(
            published.revision, committed_revision,
            "#1570: the reseal published the card of the record it committed"
        );
    }
    Ok(())
}

/// The same ruling, 29 Oct 19:56, in the SECOND held-back state: the
/// group's un-placeholdering write has not landed (`unplacehold_pending`).
/// The seal's own persist encodes the group's real record and lands it
/// Durable, so the reseal succeeds and publishes its card; the pending
/// flag itself leaves only with the entry, in the next worker pass.
#[tokio::test]
async fn a_seal_in_the_unplacehold_pending_state_lands_the_real_record() -> Result<()> {
    let fx = held_back_fixture().await?;
    let state = &fx.state;

    // Build the pending state as the negative-control pass does: the
    // sidecar is writable again, but the LEGACY file is not, so the pass
    // that un-placeholds the group cannot commit the real record.
    tokio::fs::remove_dir_all(&fx.sidecar).await?;
    let legacy = state.data_dir.join("named_groups.json");
    tokio::fs::remove_file(&legacy).await?;
    tokio::fs::create_dir_all(legacy.join("blocked")).await?;
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    assert!(
        !group_recovery::is_held_back(state, &fx.stable),
        "the pass ended the sidecar hold"
    );
    assert!(
        group_recovery::is_card_held_back(state, &fx.stable),
        "#1570: a group whose un-placeholdering write has not landed stays held back for the card routes"
    );
    let revision_before = state
        .named_groups
        .read()
        .await
        .get(&fx.key)
        .map(|info| info.state_revision)
        .ok_or_else(|| anyhow::anyhow!("group A in the pending state"))?;

    // The legacy file is writable again. The seal's own persist encodes
    // the group's real record and lands it Durable, so the reseal ends
    // the hold itself and succeeds, as in the first held-back state.
    tokio::fs::remove_dir_all(&legacy).await?;
    let (status, body) = seal_body(state, &fx.key).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1570: a seal whose persist lands the pending un-placeholdering ends the hold itself and succeeds"
    );
    assert_eq!(body["ok"].as_bool(), Some(true));
    assert!(
        body["commit"].is_object(),
        "the seal returns its commit: {}",
        body["commit"]
    );
    // The seal's durable persist landed the real record, but the pending
    // flag leaves only with the entry, in a worker pass — the same ruling
    // as the pass's own step: held back for the card routes until a pass
    // completes the un-placeholdering.
    assert!(
        group_recovery::is_card_held_back(state, &fx.stable),
        "#1570: the pending flag survives the seal that landed its write"
    );
    let committed_revision = state
        .named_groups
        .read()
        .await
        .get(&fx.key)
        .map(|info| info.state_revision)
        .ok_or_else(|| anyhow::anyhow!("group A after the seal"))?;
    assert!(
        committed_revision > revision_before,
        "the seal committed a new revision: {committed_revision} > {revision_before}"
    );
    // The seal route publishes inline, so no detached publish needs
    // draining before the shard cache is read.
    {
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&fx.stable)
            .ok_or_else(|| anyhow::anyhow!("the reseal published its card"))?;
        assert_eq!(
            published.revision, committed_revision,
            "#1570: the reseal published the card of the record it committed"
        );
    }
    // The next worker pass completes the un-placeholdering: the seal's
    // Durable write landed the real record, so the entry goes and the
    // hold ends for the card routes too.
    group_recovery::ensure_placeholders(state).await;
    drain_detached_cards(state).await;
    assert!(
        !group_recovery::is_card_held_back(state, &fx.stable),
        "#1570: the pass after the seal completes the un-placeholdering"
    );
    Ok(())
}
