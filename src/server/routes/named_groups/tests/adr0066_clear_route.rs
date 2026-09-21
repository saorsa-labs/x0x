//! #732 — the manual quarantine clear accepts BOTH spellings of a group id.
//!
//! WHY this matters more than a lookup nicety. ADR-0066 §2 makes the manual
//! clear the ONLY exit for an ordinary group's `no_anchor` marker: no commit
//! ever lifts it. The §5 refusal message every gated route emits therefore
//! points the operator at `POST /groups/:id/quarantine/clear`. But the
//! `named_groups` map is keyed by whichever alias this daemon learned the
//! group under, while every id the operator can actually SEE — the history
//! scope, the WS/SSE `fork_quarantine` annotation, a delegation envelope,
//! `GET /history/scopes` — is the group's STABLE id. With a single-spelling
//! lookup the route answered 404 for exactly the id the refusal had taught
//! the operator to use, so an alias-keyed group's quarantine was permanent
//! from every reachable direction. That is an availability defect dressed as
//! a 404, and it is what these tests pin.
//!
//! The preconditions are asserted too, because "accepts both spellings" must
//! not have been bought by loosening the gate: path (a)/(b) selection, the
//! `force`-without-reason refusal, the no-marker 409, the audit counter and
//! the genuine 404 all still behave as slice 3 left them.

use super::*;

/// The same group filed under a LOCAL ALIAS that is not its stable id — the
/// shape a daemon reaches when it learned the group under one name while the
/// group's own genesis carries another. Mirrors
/// `adr0066_delegations::seed_group_under_alias` deliberately: the fixture
/// that exposed this class in slice 3 is the one that should exercise it here.
///
/// Returns `(alias_key, stable_id)`, which are always different.
async fn seed_alias_keyed_group(
    state: &AppState,
    alias_key: &str,
    genesis_id: &str,
    policy: x0x::groups::GroupPolicy,
) -> Result<(String, String)> {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "issue732-clear-route".to_string(),
        "alias-keyed clear fixture".to_string(),
        state.agent.agent_id(),
        genesis_id.to_string(),
        policy,
    );
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 7,
        state_hash: info.state_hash.clone(),
        committed_by: "9e".repeat(32),
        observed_at_ms: 1_726_000_000_000,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: info.terminal_commit_header(),
            conflicting_commit: info.terminal_commit_header(),
            classification: None,
        },
        // ADR-0066 §2: the ordinary-group shape whose only exit is this route.
        no_anchor: true,
    });
    let stable = info.stable_group_id().to_string();
    assert_ne!(
        stable, alias_key,
        "fixture precondition: the map key must NOT be the stable id, or the \
         test proves nothing"
    );
    state
        .named_groups
        .write()
        .await
        .insert(alias_key.to_string(), info);
    Ok((alias_key.to_string(), stable))
}

fn ordinary_policy() -> x0x::groups::GroupPolicy {
    x0x::groups::GroupPolicy {
        discoverability: x0x::groups::GroupDiscoverability::Hidden,
        admission: x0x::groups::GroupAdmission::InviteOnly,
        confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
        ..x0x::groups::GroupPolicy::default()
    }
}

async fn marker_still_set(state: &AppState, alias_key: &str) -> bool {
    state
        .named_groups
        .read()
        .await
        .get(alias_key)
        .is_some_and(|info| info.is_fork_quarantined())
}

async fn call_clear(
    state: &Arc<AppState>,
    id: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value)> {
    let req: ClearQuarantineRequest = serde_json::from_value(body)?;
    let response =
        clear_group_quarantine(State(Arc::clone(state)), Path(id.to_string()), Json(req))
            .await
            .into_response();
    response_json(response).await
}

/// The defect, stated as behaviour: the STABLE id clears an alias-keyed
/// group. Before #732 this exact call answered 404 while the group sat in the
/// map, quarantined, with no other exit.
#[tokio::test]
async fn issue732_manual_clear_accepts_the_stable_id_of_an_alias_keyed_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (alias_key, stable_id) = seed_alias_keyed_group(
        &state,
        &"5e".repeat(16),
        &"a1".repeat(32),
        ordinary_policy(),
    )
    .await?;

    // A `no_anchor` group has no owner axis, so path (a) is unreachable and
    // must SAY so rather than 404 — reaching this refusal is itself proof the
    // record was resolved under the stable spelling.
    let (status, body) = call_clear(&state, &stable_id, serde_json::json!({})).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the stable id must reach the route's preconditions, not a 404: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("force_required"),
        "path (a) is still unavailable for a group with no owner axis: {body}"
    );
    assert!(
        marker_still_set(&state, &alias_key).await,
        "a refused clear leaves the marker in place"
    );

    // `force` without a reason is still a malformed override, under either
    // spelling — the audit trail is not optional.
    let (status, body) =
        call_clear(&state, &stable_id, serde_json::json!({ "force": true })).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        marker_still_set(&state, &alias_key).await,
        "the malformed override changed nothing"
    );

    // Path (b) through the STABLE id: the exit ADR-0066 §2 promises.
    let (status, body) = call_clear(
        &state,
        &stable_id,
        serde_json::json!({ "force": true, "reason": "benign split confirmed by both operators" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the stable id clears: {body}");
    assert_eq!(body["cleared_by"].as_str(), Some("force"));
    assert_eq!(
        body["group_id"].as_str(),
        Some(stable_id.as_str()),
        "the response still reports the stable id, as it always did"
    );
    assert!(
        !marker_still_set(&state, &alias_key).await,
        "the marker is gone from the record the map actually holds — the \
         ALIAS-keyed one, not a phantom under the stable id"
    );
    assert_eq!(
        state.named_groups.read().await.len(),
        1,
        "resolving the stable id must not have inserted a second record"
    );
    Ok(())
}

/// The spelling that always worked keeps working, and the clear is still
/// attributable. Same fixture, same marker, the other id.
#[tokio::test]
async fn issue732_manual_clear_still_accepts_the_roster_map_key() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (alias_key, stable_id) = seed_alias_keyed_group(
        &state,
        &"6f".repeat(16),
        &"b2".repeat(32),
        ordinary_policy(),
    )
    .await?;

    let (status, body) = call_clear(
        &state,
        &alias_key,
        serde_json::json!({ "force": true, "reason": "operator override via the map key" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the map key clears: {body}");
    assert_eq!(
        body["group_id"].as_str(),
        Some(stable_id.as_str()),
        "the response reports the stable id whichever spelling was called"
    );
    assert!(!marker_still_set(&state, &alias_key).await);

    // Clearing twice is a 409, not a second silent success: there is nothing
    // left to clear, and the counter must not be inflated by retries.
    let (status, body) = call_clear(
        &state,
        &stable_id,
        serde_json::json!({ "force": true, "reason": "retry" }),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a cleared group has no marker to clear, under either spelling: {body}"
    );
    Ok(())
}

/// An owner-anchored group reaches the owner-key fence through the stable id
/// too. This install holds no owner user key, so the reachable proof is the
/// typed `owner_key_unavailable` 409 — previously a 404, which told the
/// operator the group did not exist rather than which path to take.
#[tokio::test]
async fn issue732_owner_anchored_precondition_is_reached_through_the_stable_id() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let mut policy = ordinary_policy();
    policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
    let (alias_key, stable_id) =
        seed_alias_keyed_group(&state, &"7a".repeat(16), &"c3".repeat(32), policy).await?;

    let (status, body) = call_clear(&state, &stable_id, serde_json::json!({})).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("owner_key_unavailable"),
        "the owner-axis fence is what answers, so the record WAS found under \
         the stable id: {body}"
    );
    assert!(
        marker_still_set(&state, &alias_key).await,
        "the fence held: no marker was cleared without the owner key or force"
    );
    Ok(())
}

/// A genuinely unknown id is still a 404. The scan by `stable_group_id()`
/// must not turn "no such group" into a match on some other record.
#[tokio::test]
async fn issue732_unknown_group_id_is_still_not_found() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (alias_key, _stable) = seed_alias_keyed_group(
        &state,
        &"8b".repeat(16),
        &"d4".repeat(32),
        ordinary_policy(),
    )
    .await?;

    let (status, body) = call_clear(
        &state,
        &"ff".repeat(32),
        serde_json::json!({ "force": true, "reason": "should never apply" }),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        marker_still_set(&state, &alias_key).await,
        "the seeded group's marker is untouched by a miss on another id"
    );
    Ok(())
}

/// WHY (#732 r7 — cross-model review, Codex P1 side b). A roster can
/// legitimately hold TWO entries for one group: `merge_home_suite_groups`
/// inserts the sidecar record under ITS key while a differently-keyed named
/// entry stays in place, which is the shape
/// `collect_same_stable_group_aliases` exists for and which a dozen other
/// mutations already spread across.
///
/// The clear route mutated only the resolver's `map_key`, so a successful,
/// durable clear left the OTHER spelling quarantined. The endpoint reported
/// `ok: true`; `server::resolve_group_entry_locked` returns an exact key match
/// FIRST, so any gate asked by that spelling still refused, with no remaining
/// exit — the route had already said it was cleared.
///
/// The claim: install and clear are decisions about a GROUP, not about a map
/// key, so both apply to every entry sharing the stable id, and the clear
/// survives a reload from disk.
#[tokio::test]
async fn issue732_manual_clear_clears_every_spelling_and_survives_reload() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let alias_key = "issue732-duplicate-alias";
    let (_alias, stable_id) =
        seed_alias_keyed_group(&state, alias_key, &"c7".repeat(32), ordinary_policy()).await?;

    // The duplicate: the SAME group filed a second time under its stable id,
    // exactly as the sidecar/named merge leaves it.
    let duplicate = state
        .named_groups
        .read()
        .await
        .get(alias_key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("seeded record"))?;
    state
        .named_groups
        .write()
        .await
        .insert(stable_id.clone(), duplicate);
    {
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups
                .values()
                .filter(|info| info.stable_group_id() == stable_id)
                .count(),
            2,
            "fixture precondition: two entries, one stable id"
        );
        assert!(
            groups.values().all(|info| info.is_fork_quarantined()),
            "both spellings start contained"
        );
    }

    let (status, body) = call_clear(
        &state,
        alias_key,
        serde_json::json!({ "force": true, "reason": "duplicate-alias clear" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the clear succeeds: {body}");

    {
        let groups = state.named_groups.read().await;
        assert!(
            groups.values().all(|info| !info.is_fork_quarantined()),
            "#732 r7: EVERY spelling is cleared — a clear is about the group, not the map key"
        );
        // The resolver's own answer, by BOTH spellings, is what the gates ask.
        for spelling in [alias_key, stable_id.as_str()] {
            let (_key, info) = crate::server::resolve_group_entry_locked(&groups, spelling)
                .ok_or_else(|| anyhow::anyhow!("resolver lost {spelling}"))?;
            assert!(
                !info.is_fork_quarantined(),
                "the spelling `{spelling}` must resolve to a CLEARED record"
            );
        }
        assert!(
            groups.values().all(|info| info
                .invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref())
                .is_none()),
            "and the evidence gate is re-armed on every spelling, not just one"
        );
    }

    // And it is DURABLE on every spelling: a reload from the store files must
    // not bring either one back.
    let reloaded =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    assert!(
        reloaded
            .values()
            .filter(|info| info.stable_group_id() == stable_id)
            .all(|info| !info.is_fork_quarantined()),
        "#732 r7: the clear survives a reload — no spelling resurrects the marker"
    );
    Ok(())
}
