//! ADR-0066 §3b (slice 3) — delegations fail closed under fork quarantine.
//!
//! WHY these tests exist, in the ADR's own terms: "a quarantined group's
//! roster is exactly the thing under dispute, so minting new authority
//! from it, or honouring authority derived from it, must fail closed."
//! Two entries in the ADR's Attack/Regression matrix are the behaviours
//! pinned here — "quarantined owner-axis group grants a delegation:
//! succeeds → refused" and "delegated send-as from a contested roster:
//! honoured → fails closed".
//!
//! Each test states the availability claim it defends, not just the code
//! path it walks:
//!
//! - rows 15/17/18/19 refuse, and refuse having changed NOTHING — no
//!   signature, no history row, no index entry, no registry id. A refusal
//!   that happens after the mutation is not containment, it is an error
//!   message;
//! - row 16 keeps SERVING, annotated — containment must not blind the
//!   operator who is reading the delegation list to find out who holds
//!   authority during the fork;
//! - the refusal carries the §5 body (R5's acceptance bar: a refusal
//!   without its message is a failing test), including the `no_anchor`
//!   branch that tells an ordinary group's operator that nothing will
//!   clear this for them;
//! - a group with no marker is byte-for-byte unaffected, and so is a
//!   delegation whose group is not the quarantined one. The blast radius
//!   of this slice is the contested group and nothing else.

use super::*;

use crate::server::delegations::{
    authorize, authorize_send_as, chain_members_active, delegate_group_authority,
    fork_quarantine_marker, index_committed, list_group_delegations,
    rebuild_global_delegation_registry, DelegateRequest,
};

/// A minimal loopback-only daemon state on a temp dir. No sockets are
/// dialled and no peer exists: every assertion here is about local state.
async fn delegation_state() -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            // Durable ADR-0023 history is not optional here: it is the
            // source of truth a delegation's effectiveness rests on, and
            // "nothing was written" is only an assertion if there is a
            // store that COULD have been written to.
            .with_history(x0x::history::HistoryConfig {
                enabled: true,
                db_path: Some(data_dir.join("history.db")),
                ..x0x::history::HistoryConfig::default()
            })
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(data_dir, agent).await?;
    Ok((state, dir))
}

/// Delegation rides the SignedPublic bus (`delegate_group_authority`
/// rejects anything else), so the fixture group has to be one.
fn signed_public_policy() -> x0x::groups::GroupPolicy {
    x0x::groups::GroupPolicy {
        discoverability: x0x::groups::GroupDiscoverability::Hidden,
        admission: x0x::groups::GroupAdmission::InviteOnly,
        confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    }
}

/// A signed-public group the local agent administers, with `delegate` as a
/// second active member so a grant to it is well-formed.
async fn seed_group(
    state: &AppState,
    group_id: &str,
    delegate_hex: &str,
) -> Result<(String, x0x::groups::GroupInfo)> {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "adr0066-delegations".to_string(),
        "slice 3 fixture".to_string(),
        state.agent.agent_id(),
        group_id.to_string(),
        signed_public_policy(),
    );
    let member = x0x::groups::GroupMember::new_member(
        delegate_hex.to_string(),
        None,
        Some(hex::encode(state.agent.agent_id().as_bytes())),
        1,
    );
    info.members_v2.insert(delegate_hex.to_string(), member);
    let stable = info.stable_group_id().to_string();
    let mut groups = state.named_groups.write().await;
    groups.insert(group_id.to_string(), info.clone());
    Ok((stable, info))
}

/// The same group, but filed in the roster map under a LOCAL ALIAS that is
/// not its stable id — the shape a daemon ends up in when it learned the
/// group under one name and the group's own genesis carries another.
///
/// Returns `(alias_key, stable_id)`, which are deliberately different.
async fn seed_group_under_alias(
    state: &AppState,
    alias_key: &str,
    stable_id: &str,
    delegate_hex: &str,
) -> Result<(String, String)> {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "adr0066-delegations-alias".to_string(),
        "slice 3 alias fixture".to_string(),
        state.agent.agent_id(),
        stable_id.to_string(),
        signed_public_policy(),
    );
    let member = x0x::groups::GroupMember::new_member(
        delegate_hex.to_string(),
        None,
        Some(hex::encode(state.agent.agent_id().as_bytes())),
        1,
    );
    info.members_v2.insert(delegate_hex.to_string(), member);
    let stable = info.stable_group_id().to_string();
    assert_ne!(
        stable, alias_key,
        "fixture precondition: the whole point is that the map key is NOT the stable id"
    );
    let mut groups = state.named_groups.write().await;
    groups.insert(alias_key.to_string(), info);
    Ok((alias_key.to_string(), stable))
}

/// An authenticated-evidence marker, in whichever branch the caller wants.
/// `no_anchor` is the ordinary-group shape slice 2 introduced: nothing
/// clears it automatically, which is exactly why the §5 message has to
/// name the manual remedy.
fn marker(info: &x0x::groups::GroupInfo, no_anchor: bool) -> x0x::groups::ForkQuarantine {
    x0x::groups::ForkQuarantine {
        revision: 7,
        state_hash: info.state_hash.clone(),
        committed_by: "9e".repeat(32),
        observed_at_ms: 1_726_000_000_000,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: info.terminal_commit_header(),
            conflicting_commit: info.terminal_commit_header(),
            classification: None,
        },
        no_anchor,
    }
}

async fn install_marker(state: &AppState, group_id: &str, no_anchor: bool) {
    let mut groups = state.named_groups.write().await;
    if let Some(info) = groups.get_mut(group_id) {
        let m = marker(info, no_anchor);
        info.fork_quarantine = Some(m);
    }
}

/// The manual clear, applied to local state the way
/// `POST /groups/:id/quarantine/clear` leaves it.
async fn manual_clear(state: &AppState, group_id: &str) {
    let mut groups = state.named_groups.write().await;
    if let Some(info) = groups.get_mut(group_id) {
        info.fork_quarantine = None;
    }
}

/// A well-formed, signature-valid grant for `group_id`, plus the roster
/// view that would make it pass every pre-ADR-0066 check. Anything this
/// helper returns is authority that WOULD be honoured, so a test that
/// shows it refused is showing the quarantine gate doing the work and not
/// some unrelated invalidity.
fn valid_grant(
    group_id: &str,
) -> Result<(
    x0x::delegation::SignedDelegation,
    x0x::identity::AgentId,
    std::collections::HashSet<String>,
)> {
    let delegator = x0x::identity::AgentKeypair::generate()?;
    let delegate = x0x::identity::AgentKeypair::generate()?;
    let d = x0x::delegation::Delegation {
        delegation_id: [0x5A; 16],
        issued_at_ms: 1_000,
        task_ref: None,
        from_agent: delegator.agent_id(),
        to_agent: delegate.agent_id(),
        authority_scope: x0x::delegation::AuthorityScope::SendAs,
        verbs: vec![x0x::delegation::DelegationVerb::SendPublicMessage],
        expiry_ms: u64::MAX,
        parent_delegation: None,
        depth: 1,
        group_id: group_id.to_string(),
    };
    let sd = x0x::delegation::sign_delegation(&delegator, &d)?;
    let active: std::collections::HashSet<String> = [
        hex::encode(delegator.agent_id().as_bytes()),
        hex::encode(delegate.agent_id().as_bytes()),
    ]
    .into_iter()
    .collect();
    Ok((sd, delegate.agent_id(), active))
}

/// The §5 acceptance bar, asserted in one place so every refusing row is
/// held to the same contract rather than to whatever its own test
/// remembered to check.
fn assert_adr0066_refusal(body: &serde_json::Value, no_anchor: bool, case: &str) {
    assert_eq!(
        body["reason"].as_str(),
        Some("fork_quarantined"),
        "({case}) §5: the machine code lives in `reason` — clients match on this"
    );
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        !error.is_empty() && error != "fork_quarantined",
        "({case}) §5: `error` is prose, never the bare machine code — got {error:?}"
    );
    assert!(
        error.contains("fork-quarantined") && error.contains("contested"),
        "({case}) §5: the sentence must name the condition and why: {error:?}"
    );
    assert!(
        error.contains("quarantine/clear") && error.contains("x0x groups quarantine clear"),
        "({case}) §5: a message naming the condition but not the REMEDY fails R5's \
         'actionable' bar: {error:?}"
    );
    let fq = &body["fork_quarantine"];
    assert_eq!(
        fq["revision"].as_u64(),
        Some(7),
        "({case}) which divergence"
    );
    assert_eq!(
        fq["observed_at_ms"].as_u64(),
        Some(1_726_000_000_000),
        "({case}) when this node saw it"
    );
    assert_eq!(
        fq["no_anchor"].as_bool(),
        Some(no_anchor),
        "({case}) §5: `no_anchor` is what tells an ordinary group's operator that \
         nothing clears this automatically"
    );
    assert_eq!(
        fq["clear_with"].as_str(),
        Some("POST /groups/:id/quarantine/clear"),
        "({case}) §5: the remedy, machine-readable"
    );
}

fn delegate_body(to_agent: &str) -> Result<DelegateRequest> {
    Ok(serde_json::from_value(serde_json::json!({
        "to_agent": to_agent,
        "scope": "send_as",
        "expiry_ms": now_millis_u64() + 600_000,
    }))?)
}

async fn call_delegate(
    state: &Arc<AppState>,
    group_id: &str,
    to_agent: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let resp = delegate_group_authority(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.to_string()),
        Json(delegate_body(to_agent)?),
    )
    .await
    .into_response();
    response_json(resp).await
}

async fn call_list(
    state: &Arc<AppState>,
    group_id: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let resp = list_group_delegations(State(Arc::clone(state)), Path(group_id.to_string()))
        .await
        .into_response();
    response_json(resp).await
}

/// Durable history rows for one group scope — the mutation probe. Rows 15
/// and 19 both promise "nothing was written", and this is what makes that
/// an assertion rather than a hope.
fn history_rows(state: &AppState, scope: &str) -> usize {
    let Some(history) = state.agent.history() else {
        return usize::MAX;
    };
    let q = x0x::history::HistoryQuery {
        scope: Some(x0x::history::Scope::Group(scope.to_string())),
        limit: 100,
        ..Default::default()
    };
    history.store().query(&q).map(|r| r.len()).unwrap_or(0)
}

async fn registry_ids(state: &AppState) -> usize {
    state.delegation_ids.read().await.len()
}

async fn index_has_entry(state: &AppState, group_id: &str) -> bool {
    state.delegation_index.read().await.contains_key(group_id)
}

// ─────────────────────── rows 17 / 18: the predicates ────────────────────
//
// These two are inert by construction — pure functions, no `AppState`, no
// sockets — because the ADR calls them "an authority path, not a read" and
// an authority predicate is the last thing that should only be covered by
// a test nobody can run.

/// WHY: `authorize` is the single predicate every delegated act funnels
/// through. The assertion that matters is not merely that it returns an
/// error — a wrong digest does that too — but that the error says the
/// group is CONTESTED (the ADR's own words: fixtures must assert
/// "contested rather than merely absent"). An operator who cannot tell
/// "this grant does not exist" from "this group is quarantined" cannot act.
#[test]
fn adr0066_row17_authorize_fails_closed_and_says_contested() -> Result<()> {
    let group_id = "aa".repeat(16);
    let (sd, actor, _active) = valid_grant(&group_id)?;
    let info = x0x::groups::GroupInfo::with_policy(
        "g".to_string(),
        String::new(),
        sd.delegation.from_agent,
        group_id.clone(),
        signed_public_policy(),
    );

    // CONTROL FIRST: with no marker this grant authorizes. Without this
    // arm, the refusal below could be the grant being invalid for some
    // unrelated reason and the test would pass for the wrong reason.
    authorize(
        &sd,
        &actor,
        x0x::delegation::DelegationVerb::SendPublicMessage,
        &group_id,
        2_000,
        &[],
        None,
    )
    .map_err(|e| anyhow::anyhow!("control: an unquarantined grant must authorize: {e}"))?;

    for no_anchor in [false, true] {
        let m = marker(&info, no_anchor);
        let why = authorize(
            &sd,
            &actor,
            x0x::delegation::DelegationVerb::SendPublicMessage,
            &group_id,
            2_000,
            &[],
            Some(&m),
        )
        .expect_err("a quarantined group must not authorize a delegated act");
        assert!(
            why.contains("fork-quarantined") && why.contains("contested"),
            "the reason must name the CONTEST, not look like a missing grant: {why}"
        );
        assert!(
            why.contains("x0x groups quarantine clear"),
            "§5: even the predicate's reason carries the remedy: {why}"
        );
        if no_anchor {
            assert!(
                why.contains("no owner axis"),
                "the no_anchor branch must say nothing clears this automatically: {why}"
            );
        }
    }
    Ok(())
}

/// WHY: `chain_members_active` reads the roster to decide whether every
/// agent in a delegation chain is still a member. Under a fork that roster
/// is one branch's answer presented as the answer — so a chain that looks
/// fully membered may be membered on only one side of the split. The
/// control arm supplies a roster that DOES contain both parties, so the
/// refusal cannot be mistaken for "a member was missing".
#[test]
fn adr0066_row17_chain_members_active_fails_closed_on_a_contested_roster() -> Result<()> {
    let group_id = "bb".repeat(16);
    let (sd, _actor, active) = valid_grant(&group_id)?;
    let info = x0x::groups::GroupInfo::with_policy(
        "g".to_string(),
        String::new(),
        sd.delegation.from_agent,
        group_id.clone(),
        signed_public_policy(),
    );

    chain_members_active(&sd, &[], &active, None)
        .map_err(|e| anyhow::anyhow!("control: a fully membered chain must pass: {e}"))?;

    let m = marker(&info, true);
    let why = chain_members_active(&sd, &[], &active, Some(&m))
        .expect_err("a contested roster must not certify a chain as active");
    assert!(
        why.contains("fork-quarantined") && why.contains("contested"),
        "the refusal must be about the fork, not about membership: {why}"
    );
    Ok(())
}

// ───────────────────── row 15: minting, and mutation order ───────────────

/// WHY: this is the ADR's own attack row — "quarantined owner-axis group
/// grants a delegation: succeeds → refused". The refusal has to land
/// BEFORE the irreversible steps, and this handler has four of them: the
/// envelope is signed with the agent key, its carrier row is committed to
/// SQLite, the index is written and the carrier is published to the group
/// bus. So the test asserts the 409 AND that history, the index and the
/// global id registry are all untouched: a refusal after the mint would
/// still read as a 409 while the authority already existed.
#[tokio::test]
async fn adr0066_row15_delegate_refuses_and_mints_nothing() -> Result<()> {
    for no_anchor in [false, true] {
        let case = if no_anchor { "no_anchor" } else { "owner-axis" };
        let (state, _dir) = delegation_state().await?;
        let delegate_hex = hex::encode([0x11u8; 32]);
        let group_id = "cc".repeat(16);
        let (stable, _info) = seed_group(&state, &group_id, &delegate_hex).await?;
        install_marker(&state, &group_id, no_anchor).await;

        let (status, body) = call_delegate(&state, &group_id, &delegate_hex).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "({case}) §3b row 15: minting new authority from a contested roster is refused"
        );
        assert_adr0066_refusal(&body, no_anchor, case);

        // Nothing was minted. Each of these would be a durable
        // consequence of the act the 409 claims did not happen.
        assert_eq!(
            history_rows(&state, &stable),
            0,
            "({case}) no carrier row: the delegation is not effective anywhere"
        );
        assert!(
            !index_has_entry(&state, &stable).await,
            "({case}) no per-group index entry was created"
        );
        assert_eq!(
            registry_ids(&state).await,
            0,
            "({case}) no delegation id entered the global registry"
        );
    }
    Ok(())
}

/// WHY (R5's no-grace fixture, applied to this row): the rejected
/// warn-only design would have let the first request or two through. The
/// refusal above is the FIRST call this state ever saw, and here the same
/// group refuses again on a second and third attempt — so no request
/// budget or counter threshold can creep back in without failing a test.
#[tokio::test]
async fn adr0066_row15_refuses_from_the_very_first_request() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x12u8; 32]);
    let group_id = "dd".repeat(16);
    let (stable, _info) = seed_group(&state, &group_id, &delegate_hex).await?;
    install_marker(&state, &group_id, true).await;

    for attempt in 1..=3 {
        let (status, body) = call_delegate(&state, &group_id, &delegate_hex).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "attempt {attempt}: R5 removed the warn-only window — there is no grace"
        );
        assert_adr0066_refusal(&body, true, &format!("attempt {attempt}"));
    }
    assert_eq!(
        history_rows(&state, &stable),
        0,
        "three refused attempts wrote nothing"
    );
    Ok(())
}

/// WHY: containment that cannot be lifted is an outage, and for an
/// ordinary group the manual clear is the ONLY exit (R1/§2). This test is
/// what makes the §5 message's promise true: follow the remedy it names
/// and the service comes back.
///
/// It is also the POSITIVE control for the whole file. The success arm
/// proves the fixture can mint — that the group, the roster, the token and
/// the history store are all real — so every "nothing happened" assertion
/// elsewhere is a fact about the gate rather than about a fixture that
/// could never have minted anything.
#[tokio::test]
async fn adr0066_row15_manual_clear_restores_delegation_service() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x13u8; 32]);
    let group_id = "ee".repeat(16);
    let (stable, _info) = seed_group(&state, &group_id, &delegate_hex).await?;
    install_marker(&state, &group_id, true).await;

    let (status, _body) = call_delegate(&state, &group_id, &delegate_hex).await?;
    assert_eq!(status, StatusCode::CONFLICT, "refused while quarantined");

    manual_clear(&state, &group_id).await;

    let (status, body) = call_delegate(&state, &group_id, &delegate_hex).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the manual clear is the remedy the §5 message names, so it must work: {body}"
    );
    assert_eq!(
        body["effective"].as_bool(),
        Some(true),
        "the delegation is effective once the carrier row commits"
    );
    assert!(
        history_rows(&state, &stable) > 0,
        "PROBE POWER: the mint writes a durable row, so the 'nothing was written' \
         assertions in this file are able to fail"
    );
    assert!(
        registry_ids(&state).await > 0,
        "PROBE POWER: a real mint registers its id globally"
    );
    Ok(())
}

// ───────────────── row 16: the list keeps serving, annotated ─────────────

/// WHY: row 16 is annotate-class and the reason is explicit in the ADR —
/// "containment does not cost visibility". An operator hits this endpoint
/// during an incident precisely to find out who holds authority on the
/// contested roster, so refusing it would destroy the evidence the rest of
/// the slice exists to protect. The annotation is what stops that from
/// being a silent half-truth.
#[tokio::test]
async fn adr0066_row16_list_serves_annotated_and_is_untouched_when_clean() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x14u8; 32]);
    let group_id = "ff".repeat(16);
    let (_stable, _info) = seed_group(&state, &group_id, &delegate_hex).await?;

    // Clean control: the response carries NO annotation keys at all, so
    // an un-quarantined group's clients see a byte-identical shape.
    let (status, clean) = call_list(&state, &group_id).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        clean.get("fork_quarantined").is_none() && clean.get("fork_quarantine").is_none(),
        "a group with no marker is unaffected: {clean}"
    );

    install_marker(&state, &group_id, true).await;
    let (status, annotated) = call_list(&state, &group_id).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "row 16 SERVES — refusing it would blind the operator mid-incident"
    );
    assert_eq!(
        annotated["ok"].as_bool(),
        Some(true),
        "still a success response, not a refusal wearing a 200"
    );
    assert!(
        annotated["delegations"].is_array(),
        "the payload the operator came for is still there"
    );
    assert_eq!(
        annotated["fork_quarantined"].as_bool(),
        Some(true),
        "§3b: the list is annotated so the reader knows the roster is contested"
    );
    assert_eq!(
        annotated["fork_quarantine"]["revision"].as_u64(),
        Some(7),
        "the annotation carries the marker's own revision"
    );
    assert_eq!(
        annotated["fork_quarantine"]["no_anchor"].as_bool(),
        Some(true),
        "and says plainly that nothing clears this automatically"
    );
    assert_eq!(
        annotated["fork_quarantine"]["clear_with"].as_str(),
        Some("POST /groups/:id/quarantine/clear"),
        "the annotation and the refusal carry the SAME shape, so clients parse one"
    );
    Ok(())
}

// ───────── row 19: registry seeding, including the non-REST seam ─────────

/// WHY: `index_committed` is the NON-REST honour seam. Its caller is
/// `route_delegation_and_mentions`, reached from gossip ingest, so a
/// delegation minted on the other side of a fork arrives here with no HTTP
/// request behind it. If only the REST handler were gated, a peer could
/// gossip authority into this node's effectiveness index and the local
/// refusal would be decorative.
///
/// The carrier's history row is committed by the caller BEFORE this point
/// and stays committed (R3: ingest is tag-and-retain, never refused) — so
/// what this test pins is narrower and correct: the record is kept, the
/// authority is not honoured.
#[tokio::test]
async fn adr0066_row19_gossip_ingest_does_not_index_a_contested_group() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x15u8; 32]);
    let group_id = "1a".repeat(16);
    let (stable, _info) = seed_group(&state, &group_id, &delegate_hex).await?;
    install_marker(&state, &group_id, true).await;
    let (sd, _actor, _active) = valid_grant(&stable)?;

    index_committed(&state, &stable, sd.clone()).await;
    assert!(
        !index_has_entry(&state, &stable).await,
        "§3b row 19: a contested group's grant never enters the effectiveness index"
    );
    assert_eq!(
        registry_ids(&state).await,
        0,
        "and never seeds the global id registry — an unregistered id cannot authorize"
    );

    // PROBE POWER + the remedy: after the manual clear the SAME call
    // indexes, so the assertions above are about the gate.
    manual_clear(&state, &group_id).await;
    index_committed(&state, &stable, sd).await;
    assert!(
        index_has_entry(&state, &stable).await,
        "after the clear the same grant indexes — the gate was the only thing stopping it"
    );
    assert_eq!(registry_ids(&state).await, 1, "and registers its id");
    Ok(())
}

/// WHY: the boot-time rebuild is the worst place for a contested grant to
/// be admitted, because nobody is watching. `rebuild_global_delegation_registry`
/// walks EVERY scope's durable history, so a group that was quarantined
/// before the restart would otherwise come back with its authority
/// re-registered and working.
///
/// The fixture mints for real (on a clean group), wipes only the in-memory
/// registry and index to simulate the restart, then quarantines the group
/// and rebuilds.
#[tokio::test]
async fn adr0066_row19_registry_rebuild_skips_a_quarantined_group() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x16u8; 32]);
    let group_id = "2b".repeat(16);
    let (stable, _info) = seed_group(&state, &group_id, &delegate_hex).await?;

    let (status, _body) = call_delegate(&state, &group_id, &delegate_hex).await?;
    assert_eq!(status, StatusCode::OK, "fixture: a real grant is committed");
    assert!(
        history_rows(&state, &stable) > 0,
        "fixture: the carrier is in durable history, which is what the rebuild reads"
    );

    // Simulate the restart: durable history survives, memory does not.
    state.delegation_ids.write().await.clear();
    state.delegation_index.write().await.clear();
    install_marker(&state, &group_id, true).await;

    rebuild_global_delegation_registry(&state).await;
    assert_eq!(
        registry_ids(&state).await,
        0,
        "§3b row 19: boot must not re-seed the registry from a contested roster"
    );

    // The control in the other direction: with the marker cleared the
    // rebuild finds the very same row and registers it, so the empty
    // result above is the skip and not an empty history.
    state.delegation_ids.write().await.clear();
    manual_clear(&state, &group_id).await;
    rebuild_global_delegation_registry(&state).await;
    assert!(
        registry_ids(&state).await > 0,
        "PROBE POWER: the rebuild does find this group's grants when it is not contested"
    );
    Ok(())
}

// ──────────────────────────── blast radius ──────────────────────────────

/// WHY: a containment gate that over-reaches is its own outage. ADR-0066's
/// Migration table promises that anything other than the contested group
/// is "byte-for-byte unchanged", so this test quarantines group A and then
/// exercises the same paths on group B and on a group this node holds no
/// roster entry for at all.
///
/// The third case is the one worth spelling out: a delegation whose group
/// is not in `named_groups` (a grant seen for a group this daemon never
/// joined) has no marker to consult, and the gate must treat that as "no
/// quarantine" rather than as "unknown, refuse" — the ADR gates contested
/// groups, not unknown ones, and the existing effectiveness rules already
/// govern the unknown case.
#[tokio::test]
async fn adr0066_slice3_does_not_touch_other_groups_or_ungrouped_delegations() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x17u8; 32]);
    let quarantined_id = "3c".repeat(16);
    let healthy_id = "4d".repeat(16);
    let (quarantined_stable, _a) = seed_group(&state, &quarantined_id, &delegate_hex).await?;
    let (healthy_stable, _b) = seed_group(&state, &healthy_id, &delegate_hex).await?;
    install_marker(&state, &quarantined_id, true).await;

    // The marker is scoped to the group that carries it.
    assert!(
        fork_quarantine_marker(&state, &quarantined_id)
            .await
            .is_some(),
        "the contested group has a marker"
    );
    assert!(
        fork_quarantine_marker(&state, &healthy_id).await.is_none(),
        "its neighbour does not"
    );
    assert!(
        fork_quarantine_marker(&state, &"9f".repeat(16))
            .await
            .is_none(),
        "and a group this node never joined has none either"
    );

    // Minting on the healthy group still works.
    let (status, body) = call_delegate(&state, &healthy_id, &delegate_hex).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "one group's quarantine must not refuse another group's delegations: {body}"
    );

    // And a grant for a group with no roster entry still indexes: the gate
    // asks "is this group contested?", never "is this group known?".
    let unknown_group = "9f".repeat(16);
    let (sd, _actor, _active) = valid_grant(&unknown_group)?;
    index_committed(&state, &unknown_group, sd).await;
    assert!(
        index_has_entry(&state, &unknown_group).await,
        "a delegation not tied to a quarantined named group is unaffected"
    );

    // The contested group is still refused, after all of the above — the
    // gate did not get cleared by a neighbour's success.
    let (status, refusal) = call_delegate(&state, &quarantined_id, &delegate_hex).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_adr0066_refusal(&refusal, true, "still refused");
    assert_eq!(
        history_rows(&state, &quarantined_stable),
        0,
        "the contested group wrote nothing throughout"
    );
    assert!(
        history_rows(&state, &healthy_stable) > 0,
        "while its neighbour served normally"
    );
    Ok(())
}

/// WHY: row 17's REST surface is the delegation-cited branch of task
/// claim/complete, and §5 lists row 17 among the rows that must carry the
/// FULL body — a 403 with the sentence buried in a string would not satisfy
/// it. `tasks.rs` returns exactly what this helper builds, so this pins the
/// payload contract for that route.
///
/// HONEST LIMIT, stated rather than papered over: the end-to-end arm
/// (walking `PATCH /task-lists/:id/tasks/:tid` and asserting the task is
/// left unclaimed) is NOT covered by a unit test, because registering a
/// group-scoped task list requires an initialized gossip runtime
/// (`create_task_list_persistent` fails with "gossip runtime not
/// initialized") and this file is deliberately loopback-only. What the
/// unit suite does cover is both halves either side of that gap: the
/// payload here, and the `authorize` / `chain_members_active` predicates
/// above, which fail closed regardless of who calls them. The ordering
/// claim — refusal before `committed_delegations` and before
/// `claim_task_versioned` / `complete_task_versioned` — is a reading of
/// `tasks.rs`, and the daemon harness in CI is what exercises it.
#[test]
fn adr0066_row17_task_execute_refusal_carries_the_five_body() -> Result<()> {
    let group_id = "8b".repeat(16);
    let info = x0x::groups::GroupInfo::with_policy(
        "g".to_string(),
        String::new(),
        x0x::identity::AgentKeypair::generate()?.agent_id(),
        group_id.clone(),
        signed_public_policy(),
    );
    for no_anchor in [false, true] {
        let m = marker(&info, no_anchor);
        let body = crate::server::routes::named_groups::fork_quarantine_refusal_body(&group_id, &m);
        assert_adr0066_refusal(&body, no_anchor, "task-execute refusal body");
    }
    Ok(())
}

// ──────────────────── alias-keyed rosters (review r1) ───────────────────

/// WHY (cross-model review r1 — this was a real hole, not a hypothetical):
/// the roster map is keyed by whichever alias this daemon learned the group
/// under, and the apply path installs the marker under that MAP key. But
/// every honour path arrives with the STABLE id, because that is what a
/// delegation envelope carries. A gate that resolved only the map key
/// therefore MISSED the marker whenever key ≠ stable id — and a missed
/// marker does not degrade gracefully: row 19 is violated outright, because
/// a contested group's gossiped grant is indexed and globally registered.
///
/// Every §3b surface reachable by stable id is asserted here, so the fix
/// cannot be partially reverted one path at a time.
#[tokio::test]
async fn adr0066_slice3_gates_resolve_a_group_keyed_by_an_alias() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x18u8; 32]);
    let alias_key = "5e".repeat(16);
    let stable_id = "6f".repeat(16);
    let (alias_key, stable_id) =
        seed_group_under_alias(&state, &alias_key, &stable_id, &delegate_hex).await?;

    // Control: with no marker, resolving by either spelling finds none.
    assert!(
        fork_quarantine_marker(&state, &stable_id).await.is_none(),
        "control: a clean alias-keyed group is not quarantined under either name"
    );

    // The marker installs on the entry the map holds — i.e. under the ALIAS.
    install_marker(&state, &alias_key, true).await;

    // 1. The resolver itself must find it by the stable id. Without the
    //    alias fallback this is `None` and every assertion below flips.
    let by_stable = fork_quarantine_marker(&state, &stable_id).await;
    assert!(
        by_stable.is_some(),
        "the marker is installed under the map key, but every honour path \
         arrives with the stable id — resolving only one spelling serves the \
         contested roster"
    );
    assert!(
        fork_quarantine_marker(&state, &alias_key).await.is_some(),
        "and the direct key hit still works — the fallback is additive"
    );

    // 2. Row 19, the path the miss broke outright: a gossiped grant for the
    //    stable id must NOT be indexed and must NOT seed the registry.
    let (sd, _actor, _active) = valid_grant(&stable_id)?;
    index_committed(&state, &stable_id, sd).await;
    assert!(
        !index_has_entry(&state, &stable_id).await,
        "row 19: an alias-keyed contested group's grant must not enter the index"
    );
    assert_eq!(
        registry_ids(&state).await,
        0,
        "row 19: nor the global id registry"
    );

    // 3. Row 18 must refuse with the §5 SENTENCE, not by accident. Before
    //    the fix this path failed closed only incidentally, via a
    //    single-spelling roster read that produced a misleading "removed
    //    member" error — right outcome, wrong and undiagnosable reason.
    let why = authorize_send_as(
        &state,
        &stable_id,
        &state.agent.agent_id(),
        &"ab".repeat(32),
        now_millis_u64(),
    )
    .await
    .expect_err("row 18 must refuse for an alias-keyed contested group");
    assert!(
        why.contains("fork-quarantined") && why.contains("contested"),
        "the reason must be the §5 sentence, not a misleading membership error: {why}"
    );

    // 4. Row 15 refuses through the alias key the REST path is called with.
    let (status, body) = call_delegate(&state, &alias_key, &delegate_hex).await?;
    assert_eq!(status, StatusCode::CONFLICT, "row 15 on the alias key");
    assert_adr0066_refusal(&body, true, "alias");
    Ok(())
}

/// WHY: row 18 is the predicate the gossip-ingest seam calls, so it needs a
/// direct test of its own rather than only being exercised through the
/// ingest handler. The control arm is the point: with no marker the SAME
/// call fails with the effectiveness error ("not durably committed"), so the
/// quarantine refusal is provably distinguishable from a missing grant —
/// the ADR's "contested rather than merely absent" bar.
#[tokio::test]
async fn adr0066_row18_authorize_send_as_refuses_contested_not_absent() -> Result<()> {
    let (state, _dir) = delegation_state().await?;
    let delegate_hex = hex::encode([0x19u8; 32]);
    let group_id = "7a".repeat(16);
    let (stable, _info) = seed_group(&state, &group_id, &delegate_hex).await?;
    let digest_hex = "cd".repeat(32);

    let absent = authorize_send_as(
        &state,
        &stable,
        &state.agent.agent_id(),
        &digest_hex,
        now_millis_u64(),
    )
    .await
    .expect_err("control: an uncommitted digest never authorizes");
    assert!(
        absent.contains("not durably committed"),
        "control: without a marker the failure is the effectiveness rule: {absent}"
    );
    assert!(
        !absent.contains("fork-quarantined"),
        "control: and it is NOT the quarantine refusal: {absent}"
    );

    for no_anchor in [false, true] {
        install_marker(&state, &group_id, no_anchor).await;
        let why = authorize_send_as(
            &state,
            &stable,
            &state.agent.agent_id(),
            &digest_hex,
            now_millis_u64(),
        )
        .await
        .expect_err("row 18 fails closed on a contested roster");
        assert!(
            why.contains("fork-quarantined") && why.contains("contested"),
            "the refusal names the contest: {why}"
        );
        assert!(
            why.contains("x0x groups quarantine clear"),
            "§5: and the remedy, even on the non-REST surface: {why}"
        );
        if no_anchor {
            assert!(
                why.contains("no owner axis"),
                "the no_anchor branch says nothing clears this automatically: {why}"
            );
        }
        manual_clear(&state, &group_id).await;
    }
    Ok(())
}
