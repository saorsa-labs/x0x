//! ADR-0066 §3c row 20 (slice 5) — group task-list mutations fail closed
//! under fork quarantine, reads keep serving annotated.
//!
//! WHY this row is a SPLIT and not simply "refuse": a task list bound to a
//! contested roster is both an authority surface and a forensic one. The ADR
//! settled the split with an argument worth restating, because it is the one
//! David's R5 override turned on: the drafter argued task mutations could have
//! a warn-only release since CRDT task state is recoverable, and the ratified
//! answer was that "recoverable" describes the cleanup, not the exposure — a
//! claim or completion accepted while membership is disputed is still an act
//! taken under disputed membership. So mutations refuse from the FIRST request
//! after the marker installs, with no grace, while reads stay open so the
//! operator can see what the contested roster has been doing.
//!
//! What each test defends:
//!
//! - every mutating handler refuses, and refuses BEFORE it resolves the task
//!   list handle — proven by the 409-instead-of-404 flip, which is the only
//!   in-process observation that pins the ordering (see the honest limit on
//!   `adr0066_row20_mutations_refuse_before_any_crdt_work`);
//! - `POST /task-lists` leaves NOTHING behind: no live handle and no durable
//!   subscription registration;
//! - the refusal carries the §5 body, in both the `no_anchor` and
//!   owner-axis branches, and it is the shared slice-1 helper's body rather
//!   than a locally invented one;
//! - reads are not refused and are annotated;
//! - a task list that is NOT bound to a named group is completely unaffected,
//!   which bounds this slice's blast radius to group-scoped lists;
//! - and the alias-key regression: a group filed under a map key that is not
//!   its stable id is still found, with a negative control showing the
//!   single-spelling lookup the gate must not use.

use super::*;

use crate::server::routes::tasks::{
    add_task, create_task_list, list_task_lists, list_tasks, task_list_fork_quarantine,
    update_task, AddTaskRequest, CreateTaskListRequest, UpdateTaskRequest,
};

/// A loopback-only daemon state on a temp dir. No gossip runtime is started,
/// which is the constraint that shapes the assertions below.
async fn task_state() -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(data_dir, agent).await?;
    Ok((state, dir))
}

/// Symphony's group-scoped task-list id for `group_id`.
fn scoped_list_id(group_id: &str) -> String {
    format!("x0x.group.{group_id}.symphony.inbox")
}

/// A group the local agent is an ACTIVE member of, so #153's membership guard
/// allows the request and the only thing left to refuse it is ADR-0066. A
/// fixture whose membership check denied first would prove nothing.
fn member_group(state: &AppState, group_id: &str) -> x0x::groups::GroupInfo {
    x0x::groups::GroupInfo::new(
        "adr0066-tasks".to_string(),
        "slice 5 fixture".to_string(),
        state.agent.agent_id(),
        group_id.to_string(),
    )
}

async fn seed_group(state: &AppState, map_key: &str, group_id: &str) -> Result<String> {
    let info = member_group(state, group_id);
    assert!(
        info.members_v2
            .get(&hex::encode(state.agent.agent_id().as_bytes()))
            .is_some_and(|m| matches!(m.state, x0x::groups::GroupMemberState::Active)),
        "fixture precondition: the local agent must be an ACTIVE member, or #153 \
         denies before ADR-0066 is ever consulted"
    );
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(map_key.to_string(), info);
    Ok(stable)
}

fn marker(info: &x0x::groups::GroupInfo, no_anchor: bool) -> x0x::groups::ForkQuarantine {
    x0x::groups::ForkQuarantine {
        revision: 11,
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

async fn install_marker(state: &AppState, map_key: &str, no_anchor: bool) {
    let mut groups = state.named_groups.write().await;
    if let Some(info) = groups.get_mut(map_key) {
        let m = marker(info, no_anchor);
        info.fork_quarantine = Some(m);
    }
}

async fn manual_clear(state: &AppState, map_key: &str) {
    let mut groups = state.named_groups.write().await;
    if let Some(info) = groups.get_mut(map_key) {
        info.fork_quarantine = None;
    }
}

/// The §5 acceptance bar, in one place so every refusing surface in this file
/// is held to the same contract rather than to whatever its own test
/// remembered to check. Deliberately the same shape slice 3's suite asserts.
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
        Some(11),
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

async fn call_create(
    state: &Arc<AppState>,
    topic: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let req: CreateTaskListRequest = serde_json::from_value(serde_json::json!({
        "name": "slice 5",
        "topic": topic,
    }))?;
    let resp = create_task_list(State(Arc::clone(state)), Json(req))
        .await
        .into_response();
    response_json(resp).await
}

async fn call_add(state: &Arc<AppState>, id: &str) -> Result<(StatusCode, serde_json::Value)> {
    let req: AddTaskRequest = serde_json::from_value(serde_json::json!({ "title": "t" }))?;
    let resp = add_task(State(Arc::clone(state)), Path(id.to_string()), Json(req))
        .await
        .into_response();
    response_json(resp).await
}

async fn call_update(
    state: &Arc<AppState>,
    id: &str,
    task_hex: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let req: UpdateTaskRequest = serde_json::from_value(serde_json::json!({ "action": "claim" }))?;
    let resp = update_task(
        State(Arc::clone(state)),
        Path((id.to_string(), task_hex.to_string())),
        Json(req),
    )
    .await
    .into_response();
    response_json(resp).await
}

async fn call_list_tasks(
    state: &Arc<AppState>,
    id: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let resp = list_tasks(State(Arc::clone(state)), Path(id.to_string()))
        .await
        .into_response();
    response_json(resp).await
}

/// WHY: this is the ordering claim the row rests on. A refusal that arrives
/// after the CRDT has already been mutated is an error message, not
/// containment, so the test has to show the gate running before the handler
/// does any work at all.
///
/// HOW it is observable in-process, and the HONEST LIMIT. Registering a real
/// task-list handle needs an initialized gossip runtime
/// (`create_task_list_persistent` → "gossip runtime not initialized"), and
/// this suite is deliberately loopback-only, so no handle exists to mutate.
/// That absence is turned into the proof instead of being papered over: with
/// no marker, `POST/PATCH .../tasks` on this id returns 404 "task list not
/// found" (the handle lookup is reached) and `POST /task-lists` returns 500
/// "gossip runtime not initialized" (creation is reached). With the marker,
/// all three return 409 `fork_quarantined`. The flip from 404/500 to 409 can
/// only happen if the gate precedes the handle lookup and the creation —
/// which is precisely the claim, since every CRDT mutation, snapshot write
/// and delta publish lives downstream of those two points.
#[tokio::test]
async fn adr0066_row20_mutations_refuse_before_any_crdt_work() -> Result<()> {
    let (state, _dir) = task_state().await?;
    let group_id = "a1".repeat(16);
    let list_id = scoped_list_id(&group_id);
    seed_group(&state, &group_id, &group_id).await?;
    let task_hex = "04".repeat(32);

    // Controls: the ungated handlers get past the gate's position and fail
    // further downstream, which is what makes the 409 below meaningful.
    let (status, body) = call_add(&state, &list_id).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "control: with no marker, add_task reaches the handle lookup: {body}"
    );
    let (status, _) = call_update(&state, &list_id, &task_hex).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "control: with no marker, update_task reaches the handle lookup"
    );
    let (status, body) = call_create(&state, &list_id).await?;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "control: with no marker, create_task_list reaches CRDT creation"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("gossip runtime"),
        "control: and fails inside creation, not before it: {body}"
    );

    // R5's no-grace rule: the FIRST request after the marker installs is
    // refused. There is no request budget, counter threshold or elapsed-time
    // window that lets one through — this arm is the regression test for the
    // warn-only design the ADR rejected.
    for no_anchor in [false, true] {
        install_marker(&state, &group_id, no_anchor).await;
        let case = if no_anchor { "no_anchor" } else { "owner-axis" };

        let (status, body) = call_add(&state, &list_id).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "({case}) add_task refuses on the FIRST attempt, before the handle lookup"
        );
        assert_adr0066_refusal(&body, no_anchor, &format!("{case}/add_task"));

        let (status, body) = call_update(&state, &list_id, &task_hex).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "({case}) claim/complete refuses before the handle lookup"
        );
        assert_adr0066_refusal(&body, no_anchor, &format!("{case}/update_task"));

        let (status, body) = call_create(&state, &list_id).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "({case}) binding a new list to a contested roster refuses before creation"
        );
        assert_adr0066_refusal(&body, no_anchor, &format!("{case}/create_task_list"));

        // The store is untouched: no live handle, and no durable subscription
        // registration for the refused list. "Nothing was created" is only an
        // assertion if there is somewhere it COULD have been recorded.
        assert!(
            !state.task_lists.read().await.contains_key(&list_id),
            "({case}) a refused create must leave no live handle"
        );
        assert!(
            !state.crdt_subscriptions_path.exists(),
            "({case}) nor a durable subscription manifest — the refusal is \
             upstream of `crdt_subscriptions::record`"
        );

        manual_clear(&state, &group_id).await;
    }

    // And the manual clear restores service: back to the downstream failures,
    // which is the same evidence read in the other direction.
    let (status, _) = call_add(&state, &list_id).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the manual clear is the exit: mutations are admitted again"
    );
    Ok(())
}

/// WHY: §3c and R5 are explicit that the annotate half is NOT converted into
/// a refusal. An operator who loses the read during an incident loses the
/// only view of what the contested roster did, so a regression that gated
/// reads would be a containment "improvement" that destroys visibility.
#[tokio::test]
async fn adr0066_row20_reads_keep_serving_annotated() -> Result<()> {
    let (state, _dir) = task_state().await?;
    let group_id = "b2".repeat(16);
    let list_id = scoped_list_id(&group_id);
    seed_group(&state, &group_id, &group_id).await?;

    // The collection endpoint serves, unannotated, with no marker.
    let (status, body) = {
        let resp = list_task_lists(State(Arc::clone(&state)))
            .await
            .into_response();
        response_json(resp).await?
    };
    assert_eq!(status, StatusCode::OK, "collection read always serves");
    assert!(
        body.get("fork_quarantined").is_none(),
        "no marker ⇒ byte-identical to the pre-ADR shape: {body}"
    );

    install_marker(&state, &group_id, true).await;

    // The per-list read is NOT refused. It 404s here only because no handle
    // is registered — the point is that the status is not 409.
    let (status, _) = call_list_tasks(&state, &list_id).await?;
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "§3c/R5: reads are never refused, even while the roster is contested"
    );

    // And the annotation is the same object the refusal body carries, so a
    // client parses one shape either way.
    let (_, marker) = task_list_fork_quarantine(&state, &list_id)
        .await
        .expect("the read half resolves the same marker the mutation half refuses on");
    let annotation = crate::server::routes::named_groups::fork_quarantine_annotation(&marker);
    assert_eq!(annotation["revision"].as_u64(), Some(11));
    assert_eq!(annotation["no_anchor"].as_bool(), Some(true));
    assert_eq!(
        annotation["clear_with"].as_str(),
        Some("POST /groups/:id/quarantine/clear"),
        "the annotation names the remedy too — an operator reading a contested \
         list must not have to hit a refusal to learn how to clear it"
    );
    Ok(())
}

/// WHY: the blast radius claim. A plain task list has no roster to contest,
/// so a quarantined group anywhere on this daemon must not touch it. Without
/// this test the simplest over-broad implementation — refusing whenever ANY
/// group is quarantined — would pass every other test in this file.
#[tokio::test]
async fn adr0066_row20_leaves_non_group_task_lists_alone() -> Result<()> {
    let (state, _dir) = task_state().await?;
    let group_id = "c3".repeat(16);
    seed_group(&state, &group_id, &group_id).await?;
    install_marker(&state, &group_id, true).await;

    for plain in ["plain-topic", "x0x.group.acme", "inbox"] {
        assert!(
            task_list_fork_quarantine(&state, plain).await.is_none(),
            "a list that is not group-scoped has no roster to contest: {plain}"
        );
        let (status, body) = call_add(&state, plain).await?;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "and its mutations are unaffected while another group is quarantined: {body}"
        );
    }

    // A group-scoped list for a DIFFERENT, clean group is equally unaffected.
    let other = "d4".repeat(16);
    seed_group(&state, &other, &other).await?;
    let (status, _) = call_add(&state, &scoped_list_id(&other)).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "only the contested group's lists refuse"
    );
    Ok(())
}

/// WHY (the hard-won requirement, found by review in slices 3, 4 AND 6):
/// groups can sit in the roster map under a LOCAL ALIAS that is not their
/// stable id, while the caller's id carries the other spelling. A gate that
/// reads only one spelling serves mutations on exactly the contested groups
/// whose two names differ — silently, and only for them.
///
/// The negative control is the first assertion: a bare `named_groups.get()`
/// by the stable id MISSES, so a single-spelling gate provably fails this
/// case. Everything after it therefore measures the two-spelling resolver.
#[tokio::test]
async fn adr0066_row20_gate_resolves_a_group_keyed_by_an_alias() -> Result<()> {
    let (state, _dir) = task_state().await?;
    let alias_key = "5e".repeat(16);
    let stable_id = "6f".repeat(16);
    let stable = seed_group(&state, &alias_key, &stable_id).await?;
    assert_ne!(
        stable, alias_key,
        "fixture precondition: the whole point is that the map key is NOT the stable id"
    );

    // NEGATIVE CONTROL: the single-spelling lookup a gate must not use.
    assert!(
        state.named_groups.read().await.get(&stable).is_none(),
        "control: `groups.get(stable_id)` misses an alias-keyed group — this is \
         the exact read that would let the contested roster through"
    );

    install_marker(&state, &alias_key, true).await;

    // The resolver finds it under BOTH spellings.
    let by_stable = scoped_list_id(&stable);
    let by_alias = scoped_list_id(&alias_key);
    assert!(
        task_list_fork_quarantine(&state, &by_stable)
            .await
            .is_some(),
        "a task list naming the stable id must resolve the marker installed \
         under the alias key"
    );
    assert!(
        task_list_fork_quarantine(&state, &by_alias).await.is_some(),
        "and the direct key hit still works — the fallback is additive"
    );

    // Both spellings refuse, with the §5 body. Note the alias spelling also
    // passes #153's membership guard (it is the map key), so that arm is a
    // genuine end-to-end refusal rather than an incidental 403.
    let (status, body) = call_add(&state, &by_alias).await?;
    assert_eq!(status, StatusCode::CONFLICT, "alias spelling refuses");
    assert_adr0066_refusal(&body, true, "alias");
    let (status, body) = call_update(&state, &by_stable, &"07".repeat(32)).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "stable spelling refuses too — this is the arm a single-spelling gate \
         would have admitted"
    );
    assert_adr0066_refusal(&body, true, "stable");
    Ok(())
}
