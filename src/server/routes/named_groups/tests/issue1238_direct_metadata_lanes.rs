//! #1238: the shared direct metadata listener (`run_direct_metadata_listener`)
//! receives the named-group metadata events of every group on one
//! subscription. A seating `MemberAdded` whose Welcome is staged by
//! reference makes the joiner's apply wait for that Welcome, up to
//! `WELCOME_FETCH_TIMEOUT` (115 s). That wait must not delay the direct
//! events of another group.
//!
//! In-process only: the agents have no network config. The joiner's Welcome
//! request is parked (`detached_send_test_seam`) like a request whose
//! receipt never arrives, so its fetch keeps waiting. The events are
//! injected into the joiner's direct-message bus. No socket is used.

use super::adr0107_stuck_join_rearm::{build, welcome_id_of};
use super::*;

/// How long group B's event may wait while group A's Welcome fetch waits.
const BOUND: Duration = Duration::from_secs(5);
/// How long a test waits for a fixture step.
const WAIT: Duration = Duration::from_secs(15);
const GROUP_B: &str = "1238-group-b-local-key";
const STABLE_B: &str = "1238-group-b-stable-id";
const RENAMED_B: &str = "1238 group B renamed while group A waits for its Welcome";

/// Install group B, which the joiner administers, and persist it.
async fn install_group_b(state: &Arc<AppState>) -> Result<x0x::groups::GroupInfo> {
    let (mut info, admin_hex, _) = metadata_terminality_test_group(state, GROUP_B);
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        STABLE_B.to_string(),
        admin_hex,
        info.created_at,
        String::new(),
    ));
    info.metadata_topic = "local:1238-group-b".to_string();
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(GROUP_B.to_string(), info.clone());
    anyhow::ensure!(
        save_named_groups(state).await,
        "group B is persisted before the listener's apply"
    );
    Ok(info)
}

/// A signed rename of group B by the joiner, its local admin.
fn rename_b(state: &Arc<AppState>, parent: &x0x::groups::GroupInfo) -> NamedGroupMetadataEvent {
    let mut next = parent.clone();
    next.name = RENAMED_B.to_string();
    next.roster_revision += 1;
    NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: STABLE_B.to_string(),
        revision: next.roster_revision,
        actor: hex::encode(state.agent.agent_id().as_bytes()),
        name: Some(next.name.clone()),
        description: None,
        commit: Some(sign_metadata_terminality_commit(
            parent,
            &next,
            state,
            now_millis_u64(),
        )),
    }
}

/// Put `event` from `from` on `to`'s direct-message bus.
async fn inject(to: &AppState, from: &AppState, event: &NamedGroupMetadataEvent) -> Result<()> {
    let delivered = to
        .agent
        .direct_messaging()
        .handle_incoming(
            from.agent.machine_id(),
            from.agent.agent_id(),
            serde_json::to_vec(event)?,
            true,
            None,
            None,
        )
        .await;
    anyhow::ensure!(delivered >= 1, "the listener is subscribed");
    Ok(())
}

async fn welcome_fetch_waits(state: &AppState, welcome_id: &str) -> bool {
    state
        .pending_welcome_waiters
        .read()
        .await
        .contains_key(welcome_id)
}

async fn name_of(state: &AppState, group_key: &str) -> Option<String> {
    state
        .named_groups
        .read()
        .await
        .get(group_key)
        .map(|info| info.name.clone())
}

/// Poll until group B carries the rename, or `within` ends.
async fn renamed_within(state: &AppState, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if name_of(state, GROUP_B).await.as_deref() == Some(RENAMED_B) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Group A: the authority's seat for the joiner, its Welcome by reference.
/// Its apply waits in the Welcome fetch. Group B: a signed rename by the
/// joiner, received after A's seat. B's apply must not wait for A's fetch:
/// the rename applies within `BOUND` while A's fetch still waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1238_slow_welcome_fetch_for_one_group_does_not_delay_another_group() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let joiner = Arc::clone(&s.j1);
    let welcome_id = welcome_id_of(&s.j1_add)
        .ok_or_else(|| anyhow::anyhow!("the joiner's seat stages its Welcome by reference"))?;
    let parent_b = install_group_b(&joiner).await?;
    // The Welcome request parks like a send whose receipt never arrives,
    // so group A's apply waits in its fetch (the in-process transport
    // would refuse the send at once instead).
    let request_pause =
        detached_send_test_seam::arm(&detached_send_test_seam::welcome_fetch_key(&welcome_id));
    let listener = tokio::spawn(run_direct_metadata_listener(
        Arc::clone(&joiner),
        joiner.agent.subscribe_direct(),
    ));

    inject(&joiner, &s.authority, &s.j1_add).await?;
    let deadline = tokio::time::Instant::now() + WAIT;
    while !(request_pause.reached() && welcome_fetch_waits(&joiner, &welcome_id).await) {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the seat apply starts its Welcome fetch"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    inject(&joiner, &joiner, &rename_b(&joiner, &parent_b)).await?;
    let started = tokio::time::Instant::now();
    let applied = renamed_within(&joiner, BOUND).await;
    let waited = started.elapsed();
    let a_still_waits = welcome_fetch_waits(&joiner, &welcome_id).await;

    // Stop before the asserts: shutdown ends group A's fetch at once
    // (#1269 r2), so a failure leaves no 115 s wait behind.
    crate::server::drain_server_tasks(&joiner, vec![listener]).await;
    drop(request_pause);
    assert!(
        a_still_waits,
        "precondition: group A's Welcome fetch still waits at the end of the check"
    );
    assert!(
        applied,
        "group B's metadata event must apply within {BOUND:?} while group A's \
         Welcome fetch waits; it was not applied after {waited:?}"
    );
    Ok(())
}
