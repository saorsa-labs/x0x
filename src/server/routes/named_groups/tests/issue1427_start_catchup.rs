#![cfg(test)]
//! #1427: the start catch-up of a TreeKEM member that was down past the
//! last metadata resend survives a slow bootstrap.
//!
//! The start rounds run beside the network join. When no member is
//! reachable until the join ends, those rounds end with nothing served.
//! The outage record must stay, the up-time record must not hide the
//! outage, and the end of the join must ask again. A page whose head is
//! the local head ends the catch-up and removes the record.
//!
//! Inert: tempdirs only. The catch-up sends go to a peer with no address,
//! so they fail locally.

use super::*;

const PEER: x0x::identity::AgentId = x0x::identity::AgentId([0xee; 32]);

async fn treekem_member_state() -> Result<(Arc<AppState>, tempfile::TempDir, String)> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let group_id = "1427".repeat(8);
    let local = state.agent.agent_id();
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, local, &seed)?;
    let mut info = x0x::groups::GroupInfo::new(
        "start-catchup".to_string(),
        String::new(),
        local,
        group_id.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        hex::encode(PEER.as_bytes()),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    info.secret_epoch = group.epoch();
    info.security_binding = Some(format!("treekem:epoch={}", group.epoch()));
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    state
        .treekem_groups
        .write()
        .await
        .insert(group_id.clone(), Arc::new(tokio::sync::Mutex::new(group)));
    Ok((state, dir, group_id))
}

fn pending(state: &AppState, key: &str) -> bool {
    state
        .treekem_start_catchup_pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(key)
}

async fn task_registered(state: &AppState, key: &str) -> bool {
    state
        .treekem_epoch_ahead_targets
        .lock()
        .await
        .contains_key(key)
}

/// Lets the spawned tasks run until `done`, with the paused clock moving
/// on when they sleep.
async fn settle(what: &str, mut done: impl AsyncFnMut() -> bool) -> Result<()> {
    for _ in 0..2_000 {
        if done().await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("#1427: {what} did not happen")
}

async fn write_last_up(state: &AppState, ago: Duration) -> Result<()> {
    let ago_ms = u64::try_from(ago.as_millis())?;
    let last = treekem_unix_now_ms().saturating_sub(ago_ms);
    tokio::fs::write(treekem_alive_path(state), last.to_string()).await?;
    Ok(())
}

fn last_up_age(state: &AppState) -> Option<Duration> {
    let text = std::fs::read_to_string(treekem_alive_path(state)).ok()?;
    let last = text.trim().parse::<u64>().ok()?;
    Some(Duration::from_millis(
        treekem_unix_now_ms().saturating_sub(last),
    ))
}

fn head_page(state_hash: &str, group_id: &str) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: Vec::new(),
        truncated: false,
        responder_state_hash: Some(state_hash.to_string()),
        responder_state_revision: None,
    }
}

#[tokio::test(start_paused = true)]
async fn issue1427_slow_bootstrap_keeps_the_outage_and_asks_after_the_join() -> Result<()> {
    let (state, _dir, key) = treekem_member_state().await?;
    write_last_up(&state, Duration::from_secs(600)).await?;
    let record = treekem_catchup_pending_path(&state);

    // The start, with no member reachable (the join is still dialling).
    let start = tokio::spawn(run_treekem_start_catchup(Arc::clone(&state)));
    settle("the start catch-up task", async || {
        task_registered(&state, &key).await
    })
    .await?;
    assert!(
        record.exists(),
        "#1427: a start past the last resend writes the outage record"
    );
    assert!(
        last_up_age(&state).is_some_and(|age| age < Duration::from_secs(60)),
        "#1427: the running daemon records its up time at once"
    );
    settle("the end of the start rounds", async || {
        !task_registered(&state, &key).await
    })
    .await?;
    // The task finishes its after-rounds check once the rounds end.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        pending(&state, &key) && record.exists(),
        "#1427: start rounds that reached no member must keep the group \
         pending and the outage record on disk"
    );

    // The join ends: the pending group asks again.
    retry_treekem_start_catchup(&state);
    settle("the catch-up after the join", async || {
        task_registered(&state, &key).await
    })
    .await?;

    // A member answers with the local head: the catch-up is done.
    let head = state
        .named_groups
        .read()
        .await
        .get(&key)
        .map(|info| info.state_hash.clone())
        .context("group record")?;
    handle_treekem_catchup_response(
        &state,
        &PEER,
        &clean_sender_machine(),
        true,
        head_page(&head, &key),
    )
    .await;
    assert!(
        !pending(&state, &key),
        "#1427: a last page with the local head ends the start catch-up"
    );
    settle("the removal of the outage record", async || {
        !record.exists()
    })
    .await?;
    start.abort();
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn issue1427_outage_record_asks_again_on_the_next_start() -> Result<()> {
    let (state, _dir, key) = treekem_member_state().await?;
    // The last start's catch-up never succeeded; the daemon then ran for
    // a while, so the up-time record shows no outage.
    write_last_up(&state, Duration::from_secs(5)).await?;
    crate::profile::write_atomically(&treekem_catchup_pending_path(&state), b"600000").await?;
    let start = tokio::spawn(run_treekem_start_catchup(Arc::clone(&state)));
    settle("the start catch-up from the record", async || {
        task_registered(&state, &key).await
    })
    .await?;
    assert!(
        pending(&state, &key),
        "#1427: the recorded outage is pending"
    );
    start.abort();
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn issue1427_short_outage_asks_nothing() -> Result<()> {
    let (state, _dir, key) = treekem_member_state().await?;
    write_last_up(&state, Duration::from_secs(20)).await?;
    let start = tokio::spawn(run_treekem_start_catchup(Arc::clone(&state)));
    settle("the first up-time write", async || {
        last_up_age(&state).is_some_and(|age| age < Duration::from_secs(5))
    })
    .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !pending(&state, &key)
            && !task_registered(&state, &key).await
            && !treekem_catchup_pending_path(&state).exists(),
        "#1427: an outage the resends cover asks nothing"
    );
    start.abort();
    Ok(())
}

fn passes(state: &AppState) -> u64 {
    state
        .treekem_start_catchup_passes
        .load(std::sync::atomic::Ordering::Relaxed)
}

/// Review round 2: the join task can end before the start registers its
/// pending groups. The retry must still come after the registration.
#[tokio::test(start_paused = true)]
async fn issue1427_join_ended_before_registration_still_asks_again() -> Result<()> {
    let (state, _dir, key) = treekem_member_state().await?;
    write_last_up(&state, Duration::from_secs(600)).await?;
    // The join ends first, while nothing is pending yet.
    retry_treekem_start_catchup(&state);
    assert_eq!(passes(&state), 0);
    let start = tokio::spawn(run_treekem_start_catchup(Arc::clone(&state)));
    settle("a second start pass after the join", async || {
        passes(&state) >= 2
    })
    .await?;
    assert!(
        pending(&state, &key),
        "#1427: passes that reached no member keep the group pending"
    );
    start.abort();
    Ok(())
}

/// Review round 2: a member several commits behind keeps asking while
/// each cycle moves it one epoch, and stops when a cycle brings no newer
/// epoch.
#[tokio::test(start_paused = true)]
async fn issue1427_start_pass_follows_a_multi_epoch_gap() {
    // The member is at epoch 3; the group is at 6. Each served page moves
    // it one epoch.
    let epoch = std::cell::Cell::new(3_u64);
    let targets = std::cell::RefCell::new(Vec::new());
    let end = drive_treekem_start_catchup(
        || std::future::ready(Some(epoch.get())),
        |target| {
            targets.borrow_mut().push(target);
            if epoch.get() < 6 {
                epoch.set(epoch.get() + 1);
            }
            std::future::ready(())
        },
        || true,
    )
    .await;
    assert_eq!(end, TreeKemStartCatchupEnd::Done);
    assert_eq!(epoch.get(), 6, "#1427: the pass must reach the group epoch");
    assert_eq!(*targets.borrow(), vec![4, 5, 6, 7]);

    // No cycle moves the group: it stays pending after one cycle.
    let cycles = std::cell::Cell::new(0);
    let end = drive_treekem_start_catchup(
        || std::future::ready(Some(3)),
        |_| {
            cycles.set(cycles.get() + 1);
            std::future::ready(())
        },
        || true,
    )
    .await;
    assert_eq!(end, TreeKemStartCatchupEnd::KeepPending);
    assert_eq!(cycles.get(), 1);

    // A member reports the local head: the pass ends at once.
    let cycles = std::cell::Cell::new(0);
    let end = drive_treekem_start_catchup(
        || std::future::ready(Some(3)),
        |_| {
            cycles.set(cycles.get() + 1);
            std::future::ready(())
        },
        || false,
    )
    .await;
    assert_eq!(end, TreeKemStartCatchupEnd::Done);
    assert_eq!(cycles.get(), 1);

    // A group that keeps moving is bounded and stays pending.
    let epoch = std::cell::Cell::new(0_u64);
    let end = drive_treekem_start_catchup(
        || std::future::ready(Some(epoch.get())),
        |_| {
            epoch.set(epoch.get() + 1);
            std::future::ready(())
        },
        || true,
    )
    .await;
    assert_eq!(end, TreeKemStartCatchupEnd::KeepPending);
    assert_eq!(epoch.get(), TREEKEM_START_CATCHUP_CYCLES as u64);
}
