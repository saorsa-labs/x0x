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

/// #1913 review follow-up: when another epoch-ahead task holds the group,
/// a start cycle only hands it the target. The start pass must wait for
/// that task to end before it judges the cycle.
#[tokio::test(start_paused = true)]
async fn issue1427_start_pass_waits_for_another_epoch_ahead_task() -> Result<()> {
    let (state, _dir, key) = treekem_member_state().await?;
    state
        .treekem_start_catchup_pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key.clone());
    // Another task holds the group.
    state.treekem_epoch_ahead_targets.lock().await.insert(
        key.clone(),
        EpochAheadTarget {
            epoch: 99,
            observations: 0,
        },
    );
    let pass = tokio::spawn({
        let state = Arc::clone(&state);
        let key = key.clone();
        async move { request_treekem_catchup_after_start(&state, &key, None).await }
    });
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(
        !pass.is_finished(),
        "#1427: the start pass must not end while another task holds the group"
    );
    state.treekem_epoch_ahead_targets.lock().await.remove(&key);
    settle("the start pass after the other task ends", async || {
        pass.is_finished()
    })
    .await?;
    assert!(
        pending(&state, &key),
        "#1427: no move keeps the group pending"
    );
    Ok(())
}

/// #1427: a member that stays up through a network outage. The reconnect
/// asks only after an isolation longer than the last metadata resend, at
/// most once per isolation, and a short one asks nothing.
#[test]
fn issue1427_reconnect_after_a_long_isolation_asks_once() {
    let resend = Duration::from_secs(60);
    let t0 = tokio::time::Instant::now();
    let at = |secs: u64| t0 + Duration::from_secs(secs);
    let mut isolation = TreeKemIsolation::default();
    assert!(!isolation.note(3, at(0), resend), "connected: nothing");
    assert!(!isolation.note(0, at(1), resend), "the isolation starts");
    assert!(!isolation.note(0, at(300), resend), "still isolated");
    assert!(
        isolation.note(1, at(601), resend),
        "the first peer after 600 s asks"
    );
    assert!(
        !isolation.note(2, at(602), resend),
        "a second peer of the same reconnect asks nothing more"
    );
    assert!(!isolation.note(0, at(700), resend));
    assert!(
        !isolation.note(1, at(730), resend),
        "an isolation within the resends asks nothing"
    );
}

#[test]
fn issue1427_reconnect_during_a_pass_runs_one_more_pass() {
    let gate = TreeKemReconnectGate::default();
    assert!(gate.request(), "the first reconnect starts a pass");
    assert!(!gate.request(), "a reconnect during the pass waits");
    assert!(
        !gate.request(),
        "a second one during the same pass adds nothing"
    );
    assert!(gate.finish(), "the pass ends: one more pass runs");
    assert!(!gate.finish(), "that pass ends: no reconnect came, done");
    assert!(gate.request(), "a later reconnect starts a pass again");
    assert!(!gate.finish());
}

type TaskFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// The test spawner: a plain tokio task.
fn tokio_spawn(task: TaskFuture) -> bool {
    tokio::spawn(task);
    true
}

/// Asks recorded by key, with their virtual start times.
type Asks = Arc<std::sync::Mutex<Vec<(String, tokio::time::Instant)>>>;

fn asks_of(asks: &Asks, key: &str) -> usize {
    asks.lock()
        .unwrap()
        .iter()
        .filter(|(k, _)| k == key)
        .count()
}

#[tokio::test(start_paused = true)]
async fn issue1427_reconnect_pass_retries_a_group_left_pending() {
    use std::sync::Mutex as StdMutex;
    // Group "a" is done after its first ask; "b" stays pending, as after
    // a reconnect to peers that were not members. Four more keys show the
    // concurrency cap.
    let calls: Arc<StdMutex<Vec<(String, tokio::time::Instant)>>> = Arc::default();
    let pending: Arc<StdMutex<std::collections::HashSet<String>>> = Arc::new(StdMutex::new(
        ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|k| k.to_string())
            .collect(),
    ));
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let most = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let gate = Arc::new(TreeKemReconnectGate::default());
    assert!(gate.request());
    let t0 = tokio::time::Instant::now();
    let retry = [Duration::from_secs(60), Duration::from_secs(300)];
    drive_treekem_reconnect_pass(
        ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|k| k.to_string())
            .collect(),
        (2, Duration::from_secs(120)),
        || Duration::from_secs(1),
        {
            let (calls, pending) = (Arc::clone(&calls), Arc::clone(&pending));
            let (in_flight, most) = (Arc::clone(&in_flight), Arc::clone(&most));
            move |key: String| {
                let calls = Arc::clone(&calls);
                let pending = Arc::clone(&pending);
                let in_flight = Arc::clone(&in_flight);
                let most = Arc::clone(&most);
                async move {
                    let now = in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    most.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    calls
                        .lock()
                        .unwrap()
                        .push((key.clone(), tokio::time::Instant::now()));
                    if key != "b" {
                        pending.lock().unwrap().remove(&key);
                    }
                }
            }
        },
        &tokio_spawn,
        |key| pending.lock().unwrap().contains(key),
        &retry,
        &gate,
    )
    .await;
    let calls = calls.lock().unwrap().clone();
    let asks = |k: &str| calls.iter().filter(|(key, _)| key == k).count();
    assert_eq!(asks("a"), 1, "a done group is asked once");
    assert_eq!(
        asks("b"),
        3,
        "a pending group is asked again after each wait"
    );
    assert_eq!(
        most.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the cap holds"
    );
    let b_times: Vec<Duration> = calls
        .iter()
        .filter(|(key, _)| key == "b")
        .map(|(_, at)| at.saturating_duration_since(t0))
        .collect();
    assert!(b_times[1] - b_times[0] >= Duration::from_secs(60));
    assert!(b_times[2] - b_times[1] >= Duration::from_secs(300));
    assert!(!gate.finish());
}

#[tokio::test(start_paused = true)]
async fn issue1427_reconnect_during_a_retry_wait_ends_the_pass() {
    let gate = Arc::new(TreeKemReconnectGate::default());
    assert!(gate.request());
    let asks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let driver_gate = Arc::clone(&gate);
    let driver_asks = Arc::clone(&asks);
    let driver = tokio::spawn(async move {
        drive_treekem_reconnect_pass(
            vec!["b".to_string()],
            (4, Duration::from_secs(120)),
            || Duration::ZERO,
            move |_key: String| {
                let asks = Arc::clone(&driver_asks);
                async move {
                    asks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            },
            &tokio_spawn,
            |_key| true,
            &[Duration::from_secs(900)],
            &driver_gate,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!gate.request(), "a reconnect during the retry wait");
    tokio::time::timeout(Duration::from_secs(1), driver)
        .await
        .expect("the wait ends early")
        .expect("driver task");
    assert_eq!(asks.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(gate.finish(), "the next pass runs for the reconnect");
}

/// #1936 review: a group whose catch-up never ends (it renews while
/// epoch-ahead traffic for an unservable commit arrives) holds its slot
/// for one turn only, so the groups behind it are still asked.
#[tokio::test(start_paused = true)]
async fn issue1427_a_catchup_that_never_ends_holds_its_slot_for_one_turn() {
    let asks: Asks = Arc::default();
    let gate = Arc::new(TreeKemReconnectGate::default());
    assert!(gate.request());
    let (driver_asks, driver_gate) = (Arc::clone(&asks), Arc::clone(&gate));
    let turn = Duration::from_secs(120);
    let t0 = tokio::time::Instant::now();
    let driver = tokio::spawn(async move {
        drive_treekem_reconnect_pass(
            ["stuck1", "stuck2", "late"]
                .iter()
                .map(|k| k.to_string())
                .collect(),
            (2, turn),
            || Duration::ZERO,
            move |key: String| {
                let asks = Arc::clone(&driver_asks);
                async move {
                    asks.lock()
                        .unwrap()
                        .push((key.clone(), tokio::time::Instant::now()));
                    if key.starts_with("stuck") {
                        std::future::pending::<()>().await;
                    }
                }
            },
            &tokio_spawn,
            |key| key.starts_with("stuck"),
            &[Duration::from_secs(60)],
            &driver_gate,
        )
        .await;
    });
    tokio::time::sleep(turn + Duration::from_secs(5)).await;
    assert_eq!(
        asks_of(&asks, "late"),
        1,
        "the group behind the stuck ones is asked"
    );
    let late_at = asks
        .lock()
        .unwrap()
        .iter()
        .find(|(k, _)| k == "late")
        .map(|(_, at)| *at);
    assert!(late_at.is_some_and(|at| at.saturating_duration_since(t0) >= turn));
    // The retry round skips the stuck groups whose catch-up still runs.
    tokio::time::timeout(Duration::from_secs(600), driver)
        .await
        .expect("the pass ends")
        .expect("driver task");
    assert_eq!(
        asks_of(&asks, "stuck1"),
        1,
        "no second catch-up beside a running one"
    );
    assert_eq!(asks_of(&asks, "stuck2"), 1);
}

/// #1936 review: a reconnect that waits ends the current turns and starts
/// no further group; the next pass asks for every group.
#[tokio::test(start_paused = true)]
async fn issue1427_a_waiting_reconnect_cuts_the_round_short() {
    let asks: Asks = Arc::default();
    let gate = Arc::new(TreeKemReconnectGate::default());
    assert!(gate.request());
    let (driver_asks, driver_gate) = (Arc::clone(&asks), Arc::clone(&gate));
    let driver = tokio::spawn(async move {
        drive_treekem_reconnect_pass(
            ["stuck", "b", "c"].iter().map(|k| k.to_string()).collect(),
            (1, Duration::from_secs(3600)),
            || Duration::ZERO,
            move |key: String| {
                let asks = Arc::clone(&driver_asks);
                async move {
                    asks.lock()
                        .unwrap()
                        .push((key.clone(), tokio::time::Instant::now()));
                    std::future::pending::<()>().await;
                }
            },
            &tokio_spawn,
            |_key| true,
            &[Duration::from_secs(60)],
            &driver_gate,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(
        !gate.request(),
        "a reconnect while the stuck group holds the slot"
    );
    tokio::time::timeout(Duration::from_secs(1), driver)
        .await
        .expect("the round ends at once")
        .expect("driver task");
    assert_eq!(asks_of(&asks, "stuck"), 1);
    assert_eq!(
        asks_of(&asks, "b") + asks_of(&asks, "c"),
        0,
        "no group starts after it"
    );
    assert!(gate.finish(), "the next pass runs for the reconnect");
}

/// #1936 review: the record lock orders the removal of the outage record
/// against a new mark. While a pass holds the lock, the last finished
/// group does not remove the record; once the pass has marked a new group
/// under the lock, the record stays.
#[tokio::test]
async fn issue1427_record_removal_waits_for_the_record_lock() -> Result<()> {
    let (state, _dir, key) = treekem_member_state().await?;
    let record = treekem_catchup_pending_path(&state);
    crate::profile::write_atomically(&record, b"outage").await?;
    state
        .treekem_start_catchup_pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key.clone());
    // A reconnect pass holds the lock, as it does while it marks.
    let held = state.treekem_catchup_record_lock.lock().await;
    let done_state = Arc::clone(&state);
    let done_key = key.clone();
    let mut done = tokio::spawn(async move {
        treekem_start_catchup_done(&done_state, &done_key, None).await;
    });
    let waited = tokio::time::timeout(Duration::from_millis(300), &mut done).await;
    assert!(waited.is_err(), "the removal waits for the record lock");
    assert!(
        tokio::fs::try_exists(&record).await?,
        "the record stays meanwhile"
    );
    // The pass marks a new group under the lock and sees the record.
    state
        .treekem_start_catchup_pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert("another-group".to_string());
    drop(held);
    done.await?;
    assert!(
        tokio::fs::try_exists(&record).await?,
        "a group is pending again, so the record stays"
    );
    Ok(())
}

/// #1936 delta review: a pass that finds a group's catch-up from an earlier
/// pass still running does not start a second one, but that catch-up asks
/// once more when it ends, so a pending mark the later pass set is served
/// after the mark (the old catch-up's `Done` could clear it).
#[tokio::test(start_paused = true)]
async fn issue1427_a_busy_group_is_asked_again_when_its_catchup_ends() {
    let asks: Asks = Arc::default();
    let first = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new(TreeKemReconnectGate::default());
    let run = {
        let (asks, first) = (Arc::clone(&asks), Arc::clone(&first));
        move |key: String| {
            let (asks, first) = (Arc::clone(&asks), Arc::clone(&first));
            async move {
                let n = {
                    let mut asks = asks.lock().unwrap();
                    asks.push((key, tokio::time::Instant::now()));
                    asks.len()
                };
                if n == 1 {
                    // The first catch-up outlives its turn.
                    first.notified().await;
                }
            }
        }
    };
    // Pass 1: G's catch-up outlives its turn.
    assert!(gate.request());
    drive_treekem_reconnect_pass(
        vec!["g".to_string()],
        (4, Duration::from_secs(120)),
        || Duration::ZERO,
        run.clone(),
        &tokio_spawn,
        |_key| false,
        &[],
        &gate,
    )
    .await;
    assert!(!gate.finish());
    // Pass 2, after another isolation: G is marked again but still busy.
    assert!(gate.request());
    drive_treekem_reconnect_pass(
        vec!["g".to_string()],
        (4, Duration::from_secs(120)),
        || Duration::ZERO,
        run,
        &tokio_spawn,
        |_key| false,
        &[],
        &gate,
    )
    .await;
    assert_eq!(
        asks_of(&asks, "g"),
        1,
        "no second catch-up beside the running one"
    );
    // The first catch-up ends: it asks once more for pass 2.
    first.notify_one();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        asks_of(&asks, "g"),
        2,
        "the busy group is asked again after its catch-up"
    );
    assert!(gate.claim("g"), "and is released after that");
}

/// #1936 delta review: a catch-up task that panics releases its group.
#[tokio::test(start_paused = true)]
async fn issue1427_a_panicking_catchup_releases_its_group() {
    let gate = Arc::new(TreeKemReconnectGate::default());
    assert!(gate.request());
    drive_treekem_reconnect_pass(
        vec!["g".to_string()],
        (4, Duration::from_secs(120)),
        || Duration::ZERO,
        |_key: String| async move { panic!("catch-up task panics") },
        &tokio_spawn,
        |_key| false,
        &[],
        &gate,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(gate.claim("g"), "the panicked task's group is free again");
}

/// #1936 review follow-up: a later pass marks a group whose catch-up from
/// an earlier pass still runs. That older catch-up then ends `Done`. The
/// later pass's mark and the outage record stay, so the re-ask can end
/// KeepPending and the later pass retries the group. A `Done` with no
/// later mark still removes both.
///
/// The clock is paused and the steps are ordered by signals, not by real
/// sleeps (#1949 review): the older catch-up ends only after pass 2 has
/// checked its pending groups, that is, inside pass 2's retry wait. From
/// there to the re-ask's end nothing waits on a timer or on file I/O, so
/// the paused clock cannot move the retry ahead of the re-ask.
#[tokio::test(start_paused = true)]
async fn issue1427_a_later_pass_mark_survives_the_older_catchups_done() -> Result<()> {
    let (state, _dir, key) = treekem_member_state().await?;
    let record = treekem_catchup_pending_path(&state);
    let gate = Arc::new(TreeKemReconnectGate::default());
    let asks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first = Arc::new(tokio::sync::Notify::new());
    // The first catch-up waits, then ends Done. Later ones end KeepPending.
    let run = {
        let (state, gate) = (Arc::clone(&state), Arc::clone(&gate));
        let (asks, first) = (Arc::clone(&asks), Arc::clone(&first));
        move |key: String| {
            let (state, gate) = (Arc::clone(&state), Arc::clone(&gate));
            let (asks, first) = (Arc::clone(&asks), Arc::clone(&first));
            async move {
                if asks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    first.notified().await;
                    treekem_start_catchup_done(&state, &key, Some(&gate)).await;
                }
            }
        }
    };
    let keys = vec![key.clone()];
    // Pass 1: the catch-up outlives its turn.
    assert!(gate.request());
    mark_treekem_reconnect_pass(&state, &gate, &keys).await;
    drive_treekem_reconnect_pass(
        keys.clone(),
        (4, Duration::from_millis(50)),
        || Duration::ZERO,
        run.clone(),
        &tokio_spawn,
        |_key| false,
        &[],
        &gate,
    )
    .await;
    assert!(!gate.finish());
    // Pass 2, after another isolation: the group is busy.
    assert!(gate.request());
    mark_treekem_reconnect_pass(&state, &gate, &keys).await;
    let pass_state = Arc::clone(&state);
    let pass_gate = Arc::clone(&gate);
    let pass_keys = keys.clone();
    // Signalled when pass 2 checks its pending groups after its first
    // round; its retry wait starts right after.
    let retry_wait = Arc::new(tokio::sync::Notify::new());
    let in_retry_wait = Arc::clone(&retry_wait);
    let pass2 = tokio::spawn(async move {
        drive_treekem_reconnect_pass(
            pass_keys,
            (4, Duration::from_millis(50)),
            || Duration::ZERO,
            run,
            &tokio_spawn,
            |key| {
                in_retry_wait.notify_one();
                pending(&pass_state, key)
            },
            &[Duration::from_secs(1)],
            &pass_gate,
        )
        .await;
    });
    retry_wait.notified().await;
    // The older catch-up ends Done during pass 2's retry wait.
    first.notify_one();
    pass2.await?;
    assert_eq!(
        asks.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "the re-ask, then pass 2's retry"
    );
    assert!(pending(&state, &key), "pass 2's mark stays");
    assert!(tokio::fs::try_exists(&record).await?, "the record stays");
    // A Done with no later mark removes both: no permanent mark.
    assert!(gate.claim(&key), "the group is free");
    treekem_start_catchup_done(&state, &key, Some(&gate)).await;
    assert!(!pending(&state, &key));
    assert!(!tokio::fs::try_exists(&record).await?);
    Ok(())
}

/// #1936 review follow-up: a claim whose task the spawner refuses
/// (shutdown) is released. This pins the driver's claim guard with a
/// stand-in spawner; the real `spawn_detached` drops a refused task the
/// same way.
#[tokio::test]
async fn issue1427_a_refused_spawn_releases_its_group() {
    let gate = Arc::new(TreeKemReconnectGate::default());
    assert!(gate.request());
    let refuse = |task: TaskFuture| {
        drop(task);
        false
    };
    drive_treekem_reconnect_pass(
        vec!["g".to_string()],
        (4, Duration::from_secs(120)),
        || Duration::ZERO,
        |_key: String| async move {},
        &refuse,
        |_key| false,
        &[],
        &gate,
    )
    .await;
    assert!(gate.claim("g"), "the refused task's group is free again");
}
