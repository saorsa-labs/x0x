//! W3-H S1 controls: the harness itself, before any failure case.
//!
//! - `w3h_clock_gate_*`: virtual time does not move outside a barrier.
//! - `w3h_auto_advance_freezes_*`: without `tokio_unstable`, auto-advance
//!   stays put while `spawn_blocking` runs.
//! - `w3h_blocking_completion_does_not_stall_paused_time`: a finished
//!   blocking task does not add a wall stall before the paused clock steps.
//! - `w3h_next_blocking_task_keeps_the_paused_clock_still`: that wind-down
//!   does not keep stepping once the pool thread runs the next blocking task.
//! - `w3h_wind_down_does_not_step_while_another_blocking_task_runs`: the
//!   stamp excuses only the thread that published it.
//! - `w3h_blocking_task_queued_after_the_finish_check_keeps_the_clock_still`:
//!   a task queued after the finish hook's queue check does not inherit it.
//! - `w3h_blocking_task_popped_after_the_admission_snapshot_keeps_the_clock_still`:
//!   the same pool thread pops a task queued after the admission snapshot.
//! - `w3h_blocking_task_running_before_the_pool_sample_keeps_the_clock_still`:
//!   that task is running, and the queue is empty, before the next pool sample.
//! - `w3h_blocking_task_after_unseen_idle_keeps_the_clock_still`: the pool
//!   thread goes idle without a sample, then a new task brings the busy
//!   count back.
//! - `w3h_retired_idle_slot_ignores_a_leftover_pool_thread`: the next runtime
//!   does not share the previous idle slot.
//! - `w3h_zero_task_id_does_not_publish_a_wind_down`: a task id of 0 does
//!   not arm the excuse.
//! - `w3h_finish_gate_is_owned_before_completion_is_published`: the terminate
//!   hook owns the finish gate before it publishes completion.
//! - `w3h_recheck_*`: the unstable recheck thread re-arms after a lost park,
//!   including when the pool stays busy across disarm, and does not publish
//!   `ready` into the next barrier. It also must not wake the barrier in the
//!   gap after the driver returns and before `after_unpark` clears `parked`.
//! - `w3h_spawn_blocking_completion_does_not_resume_block_on_mid_chain`:
//!   `block_on` does not poll its future in the middle of a ready task chain.
//! - `w3h_s1_control_*`: three real daemons, public API only, over the
//!   fabric. The positive control must converge AND deliver group data; the
//!   negative control (joiner offline) must fail for exactly the intended
//!   reason, with every authority read succeeding.
//!
//! The group shape is the live fixture's `private_secure` path
//! (`tests/e2e_vps_private_kv.py` `run_private`): create with the preset,
//! join by invite, open the same `wiki` store on every member, write on
//! the owner, read on the joiners.
//!
//! Daemon controls run only in the Linux isolated namespace (CI `w3h`
//! profile); they are compile-checked elsewhere.

#![cfg(test)]

use super::*;
use anyhow::{anyhow, bail, ensure};
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Percent-encode one path segment (every byte outside RFC 3986's
/// unreserved set), as the live fixture's `urllib.parse.quote(v, safe="")`
/// does. A group store id is its topic, `x0x/group/<gid>/kv/<name>`, so
/// its slashes must not split the `/stores/:id/:key` route.
fn path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The members `label` lists for `group`; `Err` when the read itself fails
/// (non-2xx, or no `members` array).
pub(super) async fn members(sim: &Sim, label: &str, group: &str) -> Result<Vec<String>> {
    let (status, info) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(status.is_success(), "{label} GET /groups/{group}: {status}");
    Ok(info["members"]
        .as_array()
        .context("no members array")?
        .iter()
        .filter_map(|member| member["agent_id"].as_str().map(str::to_string))
        .collect())
}

pub(super) async fn mesh(sim: &Sim, labels: &[&str]) -> Result<()> {
    sim.until("mesh up", secs(60), async |s: &Sim| {
        for label in labels {
            if s.connected_peer_count(label).await == 0 {
                return false;
            }
        }
        true
    })
    .await
}

pub(super) async fn create_group(sim: &Sim, owner: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({"name": "w3h control", "display_name": owner, "preset": "private_secure"})),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

pub(super) async fn invite(sim: &Sim, inviter: &str, group: &str) -> Result<String> {
    let (status, invite) = sim
        .api(
            inviter,
            Method::POST,
            &format!("/groups/{group}/invite"),
            Some(json!({})),
        )
        .await?;
    ensure!(status.is_success(), "invite: {status} {invite}");
    Ok(invite["invite_link"]
        .as_str()
        .context("invite response has no invite_link")?
        .to_string())
}

pub(super) async fn join(sim: &Sim, joiner: &str, link: &str) -> Result<()> {
    let (status, joined) = sim
        .api(
            joiner,
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": joiner})),
        )
        .await?;
    ensure!(
        status.is_success() && joined["ok"] != false,
        "{joiner} join: {status} {joined}"
    );
    Ok(())
}

pub(super) async fn open_store(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let (status, store) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "wiki"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} open store: {status} {store}");
    Ok(store["id"].as_str().context("store id")?.to_string())
}

/// `membership_state` of `group` as `label` reports it.
pub(super) async fn local_membership(sim: &Sim, label: &str, group: &str) -> Option<String> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    body["membership_state"].as_str().map(str::to_string)
}

/// `POST /groups/:id/stores` without a barrier (for use inside one).
pub(super) async fn try_open_store(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let (status, store) = sim
        .request(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "wiki"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} open store: {status} {store}");
    Ok(store["id"].as_str().context("store id")?.to_string())
}

pub(super) async fn read_value(sim: &Sim, label: &str, store: &str, key: &str) -> Option<String> {
    let (status, body) = sim
        .request(
            label,
            Method::GET,
            &format!("/stores/{}/{}", path_segment(store), path_segment(key)),
            None,
        )
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    let bytes = BASE64.decode(body["value"].as_str()?).ok()?;
    String::from_utf8(bytes).ok()
}

/// `label` writes `value` under `key` in the group store `store`, inside
/// its own barrier (the S1 control's write, as a helper).
pub(super) async fn put_value(
    sim: &Sim,
    label: &str,
    store: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let (status, put) = sim
        .api(
            label,
            Method::PUT,
            &format!("/stores/{}/{}", path_segment(store), path_segment(key)),
            Some(json!({"value": BASE64.encode(value), "content_type": "text/plain"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} put {key}: {status} {put}");
    Ok(())
}

#[test]
fn w3h_clock_gate_holds_virtual_time_outside_barriers() -> Result<()> {
    super::block_on_paused(async move {
        let start = tokio::time::Instant::now();
        let gate = ClockGate::close();
        let sleeper = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(10)).await });
        // Stay idle for 300 ms of real time with a 10 s virtual timer pending.
        // Without the gate, paused tokio would auto-advance straight to it.
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = tx.send(());
        });
        rx.await?;
        ensure!(
            tokio::time::Instant::now() == start,
            "virtual time moved while the gate was closed"
        );
        ensure!(!sleeper.is_finished(), "a 10 s timer fired while gated");
        gate.open().await;
        sleeper.await?;
        ensure!(tokio::time::Instant::now() >= start + Duration::from_secs(10));
        Ok(())
    })
}

/// #1245: a barrier must not spend virtual time while `spawn_blocking`
/// runs. Stepping on every wake turned a slow pool task into a different
/// virtual duration on each rerun, and burned barrier budgets.
#[test]
#[cfg(tokio_unstable)]
fn w3h_drive_paused_freezes_while_spawn_blocking_runs() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let start = tokio::time::Instant::now();
        // 30 s of virtual time. With auto-advance inhibited, a missed idle
        // wake parks the runtime for that long in real time. The wall bound
        // below is much shorter, so a lost recheck fails this case.
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        super::drive_paused(async {
            super::spawn_blocking(|| {
                std::thread::sleep(std::time::Duration::from_millis(80));
            })
            .await
            .expect("blocking task");
            ensure!(
                tokio::time::Instant::now() == start,
                "virtual time moved during spawn_blocking"
            );
            ensure!(
                !sleeper.is_finished(),
                "a 30 s timer fired while a blocking task held the clock"
            );
            Ok(())
        })
        .await?;
        // Poll the sleeper once so its timer is in the wheel before the
        // next park. One idle step must move virtual time inside the wall
        // bound. Waiting out the 30 s timer would pass a broken recheck.
        tokio::task::yield_now().await;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = tx.send(());
        });
        tokio::select! {
            biased;
            stepped = super::drive_paused(async {
                let origin = tokio::time::Instant::now();
                std::future::poll_fn(|_cx| {
                    if tokio::time::Instant::now() > origin {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
                Ok::<(), anyhow::Error>(())
            }) => stepped?,
            _ = rx => bail!("idle step stalled in wall time after spawn_blocking"),
        }
        ensure!(
            tokio::time::Instant::now() > start,
            "idle barrier did not step after spawn_blocking"
        );
        ensure!(
            !sleeper.is_finished(),
            "the 30 s timer fired inside the wall bound"
        );
        Ok(())
    })
}

/// #1662: once a blocking closure has returned, the paused clock must step
/// even though Tokio has not yet marked that pool thread idle. The finish
/// gate holds the thread in that gap. Waiting for the idle mark stalls the
/// wall clock.
#[test]
#[cfg(tokio_unstable)]
fn w3h_blocking_completion_does_not_stall_paused_time() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_gate_tx, release_gate_rx) = std::sync::mpsc::channel::<()>();
        super::install_blocking_finish_gate(&slot, entered_tx, release_gate_rx);
        let (release_task_tx, release_task_rx) = std::sync::mpsc::channel::<()>();
        let (moved_tx, moved_rx) = std::sync::mpsc::channel::<()>();
        let blocker = super::spawn_blocking(move || {
            let _ = release_task_rx.recv();
        });
        let coord = std::thread::spawn(move || {
            struct Release(Option<std::sync::mpsc::Sender<()>>);
            impl Drop for Release {
                fn drop(&mut self) {
                    if let Some(release) = self.0.take() {
                        let _ = release.send(());
                    }
                }
            }
            let release = Release(Some(release_gate_tx));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let order = std::sync::atomic::Ordering::Acquire;
            while std::time::Instant::now() < deadline {
                if slot.parked.load(order) {
                    break;
                }
                std::thread::yield_now();
            }
            if !slot.parked.load(order) {
                panic!("runtime did not park while the blocking task held the pool");
            }
            let _ = release_task_tx.send(());
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("blocking task did not reach the idle-mark gap");
            let started = std::time::Instant::now();
            // The gate is still held. A correct clock moves before this
            // wait ends. 2 s is a stall watchdog, not a scheduling deadline:
            // a busy host can pause the wake longer than a few milliseconds.
            let moved = moved_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .is_ok();
            let elapsed = started.elapsed();
            drop(release);
            (moved, elapsed)
        });
        let virtual_start = tokio::time::Instant::now();
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let _ = wall_tx.send(());
        });
        tokio::select! {
            biased;
            stepped = super::drive_paused(async move {
                let origin = tokio::time::Instant::now();
                std::future::poll_fn(move |_cx| {
                    if tokio::time::Instant::now() > origin {
                        let _ = moved_tx.send(());
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
                blocker.await.expect("blocking task");
                Ok::<(), anyhow::Error>(())
            }) => stepped?,
            _ = wall_rx => bail!("paused step stalled on the wall after a blocking task"),
        }
        let (moved, elapsed) = coord.join().expect("stall coordinator");
        let advanced = tokio::time::Instant::now().saturating_duration_since(virtual_start);
        ensure!(
            moved,
            "paused clock did not move while the pool thread was still winding down \
             (wall wait {elapsed:?})"
        );
        ensure!(
            advanced >= Duration::from_millis(1),
            "paused clock advanced {advanced:?}"
        );
        Ok(())
    })
}

/// #1662: the wind-down stamp covers the closure that just returned, and
/// only that closure. The next blocking task in the same barrier keeps the
/// paused clock still. `force_pool_busy` hides the queued window from
/// `pool_busy`, so the stamp has to be cleared when that task is admitted
/// rather than when a later sample happens to see the queue.
#[test]
#[cfg(tokio_unstable)]
fn w3h_next_blocking_task_keeps_the_paused_clock_still() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        super::set_force_pool_busy(&slot, true);
        let slot_for_coord = std::sync::Arc::clone(&slot);
        let handle = tokio::runtime::Handle::current();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_gate_tx, release_gate_rx) = std::sync::mpsc::channel::<()>();
        super::install_blocking_finish_gate(&slot, entered_tx, release_gate_rx);
        let (release_a_tx, release_a_rx) = std::sync::mpsc::channel::<()>();
        let (b_started_tx, b_started_rx) = std::sync::mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = std::sync::mpsc::channel::<()>();
        let (measure_tx, measure_rx) = tokio::sync::oneshot::channel::<()>();
        let (measured_tx, measured_rx) = std::sync::mpsc::channel::<()>();
        let _task_a = super::spawn_blocking(move || {
            let _ = release_a_rx.recv();
        });
        let coord = std::thread::spawn(move || {
            struct Release {
                slot: std::sync::Arc<super::IdleWait>,
                gate: Option<std::sync::mpsc::Sender<()>>,
                task_b: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    super::set_force_pool_busy(&self.slot, false);
                    if let Some(gate) = self.gate.take() {
                        let _ = gate.send(());
                    }
                    if let Some(task_b) = self.task_b.take() {
                        let _ = task_b.send(());
                    }
                }
            }
            let mut release = Release {
                slot: std::sync::Arc::clone(&slot_for_coord),
                gate: Some(release_gate_tx),
                task_b: Some(release_b_tx),
            };
            wait_until_idle(
                &slot_for_coord,
                |slot| slot.parked.load(std::sync::atomic::Ordering::Acquire),
                "runtime did not park while the first blocking task ran",
            );
            let _ = release_a_tx.send(());
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("first blocking task did not reach the idle-mark gap");
            let _task_b = super::spawn_blocking_on(&handle, move || {
                let _ = b_started_tx.send(());
                let _ = release_b_rx.recv();
            });
            if let Some(gate) = release.gate.take() {
                let _ = gate.send(());
            }
            b_started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("second blocking task did not start");
            super::set_force_pool_busy(&slot_for_coord, false);
            let _ = measure_tx.send(());
            let _ = measured_rx.recv_timeout(std::time::Duration::from_secs(2));
            drop(release);
        });
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let _ = wall_tx.send(());
        });
        tokio::select! {
            biased;
            stepped = super::drive_paused(async move {
                measure_rx.await.expect("stall coordinator");
                clock_stays_still_while_blocking(
                    "paused clock stepped while the next blocking task ran",
                )
                .await
            }) => {
                let _ = measured_tx.send(());
                stepped?;
            }
            _ = wall_rx => bail!("barrier stalled while two blocking tasks ran"),
        }
        coord.join().expect("stall coordinator");
        Ok(())
    })
}

/// #1662: publishing completion wakes the runtime, and the runtime can end
/// the barrier and drop the slot gate. The hook takes the gate first, so
/// that drop does not lose `entered`.
#[test]
#[cfg(tokio_unstable)]
fn w3h_finish_gate_is_owned_before_completion_is_published() -> Result<()> {
    super::block_on_paused(async move {
        let slot = super::idle_slot();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        super::install_blocking_finish_gate(&slot, entered_tx, release_rx);
        super::arm_drop_finish_gate_on_publish(&slot);
        let (release_task_tx, release_task_rx) = std::sync::mpsc::channel::<()>();
        let task = super::spawn_blocking(move || {
            let _ = release_task_rx.recv();
        });
        let _ = release_task_tx.send(());
        let entered = entered_rx.recv_timeout(std::time::Duration::from_secs(2));
        let _ = release_tx.send(());
        task.await.expect("blocking task");
        entered.expect(
            "finish gate was dropped when completion was published, before the hook owned it",
        );
        Ok(())
    })
}

/// #1662: task B is already running when task A finishes. The wind-down
/// stamp excuses A's thread only. Virtual time stays put while B runs,
/// including after A's thread has gone idle.
#[test]
#[cfg(tokio_unstable)]
fn w3h_wind_down_does_not_step_while_another_blocking_task_runs() -> Result<()> {
    let _cap = super::push_blocking_thread_cap(3);
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        let slot_for_coord = std::sync::Arc::clone(&slot);
        let handle = tokio::runtime::Handle::current();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_gate_tx, release_gate_rx) = std::sync::mpsc::channel::<()>();
        super::install_blocking_finish_gate(&slot, entered_tx, release_gate_rx);
        let (a_started_tx, a_started_rx) = std::sync::mpsc::channel::<()>();
        let (release_a_tx, release_a_rx) = std::sync::mpsc::channel::<()>();
        let (b_started_tx, b_started_rx) = std::sync::mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = std::sync::mpsc::channel::<()>();
        let (overlap_tx, overlap_rx) = tokio::sync::oneshot::channel::<()>();
        let (overlap_done_tx, overlap_done_rx) = std::sync::mpsc::channel::<()>();
        let (idle_tx, idle_rx) = tokio::sync::oneshot::channel::<()>();
        let (idle_done_tx, idle_done_rx) = std::sync::mpsc::channel::<()>();
        let _task_b = super::spawn_blocking(move || {
            let _ = b_started_tx.send(());
            let _ = release_b_rx.recv();
        });
        let _task_a = super::spawn_blocking(move || {
            let _ = a_started_tx.send(());
            let _ = release_a_rx.recv();
        });
        let coord = std::thread::spawn(move || {
            struct Release {
                gate: Option<std::sync::mpsc::Sender<()>>,
                task_b: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    if let Some(gate) = self.gate.take() {
                        let _ = gate.send(());
                    }
                    if let Some(task_b) = self.task_b.take() {
                        let _ = task_b.send(());
                    }
                }
            }
            let mut release = Release {
                gate: Some(release_gate_tx),
                task_b: Some(release_b_tx),
            };
            a_started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("first blocking task did not start");
            b_started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("second blocking task did not start");
            wait_until_idle(
                &slot_for_coord,
                |slot| slot.parked.load(std::sync::atomic::Ordering::Acquire),
                "runtime did not park while both blocking tasks ran",
            );
            let _ = release_a_tx.send(());
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("first blocking task did not reach the idle-mark gap");
            let _ = overlap_tx.send(());
            let _ = overlap_done_rx.recv_timeout(std::time::Duration::from_secs(2));
            if let Some(gate) = release.gate.take() {
                let _ = gate.send(());
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                let metrics = handle.metrics();
                let busy = metrics
                    .num_blocking_threads()
                    .saturating_sub(metrics.num_idle_blocking_threads());
                if busy <= 2 {
                    break;
                }
                if std::time::Instant::now() > deadline {
                    panic!("pool thread did not go idle after the finish gate, busy={busy}");
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = idle_tx.send(());
            let _ = idle_done_rx.recv_timeout(std::time::Duration::from_secs(2));
            drop(release);
        });
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(4));
            let _ = wall_tx.send(());
        });
        tokio::select! {
            biased;
            stepped = super::drive_paused(async move {
                overlap_rx.await.expect("stall coordinator");
                let overlap = clock_stays_still_while_blocking(
                    "paused clock stepped while another blocking task ran during wind-down",
                )
                .await;
                let _ = overlap_done_tx.send(());
                overlap?;
                idle_rx.await.expect("stall coordinator");
                let idle = clock_stays_still_while_blocking(
                    "paused clock stepped while another blocking task ran after wind-down",
                )
                .await;
                let _ = idle_done_tx.send(());
                idle?;
                Ok::<(), anyhow::Error>(())
            }) => stepped?,
            _ = wall_rx => bail!("barrier stalled while two blocking tasks ran"),
        }
        coord.join().expect("stall coordinator");
        Ok(())
    })
}

/// #1662: task B is queued after the finish hook has already seen an empty
/// queue. The hook admits B before this pool thread pops it. Virtual time
/// stays put while B runs.
#[test]
#[cfg(tokio_unstable)]
fn w3h_blocking_task_queued_after_the_finish_check_keeps_the_clock_still() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        super::set_force_pool_busy(&slot, true);
        let slot_for_coord = std::sync::Arc::clone(&slot);
        let handle = tokio::runtime::Handle::current();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_gate_tx, release_gate_rx) = std::sync::mpsc::channel::<()>();
        super::install_after_finish_check_gate(entered_tx, release_gate_rx);
        let (release_a_tx, release_a_rx) = std::sync::mpsc::channel::<()>();
        let (b_started_tx, b_started_rx) = std::sync::mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = std::sync::mpsc::channel::<()>();
        let (measure_tx, measure_rx) = tokio::sync::oneshot::channel::<()>();
        let (measured_tx, measured_rx) = std::sync::mpsc::channel::<()>();
        let _task_a = super::spawn_blocking(move || {
            let _ = release_a_rx.recv();
        });
        let coord = std::thread::spawn(move || {
            struct Release {
                slot: std::sync::Arc<super::IdleWait>,
                gate: Option<std::sync::mpsc::Sender<()>>,
                task_b: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    super::set_force_pool_busy(&self.slot, false);
                    if let Some(gate) = self.gate.take() {
                        let _ = gate.send(());
                    }
                    if let Some(task_b) = self.task_b.take() {
                        let _ = task_b.send(());
                    }
                }
            }
            let mut release = Release {
                slot: std::sync::Arc::clone(&slot_for_coord),
                gate: Some(release_gate_tx),
                task_b: Some(release_b_tx),
            };
            wait_until_idle(
                &slot_for_coord,
                |slot| slot.parked.load(std::sync::atomic::Ordering::Acquire),
                "runtime did not park while the first blocking task ran",
            );
            let _ = release_a_tx.send(());
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("finish hook did not pass the queue check");
            let _task_b = super::spawn_blocking_on(&handle, move || {
                let _ = b_started_tx.send(());
                let _ = release_b_rx.recv();
            });
            if let Some(gate) = release.gate.take() {
                let _ = gate.send(());
            }
            b_started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("blocking task queued after the finish check did not start");
            super::set_force_pool_busy(&slot_for_coord, false);
            let _ = measure_tx.send(());
            let _ = measured_rx.recv_timeout(std::time::Duration::from_secs(2));
            drop(release);
        });
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let _ = wall_tx.send(());
        });
        tokio::select! {
            biased;
            stepped = super::drive_paused(async move {
                measure_rx.await.expect("stall coordinator");
                clock_stays_still_while_blocking(
                    "paused clock stepped while a task queued after the finish check ran",
                )
                .await
            }) => {
                let _ = measured_tx.send(());
                stepped?;
            }
            _ = wall_rx => bail!("barrier stalled after a late blocking enqueue"),
        }
        coord.join().expect("stall coordinator");
        Ok(())
    })
}

/// Claude path 1: B is queued after the admission snapshot, and the same
/// pool thread pops it. The queue is empty again before the clock is allowed
/// to sample.
#[test]
#[cfg(tokio_unstable)]
fn w3h_blocking_task_popped_after_the_admission_snapshot_keeps_the_clock_still() -> Result<()> {
    late_admission_after_snapshot(true)
}

/// Codex: B is already running, the queue is empty, and the busy count is
/// back to the wind-down value, before the first pool sample that can step
/// the clock.
#[test]
#[cfg(tokio_unstable)]
fn w3h_blocking_task_running_before_the_pool_sample_keeps_the_clock_still() -> Result<()> {
    late_admission_after_snapshot(false)
}

#[cfg(tokio_unstable)]
fn late_admission_after_snapshot(same_thread: bool) -> Result<()> {
    let what = if same_thread {
        "paused clock stepped while the same pool thread ran a task admitted after the snapshot"
    } else {
        "paused clock stepped while a task admitted after the snapshot was already running"
    };
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        super::set_force_pool_busy(&slot, true);
        let slot_for_coord = std::sync::Arc::clone(&slot);
        let handle = tokio::runtime::Handle::current();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_gate_tx, release_gate_rx) = std::sync::mpsc::channel::<()>();
        super::install_after_admission_check_gate(entered_tx, release_gate_rx);
        let (a_tid_tx, a_tid_rx) = std::sync::mpsc::channel();
        let (b_tid_tx, b_tid_rx) = std::sync::mpsc::channel();
        let (b_started_tx, b_started_rx) = std::sync::mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = std::sync::mpsc::channel::<()>();
        let (measure_tx, measure_rx) = tokio::sync::oneshot::channel::<()>();
        let (measured_tx, measured_rx) = std::sync::mpsc::channel::<()>();
        let _task_a = super::spawn_blocking(move || {
            let _ = a_tid_tx.send(std::thread::current().id());
        });
        let coord = std::thread::spawn(move || {
            struct Release {
                slot: std::sync::Arc<super::IdleWait>,
                gate: Option<std::sync::mpsc::Sender<()>>,
                task_b: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    super::set_force_pool_busy(&self.slot, false);
                    if let Some(gate) = self.gate.take() {
                        let _ = gate.send(());
                    }
                    if let Some(task_b) = self.task_b.take() {
                        let _ = task_b.send(());
                    }
                }
            }
            let mut release = Release {
                slot: std::sync::Arc::clone(&slot_for_coord),
                gate: Some(release_gate_tx),
                task_b: Some(release_b_tx),
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("finish hook did not reach the admission snapshot");
            let a_tid = a_tid_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("first blocking task did not report its thread");
            assert!(
                excuse_matches(&slot_for_coord),
                "wind-down was not published at the admission snapshot"
            );
            let _task_b = super::spawn_blocking_on(&handle, move || {
                let _ = b_tid_tx.send(std::thread::current().id());
                let _ = b_started_tx.send(());
                let _ = release_b_rx.recv();
            });
            assert!(
                admission_voids_excuse(&slot_for_coord),
                "spawning the next task did not record an admission"
            );
            if let Some(gate) = release.gate.take() {
                let _ = gate.send(());
            }
            b_started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("task admitted after the snapshot did not start");
            let b_tid = b_tid_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("second blocking task did not report its thread");
            if same_thread {
                assert_eq!(
                    a_tid, b_tid,
                    "the pool thread that finished the first task did not pop the next one"
                );
            }
            assert_eq!(
                handle.metrics().blocking_queue_depth(),
                0,
                "the next task was still queued when the clock was allowed to sample"
            );
            assert_eq!(
                super::blocking_extra(&handle),
                1,
                "the busy count did not return to the wind-down value before the sample"
            );
            assert!(
                admission_voids_excuse(&slot_for_coord),
                "the excuse was cleared before the sample, so the admission count was not what held the clock"
            );
            super::set_force_pool_busy(&slot_for_coord, false);
            let _ = measure_tx.send(());
            let _ = measured_rx.recv_timeout(std::time::Duration::from_secs(2));
            drop(release);
        });
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let _ = wall_tx.send(());
        });
        tokio::select! {
            biased;
            stepped = super::drive_paused(async move {
                measure_rx.await.expect("stall coordinator");
                clock_stays_still_while_blocking(what).await
            }) => {
                let _ = measured_tx.send(());
                stepped?;
            }
            _ = wall_rx => bail!("barrier stalled after a task was admitted past the snapshot"),
        }
        coord.join().expect("stall coordinator");
        Ok(())
    })
}

/// Claude path 2: the finishing thread goes idle without `pool_busy` seeing
/// it, then B is admitted and the busy count returns to the published value.
#[test]
#[cfg(tokio_unstable)]
fn w3h_blocking_task_after_unseen_idle_keeps_the_clock_still() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        super::set_force_pool_busy(&slot, true);
        let slot_for_coord = std::sync::Arc::clone(&slot);
        let handle = tokio::runtime::Handle::current();
        let (b_started_tx, b_started_rx) = std::sync::mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = std::sync::mpsc::channel::<()>();
        let (measure_tx, measure_rx) = tokio::sync::oneshot::channel::<()>();
        let (measured_tx, measured_rx) = std::sync::mpsc::channel::<()>();
        let _task_a = super::spawn_blocking(|| {});
        let coord = std::thread::spawn(move || {
            struct Release {
                slot: std::sync::Arc<super::IdleWait>,
                task_b: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    super::set_force_pool_busy(&self.slot, false);
                    if let Some(task_b) = self.task_b.take() {
                        let _ = task_b.send(());
                    }
                }
            }
            let release = Release {
                slot: std::sync::Arc::clone(&slot_for_coord),
                task_b: Some(release_b_tx),
            };
            wait_until_idle(
                &slot_for_coord,
                |slot| super::blocking_extra(&handle) == 0 && excuse_matches(slot),
                "wind-down was not still armed after the pool thread went idle unseen",
            );
            let _task_b = super::spawn_blocking_on(&handle, move || {
                let _ = b_started_tx.send(());
                let _ = release_b_rx.recv();
            });
            b_started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("task admitted after the unseen idle did not start");
            assert_eq!(
                super::blocking_extra(&handle),
                1,
                "the busy count did not return to the wind-down value"
            );
            assert!(
                admission_voids_excuse(&slot_for_coord),
                "the new admission did not void the excuse that survived the idle gap"
            );
            super::set_force_pool_busy(&slot_for_coord, false);
            let _ = measure_tx.send(());
            let _ = measured_rx.recv_timeout(std::time::Duration::from_secs(2));
            drop(release);
        });
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(4));
            let _ = wall_tx.send(());
        });
        tokio::select! {
            biased;
            stepped = super::drive_paused(async move {
                measure_rx.await.expect("stall coordinator");
                clock_stays_still_while_blocking(
                    "paused clock stepped after a new task restored the wind-down busy count",
                )
                .await
            }) => {
                let _ = measured_tx.send(());
                stepped?;
            }
            _ = wall_rx => bail!("barrier stalled after an unseen idle"),
        }
        coord.join().expect("stall coordinator");
        Ok(())
    })
}

/// A leftover pool thread can write the idle slot it already holds. The
/// fresh slot's excuse inputs stay at zero while that write runs.
#[test]
#[cfg(tokio_unstable)]
fn w3h_retired_idle_slot_ignores_a_leftover_pool_thread() {
    let old = super::idle_slot();
    super::retire_idle_slot();
    let fresh = super::idle_slot();
    assert!(
        !std::sync::Arc::ptr_eq(&old, &fresh),
        "a new runtime reused the previous idle slot"
    );
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_writer = std::sync::Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let order = std::sync::atomic::Ordering::Release;
        while !stop_writer.load(std::sync::atomic::Ordering::Acquire) {
            old.blocking_admissions.store(u64::MAX, order);
            old.blocking_finished.store(u64::MAX, order);
            old.blocking_unsettled_task.store(9, order);
            old.blocking_unsettled_admissions.store(4, order);
            old.pool_samples.store(u64::MAX, order);
        }
    });
    let order = std::sync::atomic::Ordering::Acquire;
    for _ in 0..1_000 {
        assert_eq!(
            fresh.blocking_admissions.load(order),
            0,
            "leftover admission write landed on the fresh slot"
        );
        assert_eq!(
            fresh.blocking_finished.load(order),
            0,
            "leftover completion write landed on the fresh slot"
        );
        assert_eq!(
            fresh.blocking_unsettled_task.load(order),
            0,
            "leftover excuse write landed on the fresh slot"
        );
        assert_eq!(
            fresh.blocking_unsettled_admissions.load(order),
            0,
            "leftover recorded admission landed on the fresh slot"
        );
        assert_eq!(
            fresh.pool_samples.load(order),
            0,
            "leftover sample write landed on the fresh slot"
        );
        assert!(
            std::sync::Arc::ptr_eq(&fresh, &super::idle_slot()),
            "the harness stopped reading the fresh slot"
        );
    }
    stop.store(true, std::sync::atomic::Ordering::Release);
    writer.join().expect("leftover writer");
}

/// A task id of 0 does not arm a wind-down. The clock then waits for the
/// idle mark instead of stepping over a later task.
#[test]
#[cfg(tokio_unstable)]
fn w3h_zero_task_id_does_not_publish_a_wind_down() {
    super::retire_idle_slot();
    let slot = super::idle_slot();
    let order = std::sync::atomic::Ordering::Release;
    slot.blocking_admissions.store(3, order);
    super::publish_wind_down(&slot, 0);
    let order = std::sync::atomic::Ordering::Acquire;
    assert_eq!(slot.blocking_unsettled_task.load(order), 0);
    assert_eq!(
        slot.blocking_unsettled_admissions.load(order),
        0,
        "a zero task id stored an admission snapshot"
    );
}

#[cfg(tokio_unstable)]
fn excuse_matches(slot: &super::IdleWait) -> bool {
    let order = std::sync::atomic::Ordering::Acquire;
    let unsettled = slot.blocking_unsettled_task.load(order);
    unsettled != 0
        && slot.blocking_admissions.load(order) == slot.blocking_unsettled_admissions.load(order)
}

#[cfg(tokio_unstable)]
fn admission_voids_excuse(slot: &super::IdleWait) -> bool {
    let order = std::sync::atomic::Ordering::Acquire;
    slot.blocking_unsettled_task.load(order) != 0
        && slot.blocking_admissions.load(order) > slot.blocking_unsettled_admissions.load(order)
}

/// The clock must stay put across a real pool sample. A wall slice is not
/// the oracle: a slow host can finish that slice before the paused clock
/// has had a chance to step.
#[cfg(tokio_unstable)]
async fn clock_stays_still_while_blocking(what: &str) -> Result<()> {
    let origin = tokio::time::Instant::now();
    let slot = super::idle_slot();
    let seen = slot.pool_samples.load(std::sync::atomic::Ordering::Acquire);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let slot_watch = std::sync::Arc::clone(&slot);
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let order = std::sync::atomic::Ordering::Acquire;
        while std::time::Instant::now() < deadline {
            if slot_watch.pool_samples.load(order) > seen {
                let _ = done_tx.send(true);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let _ = done_tx.send(false);
    });
    tokio::select! {
        biased;
        _ = tokio::time::sleep(Duration::from_millis(1)) => {
            bail!("{what}");
        }
        sampled = done_rx => {
            let sampled = sampled.expect("pool sample watcher ended");
            ensure!(
                sampled,
                "the pool was not sampled while the blocking task ran"
            );
            ensure!(tokio::time::Instant::now() == origin, "{what}");
            Ok(())
        }
    }
}

#[cfg(tokio_unstable)]
fn wait_until_idle(slot: &super::IdleWait, pred: impl Fn(&super::IdleWait) -> bool, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let order = std::sync::atomic::Ordering::Acquire;
    while std::time::Instant::now() < deadline {
        if pred(slot) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!(
        "{what}: parked={} epoch={} recheck={} ready={}",
        slot.parked.load(order),
        slot.epoch.load(order),
        slot.recheck_epoch.load(order),
        slot.ready.load(order)
    );
}

/// #1245: the recheck thread can see `parked == false` and, before it drops
/// its epoch claim, the runtime can park again. The park hook then starts
/// no thread. After the claim drops, this case marks the pool idle with no
/// further wake. A broken recheck sits in the 30 s timer. The fixed one
/// publishes `ready` and steps inside the wall bound.
#[test]
#[cfg(tokio_unstable)]
fn w3h_recheck_rearms_when_the_runtime_reparks_before_disarm() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        let slot_for_coord = std::sync::Arc::clone(&slot);
        super::set_force_pool_busy(&slot, true);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        super::install_disarm_gate(entered_tx, release_rx);
        let (wake_tx, wake_rx) = tokio::sync::oneshot::channel::<()>();
        let (holding_tx, holding_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        tokio::task::yield_now().await;

        let coord = std::thread::spawn(move || {
            struct Release {
                resume: Option<std::sync::mpsc::Sender<()>>,
                disarm: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    if let Some(resume) = self.resume.take() {
                        let _ = resume.send(());
                    }
                    if let Some(disarm) = self.disarm.take() {
                        let _ = disarm.send(());
                    }
                }
            }
            let mut release = Release {
                resume: Some(resume_tx),
                disarm: Some(release_tx),
            };
            let order = std::sync::atomic::Ordering::Acquire;
            wait_until_idle(
                &slot_for_coord,
                |slot| {
                    let epoch = slot.epoch.load(order);
                    slot.parked.load(order) && slot.recheck_epoch.load(order) == epoch
                },
                "recheck was not armed while the runtime was parked",
            );
            let _ = wake_tx.send(());
            holding_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("runtime thread did not block outside the park hook");
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("recheck thread did not stop before disarm");
            let resume = release.resume.take().expect("resume sender");
            let _ = resume.send(());
            wait_until_idle(
                &slot_for_coord,
                |slot| {
                    let epoch = slot.epoch.load(order);
                    slot.parked.load(order) && slot.recheck_epoch.load(order) == epoch
                },
                "runtime did not park again before the recheck disarmed",
            );
            // The pool is idle, and nothing wakes the runtime. The broken
            // thread now exits. The fixed one publishes `ready`.
            super::set_force_pool_busy(&slot_for_coord, false);
            let disarm = release.disarm.take().expect("disarm sender");
            let _ = disarm.send(());
        });

        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = wall_tx.send(());
        });
        let start = tokio::time::Instant::now();
        let stepped = tokio::select! {
            biased;
            stepped = super::drive_paused(async {
                wake_rx.await.ok();
                let _ = holding_tx.send(());
                let _ = resume_rx.recv();
                let origin = tokio::time::Instant::now();
                std::future::poll_fn(|_cx| {
                    if tokio::time::Instant::now() > origin {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
                Ok::<(), anyhow::Error>(())
            }) => stepped,
            _ = wall_rx => bail!("idle step stalled after the recheck disarmed"),
        };
        coord.join().expect("recheck coordinator");
        stepped?;
        ensure!(
            tokio::time::Instant::now() > start,
            "re-arm did not step virtual time"
        );
        ensure!(
            !sleeper.is_finished(),
            "the 30 s timer fired inside the wall bound"
        );
        Ok(())
    })
}

/// #1245: the recheck thread is a plain OS thread. If the runtime parks
/// again before disarm and the pool is still busy, that thread must re-arm
/// with the handle captured on the runtime. `Handle::current` panics there,
/// after the epoch claim, and a later park starts no thread. This case
/// keeps the pool marked busy until the first recheck thread has exited.
#[test]
#[cfg(tokio_unstable)]
fn w3h_recheck_rearms_when_the_pool_stays_busy_across_disarm() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        let slot_for_coord = std::sync::Arc::clone(&slot);
        super::set_force_pool_busy(&slot, true);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        super::install_disarm_gate(entered_tx, release_rx);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        super::install_recheck_finished(finished_tx);
        let (wake_tx, wake_rx) = tokio::sync::oneshot::channel::<()>();
        let (holding_tx, holding_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        tokio::task::yield_now().await;

        let coord = std::thread::spawn(move || {
            struct Release {
                resume: Option<std::sync::mpsc::Sender<()>>,
                disarm: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    if let Some(resume) = self.resume.take() {
                        let _ = resume.send(());
                    }
                    if let Some(disarm) = self.disarm.take() {
                        let _ = disarm.send(());
                    }
                }
            }
            let mut release = Release {
                resume: Some(resume_tx),
                disarm: Some(release_tx),
            };
            let order = std::sync::atomic::Ordering::Acquire;
            wait_until_idle(
                &slot_for_coord,
                |slot| {
                    let epoch = slot.epoch.load(order);
                    slot.parked.load(order) && slot.recheck_epoch.load(order) == epoch
                },
                "recheck was not armed while the runtime was parked",
            );
            let _ = wake_tx.send(());
            holding_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("runtime thread did not block outside the park hook");
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("recheck thread did not stop before disarm");
            let resume = release.resume.take().expect("resume sender");
            let _ = resume.send(());
            wait_until_idle(
                &slot_for_coord,
                |slot| {
                    let epoch = slot.epoch.load(order);
                    slot.parked.load(order) && slot.recheck_epoch.load(order) == epoch
                },
                "runtime did not park again before the recheck disarmed",
            );
            // Busy stays set across disarm. The broken thread panics in
            // `Handle::current` and leaves the claim. The fixed thread has
            // already started its replacement when this signal arrives.
            let disarm = release.disarm.take().expect("disarm sender");
            let _ = disarm.send(());
            finished_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("recheck thread did not exit after disarm");
            super::set_force_pool_busy(&slot_for_coord, false);
        });

        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = wall_tx.send(());
        });
        let start = tokio::time::Instant::now();
        let stepped = tokio::select! {
            biased;
            stepped = super::drive_paused(async {
                wake_rx.await.ok();
                let _ = holding_tx.send(());
                let _ = resume_rx.recv();
                let origin = tokio::time::Instant::now();
                std::future::poll_fn(|_cx| {
                    if tokio::time::Instant::now() > origin {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
                Ok::<(), anyhow::Error>(())
            }) => stepped,
            _ = wall_rx => bail!("idle step stalled while the pool stayed busy across disarm"),
        };
        coord.join().expect("recheck coordinator");
        stepped?;
        ensure!(
            tokio::time::Instant::now() > start,
            "re-arm did not step virtual time"
        );
        ensure!(
            !sleeper.is_finished(),
            "the 30 s timer fired inside the wall bound"
        );
        Ok(())
    })
}

/// #1245: a recheck that has already decided the pool is idle can still be
/// running when the barrier ends. Its `ready` store must not complete the
/// next barrier's idle pulse.
#[test]
#[cfg(tokio_unstable)]
fn w3h_recheck_ready_stays_on_its_barrier_epoch() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let slot = super::idle_slot();
        let slot_for_coord = std::sync::Arc::clone(&slot);
        super::set_force_pool_busy(&slot, true);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        super::install_before_publish_gate(entered_tx, release_rx);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        super::install_recheck_finished(finished_tx);
        let (end_tx, end_rx) = tokio::sync::oneshot::channel::<()>();
        let (parked_again_tx, parked_again_rx) = std::sync::mpsc::channel::<()>();

        let coord = std::thread::spawn(move || {
            struct Release {
                end: Option<tokio::sync::oneshot::Sender<()>>,
                publish: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    if let Some(end) = self.end.take() {
                        let _ = end.send(());
                    }
                    if let Some(publish) = self.publish.take() {
                        let _ = publish.send(());
                    }
                }
            }
            let mut release = Release {
                end: Some(end_tx),
                publish: Some(release_tx),
            };
            let order = std::sync::atomic::Ordering::Acquire;
            wait_until_idle(
                &slot_for_coord,
                |slot| {
                    let epoch = slot.epoch.load(order);
                    slot.parked.load(order) && slot.recheck_epoch.load(order) == epoch
                },
                "recheck was not armed while the pool was forced busy",
            );
            let epoch = slot_for_coord.epoch.load(order);
            super::set_force_pool_busy(&slot_for_coord, false);
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("recheck thread did not stop before publish");
            let end = release.end.take().expect("end sender");
            let _ = end.send(());
            wait_until_idle(
                &slot_for_coord,
                |slot| slot.epoch.load(order) != epoch,
                "barrier did not end while the recheck was held",
            );
            parked_again_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("next barrier did not park");
            let publish = release.publish.take().expect("publish sender");
            let _ = publish.send(());
        });

        super::drive_paused(end_rx).await.ok();
        // The next barrier is parked and has cleared `ready`. `parked` is
        // true, so only an epoch check can refuse the late store.
        let order = std::sync::atomic::Ordering::Release;
        slot.parked.store(true, order);
        slot.ready.store(false, order);
        let _ = parked_again_tx.send(());
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("recheck thread did not exit");
        let ready = slot.ready.load(std::sync::atomic::Ordering::Acquire);
        coord.join().expect("recheck coordinator");
        ensure!(
            !ready,
            "a recheck from the previous barrier published ready={ready}"
        );
        Ok(())
    })
}

/// #1245: `parked` stays true from the driver wake until `after_unpark`.
/// A recheck that publishes `ready` in that gap polls the barrier before a
/// task the wake already queued. This case freezes the gap, lets the
/// recheck act, then requires the queued task to have run first.
#[test]
#[cfg(tokio_unstable)]
fn w3h_recheck_does_not_wake_the_barrier_in_the_unpark_gap() -> Result<()> {
    super::block_on_paused(async move {
        let _hold = super::AutoAdvanceHold::acquire();
        let handle = tokio::runtime::Handle::current();
        let slot = super::idle_slot();
        let slot_for_coord = std::sync::Arc::clone(&slot);
        super::set_force_pool_busy(&slot, true);
        let (publish_entered_tx, publish_entered_rx) = std::sync::mpsc::channel();
        let (publish_release_tx, publish_release_rx) = std::sync::mpsc::channel();
        super::install_before_publish_gate(publish_entered_tx, publish_release_rx);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        super::install_recheck_finished(finished_tx);
        let (unpark_entered_tx, unpark_entered_rx) = std::sync::mpsc::channel();
        let (unpark_release_tx, unpark_release_rx) = std::sync::mpsc::channel();

        let daemon_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gap_open = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let barrier_first = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recorded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let daemon_for_coord = std::sync::Arc::clone(&daemon_ran);
        let gap_for_coord = std::sync::Arc::clone(&gap_open);

        let coord = std::thread::spawn(move || {
            struct Release {
                publish: Option<std::sync::mpsc::Sender<()>>,
                unpark: Option<std::sync::mpsc::Sender<()>>,
            }
            impl Drop for Release {
                fn drop(&mut self) {
                    if let Some(publish) = self.publish.take() {
                        let _ = publish.send(());
                    }
                    if let Some(unpark) = self.unpark.take() {
                        let _ = unpark.send(());
                    }
                }
            }
            let mut release = Release {
                publish: Some(publish_release_tx),
                unpark: Some(unpark_release_tx),
            };
            let order = std::sync::atomic::Ordering::Acquire;
            wait_until_idle(
                &slot_for_coord,
                |slot| {
                    let epoch = slot.epoch.load(order);
                    slot.parked.load(order) && slot.recheck_epoch.load(order) == epoch
                },
                "recheck was not armed while the runtime was parked",
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
            if !slot_for_coord.parked.load(order) {
                panic!("runtime left the park before the unpark gap was armed");
            }
            super::install_unpark_gap_gate(&slot_for_coord, unpark_entered_tx, unpark_release_rx);
            let daemon_ran = daemon_for_coord;
            handle.spawn(async move {
                daemon_ran.store(true, std::sync::atomic::Ordering::Release);
            });
            unpark_entered_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("runtime did not stop in the unpark gap");
            super::set_force_pool_busy(&slot_for_coord, false);
            publish_entered_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("recheck did not stop before publish");
            gap_for_coord.store(true, std::sync::atomic::Ordering::Release);
            let publish = release.publish.take().expect("publish sender");
            let _ = publish.send(());
            finished_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("recheck did not finish while the unpark gap was held");
            let unpark = release.unpark.take().expect("unpark sender");
            let _ = unpark.send(());
        });

        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(4));
            let _ = wall_tx.send(());
        });
        let daemon_for_barrier = std::sync::Arc::clone(&daemon_ran);
        let gap_for_barrier = std::sync::Arc::clone(&gap_open);
        let barrier_for_poll = std::sync::Arc::clone(&barrier_first);
        let recorded_for_poll = std::sync::Arc::clone(&recorded);
        let stepped = tokio::select! {
            biased;
            stepped = super::drive_paused(async move {
                std::future::poll_fn(|_cx| {
                    let order = std::sync::atomic::Ordering::Acquire;
                    if gap_for_barrier.load(order)
                        && !recorded_for_poll.swap(true, std::sync::atomic::Ordering::AcqRel)
                        && !daemon_for_barrier.load(order)
                    {
                        barrier_for_poll.store(true, std::sync::atomic::Ordering::Release);
                    }
                    if daemon_for_barrier.load(order) {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
                Ok::<(), anyhow::Error>(())
            }) => stepped,
            _ = wall_rx => bail!("unpark-gap case stalled"),
        };
        let coord_result = coord.join();
        stepped?;
        coord_result.expect("unpark-gap coordinator");
        ensure!(
            !barrier_first.load(std::sync::atomic::Ordering::Acquire),
            "the barrier was polled before the task queued by the wake"
        );
        ensure!(
            daemon_ran.load(std::sync::atomic::Ordering::Acquire),
            "the queued task did not run"
        );
        ensure!(
            !sleeper.is_finished(),
            "the 30 s timer fired inside the wall bound"
        );
        Ok(())
    })
}

/// #1245: `block_on` polls its future every `event_interval` tasks (61).
/// A `spawn_blocking` completion wakes that future, so the poll lands in
/// the middle of a daemon task chain and the chain is cut. With the
/// interval at `u32::MAX` every queued task runs before the future resumes.
#[test]
#[cfg(tokio_unstable)]
fn w3h_spawn_blocking_completion_does_not_resume_block_on_mid_chain() -> Result<()> {
    const CHAIN: u16 = 80;
    super::block_on_paused(async move {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u16>::new()));
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = go_rx.recv();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("blocking task did not start");
        let baseline = super::task_terminations();
        for i in 0..CHAIN {
            let log = std::sync::Arc::clone(&log);
            let go = if i == 0 { Some(go_tx.clone()) } else { None };
            tokio::spawn(async move {
                if let Some(go) = go {
                    let _ = go.send(());
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                    while super::task_terminations() == baseline {
                        if std::time::Instant::now() > deadline {
                            panic!("blocking task did not terminate before the chain continued");
                        }
                        std::thread::yield_now();
                    }
                }
                log.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(i);
            });
        }
        drop(go_tx);
        let (wall_tx, wall_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(4));
            let _ = wall_tx.send(());
        });
        let log_for_end = std::sync::Arc::clone(&log);
        tokio::select! {
            biased;
            result = async move {
                blocker.await.expect("blocking task");
                log_for_end
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(CHAIN);
                Ok::<(), anyhow::Error>(())
            } => result,
            _ = wall_rx => bail!("spawn_blocking chain stalled"),
        }?;
        let log = log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        ensure!(
            log.len() == usize::from(CHAIN) + 1 && log.last() == Some(&CHAIN),
            "block_on resumed before the ready chain finished: {log:?}"
        );
        Ok(())
    })
}

/// #1245: without `tokio_unstable` a barrier lets paused tokio auto-advance.
/// That advance freezes while `spawn_blocking` runs, so a 50 ms timer must
/// not fire during the pool task and must fire once the pool is idle.
#[test]
#[cfg(not(tokio_unstable))]
fn w3h_auto_advance_freezes_while_spawn_blocking_runs() -> Result<()> {
    super::block_on_paused(async move {
        let start = tokio::time::Instant::now();
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        // Same open path as `Sim::within`: shut the gate, then
        // `run_open_barrier` while it is open.
        let gate = super::shut_clock_gate();
        gate.open().await;
        super::run_open_barrier(async {
            tokio::task::spawn_blocking(|| {
                std::thread::sleep(std::time::Duration::from_millis(80));
            })
            .await
            .expect("blocking task");
            ensure!(
                tokio::time::Instant::now() == start,
                "virtual time moved during spawn_blocking"
            );
            ensure!(
                !sleeper.is_finished(),
                "a 50 ms timer fired while a blocking task held the clock"
            );
            Ok(())
        })
        .await?;
        sleeper.await?;
        ensure!(
            tokio::time::Instant::now() >= start + Duration::from_millis(50),
            "auto-advance did not reach the 50 ms timer"
        );
        Ok(())
    })
}

/// #1245: pull-based wall offset tracks a virtual-time jump immediately,
/// without waiting for a 1 ms ticker task to be polled first.
#[test]
fn w3h_wall_offset_tracks_virtual_jump_without_ticker() -> Result<()> {
    super::block_on_paused(async move {
        let origin = tokio::time::Instant::now();
        super::install_virt_clock_for_test(origin);
        // SAFETY: same callback the shim invokes on every clock_gettime.
        let before = unsafe { super::virt_offset_ns() };
        ensure!(
            before < 1_000_000,
            "offset at origin should be ~0 ns, got {before}"
        );
        tokio::time::advance(Duration::from_secs(5)).await;
        let after_runtime = unsafe { super::virt_offset_ns() };
        // Plain OS thread: must enter the owning runtime Handle, not read real time.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // SAFETY: same C ABI callback the shim calls from any thread.
            let _ = tx.send(unsafe { super::virt_offset_ns() });
        });
        let after_os = rx
            .recv()
            .map_err(|_| anyhow::anyhow!("OS-thread callback did not return"))?;
        super::clear_virt_clock_for_test();
        let expected = Duration::from_secs(5).as_nanos() as u64;
        for (label, after) in [("runtime", after_runtime), ("os-thread", after_os)] {
            ensure!(
                after >= expected.saturating_sub(1_000) && after <= expected.saturating_add(1_000),
                "pull offset after 5s jump on {label} should be ~{expected} ns, got {after}"
            );
        }
        Ok(())
    })
}

/// #1245: with the W3-H shim preloaded, `SystemTime::now()` must follow
/// the pull callback after a virtual jump (no separate wall-offset push).
///
/// Declared `#[ignore]`: it needs `LD_PRELOAD=libw3h_shim.so` and cannot
/// honestly pass without it (ADR 0025 §3–4). The W3-H harness job runs it
/// via `nextest --profile w3h-gate --run-ignored all`. A missing shim under
/// that job is a hard failure, never a silent `Ok`.
#[test]
#[ignore = "requires W3-H LD_PRELOAD shim (nextest profile w3h / w3h-gate --run-ignored all)"]
fn w3h_system_time_follows_pull_callback_via_shim() -> Result<()> {
    super::block_on_paused(async move {
        let shim = super::Shim::detect().map_err(|reason| {
            anyhow::anyhow!("W3-H shim required for wall-clock interposition: {reason}")
        })?;
        let origin = tokio::time::Instant::now();
        // Install the pull callback before the baseline so both reads go through the
        // virtual clock (real wall time would make wall_after look like it went
        // backwards after a jump to the 2026-01-01 epoch).
        shim.install_virt_time(origin);
        // Always clear the pull callback, including on early `?` / panic.
        struct ClearVirt(super::Shim);
        impl Drop for ClearVirt {
            fn drop(&mut self) {
                self.0.clear_virt_time();
            }
        }
        let _clear = ClearVirt(shim);
        let wall_before = std::time::SystemTime::now();
        tokio::time::advance(Duration::from_secs(600)).await;
        let wall_after = std::time::SystemTime::now();
        let elapsed = wall_after
            .duration_since(wall_before)
            .map_err(|e| anyhow::anyhow!("SystemTime went backwards: {e}"))?;
        ensure!(
            elapsed >= Duration::from_secs(599) && elapsed <= Duration::from_secs(601),
            "SystemTime::now() after 600s virtual jump should advance ~600s, got {elapsed:?} \
         (registration/interposition failure would leave real wall time)"
        );
        Ok(())
    })
}

/// #1245: one spawned task's `getrandom` stream does not move when a sibling
/// draws. The shim keys the stream by the task's lineage key.
///
/// Declared `#[ignore]`: it needs `LD_PRELOAD=libw3h_shim.so` (ADR 0025
/// §3–4). The W3-H harness runs it via `nextest --profile w3h-gate
/// --run-ignored all`. A missing shim there is a hard failure.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires W3-H LD_PRELOAD shim (nextest profile w3h / w3h-gate --run-ignored all)"]
fn w3h_task_entropy_stream_ignores_sibling_draws() -> Result<()> {
    super::block_on_paused(async move {
        let shim = super::Shim::detect()
            .map_err(|reason| anyhow!("W3-H shim required for per-task entropy: {reason}"))?;
        shim.install_entropy_key();
        struct ClearEntropy(super::Shim);
        impl Drop for ClearEntropy {
            fn drop(&mut self) {
                self.0.clear_entropy_key();
            }
        }
        let _clear = ClearEntropy(shim);

        let sibling = tokio::spawn(async {
            let mut noise = [0u8; 256];
            draw_exact(&mut noise)?;
            Ok::<(), anyhow::Error>(())
        });
        sibling
            .await
            .map_err(|error| anyhow!("sibling task join: {error}"))??;

        tokio::spawn(async {
            let key = super::current_task_entropy_key();
            ensure!(key != 0, "task entropy key 0 is the thread-stream sentinel");

            let fill = shim_test_fill()?;
            let reset = shim_test_reset_key()?;
            let mut expected = [0u8; 16];
            // Drop draws made while resolving this task id. `fill` then samples
            // the fresh stream, and the second reset makes `getrandom` repeat it.
            // SAFETY: `expected` is writable for 16 bytes. `reset` drops only the
            // shim table entry for `key`. The shim does not keep the pointer.
            unsafe { reset(key) };
            unsafe { fill(key, expected.as_mut_ptr().cast(), expected.len()) };
            unsafe { reset(key) };

            let mut got = [0u8; 16];
            draw_exact(&mut got)?;
            ensure!(
                got.as_slice() == expected.as_slice(),
                "task stream diverged from its own seed after a sibling drew \
             (got {got:?} expected {expected:?})"
            );
            Ok::<(), anyhow::Error>(())
        })
        .await
        .map_err(|error| anyhow!("entropy task join: {error}"))??;
        Ok(())
    })
}

/// #1245: a spawn at another source line must not move the key of this
/// spawn site. The process-wide task id still moves. Needs
/// `--cfg tokio_unstable`, which only the W3-H build sets.
#[cfg(tokio_unstable)]
#[test]
fn w3h_lineage_key_ignores_an_unrelated_root_spawn() {
    fn noise() {
        tokio::spawn(async {});
    }
    fn worker() -> (u64, u64) {
        let id = tokio::task::try_id().expect("worker has a task id");
        let bits = super::task_id_bits(id);
        (bits, super::current_task_entropy_key())
    }
    fn spawn_worker() -> tokio::task::JoinHandle<(u64, u64)> {
        tokio::spawn(async { worker() })
    }
    fn once(extra: bool) -> (u64, u64) {
        super::block_on_paused(async move {
            if extra {
                noise();
            }
            spawn_worker().await.expect("worker")
        })
    }

    let (id_extra, key_extra) = once(true);
    let (id_plain, key_plain) = once(false);
    assert_ne!(
        id_extra, id_plain,
        "the extra spawn must move the process-wide task id"
    );
    assert_eq!(
        key_extra, key_plain,
        "lineage key must stay put when another site spawns"
    );
    assert_ne!(key_plain, 0);
    assert_ne!(key_plain, id_plain);
    assert_ne!(key_extra, id_extra);

    let (first, second) = super::block_on_paused(async {
        let first = spawn_worker().await.expect("first");
        let second = spawn_worker().await.expect("second");
        (first.1, second.1)
    });
    assert_ne!(
        first, second,
        "two spawns at one site must not share a stream key"
    );
}

/// #1245: a runtime with no spawn hooks does not record lineage. The miss
/// must fail the case. A silent fallback to the process-wide task id is
/// the instability this key removes.
#[cfg(tokio_unstable)]
#[test]
fn w3h_lineage_miss_fails_the_case() {
    super::lineage::reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        tokio::spawn(async {
            let _ = super::current_task_entropy_key();
        })
        .await
        .expect("worker");
    });
    assert!(
        super::lineage::misses() > 0,
        "an unhooked runtime must count a lineage miss"
    );
    let panicked = std::panic::catch_unwind(super::ensure_lineage_recorded);
    super::lineage::reset();
    let payload = panicked.expect_err("a lineage miss must fail the case");
    let text = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        text.contains("lineage lookup missed"),
        "panic text was {text}"
    );
}

/// #1245: a Tokio blocking task does not run `on_task_spawn`. Its key is
/// still lineage, not the task id, and a second run keeps that key.
#[cfg(tokio_unstable)]
#[test]
fn w3h_lineage_key_of_a_blocking_task_ignores_the_task_id() {
    fn once() -> (u64, u64) {
        super::block_on_paused(async {
            tokio::task::spawn_blocking(|| {
                let id = tokio::task::try_id().expect("blocking task has a task id");
                let bits = super::task_id_bits(id);
                (bits, super::current_task_entropy_key())
            })
            .await
            .expect("blocking task")
        })
    }

    let (id_first, key_first) = once();
    let (id_second, key_second) = once();
    assert_ne!(id_first, id_second, "the task id must move across runtimes");
    assert_ne!(key_first, 0);
    assert_ne!(key_first, id_first);
    assert_ne!(key_second, id_second);
    assert_eq!(
        key_first, key_second,
        "blocking-task lineage key must not follow the task id"
    );
    assert_eq!(super::lineage::misses(), 0);
}

#[cfg(target_os = "linux")]
type ShimTestFill = unsafe extern "C" fn(u64, *mut libc::c_void, usize);
#[cfg(target_os = "linux")]
type ShimTestReset = unsafe extern "C" fn(u64);

#[cfg(target_os = "linux")]
fn shim_test_fill() -> Result<ShimTestFill> {
    shim_fn(c"w3h_shim_test_fill")
}

#[cfg(target_os = "linux")]
fn shim_test_reset_key() -> Result<ShimTestReset> {
    shim_fn(c"w3h_shim_test_reset_key")
}

#[cfg(target_os = "linux")]
fn shim_fn<T>(name: &std::ffi::CStr) -> Result<T> {
    // SAFETY: `dlsym` with RTLD_DEFAULT and a NUL-terminated name has no
    // preconditions. Null means the shim did not export `name`.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    ensure!(
        !symbol.is_null(),
        "shim symbol {} is missing",
        name.to_string_lossy()
    );
    // SAFETY: `symbol` is the shim export the caller named as `T`.
    Ok(unsafe { std::mem::transmute_copy(&symbol) })
}

#[cfg(target_os = "linux")]
fn draw_exact(buf: &mut [u8]) -> Result<()> {
    // SAFETY: `buf` is writable for its length. Flag 0 is a blocking
    // getrandom, which the shim serves in full when it is active.
    let got = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    let len = isize::try_from(buf.len()).map_err(|error| anyhow!("draw length: {error}"))?;
    ensure!(got == len, "getrandom returned {got}, expected {len}");
    Ok(())
}

/// Restores `W3H_SHIM_ACTIVE` on drop so an early `?` / panic cannot leak
/// the env into another test in the same process.
struct W3hShimEnvGuard;
impl W3hShimEnvGuard {
    fn arm() -> Self {
        // SAFETY: test-only env mutation; Drop restores.
        std::env::set_var("W3H_SHIM_ACTIVE", "1");
        Self
    }
}
impl Drop for W3hShimEnvGuard {
    fn drop(&mut self) {
        // SAFETY: paired with [`W3hShimEnvGuard::arm`].
        std::env::remove_var("W3H_SHIM_ACTIVE");
    }
}

/// #1245: with the W3-H shim env set, history `run_blocking` runs inline so
/// a completion cannot reorder other ready tasks via the blocking pool.
#[test]
fn w3h_run_blocking_is_inline_when_shim_env_set() -> Result<()> {
    super::block_on_paused(async move {
        let runtime_tid = std::thread::current().id();
        let _shim_env = W3hShimEnvGuard::arm();
        let blocking_tid = std::sync::Arc::new(std::sync::Mutex::new(None));
        let slot = std::sync::Arc::clone(&blocking_tid);
        let value = crate::history::run_blocking(move || {
            *slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(std::thread::current().id());
            7u32
        })
        .await?;
        ensure!(value == 7);
        let got = blocking_tid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ok_or_else(|| anyhow::anyhow!("run_blocking body did not run"))?;
        ensure!(
            got == runtime_tid,
            "inline blocking must run on the runtime thread"
        );
        Ok(())
    })
}

#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
fn w3h_s1_control_group_invite_join_over_public_api() -> Result<()> {
    super::block_on_paused(async move {
        let sim = Sim::start(
            "w3h_s1_control_group_invite_join_over_public_api",
            0x5100_0001,
            &["A", "B", "C"],
        )
        .await?;
        mesh(&sim, &["A", "B", "C"]).await?;
        let group = create_group(&sim, "A").await?;
        for joiner in ["B", "C"] {
            let link = invite(&sim, "A", &group).await?;
            join(&sim, joiner, &link).await?;
        }
        let want = [
            sim.agent_hex("A")?,
            sim.agent_hex("B")?,
            sim.agent_hex("C")?,
        ];
        sim.until("A lists A, B and C", secs(180), async |s: &Sim| {
            members(s, "A", &group)
                .await
                .is_ok_and(|listed| want.iter().all(|id| listed.contains(id)))
        })
        .await?;
        sim.fabric().mark("checkpoint: membership converged on A");

        // Data-plane delivery: one write on A reaches B and C through the
        // group store (the same store id on every member). Each joiner must
        // first be seated locally (`membership_state == active`, the live
        // fixture's local readiness) and able to open the store, which needs
        // the group key; both are awaited inside named barriers.
        for member in ["B", "C"] {
            sim.until(
                &format!("{member} reports active membership"),
                secs(120),
                async |s: &Sim| {
                    local_membership(s, member, &group).await.as_deref() == Some("active")
                },
            )
            .await?;
        }
        let store = open_store(&sim, "A", &group).await?;
        for member in ["B", "C"] {
            let mut opened = None;
            let mut last = String::new();
            sim.until(
                &format!("{member} opens the group store"),
                secs(60),
                async |s: &Sim| match try_open_store(s, member, &group).await {
                    Ok(id) => {
                        opened = Some(id);
                        true
                    }
                    Err(error) => {
                        last = format!("{error:#}");
                        false
                    }
                },
            )
            .await
            .with_context(|| format!("{member} last store-open error: {last}"))?;
            ensure!(
                opened.as_deref() == Some(store.as_str()),
                "{member} opened a different store id: {opened:?}"
            );
        }
        let (status, put) = sim
            .api(
                "A",
                Method::PUT,
                &format!("/stores/{}/w3h-control", path_segment(&store)),
                Some(json!({"value": BASE64.encode("delivered"), "content_type": "text/plain"})),
            )
            .await?;
        ensure!(status.is_success(), "A put: {status} {put}");
        sim.until("B and C read A's write", secs(120), async |s: &Sim| {
            read_value(s, "B", &store, "w3h-control").await.as_deref() == Some("delivered")
                && read_value(s, "C", &store, "w3h-control").await.as_deref() == Some("delivered")
        })
        .await?;
        sim.fabric()
            .mark("checkpoint: group data delivered to B and C");
        sim.finish().await?;
        Ok(())
    })
}

#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
fn w3h_s1_negative_control_offline_joiner_is_not_admitted() -> Result<()> {
    super::block_on_paused(async move {
        let sim = Sim::start(
            "w3h_s1_negative_control_offline_joiner_is_not_admitted",
            0x5100_0002,
            &["A", "B", "C"],
        )
        .await?;
        mesh(&sim, &["A", "B", "C"]).await?;
        let group = create_group(&sim, "A").await?;
        let link = invite(&sim, "A", &group).await?;
        let c_peer = sim.peer("C")?;
        let offline_at = sim.fabric().now();
        sim.set_online("C", false)?;
        // The join is a valid local attempt: C accepts it and queues the
        // request (the handler's only refusals are local durability/signing).
        join(&sim, "C", &link).await?;
        let c = sim.agent_hex("C")?;
        let what = "A lists C (must not happen)";
        // Only an expired budget with every read completed and successful is
        // "not admitted"; a failed or cut-off read is INFRA.
        let mut seen = Observations::default();
        let waited = sim
            .until(what, secs(60), async |s: &Sim| {
                match seen.observe(members(s, "A", &group)).await {
                    Some(listed) => listed.contains(&c),
                    None => true,
                }
            })
            .await;
        seen.verify(what)?;
        match waited {
            Ok(()) => bail!("an offline joiner was admitted"),
            Err(error) if expired(&error) => {}
            Err(error) => return Err(error),
        }
        // A's view at the frozen instant after the barrier closed.
        let listed = sim
            .at_instant("A members after the barrier", members(&sim, "A", &group))
            .await??;
        ensure!(!listed.contains(&c), "C is listed: {listed:?}");
        // The intended refusal: the transport refused C's attempts (dials or
        // sends) and nothing C wrote after going offline was delivered.
        let refused = sim.fabric().refused_since(&c_peer, offline_at);
        let delivered = sim.fabric().delivered_from_since(&c_peer, offline_at);
        ensure!(
            !refused.is_empty(),
            "C's join produced no transport refusal; the window did not exercise the fault"
        );
        ensure!(
            delivered.is_empty(),
            "{} frames from C were delivered while it was offline",
            delivered.len()
        );
        sim.fabric().mark(format!(
            "checkpoint: C refused {} times, 0 frames delivered",
            refused.len()
        ));
        sim.finish().await?;
        Ok(())
    })
}

/// Streams (by pair and ordinal) whose opener wrote `prefix` first and
/// whose acceptor wrote a reply: (opener, acceptor) peer ids.
fn answered_streams(
    sim: &Sim,
    prefix: u8,
) -> Vec<(crate::network::sim::Key, crate::network::sim::Key)> {
    use crate::network::sim::LaneClass;
    let writes = sim.fabric().writes();
    writes
        .iter()
        .filter(|w| {
            matches!(w.lane.class, LaneClass::Stream(_))
                && w.seq == 0
                && w.bytes.first() == Some(&prefix)
        })
        .filter(|opener| {
            writes.iter().any(|reply| {
                reply.lane.class == opener.lane.class
                    && reply.lane.src == opener.lane.dst
                    && reply.lane.dst == opener.lane.src
                    && !reply.bytes.is_empty()
            })
        })
        .map(|w| (w.lane.src, w.lane.dst))
        .collect()
}

/// Whether `observer` holds `subject`'s network-verified evidence: the
/// pairing capture (unrelated peers) or the relationship store. Both are
/// written only after the evidence verified (`evidence_wire::ingest_hello`).
fn holds_verified_evidence(sim: &Sim, observer: &str, subject: &str) -> Result<bool> {
    let state = sim.state(observer)?;
    let agent = sim.state(subject)?.agent.agent_id();
    let now = crate::dm_capability::now_unix_ms();
    let captured = state
        .agent
        .capability_store
        .evidence_wire
        .get(agent, true, now)
        .is_some();
    let stored = state
        .agent
        .peer_evidence()
        .store()
        .is_some_and(|store| store.usable_agent(agent, now).is_some());
    Ok(captured || stored)
}

/// One EvidenceV1 stream as the fabric recorded it: who opened it, the
/// request and reply frames (each `kind`, u32 length, body), and when the
/// opener read the reply to its FIN.
struct EvidenceStream {
    opener: crate::network::sim::Key,
    acceptor: crate::network::sim::Key,
    opened_at: Duration,
    request: Option<(u8, Vec<u8>)>,
    reply: Option<(u8, Vec<u8>)>,
    reply_fin_read: Option<Duration>,
}

/// Exactly one whole frame (`kind`, u32 length, body), or `None`.
fn one_frame(bytes: &[u8]) -> Option<(u8, Vec<u8>)> {
    let (&kind, rest) = bytes.split_first()?;
    let (len, body) = rest.split_first_chunk::<4>()?;
    (usize::try_from(u32::from_be_bytes(*len)).ok() == Some(body.len()))
        .then(|| (kind, body.to_vec()))
}

/// Every EvidenceV1 stream opened at or after `since`.
fn evidence_streams(sim: &Sim, since: Duration) -> Vec<EvidenceStream> {
    use crate::network::sim::{LaneClass, LaneKey};
    const EVIDENCE_V1: u8 = 0x06;
    let writes = sim.fabric().writes();
    let lane_bytes = |lane: LaneKey| {
        let mut on_lane: Vec<_> = writes.iter().filter(|w| w.lane == lane).collect();
        on_lane.sort_by_key(|w| w.seq);
        on_lane
            .iter()
            .flat_map(|w| w.bytes.iter().copied())
            .collect::<Vec<u8>>()
    };
    writes
        .iter()
        .filter(|w| {
            matches!(w.lane.class, LaneClass::Stream(_))
                && w.seq == 0
                && w.at >= since
                && w.bytes.first() == Some(&EVIDENCE_V1)
        })
        .map(|open| {
            let reverse = LaneKey {
                src: open.lane.dst,
                dst: open.lane.src,
                class: open.lane.class,
            };
            let request = lane_bytes(open.lane);
            EvidenceStream {
                opener: open.lane.src,
                acceptor: open.lane.dst,
                opened_at: open.at,
                request: request.get(1..).and_then(one_frame),
                reply: one_frame(&lane_bytes(reverse)),
                reply_fin_read: sim.fabric().fin_read_at(&reverse),
            }
        })
        .collect()
}

/// The announce digest of `label`'s own certificate pair, if it has a
/// certificate: what an ACK's `have_certificate` must equal for the node to
/// skip its CERTIFICATE follow-up (`mint_hello`).
fn own_certificate_digest(sim: &Sim, label: &str) -> Result<Option<[u8; 32]>> {
    let state = sim.state(label)?;
    let pair = state
        .agent
        .own_cert_pair
        .read()
        .map_err(|_| anyhow!("{label}: certificate pair lock poisoned"))?;
    Ok(pair
        .1
        .is_some()
        .then(|| crate::announce_v3::cert_digest(&pair.0, &pair.1)))
}

/// EvidenceV1 exchanges opened at or after `since` that the INITIATOR
/// completed, as `opener->acceptor …`. Every counted reply is one whole
/// frame that the opener read to its FIN, and the opener's resulting state
/// shows it accepted the reply:
/// - HELLO request, HELLO reply: the opener holds the acceptor's verified
///   evidence, and the acceptor opened no EvidenceV1 stream of its own to
///   the opener (so only the reply can have provided it);
/// - HELLO request, ACK reply whose `have_certificate` (bincode
///   `Option<[u8; 32]>`) differs from the opener's own certificate digest:
///   the opener acted on the decoded ACK by opening a CERTIFICATE exchange
///   to the acceptor afterwards, and that exchange completed too (an empty
///   ACK, read to FIN), which is the opener's only success outcome
///   (`send_certificate_if_missing`).
///
/// An ACK that leaves the opener nothing to send changes no opener state,
/// so it proves nothing about the opener and is not counted.
fn completed_evidence_exchanges(
    sim: &Sim,
    labels: &[&str],
    since: Duration,
) -> Result<Vec<String>> {
    // `evidence_wire.rs` message kinds.
    const HELLO: u8 = 1;
    const CERTIFICATE: u8 = 3;
    const ACK: u8 = 5;
    let mut peers = Vec::new();
    for label in labels {
        peers.push((sim.peer(label)?.0, *label));
    }
    let label_of = |key| peers.iter().find(|(peer, _)| *peer == key).map(|(_, l)| *l);
    let streams = evidence_streams(sim, since);
    let mut done = Vec::new();
    for stream in &streams {
        let (Some(opener), Some(acceptor)) = (label_of(stream.opener), label_of(stream.acceptor))
        else {
            continue;
        };
        let (Some((HELLO, _)), Some((reply_kind, reply)), Some(read_at)) =
            (&stream.request, &stream.reply, stream.reply_fin_read)
        else {
            continue;
        };
        match *reply_kind {
            HELLO => {
                let reverse_stream = streams.iter().any(|other| {
                    other.opener == stream.acceptor && other.acceptor == stream.opener
                });
                if !reverse_stream && holds_verified_evidence(sim, opener, acceptor)? {
                    done.push(format!("{opener}->{acceptor} HELLO/HELLO"));
                }
            }
            ACK => {
                let have = match reply.as_slice() {
                    [0] => None,
                    [1, digest @ ..] => match <[u8; 32]>::try_from(digest) {
                        Ok(digest) => Some(digest),
                        Err(_) => continue,
                    },
                    _ => continue,
                };
                let Some(own) = own_certificate_digest(sim, opener)? else {
                    continue;
                };
                if have == Some(own) {
                    continue;
                }
                let followed = streams.iter().any(|follow| {
                    follow.opener == stream.opener
                        && follow.acceptor == stream.acceptor
                        && follow.opened_at >= read_at
                        && matches!(&follow.request, Some((CERTIFICATE, _)))
                        && matches!(&follow.reply, Some((ACK, body)) if body.is_empty())
                        && follow.reply_fin_read.is_some()
                });
                if followed {
                    done.push(format!(
                        "{opener}->{acceptor} HELLO/ACK then CERTIFICATE/ACK"
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(done)
}

/// S4 control: the peer-evidence hello (`EvidenceV1`) runs over simulated
/// byte streams between relationship peers, and the initiator completes it
/// (see [`completed_evidence_exchanges`]).
///
/// The topology matters (be1a8db CI: two strangers never exchanged any).
/// A Hello is sent only to a relationship peer: an enrolled machine, a
/// stored record or a live relationship (ADR 0089 §6; `begin_hello` refuses
/// when `!related`, `evidence_wire.rs:318`). Here X is O's same-owner
/// device: O enrolls X's machine before X starts, so O sends X a Hello on
/// connect.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
fn w3h_s4_control_evidence_hello_over_sim_streams() -> Result<()> {
    super::block_on_paused(async move {
        let mut sim = Sim::empty(
            "w3h_s4_control_evidence_hello_over_sim_streams",
            0x5400_0001,
            &["O", "X"],
        )?;
        let outcome = evidence_hello_scenario(&mut sim).await;
        sim.conclude(outcome).await
    })
}

async fn evidence_hello_scenario(sim: &mut Sim) -> Result<()> {
    // Before any daemon starts, like the node keys (`Sim::empty`).
    let owner = crate::identity::UserKeypair::generate()?;
    let home = sim.start_owner_device("O", &owner).await?;
    sim.certify_owner_device("O", "X", &owner, &home).await?;
    let mut done = Vec::new();
    let mut failure = None;
    sim.until(
        "an EvidenceV1 exchange between O and X completes",
        secs(60),
        async |s: &Sim| match completed_evidence_exchanges(s, &["O", "X"], Duration::ZERO) {
            Ok(found) => {
                done = found;
                !done.is_empty()
            }
            Err(error) => {
                failure = Some(error);
                true
            }
        },
    )
    .await?;
    if let Some(error) = failure {
        return Err(error.context("INFRA: reading evidence state"));
    }
    sim.fabric().mark(format!(
        "checkpoint: EvidenceV1 completed over sim streams: {}",
        done.join(", ")
    ));
    Ok(())
}

/// S4 control: owner sync (Tier-1, `SyncV1`) runs over simulated byte
/// streams, dialled by the daemons themselves, and delivers the canonical
/// Home pointer: a second same-owner device yields to the owner's Home.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
fn w3h_s4_control_owner_sync_over_sim_streams() -> Result<()> {
    super::block_on_paused(async move {
        let mut sim = Sim::empty(
            "w3h_s4_control_owner_sync_over_sim_streams",
            0x5400_0002,
            &["O", "X"],
        )?;
        let outcome = owner_sync_scenario(&mut sim).await;
        sim.conclude(outcome).await
    })
}

async fn owner_sync_scenario(sim: &mut Sim) -> Result<()> {
    const SYNC_V1: u8 = 0x05;
    // Before any daemon starts, like the node keys (`Sim::empty`).
    let owner = crate::identity::UserKeypair::generate()?;
    let home = sim.start_owner_device("O", &owner).await?;
    // Waits for X to report `elsewhere` with O's canonical Home id, which
    // only owner sync can deliver.
    sim.certify_owner_device("O", "X", &owner, &home).await?;
    let synced = answered_streams(sim, SYNC_V1);
    let (o, x) = (sim.peer("O")?.0, sim.peer("X")?.0);
    ensure!(
        synced.iter().any(|pair| *pair == (x, o) || *pair == (o, x)),
        "no answered SyncV1 stream between X and O"
    );
    sim.fabric()
        .mark("checkpoint: X yielded to O's Home via SyncV1 over sim streams");
    Ok(())
}
