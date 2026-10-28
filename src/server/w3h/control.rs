//! W3-H S1 controls: the harness itself, before any failure case.
//!
//! - `w3h_clock_gate_*`: virtual time does not move outside a barrier.
//! - `w3h_auto_advance_freezes_*`: without `tokio_unstable`, auto-advance
//!   stays put while `spawn_blocking` runs.
//! - `w3h_recheck_*`: the unstable recheck thread re-arms after a lost park,
//!   including when the pool stays busy across disarm, and does not publish
//!   `ready` into the next barrier.
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
