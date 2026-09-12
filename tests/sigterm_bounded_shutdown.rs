//! #371: SIGTERM must terminate x0xd within the bounded-shutdown deadline.
//!
//! Why this matters: supervisors (launchd, systemd, the #261/#363
//! transactional upgrade handoff) and this suite's own `DaemonFixture`
//! teardown send SIGTERM and fall through to SIGKILL when the daemon
//! outlives the bound — losing every clean-shutdown guarantee (WAL flush,
//! dhat heap dumps, group-withdraw fan-out). The binary's
//! `SHUTDOWN_EXIT_DEADLINE` watchdog exists to enforce that bound no matter
//! what teardown does.
//!
//! The watchdog must therefore not depend on the async runtime it is
//! supervising. Measured on the old tokio-task watchdog (macOS arm64,
//! `--all-features` build, idle hermetic daemon): once the post-shutdown
//! teardown blocked the `block_on` thread (heap-profiler finalization),
//! **every** tokio timer stopped firing — the watchdog armed but never
//! went off, and SIGTERM→exit took 6.8–8.4 s, past the 5 s contract, with
//! no forced-exit marker. The regression this test pins: any watchdog
//! (or teardown path) that lets the process outlive the bound again fails
//! here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::time::{Duration, Instant};

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

/// x0xd's watchdog deadline (5 s) plus scheduling slack for signal delivery
/// and the 50 ms arm-poll. The old behaviour measured 6.8–8.4 s on the same
/// machine, comfortably past this bound.
const BOUNDED_EXIT_DEADLINE: Duration = Duration::from_secs(6);

/// Why: SIGTERM→process-exit must stay inside the bounded-shutdown deadline
/// even when teardown work after the graceful tail (here: the `--all-features`
/// test binary's heap-profiler finalization, which alone runs ~5 s and freezes
/// all tokio timers) outruns it — because supervisors escalate to SIGKILL and
/// destroy the clean-shutdown guarantees the moment the bound is missed.
#[tokio::test]
async fn sigterm_exits_within_bounded_deadline() {
    let mut d = DaemonFixture::start("sigterm-bound").await;

    let started = Instant::now();
    let status = Command::new("kill")
        .args(["-TERM".to_string(), d.pid().to_string()])
        .status()
        .expect("run kill -TERM");
    assert!(status.success(), "kill -TERM {} failed", d.pid());

    // Poll via try_wait (it reaps the child; kill -0 keeps succeeding on a
    // zombie). Exit must land inside the deadline: the watchdog forces
    // exit(0) at cancel+SHUTDOWN_EXIT_DEADLINE regardless of what teardown
    // is still doing.
    let deadline = tokio::time::Instant::now() + BOUNDED_EXIT_DEADLINE;
    let exited = loop {
        match d.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(e) => panic!("try_wait on daemon: {e}"),
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let elapsed = started.elapsed();
    let status = exited.unwrap_or_else(|| {
        panic!(
            "daemon did not exit within {BOUNDED_EXIT_DEADLINE:?} of SIGTERM \
             ({elapsed:?} elapsed) — bounded-shutdown contract violated (#371)"
        )
    });
    assert!(
        status.success(),
        "daemon exited with {status} after SIGTERM (bounded exit must be clean)"
    );
}
