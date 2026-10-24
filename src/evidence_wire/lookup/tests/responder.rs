//! #1239: the AWAITED Lookup responder's authority reads must not occupy a
//! Tokio worker. `Context::accept` evaluates `Relations::authorized` on the
//! stream task; its `Relations::shared` policy reads are synchronous
//! std-lock reads a lease deadline cannot interrupt. Keys, files and policy
//! only: no sockets, NetworkNode or daemon.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

const WATCHDOG: Duration = Duration::from_secs(3);

#[tokio::test(flavor = "current_thread")]
async fn held_responder_policy_keeps_the_stream_worker_running_and_fails_closed() {
    let responder = Arc::new(Node::new().await);
    let requester = Node::new().await;
    // An authenticated binding makes `peer()` resolve the requester so the
    // authorization reaches the shared-context policy reads.
    responder.know(&requester).await;
    let runtime = Arc::clone(&responder.relations.runtime);
    let target = AgentId([39; 32]);

    // An OS-thread writer holds the actual responder-policy std RwLock.
    let (release, wait) = std::sync::mpsc::channel();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let active = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&active);
    let policy = Arc::clone(&runtime);
    let holder = std::thread::spawn(move || {
        let held = policy.group_context.write().unwrap();
        flag.store(true, Ordering::SeqCst);
        entered.send(()).unwrap();
        // Release even on main, whose synchronous read blocks the sole
        // Tokio worker. Always clean up before assertions.
        let _ = wait.recv_timeout(WATCHDOG);
        flag.store(false, Ordering::SeqCst);
        drop(held);
    });
    ready.await.unwrap();

    // The awaited responder path (`Context::accept` -> `authorized`)
    // evaluates responder policy with the real `Relations::shared` reads.
    let authorized = responder.relations.authorized(requester.m(), target);
    tokio::pin!(authorized);
    assert!(futures::poll!(&mut authorized).is_pending());
    tokio::time::sleep(Duration::from_millis(25)).await;
    let timer_ran_while_held = active.load(Ordering::SeqCst);
    assert!(
        timer_ran_while_held,
        "responder policy read blocked the sole Tokio worker until the OS watchdog released it"
    );

    // The evaluation finishes once the writer releases; an unrelated
    // requester without a shared group is not authorized.
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Poll::Ready(outcome) = futures::poll!(&mut authorized) {
                return outcome;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("held policy must not keep the evaluation past the watchdog");
    assert!(!outcome, "an unrelated requester must not be authorized");

    // Control: once the policy lock is free again, the same live-roster
    // relationship authorizes the requester.
    let _ = release.send(());
    holder.join().unwrap();
    responder.group(&[responder.a(), requester.a(), target]);
    assert!(
        responder.relations.authorized(requester.m(), target).await,
        "brief policy contention must not lose the live group relationship"
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.shutdown_workers().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(runtime.readers_idle_for_testing());
}
