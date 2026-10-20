//! #1239: background Lookup must not occupy a Tokio executor thread.
//! The Node fixture has keys, files and policy only; no network or daemon.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const WATCHDOG: Duration = Duration::from_secs(3);

struct Held {
    release: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
    active: Arc<AtomicBool>,
}

impl Held {
    async fn new(
        lock: impl FnOnce(tokio::sync::oneshot::Sender<()>, std::sync::mpsc::Receiver<()>, Arc<AtomicBool>)
            + Send
            + 'static,
    ) -> Self {
        let (release, wait) = std::sync::mpsc::channel();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let active = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&active);
        let thread = std::thread::spawn(move || lock(entered, wait, held));
        ready.await.unwrap();
        Self {
            release,
            thread,
            active,
        }
    }

    fn finish(self) {
        let _ = self.release.send(());
        self.thread.join().unwrap();
    }
}

async fn held_store(store: Arc<PeerEvidenceStore>) -> Held {
    Held::new(move |entered, wait, active| {
        let guard = store.hold_state_for_testing();
        active.store(true, Ordering::SeqCst);
        entered.send(()).unwrap();
        // Release even on main, whose synchronous read prevents Tokio timers
        // and the observer from running. Always clean up before assertions.
        let _ = wait.recv_timeout(WATCHDOG);
        active.store(false, Ordering::SeqCst);
        drop(guard);
    })
    .await
}

async fn drain(runtime: &EvidenceRuntime) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.shutdown_workers().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

fn assert_permits_returned(runtime: &EvidenceRuntime) {
    let permits: Vec<_> = (0..16)
        .map(|_| runtime.wire_limits.try_lookup_permit().unwrap())
        .collect();
    assert!(runtime.wire_limits.try_lookup_permit().is_none());
    drop(permits);
}

#[tokio::test(flavor = "current_thread")]
async fn agent_lookup_held_store_leaves_caller_timer_running() {
    let node = Node::new().await;
    let runtime = &node.relations.runtime;
    let store = node.store();
    let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
    assert!(store.usable_agent_entered.set(entered).is_ok());
    let held = held_store(store).await;
    runtime.spawn_agent_lookup(AgentId([39; 32]));
    // The existing hook fires immediately before the real state.lock().
    assert_eq!(entries.recv().await, Some(()));
    tokio::time::sleep(Duration::from_millis(25)).await;
    let timer_ran_while_held = held.active.load(Ordering::SeqCst);
    held.finish();
    drain(runtime).await;
    assert_permits_returned(runtime);
    assert!(
        timer_ran_while_held,
        "background evidence read blocked the sole Tokio worker until the OS watchdog released it"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn raw_lookup_held_policy_leaves_caller_timer_running_and_recovers() {
    let node = Arc::new(Node::new().await);
    let runtime = &node.relations.runtime;
    let target = AgentId([39; 32]);
    node.group(&[node.a(), target]);
    let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
    let (checked, mut checks) = tokio::sync::mpsc::unbounded_channel();
    let weak = Arc::downgrade(&node);
    assert!(runtime
        .lookup_responder
        .set(Arc::new(move |agent| {
            let node = weak.upgrade().unwrap();
            let entered = entered.clone();
            let checked = checked.clone();
            Box::pin(async move {
                entered.send(()).unwrap();
                // Use the actual responder-policy method and its actual std
                // RwLock at the existing in-memory Lookup seam, without sockets.
                let allowed = node.relations.shared(
                    &node.relations.local,
                    &Peer {
                        agent,
                        machine: MachineId([0; 32]),
                        cert: None,
                    },
                );
                checked.send(allowed).unwrap();
            })
        }))
        .is_ok());
    let policy = Arc::clone(runtime);
    let held = Held::new(move |entered, wait, active| {
        let guard = policy.group_context.write().unwrap();
        active.store(true, Ordering::SeqCst);
        entered.send(()).unwrap();
        let _ = wait.recv_timeout(WATCHDOG);
        active.store(false, Ordering::SeqCst);
        drop(guard);
    })
    .await;
    runtime.spawn_lookup(target, MachineId([40; 32]));
    assert_eq!(entries.recv().await, Some(()));
    tokio::time::sleep(Duration::from_millis(25)).await;
    let timer_ran_while_held = held.active.load(Ordering::SeqCst);
    held.finish();
    let allowed = tokio::time::timeout(Duration::from_secs(1), checks.recv())
        .await
        .unwrap();
    drain(runtime).await;
    assert_permits_returned(runtime);
    assert!(timer_ran_while_held, "background responder policy blocked the sole Tokio worker until the OS watchdog released it");
    assert_eq!(
        allowed,
        Some(true),
        "brief policy contention lost the live group relationship"
    );
    assert_eq!(
        runtime.lookup_hints.machines(target),
        vec![MachineId([40; 32])]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn held_background_read_retains_permit_and_shutdown_custody() {
    let node = Node::new().await;
    let runtime = &node.relations.runtime;
    let store = node.store();
    let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
    assert!(store.usable_agent_entered.set(entered).is_ok());
    let held = held_store(store).await;
    runtime.spawn_agent_lookup(AgentId([39; 32]));
    assert_eq!(entries.recv().await, Some(()));
    tokio::time::pause();
    let mut shutdown = Box::pin(runtime.shutdown_workers());
    let initially_pending = futures::poll!(&mut shutdown).is_pending();
    drop(shutdown);
    // Cancelling a drain retains its original grace and worker handle.
    tokio::time::advance(Duration::from_millis(5001)).await;
    let unfinished = runtime.shutdown_workers().await;
    let repeated = runtime.shutdown_workers().await;
    let still_held = held.active.load(Ordering::SeqCst);
    let permits: Vec<_> = (0..16)
        .filter_map(|_| runtime.wire_limits.try_lookup_permit())
        .collect();
    let available = permits.len();
    drop(permits);
    // Closed admission must reject both launchers while the old read lives.
    runtime.spawn_agent_lookup(AgentId([41; 32]));
    runtime.spawn_lookup(AgentId([42; 32]), MachineId([43; 32]));
    tokio::time::resume();
    held.finish();
    drain(runtime).await;
    assert_permits_returned(runtime);
    assert!(
        initially_pending && still_held,
        "shutdown did not observe a running held background read"
    );
    assert_eq!(
        unfinished, 1,
        "shutdown must report the held worker after one grace"
    );
    assert_eq!(
        repeated, 1,
        "repeated shutdown must retain unfinished custody"
    );
    assert_eq!(available, 15, "the held read lost its Lookup reservation");
    assert!(
        entries.try_recv().is_err(),
        "shutdown admitted another read"
    );
    assert_eq!(Arc::strong_count(runtime), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn background_launchers_share_cap_and_shutdown_cancels_async_work() {
    let runtime = Arc::new(EvidenceRuntime::default());
    let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
    assert!(runtime
        .lookup_responder
        .set(Arc::new(move |_| {
            let entered = entered.clone();
            Box::pin(async move {
                entered.send(()).unwrap();
                std::future::pending::<()>().await;
            })
        }))
        .is_ok());
    for i in 0..128 {
        if i % 2 == 0 {
            runtime.spawn_agent_lookup(AgentId([i; 32]));
        } else {
            runtime.spawn_lookup(AgentId([i; 32]), MachineId([40; 32]));
        }
    }
    assert!(runtime.wire_limits.try_lookup_permit().is_none());
    assert_eq!(runtime.evidence_lookup_skipped.load(Ordering::Relaxed), 112);
    tokio::time::timeout(Duration::from_secs(2), async {
        for _ in 0..16 {
            assert_eq!(entries.recv().await, Some(()));
        }
    })
    .await
    .unwrap();
    drain(&runtime).await;
    assert_permits_returned(&runtime);
    assert!(entries.try_recv().is_err(), "skipped work was queued");
    assert_eq!(Arc::strong_count(&runtime), 1);
}

#[test]
fn shutdown_aborts_queued_background_workers_before_their_reads() {
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    executor.block_on(async {
        let runtime = Arc::new(EvidenceRuntime::default());
        let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
        assert!(runtime
            .lookup_responder
            .set(Arc::new(move |_| {
                let entered = entered.clone();
                Box::pin(async move {
                    entered.send(()).unwrap();
                })
            }))
            .is_ok());
        let (release, wait) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = wait.recv_timeout(WATCHDOG);
        });
        running.await.unwrap();
        runtime.spawn_agent_lookup(AgentId([39; 32]));
        runtime.spawn_lookup(AgentId([40; 32]), MachineId([41; 32]));
        let mut shutdown = Box::pin(runtime.shutdown_workers());
        let _ = futures::poll!(&mut shutdown);
        release.send(()).unwrap();
        blocker.await.unwrap();
        drop(shutdown);
        drain(&runtime).await;
        assert_permits_returned(&runtime);
        assert!(
            entries.try_recv().is_err(),
            "shutdown let a queued Lookup execute"
        );
        assert_eq!(Arc::strong_count(&runtime), 1);
    });
}
