#![cfg(test)]

//! Real Agent shutdown with an inert Agent: no network, gossip or daemon.
use super::*;

async fn fixture() -> (
    tempfile::TempDir,
    Agent,
    Arc<peer_evidence::PeerEvidenceStore>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = agent_in(dir.path()).await.unwrap();
    assert!(agent.network.is_none());
    assert!(agent.gossip_runtime.is_none());
    let (store, ready) = install_evidence(&mut agent, dir.path()).unwrap();
    ready.cancel();
    let (entered, entries) = tokio::sync::mpsc::unbounded_channel();
    assert!(store.usable_agent_entered.set(entered).is_ok());
    (dir, agent, store, entries)
}

async fn read(agent: &Agent, lookup: bool, deadline: tokio::time::Instant) -> Result<(), ()> {
    let recipient = identity::AgentId([0x39; 32]);
    if lookup {
        agent
            .peer_evidence()
            .lookup_before(recipient, deadline)
            .await
    } else {
        agent
            .peer_evidence()
            .usable_before(recipient, None, deadline)
            .await
            .map(|_| ())
    }
}

async fn held_read_shutdown(lookup: bool, timeout: bool) {
    let (_dir, agent, store, mut entries) = fixture().await;
    let held = store.hold_state_for_testing();
    let mut caller = Box::pin(read(
        &agent,
        lookup,
        tokio::time::Instant::now() + Duration::from_secs(2),
    ));
    assert!(futures::poll!(&mut caller).is_pending());
    // This signal is sent immediately before the real state.lock(). The
    // blocking closure has started, so abort cannot stop it at this point.
    assert_eq!(entries.recv().await, Some(()));
    if timeout {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2) + Duration::from_millis(1)).await;
        assert_eq!(caller.as_mut().await, Err(()));
        tokio::time::resume();
    }
    drop(caller);

    let mut first = Box::pin(agent.try_shutdown());
    let first_pending = futures::poll!(&mut first).is_pending();
    // Cancellation must leave custody in the runtime, not in this future.
    drop(first);
    let mut second = Box::pin(agent.try_shutdown());
    let second_pending = futures::poll!(&mut second).is_pending();
    drop(held);
    if second_pending {
        second.await.unwrap();
    }
    assert!(
        first_pending,
        "shutdown returned while the store read was held"
    );
    assert!(second_pending, "cancelled shutdown lost the worker handle");
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    // Drain is idempotent and all 16 Lookup permits are returned.
    agent.try_shutdown().await.unwrap();
    let permits: Vec<_> = (0..16)
        .map(|_| {
            agent
                .peer_evidence()
                .wire_limits
                .try_lookup_permit()
                .unwrap()
        })
        .collect();
    assert!(agent
        .peer_evidence()
        .wire_limits
        .try_lookup_permit()
        .is_none());
    drop(permits);
}

#[tokio::test]
async fn held_read_timeout_is_drained_by_agent() {
    held_read_shutdown(false, true).await;
}

#[tokio::test]
async fn held_lookup_timeout_is_drained_by_agent() {
    held_read_shutdown(true, true).await;
}

#[tokio::test]
async fn dropped_read_is_drained_by_agent() {
    held_read_shutdown(false, false).await;
}

#[tokio::test]
async fn dropped_lookup_is_drained_by_agent() {
    held_read_shutdown(true, false).await;
}

// A single blocking thread makes queue occupancy deterministic. All file/key
// setup is complete before occupying it. The blocker is always released before
// asserting a red result, so the test itself cannot leak a blocking worker.
#[test]
fn queued_cancellation_is_drained_by_agent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (_dir, agent, _store, mut entries) = fixture().await;
        let (release, wait) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = wait.recv();
        });
        running.await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut caller = Box::pin(read(&agent, false, deadline));
        let mut lookup = Box::pin(read(&agent, true, deadline));
        assert!(futures::poll!(&mut caller).is_pending());
        assert!(futures::poll!(&mut lookup).is_pending());
        drop(caller);
        drop(lookup);
        let mut shutdown = Box::pin(agent.try_shutdown());
        let pending = futures::poll!(&mut shutdown).is_pending();
        release.send(()).unwrap();
        blocker.await.unwrap();
        if pending {
            shutdown.await.unwrap();
        }
        assert!(pending, "shutdown discarded the cancelled queued handles");
        assert!(entries.try_recv().is_err(), "cancelled queued reads ran");
        assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    });
}

#[tokio::test]
async fn shutdown_closes_racing_read_admission() {
    let (_dir, agent, store, mut entries) = fixture().await;
    let held = store.hold_state_for_testing();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut callers = Vec::new();
    for _ in 0..16 {
        let mut caller = Box::pin(read(&agent, false, deadline));
        assert!(futures::poll!(&mut caller).is_pending());
        callers.push(caller);
    }
    for _ in 0..16 {
        assert_eq!(entries.recv().await, Some(()));
    }
    let mut racing = Box::pin(read(&agent, false, deadline));
    assert!(
        futures::poll!(&mut racing).is_pending(),
        "16-read cap changed"
    );
    let mut shutdown = Box::pin(agent.try_shutdown());
    let pending = futures::poll!(&mut shutdown).is_pending();
    let refused = matches!(futures::poll!(&mut racing), Poll::Ready(Err(())));
    drop(racing);
    drop(callers);
    drop(held);
    if pending {
        shutdown.await.unwrap();
    }
    assert!(pending, "shutdown returned before draining admitted reads");
    assert!(refused, "a waiting admission survived shutdown closure");
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    assert_eq!(read(&agent, false, deadline).await, Err(()));
    assert_eq!(read(&agent, true, deadline).await, Err(()));
    assert!(
        entries.try_recv().is_err(),
        "shutdown admitted another read"
    );
}

#[tokio::test]
async fn agent_shutdown_cancels_pending_async_lookup() {
    let (_dir, agent, _store, _entries) = fixture().await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&entered);
    let wait = Arc::clone(&release);
    assert!(agent
        .peer_evidence()
        .lookup_responder
        .set(Arc::new(move |_| {
            let signal = Arc::clone(&signal);
            let wait = Arc::clone(&wait);
            Box::pin(async move {
                signal.notify_one();
                wait.notified().await;
            })
        }))
        .is_ok());
    let mut caller = Box::pin(read(
        &agent,
        true,
        tokio::time::Instant::now() + Duration::from_secs(2),
    ));
    assert!(futures::poll!(&mut caller).is_pending());
    entered.notified().await;
    // Keep the caller alive. Shutdown, not caller drop/deadline, must cancel
    // the async exchange and join its blocking worker before success.
    agent.try_shutdown().await.unwrap();
    let retained = Arc::strong_count(agent.peer_evidence());
    release.notify_one();
    let result = caller.await;
    assert_eq!(retained, 1, "shutdown left a pending async Lookup worker");
    assert_eq!(result, Err(()));
}

// Hold actual, already-started reads across the entire drain grace. Release
// them before asserting a red result so runtime destruction cannot hang.
async fn bounded_shutdown_with_held_reads(lookup: bool, cancel_shutdown: bool) {
    let (_dir, agent, store, mut entries) = fixture().await;
    let held = store.hold_state_for_testing();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut callers = Vec::new();
    for _ in 0..2 {
        let mut caller = Box::pin(read(&agent, lookup, deadline));
        assert!(futures::poll!(&mut caller).is_pending());
        callers.push(caller);
    }
    for _ in 0..2 {
        assert_eq!(entries.recv().await, Some(()));
    }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2) + Duration::from_millis(1)).await;
    for caller in callers {
        assert_eq!(caller.await, Err(()));
    }

    // A completed tracked task still owns its handle until shutdown reaches
    // the later cleanup steps. Evidence timeout must not skip those steps.
    agent.spawn_tracked(async {});
    tokio::task::yield_now().await;
    assert_eq!(agent.tracked_tasks.lock().unwrap().handles.len(), 1);
    let mut shutdown = Box::pin(agent.try_shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(futures::poll!(&mut shutdown).is_pending());
    if cancel_shutdown {
        drop(shutdown);
        shutdown = Box::pin(agent.try_shutdown());
        assert!(futures::poll!(&mut shutdown).is_pending());
    }
    tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
    // Permit the already-completed tracked-task custody to run after the
    // evidence timer. The extra second is a test watchdog, not another grace.
    let mut bounded = Box::pin(tokio::time::timeout(Duration::from_secs(1), shutdown));
    let result = match futures::poll!(&mut bounded) {
        Poll::Ready(result) => result,
        Poll::Pending => {
            tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
            bounded.await
        }
    };
    let retained = Arc::strong_count(agent.peer_evidence());
    let cleaned = agent.tracked_tasks.lock().unwrap().handles.is_empty();
    let mut repeated = Box::pin(agent.try_shutdown());
    let repeated_result = futures::poll!(&mut repeated);
    drop(repeated);
    let admission_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let refused_read = read(&agent, false, admission_deadline).await;
    let refused_lookup = read(&agent, true, admission_deadline).await;
    drop(held);
    tokio::time::resume();

    // Join the real workers before the assertions, including on current main.
    // Keep driving their executor: a blocking Lookup resumes async code after
    // the synchronous lock returns. A bounded observer does not restart grace.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if agent.try_shutdown().await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        matches!(result, Ok(Err(error::NetworkError::NodeError(ref reason)))
            if reason == "agent shutdown incomplete: 2 peer evidence workers unfinished after the shutdown grace"),
        "held workers must return the existing incomplete-shutdown error: {result:?}"
    );
    assert!(
        matches!(repeated_result, Poll::Ready(Err(error::NetworkError::NodeError(ref reason)))
            if reason == "agent shutdown incomplete: 2 peer evidence workers unfinished after the shutdown grace"),
        "a later shutdown must retain failure without a new grace: {repeated_result:?}"
    );
    assert_eq!(retained, 3, "unfinished worker custody was lost");
    assert!(cleaned, "evidence timeout skipped later shutdown cleanup");
    assert_eq!(refused_read, Err(()));
    assert_eq!(refused_lookup, Err(()));
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    assert!(
        entries.try_recv().is_err(),
        "shutdown admitted another read"
    );
    let permits: Vec<_> = (0..16)
        .map(|_| {
            agent
                .peer_evidence()
                .wire_limits
                .try_lookup_permit()
                .unwrap()
        })
        .collect();
    assert!(agent
        .peer_evidence()
        .wire_limits
        .try_lookup_permit()
        .is_none());
    drop(permits);
}

#[tokio::test]
async fn held_reads_end_shutdown_at_one_grace_and_keep_custody() {
    bounded_shutdown_with_held_reads(false, false).await;
}

#[tokio::test]
async fn held_lookups_end_shutdown_at_one_grace_and_keep_custody() {
    bounded_shutdown_with_held_reads(true, false).await;
}

#[tokio::test]
async fn cancelled_shutdown_keeps_original_read_grace() {
    bounded_shutdown_with_held_reads(false, true).await;
}

#[tokio::test]
async fn cancelled_shutdown_keeps_original_lookup_grace() {
    bounded_shutdown_with_held_reads(true, true).await;
}
