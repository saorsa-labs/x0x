#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Inert retry-orchestration tests: paused Tokio time, in-memory callbacks,
//! and independently supplied install keys. No child, socket, or file I/O.

use std::future::{ready, Ready};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex, Notify};
use tokio::time::Instant;

#[path = "../src/upgrade/probe_retry.rs"]
mod probe_retry;

use probe_retry::{claim_retry, run_retry_loop, RetryWait};

fn install_key(label: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".planning/upgrade-probe-retry")
        .join(format!(
            "{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ))
}

fn pending_check(
    transaction_id: &str,
    deadline: Instant,
    observed: Arc<Notify>,
) -> impl FnMut() -> Ready<Result<Option<RetryWait>, &'static str>> {
    let transaction_id = transaction_id.to_owned();
    move || {
        observed.notify_one();
        ready(Ok(Some(RetryWait {
            delay: deadline.saturating_duration_since(Instant::now()),
            transaction_id: transaction_id.clone(),
        })))
    }
}

#[test]
fn retry_claim_deduplicates_until_the_original_owner_drops() {
    let install = install_key("dedup");
    let owner = claim_retry(install.clone(), "9.9.9".to_owned()).unwrap();
    assert!(claim_retry(install.clone(), "9.9.9".to_owned()).is_none());
    assert!(
        claim_retry(install.clone(), "9.9.9".to_owned()).is_none(),
        "a rejected duplicate must not remove the existing owner's claim"
    );
    assert!(claim_retry(install.clone(), "9.9.10".to_owned()).is_some());
    assert!(claim_retry(install_key("independent"), "9.9.9".to_owned()).is_some());
    drop(owner);
    assert!(claim_retry(install, "9.9.9".to_owned()).is_some());
}

#[tokio::test(start_paused = true)]
async fn durable_wait_releases_apply_mutex_and_reacquires_it_only_for_the_attempt() {
    let lock = Arc::new(Mutex::new(()));
    let observed = Arc::new(Notify::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let (_notify, mut shutdown) = watch::channel(false);
    let delay = Duration::from_secs(30 * 60);
    let deadline = Instant::now() + delay;
    let worker_lock = Arc::clone(&lock);
    let attempt_lock = Arc::clone(&lock);
    let worker_attempts = Arc::clone(&attempts);
    let check = pending_check("transaction-1", deadline, Arc::clone(&observed));
    let task = tokio::spawn(async move {
        run_retry_loop(&worker_lock, &mut shutdown, check, move || {
            assert!(
                attempt_lock.try_lock().is_err(),
                "the attempt must own the apply mutex"
            );
            worker_attempts.fetch_add(1, Ordering::SeqCst);
            ready(Ok::<_, &'static str>(42))
        })
        .await
    });
    observed.notified().await;
    let during_wait = lock
        .try_lock()
        .expect("durable wait must release the apply mutex");
    tokio::time::advance(delay - Duration::from_millis(1)).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "an elapsed wait must still reacquire the apply mutex"
    );
    drop(during_wait);
    assert_eq!(task.await.unwrap(), Ok(Some(42)));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(lock.try_lock().is_ok());
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_wait_drops_retry_ownership_without_an_attempt() {
    let install = install_key("shutdown");
    let owner = claim_retry(install.clone(), "9.9.9".to_owned()).unwrap();
    let lock = Arc::new(Mutex::new(()));
    let observed = Arc::new(Notify::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let (notify, mut shutdown) = watch::channel(false);
    let check = pending_check(
        "transaction-1",
        Instant::now() + Duration::from_secs(30 * 60),
        Arc::clone(&observed),
    );
    let worker_attempts = Arc::clone(&attempts);
    let task = tokio::spawn(async move {
        let _owner = owner;
        run_retry_loop(&lock, &mut shutdown, check, move || {
            worker_attempts.fetch_add(1, Ordering::SeqCst);
            ready(Ok::<_, &'static str>(42))
        })
        .await
    });
    observed.notified().await;
    assert!(claim_retry(install.clone(), "9.9.9".to_owned()).is_none());
    notify.send(true).unwrap();
    assert_eq!(task.await.unwrap(), Ok(None));
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    assert!(claim_retry(install, "9.9.9".to_owned()).is_some());
}

#[tokio::test(start_paused = true)]
async fn preexisting_shutdown_and_closed_watch_never_start_an_attempt() {
    for initially_stopped in [false, true] {
        let lock = Arc::new(Mutex::new(()));
        let (notify, mut shutdown) = watch::channel(initially_stopped);
        if !initially_stopped {
            drop(notify);
        }
        let attempts = AtomicUsize::new(0);
        let result = run_retry_loop(
            &lock,
            &mut shutdown,
            || {
                ready(Ok::<_, &'static str>(Some(RetryWait {
                    delay: Duration::ZERO,
                    transaction_id: "expired".to_owned(),
                })))
            },
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                ready(Ok::<_, &'static str>(42))
            },
        )
        .await;
        assert_eq!(result, Ok(None));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_while_waiting_for_apply_mutex_cancels_without_waiting_for_unlock() {
    let lock = Arc::new(Mutex::new(()));
    let holder = lock.lock().await;
    let observed = Arc::new(Notify::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let (notify, mut shutdown) = watch::channel(false);
    let check = pending_check("expired", Instant::now(), Arc::clone(&observed));
    let worker_lock = Arc::clone(&lock);
    let worker_attempts = Arc::clone(&attempts);
    let task = tokio::spawn(async move {
        run_retry_loop(&worker_lock, &mut shutdown, check, move || {
            worker_attempts.fetch_add(1, Ordering::SeqCst);
            ready(Ok::<_, &'static str>(42))
        })
        .await
    });
    observed.notified().await;
    tokio::task::yield_now().await;
    notify.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("shutdown must interrupt mutex acquisition");
    assert_eq!(result.unwrap(), Ok(None));
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    drop(holder);
}

struct DroppedAttempt(Arc<AtomicBool>);

impl Drop for DroppedAttempt {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_attempt_drops_the_future_and_releases_apply_mutex() {
    let lock = Arc::new(Mutex::new(()));
    let attempt_started = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let (notify, mut shutdown) = watch::channel(false);
    let worker_lock = Arc::clone(&lock);
    let started_in_attempt = Arc::clone(&attempt_started);
    let dropped_in_attempt = Arc::clone(&dropped);
    let task = tokio::spawn(async move {
        run_retry_loop(
            &worker_lock,
            &mut shutdown,
            || {
                ready(Ok::<_, &'static str>(Some(RetryWait {
                    delay: Duration::ZERO,
                    transaction_id: "expired".to_owned(),
                })))
            },
            move || {
                let started = Arc::clone(&started_in_attempt);
                let dropped = Arc::clone(&dropped_in_attempt);
                async move {
                    let _guard = DroppedAttempt(dropped);
                    started.notify_one();
                    std::future::pending::<Result<usize, &'static str>>().await
                }
            },
        )
        .await
    });
    attempt_started.notified().await;
    assert!(lock.try_lock().is_err());
    notify.send(true).unwrap();
    assert_eq!(task.await.unwrap(), Ok(None));
    assert!(dropped.load(Ordering::SeqCst));
    assert!(lock.try_lock().is_ok());
}

#[tokio::test(start_paused = true)]
async fn expired_pending_retry_runs_immediately_but_no_pending_record_does_not() {
    for pending in [false, true] {
        let lock = Arc::new(Mutex::new(()));
        let (_notify, mut shutdown) = watch::channel(false);
        let attempts = AtomicUsize::new(0);
        let started = Instant::now();
        let result = run_retry_loop(
            &lock,
            &mut shutdown,
            || {
                ready(Ok::<_, &'static str>(pending.then(|| RetryWait {
                    delay: Duration::ZERO,
                    transaction_id: "durable-expired-transaction".to_owned(),
                })))
            },
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                ready(Ok::<_, &'static str>(42))
            },
        )
        .await;
        assert_eq!(result, Ok(pending.then_some(42)));
        assert_eq!(attempts.load(Ordering::SeqCst), usize::from(pending));
        assert!(
            started.elapsed() <= Duration::from_millis(2),
            "an expired durable retry must not receive a new backoff"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn unchanged_expired_transaction_returns_the_staging_error_without_a_hot_loop() {
    let lock = Arc::new(Mutex::new(()));
    let (_notify, mut shutdown) = watch::channel(false);
    let attempts = AtomicUsize::new(0);
    let result = run_retry_loop(
        &lock,
        &mut shutdown,
        || {
            ready(Ok::<_, &'static str>(Some(RetryWait {
                delay: Duration::ZERO,
                transaction_id: "same-durable-transaction".to_owned(),
            })))
        },
        || {
            assert_eq!(
                attempts.fetch_add(1, Ordering::SeqCst),
                0,
                "unchanged transaction must not start a second staging attempt"
            );
            ready(Err::<usize, _>("staging failed before new probe record"))
        },
    )
    .await;
    assert_eq!(result, Err("staging failed before new probe record"));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(lock.try_lock().is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_new_durable_transaction_gets_its_own_retry_wait() {
    let lock = Arc::new(Mutex::new(()));
    let (_notify, mut shutdown) = watch::channel(false);
    let attempts = Arc::new(AtomicUsize::new(0));
    let first_attempt = Arc::new(Notify::new());
    let started = Instant::now();
    let first_due = started + Duration::from_secs(30 * 60);
    let second_due = first_due + Duration::from_secs(60 * 60);
    let check_attempts = Arc::clone(&attempts);
    let apply_attempts = Arc::clone(&attempts);
    let first_in_attempt = Arc::clone(&first_attempt);
    let task = tokio::spawn(async move {
        run_retry_loop(
            &lock,
            &mut shutdown,
            move || {
                let prior_attempts = check_attempts.load(Ordering::SeqCst);
                let deadline = if prior_attempts == 0 {
                    first_due
                } else {
                    second_due
                };
                ready(Ok::<_, &'static str>(Some(RetryWait {
                    delay: deadline.saturating_duration_since(Instant::now()),
                    transaction_id: format!("transaction-{prior_attempts}"),
                })))
            },
            move || {
                let attempt = apply_attempts.fetch_add(1, Ordering::SeqCst);
                assert!(attempt < 2, "no third retry is scheduled");
                if attempt == 0 {
                    assert!(Instant::now() >= first_due);
                    assert!(Instant::now() - first_due <= Duration::from_millis(2));
                    first_in_attempt.notify_one();
                    ready(Err("fresh probe interruption persisted"))
                } else {
                    assert!(Instant::now() >= second_due);
                    assert!(Instant::now() - second_due <= Duration::from_millis(2));
                    ready(Ok(42))
                }
            },
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(30 * 60)).await;
    first_attempt.notified().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(60 * 60 - 1)).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(task.await.unwrap(), Ok(Some(42)));
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}
