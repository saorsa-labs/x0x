//! `kv:changed` SSE events (#1094).
//!
//! Every KV store the agent opens sends a change notice to one agent-wide
//! channel ([`crate::Agent::subscribe_kv_changes`]): one per local write or
//! delete, and one per merged remote record or delta. This task turns the
//! notices into `kv:changed` events on the daemon broadcast (`GET /events`).
//!
//! Bursts are merged: the first notice opens a window of
//! [`KV_CHANGE_COALESCE`]; at its end the task emits ONE event per store
//! that changed in it, with the set of origins. A sync burst of a hundred
//! records therefore costs one event, not a hundred. An event names the
//! store and the origins only; a client reads the store to see what
//! changed, through its own authorised path.
//!
//! When the task falls behind and the channel drops notices, it emits one
//! `kv:changed` event with `"store_id": null` and `"lagged": true`: the
//! client must re-read every store it shows.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use super::sse::SseEvent;
use super::state::AppState;
use crate::kv::{KvChangeOrigin, KvStoreChanged};

/// The merge window for change notices.
const KV_CHANGE_COALESCE: Duration = Duration::from_millis(200);

/// The SSE event type.
const KV_CHANGED_EVENT: &str = "kv:changed";

/// The stores that changed in one window, with their origins.
type Pending = BTreeMap<String, BTreeSet<KvChangeOrigin>>;

/// Start the forwarder for the daemon's agent.
pub(super) fn spawn(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    let rx = state.agent.subscribe_kv_changes();
    let tx = state.broadcast_tx.clone();
    tokio::spawn(forward(rx, tx, KV_CHANGE_COALESCE))
}

/// Forward notices from `rx` to `tx` as merged `kv:changed` events, until
/// `rx` closes (the agent is gone).
async fn forward(
    mut rx: broadcast::Receiver<KvStoreChanged>,
    tx: broadcast::Sender<SseEvent>,
    window: Duration,
) {
    loop {
        // The first notice opens a window.
        let mut pending = Pending::new();
        let mut lagged = false;
        let mut closed = absorb(rx.recv().await, &mut pending, &mut lagged);
        if closed && pending.is_empty() && !lagged {
            return;
        }
        // Collect until the window ends.
        let deadline = tokio::time::Instant::now() + window;
        while !closed {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Err(_elapsed) => break,
                Ok(received) => closed = absorb(received, &mut pending, &mut lagged),
            }
        }
        if lagged {
            emit(&tx, serde_json::json!({ "store_id": null, "lagged": true }));
        }
        for (store_id, origins) in pending {
            emit(
                &tx,
                serde_json::json!({ "store_id": store_id, "origins": origins }),
            );
        }
        if closed {
            return;
        }
    }
}

/// Add one receive result to the window. Returns whether `rx` is closed.
fn absorb(
    received: Result<KvStoreChanged, RecvError>,
    pending: &mut Pending,
    lagged: &mut bool,
) -> bool {
    match received {
        Ok(change) => {
            pending
                .entry(change.topic)
                .or_default()
                .insert(change.origin);
            false
        }
        Err(RecvError::Lagged(_)) => {
            *lagged = true;
            false
        }
        Err(RecvError::Closed) => true,
    }
}

fn emit(tx: &broadcast::Sender<SseEvent>, data: serde_json::Value) {
    let _ = tx.send(SseEvent {
        event_type: KV_CHANGED_EVENT.to_string(),
        data,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(topic: &str, origin: KvChangeOrigin) -> KvStoreChanged {
        KvStoreChanged {
            topic: topic.to_string(),
            origin,
        }
    }

    /// WHY (#1094): a burst of notices inside one window gives ONE event per
    /// store, with the union of origins, and nothing else.
    #[tokio::test(start_paused = true)]
    async fn issue1094_a_burst_gives_one_event_per_store() {
        let (ntx, nrx) = broadcast::channel(64);
        let (etx, mut erx) = broadcast::channel(64);
        let task = tokio::spawn(forward(nrx, etx, Duration::from_millis(200)));
        for _ in 0..50 {
            ntx.send(notice("store-a", KvChangeOrigin::Remote)).unwrap();
        }
        ntx.send(notice("store-a", KvChangeOrigin::Local)).unwrap();
        ntx.send(notice("store-b", KvChangeOrigin::Local)).unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;

        let a = erx.recv().await.unwrap();
        assert_eq!(a.event_type, "kv:changed");
        assert_eq!(
            a.data,
            serde_json::json!({"store_id": "store-a", "origins": ["local", "remote"]})
        );
        let b = erx.recv().await.unwrap();
        assert_eq!(
            b.data,
            serde_json::json!({"store_id": "store-b", "origins": ["local"]})
        );
        assert!(matches!(
            erx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        // A later change opens a new window and gives a new event.
        ntx.send(notice("store-a", KvChangeOrigin::Remote)).unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let again = erx.recv().await.unwrap();
        assert_eq!(
            again.data,
            serde_json::json!({"store_id": "store-a", "origins": ["remote"]})
        );

        drop(ntx);
        task.await.unwrap();
    }

    /// WHY (#1094): a forwarder that lost notices says so, so a client
    /// re-reads instead of trusting a partial picture.
    #[tokio::test(start_paused = true)]
    async fn issue1094_lost_notices_give_a_lagged_event() {
        let (ntx, nrx) = broadcast::channel(2);
        let (etx, mut erx) = broadcast::channel(64);
        for i in 0..5 {
            ntx.send(notice(&format!("s{i}"), KvChangeOrigin::Remote))
                .unwrap();
        }
        let task = tokio::spawn(forward(nrx, etx, Duration::from_millis(200)));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let first = erx.recv().await.unwrap();
        assert_eq!(
            first.data,
            serde_json::json!({"store_id": null, "lagged": true})
        );
        drop(ntx);
        task.await.unwrap();
    }
}
