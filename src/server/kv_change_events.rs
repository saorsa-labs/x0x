//! `kv:changed` and `task:changed` SSE events (#1094).
//!
//! Every KV store and task list the agent opens sends a change notice to an
//! agent-wide channel ([`crate::Agent::subscribe_kv_changes`],
//! [`crate::Agent::subscribe_task_changes`]): one per local mutation and one
//! per merged remote record or delta. One task per channel turns the notices
//! into events on the daemon broadcast (`GET /events`).
//!
//! Bursts are merged: the first notice opens a window of
//! [`CHANGE_COALESCE`]; at its end the task emits ONE event per store (or
//! list) that changed in it, with the set of origins. A sync burst of a
//! hundred records therefore costs one event, not a hundred. An event names
//! the store or list and the origins only; a client reads it to see what
//! changed, through its own authorised path.
//!
//! When a task falls behind and its channel drops notices, it emits one
//! event with a `null` id and `"lagged": true`: the client must re-read
//! every store or list it shows.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use super::sse::SseEvent;
use super::state::AppState;
use crate::crdt::TaskListChanged;
use crate::kv::{KvChangeOrigin, KvStoreChanged};

/// The merge window for change notices.
const CHANGE_COALESCE: Duration = Duration::from_millis(200);

/// A change notice the forwarder can merge.
trait ChangeNotice: Clone + Send + 'static {
    /// The SSE event type.
    const EVENT: &'static str;
    /// The JSON field that names the store or list.
    const ID_FIELD: &'static str;
    /// The topic and the origin.
    fn into_parts(self) -> (String, KvChangeOrigin);
}

impl ChangeNotice for KvStoreChanged {
    const EVENT: &'static str = "kv:changed";
    const ID_FIELD: &'static str = "store_id";
    fn into_parts(self) -> (String, KvChangeOrigin) {
        (self.topic, self.origin)
    }
}

impl ChangeNotice for TaskListChanged {
    const EVENT: &'static str = "task:changed";
    const ID_FIELD: &'static str = "list_id";
    fn into_parts(self) -> (String, KvChangeOrigin) {
        (self.topic, self.origin)
    }
}

/// The topics that changed in one window, with their origins.
type Pending = BTreeMap<String, BTreeSet<KvChangeOrigin>>;

/// Start the forwarders for the daemon's agent.
pub(super) fn spawn(state: Arc<AppState>) -> [tokio::task::JoinHandle<()>; 2] {
    let tx = state.broadcast_tx.clone();
    [
        tokio::spawn(forward(
            state.agent.subscribe_kv_changes(),
            tx.clone(),
            CHANGE_COALESCE,
        )),
        tokio::spawn(forward(
            state.agent.subscribe_task_changes(),
            tx,
            CHANGE_COALESCE,
        )),
    ]
}

/// Forward notices from `rx` to `tx` as merged events, until `rx` closes
/// (the agent is gone).
async fn forward<T: ChangeNotice>(
    mut rx: broadcast::Receiver<T>,
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
            emit_lagged::<T>(&tx);
        }
        for (id, origins) in pending {
            emit_changed::<T>(&tx, id, origins);
        }
        if closed {
            return;
        }
    }
}

/// Add one receive result to the window. Returns whether `rx` is closed.
fn absorb<T: ChangeNotice>(
    received: Result<T, RecvError>,
    pending: &mut Pending,
    lagged: &mut bool,
) -> bool {
    match received {
        Ok(change) => {
            let (topic, origin) = change.into_parts();
            pending.entry(topic).or_default().insert(origin);
            false
        }
        Err(RecvError::Lagged(_)) => {
            *lagged = true;
            false
        }
        Err(RecvError::Closed) => true,
    }
}

/// `{ID_FIELD: id, "origins": [...]}` for one store or list.
fn emit_changed<T: ChangeNotice>(
    tx: &broadcast::Sender<SseEvent>,
    id: String,
    origins: BTreeSet<KvChangeOrigin>,
) {
    send::<T>(
        tx,
        serde_json::json!(id),
        "origins",
        serde_json::json!(origins),
    );
}

/// `{ID_FIELD: null, "lagged": true}`: notices were lost.
fn emit_lagged<T: ChangeNotice>(tx: &broadcast::Sender<SseEvent>) {
    send::<T>(
        tx,
        serde_json::Value::Null,
        "lagged",
        serde_json::json!(true),
    );
}

fn send<T: ChangeNotice>(
    tx: &broadcast::Sender<SseEvent>,
    id: serde_json::Value,
    field: &str,
    value: serde_json::Value,
) {
    let mut data = serde_json::Map::new();
    data.insert(T::ID_FIELD.to_string(), id);
    data.insert(field.to_string(), value);
    let _ = tx.send(SseEvent {
        event_type: T::EVENT.to_string(),
        data: serde_json::Value::Object(data),
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

    /// WHY (#1094 `task:changed`): task-list notices give `task:changed`
    /// events keyed by `list_id`, merged the same way.
    #[tokio::test(start_paused = true)]
    async fn issue1094_task_notices_give_task_changed_events() {
        let (ntx, nrx) = broadcast::channel(16);
        let (etx, mut erx) = broadcast::channel(16);
        let task = tokio::spawn(forward(nrx, etx, Duration::from_millis(200)));
        for origin in [
            KvChangeOrigin::Local,
            KvChangeOrigin::Remote,
            KvChangeOrigin::Local,
        ] {
            ntx.send(TaskListChanged {
                topic: "list-a".to_string(),
                origin,
            })
            .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let event = erx.recv().await.unwrap();
        assert_eq!(event.event_type, "task:changed");
        assert_eq!(
            event.data,
            serde_json::json!({"list_id": "list-a", "origins": ["local", "remote"]})
        );
        assert!(matches!(
            erx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
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
