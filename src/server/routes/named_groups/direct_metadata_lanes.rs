//! #1238: per-group apply lanes for the shared direct metadata listener.
//!
//! One direct-message subscription carries the named-group metadata events
//! of every group. An apply can wait on the network: a seating `MemberAdded`
//! whose Welcome is staged by reference waits in the Welcome fetch, up to
//! `WELCOME_FETCH_TIMEOUT` (115 s). When the listener awaited each apply
//! inline, that wait held the direct events of every other group.
//!
//! Now the listener only parses an event and routes it to the lane of its
//! group. A lane is a bounded FIFO queue and one worker task. The worker
//! applies the events of its group one at a time, in arrival order, through
//! the same shielded apply as before (#1275). Lanes of different groups
//! apply at the same time, as the per-group metadata topic listeners
//! already do.
//!
//! # Locks and ADR 0066
//!
//! A lane takes no group lock. The per-group membership lock and the
//! ADR 0066 epoch re-check stay inside the apply, unchanged. The listener
//! and the workers never wait while they hold the membership lock, the
//! `named_groups` lock or the lane registry lock. The registry is a std
//! mutex: no code holds it across an await.
//!
//! # Order
//!
//! Each pending event (queued, or in apply) holds a reservation on its lane
//! for the group spellings it carries: the raw `group_id` of the event and,
//! when that names a local group, the map key, the stable id and the MLS
//! id of that group. The listener routes an event to the live lane that
//! holds any of its spellings. An event that names no local group, and
//! matches no lane, goes to the one lane for unknown groups. Thus all
//! pending events that can apply to one group are in one lane, and that
//! lane applies them in arrival order. A new lane for a group starts only
//! when no event of that group is pending, so it cannot overtake an earlier
//! event. This is the order of the inline listener.
//!
//! When nothing of a group is pending, its next event goes to the idle lane
//! that applied its last event, if that lane is still live. This only saves
//! a task start. Events of unknown groups share one lane; their applies
//! normally refuse at once (unknown group).
//!
//! # Bounds (ADR A06)
//!
//! - [`LANE_QUEUE_CAP`] events wait in one lane, plus the one in apply.
//! - [`MAX_LANES`] lanes are live at once. Each lane is one worker task.
//! - A worker whose queue stays empty for [`LANE_IDLE_EXIT`] exits.
//!
//! At a bound the listener applies back-pressure and drops nothing. When a
//! lane queue is full, the listener waits for space in it. When all lane
//! slots are in use, the listener first takes back a lane with nothing
//! pending, at once. If no such lane exists, it waits until one exists.
//! While it waits, new direct messages stay in the bounded subscriber queue
//! of the agent, with its existing drop-oldest policy and counter. A seating
//! or removal event is never dropped by this module. Each wait at a bound
//! adds one to a counter and writes a debug log.
//!
//! The only drop is at shutdown. Shutdown stops the listener and the lanes,
//! and their queued events are not applied. The inline listener lost its
//! unread events in the same way. An apply that has started is shielded and
//! runs to completion (#1275).
//!
//! An apply that does not complete (it panicked) adds one to a counter and
//! writes a warn log. Its lane then applies the next event of its group.
//! The inline listener stopped for every group in that case, so the direct
//! events of all groups were lost until a restart.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::Duration;

use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio_util::sync::CancellationToken;

use super::{
    apply_listener_metadata_event, named_group_metadata_event_group_id,
    named_group_metadata_event_kind, AppState, NamedGroupMetadataEvent,
};
use crate as x0x;
use x0x::identity::AgentId;

/// Events that can wait in one lane, not counting the one in apply.
const LANE_QUEUE_CAP: usize = 32;

/// Lanes (worker tasks) that can be live at once.
const MAX_LANES: usize = 16;

/// A worker whose queue stays empty for this long exits.
const LANE_IDLE_EXIT: Duration = Duration::from_secs(5);

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Applies one event. `false`: the apply did not complete (it panicked, or
/// shutdown refused it).
type ApplyFn<T> = Arc<dyn Fn(T) -> BoxFuture<bool> + Send + Sync>;

/// Starts a worker task. `false`: shutdown refused it, and it was dropped.
type SpawnFn = Arc<dyn Fn(BoxFuture<()>) -> bool + Send + Sync>;

/// The direct-channel named-group metadata listener (spawned once by the
/// server; `rx` is its direct-message subscription). It applies
/// authority-authored commits that are direct-delivered (see
/// `spawn_named_group_event_delivery`), through the same shielded apply
/// (#1275) as the per-group metadata topic listener, one lane per group
/// (#1238, see the module documentation).
///
/// It stops when the subscription closes or shutdown starts.
pub(in crate::server) async fn run_direct_metadata_listener(
    state: Arc<AppState>,
    mut rx: x0x::direct::DirectMessageReceiver,
) {
    let mut lanes = GroupLanes::new(
        LaneLimits::DIRECT_METADATA,
        state.shutdown_started.clone(),
        listener_apply(&state),
        listener_spawn(&state),
    );
    loop {
        let msg = tokio::select! {
            biased;
            () = state.shutdown_started.cancelled() => break,
            msg = rx.recv() => msg,
        };
        let Some(msg) = msg else { break };
        let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload) else {
            continue; // not a named-group metadata event
        };
        tracing::debug!(
            target: "treekem.trace",
            stage = "direct_classified_metadata_event",
            sender = %hex::encode(msg.sender.as_bytes()),
            len = msg.payload.len(),
            verified = msg.verified,
            event = named_group_metadata_event_kind(&event),
        );
        let key = lane_key(&state, named_group_metadata_event_group_id(&event)).await;
        let item = ListenerEvent {
            event,
            sender: msg.sender,
            verified: msg.verified,
        };
        if lanes.dispatch(key, item).await == Dispatched::Stopped {
            break;
        }
    }
}

/// One direct metadata event, as the listener received it.
struct ListenerEvent {
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    verified: bool,
}

/// The apply of the inline listener: shielded (#1275), with no V2 envelope
/// on the direct path. `None` (shutdown refused it, or it panicked) becomes
/// `false`.
fn listener_apply(state: &Arc<AppState>) -> ApplyFn<ListenerEvent> {
    let state = Arc::clone(state);
    Arc::new(move |item: ListenerEvent| {
        let state = Arc::clone(&state);
        Box::pin(async move {
            apply_listener_metadata_event(&state, item.event, item.sender, item.verified, None)
                .await
                .is_some()
        })
    })
}

/// Workers are detached tasks (#1269): the shutdown drain collects them,
/// gives them the server grace and then aborts them. They stop at once when
/// shutdown starts, and an apply in progress is shielded, so the abort
/// cuts no write.
fn listener_spawn(state: &Arc<AppState>) -> SpawnFn {
    let state = Arc::clone(state);
    Arc::new(move |worker: BoxFuture<()>| state.spawn_detached_with_abort(worker).is_some())
}

/// The spellings of `group_id`, resolved as the membership lock resolves
/// them (`group_membership_lock`): the map key, then a stable id or MLS id
/// match.
async fn lane_key(state: &AppState, group_id: &str) -> LaneKey {
    let groups = state.named_groups.read().await;
    let found = groups.get_key_value(group_id).or_else(|| {
        groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == group_id || info.mls_group_id == group_id)
    });
    match found {
        Some((key, info)) => LaneKey::resolved([
            group_id,
            key.as_str(),
            info.stable_group_id(),
            info.mls_group_id.as_str(),
        ]),
        None => LaneKey::unresolved(group_id),
    }
}

/// The spellings that name the group of one event, as resolved when it
/// arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneKey {
    names: BTreeSet<String>,
    /// The event names a local group.
    resolved: bool,
}

impl LaneKey {
    fn resolved<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            names: names.into_iter().map(str::to_string).collect(),
            resolved: true,
        }
    }

    fn unresolved(name: &str) -> Self {
        Self {
            names: BTreeSet::from([name.to_string()]),
            resolved: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaneLimits {
    queue_cap: usize,
    max_lanes: usize,
    idle_exit: Duration,
}

impl LaneLimits {
    const DIRECT_METADATA: Self = Self {
        queue_cap: LANE_QUEUE_CAP,
        max_lanes: MAX_LANES,
        idle_exit: LANE_IDLE_EXIT,
    };
}

/// What [`GroupLanes::dispatch`] did with an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dispatched {
    /// Queued behind the pending events of its group.
    Queued,
    /// Shutdown started, or shutdown refused a new worker. The event is not
    /// applied, and the listener stops.
    Stopped,
}

/// How often lanes met a bound or lost events. Written with a debug or warn
/// log at the same place.
#[derive(Debug, Default)]
struct LaneCounters {
    lanes_started: AtomicU64,
    /// The listener waited for space in a full lane queue.
    queue_full_waits: AtomicU64,
    /// The listener waited for a lane slot: all were busy.
    lane_slot_waits: AtomicU64,
    /// The listener took back a lane with nothing pending for a new group.
    idle_lanes_reclaimed: AtomicU64,
    /// Applies that did not complete (they panicked).
    failed_applies: AtomicU64,
}

/// One live lane in the registry.
struct Lane<T: Send + 'static> {
    tx: mpsc::Sender<LaneItem<T>>,
    /// Events queued in this lane or in its apply.
    pending: usize,
    /// Each spelling that a pending event carries, with its event count.
    names: HashMap<String, usize>,
    /// The lane for events that name no local group.
    unknown_groups: bool,
    /// The spellings of the last event released here (at most four). An
    /// idle lane takes the next event of that group (fewer task starts).
    recent: BTreeSet<String>,
}

impl<T: Send + 'static> Lane<T> {
    fn reserve(&mut self, key: &LaneKey) {
        self.pending = self.pending.saturating_add(1);
        for name in &key.names {
            let count = self.names.entry(name.clone()).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    fn release(&mut self, key: &LaneKey) {
        self.pending = self.pending.saturating_sub(1);
        for name in &key.names {
            if let Some(count) = self.names.get_mut(name) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.names.remove(name);
                }
            }
        }
        self.recent.clone_from(&key.names);
    }

    /// A pending event of this lane carries one of the spellings of `key`.
    fn holds_any(&self, key: &LaneKey) -> bool {
        key.names.iter().any(|name| self.names.contains_key(name))
    }

    /// Nothing is pending, and the last event here was of the group of
    /// `key`.
    fn idle_for(&self, key: &LaneKey) -> bool {
        self.pending == 0 && key.names.iter().any(|name| self.recent.contains(name))
    }
}

struct Registry<T: Send + 'static> {
    /// By lane id: the oldest lane comes first.
    lanes: BTreeMap<u64, Lane<T>>,
    next_lane_id: u64,
}

struct Shared<T: Send + 'static> {
    registry: StdMutex<Registry<T>>,
    /// One permit for each live worker task.
    slots: Arc<Semaphore>,
    /// A lane has nothing pending: the listener can take it back.
    became_idle: Notify,
    counters: LaneCounters,
}

impl<T: Send + 'static> Shared<T> {
    fn registry(&self) -> std::sync::MutexGuard<'_, Registry<T>> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn release(&self, lane_id: u64, key: &LaneKey) {
        let idle = {
            let mut registry = self.registry();
            registry.lanes.get_mut(&lane_id).is_some_and(|lane| {
                lane.release(key);
                lane.pending == 0
            })
        };
        if idle {
            self.became_idle.notify_one();
        }
    }

    /// Reserve a place for `key` in a live lane, in this order of choice:
    /// 1. The lane where a pending event carries one of its spellings (the
    ///    order rule).
    /// 2. For an event of an unknown group: the unknown-groups lane. Its
    ///    pending events can be other spellings of the same group.
    /// 3. An idle lane whose last event was of this group.
    fn reserve_existing(
        self: &Arc<Self>,
        key: &LaneKey,
    ) -> Option<(Reservation<T>, mpsc::Sender<LaneItem<T>>)> {
        let mut registry = self.registry();
        let lanes = &registry.lanes;
        let lane_id = lanes
            .iter()
            .find(|(_, lane)| lane.holds_any(key))
            .or_else(|| {
                (!key.resolved)
                    .then(|| lanes.iter().find(|(_, lane)| lane.unknown_groups))
                    .flatten()
            })
            .or_else(|| lanes.iter().find(|(_, lane)| lane.idle_for(key)))
            .map(|(lane_id, _)| *lane_id)?;
        let lane = registry.lanes.get_mut(&lane_id)?;
        lane.reserve(key);
        let tx = lane.tx.clone();
        drop(registry);
        Some((self.reservation(lane_id, key), tx))
    }

    fn reservation(self: &Arc<Self>, lane_id: u64, key: &LaneKey) -> Reservation<T> {
        Reservation {
            shared: Arc::clone(self),
            lane_id,
            key: Some(key.clone()),
        }
    }

    /// Take a lane out of the registry. The caller drops it after the
    /// registry lock is released: the last sender of a lane can drop queued
    /// items, and each item releases its reservation under that lock.
    fn take_lane(&self, lane_id: u64) -> Option<Lane<T>> {
        self.registry().lanes.remove(&lane_id)
    }

    /// Take back the oldest lane with nothing pending. Its worker sees its
    /// queue close and exits, which frees its slot.
    fn reclaim_idle_lane(&self) -> bool {
        let lane = {
            let mut registry = self.registry();
            let idle = registry
                .lanes
                .iter()
                .find(|(_, lane)| lane.pending == 0)
                .map(|(lane_id, _)| *lane_id);
            idle.and_then(|lane_id| registry.lanes.remove(&lane_id))
        };
        let reclaimed = lane.is_some();
        drop(lane);
        if reclaimed {
            self.counters
                .idle_lanes_reclaimed
                .fetch_add(1, Ordering::Relaxed);
        }
        reclaimed
    }

    /// Retire the lane of an idle worker if nothing is pending in it. `true`
    /// also when the lane is gone already (the listener took it back).
    fn retire_if_idle(&self, lane_id: u64) -> bool {
        let (retire, lane) = {
            let mut registry = self.registry();
            match registry.lanes.get(&lane_id) {
                None => (true, None),
                Some(lane) if lane.pending == 0 => (true, registry.lanes.remove(&lane_id)),
                Some(_) => (false, None),
            }
        };
        drop(lane);
        retire
    }
}

/// A pending event's hold on its lane: one count, and its spellings. It is
/// released when it drops: after the apply, or with an item that is never
/// applied (a failed send, an abort, a stopped lane).
struct Reservation<T: Send + 'static> {
    shared: Arc<Shared<T>>,
    lane_id: u64,
    key: Option<LaneKey>,
}

impl<T: Send + 'static> Drop for Reservation<T> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.shared.release(self.lane_id, &key);
        }
    }
}

struct LaneItem<T: Send + 'static> {
    event: T,
    reservation: Reservation<T>,
}

/// Bounded per-group FIFO lanes. One task (the listener) dispatches; each
/// lane has one worker that applies its events in order.
struct GroupLanes<T: Send + 'static> {
    shared: Arc<Shared<T>>,
    limits: LaneLimits,
    shutdown: CancellationToken,
    apply: ApplyFn<T>,
    spawn: SpawnFn,
}

impl<T: Send + 'static> GroupLanes<T> {
    fn new(
        limits: LaneLimits,
        shutdown: CancellationToken,
        apply: ApplyFn<T>,
        spawn: SpawnFn,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                registry: StdMutex::new(Registry {
                    lanes: BTreeMap::new(),
                    next_lane_id: 0,
                }),
                slots: Arc::new(Semaphore::new(limits.max_lanes.max(1))),
                became_idle: Notify::new(),
                counters: LaneCounters::default(),
            }),
            limits: LaneLimits {
                queue_cap: limits.queue_cap.max(1),
                max_lanes: limits.max_lanes.max(1),
                idle_exit: limits.idle_exit,
            },
            shutdown,
            apply,
            spawn,
        }
    }

    /// Queue `event` behind the pending events of its group. Waits when its
    /// lane queue is full, or when a new lane is needed and every slot is
    /// busy (back-pressure: see the module documentation). `&mut self`: one
    /// dispatcher, so events are routed in arrival order.
    async fn dispatch(&mut self, key: LaneKey, mut event: T) -> Dispatched {
        // A worker stops early only at shutdown, or when its task is
        // aborted. An aborted worker leaves its lane with a closed queue:
        // take that lane out, and try once more with a new lane.
        for _ in 0..2 {
            let Some((reservation, tx)) = self.reserve(&key).await else {
                return Dispatched::Stopped;
            };
            let lane_id = reservation.lane_id;
            let item = match tx.try_send(LaneItem { event, reservation }) {
                Ok(()) => return Dispatched::Queued,
                Err(mpsc::error::TrySendError::Full(item)) => {
                    self.shared
                        .counters
                        .queue_full_waits
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        queue_cap = self.limits.queue_cap,
                        "direct metadata lane is full; the listener waits for space"
                    );
                    item
                }
                Err(mpsc::error::TrySendError::Closed(item)) => {
                    event = item.event;
                    drop(self.shared.take_lane(lane_id));
                    continue;
                }
            };
            let sent = tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return Dispatched::Stopped,
                sent = tx.send(item) => sent,
            };
            match sent {
                Ok(()) => return Dispatched::Queued,
                Err(mpsc::error::SendError(item)) => {
                    event = item.event;
                    drop(self.shared.take_lane(lane_id));
                }
            }
        }
        tracing::warn!(
            "direct metadata lanes closed twice outside shutdown; the listener stops and this \
             event is not applied"
        );
        Dispatched::Stopped
    }

    /// Reserve a place in the lane of `key`, and start a lane when none
    /// holds it. `None`: shutdown.
    async fn reserve(
        &mut self,
        key: &LaneKey,
    ) -> Option<(Reservation<T>, mpsc::Sender<LaneItem<T>>)> {
        let mut reclaimed = false;
        let mut counted = false;
        loop {
            if self.shutdown.is_cancelled() {
                return None;
            }
            if let Some(reserved) = self.shared.reserve_existing(key) {
                return Some(reserved);
            }
            // Only the dispatcher (`&mut self`) starts lanes, so no lane for
            // `key` can start while it waits for a slot below.
            let slot = match Arc::clone(&self.shared.slots).try_acquire_owned() {
                Ok(slot) => slot,
                Err(TryAcquireError::Closed) => return None,
                Err(TryAcquireError::NoPermits) => {
                    // Take back one idle lane at most: its worker exits and
                    // frees its slot at once.
                    if !reclaimed {
                        reclaimed = self.shared.reclaim_idle_lane();
                    }
                    if !reclaimed && !counted {
                        counted = true;
                        self.shared
                            .counters
                            .lane_slot_waits
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            max_lanes = self.limits.max_lanes,
                            "every direct metadata lane is busy; the listener waits for one"
                        );
                    }
                    tokio::select! {
                        biased;
                        () = self.shutdown.cancelled() => return None,
                        slot = Arc::clone(&self.shared.slots).acquire_owned() => match slot {
                            Ok(slot) => slot,
                            Err(_) => return None,
                        },
                        // A lane went idle: take it back on the next pass.
                        () = self.shared.became_idle.notified(), if !reclaimed => continue,
                    }
                }
            };
            return self.start_lane(key, slot);
        }
    }

    fn start_lane(
        &self,
        key: &LaneKey,
        slot: OwnedSemaphorePermit,
    ) -> Option<(Reservation<T>, mpsc::Sender<LaneItem<T>>)> {
        let (tx, rx) = mpsc::channel(self.limits.queue_cap);
        let lane_id = {
            let mut registry = self.shared.registry();
            let lane_id = registry.next_lane_id;
            registry.next_lane_id = registry.next_lane_id.wrapping_add(1);
            let mut lane = Lane {
                tx: tx.clone(),
                pending: 0,
                names: HashMap::new(),
                unknown_groups: !key.resolved,
                recent: BTreeSet::new(),
            };
            lane.reserve(key);
            registry.lanes.insert(lane_id, lane);
            lane_id
        };
        let reservation = self.shared.reservation(lane_id, key);
        let worker = run_lane(
            Arc::clone(&self.shared),
            lane_id,
            rx,
            Arc::clone(&self.apply),
            self.shutdown.clone(),
            self.limits.idle_exit,
            slot,
        );
        if !(self.spawn)(Box::pin(worker)) {
            // Shutdown refused the worker; the dropped worker freed its slot.
            drop(reservation);
            drop(self.shared.take_lane(lane_id));
            return None;
        }
        self.shared
            .counters
            .lanes_started
            .fetch_add(1, Ordering::Relaxed);
        Some((reservation, tx))
    }

    /// A read-only view of the lanes for tests, usable while another task
    /// owns the dispatcher.
    #[cfg(test)]
    fn watch(&self) -> LanesWatch<T> {
        LanesWatch {
            shared: Arc::clone(&self.shared),
        }
    }
}

#[cfg(test)]
struct LanesWatch<T: Send + 'static> {
    shared: Arc<Shared<T>>,
}

#[cfg(test)]
impl<T: Send + 'static> LanesWatch<T> {
    fn live_lanes(&self) -> usize {
        self.shared.registry().lanes.len()
    }

    fn free_slots(&self) -> usize {
        self.shared.slots.available_permits()
    }

    fn counter(&self, pick: fn(&LaneCounters) -> &AtomicU64) -> u64 {
        pick(&self.shared.counters).load(Ordering::Relaxed)
    }
}

/// The worker of one lane: apply its events one at a time, in order.
async fn run_lane<T: Send + 'static>(
    shared: Arc<Shared<T>>,
    lane_id: u64,
    mut rx: mpsc::Receiver<LaneItem<T>>,
    apply: ApplyFn<T>,
    shutdown: CancellationToken,
    idle_exit: Duration,
    slot: OwnedSemaphorePermit,
) {
    loop {
        let received = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            received = tokio::time::timeout(idle_exit, rx.recv()) => received,
        };
        let item = match received {
            Ok(Some(item)) => item,
            // The listener took this idle lane back.
            Ok(None) => break,
            Err(_idle) => {
                if shared.retire_if_idle(lane_id) {
                    break;
                }
                continue;
            }
        };
        let LaneItem { event, reservation } = item;
        let completed = tokio::select! {
            biased;
            // Stop waiting. A shielded apply still runs to completion, and
            // the shutdown drain awaits it (#1275).
            () = shutdown.cancelled() => break,
            completed = apply(event) => completed,
        };
        drop(reservation);
        // `false` outside shutdown: the apply panicked. The inline listener
        // stopped for every group here; the lane goes on with the next
        // event of its group.
        if !completed && !shutdown.is_cancelled() {
            shared
                .counters
                .failed_applies
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                "a direct metadata apply did not complete; its lane goes on with the next event"
            );
        }
    }
    // Queued events drop with the lane (shutdown only). Each releases its
    // reservation; the lane is out of the registry first, so that is a
    // no-op.
    drop(shared.take_lane(lane_id));
    drop(rx);
    drop(slot);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How long a test waits for a step that must happen.
    const WAIT: Duration = Duration::from_secs(10);
    /// How long a test watches for a step that must not happen.
    const QUIET: Duration = Duration::from_millis(300);

    const ROOMY: LaneLimits = LaneLimits {
        queue_cap: 8,
        max_lanes: 8,
        idle_exit: Duration::from_secs(60),
    };

    /// One test event. Its apply records its start and end, waits for
    /// `gate` (when set) and then for `delay`, and returns `completes`.
    struct Probe {
        group: &'static str,
        label: String,
        gate: Option<Arc<Semaphore>>,
        delay: Duration,
        completes: bool,
    }

    #[derive(Default)]
    struct Log {
        lines: StdMutex<Vec<String>>,
        in_apply: StdMutex<HashMap<&'static str, usize>>,
        overlaps: AtomicU64,
    }

    impl Log {
        fn push(&self, line: String) {
            self.lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line);
        }

        fn lines(&self) -> Vec<String> {
            self.lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn has(&self, line: &str) -> bool {
            self.lines().iter().any(|l| l == line)
        }

        async fn wait_for(&self, line: &str) -> bool {
            let deadline = tokio::time::Instant::now() + WAIT;
            while !self.has(line) {
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            true
        }

        fn enter(&self, group: &'static str) {
            let mut in_apply = self.in_apply.lock().unwrap_or_else(PoisonError::into_inner);
            let count = in_apply.entry(group).or_insert(0);
            *count += 1;
            if *count > 1 {
                self.overlaps.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn leave(&self, group: &'static str) {
            let mut in_apply = self.in_apply.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = in_apply.get_mut(group) {
                *count = count.saturating_sub(1);
            }
        }
    }

    fn probe_apply(log: &Arc<Log>) -> ApplyFn<Probe> {
        let log = Arc::clone(log);
        Arc::new(move |probe: Probe| {
            let log = Arc::clone(&log);
            Box::pin(async move {
                log.enter(probe.group);
                log.push(format!("start {}", probe.label));
                if let Some(gate) = &probe.gate {
                    let _ = gate.acquire().await;
                }
                if !probe.delay.is_zero() {
                    tokio::time::sleep(probe.delay).await;
                }
                log.push(format!("end {}", probe.label));
                log.leave(probe.group);
                probe.completes
            })
        })
    }

    fn tokio_spawn() -> SpawnFn {
        Arc::new(|worker: BoxFuture<()>| {
            tokio::spawn(worker);
            true
        })
    }

    struct Rig {
        lanes: GroupLanes<Probe>,
        watch: LanesWatch<Probe>,
        shutdown: CancellationToken,
        log: Arc<Log>,
    }

    fn rig(limits: LaneLimits) -> Rig {
        let log = Arc::new(Log::default());
        let shutdown = CancellationToken::new();
        let lanes = GroupLanes::new(limits, shutdown.clone(), probe_apply(&log), tokio_spawn());
        let watch = lanes.watch();
        Rig {
            lanes,
            watch,
            shutdown,
            log,
        }
    }

    fn gate() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(0))
    }

    fn open(gate: &Semaphore) {
        gate.add_permits(1);
    }

    fn probe(group: &'static str, label: &str) -> Probe {
        Probe {
            group,
            label: label.to_string(),
            gate: None,
            delay: Duration::ZERO,
            completes: true,
        }
    }

    fn gated(group: &'static str, label: &str, gate: &Arc<Semaphore>) -> Probe {
        Probe {
            gate: Some(Arc::clone(gate)),
            ..probe(group, label)
        }
    }

    fn key(group: &str) -> LaneKey {
        LaneKey::resolved([group])
    }

    async fn send(lanes: &mut GroupLanes<Probe>, key: LaneKey, probe: Probe) {
        assert_eq!(lanes.dispatch(key, probe).await, Dispatched::Queued);
    }

    /// Dispatch from another task, because the dispatch can wait. The task
    /// gives the dispatcher back with the result.
    fn send_in_task(
        mut lanes: GroupLanes<Probe>,
        key: LaneKey,
        probe: Probe,
    ) -> tokio::task::JoinHandle<(GroupLanes<Probe>, Dispatched)> {
        tokio::spawn(async move {
            let dispatched = lanes.dispatch(key, probe).await;
            (lanes, dispatched)
        })
    }

    async fn joined(
        task: tokio::task::JoinHandle<(GroupLanes<Probe>, Dispatched)>,
    ) -> (GroupLanes<Probe>, Dispatched) {
        match tokio::time::timeout(WAIT, task).await {
            Ok(Ok(joined)) => joined,
            Ok(Err(e)) => panic!("dispatch task failed: {e}"),
            Err(_) => panic!("dispatch still waits after {WAIT:?}"),
        }
    }

    /// Wait until no lane is live and every slot is free.
    async fn all_lanes_gone(watch: &LanesWatch<Probe>, max_lanes: usize) -> bool {
        let deadline = tokio::time::Instant::now() + WAIT;
        while watch.live_lanes() != 0 || watch.free_slots() != max_lanes {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        true
    }

    fn sequence(labels: &[&str]) -> Vec<String> {
        labels
            .iter()
            .flat_map(|label| [format!("start {label}"), format!("end {label}")])
            .collect()
    }

    #[tokio::test]
    async fn one_group_applies_in_arrival_order_one_at_a_time() {
        let mut r = rig(ROOMY);
        let a1 = gate();
        send(&mut r.lanes, key("a"), gated("a", "a1", &a1)).await;
        send(&mut r.lanes, key("a"), probe("a", "a2")).await;
        send(&mut r.lanes, key("a"), probe("a", "a3")).await;
        assert!(r.log.wait_for("start a1").await);
        tokio::time::sleep(QUIET).await;
        assert!(
            !r.log.has("start a2"),
            "a2 waits for a1: {:?}",
            r.log.lines()
        );
        open(&a1);
        assert!(r.log.wait_for("end a3").await);
        assert_eq!(r.log.lines(), sequence(&["a1", "a2", "a3"]));
        assert_eq!(r.log.overlaps.load(Ordering::SeqCst), 0);
        assert_eq!(r.watch.live_lanes(), 1, "one lane for one group");
    }

    #[tokio::test]
    async fn a_waiting_group_does_not_delay_another_group() {
        let mut r = rig(ROOMY);
        let a1 = gate();
        send(&mut r.lanes, key("a"), gated("a", "a1", &a1)).await;
        assert!(r.log.wait_for("start a1").await);
        send(&mut r.lanes, key("b"), probe("b", "b1")).await;
        assert!(r.log.wait_for("end b1").await, "b1 applies while a1 waits");
        assert!(!r.log.has("end a1"));
        open(&a1);
        assert!(r.log.wait_for("end a1").await);
    }

    #[tokio::test]
    async fn every_spelling_of_a_pending_group_shares_its_lane() {
        let mut r = rig(ROOMY);
        let a1 = gate();
        // A local group with three spellings; its first event is pending.
        let all = LaneKey::resolved(["a-key", "a-stable", "a-mls"]);
        send(&mut r.lanes, all, gated("a", "a1", &a1)).await;
        assert!(r.log.wait_for("start a1").await);
        // The group was dropped locally: its next event does not resolve.
        send(&mut r.lanes, LaneKey::unresolved("a-mls"), probe("a", "a2")).await;
        send(
            &mut r.lanes,
            LaneKey::resolved(["a-stable"]),
            probe("a", "a3"),
        )
        .await;
        tokio::time::sleep(QUIET).await;
        assert!(!r.log.has("start a2") && !r.log.has("start a3"));
        assert_eq!(r.watch.live_lanes(), 1);
        open(&a1);
        assert!(r.log.wait_for("end a3").await);
        assert_eq!(r.log.lines(), sequence(&["a1", "a2", "a3"]));
    }

    #[tokio::test]
    async fn unknown_groups_share_one_lane_that_a_later_resolved_event_joins() {
        let mut r = rig(ROOMY);
        let u1 = gate();
        // Two spellings of a group that is not local yet.
        send(
            &mut r.lanes,
            LaneKey::unresolved("x-mls"),
            gated("x", "u1", &u1),
        )
        .await;
        assert!(r.log.wait_for("start u1").await);
        send(
            &mut r.lanes,
            LaneKey::unresolved("x-stable"),
            probe("x", "u2"),
        )
        .await;
        // The group is local now. Its event joins the lane of the earlier
        // spellings and does not overtake them.
        let all = LaneKey::resolved(["x-key", "x-stable", "x-mls"]);
        send(&mut r.lanes, all, probe("x", "r3")).await;
        // A local group with no pending event gets its own lane.
        send(&mut r.lanes, key("other"), probe("other", "o1")).await;
        assert!(r.log.wait_for("end o1").await);
        tokio::time::sleep(QUIET).await;
        assert!(!r.log.has("start u2") && !r.log.has("start r3"));
        assert_eq!(r.watch.live_lanes(), 2);
        open(&u1);
        assert!(r.log.wait_for("end r3").await);
        let x_lines: Vec<String> = r
            .log
            .lines()
            .into_iter()
            .filter(|line| !line.ends_with("o1"))
            .collect();
        assert_eq!(x_lines, sequence(&["u1", "u2", "r3"]));
    }

    #[tokio::test]
    async fn a_full_lane_makes_the_listener_wait_and_drops_nothing() {
        let limits = LaneLimits {
            queue_cap: 2,
            ..ROOMY
        };
        let mut r = rig(limits);
        let a1 = gate();
        send(&mut r.lanes, key("a"), gated("a", "a1", &a1)).await;
        assert!(r.log.wait_for("start a1").await);
        send(&mut r.lanes, key("a"), probe("a", "a2")).await;
        send(&mut r.lanes, key("a"), probe("a", "a3")).await;
        let waiting = send_in_task(r.lanes, key("a"), probe("a", "a4"));
        tokio::time::sleep(QUIET).await;
        assert!(
            !waiting.is_finished(),
            "the third queued event waits for space"
        );
        assert_eq!(r.watch.counter(|c| &c.queue_full_waits), 1);
        open(&a1);
        let (_lanes, dispatched) = joined(waiting).await;
        assert_eq!(dispatched, Dispatched::Queued);
        assert!(r.log.wait_for("end a4").await);
        assert_eq!(r.log.lines(), sequence(&["a1", "a2", "a3", "a4"]));
    }

    #[tokio::test]
    async fn busy_lane_slots_make_a_new_group_wait_for_a_free_one() {
        let limits = LaneLimits {
            max_lanes: 2,
            ..ROOMY
        };
        let mut r = rig(limits);
        let (a1, b1) = (gate(), gate());
        send(&mut r.lanes, key("a"), gated("a", "a1", &a1)).await;
        send(&mut r.lanes, key("b"), gated("b", "b1", &b1)).await;
        assert!(r.log.wait_for("start a1").await && r.log.wait_for("start b1").await);
        let waiting = send_in_task(r.lanes, key("c"), probe("c", "c1"));
        tokio::time::sleep(QUIET).await;
        assert!(!waiting.is_finished(), "a third group waits for a lane");
        assert_eq!(r.watch.counter(|c| &c.lane_slot_waits), 1);
        // a1 ends, so lane a has nothing pending. The listener takes it back
        // at once (not after the 60 s idle exit) and starts lane c.
        open(&a1);
        let (_lanes, dispatched) = joined(waiting).await;
        assert_eq!(dispatched, Dispatched::Queued);
        assert!(r.log.wait_for("end c1").await);
        assert!(!r.log.has("end b1"));
        assert_eq!(r.watch.counter(|c| &c.idle_lanes_reclaimed), 1);
        assert!(r.watch.live_lanes() <= 2);
        open(&b1);
        assert!(r.log.wait_for("end b1").await);
    }

    #[tokio::test]
    async fn an_idle_lane_slot_is_taken_back_at_once() {
        let limits = LaneLimits {
            max_lanes: 1,
            ..ROOMY
        };
        let mut r = rig(limits);
        send(&mut r.lanes, key("a"), probe("a", "a1")).await;
        assert!(r.log.wait_for("end a1").await);
        let started = tokio::time::Instant::now();
        send(&mut r.lanes, key("b"), probe("b", "b1")).await;
        assert!(r.log.wait_for("end b1").await);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(r.watch.counter(|c| &c.idle_lanes_reclaimed), 1);
        assert_eq!(r.watch.live_lanes(), 1);
    }

    #[tokio::test]
    async fn an_idle_lane_takes_the_next_event_of_its_group() {
        let mut r = rig(ROOMY);
        send(&mut r.lanes, key("a"), probe("a", "a1")).await;
        assert!(r.log.wait_for("end a1").await);
        send(&mut r.lanes, key("a"), probe("a", "a2")).await;
        assert!(r.log.wait_for("end a2").await);
        assert_eq!(r.watch.counter(|c| &c.lanes_started), 1, "no new task");
        send(&mut r.lanes, key("b"), probe("b", "b1")).await;
        assert!(r.log.wait_for("end b1").await);
        assert_eq!(
            r.watch.counter(|c| &c.lanes_started),
            2,
            "another group does not take the idle lane of group a"
        );
    }

    #[tokio::test]
    async fn a_worker_exits_when_its_queue_stays_empty() {
        let limits = LaneLimits {
            idle_exit: Duration::from_millis(100),
            ..ROOMY
        };
        let mut r = rig(limits);
        send(&mut r.lanes, key("a"), probe("a", "a1")).await;
        send(&mut r.lanes, key("b"), probe("b", "b1")).await;
        assert!(r.log.wait_for("end a1").await && r.log.wait_for("end b1").await);
        assert!(all_lanes_gone(&r.watch, limits.max_lanes).await);
        assert_eq!(r.watch.counter(|c| &c.lanes_started), 2);
        // A later event of the same group starts a new lane.
        send(&mut r.lanes, key("a"), probe("a", "a2")).await;
        assert!(r.log.wait_for("end a2").await);
        assert_eq!(r.watch.counter(|c| &c.lanes_started), 3);
    }

    #[tokio::test]
    async fn shutdown_stops_the_listener_and_every_lane() {
        let mut r = rig(ROOMY);
        let a1 = gate();
        send(&mut r.lanes, key("a"), gated("a", "a1", &a1)).await;
        assert!(r.log.wait_for("start a1").await);
        send(&mut r.lanes, key("a"), probe("a", "a2")).await;
        r.shutdown.cancel();
        assert_eq!(
            r.lanes.dispatch(key("b"), probe("b", "b1")).await,
            Dispatched::Stopped
        );
        assert!(all_lanes_gone(&r.watch, ROOMY.max_lanes).await);
        open(&a1);
        tokio::time::sleep(QUIET).await;
        assert!(!r.log.has("start a2") && !r.log.has("start b1"));
        assert_eq!(r.watch.counter(|c| &c.failed_applies), 0);
    }

    #[tokio::test]
    async fn shutdown_ends_a_dispatch_that_waits_for_space() {
        let limits = LaneLimits {
            queue_cap: 1,
            ..ROOMY
        };
        let mut r = rig(limits);
        let a1 = gate();
        send(&mut r.lanes, key("a"), gated("a", "a1", &a1)).await;
        assert!(r.log.wait_for("start a1").await);
        send(&mut r.lanes, key("a"), probe("a", "a2")).await;
        let waiting = send_in_task(r.lanes, key("a"), probe("a", "a3"));
        tokio::time::sleep(QUIET).await;
        assert!(!waiting.is_finished());
        r.shutdown.cancel();
        let (_lanes, dispatched) = joined(waiting).await;
        assert_eq!(dispatched, Dispatched::Stopped);
        assert!(all_lanes_gone(&r.watch, ROOMY.max_lanes).await);
    }

    #[tokio::test]
    async fn a_failed_apply_does_not_stop_its_lane() {
        let mut r = rig(ROOMY);
        let a1 = gate();
        let failing = Probe {
            completes: false,
            ..gated("a", "a1", &a1)
        };
        send(&mut r.lanes, key("a"), failing).await;
        assert!(r.log.wait_for("start a1").await);
        send(&mut r.lanes, key("a"), probe("a", "a2")).await;
        open(&a1);
        assert!(r.log.wait_for("end a2").await, "the lane goes on");
        assert_eq!(r.log.lines(), sequence(&["a1", "a2"]));
        assert_eq!(r.watch.counter(|c| &c.failed_applies), 1);
        assert_eq!(r.watch.live_lanes(), 1);
    }

    /// Many groups through few small lanes: every event applies once, each
    /// group in its own arrival order and never two at once, and the lanes
    /// stay within their bounds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_groups_keep_their_order_within_the_bounds() {
        const GROUPS: [&str; 6] = ["g0", "g1", "g2", "g3", "g4", "g5"];
        const EVENTS: usize = 10;
        let limits = LaneLimits {
            queue_cap: 2,
            max_lanes: 3,
            idle_exit: Duration::from_millis(50),
        };
        let mut r = rig(limits);
        for n in 0..EVENTS {
            for (g, group) in GROUPS.iter().enumerate() {
                let delay = Duration::from_millis(((n + g) % 3) as u64);
                let event = Probe {
                    delay,
                    ..probe(group, &format!("{group}-{n}"))
                };
                send(&mut r.lanes, key(group), event).await;
                assert!(r.watch.live_lanes() <= limits.max_lanes);
            }
        }
        let deadline = tokio::time::Instant::now() + WAIT;
        while r
            .log
            .lines()
            .iter()
            .filter(|line| line.starts_with("end "))
            .count()
            < GROUPS.len() * EVENTS
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "every event applies"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for group in GROUPS {
            let ends: Vec<String> = r
                .log
                .lines()
                .into_iter()
                .filter(|line| line.starts_with(&format!("end {group}-")))
                .collect();
            let expected: Vec<String> = (0..EVENTS).map(|n| format!("end {group}-{n}")).collect();
            assert_eq!(ends, expected, "group {group} applies in arrival order");
        }
        assert_eq!(r.log.overlaps.load(Ordering::SeqCst), 0);
        assert!(all_lanes_gone(&r.watch, limits.max_lanes).await);
    }
}
