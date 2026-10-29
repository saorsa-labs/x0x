//! ADR 0109 §3 re-seat scope (#1699).
//!
//! §3 step 2 says the re-seat subject joins into a staging record outside
//! the live map. The live record keeps its marker, its gate and every
//! ADR 0066 refusal until the keyed swap (§3 step 3).
//!
//! [`ScopedGroupMap`] holds two maps with the same key type: the live map
//! and a staging slot. `read`/`write`/`try_read`/`try_write` select the
//! map for the current task. A task that runs inside [`in_reseat_scope`]
//! (the staged join and its inbound steps) uses the staging slot. All other
//! tasks (serving paths, the API, probes, other groups) use the live map.
//! The call sites keep the same `RwLock` guard API.
//!
//! The scope is a tokio task-local, so it does not pass across
//! `tokio::spawn` by itself. The spawn helpers wrap their task with
//! [`inherit_reseat_scope`], and inbound handlers enter the scope through
//! [`ReseatStagings`].
//!
//! `live_*` and `staging_*` ignore the scope. Every whole-roster encode
//! uses the live map, so the staging slot never reaches disk. No path holds
//! a live guard and a staging guard at the same time; the swap moves a
//! staged entry into the live map and then clears the slot.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};

tokio::task_local! {
    /// Set while the current task runs a step of a staged re-seat join.
    static RESEAT_SCOPE: ReseatScope;
}

/// The staged re-seat join that the current task runs.
///
/// The scope selects the staging slot only while its staging is open. The
/// swap and the rollback close it, so a task of the staged join that is
/// still running afterwards uses the live map.
#[derive(Debug, Clone)]
pub(crate) struct ReseatScope {
    /// The live-map key of the record under re-seat (the group-id hex).
    pub(crate) group_key: String,
    open: Arc<AtomicBool>,
}

impl ReseatScope {
    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }
}

/// The open re-seat staging of the current task, if any.
pub(crate) fn current_reseat_scope() -> Option<ReseatScope> {
    RESEAT_SCOPE
        .try_with(Clone::clone)
        .ok()
        .filter(ReseatScope::is_open)
}

/// Whether the current task runs inside an open re-seat staging.
pub(crate) fn in_any_reseat_scope() -> bool {
    RESEAT_SCOPE.try_with(ReseatScope::is_open).unwrap_or(false)
}

/// Run `fut` inside `scope`: while it is open, every [`ScopedGroupMap`]
/// selects its staging slot for this task.
pub(crate) async fn in_reseat_scope<F: Future>(scope: ReseatScope, fut: F) -> F::Output {
    RESEAT_SCOPE.scope(scope, fut).await
}

/// `fut`, run in the open re-seat staging of the task that calls this.
/// Each spawn helper wraps its task with it, so a step that the staged join
/// spawns stays in the scope.
pub(crate) fn inherit_reseat_scope<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let scope = current_reseat_scope();
    async move {
        match scope {
            Some(scope) => RESEAT_SCOPE.scope(scope, fut).await,
            None => fut.await,
        }
    }
}

/// `fut`, run outside any re-seat scope (a closed scope shadows the
/// caller's): for a whole-node worker that a staged join's step can start,
/// which must see every group's live record.
pub(crate) async fn outside_reseat_scope<F: Future>(fut: F) -> F::Output {
    let closed = ReseatScope {
        group_key: String::new(),
        open: Arc::new(AtomicBool::new(false)),
    };
    RESEAT_SCOPE.scope(closed, fut).await
}

/// The open re-seat stagings of this node, by live-map key and by stable
/// group id. An inbound step of a staged join (a join result, a metadata
/// event, a catch-up response) looks its group up here and enters the
/// scope ([`ReseatStagings::run_in_staging_of`]).
#[derive(Debug, Default)]
pub(crate) struct ReseatStagings {
    open: StdMutex<HashMap<String, ReseatScope>>,
}

impl ReseatStagings {
    fn open_map(&self) -> std::sync::MutexGuard<'_, HashMap<String, ReseatScope>> {
        self.open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Open the staging of `group_key` (also found by `stable`), or return
    /// the one that is open.
    pub(crate) fn open(&self, group_key: &str, stable: &str) -> ReseatScope {
        let mut open = self.open_map();
        let scope = open.get(group_key).cloned().unwrap_or_else(|| ReseatScope {
            group_key: group_key.to_string(),
            open: Arc::new(AtomicBool::new(true)),
        });
        open.insert(group_key.to_string(), scope.clone());
        open.insert(stable.to_string(), scope.clone());
        scope
    }

    /// The open staging that `group_id` (a live-map key or a stable id)
    /// names.
    pub(crate) fn scope_for(&self, group_id: &str) -> Option<ReseatScope> {
        self.open_map().get(group_id).cloned()
    }

    /// Close the staging of `group_key`. Returns whether one was open.
    pub(crate) fn close(&self, group_key: &str) -> bool {
        let mut open = self.open_map();
        let mut closed = false;
        open.retain(|_, scope| {
            let same = scope.group_key == group_key;
            if same {
                scope.open.store(false, Ordering::Release);
                closed = true;
            }
            !same
        });
        closed
    }

    /// Run `fut` in the staging that `group_id` names when one is open and
    /// the task is not in a scope yet; otherwise run it as it is.
    pub(crate) async fn run_in_staging_of<F: Future>(&self, group_id: &str, fut: F) -> F::Output {
        match self.scope_for(group_id).filter(|_| !in_any_reseat_scope()) {
            Some(scope) => in_reseat_scope(scope, fut).await,
            None => fut.await,
        }
    }
}

/// A group map with a re-seat staging slot (see the module docs).
#[derive(Debug)]
pub(crate) struct ScopedGroupMap<V> {
    live: RwLock<HashMap<String, V>>,
    staging: RwLock<HashMap<String, V>>,
}

impl<V> Default for ScopedGroupMap<V> {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}

impl<V> ScopedGroupMap<V> {
    /// A map with `live` as its live entries and an empty staging slot.
    pub(crate) fn new(live: HashMap<String, V>) -> Self {
        Self {
            live: RwLock::new(live),
            staging: RwLock::new(HashMap::new()),
        }
    }

    fn selected(&self) -> &RwLock<HashMap<String, V>> {
        if in_any_reseat_scope() {
            &self.staging
        } else {
            &self.live
        }
    }

    /// Read the map that the current task's scope selects.
    pub(crate) async fn read(&self) -> RwLockReadGuard<'_, HashMap<String, V>> {
        self.selected().read().await
    }

    /// Write the map that the current task's scope selects.
    pub(crate) async fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, V>> {
        self.selected().write().await
    }

    /// Try to read the map that the current task's scope selects.
    pub(crate) fn try_read(&self) -> Result<RwLockReadGuard<'_, HashMap<String, V>>, TryLockError> {
        self.selected().try_read()
    }

    /// Try to write the map that the current task's scope selects.
    #[cfg(test)]
    pub(crate) fn try_write(
        &self,
    ) -> Result<RwLockWriteGuard<'_, HashMap<String, V>>, TryLockError> {
        self.selected().try_write()
    }

    /// Read the live map, whatever the scope.
    pub(crate) async fn live_read(&self) -> RwLockReadGuard<'_, HashMap<String, V>> {
        self.live.read().await
    }

    /// Write the live map, whatever the scope.
    pub(crate) async fn live_write(&self) -> RwLockWriteGuard<'_, HashMap<String, V>> {
        self.live.write().await
    }

    /// Read the staging slot, whatever the scope.
    pub(crate) async fn staging_read(&self) -> RwLockReadGuard<'_, HashMap<String, V>> {
        self.staging.read().await
    }

    /// Write the staging slot, whatever the scope.
    pub(crate) async fn staging_write(&self) -> RwLockWriteGuard<'_, HashMap<String, V>> {
        self.staging.write().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> ScopedGroupMap<u32> {
        ScopedGroupMap::new(HashMap::from([("g".to_string(), 1)]))
    }

    #[tokio::test]
    async fn outside_a_scope_the_guards_select_the_live_map() {
        let groups = map();
        assert!(current_reseat_scope().is_none());
        assert_eq!(groups.read().await.get("g"), Some(&1));
        groups.write().await.insert("h".to_string(), 2);
        groups.live_write().await.insert("i".to_string(), 3);
        assert_eq!(groups.live_read().await.len(), 3);
        assert!(groups.staging_read().await.is_empty());
        assert_eq!(groups.try_read().map(|g| g.len()).ok(), Some(3));
    }

    #[tokio::test]
    async fn inside_a_scope_the_guards_select_the_staging_slot() {
        let groups = map();
        let stagings = ReseatStagings::default();
        let scope = stagings.open("g", "stable-g");
        in_reseat_scope(scope, async {
            assert_eq!(
                current_reseat_scope().map(|scope| scope.group_key),
                Some("g".to_string())
            );
            assert!(groups.read().await.get("g").is_none());
            groups.write().await.insert("g".to_string(), 9);
            assert_eq!(groups.read().await.get("g"), Some(&9));
            assert_eq!(groups.live_read().await.get("g"), Some(&1));
            if let Ok(mut staged) = groups.try_write() {
                staged.insert("x".to_string(), 3);
            }
        })
        .await;
        assert_eq!(groups.read().await.get("g"), Some(&1));
        assert_eq!(groups.staging_read().await.get("g"), Some(&9));
        assert_eq!(groups.staging_read().await.len(), 2);
        groups.staging_write().await.clear();
        assert!(groups.staging_read().await.is_empty());
    }

    #[tokio::test]
    async fn a_spawned_task_does_not_inherit_the_scope() {
        let groups = std::sync::Arc::new(map());
        let inner = std::sync::Arc::clone(&groups);
        let scope = ReseatStagings::default().open("g", "stable-g");
        let seen = in_reseat_scope(scope, async move {
            tokio::spawn(async move { inner.read().await.get("g").copied() })
                .await
                .ok()
                .flatten()
        })
        .await;
        assert_eq!(seen, Some(1));
    }

    #[tokio::test]
    async fn a_closed_scope_shadows_the_callers_and_close_falls_back_to_live() {
        let groups = map();
        let stagings = ReseatStagings::default();
        let scope = stagings.open("g", "stable-g");
        assert!(stagings.scope_for("stable-g").is_some());
        in_reseat_scope(scope, async {
            groups.write().await.insert("g".to_string(), 9);
            let seen = outside_reseat_scope(async { groups.read().await.get("g").copied() }).await;
            assert_eq!(seen, Some(1), "a whole-node worker sees the live map");
            assert!(stagings.close("g"));
            assert_eq!(groups.read().await.get("g"), Some(&1), "closed: live again");
        })
        .await;
        assert!(stagings.scope_for("g").is_none());
        assert!(stagings.scope_for("stable-g").is_none());
    }
}
