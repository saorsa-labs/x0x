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
//! `tokio::spawn`. A spawned step of the staged join must enter the scope
//! again.
//!
//! `live_*` and `staging_*` ignore the scope. Every whole-roster encode
//! uses the live map, so the staging slot never reaches disk. No path holds
//! a live guard and a staging guard at the same time; the swap moves a
//! staged entry into the live map and then clears the slot.

use std::collections::HashMap;
use std::future::Future;

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};

tokio::task_local! {
    /// Set while the current task runs a step of a staged re-seat join.
    static RESEAT_SCOPE: ReseatScope;
}

/// The staged re-seat join that the current task runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReseatScope {
    /// The live-map key of the record under re-seat (the group-id hex).
    pub(crate) group_key: String,
}

/// The re-seat scope of the current task, if any.
#[cfg_attr(not(test), allow(dead_code, reason = "#1699 part 2 enters the scope"))]
pub(crate) fn current_reseat_scope() -> Option<ReseatScope> {
    RESEAT_SCOPE.try_with(Clone::clone).ok()
}

/// Whether the current task runs inside a re-seat scope.
pub(crate) fn in_any_reseat_scope() -> bool {
    RESEAT_SCOPE.try_with(|_| ()).is_ok()
}

/// Run `fut` inside the re-seat scope of `group_key`: every
/// [`ScopedGroupMap`] then selects its staging slot for this task.
#[cfg_attr(not(test), allow(dead_code, reason = "#1699 part 2 enters the scope"))]
pub(crate) async fn in_reseat_scope<F: Future>(group_key: impl Into<String>, fut: F) -> F::Output {
    RESEAT_SCOPE
        .scope(
            ReseatScope {
                group_key: group_key.into(),
            },
            fut,
        )
        .await
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
    #[cfg_attr(not(test), allow(dead_code, reason = "#1699 part 2 enters the scope"))]
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
    #[cfg_attr(not(test), allow(dead_code, reason = "#1699 part 2 enters the scope"))]
    pub(crate) async fn live_write(&self) -> RwLockWriteGuard<'_, HashMap<String, V>> {
        self.live.write().await
    }

    /// Read the staging slot, whatever the scope.
    #[cfg_attr(not(test), allow(dead_code, reason = "#1699 part 2 enters the scope"))]
    pub(crate) async fn staging_read(&self) -> RwLockReadGuard<'_, HashMap<String, V>> {
        self.staging.read().await
    }

    /// Write the staging slot, whatever the scope.
    #[cfg_attr(not(test), allow(dead_code, reason = "#1699 part 2 enters the scope"))]
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
        in_reseat_scope("g", async {
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
        let seen = in_reseat_scope("g", async move {
            tokio::spawn(async move { inner.read().await.get("g").copied() })
                .await
                .ok()
                .flatten()
        })
        .await;
        assert_eq!(seen, Some(1));
    }
}
