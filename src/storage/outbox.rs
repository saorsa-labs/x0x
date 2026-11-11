//! #1365 (D18): one generic durable outbox for typed messages.
//!
//! The daemon has several hand-made outboxes. Each one keeps typed
//! obligations per group, writes them to a private sidecar before it
//! sends, retries failed sends on a bounded backoff, and loads the
//! sidecar again at boot. [`Outbox`] holds that shared logic once:
//!
//! - **Commit discipline.** Each change runs under the persistence lock:
//!   snapshot, change a copy, durable write, then commit the copy to
//!   memory. A failure before the rename keeps the old set in memory. A
//!   failure after the rename (#1101) commits the new set, because the
//!   disk already holds it, and still reports the error.
//! - **Caps.** Per-group and per-store count and byte caps. The oldest
//!   entry (smallest `first_seen_ms`) is evicted first.
//! - **Retry.** A failed send keeps the entry, counts the attempt and
//!   schedules the next one from a fixed offset table. Past the end of
//!   the table the last offset repeats: the interval is bounded, the
//!   attempt count is not.
//! - **Restart.** The boot load checks the size guard, the record codec,
//!   the caps and each entry. A file that fails a check is moved aside
//!   and the outbox starts empty (fail-visible, never blocks startup).
//!
//! The record type owns its sidecar codec ([`OutboxRecord::encode`] and
//! [`OutboxRecord::decode`]), so a move onto this type keeps the
//! persisted bytes identical.
//!
//! The type is crate-private. It is a view over storage that the owner
//! keeps (the lock, the map and the path), so a caller can move onto it
//! without a change to how that storage is built.

use std::collections::HashMap;
use std::path::Path;

use tokio::sync::{Mutex, RwLock};

use super::DurableWriteError;

/// Entries grouped by partition (the group id).
pub(crate) type OutboxMap<T> = HashMap<String, Vec<T>>;

/// Count and byte caps for one outbox.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboxCaps {
    /// Max entries in one partition.
    pub(crate) per_partition: usize,
    /// Max summed `byte_size` in one partition.
    pub(crate) per_partition_bytes: usize,
    /// Max entries in the whole store.
    pub(crate) total: usize,
    /// Max summed `byte_size` in the whole store.
    pub(crate) total_bytes: usize,
}

/// One typed obligation that an [`Outbox`] can hold.
pub(crate) trait OutboxRecord: Clone {
    /// Name used in log and error text, for example `"requester offer outbox"`.
    const LABEL: &'static str;
    /// The partition (group id) this entry belongs to.
    fn partition(&self) -> &str;
    /// The entry identity inside its partition.
    fn id(&self) -> &str;
    /// When the entry was first created (eviction order).
    fn first_seen_ms(&self) -> u64;
    /// Accounted size for the byte caps.
    fn byte_size(&self) -> usize;
    /// When the next attempt is due.
    fn next_retry_at_ms(&self) -> u64;
    /// Attempts completed so far.
    fn retry_count(&self) -> u32;
    /// Set the attempt count and the next due time.
    fn set_schedule(&mut self, retry_count: u32, next_retry_at_ms: u64);
    /// Load-time consistency check of one entry. `Err` is the reason.
    fn check(&self) -> Result<(), String>;
    /// Encode the whole store as sidecar bytes.
    fn encode(map: &OutboxMap<Self>) -> Result<Vec<u8>, String>;
    /// Decode sidecar bytes (including any version check).
    fn decode(bytes: &[u8], path: &Path) -> Result<OutboxMap<Self>, String>;
}

/// The result of [`Outbox::settle`].
#[derive(Debug)]
pub(crate) enum Settled {
    /// Durable. Partitions of delivered entries and of dropped entries.
    Committed {
        delivered: Vec<String>,
        dropped: Vec<String>,
    },
    /// The new set is on disk and in memory, but the directory fsync
    /// failed: durability is not confirmed.
    Unconfirmed(DurableWriteError),
    /// The write failed before the rename; memory is the old set again.
    RolledBack(DurableWriteError),
}

/// The retry offset (seconds) after `retry_count` completed attempts.
/// Past the end of `schedule` the last offset repeats.
pub(crate) fn retry_delay_secs(schedule: &[u64], retry_count: u32) -> u64 {
    let idx = (retry_count as usize)
        .saturating_sub(1)
        .min(schedule.len().saturating_sub(1));
    schedule.get(idx).copied().unwrap_or(0)
}

/// Enforce the per-partition and whole-store caps, evicting the OLDEST
/// entries first. Each partition is left sorted by `first_seen_ms`.
pub(crate) fn enforce_caps<T: OutboxRecord>(map: &mut OutboxMap<T>, caps: &OutboxCaps) {
    for list in map.values_mut() {
        list.sort_by_key(T::first_seen_ms);
        while list.len() > caps.per_partition
            || list.iter().map(T::byte_size).sum::<usize>() > caps.per_partition_bytes
        {
            list.remove(0);
            if list.is_empty() {
                break;
            }
        }
    }
    loop {
        let count: usize = map.values().map(Vec::len).sum();
        let bytes: usize = map.values().flatten().map(T::byte_size).sum();
        if count <= caps.total && bytes <= caps.total_bytes {
            break;
        }
        // Evict the single oldest entry store-wide (a linear scan; the
        // store is capped at ~`caps.total` entries).
        let mut oldest: Option<(String, usize, u64)> = None;
        for (partition, list) in map.iter() {
            for (idx, entry) in list.iter().enumerate() {
                let seen = entry.first_seen_ms();
                if oldest.as_ref().is_none_or(|(_, _, best)| seen < *best) {
                    oldest = Some((partition.clone(), idx, seen));
                }
            }
        }
        let Some((partition, idx, _)) = oldest else {
            break;
        };
        if let Some(list) = map.get_mut(&partition) {
            if idx < list.len() {
                list.remove(idx);
            }
        }
    }
    map.retain(|_, list| !list.is_empty());
}

/// Remove `entry` (by partition and id). True if something was removed.
fn remove_entry<T: OutboxRecord>(map: &mut OutboxMap<T>, entry: &T) -> bool {
    let Some(list) = map.get_mut(entry.partition()) else {
        return false;
    };
    let before = list.len();
    list.retain(|o| o.id() != entry.id());
    let after = list.len();
    if after == 0 {
        map.remove(entry.partition());
    }
    before != after
}

/// A durable typed outbox: a view over storage that its owner keeps.
pub(crate) struct Outbox<'a, T> {
    entries: &'a RwLock<OutboxMap<T>>,
    path: &'a Path,
    persist_lock: &'a Mutex<()>,
    caps: OutboxCaps,
}

impl<'a, T: OutboxRecord> Outbox<'a, T> {
    /// A view over the owner's map, sidecar path and persistence lock.
    pub(crate) fn new(
        entries: &'a RwLock<OutboxMap<T>>,
        path: &'a Path,
        persist_lock: &'a Mutex<()>,
        caps: OutboxCaps,
    ) -> Self {
        Self {
            entries,
            path,
            persist_lock,
            caps,
        }
    }

    /// All entries, flattened (test-only view).
    #[cfg(test)]
    pub(crate) async fn snapshot(&self) -> Vec<T> {
        self.entries
            .read()
            .await
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    /// Entries due at `now_ms`, in send order: first attempts ahead of
    /// retries, then oldest due first.
    pub(crate) async fn due(&self, now_ms: u64) -> Vec<T> {
        let mut due: Vec<T> = self
            .entries
            .read()
            .await
            .values()
            .flatten()
            .filter(|o| o.next_retry_at_ms() <= now_ms)
            .cloned()
            .collect();
        due.sort_by_key(|o| (o.retry_count() > 0, o.next_retry_at_ms()));
        due
    }

    /// Make every entry that `matches` due at `now_ms` (#1158: the
    /// recipient's capability advert arrived). Returns whether any entry
    /// matched. In memory only: the persisted schedule is merely later,
    /// which is safe. The retry count is unchanged.
    pub(crate) async fn nudge(&self, now_ms: u64, matches: impl Fn(&T) -> bool) -> bool {
        let mut nudged = false;
        for entry in self.entries.write().await.values_mut().flatten() {
            if matches(entry) {
                let due = entry.next_retry_at_ms().min(now_ms);
                entry.set_schedule(entry.retry_count(), due);
                nudged = true;
            }
        }
        nudged
    }

    /// Insert `entry` (replacing the same partition and id), enforce the
    /// caps and persist. Memory changes only on a durable write, or on a
    /// failure after the rename (then the error is still returned).
    pub(crate) async fn insert(&self, entry: T) -> Result<(), DurableWriteError> {
        let _guard = self.persist_lock.lock().await;
        let mut next = self.entries.read().await.clone();
        let list = next.entry(entry.partition().to_string()).or_default();
        list.retain(|o| o.id() != entry.id());
        list.push(entry);
        enforce_caps(&mut next, &self.caps);
        self.persist_then_commit(next).await
    }

    /// Apply one worker pass: drop `resolved`, remove delivered entries,
    /// and reschedule failed ones from `schedule_secs`. Then persist.
    pub(crate) async fn settle(
        &self,
        now_ms: u64,
        resolved: &[T],
        attempts: &[(T, bool)],
        schedule_secs: &[u64],
    ) -> Settled {
        let _guard = self.persist_lock.lock().await;
        let snapshot = self.entries.read().await.clone();
        let mut next = snapshot.clone();
        let mut delivered: Vec<String> = Vec::new();
        let mut dropped: Vec<String> = Vec::new();
        for entry in resolved {
            if remove_entry(&mut next, entry) {
                dropped.push(entry.partition().to_string());
            }
        }
        for (entry, ok) in attempts {
            let Some(live) = next
                .get_mut(entry.partition())
                .and_then(|list| list.iter_mut().find(|o| o.id() == entry.id()))
            else {
                continue;
            };
            let retry_count = live.retry_count().saturating_add(1);
            if *ok {
                delivered.push(entry.partition().to_string());
                live.set_schedule(retry_count, live.next_retry_at_ms());
            } else {
                let delay = retry_delay_secs(schedule_secs, retry_count);
                live.set_schedule(
                    retry_count,
                    now_ms.saturating_add(delay.saturating_mul(1000)),
                );
            }
        }
        // A delivered entry leaves the store; a failed one never does.
        for (entry, ok) in attempts {
            if *ok {
                if let Some(list) = next.get_mut(entry.partition()) {
                    list.retain(|o| o.id() != entry.id());
                }
            }
        }
        next.retain(|_, list| !list.is_empty());
        match self.persist_then_commit(next).await {
            Ok(()) => Settled::Committed { delivered, dropped },
            Err(e) if e.crossed_rename() => Settled::Unconfirmed(e),
            Err(e) => {
                // Before the rename the file still holds the snapshot.
                *self.entries.write().await = snapshot;
                Settled::RolledBack(e)
            }
        }
    }

    /// Load the sidecar at boot. Missing means empty. A file that fails
    /// a check is moved aside (`corrupt-<aside_stamp_ms>`) and the
    /// outbox stays empty; the error is returned.
    pub(crate) async fn load(&self, aside_stamp_ms: u64) -> Result<(), String> {
        let bytes = match crate::w3h_inline::fs::read(self.path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("failed to read {}: {e}", self.path.display())),
        };
        match self.validate(&bytes) {
            Ok(map) => {
                *self.entries.write().await = map;
                Ok(())
            }
            Err(error) => {
                let aside = self
                    .path
                    .with_extension(format!("corrupt-{aside_stamp_ms}"));
                let _ = crate::w3h_inline::fs::rename(self.path, &aside).await;
                Err(format!("{error} (file moved aside to {})", aside.display()))
            }
        }
    }

    fn validate(&self, bytes: &[u8]) -> Result<OutboxMap<T>, String> {
        let path = self.path;
        // #942 M3: a sidecar within the caps is at most ~4x the byte cap
        // when encoded, so anything larger is corruption.
        let size_guard = self
            .caps
            .total_bytes
            .saturating_mul(4)
            .saturating_add(1 << 20);
        if bytes.len() > size_guard {
            return Err(format!(
                "{}: {} file is {} bytes (over the {:?}-byte guard)",
                path.display(),
                T::LABEL,
                bytes.len(),
                size_guard
            ));
        }
        let map = T::decode(bytes, path)?;
        let count: usize = map.values().map(Vec::len).sum();
        let total_bytes: usize = map.values().flatten().map(T::byte_size).sum();
        let mut rejection: Option<String> = None;
        if count > self.caps.total || total_bytes > self.caps.total_bytes {
            rejection = Some(format!(
                "exceeds daemon caps ({count} envelopes, {total_bytes} bytes)"
            ));
        }
        for (group, list) in &map {
            if list.len() > self.caps.per_partition
                || list.iter().map(T::byte_size).sum::<usize>() > self.caps.per_partition_bytes
            {
                rejection = Some(format!("group {group} exceeds per-group caps"));
                break;
            }
            if let Some(reason) = list.iter().find_map(|o| o.check().err()) {
                rejection = Some(reason);
            }
            // As before the move: a store-cap rejection stops the scan
            // after the first group.
            if rejection.is_some() {
                break;
            }
        }
        match rejection {
            Some(reason) => Err(format!("{}: {} {reason}", path.display(), T::LABEL)),
            None => Ok(map),
        }
    }

    /// Durable write of `next`, then commit it to memory. A failure
    /// after the rename also commits (#1101: the disk holds `next`).
    async fn persist_then_commit(&self, next: OutboxMap<T>) -> Result<(), DurableWriteError> {
        let bytes = T::encode(&next)
            .map_err(|e| DurableWriteError::BeforeRename(std::io::Error::other(e)))?;
        let written = super::write_private_bytes_durable_typed(self.path, bytes)
            .await
            .map_err(|e| e.with_path(self.path));
        match written {
            Ok(()) => {}
            Err(e) if e.crossed_rename() => {
                *self.entries.write().await = next;
                return Err(e);
            }
            Err(e) => return Err(e),
        }
        *self.entries.write().await = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
