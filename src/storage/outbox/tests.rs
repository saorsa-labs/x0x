//! #1365 unit tests for [`Outbox`]: restart and retry behaviour with a
//! toy record. Inert: local files only.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Note {
    group: String,
    id: String,
    first_seen_ms: u64,
    size: usize,
    next_retry_at_ms: u64,
    retry_count: u32,
}

impl OutboxRecord for Note {
    const LABEL: &'static str = "note outbox";
    fn partition(&self) -> &str {
        &self.group
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn first_seen_ms(&self) -> u64 {
        self.first_seen_ms
    }
    fn byte_size(&self) -> usize {
        self.size
    }
    fn next_retry_at_ms(&self) -> u64 {
        self.next_retry_at_ms
    }
    fn retry_count(&self) -> u32 {
        self.retry_count
    }
    fn set_schedule(&mut self, retry_count: u32, next_retry_at_ms: u64) {
        self.retry_count = retry_count;
        self.next_retry_at_ms = next_retry_at_ms;
    }
    fn check(&self) -> Result<(), String> {
        if self.size == 0 {
            return Err(format!("empty note {}", self.id));
        }
        Ok(())
    }
    fn encode(map: &OutboxMap<Self>) -> Result<Vec<u8>, String> {
        serde_json::to_vec(map).map_err(|e| e.to_string())
    }
    fn decode(bytes: &[u8], path: &Path) -> Result<OutboxMap<Self>, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }
}

const SCHEDULE: &[u64] = &[0, 1, 2, 4];
const CAPS: OutboxCaps = OutboxCaps {
    per_partition: 3,
    per_partition_bytes: 1_000,
    total: 4,
    total_bytes: 10_000,
};

fn note(group: &str, id: &str, first_seen_ms: u64) -> Note {
    Note {
        group: group.to_string(),
        id: id.to_string(),
        first_seen_ms,
        size: 10,
        next_retry_at_ms: first_seen_ms,
        retry_count: 0,
    }
}

/// The storage an owner keeps: map, path and persistence lock.
struct Cells {
    entries: RwLock<OutboxMap<Note>>,
    path: std::path::PathBuf,
    lock: Mutex<()>,
}

impl Cells {
    fn new(dir: &Path) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            path: dir.join("note_outbox.json"),
            lock: Mutex::new(()),
        }
    }
    fn outbox(&self) -> Outbox<'_, Note> {
        Outbox::new(&self.entries, &self.path, &self.lock, CAPS)
    }
    /// A fresh process: empty memory over the same sidecar.
    async fn restarted(&self) -> Self {
        let cells = Self {
            entries: RwLock::new(HashMap::new()),
            path: self.path.clone(),
            lock: Mutex::new(()),
        };
        cells.outbox().load(1).await.expect("sidecar loads");
        cells
    }
}

fn sorted(mut v: Vec<Note>) -> Vec<Note> {
    v.sort_by(|a, b| (&a.group, &a.id).cmp(&(&b.group, &b.id)));
    v
}

#[test]
fn retry_offsets_clamp_at_the_last_entry() {
    assert_eq!(retry_delay_secs(SCHEDULE, 0), 0);
    assert_eq!(retry_delay_secs(SCHEDULE, 1), 0);
    assert_eq!(retry_delay_secs(SCHEDULE, 2), 1);
    assert_eq!(retry_delay_secs(SCHEDULE, 4), 4);
    assert_eq!(retry_delay_secs(SCHEDULE, 99), 4, "bounded interval");
    assert_eq!(retry_delay_secs(&[], 3), 0, "no table, no panic");
}

/// #1840: `replace_if` replaces only a stored entry that `accept` admits,
/// never adds one, and the replacement is durable.
#[tokio::test]
async fn replace_if_replaces_only_an_accepted_stored_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cells = Cells::new(dir.path());
    let a = note("g1", "a", 10);
    cells.outbox().insert(a.clone()).await.expect("insert a");
    let mut a2 = a.clone();
    a2.size = 11;

    // No stored entry with that id, or that partition: nothing is added.
    for absent in [note("g1", "zz", 10), note("g9", "a", 10)] {
        let replaced = cells.outbox().replace_if(absent, |_| true).await;
        assert!(matches!(replaced, Ok(false)));
    }
    // `accept` sees the STORED entry and can refuse it.
    let refused = cells
        .outbox()
        .replace_if(a2.clone(), |stored| stored.size != 10)
        .await;
    assert!(matches!(refused, Ok(false)));
    assert_eq!(cells.outbox().snapshot().await, vec![a.clone()]);
    assert_eq!(cells.restarted().await.outbox().snapshot().await, vec![a]);

    let replaced = cells
        .outbox()
        .replace_if(a2.clone(), |stored| stored.size == 10)
        .await;
    assert!(matches!(replaced, Ok(true)));
    assert_eq!(cells.outbox().snapshot().await, vec![a2.clone()]);
    assert_eq!(cells.restarted().await.outbox().snapshot().await, vec![a2]);
}

#[tokio::test]
async fn insert_is_durable_and_survives_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cells = Cells::new(dir.path());
    let a = note("g1", "a", 10);
    let b = note("g2", "b", 20);
    cells.outbox().insert(a.clone()).await.expect("insert a");
    cells.outbox().insert(b.clone()).await.expect("insert b");
    // Replacing the same (group, id) does not duplicate.
    let mut a2 = a.clone();
    a2.size = 11;
    cells.outbox().insert(a2.clone()).await.expect("replace a");
    let restarted = cells.restarted().await;
    assert_eq!(
        sorted(restarted.outbox().snapshot().await),
        vec![a2, b],
        "restart restores exactly the durable set"
    );
}

#[tokio::test]
async fn failed_sends_follow_the_schedule_across_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cells = Cells::new(dir.path());
    let n = note("g", "n", 100);
    cells.outbox().insert(n.clone()).await.expect("insert");

    // Due at 100. Four failed attempts walk the offsets 0, 1, 2, 4 s,
    // and a fifth stays at the last offset.
    let mut now = 100;
    for (attempt, offset) in [(1u32, 0u64), (2, 1), (3, 2), (4, 4), (5, 4)] {
        let due = cells.outbox().due(now).await;
        assert_eq!(due.len(), 1, "attempt {attempt} is due at {now}");
        let settled = cells
            .outbox()
            .settle(now, &[], &[(due[0].clone(), false)], SCHEDULE)
            .await;
        assert!(matches!(settled, Settled::Committed { .. }));
        let live = cells.outbox().snapshot().await;
        assert_eq!(live.len(), 1, "a failed send keeps the entry");
        assert_eq!(live[0].retry_count, attempt);
        assert_eq!(live[0].next_retry_at_ms, now + offset * 1000);
        // Restart between every attempt: count and schedule persist.
        let restarted = cells.restarted().await;
        assert_eq!(restarted.outbox().snapshot().await, live);
        // Not due one millisecond before the scheduled time.
        if offset > 0 {
            assert!(cells.outbox().due(now + offset * 1000 - 1).await.is_empty());
        }
        now += offset * 1000;
    }

    // A delivered attempt removes the entry, durably.
    let due = cells.outbox().due(now).await;
    let settled = cells
        .outbox()
        .settle(now, &[], &[(due[0].clone(), true)], SCHEDULE)
        .await;
    let Settled::Committed { delivered, dropped } = settled else {
        panic!("durable settle expected");
    };
    assert_eq!(delivered, vec!["g".to_string()]);
    assert!(dropped.is_empty());
    assert!(cells.restarted().await.outbox().snapshot().await.is_empty());
}

#[tokio::test]
async fn resolved_entries_drop_and_due_order_puts_first_attempts_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cells = Cells::new(dir.path());
    let mut retry = note("g", "retry", 1);
    retry.retry_count = 3;
    retry.next_retry_at_ms = 5;
    let fresh = note("g", "fresh", 50);
    let gone = note("h", "gone", 2);
    for n in [&retry, &fresh, &gone] {
        cells.outbox().insert(n.clone()).await.expect("insert");
    }
    let due = cells.outbox().due(100).await;
    let ids: Vec<&str> = due.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(ids, vec!["gone", "fresh", "retry"], "first attempts first");
    let settled = cells.outbox().settle(100, &[gone], &[], SCHEDULE).await;
    let Settled::Committed { dropped, .. } = settled else {
        panic!("durable settle expected");
    };
    assert_eq!(dropped, vec!["h".to_string()]);
    let restarted = cells.restarted().await;
    assert_eq!(
        sorted(restarted.outbox().snapshot().await),
        vec![fresh, retry]
    );
}

#[tokio::test]
async fn caps_evict_the_oldest_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cells = Cells::new(dir.path());
    for i in 0..5u64 {
        cells
            .outbox()
            .insert(note("g", &format!("p{i}"), i))
            .await
            .expect("insert");
    }
    let ids: Vec<String> = cells
        .outbox()
        .snapshot()
        .await
        .into_iter()
        .map(|n| n.id)
        .collect();
    assert_eq!(
        ids,
        vec!["p2", "p3", "p4"],
        "per-group cap keeps the newest"
    );
    cells
        .outbox()
        .insert(note("h", "q0", 0))
        .await
        .expect("insert");
    cells
        .outbox()
        .insert(note("h", "q9", 9))
        .await
        .expect("insert");
    let all = cells.outbox().snapshot().await;
    assert_eq!(all.len(), CAPS.total, "store cap");
    assert!(
        !all.iter().any(|n| n.id == "q0"),
        "store-wide oldest evicted"
    );
}

#[tokio::test]
async fn a_bad_sidecar_is_moved_aside_and_the_outbox_starts_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cells = Cells::new(dir.path());
    let mut bad = note("g", "bad", 1);
    bad.size = 0;
    let mut map: OutboxMap<Note> = HashMap::new();
    map.insert("g".to_string(), vec![bad]);
    std::fs::write(&cells.path, Note::encode(&map).expect("encode")).expect("write");
    let error = cells.outbox().load(77).await.expect_err("rejected");
    assert!(error.contains("note outbox empty note bad"), "{error}");
    assert!(cells.outbox().snapshot().await.is_empty());
    assert!(!cells.path.exists(), "the bad file is moved aside");
    assert!(cells.path.with_extension("corrupt-77").exists());
    // A missing sidecar is an empty outbox, not an error.
    cells.outbox().load(78).await.expect("missing is empty");
}

#[tokio::test]
async fn write_failures_keep_memory_aligned_with_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cells = Cells::new(dir.path());
    let a = note("g", "a", 1);
    cells.outbox().insert(a.clone()).await.expect("insert");

    // Before the rename: the disk keeps the old set, so memory does too.
    {
        let _armed = crate::storage::arm_fail_durable_before_rename_for_testing(&cells.path);
        let err = cells
            .outbox()
            .insert(note("g", "b", 2))
            .await
            .expect_err("fails");
        assert!(!err.crossed_rename());
        let settled = cells
            .outbox()
            .settle(1, &[], &[(a.clone(), true)], SCHEDULE)
            .await;
        assert!(matches!(settled, Settled::RolledBack(_)));
        assert_eq!(cells.outbox().snapshot().await, vec![a.clone()]);
    }
    assert_eq!(
        cells.restarted().await.outbox().snapshot().await,
        vec![a.clone()]
    );

    // After the rename (#1101): the disk holds the new set, so memory
    // commits to it and the error still reports it.
    {
        let _armed = crate::storage::arm_fail_parent_dir_fsync_for_testing(&cells.path);
        let err = cells
            .outbox()
            .insert(note("g", "b", 2))
            .await
            .expect_err("fails");
        assert!(err.crossed_rename());
        assert_eq!(cells.outbox().snapshot().await.len(), 2);
        let settled = cells
            .outbox()
            .settle(1, &[], &[(a.clone(), true)], SCHEDULE)
            .await;
        assert!(matches!(settled, Settled::Unconfirmed(_)));
        assert_eq!(
            cells.outbox().snapshot().await,
            vec![note("g", "b", 2)],
            "memory matches the advanced disk"
        );
    }
    assert_eq!(
        cells.restarted().await.outbox().snapshot().await,
        vec![note("g", "b", 2)]
    );
}
