//! Per-snapshot-path lifecycle fence and persist-generation ownership (#760).
//!
//! Two coordinated, per-canonical-snapshot-path mechanisms close the
//! retire → re-open race over one snapshot file:
//!
//! 1. **Open/retire lifecycle** (`Lifecycle`): every retirement marks its
//!    path `Retiring` SYNCHRONOUSLY (under whatever registry/membership lock
//!    the retirer already holds) before cancelling; the drain
//!    (`KvStoreSync::cancel_sync_and_drain`) runs only after the retirer
//!    releases every lock a receive section takes — inline where safe,
//!    detached where the retirer cannot await (secure-refresh hooks run
//!    *inside* a section). Only the drain's completion returns the path to
//!    `Idle`. Every persistent opener waits for "not `Retiring`" BEFORE
//!    `load_snapshot` and BEFORE taking the group-membership / registry
//!    guards, so the opener's load observes the retired sync's final write.
//!
//! 2. **Persist-generation ownership**: `set_persist_path` arms the path
//!    with a fresh globally-unique generation and stamps it into the
//!    `PersistCtx`; a snapshot write only renames when its ctx generation
//!    still owns the path, with the ownership check and the rename under the
//!    same leaf mutex. A younger arming therefore either happens before an
//!    older write's rename (the younger lineage overwrites it later) or the
//!    older write is skipped outright. This is defense in depth for the
//!    caller-driven paths the lifecycle fence cannot cancel (#758
//!    deliberately does not fence them): a stale caller-driven persist
//!    returns a typed error and marks the store durability-degraded instead
//!    of reporting success.
//!
//! Lock discipline: the registry mutex and every per-path mutex here are
//! leaves. Nothing in this module awaits while holding them, and no caller
//! may hold them across an await of `lifecycle`/`kv_stores`/membership
//! guards (the waiting happens in [`claim_open`] BEFORE those guards are
//! taken).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use tokio::sync::watch;

/// Monotonic source for every generation stamped into the fence. Globally
/// unique (not per-path) so pruning an idle path entry can never let an
/// older ctx generation collide with a freshly re-created entry's counter.
static FENCE_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_generation() -> u64 {
    FENCE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Lifecycle of one canonical snapshot path.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Lifecycle {
    /// No committed handle and no lifecycle operation is outstanding.
    Idle,
    /// The generation of the committed handle that owns the path.
    Active { generation: u64 },
    /// A constructor owns the path while it loads and registers. The direct
    /// predecessor may retire during this window without granting older
    /// stale clones authority over a later successor.
    Opening {
        generation: u64,
        predecessor: Option<u64>,
    },
    /// A retire marked the path and its drain obligation is outstanding.
    /// Openers wait; the retirer's drain completion returns the path to
    /// `Idle` and wakes them.
    Retiring { generation: u64 },
}

/// One path's fence. Both halves are leaves; neither mutex is ever held
/// across an await of anything else.
struct PathFence {
    /// Broadcast lifecycle state. Waiting openers `subscribe` BEFORE their
    /// state check and `changed().await` after, the race-free watch pattern:
    /// no `Retiring` → `Idle` transition can be missed.
    lifecycle: watch::Sender<Lifecycle>,
    /// Keeps the watch channel open forever (send_modify works regardless,
    /// but a retained receiver makes `changed()` infallibility obvious).
    _lifecycle_rx: watch::Receiver<Lifecycle>,
    /// Current persist-owner generation for the file (`0` = never armed).
    /// Held across the [ownership check → write → rename] span so the check
    /// is atomic with the rename; `arm_persist` briefly takes the same
    /// mutex, making arming and any older write's rename strictly ordered.
    persist_owner: Mutex<u64>,
}

fn registry() -> &'static Mutex<HashMap<PathBuf, Arc<PathFence>>> {
    static REGISTRY: LazyLock<Mutex<HashMap<PathBuf, Arc<PathFence>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    &REGISTRY
}

/// Look up (or create) the fence for `path`, opportunistically pruning
/// entries nobody references. Bounded state: an entry is kept only while
/// some lease/claim/writer still holds an `Arc` of it (strong count > 1) —
/// the registry itself is the only other holder, so retired-and-reopened
/// and one-shot paths do not accumulate (mirrors the
/// `crdt_handle_locks` pruning discipline).
fn entry_for(path: &Path) -> Arc<PathFence> {
    let mut registry = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.retain(|_, entry| Arc::strong_count(entry) > 1);
    Arc::clone(registry.entry(path.to_path_buf()).or_insert_with(|| {
        let (lifecycle, _lifecycle_rx) = watch::channel(Lifecycle::Idle);
        Arc::new(PathFence {
            lifecycle,
            _lifecycle_rx,
            persist_owner: Mutex::new(0),
        })
    }))
}

/// Claim `path` for an open (#760).
///
/// Waits while the path is `Retiring` (a retirement's drain is outstanding)
/// or while a sibling open is in progress, then claims `Opening` and
/// returns the lease. MUST be called BEFORE the caller takes any lock a
/// receive section takes (group membership, `named_groups`, `kv_stores`):
/// the wait is exactly what must not happen under those guards.
///
/// The lease must end in [`StoreOpenLease::commit`] (construction
/// succeeded) or be dropped (construction failed / the opener was
/// cancelled) — its `Drop` aborts an uncommitted claim and wakes waiters.
pub(crate) async fn claim_open(path: &Path) -> StoreOpenLease {
    loop {
        let entry = entry_for(path);
        // Subscribe BEFORE the check so a transition in between cannot be
        // missed (race-free watch pattern).
        let mut rx = entry.lifecycle.subscribe();
        let generation = next_generation();
        let mut claimed = false;
        entry.lifecycle.send_if_modified(|state| {
            match *state {
                // A retire's drain is outstanding, or a sibling open is
                // mid-construction — wait for a transition and re-check.
                Lifecycle::Retiring { .. } | Lifecycle::Opening { .. } => false,
                Lifecycle::Idle => {
                    *state = Lifecycle::Opening {
                        generation,
                        predecessor: None,
                    };
                    claimed = true;
                    true
                }
                Lifecycle::Active {
                    generation: predecessor,
                } => {
                    *state = Lifecycle::Opening {
                        generation,
                        predecessor: Some(predecessor),
                    };
                    claimed = true;
                    true
                }
            }
        });
        if claimed {
            return StoreOpenLease {
                entry,
                generation,
                path: path.to_path_buf(),
            };
        }
        // The sender lives in `entry` (and this lease cycle holds the
        // entry), so `changed()` cannot observe a closed channel.
        let _ = rx.changed().await;
    }
}

/// A claimed (or committed) opening lease over one canonical snapshot path.
///
/// Held across load → arm → sync start → registration → rollback; moved
/// into the returned [`crate::KvStoreHandle`] on success. Cheap to clone:
/// every clone sees the same shared fence state, and retirement marking is
/// idempotent across clones.
pub(crate) struct StoreOpenLease {
    entry: Arc<PathFence>,
    generation: u64,
    path: PathBuf,
}

impl Clone for StoreOpenLease {
    fn clone(&self) -> Self {
        Self {
            entry: Arc::clone(&self.entry),
            generation: self.generation,
            path: self.path.clone(),
        }
    }
}

impl StoreOpenLease {
    /// The canonical path this lease fences.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Arm persistence only for an uncontested open claimed from `Idle`.
    ///
    /// An open claimed while a predecessor is active must fail and retry
    /// after that predecessor retires and drains. Letting such an opener arm
    /// would suppress, or overwrite, a receive persist already admitted by
    /// the predecessor. The lifecycle validation and owner installation are
    /// one synchronous watch mutation, so a retirement cannot land between
    /// them.
    pub(crate) fn arm_persist(&self) -> Option<PersistOwner> {
        let persist_generation = next_generation();
        let mut armed = false;
        self.entry.lifecycle.send_if_modified(|state| {
            if matches!(
                *state,
                Lifecycle::Opening {
                    generation,
                    predecessor: None,
                } if generation == self.generation
            ) {
                let mut owner = self
                    .entry
                    .persist_owner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *owner = persist_generation;
                armed = true;
            }
            // Arming does not change lifecycle state or notify waiters.
            false
        });
        armed.then(|| PersistOwner {
            entry: Arc::clone(&self.entry),
            generation: persist_generation,
            path: self.path.clone(),
        })
    }

    /// Commit the open: the constructor finished (loaded, armed, started)
    /// and the handle is about to become live/registered. Returns `false`
    /// when a retirement trampled the claim mid-construction — the caller
    /// MUST fail the open (drop the constructed sync) and let the retirer's
    /// drain-completion own the path. A replacement claimed from an active
    /// predecessor commits as the new active generation; the predecessor's
    /// later stale calls cannot alter it.
    pub(crate) fn commit(&self) -> bool {
        let mut committed_ok = false;
        self.entry.lifecycle.send_if_modified(|state| match *state {
            Lifecycle::Opening { generation, .. } if generation == self.generation => {
                *state = Lifecycle::Active { generation };
                committed_ok = true;
                true
            }
            Lifecycle::Idle
            | Lifecycle::Active { .. }
            | Lifecycle::Retiring { .. }
            | Lifecycle::Opening { .. } => false,
        });
        committed_ok
    }

    /// Synchronously mark the path `Retiring` (#760). Safe under ANY lock
    /// (no await, leaf locks only). Returns a token only when this exact
    /// lease is the active owner, the opening owner, or that opening's
    /// direct predecessor. An obsolete clone cannot retire a committed
    /// successor. The token must be completed after this handle drains.
    pub(crate) fn begin_retire(&self) -> Option<RetirementToken> {
        let generation = next_generation();
        let mut marked = false;
        self.entry.lifecycle.send_if_modified(|state| {
            let owns_lineage = match *state {
                Lifecycle::Active { generation } => generation == self.generation,
                Lifecycle::Opening {
                    generation,
                    predecessor,
                } => generation == self.generation || predecessor == Some(self.generation),
                Lifecycle::Idle | Lifecycle::Retiring { .. } => false,
            };
            if owns_lineage {
                *state = Lifecycle::Retiring { generation };
                marked = true;
                true
            } else {
                false
            }
        });
        marked.then(|| RetirementToken {
            entry: Arc::clone(&self.entry),
            generation,
        })
    }
}

/// Exclusive authority to complete one exact retirement generation.
///
/// Tokens are created only for the caller that changed the lifecycle to
/// `Retiring`; duplicate retirement requests receive no token and therefore
/// cannot release this or any later retirement.
pub(crate) struct RetirementToken {
    entry: Arc<PathFence>,
    generation: u64,
}

impl RetirementToken {
    /// Complete this retirement after its drain returned. A stale token is a
    /// no-op even when a later retirement is currently outstanding.
    pub(crate) fn complete(self) {
        self.entry.lifecycle.send_if_modified(|state| {
            if matches!(
                *state,
                Lifecycle::Retiring { generation } if generation == self.generation
            ) {
                *state = Lifecycle::Idle;
                true
            } else {
                false
            }
        });
    }
}

impl Drop for StoreOpenLease {
    fn drop(&mut self) {
        // Abort only OUR OWN opening claim and restore the committed
        // predecessor, if any. A sibling, successor, or retirement is left
        // untouched.
        self.entry.lifecycle.send_if_modified(|state| {
            if let Lifecycle::Opening {
                generation,
                predecessor,
            } = *state
            {
                if generation == self.generation {
                    *state = predecessor.map_or(Lifecycle::Idle, |generation| Lifecycle::Active {
                        generation,
                    });
                    return true;
                }
            }
            false
        });
    }
}

/// A persist generation together with the exact path entry that owns it.
/// Keeping the entry alive is required: otherwise opportunistic registry
/// pruning could discard the owner between arming and the first write.
pub(crate) struct PersistOwner {
    entry: Arc<PathFence>,
    generation: u64,
    path: PathBuf,
}

impl PersistOwner {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// True iff this generation still owns its path (#760).
    ///
    /// No-write ownership query for version-gated skips: it takes the
    /// same leaf mutex as [`arm_persist`] and [`write_if_owner`], so the
    /// answer linearizes against successor arming exactly like a write.
    /// Query-before-arm — the caller's already-durable state was
    /// legitimately current at that instant; arm-before-query — `false`,
    /// and the caller must treat its unchanged-version skip as
    /// supersession, not success.
    pub(crate) fn is_current_owner(&self) -> bool {
        let current = self
            .entry
            .persist_owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current == self.generation
    }
}

/// Arm `path` for a new persist owner and return its retained lease.
/// Called by `set_persist_path` — the youngest arming owns the file.
pub(crate) fn arm_persist(path: &Path) -> PersistOwner {
    let entry = entry_for(path);
    let generation = next_generation();
    {
        let mut owner = entry
            .persist_owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *owner = generation;
    }
    PersistOwner {
        entry,
        generation,
        path: path.to_path_buf(),
    }
}

/// Run `write(path, bytes)` iff `generation` still owns `path`.
///
/// The ownership check and the write (temp+fsync+rename) execute under the
/// same leaf mutex `arm_persist` uses, so exactly one of two orders holds
/// for an older writer vs. a younger arming: the older write renamed BEFORE
/// the arming took the mutex (a younger lineage overwrites it later), or
/// the arming happened first and the older write is suppressed here.
/// Returns `Ok(false)` for the suppressed case; the caller decides policy
/// (receive-path: skip; caller-driven: typed error + durability degraded).
pub(crate) fn write_if_owner<F>(
    owner: &PersistOwner,
    bytes: &[u8],
    write: F,
) -> std::io::Result<bool>
where
    F: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
{
    let current = owner
        .entry
        .persist_owner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *current != owner.generation {
        return Ok(false);
    }
    write(&owner.path, bytes)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("{tag}.bin"));
        (dir, path)
    }

    #[tokio::test]
    async fn claim_waits_until_retire_completes() {
        let (_dir, path) = temp_path("claim-waits");
        let lease = claim_open(&path).await;
        assert!(lease.commit(), "fresh claim commits");

        // Retire synchronously; a new claim must park until completion.
        let retirement = lease.begin_retire().expect("first retire marks");
        let mut claim = Box::pin(claim_open(&path));
        assert!(
            futures::poll!(&mut claim).is_pending(),
            "claim must wait while the drain obligation is outstanding"
        );
        retirement.complete();
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), claim)
            .await
            .expect("claim resumes after completion");
        assert!(next.commit(), "post-drain claim commits");
    }

    #[tokio::test]
    async fn claim_waits_for_sibling_open_resolution() {
        let (_dir, path) = temp_path("claim-sibling");
        let opener = claim_open(&path).await;
        let mut claim = Box::pin(claim_open(&path));
        assert!(
            futures::poll!(&mut claim).is_pending(),
            "second open must wait for the in-flight sibling"
        );
        // Sibling failed construction: its uncommitted claim aborts to Idle.
        drop(opener);
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), claim)
            .await
            .expect("claim resumes after sibling abort");
        assert!(next.commit());
    }

    #[tokio::test]
    async fn duplicate_retire_has_no_completion_authority() {
        let (_dir, path) = temp_path("dup-retire");
        let lease = claim_open(&path).await;
        assert!(lease.commit());
        let clone = lease.clone();
        let retirement = lease.begin_retire().expect("first mark wins");
        assert!(
            clone.begin_retire().is_none(),
            "duplicate mark owns no completion"
        );
        retirement.complete();
        let again = claim_open(&path).await;
        assert!(again.commit());
    }

    #[tokio::test]
    async fn retire_trample_fails_the_open_commit() {
        let (_dir, path) = temp_path("trample");
        let lease = claim_open(&path).await;
        // A retire lands between claim and commit (the hook/rollback window).
        let retirer = lease.clone();
        let retirement = retirer.begin_retire().expect("retire marks");
        assert!(!lease.commit(), "trampled open must fail closed");
        retirement.complete();
    }

    #[tokio::test]
    async fn stale_completion_cannot_release_a_later_retirement() {
        let (_dir, path) = temp_path("stale-complete");
        let first = claim_open(&path).await;
        assert!(first.commit());
        let first_retirement = first.begin_retire().expect("first retire");
        let stale = RetirementToken {
            entry: Arc::clone(&first_retirement.entry),
            generation: first_retirement.generation,
        };

        let mut claim = Box::pin(claim_open(&path));
        assert!(futures::poll!(&mut claim).is_pending());
        first_retirement.complete();
        let second = tokio::time::timeout(std::time::Duration::from_secs(5), claim)
            .await
            .expect("second claim proceeds");
        assert!(second.commit());
        let second_retirement = second.begin_retire().expect("second retire");

        stale.complete();
        let mut blocked = Box::pin(claim_open(&path));
        assert!(
            futures::poll!(&mut blocked).is_pending(),
            "stale completion must not release a later retirement"
        );
        second_retirement.complete();
        let third = tokio::time::timeout(std::time::Duration::from_secs(5), blocked)
            .await
            .expect("later retirement completion releases claim");
        assert!(third.commit());
    }

    #[tokio::test]
    async fn stale_begin_retire_cannot_mark_or_release_a_committed_successor() {
        let (_dir, path) = temp_path("stale-begin");
        let stale = claim_open(&path).await;
        assert!(stale.commit());
        let successor = claim_open(&path).await;
        assert!(successor.commit());

        assert!(stale.begin_retire().is_none());
        let retirement = successor.begin_retire().expect("successor retires itself");
        assert!(stale.begin_retire().is_none());
        let mut blocked = Box::pin(claim_open(&path));
        assert!(futures::poll!(&mut blocked).is_pending());
        retirement.complete();
        let reopened = tokio::time::timeout(std::time::Duration::from_secs(5), blocked)
            .await
            .expect("successor completion releases opener");
        assert!(reopened.commit());
    }

    #[tokio::test]
    async fn predecessor_backed_or_trampled_open_cannot_arm_persistence() {
        let (_dir, path) = temp_path("predecessor-arm");
        let old = claim_open(&path).await;
        assert!(old.commit());
        let replacement = claim_open(&path).await;
        assert!(
            replacement.arm_persist().is_none(),
            "an active predecessor must drain before replacement arming"
        );
        let retirement = old.begin_retire().expect("predecessor retires");
        assert!(
            replacement.arm_persist().is_none(),
            "a trampled opening must not acquire file ownership"
        );
        retirement.complete();
        assert!(!replacement.commit());

        let retry = claim_open(&path).await;
        assert!(
            retry.arm_persist().is_some(),
            "a retry claimed from Idle is the positive control"
        );
        assert!(retry.commit());
    }

    #[tokio::test]
    async fn trampled_claim_cannot_attach_to_a_later_committed_open() {
        let (_dir, path) = temp_path("trampled-later");
        let stale = claim_open(&path).await;
        let retirement = stale.begin_retire().expect("retire tramples claim");
        retirement.complete();
        let current = claim_open(&path).await;
        assert!(current.commit());
        assert!(
            !stale.commit(),
            "pre-retirement generation must not attach to a later open"
        );
    }

    #[tokio::test]
    async fn blocked_claim_does_not_publish_its_own_watch_change() {
        let (_dir, path) = temp_path("no-self-notify");
        let lease = claim_open(&path).await;
        assert!(lease.commit());
        let retirement = lease.begin_retire().expect("retire marks");
        let entry = entry_for(&path);
        let rx = entry.lifecycle.subscribe();
        let mut blocked = Box::pin(claim_open(&path));
        assert!(futures::poll!(&mut blocked).is_pending());
        assert!(
            !rx.has_changed().expect("watch remains open"),
            "failed claim must not notify itself or peer waiters"
        );
        retirement.complete();
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), blocked)
            .await
            .expect("completion releases blocked claim");
        assert!(next.commit());
    }

    #[test]
    fn registry_state_is_bounded_by_referenced_paths() {
        let (unrelated_dir, unrelated_path) = temp_path("bounded-unrelated-live");
        let unrelated = futures::executor::block_on(claim_open(&unrelated_path));
        let owned: Vec<_> = (0..16)
            .map(|i| {
                let (dir, path) = temp_path(&format!("bounded-{i}"));
                let lease = futures::executor::block_on(claim_open(&path));
                assert!(lease.commit());
                (dir, path, lease)
            })
            .collect();
        let owned_paths: Vec<_> = owned.iter().map(|(_, path, _)| path.clone()).collect();
        assert!(owned_paths
            .iter()
            .all(|path| registry_contains_for_test(path)));
        // Drop every lease: the next lookup prunes the unreferenced entries.
        drop(owned);
        let (_keep_dir, keep_path) = temp_path("bounded-keep");
        let keeper = futures::executor::block_on(claim_open(&keep_path));
        assert!(
            owned_paths
                .iter()
                .all(|path| !registry_contains_for_test(path)),
            "this test's unreferenced paths must be pruned"
        );
        assert!(registry_contains_for_test(&keep_path));
        assert!(
            registry_contains_for_test(&unrelated_path),
            "pruning must retain an unrelated live path"
        );
        drop(keeper);
        drop(unrelated);
        drop(unrelated_dir);
    }

    #[test]
    fn persist_ownership_follows_the_youngest_arming() {
        let (_dir, path) = temp_path("persist-owner");
        let write = |p: &Path, b: &[u8]| write_snapshot_bytes(p, b);
        let g1 = arm_persist(&path);
        assert!(g1.is_current_owner(), "fresh arming owns the path");
        assert!(
            write_if_owner(&g1, b"one", write).expect("owner write"),
            "current owner writes"
        );
        let g2 = arm_persist(&path);
        assert!(
            !g1.is_current_owner(),
            "ownership query flips for the superseded generation"
        );
        assert!(g2.is_current_owner(), "query tracks the youngest arming");
        assert!(
            !write_if_owner(&g1, b"stale", write).expect("no io error"),
            "superseded generation is skipped"
        );
        assert_eq!(
            std::fs::read(&path).expect("file"),
            b"one",
            "suppressed write must not touch the file"
        );
        assert!(
            write_if_owner(&g2, b"two", write).expect("owner write"),
            "younger owner writes"
        );
        assert_eq!(std::fs::read(&path).expect("file"), b"two");
    }

    fn write_snapshot_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }

    fn registry_contains_for_test(path: &Path) -> bool {
        registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(path)
    }
}
