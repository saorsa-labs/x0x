#![cfg(test)]
//! #1107: a commit writes its kind 0x05 records in its one register
//! write (`OwnerSyncStore::replace_records`).

use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

use super::tests::{clock, machine, names_value, owner_kp};
use super::*;

fn sign(kind: SyncKind, key: &str, value: SyncValue, version: u64) -> VersionedRecord {
    let clock = clock(version, 1, 1);
    VersionedRecord::sign(kind, key, &value, clock, &owner_kp(7)).expect("sign")
}

fn device_record() -> VersionedRecord {
    let m = machine(9);
    let enrollment = OwnerEnrollment::sign(m, &owner_kp(7), 1_000, None).expect("sign");
    let state = DeviceEnrollmentState::Enrolled { enrollment };
    let version = device_enrollment_version(&state).expect("version");
    let value = SyncValue::DeviceEnrollment { state };
    sign(
        SyncKind::DeviceEnrollment,
        &hex::encode(m.0),
        value,
        version,
    )
}

fn names_record(seed: u8) -> VersionedRecord {
    let key = hex::encode(machine(seed).0);
    sign(SyncKind::MachineNames, &key, names_value("n"), 1)
}

fn mixed() -> Vec<VersionedRecord> {
    vec![device_record(), names_record(2)]
}

fn owner() -> UserId {
    owner_kp(7).user_id()
}

fn devices(records: &[VersionedRecord]) -> usize {
    let device = |r: &&VersionedRecord| r.kind == SyncKind::DeviceEnrollment;
    records.iter().filter(device).count()
}

/// A store holding one names record, and that pre-batch register.
async fn seeded() -> (tempfile::TempDir, Arc<OwnerSyncStore>, Vec<VersionedRecord>) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let store = Arc::new(OwnerSyncStore::load(dir.path()).await.expect("store"));
    let seed = store.commit_batch(vec![names_record(1)], &owner()).await;
    seed.expect("seed");
    let before = store.records_snapshot().await;
    (dir, store, before)
}

/// The records of one register file, or none when it does not exist.
fn file(dir: &Path, name: &str) -> Vec<VersionedRecord> {
    let Ok(bytes) = std::fs::read(dir.join(SYNC_DIR).join(name)) else {
        return Vec::new();
    };
    let persisted: PersistedRecords = serde_json::from_slice(&bytes).expect("decode");
    persisted.records
}

fn temp_files(dir: &Path) -> usize {
    let entries = std::fs::read_dir(dir.join(SYNC_DIR)).expect("sync dir");
    let names = entries.filter_map(|e| e.ok()?.file_name().into_string().ok());
    names.filter(|name| name.contains(".tmp-")).count()
}

/// A reload of `dir` holds `expected`.
async fn assert_reload(dir: &Path, expected: &[VersionedRecord]) {
    let reloaded = OwnerSyncStore::load(dir).await.expect("reload");
    let records = reloaded.records_snapshot().await;
    assert_eq!(records, expected, "disk == memory");
}

/// P1: a failed register write stores none of the batch, kind 0x05
/// included, and advertises nothing; the batch is accepted when it is
/// delivered again.
#[tokio::test]
async fn a_failed_register_write_stores_no_device_record() {
    let (dir, store, before) = seeded().await;
    let generation = *store.generation_rx().borrow();
    store.fail_next_register_write();
    assert!(store.commit_batch(mixed(), &owner()).await.is_err());
    assert_eq!(
        store.records_snapshot().await,
        before,
        "memory is pre-batch"
    );
    assert_eq!(*store.generation_rx().borrow(), generation, "no advert");
    let enrollment = file(dir.path(), ENROLLMENT_RECORDS_FILE);
    assert_eq!(devices(&enrollment), 0, "not on disk");
    assert_reload(dir.path(), &before).await;

    let outcome = store.commit_batch(mixed(), &owner()).await;
    assert_eq!(outcome.expect("again").accepted.len(), 2, "both accepted");
}

/// P1: when the enrollment file cannot be staged, neither file changes
/// and no temp file is left.
#[tokio::test]
async fn a_failed_enrollment_stage_leaves_both_files_pre_batch() {
    let (dir, store, before) = seeded().await;
    let records_file = file(dir.path(), RECORDS_FILE);
    store.fail_next_enrollment_stage.store(true, Relaxed);
    let failed = store.commit_batch(mixed(), &owner()).await;
    assert!(matches!(failed, Err(SyncError::Io(_))), "{failed:?}");
    assert_eq!(
        store.records_snapshot().await,
        before,
        "memory is pre-batch"
    );
    assert_eq!(file(dir.path(), RECORDS_FILE), records_file);
    assert!(file(dir.path(), ENROLLMENT_RECORDS_FILE).is_empty());
    assert_eq!(temp_files(dir.path()), 0, "no temp file is left");
    assert_reload(dir.path(), &before).await;
}

/// When the second rename fails, memory takes what the disk holds (the
/// new older kinds, the old 0x05 part) and the store is poisoned. After a
/// restart, the 0x05 record is new again and is accepted.
#[tokio::test]
async fn a_failed_second_rename_keeps_memory_as_the_disk_and_poisons() {
    let (dir, store, _) = seeded().await;
    store.fail_next_enrollment_rename.store(true, Relaxed);
    let failed = store.commit_batch(mixed(), &owner()).await;
    assert!(matches!(failed, Err(SyncError::Poisoned(_))), "{failed:?}");
    let memory = store.records_snapshot().await;
    assert_eq!(memory.len(), 2, "both names records");
    assert_eq!(devices(&memory), 0, "no device record");
    assert_eq!(temp_files(dir.path()), 0, "no temp file is left");
    assert_reload(dir.path(), &memory).await;

    let store = OwnerSyncStore::load(dir.path()).await.expect("restart");
    let outcome = store.commit_batch(vec![device_record()], &owner()).await;
    assert_eq!(outcome.expect("again").accepted.len(), 1, "new again");
}

/// P2: a caller cancelled while its register write is in flight keeps
/// the canonical gate held until the write has landed.
#[tokio::test]
async fn a_cancelled_commit_holds_the_gate_until_its_write_lands() {
    let (dir, store, _) = seeded().await;
    let home = SyncValue::HomePointer {
        group_id: "g".into(),
        policy: GroupPolicy::default(),
        roster: vec![],
        primary_agent: String::new(),
        provisioned_at_ms: 1,
    };
    let home = sign(SyncKind::HomePointer, HOME_POINTER_KEY, home, 1);
    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    OwnerSyncStore::arm_pause(&store.register_write_pause, reached_tx, release_rx);
    let committer = Arc::clone(&store);
    let batch = vec![home, device_record()];
    let task = tokio::spawn(async move { committer.commit_batch(batch, &owner()).await });
    reached_rx.await.expect("the write is in flight");
    task.abort();
    assert!(task.await.is_err(), "the caller is cancelled");

    let gate_free = store.canonical_home_gate.try_write().is_ok();
    let _ = release_tx.send(());
    assert!(!gate_free, "the gate is held while the write is in flight");

    let gate = store.canonical_home_gate.write();
    let landed = tokio::time::timeout(std::time::Duration::from_secs(10), gate).await;
    let _gate = landed.expect("the gate is released once the write lands");
    let memory = store.records_snapshot().await;
    assert_eq!(devices(&memory), 1, "the write landed");
    assert_reload(dir.path(), &memory).await;
}

/// The register has a record of `kind` with the key of `machine(seed)`.
fn holds(records: &[VersionedRecord], kind: SyncKind, seed: u8) -> bool {
    let key = hex::encode(machine(seed).0);
    records.iter().any(|r| r.kind == kind && r.key == key)
}

/// Copy the sync directory of `from` to a new directory: the files of a
/// process that stops now.
fn copy_sync_dir(from: &Path) -> tempfile::TempDir {
    let to = tempfile::tempdir().expect("tmpdir");
    std::fs::create_dir_all(to.path().join(SYNC_DIR)).expect("sync dir");
    let entries = std::fs::read_dir(from.join(SYNC_DIR)).expect("read sync dir");
    for entry in entries {
        let entry = entry.expect("entry");
        if entry.file_type().expect("file type").is_file() {
            let target = to.path().join(SYNC_DIR).join(entry.file_name());
            std::fs::copy(entry.path(), target).expect("copy");
        }
    }
    to
}

/// Review of #1886: `RECORDS_FILE` is renamed before
/// `ENROLLMENT_RECORDS_FILE`. A stop between the two renames stores the
/// older kinds only, and the kind 0x05 record is new again after it.
#[tokio::test]
async fn records_file_is_renamed_before_the_enrollment_file() {
    let (dir, store, _) = seeded().await;
    let enrollment_path = dir.path().join(SYNC_DIR).join(ENROLLMENT_RECORDS_FILE);
    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    crate::profile::journal_faults::pause_next_rename(&enrollment_path, reached_tx, release_rx);
    let committer = Arc::clone(&store);
    let task = tokio::spawn(async move { committer.commit_batch(mixed(), &owner()).await });
    let reached = tokio::time::timeout(std::time::Duration::from_secs(10), reached_rx).await;
    reached
        .expect("the enrollment rename is reached")
        .expect("hook");

    // Between the two renames.
    let records = file(dir.path(), RECORDS_FILE);
    assert!(
        holds(&records, SyncKind::MachineNames, 2),
        "records.json is renamed first"
    );
    let enrollment = file(dir.path(), ENROLLMENT_RECORDS_FILE);
    assert_eq!(
        devices(&enrollment),
        0,
        "enrollment file is not renamed yet"
    );

    // A process that stops here.
    let stopped = copy_sync_dir(dir.path());
    let restarted = OwnerSyncStore::load(stopped.path()).await.expect("load");
    let memory = restarted.records_snapshot().await;
    assert!(holds(&memory, SyncKind::MachineNames, 2), "older kind");
    assert_eq!(devices(&memory), 0, "no kind 0x05 record");
    let again = restarted
        .commit_batch(vec![device_record()], &owner())
        .await;
    let again = again.expect("again");
    assert_eq!((again.accepted.len(), again.superseded), (1, 0), "new");

    release_tx.send(()).expect("release the rename");
    let done = tokio::time::timeout(std::time::Duration::from_secs(10), task).await;
    let outcome = done
        .expect("the commit ends")
        .expect("task")
        .expect("commit");
    assert_eq!(outcome.accepted.len(), 2, "both parts accepted");
    let memory = store.records_snapshot().await;
    assert_eq!(devices(&memory), 1, "the 0x05 record is stored");
    assert!(holds(&memory, SyncKind::MachineNames, 2));
    assert_eq!(devices(&file(dir.path(), ENROLLMENT_RECORDS_FILE)), 1);
    assert_reload(dir.path(), &memory).await;
}

/// Review of #1886: both files are renamed and a later fsync fails.
/// Memory takes the new register, 0x05 included, and the store is
/// poisoned.
#[tokio::test]
async fn a_failed_fsync_after_both_renames_keeps_next_and_poisons() {
    let (dir, store, _) = seeded().await;
    store.set_fail_after_rename_for_testing(true);
    let failed = store.commit_batch(mixed(), &owner()).await;
    store.set_fail_after_rename_for_testing(false);
    assert!(matches!(failed, Err(SyncError::Poisoned(_))), "{failed:?}");
    assert!(store.poisoned_reason().is_some(), "store is poisoned");
    let memory = store.records_snapshot().await;
    assert_eq!(
        memory.len(),
        3,
        "next: two names records and the 0x05 record"
    );
    assert_eq!(devices(&memory), 1, "memory holds the 0x05 record");
    let records = file(dir.path(), RECORDS_FILE);
    assert!(
        holds(&records, SyncKind::MachineNames, 2),
        "new older kinds"
    );
    assert_eq!(devices(&records), 0);
    let enrollment = file(dir.path(), ENROLLMENT_RECORDS_FILE);
    assert_eq!(
        (enrollment.len(), devices(&enrollment)),
        (1, 1),
        "new 0x05 part"
    );
    assert_eq!(temp_files(dir.path()), 0, "no temp file is left");
    assert_reload(dir.path(), &memory).await;
}

/// Review of #1886: when the first rename fails, neither file changes,
/// memory stays pre-batch and no temp file is left. A directory at
/// `RECORDS_FILE` makes the rename fail.
#[tokio::test]
async fn a_failed_first_rename_removes_both_temp_files() {
    let (dir, store, before) = seeded().await;
    let records_path = dir.path().join(SYNC_DIR).join(RECORDS_FILE);
    std::fs::remove_file(&records_path).expect("remove records.json");
    std::fs::create_dir(&records_path).expect("directory");
    std::fs::write(records_path.join("keep"), b"x").expect("non-empty");
    let failed = store.commit_batch(mixed(), &owner()).await;
    assert!(matches!(failed, Err(SyncError::Io(_))), "{failed:?}");
    assert!(store.poisoned_reason().is_none(), "not poisoned");
    assert_eq!(
        store.records_snapshot().await,
        before,
        "memory is pre-batch"
    );
    assert!(records_path.is_dir(), "records.json is not replaced");
    assert!(file(dir.path(), ENROLLMENT_RECORDS_FILE).is_empty());
    assert_eq!(temp_files(dir.path()), 0, "no temp file is left");
}

/// Review of #1886: a write with no enrollment change does not consume
/// the enrollment injections.
#[tokio::test]
async fn enrollment_injections_stay_armed_without_an_enrollment_change() {
    let (_dir, store, _) = seeded().await;
    store.fail_next_enrollment_rename.store(true, Relaxed);
    let names_only = store.commit_batch(vec![names_record(3)], &owner()).await;
    assert_eq!(names_only.expect("names only").accepted.len(), 1);
    let failed = store.commit_batch(mixed(), &owner()).await;
    assert!(matches!(failed, Err(SyncError::Poisoned(_))), "{failed:?}");
}

/// A mixed batch puts each part in its own file; a reload is the
/// register in memory.
#[tokio::test]
async fn a_mixed_batch_writes_each_part_to_its_own_file() {
    let (dir, store, _) = seeded().await;
    let outcome = store.commit_batch(mixed(), &owner()).await;
    assert_eq!(outcome.expect("commit").accepted.len(), 2);
    let records = file(dir.path(), RECORDS_FILE);
    assert_eq!(records.len(), 2);
    assert_eq!(devices(&records), 0, "records.json holds no kind 0x05");
    let enrollment = file(dir.path(), ENROLLMENT_RECORDS_FILE);
    assert_eq!((enrollment.len(), devices(&enrollment)), (1, 1));
    assert_eq!(temp_files(dir.path()), 0);
    assert_reload(dir.path(), &store.records_snapshot().await).await;
}
