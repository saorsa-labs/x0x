//! Durable pre-merge intents and receipts for explicit legacy Wiki/Web store
//! imports.
//!
//! An intent binds an idempotency key to the exact reviewed source snapshot
//! BEFORE any canonical destination mutation, so a crash or receipt-append
//! failure after the merge can still finish the original import even if the
//! on-disk legacy source changes afterwards. A receipt is the completed
//! local-import record and supersedes any intent for the same key.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

const RECEIPT_VERSION: u8 = 1;
const INTENT_VERSION: u8 = 1;
const INTENT_DIR_NAME: &str = "legacy-page-import-intents-v1";
const MAX_LISTED_INTENTS: usize = 128;
const MAX_LISTED_INTENT_BYTES: u64 = 64 * 1024 * 1024;

static JOURNAL_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static INTENT_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
#[cfg(test)]
static FAIL_APPEND_KEYS: LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static FAIL_MARK_KEYS: LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static FAIL_INTENT_KEYS: LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static FAIL_INTENT_DIR_SYNC_KEYS: LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static INTENT_DIR_SYNC_TARGETS: LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, PathBuf>>,
> = LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct LegacyImportReceipt {
    pub version: u8,
    pub idempotency_key: String,
    pub group_id: String,
    pub app: String,
    pub source_store_id: String,
    pub source_digest: String,
    pub endorser: String,
    pub authority_binding: String,
    pub destination_digest_before: String,
    pub destination_digest_after: String,
    pub imported_at_ms: u64,
    /// When every retained frame was accepted by this daemon's local pubsub.
    /// This is not peer delivery, assembly, persistence, or acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_accepted_at_ms: Option<u64>,
}

pub(super) struct LegacyImportReceiptInput {
    pub idempotency_key: String,
    pub group_id: String,
    pub app: String,
    pub source_store_id: String,
    pub source_digest: String,
    pub endorser: String,
    pub authority_binding: String,
    pub destination_digest_before: String,
    pub destination_digest_after: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LegacyImportJournal {
    #[serde(default)]
    receipts: Vec<LegacyImportReceipt>,
}

pub(super) fn journal_path(kv_state_dir: &Path) -> PathBuf {
    kv_state_dir.join("legacy-page-import-receipts-v1.json")
}

pub(super) async fn read_receipts(path: &Path) -> std::io::Result<Vec<LegacyImportReceipt>> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let journal: LegacyImportJournal = serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if journal
        .receipts
        .iter()
        .any(|receipt| receipt.version != RECEIPT_VERSION)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported legacy import receipt version",
        ));
    }
    Ok(journal.receipts)
}

pub(super) async fn append_receipt(
    path: &Path,
    receipt: LegacyImportReceipt,
) -> std::io::Result<()> {
    // Receipts for every group share one journal. Per-import and per-group
    // locks cannot prevent two unrelated imports from losing each other's
    // read-modify-write update.
    let _journal_guard = JOURNAL_LOCK.lock().await;
    let mut receipts = read_receipts(path).await?;
    if let Some(existing) = receipts
        .iter()
        .find(|existing| existing.idempotency_key == receipt.idempotency_key)
    {
        return if existing == &receipt {
            sync_parent_directory(path).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "idempotency key already binds different import arguments",
            ))
        };
    }
    #[cfg(test)]
    if FAIL_APPEND_KEYS
        .lock()
        .map(|mut keys| keys.remove(receipt.idempotency_key.as_str()))
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected receipt append failure",
        ));
    }
    receipts.push(receipt);
    let bytes = serde_json::to_vec_pretty(&LegacyImportJournal { receipts })
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(path, &bytes).await
}

pub(super) async fn mark_publish_accepted(
    path: &Path,
    idempotency_key: &str,
) -> std::io::Result<LegacyImportReceipt> {
    let _journal_guard = JOURNAL_LOCK.lock().await;
    let mut receipts = read_receipts(path).await?;
    let receipt = receipts
        .iter_mut()
        .find(|receipt| receipt.idempotency_key == idempotency_key)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "legacy import receipt disappeared before publication update",
            )
        })?;
    if receipt.publish_accepted_at_ms.is_none() {
        receipt.publish_accepted_at_ms = Some(now_ms());
    }
    let updated = receipt.clone();
    #[cfg(test)]
    if FAIL_MARK_KEYS
        .lock()
        .map(|mut keys| keys.remove(idempotency_key))
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected publication receipt update failure",
        ));
    }
    let bytes = serde_json::to_vec_pretty(&LegacyImportJournal { receipts })
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(path, &bytes).await?;
    Ok(updated)
}

/// Durable record of a REVIEWED legacy source, written before any canonical
/// destination mutation. The exact snapshot bytes the operator reviewed are
/// preserved so a retry after a merge-persist or receipt-append failure — or
/// after a daemon restart — can finish the ORIGINAL import even if the
/// on-disk legacy source is edited in between. An intent is not an import:
/// only a receipt records a completed local import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct LegacyImportIntent {
    pub version: u8,
    pub idempotency_key: String,
    pub group_id: String,
    pub app: String,
    pub source_store_id: String,
    pub source_digest: String,
    pub endorser: String,
    pub authority_binding: String,
    source_snapshot_b64: String,
    created_at_ms: u64,
}

pub(super) struct LegacyImportIntentInput {
    pub idempotency_key: String,
    pub group_id: String,
    pub app: String,
    pub source_store_id: String,
    pub source_digest: String,
    pub endorser: String,
    pub authority_binding: String,
    pub source_snapshot: Vec<u8>,
}

impl LegacyImportIntent {
    /// Decode the preserved reviewed snapshot. An error means the journal
    /// entry is corrupt or tampered with; recovery must refuse rather than
    /// merge unknown bytes.
    pub(super) fn source_snapshot(&self) -> std::io::Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(self.source_snapshot_b64.as_bytes())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }

    /// Argument equality ignoring the creation timestamp, so a retried
    /// identical write is idempotent while any changed binding conflicts.
    fn binds_same_arguments(&self, other: &LegacyImportIntent) -> bool {
        self.version == other.version
            && self.idempotency_key == other.idempotency_key
            && self.group_id == other.group_id
            && self.app == other.app
            && self.source_store_id == other.source_store_id
            && self.source_digest == other.source_digest
            && self.endorser == other.endorser
            && self.authority_binding == other.authority_binding
            && self.source_snapshot_b64 == other.source_snapshot_b64
    }
}

/// One intent file per idempotency key (blake3 of the key), so unrelated
/// imports never contend on a shared file; same-key callers are already
/// serialized by the route's reservation lock.
pub(super) fn intent_path(kv_state_dir: &Path, idempotency_key: &str) -> PathBuf {
    let key_digest = hex::encode(blake3::hash(idempotency_key.as_bytes()).as_bytes());
    kv_state_dir
        .join(INTENT_DIR_NAME)
        .join(format!("{key_digest}.json"))
}

async fn read_intent_file(path: &Path) -> std::io::Result<Option<LegacyImportIntent>> {
    use tokio::io::AsyncReadExt;
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(MAX_LISTED_INTENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_LISTED_INTENT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "legacy import intent exceeds the listing byte limit",
        ));
    }
    let intent: LegacyImportIntent = serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if intent.version != INTENT_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported legacy import intent version",
        ));
    }
    Ok(Some(intent))
}

/// Read every durable, unsettled import intent with bounded file-count and
/// aggregate-byte custody. Corrupt or unexpected entries fail the listing;
/// recovery must not silently hide a valid pending import.
pub(super) async fn read_intents(kv_state_dir: &Path) -> std::io::Result<Vec<LegacyImportIntent>> {
    let directory = kv_state_dir.join(INTENT_DIR_NAME);
    let mut entries = match tokio::fs::read_dir(&directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut paths = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "legacy import intent directory contains a non-file entry",
            ));
        }
        paths.push(entry.path());
        if paths.len() > MAX_LISTED_INTENTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "legacy import intent count exceeds the listing limit",
            ));
        }
    }
    paths.sort();
    let mut total_bytes = 0_u64;
    let mut intents = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = tokio::fs::metadata(&path).await?;
        total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "intent byte count overflow",
            )
        })?;
        if total_bytes > MAX_LISTED_INTENT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "legacy import intents exceed the aggregate listing byte limit",
            ));
        }
        let intent = read_intent_file(&path).await?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "legacy import intent disappeared",
            )
        })?;
        if intent_path(kv_state_dir, &intent.idempotency_key) != path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "legacy import intent filename does not match its idempotency key",
            ));
        }
        intents.push(intent);
    }
    Ok(intents)
}

pub(super) async fn read_intent(
    kv_state_dir: &Path,
    idempotency_key: &str,
) -> std::io::Result<Option<LegacyImportIntent>> {
    read_intent_file(&intent_path(kv_state_dir, idempotency_key)).await
}

/// Durably record the intent BEFORE any canonical destination mutation. The
/// single atomic write covers metadata and the preserved snapshot together,
/// so a crash leaves either the complete intent or no intent at all. On
/// success the intent directory's entry in `kv_state_dir` is also synced, so
/// a power loss cannot unlink the whole intents directory after the caller
/// has been told the intent is durable.
pub(super) async fn write_intent(
    kv_state_dir: &Path,
    input: LegacyImportIntentInput,
) -> std::io::Result<()> {
    let path = intent_path(kv_state_dir, &input.idempotency_key);
    let intent = LegacyImportIntent {
        version: INTENT_VERSION,
        source_snapshot_b64: base64::engine::general_purpose::STANDARD
            .encode(&input.source_snapshot),
        created_at_ms: now_ms(),
        idempotency_key: input.idempotency_key,
        group_id: input.group_id,
        app: input.app,
        source_store_id: input.source_store_id,
        source_digest: input.source_digest,
        endorser: input.endorser,
        authority_binding: input.authority_binding,
    };
    let bytes = serde_json::to_vec_pretty(&intent)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let _intent_guard = INTENT_LOCK.lock().await;
    if let Some(existing) = read_intent_file(&path).await? {
        if existing.binds_same_arguments(&intent) {
            // Identical-argument retry: the file is already on disk, but its
            // durability proof must complete before reporting success.
            sync_parent_directory(&path).await?;
            return sync_intent_directory_entry(kv_state_dir, &intent.idempotency_key).await;
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "idempotency key already binds different import arguments",
        ));
    }
    let existing_intents = read_intents(kv_state_dir).await?;
    let mut existing_bytes = 0_u64;
    for existing in &existing_intents {
        let metadata =
            tokio::fs::metadata(intent_path(kv_state_dir, &existing.idempotency_key)).await?;
        existing_bytes = existing_bytes.checked_add(metadata.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "intent byte count overflow",
            )
        })?;
    }
    if existing_intents.len() >= MAX_LISTED_INTENTS
        || existing_bytes
            .checked_add(bytes.len() as u64)
            .is_none_or(|projected| projected > MAX_LISTED_INTENT_BYTES)
    {
        return Err(std::io::Error::other(
            "legacy import intent capacity is exhausted; settle a pending import before starting another",
        ));
    }
    #[cfg(test)]
    if FAIL_INTENT_KEYS
        .lock()
        .map(|mut keys| keys.remove(intent.idempotency_key.as_str()))
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected intent persistence failure",
        ));
    }
    write_atomic(&path, &bytes).await?;
    sync_intent_directory_entry(kv_state_dir, &intent.idempotency_key).await
}

/// Remove a settled intent: once the receipt exists it is the sole durable
/// idempotency binding and the preserved snapshot is redundant. A missing
/// file is success (idempotent). Callers treat removal as best-effort — a
/// stale intent never wins over a receipt and the next retry retries it.
pub(super) async fn remove_intent(
    kv_state_dir: &Path,
    idempotency_key: &str,
) -> std::io::Result<()> {
    let _intent_guard = INTENT_LOCK.lock().await;
    let path = intent_path(kv_state_dir, idempotency_key);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => sync_parent_directory(&path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Fsync `kv_state_dir` ITSELF so the intent directory's entry is durably
/// linked. `write_atomic` fsyncs the intent directory (the rename target's
/// parent), but a NEWLY CREATED directory only becomes durable once its
/// entry in the containing directory — `kv_state_dir` — is synced; a power
/// loss could otherwise unlink the entire intents directory while the
/// canonical merge persists, reopening the exact hole the intent exists to
/// close.
///
/// The one-shot test gate is consumed BEFORE the real sync runs, and the
/// directory that was ACTUALLY synced (returned by `sync_directory_exact`)
/// is recorded per key, so tests can prove the sync targets `kv_state_dir`
/// itself — never its parent.
async fn sync_intent_directory_entry(
    kv_state_dir: &Path,
    idempotency_key: &str,
) -> std::io::Result<()> {
    #[cfg(test)]
    let injected = FAIL_INTENT_DIR_SYNC_KEYS
        .lock()
        .map(|mut keys| keys.remove(idempotency_key))
        .unwrap_or(false);
    #[cfg(test)]
    let synced = sync_directory_exact(kv_state_dir).await?;
    #[cfg(not(test))]
    sync_directory_exact(kv_state_dir).await?;
    #[cfg(test)]
    if let Ok(mut targets) = INTENT_DIR_SYNC_TARGETS.lock() {
        targets.insert(idempotency_key.to_string(), synced);
    }
    #[cfg(not(test))]
    let _ = idempotency_key;
    #[cfg(test)]
    if injected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected intent directory sync failure",
        ));
    }
    Ok(())
}

/// Prove an already-persisted intent is fully durable before a retry may
/// mutate the canonical destination: the intent file's entry in the intents
/// directory AND the intents directory's entry in `kv_state_dir` must both
/// be synced. This closes the window where a prior `write_intent` persisted
/// and synced the intent file but crashed before `kv_state_dir` was synced.
pub(super) async fn ensure_intent_durable(
    kv_state_dir: &Path,
    idempotency_key: &str,
) -> std::io::Result<()> {
    let path = intent_path(kv_state_dir, idempotency_key);
    sync_parent_directory(&path).await?;
    sync_intent_directory_entry(kv_state_dir, idempotency_key).await
}

#[cfg(test)]
pub(super) fn fail_next_append_for_test(idempotency_key: &str) {
    if let Ok(mut keys) = FAIL_APPEND_KEYS.lock() {
        keys.insert(idempotency_key.to_string());
    }
}

#[cfg(test)]
pub(super) fn fail_next_mark_for_test(idempotency_key: &str) {
    if let Ok(mut keys) = FAIL_MARK_KEYS.lock() {
        keys.insert(idempotency_key.to_string());
    }
}

#[cfg(test)]
pub(super) fn fail_next_intent_for_test(idempotency_key: &str) {
    if let Ok(mut keys) = FAIL_INTENT_KEYS.lock() {
        keys.insert(idempotency_key.to_string());
    }
}

#[cfg(test)]
pub(super) fn fail_next_intent_dir_sync_for_test(idempotency_key: &str) {
    if let Ok(mut keys) = FAIL_INTENT_DIR_SYNC_KEYS.lock() {
        keys.insert(idempotency_key.to_string());
    }
}

/// The directory the intent durability sync ACTUALLY fsynced for this key.
/// Recorded from `sync_directory_exact`'s return value — never from the
/// caller's parameter — so a test asserting this equals `kv_state_dir`
/// fails if the implementation ever syncs the wrong directory (e.g. the
/// parent of `kv_state_dir`).
#[cfg(test)]
pub(super) fn intent_dir_sync_target_for_test(idempotency_key: &str) -> Option<PathBuf> {
    INTENT_DIR_SYNC_TARGETS
        .lock()
        .ok()
        .and_then(|targets| targets.get(idempotency_key).cloned())
}

pub(super) fn new_receipt(input: LegacyImportReceiptInput) -> LegacyImportReceipt {
    LegacyImportReceipt {
        version: RECEIPT_VERSION,
        idempotency_key: input.idempotency_key,
        group_id: input.group_id,
        app: input.app,
        source_store_id: input.source_store_id,
        source_digest: input.source_digest,
        endorser: input.endorser,
        authority_binding: input.authority_binding,
        destination_digest_before: input.destination_digest_before,
        destination_digest_after: input.destination_digest_after,
        imported_at_ms: now_ms(),
        publish_accepted_at_ms: None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let temporary = PathBuf::from(temporary);
    let result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, path).await?;
        sync_parent_directory(path).await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result
}

async fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) => sync_directory_exact(parent).await.map(|_| ()),
        None => Ok(()),
    }
}

/// Fsync EXACTLY `dir` — never its parent — and return the directory that
/// was actually synced, so callers can record the true OS-sync target.
/// (`sync_parent_directory` hops to the parent; using it to sync a specific
/// directory such as `kv_state_dir` silently syncs the WRONG directory.)
async fn sync_directory_exact(dir: &Path) -> std::io::Result<PathBuf> {
    let target = dir.to_path_buf();
    #[cfg(unix)]
    {
        let opened = target.clone();
        tokio::task::spawn_blocking(move || std::fs::File::open(&opened)?.sync_all())
            .await
            .map_err(std::io::Error::other)??;
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(key: &str, group: &str) -> LegacyImportReceipt {
        new_receipt(LegacyImportReceiptInput {
            idempotency_key: key.to_string(),
            group_id: group.to_string(),
            app: "wiki".to_string(),
            source_store_id: format!("source-{group}"),
            source_digest: format!("digest-{group}"),
            endorser: "endorser".to_string(),
            authority_binding: "binding".to_string(),
            destination_digest_before: "before".to_string(),
            destination_digest_after: "after".to_string(),
        })
    }

    #[tokio::test]
    async fn journal_preserves_concurrent_cross_group_receipts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_path(dir.path());
        let (a, b) = tokio::join!(
            append_receipt(&path, receipt("key-a", "group-a")),
            append_receipt(&path, receipt("key-b", "group-b")),
        );
        a.expect("append a");
        b.expect("append b");
        let saved = read_receipts(&path).await.expect("read journal");
        assert_eq!(saved.len(), 2);
        assert!(saved.iter().any(|item| item.idempotency_key == "key-a"));
        assert!(saved.iter().any(|item| item.idempotency_key == "key-b"));
    }

    #[tokio::test]
    async fn independent_fault_injections_are_keyed_and_one_shot() {
        let append_dir = tempfile::tempdir().expect("append tempdir");
        let append_path = journal_path(append_dir.path());
        fail_next_append_for_test("append-a");
        fail_next_append_for_test("append-b");
        for key in ["append-a", "append-b"] {
            assert_eq!(
                append_receipt(&append_path, receipt(key, key))
                    .await
                    .expect_err("each armed append fails")
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            append_receipt(&append_path, receipt(key, key))
                .await
                .expect("each append fault is consumed once");
        }

        fail_next_mark_for_test("append-a");
        fail_next_mark_for_test("append-b");
        for key in ["append-a", "append-b"] {
            assert_eq!(
                mark_publish_accepted(&append_path, key)
                    .await
                    .expect_err("each armed mark fails")
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            mark_publish_accepted(&append_path, key)
                .await
                .expect("each mark fault is consumed once");
        }

        let intent_dir = tempfile::tempdir().expect("intent tempdir");
        fail_next_intent_for_test("intent-a");
        fail_next_intent_for_test("intent-b");
        for key in ["intent-a", "intent-b"] {
            assert_eq!(
                write_intent(intent_dir.path(), intent_input(key, key))
                    .await
                    .expect_err("each armed intent write fails")
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            write_intent(intent_dir.path(), intent_input(key, key))
                .await
                .expect("each intent fault is consumed once");
        }

        fail_next_intent_dir_sync_for_test("sync-a");
        fail_next_intent_dir_sync_for_test("sync-b");
        for key in ["sync-a", "sync-b"] {
            assert_eq!(
                write_intent(intent_dir.path(), intent_input(key, key))
                    .await
                    .expect_err("each armed directory sync fails")
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            ensure_intent_durable(intent_dir.path(), key)
                .await
                .expect("each directory-sync fault is consumed once");
        }
    }

    #[tokio::test]
    async fn journal_rejects_same_key_with_different_binding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_path(dir.path());
        append_receipt(&path, receipt("same", "group-a"))
            .await
            .expect("first receipt");
        let error = append_receipt(&path, receipt("same", "group-b"))
            .await
            .expect_err("changed binding must conflict");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[tokio::test]
    async fn publication_acceptance_update_is_atomic_and_retryable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_path(dir.path());
        append_receipt(&path, receipt("pending", "group-a"))
            .await
            .expect("append pending receipt");
        fail_next_mark_for_test("pending");
        assert!(
            mark_publish_accepted(&path, "pending").await.is_err(),
            "injected atomic update failure is surfaced"
        );
        let pending = read_receipts(&path).await.expect("read pending receipt");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].publish_accepted_at_ms, None);

        let accepted = mark_publish_accepted(&path, "pending")
            .await
            .expect("retry publication acceptance update");
        assert!(accepted.publish_accepted_at_ms.is_some());
        let saved = read_receipts(&path).await.expect("read accepted receipt");
        assert_eq!(saved, vec![accepted]);
    }

    fn intent_input(key: &str, group: &str) -> LegacyImportIntentInput {
        LegacyImportIntentInput {
            idempotency_key: key.to_string(),
            group_id: group.to_string(),
            app: "wiki".to_string(),
            source_store_id: format!("source-{group}"),
            source_digest: format!("digest-{group}"),
            endorser: "endorser".to_string(),
            authority_binding: "binding".to_string(),
            source_snapshot: b"reviewed-snapshot-bytes".to_vec(),
        }
    }

    #[tokio::test]
    async fn intent_preserves_reviewed_snapshot_and_settles_idempotently() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_intent(dir.path(), intent_input("key", "group-a"))
            .await
            .expect("write intent");
        let saved = read_intent(dir.path(), "key")
            .await
            .expect("read intent")
            .expect("intent present");
        assert_eq!(saved.source_digest, "digest-group-a");
        assert_eq!(
            saved.source_snapshot().expect("decode snapshot"),
            b"reviewed-snapshot-bytes"
        );
        // An identical rewrite (only the timestamp differs) is idempotent;
        // any changed binding under the same key conflicts.
        write_intent(dir.path(), intent_input("key", "group-a"))
            .await
            .expect("idempotent rewrite");
        let error = write_intent(dir.path(), intent_input("key", "group-b"))
            .await
            .expect_err("changed binding must conflict");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

        remove_intent(dir.path(), "key")
            .await
            .expect("remove settled intent");
        assert!(read_intent(dir.path(), "key")
            .await
            .expect("read after remove")
            .is_none());
        remove_intent(dir.path(), "key")
            .await
            .expect("removal is idempotent");
    }

    #[tokio::test]
    async fn intent_injected_failure_writes_no_partial_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        fail_next_intent_for_test("key");
        assert!(
            write_intent(dir.path(), intent_input("key", "group-a"))
                .await
                .is_err(),
            "injected intent persistence failure is surfaced"
        );
        assert!(
            read_intent(dir.path(), "key")
                .await
                .expect("read after failure")
                .is_none(),
            "failed intent write leaves no partial file"
        );
        write_intent(dir.path(), intent_input("key", "group-a"))
            .await
            .expect("retry writes the intent");
    }

    #[tokio::test]
    async fn intent_directory_entry_sync_failure_blocks_durability() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The atomic file write succeeds; only the kv_state_dir sync fails.
        fail_next_intent_dir_sync_for_test("key");
        assert!(
            write_intent(dir.path(), intent_input("key", "group-a"))
                .await
                .is_err(),
            "an unproven directory entry must fail write_intent"
        );
        // Path-target control: the durability sync must have fsynced
        // kv_state_dir ITSELF (here, the tempdir), never its parent — the
        // exact regression sync_parent_directory(kv_state_dir) introduced.
        let target = intent_dir_sync_target_for_test("key").expect("target recorded");
        assert_eq!(
            target,
            dir.path(),
            "intent durability must fsync kv_state_dir itself"
        );
        assert_ne!(
            target,
            dir.path().parent().expect("tempdir parent"),
            "syncing kv_state_dir's PARENT leaves the intents directory entry unlinked"
        );
        assert!(
            read_intent(dir.path(), "key")
                .await
                .expect("read after sync fault")
                .is_some(),
            "the intent file itself is on disk, only its durability is unproven"
        );
        // A retry that finds the identical intent must still complete the
        // sync before reporting success — inject the fault again.
        fail_next_intent_dir_sync_for_test("key");
        assert!(
            write_intent(dir.path(), intent_input("key", "group-a"))
                .await
                .is_err(),
            "identical-argument retry must not skip the directory sync"
        );
        ensure_intent_durable(dir.path(), "key")
            .await
            .expect("unfaulted durability check succeeds");
        write_intent(dir.path(), intent_input("key", "group-a"))
            .await
            .expect("identical rewrite succeeds once the sync is proven");
    }

    #[tokio::test]
    async fn intent_admission_is_atomic_at_capacity_and_identical_retry_survives() {
        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..(MAX_LISTED_INTENTS - 1) {
            write_intent(
                dir.path(),
                intent_input(&format!("seed-{index}"), "group-a"),
            )
            .await
            .expect("seed intent below capacity");
        }
        let (left, right) = tokio::join!(
            write_intent(dir.path(), intent_input("boundary-left", "group-a")),
            write_intent(dir.path(), intent_input("boundary-right", "group-a")),
        );
        let left_accepted = left.is_ok();
        let right_accepted = right.is_ok();
        assert_eq!(
            usize::from(left_accepted) + usize::from(right_accepted),
            1,
            "serialized new-key admission must accept exactly one boundary caller"
        );
        let rejected = if left_accepted {
            right.expect_err("right rejected")
        } else {
            left.expect_err("left rejected")
        };
        assert!(
            rejected.to_string().contains("capacity is exhausted"),
            "capacity refusal must be truthful: {rejected}"
        );
        let accepted_key = if left_accepted {
            "boundary-left"
        } else {
            "boundary-right"
        };
        write_intent(dir.path(), intent_input(accepted_key, "group-a"))
            .await
            .expect("identical retry remains available at capacity");
        assert_eq!(
            read_intents(dir.path())
                .await
                .expect("capacity remains listable")
                .len(),
            MAX_LISTED_INTENTS
        );
    }

    #[tokio::test]
    async fn intent_listing_fails_closed_on_corruption_and_bounds() {
        let corrupt = tempfile::tempdir().expect("corrupt tempdir");
        let corrupt_path = intent_path(corrupt.path(), "corrupt");
        tokio::fs::create_dir_all(corrupt_path.parent().expect("intent parent"))
            .await
            .expect("create intent directory");
        tokio::fs::write(&corrupt_path, b"{}")
            .await
            .expect("write corrupt intent");
        assert!(
            read_intents(corrupt.path()).await.is_err(),
            "corrupt intent must fail the complete listing"
        );

        let crowded = tempfile::tempdir().expect("crowded tempdir");
        let intent_dir = crowded.path().join(INTENT_DIR_NAME);
        tokio::fs::create_dir_all(&intent_dir)
            .await
            .expect("create crowded intent directory");
        for index in 0..=MAX_LISTED_INTENTS {
            tokio::fs::write(intent_dir.join(format!("{index:064x}.json")), b"{}")
                .await
                .expect("write bounded fixture");
        }
        assert!(
            read_intents(crowded.path()).await.is_err(),
            "too many intent records must fail rather than hide recovery work"
        );

        let oversized = tempfile::tempdir().expect("oversized tempdir");
        let intent_dir = oversized.path().join(INTENT_DIR_NAME);
        tokio::fs::create_dir_all(&intent_dir)
            .await
            .expect("create oversized intent directory");
        let path = intent_dir.join(format!("{:064x}.json", 1));
        let file = std::fs::File::create(path).expect("create sparse intent");
        file.set_len(MAX_LISTED_INTENT_BYTES + 1)
            .expect("size sparse intent");
        assert!(
            read_intents(oversized.path()).await.is_err(),
            "aggregate intent bytes must be bounded before decoding"
        );
    }

    #[test]
    fn version_one_receipt_without_publication_field_decodes_pending() {
        let value = serde_json::json!({
            "version": 1,
            "idempotency_key": "old",
            "group_id": "group",
            "app": "wiki",
            "source_store_id": "source",
            "source_digest": "digest",
            "endorser": "endorser",
            "authority_binding": "binding",
            "destination_digest_before": "before",
            "destination_digest_after": "after",
            "imported_at_ms": 1
        });
        let receipt: LegacyImportReceipt =
            serde_json::from_value(value).expect("old v1 receipt remains readable");
        assert_eq!(receipt.publish_accepted_at_ms, None);
    }
}
