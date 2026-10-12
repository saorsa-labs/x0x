//! #1187: a parent-directory fsync failure AFTER the atomic rename (the
//! #1101 `DurableWriteError::AfterRename` case) at a named-groups durable
//! write must not make a restart disagree with what the API reported.
//!
//! Each test arms the #1101 path-scoped storage seam
//! (`storage::arm_fail_parent_dir_fsync_for_testing`) for ONE durable write,
//! runs the production transaction, and then runs the daemon's own startup
//! recovery on the same data directory, in `serve()` order
//! (`recover_treekem_named_journals`, `recover_home_suite_sidecar_journals`,
//! `load_named_groups_merged`, `restore_treekem_groups`). Two rules hold:
//!
//! - the state the running daemon serves after the call equals the state
//!   the restart loads;
//! - a success report means the new state; for a seal, whose callers roll
//!   the TreeKEM group back on error, a failure report means the old state.
//!
//! The sites (`src/server/routes/named_groups.rs`):
//! 1. the rebind legacy journal (`prepare_rebind_journal_for_groups`);
//! 2. `persist_treekem_snapshot_bytes`, in the rebind apply, the seal
//!    transaction and the startup replay;
//! 3. the seal legacy journal
//!    (`persist_treekem_and_named_groups_atomic_with_info`);
//! 4. the `.hsjournal` (`write_home_suite_sidecar_journal`), in both
//!    transactions.
//!
//! Inert: tempdirs only, no network config, no sockets.

use super::*;

// ---------------------------------------------------------------------------
// #1187 test seam: a path-scoped journal-discard failure.
// ---------------------------------------------------------------------------

/// Legacy journal paths whose rollback discard (`discard_rebind_journal`)
/// must fail. Path-scoped, like the #1101 storage seam: a test arms only
/// its own tempdir path, so concurrent tests in the same process are not
/// affected.
static FAIL_JOURNAL_DISCARD_FOR_TESTING: std::sync::Mutex<Vec<PathBuf>> =
    std::sync::Mutex::new(Vec::new());

/// Whether `discard_rebind_journal` must fail for `path` (#1187 seam).
pub(in crate::server) fn journal_discard_fails_for_testing(path: &FsPath) -> bool {
    FAIL_JOURNAL_DISCARD_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|armed| armed == path)
}

/// Disarms only its own path on drop, so a failed assertion cannot leak
/// the fault into another test.
struct FailJournalDiscardGuard {
    path: PathBuf,
}

fn arm_fail_journal_discard(path: &FsPath) -> FailJournalDiscardGuard {
    FAIL_JOURNAL_DISCARD_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(path.to_path_buf());
    FailJournalDiscardGuard {
        path: path.to_path_buf(),
    }
}

impl Drop for FailJournalDiscardGuard {
    fn drop(&mut self) {
        let mut armed = FAIL_JOURNAL_DISCARD_FOR_TESTING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(idx) = armed.iter().position(|p| *p == self.path) {
            armed.swap_remove(idx);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// What a restart loads from the data directory.
struct Restarted {
    merged: HashMap<String, x0x::groups::GroupInfo>,
    treekem: HashMap<String, Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>>,
}

/// Run the daemon's startup recovery on `state`'s data directory, in the
/// order `serve()` uses.
async fn restart(state: &AppState) -> Result<Restarted> {
    recover_treekem_named_journals(
        &state.named_groups_path,
        &state.home_suite_groups_path,
        &state.treekem_dir,
    )
    .await?;
    recover_home_suite_sidecar_journals(&state.home_suite_groups_path, &state.treekem_dir).await?;
    let merged =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    let treekem = restore_treekem_groups(&merged, state.agent.as_ref(), &state.treekem_dir).await;
    Ok(Restarted { merged, treekem })
}

async fn live_epoch(
    groups: &HashMap<String, Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>>,
    group_id: &str,
) -> Option<u64> {
    match groups.get(group_id) {
        Some(group) => Some(group.lock().await.epoch()),
        None => None,
    }
}

/// The record fields a rename changes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordView {
    name: String,
    state_revision: u64,
    state_hash: String,
}

impl RecordView {
    fn of(info: &x0x::groups::GroupInfo) -> Self {
        Self {
            name: info.name.clone(),
            state_revision: info.state_revision,
            state_hash: info.state_hash.clone(),
        }
    }
}

async fn served_record(state: &AppState, group_id: &str) -> Result<RecordView> {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .map(RecordView::of)
        .context("the daemon serves the group record")
}

/// A TreeKEM group whose baseline (named store and bound snapshot) is
/// durable on disk, with no journal left behind.
async fn rebind_fixture(byte: u8) -> Result<MemberJoinedTreeKemFixture> {
    let fixture = member_joined_treekem_fixture(byte, byte).await?;
    let baseline = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .cloned()
        .context("fixture record")?;
    assert_eq!(
        persist_named_group_info(&fixture.state, &fixture.group_id, baseline).await?,
        AtomicWriteOutcome::Durable,
        "baseline persist"
    );
    assert!(!treekem_journal_path(&fixture.state.treekem_dir, &fixture.group_id).exists());
    assert!(treekem_snapshot_path(&fixture.state.treekem_dir, &fixture.group_id).exists());
    Ok(fixture)
}

/// Rename the group through the production HTTP handler (a metadata-only
/// seal: the TreeKEM rebind path) and return the reported status.
async fn rename_via_api(fixture: &MemberJoinedTreeKemFixture, name: &str) -> StatusCode {
    update_named_group(
        State(Arc::clone(&fixture.state)),
        Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(fixture.group_id.clone()),
        Json(UpdateGroupRequest {
            name: Some(name.to_string()),
            description: None,
        }),
    )
    .await
    .into_response()
    .status()
}

/// The two #1187 rules for a rebind: the restart loads the record the
/// daemon served after the call, and a 200 means the new name.
async fn assert_rebind_restart_agrees(
    fixture: &MemberJoinedTreeKemFixture,
    status: StatusCode,
    new_name: &str,
) -> Result<Restarted> {
    let served = served_record(&fixture.state, &fixture.group_id).await?;
    let restarted = restart(&fixture.state).await?;
    let loaded = restarted
        .merged
        .get(&fixture.group_id)
        .map(RecordView::of)
        .context("the group record survives the restart")?;
    assert_eq!(
        loaded, served,
        "#1187: the restart must load the record the daemon served after the call \
         (status {status})"
    );
    if status == StatusCode::OK {
        assert_eq!(
            loaded.name, new_name,
            "#1187: a 200 must mean the new state is the one a restart loads"
        );
    }
    assert!(
        restarted.treekem.contains_key(&fixture.group_id),
        "the TreeKEM group restores after the restart (no #457 wedge)"
    );
    Ok(restarted)
}

/// A TreeKEM group in which this node is a member, with a durable baseline
/// at `base_epoch`, plus a real authority commit that adds one more member
/// and moves the group to `expected_epoch`.
struct SealFixture {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
    group_id: String,
    next: x0x::groups::GroupInfo,
    commit: Vec<u8>,
    base_epoch: u64,
    expected_epoch: u64,
    added_hex: String,
}

async fn seal_fixture(byte: u8) -> Result<SealFixture> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let group_id = format!("{byte:02x}").repeat(32);
    let group_id_bytes = hex::decode(&group_id)?;
    let authority = AgentId([byte; 32]);
    let authority_hex = hex::encode(authority.as_bytes());
    let mut authority_group =
        x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), authority, &[byte; 32])?;
    let local_id = state.agent.agent_id();
    let local_hex = hex::encode(local_id.as_bytes());
    let local_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let local_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(local_id, &local_seed)?;
    let local_add = authority_group.add_member(local_id, local_prepared.key_package_bytes())?;
    let joined = x0x::mls::TreeKemMlsGroup::join_from_welcome(local_prepared, &local_add.welcome)?;
    let base_epoch = joined.epoch();

    let mut info = treekem_metadata_group_info(authority, &group_id, &group_id);
    info.add_member(
        local_hex,
        x0x::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    info.state_revision = 1;
    info.secret_epoch = base_epoch;
    info.security_binding = Some(format!("treekem:epoch={base_epoch}"));
    info.recompute_state_hash();
    // The baseline goes through the same seal transaction (site 3), so it
    // is durable: named store, sidecar, snapshot, and no journal.
    install_joined_treekem_group_after_crypto_recheck(
        state.as_ref(),
        &group_id,
        info.clone(),
        joined,
        "issue1187_baseline",
    )
    .await?;
    assert!(treekem_snapshot_path(&state.treekem_dir, &group_id).exists());
    assert!(!treekem_journal_path(&state.treekem_dir, &group_id).exists());
    assert!(!treekem_home_suite_journal_path(&state.treekem_dir, &group_id).exists());

    let added = AgentId([byte.wrapping_add(1); 32]);
    let added_hex = hex::encode(added.as_bytes());
    let added_prepared =
        x0x::mls::TreeKemMlsGroup::prepare_member(added, &[byte.wrapping_add(1); 32])?;
    let add = authority_group.add_member(added, added_prepared.key_package_bytes())?;
    let expected_epoch = authority_group.epoch();
    assert!(expected_epoch > base_epoch);
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.add_member(
        added_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(authority_hex),
        None,
    );
    next.state_revision = info.state_revision.saturating_add(1);
    next.prev_state_hash = Some(info.state_hash.clone());
    next.secret_epoch = expected_epoch;
    next.security_binding = Some(format!("treekem:epoch={expected_epoch}"));
    next.recompute_state_hash();
    Ok(SealFixture {
        state,
        _dir: dir,
        group_id,
        next,
        commit: add.commit,
        base_epoch,
        expected_epoch,
        added_hex,
    })
}

/// Apply the authority commit through the production seal path (the
/// gossip `MemberAdded` apply calls this; on error it reports REJECTED).
async fn apply_seal(fixture: &SealFixture) -> anyhow::Result<()> {
    let group = fixture
        .state
        .treekem_groups
        .read()
        .await
        .get(&fixture.group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("baseline installed the TreeKEM group"))?;
    process_treekem_commit_after_crypto_recheck(
        fixture.state.as_ref(),
        &fixture.group_id,
        &fixture.next,
        group,
        &fixture.commit,
        fixture.expected_epoch,
        "issue1187_seal",
    )
    .await
}

/// (added member present, TreeKEM epoch).
type SealView = (bool, Option<u64>);

async fn served_seal_view(fixture: &SealFixture) -> SealView {
    let has_member = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .is_some_and(|info| info.has_active_member(&fixture.added_hex));
    let epoch = live_epoch(
        &*fixture.state.treekem_groups.read().await,
        &fixture.group_id,
    )
    .await;
    (has_member, epoch)
}

/// The two #1187 rules for a seal. Its callers roll the TreeKEM group back
/// on error, so an error must mean the old state, and Ok the new state.
async fn assert_seal_restart_agrees(
    fixture: &SealFixture,
    result: &anyhow::Result<()>,
) -> Result<()> {
    let served = served_seal_view(fixture).await;
    let restarted = restart(&fixture.state).await?;
    let loaded: SealView = (
        restarted
            .merged
            .get(&fixture.group_id)
            .is_some_and(|info| info.has_active_member(&fixture.added_hex)),
        live_epoch(&restarted.treekem, &fixture.group_id).await,
    );
    assert_eq!(
        loaded, served,
        "#1187: the restart must load the seal state the daemon served after the call \
         (result {result:?})"
    );
    let expected = if result.is_ok() {
        (true, Some(fixture.expected_epoch))
    } else {
        (false, Some(fixture.base_epoch))
    };
    assert_eq!(
        loaded, expected,
        "#1187: the reported outcome (result {result:?}) must be the state a restart loads"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Site 1: the rebind legacy journal (`prepare_rebind_journal_for_groups`).
// ---------------------------------------------------------------------------

/// The journal is the commit point. Once it is renamed into place, a
/// rollback has to delete it again, and nothing makes that delete durable.
/// So the transaction must complete and report the new state.
#[tokio::test]
async fn issue1187_site1_rebind_journal_after_rename_completes_the_rebind() -> Result<()> {
    let fixture = rebind_fixture(0x61).await?;
    let journal = treekem_journal_path(&fixture.state.treekem_dir, &fixture.group_id);
    let status = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&journal);
        rename_via_api(&fixture, "Site1 Journal In Place").await
    };
    assert_eq!(
        status,
        StatusCode::OK,
        "#1187 site 1: the journal crossed its rename, so the rebind must complete, not roll back"
    );
    assert_eq!(
        served_record(&fixture.state, &fixture.group_id).await?.name,
        "Site1 Journal In Place"
    );
    assert!(
        !journal.exists(),
        "the completed rebind consumes its journal"
    );
    assert_rebind_restart_agrees(&fixture, status, "Site1 Journal In Place").await?;
    Ok(())
}

/// The #1187 bug: the journal crossed its rename, the rollback then failed
/// to delete it, and the API reported a failure. A restart then replayed
/// the rebind that the API reported as failed.
#[tokio::test]
async fn issue1187_site1_rebind_journal_after_rename_with_failed_discard_restart_agrees(
) -> Result<()> {
    let fixture = rebind_fixture(0x62).await?;
    let journal = treekem_journal_path(&fixture.state.treekem_dir, &fixture.group_id);
    let status = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&journal);
        let _discard = arm_fail_journal_discard(&journal);
        rename_via_api(&fixture, "Site1 Discard Failed").await
    };
    assert_rebind_restart_agrees(&fixture, status, "Site1 Discard Failed").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Site 2: `persist_treekem_snapshot_bytes`.
// ---------------------------------------------------------------------------

/// Rebind apply: the snapshot crossed its rename, so the new snapshot is in
/// place. A journal kept for replay holds the snapshot from the time of the
/// rebind; after a later encrypt persists a newer ratchet state, a replay
/// of that old journal would load an older group state.
#[tokio::test]
async fn issue1187_site2_rebind_snapshot_after_rename_keeps_later_ratchet_across_restart(
) -> Result<()> {
    let fixture = rebind_fixture(0x63).await?;
    let snapshot = treekem_snapshot_path(&fixture.state.treekem_dir, &fixture.group_id);
    let status = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&snapshot);
        rename_via_api(&fixture, "Site2 Snapshot In Place").await
    };
    // The issue's claim: the rebind itself stays consistent across a
    // restart (the daemon already serves the new record).
    assert_eq!(
        served_record(&fixture.state, &fixture.group_id).await?.name,
        "Site2 Snapshot In Place"
    );
    // A secure send after the call: the API persists the advanced ratchet.
    let rebound = tokio::fs::read(&snapshot).await?;
    let persisted = {
        let mut guard = fixture.group.lock().await;
        guard.encrypt_message(b"issue1187 site 2")?;
        persist_treekem_snapshot_bound(&fixture.state, &fixture.group_id, &guard).await?;
        drop(guard);
        tokio::fs::read(&snapshot).await?
    };
    assert_ne!(
        persisted, rebound,
        "precondition: the encrypt advanced the persisted ratchet state"
    );
    assert_rebind_restart_agrees(&fixture, status, "Site2 Snapshot In Place").await?;
    assert_eq!(
        tokio::fs::read(&snapshot).await?,
        persisted,
        "#1187 site 2: the restart must keep the ratchet state the encrypt call persisted"
    );
    Ok(())
}

/// Seal transaction: the snapshot crossed its rename. Its callers roll the
/// TreeKEM group back on error, while the journals that a restart replays
/// stay on disk.
#[tokio::test]
async fn issue1187_site2_seal_snapshot_after_rename_restart_agrees() -> Result<()> {
    let fixture = seal_fixture(0x64).await?;
    let snapshot = treekem_snapshot_path(&fixture.state.treekem_dir, &fixture.group_id);
    let result = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&snapshot);
        apply_seal(&fixture).await
    };
    assert_seal_restart_agrees(&fixture, &result).await
}

/// Startup replay: the snapshot crossed its rename. A journal kept for the
/// next boot would overwrite the newer ratchet state that this boot
/// persists after the replay.
#[tokio::test]
async fn issue1187_site2_replay_snapshot_after_rename_consumes_the_journal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let treekem_dir = dir.path().join("treekem");
    tokio::fs::create_dir_all(&treekem_dir).await?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    let group_id = "c7".repeat(16);
    let journaled = sample_treekem_snapshot_envelope()?;
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id.clone(),
        named_groups_json: serde_json::to_string_pretty(&HashMap::from([(
            group_id.clone(),
            sample_treekem_group_info(&group_id, false),
        )]))?,
        snapshot_envelope: journaled.clone(),
    };
    let journal_path = treekem_journal_path(&treekem_dir, &group_id);
    x0x::storage::write_private_bytes(&journal_path, postcard::to_stdvec(&journal)?).await?;
    let snapshot_path = treekem_snapshot_path(&treekem_dir, &group_id);

    // Boot 1: the replay's snapshot write crosses its rename, and then the
    // directory fsync fails.
    {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&snapshot_path);
        recover_treekem_named_journals(&named_path, &sidecar_path, &treekem_dir).await?;
    }
    assert_eq!(
        tokio::fs::read(&snapshot_path).await?,
        journaled,
        "the replayed snapshot is in place"
    );
    // Later in boot 1, an encrypt persists a newer ratchet state under the
    // same binding.
    let mut newer = TREEKEM_DAEMON_SNAPSHOT_MAGIC.to_vec();
    newer.extend(postcard::to_stdvec(&TreeKemSnapshotEnvelope {
        version: TREEKEM_DAEMON_SNAPSHOT_VERSION,
        state_revision: 1,
        state_hash: "state".to_string(),
        security_binding: Some("treekem:epoch=1".to_string()),
        snapshot: b"newer-ratchet".to_vec(),
    })?);
    persist_treekem_snapshot_bytes(&treekem_dir, &group_id, newer.clone()).await?;

    // Boot 2.
    recover_treekem_named_journals(&named_path, &sidecar_path, &treekem_dir).await?;
    assert_eq!(
        tokio::fs::read(&snapshot_path).await?,
        newer,
        "#1187 site 2: boot 2 must keep the snapshot that boot 1 persisted after the replay"
    );
    assert!(!journal_path.exists(), "the replay consumed the journal");
    Ok(())
}

// ---------------------------------------------------------------------------
// Site 3: the seal legacy journal
// (`persist_treekem_and_named_groups_atomic_with_info`).
// ---------------------------------------------------------------------------

/// The legacy journal is the commit point: a restart replays it. The
/// callers roll the TreeKEM group back on error, so an error after the
/// rename leaves the daemon behind the disk.
#[tokio::test]
async fn issue1187_site3_seal_journal_after_rename_restart_agrees() -> Result<()> {
    let fixture = seal_fixture(0x65).await?;
    let journal = treekem_journal_path(&fixture.state.treekem_dir, &fixture.group_id);
    let result = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&journal);
        apply_seal(&fixture).await
    };
    assert_seal_restart_agrees(&fixture, &result).await
}

// ---------------------------------------------------------------------------
// Site 4: the `.hsjournal` (`write_home_suite_sidecar_journal`).
// ---------------------------------------------------------------------------

/// Rebind: the `.hsjournal` is written first and the legacy journal last.
/// An error here aborts before the commit point; a restart discards an
/// orphan `.hsjournal` (#457 r5a). Confirms the issue's "probably safe".
#[tokio::test]
async fn issue1187_site4_rebind_hsjournal_after_rename_restart_agrees() -> Result<()> {
    let fixture = rebind_fixture(0x66).await?;
    let hsjournal = treekem_home_suite_journal_path(&fixture.state.treekem_dir, &fixture.group_id);
    let before = served_record(&fixture.state, &fixture.group_id).await?;
    let status = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&hsjournal);
        rename_via_api(&fixture, "Site4 Never Committed").await
    };
    assert_ne!(status, StatusCode::OK, "no commit point was written");
    assert_eq!(
        served_record(&fixture.state, &fixture.group_id).await?,
        before
    );
    assert_rebind_restart_agrees(&fixture, status, "Site4 Never Committed").await?;
    Ok(())
}

/// Seal: the same order. The error leaves the `.hsjournal` on disk as an
/// orphan; the restart discards it and loads the old state, which is what
/// the rolled-back daemon serves. Confirms the issue's "probably safe".
#[tokio::test]
async fn issue1187_site4_seal_hsjournal_after_rename_restart_agrees() -> Result<()> {
    let fixture = seal_fixture(0x67).await?;
    let hsjournal = treekem_home_suite_journal_path(&fixture.state.treekem_dir, &fixture.group_id);
    let result = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&hsjournal);
        apply_seal(&fixture).await
    };
    assert!(result.is_err(), "no commit point was written");
    assert!(
        hsjournal.exists(),
        "precondition: the orphan .hsjournal is on disk"
    );
    assert_seal_restart_agrees(&fixture, &result).await?;
    assert!(!hsjournal.exists(), "the restart discarded the orphan");
    Ok(())
}
