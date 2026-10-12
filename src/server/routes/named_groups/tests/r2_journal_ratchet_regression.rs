//! Regression: a TreeKEM journal KEPT for replay must never roll the send
//! ratchet back at restart, because saorsa-mls 0.3.8 derives the
//! ChaCha20-Poly1305 key and nonce from (epoch secret, sender leaf,
//! generation) with no randomness, so a repeated generation repeats the
//! exact (key, nonce) pair.
//!
//! Fixed in v0.47.1 (#1326, GHSA-63j6-cch7-w9h4). Before that fix, these
//! tests fail: the restart replays the journal's older snapshot over the
//! newer `<gid>.snap`, the restored group repeats a send generation, and
//! the two wire ciphertexts carry the same epoch, sender leaf, generation
//! and nonce. With the fix they pass: every retained-journal path keeps the
//! journal's snapshot in step with the live ratchet (or discards and rolls
//! back a rejected transaction), so a restart never reuses a (key, nonce)
//! pair. The fail-closed cases assert that a journal this binary cannot
//! read, or cannot refresh durably, refuses the send (no ciphertext leaves).
//!
//! The entry paths (src/server/routes/named_groups.rs):
//! - A1: the rebind named save returns ReplacedNotDurable, so the journal
//!   stays on disk (apply runs only on Durable).
//! - A2: the rebind apply snapshot write fails after its rename. The #1187
//!   part of #1326 (complete the transaction after the rename) consumes the
//!   journal here, so A2 does not depend on the journal refresh: it stays
//!   green if only the refresh is removed, and fails if that post-rename
//!   completion is reverted.
//! - B: a crash after the rebind commit point, then a replay apply failure
//!   before the snapshot write keeps the pair; a later boot replays it.
//! - C: a seal caller that leaves the group advanced on a failed named
//!   write (direct add); the kept journal rolls the e+1 ratchet back.
//!
//! Inert: tempdirs only, no network config, no sockets. Each fault comes
//! from a cfg(test) seam scoped to this test's own data: the replay fault
//! used by path B is keyed by the test's TreeKEM directory (#1331 review),
//! the fsync and write-pause seams by path, and the named-save fault lives
//! on the test's own `AppState`. So a fault armed here cannot fire inside
//! another test's recovery in a threaded run. Each test also holds
//! `fault_test_lock`, because other suites arm process-global quarantine
//! faults under that lock.

use super::*;

/// What a restart loads from the data directory.
struct Restarted {
    merged: HashMap<String, x0x::groups::GroupInfo>,
    treekem: HashMap<String, Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>>,
}

/// Run the daemon's startup recovery on `state`'s data directory, in the
/// order `serve()` uses (recover journals, recover sidecar journals, load
/// merged, restore).
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

/// Make `state` serve what a restart loaded, so the next API call runs on
/// the restarted daemon's maps.
async fn adopt(state: &AppState, restarted: Restarted) {
    *state.named_groups.write().await = restarted.merged;
    *state.treekem_groups.write().await = restarted.treekem;
}

/// A TreeKEM group with a durable baseline (named store and bound snapshot)
/// and no journal.
async fn baseline_fixture(byte: u8) -> Result<MemberJoinedTreeKemFixture> {
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

/// Rename through the production HTTP handler (a metadata-only seal: the
/// TreeKEM rebind path, `persist_named_group_info_inner`).
async fn rename_via_api(state: &Arc<AppState>, group_id: &str, name: &str) -> StatusCode {
    update_named_group(
        State(Arc::clone(state)),
        Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.to_string()),
        Json(UpdateGroupRequest {
            name: Some(name.to_string()),
            description: None,
        }),
    )
    .await
    .into_response()
    .status()
}

/// Encrypt through the production secure-send path. Asserts the send
/// succeeded and returns the self-describing `ApplicationCiphertext` bytes.
async fn api_encrypt(state: &AppState, group_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (status, Json(body)) =
        treekem_group_encrypt(state, group_id, None, &BASE64.encode(plaintext), None).await;
    assert_eq!(status, StatusCode::OK, "encrypt failed: {body}");
    let b64 = body["ciphertext_b64"]
        .as_str()
        .context("ciphertext_b64 in the encrypt response")?;
    Ok(BASE64.decode(b64)?)
}

/// Encrypt through the production secure-send path, returning ONLY the
/// status (for the fail-closed tests: a non-200 means no ciphertext left).
async fn api_encrypt_status(state: &AppState, group_id: &str, plaintext: &[u8]) -> StatusCode {
    treekem_group_encrypt(state, group_id, None, &BASE64.encode(plaintext), None)
        .await
        .0
}

/// Encrypt on a restored group, exactly as the API does after a restart.
async fn restored_encrypt(
    restarted: &Restarted,
    group_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let group = restarted
        .treekem
        .get(group_id)
        .cloned()
        .context("the TreeKEM group restores after the restart")?;
    let mut guard = group.lock().await;
    Ok(guard.encrypt_message(plaintext)?)
}

fn decode_ct(bytes: &[u8]) -> Result<saorsa_mls::treekem_group::ApplicationCiphertext> {
    Ok(postcard::from_bytes(bytes)?)
}

/// The fix property: the two ciphertexts must NOT share a (key, nonce)
/// pair. The key and nonce are derived from (epoch secret, sender leaf,
/// generation), so a shared pair means the same epoch, sender leaf,
/// generation AND nonce. Assert at least one differs (and the 12-byte
/// nonce prefix differs).
fn assert_no_aead_key_nonce_reuse(label: &str, before: &[u8], after: &[u8]) -> Result<()> {
    let a = decode_ct(before)?;
    let b = decode_ct(after)?;
    eprintln!(
        "[{label}] before restart: epoch={} leaf={} generation={} nonce={}",
        a.epoch,
        a.sender_leaf,
        a.generation,
        hex::encode(&a.ciphertext[..12])
    );
    eprintln!(
        "[{label}] after  restart: epoch={} leaf={} generation={} nonce={}",
        b.epoch,
        b.sender_leaf,
        b.generation,
        hex::encode(&b.ciphertext[..12])
    );
    let same_tuple =
        a.epoch == b.epoch && a.sender_leaf == b.sender_leaf && a.generation == b.generation;
    assert!(
        !same_tuple,
        "[{label}] the restarted daemon reused a (key, nonce) pair: \
         epoch={} leaf={} generation={}",
        a.epoch, a.sender_leaf, a.generation
    );
    assert_ne!(
        &a.ciphertext[..12],
        &b.ciphertext[..12],
        "[{label}] the AEAD nonce repeated across the restart"
    );
    Ok(())
}

const P1: &[u8] = b"r2: first secret, before restart";
const P2: &[u8] = b"r2: other secret, after  restart";

// ---------------------------------------------------------------------------
// A1: the rebind's named save is ReplacedNotDurable. The journal apply runs
// only on Durable (named_groups.rs:6463), so the journal stays on disk.
// FIX: the next send refreshes the retained journal to the current ratchet.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r2_rebind_replaced_not_durable_no_aead_nonce_reuse() -> Result<()> {
    let _fault_test_lock = fault_test_lock().await;
    let fixture = baseline_fixture(0xb1).await?;
    let state = &fixture.state;
    let gid = fixture.group_id.clone();
    let journal = treekem_journal_path(&state.treekem_dir, &gid);

    // ONE fault: the named_groups.json rename lands, its directory fsync
    // fails (real write, one-shot cell).
    state.named_groups_save_fault.store(
        SaveFault::ReplacedNotDurableAfterWrite as u8,
        std::sync::atomic::Ordering::SeqCst,
    );
    let status = rename_via_api(state, &gid, "R2 Replaced Not Durable").await;
    eprintln!("[A1] rename status with ReplacedNotDurable: {status}");
    assert!(journal.exists(), "[A1] the rebind journal is kept on disk");

    // The daemon keeps serving. A secure send persists a newer ratchet (and,
    // on the fix, refreshes the retained journal before the ciphertext
    // leaves).
    let c1 = api_encrypt(state, &gid, P1).await?;

    // Restart on the same data directory, then send on the restored group.
    let restarted = restart(state).await?;
    let c2 = restored_encrypt(&restarted, &gid, P2).await?;
    assert_no_aead_key_nonce_reuse("A1", &c1, &c2)
}

// ---------------------------------------------------------------------------
// A2: the rebind apply snapshot write fails after its rename. The post-rename
// completion (the #1187 part of #1326) consumes the journal, so this path has
// no kept journal. The test confirms no reuse. It does not depend on the
// journal refresh; it fails if the post-rename completion is reverted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r2_rebind_snapshot_after_rename_no_aead_nonce_reuse() -> Result<()> {
    let _fault_test_lock = fault_test_lock().await;
    let fixture = baseline_fixture(0xb2).await?;
    let state = &fixture.state;
    let gid = fixture.group_id.clone();
    let journal = treekem_journal_path(&state.treekem_dir, &gid);
    let snapshot = treekem_snapshot_path(&state.treekem_dir, &gid);

    let status = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&snapshot);
        rename_via_api(state, &gid, "R2 Snapshot After Rename").await
    };
    eprintln!("[A2] rename status with snapshot AfterRename: {status}");
    assert!(
        !journal.exists(),
        "[A2] #1187 completes the rebind and consumes the journal"
    );

    let c1 = api_encrypt(state, &gid, P1).await?;
    let restarted = restart(state).await?;
    let c2 = restored_encrypt(&restarted, &gid, P2).await?;
    assert_no_aead_key_nonce_reuse("A2", &c1, &c2)
}

// ---------------------------------------------------------------------------
// B: a crash after the rebind commit point, then a replay apply failure
// before the snapshot write keeps the pair (named_groups.rs:29985-29997).
// Boot 1 sends; boot 2 replays. FIX: boot 1's send refreshes the journal.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r2_replay_apply_failure_no_aead_nonce_reuse() -> Result<()> {
    let _fault_test_lock = fault_test_lock().await;
    let fixture = baseline_fixture(0xb3).await?;
    let state = Arc::clone(&fixture.state);
    let gid = fixture.group_id.clone();
    let journal = treekem_journal_path(&state.treekem_dir, &gid);

    // Normal traffic first.
    let _c0 = api_encrypt(&state, &gid, b"r2: pre-crash traffic ....").await?;

    // Crash inside a rename: park the named_groups.json write (after the
    // journal commit point), then kill the task.
    let pause = atomic_write_test_seam::arm(&state.named_groups_path);
    let task = {
        let state = Arc::clone(&state);
        let gid = gid.clone();
        tokio::spawn(async move { rename_via_api(&state, &gid, "R2 Crash").await })
    };
    for _ in 0..2000 {
        if pause.reached() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        pause.reached(),
        "[B] the rename parked inside the named write"
    );
    assert!(
        journal.exists(),
        "[B] the journal (commit point) is on disk"
    );
    task.abort();
    let _ = task.await;

    // Boot 1: the replay fails between the named write and the snapshot
    // write (one I/O error), so both journals are retained.
    let boot1 = {
        let _fault = set_replay_fault(&state.treekem_dir, &[ReplayFault::AfterNamedApply]);
        restart(&state).await?
    };
    assert!(journal.exists(), "[B] boot 1 retained the journal pair");
    assert!(
        boot1.treekem.contains_key(&gid),
        "[B] boot 1 restores the group (#457 metadata-only re-bind)"
    );
    adopt(&state, boot1).await;

    // Boot 1 traffic: a secure send persists a newer ratchet (and, on the
    // fix, refreshes the retained journal).
    let c1 = api_encrypt(&state, &gid, P1).await?;

    // Boot 2: no fault.
    let boot2 = restart(&state).await?;
    let c2 = restored_encrypt(&boot2, &gid, P2).await?;
    assert_no_aead_key_nonce_reuse("B", &c1, &c2)
}

// ---------------------------------------------------------------------------
// C: a seal caller that leaves the group advanced on a failed named write
// (`add_treekem_named_group_member`). On the pre-fix tree the kept journal
// rolls the e+1 ratchet back at restart. FIX: the caller rolls the group
// back and the seal discards its journal, so a restart loads the old state.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r2_direct_add_named_write_failure_no_aead_nonce_reuse() -> Result<()> {
    let _fault_test_lock = fault_test_lock().await;
    let fixture = baseline_fixture(0xb4).await?;
    let state = Arc::clone(&fixture.state);
    let gid = fixture.group_id.clone();
    let named = state.named_groups_path.clone();

    // The member to add (its own TreeKEM key package).
    let added = x0x::identity::AgentKeypair::generate()?.agent_id();
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(added, &[0xb5; 32])?;
    let req = AddNamedGroupMemberRequest {
        agent_id: hex::encode(added.as_bytes()),
        display_name: None,
        treekem_key_package_b64: Some(BASE64.encode(prepared.key_package_bytes())),
    };

    // ONE fault: the named_groups.json rename fails (NotReplaced). The park
    // seam holds the write after its temp file is synced; a directory at the
    // destination makes rename(2) fail with EISDIR; then the file is put
    // back unchanged.
    let pause = atomic_write_test_seam::arm(&named);
    let task = {
        let state = Arc::clone(&state);
        let gid = gid.clone();
        tokio::spawn(async move { add_treekem_named_group_member(state, gid, added, req).await })
    };
    for _ in 0..2000 {
        if pause.reached() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        pause.reached(),
        "[C] the seal parked inside the named write"
    );
    let hold = named.with_extension("json.r2-hold");
    std::fs::rename(&named, &hold)?;
    std::fs::create_dir(&named)?;
    pause.release();
    let (status, Json(body)) = task.await?;
    std::fs::remove_dir(&named)?;
    std::fs::rename(&hold, &named)?;
    eprintln!("[C] direct add status with named NotReplaced: {status} {body}");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // The daemon keeps serving. A secure send persists a newer ratchet.
    let c1 = api_encrypt(&state, &gid, P1).await?;

    let restarted = restart(&state).await?;
    let c2 = restored_encrypt(&restarted, &gid, P2).await?;
    assert_no_aead_key_nonce_reuse("C", &c1, &c2)
}

// ---------------------------------------------------------------------------
// Fail-closed: a retained journal this binary cannot read must fail the send
// closed (no ciphertext leaves), rather than silently skipping the journal
// refresh (ADR 0085 rule 4). On the pre-fix tree the send ignores the
// journal and returns 200, so these FAIL there and PASS on the fix.
// ---------------------------------------------------------------------------

/// Set up a kept journal via the A1 path, with no fault left armed.
///
/// Returns the fixture too: it owns the test's `TempDir` and agent state.
/// The caller keeps it alive for the whole test (bind it as `_fixture`, not
/// `_`) and it drops at the end of the test, which removes the temp files.
async fn fixture_with_kept_journal(
    byte: u8,
) -> Result<(Arc<AppState>, String, PathBuf, MemberJoinedTreeKemFixture)> {
    let fixture = baseline_fixture(byte).await?;
    let state = Arc::clone(&fixture.state);
    let gid = fixture.group_id.clone();
    let journal = treekem_journal_path(&state.treekem_dir, &gid);
    state.named_groups_save_fault.store(
        SaveFault::ReplacedNotDurableAfterWrite as u8,
        std::sync::atomic::Ordering::SeqCst,
    );
    let _ = rename_via_api(&state, &gid, "R2 Kept Journal").await;
    assert!(journal.exists(), "the rebind journal is kept on disk");
    // The one-shot save fault is spent by the rename; nothing is left armed.
    Ok((state, gid, journal, fixture))
}

#[tokio::test]
async fn r2_kept_journal_undecodable_fails_the_send_closed() -> Result<()> {
    let _fault_test_lock = fault_test_lock().await;
    let (state, gid, journal, _fixture) = fixture_with_kept_journal(0xb6).await?;

    // Replace the retained journal with bytes this binary cannot decode.
    std::fs::write(&journal, b"not a postcard journal")?;

    let status = api_encrypt_status(&state, &gid, P1).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an undecodable retained journal must fail the send closed (no ciphertext leaves)"
    );
    Ok(())
}

#[tokio::test]
async fn r2_kept_journal_unbound_snapshot_fails_the_send_closed() -> Result<()> {
    let _fault_test_lock = fault_test_lock().await;
    let (state, gid, journal, _fixture) = fixture_with_kept_journal(0xb7).await?;

    // Rewrite the journal so its snapshot envelope has no binding magic (a
    // legacy unbound snapshot the refresh cannot re-bind).
    let bytes = std::fs::read(&journal)?;
    let mut decoded: TreeKemNamedPersistJournal = postcard::from_bytes(&bytes)?;
    decoded.snapshot_envelope = vec![0u8; 8];
    std::fs::write(&journal, postcard::to_stdvec(&decoded)?)?;

    let status = api_encrypt_status(&state, &gid, P1).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a retained journal with an unbound snapshot must fail the send closed"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Durable refresh: the journal refresh must be DURABLE before the
// send proceeds. If the refresh write crosses its rename but its directory
// fsync fails, a crash can revert the journal to the journal-time snapshot;
// a restart would then replay that older snapshot over the newer `.snap`
// (equal revision and hash -> Apply) and a send that already left would
// repeat a generation. The send must fail closed on that fault, so no
// ciphertext leaves. Without the durable-refresh requirement (before #1326,
// or with a crossed-rename treated as success) the send returns 200 and this
// fails; with it, the send is refused.
//
// Both crash outcomes are then safe, because the send emitted nothing:
// - the rename survived: a restart replays the refreshed (current) snapshot;
// - the rename was lost: a restart replays the journal-time snapshot, and
//   the generation the refused send would have used was never on the wire.
// The test drives both restart outcomes and asserts each restores a usable
// group.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r2_refresh_not_durable_fails_the_send_closed() -> Result<()> {
    let _fault_test_lock = fault_test_lock().await;
    let (state, gid, journal, _fixture) = fixture_with_kept_journal(0xb8).await?;

    // The journal's bytes as they stand before the send (the journal-time
    // snapshot), so the "rename was lost" outcome can be reconstructed.
    let before = std::fs::read(&journal)?;

    // The send advances the ratchet: the `.snap` write is durable, but the
    // journal refresh crosses its rename and its directory fsync fails.
    let status = {
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&journal);
        api_encrypt_status(&state, &gid, P1).await
    };
    assert_ne!(
        status,
        StatusCode::OK,
        "a refresh whose directory fsync failed must fail the send closed (no ciphertext leaves)"
    );

    // Outcome 1 — the rename survived (the fault left the rewritten journal
    // in place). A restart must restore a usable group.
    let restarted = restart(&state).await?;
    let c1 = restored_encrypt(&restarted, &gid, P2).await?;
    decode_ct(&c1)?;

    // Outcome 2 — the rename was lost (power loss reverted it). Put the
    // journal-time bytes back and restart again; the group must still be
    // usable, and no earlier ciphertext exists to pair with.
    std::fs::write(&journal, &before)?;
    let restarted2 = restart(&state).await?;
    let c2 = restored_encrypt(&restarted2, &gid, b"r2: after reverted refresh").await?;
    decode_ct(&c2)?;
    Ok(())
}
