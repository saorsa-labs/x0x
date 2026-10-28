//! #1570 (Codex P1 on PR #1646), ADR 0109 §4: a metadata-only seal of a
//! held-back placeheld TreeKEM group must not move the TreeKEM snapshot
//! past the saved roster. The legacy views keep the group's last durable
//! form, so a snapshot re-bound to the new revision is ahead of the roster
//! that a restart loads, and `restore_treekem_groups` rejects that pair.
//! Local temp state only: no network config, sockets or bootstrap.

use super::*;

use x0x::groups::recovery as s3;

/// The group is S3-placeheld with a durable authoritative record, then its
/// sidecar becomes unwritable. A rename sealed at the next revision is held
/// back: the roster file keeps the placeholder of the old record. The
/// snapshot must stay bound to the old record, and no rebind journal may
/// remain, so the restart loads a roster and a snapshot that agree and the
/// secure plane is restored.
#[tokio::test]
async fn held_back_metadata_seal_keeps_snapshot_at_saved_roster_across_restart() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x70, 0x71).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
    assert!(
        state.treekem_groups.read().await.contains_key(&group_id),
        "fixture TreeKEM group must be live"
    );

    // Seed the on-disk snapshot, bound to the current revision.
    let seeded = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("fixture group"))?;
    let outcome = persist_named_group_info(state, &group_id, seeded).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "seed persist must be durable: {outcome:?}"
    );
    let durable = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("seeded group"))?;
    let stable = durable.stable_group_id().to_string();
    let snapshot_path = treekem_snapshot_path(&state.treekem_dir, &group_id);
    let journal_path = treekem_journal_path(&state.treekem_dir, &group_id);
    let envelope = decode_treekem_snapshot_envelope(&tokio::fs::read(&snapshot_path).await?)?
        .ok_or_else(|| anyhow::anyhow!("seeded snapshot is bound"))?;
    assert_eq!(envelope.state_revision, durable.state_revision);

    // Placehold the group: the roster save writes its authoritative record
    // to the sidecar, durably, and its placeholder to the legacy views.
    group_recovery::begin_placehold(state, &group_id, &durable);
    let outcome = save_named_groups_checked(state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "placehold save must be durable: {outcome:?}"
    );
    assert!(!group_recovery::is_held_back(state, &stable));

    // The sidecar cannot be written: a non-empty directory holds its name.
    // Its durable bytes are kept, to put back before the restart.
    let sidecar = state
        .data_dir
        .join(s3::GROUP_RECOVERY_DIR)
        .join(s3::sidecar_file_name(&stable));
    let durable_sidecar = tokio::fs::read(&sidecar).await?;
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;

    // A metadata-only seal at the next revision (rename): the TreeKEM
    // crypto state and its security binding do not move.
    let mut renamed = durable.clone();
    renamed.name = "renamed while held back".to_string();
    renamed.roster_revision = renamed.roster_revision.saturating_add(1);
    renamed.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    assert!(renamed.state_revision > durable.state_revision);
    assert_ne!(renamed.state_hash, durable.state_hash);
    assert_eq!(renamed.security_binding, durable.security_binding);
    let outcome = persist_named_group_info(state, &group_id, renamed).await;
    assert!(
        !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "a held-back change is not durable: {outcome:?}"
    );
    assert!(group_recovery::is_held_back(state, &stable));
    assert!(
        !tokio::fs::try_exists(&journal_path).await?,
        "no rebind journal is left for a held-back group"
    );

    // Simulate the restart. The sidecar holds its last durable record (an
    // unwritable sidecar is not a lost one). Load the roster from disk (the
    // S3 splice replaces the placeholder by the sidecar's authoritative
    // record), then restore the TreeKEM plane from the snapshots.
    tokio::fs::remove_dir_all(&sidecar).await?;
    tokio::fs::write(&sidecar, &durable_sidecar).await?;
    let reloaded =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    let saved = reloaded
        .get(&group_id)
        .ok_or_else(|| anyhow::anyhow!("reloaded group"))?;
    assert!(
        !s3::is_s3_placeholder(saved),
        "the splice restores the record"
    );
    assert_eq!(saved.state_revision, durable.state_revision);
    assert_eq!(saved.state_hash, durable.state_hash);
    let envelope = decode_treekem_snapshot_envelope(&tokio::fs::read(&snapshot_path).await?)?
        .ok_or_else(|| anyhow::anyhow!("snapshot is bound"))?;
    assert!(
        envelope.state_revision <= saved.state_revision,
        "the snapshot (revision {}) is not ahead of the saved roster (revision {})",
        envelope.state_revision,
        saved.state_revision
    );
    let restored =
        restore_treekem_groups(&reloaded, state.agent.as_ref(), &state.treekem_dir).await;
    assert!(
        restored.contains_key(&group_id),
        "#1570: the TreeKEM group restores after a held-back metadata seal"
    );
    Ok(())
}
