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

/// ZCode on d1be57f1 (#1570), ADR 0109 §4: the TreeKEM atomic writer is a
/// roster writer too. When its encode holds the group back, the legacy
/// views keep the group's last committed form, so a snapshot written for
/// the new state would be ahead of the saved roster. RED (before the fix):
/// the writer wrote the snapshot, journal and roster and returned `Ok`.
/// GREEN: it stops before its commit point, and the snapshot and the
/// roster on disk do not change.
#[tokio::test]
async fn held_back_treekem_atomic_persist_stops_before_commit() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x74, 0x75).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
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
    group_recovery::begin_placehold(state, &group_id, &durable);
    let outcome = save_named_groups_checked(state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "placehold save must be durable: {outcome:?}"
    );

    let sidecar = state
        .data_dir
        .join(s3::GROUP_RECOVERY_DIR)
        .join(s3::sidecar_file_name(&stable));
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
    let snapshot_path = treekem_snapshot_path(&state.treekem_dir, &group_id);
    let journal_path = treekem_journal_path(&state.treekem_dir, &group_id);
    let snapshot_before = tokio::fs::read(&snapshot_path).await?;
    let roster_before = tokio::fs::read(&state.named_groups_path).await?;

    let mut renamed = durable.clone();
    renamed.name = "renamed by the TreeKEM writer while held back".to_string();
    renamed.roster_revision = renamed.roster_revision.saturating_add(1);
    renamed.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    let live = state
        .treekem_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("live TreeKEM group"))?;
    let group = live.lock().await;
    let result =
        persist_treekem_and_named_groups_atomic_with_info(state, &group_id, renamed, &group).await;
    drop(group);
    let error = result.expect_err("#1570: a held-back TreeKEM persist is refused");
    assert!(
        persist_stopped_before_commit(&error),
        "the refusal comes before the commit point: {error:#}"
    );
    assert!(group_recovery::is_held_back(state, &stable));
    assert_eq!(
        tokio::fs::read(&snapshot_path).await?,
        snapshot_before,
        "the snapshot does not move past the saved roster"
    );
    assert_eq!(
        tokio::fs::read(&state.named_groups_path).await?,
        roster_before,
        "the roster file does not change"
    );
    assert!(!tokio::fs::try_exists(&journal_path).await?);
    Ok(())
}

/// ZCode on d1be57f1 (#1570), ADR 0109 §4: a Durable write by the TreeKEM
/// atomic writer commits the legacy form that its encode gave every other
/// placeheld group. RED (before the fix): the writer did not commit it, so
/// a later held-back save wrote the older committed form over the newer
/// durable one, and a change that was durable on disk went back. GREEN: the
/// held-back save keeps the form that the TreeKEM writer made durable.
#[tokio::test]
async fn treekem_writer_commits_other_placeheld_groups_legacy_form() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x76, 0x77).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
    let treekem_record = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("fixture group"))?;

    // A second group P is placeheld, with a durable authoritative record.
    let admin = x0x::identity::AgentKeypair::generate()?;
    let mut other = x0x::groups::GroupInfo::new(
        "issue1570-other".to_string(),
        "v1".to_string(),
        admin.agent_id(),
        "1570".repeat(16),
    );
    other.seal_commit(&admin, 1_000)?;
    let other_key = other.mls_group_id.clone();
    let other_stable = other.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(other_key.clone(), other.clone());
    group_recovery::begin_placehold(state, &other_key, &other);
    let outcome = save_named_groups_checked(state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "placehold save must be durable: {outcome:?}"
    );

    // P changes to v2 in memory; the TreeKEM writer's Durable write puts
    // P's v2 placeholder on disk.
    if let Some(live) = state.named_groups.write().await.get_mut(&other_key) {
        live.description = "v2".to_string();
    }
    let live = state
        .treekem_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("live TreeKEM group"))?;
    let group = live.lock().await;
    persist_treekem_and_named_groups_atomic_with_info(state, &group_id, treekem_record, &group)
        .await?;
    drop(group);
    let legacy_description = |roster: &[u8]| -> Result<String> {
        let roster: HashMap<String, x0x::groups::GroupInfo> = serde_json::from_slice(roster)?;
        let entry = roster
            .get(&other_key)
            .ok_or_else(|| anyhow::anyhow!("P's legacy entry"))?;
        assert!(s3::is_s3_placeholder(entry));
        Ok(entry.description.clone())
    };
    assert_eq!(
        legacy_description(&tokio::fs::read(&state.named_groups_path).await?)?,
        "v2",
        "the TreeKEM writer saved P's v2 placeholder"
    );

    // P's sidecar cannot be written, and P changes to v3: P is held back.
    let sidecar = state
        .data_dir
        .join(s3::GROUP_RECOVERY_DIR)
        .join(s3::sidecar_file_name(&other_stable));
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
    if let Some(live) = state.named_groups.write().await.get_mut(&other_key) {
        live.description = "v3".to_string();
    }
    save_named_groups_checked(state).await?;
    assert!(group_recovery::is_held_back(state, &other_stable));
    assert_eq!(
        legacy_description(&tokio::fs::read(&state.named_groups_path).await?)?,
        "v2",
        "#1570: the held-back form is the last durable one (v2), not v1"
    );
    Ok(())
}

/// ZCode on fa096d0f (#1570): a held-back group's live roster is ahead of
/// its durable form, so no caller's gossip refresh may publish it. RED
/// (before the fix): only `persist_named_group_info` skipped the refresh;
/// any other caller published the live roster, here a withdrawal made in
/// memory only, which dropped the group's hint. GREEN: every refresh keeps the hint last published for
/// the group until it commits.
#[tokio::test]
async fn a_held_back_roster_is_not_published_by_another_refresh() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x76, 0x77).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
    let seeded = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("fixture group"))?;
    let outcome = persist_named_group_info(state, &group_id, seeded).await;
    assert!(matches!(outcome, Ok(AtomicWriteOutcome::Durable)));
    let durable = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("seeded group"))?;
    let stable = durable.stable_group_id().to_string();
    let members = |info: &x0x::groups::GroupInfo| {
        let mut ids: Vec<String> = info.active_members().map(|m| m.agent_id.clone()).collect();
        ids.sort();
        ids
    };
    let before = members(&durable);
    assert!(!before.is_empty());
    group_recovery::begin_placehold(state, &group_id, &durable);
    let outcome = save_named_groups_checked(state).await;
    assert!(matches!(outcome, Ok(AtomicWriteOutcome::Durable)));
    refresh_group_rosters_for_gossip(state).await;

    let sidecar = state
        .data_dir
        .join(s3::GROUP_RECOVERY_DIR)
        .join(s3::sidecar_file_name(&stable));
    tokio::fs::remove_file(&sidecar).await?;
    tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
    // Withdrawn in memory only: its live roster would publish no hint.
    let mut changed = durable.clone();
    changed.withdrawn = true;
    changed.roster_revision = changed.roster_revision.saturating_add(1);
    let outcome = persist_named_group_info(state, &group_id, changed).await;
    assert!(
        !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the change is held back: {outcome:?}"
    );
    assert!(group_recovery::is_held_back(state, &stable));

    // Another caller's refresh, as after a different group's durable save.
    refresh_group_rosters_for_gossip(state).await;
    let published = state.group_roster_gossip_lock.lock().await;
    let (_, _, agents) = published
        .get(&stable)
        .cloned()
        .flatten()
        .ok_or_else(|| anyhow::anyhow!("the group keeps a published hint"))?;
    let mut agents: Vec<String> = agents.iter().map(|a| hex::encode(a.as_bytes())).collect();
    agents.sort();
    assert_eq!(agents, before, "the hint stays at the durable roster");
    Ok(())
}
