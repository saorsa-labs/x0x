//! #1570 (Codex P1 on PR #1646), ADR 0109 §4: a withdrawal tombstone of a
//! held-back placeheld TreeKEM group must not run its destructive effects.
//! The sidecar write fails, so the legacy views keep the group's last
//! durable form and the withdrawal is not on disk. If the whole-map persist
//! reported Durable, the tombstone path would delete the TreeKEM snapshot,
//! drop the live TreeKEM group and let its caller publish the withdrawal,
//! while a restart restores the old, not-withdrawn record.
//! Local temp state only: no network config, sockets or bootstrap.

use super::*;

use x0x::groups::recovery as s3;

/// The group is S3-placeheld with a durable authoritative record, then its
/// sidecar becomes unwritable. A withdrawal tombstone of the group is held
/// back: the persist writes nothing and reports not durable. The tombstone
/// path must return false (the gate its callers use before they publish the
/// withdrawal), keep the live record, keep the TreeKEM snapshot and the live
/// TreeKEM group, and keep the card cache. A restart loads the old record
/// and restores the secure plane.
#[tokio::test]
async fn held_back_tombstone_deletes_no_snapshot_and_restart_is_consistent() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x72, 0x73).await?;
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
    assert!(!durable.withdrawn);
    let stable = durable.stable_group_id().to_string();
    let snapshot_path = treekem_snapshot_path(&state.treekem_dir, &group_id);
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

    // Record the card-cache entries before the tombstone. A durable
    // tombstone refreshes them from the withdrawn record (it removes them);
    // a held-back one must not touch them.
    let cards_before = {
        let cache = state.group_card_cache.read().await;
        (cache.contains_key(&group_id), cache.contains_key(&stable))
    };

    // The withdrawal tombstone. Its persist touches the held-back group, so
    // it writes nothing, rolls the live map back and is not durable.
    let retained =
        retain_withdrawn_group_tombstone(state, &group_id, durable.clone(), "test").await;
    // Nothing is published: `retain_withdrawn_group_tombstone` does not
    // publish by itself. Its callers (the local delete route, and the
    // GroupDeleted apply path) publish the GroupDeleted event, the withdrawn
    // card and the direct delivery ONLY when it returns true. A false return
    // makes the route answer 503 and the apply path REJECTED, before any
    // publication. So this assert is the publication gate.
    assert!(
        !retained,
        "#1570: a held-back tombstone must report not retained"
    );

    // The live map keeps the old record, not withdrawn.
    let live = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("live group after held-back tombstone"))?;
    assert!(!live.withdrawn, "#1570: the live record is not withdrawn");
    assert_eq!(live.state_revision, durable.state_revision);
    assert_eq!(live.state_hash, durable.state_hash);

    // The legacy views on disk keep the placeholder of the old record.
    let legacy = merge_home_suite_groups(
        load_named_groups(&state.named_groups_path).await?,
        load_home_suite_groups(&state.home_suite_groups_path).await?,
    );
    let legacy_entry = legacy
        .get(&group_id)
        .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
    assert!(
        !legacy_entry.withdrawn,
        "#1570: the legacy entry is not withdrawn"
    );
    assert!(
        s3::is_s3_placeholder(legacy_entry),
        "the legacy entry is still the placeholder"
    );

    // No destructive effect ran: the snapshot is on disk, still bound to
    // the old revision, and the TreeKEM group is still live.
    assert!(
        tokio::fs::try_exists(&snapshot_path).await?,
        "#1570: the TreeKEM snapshot is not deleted"
    );
    let envelope = decode_treekem_snapshot_envelope(&tokio::fs::read(&snapshot_path).await?)?
        .ok_or_else(|| anyhow::anyhow!("snapshot is still bound"))?;
    assert_eq!(envelope.state_revision, durable.state_revision);
    assert!(
        state.treekem_groups.read().await.contains_key(&group_id),
        "#1570: the live TreeKEM group is not pruned"
    );
    let cards_after = {
        let cache = state.group_card_cache.read().await;
        (cache.contains_key(&group_id), cache.contains_key(&stable))
    };
    assert_eq!(
        cards_before, cards_after,
        "the card cache is not refreshed from a withdrawal that is not on disk"
    );

    // Simulate the restart. The sidecar holds its last durable record. Load
    // the roster from disk (the S3 splice replaces the placeholder by the
    // sidecar's authoritative record), then restore the TreeKEM plane.
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
    assert!(!saved.withdrawn, "the restart loads a record not withdrawn");
    assert_eq!(saved.state_revision, durable.state_revision);
    assert_eq!(saved.state_hash, durable.state_hash);
    let restored =
        restore_treekem_groups(&reloaded, state.agent.as_ref(), &state.treekem_dir).await;
    assert!(
        restored.contains_key(&group_id),
        "#1570: the TreeKEM group restores after a held-back tombstone"
    );
    Ok(())
}
