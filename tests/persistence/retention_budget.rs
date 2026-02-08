use tokio::fs;
use x0x::crdt::persistence::{
    enforce_retention_cycle, evaluate_budget, BudgetDecision, PersistenceMode, RetentionPolicy,
};

#[test]
fn retention_budget_mode_specific_full_budget_behavior() {
    let retention = RetentionPolicy::default();
    let used = retention.storage_budget_bytes;

    assert_eq!(
        evaluate_budget(&retention, PersistenceMode::Strict, used),
        BudgetDecision::StrictFailAtCapacity
    );
    assert_eq!(
        evaluate_budget(&retention, PersistenceMode::Degraded, used),
        BudgetDecision::DegradedSkipAtCapacity
    );
}

#[tokio::test]
async fn retention_budget_truncates_history_to_three_snapshots() {
    let temp = tempfile::tempdir().expect("temp dir");
    let entity = "entity-retention";
    let entity_dir = temp.path().join(entity);
    fs::create_dir_all(&entity_dir)
        .await
        .expect("create entity directory");

    for idx in 1..=5 {
        let path = entity_dir.join(format!("{:020}.snapshot", idx));
        fs::write(path, format!("snapshot-{idx}").as_bytes())
            .await
            .expect("write snapshot");
    }

    let outcome = enforce_retention_cycle(temp.path(), &[entity.to_string()], 3)
        .await
        .expect("run retention");

    assert_eq!(outcome.deleted_old_snapshots, 2);
    assert_eq!(outcome.deleted_orphan_entities, 0);

    let mut dir = fs::read_dir(&entity_dir).await.expect("read entity dir");
    let mut snapshot_count = 0;
    while let Some(entry) = dir.next_entry().await.expect("next entry") {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("snapshot") {
            snapshot_count += 1;
        }
    }
    assert_eq!(snapshot_count, 3);
}

#[tokio::test]
async fn retention_budget_removes_orphan_entity_directories_on_cycle() {
    let temp = tempfile::tempdir().expect("temp dir");
    let active = "active-entity";
    let orphan = "orphan-entity";
    fs::create_dir_all(temp.path().join(active))
        .await
        .expect("create active entity dir");
    fs::create_dir_all(temp.path().join(orphan))
        .await
        .expect("create orphan entity dir");

    let outcome = enforce_retention_cycle(temp.path(), &[active.to_string()], 3)
        .await
        .expect("run retention");
    assert_eq!(outcome.deleted_orphan_entities, 1);

    assert!(
        !fs::try_exists(temp.path().join(orphan))
            .await
            .expect("check orphan existence")
    );
}
