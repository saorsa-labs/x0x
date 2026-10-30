//! #1569, ADR 0109 §4 "Placeholder": while an OwnerCertified group is
//! placeheld, BOTH legacy files that a released binary loads hold its S3
//! placeholder. Released binaries load `named_groups.json` and
//! `home-suite-groups.json`, and the sidecar entry wins. Before the fix
//! the sidecar had no entry for the group, so the released binary loaded
//! the `named_groups.json` entry alone. A crash between the sidecar write
//! and the `named_groups.json` write of the arming save then left the
//! #451 placeholder of the real record there (empty roster). Released
//! `migrate_from_v1` seats the creator as an Active Admin on an empty
//! roster, so the group was live again and the containment was lost.
//! Local temp state only: no network config, sockets or bootstrap.

use super::*;

use crate::groups::policy::{GroupAdmission, GroupPolicy};
use crate::groups::{GroupConfidentiality, GroupDiscoverability};
use x0x::groups::recovery as s3;

fn owner_certified_policy(owner: x0x::identity::UserId) -> GroupPolicy {
    GroupPolicy {
        discoverability: GroupDiscoverability::Hidden,
        admission: GroupAdmission::OwnerCertified(owner),
        confidentiality: GroupConfidentiality::MlsEncrypted,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    }
}

/// No seat of `info` is Active, and no seat is an Active admin.
fn seats_no_one(info: &x0x::groups::GroupInfo) -> bool {
    !info.members_v2.is_empty() && info.members_v2.values().all(|member| !member.is_active())
}

/// The released binary's view of the data directory: each file is loaded
/// with `migrate_from_v1`, then the sidecar entry replaces the
/// `named_groups.json` entry with the same ID (released
/// `load_named_groups_merged` without the S3 splice).
async fn released_view(state: &AppState) -> Result<HashMap<String, x0x::groups::GroupInfo>> {
    Ok(merge_home_suite_groups(
        load_named_groups(&state.named_groups_path).await?,
        load_home_suite_groups(&state.home_suite_groups_path).await?,
    ))
}

#[tokio::test]
async fn placeheld_owner_certified_group_has_a_contained_sidecar_entry() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let state = state.as_ref();
    let group_id = "issue1569-owner-certified".to_string();
    let owner = x0x::identity::UserKeypair::generate()?.user_id();
    // Seal a chain head under the default admission, then make the group
    // OwnerCertified. The store split reads only the admission, and the S3
    // splice matches by head, so no certificate evidence is needed here.
    let mut info = x0x::groups::GroupInfo::with_policy(
        "issue1569".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        GroupPolicy::default(),
    );
    info.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    info.policy = owner_certified_policy(owner);
    assert!(
        info.members_v2.values().any(|member| member.is_active()),
        "the real record seats its creator"
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info.clone());

    // Before arming: the #451 split. The sidecar holds the real record;
    // `named_groups.json` holds the #451 placeholder (empty roster).
    let outcome = save_named_groups_checked(state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "seed save must be durable: {outcome:?}"
    );
    let named_before_arm = tokio::fs::read(&state.named_groups_path).await?;

    // Arm: the group is placeheld, and the roster save writes the S3
    // placeholder into the legacy files.
    group_recovery::begin_placehold(state, &group_id, &info);
    let outcome = save_named_groups_checked(state).await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "placehold save must be durable: {outcome:?}"
    );

    // `home-suite-groups.json` holds the S3 placeholder, with the
    // OwnerCertified policy that puts it in that file.
    let sidecar = load_home_suite_groups(&state.home_suite_groups_path).await?;
    let entry = sidecar.get(&group_id).ok_or_else(|| {
        anyhow::anyhow!(
            "#1569: a placeheld OwnerCertified group needs a home-suite-groups.json entry"
        )
    })?;
    assert!(
        s3::is_s3_placeholder(entry),
        "the sidecar entry is the S3 placeholder"
    );
    assert!(seats_no_one(entry), "the sidecar placeholder seats no one");
    assert_eq!(
        entry.policy.admission,
        GroupAdmission::OwnerCertified(owner)
    );
    assert_eq!(entry.state_revision, info.state_revision);
    assert_eq!(entry.state_hash, info.state_hash);

    // `named_groups.json` keeps a pre-ADR-0038-safe S3 placeholder: the
    // default admission and the non-empty, all-Removed roster.
    let named = load_named_groups(&state.named_groups_path).await?;
    let named_entry = named
        .get(&group_id)
        .ok_or_else(|| anyhow::anyhow!("named_groups.json entry"))?;
    assert!(s3::is_s3_placeholder(named_entry));
    assert!(seats_no_one(named_entry));
    assert!(named_entry
        .policy
        .admission
        .owner_certified_user_id()
        .is_none());

    // A released binary loads an inert group.
    let released = released_view(state).await?;
    let loaded = released
        .get(&group_id)
        .ok_or_else(|| anyhow::anyhow!("released entry"))?;
    assert!(seats_no_one(loaded), "released binary: no Active seat");

    // The crash window of the arming save: the sidecar is replaced, but
    // `named_groups.json` still holds the pre-arm #451 placeholder. The
    // released binary must still load an inert group.
    tokio::fs::write(&state.named_groups_path, &named_before_arm).await?;
    let released = released_view(state).await?;
    let loaded = released
        .get(&group_id)
        .ok_or_else(|| anyhow::anyhow!("released entry after the crash"))?;
    assert!(
        seats_no_one(loaded),
        "#1569: after a crash in the arming save, a released binary must not seat anyone"
    );

    // This binary's load splices the authoritative record back in.
    let current =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    let record = current
        .get(&group_id)
        .ok_or_else(|| anyhow::anyhow!("current entry"))?;
    assert!(
        !s3::is_s3_placeholder(record),
        "the splice restores the record"
    );
    assert_eq!(record.state_hash, info.state_hash);
    assert_eq!(
        record.policy.admission,
        GroupAdmission::OwnerCertified(owner)
    );
    Ok(())
}
