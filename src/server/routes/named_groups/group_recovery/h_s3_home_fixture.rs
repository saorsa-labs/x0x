//! #1571, ADR 0109 H-S3-home and ADR 0085 rule 6: candidate data
//! directories that hold the S3 Home placeholder, under
//! `tests/fixtures/h_s3_home/<variant>/`. The H-S3-home gate starts the
//! released binaries on copies of them; the inert test here loads them.
//!
//! Variants (ADR 0109 Validation, H-S3-home): `creator` is the Home creator
//! O (owner install, with `home.json`); `owner_device` is J with the
//! owner's user key and its own agent certificate; `device` is J with an
//! agent certificate and no user key. A promoted admin A2 signs the ATA.
//! No owner-sync data is copied, so no canonical Home pointer is stored.

use super::*;
use std::path::{Path, PathBuf};

/// Fixed owner seed: the owner user ID is the same on every run.
const OWNER_SEED: [u8; 32] = [0x16; 32];

/// The variants, and whether each is an owner install. ADR 0109 §4 "Risk"
/// predicted that owner installs fail H-S3-home. Measured on 31 Oct 2026,
/// they pass on v0.45.0 and v0.46.1: the released adoption step tries to
/// stamp the inert group and its seal fails the zero-active-admins
/// invariant, so no fresh Home is created. No variant is an expected
/// failure.
const VARIANTS: [(&str, bool); 3] = [("creator", true), ("owner_device", true), ("device", false)];

/// Identity and data files of a variant that the fixture keeps.
const KEPT: [&str; 7] = [
    "identity/machine.key",
    "identity/agent.key",
    "identity/agent.cert",
    "identity/user.key",
    "named_groups.json",
    "home-suite-groups.json",
    "home.json",
];

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/h_s3_home")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// A daemon-shaped state on `dir`: keys under `identity/` (the gate's
/// `identity_dir`), an owner-issued agent certificate, and the user key
/// only for an owner install.
async fn variant_state(
    dir: &Path,
    user: &x0x::identity::UserKeypair,
    owner_install: bool,
) -> anyhow::Result<Arc<AppState>> {
    let identity = dir.join("identity");
    tokio::fs::create_dir_all(&identity).await?;
    let agent_kp = x0x::identity::AgentKeypair::generate()?;
    x0x::storage::save_agent_keypair_to(&agent_kp, identity.join("agent.key")).await?;
    let cert = x0x::identity::AgentCertificate::issue(user, &agent_kp)?;
    x0x::storage::save_agent_certificate_to(&cert, identity.join("agent.cert")).await?;
    let mut builder = x0x::Agent::builder()
        .with_machine_key(identity.join("machine.key"))
        .with_agent_key_path(identity.join("agent.key"))
        .with_agent_cert_path(identity.join("agent.cert"))
        .with_peer_cache_disabled()
        .with_contact_store_path(dir.join("contacts.json"));
    if owner_install {
        x0x::storage::save_user_keypair_to(user, identity.join("user.key")).await?;
        builder = builder.with_user_key(x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?);
    }
    let agent = Arc::new(builder.build().await?);
    super::super::tests::secure_endpoint_test_state_at(dir, agent).await
}

/// Generate the fixture. Run by hand, then update `PROVENANCE.md`:
/// `cargo nextest run --all-features --lib --run-ignored only -E
/// 'test(generate_h_s3_home_fixture)'`. ML-DSA signatures and timestamps
/// differ on each run; the layout and the placeholder form do not.
#[tokio::test]
#[ignore = "writes tests/fixtures/h_s3_home; run by hand"]
async fn generate_h_s3_home_fixture() -> anyhow::Result<()> {
    let scratch = tempfile::tempdir()?;
    let user = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
    let mut states = Vec::new();
    for (name, owner_install) in VARIANTS {
        states.push(variant_state(&scratch.path().join(name), &user, owner_install).await?);
    }
    let creator = Arc::clone(&states[0]);
    crate::server::routes::home::provision_home(&creator).await;
    let (group_key, mut info) = crate::server::routes::home::find_home(&creator, &user.user_id())
        .await
        .ok_or_else(|| anyhow::anyhow!("the creator provisioned no Home"))?;

    // A2 (promoted admin) and both J devices are seated, each with the
    // owner-issued certificate that OwnerCertified admission needs.
    let a2 = x0x::identity::AgentKeypair::generate()?;
    let creator_hex = local_hex(&creator);
    let mut seats = vec![(&a2, x0x::groups::GroupRole::Admin)];
    for state in &states[1..] {
        seats.push((
            state.agent.identity().agent_keypair(),
            x0x::groups::GroupRole::Member,
        ));
    }
    for (kp, role) in seats {
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        info.add_member(hex_id.clone(), role, Some(creator_hex.clone()), None);
        let cert = x0x::identity::AgentCertificate::issue(&user, kp)?;
        anyhow::ensure!(info.set_member_certificate(&hex_id, cert).is_ok());
    }
    let signer = creator.agent.identity().agent_keypair();
    super::super::seal_commit_owner_certified(&creator, &mut info, signer, now_ms())
        .await
        .map_err(|e| anyhow::anyhow!("seal: {e:?}"))?;
    anyhow::ensure!(is_home_policy_group(&info) && info.home.is_some());

    let stable = info.stable_group_id().to_string();
    let root = fixture_root();
    let _ = tokio::fs::remove_dir_all(&root).await;
    let mut manifest = serde_json::Map::new();
    for ((name, owner_install), state) in VARIANTS.into_iter().zip(&states) {
        state
            .named_groups
            .write()
            .await
            .insert(group_key.clone(), info.clone());
        anyhow::ensure!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        // Home activation on by test configuration; A2's ATA arms the
        // subject through the real arming path.
        state.group_recovery.activate_home();
        let ata = AdminTerminalAttestation::sign(
            AtaFields {
                group: stable.clone(),
                subject: local_hex(state),
                attested_by: hex::encode(a2.agent_id().as_bytes()),
                signer_public_key: hex::encode(a2.public_key().as_bytes()),
                from_revision: info.state_revision,
                from_state_hash: info.state_hash.clone(),
                sequence: vec!["a1".to_string(), "a2".to_string()],
                segment_terminal_revision: info.state_revision + 2,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &a2,
        )?;
        anyhow::ensure!(arm_in_place(state, &group_key, &info, ata).await);

        let src = scratch.path().join(name);
        let dst = root.join(name);
        let grecov = format!("group-recovery/{}", s3::sidecar_file_name(&stable));
        for rel in KEPT.iter().copied().chain([grecov.as_str()]) {
            if let Ok(bytes) = tokio::fs::read(src.join(rel)).await {
                let out = dst.join(rel);
                if let Some(parent) = out.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(out, bytes).await?;
            }
        }
        let home_json = tokio::fs::read(dst.join("home.json")).await.ok();
        manifest.insert(
            name.to_string(),
            serde_json::json!({
                "agent_id": local_hex(state),
                "owner_install": owner_install,
                "expected_failure": false,
                "stable_group_id": stable,
                "group_key": group_key,
                "group_ids": [group_key],
                "home_json_sha256": home_json.as_deref().map(sha256_hex),
                "grecov": grecov,
                "grecov_sha256": sha256_hex(&tokio::fs::read(dst.join(&grecov)).await?),
            }),
        );
    }
    let text = serde_json::to_string_pretty(&serde_json::Value::Object(manifest))?;
    tokio::fs::write(root.join("manifest.json"), format!("{text}\n")).await?;
    Ok(())
}

/// ADR 0085 rule 6: every variant of the fixture loads. A released
/// binary's view (no S3 splice) holds one inert Home with its `home`
/// metadata; this binary's load splices the real record back; the sidecar
/// decodes as `X0GRCV1`. The manifest hashes match the files.
#[tokio::test]
async fn h_s3_home_fixture_loads() -> anyhow::Result<()> {
    let root = fixture_root();
    let manifest: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(root.join("manifest.json")).await?)?;
    for (name, _) in VARIANTS {
        let entry = &manifest[name];
        let dir = root.join(name);
        let key = entry["group_key"].as_str().unwrap_or_default();
        let agent = entry["agent_id"].as_str().unwrap_or_default();
        let named_path = dir.join("named_groups.json");
        let suite_path = dir.join(super::super::HOME_SUITE_GROUPS_FILE);

        let named = super::super::load_named_groups(&named_path).await?;
        let suite = super::super::load_home_suite_groups(&suite_path).await?;
        let named_entry = named
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{name}"))?;
        let suite_entry = suite
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{name}"))?;
        assert!(s3::is_s3_placeholder(&named_entry), "{name}");
        assert!(named_entry.home.is_none(), "{name}: #451 form");
        assert!(named_entry
            .policy
            .admission
            .owner_certified_user_id()
            .is_none());
        assert!(s3::is_s3_placeholder(&suite_entry), "{name}");
        assert!(suite_entry.home.is_some(), "{name}: Home metadata kept");
        assert!(is_home_policy_group(&suite_entry), "{name}");
        let released = super::super::merge_home_suite_groups(named, suite);
        assert_eq!(released.len(), 1, "{name}");
        let loaded = released.get(key).ok_or_else(|| anyhow::anyhow!("{name}"))?;
        assert!(loaded.members_v2.values().all(|m| !m.is_active()), "{name}");

        let current = super::super::load_named_groups_merged(&named_path, &suite_path).await?;
        let record = current.get(key).ok_or_else(|| anyhow::anyhow!("{name}"))?;
        assert!(!s3::is_s3_placeholder(record), "{name}: spliced back");
        assert!(
            record.home.is_some() && record.has_active_member(agent),
            "{name}"
        );

        let grecov =
            tokio::fs::read(dir.join(entry["grecov"].as_str().unwrap_or_default())).await?;
        assert_eq!(
            Some(sha256_hex(&grecov).as_str()),
            entry["grecov_sha256"].as_str()
        );
        let body = s3::decode_sidecar(&grecov).map_err(|e| anyhow::anyhow!("{name}: {e:?}"))?;
        assert!(
            body.active_ata.is_some() && body.authoritative_record.is_some(),
            "{name}"
        );
        let home_json = tokio::fs::read(dir.join("home.json")).await.ok();
        assert_eq!(
            home_json.as_deref().map(sha256_hex).as_deref(),
            entry["home_json_sha256"].as_str(),
            "{name}"
        );
    }
    Ok(())
}
