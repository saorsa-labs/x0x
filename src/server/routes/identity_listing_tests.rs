#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Issue #1108 (additive slice): `GET /agent` discloses the agent signing
//! key, and `GET /identity/revocations` lists every subject kind.

use super::*;
use crate::identity::{AgentCertificate, AgentId, AgentKeypair, MachineId, UserKeypair};
use crate::revocation::{
    AgentMachineBinding, RevocationRecord, RevokedSubject, ShareGrantRevocation,
};
use crate::server::routes::named_groups::tests::secure_endpoint_test_state_at;

async fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let agent = Arc::new(
        crate::Agent::builder()
            // An own identity dir: the default one is shared by all tests
            // and can hold revocation records from other tests.
            .with_identity_dir(&data_dir)
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(AgentKeypair::generate().unwrap())
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await
            .unwrap(),
    );
    let state = secure_endpoint_test_state_at(&data_dir, agent)
        .await
        .unwrap();
    (state, dir)
}

/// WHY (#1108 item 4): a caller needs the agent ML-DSA-65 public key to ask
/// an owner for a certificate (`POST /owner/agents/issue` takes it as hex).
/// The key must be the one `agent_id` is derived from, or the caller would
/// certify a different identity.
#[tokio::test]
async fn agent_info_returns_the_public_key_that_hashes_to_agent_id() {
    use sha2::{Digest, Sha256};

    let (state, _dir) = test_state().await;
    let Json(resp) = agent_info(State(Arc::clone(&state))).await;
    let data = serde_json::to_value(&resp.data).unwrap();

    let key_hex = data["agent_public_key"]
        .as_str()
        .expect("GET /agent must return agent_public_key");
    let key_bytes = hex::decode(key_hex).expect("agent_public_key is hex");
    assert_eq!(key_bytes.len(), 1952, "ML-DSA-65 public key length");

    // The identity derivation: SHA-256 over the domain separator and the key.
    let mut hasher = Sha256::new();
    hasher.update(b"AUTONOMI_PEER_ID_V2:");
    hasher.update(&key_bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    assert_eq!(data["agent_id"], hex::encode(digest));
    assert_eq!(digest, *state.agent.agent_id().as_bytes());

    // The fields that existed before stay.
    assert!(data["machine_id"].is_string());
    assert!(data["kem_public_key_b64"].is_string());
}

/// WHY (#1108 item 3): binding tombstones and share-grant revocations are in
/// force on this daemon, so an operator must be able to see them. The old
/// listing showed Agent and Machine records only.
#[tokio::test]
async fn revocation_listing_shows_every_subject_kind() {
    let (state, _dir) = test_state().await;

    // An owner, and an agent the owner certified.
    let owner = UserKeypair::generate().unwrap();
    let sub_agent = AgentKeypair::generate().unwrap();
    let cert = AgentCertificate::issue(&owner, &sub_agent).unwrap();
    let sub_agent_id = AgentId::from_public_key(sub_agent.public_key());
    let machine = MachineId([0x4D; 32]);
    let grant_id = [0x6A; 32];

    // A second agent that revokes itself (a v1 record).
    let other_agent = AgentKeypair::generate().unwrap();
    let other_agent_id = AgentId::from_public_key(other_agent.public_key());

    let agent_record = RevocationRecord::sign(
        RevokedSubject::Agent(other_agent_id),
        other_agent.public_key(),
        other_agent.secret_key(),
        1_800_000_001,
        Some("retired".to_string()),
    )
    .unwrap();
    let binding_record = RevocationRecord::sign(
        RevokedSubject::AgentMachineBinding(AgentMachineBinding {
            agent: sub_agent_id,
            machine,
            move_epoch: 7,
        }),
        owner.public_key(),
        owner.secret_key(),
        1_800_000_002,
        Some("lost laptop".to_string()),
    )
    .unwrap();
    let grant_record = RevocationRecord::sign(
        RevokedSubject::ShareGrant(ShareGrantRevocation {
            grant_id,
            owner: owner.user_id(),
            grant_expiry: 1_900_000_000,
        }),
        owner.public_key(),
        owner.secret_key(),
        1_800_000_003,
        None,
    )
    .unwrap();

    {
        let set = state.agent.revocation_set();
        let mut set = set.write().await;
        assert!(set.verify_and_insert(agent_record, None).unwrap());
        assert!(set.verify_and_insert(binding_record, Some(&cert)).unwrap());
        assert!(set.verify_and_insert(grant_record, None).unwrap());
    }

    let resp = identity_revocations(State(Arc::clone(&state)))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let items = body["revocations"].as_array().unwrap();
    assert_eq!(items.len(), 3, "one row per held record: {body}");

    let row = |kind: &str| {
        items
            .iter()
            .find(|item| item["subject_kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} row in {body}"))
    };
    let owner_hex = hex::encode(owner.user_id().as_bytes());
    // `issuer` keeps its old meaning: plain SHA-256 of the issuer key.
    let owner_key_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(owner.public_key().as_bytes()))
    };

    // Each row keeps the fields that existed before.
    for item in items {
        for field in ["subject", "subject_kind", "issuer", "revoked_at"] {
            assert!(!item[field].is_null(), "{field} missing in {item}");
        }
        assert!(item.get("reason").is_some(), "reason missing in {item}");
    }

    let agent_row = row("agent");
    assert_eq!(agent_row["subject"], hex::encode(other_agent_id.as_bytes()));
    assert_eq!(agent_row["reason"], "retired");
    assert_eq!(
        agent_row["agent_id"],
        hex::encode(other_agent_id.as_bytes())
    );

    let binding_row = row("binding");
    assert_eq!(binding_row["subject"], hex::encode(sub_agent_id.as_bytes()));
    assert_eq!(
        binding_row["agent_id"],
        hex::encode(sub_agent_id.as_bytes())
    );
    assert_eq!(binding_row["machine_id"], hex::encode(machine.as_bytes()));
    assert_eq!(binding_row["move_epoch"], 7);
    assert_eq!(binding_row["issuer"], owner_key_hash);
    assert_eq!(binding_row["revoked_at"], 1_800_000_002u64);
    assert_eq!(binding_row["reason"], "lost laptop");

    let grant_row = row("share_grant");
    assert_eq!(grant_row["subject"], hex::encode(grant_id));
    assert_eq!(grant_row["grant_id"], hex::encode(grant_id));
    assert_eq!(grant_row["owner"], owner_hex);
    assert_eq!(grant_row["grant_expiry"], 1_900_000_000u64);
    assert_eq!(grant_row["issuer"], owner_key_hash);
    assert!(grant_row["reason"].is_null());

    // Rows are in a stable order: oldest first.
    let times: Vec<u64> = items
        .iter()
        .map(|item| item["revoked_at"].as_u64().unwrap())
        .collect();
    assert_eq!(times, [1_800_000_001, 1_800_000_002, 1_800_000_003]);

    // The v1 snapshot still holds legacy subjects only.
    let v1 = state.agent.revocation_records().await;
    assert_eq!(v1.len(), 1);
    assert!(matches!(v1[0].subject, RevokedSubject::Agent(_)));
}

async fn revoke_machine(
    state: &Arc<AppState>,
    durable: bool,
    machine: &MachineId,
) -> (StatusCode, serde_json::Value) {
    let response = identity_revoke(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable }),
        Json(RevokeRequest {
            agent_id: None,
            machine_id: Some(hex::encode(machine.as_bytes())),
            move_epoch: None,
            reason: Some("retired".to_string()),
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// WHY (#1108 item 1): the docs said a daemon can revoke its own machine,
/// but the route signed with the agent key, so the answer was always 403.
/// The daemon holds the machine key; a record signed with it is one that
/// every peer accepts with no other evidence.
#[tokio::test]
async fn own_machine_revoke_signs_with_the_machine_key() {
    let (state, _dir) = test_state().await;
    let machine = state.agent.machine_id();

    let announce_before = state.agent.announce_identity(false, false).await.is_ok();

    let (status, body) = revoke_machine(&state, true, &machine).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["subject_kind"], "machine");
    assert_eq!(body["subject"], hex::encode(machine.as_bytes()));
    assert!(
        body["warning"]
            .as_str()
            .is_some_and(|w| w.contains("revoked for good")),
        "the answer warns that the machine identity is dead: {body}"
    );

    // Another daemon accepts the record from the record alone.
    let records = state.agent.all_revocation_records().await;
    assert_eq!(records.len(), 1);
    let mut peer = crate::revocation::RevocationSet::new();
    assert!(peer.verify_and_insert(records[0].clone(), None).unwrap());
    assert!(peer.is_machine_revoked(&machine));

    // The daemon does not stop itself: its own announce call gives the
    // same result as before the revocation (peers are the ones that
    // refuse it).
    assert_eq!(
        state.agent.announce_identity(false, false).await.is_ok(),
        announce_before
    );

    // A repeat signs no second record.
    let (status, body) = revoke_machine(&state, true, &machine).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["already_revoked"], true);
    assert_eq!(state.agent.all_revocation_records().await.len(), 1);
}

/// WHY: a machine revocation cannot be undone, so a session token must
/// not do it. A daemon has no authority over any other machine, so that
/// request keeps its 403 and signs nothing that a peer would accept.
#[tokio::test]
async fn machine_revoke_refuses_a_session_token_and_another_machine() {
    let (state, _dir) = test_state().await;

    let (status, _) = revoke_machine(&state, false, &state.agent.machine_id()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "session token");

    let other = MachineId([0x4E; 32]);
    let (status, _) = revoke_machine(&state, true, &other).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "another machine");

    let set = state.agent.revocation_set();
    let set = set.read().await;
    assert!(!set.is_machine_revoked(&state.agent.machine_id()));
    assert!(!set.is_machine_revoked(&other));
}
