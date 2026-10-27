//! ADR 0085 rule 6 format fixture for the S3 sidecar (#1568).
//!
//! `tests/fixtures/group_recovery_v1.bin` is a `X0GRCV1\0` file written by
//! this crate's own [`encode_sidecar`], with every [`GroupRecoveryV1`] field
//! set, including the two fields that #1533 added beyond the ADR 0109 §4
//! list: `attestation_conflict` and `authoritative_binding`. The format is
//! not released yet, so this is the initial encoder fixture (provenance in
//! `tests/fixtures/group_recovery_v1.PROVENANCE.txt`). Keep it unchanged
//! when the format releases: a change to the field order or to a field's
//! type then fails [`v1_sidecar_fixture_decodes_and_re_encodes_exactly`].

#![cfg(test)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::*;
use crate::groups::member::GroupRole;

/// Signed-time and issue-time stamp for every signed record (unix ms).
const NOW_MS: u64 = 2_000_000_000_000;

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/group_recovery_v1.bin")
}

fn ata(admin: &AgentKeypair, group: &str, sequence: &[&str]) -> AdminTerminalAttestation {
    let fields = AtaFields {
        group: group.to_string(),
        subject: "ab".repeat(32),
        attested_by: hex::encode(admin.agent_id().as_bytes()),
        signer_public_key: hex::encode(admin.public_key().as_bytes()),
        from_revision: 1,
        from_state_hash: "h1".to_string(),
        sequence: sequence.iter().map(ToString::to_string).collect(),
        segment_terminal_revision: 1 + sequence.len() as u64,
        segment_terminal_epoch: Some(2),
        issued_at_ms: NOW_MS,
    };
    AdminTerminalAttestation::sign(fields, admin).expect("sign ata")
}

/// A sidecar with every field set, as a subject that holds an S3
/// placeholder, a conflicting ATA and an open re-seat would write it.
fn full_sidecar(admin: &AgentKeypair) -> GroupRecoveryV1 {
    let mut info = GroupInfo::new(
        "fixture".to_string(),
        "S3 sidecar fixture".to_string(),
        admin.agent_id(),
        "cd".repeat(32),
    );
    info.add_member(
        "ab".repeat(32),
        GroupRole::Member,
        Some(hex::encode(admin.agent_id().as_bytes())),
        None,
    );
    info.seal_commit(admin, NOW_MS).expect("seal");
    let group = info.stable_group_id().to_string();
    let record = serde_json::to_vec(&info).expect("record json");
    let served_chain = info
        .commit_log
        .iter()
        .map(|entry| serde_json::to_vec(entry).expect("commit json"))
        .collect();
    let authorisation = ReseatAuthorisation::sign(
        ReseatAuthorisationFields {
            group: group.clone(),
            subject: "ab".repeat(32),
            basis: ReseatBasis::Removal {
                revision: 2,
                state_hash: "h2".to_string(),
            },
            invite_secret_hash: invite_secret_hash("fixture-secret"),
            invite_base_revision: info.state_revision,
            invite_base_state_hash: info.state_hash.clone(),
            signer: hex::encode(admin.agent_id().as_bytes()),
            reason_hash: reason_hash("fixture"),
            expires_at_ms: NOW_MS + 3_600_000,
        },
        admin,
    )
    .expect("sign authorisation");
    let head = AuthoritativeHead::of(&info);
    GroupRecoveryV1 {
        generation: 7,
        rebuilt_from: vec![[0x11; 16]],
        served_chain,
        active_ata: Some(ata(admin, &group, &["h2", "h3"])),
        queued_terminal: Some(br#"{"event":"fixture"}"#.to_vec()),
        authoritative_record: Some(record.clone()),
        reseat_journal: Some(ReseatJournalV1 {
            authorisation: authorisation.clone(),
            invite: "x0x://invite/fixture".to_string(),
            record_digest: *blake3::hash(&record).as_bytes(),
            phase: ReseatPhase::Staging,
            live_key: info.mls_group_id.clone(),
            live_record: record.clone(),
            live_tree: Some(vec![0x22; 8]),
            started_at_ms: NOW_MS,
        }),
        staging_record: Some(record.clone()),
        issued_reseats: vec![IssuedReseatV1 {
            authorisation,
            invite: "x0x://invite/fixture".to_string(),
            issued_at_ms: NOW_MS,
        }],
        retired: vec![RetiredRecordV1 {
            cause: "reseat".to_string(),
            retired_at_ms: NOW_MS,
            record: record.clone(),
        }],
        attestation_conflict: Some(ata(admin, &group, &["h2", "x3"])),
        authoritative_binding: Some(AuthoritativeBindingV1 {
            live_key: info.mls_group_id.clone(),
            before: AuthoritativeHead {
                revision: 1,
                state_hash: "h1".to_string(),
                marker: None,
            },
            before_record: Some(record),
            after: head,
        }),
    }
}

#[test]
#[ignore = "Explicit initial V1 fixture generation; never rewrite a released fixture"]
fn generate_initial_v1_sidecar_fixture() {
    let admin = AgentKeypair::generate().expect("keypair");
    let bytes = encode_sidecar(&full_sidecar(&admin)).expect("encode");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(fixture_path())
        .expect("create_new fixture");
    output.write_all(&bytes).expect("write fixture");
}

/// The fixture decodes, every field is present and verifiable, and the
/// current encoder writes the same bytes again. A reordered, removed,
/// added (other than at a new format version) or retyped field fails here.
#[test]
fn v1_sidecar_fixture_decodes_and_re_encodes_exactly() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    assert!(bytes.starts_with(GROUP_RECOVERY_HEADER_V1));
    let body = decode_sidecar(&bytes).expect("decode fixture");
    assert_eq!(encode_sidecar(&body).expect("re-encode"), bytes);

    assert_eq!(body.generation, 7);
    assert_eq!(body.rebuilt_from, vec![[0x11; 16]]);
    assert!(!body.served_chain.is_empty());
    for link in &body.served_chain {
        serde_json::from_slice::<crate::groups::state_commit::RetainedCommit>(link)
            .expect("served link json");
    }
    let active = body.active_ata.as_ref().expect("active_ata");
    active.verify_signature().expect("active_ata signature");
    assert!(body.queued_terminal.is_some());
    let record: GroupInfo =
        serde_json::from_slice(body.authoritative_record.as_deref().expect("record"))
            .expect("authoritative_record json");
    let journal = body.reseat_journal.as_ref().expect("reseat_journal");
    assert_eq!(journal.phase, ReseatPhase::Staging);
    journal
        .authorisation
        .verify_signature(&active.fields.signer_public_key)
        .expect("authorisation signature");
    assert!(body.staging_record.is_some());
    assert_eq!(body.issued_reseats.len(), 1);
    assert_eq!(body.retired.len(), 1);

    // The two fields beyond the ADR 0109 §4 list.
    let conflict = body
        .attestation_conflict
        .as_ref()
        .expect("attestation_conflict");
    conflict
        .verify_signature()
        .expect("attestation_conflict signature");
    assert_ne!(conflict.fields.sequence, active.fields.sequence);
    let binding = body
        .authoritative_binding
        .as_ref()
        .expect("authoritative_binding");
    assert_eq!(binding.live_key, record.mls_group_id);
    assert_eq!(binding.after, AuthoritativeHead::of(&record));
    assert!(binding.before_record.is_some());
}
