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
//!
//! postcard is positional. If two fields of the same type held the same
//! bytes, a swap of their declarations would still decode and re-encode
//! exactly. So no two same-typed fields in the fixture hold the same value,
//! and the test checks the expected value of each field.

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
        subject: SUBJECT.to_string(),
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

/// The ATA and re-seat subject (hex agent id).
const SUBJECT: &str = "abababababababababababababababababababababababababababababababab";

/// The ATA sequence of `active_ata`.
const ACTIVE_SEQUENCE: [&str; 2] = ["h2", "h3"];
/// The ATA sequence of `attestation_conflict` (forks at the second step).
const CONFLICT_SEQUENCE: [&str; 3] = ["h2", "x3", "x4"];
/// The exact `queued_terminal` bytes.
const QUEUED_TERMINAL: &[u8] = br#"{"event":"fixture-queued-terminal"}"#;
const JOURNAL_INVITE: &str = "x0x://invite/fixture-journal";
const ISSUED_INVITE: &str = "x0x://invite/fixture-issued";
const LIVE_TREE: [u8; 8] = [0x22; 8];
const RETIRED_CAUSE: &str = "reseat";

/// Each embedded `GroupInfo` record carries its own description, so that a
/// decoded record shows which field it came from. Postcard is positional:
/// identical bytes in two same-typed fields would hide a swap of the two.
const AUTHORITATIVE_LABEL: &str = "fixture authoritative_record";
const STAGING_LABEL: &str = "fixture staging_record";
const LIVE_LABEL: &str = "fixture reseat_journal.live_record";
const RETIRED_LABEL: &str = "fixture retired.record";
const BEFORE_LABEL: &str = "fixture authoritative_binding.before_record";

/// `info` as JSON, with `label` as its description.
fn labelled_record(info: &GroupInfo, label: &str) -> Vec<u8> {
    let mut copy = info.clone();
    copy.description = label.to_string();
    serde_json::to_vec(&copy).expect("record json")
}

/// The description of a JSON `GroupInfo` record.
fn record_label(bytes: &[u8]) -> String {
    serde_json::from_slice::<GroupInfo>(bytes)
        .expect("record json")
        .description
}

/// A sidecar with every field set, as a subject that holds an S3
/// placeholder, a conflicting ATA and an open re-seat would write it.
/// Two fields of the same type never hold the same value.
fn full_sidecar(admin: &AgentKeypair) -> GroupRecoveryV1 {
    let mut info = GroupInfo::new(
        "fixture".to_string(),
        "S3 sidecar fixture".to_string(),
        admin.agent_id(),
        "cd".repeat(32),
    );
    info.add_member(
        SUBJECT.to_string(),
        GroupRole::Member,
        Some(hex::encode(admin.agent_id().as_bytes())),
        None,
    );
    info.seal_commit(admin, NOW_MS).expect("seal");
    let group = info.stable_group_id().to_string();
    let served_chain = info
        .commit_log
        .iter()
        .map(|entry| serde_json::to_vec(entry).expect("commit json"))
        .collect();
    let live_record = labelled_record(&info, LIVE_LABEL);
    let authorisation = ReseatAuthorisation::sign(
        ReseatAuthorisationFields {
            group: group.clone(),
            subject: SUBJECT.to_string(),
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
        active_ata: Some(ata(admin, &group, &ACTIVE_SEQUENCE)),
        queued_terminal: Some(QUEUED_TERMINAL.to_vec()),
        authoritative_record: Some(labelled_record(&info, AUTHORITATIVE_LABEL)),
        reseat_journal: Some(ReseatJournalV1 {
            authorisation: authorisation.clone(),
            invite: JOURNAL_INVITE.to_string(),
            record_digest: *blake3::hash(&live_record).as_bytes(),
            phase: ReseatPhase::Staging,
            live_key: info.mls_group_id.clone(),
            live_record,
            live_tree: Some(LIVE_TREE.to_vec()),
            started_at_ms: NOW_MS + 1,
        }),
        staging_record: Some(labelled_record(&info, STAGING_LABEL)),
        issued_reseats: vec![IssuedReseatV1 {
            authorisation,
            invite: ISSUED_INVITE.to_string(),
            issued_at_ms: NOW_MS + 2,
        }],
        retired: vec![RetiredRecordV1 {
            cause: RETIRED_CAUSE.to_string(),
            retired_at_ms: NOW_MS + 3,
            record: labelled_record(&info, RETIRED_LABEL),
        }],
        attestation_conflict: Some(ata(admin, &group, &CONFLICT_SEQUENCE)),
        authoritative_binding: Some(AuthoritativeBindingV1 {
            live_key: info.mls_group_id.clone(),
            before: AuthoritativeHead {
                revision: 1,
                state_hash: "h1".to_string(),
                marker: None,
            },
            before_record: Some(labelled_record(&info, BEFORE_LABEL)),
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

/// The fixture decodes, every field holds its own expected value and is
/// verifiable, and the current encoder writes the same bytes again. A
/// reordered, removed, added (other than at a new format version) or
/// retyped field fails here. Postcard is positional, so a swap of two
/// same-typed fields still round-trips: the per-field value checks below
/// catch it, because no two same-typed fields hold the same value.
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

    // The three `Option<Vec<u8>>` fields.
    assert_eq!(body.queued_terminal.as_deref(), Some(QUEUED_TERMINAL));
    let record_bytes = body.authoritative_record.as_deref().expect("record");
    assert_eq!(record_label(record_bytes), AUTHORITATIVE_LABEL);
    let record: GroupInfo = serde_json::from_slice(record_bytes).expect("record json");
    let staging = body.staging_record.as_deref().expect("staging_record");
    assert_eq!(record_label(staging), STAGING_LABEL);

    // The two `Option<AdminTerminalAttestation>` fields.
    let active = body.active_ata.as_ref().expect("active_ata");
    active.verify_signature().expect("active_ata signature");
    assert_eq!(active.fields.sequence, ACTIVE_SEQUENCE);
    assert_eq!(active.fields.group, record.stable_group_id());
    assert_eq!(active.fields.subject, SUBJECT);
    let conflict = body
        .attestation_conflict
        .as_ref()
        .expect("attestation_conflict");
    conflict
        .verify_signature()
        .expect("attestation_conflict signature");
    assert_eq!(conflict.fields.sequence, CONFLICT_SEQUENCE);

    let journal = body.reseat_journal.as_ref().expect("reseat_journal");
    assert_eq!(journal.phase, ReseatPhase::Staging);
    journal
        .authorisation
        .verify_signature(&active.fields.signer_public_key)
        .expect("journal authorisation signature");
    assert_eq!(journal.authorisation.fields.subject, SUBJECT);
    assert_eq!(journal.invite, JOURNAL_INVITE);
    assert_eq!(journal.live_key, record.mls_group_id);
    assert_eq!(record_label(&journal.live_record), LIVE_LABEL);
    assert_eq!(
        journal.record_digest,
        *blake3::hash(&journal.live_record).as_bytes()
    );
    assert_eq!(journal.live_tree.as_deref(), Some(&LIVE_TREE[..]));
    assert_eq!(journal.started_at_ms, NOW_MS + 1);

    let [issued] = body.issued_reseats.as_slice() else {
        panic!("one issued re-seat");
    };
    issued
        .authorisation
        .verify_signature(&active.fields.signer_public_key)
        .expect("issued authorisation signature");
    assert_eq!(issued.invite, ISSUED_INVITE);
    assert_eq!(issued.issued_at_ms, NOW_MS + 2);

    let [retired] = body.retired.as_slice() else {
        panic!("one retired record");
    };
    assert_eq!(retired.cause, RETIRED_CAUSE);
    assert_eq!(retired.retired_at_ms, NOW_MS + 3);
    assert_eq!(record_label(&retired.record), RETIRED_LABEL);

    let binding = body
        .authoritative_binding
        .as_ref()
        .expect("authoritative_binding");
    assert_eq!(binding.live_key, record.mls_group_id);
    assert_eq!(
        binding.before,
        AuthoritativeHead {
            revision: 1,
            state_hash: "h1".to_string(),
            marker: None,
        }
    );
    assert_eq!(binding.after, AuthoritativeHead::of(&record));
    assert_ne!(binding.before, binding.after);
    assert_eq!(
        record_label(binding.before_record.as_deref().expect("before_record")),
        BEFORE_LABEL
    );
}
