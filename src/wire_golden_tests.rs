//! Golden wire fixtures for the wire-format enums (#1604).
//!
//! Each file in `tests/fixtures/wire-enums-1604/` holds, for one enum, a
//! hand-written JSON `input` per existing variant and the `wire` encoding of
//! that value as `origin/main` @ `545b781` produced it (hex for bincode and
//! postcard, text for serde_json). The fixtures were captured on that
//! commit, before any `#[non_exhaustive]` or `Unknown` change.
//!
//! [`check`] proves, for each case and codec:
//! - encoding the input value gives the main-era bytes exactly;
//! - the main-era bytes still decode (round-trip codecs), re-encode to the
//!   same bytes, and give the same value.
//!
//! Do not regenerate a fixture unless an approved wire change alters it.
//! Capture mode (`X0X_WIRE_GOLDEN_CAPTURE=1`) only fills a `wire` entry
//! that is still `null`; it never overwrites a frozen one.

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// Wire codec of one fixture encoding.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Codec {
    /// `serde_json` text.
    Json,
    /// `bincode::serialize` (fixint, little endian).
    Bincode,
    /// `postcard::to_stdvec`.
    Postcard,
}

/// What the fixture proves for a codec.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode {
    /// Encode and decode are both on the wire.
    RoundTrip,
    /// Only the encoding is used (a signing or hash preimage, or a codec
    /// that cannot decode this enum shape).
    EncodeOnly,
}

impl Codec {
    fn key(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Bincode => "bincode",
            Self::Postcard => "postcard",
        }
    }

    fn encode<T: Serialize>(self, value: &T) -> String {
        match self {
            Self::Json => serde_json::to_string(value).expect("json encode"),
            Self::Bincode => hex::encode(bincode::serialize(value).expect("bincode encode")),
            Self::Postcard => hex::encode(postcard::to_stdvec(value).expect("postcard encode")),
        }
    }

    fn decode<T: DeserializeOwned>(self, wire: &str) -> Result<T, String> {
        match self {
            Self::Json => serde_json::from_str(wire).map_err(|e| e.to_string()),
            Self::Bincode => {
                let bytes = hex::decode(wire).map_err(|e| e.to_string())?;
                bincode::deserialize(&bytes).map_err(|e| e.to_string())
            }
            Self::Postcard => {
                let bytes = hex::decode(wire).map_err(|e| e.to_string())?;
                postcard::from_bytes(&bytes).map_err(|e| e.to_string())
            }
        }
    }
}

fn fixture_path(type_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wire-enums-1604")
        .join(format!("{type_name}.json"))
}

/// Expand the byte-array shorthands used in fixture inputs:
/// `"@b<N>:<V>"` becomes a JSON array of `N` copies of byte `V`.
fn expand(value: &Value) -> Value {
    match value {
        Value::String(s) => {
            if let Some(rest) = s.strip_prefix("@b") {
                if let Some((len, byte)) = rest.split_once(':') {
                    let len: usize = len.parse().expect("shorthand length");
                    let byte: u8 = byte.parse().expect("shorthand byte");
                    return Value::Array(vec![Value::from(byte); len]);
                }
            }
            value.clone()
        }
        Value::Array(items) => Value::Array(items.iter().map(expand).collect()),
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), expand(v))).collect())
        }
        _ => value.clone(),
    }
}

/// Check every case of `type_name` against its frozen main-era encodings.
///
/// `variants` lists the variant labels the fixture must cover, so a
/// fixture cannot silently miss an existing variant.
pub(crate) fn check<T: Serialize + DeserializeOwned>(
    type_name: &str,
    codecs: &[(Codec, Mode)],
    variants: &[&str],
) {
    let path = fixture_path(type_name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let mut doc: Value = serde_json::from_str(&text).expect("fixture json");
    let capture = std::env::var_os("X0X_WIRE_GOLDEN_CAPTURE").is_some();
    let mut captured = false;

    let labels: Vec<String> = doc["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .map(|c| c["variant"].as_str().expect("variant label").to_string())
        .collect();
    let mut expected: Vec<String> = variants.iter().map(|v| (*v).to_string()).collect();
    let mut have = labels.clone();
    expected.sort();
    have.sort();
    have.dedup();
    assert_eq!(have, expected, "{type_name}: fixture variant coverage");

    let cases = doc["cases"].as_array_mut().expect("cases array");
    for case in cases.iter_mut() {
        let label = case["variant"].as_str().expect("label").to_string();
        let value: T = serde_json::from_value(expand(&case["input"]))
            .unwrap_or_else(|e| panic!("{type_name}/{label}: build input: {e}"));
        let value_json = serde_json::to_value(&value).expect("value to json");
        for (codec, mode) in codecs {
            let encoded = codec.encode(&value);
            let frozen = case["wire"][codec.key()].as_str().map(str::to_string);
            let Some(frozen) = frozen else {
                assert!(
                    capture,
                    "{type_name}/{label}: no frozen {} encoding",
                    codec.key()
                );
                if !case["wire"].is_object() {
                    case["wire"] = Value::Object(serde_json::Map::new());
                }
                case["wire"][codec.key()] = Value::String(encoded);
                captured = true;
                continue;
            };
            assert_eq!(
                encoded,
                frozen,
                "{type_name}/{label}: {} encoding differs from main",
                codec.key()
            );
            if matches!(mode, Mode::RoundTrip) {
                let decoded: T = codec.decode(&frozen).unwrap_or_else(|e| {
                    panic!("{type_name}/{label}: main-era {} decode: {e}", codec.key())
                });
                assert_eq!(
                    codec.encode(&decoded),
                    frozen,
                    "{type_name}/{label}: {} re-encode differs",
                    codec.key()
                );
                assert_eq!(
                    serde_json::to_value(&decoded).expect("decoded to json"),
                    value_json,
                    "{type_name}/{label}: {} decode gives a different value",
                    codec.key()
                );
            }
        }
    }
    if captured {
        let text = serde_json::to_string_pretty(&doc).expect("fixture json") + "\n";
        std::fs::write(&path, text).expect("write fixture");
    }
}

use Codec::{Bincode, Json, Postcard};
use Mode::{EncodeOnly, RoundTrip};

const JSON: &[(Codec, Mode)] = &[(Json, RoundTrip)];
const BINCODE: &[(Codec, Mode)] = &[(Bincode, RoundTrip)];
const POSTCARD: &[(Codec, Mode)] = &[(Postcard, RoundTrip)];
const JSON_AND_BINCODE: &[(Codec, Mode)] = &[(Json, RoundTrip), (Bincode, RoundTrip)];

#[test]
fn dm_enums_match_main() {
    check::<crate::dm::DmBody>("DmBody", POSTCARD, &["Payload", "Ack"]);
    check::<crate::dm::DmAckOutcome>(
        "DmAckOutcome",
        POSTCARD,
        &[
            "Accepted",
            "RejectedByPolicy",
            "AckSemanticsUnavailable",
            "IdempotencyConflict",
        ],
    );
}

#[test]
fn owner_sync_enums_match_main() {
    check::<crate::owner_sync::SyncKind>(
        "SyncKind",
        BINCODE,
        &[
            "OwnerProfile",
            "MachineNames",
            "HomePointer",
            "IssuanceJournal",
        ],
    );
    check::<crate::owner_sync::SyncValue>(
        "SyncValue",
        BINCODE,
        &[
            "OwnerProfile",
            "MachineNames",
            "HomePointer",
            "IssuanceJournal",
        ],
    );
    check::<crate::owner_sync::SyncFrame>(
        "SyncFrame",
        BINCODE,
        &[
            "Hello",
            "Proof",
            "VersionVector",
            "VectorEnd",
            "Records",
            "Done",
            "Abort",
        ],
    );
}

#[test]
fn call_and_file_frames_match_main() {
    check::<crate::calls::CallFrame>("CallFrame", JSON, &["Invite", "Accept", "Reject", "Hangup"]);
    check::<crate::files::FileMessage>(
        "FileMessage",
        JSON,
        &[
            "Offer",
            "Chunk",
            "Complete",
            "Accept",
            "Reject",
            "ChunkAck",
            "ControlAck",
        ],
    );
}

#[test]
fn grant_delegation_and_move_enums_match_main() {
    check::<crate::share_grant::Grantee>("Grantee", BINCODE, &["User", "Agent"]);
    check::<crate::share_grant::ShareCap>(
        "ShareCap",
        BINCODE,
        &["Dm", "Exec", "Connect", "GroupInvite", "Call"],
    );
    check::<crate::delegation::AuthorityScope>("AuthorityScope", JSON, &["TaskExecute", "SendAs"]);
    check::<crate::delegation::DelegationVerb>(
        "DelegationVerb",
        JSON,
        &["Claim", "Complete", "SendPublicMessage"],
    );
    check::<crate::key_move::Placement>("Placement", BINCODE, &["Pinned", "Roaming"]);
    check::<crate::key_move::MoveRecord>(
        "MoveRecord",
        BINCODE,
        &[
            "PlacementMint",
            "MoveAuthorization",
            "ExportReceipt",
            "ImportReceipt",
            "ActivationBundle",
            "RetireReceipt",
            "AbortRecord",
        ],
    );
    check::<crate::revocation::RevokedSubject>(
        "RevokedSubject",
        BINCODE,
        &["Agent", "Machine", "AgentMachineBinding", "ShareGrant"],
    );
}

#[test]
fn crdt_and_kv_enums_match_main() {
    check::<crate::crdt::sealed::SealedTaskRecordBody>(
        "SealedTaskRecordBody",
        BINCODE,
        &["Gss", "TreeKem"],
    );
    check::<crate::crdt::CheckboxState>("CheckboxState", BINCODE, &["Empty", "Claimed", "Done"]);
    check::<crate::crdt::provenance::OpKind>("OpKind", BINCODE, &["Claim", "Complete"]);
    check::<crate::kv::encrypted::KvMutationKind>(
        "KvMutationKind",
        BINCODE,
        &["Delta", "FullState", "Control", "RetainedState"],
    );
    check::<crate::kv::AccessPolicy>(
        "AccessPolicy",
        BINCODE,
        &[
            "Signed",
            "Allowlisted",
            "Encrypted",
            "AppendOnly",
            "SelfKeyed",
            "GroupSigned",
            "TreeKemEncrypted",
        ],
    );
    check::<crate::kv::retained_paging::RetainedPageV1>(
        "RetainedPageV1",
        BINCODE,
        &["Manifest", "Page"],
    );
}

#[test]
fn group_enums_match_main() {
    check::<crate::groups::public_message::GroupPublicMessageKind>(
        "GroupPublicMessageKind",
        &[(Json, RoundTrip), (Bincode, EncodeOnly)],
        &["Chat", "Announcement", "Delegation"],
    );
    check::<crate::groups::JoinRequestStatus>(
        "JoinRequestStatus",
        JSON,
        &["Pending", "Approved", "Rejected", "Cancelled"],
    );
    check::<crate::groups::GroupRole>(
        "GroupRole",
        JSON_AND_BINCODE,
        &["Owner", "Admin", "Moderator", "Member", "Guest"],
    );
    check::<crate::groups::GroupMemberState>(
        "GroupMemberState",
        JSON_AND_BINCODE,
        &["Active", "Pending", "Removed", "Banned"],
    );
    check::<crate::groups::GroupDiscoverability>(
        "GroupDiscoverability",
        JSON_AND_BINCODE,
        &["Hidden", "ListedToContacts", "PublicDirectory"],
    );
    check::<crate::groups::GroupAdmission>(
        "GroupAdmission",
        JSON_AND_BINCODE,
        &["InviteOnly", "RequestAccess", "OpenJoin", "OwnerCertified"],
    );
    check::<crate::groups::GroupConfidentiality>(
        "GroupConfidentiality",
        JSON_AND_BINCODE,
        &["MlsEncrypted", "SignedPublic"],
    );
    check::<crate::groups::GroupReadAccess>(
        "GroupReadAccess",
        JSON_AND_BINCODE,
        &["MembersOnly", "Public"],
    );
    check::<crate::groups::GroupWriteAccess>(
        "GroupWriteAccess",
        JSON_AND_BINCODE,
        &["MembersOnly", "ModeratedPublic", "AdminOnly"],
    );
    check::<crate::groups::discovery::ShardKind>("ShardKind", JSON, &["Tag", "Name", "Id"]);
    check::<crate::groups::discovery::DirectoryMessage>(
        "DirectoryMessage",
        JSON,
        &["Card", "Digest", "Pull"],
    );
    check::<crate::groups::InviteOrigin>(
        "InviteOrigin",
        &[(Json, RoundTrip), (Postcard, RoundTrip)],
        &["Explicit", "Card"],
    );
    check::<crate::groups::MemberPlacement>("MemberPlacement", JSON, &["Pinned", "Roaming"]);
    check::<crate::mls::SecureGroupPlane>("SecureGroupPlane", JSON, &["Gss", "TreeKem"]);
    check::<crate::mls::CommitOperation>(
        "CommitOperation",
        JSON_AND_BINCODE,
        &["AddMember", "RemoveMember", "UpdateKeys"],
    );
}

#[test]
fn exec_enums_match_main() {
    check::<crate::exec::protocol::ExecFrame>(
        "ExecFrame",
        BINCODE,
        &[
            "Request",
            "LeaseRenew",
            "Started",
            "Stdout",
            "Stderr",
            "Warning",
            "Exit",
            "Cancel",
        ],
    );
    check::<crate::exec::protocol::StreamKind>(
        "StreamKind",
        JSON_AND_BINCODE,
        &["Stdout", "Stderr"],
    );
    check::<crate::exec::protocol::WarningKind>(
        "WarningKind",
        BINCODE,
        &[
            "StdoutCapHit",
            "StderrCapHit",
            "DurationApproachingCap",
            "StdoutApproachingCap",
            "StderrApproachingCap",
            "LeaseExpired",
            "PeerDisconnected",
            "Cancelled",
        ],
    );
    check::<crate::exec::protocol::DenialReason>(
        "DenialReason",
        BINCODE,
        &[
            "ExecDisabled",
            "UnverifiedSender",
            "TrustRejected",
            "AgentMachineNotInAcl",
            "ArgvNotAllowed",
            "StdinTooLarge",
            "TimeoutTooLarge",
            "CwdNotAllowed",
            "ConcurrencyLimitReached",
            "ShellMetacharInArgv",
            "SpawnFailed",
            "MalformedFrame",
        ],
    );
}

/// `StreamProtocol` has no serde form: its wire form is the one-byte
/// stream prefix. Pin each existing byte.
#[test]
fn stream_protocol_prefix_bytes_match_main() {
    use crate::streams::StreamProtocol;
    let pinned = [
        (StreamProtocol::ForwardV1, 0x01u8),
        (StreamProtocol::SocksV1, 0x02),
        (StreamProtocol::ForwardV2, 0x03),
        (StreamProtocol::WebRtcV1, 0x04),
        (StreamProtocol::SyncV1, 0x05),
        (StreamProtocol::EvidenceV1, 0x06),
    ];
    for (protocol, byte) in pinned {
        assert_eq!(protocol as u8, byte, "{protocol:?}");
    }
}

// ───────── Unknown variants: typed, counted, never a panic (#1604) ─────────

use crate::wire_compat::{
    decode_bincode, decode_json, reject_unknown, unknown_variant_count, WireDecodeError,
};

/// A bincode enum value whose variant index no build has assigned.
fn bincode_unknown_index() -> Vec<u8> {
    let mut bytes = 0xfeed_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 64]);
    bytes
}

fn assert_unknown_bincode<T: DeserializeOwned + std::fmt::Debug>(wire_type: &'static str) {
    let before = unknown_variant_count(wire_type);
    let err = decode_bincode::<T>(wire_type, &bincode_unknown_index()).unwrap_err();
    assert!(
        matches!(err, WireDecodeError::UnknownVariant { .. }),
        "{wire_type}: {err}"
    );
    assert_eq!(unknown_variant_count(wire_type), before + 1, "{wire_type}");
}

/// G1: every bincode/postcard message enum refuses an unknown variant index
/// with a typed, counted error. None has a catch-all that could accept it.
#[test]
fn bincode_enums_refuse_unknown_variant_index() {
    assert_unknown_bincode::<crate::owner_sync::SyncFrame>("u.SyncFrame");
    assert_unknown_bincode::<crate::owner_sync::SyncValue>("u.SyncValue");
    assert_unknown_bincode::<crate::owner_sync::SyncKind>("u.SyncKind");
    assert_unknown_bincode::<crate::share_grant::Grantee>("u.Grantee");
    assert_unknown_bincode::<crate::share_grant::ShareCap>("u.ShareCap");
    assert_unknown_bincode::<crate::key_move::Placement>("u.Placement");
    assert_unknown_bincode::<crate::key_move::MoveRecord>("u.MoveRecord");
    assert_unknown_bincode::<crate::revocation::RevokedSubject>("u.RevokedSubject");
    assert_unknown_bincode::<crate::crdt::sealed::SealedTaskRecordBody>("u.SealedTaskRecordBody");
    assert_unknown_bincode::<crate::crdt::CheckboxState>("u.CheckboxState");
    assert_unknown_bincode::<crate::crdt::provenance::OpKind>("u.OpKind");
    assert_unknown_bincode::<crate::kv::encrypted::KvMutationKind>("u.KvMutationKind");
    assert_unknown_bincode::<crate::kv::AccessPolicy>("u.AccessPolicy");
    assert_unknown_bincode::<crate::kv::retained_paging::RetainedPageV1>("u.RetainedPageV1");
    assert_unknown_bincode::<crate::exec::protocol::ExecFrame>("u.ExecFrame");
    assert_unknown_bincode::<crate::exec::protocol::StreamKind>("u.StreamKind");
    assert_unknown_bincode::<crate::exec::protocol::WarningKind>("u.WarningKind");
    assert_unknown_bincode::<crate::exec::protocol::DenialReason>("u.DenialReason");
    assert_unknown_bincode::<crate::mls::CommitOperation>("u.CommitOperation");
}

/// G3: a JSON unit enum decodes an unknown string as `Unknown`, which can
/// never be encoded, and `reject_unknown` refuses it with a counted error.
#[test]
fn json_unit_enums_decode_unknown_and_refuse_it() {
    fn check_unit<T>(wire_type: &'static str, unknown: T)
    where
        T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug,
    {
        let decoded: T = serde_json::from_str("\"brand_new_variant\"")
            .unwrap_or_else(|e| panic!("{wire_type}: unknown string must decode: {e}"));
        assert_eq!(decoded, unknown, "{wire_type}");
        assert!(
            serde_json::to_vec(&decoded).is_err(),
            "{wire_type}: never encoded"
        );
        assert!(
            bincode::serialize(&decoded).is_err(),
            "{wire_type}: never encoded"
        );
        let before = unknown_variant_count(wire_type);
        assert!(matches!(
            reject_unknown(wire_type, decoded),
            Err(WireDecodeError::UnknownVariant { .. })
        ));
        assert_eq!(unknown_variant_count(wire_type), before + 1, "{wire_type}");
    }
    use crate::groups::{
        GroupAdmission, GroupConfidentiality, GroupDiscoverability, GroupMemberState,
        GroupReadAccess, GroupRole, GroupWriteAccess, InviteOrigin, JoinRequestStatus,
        MemberPlacement,
    };
    check_unit("u.GroupRole", GroupRole::Unknown);
    check_unit("u.GroupMemberState", GroupMemberState::Unknown);
    check_unit("u.GroupDiscoverability", GroupDiscoverability::Unknown);
    check_unit("u.GroupAdmission", GroupAdmission::Unknown);
    check_unit("u.GroupConfidentiality", GroupConfidentiality::Unknown);
    check_unit("u.GroupReadAccess", GroupReadAccess::Unknown);
    check_unit("u.GroupWriteAccess", GroupWriteAccess::Unknown);
    check_unit("u.JoinRequestStatus", JoinRequestStatus::Unknown);
    check_unit("u.ShardKind", crate::groups::discovery::ShardKind::Unknown);
    check_unit("u.InviteOrigin", InviteOrigin::Unknown);
    check_unit("u.MemberPlacement", MemberPlacement::Unknown);
    check_unit("u.SecureGroupPlane", crate::mls::SecureGroupPlane::Unknown);
    check_unit(
        "u.AuthorityScope",
        crate::delegation::AuthorityScope::Unknown,
    );
    check_unit(
        "u.DelegationVerb",
        crate::delegation::DelegationVerb::Unknown,
    );
}

/// G3 over bincode: the unit enums that also travel in bincode records
/// (Home roster, policy) map an unknown index to `Unknown` without reading
/// a payload; `reject_unknown` then refuses the record.
#[test]
fn json_unit_enums_map_unknown_bincode_index_to_unknown() {
    let role: crate::groups::GroupRole =
        bincode::deserialize(&0xfeed_u32.to_le_bytes()).expect("unit Unknown");
    assert_eq!(role, crate::groups::GroupRole::Unknown);
    let policy = crate::groups::GroupPolicy::default();
    let mut bytes = bincode::serialize(&policy).expect("policy");
    bytes[..4].copy_from_slice(&0xfeed_u32.to_le_bytes());
    let decoded: crate::groups::GroupPolicy =
        bincode::deserialize(&bytes).expect("unit Unknown keeps the rest aligned");
    assert_eq!(
        decoded.discoverability,
        crate::groups::GroupDiscoverability::Unknown
    );
    assert_eq!(decoded.admission, policy.admission);
    assert!(reject_unknown("u.GroupPolicy", decoded).is_err());
}

/// Fail-closed consumers: an unknown role satisfies no privilege check.
#[test]
fn unknown_role_has_no_privilege() {
    use crate::groups::GroupRole;
    for minimum in [
        GroupRole::Guest,
        GroupRole::Member,
        GroupRole::Moderator,
        GroupRole::Admin,
        GroupRole::Owner,
    ] {
        assert!(!GroupRole::Unknown.at_least(minimum), "{minimum:?}");
        assert!(!GroupRole::Unknown.outranks(minimum), "{minimum:?}");
    }
    assert!(GroupRole::Guest.at_least(GroupRole::Guest));
}

/// G5: a delegation with an unknown scope or verb is refused before any
/// signature check, with a typed error.
#[test]
fn delegation_with_unknown_verb_is_refused_before_signature() {
    let json = serde_json::json!({
        "delegation_id": "@b16:1",
        "issued_at_ms": 1,
        "task_ref": "@b32:2",
        "from_agent": "@b32:3",
        "to_agent": "@b32:4",
        "authority_scope": "task_execute",
        "verbs": ["claim", "teleport"],
        "expiry_ms": 9,
        "parent_delegation": null,
        "depth": 1,
        "group_id": "g",
    });
    let delegation: crate::delegation::Delegation =
        serde_json::from_value(expand(&json)).expect("unknown verb decodes as Unknown");
    let err = crate::delegation::validate_policy(&delegation).unwrap_err();
    assert!(
        err.to_string().contains("unsupported variant"),
        "typed refusal, got {err}"
    );
}

/// G4: JSON tagged message enums refuse an unknown tag with a typed,
/// counted error.
#[test]
fn json_tagged_messages_refuse_unknown_tag() {
    let before = unknown_variant_count("DirectoryMessage");
    assert!(crate::groups::DirectoryMessage::decode(br#"{"m":"gossip_v9","x":1}"#).is_err());
    assert!(
        unknown_variant_count("DirectoryMessage") > before,
        "DirectoryMessage counted"
    );

    let before = unknown_variant_count("u.GroupPublicMessageKind");
    let err = decode_json::<crate::groups::public_message::GroupPublicMessageKind>(
        "u.GroupPublicMessageKind",
        "",
        br#"{"kind":"poll"}"#,
    )
    .unwrap_err();
    assert!(matches!(err, WireDecodeError::UnknownVariant { .. }));
    assert_eq!(
        unknown_variant_count("u.GroupPublicMessageKind"),
        before + 1
    );

    // CallFrame: only the `x0x_call_*` family is counted.
    let frame = crate::calls::CallFrame::Invite {
        call_id: "ab".repeat(16),
        media: crate::calls::MediaKinds {
            audio: true,
            video: false,
        },
    };
    let encoded = frame.encode().expect("encode");
    let text = String::from_utf8_lossy(&encoded).replace("x0x_call_invite", "x0x_call_teleport");
    let before = unknown_variant_count("CallFrame");
    assert!(crate::calls::CallFrame::decode(text.as_bytes()).is_none());
    assert!(
        unknown_variant_count("CallFrame") > before,
        "CallFrame counted"
    );

    // FileMessage: only the `file-*` family is counted.
    let before = unknown_variant_count("FileMessage");
    assert!(decode_json::<crate::files::FileMessage>(
        "FileMessage",
        "file-",
        br#"{"type":"file-teleport","transfer_id":"t"}"#
    )
    .is_err());
    let counted = unknown_variant_count("FileMessage");
    assert!(counted > before, "FileMessage counted");
    assert!(decode_json::<crate::files::FileMessage>(
        "FileMessage",
        "file-",
        br#"{"type":"something-else"}"#
    )
    .is_err());
    assert_eq!(
        unknown_variant_count("FileMessage"),
        counted,
        "another family is not counted"
    );
}

/// A nested unknown (a card's policy) refuses the whole directory message
/// before the card signature is checked.
#[test]
fn directory_card_with_unknown_policy_is_refused() {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_path("DirectoryMessage")).expect("fixture"),
    )
    .expect("json");
    let mut card_msg = fixture["cases"][0]["input"].clone();
    card_msg["card"]["policy_summary"]["read_access"] = Value::from("guests_with_cake");
    let bytes = serde_json::to_vec(&card_msg).expect("bytes");
    assert!(crate::groups::DirectoryMessage::decode(&bytes).is_err());
    let before = unknown_variant_count("u.DirectoryCard");
    assert!(matches!(
        decode_json::<crate::groups::DirectoryMessage>("u.DirectoryCard", "", &bytes),
        Err(WireDecodeError::UnknownVariant { .. })
    ));
    assert_eq!(unknown_variant_count("u.DirectoryCard"), before + 1);
}

/// G1: a DM envelope whose body or ACK outcome variant is unknown is a
/// counted, logged decode error, not a silent drop.
#[test]
fn dm_envelope_with_unknown_body_or_outcome_is_counted() {
    let envelope = crate::dm::DmEnvelope {
        protocol_version: 1,
        request_id: [1; 16],
        sender_agent_id: [2; 32],
        sender_machine_id: [3; 32],
        recipient_agent_id: [4; 32],
        created_at_unix_ms: 300,
        expires_at_unix_ms: 70_000,
        body: crate::dm::DmBody::Ack(crate::dm::DmAckBody {
            acks_request_id: [5; 16],
            outcome: crate::dm::DmAckOutcome::Accepted,
        }),
        signature: vec![6],
        origin_attestation: None,
    };
    let wire = envelope.to_wire_bytes().expect("encode");
    assert!(crate::dm::DmEnvelope::from_wire_bytes(&wire).is_ok());
    // Layout: version(1) + 16 + 96 + varint 300 (2) + varint 70000 (3).
    let body_tag = 1 + 16 + 96 + 2 + 3;
    assert_eq!(wire[body_tag], 1, "Ack body index");
    let outcome_tag = body_tag + 1 + 16;
    assert_eq!(wire[outcome_tag], 0, "Accepted outcome index");

    let mut unknown_body = wire.clone();
    unknown_body[body_tag] = 7;
    let before = unknown_variant_count("DmBody");
    let err = crate::dm::DmEnvelope::from_wire_bytes(&unknown_body).unwrap_err();
    assert!(err.to_string().contains("unsupported variant"), "{err}");
    assert!(unknown_variant_count("DmBody") > before, "DmBody counted");

    let mut unknown_outcome = wire;
    unknown_outcome[outcome_tag] = 9;
    let before = unknown_variant_count("DmAckOutcome");
    let err = crate::dm::DmEnvelope::from_wire_bytes(&unknown_outcome).unwrap_err();
    assert!(err.to_string().contains("unsupported variant"), "{err}");
    assert!(
        unknown_variant_count("DmAckOutcome") > before,
        "DmAckOutcome counted"
    );
}

/// G1: a share grant with an unknown grantee variant is refused with a
/// counted error.
#[test]
fn share_grant_with_unknown_grantee_is_refused() {
    let grant = crate::share_grant::ShareGrant {
        grant_id: [1; 32],
        owner: crate::identity::UserId([2; 32]),
        owner_public_key: Vec::new(),
        grantee: crate::share_grant::Grantee::User(crate::identity::UserId([3; 32])),
        agents: vec![crate::identity::AgentId([4; 32])],
        caps: [crate::share_grant::ShareCap::Dm].into_iter().collect(),
        not_before: 1,
        expiry: 2,
        signature: Vec::new(),
    };
    let mut payload = grant.to_dm_payload().expect("encode");
    assert!(crate::share_grant::ShareGrant::from_dm_payload(&payload).is_ok());
    let grantee_tag = crate::share_grant::SHARE_GRANT_DM_PREFIX.len() + 32 + 32 + 8;
    payload[grantee_tag..grantee_tag + 4].copy_from_slice(&0xfeed_u32.to_le_bytes());
    let before = unknown_variant_count("ShareGrant");
    let err = crate::share_grant::ShareGrant::from_dm_payload(&payload).unwrap_err();
    assert!(err.to_string().contains("unsupported variant"), "{err}");
    assert!(
        unknown_variant_count("ShareGrant") > before,
        "ShareGrant counted"
    );
}

/// G1 + reply path: an unknown `SyncFrame` is the typed
/// `SyncError::UnsupportedVariant`, not `MalformedFrame`.
#[tokio::test]
async fn sync_frame_with_unknown_variant_is_typed() {
    let body = bincode_unknown_index();
    let mut wire = (body.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(&body);
    let mut cursor = std::io::Cursor::new(wire);
    let err = crate::owner_sync::read_frame(&mut cursor)
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::owner_sync::SyncError::UnsupportedVariant(_)),
        "{err}"
    );
}

/// G5: an owner-signed Home record whose policy holds an unknown variant
/// is refused before the signature check, with the typed error.
#[test]
fn owner_record_with_unknown_policy_is_refused_before_signature() {
    let record = crate::owner_sync::VersionedRecord {
        kind: crate::owner_sync::SyncKind::HomePointer,
        key: "home".into(),
        value: crate::owner_sync::SyncValue::HomePointer {
            group_id: "g".into(),
            policy: crate::groups::GroupPolicy {
                read_access: crate::groups::GroupReadAccess::Unknown,
                ..crate::groups::GroupPolicy::default()
            },
            roster: Vec::new(),
            primary_agent: "p".into(),
            provisioned_at_ms: 1,
        },
        clock: crate::owner_sync::RecordClock {
            version: 1,
            signed_at_ms: 2,
            writer_machine: [3; 32],
        },
        owner_public_key: Vec::new(),
        signature: Vec::new(),
    };
    let err = record.verify().unwrap_err();
    assert!(
        matches!(err, crate::owner_sync::SyncError::UnsupportedVariant(_)),
        "{err}"
    );
}

fn revocation(subject: crate::revocation::RevokedSubject) -> crate::revocation::RevocationRecord {
    crate::revocation::RevocationRecord {
        subject,
        issuer_public_key: vec![7],
        revoked_at: 8,
        reason: None,
        signature: vec![9],
    }
}

/// G2: today's batches keep the legacy bytes exactly.
#[test]
fn revocation_batch_keeps_legacy_bytes_for_known_subjects() {
    let records = vec![
        revocation(crate::revocation::RevokedSubject::Agent(
            crate::identity::AgentId([1; 32]),
        )),
        revocation(crate::revocation::RevokedSubject::Machine(
            crate::identity::MachineId([2; 32]),
        )),
    ];
    let encoded = crate::revocation::encode_revocation_batch(&records).expect("encode");
    assert_eq!(encoded, bincode::serialize(&records).expect("legacy"));
    assert_eq!(
        crate::revocation::decode_revocation_batch(&encoded).expect("decode"),
        records
    );
}

/// G2: in a framed batch, one record with an unknown subject is skipped
/// and counted; every other record is kept.
#[test]
fn framed_revocation_batch_skips_only_the_unknown_record() {
    let first = revocation(crate::revocation::RevokedSubject::Agent(
        crate::identity::AgentId([1; 32]),
    ));
    let last = revocation(crate::revocation::RevokedSubject::Machine(
        crate::identity::MachineId([2; 32]),
    ));
    let mut unknown = bincode::serialize(&first).expect("record");
    unknown[..4].copy_from_slice(&0xfeed_u32.to_le_bytes());
    let elements = vec![
        bincode::serialize(&first).expect("first"),
        unknown,
        bincode::serialize(&last).expect("last"),
    ];
    let mut framed = crate::revocation::REVOCATION_BATCH_FRAMED_MAGIC.to_vec();
    framed.extend_from_slice(&bincode::serialize(&elements).expect("frame"));

    let before = unknown_variant_count("RevocationRecord");
    let decoded = crate::revocation::decode_revocation_batch(&framed).expect("decode");
    assert_eq!(decoded, vec![first.clone(), last]);
    assert!(
        unknown_variant_count("RevocationRecord") > before,
        "RevocationRecord counted"
    );

    // The same unknown record in a legacy batch fails the whole batch, as
    // it always did, but now with a counted, typed error.
    let mut legacy = bincode::serialize(&vec![first]).expect("legacy");
    legacy[8..12].copy_from_slice(&0xfeed_u32.to_le_bytes());
    let before = unknown_variant_count("RevocationBatch");
    assert!(matches!(
        crate::revocation::decode_revocation_batch(&legacy),
        Err(WireDecodeError::UnknownVariant { .. })
    ));
    assert!(
        unknown_variant_count("RevocationBatch") > before,
        "RevocationBatch counted"
    );

    // A malformed element refuses the whole framed batch (fail closed).
    let mut bad = crate::revocation::REVOCATION_BATCH_FRAMED_MAGIC.to_vec();
    bad.extend_from_slice(&bincode::serialize(&vec![vec![1u8, 2, 3]]).expect("frame"));
    assert!(matches!(
        crate::revocation::decode_revocation_batch(&bad),
        Err(WireDecodeError::Malformed { .. })
    ));
}

/// G7: the closed sets keep their typed rejection and have no catch-all.
#[test]
fn closed_sets_stay_closed() {
    for byte in [0x00u8, 0x07, 0xff] {
        assert_eq!(
            crate::streams::StreamProtocol::from_u8(byte),
            None,
            "{byte:#x}"
        );
    }
    for byte in [0x00u8, 0x05, 0xff] {
        assert_eq!(
            crate::owner_sync::SyncKind::from_u8(byte),
            None,
            "{byte:#x}"
        );
    }
}

/// G8: `KvMutationKind` is `repr(u8)` with explicit discriminants, but serde
/// encodes the variant index. Pin both, so a reorder cannot change bytes.
#[test]
fn kv_mutation_kind_index_and_discriminant_are_pinned() {
    use crate::kv::encrypted::KvMutationKind;
    for (kind, value) in [
        (KvMutationKind::Delta, 0u8),
        (KvMutationKind::FullState, 1),
        (KvMutationKind::Control, 2),
        (KvMutationKind::RetainedState, 3),
    ] {
        assert_eq!(kind as u8, value, "{kind:?} discriminant");
        assert_eq!(
            bincode::serialize(&kind).expect("encode"),
            u32::from(value).to_le_bytes().to_vec(),
            "{kind:?} variant index"
        );
    }
}
