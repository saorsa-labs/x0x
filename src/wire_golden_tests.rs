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
