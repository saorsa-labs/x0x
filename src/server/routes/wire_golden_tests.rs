#![cfg(test)]

//! #1604: main-era wire fixtures for the `x0xd` named-group enums. These
//! types are `pub(in crate::server)`, so their checks live here. The
//! harness is `crate::wire_golden_tests`. `ControlBlobKind` is private to
//! `control_blob`; both of its variants are covered as the `kind` field of
//! the `ControlBlobMessage` fixtures.

use super::named_groups::{
    ControlBlobMessage, JoinRefusalReason, JoinResultMessage, NamedGroupMetadataEvent,
    WelcomeBlobMessage,
};
use crate::wire_golden_tests::{check, Codec, Mode};

const JSON: &[(Codec, Mode)] = &[(Codec::Json, Mode::RoundTrip)];

#[test]
fn named_group_wire_enums_match_main() {
    check::<JoinResultMessage>(
        "JoinResultMessage",
        JSON,
        &["FetchRequest", "Result", "Refused"],
    );
    check::<JoinRefusalReason>(
        "JoinRefusalReason",
        JSON,
        &[
            "InviteSecretUnknown",
            "InviteSecretConsumed",
            "CertificateEvidenceUnavailable",
            "InviteRoleExceedsCap",
            "InviteEventBeforeCreation",
            "InviteExpired",
            "InviteNotAddressed",
        ],
    );
    check::<WelcomeBlobMessage>(
        "WelcomeBlobMessage",
        JSON,
        &["FetchRequest", "Offer", "Chunk", "ChunkAck", "Complete"],
    );
    check::<NamedGroupMetadataEvent>(
        "NamedGroupMetadataEvent",
        JSON,
        &[
            "MemberAdded",
            "MemberRemoved",
            "GroupDeleted",
            "PolicyUpdated",
            "MemberRoleUpdated",
            "MemberBanned",
            "MemberUnbanned",
            "JoinRequestCreated",
            "JoinRequestApproved",
            "JoinRequestRejected",
            "JoinRequestCancelled",
            "GroupCardPublished",
            "GroupMetadataUpdated",
            "MemberJoined",
            "SecureShareDelivered",
        ],
    );
    check::<ControlBlobMessage>(
        "ControlBlobMessage",
        JSON,
        &["Reference", "Fetch", "Chunk", "Release"],
    );
}

fn fixture_input(type_name: &str, case: usize) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wire-enums-1604")
        .join(format!("{type_name}.json"));
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json");
    doc["cases"][case]["input"].clone()
}

fn assert_refused<T: serde::de::DeserializeOwned + serde::Serialize>(
    wire_type: &'static str,
    value: &serde_json::Value,
) {
    let bytes = serde_json::to_vec(value).expect("bytes");
    let before = crate::wire_compat::unknown_variant_count(wire_type);
    let result = crate::wire_compat::decode_json::<T>(wire_type, "", &bytes);
    assert!(
        matches!(
            result,
            Err(crate::wire_compat::WireDecodeError::UnknownVariant { .. })
        ),
        "{wire_type}: {value}"
    );
    assert_eq!(
        crate::wire_compat::unknown_variant_count(wire_type),
        before + 1,
        "{wire_type}"
    );
}

/// #1604 G3/G4/G5: an unknown top-level tag, or an unknown unit value
/// nested inside a known message, is a typed, counted refusal before any
/// signature check.
#[test]
fn named_group_messages_refuse_unknown_variants() {
    // Unknown top-level tags.
    assert_refused::<JoinResultMessage>(
        "s.JoinResultMessage",
        &serde_json::json!({"type": "teleport", "group_id": "g"}),
    );
    assert_refused::<NamedGroupMetadataEvent>(
        "s.NamedGroupMetadataEvent",
        &serde_json::json!({"event": "group_teleported", "group_id": "g"}),
    );
    assert_refused::<ControlBlobMessage>(
        "s.ControlBlobMessage",
        &serde_json::json!({"type": "control_blob_teleport"}),
    );
    assert_refused::<WelcomeBlobMessage>(
        "s.WelcomeBlobMessage",
        &serde_json::json!({"type": "teleport", "welcome_id": "w"}),
    );

    // Unknown unit values nested inside known messages.
    let mut role = fixture_input("NamedGroupMetadataEvent", 4);
    role["role"] = "overlord".into();
    assert_refused::<NamedGroupMetadataEvent>("s.NamedGroupMetadataEvent.role", &role);

    let mut policy = fixture_input("NamedGroupMetadataEvent", 3);
    policy["policy"]["confidentiality"] = "quantum_sealed".into();
    assert_refused::<NamedGroupMetadataEvent>("s.NamedGroupMetadataEvent.policy", &policy);

    let mut refused = fixture_input("JoinResultMessage", 2);
    refused["receipt"]["reason"] = "invite_eaten_by_dog".into();
    assert_refused::<JoinResultMessage>("s.JoinResultMessage.reason", &refused);

    let mut kind = fixture_input("ControlBlobMessage", 0);
    kind["reference"]["kind"] = "holiday_photos".into();
    assert_refused::<ControlBlobMessage>("s.ControlBlobMessage.kind", &kind);
}

/// `JoinRefusalReason::Unknown` decodes but is never encoded, so a signed
/// receipt holding it can never be re-signed or relayed.
#[test]
fn unknown_join_refusal_reason_is_never_encoded() {
    let reason: JoinRefusalReason =
        serde_json::from_str("\"invite_eaten_by_dog\"").expect("decodes as Unknown");
    assert_eq!(reason, JoinRefusalReason::Unknown);
    assert!(serde_json::to_vec(&reason).is_err());
}

/// #1604 G5 (Codex): a TreeKEM catch-up response carrying an event with an
/// unknown role is refused before any apply.
#[test]
fn treekem_catchup_response_with_unknown_is_refused() {
    let mut event = fixture_input("NamedGroupMetadataEvent", 4);
    event["role"] = "overlord".into();
    let response = serde_json::json!({
        "message_type": "treekem_catchup_response",
        "group_id": "g",
        "events": [event],
        "truncated": false,
    });
    let decoded: super::named_groups::TreeKemCatchupResponse =
        serde_json::from_value(response).expect("decodes with Unknown");
    assert!(crate::wire_compat::reject_unknown("s.TreeKemCatchupResponse", decoded).is_err());
}
