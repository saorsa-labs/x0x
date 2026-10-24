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
