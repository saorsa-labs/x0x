//! DM payload classification for ADR-0023 §4.
//!
//! The DM plane carries user communication *and* protocol plumbing
//! (file/welcome chunks, catch-up frames, KV deltas, exec frames). History
//! records communication, not plumbing, so every DM payload is classified
//! once — by payload shape, not topic — at the wiring points in
//! `dm_inbox.rs` (inbound) and `Agent::send_direct_with_config` (outbound).
//!
//! The typed-prefix byte literals below mirror `pub(in crate::server)`
//! constants that cannot be imported from here; `tests/history_wiring.rs`
//! pins them so drift fails loudly.

use serde::Deserialize;

/// Group public-message DM direct-push frame
/// (`server::routes::named_groups::GROUP_PUBLIC_MESSAGE_DM_PREFIX`).
/// Recorded at the group ingest convergence point, not the DM layer.
pub const GROUP_PUBLIC_MESSAGE_DM_PREFIX: &[u8] = b"X0X-GROUP-PUBLIC-V1\n";
/// Group-card LTC frame (`named_groups::LTC_CARD_FRAME_PREFIX`).
pub const LTC_CARD_FRAME_PREFIX: &[u8] = b"X0X-LTC-CARD-V1\n";
/// KV-store delta DM fallback (`server::routes::stores::KV_STORE_DELTA_DM_PREFIX`).
/// The KV store is its own durable surface.
pub const KV_STORE_DELTA_DM_PREFIX: &[u8] = b"X0X-KV-DELTA-V1\n";
/// Voice signaling frames (`voice` feature, saorsa-webrtc V1.1). Call
/// setup/teardown control traffic — Ephemeral like all signaling; the
/// conversation itself is media, not DM history. The const lives here
/// (not in the feature-gated voice module) so classification and the
/// deny-test hold even when the `voice` feature is off.
pub const VOICE_SIGNALING_DM_PREFIX: &[u8] = b"x0x-voice-sig-v1\n";

/// JSON `"type"` tag values that are protocol plumbing (never recorded):
/// file-transfer chunk traffic plus the `WelcomeBlobMessage` /
/// `JoinResultMessage` snake_case variant tags.
const EPHEMERAL_TYPE_TAGS: &[&str] = &[
    "file-chunk",
    "file-chunk-ack",
    "fetch_request",
    "offer",
    "chunk",
    "chunk_ack",
    "complete",
    "result",
];

/// JSON `"type"` tag values recorded as the durable record of a transfer.
const DURABLE_FILE_TAGS: &[&str] = &["file-offer", "file-accept", "file-reject", "file-complete"];

/// `"message_type"` values for TreeKEM catch-up anti-entropy frames.
const EPHEMERAL_MESSAGE_TYPES: &[&str] = &["treekem_catchup_request", "treekem_catchup_response"];

/// Classification outcome for one DM payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmPayloadClass {
    /// Record with the given MIME content type.
    Durable(&'static str),
    /// Protocol plumbing — never recorded.
    Ephemeral,
}

#[derive(Deserialize)]
struct Probe {
    #[serde(rename = "type")]
    type_tag: Option<String>,
    message_type: Option<String>,
    event: Option<String>,
    jsonrpc: Option<String>,
}

/// Classify a decrypted DM payload per the ADR-0023 §4 taxonomy.
///
/// Unrecognized payloads default to Durable — an unknown shape is user
/// communication until a protocol family claims it explicitly.
#[must_use]
pub fn classify_dm_payload(payload: &[u8]) -> DmPayloadClass {
    // Typed byte-prefix frames: plumbing families with their own durable
    // surfaces (group ingest, KV store, exec audit log, card import).
    if payload.starts_with(GROUP_PUBLIC_MESSAGE_DM_PREFIX)
        || payload.starts_with(LTC_CARD_FRAME_PREFIX)
        || payload.starts_with(KV_STORE_DELTA_DM_PREFIX)
        || payload.starts_with(VOICE_SIGNALING_DM_PREFIX)
        || payload.starts_with(crate::exec::protocol::EXEC_DM_PREFIX)
    {
        return DmPayloadClass::Ephemeral;
    }

    if payload.first() == Some(&b'{') {
        if let Ok(probe) = serde_json::from_slice::<Probe>(payload) {
            if let Some(tag) = probe.type_tag.as_deref() {
                if EPHEMERAL_TYPE_TAGS.contains(&tag) {
                    return DmPayloadClass::Ephemeral;
                }
                if DURABLE_FILE_TAGS.contains(&tag) {
                    return DmPayloadClass::Durable("application/json");
                }
            }
            if let Some(mt) = probe.message_type.as_deref() {
                if EPHEMERAL_MESSAGE_TYPES.contains(&mt) {
                    return DmPayloadClass::Ephemeral;
                }
            }
            // Named-group metadata events are tagged `"event": "<kind>"`
            // (serde tag on `NamedGroupMetadataEvent`); their durable effect
            // lives in the group state chain.
            if probe.event.is_some() {
                return DmPayloadClass::Ephemeral;
            }
            // a2a JSON-RPC task traffic: the ADR's "agents need memory" case.
            if probe.jsonrpc.is_some() {
                return DmPayloadClass::Durable("application/json");
            }
            return DmPayloadClass::Durable("application/json");
        }
    }

    if std::str::from_utf8(payload).is_ok() {
        DmPayloadClass::Durable("text/plain")
    } else {
        DmPayloadClass::Durable("application/octet-stream")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_frames_are_ephemeral() {
        for prefix in [
            &b"X0X-GROUP-PUBLIC-V1\n"[..],
            &b"X0X-LTC-CARD-V1\n"[..],
            &b"X0X-KV-DELTA-V1\n"[..],
            crate::exec::protocol::EXEC_DM_PREFIX,
        ] {
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(b"{\"anything\":1}");
            assert_eq!(classify_dm_payload(&payload), DmPayloadClass::Ephemeral);
        }
    }

    #[test]
    fn chunk_traffic_is_ephemeral_and_file_records_are_durable() {
        for tag in EPHEMERAL_TYPE_TAGS {
            let payload = format!("{{\"type\":\"{tag}\",\"x\":1}}");
            assert_eq!(
                classify_dm_payload(payload.as_bytes()),
                DmPayloadClass::Ephemeral,
                "tag {tag} must be ephemeral"
            );
        }
        for tag in DURABLE_FILE_TAGS {
            let payload = format!("{{\"type\":\"{tag}\",\"x\":1}}");
            assert_eq!(
                classify_dm_payload(payload.as_bytes()),
                DmPayloadClass::Durable("application/json"),
                "tag {tag} must be durable"
            );
        }
    }

    #[test]
    fn catchup_and_metadata_events_are_ephemeral() {
        assert_eq!(
            classify_dm_payload(br#"{"message_type":"treekem_catchup_request","group_id":"g"}"#),
            DmPayloadClass::Ephemeral
        );
        assert_eq!(
            classify_dm_payload(br#"{"message_type":"treekem_catchup_response","group_id":"g"}"#),
            DmPayloadClass::Ephemeral
        );
        assert_eq!(
            classify_dm_payload(br#"{"event":"member_added","group_id":"g","revision":1}"#),
            DmPayloadClass::Ephemeral
        );
    }

    #[test]
    fn user_communication_is_durable() {
        assert_eq!(
            classify_dm_payload(br#"{"jsonrpc":"2.0","method":"tasks/send","id":1}"#),
            DmPayloadClass::Durable("application/json")
        );
        assert_eq!(
            classify_dm_payload(b"hello over x0x"),
            DmPayloadClass::Durable("text/plain")
        );
        assert_eq!(
            classify_dm_payload(&[0u8, 159, 146, 150]),
            DmPayloadClass::Durable("application/octet-stream")
        );
        assert_eq!(
            classify_dm_payload(br#"{"note":"plain json chat"}"#),
            DmPayloadClass::Durable("application/json")
        );
    }
}
