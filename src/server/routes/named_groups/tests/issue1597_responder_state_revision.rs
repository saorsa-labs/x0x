//! #1597 item 5b: `responder_state_revision` wire compatibility.

use super::super::*;

/// The catch-up answer shape before #1597 item 5b. An old peer decodes
/// answers into this shape.
#[derive(Debug, serde::Deserialize)]
struct OldShape {
    message_type: String,
    group_id: String,
    events: Vec<serde_json::Value>,
    truncated: bool,
    #[serde(default)]
    responder_state_hash: Option<String>,
}

fn response(revision: Option<u64>) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: "g".to_string(),
        events: Vec::new(),
        truncated: false,
        responder_state_hash: Some("ab".repeat(32)),
        responder_state_revision: revision,
    }
}

/// An old peer sends no revision key. The answer still decodes. The
/// revision is `None` and the head hash stays.
#[test]
fn an_old_answer_without_the_key_decodes_with_no_revision() {
    let old = serde_json::json!({
        "message_type": "treekem_catchup_response",
        "group_id": "g",
        "events": [],
        "truncated": false,
        "responder_state_hash": "cd".repeat(32),
    });
    let decoded: TreeKemCatchupResponse =
        serde_json::from_value(old).expect("an old answer decodes");
    assert_eq!(decoded.responder_state_revision, None);
    assert_eq!(decoded.responder_state_hash, Some("cd".repeat(32)));
    assert!(!decoded.truncated);
}

/// An answer with no revision has the old shape on the wire: the key
/// is absent.
#[test]
fn no_revision_serializes_without_the_key() {
    let encoded = serde_json::to_value(response(None)).expect("serializes");
    let object = encoded.as_object().expect("an object");
    assert!(!object.contains_key("responder_state_revision"));
    assert_eq!(
        object.get("responder_state_hash"),
        Some(&serde_json::Value::String("ab".repeat(32)))
    );
}

/// A revision is on the wire and decodes back to the same value.
#[test]
fn a_revision_round_trips_with_the_key_present() {
    for revision in [0, 41, u64::MAX] {
        let encoded = serde_json::to_vec(&response(Some(revision))).expect("serializes");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("json");
        assert_eq!(
            value.get("responder_state_revision"),
            Some(&serde_json::Value::from(revision))
        );
        let decoded: TreeKemCatchupResponse = serde_json::from_slice(&encoded).expect("decodes");
        assert_eq!(decoded.responder_state_revision, Some(revision));
        assert_eq!(decoded.responder_state_hash, Some("ab".repeat(32)));
    }
}

/// An old peer decodes a new answer and ignores the extra key. The
/// head hash still reaches it.
#[test]
fn an_old_peer_ignores_the_new_key() {
    let encoded = serde_json::to_vec(&response(Some(7))).expect("serializes");
    let old: OldShape = serde_json::from_slice(&encoded).expect("an old peer decodes it");
    assert_eq!(old.message_type, "treekem_catchup_response");
    assert_eq!(old.group_id, "g");
    assert!(old.events.is_empty());
    assert!(!old.truncated);
    assert_eq!(old.responder_state_hash, Some("ab".repeat(32)));
}
