//! ADR-0023 Phase-2 wiring tests: the §4 taxonomy deny-set (payload-shape
//! classification at the DM wiring point) plus the restart-survival proof.
//!
//! The classification tests run everywhere. The restart-survival test is
//! `#[ignore]` — it boots real x0xd daemons via the shared cluster harness.
//! Run with: cargo nextest run --test history_wiring -- --ignored
//! Before running: cargo build --release --bin x0xd

use x0x::history::classify::{classify_dm_payload, DmPayloadClass};
use x0x::history::store::Store;
use x0x::history::{Direction, Scope};

#[path = "harness/src/cluster.rs"]
mod cluster;

/// The Ephemeral DM payload families from the §4 table, constructed with
/// their real wire shapes. None of these may ever produce a history row.
fn ephemeral_family_payloads() -> Vec<(&'static str, Vec<u8>)> {
    let chunk = serde_json::to_vec(&x0x::files::FileMessage::Chunk(x0x::files::FileChunk {
        transfer_id: "t1".into(),
        sequence: 0,
        data: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            vec![0u8; 32 * 1024],
        ),
    }))
    .expect("serialize file chunk");
    let chunk_ack = serde_json::to_vec(&x0x::files::FileMessage::ChunkAck {
        transfer_id: "t1".into(),
        sequence: 0,
    })
    .expect("serialize chunk ack");

    let mut group_public = b"X0X-GROUP-PUBLIC-V1\n".to_vec();
    group_public.extend_from_slice(br#"{"group_id":"g"}"#);
    let mut kv_delta = b"X0X-KV-DELTA-V1\n".to_vec();
    kv_delta.extend_from_slice(b"delta-bytes");
    let mut ltc_card = b"X0X-LTC-CARD-V1\n".to_vec();
    ltc_card.extend_from_slice(b"frame");
    let mut exec = x0x::exec::protocol::EXEC_DM_PREFIX.to_vec();
    exec.extend_from_slice(b"exec-frame");

    vec![
        ("file-chunk", chunk),
        ("file-chunk-ack", chunk_ack),
        (
            "welcome-blob-chunk",
            br#"{"type":"chunk","group_id":"g","welcome_id":"w","index":0,"data_b64":"AAAA"}"#
                .to_vec(),
        ),
        (
            "welcome-blob-offer",
            br#"{"type":"offer","group_id":"g","welcome_id":"w","byte_len":1,"chunk_size":1,"total_chunks":1,"blake3_hex":"00"}"#
                .to_vec(),
        ),
        (
            "join-result-fetch",
            br#"{"type":"fetch_request","group_id":"g","member_agent_id":"m"}"#.to_vec(),
        ),
        (
            "treekem-catchup-request",
            br#"{"message_type":"treekem_catchup_request","group_id":"g","requester_agent_id":"r","from_revision":0,"from_treekem_epoch":0,"current_state_hash":"h","missing_prev_state_hash":null,"limit":8}"#
                .to_vec(),
        ),
        (
            "treekem-catchup-response",
            br#"{"message_type":"treekem_catchup_response","group_id":"g","events":[],"truncated":false}"#
                .to_vec(),
        ),
        (
            "named-group-metadata-event",
            br#"{"event":"member_added","group_id":"g","revision":1,"actor":"a","agent_id":"b"}"#
                .to_vec(),
        ),
        ("group-public-dm-frame", group_public),
        ("kv-delta-dm-frame", kv_delta),
        ("ltc-card-frame", ltc_card),
        ("exec-frame", exec),
    ]
}

/// §4 deny-test: every Ephemeral payload family classifies Ephemeral at the
/// DM wiring point — by payload shape, not topic — so the store never sees
/// them. This is the test that fails if a new plumbing family is added to
/// the DM plane without a taxonomy decision.
#[test]
fn ephemeral_dm_families_are_never_recorded() {
    for (name, payload) in ephemeral_family_payloads() {
        assert_eq!(
            classify_dm_payload(&payload),
            DmPayloadClass::Ephemeral,
            "family `{name}` must classify Ephemeral"
        );
    }
}

/// Positive side of the taxonomy: user communication and durable
/// file-transfer records classify Durable.
#[test]
fn durable_dm_families_are_recorded() {
    let offer = serde_json::to_vec(&x0x::files::FileMessage::Offer(x0x::files::FileOffer {
        transfer_id: "t1".into(),
        filename: "a.txt".into(),
        size: 1,
        sha256: "00".into(),
        chunk_size: 1,
        total_chunks: 1,
    }))
    .expect("serialize offer");
    for (name, payload, want_ct) in [
        ("chat-text", b"hello over x0x".to_vec(), "text/plain"),
        (
            "a2a-jsonrpc",
            br#"{"jsonrpc":"2.0","method":"tasks/send","id":1}"#.to_vec(),
            "application/json",
        ),
        ("file-offer", offer, "application/json"),
    ] {
        assert_eq!(
            classify_dm_payload(&payload),
            DmPayloadClass::Durable(want_ct),
            "family `{name}` must classify Durable({want_ct})"
        );
    }
}

/// The wire-prefix literals in `history::classify` mirror
/// `pub(in crate::server)` constants that cannot be imported here. Pin the
/// exec prefix (importable) against the real constant so at least one
/// mirror is structurally verified, and pin the others as byte literals so
/// any drift shows up as a deliberate diff in this file.
#[test]
fn classify_prefix_literals_are_pinned() {
    assert_eq!(
        x0x::history::classify::GROUP_PUBLIC_MESSAGE_DM_PREFIX,
        b"X0X-GROUP-PUBLIC-V1\n"
    );
    assert_eq!(
        x0x::history::classify::KV_STORE_DELTA_DM_PREFIX,
        b"X0X-KV-DELTA-V1\n"
    );
    assert_eq!(
        x0x::history::classify::LTC_CARD_FRAME_PREFIX,
        b"X0X-LTC-CARD-V1\n"
    );
    assert_eq!(x0x::exec::protocol::EXEC_DM_PREFIX, b"x0x-exec-v1\0");
}

/// ADR-0023 restart survival (the design's headline integration test):
/// a DM sent between two real daemons lands in BOTH daemons' history.db —
/// outbound row on the sender, inbound row with the verbatim signed
/// artifact on the receiver — and both survive a hard process kill.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "boots real x0xd daemons"]
async fn dm_history_survives_daemon_kill() {
    let mut mesh = cluster::pair().await;
    let alice_id = mesh.alice.agent_id().await;
    let bob_id = mesh.bob.agent_id().await;

    let message = b"history restart-survival probe";
    let payload_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, message);
    let resp = mesh
        .alice
        .post(
            "/direct/send",
            serde_json::json!({ "agent_id": bob_id, "payload": payload_b64 }),
        )
        .await;
    assert!(
        resp.status().is_success(),
        "direct send failed: {}",
        resp.status()
    );

    // The inbound write is asynchronous (bounded writer thread) — poll the
    // sender-side DB for the outbound row and the receiver side for the
    // inbound row before killing anything.
    let alice_db = mesh.alice.data_dir().join("history.db");
    let bob_db = mesh.bob.data_dir().join("history.db");

    // Hard-kill both daemons; Child::kill is SIGKILL on unix. The store
    // must be readable and complete after the kill (WAL recovery).
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    mesh.alice.stop();
    mesh.bob.stop();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let alice_store = Store::open(&alice_db).expect("open alice history.db after kill");
    let outbound = alice_store
        .query(&x0x::history::HistoryQuery {
            scope: Some(Scope::Dm(bob_id.clone())),
            ..Default::default()
        })
        .expect("query alice history");
    assert!(
        outbound
            .iter()
            .any(|r| r.record.payload == message && r.record.direction == Direction::Outbound),
        "sender must hold an outbound row for the DM (rows: {})",
        outbound.len()
    );
    drop(alice_store);

    let bob_store = Store::open(&bob_db).expect("open bob history.db after kill");
    let inbound = bob_store
        .query(&x0x::history::HistoryQuery {
            scope: Some(Scope::Dm(alice_id.clone())),
            ..Default::default()
        })
        .expect("query bob history");
    let row = inbound
        .iter()
        .find(|r| r.record.payload == message && r.record.direction == Direction::Inbound)
        .expect("receiver must hold the inbound DM row");
    let artifact = row
        .record
        .signed_artifact
        .as_deref()
        .expect("inbound row must carry the verbatim signed artifact");
    let envelope = x0x::dm::DmEnvelope::from_wire_bytes(artifact)
        .expect("signed artifact must decode as a DmEnvelope");
    assert_eq!(hex::encode(envelope.sender_agent_id), alice_id);
    assert!(
        !envelope.signature.is_empty(),
        "artifact must retain the ML-DSA signature"
    );
    assert_eq!(
        row.record.author_pubkey.as_deref().map(<[u8]>::is_empty),
        Some(false),
        "inbound row must retain the author's public key"
    );
}
