#![cfg(test)]
//! Issue #1094 slice D1: a grantee reads a store through a `ShareCap::Data`
//! grant. The granted agent's handler runs for real (grant evaluation with
//! an authenticated machine binding, a real store); the grantee side runs
//! its real route against the reply handler.

use super::*;
use crate::identity::AgentKeypair;
use crate::identity::{MachineId, UserKeypair};
use crate::share_grant::{DataAccess, Grantee, ShareCap, ShareGrant, ShareGrantStore};

const GROUP: &str = "1094d1aa1094d1aa1094d1aa1094d1aa";
const STORE: &str = "scratch";

fn unix_secs() -> u64 {
    now_ms() / 1000
}

/// Loopback-only network: the store needs an in-process gossip runtime.
fn loopback() -> crate::network::NetworkConfig {
    crate::network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..crate::network::NetworkConfig::default()
    }
}

async fn state_with_store() -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    let data_dir = dir.path().to_path_buf();
    let agent = Arc::new(
        crate::Agent::builder()
            .with_identity_dir(&data_dir)
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(AgentKeypair::generate().expect("key"))
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .with_network_config(loopback())
            .build()
            .await
            .expect("agent"),
    );
    let state =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(&data_dir, agent)
            .await
            .expect("state");
    let (_, topic) = crate::kv::encrypted::group_store_identity(GROUP, STORE);
    let handle = state
        .agent
        .create_kv_store(STORE, &topic)
        .await
        .expect("store");
    handle
        .put_with_delta("note".to_string(), b"hello".to_vec(), "text/plain".into())
        .await
        .expect("put");
    state.kv_stores.write().await.insert(topic, handle);
    (state, dir)
}

/// The owner of `state`'s install signs a grant to `grantee` with `caps`.
async fn install_grant(state: &AppState, grantee: AgentId, caps: Vec<ShareCap>) {
    let owner = UserKeypair::generate().expect("owner");
    let local = state.agent.agent_id();
    let grants = Arc::new(ShareGrantStore::in_memory(local, Some(owner.user_id())));
    if !caps.is_empty() {
        let grant = ShareGrant::sign(
            &owner,
            rand::random(),
            Grantee::Agent(grantee),
            vec![local],
            caps,
            unix_secs().saturating_sub(30),
            unix_secs().saturating_add(3_600),
        )
        .expect("sign");
        grants.accept(grant, unix_secs()).await.expect("accept");
    }
    state.agent.install_share_grant_store(grants);
}

fn data_cap(access: DataAccess) -> ShareCap {
    ShareCap::Data {
        group: GROUP.to_string(),
        store: STORE.to_string(),
        access,
    }
}

async fn bound_sender(state: &AppState) -> (AgentId, MachineId) {
    let agent = AgentKeypair::generate().expect("grantee").agent_id();
    let machine = MachineId(rand::random());
    state
        .agent
        .record_authenticated_binding_for_testing(agent, machine, unix_secs())
        .await;
    (agent, machine)
}

fn typed(sender: AgentId, machine: MachineId, payload: Vec<u8>) -> DmTypedPayload {
    DmTypedPayload {
        sender,
        machine_id: machine,
        payload,
        verified: true,
        trust_decision: None,
        received_at_unix_ms: now_ms(),
        request_id: [0u8; 16],
        completion: None,
    }
}

fn request(op: DataReadOp) -> Vec<u8> {
    DataReadRequest {
        request_id: hex::encode(rand::random::<[u8; 16]>()),
        group: GROUP.to_string(),
        store: STORE.to_string(),
        op,
    }
    .encode()
    .expect("encode")
}

async fn serve(
    state: &AppState,
    sender: AgentId,
    machine: MachineId,
    op: DataReadOp,
) -> DataReadReply {
    let (to, bytes) = serve_data_read(state, &typed(sender, machine, request(op)))
        .await
        .expect("a reply");
    assert_eq!(to, sender, "the reply goes to the sender");
    DataReadReply::decode(&bytes).expect("reply")
}

/// #1094: "a grantee without the cap gets 403". A sender with no grant,
/// and one whose grant has other caps only, is refused; nothing is read.
#[tokio::test]
async fn issue1094_grantee_without_the_data_cap_is_forbidden() {
    let (state, _dir) = state_with_store().await;
    let (agent, machine) = bound_sender(&state).await;
    install_grant(&state, agent, vec![ShareCap::Dm]).await;
    for op in [
        DataReadOp::Keys,
        DataReadOp::Get {
            key: "note".to_string(),
        },
    ] {
        let reply = serve(&state, agent, machine, op).await;
        assert_eq!(reply.status, DataReadStatus::Forbidden);
        assert!(reply.keys.is_none() && reply.entry.is_none());
    }
    let (stranger, stranger_machine) = bound_sender(&state).await;
    let reply = serve(&state, stranger, stranger_machine, DataReadOp::Keys).await;
    assert_eq!(reply.status, DataReadStatus::Forbidden);
}

/// A grant for ANOTHER store of the group, or the same store of another
/// group, does not cover this one.
#[tokio::test]
async fn issue1094_a_data_cap_covers_only_its_store() {
    let (state, _dir) = state_with_store().await;
    let (agent, machine) = bound_sender(&state).await;
    install_grant(
        &state,
        agent,
        vec![
            ShareCap::Data {
                group: GROUP.to_string(),
                store: "notes".to_string(),
                access: DataAccess::Rw,
            },
            ShareCap::Data {
                group: "ff".repeat(16),
                store: STORE.to_string(),
                access: DataAccess::Rw,
            },
        ],
    )
    .await;
    let reply = serve(&state, agent, machine, DataReadOp::Keys).await;
    assert_eq!(reply.status, DataReadStatus::Forbidden);
}

/// `ro` and `rw` grantees read the keys and a value; a missing key is
/// `not_found`. The sender's machine must be its authenticated binding: the
/// same agent on another machine is refused.
#[tokio::test]
async fn issue1094_data_grantee_reads_keys_and_values() {
    for access in [DataAccess::Ro, DataAccess::Rw] {
        let (state, _dir) = state_with_store().await;
        let (agent, machine) = bound_sender(&state).await;
        install_grant(&state, agent, vec![data_cap(access)]).await;

        let keys = serve(&state, agent, machine, DataReadOp::Keys).await;
        assert_eq!(keys.status, DataReadStatus::Ok, "{access:?}");
        let keys = keys.keys.expect("keys");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, "note");
        assert_eq!(keys[0].size, 5);

        let value = serve(
            &state,
            agent,
            machine,
            DataReadOp::Get {
                key: "note".to_string(),
            },
        )
        .await;
        assert_eq!(value.status, DataReadStatus::Ok);
        let entry = value.entry.expect("entry");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(entry.value_b64)
                .expect("b64"),
            b"hello"
        );

        let missing = serve(
            &state,
            agent,
            machine,
            DataReadOp::Get {
                key: "absent".to_string(),
            },
        )
        .await;
        assert_eq!(missing.status, DataReadStatus::NotFound);

        let other_machine = MachineId(rand::random());
        let spoofed = serve(&state, agent, other_machine, DataReadOp::Keys).await;
        assert_eq!(
            spoofed.status,
            DataReadStatus::Forbidden,
            "an unauthenticated machine never pairs with the grant"
        );
    }
}

/// A store this daemon does not hold open is `unavailable`; an unverified
/// or malformed request gets no reply.
#[tokio::test]
async fn issue1094_unheld_store_and_bad_requests() {
    let (state, _dir) = state_with_store().await;
    let (agent, machine) = bound_sender(&state).await;
    install_grant(
        &state,
        agent,
        vec![ShareCap::Data {
            group: "ee".repeat(16),
            store: STORE.to_string(),
            access: DataAccess::Ro,
        }],
    )
    .await;
    let payload = DataReadRequest {
        request_id: "aa".repeat(16),
        group: "ee".repeat(16),
        store: STORE.to_string(),
        op: DataReadOp::Keys,
    }
    .encode()
    .expect("encode");
    let (_, bytes) = serve_data_read(&state, &typed(agent, machine, payload.clone()))
        .await
        .expect("reply");
    assert_eq!(
        DataReadReply::decode(&bytes).expect("reply").status,
        DataReadStatus::Unavailable
    );
    let mut unverified = typed(agent, machine, payload);
    unverified.verified = false;
    assert!(serve_data_read(&state, &unverified).await.is_none());
    assert!(serve_data_read(
        &state,
        &typed(agent, machine, b"x0x-data-read-v1\0{".to_vec())
    )
    .await
    .is_none());
}

/// The serve limit: a sender gets at most `DATA_READ_SERVE_PER_WINDOW`
/// replies per window.
#[tokio::test]
async fn issue1094_serve_limit_per_sender() {
    let (state, _dir) = state_with_store().await;
    let (agent, machine) = bound_sender(&state).await;
    install_grant(&state, agent, vec![data_cap(DataAccess::Ro)]).await;
    for _ in 0..DATA_READ_SERVE_PER_WINDOW {
        assert!(
            serve_data_read(&state, &typed(agent, machine, request(DataReadOp::Keys)))
                .await
                .is_some()
        );
    }
    assert!(
        serve_data_read(&state, &typed(agent, machine, request(DataReadOp::Keys)))
            .await
            .is_none(),
        "over the limit"
    );
}

/// Grantee side: the route sends one request to the granted agent and
/// answers with its reply. A reply from any other agent is ignored. A
/// `forbidden` reply is a 403.
#[tokio::test]
async fn issue1094_grantee_route_waits_for_the_granted_agents_reply() {
    let (grantee, _dir) = crate::server::routes::named_groups::tests::secure_endpoint_test_state()
        .await
        .expect("state");
    let granted = AgentKeypair::generate().expect("granted").agent_id();
    let mut caps = crate::dm::DmCapabilities::v2_durable_gossip_ready(
        grantee.agent_kem_keypair.public_bytes.clone(),
    );
    caps.application_registry = crate::dm::CapabilityRegistry {
        version: 1,
        bits: crate::dm::CapabilityRegistry::DATA_READ_V1,
    };
    assert!(grantee.agent.capability_store().insert(
        granted,
        MachineId(rand::random()),
        caps,
        crate::dm_capability::now_unix_ms(),
    ));

    for (status, code) in [
        (DataReadStatus::Forbidden, StatusCode::FORBIDDEN),
        (DataReadStatus::Ok, StatusCode::OK),
    ] {
        let route_state = Arc::clone(&grantee);
        let call = tokio::spawn(async move {
            read_granted_store(
                &route_state,
                granted,
                GROUP.to_string(),
                STORE.to_string(),
                DataReadOp::Keys,
            )
            .await
        });
        let sent = loop {
            if let Some((to, payload)) = test_seam::sent_by(&grantee)
                .into_iter()
                .filter(|(to, _)| *to == granted)
                .filter_map(|(to, p)| DataReadRequest::decode(&p).map(|r| (to, r)))
                .find(|(_, r)| {
                    grantee
                        .data_read_waiters
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .contains_key(&r.request_id)
                })
            {
                break (to, payload);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(sent.0, granted);
        let mut reply = DataReadReply::status(&sent.1.request_id, status);
        if status == DataReadStatus::Ok {
            reply.keys = Some(Vec::new());
        }
        // A reply from another agent does not complete the call.
        let imposter = AgentKeypair::generate().expect("imposter").agent_id();
        handle_data_read_typed(
            &grantee,
            typed(
                imposter,
                MachineId([0; 32]),
                DataReadReply::status(&sent.1.request_id, DataReadStatus::Ok)
                    .encode()
                    .expect("encode"),
            ),
        )
        .await;
        assert!(!call.is_finished());
        handle_data_read_typed(
            &grantee,
            typed(granted, MachineId([0; 32]), reply.encode().expect("encode")),
        )
        .await;
        let (got, _) = call.await.expect("route");
        assert_eq!(got, code);
    }
    assert!(grantee
        .data_read_waiters
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty());
}

/// Mixed versions: a granted agent without `data_read_v1` is never sent a
/// request; the route answers 424.
#[tokio::test]
async fn issue1094_grantee_route_needs_the_peer_capability() {
    let (grantee, _dir) = crate::server::routes::named_groups::tests::secure_endpoint_test_state()
        .await
        .expect("state");
    let old_peer = AgentKeypair::generate().expect("peer").agent_id();
    let (code, _) = read_granted_store(
        &grantee,
        old_peer,
        GROUP.to_string(),
        STORE.to_string(),
        DataReadOp::Keys,
    )
    .await;
    assert_eq!(code, StatusCode::FAILED_DEPENDENCY);
    assert!(test_seam::sent_by(&grantee)
        .iter()
        .all(|(to, _)| *to != old_peer));
}

/// Review of #1935: a value at the 32 KiB read limit is served; one byte
/// over it, and a 40 KB value (a store takes up to 64 KiB inline), is
/// `too_large`, which the grantee route answers with 413.
#[tokio::test]
async fn issue1094_value_size_limit_is_typed() {
    let (state, _dir) = state_with_store().await;
    let (_, topic) = crate::kv::encrypted::group_store_identity(GROUP, STORE);
    let handle = state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .cloned()
        .expect("store");
    for (key, len) in [
        ("at-limit", MAX_DATA_READ_VALUE_BYTES),
        ("over-limit", MAX_DATA_READ_VALUE_BYTES + 1),
        ("forty-kb", 40_000),
    ] {
        handle
            .put_with_delta(key.to_string(), vec![b'v'; len], "text/plain".into())
            .await
            .expect("put");
    }
    // Review of #1935: the worst-case key (256 control characters, 6 bytes
    // each once escaped) with a value at the limit still fits one reply,
    // and a content type over its bound has its own status.
    let worst_key = "\u{1}".repeat(crate::share_grant::data_read::MAX_DATA_READ_FIELD_BYTES);
    handle
        .put_with_delta(
            worst_key.clone(),
            vec![b'v'; MAX_DATA_READ_VALUE_BYTES],
            "\u{1}".repeat(MAX_DATA_READ_CONTENT_TYPE_BYTES),
        )
        .await
        .expect("put");
    handle
        .put_with_delta(
            "long-type".to_string(),
            b"small".to_vec(),
            "t".repeat(MAX_DATA_READ_CONTENT_TYPE_BYTES + 1),
        )
        .await
        .expect("put");
    let (agent, machine) = bound_sender(&state).await;
    install_grant(&state, agent, vec![data_cap(DataAccess::Ro)]).await;

    let get = |key: &str| DataReadOp::Get {
        key: key.to_string(),
    };
    let at = serve(&state, agent, machine, get("at-limit")).await;
    assert_eq!(at.status, DataReadStatus::Ok);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(at.entry.expect("entry").value_b64)
            .expect("b64")
            .len(),
        MAX_DATA_READ_VALUE_BYTES
    );
    let worst = serve(&state, agent, machine, get(&worst_key)).await;
    assert_eq!(worst.status, DataReadStatus::Ok, "the worst case fits");
    let long_type = serve(&state, agent, machine, get("long-type")).await;
    assert_eq!(long_type.status, DataReadStatus::ContentTypeTooLong);
    let (code, body) = reply_response(long_type);
    assert_eq!(code, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body.0.to_string().contains("content type"));
    for key in ["over-limit", "forty-kb"] {
        let reply = serve(&state, agent, machine, get(key)).await;
        assert_eq!(reply.status, DataReadStatus::TooLarge, "{key}");
        let (code, _) = reply_response(reply);
        assert_eq!(code, StatusCode::PAYLOAD_TOO_LARGE);
    }
}

/// Review of #1935: senders without a data grant have their own small
/// bucket, so a crowd of strangers cannot take the grantees' slots.
#[tokio::test]
async fn issue1094_strangers_cannot_crowd_out_grantees() {
    let (state, _dir) = state_with_store().await;
    let (grantee, grantee_machine) = bound_sender(&state).await;
    install_grant(&state, grantee, vec![data_cap(DataAccess::Ro)]).await;
    for _ in 0..DATA_READ_SERVE_STRANGERS_CAP {
        let (stranger, machine) = bound_sender(&state).await;
        assert!(
            serve_data_read(&state, &typed(stranger, machine, request(DataReadOp::Keys)))
                .await
                .is_some()
        );
    }
    let (late, late_machine) = bound_sender(&state).await;
    assert!(
        serve_data_read(
            &state,
            &typed(late, late_machine, request(DataReadOp::Keys))
        )
        .await
        .is_none(),
        "the strangers' bucket is full"
    );
    let reply = serve(&state, grantee, grantee_machine, DataReadOp::Keys).await;
    assert_eq!(
        reply.status,
        DataReadStatus::Ok,
        "the grantee is still served"
    );
}
