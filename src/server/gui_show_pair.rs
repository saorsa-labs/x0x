//! ADR 0083 remote show on two loopback QUIC daemons with one owner.
//!
//! The opener is the test seam. Nothing is sent to a browser. Bootstrap
//! lists only the other daemon. mDNS and port mapping stay off.

#![cfg(test)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::gui::CapturingOpener;
use crate::identity::UserKeypair;
use crate::owner_sync::OwnerEnrollment;
use crate::server::{serve_with_options, DaemonConfig, ServeOptions};
use tower::ServiceExt;

/// One daemon start or shutdown.
const LIFECYCLE: Duration = Duration::from_secs(60);
/// How long A may wait to see B as an enrolled show target.
const DISCOVERY: Duration = Duration::from_secs(45);

fn options() -> ServeOptions {
    ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    }
}

fn config(root: &std::path::Path, network_id: &str, bootstrap: &str) -> DaemonConfig {
    let peers: Vec<String> = if bootstrap.is_empty() {
        Vec::new()
    } else {
        vec![bootstrap.to_string()]
    };
    serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": root.join("data"),
        "identity_dir": root.join("identity"),
        "bootstrap_peers": peers,
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": network_id,
        "history": { "enabled": false }
    }))
    .expect("loopback daemon config")
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

async fn install_owner(identity: &std::path::Path, owner: &UserKeypair) {
    tokio::fs::create_dir_all(identity)
        .await
        .expect("identity dir");
    crate::storage::save_user_keypair_to(owner, identity.join("user.key"))
        .await
        .expect("save shared owner key");
}

/// A opens `people` on B. Both daemons share one owner and speak only on
/// loopback. B's opener records the URL. The HTTP body has no token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_show_opens_on_the_other_owner_daemon() {
    let owner = UserKeypair::generate().expect("owner");
    let network_id = format!(
        "x0x.test.1593.pair.{}.{:08x}",
        std::process::id(),
        rand::random::<u32>()
    );
    let root_a = tempfile::tempdir().expect("A dir");
    let root_b = tempfile::tempdir().expect("B dir");
    install_owner(&root_a.path().join("identity"), &owner).await;
    install_owner(&root_b.path().join("identity"), &owner).await;

    let handle_a = tokio::time::timeout(
        LIFECYCLE,
        serve_with_options(config(root_a.path(), &network_id, ""), options()),
    )
    .await
    .expect("A starts")
    .expect("A serves");
    let state_a = handle_a.test_state.upgrade().expect("A state");
    let udp_a = state_a
        .agent
        .network()
        .expect("A QUIC node")
        .bound_addr()
        .await
        .expect("A UDP address");
    assert!(
        udp_a.ip().is_loopback(),
        "A must bind loopback, got {udp_a}"
    );

    let handle_b = tokio::time::timeout(
        LIFECYCLE,
        serve_with_options(
            config(root_b.path(), &network_id, &udp_a.to_string()),
            options(),
        ),
    )
    .await
    .expect("B starts")
    .expect("B serves");
    let state_b = handle_b.test_state.upgrade().expect("B state");
    let opener = CapturingOpener::new();
    state_b
        .gui_show
        .replace_opener_for_test(Arc::new(opener.clone()));
    let machine_a = state_a.agent.machine_id();
    let machine_b = state_b.agent.machine_id();
    let agent_a = state_a.agent.agent_id();
    let agent_b = state_b.agent.agent_id();
    let now = unix_ms();
    let record_a = OwnerEnrollment::sign(machine_a, &owner, now, None).expect("enroll A");
    let record_b = OwnerEnrollment::sign(machine_b, &owner, now, None).expect("enroll B");
    for state in [&state_a, &state_b] {
        let store = state
            .owner_sync
            .as_ref()
            .expect("owner sync")
            .store()
            .clone();
        store
            .enroll(record_a.clone())
            .await
            .expect("store enrollment A");
        store
            .enroll(record_b.clone())
            .await
            .expect("store enrollment B");
    }
    // Heartbeats omit the owner certificate until the human discloses it.
    // Owner trust reads that certificate. Both daemons announce it the same
    // way `POST /announce` does.
    //
    // #1643: consent is recorded before the disclosure is built, and a
    // same-second anonymous beat (built before consent) no longer drops a
    // cached certificate on the peer, so one disclosure per daemon is
    // enough. The second disclosure in a later second stays as
    // belt-and-braces: it also covers a beat that was already built when
    // consent landed, and exercises the strictly-fresher announce peers
    // see from the 3 s re-announce.
    for state in [&state_a, &state_b] {
        state
            .agent
            .announce_identity(true, true)
            .await
            .expect("disclose the owner certificate");
    }
    let consented_at = unix_ms() / 1000;
    while unix_ms() / 1000 <= consented_at {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for state in [&state_a, &state_b] {
        state
            .agent
            .announce_identity(true, true)
            .await
            .expect("disclose the owner certificate in a later second");
    }

    let ready = Instant::now();
    let mut last = String::new();
    while ready.elapsed() < DISCOVERY {
        let bound = state_a
            .agent
            .authenticated_bound_machine(&agent_b)
            .await
            .map(|binding| binding.machine_id);
        let advert = state_a
            .agent
            .capability_store()
            .lookup_binding(&agent_b)
            .map(|binding| binding.machine_id);
        let connected = state_a.agent.is_agent_connected(&agent_b).await;
        let shows = state_a
            .agent
            .capability_store()
            .verified_registry_supports(&agent_b, crate::dm::CapabilityRegistry::GUI_SHOW_V1);
        let trusted = state_a
            .agent
            .is_owner_trusted_pair(&agent_b, &machine_b)
            .await;
        let reverse = state_b
            .agent
            .is_owner_trusted_pair(&agent_a, &machine_a)
            .await;
        let cert = state_a
            .agent
            .identity_discovery_cache()
            .read()
            .await
            .get(&agent_b)
            .is_some_and(|entry| entry.agent_certificate.is_some());
        last = format!(
            "bound_ok={} advert_ok={} connected={connected} gui_show_v1={shows:?} trusted={trusted} reverse={reverse} cert={cert}",
            bound == Some(machine_b),
            advert == Some(machine_b)
        );
        // Same gates as `show_peer`: binding, advert machine, capability bit,
        // owner trust, and a live connection so the result is not `unconfirmed`.
        // B must trust A too, or it refuses the show.
        if bound == Some(machine_b)
            && advert == Some(machine_b)
            && connected
            && shows == Some(true)
            && trusted
            && reverse
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        ready.elapsed() < DISCOVERY,
        "B was not a show target within {}s ({last})",
        DISCOVERY.as_secs()
    );

    let router = handle_a.test_router.clone();
    let body = serde_json::json!({
        "view": "people",
        "target_machine": hex::encode(machine_b.as_bytes())
    });
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/gui/show")
        .header("authorization", format!("Bearer {}", state_a.api_token))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("show request");
    let response = tokio::time::timeout(Duration::from_secs(20), router.oneshot(request))
        .await
        .expect("show returns inside 20s")
        .expect("show response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("show body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert!(status.is_success(), "show failed {status} {json}");
    assert_eq!(json["outcome"], "opened", "{json}");
    assert_eq!(
        json["machine_id"],
        hex::encode(machine_b.as_bytes()),
        "{json}"
    );
    assert!(json.get("token").is_none(), "{json}");
    assert!(!json.to_string().contains("http"), "{json}");
    let urls = opener.urls.lock().expect("urls").clone();
    assert_eq!(urls.len(), 1, "B must open one view, urls={urls:?}");
    assert!(
        urls[0].contains("127.0.0.1") && urls[0].contains("#/people"),
        "B must open its own loopback people view, got {}",
        urls[0]
    );

    drop(state_a);
    drop(state_b);
    tokio::time::timeout(LIFECYCLE, handle_a.shutdown_and_wait())
        .await
        .expect("A stops")
        .expect("A shutdown");
    tokio::time::timeout(LIFECYCLE, handle_b.shutdown_and_wait())
        .await
        .expect("B stops")
        .expect("B shutdown");
    let _ = (root_a, root_b);
}
