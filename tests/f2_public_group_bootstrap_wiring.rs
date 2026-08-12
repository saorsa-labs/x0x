//! Handler-level wiring test for the signed-public group bootstrap dispatch
//! (review finding F2 on v0.37.0).
//!
//! `serve_with_options` spawns a background listener on the direct channel that
//! deserializes a `PublicGroupBootstrap`, drops unverified senders, and calls
//! `handle_public_group_bootstrap`. The unit tests around that handler
//! (`signed_public_bootstrap_is_secret_free_and_commit_bound` and friends in
//! `src/server/routes/named_groups.rs`) exercise the snapshot and the handler in
//! isolation — deleting the dispatch block from `serve_with_options` leaves all
//! of them green while remote bootstrap silently stops working.
//!
//! This test drives the real thing: two in-process daemons, a SignedPublic group
//! created on the authority, a member add that direct-sends the snapshot, and an
//! assertion that the group is installed on the receiver.
//!
//! Unlike `tests/server_inprocess.rs` (whose tests are all `#[ignore]`), this one
//! runs in the default suite: it binds only loopback, uses ephemeral ports, and
//! completes in a couple of seconds because it never waits on a gossip mesh.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use x0x::server::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};

/// A running in-process daemon plus a pre-authenticated REST client.
struct Daemon {
    _handle: ServerHandle,
    client: reqwest::Client,
    base: String,
}

impl Daemon {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn get_json(&self, path: &str) -> Value {
        self.client
            .get(self.url(path))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"))
            .json()
            .await
            .unwrap_or_else(|e| panic!("GET {path} json: {e}"))
    }

    async fn post_json(&self, path: &str, body: Value) -> Value {
        self.client
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {path}: {e}"))
            .json()
            .await
            .unwrap_or_else(|e| panic!("POST {path} json: {e}"))
    }
}

/// Start a hermetic daemon: loopback-only, ephemeral API and QUIC ports, all
/// state under `dir`, and — critically for this test — an explicitly EMPTY
/// bootstrap-peer list, so the two daemons never form a gossip mesh.
async fn start_daemon(dir: &Path) -> Daemon {
    let data_dir = dir.join("data");
    tokio::fs::create_dir_all(&data_dir)
        .await
        .expect("create data dir");

    // Pin the API token up front rather than reading it back: `serve` only
    // generates one when `<data_dir>/api-token` is absent.
    let token = "f2".repeat(32);
    tokio::fs::write(data_dir.join("api-token"), &token)
        .await
        .expect("write api token");

    let mut config = DaemonConfig::default();
    config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bind_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bootstrap_peers = Some(Vec::new());
    config.data_dir = data_dir;
    config.identity_dir = Some(dir.join("identity"));

    let options = ServeOptions {
        skip_update_check: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    };
    let handle = serve_with_options(config, options)
        .await
        .expect("serve_with_options should start");
    let base = format!("http://{}", handle.local_addr());

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");

    Daemon {
        _handle: handle,
        client,
        base,
    }
}

/// A newly-added member must receive and install the authority's SignedPublic
/// roster snapshot over the direct channel.
///
/// REVERT GUARD: delete the `handle_public_group_bootstrap(&bootstrap_state,
/// &msg.sender, bootstrap).await` call (or the whole "signed-public group
/// bootstrap listener" block) from `serve_with_options` in `src/server/mod.rs`
/// and this test fails with "daemon A never installed the SignedPublic group".
/// `signed_public_bootstrap_is_secret_free_and_commit_bound` and the other
/// named-group unit tests keep passing, because they call the snapshot builder
/// and the handler directly and never go through the listener.
///
/// Why the direct dispatch is the ONLY way the group can reach daemon A here:
/// both daemons run with `bootstrap_peers = Some(vec![])`, so neither seeds any
/// gossip peer and no metadata topic mesh exists between them. The only link is
/// the QUIC connection `/agents/connect` opens, and the only thing sent over it
/// is the bootstrap snapshot `add_named_group_member` direct-sends. The
/// named-group metadata listener cannot substitute: it applies commits to an
/// existing local group and never creates one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serve_installs_signed_public_group_from_direct_bootstrap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // `alice` is the receiving member, `bob` is the group authority.
    let alice = start_daemon(&tmp.path().join("alice")).await;
    let bob = start_daemon(&tmp.path().join("bob")).await;

    // `include_local_addresses` is required for loopback: the card filters to
    // globally-advertisable addresses otherwise, and 127.0.0.1 is not one.
    let card_path = "/agent/card?include_local_addresses=true";
    let alice_card = alice.get_json(card_path).await;
    let bob_card = bob.get_json(card_path).await;
    let alice_agent = alice_card["card"]["agent_id"]
        .as_str()
        .expect("alice agent_id")
        .to_string();
    let bob_agent = bob_card["card"]["agent_id"]
        .as_str()
        .expect("bob agent_id")
        .to_string();
    let alice_link = alice_card["link"].as_str().expect("alice card link");
    let bob_link = bob_card["link"].as_str().expect("bob card link");

    // Card import is what gives each side the other's AgentId->MachineId
    // binding (so the inbound direct message is `verified`) and the contact
    // trust the bootstrap consent gate requires (>= Known).
    let imported = alice
        .post_json(
            "/agent/card/import",
            serde_json::json!({ "card": bob_link, "trust_level": "trusted" }),
        )
        .await;
    assert_eq!(imported["ok"], true, "alice import of bob: {imported:?}");
    let imported = bob
        .post_json(
            "/agent/card/import",
            serde_json::json!({ "card": alice_link, "trust_level": "trusted" }),
        )
        .await;
    assert_eq!(imported["ok"], true, "bob import of alice: {imported:?}");

    let connected = bob
        .post_json(
            "/agents/connect",
            serde_json::json!({ "agent_id": alice_agent }),
        )
        .await;
    assert_eq!(connected["ok"], true, "bob -> alice connect: {connected:?}");

    // `public_open` is the preset whose confidentiality is SignedPublic; the
    // bootstrap snapshot is built only for SignedPublic groups.
    let group_name = format!("f2-bootstrap-{}", rand::random::<u32>());
    let created = bob
        .post_json(
            "/groups",
            serde_json::json!({
                "name": group_name,
                "description": "F2 bootstrap dispatch wiring",
                "preset": "public_open",
            }),
        )
        .await;
    assert_eq!(created["ok"], true, "create group: {created:?}");
    let group_id = created["group_id"].as_str().expect("group_id").to_string();

    // The member add is what direct-sends the bootstrap snapshot to alice.
    let added = bob
        .post_json(
            &format!("/groups/{group_id}/members"),
            serde_json::json!({ "agent_id": alice_agent, "display_name": "alice" }),
        )
        .await;
    assert_eq!(added["ok"], true, "add member: {added:?}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let groups = alice.get_json("/groups").await;
        if group_listing_contains(&groups, &group_name) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "daemon A never installed the SignedPublic group within 10 s; if this \
             fails, the PublicGroupBootstrap dispatch block was removed from \
             serve_with_options (the named-group unit tests cannot catch that). \
             alice /groups = {groups:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The installed group must be bob's, not a locally-created shell: the
    // creator is the sending authority (alice cannot locally create a group
    // whose creator is bob) and the roster carries both members.
    let groups = alice.get_json("/groups").await;
    let installed = group_entry(&groups, &group_name).expect("installed group entry");
    assert_eq!(
        installed["creator"], bob_agent,
        "the installed group's creator must be the sending authority: {installed:?}"
    );
    assert_eq!(
        installed["member_count"], 2,
        "the installed roster must carry both the authority and alice: {installed:?}"
    );
}

fn group_entries(groups: &Value) -> &[Value] {
    groups["groups"]
        .as_array()
        .map_or(&[][..], |entries| entries.as_slice())
}

fn group_entry<'a>(groups: &'a Value, name: &str) -> Option<&'a Value> {
    group_entries(groups)
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
}

fn group_listing_contains(groups: &Value, name: &str) -> bool {
    group_entry(groups, name).is_some()
}
