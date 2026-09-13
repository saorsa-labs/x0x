//! Handler-level wiring test for the signed-public group bootstrap dispatch
//! (review finding F2 on v0.37.0).
//!
//! Since ADR 0030 §5 the snapshot is no longer direct-sent fire-and-forget. A
//! member add records a durable *obligation* in the bootstrap outbox
//! (`src/server/routes/public_group_bootstrap_outbox.rs`); a background worker
//! in `serve_with_options` retries it, and the obligation is discharged only by
//! a v2 application ACK, which the recipient's durable typed route releases
//! after it has installed the snapshot.
//!
//! That makes four separate pieces of `serve_with_options` wiring load-bearing:
//! the sidecar path and its fail-closed load, the `with_durable_typed_payload_route`
//! registration, the typed-payload listener, and the retry worker. The unit
//! tests around each part (`src/server/routes/public_group_bootstrap_outbox.rs`
//! and `signed_public_bootstrap_is_secret_free_and_commit_bound` in
//! `src/server/routes/named_groups.rs`) all stay green if any one of them is
//! deleted from `serve_with_options`, while remote bootstrap silently stops
//! working — which is what these tests exist to catch.
//!
//! They drive the real thing: in-process daemons, a SignedPublic group created
//! on the authority, a member add, and assertions on both the receiver's
//! installed state and the authority's on-disk outbox.
//!
//! Unlike `tests/server_inprocess.rs` (whose tests are all `#[ignore]`), this one
//! runs in the default suite: it binds only loopback, uses ephemeral ports, and
//! completes in a couple of seconds because it never waits on a gossip mesh.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use std::{error::Error, io};

use serde_json::Value;
use x0x::server::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};

/// A running in-process daemon plus a pre-authenticated REST client.
struct Daemon {
    handle: ServerHandle,
    client: reqwest::Client,
    base: String,
}

impl Daemon {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Stop the daemon and wait for run-to-completion, so a restart on the same
    /// data directory cannot race the previous instance's sidecar writes.
    async fn stop(self) {
        self.handle
            .shutdown_and_wait()
            .await
            .expect("daemon shutdown");
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
        let route = safe_route(path);
        let response = match self.client.post(self.url(path)).json(&body).send().await {
            Ok(response) => response,
            Err(error) => {
                let flags = RequestFailureFlags::from_error(&error);
                let health = self.failure_health_async().await;
                let supervisor_finished = self.handle.is_finished();
                let shutdown_requested = self.handle.cancellation_token().is_cancelled();
                panic!(
                    "POST {route}: request_failed category={} connect={} timeout={} request={} body={} source={} health={} health_status={} supervisor_finished={} shutdown_requested={}",
                    flags.category(),
                    flags.connect,
                    flags.timeout,
                    flags.request,
                    flags.body,
                    flags.source,
                    health.category,
                    health.status.map_or("none".to_string(), |status| status.to_string()),
                    supervisor_finished,
                    shutdown_requested,
                )
            }
        };
        response
            .json()
            .await
            .unwrap_or_else(|e| panic!("POST {route} json decode failed: {e}"))
    }

    /// Probe only after a POST transport failure. `/health` is auth-exempt and
    /// this short bound avoids perturbing the successful path or test deadline.
    async fn failure_health_async(&self) -> HealthProbe {
        match tokio::time::timeout(
            Duration::from_millis(500),
            self.client.get(self.url("/health")).send(),
        )
        .await
        {
            Ok(Ok(response)) => HealthProbe {
                category: "response",
                status: Some(response.status().as_u16()),
            },
            Ok(Err(error)) => HealthProbe {
                category: RequestFailureFlags::from_error(&error).category(),
                status: None,
            },
            Err(_) => HealthProbe {
                category: "outer_timeout",
                status: None,
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RequestFailureFlags {
    connect: bool,
    timeout: bool,
    request: bool,
    body: bool,
    source: &'static str,
}

impl RequestFailureFlags {
    fn from_error(error: &reqwest::Error) -> Self {
        Self {
            connect: error.is_connect(),
            timeout: error.is_timeout(),
            request: error.is_request(),
            body: error.is_body(),
            source: source_category(error),
        }
    }

    fn category(&self) -> &'static str {
        if self.timeout {
            "timeout"
        } else if self.connect {
            "connect"
        } else if self.body {
            "body"
        } else if self.request {
            "request"
        } else {
            "other"
        }
    }
}

#[derive(Debug)]
struct HealthProbe {
    category: &'static str,
    status: Option<u16>,
}

fn source_category(error: &reqwest::Error) -> &'static str {
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            return io_kind_category(io_error.kind());
        }
        source = cause.source();
    }
    "none"
}

fn io_kind_category(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::ConnectionRefused => "io_connection_refused",
        io::ErrorKind::ConnectionReset => "io_connection_reset",
        io::ErrorKind::ConnectionAborted => "io_connection_aborted",
        io::ErrorKind::TimedOut => "io_timed_out",
        io::ErrorKind::NotConnected => "io_not_connected",
        _ => "io_other",
    }
}

fn safe_route(path: &str) -> &'static str {
    match path {
        "/agents/connect" => "agents_connect",
        "/groups" => "groups",
        p if p.starts_with("/groups/") => "groups_subroute",
        "/agent/card/import" => "agent_card_import",
        p if p.starts_with("/agent/card") => "agent_card",
        "/health" => "health",
        _ => "other",
    }
}

/// Start a hermetic daemon: loopback-only, ephemeral API and QUIC ports, all
/// state under `dir`, and — critically for this test — an explicitly EMPTY
/// bootstrap-peer list, so the two daemons never form a gossip mesh.
///
/// REGRESSION NOTE (#638): ant-quic 0.27.50 honors the explicit
/// `bind_address = 127.0.0.1` exactly (previously the QUIC socket silently
/// bound wildcard, which made every interface address on the host — LAN,
/// utun/CGNAT — accidentally dialable). Since that fix, advertising those
/// interface hints in the card would make `/agents/connect` burn its local
/// probe ladder on undialable addresses (same-LAN IPv4 ranked first,
/// loopback excluded from the fast probes: ~6 s per dead interface) before
/// the hinted dial ever reaches the one live loopback address — past the
/// 20 s client budget and this test's `POST agents_connect` timeout.
/// `card_addresses` (src/server/routes/identity.rs) therefore suppresses
/// interface hints that do not match the specifically bound listener
/// address (loopback being this fixture's case); with the card carrying
/// only `127.0.0.1:<port>`, the connect lands on the hinted peer dial and
/// completes in well under a second.
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

    // A restart on the same data directory can briefly race the previous
    // instance releasing its SQLite history database: `shutdown_and_wait`
    // returns when the supervisor is done, and since #661 the history
    // reaper is awaited inside the drain, so the remaining window is only a
    // retention pass already inside its `spawn_blocking` (uncancellable by
    // design — see HistoryService::shutdown). Retry rather than sleep a
    // fixed amount, so the common (first-start) case stays instant.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let handle = loop {
        let options = ServeOptions {
            skip_update_check: true,
            self_update_enabled: false,
            ..ServeOptions::default()
        };
        match serve_with_options(config.clone(), options).await {
            Ok(handle) => break handle,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "serve_with_options never started: {error:#}"
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    };
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
        handle,
        client,
        base,
    }
}

/// The authority's durable bootstrap obligations, read straight off disk.
///
/// Reading the sidecar rather than a REST surface is the point: the guarantee
/// under test is that the debt is on disk, not merely in memory.
async fn outbox_entries(dir: &Path) -> Vec<Value> {
    let path = dir.join("data").join("public_group_bootstrap_outbox.json");
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return Vec::new();
    };
    let sidecar: Value = serde_json::from_slice(&bytes).expect("outbox sidecar json");
    sidecar["entries"].as_array().cloned().unwrap_or_default()
}

/// Poll `condition` until it holds or the deadline passes.
async fn wait_until<F, Fut>(what: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if condition().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out after {timeout:?} waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Import `other`'s current card into `into` at full trust. Re-importing after
/// a restart is what refreshes the peer's ephemeral address.
async fn import_card(into: &Daemon, other: &Daemon, label: &str) {
    let card = other
        .get_json("/agent/card?include_local_addresses=true")
        .await;
    let link = card["link"].as_str().expect("card link").to_string();
    let imported = into
        .post_json(
            "/agent/card/import",
            serde_json::json!({ "card": link, "trust_level": "trusted" }),
        )
        .await;
    assert_eq!(imported["ok"], true, "{label}: {imported:?}");
}

/// A newly-added member must receive and install the authority's SignedPublic
/// roster snapshot, and the authority's obligation must then be discharged.
///
/// REVERT GUARD: delete any of the four ADR 0030 §5 wiring pieces from
/// `serve_with_options` in `src/server/mod.rs` and this test fails —
///
/// - the retry worker (`public_group_bootstrap_outbox_step` timer): nothing
///   ever sends, and the test fails with "daemon A never installed the
///   SignedPublic group";
/// - the typed-payload listener (`handle_public_group_bootstrap_typed_payload`):
///   same, because the strict v2 send is the only send;
/// - `with_durable_typed_payload_route` downgraded to `with_typed_payload_route`:
///   verified by hand — the inbox refuses a non-opted-in typed route *before*
///   dispatch (ADR 0030 §7), so the handler never even sees the payload and the
///   test fails on "never installed the SignedPublic group";
/// - the fail-closed `load_public_group_bootstrap_outbox` call: caught by the
///   restart test below rather than this one.
///
/// The outbox unit tests and
/// `signed_public_bootstrap_is_secret_free_and_commit_bound` all keep passing
/// through every one of those deletions, because they call the persistence,
/// snapshot, and admission functions directly and never go through
/// `serve_with_options`.
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
    let alice_agent = alice.get_json(card_path).await["card"]["agent_id"]
        .as_str()
        .expect("alice agent_id")
        .to_string();
    let bob_agent = bob.get_json(card_path).await["card"]["agent_id"]
        .as_str()
        .expect("bob agent_id")
        .to_string();

    // Card import is what gives each side the other's AgentId->MachineId
    // binding (so the inbound direct message is `verified`) and the contact
    // trust the bootstrap consent gate requires (>= Known).
    import_card(&alice, &bob, "alice import of bob").await;
    import_card(&bob, &alice, "bob import of alice").await;

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

    // The member add is what records the durable bootstrap obligation; the
    // outbox worker is what delivers it.
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

    // The debt is discharged only by alice's v2 application ACK. If the route
    // were registered non-durably the ACK would be withheld by policy and this
    // is where that shows up — the group installs, but the outbox never drains.
    let bob_dir = tmp.path().join("bob");
    wait_until(
        "the authority's outbox never drained after the member installed the group",
        Duration::from_secs(30),
        || async { outbox_entries(&bob_dir).await.is_empty() },
    )
    .await;
}

/// ADR 0030 §5 validation: the outbox survives a sender restart, and an
/// obligation is cleared only by a frontier-matching v2 application ACK.
///
/// REVERT GUARD: this is the test that fails if the durable obligation is
/// dropped in favour of a fire-and-forget send. With a fire-and-forget send
/// there is no sidecar to survive anything, so the first assertion — that the
/// authority wrote a durable obligation for a member it could not reach — fails
/// immediately.
///
/// It also guards the fail-closed startup load: if
/// `load_public_group_bootstrap_outbox` is deleted from `serve_with_options`,
/// the restarted authority starts with an empty in-memory outbox and never
/// delivers, so the final drain-and-install assertion times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_outbox_survives_sender_restart_and_clears_only_on_ack() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let alice_dir = tmp.path().join("alice");
    let bob_dir = tmp.path().join("bob");

    let alice = start_daemon(&alice_dir).await;
    let bob = start_daemon(&bob_dir).await;
    let card_path = "/agent/card?include_local_addresses=true";
    let alice_agent = alice.get_json(card_path).await["card"]["agent_id"]
        .as_str()
        .expect("alice agent_id")
        .to_string();
    import_card(&alice, &bob, "alice import of bob").await;
    import_card(&bob, &alice, "bob import of alice").await;

    let group_name = format!("f2-outbox-{}", rand::random::<u32>());
    let created = bob
        .post_json(
            "/groups",
            serde_json::json!({
                "name": group_name,
                "description": "ADR 0030 bootstrap outbox durability",
                "preset": "public_open",
            }),
        )
        .await;
    assert_eq!(created["ok"], true, "create group: {created:?}");
    let group_id = created["group_id"].as_str().expect("group_id").to_string();

    // Take the recipient down BEFORE the add. No ACK can exist while alice is
    // gone, so anything that clears the obligation in this window is clearing
    // it on something weaker than an application ACK.
    alice.stop().await;

    let added = bob
        .post_json(
            &format!("/groups/{group_id}/members"),
            serde_json::json!({ "agent_id": alice_agent, "display_name": "alice" }),
        )
        .await;
    assert_eq!(added["ok"], true, "add member: {added:?}");

    wait_until(
        "the authority never recorded a durable bootstrap obligation",
        Duration::from_secs(10),
        || async { outbox_entries(&bob_dir).await.len() == 1 },
    )
    .await;

    // Several retry passes go by with the recipient unreachable. Every one of
    // them fails, and none of them may discharge the debt.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        outbox_entries(&bob_dir).await.len(),
        1,
        "failed delivery attempts must never clear an obligation"
    );

    // Restart the SENDER. The obligation lives on disk, so it must come back.
    bob.stop().await;
    let bob = start_daemon(&bob_dir).await;
    let after_restart = outbox_entries(&bob_dir).await;
    assert_eq!(
        after_restart.len(),
        1,
        "the obligation must survive a sender restart: {after_restart:?}"
    );

    // Bring the recipient back. Its ephemeral port changed, so the authority
    // needs the refreshed card before it can reach it again.
    let alice = start_daemon(&alice_dir).await;
    import_card(&bob, &alice, "bob re-import of restarted alice").await;
    import_card(&alice, &bob, "alice re-import of restarted bob").await;
    let connected = bob
        .post_json(
            "/agents/connect",
            serde_json::json!({ "agent_id": alice_agent }),
        )
        .await;
    assert_eq!(
        connected["ok"], true,
        "bob -> alice reconnect: {connected:?}"
    );

    // Now — and only now — an application ACK is possible, so the obligation
    // written before the restart must both deliver and drain.
    wait_until(
        "the restarted authority never delivered the surviving obligation",
        Duration::from_secs(120),
        || async {
            let groups = alice.get_json("/groups").await;
            group_listing_contains(&groups, &group_name)
        },
    )
    .await;
    wait_until(
        "the obligation was delivered but never cleared by its v2 ACK",
        Duration::from_secs(120),
        || async { outbox_entries(&bob_dir).await.is_empty() },
    )
    .await;
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

#[test]
fn failure_classification_is_deterministic_and_route_safe() {
    let timeout = RequestFailureFlags {
        connect: true,
        timeout: true,
        request: true,
        body: false,
        source: "io_timed_out",
    };
    assert_eq!(timeout.category(), "timeout");
    assert_eq!(safe_route("/groups/secret-id/members"), "groups_subroute");
    assert_eq!(safe_route("/agents/connect"), "agents_connect");
    assert_eq!(safe_route("/unknown/secret-id"), "other");
}

#[test]
fn failure_classification_preserves_connect_and_body_categories() {
    let connect = RequestFailureFlags {
        connect: true,
        timeout: false,
        request: true,
        body: false,
        source: "io_connection_refused",
    };
    let body = RequestFailureFlags {
        connect: false,
        timeout: false,
        request: false,
        body: true,
        source: "none",
    };
    assert_eq!(connect.category(), "connect");
    assert_eq!(connect.source, "io_connection_refused");
    assert_eq!(body.category(), "body");
    assert_eq!(
        io_kind_category(io::ErrorKind::ConnectionReset),
        "io_connection_reset"
    );
    assert_eq!(io_kind_category(io::ErrorKind::Other), "io_other");
}
