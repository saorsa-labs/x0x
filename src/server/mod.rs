//! HTTP/WebSocket server for the x0x daemon.
//!
//! Phase 1 (Issue #110): the daemon's axum router, handlers, SSE/WS
//! plumbing, auth middleware, and serving-side background tasks were
//! relocated here verbatim from `src/bin/x0xd.rs` so the library can
//! expose a serving entrypoint. Behavior is unchanged from the binary.

// The moved handler bodies use thousands of `x0x::...` paths; alias the
// crate to itself so those paths resolve unchanged inside the library.
use crate as x0x;

mod auth;
mod crdt_subscriptions;
mod routes;
mod sse;
mod state;
mod ws;

// Re-export the public server API surface so `x0x::server::*` paths are
// unchanged after the #125 / WS1.4 extraction. Internal types (AppState,
// DaemonUpdateConfig, CachedUpgradeCheck) stay private to the crate.
use routes::{
    ack_diagnostics, add_contact, add_machine, add_mls_member, add_named_group_member, add_task,
    agent_info, agent_reachability, agent_sign, agent_user_id_handler, agent_verify,
    agents_by_user_handler, announce_identity, apply_direct_kv_store_delta,
    apply_named_group_metadata_event, apply_upgrade, approve_join_request, ban_group_member,
    bootstrap_cache_stats, broadcast_current_manifest, cancel_join_request, check_upgrade,
    connect_agent, connect_diagnostics_handler, connect_machine, connectivity_diagnostics,
    create_discovery_subscription, create_group_invite, create_join_request, create_kv_store,
    create_mls_group, create_mls_welcome, create_named_group, create_task_list, delete_contact,
    delete_discovery_subscription, delete_kv_value, delete_machine, direct_connections,
    direct_message_send_config, direct_send, discover_groups, discover_groups_nearby,
    discovered_agent, discovered_agents, discovered_machine, discovered_machines, dm_diagnostics,
    ensure_named_group_listeners, evaluate_trust, exec_cancel, exec_diagnostics, exec_run,
    exec_sessions, file_accept_handler, file_reject_handler, file_send_handler,
    file_transfer_status_handler, file_transfers_handler, find_agent, forward_add, forward_list,
    forward_remove, get_a2a_agent_card, get_agent_card, get_constitution, get_constitution_json,
    get_group_card, get_group_public_messages, get_group_state, get_group_state_commits,
    get_kv_value, get_mls_group, get_named_group, get_named_group_members, gossip_diagnostics,
    groups_diagnostics, handle_file_message, handle_join_result_message,
    handle_treekem_catchup_request, handle_treekem_catchup_response, handle_welcome_blob_message,
    health, identity_revocations, identity_revoke, import_agent_card, import_group_card,
    ingest_public_message, introduction, join_group_via_invite, join_kv_store, leave_group,
    list_contacts, list_discovery_subscriptions, list_join_requests, list_kv_keys, list_kv_stores,
    list_machines, list_mls_groups, list_named_groups, list_revocations, list_task_lists,
    list_tasks, load_named_groups, load_treekem_member_key_packages, machine_for_agent_handler,
    machines_by_user_handler, mls_decrypt, mls_encrypt, named_group_metadata_event_kind,
    network_status, peer_health_handler, peers, pin_machine, presence, presence_find,
    presence_foaf, presence_online, presence_status, probe_peer_handler, publish,
    publish_group_card_to_discovery, put_kv_value, quick_trust, recover_treekem_named_journals,
    reject_join_request, remove_mls_member, remove_named_group_member, restore_treekem_groups,
    revoke_contact, run_fallback_github_poll, run_gossip_update_listener, run_startup_update_check,
    seal_group_state, secure_group_decrypt, secure_group_encrypt, secure_group_reseal,
    secure_open_envelope_adversarial, send_group_public_message, set_group_display_name,
    shutdown_handler, spawn_directory_resubscribe, spawn_global_discovery_listener,
    spawn_global_public_message_listener, spawn_listed_to_contacts_listener, status,
    streams_diagnostics, subscribe, unban_group_member, unpin_machine, unsubscribe, update_contact,
    update_group_policy, update_member_role, update_named_group, update_task, withdraw_group_state,
    JoinResultMessage, KvStoreDirectDelta, NamedGroupMetadataEvent, SelfPublishedReleaseManifests,
    TreeKemCatchupRequest, TreeKemCatchupResponse, WelcomeBlobMessage,
    DIRECTORY_DIGEST_INTERVAL_SECS, DIRECTORY_RESUBSCRIBE_JITTER_MS,
    GROUP_PUBLIC_MESSAGE_DM_PREFIX, KV_STORE_DELTA_DM_PREFIX,
};
use sse::{direct_events_sse, events_sse, peer_events_handler, presence_events, SseEvent};
use state::AppState;
pub use state::{
    default_api_address, default_bind_address, default_data_dir, validate_instance_name,
    DaemonConfig, InstanceName, ServeOptions, ServerHandle, DEFAULT_QUIC_PORT,
};
use ws::{serve_gui, ws_diagnostics, ws_direct_handler, ws_handler, ws_sessions, WsOutboundStats};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tokio::sync::{broadcast, mpsc, watch, Mutex, RwLock};
use tower_http::cors::CorsLayer;
use x0x::identity::AgentId;
use x0x::identity::MachineId;
use x0x::network::NetworkConfig;
use x0x::Agent;

// ---------------------------------------------------------------------------
// Optional JSON body helper
// ---------------------------------------------------------------------------

/// Parse an optional JSON body: returns `Ok(T::default())` when the body is
/// empty (no Content-Type or zero-length), but returns an axum 400 error if
/// Content-Type is `application/json` and the body is malformed.
fn parse_optional_json<T: serde::de::DeserializeOwned + Default>(
    headers: &HeaderMap,
    body: &Bytes,
) -> std::result::Result<T, (StatusCode, Json<serde_json::Value>)> {
    if body.is_empty() {
        return Ok(T::default());
    }
    let is_json = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false);
    if !is_json {
        // Non-JSON content type with a body — reject
        return Err(api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        ));
    }
    serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))
}

const DM_INBOX_START_MAX_ATTEMPTS: u32 = 120;
const DM_INBOX_START_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Run the daemon HTTP/WebSocket server to completion.
///
/// Thin blocking wrapper over [`serve_with_options`]: performs all fallible
/// startup, then awaits run-to-completion. Shutdown is driven by the `/shutdown`
/// HTTP endpoint. This entrypoint does NOT install a Ctrl-C handler — a host
/// process that wants Ctrl-C must use [`serve_with_options`] and select over
/// [`ServerHandle::wait`] alongside its own signal handling (the daemon binary
/// does exactly that).
pub async fn run(config: DaemonConfig, options: ServeOptions) -> anyhow::Result<()> {
    serve_with_options(config, options).await?.wait().await
}

/// CLI `--check-updates`: run the startup update check, print its outcome, and
/// return without serving. Mirrors the print-and-exit behaviour the daemon had
/// inline before the [`serve_with_options`] extraction. Only the binary calls
/// this; the embed path never installs updates.
pub async fn run_update_check_and_report(
    config: &DaemonConfig,
    skip_update_check: bool,
) -> anyhow::Result<()> {
    if config.update.enabled && !skip_update_check {
        match run_startup_update_check(config, None).await {
            Ok(Some(version)) => println!("x0xd updated to {version}"),
            Ok(None) => println!("x0xd is up to date ({})", x0x::VERSION),
            Err(e) => return Err(e).context("self-update check failed"),
        }
    } else if !config.update.enabled {
        println!("self-update checks are disabled by configuration");
    } else {
        println!("self-update check skipped by --skip-update-check");
    }
    Ok(())
}

/// Start the x0x server in-process and return a [`ServerHandle`].
///
/// Self-update install/restart is DISABLED and the startup update check is
/// skipped — an embedded library must never replace or restart the host
/// application. Supply an `identity_dir` (or `data_dir`) in `config` so no
/// state is written under `~/.x0x`. See [`serve_with_options`] for full
/// control over runtime options.
pub async fn serve(config: DaemonConfig) -> anyhow::Result<ServerHandle> {
    let options = ServeOptions {
        skip_update_check: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    };
    serve_with_options(config, options).await
}

/// Start the x0x server in-process with explicit runtime options.
///
/// All synchronous, fallible startup (data-dir create, identity load/gen,
/// API-token load, listener bind, state + router build, `api.port` write) runs
/// here and surfaces as `Err` BEFORE any long-lived task is spawned. On success
/// a single supervisor task is spawned and a [`ServerHandle`] is returned with
/// the bound address already readable.
pub async fn serve_with_options(
    config: DaemonConfig,
    options: ServeOptions,
) -> anyhow::Result<ServerHandle> {
    let ServeOptions {
        skip_update_check,
        cli_no_port_mapping,
        cli_disable_peer_cache,
        instance_name,
        exec_policy,
        connect_policy,
        self_update_enabled,
    } = options;
    // Ensure data directory exists early so self-update has a working directory.
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .context("failed to create data directory")?;

    // Startup banner
    tracing::info!(
        version = %x0x::VERSION,
        binary = "x0xd",
        pid = std::process::id(),
        "x0xd started"
    );

    // Note: `--check-updates` is a CLI-only print-and-exit mode handled entirely
    // by the binary (see `run_update_check_and_report`) before it ever calls
    // `serve_with_options`; it is intentionally not a `ServeOptions` field.

    // Startup GitHub check (fallback mechanism — gossip is primary).
    // Gated on `self_update_enabled` so embedders never download/install a new
    // binary in-process; the daemon binary sets it to `config.update.enabled`.
    if self_update_enabled && config.update.enabled && !skip_update_check {
        if let Err(e) = run_startup_update_check(&config, None).await {
            tracing::warn!(error = %e, "Startup update check failed: {e}");
        }
    }

    tracing::info!("Starting x0xd v{}", x0x::VERSION);
    if let Some(ref name) = instance_name {
        tracing::info!("Instance name: {name}");
    }
    tracing::info!("API address: {}", config.api_address);

    // Promote IPv4 unspecified (0.0.0.0) to IPv6 unspecified (::) for dual-stack.
    // An IPv6 socket with IPV6_V6ONLY=false accepts both IPv4 and IPv6 traffic,
    // avoiding port conflicts when multiple instances run on the same machine.
    let bind_address = if config.bind_address.ip().is_unspecified() && config.bind_address.is_ipv4()
    {
        let promoted = SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            config.bind_address.port(),
        );
        tracing::info!(
            "Bind address: {} (promoted to {} for dual-stack)",
            config.bind_address,
            promoted
        );
        promoted
    } else {
        tracing::info!("Bind address: {}", config.bind_address);
        config.bind_address
    };

    // Resolve the identity directory. Precedence:
    //   1. `config.identity_dir` — explicit host-supplied directory. This is the
    //      storage boundary for in-process embedding: when set, ALL identity
    //      keys derive from it and `~/.x0x` is never touched.
    //   2. `~/.x0x-<name>` — instance-scoped directory when `--name` is active.
    //   3. `None` — default daemon behaviour (keys fall back to `~/.x0x`).
    let identity_dir = match (&config.identity_dir, &instance_name) {
        (Some(dir), _) => {
            tokio::fs::create_dir_all(dir)
                .await
                .context("failed to create configured identity directory")?;
            tracing::info!("Identity directory: {} (configured)", dir.display());
            Some(dir.clone())
        }
        (None, Some(name)) => {
            let dir = dirs::home_dir()
                .context("home directory required for instance identity directory")?
                .join(format!(".x0x-{name}"));
            tokio::fs::create_dir_all(&dir)
                .await
                .context("failed to create instance identity directory")?;
            tracing::info!("Identity directory: {}", dir.display());
            Some(dir)
        }
        (None, None) => None,
    };

    // Create agent
    //
    // Peer cache is strictly per-data-dir (issue #206): co-located daemons
    // must never share a bootstrap cache, or peers learned on one gossip
    // plane leak into another plane's restart redials (the #189
    // shared-default-path shape). The previous `shared_cache_dir()` arm
    // collapsed to the same path when data_dir was default, but made the
    // sharing explicit and silently reachable for embedders passing
    // `DaemonConfig::default()` — removed, not rehabilitated. Multi-process
    // collision on one cache dir is fenced by ant-quic's cache file locking.
    let cache_dir = {
        let dir = config.data_dir.join("peers");
        let _ = std::fs::create_dir_all(&dir);
        dir
    };
    // Issue #206: resolve the effective gossip plane. Unset TOML
    // `network_id` maps to the well-known prod plane so co-located daemons
    // are isolated by default; an explicit empty string opts out (open).
    let network_id = config.resolved_network_id();
    match &network_id {
        Some(id) => tracing::info!(network_id = %id, "Gossip plane isolation enabled"),
        None => tracing::warn!(
            "Gossip plane isolation DISABLED (network_id = \"\") — this daemon will \n             exchange gossip with every plane, including cross-plane mDNS peers"
        ),
    }
    let network_config = NetworkConfig {
        bind_addr: Some(bind_address),
        bootstrap_nodes: config.resolved_bootstrap_peers(),
        max_connections: 50,
        connection_timeout: std::time::Duration::from_secs(30),
        stats_interval: std::time::Duration::from_secs(60),
        pinned_bootstrap_peers: std::collections::HashSet::new(),
        inbound_allowlist: std::collections::HashSet::new(),
        max_peers_per_ip: 3,
        // CLI flag wins over config TOML so operators can override on a
        // single invocation without editing the config file.
        port_mapping_enabled: config.port_mapping_enabled && !cli_no_port_mapping,
        peer_relay: config.peer_relay.clone(),
        network_id,
        observed_prefix_enabled: config.observed_prefix_enabled,
    };

    let contacts_path = config.data_dir.join("contacts.json");
    // ADR-0023: the daemon passes its `[history]` config through (default-on;
    // `enabled = false` is the escape hatch). Named instances resolve to a
    // per-instance `history.db` because `data_dir` is per-instance.
    let mut history_config = config.history.clone();
    if history_config.db_path.is_none() {
        history_config.db_path = Some(config.data_dir.join("history.db"));
    }
    let mut builder = Agent::builder()
        .with_network_config(network_config)
        .with_gossip_config(config.gossip.clone())
        .with_peer_cache_dir(cache_dir)
        .with_contact_store_path(&contacts_path)
        .with_history(history_config)
        .with_heartbeat_interval(config.heartbeat_interval_secs)
        .with_identity_ttl(config.identity_ttl_secs);

    if let Some(secs) = config.presence_beacon_interval_secs {
        builder = builder.with_presence_beacon_interval(secs);
    }
    if let Some(secs) = config.presence_event_poll_interval_secs {
        builder = builder.with_presence_event_poll_interval(secs);
    }
    if let Some(secs) = config.presence_offline_timeout_secs {
        builder = builder.with_presence_offline_timeout(secs);
    }
    if cli_disable_peer_cache {
        tracing::info!("Peer cache disabled by --disable-peer-cache");
        builder = builder.with_peer_cache_disabled();
    }

    // NOTE: --no-hard-coded-bootstrap clears only the *embedded* global
    // bootstrap network; an explicit `bootstrap_peers` list in the config
    // file is honored verbatim (see DaemonConfig::resolved_bootstrap_peers).
    // ant-quic's first-party mDNS LAN discovery and the peer cache remain
    // active by design so that:
    //   - Local mesh (two laptops on WiFi) still works via mDNS
    //   - FOAF presence discovery still finds peers
    //   - Previously-seen peers can reconnect via cache
    // mDNS-discovered co-located daemons can no longer bridge gossip
    // planes, though: every connection exchanges a plane hello, and peers
    // on a different `network_id` plane are refused at the gossip layer
    // (issue #206).

    if let Some(ref id_dir) = identity_dir {
        builder = builder
            .with_machine_key(id_dir.join("machine.key"))
            .with_agent_key_path(id_dir.join("agent.key"))
            .with_agent_cert_path(id_dir.join("agent.cert"))
            .with_identity_dir(id_dir);
    }

    if let Some(ref user_key_path) = config.user_key_path {
        builder = builder.with_user_key_path(user_key_path);
        tracing::info!("User key path: {}", user_key_path.display());
    } else if let Some(ref id_dir) = identity_dir {
        // Storage boundary: with an explicit identity directory and no
        // configured user key, scope the (opt-in) user key lookup to that
        // directory so the builder never falls back to reading `~/.x0x/user.key`.
        // `with_user_key_path` loads only if the file exists and never
        // auto-generates, so this stays opt-in.
        builder = builder.with_user_key_path(id_dir.join("user.key"));
    }

    // Fix A (Issue #110 Phase 2): perform every agent-independent fallible
    // startup step BEFORE building the agent. `Agent::builder().build()` spawns
    // the NetworkNode receiver/accept/eviction tasks (and binds the QUIC
    // socket), so any error AFTER it would leak those running tasks for an
    // embedder. The common failure — API port already in use — is caught here,
    // before the agent exists, so `serve_with_options()` returns Err having
    // started nothing.

    // MLS groups are session-scoped (saorsa-mls groups are not serializable)
    let mls_groups_path = config.data_dir.join("mls_groups.bin");
    let mls_groups: HashMap<String, x0x::mls::MlsGroup> = HashMap::new();

    // Load named groups from disk (if any)
    let named_groups_path = config.data_dir.join("named_groups.json");
    let treekem_dir = config.data_dir.join("treekem");
    if let Err(e) = tokio::fs::create_dir_all(&treekem_dir).await {
        tracing::warn!(
            "failed to create TreeKEM snapshot dir {}: {e}",
            treekem_dir.display()
        );
    }
    recover_treekem_named_journals(&named_groups_path, &treekem_dir)
        .await
        .map_err(|e| anyhow::anyhow!("failed to recover TreeKEM persistence journal: {e}"))?;
    let named_groups = load_named_groups(&named_groups_path).await?;
    let treekem_member_key_packages = load_treekem_member_key_packages(
        &treekem_dir.join("member-key-packages.json"),
        &named_groups,
    )
    .await?;

    // Load or generate API bearer token for local authentication.
    let api_token = auth::load_or_generate_api_token(&config.data_dir).await?;

    // Bind the API listener early so the daemon can report the actual bound
    // address even when configured with an ephemeral port. Done before the agent
    // is built so a bind failure (port in use) returns Err with nothing running.
    let listener = tokio::net::TcpListener::bind(config.api_address)
        .await
        .context("failed to bind API address")?;
    let actual_api_addr = listener.local_addr()?;

    // #195: warn loudly when the control plane is bound off-loopback — the
    // API is bearer-token-only with no auth rate-limiting, so a non-loopback
    // bind exposes it off-host. --api-port only changes the port and stays
    // loopback-safe; only a TOML `api_address = "0.0.0.0:…"` reaches here.
    if !actual_api_addr.ip().is_loopback() {
        tracing::warn!(
            target: "x0x::startup",
            api_address = %actual_api_addr,
            "API listener bound on a NON-LOOPBACK address — the control plane is reachable \
             off-host, protected only by the bearer token (no auth rate-limiting). Bind \
             127.0.0.1 (the default) unless you intentionally want remote control-plane access."
        );
    }

    let (broadcast_tx, _) = broadcast::channel::<SseEvent>(256);
    // Load or generate the per-daemon ML-KEM-768 keypair. Persisted under
    // `<data_dir>/agent_kem.key` with mode 0600. This keypair is the root of
    // trust for `SecureShareDelivered` — only the holder of the secret half
    // can open group-shared-secret envelopes addressed to this agent.
    let agent_kem_path = config.data_dir.join("agent_kem.key");
    let agent_kem_keypair = Arc::new(
        x0x::groups::kem_envelope::AgentKemKeypair::load_or_generate(&agent_kem_path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to load/generate agent KEM keypair: {e}"))?,
    );
    tracing::info!(
        "agent KEM-768 public key loaded ({} bytes)",
        agent_kem_keypair.public_bytes.len()
    );

    // All agent-independent fallible startup has succeeded. Build the agent now
    // (this spawns the network tasks and binds the QUIC socket). From here on,
    // any fallible step must `agent.shutdown().await` on the error path so a
    // failure does not leak the agent/network/tasks.
    let agent = builder.build().await.context("failed to create agent")?;

    tracing::info!("Agent ID: {}", agent.agent_id());
    tracing::info!("Machine ID: {}", agent.machine_id());
    if let Some(uid) = agent.user_id() {
        tracing::info!("User ID: {}", uid);
    }

    // Attach the agent-owned contact store to gossip and API state so the
    // DM inbox trust evaluator observes the same mutations made by REST
    // contact/card endpoints.
    let contacts = Arc::clone(agent.contacts());
    agent.set_contacts(Arc::clone(&contacts));
    tracing::info!("Contact store loaded from {}", contacts_path.display());

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let (shutdown_notify, _) = watch::channel(false);
    let agent = Arc::new(agent);
    let (exec_dm_tx, exec_dm_rx) = mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1024);
    let (group_public_dm_tx, mut group_public_dm_rx) =
        mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1024);
    let (kv_store_delta_dm_tx, mut kv_store_delta_dm_rx) =
        mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1024);
    let exec_service = x0x::exec::ExecService::spawn(Arc::clone(&agent), exec_policy, exec_dm_rx);

    // Zero-peer watchdog (issue #262): opt-in supervised self-heal for the
    // wedged-transport state (process alive, API healthy, socket silent,
    // peers pinned at 0). Samples every 30s; after `window` seconds of
    // CONTINUOUS zero peers (plus the same startup grace) it attempts a
    // graceful shutdown and hard-exits 30s later so the known shutdown hang
    // cannot defeat the restart. Only meaningful under a supervisor
    // (systemd Restart=always) — off by default.
    if let Some(window) = config.zero_peer_restart_secs {
        let watchdog_agent = Arc::clone(&agent);
        let watchdog_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            let window = std::time::Duration::from_secs(window.max(60));
            let mut zero_since: Option<std::time::Instant> = None;
            // Startup grace: give bootstrap the same window before arming.
            tokio::time::sleep(window).await;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let peers = watchdog_agent
                    .peers()
                    .await
                    .map(|p| p.len())
                    .unwrap_or(usize::MAX);
                if peers == 0 {
                    let since = *zero_since.get_or_insert_with(std::time::Instant::now);
                    if since.elapsed() >= window {
                        tracing::error!(
                            window_secs = window.as_secs(),
                            "zero-peer watchdog tripped (issue #262): no peers for the \
                             full window — transport presumed wedged; exiting for \
                             supervisor restart"
                        );
                        let _ = watchdog_shutdown.send(()).await;
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        std::process::exit(86);
                    }
                } else {
                    zero_since = None;
                }
            }
        });
    }

    // Tailnet streams + forwarder (#131 × #132): install the loaded connect
    // policy on the agent so the inbound byte-stream accept loop refuses
    // streams from ACL-unlisted peers (default-closed when the policy is
    // Enabled; no ACL constraint when Disabled). Then build the connect-ACL
    // diagnostics + the ForwardService, whose inbound consumers are the
    // registered acceptors for the ForwardV1/ForwardV2 stream protocols and
    // gate each stream at `evaluate_connect_gate` before any local connect.
    // Only spawn the forwarder when connect is enabled by policy.
    agent.set_connect_policy(Arc::new(connect_policy.clone()));
    let connect_diagnostics = Arc::new(x0x::connect::ConnectDiagnostics::new(
        connect_policy.summary(),
    ));
    let forward_service = if connect_policy.enabled() {
        let fs = Arc::new(
            x0x::forward::ForwardService::new(
                Arc::clone(&agent),
                Arc::new(connect_policy.clone()),
                Arc::clone(&connect_diagnostics),
                config.forward.require_attestation,
            )
            .context("failed to register forwarder stream acceptors")?,
        );
        fs.spawn_inbound();
        Some(fs)
    } else {
        None
    };

    // ADR-0012 Phase 4: restore live TreeKEM groups from on-disk snapshots.
    // Must happen before the AppState is built so secure endpoints see the
    // groups immediately. Done with `named_groups` still owned (it is moved
    // into the RwLock below).
    let treekem_groups = restore_treekem_groups(&named_groups, agent.as_ref(), &treekem_dir).await;

    let state = Arc::new(AppState {
        agent: Arc::clone(&agent),
        history_record_topics: config.history.record_topics.clone(),
        subscriptions: RwLock::new(HashMap::new()),
        task_lists: RwLock::new(HashMap::new()),
        kv_stores: RwLock::new(HashMap::new()),
        crdt_subscriptions: RwLock::new(crdt_subscriptions::CrdtSubscriptionManifest::default()),
        crdt_subscriptions_path: config.data_dir.join("crdt-subscriptions.json"),
        kv_store_state_dir: config.data_dir.join("kv-stores"),
        crdt_subscriptions_persistence_lock: Mutex::new(()),
        crdt_handle_locks: RwLock::new(HashMap::new()),
        named_groups: RwLock::new(named_groups),
        named_groups_path,
        named_groups_persistence_lock: Mutex::new(()),
        group_metadata_tasks: RwLock::new(HashMap::new()),
        group_card_cache: RwLock::new(HashMap::new()),
        directory_cache: RwLock::new(x0x::groups::DirectoryShardCache::default()),
        directory_subscriptions: RwLock::new(x0x::groups::SubscriptionSet::default()),
        directory_subscriptions_path: config.data_dir.join("directory-subscriptions.json"),
        directory_tasks: RwLock::new(HashMap::new()),
        directory_digest_interval_secs: config
            .directory_digest_interval_secs
            .unwrap_or(DIRECTORY_DIGEST_INTERVAL_SECS),
        directory_resubscribe_jitter_ms: config
            .directory_resubscribe_jitter_ms
            .unwrap_or(DIRECTORY_RESUBSCRIBE_JITTER_MS),
        public_messages: RwLock::new(HashMap::new()),
        public_message_tasks: RwLock::new(HashMap::new()),
        agent_kem_keypair: Arc::clone(&agent_kem_keypair),
        contacts,
        mls_groups: RwLock::new(mls_groups),
        mls_groups_path,
        pending_join_results: RwLock::new(HashMap::new()),
        expected_join_result_inviters: StdMutex::new(HashMap::new()),
        pending_welcomes: RwLock::new(HashMap::new()),
        pending_welcome_receives: RwLock::new(HashMap::new()),
        pending_welcome_waiters: RwLock::new(HashMap::new()),
        pending_welcome_acks: RwLock::new(HashMap::new()),
        treekem_pending_events: RwLock::new(HashMap::new()),
        treekem_event_log: RwLock::new(HashMap::new()),
        treekem_member_key_packages,
        treekem_catchup_throttle: RwLock::new(HashMap::new()),
        group_membership_locks: RwLock::new(HashMap::new()),
        treekem_groups: RwLock::new(treekem_groups),
        treekem_dir,
        ws_sessions: RwLock::new(HashMap::new()),
        ws_topics: RwLock::new(HashMap::new()),
        ws_outbound_stats: Arc::new(WsOutboundStats::default()),
        api_address: actual_api_addr,
        start_time: Instant::now(),
        broadcast_tx,
        file_transfers: RwLock::new(HashMap::new()),
        receive_hashers: RwLock::new(HashMap::new()),
        pending_file_chunks: RwLock::new(HashMap::new()),
        file_chunk_acks: RwLock::new(HashMap::new()),
        transfers_dir: config.data_dir.join("transfers"),
        shutdown_tx,
        shutdown_notify,
        update_config: config.update.clone(),
        self_update_enabled,
        upgrade_check_cache: Mutex::new(None),
        upgrade_apply_lock: Arc::new(Mutex::new(())),
        api_token,
        sessions: auth::SessionStore::new(auth::SESSION_TOKEN_TTL),
        exec_service: Arc::clone(&exec_service),
        groups_diagnostics: Arc::new(x0x::groups::GroupsDiagnostics::new()),
        connect_diagnostics,
        forward_service,
    });

    // Fix A (Issue #110 Phase 2 + #116): the `api.port` advertisement is written
    // here, before any long-lived server-owned task is spawned. The agent and the
    // ExecService ARE already built/spawned by this point (both needed for
    // AppState), so on the error path we must tear BOTH down — ExecService first
    // (its loops use the agent transport), then `agent.shutdown()` — so a failed
    // write does not leak the exec loops or the agent/network. The file is removed
    // again in the shutdown tail.
    let port_file = config.data_dir.join("api.port");
    if let Err(e) = tokio::fs::write(&port_file, actual_api_addr.to_string()).await {
        exec_service.shutdown().await;
        agent.shutdown().await;
        return Err(anyhow::Error::new(e).context("failed to write api.port"));
    }
    tracing::info!(
        "API server listening on {actual_api_addr} (port file: {})",
        port_file.display()
    );

    // Fix C (Issue #110 Phase 2): collect every server-owned background-task
    // `JoinHandle` spawned in the startup path so the shutdown tail can
    // grace-await then abort any straggler. (Agent-internal and ExecService tasks
    // are owned by the Agent/ExecService and stopped by their own `shutdown()`
    // calls in the shutdown tail — issue #116 — not collected here.)
    let mut bg_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    let existing_group_ids: Vec<String> = {
        let groups = state.named_groups.read().await;
        groups.keys().cloned().collect()
    };
    for group_id in existing_group_ids {
        // The metadata + public-message listeners spawned here self-register in
        // `state.group_metadata_tasks` / `state.public_message_tasks`; the
        // shutdown tail drains and aborts those maps directly (Fix C), so there
        // is nothing to collect into `bg_tasks` from this call.
        ensure_named_group_listeners(Arc::clone(&state), &group_id).await;
    }

    // P0-1: subscribe to the global group discovery topic so remote public
    // groups populate the local card cache without manual import.
    bg_tasks.extend(spawn_global_discovery_listener(Arc::clone(&state)).await);
    // Phase C.2: load persisted shard subscriptions and re-subscribe with
    // staggered jitter to avoid anti-entropy storms.
    bg_tasks.extend(spawn_directory_resubscribe(Arc::clone(&state)).await);
    // Restart-amnesia fix: load the persisted task-list/kv-store subscription
    // manifest now (before REST handlers can mutate it) — the actual
    // re-create/re-join runs after `join_network` in the join task below.
    crdt_subscriptions::load(&state).await;
    // Phase C.2: subscribe inbound direct messages for the
    // ListedToContacts pairwise sync channel.
    bg_tasks.extend(spawn_listed_to_contacts_listener(Arc::clone(&state)).await);
    // Phase E: subscribe to a stable global SignedPublic message fallback so
    // first messages are not dependent on a brand-new per-group topic tree.
    bg_tasks.extend(spawn_global_public_message_listener(Arc::clone(&state)).await);

    // Re-publish our own discoverable group cards after startup so late joiners
    // pick them up.
    let discoverable_ids: Vec<String> = {
        let groups = state.named_groups.read().await;
        groups
            .iter()
            .filter(|(_, info)| {
                info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
            })
            .map(|(id, _)| id.clone())
            .collect()
    };
    let republish_interval_secs = config.group_card_republish_interval_secs.unwrap_or(300);
    if republish_interval_secs > 0 {
        let state_for_republish = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            // First publish after a short warmup so the gossip mesh has a chance
            // to form. Then republish periodically so late joiners also see cards.
            // Without this, a peer that starts after another daemon published
            // would miss the initial card.
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut shutdown = state_for_republish.shutdown_notify.subscribe();
            loop {
                let current_ids: Vec<String> = {
                    let groups = state_for_republish.named_groups.read().await;
                    groups
                        .iter()
                        .filter(|(_, info)| {
                            info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
                        })
                        .map(|(id, _)| id.clone())
                        .collect()
                };
                for id in current_ids {
                    publish_group_card_to_discovery(&state_for_republish, &id).await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(republish_interval_secs)) => {}
                    _ = shutdown.changed() => break,
                }
            }
        }));
    }
    // Consume the pre-computed list to avoid the dead-warning.
    let _ = discoverable_ids;

    // Join network in background — API is available immediately
    let join_agent = Arc::clone(&agent);
    let rendezvous_enabled = config.rendezvous_enabled;
    let rendezvous_validity_ms = config.rendezvous_validity_ms;

    // Start the DM inbox as soon as join_network has created the gossip
    // runtime. join_network may keep working through slow bootstrap/cache
    // peers for a long time; the daemon must still be able to receive gossip
    // DMs once `/agent/card` advertises a KEM key.
    let dm_inbox_agent = Arc::clone(&agent);
    let dm_inbox_kem = Arc::clone(&agent_kem_keypair);
    let dm_inbox_exec_route_tx = exec_dm_tx.clone();
    let dm_inbox_group_public_route_tx = group_public_dm_tx.clone();
    let dm_inbox_kv_store_delta_route_tx = kv_store_delta_dm_tx.clone();
    bg_tasks.push(tokio::spawn(start_dm_inbox_when_gossip_ready(
        dm_inbox_agent,
        dm_inbox_kem,
        dm_inbox_exec_route_tx,
        dm_inbox_group_public_route_tx,
        dm_inbox_kv_store_delta_route_tx,
    )));

    // Restart-amnesia fix: re-register every persisted task-list/kv-store
    // subscription via the same Agent create/join paths the REST handlers
    // use, so the topic subscription + empty-replica state-request happen
    // and offline mutations arrive from peers.
    //
    // Runs CONCURRENTLY with join_network (issue #238): rehydration needs
    // only the local gossip runtime, which exists at Agent build time —
    // subscriptions register locally and the per-CRDT state-request tail
    // keeps re-requesting until peers appear, so nothing here depends on
    // the mesh being formed. Sequencing rehydration AFTER join_network
    // wedged the daemon's OWN stores (restored from local snapshots, no
    // network needed) behind an unreachable bootstrap peer's full dial
    // schedule (~70s of "store not found").
    let crdt_rehydrate_state = Arc::clone(&state);
    bg_tasks.push(tokio::spawn(async move {
        crdt_subscriptions::rehydrate(crdt_rehydrate_state).await;
    }));
    bg_tasks.push(tokio::spawn(async move {
        match join_agent.join_network().await {
            Ok(()) => {
                tracing::info!("Network joined");
                if rendezvous_enabled {
                    if let Err(e) = join_agent.advertise_identity(rendezvous_validity_ms).await {
                        tracing::warn!("Initial rendezvous advertisement failed: {e}");
                    } else {
                        tracing::info!("Rendezvous advertisement published");
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to join network: {e}");
            }
        }
    }));

    let self_published_release_manifests =
        Arc::new(Mutex::new(SelfPublishedReleaseManifests::default()));

    // Reclaim upgrade debris left by previous failed/interrupted attempts:
    // orphaned `.x0x-upgrade-*` temp dirs and `*.x0xold-*` sidelined binaries.
    // Runs UNCONDITIONALLY (deliberately NOT gated on self_update_enabled): this
    // is the disk-fill safety net from the Windows self-update fix and must clean
    // a machine even when self-update is disabled. It only matches x0x-specific
    // artifact patterns next to the binary, so it is a harmless no-op for an
    // embedder (which never creates such artifacts) — no host files can match.
    bg_tasks.push(tokio::spawn(async {
        let removed = tokio::task::spawn_blocking(|| {
            let exe = x0x::upgrade::apply::current_binary_path().ok()?;
            let dir = exe.parent()?.to_path_buf();
            Some(x0x::upgrade::sweep_stale_upgrade_artifacts(
                &dir,
                Duration::from_secs(3600),
            ))
        })
        .await
        .ok()
        .flatten()
        .unwrap_or(0);
        if removed > 0 {
            tracing::info!(removed, "Reclaimed stale upgrade artifacts at startup");
        }
    }));

    // Gossip-based release subscription (primary update mechanism). This
    // listener can download + install + restart, so it is gated on
    // `self_update_enabled` — embedders never replace the host binary.
    if self_update_enabled && config.update.enabled && config.update.gossip_updates {
        let update_config = config.update.clone();
        let agent_for_gossip = Arc::clone(&state.agent);
        let data_dir = config.data_dir.clone();
        let upgrade_apply_lock = Arc::clone(&state.upgrade_apply_lock);
        let self_published_for_gossip = Arc::clone(&self_published_release_manifests);
        bg_tasks.push(tokio::spawn(async move {
            run_gossip_update_listener(
                agent_for_gossip,
                update_config,
                data_dir,
                upgrade_apply_lock,
                self_published_for_gossip,
            )
            .await;
        }));
    }

    // Broadcast current manifest to gossip after joining the network.
    // Ensures nodes that missed the initial gossip window can still receive it.
    // Also syncs SKILL.md with the current manifest.
    // Fix D (Issue #110 Phase 2): gated on `self_update_enabled` — this fetches a
    // GitHub release manifest and writes SKILL.md, both updater side-effects an
    // embedder with self-update off must not perform. The daemon keeps it on
    // (self_update_enabled = config.update_enabled()), so behaviour is unchanged.
    if self_update_enabled && config.update.enabled {
        let agent_for_broadcast = Arc::clone(&state.agent);
        let update_config = config.update.clone();
        let data_dir_for_broadcast = config.data_dir.clone();
        let self_published_for_broadcast = Arc::clone(&self_published_release_manifests);
        bg_tasks.push(tokio::spawn(async move {
            broadcast_current_manifest(
                &agent_for_broadcast,
                &update_config.repo,
                update_config.include_prereleases,
                &data_dir_for_broadcast,
                self_published_for_broadcast,
            )
            .await;
        }));
    }

    // GitHub fallback poll (safety net, default every 48h). Install/restart
    // capable, so gated on `self_update_enabled` (embedders opt out).
    if self_update_enabled
        && config.update.enabled
        && config.update.fallback_check_interval_minutes > 0
    {
        let update_config = config.update.clone();
        let agent_for_poll = Arc::clone(&state.agent);
        let data_dir_for_poll = config.data_dir.clone();
        let upgrade_apply_lock = Arc::clone(&state.upgrade_apply_lock);
        let self_published_for_poll = Arc::clone(&self_published_release_manifests);
        bg_tasks.push(tokio::spawn(async move {
            run_fallback_github_poll(
                agent_for_poll,
                update_config,
                data_dir_for_poll,
                upgrade_apply_lock,
                self_published_for_poll,
            )
            .await;
        }));
    }

    // Background rendezvous re-advertisement (re-advertise every validity_ms / 2)
    if config.rendezvous_enabled && config.rendezvous_validity_ms > 0 {
        let rendezvous_agent = Arc::clone(&state.agent);
        let validity_ms = config.rendezvous_validity_ms;
        let mut shutdown_rx = state.shutdown_notify.subscribe();
        bg_tasks.push(tokio::spawn(async move {
            let interval_secs = (validity_ms / 2).max(60_000) / 1000;
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.tick().await; // skip immediate tick (already advertised at startup)
            loop {
                // Watch shutdown so teardown is prompt (Fix C): without this the
                // loop would only stop when aborted at the end of the grace window.
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = ticker.tick() => {}
                }
                if let Err(e) = rendezvous_agent.advertise_identity(validity_ms).await {
                    tracing::warn!("Periodic rendezvous re-advertisement failed: {e}");
                } else {
                    tracing::debug!("Rendezvous re-advertisement published");
                }
            }
        }));
    }

    // Background connectivity snapshot logger — writes an ant-quic NodeStatus
    // summary line every 60 seconds at target "x0x::diag::connectivity". This
    // gives journalctl a tick-by-tick record of UPnP state, external address
    // observations, direct vs relayed counts, and hole-punch success rate so
    // long-running deployments have a time series to diagnose from without
    // polling the HTTP diagnostics endpoint.
    {
        let diag_state = Arc::clone(&state);
        let mut shutdown_rx = state.shutdown_notify.subscribe();
        bg_tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.tick().await; // skip the immediate tick — node is still warming up
            loop {
                // Watch shutdown so teardown is prompt (Fix C).
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = ticker.tick() => {}
                }
                let Some(network) = diag_state.agent.network() else {
                    continue;
                };
                let Some(ns) = network.node_status().await else {
                    continue;
                };
                tracing::info!(
                    target: "x0x::diag::connectivity",
                    nat_type = ?ns.nat_type,
                    can_receive_direct = ?ns.can_receive_direct,
                    has_global_address = ns.has_global_address,
                    external_addrs = ns.external_addrs.len(),
                    port_mapping_active = ns.port_mapping_active,
                    port_mapping_addr = ?ns.port_mapping_addr,
                    mdns_browsing = ns.mdns_browsing,
                    mdns_advertising = ns.mdns_advertising,
                    mdns_discovered = ns.mdns_discovered_peers,
                    connected_peers = ns.connected_peers,
                    direct_connections = ns.direct_connections,
                    relayed_connections = ns.relayed_connections,
                    hole_punch_success_rate = ns.hole_punch_success_rate,
                    avg_rtt_ms = ns.avg_rtt.as_millis() as u64,
                    uptime_s = ns.uptime.as_secs(),
                    "connectivity snapshot"
                );
            }
        }));
    }

    // Background file-message listener — processes FileMessage on the direct channel
    {
        let file_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            if let Err(e) = tokio::fs::create_dir_all(&file_state.transfers_dir).await {
                tracing::error!("Failed to create transfers dir: {e}");
            }
            let mut rx = file_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(file_msg) = serde_json::from_slice::<x0x::files::FileMessage>(&msg.payload)
                else {
                    continue; // not a file message
                };
                handle_file_message(&file_state, &msg.sender, file_msg).await;
            }
        }));
    }

    // Background join-result listener — joiner-initiated recovery path for
    // fresh TreeKEM members that miss the anchor's opportunistic MemberAdded push.
    {
        let join_result_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = join_result_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(join_msg) = serde_json::from_slice::<JoinResultMessage>(&msg.payload) else {
                    continue;
                };
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "direct_classified_join_result",
                    sender = %hex::encode(msg.sender.as_bytes()),
                    len = msg.payload.len(),
                    verified = msg.verified,
                );
                handle_join_result_message(&join_result_state, &msg.sender, join_msg).await;
            }
        }));
    }

    // Background TreeKEM Welcome blob listener — pull-based bulk delivery for
    // oversized Welcome payloads referenced by named-group metadata events.
    {
        let welcome_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = welcome_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(welcome_msg) = serde_json::from_slice::<WelcomeBlobMessage>(&msg.payload)
                else {
                    continue;
                };
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "direct_classified_welcome_blob",
                    sender = %hex::encode(msg.sender.as_bytes()),
                    len = msg.payload.len(),
                    verified = msg.verified,
                );
                handle_welcome_blob_message(&welcome_state, &msg.sender, welcome_msg).await;
            }
        }));
    }

    // Background TreeKEM catch-up listener — explicit anti-entropy for
    // order-sensitive membership events that arrive before local readiness or
    // ahead of the local epoch/state frontier.
    {
        let catchup_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = catchup_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                if let Ok(request) = serde_json::from_slice::<TreeKemCatchupRequest>(&msg.payload) {
                    if request.message_type == "treekem_catchup_request" {
                        handle_treekem_catchup_request(
                            &catchup_state,
                            &msg.sender,
                            msg.verified,
                            request,
                        )
                        .await;
                    }
                    continue;
                }
                if let Ok(response) = serde_json::from_slice::<TreeKemCatchupResponse>(&msg.payload)
                {
                    if response.message_type == "treekem_catchup_response" {
                        handle_treekem_catchup_response(
                            &catchup_state,
                            &msg.sender,
                            msg.verified,
                            response,
                        )
                        .await;
                    }
                }
            }
        }));
    }

    // Background named-group metadata listener on the direct channel — applies
    // authority-authored review commits (approve / reject) that are
    // direct-delivered to a requester before they are grafted into the
    // metadata topic's gossip mesh (see `spawn_named_group_event_delivery`).
    // This mirrors the per-group metadata topic-subscription apply loop; the
    // shared apply handler re-validates the signed commit, enforces the same
    // authorization checks, and is idempotent, so applying via both the direct
    // and gossip channels is safe.
    {
        let meta_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = meta_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload)
                else {
                    continue; // not a named-group metadata event
                };
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "direct_classified_metadata_event",
                    sender = %hex::encode(msg.sender.as_bytes()),
                    len = msg.payload.len(),
                    verified = msg.verified,
                    event = named_group_metadata_event_kind(&event),
                );
                apply_named_group_metadata_event(&meta_state, event, msg.sender, msg.verified)
                    .await;
            }
        }));
    }

    // Background signed public-message listener for typed gossip-DM fallback
    // delivery. Per-group pubsub is still the primary fan-out path; this route
    // handles the same signed message when the sender additionally direct-
    // delivers it to active members.
    {
        let public_dm_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            while let Some(typed) = group_public_dm_rx.recv().await {
                if !typed.verified {
                    continue;
                }
                let Some(payload) = typed.payload.strip_prefix(GROUP_PUBLIC_MESSAGE_DM_PREFIX)
                else {
                    continue;
                };
                let Ok(msg) = serde_json::from_slice::<x0x::groups::GroupPublicMessage>(payload)
                else {
                    tracing::debug!(
                        sender = %hex::encode(typed.sender.as_bytes()),
                        "typed group-public DM payload was not a GroupPublicMessage"
                    );
                    continue;
                };
                let group_id = msg.group_id.clone();
                tracing::debug!(
                    group_id = %group_id,
                    sender = %hex::encode(typed.sender.as_bytes()),
                    "direct-delivered public group message received"
                );
                ingest_public_message(&public_dm_state, msg, &group_id).await;
            }
        }));
    }

    // Background KvStore delta listener for typed gossip-DM fallback delivery.
    // Store pub/sub remains the primary path; this side channel gives joined
    // peers a reliable replay of the same CRDT delta when the topic mesh is
    // late or congested. Peers that have not joined the store simply ignore it.
    {
        let kv_delta_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            while let Some(typed) = kv_store_delta_dm_rx.recv().await {
                if !typed.verified {
                    continue;
                }
                let Some(payload) = typed.payload.strip_prefix(KV_STORE_DELTA_DM_PREFIX) else {
                    continue;
                };
                let Ok(delta_msg) = serde_json::from_slice::<KvStoreDirectDelta>(payload) else {
                    tracing::debug!(
                        sender = %hex::encode(typed.sender.as_bytes()),
                        "typed kv-store DM payload was not a KvStoreDirectDelta"
                    );
                    continue;
                };
                apply_direct_kv_store_delta(&kv_delta_state, typed.sender, delta_msg).await;
            }
        }));
    }

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/agent", get(agent_info))
        .route("/introduction", get(introduction))
        .route("/agent/card", get(get_agent_card))
        .route("/.well-known/agent-card.json", get(get_a2a_agent_card))
        .route("/agent/card/import", post(import_agent_card))
        .route("/agent/sign", post(agent_sign))
        .route("/agent/verify", post(agent_verify))
        .route("/identity/revoke", post(identity_revoke))
        .route("/identity/revocations", get(identity_revocations))
        .route("/announce", post(announce_identity))
        .route("/peers", get(peers))
        .route("/network/status", get(network_status))
        .route("/publish", post(publish))
        .route("/subscribe", post(subscribe))
        .route("/subscribe/:id", delete(unsubscribe))
        .route("/events", get(events_sse))
        .route("/presence", get(presence))
        .route("/presence/online", get(presence_online))
        .route("/presence/foaf", get(presence_foaf))
        .route("/presence/find/:id", get(presence_find))
        .route("/presence/status/:id", get(presence_status))
        .route("/presence/events", get(presence_events))
        .route("/agents/discovered", get(discovered_agents))
        .route("/agents/discovered/:agent_id", get(discovered_agent))
        .route("/agents/:agent_id/machine", get(machine_for_agent_handler))
        .route("/machines/discovered", get(discovered_machines))
        .route("/machines/discovered/:machine_id", get(discovered_machine))
        .route("/machines/connect", post(connect_machine))
        .route("/users/:user_id/agents", get(agents_by_user_handler))
        .route("/users/:user_id/machines", get(machines_by_user_handler))
        .route("/agent/user-id", get(agent_user_id_handler))
        .route("/contacts", get(list_contacts))
        .route("/contacts", post(add_contact))
        .route("/contacts/trust", post(quick_trust))
        .route("/contacts/:agent_id", patch(update_contact))
        .route("/contacts/:agent_id", delete(delete_contact))
        .route(
            "/contacts/:agent_id/machines",
            get(list_machines).post(add_machine),
        )
        .route(
            "/contacts/:agent_id/machines/:machine_id",
            delete(delete_machine),
        )
        .route("/task-lists", get(list_task_lists))
        .route("/task-lists", post(create_task_list))
        .route("/task-lists/:id/tasks", get(list_tasks))
        .route("/task-lists/:id/tasks", post(add_task))
        .route("/task-lists/:id/tasks/:tid", patch(update_task))
        // Named group endpoints
        .route("/groups", post(create_named_group))
        .route("/groups", get(list_named_groups))
        // Static-prefix routes BEFORE /groups/:id so axum matches them first.
        .route("/groups/discover", get(discover_groups))
        // Phase C.2: shard discovery + nearby + subscription management.
        .route("/groups/discover/nearby", get(discover_groups_nearby))
        .route(
            "/groups/discover/subscriptions",
            get(list_discovery_subscriptions),
        )
        .route(
            "/groups/discover/subscribe",
            post(create_discovery_subscription),
        )
        .route(
            "/groups/discover/subscribe/:kind/:shard",
            delete(delete_discovery_subscription),
        )
        .route("/groups/cards/import", post(import_group_card))
        .route("/groups/cards/:id", get(get_group_card))
        .route("/groups/join", post(join_group_via_invite))
        .route("/groups/:id", get(get_named_group))
        .route("/groups/:id", patch(update_named_group))
        .route("/groups/:id/policy", patch(update_group_policy))
        .route("/groups/:id/members", get(get_named_group_members))
        .route("/groups/:id/members", post(add_named_group_member))
        .route(
            "/groups/:id/members/:agent_id",
            delete(remove_named_group_member),
        )
        .route(
            "/groups/:id/members/:agent_id/role",
            patch(update_member_role),
        )
        .route("/groups/:id/ban/:agent_id", post(ban_group_member))
        .route("/groups/:id/ban/:agent_id", delete(unban_group_member))
        .route("/groups/:id/requests", get(list_join_requests))
        .route("/groups/:id/requests", post(create_join_request))
        .route(
            "/groups/:id/requests/:request_id/approve",
            post(approve_join_request),
        )
        .route(
            "/groups/:id/requests/:request_id/reject",
            post(reject_join_request),
        )
        .route(
            "/groups/:id/requests/:request_id",
            delete(cancel_join_request),
        )
        // Phase D.2 — cross-daemon secure encrypt/decrypt.
        .route("/groups/:id/secure/encrypt", post(secure_group_encrypt))
        .route("/groups/:id/secure/decrypt", post(secure_group_decrypt))
        .route("/groups/:id/secure/reseal", post(secure_group_reseal))
        .route(
            "/groups/secure/open-envelope",
            post(secure_open_envelope_adversarial),
        )
        // Phase E: public-group messaging.
        .route("/groups/:id/send", post(send_group_public_message))
        .route("/groups/:id/messages", get(get_group_public_messages))
        .route("/groups/:id/invite", post(create_group_invite))
        .route("/groups/:id/display-name", put(set_group_display_name))
        // Phase D.3 — state-commit chain endpoints.
        .route("/groups/:id/state", get(get_group_state))
        .route("/groups/:id/state/commits", get(get_group_state_commits))
        .route("/groups/:id/state/seal", post(seal_group_state))
        .route("/groups/:id/state/withdraw", post(withdraw_group_state))
        .route("/groups/:id", delete(leave_group))
        // KvStore endpoints
        .route("/stores", get(list_kv_stores))
        .route("/stores", post(create_kv_store))
        .route("/stores/:id/join", post(join_kv_store))
        .route("/stores/:id/keys", get(list_kv_keys))
        .route("/stores/:id/:key", get(get_kv_value))
        .route("/stores/:id/:key", put(put_kv_value))
        .route("/stores/:id/:key", delete(delete_kv_value))
        // Direct messaging endpoints
        .route("/agents/connect", post(connect_agent))
        .route("/direct/send", post(direct_send))
        .route("/direct/connections", get(direct_connections))
        .route("/direct/events", get(direct_events_sse))
        // MLS group encryption endpoints
        .route("/mls/groups", post(create_mls_group))
        .route("/mls/groups", get(list_mls_groups))
        .route("/mls/groups/:id", get(get_mls_group))
        .route("/mls/groups/:id/members", post(add_mls_member))
        .route(
            "/mls/groups/:id/members/:agent_id",
            delete(remove_mls_member),
        )
        .route("/mls/groups/:id/encrypt", post(mls_encrypt))
        .route("/mls/groups/:id/decrypt", post(mls_decrypt))
        // Agent discovery & connectivity
        .route("/agents/find/:agent_id", post(find_agent))
        .route("/agents/reachability/:agent_id", get(agent_reachability))
        // Contact trust extensions
        .route("/contacts/:agent_id/revoke", post(revoke_contact))
        .route("/contacts/:agent_id/revocations", get(list_revocations))
        .route(
            "/contacts/:agent_id/machines/:machine_id/pin",
            post(pin_machine).delete(unpin_machine),
        )
        // Trust evaluation
        .route("/trust/evaluate", post(evaluate_trust))
        // MLS welcome
        .route("/mls/groups/:id/welcome", post(create_mls_welcome))
        // Upgrade
        .route("/upgrade", get(check_upgrade))
        .route("/upgrade/apply", post(apply_upgrade))
        // Network diagnostics
        .route("/network/bootstrap-cache", get(bootstrap_cache_stats))
        .route("/diagnostics/connectivity", get(connectivity_diagnostics))
        .route("/diagnostics/ack", get(ack_diagnostics))
        .route("/diagnostics/gossip", get(gossip_diagnostics))
        .route("/diagnostics/dm", get(dm_diagnostics))
        .route("/diagnostics/groups", get(groups_diagnostics))
        .route("/diagnostics/exec", get(exec_diagnostics))
        .route("/diagnostics/connect", get(connect_diagnostics_handler))
        .route("/diagnostics/ws", get(ws_diagnostics))
        .route("/exec/run", post(exec_run))
        .route("/exec/cancel", post(exec_cancel))
        .route("/exec/sessions", get(exec_sessions))
        // Tailnet forwarding (#132 T6)
        .route("/forwards", post(forward_add).get(forward_list))
        .route("/forwards/:local_addr", delete(forward_remove))
        .route("/streams", get(streams_diagnostics))
        // Peer observability (ant-quic 0.27.1/0.27.2 surface)
        .route("/peers/:peer_id/probe", post(probe_peer_handler))
        .route("/peers/:peer_id/health", get(peer_health_handler))
        .route("/peers/events", get(peer_events_handler))
        // WebSocket endpoints
        .route("/ws", get(ws_handler))
        .route("/ws/direct", get(ws_direct_handler))
        .route("/ws/sessions", get(ws_sessions))
        .route("/shutdown", post(shutdown_handler))
        // File transfer endpoints
        .route("/files/send", post(file_send_handler))
        .route("/files/transfers", get(file_transfers_handler))
        .route("/files/transfers/:id", get(file_transfer_status_handler))
        .route("/files/accept/:id", post(file_accept_handler))
        .route("/files/reject/:id", post(file_reject_handler))
        // Constitution
        .route("/constitution", get(get_constitution))
        .route("/constitution/json", get(get_constitution_json))
        // Embedded GUI
        .route("/gui", get(serve_gui))
        .route("/gui/", get(serve_gui))
        // Session-token exchange (#127 / WS1.6): durable bearer → short-lived
        // browser session token, the only kind valid in ?token= query strings.
        .route("/auth/session", post(auth::create_session))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1 MB
        .layer({
            // Restrict CORS to exact loopback origins only.
            // The daemon API is a local control plane — external origins must not access it.
            use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin};
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin, _| {
                    auth::is_allowed_loopback_origin(origin)
                }))
                .allow_methods(AllowMethods::any())
                .allow_headers(AllowHeaders::any())
        })
        // Bearer-token authentication: all control-plane endpoints.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));

    // Note: the `api.port` advertisement is written above (Fix A), before any
    // background task is spawned, so a failure there leaves nothing to tear down.

    // Lifecycle: a CancellationToken drives library-initiated shutdown
    // (ServerHandle::shutdown / Drop). The mpsc `/shutdown` HTTP path still
    // works — the supervisor selects on both. Ctrl-C is deliberately NOT
    // handled here: a library must not steal the host's signal. The daemon
    // binary installs its own Ctrl-C handler around `ServerHandle::wait`.
    let cancel = tokio_util::sync::CancellationToken::new();
    let supervisor_cancel = cancel.clone();

    let task = tokio::spawn(async move {
        let mut server_shutdown_rx = state.shutdown_notify.subscribe();
        let mut server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = server_shutdown_rx.changed().await;
                })
                .await
        });

        // Fix B (Issue #110 Phase 2): include the axum server `JoinHandle` in the
        // select so that if the HTTP task ends on its own (panic / bind loss /
        // Err) the supervisor wakes immediately instead of waiting for an external
        // shutdown signal. The result is still drained and propagated below.
        // When the select observes the axum task ending on its own, capture its
        // result here so it can be propagated out of the supervisor — an Err or a
        // panic (JoinError) must surface from `wait()`/`shutdown_and_wait()`. A
        // clean self-requested graceful stop stays `Ok(())`.
        let mut server_result: Option<anyhow::Result<()>> = None;
        tokio::select! {
            _ = supervisor_cancel.cancelled() => {
                tracing::info!("Received shutdown request (cancellation)");
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Received API shutdown request");
            }
            res = &mut server => {
                server_result = Some(match res {
                    Ok(Ok(())) => {
                        tracing::info!("API server task ended on its own");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        tracing::error!("API server exited with error: {e}");
                        Err(anyhow::Error::new(e).context("API server error"))
                    }
                    Err(e) => {
                        tracing::error!("API server task failed: {e}");
                        Err(anyhow::Error::new(e).context("API server task failed"))
                    }
                });
            }
        }

        // Tell every `shutdown_notify`-watching loop (and the axum graceful
        // shutdown future) to stop.
        let _ = state.shutdown_notify.send(true);

        // Drain the axum server result and propagate any failure. If the select
        // already observed it ending, `server` was consumed there and its result
        // captured above; otherwise await it (with a bound) and propagate.
        let server_result: anyhow::Result<()> = match server_result {
            Some(res) => res,
            None => match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(Ok(Err(e))) => Err(anyhow::Error::new(e).context("API server error")),
                Ok(Err(e)) => Err(anyhow::Error::new(e).context("API server task failed")),
                Err(_) => {
                    tracing::warn!(
                        "API server did not shut down within 2s; aborting lingering connections"
                    );
                    server.abort();
                    let _ = server.await;
                    Ok(())
                }
            },
        };

        // Fix C (Issue #110 Phase 2 + 2b): tear down the server-owned tasks, the
        // ExecService loops, the Agent listeners, and the QUIC node so that when
        // this supervisor returns, the HTTP/SSE server, the server-owned
        // background tasks, the ExecService loops, the Agent-internal listeners,
        // the gossip runtime, and the QUIC NetworkNode are all stopped/closed.
        //
        // 0. `ExecService::shutdown()` first (issue #116): stop the exec inbound,
        //    peer-lifecycle, and session-idle loops while the Agent transport is
        //    still alive, so in-flight sessions can cancel cleanly before the
        //    network goes away.
        state.exec_service.shutdown().await;
        // 0b. Forwarder listeners + inbound consumer (issue #132): stop
        //     accepting/bridging while the Agent transport is still alive.
        if let Some(forwarder) = &state.forward_service {
            forwarder.shutdown();
        }
        // 1. `Agent::begin_shutdown()` (issue #116 Codex finding 1): cancel the
        //    Agent's shutdown token and close its tracked-task registry NOW,
        //    BEFORE draining the server bg_tasks. A still-bootstrapping
        //    `join_network` is one of those bg_tasks; cancelling first makes its
        //    in-flight `start_identity_heartbeat`/`start_discovery_cache_reaper`/
        //    presence-start/`start_capability_advert_service`/delayed-reannounce
        //    no-op (each checks `is_cancelled()` under its handle lock), so it
        //    cannot leak a dedicated-handle service past `agent.shutdown()`.
        state.agent.begin_shutdown();
        // 2. Grace-await then abort every server background task, INCLUDING
        //    join_network. Tasks tracked in the AppState handle maps (metadata /
        //    public-message / directory shard listeners spawned at startup AND
        //    by request handlers) are included so nothing leaks. The grace
        //    window is a single bounded 2s budget across all tasks (not 2s each)
        //    so shutdown stays prompt regardless of task count; any task still
        //    running after the window is aborted. A cancelled/aborted task
        //    returns a `JoinError`; that is expected, never unwrap it. Draining
        //    here (after begin_shutdown, before agent.shutdown) guarantees
        //    join_network has fully stopped before the Agent stops are run.
        let mut bg_tasks = bg_tasks;
        bg_tasks
            .extend(std::mem::take(&mut *state.group_metadata_tasks.write().await).into_values());
        bg_tasks
            .extend(std::mem::take(&mut *state.public_message_tasks.write().await).into_values());
        bg_tasks.extend(std::mem::take(&mut *state.directory_tasks.write().await).into_values());
        // Keep abort handles so stragglers can be aborted after the grace window.
        // Fix C (issue #116): on the timeout path, AWAIT the aborts too — keep the
        // JoinHandles owned by `join` (select! over `&mut join` vs the 2s sleep)
        // so that after aborting we `join.await` the remainder. Without this, the
        // "join_network fully stopped before agent.shutdown()" guarantee would
        // only hold on the non-timeout path; now it holds on BOTH. A cancelled/
        // aborted task yields Err(JoinError) — expected, never unwrapped.
        let abort_handles: Vec<tokio::task::AbortHandle> =
            bg_tasks.iter().map(|h| h.abort_handle()).collect();
        let mut join = futures::future::join_all(bg_tasks);
        tokio::select! {
            _results = &mut join => {}
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                tracing::warn!("background tasks did not stop within grace; aborting stragglers");
                for handle in &abort_handles {
                    handle.abort();
                }
                let _results: Vec<Result<(), tokio::task::JoinError>> = join.await;
            }
        }
        // 3. Now that join_network is stopped (and the token cancelled so any
        //    in-flight start_* no-ops), tear the Agent down: stop heartbeat /
        //    reaper / DM-inbox / advert / presence, drain the Agent's own
        //    tracked listener tasks, shut down the gossip runtime, and shut down
        //    the QUIC NetworkNode. (The OS frees the UDP socket on process exit;
        //    ant-quic does not release it in-process — embedders that restart
        //    should use an ephemeral QUIC port.)
        state.agent.shutdown().await;

        // Clean up port file on shutdown (kept after task teardown so the
        // existing ordering — port advertisement removed last — is preserved).
        let _ = tokio::fs::remove_file(&port_file).await;
        tracing::info!("Shutdown complete");
        server_result
    });

    Ok(ServerHandle {
        local_addr: actual_api_addr,
        cancel,
        task: Some(task),
    })
}

pub async fn list_instances() -> Result<()> {
    let data_base = dirs::data_dir().context("cannot determine data directory")?;

    // Collect candidate directories: x0x and x0x-*
    let mut instances: Vec<(String, PathBuf)> = Vec::new();

    let default_port_file = data_base.join("x0x").join("api.port");
    if default_port_file.exists() {
        instances.push(("(default)".to_string(), default_port_file));
    }

    if let Ok(mut entries) = tokio::fs::read_dir(&data_base).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(instance) = name_str.strip_prefix("x0x-") {
                let port_file = entry.path().join("api.port");
                if port_file.exists() {
                    instances.push((instance.to_string(), port_file));
                }
            }
        }
    }

    if instances.is_empty() {
        println!("No running instances found.");
        return Ok(());
    }

    let name_width = instances
        .iter()
        .map(|(n, _)| n.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!("{:<name_width$}  {:<21}  {:<10}", "NAME", "API", "STATUS");
    for (name, port_file) in &instances {
        let addr = tokio::fs::read_to_string(port_file)
            .await
            .unwrap_or_default();
        let addr = addr.trim().to_string();

        let status = if !addr.is_empty() {
            match reqwest::Client::new()
                .get(format!("http://{addr}/health"))
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => "running",
                _ => "stale",
            }
        } else {
            "stale"
        };
        println!("{:<name_width$}  {:<21}  {:<10}", name, addr, status);
    }
    Ok(())
}

async fn start_dm_inbox_when_gossip_ready(
    agent: Arc<x0x::Agent>,
    kem_keypair: Arc<x0x::groups::kem_envelope::AgentKemKeypair>,
    exec_route_tx: mpsc::Sender<x0x::dm_inbox::DmTypedPayload>,
    group_public_route_tx: mpsc::Sender<x0x::dm_inbox::DmTypedPayload>,
    kv_store_delta_route_tx: mpsc::Sender<x0x::dm_inbox::DmTypedPayload>,
) {
    for attempt in 1..=DM_INBOX_START_MAX_ATTEMPTS {
        let dm_inbox_config = x0x::dm_inbox::DmInboxConfig::default()
            .with_typed_payload_route(x0x::exec::EXEC_DM_PREFIX, exec_route_tx.clone())
            .with_typed_payload_route(
                GROUP_PUBLIC_MESSAGE_DM_PREFIX,
                group_public_route_tx.clone(),
            )
            .with_typed_payload_route(KV_STORE_DELTA_DM_PREFIX, kv_store_delta_route_tx.clone());
        match agent
            .start_dm_inbox(Arc::clone(&kem_keypair), dm_inbox_config)
            .await
        {
            Ok(()) => {
                if let Err(e) = agent.start_capability_advert_service().await {
                    tracing::warn!(
                        attempt,
                        "Capability advert service not ready after DM inbox start: {e}"
                    );
                }
                tracing::info!(
                    attempt,
                    "DM inbox service started independently of network join completion"
                );
                return;
            }
            Err(e) if attempt < DM_INBOX_START_MAX_ATTEMPTS => {
                tracing::debug!(attempt, "DM inbox not ready yet: {e}");
                tokio::time::sleep(DM_INBOX_START_RETRY_DELAY).await;
            }
            Err(e) => {
                tracing::warn!(
                    attempts = DM_INBOX_START_MAX_ATTEMPTS,
                    "Failed to start DM inbox service: {e}"
                );
                return;
            }
        }
    }
}

/// Parse a 64-character hex string into an AgentId.
fn parse_agent_id_hex(hex_str: &str) -> Result<AgentId, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(AgentId(arr))
}

/// Parse a 64-character hex string into a MachineId.
fn parse_machine_id_hex(hex_str: &str) -> Result<MachineId, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(MachineId(arr))
}

/// Build a uniform `{ "ok": false, "error": <msg> }` JSON error response paired
/// with the given status code. Used by handlers in place of hand-rolled literals.
fn api_error(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": msg.into() })),
    )
}

/// `400 Bad Request` error response.
fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    api_error(StatusCode::BAD_REQUEST, msg)
}

/// `404 Not Found` error response.
fn not_found(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    api_error(StatusCode::NOT_FOUND, msg)
}

/// `403 Forbidden` error response.
fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    api_error(StatusCode::FORBIDDEN, msg)
}

/// Decode a base64-encoded payload from a request field.
fn decode_base64_payload(encoded: &str) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    BASE64
        .decode(encoded)
        .map_err(|e| bad_request(format!("invalid base64: {e}")))
}
