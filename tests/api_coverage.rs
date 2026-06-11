//! API coverage guardian tests.
//!
//! These tests ensure every endpoint in the ENDPOINTS registry has a corresponding
//! test, every route in x0xd is in the registry, and CLI names are unique.
//!
//! Runs in normal `cargo nextest run` — no daemon needed, no `--ignored` flag.
//! When a developer adds a new EndpointDef to ENDPOINTS, this test immediately
//! fails, forcing them to add coverage.

use std::collections::HashSet;
use x0x::api::{Method, ENDPOINTS};

#[derive(Clone, Copy)]
struct CoveredEndpoint {
    method: Method,
    path: &'static str,
    marker: &'static str,
}

macro_rules! covered {
    ($method:ident, $path:literal, $marker:ident) => {
        CoveredEndpoint {
            method: Method::$method,
            path: $path,
            marker: stringify!($marker),
        }
    };
    ($method:ident, $path:literal, $marker:literal) => {
        CoveredEndpoint {
            method: Method::$method,
            path: $path,
            marker: $marker,
        }
    };
}

/// Every endpoint (method, path) that has a marker in the test suite.
///
/// When you add a new endpoint to `src/api/mod.rs:ENDPOINTS`, you MUST add a
/// corresponding entry here AND set `marker` to the test function or external
/// probe label that exercises it.
///
/// This is deliberately manual, but the marker must exist outside this file so
/// a tuple alone cannot claim coverage.
const COVERED: &[CoveredEndpoint] = &[
    // ── Status ──────────────────────────────────────────────────────────
    covered!(Get, "/health", daemon_api_health),
    covered!(Get, "/status", daemon_api_status),
    covered!(Post, "/shutdown", daemon_api_shutdown_with_sse_client),
    // ── Identity ────────────────────────────────────────────────────────
    covered!(Get, "/agent", daemon_api_agent),
    covered!(Post, "/announce", daemon_api_announce),
    covered!(Get, "/agent/user-id", "GET /agent/user-id"),
    covered!(Get, "/agent/card", "GET /agent/card"),
    covered!(Get, "/introduction", "GET /introduction"),
    covered!(
        Post,
        "/agent/card/import",
        daemon_api_import_card_invalid_trust_level_rejected
    ),
    covered!(Post, "/agent/sign", daemon_api_agent_sign_roundtrip),
    covered!(Post, "/agent/verify", daemon_api_agent_verify_roundtrip),
    // ── Network ─────────────────────────────────────────────────────────
    covered!(Get, "/peers", daemon_api_peers),
    // ── Presence ────────────────────────────────────────────────────────
    covered!(Get, "/presence", "GET /presence"),
    covered!(Get, "/presence/online", "GET /presence/online"),
    covered!(Get, "/presence/foaf", "presence/foaf body shape"),
    covered!(Get, "/presence/find/:id", "GET /presence/find/:id"),
    covered!(Get, "/presence/status/:id", "GET /presence/status/:id"),
    covered!(Get, "/presence/events", "GET /presence/events"),
    // ── Network (cont.) ─────────────────────────────────────────────────
    covered!(Get, "/network/status", daemon_api_network_status),
    covered!(Get, "/network/bootstrap-cache", daemon_api_bootstrap_cache),
    covered!(
        Get,
        "/diagnostics/connectivity",
        daemon_api_diagnostics_connectivity
    ),
    covered!(Get, "/diagnostics/ack", daemon_api_diagnostics_ack),
    covered!(
        Get,
        "/diagnostics/gossip",
        "/diagnostics/gossip endpoint proves"
    ),
    covered!(Get, "/diagnostics/dm", daemon_api_diagnostics_dm),
    covered!(
        Get,
        "/diagnostics/groups",
        member_joined_event_propagates_to_inviter
    ),
    covered!(Get, "/diagnostics/exec", daemon_api_diagnostics_exec),
    covered!(
        Post,
        "/peers/:peer_id/probe",
        peer_probe_returns_finite_rtt_against_live_peer
    ),
    covered!(
        Get,
        "/peers/:peer_id/health",
        peer_health_snapshot_observable_for_live_peer
    ),
    covered!(
        Get,
        "/peers/events",
        peer_events_sse_emits_established_on_new_connection
    ),
    // ── Messaging ───────────────────────────────────────────────────────
    covered!(Post, "/publish", daemon_api_subscribe_publish),
    covered!(Post, "/subscribe", daemon_api_subscribe_publish),
    covered!(Delete, "/subscribe/:id", daemon_api_unsubscribe),
    covered!(Get, "/events", daemon_api_events_sse),
    // ── Discovery ───────────────────────────────────────────────────────
    covered!(Get, "/agents/discovered", daemon_api_discovered_agents),
    covered!(
        Get,
        "/agents/discovered/:agent_id",
        "GET /agents/discovered/:id"
    ),
    covered!(
        Get,
        "/agents/:agent_id/machine",
        machine_for_agent_returns_linked_endpoint
    ),
    covered!(Get, "/machines/discovered", gui_api_paths_exist_in_registry),
    covered!(
        Get,
        "/machines/discovered/:machine_id",
        gui_api_paths_exist_in_registry
    ),
    covered!(
        Get,
        "/agents/reachability/:agent_id",
        daemon_api_reachability_unknown
    ),
    covered!(
        Post,
        "/agents/find/:agent_id",
        daemon_api_find_agent_unknown
    ),
    covered!(Get, "/users/:user_id/agents", daemon_api_agents_by_user),
    covered!(
        Get,
        "/users/:user_id/machines",
        gui_api_paths_exist_in_registry
    ),
    // ── Contacts ────────────────────────────────────────────────────────
    covered!(Get, "/contacts", daemon_api_list_contacts),
    covered!(Post, "/contacts", daemon_api_add_contact),
    covered!(Post, "/contacts/trust", daemon_api_quick_trust),
    covered!(Patch, "/contacts/:agent_id", daemon_api_update_contact),
    covered!(Delete, "/contacts/:agent_id", daemon_api_delete_contact),
    covered!(
        Post,
        "/contacts/:agent_id/revoke",
        daemon_api_revoke_contact
    ),
    covered!(
        Get,
        "/contacts/:agent_id/revocations",
        daemon_api_list_revocations
    ),
    // ── Machines ────────────────────────────────────────────────────────
    covered!(Get, "/contacts/:agent_id/machines", "machines GET"),
    covered!(Post, "/contacts/:agent_id/machines", daemon_api_add_machine),
    covered!(
        Delete,
        "/contacts/:agent_id/machines/:machine_id",
        "DELETE /contacts/:id/machines/:mid"
    ),
    covered!(
        Post,
        "/contacts/:agent_id/machines/:machine_id/pin",
        daemon_api_pin_unpin_machine
    ),
    covered!(
        Delete,
        "/contacts/:agent_id/machines/:machine_id/pin",
        daemon_api_pin_unpin_machine
    ),
    // ── Trust ───────────────────────────────────────────────────────────
    covered!(Post, "/trust/evaluate", daemon_api_evaluate_trust),
    // ── Direct messaging ────────────────────────────────────────────────
    covered!(Post, "/agents/connect", daemon_api_connect_unknown),
    covered!(Post, "/machines/connect", gui_api_paths_exist_in_registry),
    covered!(Post, "/direct/send", daemon_api_direct_send_not_found),
    covered!(Get, "/direct/connections", daemon_api_direct_connections),
    covered!(Get, "/direct/events", daemon_api_direct_events_sse),
    // ── Exec ───────────────────────────────────────────────────────────
    covered!(Post, "/exec/run", daemon_api_exec_run_bad_agent_id),
    covered!(Post, "/exec/cancel", daemon_api_exec_cancel_bad_request_id),
    covered!(Get, "/exec/sessions", daemon_api_exec_sessions),
    // ── MLS groups ──────────────────────────────────────────────────────
    covered!(Post, "/mls/groups", daemon_api_create_group),
    covered!(Get, "/mls/groups", daemon_api_list_groups),
    covered!(Get, "/mls/groups/:id", daemon_api_get_group),
    covered!(Post, "/mls/groups/:id/members", daemon_api_add_member),
    covered!(
        Delete,
        "/mls/groups/:id/members/:agent_id",
        daemon_api_remove_member
    ),
    covered!(Post, "/mls/groups/:id/encrypt", daemon_api_encrypt_decrypt),
    covered!(Post, "/mls/groups/:id/decrypt", daemon_api_encrypt_decrypt),
    covered!(Post, "/mls/groups/:id/welcome", daemon_api_mls_welcome),
    // ── Named groups ────────────────────────────────────────────────────
    covered!(
        Post,
        "/groups",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(Get, "/groups", "GET /groups"),
    covered!(
        Get,
        "/groups/:id",
        d4_join_request_events_converge_via_signed_commits
    ),
    covered!(
        Get,
        "/groups/:id/members",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/members",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Delete,
        "/groups/:id/members/:agent_id",
        d4_stateful_events_converge_via_signed_commits
    ),
    // ── Phase E: public-group messaging ─────────────────────────────────
    covered!(
        Post,
        "/groups/:id/send",
        e_moderated_public_positive_cross_daemon_receive
    ),
    covered!(
        Get,
        "/groups/:id/messages",
        e_moderated_public_positive_cross_daemon_receive
    ),
    covered!(
        Post,
        "/groups/:id/invite",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/join",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Put,
        "/groups/:id/display-name",
        "PUT /groups/:id/display-name"
    ),
    covered!(
        Delete,
        "/groups/:id",
        d4_stateful_events_converge_via_signed_commits
    ),
    // ── Named groups: policy/roles/requests/discovery ───────────────────
    covered!(
        Patch,
        "/groups/:id",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Patch,
        "/groups/:id/policy",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Patch,
        "/groups/:id/members/:agent_id/role",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/ban/:agent_id",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Delete,
        "/groups/:id/ban/:agent_id",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Get,
        "/groups/:id/requests",
        d4_join_request_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/requests",
        d4_join_request_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/requests/:request_id/approve",
        d4_join_request_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/requests/:request_id/reject",
        d4_join_request_events_converge_via_signed_commits
    ),
    covered!(
        Delete,
        "/groups/:id/requests/:request_id",
        d4_join_request_events_converge_via_signed_commits
    ),
    covered!(
        Get,
        "/groups/discover",
        c2_publicdirectory_discovered_via_shard_only_nearby_witness
    ),
    // ── Phase C.2: shard discovery ──────────────────────────────────────
    covered!(
        Get,
        "/groups/discover/nearby",
        c2_publicdirectory_discovered_via_shard_only_nearby_witness
    ),
    covered!(
        Get,
        "/groups/discover/subscriptions",
        c2_publicdirectory_discovered_via_shard_only_nearby_witness
    ),
    covered!(
        Post,
        "/groups/discover/subscribe",
        c2_publicdirectory_discovered_via_shard_only_nearby_witness
    ),
    covered!(
        Delete,
        "/groups/discover/subscribe/:kind/:shard",
        "BDEL /groups/discover/subscribe/tag/$SUB_SHARD"
    ),
    covered!(
        Get,
        "/groups/cards/:id",
        c2_publicdirectory_discovered_via_shard_only_nearby_witness
    ),
    covered!(
        Post,
        "/groups/cards/import",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/secure/encrypt",
        "/groups/$GID_D2/secure/encrypt"
    ),
    covered!(
        Post,
        "/groups/:id/secure/decrypt",
        "/groups/$GID_D2_REMOTE/secure/decrypt"
    ),
    covered!(
        Post,
        "/groups/:id/secure/reseal",
        "/groups/$GID_ADV/secure/reseal"
    ),
    covered!(
        Post,
        "/groups/secure/open-envelope",
        "/groups/secure/open-envelope rejects random-bytes envelope"
    ),
    // ── Phase D.3: state-commit chain ───────────────────────────────────
    covered!(
        Get,
        "/groups/:id/state",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/state/seal",
        d4_stateful_events_converge_via_signed_commits
    ),
    covered!(
        Post,
        "/groups/:id/state/withdraw",
        c2_late_subscriber_recovers_via_digest_pull_without_republish
    ),
    // ── Task lists ──────────────────────────────────────────────────────
    covered!(Get, "/task-lists", daemon_api_list_tasks),
    covered!(Post, "/task-lists", daemon_api_create_task_list),
    covered!(Get, "/task-lists/:id/tasks", "GET /task-lists/:id/tasks"),
    covered!(Post, "/task-lists/:id/tasks", daemon_api_add_task),
    covered!(Patch, "/task-lists/:id/tasks/:tid", daemon_api_claim_task),
    // ── Key-value stores ────────────────────────────────────────────────
    covered!(Get, "/stores", "GET /stores"),
    covered!(Post, "/stores", "POST /stores"),
    covered!(Post, "/stores/:id/join", "POST /stores/:id/join"),
    covered!(Get, "/stores/:id/keys", "GET /stores/:id/keys"),
    covered!(Put, "/stores/:id/:key", "PUT /stores/:id/:key"),
    covered!(Get, "/stores/:id/:key", "GET /stores/:id/:key"),
    covered!(Delete, "/stores/:id/:key", "DELETE /stores/:id/:key"),
    // ── Files ───────────────────────────────────────────────────────────
    covered!(Post, "/files/send", "POST /files/send"),
    covered!(Get, "/files/transfers", "GET /files/transfers"),
    covered!(Get, "/files/transfers/:id", "GET /files/transfers/:id"),
    covered!(Post, "/files/accept/:id", "POST /files/accept/:id"),
    covered!(Post, "/files/reject/:id", "POST /files/reject/:id"),
    // ── Constitution ────────────────────────────────────────────────────
    covered!(Get, "/constitution", "GET /constitution"),
    covered!(Get, "/constitution/json", "GET /constitution/json"),
    // ── Upgrade ─────────────────────────────────────────────────────────
    covered!(Get, "/upgrade", daemon_api_upgrade_check),
    covered!(Post, "/upgrade/apply", "gui-upgrade-apply"),
    // ── WebSocket ───────────────────────────────────────────────────────
    covered!(Get, "/ws", daemon_api_ws_connect),
    covered!(Get, "/ws/direct", ws_direct_endpoint),
    covered!(Get, "/ws/sessions", daemon_api_ws_sessions),
    covered!(Get, "/gui", gui_html_contains_brand),
];

const COVERAGE_MARKER_SOURCES: &[(&str, &str)] = &[
    (
        "tests/daemon_api_integration.rs",
        include_str!("daemon_api_integration.rs"),
    ),
    (
        "tests/peer_lifecycle_integration.rs",
        include_str!("peer_lifecycle_integration.rs"),
    ),
    (
        "tests/named_group_d4_apply.rs",
        include_str!("named_group_d4_apply.rs"),
    ),
    (
        "tests/named_group_c2_live.rs",
        include_str!("named_group_c2_live.rs"),
    ),
    (
        "tests/named_group_e_live.rs",
        include_str!("named_group_e_live.rs"),
    ),
    (
        "tests/named_group_join_metadata_event.rs",
        include_str!("named_group_join_metadata_event.rs"),
    ),
    (
        "tests/connectivity_test.rs",
        include_str!("connectivity_test.rs"),
    ),
    ("tests/gui_smoke.rs", include_str!("gui_smoke.rs")),
    ("tests/ws_integration.rs", include_str!("ws_integration.rs")),
    ("tests/e2e_full_audit.sh", include_str!("e2e_full_audit.sh")),
    (
        "tests/e2e_comprehensive.sh",
        include_str!("e2e_comprehensive.sh"),
    ),
    (
        "tests/e2e_named_groups.sh",
        include_str!("e2e_named_groups.sh"),
    ),
    (
        "tests/e2e_stress_gossip.sh",
        include_str!("e2e_stress_gossip.sh"),
    ),
    (
        "tests/e2e_gui_chrome.mjs",
        include_str!("e2e_gui_chrome.mjs"),
    ),
];

const INTEGRATION_WORKFLOW: &str = include_str!("../.github/workflows/integration.yml");

/// Verifies every endpoint in the ENDPOINTS registry has a corresponding
/// entry in the COVERED list. Fails with a clear message listing missing
/// endpoints when a new endpoint is added without test coverage.
#[test]
fn all_endpoints_covered() {
    let covered: HashSet<(String, &str)> = COVERED
        .iter()
        .map(|entry| (format!("{}", entry.method), entry.path))
        .collect();

    let mut missing = Vec::new();
    for ep in ENDPOINTS {
        let key = (format!("{}", ep.method), ep.path);
        if !covered.contains(&key) {
            missing.push(format!(
                "  {} {} (cli: {}, category: {})",
                ep.method, ep.path, ep.cli_name, ep.category
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "\n\nEndpoints missing test coverage ({} missing):\n{}\n\n\
         To fix: add the endpoint to COVERED in tests/api_coverage.rs\n\
         AND point it at a real test marker outside tests/api_coverage.rs\n",
        missing.len(),
        missing.join("\n")
    );
}

/// Verifies daemon-backed named-group behavior is required by the CI-visible
/// validation path, not only claimed by the daemon-free COVERED list.
#[test]
fn named_group_ignored_integration_suite_is_required_by_ci() {
    const REQUIRED_COMMAND: &str = "cargo nextest run --all-features --test \
                                   named_group_integration --run-ignored ignored-only";

    assert!(
        INTEGRATION_WORKFLOW.contains(REQUIRED_COMMAND),
        "\n\nThe named-group REST endpoints in COVERED rely on \
         tests/named_group_integration.rs for daemon-backed behavior. \
         Keep that ignored test binary wired into CI with:\n  {REQUIRED_COMMAND}\n"
    );
}

/// Verifies every COVERED entry points at a real test function or probe label
/// outside this file, so a tuple in this guardian cannot claim coverage alone.
#[test]
fn covered_entries_reference_real_test_markers() {
    let missing = missing_coverage_markers(COVERED, COVERAGE_MARKER_SOURCES);

    assert!(
        missing.is_empty(),
        "\n\nCoverage entries without real test markers ({} missing):\n{}\n\n\
         To fix: add or rename the endpoint's marker in the actual test/probe \
         source, not only in tests/api_coverage.rs\n",
        missing.len(),
        missing.join("\n")
    );
}

/// Verifies the COVERED list doesn't contain stale entries that are no
/// longer in ENDPOINTS (i.e., endpoints that were removed but not cleaned
/// up from the coverage list).
#[test]
fn no_stale_coverage_entries() {
    let endpoints: HashSet<(String, &str)> = ENDPOINTS
        .iter()
        .map(|ep| (format!("{}", ep.method), ep.path))
        .collect();

    let mut stale = Vec::new();
    for entry in COVERED {
        let key = (format!("{}", entry.method), entry.path);
        if !endpoints.contains(&key) {
            stale.push(format!("  {} {}", entry.method, entry.path));
        }
    }

    assert!(
        stale.is_empty(),
        "\n\nStale entries in COVERED (no longer in ENDPOINTS):\n{}\n\n\
         To fix: remove these from COVERED in tests/api_coverage.rs\n",
        stale.join("\n")
    );
}

/// Verifies the COVERED list has no duplicates.
#[test]
fn no_duplicate_coverage_entries() {
    let mut seen = HashSet::new();
    let mut dupes = Vec::new();
    for entry in COVERED {
        let key = (format!("{}", entry.method), entry.path);
        if !seen.insert(key.clone()) {
            dupes.push(format!("  {} {}", entry.method, entry.path));
        }
    }

    assert!(
        dupes.is_empty(),
        "\n\nDuplicate entries in COVERED:\n{}\n",
        dupes.join("\n")
    );
}

/// Verifies COVERED count matches ENDPOINTS count exactly.
#[test]
fn coverage_count_matches_endpoint_count() {
    assert_eq!(
        COVERED.len(),
        ENDPOINTS.len(),
        "COVERED has {} entries but ENDPOINTS has {} — they must match exactly",
        COVERED.len(),
        ENDPOINTS.len()
    );
}

#[test]
fn missing_marker_detection_rejects_tuple_without_test_marker() {
    let declared = [covered!(Get, "/health", missing_health_marker)];
    let sources = [(
        "tests/fake_endpoint_test.rs",
        "#[test]\nfn real_test() {}\n",
    )];

    assert_eq!(
        missing_coverage_markers(&declared, &sources),
        vec![String::from(
            r#"  GET /health -> marker "missing_health_marker""#
        )]
    );
}

fn missing_coverage_markers(covered: &[CoveredEndpoint], sources: &[(&str, &str)]) -> Vec<String> {
    let rust_test_symbols = collect_rust_test_symbols(sources);

    covered
        .iter()
        .filter(|entry| !coverage_marker_exists(entry.marker, sources, &rust_test_symbols))
        .map(|entry| {
            format!(
                r#"  {} {} -> marker "{}""#,
                entry.method, entry.path, entry.marker
            )
        })
        .collect()
}

fn coverage_marker_exists(
    marker: &str,
    sources: &[(&str, &str)],
    rust_test_symbols: &HashSet<String>,
) -> bool {
    if is_rust_identifier(marker) {
        return rust_test_symbols.contains(marker);
    }

    sources.iter().any(|(_, source)| source.contains(marker))
}

fn collect_rust_test_symbols(sources: &[(&str, &str)]) -> HashSet<String> {
    let mut symbols = HashSet::new();

    for (path, source) in sources {
        if !path.ends_with(".rs") {
            continue;
        }

        let mut pending_test_attr = false;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test]") {
                pending_test_attr = true;
                continue;
            }

            if pending_test_attr && trimmed.starts_with("#[") {
                continue;
            }

            if pending_test_attr {
                if let Some(symbol) = extract_test_fn_name(trimmed) {
                    symbols.insert(symbol.to_string());
                }
                pending_test_attr = false;
            }
        }
    }

    symbols
}

fn extract_test_fn_name(line: &str) -> Option<&str> {
    let line = line.strip_prefix("async ").unwrap_or(line);
    let rest = line.strip_prefix("fn ")?;
    let end = rest.find('(')?;
    Some(&rest[..end])
}

fn is_rust_identifier(marker: &str) -> bool {
    let mut chars = marker.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Verifies all cli_name values in ENDPOINTS are unique.
#[test]
fn cli_names_unique() {
    let mut seen = HashSet::new();
    let mut dupes = Vec::new();
    for ep in ENDPOINTS {
        if !seen.insert(ep.cli_name) {
            dupes.push(format!(
                "  cli_name={:?} used by {} {} AND another endpoint",
                ep.cli_name, ep.method, ep.path
            ));
        }
    }

    assert!(
        dupes.is_empty(),
        "\n\nDuplicate cli_name values in ENDPOINTS:\n{}\n",
        dupes.join("\n")
    );
}

/// Verifies the route set in x0xd.rs matches the ENDPOINTS registry exactly,
/// excluding documented aliases.
#[test]
fn route_set_matches_registry() {
    let source = include_str!("../src/bin/x0xd.rs");
    let routes = extract_route_defs(source);

    let endpoints: HashSet<(String, String)> = ENDPOINTS
        .iter()
        .map(|ep| (format!("{}", ep.method), ep.path.to_string()))
        .collect();

    let known_extras: HashSet<(String, String)> = [(String::from("GET"), String::from("/gui/"))]
        .into_iter()
        .collect();

    let missing_from_registry: Vec<String> = routes
        .difference(&endpoints)
        .filter(|route| !known_extras.contains(*route))
        .map(|(method, path)| format!("  {} {}", method, path))
        .collect();

    let missing_from_router: Vec<String> = endpoints
        .difference(&routes)
        .map(|(method, path)| format!("  {} {}", method, path))
        .collect();

    assert!(
        missing_from_registry.is_empty() && missing_from_router.is_empty(),
        "\n\nRegistry/router drift detected.\n\
         Routes in x0xd.rs missing from ENDPOINTS:\n{}\n\n\
         ENDPOINTS entries missing from x0xd.rs:\n{}\n",
        if missing_from_registry.is_empty() {
            String::from("  <none>")
        } else {
            missing_from_registry.join("\n")
        },
        if missing_from_router.is_empty() {
            String::from("  <none>")
        } else {
            missing_from_router.join("\n")
        }
    );
}

/// Verifies every category in ENDPOINTS is non-empty and recognized.
#[test]
fn categories_are_valid() {
    let valid_categories = [
        "status",
        "identity",
        "network",
        "presence",
        "messaging",
        "discovery",
        "contacts",
        "machines",
        "trust",
        "direct",
        "groups",
        "named-groups",
        "tasks",
        "stores",
        "files",
        "exec",
        "upgrade",
        "websocket",
    ];

    for ep in ENDPOINTS {
        assert!(
            !ep.category.is_empty(),
            "Endpoint {} {} has empty category",
            ep.method,
            ep.path
        );
        assert!(
            valid_categories.contains(&ep.category),
            "Endpoint {} {} has unknown category {:?}. \
             Valid categories: {:?}",
            ep.method,
            ep.path,
            ep.category,
            valid_categories
        );
    }
}

/// Verifies the GUI HTML calls only endpoints that exist in ENDPOINTS.
#[test]
fn gui_api_calls_match_endpoints() {
    let gui_html = include_str!("../src/gui/x0x-gui.html");
    let endpoints: HashSet<(String, &str)> = ENDPOINTS
        .iter()
        .map(|e| (format!("{}", e.method), e.path))
        .collect();
    let unknown = unknown_gui_api_calls(gui_html, &endpoints);

    assert!(
        unknown.is_empty(),
        "\nGUI calls {} API endpoints not found in ENDPOINTS:\n{}\n",
        unknown.len(),
        unknown.join("\n")
    );
}

const REVIEWED_GUI_DYNAMIC_METHODS: &[(&str, &str)] = &[(
    "/contacts/:/machines/:/pin",
    "togglePin chooses POST or DELETE, and both methods are registered",
)];

#[derive(Debug, PartialEq, Eq)]
enum GuiPathSegment {
    Literal(String),
    Dynamic,
}

#[derive(Debug, PartialEq, Eq)]
enum GuiApiMethod {
    Static(String),
    Dynamic(String),
}

#[derive(Debug, PartialEq, Eq)]
struct GuiApiCall {
    path_expr: String,
    normalized_path: String,
    method: GuiApiMethod,
}

fn unknown_gui_api_calls(gui_html: &str, endpoints: &HashSet<(String, &str)>) -> Vec<String> {
    extract_gui_api_calls(gui_html)
        .into_iter()
        .filter_map(|call| match &call.method {
            GuiApiMethod::Static(method) => {
                if matches_any_endpoint(method, &call.normalized_path, endpoints) {
                    None
                } else {
                    Some(format_gui_api_error(&call, endpoints))
                }
            }
            GuiApiMethod::Dynamic(_) => {
                if is_reviewed_dynamic_method_call(&call.normalized_path)
                    && matching_endpoint_methods(&call.normalized_path, endpoints).len() > 1
                {
                    None
                } else {
                    Some(format_gui_api_error(&call, endpoints))
                }
            }
        })
        .collect()
}

fn extract_gui_api_calls(gui_html: &str) -> Vec<GuiApiCall> {
    let bytes = gui_html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i + 4 <= bytes.len() {
        if &bytes[i..i + 4] == b"api(" {
            let start = i + 4;
            let Some(end) = find_api_args_end(bytes, start) else {
                i += 4;
                continue;
            };
            let args = &gui_html[start..end];
            let (expr, options) = split_top_level_comma(args);
            let expr = expr.trim();
            if looks_like_path_arg(expr) {
                out.push(GuiApiCall {
                    path_expr: expr.to_string(),
                    normalized_path: normalize_gui_api_expr(expr),
                    method: extract_gui_api_method(options),
                });
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }

    out
}

fn extract_gui_api_method(options: &str) -> GuiApiMethod {
    let trimmed = options.trim_start();
    if trimmed.is_empty() {
        return GuiApiMethod::Static(String::from("GET"));
    }

    let trimmed = trimmed
        .strip_prefix(',')
        .map(str::trim_start)
        .unwrap_or(trimmed);

    if trimmed.is_empty() {
        return GuiApiMethod::Static(String::from("GET"));
    }

    if !trimmed.starts_with('{') {
        return GuiApiMethod::Dynamic(trimmed.to_string());
    }

    let Some(method_value) = find_top_level_object_property(trimmed, "method") else {
        return GuiApiMethod::Static(String::from("GET"));
    };
    let method_value = method_value.trim();
    let bytes = method_value.as_bytes();

    if let Some(quote) = bytes
        .first()
        .copied()
        .filter(|q| matches!(q, b'\'' | b'"' | b'`'))
    {
        let mut method = String::new();
        append_literal_until_quote(method_value, quote, &mut method);
        GuiApiMethod::Static(method.to_ascii_uppercase())
    } else {
        GuiApiMethod::Dynamic(method_value.to_string())
    }
}

fn find_top_level_object_property<'a>(source: &'a str, property: &str) -> Option<&'a str> {
    let bytes = source.as_bytes();
    let property_bytes = property.as_bytes();
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'{' => depth += 1,
                b'}' => {
                    if depth == 1 {
                        return None;
                    }
                    depth = depth.saturating_sub(1);
                }
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth = depth.saturating_sub(1),
                _ if depth == 1 && source[i..].starts_with(property) => {
                    let after = i + property_bytes.len();
                    if is_identifier_boundary(bytes, i, after) {
                        let value = source[after..].trim_start();
                        if let Some(value) = value.strip_prefix(':') {
                            return Some(read_property_value(value));
                        }
                        if value.starts_with(',') || value.starts_with('}') {
                            return Some(&source[i..after]);
                        }
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }

    None
}

fn is_identifier_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).and_then(|index| bytes.get(index));
    let after = bytes.get(end);
    !before.is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && !after.is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn read_property_value(source: &str) -> &str {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => {
                    if depth == 0 {
                        return source[..i].trim();
                    }
                    depth -= 1;
                }
                b',' if depth == 0 => return source[..i].trim(),
                _ => {}
            }
        }
        i += 1;
    }

    source.trim()
}

fn append_literal_until_quote(source: &str, quote: u8, out: &mut String) {
    let bytes = source.as_bytes();
    let mut i = 1usize;

    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            if let Some(next) = bytes.get(i + 1) {
                out.push(*next as char);
                i += 2;
                continue;
            }
            return;
        }
        if c == quote {
            return;
        }
        out.push(c as char);
        i += 1;
    }
}

fn find_api_args_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut i = start;
    let mut in_str: Option<u8> = None;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(i);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        i += 1;
    }

    None
}

fn split_top_level_comma(args: &str) -> (&str, &str) {
    let bytes = args.as_bytes();
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => return (&args[..i], &args[i..]),
                _ => {}
            }
        }
        i += 1;
    }

    (args, "")
}

fn looks_like_path_arg(expr: &str) -> bool {
    let trimmed = expr.trim_start();
    let bytes = trimmed.as_bytes();
    bytes.len() >= 3 && matches!(bytes[0], b'\'' | b'"' | b'`') && bytes[1] == b'/'
}

fn normalize_gui_api_expr(expr: &str) -> String {
    let bytes = expr.as_bytes();
    let mut normalized = String::new();
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => i = append_quoted_literal(expr, i, &mut normalized),
            b'`' => i = append_template_literal(expr, i, &mut normalized),
            b'+' | b' ' | b'\n' | b'\r' | b'\t' => i += 1,
            _ => {
                normalized.push(':');
                i = skip_dynamic_operand(bytes, i);
            }
        }
    }

    if let Some(index) = normalized.find('?') {
        normalized.truncate(index);
    }
    normalized
}

fn append_quoted_literal(expr: &str, start: usize, normalized: &mut String) -> usize {
    let bytes = expr.as_bytes();
    let quote = bytes[start];
    let mut i = start + 1;

    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            if let Some(next) = bytes.get(i + 1) {
                normalized.push(*next as char);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if c == quote {
            return i + 1;
        }
        if c == b'$' && bytes.get(i + 1) == Some(&b'{') {
            normalized.push(':');
            i = skip_template_placeholder(bytes, i + 2);
            continue;
        }
        normalized.push(c as char);
        i += 1;
    }

    i
}

fn append_template_literal(expr: &str, start: usize, normalized: &mut String) -> usize {
    let bytes = expr.as_bytes();
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if let Some(next) = bytes.get(i + 1) {
                    normalized.push(*next as char);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'`' => return i + 1,
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                normalized.push(':');
                i = skip_template_placeholder(bytes, i + 2);
            }
            c => {
                normalized.push(c as char);
                i += 1;
            }
        }
    }

    i
}

fn skip_dynamic_operand(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = start;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth = depth.saturating_sub(1),
                b'+' if depth == 0 => return i,
                _ => {}
            }
        }
        i += 1;
    }

    i
}

fn skip_template_placeholder(bytes: &[u8], start: usize) -> usize {
    let mut depth = 1usize;
    let mut in_str: Option<u8> = None;
    let mut i = start;

    while i < bytes.len() && depth > 0 {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }

    i
}

fn path_segments(path: &str) -> Vec<GuiPathSegment> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment == ":" || segment.starts_with(':') {
                GuiPathSegment::Dynamic
            } else {
                GuiPathSegment::Literal(segment.to_string())
            }
        })
        .collect()
}

fn matches_any_endpoint(method: &str, path: &str, endpoints: &HashSet<(String, &str)>) -> bool {
    let path_parts = path_segments(path);
    endpoints.iter().any(|(ep_method, ep_path)| {
        ep_method.as_str() == method && endpoint_path_matches(&path_parts, ep_path)
    })
}

fn matching_endpoint_methods(path: &str, endpoints: &HashSet<(String, &str)>) -> Vec<String> {
    let path_parts = path_segments(path);
    let mut methods: Vec<String> = endpoints
        .iter()
        .filter(|(_, ep_path)| endpoint_path_matches(&path_parts, ep_path))
        .map(|(method, _)| method.to_string())
        .collect();
    methods.sort();
    methods.dedup();
    methods
}

fn endpoint_path_matches(path_parts: &[GuiPathSegment], ep_path: &str) -> bool {
    let ep_parts = path_segments(ep_path);
    path_parts.len() == ep_parts.len()
        && path_parts
            .iter()
            .zip(ep_parts.iter())
            .all(|(path_part, ep_part)| match ep_part {
                GuiPathSegment::Dynamic => true,
                GuiPathSegment::Literal(ep_literal) => {
                    matches!(path_part, GuiPathSegment::Literal(path_literal) if path_literal == ep_literal)
                }
            })
}

fn is_reviewed_dynamic_method_call(path: &str) -> bool {
    REVIEWED_GUI_DYNAMIC_METHODS
        .iter()
        .any(|(reviewed_path, _reason)| *reviewed_path == path)
}

fn format_gui_api_error(call: &GuiApiCall, endpoints: &HashSet<(String, &str)>) -> String {
    let methods = matching_endpoint_methods(&call.normalized_path, endpoints);
    let api_args = format_gui_api_args(call);
    if methods.is_empty() {
        format!(
            "  {} {} (from api({api_args}); no matching path in ENDPOINTS)",
            format_gui_method(&call.method),
            call.normalized_path,
        )
    } else {
        format!(
            "  {} {} (from api({api_args}); registered methods: {})",
            format_gui_method(&call.method),
            call.normalized_path,
            methods.join(", ")
        )
    }
}

fn format_gui_method(method: &GuiApiMethod) -> &str {
    match method {
        GuiApiMethod::Static(method) => method,
        GuiApiMethod::Dynamic(_) => "<dynamic method>",
    }
}

fn format_gui_api_args(call: &GuiApiCall) -> String {
    match &call.method {
        GuiApiMethod::Static(method) if method == "GET" => call.path_expr.clone(),
        GuiApiMethod::Static(method) => format!("{}, {{method:'{}'}}", call.path_expr, method),
        GuiApiMethod::Dynamic(method) => format!("{}, {{method:{method}}}", call.path_expr),
    }
}

#[test]
fn gui_api_path_checker_rejects_unknown_static_path() {
    let endpoints: HashSet<(String, &str)> =
        [(String::from("GET"), "/health")].into_iter().collect();
    let unknown = unknown_gui_api_calls(
        r#"
        api('/health');
        api("/not-in-ENDPOINTS");
        "#,
        &endpoints,
    );

    assert_eq!(
        unknown,
        vec![String::from(
            r#"  GET /not-in-ENDPOINTS (from api("/not-in-ENDPOINTS"); no matching path in ENDPOINTS)"#
        )]
    );
}

#[test]
fn gui_api_path_checker_accepts_dynamic_endpoint_shapes() {
    let endpoints: HashSet<(String, &str)> = [(String::from("GET"), "/stores/:id/:key")]
        .into_iter()
        .collect();
    let unknown = unknown_gui_api_calls(
        "api('/stores/'+storeId+'/channels_index'); api(`/stores/${storeId}/${key}`);",
        &endpoints,
    );

    assert!(
        unknown.is_empty(),
        "dynamic GUI paths should match parameterized endpoints: {unknown:?}"
    );
}

#[test]
fn gui_api_path_checker_rejects_dynamic_suffixes() {
    let endpoints: HashSet<(String, &str)> =
        [(String::from("GET"), "/groups/:id")].into_iter().collect();
    let unknown = unknown_gui_api_calls("api('/groups/'+gid+'/bogus');", &endpoints);

    assert_eq!(
        unknown,
        vec![String::from(
            "  GET /groups/:/bogus (from api('/groups/'+gid+'/bogus'); no matching path in ENDPOINTS)"
        )]
    );
}

#[test]
fn gui_api_path_checker_rejects_method_mismatches() {
    let endpoints: HashSet<(String, &str)> =
        [(String::from("GET"), "/groups/:id")].into_iter().collect();
    let unknown = unknown_gui_api_calls("api('/groups/'+gid,{method:'POST'});", &endpoints);

    assert_eq!(
        unknown,
        vec![String::from(
            "  POST /groups/: (from api('/groups/'+gid, {method:'POST'}); registered methods: GET)"
        )]
    );
}

#[test]
fn gui_api_path_checker_allows_reviewed_dynamic_methods() {
    let endpoints: HashSet<(String, &str)> = [
        (
            String::from("DELETE"),
            "/contacts/:agent_id/machines/:machine_id/pin",
        ),
        (
            String::from("POST"),
            "/contacts/:agent_id/machines/:machine_id/pin",
        ),
    ]
    .into_iter()
    .collect();
    let unknown = unknown_gui_api_calls(
        "api('/contacts/'+agentId+'/machines/'+machineId+'/pin',{method});",
        &endpoints,
    );

    assert!(
        unknown.is_empty(),
        "reviewed dynamic method call should pass: {unknown:?}"
    );
}

fn extract_route_defs(source: &str) -> HashSet<(String, String)> {
    let flat = source.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut routes = HashSet::new();
    let marker = ".route(";
    let mut i = 0usize;

    while let Some(pos) = flat[i..].find(marker) {
        let start = i + pos + marker.len();
        let mut depth = 1usize;
        let mut j = start;
        let bytes = flat.as_bytes();
        while j < flat.len() && depth > 0 {
            match bytes[j] as char {
                '"' => {
                    j += 1;
                    while j < flat.len() {
                        match bytes[j] as char {
                            '\\' => j += 2,
                            '"' => {
                                j += 1;
                                break;
                            }
                            _ => j += 1,
                        }
                    }
                    continue;
                }
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            j += 1;
        }

        if j <= start {
            break;
        }

        let inner = flat[start..j - 1].trim();
        i = j;

        let Some(path_start) = inner.find('"') else {
            continue;
        };
        let rest = &inner[path_start + 1..];
        let Some(path_end) = rest.find('"') else {
            continue;
        };
        let path = &rest[..path_end];
        let methods_src = &rest[path_end + 1..];

        for (needle, method) in [
            ("get(", "GET"),
            ("post(", "POST"),
            ("put(", "PUT"),
            ("patch(", "PATCH"),
            ("delete(", "DELETE"),
        ] {
            if methods_src.contains(needle) {
                routes.insert((method.to_string(), path.to_string()));
            }
        }
    }

    routes
}
