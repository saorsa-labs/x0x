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

/// Every endpoint (method, path) that has a test somewhere in the test suite.
///
/// When you add a new endpoint to `src/api/mod.rs:ENDPOINTS`, you MUST add a
/// corresponding entry here AND write the actual test in `rest_coverage.rs`,
/// `cli_coverage.rs`, or another test file.
///
/// This is deliberately manual — the failing test message tells you exactly
/// what is missing.
const COVERED: &[(Method, &str)] = &[
    // ── Status ──────────────────────────────────────────────────────────
    (Method::Get, "/health"),
    (Method::Get, "/status"),
    (Method::Post, "/shutdown"),
    // ── Identity ────────────────────────────────────────────────────────
    (Method::Get, "/agent"),
    (Method::Post, "/announce"),
    (Method::Get, "/agent/user-id"),
    (Method::Get, "/agent/card"),
    (Method::Get, "/introduction"),
    (Method::Post, "/agent/card/import"),
    // ── Network ─────────────────────────────────────────────────────────
    (Method::Get, "/peers"),
    // ── Presence ────────────────────────────────────────────────────────
    (Method::Get, "/presence"),
    (Method::Get, "/presence/online"),
    (Method::Get, "/presence/foaf"),
    (Method::Get, "/presence/find/:id"),
    (Method::Get, "/presence/status/:id"),
    (Method::Get, "/presence/events"),
    // ── Network (cont.) ─────────────────────────────────────────────────
    (Method::Get, "/network/status"),
    (Method::Get, "/network/bootstrap-cache"),
    (Method::Get, "/diagnostics/connectivity"),
    (Method::Get, "/diagnostics/gossip"),
    (Method::Get, "/diagnostics/dm"),
    (Method::Get, "/diagnostics/exec"),
    (Method::Post, "/peers/:peer_id/probe"),
    (Method::Get, "/peers/:peer_id/health"),
    (Method::Get, "/peers/events"),
    // ── Messaging ───────────────────────────────────────────────────────
    (Method::Post, "/publish"),
    (Method::Post, "/subscribe"),
    (Method::Delete, "/subscribe/:id"),
    (Method::Get, "/events"),
    // ── Discovery ───────────────────────────────────────────────────────
    (Method::Get, "/agents/discovered"),
    (Method::Get, "/agents/discovered/:agent_id"),
    (Method::Get, "/agents/:agent_id/machine"),
    (Method::Get, "/machines/discovered"),
    (Method::Get, "/machines/discovered/:machine_id"),
    (Method::Get, "/agents/reachability/:agent_id"),
    (Method::Post, "/agents/find/:agent_id"),
    (Method::Get, "/users/:user_id/agents"),
    (Method::Get, "/users/:user_id/machines"),
    // ── Contacts ────────────────────────────────────────────────────────
    (Method::Get, "/contacts"),
    (Method::Post, "/contacts"),
    (Method::Post, "/contacts/trust"),
    (Method::Patch, "/contacts/:agent_id"),
    (Method::Delete, "/contacts/:agent_id"),
    (Method::Post, "/contacts/:agent_id/revoke"),
    (Method::Get, "/contacts/:agent_id/revocations"),
    // ── Machines ────────────────────────────────────────────────────────
    (Method::Get, "/contacts/:agent_id/machines"),
    (Method::Post, "/contacts/:agent_id/machines"),
    (Method::Delete, "/contacts/:agent_id/machines/:machine_id"),
    (Method::Post, "/contacts/:agent_id/machines/:machine_id/pin"),
    (
        Method::Delete,
        "/contacts/:agent_id/machines/:machine_id/pin",
    ),
    // ── Trust ───────────────────────────────────────────────────────────
    (Method::Post, "/trust/evaluate"),
    // ── Direct messaging ────────────────────────────────────────────────
    (Method::Post, "/agents/connect"),
    (Method::Post, "/machines/connect"),
    (Method::Post, "/direct/send"),
    (Method::Get, "/direct/connections"),
    (Method::Get, "/direct/events"),
    // ── Exec ───────────────────────────────────────────────────────────
    (Method::Post, "/exec/run"),
    (Method::Post, "/exec/cancel"),
    (Method::Get, "/exec/sessions"),
    // ── MLS groups ──────────────────────────────────────────────────────
    (Method::Post, "/mls/groups"),
    (Method::Get, "/mls/groups"),
    (Method::Get, "/mls/groups/:id"),
    (Method::Post, "/mls/groups/:id/members"),
    (Method::Delete, "/mls/groups/:id/members/:agent_id"),
    (Method::Post, "/mls/groups/:id/encrypt"),
    (Method::Post, "/mls/groups/:id/decrypt"),
    (Method::Post, "/mls/groups/:id/welcome"),
    // ── Named groups ────────────────────────────────────────────────────
    (Method::Post, "/groups"),
    (Method::Get, "/groups"),
    (Method::Get, "/groups/:id"),
    (Method::Get, "/groups/:id/members"),
    (Method::Post, "/groups/:id/members"),
    (Method::Delete, "/groups/:id/members/:agent_id"),
    // ── Phase E: public-group messaging ─────────────────────────────────
    (Method::Post, "/groups/:id/send"),
    (Method::Get, "/groups/:id/messages"),
    (Method::Post, "/groups/:id/invite"),
    (Method::Post, "/groups/join"),
    (Method::Put, "/groups/:id/display-name"),
    (Method::Delete, "/groups/:id"),
    // ── Named groups: policy/roles/requests/discovery ───────────────────
    (Method::Patch, "/groups/:id"),
    (Method::Patch, "/groups/:id/policy"),
    (Method::Patch, "/groups/:id/members/:agent_id/role"),
    (Method::Post, "/groups/:id/ban/:agent_id"),
    (Method::Delete, "/groups/:id/ban/:agent_id"),
    (Method::Get, "/groups/:id/requests"),
    (Method::Post, "/groups/:id/requests"),
    (Method::Post, "/groups/:id/requests/:request_id/approve"),
    (Method::Post, "/groups/:id/requests/:request_id/reject"),
    (Method::Delete, "/groups/:id/requests/:request_id"),
    (Method::Get, "/groups/discover"),
    // ── Phase C.2: shard discovery ──────────────────────────────────────
    (Method::Get, "/groups/discover/nearby"),
    (Method::Get, "/groups/discover/subscriptions"),
    (Method::Post, "/groups/discover/subscribe"),
    (Method::Delete, "/groups/discover/subscribe/:kind/:shard"),
    (Method::Get, "/groups/cards/:id"),
    (Method::Post, "/groups/cards/import"),
    (Method::Post, "/groups/:id/secure/encrypt"),
    (Method::Post, "/groups/:id/secure/decrypt"),
    (Method::Post, "/groups/:id/secure/reseal"),
    (Method::Post, "/groups/secure/open-envelope"),
    // ── Phase D.3: state-commit chain ───────────────────────────────────
    (Method::Get, "/groups/:id/state"),
    (Method::Post, "/groups/:id/state/seal"),
    (Method::Post, "/groups/:id/state/withdraw"),
    // ── Task lists ──────────────────────────────────────────────────────
    (Method::Get, "/task-lists"),
    (Method::Post, "/task-lists"),
    (Method::Get, "/task-lists/:id/tasks"),
    (Method::Post, "/task-lists/:id/tasks"),
    (Method::Patch, "/task-lists/:id/tasks/:tid"),
    // ── Key-value stores ────────────────────────────────────────────────
    (Method::Get, "/stores"),
    (Method::Post, "/stores"),
    (Method::Post, "/stores/:id/join"),
    (Method::Get, "/stores/:id/keys"),
    (Method::Put, "/stores/:id/:key"),
    (Method::Get, "/stores/:id/:key"),
    (Method::Delete, "/stores/:id/:key"),
    // ── Files ───────────────────────────────────────────────────────────
    (Method::Post, "/files/send"),
    (Method::Get, "/files/transfers"),
    (Method::Get, "/files/transfers/:id"),
    (Method::Post, "/files/accept/:id"),
    (Method::Post, "/files/reject/:id"),
    // ── Constitution ────────────────────────────────────────────────────
    (Method::Get, "/constitution"),
    (Method::Get, "/constitution/json"),
    // ── Upgrade ─────────────────────────────────────────────────────────
    (Method::Get, "/upgrade"),
    (Method::Post, "/upgrade/apply"),
    // ── WebSocket ───────────────────────────────────────────────────────
    (Method::Get, "/ws"),
    (Method::Get, "/ws/direct"),
    (Method::Get, "/ws/sessions"),
    (Method::Get, "/gui"),
];

/// Verifies every endpoint in the ENDPOINTS registry has a corresponding
/// entry in the COVERED list. Fails with a clear message listing missing
/// endpoints when a new endpoint is added without test coverage.
#[test]
fn all_endpoints_covered() {
    let covered: HashSet<(String, &str)> =
        COVERED.iter().map(|(m, p)| (format!("{m}"), *p)).collect();

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
         AND write the actual test in tests/rest_coverage.rs\n",
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
    for (method, path) in COVERED {
        let key = (format!("{method}"), *path);
        if !endpoints.contains(&key) {
            stale.push(format!("  {method} {path}"));
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
    for (method, path) in COVERED {
        let key = (format!("{method}"), *path);
        if !seen.insert(key.clone()) {
            dupes.push(format!("  {method} {path}"));
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

    // Extract API paths from the GUI JavaScript.
    // The GUI uses: api("/path", ...) or api(`/path`, ...)
    let mut gui_paths = Vec::new();
    for line in gui_html.lines() {
        let trimmed = line.trim();
        // Match patterns like: api("/health" or api(`/health` or api('/health'
        if let Some(start) = trimmed.find("api(\"") {
            if let Some(path) = extract_api_path(&trimmed[start + 4..]) {
                gui_paths.push(path);
            }
        }
        if let Some(start) = trimmed.find("api(`") {
            if let Some(path) = extract_api_path(&trimmed[start + 4..]) {
                gui_paths.push(path);
            }
        }
        if let Some(start) = trimmed.find("api('") {
            if let Some(path) = extract_api_path(&trimmed[start + 4..]) {
                gui_paths.push(path);
            }
        }
    }

    // Normalize paths: /stores/${storeId}/key -> /stores/:id/:key
    let endpoint_paths: HashSet<&str> = ENDPOINTS.iter().map(|e| e.path).collect();

    let mut unknown = Vec::new();
    for path in &gui_paths {
        // Normalize dynamic segments: remove ${...} and replace with :param
        let normalized = normalize_gui_path(path);
        if !endpoint_paths.contains(normalized.as_str()) {
            // Check if it matches a parameterized endpoint
            if !matches_any_endpoint(&normalized, &endpoint_paths) {
                unknown.push(format!("  {path} (normalized: {normalized})"));
            }
        }
    }

    // This is informational — GUI may use computed paths that are hard to
    // statically extract. We warn but don't fail for now.
    if !unknown.is_empty() {
        eprintln!(
            "\nGUI calls {} API paths not directly found in ENDPOINTS:\n{}\n\
             (These may be dynamically constructed — verify manually)\n",
            unknown.len(),
            unknown.join("\n")
        );
    }
}

fn extract_api_path(s: &str) -> Option<String> {
    // Find the closing quote/backtick
    let _quote = s.chars().next()?;
    let rest = &s[1..]; // skip opening quote
    let end = rest.find(['"', '\'', '`', ','])?;
    let path = &rest[..end];
    if path.starts_with('/') {
        Some(path.to_string())
    } else {
        None
    }
}

fn normalize_gui_path(path: &str) -> String {
    // Replace ${variable} with :param
    let mut result = String::new();
    let mut chars = path.chars().peekable();
    #[allow(clippy::while_let_on_iterator)]
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // skip {
                          // Skip until }
            while let Some(c2) = chars.next() {
                if c2 == '}' {
                    break;
                }
            }
            result.push_str(":id");
        } else {
            result.push(c);
        }
    }
    result
}

fn matches_any_endpoint(path: &str, endpoints: &HashSet<&str>) -> bool {
    // Simple matching: split by / and check if any endpoint matches
    // with :param wildcards
    let path_parts: Vec<&str> = path.split('/').collect();
    for ep_path in endpoints {
        let ep_parts: Vec<&str> = ep_path.split('/').collect();
        if path_parts.len() == ep_parts.len() {
            let matches = path_parts
                .iter()
                .zip(ep_parts.iter())
                .all(|(p, e)| e.starts_with(':') || p == e);
            if matches {
                return true;
            }
        }
    }
    false
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
