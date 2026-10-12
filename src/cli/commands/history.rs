//! `x0x history …` — ADR-0023 durable-history commands.

use crate::cli::{DaemonClient, NewerOperation};
use anyhow::Result;

/// Build the shared `(key, value)` query list for list/search.
///
/// `scope` is `None` only for the cross-scope search form (issue #275);
/// `history list` always supplies it.
fn common_query<'a>(
    scope: Option<&'a str>,
    since_ms: &'a Option<String>,
    until_ms: &'a Option<String>,
    limit: &'a Option<String>,
    before_id: &'a Option<String>,
) -> Vec<(&'a str, &'a str)> {
    let mut q: Vec<(&str, &str)> = Vec::new();
    if let Some(scope) = scope {
        q.push(("scope", scope));
    }
    if let Some(v) = since_ms {
        q.push(("since_ms", v));
    }
    if let Some(v) = until_ms {
        q.push(("until_ms", v));
    }
    if let Some(v) = limit {
        q.push(("limit", v));
    }
    if let Some(v) = before_id {
        q.push(("before_id", v));
    }
    q
}

/// `x0x history list` — GET /history
///
/// Lists durable history for one scope (`dm:<agent_hex>`,
/// `group:<stable_id>`, `topic:<name>`), newest first, keyset-paginated via
/// `--before-id`.
pub async fn list(
    client: &DaemonClient,
    scope: &str,
    since_ms: Option<u64>,
    until_ms: Option<u64>,
    limit: Option<usize>,
    before_id: Option<i64>,
) -> Result<()> {
    let since = since_ms.map(|v| v.to_string());
    let until = until_ms.map(|v| v.to_string());
    let lim = limit.map(|v| v.to_string());
    let before = before_id.map(|v| v.to_string());
    let q = common_query(Some(scope), &since, &until, &lim, &before);
    client.run_get_query("/history", &q).await
}

/// `x0x history message` — GET /history/message/:msg_id
///
/// Point lookup by any id the listing exposes; canonical group ids need
/// the scope hint (issue #319).
pub async fn message(client: &DaemonClient, msg_id: &str, scope: Option<&str>) -> Result<()> {
    let mut q: Vec<(&str, &str)> = Vec::new();
    if let Some(scope) = scope {
        q.push(("scope", scope));
    }
    client
        .run_get_query(&format!("/history/message/{msg_id}"), &q)
        .await
}

/// `x0x history search` — GET /history/search
///
/// Full-text search over text payloads. `scope = None` omits the `scope`
/// query parameter entirely, which the daemon reads as "every retained
/// scope" (issue #275); `Some(..)` keeps the legacy scoped behaviour.
pub async fn search(
    client: &DaemonClient,
    scope: Option<&str>,
    needle: &str,
    since_ms: Option<u64>,
    until_ms: Option<u64>,
    limit: Option<usize>,
    before_id: Option<i64>,
) -> Result<()> {
    let since = since_ms.map(|v| v.to_string());
    let until = until_ms.map(|v| v.to_string());
    let lim = limit.map(|v| v.to_string());
    let before = before_id.map(|v| v.to_string());
    let pairs = search_query_pairs(scope, needle, &since, &until, &lim, &before);
    let q: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    client.run_get_query("/history/search", &q).await
}

/// Split `x0x history search`'s positionals into `(scope, needle)`.
///
/// The command has two forms (issue #275) and they are told apart by
/// argument COUNT, never by inspecting the text:
///
/// - two positionals ⇒ `(Some(scope), query)` — the legacy scoped form;
/// - one positional  ⇒ `(None, query)` — search every retained scope.
///
/// `src/bin/x0x.rs` calls exactly this function, so the CLI cannot drift
/// from what the tests below pin.
#[must_use]
pub fn split_search_args(first: String, second: Option<String>) -> (Option<String>, String) {
    match second {
        Some(needle) => (Some(first), needle),
        None => (None, first),
    }
}

/// The exact query pairs `search` puts on the wire.
///
/// Extracted so the two-form contract is provable without spawning the
/// binary: an omitted scope must produce NO `scope` key at all (an empty or
/// echoed one would be a 400 instead of a cross-scope search).
fn search_query_pairs(
    scope: Option<&str>,
    needle: &str,
    since: &Option<String>,
    until: &Option<String>,
    lim: &Option<String>,
    before: &Option<String>,
) -> Vec<(String, String)> {
    let mut q = common_query(scope, since, until, lim, before);
    q.push(("q", needle));
    q.into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// `x0x history scopes` — GET /history/scopes
///
/// Lists the scopes that still hold retained rows, with row counts and the
/// newest local receipt time, keyset-paginated via `--after-scope`.
pub async fn scopes(
    client: &DaemonClient,
    after_scope: Option<&str>,
    limit: Option<usize>,
) -> Result<()> {
    let lim = limit.map(|v| v.to_string());
    let mut q: Vec<(&str, &str)> = Vec::new();
    if let Some(after) = after_scope {
        q.push(("after_scope", after));
    }
    if let Some(v) = &lim {
        q.push(("limit", v));
    }
    client.run_get_query("/history/scopes", &q).await
}

/// `x0x history stats` — GET /history/stats
///
/// Prints row counts, database size, and the retention bounds in force.
pub async fn stats(client: &DaemonClient) -> Result<()> {
    client.run_get("/history/stats").await
}

/// `x0x history policy` — GET /history/policy (ADR 0116 §3)
///
/// Prints the local history policy in force: rules, defaults, protected
/// groups and counters. Needs the durable API token.
pub async fn policy(client: &DaemonClient) -> Result<()> {
    client.run_newer(&POLICY, None).await
}

/// `x0x history policy`: older daemons lack the route (ADR 0116 §5).
pub(crate) const POLICY: NewerOperation = NewerOperation {
    command: "x0x history policy",
    method: crate::api::Method::Get,
    path: "/history/policy",
};

/// `x0x history retain` — POST /history/retain (ADR 0116 §4)
///
/// Trims local history now under the daemon's startup policy, within a row
/// budget and a time budget, and prints the report: committed deletions by
/// phase, pin-ceiling deletions, elapsed time and `state` (`complete`,
/// `more_work` or `blocked_by_protected_rows`). Needs the durable API token.
/// Only the budgets given are sent; the daemon applies its defaults for the
/// rest. An older daemon reports an unsupported operation.
pub async fn retain(
    client: &DaemonClient,
    max_rows: Option<u32>,
    budget_ms: Option<u32>,
) -> Result<()> {
    client
        .run_newer(&RETAIN, Some(&retain_body(max_rows, budget_ms)))
        .await
}

/// The `POST /history/retain` body: only the budgets the user gave.
fn retain_body(max_rows: Option<u32>, budget_ms: Option<u32>) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    if let Some(max_rows) = max_rows {
        body.insert("max_rows".into(), max_rows.into());
    }
    if let Some(budget_ms) = budget_ms {
        body.insert("budget_ms".into(), budget_ms.into());
    }
    serde_json::Value::Object(body)
}

/// `x0x history retain`: older daemons lack the route (ADR 0116 §5).
pub(crate) const RETAIN: NewerOperation = NewerOperation {
    command: "x0x history retain",
    method: crate::api::Method::Post,
    path: "/history/retain",
};

/// `x0x history purge` — DELETE /history
///
/// Purges one scope from the local store. Local-only: never propagated to
/// the network (ADR-0023 non-goal).
pub async fn purge(client: &DaemonClient, scope: &str) -> Result<()> {
    client.run_delete(&format!("/history?scope={scope}")).await
}

/// `x0x diagnostics history` — GET /diagnostics/history
///
/// Prints the durable-history writer/reaper counters (written, dropped-full,
/// dedupe hits, write errors, reaper evictions).
pub async fn diagnostics(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/history").await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WHY (issue #275, independent design review): the registry is metadata
    /// — it does not implement the CLI. `history search` is the only history
    /// command whose argument COUNT changes the request it builds, so both
    /// forms are pinned on the request the client actually constructs. This
    /// is fully inert: no process is spawned, no socket is opened.
    #[test]
    fn search_two_forms_build_distinct_wire_queries() {
        let (scope, needle) =
            split_search_args("group:g-1".to_string(), Some("needle".to_string()));
        assert_eq!(scope.as_deref(), Some("group:g-1"));
        assert_eq!(needle, "needle");
        let scoped = search_query_pairs(scope.as_deref(), &needle, &None, &None, &None, &None);
        assert_eq!(
            scoped,
            vec![
                ("scope".to_string(), "group:g-1".to_string()),
                ("q".to_string(), "needle".to_string()),
            ],
            "the legacy two-positional form must keep sending scope"
        );

        let (scope, needle) = split_search_args("needle".to_string(), None);
        assert!(scope.is_none(), "one positional is the query, not a scope");
        assert_eq!(needle, "needle");
        let cross = search_query_pairs(scope.as_deref(), &needle, &None, &None, &None, &None);
        assert_eq!(
            cross,
            vec![("q".to_string(), "needle".to_string())],
            "the one-positional form must omit the scope key entirely"
        );
    }

    /// WHY: a scope string that happens to look like a query (or vice versa)
    /// must not change the split — the form is decided by COUNT alone, so a
    /// user searching for the literal text `dm:peer` gets a cross-scope
    /// search rather than a silently scoped one.
    #[test]
    fn the_split_never_sniffs_the_text() {
        let (scope, needle) = split_search_args("dm:peer".to_string(), None);
        assert!(scope.is_none());
        assert_eq!(needle, "dm:peer");

        let (scope, needle) = split_search_args("plain".to_string(), Some("terms".to_string()));
        assert_eq!(
            scope.as_deref(),
            Some("plain"),
            "with two positionals the first is the scope even if malformed — \
             the daemon owns that 400, the CLI does not guess"
        );
        assert_eq!(needle, "terms");
    }

    /// WHY: `history list` has no cross-scope form; its scope is mandatory
    /// and must always reach the wire.
    #[test]
    fn list_always_sends_its_scope() {
        let q = common_query(Some("dm:abc"), &None, &None, &None, &None);
        assert_eq!(q, vec![("scope", "dm:abc")]);
    }

    /// Every operation older daemons may lack names the registered route
    /// and the registered CLI command, so the unsupported-operation error
    /// points at the real route.
    /// Every history operation older daemons may lack.
    const NEWER_OPERATIONS: &[NewerOperation] = &[POLICY, RETAIN];

    #[test]
    fn adr0116_unsupported_operations_match_the_api_registry() {
        for op in NEWER_OPERATIONS {
            let entry = crate::api::ENDPOINTS
                .iter()
                .find(|e| e.method == op.method && e.path == op.path)
                .unwrap_or_else(|| panic!("{} {} is not registered", op.method, op.path));
            assert_eq!(format!("x0x {}", entry.cli_name), op.command);
        }
    }

    /// Serve `router` on a loopback port and point a CLI client at it.
    /// Loopback only: the sandbox and CI forbid anything else.
    async fn daemon_at(router: axum::Router) -> (DaemonClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("loopback address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = DaemonClient::new(
            None,
            Some(&addr.to_string()),
            crate::cli::OutputFormat::Json,
        )
        .expect("client");
        (client, server)
    }

    /// A daemon from before ADR 0116: it serves `/health` and has no
    /// `/history/policy` route, so axum answers an empty 404.
    fn older_daemon() -> axum::Router {
        axum::Router::new().route(
            "/health",
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "ok": true })) }),
        )
    }

    /// WHY (ADR 0116 §5 and its validation line "test the new API's absence
    /// on an older daemon", Codex E r1 P2): `x0x history policy` against an
    /// older daemon must report an unsupported operation, not `unknown
    /// error (HTTP 404)`.
    #[tokio::test]
    async fn adr0116_unsupported_policy_on_an_older_daemon() {
        let (client, server) = daemon_at(older_daemon()).await;
        let rendered = policy(&client)
            .await
            .expect_err("an older daemon cannot serve the policy")
            .to_string();
        server.abort();
        assert!(
            rendered.contains("unsupported operation")
                && rendered.contains("`x0x history policy`")
                && rendered.contains("GET /history/policy")
                && rendered.contains("predates"),
            "{rendered}"
        );
        assert!(!rendered.contains("unknown error"), "{rendered}");
    }

    /// The same with an older daemon whose unknown routes answer a JSON 404.
    #[tokio::test]
    async fn adr0116_unsupported_policy_json_404_on_an_older_daemon() {
        let router = older_daemon().fallback(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({ "ok": false, "error": "not found" })),
            )
        });
        let (client, server) = daemon_at(router).await;
        let rendered = policy(&client)
            .await
            .expect_err("an older daemon cannot serve the policy")
            .to_string();
        server.abort();
        assert!(
            rendered.contains("unsupported operation")
                && rendered.contains("`x0x history policy`")
                && rendered.contains("predates"),
            "{rendered}"
        );
    }

    /// Control: a daemon that has the route but refuses the caller keeps
    /// its own error. A 403 is never reported as an older daemon.
    #[tokio::test]
    async fn adr0116_unsupported_policy_keeps_a_403() {
        let router = older_daemon().route(
            "/history/policy",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "ok": false,
                        "error": "durable API token required",
                    })),
                )
            }),
        );
        let (client, server) = daemon_at(router).await;
        let rendered = policy(&client)
            .await
            .expect_err("a 403 is an error")
            .to_string();
        server.abort();
        assert_eq!(rendered, "durable API token required (HTTP 403)");
    }

    /// ADR 0116 §5 for the trim: `x0x history retain` against a daemon from
    /// before ADR 0116 reports an unsupported operation, as `policy` does.
    #[tokio::test]
    async fn adr0116_unsupported_retain_on_an_older_daemon() {
        let (client, server) = daemon_at(older_daemon()).await;
        let rendered = retain(&client, Some(10), None)
            .await
            .expect_err("an older daemon cannot trim")
            .to_string();
        server.abort();
        assert!(
            rendered.contains("unsupported operation")
                && rendered.contains("`x0x history retain`")
                && rendered.contains("POST /history/retain")
                && rendered.contains("predates"),
            "{rendered}"
        );
    }

    /// The CLI sends only the budgets the user gave; the daemon applies its
    /// defaults (ruling Q12: an empty object is the default request).
    #[test]
    fn retain_sends_only_the_budgets_given() {
        assert_eq!(retain_body(None, None), serde_json::json!({}));
        assert_eq!(
            retain_body(Some(5), None),
            serde_json::json!({ "max_rows": 5 })
        );
        assert_eq!(
            retain_body(Some(5), Some(50)),
            serde_json::json!({ "max_rows": 5, "budget_ms": 50 })
        );
    }
}
