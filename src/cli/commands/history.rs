//! `x0x history …` — ADR-0023 durable-history commands.

use crate::cli::DaemonClient;
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
}
