//! `x0x history …` — ADR-0023 durable-history commands.

use crate::cli::DaemonClient;
use anyhow::Result;

/// Build the shared `(key, value)` query list for list/search.
fn common_query<'a>(
    scope: &'a str,
    since_ms: &'a Option<String>,
    until_ms: &'a Option<String>,
    limit: &'a Option<String>,
    before_id: &'a Option<String>,
) -> Vec<(&'a str, &'a str)> {
    let mut q: Vec<(&str, &str)> = vec![("scope", scope)];
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
    let q = common_query(scope, &since, &until, &lim, &before);
    client.run_get_query("/history", &q).await
}

/// `x0x history search` — GET /history/search
///
/// Full-text search over text payloads within a scope.
pub async fn search(
    client: &DaemonClient,
    scope: &str,
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
    let mut q = common_query(scope, &since, &until, &lim, &before);
    q.push(("q", needle));
    client.run_get_query("/history/search", &q).await
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
