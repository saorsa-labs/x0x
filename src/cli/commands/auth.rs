//! `x0x auth` — session-token management (#127 / WS1.6).

use anyhow::Result;

use crate::cli::DaemonClient;

/// `x0x auth session` — POST /auth/session.
///
/// Exchanges the durable API bearer token for a short-lived browser session
/// token. The session token is the only kind accepted via `?token=` query
/// strings on WS/SSE endpoints; the durable token is never valid in a URL.
pub async fn session(client: &DaemonClient) -> Result<()> {
    let r = client.post_empty("/auth/session").await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

/// `x0x auth refresh` — POST /auth/session/refresh (#893).
///
/// Only a SESSION token is accepted, so run it as
/// `X0X_API_TOKEN=<session token> x0x auth refresh`; the durable token is
/// refused. Without `--idle-ms` the refresh reports no user activity, so it
/// does not extend the session's idle timeout.
pub async fn refresh(client: &DaemonClient, idle_ms: Option<u64>) -> Result<()> {
    let r = match idle_ms {
        Some(idle_ms) => {
            client
                .post(
                    "/auth/session/refresh",
                    &serde_json::json!({ "idle_ms": idle_ms }),
                )
                .await?
        }
        None => client.post_empty("/auth/session/refresh").await?,
    };
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

/// `x0x auth revoke` — POST /auth/session/revoke.
///
/// Ends the session whose token is passed as
/// `X0X_API_TOKEN=<session token> x0x auth revoke`; the durable token is
/// refused.
pub async fn revoke(client: &DaemonClient) -> Result<()> {
    let r = client.post_empty("/auth/session/revoke").await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
