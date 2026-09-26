//! `x0x grant issue|list|revoke|received` — ADR-0070 §2 share grants.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x grant issue GRANT_JSON` — GRANT_JSON is the `POST /grants` body
/// (literal, `@path` or a bare path, or `-` for stdin), e.g.
/// `{"grantee_user":"<hex>","agents":["<hex>"],"caps":["dm",{"connect":{"ports":[22]}}],"ttl_secs":86400}`.
pub async fn issue(client: &DaemonClient, grant_json: &str) -> Result<()> {
    let body = read_json_arg(grant_json)?;
    let resp = client.post("/grants", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x grant list` — grants this install's owner issued, with status.
pub async fn list(client: &DaemonClient) -> Result<()> {
    let resp = client.get("/grants").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x grant revoke GRANT_ID` — revoke with the owner key.
pub async fn revoke(client: &DaemonClient, grant_id: &str) -> Result<()> {
    let resp = client.delete(&format!("/grants/{grant_id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x grant received` — grants that name this install as grantee.
pub async fn received(client: &DaemonClient) -> Result<()> {
    let resp = client.get("/grants/received").await?;
    print_value(client.format(), &resp);
    Ok(())
}

fn read_json_arg(spec: &str) -> Result<serde_json::Value> {
    let text = if spec == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| anyhow::anyhow!("stdin read failed: {e}"))?;
        buf
    } else if spec.trim_start().starts_with(['{', '[']) {
        spec.to_string()
    } else {
        // `@path` or a bare path: every other `*_JSON` CLI argument is a file.
        let path = spec.strip_prefix('@').unwrap_or(spec);
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("read {path}: {e}"))?
    };
    serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("grant JSON parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_json_literal_parses_and_garbage_is_rejected() {
        let v = read_json_arg(r#"{"agents":["aa"],"caps":["dm"],"ttl_secs":60}"#)
            .expect("literal parses");
        assert_eq!(v["caps"][0], "dm");
        assert!(read_json_arg("{not json").is_err());
    }

    #[test]
    fn grant_json_bare_path_is_read_like_other_json_file_args() {
        // Scripts pass a file path, as for every other `*_JSON` argument;
        // treating it as literal JSON made `grant issue grant.json` fail.
        let p = std::env::temp_dir().join(format!("x0x-grant-{}.json", std::process::id()));
        std::fs::write(&p, r#"{"caps":["dm"]}"#).expect("write");
        let s = p.display().to_string();
        assert_eq!(read_json_arg(&s).expect("bare path")["caps"][0], "dm");
        assert_eq!(
            read_json_arg(&format!("@{s}")).expect("@path")["caps"][0],
            "dm"
        );
        let _ = std::fs::remove_file(&p);
        assert!(read_json_arg("/nonexistent/x0x-grant.json").is_err());
    }

    #[test]
    fn grant_paths_match_the_registry() {
        // The CLI must hit exactly the registered routes.
        for (cli, path) in [
            ("grant list", "/grants"),
            ("grant issue", "/grants"),
            ("grant revoke", "/grants/:id"),
            ("grant received", "/grants/received"),
        ] {
            let ep = crate::api::find_by_cli_name(cli).expect("registered");
            assert_eq!(ep.path, path, "{cli}");
        }
    }
}
