//! `x0x grant issue|list|revoke|received|renew` — ADR-0070 §2 share grants.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x grant issue GRANT_JSON` — GRANT_JSON is the `POST /grants` body
/// (literal, `@path` or a bare path, or `-` for stdin), e.g.
/// `{"grantee_user":"<hex>","agents":["<hex>"],"caps":["dm",{"connect":{"ports":[22]}}],"ttl_secs":86400}`.
pub async fn issue(client: &DaemonClient, grant_json: &str, no_names: bool) -> Result<()> {
    let body = issue_body(grant_json, no_names)?;
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

/// `x0x grant renew GRANT_ID [--ttl-secs N] [--deliver-to AGENT]... [--no-names]` — renew an
/// issued grant (#1350): a new grant, valid from now for at most 90 days.
pub async fn renew(
    client: &DaemonClient,
    grant_id: &str,
    ttl_secs: Option<u64>,
    deliver_to: &[String],
    no_names: bool,
) -> Result<()> {
    let resp = client
        .post(
            &format!("/grants/{grant_id}/renew"),
            &renew_body(ttl_secs, deliver_to, no_names),
        )
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// The `POST /grants/:id/renew` body: only the fields the user set, so the
/// daemon's defaults apply to the rest.
fn renew_body(ttl_secs: Option<u64>, deliver_to: &[String], no_names: bool) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    if let Some(ttl) = ttl_secs {
        body.insert("ttl_secs".to_string(), serde_json::json!(ttl));
    }
    if !deliver_to.is_empty() {
        body.insert("deliver_to".to_string(), serde_json::json!(deliver_to));
    }
    if no_names {
        body.insert("include_names".to_string(), serde_json::json!(false));
    }
    serde_json::Value::Object(body)
}

/// The `POST /grants` body for `x0x grant issue`: GRANT_JSON as given, with
/// `include_names: false` added for `--no-names` (ADR 0079).
fn issue_body(grant_json: &str, no_names: bool) -> Result<serde_json::Value> {
    let mut body = read_json_arg(grant_json)?;
    if no_names {
        let obj = body
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("--no-names needs a JSON object grant body"))?;
        obj.insert("include_names".to_string(), serde_json::json!(false));
    }
    Ok(body)
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

    /// WHY (ADR 0079, #1831 review): `--no-names` sets
    /// `include_names: false` in the body and overrides a `true` in
    /// GRANT_JSON; without the flag the body is sent as given, so the
    /// daemon's default (`true`) applies. A non-object body is refused.
    #[test]
    fn no_names_sets_include_names_false_in_the_body() {
        let grant = r#"{"agents":["aa"],"caps":["dm"],"ttl_secs":60}"#;
        let body = issue_body(grant, true).expect("body");
        assert_eq!(body["include_names"], serde_json::json!(false));
        assert_eq!(body["caps"][0], "dm");
        let body = issue_body(grant, false).expect("body");
        assert!(body.get("include_names").is_none(), "{body}");
        let explicit = r#"{"agents":["aa"],"caps":["dm"],"ttl_secs":60,"include_names":true}"#;
        assert_eq!(
            issue_body(explicit, true).expect("body")["include_names"],
            serde_json::json!(false)
        );
        assert!(issue_body("[1,2]", true).is_err());
    }

    /// WHY (#1350): `grant renew` sends only the fields the user set, so
    /// the daemon's defaults (90 days, names included) apply otherwise.
    #[test]
    fn renew_body_sends_only_set_fields() {
        assert_eq!(renew_body(None, &[], false), serde_json::json!({}));
        assert_eq!(
            renew_body(Some(600), &["aa".to_string()], true),
            serde_json::json!({"ttl_secs": 600, "deliver_to": ["aa"], "include_names": false})
        );
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
            ("grant renew", "/grants/:id/renew"),
        ] {
            let ep = crate::api::find_by_cli_name(cli).expect("registered");
            assert_eq!(ep.path, path, "{cli}");
        }
    }
}
