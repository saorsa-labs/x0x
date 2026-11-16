//! `x0x grant issue|list|revoke|received|renew|data` — ADR-0070 §2 share grants.

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
    let resp = client
        .delete(&format!("/grants/{}", encode_segment(grant_id)))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x grant received` — grants that name this install as grantee.
pub async fn received(client: &DaemonClient) -> Result<()> {
    let resp = client.get("/grants/received").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x grant data AGENT GROUP STORE [KEY]` — read a store on a granted
/// agent through a received `ShareCap::Data` grant (#1094): its keys, or
/// one value when KEY is given.
pub async fn data(
    client: &DaemonClient,
    agent: &str,
    group: &str,
    store: &str,
    key: Option<&str>,
) -> Result<()> {
    let resp = client
        .get(&granted_store_path(agent, group, store, key))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x grant data put AGENT GROUP STORE KEY VALUE [--content-type T]` —
/// set one value of a store on a granted agent through a received `rw`
/// `ShareCap::Data` grant (#1094 D2).
pub async fn data_put(
    client: &DaemonClient,
    agent: &str,
    group: &str,
    store: &str,
    key: &str,
    value: &str,
    content_type: Option<&str>,
) -> Result<()> {
    use base64::Engine;
    let mut body = serde_json::json!({
        "value": base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
    });
    if let Some(ct) = content_type {
        body["content_type"] = serde_json::Value::String(ct.to_string());
    }
    let resp = client
        .put(&granted_store_path(agent, group, store, Some(key)), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x grant data rm AGENT GROUP STORE KEY` — remove one key of a store
/// on a granted agent through a received `rw` `ShareCap::Data` grant
/// (#1094 D2).
pub async fn data_rm(
    client: &DaemonClient,
    agent: &str,
    group: &str,
    store: &str,
    key: &str,
) -> Result<()> {
    let resp = client
        .delete(&granted_store_path(agent, group, store, Some(key)))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// The `/grants/data/...` path for a store, or for one key of it. Each
/// part is one percent-encoded path segment.
fn granted_store_path(agent: &str, group: &str, store: &str, key: Option<&str>) -> String {
    let mut path = String::from("/grants/data");
    for segment in [agent, group, store].into_iter().chain(key) {
        path.push('/');
        path.push_str(&encode_segment(segment));
    }
    path
}

/// Percent-encode `text` as one URL path segment: every byte but the RFC
/// 3986 unreserved set (`A-Z a-z 0-9 - . _ ~`) becomes `%XX`, so a `/`,
/// `?`, `#` or `%` in user text cannot end or change the segment.
fn encode_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
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
            &format!("/grants/{}/renew", encode_segment(grant_id)),
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

    /// WHY (#1953 review): each path part is one percent-encoded segment.
    /// A raw `#` or `?` cut the key, so `put`/`rm` changed the wrong key.
    #[test]
    fn granted_store_path_encodes_each_segment() {
        let path = |key| granted_store_path("aa", "g1", "scratch", Some(key));
        assert_eq!(path("note"), "/grants/data/aa/g1/scratch/note");
        assert_eq!(
            path("note#draft"),
            "/grants/data/aa/g1/scratch/note%23draft"
        );
        assert_eq!(path("a?b"), "/grants/data/aa/g1/scratch/a%3Fb");
        assert_eq!(path("a/b"), "/grants/data/aa/g1/scratch/a%2Fb");
        assert_eq!(path("a b"), "/grants/data/aa/g1/scratch/a%20b");
        assert_eq!(path("100%"), "/grants/data/aa/g1/scratch/100%25");
        assert_eq!(path("-._~"), "/grants/data/aa/g1/scratch/-._~");
        assert_eq!(path("é"), "/grants/data/aa/g1/scratch/%C3%A9");
        assert_eq!(
            granted_store_path("a/a", "g?", "s#", None),
            "/grants/data/a%2Fa/g%3F/s%23"
        );
    }

    /// WHY (#1953 review): end to end, the CLI client sends the encoded
    /// path unchanged (no double encoding of `%`), and the daemon's route
    /// pattern with its `Path` extractor decodes each segment back to the
    /// exact text, a `/` included, for get, put and rm.
    #[tokio::test]
    async fn granted_store_keys_reach_the_route_exactly() {
        use axum::extract::Path;
        use std::sync::{Arc, Mutex};

        type Seen = Arc<Mutex<Vec<(String, [String; 4])>>>;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let record = |method: &'static str, seen: Seen| {
            move |Path((a, g, s, k)): Path<(String, String, String, String)>| async move {
                seen.lock()
                    .expect("lock")
                    .push((method.to_string(), [a, g, s, k]));
                axum::Json(serde_json::json!({"ok": true}))
            }
        };
        let app = axum::Router::new().route(
            "/grants/data/:agent/:group/:store/:key",
            axum::routing::get(record("GET", Arc::clone(&seen)))
                .put(record("PUT", Arc::clone(&seen)))
                .delete(record("DELETE", Arc::clone(&seen))),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let client =
            DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).expect("client");

        let keys = ["note#draft", "a?b=c&d", "a/b", "100%25 é", "plain"];
        for key in keys {
            data(&client, "aa", "g/1", "s#1", Some(key))
                .await
                .expect("get");
            data_put(&client, "aa", "g/1", "s#1", key, "v", None)
                .await
                .expect("put");
            data_rm(&client, "aa", "g/1", "s#1", key).await.expect("rm");
        }
        server.abort();
        let seen = seen.lock().expect("lock").clone();
        assert_eq!(seen.len(), keys.len() * 3, "{seen:?}");
        for (i, (method, parts)) in seen.iter().enumerate() {
            assert_eq!(method, ["GET", "PUT", "DELETE"][i % 3]);
            let want = ["aa", "g/1", "s#1", keys[i / 3]];
            assert_eq!(parts, &want.map(String::from), "{method}");
        }
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
            ("grant data keys", "/grants/data/:agent/:group/:store"),
            ("grant data get", "/grants/data/:agent/:group/:store/:key"),
            ("grant data put", "/grants/data/:agent/:group/:store/:key"),
            ("grant data rm", "/grants/data/:agent/:group/:store/:key"),
        ] {
            let ep = crate::api::find_by_cli_name(cli).expect("registered");
            assert_eq!(ep.path, path, "{cli}");
        }
    }
}
