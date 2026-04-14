//! `x0x group` subcommands.
//!
//! Thin wrappers around the named-groups REST endpoints registered in
//! `src/api/mod.rs::ENDPOINTS`. When you add a handler here, ensure its
//! `cli_name` in the registry matches the clap subcommand in
//! `src/bin/x0x.rs`. The `parity_cli` integration test guards this.

use crate::cli::{print_value, DaemonClient};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

// ── Core CRUD ───────────────────────────────────────────────────────────

/// `x0x group list` — GET /groups.
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/groups").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group create` — POST /groups.
pub async fn create(
    client: &DaemonClient,
    name: &str,
    description: Option<&str>,
    display_name: Option<&str>,
    preset: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = json!({ "name": name });
    if let Some(desc) = description {
        body["description"] = Value::String(desc.to_string());
    }
    if let Some(dn) = display_name {
        body["display_name"] = Value::String(dn.to_string());
    }
    if let Some(p) = preset {
        body["preset"] = Value::String(p.to_string());
    }
    let resp = client.post("/groups", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group info` — GET /groups/:id.
pub async fn info(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/groups/{group_id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group update` — PATCH /groups/:id.
pub async fn update(
    client: &DaemonClient,
    group_id: &str,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<()> {
    ensure!(
        name.is_some() || description.is_some(),
        "group update requires at least one of: --name, --description"
    );
    client.ensure_running().await?;
    let mut body = json!({});
    if let Some(n) = name {
        body["name"] = Value::String(n.to_string());
    }
    if let Some(d) = description {
        body["description"] = Value::String(d.to_string());
    }
    let resp = client.patch(&format!("/groups/{group_id}"), &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group members` — GET /groups/:id/members.
pub async fn members(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/groups/{group_id}/members")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group add-member` — POST /groups/:id/members.
pub async fn add_member(
    client: &DaemonClient,
    group_id: &str,
    agent_id: &str,
    display_name: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = json!({ "agent_id": agent_id });
    if let Some(dn) = display_name {
        body["display_name"] = Value::String(dn.to_string());
    }
    let resp = client
        .post(&format!("/groups/{group_id}/members"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group remove-member` — DELETE /groups/:id/members/:agent_id.
pub async fn remove_member(client: &DaemonClient, group_id: &str, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/groups/{group_id}/members/{agent_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group invite` — POST /groups/:id/invite.
pub async fn invite(client: &DaemonClient, group_id: &str, expiry_secs: u64) -> Result<()> {
    client.ensure_running().await?;
    let body = json!({ "expiry_secs": expiry_secs });
    let resp = client
        .post(&format!("/groups/{group_id}/invite"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group join` — POST /groups/join.
pub async fn join(
    client: &DaemonClient,
    invite_link: &str,
    display_name: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = json!({ "invite": invite_link });
    if let Some(dn) = display_name {
        body["display_name"] = Value::String(dn.to_string());
    }
    let resp = client.post("/groups/join", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group set-name` — PUT /groups/:id/display-name.
pub async fn set_name(client: &DaemonClient, group_id: &str, name: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = json!({ "name": name });
    let resp = client
        .put(&format!("/groups/{group_id}/display-name"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group leave` — DELETE /groups/:id.
pub async fn leave(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.delete(&format!("/groups/{group_id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

// ── Policy / roles / bans ───────────────────────────────────────────────

/// `x0x group policy` — PATCH /groups/:id/policy.
///
/// Accepts either a preset name via `--preset` or individual axes via the
/// other flags. When both are supplied, the daemon applies the preset
/// first and overlays the individual axes. At least one field must be
/// set; the CLI rejects empty patches before contacting the daemon.
#[allow(clippy::too_many_arguments)]
pub async fn policy(
    client: &DaemonClient,
    group_id: &str,
    preset: Option<&str>,
    discoverability: Option<&str>,
    admission: Option<&str>,
    confidentiality: Option<&str>,
    read_access: Option<&str>,
    write_access: Option<&str>,
) -> Result<()> {
    ensure!(
        preset.is_some()
            || discoverability.is_some()
            || admission.is_some()
            || confidentiality.is_some()
            || read_access.is_some()
            || write_access.is_some(),
        "group policy requires at least one of: --preset, --discoverability, --admission, --confidentiality, --read-access, --write-access"
    );
    client.ensure_running().await?;
    let mut body = json!({});
    if let Some(v) = preset {
        body["preset"] = Value::String(v.to_string());
    }
    if let Some(v) = discoverability {
        body["discoverability"] = Value::String(v.to_string());
    }
    if let Some(v) = admission {
        body["admission"] = Value::String(v.to_string());
    }
    if let Some(v) = confidentiality {
        body["confidentiality"] = Value::String(v.to_string());
    }
    if let Some(v) = read_access {
        body["read_access"] = Value::String(v.to_string());
    }
    if let Some(v) = write_access {
        body["write_access"] = Value::String(v.to_string());
    }
    let resp = client
        .patch(&format!("/groups/{group_id}/policy"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group set-role` — PATCH /groups/:id/members/:agent_id/role.
pub async fn set_role(
    client: &DaemonClient,
    group_id: &str,
    agent_id: &str,
    role: &str,
) -> Result<()> {
    client.ensure_running().await?;
    let body = json!({ "role": role });
    let resp = client
        .patch(
            &format!("/groups/{group_id}/members/{agent_id}/role"),
            &body,
        )
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group ban` — POST /groups/:id/ban/:agent_id.
pub async fn ban(client: &DaemonClient, group_id: &str, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/groups/{group_id}/ban/{agent_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group unban` — DELETE /groups/:id/ban/:agent_id.
pub async fn unban(client: &DaemonClient, group_id: &str, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/groups/{group_id}/ban/{agent_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

// ── Join requests ───────────────────────────────────────────────────────

/// `x0x group requests` — GET /groups/:id/requests.
pub async fn requests(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/groups/{group_id}/requests")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group request-access` — POST /groups/:id/requests.
pub async fn request_access(
    client: &DaemonClient,
    group_id: &str,
    message: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let body = match message {
        Some(m) => json!({ "message": m }),
        None => json!({}),
    };
    let resp = client
        .post(&format!("/groups/{group_id}/requests"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group approve-request` — POST /groups/:id/requests/:request_id/approve.
pub async fn approve_request(
    client: &DaemonClient,
    group_id: &str,
    request_id: &str,
) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/groups/{group_id}/requests/{request_id}/approve"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group reject-request` — POST /groups/:id/requests/:request_id/reject.
pub async fn reject_request(client: &DaemonClient, group_id: &str, request_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/groups/{group_id}/requests/{request_id}/reject"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group cancel-request` — DELETE /groups/:id/requests/:request_id.
pub async fn cancel_request(client: &DaemonClient, group_id: &str, request_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/groups/{group_id}/requests/{request_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

// ── Discovery ───────────────────────────────────────────────────────────

/// `x0x group discover` — GET /groups/discover?q=...
pub async fn discover(client: &DaemonClient, query: Option<&str>) -> Result<()> {
    client.ensure_running().await?;
    let resp = match query {
        Some(q) if !q.is_empty() => client.get_query("/groups/discover", &[("q", q)]).await?,
        _ => client.get("/groups/discover").await?,
    };
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group discover-nearby` — GET /groups/discover/nearby.
pub async fn discover_nearby(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/groups/discover/nearby").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group discover-subscriptions` — GET /groups/discover/subscriptions.
pub async fn discover_subscriptions(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/groups/discover/subscriptions").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group discover-subscribe` — POST /groups/discover/subscribe.
pub async fn discover_subscribe(
    client: &DaemonClient,
    kind: &str,
    key: Option<&str>,
    shard: Option<u32>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = json!({ "kind": kind });
    if let Some(k) = key {
        body["key"] = Value::String(k.to_string());
    }
    if let Some(s) = shard {
        body["shard"] = Value::Number(s.into());
    }
    let resp = client.post("/groups/discover/subscribe", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group discover-unsubscribe` — DELETE /groups/discover/subscribe/:kind/:shard.
pub async fn discover_unsubscribe(client: &DaemonClient, kind: &str, shard: u32) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/groups/discover/subscribe/{kind}/{shard}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group card` — GET /groups/cards/:id.
pub async fn card(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/groups/cards/{group_id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group card-import` — POST /groups/cards/import.
///
/// Takes a path to a JSON file containing a signed `GroupCard`. Stdin
/// support: pass `-` as the path.
pub async fn card_import(client: &DaemonClient, path: &str) -> Result<()> {
    client.ensure_running().await?;
    let raw = if path == "-" {
        use std::io::Read as _;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("read card from stdin")?;
        s
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read card from {path}"))?
    };
    let card: Value = serde_json::from_str(&raw).context("parse card JSON")?;
    let resp = client.post("/groups/cards/import", &card).await?;
    print_value(client.format(), &resp);
    Ok(())
}

// ── Public messaging (Phase E) ──────────────────────────────────────────

/// `x0x group send` — POST /groups/:id/send.
pub async fn send(
    client: &DaemonClient,
    group_id: &str,
    body_text: &str,
    kind: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut req = json!({ "body": body_text });
    if let Some(k) = kind {
        req["kind"] = Value::String(k.to_string());
    }
    let resp = client
        .post(&format!("/groups/{group_id}/send"), &req)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group messages` — GET /groups/:id/messages.
pub async fn messages(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/groups/{group_id}/messages")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

// ── State-commit chain (Phase D.3) ──────────────────────────────────────

/// `x0x group state` — GET /groups/:id/state.
pub async fn state(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/groups/{group_id}/state")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group state-seal` — POST /groups/:id/state/seal.
pub async fn state_seal(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/groups/{group_id}/state/seal"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group state-withdraw` — POST /groups/:id/state/withdraw.
pub async fn state_withdraw(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/groups/{group_id}/state/withdraw"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

// ── Secure plane (Phase D.2) ────────────────────────────────────────────

/// `x0x group secure-encrypt` — POST /groups/:id/secure/encrypt.
///
/// `payload` is encoded as base64 before being sent.
pub async fn secure_encrypt(client: &DaemonClient, group_id: &str, payload: &[u8]) -> Result<()> {
    use base64::Engine as _;
    client.ensure_running().await?;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let body = json!({ "payload_b64": payload_b64 });
    let resp = client
        .post(&format!("/groups/{group_id}/secure/encrypt"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group secure-decrypt` — POST /groups/:id/secure/decrypt.
pub async fn secure_decrypt(
    client: &DaemonClient,
    group_id: &str,
    ciphertext_b64: &str,
    nonce_b64: &str,
    secret_epoch: u64,
) -> Result<()> {
    client.ensure_running().await?;
    let body = json!({
        "ciphertext_b64": ciphertext_b64,
        "nonce_b64": nonce_b64,
        "secret_epoch": secret_epoch,
    });
    let resp = client
        .post(&format!("/groups/{group_id}/secure/decrypt"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group secure-reseal` — POST /groups/:id/secure/reseal.
pub async fn secure_reseal(client: &DaemonClient, group_id: &str, recipient: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = json!({ "recipient": recipient });
    let resp = client
        .post(&format!("/groups/{group_id}/secure/reseal"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group secure-open-envelope` — POST /groups/secure/open-envelope.
///
/// Reads the envelope JSON from `path` (or stdin if `path == "-"`).
/// Adversarial test endpoint: attempts to decrypt the envelope with this
/// daemon's KEM private key.
pub async fn secure_open_envelope(client: &DaemonClient, path: &str) -> Result<()> {
    client.ensure_running().await?;
    let raw = if path == "-" {
        use std::io::Read as _;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("read envelope from stdin")?;
        s
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read envelope from {path}"))?
    };
    let envelope: Value = serde_json::from_str(&raw).context("parse envelope JSON")?;
    let resp = client
        .post("/groups/secure/open-envelope", &envelope)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}
