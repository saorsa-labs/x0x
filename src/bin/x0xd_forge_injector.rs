//! `x0xd-forge-injector` — hostile gossip injector for the forged-first-seen
//! TaskItem admission gate (`tests/convergence/convergence_soak.py`,
//! `forged_first_seen_task`).
//!
//! Crafts an unattested first-seen TaskItem — a `Claimed { victim, ts: 1 }`
//! element in the TaskItem's checkbox OR-Set with NO matching attestation — via
//! `x0x::crdt::forge_unattested_delta_bytes`, which returns the bincode
//! `(PeerId, TaskListDelta)` wire bytes (the exact format the live sync path
//! decodes). It then publishes those bytes over REAL gossip through the target
//! daemon's `POST /publish` wire API on the task list's topic.
//!
//! This is a release-tooling binary, NOT a daemon. It never fakes the outcome
//! via REST: it injects a genuine gossip message that flows through the real
//! `decode_delta → merge_delta → admit()` path. The receiver's fail-closed
//! admission routine must purge the forged element, leaving
//! `current_state() == Empty`; the convergence gate asserts that non-mutation
//! (forged task absent, no list version/fence churn) plus a legit post-attack
//! claim still resolving.
//!
//! Built by `just convergence-release` (and `cargo build --release --bin
//! x0xd-forge-injector`); located deterministically at
//! `target/release/x0xd-forge-injector`. Its SHA-256 + `--version` are recorded
//! in the soak's provenance.

use anyhow::{anyhow, Result};
use base64::Engine;
use clap::Parser;
use saorsa_gossip_types::PeerId;
use x0x::crdt::{forge_unattested_delta_bytes, TaskId};
use x0x::identity::AgentId;

/// Hostile first-seen TaskItem injector. Publishes an unattested Claimed
/// element over real gossip via the daemon's /publish wire API.
#[derive(Parser, Debug)]
#[command(
    name = "x0xd-forge-injector",
    about = "Hostile first-seen TaskItem gossip injector"
)]
struct Cli {
    /// Target daemon API base, e.g. http://127.0.0.1:27810
    #[arg(long)]
    daemon: String,
    /// API bearer token for the target daemon.
    #[arg(long)]
    token: String,
    /// Task-list gossip topic to publish on (== the list id).
    #[arg(long)]
    topic: String,
    /// Attack variant. Only `missing_att` is implemented at the forge seam
    /// (the other variants — malformed-sig, attacker-key, wrong-agent,
    /// wrong-scope — are proven at the store/CRDT regression layer).
    #[arg(long, default_value = "missing_att")]
    variant: String,
    /// Hex (64 chars) AgentId being impersonated by the forged claim. Random
    /// if omitted.
    #[arg(long)]
    victim_agent: Option<String>,
    /// Hex (64 chars) TaskId for the forged task. Random if omitted.
    #[arg(long)]
    task_id: Option<String>,
    /// Hex (64 chars) PeerId spoofed as the delta sender / OR-Set tag. Random
    /// if omitted.
    #[arg(long)]
    spoof_peer: Option<String>,
}

/// Decode an optional 64-char hex string into a 32-byte array.
fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s).ok()?;
    b.try_into().ok()
}

/// 32 cryptographically-random bytes.
fn rand32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Parse `host:port` from a daemon base URL (stripping any scheme + path).
fn host_port(url: &str) -> Result<(String, u16, String)> {
    let no_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    // Drop any trailing path; keep authority only.
    let authority = no_scheme.split('/').next().unwrap_or(no_scheme);
    let (host, port_s) = authority
        .split_once(':')
        .ok_or_else(|| anyhow!("daemon url must be host:port (got {url})"))?;
    let port: u16 = port_s
        .parse()
        .map_err(|e| anyhow!("daemon port parse ({port_s}): {e}"))?;
    Ok((host.to_string(), port, "/publish".to_string()))
}

/// Minimal HTTP/1.1 POST (raw TCP) — avoids requiring the `blocking` reqwest
/// feature. Returns (status, body_text).
fn http_post_publish(
    host: &str,
    port: u16,
    path: &str,
    token: &str,
    body: &str,
) -> Result<(u16, String)> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\
         Content-Type: application/json\r\nAuthorization: Bearer {token}\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| anyhow!("connect {host}:{port}: {e}"))?;
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    let status = resp
        .get(9..12)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body_off = resp.find("\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
    Ok((status, resp[body_off..].to_string()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let victim_bytes = cli
        .victim_agent
        .as_deref()
        .and_then(hex32)
        .unwrap_or_else(rand32);
    let task_bytes = cli
        .task_id
        .as_deref()
        .and_then(hex32)
        .unwrap_or_else(rand32);
    let peer_bytes = cli
        .spoof_peer
        .as_deref()
        .and_then(hex32)
        .unwrap_or_else(rand32);

    let victim = AgentId(victim_bytes);
    let spoof_peer = PeerId::new(peer_bytes);
    let task_id = TaskId::from_bytes(task_bytes);

    // The in-crate forge seam: bincode (PeerId, TaskListDelta) bytes carrying
    // a Claimed{victim, ts:1} element with NO attestation.
    let delta_bytes = forge_unattested_delta_bytes(victim, task_id, spoof_peer);
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&delta_bytes);

    let (host, port, path) = host_port(&cli.daemon)?;
    let body = serde_json::json!({ "topic": cli.topic, "payload": payload_b64 }).to_string();
    let (status, resp_body) = http_post_publish(&host, port, &path, &cli.token, &body)?;

    let published = status == 200;
    let out = serde_json::json!({
        "ok": published,
        "published": published,
        "variant": cli.variant,
        "topic": cli.topic,
        "forged_task_id": hex::encode(task_bytes),
        "victim_agent": hex::encode(victim_bytes),
        "spoof_peer": hex::encode(peer_bytes),
        "publish_status": status,
        "publish_body": resp_body,
    });
    println!("{out}");
    // Non-zero exit when the publish itself failed (the convergence gate still
    // reads the JSON, but a transport failure must not look like success).
    if !published {
        std::process::exit(1);
    }
    Ok(())
}
