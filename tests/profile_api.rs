//! ADR-0036 profile + owner endpoints over a real daemon (router wiring).
//!
//! All tests are `#[ignore]` — they require a running x0xd daemon.
//! Run with: cargo nextest run -E 'test(daemon_api_profile)' -- --ignored
//!
//! Before running: cargo build --bin x0xd
//!
//! The in-crate handler tests (`src/server/routes/profile.rs`) prove the
//! handler semantics (persistence, partial PUT, roster derivation); these
//! tests prove the ROUTER wiring end-to-end: route registration, bearer
//! auth, and the JSON shapes a real client sees.

use anyhow::{ensure, Result};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

async fn daemon() -> DaemonFixture {
    DaemonFixture::start("profile-api-test").await
}

fn ca(d: &DaemonFixture) -> reqwest::Client {
    d.authed_client(Duration::from_secs(10))
}

/// PUT/GET /profile + names in /agent + GET /owner/agents over the wire.
#[tokio::test]
#[ignore]
async fn daemon_api_profile_round_trip() -> Result<()> {
    let d = daemon().await;

    // Before any PUT, the profile exists but is unnamed.
    let r: Value = ca(&d)
        .get(d.url("/profile"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ensure!(r["ok"] == true, "GET /profile ok: {r}");
    ensure!(
        r["data"]["human_name"].is_null(),
        "fresh profile unnamed: {r}"
    );

    // Partial PUT: only display_name + human_name now, machine_name later —
    // an omitted field must never clobber a stored one.
    let put: Value = ca(&d)
        .put(d.url("/profile"))
        .json(&json!({
            "human_name": "David Irvine",
            "display_name": "fae",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ensure!(put["ok"] == true, "PUT /profile ok: {put}");

    let put2: Value = ca(&d)
        .put(d.url("/profile"))
        .json(&json!({ "machine_name": "m5-max" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ensure!(put2["ok"] == true, "second PUT ok: {put2}");
    ensure!(
        put2["profile"]["human_name"] == "David Irvine",
        "partial PUT keeps human_name: {put2}"
    );

    // GET reflects the merged profile.
    let r: Value = ca(&d)
        .get(d.url("/profile"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ensure!(r["data"]["human_name"] == "David Irvine", "{r}");
    ensure!(r["data"]["display_name"] == "fae", "{r}");
    ensure!(r["data"]["machine_name"] == "m5-max", "{r}");

    // ADR-0036: /agent surfaces the same names.
    let agent: Value = ca(&d)
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ensure!(agent["data"]["human_name"] == "David Irvine", "{agent}");
    ensure!(agent["data"]["display_name"] == "fae", "{agent}");
    ensure!(agent["data"]["machine_name"] == "m5-max", "{agent}");

    // The fixture daemon has no user identity, so there is no owner and the
    // roster endpoint must say so (409) rather than return an empty list
    // that would read as "owner has no agents".
    let resp = ca(&d).get(d.url("/owner/agents")).send().await.unwrap();
    ensure!(
        resp.status() == StatusCode::CONFLICT,
        "no owner => 409, got {}",
        resp.status()
    );
    Ok(())
}
