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
    // GET responses are FLAT (`ApiResponse` flattens its `data`), so assert
    // the key is PRESENT and null — `r["data"]["human_name"].is_null()` was
    // true even when the field lived elsewhere and passed vacuously (#609).
    ensure!(
        r.get("human_name").is_some_and(|v| v.is_null()),
        "fresh profile has a present-but-null human_name (flat shape): {r}"
    );

    // Partial PUT: only display_name + human_name now, machine_name later —
    // an omitted field must never clobber a stored one.
    let put: Value = ca(&d)
        .put(d.url("/profile"))
        .json(&json!({
            "human_name": "Fixture Human",
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
        .json(&json!({ "machine_name": "fixture-desk" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ensure!(put2["ok"] == true, "second PUT ok: {put2}");
    ensure!(
        put2["profile"]["human_name"] == "Fixture Human",
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
    ensure!(r["human_name"] == "Fixture Human", "{r}");
    ensure!(r["display_name"] == "fae", "{r}");
    ensure!(r["machine_name"] == "fixture-desk", "{r}");

    // ADR-0036: /agent surfaces the same names.
    let agent: Value = ca(&d)
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ensure!(agent["human_name"] == "Fixture Human", "{agent}");
    ensure!(agent["display_name"] == "fae", "{agent}");
    ensure!(agent["machine_name"] == "fixture-desk", "{agent}");

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

/// #609: a fixture daemon must keep its identity INSIDE the fixture tempdir.
/// The original defect let the daemon derive `$HOME/.x0x-<name>`, reading
/// and writing key material under the operator's real home whenever the
/// runner did not redirect HOME (plain `cargo test -- --ignored`); the
/// nextest wrapper only contained it by accident of environment. Isolation
/// must hold by construction — an explicit `identity_dir` in the fixture
/// config — not by env. The harness additionally asserts at startup that
/// no home-derived instance dir appeared; this test pins the contract from
/// the client side so a harness regression cannot pass silently.
#[tokio::test]
#[ignore]
async fn fixture_identity_stays_out_of_home_dirs() -> Result<()> {
    let d = daemon().await;

    // Identity material must live under the fixture's own tempdir…
    let identity = d.data_dir().join("identity");
    ensure!(
        identity.join("machine.key").exists(),
        "identity must be fixture-owned at {}: missing machine.key",
        identity.display()
    );

    // …because the fixture config pins it there. If this line fails, the
    // harness regressed to home-derived identity resolution.
    let config = std::fs::read_to_string(d.data_dir().join("config.toml"))?;
    ensure!(
        config.contains(&format!("identity_dir = \"{}\"", identity.display())),
        "fixture config must pin identity_dir inside the fixture tempdir; config:\n{config}"
    );
    Ok(())
}
