//! W3-H case `w3h_1161_card_import_invite` (#1161 / A08 liveness).
//!
//! Nodes: A (owner) and J (joiner). Public HTTP only.
//!
//! 1. A creates a `public_request_secure` group (discoverable card).
//! 2. J imports A's signed group card (`POST /groups/cards/import`), which
//!    inserts the inert local stub (owner-only roster, no seat, no secret).
//! 3. A mints a verified v4 invite. J posts `POST /groups/join`.
//! 4. Fixed: the stub clears and J completes the join (`active`, listed by A).
//!
//! Baseline on main: step 3 is 409 with the lineage-free `join failed` /
//! `fresh invite cannot replace` refusal (`JoinFailed` — no
//! `InertCardImportStub` clear). The test expects the fixed verdict, so a
//! checkout of main without this PR is RED. D55's #1150(a) exception does
//! not apply; this case is the A08 / D181 harness-first reproduction.

#![cfg(test)]

use std::time::Duration;

use super::control::{invite, local_membership, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use anyhow::ensure;
use axum::http::StatusCode;
use serde_json::json;

const SEED: u64 = 0x1161_0001;
const CASE: &str = "w3h_1161_card_import_invite";
const FINAL: &str = "card_import_stub_clears_and_invite_join_seats";
const JOIN_BUDGET: Duration = Duration::from_secs(120);

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

async fn create_discoverable_group(sim: &Sim, owner: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({
                "name": "w3h 1161 card",
                "display_name": owner,
                "preset": "public_request_secure"
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

async fn scenario(sim: &Sim, receipt: &mut Receipt) -> Result<bool> {
    mesh(sim, &["A", "J"]).await?;
    let group = create_discoverable_group(sim, "A").await?;
    receipt.setup_done(at(sim));

    let (card_status, card) = sim
        .api("A", Method::GET, &format!("/groups/cards/{group}"), None)
        .await?;
    ensure!(card_status.is_success(), "GET card: {card_status} {card}");
    ensure!(
        card.get("group_id").is_some(),
        "card payload missing group_id: {card}"
    );

    let (import_status, imported) = sim
        .api("J", Method::POST, "/groups/cards/import", Some(card))
        .await?;
    ensure!(
        import_status.is_success() && imported["ok"] != false,
        "card import: {import_status} {imported}"
    );

    let membership = local_membership(sim, "J", &group).await;
    let stub_not_member = membership.as_deref() == Some("not_member");
    receipt.evidence(
        "J holds a card-import stub (membership_state not_member)",
        stub_not_member,
        format!("membership_state={membership:?}"),
        at(sim),
    );
    ensure!(
        stub_not_member,
        "card import did not leave a not_member stub"
    );

    let link = invite(sim, "A", &group).await?;
    let (join_status, join_body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "J"})),
        )
        .await?;
    receipt.request_delivered(
        "POST /groups/join with verified invite after card import",
        true,
        format!("status={join_status} body={join_body}"),
        at(sim),
    );

    let refused = join_status == StatusCode::CONFLICT
        && join_body["error"].as_str().is_some_and(|error| {
            error.contains("join failed") && error.contains("fresh invite cannot replace")
        });
    if refused {
        receipt.cause(
            "POST /groups/join returns 409 JoinFailed on card-import stub",
            Some(format!("{join_status} {join_body}")),
            true,
            at(sim),
        );
        return Ok(false);
    }

    ensure!(
        join_status.is_success() && join_body["ok"] != false,
        "unexpected join response: {join_status} {join_body}"
    );
    receipt.note(format!("join accepted: {join_body}"));

    let j_hex = sim.agent_hex("J")?;
    sim.until(
        "J active after card-stub invite",
        JOIN_BUDGET,
        async |s: &Sim| {
            if local_membership(s, "J", &group).await.as_deref() != Some("active") {
                return false;
            }
            let Ok(list) = members(s, "A", &group).await else {
                return false;
            };
            list.iter().any(|id| id.eq_ignore_ascii_case(&j_hex))
        },
    )
    .await?;
    Ok(true)
}

async fn run() -> Receipt {
    let mut receipt = Receipt::new(CASE, SEED);
    let seated = match Sim::start(CASE, SEED, &["A", "J"]).await {
        Ok(sim) => {
            let outcome = match scenario(&sim, &mut receipt).await {
                Ok(seated) => seated,
                Err(error) => {
                    receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
                    false
                }
            };
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
            outcome
        }
        Err(error) => {
            receipt.infra(format!("sim: {error:#}"), 0);
            false
        }
    };
    if receipt.verdict().is_none() {
        receipt.finish(FINAL, seated && !receipt.has_infra(), 0);
    }
    if receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

/// #1161 on main: card-import stub + verified invite is 409 JoinFailed.
/// The test expects the fixed verdict, so this run is red until the stub
/// clear ships.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1161_card_import_invite() -> Result<()> {
    let receipt = run().await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{CASE}: expected GREEN, got {:?} (RED is the #1161 baseline on main)",
        receipt.verdict()
    );
    Ok(())
}
