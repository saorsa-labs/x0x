//! W3-H case `w3h_1471_forged_card_import_invite` (#1471 / A08 liveness).
//!
//! Nodes: A (real owner), X (attacker), J (joiner).
//!
//! 1. A creates a `public_request_secure` group (discoverable card).
//! 2. X forges a signed `GroupCard` that reuses A's `group_id` but names X
//!    as `owner_agent_id` / authority (card owner text is unauthenticated).
//! 3. J imports that forged card (`POST /groups/cards/import`) → inert stub
//!    with attacker as sole admin.
//! 4. A mints a verified v4 invite. J posts `POST /groups/join`.
//! 5. On unfixed main: step 4 refuses (RED). On the #1472 fix: the forged
//!    stub clears, J reaches `active`, and encrypted round trip succeeds.
//!
//! Baseline on unfixed main (#1463 creator-equality gate): step 4 is 409
//! with the lineage-free `join failed` / `fresh invite cannot replace`
//! refusal. This red-proof branch asserts RED so nextest `--stress-count
//! 20` can finish (CI `--expect …=RED`). GREEN is demonstrated on #1472
//! with the fix. D55's #1150(a) exception does not apply.

#![cfg(test)]

use std::time::Duration;

use super::control::{
    invite, local_membership, members, mesh, open_store, put_value, read_value, try_open_store,
};
use super::receipt::{Receipt, Verdict};
use super::*;
use anyhow::{ensure, Context};
use axum::http::StatusCode;
use serde_json::json;

const SEED: u64 = 0x1471_0001;
const CASE: &str = "w3h_1471_forged_card_import_invite";
const FINAL: &str = "forged_card_stub_clears_and_encrypted_round_trip";
const JOIN_BUDGET: Duration = Duration::from_secs(120);
const STORE_BUDGET: Duration = Duration::from_secs(90);

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
                "name": "w3h 1471 forged card",
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

/// Attacker-signed card: real `group_id`, forged owner/authority = X.
async fn forge_attacker_card(sim: &Sim, group: &str) -> Result<serde_json::Value> {
    let (card_status, real_card) = sim
        .api("A", Method::GET, &format!("/groups/cards/{group}"), None)
        .await?;
    ensure!(
        card_status.is_success(),
        "GET real card: {card_status} {real_card}"
    );

    let mut card: crate::groups::GroupCard =
        serde_json::from_value(real_card).context("decode real GroupCard")?;
    let x_state = sim.state("X")?;
    let x_hex = sim.agent_hex("X")?;
    card.owner_agent_id = x_hex;
    card.admin_count = 1;
    card.member_count = 1;
    card.sign(x_state.agent.identity().agent_keypair())
        .context("X signs forged card")?;
    ensure!(
        card.verify_signature().is_ok(),
        "forged card must verify under X"
    );
    ensure!(
        card.group_id == group,
        "forged card must keep the real group id"
    );
    serde_json::to_value(card).context("encode forged GroupCard")
}

/// True when J can open A's group store and read A's ciphertext.
async fn encrypted_round_trip(sim: &Sim, group: &str, store: &str) -> bool {
    match try_open_store(sim, "J", group).await {
        Ok(id) if id == store => {
            read_value(sim, "J", store, "w3h-1471").await.as_deref() == Some("delivered")
        }
        _ => false,
    }
}

async fn scenario(sim: &Sim, receipt: &mut Receipt) -> Result<bool> {
    mesh(sim, &["A", "X", "J"]).await?;
    let group = create_discoverable_group(sim, "A").await?;
    receipt.setup_done(at(sim));

    let forged = forge_attacker_card(sim, &group).await?;
    let x_hex = sim.agent_hex("X")?;
    receipt.evidence(
        "X forged a signed card for A's group_id with X as owner",
        forged["owner_agent_id"]
            .as_str()
            .is_some_and(|owner| owner.eq_ignore_ascii_case(&x_hex))
            && forged["group_id"].as_str() == Some(group.as_str()),
        format!(
            "owner={} group_id={}",
            forged["owner_agent_id"], forged["group_id"]
        ),
        at(sim),
    );

    let (import_status, imported) = sim
        .api("J", Method::POST, "/groups/cards/import", Some(forged))
        .await?;
    ensure!(
        import_status.is_success() && imported["ok"] != false,
        "forged card import: {import_status} {imported}"
    );

    let membership = local_membership(sim, "J", &group).await;
    let stub_not_member = membership.as_deref() == Some("not_member");
    receipt.evidence(
        "J holds a forged card-import stub (membership_state not_member)",
        stub_not_member,
        format!("membership_state={membership:?}"),
        at(sim),
    );
    ensure!(
        stub_not_member,
        "forged card import did not leave a not_member stub"
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
        "POST /groups/join with verified invite after forged card import",
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
            "POST /groups/join returns 409 JoinFailed on forged card-import stub",
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
    let a_hex = sim.agent_hex("A")?;
    sim.until(
        "J active after forged-stub invite",
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

    // Forged admin must not remain on A's roster view of the live group.
    let a_members = members(sim, "A", &group).await?;
    let forged_absent = !a_members.iter().any(|id| id.eq_ignore_ascii_case(&x_hex));
    let authority_present = a_members.iter().any(|id| id.eq_ignore_ascii_case(&a_hex));
    receipt.evidence(
        "A's roster has verified authority and no forged attacker admin",
        forged_absent && authority_present,
        format!("members={a_members:?}"),
        at(sim),
    );
    ensure!(
        forged_absent && authority_present,
        "forged admin still present or verified authority missing: {a_members:?}"
    );

    let store = open_store(sim, "A", &group).await?;
    put_value(sim, "A", &store, "w3h-1471", "delivered").await?;

    sim.until(
        "J encrypted round trip after forged-stub invite",
        STORE_BUDGET,
        async |s: &Sim| encrypted_round_trip(s, &group, &store).await,
    )
    .await
    .context("encrypted round trip on fixed path")?;

    receipt.evidence(
        "J opens A's store and reads A's encrypted write",
        true,
        format!("store={store} key=w3h-1471"),
        at(sim),
    );
    Ok(true)
}

async fn run() -> Receipt {
    let mut receipt = Receipt::new(CASE, SEED);
    let seated = match Sim::start(CASE, SEED, &["A", "X", "J"]).await {
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

/// #1471 on main: forged card-import stub + verified invite is 409 JoinFailed.
/// Red-proof branch: the test asserts RED so nextest stress can complete
/// 20 iterations (CI `--expect …=RED` alone cannot override a Green ensure).
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1471_forged_card_import_invite() -> Result<()> {
    let receipt = run().await;
    ensure!(
        receipt.verdict() == Some(Verdict::Red),
        "{CASE}: expected RED on unfixed main, got {:?}",
        receipt.verdict()
    );
    Ok(())
}
