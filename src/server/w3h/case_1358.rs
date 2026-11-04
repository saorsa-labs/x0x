//! W3-H case for #1358 (ADR 0111 S5, Validation row H6, D95): an
//! invite-bound roster fetch above the invite roster cap (#646).
//!
//! Nodes: A (owner, the invite issuer), H (an Admin that stays online),
//! M01–M23 (members) and J (the joiner). Every node is a real daemon on
//! the sim fabric. The group is `private_secure` (TreeKEM). Public HTTP
//! only.
//!
//! 1. A creates the group and seats H through the public invite API. A
//!    promotes H to Admin.
//! 2. A seats M01–M23 through the public invite API, one at a time, so
//!    the group has 25 Active seats. H applies every add.
//! 3. A mints an invite for J through the public invite API. Above the
//!    cap this is ADR 0112's V5 view, which binds the base root R.
//! 4. A stops (crash). H stays online.
//! 5. J calls `POST /groups/join`.
//!
//! FINAL `j_holds_the_25_seat_base_roster_from_h_while_a_is_stopped`:
//! within 120 s of the join call, J lists all 25 base seats. A is
//! stopped, so on the ADR 0111/0112 path the roster comes from H (S5's
//! `roster_projection` fetch at R).
//!
//! Baseline on `main`: RED. A cannot mint an invite whose base roster has
//! more than `MAX_INVITE_ROSTER_ENTRIES` (20) entries (#646,
//! `src/groups/invite.rs`). With 21 seats seated (A, H and M01–M19),
//! the mint for M20, the 22nd seat, is `413 invite_too_large` with
//! `field = base_roster` and `size = 21`. So step 2 never reaches 25
//! seats. The red test pins that cause: the 413
//! body must name `base_roster` and a size above 20. Any other failure
//! is INFRA, never the expected RED.
//!
//! Fidelity notes:
//! - ADR H6's setup also gives J an authenticated relationship with H and
//!   H's verified advert with the S5 bit. Those surfaces do not exist on
//!   `main`. On the S5/S6 branch the case must add them before step 5.
//! - The S5 serving assertions (H admits the request inside the
//!   membership lock; J makes no other pre-member fetch) need S5
//!   counters that `main` does not have. The FINAL here is the public
//!   observable only: J holds the 25-seat base roster while A is down.
//! - The test expects RED until S5 (ADR 0111) and V5 (ADR 0112) merge.
//!   Then it flips to GREEN, as #1256 and #1357 did.

#![cfg(test)]

use std::collections::BTreeSet;
use std::time::Duration;

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use anyhow::ensure;
use axum::http::StatusCode;
use serde_json::{json, Value};

const SEED: u64 = 0x1358_0006;
const CASE: &str = "w3h_1358_red_h6_invite_roster_above_cap";
const FINAL: &str = "j_holds_the_25_seat_base_roster_from_h_while_a_is_stopped";
/// The shipped v4 invite roster cap (#646). A literal on purpose: if
/// `MAX_INVITE_ROSTER_ENTRIES` changes, this case must be read again.
const INVITE_ROSTER_CAP: usize = 20;
/// ADR 0111 H6: 25 Active seats (A, H and 23 members).
const SEATS: usize = 25;
const MEMBERS: &[&str] = &[
    "M01", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M09", "M10", "M11", "M12", "M13",
    "M14", "M15", "M16", "M17", "M18", "M19", "M20", "M21", "M22", "M23",
];
/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// ADR 0111 H6: J re-derives R within 120 s.
const ROSTER_BUDGET: Duration = Duration::from_secs(120);
/// The cause the red test pins.
const CAUSE: &str = "A's invite mint refuses a base roster over the 20-entry cap \
                     (#646): 413 invite_too_large, field base_roster";

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

fn labels() -> Vec<&'static str> {
    let mut labels = vec!["A", "H"];
    labels.extend_from_slice(MEMBERS);
    labels.push("J");
    labels
}

/// The #646 refusal: `413 invite_too_large` naming `base_roster` with a
/// size above the cap. Anything else is not the expected cause.
fn is_roster_cap_refusal(status: StatusCode, body: &Value) -> bool {
    status == StatusCode::PAYLOAD_TOO_LARGE
        && body["error"].as_str() == Some("invite_too_large")
        && body["field"].as_str() == Some("base_roster")
        && body["size"]
            .as_u64()
            .is_some_and(|size| size > INVITE_ROSTER_CAP as u64)
}

/// One mint through the public invite API: the link, or the #646 refusal
/// body. Any other failure is an error (INFRA).
async fn mint(sim: &Sim, group: &str) -> Result<std::result::Result<String, Value>> {
    let (status, body) = sim
        .api(
            "A",
            Method::POST,
            &format!("/groups/{group}/invite"),
            Some(json!({})),
        )
        .await?;
    if is_roster_cap_refusal(status, &body) {
        return Ok(Err(body));
    }
    ensure!(status.is_success(), "A invite: {status} {body}");
    Ok(Ok(body["invite_link"]
        .as_str()
        .context("invite response has no invite_link")?
        .to_string()))
}

/// Whether `observer` lists every agent in `want`.
async fn lists_all(sim: &Sim, observer: &str, group: &str, want: &BTreeSet<String>) -> bool {
    members(sim, observer, group).await.is_ok_and(|listed| {
        let listed: BTreeSet<String> = listed.into_iter().collect();
        want.is_subset(&listed)
    })
}

/// Join `member` with `link` and wait until A lists it and it is active.
async fn seat_with(sim: &Sim, link: &str, member: &str, group: &str) -> Result<()> {
    join(sim, member, link).await?;
    let hex = sim.agent_hex(member)?;
    sim.until(&format!("{member} seated"), SETUP, async |s: &Sim| {
        let listed = members(s, "A", group)
            .await
            .is_ok_and(|listed| listed.contains(&hex));
        listed
            && membership_state(s, member, group)
                .await
                .ok()
                .flatten()
                .as_deref()
                == Some("active")
    })
    .await
}

async fn promote_h(sim: &Sim, group: &str) -> Result<()> {
    let h_hex = sim.agent_hex("H")?;
    let (status, body) = sim
        .api(
            "A",
            Method::PATCH,
            &format!("/groups/{group}/members/{h_hex}/role"),
            Some(json!({"role": "admin"})),
        )
        .await?;
    ensure!(status.is_success(), "promote H: {status} {body}");
    sim.until("H sees its promotion", SETUP, async |s: &Sim| {
        let Ok(state) = s.state("H") else {
            return false;
        };
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, group).is_some_and(|(_, info)| {
            info.active_members().any(|member| {
                member.agent_id.eq_ignore_ascii_case(&h_hex)
                    && member.role.at_least(crate::groups::GroupRole::Admin)
            })
        })
    })
    .await
}

/// Record the #646 refusal and H's view of what A committed before it.
async fn record_refusal(
    sim: &Sim,
    receipt: &mut Receipt,
    group: &str,
    seated: &BTreeSet<String>,
    body: &Value,
) -> Result<()> {
    sim.until("H applies every add A committed", SETUP, async |s: &Sim| {
        lists_all(s, "H", group, seated).await
    })
    .await?;
    receipt.request_delivered(
        "H applied A's MemberAdded for every seat A committed before the refusal",
        lists_all(sim, "H", group, seated).await,
        format!("seats={}", seated.len()),
        at(sim),
    );
    receipt.cause(
        CAUSE,
        Some(format!("seats={} body={body}", seated.len())),
        seated.len() > INVITE_ROSTER_CAP,
        at(sim),
    );
    Ok(())
}

/// Runs the scenario. `Ok(true)` is the ADR 0111 H6 behaviour; `Ok(false)`
/// is the recorded #646 refusal.
async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<bool> {
    mesh(sim, &labels()).await?;
    let group = create_group(sim, "A").await?;
    let link = invite(sim, "A", &group).await?;
    seat_with(sim, &link, "H", &group).await?;
    promote_h(sim, &group).await?;
    let mut seated: BTreeSet<String> = [sim.agent_hex("A")?, sim.agent_hex("H")?]
        .into_iter()
        .collect();
    receipt.setup_done(at(sim));
    receipt.evidence(
        "A seated H through the public invite API and H is an Admin",
        true,
        format!("seats={}", seated.len()),
        at(sim),
    );

    // Step 2: 25 Active seats through the public invite API.
    for member in MEMBERS {
        match mint(sim, &group).await? {
            Ok(link) => seat_with(sim, &link, member, &group).await?,
            Err(body) => {
                record_refusal(sim, receipt, &group, &seated, &body).await?;
                return Ok(false);
            }
        }
        seated.insert(sim.agent_hex(member)?);
    }
    ensure!(seated.len() == SEATS, "seated {} of {SEATS}", seated.len());
    sim.until("H applies all 25 seats", SETUP, async |s: &Sim| {
        lists_all(s, "H", &group, &seated).await
    })
    .await?;
    receipt.evidence(
        "A seated 25 Active members and H lists all of them",
        true,
        format!("seats={}", seated.len()),
        at(sim),
    );

    // Step 3: J's invite. Above the cap this is ADR 0112's V5 view.
    let link = match mint(sim, &group).await? {
        Ok(link) => link,
        Err(body) => {
            record_refusal(sim, receipt, &group, &seated, &body).await?;
            return Ok(false);
        }
    };

    // Steps 4 and 5: A stops, H stays online, J joins.
    sim.stop("A", RestartMode::Crash).await?;
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "J"})),
        )
        .await?;
    receipt.note(format!("J join with A stopped: {status} {body}"));
    let started = sim.fabric().now();
    let holds = sim
        .until(
            "J holds the 25-seat base roster with A stopped",
            ROSTER_BUDGET,
            async |s: &Sim| lists_all(s, "J", &group, &seated).await,
        )
        .await
        .is_ok();
    let elapsed = sim.fabric().now().saturating_sub(started);
    receipt.request_delivered(
        "J holds the 25-seat base roster while A is stopped (H is the only issuer-side holder)",
        holds,
        format!("elapsed_ms={}", elapsed.as_millis()),
        at(sim),
    );
    Ok(holds)
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    let labels = labels();
    let passed = match Sim::start(case, seed, &labels).await {
        Ok(mut sim) => {
            let outcome = match scenario(&mut sim, &mut receipt).await {
                Ok(passed) => passed,
                Err(error) => {
                    receipt.infra(format!("{error:#}"), at(&sim));
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
        receipt.finish(FINAL, passed && !receipt.has_infra(), 0);
    }
    if receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

/// ADR 0111 H6 on `main`: RED, with the #646 cause pinned. It flips to
/// GREEN once S5 (ADR 0111) and V5 (ADR 0112) have merged.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
#[cfg_attr(
    target_os = "linux",
    ignore = "#1559: needs the W3-H entropy shim (nextest profile w3h / w3h-gate \
              --run-ignored all); plain suites run unseeded entropy, which is not an \
              observation"
)]
fn w3h_1358_red_h6_invite_roster_above_cap() -> Result<()> {
    super::block_on_paused(async move {
        let receipt = run(CASE, SEED).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Red),
            "{CASE}: expected RED (the #646 baseline), got {:?}",
            receipt.verdict()
        );
        ensure!(
            receipt.named_causes() == [CAUSE],
            "{CASE}: RED for another cause: {:?}",
            receipt.named_causes()
        );
        Ok(())
    })
}

#[test]
fn w3h_1358_roster_cap_refusal_is_closed() {
    let body =
        json!({"ok": false, "error": "invite_too_large", "field": "base_roster", "size": 21});
    assert!(is_roster_cap_refusal(StatusCode::PAYLOAD_TOO_LARGE, &body));
    let at_cap =
        json!({"ok": false, "error": "invite_too_large", "field": "base_roster", "size": 20});
    assert!(!is_roster_cap_refusal(
        StatusCode::PAYLOAD_TOO_LARGE,
        &at_cap
    ));
    let other_field =
        json!({"ok": false, "error": "invite_too_large", "field": "group_name", "size": 300});
    assert!(!is_roster_cap_refusal(
        StatusCode::PAYLOAD_TOO_LARGE,
        &other_field
    ));
    assert!(!is_roster_cap_refusal(StatusCode::TOO_MANY_REQUESTS, &body));
    let bytes = json!({"ok": false, "error": "invite_too_large", "actual_bytes": 50000});
    assert!(!is_roster_cap_refusal(
        StatusCode::PAYLOAD_TOO_LARGE,
        &bytes
    ));
}

#[test]
fn w3h_1358_labels_are_25_seats_and_a_joiner() {
    let labels = labels();
    assert_eq!(labels.len(), SEATS + 1);
    let unique: BTreeSet<&str> = labels.iter().copied().collect();
    assert_eq!(unique.len(), labels.len());
    assert_eq!(labels.first(), Some(&"A"));
    assert_eq!(labels.last(), Some(&"J"));
}
