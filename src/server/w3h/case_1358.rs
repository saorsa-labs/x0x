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
//!    the group has 25 Active seats. The 25 seats converge: A, H and
//!    every member list all 25.
//! 3. A mints an invite for J through the public invite API. The request
//!    is addressed to J (`intended_joiner`) and has an explicit finite
//!    lifetime (`expiry_secs`, the 7-day default). These are the two
//!    fields that ADR 0112 V5 makes mandatory (D99, D104). On `main`
//!    there is no V5, so this request mints a V4 invite.
//! 4. A stops (crash). H stays online.
//! 5. J calls `POST /groups/join`.
//!
//! FINAL `j_holds_the_25_seat_base_roster_while_a_is_stopped`: within
//! 120 s of the join call, J lists all 25 base seats while A is stopped.
//!
//! Baseline on `main`: RED. A cannot mint an invite whose base roster has
//! more than `MAX_INVITE_ROSTER_ENTRIES` (20) entries (#646,
//! `src/groups/invite.rs`). With 21 seats (A, H and M01–M19), the mint
//! for M20, the 22nd seat, is `413 invite_too_large` with
//! `field = base_roster` and `size = 21`. So step 2 never reaches 25
//! seats. The red test pins that cause: the 413 body must name
//! `base_roster` and a size equal to the seats A holds, above 20. Any
//! other failure is INFRA, never the expected RED.
//!
//! Fidelity notes (what the GREEN slice must change):
//! - Step 3 sends the V5 request fields, but it mints a V4 invite on
//!   `main`. A V4 invite stays issuer-pinned (ADR 0112, D99), so with A
//!   stopped it cannot turn GREEN. The V5 slice must make this request
//!   mint the InviteV5 view that binds the base root R (or change the
//!   request to the V5 mint selector it adds), and assert that it did.
//! - ADR H6's setup also gives J an authenticated relationship with H and
//!   H's verified advert with the S5 bit. Those surfaces do not exist on
//!   `main`. On the S5/S6 branch the case must add them before step 5.
//! - The FINAL is the public observable only: J lists the 25 base seats
//!   while A is down. It does not show which holder served the roster
//!   (H or a member: all are online), and it does not check that J
//!   re-derives R. H6's S5 assertions (J sends H one
//!   `group_object_fetch_v1` for `roster_projection` at R, H admits it
//!   inside the membership lock, J re-derives R, J makes no other
//!   pre-member fetch) need S5 counters that `main` does not have. The
//!   S5 slice must add them.
//! - The test expects RED with the #646 cause pinned. When S5 (ADR 0111)
//!   and V5 (ADR 0112) merge, the implementing PR changes the expectation
//!   to GREEN and keeps the `_red_` name, as #1256 and #1357 did.
//! - ADR 0111's control C4 (no roster to a banned or forged joiner) is
//!   not in this case. It is a later slice.

#![cfg(test)]

use std::collections::BTreeSet;
use std::time::Duration;

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use serde_json::{json, Value};

const SEED: u64 = 0x1358_0006;
const CASE: &str = "w3h_1358_red_h6_invite_roster_above_cap";
const FINAL: &str = "j_holds_the_25_seat_base_roster_while_a_is_stopped";
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

/// The shipped default invite lifetime (`DEFAULT_EXPIRY_SECS`, 7 days),
/// sent explicitly for J's invite: ADR 0112 V5 needs a finite expiry
/// (D104).
const J_INVITE_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;

/// One mint through the public invite API with `request` as the body: the
/// link, or the #646 refusal body. Any other failure is an error (INFRA).
async fn mint(
    sim: &Sim,
    group: &str,
    request: Value,
) -> Result<std::result::Result<String, Value>> {
    let (status, body) = sim
        .api(
            "A",
            Method::POST,
            &format!("/groups/{group}/invite"),
            Some(request),
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
    let size_is_seats = body["size"].as_u64() == u64::try_from(seated.len()).ok();
    receipt.cause(
        CAUSE,
        Some(format!("seats={} body={body}", seated.len())),
        seated.len() > INVITE_ROSTER_CAP && size_is_seats,
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
        match mint(sim, &group, json!({})).await? {
            Ok(link) => seat_with(sim, &link, member, &group).await?,
            Err(body) => {
                record_refusal(sim, receipt, &group, &seated, &body).await?;
                return Ok(false);
            }
        }
        seated.insert(sim.agent_hex(member)?);
    }
    ensure!(seated.len() == SEATS, "seated {} of {SEATS}", seated.len());
    // Step 1 of H6: the 25 seats converge on every seated node.
    let mut holders = vec!["A", "H"];
    holders.extend_from_slice(MEMBERS);
    sim.until("the 25 seats converge", SETUP, async |s: &Sim| {
        for holder in &holders {
            if !lists_all(s, holder, &group, &seated).await {
                return false;
            }
        }
        true
    })
    .await?;
    receipt.evidence(
        "A seated 25 Active members and every seated node lists all of them",
        true,
        format!("seats={}", seated.len()),
        at(sim),
    );

    // Step 3: J's invite, addressed to J with a finite expiry (the ADR
    // 0112 V5 request fields, D99 and D104). On `main` this is a V4 invite.
    let request = json!({
        "intended_joiner": sim.agent_hex("J")?,
        "expiry_secs": J_INVITE_EXPIRY_SECS,
    });
    let link = match mint(sim, &group, request).await? {
        Ok(link) => link,
        Err(body) => {
            record_refusal(sim, receipt, &group, &seated, &body).await?;
            return Ok(false);
        }
    };

    // Steps 4 and 5: A stops, H stays online, J joins.
    sim.stop("A", RestartMode::Crash).await?;
    // H6 measures the 120 s from the join call.
    let started = sim.fabric().now();
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "J"})),
        )
        .await?;
    receipt.note(format!("J join with A stopped: {status} {body}"));
    let remaining = ROSTER_BUDGET.saturating_sub(sim.fabric().now().saturating_sub(started));
    let holds = sim
        .until(
            "J holds the 25-seat base roster with A stopped",
            remaining,
            async |s: &Sim| lists_all(s, "J", &group, &seated).await,
        )
        .await
        .is_ok();
    let elapsed = sim.fabric().now().saturating_sub(started);
    receipt.request_delivered(
        "J holds the 25-seat base roster within 120 s of the join call while A is stopped",
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

/// ADR 0111 H6 on `main`: RED, with the #646 cause pinned. The PR that
/// implements S5 (ADR 0111) and V5 (ADR 0112) changes this expectation to
/// GREEN and keeps the `_red_` name, as #1357 did.
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
