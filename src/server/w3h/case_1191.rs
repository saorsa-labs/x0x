//! W3-H case `w3h_1191_attempt_exit` (#1191, ADR 0114 `s8b_1191_attempt_exit`).
//!
//! Nodes: A (owner) and J (joiner). Public HTTP only.
//!
//! 1. A creates a `private_secure` group. Every frame from A to J except
//!    plane hello is dropped, so J's first join times out with no carry and
//!    no local row. A's roster still seats J.
//! 2. J redeems a fresh invite whose base already seats J. J reports
//!    `active` and installs no TreeKEM group. The poll then runs to its
//!    120 s deadline while that seat still wins.
//! 3. The drop lifts. A removes J and the removal is delivered. A mints
//!    another invite and J posts `POST /groups/join` on the same process.
//! 4. A few seconds later, the case checks that a newly started attempt is
//!    still the current one (a late finalizer of the ended attempt must
//!    not erase it).
//!
//! Baseline on main: the re-invite is 409 `join_already_pending`.
//! Fixed: the POST is accepted and the new attempt survives that tick.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::control::{create_group, invite, join, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass, Write};
use anyhow::ensure;
use axum::http::StatusCode;
use serde_json::json;

const SEED: u64 = 0x1191_0001;
const CASE: &str = "w3h_1191_attempt_exit";
const FINAL: &str = "reinvite_starts_a_new_attempt";
/// `JOIN_RESULT_POLL_TIMEOUT` plus margin for the poll that started inside
/// the redeem barrier.
const POLL_DEADLINE: Duration = Duration::from_secs(130);
const LATER_TICK: Duration = Duration::from_secs(4);

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

/// Drops every A→J frame except plane hello while held.
struct AwayFromJ {
    held: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl AwayFromJ {
    fn install(sim: &Sim) -> Result<Self> {
        let src = sim.peer("A")?.0;
        let dst = sim.peer("J")?.0;
        let held = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_dropped) = (Arc::clone(&held), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write: &Write| {
            let blocked = rule_held.load(Ordering::SeqCst)
                && write.lane.src == src
                && write.lane.dst == dst
                && write.lane.class != LaneClass::PlaneHello;
            if blocked {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { held, dropped })
    }

    fn set(&self, held: bool) {
        self.held.store(held, Ordering::SeqCst);
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

async fn membership(sim: &Sim, label: &str, group: &str) -> Result<Option<String>> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(body["membership_state"].as_str().map(str::to_string))
}

async fn join_outcome(sim: &Sim, group: &str) -> Result<Option<String>> {
    let (_status, body) = sim
        .request(
            "J",
            Method::GET,
            &format!("/groups/{group}/join-status"),
            None,
        )
        .await?;
    Ok(body["last_join_outcome"]["outcome"]
        .as_str()
        .map(str::to_string))
}

async fn has_treekem(sim: &Sim, group: &str) -> Result<bool> {
    Ok(sim
        .state("J")?
        .treekem_groups
        .read()
        .await
        .contains_key(group))
}

fn attempt_ids(sim: &Sim, group: &str) -> Result<Vec<String>> {
    let state = sim.state("J")?;
    let attempts = state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ids: Vec<String> = attempts
        .values()
        .filter(|attempt| {
            attempt.local_group_key == group || attempt.invite_group_id.eq_ignore_ascii_case(group)
        })
        .map(|attempt| attempt.attempt_id.clone())
        .collect();
    drop(attempts);
    ids.sort();
    Ok(ids)
}

async fn listed(sim: &Sim, label: &str, group: &str, agent: &str) -> Result<bool> {
    Ok(members(sim, label, group)
        .await?
        .iter()
        .any(|id| id == agent))
}

async fn scenario(sim: &Sim, receipt: &mut Receipt) -> Result<()> {
    mesh(sim, &["A", "J"]).await?;
    let group = create_group(sim, "A").await?;
    let block = AwayFromJ::install(sim)?;
    receipt.setup_done(at(sim));

    block.set(true);
    let link = invite(sim, "A", &group).await?;
    join(sim, "J", &link).await?;
    let j = sim.agent_hex("J")?;
    sim.until(
        "A seats J while J receives no carry",
        secs(180),
        async |s| listed(s, "A", &group, &j).await.unwrap_or(false),
    )
    .await?;
    let seated = listed(sim, "A", &group, &j).await?;
    receipt.evidence(
        "A seated J while every A-to-J frame except plane hello was dropped",
        seated,
        format!("dropped={}", block.dropped()),
        at(sim),
    );

    sim.until(
        "J's no-carry poll records timed_out",
        secs(160),
        async |s| join_outcome(s, &group).await.ok().flatten().as_deref() == Some("timed_out"),
    )
    .await?;
    let after_timeout = membership(sim, "J", &group).await?;
    let outcome = join_outcome(sim, &group).await?;
    let no_treekem = !has_treekem(sim, &group).await?;
    receipt.evidence(
        "the no-carry timeout left J with no local row and no TreeKEM group",
        after_timeout.is_none() && outcome.as_deref() == Some("timed_out") && no_treekem,
        format!(
            "membership={after_timeout:?} outcome={outcome:?} treekem={}",
            !no_treekem
        ),
        at(sim),
    );

    let seated_link = invite(sim, "A", &group).await?;
    let (redeem_status, redeem_body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": seated_link, "display_name": "J"})),
        )
        .await?;
    let redeem_state = membership(sim, "J", &group).await?;
    let redeem_attempts = attempt_ids(sim, &group)?;
    let redeem_treekem = has_treekem(sim, &group).await?;
    receipt.evidence(
        "the base-seated invite reports active, installs no TreeKEM group, and leaves an attempt",
        redeem_status.is_success()
            && redeem_body["join_state"].as_str() == Some("active")
            && redeem_state.as_deref() == Some("active")
            && !redeem_treekem
            && !redeem_attempts.is_empty(),
        format!(
            "status={redeem_status} body={redeem_body} membership={redeem_state:?} \
             attempts={redeem_attempts:?} treekem={redeem_treekem}"
        ),
        at(sim),
    );

    sim.within("keyless poll deadline", POLL_DEADLINE + secs(10), async {
        tokio::time::sleep(POLL_DEADLINE).await;
    })
    .await?;
    let still_active = membership(sim, "J", &group).await?;
    let still_keyless = !has_treekem(sim, &group).await?;
    let after_deadline = attempt_ids(sim, &group)?;
    receipt.evidence(
        "after the keyless poll deadline J is still active and still has no TreeKEM group",
        still_active.as_deref() == Some("active") && still_keyless,
        format!(
            "membership={still_active:?} treekem={} attempts={after_deadline:?}",
            !still_keyless
        ),
        at(sim),
    );
    receipt.note(format!(
        "attempts after the keyless deadline (main keeps them): {after_deadline:?}"
    ));

    block.set(false);
    let (remove_status, remove_body) = sim
        .api(
            "A",
            Method::DELETE,
            &format!("/groups/{group}/members/{j}"),
            None,
        )
        .await?;
    ensure!(
        remove_status.is_success(),
        "remove-member: {remove_status} {remove_body}"
    );
    sim.until("J applies A's removal", secs(60), async |s| {
        let gone_on_j = membership(s, "J", &group)
            .await
            .ok()
            .is_some_and(|state| state.as_deref() != Some("active"));
        let gone_on_a = listed(s, "A", &group, &j).await.ok() == Some(false);
        gone_on_j && gone_on_a
    })
    .await?;
    let j_after = membership(sim, "J", &group).await?;
    let a_still = listed(sim, "A", &group, &j).await?;
    receipt.request_delivered(
        "J applied A's MemberRemoved",
        j_after.as_deref() != Some("active") && !a_still,
        format!("j_membership={j_after:?} a_lists_j={a_still}"),
        at(sim),
    );

    let again = invite(sim, "A", &group).await?;
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": again, "display_name": "J"})),
        )
        .await?;
    let pending =
        status == StatusCode::CONFLICT && body["error"].as_str() == Some("join_already_pending");
    if pending {
        receipt.cause(
            "POST /groups/join returns 409 join_already_pending",
            Some(format!("{status} {body}")),
            true,
            at(sim),
        );
    }
    let accepted = status.is_success() && body["ok"] != false && !pending;
    let started = attempt_ids(sim, &group)?;
    let mut erased = false;
    if accepted {
        sim.within("later finalizer tick", LATER_TICK + secs(5), async {
            tokio::time::sleep(LATER_TICK).await;
        })
        .await?;
        let later = attempt_ids(sim, &group)?;
        let keyed = has_treekem(sim, &group).await?;
        let member = membership(sim, "J", &group).await?;
        let reseated = listed(sim, "A", &group, &j).await?;
        erased = !started.is_empty()
            && later.is_empty()
            && !keyed
            && member.as_deref() != Some("active")
            && !reseated;
        receipt.note(format!(
            "new attempt ids at accept={started:?} after {later:?} keyed={keyed} \
             membership={member:?} a_lists_j={reseated} erased={erased}"
        ));
    }
    receipt.note(format!("reinvite status={status} body={body}"));
    let passed = accepted && !erased && (!started.is_empty() || body["join_state"].is_string());
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run() -> Receipt {
    let mut receipt = Receipt::new(CASE, SEED);
    match Sim::start(CASE, SEED, &["A", "J"]).await {
        Ok(sim) => {
            if let Err(error) = scenario(&sim, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

/// #1191 on main: remove + re-invite on the same running joiner is 409
/// `join_already_pending`. The test expects the fixed verdict, so this run
/// is red until the attempt is retired.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1191_attempt_exit() -> Result<()> {
    let receipt = run().await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{CASE}: expected GREEN, got {:?} (RED is the #1191 baseline)",
        receipt.verdict()
    );
    Ok(())
}
