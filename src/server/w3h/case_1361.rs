//! W3-H case `w3h_1361_staging_loss_restart_a` (#1361, ADR 0114
//! `s8b_1150_staging_loss`, the restart-A variant with no carry).
//!
//! Nodes: A (admin and sealer) and J (joiner). Public HTTP only.
//!
//! 1. A creates a `private_secure` group. Every frame from A to J except
//!    plane hello is dropped. J redeems an invite. A seats J and stages
//!    J's result, but J gets no carry, so J's poll ends `timed_out` with
//!    no local row and no TreeKEM group.
//! 2. A restarts. The staged result is in memory only, so the restart
//!    loses it. A still seats J on its signed roster.
//! 3. The drop lifts. A mints a fresh invite, whose base already seats J,
//!    and J redeems it on the same process (the ADR's retry step).
//! 4. Fixed (ADR 0114 §1 to §4): within the repair bound, J holds the
//!    group's TreeKEM keys, reports `active`, A lists J once, and an
//!    encrypted probe goes both ways (J to A and A to J). A `join_state`
//!    string alone does not pass.
//!
//! Baseline on main: J reports `active` but has no TreeKEM group and
//! cannot encrypt. No path re-Welcomes a seat whose staging is lost.
//!
//! The repair bound (D89) has no final number until ADR 0110 (S4) is
//! accepted. This case uses [`REPAIR_BOUND`], a harness value.
//!
//! The ADR's no-carry (10 minute staging horizon), carry and
//! no-retained-row variants are later slices. The horizon variant needs
//! the wall-clock shim, because the staging TTL reads `std::time::Instant`.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::control::{create_group, invite, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass, Write};
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const SEED: u64 = 0x1361_0001;
const CASE: &str = "w3h_1361_staging_loss_restart_a";
const FINAL: &str = "staging_loss_repaired_with_usable_keys";
const CAUSE: &str = "after staging loss and a base-seated retry, J holds no usable group keys";
/// The harness repair bound. ADR 0114 takes the final number from ADR
/// 0110 (S4) under D89; a fix must complete inside this budget.
const REPAIR_BOUND: Duration = Duration::from_secs(180);
const PROBE: &[u8] = b"w3h-1361 probe";
const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

/// Drops every A→J frame except plane hello while held. The rule keys on
/// peer ids, so it still applies after A's restart.
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

/// How many times A lists J in `group`.
async fn listings(sim: &Sim, group: &str, agent: &str) -> Result<usize> {
    Ok(members(sim, "A", group)
        .await?
        .iter()
        .filter(|id| id.as_str() == agent)
        .count())
}

/// A's staged join results for J (ADR 0107's in-memory S8(a) staging).
async fn staged_for(sim: &Sim, agent: &str) -> Result<usize> {
    Ok(sim
        .state("A")?
        .pending_join_results
        .read()
        .await
        .keys()
        .filter(|key| {
            key.rsplit_once(':')
                .is_some_and(|(_, member)| member.eq_ignore_ascii_case(agent))
        })
        .count())
}

/// `from` encrypts the probe and `to` decrypts it. `Err` carries the
/// observed reply.
async fn probe(sim: &Sim, group: &str, from: &str, to: &str) -> Result<Result<(), String>> {
    let (status, body) = sim
        .api(
            from,
            Method::POST,
            &format!("/groups/{group}/secure/encrypt"),
            Some(json!({"payload_b64": BASE64.encode(PROBE)})),
        )
        .await?;
    let Some(ciphertext) = body["ciphertext_b64"]
        .as_str()
        .filter(|_| status.is_success() && body["ok"] != false)
    else {
        return Ok(Err(format!("{from} encrypt: {status} {body}")));
    };
    let (status, body) = sim
        .api(
            to,
            Method::POST,
            &format!("/groups/{group}/secure/decrypt"),
            Some(json!({"ciphertext_b64": ciphertext})),
        )
        .await?;
    let ok = status.is_success()
        && body["payload_b64"]
            .as_str()
            .and_then(|payload| BASE64.decode(payload).ok())
            .is_some_and(|payload| payload == PROBE);
    Ok(if ok {
        Ok(())
    } else {
        Err(format!("{to} decrypt: {status} {body}"))
    })
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<bool> {
    mesh(sim, &["A", "J"]).await?;
    let group = create_group(sim, "A").await?;
    let block = AwayFromJ::install(sim)?;
    let j = sim.agent_hex("J")?;
    receipt.setup_done(at(sim));

    // Step 1: A seats and stages J; J gets no carry.
    block.set(true);
    let link = invite(sim, "A", &group).await?;
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "J"})),
        )
        .await?;
    ensure!(
        status.is_success() && body["ok"] != false,
        "J first join: {status} {body}"
    );
    sim.until(
        "A seats and stages J while J receives no carry",
        secs(180),
        async |s| {
            listings(s, &group, &j).await.unwrap_or(0) == 1
                && staged_for(s, &j).await.unwrap_or(0) > 0
        },
    )
    .await?;
    let staged = staged_for(sim, &j).await?;
    receipt.evidence(
        "A seated J and staged J's join result while A-to-J frames were dropped",
        staged > 0 && listings(sim, &group, &j).await? == 1,
        format!("staged={staged} dropped={}", block.dropped()),
        at(sim),
    );

    sim.until(
        "J's no-carry poll records timed_out",
        secs(160),
        async |s| join_outcome(s, &group).await.ok().flatten().as_deref() == Some("timed_out"),
    )
    .await?;
    let row = membership(sim, "J", &group).await?;
    let keyed = has_treekem(sim, &group).await?;
    receipt.evidence(
        "J's poll timed out with no local row and no TreeKEM group",
        row.is_none() && !keyed,
        format!("membership={row:?} treekem={keyed}"),
        at(sim),
    );

    // Step 2: A restarts and loses its in-memory staging.
    sim.restart("A", RestartMode::Graceful).await?;
    let staged_after = staged_for(sim, &j).await?;
    let still_seated = listings(sim, &group, &j).await?;
    receipt.evidence(
        "A's restart lost the staged result, and A's roster still seats J",
        staged_after == 0 && still_seated == 1,
        format!("staged_after_restart={staged_after} a_listings_of_j={still_seated}"),
        at(sim),
    );

    // Step 3: lift the drop; J retries with a fresh (base-seated) invite.
    block.set(false);
    let retry_link = invite(sim, "A", &group).await?;
    let (a, j_peer) = (sim.peer("A")?, sim.peer("J")?);
    let from = sim
        .fabric()
        .mark_indexed("J redeems the base-seated retry invite");
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": retry_link, "display_name": "J"})),
        )
        .await?;
    receipt.note(format!("retry redeem: {status} {body}"));

    // Step 4: the repair bound. Stop early once J holds keys.
    let mut keyed = false;
    let mut active = None;
    let repaired = sim
        .until(
            "J holds usable group keys within the repair bound",
            REPAIR_BOUND,
            async |s| {
                keyed = has_treekem(s, &group).await.unwrap_or(false);
                active = membership(s, "J", &group).await.ok().flatten();
                keyed && active.as_deref() == Some("active")
            },
        )
        .await
        .is_ok();
    let to = sim.fabric().mark_indexed("repair bound reached");
    let sent_to_a = sim
        .fabric()
        .writes_from_between(&j_peer, from..to)
        .iter()
        .filter(|write| write.lane.dst == a.0 && write.lane.class != LaneClass::PlaneHello)
        .count();
    receipt.request_delivered(
        "J's retry redeem was accepted and J sent frames to A after it",
        status.is_success() && sent_to_a > 0,
        format!("status={status} j_to_a_frames={sent_to_a}"),
        at(sim),
    );

    let listed = listings(sim, &group, &j).await?;
    let j_to_a = probe(sim, &group, "J", "A").await?;
    let a_to_j = probe(sim, &group, "A", "J").await?;
    receipt.note(format!(
        "after the bound: membership={active:?} treekem={keyed} a_listings_of_j={listed} \
         j_to_a={j_to_a:?} a_to_j={a_to_j:?}"
    ));
    if !keyed {
        receipt.cause(
            CAUSE,
            Some(format!(
                "membership={active:?} treekem=false j_to_a={j_to_a:?}"
            )),
            true,
            at(sim),
        );
    }
    Ok(repaired && listed == 1 && j_to_a.is_ok() && a_to_j.is_ok())
}

async fn run() -> Receipt {
    let mut receipt = Receipt::new(CASE, SEED);
    let mut passed = false;
    match Sim::start(CASE, SEED, &["A", "J"]).await {
        Ok(mut sim) => {
            match scenario(&mut sim, &mut receipt).await {
                Ok(outcome) => passed = outcome,
                Err(error) => receipt.infra(format!("{error:#}"), at(&sim)),
            }
            if let Err(error) = sim.finish().await {
                passed = false;
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() {
        receipt.finish(FINAL, passed && !receipt.has_infra(), 0);
    }
    if receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

/// ADR 0114 `s8b_1150_staging_loss`, restart-A variant. The test expects
/// the fixed verdict, so it is RED on main until S8(b) re-Welcomes J.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1361_staging_loss_restart_a() -> Result<()> {
    super::block_on_paused(async move {
        let receipt = run().await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{CASE}: expected GREEN, got {:?} with causes {:?} (RED is the ADR 0114 \
             staging-loss baseline)",
            receipt.verdict(),
            receipt.named_causes()
        );
        Ok(())
    })
}
