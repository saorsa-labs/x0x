//! W3-H case for #1973 (ADR 0110 §4b(1) `s4_owner_recovery`): the
//! owner-recovery commit while another revoked member is still seated.
//!
//! Nodes A, B, C, E; A provisions its Home (`OwnerCertified`, TreeKEM)
//! and is the only admin; every device holds the owner key U, so C signs
//! the mandates. At t = 0 A and E revoke their own agents; B and C hold
//! both records and show the owner-recovery wait. C's mandate naming the
//! revoked member E is refused with `recovery_member_ineligible`; C's
//! mandate naming B answers `202 waiting_for_recovery_member`. Desired:
//! B commits the recovery (on C, B is an Admin and A is Removed), and B
//! then works E's own S4 row (on C, E is Removed) under the admin the
//! recovery seated. On `main` the ADR-0038 seal check refused B's commit
//! while revoked E was seated, and E's eviction waited for the eligible
//! admin the recovery would have seated, so the two waits on each other
//! and the group stayed without an admin forever (the issue's deadlock);
//! the arm then records [`CAUSE_DEADLOCK`] with B's seal-refusal log
//! naming E.
//!
//! The harness pieces this arm needs that live in `s4ab` (a sibling
//! module, not reachable from here) are small local copies.

use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::S4Timing;
use crate::identity::UserKeypair;
use anyhow::{ensure, Result};
use serde_json::json;

const FOUR_E: &[&str] = &["A", "B", "C", "E"];
const QUIET: Duration = Duration::from_secs(5);
const RECOVERY: Duration = Duration::from_secs(120);
/// A case that has not finished after this much real time has stalled.
const REAL_TIME_STALL: Duration = Duration::from_secs(200);
const ELIGIBLE_ADMIN_REVOCATION: &str = "waiting_for_eligible_admin_revocation";

const FINAL: &str = "an_owner_recovery_commits_while_a_revoked_member_is_seated_then_ejects_it";
/// #1973: the deadlock the fix removes.
const CAUSE_DEADLOCK: &str = "B's owner-recovery seal is refused (ADR-0038 explicit \
     eviction+rekey) for revoked member E, which is still seated, so neither the recovery nor \
     E's eviction can ever commit";

/// A 2xx reply is quiet for `QUIET`.
async fn pause(sim: &Sim, what: &str, duration: Duration) -> Result<()> {
    sim.within(what, duration + secs(2), async {
        tokio::time::sleep(duration).await;
    })
    .await
}

/// A real-time watchdog for one scenario; see `s4ab` for the rationale.
struct Watchdog {
    disarmed: Arc<std::sync::atomic::AtomicBool>,
}

impl Watchdog {
    fn disarm(&self) {
        self.disarmed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn real_time_watchdog(case: &str, fabric: Arc<SimFabric>) -> Watchdog {
    let disarmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&disarmed);
    let case = case.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(REAL_TIME_STALL);
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let trace = fabric.canonical_trace();
        let tail: Vec<&str> = trace.lines().rev().take(60).collect();
        println!(
            "W3H-STALL {case}: no progress after {REAL_TIME_STALL:?} real time; last trace lines \
             (newest first):"
        );
        for line in tail {
            println!("W3H-STALL {line}");
        }
        std::process::exit(101);
    });
    Watchdog { disarmed }
}

async fn self_revoke(sim: &Sim, label: &str) -> Result<()> {
    let hex = sim.agent_hex(label)?;
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": hex, "reason": "w3h-1973"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} self-revokes: {status} {body}");
    Ok(())
}

/// `GET /groups/:id` on `label`, without a barrier (for `until`
/// predicates and `at_instant` reads).
async fn group_body(sim: &Sim, label: &str, group: &str) -> Result<serde_json::Value> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(body)
}

/// `admin_availability` names the typed wait with exit `owner_recovery`
/// and A among the revoked admins.
fn waits_for_owner_recovery(body: &serde_json::Value, a_hex: &str) -> bool {
    let availability = &body["admin_availability"];
    availability["state"] == ELIGIBLE_ADMIN_REVOCATION
        && availability["exit"] == "owner_recovery"
        && availability["revoked_admins"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(a_hex)))
}

/// Whether `observer` shows the owner-recovery wait naming A. A failed
/// read is an error, never "no wait".
async fn shows_wait(sim: &Sim, observer: &str, group: &str, a_hex: &str) -> Result<bool> {
    Ok(waits_for_owner_recovery(
        &group_body(sim, observer, group).await?,
        a_hex,
    ))
}

/// Every holder holds the revocation record. An empty list fails.
fn all_hold(held: &[(&str, bool)]) -> bool {
    !held.is_empty() && held.iter().all(|(_, has)| *has)
}

/// After `await_holders`: every holder must hold `subject_hex`'s
/// revocation, else the arm tests nothing new and is INFRA.
async fn holders_hold(
    sim: &Sim,
    receipt: &mut Receipt,
    name: &str,
    holders: &[&'static str],
    subject_hex: &str,
) -> Result<()> {
    await_holders(sim, holders, subject_hex).await?;
    let held = held_by(sim, holders, subject_hex).await?;
    receipt.evidence(
        name,
        all_hold(&held),
        format!("revocation held {held:?}"),
        sim.fabric().now().as_micros(),
    );
    Ok(())
}

/// The mandate request on the owner device `signer`, naming `promoted`.
async fn mandate(
    sim: &Sim,
    signer: &str,
    group: &str,
    promoted_hex: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    sim.api(
        signer,
        Method::POST,
        &format!("/owner/groups/{group}/recovery-mandate"),
        Some(json!({"promoted_agent_id": promoted_hex})),
    )
    .await
}

/// A provisions its Home with a fresh owner key; every other label is a
/// certified same-owner device with a seat (`s4ab::home_with` without
/// the expiring-certificate branch). A is the only admin.
async fn home(sim: &mut Sim, labels: &[&'static str]) -> Result<super::super::home::HomeIds> {
    let owner = UserKeypair::generate()?;
    let home = sim.start_owner_device("A", &owner).await?;
    for device in labels.iter().filter(|label| **label != "A") {
        sim.certify_owner_device("A", device, &owner, &home).await?;
    }
    for member in labels.iter().filter(|label| **label != "A") {
        let invite = sim.home_seat("A", member, &home).await?;
        ensure!(
            sim.join_home("A", member, &home, &invite, SETUP).await?,
            "setup: A could not seat {member} in its Home"
        );
    }
    Ok(home)
}

/// The parent case's pre-t0 wait: every node is past its restart sync
/// wait from process start (ADR 0110 §2, D73).
async fn past_sync_wait(sim: &Sim, receipt: &mut Receipt) -> Result<()> {
    let setup_end = sim.fabric().now();
    let sync_wait = S4Timing::default().restart_sync_wait;
    pause(sim, "every node's restart sync wait", sync_wait).await?;
    let t0 = sim.fabric().now();
    receipt.evidence(
        "every_node_past_its_restart_sync_wait_at_t0",
        t0.saturating_sub(setup_end) >= sync_wait,
        format!(
            "setup ended at {} us; restart sync wait {sync_wait:?}; t0 at {} us",
            setup_end.as_micros(),
            t0.as_micros()
        ),
        t0.as_micros(),
    );
    Ok(())
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let home_ids = home(sim, FOUR_E).await?;
    let group = home_ids.gid.clone();
    let (a, _) = sim.ids("A")?;
    let (e, _) = sim.ids("E")?;
    let a_hex = sim.agent_hex("A")?;
    let b_hex = sim.agent_hex("B")?;
    let e_hex = sim.agent_hex("E")?;
    settled(sim, FOUR_E, &group, &a).await?;
    receipt.setup_done(at(sim));
    past_sync_wait(sim, receipt).await?;

    let trigger = sim
        .fabric()
        .mark_indexed("case: t=0 A and E revoke their own agents");
    self_revoke(sim, "A").await?;
    self_revoke(sim, "E").await?;
    holders_hold(
        sim,
        receipt,
        "b_and_c_hold_a_revocation",
        &["B", "C"],
        &a_hex,
    )
    .await?;
    holders_hold(
        sim,
        receipt,
        "b_and_c_hold_e_revocation",
        &["B", "C"],
        &e_hex,
    )
    .await?;
    let waited = sim
        .until(
            "B and C show the owner-recovery wait",
            EVIDENCE,
            async |s: &Sim| {
                matches!(shows_wait(s, "B", &group, &a_hex).await, Ok(true))
                    && matches!(shows_wait(s, "C", &group, &a_hex).await, Ok(true))
            },
        )
        .await;
    let waits_typed = match waited {
        Ok(()) => true,
        Err(error) if expired(&error) => false,
        Err(error) => return Err(error),
    };
    receipt.evidence(
        "b_and_c_wait_for_owner_recovery_naming_a",
        waits_typed,
        statuses(sim, &["B", "C"], &group).await?,
        at(sim),
    );

    // A mandate naming the revoked member E is refused.
    let (status_e, body_e) = mandate(sim, "C", &group, &e_hex).await?;
    receipt.note(format!("C's mandate naming revoked E: {status_e} {body_e}"));
    let refused_e = !status_e.is_success() && body_e["error"] == "recovery_member_ineligible";

    // C's mandate names B.
    let (status_b, body_b) = mandate(sim, "C", &group, &b_hex).await?;
    let signed = status_b == StatusCode::ACCEPTED
        && body_b["state"] == "waiting_for_recovery_member"
        && body_b["promoted_member"].as_str() == Some(b_hex.as_str());
    pause(sim, "after the mandate naming B", QUIET).await?;
    receipt.note(format!(
        "C's mandate naming B: {status_b} {body_b}; S4 status {}",
        statuses(sim, &["B", "C"], &group).await?
    ));

    // B commits the recovery: on C, B is an Admin and A is Removed.
    let started = sim.fabric().now();
    let mut committed_at: Option<Duration> = None;
    let committed = sim
        .until("B commits the owner recovery", RECOVERY, async |s: &Sim| {
            let done = sees_admin(s, "C", &group, "B").await.unwrap_or(false)
                && views_now(s, &["C"], &group, &a).await.is_ok_and(|seen| {
                    seen.iter().all(|(_, view)| {
                        view.as_ref().is_some_and(|view| {
                            !view.lists_b && view.b_state.as_deref() == Some("Removed")
                        })
                    })
                });
            if done {
                committed_at.get_or_insert(s.fabric().now().saturating_sub(started));
            }
            done
        })
        .await
        .is_ok();
    receipt.note(format!(
        "refused E recovery_member_ineligible {refused_e}; B mandate signed {signed}; recovery \
         committed {committed} at {committed_at:?}; C about A: {}; S4 status {}",
        describe_all(&views(sim, &["C"], &group, &a).await?),
        statuses(sim, &["B", "C"], &group).await?
    ));

    // B, now the eligible admin, works E's own S4 row: on C, E is
    // Removed ("B commits and later evicts E", #1973).
    let e_evicted = sim
        .until(
            "B ejects the seated revoked member E",
            RECOVERY,
            async |s: &Sim| {
                views_now(s, &["C"], &group, &e).await.is_ok_and(|seen| {
                    seen.iter().all(|(_, view)| {
                        view.as_ref().is_some_and(|view| {
                            !view.lists_b && view.b_state.as_deref() == Some("Removed")
                        })
                    })
                })
            },
        )
        .await
        .is_ok();
    receipt.note(format!(
        "E evicted on C {e_evicted}; C about E: {}",
        describe_all(&views(sim, &["C"], &group, &e).await?)
    ));

    receipt.request_delivered(
        "c_answered_the_mandates_and_a_reached_c",
        status_b != StatusCode::NOT_FOUND
            && !sim
                .fabric()
                .delivered_writes_after(&sim.peer("A")?, &sim.peer("C")?, trigger)
                .is_empty(),
        format!("mandate replies {status_e} / {status_b}"),
        at(sim),
    );
    if !committed {
        // #1973: the seal refusal that names E is the deadlock's
        // signature. It counts only when every step before the commit
        // held, so a broken mandate reply leaves the arm INFRA.
        let refusals = sim.logs_containing(&[
            "owner recovery deferred: seal failed",
            "explicit eviction+rekey",
            e_hex.as_str(),
        ]);
        receipt.note(format!(
            "B's seal refusals naming E: {}; first {:?}",
            refusals.len(),
            refusals.first().map(|log| (log.at, log.text.clone()))
        ));
        receipt.cause(
            CAUSE_DEADLOCK,
            refusals.first().map(|log| log.text.clone()),
            !refusals.is_empty() && waits_typed && refused_e && signed,
            at(sim),
        );
    }
    receipt.finish(
        FINAL,
        waits_typed && refused_e && signed && committed && e_evicted,
        at(sim),
    );
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1973 / ADR 0110 S4 s4_owner_recovery with a second revoked member. Timing from \
         S4Timing::default(): {:?}.",
        timing()
    ));
    match Sim::empty(case, seed, FOUR_E) {
        Ok(mut sim) => {
            let fabric = Arc::clone(sim.fabric());
            let watchdog = real_time_watchdog(case, fabric);
            let outcome = scenario(&mut sim, &mut receipt).await;
            watchdog.disarm();
            if let Err(error) = outcome {
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

/// ADR 0110 `s4_owner_recovery`, the seated-revoked-member form (#1973):
/// the recovery commits while E is seated, then B ejects E.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1357_s4_owner_recovery_revoked_member_1973() -> Result<()> {
    super::super::block_on_paused(async move {
        let receipt = run(
            "w3h_1357_s4_owner_recovery_revoked_member_1973",
            0x1973_0051,
        )
        .await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
