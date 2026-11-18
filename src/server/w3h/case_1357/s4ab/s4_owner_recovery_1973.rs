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
//! recovery seated. Each commit advances the TreeKEM epoch one step —
//! the recovery to n-1 leaves with E still seated, E's own row to n-2
//! — and after that row commits, E can no longer open the group's
//! ciphertext. On `main` the ADR-0038 seal check refused B's commit
//! while revoked E was seated, and E's eviction waited for the eligible
//! admin the recovery would have seated, so the two waits on each other
//! and the group stayed without an admin forever (the issue's deadlock);
//! the arm then records [`CAUSE_DEADLOCK`] with B's seal-refusal log
//! naming E.
//!
//! A child of `s4ab` (as `expiry_skew` is), so the Home, mandate, wait
//! and watchdog helpers are shared, not copied.
//!
//! The checks after the mandates (the commit, the epochs and leaves, the
//! crypto plane, B's S4 rows) are receipt notes that feed only
//! [`Receipt::finish`], never `evidence` stages: on the deadlock path
//! they are all false, and a false `evidence` stage would make the
//! verdict INFRA, hiding the RED for a #1973 regression
//! (`recovery_scenario` records its outcome checks the same way).

use super::*;
use anyhow::{ensure, Context, Result};
use serde_json::json;

const FOUR_E: &[&str] = &["A", "B", "C", "E"];

const FINAL: &str = "an_owner_recovery_commits_while_a_revoked_member_is_seated_then_ejects_it";
/// #1973: the deadlock the fix removes.
const CAUSE_DEADLOCK: &str = "B's owner-recovery seal is refused (ADR-0038 explicit \
     eviction+rekey) for revoked member E, which is still seated, so neither the recovery nor \
     E's eviction can ever commit";

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

/// Whether `observer` shows the owner-recovery wait naming A. A failed
/// read is an error, never "no wait": every poll sends this through
/// [`Observations`] and verifies after.
async fn shows_wait(sim: &Sim, observer: &str, group: &str, a_hex: &str) -> Result<bool> {
    Ok(waits_for_owner_recovery(
        &group_body(sim, observer, group).await?,
        a_hex,
    ))
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

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let (home_ids, _) = home_with(sim, FOUR_E, None, &[]).await?;
    let group = home_ids.gid.clone();
    let (a, _) = sim.ids("A")?;
    let (e, _) = sim.ids("E")?;
    let a_hex = sim.agent_hex("A")?;
    let b_hex = sim.agent_hex("B")?;
    let e_hex = sim.agent_hex("E")?;
    settled(sim, FOUR_E, &group, &a).await?;
    // Baseline for the two commits this arm measures (`recovery_scenario`):
    // one epoch and leaf count, with E seated.
    let base = view(sim, "C", &group, &a).await?;
    let e0 = base.epoch.context("C has no live TreeKEM group")?;
    let leaves0 = base.leaves.context("C has no live TreeKEM group")?;
    let e_base = view(sim, "C", &group, &e).await?;
    receipt.evidence(
        "home_treekem_group_settled_with_e_seated",
        e_base.lists_b
            && e_base.b_state.as_deref() == Some("Active")
            && u32::try_from(FOUR_E.len()).is_ok_and(|seats| seats == leaves0)
            && !base.quarantined,
        format!(
            "e0={e0} leaves0={leaves0}; C about A: {}; C about E: {}",
            base.describe(),
            e_base.describe()
        ),
        at(sim),
    );
    // E opens the probe at e0, so a later refusal on E means exclusion,
    // not a broken path (the parent case's data-plane control).
    let control = match encrypt(sim, "A", &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "E", &group, &ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error)),
    };
    receipt.evidence(
        "c_and_e_decrypt_at_e0_before_the_trigger",
        control.0 .0 && control.1 .0,
        format!("{}; {}", control.0 .1, control.1 .1),
        at(sim),
    );
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
    let mut wait_reads = Observations::default();
    let waited = sim
        .until(
            "B and C show the owner-recovery wait",
            EVIDENCE,
            async |s: &Sim| {
                let mut all = true;
                for label in ["B", "C"] {
                    let Some(wait) = wait_reads
                        .observe(shows_wait(s, label, &group, &a_hex))
                        .await
                    else {
                        // A failed read ends the barrier; `verify` below
                        // makes it INFRA, never "no wait".
                        return true;
                    };
                    all &= wait;
                }
                all
            },
        )
        .await;
    let waits_typed = match waited {
        Ok(()) => true,
        Err(error) if expired(&error) => false,
        Err(error) => return Err(error),
    };
    wait_reads.verify("B and C show the owner-recovery wait")?;
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

    // B commits the recovery: on C, B is an Admin and A is Removed. The
    // same poll also reads C's view of E: when the poll catches the
    // commit before B works E's own row, E is still seated and Active
    // on C — #1973's precondition, recorded in the note. C's
    // convergence can batch both commits into one poll, so the gated
    // proof of the precondition is the durable one below (B's S4 rows:
    // E's eviction lands one epoch after the recovery).
    let started = sim.fabric().now();
    let mut committed_at: Option<Duration> = None;
    let mut e_active_when_committed: Option<bool> = None;
    let mut commit_reads = Observations::default();
    let waited = sim
        .until("B commits the owner recovery", RECOVERY, async |s: &Sim| {
            let Some(e_on_c) = commit_reads.observe(views_now(s, &["C"], &group, &e)).await else {
                return true;
            };
            let Some(b_admin) = commit_reads.observe(sees_admin(s, "C", &group, "B")).await else {
                return true;
            };
            let Some(a_on_c) = commit_reads.observe(views_now(s, &["C"], &group, &a)).await else {
                return true;
            };
            let done = b_admin
                && a_on_c.iter().all(|(_, view)| {
                    view.as_ref()
                        .is_some_and(|view| view.b_state.as_deref() == Some("Removed"))
                });
            if done {
                committed_at.get_or_insert(s.fabric().now().saturating_sub(started));
                e_active_when_committed.get_or_insert(e_on_c.iter().all(|(_, view)| {
                    view.as_ref().is_some_and(|view| {
                        view.lists_b && view.b_state.as_deref() == Some("Active")
                    })
                }));
            }
            done
        })
        .await;
    // Only an expired budget means "not committed": a barrier error or a
    // failed read is an error, so a daemon crash is INFRA, never a
    // false deadlock.
    let committed = match waited {
        Ok(()) => true,
        Err(error) if expired(&error) => false,
        Err(error) => return Err(error),
    };
    commit_reads.verify("B commits the owner recovery")?;
    receipt.note(format!(
        "refused E recovery_member_ineligible {refused_e}; B mandate signed {signed}; recovery \
         committed {committed} at {committed_at:?}; E active at the commit \
         {e_active_when_committed:?}; C about A: {}; S4 status {}",
        describe_all(&views(sim, &["C"], &group, &a).await?),
        statuses(sim, &["B", "C"], &group).await?
    ));

    // B, now the eligible admin, works E's own S4 row: on C, E is
    // Removed ("B commits and later evicts E", #1973) and the exclusion
    // advanced the epoch a second step, to n-2 leaves.
    let mut evict_reads = Observations::default();
    let waited = sim
        .until(
            "B ejects the seated revoked member E",
            RECOVERY,
            async |s: &Sim| {
                let Some(e_on_c) = evict_reads.observe(views_now(s, &["C"], &group, &e)).await
                else {
                    return true;
                };
                e_on_c.iter().all(|(_, view)| {
                    view.as_ref().is_some_and(|view| {
                        !view.lists_b
                            && view.b_state.as_deref() == Some("Removed")
                            && view.epoch == Some(e0 + 2)
                            && view.leaves == Some(leaves0 - 2)
                            && !view.quarantined
                    })
                })
            },
        )
        .await;
    let e_evicted = match waited {
        Ok(()) => true,
        Err(error) if expired(&error) => false,
        Err(error) => return Err(error),
    };
    evict_reads.verify("B ejects the seated revoked member E")?;
    receipt.note(format!(
        "E evicted on C {e_evicted}; C about E: {}",
        describe_all(&views(sim, &["C"], &group, &e).await?)
    ));
    // From here to `finish` every check is a note: on the deadlock path
    // they are false, and a false `evidence` stage would make the
    // verdict INFRA instead of RED.
    //
    // The exclusion settles at exactly e0 + 2 with two fewer leaves: one
    // epoch step per commit, no duplicate rekey (`recovery_scenario`'s
    // settle read at exactly e0 + 1, one step further here).
    pause(sim, "the second exclusion settles", SETTLE).await?;
    let end = views(sim, &["C"], &group, &e).await?;
    let e_end_excluded = all_at(&end, e0 + 2)
        && end.iter().all(|(_, view)| {
            view.as_ref().is_some_and(|view| {
                !view.lists_b
                    && view.b_state.as_deref() == Some("Removed")
                    && view.leaves == Some(leaves0 - 2)
            })
        });
    receipt.note(format!(
        "c_holds_exactly_e0_plus_2_with_two_fewer_leaves_after_settle: {e_end_excluded}; {}",
        describe_all(&end)
    ));
    // The crypto plane agrees: B's new ciphertext opens on C and no
    // longer on the ejected member E (`recovery_scenario`'s `plane_ok`).
    let (c_after, e_after) = match encrypt(sim, "B", &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "E", &group, &ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error)),
    };
    let plane_ok = c_after.0 && !e_after.0;
    receipt.note(format!(
        "e_cannot_decrypt_after_its_own_eviction_row_commits: {plane_ok}; {}; {}",
        c_after.1, e_after.1
    ));
    // #1973's precondition, durably: B's own S4 rows show the recovery
    // (A's row) complete in epoch e0 + 1 while E was still seated — E's
    // own row then completes one epoch later, under the admin the
    // recovery seated (its designated_admin). A removed member has no
    // leaf to evict in a later epoch, so E's row completing at e0 + 2
    // is only possible if E was seated when the recovery committed.
    let s4 = eviction_status(sim, "B", &group).await?;
    let row = |target: &str| {
        s4["revocation_evictions"].as_array().and_then(|rows| {
            rows.iter().find(|row| {
                row["target"]
                    .as_str()
                    .is_some_and(|id| id.eq_ignore_ascii_case(target))
            })
        })
    };
    let recovery_row = row(&a_hex).cloned().unwrap_or(serde_json::Value::Null);
    let eviction_row = row(&e_hex).cloned().unwrap_or(serde_json::Value::Null);
    let rows_prove_precondition = recovery_row["phase"].as_str() == Some("complete")
        && recovery_row["result_epoch"].as_u64() == Some(e0 + 1)
        && eviction_row["phase"].as_str() == Some("complete")
        && eviction_row["result_epoch"].as_u64() == Some(e0 + 2)
        && eviction_row["designated_admin"]
            .as_str()
            .is_some_and(|id| id.eq_ignore_ascii_case(&b_hex));
    receipt.note(format!(
        "bs_rows_prove_e_was_seated_when_the_recovery_committed: {rows_prove_precondition}; \
         A's row: {recovery_row}; E's row: {eviction_row}"
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
        waits_typed
            && refused_e
            && signed
            && committed
            && e_evicted
            && e_end_excluded
            && plane_ok
            && rows_prove_precondition,
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
    super::super::super::block_on_paused(async move {
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
