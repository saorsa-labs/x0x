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
//! E receives nothing at the first owner-recovery epoch (#1581, follow-up
//! to #1973 / #2061). The recovery seal tolerates E's seat, so E keeps
//! its leaf and the e0+1 commit names it as a survivor; the delivery
//! stack must withhold every delivery to revoked E. The arm checks the
//! whole stack, not one gate, on E's side and not with wire-byte
//! filters: from before the trigger to the end of the arm it reads E's
//! own direct-message stream (`Agent::subscribe_direct`, the same stream
//! E's daemon handlers read) and E's own TreeKEM epoch at every poll. E
//! never holds e0+1, and no frame E receives is an owner-recovery commit,
//! a GSS share, or a metadata event or catch-up page that carries e0+1.
//! A delivery to E is the typed cause [`CAUSE_E_RECEIVED_E1`], so it reads
//! RED. Control: the same watch on survivor C sees the owner-recovery
//! commit to e0+1.
//!
//! Red proofs (Lima VM): with E's self-revocation skipped (and the steps
//! that need it), E's stream received the e0+1 commit three times and E
//! held epoch e0+1, so the watch sees a delivery to E on its own stream.
//! With E revoked, turning off D60's `write_allowed` and its seam check,
//! the ADR 0107 revoked-member check, and the agent-revoked checks at
//! connect time and in `pinned_admission_seam`, all together, still left
//! E with nothing: other gates (the owner-recovery capability lookup and
//! `join_artifact_member_check`) also withhold. Not watched: pubsub
//! group and meta topics and KV deltas (no key material there today; E's
//! epoch is the backstop), and sampling stops once E's eviction commits.
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
use serde_json::{json, Value};
use std::collections::BTreeSet;

const FOUR_E: &[&str] = &["A", "B", "C", "E"];

const FINAL: &str = "an_owner_recovery_commits_while_a_revoked_member_is_seated_then_ejects_it";
/// #1973: the deadlock the fix removes.
const CAUSE_DEADLOCK: &str = "B's owner-recovery seal is refused (ADR-0038 explicit \
     eviction+rekey) for revoked member E, which is still seated, so neither the recovery nor \
     E's eviction can ever commit";
/// #1581: a delivery to revoked E at the first owner-recovery epoch.
const CAUSE_E_RECEIVED_E1: &str = "revoked member E holds or receives keys or a commit for the \
     first owner-recovery epoch e0+1";

/// What a node received and held from the trigger on, read on its own
/// side: its own direct-message stream and its own TreeKEM epoch. The arm
/// watches E, and survivor C as the control that the watch sees a
/// delivered commit.
struct Watch {
    label: &'static str,
    rx: crate::direct::DirectMessageReceiver,
    /// The first owner-recovery epoch, e0 + 1.
    e1: u64,
    /// Every direct frame E received.
    frames: usize,
    /// The frames that carry keys or a commit for e0 + 1.
    keyed: Vec<String>,
    /// E's own TreeKEM epochs at the polls.
    epochs: BTreeSet<u64>,
    /// Polls where E held no live TreeKEM group.
    no_tree: usize,
    /// Failed reads of E's view (INFRA, never a pass).
    read_errors: usize,
}

impl Watch {
    fn new(sim: &Sim, label: &'static str, e1: u64) -> Result<Self> {
        Ok(Self {
            label,
            rx: sim.state(label)?.agent.subscribe_direct(),
            e1,
            frames: 0,
            keyed: Vec::new(),
            epochs: BTreeSet::new(),
            no_tree: 0,
            read_errors: 0,
        })
    }

    fn drain(&mut self) {
        while let Some(msg) = self.rx.try_recv() {
            self.frames += 1;
            if let Some(kind) = keyed_at(&msg.payload, self.e1) {
                let sender = hex::encode(msg.sender.as_bytes());
                self.keyed
                    .push(format!("{kind} from {}", sender.get(..8).unwrap_or("")));
            }
        }
    }

    async fn sample(&mut self, sim: &Sim, group: &str, e: &crate::identity::AgentId) {
        self.drain();
        match try_view_now(sim, self.label, group, e).await {
            Ok(view) => match view.and_then(|view| view.epoch) {
                Some(epoch) => {
                    self.epochs.insert(epoch);
                }
                None => self.no_tree += 1,
            },
            Err(_) => self.read_errors += 1,
        }
    }

    fn describe(&self) -> String {
        format!(
            "{label} received {} direct frames, keyed for e0+1: {:?}; {label}'s own epochs {:?}, \
             polls with no tree {}",
            self.frames,
            self.keyed,
            self.epochs,
            self.no_tree,
            label = self.label
        )
    }
}

/// The kind of a frame E received that carries keys or a commit for
/// `e1`, if `payload` is one: an owner-recovery commit (`X0XORC1`, any
/// epoch: the only one in this arm is the e0+1 recovery), a GSS share
/// (`secure_share_delivered`), a catch-up page with a link at `e1`, or a
/// metadata event at `e1`.
fn keyed_at(payload: &[u8], e1: u64) -> Option<String> {
    use crate::groups::owner_recovery::{
        decode_frame, OwnerRecoveryCryptoV1, OwnerRecoveryFrameV1, OWNER_RECOVERY_PREFIX,
    };
    if payload.starts_with(OWNER_RECOVERY_PREFIX) {
        return match decode_frame(payload) {
            Ok(OwnerRecoveryFrameV1::Commit(commit)) => {
                let epoch = match &commit.body.crypto {
                    OwnerRecoveryCryptoV1::TreeKem { next_epoch, .. } => Some(*next_epoch),
                    OwnerRecoveryCryptoV1::Gss { next_secret_epoch } => Some(*next_secret_epoch),
                    _ => None,
                };
                Some(format!("owner-recovery commit to epoch {epoch:?}"))
            }
            Ok(OwnerRecoveryFrameV1::Mandate(_)) => None,
            Err(error) => Some(format!("undecoded owner-recovery frame ({error:?})")),
        };
    }
    let value: Value = serde_json::from_slice(payload).ok()?;
    let at_e1 = |event: &Value| {
        event["treekem_epoch"].as_u64() == Some(e1) || event["secret_epoch"].as_u64() == Some(e1)
    };
    if value["event"] == "secure_share_delivered" {
        return Some(format!(
            "GSS share (secret_epoch {})",
            value["secret_epoch"]
        ));
    }
    if value["message_type"] == "treekem_catchup_response" {
        let linked = value["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(at_e1));
        return linked.then(|| "catch-up page with an e0+1 link".to_string());
    }
    (value.get("event").is_some() && at_e1(&value))
        .then(|| format!("metadata event {} at e0+1", value["event"]))
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
    // #1581: E's own stream, open before the trigger so nothing sent to E
    // after it is missed.
    let mut e_watch = Watch::new(sim, "E", e0 + 1)?;
    let mut c_watch = Watch::new(sim, "C", e0 + 1)?;

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
            e_watch.sample(s, &group, &e).await;
            c_watch.sample(s, &group, &e).await;
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
                e_watch.sample(s, &group, &e).await;
                c_watch.sample(s, &group, &e).await;
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
    // #1581: E received nothing at e0 + 1. E's own epoch was read at e0
    // and never at e0 + 1, and no frame E received carries keys or a
    // commit for it. Control: the same watch on survivor C sees the
    // owner-recovery commit, so the watch does see a delivered commit. A
    // failed read of a view is INFRA.
    for watch in [&mut e_watch, &mut c_watch] {
        watch.sample(sim, &group, &e).await;
        ensure!(
            watch.read_errors == 0,
            "{} failed reads of {}'s view",
            watch.read_errors,
            watch.label
        );
    }
    let c_saw_the_commit = c_watch
        .keyed
        .iter()
        .any(|kind| kind.starts_with(&format!("owner-recovery commit to epoch Some({})", e0 + 1)));
    let e_nothing_at_e1 = c_saw_the_commit
        && e_watch.keyed.is_empty()
        && e_watch.epochs.contains(&e0)
        && !e_watch.epochs.contains(&(e0 + 1));
    receipt.note(format!(
        "e_receives_nothing_at_the_first_owner_recovery_epoch: {e_nothing_at_e1} (control: C \
         received the e0+1 commit {c_saw_the_commit}); {}; {}",
        e_watch.describe(),
        c_watch.describe()
    ));
    let e_leak = !e_watch.keyed.is_empty() || e_watch.epochs.contains(&(e0 + 1));
    if e_leak {
        receipt.cause(
            CAUSE_E_RECEIVED_E1,
            Some(e_watch.describe()),
            c_saw_the_commit,
            at(sim),
        );
    }
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
            && rows_prove_precondition
            && e_nothing_at_e1,
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
