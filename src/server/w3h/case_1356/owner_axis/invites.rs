//! ADR 0109 §10 row H-S3-rm4 (the re-seat invite check, ADR 0059
//! exception, D156; #1572), variants (1) and (2).
//!
//! Setup: H-S3-c up to A's re-seat call. O stops and A removes J (r+3).
//! J's writes and A's writes to J are held, and A re-seats J with basis
//! `Removal(r+3)`. A's push of the authorisation ends unseen. Then one
//! variant runs, and one test runs each variant:
//! (1) J's operator calls `POST /groups/join` with A's re-seat invite.
//! (2) Node E, never seated, calls `POST /groups/join` with it.
//! Last, J's writes pass and A sends J its real authorisation.
//!
//! Desired: J refuses (1) and E refuses (2) with
//! `reseat_invite_outside_staging`, and each refusal is counted in
//! `invites_refused {reason}`. J stays `reseat_required`, with no staging
//! stub and an unchanged live record. E has no record of the group. Then
//! A's real authorisation re-seats J: J is Active with keys at r+4. The
//! join route answers J's operator and writes no recovery state, so for
//! (1) the row reads that answer, not `last_refusal`.
//!
//! Not in this file: variants (3) to (5) are RED on `main`. J refuses each
//! one, but reports the refusal in the wrong place:
//! - (3) and (5): the staged join refuses with `owner_mismatch` or
//!   `invite_downgraded` and counts it, but `consume_reseat` rolls back
//!   with `last_refusal = "join_409"`, which drops the reason
//!   (`src/server/routes/named_groups/group_recovery.rs:6623`).
//! - (4): `refuse_authorisation` (`group_recovery.rs:6320`) sets
//!   `last_refusal`, but does not count the refusal in `invites_refused`.
//!
//! The fix is in `group_recovery.rs`, which open PRs change, so (3) to (5)
//! come with that fix as its red proof. Variant (6), the Home policy, is
//! not in this file. A released joiner's refusal of (2) needs a released
//! binary (the H-S3-home gate harness).
//!
//! RED: the variant reached J (or E) and the refusal, the count, J's
//! containment or the last re-seat is wrong. Any other failure is INFRA.

use super::*;
use crate::groups::recovery::{
    encode_message, AttestAnswer, GroupAttestResponseV1, GroupRecoveryMessageV1, IssuedReseatV1,
    ReseatAuthorisation,
};
use std::sync::atomic::{AtomicBool, Ordering};

const FINAL_RM4: &str =
    "j_refuses_the_reseat_invite_variant_then_the_real_authorisation_reseats_it";
const CAUSE_RM4: &str = "the row's main observation: A's re-seat route returns 404 (no S3 \
                         re-seat); or J (or E) does not refuse the variant with its reason \
                         and count before any stub, J leaves containment, or A's real \
                         authorisation does not re-seat J at r+4; `observed` lists each \
                         failing step";
/// H-S3-c's nodes plus E, never seated (variant 2 only).
const RM4_E_LABELS: &[&str] = &["O", "A", "X", "J", "E"];
/// A answers the re-seat call with one direct send to J (with its
/// retries); it has ended by then.
const PUSH_DONE: Duration = Duration::from_secs(120);
/// One direct send with J's ack held: every attempt and its retry.
const SEND_BOUND: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Variant {
    PlainJoin,
    Stranger,
}

impl Variant {
    fn reason(self) -> &'static str {
        match self {
            Self::PlainJoin | Self::Stranger => "reseat_invite_outside_staging",
        }
    }

    fn what(self) -> &'static str {
        match self {
            Self::PlainJoin => "(1) J's operator joins with the re-seat invite",
            Self::Stranger => "(2) E joins with the re-seat invite",
        }
    }
}

/// Holds every write from A to J while the flag is set. The rule is added
/// after the prefix's hold, which passes these writes.
fn hold_a_to_j(sim: &Sim) -> Result<Arc<AtomicBool>> {
    use crate::network::sim::Fault;
    let (a, j) = (sim.peer("A")?.0, sim.peer("J")?.0);
    let held = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&held);
    sim.fabric().add_rule(move |write| {
        match flag.load(Ordering::SeqCst) && write.lane.src == a && write.lane.dst == j {
            true => Fault::Drop,
            false => Fault::Pass,
        }
    });
    sim.fabric().mark("fault: every write from A to J held");
    Ok(held)
}

/// `label`'s `invites_refused_reasons` for `group` (`GET
/// /diagnostics/groups`); `Null` while the map is empty.
async fn refused(sim: &Sim, label: &str, group: &str) -> Result<Value> {
    let (code, body) = sim
        .request(label, Method::GET, "/diagnostics/groups", None)
        .await?;
    ensure!(code.is_success(), "{label} diagnostics: {code} {body}");
    let rows = body["groups"].as_array().into_iter().flatten();
    Ok(rows
        .into_iter()
        .find(|row| row["group_id"] == group)
        .map_or(Value::Null, |row| row["invites_refused_reasons"].clone()))
}

fn count(reasons: &Value, reason: &str) -> u64 {
    reasons[reason].as_u64().unwrap_or(0)
}

/// Whether `label` holds a re-seat journal or a staging record.
fn has_journal(sim: &Sim, label: &str) -> Result<bool> {
    Ok(sidecars(sim, label)?
        .iter()
        .any(|body| body.reseat_journal.is_some() || body.staging_record.is_some()))
}

/// A sends J `authorisation` with `invite` as a `group_attest_response`.
/// J's ack is held, so the send can fail after the frame is delivered;
/// the count of frames A->J is the evidence.
async fn send_reseat(
    sim: &Sim,
    group: &str,
    what: &str,
    authorisation: &ReseatAuthorisation,
    invite: &str,
) -> Result<usize> {
    let (j, _) = sim.ids("J")?;
    let payload = encode_message(&GroupRecoveryMessageV1::Response(GroupAttestResponseV1 {
        group: group.to_string(),
        subject: j.0,
        for_head_state_hash: String::new(),
        answer: AttestAnswer::Reseat {
            authorisation: Box::new(authorisation.clone()),
            invite: invite.to_string(),
        },
    }))?;
    let cut = sim.fabric().mark_indexed(format!("case: A sends {what}"));
    let agent = sim.state("A")?.agent.clone();
    sim.within(&format!("A sends {what}"), SEND_BOUND, async {
        let _ = agent.send_direct(&j, payload).await;
    })
    .await?;
    delivered_after(sim, "A", "J", cut)
}

/// What one variant left: its sub-checks, whether it reached its target,
/// and a note.
struct Outcome {
    checks: Vec<(&'static str, bool)>,
    reached: bool,
    note: String,
}

/// Runs `variant` and reads its refusal. J's writes are held, so no answer
/// to a request of J's changes `last_refusal` meanwhile.
async fn run_variant(
    sim: &mut Sim,
    group: &str,
    issued: &IssuedReseatV1,
    variant: Variant,
) -> Result<Outcome> {
    let reason = variant.reason();
    let before = refused(sim, "J", group).await?;
    let mut checks = Vec::new();
    let (reached, note) = match variant {
        Variant::PlainJoin | Variant::Stranger => {
            let joiner = ["J", "E"][usize::from(variant == Variant::Stranger)];
            let owner = crate::identity::UserKeypair::from_seed(&[0x13; 32])?;
            if variant == Variant::Stranger {
                start_certified(sim, "E", &owner, false).await?;
                for other in ["O", "A", "X", "J"] {
                    sim.fabric()
                        .set_partitioned(&sim.peer("E")?, &sim.peer(other)?, true);
                }
                sim.fabric().mark("fault: E partitioned from every node");
            }
            let (code, answer) = redeem(sim, joiner, &issued.invite, &owner).await?;
            let after = refused(sim, joiner, group).await?;
            let base = if joiner == "J" { &before } else { &Value::Null };
            checks.push((
                "join_refused_reseat_invite_outside_staging",
                code == StatusCode::CONFLICT && answer["error"] == reason,
            ));
            checks.push((
                "refusal_counted_reseat_invite_outside_staging",
                count(&after, reason) > count(base, reason),
            ));
            if variant == Variant::Stranger {
                let record = try_view_now(sim, "E", group).await?;
                checks.push(("e_has_no_record_of_the_group", record.is_none()));
            }
            // The join route answered, so the invite reached the joiner:
            // any answer but the refusal (an accept too) is RED.
            (
                true,
                format!("{joiner} join {code} {answer}; refusals before {before} after {after}"),
            )
        }
    };
    Ok(Outcome {
        checks,
        reached,
        note: format!("{} (want {reason}): {note}", variant.what()),
    })
}

/// H-S3-rm4 variant `variant` (ADR 0109 §10).
async fn invite_check(sim: &mut Sim, receipt: &mut Receipt, variant: Variant) -> Result<()> {
    let Some(p) = fork_prefix(sim, receipt, false, false, FINAL_RM4).await? else {
        return Ok(());
    };
    let window = (GATE_WINDOW, "not_on_chain");
    let Some(adv) = advance(sim, receipt, &p, false, window, FINAL_RM4).await? else {
        return Ok(());
    };
    let (group, j_hex) = (p.group.clone(), p.j_hex.clone());
    // H-S3-c: A holds O's mandate advert, then O stops and A removes J.
    let o_agent = sim.ids("O")?.0;
    let bit = crate::dm::CapabilityRegistry::GROUP_RESEAT_MANDATE_V1;
    let floor = sim
        .until("A holds O's mandate advert", SETUP, async |s: &Sim| {
            let Ok(st) = s.state("A") else {
                return false;
            };
            let store = st.agent.capability_store();
            if store.verified_registry_supports(&o_agent, bit) == Some(true) {
                return true;
            }
            st.agent.refresh_application_capability(o_agent, bit).await;
            false
        })
        .await
        .is_ok();
    sim.stop("O", RestartMode::Graceful).await?;
    p.o_to_j_held.store(false, Ordering::SeqCst);
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = sim.api("A", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "A removes J: {code} {body}");
    sim.until("A no longer lists J", SETUP, async |s: &Sim| {
        view_now(s, "A", &group)
            .await
            .is_ok_and(|v| !v.lists(&j_hex))
    })
    .await?;
    let j_removal = view(sim, "A", &group).await?;

    // A's re-seat call. Its push and every write from J are held.
    let a_to_j = hold_a_to_j(sim)?;
    p.j_out_held.store(true, Ordering::SeqCst);
    sim.fabric().mark("fault: every write from J held");
    let path = format!("/groups/{group}/members/{j_hex}/reseat");
    let (reseat_code, answer) = sim
        .api("A", Method::POST, &path, Some(reseat_body(&j_removal)))
        .await?;
    let issued = issued_reseat(sim, "A", &j_hex)?;
    receipt.note(format!(
        "A removes J at {}; reseat by A {reseat_code} {answer}",
        j_removal.describe()
    ));
    let mut checks = advance_checks(&p, &adv, false);
    checks.extend([
        ("a_holds_o_mandate_advert_before_o_stops", floor),
        (
            "a_removal_at_r_plus_3",
            j_removal.state_revision == p.minted.state_revision + 3,
        ),
        (
            "reseat_route_accepts_with_owner_offline",
            reseat_code.is_success(),
        ),
        ("a_stores_the_authorisation", issued.is_some()),
    ]);
    let Some(issued) = issued.filter(|_| reseat_code.is_success()) else {
        // No request has reached J yet, so the receipt classifies INFRA.
        let failing: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
        let observed = format!("failing {failing:?}; reseat {reseat_code} {answer}");
        let red = reseat_code == StatusCode::NOT_FOUND;
        conclude_row(
            receipt,
            (FINAL_RM4, CAUSE_RM4),
            &failing,
            observed,
            red,
            at(sim),
        );
        return Ok(());
    };
    sim.within("A's re-seat push ends", PUSH_DONE + secs(2), async {
        tokio::time::sleep(PUSH_DONE).await;
    })
    .await?;
    a_to_j.store(false, Ordering::SeqCst);
    sim.fabric().mark("fault: A's writes pass to J");
    let base = view(sim, "J", &group).await?;

    let outcome = run_variant(sim, &group, &issued, variant).await?;
    let st = status(sim, "J", &group).await?;
    let jv = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let journal = has_journal(sim, "J")?;
    let contained = st
        .as_ref()
        .is_some_and(|st| st.recovery_state() == Some("reseat_required"))
        && !journal
        && same_record(jv.as_ref(), Some(&base));
    let j_text = st
        .as_ref()
        .map_or_else(|| "404".to_string(), Status::describe);
    receipt.note(format!(
        "{}; J then {j_text}; journal {journal}",
        outcome.note
    ));
    receipt.evidence(
        "the_variant_reached_its_target",
        outcome.reached,
        outcome.note.clone(),
        at(sim),
    );
    let variant_ok = outcome.checks.iter().all(|c| c.1) && contained;
    checks.extend(outcome.checks);
    checks.push(("j_contained_with_no_stub_after_the_variant", contained));

    // Last, A's real authorisation: J's staged join runs.
    p.j_out_held.store(false, Ordering::SeqCst);
    sim.fabric().mark("fault: J's writes released");
    let what = "its real authorisation";
    let real = send_reseat(sim, &group, what, &issued.authorisation, &issued.invite).await?;
    let waited = sim
        .until("J is re-seated", RESEAT_BOUND, async |s: &Sim| {
            let (Ok(Some(jv)), Ok(m), Ok(a)) = (
                try_view_now(s, "J", &group).await,
                membership_now(s, "J", &group).await,
                view_now(s, "A", &group).await,
            ) else {
                return false;
            };
            caught_up(Some(&jv), &a, m.as_deref()) && jv.gap_refusal.is_none()
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    let head = view(sim, "A", &group).await?;
    let j_end = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let membership = sim
        .at_instant("read J's membership", membership_now(sim, "J", &group))
        .await??;
    let reseated = caught_up(j_end.as_ref(), &head, membership.as_deref())
        && j_end.as_ref().is_some_and(|v| v.gap_refusal.is_none());
    checks.push((
        "reseat_head_at_r_plus_4",
        head.state_revision == p.minted.state_revision + 4,
    ));
    checks.push(("j_active_with_keys_at_a_head_after_the_real_one", reseated));
    receipt.request_delivered(
        "a_reached_j",
        real > 0,
        format!("frames A->J with the real authorisation {real}"),
        at(sim),
    );
    let red = (outcome.reached && !variant_ok) || (real > 0 && !reseated);
    let failing: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
    receipt.note(format!("sub-checks {checks:?}"));
    let j_end_text = j_end
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);
    let observed = format!(
        "failing {failing:?}; {}; J before the variant {}; A {}; J at the end {j_end_text} \
         membership {membership:?}",
        outcome.note,
        base.describe(),
        head.describe()
    );
    conclude_row(
        receipt,
        (FINAL_RM4, CAUSE_RM4),
        &failing,
        observed,
        red,
        at(sim),
    );
    Ok(())
}

async fn run(case: &str, seed: u64, variant: Variant) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "ADR 0109 S3 (#1356, #1572) H-S3-rm4 {}; A re-seats with the owner offline",
        variant.what()
    ));
    let labels = match variant {
        Variant::Stranger => RM4_E_LABELS,
        _ => C_LABELS,
    };
    match Sim::empty(case, seed, labels) {
        Ok(mut sim) => {
            if let Err(error) = invite_check(&mut sim, &mut receipt, variant).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL_RM4);
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, variant: Variant) -> Result<()> {
    let receipt = run(case, seed, variant).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// H-S3-rm4 (1): J's own plain join with the re-seat invite is refused.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_rm4_plain_join_refused_outside_staging() -> Result<()> {
    let case = "w3h_1356_control_s3_rm4_plain_join_refused_outside_staging";
    super::super::super::block_on_paused(expect(case, 0x1356_0121, Variant::PlainJoin))
}

/// H-S3-rm4 (2): a node never seated is refused the re-seat invite.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_rm4_stranger_join_refused_outside_staging() -> Result<()> {
    let case = "w3h_1356_control_s3_rm4_stranger_join_refused_outside_staging";
    super::super::super::block_on_paused(expect(case, 0x1356_0122, Variant::Stranger))
}
