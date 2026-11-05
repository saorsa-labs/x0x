//! ADR 0109 §10 row H-S3-rm4 (the re-seat invite check, ADR 0059
//! exception, D156; #1572), variants (1) to (5). Variant (6), the Home
//! policy, is not in this file.
//!
//! Setup: H-S3-c up to A's re-seat call. O stops and A removes J (r+3).
//! J's writes and A's writes to J are held, and A re-seats J with basis
//! `Removal(r+3)`. A's push of the authorisation ends unseen. Then one
//! variant runs, and one test runs each variant:
//! (1) J's operator calls `POST /groups/join` with A's re-seat invite.
//! (2) Node E, never seated, calls `POST /groups/join` with it.
//! (3) A sends J an authorisation whose invite names another owner in its
//! policy, re-signed with A's key.
//! (4) A sends J the re-seat invite with no authorisation paired to it.
//! (5) A sends J a re-seat invite whose policy has no owner axis.
//! Last, J's writes pass and A sends J its real authorisation.
//!
//! Desired: J refuses (1) `reseat_invite_outside_staging`, (3)
//! `owner_mismatch`, (4) `reseat_invite_unpaired` and (5)
//! `invite_downgraded`. Each refusal is counted in `invites_refused
//! {reason}`. J stays `reseat_required`, with no re-seat journal or
//! staging record left, and
//! `last_refusal` names the reason (the API reference adds the prefix
//! `authorisation_refused:` to a refused authorisation). E refuses (2)
//! `reseat_invite_outside_staging` and has no record of the group. Then
//! A's real authorisation re-seats J: J is Active with keys at r+4.
//!
//! `AttestAnswer::Reseat` always carries an authorisation, so (4) sends the
//! real invite with an authorisation that A re-signed for another invite
//! secret. For (1) the join route answers J's operator and writes no
//! recovery state, so the row reads that answer, not `last_refusal`.
//!
//! Where the code differs from the ADR text: ADR 0109 §3a puts the owner
//! pin (check 3) "before any staging stub". The code runs it in the
//! staged join, so (3) and (5) stage, are refused there, and the staging
//! rolls back. The row checks the result the ruling accepts (4 Nov 2026,
//! as for H-S3-rm2 option (b)): after the refusal J holds no re-seat
//! journal and no staging record, and its live record is unchanged.
//!
//! (3) to (5) are the red proof of the fix in `group_recovery.rs`. Before
//! it, the rollback of the refused staged join in (3) and (5) wrote
//! `last_refusal = "join_409"`, and the refusal of (4) was not counted in
//! `invites_refused`. A released joiner's refusal of (2) needs a released
//! binary (the H-S3-home gate harness), so it is not in this file.
//!
//! RED: the variant reached J (or E) and the refusal, the count, J's
//! containment or the last re-seat is wrong. Any other failure is INFRA.

use super::*;
use crate::groups::recovery::{
    encode_message, invite_secret_hash, AttestAnswer, GroupAttestResponseV1,
    GroupRecoveryMessageV1, IssuedReseatV1, ReseatAuthorisation,
};
use crate::groups::state_commit as sc;
use std::sync::atomic::{AtomicBool, Ordering};

const FINAL_RM4: &str =
    "j_refuses_the_reseat_invite_variant_then_the_real_authorisation_reseats_it";
const CAUSE_RM4: &str = "the row's main observation: A's re-seat route returns 404 (no S3 \
                         re-seat); or J (or E) does not refuse the variant with its reason \
                         and count with no stub left, J leaves containment, or A's real \
                         authorisation does not re-seat J at r+4; `observed` lists each \
                         failing step";
/// H-S3-c's nodes plus E, never seated (variant 2 only).
const RM4_E_LABELS: &[&str] = &["O", "A", "X", "J", "E"];
/// A answers the re-seat call with one direct send to J (with its
/// retries); it has ended by then.
const PUSH_DONE: Duration = Duration::from_secs(120);
/// One direct send with J's ack held: every attempt and its retry.
const SEND_BOUND: Duration = Duration::from_secs(60);
/// How long J has to record its answer to one variant.
const REFUSAL_WAIT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Variant {
    PlainJoin,
    Stranger,
    OtherOwner,
    Unpaired,
    Downgraded,
}

impl Variant {
    fn reason(self) -> &'static str {
        match self {
            Self::PlainJoin | Self::Stranger => "reseat_invite_outside_staging",
            Self::OtherOwner => "owner_mismatch",
            Self::Unpaired => "reseat_invite_unpaired",
            Self::Downgraded => "invite_downgraded",
        }
    }

    fn what(self) -> &'static str {
        match self {
            Self::PlainJoin => "(1) J's operator joins with the re-seat invite",
            Self::Stranger => "(2) E joins with the re-seat invite",
            Self::OtherOwner => "(3) an invite naming another owner",
            Self::Unpaired => "(4) the re-seat invite with no paired authorisation",
            Self::Downgraded => "(5) an invite with no owner axis",
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

/// Whether `last_refusal` names `reason`, with or without the
/// `authorisation_refused:` prefix.
fn names(last: Option<&str>, reason: &str) -> bool {
    last.and_then(|r| r.rsplit(':').next()) == Some(reason)
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

/// The variant's authorisation and invite, built from A's real pair and
/// re-signed with A's key. (3) and (5) change the invite's policy, so the
/// base hash is derived again (as the join route derives it) and the
/// authorisation names the new hash.
fn forged(
    sim: &Sim,
    real: &IssuedReseatV1,
    variant: Variant,
) -> Result<(ReseatAuthorisation, String)> {
    let state = sim.state("A")?;
    let a_key = state.agent.identity().agent_keypair();
    let mut fields = real.authorisation.fields.clone();
    let mut link = real.invite.clone();
    if variant == Variant::Unpaired {
        fields.invite_secret_hash = invite_secret_hash("w3h rm4: another invite secret");
    } else {
        let mut invite = crate::groups::invite::SignedInvite::from_link(&real.invite)
            .map_err(|e| anyhow!("A's re-seat invite: {e}"))?;
        let policy = invite.policy.as_mut().context("A's invite has no policy")?;
        policy.admission = match variant {
            Variant::OtherOwner => {
                let other = crate::identity::UserKeypair::from_seed(&[0x31; 32])?;
                crate::groups::GroupAdmission::OwnerCertified(other.user_id())
            }
            _ => crate::groups::GroupAdmission::InviteOnly,
        };
        let view = crate::groups::invite::InviteSignedViewV4::from_invite(&invite)
            .map_err(|r| anyhow!("the changed invite's view: {}", r.reason()))?;
        let policy = view.policy.as_ref().context("the view has no policy")?;
        let hash = sc::compute_state_hash(
            &view.stable_group_id,
            view.base_state_revision,
            view.base_prev_state_hash.as_deref(),
            &sc::roster_root_of_projection(&view.base_roster),
            &sc::compute_policy_hash(policy),
            &sc::compute_public_meta_hash(&view.public_meta),
            view.base_security_binding.as_deref(),
            false,
        );
        invite.base_state_hash = Some(hash.clone());
        invite
            .sign_v4(a_key, None)
            .map_err(|e| anyhow!("A re-signs the changed invite: {e}"))?;
        link = invite
            .encode_link()
            .map_err(|e| anyhow!("the changed invite link: {e:?}"))?;
        fields.invite_base_state_hash = hash;
    }
    let authorisation = ReseatAuthorisation::sign(fields, a_key)
        .map_err(|e| anyhow!("A signs the authorisation: {}", e.as_str()))?;
    Ok((authorisation, link))
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
        _ => {
            let (authorisation, link) = forged(sim, issued, variant)?;
            let delivered = send_reseat(sim, group, variant.what(), &authorisation, &link).await?;
            let mut last = None;
            let mut after = Value::Null;
            let waited = sim
                .until(
                    &format!("J refuses {}", variant.what()),
                    REFUSAL_WAIT,
                    async |s: &Sim| {
                        let st = status_now(s, "J", group).await.ok().flatten();
                        last = st.as_ref().and_then(|st| {
                            st.recovery["last_refusal"].as_str().map(str::to_string)
                        });
                        after = refused(s, "J", group).await.unwrap_or(Value::Null);
                        names(last.as_deref(), reason)
                            && count(&after, reason) > count(&before, reason)
                    },
                )
                .await;
            if let Err(error) = waited {
                ensure!(expired(&error), error);
            }
            checks.push((
                "last_refusal_names_the_reason",
                names(last.as_deref(), reason),
            ));
            checks.push((
                "refusal_counted_under_the_reason",
                count(&after, reason) > count(&before, reason),
            ));
            (
                delivered > 0,
                format!(
                    "frames A->J {delivered}; J last_refusal {last:?}; refusals before {before} \
                     after {after}"
                ),
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

/// H-S3-rm4 (3): an invite that names another owner is refused.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_rm4_other_owner_refused() -> Result<()> {
    let case = "w3h_1356_control_s3_rm4_other_owner_refused";
    super::super::super::block_on_paused(expect(case, 0x1356_0123, Variant::OtherOwner))
}

/// H-S3-rm4 (4): the re-seat invite with no paired authorisation is refused.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_rm4_unpaired_invite_refused() -> Result<()> {
    let case = "w3h_1356_control_s3_rm4_unpaired_invite_refused";
    super::super::super::block_on_paused(expect(case, 0x1356_0124, Variant::Unpaired))
}

/// H-S3-rm4 (5): a re-seat invite with no owner axis is refused.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_rm4_downgraded_invite_refused() -> Result<()> {
    let case = "w3h_1356_control_s3_rm4_downgraded_invite_refused";
    super::super::super::block_on_paused(expect(case, 0x1356_0125, Variant::Downgraded))
}
