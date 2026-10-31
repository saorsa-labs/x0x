//! ADR 0109 §10 row H-S3-d3 (authorisation refusals, #1572). H-S3-c runs
//! up to `reseat_required {not_on_chain, Gap(..)}` with member M1 seated
//! before invite I. A removes J (r+3) and O re-seats it with basis
//! `Removal(r+3)`; that delivery is held from J. O then sends J, one at a
//! time, five bad authorisations and, past its expiry, the held one. J must
//! answer each with `authorisation_refused` and its typed cause, stay
//! `reseat_required` with no re-seat journal and an unchanged live record,
//! and not re-seat in the hour after.
//!
//! J's writes to A and O are held from the removal until the expired one
//! is refused, so no answer to J's own requests changes `last_refusal`
//! (§8: the newest refusal) between an injection and its read.

use super::*;
use crate::groups::recovery::{
    encode_message, AttestAnswer, GroupAttestResponseV1, GroupRecoveryMessageV1, RecoveryRef,
    ReseatAuthorisation, ReseatAuthorisationFields, ReseatBasis,
};
use std::sync::atomic::Ordering;

pub(super) const FINAL_D3: &str =
    "j_refuses_each_bad_authorisation_with_its_typed_cause_and_never_reseats";
const CAUSE_D3: &str = "the row's main observation: O's re-seat route returns 404 (no S3 \
                        re-seat); or J consumes a refused authorisation, answers one with \
                        another cause or re-seats in the last hour; `observed` lists each \
                        failing step";
/// O answers the re-seat call with one direct send to J (with its
/// retries); it has ended by then.
const PUSH_DONE: Duration = Duration::from_secs(120);
/// One direct send with J's ack held: every attempt and its retry.
const SEND_BOUND: Duration = Duration::from_secs(60);
/// How long J has to record its answer to one injection.
const REFUSAL_WAIT: Duration = Duration::from_secs(60);
/// "Advance 1 h with no further route call."
const QUIET: Duration = Duration::from_secs(60 * 60);

/// One authorisation O sends to J, and the `last_refusal` J must show.
struct Injection {
    what: &'static str,
    authorisation: ReseatAuthorisation,
    invite: String,
    expect: &'static str,
    /// The row's sub-checks: refused with `expect`, and contained after.
    checks: (&'static str, &'static str),
}

/// J's answer to one injection.
struct Answer {
    delivered: usize,
    refusal: Option<String>,
    contained: bool,
}

/// O sends `injection` to J as a `group_attest_response`, then waits for
/// J's `last_refusal` to name the expected cause. J's ack to O is held, so
/// the send can report a failure after the frame is delivered; the
/// delivered count is the evidence.
async fn inject(sim: &Sim, group: &str, base: &View, injection: &Injection) -> Result<Answer> {
    let (j, _) = sim.ids("J")?;
    let payload = encode_message(&GroupRecoveryMessageV1::Response(GroupAttestResponseV1 {
        group: group.to_string(),
        subject: j.0,
        for_head_state_hash: String::new(),
        answer: AttestAnswer::Reseat {
            authorisation: Box::new(injection.authorisation.clone()),
            invite: injection.invite.clone(),
        },
    }))?;
    let cut = sim
        .fabric()
        .mark_indexed(format!("case: O injects {}", injection.what));
    // The send waits out J's held ack (its attempts and retry), so it
    // runs in a barrier, where virtual time moves.
    let agent = sim.state("O")?.agent.clone();
    sim.within(&format!("O sends {}", injection.what), SEND_BOUND, async {
        let _ = agent.send_direct(&j, payload).await;
    })
    .await?;
    let want = format!("authorisation_refused:{}", injection.expect);
    let mut refusal = None;
    let waited = sim
        .until(
            &format!("J refuses {}", injection.what),
            REFUSAL_WAIT,
            async |s: &Sim| {
                let st = status_now(s, "J", group).await.ok().flatten();
                refusal = st
                    .as_ref()
                    .and_then(|st| st.recovery["last_refusal"].as_str().map(str::to_string));
                refusal.as_deref() == Some(want.as_str())
            },
        )
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    let st = status(sim, "J", group).await?;
    let jv = sim
        .at_instant("read J's group", try_view_now(sim, "J", group))
        .await??;
    let contained = st.is_some_and(|st| st.recovery_state() == Some("reseat_required"))
        && !has_reseat_journal(sim, "J")?
        && same_record(jv.as_ref(), Some(base));
    Ok(Answer {
        delivered: delivered_after(sim, "O", "J", cut)?,
        refusal,
        contained,
    })
}

/// Whether `label` holds a re-seat journal or a staging record.
fn has_reseat_journal(sim: &Sim, label: &str) -> Result<bool> {
    Ok(sidecars(sim, label)?
        .iter()
        .any(|body| body.reseat_journal.is_some() || body.staging_record.is_some()))
}

/// The five bad authorisations, built from O's real one (`real`, paired
/// with `link`): (1) a changed signature byte; (2) signed with M1's key;
/// (3) signed by O for subject M1; (4) a `Gap` ref J does not hold; (5) an
/// invite base at r+2, which seats J, with J's live `Gap` ref as basis.
fn forgeries(
    sim: &Sim,
    p: &Prefix,
    gap: &RecoveryRef,
    real: &ReseatAuthorisation,
    link: &str,
) -> Result<Vec<Injection>> {
    let sign = |label: &str, fields: ReseatAuthorisationFields| {
        let state = sim.state(label)?;
        ReseatAuthorisation::sign(fields, state.agent.identity().agent_keypair())
            .map_err(|e| anyhow!("{label} signs an authorisation: {}", e.as_str()))
    };
    let m1_hex = sim.agent_hex("M1")?;
    let mut bad_signature = real.clone();
    let mut raw = hex::decode(&bad_signature.signature)?;
    let first = raw
        .first_mut()
        .context("O's authorisation has no signature")?;
    *first ^= 0x01;
    bad_signature.signature = hex::encode(raw);
    // O issued `real`, so its fields name O as signer.
    let fields = || real.fields.clone();
    let RecoveryRef::Gap {
        reason,
        head_state_hash,
        terminal_revision,
        ..
    } = gap
    else {
        bail!("J's live ref is not a gap ref: {gap:?}");
    };
    let unknown_gap = RecoveryRef::Gap {
        reason: reason.clone(),
        head_state_hash: head_state_hash.clone(),
        terminal_revision: *terminal_revision,
        terminal_state_hash: blake3::hash(b"w3h d3: a gap J does not hold")
            .to_hex()
            .to_string(),
    };
    // (5): O's invite with its base moved to r+2, where J is Active.
    let mut invite = crate::groups::invite::SignedInvite::from_link(link)
        .map_err(|e| anyhow!("O's re-seat invite: {e}"))?;
    invite.base_state_revision = Some(p.sealed.state_revision);
    invite.base_state_hash = Some(p.sealed.state_hash.clone());
    invite.base_roster.get_or_insert_default().insert(
        p.j_hex.clone(),
        crate::groups::state_commit::RosterMemberSnapshot {
            role: crate::groups::GroupRole::Member,
            state: crate::groups::GroupMemberState::Active,
            treekem_key_package_hash: None,
            certificate_digest: None,
        },
    );
    let owner = crate::identity::UserKeypair::from_seed(&[0x13; 32])?;
    invite
        .sign_v4(
            sim.state("O")?.agent.identity().agent_keypair(),
            Some(&owner),
        )
        .map_err(|e| anyhow!("O re-signs the r+2 invite: {e}"))?;
    let seats_j = invite
        .encode_link()
        .map_err(|e| anyhow!("the r+2 invite link: {e:?}"))?;
    let one = |what, authorisation, invite: &str, expect, checks| Injection {
        what,
        authorisation,
        invite: invite.to_string(),
        expect,
        checks,
    };
    Ok(vec![
        one(
            "(1) a changed signature byte",
            bad_signature,
            link,
            "signature",
            ("refused_signature", "j_contained_after_signature"),
        ),
        one(
            "(2) one signed with M1's key",
            sign(
                "M1",
                ReseatAuthorisationFields {
                    signer: m1_hex.clone(),
                    ..real.fields.clone()
                },
            )?,
            link,
            "signer",
            ("refused_signer", "j_contained_after_signer"),
        ),
        one(
            "(3) one naming subject M1",
            sign(
                "O",
                ReseatAuthorisationFields {
                    subject: m1_hex,
                    ..fields()
                },
            )?,
            link,
            "subject",
            ("refused_subject", "j_contained_after_subject"),
        ),
        one(
            "(4) one naming a gap ref J does not hold",
            sign(
                "O",
                ReseatAuthorisationFields {
                    basis: ReseatBasis::Ref(unknown_gap),
                    ..fields()
                },
            )?,
            link,
            "basis",
            ("refused_basis", "j_contained_after_basis"),
        ),
        one(
            "(5) one whose invite base r+2 seats J",
            sign(
                "O",
                ReseatAuthorisationFields {
                    basis: ReseatBasis::Ref(gap.clone()),
                    invite_base_revision: p.sealed.state_revision,
                    invite_base_state_hash: p.sealed.state_hash.clone(),
                    ..fields()
                },
            )?,
            &seats_j,
            "base_seats_subject",
            (
                "refused_base_seats_subject",
                "j_contained_after_base_seats_subject",
            ),
        ),
    ])
}

/// H-S3-d3 (ADR 0109 §10).
pub(super) async fn authorisation_refusals(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let Some(p) = fork_prefix(sim, receipt, false, true).await? else {
        return Ok(());
    };
    let (group, j_hex) = (p.group.clone(), p.j_hex.clone());
    let typed = sim
        .until(
            "J shows reseat_required {not_on_chain, Gap}",
            GATE_WINDOW,
            async |s: &Sim| {
                status_now(s, "J", &group)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|st| {
                        st.recovery_state() == Some("reseat_required")
                            && st.recovery_cause() == Some("not_on_chain")
                            && st.recovery["ref"]["kind"] == "gap"
                    })
            },
        )
        .await
        .is_ok();
    let j_status = status(sim, "J", &group).await?;
    let gap = j_status
        .as_ref()
        .and_then(|st| ReseatBasis::from_json(&st.recovery["ref"]))
        .and_then(|basis| match basis {
            ReseatBasis::Ref(gap @ RecoveryRef::Gap { .. }) => Some(gap),
            _ => None,
        });
    let j_text = j_status
        .as_ref()
        .map_or_else(|| "404".to_string(), Status::describe);
    receipt.evidence(
        "j_reseat_required_not_on_chain_with_a_gap_ref",
        typed && gap.is_some(),
        format!("J {j_text}"),
        at(sim),
    );
    let Some(gap) = gap else {
        receipt.note("J shows no gap ref: the row's prerequisite is missing");
        receipt.finish(FINAL_D3, false, at(sim));
        return Ok(());
    };

    // From here no answer to J's own requests reaches J.
    p.j_out_held.store(true, Ordering::SeqCst);
    sim.fabric()
        .mark("fault: every write from J to A and O held");
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = sim.api("A", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "A removes J: {code} {body}");
    let j_removal = view(sim, "A", &group).await?;
    all_reach(sim, &["O"], &group, &j_removal.state_hash).await?;
    let cut = sim.fabric().writes().len();
    let path = format!("/groups/{group}/members/{j_hex}/reseat");
    let (reseat_code, answer) = sim
        .api("O", Method::POST, &path, Some(reseat_body(&j_removal)))
        .await?;
    let issued = issued_reseat(sim, "O", &j_hex)?;
    receipt.note(format!(
        "A removes J at {}; reseat by O {reseat_code} {answer}",
        j_removal.describe()
    ));
    let mut checks = vec![
        (
            "a_removal_at_r_plus_3",
            j_removal.state_revision == p.minted.state_revision + 3 && !j_removal.lists(&j_hex),
        ),
        (
            "reseat_route_accepts_the_removal_basis",
            reseat_code.is_success(),
        ),
    ];
    checks.push(("o_stores_the_authorisation", issued.is_some()));
    let Some(issued) = issued.filter(|_| reseat_code.is_success()) else {
        let red = reseat_code == StatusCode::NOT_FOUND;
        let failing: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
        let observed = format!("failing {failing:?}; reseat {reseat_code} {answer}");
        conclude_row(
            receipt,
            (FINAL_D3, CAUSE_D3),
            &failing,
            observed,
            red,
            at(sim),
        );
        return Ok(());
    };
    // O's own push of the authorisation is held (every O->J write since
    // the prefix). Once it has ended, O's direct writes pass to J.
    sim.within("O's re-seat push ends", PUSH_DONE + secs(2), async {
        tokio::time::sleep(PUSH_DONE).await;
    })
    .await?;
    p.o_to_j_held.store(false, Ordering::SeqCst);
    sim.fabric().mark("fault: O's direct writes pass to J");
    let base = view(sim, "J", &group).await?;

    let mut answers = Vec::new();
    let mut injections = forgeries(sim, &p, &gap, &issued.authorisation, &issued.invite)?;
    for injection in &injections {
        answers.push(inject(sim, &group, &base, injection).await?);
    }
    // Past the held authorisation's expiry, O sends it as it was.
    let expires = Duration::from_millis(issued.authorisation.fields.expires_at_ms);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let wait = expires.saturating_sub(now) + secs(60);
    sim.within("past the authorisation's expiry", wait + secs(2), async {
        tokio::time::sleep(wait).await;
    })
    .await?;
    let expired_one = Injection {
        what: "(6) the held authorisation after its expiry",
        authorisation: issued.authorisation.clone(),
        invite: issued.invite.clone(),
        expect: "expired",
        checks: ("refused_expired", "j_contained_after_expired"),
    };
    answers.push(inject(sim, &group, &base, &expired_one).await?);
    injections.push(expired_one);

    // "Advance 1 h with no further route call": J asks A and O again.
    p.j_out_held.store(false, Ordering::SeqCst);
    sim.fabric().mark("fault: J's writes to A and O released");
    let mut states = Vec::new();
    let mut seen = Observations::default();
    let waited = sim
        .until("the last hour", QUIET, async |s: &Sim| {
            let Some(st) = seen.observe(status_now(s, "J", &group)).await else {
                return true;
            };
            let state = st.map(|st| st.recovery_state().map(str::to_string));
            if states.last() != Some(&state) {
                states.push(state);
            }
            false
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    seen.verify("the last hour")?;
    let j_end = view(sim, "J", &group).await?;
    let journal = has_reseat_journal(sim, "J")?;
    let mut adds = 0;
    for issuer in ["O", "A"] {
        adds += member_added_mandates(sim, cut, issuer, "J")?.0;
    }
    let quiet = states
        .iter()
        .all(|s| s.as_ref().and_then(Option::as_deref) == Some("reseat_required"))
        && !journal
        && adds == 0
        && same_record(Some(&j_end), Some(&base));

    let mut red = reseat_code == StatusCode::NOT_FOUND || !quiet;
    for (injection, answer) in injections.iter().zip(&answers) {
        receipt.evidence(
            "o_injection_delivered_to_j",
            answer.delivered > 0,
            format!("{}: frames O->J {}", injection.what, answer.delivered),
            at(sim),
        );
        let refused = answer.refusal.as_deref()
            == Some(format!("authorisation_refused:{}", injection.expect).as_str());
        // An injection that never reached J is INFRA (the evidence above).
        red |= answer.delivered > 0 && !(refused && answer.contained);
        receipt.note(format!(
            "{}: J last_refusal {:?} (want {}); contained {}",
            injection.what, answer.refusal, injection.expect, answer.contained
        ));
        checks.push((injection.checks.0, refused));
        checks.push((injection.checks.1, answer.contained));
    }
    checks.push(("no_reseat_in_the_last_hour", quiet));
    receipt.request_delivered(
        "o_reached_j",
        answers.iter().all(|a| a.delivered > 0),
        format!(
            "injections delivered {:?}",
            answers.iter().map(|a| a.delivered).collect::<Vec<_>>()
        ),
        at(sim),
    );
    let failing: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
    receipt.note(format!("sub-checks {checks:?}"));
    let observed = format!(
        "failing {failing:?}; J states over the last hour {states:?}; MemberAdded(J) writes \
         {adds}; journal {journal}; J at the end {}; J before the injections {}",
        j_end.describe(),
        base.describe()
    );
    conclude_row(
        receipt,
        (FINAL_D3, CAUSE_D3),
        &failing,
        observed,
        red,
        at(sim),
    );
    Ok(())
}
