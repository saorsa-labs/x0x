//! ADR 0109 §10 row H-S3-q (unreadable sidecar, D120, D119; #1572),
//! variant (3): the issuer. Variant (1) is in `sidecar_q.rs`.
//!
//! Setup: H-S3-c3 (the owner path) up to O's re-seat call. J's writes and
//! O's writes to J are held, O removes J (r+3) and calls the re-seat route
//! with basis `Removal(r+3)`, so O's push of the authorisation ends
//! unseen. Then O stops (not J), its `.grecov` is replaced with 64 bytes
//! that start `JUNKJUNK`, and O starts again. The sim writes no ADR 0094
//! upgrade journal, so the host commit gate is open. Last, every hold is
//! released and O's agent sends J the authorisation it issued before the
//! stop, so J starts its staged join.
//!
//! Desired result (the row's "All" and "(3)" cells):
//! - The old bytes sit, byte-identical, in one ADR 0108 §5a history copy,
//!   and a fresh `.grecov` exists that names one rebuild.
//! - No node commits because of the rebuild: O's head after the restart
//!   is its head before the stop.
//! - O's guard refuses J's staged join. J shows `reseat_required
//!   {reseat_failed}`, and its live record is unchanged.
//! - O's `GET /groups/:id/recovery` shows `issued_reseats_lost`.
//! - O calls the re-seat route again, and J is Active with keys at r+4.
//!
//! RED: the authorisation reached J and one of these steps is wrong. Any
//! other failure is INFRA.
//!
//! **On main (15 Nov 2026): expected RED, #1941.** The quarantine works,
//! nothing commits and O shows `issued_reseats_lost`, but O's guard admits
//! J's staged join for the lost authorisation: J is Active at r+4 at once,
//! and O's second re-seat call answers `409 subject_active`. The arm pins
//! that cause ([`CAUSE_ADMITTED`]); with the fix it turns GREEN and is
//! renamed a control.

use super::super::gaps::recovery_route;
use super::*;
use crate::groups::recovery::{
    decode_message, decode_sidecar, encode_message, AttestAnswer, GroupAttestResponseV1,
    GroupRecoveryMessageV1, IssuedReseatV1, GROUP_RECOVERY_DIR, GROUP_RECOVERY_EXTENSION,
};
use std::sync::atomic::{AtomicBool, Ordering};

const FINAL_Q3: &str = "issuer_sidecar_rebuilt_refuses_the_lost_reseat_then_a_new_reseat_seats_j";
const CAUSE_Q3: &str = "after O's .grecov is rebuilt: the junk is not kept byte-identical in \
                        one history copy, O commits because of the rebuild, O's guard does not \
                        refuse J's staged join (J not reseat_required {reseat_failed} with its \
                        live record unchanged), O's recovery route does not show \
                        issued_reseats_lost, or O's second re-seat does not seat J at r+4; \
                        `observed` lists each failing step";
/// The cause the expected-RED arm pins (#1941).
const CAUSE_ADMITTED: &str = "O's rebuilt sidecar shows issued_reseats_lost, but O admits J's \
                              staged join for the lost authorisation: J is Active at r+4 and O's \
                              second re-seat call answers 409 subject_active (#1941)";
/// The checks #1941 fails, sorted. [`CAUSE_ADMITTED`] applies only when
/// the failing checks are exactly these.
const ADMITTED_FAILING: [&str; 3] = [
    "j_live_record_unchanged_after_the_refusal",
    "j_reseat_required_reseat_failed",
    "second_reseat_route_accepts",
];
/// O answers the re-seat call with one direct send to J (with its
/// retries); it has ended by then.
const PUSH_DONE: Duration = Duration::from_secs(120);
/// One direct send with J's ack held: every attempt and its retry.
const SEND_BOUND: Duration = Duration::from_secs(60);
/// Sends of the lost authorisation before the row gives up (INFRA).
const SEND_ATTEMPTS: usize = 6;
/// How long J has to try its staged join and roll it back.
const REFUSAL_WAIT: Duration = Duration::from_secs(300);

/// The 64 junk bytes the row writes: `JUNKJUNK` and 56 more.
fn junk() -> Vec<u8> {
    [b"JUNKJUNK".as_slice(), &[0u8; 56]].concat()
}

/// Holds every write from O to J while the flag is set. The prefix's own
/// O->J hold is released for the re-seat; this rule holds O's push.
fn hold_o_to_j(sim: &Sim) -> Result<Arc<AtomicBool>> {
    use crate::network::sim::Fault;
    let (o, j) = (sim.peer("O")?.0, sim.peer("J")?.0);
    let held = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&held);
    sim.fabric().add_rule(move |write| {
        match flag.load(Ordering::SeqCst) && write.lane.src == o && write.lane.dst == j {
            true => Fault::Drop,
            false => Fault::Pass,
        }
    });
    sim.fabric().mark("fault: every write from O to J held");
    Ok(held)
}

/// Whether `rx` holds O's re-seat answer for J: a `group_attest_response`
/// from O whose answer is `Reseat` with `digest`'s authorisation.
fn reseat_received(
    rx: &mut crate::direct::DirectMessageReceiver,
    o: &crate::identity::AgentId,
    digest: &[u8],
) -> bool {
    let mut seen = false;
    while let Some(msg) = rx.try_recv() {
        if msg.sender != *o {
            continue;
        }
        if let Ok(GroupRecoveryMessageV1::Response(response)) = decode_message(&msg.payload) {
            if let AttestAnswer::Reseat { authorisation, .. } = &response.answer {
                seen |= authorisation.digest().as_slice() == digest;
            }
        }
    }
    seen
}

/// O sends J `issued` as a `group_attest_response`, as O's push would.
/// Returns whether J received it, read on J's own direct-message stream
/// (not from wire frames: O's reconnect traffic reaches J too).
async fn send_reseat(sim: &Sim, group: &str, issued: &IssuedReseatV1) -> Result<bool> {
    let (j, _) = sim.ids("J")?;
    let o = sim.ids("O")?.0;
    let payload = encode_message(&GroupRecoveryMessageV1::Response(GroupAttestResponseV1 {
        group: group.to_string(),
        subject: j.0,
        for_head_state_hash: String::new(),
        answer: AttestAnswer::Reseat {
            authorisation: Box::new(issued.authorisation.clone()),
            invite: issued.invite.clone(),
        },
    }))?;
    let digest = issued.authorisation.digest();
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    sim.fabric()
        .mark("case: O sends J the authorisation issued before its stop");
    let agent = sim.state("O")?.agent.clone();
    // Right after its restart O can have no link to J yet, so a send can
    // fail before anything leaves: send again until J has received it.
    for _ in 0..SEND_ATTEMPTS {
        sim.within("O sends the lost authorisation", SEND_BOUND, async {
            let _ = agent.send_direct(&j, payload.clone()).await;
        })
        .await?;
        let mut received = false;
        let _ = sim
            .until(
                "J receives the lost authorisation",
                secs(10),
                async |_s: &Sim| {
                    received |= reseat_received(&mut rx, &o, digest.as_slice());
                    received
                },
            )
            .await;
        if received {
            return Ok(true);
        }
    }
    Ok(false)
}

/// O's sidecar directory and its file names (O is stopped).
fn sidecar_dir(sim: &Sim) -> Result<(std::path::PathBuf, Vec<String>)> {
    let dir = sim.data_dir("O")?.join(GROUP_RECOVERY_DIR);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok((dir, names))
}

/// One history copy of `file` holds `junk` byte for byte, no pending copy
/// is left, and the fresh `file` decodes and names exactly one rebuild.
fn quarantined(dir: &std::path::Path, names: &[String], file: &str, junk: &[u8]) -> bool {
    let prefix = format!("{file}.q-");
    let history: Vec<&String> = names
        .iter()
        .filter(|name| name.starts_with(&prefix) && !name.ends_with(".pending"))
        .collect();
    let identical = history
        .iter()
        .filter(|name| std::fs::read(dir.join(name.as_str())).is_ok_and(|bytes| bytes == junk))
        .count();
    let pending = names
        .iter()
        .filter(|name| name.ends_with(".pending"))
        .count();
    let fresh = std::fs::read(dir.join(file))
        .ok()
        .and_then(|bytes| decode_sidecar(&bytes).ok())
        .is_some_and(|body| body.rebuilt_from.len() == 1);
    history.len() == 1 && identical == 1 && pending == 0 && fresh
}

/// H-S3-q (3), the issuer.
async fn issuer_rebuild(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let Some(p) = fork_prefix(sim, receipt, false, false, FINAL_Q3).await? else {
        return Ok(());
    };
    let window = (GATE_WINDOW, "not_on_chain");
    let Some(adv) = advance(sim, receipt, &p, false, window, FINAL_Q3).await? else {
        return Ok(());
    };
    let (group, j_hex) = (p.group.clone(), p.j_hex.clone());

    // O removes J and re-seats it; O's push and J's writes are held.
    let o_to_j = hold_o_to_j(sim)?;
    p.o_to_j_held.store(false, Ordering::SeqCst);
    p.j_out_held.store(true, Ordering::SeqCst);
    sim.fabric().mark("fault: every write from J held");
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = sim.api("O", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "O removes J: {code} {body}");
    sim.until("O no longer lists J", SETUP, async |s: &Sim| {
        view_now(s, "O", &group)
            .await
            .is_ok_and(|v| !v.lists(&j_hex))
    })
    .await?;
    let j_removal = view(sim, "O", &group).await?;
    let reseat_path = format!("/groups/{group}/members/{j_hex}/reseat");
    let (reseat_code, answer) = sim
        .api(
            "O",
            Method::POST,
            &reseat_path,
            Some(reseat_body(&j_removal)),
        )
        .await?;
    let issued = issued_reseat(sim, "O", &j_hex)?;
    receipt.note(format!(
        "O removes J at {}; first reseat by O {reseat_code} {answer}",
        j_removal.describe()
    ));
    let mut checks = advance_checks(&p, &adv, false);
    checks.extend([
        (
            "o_removal_at_r_plus_3",
            j_removal.state_revision == p.minted.state_revision + 3,
        ),
        ("first_reseat_route_accepts", reseat_code.is_success()),
        ("o_stores_the_authorisation", issued.is_some()),
    ]);
    let Some(issued) = issued.filter(|_| reseat_code.is_success()) else {
        let failing: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
        let observed = format!("failing {failing:?}; reseat {reseat_code} {answer}");
        let red = reseat_code == StatusCode::NOT_FOUND;
        conclude_row(
            receipt,
            (FINAL_Q3, CAUSE_Q3),
            &failing,
            observed,
            red,
            at(sim),
        );
        return Ok(());
    };
    sim.within("O's re-seat push ends", PUSH_DONE + secs(2), async {
        tokio::time::sleep(PUSH_DONE).await;
    })
    .await?;
    let base = view(sim, "J", &group).await?;
    let o_before = view(sim, "O", &group).await?;

    // Stop O, damage its sidecar, start it again.
    sim.stop("O", RestartMode::Graceful).await?;
    let (dir, names) = sidecar_dir(sim)?;
    let suffix = format!(".{GROUP_RECOVERY_EXTENSION}");
    let grecov: Vec<&String> = names.iter().filter(|n| n.ends_with(&suffix)).collect();
    ensure!(
        grecov.len() == 1,
        "INFRA: O's sidecar directory holds {} .grecov files, want 1: {names:?}",
        grecov.len()
    );
    let file = grecov[0].clone();
    let junk = junk();
    let target = dir.join(&file);
    std::fs::write(&target, &junk).with_context(|| format!("write {}", target.display()))?;
    sim.fabric()
        .mark(format!("case: O's {file} replaced with 64 junk bytes"));
    sim.start_again("O").await?;
    let o_after = view(sim, "O", &group).await?;
    let route = sim
        .at_instant("read O's recovery route", recovery_route(sim, "O", &group))
        .await??;
    let lost = route["issued_reseats_lost"] == Value::Bool(true);
    receipt.note(format!(
        "O's GET /groups/:id/recovery after the rebuild: {route}"
    ));

    // Release the holds; O's agent sends J the lost authorisation.
    o_to_j.store(false, Ordering::SeqCst);
    p.j_out_held.store(false, Ordering::SeqCst);
    sim.fabric().mark("fault: O->J and J's writes released");
    let received = send_reseat(sim, &group, &issued).await?;
    let mut st = None;
    let waited = sim
        .until(
            "J's staged join is refused",
            REFUSAL_WAIT,
            async |s: &Sim| {
                st = status_now(s, "J", &group).await.ok().flatten();
                st.as_ref().is_some_and(|st| {
                    st.recovery_state() == Some("reseat_required")
                        && st.recovery_cause() == Some("reseat_failed")
                })
            },
        )
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    let jv = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let failed = st.as_ref().is_some_and(|st| {
        st.recovery_state() == Some("reseat_required")
            && st.recovery_cause() == Some("reseat_failed")
    });
    let unchanged = same_record(jv.as_ref(), Some(&base));
    let o_now = view(sim, "O", &group).await?;
    let membership_now_j = sim
        .at_instant("read J's membership", membership_now(sim, "J", &group))
        .await??;
    // The gap the expected-RED arm pins: J was admitted on the lost
    // authorisation.
    let admitted = caught_up(jv.as_ref(), &o_now, membership_now_j.as_deref())
        && o_now.state_revision == p.minted.state_revision + 4;
    let j_text = st
        .as_ref()
        .map_or_else(|| "404".to_string(), Status::describe);
    receipt.note(format!(
        "J received the lost authorisation {received}; J then {j_text}"
    ));
    receipt.request_delivered(
        "o_reached_j_with_the_lost_authorisation",
        received,
        format!("J's direct-message stream holds O's re-seat answer: {received}"),
        at(sim),
    );

    // O calls the route again; J is re-seated.
    let j_removal_now = view(sim, "O", &group).await?;
    let (again_code, again) = sim
        .api(
            "O",
            Method::POST,
            &reseat_path,
            Some(reseat_body(&j_removal_now)),
        )
        .await?;
    let waited = sim
        .until("J is re-seated", RESEAT_BOUND, async |s: &Sim| {
            let (Ok(Some(jv)), Ok(m), Ok(o)) = (
                try_view_now(s, "J", &group).await,
                membership_now(s, "J", &group).await,
                view_now(s, "O", &group).await,
            ) else {
                return false;
            };
            caught_up(Some(&jv), &o, m.as_deref()) && jv.gap_refusal.is_none()
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    let head = view(sim, "O", &group).await?;
    let j_end = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let membership = sim
        .at_instant("read J's membership", membership_now(sim, "J", &group))
        .await??;
    let reseated = caught_up(j_end.as_ref(), &head, membership.as_deref())
        && j_end.as_ref().is_some_and(|v| v.gap_refusal.is_none());

    // The harness reads a node's files only while it is stopped.
    sim.stop("O", RestartMode::Graceful).await?;
    let (dir, names) = sidecar_dir(sim)?;
    let kept = quarantined(&dir, &names, &file, &junk);
    receipt.note(format!("O's sidecar directory at the end: {names:?}"));

    let rebuild_checks = [
        ("old_bytes_in_one_history_copy_and_a_fresh_sidecar", kept),
        (
            "no_commit_because_of_the_rebuild",
            o_after.state_revision == o_before.state_revision
                && o_after.state_hash == o_before.state_hash,
        ),
        ("o_recovery_route_shows_issued_reseats_lost", lost),
        ("j_reseat_required_reseat_failed", failed),
        ("j_live_record_unchanged_after_the_refusal", unchanged),
        ("second_reseat_route_accepts", again_code.is_success()),
        (
            "reseat_head_at_r_plus_4",
            head.state_revision == p.minted.state_revision + 4,
        ),
        ("j_active_with_keys_after_the_second_reseat", reseated),
    ];
    let after_ok = rebuild_checks.iter().all(|c| c.1);
    checks.extend(rebuild_checks);
    let failing: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
    receipt.note(format!("sub-checks {checks:?}"));
    let j_end_text = j_end
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);
    let observed = format!(
        "failing {failing:?}; O before the stop {}, after {}; J before {}; second reseat \
         {again_code} {again}; O {}; J at the end {j_end_text} membership {membership:?}",
        o_before.describe(),
        o_after.describe(),
        base.describe(),
        head.describe()
    );
    let red = received && !after_ok;
    // The pin needs exactly the known set of failing checks. Any other
    // failing check gives the unpinned cause, so a new regression is red.
    let mut failing_set = failing.clone();
    failing_set.sort_unstable();
    let pinned = failing_set == ADMITTED_FAILING
        && admitted
        && again_code == StatusCode::CONFLICT
        && again["error"] == "subject_active";
    let cause = if pinned { CAUSE_ADMITTED } else { CAUSE_Q3 };
    conclude_row(receipt, (FINAL_Q3, cause), &failing, observed, red, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt
        .note("ADR 0109 S3 (#1356, #1572) H-S3-q (3): the issuer's .grecov is rebuilt".to_string());
    match Sim::empty(case, seed, C_LABELS) {
        Ok(mut sim) => {
            if let Err(error) = issuer_rebuild(&mut sim, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL_Q3);
    }
    receipt.emit();
    receipt
}

/// H-S3-q (3): an expected RED on main (#1941), pinned `=RED` in the W3-H
/// gate with [`CAUSE_ADMITTED`]. With the fix the issuer's rebuilt sidecar
/// refuses the lost re-seat, a new re-seat seats J, and the arm is GREEN.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_red_s3_q3_issuer_unreadable_sidecar() -> Result<()> {
    let case = "w3h_1356_red_s3_q3_issuer_unreadable_sidecar";
    let receipt = super::super::super::block_on_paused(run(case, 0x1356_0143));
    // The pin names the exact failure, not any RED.
    ensure!(
        receipt.verdict() == Some(Verdict::Red) && receipt.named_causes().contains(&CAUSE_ADMITTED),
        "{case}: expected Red with the admitted-lost-authorisation cause, got {:?} {:?}",
        receipt.verdict(),
        receipt.named_causes()
    );
    Ok(())
}
