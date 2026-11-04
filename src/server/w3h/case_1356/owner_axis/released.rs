//! ADR 0109 §10 H-S3-rm1 (capability floor, D156, #1572) with M on the
//! released v0.46.1 binary. Not a W3-H gate case (no `w3h_` prefix; the
//! test is ignored and runs in its own CI job). The harness is in
//! [`harness`].
//!
//! Setup. Phase 1: the H-S3-c prefix with M1 seated before invite I (`m1`)
//! and the advance on the paused sim; graceful stops; a copy of each node's
//! data and identity dirs. Phase 2, on real loopback sockets on a new
//! plane: O, A and J run in-process on the copies, M runs the released
//! `x0xd` on M1's copy. A holds O's mandate advert (`Some(true)`) and M's
//! advert without the bit (`Some(false)`), so the floor check is not blind.
//!
//! Row. Stop O. A removes J (r+3) and calls the re-seat with basis
//! `Removal(r+3)`. M restarts on the candidate; once A verifies M's current
//! advert (`Some(true)`), A calls the re-seat again.
//!
//! Desired result. The first call is 409 `reseat_receiver_upgrade_required`
//! with `members == [M]`, and A signs, stores and mints nothing (sidecar
//! bytes and A's head unchanged, no issued re-seat). The second call
//! succeeds; J is Active with keys at A's r+4 head, its marker and gap
//! record retired. O's advert stays current, inside the 900 s TTL.
//! A failed row check is RED; a missing prerequisite is INFRA.

use super::*;
use harness::*;
use std::path::Path;

mod harness;
mod rm3;

const CASE: &str = "released_s3_rm1_floor_names_the_released_member";
const SEED: u64 = 0x1356_0152;
const FINAL_RM1: &str = "reseat_refused_while_m_is_released_then_seats_j_at_r_plus_4";
const CAUSE_RM1: &str = "the capability floor did not name only M, A stored or minted on the \
                         refusal, or the second re-seat did not seat J at r+4";

/// Phase 2: the row on real sockets.
async fn floor_row(out: &Path, ex: &Exported, bin: &Path, receipt: &mut Receipt) -> Result<Checks> {
    let plane = format!("x0x.test.h-s3-rm1.{:032x}", rand::random::<u128>());
    let (group, j_hex, m_hex) = (ex.group.as_str(), ex.j_hex.as_str(), ex.m_hex.as_str());
    let a = serve_real(&out.join("A"), &plane, None).await?;
    let o = serve_real(&out.join("O"), &plane, None).await?;
    let j = serve_real(&out.join("J"), &plane, None).await?;
    a.join(o.udp).await?;
    o.join(a.udp).await?;
    j.join(a.udp).await?;
    let released = Released::start(bin, &out.join("M1"), &plane, a.udp, "").await?;
    let o_hex = hex::encode(o.state.agent.agent_id().as_bytes());
    let o_advert = a.advert(&o_hex, true).await?;
    let m_old = a.advert(m_hex, false).await?;
    receipt.note(format!(
        "A's adverts before O stops: O {o_advert:?}, M {m_old:?}"
    ));
    ensure!(o_advert == Some(true), "INFRA: A lacks O's mandate advert");
    ensure!(m_old == Some(false), "INFRA: A lacks M's released advert");

    // Stop O. A removes J (r+3) and calls the re-seat.
    o.stop().await?;
    let o_stopped = tokio::time::Instant::now();
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = a.call(Method::DELETE, &path, None).await?;
    ensure!(code < 300, "INFRA: A removes J: {code} {body}");
    let removal = a.view(group).await?;
    ensure!(!removal.lists(j_hex), "INFRA: A still lists J");
    let a_data = out.join("A").join("data");
    let before = sidecar_state(&a_data, j_hex)?;
    let reseat = format!("/groups/{group}/members/{j_hex}/reseat");
    let (first, refusal) = a
        .call(Method::POST, &reseat, Some(reseat_body(&removal)))
        .await?;
    let after = sidecar_state(&a_data, j_hex)?;
    let held = a.view(group).await?;
    receipt.note(format!(
        "first re-seat {first} {refusal}; A removal {}; A after {}; sidecars before {before:?} \
         after {after:?}",
        removal.describe(),
        held.describe()
    ));

    // Restart M on the candidate; A must verify its current advert.
    released.stop().await;
    let m = serve_real(&out.join("M1"), &plane, None).await?;
    m.join(a.udp).await?;
    a.join(m.udp).await?;
    let m_new = a.advert(m_hex, true).await?;
    let o_before = a.advert(&o_hex, true).await?;
    let (second, answer) = a
        .call(Method::POST, &reseat, Some(reseat_body(&removal)))
        .await?;
    // Read at once: A prunes its issued re-seat when J is seated. This also
    // shows that the sidecar read is not blind.
    let issued = sidecar_state(&a_data, j_hex)?;
    // J must reach A's r+4 head; J's state is read, not its API.
    let deadline = tokio::time::Instant::now() + RESEAT_BOUND;
    let (mut head, mut jv) = (a.view(group).await?, j.view(group).await?);
    while !caught_up(Some(&jv), &head, Some("active")) || !jv.lists(j_hex) {
        if tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        (head, jv) = (a.view(group).await?, j.view(group).await?);
    }
    let (_, j_body) = j
        .call(Method::GET, &format!("/groups/{group}"), None)
        .await?;
    let o_after = a.advert(&o_hex, true).await?;
    let window = o_stopped.elapsed();
    receipt.note(format!(
        "second re-seat {second} {answer}; M advert {m_new:?}; O advert before {o_before:?} \
         after {o_after:?}, {window:?} after O stopped; sidecars {issued:?}; A {}; J {}; J membership {}",
        head.describe(),
        jv.describe(),
        j_body["membership_state"]
    ));
    let (r3, r4) = (removal.state_revision, removal.state_revision + 1);
    let floor = refusal["detail"]["members"] == json!([m_hex]);
    let reason = refusal["reason"] == "reseat_receiver_upgrade_required";
    let seated = caught_up(Some(&jv), &head, Some("active")) && jv.lists(j_hex);
    let retired = jv.marker.is_none() && jv.gap_refusal.is_none();
    let o_current = o_before == Some(true) && o_after == Some(true);
    // Setup: the removal basis, M's candidate advert, O's advert and the
    // TTL window. A failure here is INFRA.
    let setup = vec![
        ("a_removes_j_at_r_plus_3", r3 == ex.sealed + 1),
        ("a_verifies_m_candidate_advert", m_new == Some(true)),
        ("o_advert_current_through_the_row", o_current),
        ("row_inside_the_advert_ttl", window < ADVERT_TTL),
    ];
    let row = vec![
        ("first_reseat_is_409", first == 409),
        (
            "first_reseat_reason_is_reseat_receiver_upgrade_required",
            reason,
        ),
        ("floor_members_are_exactly_m", floor),
        (
            "refusal_leaves_a_sidecar_bytes_unchanged",
            before.0 == after.0,
        ),
        ("refusal_issues_no_reseat", before.1 == 0 && after.1 == 0),
        (
            "refusal_mints_nothing_a_head_unchanged",
            held.state_hash == removal.state_hash,
        ),
        ("second_reseat_succeeds", (200..300).contains(&second)),
        ("second_reseat_issues_one_reseat", issued.1 == 1),
        ("j_active_with_keys_at_a_head", seated),
        ("j_head_is_r_plus_4", jv.state_revision == r4),
        (
            "j_api_reports_active",
            j_body["membership_state"] == "active",
        ),
        ("j_marker_and_gap_retired", retired),
    ];
    for node in [m, j, a] {
        node.stop().await?;
    }
    Ok((setup, row))
}

fn row(receipt: &mut Receipt) -> Result<()> {
    let bin = released_bin()?;
    let (out, exported, runtime) = phase1(CASE, SEED, FINAL_RM1, receipt)?;
    let started = std::time::Instant::now();
    let (setup, row) = runtime.block_on(floor_row(out.path(), &exported, &bin, receipt))?;
    receipt.note(format!("real-socket phase {:?}", started.elapsed()));
    let setup: Vec<_> = exported.checks.iter().copied().chain(setup).collect();
    conclude_checks(receipt, (FINAL_RM1, CAUSE_RM1), &setup, &row);
    Ok(())
}

/// H-S3-rm1 (capability floor, D156): a control (on `main` the route
/// returned 404).
#[test]
#[ignore = "released-binary row: needs X0X_V0461_BIN; runs in its own CI job (#1572)"]
fn released_s3_rm1_floor_names_the_released_member() -> Result<()> {
    let note = "ADR 0109 S3 (#1356, #1572) H-S3-rm1; M runs the released v0.46.1";
    released_test(CASE, SEED, FINAL_RM1, note, row)
}
