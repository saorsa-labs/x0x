//! ADR 0109 §10 H-S3-m (versions; #1572), the OwnerCertified variant: a
//! released v0.46.1 node on J's data directory while J holds an
//! OwnerCertified group in both legacy views. Not a W3-H gate case (no
//! `w3h_` prefix; the test is ignored and runs in the released-rows CI
//! job). The non-Home variant on H-S3-s is [`super::m`].
//!
//! **Why the H-S3-c setup.** H-S3-s cannot carry this variant: its
//! joiner redeems a plain invite, and an owner-pinned joiner keeps no
//! record while the metadata topic is held, so it ends
//! `no_admission_result` and a plain join of the OwnerCertified group is
//! refused (409). H-S3-c is the OwnerCertified setup of ADR 0109 §10: J
//! holds an owner-issued agent certificate, redeems invite I, and O's
//! seal (r+2) arms J's gap gate. Its phase 1 is H-S3-rm1's
//! ([`super::harness::phase1`]).
//!
//! **No placeholder here.** J's gap is owner-reason
//! (`owner_attested_stale_base_gap`, from O's v2 terminal attestation),
//! and no admin ATA is armed. ADR 0109 §4 writes the S3 placeholder only
//! while an admin-reason gap record is armed (`needs_placeholder`), so
//! J's views hold its real record (X's fork r+1′, which seats others) and
//! J has no sidecar. The row's "no Active and no admin seat" cell is the
//! placeholder's, so this variant checks what the released binary can do
//! on that record instead: nothing changes and nothing is minted.
//!
//! Setup. Phase 1: the H-S3-c prefix with M1 and the advance on the
//! paused sim; graceful stops; copies of each node's dirs.
//!
//! Row. The released v0.46.1 `x0xd` starts on J's copy with no network
//! peers (as H-S3-home and H-S3-m), is checked, stops, starts again (the
//! reload) and is checked again. Then, on real loopback sockets on a new
//! plane, O, A, M1 and J run the candidate on the copies. Stop O. A
//! removes J (r+3) and calls the re-seat with basis `Removal(r+3)` (as
//! the second call of H-S3-rm1).
//!
//! Desired result:
//! - Old-authority bytes are unchanged: J's entry in `named_groups.json`
//!   and in `home-suite-groups.json` (revision, hash, roster) does not
//!   move through both released runs, and no sidecar appears.
//! - On the released binary, in each run: the members API answers a
//!   roster array; `POST /groups/:id/invite` is refused with 403; the
//!   roster revision does not move through a 45 s wait; J's membership is
//!   `not_member`.
//! - The candidate resumes and converges: the re-seat succeeds, and J is
//!   Active with keys at A's r+4 head, its marker and gap record retired.
//!
//! A failed row check is RED; a missing prerequisite is INFRA.

use super::m::{released_run, view_entry, Legacy, LiveRun};
use super::*;
use std::path::Path;

const CASE: &str = "released_s3_m_owner_certified_released_node_on_j";
const SEED: u64 = 0x1356_0157;
const FINAL_MO: &str = "released_j_inert_on_owner_certified_then_the_candidate_converges";
const CAUSE_MO: &str = "the released v0.46.1 on J's data directory changed a durable view or \
                        the sidecar, seated someone, minted an invite or moved the roster, or \
                        the re-seat did not then seat J at r+4";

/// J's two durable views of the group.
#[derive(Debug, Clone, PartialEq)]
struct Views {
    legacy: Option<Legacy>,
    home_suite: Option<Legacy>,
}

fn views(data: &Path, group: &str) -> Result<Views> {
    let file = crate::server::routes::named_groups::HOME_SUITE_GROUPS_FILE;
    let home_suite = if data.join(file).is_file() {
        view_entry(data, file, group)?
    } else {
        None
    };
    Ok(Views {
        legacy: view_entry(data, "named_groups.json", group)?,
        home_suite,
    })
}

/// The released runs (start, then the reload) on J's copy.
async fn released_runs(bin: &Path, node: &Path, group: &str) -> Result<(LiveRun, LiveRun)> {
    let first = released_run(bin, node, group).await?;
    let reload = released_run(bin, node, group).await?;
    Ok((first, reload))
}

async fn owner_row(out: &Path, ex: &Exported, bin: &Path, receipt: &mut Receipt) -> Result<Checks> {
    let (group, j_hex, m_hex) = (ex.group.as_str(), ex.j_hex.as_str(), ex.m_hex.as_str());

    // The released binary on J's copy.
    let j_node = out.join("J");
    let j_data = j_node.join("data");
    let before = views(&j_data, group)?;
    let sidecar_before = sidecar_state(&j_data, j_hex)?.0;
    let (first, reload) = released_runs(bin, &j_node, group).await?;
    let after = views(&j_data, group)?;
    let sidecar_after = sidecar_state(&j_data, j_hex)?.0;
    receipt.note(format!(
        "views before {before:?}, after both runs {after:?}; run 1 {first:?}; reload \
         {reload:?} (each run wants invite 403, members 200 with a roster, membership \
         not_member); sidecars before {sidecar_before:?} after {sidecar_after:?}"
    ));

    // The candidate resumes on real sockets; the re-seat seats J.
    let plane = format!("x0x.test.h-s3-m-owner.{:032x}", rand::random::<u128>());
    let a = serve_real(&out.join("A"), &plane, None).await?;
    let o = serve_real(&out.join("O"), &plane, None).await?;
    let m = serve_real(&out.join("M1"), &plane, None).await?;
    let j = serve_real(&j_node, &plane, None).await?;
    a.join(o.udp).await?;
    o.join(a.udp).await?;
    m.join(a.udp).await?;
    a.join(m.udp).await?;
    j.join(a.udp).await?;
    let o_hex = hex::encode(o.state.agent.agent_id().as_bytes());
    let o_advert = a.advert(&o_hex, true).await?;
    let m_advert = a.advert(m_hex, true).await?;
    receipt.note(format!(
        "A's adverts before O stops: O {o_advert:?}, M {m_advert:?}"
    ));
    o.stop().await?;
    let o_stopped = tokio::time::Instant::now();
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = a.call(Method::DELETE, &path, None).await?;
    ensure!(code < 300, "INFRA: A removes J: {code} {body}");
    let removal = a.view(group).await?;
    ensure!(!removal.lists(j_hex), "INFRA: A still lists J");
    let reseat = format!("/groups/{group}/members/{j_hex}/reseat");
    let (code, answer) = a
        .call(Method::POST, &reseat, Some(reseat_body(&removal)))
        .await?;
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
    let window = o_stopped.elapsed();
    receipt.note(format!(
        "re-seat {code} {answer}; {window:?} after O stopped; A {}; J {}; J membership {}",
        head.describe(),
        jv.describe(),
        j_body["membership_state"]
    ));
    let r4 = removal.state_revision + 1;
    let seated = caught_up(Some(&jv), &head, Some("active")) && jv.lists(j_hex);
    let retired = jv.marker.is_none() && jv.gap_refusal.is_none();
    receipt.request_delivered(
        "a_answered_the_candidate_j",
        jv.state_revision > ex.sealed,
        format!(
            "J's head {} after the re-seat, sealed {}",
            jv.state_revision, ex.sealed
        ),
        0,
    );
    // J's head before the stop is X's r+1′, one below O's seal r+2.
    let real_record = before
        .legacy
        .as_ref()
        .is_some_and(|entry| entry.revision == Some(ex.sealed - 1) && !entry.seats_no_one);
    let setup = vec![
        ("j_legacy_entry_is_its_real_r_plus_1_prime", real_record),
        (
            "j_home_suite_entry_matches",
            before.home_suite == before.legacy,
        ),
        (
            "j_has_no_sidecar_owner_reason_gap",
            sidecar_before.is_empty(),
        ),
        (
            "a_verifies_o_and_m_adverts",
            o_advert == Some(true) && m_advert == Some(true),
        ),
        (
            "a_removes_j_at_r_plus_3",
            removal.state_revision == ex.sealed + 1,
        ),
        ("row_inside_the_advert_ttl", window < ADVERT_TTL),
    ];
    for (name, ok) in &setup {
        receipt.evidence(name, *ok, format!("{name}: {ok}"), 0);
    }
    let row = vec![
        (
            "old_authority_views_unchanged_through_both_runs",
            after == before,
        ),
        ("no_sidecar_appears", sidecar_after == sidecar_before),
        ("released_run_1_inert", first.inert_with_roster()),
        ("released_reload_inert", reload.inert_with_roster()),
        ("reseat_succeeds", (200..300).contains(&code)),
        ("j_active_with_keys_at_a_head", seated),
        ("j_head_is_r_plus_4", jv.state_revision == r4),
        ("j_marker_and_gap_retired", retired),
    ];
    for node in [m, j, a] {
        node.stop().await?;
    }
    Ok((setup, row))
}

fn row(receipt: &mut Receipt) -> Result<()> {
    let bin = released_bin()?;
    let (out, exported, runtime) = phase1(CASE, SEED, FINAL_MO, receipt)?;
    let started = std::time::Instant::now();
    let (setup, row) = runtime.block_on(owner_row(out.path(), &exported, &bin, receipt))?;
    receipt.note(format!(
        "released and real-socket phase {:?}",
        started.elapsed()
    ));
    let setup: Vec<_> = exported.checks.iter().copied().chain(setup).collect();
    conclude_checks(receipt, (FINAL_MO, CAUSE_MO), &setup, &row);
    Ok(())
}

/// H-S3-m (versions), OwnerCertified group.
#[test]
#[ignore = "released-binary row: needs X0X_V0461_BIN; runs in its own CI job (#1572)"]
fn released_s3_m_owner_certified_released_node_on_j() -> Result<()> {
    let note = "ADR 0109 S3 (#1356, #1572) H-S3-m OwnerCertified; J's data dir runs the \
                released v0.46.1 under H-S3-c's owner-reason gap";
    released_test(CASE, SEED, FINAL_MO, note, row)
}
