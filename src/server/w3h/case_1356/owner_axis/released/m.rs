//! ADR 0109 §10 H-S3-m (versions; #1572): a released v0.46.1 node on J's
//! data directory mid-H-S3-s. Not a W3-H gate case (no `w3h_` prefix; the
//! test is ignored and runs in the released-rows CI job).
//!
//! On the paused sim: H-S3-s (`segments_s`) with the segment length 2 by
//! test configuration, up to J stopped between the segments at r+2, with
//! its S3 placeholder on disk. While the sim waits, the released v0.46.1
//! `x0xd` starts on J's own data directory with no network peers (as
//! H-S3-home), is checked, stops, starts again (the reload) and is checked
//! again. Then J starts again on the candidate, in the sim.
//!
//! Desired result (the row's cells, non-Home group):
//! - Old-authority bytes are unchanged: J's `named_groups.json` entry for
//!   the group (the legacy view a released binary loads) seats no one,
//!   and its state revision and hash do not move through both released
//!   runs. The sidecar sha256 is unchanged.
//! - On the released binary: it starts; after the reload the group has no
//!   Active and no admin seat (members API, which must answer a roster
//!   array, and legacy view); `POST /groups/:id/invite` is refused with
//!   403; the roster revision in its API does not move through a 45 s
//!   wait, and J's membership is `not_member`.
//! - The candidate resumes and converges: J is Active with keys at A's
//!   terminal r+4, with no marker.
//!
//! **Why the sim.** A first version ran A and the candidate J on real
//! sockets from copies of the sim's data (as H-S3-rm1). There the
//! candidate J stopped at `catching_up {cursor: r+3, segment_terminal:
//! r+4}` for 420 s, with or without the released runs: A restarted from
//! its copy does not serve J's terminal. Here A never restarts, as in
//! H-S3-s. The released runs have no peers, so "no page applies" means no
//! local commit; H-S3-home makes the same choice.
//!
//! The row also asks for the same with an OwnerCertified group in both
//! views; that variant is not in this file (#1572). Home is H-S3-home.
//! A failed row check is RED; a missing prerequisite is INFRA.

use super::super::super::gaps::{remove, s0, seal_j, sees_s3};
use super::super::super::segments::hold_meta_from_j;
use super::super::super::segments_s::MuteAtEnd;
use super::*;
use crate::groups::recovery::AtaMaxLinksOverride;
use std::path::Path;

const CASE: &str = "released_s3_m_released_node_on_j_between_segments";
const SEED: u64 = 0x1356_0156;
const FINAL_M: &str = "released_j_inert_mid_segments_then_the_candidate_converges";
const CAUSE_M: &str = "the released v0.46.1 on J's data directory changed the old-authority \
                       entry or the sidecar, seated someone, minted an invite or moved the \
                       roster, or the candidate did not then converge";
const LABELS: &[&str] = &["A", "M1", "M2", "J"];
/// The test segment length (H-S3-s).
const SEGMENT: u64 = 2;
/// ADR 0109 H-S3-a's window, also enough for one request round.
const WINDOW: Duration = Duration::from_secs(130);
/// The candidate J's convergence bound after the restart (virtual time).
/// A plain run (no W3-H entropy shim) once needed more than one window.
const CONVERGE: Duration = Duration::from_secs(390);
const QUIET: Duration = Duration::from_secs(30);
/// Real time each released run stays up, for a commit to show.
const RELEASED_WAIT: Duration = Duration::from_secs(45);

/// J's legacy-view entry for the group in `named_groups.json`.
#[derive(Debug, Clone, PartialEq)]
struct Legacy {
    /// A non-empty roster with no Active member, so no admin.
    seats_no_one: bool,
    revision: Option<u64>,
    hash: Option<String>,
}

fn legacy(data: &Path, group: &str) -> Result<Option<Legacy>> {
    let bytes = std::fs::read(data.join("named_groups.json"))?;
    let map: serde_json::Map<String, Value> = serde_json::from_slice(&bytes)?;
    let entry = map.iter().find_map(|(key, entry)| {
        let named = key.eq_ignore_ascii_case(group)
            || entry["stable_group_id"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(group));
        named.then_some(entry)
    });
    Ok(entry.map(|entry| Legacy {
        seats_no_one: entry["members_v2"].as_object().is_some_and(|members| {
            !members.is_empty() && members.values().all(|member| member["state"] != "active")
        }),
        revision: entry["state_revision"].as_u64(),
        hash: entry["state_hash"].as_str().map(str::to_string),
    }))
}

/// One released run's live checks.
#[derive(Debug, Default)]
struct LiveRun {
    invite: u16,
    /// The status of `GET /groups/:id/members` and its Active and admin
    /// row counts; `None` when the body has no `members` array.
    members: (u16, Option<(usize, usize)>),
    /// `roster_revision` in `GET /groups/:id` at the start and after the
    /// wait (v0.46.1 reports no state revision there; the legacy view's
    /// state revision is checked on disk).
    revisions: (Option<u64>, Option<u64>),
    /// `membership_state` in the first `GET /groups/:id`.
    membership: Option<String>,
    up_after_wait: bool,
}

impl LiveRun {
    /// v0.46.1's answers on J's placeholder: the invite is refused by
    /// `require_admin_or_above` (403), and `local_join_membership_state`
    /// is `not_member` (J has no Active or Pending row). PR #1957's CI run
    /// saw exactly these in both runs.
    fn ok(&self) -> bool {
        self.invite == 403
            && self.members == (200, Some((0, 0)))
            && self.revisions.0.is_some()
            && self.revisions.1 == self.revisions.0
            && self.membership.as_deref() == Some("not_member")
            && self.up_after_wait
    }
}

/// The members cell: the status, and the Active and admin row counts only
/// when the body holds a `members` array (an unreadable body is not an
/// empty roster).
fn roster_counts(code: u16, body: &Value) -> (u16, Option<(usize, usize)>) {
    let counts = body["members"].as_array().map(|rows| {
        let active = rows.iter().filter(|row| row["state"] == "active");
        let admins = active.clone().filter(|row| row["role"] == "admin").count();
        (active.count(), admins)
    });
    (code, counts)
}

async fn released_run(bin: &Path, node: &Path, group: &str) -> Result<LiveRun> {
    // The released runs have no peers: a loopback port bound and freed
    // here answers nothing (the daemon refuses a privileged port).
    let no_peer = std::net::UdpSocket::bind("127.0.0.1:0")?.local_addr()?;
    let plane = format!("x0x.test.h-s3-m.{:032x}", rand::random::<u128>());
    let released = Released::start(bin, node, &plane, no_peer, "").await?;
    let mut run = LiveRun::default();
    let path = format!("/groups/{group}");
    let (_, body) = released.call(Method::GET, &path, None).await?;
    run.revisions.0 = body["roster_revision"].as_u64();
    run.membership = body["membership_state"].as_str().map(str::to_string);
    let invite = format!("/groups/{group}/invite");
    let (code, _) = released
        .call(Method::POST, &invite, Some(json!({"expiry_secs": 3600})))
        .await?;
    run.invite = code;
    tokio::time::sleep(RELEASED_WAIT).await;
    let (code, body) = released
        .call(Method::GET, &format!("{path}/members"), None)
        .await?;
    run.members = roster_counts(code, &body);
    let (code, body) = released.call(Method::GET, &path, None).await?;
    run.up_after_wait = code == 200;
    run.revisions.1 = body["roster_revision"].as_u64();
    released.stop().await;
    Ok(run)
}

/// The two released runs (start, then the reload) on J's node dir, on a
/// thread of their own. The sim's thread blocks meanwhile, so the sim's
/// paused clock does not move.
fn released_runs(bin: &Path, node: &Path, group: &str) -> Result<(LiveRun, LiveRun)> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async {
                    let first = released_run(bin, node, group).await?;
                    let reload = released_run(bin, node, group).await?;
                    anyhow::Ok((first, reload))
                })
            })
            .join()
            .map_err(|_| anyhow!("the released-run thread panicked"))?
    })
}

async fn scenario(sim: &mut Sim, bin: &Path, receipt: &mut Receipt) -> Result<Checks> {
    let (group, _) = s0(sim, LABELS, true, &[]).await?;
    let link = invite(sim, "A", &group).await?;
    let base = view(sim, "A", &group).await?.state_revision;
    remove(sim, "A", "M1", &group).await?;
    remove(sim, "A", "M2", &group).await?;
    rename(sim, "A", &group, "w3h m released node").await?;
    let gap = view(sim, "A", &group).await?.state_revision;
    ensure!(
        gap == base + 3,
        "INFRA: the gap is {} links, want 3",
        gap - base
    );
    let end = base + SEGMENT;
    hold_meta_from_j(sim, &group).await?;
    let mute = MuteAtEnd::install(sim, &group, end)?;
    let sealed = seal_j(sim, &link, &group).await?;
    ensure!(
        sealed.state_revision == base + 4,
        "INFRA: A sealed J at {}, want {}",
        sealed.state_revision,
        base + 4
    );
    let mut quiet_from: Option<Duration> = None;
    let _ = sim
        .until(
            "J stays at the end of segment 1",
            WINDOW + QUIET,
            async |s: &Sim| {
                let Ok(j) = view_now(s, "J", &group).await else {
                    return false;
                };
                if j.state_revision != end {
                    quiet_from = None;
                    return j.state_revision > end;
                }
                let now = s.fabric().now();
                let first = *quiet_from.get_or_insert(now);
                now.saturating_sub(first) >= QUIET
            },
        )
        .await;
    let stopped = view(sim, "J", &group).await?.state_revision;
    ensure!(
        stopped == end,
        "INFRA: J is at {stopped} before the stop, want the segment end {end}"
    );
    let j_hex = sim.agent_hex("J")?;
    sim.stop("J", RestartMode::Graceful).await?;
    receipt.setup_done(at(sim));

    // The released binary on J's own data directory.
    let data = sim.data_dir("J")?;
    let node = data
        .parent()
        .context("a sim data dir has a parent")?
        .to_path_buf();
    let legacy_before = legacy(&data, &group)?;
    let sidecar_before = sidecar_state(&data, &j_hex)?.0;
    sim.fabric()
        .mark("case: released v0.46.1 runs on J's data dir".to_string());
    let (first, reload) = released_runs(bin, &node, &group)?;
    let legacy_after = legacy(&data, &group)?;
    let sidecar_after = sidecar_state(&data, &j_hex)?.0;
    receipt.note(format!(
        "legacy before {legacy_before:?}, after both runs {legacy_after:?}; run 1 {first:?}; \
         reload {reload:?} (each run wants invite 403, members (200, Some((0, 0))), \
         membership not_member); sidecars before {sidecar_before:?} after {sidecar_after:?}"
    ));

    // The candidate resumes.
    let since = sim
        .fabric()
        .mark_indexed("case: the candidate J starts again".to_string());
    let _ = mute.release(sim);
    sim.start_again("J").await?;
    sees_s3(sim, "J", "A").await?;
    sees_s3(sim, "A", "J").await?;
    let mut last: Option<(View, Option<String>)> = None;
    let _ = sim
        .until(
            "J converges after the restart",
            CONVERGE,
            async |s: &Sim| {
                let (Ok(j), Ok(Some(status))) = (
                    view_now(s, "J", &group).await,
                    status_now(s, "J", &group).await,
                ) else {
                    return false;
                };
                let done = caught_up(Some(&j), &sealed, status.membership.as_deref());
                last = Some((j, status.membership));
                done
            },
        )
        .await;
    let converged = last
        .as_ref()
        .is_some_and(|(j, membership)| caught_up(Some(j), &sealed, membership.as_deref()));
    receipt.note(format!(
        "candidate J {:?}; A {}",
        last.as_ref()
            .map(|(j, membership)| format!("{} membership {membership:?}", j.describe())),
        sealed.describe()
    ));
    let frames = (
        delivered_after(sim, "J", "A", since)?,
        delivered_after(sim, "A", "J", since)?,
    );
    receipt.request_delivered(
        "candidate_j_reached_a_and_a_answered",
        frames.0 > 0 && frames.1 > 0,
        format!("frames J->A, A->J after the restart: {frames:?}"),
        at(sim),
    );
    let inert = |entry: &Option<Legacy>| {
        entry
            .as_ref()
            .is_some_and(|entry| entry.seats_no_one && entry.revision == Some(stopped))
    };
    let setup = vec![
        (
            "j_legacy_entry_is_the_s3_placeholder",
            inert(&legacy_before),
        ),
        ("j_has_one_sidecar", sidecar_before.len() == 1),
    ];
    for (name, ok) in &setup {
        receipt.evidence(name, *ok, format!("{name}: {ok}"), at(sim));
    }
    let row = vec![
        (
            "old_authority_entry_unchanged_through_both_runs",
            legacy_after == legacy_before,
        ),
        ("sidecar_sha256_unchanged", sidecar_after == sidecar_before),
        ("released_run_1_inert", first.ok()),
        ("released_reload_inert", reload.ok()),
        (
            "candidate_converges_active_with_keys_at_r_plus_4",
            converged,
        ),
    ];
    Ok((setup, row))
}

fn row(receipt: &mut Receipt) -> Result<()> {
    let bin = released_bin()?;
    // Every daemon of the case runs on this thread (`block_on_paused`).
    let _limit = AtaMaxLinksOverride::set(SEGMENT as usize);
    let (setup, row) = crate::server::w3h::block_on_paused(async {
        let mut sim = Sim::start(CASE, SEED, LABELS).await?;
        let checks = scenario(&mut sim, &bin, receipt).await;
        if let Err(error) = sim.finish().await {
            receipt.infra(format!("finish: {error:#}"), 0);
        }
        checks
    })?;
    conclude_checks(receipt, (FINAL_M, CAUSE_M), &setup, &row);
    Ok(())
}

/// H-S3-m (versions), non-Home group.
#[test]
#[ignore = "released-binary row: needs X0X_V0461_BIN; runs in its own CI job (#1572)"]
fn released_s3_m_released_node_on_j_between_segments() -> Result<()> {
    let note = "ADR 0109 S3 (#1356, #1572) H-S3-m; J's data dir runs the released v0.46.1 \
                between the H-S3-s segments";
    released_test(CASE, SEED, FINAL_M, note, row)
}

/// The live-cell judgement, without a daemon.
mod cells {
    use super::*;

    fn inert_run(members: (u16, Option<(usize, usize)>)) -> LiveRun {
        LiveRun {
            invite: 403,
            members,
            revisions: (Some(7), Some(7)),
            membership: Some("not_member".to_string()),
            up_after_wait: true,
        }
    }

    /// A body without a `members` array is not an empty roster.
    #[test]
    fn released_m_unreadable_roster_is_not_an_empty_roster() {
        let bodies = [
            Value::Null,
            json!({}),
            json!({"members": null}),
            json!({"members": "none"}),
            json!({"members": {"a": {"state": "active"}}}),
        ];
        for body in bodies {
            let run = inert_run(roster_counts(200, &body));
            assert!(!run.ok(), "{body} must fail the members cell");
        }
    }

    /// An empty array is the inert answer; an Active admin is not.
    #[test]
    fn released_m_roster_counts_active_and_admin_rows() {
        assert!(inert_run(roster_counts(200, &json!({"members": []}))).ok());
        let seated = json!({"members": [
            {"state": "active", "role": "admin"},
            {"state": "active", "role": "member"},
            {"state": "removed", "role": "admin"},
        ]});
        assert_eq!(roster_counts(200, &seated), (200, Some((2, 1))));
        assert!(!inert_run(roster_counts(200, &seated)).ok());
        assert!(!inert_run(roster_counts(500, &json!({"members": []}))).ok());
    }

    /// The other live cells fail closed too, and pin v0.46.1's answers.
    #[test]
    fn released_m_live_cells_fail_closed() {
        let base = || inert_run(roster_counts(200, &json!({"members": []})));
        let mut run = base();
        run.membership = None;
        assert!(!run.ok(), "no membership_state must fail");
        let mut run = base();
        run.membership = Some("pending".to_string());
        assert!(!run.ok(), "v0.46.1 answers not_member");
        let mut run = base();
        run.invite = 500;
        assert!(!run.ok(), "v0.46.1 refuses the invite with 403");
        let mut run = base();
        run.invite = 404;
        assert!(!run.ok(), "v0.46.1 refuses the invite with 403");
        let mut run = base();
        run.revisions = (None, None);
        assert!(!run.ok(), "no roster_revision must fail");
    }
}
