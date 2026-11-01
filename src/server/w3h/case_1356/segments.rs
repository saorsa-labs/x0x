//! ADR 0109 §10 row H-S3-s64 (D83 segment boundary; #1572). Control,
//! expected GREEN with S3 (on `main` before S3, J is marked, as in
//! H-S3-a).
//!
//! Setup S0, then three runs on three groups in one simulation. In each
//! run A mints invite I at r, renames `n` times and seals J. The gap is
//! `n + 1` links, because the seal is a link too.
//! - **64 links** (63 renames). One ATA of 64 entries (the join carry), no
//!   request, and J converges.
//! - **65 links** (64 renames). The join-carry ATA holds 64 entries and
//!   ends at r+64. The one link left is the terminal: A's seal, which is
//!   J's own join result. Timing decides how J takes it: by the join rule
//!   (the seal chains from J's attested head and A signed it), or by one
//!   requested ATA of 1 entry from r+64.
//! - **66 links** (65 renames). The join-carry ATA ends at r+64, and the
//!   link after it is a rename, not the terminal. The exhausted segment
//!   admits nothing: J shows `awaiting_attestation {segment_exhausted}` at
//!   r+64 only, and asks A again from r+64. J then converges. J asks at
//!   once from its new head (#1726), so the answer can arrive before the
//!   case reads the exhausted state; A's answer from r+64 then shows that
//!   the segment ended there.
//!
//! **One responder interval between runs.** A, the one admin, answers J
//! at most once per `RESPONDER_PER_REQUESTER_INTERVAL` (§11), and that
//! limit is per requester, across groups. The three runs share A and J
//! and take about 6–30 virtual seconds together. When J asks A in the
//! 65-link run, A refused J's r+64 request in the 66-link run with
//! `rate_limited` (s3 job, run 41233639089 attempt 1, iteration 17/20).
//! The refusal replaced `segment_exhausted` before a poll read it, and J
//! took the rest from its join-result poll, not from an answer. So the
//! 66-link run starts only after A's interval for J's requests in the
//! 65-link run has passed. The 64-link run sends A no request, so the
//! case waits one interval (plus a margin) before the 66-link run only.
//!
//! In each run, any ATA that A sends J in answer starts at r+64, and J
//! never holds a marker. The case does not count the join-carry entries
//! directly (J arms and retires that ATA within one poll). The 64-link
//! run (no exhausted segment) and the 66-link run (exhausted at exactly
//! r+64) fix the cap at 64 between them.
//!
//! **Plan against code (#1572).** The row expects, at 65 links, a second
//! ATA of 1 entry. The code answers 64 + 1: 64 attested links, then the
//! last link by the join rule or by a 1-entry ATA, as timing decides.
//! This PR keeps the code: the last link is the joiner's own seal, and the
//! join rule verifies it on the attested head, so a request round adds no
//! check. No wire or API change.
//!
//! **Hold.** The case drops every gossip write to J on the group's
//! metadata topic. Without it, a resend or a cache pull of A's renames can
//! move J's stub past r while its large join result is in flight, and the
//! join carry then starts from that later head. S3's messages and the join
//! result go on other paths, so the hold does not touch them. With the
//! hold, only the join result moves J, and A sends it after the seal, so
//! J is still at r when the case reads it after the seal.
//!
//! **Observations.** J's head and `recovery` state at each poll, and A's
//! answers to J from J's direct message stream (decoded with
//! `recovery::decode_message`). A's requester list is a note only: it may
//! drop an answered entry.

use super::gaps::{recovery_route, recovery_text, s0, seal_j};
use super::*;
use crate::groups::recovery::{
    decode_message, AttestAnswer, GroupRecoveryMessageV1, ATA_MAX_LINKS,
    RESPONDER_PER_REQUESTER_INTERVAL,
};

const LABELS: &[&str] = &["A", "M1", "M2", "J"];
const FINAL: &str = "a_64_link_segment_then_the_terminal_or_a_second_ata_from_r_plus_64";
const CAUSE: &str = "J does not converge with no marker, or the segment does not end at r+64 \
                     (a link past it applies while J shows segment_exhausted, the 66-link run \
                     shows no exhausted segment, or an answer starts elsewhere)";
/// ADR 0109 H-S3-a's window, also enough for one request round.
const WINDOW: Duration = Duration::from_secs(130);
const EXHAUSTED: &str = "awaiting_attestation{segment_exhausted}";

/// What one run saw of J.
#[derive(Default)]
struct Run {
    /// r: A's revision when it minted I.
    base: u64,
    /// J's state revision when A sealed it.
    head_at_seal: u64,
    /// The terminal: A's seal of J.
    terminal: u64,
    /// Distinct `recovery` states of J, in order.
    states: Vec<String>,
    /// `(from, entries)` of each ATA that A sent J in answer to a request.
    answered: Vec<(u64, usize)>,
    /// A's requester list has an entry for J.
    requested: bool,
    /// J's distinct state revisions while it showed `segment_exhausted`.
    exhausted_at: Vec<u64>,
    /// Frames J->A and A->J from J's redemption on.
    frames: (usize, usize),
    marked: Option<String>,
    caught_up: bool,
}

impl Run {
    fn describe(&self) -> String {
        format!(
            "r={} J at seal {}; answered {:?}; A lists J {}; exhausted at {:?}; states {:?}; \
             marked {:?}; caught up {}",
            self.base,
            self.head_at_seal,
            self.answered,
            self.requested,
            self.exhausted_at,
            self.states,
            self.marked,
            self.caught_up
        )
    }

    fn exhausted(&self) -> bool {
        self.states.iter().any(|state| state == EXHAUSTED)
    }

    /// The join-carry segment ended at r+64: J showed `segment_exhausted`,
    /// or A answered J's request from r+64. J asks again from a new head
    /// at once (#1726), so A's answer can arrive inside one poll and the
    /// case never reads the exhausted state. In iteration 10/20 of s3 job
    /// 124525597881 the 66-link run had states null, catching_up, null and
    /// one answer (71, 2) from r+64. The answer is the stronger evidence:
    /// J asks from r+64 only because the segment admits nothing past it.
    fn segment_ended(&self) -> bool {
        let end = self.base + ATA_MAX_LINKS as u64;
        self.exhausted() || self.answered.iter().any(|(from, _)| *from == end)
    }

    /// J started at r and converged with no marker.
    fn converged_from_r(&self) -> bool {
        self.head_at_seal == self.base && self.caught_up && self.marked.is_none()
    }
}

/// Waits out A's per-requester interval for any request J sent in the run
/// before. J stops asking once it catches up, which ends that run; the
/// margin covers a request still in flight to A then.
async fn after_responder_interval(sim: &Sim) -> Result<()> {
    let wait = RESPONDER_PER_REQUESTER_INTERVAL + Duration::from_secs(5);
    sim.within(
        "A's per-requester interval for J passes",
        wait + Duration::from_secs(2),
        async {
            tokio::time::sleep(wait).await;
        },
    )
    .await
}

/// Drops every gossip write to J on `group`'s metadata topic.
async fn hold_meta_from_j(sim: &Sim, group: &str) -> Result<()> {
    use crate::network::sim::{Fault, LaneClass};
    let topic = {
        let state = sim.state("A")?;
        let groups = state.named_groups.read().await;
        let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
            .with_context(|| format!("A has no record of {group}"))?;
        saorsa_gossip_types::TopicId::from_entity(info.metadata_topic.as_bytes()).to_bytes()
    };
    let j = sim.peer("J")?.0;
    sim.fabric().add_rule(move |write| {
        let to_j_meta = write.lane.dst == j
            && write.lane.class == LaneClass::PubSub
            && pubsub_header(&write.bytes).is_some_and(|(t, _)| t == topic);
        if to_j_meta {
            Fault::Drop
        } else {
            Fault::Pass
        }
    });
    sim.fabric()
        .mark("fault: metadata-topic gossip to J dropped".to_string());
    Ok(())
}

/// One run: A renames `renames` times after the mint, then seals J.
async fn gap_run(sim: &Sim, renames: usize) -> Result<Run> {
    let (group, _) = s0(sim, LABELS, true, &[]).await?;
    let link = invite(sim, "A", &group).await?;
    let mut run = Run {
        base: view(sim, "A", &group).await?.state_revision,
        ..Run::default()
    };
    for index in 0..renames {
        rename(sim, "A", &group, &format!("w3h s64 {renames} {index}")).await?;
    }
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold the renames").await?;
    hold_meta_from_j(sim, &group).await?;
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    let a_id = sim.ids("A")?.0;
    let since = sim
        .fabric()
        .mark_indexed(format!("case: J redeems I across {} links", renames + 1));
    let sealed = seal_j(sim, &link, &group).await?;
    let want = run.base + renames as u64 + 1;
    ensure!(
        sealed.state_revision == want,
        "INFRA: A sealed J at {}, want {want}",
        sealed.state_revision
    );
    run.head_at_seal = view(sim, "J", &group).await?.state_revision;
    run.terminal = sealed.state_revision;
    let _ = sim
        .until(
            &format!("J crosses the {}-link gap", renames + 1),
            WINDOW,
            async |s: &Sim| {
                while let Some(msg) = rx.try_recv() {
                    if msg.sender != a_id {
                        continue;
                    }
                    if let Ok(GroupRecoveryMessageV1::Response(response)) =
                        decode_message(&msg.payload)
                    {
                        if let AttestAnswer::Attested(ata) = &response.answer {
                            run.answered
                                .push((ata.fields.from_revision, ata.fields.sequence.len()));
                        }
                    }
                }
                // The head first: a head read after the state could be a
                // link the next segment applied in between.
                let Ok(j) = view_now(s, "J", &group).await else {
                    return false;
                };
                let Ok(Some(j_status)) = status_now(s, "J", &group).await else {
                    return false;
                };
                let text = recovery_text(&j_status.recovery);
                if run.states.last() != Some(&text) {
                    run.states.push(text.clone());
                }
                if text == EXHAUSTED && !run.exhausted_at.contains(&j.state_revision) {
                    run.exhausted_at.push(j.state_revision);
                }
                if let Some(marker) = &j.marker {
                    run.marked.get_or_insert_with(|| format!("{marker:?}"));
                }
                run.caught_up = caught_up(Some(&j), &sealed, j_status.membership.as_deref());
                run.caught_up
            },
        )
        .await;
    run.frames = (
        delivered_after(sim, "J", "A", since)?,
        delivered_after(sim, "A", "J", since)?,
    );
    let route = sim
        .at_instant("read A's recovery", recovery_route(sim, "A", &group))
        .await??;
    let j_hex = sim.agent_hex("J")?;
    run.requested = route["requesters"].as_array().is_some_and(|rows| {
        rows.iter().any(|row| {
            row["requester"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(&j_hex))
        })
    });
    Ok(run)
}

/// 64 links: the join carry alone, with no request or wait.
fn one_segment(run: &Run) -> bool {
    run.converged_from_r() && run.answered.is_empty() && !run.exhausted()
}

/// Past 64 links: the join-carry segment ends at r+64 and admits nothing
/// more. While J shows `segment_exhausted`, its head is r+64, or already
/// the terminal (the state is read just after the head). Any ATA that A
/// sends J in answer starts at r+64. The links after r+64 come by one of
/// two paths, as timing decides: the terminal by the join rule (65
/// links), or one requested ATA from r+64.
fn segment_boundary(run: &Run) -> bool {
    let end = run.base + ATA_MAX_LINKS as u64;
    run.converged_from_r()
        && run
            .exhausted_at
            .iter()
            .all(|revision| *revision == end || *revision == run.terminal)
        && run.answered.len() <= 1
        && run.answered.iter().all(|(from, _)| *from == end)
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let run64 = gap_run(sim, ATA_MAX_LINKS - 1).await?;
    receipt.setup_done(at(sim));
    // The 64-link run sends no request: its join carry holds all 64 links,
    // so no segment is exhausted (and `one_segment` fails on any answer).
    // The 65-link run may ask A from r+64.
    let run65 = gap_run(sim, ATA_MAX_LINKS).await?;
    after_responder_interval(sim).await?;
    let run66 = gap_run(sim, ATA_MAX_LINKS + 1).await?;
    let runs = [&run64, &run65, &run66];
    receipt.evidence(
        "j_at_r_when_a_seals_it_in_each_run",
        runs.iter().all(|run| run.head_at_seal == run.base),
        runs.iter()
            .map(|run| format!("r={} J={}", run.base, run.head_at_seal))
            .collect::<Vec<_>>()
            .join("; "),
        at(sim),
    );
    receipt.request_delivered(
        "j_join_reached_a_and_a_answered_in_each_run",
        runs.iter().all(|run| run.frames.0 > 0 && run.frames.1 > 0),
        format!(
            "frames J->A, A->J: {:?}",
            runs.iter().map(|run| run.frames).collect::<Vec<_>>()
        ),
        at(sim),
    );
    let ok64 = one_segment(&run64);
    let ok65 = segment_boundary(&run65);
    let ok66 = segment_boundary(&run66) && run66.segment_ended();
    for (name, ok, run) in [
        ("gap_64_one_join_carry_ata_and_no_request", ok64, &run64),
        ("gap_65_join_carry_ata_of_64_then_one_link", ok65, &run65),
        (
            "gap_66_segment_exhausted_at_r_plus_64_then_converges",
            ok66,
            &run66,
        ),
    ] {
        receipt.note(format!("{name}: ok={ok}; {}", run.describe()));
    }
    let passed = ok64 && ok65 && ok66;
    if !passed {
        receipt.cause(
            CAUSE,
            Some(
                runs.iter()
                    .map(|run| run.describe())
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
            // Each check that `passed` combines is one of CAUSE's cases;
            // J's head at the seal is a precondition (INFRA when false).
            true,
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("ADR 0109 S3 (#1356, #1572) H-S3-s64: D83 segment boundary".to_string());
    match Sim::start(case, seed, LABELS).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt).await {
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

/// The row's shapes, checked on fixed observations.
#[test]
fn w3h_1356_s64_segment_shapes() {
    let mut run = Run {
        base: 5,
        head_at_seal: 5,
        terminal: 71,
        caught_up: true,
        ..Run::default()
    };
    assert!(one_segment(&run));
    assert!(segment_boundary(&run), "64 + the terminal");
    assert!(!run.segment_ended(), "no exhausted state and no answer");
    run.answered = vec![(69, 2)];
    assert!(run.segment_ended(), "an answer from r+64 ends the segment");
    run.answered = vec![(70, 1)];
    assert!(!run.segment_ended(), "an answer not from r+64");
    run.answered.clear();
    run.head_at_seal = 6;
    assert!(!one_segment(&run), "J did not start at r");
    assert!(!segment_boundary(&run), "J did not start at r");
    run.head_at_seal = 5;
    run.states = vec![EXHAUSTED.to_string()];
    run.exhausted_at = vec![69, 71];
    run.answered = vec![(69, 2)];
    assert!(!one_segment(&run), "the segment was exhausted");
    assert!(segment_boundary(&run));
    run.exhausted_at.push(70);
    assert!(!segment_boundary(&run), "a link applied past the segment");
    run.exhausted_at.pop();
    run.answered.push((69, 2));
    assert!(!segment_boundary(&run), "two answers");
    run.answered = vec![(70, 1)];
    assert!(!segment_boundary(&run), "an answer not from r+64");
}

/// H-S3-s64 (D83): control, GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_s64_segment_boundary() -> Result<()> {
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_s64_segment_boundary";
        let receipt = run(case, 0x1356_0107).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
