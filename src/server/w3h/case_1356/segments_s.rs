//! ADR 0109 §10 row H-S3-s (segments across a restart; #1572). Control,
//! expected GREEN with S3.
//!
//! The test configuration sets the segment length to 2 on the case thread
//! ([`AtaMaxLinksOverride`]). All daemons of the case run on that thread,
//! so A builds 2-link segments and J accepts no longer one.
//!
//! Setup S0. A mints invite I at r, removes M1 and M2 and renames, then
//! seals J. The gap before the seal is 3 links, and the seal is a fourth
//! link (the terminal, r+4).
//! - **Segment 1.** The first ATA covers r+1 and r+2 exactly. The
//!   exhausted segment admits nothing: J stays at r+2.
//! - **Restart.** J restarts at r+2.
//! - **Segment 2.** J shows `awaiting_attestation {segment_exhausted}` at
//!   r+2 only. The second ATA arms from J's head r+2 and covers r+3 and
//!   the terminal. J converges with no marker.
//!
//! J can show `segment_exhausted` before the restart too. Before the
//! restart J's view is usually still `catching_up` (its join is not
//! confirmed while the hold below drops its writes), so the case accepts
//! the state on either side of the restart, at r+2 only.
//!
//! **Holds.** The case drops every gossip write to J on the group's
//! metadata topic, as H-S3-s64 does, so only S3 moves J's head. J asks for
//! the next segment at once (#1726). Then A answers in the same instant,
//! and the restart is not between the segments. So the case also drops
//! every write from J (except membership and plane hello frames) from the
//! first one that J makes at r+2 or later until J restarts. J's direct
//! messages are encrypted envelopes, so the hold cannot pick out the S3
//! request by its bytes. The first ATA comes with the join result or as
//! an answer to J's request at r, before the hold starts. An S3 answer
//! from past r before the restart is an INFRA hold leak.
//!
//! **Observations.** J's head and `recovery` state at each poll; A's S3
//! answers to J (`recovery::decode_message` on J's direct messages); J's
//! head when it restarts and again when it is back.

use super::gaps::{recovery_route, recovery_text, remove, s0, seal_j, sees_s3};
use super::segments::hold_meta_from_j;
use super::*;
use crate::groups::recovery::{
    decode_message, AtaMaxLinksOverride, AttestAnswer, GroupRecoveryMessageV1,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const LABELS: &[&str] = &["A", "M1", "M2", "J"];
/// The test segment length (ADR 0109 §10 H-S3-s).
const SEGMENT: u64 = 2;
const FINAL: &str = "two_link_segments_the_second_arms_from_j_head_after_a_restart";
const CAUSE: &str = "a segment does not cover exactly 2 links (J moves past r+2 before the \
                     restart, or shows no segment_exhausted there), or after the restart the \
                     second ATA does not start at J's head r+2, or J does not converge with no \
                     marker";
/// ADR 0109 H-S3-a's window, also enough for one request round.
const WINDOW: Duration = Duration::from_secs(130);
/// How long J stays at the segment end, with no answer, before it
/// restarts.
const QUIET: Duration = Duration::from_secs(30);
const EXHAUSTED: &str = "awaiting_attestation{segment_exhausted}";

/// What the case saw of J.
#[derive(Default)]
struct Run {
    /// r: A's revision when it minted I.
    base: u64,
    /// J's state revision when A sealed it.
    head_at_seal: u64,
    /// The base revision of J's join stub (its invite lineage).
    stub_base: Option<u64>,
    /// The terminal: A's seal of J (r+4).
    terminal: u64,
    /// Distinct `recovery` states of J before the restart, in order.
    states_before: Vec<String>,
    /// J's distinct state revisions before the restart.
    heads_before: Vec<u64>,
    /// J's distinct state revisions while it showed `segment_exhausted`,
    /// before or after the restart.
    exhausted_at: Vec<u64>,
    /// `(from, entries)` of each ATA that A sent J before the restart.
    answered_before: Vec<(u64, usize)>,
    /// J's head when it stopped, and when it was back.
    restart_heads: (u64, u64),
    /// Distinct `recovery` states and revisions of J after the restart.
    states_after: Vec<String>,
    heads_after: Vec<u64>,
    /// `(from, entries)` of each ATA that A sent J after the restart.
    answered_after: Vec<(u64, usize)>,
    /// Writes from J that the hold dropped.
    held: usize,
    /// Frames J->A and A->J from J's redemption on.
    frames: (usize, usize),
    /// The head of J's last request in A's requester list.
    requested_from: Option<u64>,
    marked: Option<String>,
    caught_up: bool,
}

impl Run {
    fn describe(&self) -> String {
        format!(
            "r={} J at seal {} (stub base {:?}); terminal {}; before: heads {:?} states {:?} exhausted at {:?} \
             answered {:?}; restart heads {:?}; after: heads {:?} states {:?} answered {:?}; \
             held {}; A lists J from {:?}; marked {:?}; caught up {}",
            self.base,
            self.head_at_seal,
            self.stub_base,
            self.terminal,
            self.heads_before,
            self.states_before,
            self.exhausted_at,
            self.answered_before,
            self.restart_heads,
            self.heads_after,
            self.states_after,
            self.answered_after,
            self.held,
            self.requested_from,
            self.marked,
            self.caught_up
        )
    }

    /// J started from r: its stub is at r, or its lineage base is r. A
    /// small join result can reach J before the case reads J after the
    /// seal, so J can be at r+2 already then.
    fn started_at_r(&self) -> bool {
        self.head_at_seal == self.base || self.stub_base == Some(self.base)
    }

    fn segment_end(&self) -> u64 {
        self.base + SEGMENT
    }

    /// Segment 1 covers r+1 and r+2 only: J never passes r+2 before the
    /// restart, and any answer before the restart is that segment (from r,
    /// 2 entries).
    fn first_segment(&self) -> bool {
        let end = self.segment_end();
        self.started_at_r()
            && self.heads_before.iter().all(|head| *head <= end)
            && self.restart_heads.0 == end
            && self
                .answered_before
                .iter()
                .all(|answer| *answer == (self.base, SEGMENT as usize))
    }

    /// The exhausted segment: J shows `segment_exhausted` at r+2 and at
    /// no other head.
    fn exhausted_at_end(&self) -> bool {
        let end = self.segment_end();
        !self.exhausted_at.is_empty() && self.exhausted_at.iter().all(|head| *head == end)
    }

    /// Segment 2 arms from J's head after the restart: J is back at r+2,
    /// never below it, A lists J's last request from r+2, J sees at least
    /// one answer after the restart, every such answer starts at r+2 with
    /// 2 entries, and J converges with no marker. An empty answer list
    /// fails: then nothing shows that the second ATA came from J's head.
    fn second_segment(&self) -> bool {
        let end = self.segment_end();
        self.restart_heads.1 == end
            && self.heads_after.iter().all(|head| *head >= end)
            && self.requested_from == Some(end)
            && !self.answered_after.is_empty()
            && self
                .answered_after
                .iter()
                .all(|answer| *answer == (end, SEGMENT as usize))
            && self.caught_up
            && self.marked.is_none()
    }
}

/// The hold on J's writes at the segment end.
struct MuteAtEnd {
    released: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl MuteAtEnd {
    /// From J's first write at head `end` or later, drop J's writes
    /// (except membership and plane hello frames) until [`Self::release`].
    /// The rule reads J's head without waiting: when J's group map is
    /// locked, it keeps its last decision.
    fn install(sim: &Sim, group: &str, end: u64) -> Result<Self> {
        use crate::network::sim::{Fault, LaneClass};
        let j = sim.peer("J")?.0;
        let state = Arc::downgrade(&sim.state("J")?);
        let group = group.to_string();
        let released = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let latched = AtomicBool::new(false);
        let (rule_released, rule_dropped) = (Arc::clone(&released), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            if write.lane.src != j
                || rule_released.load(Ordering::SeqCst)
                || matches!(
                    write.lane.class,
                    LaneClass::Membership | LaneClass::PlaneHello
                )
            {
                return Fault::Pass;
            }
            if !latched.load(Ordering::SeqCst) {
                let at_end = state.upgrade().is_some_and(|state| {
                    state.named_groups.try_read().is_ok_and(|groups| {
                        crate::server::resolve_group_entry_locked(&groups, &group)
                            .is_some_and(|(_, info)| info.state_revision >= end)
                    })
                });
                if !at_end {
                    return Fault::Pass;
                }
                latched.store(true, Ordering::SeqCst);
            }
            rule_dropped.fetch_add(1, Ordering::SeqCst);
            Fault::Drop
        });
        sim.fabric()
            .mark(format!("fault: J's writes dropped from head {end} on"));
        Ok(Self { released, dropped })
    }

    fn release(&self, sim: &Sim) -> usize {
        self.released.store(true, Ordering::SeqCst);
        sim.fabric()
            .mark("fault: J's writes pass again".to_string());
        self.dropped.load(Ordering::SeqCst)
    }
}

/// A's S3 answers to J in `rx`, as `(from, entries)`.
fn drain_answers(
    rx: &mut crate::direct::DirectMessageReceiver,
    a_id: &crate::identity::AgentId,
    into: &mut Vec<(u64, usize)>,
) {
    while let Some(msg) = rx.try_recv() {
        if msg.sender != *a_id {
            continue;
        }
        if let Ok(GroupRecoveryMessageV1::Response(response)) = decode_message(&msg.payload) {
            if let AttestAnswer::Attested(ata) = &response.answer {
                into.push((ata.fields.from_revision, ata.fields.sequence.len()));
            }
        }
    }
}

/// J's head (read first) and `recovery` text now.
async fn poll_j(sim: &Sim, group: &str) -> Option<(View, Option<String>, String)> {
    let j = view_now(sim, "J", group).await.ok()?;
    let status = status_now(sim, "J", group).await.ok()??;
    let text = recovery_text(&status.recovery);
    Some((j, status.membership, text))
}

fn push_new<T: PartialEq + Clone>(list: &mut Vec<T>, item: &T) {
    if !list.contains(item) {
        list.push(item.clone());
    }
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let (group, _) = s0(sim, LABELS, true, &[]).await?;
    let link = invite(sim, "A", &group).await?;
    let mut run = Run {
        base: view(sim, "A", &group).await?.state_revision,
        ..Run::default()
    };
    remove(sim, "A", "M1", &group).await?;
    remove(sim, "A", "M2", &group).await?;
    rename(sim, "A", &group, "w3h s segments").await?;
    let gap = view(sim, "A", &group).await?.state_revision;
    ensure!(
        gap == run.base + 3,
        "INFRA: the gap is {} links, want 3",
        gap - run.base
    );
    hold_meta_from_j(sim, &group).await?;
    let mute = MuteAtEnd::install(sim, &group, run.segment_end())?;
    receipt.setup_done(at(sim));

    let a_id = sim.ids("A")?.0;
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    let since = sim
        .fabric()
        .mark_indexed("case: J redeems I across 4 links".to_string());
    let sealed = seal_j(sim, &link, &group).await?;
    ensure!(
        sealed.state_revision == run.base + 4,
        "INFRA: A sealed J at {}, want {}",
        sealed.state_revision,
        run.base + 4
    );
    let stub = view(sim, "J", &group).await?;
    run.head_at_seal = stub.state_revision;
    run.stub_base = stub.base_revision;
    run.terminal = sealed.state_revision;

    // Segment 1: J reaches the segment end and stays there.
    let end = run.segment_end();
    let mut quiet_from: Option<Duration> = None;
    let _ = sim
        .until(
            "J stays at the end of segment 1",
            WINDOW + QUIET,
            async |s: &Sim| {
                drain_answers(&mut rx, &a_id, &mut run.answered_before);
                let Some((j, _, text)) = poll_j(s, &group).await else {
                    return false;
                };
                push_new(&mut run.heads_before, &j.state_revision);
                if run.states_before.last() != Some(&text) {
                    run.states_before.push(text.clone());
                }
                if text == EXHAUSTED {
                    push_new(&mut run.exhausted_at, &j.state_revision);
                }
                if let Some(marker) = &j.marker {
                    run.marked.get_or_insert_with(|| format!("{marker:?}"));
                }
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
    run.restart_heads.0 = view(sim, "J", &group).await?.state_revision;

    // The restart, between the segments.
    run.held = mute.release(sim);
    sim.restart("J", RestartMode::Graceful).await?;
    run.restart_heads.1 = view(sim, "J", &group).await?.state_revision;
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    sees_s3(sim, "J", "A").await?;
    sees_s3(sim, "A", "J").await?;

    // Segment 2: from J's head to the terminal.
    let _ = sim
        .until("J converges after the restart", WINDOW, async |s: &Sim| {
            drain_answers(&mut rx, &a_id, &mut run.answered_after);
            let Some((j, membership, text)) = poll_j(s, &group).await else {
                return false;
            };
            push_new(&mut run.heads_after, &j.state_revision);
            if text == EXHAUSTED {
                push_new(&mut run.exhausted_at, &j.state_revision);
            }
            if run.states_after.last() != Some(&text) {
                run.states_after.push(text);
            }
            if let Some(marker) = &j.marker {
                run.marked.get_or_insert_with(|| format!("{marker:?}"));
            }
            run.caught_up = caught_up(Some(&j), &sealed, membership.as_deref());
            run.caught_up
        })
        .await;
    drain_answers(&mut rx, &a_id, &mut run.answered_after);
    run.frames = (
        delivered_after(sim, "J", "A", since)?,
        delivered_after(sim, "A", "J", since)?,
    );
    let route = sim
        .at_instant("read A's recovery", recovery_route(sim, "A", &group))
        .await??;
    let j_hex = sim.agent_hex("J")?;
    run.requested_from = route["requesters"].as_array().and_then(|rows| {
        rows.iter()
            .filter(|row| {
                row["requester"]
                    .as_str()
                    .is_some_and(|id| id.eq_ignore_ascii_case(&j_hex))
            })
            .filter_map(|row| row["head_revision"].as_u64())
            .next_back()
    });

    receipt.evidence(
        "j_starts_at_r",
        run.started_at_r(),
        format!(
            "r={} J at seal {} stub base {:?}",
            run.base, run.head_at_seal, run.stub_base
        ),
        at(sim),
    );
    receipt.evidence(
        "the_hold_dropped_j_writes_at_the_segment_end",
        run.held > 0,
        format!("dropped {}", run.held),
        at(sim),
    );
    receipt.request_delivered(
        "j_join_reached_a_and_a_answered",
        run.frames.0 > 0 && run.frames.1 > 0,
        format!("frames J->A, A->J: {:?}", run.frames),
        at(sim),
    );
    // An answer from past r before the restart means J's request at r+2
    // got out: the hold failed, not S3.
    if run
        .answered_before
        .iter()
        .any(|(from, _)| *from != run.base)
    {
        receipt.infra(
            format!("the hold let an answer through: {}", run.describe()),
            at(sim),
        );
    }
    let ok1 = run.first_segment();
    let exhausted = run.exhausted_at_end();
    let ok2 = run.second_segment();
    receipt.note(format!(
        "segment_1_covers_r_plus_1_and_r_plus_2_only: ok={ok1}"
    ));
    receipt.note(format!(
        "segment_exhausted_at_r_plus_2_only: ok={exhausted}"
    ));
    receipt.note(format!(
        "segment_2_arms_from_r_plus_2_after_the_restart_and_j_converges: ok={ok2}"
    ));
    receipt.note(run.describe());
    let passed = ok1 && exhausted && ok2;
    if !passed {
        receipt.cause(CAUSE, Some(run.describe()), true, at(sim));
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "ADR 0109 S3 (#1356, #1572) H-S3-s: segment length {SEGMENT} by test configuration"
    ));
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
fn w3h_1356_s_segment_shapes() {
    let mut run = Run {
        base: 5,
        head_at_seal: 5,
        terminal: 9,
        heads_before: vec![5, 6, 7],
        exhausted_at: vec![7],
        answered_before: vec![(5, 2)],
        restart_heads: (7, 7),
        heads_after: vec![7, 9],
        answered_after: vec![(7, 2)],
        requested_from: Some(7),
        caught_up: true,
        ..Run::default()
    };
    assert!(run.first_segment());
    assert!(run.second_segment());
    run.heads_before.push(8);
    assert!(!run.first_segment(), "a link past the segment end applied");
    run.heads_before.pop();
    assert!(run.exhausted_at_end());
    run.exhausted_at = vec![6, 7];
    assert!(!run.exhausted_at_end(), "exhausted before the segment end");
    run.exhausted_at.clear();
    assert!(!run.exhausted_at_end(), "no segment_exhausted");
    run.exhausted_at = vec![7];
    run.answered_before = vec![(5, 3)];
    assert!(!run.first_segment(), "a 3-link segment");
    run.answered_before.clear();
    assert!(
        run.first_segment(),
        "the first ATA came with the join result"
    );
    run.restart_heads = (7, 5);
    assert!(!run.second_segment(), "J lost its progress at the restart");
    run.restart_heads = (7, 7);
    run.answered_after = vec![(5, 2)];
    assert!(!run.second_segment(), "the second ATA is not from J's head");
    run.answered_after.clear();
    assert!(!run.second_segment(), "no answer seen after the restart");
    run.answered_after = vec![(7, 2)];
    run.requested_from = None;
    assert!(!run.second_segment(), "A lists no request from J");
    run.requested_from = Some(5);
    assert!(
        !run.second_segment(),
        "J's last request is not from its head"
    );
    run.requested_from = Some(7);
    assert!(run.second_segment());
    run.caught_up = false;
    assert!(!run.second_segment(), "J did not converge");
    run.head_at_seal = 7;
    assert!(!run.first_segment(), "no evidence that J started at r");
    run.stub_base = Some(5);
    assert!(run.first_segment(), "J's stub base is r");
}

/// H-S3-s: control, GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_s_two_link_segments_across_a_restart() -> Result<()> {
    // Every daemon of the case runs on this thread (`block_on_paused`).
    let _limit = AtaMaxLinksOverride::set(SEGMENT as usize);
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_s_two_link_segments_across_a_restart";
        let receipt = run(case, 0x1356_0119).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
