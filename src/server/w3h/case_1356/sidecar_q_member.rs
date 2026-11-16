//! ADR 0109 Validation table row H-S3-q (unreadable sidecar, D120, D119;
//! #1572), variant (2): the confirmed member.
//!
//! Setup S0′ with admin B promoted after step 2, and the segment length 1
//! by test configuration ([`AtaMaxLinksOverride`]). J joins with I and is
//! Active at r+1. Every message between B and {A, J} is held. A renames
//! three times (r+2, r+3, r+4); B renames (r+2′). A's r+2 reaches J, then
//! B's r+2′, so J holds a sibling marker. J asks A and arms A's one-link
//! ATA for r+3; the case stops J at once after that (see "Stop point"). It replaces J's `.grecov` with 64 bytes that start
//! `JUNKJUNK` (no family prefix) and starts J again. The sim writes no
//! ADR 0094 upgrade journal, so the host commit gate is open.
//!
//! Desired result (the row's "All" and "(2)" cells):
//! - The old bytes sit, byte-identical, in one ADR 0108 §5a history copy,
//!   and a fresh `.grecov` exists that names one rebuild `txid`.
//! - `recovery.recovery_sidecar_rebuilt` names the file, that `txid` and
//!   what was lost.
//! - No node commits because of the rebuild: J stays at its stop head, A
//!   at r+4 and B at r+2′. J's marker is the same before the damage and at the end.
//! - J stays inert and shows `readmission_required {local_state_lost}`,
//!   with an `exit` (D43's remedy; ADR 0114's retention re-Welcome is not
//!   in effect).
//!
//! **Why `local_state_lost`.** J armed A's ATA, so S3 wrote J's legacy
//! view as the S3 placeholder, as it does for any armed gap. The §4
//! rebuild table then applies its row "`authoritative_record`, when the
//! legacy view holds an S3 placeholder": the record is on no holder, the
//! group stays inert under the placeholder and the node shows
//! `local_state_lost`. Before the #1937 fix the node missed this (a
//! rebuilt sidecar was never `lost`): J stayed in `awaiting_attestation`
//! and kept asking (#1946). The same fix covers both variants.
//!
//! **Stop point.** The row stops J after it applies r+3, before its next
//! segment. On this build that state is not reached: the ATA attests A's
//! head r+4 as its terminal, and one link (r+3) is all that lies between
//! J's head r+2 and that terminal, so J applies r+3 and the attested
//! terminal r+4 in the same instant after A's one `(r+2, 1)` answer
//! (every VM run). A trial with a fourth A rename (terminal r+5) did not
//! help: J then went from r+2 to r+4 or to r+5 in one instant, run by
//! run. So the case keeps the row's three renames and stops J as soon as
//! its head reaches r+3 or later, with its S3 sidecar still on disk; the
//! "no commit" check uses that head.
//!
//! **Holds.** An origin hold (gossip relays included) drops every message
//! between B and {A, J}. A's r+2 reaches J by gossip; from then on every
//! write to J on the group's metadata topic is dropped, so only S3 moves
//! J. While A seals r+3 and r+4 and until their resends end, every write
//! to J (except membership and plane hello frames) is dropped: the first
//! VM run showed a confirmed member gets A's commits by a route other
//! than the metadata topic. B's messages then reach J (not A), so B's r+2′ reaches J. J's
//! writes are dropped from its first write at r+3 until its graceful stop
//! ([`MuteAtEnd`]), so J cannot ask for r+4 before the restart, and every
//! write to J is dropped from the first one that finds J at r+3 until the
//! restart ([`deaf_at_end`]), so J applies nothing past r+3 by any route
//! (the second VM run showed J reach r+4 after the one-link ATA). The holds
//! on B and on the metadata topic stay for the rest of the case. The
//! TreeKEM catch-up logs of A, M1 and M2 are emptied after A's r+4 (as a
//! restart does; #1623): on the first VM run J took r+3 and r+4 from them
//! with no S3 answer.

use super::gaps::{keys, promote, recovery_route, seal_j, start_ranked, Frame, Key, OriginHold};
use super::segments_s::{drain_answers, poll_j, push_new, MuteAtEnd};
use super::sidecar_q::{junk, sidecar_files, Disk};
use super::*;
use crate::groups::recovery::{
    decode_sidecar, AtaMaxLinksOverride, GATE_STALL, GROUP_RECOVERY_EXTENSION,
};
use std::sync::atomic::{AtomicBool, Ordering};

const LABELS: &[&str] = &["A", "M1", "M2", "B", "J"];
/// The test segment length (H-S3-q (2)).
const SEGMENT: u64 = 1;
const FINAL: &str = "member_junk_sidecar_quarantined_rebuilt_and_j_inert_in_local_state_lost";
const CAUSE: &str = "the junk .grecov was not kept byte-identical in one history copy, no \
                     fresh sidecar names the rebuild, recovery_sidecar_rebuilt is missing, a \
                     node committed or a marker cleared after the rebuild, or J does not stay \
                     inert in readmission_required {local_state_lost}";
/// ADR 0109 H-S3-a's window, also enough for one request round.
const WINDOW: Duration = Duration::from_secs(130);
const LOST: &str = "readmission_required{local_state_lost}";

/// The metadata topic of `group`, as A holds it.
async fn meta_topic(sim: &Sim, group: &str) -> Result<[u8; 32]> {
    let state = sim.state("A")?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("A has no record of {group}"))?;
    Ok(saorsa_gossip_types::TopicId::from_entity(info.metadata_topic.as_bytes()).to_bytes())
}

/// #1623: each node's in-memory TreeKEM catch-up log serves its commits
/// page by page, a path the metadata hold does not cover. Empty `label`'s
/// log for the group, as a restart does (the log is in memory), so only
/// S3 moves J past r+2.
async fn empty_catchup_log(sim: &Sim, label: &str, group: &str) -> Result<()> {
    let state = sim.state(label)?;
    let keys = {
        let groups = state.named_groups.read().await;
        let (key, info) = crate::server::resolve_group_entry_locked(&groups, group)
            .with_context(|| format!("{label} has no record of {group}"))?;
        [
            key.to_string(),
            info.stable_group_id().to_string(),
            info.mls_group_id.clone(),
        ]
    };
    let mut logs = state.treekem_event_log.write().await;
    for key in &keys {
        logs.remove(key);
    }
    sim.fabric()
        .mark(format!("fault: {label}'s TreeKEM catch-up log emptied"));
    Ok(())
}

/// From the first write to J that finds J at head `end` or later, drop
/// every write to J (except membership and plane hello frames) until the
/// returned flag is set. J then applies nothing past `end` by any route.
fn deaf_at_end(sim: &Sim, group: &str, end: u64) -> Result<Arc<AtomicBool>> {
    use crate::network::sim::{Fault, LaneClass};
    let j = sim.peer("J")?.0;
    let state = Arc::downgrade(&sim.state("J")?);
    let group = group.to_string();
    let released = Arc::new(AtomicBool::new(false));
    let latched = AtomicBool::new(false);
    let rule_released = Arc::clone(&released);
    sim.fabric().add_rule(move |write| {
        if write.lane.dst != j
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
        Fault::Drop
    });
    sim.fabric()
        .mark(format!("fault: writes to J dropped from head {end} on"));
    Ok(released)
}

/// Whether the hold drops `frame`.
#[derive(Clone)]
struct Policy {
    b: Key,
    j: Key,
    a_and_j: Vec<Key>,
    topic: [u8; 32],
    /// Drop every write to J on the metadata topic (except B's, once
    /// `b_to_j`).
    meta_to_j: bool,
    /// B's messages reach J.
    b_to_j: bool,
    /// Drop every write to J (except membership and plane hello frames).
    all_to_j: bool,
}

impl Policy {
    fn drops(&self, f: &Frame) -> bool {
        let from_b = f.origin == self.b && self.a_and_j.contains(&f.dst);
        let to_b = self.a_and_j.contains(&f.origin) && f.dst == self.b;
        let b_cut = to_b || (from_b && !(self.b_to_j && f.dst == self.j));
        let meta = self.meta_to_j
            && f.dst == self.j
            && f.topic == Some(self.topic)
            && !(self.b_to_j && f.origin == self.b);
        let all = self.all_to_j
            && f.dst == self.j
            && !matches!(
                f.class,
                crate::network::sim::LaneClass::Membership
                    | crate::network::sim::LaneClass::PlaneHello
            );
        b_cut || meta || all
    }

    fn set(&self, hold: &OriginHold, sim: &Sim, what: &str) {
        let policy = self.clone();
        hold.set(sim, what, move |f| policy.drops(f));
    }
}

/// What the case saw of J, A and B.
#[derive(Default)]
struct Run {
    /// J's state revision at its seal (r+1).
    sealed: u64,
    /// A's terminal revision (r+4) and B's fork revision (r+2′).
    terminal: u64,
    fork: u64,
    /// J was Active after the seal.
    active: bool,
    /// J's head at its stop, and once it is back.
    restart_heads: (u64, u64),
    /// J's distinct heads and `recovery` states after the restart.
    heads_after: Vec<u64>,
    states_after: Vec<String>,
    /// J's `recovery` states and distinct heads before the stop.
    states_before: Vec<String>,
    heads_before: Vec<(u64, u128)>,
    /// J's marker before the damage, and at the end.
    markers: (Option<String>, Option<String>),
    /// J's marker names B before the damage.
    marked_by_b: bool,
    /// A's and B's state revisions at the end.
    a_end: u64,
    b_end: u64,
    /// `recovery_sidecar_rebuilt` and `exit` in J's last `recovery`.
    rebuilt: Value,
    exit: Option<String>,
    /// `(from, entries)` of each ATA A sent J before and after the
    /// restart.
    answered_before: Vec<(u64, usize)>,
    answered_after: Vec<(u64, usize)>,
    /// B's agent ID, and the `(agent, answer)` rows of `asked` in J's
    /// last `recovery`.
    b_hex: String,
    asked: Vec<(String, String)>,
}

impl Run {
    fn describe(&self, disk: &Disk) -> String {
        format!(
            "sealed r+1={} active {}; terminal {} fork {}; before: states {:?} answered {:?} \
             marker by B {}; restart heads {:?}; after: heads {:?} states {:?} answered {:?}; \
             markers {:?}; A at end {}; B at end {}; rebuilt {}; exit {:?}; asked {:?}; disk {:?}",
            self.sealed,
            self.active,
            self.terminal,
            self.fork,
            self.states_before,
            self.answered_before,
            self.marked_by_b,
            self.restart_heads,
            self.heads_after,
            self.states_after,
            self.answered_after,
            self.markers,
            self.a_end,
            self.b_end,
            self.rebuilt,
            self.exit,
            self.asked,
            disk
        )
    }

    /// J armed A's one-link ATA from r+2 and stopped at r+3 or later (at
    /// most the terminal), holding the marker that names B.
    fn stopped_after_segment(&self) -> bool {
        let r3 = self.sealed + 2;
        (r3..=self.terminal).contains(&self.restart_heads.0)
            && self.marked_by_b
            && self
                .answered_before
                .iter()
                .any(|answer| *answer == (r3 - 1, SEGMENT as usize))
    }

    /// `recovery_sidecar_rebuilt` names the file, the fresh sidecar's
    /// `txid` and a non-empty list of what was lost.
    fn rebuild_named(&self, file: &str, disk: &Disk) -> bool {
        let txid = disk
            .fresh_rebuilt_from
            .as_ref()
            .and_then(|from| from.last().cloned());
        self.rebuilt["file"].as_str() == Some(file)
            && txid.is_some()
            && self.rebuilt["txid"].as_str() == txid.as_deref()
            && self.rebuilt["lost"]
                .as_array()
                .is_some_and(|lost| !lost.is_empty())
    }

    /// No node commits because of the rebuild and no marker is cleared.
    fn nothing_committed(&self) -> bool {
        let stop = self.restart_heads.0;
        self.restart_heads.1 == stop
            && self.heads_after.iter().all(|head| *head == stop)
            && self.a_end == self.terminal
            && self.b_end == self.fork
            && self.markers.0.is_some()
            && self.markers.0 == self.markers.1
    }

    /// The #1946 gap's shape, kept for the shape test: J never shows
    /// `local_state_lost`, ends in `awaiting_attestation`, still asks (its
    /// last `recovery` lists B as `pending`) and names no exit.
    fn asking(&self) -> bool {
        !self.states_after.is_empty()
            && self.asked.iter().any(|(agent, answer)| {
                agent.eq_ignore_ascii_case(&self.b_hex) && answer == "pending"
            })
            && !self.states_after.iter().any(|state| state == LOST)
            && self
                .states_after
                .last()
                .is_some_and(|state| state.starts_with("awaiting_attestation"))
            && self.exit.is_none()
    }

    /// J ends in `readmission_required {local_state_lost}` with an exit.
    fn inert_lost(&self) -> bool {
        self.states_after.last().map(String::as_str) == Some(LOST)
            && self.exit.as_deref().is_some_and(|exit| !exit.is_empty())
    }
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    // J asks capable admins lowest agent ID first (D40). The row has J ask
    // A, so A takes the lower agent ID of the two admins.
    start_ranked(sim, LABELS, &["A", "B"]).await?;
    mesh(sim, LABELS).await?;
    let group = create_group(sim, "A").await?;
    for member in ["M1", "M2", "B"] {
        seat(sim, "A", member, &group).await?;
    }
    promote(sim, "A", "B", &group, &["A", "M1", "M2", "B"]).await?;
    settled(
        sim,
        &["M1", "M2", "B"],
        &group,
        "every member holds A's revision",
    )
    .await?;
    let link = invite(sim, "A", &group).await?;
    let sealed = seal_j(sim, &link, &group).await?;
    let mut run = Run {
        sealed: sealed.state_revision,
        ..Run::default()
    };
    settled(
        sim,
        &["M1", "M2", "B", "J"],
        &group,
        "every node holds J's seal",
    )
    .await?;
    sim.within("the seal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    run.active = status(sim, "J", &group)
        .await?
        .and_then(|st| st.membership)
        .as_deref()
        == Some("active");

    let hold = OriginHold::install(sim, "H-S3-q (2)");
    let mut policy = Policy {
        b: sim.peer("B")?.0,
        j: sim.peer("J")?.0,
        a_and_j: keys(sim, &["A", "J"])?,
        topic: meta_topic(sim, &group).await?,
        meta_to_j: false,
        b_to_j: false,
        all_to_j: false,
    };
    policy.set(&hold, sim, "every message between B and {A, J} held");
    rename(sim, "A", &group, "w3h q2 A r+2").await?;
    settled(sim, &["J"], &group, "J holds A's r+2").await?;
    policy.meta_to_j = true;
    policy.all_to_j = true;
    policy.set(&hold, sim, "and every write to J");
    rename(sim, "A", &group, "w3h q2 A r+3").await?;
    rename(sim, "A", &group, "w3h q2 A r+4").await?;
    run.terminal = view(sim, "A", &group).await?.state_revision;
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold A's r+4").await?;
    sim.within("the r+4 resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    for label in ["A", "M1", "M2"] {
        empty_catchup_log(sim, label, &group).await?;
    }
    policy.all_to_j = false;
    policy.set(
        &hold,
        sim,
        "writes to J pass again, except the metadata topic",
    );
    rename(sim, "B", &group, "w3h q2 B r+2'").await?;
    let fork = view(sim, "B", &group).await?;
    run.fork = fork.state_revision;
    let r2 = view(sim, "J", &group).await?;
    ensure!(
        run.terminal == run.sealed + 3
            && run.fork == run.sealed + 1
            && r2.state_revision == run.sealed + 1
            && r2.state_hash != fork.state_hash,
        "INFRA: A at {}, B at {} ({}), J at {} ({}); want r+4, r+2' and r+2 beside it",
        run.terminal,
        run.fork,
        short(&fork.state_hash),
        r2.state_revision,
        short(&r2.state_hash)
    );
    let r3 = run.sealed + 2;
    let mute = MuteAtEnd::install(sim, &group, r3)?;
    let deaf = deaf_at_end(sim, &group, r3)?;
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    let a_id = sim.ids("A")?.0;
    policy.b_to_j = true;
    policy.set(&hold, sim, "B's messages reach J (not A)");
    let b_hex = sim.agent_hex("B")?;
    sim.until("J holds a marker naming B", SETUP, async |s: &Sim| {
        view_now(s, "J", &group).await.is_ok_and(|v| {
            v.marker
                .as_ref()
                .is_some_and(|m| m.committed_by.eq_ignore_ascii_case(&b_hex))
        })
    })
    .await?;
    receipt.setup_done(at(sim));
    let since = sim
        .fabric()
        .mark_indexed("case: J asks A for its one-link segment".to_string());

    // J reaches r+3 or later. The case stops J at once: from r+3 on every
    // write to J is dropped, so J moves no further, and its S3 state is
    // still on disk (a run that waited 30 s found no `.grecov` left).
    let _ = sim
        .until(
            "J applies its one-link segment",
            WINDOW + WINDOW,
            async |s: &Sim| {
                drain_answers(&mut rx, &a_id, &mut run.answered_before);
                let Some((j, _, text)) = poll_j(s, &group).await else {
                    return false;
                };
                if run.states_before.last() != Some(&text) {
                    run.states_before.push(text);
                }
                if run.heads_before.last().map(|h| h.0) != Some(j.state_revision) {
                    run.heads_before.push((j.state_revision, at(s)));
                }
                j.state_revision >= r3
            },
        )
        .await;
    drain_answers(&mut rx, &a_id, &mut run.answered_before);
    let stopped = view(sim, "J", &group).await?;
    run.restart_heads.0 = stopped.state_revision;
    run.markers.0 = stopped.marker.as_ref().map(|marker| format!("{marker:?}"));
    run.marked_by_b = stopped
        .marker
        .as_ref()
        .is_some_and(|m| m.committed_by.eq_ignore_ascii_case(&b_hex));
    receipt.note(format!(
        "J before the stop: {}; states {:?}; heads {:?}; answers {:?}; fork {}; terminal {}",
        stopped.describe(),
        run.states_before,
        run.heads_before,
        run.answered_before,
        fork.describe(),
        run.terminal
    ));
    let frames = (
        delivered_after(sim, "J", "A", since)?,
        delivered_after(sim, "A", "J", since)?,
    );
    receipt.request_delivered(
        "j_asked_a_and_a_answered",
        frames.0 > 0 && frames.1 > 0,
        format!("frames J->A, A->J: {frames:?}"),
        at(sim),
    );

    // Stop J after r+3, before its next segment.
    sim.stop("J", RestartMode::Graceful).await?;
    let (dir, names) = sidecar_files(sim, "J")?;
    let suffix = format!(".{GROUP_RECOVERY_EXTENSION}");
    let grecov: Vec<&String> = names
        .iter()
        .filter(|name| name.ends_with(&suffix))
        .collect();
    ensure!(
        grecov.len() == 1,
        "INFRA: J's sidecar directory holds {} .grecov files, want 1: {names:?}",
        grecov.len()
    );
    let file = grecov[0].clone();
    let path = dir.join(&file);
    let decoded_before = std::fs::read(&path)
        .ok()
        .and_then(|bytes| decode_sidecar(&bytes).ok())
        .is_some();
    let junk = junk();
    std::fs::write(&path, &junk).with_context(|| format!("write {}", path.display()))?;
    sim.fabric()
        .mark(format!("case: J's {file} replaced with 64 junk bytes"));
    let _held = mute.release(sim);
    deaf.store(true, Ordering::SeqCst);
    sim.fabric()
        .mark("fault: writes to J pass again (metadata topic still held)".to_string());
    sim.start_again("J").await?;
    // No await between the start and the subscription.
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    run.restart_heads.1 = view(sim, "J", &group).await?.state_revision;

    // Watch J past the `local_state_lost` stall.
    let _ = sim
        .until(
            "J stays inert after the rebuild",
            GATE_STALL + WINDOW + WINDOW,
            async |s: &Sim| {
                drain_answers(&mut rx, &a_id, &mut run.answered_after);
                let Some((j, _, text)) = poll_j(s, &group).await else {
                    return false;
                };
                push_new(&mut run.heads_after, &j.state_revision);
                if run.states_after.last() != Some(&text) {
                    run.states_after.push(text);
                }
                run.markers.1 = j.marker.as_ref().map(|marker| format!("{marker:?}"));
                false
            },
        )
        .await;
    drain_answers(&mut rx, &a_id, &mut run.answered_after);
    let recovery = sim
        .at_instant("read J's recovery", status_now(sim, "J", &group))
        .await??
        .map(|status| status.recovery)
        .unwrap_or(Value::Null);
    run.rebuilt = recovery["recovery_sidecar_rebuilt"].clone();
    run.exit = recovery["exit"].as_str().map(str::to_string);
    run.b_hex = hex::encode(sim.ids("B")?.0.as_bytes());
    run.asked = recovery["asked"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            Some((
                row["agent"].as_str()?.to_string(),
                row["answer"].as_str()?.to_string(),
            ))
        })
        .collect();
    run.a_end = view(sim, "A", &group).await?.state_revision;
    run.b_end = view(sim, "B", &group).await?.state_revision;
    let route = sim
        .at_instant("read J's recovery route", recovery_route(sim, "J", &group))
        .await??;
    receipt.note(format!("J's GET /groups/:id/recovery at the end: {route}"));

    // The harness reads a node's files only while it is stopped.
    sim.stop("J", RestartMode::Graceful).await?;
    let (dir, names) = sidecar_files(sim, "J")?;
    let disk = Disk::read(&dir, &names, &file, &junk);
    receipt.note(format!("J's sidecar directory at the end: {names:?}"));

    receipt.evidence(
        "j_active_member_at_r_plus_1",
        run.active,
        format!("J sealed at {} active {}", run.sealed, run.active),
        at(sim),
    );
    receipt.evidence(
        "j_marked_by_b_armed_a_one_link_ata_and_stopped_after_it",
        run.stopped_after_segment() && decoded_before,
        format!(
            "J at {} marker by B {} answers {:?}; sidecar decoded before the damage {}",
            run.restart_heads.0, run.marked_by_b, run.answered_before, decoded_before
        ),
        at(sim),
    );
    let quarantined = disk.quarantined();
    let named = run.rebuild_named(&file, &disk);
    let still = run.nothing_committed();
    let lost = run.inert_lost();
    receipt.note(format!(
        "old_bytes_in_one_history_copy_and_a_fresh_sidecar: ok={quarantined}"
    ));
    receipt.note(format!(
        "recovery_sidecar_rebuilt_names_file_txid_and_loss: ok={named}"
    ));
    receipt.note(format!(
        "no_commit_and_no_marker_cleared_after_the_rebuild: ok={still}"
    ));
    receipt.note(format!(
        "j_inert_in_readmission_required_local_state_lost_with_exit: ok={lost}"
    ));
    receipt.note(run.describe(&disk));
    let passed = quarantined && named && still && lost;
    if !passed {
        receipt.cause(CAUSE, Some(run.describe(&disk)), true, at(sim));
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "ADR 0109 S3 (#1356, #1572) H-S3-q (2): segment length {SEGMENT} by test configuration"
    ));
    // The case ranks its admins' identities before each start.
    match Sim::empty(case, seed, LABELS) {
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
fn w3h_1356_q_member_shapes() {
    let mut run = Run {
        sealed: 6,
        terminal: 9,
        fork: 7,
        restart_heads: (9, 9),
        heads_after: vec![9],
        states_after: vec![
            "awaiting_attestation{no_reply}".to_string(),
            LOST.to_string(),
        ],
        markers: (Some("m".to_string()), Some("m".to_string())),
        marked_by_b: true,
        a_end: 9,
        b_end: 7,
        exit: Some("manual_remove_and_reinvite".to_string()),
        answered_before: vec![(7, 1)],
        ..Run::default()
    };
    assert!(run.stopped_after_segment());
    assert!(run.nothing_committed());
    assert!(run.inert_lost());
    assert!(!run.asking(), "J showed local_state_lost");
    run.restart_heads.0 = 11;
    assert!(!run.stopped_after_segment(), "J went past the terminal");
    run.restart_heads.0 = 7;
    assert!(!run.stopped_after_segment(), "J did not move past r+2");
    run.restart_heads.0 = 9;
    run.answered_before = vec![(8, 1)];
    assert!(!run.stopped_after_segment(), "no one-link answer from r+2");
    run.heads_after.push(10);
    assert!(!run.nothing_committed(), "J committed after the rebuild");
    run.heads_after.pop();
    run.b_end = 8;
    assert!(!run.nothing_committed(), "B committed");
    run.b_end = 7;
    run.markers.1 = None;
    assert!(!run.nothing_committed(), "the marker was cleared");
    run.markers.1 = run.markers.0.clone();
    run.states_after = vec![
        "awaiting_attestation{no_reply}".to_string(),
        "awaiting_attestation{no_capable_peer}".to_string(),
    ];
    run.exit = None;
    assert!(!run.inert_lost());
    assert!(!run.asking(), "an empty asked list is not asking");
    run.b_hex = "0b".repeat(32);
    run.asked = vec![("0a".repeat(32), "pending".to_string())];
    assert!(!run.asking(), "B is not asked");
    run.asked = vec![("0b".repeat(32), "no_reply".to_string())];
    assert!(!run.asking(), "B is not pending");
    run.asked.push(("0B".repeat(32), "pending".to_string()));
    assert!(run.asking());
    run.exit = Some("x".to_string());
    assert!(!run.asking(), "an exit is named");

    let key = |b: u8| -> Key { [b; 32] };
    let (a, b, j) = (key(1), key(2), key(3));
    let mut policy = Policy {
        b,
        j,
        a_and_j: vec![a, j],
        topic: [9; 32],
        meta_to_j: false,
        b_to_j: false,
        all_to_j: false,
    };
    let frame = |origin, dst, topic: Option<[u8; 32]>| Frame {
        origin,
        dst,
        topic,
        class: crate::network::sim::LaneClass::PubSub,
    };
    assert!(policy.drops(&frame(b, j, None)), "B to J held");
    assert!(policy.drops(&frame(a, b, None)), "A to B held");
    assert!(
        !policy.drops(&frame(a, j, Some([9; 32]))),
        "A's r+2 reaches J"
    );
    policy.meta_to_j = true;
    assert!(
        policy.drops(&frame(a, j, Some([9; 32]))),
        "metadata to J held"
    );
    assert!(
        !policy.drops(&frame(a, j, Some([8; 32]))),
        "another topic passes"
    );
    policy.all_to_j = true;
    assert!(
        policy.drops(&frame(a, j, Some([8; 32]))),
        "every write to J held"
    );
    let membership = Frame {
        class: crate::network::sim::LaneClass::Membership,
        ..frame(a, j, None)
    };
    assert!(!policy.drops(&membership), "membership passes");
    policy.all_to_j = false;
    policy.b_to_j = true;
    assert!(
        !policy.drops(&frame(b, j, Some([9; 32]))),
        "B's r+2' reaches J"
    );
    assert!(policy.drops(&frame(b, a, None)), "B to A still held");
    assert!(policy.drops(&frame(j, b, None)), "J to B still held");
}

/// H-S3-q (2): a control, GREEN with the #1937 fix (#1946).
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
#[cfg_attr(
    target_os = "linux",
    ignore = "#1559: needs the W3-H entropy shim (nextest profile w3h / w3h-gate \
              --run-ignored all); plain suites run unseeded entropy, which is not an \
              observation"
)]
fn w3h_1356_control_s3_q_member_unreadable_sidecar() -> Result<()> {
    // Every daemon of the case runs on this thread (`block_on_paused`).
    let _limit = AtaMaxLinksOverride::set(SEGMENT as usize);
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_q_member_unreadable_sidecar";
        let receipt = run(case, 0x1356_0134).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?} {:?}",
            receipt.verdict(),
            receipt.named_causes()
        );
        Ok(())
    })
}
