//! ADR 0109 Validation table row H-S3-q (unreadable sidecar, D120, D119;
//! #1572), variant (1): the joiner. The row is a control; on this build
//! the arm is an expected RED (see "On main").
//!
//! Setup: H-S3-s ([`super::segments_s`]) up to J stopped between the
//! segments, with the segment length 2 by test configuration. J stops at
//! r+2 with its placeholder on disk. The case replaces J's `.grecov` with
//! 64 bytes that start `JUNKJUNK` (no family prefix) and starts J again.
//! The sim writes no ADR 0094 upgrade journal, so the host commit gate is
//! open (host commit written).
//!
//! Desired result (the row's "All" and "(1)" cells):
//! - The old bytes sit, byte-identical, in one ADR 0108 §5a history copy,
//!   and a fresh `.grecov` exists that names one rebuild `txid`.
//! - `recovery.recovery_sidecar_rebuilt` names the file, that `txid` and
//!   what was lost.
//! - No node commits because of the rebuild: J stays at r+2 and A stays
//!   at the terminal r+4. No marker is cleared (J's marker is the same
//!   before the damage and at the end).
//! - J stays inert and shows `readmission_required {local_state_lost}`,
//!   with an `exit`. In this build the exit is D43's remedy
//!   (`manual_remove_and_reinvite`); ADR 0114's repair is not in effect.
//!
//! **On main (14 Nov 2026).** The quarantine works: the junk bytes sit
//! in one history copy and a fresh `.grecov` names the rebuild `txid`.
//! Nothing commits and no marker clears. But after the rebuild J has no
//! `recovery` object at all (`GET /groups/:id` shows `recovery: null`),
//! so `recovery_sidecar_rebuilt` never shows, and J sends A no request
//! for the whole watch. `local_state_lost` is set by two paths in
//! `group_recovery.rs`, and neither fires here: `ensure_placeholders`
//! needs an authoritative record in the sidecar (the rebuild dropped it),
//! and `local_state_lost` needs an admin-armed ATA (J asks for none). The
//! arm pins that cause ([`CAUSE_SILENT`]); the fix belongs to the S3
//! code, and with it the arm turns GREEN and is renamed a control.
//!
//! **Holds.** As H-S3-s: every gossip write to J on the group's metadata
//! topic is dropped for the whole case, and J's writes are dropped from
//! r+2 until its graceful stop. J's writes pass again before it starts,
//! so J can ask A after the rebuild; the row asks that J still stays
//! inert. The `local_state_lost` stall is `GATE_STALL` (10 min) after J
//! is admin-armed with no progress, so the case watches J for
//! `GATE_STALL` plus two request windows.

use super::gaps::{recovery_route, remove, s0, seal_j};
use super::segments::hold_meta_from_j;
use super::segments_s::{drain_answers, poll_j, push_new, MuteAtEnd};
use super::*;
use crate::groups::recovery::{
    decode_sidecar, AtaMaxLinksOverride, GATE_STALL, GROUP_RECOVERY_DIR, GROUP_RECOVERY_EXTENSION,
};
use std::path::Path;

const LABELS: &[&str] = &["A", "M1", "M2", "J"];
/// The test segment length (H-S3-q (1) runs on H-S3-s).
const SEGMENT: u64 = 2;
const FINAL: &str = "junk_sidecar_quarantined_rebuilt_and_j_inert_in_local_state_lost";
const CAUSE: &str = "the junk .grecov was not kept byte-identical in one history copy, no \
                     fresh sidecar names the rebuild, recovery_sidecar_rebuilt is missing, a \
                     node committed or a marker cleared after the rebuild, or J does not stay \
                     inert in readmission_required {local_state_lost}";
/// The cause the expected-RED arm pins: J is silent after the rebuild.
const CAUSE_SILENT: &str = "after the rebuild J has no recovery object (no \
                            recovery_sidecar_rebuilt, no readmission_required \
                            {local_state_lost}) and asks A for nothing, while the quarantine \
                            itself is correct and nothing commits";
/// ADR 0109 H-S3-a's window, also enough for one request round.
const WINDOW: Duration = Duration::from_secs(130);
const QUIET: Duration = Duration::from_secs(30);
const LOST: &str = "readmission_required{local_state_lost}";
/// The 64 junk bytes the row writes: `JUNKJUNK` and 56 more.
fn junk() -> Vec<u8> {
    [b"JUNKJUNK".as_slice(), &[0u8; 56]].concat()
}

/// The sidecar directory of `label`, and the files in it.
fn sidecar_files(sim: &Sim, label: &str) -> Result<(std::path::PathBuf, Vec<String>)> {
    let dir = sim.data_dir(label)?.join(GROUP_RECOVERY_DIR);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok((dir, names))
}

/// What the case read of J's sidecar directory after the rebuild.
#[derive(Default, Debug)]
struct Disk {
    /// History copies of the damaged file (`<file>.q-...`, no `.pending`).
    history: Vec<String>,
    /// History copies whose bytes are the junk, byte for byte.
    identical: usize,
    /// The fresh sidecar decodes; its `rebuilt_from` as hex.
    fresh_rebuilt_from: Option<Vec<String>>,
    /// Pending copies left in the directory.
    pending: usize,
}

impl Disk {
    fn read(dir: &Path, names: &[String], file: &str, junk: &[u8]) -> Self {
        let prefix = format!("{file}.q-");
        let mut disk = Disk::default();
        for name in names {
            if name.ends_with(".pending") {
                disk.pending += 1;
            } else if name.starts_with(&prefix) {
                if std::fs::read(dir.join(name)).is_ok_and(|bytes| bytes == junk) {
                    disk.identical += 1;
                }
                disk.history.push(name.clone());
            }
        }
        disk.fresh_rebuilt_from = std::fs::read(dir.join(file))
            .ok()
            .and_then(|bytes| decode_sidecar(&bytes).ok())
            .map(|body| body.rebuilt_from.iter().map(hex::encode).collect());
        disk
    }

    /// One history copy holds the junk byte for byte, no pending copy is
    /// left, and the fresh sidecar names exactly one rebuild.
    fn quarantined(&self) -> bool {
        self.history.len() == 1
            && self.identical == 1
            && self.pending == 0
            && self
                .fresh_rebuilt_from
                .as_ref()
                .is_some_and(|from| from.len() == 1)
    }
}

/// What the case saw of J and A.
#[derive(Default)]
struct Run {
    base: u64,
    terminal: u64,
    /// J's head at its stop, and once it is back.
    restart_heads: (u64, u64),
    /// J's distinct heads and `recovery` states after the restart.
    heads_after: Vec<u64>,
    states_after: Vec<String>,
    /// J's marker before the damage, and at the end.
    markers: (Option<String>, Option<String>),
    /// J's sidecar held an authoritative record (the placeholder) before
    /// the damage.
    placeheld: bool,
    /// A's state revision at the end.
    a_end: u64,
    /// `recovery_sidecar_rebuilt` and `exit` in J's last `recovery`.
    rebuilt: Value,
    exit: Option<String>,
    /// `(from, entries)` of each ATA A sent J after the restart.
    answered_after: Vec<(u64, usize)>,
}

impl Run {
    fn describe(&self, disk: &Disk) -> String {
        format!(
            "r={} terminal {}; placeheld {}; restart heads {:?}; after: heads {:?} states {:?} \
             answered {:?}; markers {:?}; A at end {}; rebuilt {}; exit {:?}; disk {:?}",
            self.base,
            self.terminal,
            self.placeheld,
            self.restart_heads,
            self.heads_after,
            self.states_after,
            self.answered_after,
            self.markers,
            self.a_end,
            self.rebuilt,
            self.exit,
            disk
        )
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
        let end = self.base + SEGMENT;
        self.restart_heads == (end, end)
            && self.heads_after.iter().all(|head| *head == end)
            && self.a_end == self.terminal
            && self.markers.0 == self.markers.1
    }

    /// J ends in `readmission_required {local_state_lost}` with an exit.
    /// The gap the expected-RED arm pins: after the rebuild J only ever
    /// shows no `recovery` object and A sent it no ATA.
    fn silent(&self) -> bool {
        !self.states_after.is_empty()
            && self.states_after.iter().all(|state| state == "null")
            && self.answered_after.is_empty()
            && self.rebuilt.is_null()
    }

    fn inert_lost(&self) -> bool {
        self.states_after.last().map(String::as_str) == Some(LOST)
            && self.exit.as_deref().is_some_and(|exit| !exit.is_empty())
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
    rename(sim, "A", &group, "w3h q unreadable sidecar").await?;
    let gap = view(sim, "A", &group).await?.state_revision;
    ensure!(
        gap == run.base + 3,
        "INFRA: the gap is {} links, want 3",
        gap - run.base
    );
    let end = run.base + SEGMENT;
    hold_meta_from_j(sim, &group).await?;
    let mute = MuteAtEnd::install(sim, &group, end)?;
    receipt.setup_done(at(sim));

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
    run.terminal = sealed.state_revision;

    // Segment 1: J reaches the segment end and stays there.
    let mut quiet_from: Option<Duration> = None;
    let _ = sim
        .until(
            "J stays at the end of segment 1",
            WINDOW + QUIET,
            async |s: &Sim| {
                let Some((j, _, _)) = poll_j(s, &group).await else {
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
    let stopped = view(sim, "J", &group).await?;
    run.restart_heads.0 = stopped.state_revision;
    run.markers.0 = stopped.marker.as_ref().map(|marker| format!("{marker:?}"));
    ensure!(
        run.restart_heads.0 == end,
        "INFRA: J is at {} before the stop, want the segment end {end}",
        run.restart_heads.0
    );

    // Stop J between the segments, with its placeholder on disk.
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
    run.placeheld = std::fs::read(&path)
        .ok()
        .and_then(|bytes| decode_sidecar(&bytes).ok())
        .is_some_and(|body| body.authoritative_record.is_some());
    let junk = junk();
    std::fs::write(&path, &junk).with_context(|| format!("write {}", path.display()))?;
    sim.fabric()
        .mark(format!("case: J's {file} replaced with 64 junk bytes"));
    let _held = mute.release(sim);
    sim.start_again("J").await?;
    // No await between the start and the subscription.
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    let a_id = sim.ids("A")?.0;
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
    run.a_end = view(sim, "A", &group).await?.state_revision;
    let frames = (
        delivered_after(sim, "J", "A", since)?,
        delivered_after(sim, "A", "J", since)?,
    );
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
        "j_placeheld_before_the_damage",
        run.placeheld,
        format!("{file} held an authoritative record: {}", run.placeheld),
        at(sim),
    );
    receipt.request_delivered(
        "j_join_reached_a_and_a_answered",
        frames.0 > 0 && frames.1 > 0,
        format!("frames J->A, A->J: {frames:?}"),
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
        let expected = if quarantined && still && run.silent() {
            CAUSE_SILENT
        } else {
            CAUSE
        };
        receipt.cause(expected, Some(run.describe(&disk)), true, at(sim));
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "ADR 0109 S3 (#1356, #1572) H-S3-q (1): segment length {SEGMENT} by test configuration"
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
fn w3h_1356_q_sidecar_shapes() {
    let junk = junk();
    let dir = tempfile::tempdir().expect("tempdir");
    let file = "g.grecov";
    std::fs::write(dir.path().join("g.grecov.q-01-02"), &junk).expect("write");
    let names = vec!["g.grecov".to_string(), "g.grecov.q-01-02".to_string()];
    let mut disk = Disk::read(dir.path(), &names, file, &junk);
    assert_eq!(disk.history.len(), 1);
    assert_eq!(disk.identical, 1);
    assert!(disk.fresh_rebuilt_from.is_none(), "no fresh file on disk");
    assert!(!disk.quarantined(), "no fresh sidecar");
    disk.fresh_rebuilt_from = Some(vec!["07".repeat(16)]);
    assert!(disk.quarantined());
    disk.pending = 1;
    assert!(!disk.quarantined(), "a pending copy is left");
    disk.pending = 0;
    std::fs::write(dir.path().join("g.grecov.q-01-02"), b"other").expect("write");
    let changed = Disk::read(dir.path(), &names, file, &junk);
    assert_eq!(changed.identical, 0, "the history copy is not the junk");

    let mut run = Run {
        base: 5,
        terminal: 9,
        restart_heads: (7, 7),
        heads_after: vec![7],
        states_after: vec!["catching_up".to_string(), LOST.to_string()],
        a_end: 9,
        rebuilt: json!({"file": file, "txid": "07".repeat(16), "lost": ["served_chain"]}),
        exit: Some("manual_remove_and_reinvite".to_string()),
        ..Run::default()
    };
    assert!(run.rebuild_named(file, &disk));
    assert!(run.nothing_committed());
    assert!(run.inert_lost());
    run.rebuilt["txid"] = json!("08".repeat(16));
    assert!(!run.rebuild_named(file, &disk), "another txid");
    run.rebuilt = Value::Null;
    assert!(!run.rebuild_named(file, &disk), "no rebuilt object");
    run.heads_after.push(9);
    assert!(!run.nothing_committed(), "J committed after the rebuild");
    run.heads_after.pop();
    run.a_end = 10;
    assert!(!run.nothing_committed(), "A committed after the rebuild");
    run.a_end = 9;
    run.markers = (Some("m".to_string()), None);
    assert!(!run.nothing_committed(), "a marker was cleared");
    run.markers = (None, None);
    run.exit = None;
    assert!(!run.inert_lost(), "no exit");
    run.exit = Some("manual_remove_and_reinvite".to_string());
    run.states_after.push("null".to_string());
    assert!(!run.inert_lost(), "J left local_state_lost");
    assert!(!run.silent(), "J showed a state before null");
    run.states_after = vec!["null".to_string()];
    run.rebuilt = json!({"file": file});
    assert!(!run.silent(), "the rebuilt object is present");
    run.rebuilt = Value::Null;
    assert!(run.silent());
    run.answered_after.push((7, 2));
    assert!(!run.silent(), "A answered J after the rebuild");
}

/// H-S3-q (1): an expected RED on main, pinned `=RED` in the W3-H gate
/// with [`CAUSE_SILENT`]; GREEN with the S3 fix.
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
fn w3h_1356_red_s3_q_joiner_unreadable_sidecar() -> Result<()> {
    // Every daemon of the case runs on this thread (`block_on_paused`).
    let _limit = AtaMaxLinksOverride::set(SEGMENT as usize);
    super::super::block_on_paused(async move {
        let case = "w3h_1356_red_s3_q_joiner_unreadable_sidecar";
        let receipt = run(case, 0x1356_0133).await;
        // The pin names the exact failure, not any RED.
        ensure!(
            receipt.verdict() == Some(Verdict::Red)
                && receipt.named_causes().contains(&CAUSE_SILENT),
            "{case}: expected Red with the silent-joiner cause, got {:?} {:?}",
            receipt.verdict(),
            receipt.named_causes()
        );
        Ok(())
    })
}
