//! ADR 0109 Validation table row H-S3-q2 (ADR 0108 §5a fault cases for
//! `F` = `<stable_group_id>.grecov`, D120; #1572).
//!
//! Setup: H-S3-q (1)'s data directory, which is H-S3-s ([`super::segments_s`])
//! up to J stopped between the segments with its placeholder on disk
//! (segment length 2 by test configuration). The case copies J's sidecar
//! directory once. Each fault case then starts from that copy: the case
//! puts the copy back, plants the case's on-disk state, starts J, watches
//! it for one request window, stops it and reads the directory. J's writes
//! (except membership and plane hello frames) stay dropped from the
//! segment end for the whole case, so J's live state never moves and every
//! case starts from the same J. The sim writes no ADR 0094 upgrade
//! journal, so the host commit gate is open.
//!
//! Cases and desired results (ADR 0108 §5a, `sidecar_resume.rs`):
//! - Classification forms on `F`: a missing prefix (`JUNKJUNK` and 56
//!   bytes), a truncated header (the 6 bytes `X0GRCV`), an invalid version
//!   (`X0GRCV0\0` and 64 bytes) and a bad terminator (`X0GRCV1`, 0x01 and
//!   64 bytes) each quarantine in one transaction: one history copy holds
//!   the bytes, a fresh `F` names one rebuild, no `.pending` is left.
//! - A newer `F` (`X0GRCV2\0` and 64 bytes) shows `sidecar_newer_format`;
//!   `F` stays byte-identical and no copy is made.
//! - A read error (`F` is a directory) shows `sidecar_unavailable`; `F`
//!   stays and no copy is made.
//! - Resume forms (the §5a cut points as the on-disk states they leave):
//!   a verified pending copy with `F` missing resumes into one replacement
//!   that lists its `txid`; a pending copy that fails verify with `F`
//!   missing writes no replacement and shows `sidecar_quarantine_failed
//!   {step: verify}`; of three pending copies with `F` missing, one failing
//!   verify, the replacement lists the two that pass and the failed one
//!   stays pending; a verified pending copy beside a valid `F` (a crash
//!   after the replacement write) becomes history and `F` is kept.
//! - History with `F` present: both stay byte-identical. History with `F`
//!   absent: no replacement is written and the history stays.
//! - A healthy restart: `F`'s bytes and `generation` do not change.
//!
//! In addition, for S3: while a §5a fault state holds (newer, unavailable,
//! quarantine failed) J sends no request and arms nothing, and no marker
//! or gate is cleared. A request is any direct write from J to A, counted
//! when J hands it to the transport (J's writes are dropped after that).
//! The healthy restart is the control: there J does ask A, so the count
//! can see a request.
//!
//! Not covered, by name: the fsync failures at §5a steps 2, 4 and 5 (no
//! fsync seam, as for S4's files in `case_1581g`), and a clock rollback
//! between two corruptions (the shim cannot move wall time back; the
//! `txid` is random, so no name depends on the clock).

use super::gaps::{recovery_route, remove, s0, seal_j};
use super::segments::hold_meta_from_j;
use super::segments_s::{drain_answers, MuteAtEnd};
use super::*;
use crate::groups::eviction::{quarantine_history_name, quarantine_pending_name};
use crate::groups::recovery::{
    decode_sidecar, AtaMaxLinksOverride, GROUP_RECOVERY_DIR, GROUP_RECOVERY_EXTENSION,
};
use std::path::Path;

const LABELS: &[&str] = &["A", "M1", "M2", "J"];
/// The test segment length (H-S3-q2 runs on H-S3-q (1)'s data directory).
const SEGMENT: u64 = 2;
const FINAL: &str = "every_grecov_fault_case_meets_adr_0108_5a_and_j_stays_inert_in_a_fault";
const CAUSE: &str = "a §5a fault case for the .grecov went wrong (quarantine, untouched \
                     newer or unreadable file, resume, history, or healthy restart), or J \
                     sent a request, moved or cleared a marker while a fault state held; \
                     `observed` lists each failing case";
/// ADR 0109 H-S3-a's window, also enough for one request round.
const WINDOW: Duration = Duration::from_secs(130);
const QUIET: Duration = Duration::from_secs(30);

/// One fault case.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Case {
    MissingPrefix,
    Truncated,
    BadVersion,
    BadTerminator,
    Newer,
    ReadError,
    PendingFMissing,
    PendingFailsVerify,
    ThreePendingOneFails,
    PendingBesideValidF,
    HistoryFPresent,
    HistoryFAbsent,
    Healthy,
}

/// In order. The healthy restart is last.
const CASES: &[Case] = &[
    Case::MissingPrefix,
    Case::Truncated,
    Case::BadVersion,
    Case::BadTerminator,
    Case::Newer,
    Case::ReadError,
    Case::PendingFMissing,
    Case::PendingFailsVerify,
    Case::ThreePendingOneFails,
    Case::PendingBesideValidF,
    Case::HistoryFPresent,
    Case::HistoryFAbsent,
    Case::Healthy,
];

impl Case {
    /// The bytes a classification case writes at `F`.
    fn damage(self) -> Option<Vec<u8>> {
        let tail = |head: &[u8], n: usize| [head, &vec![0u8; n]].concat();
        Some(match self {
            Self::MissingPrefix => tail(b"JUNKJUNK", 56),
            Self::Truncated => b"X0GRCV".to_vec(),
            Self::BadVersion => tail(b"X0GRCV0\0", 64),
            Self::BadTerminator => tail(b"X0GRCV1\x01", 64),
            Self::Newer => tail(b"X0GRCV2\0", 64),
            _ => return None,
        })
    }

    /// A §5a fault state holds after the load (J must stay inert).
    fn fault(self) -> Option<&'static str> {
        match self {
            Self::Newer => Some("sidecar_newer_format"),
            Self::ReadError => Some("sidecar_unavailable"),
            Self::PendingFailsVerify => Some("sidecar_quarantine_failed"),
            _ => None,
        }
    }
}

/// The bytes of a quarantined copy the case plants.
fn copy_bytes(n: u8) -> Vec<u8> {
    [b"JUNKJUNK".as_slice(), &[n; 56]].concat()
}

/// J's sidecar directory as `(name, bytes)` (J stopped).
fn snapshot(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push((
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path())?,
            ));
        }
    }
    files.sort();
    Ok(files)
}

/// Put `files` back as the whole directory.
fn restore(dir: &Path, files: &[(String, Vec<u8>)]) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).with_context(|| format!("clear {}", dir.display()))?;
    }
    std::fs::create_dir_all(dir)?;
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes)?;
    }
    Ok(())
}

/// Write a pending copy of `F` holding `bytes`, named after `named`'s hash
/// (a copy that fails verify has `named != bytes`). Returns its name.
fn plant_pending(dir: &Path, file: &str, n: u8, named: &[u8], bytes: &[u8]) -> Result<String> {
    let txid = [n; 16];
    let name = quarantine_pending_name(file, &txid, named);
    std::fs::write(dir.join(&name), bytes)?;
    Ok(name)
}

/// The planted state, as the case's expectations need it.
#[derive(Default, Debug)]
struct Planted {
    /// The bytes at `F`, when `F` is a file.
    f: Option<Vec<u8>>,
    /// The pending copies that verify, and the ones that fail.
    good: Vec<String>,
    bad: Vec<String>,
    /// History copies planted, with their bytes.
    history: Vec<(String, Vec<u8>)>,
}

fn plant(dir: &Path, file: &str, healthy: &[u8], case: Case) -> Result<Planted> {
    let path = dir.join(file);
    let mut planted = Planted {
        f: Some(healthy.to_vec()),
        ..Planted::default()
    };
    if let Some(bytes) = case.damage() {
        std::fs::write(&path, &bytes)?;
        planted.f = Some(bytes);
        return Ok(planted);
    }
    match case {
        Case::ReadError => {
            std::fs::remove_file(&path)?;
            std::fs::create_dir(&path)?;
            planted.f = None;
        }
        Case::PendingFMissing => {
            std::fs::remove_file(&path)?;
            planted.f = None;
            let bytes = copy_bytes(1);
            planted
                .good
                .push(plant_pending(dir, file, 1, &bytes, &bytes)?);
        }
        Case::PendingFailsVerify => {
            std::fs::remove_file(&path)?;
            planted.f = None;
            let bytes = copy_bytes(2);
            planted
                .bad
                .push(plant_pending(dir, file, 2, b"other bytes", &bytes)?);
        }
        Case::ThreePendingOneFails => {
            std::fs::remove_file(&path)?;
            planted.f = None;
            for n in [3u8, 4] {
                let bytes = copy_bytes(n);
                planted
                    .good
                    .push(plant_pending(dir, file, n, &bytes, &bytes)?);
            }
            let bytes = copy_bytes(5);
            planted
                .bad
                .push(plant_pending(dir, file, 5, b"other bytes", &bytes)?);
        }
        Case::PendingBesideValidF => {
            let bytes = copy_bytes(6);
            planted
                .good
                .push(plant_pending(dir, file, 6, &bytes, &bytes)?);
        }
        Case::HistoryFPresent | Case::HistoryFAbsent => {
            if case == Case::HistoryFAbsent {
                std::fs::remove_file(&path)?;
                planted.f = None;
            }
            let bytes = copy_bytes(7);
            let pending = quarantine_pending_name(file, &[7u8; 16], &bytes);
            let name = quarantine_history_name(&pending)
                .context("a pending name ends in .pending")?
                .to_string();
            std::fs::write(dir.join(&name), &bytes)?;
            planted.history.push((name, bytes));
        }
        _ => {}
    }
    Ok(planted)
}

/// What the case read of J's sidecar directory after one load (J stopped).
#[derive(Default, Debug)]
struct Disk {
    /// The bytes at `F`; `None` when `F` is missing or not a file.
    f: Option<Vec<u8>>,
    f_is_dir: bool,
    /// `F` decodes: its `generation` and `rebuilt_from` as hex.
    generation: Option<u64>,
    rebuilt_from: Vec<String>,
    /// History and pending copies of `F`, with their bytes.
    history: Vec<(String, Vec<u8>)>,
    pending: Vec<String>,
}

impl Disk {
    fn read(dir: &Path, file: &str) -> Result<Self> {
        let path = dir.join(file);
        let mut disk = Disk {
            f_is_dir: path.is_dir(),
            ..Disk::default()
        };
        if path.is_file() {
            let bytes = std::fs::read(&path)?;
            if let Ok(body) = decode_sidecar(&bytes) {
                disk.generation = Some(body.generation);
                disk.rebuilt_from = body.rebuilt_from.iter().map(hex::encode).collect();
            }
            disk.f = Some(bytes);
        }
        let prefix = format!("{file}.q-");
        for entry in std::fs::read_dir(dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&prefix) {
                continue;
            }
            if name.ends_with(".pending") {
                disk.pending.push(name);
            } else {
                let bytes = std::fs::read(dir.join(&name))?;
                disk.history.push((name, bytes));
            }
        }
        disk.history.sort();
        disk.pending.sort();
        Ok(disk)
    }

    /// The history copies whose names are not in `planted`.
    fn new_history(&self, planted: &Planted) -> Vec<&(String, Vec<u8>)> {
        self.history
            .iter()
            .filter(|(name, _)| !planted.history.iter().any(|(p, _)| p == name))
            .collect()
    }
}

/// The `txid` (hex) in a quarantined copy's name.
fn txid_of(name: &str, file: &str) -> Option<String> {
    name.strip_prefix(&format!("{file}.q-"))
        .and_then(|rest| rest.split('-').next())
        .map(str::to_string)
}

/// What one case left: whether its §5a result holds, and a note.
struct Outcome {
    ok: bool,
    asked: bool,
    note: String,
}

/// The §5a result of `case`, from the planted state, the directory after
/// the load, J's recovery state and the healthy bytes.
fn judge(
    case: Case,
    file: &str,
    planted: &Planted,
    disk: &Disk,
    state: Option<&str>,
    healthy: &[u8],
) -> bool {
    let new_history = disk.new_history(planted);
    let history_kept = planted
        .history
        .iter()
        .all(|copy| disk.history.contains(copy));
    let txids = |names: &[String]| -> Vec<String> {
        let mut ids: Vec<String> = names.iter().filter_map(|n| txid_of(n, file)).collect();
        ids.sort();
        ids
    };
    let mut rebuilt = disk.rebuilt_from.clone();
    rebuilt.sort();
    match case {
        Case::MissingPrefix | Case::Truncated | Case::BadVersion | Case::BadTerminator => {
            let damage = case.damage().unwrap_or_default();
            new_history.len() == 1
                && new_history[0].1 == damage
                && disk.pending.is_empty()
                && disk.rebuilt_from.len() == 1
                && txid_of(&new_history[0].0, file).as_ref() == disk.rebuilt_from.first()
        }
        Case::Newer => {
            disk.f.as_deref() == planted.f.as_deref()
                && disk.history.is_empty()
                && disk.pending.is_empty()
                && state == case.fault()
        }
        Case::ReadError => {
            disk.f_is_dir
                && disk.history.is_empty()
                && disk.pending.is_empty()
                && state == case.fault()
        }
        Case::PendingFMissing | Case::ThreePendingOneFails => {
            rebuilt == txids(&planted.good)
                && new_history.len() == planted.good.len()
                && disk.pending == planted.bad
        }
        Case::PendingFailsVerify => {
            disk.f.is_none()
                && !disk.f_is_dir
                && disk.history.is_empty()
                && disk.pending == planted.bad
                && state == case.fault()
        }
        Case::PendingBesideValidF => {
            disk.f.as_deref() == Some(healthy) && new_history.len() == 1 && disk.pending.is_empty()
        }
        Case::HistoryFPresent => {
            disk.f.as_deref() == Some(healthy)
                && history_kept
                && new_history.is_empty()
                && disk.pending.is_empty()
        }
        Case::HistoryFAbsent => {
            disk.f.is_none() && history_kept && new_history.is_empty() && disk.pending.is_empty()
        }
        // J's writes pass in this case, so J can move on and rewrite `F`
        // later; the restart itself is checked on `F` at the start.
        Case::Healthy => disk.history.is_empty() && disk.pending.is_empty(),
    }
}

/// Drops every write J originates (except membership and plane hello
/// frames) while the flag is set.
fn hold_j_out(sim: &Sim) -> Result<Arc<std::sync::atomic::AtomicBool>> {
    use crate::network::sim::{Fault, LaneClass};
    use std::sync::atomic::{AtomicBool, Ordering};
    let j = sim.peer("J")?.0;
    let held = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&held);
    sim.fabric().add_rule(move |write| {
        let control = matches!(
            write.lane.class,
            LaneClass::Membership | LaneClass::PlaneHello
        );
        match flag.load(Ordering::SeqCst) && write.lane.src == j && !control {
            true => Fault::Drop,
            false => Fault::Pass,
        }
    });
    sim.fabric()
        .mark("fault: J's writes held between the cases");
    Ok(held)
}

/// A's requester row for J (`GET /groups/:id/recovery` on A).
async fn a_row_for_j(sim: &Sim, group: &str) -> Result<Value> {
    let j_hex = sim.agent_hex("J")?;
    let route = sim
        .at_instant("read A's recovery route", recovery_route(sim, "A", group))
        .await??;
    Ok(route["requesters"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| {
                    row["requester"]
                        .as_str()
                        .is_some_and(|id| id.eq_ignore_ascii_case(&j_hex))
                })
                .cloned()
        })
        .unwrap_or(Value::Null))
}

/// Run one case from the copy: plant, start J, watch, stop, read.
async fn one_case(
    sim: &mut Sim,
    group: &str,
    copy: &[(String, Vec<u8>)],
    (file, healthy): (&str, &[u8]),
    stopped: &View,
    case: Case,
    j_out: &std::sync::atomic::AtomicBool,
) -> Result<Outcome> {
    use std::sync::atomic::Ordering;
    let dir = sim.data_dir("J")?.join(GROUP_RECOVERY_DIR);
    restore(&dir, copy)?;
    let planted = plant(&dir, file, healthy, case)?;
    // J's writes pass in a fault case (to see that J sends nothing) and in
    // the healthy restart (to see that it does). Elsewhere they stay held,
    // so J never moves.
    let open = case.fault().is_some() || case == Case::Healthy;
    j_out.store(!open, Ordering::SeqCst);
    let row_before = a_row_for_j(sim, group).await?;
    sim.fabric().mark(format!("case: H-S3-q2 {case:?}"));
    sim.start_again("J").await?;
    // No await between the start and the subscription.
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    let a_id = sim.ids("A")?.0;
    let mut answered: Vec<(u64, usize)> = Vec::new();
    // The healthy restart: F before J does anything (a passive read).
    let at_start = std::fs::read(dir.join(file)).ok();
    let mut heads: Vec<u64> = Vec::new();
    let mut markers: Vec<Option<String>> = Vec::new();
    let mut gates: Vec<Option<String>> = Vec::new();
    let mut state: Option<String> = None;
    let _ = sim
        .until(
            &format!("J watched in {case:?}"),
            WINDOW,
            async |s: &Sim| {
                drain_answers(&mut rx, &a_id, &mut answered);
                if let Ok(j) = view_now(s, "J", group).await {
                    if !heads.contains(&j.state_revision) {
                        heads.push(j.state_revision);
                    }
                    let marker = j.marker.as_ref().map(|m| format!("{m:?}"));
                    if !markers.contains(&marker) {
                        markers.push(marker);
                    }
                    if !gates.contains(&j.gap_refusal) {
                        gates.push(j.gap_refusal.clone());
                    }
                }
                if let Ok(Some(st)) = status_now(s, "J", group).await {
                    state = st.recovery_state().map(str::to_string);
                }
                false
            },
        )
        .await;
    drain_answers(&mut rx, &a_id, &mut answered);
    let row_after = a_row_for_j(sim, group).await?;
    let asked = row_after != row_before || !answered.is_empty();
    sim.stop("J", RestartMode::Graceful).await?;
    j_out.store(true, Ordering::SeqCst);
    let disk = Disk::read(&dir, file)?;
    let mut ok = judge(case, file, &planted, &disk, state.as_deref(), healthy);
    let stopped_marker = stopped.marker.as_ref().map(|m| format!("{m:?}"));
    let still = heads.iter().all(|h| *h == stopped.state_revision)
        && markers.iter().all(|m| *m == stopped_marker)
        && gates.iter().all(|g| *g == stopped.gap_refusal);
    if case.fault().is_some() {
        ok = ok && !asked && still;
    }
    if case == Case::Healthy {
        let generation = |bytes: Option<&[u8]>| {
            bytes
                .and_then(|b| decode_sidecar(b).ok())
                .map(|b| b.generation)
        };
        ok = ok
            && at_start.as_deref() == Some(healthy)
            && generation(at_start.as_deref()) == generation(Some(healthy));
    }
    let note = format!(
        "{case:?}: ok={ok}; state {state:?}; asked {asked} (answers {answered:?}, A's row before \
         {row_before} after {row_after}); heads {heads:?}; markers \
         {markers:?}; gates {gates:?}; planted good {:?} bad {:?} history {:?}; disk f {:?} \
         dir {} generation {:?} rebuilt_from {:?} history {:?} pending {:?}",
        planted.good,
        planted.bad,
        planted
            .history
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>(),
        disk.f.as_ref().map(Vec::len),
        disk.f_is_dir,
        disk.generation,
        disk.rebuilt_from,
        disk.history
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>(),
        disk.pending
    );
    Ok(Outcome { ok, asked, note })
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let (group, _) = s0(sim, LABELS, true, &[]).await?;
    let link = invite(sim, "A", &group).await?;
    let base = view(sim, "A", &group).await?.state_revision;
    remove(sim, "A", "M1", &group).await?;
    remove(sim, "A", "M2", &group).await?;
    rename(sim, "A", &group, "w3h q2 sidecar faults").await?;
    let gap = view(sim, "A", &group).await?.state_revision;
    ensure!(
        gap == base + 3,
        "INFRA: the gap is {} links, want 3",
        gap - base
    );
    let end = base + SEGMENT;
    hold_meta_from_j(sim, &group).await?;
    // J's writes are held from the segment end; between the cases the
    // toggle in [`hold_j_out`] holds them instead.
    let mute = MuteAtEnd::install(sim, &group, end)?;
    receipt.setup_done(at(sim));

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
    let stopped = view(sim, "J", &group).await?;
    ensure!(
        stopped.state_revision == end,
        "INFRA: J is at {} before the stop, want the segment end {end}",
        stopped.state_revision
    );
    sim.stop("J", RestartMode::Graceful).await?;
    let j_out = hold_j_out(sim)?;
    let _ = mute.release(sim);
    let dir = sim.data_dir("J")?.join(GROUP_RECOVERY_DIR);
    let copy = snapshot(&dir)?;
    let suffix = format!(".{GROUP_RECOVERY_EXTENSION}");
    let grecov: Vec<&(String, Vec<u8>)> = copy
        .iter()
        .filter(|(name, _)| name.ends_with(&suffix))
        .collect();
    ensure!(
        grecov.len() == 1 && copy.len() == 1,
        "INFRA: J's sidecar directory holds {:?}, want one .grecov",
        copy.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()
    );
    let (file, healthy) = (grecov[0].0.clone(), grecov[0].1.clone());
    let placeheld = decode_sidecar(&healthy).is_ok_and(|b| b.authoritative_record.is_some());
    receipt.evidence(
        "j_placeheld_before_the_cases",
        placeheld,
        format!("{file} held an authoritative record: {placeheld}"),
        at(sim),
    );

    let mut failing = Vec::new();
    let mut healthy_requests = false;
    for case in CASES {
        let outcome = one_case(
            sim,
            &group,
            &copy,
            (&file, &healthy),
            &stopped,
            *case,
            &j_out,
        )
        .await?;
        receipt.note(outcome.note.clone());
        if *case == Case::Healthy {
            healthy_requests = outcome.asked;
        }
        if !outcome.ok {
            failing.push(format!("{case:?}"));
        }
    }
    receipt.request_delivered(
        "j_asks_a_on_a_healthy_restart",
        healthy_requests,
        "on the healthy restart A records J's request or answers it".to_string(),
        at(sim),
    );
    let passed = failing.is_empty();
    if !passed {
        receipt.cause(
            CAUSE,
            Some(format!("failing cases {failing:?}")),
            true,
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "ADR 0109 S3 (#1356, #1572) H-S3-q2: segment length {SEGMENT} by test configuration"
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

/// The judge, checked on fixed directories.
#[test]
fn w3h_1356_q2_judge_shapes() {
    let file = "g.grecov";
    let healthy = b"healthy".to_vec();
    let damage = Case::MissingPrefix.damage().unwrap_or_default();
    let planted = Planted {
        f: Some(damage.clone()),
        ..Planted::default()
    };
    let txid = "11".repeat(16);
    let copy = format!("{file}.q-{txid}-ab");
    let quarantined = Disk {
        f: Some(b"fresh".to_vec()),
        rebuilt_from: vec![txid.clone()],
        history: vec![(copy.clone(), damage.clone())],
        ..Disk::default()
    };
    assert!(judge(
        Case::MissingPrefix,
        file,
        &planted,
        &quarantined,
        None,
        &healthy
    ));
    let left = Disk {
        f: Some(damage.clone()),
        ..Disk::default()
    };
    assert!(!judge(
        Case::MissingPrefix,
        file,
        &planted,
        &left,
        None,
        &healthy
    ));
    let newer = Planted {
        f: Case::Newer.damage(),
        ..Planted::default()
    };
    let untouched = Disk {
        f: Case::Newer.damage(),
        ..Disk::default()
    };
    assert!(judge(
        Case::Newer,
        file,
        &newer,
        &untouched,
        Some("sidecar_newer_format"),
        &healthy
    ));
    assert!(!judge(
        Case::Newer,
        file,
        &newer,
        &untouched,
        None,
        &healthy
    ));
    assert_eq!(txid_of(&copy, file), Some(txid));
}

/// H-S3-q2: every ADR 0108 §5a fault case for the `.grecov` that has an
/// on-disk form.
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
fn w3h_1356_control_s3_q2_sidecar_fault_cases() -> Result<()> {
    // Every daemon of the case runs on this thread (`block_on_paused`).
    let _limit = AtaMaxLinksOverride::set(SEGMENT as usize);
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_q2_sidecar_fault_cases";
        let receipt = run(case, 0x1356_0134).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
