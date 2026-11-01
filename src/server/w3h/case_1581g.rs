//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_sidecar_lifecycle`): the ADR 0108 §5a fault forms for S4's own
//! files, `revocation-evictions.evs` and one `.evjournal`, on the real
//! daemon's boot load. The forms are planted on disk between a crash stop
//! and the next start, which is the §5a harness norm the row names. With
//! S4 merged (#1357) both arms expect the ADR behaviour (GREEN) and keep
//! the row's causes for a regression: the row's "red on main, where no
//! binary quarantines" predates #1508, and the red proof is a
//! never-committed neutralisation of the two quarantine call sites
//! (receipts in the PR body).
//!
//! - `control_sidecar_lifecycle_evs_damage_rebuilds`: the five `.evs`
//!   header damage forms the row names (a missing prefix, a header
//!   truncated to 9 bytes, version byte `0` or a non-digit, and a missing
//!   NUL terminator) each quarantine in one transaction — the damaged
//!   bytes move to a history copy, one empty replacement whose
//!   `rebuilt_from` lists the transaction id, the store state `rebuilt`,
//!   no `.pending` left — and a newer-layout `.evs` (`X0XEVICT3\0`; v2 is
//!   readable since #1508, so the row's "newer" form moves to v3) runs
//!   memory-only: state `sidecar_newer_format` naming the version, the
//!   file byte-identical, no history.
//! - `red_sidecar_lifecycle_journal_and_pending_resume`: a `.evjournal`
//!   header truncated to 7 bytes quarantines with no replacement (a
//!   missing journal is the normal state); a newer-layout journal
//!   (`X0XEVJ2\0`) is left untouched; a resume that finds a verified
//!   pending copy beside a damaged `.evs` writes one replacement listing
//!   both transaction ids.
//!
//! Harness honesty: fsync-failure injection has no seam, so the §5a cut
//! points are modelled as the on-disk states they leave. The journal stem
//! is arbitrary: §5a classification is keyed on the extension, and a
//! damaged or newer journal never decodes, so its stem cannot change the
//! outcome. A boot whose only fault must change nothing (the newer
//! journal) also plants a damaged `.evs` in the same load: the store
//! state publishes only after the whole load, journal scan included, so
//! the untouched read happens after it, not after a guessed settle
//! window. Not covered: the fsync failures at §5a steps 2, 4 and 5
//! themselves, a resume with the `.evs` missing and only the pending
//! copy, a scan with three pendings of which one fails verification,
//! retention (D148), and the ADR 0094 trial-gate forms, which stay with
//! the upgrade paths.

#![cfg(test)]

use super::control::create_group;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::{decode_evs, quarantine_pending_name, EVS_FILE_NAME};
use anyhow::{bail, Context as _};
use std::path::{Path, PathBuf};

/// Budget for one restarted daemon to publish its store classification.
const BOOT: Duration = Duration::from_secs(60);

const EVS_FILE: &str = EVS_FILE_NAME;
/// The planted journal: any stem is equivalent (see the module honesty
/// note); `treekem/planted.evjournal`.
const JOURNAL_FILE: &str = "planted.evjournal";
/// A newer-layout `.evs` body: `X0XEVICT3\0` plus bytes this binary
/// never reads.
const EVS_NEWER: &[u8] = b"X0XEVICT3\0newer-layout";
/// A newer-layout `.evjournal` body (`X0XEVJ2\0`; v1 is the highest this
/// binary reads).
const JOURNAL_NEWER: &[u8] = b"X0XEVJ2\0newer-layout";

const FINAL_CONTROL: &str =
    "every_damaged_evs_form_quarantines_with_history_and_an_empty_replacement";
const FINAL_RESUME: &str = "journal_faults_and_pending_resume_meet_adr_0108_5a";
const CAUSE_NOT_QUARANTINED: &str = "a damaged S4 file stayed in place: no quarantine \
                                     transaction, no history copy, no replacement";
const CAUSE_NEWER_TOUCHED: &str = "a newer-layout S4 file was rewritten, quarantined or \
                                   removed";
const CAUSE_RESUME_LOST: &str = "the 5a resume dropped pending evidence: the replacement \
                                 does not list every verified txid, or a pending copy or the \
                                 damaged file was left behind";

const LABELS: &[&str] = &["A"];

/// The five `.evs` header damage forms the row names (ADR 0110 S4
/// validation table, `s4_sidecar_lifecycle`).
const EVS_DAMAGE: &[(&str, &[u8])] = &[
    ("missing_prefix", b"X0XEVICU1\0damaged"),
    ("truncated_header_9_bytes", b"X0XEVICT1"),
    ("version_byte_zero", b"X0XEVICT\0\0damaged"),
    ("version_byte_non_digit", b"X0XEVICT?\0damaged"),
    ("missing_nul", b"X0XEVICT1Xdamaged"),
];

/// The quarantine history and pending names of one file family in `dir`.
fn quarantine_names(dir: &Path, family: &str) -> (Vec<String>, Vec<String>) {
    let mut history = Vec::new();
    let mut pending = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (history, pending);
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !name.starts_with(family) || !name.contains(".q-") {
            continue;
        }
        if name.ends_with(".pending") {
            pending.push(name);
        } else {
            history.push(name);
        }
    }
    (history, pending)
}

/// A's store view of `group`: `(state, detail, rebuilt_from)` from
/// `GET /groups/:id`.
async fn store_view(
    sim: &Sim,
    group: &str,
) -> Result<Option<(String, Option<String>, Vec<String>)>> {
    let (status, body) = sim
        .request("A", Method::GET, &format!("/groups/{group}"), None)
        .await?;
    if !status.is_success() {
        bail!("A GET /groups/{group}: {status} {body}");
    }
    let store = &body["revocation_eviction_store"];
    if !store.is_object() {
        return Ok(None);
    }
    Ok(Some((
        store["state"].as_str().unwrap_or_default().to_string(),
        store["detail"].as_str().map(str::to_string),
        store["rebuilt_from"]
            .as_array()
            .map(|txids| {
                txids
                    .iter()
                    .filter_map(|txid| txid.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    )))
}

/// Wait until the store state is `want`, then read it once. A budget that
/// ends is not an error: the caller's assertion fails with its named
/// cause instead.
async fn await_store_state(
    sim: &Sim,
    group: &str,
    want: &str,
) -> Result<(String, Option<String>, Vec<String>)> {
    let _ = sim
        .until(
            &format!("store state becomes {want}"),
            BOOT,
            async |s: &Sim| {
                matches!(&store_view(s, group).await, Ok(Some((state, _, _))) if state == want)
            },
        )
        .await;
    store_view(sim, group)
        .await?
        .context("the group status carries no revocation_eviction_store")
}

/// [`await_store_state`] plus the delivered read one boot cycle records.
async fn boot_read(
    sim: &Sim,
    receipt: &mut Receipt,
    group: &str,
    want: &str,
    delivered: &str,
) -> Result<(String, Option<String>, Vec<String>)> {
    let (state, detail, rebuilt_from) = await_store_state(sim, group, want).await?;
    receipt.request_delivered(
        delivered,
        true,
        format!("store state {state}"),
        sim.fabric().now().as_micros(),
    );
    Ok((state, detail, rebuilt_from))
}

/// Whether the on-disk `.evs` is the §5a empty replacement whose
/// `rebuilt_from` equals `shown`, and what it holds.
fn replacement_check(dir: &Path, shown: &[String]) -> (bool, String) {
    let Ok(bytes) = std::fs::read(dir.join(EVS_FILE)) else {
        return (false, "no .evs on disk".to_string());
    };
    match decode_evs(&bytes) {
        Ok(body) => {
            let listed: Vec<String> = body.rebuilt_from.iter().map(hex::encode).collect();
            (
                body.rows.is_empty() && listed == shown,
                format!("rows={} rebuilt_from={listed:?}", body.rows.len()),
            )
        }
        Err(error) => (false, format!("{error:?}")),
    }
}

/// Plant a verified §5a pending copy of `bytes` under its pending name.
fn write_pending(dir: &Path, txid: &[u8; 16], bytes: &[u8]) -> Result<PathBuf> {
    let path = dir.join(quarantine_pending_name(EVS_FILE, txid, bytes));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// One §5a `.evs` damage cycle: crash-stop A, plant `bytes`, boot, and
/// check the whole transaction. Records the premise and the delivered
/// restart read; a failure records the row's cause.
async fn damage_cycle(
    sim: &mut Sim,
    receipt: &mut Receipt,
    group: &str,
    form: &str,
    bytes: &[u8],
) -> Result<bool> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    sim.stop("A", RestartMode::Crash).await?;
    let dir = sim.data_dir("A")?;
    let path = dir.join(EVS_FILE);
    std::fs::write(&path, bytes)?;
    sim.fabric().mark(format!("case: .evs damaged ({form})"));
    receipt.evidence(
        &format!("{form}: the damaged bytes are at the sidecar path"),
        std::fs::read(&path)? == bytes,
        format!("{} bytes planted", bytes.len()),
        at(sim),
    );
    let (history_before, _) = quarantine_names(&dir, EVS_FILE);
    sim.start_again("A").await?;
    let (state, detail, rebuilt_from) = boot_read(
        sim,
        receipt,
        group,
        "rebuilt",
        &format!("{form}: the restarted daemon serves the group and its S4 store view"),
    )
    .await?;
    let (history, pending) = quarantine_names(&dir, EVS_FILE);
    let preserved = history
        .iter()
        .filter_map(|name| std::fs::read(dir.join(name)).ok())
        .filter(|kept| kept.as_slice() == bytes)
        .count();
    let (replaced, replaced_detail) = replacement_check(&dir, &rebuilt_from);
    let ok = state == "rebuilt"
        && rebuilt_from.len() == 1
        && pending.is_empty()
        && history.len() == history_before.len() + 1
        && preserved == 1
        && replaced;
    if !ok {
        receipt.cause(
            CAUSE_NOT_QUARANTINED,
            Some(format!(
                "{form}: state={state} detail={detail:?} rebuilt_from={rebuilt_from:?} \
                 history={} pending={} preserved={preserved} replacement: {replaced_detail}",
                history.len(),
                pending.len(),
            )),
            true,
            at(sim),
        );
    }
    Ok(ok)
}

/// The §5a newer-layout `.evs` cycle: the file is never rewritten.
async fn newer_cycle(sim: &mut Sim, receipt: &mut Receipt, group: &str) -> Result<bool> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    sim.stop("A", RestartMode::Crash).await?;
    let dir = sim.data_dir("A")?;
    let path = dir.join(EVS_FILE);
    std::fs::write(&path, EVS_NEWER)?;
    sim.fabric().mark("case: .evs holds a v3 (newer) layout");
    receipt.evidence(
        "newer: the v3 bytes are at the sidecar path",
        std::fs::read(&path)? == EVS_NEWER,
        format!("{} bytes planted", EVS_NEWER.len()),
        at(sim),
    );
    let (history_before, _) = quarantine_names(&dir, EVS_FILE);
    sim.start_again("A").await?;
    let (state, detail, rebuilt_from) = boot_read(
        sim,
        receipt,
        group,
        "sidecar_newer_format",
        "newer: the restarted daemon serves the group and its S4 store view",
    )
    .await?;
    let untouched = std::fs::read(&path).unwrap_or_default() == EVS_NEWER;
    let (history, pending) = quarantine_names(&dir, EVS_FILE);
    let ok = state == "sidecar_newer_format"
        && detail.as_deref() == Some("version 3")
        && rebuilt_from.is_empty()
        && untouched
        && pending.is_empty()
        && history.len() == history_before.len();
    if !ok {
        receipt.cause(
            CAUSE_NEWER_TOUCHED,
            Some(format!(
                "state={state} detail={detail:?} rebuilt_from={rebuilt_from:?} \
                 untouched={untouched} history={} pending={}",
                history.len(),
                pending.len(),
            )),
            true,
            at(sim),
        );
    }
    Ok(ok)
}

async fn control_arm(sim: &mut Sim, receipt: &mut Receipt, group: &str) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let mut passed = true;
    for (form, bytes) in EVS_DAMAGE {
        passed &= damage_cycle(sim, receipt, group, form, bytes).await?;
    }
    passed &= newer_cycle(sim, receipt, group).await?;
    receipt.finish(FINAL_CONTROL, passed, at(sim));
    Ok(())
}

async fn red_arm(sim: &mut Sim, receipt: &mut Receipt, group: &str) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let mut passed = true;

    // A `.evjournal` header truncated to 7 bytes quarantines with no
    // replacement: the journal is gone, one history copy, no `.evs`
    // conjured from a journal-only fault.
    sim.stop("A", RestartMode::Crash).await?;
    let dir = sim.data_dir("A")?;
    let treekem = dir.join("treekem");
    std::fs::create_dir_all(&treekem)?;
    let journal = treekem.join(JOURNAL_FILE);
    std::fs::write(&journal, b"X0XEVJ1")?;
    sim.fabric()
        .mark("case: .evjournal header truncated to 7 bytes");
    receipt.evidence(
        "journal: the 7-byte truncated header is at the journal path",
        std::fs::read(&journal)? == b"X0XEVJ1",
        "7 bytes planted",
        at(sim),
    );
    sim.start_again("A").await?;
    let _ = sim
        .until("damaged journal quarantined", BOOT, async |_: &Sim| {
            !journal.exists()
        })
        .await;
    let (state, detail, rebuilt_from) = store_view(sim, group)
        .await?
        .context("the group status carries no revocation_eviction_store")?;
    receipt.request_delivered(
        "journal damage: the restarted daemon serves the group and its S4 store view",
        true,
        format!("store state {state}"),
        at(sim),
    );
    let (j_history, j_pending) = quarantine_names(&treekem, JOURNAL_FILE);
    let gone = !journal.exists();
    let evs_absent = !dir.join(EVS_FILE).exists();
    let ok = gone && j_pending.is_empty() && j_history.len() == 1 && evs_absent && state == "ok";
    if !ok {
        receipt.cause(
            CAUSE_NOT_QUARANTINED,
            Some(format!(
                "journal damage: gone={gone} history={} pending={} evs_absent={evs_absent} \
                 state={state} detail={detail:?} rebuilt_from={rebuilt_from:?}",
                j_history.len(),
                j_pending.len(),
            )),
            true,
            at(sim),
        );
    }
    passed &= ok;

    // A newer-layout journal is left untouched. The damaged `.evs`
    // planted in the same load anchors the read: `rebuilt` publishes only
    // after the whole load, journal scan included. Its bytes differ from
    // the resume file below, so each history copy stays identifiable.
    const ANCHOR: &[u8] = b"X0XEVICU1\0anchor";
    sim.stop("A", RestartMode::Crash).await?;
    std::fs::write(&journal, JOURNAL_NEWER)?;
    std::fs::write(dir.join(EVS_FILE), ANCHOR)?;
    sim.fabric()
        .mark("case: .evjournal v2 (newer) beside a damaged .evs anchor");
    receipt.evidence(
        "journal newer: the v2 bytes and the damaged anchor .evs are planted",
        std::fs::read(&journal)? == JOURNAL_NEWER && std::fs::read(dir.join(EVS_FILE))? == ANCHOR,
        "both files planted",
        at(sim),
    );
    sim.start_again("A").await?;
    let (state, _detail, rebuilt_from) = boot_read(
        sim,
        receipt,
        group,
        "rebuilt",
        "journal newer: the restarted daemon finished its whole load",
    )
    .await?;
    let untouched = std::fs::read(&journal).unwrap_or_default() == JOURNAL_NEWER;
    let (j_history, j_pending) = quarantine_names(&treekem, JOURNAL_FILE);
    let ok = state == "rebuilt"
        && untouched
        && j_history.len() == 1
        && j_pending.is_empty()
        && rebuilt_from.len() == 1;
    if !ok {
        receipt.cause(
            CAUSE_NEWER_TOUCHED,
            Some(format!(
                "journal newer: untouched={untouched} history={} pending={} \
                 rebuilt_from={rebuilt_from:?}",
                j_history.len(),
                j_pending.len(),
            )),
            true,
            at(sim),
        );
    }
    passed &= ok;

    // Resume at the cut point between rename and replace: a verified
    // pending copy beside the damaged `.evs`; one replacement listing
    // both transaction ids (§5a).
    sim.stop("A", RestartMode::Crash).await?;
    let damaged = b"X0XEVICT1".as_slice();
    std::fs::write(dir.join(EVS_FILE), damaged)?;
    let pending = write_pending(&dir, &[0x15; 16], damaged)?;
    sim.fabric()
        .mark("case: verified pending beside the damaged .evs");
    receipt.evidence(
        "resume: a verified pending copy and the damaged .evs are planted",
        std::fs::read(dir.join(EVS_FILE))? == damaged && pending.exists(),
        "the cut point between rename and replace",
        at(sim),
    );
    let (history_before, _) = quarantine_names(&dir, EVS_FILE);
    sim.start_again("A").await?;
    let (state, _detail, rebuilt_from) = boot_read(
        sim,
        receipt,
        group,
        "rebuilt",
        "resume beside damage: the restarted daemon finished its whole load",
    )
    .await?;
    let (history, pendings) = quarantine_names(&dir, EVS_FILE);
    let preserved = history
        .iter()
        .filter_map(|name| std::fs::read(dir.join(name)).ok())
        .filter(|kept| kept.as_slice() == damaged)
        .count();
    let (replaced, replaced_detail) = replacement_check(&dir, &rebuilt_from);
    let newer_kept = std::fs::read(&journal).unwrap_or_default() == JOURNAL_NEWER;
    let ok = state == "rebuilt"
        && rebuilt_from.len() == 2
        && rebuilt_from.contains(&hex::encode([0x15; 16]))
        && pendings.is_empty()
        && history.len() == history_before.len() + 2
        && preserved == 2
        && replaced
        && newer_kept;
    if !ok {
        receipt.cause(
            CAUSE_RESUME_LOST,
            Some(format!(
                "resume beside damage: state={state} rebuilt_from={rebuilt_from:?} history={} \
                 pending={} preserved={preserved} newer_journal_kept={newer_kept} \
                 replacement: {replaced_detail}",
                history.len(),
                pendings.len(),
            )),
            true,
            at(sim),
        );
    }
    passed &= ok;

    receipt.finish(FINAL_RESUME, passed, at(sim));
    Ok(())
}

/// Start the one node and create the group the store view hangs off.
async fn setup(sim: &mut Sim, receipt: &mut Receipt) -> Result<String> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let group = create_group(sim, "A").await?;
    let (state, _, _) = store_view(sim, &group)
        .await?
        .context("the fresh group status carries no revocation_eviction_store")?;
    receipt.evidence(
        "the private_secure group is served with its S4 store view",
        state == "ok",
        format!("store state {state}"),
        at(sim),
    );
    receipt.setup_done(at(sim));
    Ok(group)
}

async fn start(case: &str, seed: u64) -> Result<Sim> {
    let mut sim = Sim::empty(case, seed, LABELS)?;
    sim.start_node_with("A", Provision::default()).await?;
    Ok(sim)
}

/// Which arm of the case runs.
#[derive(Clone, Copy, Debug)]
enum Arm {
    /// The `.evs` damage forms and the newer layout.
    Control,
    /// The journal faults and the pending-copy resume.
    Resume,
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "#1581 / ADR 0110 S4 `s4_sidecar_lifecycle`. The 5a forms are planted on disk between \
         a crash stop and the next start; fsync-failure injection has no seam, so the cut \
         points are the on-disk states they leave.",
    );
    match start(case, seed).await {
        Ok(mut sim) => {
            let outcome = match setup(&mut sim, &mut receipt).await {
                Ok(group) => match arm {
                    Arm::Control => control_arm(&mut sim, &mut receipt, &group).await,
                    Arm::Resume => red_arm(&mut sim, &mut receipt, &group).await,
                },
                Err(error) => Err(error),
            };
            if let Err(error) = outcome {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    let final_name = match arm {
        Arm::Control => FINAL_CONTROL,
        Arm::Resume => FINAL_RESUME,
    };
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(final_name);
    }
    receipt.emit();
    receipt
}

async fn expect_green(case: &str, seed: u64, arm: Arm) -> Result<()> {
    let receipt = run(case, seed, arm).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// ADR 0110 `s4_sidecar_lifecycle`, control: every `.evs` header damage
/// form quarantines in one transaction with history and an empty
/// replacement, and a newer layout runs memory-only, untouched.
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
fn w3h_1581g_control_sidecar_lifecycle_evs_damage_rebuilds() -> Result<()> {
    super::block_on_paused(async move {
        expect_green(
            "w3h_1581g_control_sidecar_lifecycle_evs_damage_rebuilds",
            0x1581_000c,
            Arm::Control,
        )
        .await
    })
}

/// ADR 0110 `s4_sidecar_lifecycle`, the row's red arm: journal faults
/// quarantine or stay untouched as §5a says, and a resume keeps every
/// verified pending id in one replacement (GREEN with S4; the causes stay
/// for a regression).
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
fn w3h_1581g_red_sidecar_lifecycle_journal_and_pending_resume() -> Result<()> {
    super::block_on_paused(async move {
        expect_green(
            "w3h_1581g_red_sidecar_lifecycle_journal_and_pending_resume",
            0x1581_000d,
            Arm::Resume,
        )
        .await
    })
}
