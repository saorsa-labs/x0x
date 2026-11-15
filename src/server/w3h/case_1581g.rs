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
//!   no `.pending` left — and a newer-layout `.evs` (`X0XEVICT4\0`; v3 is
//!   readable since #1785, so the row's "newer" form moves to v4) runs
//!   memory-only: state `sidecar_newer_format` naming the version, the
//!   file byte-identical, no history.
//! - `red_sidecar_lifecycle_journal_and_pending_resume`: a `.evjournal`
//!   header truncated to 7 bytes quarantines with no replacement (a
//!   missing journal is the normal state); a newer-layout journal
//!   (`X0XEVJ2\0`) is left untouched; a resume that finds a verified
//!   pending copy beside a damaged `.evs` writes one replacement listing
//!   both transaction ids.
//!
//! - `control_sidecar_lifecycle_pending_resume_forms`: the §5a resume
//!   forms the other arms leave out. A verified pending copy with the
//!   `.evs` missing resumes into one replacement that lists its txid. A
//!   pending copy that fails verify with the `.evs` missing writes no
//!   replacement and shows `sidecar_quarantine_failed` with `step verify`.
//!   Three pending copies, one of which fails verify: the replacement
//!   lists the two that pass and the failed one stays pending. Once its
//!   bytes verify, the next load finalizes it as history beside the valid
//!   `.evs`, which keeps its `rebuilt_from`.
//!
//! Harness honesty: fsync-failure injection has no seam, so the §5a cut
//! points are modelled as the on-disk states they leave. The journal stem
//! is arbitrary: §5a classification is keyed on the extension, and a
//! damaged or newer journal never decodes, so its stem cannot change the
//! outcome. A boot whose only fault must change nothing (the newer
//! journal) also plants a damaged `.evs` in the same load: the store
//! state publishes only after the whole load, journal scan included, so
//! the untouched read happens after it, not after a guessed settle
//! window. A pending copy that "fails verify" holds bytes whose BLAKE3 is
//! not the `h` in its name, which is what a failed step 3 read leaves.
//! Not covered: the fsync failures at §5a steps 2, 4 and 5 themselves,
//! retention (D148), and the ADR 0094 trial-gate forms, which stay with
//! the upgrade paths.

#![cfg(test)]

use super::control::create_group;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::{
    decode_evs, parse_quarantine_pending_name, quarantine_hash_hex, quarantine_pending_name,
    EVS_FILE_NAME,
};
use anyhow::{bail, Context as _};
use std::path::{Path, PathBuf};

/// Budget for one restarted daemon to publish its store classification.
const BOOT: Duration = Duration::from_secs(60);

const EVS_FILE: &str = EVS_FILE_NAME;
/// The planted journal: any stem is equivalent (see the module honesty
/// note); `treekem/planted.evjournal`.
const JOURNAL_FILE: &str = "planted.evjournal";
/// A newer-layout `.evs` body: `X0XEVICT4\0` plus bytes this binary
/// never reads.
const EVS_NEWER: &[u8] = b"X0XEVICT4\0newer-layout";
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
const FINAL_PENDING: &str = "pending_resume_forms_meet_adr_0108_5a";
const CAUSE_PENDING_FORMS: &str = "a 5a resume form went wrong: a verified pending copy was \
                                   not covered or finalized, a failed copy was covered, \
                                   finalized or removed, or a replacement was written with no \
                                   verified copy";
const CAUSE_RESUME_LOST: &str = "the 5a resume dropped pending evidence: the replacement \
                                 does not list every verified txid, or a pending copy or the \
                                 damaged file was left behind";

const LABELS: &[&str] = &["A"];

/// The five `.evs` header damage forms the row names (ADR 0110 S4
/// validation table, `s4_sidecar_lifecycle`).
const EVS_DAMAGE: &[(&str, &[u8])] = &[
    ("missing_prefix", b"X0XEVICU1\0damaged"),
    ("truncated_header_9_bytes", b"X0XEVICT1"),
    ("version_byte_zero", b"X0XEVICT0\0damaged"),
    ("version_byte_non_digit", b"X0XEVICT?\0damaged"),
    ("missing_nul", b"X0XEVICT1Xdamaged"),
];

/// The history names in `history` that are not in `before`.
fn new_names<'a>(history: &'a [String], before: &[String]) -> Vec<&'a String> {
    history
        .iter()
        .filter(|name| !before.contains(name))
        .collect()
}

/// Whether every name in `fresh` is a §5a history copy of `bytes` under its
/// own name: `<family>.q-<txid>-<h>` with `h` over the bytes saved in that
/// file and the saved bytes equal to `bytes`. With `txids`, the parsed txids
/// are exactly `txids`, each once.
fn history_named(
    dir: &Path,
    family: &str,
    fresh: &[&String],
    bytes: &[u8],
    txids: Option<&[String]>,
) -> bool {
    let mut seen = Vec::with_capacity(fresh.len());
    for name in fresh {
        let Some((txid, h)) = parse_quarantine_pending_name(family, &format!("{name}.pending"))
        else {
            return false;
        };
        let Ok(saved) = std::fs::read(dir.join(name.as_str())) else {
            return false;
        };
        if saved != bytes || h != quarantine_hash_hex(&saved) {
            return false;
        }
        seen.push(hex::encode(txid));
    }
    match txids {
        Some(txids) => {
            let mut want = txids.to_vec();
            want.sort();
            seen.sort();
            seen == want
        }
        None => true,
    }
}

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
    let (replaced, replaced_detail) = replacement_check(&dir, &rebuilt_from);
    let new_history = new_names(&history, &history_before);
    let named = history_named(
        &dir,
        EVS_FILE,
        &new_history,
        bytes,
        Some(rebuilt_from.as_slice()),
    );
    let ok = state == "rebuilt"
        && rebuilt_from.len() == 1
        && pending.is_empty()
        && new_history.len() == 1
        && history.len() == history_before.len() + 1
        && named
        && replaced;
    if !ok {
        receipt.cause(
            CAUSE_NOT_QUARANTINED,
            Some(format!(
                "{form}: state={state} detail={detail:?} rebuilt_from={rebuilt_from:?} \
                 history={} pending={} new_history={new_history:?} named={named} \
                 replacement: {replaced_detail}",
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
    sim.fabric().mark("case: .evs holds a v4 (newer) layout");
    receipt.evidence(
        "newer: the v4 bytes are at the sidecar path",
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
        && detail.as_deref() == Some("version 4")
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
    // The history copy holds the planted 7 bytes under a well-formed §5a
    // name whose hash is over those bytes. The txid is random and published
    // nowhere (a journal fault writes no replacement), so only its form is
    // checked.
    let j_fresh: Vec<&String> = j_history.iter().collect();
    let named = history_named(&treekem, JOURNAL_FILE, &j_fresh, b"X0XEVJ1", None);
    let ok = gone
        && j_pending.is_empty()
        && j_history.len() == 1
        && named
        && evs_absent
        && state == "ok";
    if !ok {
        receipt.cause(
            CAUSE_NOT_QUARANTINED,
            Some(format!(
                "journal damage: gone={gone} history={} pending={} named={named} \
                 evs_absent={evs_absent} state={state} detail={detail:?} \
                 rebuilt_from={rebuilt_from:?}",
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
    let (replaced, replaced_detail) = replacement_check(&dir, &rebuilt_from);
    let newer_kept = std::fs::read(&journal).unwrap_or_default() == JOURNAL_NEWER;
    let new_history = new_names(&history, &history_before);
    let named = history_named(
        &dir,
        EVS_FILE,
        &new_history,
        damaged,
        Some(rebuilt_from.as_slice()),
    );
    let ok = state == "rebuilt"
        && rebuilt_from.len() == 2
        && rebuilt_from.contains(&hex::encode([0x15; 16]))
        && pendings.is_empty()
        && new_history.len() == 2
        && history.len() == history_before.len() + 2
        && named
        && replaced
        && newer_kept;
    if !ok {
        receipt.cause(
            CAUSE_RESUME_LOST,
            Some(format!(
                "resume beside damage: state={state} rebuilt_from={rebuilt_from:?} history={} \
                 pending={} new_history={new_history:?} named={named} \
                 newer_journal_kept={newer_kept} \
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

/// Plant a pending copy named for `named` that holds `bytes`: it verifies
/// only when `bytes == named`.
fn write_pending_as(dir: &Path, txid: &[u8; 16], named: &[u8], bytes: &[u8]) -> Result<PathBuf> {
    let path = dir.join(quarantine_pending_name(EVS_FILE, txid, named));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// The pending-resume forms (ADR 0108 §5a "Resume at startup" and its
/// test list).
async fn pending_arm(sim: &mut Sim, receipt: &mut Receipt, group: &str) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let mut passed = true;
    let mut fail = |receipt: &mut Receipt, sim: &Sim, ok: bool, detail: String| {
        if !ok {
            receipt.cause(CAUSE_PENDING_FORMS, Some(detail), true, at(sim));
        }
        passed &= ok;
    };

    // (1) The `.evs` missing, one verified pending copy: one replacement
    // that lists its txid; the copy becomes history.
    sim.stop("A", RestartMode::Crash).await?;
    // The harness reads a node's files only while it is stopped.
    let dir = sim.data_dir("A")?;
    let evs = dir.join(EVS_FILE);
    let one = b"X0XEVICU1\0missing-file".as_slice();
    if evs.exists() {
        std::fs::remove_file(&evs)?;
    }
    let copy = write_pending(&dir, &[0x16; 16], one)?;
    sim.fabric()
        .mark("case: .evs missing, one verified pending copy");
    receipt.evidence(
        "missing: no .evs and one verified pending copy",
        !evs.exists() && copy.exists(),
        "planted",
        at(sim),
    );
    let (history_before, _) = quarantine_names(&dir, EVS_FILE);
    sim.start_again("A").await?;
    let (state, detail, rebuilt_from) = boot_read(
        sim,
        receipt,
        group,
        "rebuilt",
        "missing: the restarted daemon serves the group and its S4 store view",
    )
    .await?;
    let (history, pendings) = quarantine_names(&dir, EVS_FILE);
    let (replaced, replaced_detail) = replacement_check(&dir, &rebuilt_from);
    let new_history = new_names(&history, &history_before);
    let named = history_named(
        &dir,
        EVS_FILE,
        &new_history,
        one,
        Some(&[hex::encode([0x16; 16])][..]),
    );
    let ok = state == "rebuilt"
        && rebuilt_from == [hex::encode([0x16; 16])]
        && pendings.is_empty()
        && new_history.len() == 1
        && named
        && replaced;
    fail(
        receipt,
        sim,
        ok,
        format!(
            "missing: state={state} detail={detail:?} rebuilt_from={rebuilt_from:?} \
             new_history={new_history:?} pending={pendings:?} named={named} \
             replacement: {replaced_detail}"
        ),
    );

    // (2) The `.evs` missing and the only pending copy fails verify: no
    // replacement, `sidecar_quarantine_failed {step verify}`, the copy
    // kept.
    sim.stop("A", RestartMode::Crash).await?;
    std::fs::remove_file(&evs)?;
    let good = b"X0XEVICU1\0verify-later".as_slice();
    let bad = write_pending_as(&dir, &[0x17; 16], good, b"X0XEVICU1\0bit-flipped!")?;
    sim.fabric()
        .mark("case: .evs missing, the only pending copy fails verify");
    receipt.evidence(
        "verify: no .evs and one pending copy whose bytes do not verify",
        !evs.exists() && bad.exists(),
        "planted",
        at(sim),
    );
    sim.start_again("A").await?;
    let (state, detail, rebuilt_from) = boot_read(
        sim,
        receipt,
        group,
        "sidecar_quarantine_failed",
        "verify: the restarted daemon serves the group and its S4 store view",
    )
    .await?;
    let ok = state == "sidecar_quarantine_failed"
        && detail.as_deref() == Some("step verify")
        && !evs.exists()
        && bad.exists();
    fail(
        receipt,
        sim,
        ok,
        format!(
            "verify: state={state} detail={detail:?} rebuilt_from={rebuilt_from:?} \
             evs_exists={} failed_copy_kept={}",
            evs.exists(),
            bad.exists()
        ),
    );

    // (3) Three pending copies, one of which fails verify (the copy from
    // (2)): the replacement lists the two that pass; the failed one stays
    // pending.
    sim.stop("A", RestartMode::Crash).await?;
    let two = b"X0XEVICU1\0second".as_slice();
    let three = b"X0XEVICU1\0third".as_slice();
    // The failing copy from (2) stays pending and no `.evs` exists. A
    // regression in (2) can change both; the step restores its own
    // premise so such a regression shows as RED here too.
    if evs.exists() {
        std::fs::remove_file(&evs)?;
    }
    if !bad.exists() {
        write_pending_as(&dir, &[0x17; 16], good, b"X0XEVICU1\0bit-flipped!")?;
    }
    write_pending(&dir, &[0x18; 16], two)?;
    write_pending(&dir, &[0x19; 16], three)?;
    sim.fabric()
        .mark("case: three pending copies, one fails verify");
    let (history_before, pending_before) = quarantine_names(&dir, EVS_FILE);
    receipt.evidence(
        "three: no .evs and three pending copies",
        !evs.exists() && pending_before.len() == 3,
        format!("pending {pending_before:?}"),
        at(sim),
    );
    sim.start_again("A").await?;
    let (state, detail, rebuilt_from) = boot_read(
        sim,
        receipt,
        group,
        "rebuilt",
        "three: the restarted daemon serves the group and its S4 store view",
    )
    .await?;
    let passing = [hex::encode([0x18; 16]), hex::encode([0x19; 16])];
    let (history, pendings) = quarantine_names(&dir, EVS_FILE);
    let (replaced, replaced_detail) = replacement_check(&dir, &rebuilt_from);
    let new_history = new_names(&history, &history_before);
    let ok = state == "rebuilt"
        && rebuilt_from == passing
        && pendings.len() == 1
        && bad.exists()
        && new_history.len() == 2
        && replaced;
    fail(
        receipt,
        sim,
        ok,
        format!(
            "three: state={state} detail={detail:?} rebuilt_from={rebuilt_from:?} \
             new_history={new_history:?} pending={pendings:?} replacement: {replaced_detail}"
        ),
    );

    // (4) The failed copy's bytes now verify: the next load finalizes it
    // as history beside the valid `.evs`, which keeps its `rebuilt_from`.
    sim.stop("A", RestartMode::Crash).await?;
    std::fs::write(&bad, good)?;
    sim.fabric()
        .mark("case: the failed pending copy now verifies");
    let (history_before, _) = quarantine_names(&dir, EVS_FILE);
    sim.start_again("A").await?;
    let _ = sim
        .until("the repaired copy is finalized", BOOT, async |_: &Sim| {
            !bad.exists()
        })
        .await;
    let (state, detail, rebuilt_from) = store_view(sim, group)
        .await?
        .context("the group status carries no revocation_eviction_store")?;
    receipt.request_delivered(
        "finalize: the restarted daemon serves the group and its S4 store view",
        true,
        format!("store state {state}"),
        at(sim),
    );
    let (history, pendings) = quarantine_names(&dir, EVS_FILE);
    let (kept, kept_detail) = replacement_check(&dir, &passing);
    let new_history = new_names(&history, &history_before);
    let named = history_named(
        &dir,
        EVS_FILE,
        &new_history,
        good,
        Some(&[hex::encode([0x17; 16])][..]),
    );
    let ok =
        pendings.is_empty() && new_history.len() == 1 && named && kept && rebuilt_from == passing;
    fail(
        receipt,
        sim,
        ok,
        format!(
            "finalize: state={state} detail={detail:?} rebuilt_from={rebuilt_from:?} \
             new_history={new_history:?} pending={pendings:?} named={named} \
             .evs: {kept_detail}"
        ),
    );

    receipt.finish(FINAL_PENDING, passed, at(sim));
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
    /// The pending-resume forms.
    Pending,
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
                    Arm::Pending => pending_arm(&mut sim, &mut receipt, &group).await,
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
        Arm::Pending => FINAL_PENDING,
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

/// ADR 0110 `s4_sidecar_lifecycle`, control: the §5a resume forms with the
/// `.evs` missing, a pending copy that fails verify, and three pending
/// copies of which one fails verify and is finalized at the next load.
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
fn w3h_1581g_control_sidecar_lifecycle_pending_resume_forms() -> Result<()> {
    super::block_on_paused(async move {
        expect_green(
            "w3h_1581g_control_sidecar_lifecycle_pending_resume_forms",
            0x1581_000e,
            Arm::Pending,
        )
        .await
    })
}
