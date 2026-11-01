//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_sidecar_rebuild`): A, B, C with pending self-leave work on A. A
//! holds the open row for B's self-leave (the row cannot seal: A sits
//! inside its own boot head gate, so the restart sync wait holds it and
//! no fault rule is needed), the `.evs` body is damaged on disk while A
//! is stopped, and A restarts. With S4 merged (#1508) the arm expects
//! the ADR behaviour (GREEN): the damaged file is quarantined with one
//! history copy and an empty replacement written
//! (`rebuilt_from` names the quarantine transaction), the rebuilt store
//! re-derives the open row from the verified chain in its first pass —
//! the row shows the typed `rebuilding_obligation_store`, then the
//! typed `waiting_for_head_sync` until the new restart sync wait
//! passes — and the designated A completes the exclusion with exactly
//! one rotation (`result_epoch` e0 + 1, no second rekey).
//!
//! The second arm is the row's newer-file variant, read with ADR 0110
//! line 378 ("Memory-only durability"): a `X0XEVICT3\0` sidecar (v2 is
//! readable since #1508) runs memory-only, and a new self-leave
//! trigger — durable on the verified chain — is sealed without the
//! `waiting_for_durable_intake` wait (GREEN on main). The arm also
//! guards the other side of line 378: if the wait ever appears for a
//! chain-durable trigger, the arm fails with
//! [`CAUSE_DURABLE_WAIT_SHOWN`]. Line 451's "a new trigger whose
//! evidence is not yet in the revocation store" names the other kind —
//! a trigger with no durable record anywhere — and S4 derives no such
//! trigger today, so that variant is not drivable and is recorded by
//! name below (the FOR ENGINEER question on the PR body asks David to
//! confirm this reading of line 451 against line 378).
//!
//! Harness honesty:
//!
//! - The fsync cut points of ADR 0108 §5a have no injection seam; the
//!   case models the damage as the on-disk bytes it leaves (a valid v2
//!   header over a body that cannot decode), the same on-disk shape
//!   the header-damage forms of the `s4_sidecar_lifecycle` row use.
//! - The trigger is a self-leave, not a revocation: a loaded
//!   revocation record stores a `Notify` permit at boot
//!   (`RevocationIntake::note_loaded`), which wakes a second worker
//!   pass at once and would overwrite the stored
//!   `rebuilding_obligation_store` wait before the API can read it. A
//!   self-leave derives from the verified chain with no intake wake,
//!   so the pass-1 wait stays readable for a whole worker tick
//!   ([`S4_WORKER_TICK`], 1 s). Nothing enforces that window: a boot
//!   path that called `request_reconcile` would end it early. The
//!   paused clock and the fixed seed keep today's boot quiet, so the
//!   reading is deterministic; a boot wake introduced later would fail
//!   the arm with [`CAUSE_NO_REBUILDING`] and this note explains why.
//! - The row's "restart A with no holder of the head online" variant
//!   is not driven: after both other members leave, no active member
//!   remains to serve A's catch-up, so the leave that opens the row
//!   can never reach the restarted A (left members are not catch-up
//!   candidates). Recorded by name below.
//!
//! Not covered, by name: line 451's new trigger with no durable record
//! anywhere (S4 derives no such trigger today — every kind is durable
//! in the revocation store, on the verified chain or as a committed
//! certificate, per the §5 comment in `revocation_eviction.rs`); the
//! rebuilt row's fresh T_obs (the budget restart at re-derivation —
//! the case proves the one-rotation completion but not the reset
//! timing); the
//! `.evjournal` damage between its prepare and the legacy commit (with
//! and without the landed commit); the `.evs` case inside an ADR 0094
//! trial; the no-holder restart form; the self-revocation and
//! certificate-expiry trigger forms; the fsync failures at §5a steps
//! 2, 4 and 5; and the row's expiry-only "derivable set" member.
//! Receipts use `w3h.receipt/1`.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::{decode_evs, EVS_FILE_NAME};
use anyhow::{ensure, Context as _};
use std::path::{Path, PathBuf};

/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for the leave and its record to reach its holders.
const EVIDENCE: Duration = Duration::from_secs(60);
/// Budget for a restart's store classification and row re-derivation.
const BOOT: Duration = Duration::from_secs(60);
/// Budget for the rebuilt row to complete: the restart sync wait plus
/// the completion bound, with slack.
const COMPLETE: Duration = Duration::from_secs(60);
/// The case waits this long after the completion and re-reads, so a
/// second rotation (another epoch step) is seen.
const SETTLE: Duration = Duration::from_secs(10);
/// How long the newer-file arm watches the new trigger's wait under
/// the newer-format sidecar.
const WATCH: Duration = Duration::from_secs(45);

/// A `.evs` whose v2 header is valid but whose body cannot decode: the
/// row's "damage the `.evs` body" form.
const DAMAGED_BODY: &[u8] = b"X0XEVICT2\0not a postcard body";
/// The newer `.evs` layout this binary must leave untouched (#1508
/// reads v2, so v3 is the newer form).
const NEWER_EVS: &[u8] = b"X0XEVICT3\0future layout";

const FINAL_CONTROL: &str = "the_rebuilt_store_rederives_the_open_row_and_completes_one_rotation";
const FINAL_NEWER: &str = "the_memory_only_sidecar_seals_the_chain_durable_trigger";
const CAUSE_NO_REBUILD: &str = "the damaged .evs body was not quarantined and rebuilt: the store \
                                state, the history copy, the pending copies or the replacement's \
                                rebuilt_from did not meet ADR 0108 §5a";
const CAUSE_NO_REBUILDING: &str = "no typed rebuilding_obligation_store: the rebuilt row's first \
                                   passes showed no rebuild wait";
const CAUSE_NO_HEAD_SYNC: &str = "no typed waiting_for_head_sync: the rebuilt row's waits never \
                                  named the head while the restart sync wait held it";
const CAUSE_ROW_LOST: &str = "the rebuilt store did not re-derive and complete the open row: A's \
                              row for B never completed, or the survivors never reached the \
                              single exclusion";
const CAUSE_SECOND_ROTATION: &str = "the rebuilt completion was not exactly one rotation: the \
                                     survivors moved past e0 + 1, or the row's result_epoch is \
                                     not the survivors' epoch";
const CAUSE_NEWER_MISCLASSIFIED: &str =
    "the newer-format .evs was not classified memory-only: the \
                                         store did not publish sidecar_newer_format with the \
                                         version detail";
const CAUSE_NEWER_TOUCHED: &str = "the newer-format .evs was rewritten: ADR 0108 §5a leaves a \
                                   newer layout untouched, byte-identical";
const CAUSE_DURABLE_WAIT_SHOWN: &str = "waiting_for_durable_intake shown for a chain-durable \
                                        self-leave under a memory-only sidecar: ADR 0110's \
                                        Memory-only durability rule (line 378) seals it without \
                                        the intake wait";
const CAUSE_NEWER_ROW_INCOMPLETE: &str = "the chain-durable trigger under the newer file did not \
                                          complete its one exclusion: the row never completed, \
                                          or A's epoch is not e0 + 1";

/// `label`'s view of `group`; `None` when it holds no record of it.
#[derive(Debug, Clone)]
struct View {
    state_revision: u64,
    lists_b: bool,
    quarantined: bool,
    epoch: Option<u64>,
    leaves: Option<u32>,
    head_committed_by: Option<String>,
}

impl View {
    fn describe(&self) -> String {
        format!(
            "state={} lists_b={} epoch={:?} leaves={:?} quarantined={} head_committed_by={:?}",
            self.state_revision,
            self.lists_b,
            self.epoch,
            self.leaves,
            self.quarantined,
            self.head_committed_by
        )
    }
}

async fn try_view_now(sim: &Sim, label: &str, group: &str, b_hex: &str) -> Result<Option<View>> {
    let state = sim.state(label)?;
    let (key, view) = {
        let groups = state.named_groups.read().await;
        let Some((key, info)) = crate::server::resolve_group_entry_locked(&groups, group) else {
            return Ok(None);
        };
        let view = View {
            state_revision: info.state_revision,
            lists_b: info
                .active_members()
                .any(|member| member.agent_id.eq_ignore_ascii_case(b_hex)),
            quarantined: info.fork_quarantine.is_some(),
            epoch: None,
            leaves: None,
            head_committed_by: info
                .commit_log
                .iter()
                .rev()
                .find(|retained| retained.commit.revision == info.state_revision)
                .map(|retained| retained.commit.committed_by.to_ascii_lowercase()),
        };
        (key.to_string(), view)
    };
    let live = state.treekem_groups.read().await.get(&key).cloned();
    let Some(live) = live else {
        return Ok(Some(view));
    };
    let guard = live.lock().await;
    Ok(Some(View {
        epoch: Some(guard.epoch()),
        leaves: Some(guard.member_count()),
        ..view
    }))
}

async fn view_now(sim: &Sim, label: &str, group: &str, b_hex: &str) -> Result<View> {
    try_view_now(sim, label, group, b_hex)
        .await?
        .with_context(|| format!("{label} has no record of the group"))
}

/// A invites `member`; A lists it and it reports itself active.
async fn seat(sim: &Sim, member: &str, group: &str) -> Result<()> {
    let link = invite(sim, "A", group).await?;
    join(sim, member, &link).await?;
    let hex = sim.agent_hex(member)?;
    sim.until(&format!("{member} seated"), SETUP, async |s: &Sim| {
        let listed = members(s, "A", group)
            .await
            .is_ok_and(|listed| listed.contains(&hex));
        listed
            && membership_state(s, member, group)
                .await
                .ok()
                .flatten()
                .as_deref()
                == Some("active")
    })
    .await
}

/// Every label holds A's state revision and TreeKEM epoch.
async fn settled(sim: &Sim, labels: &[&str], group: &str, b_hex: &str) -> Result<(u64, u64, u32)> {
    let (mut revision, mut epoch, mut leaves) = (None, None, None);
    sim.until(
        "every node holds A's head and epoch",
        SETUP,
        async |s: &Sim| {
            let Ok(authority) = view_now(s, "A", group, b_hex).await else {
                return false;
            };
            let Some(head_epoch) = authority.epoch else {
                return false;
            };
            for label in labels {
                match view_now(s, label, group, b_hex).await {
                    Ok(seen)
                        if seen.state_revision == authority.state_revision
                            && seen.epoch == authority.epoch => {}
                    _ => return false,
                }
            }
            revision = Some(authority.state_revision);
            epoch = Some(head_epoch);
            leaves = authority.leaves;
            true
        },
    )
    .await?;
    Ok((
        revision.context("no revision observed")?,
        epoch.context("no epoch observed")?,
        leaves.context("A has no live TreeKEM group")?,
    ))
}

/// Whether `label` has a live fabric link to `other`.
async fn connected_to(sim: &Sim, label: &str, other: &str) -> bool {
    let (Ok(state), Ok(other)) = (sim.state(label), sim.peer(other)) else {
        return false;
    };
    match state.agent.network() {
        Some(network) => network.connected_peers().await.contains(&other),
        None => false,
    }
}

/// `label`'s public S4 row for `target` in `group` (the
/// `revocation_evictions` entry of `GET /groups/:id`), or `None` when
/// the status has no row for the target.
async fn s4_row(
    sim: &Sim,
    label: &str,
    group: &str,
    target_hex: &str,
) -> Result<Option<serde_json::Value>> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(body["revocation_evictions"].as_array().and_then(|rows| {
        rows.iter()
            .find(|row| row["target"].as_str() == Some(target_hex))
            .cloned()
    }))
}

/// `label`'s public sidecar store view: `(state, detail, rebuilt_from)`.
async fn store_view(
    sim: &Sim,
    label: &str,
    group: &str,
) -> Result<(String, Option<String>, Vec<String>)> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    let store = &body["revocation_eviction_store"];
    Ok((
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
    ))
}

/// The `.evs` history and pending copy names in `dir` (the
/// `<evs>.q-…` family), split into `(history, pending)`.
fn quarantine_names(dir: &Path) -> (Vec<String>, Vec<String>) {
    let mut history = Vec::new();
    let mut pending = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (history, pending);
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        if name.starts_with(&format!("{EVS_FILE_NAME}.q-")) {
            if name.ends_with(".pending") {
                pending.push(name);
            } else {
                history.push(name);
            }
        }
    }
    (history, pending)
}

/// A's `.evs` path while A runs (the harness's state read, not the
/// stopped-node `data_dir` helper).
fn evs_path(sim: &Sim, label: &str) -> Result<PathBuf> {
    Ok(sim.state(label)?.data_dir.join(EVS_FILE_NAME))
}

/// Decode A's `.evs`; `None` when the file does not exist.
fn read_evs(sim: &Sim, label: &str) -> Result<Option<crate::groups::eviction::EvsBodyV1>> {
    let path = evs_path(sim, label)?;
    match std::fs::read(&path) {
        Ok(bytes) => decode_evs(&bytes)
            .map(Some)
            .map_err(|error| anyhow::anyhow!("{label} .evs: {error:?}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Record one desired-behaviour check: a pass is evidence, a failure
/// becomes the named cause. The premise stages stay `evidence` however
/// the arm ends, so a neutralisation is RED with every premise still
/// ok, not INFRA. Returns whether the check held.
fn record_check(
    receipt: &mut Receipt,
    name: &str,
    ok: bool,
    cause: &str,
    observed: Option<String>,
    detail: String,
    at_us: u128,
) -> bool {
    if ok {
        receipt.evidence(name, true, detail, at_us);
    } else {
        receipt.cause(cause, observed, true, at_us);
    }
    ok
}

/// The survivors' views as one readable line.
fn describe_views(views: &[(&str, View)]) -> String {
    views
        .iter()
        .map(|(label, seen)| format!("{label}: {}", seen.describe()))
        .collect::<Vec<_>>()
        .join("; ")
}

/// B's self-leave: the public `DELETE /groups/:id` from B.
async fn b_leaves(sim: &Sim, group: &str) -> Result<(StatusCode, serde_json::Value)> {
    sim.api("B", Method::DELETE, &format!("/groups/{group}"), None)
        .await
}

/// Restart A and wait until it links to `peer` again.
async fn restart_a(sim: &mut Sim, peer: &str) -> Result<()> {
    sim.start_again("A").await?;
    sim.until("A reconnects", SETUP, async |s: &Sim| {
        connected_to(s, "A", peer).await
    })
    .await
}

/// The shared setup: mesh, the ordinary `private_secure` group A
/// creates, `member_labels` seated, settled. Returns
/// `(group, b_hex, r0, e0, leaves0)`.
async fn setup(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
) -> Result<(String, String, u64, u64, u32)> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, labels).await?;
    let group = create_group(sim, "A").await?;
    for member in labels.iter().filter(|label| **label != "A") {
        seat(sim, member, &group).await?;
    }
    let b_hex = sim.agent_hex("B")?;
    let (r0, e0, leaves0) = settled(sim, labels, &group, &b_hex).await?;
    receipt.evidence(
        "treekem_group_settled_with_every_member_seated",
        true,
        format!("r0={r0} e0={e0} leaves0={leaves0} members={}", labels.len()),
        at(sim),
    );
    receipt.setup_done(at(sim));
    Ok((group, b_hex, r0, e0, leaves0))
}

/// Open B's self-leave row on A while A sits inside its fresh boot head
/// gate, so the row stays `pending` with the typed
/// `waiting_for_head_sync` and cannot seal.
async fn open_held_row(
    sim: &mut Sim,
    receipt: &mut Receipt,
    group: &str,
    b_hex: &str,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    // A restarts first: the fresh boot restart sync wait is the hold,
    // so the leave lands well inside it.
    sim.stop("A", RestartMode::Crash).await?;
    sim.fabric()
        .mark("case: A crash-stopped for a fresh boot head gate");
    restart_a(sim, "C").await?;

    let (status, body) = b_leaves(sim, group).await?;
    ensure!(status.is_success(), "B leaves: {status} {body}");
    receipt.request_delivered(
        "b_self_leave_api_call",
        true,
        format!("DELETE /groups/{group} from B: {status}"),
        at(sim),
    );
    sim.until("A and C hold B's leave", EVIDENCE, async |s: &Sim| {
        try_view_now(s, "A", group, b_hex)
            .await
            .is_ok_and(|seen| seen.is_some_and(|seen| !seen.lists_b))
            && try_view_now(s, "C", group, b_hex)
                .await
                .is_ok_and(|seen| seen.is_some_and(|seen| !seen.lists_b))
    })
    .await?;
    sim.until(
        "A's public S4 row for B waits for the head",
        BOOT,
        async |s: &Sim| {
            s4_row(s, "A", group, b_hex).await.is_ok_and(|row| {
                row.as_ref().is_some_and(|row| {
                    row["waiting"]["cause"].as_str() == Some("waiting_for_head_sync")
                })
            })
        },
    )
    .await?;
    let row = s4_row(sim, "A", group, b_hex)
        .await?
        .context("A's row for B")?;
    receipt.evidence(
        "a_holds_an_open_row_for_b_held_by_the_boot_head_gate",
        row["phase"].as_str() == Some("pending"),
        format!("A's public S4 row for B while A is inside its restart sync wait: {row}"),
        at(sim),
    );
    let durable_row = read_evs(sim, "A")?;
    let target_bytes: [u8; 32] = hex::decode(b_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .context("decode B's agent id")?;
    receipt.evidence(
        "the_open_row_is_durable_in_the_evs",
        durable_row
            .as_ref()
            .is_some_and(|body| body.rows.iter().any(|row| row.target == target_bytes)),
        format!(
            "A's .evs holds {} row(s) before the damage; T_obs for B: {:?}",
            durable_row.as_ref().map_or(0, |body| body.rows.len()),
            durable_row.as_ref().and_then(|body| {
                body.rows
                    .iter()
                    .find(|row| row.target == target_bytes)
                    .map(|row| row.observed_at_unix_ms)
            })
        ),
        at(sim),
    );
    Ok(())
}

/// The control arm body: damage the `.evs` body while A is stopped with
/// the open row, then watch the rebuild re-derive it and complete.
async fn control_arm(
    sim: &mut Sim,
    receipt: &mut Receipt,
    group: &str,
    b_hex: &str,
    e0: u64,
    leaves0: u32,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let mut passed = true;
    open_held_row(sim, receipt, group, b_hex).await?;

    // The damage: the row's open state is on disk, A is stopped, and
    // the bytes cannot decode as a body.
    let a_view = view_now(sim, "A", group, b_hex).await?;
    let a_epoch_at_crash = a_view.epoch;
    sim.stop("A", RestartMode::Crash).await?;
    sim.fabric()
        .mark("case: A crash-stopped with the open row durable");
    let dir = sim.data_dir("A")?;
    let (history_before, pending_before) = quarantine_names(&dir);
    let path = dir.join(EVS_FILE_NAME);
    let pre_damage = std::fs::read(&path).context("A's .evs at the crash")?;
    std::fs::write(&path, DAMAGED_BODY).with_context(|| format!("damage {}", path.display()))?;
    sim.fabric().mark("case: .evs body damaged on disk");
    receipt.evidence(
        "the_damaged_bytes_are_at_the_sidecar_path",
        std::fs::read(&path)? == DAMAGED_BODY,
        format!(
            "{} bytes of real store overwritten by the {}-byte body-damage form; {} history, {} \
             pending copies before the restart",
            pre_damage.len(),
            DAMAGED_BODY.len(),
            history_before.len(),
            pending_before.len()
        ),
        at(sim),
    );

    // The restart: the load quarantines the damaged file, writes the
    // empty replacement and re-derives the row in its first pass.
    restart_a(sim, "C").await?;
    let _ = sim
        .until(
            "the store publishes the rebuild classification",
            BOOT,
            async |s: &Sim| {
                store_view(s, "A", group)
                    .await
                    .is_ok_and(|(state, _, _)| state == "rebuilt")
            },
        )
        .await;
    let (state, detail, rebuilt_from) = store_view(sim, "A", group).await?;
    let (history_after, pending_after) = quarantine_names(&dir);
    let replacement = read_evs(sim, "A")?;
    // The one new history copy must name the same txid the store
    // publishes (and the replacement must carry it too).
    let new_history = history_after
        .iter()
        .filter(|name| !history_before.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let replacement_txid = replacement
        .as_ref()
        .and_then(|body| body.rebuilt_from.first().map(hex::encode));
    let rebuilt_ok = state == "rebuilt"
        && rebuilt_from.len() == 1
        && history_after.len() == history_before.len() + 1
        && pending_after.is_empty()
        && new_history.len() == 1
        && new_history[0].contains(&format!(".q-{}-", rebuilt_from[0]))
        && replacement_txid.as_deref() == rebuilt_from.first().map(String::as_str);
    passed &= record_check(
        receipt,
        "the_damaged_body_is_quarantined_and_rebuilt",
        rebuilt_ok,
        CAUSE_NO_REBUILD,
        Some(format!("state={state} detail={detail:?}")),
        format!(
            "state={state:?} detail={detail:?} rebuilt_from={rebuilt_from:?}; history {} -> {}, \
             pending {:?}; the new history copy: {new_history:?}; the replacement's txid: \
             {replacement_txid:?}",
            history_before.len(),
            history_after.len(),
            pending_after,
        ),
        at(sim),
    );

    // The re-derived row's first passes show the typed rebuild wait
    // (one worker tick; the self-leave trigger derives with no intake
    // wake, so the stored wait is readable).
    let mut rebuilding_seen = false;
    let watched = sim
        .until(
            "the rebuilt row shows rebuilding_obligation_store",
            Duration::from_secs(5),
            async |s: &Sim| {
                rebuilding_seen |= s4_row(s, "A", group, b_hex)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|row| {
                        row["waiting"]["cause"].as_str() == Some("rebuilding_obligation_store")
                    });
                rebuilding_seen
            },
        )
        .await;
    if let Err(error) = watched {
        if !expired(&error) {
            return Err(error);
        }
    }
    passed &= record_check(
        receipt,
        "the_re_derived_row_names_rebuilding_obligation_store",
        rebuilding_seen,
        CAUSE_NO_REBUILDING,
        Some("no rebuilding wait observed across the first worker passes".to_string()),
        "the row's stored wait during the first worker passes".to_string(),
        at(sim),
    );

    // The row then waits for the new head round — the typed
    // `waiting_for_head_sync` from the passes after the rebuild flag
    // cleared until the new restart sync wait passes.
    let mut head_sync_seen = false;
    let head_watch = sim
        .until(
            "the rebuilt row shows waiting_for_head_sync",
            Duration::from_secs(5),
            async |s: &Sim| {
                head_sync_seen |= s4_row(s, "A", group, b_hex)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|row| {
                        row["waiting"]["cause"].as_str() == Some("waiting_for_head_sync")
                    });
                head_sync_seen
            },
        )
        .await;
    if let Err(error) = head_watch {
        if !expired(&error) {
            return Err(error);
        }
    }
    passed &= record_check(
        receipt,
        "the_rebuilt_row_names_waiting_for_head_sync",
        head_sync_seen,
        CAUSE_NO_HEAD_SYNC,
        Some("no head-sync wait observed while the restart wait held the row".to_string()),
        "the row's stored wait through the restart sync window".to_string(),
        at(sim),
    );

    // The row then completes with one rotation.
    let _ = sim
        .until("the rebuilt row completes", COMPLETE, async |s: &Sim| {
            s4_row(s, "A", group, b_hex)
                .await
                .ok()
                .flatten()
                .is_some_and(|row| row["phase"].as_str() == Some("complete"))
        })
        .await;
    let row = s4_row(sim, "A", group, b_hex)
        .await?
        .context("A's row for B")?;
    let result_epoch = row["result_epoch"].as_u64();
    let survivors = ["A", "C"];
    let mut views = Vec::new();
    for label in survivors {
        views.push((label, view_now(sim, label, group, b_hex).await?));
    }
    let a_hex = sim.agent_hex("A")?;
    let one_rotation = result_epoch == Some(e0 + 1)
        && views.iter().all(|(_, seen)| {
            seen.epoch == Some(e0 + 1)
                && seen.leaves == Some(leaves0 - 1)
                && !seen.lists_b
                && !seen.quarantined
                && seen.head_committed_by.as_deref() == Some(a_hex.as_str())
        });
    let row_line = format!(
        "A's epoch at the crash: {a_epoch_at_crash:?}; the row: phase={} result_epoch={:?}; {}",
        row["phase"].as_str().unwrap_or_default(),
        result_epoch,
        describe_views(&views)
    );
    passed &= record_check(
        receipt,
        "the_rebuilt_row_completes_with_exactly_one_rotation",
        one_rotation,
        CAUSE_ROW_LOST,
        Some(format!(
            "phase={} result_epoch={result_epoch:?}",
            row["phase"].as_str().unwrap_or_default()
        )),
        row_line,
        at(sim),
    );

    // No second rotation follows the rebuilt completion.
    sim.within(
        "the settle window after the completion",
        SETTLE + secs(1),
        async {
            tokio::time::sleep(SETTLE).await;
        },
    )
    .await?;
    let mut settled_again = Vec::new();
    for label in survivors {
        settled_again.push((label, view_now(sim, label, group, b_hex).await?));
    }
    let row_again = s4_row(sim, "A", group, b_hex).await?;
    let still_one = settled_again
        .iter()
        .all(|(_, seen)| seen.epoch == Some(e0 + 1))
        && row_again
            .as_ref()
            .is_some_and(|row| row["phase"].as_str() == Some("complete"));
    passed &= record_check(
        receipt,
        "no_second_rotation_after_the_rebuilt_completion",
        still_one,
        CAUSE_SECOND_ROTATION,
        None,
        format!(
            "{} after {SETTLE:?}; A's row: {}",
            describe_views(&settled_again),
            row_again
                .as_ref()
                .map(|row| row["phase"].as_str().unwrap_or_default().to_string())
                .unwrap_or_else(|| "no row".to_string())
        ),
        at(sim),
    );
    receipt.finish(FINAL_CONTROL, passed, at(sim));
    Ok(())
}

/// The newer-file arm body: the newer-format `.evs` runs memory-only,
/// a new self-leave trigger — chain-durable — opens a row and is
/// sealed without the `waiting_for_durable_intake` wait (ADR 0110
/// line 378, "Memory-only durability"), the file stays untouched and
/// the exclusion completes with one rotation.
async fn newer_file_arm(
    sim: &mut Sim,
    receipt: &mut Receipt,
    group: &str,
    b_hex: &str,
    e0: u64,
    leaves0: u32,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let mut passed = true;
    sim.stop("A", RestartMode::Crash).await?;
    sim.fabric()
        .mark("case: A stopped; the newer-format .evs is planted");
    let dir = sim.data_dir("A")?;
    let path = dir.join(EVS_FILE_NAME);
    std::fs::write(&path, NEWER_EVS).with_context(|| format!("plant {}", path.display()))?;
    receipt.evidence(
        "the_newer_format_bytes_are_at_the_sidecar_path",
        std::fs::read(&path)? == NEWER_EVS,
        format!("the {NEWER_EVS:?} form; v2 is readable since #1508"),
        at(sim),
    );
    restart_a(sim, "B").await?;

    let _ = sim
        .until(
            "the store publishes the newer-format classification",
            BOOT,
            async |s: &Sim| {
                store_view(s, "A", group)
                    .await
                    .is_ok_and(|(state, _, _)| state == "sidecar_newer_format")
            },
        )
        .await;
    let (state, detail, _) = store_view(sim, "A", group).await?;
    passed &= record_check(
        receipt,
        "the_sidecar_runs_memory_only_newer_format",
        state == "sidecar_newer_format" && detail.as_deref() == Some("version 3"),
        CAUSE_NEWER_MISCLASSIFIED,
        Some(format!("state={state} detail={detail:?}")),
        format!("state={state:?} detail={detail:?}; the file must stay untouched"),
        at(sim),
    );

    // The new trigger: B's self-leave opens a row under the newer file.
    let (status, body) = b_leaves(sim, group).await?;
    ensure!(status.is_success(), "B leaves: {status} {body}");
    receipt.request_delivered(
        "b_self_leave_api_call_under_the_newer_file",
        true,
        format!("DELETE /groups/{group} from B: {status}"),
        at(sim),
    );
    let mut row_pending = false;
    let row_opened = sim
        .until("the new trigger opens a row on A", BOOT, async |s: &Sim| {
            row_pending |= s4_row(s, "A", group, b_hex)
                .await
                .ok()
                .flatten()
                .is_some_and(|row| row["phase"].as_str() == Some("pending"));
            row_pending
        })
        .await;
    if let Err(error) = row_opened {
        if !expired(&error) {
            return Err(error);
        }
    }
    receipt.evidence(
        "the_new_trigger_opens_a_row_under_the_newer_file",
        row_pending,
        "A's public S4 row for B reached `pending` under the memory-only store".to_string(),
        at(sim),
    );

    // Watch the row's wait through the whole window: every cause it
    // names, until the row completes or the budget ends.
    let mut causes = std::collections::BTreeSet::new();
    let mut final_phase = String::new();
    let watched = sim
        .until(
            "the row completes or the watch ends",
            WATCH,
            async |s: &Sim| {
                if let Ok(Some(row)) = s4_row(s, "A", group, b_hex).await {
                    if let Some(cause) = row["waiting"]["cause"].as_str() {
                        causes.insert(cause.to_string());
                    }
                    final_phase = row["phase"].as_str().unwrap_or_default().to_string();
                    return final_phase == "complete";
                }
                false
            },
        )
        .await;
    if let Err(error) = watched {
        if !expired(&error) {
            return Err(error);
        }
    }
    let causes_line = format!(
        "the causes the row named: {:?}; final phase {final_phase:?}",
        causes.iter().collect::<Vec<_>>()
    );
    // ADR 0110 line 378: a chain-durable self-leave seals under a
    // memory-only file, so the intake wait must not appear for it.
    passed &= record_check(
        receipt,
        "the_chain_durable_trigger_never_waits_for_intake",
        !causes.contains("waiting_for_durable_intake"),
        CAUSE_DURABLE_WAIT_SHOWN,
        Some(causes_line.clone()),
        causes_line,
        at(sim),
    );
    // A short settle before the teardown: the arm ends while the
    // exclusion's delivery is still in flight, and a teardown that
    // races it leaves the test process leaky.
    sim.within(
        "the settle window after the watch",
        SETTLE + secs(1),
        async {
            tokio::time::sleep(SETTLE).await;
        },
    )
    .await?;
    let row = s4_row(sim, "A", group, b_hex)
        .await?
        .context("A's row for B")?;
    let view = view_now(sim, "A", group, b_hex).await?;
    let a_hex = sim.agent_hex("A")?;
    passed &= record_check(
        receipt,
        "the_chain_durable_trigger_completes_one_rotation",
        row["phase"].as_str() == Some("complete")
            && row["result_epoch"].as_u64() == Some(e0 + 1)
            && view.epoch == Some(e0 + 1)
            && view.leaves == Some(leaves0 - 1)
            && !view.lists_b
            && !view.quarantined
            && view.head_committed_by.as_deref() == Some(a_hex.as_str()),
        CAUSE_NEWER_ROW_INCOMPLETE,
        Some(format!(
            "phase={} result_epoch={:?}; A: {}",
            row["phase"].as_str().unwrap_or_default(),
            row["result_epoch"].as_u64(),
            view.describe()
        )),
        format!(
            "the row: phase={} result_epoch={:?}; A: {}",
            row["phase"].as_str().unwrap_or_default(),
            row["result_epoch"].as_u64(),
            view.describe()
        ),
        at(sim),
    );
    passed &= record_check(
        receipt,
        "the_newer_file_stays_byte_identical",
        std::fs::read(&path)? == NEWER_EVS,
        CAUSE_NEWER_TOUCHED,
        Some(format!("the file at {} changed", path.display())),
        format!(
            "the {}-byte {NEWER_EVS:?} form is unchanged after the seal",
            NEWER_EVS.len()
        ),
        at(sim),
    );
    receipt.finish(FINAL_NEWER, passed, at(sim));
    Ok(())
}

async fn start(case: &str, seed: u64, labels: &[&str]) -> Result<Sim> {
    let mut sim = Sim::empty(case, seed, labels)?;
    for label in labels {
        sim.start_node_with(label, Provision::default()).await?;
    }
    Ok(sim)
}

/// Which arm runs.
#[derive(Clone, Copy, Debug)]
enum Arm {
    Control,
    NewerFile,
}

async fn run(case: &str, seed: u64, labels: &[&str], arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(concat!(
        "#1581 / ADR 0110 S4 `s4_sidecar_rebuild`. ",
        "The fsync cut points have no seam: the damage is the on-disk bytes it leaves. ",
        "The trigger is a self-leave because a loaded revocation record's intake permit ",
        "would wake a second worker pass at once and overwrite the stored rebuild wait."
    ));
    match start(case, seed, labels).await {
        Ok(mut sim) => {
            let outcome = match setup(&mut sim, &mut receipt, labels).await {
                Ok((group, b_hex, _, e0, leaves0)) => match arm {
                    Arm::Control => {
                        control_arm(&mut sim, &mut receipt, &group, &b_hex, e0, leaves0).await
                    }
                    Arm::NewerFile => {
                        newer_file_arm(&mut sim, &mut receipt, &group, &b_hex, e0, leaves0).await
                    }
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
        Arm::NewerFile => FINAL_NEWER,
    };
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(final_name);
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, labels: &[&str], arm: Arm) -> Result<()> {
    let receipt = run(case, seed, labels, arm).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

const CONTROL_LABELS: &[&str] = &["A", "B", "C"];
const NEWER_LABELS: &[&str] = &["A", "B"];

/// ADR 0110 `s4_sidecar_rebuild`, the `.evs` body-damage rebuild: A
/// holds the open self-leave row held by its boot head gate, the body
/// is damaged on disk, and the restarted A quarantines, rebuilds,
/// re-derives the row (the typed `rebuilding_obligation_store`, then
/// `waiting_for_head_sync`) and completes with exactly one rotation.
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
fn w3h_1581h_control_sidecar_rebuild_body_damage_rederives() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581h_control_sidecar_rebuild_body_damage_rederives",
            0x1581_000e,
            CONTROL_LABELS,
            Arm::Control,
        )
        .await
    })
}

/// ADR 0110 `s4_sidecar_rebuild`, the newer-file variant, read with
/// line 378 ("Memory-only durability"): with a `X0XEVICT3\0` sidecar
/// running memory-only, a new self-leave trigger — durable on the
/// verified chain — is sealed without the `waiting_for_durable_intake`
/// wait, the file stays untouched and the exclusion completes with one
/// rotation. If the intake wait ever appears for a chain-durable
/// trigger, the arm fails (line 378 seals it).
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
fn w3h_1581h_control_sidecar_rebuild_newer_file_memory_only() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581h_control_sidecar_rebuild_newer_file_memory_only",
            0x1581_000f,
            NEWER_LABELS,
            Arm::NewerFile,
        )
        .await
    })
}
