//! W3-H case for #1765 (ADR 0110 S4 Validation row `s4_sidecar_rebuild`,
//! line 451, the newer-file variant "a new trigger whose evidence is not
//! yet in the revocation store", read with line 378 "Memory-only
//! durability": the revocation-store write fails, then succeeds): A (the
//! sole admin, so the designated committer), B and C in a TreeKEM group
//! settled at e0.
//!
//! A stops, a `X0XEVICT4\0` sidecar is put at A's `.evs` path and A
//! restarts, so A's S4 store runs memory-only (`sidecar_newer_format`).
//! After the restart sync wait, the case makes A's revocation-store
//! write fail and B revokes its own agent (`POST /identity/revoke` on
//! B). ADR 0110 line 378 ("Memory-only durability"): under a memory-only
//! sidecar S4 seals only a trigger that is durable elsewhere, and a
//! revocation is durable only when it is in the revocation store on
//! disk. So while the write fails, A's row for B must show the typed
//! `waiting_for_durable_intake` and A must stay at e0. On a tree without
//! the #1765 fix, A seals a revocation that is not in the store
//! ([`CAUSE_SEALED_NOT_DURABLE`], RED). When the fault is removed, the
//! retried write succeeds and the row completes with exactly one
//! rotation (A and C at e0 + 1, `result_epoch` e0 + 1, no second
//! rekey), and the newer `.evs` stays byte-identical.
//!
//! Harness honesty:
//!
//! - The write fault is a file mode, not an fsync seam: A's identity
//!   directory (which holds `revocations.bin`) is set to mode 0500, so
//!   the durable writer cannot create its temp file. The revocation-store
//!   guard can still read the store, so the error is an ordinary storage
//!   error, not the "persistence blocked" refusal. A probe file create
//!   proves the fault before the trigger (a root process ignores the
//!   mode; the probe then fails the premise and the case is INFRA). The
//!   mode is put back on every exit path by a drop guard.
//! - The case does not say which route (the v1 legacy topic or v2)
//!   brought B's record to A first. Both write the v1 store, which holds
//!   every Agent subject, and both meet the same fault.
//! - Other identity-directory writes during the fault window (for
//!   example caches) fail too. The case asserts only the S4 row, A's
//!   epoch and the revocation-store bytes.
//!
//! Not covered, by name: the fsync failures at the §5a steps; a write
//! that fails after the rename; the revocation-store "persistence
//! blocked" refusal (it is not retried); the issuer-revocation and
//! certificate-expiry trigger forms; and `s4_restart_intake_prepare`,
//! whose failed intake write is the writable `.evs` write, not the
//! revocation store. Receipts use `w3h.receipt/1`.

#![cfg(all(test, unix))]

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::{S4Timing, EVS_FILE_NAME};
use anyhow::{ensure, Context as _};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for the revocation record to reach A.
const EVIDENCE: Duration = Duration::from_secs(60);
/// Budget for a restart's store classification.
const BOOT: Duration = Duration::from_secs(60);
/// How long the case watches A's row while the store write fails. It is
/// longer than the restart sync wait and many worker ticks, so a node
/// that seals without the store write seals inside it.
const WATCH: Duration = Duration::from_secs(20);
/// Budget for the row to complete after the fault is removed: the
/// largest retry delay (10 s) plus the completion bound, with slack.
const COMPLETE: Duration = Duration::from_secs(60);
/// The case waits this long after the completion and re-reads, so a
/// second rotation (another epoch step) is seen.
const SETTLE: Duration = Duration::from_secs(10);

/// The newer `.evs` layout this binary must leave untouched (#1508 reads
/// v2, so v3 is the newer form).
const NEWER_EVS: &[u8] = b"X0XEVICT4\0future layout";
/// The v1 revocation store's file name in the identity directory.
const REVOCATION_FILE: &str = "revocations.bin";
/// The fault mode of A's identity directory: read and search, no write.
const READ_ONLY_DIR: u32 = 0o500;

const FINAL: &str = "the_memory_only_sidecar_seals_the_revocation_only_after_its_store_write";
const CAUSE_NEWER_MISCLASSIFIED: &str =
    "the newer-format .evs was not classified memory-only: the \
                                         store did not publish sidecar_newer_format with the \
                                         version detail";
const CAUSE_SEALED_NOT_DURABLE: &str = "no waiting_for_durable_intake: A sealed a revocation that \
                                        is not yet in the revocation store under a memory-only \
                                        sidecar";
const CAUSE_STORE_NOT_WRITTEN: &str = "the revocation store was not written after the fault was \
                                       removed: the failed intake write was not retried";
const CAUSE_ROW_INCOMPLETE: &str = "the revocation row did not complete with exactly one \
                                    rotation after the store write: the row never completed, \
                                    or the survivors are not at e0 + 1";
const CAUSE_SECOND_ROTATION: &str = "the completion was not exactly one rotation: the survivors \
                                     moved past e0 + 1 in the settle window";
const CAUSE_NEWER_TOUCHED: &str = "the newer-format .evs was rewritten: ADR 0108 §5a leaves a \
                                   newer layout untouched, byte-identical";

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

/// `label`'s public sidecar store view: `(state, detail)`.
async fn store_view(sim: &Sim, label: &str, group: &str) -> Result<(String, Option<String>)> {
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
    ))
}

/// Whether `label` holds a revocation record whose subject is `subject_hex`.
async fn holds_revocation(sim: &Sim, label: &str, subject_hex: &str) -> Result<bool> {
    let (status, body) = sim
        .request(label, Method::GET, "/identity/revocations", None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /identity/revocations: {status} {body}"
    );
    Ok(body["revocations"]
        .as_array()
        .context("no revocations array")?
        .iter()
        .any(|record| {
            record["subject"]
                .as_str()
                .is_some_and(|subject| subject.eq_ignore_ascii_case(subject_hex))
        }))
}

/// The bytes at `path`; `None` when the file does not exist.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Record one desired-behaviour check: a pass is evidence, a failure
/// becomes the named cause. The premise stages stay `evidence` however
/// the case ends, so a neutralisation is RED with every premise still
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

/// The write fault: `dir` has mode [`READ_ONLY_DIR`] while this guard
/// lives. [`Self::restore`] puts the old mode back; the drop does it on
/// every other exit path.
struct ReadOnlyDir {
    path: PathBuf,
    mode: u32,
    restored: bool,
}

impl ReadOnlyDir {
    fn install(path: &Path) -> Result<Self> {
        let mode = std::fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions()
            .mode();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(READ_ONLY_DIR))
            .with_context(|| format!("chmod {:o} {}", READ_ONLY_DIR, path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            mode,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<()> {
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode))
            .with_context(|| format!("chmod {:o} {}", self.mode, self.path.display()))?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for ReadOnlyDir {
    fn drop(&mut self) {
        if !self.restored {
            let _ =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode));
        }
    }
}

/// Restart A and wait until it links to B and C again.
async fn restart_a(sim: &mut Sim) -> Result<()> {
    sim.start_again("A").await?;
    sim.until("A reconnects to B and C", SETUP, async |s: &Sim| {
        connected_to(s, "A", "B").await && connected_to(s, "A", "C").await
    })
    .await
}

/// The shared setup: mesh, the ordinary `private_secure` group A
/// creates, B and C seated, settled. Returns `(group, b_hex, e0, leaves0)`.
async fn setup(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
) -> Result<(String, String, u64, u32)> {
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
    Ok((group, b_hex, e0, leaves0))
}

/// The case body: the newer `.evs` runs memory-only, A's revocation-store
/// write fails, B self-revokes, A's row waits for the durable intake; the
/// fault goes, the retried write succeeds and the row completes.
async fn body(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
    group: &str,
    b_hex: &str,
    e0: u64,
    leaves0: u32,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let mut passed = true;

    // The newer-format sidecar, put while A is stopped.
    sim.stop("A", RestartMode::Crash).await?;
    sim.fabric()
        .mark("case: A stopped; the newer-format .evs is planted");
    let dir = sim.data_dir("A")?;
    let evs = dir.join(EVS_FILE_NAME);
    std::fs::write(&evs, NEWER_EVS).with_context(|| format!("plant {}", evs.display()))?;
    // The harness puts the identity directory next to the data directory.
    let identity = dir
        .parent()
        .context("A's data dir has a parent")?
        .join("identity");
    let store = identity.join(REVOCATION_FILE);
    receipt.evidence(
        "the_newer_format_bytes_are_at_the_sidecar_path",
        std::fs::read(&evs)? == NEWER_EVS && identity.join("agent.key").is_file(),
        format!(
            "the {NEWER_EVS:?} form at {}; A's identity dir {} holds agent.key",
            evs.display(),
            identity.display()
        ),
        at(sim),
    );
    restart_a(sim).await?;

    let _ = sim
        .until(
            "the store publishes the newer-format classification",
            BOOT,
            async |s: &Sim| {
                store_view(s, "A", group)
                    .await
                    .is_ok_and(|(state, _)| state == "sidecar_newer_format")
            },
        )
        .await;
    let (state, detail) = store_view(sim, "A", group).await?;
    passed &= record_check(
        receipt,
        "the_sidecar_runs_memory_only_newer_format",
        state == "sidecar_newer_format" && detail.as_deref() == Some("version 4"),
        CAUSE_NEWER_MISCLASSIFIED,
        Some(format!("state={state} detail={detail:?}")),
        format!("state={state:?} detail={detail:?}; the file must stay untouched"),
        at(sim),
    );

    // Past A's restart sync wait, so the head gate cannot hold the seal
    // and only the durability rule can.
    let wait = S4Timing::default().restart_sync_wait;
    sim.within("A's restart sync wait", wait + secs(2), async {
        tokio::time::sleep(wait).await;
    })
    .await?;
    let (_, epoch_now, _) = settled(sim, labels, group, b_hex).await?;
    receipt.evidence(
        "a_is_past_the_restart_sync_wait_at_e0",
        epoch_now == e0,
        format!("every node at epoch {epoch_now} (e0={e0}) after {wait:?}"),
        at(sim),
    );

    // The fault: A's identity directory refuses new files, so the
    // revocation-store write cannot create its temp file.
    let store_before = read_optional(&store)?;
    let mut fault = ReadOnlyDir::install(&identity)?;
    sim.fabric()
        .mark("case: A's identity dir is read-only (revocation-store write fault)");
    let probe = identity.join("w3h-1765-probe");
    let probe_refused = match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            false
        }
        Err(error) => error.kind() == std::io::ErrorKind::PermissionDenied,
    };
    receipt.evidence(
        "the_identity_dir_refuses_new_files",
        probe_refused,
        format!(
            "mode {READ_ONLY_DIR:o} on {}; a probe create was refused: {probe_refused}; the \
             store before the trigger: {:?} bytes",
            identity.display(),
            store_before.as_ref().map(Vec::len)
        ),
        at(sim),
    );

    // The new trigger: B revokes its own agent.
    sim.fabric().mark("case: B self-revokes");
    let (status, response) = sim
        .api(
            "B",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": b_hex, "reason": "w3h-1765"})),
        )
        .await?;
    ensure!(status.is_success(), "B self-revokes: {status} {response}");
    sim.until("A holds B's revocation", EVIDENCE, async |s: &Sim| {
        holds_revocation(s, "A", b_hex).await.unwrap_or(false)
    })
    .await?;
    receipt.request_delivered(
        "a_holds_b_self_revocation_under_the_write_fault",
        true,
        format!("POST /identity/revoke from B: {status}; A lists the record"),
        at(sim),
    );

    // Watch A's row through the window: every cause, the last cause, and
    // whether A left e0 (a seal) or the row completed.
    let mut causes = std::collections::BTreeSet::new();
    let mut last = String::from("no row read");
    let mut last_held = false;
    let mut sealed = false;
    let watched = sim
        .until(
            "A seals B's revocation or the watch ends",
            WATCH,
            async |s: &Sim| {
                let row = s4_row(s, "A", group, b_hex).await.ok().flatten();
                let epoch = view_now(s, "A", group, b_hex)
                    .await
                    .ok()
                    .and_then(|seen| seen.epoch);
                let cause = row
                    .as_ref()
                    .and_then(|row| row["waiting"]["cause"].as_str().map(str::to_string));
                let phase = row
                    .as_ref()
                    .and_then(|row| row["phase"].as_str().map(str::to_string));
                if let Some(cause) = &cause {
                    causes.insert(cause.clone());
                }
                last = format!("cause={cause:?} phase={phase:?} A epoch={epoch:?}");
                last_held = cause.as_deref() == Some("waiting_for_durable_intake")
                    && phase.as_deref() == Some("pending")
                    && epoch == Some(e0);
                sealed |= epoch != Some(e0) || phase.as_deref() == Some("complete");
                sealed
            },
        )
        .await;
    if let Err(error) = watched {
        if !expired(&error) {
            return Err(error);
        }
    }
    let store_during = read_optional(&store)?;
    receipt.evidence(
        "the_fault_held_the_revocation_store_write",
        store_during == store_before,
        format!(
            "revocations.bin unchanged through the watch: {:?} bytes before, {:?} after",
            store_before.as_ref().map(Vec::len),
            store_during.as_ref().map(Vec::len)
        ),
        at(sim),
    );
    let held = !sealed && last_held;
    let watch_line = format!(
        "over {WATCH:?}: the causes A's row named: {:?}; sealed or left e0: {sealed}; the last \
         reading: {last}",
        causes.iter().collect::<Vec<_>>()
    );
    passed &= record_check(
        receipt,
        "the_row_waits_for_durable_intake_while_the_store_write_fails",
        held,
        CAUSE_SEALED_NOT_DURABLE,
        Some(watch_line.clone()),
        watch_line,
        at(sim),
    );

    // The fault goes: the retried write succeeds and the row proceeds.
    fault.restore()?;
    sim.fabric()
        .mark("case: A's identity dir is writable again");
    let restored_at = sim.fabric().now();
    let _ = sim
        .until("A's row for B completes", COMPLETE, async |s: &Sim| {
            s4_row(s, "A", group, b_hex)
                .await
                .ok()
                .flatten()
                .is_some_and(|row| row["phase"].as_str() == Some("complete"))
        })
        .await;
    let completed_after = sim.fabric().now().saturating_sub(restored_at);
    let store_after = read_optional(&store)?;
    // The bytes must hold B's revocation, not only differ: a written store
    // without B's record would not carry the exclusion's evidence.
    let b_id = crate::identity::AgentId(
        <[u8; 32]>::try_from(hex::decode(b_hex).context("B's agent id hex")?.as_slice())
            .context("B's agent id length")?,
    );
    let store_holds_b = store_after.as_deref().is_some_and(|bytes| {
        crate::revocation::RevocationSet::from_bytes(bytes)
            .is_ok_and(|set| set.is_agent_revoked(&b_id))
    });
    passed &= record_check(
        receipt,
        "the_retried_write_puts_the_revocation_in_the_store",
        store_holds_b && store_after != store_before,
        CAUSE_STORE_NOT_WRITTEN,
        Some(format!(
            "revocations.bin: {:?} bytes before, {:?} after the restore; holds B's revocation: \
             {store_holds_b}",
            store_before.as_ref().map(Vec::len),
            store_after.as_ref().map(Vec::len)
        )),
        format!(
            "revocations.bin: {:?} bytes before the fault, {:?} after the restore; holds B's \
             revocation: {store_holds_b}",
            store_before.as_ref().map(Vec::len),
            store_after.as_ref().map(Vec::len)
        ),
        at(sim),
    );

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
    passed &= record_check(
        receipt,
        "the_row_completes_with_exactly_one_rotation_after_the_write",
        one_rotation,
        CAUSE_ROW_INCOMPLETE,
        Some(format!(
            "phase={} result_epoch={result_epoch:?}",
            row["phase"].as_str().unwrap_or_default()
        )),
        format!(
            "the row: phase={} result_epoch={result_epoch:?}, {completed_after:?} after the \
             restore; {}",
            row["phase"].as_str().unwrap_or_default(),
            describe_views(&views)
        ),
        at(sim),
    );

    // No second rotation follows the completion.
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
        "no_second_rotation_after_the_completion",
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
    passed &= record_check(
        receipt,
        "the_newer_file_stays_byte_identical",
        std::fs::read(&evs)? == NEWER_EVS,
        CAUSE_NEWER_TOUCHED,
        Some(format!("the file at {} changed", evs.display())),
        format!(
            "the {}-byte {NEWER_EVS:?} form is unchanged after the seal",
            NEWER_EVS.len()
        ),
        at(sim),
    );
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn start(case: &str, seed: u64, labels: &[&str]) -> Result<Sim> {
    let mut sim = Sim::empty(case, seed, labels)?;
    for label in labels {
        sim.start_node_with(label, Provision::default()).await?;
    }
    Ok(sim)
}

async fn run(case: &str, seed: u64, labels: &[&str]) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(concat!(
        "#1765 / ADR 0110 S4 `s4_sidecar_rebuild` (newer file, a trigger not yet in the ",
        "revocation store; line 378, the revocation-store write fails, then succeeds). ",
        "The write fault is a read-only identity directory, not an fsync seam."
    ));
    match start(case, seed, labels).await {
        Ok(mut sim) => {
            let outcome = match setup(&mut sim, &mut receipt, labels).await {
                Ok((group, b_hex, e0, leaves0)) => {
                    body(&mut sim, &mut receipt, labels, &group, &b_hex, e0, leaves0).await
                }
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
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

const LABELS: &[&str] = &["A", "B", "C"];

/// ADR 0110 `s4_sidecar_rebuild`, the newer-file variant with a new
/// trigger whose evidence is not yet in the revocation store, with a
/// failed-then-successful revocation-store write (line 378):
/// under a `X0XEVICT4\0` memory-only sidecar, B's self-revocation reaches
/// A while A's revocation-store write fails. A's row shows the typed
/// `waiting_for_durable_intake` and A stays at e0; when the write
/// succeeds, the row completes with exactly one rotation and the newer
/// file stays untouched. RED before #1765: A sealed without the wait.
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
fn w3h_1765_red_newer_file_revocation_waits_for_store_write() -> Result<()> {
    super::block_on_paused(async move {
        let case = "w3h_1765_red_newer_file_revocation_waits_for_store_write";
        let receipt = run(case, 0x1765_0001, LABELS).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
