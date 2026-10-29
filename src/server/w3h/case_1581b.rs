//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_dropped_eager_frame`): A, D, B, C with A < D, so A is the
//! designated committer; D observes B's self-revocation first, and the
//! initial eager revocation and hand-off frames toward A are lost, with
//! the retry delivered only after the 1.5 s per-peer timeout floor
//! (D69). With S4 merged (#1357) both arms expect the ADR behaviour
//! (GREEN) and keep the row's causes for a regression: the recovered
//! schedule seats exactly one exclusion, signed by A, with no premature
//! sibling from D (the control), and total A loss gives D's rank-1
//! fallback after W, a current-head sync and H (the row's red arm; the
//! five-node shape of that arm was RED on pre-S4 `main`, DIAG PR #1496,
//! so the cause strings stay).
//!
//! Harness honesty: the fabric cannot command the gossip IHAVE timer,
//! so the row's departure ("flush IHAVE at 100 ms, deliver the retry
//! only after the 1.5 s floor") is expressed as one hold on every
//! application lane toward A (pubsub, the revocation gossip; direct and
//! relayed DMs, the S4 hand-off; bulk) that releases at t = 0 + 1.5 s.
//! Nothing reaches A before the floor; the held frames arrive there in
//! lane order together with any retries the transport itself made. The
//! pre-release read proves A observed nothing before the floor, and the
//! held-frame counts by lane are in the receipt. Stream writes toward A
//! cannot be delayed by the fabric and pass; the pre-release read would
//! show anything that reached A that way.
//!
//! Before t = 0 the ordinary `private_secure` (TreeKEM) group is settled
//! (every node at A's state revision and epoch e0, four leaves) and a
//! data-plane probe opens on B and C. The case waits out
//! `S4Timing::restart_sync_wait` after setup, so t = 0 is past every
//! node's boot head gate and the arms measure the S4 path. Healthy exit
//! H: every survivor at exactly e0 + 1 with three leaves, B not listed,
//! no fork-quarantine, one commit signed by the expected admin, and the
//! data plane open on C and not on B. Receipts use `w3h.receipt/1`.
//!
//! Arms:
//!
//! - `control_dropped_eager_frame_retry_floor`: D, B and C observe at
//!   t = 0; A's first observation (its `.evs` row for B) is at or after
//!   the floor. A, designated and observed before W, signs the
//!   exclusion on every survivor; a sibling signer (D) fails the arm
//!   with [`CAUSE_SIBLING_SIGNED`], and H must hold within the
//!   completion bound from A's first row sighting, at e0 + 1 and only
//!   there after [`SETTLE`].
//! - `red_dropped_eager_frame_total_a_loss`: A is off the fabric from
//!   before t = 0 to the end; D and C observe at t = 0. At W/2 no
//!   survivor has rekeyed and none is quarantined (no premature
//!   sibling), and the first epoch move is at or after W
//!   ([`S4Timing::fallback_offset`] of rank 1). D then reaches H within
//!   W plus the completion bound, signed by D on every survivor. A
//!   failure where nothing acts is [`CAUSE_NO_FALLBACK`].
//!
//! Not covered by this case (the row's IHAVE-specific timing): the
//! 100 ms IHAVE flush itself is the transport's own behaviour; the
//! harness holds the affected lanes and reports the counts, and does
//! not claim to observe the IHAVE clock.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::S4Timing;
use anyhow::{ensure, Context as _};
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for the revocation record to reach its holders.
const EVIDENCE: Duration = Duration::from_secs(60);
/// After H, the case waits this long and re-reads, so a duplicate rekey
/// (a second epoch step) is seen.
const SETTLE: Duration = Duration::from_secs(30);
/// The row's per-peer retry floor for a lost eager frame (D69): nothing
/// toward A is delivered before this much virtual time after t = 0.
const RETRY_FLOOR: Duration = Duration::from_millis(1500);
/// How far before the release point the pre-release read happens.
const READ_MARGIN: Duration = Duration::from_millis(50);
const PROBE: &[u8] = b"w3h-1581b probe";

const FINAL_CONTROL: &str = "designated_a_seals_once_after_the_retry_floor_with_no_sibling";
const FINAL_LOSS: &str = "rank_one_d_falls_back_after_w_total_a_loss_reaches_h";
const CAUSE_SIBLING_SIGNED: &str = "survivors reached H, but the head commit is not signed by \
                                    the designated admin A: a sibling (D) signed the exclusion";
const CAUSE_OVER_BOUND: &str = "survivors reached H with the expected signer, but later than \
                                the bound: the completion bound from A's first observation";
const CAUSE_EARLY_SIBLING: &str = "a non-designated admin rekeyed before the rank-1 fallback \
                                   time W while the designated admin A was offline";
const CAUSE_NO_FALLBACK: &str = "no ranked fallback with total A loss: after W plus the \
                                 completion bound every survivor still lists B active, at epoch \
                                 e0, with the same leaf count";
const CAUSE_NOT_SIGNED_BY_D: &str = "survivors reached H, but the head commit is not signed by \
                                     the rank-1 fallback D";
const CAUSE_FALLBACK_LATE: &str = "survivors reached H with signer D, but later than W plus the \
                                   completion bound from t = 0";
const CAUSE_NO_RECOVERY: &str = "the held eager frames were released at the retry floor, but the \
                                 designated admin A never sealed: after the completion bound \
                                 every survivor still lists B active, at epoch e0, with the same \
                                 leaf count";
const CAUSE_DATA_PLANE: &str = "the survivors reached H with the expected signer, but the data \
                                plane did not follow: C did not decrypt the new traffic, or B \
                                still could";
const CAUSE_SECOND_ROTATION: &str = "the exclusion was not exactly one rotation: a survivor moved \
                                     past e0 + 1, or a rekey repeated or diverged, after the \
                                     first exclusion";

/// `label`'s view of `group`; `None` when it holds no record of it.
#[derive(Debug, Clone)]
struct View {
    state_revision: u64,
    lists_b: bool,
    quarantined: bool,
    epoch: Option<u64>,
    leaves: Option<u32>,
    /// Who signed the commit at `state_revision` (hex agent id, lower
    /// case), from the node's retained commit log.
    head_committed_by: Option<String>,
}

impl View {
    fn describe(&self) -> String {
        format!(
            "state={} lists_b={} epoch={:?} leaves={:?} quarantined={} \
             head_committed_by={:?}",
            self.state_revision,
            self.lists_b,
            self.epoch,
            self.leaves,
            self.quarantined,
            self.head_committed_by
        )
    }
}

async fn try_view_now(
    sim: &Sim,
    label: &str,
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Option<View>> {
    let b_hex = hex::encode(b.as_bytes());
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
                .any(|member| member.agent_id.eq_ignore_ascii_case(&b_hex)),
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

async fn view_now(
    sim: &Sim,
    label: &str,
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<View> {
    try_view_now(sim, label, group, b)
        .await?
        .with_context(|| format!("{label} has no record of the group"))
}

async fn views_now<'a>(
    sim: &Sim,
    labels: &[&'a str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Vec<(&'a str, Option<View>)>> {
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        out.push((*label, try_view_now(sim, label, group, b).await?));
    }
    Ok(out)
}

async fn views<'a>(
    sim: &Sim,
    labels: &[&'a str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Vec<(&'a str, Option<View>)>> {
    sim.at_instant(
        "read the survivors' groups",
        views_now(sim, labels, group, b),
    )
    .await?
}

/// The structural part of H over the survivors' views: one coherent
/// epoch above e0 with one leaf fewer, B not listed, no quarantine, and
/// the same epoch on every survivor.
fn excluded(views: &[(&str, Option<View>)], e0: u64, leaves0: u32) -> bool {
    let mut epoch = None;
    for (_, seen) in views {
        let Some(seen) = seen else {
            return false;
        };
        let Some(now) = seen.epoch else {
            return false;
        };
        if now <= e0
            || seen.lists_b
            || seen.quarantined
            || seen.leaves != Some(leaves0.saturating_sub(1))
            || epoch.is_some_and(|first| first != now)
        {
            return false;
        }
        epoch = Some(now);
    }
    !views.is_empty()
}

fn all_at(views: &[(&str, Option<View>)], epoch: u64) -> bool {
    !views.is_empty()
        && views
            .iter()
            .all(|(_, seen)| seen.as_ref().is_some_and(|seen| seen.epoch == Some(epoch)))
}

fn describe_all(views: &[(&str, Option<View>)]) -> String {
    views
        .iter()
        .map(|(label, seen)| {
            format!(
                "{label}: {}",
                seen.as_ref()
                    .map_or_else(|| "no record".to_string(), View::describe)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
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

/// Whether `observer` lists `subject` as an active admin or owner.
async fn sees_admin(sim: &Sim, observer: &str, group: &str, subject: &str) -> Result<bool> {
    let subject = sim.agent_hex(subject)?;
    let state = sim.state(observer)?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("{observer} has no record of the group"))?;
    let admin = info.active_members().any(|member| {
        member.agent_id.eq_ignore_ascii_case(&subject)
            && member.role.at_least(crate::groups::GroupRole::Admin)
    });
    Ok(admin)
}

/// Every label holds A's state revision and TreeKEM epoch.
async fn settled(
    sim: &Sim,
    labels: &[&str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<()> {
    sim.until(
        "every node holds A's head and epoch",
        SETUP,
        async |s: &Sim| {
            let Ok(authority) = view_now(s, "A", group, b).await else {
                return false;
            };
            if authority.epoch.is_none() {
                return false;
            }
            for label in labels {
                match view_now(s, label, group, b).await {
                    Ok(seen)
                        if seen.state_revision == authority.state_revision
                            && seen.epoch == authority.epoch => {}
                    _ => return false,
                }
            }
            true
        },
    )
    .await
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

/// Wait until every holder holds B's revocation record; a timeout is
/// INFRA (the trigger never reached its target).
async fn await_holders(sim: &Sim, holders: &[&str], b_hex: &str) -> Result<()> {
    let mut seen = Observations::default();
    let what = "the holders hold B's revocation";
    let waited = sim
        .until(what, EVIDENCE, async |s: &Sim| {
            for holder in holders {
                match seen.observe(holds_revocation(s, holder, b_hex)).await {
                    Some(true) => {}
                    Some(false) => return false,
                    None => return true,
                }
            }
            true
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify(what)
}

/// `label`'s persisted S4 row for `target` (the `.evs` sidecar): its
/// first observation (T_obs), in wall-clock Unix ms. `None` when the
/// sidecar has no row for `target`.
fn persisted_t_obs(sim: &Sim, label: &str, target: &[u8; 32]) -> Result<Option<u64>> {
    use crate::groups::eviction::{decode_evs, EVS_FILE_NAME};
    let path = sim.state(label)?.data_dir.join(EVS_FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let body = decode_evs(&bytes).map_err(|error| anyhow::anyhow!("{label} .evs: {error:?}"))?;
    Ok(body
        .rows
        .iter()
        .find(|row| &row.target == target)
        .map(|row| row.observed_at_unix_ms))
}

/// `label` encrypts the probe; the ciphertext, or why it could not.
async fn encrypt(
    sim: &Sim,
    label: &str,
    group: &str,
) -> Result<std::result::Result<String, String>> {
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/secure/encrypt"),
            Some(json!({"payload_b64": BASE64.encode(PROBE)})),
        )
        .await?;
    Ok(match body["ciphertext_b64"].as_str() {
        Some(ciphertext) if status.is_success() && body["ok"] != false => {
            Ok(ciphertext.to_string())
        }
        _ => Err(format!("{label} encrypt: {status} {body}")),
    })
}

/// Whether `label` recovers the probe from `ciphertext`, with the reply.
async fn decrypts(sim: &Sim, label: &str, group: &str, ciphertext: &str) -> Result<(bool, String)> {
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/secure/decrypt"),
            Some(json!({"ciphertext_b64": ciphertext})),
        )
        .await?;
    let ok = status.is_success()
        && body["payload_b64"]
            .as_str()
            .and_then(|payload| BASE64.decode(payload).ok())
            .is_some_and(|payload| payload == PROBE);
    Ok((ok, format!("{label} decrypt: {status} {body}")))
}

/// Holds every frame toward one node, except its membership and
/// plane-hello lanes (so its links and liveness stay up), until a fixed
/// virtual release point, then delivers the frames there in lane order
/// (the fabric keeps each lane FIFO). Pubsub (the revocation gossip),
/// direct and relayed DMs (the S4 hand-off) and bulk are all held. The
/// fabric cannot delay stream lanes; stream writes toward the node pass
/// and are counted, and the pre-release read shows whether anything
/// reached the node early that way. (The sibling shape of #1357's late
/// arm; the release here is the row's 1.5 s retry floor, not W/2.)
struct LateHold {
    release: Duration,
    /// Frames held, per lane class (`Debug` name).
    held: Arc<std::sync::Mutex<BTreeMap<String, usize>>>,
    /// Stream writes toward the node while held (not delayable).
    streams: Arc<std::sync::atomic::AtomicUsize>,
}

impl LateHold {
    fn install(sim: &Sim, target: &str, release: Duration) -> Result<Self> {
        use crate::network::sim::{Fault, LaneClass};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let machine = sim.peer(target)?.0;
        let held = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let streams = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_streams) = (Arc::clone(&held), Arc::clone(&streams));
        sim.fabric().add_rule(move |write| {
            if write.lane.dst != machine || write.at >= release {
                return Fault::Pass;
            }
            match write.lane.class {
                LaneClass::Membership | LaneClass::PlaneHello => Fault::Pass,
                LaneClass::Stream(_) => {
                    rule_streams.fetch_add(1, Ordering::SeqCst);
                    Fault::Pass
                }
                class => {
                    if let Ok(mut counts) = rule_held.lock() {
                        *counts.entry(format!("{class:?}")).or_insert(0) += 1;
                    }
                    Fault::Delay(release.saturating_sub(write.at))
                }
            }
        });
        sim.fabric().mark(format!(
            "fault: every non-membership frame toward {target} held until {} us",
            release.as_micros()
        ));
        Ok(Self {
            release,
            held,
            streams,
        })
    }

    fn describe(&self) -> String {
        let counts = self
            .held
            .lock()
            .map_or_else(|_| "poisoned".to_string(), |counts| format!("{counts:?}"));
        format!(
            "held until {} us: {counts}; stream writes passed (not delayable): {}",
            self.release.as_micros(),
            self.streams.load(std::sync::atomic::Ordering::SeqCst)
        )
    }
}

/// Start the four nodes. A and D get the two pre-generated key pairs
/// sorted by agent id, so A < D (B and C keep theirs). The swap happens
/// before any daemon runs.
async fn start(case: &str, seed: u64, labels: &[&str]) -> Result<Sim> {
    let mut sim = Sim::empty(case, seed, labels)?;
    let ranked = ["A", "D"];
    let mut pairs = Vec::with_capacity(ranked.len());
    for label in ranked {
        pairs.push(sim.take_keys(label)?);
    }
    pairs.sort_by_key(|pair| pair.1.agent_id().0);
    let mut provisions: BTreeMap<&str, Provision> = BTreeMap::new();
    for (label, (machine, agent)) in ranked.into_iter().zip(pairs) {
        provisions.insert(
            label,
            Provision {
                machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
                agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
                ..Provision::default()
            },
        );
    }
    sim.fabric()
        .mark("case: admin keys reassigned so that A < D by agent id");
    for label in labels {
        let provision = provisions.remove(label).unwrap_or_default();
        sim.start_node_with(label, provision).await?;
    }
    Ok(sim)
}

/// The shared setup: mesh, an ordinary `private_secure` group A creates,
/// everyone seated, D promoted, settled at (e0, leaves0), the probe
/// opens on B and C, D holds B's authority-signed KeyPackage, and every
/// node is past its restart sync wait. Returns (group, b, e0, leaves0).
async fn setup(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
) -> Result<(String, crate::identity::AgentId, u64, u32)> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, labels).await?;
    let group = create_group(sim, "A").await?;
    for member in labels.iter().filter(|label| **label != "A") {
        seat(sim, member, &group).await?;
    }
    let d_hex = sim.agent_hex("D")?;
    let (status, body) = sim
        .api(
            "A",
            Method::PATCH,
            &format!("/groups/{group}/members/{d_hex}/role"),
            Some(json!({"role": "admin"})),
        )
        .await?;
    ensure!(status.is_success(), "promote D: {status} {body}");
    sim.until("every node sees D's promotion", SETUP, async |s: &Sim| {
        for observer in labels {
            if !sees_admin(s, observer, &group, "D").await.unwrap_or(false) {
                return false;
            }
        }
        true
    })
    .await?;

    let (b, _) = sim.ids("B")?;
    settled(sim, labels, &group, &b).await?;
    let base = view_now(sim, "A", &group, &b).await?;
    let e0 = base.epoch.context("A has no live TreeKEM group")?;
    let leaves0 = base.leaves.context("A has no live TreeKEM group")?;

    // Pre-trigger data plane: A's ciphertext opens on B and C, so a later
    // refusal on B means exclusion, not a broken path.
    let before = encrypt(sim, "A", &group).await?;
    let (b_before, c_before) = match &before {
        Ok(ciphertext) => (
            decrypts(sim, "B", &group, ciphertext).await?,
            decrypts(sim, "C", &group, ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error.clone())),
    };
    // D, the possible author of B's removal while A is away or held,
    // must hold B's KeyPackage by the remove route's own lookup. A miss
    // here is INFRA, not the S4 path.
    let b_hex = hex::encode(b.as_bytes());
    sim.until(
        "D holds B's authority-signed KeyPackage",
        SETUP,
        async |s: &Sim| {
            let Ok(state) = s.state("D") else {
                return false;
            };
            crate::server::routes::named_groups::holds_member_key_package_for_removal(
                &state, &group, &b_hex,
            )
            .await
        },
    )
    .await?;

    receipt.setup_done(at(sim));
    let timing = S4Timing::default();
    let mut differ = Vec::new();
    for label in labels {
        let have = sim.state(label)?.revocation_evictions.timing;
        if have != timing {
            differ.push(format!("{label}: {have:?}"));
        }
    }
    receipt.evidence(
        "every_node_runs_s4timing_default",
        differ.is_empty(),
        format!("want {timing:?}; differ: {differ:?}"),
        at(sim),
    );
    receipt.evidence(
        "treekem_group_settled_with_b_seated",
        base.lists_b && u32::try_from(labels.len()).ok() == Some(leaves0),
        format!("e0={e0} leaves0={leaves0}; A {}", base.describe()),
        at(sim),
    );
    receipt.evidence(
        "b_and_c_decrypt_at_e0_before_the_trigger",
        b_before.0 && c_before.0,
        format!("{}; {}", b_before.1, c_before.1),
        at(sim),
    );
    let mut ranked: Vec<(String, &str)> = ["A", "D"]
        .into_iter()
        .map(|label| sim.agent_hex(label).map(|hex| (hex, label)))
        .collect::<Result<_>>()?;
    ranked.sort();
    let order: Vec<&str> = ranked.iter().map(|(_, label)| *label).collect();
    receipt.evidence(
        "admins_rank_a_before_d",
        order == ["A", "D"],
        format!("admin agent-id order {order:?}"),
        at(sim),
    );

    // ADR 0110 §2: no S4 seal before a node's restart sync wait from
    // process start has passed (D73), so t = 0 measures the S4 path.
    // Every node started before setup ended, so waiting that long from
    // here puts t = 0 after every node's sync wait.
    let setup_end = sim.fabric().now();
    let sync_wait = timing.restart_sync_wait;
    sim.within(
        "every node's restart sync wait",
        sync_wait + secs(2),
        async {
            tokio::time::sleep(sync_wait).await;
        },
    )
    .await?;
    receipt.evidence(
        "every_node_past_its_restart_sync_wait_at_t0",
        sim.fabric().now().saturating_sub(setup_end) >= sync_wait,
        format!(
            "setup ended at {} us (every node started before it); restart sync wait {sync_wait:?}; \
             t0 at {} us",
            setup_end.as_micros(),
            sim.fabric().now().as_micros()
        ),
        at(sim),
    );
    Ok((group, b, e0, leaves0))
}

/// The control arm: the eager frames toward A are held to the retry
/// floor; A, designated, observes at or after the floor and signs the
/// one exclusion; no sibling from D.
async fn control_arm(sim: &mut Sim, receipt: &mut Receipt, labels: &[&str]) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let timing = S4Timing::default();
    let (group, b, e0, leaves0) = setup(sim, receipt, labels).await?;
    let b_hex = sim.agent_hex("B")?;
    let survivors = ["A", "D", "C"];

    // The row's departure: nothing toward A before the retry floor.
    let t0 = sim.fabric().now();
    let floor = t0.saturating_add(RETRY_FLOOR);
    let hold = LateHold::install(sim, "A", floor)?;
    let trigger = sim.fabric().mark_indexed(format!(
        "case: t=0 trigger SelfRevoke (floor {RETRY_FLOOR:?})"
    ));
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": b_hex, "reason": "w3h-1581b"})),
        )
        .await?;
    ensure!(status.is_success(), "B self-revokes: {status} {body}");
    // D observes first (with C); A observes nothing yet.
    await_holders(sim, &["D", "C"], &b_hex).await?;

    // Just before the floor: A holds no revocation record for B and has
    // no S4 row for B, so its T_obs is not before the floor (a row, once
    // created, stays).
    let read_at = floor.saturating_sub(READ_MARGIN);
    let left = read_at.saturating_sub(sim.fabric().now());
    sim.within(
        "wait to just before the retry floor",
        left + secs(2),
        async {
            tokio::time::sleep(left).await;
        },
    )
    .await?;
    let pre_read = sim.fabric().now();
    let pre_holds = sim
        .at_instant(
            "read A's revocations before the floor",
            holds_revocation(sim, "A", &b_hex),
        )
        .await??;
    let pre_t_obs = persisted_t_obs(sim, "A", b.as_bytes())?;
    receipt.evidence(
        "a_observed_nothing_before_the_retry_floor",
        !pre_holds && pre_t_obs.is_none(),
        format!(
            "read at {} us (floor {} us): A holds B's revocation {pre_holds}, A's .evs T_obs \
             {pre_t_obs:?}; {}",
            pre_read.as_micros(),
            floor.as_micros(),
            hold.describe()
        ),
        at(sim),
    );

    // The floor passes; the held frames (the transport's own retries
    // included) reach A. The row is polled from just before the floor
    // (the pre-release read is 50 ms early), so a sighting before the
    // floor — a lane the hold cannot carry, or a late pre-read — fails
    // the evidence; the sighting bounds A's T_obs from above.
    let mut row_seen: Option<Duration> = None;
    let mut early_row = false;
    let waited = sim
        .until("A's S4 row for B appears", EVIDENCE, async |s: &Sim| {
            if persisted_t_obs(s, "A", b.as_bytes()).is_ok_and(|t_obs| t_obs.is_some()) {
                let now = s.fabric().now();
                early_row |= now < floor;
                row_seen = Some(now);
                true
            } else {
                false
            }
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    let row_seen = match row_seen {
        Some(at) => at,
        None => {
            // The held delivery never reached A: the arm's own cause, not
            // INFRA. The trigger did reach its other targets, which is the
            // delivery fact the receipt needs.
            let d_holds = sim
                .at_instant(
                    "read D's revocations after the floor",
                    holds_revocation(sim, "D", &b_hex),
                )
                .await??;
            receipt.request_delivered(
                "holders_hold_b_revocation",
                d_holds,
                format!("D holds B's revocation record: {d_holds}"),
                at(sim),
            );
            receipt.cause(
                CAUSE_NO_RECOVERY,
                Some("A's .evs row for B never appeared after the floor".to_string()),
                true,
                at(sim),
            );
            receipt.finish(FINAL_CONTROL, false, at(sim));
            return Ok(());
        }
    };
    receipt.evidence(
        "a_t_obs_at_or_after_the_retry_floor",
        row_seen >= floor && !early_row,
        format!(
            "A's row first seen at {} us, the floor is at {} us; a sighting before the floor: \
             {early_row} (the pre-floor read had no record and no row)",
            row_seen.as_micros(),
            floor.as_micros()
        ),
        at(sim),
    );

    // H within the completion bound from A's first row sighting (an
    // upper bound of T_obs), once, signed by A on every survivor.
    let bound = timing.completion_bound;
    let deadline = row_seen.saturating_add(bound);
    let mut reached_after: Option<Duration> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the survivors reach H", bound + secs(5), async |s: &Sim| {
            let Some(now) = seen.observe(views_now(s, &survivors, &group, &b)).await else {
                return true;
            };
            let done = excluded(&now, e0, leaves0);
            if done {
                reached_after.get_or_insert(s.fabric().now());
            }
            done
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("the survivors reach H")?;
    sim.within("H settles", SETTLE + secs(2), async {
        tokio::time::sleep(SETTLE).await;
    })
    .await?;
    let end = views(sim, &survivors, &group, &b).await?;

    // Data plane after the wait: a survivor's new ciphertext opens on C
    // and not on B.
    let (c_after, b_after) = match encrypt(sim, "A", &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "B", &group, &ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error.clone())),
    };
    let data_plane = c_after.0 && !b_after.0;

    let a_hex = sim.agent_hex("A")?;
    let signed_by_a = end.iter().all(|(_, seen)| {
        seen.as_ref()
            .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(a_hex.as_str()))
    });
    let h_once = excluded(&end, e0, leaves0) && all_at(&end, e0 + 1);
    let in_bound = reached_after.is_some_and(|after| after <= deadline);

    receipt.note(format!(
        "signer wanted A ({a_hex}) on every survivor: {signed_by_a}; {}; {}; {}",
        describe_all(&end),
        c_after.1,
        b_after.1
    ));
    receipt.note(format!(
        "control arm: H at {:?} after A's row sighting (bound {bound:?}); released hold: {}",
        reached_after,
        hold.describe()
    ));

    // The trigger reached its targets: the holders hold the record, and
    // at least one frame reached A after t = 0 (the held delivery).
    // Only the lanes the hold can delay count: stream writes toward A
    // pass undelayed, so they prove nothing about the held delivery.
    let mut toward_a = 0usize;
    for src in ["B", "D", "C"] {
        toward_a += sim
            .fabric()
            .delivered_writes_after(&sim.peer(src)?, &sim.peer("A")?, trigger)
            .iter()
            .filter(|(write, _)| {
                use crate::network::sim::LaneClass;
                // Only writes the hold delayed: sent before the floor, on a
                // lane the hold covers (stream writes pass undelayed).
                write.at < floor
                    && matches!(
                        write.lane.class,
                        LaneClass::Direct
                            | LaneClass::RelayedDm
                            | LaneClass::PubSub
                            | LaneClass::Bulk
                    )
            })
            .count();
    }
    let d_holds = sim
        .at_instant(
            "read D's revocations at the end",
            holds_revocation(sim, "D", &b_hex),
        )
        .await??;
    receipt.request_delivered(
        "holders_hold_b_and_frames_reached_a",
        d_holds && toward_a > 0,
        format!(
            "D holds B's revocation: {d_holds}; frames delivered toward A since t=0: {toward_a}"
        ),
        at(sim),
    );

    let passed = h_once && data_plane && signed_by_a && in_bound;
    if !passed {
        let moved_off_e0 = end.iter().any(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.epoch.is_some_and(|epoch| epoch > e0))
        });
        let (cause, ok, observed) = if !h_once && moved_off_e0 {
            (
                CAUSE_SECOND_ROTATION,
                true,
                format!("H at {reached_after:?}; {}", describe_all(&end)),
            )
        } else if h_once && !signed_by_a {
            (CAUSE_SIBLING_SIGNED, true, describe_all(&end))
        } else if h_once && signed_by_a && in_bound && !data_plane {
            (
                CAUSE_DATA_PLANE,
                true,
                format!("{}; {}", c_after.1, b_after.1),
            )
        } else if h_once && !in_bound {
            (
                CAUSE_OVER_BOUND,
                true,
                format!(
                    "H at {reached_after:?} after A's row sighting at {} us; {}",
                    row_seen.as_micros(),
                    describe_all(&end)
                ),
            )
        } else {
            let stalled = end.iter().all(|(_, seen)| {
                seen.as_ref()
                    .is_some_and(|seen| seen.lists_b && seen.epoch == Some(e0))
            });
            (CAUSE_NO_RECOVERY, stalled, describe_all(&end))
        };
        receipt.cause(cause, Some(observed), ok, at(sim));
    }
    receipt.finish(FINAL_CONTROL, passed, at(sim));
    Ok(())
}

/// The red arm: total A loss while D and C stay reachable. D waits out
/// W (no premature sibling), then its rank-1 fallback reaches H.
async fn loss_arm(sim: &mut Sim, receipt: &mut Receipt, labels: &[&str]) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let timing = S4Timing::default();
    let (group, b, e0, leaves0) = setup(sim, receipt, labels).await?;
    let b_hex = sim.agent_hex("B")?;
    let survivors = ["D", "C"];
    let w = timing.designated_window;

    // Total A loss from before t = 0 to the end.
    sim.set_online("A", false)?;
    sim.fabric()
        .mark("case: A offline (total loss) from before t=0");
    let t0 = sim.fabric().now();
    sim.fabric()
        .mark_indexed("case: t=0 trigger SelfRevoke (total A loss)");
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": b_hex, "reason": "w3h-1581b loss"})),
        )
        .await?;
    ensure!(status.is_success(), "B self-revokes: {status} {body}");
    await_holders(sim, &survivors, &b_hex).await?;

    // No premature sibling: at W/2 no survivor has rekeyed and none is
    // quarantined, and B is still listed (only the designated admin,
    // lost, may act before W).
    let half = t0.saturating_add(w / 2);
    let left = half.saturating_sub(sim.fabric().now());
    sim.within("wait to W/2", left + secs(2), async {
        tokio::time::sleep(left).await;
    })
    .await?;
    let mid = views(sim, &survivors, &group, &b).await?;
    receipt.note(format!("at W/2: {}", describe_all(&mid)));

    // The rank-1 fallback: D may start at T_obs + W; H within W plus the
    // completion bound from t = 0. The first epoch move is at or after W.
    let bound = w.saturating_add(timing.completion_bound);
    let mut first_move: Option<Duration> = None;
    let mut reached_after: Option<Duration> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the survivors reach H", bound + secs(5), async |s: &Sim| {
            let Some(now) = seen.observe(views_now(s, &survivors, &group, &b)).await else {
                return true;
            };
            let moved = now.iter().any(|(_, seen)| {
                seen.as_ref()
                    .is_some_and(|seen| seen.epoch.is_some_and(|epoch| epoch > e0))
            });
            if moved {
                first_move.get_or_insert(s.fabric().now().saturating_sub(t0));
            }
            let done = excluded(&now, e0, leaves0);
            if done {
                reached_after.get_or_insert(s.fabric().now().saturating_sub(t0));
            }
            done
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("the survivors reach H")?;
    sim.within("H settles", SETTLE + secs(2), async {
        tokio::time::sleep(SETTLE).await;
    })
    .await?;
    let end = views(sim, &survivors, &group, &b).await?;

    let (c_after, b_after) = match encrypt(sim, "D", &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "B", &group, &ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error.clone())),
    };
    let data_plane = c_after.0 && !b_after.0;

    let d_hex = sim.agent_hex("D")?;
    let signed_by_d = end.iter().all(|(_, seen)| {
        seen.as_ref()
            .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(d_hex.as_str()))
    });
    let h_once = excluded(&end, e0, leaves0) && all_at(&end, e0 + 1);
    let in_bound = reached_after.is_some_and(|after| after <= bound);
    let not_early = first_move.is_some_and(|moved| moved >= w);

    let mid_quiet = all_at(&mid, e0)
        && mid.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.lists_b && !seen.quarantined)
        });
    receipt.note(format!(
        "at W/2 (quiet {mid_quiet}): {}; first epoch move {first_move:?} after t=0 (rank-1 \
         fallback offset {:?}); signer wanted D ({d_hex}): {signed_by_d}; {}; {}; {}",
        describe_all(&mid),
        timing.fallback_offset(1),
        describe_all(&end),
        c_after.1,
        b_after.1
    ));
    let holders_at_end = sim
        .at_instant("read the holders' revocations at the end", async {
            Ok::<_, anyhow::Error>((
                holds_revocation(sim, "D", &b_hex).await?,
                holds_revocation(sim, "C", &b_hex).await?,
            ))
        })
        .await??;
    receipt.request_delivered(
        "holders_hold_b_revocation",
        holders_at_end.0 && holders_at_end.1,
        format!("D and C hold B's revocation record: {holders_at_end:?}"),
        at(sim),
    );

    let passed = h_once && data_plane && signed_by_d && in_bound && not_early && mid_quiet;
    if !passed {
        let (cause, ok, observed) = if !mid_quiet {
            (
                CAUSE_EARLY_SIBLING,
                true,
                format!("at W/2: {}", describe_all(&mid)),
            )
        } else if !h_once && first_move.is_some() {
            (
                CAUSE_SECOND_ROTATION,
                true,
                format!("first epoch move {first_move:?}; {}", describe_all(&end)),
            )
        } else if h_once && !signed_by_d {
            (CAUSE_NOT_SIGNED_BY_D, true, describe_all(&end))
        } else if h_once && signed_by_d && in_bound && !data_plane {
            (
                CAUSE_DATA_PLANE,
                true,
                format!("{}; {}", c_after.1, b_after.1),
            )
        } else if h_once && !in_bound {
            (
                CAUSE_FALLBACK_LATE,
                true,
                format!(
                    "H at {reached_after:?} after t=0; the bound is {bound:?}; {}",
                    describe_all(&end)
                ),
            )
        } else if h_once && !not_early {
            (
                CAUSE_EARLY_SIBLING,
                true,
                format!(
                    "first epoch move {first_move:?} after t=0, W is {w:?}; {}",
                    describe_all(&end)
                ),
            )
        } else {
            (
                CAUSE_NO_FALLBACK,
                end.iter().all(|(_, seen)| {
                    seen.as_ref()
                        .is_some_and(|seen| seen.lists_b && seen.epoch == Some(e0))
                }),
                describe_all(&end),
            )
        };
        receipt.cause(cause, Some(observed), ok, at(sim));
    }
    receipt.finish(FINAL_LOSS, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, labels: &[&str], arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 `s4_dropped_eager_frame`. Timing from S4Timing::default() \
         (measured; D69, D73): {:?}; retry floor {RETRY_FLOOR:?}.",
        S4Timing::default()
    ));
    match start(case, seed, labels).await {
        Ok(mut sim) => {
            let outcome = match arm {
                Arm::Control => control_arm(&mut sim, &mut receipt, labels).await,
                Arm::TotalLoss => loss_arm(&mut sim, &mut receipt, labels).await,
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
        Arm::TotalLoss => FINAL_LOSS,
    };
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(final_name);
    }
    receipt.emit();
    receipt
}

async fn expect_green(case: &str, seed: u64, labels: &[&str], arm: Arm) -> Result<()> {
    let receipt = run(case, seed, labels, arm).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// Which arm of the case runs.
#[derive(Clone, Copy, Debug)]
enum Arm {
    /// The recovered schedule: retry after the floor, A signs, no sibling.
    Control,
    /// Total A loss: D's rank-1 fallback after W.
    TotalLoss,
}

const LABELS: &[&str] = &["A", "D", "B", "C"];

/// ADR 0110 `s4_dropped_eager_frame`, control: the eager revocation and
/// hand-off frames toward A are held to the 1.5 s per-peer retry floor;
/// the recovered schedule seats one exclusion signed by the designated
/// admin A, with no premature sibling from D.
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
fn w3h_1581b_control_dropped_eager_frame_retry_floor() -> Result<()> {
    super::block_on_paused(async move {
        expect_green(
            "w3h_1581b_control_dropped_eager_frame_retry_floor",
            0x1581_0002,
            LABELS,
            Arm::Control,
        )
        .await
    })
}

/// ADR 0110 `s4_dropped_eager_frame`, the row's red arm: total A loss
/// while D and C remain reachable gives D's fallback after W, a
/// current-head sync and H (RED on pre-S4 `main`; GREEN with S4).
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
fn w3h_1581b_red_dropped_eager_frame_total_a_loss() -> Result<()> {
    super::block_on_paused(async move {
        expect_green(
            "w3h_1581b_red_dropped_eager_frame_total_a_loss",
            0x1581_0003,
            LABELS,
            Arm::TotalLoss,
        )
        .await
    })
}
