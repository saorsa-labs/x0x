//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_restart_stale_head`): A, D, B, C with A < D. A holds pending S4
//! work for B's self-revocation and is crash-stopped before any
//! exclusion; D's public remove API commits the exclusion while A is
//! down (queued as `waiting_for_designated_admin` naming A, then D's
//! rank-1 fallback after W); A restarts with the window expired and its
//! head stale, and the case holds every application frame toward A —
//! the row's delayed head catch-up — before it releases them. With S4
//! merged (#1357) both arms expect the ADR behaviour (GREEN): A never
//! seals from the stale head, its public S4 row exposes the typed
//! `waiting_for_head_sync` (D64) while the head is unsynced — also past
//! the restart sync wait, when catch-up stays unavailable — and the
//! learned exclusion then completes A's row with no second rotation.
//! The row's red line on pre-S4 `main` was that no resume was scheduled
//! and no typed state was shown; the cause strings stay for a
//! regression.
//!
//! Harness honesty, two departures the row needs stated plainly:
//!
//! - "Save pending work on A, stop it" is not reachable by crashing A
//!   right after its intake alone: A is the designated admin, and the
//!   §2 head round its intake pass opens confirms through any reachable
//!   holder (D or C answers its catch-up ask), so a healthy A seals
//!   within a worker tick or two of observing — even mid-shutdown. The
//!   case blocks only the direct and relayed-DM lanes between A and
//!   D/C — the round's ask path — while B stays connected to A, so
//!   B's self-revocation still reaches A and opens its row, but no
//!   holder can answer A's round: the row stays `pending` with the
//!   typed `waiting_for_head_sync` until the crash, deterministically.
//! - The row's "delay head catch-up until t = 500 ms" cannot be a
//!   fabric delay, because the fabric cannot delay stream lanes and
//!   TreeKEM catch-up pages ride streams. The case drops every frame
//!   toward A except plane-hello while held — including the gossip
//!   membership lane, which carries the named-group roster
//!   anti-entropy; a first run of this case passed that lane and A's
//!   roster caught up 160 ms after the restart, before any gate.
//!   Dropped frames are retried by the transport once the hold
//!   releases, which is the same observable contract, and the hold
//!   releases 500 ms after A's restart.
//!
//! The second arm covers the row's "No fallback before sync": inside
//! the restart sync wait the typed state is shown and nothing seals.
//! What main does past the wait under a total blackout — the same
//! `HeadRound::synced` wait branch, now on the restarted A, treats 13 s
//! of silence from holders it asked as a usable local head, so A seals
//! its stale head at about the sync wait — is recorded in the receipt
//! notes, not asserted: ADR 0110 §2 (L227) says a head that cannot be
//! established retains `waiting_for_head_sync` and forbids the sibling,
//! D73 as implemented ends discovery at the wait. Resolving that
//! tension needs a change in `revocation_eviction.rs`, which open PRs
//! fence; the remainder is named in #1581.
//!
//! Before t = 0 the ordinary `private_secure` (TreeKEM) group is
//! settled (every node at A's state revision r0 and epoch e0, four
//! leaves) and a data-plane probe opens on B and C; every node is past
//! its boot head gate. Healthy exit H: every survivor at exactly
//! e0 + 1 with three leaves, B not listed, no fork-quarantine, one
//! commit signed by D, and the data plane open on A and C and not on
//! B. Receipts use `w3h.receipt/1`.
//!
//! Arms:
//!
//! - `control_restart_stale_head_resume`: the hold releases 500 ms
//!   after the restart. During the hold A still runs on the stale head
//!   loaded from disk (r0, e0); A's public row waits with
//!   `waiting_for_head_sync`; after the release A catches up to D's
//!   commit, its row completes from the learned exclusion
//!   (`result_epoch` e0 + 1) and no second rotation follows
//!   ([`SETTLE`] later every survivor is still at e0 + 1, signed by
//!   D). A seal by A, or any epoch past e0 + 1, fails with
//!   [`CAUSE_STALE_SEAL`].
//! - `red_restart_stale_head_no_sync_no_early_seal`: the hold stays past
//!   the restart sync wait. Inside the window (read through 12 s) A's
//!   row exposes the typed `waiting_for_head_sync`, A's epoch is still
//!   e0 at the stale revision, and D's and C's revisions are unchanged
//!   since D's commit: the expired window alone authorizes nothing on
//!   an unrefreshed head before the sync wait ends. What A then does at
//!   the wait (see above) is recorded, and the release and the data
//!   plane are recorded with it. A missing typed state fails with
//!   [`CAUSE_NO_TYPED_STATE`]; an early seal fails with
//!   [`CAUSE_STALE_SEAL`].

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
/// After the resume, the case waits this long and re-reads, so a second
/// rotation (another epoch step) is seen.
const SETTLE: Duration = Duration::from_secs(30);
/// The row's delayed head catch-up: the hold toward A releases this
/// much virtual time after A's restart.
const CATCHUP_DELAY: Duration = Duration::from_millis(500);
/// The no-sync arm: the hold stays this far past the restart sync wait.
const PAST_WAIT: Duration = Duration::from_secs(5);
/// The stale-head read sits this far into the 500 ms catch-up delay.
const STALE_READ_AT: Duration = Duration::from_millis(250);
const PROBE: &[u8] = b"w3h-1581c probe";

const FINAL_RESUME: &str = "a_resumes_on_the_learned_exclusion_without_a_second_rotation";
const FINAL_NO_SYNC: &str =
    "a_shows_the_typed_head_sync_wait_and_seals_nothing_before_the_sync_wait";
const CAUSE_STALE_SEAL: &str = "A sealed from the stale head: after its restart A's epoch moved \
                                without a synced head, or a second rotation followed D's commit";
const CAUSE_NO_TYPED_STATE: &str = "no typed waiting_for_head_sync: A's public S4 row exposed no \
                                    cause while its head was stale";
const CAUSE_NO_COMPLETION: &str = "A never completed the learned exclusion: after the release \
                                   A's row stayed open, or its epoch never reached D's";
const CAUSE_NO_COMMIT: &str = "D's fallback never committed the exclusion while A was down: the \
                               remove was not queued as the typed wait naming A, or D and C \
                               never reached H signed by D";
const CAUSE_DATA_PLANE: &str = "A completed the learned exclusion with D's signer, but the data \
                                plane did not follow: A or C did not decrypt the new traffic, \
                                or B still could";
const CAUSE_SECOND_ROTATION: &str = "the exclusion was not exactly one rotation: a survivor moved \
                                     past e0 + 1, or D's and C's heads moved again, after D's \
                                     commit";
const CAUSE_EARLY_FALLBACK: &str = "D's fallback committed the exclusion before W while A was \
                                    down, without waiting out the designated window";

/// The first wait before a retry of a typed `retry: true` 424 reply; it
/// doubles per retry, up to [`RETRY_CAP`]. Virtual time.
const RETRY_FIRST: Duration = Duration::from_millis(250);
const RETRY_CAP: Duration = Duration::from_secs(2);

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

/// The structural part of H over the survivors' views.
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

/// Drops every frame toward `target` except plane-hello (QUIC link
/// liveness) while held, and counts them: direct, relayed DM, pubsub,
/// bulk, stream — and the gossip membership lane, which carries the
/// named-group roster anti-entropy (the 20–47 KB state frames; a first
/// run of this case passed that lane and A's roster caught up 160 ms
/// after the restart, before any S4 gate, so the hold must cover it).
/// With it covered, the restarted node reconnects and stays linked
/// while no group state — the roster, the revocation gossip, the
/// hand-off, the TreeKEM catch-up pages — reaches it: the row's
/// "delay head catch-up". (Built on the #1427 shape; the fabric cannot
/// delay stream lanes, so a drop with the transport's own retries is
/// the stream-safe expression of a delayed catch-up.)
struct InboundHold {
    held: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

impl InboundHold {
    fn install(sim: &Sim, target: &str) -> Result<Self> {
        use crate::network::sim::{Fault, LaneClass};
        use std::sync::atomic::Ordering;
        let machine = sim.peer(target)?.0;
        let held = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (rule_held, rule_dropped) = (Arc::clone(&held), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            let group_state = !matches!(write.lane.class, LaneClass::PlaneHello);
            if rule_held.load(Ordering::SeqCst) && write.lane.dst == machine && group_state {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { held, dropped })
    }

    fn set(&self, held: bool) {
        self.held.store(held, std::sync::atomic::Ordering::SeqCst);
    }

    fn dropped(&self) -> usize {
        self.dropped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Drops direct and relayed-DM frames in both directions between
/// `target` and each label in `others` while set: the §2 head round's
/// ask path, and the S4 hand-off. Everything else — the roster
/// anti-entropy on the gossip membership lane, the TreeKEM catch-up
/// pages, B's revocation record toward `target` — still flows, so the
/// group stays converged while `target`'s round can neither ask nor be
/// answered and its open S4 row cannot reach a seal.
struct DirectHold {
    set: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

impl DirectHold {
    fn install(sim: &Sim, target: &str, others: &[&str]) -> Result<Self> {
        use crate::network::sim::{Fault, LaneClass};
        use std::sync::atomic::Ordering;
        let machine = sim.peer(target)?.0;
        let mut peers = Vec::with_capacity(others.len());
        for label in others {
            peers.push(sim.peer(label)?.0);
        }
        let set = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (rule_set, rule_dropped) = (Arc::clone(&set), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            let dm = matches!(write.lane.class, LaneClass::Direct | LaneClass::RelayedDm);
            let between = (write.lane.src == machine && peers.contains(&write.lane.dst))
                || (write.lane.dst == machine && peers.contains(&write.lane.src));
            if rule_set.load(Ordering::SeqCst) && dm && between {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { set, dropped })
    }

    fn set(&self, held: bool) {
        self.set.store(held, std::sync::atomic::Ordering::SeqCst);
    }

    fn dropped(&self) -> usize {
        self.dropped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A `424 Failed Dependency` reply that names `retry: true` (for example
/// `member_key_package_pending`: the daemon requested the catch-up and
/// asks the client to retry).
fn typed_retry(status: StatusCode, body: &serde_json::Value) -> bool {
    status == StatusCode::FAILED_DEPENDENCY && body["retry"] == true
}

/// Send D's manual remove request. A typed `424 retry: true` reply is
/// retried with a doubling virtual-time wait, while the next attempt
/// still starts before `deadline`. Any other reply is returned as is:
/// the caller judges it. (The #1357 shape.)
async fn remove_retrying(
    sim: &Sim,
    group: &str,
    b_hex: &str,
    deadline: Duration,
) -> Result<(StatusCode, serde_json::Value, usize)> {
    let path = format!("/groups/{group}/members/{b_hex}");
    let mut retries = 0usize;
    let mut wait = RETRY_FIRST;
    loop {
        let (status, body) = sim.api("D", Method::DELETE, &path, None).await?;
        if !typed_retry(status, &body) || sim.fabric().now().saturating_add(wait) >= deadline {
            return Ok((status, body, retries));
        }
        retries += 1;
        sim.fabric().mark(format!(
            "case: D DELETE {path} -> 424 retry: true; retry in {wait:?}"
        ));
        sim.within("the typed-retry wait", wait + secs(1), async {
            tokio::time::sleep(wait).await;
        })
        .await?;
        wait = wait.saturating_mul(2).min(RETRY_CAP);
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
/// everyone seated, D promoted, settled at (r0, e0, leaves0), the probe
/// opens on B and C, D holds B's authority-signed KeyPackage, and every
/// node is past its restart sync wait. Returns (group, b, r0, e0,
/// leaves0).
async fn setup(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
) -> Result<(String, crate::identity::AgentId, u64, u64, u32)> {
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
    let b_hex = hex::encode(b.as_bytes());
    settled(sim, labels, &group, &b).await?;
    let base = view_now(sim, "A", &group, &b).await?;
    let r0 = base.state_revision;
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
    // D, the author of B's removal while A is down, must hold B's
    // KeyPackage by the remove route's own lookup. A miss here is
    // INFRA, not the S4 path.
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
        format!("r0={r0} e0={e0} leaves0={leaves0}; A {}", base.describe()),
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
    Ok((group, b, r0, e0, leaves0))
}

/// Both arms share one body: the crash with pending work, D's queued
/// removal and fallback commit, A's restart on the stale head, the held
/// catch-up (released per `arm`), the typed wait, and the resume.
async fn scenario(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
    no_sync_past_wait: bool,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let timing = S4Timing::default();
    let w = timing.designated_window;
    let sync_wait = timing.restart_sync_wait;
    let (group, b, r0, e0, leaves0) = setup(sim, receipt, labels).await?;
    let b_hex = sim.agent_hex("B")?;
    let a_hex = sim.agent_hex("A")?;
    let d_hex = sim.agent_hex("D")?;
    let survivors = ["A", "D", "C"];

    // The pending-work scaffold: the direct and relayed-DM lanes
    // between A and D/C — the §2 round's ask path — are dropped while B
    // stays connected to A, so the row B's revocation opens on A can
    // neither ask a holder nor be answered and cannot reach a seal
    // before the crash (a healthy designated A otherwise confirms its
    // round through D or C within a worker tick or two and seals; see
    // the module doc).
    let dm_hold = DirectHold::install(sim, "A", &["D", "C"])?;
    dm_hold.set(true);
    sim.fabric()
        .mark("fault: direct and relayed-DM frames between A and D/C dropped (round ask path)");

    // t = 0: B revokes its own agent; every other node observes.
    let t0 = sim.fabric().now();
    sim.fabric().mark_indexed("case: t=0 trigger SelfRevoke");
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": b_hex, "reason": "w3h-1581c"})),
        )
        .await?;
    ensure!(status.is_success(), "B self-revokes: {status} {body}");
    await_holders(sim, &["A", "D", "C"], &b_hex).await?;

    // The pending work is durable on A (its `.evs` row for B exists);
    // crash A before any exclusion (the row is created at intake, and
    // the crash races nothing: A is still at e0).
    sim.until("A's intake is durable", EVIDENCE, async |s: &Sim| {
        persisted_t_obs(s, "A", b.as_bytes()).is_ok_and(|t_obs| t_obs.is_some())
    })
    .await?;
    let at_crash = view_now(sim, "A", &group, &b).await?;
    let a_row_at_crash = sim
        .at_instant(
            "read A's public S4 row at the crash",
            s4_row(sim, "A", &group, &b_hex),
        )
        .await??;
    receipt.evidence(
        "a_holds_an_open_row_for_b_at_the_crash",
        at_crash.epoch == Some(e0) && at_crash.state_revision == r0 && a_row_at_crash.is_some(),
        format!(
            "A at the crash: {}; A's public S4 row for B: {a_row_at_crash:?}; DM frames dropped \
             between A and D/C: {}",
            at_crash.describe(),
            dm_hold.dropped()
        ),
        at(sim),
    );
    let pending_ok = a_row_at_crash
        .as_ref()
        .is_some_and(|row| row["phase"].as_str() == Some("pending"));
    receipt.note(format!(
        "A's row for B is still pending at the crash (the ask-path hold held): {pending_ok}"
    ));
    let hold = InboundHold::install(sim, "A")?;
    sim.stop("A", RestartMode::Crash).await?;
    dm_hold.set(false);
    sim.fabric()
        .mark("case: A crash-stopped with pending S4 work");

    // D's remove API: queued as the typed wait naming A, then D's
    // rank-1 fallback commits the exclusion while A is down.
    let bound = w.saturating_add(timing.completion_bound);
    let deadline = t0.saturating_add(bound);
    let (rm_status, rm_body, rm_retries) = remove_retrying(sim, &group, &b_hex, deadline).await?;
    let queued_typed = rm_body["waiting"]["cause"].as_str() == Some("waiting_for_designated_admin")
        && rm_body["waiting"]["designated_admin"]
            .as_str()
            .is_some_and(|named| named.eq_ignore_ascii_case(&a_hex));
    receipt.note(format!(
        "D DELETE members/{b_hex}: {rm_status} {rm_body} ({rm_retries} typed 424 retries); the \
         typed wait names A: {queued_typed}"
    ));

    // D's fallback reaches H on the survivors that stayed online.
    let mut seen = Observations::default();
    let mut d_first_move: Option<Duration> = None;
    let waited = sim
        .until("D and C reach H", bound + secs(5), async |s: &Sim| {
            let Some(now) = seen.observe(views_now(s, &["D", "C"], &group, &b)).await else {
                return true;
            };
            if d_first_move.is_none()
                && now.iter().any(|(_, seen)| {
                    seen.as_ref()
                        .is_some_and(|seen| seen.epoch.is_some_and(|epoch| epoch > e0))
                })
            {
                d_first_move = Some(s.fabric().now().saturating_sub(t0));
            }
            excluded(&now, e0, leaves0)
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("D and C reach H")?;
    let h1 = views(sim, &["D", "C"], &group, &b).await?;
    let h1_revision = h1
        .first()
        .and_then(|(_, seen)| seen.as_ref())
        .map(|seen| seen.state_revision);
    let signed_by_d = h1.iter().all(|(_, seen)| {
        seen.as_ref()
            .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(d_hex.as_str()))
    });
    receipt.note(format!(
        "D's fallback commit while A was down (signer wanted D ({d_hex})): {}",
        describe_all(&h1)
    ));

    // A restarts with the window expired and its head stale. Every
    // application frame toward A is dropped until the release point.
    let restart_at = sim.fabric().now();
    let window_expired = restart_at.saturating_sub(t0) >= w;
    let d_not_early = d_first_move.is_some_and(|moved| moved >= w);
    receipt.note(format!(
        "D's first epoch move {d_first_move:?} after t=0 (W is {w:?}, so not early: \
         {d_not_early}); A restarts {} us after t=0 (the window expired: {window_expired})",
        restart_at.saturating_sub(t0).as_micros()
    ));
    let mut a_authored = false;
    let mut sealed_early: Option<Duration> = None;
    let mut typed_observed = false;
    hold.set(true);
    sim.fabric()
        .mark("fault: every application frame toward A dropped (stale-head hold)");
    sim.start_again("A").await?;
    sim.until("A reconnects", SETUP, async |s: &Sim| {
        connected_to(s, "A", "D").await || connected_to(s, "A", "C").await
    })
    .await?;

    // Inside the catch-up delay: A still runs on the head it loaded
    // from disk (r0, e0) — the stale head.
    sim.within(
        "wait into the catch-up delay",
        STALE_READ_AT + secs(1),
        async {
            tokio::time::sleep(STALE_READ_AT).await;
        },
    )
    .await?;
    let stale = view_now(sim, "A", &group, &b).await?;
    let stale_ok = stale.epoch == Some(e0) && stale.state_revision == r0;
    // A seal inside the hold would already show here: the watch starts at
    // this read, not only after the release.
    if stale.epoch.is_some_and(|epoch| epoch > e0) {
        a_authored |= stale.head_committed_by.as_deref() == Some(a_hex.as_str());
        sealed_early.get_or_insert(sim.fabric().now().saturating_sub(restart_at));
    }
    // A first typed sample during the hold, so a quick clear after the
    // release cannot hide the state.
    if let Ok(Some(row)) = s4_row(sim, "A", &group, &b_hex).await {
        typed_observed |= row["waiting"]["cause"].as_str() == Some("waiting_for_head_sync");
    }
    receipt.note(format!(
        "read {} us after the restart (hold still set; stale head loaded {stale_ok}): A {}; \
         frames dropped toward A: {}",
        sim.fabric().now().saturating_sub(restart_at).as_micros(),
        stale.describe(),
        hold.dropped()
    ));

    // The no-sync arm's gated window: through `sync_wait - 1 s` the
    // typed `waiting_for_head_sync` is shown (polled from the first
    // passes after the restart, while the boot head gate holds) and
    // nothing seals — A keeps the stale head and D/C keep D's commit.
    // What main does past the wait under the total blackout (the
    // `HeadRound::synced` wait branch treats the elapsed sync wait alone
    // as a usable local head; see the module doc) is recorded below,
    // not asserted.
    let mut typed_detail = String::new();
    let mut window_quiet = false;
    let mut unchanged_at_window = false;
    if no_sync_past_wait {
        let mut typed_seen_at: Option<Duration> = None;
        let window = sync_wait.saturating_sub(Duration::from_secs(1));
        // The watch runs the whole window (it ends at the boundary, not
        // at the first typed sighting), so a seal at any point inside it
        // is seen.
        let waited = sim
            .until(
                "watch A through the pre-wait window",
                window + secs(2),
                async |s: &Sim| {
                    let elapsed = s.fabric().now().saturating_sub(restart_at);
                    let view = try_view_now(s, "A", &group, &b).await.ok().flatten();
                    if view.as_ref().is_some_and(|seen| {
                        seen.epoch.is_some_and(|epoch| epoch != e0) || seen.state_revision != r0
                    }) {
                        sealed_early.get_or_insert(elapsed);
                    }
                    if let Ok(Some(row)) = s4_row(s, "A", &group, &b_hex).await {
                        if row["waiting"]["cause"].as_str() == Some("waiting_for_head_sync") {
                            typed_seen_at.get_or_insert(elapsed);
                        }
                    }
                    elapsed >= window
                },
            )
            .await;
        if let Err(error) = waited {
            if !expired(&error) {
                return Err(error);
            }
        }
        let others_now = views_now(sim, &["D", "C"], &group, &b).await?;
        let unchanged = h1_revision.is_some_and(|want| {
            others_now.iter().all(|(_, seen)| {
                seen.as_ref()
                    .is_some_and(|seen| seen.state_revision == want && seen.epoch == Some(e0 + 1))
            })
        });
        typed_detail = format!(
            "typed wait first seen {typed_seen_at:?} after the restart; A left the stale head \
             {sealed_early:?} after the restart; D/C revisions unchanged \
             since D's commit: {unchanged}; frames dropped toward A: {}",
            hold.dropped()
        );
        typed_observed |= typed_seen_at.is_some();
        unchanged_at_window = unchanged;
        window_quiet = typed_seen_at.is_some() && sealed_early.is_none() && unchanged;
        receipt.note(format!(
            "inside the pre-wait window (quiet {window_quiet}): {typed_detail}"
        ));
        // Record (not assert) what main does past the sync wait under
        // the blackout, and A's own seal state at that instant.
        let read_at = restart_at
            .saturating_add(sync_wait)
            .saturating_add(PAST_WAIT);
        let left = read_at.saturating_sub(sim.fabric().now());
        sim.within("wait past the restart sync wait", left + secs(2), async {
            tokio::time::sleep(left).await;
        })
        .await?;
        let row = sim
            .at_instant(
                "read A's public S4 row past the sync wait",
                s4_row(sim, "A", &group, &b_hex),
            )
            .await??;
        let a_past = view_now(sim, "A", &group, &b).await?;
        let probe = match sim.state("A") {
            Ok(state) => {
                crate::server::routes::named_groups::s4_seal_probe_for_test(&state, &group, &b_hex)
                    .await
            }
            Err(error) => format!("{error:#}"),
        };
        receipt.note(format!(
            "past the sync wait under the total blackout (recorded, not asserted — see the module \
             doc): A {}; row {row:?}; seal probe: {probe}",
            a_past.describe()
        ));
    }
    let release_at = if no_sync_past_wait {
        sim.fabric().now()
    } else {
        let target = restart_at.saturating_add(CATCHUP_DELAY);
        let left = target.saturating_sub(sim.fabric().now());
        sim.within("wait to the catch-up release", left + secs(1), async {
            tokio::time::sleep(left).await;
        })
        .await?;
        sim.fabric().now()
    };
    hold.set(false);
    sim.fabric().mark(format!(
        "case: stale-head hold released at {} us ({} frames dropped)",
        release_at.as_micros(),
        hold.dropped()
    ));

    // While A's head was unsynced its public row exposed the typed
    // `waiting_for_head_sync` (D64). The resume arm polls for it after
    // the release — the boot head gate keeps the head unsynced for the
    // restart sync wait, so the typed state is still there; the no-sync
    // arm read it at the fixed instant above.
    let mut observed = false;
    if !no_sync_past_wait {
        let waited = sim
            .until(
                "A's row waits for head sync",
                sync_wait,
                async |s: &Sim| match s4_row(s, "A", &group, &b_hex).await {
                    Ok(Some(row)) => {
                        observed |=
                            row["waiting"]["cause"].as_str() == Some("waiting_for_head_sync");
                        row["waiting"]["cause"].as_str() == Some("waiting_for_head_sync")
                    }
                    Ok(None) => false,
                    Err(_) => false,
                },
            )
            .await;
        if let Err(error) = waited {
            if !expired(&error) {
                return Err(error);
            }
        }
        typed_observed |= observed;
        receipt.note(format!(
            "A exposed the typed waiting_for_head_sync while unsynced (observed {observed}); \
             polled after the release at {} us; frames dropped toward A while held: {}",
            release_at.as_micros(),
            hold.dropped()
        ));
    }

    // The resume: A catches up to D's commit and its row completes from
    // the learned exclusion — no second rotation. On the no-sync arm
    // this is recorded, not gated (past the sync wait main's behaviour
    // is the design question the module doc names).
    let converge_bound = sync_wait.saturating_add(timing.completion_bound);
    let mut converged = false;
    // "No fallback before sync", watched continuously on the resume arm
    // too: A authoring an exclusion commit at any point (a stale-head
    // seal that fork resolution might later paper over) is seen here,
    // not only in the end read. The watch began at the stale-head read,
    // inside the hold.
    let waited = sim
        .until(
            "A completes the learned exclusion",
            converge_bound + secs(5),
            async |s: &Sim| {
                if let Ok(Some(seen)) = try_view_now(s, "A", &group, &b).await {
                    if seen.head_committed_by.as_deref() == Some(a_hex.as_str())
                        && seen.epoch.is_some_and(|epoch| epoch > e0)
                    {
                        a_authored = true;
                    }
                }
                let caught_up = view_now(s, "A", &group, &b)
                    .await
                    .is_ok_and(|seen| seen.epoch == Some(e0 + 1));
                let done = caught_up
                    && matches!(
                        s4_row(s, "A", &group, &b_hex).await,
                        Ok(Some(row)) if row["phase"].as_str() == Some("complete")
                    );
                if done {
                    converged = true;
                }
                done
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    sim.within("the resume settles", SETTLE + secs(2), async {
        tokio::time::sleep(SETTLE).await;
    })
    .await?;
    let end = views(sim, &survivors, &group, &b).await?;
    let final_row = sim
        .at_instant("read A's completed row", s4_row(sim, "A", &group, &b_hex))
        .await?;
    let completed = final_row.as_ref().is_ok_and(|row| {
        row.as_ref().is_some_and(|row| {
            row["phase"].as_str() == Some("complete")
                && row["result_epoch"].as_u64() == Some(e0 + 1)
        })
    });
    let h_once = excluded(&end, e0, leaves0) && all_at(&end, e0 + 1);
    let still_signed_by_d = end.iter().all(|(_, seen)| {
        seen.as_ref()
            .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(d_hex.as_str()))
    });

    // Data plane after the resume: a survivor's new ciphertext opens on
    // A and C, and not on B.
    let (a_after, c_after, b_after) = match encrypt(sim, "D", &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "A", &group, &ciphertext).await?,
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "B", &group, &ciphertext).await?,
        ),
        Err(error) => (
            (false, error.clone()),
            (false, error.clone()),
            (false, error),
        ),
    };
    let data_plane = a_after.0 && c_after.0 && !b_after.0;

    if no_sync_past_wait {
        receipt.note(format!(
            "after the release (recorded, not asserted): converged {converged}; A's row \
             {final_row:?}; {}; A decrypt: {}; C decrypt: {}; B decrypt: {}",
            describe_all(&end),
            a_after.1,
            c_after.1,
            b_after.1
        ));
    } else {
        receipt.note(format!(
            "A completed the learned exclusion: row {final_row:?}; A authored an exclusion \
             commit itself: {a_authored}; {}; {}; {}; {}",
            describe_all(&end),
            a_after.1,
            c_after.1,
            b_after.1
        ));
    }
    receipt.request_delivered(
        "d_remove_b_request_answered",
        true,
        format!(
            "D's remove of B answered {rm_status} ({rm_retries} typed 424 retries); the typed \
             queue names A: {queued_typed}; D's commit signed on every survivor: {signed_by_d}"
        ),
        at(sim),
    );

    let passed = if no_sync_past_wait {
        queued_typed
            && excluded(&h1, e0, leaves0)
            && signed_by_d
            && pending_ok
            && window_expired
            && d_not_early
            && window_quiet
    } else {
        queued_typed
            && excluded(&h1, e0, leaves0)
            && signed_by_d
            && pending_ok
            && window_expired
            && d_not_early
            && stale_ok
            && typed_observed
            && completed
            && h_once
            && still_signed_by_d
            && !a_authored
            && data_plane
    };
    if !passed {
        let (cause, ok, observed) = if !queued_typed || !excluded(&h1, e0, leaves0) || !signed_by_d
        {
            (
                CAUSE_NO_COMMIT,
                true,
                format!(
                    "D's remove {rm_status} {rm_body}; at D's commit: {}",
                    describe_all(&h1)
                ),
            )
        } else if !d_not_early {
            (
                CAUSE_EARLY_FALLBACK,
                true,
                format!("D's first epoch move {d_first_move:?} after t=0; W is {w:?}"),
            )
        } else if !stale_ok && !no_sync_past_wait {
            (
                CAUSE_STALE_SEAL,
                true,
                "A had already left the stale head at the first read after the restart".to_string(),
            )
        } else if no_sync_past_wait && sealed_early.is_some() {
            (
                CAUSE_STALE_SEAL,
                true,
                format!(
                    "A left the stale head {sealed_early:?} after the restart, before the sync \
                     wait ended; {typed_detail}"
                ),
            )
        } else if no_sync_past_wait && !unchanged_at_window {
            (CAUSE_SECOND_ROTATION, true, typed_detail.clone())
        } else if (!still_signed_by_d || a_authored) && !no_sync_past_wait {
            (CAUSE_STALE_SEAL, true, describe_all(&end))
        } else if !h_once && !no_sync_past_wait {
            (CAUSE_SECOND_ROTATION, true, describe_all(&end))
        } else if completed
            && h_once
            && still_signed_by_d
            && !a_authored
            && !data_plane
            && !no_sync_past_wait
        {
            (
                CAUSE_DATA_PLANE,
                true,
                format!("{}; {}; {}", a_after.1, c_after.1, b_after.1),
            )
        } else if !completed && !no_sync_past_wait {
            (
                CAUSE_NO_COMPLETION,
                true,
                format!("A's row {final_row:?}; {}", describe_all(&end)),
            )
        } else {
            (
                CAUSE_NO_TYPED_STATE,
                !typed_observed,
                format!("A's row {final_row:?}; {typed_detail}"),
            )
        };
        receipt.cause(cause, Some(observed), ok, at(sim));
    }
    let final_name = if no_sync_past_wait {
        FINAL_NO_SYNC
    } else {
        FINAL_RESUME
    };
    receipt.finish(final_name, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, labels: &[&str], no_sync_past_wait: bool) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 `s4_restart_stale_head`. Timing from S4Timing::default() \
         (measured; D69, D73): {:?}; catch-up delay {CATCHUP_DELAY:?}.",
        S4Timing::default()
    ));
    match start(case, seed, labels).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, labels, no_sync_past_wait).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    let final_name = if no_sync_past_wait {
        FINAL_NO_SYNC
    } else {
        FINAL_RESUME
    };
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(final_name);
    }
    receipt.emit();
    receipt
}

async fn expect_green(
    case: &str,
    seed: u64,
    labels: &[&str],
    no_sync_past_wait: bool,
) -> Result<()> {
    let receipt = run(case, seed, labels, no_sync_past_wait).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

const LABELS: &[&str] = &["A", "D", "B", "C"];

/// ADR 0110 `s4_restart_stale_head`, control + red resume: A restarts
/// on the stale head with the window expired; nothing seals before the
/// head sync, and the learned exclusion completes A's row with no
/// second rotation.
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
fn w3h_1581c_control_restart_stale_head_resume() -> Result<()> {
    super::block_on_paused(async move {
        expect_green(
            "w3h_1581c_control_restart_stale_head_resume",
            0x1581_0004,
            LABELS,
            false,
        )
        .await
    })
}

/// ADR 0110 `s4_restart_stale_head`, the row's second run, its
/// "no fallback before sync" leg: with the head catch-up unavailable,
/// A shows the typed `waiting_for_head_sync` and seals nothing through
/// the restart sync wait. What main does past the wait (it seals the
/// stale head; see the module doc) is recorded, not asserted.
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
fn w3h_1581c_red_restart_stale_head_no_sync_no_early_seal() -> Result<()> {
    super::block_on_paused(async move {
        expect_green(
            "w3h_1581c_red_restart_stale_head_no_sync_no_early_seal",
            0x1581_0005,
            LABELS,
            true,
        )
        .await
    })
}
