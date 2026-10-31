//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_crash_commit_fallback`): A, D, B, C with D < A. The designated
//! admin D is crash-stopped before t = 0, so A is the rank-1 admin for
//! B's self-revocation: it waits out the designated window W with its
//! §2 head round confirmed through the survivor C, and at its fallback
//! time it commits the exclusion durably with its publication lost —
//! the row's crash window, "crash A after durable exclusion before
//! publish" — because from the confirmed round on, every frame A sends
//! toward B or C is dropped: the roster volley and the direct removal
//! deliveries of A's commit never reach a peer. A is then crash-stopped
//! with the row `committed_delivery_pending`. The two arms cover §3's
//! two restart outcomes of a saved delivery-pending row:
//!
//! - the fork arm: while A is down, D is restarted and, as the
//!   designated admin, commits a competing exclusion from the same
//!   parent head (A's commit never reached anyone); the restarted A
//!   must keep the saved event as fork evidence, expose the typed
//!   `waiting_for_fork_resolution` (D64) with the manual-resolution
//!   quarantine marker, and publish no saved sibling (D and C stay on
//!   D's single commit, unquarantined; A's divergent key cannot claim H
//!   across the real fork). On `main` the containment half is green —
//!   the stale-replica protection (an unknown holder head conflicts the
//!   round) withholds the resend — but the typed half is RED: A's row
//!   silently completes across the real fork, no fork evidence is
//!   persisted and no `waiting_for_fork_resolution` is shown, which
//!   ADR 0110 §3 (L225–L227) forbids. The arm is wired as an expected
//!   RED with `CAUSE_NO_TYPED_FORK` — the only cause this arm accepts
//!   as its RED (the test checks the cause, not only the verdict) — and
//!   it turns GREEN with that fix. The gap is recorded on #1581 by
//!   name. A sibling that a receiver keeps fails the end-state
//!   evidence (INFRA); a sibling sighting the receivers refuse names
//!   `CAUSE_SIBLING_PUBLISHED`, which also fails the arm's cause
//!   check. A neutralisation of the conflicting-report protection
//!   (never committed) does not change the outcome on main: the
//!   receivers' own validation still refuses the stale-rotation event,
//!   so the observed RED is anchored in the typed-state gap itself.
//! - the resume arm: no competing commit exists (D stays down). A
//!   restarts and finishes the eligible delivery of its saved event
//!   without another rekey; once D returns onto the compatible chain,
//!   A's and D's rows close and every survivor converges on A's commit.
//!   GREEN on `main`.
//!
//! Harness honesty, six departures stated plainly:
//!
//! - The committer that crashes is the rank-1 fallback, not the
//!   designated admin the row's cast names, and the designated seat is
//!   held down through the window. A designated admin that is online
//!   seals within a worker tick of its round confirming — faster than
//!   any fabric fault can be armed around its publication — so the
//!   case reaches the same crash window (a durable exclusion whose
//!   publication is lost) through the §2 fallback path instead: A
//!   waits out W with a confirmed round, and the blackout is armed
//!   only after the production `s4_seal_probe_for_test` shows
//!   `confirmed=true`, so the seal that follows never rests on the
//!   elapsed-time branch of `HeadRound::synced` (the #1698 finding,
//!   fenced under #1627) and stays green when that fix lands.
//! - The publication loss is a receiver-side blackout, not a stopped
//!   publisher: the frames leave A and are dropped by the fabric, from
//!   the confirmed round on — after the ask and its answer, before any
//!   publication, with the whole designated window as margin. The
//!   observable contract — A's exclusion is durable on A and no peer
//!   ever received it — is the crash the row names, with no production
//!   seam. `RestartMode::Crash` remains the in-process model 1581c
//!   documents: tasks drain and file writes complete, but the node is
//!   off the fabric from the stop mark, so nothing leaves after it.
//! - "Deliver D's head/proof before releasing A's resend" is made
//!   deterministic by a margin, not by a fabric hold: D commits, D and
//!   C converge, and ten more virtual seconds pass before A restarts,
//!   so A's boot head round asks holders that already hold the
//!   competing commit and its answers name it. Without the margin the
//!   boot ask races D's commit — a confirmed round never re-asks, and
//!   the resend gate would open blind (that shape is exactly what the
//!   neutralised proof shows). The blackout is released at A's
//!   restart, so nothing fabric-side stops a resend.
//! - The row's "advance D past W" is carried by A, not D: A is the
//!   rank-1 admin that waits out the designated window before its
//!   fallback commits, while the restarted D — the designated admin —
//!   commits straight after its own boot gate, which is its §2 right.
//!   D's own wait-past-W fallback flow is 1581c's D path and is not
//!   duplicated here.
//! - The resume arm restarts D only after A's saved delivery has
//!   converged with C: a committed row stays open while a survivor is
//!   down, so D's return is what closes the rows. D's own row is not
//!   this arm's outcome — the restarted D may first wait for B's
//!   KeyPackage (`waiting_for_member_key_package`, the #1567 cache
//!   loss) before its row closes on its own.
//! - The fork arm crash-stops A a second time once the outcome has
//!   settled, and takes its final reads after that restart, so §3's
//!   "fork evidence and typed manual-resolution exit survive" is
//!   asserted across a restart, not only in memory: the typed
//!   `waiting_for_fork_resolution` and the public `fork_quarantine`
//!   marker must both still be there.
//!
//! Before t = 0 the ordinary `private_secure` (TreeKEM) group is
//! settled (every node at A's state revision r0 and epoch e0, four
//! leaves) and a data-plane probe opens on B and C; every node is past
//! its boot head gate. Healthy exit H (the survivors that stay on the
//! committing chain): exactly e0 + 1 with three leaves, B not listed,
//! no fork-quarantine, one commit by the sealing admin, and the data
//! plane open on the survivors and not on B. Receipts use
//! `w3h.receipt/1`.

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
/// Budget for A's rank-1 fallback window plus the commit.
const FALLBACK: Duration = Duration::from_secs(60);
/// After the outcome, the case waits this long and re-reads, so a later
/// rotation or a late sibling is seen.
const SETTLE: Duration = Duration::from_secs(30);
const PROBE: &[u8] = b"w3h-1581e probe";

const FINAL_FORK: &str = "a_publishes_no_saved_sibling_and_waits_typed_for_fork_resolution";
const FINAL_RESUME: &str = "a_finishes_the_saved_delivery_on_the_same_chain_without_a_rekey";
const CAUSE_NO_DURABLE_COMMIT: &str = "A never reached the durable exclusion before the crash: \
                                       its public row stayed short of \
                                       committed_delivery_pending, or its epoch never moved";
const CAUSE_EARLY_FALLBACK: &str = "A's fallback committed the exclusion before W, without \
                                    waiting out the designated window";
const CAUSE_LEAKED_COMMIT: &str = "A's exclusion reached B or C before the crash: the blackout \
                                   did not cover the publication, so no fork exists to contain";
const CAUSE_NO_D_COMMIT: &str = "D never committed the competing exclusion while A was down: D \
                                 and C did not reach H signed by D after D's restart";
const CAUSE_NO_TYPED_FORK: &str = "no typed waiting_for_fork_resolution: after D's competing \
                                   commit reached the restarted A, its public S4 row exposed no \
                                   cause while it held an undelivered saved exclusion";
const CAUSE_SIBLING_PUBLISHED: &str = "a competing sibling was published across the restart: a \
                                       node took the other admin's commit, or left the one \
                                       exclusion it had settled on";
const CAUSE_SECOND_ROTATION: &str = "the exclusion was not exactly one rotation: a node moved \
                                     past e0 + 1 after the outcome";
const CAUSE_NO_RESUME: &str = "A never finished the saved delivery on the same chain: its row \
                               stayed open, or C never reached A's commit";
const CAUSE_DATA_PLANE: &str = "the commits converged but the data plane did not follow: a \
                                survivor did not decrypt the new traffic, or B still could";

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

/// The structural part of H over the given views.
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

/// Whether `label`'s public group status carries the fork-quarantine
/// marker — the persisted fork evidence and ADR 0088 §2 item 7's
/// manual-resolution exit, surfaced as `fork_quarantine` in
/// `GET /groups/:id`.
async fn fork_quarantine_present(sim: &Sim, label: &str, group: &str) -> Result<bool> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(!body["fork_quarantine"].is_null())
}

/// The production S4 seal-probe diagnostic for `target` on `label`
/// (read-only; it names the §2 head round's `confirmed` state, which no
/// public API exposes).
async fn seal_probe(sim: &Sim, label: &str, group: &str, target_hex: &str) -> Result<String> {
    let state = sim.state(label)?;
    Ok(
        crate::server::routes::named_groups::s4_seal_probe_for_test(&state, group, target_hex)
            .await,
    )
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

/// The publication blackout: while set, every frame `target` sends
/// toward any label in `others` is dropped, on every lane except
/// plane-hello. Frames toward `target` always flow, so the §2 round's
/// answer — and, later, D's head and proof — reach it. Armed only after
/// the production seal probe shows the round `confirmed=true`, so the
/// ask and its answer have passed and nothing `target` still needs to
/// send is lost: what dies is exactly the publication of the durable
/// exclusion that follows, which is the row's crash window, with no
/// production seam.
struct SenderBlackout {
    set: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

impl SenderBlackout {
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
            if rule_set.load(Ordering::SeqCst)
                && write.lane.src == machine
                && peers.contains(&write.lane.dst)
                && !matches!(write.lane.class, LaneClass::PlaneHello)
            {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                return Fault::Drop;
            }
            Fault::Pass
        });
        Ok(Self { set, dropped })
    }

    fn set(&self, on: bool) {
        self.set.store(on, std::sync::atomic::Ordering::SeqCst);
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

/// Send `caller`'s manual remove request for B. A typed `424 retry:
/// true` reply is retried with a doubling virtual-time wait, while the
/// next attempt still starts before `deadline`. Any other reply is
/// returned as is: the caller judges it. (The #1357 shape.)
async fn remove_retrying(
    sim: &Sim,
    caller: &str,
    group: &str,
    b_hex: &str,
    deadline: Duration,
) -> Result<(StatusCode, serde_json::Value, usize)> {
    let path = format!("/groups/{group}/members/{b_hex}");
    let mut retries = 0usize;
    let mut wait = RETRY_FIRST;
    loop {
        let (status, body) = sim.api(caller, Method::DELETE, &path, None).await?;
        if !typed_retry(status, &body) || sim.fabric().now().saturating_add(wait) >= deadline {
            return Ok((status, body, retries));
        }
        retries += 1;
        sim.fabric().mark(format!(
            "case: {caller} DELETE {path} -> 424 retry: true; retry in {wait:?}"
        ));
        sim.within("the typed-retry wait", wait + secs(1), async {
            tokio::time::sleep(wait).await;
        })
        .await?;
        wait = wait.saturating_mul(2).min(RETRY_CAP);
    }
}

/// Start the four nodes. D and A get the two pre-generated key pairs
/// sorted by agent id, so D < A (B and C keep theirs): D is the
/// designated admin the case holds down, A the rank-1 fallback that
/// reaches the crash window. The swap happens before any daemon runs.
async fn start(case: &str, seed: u64, labels: &[&str]) -> Result<Sim> {
    let mut sim = Sim::empty(case, seed, labels)?;
    let ranked = ["D", "A"];
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
        .mark("case: admin keys reassigned so that D < A by agent id");
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
    // D, the author of the competing exclusion after its restart in the
    // fork arm, must hold B's KeyPackage by the remove route's own
    // lookup before the case stops it. A miss here is INFRA.
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
        "admins_rank_d_before_a",
        order == ["D", "A"],
        format!("admin agent-id order {order:?}"),
        at(sim),
    );

    // ADR 0110 §2: no S4 seal before a node's restart sync wait from
    // process start has passed (D73), so t = 0 measures the S4 path.
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

/// Both arms share one body: the designated seat held down, A's
/// confirmed-round fallback committed into the blackout, A's crash,
/// then per `competing` either D's restarted sibling with A's
/// fork-contained restart, or A's same-chain resume.
async fn scenario(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
    competing: bool,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let timing = S4Timing::default();
    let w = timing.designated_window;
    let sync_wait = timing.restart_sync_wait;
    let (group, b, r0, e0, leaves0) = setup(sim, receipt, labels).await?;
    let b_hex = sim.agent_hex("B")?;
    let a_hex = sim.agent_hex("A")?;
    let d_hex = sim.agent_hex("D")?;

    // The designated seat is held down before the trigger, so A is the
    // rank-1 admin for the row B's revocation opens (D74: designation
    // follows the roster, not reachability).
    sim.stop("D", RestartMode::Crash).await?;
    sim.fabric()
        .mark("case: D, the designated admin, crash-stopped before t=0");

    // t = 0: B revokes its own agent; A and C observe.
    let t0 = sim.fabric().now();
    sim.fabric().mark_indexed("case: t=0 trigger SelfRevoke");
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": b_hex, "reason": "w3h-1581e"})),
        )
        .await?;
    ensure!(status.is_success(), "B self-revokes: {status} {body}");
    let revoke_reply = format!("B POST /identity/revoke: {status} {body}");
    await_holders(sim, &["A", "C"], &b_hex).await?;

    // A's §2 head round confirms through C (the only reachable holder:
    // D is down, B is the open target). The production seal probe names
    // the round's `confirmed` state; the blackout is armed only once it
    // holds, so the fallback seal that follows rests on a confirmed
    // round — never the elapsed-time branch — and every publication of
    // A's later commit dies in the blackout.
    let mut probe_at_arm = String::new();
    let waited = sim
        .until(
            "A's head round confirms through C",
            EVIDENCE,
            async |s: &Sim| match seal_probe(s, "A", &group, &b_hex).await {
                Ok(probe) => {
                    let confirmed = probe.contains("confirmed=true");
                    if confirmed {
                        probe_at_arm.clone_from(&probe);
                    }
                    confirmed
                }
                Err(_) => false,
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    ensure!(
        probe_at_arm.contains("confirmed=true"),
        "A's round never confirmed through C; probe: {probe_at_arm}"
    );
    let blackout = SenderBlackout::install(sim, "A", &["B", "C"])?;
    blackout.set(true);
    sim.fabric()
        .mark("fault: every frame A sends toward B or C dropped (the publication blackout)");
    receipt.evidence(
        "a_round_confirmed_before_the_blackout",
        probe_at_arm.contains("confirmed=true"),
        format!("A's seal probe at the blackout: {probe_at_arm}"),
        at(sim),
    );

    // A's manual remove of the S4 target, as the rank-1 admin inside the
    // window: queued with the typed wait naming the down designated D.
    let deadline = t0.saturating_add(w.saturating_add(timing.completion_bound));
    let (rm_status, rm_body, rm_retries) =
        remove_retrying(sim, "A", &group, &b_hex, deadline).await?;
    let queued_typed = rm_body["waiting"]["cause"].as_str() == Some("waiting_for_designated_admin")
        && rm_body["waiting"]["designated_admin"]
            .as_str()
            .is_some_and(|named| named.eq_ignore_ascii_case(&d_hex));
    // A premise of the arm, recorded as evidence so its failure is INFRA,
    // not a RED the gate's expected-verdict pin would satisfy.
    receipt.evidence(
        "a_manual_remove_queues_typed_naming_the_down_designated",
        queued_typed,
        format!("A DELETE members/{b_hex}: {rm_status} {rm_body} ({rm_retries} typed 424 retries)"),
        at(sim),
    );
    let remove_reply = format!(
        "A DELETE members/{b_hex}: {rm_status} {rm_body} ({rm_retries} typed 424 retries); the \
         typed queue names the down designated D: {queued_typed}"
    );

    // A's rank-1 fallback commits the exclusion at T_obs + W: durable on
    // A (its public row `committed_delivery_pending`, its epoch e0 + 1,
    // its head committed by A) while its publication dies in the
    // blackout. The commit must not precede the window.
    let mut a_commit_at: Option<Duration> = None;
    let waited = sim
        .until(
            "A's fallback commits into the blackout",
            FALLBACK,
            async |s: &Sim| {
                let committed = matches!(
                    s4_row(s, "A", &group, &b_hex).await,
                    Ok(Some(row)) if row["phase"].as_str() == Some("committed_delivery_pending")
                ) && try_view_now(s, "A", &group, &b).await.is_ok_and(|seen| {
                    seen.is_some_and(|seen| seen.epoch == Some(e0 + 1) && !seen.lists_b)
                });
                if committed && a_commit_at.is_none() {
                    a_commit_at = Some(s.fabric().now().saturating_sub(t0));
                }
                committed
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    let a_committed = view_now(sim, "A", &group, &b).await?;
    let a_row_committed = sim
        .at_instant(
            "read A's public S4 row at the crash window",
            s4_row(sim, "A", &group, &b_hex),
        )
        .await??;
    let durable = a_committed.epoch == Some(e0 + 1)
        && a_committed.state_revision == r0 + 1
        && a_committed.head_committed_by.as_deref() == Some(a_hex.as_str())
        && !a_committed.lists_b
        && a_row_committed
            .as_ref()
            .is_some_and(|row| row["phase"].as_str() == Some("committed_delivery_pending"));
    let not_early = a_commit_at.is_some_and(|at| at >= w);
    receipt.evidence(
        "a_commits_durably_into_the_blackout",
        durable && not_early && blackout.dropped() > 0,
        format!(
            "A at the crash window: {}; A's public row for B: {a_row_committed:?}; first durable \
             commit {:?} after t=0 (W is {w:?}, so the window was waited out: {not_early}); \
             blackout dropped {} frames from A toward B/C",
            a_committed.describe(),
            a_commit_at,
            blackout.dropped()
        ),
        at(sim),
    );

    // Nobody else saw the exclusion: B and C are untouched at
    // (r0, e0), B still listed, no quarantine. With that, A is
    // crash-stopped with the saved delivery pending.
    let others_at_crash = views(sim, &["C", "B"], &group, &b).await?;
    let others_clean = others_at_crash.iter().all(|(_, seen)| {
        seen.as_ref().is_some_and(|seen| {
            seen.state_revision == r0 && seen.epoch == Some(e0) && seen.lists_b && !seen.quarantined
        })
    });
    receipt.evidence(
        "b_and_c_never_saw_the_commit_at_the_crash",
        others_clean,
        describe_all(&others_at_crash),
        at(sim),
    );
    sim.stop("A", RestartMode::Crash).await?;
    sim.fabric()
        .mark("case: A crash-stopped with the saved delivery pending");

    // The fork arm's competing sibling: D restarts while A is down and,
    // as the designated admin on the same parent head A's commit never
    // left, commits its own exclusion of B and delivers it to C.
    let mut h1_revision: Option<u64> = None;
    let mut signed_by_d = !competing;
    if competing {
        sim.fabric().mark("case: D restarts while A is down");
        sim.start_again("D").await?;
        let mut seen = Observations::default();
        let bound = sync_wait.saturating_add(timing.completion_bound);
        let waited = sim
            .until("D and C reach H", bound + secs(5), async |s: &Sim| {
                let Some(now) = seen.observe(views_now(s, &["D", "C"], &group, &b)).await else {
                    return true;
                };
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
        h1_revision = h1
            .first()
            .and_then(|(_, seen)| seen.as_ref())
            .map(|seen| seen.state_revision);
        signed_by_d = h1.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(d_hex.as_str()))
        });
        receipt.note(format!(
            "D's commit while A was down (signer wanted D ({d_hex})): {}",
            describe_all(&h1)
        ));
    }

    // The row's ordering, made deterministic: D's head and proof are on
    // the fabric well before A restarts, so A's boot head round asks
    // holders that already hold the competing commit and its answers
    // name r_D — the ask cannot confirm against a stale pre-fork answer.
    // (Without this margin the boot ask races D's commit; a confirmed
    // round never re-asks, and the resend gate would open blind.)
    if competing {
        sim.within("the margin past D's commit", secs(10) + secs(1), async {
            tokio::time::sleep(secs(10)).await;
        })
        .await?;
    }

    // A restarts with the blackout released: nothing fabric-side holds
    // A's resend back, so any sibling it publishes lands on D and C and
    // fails the containment watch below.
    blackout.set(false);
    sim.fabric().mark(format!(
        "case: blackout released for A's restart ({} frames had been dropped); A restarts on \
         its saved delivery-pending row",
        blackout.dropped()
    ));
    sim.start_again("A").await?;

    // Fork arm: D's head and proof reach A before any resend of A's own
    // gate — A meets the competing branch, keeps the saved event as
    // fork evidence and shows the typed `waiting_for_fork_resolution`.
    // Resume arm: no sibling exists, so A finishes the eligible delivery
    // of its saved event and the survivors converge on A's commit. The
    // containment watch runs through both: from A's restart on, a
    // published sibling or a second rotation is seen the moment it
    // lands, not only in the end read.
    let converge_bound = sync_wait.saturating_add(timing.completion_bound);
    let mut typed_fork = false;
    let mut sibling: Option<String> = None;
    let mut second_rotation: Option<String> = None;
    let mut converged = false;
    let waited = sim
        .until(
            "A restarts onto the branch the row names",
            converge_bound + secs(10),
            async |s: &Sim| {
                let watched: &[&str] = if competing { &["D", "C"] } else { &["C"] };
                if let Ok(now) = views_now(s, watched, &group, &b).await {
                    for (label, seen) in now {
                        let Some(seen) = seen else {
                            continue;
                        };
                        if competing
                            && (seen.quarantined
                                || seen.head_committed_by.as_deref() == Some(a_hex.as_str())
                                || h1_revision.is_some_and(|rev| seen.state_revision > rev))
                        {
                            sibling.get_or_insert(format!(
                                "{label} left D's commit: {}",
                                seen.describe()
                            ));
                        }
                        if !competing && seen.head_committed_by.as_deref() == Some(d_hex.as_str()) {
                            sibling.get_or_insert(format!(
                                "{label} took a D-signed commit: {}",
                                seen.describe()
                            ));
                        }
                        if seen.epoch.is_some_and(|epoch| epoch > e0 + 1) {
                            second_rotation.get_or_insert(format!(
                                "{label} stepped past e0+1: {}",
                                seen.describe()
                            ));
                        }
                    }
                }
                if let Ok(Some(row)) = s4_row(s, "A", &group, &b_hex).await {
                    if competing {
                        typed_fork |=
                            row["waiting"]["cause"].as_str() == Some("waiting_for_fork_resolution");
                    } else {
                        converged |= row["phase"].as_str() == Some("complete")
                            && row["result_epoch"].as_u64() == Some(e0 + 1);
                    }
                }
                if competing {
                    typed_fork
                        && matches!(try_view_now(s, "A", &group, &b).await, Ok(Some(seen))
                            if seen.epoch == Some(e0 + 1) && seen.quarantined)
                } else {
                    converged
                        && matches!(
                            views_now(s, &["A", "C"], &group, &b).await,
                            Ok(now) if excluded(&now, e0, leaves0) && now.iter().all(|(_, seen)| {
                                seen.as_ref().is_some_and(|seen| {
                                    seen.head_committed_by.as_deref() == Some(a_hex.as_str())
                                })
                            })
                        )
                }
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }

    // Resume arm, second phase: D returns after A's saved delivery has
    // converged with C. D boots onto a compatible chain (its head r0 is
    // A's parent), learns the exclusion, and A's withheld delivery to D
    // resumes and converges — which is what closes both rows. Without
    // this, A's row correctly stays `committed_delivery_pending` while a
    // survivor is down.
    if !competing {
        sim.fabric()
            .mark("case: D restarts after A's resumed delivery");
        sim.start_again("D").await?;
        let waited = sim
            .until(
                "D returns and both rows close",
                sync_wait + timing.completion_bound + secs(10),
                async |s: &Sim| {
                    let done = matches!(views_now(s, &["A", "D", "C"], &group, &b).await, Ok(now)
                    if excluded(&now, e0, leaves0)
                        && now.iter().all(|(_, seen)| {
                            seen.as_ref().is_some_and(|seen| {
                                seen.head_committed_by.as_deref() == Some(a_hex.as_str())
                            })
                        }))
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
    }

    sim.within("the outcome settles", SETTLE + secs(2), async {
        tokio::time::sleep(SETTLE).await;
    })
    .await?;

    // Fork arm: ADR 0110 §3's "fork evidence and typed manual-resolution
    // exit survive" is proven across a second crash restart — the final
    // reads below are taken after it, so a marker or a typed wait that
    // did not persist fails the arm.
    let mut survives = !competing;
    if competing {
        sim.restart("A", RestartMode::Crash).await?;
        sim.fabric()
            .mark("case: A crash-stopped a second time, onto its fork evidence");
        let waited = sim
            .until(
                "A's second restart reloads its row",
                sync_wait + secs(5),
                async |s: &Sim| s4_row(s, "A", &group, &b_hex).await.is_ok(),
            )
            .await;
        if let Err(error) = waited {
            if !expired(&error) {
                return Err(error);
            }
        }
        let row_again = sim
            .at_instant(
                "read A's public S4 row after the second restart",
                s4_row(sim, "A", &group, &b_hex),
            )
            .await??;
        survives = row_again.as_ref().is_some_and(|row| {
            row["phase"].as_str() != Some("complete")
                && row["waiting"]["cause"].as_str() == Some("waiting_for_fork_resolution")
        }) && fork_quarantine_present(sim, "A", &group).await?;
        receipt.note(format!(
            "after A's second restart: row {row_again:?}; the typed cause and the public \
             fork-quarantine marker survived: {survives}"
        ));
    }

    let survivors: &[&str] = if competing {
        &["D", "C"]
    } else {
        &["A", "D", "C"]
    };
    let end = views(sim, survivors, &group, &b).await?;
    let a_end = view_now(sim, "A", &group, &b).await?;
    let a_row = sim
        .at_instant(
            "read A's public S4 row after the restart",
            s4_row(sim, "A", &group, &b_hex),
        )
        .await?;
    let d_row = sim
        .at_instant(
            "read D's public S4 row after the restart",
            s4_row(sim, "D", &group, &b_hex),
        )
        .await?;

    // Data plane after the outcome: the committing side's new traffic
    // opens on the survivors that stayed on the committing chain, never
    // on B, and — fork arm — not on A's divergent key either.
    let encryptor = if competing { "D" } else { "C" };
    let (c_after, b_after, a_after) = match encrypt(sim, encryptor, &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "B", &group, &ciphertext).await?,
            decrypts(sim, "A", &group, &ciphertext).await?,
        ),
        Err(error) => (
            (false, error.clone()),
            (false, error.clone()),
            (false, error),
        ),
    };

    receipt.request_delivered(
        "b_self_revoke_answered",
        status.is_success(),
        revoke_reply,
        at(sim),
    );
    receipt.request_delivered(
        "a_remove_b_request_answered",
        rm_body.is_object(),
        remove_reply.clone(),
        at(sim),
    );

    if competing {
        let row_open = a_row.as_ref().is_ok_and(|row| {
            row.as_ref().is_some_and(|row| {
                row["phase"].as_str() != Some("complete")
                    && row["waiting"]["cause"].as_str() == Some("waiting_for_fork_resolution")
            })
        });
        // The end-state control only: a sibling sighting is judged in the
        // cause ladder (a published sibling is a named RED, not an INFRA
        // premise), including the refused-send shape where D and C stay
        // clean because the receivers are the backstop.
        let d_c_hold_ds_commit = end.iter().all(|(_, seen)| {
            seen.as_ref().is_some_and(|seen| {
                seen.epoch == Some(e0 + 1)
                    && !seen.quarantined
                    && seen.head_committed_by.as_deref() == Some(d_hex.as_str())
            })
        });
        receipt.evidence(
            "d_and_c_hold_ds_single_commit",
            d_c_hold_ds_commit,
            format!(
                "{}; first sibling sighting: {:?}; first past-e0+1 sighting: {:?}; frames A sent \
                 toward B/C before its crash: {}",
                describe_all(&end),
                sibling,
                second_rotation,
                blackout.dropped()
            ),
            at(sim),
        );
        let a_keeps_own = a_end.epoch == Some(e0 + 1)
            && a_end.state_revision == r0 + 1
            && a_end.head_committed_by.as_deref() == Some(a_hex.as_str())
            && persisted_t_obs(sim, "A", b.as_bytes())?.is_some();
        receipt.evidence(
            "a_keeps_its_own_commit_and_saved_row_across_the_restart",
            a_keeps_own,
            format!(
                "A after the restarts: {}; its persisted .evs row for B is still on disk: {}",
                a_end.describe(),
                persisted_t_obs(sim, "A", b.as_bytes())?.is_some()
            ),
            at(sim),
        );
        // A cannot claim H across the real fork: its divergent e0 + 1
        // key does not open D's new traffic, while C's does and B's
        // retained keys cannot.
        let fork_data_plane = c_after.0 && !b_after.0 && !a_after.0;
        receipt.evidence(
            "the_fork_is_real_on_the_data_plane",
            fork_data_plane,
            format!("{}; {}; {}", c_after.1, b_after.1, a_after.1),
            at(sim),
        );
        let d_row_complete = d_row.as_ref().is_ok_and(|row| {
            row.as_ref()
                .is_some_and(|row| row["phase"].as_str() == Some("complete"))
        });
        receipt.evidence(
            "d_completes_the_competing_exclusion",
            d_row_complete,
            format!("D's row for B: {d_row:?}"),
            at(sim),
        );
        let marker_present = fork_quarantine_present(sim, "A", &group).await?;
        let typed_outcome = row_open && typed_fork && a_end.quarantined && marker_present;
        let passed = durable
            && not_early
            && others_clean
            && queued_typed
            && excluded(&end, e0, leaves0)
            && signed_by_d
            && a_keeps_own
            && d_c_hold_ds_commit
            && d_row_complete
            && fork_data_plane
            && sibling.is_none()
            && second_rotation.is_none()
            && typed_outcome
            && survives;
        if !passed {
            let (cause, observed) = if !durable {
                (
                    CAUSE_NO_DURABLE_COMMIT,
                    format!(
                        "A at the crash window: {}; A's public row for B: {a_row_committed:?}",
                        a_committed.describe()
                    ),
                )
            } else if !not_early {
                (
                    CAUSE_EARLY_FALLBACK,
                    format!(
                        "A's first durable commit {a_commit_at:?} after t=0; W is {w:?}; the \
                         typed queue reply was {remove_reply}"
                    ),
                )
            } else if !others_clean {
                (CAUSE_LEAKED_COMMIT, describe_all(&others_at_crash))
            } else if !excluded(&end, e0, leaves0) || !signed_by_d || !d_row_complete {
                (
                    CAUSE_NO_D_COMMIT,
                    format!("D and C at the end: {}", describe_all(&end)),
                )
            } else if sibling.is_some() {
                (CAUSE_SIBLING_PUBLISHED, sibling.unwrap_or_default())
            } else if second_rotation.is_some() {
                (CAUSE_SECOND_ROTATION, second_rotation.unwrap_or_default())
            } else if !fork_data_plane {
                (
                    CAUSE_DATA_PLANE,
                    format!("{}; {}; {}", c_after.1, b_after.1, a_after.1),
                )
            } else {
                (
                    CAUSE_NO_TYPED_FORK,
                    format!(
                        "A's row {a_row:?}; A {}; the typed waiting_for_fork_resolution was \
                         observed: {typed_fork}; the public fork-quarantine marker is present: \
                         {marker_present}; the typed cause and marker survived A's second \
                         restart: {survives}",
                        a_end.describe()
                    ),
                )
            };
            // Only the row's named failures classify RED; every premise
            // failure (no durable commit, no D commit, a leak, a broken
            // data plane) stays INFRA, so the gate's `--expect=RED` pin
            // cannot be satisfied by an unrelated regression while the
            // §3 fix waits.
            let named = matches!(cause, CAUSE_SIBLING_PUBLISHED | CAUSE_NO_TYPED_FORK);
            receipt.cause(cause, Some(observed), named, at(sim));
        }
        receipt.finish(FINAL_FORK, passed, at(sim));
    } else {
        let a_signed = end.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(a_hex.as_str()))
        });
        let once = excluded(&end, e0, leaves0)
            && end
                .iter()
                .all(|(_, seen)| seen.as_ref().is_some_and(|seen| seen.epoch == Some(e0 + 1)));
        let a_done = a_row.as_ref().is_ok_and(|row| {
            row.as_ref().is_some_and(|row| {
                row["phase"].as_str() == Some("complete")
                    && row["result_epoch"].as_u64() == Some(e0 + 1)
            })
        });
        receipt.evidence(
            "a_finishes_the_saved_delivery_with_no_rekey",
            converged && a_done && once && a_signed && sibling.is_none(),
            format!(
                "A's row {a_row:?}; D's own row after its return (its closure is not this arm's \
                 outcome; a restarted daemon may first wait for B's KeyPackage): {d_row:?}; \
                 converged {converged}; sibling sighting {sibling:?}; {}",
                describe_all(&end)
            ),
            at(sim),
        );
        let resume_data_plane = a_after.0 && c_after.0 && !b_after.0;
        receipt.evidence(
            "the_data_plane_follows_the_resumed_delivery",
            resume_data_plane,
            format!("{}; {}; {}", a_after.1, c_after.1, b_after.1),
            at(sim),
        );
        let passed = durable
            && not_early
            && others_clean
            && converged
            && a_done
            && once
            && a_signed
            && sibling.is_none()
            && second_rotation.is_none()
            && resume_data_plane;
        if !passed {
            let (cause, observed) = if !durable {
                (
                    CAUSE_NO_DURABLE_COMMIT,
                    format!(
                        "A at the crash window: {}; A's public row for B: {a_row_committed:?}",
                        a_committed.describe()
                    ),
                )
            } else if !not_early {
                (
                    CAUSE_EARLY_FALLBACK,
                    format!(
                        "A's first durable commit {a_commit_at:?} after t=0; W is {w:?}; the \
                         typed queue reply was {remove_reply}"
                    ),
                )
            } else if !others_clean {
                (CAUSE_LEAKED_COMMIT, describe_all(&others_at_crash))
            } else if sibling.is_some() {
                (CAUSE_SIBLING_PUBLISHED, sibling.unwrap_or_default())
            } else if second_rotation.is_some() {
                (CAUSE_SECOND_ROTATION, second_rotation.unwrap_or_default())
            } else if !once {
                (CAUSE_SECOND_ROTATION, describe_all(&end))
            } else if !converged || !a_done {
                (
                    CAUSE_NO_RESUME,
                    format!("A's row {a_row:?}; {}", describe_all(&end)),
                )
            } else {
                (
                    CAUSE_DATA_PLANE,
                    format!("{}; {}; {}", a_after.1, c_after.1, b_after.1),
                )
            };
            // Premise failures stay INFRA like the fork arm's; only the
            // arm's own outcome causes classify RED.
            let premise = matches!(
                cause,
                CAUSE_NO_DURABLE_COMMIT | CAUSE_EARLY_FALLBACK | CAUSE_LEAKED_COMMIT
            );
            receipt.cause(cause, Some(observed), !premise, at(sim));
        }
        receipt.finish(FINAL_RESUME, passed, at(sim));
    }
    Ok(())
}

async fn run(case: &str, seed: u64, labels: &[&str], competing: bool) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 `s4_crash_commit_fallback`. Timing from S4Timing::default() \
         (measured; D69, D73): {:?}.",
        S4Timing::default()
    ));
    match start(case, seed, labels).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, labels, competing).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    let final_name = if competing { FINAL_FORK } else { FINAL_RESUME };
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(final_name);
    }
    receipt.emit();
    receipt
}

async fn expect(
    case: &str,
    seed: u64,
    labels: &[&str],
    competing: bool,
    want: Verdict,
) -> Result<()> {
    let receipt = run(case, seed, labels, competing).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    // While the §3 fix waits, this arm's RED must be exactly the
    // typed-state cause: the CI gate checks only the verdict, so the
    // test itself names the cause, and any other RED (a containment
    // regression) fails here instead of satisfying the pin.
    if competing {
        ensure!(
            receipt.named_causes() == [CAUSE_NO_TYPED_FORK],
            "{case}: expected the RED cause {CAUSE_NO_TYPED_FORK:?}, got {:?}",
            receipt.named_causes()
        );
    }
    Ok(())
}

const LABELS: &[&str] = &["A", "D", "B", "C"];

/// ADR 0110 `s4_crash_commit_fallback`, the fork arm: A's rank-1
/// fallback commits the exclusion durably into the publication
/// blackout and is crash-stopped; the restarted designated D commits
/// the competing sibling from the same parent head; the restarted A
/// keeps the fork evidence, shows the typed
/// `waiting_for_fork_resolution`, and publishes no saved sibling. The
/// containment half (no sibling published, the fork real on the data
/// plane) is green on `main`; the typed fork state is RED on `main`,
/// which silently completes the saved delivery across the real fork
/// (recorded on #1581 by name), and turns GREEN with the §3 fix.
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
fn w3h_1581e_red_crash_commit_fork_contained() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581e_red_crash_commit_fork_contained",
            0x1581_0007,
            LABELS,
            true,
            // RED on main: CAUSE_NO_TYPED_FORK — the saved delivery
            // completes across the real fork with no fork evidence and
            // no typed waiting_for_fork_resolution (ADR 0110 §3 L225).
            Verdict::Red,
        )
        .await
    })
}

/// ADR 0110 `s4_crash_commit_fallback`, the same-chain resume arm: with
/// no competing commit, the restarted A finishes the eligible delivery
/// of its saved exclusion on the same chain without another rekey.
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
fn w3h_1581e_control_crash_commit_same_chain_resume() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581e_control_crash_commit_same_chain_resume",
            0x1581_0008,
            LABELS,
            false,
            Verdict::Green,
        )
        .await
    })
}
