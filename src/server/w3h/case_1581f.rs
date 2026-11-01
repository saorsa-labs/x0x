//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_local_authority_exit`): A, D, B, C with A < D. A, the
//! designated admin, holds pending S4 work for B's self-revocation
//! when it loses its own committer authority mid-window (§4 L274).
//!
//! - control arm, the revoked form: A's own agent revocation, issued
//!   through the public `/identity/revoke` route while its row for B
//!   is still open. ADR 0110 §4 L274: A stops sealing, marks
//!   `local_committer_ineligible` naming D, keeps the row and its
//!   evidence, and D resumes and completes B's exclusion. GREEN on
//!   `main`: `evaluate_row` (`src/groups/eviction.rs`) keys the
//!   `LocalCommitterIneligible` cause on the local seat still being
//!   an Active admin, which holds for the revoked-committer form.
//! - red arm, the demoted form ("D's public role API demotes A" in
//!   the row text): A is demoted to `member` through the public role
//!   route while A's row for B is open. §4 L274 wants the same
//!   `local_committer_ineligible` mark for a demoted worker, and
//!   §4 L275 (D72) keeps a demoted worker a member that retains its
//!   pending rows. `main` mislabels it — the demoted local seat is
//!   no longer an Active admin, so `evaluate_row` falls to
//!   `waiting_for_designated_admin` instead (the divergence #1751
//!   recorded on #1581, diverging from §4 L274 and
//!   `docs/api-reference.md`). Expected RED on `main` with
//!   [`CAUSE_NO_MARK`]; GREEN when the `evaluate_row` fix lands. The
//!   RED is eligible only with the mislabel itself observed — a row
//!   that never evaluated the exit is not the named divergence.
//!
//! Harness honesty, three departures the row needs stated plainly:
//!
//! - "Pending work on A" cannot be a plain race against A's worker: a
//!   healthy designated A seals within a worker tick or two of
//!   observing (#1581c's finding), faster than any exit can be armed.
//!   The case reuses #1581c's scaffold: the direct and relayed-DM
//!   lanes between A and D/C — the §2 head round's ask path — are
//!   dropped while B stays connected to A, so B's self-revocation
//!   still opens A's row but no holder can answer A's round and the
//!   row stays `pending` with the typed `waiting_for_head_sync`
//!   until the exit, deterministically.
//! - The exit window needs its own determinism: the `waiting` the
//!   public route serves is the worker's last stored evaluation, and
//!   on `main` D's completion of B's exclusion can reach A in the
//!   same anti-entropy frame as the exit evidence, closing the row
//!   before A's worker ever evaluated the exit (observed in local
//!   runs of the D-authored demotion). Both arms therefore apply the
//!   exit on A itself — the revoked arm through A's own self-revoke
//!   route, the demoted arm through A demoting itself on the same
//!   public role route the row names (the typed mark is keyed on the
//!   roster event, not on who authored it) — and from the frozen
//!   instant the route answers, every application frame toward A is
//!   dropped until the mark watch ends. Nothing can complete A's
//!   open row before A's own worker has evaluated the exit; the
//!   holds release when the watch ends, the exit evidence propagates
//!   (the transport retries the dropped frames), and D resumes.
//! - The row text's "issuer revokes A" needs a user issuer the sim
//!   fabric does not provision; the control arm drives the same
//!   verified Agent-subject revocation record for A through A's own
//!   public self-revoke route. The group-side observation the row
//!   asserts — every survivor's S4 evaluates A's agent as revoked —
//!   is the same record an issuer revocation produces; who signed it
//!   is not what the typed mark keys on.
//! - The self-left form ("or A leaves") is not driven: on `main` the
//!   public `DELETE /groups/:id` leave drops the leaver's local group
//!   record outright, so no public row exists at all — a stronger
//!   divergence from §4 L274 than the demoted form's mislabel. This
//!   corrects the account #1751 recorded on #1581 (a mislabelled row):
//!   that was a code reading of `evaluate_row`; the leave path never
//!   serves the row. The "D removes A" form, the sole-admin-revoked
//!   repeat and the genuinely-admin-empty repeat are not driven this
//!   round either; they stay named on #1581 (the exits are the
//!   `s4_owner_recovery` / `s4_ordinary_admin_revoked` rows per the
//!   ADR).
//!
//! Before t = 0 the ordinary `private_secure` (TreeKEM) group is
//! settled (every node at A's state revision r0 and epoch e0, four
//! leaves) and a data-plane probe opens on B and C; every node is past
//! its boot head gate. The arms assert:
//!
//! - A authors no commit past r0 beyond the exit's own roster change
//!   (the retained logs decide this, not the current heads).
//! - D resumes on the exit, not on the fallback clock: B's exclusion is
//!   committed before T_obs + W, on the survivors' heads, and the
//!   commit that removed B is D's on every holder's retained log. The
//!   epoch is read from those heads, not pinned — the revoked arm's
//!   exit opens a second obligation for A's own seat whose completion
//!   order is not this row's claim, and D's own obligation-row phase
//!   completes with its delivery bookkeeping, which can trail the
//!   commit while a member recovers from the exit-window blackout, so
//!   it is recorded rather than gated.
//! - A's row for B completes from the learned exclusion while A retains
//!   a record of the group. Where the record ends — the revoked arm,
//!   once A's own removal applies — the shared evidence is asserted
//!   instead: D still holds B's row and B's revocation record (§4
//!   L276), and the survivors have applied A's removal.
//! - The data plane follows: C decrypts the survivors' new traffic, B
//!   does not.
//!
//! Receipts use `w3h.receipt/1`.

#![cfg(test)]

use super::control::{create_group, invite, join, mesh};
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
/// After the resume, the case waits this long and re-reads, so a later
/// move (another epoch step) is seen.
const SETTLE: Duration = Duration::from_secs(30);
/// How long A's public row is polled for the typed exit mark; the
/// evaluation refreshes within a worker tick of the exit.
const MARK_WATCH: Duration = Duration::from_secs(10);
const PROBE: &[u8] = b"w3h-1581f probe";

const FINAL_CONTROL: &str = "a_marks_local_committer_ineligible_and_d_resumes_the_exclusion";
const FINAL_RED: &str = "a_demoted_worker_marks_local_committer_ineligible";
const CAUSE_NO_PENDING: &str = "no pending work on A at the exit: A's row for B was not open \
                                with the typed head-sync wait while A held the designation, or \
                                an exclusion commit moved before the exit";
const CAUSE_WRONG_MARK: &str = "the exit was marked local_committer_ineligible, but the mark \
                                did not name D or first showed only after the row completed";
const CAUSE_A_SEALED: &str = "A sealed after its exit: A authored a commit past r0 beyond the \
                              exit's own roster change";
const CAUSE_NO_RESUME: &str = "D never resumed: within the bound the survivors' heads did not \
                               carry B's exclusion";
const CAUSE_LATE_FALLBACK: &str = "D only acted at its fallback time, not on the exit: B's \
                                   exclusion committed no earlier than T_obs + W";
const CAUSE_NO_COMPLETION: &str = "A's row for B never completed from the learned exclusion, \
                                   or was erased by the exit instead of kept";
const CAUSE_SECOND_ROTATION: &str = "B's exclusion did not hold as D's commit: after the resume \
                                     a survivor relisted B, moved to a divergent head, \
                                     quarantined, or the removal commit was not D's";
const CAUSE_DATA_PLANE: &str = "D completed B's exclusion, but the data plane did not follow: \
                                C did not decrypt the new traffic, or B still could";
const CAUSE_NO_MARK: &str = "no typed local_committer_ineligible: after A's local authority \
                             exit its public S4 row for B never marked the exit (ADR 0110 §4 \
                             L274)";

/// `label`'s view of `group`; `None` when it holds no record of it.
#[derive(Debug, Clone)]
struct View {
    state_revision: u64,
    lists_b: bool,
    lists_a: bool,
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
            "state={} lists_b={} lists_a={} epoch={:?} leaves={:?} quarantined={} \
             head_committed_by={:?}",
            self.state_revision,
            self.lists_b,
            self.lists_a,
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
    a: &crate::identity::AgentId,
) -> Result<Option<View>> {
    let (b_hex, a_hex) = (hex::encode(b.as_bytes()), hex::encode(a.as_bytes()));
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
            lists_a: info
                .active_members()
                .any(|member| member.agent_id.eq_ignore_ascii_case(&a_hex)),
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
    a: &crate::identity::AgentId,
) -> Result<View> {
    try_view_now(sim, label, group, b, a)
        .await?
        .with_context(|| format!("{label} has no record of the group"))
}

async fn views_now<'a>(
    sim: &Sim,
    labels: &[&'a str],
    group: &str,
    b: &crate::identity::AgentId,
    a: &crate::identity::AgentId,
) -> Result<Vec<(&'a str, Option<View>)>> {
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        out.push((*label, try_view_now(sim, label, group, b, a).await?));
    }
    Ok(out)
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

/// What `label`'s retained commit log shows past `r0`: how many commits
/// A authored, and who signed the commit that removed `target` — the
/// first commit past `r0` whose roster projection no longer carries the
/// target as a seated member. The retained projections make both facts
/// independent of the current head, so a later commit by someone else
/// cannot hide either.
struct LogScan {
    a_commits: usize,
    removed_by: Option<String>,
}

async fn scan_log(
    sim: &Sim,
    label: &str,
    group: &str,
    target_hex: &str,
    a_hex: &str,
    r0: u64,
) -> Result<Option<LogScan>> {
    let state = sim.state(label)?;
    let scan = {
        let groups = state.named_groups.read().await;
        let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, group) else {
            return Ok(None);
        };
        let mut a_commits = 0usize;
        let mut removed_by = None;
        let mut prev_lists_target = None;
        for retained in &info.commit_log {
            let lists = retained
                .roster
                .keys()
                .any(|key| key.eq_ignore_ascii_case(target_hex));
            if retained.commit.revision > r0 {
                if retained.commit.committed_by.eq_ignore_ascii_case(a_hex) {
                    a_commits += 1;
                }
                if removed_by.is_none() && prev_lists_target == Some(true) && !lists {
                    removed_by = Some(retained.commit.committed_by.to_ascii_lowercase());
                }
            }
            prev_lists_target = Some(lists);
        }
        LogScan {
            a_commits,
            removed_by,
        }
    };
    Ok(Some(scan))
}

/// A invites `member`; A lists it and it reports itself active.
async fn seat(sim: &Sim, member: &str, group: &str) -> Result<()> {
    let link = invite(sim, "A", group).await?;
    join(sim, member, &link).await?;
    let hex = sim.agent_hex(member)?;
    sim.until(&format!("{member} seated"), SETUP, async |s: &Sim| {
        let listed = s
            .request("A", Method::GET, &format!("/groups/{group}"), None)
            .await
            .ok()
            .and_then(|(status, body)| {
                (status.is_success()).then(|| {
                    body["members"]
                        .as_array()
                        .map(|rows| {
                            rows.iter()
                                .filter_map(|m| m["agent_id"].as_str())
                                .any(|id| id.eq_ignore_ascii_case(&hex))
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        listed
            && super::home::membership_state(s, member, group)
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
    let admin = {
        let groups = state.named_groups.read().await;
        let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
            .with_context(|| format!("{observer} has no record of the group"))?;
        let admin = info.active_members().any(|member| {
            member.agent_id.eq_ignore_ascii_case(&subject)
                && member.role.at_least(crate::groups::GroupRole::Admin)
        });
        admin
    };
    Ok(admin)
}

/// Every label holds A's state revision and TreeKEM epoch.
async fn settled(
    sim: &Sim,
    labels: &[&str],
    group: &str,
    b: &crate::identity::AgentId,
    a: &crate::identity::AgentId,
) -> Result<()> {
    sim.until(
        "every node holds A's head and epoch",
        SETUP,
        async |s: &Sim| {
            let Ok(authority) = view_now(s, "A", group, b, a).await else {
                return false;
            };
            if authority.epoch.is_none() {
                return false;
            }
            for label in labels {
                match view_now(s, label, group, b, a).await {
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

/// Wait until every holder holds the subject's revocation record; a
/// timeout makes the caller's evidence stage fail (INFRA — the record
/// never reached its target).
async fn await_holders(sim: &Sim, holders: &[&str], subject_hex: &str) -> Result<()> {
    let mut seen = Observations::default();
    let what = "the holders hold the revocation";
    let waited = sim
        .until(what, EVIDENCE, async |s: &Sim| {
            for holder in holders {
                match seen.observe(holds_revocation(s, holder, subject_hex)).await {
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
/// the status carries no row for the target. A non-success status is
/// itself an answer of "no row", so it maps to `None` rather than an
/// error.
async fn s4_row(
    sim: &Sim,
    label: &str,
    group: &str,
    target_hex: &str,
) -> Result<Option<serde_json::Value>> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    if !status.is_success() {
        return Ok(None);
    }
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

/// Drops every frame toward `target` except plane-hello (QUIC link
/// liveness) while held, and counts them: direct, relayed DM, pubsub,
/// bulk, stream — and the gossip membership lane, which carries the
/// named-group roster anti-entropy (#1581c's primitive). The fabric
/// cannot delay stream lanes, so a drop with the transport's own
/// retries is the stream-safe expression of a held catch-up: while it
/// is set, no completion, roster batch or revocation record from any
/// survivor can reach the target.
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
/// ask path. Everything else — the roster anti-entropy on the gossip
/// membership lane, the TreeKEM catch-up pages, B's revocation record
/// toward `target` — still flows (#1581c's scaffold).
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
/// opens on B and C, and every node is past its restart sync wait.
async fn setup(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
    b: &crate::identity::AgentId,
    a: &crate::identity::AgentId,
) -> Result<(String, u64, u64, u32)> {
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

    settled(sim, labels, &group, b, a).await?;
    let base = view_now(sim, "A", &group, b, a).await?;
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
        base.lists_b && base.lists_a && u32::try_from(labels.len()).ok() == Some(leaves0),
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
    Ok((group, r0, e0, leaves0))
}

/// Both arms share one body: the pending row on A under the ask-path
/// hold, the local authority exit (`demoted` picks the form), the typed
/// mark watch, D's resume, and the learned completion.
async fn scenario(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
    demoted: bool,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let timing = S4Timing::default();
    let w = timing.designated_window;
    let (a_id, _) = sim.ids("A")?;
    let (b, _) = sim.ids("B")?;
    let (group, r0, e0, leaves0) = setup(sim, receipt, labels, &b, &a_id).await?;
    let b_hex = sim.agent_hex("B")?;
    let a_hex = sim.agent_hex("A")?;
    let d_hex = sim.agent_hex("D")?;

    // The pending-work scaffold: the direct and relayed-DM lanes between
    // A and D/C — the §2 round's ask path — are dropped while B stays
    // connected to A, so the row B's revocation opens on A can neither
    // ask a holder nor be answered and cannot reach a seal before the
    // exit (a healthy designated A otherwise confirms its round through
    // D or C within a worker tick or two and seals; see the module doc).
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
            Some(json!({"agent_id": b_hex, "reason": "w3h-1581f"})),
        )
        .await?;
    ensure!(status.is_success(), "B self-revokes: {status} {body}");
    receipt.request_delivered(
        "b_self_revoke_answered",
        status.is_success(),
        format!("B POST /identity/revoke: {status} {body}"),
        at(sim),
    );
    await_holders(sim, &["A", "D", "C"], &b_hex).await?;

    // Pending work on A, watched: the row is durable, open, and typed on
    // the unsynced head, D's row names A as the designated admin, and no
    // survivor's epoch moves before the exit.
    let mut early_move: Option<Duration> = None;
    let mut typed_head_sync = false;
    let mut d_names_a = false;
    let waited = sim
        .until(
            "A's row for B waits typed on the head sync",
            EVIDENCE,
            async |s: &Sim| {
                if let Ok(Some(row)) = s4_row(s, "A", &group, &b_hex).await {
                    typed_head_sync |= row["waiting"]["cause"].as_str()
                        == Some("waiting_for_head_sync")
                        && row["phase"].as_str() == Some("pending");
                }
                if let Ok(Some(row)) = s4_row(s, "D", &group, &b_hex).await {
                    d_names_a |= row["waiting"]["cause"].as_str()
                        == Some("waiting_for_designated_admin")
                        && row["waiting"]["designated_admin"]
                            .as_str()
                            .is_some_and(|named| named.eq_ignore_ascii_case(&a_hex));
                }
                if let Ok(views) = views_now(s, &["D", "C"], &group, &b, &a_id).await {
                    if views.iter().any(|(_, seen)| {
                        seen.as_ref()
                            .is_some_and(|seen| seen.epoch.is_some_and(|epoch| epoch > e0))
                    }) {
                        early_move.get_or_insert(s.fabric().now().saturating_sub(t0));
                    }
                }
                typed_head_sync && d_names_a
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    sim.until("A's intake is durable", EVIDENCE, async |s: &Sim| {
        persisted_t_obs(s, "A", b.as_bytes()).is_ok_and(|t_obs| t_obs.is_some())
    })
    .await?;
    let at_exit_view = view_now(sim, "A", &group, &b, &a_id).await?;
    let pending_ok = typed_head_sync
        && d_names_a
        && early_move.is_none()
        && at_exit_view.epoch == Some(e0)
        && at_exit_view.state_revision == r0;
    receipt.evidence(
        "a_holds_pending_typed_work_at_the_exit",
        pending_ok,
        format!(
            "A at the exit: {}; typed head-sync wait seen: {typed_head_sync}; D's row names A: \
             {d_names_a}; an exclusion commit moved before the exit: {early_move:?}; DM frames \
             dropped between A and D/C: {}",
            at_exit_view.describe(),
            dm_hold.dropped()
        ),
        at(sim),
    );

    // The local authority exit (§4 L274), while the row is still open:
    // the red arm's demotion through the public role API — A demotes
    // itself, see the module doc — or the control arm's agent
    // revocation. Both apply on A the moment the route answers, so the
    // instant after, every application frame toward A is dropped until
    // the mark watch ends: no completion, roster batch or later
    // evidence from any survivor can reach A's open row before A's
    // own worker has evaluated the exit.
    let inbound_hold = InboundHold::install(sim, "A")?;
    let t1 = sim.fabric().now();
    let exit_kind = if demoted { "demoted" } else { "agent-revoked" };
    sim.fabric().mark(format!(
        "case: t1 local authority exit — A {exit_kind} mid-window"
    ));
    let (exit_status, exit_body) = if demoted {
        sim.api(
            "A",
            Method::PATCH,
            &format!("/groups/{group}/members/{a_hex}/role"),
            Some(json!({"role": "member"})),
        )
        .await?
    } else {
        sim.api(
            "A",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": a_hex, "reason": "w3h-1581f"})),
        )
        .await?
    };
    ensure!(
        exit_status.is_success(),
        "A's local authority exit ({exit_kind}): {exit_status} {exit_body}"
    );
    receipt.request_delivered(
        "a_local_authority_exit_answered",
        exit_status.is_success(),
        format!("A {exit_kind}: {exit_status} {exit_body}"),
        at(sim),
    );

    // The exit is applied on A; from this frozen instant (no barrier is
    // open between the route's answer and the arming) nothing further
    // reaches A.
    inbound_hold.set(true);
    sim.fabric()
        .mark("fault: every application frame toward A dropped (exit-window blackout)");

    // The typed mark (§4 L274): A's public row for B names the exit with
    // `local_committer_ineligible`, naming D, while the row is still
    // open. The `waiting` the route serves is the worker's last stored
    // evaluation, so the watch polls until A's worker has re-evaluated
    // the open row after the exit — under the blackout nothing can
    // complete the row first — and every cause the row did show is kept
    // for the receipt.
    let mut mark_seen = false;
    let mut mark_names_d = false;
    let mut row_open_at_mark = false;
    let mut observed_causes = std::collections::BTreeSet::new();
    let waited = sim
        .until(
            "A's public row marks the exit",
            MARK_WATCH,
            async |s: &Sim| {
                match s4_row(s, "A", &group, &b_hex).await {
                    Ok(Some(row)) => {
                        if let Some(cause) = row["waiting"]["cause"].as_str() {
                            observed_causes.insert(cause.to_string());
                            if cause == "local_committer_ineligible" {
                                mark_seen = true;
                                mark_names_d |= row["waiting"]["designated_admin"]
                                    .as_str()
                                    .is_some_and(|named| named.eq_ignore_ascii_case(&d_hex));
                                row_open_at_mark |= row["phase"].as_str() != Some("complete");
                                return true;
                            }
                        }
                    }
                    Ok(None) => {
                        observed_causes.insert("<no public row for B on A>".to_string());
                    }
                    Err(_) => {
                        observed_causes.insert("<row read failed>".to_string());
                    }
                }
                false
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    let mark_sample = s4_row(sim, "A", &group, &b_hex).await?;
    receipt.note(format!(
        "A's public row for B after the exit: phase {:?}, waiting {:?}; causes seen during the \
         watch: {observed_causes:?}",
        mark_sample.as_ref().and_then(|row| row["phase"].as_str()),
        mark_sample
            .as_ref()
            .and_then(|row| row["waiting"]["cause"].as_str()),
    ));

    dm_hold.set(false);
    inbound_hold.set(false);
    sim.fabric().mark(format!(
        "case: holds released at {} us (A–D/C DM: {} frames dropped; toward A: {})",
        sim.fabric().now().as_micros(),
        dm_hold.dropped(),
        inbound_hold.dropped()
    ));

    // The exit's evidence reaches the survivors once the holds release.
    let survivors_hold_exit = if demoted {
        sim.until("D and C see A's demotion", EVIDENCE, async |s: &Sim| {
            for observer in ["D", "C"] {
                if sees_admin(s, observer, &group, "A").await.unwrap_or(true) {
                    return false;
                }
            }
            true
        })
        .await
        .is_ok()
            && !sees_admin(sim, "D", &group, "A").await.unwrap_or(true)
            && !sees_admin(sim, "C", &group, "A").await.unwrap_or(true)
    } else {
        await_holders(sim, &["D", "C"], &a_hex).await.is_ok()
            && holds_revocation(sim, "D", &a_hex).await.unwrap_or(false)
            && holds_revocation(sim, "C", &a_hex).await.unwrap_or(false)
    };
    receipt.evidence(
        "the_exit_evidence_reached_the_survivors",
        survivors_hold_exit,
        format!(
            "A {exit_kind} at {} us after t=0; survivors hold the exit evidence; mark seen: \
             {mark_seen} (naming D: {mark_names_d})",
            t1.saturating_sub(t0).as_micros()
        ),
        at(sim),
    );

    // D resumes: the survivors' heads carry B's exclusion — B gone from
    // every roster at a common epoch past e0, no fork-quarantine — and
    // the commit that removed B is D's (checked from the retained logs
    // at the end; see below). D's own obligation row completes with its
    // delivery bookkeeping, which on main can trail the commit while a
    // member's lanes recover from the exit-window blackout, so the row's
    // phase and `result_epoch` are recorded, not gated. The takeover is
    // tied to the exit: D's commit must land before its rank-1 fallback
    // time (T_obs + W; every holder observed B's record from t = 0, so
    // W past t0 bounds the fallback), which proves D acted on the
    // designation change, not on the fallback clock.
    let bound = w
        .saturating_add(timing.completion_bound)
        .saturating_add(secs(10));
    let mut b_epoch: Option<u64> = None;
    let mut b_result_epoch: Option<u64> = None;
    let mut d_first_move: Option<Duration> = None;
    let waited = sim
        .until(
            "D resumes and commits B's exclusion",
            bound,
            async |s: &Sim| {
                if let Ok(Some(row)) = s4_row(s, "D", &group, &b_hex).await {
                    if row["phase"].as_str() == Some("complete") {
                        b_result_epoch = row["result_epoch"].as_u64();
                    }
                }
                let Ok(views) = views_now(s, &["D", "C"], &group, &b, &a_id).await else {
                    return false;
                };
                let mut common: Option<u64> = None;
                for (_, seen) in &views {
                    let Some(seen) = seen else {
                        return false;
                    };
                    let Some(epoch) = seen.epoch else {
                        return false;
                    };
                    if seen.lists_b || seen.quarantined || epoch <= e0 {
                        return false;
                    }
                    match common {
                        None => common = Some(epoch),
                        Some(first) if first != epoch => return false,
                        Some(_) => {}
                    }
                }
                if d_first_move.is_none() && common.is_some() {
                    d_first_move = Some(s.fabric().now().saturating_sub(t0));
                }
                b_epoch = common;
                true
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    let resumed = b_epoch.is_some();
    let resumed_before_fallback = d_first_move.is_some_and(|moved| moved < w);
    let resumed_views = views_now(sim, &["D", "C"], &group, &b, &a_id).await?;
    receipt.note(format!(
        "D's resume: B's exclusion committed at epoch {b_epoch:?} (D's row result_epoch so far: \
         {b_result_epoch:?}, e0={e0}, leaves0={leaves0}); D's first move {d_first_move:?} after \
         t=0 (the fallback clock would allow it at W = {w:?}); {}",
        describe_all(&resumed_views)
    ));

    // The learned completion: while A retains a record of the group its
    // row for B completes from D's commit — the exit erased neither the
    // row nor its evidence. Where the record ends instead (the revoked
    // arm, once A's own removal applies; §4 L275/D128 ends a removed
    // worker's local retention), the shared evidence is asserted: D's
    // row complete and B's revocation record still held (§4 L276).
    let converge_bound = timing
        .restart_sync_wait
        .saturating_add(timing.completion_bound);
    let mut a_completed = false;
    let mut a_row_vanished = false;
    let waited = sim
        .until(
            "A's row completes from the learned exclusion",
            converge_bound + secs(5),
            async |s: &Sim| {
                match s4_row(s, "A", &group, &b_hex).await {
                    Ok(Some(row)) => {
                        if row["phase"].as_str() == Some("complete") {
                            let caught_up = try_view_now(s, "A", &group, &b, &a_id)
                                .await
                                .ok()
                                .flatten()
                                .is_some_and(|seen| {
                                    seen.epoch
                                        .zip(b_epoch)
                                        .is_some_and(|(epoch, want)| epoch >= want)
                                });
                            a_completed |= caught_up;
                        }
                        a_completed
                    }
                    Ok(None) => {
                        // A vanished row counts only when the group
                        // record itself is gone (a transient non-2xx
                        // read is not an ended record).
                        let record_gone = try_view_now(s, "A", &group, &b, &a_id)
                            .await
                            .ok()
                            .flatten()
                            .is_none();
                        a_row_vanished |= record_gone;
                        // The record ended with the removal that ended
                        // A's local retention (§4 L275/D128); this arm's
                        // end state is then the committed exclusion the
                        // resume watch already observed.
                        a_completed || (record_gone && b_epoch.is_some())
                    }
                    Err(_) => false,
                }
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

    // The settled end state: B's exclusion holds on every node that
    // holds the group, no divergent or quarantined head, every head
    // past e0 signed by D, and A's record — while it exists — carries
    // the completed row (the demoted worker stays a member, D72; the
    // revoked worker's record ends with its own removal).
    let end = views_now(sim, &["A", "D", "C"], &group, &b, &a_id).await?;
    let a_holds_record = end
        .iter()
        .any(|(label, seen)| *label == "A" && seen.is_some());
    // The survivors must carry the settled exclusion; A's view counts
    // only while A retains a record of the group (its local retention
    // ends with its own removal, §4 L275/D128 — an ended record lists
    // no one).
    let b_gone_everywhere = end.iter().all(|(label, seen)| match seen {
        None => *label == "A",
        Some(seen) => !seen.lists_b && !seen.quarantined,
    });
    let still_signed_by_d = end.iter().all(|(label, seen)| match seen {
        None => *label == "A",
        Some(seen) => {
            seen.epoch.is_some_and(|epoch| epoch <= e0)
                || seen.head_committed_by.as_deref() == Some(d_hex.as_str())
        }
    });
    let final_row = s4_row(sim, "A", &group, &b_hex).await?;
    let a_row_final = final_row
        .as_ref()
        .is_some_and(|row| row["phase"].as_str() == Some("complete"));

    // The retained commit logs decide authorship, not the current
    // heads: past r0 every commit must be D's, except exactly the one
    // roster change the red arm's exit itself authors (A's demotion),
    // and the commit that removed B must be D's on both survivors' logs
    // (A's own log is gone where its record ended, §4 L275/D128).
    let expected_a_commits = usize::from(demoted);
    let a_scan = scan_log(sim, "A", &group, &b_hex, &a_hex, r0).await?;
    let d_scan = scan_log(sim, "D", &group, &b_hex, &a_hex, r0).await?;
    let c_scan = scan_log(sim, "C", &group, &b_hex, &a_hex, r0).await?;
    let log_scans = [&a_scan, &d_scan, &c_scan];
    let a_authored = log_scans.iter().any(|scan| {
        scan.as_ref()
            .is_some_and(|scan| scan.a_commits > expected_a_commits)
    });
    let b_removed_by_d = [&d_scan, &c_scan].into_iter().all(|scan| {
        scan.as_ref()
            .is_some_and(|scan| scan.removed_by.as_deref() == Some(d_hex.as_str()))
    });
    // Where A's own record ended (the revoked arm's second obligation),
    // the survivors must have applied A's removal too.
    let survivors_dropped_a = end
        .iter()
        .all(|(label, seen)| *label == "A" || seen.as_ref().is_some_and(|seen| !seen.lists_a));

    // The shared obligation on D survives the exit (§4 L276): D still
    // holds B's row — whatever phase its delivery bookkeeping is in —
    // and B's revocation record.
    let shared_evidence_kept = holds_revocation(sim, "D", &b_hex).await.unwrap_or(false)
        && s4_row(sim, "D", &group, &b_hex)
            .await
            .is_ok_and(|row| row.is_some());
    // A's own obligation (the row A's revocation opens for A itself) is
    // recorded, not gated: the §4b exits are other rows' cases.
    let a_own_row = s4_row(sim, "D", &group, &a_hex).await?;
    receipt.note(format!(
        "after the settle (A retains a record: {a_holds_record}; A's row for B: phase {:?}, \
         result_epoch {:?}; the exclusion sits at epoch {b_epoch:?}; past-r0 log scans — A \
         authored {expected_a_commits} + {} more, B removed by {:?} on D; survivors dropped A: \
         {survivors_dropped_a}): {}; A's own row on D: {:?}; shared evidence kept on D: \
         {shared_evidence_kept}",
        final_row.as_ref().and_then(|row| row["phase"].as_str()),
        final_row
            .as_ref()
            .and_then(|row| row["result_epoch"].as_u64()),
        log_scans
            .iter()
            .filter_map(|scan| scan.as_ref())
            .map(|scan| scan.a_commits.saturating_sub(expected_a_commits))
            .sum::<usize>(),
        d_scan.as_ref().and_then(|scan| scan.removed_by.clone()),
        describe_all(&end),
        a_own_row
            .as_ref()
            .map(|row| (row["phase"].clone(), row["waiting"]["cause"].clone()))
    ));

    // Data plane after the resume: a survivor's new ciphertext opens on
    // C, and not on B. A's seat is its own obligation's outcome, so A's
    // decrypt is recorded, not gated.
    let (c_after, b_after, a_after) = match encrypt(sim, "D", &group).await? {
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
    let data_plane = c_after.0 && !b_after.0;
    receipt.note(format!(
        "data plane after the resume: C decrypt: {}; B decrypt: {} (A decrypt, recorded: {})",
        c_after.1, b_after.1, a_after.1
    ));

    receipt.note(format!(
        "A authored {} commits past r0 beyond its exit's own roster change (expected \
         {expected_a_commits}); B's removal commit signed by D on both survivors: \
         {b_removed_by_d}",
        log_scans
            .iter()
            .filter_map(|scan| scan.as_ref())
            .map(|scan| scan.a_commits)
            .max()
            .unwrap_or(0)
    ));
    let completion_kept = if a_holds_record {
        a_completed && a_row_final && !a_row_vanished
    } else {
        // The record ended with the removal that ended A's local
        // retention (§4 L275/D128): the shared obligation on D must be
        // intact instead (§4 L276), and the survivors must have
        // applied A's removal.
        shared_evidence_kept && survivors_dropped_a
    };
    receipt.evidence(
        "the_exclusion_holds_and_is_signed_by_d",
        b_gone_everywhere && still_signed_by_d && b_removed_by_d && completion_kept,
        format!(
            "B gone everywhere: {b_gone_everywhere}; heads past e0 signed by D: \
             {still_signed_by_d}; B's removal commit signed by D: {b_removed_by_d}; A's row kept \
             and complete: {a_row_final} (A's record ended: {}, an on-A completion was observed: \
             {a_completed}); {}",
            !a_holds_record,
            describe_all(&end)
        ),
        at(sim),
    );

    let passed = pending_ok
        && mark_seen
        && mark_names_d
        && row_open_at_mark
        && resumed
        && resumed_before_fallback
        && completion_kept
        && b_gone_everywhere
        && still_signed_by_d
        && b_removed_by_d
        && !a_authored
        && data_plane;
    if !passed {
        // On the red arm only the missing mark is the expected RED, and
        // only with the mislabel itself observed: every other failure
        // keeps ok=false (a false-cause stage makes the run not-RED), so
        // the gate's --expect=RED pin cannot be met while any other
        // failure persists or while A's row never showed the mislabel
        // the pin names.
        let strict_red = demoted;
        let mislabel_observed = observed_causes.contains("waiting_for_designated_admin");
        let (cause, ok, observed) = if !pending_ok {
            (
                CAUSE_NO_PENDING,
                !strict_red,
                format!(
                    "typed head-sync wait {typed_head_sync}; D's row names A: {d_names_a}; early \
                     move {early_move:?}; A at the exit: {}",
                    at_exit_view.describe()
                ),
            )
        } else if !resumed {
            (
                CAUSE_NO_RESUME,
                !strict_red,
                format!(
                    "B's exclusion epoch on the survivors: {b_epoch:?} (e0={e0}); {}",
                    describe_all(&resumed_views)
                ),
            )
        } else if !resumed_before_fallback {
            (
                CAUSE_LATE_FALLBACK,
                !strict_red,
                format!(
                    "D's first move {d_first_move:?} after t=0; the fallback clock allows it at \
                     W = {w:?}"
                ),
            )
        } else if !completion_kept {
            (
                CAUSE_NO_COMPLETION,
                !strict_red,
                format!(
                    "A's row for B completed on A: {a_completed} (final read {}), A retains a \
                     record: {a_holds_record}, shared evidence kept: {shared_evidence_kept}; the \
                     exclusion sits at epoch {b_epoch:?}",
                    a_row_final
                ),
            )
        } else if a_authored {
            (CAUSE_A_SEALED, !strict_red, describe_all(&end))
        } else if !b_gone_everywhere || !still_signed_by_d || !b_removed_by_d {
            (
                CAUSE_SECOND_ROTATION,
                !strict_red,
                format!(
                    "B's removal commit signed by D on both survivors: {b_removed_by_d}; {}",
                    describe_all(&end)
                ),
            )
        } else if !data_plane {
            (
                CAUSE_DATA_PLANE,
                !strict_red,
                format!("{}; {}", c_after.1, b_after.1),
            )
        } else if mark_seen {
            // The mark showed, but wrongly: a genuine failure, distinct
            // from a mark that never showed. On the red arm it stays
            // RED-ineligible (ok=false): the pin must not be met by a
            // wrong mark.
            (
                CAUSE_WRONG_MARK,
                !strict_red,
                format!(
                    "mark names D: {mark_names_d}; row open at the mark: {row_open_at_mark}; \
                     causes seen: {observed_causes:?}"
                ),
            )
        } else {
            // Only the typed mark is missing: the row's named failure.
            // On the red arm the pin is RED-eligible only when the
            // mislabel (`waiting_for_designated_admin`) was observed
            // live — a row that never evaluated the exit at all is not
            // the named divergence.
            (
                CAUSE_NO_MARK,
                !strict_red || mislabel_observed,
                format!(
                    "A {exit_kind}; causes A's row showed instead: {observed_causes:?}; mark names \
                     D: {mark_names_d}; row open at the mark: {row_open_at_mark}"
                ),
            )
        };
        receipt.cause(cause, Some(observed), ok, at(sim));
    }
    let final_name = if demoted { FINAL_RED } else { FINAL_CONTROL };
    receipt.finish(final_name, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, labels: &[&str], demoted: bool) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 `s4_local_authority_exit`. Timing from S4Timing::default() \
         (measured; D69, D73): {:?}; the exit fires while A's row is pending under the \
         ask-path hold, before W ({:?}) expires.",
        S4Timing::default(),
        S4Timing::default().designated_window
    ));
    match start(case, seed, labels).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, labels, demoted).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    let final_name = if demoted { FINAL_RED } else { FINAL_CONTROL };
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
    demoted: bool,
    want: Verdict,
) -> Result<()> {
    let receipt = run(case, seed, labels, demoted).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

const LABELS: &[&str] = &["A", "D", "B", "C"];

/// ADR 0110 `s4_local_authority_exit`, control arm — the revoked form:
/// A's agent revocation mid-window marks `local_committer_ineligible`
/// naming D without erasing the row, and D resumes and completes B's
/// exclusion.
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
fn w3h_1581f_control_local_authority_exit_revoked_committer() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581f_control_local_authority_exit_revoked_committer",
            0x1581_000a,
            LABELS,
            false,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_local_authority_exit`, the demoted form: §4 L274 wants
/// the same `local_committer_ineligible` mark from a worker demoted
/// mid-window, which stays a member and keeps its rows (L275, D72).
/// RED on `main`, which mislabels the demoted worker's row
/// `waiting_for_designated_admin` (the #1751 finding on #1581); GREEN
/// once the `evaluate_row` fix lands.
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
fn w3h_1581f_red_local_authority_exit_demoted_form() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581f_red_local_authority_exit_demoted_form",
            0x1581_000b,
            LABELS,
            true,
            // RED on main (CAUSE_NO_MARK, the mislabelled exit); GREEN
            // with the ADR 0110 §4 L274 fix in evaluate_row.
            Verdict::Red,
        )
        .await
    })
}
