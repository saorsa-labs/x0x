//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_evidence_holder`): A, D, B, C with A < D. D invites B, so D
//! holds B's authority-signed `MemberJoined` (its KeyPackage) while A
//! and C keep only the roster's committed hash; the case then prunes
//! A's and C's cached copies with the #1567 seam, so the designated
//! admin A cannot read B's leaf. At t = 0 B self-revokes; the holder D
//! is offline from before t = 0 and B's device is taken off the fabric
//! once A's first member-keyed catch-up round has begun (the round's
//! first send is parked by the production test seam, so B is
//! unreachable before any request could reach it — B is itself a
//! catch-up candidate while its roster seat is still Active). A's
//! public S4 row must show the typed
//! `waiting_for_member_key_package` (D64) and no fake absent-leaf
//! completion: nothing seals, the row stays open, the epoch stays e0.
//! The resume arm returns D at t = W + Δ and A completes the
//! exclusion by itself — H signed by the designated A, with no
//! remove or seal API call after t = 0. The row's item-8 control
//! (all evidence holders offline) is the second arm: through a
//! window past every S4 bound the typed wait is retained and nothing
//! completes. On `main` both arms are expected GREEN; the silent-wait
//! failure the row names (the typed state gone while the package is
//! still missing, or the row ended without the exclusion) is what the
//! arms catch, and the PR body records the neutralisation run that
//! showed them RED.
//!
//! Before t = 0 the ordinary `private_secure` (TreeKEM) group is
//! settled (every node at A's state revision r0 and epoch e0, four
//! leaves) and a data-plane probe opens on B and C; every node is past
//! its boot head gate. Healthy exit H: every survivor at exactly
//! e0 + 1 with three leaves, B not listed, no fork-quarantine, one
//! commit signed by A, and the data plane open on A and C and not on
//! B. Receipts use `w3h.receipt/1`.

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
/// After H, the case waits this long and re-reads, so a second rotation
/// (another epoch step) is seen.
const SETTLE: Duration = Duration::from_secs(30);
/// The no-holder arm re-reads this far past its last fixed read, so a
/// late fake completion (after the window it names) is still seen.
const LATE_READ: Duration = Duration::from_secs(5);
/// The no-holder arm holds past every S4 bound by this much: the row's
/// W + Δ release point plus the completion bound, then margin.
const PAST_BOUNDS: Duration = Duration::from_secs(10);
/// Budget for A's first member-keyed catch-up round to reach the parked
/// send (a worker tick or two after its intake).
const FIRST_ROUND: Duration = Duration::from_secs(15);
const PROBE: &[u8] = b"w3h-1581d probe";

const FINAL_RESUME: &str = "a_completes_the_exclusion_after_the_holders_return_without_an_api_seal";
const FINAL_NO_HOLDER: &str = "a_keeps_the_typed_member_key_package_wait_with_every_holder_offline";
const CAUSE_NO_TYPED_STATE: &str = "no typed waiting_for_member_key_package: A's public S4 row \
                                    exposed no cause, or lost it, while B's KeyPackage was still \
                                    missing";
const CAUSE_EARLY_SEAL: &str = "A sealed without B's KeyPackage: its epoch moved while every \
                                holder was unreachable, or its row left the open pending phase";
const CAUSE_NO_COMPLETION: &str = "A never completed the exclusion after D returned: the row \
                                   stayed open, or the survivors never reached one coherent \
                                   head";
const CAUSE_SECOND_ROTATION: &str = "the exclusion was not exactly one rotation: a survivor moved \
                                     past e0 + 1, or the commit was not signed by the designated \
                                     A";
const CAUSE_DATA_PLANE: &str = "the exclusion committed, but the data plane did not follow: A or \
                                C did not decrypt the new traffic, or B still could";

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

/// `inviter` invites `member`; A lists it and it reports itself active.
async fn seat(sim: &Sim, inviter: &str, member: &str, group: &str) -> Result<()> {
    let link = invite(sim, inviter, group).await?;
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

/// Whether `label` can resolve `member_hex`'s KeyPackage by the remove
/// route's own lookup (roster bytes or the cached `MemberJoined`).
async fn holds_package(sim: &Sim, label: &str, group: &str, member_hex: &str) -> Result<bool> {
    let state = sim.state(label)?;
    Ok(
        crate::server::routes::named_groups::holds_member_key_package_for_removal(
            &state, group, member_hex,
        )
        .await,
    )
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
/// D seated and promoted (A < D), C seated, and B seated by D's invite —
/// so D is B's inviter and the holder of B's authority-signed
/// KeyPackage — settled at (r0, e0, leaves0), the probe opens on B and
/// C, every node is past its restart sync wait, and A's and C's cached
/// `MemberJoined` copies for B are pruned (#1567 seam), leaving D the
/// only holder. Returns (group, internal group key, b, r0, e0,
/// leaves0).
async fn setup(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
) -> Result<(String, String, crate::identity::AgentId, u64, u64, u32)> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, labels).await?;
    let group = create_group(sim, "A").await?;
    seat(sim, "A", "D", &group).await?;
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
    // B and C are not members yet (D must be an admin before it invites
    // B), so the promotion wait polls the then-members only.
    sim.until("A and D see D's promotion", SETUP, async |s: &Sim| {
        for observer in ["A", "D"] {
            if !sees_admin(s, observer, &group, "D").await.unwrap_or(false) {
                return false;
            }
        }
        true
    })
    .await?;
    seat(sim, "A", "C", &group).await?;
    // D, not A, invites B: the inviter holds the KeyPackage bytes and is
    // the first member-keyed catch-up candidate (`added_by`).
    seat(sim, "D", "B", &group).await?;

    let (b, _) = sim.ids("B")?;
    let b_hex = sim.agent_hex("B")?;
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
    // D, the holder the row names, must hold B's KeyPackage by the
    // remove route's own lookup. A miss here is INFRA, not the S4 path.
    sim.until(
        "D holds B's authority-signed KeyPackage",
        SETUP,
        async |s: &Sim| holds_package(s, "D", &group, &b_hex).await.unwrap_or(false),
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

    // The row's premise (#1567 seam): A and C keep only the roster's
    // committed hash of B's KeyPackage; D keeps the bytes. The prune is
    // INFRA-checked — a node whose roster already holds the bytes does
    // not test the catch-up path.
    let internal = {
        let state = sim.state("A")?;
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &group)
            .context("resolve the internal group key")?
            .0
            .to_string()
    };
    let mut pruned = Vec::new();
    for label in ["A", "C"] {
        let state = sim.state(label)?;
        ensure!(
            crate::server::routes::named_groups::forget_member_join_copy_for_test(
                &state, &group, &b_hex
            )
            .await,
            "{label} holds B's KeyPackage in its roster; the lost-copy premise does not hold"
        );
        pruned.push(format!(
            "{label} holds after the prune: {}",
            holds_package(sim, label, &group, &b_hex).await?
        ));
    }
    let d_holds = holds_package(sim, "D", &group, &b_hex).await?;
    let a_lacks = !holds_package(sim, "A", &group, &b_hex).await?;
    let c_lacks = !holds_package(sim, "C", &group, &b_hex).await?;
    receipt.evidence(
        "d_holds_b_key_package_a_and_c_lack_it",
        d_holds && a_lacks && c_lacks,
        format!("D holds: {d_holds}; {pruned:?}"),
        at(sim),
    );
    sim.fabric()
        .mark("case: A's and C's cached MemberJoined copies for B pruned");
    Ok((group, internal, b, r0, e0, leaves0))
}

/// Both arms share one body: the holder D offline before t = 0, B's
/// self-revocation, B off the fabric once A's first catch-up round has
/// begun, the typed wait through the hold, and then per `resume`
/// either D's return and the autonomous completion, or the all-holders
/// window past every bound.
async fn scenario(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
    resume: bool,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let timing = S4Timing::default();
    let w = timing.designated_window;
    let delta = timing.fallback_stagger;
    let (group, internal, b, r0, e0, leaves0) = setup(sim, receipt, labels).await?;
    let b_hex = sim.agent_hex("B")?;
    let a_hex = sim.agent_hex("A")?;
    let survivors = ["A", "D", "C"];

    // The holder is held from before the trigger; its return (resume
    // arm) is the row's t = W + Δ release point.
    sim.set_online("D", false)?;
    sim.fabric()
        .mark("fault: D offline (the only KeyPackage holder)");
    // Park A's first member-keyed catch-up send (the round asks D
    // first), so B is off the fabric before any request could reach it
    // — B is itself a catch-up candidate while its seat is Active.
    let seam_key =
        crate::server::routes::named_groups::detached_send_test_seam::key_package_catchup_key(
            &internal, &b_hex,
        );
    let pause = crate::server::routes::named_groups::detached_send_test_seam::arm(&seam_key);

    // t = 0: B revokes its own agent; A and C observe (D and B go dark
    // right after, below).
    let t0 = sim.fabric().now();
    sim.fabric().mark_indexed("case: t=0 trigger SelfRevoke");
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": b_hex, "reason": "w3h-1581d"})),
        )
        .await?;
    ensure!(status.is_success(), "B self-revokes: {status} {body}");
    receipt.request_delivered(
        "b_self_revoke_answered",
        status.is_success(),
        format!("B POST /identity/revoke: {status} {body}"),
        at(sim),
    );
    await_holders(sim, &["A", "C"], &b_hex).await?;

    // A's first catch-up round reaches the parked send (its worker
    // attempt already answered `member_key_package_pending`); B then
    // leaves the fabric before the round's later candidates are asked.
    let reached = sim
        .until(
            "A's first member-keyed catch-up round begins (send parked)",
            FIRST_ROUND,
            async |_s: &Sim| pause.reached(),
        )
        .await
        .is_ok();
    sim.set_online("B", false)?;
    sim.fabric()
        .mark("fault: B offline (the revoked target's device)");
    drop(pause);
    receipt.evidence(
        "b_offline_before_any_catchup_round_could_reach_it",
        reached,
        "A's first member-keyed catch-up send was parked by the production seam, B left the \
         fabric, then the send was released; B is a catch-up candidate while its seat is Active"
            .to_string(),
        at(sim),
    );

    // The typed wait (D64) while the package is missing: a silent wait
    // or a bare timeout fails the row.
    let mut typed_seen_at: Option<Duration> = None;
    let waited = sim
        .until(
            "A's row waits for B's KeyPackage",
            w,
            async |s: &Sim| match s4_row(s, "A", &group, &b_hex).await {
                Ok(Some(row)) => {
                    if row["waiting"]["cause"].as_str() == Some("waiting_for_member_key_package") {
                        typed_seen_at.get_or_insert(s.fabric().now().saturating_sub(t0));
                        true
                    } else {
                        false
                    }
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
    receipt.note(format!(
        "A's typed waiting_for_member_key_package first seen {typed_seen_at:?} after t=0"
    ));

    // Hold to the row's t = W + Δ release point; through the whole
    // window nothing may seal and the typed wait is retained (no fake
    // absent-leaf completion: the row stays open, the epoch stays e0).
    let release_at = t0.saturating_add(w).saturating_add(delta);
    let left = release_at.saturating_sub(sim.fabric().now());
    sim.within(
        "hold the holder offline to t = W + delta",
        left + secs(2),
        async {
            tokio::time::sleep(left).await;
        },
    )
    .await?;
    let held_view = sim
        .at_instant(
            "read A at the release point",
            view_now(sim, "A", &group, &b),
        )
        .await??;
    let held_row = sim
        .at_instant(
            "read A's public S4 row at the release point",
            s4_row(sim, "A", &group, &b_hex),
        )
        .await??;
    let held_c = views(sim, &["C"], &group, &b).await?;
    let held_quiet = held_view.epoch == Some(e0)
        && held_view.state_revision == r0
        && !held_view.quarantined
        && held_c.first().is_some_and(|(_, seen)| {
            seen.as_ref().is_some_and(|seen| {
                seen.epoch == Some(e0) && seen.state_revision == r0 && !seen.quarantined
            })
        });
    let held_typed = held_row.as_ref().is_some_and(|row| {
        row["phase"]
            .as_str()
            .is_some_and(|phase| phase != "complete" && phase != "terminated")
            && row["waiting"]["cause"].as_str() == Some("waiting_for_member_key_package")
    });
    let a_still_lacks = !sim
        .at_instant(
            "A still lacks B's KeyPackage at the release point",
            holds_package(sim, "A", &group, &b_hex),
        )
        .await??;
    // The typed wait itself is judged in `passed` with its named cause,
    // not asserted here, so a silent wait is the row's RED, not INFRA.
    receipt.evidence(
        "a_seals_nothing_and_still_lacks_the_package_through_the_hold",
        held_quiet && a_still_lacks,
        format!(
            "at t=W+Δ (W {w:?}, Δ {delta:?}): A {}; C {}; A's row {held_row:?}; A still lacks the \
             package: {a_still_lacks}",
            held_view.describe(),
            describe_all(&held_c)
        ),
        at(sim),
    );

    if resume {
        // The row's resume: the holder returns, the authenticated
        // existing catch-up finishes, and A — the designated admin —
        // completes the exclusion by itself. No remove or seal API is
        // called after t = 0.
        sim.set_online("D", true)?;
        sim.fabric()
            .mark("case: D returns at t = W + delta (the holder)");
        sim.until("D reconnects", SETUP, async |s: &Sim| {
            connected_to(s, "D", "A").await || connected_to(s, "D", "C").await
        })
        .await?;
        let mut d_record = Observations::default();
        let d_holds_record = sim
            .until("D holds B's revocation", EVIDENCE, async |s: &Sim| {
                d_record.observe(holds_revocation(s, "D", &b_hex)).await == Some(true)
            })
            .await
            .is_ok();
        receipt.note(format!(
            "D reconnected and holds B's revocation record after its return: {d_holds_record}"
        ));

        // H on every survivor, signed by the designated A, within the
        // ADR bound for this shape: the holder's release at W + Δ, then
        // the completion bound, then the catch-up throttle margin.
        let bound = w
            .saturating_add(delta)
            .saturating_add(timing.completion_bound);
        let mut seen = Observations::default();
        let mut completed = false;
        let waited = sim
            .until(
                "the survivors reach H",
                bound + secs(15),
                async |s: &Sim| {
                    let Some(now) = seen.observe(views_now(s, &survivors, &group, &b)).await else {
                        return true;
                    };
                    let done = excluded(&now, e0, leaves0)
                        && matches!(
                            s4_row(s, "A", &group, &b_hex).await,
                            Ok(Some(row)) if row["phase"].as_str() == Some("complete")
                        );
                    if done {
                        completed = true;
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
        seen.verify("the survivors reach H")?;
        sim.within("the resume settles", SETTLE + secs(2), async {
            tokio::time::sleep(SETTLE).await;
        })
        .await?;
        let end = views(sim, &survivors, &group, &b).await?;
        let final_row = sim
            .at_instant("read A's completed row", s4_row(sim, "A", &group, &b_hex))
            .await?;
        let row_ok = final_row.as_ref().is_ok_and(|row| {
            row.as_ref().is_some_and(|row| {
                row["phase"].as_str() == Some("complete")
                    && row["result_epoch"].as_u64() == Some(e0 + 1)
            })
        });
        let h_once = excluded(&end, e0, leaves0) && all_at(&end, e0 + 1);
        let signed_by_a = end.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(a_hex.as_str()))
        });

        // Data plane after the resume: a survivor's new ciphertext opens
        // on A and C, and not on B.
        let (a_after, c_after, b_after) = match encrypt(sim, "C", &group).await? {
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
        receipt.note(format!(
            "after the resume: completed {completed}; A's row {final_row:?}; {}; A decrypt: {}; C \
             decrypt: {}; B decrypt: {}",
            describe_all(&end),
            a_after.1,
            c_after.1,
            b_after.1
        ));

        let passed = reached
            && typed_seen_at.is_some()
            && held_quiet
            && held_typed
            && a_still_lacks
            && completed
            && row_ok
            && h_once
            && signed_by_a
            && data_plane;
        if !passed {
            // Only the named failures of the row make a RED; anything
            // else stays ok=false (INFRA), so an unrelated regression
            // cannot satisfy a --expect=RED pin.
            let (cause, ok, observed) = if typed_seen_at.is_none() {
                (
                    CAUSE_NO_TYPED_STATE,
                    true,
                    "A never exposed the typed waiting_for_member_key_package while its holder \
                     was offline"
                        .to_string(),
                )
            } else if !held_quiet || !held_typed {
                (
                    CAUSE_EARLY_SEAL,
                    true,
                    format!(
                        "through the hold: A {}; C {}; A's row {held_row:?}",
                        held_view.describe(),
                        describe_all(&held_c)
                    ),
                )
            } else if !completed || !row_ok {
                (
                    CAUSE_NO_COMPLETION,
                    true,
                    format!("A's row {final_row:?}; {}", describe_all(&end)),
                )
            } else if !h_once || !signed_by_a {
                (CAUSE_SECOND_ROTATION, true, describe_all(&end))
            } else {
                (
                    CAUSE_DATA_PLANE,
                    true,
                    format!("{}; {}; {}", a_after.1, c_after.1, b_after.1),
                )
            };
            receipt.cause(cause, Some(observed), ok, at(sim));
        }
        receipt.finish(FINAL_RESUME, passed, at(sim));
    } else {
        // The row's item-8 control: every holder is offline (D and B off
        // the fabric, C pruned) and stays offline past every S4 bound —
        // the W + Δ release point, the completion bound on top, then
        // margin. The typed wait is retained, the row stays open, and
        // nothing seals or quarantines; a re-read a little later catches
        // a late fake completion.
        let past = release_at
            .saturating_add(timing.completion_bound)
            .saturating_add(PAST_BOUNDS);
        let left = past.saturating_sub(sim.fabric().now());
        sim.within(
            "hold every holder offline past every bound",
            left + secs(2),
            async {
                tokio::time::sleep(left).await;
            },
        )
        .await?;
        let late_view = sim
            .at_instant("read A past every bound", view_now(sim, "A", &group, &b))
            .await??;
        let late_row = sim
            .at_instant(
                "read A's public S4 row past every bound",
                s4_row(sim, "A", &group, &b_hex),
            )
            .await??;
        let late_c = views(sim, &["C"], &group, &b).await?;
        let row_open = late_row.as_ref().is_some_and(|row| {
            row["phase"]
                .as_str()
                .is_some_and(|phase| phase != "complete" && phase != "terminated")
        });
        let typed_retained = late_row
            .as_ref()
            .and_then(|row| row["waiting"]["cause"].as_str())
            == Some("waiting_for_member_key_package");
        let nothing_sealed = late_view.epoch == Some(e0)
            && late_view.state_revision == r0
            && !late_view.quarantined
            && late_c.first().is_some_and(|(_, seen)| {
                seen.as_ref().is_some_and(|seen| {
                    seen.epoch == Some(e0) && seen.state_revision == r0 && !seen.quarantined
                })
            });
        receipt.note(format!(
            "past every bound (release {w:?}+{delta:?}, completion {:?}, margin \
             {PAST_BOUNDS:?}): A {}; C {}; A's row {late_row:?}",
            timing.completion_bound,
            late_view.describe(),
            describe_all(&late_c)
        ));

        // The re-read: a completion that lands just after the window is
        // still a fake absent-leaf completion under an all-holders
        // blackout.
        sim.within("the late re-read", LATE_READ + secs(1), async {
            tokio::time::sleep(LATE_READ).await;
        })
        .await?;
        let recheck_row = sim
            .at_instant(
                "re-read A's public S4 row after the late window",
                s4_row(sim, "A", &group, &b_hex),
            )
            .await??;
        let recheck_view = views(sim, &["A", "C"], &group, &b).await?;
        let still_open = recheck_row.as_ref().is_some_and(|row| {
            row["phase"]
                .as_str()
                .is_some_and(|phase| phase != "complete" && phase != "terminated")
                && row["waiting"]["cause"].as_str() == Some("waiting_for_member_key_package")
        });
        let still_quiet = recheck_view.iter().all(|(_, seen)| {
            seen.as_ref().is_some_and(|seen| {
                seen.epoch == Some(e0) && seen.state_revision == r0 && !seen.quarantined
            })
        });
        receipt.note(format!(
            "the late re-read: row open with the typed wait {still_open}; quiet {still_quiet}; {}",
            describe_all(&recheck_view)
        ));

        let passed = reached
            && typed_seen_at.is_some()
            && held_typed
            && held_quiet
            && row_open
            && typed_retained
            && nothing_sealed
            && still_open
            && still_quiet;
        if !passed {
            let (cause, ok, observed) = if typed_seen_at.is_none() || !typed_retained || !still_open
            {
                (
                    CAUSE_NO_TYPED_STATE,
                    true,
                    format!(
                        "A's row at the release point {held_row:?}; past every bound {late_row:?}; \
                         re-read {recheck_row:?}"
                    ),
                )
            } else if !held_quiet || !nothing_sealed || !still_quiet {
                (
                    CAUSE_EARLY_SEAL,
                    true,
                    format!(
                        "A at the release point {}; past every bound {}; re-read {}",
                        held_view.describe(),
                        late_view.describe(),
                        describe_all(&recheck_view)
                    ),
                )
            } else {
                (
                    CAUSE_NO_TYPED_STATE,
                    true,
                    format!("A's row past every bound {late_row:?}"),
                )
            };
            receipt.cause(cause, Some(observed), ok, at(sim));
        }
        receipt.finish(FINAL_NO_HOLDER, passed, at(sim));
    }
    Ok(())
}

async fn run(case: &str, seed: u64, labels: &[&str], resume: bool) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 `s4_evidence_holder`. Timing from S4Timing::default() (measured; D69, \
         D73): {:?}; the holder returns at t = W + Δ.",
        S4Timing::default()
    ));
    match start(case, seed, labels).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, labels, resume).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    let final_name = if resume {
        FINAL_RESUME
    } else {
        FINAL_NO_HOLDER
    };
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(final_name);
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, labels: &[&str], resume: bool, want: Verdict) -> Result<()> {
    let receipt = run(case, seed, labels, resume).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

const LABELS: &[&str] = &["A", "D", "B", "C"];

/// ADR 0110 `s4_evidence_holder`, the resume arm: A, the designated
/// admin, lacks B's KeyPackage; the holder D returns at t = W + Δ and
/// the authenticated catch-up finishes; A completes the exclusion by
/// itself — H signed by A, no remove or seal API after t = 0.
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
fn w3h_1581d_control_evidence_holder_resume_after_holder_returns() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581d_control_evidence_holder_resume_after_holder_returns",
            0x1581_0006,
            LABELS,
            true,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_evidence_holder`, the item-8 control: with every
/// evidence holder offline past every S4 bound, A keeps the typed
/// `waiting_for_member_key_package` — no fake absent-leaf completion,
/// nothing seals, no quarantine. GREEN on `main`; the PR body records
/// the neutralisation run that showed this arm RED when the typed
/// state was dropped.
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
fn w3h_1581d_red_evidence_holder_all_holders_offline() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581d_red_evidence_holder_all_holders_offline",
            0x1581_0007,
            LABELS,
            false,
            Verdict::Green,
        )
        .await
    })
}
