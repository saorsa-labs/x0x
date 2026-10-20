//! W3-H cases for #1357 (ADR 0110 S4, revocation eviction, designated
//! admin first). Harness first (D16/D54): the red arms are committed and
//! shown RED on `main` before S4 code merges; the controls are GREEN before
//! and after.
//!
//! B is the target and C a survivor. The ordinary arms use a
//! `private_secure` (TreeKEM) group that A creates through the public API;
//! the Home arm uses A's Home (`OwnerCertified`, TreeKEM), with B and C
//! certified by A's owner key and seated through `POST /home/seat`. Before
//! t = 0 the group is settled (every node at A's state revision and TreeKEM
//! epoch e0, with `n` leaves) and a data-plane check passes (A encrypts; B
//! and C decrypt).
//!
//! Healthy exit H (ADR 0110 Validation): every survivor lists B as not
//! active and holds one TreeKEM epoch above e0 with `n - 1` leaves and no
//! fork-quarantine marker, and the adder A (when it is a survivor) no
//! longer tracks B's leaf. H must hold [`SETTLE`] later at exactly e0 + 1
//! (one exclusion, no duplicate rekey). Then a survivor encrypts, C opens
//! it, and B does not or cannot (on `main` B's own daemon still decrypts
//! after it revoked itself; only its epoch decides).
//!
//! Arms:
//!
//! - `s4_idle_revocation_one_admin` (RED on `main`). Nodes A, B, C; A is
//!   the only admin. At t = 0 B revokes its own agent through
//!   `POST /identity/revoke` (the issuer API; ADR 0110 "repeat
//!   self-revocation and ordinary groups"). A and C must hold the record.
//!   No seal or removal API is called. Desired: H within
//!   [`S4_COMPLETION_BOUND_PLACEHOLDER`]. `main` has no revocation
//!   eviction, so B stays seated at e0 on A and C ([`CAUSE_IDLE`]).
//! - `s4_idle_revocation_one_admin`, Home variant (RED on `main`). A owns
//!   the Home and is its only admin. At t = 0 A issuer-revokes B through
//!   `DELETE /owner/agents/:id` (ADR-0018, signed by the owner key). The
//!   rest is as above.
//! - `s4_self_leave_crypto_only` (control, GREEN on `main`). Nodes A, B, C.
//!   At t = 0 B leaves (`DELETE /groups/:id`). #1113 / PR #1337 already
//!   makes the lowest active admin commit the TreeKEM removal after a
//!   self-leave, so this is GREEN on `main`. After S4 the same rekey runs
//!   through ADR 0110's designated-first path (§"responsive rekey after
//!   self-leave"), so it must stay GREEN.
//! - `s4_self_leave_crypto_only`, revocation after the leave (control,
//!   GREEN on `main`). As above; once A and C hold the leave, B revokes
//!   its own agent. Desired: one exclusion (exactly e0 + 1 after
//!   [`SETTLE`]) and B stays `Removed`. On `main` the leave rekeys and the
//!   revocation does nothing more; after S4 the revocation must not rekey
//!   a second time.
//! - `s4_fallback_rank_manual` (RED on `main`). Nodes A, D, E, B, C, with
//!   admins A < D < E by agent id (the case reassigns the pre-generated
//!   keys of A, D and E so that this holds). A is held off the fabric
//!   (the designated admin, stalled). At t = 0 B revokes its own agent; D,
//!   E and C must hold the record. Then D calls the public remove API on
//!   B, well before W. Desired: D's request is queued with the typed state
//!   `waiting_for_designated_admin` naming A, no survivor's epoch moves
//!   in the next [`EARLY_READ`], and the ranked fallback then reaches H
//!   within W + Δ + the completion bound. `main` rekeys at once
//!   ([`CAUSE_MANUAL`]).
//! - `s4_manual_remove_without_obligation` (control, GREEN on `main`). The
//!   same five nodes, A held, but no revocation: D's manual remove of B is
//!   not affected by S4, so it rekeys at once and reaches H.
//!
//! W, Δ and the completion bound are not measured yet (D69, D73). The case
//! uses generous named placeholders so that the RED verdict means "never
//! happens on `main`", not a timing miss. Replace them with the W3-H
//! p99.9 numbers (`s4_timing_measurement`) before timing-dependent S4 code
//! merges.
//!
//! Receipts use `w3h.receipt/1`. The D196 receipt is 20 verdict-stable
//! reruns on the W3-H gate.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::identity::UserKeypair;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// PLACEHOLDER for ADR 0110's completion bound (D69): replace it with the
/// W3-H p99.9 measured number before timing-dependent S4 code merges.
/// Generous on purpose: the red verdict is about "never happens on main".
const S4_COMPLETION_BOUND_PLACEHOLDER: Duration = Duration::from_secs(120);
/// PLACEHOLDER for ADR 0110's designated-admin window W (D69): replace it
/// with the measured number before timing-dependent S4 code merges.
const S4_W_PLACEHOLDER: Duration = Duration::from_secs(60);
/// PLACEHOLDER for ADR 0110's fallback rank step Δ (D73): replace it with
/// the measured number before timing-dependent S4 code merges.
const S4_DELTA_PLACEHOLDER: Duration = Duration::from_secs(30);
/// The bound for arms whose designated admin is held: W + Δ + completion.
const FALLBACK_BOUND: Duration = Duration::from_secs(
    S4_W_PLACEHOLDER.as_secs()
        + S4_DELTA_PLACEHOLDER.as_secs()
        + S4_COMPLETION_BOUND_PLACEHOLDER.as_secs(),
);
/// How long after a non-designated manual request the case checks that no
/// survivor rekeyed. Far below any plausible W.
const EARLY_READ: Duration = Duration::from_secs(5);
/// After H, the case waits this long and re-reads, so a duplicate rekey
/// (a second epoch step) is seen.
const SETTLE: Duration = Duration::from_secs(30);
/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for the revocation record to reach the holders.
const EVIDENCE: Duration = Duration::from_secs(60);
const PROBE: &[u8] = b"w3h-1357 probe";

const FINAL_H: &str = "survivors_exclude_b_cryptographically_once_within_the_bound";
const FINAL_MANUAL: &str =
    "non_designated_manual_remove_queues_as_waiting_for_designated_admin_then_reaches_h";
const CAUSE_IDLE: &str = "no revocation eviction on main: after the bound every survivor still \
                          lists B active, at epoch e0, with the same leaf count";
const CAUSE_SELF_LEAVE: &str =
    "B's leaf retained after self-leave: survivors remain at epoch e0 with the same leaf count";
const CAUSE_LEAVE_THEN_REVOKE: &str = "B's leaf retained after a self-leave and a later \
                                       revocation: survivors remain at epoch e0 with the same \
                                       leaf count";
const CAUSE_MANUAL: &str = "non-designated manual remove rekeys at once on main: D's remove of B \
                            returned success without waiting_for_designated_admin and a survivor \
                            left epoch e0 within EARLY_READ while the designated admin A was held";
const CAUSE_NO_OBLIGATION: &str =
    "D's manual remove did not exclude B: survivors remain at epoch e0 with the same leaf count";

/// What happens at t = 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trigger {
    /// B revokes its own agent (`POST /identity/revoke`).
    SelfRevoke,
    /// A, the Home owner, issuer-revokes B (`DELETE /owner/agents/:id`).
    OwnerRevoke,
    /// B leaves (`DELETE /groups/:id`).
    Leave,
    /// B leaves; once A and C hold the leave, B revokes its own agent.
    LeaveThenRevoke,
    /// Nothing; only the manual request follows.
    Nothing,
}

impl Trigger {
    fn revokes(self) -> bool {
        matches!(
            self,
            Self::SelfRevoke | Self::OwnerRevoke | Self::LeaveThenRevoke
        )
    }

    fn leaves(self) -> bool {
        matches!(self, Self::Leave | Self::LeaveThenRevoke)
    }
}

/// How the designated admin A is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    /// A stays reachable.
    Reachable,
    /// A is off the fabric from before t = 0 to the end.
    Offline,
}

/// The desired-behaviour assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    /// H within the bound, once.
    Healthy,
    /// D's manual request queues and nothing moves early; then H.
    ManualQueued,
}

/// One arm of the case.
#[derive(Clone, Copy, Debug)]
struct Arm {
    labels: &'static [&'static str],
    /// Use A's Home instead of an ordinary group.
    home: bool,
    /// Admins A promotes after seating everyone (A < D < E by agent id).
    promoted: &'static [&'static str],
    /// Nodes that must reach H. The first one encrypts the probe.
    survivors: &'static [&'static str],
    /// Nodes that must hold B's revocation record.
    holders: &'static [&'static str],
    hold: Hold,
    trigger: Trigger,
    /// D calls the public remove API on B after the trigger.
    manual: bool,
    check: Check,
    bound: Duration,
    cause: &'static str,
}

const THREE: &[&str] = &["A", "B", "C"];
const FIVE: &[&str] = &["A", "D", "E", "B", "C"];

const IDLE: Arm = Arm {
    labels: THREE,
    home: false,
    promoted: &[],
    survivors: &["A", "C"],
    holders: &["A", "C"],
    hold: Hold::Reachable,
    trigger: Trigger::SelfRevoke,
    manual: false,
    check: Check::Healthy,
    bound: S4_COMPLETION_BOUND_PLACEHOLDER,
    cause: CAUSE_IDLE,
};

const HOME_IDLE: Arm = Arm {
    home: true,
    trigger: Trigger::OwnerRevoke,
    ..IDLE
};

const SELF_LEAVE: Arm = Arm {
    holders: &[],
    trigger: Trigger::Leave,
    cause: CAUSE_SELF_LEAVE,
    ..IDLE
};

const LEAVE_THEN_REVOKE: Arm = Arm {
    trigger: Trigger::LeaveThenRevoke,
    cause: CAUSE_LEAVE_THEN_REVOKE,
    ..IDLE
};

const MANUAL_DURING_WINDOW: Arm = Arm {
    labels: FIVE,
    home: false,
    promoted: &["D", "E"],
    survivors: &["D", "E", "C"],
    holders: &["D", "E", "C"],
    hold: Hold::Offline,
    trigger: Trigger::SelfRevoke,
    manual: true,
    check: Check::ManualQueued,
    bound: FALLBACK_BOUND,
    cause: CAUSE_MANUAL,
};

const MANUAL_WITHOUT_OBLIGATION: Arm = Arm {
    holders: &[],
    trigger: Trigger::Nothing,
    check: Check::Healthy,
    bound: S4_COMPLETION_BOUND_PLACEHOLDER,
    cause: CAUSE_NO_OBLIGATION,
    ..MANUAL_DURING_WINDOW
};

impl Arm {
    fn ranked_admins(self) -> bool {
        !self.promoted.is_empty()
    }

    fn final_name(self) -> &'static str {
        match self.check {
            Check::ManualQueued => FINAL_MANUAL,
            Check::Healthy => FINAL_H,
        }
    }
}

#[derive(Debug, Clone)]
struct View {
    state_revision: u64,
    /// Whether B is an active roster member.
    lists_b: bool,
    /// B's roster state (`Active`, `Removed`, …), if B has a row.
    b_state: Option<String>,
    quarantined: bool,
    epoch: Option<u64>,
    leaves: Option<u32>,
    /// Whether the live TreeKEM group still maps B to a leaf. Only the
    /// node that added B tracks it.
    tracks_b: Option<bool>,
}

impl View {
    fn describe(&self) -> String {
        format!(
            "state={} lists_b={} b_state={:?} epoch={:?} leaves={:?} tracks_b={:?} quarantined={}",
            self.state_revision,
            self.lists_b,
            self.b_state,
            self.epoch,
            self.leaves,
            self.tracks_b,
            self.quarantined
        )
    }
}

/// `label`'s view of `group`; `None` when it holds no record of it.
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
        let b_row = info
            .members_v2
            .values()
            .find(|member| member.agent_id.eq_ignore_ascii_case(&b_hex));
        let view = View {
            state_revision: info.state_revision,
            lists_b: info
                .active_members()
                .any(|member| member.agent_id.eq_ignore_ascii_case(&b_hex)),
            b_state: b_row.map(|member| format!("{:?}", member.state)),
            quarantined: info.fork_quarantine.is_some(),
            epoch: None,
            leaves: None,
            tracks_b: None,
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
        tracks_b: Some(guard.tracks_member(b)),
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
        .with_context(|| format!("{label} has no record of {group}"))
}

async fn view(sim: &Sim, label: &str, group: &str, b: &crate::identity::AgentId) -> Result<View> {
    sim.at_instant(
        &format!("read {label}'s group"),
        view_now(sim, label, group, b),
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
            || seen.tracks_b == Some(true)
            || epoch.is_some_and(|first| first != now)
        {
            return false;
        }
        epoch = Some(now);
    }
    !views.is_empty()
}

/// Every survivor still seats B at e0 with the original leaf count.
fn still_seated(views: &[(&str, Option<View>)], e0: u64, leaves0: u32) -> bool {
    !views.is_empty()
        && views.iter().all(|(_, seen)| {
            seen.as_ref().is_some_and(|seen| {
                seen.lists_b && seen.epoch == Some(e0) && seen.leaves == Some(leaves0)
            })
        })
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

async fn views_now(
    sim: &Sim,
    labels: &[&'static str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Vec<(&'static str, Option<View>)>> {
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        out.push((*label, try_view_now(sim, label, group, b).await?));
    }
    Ok(out)
}

async fn views(
    sim: &Sim,
    labels: &[&'static str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Vec<(&'static str, Option<View>)>> {
    sim.at_instant(
        "read the survivors' groups",
        views_now(sim, labels, group, b),
    )
    .await?
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
        .with_context(|| format!("{observer} has no record of {group}"))?;
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

/// Start the nodes of an ordinary arm. In the five-node arms, A, D and E
/// get the three pre-generated key pairs sorted by agent id, so A < D < E
/// (B and C keep theirs). The swap happens before any daemon runs. A Home
/// arm starts no daemon here: [`home_setup`] starts them as owner devices.
async fn start(case: &str, seed: u64, arm: Arm) -> Result<Sim> {
    let labels = arm.labels;
    let mut sim = Sim::empty(case, seed, labels)?;
    if arm.home {
        return Ok(sim);
    }
    let mut provisions: BTreeMap<&str, Provision> = BTreeMap::new();
    if arm.ranked_admins() {
        let ranked = ["A", "D", "E"];
        let mut pairs = Vec::with_capacity(ranked.len());
        for label in ranked {
            pairs.push(sim.take_keys(label)?);
        }
        pairs.sort_by_key(|pair| pair.1.agent_id().0);
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
            .mark("case: admin keys reassigned so that A < D < E by agent id");
    }
    for label in labels {
        let provision = provisions.remove(label).unwrap_or_default();
        sim.start_node_with(label, provision).await?;
    }
    Ok(sim)
}

/// A provisions its Home with a fresh owner key, certifies B and C as
/// same-owner devices and seats them. Returns the Home's group id.
async fn home_setup(sim: &mut Sim) -> Result<String> {
    // Before any daemon starts, like the node keys (`Sim::empty`).
    let owner = UserKeypair::generate()?;
    let home = sim.start_owner_device("A", &owner).await?;
    for device in ["B", "C"] {
        sim.certify_owner_device("A", device, &owner, &home).await?;
    }
    for member in ["B", "C"] {
        let invite = sim.home_seat("A", member, &home).await?;
        ensure!(
            sim.join_home("A", member, &home, &invite, SETUP).await?,
            "setup: A could not seat {member} in its Home"
        );
    }
    Ok(home.gid)
}

/// An ordinary `private_secure` group: A creates it, seats everyone and
/// promotes the arm's admins; every node sees every promotion.
async fn ordinary_setup(sim: &Sim, arm: Arm) -> Result<String> {
    let labels = arm.labels;
    let group = create_group(sim, "A").await?;
    for member in labels.iter().filter(|label| **label != "A") {
        seat(sim, member, &group).await?;
    }
    for admin in arm.promoted {
        let hex = sim.agent_hex(admin)?;
        let (status, body) = sim
            .api(
                "A",
                Method::PATCH,
                &format!("/groups/{group}/members/{hex}/role"),
                Some(json!({"role": "admin"})),
            )
            .await?;
        ensure!(status.is_success(), "promote {admin}: {status} {body}");
    }
    sim.until("every node sees every promotion", SETUP, async |s: &Sim| {
        for observer in labels {
            for admin in arm.promoted {
                if !sees_admin(s, observer, &group, admin)
                    .await
                    .unwrap_or(false)
                {
                    return false;
                }
            }
        }
        true
    })
    .await?;
    Ok(group)
}

/// Wait until every holder holds B's revocation record. The record not
/// arriving is INFRA (the trigger never reached its target).
async fn await_holders(sim: &Sim, holders: &[&'static str], b_hex: &str) -> Result<()> {
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

/// Which of `holders` hold B's revocation record now.
async fn held_by(
    sim: &Sim,
    holders: &[&'static str],
    b_hex: &str,
) -> Result<Vec<(&'static str, bool)>> {
    let mut held = Vec::with_capacity(holders.len());
    for holder in holders {
        let has = sim
            .at_instant(
                "read a holder's revocations",
                holds_revocation(sim, holder, b_hex),
            )
            .await??;
        held.push((*holder, has));
    }
    Ok(held)
}

/// Every survivor at exactly `epoch`.
fn all_at(views: &[(&str, Option<View>)], epoch: u64) -> bool {
    !views.is_empty()
        && views
            .iter()
            .all(|(_, seen)| seen.as_ref().is_some_and(|seen| seen.epoch == Some(epoch)))
}

/// Every survivor keeps B's leaf: epoch e0 and the original leaf count
/// (and, after a revocation, B still listed active).
fn retained(views: &[(&str, Option<View>)], e0: u64, leaves0: u32, listed: bool) -> bool {
    if listed {
        return still_seated(views, e0, leaves0);
    }
    !views.is_empty()
        && views.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.epoch == Some(e0) && seen.leaves == Some(leaves0))
        })
}

async fn scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let labels = arm.labels;
    let survivors = arm.survivors;
    let group = if arm.home {
        home_setup(sim).await?
    } else {
        mesh(sim, labels).await?;
        ordinary_setup(sim, arm).await?
    };
    let (b, _) = sim.ids("B")?;
    let b_hex = sim.agent_hex("B")?;
    let a_hex = sim.agent_hex("A")?;
    settled(sim, labels, &group, &b).await?;
    let base = view(sim, "A", &group, &b).await?;
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
    if arm.hold == Hold::Offline {
        sim.set_online("A", false)?;
    }
    receipt.setup_done(at(sim));

    receipt.evidence(
        if arm.home {
            "home_treekem_group_settled_with_b_seated"
        } else {
            "treekem_group_settled_with_b_seated"
        },
        base.lists_b
            && base.tracks_b == Some(true)
            && u32::try_from(labels.len()).ok() == Some(leaves0),
        format!("e0={e0} leaves0={leaves0}; A {}", base.describe()),
        at(sim),
    );
    receipt.evidence(
        "b_and_c_decrypt_at_e0_before_the_trigger",
        b_before.0 && c_before.0,
        format!("{}; {}", b_before.1, c_before.1),
        at(sim),
    );
    if arm.ranked_admins() {
        let mut ranked: Vec<(String, &str)> = ["A", "D", "E"]
            .into_iter()
            .map(|label| sim.agent_hex(label).map(|hex| (hex, label)))
            .collect::<Result<_>>()?;
        ranked.sort();
        let order: Vec<&str> = ranked.iter().map(|(_, label)| *label).collect();
        receipt.evidence(
            "admins_rank_a_before_d_before_e",
            order == ["A", "D", "E"],
            format!("admin agent-id order {order:?}; A hold {:?}", arm.hold),
            at(sim),
        );
    }

    // t = 0.
    let trigger = sim
        .fabric()
        .mark_indexed(format!("case: t=0 trigger {:?}", arm.trigger));
    let started = sim.fabric().now();
    match arm.trigger {
        Trigger::SelfRevoke => {
            let (status, body) = sim
                .api(
                    "B",
                    Method::POST,
                    "/identity/revoke",
                    Some(json!({"agent_id": b_hex, "reason": "w3h-1357"})),
                )
                .await?;
            ensure!(status.is_success(), "B self-revokes: {status} {body}");
        }
        Trigger::OwnerRevoke => {
            let (status, body) = sim
                .api(
                    "A",
                    Method::DELETE,
                    &format!("/owner/agents/{b_hex}"),
                    Some(json!({"reason": "w3h-1357"})),
                )
                .await?;
            ensure!(status.is_success(), "A issuer-revokes B: {status} {body}");
        }
        Trigger::Leave | Trigger::LeaveThenRevoke => {
            let (status, body) = sim
                .api("B", Method::DELETE, &format!("/groups/{group}"), None)
                .await?;
            ensure!(status.is_success(), "B leaves: {status} {body}");
        }
        Trigger::Nothing => {}
    }
    if arm.trigger == Trigger::LeaveThenRevoke {
        // The revocation arrives after the leave (ADR 0110 "repeat
        // revocation arriving after that leave").
        sim.until("A and C hold B's leave", SETUP, async |s: &Sim| {
            views_now(s, survivors, &group, &b).await.is_ok_and(|now| {
                now.iter()
                    .all(|(_, seen)| seen.as_ref().is_some_and(|seen| !seen.lists_b))
            })
        })
        .await?;
        let (status, body) = sim
            .api(
                "B",
                Method::POST,
                "/identity/revoke",
                Some(json!({"agent_id": b_hex, "reason": "w3h-1357"})),
            )
            .await?;
        ensure!(
            status.is_success(),
            "B self-revokes after leaving: {status} {body}"
        );
    }
    if arm.trigger.revokes() {
        await_holders(sim, arm.holders, &b_hex).await?;
    }

    // The non-designated manual request, then the early read.
    let mut manual: Option<(StatusCode, String)> = None;
    let mut early: Vec<(&str, Option<View>)> = Vec::new();
    if arm.manual {
        let (status, body) = sim
            .api(
                "D",
                Method::DELETE,
                &format!("/groups/{group}/members/{b_hex}"),
                None,
            )
            .await?;
        manual = Some((status, body.to_string()));
        sim.within("the early read window", EARLY_READ + secs(2), async {
            tokio::time::sleep(EARLY_READ).await;
        })
        .await?;
        early = views(sim, survivors, &group, &b).await?;
    }

    // H within the arm's bound, measured from t = 0.
    let bound = arm
        .bound
        .saturating_sub(sim.fabric().now().saturating_sub(started));
    let mut reached: Option<String> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the survivors reach H", bound, async |s: &Sim| {
            let Some(now) = seen.observe(views_now(s, survivors, &group, &b)).await else {
                return true;
            };
            let done = excluded(&now, e0, leaves0);
            if done {
                reached.get_or_insert_with(|| {
                    format!(
                        "at {} us after t=0",
                        s.fabric().now().saturating_sub(started).as_micros()
                    )
                });
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
    if reached.is_some() {
        sim.within("H settles", SETTLE + secs(2), async {
            tokio::time::sleep(SETTLE).await;
        })
        .await?;
    }
    let end = views(sim, survivors, &group, &b).await?;
    let h = excluded(&end, e0, leaves0) && all_at(&end, e0 + 1);

    // Data plane after the wait: a survivor's new ciphertext opens on C
    // and not on B.
    let encryptor = survivors.first().copied().context("no survivor")?;
    let (c_after, b_after) = match encrypt(sim, encryptor, &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "B", &group, &ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error)),
    };
    let data_plane = c_after.0 && !b_after.0;
    // A leaver stays Removed on every survivor: no ban, no re-admission.
    let stays_removed = !arm.trigger.leaves()
        || end.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.b_state.as_deref() == Some("Removed"))
        });

    let queued_typed = manual.as_ref().is_some_and(|(_, body)| {
        body.contains("waiting_for_designated_admin") && body.to_ascii_lowercase().contains(&a_hex)
    });
    let early_unmoved = all_at(&early, e0);
    let passed = match arm.check {
        Check::ManualQueued => queued_typed && early_unmoved && h && data_plane,
        Check::Healthy => h && data_plane && stays_removed,
    };
    receipt.note(format!(
        "arm={arm:?} e0={e0} leaves0={leaves0}; H {}; manual={manual:?}; early: {}; \
         end: {}; after: {}; {}",
        reached.as_deref().unwrap_or("never reached"),
        describe_all(&early),
        describe_all(&end),
        c_after.1,
        b_after.1
    ));

    // The trigger reached its target.
    let manual_ok = manual
        .as_ref()
        .is_some_and(|(status, _)| status.is_success());
    let (delivered_name, delivered, delivered_detail) = match arm.trigger {
        Trigger::SelfRevoke | Trigger::OwnerRevoke | Trigger::LeaveThenRevoke => {
            let held = held_by(sim, arm.holders, &b_hex).await?;
            let all = held.iter().all(|(_, has)| *has);
            (
                "holders_hold_b_revocation",
                all && (!arm.manual || manual_ok),
                format!("revocation held {held:?}; manual request {manual:?}"),
            )
        }
        Trigger::Leave => {
            let to_a = sim
                .fabric()
                .delivered_writes_after(&sim.peer("B")?, &sim.peer("A")?, trigger)
                .len();
            let to_c = sim
                .fabric()
                .delivered_writes_after(&sim.peer("B")?, &sim.peer("C")?, trigger)
                .len();
            (
                "b_leave_reached_a_and_c",
                to_a > 0 && to_c > 0,
                format!("frames since the leave: B->A={to_a} B->C={to_c}"),
            )
        }
        Trigger::Nothing => (
            "d_manual_remove_accepted",
            manual_ok,
            format!("manual request {manual:?}"),
        ),
    };
    receipt.request_delivered(delivered_name, delivered, delivered_detail, at(sim));

    if !passed {
        let (ok, observed) = match arm.check {
            Check::ManualQueued => {
                let moved = early.iter().any(|(_, seen)| {
                    seen.as_ref()
                        .is_some_and(|seen| seen.epoch.is_some_and(|now| now > e0))
                });
                (
                    manual_ok && !queued_typed && moved,
                    format!(
                        "manual request {manual:?}; early (t+{EARLY_READ:?}): {}",
                        describe_all(&early)
                    ),
                )
            }
            Check::Healthy => (
                retained(
                    &end,
                    e0,
                    leaves0,
                    arm.trigger.revokes() && !arm.trigger.leaves(),
                ),
                describe_all(&end),
            ),
        };
        receipt.cause(arm.cause, Some(observed), ok, at(sim));
    }
    receipt.finish(arm.final_name(), passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1357 / ADR 0110 S4. Placeholders (not measured; D69, D73): completion bound \
         {S4_COMPLETION_BOUND_PLACEHOLDER:?}, W {S4_W_PLACEHOLDER:?}, \u{394} \
         {S4_DELTA_PLACEHOLDER:?}."
    ));
    match start(case, seed, arm).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, arm, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(arm.final_name());
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, arm: Arm, want: Verdict) -> Result<()> {
    let receipt = run(case, seed, arm).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// ADR 0110 `s4_idle_revocation_one_admin`: RED on `main` until S4 lands.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_idle_revocation_one_admin() -> Result<()> {
    expect(
        "w3h_1357_red_s4_idle_revocation_one_admin",
        0x1357_0001,
        IDLE,
        Verdict::Red,
    )
    .await
}

/// ADR 0110 `s4_idle_revocation_one_admin`, Home (`OwnerCertified`)
/// variant: the owner issuer-revokes B. RED on `main` until S4 lands.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_idle_revocation_one_admin_home() -> Result<()> {
    expect(
        "w3h_1357_red_s4_idle_revocation_one_admin_home",
        0x1357_0005,
        HOME_IDLE,
        Verdict::Red,
    )
    .await
}

/// ADR 0110 `s4_self_leave_crypto_only`: GREEN on `main` (#1113 / #1337)
/// and after S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_control_s4_self_leave_crypto_only() -> Result<()> {
    expect(
        "w3h_1357_control_s4_self_leave_crypto_only",
        0x1357_0002,
        SELF_LEAVE,
        Verdict::Green,
    )
    .await
}

/// ADR 0110 `s4_fallback_rank_manual`: RED on `main` until S4 lands.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_fallback_rank_manual() -> Result<()> {
    expect(
        "w3h_1357_red_s4_fallback_rank_manual",
        0x1357_0003,
        MANUAL_DURING_WINDOW,
        Verdict::Red,
    )
    .await
}

/// `s4_fallback_rank_manual`'s baseline: with no S4 obligation, D's manual
/// remove rekeys at once, before and after S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_control_s4_manual_remove_without_obligation() -> Result<()> {
    expect(
        "w3h_1357_control_s4_manual_remove_without_obligation",
        0x1357_0004,
        MANUAL_WITHOUT_OBLIGATION,
        Verdict::Green,
    )
    .await
}

/// ADR 0110 `s4_self_leave_crypto_only`, repeated with B's revocation
/// arriving after the leave: one exclusion, B stays Removed. GREEN on
/// `main` (#1337 rekeys at the leave; the revocation adds nothing) and
/// after S4 (the revocation must not rekey again).
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_control_s4_self_leave_then_revocation() -> Result<()> {
    expect(
        "w3h_1357_control_s4_self_leave_then_revocation",
        0x1357_0006,
        LEAVE_THEN_REVOKE,
        Verdict::Green,
    )
    .await
}
