//! W3-H cases for #1357 (ADR 0110 S4, revocation eviction, designated
//! admin first). Harness first (D16/D54): the red arms were committed and
//! shown RED on `main` (DIAG PR #1496) before S4 code merged. This PR has
//! the S4 fix, so each red arm now expects GREEN (the ADR 0110 behaviour)
//! and keeps its `_red_` name, as #1256 did. The controls are GREEN before
//! and after. A failed red arm whose observation matches `main` (its
//! `CAUSE_*`) is RED; any other failure is INFRA, with the views and the
//! S4 status (`GET /groups/:id`) in the receipt notes.
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
//! - `s4_idle_revocation_one_admin` (RED on `main`, GREEN with S4). Nodes A, B, C; A is
//!   the only admin. At t = 0 B revokes its own agent through
//!   `POST /identity/revoke` (the issuer API; ADR 0110 "repeat
//!   self-revocation and ordinary groups"). A and C must hold the record.
//!   No seal or removal API is called. Desired: H within the completion
//!   bound ([`Bound::Completion`]). `main` has no revocation
//!   eviction, so B stays seated at e0 on A and C ([`CAUSE_IDLE`]).
//! - `s4_idle_revocation_one_admin`, Home variant (RED on `main`, GREEN
//!   with S4). A owns
//!   the Home and is its only admin. At t = 0 A issuer-revokes B through
//!   `DELETE /owner/agents/:id` (ADR-0018, signed by the owner key). The
//!   precondition is that A, the designated admin, holds the record. C is
//!   not required to hold it: in CI run 39443078214 C did not accept the
//!   issuer-revocation within [`EVIDENCE`] (no subject certificate for B
//!   on the v1 carrier, it seems), so a C-holds precondition made the arm
//!   INFRA. The rest is as above.
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
//! - `s4_restart_intake_prepare` (RED on `main`, GREEN with S4). Nodes A, B, C. At t = 0
//!   B revokes its own agent; once A and C hold the record, A is
//!   crash-stopped and restarted on the same dirs; 100 ms after the
//!   restart B sends the revocation again (the duplicate trigger). A must
//!   still hold the record. Desired: H within the restart sync wait plus
//!   the completion bound from the restart ([`Bound::Restart`]), with
//!   exactly one epoch step (no duplicate rekey). `main`
//!   never schedules the work ([`CAUSE_RESTART`]). The ADR's other runs
//!   (a crash after the prepared journal, before the legacy commit; a
//!   failed first intake write showing `waiting_for_durable_intake`) need
//!   S4's own durability barriers and are not in this case yet.
//! - `s4_fallback_rank_manual` (RED on `main`, GREEN with S4). Nodes A, D, E, B, C, with
//!   admins A < D < E by agent id (the case reassigns the pre-generated
//!   keys of A, D and E so that this holds). A is held off the fabric
//!   (the designated admin, stalled). At t = 0 B revokes its own agent; D,
//!   E and C must hold the record. Then D calls the public remove API on
//!   B, well before W. Desired: D's request is queued with the typed state
//!   `waiting_for_designated_admin` naming A, no survivor's epoch moves
//!   in the next [`EARLY_READ`], and the ranked fallback then reaches H
//!   within [`Bound::Fallback`]. `main` rekeys at once
//!   ([`CAUSE_MANUAL`]).
//! - `s4_designated_late_observation` (RED on `main`, GREEN with S4). Nodes A, D, E, B,
//!   C with A < D < E. A stays reachable, but revocation-topic gossip
//!   toward A is dropped until t = W/2, so D, E and C observe at t = 0 and
//!   A only late (direct messages, the S4 hand-off, still reach A). B
//!   revokes its own agent at t = 0. Desired (the ADR row): A, reachable,
//!   acts on D's and E's hand-off and reaches H within the completion
//!   bound from t = 0 ([`Bound::Completion`]); A signs the exclusion on
//!   every survivor and no sibling does ([`CAUSE_SIBLING_SIGNED`]). The
//!   receipt notes each admin's persisted hand-off times. `main` never
//!   acts ([`CAUSE_LATE`]).
//! - `s4_designated_late_observation`, stalled A (RED on `main`, GREEN
//!   with S4). As
//!   above, but A is off the fabric for the whole run; D, the next rank,
//!   must fall back after W and reach H. `main` never acts
//!   ([`CAUSE_STALLED`]).
//! - `s4_designated_late_observation`, no early sibling (control, GREEN on
//!   `main`). The stalled-A run read at t = W/2: no survivor has rekeyed
//!   or is quarantined, and B is still listed. Trivially true on `main`;
//!   after S4 it proves D and E wait for at least W/2 (W = 18 s, so the
//!   read is at 9 s, well past the hand-off and gossip latency). The
//!   receipt notes each node's S4 status at W/2; the ADR's typed
//!   `waiting_for_designated_admin` state is recorded there, not asserted,
//!   so the control stays a control. The ADR's "E observes first and
//!   hands off" skew variant is not in this case yet.
//! - `s4_manual_remove_without_obligation` (control, GREEN on `main`). The
//!   same five nodes, A held, but no revocation: D's manual remove of B is
//!   not affected by S4, so it rekeys at once and reaches H.
//!
//! Manual requests: D's remove can answer `424 member_key_package_pending`
//! with `retry: true` (D does not hold B's TreeKEM KeyPackage yet and
//! requested the catch-up). The case retries such a reply with a doubling
//! virtual-time wait ([`RETRY_FIRST`] to [`RETRY_CAP`]) up to the arm's
//! own bound, and notes each retry. A 424 still there at the bound is RED
//! with [`CAUSE_KEY_PACKAGE_PENDING`], not INFRA and not GREEN.
//!
//! Timing: W, Δ, the completion bound and the restart sync wait are the
//! product's measured values (D69, D73), read from
//! [`S4Timing::default`] (see [`Bound`]). Each arm also records that every
//! node's runtime S4 timing equals that default. W3-H runs on virtual
//! time, so the production values cost little wall time.
//!
//! Receipts use `w3h.receipt/1`. The D196 receipt is 20 verdict-stable
//! reruns on the W3-H gate.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::S4Timing;
use crate::identity::UserKeypair;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// ADR 0110 §2 timing: the product's measured values (D69, D73), read from
/// [`S4Timing::default`] so that the case and the product have one source.
fn timing() -> S4Timing {
    S4Timing::default()
}

/// The fallback rank of the last reachable eligible admin in the
/// five-node arms (A held: D is rank 1, E is rank 2).
const R_MAX: usize = 2;

/// Which ADR 0110 bound an arm's H must meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bound {
    /// The designated admin is reachable: the completion bound from t = 0.
    Completion,
    /// A restarted: the restart sync wait, then the completion bound,
    /// both from the restart.
    Restart,
    /// The designated admin is held: rank `R_MAX` may
    /// start at `W + (R_MAX − 1)·Δ` (`S4Timing::fallback_offset`), and its
    /// own seal needs at most the completion bound. The product's own seal
    /// margin is 1.5 × (fsync + seal) = 12 s (PR #1508 body); the
    /// completion bound (18 s) covers it, so the form is the ADR's
    /// `W + (r_max − 1)·Δ + seal margin`, rounded up to a bound that the
    /// product exposes. `R_MAX` = 2, not 1: if D's seal fails, E's
    /// fallback at `W + Δ` still reaches H, and that is ADR behaviour.
    Fallback,
}

impl Bound {
    fn duration(self, timing: &S4Timing) -> Duration {
        match self {
            Self::Completion => timing.completion_bound,
            Self::Restart => timing
                .restart_sync_wait
                .saturating_add(timing.completion_bound),
            Self::Fallback => timing
                .fallback_offset(R_MAX)
                .saturating_add(timing.completion_bound),
        }
    }
}

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
const FINAL_NO_EARLY: &str = "no_non_designated_admin_rekeys_before_half_w";
const CAUSE_IDLE: &str = "no revocation eviction on main: after the bound every survivor still \
                          lists B active, at epoch e0, with the same leaf count";
const CAUSE_SELF_LEAVE: &str =
    "B's leaf retained after self-leave: survivors remain at epoch e0 with the same leaf count";
const CAUSE_LEAVE_THEN_REVOKE: &str = "B's leaf retained after a self-leave and a later \
                                       revocation: survivors remain at epoch e0 with the same \
                                       leaf count";
const CAUSE_RESTART: &str = "no revocation eviction on main, before or after A's restart: A \
                             still holds B's revocation after the crash, but every survivor \
                             still lists B active, at epoch e0, with the same leaf count";
const CAUSE_LATE: &str = "no revocation eviction on main: the designated admin A observes late \
                          and no hand-off runs, so after the completion bound every survivor \
                          still lists B active, at epoch e0, with the same leaf count";
const CAUSE_STALLED: &str = "no ranked fallback on main: with the designated admin A held, D and \
                             E never act, so after W + \u{394} + the bound every survivor still \
                             lists B active, at epoch e0, with the same leaf count";
const CAUSE_SIBLING_SIGNED: &str = "survivors reached H, but the head commit is not signed by \
                                    the designated admin A: a sibling (D or E) signed the \
                                    exclusion while A was reachable";
const CAUSE_EARLY_SIBLING: &str =
    "a non-designated admin rekeyed before W/2 while the designated admin A was held";
const CAUSE_MANUAL: &str = "non-designated manual remove rekeys at once on main: D's remove of B \
                            returned success without waiting_for_designated_admin and a survivor \
                            left epoch e0 within EARLY_READ while the designated admin A was held";
const CAUSE_NO_OBLIGATION: &str =
    "D's manual remove did not exclude B: survivors remain at epoch e0 with the same leaf count";
const CAUSE_KEY_PACKAGE_PENDING: &str = "D's manual remove of B still answered 424 \
                                         member_key_package_pending (retry: true) at the arm's \
                                         bound: D never obtained B's TreeKEM KeyPackage";

/// The first wait before a retry of a typed `retry: true` 424 reply; it
/// doubles per retry, up to [`RETRY_CAP`]. Virtual time.
const RETRY_FIRST: Duration = Duration::from_millis(250);
const RETRY_CAP: Duration = Duration::from_secs(2);

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
    /// A stays reachable, but revocation-topic gossip toward A is dropped
    /// until t = W/2: A observes late (direct messages still pass).
    RevocationGossipUntilHalfW,
}

/// The desired-behaviour assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    /// H within the bound, once.
    Healthy,
    /// D's manual request queues and nothing moves early; then H.
    ManualQueued,
    /// At t = W/2 no survivor has rekeyed and none is quarantined.
    NoEarlySibling,
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
    /// Crash A once it holds the trigger, restart it on the same dirs, and
    /// send B's revocation again 100 ms after the restart.
    restart_a: bool,
    /// D calls the public remove API on B after the trigger.
    manual: bool,
    check: Check,
    bound: Bound,
    /// The admin that must sign the exclusion commit on every survivor
    /// (the head commit after H), when the ADR row names it.
    committer: Option<&'static str>,
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
    restart_a: false,
    manual: false,
    check: Check::Healthy,
    bound: Bound::Completion,
    committer: None,
    cause: CAUSE_IDLE,
};

const HOME_IDLE: Arm = Arm {
    home: true,
    holders: &["A"],
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

const RESTART_INTAKE: Arm = Arm {
    restart_a: true,
    bound: Bound::Restart,
    cause: CAUSE_RESTART,
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
    restart_a: false,
    manual: true,
    check: Check::ManualQueued,
    bound: Bound::Fallback,
    committer: None,
    cause: CAUSE_MANUAL,
};

const MANUAL_WITHOUT_OBLIGATION: Arm = Arm {
    holders: &[],
    trigger: Trigger::Nothing,
    check: Check::Healthy,
    bound: Bound::Completion,
    cause: CAUSE_NO_OBLIGATION,
    ..MANUAL_DURING_WINDOW
};

/// ADR 0110 `s4_designated_late_observation`: D and E hand the evidence to
/// A (`EvictionHandoffV1`, which every node advertises), so A, reachable,
/// reaches H within the completion bound from t = 0 and no sibling (D or
/// E) signs the exclusion. PR #1508 run 39483631672: H at 11.1–13.1 s
/// over 15 iterations, set by A's restart sync wait from process start
/// (D73), never at D's fallback (W + 100 ms).
const LATE_OBSERVATION: Arm = Arm {
    survivors: &["A", "D", "E", "C"],
    hold: Hold::RevocationGossipUntilHalfW,
    manual: false,
    check: Check::Healthy,
    bound: Bound::Completion,
    committer: Some("A"),
    cause: CAUSE_LATE,
    ..MANUAL_DURING_WINDOW
};

const STALLED_A_FALLBACK: Arm = Arm {
    manual: false,
    check: Check::Healthy,
    cause: CAUSE_STALLED,
    ..MANUAL_DURING_WINDOW
};

const NO_EARLY_SIBLING: Arm = Arm {
    check: Check::NoEarlySibling,
    cause: CAUSE_EARLY_SIBLING,
    ..STALLED_A_FALLBACK
};

impl Arm {
    fn ranked_admins(self) -> bool {
        !self.promoted.is_empty()
    }

    fn final_name(self) -> &'static str {
        match self.check {
            Check::ManualQueued => FINAL_MANUAL,
            Check::Healthy => FINAL_H,
            Check::NoEarlySibling => FINAL_NO_EARLY,
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
    /// Who signed the commit at `state_revision` (hex agent id, lower
    /// case), from the node's retained commit log.
    head_committed_by: Option<String>,
}

impl View {
    fn describe(&self) -> String {
        format!(
            "state={} lists_b={} b_state={:?} epoch={:?} leaves={:?} tracks_b={:?} quarantined={} \
             head_committed_by={:?}",
            self.state_revision,
            self.lists_b,
            self.b_state,
            self.epoch,
            self.leaves,
            self.tracks_b,
            self.quarantined,
            self.head_committed_by
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

/// Drops pubsub frames on the revocation topics toward one node while
/// held, and counts them. Direct messages (an S4 hand-off) still pass.
struct RevocationGossipBlock {
    held: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

impl RevocationGossipBlock {
    fn install(sim: &Sim, target: &str) -> Result<Self> {
        use crate::network::sim::{Fault, LaneClass};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        const MARKER: &[u8] = b"x0x.revocation.";
        let machine = sim.peer(target)?.0;
        let held = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_dropped) = (Arc::clone(&held), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            let on_topic = write.lane.class == LaneClass::PubSub
                && write
                    .bytes
                    .windows(MARKER.len())
                    .any(|window| window == MARKER);
            if rule_held.load(Ordering::SeqCst) && write.lane.dst == machine && on_topic {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        sim.fabric()
            .mark(format!("fault: revocation gossip toward {target} withheld"));
        Ok(Self { held, dropped })
    }

    fn held(&self) -> bool {
        self.held.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn release(&self, sim: &Sim) {
        self.held.store(false, std::sync::atomic::Ordering::SeqCst);
        sim.fabric()
            .mark("fault: revocation gossip withholding released at W/2");
    }

    fn dropped(&self) -> usize {
        self.dropped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The final reply to a request sent through [`retrying`], with each
/// typed-retry reply that came before it.
struct Answered {
    status: StatusCode,
    body: serde_json::Value,
    /// `(t_us, reply)` for each `424 retry: true` reply that was retried.
    retries: Vec<(u128, String)>,
    /// The deadline (virtual time since the sim started).
    deadline: Duration,
}

impl Answered {
    /// The last reply is a typed `424 retry: true`: the deadline came
    /// first.
    fn still_pending(&self) -> bool {
        typed_retry(self.status, &self.body)
    }

    fn describe(&self) -> String {
        format!(
            "final {} {}; {} typed 424 retry: true replies retried before it {:?}; \
             retry deadline {} us{}",
            self.status,
            self.body,
            self.retries.len(),
            self.retries,
            self.deadline.as_micros(),
            if self.still_pending() {
                " (reached with the reply still 424)"
            } else {
                ""
            }
        )
    }
}

/// A `424 Failed Dependency` reply that names `retry: true` (for example
/// `member_key_package_pending`: the daemon requested the catch-up and
/// asks the client to retry).
fn typed_retry(status: StatusCode, body: &serde_json::Value) -> bool {
    status == StatusCode::FAILED_DEPENDENCY && body["retry"] == true
}

/// Send a manual remove/ban/seal request. A typed `424 retry: true` reply
/// is retried with a doubling virtual-time wait, while the next attempt
/// still starts before `deadline` (the arm's own bound). Each retried reply
/// is kept for the receipt. Any other reply, or a 424 at the deadline, is
/// returned as is: the caller judges it.
async fn retrying(
    sim: &Sim,
    label: &str,
    method: Method,
    path: &str,
    deadline: Duration,
) -> Result<Answered> {
    let mut retries = Vec::new();
    let mut wait = RETRY_FIRST;
    loop {
        let (status, body) = sim.api(label, method.clone(), path, None).await?;
        let now = sim.fabric().now();
        if !typed_retry(status, &body) || now.saturating_add(wait) >= deadline {
            return Ok(Answered {
                status,
                body,
                retries,
                deadline,
            });
        }
        retries.push((now.as_micros(), format!("{status} {body}")));
        sim.fabric().mark(format!(
            "case: {label} {method} {path} -> 424 retry: true; retry in {wait:?}"
        ));
        sim.within("the typed-retry wait", wait + secs(1), async {
            tokio::time::sleep(wait).await;
        })
        .await?;
        wait = wait.saturating_mul(2).min(RETRY_CAP);
    }
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

/// `label`'s S4 status for `group` through the public group API
/// (`revocation_evictions` and `admin_availability`), for the receipt.
async fn eviction_status(sim: &Sim, label: &str, group: &str) -> Result<serde_json::Value> {
    let (status, body) = sim
        .api(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(json!({
        "revocation_evictions": body["revocation_evictions"],
        "admin_availability": body["admin_availability"],
    }))
}

/// The S4 status of each label, for a receipt note. A node that is off
/// the fabric still answers its local API.
async fn statuses(sim: &Sim, labels: &[&str], group: &str) -> Result<String> {
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        let seen = sim
            .at_instant(
                "read a node's S4 status",
                eviction_status(sim, label, group),
            )
            .await?;
        out.push(match seen {
            Ok(seen) => format!("{label}: {seen}"),
            Err(error) => format!("{label}: {error:#}"),
        });
    }
    Ok(out.join("; "))
}

/// Every node runs the timing that the case reads.
fn runtime_timing(sim: &Sim, labels: &[&str]) -> Result<(bool, String)> {
    let want = timing();
    let mut differ = Vec::new();
    for label in labels {
        let have = sim.state(label)?.revocation_evictions.timing;
        if have != want {
            differ.push(format!("{label}: {have:?}"));
        }
    }
    Ok((
        differ.is_empty(),
        format!("want {want:?}; differ: {differ:?}"),
    ))
}

/// Each label's verified view of whether `subject` takes an ADR 0110 §4
/// `EvictionHandoffV1`.
fn handoff_support(sim: &Sim, labels: &[&str], subject: &str) -> Result<String> {
    let (subject_id, _) = sim.ids(subject)?;
    let mut out = Vec::with_capacity(labels.len());
    for label in labels.iter().filter(|label| **label != subject) {
        let supports = sim
            .state(label)?
            .agent
            .capability_store()
            .verified_registry_supports(
                &subject_id,
                crate::dm::CapabilityRegistry::EVICTION_HANDOFF_V1,
            );
        out.push(format!("{label}: {supports:?}"));
    }
    Ok(out.join(", "))
}

/// Each label's persisted S4 row for `target` (the `.evs` sidecar), as
/// times in ms after `zero_ms` (a wall-clock Unix ms reading): first
/// observation, first hand-off dispatch, earliest verified hand-off
/// receipt and completion. The public status does not expose the hand-off
/// times; the sidecar does.
fn handoff_times(sim: &Sim, labels: &[&str], target: &[u8; 32], zero_ms: u64) -> Result<String> {
    use crate::groups::eviction::{decode_evs, EVS_FILE_NAME};
    let after = |ms: Option<u64>| ms.map(|ms| i128::from(ms) - i128::from(zero_ms));
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        let path = sim.state(label)?.data_dir.join(EVS_FILE_NAME);
        let seen = match std::fs::read(&path) {
            Ok(bytes) => match decode_evs(&bytes) {
                Ok(body) => body
                    .rows
                    .iter()
                    .find(|row| &row.target == target)
                    .map_or_else(
                        || "no row".to_string(),
                        |row| {
                            format!(
                                "observed {:?} first_dispatch {:?} handoff_receipt {:?} \
                                 completed {:?} phase {:?}",
                                after(Some(row.observed_at_unix_ms)),
                                after(row.first_dispatch_unix_ms),
                                after(row.earliest_handoff_receipt_unix_ms),
                                after(row.completed_at_unix_ms),
                                row.phase
                            )
                        },
                    ),
                Err(error) => format!("undecodable: {error:?}"),
            },
            Err(error) => format!("unreadable: {error}"),
        };
        out.push(format!("{label}: {seen}"));
    }
    Ok(out.join("; "))
}

/// The wall clock the daemons stamp rows with, in Unix ms.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
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
    let (same, detail) = runtime_timing(sim, labels)?;
    receipt.evidence("every_node_runs_s4timing_default", same, detail, at(sim));

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

    if arm.ranked_admins() {
        receipt.note(format!(
            "verified eviction_handoff_v1 support for A (ADR 0110 §4; `None` = \
             unknown, so no hand-off is sent): {}",
            handoff_support(sim, labels, "A")?
        ));
    }

    let gossip_block = (arm.hold == Hold::RevocationGossipUntilHalfW)
        .then(|| RevocationGossipBlock::install(sim, "A"))
        .transpose()?;

    // t = 0.
    let trigger = sim
        .fabric()
        .mark_indexed(format!("case: t=0 trigger {:?}", arm.trigger));
    let mut started = sim.fabric().now();
    let zero_ms = wall_ms();
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

    // Crash A after durable intake, restart it, then a duplicate trigger.
    let mut duplicate: Option<String> = None;
    if arm.restart_a {
        sim.within("A's intake is durable", secs(2), async {
            tokio::time::sleep(secs(1)).await;
        })
        .await?;
        sim.stop("A", RestartMode::Crash).await?;
        sim.start_again("A").await?;
        sim.until("A and C reconnect", SETUP, async |s: &Sim| {
            connected_to(s, "A", "C").await
        })
        .await?;
        sim.within("the duplicate trigger's delay", secs(1), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        })
        .await?;
        let (status, body) = sim
            .api(
                "B",
                Method::POST,
                "/identity/revoke",
                Some(json!({"agent_id": b_hex, "reason": "w3h-1357 duplicate"})),
            )
            .await?;
        duplicate = Some(format!("{status} {body}"));
        let held = held_by(sim, &["A"], &b_hex).await?;
        receipt.evidence(
            "a_holds_b_revocation_after_its_crash_and_restart",
            held.iter().all(|(_, has)| *has),
            format!("held {held:?}; duplicate trigger {duplicate:?}"),
            at(sim),
        );
        // The bound runs from the restart (ADR 0110 "catch-up ... after
        // restart").
        started = sim.fabric().now();
    }

    // The non-designated manual request, then the early read.
    let mut manual: Option<(StatusCode, String)> = None;
    let mut manual_pending: Option<String> = None;
    let mut early: Vec<(&str, Option<View>)> = Vec::new();
    if arm.manual {
        let answer = retrying(
            sim,
            "D",
            Method::DELETE,
            &format!("/groups/{group}/members/{b_hex}"),
            started.saturating_add(arm.bound.duration(&timing())),
        )
        .await?;
        receipt.note(format!("D's manual remove of B: {}", answer.describe()));
        if answer.still_pending() {
            manual_pending = Some(answer.describe());
        }
        manual = Some((answer.status, answer.body.to_string()));
        sim.within("the early read window", EARLY_READ + secs(2), async {
            tokio::time::sleep(EARLY_READ).await;
        })
        .await?;
        early = views(sim, survivors, &group, &b).await?;
        receipt.note(format!(
            "S4 status at the early read: {}",
            statuses(sim, labels, &group).await?
        ));
    }

    if arm.check == Check::NoEarlySibling {
        return no_early_sibling(sim, arm, receipt, &group, &b, &b_hex, e0, started).await;
    }

    // H within the arm's bound, measured from t = 0.
    let timing = timing();
    let bound = arm
        .bound
        .duration(&timing)
        .saturating_sub(sim.fabric().now().saturating_sub(started));
    let mut reached: Option<String> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the survivors reach H", bound, async |s: &Sim| {
            if let Some(block) = &gossip_block {
                if block.held()
                    && s.fabric().now().saturating_sub(started) >= timing.designated_window / 2
                {
                    block.release(s);
                }
            }
            let Some(now) = seen.observe(views_now(s, survivors, &group, &b)).await else {
                return true;
            };
            let done = excluded(&now, e0, leaves0);
            if done {
                let elapsed = s.fabric().now().saturating_sub(started);
                reached.get_or_insert_with(|| {
                    format!(
                        "at {} us after t=0 (within the completion bound {:?}: {})",
                        elapsed.as_micros(),
                        timing.completion_bound,
                        elapsed <= timing.completion_bound
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
    if let Some(block) = &gossip_block {
        if block.held() {
            block.release(sim);
        }
        // The late-observation fault fired: A's revocation gossip was
        // withheld, so a RED verdict is not "A observed on time".
        receipt.evidence(
            "revocation_gossip_toward_a_withheld_until_half_w",
            block.dropped() > 0,
            format!(
                "revocation-topic frames toward A dropped: {}",
                block.dropped()
            ),
            at(sim),
        );
    }
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
    let committed_by = match arm.committer {
        Some(label) => {
            let want = sim.agent_hex(label)?;
            let signed = end.iter().all(|(_, seen)| {
                seen.as_ref()
                    .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(want.as_str()))
            });
            receipt.note(format!(
                "exclusion signer: want {label} ({want}) on every survivor: {signed}"
            ));
            signed
        }
        None => true,
    };
    let passed = match arm.check {
        Check::ManualQueued => queued_typed && early_unmoved && h && data_plane,
        Check::Healthy | Check::NoEarlySibling => h && data_plane && stays_removed && committed_by,
    };
    receipt.note(format!(
        "S4 status at the end: {}",
        statuses(sim, labels, &group).await?
    ));
    if arm.ranked_admins() {
        receipt.note(format!(
            "persisted S4 rows for B, ms after t=0 (ADR 0110 §4 hand-off evidence): {}",
            handoff_times(sim, &["A", "D", "E"], b.as_bytes(), zero_ms)?
        ));
    }
    receipt.note(format!(
        "arm={arm:?} e0={e0} leaves0={leaves0}; H {}; manual={manual:?}; \
         duplicate={duplicate:?}; gossip to A withheld={:?}; early: {}; end: {}; \
         after: {}; {}",
        reached.as_deref().unwrap_or("never reached"),
        gossip_block.as_ref().map(RevocationGossipBlock::dropped),
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
    if let Some(pending) = &manual_pending {
        // D answered every attempt with the typed 424 `retry: true`
        // until the arm's bound: the request reached D, and D could not
        // act. That is a product failure with its own cause, not INFRA.
        receipt.request_delivered(
            "d_manual_remove_answered_with_typed_retry",
            true,
            pending.clone(),
            at(sim),
        );
        receipt.cause(
            CAUSE_KEY_PACKAGE_PENDING,
            Some(pending.clone()),
            true,
            at(sim),
        );
        receipt.finish(arm.final_name(), false, at(sim));
        return Ok(());
    }
    receipt.request_delivered(delivered_name, delivered, delivered_detail, at(sim));

    if !passed {
        let (cause, ok, observed) = match arm.check {
            Check::ManualQueued => {
                let moved = early.iter().any(|(_, seen)| {
                    seen.as_ref()
                        .is_some_and(|seen| seen.epoch.is_some_and(|now| now > e0))
                });
                (
                    arm.cause,
                    manual_ok && !queued_typed && moved,
                    format!(
                        "manual request {manual:?}; early (t+{EARLY_READ:?}): {}",
                        describe_all(&early)
                    ),
                )
            }
            Check::Healthy | Check::NoEarlySibling if h && !committed_by => {
                (CAUSE_SIBLING_SIGNED, true, describe_all(&end))
            }
            Check::Healthy | Check::NoEarlySibling => (
                arm.cause,
                retained(
                    &end,
                    e0,
                    leaves0,
                    arm.trigger.revokes() && !arm.trigger.leaves(),
                ),
                describe_all(&end),
            ),
        };
        receipt.cause(cause, Some(observed), ok, at(sim));
    }
    receipt.finish(arm.final_name(), passed, at(sim));
    Ok(())
}

/// [`Check::NoEarlySibling`]: wait to t = W/2, then no survivor may have
/// rekeyed or be quarantined, and B is still listed (only the designated
/// admin, held, may act before W).
#[allow(clippy::too_many_arguments)]
async fn no_early_sibling(
    sim: &Sim,
    arm: Arm,
    receipt: &mut Receipt,
    group: &str,
    b: &crate::identity::AgentId,
    b_hex: &str,
    e0: u64,
    started: Duration,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let half_w = timing().designated_window / 2;
    let left = half_w.saturating_sub(sim.fabric().now().saturating_sub(started));
    sim.within("wait to W/2", left + secs(2), async {
        tokio::time::sleep(left).await;
    })
    .await?;
    let now = views(sim, arm.survivors, group, b).await?;
    let quiet = all_at(&now, e0)
        && now.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.lists_b && !seen.quarantined)
        });
    receipt.note(format!(
        "arm={arm:?} e0={e0}; at W/2: {}",
        describe_all(&now)
    ));
    receipt.note(format!(
        "S4 status at W/2: {}",
        statuses(sim, arm.labels, group).await?
    ));
    let held = held_by(sim, arm.holders, b_hex).await?;
    receipt.request_delivered(
        "holders_hold_b_revocation",
        held.iter().all(|(_, has)| *has),
        format!("revocation held {held:?}"),
        at(sim),
    );
    if !quiet {
        let moved = now.iter().any(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.epoch.is_some_and(|epoch| epoch > e0))
        });
        receipt.cause(arm.cause, Some(describe_all(&now)), moved, at(sim));
    }
    receipt.finish(arm.final_name(), quiet, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1357 / ADR 0110 S4. Timing from S4Timing::default() (measured; D69, D73): {:?}; \
         arm bound {:?} = {:?}.",
        timing(),
        arm.bound,
        arm.bound.duration(&timing())
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

/// ADR 0110 `s4_idle_revocation_one_admin`: RED on `main`, GREEN with S4.
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
        // #1357 fixed: RED on main (DIAG PR #1496), GREEN with S4.
        Verdict::Green,
    )
    .await
}

/// ADR 0110 `s4_idle_revocation_one_admin`, Home (`OwnerCertified`)
/// variant: the owner issuer-revokes B. RED on `main`, GREEN with S4.
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
        // #1357 fixed: RED on main (DIAG PR #1496), GREEN with S4.
        Verdict::Green,
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

/// ADR 0110 `s4_fallback_rank_manual`: RED on `main`, GREEN with S4.
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
        // #1357 fixed: RED on main (DIAG PR #1496), GREEN with S4.
        Verdict::Green,
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

/// ADR 0110 `s4_restart_intake_prepare` (crash after durable intake, with
/// a duplicate trigger): RED on `main`, GREEN with S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_restart_intake_prepare() -> Result<()> {
    expect(
        "w3h_1357_red_s4_restart_intake_prepare",
        0x1357_0007,
        RESTART_INTAKE,
        // #1357 fixed: RED on main (DIAG PR #1496), GREEN with S4.
        Verdict::Green,
    )
    .await
}

/// ADR 0110 `s4_designated_late_observation`: A observes late; automatic
/// healthy exclusion. RED on `main`, GREEN with S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_designated_late_observation() -> Result<()> {
    expect(
        "w3h_1357_red_s4_designated_late_observation",
        0x1357_0008,
        LATE_OBSERVATION,
        // #1357 fixed: RED on main (DIAG PR #1496), GREEN with S4.
        Verdict::Green,
    )
    .await
}

/// ADR 0110 `s4_designated_late_observation`, A stalled past W + Δ:
/// D's ranked fallback reaches H. RED on `main`, GREEN with S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_designated_stalled_a_fallback() -> Result<()> {
    expect(
        "w3h_1357_red_s4_designated_stalled_a_fallback",
        0x1357_0009,
        STALLED_A_FALLBACK,
        // #1357 fixed: RED on main (DIAG PR #1496), GREEN with S4.
        Verdict::Green,
    )
    .await
}

/// ADR 0110 `s4_designated_late_observation` safety control: with A held,
/// no D/E sibling before W/2. GREEN on `main` and after S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_control_s4_designated_no_early_sibling() -> Result<()> {
    expect(
        "w3h_1357_control_s4_designated_no_early_sibling",
        0x1357_000a,
        NO_EARLY_SIBLING,
        Verdict::Green,
    )
    .await
}
