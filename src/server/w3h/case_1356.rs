//! W3-H cases for #1356 (ADR 0109, S3 of ADR 0088): ownerless attestation,
//! stale-base self-recovery and manual re-seat. Harness first (D16, D54,
//! D181): each red arm is committed and shown RED on the S3 base before
//! the S3 code merges. A red arm that fails with the observation its
//! `CAUSE_*` names is RED; any other failure is INFRA. Controls are GREEN
//! before and after S3.
//!
//! The ADR 0109 H-S3-a row (#818, skewed clocks) is `case_818`'s red
//! baseline, `w3h_818_red_baseline_ownerless_skewed_joiner_is_quarantined`.
//! Its GREEN end state is H-S3-a's candidate assertion, so the S3 code is
//! expected to flip it (issue #1356, "the W3-H case for #818 is green").
//! This file does not repeat it.
//!
//! Join arms. Nodes A (creator and only admin), M1 and M2 (members), J
//! (joiner), in an ordinary `private_secure` (TreeKEM) group with no owner
//! axis. A mints invite I at state revision r, removes M2 (r+1), waits
//! past the last metadata resend, and then J joins with I and A seals J
//! (r+2).
//!
//! - `s3_aligned_stale_joiner` (H-S3-a2, RED on the base). Setup S0′: no
//!   state-only commits before the mint, so the clocks are aligned and the
//!   seal's roster clock is above J's seed. Desired (ADR 0109 §2): within
//!   [`CATCHUP`] J is active at A's state revision and TreeKEM epoch and is
//!   never marked. The base ([`CAUSE_ALIGNED`]): the frontier gate queues
//!   the add as `revision_gap`, the r+1 page needs a TreeKEM group that a
//!   pre-Welcome joiner does not have, and the attempt ends with J not
//!   active and never marked.
//!
//! Receipts use `w3h.receipt/1`. The D196 receipt is 20 verdict-stable
//! reruns on the W3-H gate.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use anyhow::ensure;
use serde_json::Value;

const JOIN_LABELS: &[&str] = &["A", "M1", "M2", "J"];
const SETUP: Duration = Duration::from_secs(180);
/// Past the last metadata resend (60 s, `GROUP_CONTROL_REDELIVERY_SCHEDULE`).
const RESENDS_DONE: Duration = Duration::from_secs(90);
/// ADR 0109 H-S3-a and H-S3-a2: "Advance 130 s".
const CATCHUP: Duration = Duration::from_secs(130);

const FINAL_JOIN: &str = "j_active_at_the_authority_revision_and_epoch_never_marked_within_130s";
const CAUSE_ALIGNED: &str = "J is never marked and is not active at the end: the aligned-clock \
                             gap is queued, the r+1 page needs a TreeKEM group J does not have, \
                             and the join attempt ends with no typed state";

/// The WARN line the frontier gate writes when it queues an event.
const QUEUED_LOG: &str = "queued TreeKEM membership event pending catch-up/replay";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// H-S3-a2: S0′ (aligned clocks), stale invite.
    AlignedJoin,
}

/// The fork-quarantine marker as one node holds it.
#[derive(Debug, Clone)]
struct Marker {
    revision: u64,
    no_anchor: bool,
    classification: Option<String>,
    committed_by: String,
}

impl Marker {
    fn describe(&self) -> String {
        format!(
            "rev={} no_anchor={} class={:?} by={}",
            self.revision,
            self.no_anchor,
            self.classification,
            short(&self.committed_by)
        )
    }
}

/// One node's local record of the group.
#[derive(Debug, Clone)]
struct View {
    state_revision: u64,
    roster_revision: u64,
    state_hash: String,
    owner_axis: bool,
    active: Vec<String>,
    marker: Option<Marker>,
    fork_evidence: bool,
    gap_refusal: Option<String>,
    base_revision: Option<u64>,
    epoch: Option<u64>,
}

impl View {
    fn lists(&self, agent: &str) -> bool {
        self.active.iter().any(|id| id.eq_ignore_ascii_case(agent))
    }

    fn describe(&self) -> String {
        format!(
            "state={} roster={} hash={} owner_axis={} epoch={:?} base={:?} marker={:?} \
             fork_evidence={} gap_refusal={:?} active={}",
            self.state_revision,
            self.roster_revision,
            short(&self.state_hash),
            self.owner_axis,
            self.epoch,
            self.base_revision,
            self.marker.as_ref().map(Marker::describe),
            self.fork_evidence,
            self.gap_refusal,
            self.active.len()
        )
    }
}

fn short(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

/// `GET /groups/:id` as one node answers it: the status, the
/// `membership_state` and the ADR 0109 §8 `recovery` object (`Null` when
/// absent). `None` when the node has no record (404).
#[derive(Debug, Clone)]
struct Status {
    code: StatusCode,
    membership: Option<String>,
    recovery: Value,
}

impl Status {
    fn describe(&self) -> String {
        format!(
            "GET {} membership={:?} recovery={}",
            self.code, self.membership, self.recovery
        )
    }
}

async fn status_now(sim: &Sim, label: &str, group: &str) -> Result<Option<Status>> {
    let (code, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    if code == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    ensure!(
        !code.is_server_error(),
        "{label} GET /groups/{group}: {code} {body}"
    );
    Ok(Some(Status {
        code,
        membership: body["membership_state"].as_str().map(str::to_string),
        recovery: body.get("recovery").cloned().unwrap_or(Value::Null),
    }))
}

async fn view_now(sim: &Sim, label: &str, group: &str) -> Result<View> {
    try_view_now(sim, label, group)
        .await?
        .with_context(|| format!("{label} has no record of {group}"))
}

/// `label`'s view of `group`; `None` when it holds no record of it (a
/// joiner drops its stub when its join attempt times out).
async fn try_view_now(sim: &Sim, label: &str, group: &str) -> Result<Option<View>> {
    let state = sim.state(label)?;
    let (key, view) = {
        let groups = state.named_groups.read().await;
        let Some((key, info)) = crate::server::resolve_group_entry_locked(&groups, group) else {
            return Ok(None);
        };
        let lineage = info.invite_lineage.as_ref();
        let view = View {
            state_revision: info.state_revision,
            roster_revision: info.roster_revision,
            state_hash: info.state_hash.clone(),
            owner_axis: info.policy.admission.owner_certified_user_id().is_some(),
            active: info.active_members().map(|m| m.agent_id.clone()).collect(),
            marker: info.fork_quarantine.as_ref().map(|marker| Marker {
                revision: marker.revision,
                no_anchor: marker.no_anchor,
                classification: marker.snapshot.classification.clone(),
                committed_by: marker.committed_by.clone(),
            }),
            fork_evidence: lineage.is_some_and(|l| l.fork_evidence.is_some()),
            gap_refusal: lineage
                .and_then(|l| l.anchored_gap_refusal.as_ref())
                .map(|record| record.reason.clone()),
            base_revision: lineage.map(|l| l.base_revision),
            epoch: None,
        };
        (key.to_string(), view)
    };
    let live = state.treekem_groups.read().await.get(&key).cloned();
    let epoch = match live {
        Some(live) => Some(live.lock().await.epoch()),
        None => None,
    };
    Ok(Some(View { epoch, ..view }))
}

async fn view(sim: &Sim, label: &str, group: &str) -> Result<View> {
    sim.at_instant(
        &format!("read {label}'s group"),
        view_now(sim, label, group),
    )
    .await?
}

async fn status(sim: &Sim, label: &str, group: &str) -> Result<Option<Status>> {
    sim.at_instant(
        &format!("read {label}'s group status"),
        status_now(sim, label, group),
    )
    .await?
}

/// `node` is active at `authority`'s state (revision and hash) and TreeKEM
/// epoch, with no fork-quarantine marker.
fn caught_up(node: Option<&View>, authority: &View, membership: Option<&str>) -> bool {
    node.is_some_and(|node| {
        membership == Some("active")
            && node.marker.is_none()
            && node.state_revision == authority.state_revision
            && node.state_hash == authority.state_hash
            && node.epoch.is_some()
            && node.epoch == authority.epoch
    })
}

/// `inviter` invites `member`; every label in `observers` lists it and it
/// reports itself active.
async fn seat(sim: &Sim, inviter: &str, member: &str, group: &str) -> Result<()> {
    let link = invite(sim, inviter, group).await?;
    join(sim, member, &link).await?;
    let hex = sim.agent_hex(member)?;
    sim.until(&format!("{member} seated"), SETUP, async |s: &Sim| {
        let listed = members(s, inviter, group)
            .await
            .is_ok_and(|listed| listed.contains(&hex));
        let active = status_now(s, member, group)
            .await
            .ok()
            .flatten()
            .and_then(|status| status.membership)
            .as_deref()
            == Some("active");
        listed && active
    })
    .await
}

/// Every label in `labels` holds A's state revision and hash.
async fn settled(sim: &Sim, labels: &[&str], group: &str, what: &str) -> Result<()> {
    sim.until(what, SETUP, async |s: &Sim| {
        let Ok(authority) = view_now(s, "A", group).await else {
            return false;
        };
        for label in labels {
            match view_now(s, label, group).await {
                Ok(seen)
                    if seen.state_revision == authority.state_revision
                        && seen.state_hash == authority.state_hash => {}
                _ => return false,
            }
        }
        true
    })
    .await
}

fn delivered_after(sim: &Sim, src: &str, dst: &str, after: usize) -> Result<usize> {
    Ok(sim
        .fabric()
        .delivered_writes_after(&sim.peer(src)?, &sim.peer(dst)?, after)
        .len())
}

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

/// Join arms: S0′ (aligned) up to J's seal, then [`CATCHUP`].
async fn join_scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    mesh(sim, JOIN_LABELS).await?;
    let group = create_group(sim, "A").await?;
    for member in ["M1", "M2"] {
        seat(sim, "A", member, &group).await?;
    }
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold A's revision").await?;
    let minted = view(sim, "A", &group).await?;
    let link = invite(sim, "A", &group).await?;
    let m2 = sim.agent_hex("M2")?;
    let (code, removed) = sim
        .api(
            "A",
            Method::DELETE,
            &format!("/groups/{group}/members/{m2}"),
            None,
        )
        .await?;
    ensure!(code.is_success(), "A removes M2: {code} {removed}");
    settled(sim, &["M1"], &group, "M1 holds the removal").await?;
    let removal = view(sim, "A", &group).await?;
    ensure!(
        removal.state_revision == minted.state_revision + 1,
        "INFRA: the removal moved A from {} to {}",
        minted.state_revision,
        removal.state_revision
    );
    sim.within("the removal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;

    let joined_at = sim.fabric().mark_indexed("case: J redeems invite I");
    join(sim, "J", &link).await?;
    let j_hex = sim.agent_hex("J")?;
    sim.until("A seals J", SETUP, async |s: &Sim| {
        view_now(s, "A", &group)
            .await
            .is_ok_and(|a| a.lists(&j_hex))
    })
    .await?;
    let sealed = view(sim, "A", &group).await?;
    let stub = view(sim, "J", &group).await?;
    receipt.setup_done(at(sim));

    let base = minted.state_revision;
    receipt.evidence(
        "group_is_ownerless",
        !sealed.owner_axis && !stub.owner_axis,
        format!(
            "A owner_axis={} J owner_axis={}",
            sealed.owner_axis, stub.owner_axis
        ),
        at(sim),
    );
    receipt.evidence(
        "joiner_stub_seeded_at_the_invite_base",
        stub.base_revision == Some(base),
        format!("invite base {base}; J {}", stub.describe()),
        at(sim),
    );
    receipt.evidence(
        "seal_roster_clock_above_the_joiner_seed",
        sealed.roster_revision > base,
        format!(
            "A at mint state={} roster={}; A after the seal {}",
            minted.state_revision,
            minted.roster_revision,
            sealed.describe()
        ),
        at(sim),
    );
    receipt.evidence(
        "gap_is_the_authority_removal_of_m2",
        sealed.state_revision == base + 2
            && sealed.lists(&j_hex)
            && !sealed.lists(&m2)
            && sealed.marker.is_none(),
        format!("want A at {}; A {}", base + 2, sealed.describe()),
        at(sim),
    );

    let mut j_marked: Option<String> = None;
    let mut j_seen = false;
    let mut seen = Observations::default();
    let waited = sim
        .until("J catches up to A", CATCHUP, async |s: &Sim| {
            let Some(j) = seen.observe(try_view_now(s, "J", &group)).await else {
                return true;
            };
            let Some(a) = seen.observe(view_now(s, "A", &group)).await else {
                return true;
            };
            let Some(j_status) = seen.observe(status_now(s, "J", &group)).await else {
                return true;
            };
            if let Some(j) = j.as_ref() {
                j_seen = true;
                if j.marker.is_some() {
                    j_marked.get_or_insert_with(|| {
                        format!("at {} us: J {}", s.fabric().now().as_micros(), j.describe())
                    });
                }
            }
            let membership = j_status.as_ref().and_then(|st| st.membership.as_deref());
            j_marked.is_none() && caught_up(j.as_ref(), &a, membership)
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("J catches up to A")?;
    let j = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let a = view(sim, "A", &group).await?;
    let j_status = status(sim, "J", &group).await?;
    let membership = j_status.as_ref().and_then(|st| st.membership.clone());
    let passed = j_marked.is_none() && caught_up(j.as_ref(), &a, membership.as_deref());
    let j_text = j.as_ref().map_or_else(
        || "has no record (stub dropped)".to_string(),
        View::describe,
    );
    let j_status_text = j_status
        .as_ref()
        .map_or_else(|| "404".to_string(), Status::describe);
    ensure!(
        j_seen,
        "INFRA: J's record of the group was never observed after the seal"
    );
    let queued = sim.logs_containing(&[QUEUED_LOG, "revision_gap"]).len();
    receipt.note(format!(
        "arm={arm:?} at the end: J {j_status_text}; J {j_text}; A {}; \
         J marked: {j_marked:?}; revision_gap queue WARN lines: {queued}",
        a.describe()
    ));

    let to_a = delivered_after(sim, "J", "A", joined_at)?;
    let to_j = delivered_after(sim, "A", "J", joined_at)?;
    receipt.request_delivered(
        "j_join_reached_a_and_a_answered_j",
        to_a > 0 && to_j > 0 && sealed.lists(&j_hex),
        format!("frames since the join: J->A={to_a} A->J={to_j}; A lists J"),
        at(sim),
    );
    if !passed {
        let active = membership.as_deref() == Some("active");
        receipt.cause(
            CAUSE_ALIGNED,
            Some(format!(
                "J marked: {j_marked:?}; at the end J {j_status_text}, J {j_text}; \
                 revision_gap queue WARN lines: {queued}"
            )),
            j_marked.is_none() && !active,
            at(sim),
        );
    }
    receipt.finish(FINAL_JOIN, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("ADR 0109 S3 (#1356); the harness cannot inject DMs, so no ATA is forged.");
    let (labels, final_name) = match arm {
        Arm::AlignedJoin => (JOIN_LABELS, FINAL_JOIN),
    };
    match Sim::start(case, seed, labels).await {
        Ok(mut sim) => {
            let outcome = join_scenario(&mut sim, arm, &mut receipt).await;
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
        receipt.reclassify(final_name);
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

/// H-S3-a2 (#818, aligned clocks): RED until ADR 0109 S3 lands.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1356_red_s3_aligned_stale_joiner_catches_up() -> Result<()> {
    expect(
        "w3h_1356_red_s3_aligned_stale_joiner_catches_up",
        0x1356_0001,
        Arm::AlignedJoin,
        Verdict::Red,
    )
    .await
}
