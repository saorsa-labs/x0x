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
//!   active and never marked. J's direct messages carry
//!   [`JOINER_DM_LATENCY`]: on the base, J asks A and M1 for the next
//!   catch-up page each time a truncated page arrives, with no throttle
//!   (`request_treekem_catchup_page` after `was_truncated`), and it never
//!   applies the page, so the loop runs at the fabric's round-trip time.
//!   In CI run 39500376563, J sent about 8,200 requests to each of A and
//!   M1 in 71 s of virtual time (about 186 MB of responses from A), and
//!   the run cost about 3 s of real time per virtual second, past
//!   nextest's 300 s kill. The latency slows that loop; it is a WAN-like
//!   delay and changes no ordering (each lane stays FIFO).
//!
//! - `s3_attestation_touches_only_the_subject` (H-S3-d1 in part, D41;
//!   control, GREEN on the base and with S3). Setup S0 (skewed clocks,
//!   as `case_818`: four policy changes before the mint), then as above.
//!   Desired: whatever J's outcome, A and M1 are never marked in the
//!   [`CATCHUP`] window, M1 reaches A's head (r+2) by gossip, no node's
//!   state revision passes r+2, and A's and M1's `recovery` objects do not
//!   change. The ADR's step that copies J's join-carry ATA and injects it
//!   to M1 needs a DM-injection hook the harness does not have, and an ATA
//!   the base cannot build; with S3 the case still checks that J's
//!   recovery acts on J only.
//!
//! Fork arms. Nodes A (creator, admin), X (promoted to admin) and M1
//! (member), in an ordinary `private_secure` group with no owner axis, all
//! at state revision r. Every write from X is dropped ([`OutboundHold`]);
//! X renames (r+1′, on X only) and A renames (r+1). X still receives A's
//! r+1, a sibling of its own head, so X installs a `no_anchor` marker.
//! After X's resends end, only X's pubsub writes stay held, for the rest
//! of the run: direct messages (an S3 `group_attest_request`, the re-seat
//! join) pass. In CI run 39496687111 a full release let X's pubsub cache
//! replay r+1′ to A about 26 s later, and A was marked too, which is not
//! this case's shape (H-S3-c "holds" the fork from the main chain). X's head is on no admin's
//! chain: X is forked (ADR 0109 §3), while A and M1 share one chain and
//! are unmarked. The case then advances [`ATTEST_ROUND`].
//!
//! - `s3_forked_node_shows_reseat_required` (§3 and §8, RED on the base).
//!   Desired: X shows the typed wait `recovery.state = reseat_required`
//!   with `cause = not_on_chain` (A answered its request), and stays
//!   marked on its fork. The base ([`CAUSE_TYPED`]): X stays marked, and
//!   `GET /groups/:id` on X has no `recovery` object.
//! - `s3_forked_node_not_auto_recovered` (§3, 0088 §2 item 7; control,
//!   GREEN on the base and with S3). Desired: through the window X keeps
//!   its marker and its fork head, and A and M1 do not change. No
//!   attestation resolves a fork.
//! - `s3_manual_reseat_recovers_forked_node` (§3, an ownerless H-S3-c with
//!   a `Removal` basis as in H-S3-d8; RED on the base). After the window
//!   A removes X (r+2) and calls `POST /groups/:id/members/:agent_id/reseat`
//!   with a reason and basis `Removal(r+2)` ([`reseat_body`]). With no call
//!   on X's API, X consumes the authorisation and is desired active at
//!   A's state revision and TreeKEM epoch, unmarked, within
//!   [`RESEAT_BOUND`]. The base ([`CAUSE_RESEAT`]): the route does not
//!   exist (404) and X stays forked.
//!
//! The `recovery` object is read as `{"state": .., "cause": ..}` and the
//! re-seat request body as [`reseat_body`]: the harness's reading of ADR
//! 0109 §3 and §8, which name the fields but not their JSON. The S3 code
//! sets the API (`docs/api-reference.md`); if it differs, the S3 PR
//! aligns these two readers in this file.
//!
//! Receipts use `w3h.receipt/1`. The D196 receipt is 20 verdict-stable
//! reruns on the W3-H gate.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh};
use super::home::roster;
use super::receipt::{Receipt, Verdict};
use super::*;
use anyhow::ensure;
use serde_json::{json, Value};

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
/// Extra one-way latency on J's direct messages in the aligned arm (see
/// the module notes): it bounds the base's next-page loop so the run fits
/// nextest's kill.
const JOINER_DM_LATENCY: Duration = Duration::from_millis(100);

/// Real-time limit for a join arm's scenario, below nextest's 300 s kill
/// (`slow-timeout` 60 s x 5 in the `w3h-gate` profile), so a slow run
/// still writes its receipt (INFRA) with what it saw. In CI run
/// 39496687111 the aligned arm was killed at 300 s with no receipt.
const REAL_SCENARIO_LIMIT: std::time::Duration = std::time::Duration::from_secs(230);
/// Virtual interval between `W3H-PROGRESS` lines in a join window.
const PROGRESS_EVERY: Duration = Duration::from_secs(10);

const QUEUED_LOG: &str = "queued TreeKEM membership event pending catch-up/replay";

/// S0 step 3: state-only commits before the mint. A rename now moves the
/// roster clock too (`update_named_group`), so, as in `case_818`, policy
/// changes make the skew. Two would be enough; four keep a margin.
const POLICY_CHANGES: [&str; 4] = ["admin_only", "members_only", "admin_only", "members_only"];
const FORK_LABELS: &[&str] = &["A", "X", "M1"];
/// PLACEHOLDER (ADR 0109 leaves it to measurement): the time a marked,
/// forked node takes to reach its typed state. It covers the first
/// `group_attest_request` and two retries at the §11 backoff (60 s, then
/// 120 s), each with its answer.
const ATTEST_ROUND: Duration = Duration::from_secs(240);
const FINAL_TYPED: &str = "x_shows_reseat_required_not_on_chain_and_stays_contained";
const CAUSE_TYPED: &str = "X stays marked on its fork, and GET /groups/:id on X has no \
                           recovery object in the whole window";
const FINAL_NOT_AUTO: &str = "x_stays_marked_on_its_fork_and_a_m1_unchanged";
/// PLACEHOLDER (ADR 0109 leaves it to measurement): from the admin's
/// re-seat call to the subject's swap (§3: delivery, the staged join
/// with ADR 0107's guards, the TreeKEM Welcome and the durable swap).
const RESEAT_BOUND: Duration = Duration::from_secs(300);
const RESEAT_REASON: &str = "w3h #1356: X forked off the main chain while partitioned";
const FINAL_RESEAT: &str = "x_active_at_the_authority_revision_and_epoch_after_the_reseat";
const CAUSE_RESEAT: &str = "the re-seat route POST /groups/:id/members/:agent_id/reseat is \
                            absent (404) and X stays forked";
const FINAL_BYSTANDERS: &str =
    "a_and_m1_never_marked_m1_at_the_seal_no_revision_past_it_recovery_unchanged";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// H-S3-a2: S0′ (aligned clocks), stale invite.
    AlignedJoin,
    /// H-S3-d1 in part: S0 (skewed clocks); only the bystanders are judged.
    SkewBystanders,
    /// §3 and §8: the forked node's typed state.
    ForkTyped,
    /// §3: no automatic recovery of a forked node.
    ForkNotAuto,
    /// §3: the admin's manual re-seat recovers the forked node.
    ForkReseat,
}

impl Arm {
    fn skew(self) -> bool {
        self == Self::SkewBystanders
    }

    fn fork(self) -> bool {
        matches!(self, Self::ForkTyped | Self::ForkNotAuto | Self::ForkReseat)
    }
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
    fn recovery_state(&self) -> Option<&str> {
        self.recovery["state"].as_str()
    }

    fn recovery_cause(&self) -> Option<&str> {
        self.recovery["cause"].as_str()
    }

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

/// One `W3H-PROGRESS` line on stdout (nextest shows it for a killed test).
fn progress(sim: &Sim, started: std::time::Instant, what: &str) {
    println!(
        "W3H-PROGRESS virt={}ms real={}ms {what}",
        sim.fabric().now().as_millis(),
        started.elapsed().as_millis()
    );
}

/// Join arms: S0 or S0′ up to J's seal, then [`CATCHUP`].
async fn join_scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    let started = std::time::Instant::now();
    mesh(sim, JOIN_LABELS).await?;
    let group = create_group(sim, "A").await?;
    for member in ["M1", "M2"] {
        seat(sim, "A", member, &group).await?;
    }
    progress(sim, started, "M1 and M2 seated");
    if arm.skew() {
        for write_access in POLICY_CHANGES {
            let (code, body) = sim
                .api(
                    "A",
                    Method::PATCH,
                    &format!("/groups/{group}/policy"),
                    Some(json!({"write_access": write_access})),
                )
                .await?;
            ensure!(code.is_success(), "policy {write_access}: {code} {body}");
        }
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

    progress(sim, started, "removal resends done");
    let a_recovery_before = status(sim, "A", &group).await?.map(|st| st.recovery);
    let m1_recovery_before = status(sim, "M1", &group).await?.map(|st| st.recovery);
    if !arm.skew() {
        use crate::network::sim::{Fault, LaneClass};
        let joiner = sim.peer("J")?.0;
        sim.fabric().add_rule(move |write| {
            if write.lane.src == joiner && write.lane.class == LaneClass::Direct {
                Fault::Delay(JOINER_DM_LATENCY)
            } else {
                Fault::Pass
            }
        });
        sim.fabric().mark(format!(
            "fault: J's direct messages delayed {JOINER_DM_LATENCY:?}"
        ));
    }
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
    progress(sim, started, "A sealed J");
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
    let (clock_stage, clock_ok) = if arm.skew() {
        (
            "seal_roster_clock_at_or_below_the_joiner_seed",
            sealed.roster_revision <= base,
        )
    } else {
        (
            "seal_roster_clock_above_the_joiner_seed",
            sealed.roster_revision > base,
        )
    };
    receipt.evidence(
        clock_stage,
        clock_ok,
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
    let mut bystander_marked: Option<String> = None;
    let mut max_revision = 0_u64;
    let mut j_seen = false;
    let mut next_progress = sim.fabric().now();
    let mut real_limit_hit: Option<String> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("J catches up to A", CATCHUP, async |s: &Sim| {
            let Some(j) = seen.observe(try_view_now(s, "J", &group)).await else {
                return true;
            };
            let now = s.fabric().now();
            let j_text = j
                .as_ref()
                .map_or_else(|| "no record".to_string(), View::describe);
            if now >= next_progress {
                next_progress = now + PROGRESS_EVERY;
                progress(s, started, &format!("window: J {j_text}"));
            }
            if started.elapsed() > REAL_SCENARIO_LIMIT {
                real_limit_hit = Some(format!(
                    "at virtual {} ms, real {} ms: J {j_text}",
                    now.as_millis(),
                    started.elapsed().as_millis()
                ));
                return true;
            }
            let Some(a) = seen.observe(view_now(s, "A", &group)).await else {
                return true;
            };
            let Some(j_status) = seen.observe(status_now(s, "J", &group)).await else {
                return true;
            };
            let Some(m1) = seen.observe(view_now(s, "M1", &group)).await else {
                return true;
            };
            for (label, node) in [("A", &a), ("M1", &m1)] {
                if node.marker.is_some() {
                    bystander_marked.get_or_insert_with(|| {
                        format!(
                            "at {} us: {label} {}",
                            s.fabric().now().as_micros(),
                            node.describe()
                        )
                    });
                }
            }
            max_revision = max_revision
                .max(a.state_revision)
                .max(m1.state_revision)
                .max(j.as_ref().map_or(0, |j| j.state_revision));
            if let Some(j) = j.as_ref() {
                j_seen = true;
                if j.marker.is_some() {
                    j_marked.get_or_insert_with(|| {
                        format!("at {} us: J {}", s.fabric().now().as_micros(), j.describe())
                    });
                }
            }
            let membership = j_status.as_ref().and_then(|st| st.membership.as_deref());
            // The bystander control judges the whole window.
            !arm.skew() && j_marked.is_none() && caught_up(j.as_ref(), &a, membership)
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("J catches up to A")?;
    if let Some(hit) = real_limit_hit {
        bail!("INFRA: the join window passed its real-time limit {REAL_SCENARIO_LIMIT:?} {hit}");
    }
    let j = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let a = view(sim, "A", &group).await?;
    let j_status = status(sim, "J", &group).await?;
    let membership = j_status.as_ref().and_then(|st| st.membership.clone());
    let m1 = view(sim, "M1", &group).await?;
    let a_recovery_after = status(sim, "A", &group).await?.map(|st| st.recovery);
    let m1_recovery_after = status(sim, "M1", &group).await?.map(|st| st.recovery);
    let j_passed = j_marked.is_none() && caught_up(j.as_ref(), &a, membership.as_deref());
    let bystanders_passed = bystander_marked.is_none()
        && m1.state_revision == sealed.state_revision
        && m1.state_hash == sealed.state_hash
        && a.state_hash == sealed.state_hash
        && max_revision <= sealed.state_revision
        && a_recovery_before == a_recovery_after
        && m1_recovery_before == m1_recovery_after;
    let passed = if arm.skew() {
        bystanders_passed
    } else {
        j_passed
    };
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
         J marked: {j_marked:?}; revision_gap queue WARN lines: {queued}; \
         J frames since the join: to A {}, to M1 {}",
        a.describe(),
        delivered_after(sim, "J", "A", joined_at)?,
        delivered_after(sim, "J", "M1", joined_at)?
    ));
    receipt.note(format!(
        "bystanders: M1 {}; marked: {bystander_marked:?}; max revision {max_revision} \
         (seal at {}); A recovery {a_recovery_before:?} -> {a_recovery_after:?}; \
         M1 recovery {m1_recovery_before:?} -> {m1_recovery_after:?}",
        m1.describe(),
        sealed.state_revision
    ));

    let to_a = delivered_after(sim, "J", "A", joined_at)?;
    let to_j = delivered_after(sim, "A", "J", joined_at)?;
    receipt.request_delivered(
        "j_join_reached_a_and_a_answered_j",
        to_a > 0 && to_j > 0 && sealed.lists(&j_hex),
        format!("frames since the join: J->A={to_a} A->J={to_j}; A lists J"),
        at(sim),
    );
    if !passed && !arm.skew() {
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
    receipt.finish(
        if arm.skew() {
            FINAL_BYSTANDERS
        } else {
            FINAL_JOIN
        },
        passed,
        at(sim),
    );
    Ok(())
}

/// Drops writes from one node, and counts them. The node still receives.
/// Installed holding every write; [`Self::release`] then holds only its
/// pubsub writes, so its fork commit never reaches the main chain while
/// its direct messages pass.
struct OutboundHold {
    held: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
    pubsub_dropped: Arc<std::sync::atomic::AtomicUsize>,
}

impl OutboundHold {
    fn install(sim: &Sim, node: &str) -> Result<Self> {
        use crate::network::sim::{Fault, LaneClass};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let machine = sim.peer(node)?.0;
        let held = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicUsize::new(0));
        let pubsub_dropped = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_dropped, rule_pubsub) = (
            Arc::clone(&held),
            Arc::clone(&dropped),
            Arc::clone(&pubsub_dropped),
        );
        sim.fabric().add_rule(move |write| {
            if write.lane.src != machine {
                return Fault::Pass;
            }
            if rule_held.load(Ordering::SeqCst) {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else if write.lane.class == LaneClass::PubSub {
                rule_pubsub.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        sim.fabric()
            .mark(format!("fault: every write from {node} withheld"));
        Ok(Self {
            held,
            dropped,
            pubsub_dropped,
        })
    }

    fn release(&self, sim: &Sim, node: &str) {
        self.held.store(false, std::sync::atomic::Ordering::SeqCst);
        sim.fabric()
            .mark(format!("fault: writes from {node} released, except pubsub"));
    }

    fn dropped(&self) -> usize {
        self.dropped.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn pubsub_dropped(&self) -> usize {
        self.pubsub_dropped
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The §3 re-seat request: a non-empty reason and a `Removal` basis.
fn reseat_body(removal: &View) -> Value {
    json!({
        "reason": RESEAT_REASON,
        "basis": {
            "kind": "removal",
            "revision": removal.state_revision,
            "state_hash": removal.state_hash,
        },
    })
}

/// A removes X, calls the re-seat route, and waits [`RESEAT_BOUND`] for X
/// to be active at A's state and epoch. Returns whether it is.
async fn reseat(sim: &Sim, group: &str, receipt: &mut Receipt) -> Result<bool> {
    let x_hex = sim.agent_hex("X")?;
    let (code, removed) = sim
        .api(
            "A",
            Method::DELETE,
            &format!("/groups/{group}/members/{x_hex}"),
            None,
        )
        .await?;
    ensure!(code.is_success(), "A removes X: {code} {removed}");
    sim.until("A no longer lists X", SETUP, async |s: &Sim| {
        view_now(s, "A", group)
            .await
            .is_ok_and(|a| !a.lists(&x_hex))
    })
    .await?;
    let removal = view(sim, "A", group).await?;
    let (code, answer) = sim
        .api(
            "A",
            Method::POST,
            &format!("/groups/{group}/members/{x_hex}/reseat"),
            Some(reseat_body(&removal)),
        )
        .await?;
    let mut seen = Observations::default();
    let waited = sim
        .until("X is re-seated", RESEAT_BOUND, async |s: &Sim| {
            let Some(a) = seen.observe(view_now(s, "A", group)).await else {
                return true;
            };
            let Some(x) = seen.observe(try_view_now(s, "X", group)).await else {
                return true;
            };
            let Some(x_status) = seen.observe(status_now(s, "X", group)).await else {
                return true;
            };
            let membership = x_status.as_ref().and_then(|st| st.membership.as_deref());
            caught_up(x.as_ref(), &a, membership)
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("X is re-seated")?;
    let a = view(sim, "A", group).await?;
    let x = sim
        .at_instant("read X's group", try_view_now(sim, "X", group))
        .await??;
    let x_status = status(sim, "X", group).await?;
    let membership = x_status.as_ref().and_then(|st| st.membership.clone());
    let passed = caught_up(x.as_ref(), &a, membership.as_deref());
    let x_text = x
        .as_ref()
        .map_or_else(|| "has no record".to_string(), View::describe);
    let x_status_text = x_status
        .as_ref()
        .map_or_else(|| "404".to_string(), Status::describe);
    let observed = format!(
        "reseat {code} {answer}; removal at {} {}; at the end A {}; X {x_status_text}; X {x_text}",
        removal.state_revision,
        short(&removal.state_hash),
        a.describe()
    );
    receipt.note(observed.clone());
    if !passed {
        let forked = x
            .as_ref()
            .is_some_and(|x| x.marker.is_some() && x.state_hash != a.state_hash);
        receipt.cause(
            CAUSE_RESEAT,
            Some(observed),
            code == StatusCode::NOT_FOUND && forked,
            at(sim),
        );
    }
    Ok(passed)
}

async fn rename(sim: &Sim, label: &str, group: &str, name: &str) -> Result<()> {
    let (code, body) = sim
        .api(
            label,
            Method::PATCH,
            &format!("/groups/{group}"),
            Some(json!({"name": name})),
        )
        .await?;
    ensure!(code.is_success(), "{label} renames: {code} {body}");
    Ok(())
}

/// Fork arms: X forks off A's chain, then [`ATTEST_ROUND`].
async fn fork_scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    mesh(sim, FORK_LABELS).await?;
    let group = create_group(sim, "A").await?;
    for member in ["X", "M1"] {
        seat(sim, "A", member, &group).await?;
    }
    let x_hex = sim.agent_hex("X")?;
    let (code, promoted) = sim
        .api(
            "A",
            Method::PATCH,
            &format!("/groups/{group}/members/{x_hex}/role"),
            Some(json!({"role": "admin"})),
        )
        .await?;
    ensure!(code.is_success(), "A promotes X: {code} {promoted}");
    sim.until("every node sees X as admin", SETUP, async |s: &Sim| {
        for label in FORK_LABELS {
            let admin = roster(s, label, &group).await.is_ok_and(|rows| {
                rows.iter()
                    .any(|(id, role)| id.eq_ignore_ascii_case(&x_hex) && role == "admin")
            });
            if !admin {
                return false;
            }
        }
        true
    })
    .await?;
    settled(sim, &["X", "M1"], &group, "X and M1 hold A's revision").await?;
    let base = view(sim, "A", &group).await?;

    let hold = OutboundHold::install(sim, "X")?;
    rename(sim, "X", &group, "w3h fork X").await?;
    let fork_at = sim
        .fabric()
        .mark_indexed("case: A commits r+1 on the main chain");
    rename(sim, "A", &group, "w3h main A").await?;
    settled(sim, &["M1"], &group, "M1 holds A's r+1").await?;
    sim.within("X's resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let dropped = hold.dropped();
    hold.release(sim, "X");
    let a0 = view(sim, "A", &group).await?;
    let x0 = view(sim, "X", &group).await?;
    let m10 = view(sim, "M1", &group).await?;
    receipt.setup_done(at(sim));

    receipt.evidence(
        "group_is_ownerless",
        !a0.owner_axis && !x0.owner_axis,
        format!(
            "A owner_axis={} X owner_axis={}",
            a0.owner_axis, x0.owner_axis
        ),
        at(sim),
    );
    receipt.evidence(
        "x_rename_withheld_from_every_peer",
        dropped > 0,
        format!("{dropped} writes from X dropped while held"),
        at(sim),
    );
    receipt.evidence(
        "x_forked_off_a_chain_at_r_plus_1",
        a0.state_revision == base.state_revision + 1
            && x0.state_revision == a0.state_revision
            && x0.state_hash != a0.state_hash,
        format!(
            "base {}; A {}; X {}",
            base.state_revision,
            a0.describe(),
            x0.describe()
        ),
        at(sim),
    );
    receipt.evidence(
        "x_contained_by_a_marker",
        x0.marker.is_some(),
        format!("X {}", x0.describe()),
        at(sim),
    );
    receipt.evidence(
        "a_and_m1_on_one_chain_unmarked",
        a0.marker.is_none() && m10.marker.is_none() && m10.state_hash == a0.state_hash,
        format!("A {}; M1 {}", a0.describe(), m10.describe()),
        at(sim),
    );
    let to_x = delivered_after(sim, "A", "X", fork_at)?;
    receipt.request_delivered(
        "a_commit_reached_x",
        to_x > 0,
        format!("frames A->X since A's r+1: {to_x}"),
        at(sim),
    );

    let mut others_marked: Option<String> = None;
    let mut x_recovered: Option<String> = None;
    let mut x_recovery_seen: Option<String> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("X's attestation round", ATTEST_ROUND, async |s: &Sim| {
            let Some(a) = seen.observe(view_now(s, "A", &group)).await else {
                return true;
            };
            let Some(x) = seen.observe(view_now(s, "X", &group)).await else {
                return true;
            };
            let Some(m1) = seen.observe(view_now(s, "M1", &group)).await else {
                return true;
            };
            let Some(x_status) = seen.observe(status_now(s, "X", &group)).await else {
                return true;
            };
            let now = s.fabric().now().as_micros();
            for (label, node) in [("A", &a), ("M1", &m1)] {
                if node.marker.is_some() || node.state_hash != a0.state_hash {
                    others_marked
                        .get_or_insert_with(|| format!("at {now} us: {label} {}", node.describe()));
                }
            }
            if x.marker.is_none() || x.state_hash == a.state_hash {
                x_recovered.get_or_insert_with(|| format!("at {now} us: X {}", x.describe()));
            }
            if let Some(x_status) = x_status.filter(|st| !st.recovery.is_null()) {
                x_recovery_seen
                    .get_or_insert_with(|| format!("at {now} us: X {}", x_status.describe()));
            }
            // Every fork arm judges the whole window.
            false
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("X's attestation round")?;
    let a1 = view(sim, "A", &group).await?;
    let x1 = view(sim, "X", &group).await?;
    let m11 = view(sim, "M1", &group).await?;
    let x_status = status(sim, "X", &group).await?;
    let x_status_text = x_status
        .as_ref()
        .map_or_else(|| "404".to_string(), Status::describe);
    receipt.evidence(
        "a_and_m1_unchanged_in_the_window",
        others_marked.is_none()
            && a1.state_hash == a0.state_hash
            && m11.state_hash == a0.state_hash,
        format!(
            "first change: {others_marked:?}; A {}; M1 {}",
            a1.describe(),
            m11.describe()
        ),
        at(sim),
    );
    receipt.note(format!(
        "arm={arm:?} after the window: X {x_status_text}; X {}; X recovered: {x_recovered:?}; \
         X recovery first seen: {x_recovery_seen:?}; X pubsub writes held since the \
         release: {}",
        x1.describe(),
        hold.pubsub_dropped()
    ));
    let contained = x1.marker.is_some() && x_recovered.is_none();
    let (final_name, passed) = match arm {
        Arm::ForkTyped => {
            let typed = x_status.as_ref().is_some_and(|st| {
                st.recovery_state() == Some("reseat_required")
                    && st.recovery_cause() == Some("not_on_chain")
            });
            let passed = typed && contained;
            if !passed {
                receipt.cause(
                    CAUSE_TYPED,
                    Some(format!(
                        "X recovery first seen: {x_recovery_seen:?}; at the end X {x_status_text}, \
                         X {}",
                        x1.describe()
                    )),
                    contained && x_recovery_seen.is_none(),
                    at(sim),
                );
            }
            (FINAL_TYPED, passed)
        }
        Arm::ForkNotAuto => (FINAL_NOT_AUTO, contained && x1.state_hash != a1.state_hash),
        Arm::ForkReseat => (FINAL_RESEAT, reseat(sim, &group, receipt).await?),
        Arm::AlignedJoin | Arm::SkewBystanders => bail!("INFRA: {arm:?} is not a fork arm"),
    };
    receipt.finish(final_name, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("ADR 0109 S3 (#1356); the harness cannot inject DMs, so no ATA is forged.");
    let (labels, final_name) = match arm {
        Arm::AlignedJoin => (JOIN_LABELS, FINAL_JOIN),
        Arm::SkewBystanders => (JOIN_LABELS, FINAL_BYSTANDERS),
        Arm::ForkTyped => (FORK_LABELS, FINAL_TYPED),
        Arm::ForkNotAuto => (FORK_LABELS, FINAL_NOT_AUTO),
        Arm::ForkReseat => (FORK_LABELS, FINAL_RESEAT),
    };
    match Sim::start(case, seed, labels).await {
        Ok(mut sim) => {
            let outcome = if arm.fork() {
                fork_scenario(&mut sim, arm, &mut receipt).await
            } else {
                join_scenario(&mut sim, arm, &mut receipt).await
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

/// H-S3-d1 in part (D41): J's recovery never marks, clears or moves A or M1.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1356_control_s3_attestation_touches_only_the_subject() -> Result<()> {
    expect(
        "w3h_1356_control_s3_attestation_touches_only_the_subject",
        0x1356_0002,
        Arm::SkewBystanders,
        Verdict::Green,
    )
    .await
}

/// ADR 0109 §3 and §8: a forked node shows `reseat_required {not_on_chain}`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1356_red_s3_forked_node_shows_reseat_required() -> Result<()> {
    expect(
        "w3h_1356_red_s3_forked_node_shows_reseat_required",
        0x1356_0003,
        Arm::ForkTyped,
        Verdict::Red,
    )
    .await
}

/// ADR 0109 §3: a forked node is never recovered automatically.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1356_control_s3_forked_node_not_auto_recovered() -> Result<()> {
    expect(
        "w3h_1356_control_s3_forked_node_not_auto_recovered",
        0x1356_0004,
        Arm::ForkNotAuto,
        Verdict::Green,
    )
    .await
}

/// ADR 0109 §3: an admin's manual re-seat recovers a forked node.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1356_red_s3_manual_reseat_recovers_forked_node() -> Result<()> {
    expect(
        "w3h_1356_red_s3_manual_reseat_recovers_forked_node",
        0x1356_0005,
        Arm::ForkReseat,
        Verdict::Red,
    )
    .await
}
