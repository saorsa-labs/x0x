//! W3-H case for #818 part 2 (ADR 0109 H-S3-a): a TreeKEM joiner whose
//! invite base is stale, in an ownerless group, with a skewed roster clock.
//!
//! Nodes: A (creator and only admin), M1 and M2 (members), J (joiner).
//!
//! Setup S0 (skewed clocks). A creates a `private_secure` group and seats
//! M1 and M2. A then changes the group policy four times. A policy change
//! seals a commit, so the state clock moves, but the roster clock does not
//! (`update_group_policy`). ADR 0109 S0 uses renames for this step, but a
//! rename now moves both clocks (`update_named_group`), so this case uses
//! policy changes. A mints invite I at state revision r. An invite stub
//! seeds both of its clocks from r (`invite_join_group_info`).
//!
//! Schedule. A removes M2 (r+1). The case waits past the last metadata
//! resend (60 s), so the removal cannot reach J as a gossip event. J joins
//! with I, and A seals J (r+2). The roster revision that A's add carries is
//! at or below r, so J's frontier gate does not queue it. The add does not
//! chain to J's base, and a TreeKEM joiner never adopts across a gap. The
//! refused served chain then goes to `classify_refused_joiner_fork_chain`.
//!
//! GREEN (ADR 0109 S3): within 130 s J is active at A's state revision and
//! TreeKEM epoch, with no fork-quarantine marker. RED (`main`, the #818
//! design decision of 2026-09-24): an ownerless group cannot tell a gap
//! from a fork, so J installs a `signer_only` marker with `no_anchor: true`
//! on A's legitimate add and records no anchored-gap exemption.
//!
//! Controls, expected GREEN on `main`:
//! - owned: the same schedule in an `OwnerCertified` group (A holds the
//!   owner key; M1, M2 and J are same-owner devices). The owner attestation
//!   makes the refused chain a gap (`owner_attested_stale_base_gap`, #816
//!   and #818 part 1), so J catches up.
//! - just-in-time invite: the ownerless group with the same skew, but A
//!   mints I after the removal, so there is no gap (the mitigation that
//!   `docs/api-reference.md` documents).
//!
//! Receipts use `w3h.receipt/1`. The D196 receipt is 20 verdict-stable
//! reruns on the W3-H gate.

#![cfg(test)]

use super::control::{create_group, invite, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::identity::{UserId, UserKeypair};
use anyhow::ensure;
use serde_json::json;

const LABELS: &[&str] = &["A", "M1", "M2", "J"];
const SETUP: Duration = Duration::from_secs(180);
/// State-only commits before the mint. Two would be enough for the skew;
/// four keep a margin.
const POLICY_CHANGES: [&str; 4] = ["admin_only", "members_only", "admin_only", "members_only"];
/// Past the last metadata resend (60 s, `GROUP_CONTROL_REDELIVERY_SCHEDULE`).
const RESENDS_DONE: Duration = Duration::from_secs(90);
/// ADR 0109 H-S3-a: "Advance 130 s".
const CATCHUP: Duration = Duration::from_secs(130);
const FINAL: &str = "j_active_at_the_authority_revision_and_epoch_unmarked_within_130s";
const CAUSE: &str = "J installs a signer_only fork_quarantine with no_anchor=true on A's \
                     sealed add, with no anchored-gap exemption";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// Ownerless group, invite minted before the removal: the #818 gap.
    OwnerlessStale,
    /// `OwnerCertified` group, invite minted before the removal.
    OwnedStale,
    /// Ownerless group, invite minted after the removal: no gap.
    OwnerlessJustInTime,
}

impl Arm {
    fn owned(self) -> bool {
        self == Self::OwnedStale
    }

    fn gap(self) -> bool {
        self != Self::OwnerlessJustInTime
    }
}

/// The fork-quarantine marker as one node holds it.
#[derive(Debug)]
struct Marker {
    revision: u64,
    no_anchor: bool,
    classification: Option<String>,
    committed_by: String,
}

/// One node's local record of the group.
#[derive(Debug)]
struct View {
    state_revision: u64,
    roster_revision: u64,
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
            "state={} roster={} owner_axis={} epoch={:?} base={:?} marker={:?} \
             fork_evidence={} gap_refusal={:?}",
            self.state_revision,
            self.roster_revision,
            self.owner_axis,
            self.epoch,
            self.base_revision,
            self.marker,
            self.fork_evidence,
            self.gap_refusal
        )
    }
}

async fn view_now(sim: &Sim, label: &str, group: &str) -> Result<View> {
    let state = sim.state(label)?;
    let (key, view) = {
        let groups = state.named_groups.read().await;
        let (key, info) = crate::server::resolve_group_entry_locked(&groups, group)
            .with_context(|| format!("{label} has no record of {group}"))?;
        let lineage = info.invite_lineage.as_ref();
        let view = View {
            state_revision: info.state_revision,
            roster_revision: info.roster_revision,
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
    Ok(View { epoch, ..view })
}

async fn view(sim: &Sim, label: &str, group: &str) -> Result<View> {
    sim.at_instant(
        &format!("read {label}'s group"),
        view_now(sim, label, group),
    )
    .await?
}

/// `POST /groups/join`; an owner-axis invite needs home mode and the pin.
async fn join_with(sim: &Sim, joiner: &str, link: &str, owner: Option<&str>) -> Result<()> {
    let mut body = json!({"invite": link, "display_name": joiner});
    if let Some(owner) = owner {
        body["mode"] = json!("home");
        body["expected_owner_user_id"] = json!(owner);
    }
    let (status, joined) = sim
        .api(joiner, Method::POST, "/groups/join", Some(body))
        .await?;
    ensure!(
        status.is_success() && joined["ok"] != false,
        "{joiner} join: {status} {joined}"
    );
    Ok(())
}

/// A invites `member`; A lists it and it reports itself active.
async fn seat(sim: &Sim, member: &str, group: &str, owner: Option<&str>) -> Result<()> {
    let link = invite(sim, "A", group).await?;
    join_with(sim, member, &link, owner).await?;
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

/// `POST /groups` as A: the `private_secure` preset, or the same policy
/// with the `OwnerCertified` admission axis.
async fn create(sim: &Sim, owner: Option<UserId>) -> Result<String> {
    let Some(owner) = owner else {
        return create_group(sim, "A").await;
    };
    let mut policy = crate::groups::GroupPolicyPreset::PrivateSecure.to_policy();
    policy.admission = crate::groups::GroupAdmission::OwnerCertified(owner);
    let (status, created) = sim
        .api(
            "A",
            Method::POST,
            "/groups",
            Some(json!({
                "name": "w3h 818",
                "display_name": "A",
                "policy": serde_json::to_value(&policy)?,
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

/// Every label in `labels` holds A's state revision.
async fn settled(sim: &Sim, labels: &[&str], group: &str, what: &str) -> Result<()> {
    sim.until(what, SETUP, async |s: &Sim| {
        let Ok(authority) = view_now(s, "A", group).await else {
            return false;
        };
        for label in labels {
            match view_now(s, label, group).await {
                Ok(seen) if seen.state_revision == authority.state_revision => {}
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

async fn scenario(
    sim: &mut Sim,
    arm: Arm,
    owner: Option<&Owner>,
    receipt: &mut Receipt,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, LABELS).await?;
    let group = create(sim, owner.map(|o| o.id)).await?;
    let owner = owner.map(|o| o.hex.as_str());
    for member in ["M1", "M2"] {
        seat(sim, member, &group, owner).await?;
    }
    for write_access in POLICY_CHANGES {
        let (status, body) = sim
            .api(
                "A",
                Method::PATCH,
                &format!("/groups/{group}/policy"),
                Some(json!({"write_access": write_access})),
            )
            .await?;
        ensure!(
            status.is_success(),
            "policy {write_access}: {status} {body}"
        );
    }
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold A's revision").await?;
    let minted = view(sim, "A", &group).await?;
    let early = if arm.gap() {
        Some(invite(sim, "A", &group).await?)
    } else {
        None
    };
    let m2 = sim.agent_hex("M2")?;
    let (status, removed) = sim
        .api(
            "A",
            Method::DELETE,
            &format!("/groups/{group}/members/{m2}"),
            None,
        )
        .await?;
    ensure!(status.is_success(), "A removes M2: {status} {removed}");
    settled(sim, &["M1"], &group, "M1 holds the removal").await?;
    let removal = view(sim, "A", &group).await?;
    ensure!(
        removal.state_revision == minted.state_revision + 1,
        "INFRA: the removal moved A from {} to {}",
        minted.state_revision,
        removal.state_revision
    );
    let link = match early {
        Some(link) => link,
        None => invite(sim, "A", &group).await?,
    };
    sim.within("the removal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;

    let joined_at = sim.fabric().mark_indexed("case: J redeems invite I");
    join_with(sim, "J", &link, owner).await?;
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

    let base = if arm.gap() {
        minted.state_revision
    } else {
        removal.state_revision
    };
    receipt.evidence(
        if arm.owned() {
            "group_has_the_owner_axis"
        } else {
            "group_is_ownerless"
        },
        sealed.owner_axis == arm.owned() && stub.owner_axis == arm.owned(),
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
        "seal_roster_clock_at_or_below_the_joiner_seed",
        sealed.roster_revision <= base,
        format!(
            "A at mint state={} roster={}; A after the seal {}",
            minted.state_revision,
            minted.roster_revision,
            sealed.describe()
        ),
        at(sim),
    );
    let want_state = base + if arm.gap() { 2 } else { 1 };
    receipt.evidence(
        if arm.gap() {
            "gap_is_the_authority_removal_of_m2"
        } else {
            "invite_base_includes_the_removal"
        },
        sealed.state_revision == want_state
            && sealed.lists(&j_hex)
            && !sealed.lists(&m2)
            && sealed.marker.is_none(),
        format!("want A at {want_state}; A {}", sealed.describe()),
        at(sim),
    );

    let a_hex = sim.agent_hex("A")?;
    let mut seen = Observations::default();
    let waited = sim
        .until("J catches up to A", CATCHUP, async |s: &Sim| {
            let Some(j) = seen.observe(view_now(s, "J", &group)).await else {
                return true;
            };
            let Some(a) = seen.observe(view_now(s, "A", &group)).await else {
                return true;
            };
            let Some(state) = seen.observe(membership_state(s, "J", &group)).await else {
                return true;
            };
            state.as_deref() == Some("active")
                && j.marker.is_none()
                && j.state_revision == a.state_revision
                && j.epoch.is_some()
                && j.epoch == a.epoch
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("J catches up to A")?;
    let j = view(sim, "J", &group).await?;
    let a = view(sim, "A", &group).await?;
    let j_state = sim
        .at_instant("read J's membership", membership_state(sim, "J", &group))
        .await??;
    let passed = j_state.as_deref() == Some("active")
        && j.marker.is_none()
        && j.state_revision == a.state_revision
        && j.epoch.is_some()
        && j.epoch == a.epoch;
    receipt.note(format!(
        "arm={arm:?} J membership={j_state:?}; J {}; A {}",
        j.describe(),
        a.describe()
    ));
    if arm.owned() {
        receipt.evidence(
            "refused_chain_took_the_owner_attested_gap_exemption",
            j.gap_refusal.as_deref() == Some("owner_attested_stale_base_gap"),
            format!("J {}", j.describe()),
            at(sim),
        );
    }

    let to_a = delivered_after(sim, "J", "A", joined_at)?;
    let to_j = delivered_after(sim, "A", "J", joined_at)?;
    receipt.request_delivered(
        "j_join_reached_a_and_a_answered_j",
        to_a > 0 && to_j > 0 && sealed.lists(&j_hex),
        format!("frames since the join: J->A={to_a} A->J={to_j}; A lists J"),
        at(sim),
    );
    if !passed {
        let marker = j.marker.as_ref();
        let ok = marker.is_some_and(|m| {
            m.no_anchor
                && m.classification.as_deref() == Some("signer_only")
                && m.committed_by.eq_ignore_ascii_case(&a_hex)
                && m.revision > base
        }) && j.fork_evidence
            && j.gap_refusal.is_none();
        receipt.cause(
            CAUSE,
            Some(format!(
                "J membership={j_state:?} marker={marker:?} fork_evidence={} gap_refusal={:?}",
                j.fork_evidence, j.gap_refusal
            )),
            ok,
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

/// The owner axis of the owned arm.
struct Owner {
    id: UserId,
    hex: String,
}

async fn start(case: &str, seed: u64, arm: Arm) -> Result<(Sim, Option<Owner>)> {
    if !arm.owned() {
        return Ok((Sim::start(case, seed, LABELS).await?, None));
    }
    let mut sim = Sim::empty(case, seed, LABELS)?;
    // Before any daemon starts, like the node keys (`Sim::empty`).
    let owner = UserKeypair::generate()?;
    let home = sim.start_owner_device("A", &owner).await?;
    for label in ["M1", "M2", "J"] {
        sim.certify_owner_device("A", label, &owner, &home).await?;
    }
    let owner = Owner {
        id: owner.user_id(),
        hex: home.owner_user_id,
    };
    ensure!(
        hex::encode(owner.id.0).eq_ignore_ascii_case(&owner.hex),
        "INFRA: the Home names owner {}",
        owner.hex
    );
    Ok((sim, Some(owner)))
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "#818 part 2 / ADR 0109 H-S3-a. Policy changes, not renames, make the \
         state-only commits: a rename now moves the roster clock too.",
    );
    match start(case, seed, arm).await {
        Ok((mut sim, owner)) => {
            if let Err(error) = scenario(&mut sim, arm, owner.as_ref(), &mut receipt).await {
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

async fn expect(case: &str, seed: u64, arm: Arm, want: Verdict) -> Result<()> {
    let receipt = run(case, seed, arm).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// The #818 part 2 red baseline: RED on `main` until ADR 0109 S3 lands.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_818_red_baseline_ownerless_skewed_joiner_is_quarantined() -> Result<()> {
    expect(
        "w3h_818_red_baseline_ownerless_skewed_joiner_is_quarantined",
        0x0818_0001,
        Arm::OwnerlessStale,
        Verdict::Red,
    )
    .await
}

/// The same schedule with the owner axis: the owner attestation makes the
/// refused chain a gap, and J catches up (#818 part 1).
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_818_control_owned_skewed_joiner_catches_up() -> Result<()> {
    expect(
        "w3h_818_control_owned_skewed_joiner_catches_up",
        0x0818_0002,
        Arm::OwnedStale,
        Verdict::Green,
    )
    .await
}

/// The ownerless group with the same skew, but the invite is minted after
/// the removal, so there is no gap.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_818_control_ownerless_invite_after_the_removal_joins() -> Result<()> {
    expect(
        "w3h_818_control_ownerless_invite_after_the_removal_joins",
        0x0818_0003,
        Arm::OwnerlessJustInTime,
        Verdict::Green,
    )
    .await
}
