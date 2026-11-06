//! W3-H case for #1623 (ADR 0109 §2 rule (b), §7 (b), D82): a pre-Welcome
//! joiner applies the `MemberRemoved` and `MemberBanned` links of its armed
//! attested sequence state-only, with no TreeKEM group, and reaches its
//! own seal.
//!
//! Nodes O (the only install with the owner's USER key), M1, M2 and J
//! (owner-issued agent certificates only), in a non-Home OwnerCertified
//! `private_secure` (TreeKEM) group. M1 and M2 are seated. As in H-S3-c
//! (`case_1356::owner_axis`), four state-only policy changes put J's stub
//! roster clock above O's seal, so the frontier gate does not queue J's
//! seal and the refused chain reaches the owner-anchored gap check. O mints
//! invite I at revision r, removes M1 (r+1) and bans M2 (r+2), and waits
//! past the last metadata resend. J then redeems I and O seals J (r+3).
//! The seal carries the owner's v2 terminal attestation, so J's #846 gap
//! gate arms with the sequence [r+1, r+2, r+3]. The case checks the gate
//! while J is still at r with no TreeKEM group ([`JOINER_DM_LATENCY`]).
//!
//! Desired (GREEN): within [`CATCHUP`] J is active at O's state (revision
//! and hash) and TreeKEM epoch, and J's roster lists neither M1 nor M2.
//! On `main` ([`CAUSE`], RED): J has no TreeKEM group before its Welcome,
//! so the `MemberRemoved` apply refuses the r+1 link and J's catch-up
//! never passes revision r. J stays in its typed wait. Any other failure,
//! or a gate that does not arm with both links, is INFRA.
//!
//! Not covered: a `JoinRequestApproved` link for another requester (it
//! needs a second pending join request inside the gap); the admin-armed
//! (ATA) sequence. The unit tests of #1813 cover the `JoinRequestApproved`
//! kind, by direct delivery. No test arms an ATA sequence yet: the helpers
//! for it are in `group_recovery.rs` (follow-up work, Refs #1623).
//! Receipts use `w3h.receipt/1`.

#![cfg(test)]

use super::control::{invite, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::identity::UserKeypair;
use anyhow::ensure;
use serde_json::{json, Value};

const LABELS: &[&str] = &["O", "M1", "M2", "J"];
const SETUP: Duration = Duration::from_secs(180);
/// Past the last metadata resend (60 s, `GROUP_CONTROL_REDELIVERY_SCHEDULE`).
const RESENDS_DONE: Duration = Duration::from_secs(90);
/// J's catch-up window after its gate arms. Three page links need a few
/// round trips; the bound leaves a wide margin.
const CATCHUP: Duration = Duration::from_secs(90);
/// One-way delay on J's direct messages from the redeem on. With the fix,
/// J's pages arrive within one 100 ms poll of the seal, and J retires the
/// gap record when it reaches the terminal. The delay keeps the armed gate
/// visible to the poll. It is a WAN-like delay and changes no ordering
/// (each lane stays FIFO).
const JOINER_DM_LATENCY: Duration = Duration::from_millis(500);
/// The skew (see the module notes; `case_1356::POLICY_CHANGES`).
const READ_ACCESS: [&str; 4] = ["public", "members_only", "public", "members_only"];
const GAP_REASON: &str = "owner_attested_stale_base_gap";

const FINAL: &str = "j_active_at_o_state_and_epoch_without_m1_and_m2";
const CAUSE: &str = "J's catch-up never passes revision r: the pre-Welcome MemberRemoved apply \
                     refuses the r+1 link (no TreeKEM group), and J is not active at the end";

/// One node's local record of the group.
#[derive(Debug, Clone)]
struct View {
    revision: u64,
    hash: String,
    active: Vec<String>,
    /// The #846 gap record: its reason and attested sequence.
    gap: Option<(String, Vec<String>)>,
    epoch: Option<u64>,
}

impl View {
    fn lists(&self, agent: &str) -> bool {
        self.active.iter().any(|id| id.eq_ignore_ascii_case(agent))
    }

    fn describe(&self) -> String {
        format!(
            "rev={} hash={} epoch={:?} active={} gap={:?}",
            self.revision,
            self.hash.get(..12).unwrap_or(&self.hash),
            self.epoch,
            self.active.len(),
            self.gap.as_ref().map(|(reason, seq)| (reason, seq.len()))
        )
    }
}

async fn try_view(sim: &Sim, label: &str, group: &str) -> Result<Option<View>> {
    let state = sim.state(label)?;
    let (key, view) = {
        let groups = state.named_groups.read().await;
        let Some((key, info)) = crate::server::resolve_group_entry_locked(&groups, group) else {
            return Ok(None);
        };
        let gap = info
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
            .map(|record| (record.reason.clone(), record.attested_chain_hashes.clone()));
        let view = View {
            revision: info.state_revision,
            hash: info.state_hash.clone(),
            active: info.active_members().map(|m| m.agent_id.clone()).collect(),
            gap,
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
        try_view(sim, label, group),
    )
    .await??
    .with_context(|| format!("{label} has no record of {group}"))
}

/// `GET /groups/:id` on `label`: its `membership_state` and `recovery`.
async fn status(sim: &Sim, label: &str, group: &str) -> (Option<String>, Value) {
    match sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await
    {
        Ok((code, body)) if code.is_success() => (
            body["membership_state"].as_str().map(str::to_string),
            body.get("recovery").cloned().unwrap_or(Value::Null),
        ),
        Ok((code, _)) => (Some(format!("GET {code}")), Value::Null),
        Err(error) => (Some(format!("GET error {error:#}")), Value::Null),
    }
}

/// Start `label` with an owner-issued agent certificate; O also holds the
/// owner's USER key (as `case_1356::owner_axis::start_certified`).
async fn start(sim: &mut Sim, label: &str, owner: &UserKeypair) -> Result<()> {
    let (machine, agent) = sim.take_keys(label)?;
    let cert = crate::identity::AgentCertificate::issue(owner, &agent)?;
    let user_key = if label == "O" {
        Some(crate::storage::serialize_user_keypair(owner)?)
    } else {
        None
    };
    sim.start_node_with(
        label,
        Provision {
            machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
            agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
            user_key,
            agent_cert: Some(cert.to_storage_bytes()?),
        },
    )
    .await
}

/// `member` redeems `link` in the owner-pinned join mode.
async fn redeem(sim: &Sim, member: &str, link: &str, owner: &UserKeypair) -> Result<()> {
    let body = json!({
        "invite": link,
        "display_name": member,
        "mode": "home",
        "expected_owner_user_id": hex::encode(owner.user_id().as_bytes()),
    });
    let (code, answer) = sim
        .api(member, Method::POST, "/groups/join", Some(body))
        .await?;
    ensure!(code.is_success(), "{member} join: {code} {answer}");
    Ok(())
}

/// Every label in `labels` holds O's current head.
async fn settled(sim: &Sim, labels: &[&str], group: &str, what: &str) -> Result<()> {
    let head = view(sim, "O", group).await?.hash;
    sim.until(what, SETUP, async |s: &Sim| {
        for label in labels {
            match try_view(s, label, group).await {
                Ok(Some(seen)) if seen.hash == head => {}
                _ => return false,
            }
        }
        true
    })
    .await
}

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

/// O's owner-axis group with M1 and M2 seated and the clock skew, up to
/// invite I. Returns the group ID and the link.
async fn setup(sim: &mut Sim, owner: &UserKeypair) -> Result<(String, String)> {
    for label in LABELS {
        start(sim, label, owner).await?;
    }
    mesh(sim, LABELS).await?;
    sim.until("O provisions its Home", SETUP, async |s: &Sim| {
        let home = s.request("O", Method::GET, "/home", None).await;
        home.is_ok_and(|(code, body)| code.is_success() && body["state"] != "provisioning_pending")
    })
    .await?;
    for label in LABELS {
        let body = json!({"include_user_identity": true, "human_consent": true});
        let (code, answer) = sim
            .api(label, Method::POST, "/announce", Some(body))
            .await?;
        ensure!(code.is_success(), "{label} announce: {code} {answer}");
    }
    // A pinned send with no binding runs a blocking Lookup that stalls
    // paused virtual time (see `case_1357`).
    sim.until("every node pins every peer", SETUP, async |s: &Sim| {
        for (from, to) in LABELS
            .iter()
            .flat_map(|f| LABELS.iter().map(move |t| (f, t)))
        {
            let (Ok(state), Ok((id, _))) = (s.state(from), s.ids(to)) else {
                return false;
            };
            if from != to && state.agent.pinned_binding_now(&id).await.is_none() {
                return false;
            }
        }
        true
    })
    .await?;
    let policy = crate::groups::GroupPolicy {
        admission: crate::groups::GroupAdmission::OwnerCertified(owner.user_id()),
        write_access: crate::groups::GroupWriteAccess::AdminOnly,
        ..crate::groups::GroupPolicyPreset::PrivateSecure.to_policy()
    };
    let body = json!({"name": "w3h 1623", "display_name": "O", "policy": policy});
    let (code, created) = sim.api("O", Method::POST, "/groups", Some(body)).await?;
    ensure!(code.is_success(), "create: {code} {created}");
    let group = created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string();
    for member in ["M1", "M2"] {
        let link = invite(sim, "O", &group).await?;
        redeem(sim, member, &link, owner).await?;
        let hex = sim.agent_hex(member)?;
        sim.until(&format!("{member} is seated"), SETUP, async |s: &Sim| {
            let listed = members(s, "O", &group)
                .await
                .is_ok_and(|listed| listed.contains(&hex));
            listed && status(s, member, &group).await.0.as_deref() == Some("active")
        })
        .await?;
    }
    for read_access in READ_ACCESS {
        let path = format!("/groups/{group}/policy");
        let body = Some(json!({"read_access": read_access}));
        let (code, answer) = sim.api("O", Method::PATCH, &path, body).await?;
        ensure!(code.is_success(), "policy {read_access}: {code} {answer}");
    }
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold the skewed head").await?;
    let link = invite(sim, "O", &group).await?;
    Ok((group, link))
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let owner = UserKeypair::from_seed(&[0x16; 32])?;
    let (group, link) = setup(sim, &owner).await?;
    let minted = view(sim, "O", &group).await?;
    let (m1_hex, m2_hex, j_hex) = (
        sim.agent_hex("M1")?,
        sim.agent_hex("M2")?,
        sim.agent_hex("J")?,
    );
    let path = format!("/groups/{group}/members/{m1_hex}");
    let (code, body) = sim.api("O", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "O removes M1: {code} {body}");
    let removal = view(sim, "O", &group).await?;
    let path = format!("/groups/{group}/ban/{m2_hex}");
    let (code, body) = sim.api("O", Method::POST, &path, None).await?;
    ensure!(code.is_success(), "O bans M2: {code} {body}");
    let ban = view(sim, "O", &group).await?;
    sim.within(
        "the removal and ban resends end",
        RESENDS_DONE + secs(2),
        async {
            tokio::time::sleep(RESENDS_DONE).await;
        },
    )
    .await?;
    receipt.setup_done(at(sim));
    receipt.note(format!(
        "minted r={} removal={} ban={}",
        minted.revision, removal.revision, ban.revision
    ));

    // J redeems I; O seals J (r+3), and the seal arms J's gap gate.
    {
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
    redeem(sim, "J", &link, &owner).await?;
    // J's record when its gate is first seen.
    let mut gate: Option<View> = None;
    let armed = sim
        .until("O seals J and J's gap gate arms", SETUP, async |s: &Sim| {
            let o_lists = try_view(s, "O", &group)
                .await
                .ok()
                .flatten()
                .is_some_and(|v| v.lists(&j_hex));
            if gate.is_none() {
                gate = try_view(s, "J", &group)
                    .await
                    .ok()
                    .flatten()
                    .filter(|v| v.gap.is_some());
            }
            o_lists && gate.is_some()
        })
        .await
        .is_ok();
    let sealed = view(sim, "O", &group).await?;
    let stub = gate.as_ref().map_or("none".to_string(), View::describe);
    let pre_welcome = gate
        .as_ref()
        .is_some_and(|v| v.revision == minted.revision && v.epoch.is_none());
    let (reason, sequence) = gate.and_then(|v| v.gap).unwrap_or_default();
    let in_gate = |hash: &str| sequence.iter().any(|h| h == hash);
    receipt.evidence(
        "j_gate_armed_pre_welcome_with_the_removal_and_the_ban",
        armed
            && pre_welcome
            && reason == GAP_REASON
            && sealed.revision == ban.revision + 1
            && in_gate(&removal.hash)
            && in_gate(&ban.hash)
            && in_gate(&sealed.hash),
        format!(
            "armed {armed}; J at the gate {stub}; reason {reason:?}; sequence {}; O {}",
            sequence.len(),
            sealed.describe()
        ),
        at(sim),
    );

    // The window: J pages through r+1 (removal) and r+2 (ban) to r+3.
    let mut highest = 0;
    let mut last = None;
    let caught_up = sim
        .until("J catches up to O's seal", CATCHUP, async |s: &Sim| {
            let seen = try_view(s, "J", &group).await.ok().flatten();
            highest = highest.max(seen.as_ref().map_or(0, |v| v.revision));
            let membership = status(s, "J", &group).await.0;
            let done = seen.as_ref().is_some_and(|v| {
                membership.as_deref() == Some("active")
                    && v.hash == sealed.hash
                    && v.epoch.is_some()
                    && v.epoch == sealed.epoch
                    && v.lists(&j_hex)
                    && !v.lists(&m1_hex)
                    && !v.lists(&m2_hex)
            });
            last = seen;
            done
        })
        .await
        .is_ok();
    let to_o = sim
        .fabric()
        .delivered_writes_after(&sim.peer("J")?, &sim.peer("O")?, joined_at)
        .len();
    receipt.request_delivered(
        "j_reached_o",
        to_o > 0,
        format!("frames J->O after the redeem: {to_o}"),
        at(sim),
    );
    let (membership, recovery) = status(sim, "J", &group).await;
    let observed = format!(
        "J highest rev {highest} (r={}); J {}; membership {membership:?}; recovery {recovery}",
        minted.revision,
        last.as_ref()
            .map_or("no record".to_string(), View::describe),
    );
    receipt.note(observed.clone());
    if !caught_up {
        let stuck = highest <= minted.revision && membership.as_deref() != Some("active");
        receipt.cause(CAUSE, Some(observed), stuck, at(sim));
    }
    receipt.finish(FINAL, caught_up, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("#1623 (ADR 0109 §2 rule (b)); O alone holds the USER key");
    match Sim::empty(case, seed, LABELS) {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt).await {
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

/// #1623: RED on `main` ([`CAUSE`]); GREEN with the fix (PR #1813).
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1623_red_pre_welcome_joiner_applies_removal_and_ban_links() -> Result<()> {
    let case = "w3h_1623_red_pre_welcome_joiner_applies_removal_and_ban_links";
    let receipt = super::block_on_paused(run(case, 0x1623_0001));
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}
