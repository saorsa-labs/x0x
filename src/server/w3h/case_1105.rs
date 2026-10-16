//! W3-H restart-cold case for #1105 (D30 row).
//!
//! Nodes: O (the committer) and M (a member). O creates a `public_open`
//! group and seats M. Both open the same public store and sync one key at
//! revision N. M is then crash-stopped. O renames the group, which seals
//! revision N+1, while M is offline. The rename's delayed metadata DM is
//! given its 8 s to expire before M starts again, and every later publish
//! on the group's metadata topic toward M is dropped. A group card does
//! not advance a live member. The only production path left that can
//! install N+1 is the SignedPublic KV catch-up: O's store skew hook
//! (`install_public_kv_revision_catchup`), `offer_signed_public_kv_catchup`,
//! the snapshot send, and `admit_public_group_bootstrap` (apply and
//! directory-durable persistence under the membership lock).
//!
//! Three arms, the same scenario:
//! - baseline: every DM toward M is dropped during the catch-up bound, so
//!   the snapshot cannot arrive. M stays at N. The committer rejects M's
//!   state requests (`requests_received` does not move, `rejected_verify`
//!   does). RED.
//! - candidate: M records O as a Known contact, and DMs are delivered. M
//!   obtains N+1 and both stores then report `requests_received` greater
//!   than the post-restart baseline. GREEN.
//! - invite-only: M joined by invite and the test sets no contact and no
//!   share grant. O is an active admin on M's installed roster and signed
//!   the retained head, so D272 catch-up consent applies. M obtains N+1.
//!   GREEN. A new install still uses the Known-contact or grant gate.
//!
//! Disconnecting `install_public_kv_revision_catchup` from public-store
//! open leaves the candidate with no snapshot to deliver, so its request
//! stage fails and the run is INFRA rather than GREEN.
//!
//! Receipts use `w3h.receipt/1`. The D196 receipt is 20 verdict-stable
//! reruns on the existing W3-H gate. This module does not add a workflow
//! that loops CI.

#![cfg(test)]

use super::control::{
    invite, join, local_membership, members, mesh, open_store, put_value, read_value,
};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass, Write};
use anyhow::ensure;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const LABELS: &[&str] = &["O", "M"];
const SETUP: Duration = Duration::from_secs(180);
/// The metadata fan-out waits this long and sends again
/// (`GROUP_BACKGROUND_PUBLISH_DELAY` is 8 s). M stays down through it.
const RESEND_WINDOW: Duration = Duration::from_secs(10);
/// Bound for the post-restart catch-up. The same bound is both arms.
const CATCHUP: Duration = Duration::from_secs(90);
const KEY: &str = "w3h-1105-barrier";
const VALUE: &str = "before-restart";
const RENAMED: &str = "w3h 1105 n+1";
/// Gossip DM inbox and bus. A signed pubsub frame carries its topic.
const DM_TOPIC_MARKER: &[u8] = b"x0x/dm/v1/";
/// Present when the snapshot takes the raw direct lane instead of a sealed inbox.
const BOOTSTRAP_PREFIX: &[u8] = b"X0X-PUBLIC-GROUP-BOOTSTRAP-V2";
const FINAL: &str = "restarted_replica_holds_n_plus_one_and_both_receive_requests";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// DMs toward M are dropped for the catch-up bound.
    SnapshotDropped,
    /// The production snapshot path is left in place. M records O as Known.
    ProductionPath,
    /// M joined by invite. The test sets no contact and no share grant.
    InviteOnly,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn is_dm(write: &Write) -> bool {
    match write.lane.class {
        LaneClass::Direct | LaneClass::RelayedDm => true,
        LaneClass::PubSub => contains(&write.bytes, DM_TOPIC_MARKER),
        _ => false,
    }
}

fn on_topic(write: &Write, topic: &str) -> bool {
    write.lane.class == LaneClass::PubSub
        && !is_dm(write)
        && contains(&write.bytes, topic.as_bytes())
}

/// Drops metadata-topic publishes toward `target` while held, and counts them.
struct TopicBlock {
    held: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl TopicBlock {
    fn install(sim: &Sim, target: &str, topic: &str) -> Result<Self> {
        let machine = sim.peer(target)?.0;
        let topic = topic.to_string();
        let held = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_dropped) = (Arc::clone(&held), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            if rule_held.load(Ordering::SeqCst)
                && write.lane.dst == machine
                && on_topic(write, &topic)
            {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { held, dropped })
    }

    fn set(&self, held: bool) {
        self.held.store(held, Ordering::SeqCst);
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

/// Drops every DM-class frame toward `target` while held.
struct DmBlock {
    held: Arc<AtomicBool>,
}

impl DmBlock {
    fn install(sim: &Sim, target: &str) -> Result<Self> {
        let machine = sim.peer(target)?.0;
        let held = Arc::new(AtomicBool::new(false));
        let rule_held = Arc::clone(&held);
        sim.fabric().add_rule(move |write| {
            if rule_held.load(Ordering::SeqCst) && write.lane.dst == machine && is_dm(write) {
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { held })
    }

    fn set(&self, held: bool) {
        self.held.store(held, Ordering::SeqCst);
    }
}

fn delivered_to(
    sim: &Sim,
    target: &str,
    after: usize,
    keep: impl Fn(&Write) -> bool,
) -> Result<usize> {
    let dst = sim.peer(target)?;
    let mut count = 0;
    for label in LABELS.iter().filter(|label| **label != target) {
        let src = sim.peer(label)?;
        count += sim
            .fabric()
            .delivered_writes_after(&src, &dst, after)
            .into_iter()
            .filter(|(write, _)| keep(write))
            .count();
    }
    Ok(count)
}

async fn create_public(sim: &Sim, owner: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({
                "name": "w3h 1105",
                "display_name": owner,
                "preset": "public_open"
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create public group: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

async fn revision_now(sim: &Sim, label: &str, group: &str) -> Result<u64> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    crate::server::resolve_group_entry_locked(&groups, group)
        .map(|(_, info)| info.state_revision)
        .with_context(|| format!("{label} has no record of {group}"))
}

async fn revision(sim: &Sim, label: &str, group: &str) -> Result<u64> {
    let state = sim.state(label)?;
    let group = group.to_string();
    let label = label.to_string();
    sim.at_instant(&format!("read {label} revision"), async move {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &group)
            .map(|(_, info)| info.state_revision)
            .with_context(|| format!("{label} has no record of {group}"))
    })
    .await?
}

async fn metadata_topic(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let state = sim.state(label)?;
    let group = group.to_string();
    sim.at_instant("read metadata topic", async move {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &group)
            .map(|(_, info)| info.metadata_topic.clone())
            .context("group has no metadata topic")
    })
    .await?
}

async fn counter(sim: &Sim, label: &str, store: &str, field: &str) -> Result<u64> {
    let (status, body) = sim
        .request(label, Method::GET, "/diagnostics/state-sync", None)
        .await?;
    ensure!(status.is_success(), "{label} state-sync: {status} {body}");
    Ok(body["stores"][store][field].as_u64().unwrap_or(0))
}

async fn scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, LABELS).await?;
    let group = create_public(sim, "O").await?;
    let o_hex = sim.agent_hex("O")?;
    let m_hex = sim.agent_hex("M")?;
    let link = invite(sim, "O", &group).await?;
    join(sim, "M", &link).await?;
    sim.until("M seated and revisions match", SETUP, async |s: &Sim| {
        let listed = members(s, "O", &group)
            .await
            .is_ok_and(|listed| listed.contains(&m_hex));
        let active = local_membership(s, "M", &group).await.as_deref() == Some("active");
        let o_rev = revision_now(s, "O", &group).await.ok();
        let m_rev = revision_now(s, "M", &group).await.ok();
        listed && active && o_rev.is_some() && o_rev == m_rev
    })
    .await?;
    if arm == Arm::InviteOnly {
        let agent =
            super::super::parse_agent_id_hex(&o_hex).map_err(|error| anyhow::anyhow!(error))?;
        let machine = sim.ids("O")?.1;
        let (trust, grant_access_empty, stored_group_invite) = {
            let state = sim.state("M")?;
            let trust = {
                let contacts = state.contacts.read().await;
                contacts.trust_level(&agent)
            };
            let access = state.agent.share_grant_access(&agent, &machine).await;
            let stored_group_invite = state.agent.share_grant_store().is_some_and(|store| {
                [
                    crate::share_grant::GrantRole::Issued,
                    crate::share_grant::GrantRole::Received,
                ]
                .into_iter()
                .any(|role| {
                    store.grants(role).into_iter().any(|grant| {
                        grant
                            .caps
                            .contains(&crate::share_grant::ShareCap::GroupInvite)
                    })
                })
            });
            (trust, access.is_empty(), stored_group_invite)
        };
        let no_known_contact = trust == crate::contacts::TrustLevel::Unknown;
        let no_grant = grant_access_empty && !stored_group_invite;
        ensure!(
            no_known_contact && no_grant,
            "INFRA: invite-only arm recorded O as {trust}, grant_access_empty={grant_access_empty}, stored_group_invite={stored_group_invite}"
        );
        receipt.evidence(
            "invite_join_sets_no_known_contact_and_no_grant",
            no_known_contact && no_grant,
            format!(
                "trust={trust}; grant_access_empty={grant_access_empty}; stored_group_invite={stored_group_invite}"
            ),
            at(sim),
        );
    } else {
        let (status, contact) = sim
            .api(
                "M",
                Method::POST,
                "/contacts",
                Some(json!({"agent_id": o_hex, "trust_level": "known"})),
            )
            .await?;
        ensure!(
            status.is_success(),
            "M did not record O as a known contact: {status} {contact}"
        );
    }

    let topic = metadata_topic(sim, "O", &group).await?;
    let metadata = TopicBlock::install(sim, "M", &topic)?;
    let dms = DmBlock::install(sim, "M")?;
    let store = open_store(sim, "O", &group).await?;
    let opened = open_store(sim, "M", &group).await?;
    ensure!(opened == store, "M opened {opened}, O opened {store}");
    put_value(sim, "O", &store, KEY, VALUE).await?;
    sim.until(
        "M reads the shared key at revision N",
        SETUP,
        async |s: &Sim| read_value(s, "M", &store, KEY).await.as_deref() == Some(VALUE),
    )
    .await?;
    let n = revision(sim, "O", &group).await?;
    ensure!(
        revision(sim, "M", &group).await? == n,
        "revisions diverged before the restart"
    );
    receipt.evidence(
        "both_replicas_synced_at_revision_n",
        true,
        format!("revision {n} store={store}"),
        at(sim),
    );

    let before = sim
        .fabric()
        .incarnation_of(&sim.peer("M")?)
        .context("M is not on the fabric")?;
    sim.stop("M", RestartMode::Crash).await?;
    metadata.set(true);
    let rename_mark = sim
        .fabric()
        .mark_indexed("case: O seals N+1 while M is down; metadata toward M is dropped");
    let (status, renamed) = sim
        .api(
            "O",
            Method::PATCH,
            &format!("/groups/{group}"),
            Some(json!({"name": RENAMED})),
        )
        .await?;
    ensure!(status.is_success(), "rename: {status} {renamed}");
    let ahead = revision(sim, "O", &group).await?;
    ensure!(
        ahead == n.saturating_add(1),
        "rename moved O from {n} to {ahead}, expected {}",
        n + 1
    );
    sim.within(
        "metadata resend expires while M is down",
        RESEND_WINDOW.saturating_add(Duration::from_secs(2)),
        async { tokio::time::sleep(RESEND_WINDOW).await },
    )
    .await?;
    sim.start_again("M").await?;
    let incarnation = sim
        .fabric()
        .incarnation_of(&sim.peer("M")?)
        .context("M is not on the fabric after its restart")?;
    mesh(sim, LABELS).await?;
    let restarted = revision(sim, "M", &group).await?;
    ensure!(
        restarted == n,
        "INFRA: M restarted at {restarted}, not the persisted revision {n}"
    );
    ensure!(
        incarnation == before + 1,
        "M restarted as incarnation {incarnation}, expected {}",
        before + 1
    );
    let reopened = open_store(sim, "M", &group).await?;
    ensure!(reopened == store, "M reopened {reopened}, expected {store}");
    let open_mark = sim
        .fabric()
        .mark_indexed("case: M reopened the public store at revision N");
    receipt.setup_done(at(sim));
    receipt.evidence(
        "restarted_replica_is_one_commit_behind",
        restarted == n && ahead == n + 1,
        format!("M={restarted} O={ahead} incarnation {before}->{incarnation}"),
        at(sim),
    );

    if arm == Arm::SnapshotDropped {
        dms.set(true);
    }
    let base_o_received = counter(sim, "O", &store, "requests_received").await?;
    let base_m_received = counter(sim, "M", &store, "requests_received").await?;
    let base_o_rejected = counter(sim, "O", &store, "rejected_verify").await?;
    let bound_start = sim.fabric().now();
    let mut seen = Observations::default();
    let waited = sim
        .until("catch-up bound", CATCHUP, async |s: &Sim| {
            let Some(m_rev) = seen.observe(revision_now(s, "M", &group)).await else {
                return true;
            };
            let Some(o_rev) = seen.observe(revision_now(s, "O", &group)).await else {
                return true;
            };
            let Some(o_received) = seen
                .observe(counter(s, "O", &store, "requests_received"))
                .await
            else {
                return true;
            };
            let Some(m_received) = seen
                .observe(counter(s, "M", &store, "requests_received"))
                .await
            else {
                return true;
            };
            let caught_up = m_rev == o_rev
                && o_rev == n + 1
                && o_received > base_o_received
                && m_received > base_m_received;
            if arm == Arm::ProductionPath || arm == Arm::InviteOnly {
                return caught_up;
            }
            // Skew observed and still not caught up: the rest of the bound
            // is held below, so a late snapshot would still be visible.
            let Some(o_rejected) = seen
                .observe(counter(s, "O", &store, "rejected_verify"))
                .await
            else {
                return true;
            };
            o_rejected > base_o_rejected && !caught_up
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("catch-up bound")?;
    if arm == Arm::SnapshotDropped {
        let rest = CATCHUP.saturating_sub(sim.fabric().now().saturating_sub(bound_start));
        if !rest.is_zero() {
            sim.within(
                "hold the rest of the baseline bound",
                rest.saturating_add(Duration::from_secs(1)),
                async move { tokio::time::sleep(rest).await },
            )
            .await?;
        }
    }

    let m_rev = revision(sim, "M", &group).await?;
    let o_rev = revision(sim, "O", &group).await?;
    let o_received = counter(sim, "O", &store, "requests_received").await?;
    let m_received = counter(sim, "M", &store, "requests_received").await?;
    let o_rejected = counter(sim, "O", &store, "rejected_verify").await?;
    let o_delta = o_received.saturating_sub(base_o_received);
    let m_delta = m_received.saturating_sub(base_m_received);
    let metadata_delivered = delivered_to(sim, "M", rename_mark, |write| on_topic(write, &topic))?;
    let dm_delivered = delivered_to(sim, "M", open_mark, is_dm)?;
    let plaintext_snapshots = delivered_to(sim, "M", open_mark, |write| {
        contains(&write.bytes, BOOTSTRAP_PREFIX)
    })?;
    receipt.evidence(
        "no_metadata_commit_reached_the_restarted_replica",
        metadata_delivered == 0,
        format!(
            "delivered={metadata_delivered} dropped_publishes={}",
            metadata.dropped()
        ),
        at(sim),
    );
    let passed = m_rev == o_rev && o_rev == n + 1 && o_delta > 0 && m_delta > 0;
    let request_ok = match arm {
        Arm::ProductionPath | Arm::InviteOnly => dm_delivered > 0 || plaintext_snapshots > 0,
        Arm::SnapshotDropped => o_rejected > base_o_rejected && dm_delivered == 0,
    };
    receipt.request_delivered(
        match arm {
            Arm::ProductionPath => "committer_snapshot_reached_the_restarted_replica",
            Arm::SnapshotDropped => "skewed_state_request_reached_the_committer",
            Arm::InviteOnly => "snapshot_reached_the_invite_only_member",
        },
        request_ok,
        format!(
            "dm_delivered={dm_delivered} plaintext_snapshots={plaintext_snapshots} \
             O rejected_verify {} -> {o_rejected}",
            base_o_rejected
        ),
        at(sim),
    );
    if !passed {
        // M can still count a request O signed at N before O's context
        // refreshed. That does not install N+1, and O accepts nothing.
        let baseline_shape = m_rev == n && o_rev == n + 1 && o_delta == 0;
        receipt.cause(
            "restarted replica stays at revision N and the committer accepts no state request",
            Some(format!(
                "M={m_rev} O={o_rev} N={n} O requests_received +{o_delta} \
                 M requests_received +{m_delta}"
            )),
            baseline_shape,
            at(sim),
        );
    }
    receipt.note(format!(
        "arm={arm:?} M={m_rev} O={o_rev} requests O+{o_delta} M+{m_delta} \
         dm_delivered={dm_delivered} plaintext_snapshots={plaintext_snapshots}"
    ));
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "D30 restart-cold row for #1105. M crash-restarts at revision N. \
         Metadata publishes toward M are dropped and the rename's delayed \
         DM expires while M is down. The candidate obtains N+1 only through \
         the production SignedPublic snapshot path. requests_received deltas \
         are taken after M reopens the store.",
    );
    match Sim::start(case, seed, LABELS).await {
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

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1105_red_baseline_restarted_replica_stays_at_n() -> Result<()> {
    expect(
        "w3h_1105_red_baseline_restarted_replica_stays_at_n",
        0x1105_0001,
        Arm::SnapshotDropped,
        Verdict::Red,
    )
    .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1105_restarted_replica_obtains_n_plus_one_snapshot() -> Result<()> {
    expect(
        "w3h_1105_restarted_replica_obtains_n_plus_one_snapshot",
        0x1105_0002,
        Arm::ProductionPath,
        Verdict::Green,
    )
    .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1105_invite_only_restart_obtains_n_plus_one_from_local_admin() -> Result<()> {
    expect(
        "w3h_1105_invite_only_restart_obtains_n_plus_one_from_local_admin",
        0x1105_0003,
        Arm::InviteOnly,
        Verdict::Green,
    )
    .await
}
