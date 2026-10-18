//! W3-H case for #1427: a TreeKEM member that is offline past the
//! metadata redelivery schedule misses a removal commit and must still
//! reach the new epoch when it returns.
//!
//! The group is `private_secure` (TreeKEM). Every member opens the same
//! group store. The returning member V is crash-stopped. The signer
//! removes R while V is down, which advances the TreeKEM epoch from e to
//! e+1. V stays down for ten virtual minutes, far past the last metadata
//! resend, and then starts again at epoch e. V is a plain member, so the
//! startup self-leave catch-up does not apply to it. No later membership
//! event follows. The only signal V gets is store traffic from epoch e+1:
//! the signer writes a new key every few seconds. A removal whose binding
//! is the legacy `treekem:epoch=<n>` form can only be delivered by its
//! signer (`catchup_may_apply_removed_as_author`).
//!
//! Two arms, the same scenario:
//! - plain: nodes O (owner, the signer), B, V and R, all reachable. This
//!   is the shape the issue reports.
//! - rotation: nodes O, P, Q, S (owner and three admins), V and R. The
//!   signer is the admin or owner with the highest agent id, so on V's
//!   candidate order it ranks after the other three admins. Those three
//!   are crash-stopped before V returns, so the first catch-up attempt
//!   reaches nobody and a later attempt must move on to the signer.
//!
//! GREEN: V's live TreeKEM epoch reaches the signer's, then V reads a
//! value the signer writes and the signer reads a value V writes. RED (the
//! issue on `main`): V stays at epoch e for the whole bound and the signer
//! serves no catch-up page. Receipts use `w3h.receipt/1`. The D196 receipt
//! is 20 verdict-stable reruns on the existing W3-H gate.

#![cfg(test)]

use super::control::{
    create_group, invite, join, local_membership, members, mesh, open_store, path_segment,
    put_value, read_value, try_open_store,
};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::LaneClass;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const SETUP: Duration = Duration::from_secs(180);
/// V stays down this long. The issue reports ten minutes. The last metadata
/// resend is 60 s after the removal (`GROUP_CONTROL_REDELIVERY_SCHEDULE`).
const OFFLINE: Duration = Duration::from_secs(600);
/// Bound for V to reach the signer's epoch after it starts again.
const CATCHUP: Duration = Duration::from_secs(120);
/// The signer writes a new store key this often during the bound.
const TICK: Duration = Duration::from_secs(5);
/// Bound for each data-plane check after V caught up.
const DATA: Duration = Duration::from_secs(60);
const KEY: &str = "w3h-1427-before";
const FINAL: &str = "returning_member_reaches_the_new_epoch_and_reads_and_writes";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// Every other member stays reachable.
    Plain,
    /// The three admins that rank before the signer are down.
    SignerAfterThreeOfflineAdmins,
}

impl Arm {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::Plain => &["O", "B", "V", "R"],
            Self::SignerAfterThreeOfflineAdmins => &["O", "P", "Q", "S", "V", "R"],
        }
    }

    /// Labels promoted to admin by O.
    fn promoted(self) -> &'static [&'static str] {
        match self {
            Self::Plain => &[],
            Self::SignerAfterThreeOfflineAdmins => &["P", "Q", "S"],
        }
    }
}

/// `label`'s group-map key for `group`.
async fn group_key(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    crate::server::resolve_group_entry_locked(&groups, group)
        .map(|(key, _)| key.to_string())
        .with_context(|| format!("{label} has no record of {group}"))
}

/// `label`'s live TreeKEM epoch for `group`.
async fn epoch_now(sim: &Sim, label: &str, group: &str) -> Result<u64> {
    let key = group_key(sim, label, group).await?;
    let state = sim.state(label)?;
    let live = state.treekem_groups.read().await.get(&key).cloned();
    let live = live.with_context(|| format!("{label} has no live TreeKEM group"))?;
    let epoch = live.lock().await.epoch();
    Ok(epoch)
}

async fn epoch(sim: &Sim, label: &str, group: &str) -> Result<u64> {
    sim.at_instant(
        &format!("read {label} TreeKEM epoch"),
        epoch_now(sim, label, group),
    )
    .await?
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

/// Catch-up pages with at least one event that `label` built so far.
fn served_pages(sim: &Sim, label: &str) -> Result<usize> {
    let state = sim.state(label)?;
    let recorded = state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(recorded
        .iter()
        .filter_map(|page| serde_json::from_slice::<serde_json::Value>(page).ok())
        .filter(|page| {
            page["events"]
                .as_array()
                .is_some_and(|events| !events.is_empty())
        })
        .count())
}

/// `label` writes `value` under `key` without a barrier (for use inside one).
async fn try_put(sim: &Sim, label: &str, store: &str, key: &str, value: &str) -> Result<()> {
    let (status, put) = sim
        .request(
            label,
            Method::PUT,
            &format!("/stores/{}/{}", path_segment(store), path_segment(key)),
            Some(json!({"value": BASE64.encode(value), "content_type": "text/plain"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} put {key}: {status} {put}");
    Ok(())
}

async fn open_everywhere(sim: &Sim, labels: &[&str], group: &str, store: &str) -> Result<()> {
    for label in labels {
        let mut opened = None;
        let mut last = String::new();
        sim.until(
            &format!("{label} opens the group store"),
            secs(60),
            async |s: &Sim| match try_open_store(s, label, group).await {
                Ok(id) => {
                    opened = Some(id);
                    true
                }
                Err(error) => {
                    last = format!("{error:#}");
                    false
                }
            },
        )
        .await
        .with_context(|| format!("{label} last store-open error: {last}"))?;
        ensure!(
            opened.as_deref() == Some(store),
            "{label} opened a different store id: {opened:?}"
        );
    }
    Ok(())
}

async fn scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let labels = arm.labels();
    mesh(sim, labels).await?;
    let group = create_group(sim, "O").await?;
    let joiners: Vec<&str> = labels.iter().copied().filter(|l| *l != "O").collect();
    for joiner in &joiners {
        let link = invite(sim, "O", &group).await?;
        join(sim, joiner, &link).await?;
        let hex = sim.agent_hex(joiner)?;
        sim.until(&format!("{joiner} seated"), SETUP, async |s: &Sim| {
            let listed = members(s, "O", &group)
                .await
                .is_ok_and(|listed| listed.contains(&hex));
            listed && local_membership(s, joiner, &group).await.as_deref() == Some("active")
        })
        .await?;
    }
    for admin in arm.promoted() {
        let hex = sim.agent_hex(admin)?;
        let (status, body) = sim
            .api(
                "O",
                Method::PATCH,
                &format!("/groups/{group}/members/{hex}/role"),
                Some(json!({"role": "admin"})),
            )
            .await?;
        ensure!(status.is_success(), "promote {admin}: {status} {body}");
    }
    sim.until("V sees every promotion", SETUP, async |s: &Sim| {
        for admin in arm.promoted() {
            if !sees_admin(s, "V", &group, admin).await.unwrap_or(false) {
                return false;
            }
        }
        true
    })
    .await?;

    // V's catch-up candidates rank owner and admins first, by agent id.
    let mut admins: Vec<(String, &str)> = std::iter::once("O")
        .chain(arm.promoted().iter().copied())
        .map(|label| sim.agent_hex(label).map(|hex| (hex, label)))
        .collect::<Result<_>>()?;
    admins.sort();
    let ((_, signer), rest) = admins.split_last().context("no admin")?;
    let signer: &str = signer;
    let decoys: Vec<&str> = rest.iter().map(|(_, label)| *label).collect();
    let r_hex = sim.agent_hex("R")?;

    let store = open_store(sim, "O", &group).await?;
    open_everywhere(sim, &joiners, &group, &store).await?;
    put_value(sim, signer, &store, KEY, "e").await?;
    sim.until(
        "V reads the signer's write at epoch e",
        SETUP,
        async |s: &Sim| read_value(s, "V", &store, KEY).await.as_deref() == Some("e"),
    )
    .await?;
    let e = epoch(sim, "V", &group).await?;
    let signer_e = epoch(sim, signer, &group).await?;
    ensure!(
        signer_e == e,
        "INFRA: V at {e} and {signer} at {signer_e} before the removal"
    );

    sim.stop("V", RestartMode::Crash).await?;
    let (status, removed) = sim
        .api(
            signer,
            Method::DELETE,
            &format!("/groups/{group}/members/{r_hex}"),
            None,
        )
        .await?;
    ensure!(
        status.is_success(),
        "{signer} removes R: {status} {removed}"
    );
    sim.until("the removal advances the epoch", SETUP, async |s: &Sim| {
        epoch_now(s, signer, &group).await.is_ok_and(|now| now > e)
    })
    .await?;
    let ahead = epoch(sim, signer, &group).await?;
    sim.within(
        "V stays down past the metadata resends",
        OFFLINE.saturating_add(Duration::from_secs(2)),
        async { tokio::time::sleep(OFFLINE).await },
    )
    .await?;
    // Empty in the plain arm: O is the only admin.
    for decoy in &decoys {
        sim.stop(decoy, RestartMode::Crash).await?;
    }
    sim.start_again("V").await?;
    let online: Vec<&str> = labels
        .iter()
        .copied()
        .filter(|label| !decoys.contains(label))
        .collect();
    mesh(sim, &online).await?;
    let restarted = epoch(sim, "V", &group).await?;
    ensure!(
        restarted == e,
        "INFRA: V restarted at epoch {restarted}, not the persisted epoch {e}"
    );
    let reopened = open_store(sim, "V", &group).await?;
    ensure!(reopened == store, "V reopened {reopened}, expected {store}");
    let back = sim
        .fabric()
        .mark_indexed("case: V is back at epoch e; the signer is at e+1");
    receipt.setup_done(at(sim));
    receipt.evidence(
        "returning_member_missed_the_removal",
        restarted == e && ahead > e,
        format!("V={restarted} {signer}={ahead} e={e}"),
        at(sim),
    );
    if arm == Arm::SignerAfterThreeOfflineAdmins {
        let order: Vec<&str> = admins.iter().map(|(_, label)| *label).collect();
        receipt.evidence(
            "signer_ranks_after_three_offline_admins",
            decoys.len() == 3 && !decoys.contains(&signer),
            format!("admin order by agent id {order:?}; signer {signer}; down {decoys:?}"),
            at(sim),
        );
    }

    let served_before = served_pages(sim, signer)?;
    let mut ticks = 0_u32;
    let mut tick_failures = Vec::new();
    let mut next_tick = sim.fabric().now();
    let mut seen = Observations::default();
    let waited = sim
        .until("V reaches the signer's epoch", CATCHUP, async |s: &Sim| {
            if s.fabric().now() >= next_tick {
                next_tick = s.fabric().now().saturating_add(TICK);
                ticks += 1;
                let key = format!("w3h-1427-tick-{ticks}");
                if let Err(error) = try_put(s, signer, &store, &key, "e+1").await {
                    tick_failures.push(format!("{error:#}"));
                }
            }
            let Some(v) = seen.observe(epoch_now(s, "V", &group)).await else {
                return true;
            };
            let Some(now) = seen.observe(epoch_now(s, signer, &group)).await else {
                return true;
            };
            v == now
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("V reaches the signer's epoch")?;
    ensure!(
        tick_failures.is_empty(),
        "INFRA: {} of {ticks} signer writes failed; first: {}",
        tick_failures.len(),
        tick_failures.first().map_or("", String::as_str)
    );
    let v_epoch = epoch(sim, "V", &group).await?;
    let signer_epoch = epoch(sim, signer, &group).await?;
    let served = served_pages(sim, signer)?.saturating_sub(served_before);
    let caught_up = v_epoch == signer_epoch;

    let mut data_ok = false;
    if caught_up {
        put_value(sim, signer, &store, "w3h-1427-after", "seen").await?;
        let read = sim
            .until("V reads the signer's next write", DATA, async |s: &Sim| {
                read_value(s, "V", &store, "w3h-1427-after")
                    .await
                    .as_deref()
                    == Some("seen")
            })
            .await;
        put_value(sim, "V", &store, "w3h-1427-back", "heard").await?;
        let heard = sim
            .until("the signer reads V's write", DATA, async |s: &Sim| {
                read_value(s, signer, &store, "w3h-1427-back")
                    .await
                    .as_deref()
                    == Some("heard")
            })
            .await;
        for outcome in [&read, &heard] {
            if let Err(error) = outcome {
                if !expired(error) {
                    anyhow::bail!("{error:#}");
                }
            }
        }
        data_ok = read.is_ok() && heard.is_ok();
        receipt.note(format!(
            "data plane after catch-up: V read={} signer read={}",
            read.is_ok(),
            heard.is_ok()
        ));
    }

    let signer_peer = sim.peer(signer)?;
    let v_peer = sim.peer("V")?;
    let traffic = sim
        .fabric()
        .delivered_writes_after(&signer_peer, &v_peer, back)
        .into_iter()
        .filter(|(write, _)| write.lane.class == LaneClass::PubSub)
        .count();
    receipt.request_delivered(
        "later_epoch_store_writes_reached_the_returning_member",
        ticks > 0 && traffic > 0,
        format!("signer writes={ticks} pubsub frames signer->V={traffic}"),
        at(sim),
    );
    let passed = caught_up && data_ok;
    if !passed {
        receipt.cause(
            "returning member stays at epoch e and the signer serves it no catch-up page",
            Some(format!(
                "V={v_epoch} {signer}={signer_epoch} e={e} pages served by {signer}={served}"
            )),
            v_epoch == e && served == 0,
            at(sim),
        );
    }
    receipt.note(format!(
        "arm={arm:?} signer={signer} V={v_epoch} {signer}={signer_epoch} e={e} \
         pages served={served} writes={ticks}"
    ));
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "#1427. V crash-stops at TreeKEM epoch e. A removal moves the group \
         to e+1 while V is down for ten virtual minutes. V starts again with \
         no later membership event; only store traffic from e+1 reaches it.",
    );
    match Sim::start(case, seed, arm.labels()).await {
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
async fn w3h_1427_offline_member_reaches_the_epoch_it_missed() -> Result<()> {
    expect(
        "w3h_1427_offline_member_reaches_the_epoch_it_missed",
        0x1427_0001,
        Arm::Plain,
        Verdict::Red,
    )
    .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1427_catchup_moves_past_three_offline_admins_to_the_signer() -> Result<()> {
    expect(
        "w3h_1427_catchup_moves_past_three_offline_admins_to_the_signer",
        0x1427_0002,
        Arm::SignerAfterThreeOfflineAdmins,
        Verdict::Red,
    )
    .await
}
