//! W3-H cases `w3h_1149_treekem_banned_agent_not_readmitted_by_pre_ban_invite`
//! and `w3h_1149_signed_public_banned_agent_not_readmitted_by_pre_ban_invite`
//! (#1149, the authority side).
//!
//! Nodes: A (owner, the authority) and J (joiner). Public HTTP only.
//!
//! 1. A creates the group. Every frame from A to J except plane hello is
//!    dropped, so J observes nothing that A sends.
//! 2. J redeems an invite. A seats J. J's join poll times out with no carry
//!    and leaves no local row.
//! 3. A mints a second invite. Its signed base already seats J.
//! 4. A bans J through the API. J does not observe the ban.
//! 5. J redeems the stale invite from step 3. J's `MemberJoined` reaches A.
//! 6. The drop lifts, and the clock moves on. A encrypts a probe at its
//!    current TreeKEM epoch, and J tries to decrypt it.
//!
//! There is one test per confidentiality: `private_secure` (TreeKEM) and
//! `public_open` (SignedPublic).
//!
//! Baseline on main: A applies J's `MemberJoined` from the pre-ban invite.
//! The apply has no ban check, and `add_member_with_kem` sets the banned
//! row back to `active`. A seats J again, and in the TreeKEM variant J
//! gets the group keys and reads the probe that A encrypts after the ban.
//! Fixed: A refuses the `MemberJoined` of a banned agent before it
//! consumes the invite, and counts the refusal. A's row for J stays
//! `banned`, and J holds no TreeKEM group and cannot read the probe. The
//! row is GREEN only when A's ban-refusal counter went up, so it proves
//! that J's `MemberJoined` reached A and that the ban check refused it.
//!
//! J's local report from the invite base (`base_seats_joiner`) is a note
//! only. This row does not assert it.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::control::{invite, join, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass, Write};
use anyhow::ensure;
use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::json;

const SEED: u64 = 0x1149_0001;
const FINAL: &str = "banned_agent_stays_banned";
const CAUSE: &str = "A re-admits banned J from an invite minted before the ban";
/// Time after the drop lifts for A's current answer to reach J.
const SETTLE: Duration = Duration::from_secs(60);
const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
/// The plaintext A encrypts after the ban, at its current epoch.
const PROBE: &[u8] = b"w3h 1149 probe sent after the ban";

#[derive(Clone, Copy)]
enum Variant {
    TreeKem,
    SignedPublic,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Self::TreeKem => "treekem",
            Self::SignedPublic => "signed_public",
        }
    }

    fn case(self) -> &'static str {
        match self {
            Self::TreeKem => "w3h_1149_treekem_banned_agent_not_readmitted_by_pre_ban_invite",
            Self::SignedPublic => {
                "w3h_1149_signed_public_banned_agent_not_readmitted_by_pre_ban_invite"
            }
        }
    }

    fn seed(self) -> u64 {
        match self {
            Self::TreeKem => SEED,
            Self::SignedPublic => SEED + 1,
        }
    }

    fn preset(self) -> &'static str {
        match self {
            Self::TreeKem => "private_secure",
            Self::SignedPublic => "public_open",
        }
    }

    /// The joiner's first poll deadline plus margin: 120 s for TreeKEM,
    /// 10 min for the non-TreeKEM poll.
    fn first_poll_budget(self) -> Duration {
        match self {
            Self::TreeKem => secs(160),
            Self::SignedPublic => secs(640),
        }
    }
}

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

/// Drops every A→J frame except plane hello while held.
struct AwayFromJ {
    held: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl AwayFromJ {
    fn install(sim: &Sim) -> Result<Self> {
        let src = sim.peer("A")?.0;
        let dst = sim.peer("J")?.0;
        let held = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_dropped) = (Arc::clone(&held), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write: &Write| {
            let blocked = rule_held.load(Ordering::SeqCst)
                && write.lane.src == src
                && write.lane.dst == dst
                && write.lane.class != LaneClass::PlaneHello;
            if blocked {
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

async fn create_group(sim: &Sim, owner: &str, preset: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({"name": "w3h 1149", "display_name": owner, "preset": preset})),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create {preset}: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

async fn membership(sim: &Sim, label: &str, group: &str) -> Result<Option<String>> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(body["membership_state"].as_str().map(str::to_string))
}

async fn join_outcome(sim: &Sim, group: &str) -> Result<Option<String>> {
    let (_status, body) = sim
        .request(
            "J",
            Method::GET,
            &format!("/groups/{group}/join-status"),
            None,
        )
        .await?;
    Ok(body["last_join_outcome"]["outcome"]
        .as_str()
        .map(str::to_string))
}

async fn has_treekem(sim: &Sim, group: &str) -> Result<bool> {
    Ok(sim
        .state("J")?
        .treekem_groups
        .read()
        .await
        .contains_key(group))
}

/// `label`'s live TreeKEM epoch for `group`, or `None` with no live group.
async fn epoch(sim: &Sim, label: &str, group: &str) -> Result<Option<u64>> {
    let live = sim
        .state(label)?
        .treekem_groups
        .read()
        .await
        .get(group)
        .cloned();
    Ok(match live {
        Some(live) => Some(live.lock().await.epoch()),
        None => None,
    })
}

/// A encrypts [`PROBE`] at its current epoch and J tries to decrypt it.
/// Returns whether J recovered the probe, with the replies.
async fn j_reads_new_message(sim: &Sim, group: &str) -> Result<(bool, String)> {
    let (status, body) = sim
        .api(
            "A",
            Method::POST,
            &format!("/groups/{group}/secure/encrypt"),
            Some(json!({"payload_b64": BASE64.encode(PROBE)})),
        )
        .await?;
    let Some(ciphertext) = body["ciphertext_b64"]
        .as_str()
        .filter(|_| status.is_success())
    else {
        return Ok((false, format!("A encrypt: {status} {body}")));
    };
    let (status, body) = sim
        .api(
            "J",
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
    Ok((ok, format!("J decrypt: {status} {body}")))
}

/// The state of `agent`'s row in `label`'s roster, or `None` with no row.
/// A banned member stays in the `members` array with `state: "banned"`.
async fn row_state(sim: &Sim, label: &str, group: &str, agent: &str) -> Result<Option<String>> {
    let (status, info) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(status.is_success(), "{label} GET /groups/{group}: {status}");
    Ok(info["members"]
        .as_array()
        .context("no members array")?
        .iter()
        .find(|m| m["agent_id"].as_str() == Some(agent))
        .and_then(|m| m["state"].as_str())
        .map(str::to_string))
}

/// A's count of `MemberJoined` events refused because the joiner is
/// banned (#1149).
fn banned_refusals(sim: &Sim, group: &str) -> Result<u64> {
    Ok(sim
        .state("A")?
        .groups_diagnostics
        .member_joined_rejected_banned(group))
}

/// True when `label`'s roster holds `agent` in the `active` state.
async fn listed(sim: &Sim, label: &str, group: &str, agent: &str) -> Result<bool> {
    Ok(row_state(sim, label, group, agent).await?.as_deref() == Some("active"))
}

/// Returns true when J's end state is the fixed one.
async fn scenario(sim: &Sim, receipt: &mut Receipt, variant: Variant) -> Result<bool> {
    let name = variant.name();
    mesh(sim, &["A", "J"]).await?;
    let group = create_group(sim, "A", variant.preset()).await?;
    let block = AwayFromJ::install(sim)?;
    let j = sim.agent_hex("J")?;
    receipt.setup_done(at(sim));

    // 1–2: A admits J; J observes nothing and times out with no row.
    block.set(true);
    let first = invite(sim, "A", &group).await?;
    join(sim, "J", &first).await?;
    sim.until(
        &format!("{name}: A seats J while J receives nothing"),
        secs(180),
        async |s| listed(s, "A", &group, &j).await.unwrap_or(false),
    )
    .await?;
    if matches!(variant, Variant::TreeKem) {
        sim.until(
            &format!("{name}: A holds J's KeyPackage"),
            secs(60),
            async |s: &Sim| {
                let Ok(state) = s.state("A") else {
                    return false;
                };
                crate::server::routes::named_groups::holds_member_key_package_for_removal(
                    &state, &group, &j,
                )
                .await
            },
        )
        .await?;
    }
    sim.until(
        &format!("{name}: J's no-carry poll records timed_out"),
        variant.first_poll_budget(),
        async |s| join_outcome(s, &group).await.ok().flatten().as_deref() == Some("timed_out"),
    )
    .await?;
    let no_row = membership(sim, "J", &group).await?;
    let keyless = !has_treekem(sim, &group).await?;
    receipt.evidence(
        &format!("{name}: A seated J and J's first join left no local row and no keys"),
        listed(sim, "A", &group, &j).await? && no_row.is_none() && keyless,
        format!("membership={no_row:?} dropped={}", block.dropped()),
        at(sim),
    );

    // 3: the stale invite. Its signed base seats J.
    let stale = invite(sim, "A", &group).await?;
    receipt.evidence(
        &format!("{name}: A minted the second invite while its roster seats J"),
        listed(sim, "A", &group, &j).await?,
        "invite minted before the ban".to_string(),
        at(sim),
    );

    // 4: A bans J. J does not observe it.
    let dropped_before_ban = block.dropped();
    let (ban_status, ban_body) = sim
        .api("A", Method::POST, &format!("/groups/{group}/ban/{j}"), None)
        .await?;
    ensure!(
        ban_status.is_success(),
        "{name}: A bans J: {ban_status} {ban_body}"
    );
    sim.until(
        &format!("{name}: A's roster no longer seats J"),
        secs(30),
        async |s| listed(s, "A", &group, &j).await.ok() == Some(false),
    )
    .await?;
    let j_unaware = membership(sim, "J", &group).await?.is_none();
    let ban_epoch = epoch(sim, "A", &group).await?;
    receipt.evidence(
        &format!("{name}: A banned J and J has observed neither the seat nor the ban"),
        !listed(sim, "A", &group, &j).await? && j_unaware,
        format!(
            "ban={ban_status} dropped_before={dropped_before_ban} dropped_now={}",
            block.dropped()
        ),
        at(sim),
    );

    // 5: J redeems the stale invite.
    let (redeem_status, redeem_body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": stale, "display_name": "J"})),
        )
        .await?;
    let redeem_state = membership(sim, "J", &group).await?;
    let a_seats_j = listed(sim, "A", &group, &j).await?;
    receipt.request_delivered(
        &format!("{name}: J's daemon processed the stale-invite redeem"),
        !redeem_status.is_server_error() && redeem_body.is_object(),
        format!("status={redeem_status} body={redeem_body}"),
        at(sim),
    );
    // J's local report from the invite base. A note only (see the module
    // doc): this row checks the authority, not J's local view.
    let reported_active = redeem_body["join_state"].as_str() == Some("active")
        || redeem_state.as_deref() == Some("active");
    // A received J's `MemberJoined` and its ban check refused it. On main
    // there is no ban check, so the counter stays at 0 and this wait ends
    // at its bound; that is a RED input, not an infra error.
    let refused_counted = sim
        .until(
            &format!("{name}: A's ban check refuses J's MemberJoined"),
            secs(60),
            async |s| banned_refusals(s, &group).unwrap_or(0) > 0,
        )
        .await
        .is_ok();
    let refusals = banned_refusals(sim, &group)?;
    receipt.evidence(
        &format!("{name}: A refused J's MemberJoined from the stale invite as banned"),
        refused_counted,
        format!("member_joined_rejected_banned={refusals}"),
        at(sim),
    );

    // 6: lift the drop so A's answer and any Welcome can reach J.
    block.set(false);
    sim.within(&format!("{name}: settle"), SETTLE + secs(10), async {
        tokio::time::sleep(SETTLE).await;
    })
    .await?;
    let end_state = membership(sim, "J", &group).await?;
    let end_keyed = has_treekem(sim, &group).await?;
    let end_outcome = join_outcome(sim, &group).await?;
    let end_a_row = row_state(sim, "A", &group, &j).await?;
    // TreeKEM only: does J hold A's current epoch and read a message
    // that A encrypts after the ban?
    let (a_epoch, j_epoch, j_reads, read_detail) = if matches!(variant, Variant::TreeKem) {
        let (j_reads, detail) = j_reads_new_message(sim, &group).await?;
        (
            epoch(sim, "A", &group).await?,
            epoch(sim, "J", &group).await?,
            j_reads,
            detail,
        )
    } else {
        (None, None, false, "no group secret".to_string())
    };
    let fixed = refused_counted && end_a_row.as_deref() == Some("banned") && !end_keyed && !j_reads;
    if !fixed {
        receipt.cause(
            CAUSE,
            Some(format!(
                "{name}: A's row for J={end_a_row:?} J keyed={end_keyed} J reads={j_reads} \
                 A ban refusals={refusals}"
            )),
            true,
            at(sim),
        );
    }
    receipt.note(format!(
        "{name}: redeem join_state={} membership={redeem_state:?} \
         reported_active={reported_active} a_seats_j={a_seats_j}; after {}s \
         membership={end_state:?} keyed={end_keyed} outcome={end_outcome:?} \
         a_row={end_a_row:?} fixed={fixed}",
        redeem_body["join_state"],
        SETTLE.as_secs()
    ));
    receipt.note(format!(
        "{name}: A epoch at ban={ban_epoch:?} now={a_epoch:?}; J epoch={j_epoch:?}; \
         J reads A's post-ban message={j_reads} ({read_detail})"
    ));
    Ok(fixed)
}

async fn run(variant: Variant) -> Receipt {
    let mut receipt = Receipt::new(variant.case(), variant.seed());
    let mut fixed = false;
    match Sim::start(variant.case(), variant.seed(), &["A", "J"]).await {
        Ok(sim) => {
            match scenario(&sim, &mut receipt, variant).await {
                Ok(done) => fixed = done,
                Err(error) => {
                    receipt.infra(
                        format!("{}: {error:#}", variant.name()),
                        sim.fabric().now().as_micros(),
                    );
                }
            }
            if let Err(error) = sim.finish().await {
                fixed = false;
                receipt.infra(format!("{} finish: {error:#}", variant.name()), 0);
            }
        }
        Err(error) => {
            receipt.infra(format!("{} sim: {error:#}", variant.name()), 0);
        }
    }
    if receipt.verdict().is_none() {
        receipt.finish(FINAL, fixed && !receipt.has_infra(), 0);
    }
    if receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

fn expect_green(variant: Variant) -> Result<()> {
    super::block_on_paused(async move {
        let receipt = run(variant).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{}: expected GREEN, got {:?} (RED: A re-admits banned J)",
            variant.case(),
            receipt.verdict()
        );
        Ok(())
    })
}

/// #1149, TreeKEM: a banned agent is not admitted again by an invite that
/// A minted before the ban, and it gets no TreeKEM keys.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1149_treekem_banned_agent_not_readmitted_by_pre_ban_invite() -> Result<()> {
    expect_green(Variant::TreeKem)
}

/// #1149, SignedPublic: a banned agent is not seated again by an invite
/// that A minted before the ban.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1149_signed_public_banned_agent_not_readmitted_by_pre_ban_invite() -> Result<()> {
    expect_green(Variant::SignedPublic)
}
