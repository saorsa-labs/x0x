//! W3-H case for #1359 (ADR 0112 S6, `s6_offline_inviter_other_admin_admits`).
//!
//! Harness first (D16/D54/D181): ADR 0112 is Proposed, so this file adds
//! the red row only. There is no production change.
//!
//! Nodes: B (admin, node 0), A (owner and inviter), J (joiner). B is node 0,
//! so J's bootstrap link goes to B. Public HTTP only.
//!
//! 1. t=0: A creates the group, seats B and promotes B to admin through the
//!    role API. A and B settle on one head. A mints J's addressed invite
//!    through `POST /groups/:id/invite` (the current default V4 invite; the
//!    ADR's red receipt mints V4, and the fixed run mints V5).
//! 2. t=1: A crashes. A holds the only issued-invite record.
//! 3. t=2: J calls `POST /groups/join`. B is the only reachable admin.
//!    The case waits for the shipped join-result window `T` (120 s TreeKEM,
//!    600 s GSS; D102) plus margin.
//! 4. Desired (ADR 0112): B seats J, J is `active` (TreeKEM: J installed
//!    the group) and J decrypts B's next group message. A roster seat
//!    alone does not pass.
//!
//! Main: a receiver other than the inviter keeps J's `MemberJoined` as
//! recovery evidence and does not redeem it, and J pins the join result to
//! the inviter (`validate_join_result_inviter`). So B never seats J, and
//! J's attempt ends with no usable membership. The causes record both.

#![cfg(test)]

use super::control::{local_membership, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::invite::SignedInvite;
use crate::groups::GroupRole;
use crate::network::sim::LaneClass;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const PROBE: &[u8] = b"w3h-1359 probe";
const SETUP: Duration = Duration::from_secs(180);
/// After the join-result window, the time the attempt has to record its
/// outcome.
const MARGIN: Duration = Duration::from_secs(60);
const FINAL: &str = "j_usable_member_via_b_with_inviter_a_offline";
const CAUSE_NOT_REDEEMED: &str =
    "B received J's MemberJoined and did not seat J (only the inviter redeems)";
const CAUSE_PINNED: &str =
    "J's join result is pinned to inviter A, and J has no usable membership by T";

#[derive(Clone, Copy)]
enum Plane {
    /// `private_secure`: TreeKEM, 120 s join-result poll.
    TreeKem,
    /// `public_request_secure`: GSS, 600 s join-result poll.
    Gss,
}

impl Plane {
    fn preset(self) -> &'static str {
        match self {
            Self::TreeKem => "private_secure",
            Self::Gss => "public_request_secure",
        }
    }

    /// `T` (D102): `JOIN_RESULT_POLL_TIMEOUT` or
    /// `NON_TREEKEM_JOIN_RESULT_POLL_TIMEOUT`.
    fn window(self) -> Duration {
        match self {
            Self::TreeKem => Duration::from_secs(120),
            Self::Gss => Duration::from_secs(600),
        }
    }
}

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

/// `label`'s view of `group`: (state revision, `agent` is active,
/// `agent`'s role).
async fn seat(
    sim: &Sim,
    label: &str,
    group: &str,
    agent: &str,
) -> Result<Option<(u64, bool, Option<GroupRole>)>> {
    let state = sim.state(label)?;
    let (group, agent) = (group.to_string(), agent.to_string());
    sim.at_instant(&format!("read {label}'s seat for {agent}"), async move {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &group).map(|(_, info)| {
            let row = info.members_v2.get(&agent);
            (
                info.state_revision,
                row.is_some_and(|m| m.is_active()),
                row.map(|m| m.role),
            )
        })
    })
    .await
}

async fn has_treekem(sim: &Sim, label: &str, group: &str) -> Result<bool> {
    Ok(sim
        .state(label)?
        .treekem_groups
        .read()
        .await
        .contains_key(group))
}

async fn join_outcome(sim: &Sim, group: &str) -> Option<String> {
    let (_, body) = sim
        .request(
            "J",
            Method::GET,
            &format!("/groups/{group}/join-status"),
            None,
        )
        .await
        .ok()?;
    body["last_join_outcome"]["outcome"]
        .as_str()
        .map(str::to_string)
}

/// J holds usable membership: B seats J, J reports `active`, and on the
/// TreeKEM plane J installed the group.
async fn usable(sim: &Sim, plane: Plane, group: &str, j: &str) -> bool {
    let seated = matches!(seat(sim, "B", group, j).await, Ok(Some((_, true, _))));
    let active = local_membership(sim, "J", group).await.as_deref() == Some("active");
    let keyed = match plane {
        Plane::TreeKem => has_treekem(sim, "J", group).await.unwrap_or(false),
        Plane::Gss => true,
    };
    seated && active && keyed
}

/// B encrypts the probe; whether J recovers it.
async fn j_decrypts_b(sim: &Sim, group: &str) -> Result<(bool, String)> {
    let (status, cipher) = sim
        .api(
            "B",
            Method::POST,
            &format!("/groups/{group}/secure/encrypt"),
            Some(json!({"payload_b64": BASE64.encode(PROBE)})),
        )
        .await?;
    if !status.is_success() {
        return Ok((false, format!("B encrypt: {status} {cipher}")));
    }
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            &format!("/groups/{group}/secure/decrypt"),
            Some(json!({
                "ciphertext_b64": cipher["ciphertext_b64"],
                "nonce_b64": cipher["nonce_b64"],
                "secret_epoch": cipher["secret_epoch"],
            })),
        )
        .await?;
    let ok = status.is_success()
        && body["payload_b64"]
            .as_str()
            .and_then(|payload| BASE64.decode(payload).ok())
            .is_some_and(|payload| payload == PROBE);
    Ok((ok, format!("J decrypt: {status} {body}")))
}

async fn wait_for(
    sim: &Sim,
    what: &str,
    budget: Duration,
    check: impl AsyncFnMut(&Sim) -> bool,
) -> Result<bool> {
    match sim.until(what, budget, check).await {
        Ok(()) => Ok(true),
        Err(error) if expired(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// A creates the group, seats B and promotes B to admin; both settle on
/// one head. Returns the group id.
async fn setup(sim: &Sim, plane: Plane, receipt: &mut Receipt) -> Result<String> {
    mesh(sim, &["B", "A", "J"]).await?;
    let (status, created) = sim
        .api(
            "A",
            Method::POST,
            "/groups",
            Some(json!({"name": "w3h 1359", "display_name": "A", "preset": plane.preset()})),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    let group = created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string();
    let b = sim.agent_hex("B")?;
    let link = mint(sim, &group, None).await?;
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "B"})),
        )
        .await?;
    ensure!(status.is_success(), "B join: {status} {body}");
    sim.until("A seats B", SETUP, async |s: &Sim| {
        members(s, "A", &group).await.is_ok_and(|m| m.contains(&b))
            && local_membership(s, "B", &group).await.as_deref() == Some("active")
    })
    .await?;
    let (status, body) = sim
        .api(
            "A",
            Method::PATCH,
            &format!("/groups/{group}/members/{b}/role"),
            Some(json!({"role": "admin"})),
        )
        .await?;
    ensure!(status.is_success(), "promote B: {status} {body}");
    let settled = wait_for(sim, "B is admin at A's head", SETUP, async |s: &Sim| {
        let (Ok(Some((rev_a, _, _))), Ok(Some((rev_b, true, Some(GroupRole::Admin))))) = (
            seat(s, "A", &group, &b).await,
            seat(s, "B", &group, &b).await,
        ) else {
            return false;
        };
        rev_a == rev_b
    })
    .await?;
    let (a_view, b_view) = (
        seat(sim, "A", &group, &b).await?,
        seat(sim, "B", &group, &b).await?,
    );
    receipt.evidence(
        "B holds an active admin seat at A's head before the mint",
        settled,
        format!("A view {a_view:?}, B view {b_view:?}"),
        at(sim),
    );
    Ok(group)
}

/// `POST /groups/:id/invite` at A, addressed to `joiner` when given.
async fn mint(sim: &Sim, group: &str, joiner: Option<&str>) -> Result<String> {
    let body = joiner.map_or_else(|| json!({}), |id| json!({"intended_joiner": id}));
    let (status, invite) = sim
        .api(
            "A",
            Method::POST,
            &format!("/groups/{group}/invite"),
            Some(body),
        )
        .await?;
    ensure!(status.is_success(), "invite: {status} {invite}");
    Ok(invite["invite_link"]
        .as_str()
        .context("invite response has no invite_link")?
        .to_string())
}

async fn scenario(sim: &mut Sim, plane: Plane, receipt: &mut Receipt) -> Result<()> {
    let group = setup(sim, plane, receipt).await?;
    let (a, j) = (sim.agent_hex("A")?, sim.agent_hex("J")?);
    let link = mint(sim, &group, Some(&j)).await?;
    let signed = SignedInvite::from_link(&link).map_err(|error| anyhow!("decode: {error}"))?;
    receipt.evidence(
        "A minted J's addressed invite; A is its inviter",
        signed.inviter.eq_ignore_ascii_case(&a),
        format!("inviter {}", signed.inviter),
        at(sim),
    );
    receipt.setup_done(at(sim));

    // t=1: A, the inviter and only issued-invite holder, stops.
    sim.stop("A", RestartMode::Crash).await?;
    receipt.evidence(
        "A is stopped before J's join; B is the only reachable admin",
        true,
        "crash stop",
        at(sim),
    );

    // t=2: J joins with B as the only reachable admin.
    let position = sim.fabric().mark_indexed("t2: J joins with A stopped");
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "J"})),
        )
        .await?;
    receipt.note(format!("J join: {status} {body}"));
    let window = plane.window();
    let budget = window + MARGIN;
    let reached = wait_for(
        sim,
        "J reaches usable membership or its attempt ends",
        budget,
        async |s: &Sim| {
            usable(s, plane, &group, &j).await || join_outcome(s, &group).await.is_some()
        },
    )
    .await?;
    receipt.note(format!(
        "wait ended {} at {} us (T {} s + {} s margin)",
        if reached {
            "on a result"
        } else {
            "at the budget"
        },
        at(sim),
        window.as_secs(),
        MARGIN.as_secs()
    ));

    // The request: J's MemberJoined for this group reached B after the join.
    let requests = sim
        .fabric()
        .delivered_writes_after(&sim.peer("J")?, &sim.peer("B")?, position)
        .into_iter()
        .filter(|(write, _)| matches!(write.lane.class, LaneClass::PubSub | LaneClass::Direct))
        .filter(|(write, _)| {
            let text = String::from_utf8_lossy(&write.bytes);
            text.contains("\"member_joined\"") && text.contains(&j)
        })
        .count();
    receipt.request_delivered(
        "J's MemberJoined reached B after A stopped",
        requests > 0,
        format!("{requests} matching J-to-B frames delivered"),
        at(sim),
    );

    let usable_now = usable(sim, plane, &group, &j).await;
    let b_seat = seat(sim, "B", &group, &j).await?;
    let j_state = local_membership(sim, "J", &group).await;
    let j_keyed = has_treekem(sim, "J", &group).await?;
    let outcome = join_outcome(sim, &group).await;
    let (decrypted, decrypt_detail) = j_decrypts_b(sim, &group).await?;
    let detail = format!(
        "B seat for J {b_seat:?}; J membership {j_state:?}, treekem {j_keyed}, \
         last outcome {outcome:?}; {decrypt_detail}"
    );
    receipt.note(detail.clone());
    let b_seated = matches!(b_seat, Some((_, true, _)));
    if !b_seated && requests > 0 {
        receipt.cause(CAUSE_NOT_REDEEMED, Some(detail.clone()), true, at(sim));
    }
    if !usable_now && !decrypted && signed.inviter.eq_ignore_ascii_case(&a) {
        receipt.cause(CAUSE_PINNED, Some(detail), true, at(sim));
    }
    receipt.finish(FINAL, usable_now && decrypted, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, plane: Plane) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    match Sim::start(case, seed, &["B", "A", "J"]).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, plane, &mut receipt).await {
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

async fn expect(case: &str, seed: u64, plane: Plane) -> Result<()> {
    let receipt = run(case, seed, plane).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected GREEN (ADR 0112 S6), got {:?}; RED is the main baseline: {:?}",
        receipt.verdict(),
        receipt.named_causes()
    );
    Ok(())
}

/// ADR 0112 `s6_offline_inviter_other_admin_admits`, TreeKEM plane: RED on
/// `main`, GREEN with S6.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1359_red_s6_offline_inviter_other_admin_admits_treekem() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1359_red_s6_offline_inviter_other_admin_admits_treekem",
            0x1359_0001,
            Plane::TreeKem,
        )
        .await
    })
}

/// ADR 0112 `s6_offline_inviter_other_admin_admits`, GSS plane: RED on
/// `main`, GREEN with S6.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1359_red_s6_offline_inviter_other_admin_admits_gss() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1359_red_s6_offline_inviter_other_admin_admits_gss",
            0x1359_0002,
            Plane::Gss,
        )
        .await
    })
}
