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
//! 4. Desired (ADR 0112): by T, measured from J's join call, B seats J,
//!    J is `active` (TreeKEM: J installed the group) and J decrypts B's
//!    next group message. J sends no Direct-lane frame to A after A stops
//!    (written, or refused with bytes; any kind, so an encrypted V5
//!    envelope also fails). PubSub `member_joined` frames toward A and
//!    lane-less dials are noted only. A roster seat alone does not pass.
//!
//! Main: a receiver other than the inviter keeps J's `MemberJoined` as
//! recovery evidence and does not redeem it. J's attempt waits for a result
//! from inviter A only, and A is offline. So B never seats J, and J's
//! attempt ends `timed_out` with no usable membership. The case records
//! each cause only when it observes it.
//!
//! The row is red on main and the test asserts RED with both causes. It
//! carries the #1559 Linux ignore like the other red rows; CI runs it in the
//! W3-H gate (`--expect ...=RED`).
//!
//! The S6 code slice (after David accepts ADR 0112) must:
//! - mint an explicit V5 invite (V4 stays pinned to its issuer);
//! - add the "one consumption" check (it needs S6's consumption root);
//! - add the OwnerCertified variant with owner-key device O (A holds the
//!   owner's USER key at mint; stop A and O before redemption). This slice
//!   covers the ordinary variant only;
//! - add the ADR's t=1 step, "deliver current signed adverts for B and all
//!   needed authorized evidence", as an explicit delivery barrier. This
//!   slice leaves B's advert to normal gossip during setup;
//! - switch `request_delivered` to the V5 redemption envelope. This slice
//!   identifies main's request by lane and kind: a Direct frame whose JSON
//!   body is J's `member_joined` event, or a PubSub frame that carries it.
//!   S6 sends an encrypted point-to-point envelope, which this match does
//!   not see, so without the switch the fixed run scores INFRA;
//! - flip the assertion and the CI pins to GREEN.

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
    "J's attempt waits for offline inviter A and ends timed_out with no usable membership";

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

/// Whether `label` installed a TreeKEM group under its local key for
/// `group`.
async fn has_treekem(sim: &Sim, label: &str, group: &str) -> Result<bool> {
    let state = sim.state(label)?;
    let group = group.to_string();
    sim.at_instant(&format!("read {label}'s TreeKEM group"), async move {
        let key = {
            let groups = state.named_groups.read().await;
            crate::server::resolve_group_entry_locked(&groups, &group)
                .map(|(key, _)| key.to_string())
        };
        let Some(key) = key else {
            return false;
        };
        let keyed = state.treekem_groups.read().await.contains_key(&key);
        keyed
    })
    .await
}

/// The agent id of the inviter key that J's pending attempt for `group`
/// pins (the key its join result must verify under).
fn pinned_inviter(sim: &Sim, group: &str) -> Result<Option<String>> {
    let state = sim.state("J")?;
    let attempts = state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key_b64 = attempts
        .values()
        .find(|attempt| {
            attempt.local_group_key == group || attempt.invite_group_id.eq_ignore_ascii_case(group)
        })
        .map(|attempt| attempt.inviter_public_key_b64.clone());
    drop(attempts);
    let Some(key_b64) = key_b64 else {
        return Ok(None);
    };
    let bytes = BASE64
        .decode(key_b64)
        .context("pinned inviter key base64")?;
    let key = ant_quic::MlDsaPublicKey::from_bytes(&bytes)
        .map_err(|error| anyhow!("pinned inviter key: {error:?}"))?;
    Ok(Some(hex::encode(
        crate::identity::AgentId::from_public_key(&key).as_bytes(),
    )))
}

/// J's `last_join_outcome` for `group` (`join-status` answers it even on
/// a 404). A failed request is an error.
async fn join_outcome(sim: &Sim, group: &str) -> Result<Option<String>> {
    let (_, body) = sim
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

/// The lane and kind of a frame from J that is J's join message for
/// `group`, as `case_1023`'s `join_message_kind` matches it. A Direct
/// frame (`[stream type][sender agent id (32)][JSON]`) whose body names J
/// as `member_agent_id` and is J's `member_joined` event or its JoinResult
/// `fetch_request`. A PubSub frame that carries J's `member_joined` event.
/// The frame must carry `"group_id":"<group>"`. `None` for any other frame.
fn request_kind(class: LaneClass, bytes: &[u8], j: &str, group: &str) -> Option<&'static str> {
    match class {
        LaneClass::Direct => {
            let body = serde_json::from_slice::<serde_json::Value>(bytes.get(33..)?).ok()?;
            let joiner = body["member_agent_id"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(j));
            let in_group = body["group_id"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(group));
            if !joiner || !in_group {
                None
            } else if body["event"] == "member_joined" {
                Some("direct member_joined")
            } else if body["type"] == "fetch_request" {
                Some("direct fetch_request")
            } else {
                None
            }
        }
        LaneClass::PubSub => {
            let text = String::from_utf8_lossy(bytes);
            let in_group = text.contains(&format!("\"group_id\":\"{group}\""));
            (text.contains("\"member_joined\"") && text.contains(j) && in_group)
                .then_some("pubsub member_joined")
        }
        _ => None,
    }
}

/// J holds usable membership: B seats J, J reports `active`, and on the
/// TreeKEM plane J installed the group.
/// A failed read is an error.
async fn usable(sim: &Sim, plane: Plane, group: &str, j: &str) -> Result<bool> {
    let seated = matches!(seat(sim, "B", group, j).await?, Some((_, true, _)));
    let active = local_membership(sim, "J", group).await.as_deref() == Some("active");
    let keyed = match plane {
        Plane::TreeKem => has_treekem(sim, "J", group).await?,
        Plane::Gss => true,
    };
    Ok(seated && active && keyed)
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
    let what = "B is admin at A's head";
    let mut seen = Observations::default();
    let settled = wait_for(sim, what, SETUP, async |s: &Sim| {
        let (Some(a_view), Some(b_view)) = (
            seen.observe(seat(s, "A", &group, &b)).await,
            seen.observe(seat(s, "B", &group, &b)).await,
        ) else {
            return true;
        };
        match (a_view, b_view) {
            (Some((rev_a, _, _)), Some((rev_b, true, Some(GroupRole::Admin)))) => rev_a == rev_b,
            _ => false,
        }
    })
    .await?;
    seen.verify(what)?;
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
    let offline = sim.fabric().mark_indexed("t1: A stops");
    sim.stop("A", RestartMode::Crash).await?;
    let a_online = sim.fabric().is_online(&sim.peer("A")?);
    receipt.evidence(
        "A is stopped before J's join; B is the only reachable admin",
        a_online == Some(false),
        format!("crash stop; fabric online {a_online:?}"),
        at(sim),
    );

    // t=2: J joins with B as the only reachable admin.
    let position = sim.fabric().mark_indexed("t2: J joins with A stopped");
    let join_at = sim.fabric().now();
    let (status, body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "J"})),
        )
        .await?;
    receipt.note(format!("J join: {status} {body}"));
    let pinned = pinned_inviter(sim, &group)?;
    receipt.note(format!("J's attempt pins inviter {pinned:?}"));
    let window = plane.window();

    // By T: J is usable and decrypts B's next message. The checks repeat
    // until they pass or T (from before J's join call) runs out; `elapsed`
    // is taken when this wait ends.
    let what = "J is usable and decrypts B's message by T";
    let mut seen = Observations::default();
    let mut decrypt_detail = "J was never usable, so no decrypt was tried".to_string();
    let remaining = window.saturating_sub(sim.fabric().now().saturating_sub(join_at));
    let passed = wait_for(sim, what, remaining, async |s: &Sim| {
        let Some(ready) = seen.observe(usable(s, plane, &group, &j)).await else {
            return true;
        };
        if !ready {
            return false;
        }
        match seen.observe(j_decrypts_b(s, &group)).await {
            Some((decrypted, detail)) => {
                decrypt_detail = detail;
                decrypted
            }
            None => true,
        }
    })
    .await?;
    seen.verify(what)?;
    let elapsed = sim.fabric().now().saturating_sub(join_at);
    let in_time = passed && elapsed <= window;

    // Not passed: give J's attempt the margin to record its outcome.
    let mut outcome = None;
    if !passed {
        let what = "J's attempt records an outcome";
        let mut seen = Observations::default();
        wait_for(sim, what, MARGIN, async |s: &Sim| {
            match seen.observe(join_outcome(s, &group)).await {
                Some(found) => {
                    let ended = found.is_some();
                    outcome = found;
                    ended
                }
                None => true,
            }
        })
        .await?;
        seen.verify(what)?;
        let (_, detail) = j_decrypts_b(sim, &group).await?;
        decrypt_detail = detail;
    }
    receipt.note(format!(
        "usable-and-decrypt wait {} {} ms after the join (T {} s); outcome wait \
         ended at {} us",
        if passed { "passed" } else { "ran out" },
        elapsed.as_millis(),
        window.as_secs(),
        at(sim)
    ));

    // The request, by lane and kind (`request_kind`): J's MemberJoined
    // reached B after J's join mark. The S6 slice switches this stage.
    let mut by_kind = std::collections::BTreeMap::<&str, usize>::new();
    for (write, _) in
        sim.fabric()
            .delivered_writes_after(&sim.peer("J")?, &sim.peer("B")?, position)
    {
        if let Some(kind) = request_kind(write.lane.class, &write.bytes, &j, &group) {
            *by_kind.entry(kind).or_default() += 1;
        }
    }
    // Only `member_joined` kinds count: the stage and the cause name J's
    // MemberJoined. `fetch_request` frames are in the detail only.
    let requests: usize = by_kind
        .iter()
        .filter(|(kind, _)| kind.ends_with("member_joined"))
        .map(|(_, count)| count)
        .sum();
    receipt.request_delivered(
        "J's MemberJoined reached B after J's join",
        requests > 0,
        format!("J-to-B join frames delivered, by lane and kind: {by_kind:?}"),
        at(sim),
    );

    // ADR 0112 "no traffic to A", counted by trace position from A's stop
    // mark. The pass fails closed on ANY Direct-lane frame from J to A: a
    // frame J wrote to A in any fate, or a refused Direct send that carried
    // bytes. It does not use `request_kind`, so an encrypted V5 envelope to
    // A also fails. PubSub `member_joined` frames toward A and lane-less
    // dials are notes only (see the FOR ENGINEER line in the PR).
    let a_peer = sim.peer("A")?;
    let j_peer = sim.peer("J")?;
    let written: Vec<_> = sim
        .fabric()
        .writes_from_between(&j_peer, offline..usize::MAX)
        .into_iter()
        .filter(|write| write.lane.dst == a_peer.0)
        .collect();
    let direct_written = written
        .iter()
        .filter(|write| write.lane.class == LaneClass::Direct)
        .count();
    let gossip_written = written
        .iter()
        .filter(|write| {
            request_kind(write.lane.class, &write.bytes, &j, &group) == Some("pubsub member_joined")
        })
        .count();
    let refused: Vec<_> = sim
        .fabric()
        .refused_from(&j_peer, offline)
        .into_iter()
        .filter(|refusal| refusal.dst == a_peer.0)
        .collect();
    let direct_refused = refused
        .iter()
        .filter(|refusal| refusal.class == Some(LaneClass::Direct) && refusal.bytes.is_some())
        .count();
    let gossip_refused = refused
        .iter()
        .filter(|refusal| match (refusal.class, refusal.bytes.as_deref()) {
            (Some(class), Some(bytes)) => {
                request_kind(class, bytes, &j, &group) == Some("pubsub member_joined")
            }
            _ => false,
        })
        .count();
    let mut refused_by_class = std::collections::BTreeMap::<String, usize>::new();
    for refusal in &refused {
        let class = refusal.class.map_or_else(
            || "no lane (dial or link)".to_string(),
            |class| format!("{class:?}"),
        );
        *refused_by_class.entry(class).or_default() += 1;
    }
    let delivered_to_a = sim
        .fabric()
        .delivered_writes_after(&j_peer, &a_peer, offline)
        .len();
    let direct_to_a = direct_written + direct_refused;
    receipt.note(format!(
        "J to A after A stopped: {direct_to_a} Direct frames (pass gate; \
         {direct_written} written, {direct_refused} refused with bytes); notes: \
         {gossip_written} written and {gossip_refused} refused PubSub member_joined \
         frames, refused by class {refused_by_class:?}, {delivered_to_a} frames delivered"
    ));

    let b_seat = seat(sim, "B", &group, &j).await?;
    let j_state = local_membership(sim, "J", &group).await;
    let j_keyed = has_treekem(sim, "J", &group).await?;
    let detail = format!(
        "B seat for J {b_seat:?}; J membership {j_state:?}, treekem {j_keyed}, \
         last outcome {outcome:?}; pinned inviter {pinned:?}; {decrypt_detail}; \
         wait ended {} ms after the join",
        elapsed.as_millis()
    );
    receipt.note(detail.clone());
    let b_seated = matches!(b_seat, Some((_, true, _)));
    if !b_seated && requests > 0 {
        receipt.cause(CAUSE_NOT_REDEEMED, Some(detail.clone()), true, at(sim));
    }
    let pinned_to_a = pinned
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(&a));
    if pinned_to_a && !passed && outcome.as_deref() == Some("timed_out") {
        receipt.cause(CAUSE_PINNED, Some(detail), true, at(sim));
    }
    receipt.finish(FINAL, in_time && direct_to_a == 0, at(sim));
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
    // Main baseline. The S6 code slice flips this, and the CI pins, to GREEN.
    ensure!(
        receipt.verdict() == Some(Verdict::Red)
            && receipt.named_causes() == [CAUSE_NOT_REDEEMED, CAUSE_PINNED],
        "{case}: expected RED with both main causes, got {:?} {:?}",
        receipt.verdict(),
        receipt.named_causes()
    );
    Ok(())
}

/// ADR 0112 `s6_offline_inviter_other_admin_admits`, TreeKEM plane: RED on
/// `main` (asserted here), GREEN with S6.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
#[cfg_attr(
    target_os = "linux",
    ignore = "#1559: needs the W3-H entropy shim (nextest profile w3h / w3h-gate \
              --run-ignored all); plain suites run unseeded entropy, which is not an \
              observation"
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
/// `main` (asserted here), GREEN with S6.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
#[cfg_attr(
    target_os = "linux",
    ignore = "#1559: needs the W3-H entropy shim (nextest profile w3h / w3h-gate \
              --run-ignored all); plain suites run unseeded entropy, which is not an \
              observation"
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
