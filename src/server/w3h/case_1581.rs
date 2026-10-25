//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_ordinary_admin_revoked`, §4b(3) / D126): an ordinary group whose
//! verified Agent-subject revocations cover every Admin-or-higher Active
//! seat ends locally, with the typed refusal `group_admin_revoked`. With
//! this PR's seal-ordering fix the arms expect the ADR behaviour (GREEN);
//! on `main` the base arm is RED, because `POST /groups/:id/state/seal`
//! answered the caller's seat 403 before the §4 refusal. Each arm keeps
//! the row's red cause: with the §4 cover test (`revoked_admin_cover`)
//! neutralised, the assertions below observe replies that carry no typed
//! state, so the arms fail with that cause and guard the behaviour they
//! name (the neutralised run is the RED proof; see the PR body).
//!
//! A is the sole admin and B, C are members of an ordinary
//! `private_secure` (InviteOnly, TreeKEM) group created through the public
//! API. Before t = 0 the group is settled (every node at A's state
//! revision and TreeKEM epoch e0), a data-plane probe passes, and the case
//! waits out `S4Timing::restart_sync_wait` (ADR 0110 §2), so no read below
//! sits behind the boot head gate. The derived refusal needs the node's
//! own current head round, so a first read can still show the §4 409 wait
//! (`waiting_for_eligible_admin_revocation`, exit `group_admin_revoked`);
//! the arms poll to the definitive 410 and record every earlier phase.
//!
//! Arms:
//!
//! - `w3h_1581_s4_ordinary_admin_revoked` (the row's base run and its
//!   re-create variant). At t = 0 A revokes its own agent through
//!   `POST /identity/revoke`; the record reaches B and then C (the ADR
//!   names t = 100 ms and t = 1 s; delivery is the fabric default, and the
//!   case awaits the holders in that order). At t = 2 s B and C call the
//!   send, invite and seal APIs: each answers 410 `group_admin_revoked`
//!   naming A, with no key material in the body, and the status carries
//!   the re-create offer (members B and C, the group name, the policy).
//!   Local history stays readable, even A's own encrypt is refused, and
//!   after the completion bound no node's epoch has moved and none is
//!   quarantined, so no new key reached anyone. B then accepts the offer
//!   through the public create API: the re-created group has a new ID, B
//!   as its admin, C seated, and no history.
//!
//! Not covered by this case (named remainders of the row in #1581):
//! the D late-evidence variant and the joiner-J variant. The J variant
//! needs new production behaviour (ADR 0108's signed `JoinPendingNotice`
//! with cause `no_eligible_admin` is not served on the join-result poll
//! for this cause today). The D variant (B derives the refusal on a head
//! that lacks a promoted D, then clears when D's head lands) cannot be
//! built with fabric-level faults as the transport stands: pubsub frames
//! are anti-entropy frames that re-carry the retained topic state, so
//! every frame toward B names D once the promotion is retained, and a
//! fault that withholds the promotion withholds A's revocation record
//! with it (payload-dump evidence in the #1581 PR body). It needs a
//! per-message payload fault in the harness or direct-lane revocation
//! delivery in production. Receipts use `w3h.receipt/1`.

#![cfg(test)]

use super::control::{invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::S4Timing;
use anyhow::Context as _;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for the revocation record to reach its holders.
const EVIDENCE: Duration = Duration::from_secs(60);
/// How long after the refusals the case re-reads, so a late rekey (a
/// second epoch step) is seen: the completion bound plus margin.
const SETTLE: Duration = Duration::from_secs(30);
/// Budget for a node's head round to make the derived refusal definitive
/// (the round confirms through a holder, or concludes after the restart
/// sync wait).
const REFUSAL: Duration = Duration::from_secs(30);
const PROBE: &[u8] = b"w3h-1581 probe";
const GROUP_NAME: &str = "w3h-1581 ordinary";

const CAUSE_NO_STATE: &str = "no typed state: with A revoked, member sends, invites and seals \
                              still succeed (or answer another status), the status carries no \
                              re-create offer, and nothing clears a stale head";
const FINAL_BASE: &str = "sends_invite_seal_refuse_410_group_admin_revoked_with_recreate_offer";

/// A desired-behaviour observation: the bool is the ADR behaviour; the
/// string carries the observed reply for the receipt.
type Seen = (bool, String);

/// Record one desired-behaviour observation. A pass is evidence; a miss
/// records the row's main-cause (what `main` does with the §4 cover test
/// absent) and fails the arm. A harness error stays `Err` (INFRA).
fn record(receipt: &mut Receipt, name: &str, seen: &Seen, passed: &mut bool, at: u128) {
    if seen.0 {
        receipt.evidence(name, true, seen.1.clone(), at);
    } else {
        receipt.cause(CAUSE_NO_STATE, Some(seen.1.clone()), true, at);
        *passed = false;
    }
}

/// Whether the reply is the §4b(3) definitive refusal: 410, the typed
/// state, A named as the revoked admin, and no key material in the body.
fn is_group_admin_revoked(status: StatusCode, body: &serde_json::Value, a_hex: &str) -> bool {
    status == StatusCode::GONE
        && body["state"] == "group_admin_revoked"
        && body["error"] == "group_admin_revoked"
        && body["revoked_admins"].as_array().is_some_and(|ids| {
            ids.len() == 1
                && ids[0]
                    .as_str()
                    .is_some_and(|id| id.eq_ignore_ascii_case(a_hex))
        })
        && body["ciphertext_b64"].is_null()
        && body["kem_ciphertext_b64"].is_null()
}

/// One mutating request through a node's own barrier; the observation is
/// whether it answers the definitive §4b(3) refusal.
async fn refused(
    sim: &Sim,
    label: &str,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    a_hex: &str,
) -> Result<Seen> {
    let (status, reply) = sim.api(label, method, path, body).await?;
    Ok((
        is_group_admin_revoked(status, &reply, a_hex),
        format!("{label} {path}: {status} {reply}"),
    ))
}

/// Whether `label` can make group ciphertext (the member send path).
async fn sends(sim: &Sim, label: &str, group: &str) -> Result<Seen> {
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/secure/encrypt"),
            Some(json!({"payload_b64": BASE64.encode(PROBE)})),
        )
        .await?;
    Ok((
        status.is_success() && body["ciphertext_b64"].is_string(),
        format!("{label} encrypt: {status} {body}"),
    ))
}

/// Poll `label`'s member send until it answers the definitive refusal
/// (`budget` virtual time), recording each earlier reply shape once (the
/// §4 409 wait names the same exit). Uses only barrier-free reads.
async fn until_refused(
    sim: &Sim,
    label: &str,
    group: &str,
    a_hex: &str,
    budget: Duration,
) -> Result<(bool, Vec<String>)> {
    let mut phases: Vec<String> = Vec::new();
    let found = sim
        .until(
            &format!("{label} derives group_admin_revoked"),
            budget,
            async |s: &Sim| {
                let Ok((status, body)) = s
                    .request(
                        label,
                        Method::POST,
                        &format!("/groups/{group}/secure/encrypt"),
                        Some(json!({"payload_b64": BASE64.encode(PROBE)})),
                    )
                    .await
                else {
                    return false;
                };
                if is_group_admin_revoked(status, &body, a_hex) {
                    return true;
                }
                let phase = format!("{status} {body}");
                if !phases.contains(&phase) {
                    phases.push(phase);
                }
                false
            },
        )
        .await
        .is_ok();
    Ok((found, phases))
}

/// The stable group id `label` resolves for `group` (the history scope).
async fn stable_id(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("{label} has no record of {group}"))?;
    Ok(info.stable_group_id().to_string())
}

/// Whether `label`'s local history for the group stays readable (2xx), and
/// the page is empty when `expect_empty` (a re-created group carries no
/// history).
async fn history(sim: &Sim, label: &str, group: &str, expect_empty: bool) -> Result<Seen> {
    let scope = format!("group:{}", stable_id(sim, label, group).await?);
    let (status, body) = sim
        .api(label, Method::GET, &format!("/history?scope={scope}"), None)
        .await?;
    let ok = status.is_success() && body["ok"] == true && (!expect_empty || body["count"] == 0);
    Ok((
        ok,
        format!(
            "{label} GET /history?scope={scope}: {status} count={}",
            body["count"]
        ),
    ))
}

/// `label`'s (state revision, TreeKEM epoch, leaf count).
async fn head_of(sim: &Sim, label: &str, group: &str) -> Result<(u64, u64, u32)> {
    let state = sim.state(label)?;
    let (key, revision) = {
        let groups = state.named_groups.read().await;
        let (key, info) = crate::server::resolve_group_entry_locked(&groups, group)
            .with_context(|| format!("{label} has no record of {group}"))?;
        (key.to_string(), info.state_revision)
    };
    let live = state
        .treekem_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .with_context(|| format!("{label} has no live TreeKEM group for {group}"))?;
    let guard = live.lock().await;
    Ok((revision, guard.epoch(), guard.member_count()))
}

/// Whether every label sits at `head` with no fork-quarantine marker: the
/// group did not move (nothing sealed, nothing stranded).
async fn quiet_at(sim: &Sim, labels: &[&str], group: &str, head: (u64, u64, u32)) -> Result<Seen> {
    let mut lines = Vec::with_capacity(labels.len());
    let mut ok = true;
    for label in labels {
        let quarantined = {
            let state = sim.state(label)?;
            let groups = state.named_groups.read().await;
            crate::server::resolve_group_entry_locked(&groups, group)
                .is_some_and(|(_, info)| info.fork_quarantine.is_some())
        };
        let now = head_of(sim, label, group).await?;
        ok &= now == head && !quarantined;
        lines.push(format!("{label}: {now:?} quarantined={quarantined}"));
    }
    Ok((ok, lines.join("; ")))
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

/// Every node holds A's head and TreeKEM epoch.
async fn settled(sim: &Sim, labels: &[&str], group: &str) -> Result<()> {
    sim.until(
        "every node holds A's head and epoch",
        SETUP,
        async |s: &Sim| {
            let Ok(authority) = head_of(s, "A", group).await else {
                return false;
            };
            for label in labels {
                match head_of(s, label, group).await {
                    Ok(seen) if seen == authority => {}
                    _ => return false,
                }
            }
            true
        },
    )
    .await
}

/// Wait out `S4Timing::restart_sync_wait` so t = 0 sits past every node's
/// boot head gate (ADR 0110 §2).
async fn past_boot_gate(sim: &Sim) -> Result<()> {
    let wait = S4Timing::default().restart_sync_wait;
    sim.within("restart sync wait", wait + secs(2), async {
        tokio::time::sleep(wait).await;
    })
    .await
}

/// Sleep to the fixed virtual instant `to`.
async fn sleep_to(sim: &Sim, name: &str, to: Duration) -> Result<()> {
    let left = to.saturating_sub(sim.fabric().now());
    sim.within(name, left + secs(2), async {
        tokio::time::sleep(left).await;
    })
    .await
}

/// Create the ordinary `private_secure` group through the public API.
async fn create_named(sim: &Sim, owner: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({
                "name": GROUP_NAME,
                "display_name": owner,
                "preset": "private_secure",
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "{owner} create: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

/// The §4b(3) base run: the typed refusal on every mutating route, the
/// re-create offer on the status, history kept readable, no new key, then
/// B's re-created group.
async fn base_scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let labels = ["A", "B", "C"];
    let mut passed = true;
    mesh(sim, &labels).await?;
    let group = create_named(sim, "A").await?;
    for member in ["B", "C"] {
        seat(sim, member, &group).await?;
    }
    let a_hex = sim.agent_hex("A")?;
    let b_hex = sim.agent_hex("B")?;
    let c_hex = sim.agent_hex("C")?;
    settled(sim, &labels, &group).await?;
    let head0 = head_of(sim, "A", &group).await?;

    // Pre-trigger data plane: A's ciphertext opens on B and C, so a later
    // refusal means the §4 state, not a broken path. History reads, too.
    let (sent, why) = sends(sim, "A", &group).await?;
    ensure!(sent, "setup: {why}");
    let (readable, why) = history(sim, "B", &group, false).await?;
    ensure!(readable, "setup: {why}");
    past_boot_gate(sim).await?;
    receipt.setup_done(at(sim));

    // t = 0: A revokes its own agent (ADR 0110 §4b(3) trigger).
    sim.fabric().mark("case: t=0 A self-revokes");
    let (status, body) = sim
        .api(
            "A",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": a_hex, "reason": "w3h-1581"})),
        )
        .await?;
    ensure!(status.is_success(), "A self-revokes: {status} {body}");
    // The ADR's delivery order: B at t = 100 ms, C at t = 1 s.
    sim.until("B holds A's revocation", EVIDENCE, async |s: &Sim| {
        holds_revocation(s, "B", &a_hex).await.unwrap_or(false)
    })
    .await?;
    sim.until("C holds A's revocation", EVIDENCE, async |s: &Sim| {
        holds_revocation(s, "C", &a_hex).await.unwrap_or(false)
    })
    .await?;
    receipt.request_delivered(
        "b_then_c_hold_a_revocation",
        true,
        "B first, then C (the ADR's t = 100 ms / t = 1 s order)".to_string(),
        at(sim),
    );

    // t = 2 s: B and C call send, invite and seal, and read the status.
    sleep_to(sim, "wait to t=2s", sim.fabric().now() + secs(2)).await?;
    for label in ["B", "C"] {
        let (found, phases) = until_refused(sim, label, &group, &a_hex, REFUSAL).await?;
        if !phases.is_empty() {
            receipt.note(format!("{label} earlier phases: {phases:?}"));
        }
        record(
            receipt,
            &format!("{label}_send_refused_group_admin_revoked"),
            &(
                found,
                format!("{label} encrypt reached the definitive 410: {found}"),
            ),
            &mut passed,
            at(sim),
        );
        let requests: [(&str, Method, String, Option<serde_json::Value>); 2] = [
            (
                "invite",
                Method::POST,
                format!("/groups/{group}/invite"),
                Some(json!({})),
            ),
            (
                "seal",
                Method::POST,
                format!("/groups/{group}/state/seal"),
                None,
            ),
        ];
        for (name, method, path, body) in requests {
            let seen = refused(sim, label, method, &path, body, &a_hex).await?;
            record(
                receipt,
                &format!("{label}_{name}_refused_group_admin_revoked"),
                &seen,
                &mut passed,
                at(sim),
            );
        }
        // The status carries the re-create offer: B and C (the non-revoked
        // members, sorted), the name, the policy.
        let (status, offer) = sim
            .api(label, Method::GET, &format!("/groups/{group}"), None)
            .await?;
        let mut offered: Vec<String> = offer["admin_availability"]["recreate_offer"]["members"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        offered.sort();
        let mut non_revoked = vec![b_hex.clone(), c_hex.clone()];
        non_revoked.sort();
        let ok = status.is_success()
            && offer["admin_availability"]["state"] == "group_admin_revoked"
            && offer["admin_availability"]["exit"] == "group_admin_revoked"
            && offered == non_revoked
            && offer["admin_availability"]["recreate_offer"]["name"] == GROUP_NAME
            && offer["admin_availability"]["recreate_offer"]["policy"].is_object();
        record(
            receipt,
            &format!("{label}_status_carries_recreate_offer"),
            &(
                ok,
                format!("{label} status: {status} {}", offer["admin_availability"]),
            ),
            &mut passed,
            at(sim),
        );
        // Local history stays readable (nothing is deleted).
        let seen = history(sim, label, &group, false).await?;
        record(
            receipt,
            &format!("{label}_local_history_stays_readable"),
            &seen,
            &mut passed,
            at(sim),
        );
    }
    // Even A's own key gets nothing new: A's own send is refused.
    let seen = sends(sim, "A", &group).await?;
    record(
        receipt,
        "a_own_send_refused",
        &(!seen.0, seen.1),
        &mut passed,
        at(sim),
    );

    // No new key reached anyone: nothing may seal (no eligible admin
    // remains), so every node stays at the settled head, unquarantined.
    sleep_to(
        sim,
        "wait out the completion bound",
        sim.fabric().now() + SETTLE,
    )
    .await?;
    let seen = quiet_at(sim, &labels, &group, head0).await?;
    record(
        receipt,
        "no_rekey_no_quarantine_after_the_bound",
        &seen,
        &mut passed,
        at(sim),
    );

    // The re-create variant: B accepts the offer through the public
    // create API. The re-created group has a new ID, B as its admin, C
    // seated, and no history; the old group stays ended and readable.
    let recreated = create_named(sim, "B").await?;
    let link = invite(sim, "B", &recreated).await?;
    join(sim, "C", &link).await?;
    sim.until(
        "C seated in the re-created group",
        SETUP,
        async |s: &Sim| {
            members(s, "B", &recreated)
                .await
                .is_ok_and(|listed| listed.contains(&c_hex))
        },
    )
    .await?;
    let b_admin = sees_admin(sim, "C", &recreated, "B").await?;
    let no_history = history(sim, "B", &recreated, true).await?;
    let (status, old) = sim
        .api("B", Method::GET, &format!("/groups/{group}"), None)
        .await?;
    let ok = recreated != group
        && b_admin
        && no_history.0
        && status.is_success()
        && old["admin_availability"]["state"] == "group_admin_revoked";
    record(
        receipt,
        "recreated_group_new_id_b_admin_c_seated_no_history",
        &(
            ok,
            format!(
                "new id differs: {}; C sees B admin: {b_admin}; {}; old status {status} {}",
                recreated != group,
                no_history.1,
                old["admin_availability"]
            ),
        ),
        &mut passed,
        at(sim),
    );
    receipt.finish(FINAL_BASE, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, labels: &[&str]) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 §4b(3). Timing from S4Timing::default() (measured; D69, D73): {:?}.",
        S4Timing::default()
    ));
    match Sim::start(case, seed, labels).await {
        Ok(mut sim) => {
            if let Err(error) = base_scenario(&mut sim, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL_BASE);
    }
    receipt.emit();
    receipt
}

async fn expect_green(case: &str, seed: u64, labels: &[&str]) -> Result<()> {
    let receipt = run(case, seed, labels).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// ADR 0110 `s4_ordinary_admin_revoked`, base run and re-create variant:
/// GREEN with the seal-ordering fix; RED on `main` (the seat 403) and with
/// the §4 cover test neutralised.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1581_s4_ordinary_admin_revoked() -> Result<()> {
    expect_green(
        "w3h_1581_s4_ordinary_admin_revoked",
        0x1581_0001,
        &["A", "B", "C"],
    )
    .await
}
