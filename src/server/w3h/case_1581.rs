//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_ordinary_admin_revoked`, §4b(3) / D126): an ordinary group whose
//! verified Agent-subject revocations cover every Admin-or-higher Active
//! seat ends locally, with the typed refusal `group_admin_revoked`. With
//! this PR's seal-ordering fix the arms expect the ADR behaviour (GREEN);
//! on `main` the base arm is RED, because `POST /groups/:id/state/seal`
//! answered the caller's seat 403 before the §4 refusal. Each arm keeps
//! the row's red causes: with the §4 cover test (`revoked_admin_cover`)
//! neutralised, the member sends still succeed, so the arms fail with the
//! leak cause, and the reads observe no typed state, so they fail with
//! the no-state cause (the neutralised run is the RED proof; see the PR
//! body).
//!
//! A is the sole admin and B, C are members of an ordinary
//! `private_secure` (InviteOnly, TreeKEM) group created through the public
//! API. Before t = 0 the group is settled (every node at A's state
//! revision and TreeKEM epoch e0), a data-plane probe passes and opens on
//! B and C (a second ciphertext is held for the post-revocation read),
//! and the case waits out `S4Timing::restart_sync_wait` (ADR 0110 §2), so
//! no read below sits behind the boot head gate. The derived refusal
//! needs the node's own current head round, so a first read can still
//! show the §4 409 wait (`waiting_for_eligible_admin_revocation`, exit
//! `group_admin_revoked`); the arms poll to the definitive 410 and record
//! every earlier phase. Under the cover, a mutating reply that succeeds,
//! or carries ciphertext, fails the arm at once (the leak cause). The
//! row exists to prove that no new key material reaches anyone.
//!
//! Arms:
//!
//! - `w3h_1581_s4_ordinary_admin_revoked` (the row's base run and its
//!   re-create variant). At t = 0 A revokes its own agent through
//!   `POST /identity/revoke`; the record reaches B and then C (the ADR
//!   names t = 100 ms and t = 1 s; delivery is the fabric default, and
//!   the case awaits the holders in that order and reports the measured
//!   instants). At t = 2 s, measured from the revoke, B and C call the
//!   send, invite and seal APIs: each answers 410 `group_admin_revoked`
//!   naming A, with no key material in the body, and the status carries
//!   the re-create offer (members B and C, the group's own name and
//!   policy). Local history stays readable with the probe's record
//!   present, the held key still opens that record (a local read; no new
//!   key is made), and even A's own encrypt reaches the same refusal.
//!   After the completion bound no node's epoch has moved and none is
//!   quarantined, so no new key reached anyone. B then accepts the offer
//!   through the public create API with the offered name and policy
//!   object: the re-created group has a new stable id, B as its admin, C
//!   seated and active, and no history.
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
const CAUSE_LEAK: &str = "key material under the cover: with A revoked, a member send, invite \
                          or seal still answered a success, or its body still carried ciphertext";
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

/// Record one observed §4 leak: after the cover, a mutating route still
/// answered a success, or its body still carried key material. The arm
/// fails at once; no later probe can clear it. Like a miss, the cause is
/// recorded as observed, so the run with the §4 cover test neutralised
/// stays the RED proof.
fn leak(receipt: &mut Receipt, name: &str, reply: &str, passed: &mut bool, at: u128) {
    receipt.cause(CAUSE_LEAK, Some(format!("{name}: {reply}")), true, at);
    *passed = false;
}

/// Note a poll's earlier reply shapes (each shape once).
fn note_phases(receipt: &mut Receipt, label: &str, phases: &[String]) {
    if !phases.is_empty() {
        receipt.note(format!("{label} earlier phases: {phases:?}"));
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

/// Whether the reply body carries group key material (ciphertext or a
/// KEM envelope).
fn carries_key_material(body: &serde_json::Value) -> bool {
    body["ciphertext_b64"].is_string() || body["kem_ciphertext_b64"].is_string()
}

/// The classification of one post-revocation reply from a mutating route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The definitive §4b(3) refusal: 410, the typed state, A named as
    /// the revoked admin, no key material.
    Definitive,
    /// The §4 409 wait the production builder emits while the head round
    /// is not yet definitive (exit `group_admin_revoked`).
    Wait,
    /// A success, or a body with key material: the §4 property (no new
    /// key under the cover) is violated.
    Violation,
    /// Any other reply.
    Other,
}

/// Whether the reply is the §4 409 wait: 409, the typed wait state, exit
/// `group_admin_revoked`, A named among the revoked admins, and no key
/// material.
fn is_s4_wait(status: StatusCode, body: &serde_json::Value, a_hex: &str) -> bool {
    status == StatusCode::CONFLICT
        && body["state"] == "waiting_for_eligible_admin_revocation"
        && body["exit"] == "group_admin_revoked"
        && body["revoked_admins"].as_array().is_some_and(|ids| {
            ids.iter()
                .any(|id| id.as_str().is_some_and(|id| id.eq_ignore_ascii_case(a_hex)))
        })
        && !carries_key_material(body)
}

/// Classify one post-revocation reply from a mutating route. The
/// definitive refusal comes first; a success or key material is a leak,
/// even on a non-2xx status; the wait is the only allowed earlier phase.
fn classify_refusal(status: StatusCode, body: &serde_json::Value, a_hex: &str) -> Refusal {
    if is_group_admin_revoked(status, body, a_hex) {
        Refusal::Definitive
    } else if status.is_success() || carries_key_material(body) {
        Refusal::Violation
    } else if is_s4_wait(status, body, a_hex) {
        Refusal::Wait
    } else {
        Refusal::Other
    }
}

/// One mutating request through a node's own barrier, classified; the
/// string carries the observed reply for the receipt.
async fn refused(
    sim: &Sim,
    label: &str,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    a_hex: &str,
) -> Result<(Refusal, String)> {
    let (status, reply) = sim.api(label, method, path, body).await?;
    Ok((
        classify_refusal(status, &reply, a_hex),
        format!("{label} {path}: {status} {reply}"),
    ))
}

/// `label` encrypts the probe; the ciphertext, or why it could not.
async fn sends(sim: &Sim, label: &str, group: &str) -> Result<std::result::Result<String, String>> {
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/secure/encrypt"),
            Some(json!({"payload_b64": BASE64.encode(PROBE)})),
        )
        .await?;
    Ok(match body["ciphertext_b64"].as_str() {
        Some(ciphertext) if status.is_success() && body["ok"] != false => {
            Ok(ciphertext.to_string())
        }
        _ => Err(format!("{label} encrypt: {status} {body}")),
    })
}

/// Whether `label` recovers the probe from `ciphertext`, with the reply.
/// The decrypt route is a local read of held key material; the §4
/// refusal does not gate it, so it must keep working after the cover.
async fn decrypts(sim: &Sim, label: &str, group: &str, ciphertext: &str) -> Result<Seen> {
    let (status, body) = sim
        .api(
            label,
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
    Ok((ok, format!("{label} decrypt: {status} {body}")))
}

/// The outcome of one label's post-revocation send poll.
enum SendPoll {
    /// The definitive §4b(3) 410 was reached; the earlier reply shapes
    /// seen on the way (each recorded once).
    Reached(Vec<String>),
    /// The budget ended first; the earlier reply shapes seen are carried.
    WaitedOut(Vec<String>),
    /// A reply succeeded, or carried key material; the reply is carried,
    /// and the arm fails at once.
    Violation(String),
}

/// Poll `label`'s member send until it answers the definitive refusal
/// (`budget` virtual time), recording each earlier reply shape once. The
/// §4 409 wait (`waiting_for_eligible_admin_revocation`, exit
/// `group_admin_revoked`) is an allowed earlier phase. A reply that
/// succeeds, or carries key material, stops the poll at once: that is
/// the leak the row's cover exists to prevent. Uses barrier-free reads.
async fn until_refused(
    sim: &Sim,
    label: &str,
    group: &str,
    a_hex: &str,
    budget: Duration,
) -> Result<SendPoll> {
    let mut phases: Vec<String> = Vec::new();
    let mut violation: Option<String> = None;
    let refused = sim
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
                match classify_refusal(status, &body, a_hex) {
                    Refusal::Definitive => true,
                    Refusal::Violation => {
                        violation = Some(format!("{label} encrypt: {status} {body}"));
                        true
                    }
                    _ => {
                        let phase = format!("{status} {body}");
                        if !phases.contains(&phase) {
                            phases.push(phase);
                        }
                        false
                    }
                }
            },
        )
        .await
        .is_ok();
    Ok(match violation {
        Some(reply) => SendPoll::Violation(reply),
        None if refused => SendPoll::Reached(phases),
        None => SendPoll::WaitedOut(phases),
    })
}

/// Poll one label's member send to the definitive §4b(3) refusal and
/// record it under `name`. `true`: the poll saw a leak (a success, or
/// key material), so the caller stops probing; the arm already failed.
async fn send_refusal(
    sim: &Sim,
    receipt: &mut Receipt,
    label: &str,
    name: &str,
    group: &str,
    a_hex: &str,
    passed: &mut bool,
) -> Result<bool> {
    let poll = until_refused(sim, label, group, a_hex, REFUSAL).await?;
    let at = sim.fabric().now().as_micros();
    match poll {
        SendPoll::Reached(phases) => {
            note_phases(receipt, label, &phases);
            record(
                receipt,
                name,
                &(true, format!("{label} encrypt reached the definitive 410")),
                passed,
                at,
            );
            Ok(false)
        }
        SendPoll::WaitedOut(phases) => {
            note_phases(receipt, label, &phases);
            record(
                receipt,
                name,
                &(
                    false,
                    format!("{label} encrypt never reached the definitive 410; phases {phases:?}"),
                ),
                passed,
                at,
            );
            Ok(false)
        }
        SendPoll::Violation(reply) => {
            leak(receipt, name, &reply, passed, at);
            Ok(true)
        }
    }
}

/// The stable group id `label` resolves for `group` (the history scope).
async fn stable_id(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("{label} has no record of {group}"))?;
    Ok(info.stable_group_id().to_string())
}

/// Whether `label`'s local history for the group stays readable (2xx)
/// and holds at least one record (the setup probe's), or is exactly
/// empty when `expect_empty` (a re-created group carries no history).
async fn history(sim: &Sim, label: &str, group: &str, expect_empty: bool) -> Result<Seen> {
    let scope = format!("group:{}", stable_id(sim, label, group).await?);
    let (status, body) = sim
        .api(label, Method::GET, &format!("/history?scope={scope}"), None)
        .await?;
    let ok =
        status.is_success()
            && body["ok"] == true
            && body["count"].as_u64().is_some_and(|count| {
                if expect_empty {
                    count == 0
                } else {
                    count >= 1
                }
            });
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

/// Create a group through the public API from B's re-create offer: the
/// offered name and the offered policy object, verbatim. The API accepts
/// an explicit `policy` (it refuses `policy` together with `preset`, so
/// no preset is passed).
async fn create_offered(
    sim: &Sim,
    owner: &str,
    name: &str,
    policy: &serde_json::Value,
) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({
                "name": name,
                "policy": policy,
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "{owner} create from the offer: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

/// The §4b(3) base run: the typed refusal on every mutating route, the
/// re-create offer on the status, history kept readable and openable
/// with the held key, no new key, then B's re-created group. After the
/// cover, a mutating reply that succeeds, or carries key material,
/// fails the arm at once (the leak cause).
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
    // refusal means the §4 state, not a broken path. A second ciphertext
    // is held unread, for the post-revocation open. History reads carry
    // the probe's record.
    let probe = match sends(sim, "A", &group).await? {
        Ok(ciphertext) => ciphertext,
        Err(why) => bail!("setup: {why}"),
    };
    let held_probe = match sends(sim, "A", &group).await? {
        Ok(ciphertext) => ciphertext,
        Err(why) => bail!("setup: {why}"),
    };
    for label in ["B", "C"] {
        let (opened, why) = decrypts(sim, label, &group, &probe).await?;
        ensure!(opened, "setup: {why}");
    }
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
    let t0 = sim.fabric().now();
    // The ADR's delivery order: B at t = 100 ms, C at t = 1 s. The waits
    // are sequential, so B's measured instant cannot exceed C's; the
    // delivery itself is the fabric default.
    sim.until("B holds A's revocation", EVIDENCE, async |s: &Sim| {
        holds_revocation(s, "B", &a_hex).await.unwrap_or(false)
    })
    .await?;
    let b_held_at = sim.fabric().now();
    sim.until("C holds A's revocation", EVIDENCE, async |s: &Sim| {
        holds_revocation(s, "C", &a_hex).await.unwrap_or(false)
    })
    .await?;
    let c_held_at = sim.fabric().now();
    receipt.request_delivered(
        "b_then_c_hold_a_revocation",
        b_held_at <= c_held_at,
        format!(
            "B held at {} us, C held at {} us (the ADR names t = 100 ms and t = 1 s; delivery \
             is the fabric default)",
            b_held_at.as_micros(),
            c_held_at.as_micros()
        ),
        at(sim),
    );

    // t = 2 s from t0: B and C call send, invite and seal, and read the
    // status. Under the cover no mutating reply may succeed, or carry
    // key material; the first such reply fails the arm at once, and no
    // further mutating probe runs.
    sleep_to(sim, "wait to t=2s", t0 + secs(2)).await?;
    let mut leaked = false;
    let mut b_offer: Option<(String, serde_json::Value)> = None;
    for label in ["B", "C"] {
        leaked = send_refusal(
            sim,
            receipt,
            label,
            &format!("{label}_send_refused_group_admin_revoked"),
            &group,
            &a_hex,
            &mut passed,
        )
        .await?;
        if leaked {
            break;
        }
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
            let (class, reply) = refused(sim, label, method, &path, body, &a_hex).await?;
            let name = format!("{label}_{name}_refused_group_admin_revoked");
            if class == Refusal::Violation {
                leak(receipt, &name, &reply, &mut passed, at(sim));
                leaked = true;
                break;
            }
            record(
                receipt,
                &name,
                &(class == Refusal::Definitive, reply),
                &mut passed,
                at(sim),
            );
        }
        if leaked {
            break;
        }
        // The status carries the re-create offer: B and C (the non-revoked
        // members, sorted), the group's own name and policy verbatim, and
        // no key material on the read.
        let (status, offer) = sim
            .api(label, Method::GET, &format!("/groups/{group}"), None)
            .await?;
        let availability = &offer["admin_availability"];
        let mut offered: Vec<String> = availability["recreate_offer"]["members"]
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
        let offered_name = availability["recreate_offer"]["name"].clone();
        let offered_policy = availability["recreate_offer"]["policy"].clone();
        let ok = status.is_success()
            && availability["state"] == "group_admin_revoked"
            && availability["exit"] == "group_admin_revoked"
            && offered == non_revoked
            && offered_name.is_string()
            && offered_name == offer["name"]
            && offered_policy.is_object()
            && offered_policy == offer["policy"]
            && !carries_key_material(&offer);
        record(
            receipt,
            &format!("{label}_status_carries_recreate_offer"),
            &(ok, format!("{label} status: {status} {availability}")),
            &mut passed,
            at(sim),
        );
        if ok && label == "B" {
            // B re-creates with the offered name and the offered policy.
            b_offer = Some((
                offered_name.as_str().unwrap_or_default().to_string(),
                offered_policy,
            ));
        }
        // Local history stays readable with the probe's record present
        // (nothing is deleted).
        let seen = history(sim, label, &group, false).await?;
        record(
            receipt,
            &format!("{label}_local_history_stays_readable"),
            &seen,
            &mut passed,
            at(sim),
        );
        // The held key still opens what it already holds: a local decrypt
        // of A's held probe makes no new key, so the refusal gates
        // writes, not the local read of held history.
        let seen = decrypts(sim, label, &group, &held_probe).await?;
        record(
            receipt,
            &format!("{label}_held_key_still_opens_the_probe"),
            &seen,
            &mut passed,
            at(sim),
        );
    }
    // Even A's own key gets nothing new: A holds its own revocation
    // record, so A's own send must reach the same definitive refusal,
    // through the same allowed 409 wait. A success, or any ciphertext,
    // is the same leak. After a leak no further mutating probe runs.
    if !leaked {
        send_refusal(
            sim,
            receipt,
            "A",
            "a_own_send_refused",
            &group,
            &a_hex,
            &mut passed,
        )
        .await?;
    }

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
    // create API with the offered name and policy object (a run that
    // read no offer falls back to the preset and says so in a note).
    // The re-created group has a new stable id, B as its admin, C seated
    // and active, and no history; the old group stays ended and readable.
    let recreated = match &b_offer {
        Some((name, policy)) => create_offered(sim, "B", name, policy).await?,
        None => {
            receipt.note(
                "no re-create offer was read; the re-create falls back to the private_secure \
                 preset",
            );
            create_named(sim, "B").await?
        }
    };
    let link = invite(sim, "B", &recreated).await?;
    join(sim, "C", &link).await?;
    sim.until(
        "C seated in the re-created group",
        SETUP,
        async |s: &Sim| {
            members(s, "B", &recreated)
                .await
                .is_ok_and(|listed| listed.contains(&c_hex))
                && membership_state(s, "C", &recreated)
                    .await
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some("active")
        },
    )
    .await?;
    let b_admin = sees_admin(sim, "C", &recreated, "B").await?;
    let c_active = membership_state(sim, "C", &recreated)
        .await
        .ok()
        .flatten()
        .as_deref()
        == Some("active");
    let old_stable = stable_id(sim, "B", &group).await?;
    let new_stable = stable_id(sim, "B", &recreated).await?;
    let no_history = history(sim, "B", &recreated, true).await?;
    let (status, old) = sim
        .api("B", Method::GET, &format!("/groups/{group}"), None)
        .await?;
    let ok = new_stable != old_stable
        && b_admin
        && c_active
        && no_history.0
        && status.is_success()
        && old["admin_availability"]["state"] == "group_admin_revoked";
    record(
        receipt,
        "recreated_group_new_id_b_admin_c_seated_no_history",
        &(
            ok,
            format!(
                "stable ids differ (old {old_stable}, new {new_stable}): {}; C sees B admin: \
                 {b_admin}; C reports itself active: {c_active}; {}; old status {status} {}",
                new_stable != old_stable,
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
                receipt.infra(format!("finish: {error}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error}"), 0),
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
