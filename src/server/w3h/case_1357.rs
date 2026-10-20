//! W3-H cases for #1357 (ADR 0110 S4, revocation eviction, designated
//! admin first). Harness first (D16/D54): the red arms are committed and
//! shown RED on `main` before S4 code merges; the controls are GREEN before
//! and after.
//!
//! Every arm uses an ordinary `private_secure` (TreeKEM) group created by A
//! through the public API. B is the target and C a survivor. The group is
//! settled (every node at A's state revision and TreeKEM epoch e0, with
//! `n` leaves) and a pre-trigger data-plane check passes (A encrypts; B and
//! C decrypt) before t = 0.
//!
//! Healthy exit H (ADR 0110 Validation): every survivor lists B as not
//! active, holds one TreeKEM epoch above e0 with `n - 1` leaves and no
//! fork-quarantine marker, and the adder A (when it is a survivor) no
//! longer tracks B's leaf. Then a survivor encrypts, C decrypts it and B's
//! retained keys cannot.
//!
//! Arms:
//!
//! - `s4_idle_revocation_one_admin` (RED on `main`). Nodes A, B, C; A is
//!   the only admin. At t = 0 B revokes its own agent through
//!   `POST /identity/revoke` (the issuer API; ADR 0110 "repeat
//!   self-revocation and ordinary groups"). A and C must hold the record.
//!   No seal or removal API is called. Desired: H within
//!   [`S4_COMPLETION_BOUND_PLACEHOLDER`]. `main` has no revocation
//!   eviction, so B stays seated at e0 on A and C ([`CAUSE_IDLE`]).
//! - `s4_self_leave_crypto_only` (control, GREEN on `main`). Nodes A, B, C.
//!   At t = 0 B leaves (`DELETE /groups/:id`). #1113 / PR #1337 already
//!   makes the lowest active admin commit the TreeKEM removal after a
//!   self-leave, so this is GREEN on `main`. After S4 the same rekey runs
//!   through ADR 0110's designated-first path (§"responsive rekey after
//!   self-leave"), so it must stay GREEN.
//! - `s4_fallback_rank_manual` (RED on `main`). Nodes A, D, E, B, C, with
//!   admins A < D < E by agent id (the case reassigns the pre-generated
//!   keys of A, D and E so that this holds). A is held off the fabric
//!   (the designated admin, stalled). At t = 0 B revokes its own agent; D,
//!   E and C must hold the record. Then D calls the public remove API on
//!   B, well before W. Desired: D's request is queued with the typed state
//!   `waiting_for_designated_admin` naming A, no survivor's epoch moves
//!   in the next [`EARLY_READ`], and the ranked fallback then reaches H
//!   within W + Δ + the completion bound. `main` rekeys at once
//!   ([`CAUSE_MANUAL`]).
//! - `s4_manual_remove_without_obligation` (control, GREEN on `main`). The
//!   same five nodes, A held, but no revocation: D's manual remove of B is
//!   not affected by S4, so it rekeys at once and reaches H.
//!
//! W, Δ and the completion bound are not measured yet (D69, D73). The case
//! uses generous named placeholders so that the RED verdict means "never
//! happens on `main`", not a timing miss. Replace them with the W3-H
//! p99.9 numbers (`s4_timing_measurement`) before timing-dependent S4 code
//! merges.
//!
//! Receipts use `w3h.receipt/1`. The D196 receipt is 20 verdict-stable
//! reruns on the W3-H gate.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh};
use super::home::membership_state;
use super::receipt::{Receipt, Verdict};
use super::*;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// PLACEHOLDER for ADR 0110's completion bound (D69): replace it with the
/// W3-H p99.9 measured number before timing-dependent S4 code merges.
/// Generous on purpose: the red verdict is about "never happens on main".
const S4_COMPLETION_BOUND_PLACEHOLDER: Duration = Duration::from_secs(120);
/// PLACEHOLDER for ADR 0110's designated-admin window W (D69): replace it
/// with the measured number before timing-dependent S4 code merges.
const S4_W_PLACEHOLDER: Duration = Duration::from_secs(60);
/// PLACEHOLDER for ADR 0110's fallback rank step Δ (D73): replace it with
/// the measured number before timing-dependent S4 code merges.
const S4_DELTA_PLACEHOLDER: Duration = Duration::from_secs(30);
/// How long after a non-designated manual request the case checks that no
/// survivor rekeyed. Far below any plausible W.
const EARLY_READ: Duration = Duration::from_secs(5);
/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for the revocation record to reach the survivors.
const EVIDENCE: Duration = Duration::from_secs(60);
const PROBE: &[u8] = b"w3h-1357 probe";

const FINAL_H: &str = "survivors_exclude_b_cryptographically_within_the_bound";
const FINAL_MANUAL: &str =
    "non_designated_manual_remove_queues_as_waiting_for_designated_admin_then_reaches_h";
const CAUSE_IDLE: &str = "no revocation eviction on main: after the bound A and C still list B \
                          active, A still tracks B's leaf, and every survivor stays at epoch e0 \
                          with the same leaf count";
const CAUSE_SELF_LEAVE: &str =
    "B's leaf retained after self-leave: survivors remain at epoch e0 with the same leaf count";
const CAUSE_MANUAL: &str = "non-designated manual remove rekeys at once on main: D's remove of B \
                            returned success without waiting_for_designated_admin and a survivor \
                            left epoch e0 within EARLY_READ while the designated admin A was held";
const CAUSE_NO_OBLIGATION: &str =
    "D's manual remove did not exclude B: survivors remain at epoch e0 with the same leaf count";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// ADR 0110 `s4_idle_revocation_one_admin` (red).
    IdleRevocation,
    /// ADR 0110 `s4_self_leave_crypto_only` (control on `main`).
    SelfLeave,
    /// ADR 0110 `s4_fallback_rank_manual` (red).
    ManualDuringWindow,
    /// `s4_fallback_rank_manual`'s baseline: the same manual remove, no
    /// S4 obligation (control).
    ManualWithoutObligation,
}

impl Arm {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::IdleRevocation | Self::SelfLeave => &["A", "B", "C"],
            Self::ManualDuringWindow | Self::ManualWithoutObligation => &["A", "D", "E", "B", "C"],
        }
    }

    /// Admins A promotes after seating everyone.
    fn promoted(self) -> &'static [&'static str] {
        match self {
            Self::IdleRevocation | Self::SelfLeave => &[],
            Self::ManualDuringWindow | Self::ManualWithoutObligation => &["D", "E"],
        }
    }

    /// The five-node arms rank A < D < E by agent id and hold A.
    fn ranked_admins(self) -> bool {
        !self.promoted().is_empty()
    }

    /// Nodes that must reach H. The first one encrypts the data-plane probe.
    fn survivors(self) -> &'static [&'static str] {
        match self {
            Self::IdleRevocation | Self::SelfLeave => &["A", "C"],
            Self::ManualDuringWindow | Self::ManualWithoutObligation => &["D", "E", "C"],
        }
    }

    fn revokes(self) -> bool {
        matches!(self, Self::IdleRevocation | Self::ManualDuringWindow)
    }

    fn manual(self) -> bool {
        matches!(
            self,
            Self::ManualDuringWindow | Self::ManualWithoutObligation
        )
    }

    /// How long H may take after the trigger.
    fn bound(self) -> Duration {
        match self {
            Self::ManualDuringWindow => S4_W_PLACEHOLDER
                .saturating_add(S4_DELTA_PLACEHOLDER)
                .saturating_add(S4_COMPLETION_BOUND_PLACEHOLDER),
            _ => S4_COMPLETION_BOUND_PLACEHOLDER,
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::ManualDuringWindow => FINAL_MANUAL,
            _ => FINAL_H,
        }
    }
}

/// One node's local record of the group.
#[derive(Debug, Clone)]
struct View {
    state_revision: u64,
    /// Whether B is an active roster member.
    lists_b: bool,
    /// B's roster state (`Active`, `Removed`, …), if B has a row.
    b_state: Option<String>,
    quarantined: bool,
    epoch: Option<u64>,
    leaves: Option<u32>,
    /// Whether the live TreeKEM group still maps B to a leaf. Only the
    /// node that added B tracks it.
    tracks_b: Option<bool>,
}

impl View {
    fn describe(&self) -> String {
        format!(
            "state={} lists_b={} b_state={:?} epoch={:?} leaves={:?} tracks_b={:?} quarantined={}",
            self.state_revision,
            self.lists_b,
            self.b_state,
            self.epoch,
            self.leaves,
            self.tracks_b,
            self.quarantined
        )
    }
}

/// `label`'s view of `group`; `None` when it holds no record of it.
async fn try_view_now(
    sim: &Sim,
    label: &str,
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Option<View>> {
    let b_hex = hex::encode(b.as_bytes());
    let state = sim.state(label)?;
    let (key, view) = {
        let groups = state.named_groups.read().await;
        let Some((key, info)) = crate::server::resolve_group_entry_locked(&groups, group) else {
            return Ok(None);
        };
        let b_row = info
            .members_v2
            .values()
            .find(|member| member.agent_id.eq_ignore_ascii_case(&b_hex));
        let view = View {
            state_revision: info.state_revision,
            lists_b: info
                .active_members()
                .any(|member| member.agent_id.eq_ignore_ascii_case(&b_hex)),
            b_state: b_row.map(|member| format!("{:?}", member.state)),
            quarantined: info.fork_quarantine.is_some(),
            epoch: None,
            leaves: None,
            tracks_b: None,
        };
        (key.to_string(), view)
    };
    let live = state.treekem_groups.read().await.get(&key).cloned();
    let Some(live) = live else {
        return Ok(Some(view));
    };
    let guard = live.lock().await;
    Ok(Some(View {
        epoch: Some(guard.epoch()),
        leaves: Some(guard.member_count()),
        tracks_b: Some(guard.tracks_member(b)),
        ..view
    }))
}

async fn view_now(
    sim: &Sim,
    label: &str,
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<View> {
    try_view_now(sim, label, group, b)
        .await?
        .with_context(|| format!("{label} has no record of {group}"))
}

async fn view(sim: &Sim, label: &str, group: &str, b: &crate::identity::AgentId) -> Result<View> {
    sim.at_instant(
        &format!("read {label}'s group"),
        view_now(sim, label, group, b),
    )
    .await?
}

/// The structural part of H over the survivors' views.
fn excluded(views: &[(&str, Option<View>)], e0: u64, leaves0: u32) -> bool {
    let mut epoch = None;
    for (_, seen) in views {
        let Some(seen) = seen else {
            return false;
        };
        let Some(now) = seen.epoch else {
            return false;
        };
        if now <= e0
            || seen.lists_b
            || seen.quarantined
            || seen.leaves != Some(leaves0.saturating_sub(1))
            || seen.tracks_b == Some(true)
            || epoch.is_some_and(|first| first != now)
        {
            return false;
        }
        epoch = Some(now);
    }
    !views.is_empty()
}

/// Every survivor still seats B at e0 with the original leaf count.
fn still_seated(views: &[(&str, Option<View>)], e0: u64, leaves0: u32) -> bool {
    !views.is_empty()
        && views.iter().all(|(_, seen)| {
            seen.as_ref().is_some_and(|seen| {
                seen.lists_b && seen.epoch == Some(e0) && seen.leaves == Some(leaves0)
            })
        })
}

fn describe_all(views: &[(&str, Option<View>)]) -> String {
    views
        .iter()
        .map(|(label, seen)| {
            format!(
                "{label}: {}",
                seen.as_ref()
                    .map_or_else(|| "no record".to_string(), View::describe)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn views_now(
    sim: &Sim,
    labels: &[&'static str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Vec<(&'static str, Option<View>)>> {
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        out.push((*label, try_view_now(sim, label, group, b).await?));
    }
    Ok(out)
}

async fn views(
    sim: &Sim,
    labels: &[&'static str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<Vec<(&'static str, Option<View>)>> {
    sim.at_instant(
        "read the survivors' groups",
        views_now(sim, labels, group, b),
    )
    .await?
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

/// Every label holds A's state revision and TreeKEM epoch.
async fn settled(
    sim: &Sim,
    labels: &[&str],
    group: &str,
    b: &crate::identity::AgentId,
) -> Result<()> {
    sim.until(
        "every node holds A's head and epoch",
        SETUP,
        async |s: &Sim| {
            let Ok(authority) = view_now(s, "A", group, b).await else {
                return false;
            };
            if authority.epoch.is_none() {
                return false;
            }
            for label in labels {
                match view_now(s, label, group, b).await {
                    Ok(seen)
                        if seen.state_revision == authority.state_revision
                            && seen.epoch == authority.epoch => {}
                    _ => return false,
                }
            }
            true
        },
    )
    .await
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

/// `label` encrypts the probe; the ciphertext, or why it could not.
async fn encrypt(
    sim: &Sim,
    label: &str,
    group: &str,
) -> Result<std::result::Result<String, String>> {
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
async fn decrypts(sim: &Sim, label: &str, group: &str, ciphertext: &str) -> Result<(bool, String)> {
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

/// Start every node. In the five-node arms, A, D and E get the three
/// pre-generated key pairs sorted by agent id, so A < D < E (B and C keep
/// theirs). The swap happens before any daemon runs.
async fn start(case: &str, seed: u64, arm: Arm) -> Result<Sim> {
    let labels = arm.labels();
    let mut sim = Sim::empty(case, seed, labels)?;
    let mut provisions: BTreeMap<&str, Provision> = BTreeMap::new();
    if arm.ranked_admins() {
        let ranked = ["A", "D", "E"];
        let mut pairs = Vec::with_capacity(ranked.len());
        for label in ranked {
            pairs.push(sim.take_keys(label)?);
        }
        pairs.sort_by_key(|pair| pair.1.agent_id().0);
        for (label, (machine, agent)) in ranked.into_iter().zip(pairs) {
            provisions.insert(
                label,
                Provision {
                    machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
                    agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
                    ..Provision::default()
                },
            );
        }
        sim.fabric()
            .mark("case: admin keys reassigned so that A < D < E by agent id");
    }
    for label in labels {
        let provision = provisions.remove(label).unwrap_or_default();
        sim.start_node_with(label, provision).await?;
    }
    Ok(sim)
}

async fn scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let labels = arm.labels();
    let survivors = arm.survivors();
    mesh(sim, labels).await?;
    let group = create_group(sim, "A").await?;
    for member in labels.iter().filter(|label| **label != "A") {
        seat(sim, member, &group).await?;
    }
    for admin in arm.promoted() {
        let hex = sim.agent_hex(admin)?;
        let (status, body) = sim
            .api(
                "A",
                Method::PATCH,
                &format!("/groups/{group}/members/{hex}/role"),
                Some(json!({"role": "admin"})),
            )
            .await?;
        ensure!(status.is_success(), "promote {admin}: {status} {body}");
    }
    sim.until("every node sees every promotion", SETUP, async |s: &Sim| {
        for observer in labels {
            for admin in arm.promoted() {
                if !sees_admin(s, observer, &group, admin)
                    .await
                    .unwrap_or(false)
                {
                    return false;
                }
            }
        }
        true
    })
    .await?;
    let (b, _) = sim.ids("B")?;
    let b_hex = sim.agent_hex("B")?;
    let a_hex = sim.agent_hex("A")?;
    settled(sim, labels, &group, &b).await?;
    let base = view(sim, "A", &group, &b).await?;
    let e0 = base.epoch.context("A has no live TreeKEM group")?;
    let leaves0 = base.leaves.context("A has no live TreeKEM group")?;

    // Pre-trigger data plane: A's ciphertext opens on B and C, so a later
    // refusal on B means exclusion, not a broken path.
    let before = encrypt(sim, "A", &group).await?;
    let (b_before, c_before) = match &before {
        Ok(ciphertext) => (
            decrypts(sim, "B", &group, ciphertext).await?,
            decrypts(sim, "C", &group, ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error.clone())),
    };
    if arm.ranked_admins() {
        sim.set_online("A", false)?;
    }
    receipt.setup_done(at(sim));

    receipt.evidence(
        "treekem_group_settled_with_b_seated",
        base.lists_b
            && base.tracks_b == Some(true)
            && u32::try_from(labels.len()).ok() == Some(leaves0),
        format!("e0={e0} leaves0={leaves0}; A {}", base.describe()),
        at(sim),
    );
    receipt.evidence(
        "b_and_c_decrypt_at_e0_before_the_trigger",
        b_before.0 && c_before.0,
        format!("{}; {}", b_before.1, c_before.1),
        at(sim),
    );
    if arm.ranked_admins() {
        let mut ranked: Vec<(String, &str)> = ["A", "D", "E"]
            .into_iter()
            .map(|label| sim.agent_hex(label).map(|hex| (hex, label)))
            .collect::<Result<_>>()?;
        ranked.sort();
        let order: Vec<&str> = ranked.iter().map(|(_, label)| *label).collect();
        receipt.evidence(
            "admins_rank_a_before_d_before_e_and_a_is_held",
            order == ["A", "D", "E"],
            format!("admin agent-id order {order:?}; A is off the fabric"),
            at(sim),
        );
    }

    // t = 0.
    let trigger = sim
        .fabric()
        .mark_indexed(format!("case: t=0 trigger {arm:?}"));
    let started = sim.fabric().now();
    if arm.revokes() {
        let (status, body) = sim
            .api(
                "B",
                Method::POST,
                "/identity/revoke",
                Some(json!({"agent_id": b_hex, "reason": "w3h-1357"})),
            )
            .await?;
        ensure!(status.is_success(), "B self-revokes: {status} {body}");
        let holders: Vec<&str> = survivors.to_vec();
        let mut seen = Observations::default();
        let waited = sim
            .until(
                "the survivors hold B's revocation",
                EVIDENCE,
                async |s: &Sim| {
                    for holder in &holders {
                        match seen.observe(holds_revocation(s, holder, &b_hex)).await {
                            Some(true) => {}
                            Some(false) => return false,
                            None => return true,
                        }
                    }
                    true
                },
            )
            .await;
        if let Err(error) = waited {
            if !expired(&error) {
                return Err(error);
            }
        }
        seen.verify("the survivors hold B's revocation")?;
    } else if arm == Arm::SelfLeave {
        let (status, body) = sim
            .api("B", Method::DELETE, &format!("/groups/{group}"), None)
            .await?;
        ensure!(status.is_success(), "B leaves: {status} {body}");
    }

    // The non-designated manual request, then the early read.
    let mut manual: Option<(StatusCode, String)> = None;
    let mut early: Vec<(&str, Option<View>)> = Vec::new();
    if arm.manual() {
        let (status, body) = sim
            .api(
                "D",
                Method::DELETE,
                &format!("/groups/{group}/members/{b_hex}"),
                None,
            )
            .await?;
        manual = Some((status, body.to_string()));
        sim.within("the early read window", EARLY_READ + secs(2), async {
            tokio::time::sleep(EARLY_READ).await;
        })
        .await?;
        early = views(sim, survivors, &group, &b).await?;
    }

    // H within the arm's bound, measured from t = 0.
    let bound = arm
        .bound()
        .saturating_sub(sim.fabric().now().saturating_sub(started));
    let mut reached: Option<String> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the survivors reach H", bound, async |s: &Sim| {
            let Some(now) = seen.observe(views_now(s, survivors, &group, &b)).await else {
                return true;
            };
            let done = excluded(&now, e0, leaves0);
            if done {
                reached.get_or_insert_with(|| {
                    format!(
                        "at {} us after t=0",
                        s.fabric().now().saturating_sub(started).as_micros()
                    )
                });
            }
            done
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("the survivors reach H")?;
    let end = views(sim, survivors, &group, &b).await?;
    let h = excluded(&end, e0, leaves0);

    // Data plane after the wait: a survivor's new ciphertext opens on C
    // and not on B.
    let encryptor = survivors.first().copied().context("no survivor")?;
    let (c_after, b_after) = match encrypt(sim, encryptor, &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "B", &group, &ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error)),
    };
    let data_plane = c_after.0 && !b_after.0;

    let queued_typed = manual.as_ref().is_some_and(|(_, body)| {
        body.contains("waiting_for_designated_admin") && body.to_ascii_lowercase().contains(&a_hex)
    });
    let early_unmoved = early
        .iter()
        .all(|(_, seen)| seen.as_ref().is_some_and(|seen| seen.epoch == Some(e0)));
    let passed = match arm {
        Arm::ManualDuringWindow => queued_typed && early_unmoved && h && data_plane,
        _ => h && data_plane,
    };
    receipt.note(format!(
        "arm={arm:?} e0={e0} leaves0={leaves0}; H {}; manual={manual:?}; early: {}; \
         end: {}; after: {}; {}",
        reached.as_deref().unwrap_or("never reached"),
        describe_all(&early),
        describe_all(&end),
        c_after.1,
        b_after.1
    ));

    // The trigger reached its target.
    let (delivered_name, delivered, delivered_detail) = match arm {
        Arm::IdleRevocation | Arm::ManualDuringWindow => {
            let mut held = Vec::new();
            for holder in survivors {
                let has = sim
                    .at_instant(
                        "read a survivor's revocations",
                        holds_revocation(sim, holder, &b_hex),
                    )
                    .await??;
                held.push((*holder, has));
            }
            let all = held.iter().all(|(_, has)| *has);
            let manual_ok = !arm.manual()
                || manual
                    .as_ref()
                    .is_some_and(|(status, _)| status.is_success());
            (
                "survivors_hold_b_revocation",
                all && manual_ok,
                format!("revocation held {held:?}; manual request {manual:?}"),
            )
        }
        Arm::SelfLeave => {
            let to_a = sim
                .fabric()
                .delivered_writes_after(&sim.peer("B")?, &sim.peer("A")?, trigger)
                .len();
            let to_c = sim
                .fabric()
                .delivered_writes_after(&sim.peer("B")?, &sim.peer("C")?, trigger)
                .len();
            (
                "b_leave_reached_a_and_c",
                to_a > 0 && to_c > 0,
                format!("frames since the leave: B->A={to_a} B->C={to_c}"),
            )
        }
        Arm::ManualWithoutObligation => (
            "d_manual_remove_accepted",
            manual
                .as_ref()
                .is_some_and(|(status, _)| status.is_success()),
            format!("manual request {manual:?}"),
        ),
    };
    receipt.request_delivered(delivered_name, delivered, delivered_detail, at(sim));

    if !passed {
        let (expected, ok, observed) = match arm {
            Arm::IdleRevocation => {
                let a_tracks = end
                    .iter()
                    .find(|(label, _)| *label == "A")
                    .and_then(|(_, seen)| seen.as_ref())
                    .is_some_and(|seen| seen.tracks_b == Some(true));
                (
                    CAUSE_IDLE,
                    still_seated(&end, e0, leaves0) && a_tracks,
                    describe_all(&end),
                )
            }
            Arm::SelfLeave => (
                CAUSE_SELF_LEAVE,
                end.iter().all(|(_, seen)| {
                    seen.as_ref()
                        .is_some_and(|seen| seen.epoch == Some(e0) && seen.leaves == Some(leaves0))
                }),
                describe_all(&end),
            ),
            Arm::ManualDuringWindow => {
                let moved = early.iter().any(|(_, seen)| {
                    seen.as_ref()
                        .is_some_and(|seen| seen.epoch.is_some_and(|now| now > e0))
                });
                let accepted = manual
                    .as_ref()
                    .is_some_and(|(status, _)| status.is_success());
                (
                    CAUSE_MANUAL,
                    accepted && !queued_typed && moved,
                    format!(
                        "manual request {manual:?}; early (t+{EARLY_READ:?}): {}",
                        describe_all(&early)
                    ),
                )
            }
            Arm::ManualWithoutObligation => (
                CAUSE_NO_OBLIGATION,
                still_seated(&end, e0, leaves0),
                describe_all(&end),
            ),
        };
        receipt.cause(expected, Some(observed), ok, at(sim));
    }
    receipt.finish(arm.final_name(), passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1357 / ADR 0110 S4. Placeholders (not measured; D69, D73): completion bound \
         {S4_COMPLETION_BOUND_PLACEHOLDER:?}, W {S4_W_PLACEHOLDER:?}, \u{394} \
         {S4_DELTA_PLACEHOLDER:?}. The issuer API is B's own revocation \
         (POST /identity/revoke), the ordinary-group trigger ADR 0110 names."
    ));
    match start(case, seed, arm).await {
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
        receipt.reclassify(arm.final_name());
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

/// ADR 0110 `s4_idle_revocation_one_admin`: RED on `main` until S4 lands.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_idle_revocation_one_admin() -> Result<()> {
    expect(
        "w3h_1357_red_s4_idle_revocation_one_admin",
        0x1357_0001,
        Arm::IdleRevocation,
        Verdict::Red,
    )
    .await
}

/// ADR 0110 `s4_self_leave_crypto_only`: GREEN on `main` (#1113 / #1337)
/// and after S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_control_s4_self_leave_crypto_only() -> Result<()> {
    expect(
        "w3h_1357_control_s4_self_leave_crypto_only",
        0x1357_0002,
        Arm::SelfLeave,
        Verdict::Green,
    )
    .await
}

/// ADR 0110 `s4_fallback_rank_manual`: RED on `main` until S4 lands.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_red_s4_fallback_rank_manual() -> Result<()> {
    expect(
        "w3h_1357_red_s4_fallback_rank_manual",
        0x1357_0003,
        Arm::ManualDuringWindow,
        Verdict::Red,
    )
    .await
}

/// `s4_fallback_rank_manual`'s baseline: with no S4 obligation, D's manual
/// remove rekeys at once, before and after S4.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1357_control_s4_manual_remove_without_obligation() -> Result<()> {
    expect(
        "w3h_1357_control_s4_manual_remove_without_obligation",
        0x1357_0004,
        Arm::ManualWithoutObligation,
        Verdict::Green,
    )
    .await
}
