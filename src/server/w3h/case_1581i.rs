//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_intake_and_egress`), the machine-revocation part (D70): A (the
//! owner admin), B and C in an ordinary `private_secure` (TreeKEM)
//! group. At t = 0 B revokes its own machine through the public
//! `POST /identity/revoke` route (`machine_id`). ADR 0110 §1 and §3:
//! a machine revocation denies that device only; the portable agent
//! keeps its seat until the agent itself is revoked, so S4 opens no row
//! and no exclusion follows.
//!
//! - control arm (`control_machine_revoked_device_keeps_its_seat`):
//!   once A and C hold B's machine revocation, B stays an Active member
//!   on A's and C's rosters through one designated window plus the
//!   completion bound plus a margin; no S4 row for B appears on A or C;
//!   B's agent is not revoked anywhere; the group's state revision (r0)
//!   and TreeKEM epoch (e0) do not move.
//! - egress arm (`egress_machine_revoked_device_gets_no_new_key`): the
//!   same trigger, then A rotates the group key by removing C through
//!   the public remove route. ADR 0110 §3 (L236): a machine revocation
//!   blocks every key delivery to the revoked device, so B's device must
//!   not reach the new epoch: B does not decrypt A's ciphertext of the
//!   rotated epoch, while A's roster still lists B. RED on `main`
//!   ([`CAUSE_KEY_DELIVERED`]): the TreeKEM commit encrypts its path
//!   secrets to B's leaf, which stays with B's seat, so B's revoked
//!   device decrypts the new epoch.
//!
//! Not covered here (named on #1581): the agent-trigger, certificate
//! expiry and quarantine variants of the row, the staged join artifacts
//! (invite, poll, Welcome) and their scheduled resends, the binding
//! revocation, and the invalid-issuer and first-join controls. The
//! typed refusal of a request from a revoked device is #1657's
//! in-process test (`issue1657_typed_refusal_catchup`); a send to a
//! revoked machine answering `recipient_machine_revoked` is #1918's.
//!
//! Receipts use `w3h.receipt/1`.

#![cfg(test)]

use super::control::{create_group, invite, join, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::eviction::S4Timing;
use anyhow::{ensure, Context as _};
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for the machine revocation to reach A and C.
const EVIDENCE: Duration = Duration::from_secs(60);
/// Margin past W + the completion bound for the seat watch.
const MARGIN: Duration = Duration::from_secs(5);
/// Budget for the rotation (C's removal) to reach A's head.
const ROTATION: Duration = Duration::from_secs(60);
/// After the rotation, the case waits this long before B's decrypt, so
/// any delivery to B's device has had its chance.
const SETTLE: Duration = Duration::from_secs(30);
/// How often the seat watch reads.
const WATCH_STEP: Duration = Duration::from_millis(500);
const PROBE: &[u8] = b"w3h-1581i probe";

const FINAL_CONTROL: &str = "a_machine_revoked_device_keeps_its_agent_seat";
const FINAL_EGRESS: &str = "a_machine_revoked_device_gets_no_key_of_a_later_epoch";
const CAUSE_SEAT_LOST: &str = "B's agent lost its seat after its machine revocation: a roster \
                               dropped B, B's agent was revoked, or the epoch moved";
const CAUSE_S4_ROW: &str = "S4 opened a row for B after a machine-only revocation (D70: the \
                            device is denied, the agent keeps its seat)";
const CAUSE_KEY_DELIVERED: &str = "B's machine-revoked device reached the rotated epoch and \
                                   decrypted A's new ciphertext (ADR 0110 §3 L236: no key \
                                   delivery to a revoked machine)";

/// `label`'s view of `group`.
#[derive(Debug, Clone)]
struct View {
    state_revision: u64,
    lists_b: bool,
    lists_c: bool,
    epoch: Option<u64>,
}

impl View {
    fn describe(&self) -> String {
        format!(
            "state={} lists_b={} lists_c={} epoch={:?}",
            self.state_revision, self.lists_b, self.lists_c, self.epoch
        )
    }
}

async fn try_view_now(sim: &Sim, label: &str, group: &str) -> Result<Option<View>> {
    let (b_hex, c_hex) = (sim.agent_hex("B")?, sim.agent_hex("C")?);
    let state = sim.state(label)?;
    let (key, view) = {
        let groups = state.named_groups.read().await;
        let Some((key, info)) = crate::server::resolve_group_entry_locked(&groups, group) else {
            return Ok(None);
        };
        let lists = |hex: &str| {
            info.active_members()
                .any(|member| member.agent_id.eq_ignore_ascii_case(hex))
        };
        let view = View {
            state_revision: info.state_revision,
            lists_b: lists(&b_hex),
            lists_c: lists(&c_hex),
            epoch: None,
        };
        (key.to_string(), view)
    };
    let live = state.treekem_groups.read().await.get(&key).cloned();
    let Some(live) = live else {
        return Ok(Some(view));
    };
    let epoch = live.lock().await.epoch();
    Ok(Some(View {
        epoch: Some(epoch),
        ..view
    }))
}

async fn view_now(sim: &Sim, label: &str, group: &str) -> Result<View> {
    try_view_now(sim, label, group)
        .await?
        .with_context(|| format!("{label} has no record of the group"))
}

/// A invites `member`; A lists it and it reports itself active.
async fn seat(sim: &Sim, member: &str, group: &str) -> Result<()> {
    let link = invite(sim, "A", group).await?;
    join(sim, member, &link).await?;
    let hex = sim.agent_hex(member)?;
    sim.until(&format!("{member} seated"), SETUP, async |s: &Sim| {
        let on_a = {
            let Ok(state) = s.state("A") else {
                return false;
            };
            let groups = state.named_groups.read().await;
            crate::server::resolve_group_entry_locked(&groups, group).is_some_and(|(_, info)| {
                info.active_members()
                    .any(|m| m.agent_id.eq_ignore_ascii_case(&hex))
            })
        };
        on_a && super::home::membership_state(s, member, group)
            .await
            .ok()
            .flatten()
            .as_deref()
            == Some("active")
    })
    .await
}

/// Every label holds A's state revision and TreeKEM epoch.
async fn settled(sim: &Sim, labels: &[&str], group: &str) -> Result<()> {
    sim.until(
        "every node holds A's head and epoch",
        SETUP,
        async |s: &Sim| {
            let Ok(authority) = view_now(s, "A", group).await else {
                return false;
            };
            if authority.epoch.is_none() {
                return false;
            }
            for label in labels {
                match view_now(s, label, group).await {
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

/// `label`'s public S4 row for `target_hex` in `group`, if any. A failed
/// read or a body without the `revocation_evictions` array is an error
/// (INFRA), never "no row": "no S4 row for B" needs a read that could
/// have shown one (#1928 review).
async fn s4_row(
    sim: &Sim,
    label: &str,
    group: &str,
    target_hex: &str,
) -> Result<Option<serde_json::Value>> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "INFRA: {label} GET /groups/{group}: {status} {body}"
    );
    let rows = body["revocation_evictions"]
        .as_array()
        .with_context(|| format!("INFRA: {label} GET /groups/{group}: no revocation_evictions"))?;
    Ok(rows
        .iter()
        .find(|row| row["target"].as_str() == Some(target_hex))
        .cloned())
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

/// One run: setup, B's machine revocation, the seat watch, and (with
/// `rotate`) A's rotation and B's decrypt of the new epoch.
async fn scenario(
    sim: &mut Sim,
    receipt: &mut Receipt,
    labels: &[&str],
    rotate: bool,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, labels).await?;
    let group = create_group(sim, "A").await?;
    for member in labels.iter().filter(|label| **label != "A") {
        seat(sim, member, &group).await?;
    }
    settled(sim, labels, &group).await?;
    let base = view_now(sim, "A", &group).await?;
    let r0 = base.state_revision;
    let e0 = base.epoch.context("A has no live TreeKEM group")?;
    let before = encrypt(sim, "A", &group).await?;
    let b_before = match &before {
        Ok(ciphertext) => decrypts(sim, "B", &group, ciphertext).await?,
        Err(error) => (false, error.clone()),
    };
    receipt.setup_done(at(sim));
    receipt.evidence(
        "treekem_group_settled_with_b_and_c_seated",
        base.lists_b && base.lists_c,
        format!("r0={r0} e0={e0}; A {}", base.describe()),
        at(sim),
    );
    receipt.evidence(
        "b_decrypts_at_e0_before_the_trigger",
        b_before.0,
        b_before.1,
        at(sim),
    );

    // t = 0: B revokes its own machine.
    let b_machine_hex = hex::encode(sim.peer("B")?.0);
    let b_hex = sim.agent_hex("B")?;
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            "/identity/revoke",
            Some(json!({"machine_id": b_machine_hex, "reason": "w3h-1581i"})),
        )
        .await?;
    receipt.request_delivered(
        "b_machine_revoke_answered",
        status.is_success(),
        format!("B POST /identity/revoke machine: {status} {body}"),
        at(sim),
    );
    ensure!(status.is_success(), "B machine revoke: {status} {body}");

    let mut seen = Observations::default();
    let held = sim
        .until(
            "A and C hold B's machine revocation",
            EVIDENCE,
            async |s: &Sim| {
                for holder in ["A", "C"] {
                    match seen
                        .observe(holds_revocation(s, holder, &b_machine_hex))
                        .await
                    {
                        Some(true) => {}
                        Some(false) => return false,
                        None => return true,
                    }
                }
                true
            },
        )
        .await;
    match held {
        Ok(()) => seen.verify("the holders hold B's machine revocation")?,
        Err(error) if expired(&error) => {
            seen.verify("the holders hold B's machine revocation")?;
            return Err(error
                .context("INFRA: B's machine revocation never reached A and C within the budget"));
        }
        Err(error) => return Err(error),
    }
    receipt.evidence(
        "a_and_c_hold_b_machine_revocation",
        true,
        format!("subject {b_machine_hex}"),
        at(sim),
    );

    // The seat watch: W + completion bound + margin from the holders'
    // receipt, so a misread agent trigger would have sealed by its end.
    let timing = S4Timing::default();
    let watch = timing.designated_window + timing.completion_bound + MARGIN;
    let deadline = sim.fabric().now() + watch;
    let mut seat_lost: Option<String> = None;
    let mut row_seen: Option<String> = None;
    while sim.fabric().now() < deadline {
        for label in ["A", "C"] {
            let view = view_now(sim, label, &group).await?;
            if seat_lost.is_none()
                && (!view.lists_b || view.epoch != Some(e0) || view.state_revision != r0)
            {
                seat_lost = Some(format!("{label}: {}", view.describe()));
            }
            if row_seen.is_none() {
                if let Some(row) = s4_row(sim, label, &group, &b_hex).await? {
                    row_seen = Some(format!("{label}: {row}"));
                }
            }
            let agent_revoked = sim
                .state(label)?
                .agent
                .revocation_set()
                .read()
                .await
                .is_agent_revoked(&crate::identity::AgentId(
                    hex::decode(&b_hex)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .context("B's agent id")?,
                ));
            if seat_lost.is_none() && agent_revoked {
                seat_lost = Some(format!("{label} holds B's agent as revoked"));
            }
        }
        sim.within("seat watch step", WATCH_STEP + secs(1), async {
            tokio::time::sleep(WATCH_STEP).await;
        })
        .await?;
    }
    receipt.note(format!(
        "seat watch for {watch:?} after the holders' receipt: seat lost {seat_lost:?}; S4 row \
         for B {row_seen:?}"
    ));
    let seat_kept = seat_lost.is_none() && row_seen.is_none();
    if !rotate {
        // A cause stage records an observed failure (`ok`: the expected
        // cause was seen), so a RED names what broke.
        if row_seen.is_some() {
            receipt.cause(CAUSE_S4_ROW, row_seen, true, at(sim));
        }
        if seat_lost.is_some() {
            receipt.cause(CAUSE_SEAT_LOST, seat_lost, true, at(sim));
        }
        receipt.finish(FINAL_CONTROL, seat_kept, at(sim));
        return Ok(());
    }
    ensure!(
        seat_kept,
        "the seat was not kept before the rotation: {seat_lost:?} {row_seen:?}"
    );

    // The egress arm: A rotates by removing C.
    let c_hex = sim.agent_hex("C")?;
    let (status, body) = sim
        .api(
            "A",
            Method::DELETE,
            &format!("/groups/{group}/members/{c_hex}"),
            None,
        )
        .await?;
    receipt.request_delivered(
        "a_remove_c_answered",
        status.is_success(),
        format!("A DELETE member C: {status} {body}"),
        at(sim),
    );
    ensure!(status.is_success(), "A remove C: {status} {body}");
    sim.until("A's epoch moves past e0", ROTATION, async |s: &Sim| {
        view_now(s, "A", &group)
            .await
            .is_ok_and(|view| view.epoch.is_some_and(|epoch| epoch > e0) && !view.lists_c)
    })
    .await
    .context("INFRA: A's rotation never moved its epoch")?;
    sim.within("post-rotation settle", SETTLE + secs(2), async {
        tokio::time::sleep(SETTLE).await;
    })
    .await?;
    let a_after = view_now(sim, "A", &group).await?;
    let b_after = try_view_now(sim, "B", &group).await?;
    let after = encrypt(sim, "A", &group).await?;
    let b_decrypt = match &after {
        Ok(ciphertext) => decrypts(sim, "B", &group, ciphertext).await?,
        Err(error) => {
            return Err(anyhow::anyhow!(
                "A could not encrypt after the rotation: {error}"
            ))
        }
    };
    receipt.evidence(
        "a_rotated_and_still_lists_b",
        a_after.lists_b && !a_after.lists_c,
        format!("A {}", a_after.describe()),
        at(sim),
    );
    receipt.note(format!(
        "after the rotation: A {}; B {}; {}",
        a_after.describe(),
        b_after
            .as_ref()
            .map_or_else(|| "no record".to_string(), View::describe),
        b_decrypt.1
    ));
    let delivered = b_decrypt.0;
    if delivered {
        receipt.cause(
            CAUSE_KEY_DELIVERED,
            Some(b_decrypt.1.clone()),
            true,
            at(sim),
        );
    }
    receipt.finish(FINAL_EGRESS, !delivered, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, rotate: bool) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 `s4_intake_and_egress`, machine-revocation part (D70). Timing \
         from S4Timing::default(): {:?}.",
        S4Timing::default()
    ));
    match Sim::start(case, seed, LABELS).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, LABELS, rotate).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    let final_name = if rotate { FINAL_EGRESS } else { FINAL_CONTROL };
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(final_name);
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, rotate: bool, want: Verdict) -> Result<()> {
    let receipt = run(case, seed, rotate).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    // An expected RED is eligible only with the named gap observed.
    if want == Verdict::Red {
        ensure!(
            receipt.named_causes() == [CAUSE_KEY_DELIVERED],
            "{case}: RED for another cause: {:?}",
            receipt.named_causes()
        );
    }
    Ok(())
}

const LABELS: &[&str] = &["A", "B", "C"];

/// ADR 0110 `s4_intake_and_egress`, D70 control: a machine-only
/// revocation keeps the agent's seat; S4 opens no row.
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
fn w3h_1581i_control_machine_revoked_device_keeps_its_seat() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581i_control_machine_revoked_device_keeps_its_seat",
            0x1581_0020,
            false,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_intake_and_egress`, D70 guarded egress: after a later
/// rotation the machine-revoked device must get no key of the new epoch.
/// RED on `main` with [`CAUSE_KEY_DELIVERED`]: a TreeKEM rotation
/// encrypts its path secrets to every leaf in the tree, and B's leaf (its
/// device's KeyPackage) stays while B keeps its seat, so B's revoked
/// device reaches the new epoch through the published commit. Closing it
/// needs a design choice (the leaf belongs to the revoked device while
/// the seat belongs to the agent) that is tracked on #1581.
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
fn w3h_1581i_egress_machine_revoked_device_gets_no_new_key() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581i_egress_machine_revoked_device_gets_no_new_key",
            0x1581_0021,
            true,
            // RED on main (CAUSE_KEY_DELIVERED); see the doc above.
            Verdict::Red,
        )
        .await
    })
}
