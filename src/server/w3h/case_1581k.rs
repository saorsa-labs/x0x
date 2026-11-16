//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_intake_and_egress`), the staged-join part: A (the owner admin) and
//! C hold an ordinary `private_secure` (TreeKEM) group; B joins through
//! A's invite. The joiner's key material is pulled: B's join-result poll
//! (every 2 s) fetches A's staged `MemberAdded`, whose `WelcomeRef` B
//! then fetches from A. From B's join until the trigger has reached A
//! and C, the case drops every frame from A and C to B except membership
//! and plane hellos, so whatever A stages or answers in that time never
//! reaches B; after the release, B's next fetch passes A's guards anew.
//!
//! - machine arm (`staged_join_machine_revoked_device_gets_no_key`): B
//!   revokes its own machine (`POST /identity/revoke`, `machine_id`).
//!   ADR 0110 §3 (L236) and D70: the revoked device gets no key; B's
//!   agent keeps its seat. Desired: once A and C hold the revocation and
//!   B's poll reaches A again, B's device installs no TreeKEM group and
//!   does not decrypt A's ciphertext through the settle window, while A
//!   still lists B Active.
//! - agent arm (`staged_join_agent_revoked_gets_no_key`): B revokes its
//!   own agent (`agent_id`). Desired: B installs no TreeKEM group and
//!   does not decrypt A's ciphertext through the settle window (the
//!   ordinary agent-revocation gate of every join artifact).
//!
//! - control arm (`control_staged_join_unrevoked_gets_its_key`): the
//!   same hold and release with no revocation; B installs the group and
//!   decrypts A's ciphertext, so the hold alone withholds nothing.
//!
//! Not covered here (named on #1581): the certificate-expiry and
//! quarantine variants of the staged join, the binding revocation, and
//! the invalid-issuer and first-join controls.
//!
//! Receipts use `w3h.receipt/1`.

#![cfg(test)]

use super::control::{create_group, invite, join, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass};
use anyhow::{ensure, Context as _};
use base64::Engine as _;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Budget for each setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Budget for A to commit B's seat while B's frames to A are held.
const STAGE: Duration = Duration::from_secs(60);
/// Budget for the revocation to reach A and C.
const EVIDENCE: Duration = Duration::from_secs(60);
/// After the release, the case watches B this long: B's poll runs every
/// 2 s, so a served join result and Welcome would land well inside it.
const SETTLE: Duration = Duration::from_secs(40);
const WATCH_STEP: Duration = Duration::from_millis(500);
const PROBE: &[u8] = b"w3h-1581k probe";

const FINAL: &str = "a_revoked_joiner_gets_no_staged_key";
const FINAL_CONTROL: &str = "an_unrevoked_joiner_gets_its_key_after_the_release";
const CAUSE_KEY_SERVED: &str = "B installed the group's TreeKEM state or decrypted A's \
                                ciphertext after the trigger: a staged join artifact was served \
                                to a revoked recipient";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trigger {
    Machine,
    Agent,
    /// The control: the same hold and release with no revocation.
    NoneControl,
}

/// Whether `label` lists `hex` as an Active member of `group`.
async fn lists(sim: &Sim, label: &str, group: &str, hex: &str) -> bool {
    let Ok(state) = sim.state(label) else {
        return false;
    };
    let groups = state.named_groups.read().await;
    crate::server::resolve_group_entry_locked(&groups, group).is_some_and(|(_, info)| {
        info.active_members()
            .any(|member| member.agent_id.eq_ignore_ascii_case(hex))
    })
}

/// Whether `label` holds a live TreeKEM group for `group`, and its epoch.
async fn treekem_epoch(sim: &Sim, label: &str, group: &str) -> Result<Option<u64>> {
    let state = sim.state(label)?;
    let key = {
        let groups = state.named_groups.read().await;
        match crate::server::resolve_group_entry_locked(&groups, group) {
            Some((key, _)) => key.to_string(),
            None => group.to_string(),
        }
    };
    let live = state.treekem_groups.read().await.get(&key).cloned();
    Ok(match live {
        Some(live) => Some(live.lock().await.epoch()),
        None => None,
    })
}

/// A invites `member`; A lists it and it reports itself active.
async fn seat(sim: &Sim, member: &str, group: &str) -> Result<()> {
    let link = invite(sim, "A", group).await?;
    join(sim, member, &link).await?;
    let hex = sim.agent_hex(member)?;
    sim.until(&format!("{member} seated"), SETUP, async |s: &Sim| {
        lists(s, "A", group, &hex).await
            && super::home::membership_state(s, member, group)
                .await
                .ok()
                .flatten()
                .as_deref()
                == Some("active")
    })
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
async fn encrypt(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/secure/encrypt"),
            Some(json!({"payload_b64": BASE64.encode(PROBE)})),
        )
        .await?;
    match body["ciphertext_b64"].as_str() {
        Some(ciphertext) if status.is_success() && body["ok"] != false => {
            Ok(ciphertext.to_string())
        }
        _ => anyhow::bail!("{label} encrypt: {status} {body}"),
    }
}

/// Whether `label` recovers the probe from `ciphertext`, with the reply.
async fn decrypts(sim: &Sim, label: &str, group: &str, ciphertext: &str) -> Result<(bool, String)> {
    let (status, body) = sim
        .request(
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

/// Drops every frame from A or C to B, except membership and plane
/// hellos, while `on` is set; counts what it drops.
struct PollHold {
    on: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl PollHold {
    fn install(sim: &Sim) -> Result<Self> {
        let (b, a, c) = (sim.peer("B")?.0, sim.peer("A")?.0, sim.peer("C")?.0);
        let on = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (rule_on, rule_dropped) = (Arc::clone(&on), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            if write.lane.dst != b
                || (write.lane.src != a && write.lane.src != c)
                || !rule_on.load(Ordering::SeqCst)
            {
                return Fault::Pass;
            }
            match write.lane.class {
                LaneClass::Membership | LaneClass::PlaneHello => Fault::Pass,
                _ => {
                    rule_dropped.fetch_add(1, Ordering::SeqCst);
                    Fault::Drop
                }
            }
        });
        sim.fabric()
            .mark("fault: frames from A and C to B dropped (join artifacts held)");
        Ok(Self { on, dropped })
    }

    fn release(&self, sim: &Sim) -> usize {
        self.on.store(false, Ordering::SeqCst);
        sim.fabric()
            .mark("fault: frames from A and C to B released");
        self.dropped.load(Ordering::SeqCst)
    }
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt, trigger: Trigger) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, LABELS).await?;
    let group = create_group(sim, "A").await?;
    seat(sim, "C", &group).await?;
    let e0 = treekem_epoch(sim, "A", &group)
        .await?
        .context("A has no live TreeKEM group")?;
    let b_hex = sim.agent_hex("B")?;
    let b_machine_hex = hex::encode(sim.peer("B")?.0);
    receipt.setup_done(at(sim));

    // Stage B's join: nothing from A or C reaches B (but membership), so
    // A commits B's seat and stages its artifacts, and B gets none yet.
    let link = invite(sim, "A", &group).await?;
    let hold = PollHold::install(sim)?;
    join(sim, "B", &link).await?;
    sim.until("A commits B's seat (staged)", STAGE, async |s: &Sim| {
        lists(s, "A", &group, &b_hex).await
    })
    .await
    .context("INFRA: A never committed B's seat from the gossiped join")?;
    let staged_epoch = treekem_epoch(sim, "B", &group).await?;
    receipt.evidence(
        "a_staged_b_join_and_b_holds_no_key",
        staged_epoch.is_none(),
        format!("A lists B; B's TreeKEM epoch {staged_epoch:?}; A's e0={e0}"),
        at(sim),
    );
    ensure!(
        staged_epoch.is_none(),
        "INFRA: B reached the group before the trigger (the hold missed a path)"
    );

    // The trigger: B revokes its own machine or agent (none in the
    // control).
    let (subject, body) = match trigger {
        Trigger::Machine => (
            b_machine_hex.clone(),
            json!({"machine_id": b_machine_hex, "reason": "w3h-1581k"}),
        ),
        Trigger::Agent => (
            b_hex.clone(),
            json!({"agent_id": b_hex, "reason": "w3h-1581k"}),
        ),
        Trigger::NoneControl => {
            return release_and_watch(sim, receipt, trigger, &group, &b_hex, hold).await;
        }
    };
    sim.fabric()
        .mark(format!("case: t=0 B revokes its own {trigger:?}"));
    let (status, reply) = sim
        .api("B", Method::POST, "/identity/revoke", Some(body))
        .await?;
    ensure!(status.is_success(), "B revoke: {status} {reply}");
    let mut seen = Observations::default();
    let held = sim
        .until("A and C hold B's revocation", EVIDENCE, async |s: &Sim| {
            for holder in ["A", "C"] {
                match seen.observe(holds_revocation(s, holder, &subject)).await {
                    Some(true) => {}
                    Some(false) => return false,
                    None => return true,
                }
            }
            true
        })
        .await;
    seen.verify("the holders hold B's revocation")?;
    held.context("INFRA: B's revocation never reached A and C within the budget")?;
    receipt.evidence(
        "a_and_c_hold_b_revocation",
        true,
        format!("{trigger:?} subject {subject}"),
        at(sim),
    );

    release_and_watch(sim, receipt, trigger, &group, &b_hex, hold).await
}

/// Releases the hold and watches B for [`SETTLE`]; then the verdict.
async fn release_and_watch(
    sim: &mut Sim,
    receipt: &mut Receipt,
    trigger: Trigger,
    group: &str,
    b_hex: &str,
    hold: PollHold,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    // Release B's poll; watch B for SETTLE.
    // Receiver-side evidence (#1956 review): A's join-result and Welcome
    // fetch admissions log each request that reaches them; a raw B->A
    // frame count would also count membership and `MemberJoined` retries.
    // B is the only joiner with a staged Welcome on A at this point, and
    // after the release B can learn `MemberAdded` by gossip and fetch the
    // Welcome directly, so both handlers count.
    let fetches = |sim: &Sim| -> Result<(usize, usize)> {
        let state = sim.state("A")?;
        Ok((
            state.join_result_fetch_admission.asked_for_member(b_hex),
            state.welcome_fetch_admission.asked_total(),
        ))
    };
    let (results_before, welcomes_before) = fetches(sim)?;
    let dropped = hold.release(sim);
    let released = sim
        .fabric()
        .mark_indexed("case: B's join-result poll released");
    let mut served: Option<String> = None;
    let deadline = sim.fabric().now() + SETTLE;
    while sim.fabric().now() < deadline {
        if let Some(epoch) = treekem_epoch(sim, "B", group).await? {
            served = Some(format!("B installed the TreeKEM group at epoch {epoch}"));
            break;
        }
        sim.within("watch step", WATCH_STEP + secs(1), async {
            tokio::time::sleep(WATCH_STEP).await;
        })
        .await?;
    }
    let ciphertext = encrypt(sim, "A", group).await?;
    let (opened, why) = decrypts(sim, "B", group, &ciphertext).await?;
    if opened && served.is_none() {
        served = Some(why.clone());
    }
    let b_to_a = sim
        .fabric()
        .delivered_writes_after(&sim.peer("B")?, &sim.peer("A")?, released)
        .len();
    let (results_after, welcomes_after) = fetches(sim)?;
    let results = results_after.saturating_sub(results_before);
    let welcomes = welcomes_after.saturating_sub(welcomes_before);
    let fetched = results + welcomes;
    receipt.request_delivered(
        "a_received_b_join_result_fetches_after_the_release",
        dropped > 0 && fetched > 0,
        format!(
            "dropped A/C->B frames {dropped}; at A since the release: {results} join-result \
             fetches from B (before: {results_before}), {welcomes} Welcome fetches (before: \
             {welcomes_before}); B->A frames since release {b_to_a}"
        ),
        at(sim),
    );
    let a_lists_b = lists(sim, "A", group, b_hex).await;
    receipt.note(format!(
        "{trigger:?} arm: A lists B at the end {a_lists_b}; B {why}; served {served:?}"
    ));
    if trigger == Trigger::Machine {
        receipt.evidence(
            "a_still_lists_b_after_the_machine_revocation",
            a_lists_b,
            format!("D70: the agent keeps its seat; A lists B {a_lists_b}"),
            at(sim),
        );
    }
    if trigger == Trigger::NoneControl {
        receipt.finish(FINAL_CONTROL, served.is_some() && opened, at(sim));
        return Ok(());
    }
    if let Some(detail) = &served {
        receipt.cause(CAUSE_KEY_SERVED, Some(detail.clone()), true, at(sim));
    }
    receipt.finish(FINAL, served.is_none(), at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, trigger: Trigger) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 `s4_intake_and_egress`, staged join with a {trigger:?} revocation."
    ));
    match Sim::start(case, seed, LABELS).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, trigger).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(if trigger == Trigger::NoneControl {
            FINAL_CONTROL
        } else {
            FINAL
        });
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, trigger: Trigger, want: Verdict) -> Result<()> {
    let receipt = run(case, seed, trigger).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

const LABELS: &[&str] = &["A", "B", "C"];

/// ADR 0110 `s4_intake_and_egress`, staged join, machine revocation (D70).
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
fn w3h_1581k_staged_join_machine_revoked_device_gets_no_key() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581k_staged_join_machine_revoked_device_gets_no_key",
            0x1581_0040,
            Trigger::Machine,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_intake_and_egress`, staged join, agent revocation.
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
fn w3h_1581k_staged_join_agent_revoked_gets_no_key() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581k_staged_join_agent_revoked_gets_no_key",
            0x1581_0041,
            Trigger::Agent,
            Verdict::Green,
        )
        .await
    })
}

/// The control for the arms above: the same hold and release with no
/// revocation; B must then get its key.
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
fn w3h_1581k_control_staged_join_unrevoked_gets_its_key() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            "w3h_1581k_control_staged_join_unrevoked_gets_its_key",
            0x1581_0042,
            Trigger::NoneControl,
            Verdict::Green,
        )
        .await
    })
}
