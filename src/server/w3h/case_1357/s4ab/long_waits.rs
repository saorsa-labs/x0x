//! W3-H cases for #1581: the two ADR 0110 S4 runs where the owner never
//! acts, so the group keeps a typed wait and no other exit fires (D152,
//! "OwnerCertified group waiting for its owner").
//!
//! The ADR runs these for 24 virtual hours. Idle virtual time costs about
//! 0.056 s of real time per virtual second in the 12-CPU Lima VM (run (9)
//! with a 2 h hold took 498 s), so 24 h is about 81 min per run there and
//! about 160 min on a CI runner: one run does not fit a shard's test
//! deadline. The arms hold for [`LONG_WAIT`] (1 h). That is longer than
//! every S4 timer (W, the completion bound, the fallback stagger, the 60 s
//! metadata resend and the 900 s catch-up round), so a wait that a timer
//! ends or replaces fails inside it.
//!
//! - `on_demand_1581n_certificate_rebind_run9_owner_never_renews`
//!   (`s4_certificate_rebind` run (9); nodes A, D, B, C). A Home that A
//!   provisions; admins A < D by agent id; B is a member and C a survivor
//!   with a non-expiring certificate. The certificates of A (the owner
//!   device), D and B have one `not_after` N, 600 s after the first of them
//!   is issued. U never renews. Desired: nothing moves before raw N; from
//!   the admins' own trigger N + τ every node lists B's S4 row waiting with
//!   `waiting_for_admin_certificate_renewal` naming A and D. Then, sampled
//!   every [`SAMPLE`] until N + [`LONG_WAIT`], each node keeps that wait, every S4
//!   row it lists waits for a renewal, and its state revision does not
//!   move (no removal of B, no rebind and no rekey). The ADR's "for the
//!   whole run" is read from N + τ: before that no node treats an admin as
//!   expired (`self_rebind_rule`, #1533 Codex P2).
//! - `on_demand_1581n_owner_recovery_owner_silent` (`s4_owner_recovery`, the
//!   variant "O never signs over 24 virtual hours"; nodes A, B, C). A Home
//!   with A as its only admin; every device holds U, and no device calls
//!   the mandate route. At t = 0 A revokes its own agent. Desired: once B
//!   and C hold the record, they show `waiting_for_eligible_admin_revocation`
//!   with exit `owner_recovery` naming A, and, sampled every [`SAMPLE`]
//!   until t + [`LONG_WAIT`], both keep it, both sends are refused with it, their
//!   state revision does not move, A stays listed and B does not become an
//!   admin.
//!
//! A failed sample is RED with a typed cause: the wait was lost, or a
//! commit landed (another exit fired). Anything else is INFRA. Both arms
//! run on demand only, not in the W3-H gate: they confirm behaviour the
//! code already has, and a gate shard for them costs runner time on every
//! train. The command is in `tests/AGENTS.md`. Run (9) follows the
//! daemons' wall clock and needs the shim.
//!
//! Red proofs (never committed): `rebind::row_override` returning `None`
//! made run (9) RED for [`CAUSE_RENEWAL_WAIT_LOST`]; an
//! `admin_availability` of `null` in the public status made the owner
//! recovery arm RED for [`CAUSE_RECOVERY_WAIT_LOST`].

use super::expiry_skew::stall_watchdog;
use super::*;

const FOUR_D: &[&str] = &["A", "D", "B", "C"];
/// The certificates of A, D and B expire this long after the first of
/// them is issued (the ADR's t = 600 s).
const NOT_AFTER_OFFSET: u64 = 600;
/// How long each arm keeps its wait.
const LONG_WAIT: Duration = Duration::from_secs(60 * 60);
/// The case reads every node this often during [`LONG_WAIT`].
const SAMPLE: Duration = Duration::from_secs(5 * 60);

const FINAL_RUN9: &str = "every_member_keeps_the_renewal_wait_and_no_exit_fires";
const FINAL_SILENT: &str = "every_member_keeps_the_owner_recovery_wait_and_no_exit_fires";

const CAUSE_RENEWAL_WAIT_LOST: &str = "every admin's certificate expired and U never renewed, \
                                       but a node did not keep \
                                       waiting_for_admin_certificate_renewal naming A and D on \
                                       B's row (or listed another wait)";
const CAUSE_RENEWAL_EXIT_FIRED: &str = "every admin's certificate expired and U never renewed, \
                                        but a commit landed (a removal, rebind or rekey; D152)";
const CAUSE_EARLY: &str = "a node moved B's seat before raw not_after";
const CAUSE_RECOVERY_WAIT_LOST: &str = "the sole admin A is revoked and the owner never signs, \
                                        but B or C did not keep \
                                        waiting_for_eligible_admin_revocation with exit \
                                        owner_recovery naming A, or a send was not refused \
                                        with it";
const CAUSE_RECOVERY_EXIT_FIRED: &str = "the sole admin A is revoked and the owner never signs, \
                                         but a commit landed on B or C, A left the roster or B \
                                         became an admin (D152)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LongWait {
    /// `s4_certificate_rebind` run (9).
    NeverRenewed,
    /// `s4_owner_recovery` with O silent.
    OwnerSilent,
}

impl LongWait {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::NeverRenewed => FOUR_D,
            Self::OwnerSilent => THREE,
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::NeverRenewed => FINAL_RUN9,
            Self::OwnerSilent => FINAL_SILENT,
        }
    }
}

/// One sample's outcome.
#[derive(Debug, Default)]
struct Sample {
    /// Every waiting node shows the typed wait (and, for run (9), lists no
    /// row with another cause; for the owner recovery, its send is refused
    /// with it).
    waits: bool,
    /// No node's state revision moved, and the seat state is unchanged.
    unmoved: bool,
    detail: String,
}

/// Run (9): every label lists B's row waiting for a renewal naming
/// `admins`, every row it lists has that cause, and its state revision is
/// `rev0` with B Active on digest `d0`.
async fn renewal_sample(
    sim: &Sim,
    group: &str,
    b: &AgentId,
    b_hex: &str,
    admins: &[String],
    rev0: u64,
    d0: &str,
) -> Sample {
    let mut out = Sample {
        waits: true,
        unmoved: true,
        detail: String::new(),
    };
    let mut seen = Vec::with_capacity(FOUR_D.len());
    for label in FOUR_D {
        match group_body(sim, label, group).await {
            Ok(body) => {
                let rows = body["revocation_evictions"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let only_renewal = rows
                    .iter()
                    .all(|row| row["waiting"]["cause"] == ADMIN_CERTIFICATE_RENEWAL);
                out.waits &= waits_for_renewal(&body, b_hex, admins) && only_renewal;
                seen.push(format!("{label} rows: {rows:?}"));
            }
            Err(error) => {
                out.waits = false;
                seen.push(format!("{label}: {error:#}"));
            }
        }
    }
    match seats_now(sim, FOUR_D, group, b).await {
        Ok(now) => {
            out.unmoved = all_bind(&now, d0)
                && now.iter().all(|(_, seat)| {
                    seat.as_ref()
                        .is_some_and(|seat| seat.active() && seat.view.state_revision == rev0)
                });
            seen.push(format!("seats: {}", describe_seats(&now)));
        }
        Err(error) => {
            out.unmoved = false;
            seen.push(format!("seats: {error:#}"));
        }
    }
    out.detail = seen.join("; ");
    out
}

/// The owner-recovery arm: B and C show the wait naming A and refuse a
/// send with it; their state revision is `rev0`, A is still listed and B
/// is not an admin.
async fn recovery_sample(sim: &Sim, group: &str, a: &AgentId, a_hex: &str, rev0: u64) -> Sample {
    let mut out = Sample {
        waits: true,
        unmoved: true,
        detail: String::new(),
    };
    let mut seen = Vec::with_capacity(4);
    for label in ["B", "C"] {
        match group_body(sim, label, group).await {
            Ok(body) => {
                out.waits &= waits_for_owner_recovery(&body, a_hex);
                seen.push(format!("{label}: {}", body["admin_availability"]));
            }
            Err(error) => {
                out.waits = false;
                seen.push(format!("{label}: {error:#}"));
            }
        }
        match sim
            .request(
                label,
                Method::POST,
                &format!("/groups/{group}/secure/encrypt"),
                Some(json!({"payload_b64": BASE64.encode(PROBE)})),
            )
            .await
        {
            Ok((status, body)) => {
                out.waits &=
                    status == StatusCode::CONFLICT && body["error"] == ELIGIBLE_ADMIN_REVOCATION;
                seen.push(format!("{label} send: {status} {}", body["error"]));
            }
            Err(error) => {
                out.waits = false;
                seen.push(format!("{label} send: {error:#}"));
            }
        }
    }
    match views_now(sim, &["B", "C"], group, a).await {
        Ok(now) => {
            let b_admin = sees_admin(sim, "B", group, "B").await.unwrap_or(true)
                || sees_admin(sim, "C", group, "B").await.unwrap_or(true);
            out.unmoved = !b_admin
                && now.iter().all(|(_, seen)| {
                    seen.as_ref()
                        .is_some_and(|seen| seen.lists_b && seen.state_revision == rev0)
                });
            seen.push(format!(
                "about A: {}; B admin {b_admin}",
                describe_all(&now)
            ));
        }
        Err(error) => {
            out.unmoved = false;
            seen.push(format!("views: {error:#}"));
        }
    }
    out.detail = seen.join("; ");
    out
}

/// Samples every [`SAMPLE`] until the wall clock reaches `until_ms`.
/// Returns the first failed sample, if any, and how many passed.
async fn hold<F>(sim: &Sim, until_ms: u64, mut sample: F) -> Result<(Option<Sample>, usize)>
where
    F: AsyncFnMut(&Sim) -> Sample,
{
    let mut passed = 0;
    loop {
        let now = sim.at_instant("read every node", sample(sim)).await?;
        if !(now.waits && now.unmoved) {
            return Ok((Some(now), passed));
        }
        passed += 1;
        let left = until_ms.saturating_sub(wall_ms());
        if left == 0 {
            return Ok((None, passed));
        }
        let step = Duration::from_millis(left).min(SAMPLE);
        pause(sim, "the next sample of the long wait", step).await?;
    }
}

async fn run9(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    if sim.shim.is_none() {
        bail!(
            "run (9) needs the W3-H shim: the expiry follows the daemons' wall clock, which \
             without the shim does not move with virtual time"
        );
    }
    sim.rank_keys(&["A", "D"])?;
    let (home, not_after) =
        home_expiring(sim, FOUR_D, &["A", "D", "B"], NOT_AFTER_OFFSET, &["D"]).await?;
    let n = not_after.context("the certificates' not_after")?;
    let group = home.gid.clone();
    let (b, _) = sim.ids("B")?;
    let b_hex = sim.agent_hex("B")?;
    let admins: Vec<String> = ["A", "D"]
        .into_iter()
        .map(|label| sim.agent_hex(label))
        .collect::<Result<_>>()?;
    settled(sim, FOUR_D, &group, &b).await?;
    let base = seats(sim, FOUR_D, &group, &b).await?;
    let a_base = base
        .first()
        .and_then(|(_, seat)| seat.clone())
        .context("A has no record of the group")?;
    let rev0 = a_base.view.state_revision;
    let d0 = a_base
        .digest
        .clone()
        .context("A holds no committed certificate digest for B")?;
    let mut admin_not_after = Vec::with_capacity(2);
    for label in ["A", "D"] {
        let (id, _) = sim.ids(label)?;
        let seat = seats(sim, &["A"], &group, &id)
            .await?
            .into_iter()
            .next()
            .and_then(|(_, seat)| seat);
        admin_not_after.push((label, seat.and_then(|seat| seat.not_after)));
    }
    receipt.setup_done(at(sim));
    let (same, detail) = runtime_timing(sim, FOUR_D)?;
    receipt.evidence("every_node_runs_s4timing_default", same, detail, at(sim));
    let mut ranked = admins.clone();
    ranked.sort();
    receipt.evidence(
        "admins_rank_a_before_d",
        ranked == admins,
        format!("A {} D {}", admins[0], admins[1]),
        at(sim),
    );
    receipt.evidence(
        "home_settled_with_a_d_and_b_on_certificates_expiring_at_n",
        all_bind(&base, &d0)
            && base.iter().all(|(_, seat)| {
                seat.as_ref().is_some_and(|seat| {
                    seat.active() && seat.not_after == Some(n) && seat.view.state_revision == rev0
                })
            })
            && admin_not_after.iter().all(|(_, until)| *until == Some(n)),
        format!(
            "N={n} d0={d0} rev0={rev0}; admins' committed not_after on A {admin_not_after:?}; {}",
            describe_seats(&base)
        ),
        at(sim),
    );
    pinned_bindings_ready(sim, FOUR_D, receipt).await?;
    past_sync_wait(sim, receipt).await?;
    receipt.evidence(
        "setup_ended_before_raw_not_after",
        wall_ms() / 1000 < n,
        format!("wall {} s; N {n} s", wall_ms() / 1000),
        at(sim),
    );
    pause_until_wall(sim, "wait to just before raw not_after", (n - 1) * 1000).await?;
    let trigger = sim
        .fabric()
        .mark_indexed(format!("case: raw not_after N={n} is 1 s away (run 9)"));
    let early = seats(sim, FOUR_D, &group, &b).await?;
    let early_unmoved = all_bind(&early, &d0)
        && early.iter().all(|(_, seat)| {
            seat.as_ref()
                .is_some_and(|seat| seat.active() && seat.view.state_revision == rev0)
        });
    receipt.note(format!(
        "just before raw not_after: {}",
        describe_seats(&early)
    ));

    // The wait starts at the admins' own trigger N + τ.
    let start_by_ms = (n + TAU) * 1000 + u64::try_from(EVIDENCE.as_millis())?;
    let mut first = Sample::default();
    let mut shown_ms: Option<u64> = None;
    let waited = sim
        .until(
            "every node waits for an owner renewal naming A and D",
            Duration::from_millis(start_by_ms.saturating_sub(wall_ms())),
            async |s: &Sim| {
                first = renewal_sample(s, &group, &b, &b_hex, &admins, rev0, &d0).await;
                let done = first.waits || !first.unmoved;
                if first.waits && first.unmoved {
                    shown_ms.get_or_insert(wall_ms());
                }
                done
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    receipt.note(format!(
        "renewal wait first shown at wall {shown_ms:?} ms (N + \u{3c4} = {} ms): {}",
        (n + TAU) * 1000,
        first.detail
    ));
    let end_ms = n * 1000 + u64::try_from(LONG_WAIT.as_millis())?;
    let (failed, samples) = if shown_ms.is_some() {
        hold(sim, end_ms, async |s: &Sim| {
            renewal_sample(s, &group, &b, &b_hex, &admins, rev0, &d0).await
        })
        .await?
    } else {
        (Some(first), 0)
    };
    let held = failed.is_none();
    let passed = early_unmoved && held;
    receipt.note(format!(
        "run (9): unmoved before raw N {early_unmoved}; {samples} samples passed from wall \
         {shown_ms:?} ms to {end_ms} ms (N + {LONG_WAIT:?}); first failure: {}",
        failed.as_ref().map_or_else(
            || "none".to_string(),
            |sample| format!("at wall {} ms: {}", wall_ms(), sample.detail)
        )
    ));
    receipt.note(format!(
        "S4 status at the end: {}",
        statuses(sim, FOUR_D, &group).await?
    ));
    let to_c = sim
        .fabric()
        .delivered_writes_after(&sim.peer("A")?, &sim.peer("C")?, trigger)
        .len();
    receipt.request_delivered(
        "a_reached_c_after_raw_not_after",
        to_c > 0,
        format!("frames since N - 1 s: A->C={to_c}"),
        at(sim),
    );
    if !passed {
        if !early_unmoved {
            receipt.cause(CAUSE_EARLY, Some(describe_seats(&early)), true, at(sim));
        } else if let Some(sample) = failed {
            let cause = if sample.unmoved {
                CAUSE_RENEWAL_WAIT_LOST
            } else {
                CAUSE_RENEWAL_EXIT_FIRED
            };
            receipt.cause(cause, Some(sample.detail), true, at(sim));
        }
    }
    receipt.finish(FINAL_RUN9, passed, at(sim));
    Ok(())
}

async fn owner_silent(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let (home, _) = home_with(sim, THREE, None, &[]).await?;
    let group = home.gid.clone();
    let (a, _) = sim.ids("A")?;
    let a_hex = sim.agent_hex("A")?;
    let survivors: &[&'static str] = &["B", "C"];
    settled(sim, THREE, &group, &a).await?;
    let base = views(sim, survivors, &group, &a).await?;
    let rev0 = view(sim, "A", &group, &a).await?.state_revision;
    receipt.setup_done(at(sim));
    let (same, detail) = runtime_timing(sim, THREE)?;
    receipt.evidence("every_node_runs_s4timing_default", same, detail, at(sim));
    let b_admin_before = sees_admin(sim, "C", &group, "B").await?;
    receipt.evidence(
        "home_settled_with_a_as_its_only_admin",
        base.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.lists_b && seen.state_revision == rev0)
        }) && sees_admin(sim, "C", &group, "A").await?
            && !b_admin_before,
        format!("rev0={rev0}; about A: {}", describe_all(&base)),
        at(sim),
    );
    past_sync_wait(sim, receipt).await?;

    let trigger = sim
        .fabric()
        .mark_indexed("case: t=0 A revokes its own agent; the owner never signs");
    let (status, body) = sim
        .api(
            "A",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": a_hex, "reason": "w3h-1581n owner silent"})),
        )
        .await?;
    ensure!(status.is_success(), "A self-revokes: {status} {body}");
    let t0_ms = wall_ms();
    await_holders(sim, survivors, &a_hex).await?;
    let held = held_by(sim, survivors, &a_hex).await?;

    let mut first = Sample::default();
    let mut shown_ms: Option<u64> = None;
    let waited = sim
        .until(
            "B and C show waiting_for_eligible_admin_revocation",
            EVIDENCE,
            async |s: &Sim| {
                first = recovery_sample(s, &group, &a, &a_hex, rev0).await;
                if first.waits && first.unmoved {
                    shown_ms.get_or_insert(wall_ms());
                }
                first.waits || !first.unmoved
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    receipt.note(format!(
        "owner-recovery wait first shown at wall {shown_ms:?} ms (t0 {t0_ms} ms): {}",
        first.detail
    ));
    let end_ms = t0_ms + u64::try_from(LONG_WAIT.as_millis())?;
    let (failed, samples) = if shown_ms.is_some() {
        hold(sim, end_ms, async |s: &Sim| {
            recovery_sample(s, &group, &a, &a_hex, rev0).await
        })
        .await?
    } else {
        (Some(first), 0)
    };
    let passed = failed.is_none();
    receipt.note(format!(
        "owner silent: {samples} samples passed from wall {shown_ms:?} ms to {end_ms} ms (t0 + \
         {LONG_WAIT:?}); first failure: {}",
        failed.as_ref().map_or_else(
            || "none".to_string(),
            |sample| format!("at wall {} ms: {}", wall_ms(), sample.detail)
        )
    ));
    receipt.note(format!(
        "S4 status at the end: {}",
        statuses(sim, THREE, &group).await?
    ));
    receipt.request_delivered(
        "survivors_hold_a_revocation",
        held.iter().all(|(_, has)| *has)
            && !sim
                .fabric()
                .delivered_writes_after(&sim.peer("A")?, &sim.peer("C")?, trigger)
                .is_empty(),
        format!("revocation held {held:?}"),
        at(sim),
    );
    if let Some(sample) = failed {
        let cause = if sample.unmoved {
            CAUSE_RECOVERY_WAIT_LOST
        } else {
            CAUSE_RECOVERY_EXIT_FIRED
        };
        receipt.cause(cause, Some(sample.detail), true, at(sim));
    }
    receipt.finish(FINAL_SILENT, passed, at(sim));
    Ok(())
}

async fn run_long(case: &str, seed: u64, arm: LongWait) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4, arm {arm:?}: {LONG_WAIT:?} of virtual time, sampled every \
         {SAMPLE:?}. Timing from S4Timing::default() (D69, D73): {:?}; \u{3c4} = {TAU} s.",
        timing()
    ));
    match Sim::empty(case, seed, arm.labels()) {
        Ok(mut sim) => {
            let fabric = Arc::clone(sim.fabric());
            let watchdog = stall_watchdog(case, fabric);
            let outcome = match arm {
                LongWait::NeverRenewed => run9(&mut sim, &mut receipt).await,
                LongWait::OwnerSilent => owner_silent(&mut sim, &mut receipt).await,
            };
            watchdog.disarm();
            if let Err(error) = outcome {
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

async fn expect_long(case: &str, seed: u64, arm: LongWait, want: Verdict) -> Result<()> {
    let receipt = run_long(case, seed, arm).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// ADR 0110 `s4_certificate_rebind` run (9): GREEN with S4. The ADR's
/// 24 virtual hours are cut to one ([`LONG_WAIT`]), which is longer than
/// every S4 timer, so a timer that ends the wait still fails inside it.
#[test]
#[ignore = "on demand only (tests/AGENTS.md): needs the W3-H shim, not in the W3-H gate"]
fn on_demand_1581n_certificate_rebind_run9_owner_never_renews() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_long(
            "on_demand_1581n_certificate_rebind_run9_owner_never_renews",
            0x1581_0042,
            LongWait::NeverRenewed,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_owner_recovery`, O silent: GREEN with S4. The ADR's 24
/// virtual hours are cut to one ([`LONG_WAIT`]), which is longer than every
/// S4 timer, so a timer that ends the wait still fails inside it.
#[test]
#[ignore = "on demand only (tests/AGENTS.md): an hour of virtual time, not in the W3-H gate"]
fn on_demand_1581n_owner_recovery_owner_silent() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_long(
            "on_demand_1581n_owner_recovery_owner_silent",
            0x1581_0043,
            LongWait::OwnerSilent,
            Verdict::Green,
        )
        .await
    })
}
