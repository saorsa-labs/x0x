//! W3-H cases for #1581 (ADR 0110 S4 Validation row `s4_owner_recovery`),
//! the variants the public mandate route can drive. Every arm uses a Home
//! (`OwnerCertified`, TreeKEM) that A provisions; every device holds the
//! owner key U, so C signs the mandates (`POST
//! /owner/groups/:id/recovery-mandate`).
//!
//! - `w3h_1581m_recovery_not_needed_while_d_is_eligible` (nodes A, D, B,
//!   C; admins A and D). At t = 0 A revokes its own agent; once D, B and C
//!   hold the record, C signs a mandate naming B. Desired (the ADR's
//!   variant "arrives while D is still an eligible admin"): the route
//!   refuses with `recovery_not_needed`, no survivor shows
//!   `waiting_for_eligible_admin_revocation`, and B does not become an
//!   admin.
//! - `w3h_1581m_recovery_ineligible_member_then_offline_promotee` (nodes
//!   A, B, C, E; A the only admin). At t = 0 A and E revoke their own
//!   agents; B and C hold both records and show the owner-recovery wait.
//!   Desired: C's mandate naming the revoked member E is refused with
//!   `recovery_member_ineligible`. Then B stops (the ADR's "B is offline
//!   until t = 10 s"), and C's mandate naming B answers `202
//!   waiting_for_recovery_member`; for 10 s B is not an admin on C. B
//!   starts again and commits the recovery: on C, B is an Admin and A is
//!   Removed.
//!
//! Not here (named on #1581): a mandate naming an older head, signed by a
//! non-owner key, or replayed on a later head (each needs a mandate built
//! outside the route, which always signs the current head with the local
//! U); the expired-member form; a released 0.46.1 member L; O silent for
//! 24 virtual hours; the joiner J's `JoinPendingNotice`; and the
//! `SignedPublic` and non-Home `OwnerCertified` variants.

use super::*;

const FOUR_D: &[&str] = &["A", "D", "B", "C"];
const FOUR_E: &[&str] = &["A", "B", "C", "E"];
/// How long B stays offline after C's mandate names it.
const OFFLINE: Duration = Duration::from_secs(10);

const FINAL_NOT_NEEDED: &str = "a_mandate_while_a_second_admin_is_eligible_is_refused_not_needed";
const FINAL_INELIGIBLE: &str =
    "a_mandate_naming_a_revoked_member_is_refused_and_one_naming_b_is_committed";
const FINAL_OFFLINE: &str = "an_offline_promotee_commits_the_recovery_on_its_return";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    NotNeeded,
    /// A and E revoked; the mandate naming E is refused; the one naming
    /// B (online) is committed.
    IneligibleMember,
    /// Only A revoked; B is offline when the mandate names it.
    OfflinePromotee,
}

impl Variant {
    fn revokes_e(self) -> bool {
        self == Self::IneligibleMember
    }

    fn b_offline(self) -> bool {
        self == Self::OfflinePromotee
    }
}

impl Variant {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::NotNeeded => FOUR_D,
            Self::IneligibleMember | Self::OfflinePromotee => FOUR_E,
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::NotNeeded => FINAL_NOT_NEEDED,
            Self::IneligibleMember => FINAL_INELIGIBLE,
            Self::OfflinePromotee => FINAL_OFFLINE,
        }
    }
}

async fn self_revoke(sim: &Sim, label: &str) -> Result<()> {
    let hex = sim.agent_hex(label)?;
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": hex, "reason": "w3h-1581m"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} self-revokes: {status} {body}");
    Ok(())
}

/// Whether `observer` shows the owner-recovery wait naming A.
async fn shows_wait(sim: &Sim, observer: &str, group: &str, a_hex: &str) -> bool {
    group_body(sim, observer, group)
        .await
        .is_ok_and(|body| waits_for_owner_recovery(&body, a_hex))
}

async fn not_needed(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let (home, _) = home_with(sim, FOUR_D, None, &["D"]).await?;
    let group = home.gid.clone();
    let (a, _) = sim.ids("A")?;
    let a_hex = sim.agent_hex("A")?;
    let b_hex = sim.agent_hex("B")?;
    settled(sim, FOUR_D, &group, &a).await?;
    let d_admin = sees_admin(sim, "C", &group, "D").await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "home_settled_with_a_and_d_as_admins",
        d_admin && sees_admin(sim, "C", &group, "A").await?,
        format!("D admin on C {d_admin}"),
        at(sim),
    );
    past_sync_wait(sim, receipt).await?;

    let trigger = sim
        .fabric()
        .mark_indexed("case: t=0 A revokes its own agent; D stays eligible");
    self_revoke(sim, "A").await?;
    await_holders(sim, &["D", "B", "C"], &a_hex).await?;
    let (status, body) = mandate(sim, "C", &group, &b_hex).await?;
    pause(sim, "after the refused mandate", QUIET).await?;
    let refused = status == StatusCode::CONFLICT && body["error"] == "recovery_not_needed";
    let mut waits = Vec::new();
    for label in ["D", "B", "C"] {
        waits.push((label, shows_wait(sim, label, &group, &a_hex).await));
    }
    let no_wait = waits.iter().all(|(_, shown)| !shown);
    let b_admin = sees_admin(sim, "C", &group, "B").await?;
    receipt.note(format!(
        "C's mandate naming B while D is eligible: {status} {body}; owner-recovery wait shown \
         {waits:?}; B admin on C {b_admin}; S4 status {}",
        statuses(sim, FOUR_D, &group).await?
    ));
    receipt.request_delivered(
        "c_answered_the_mandate_and_a_reached_c",
        status != StatusCode::NOT_FOUND
            && status != StatusCode::METHOD_NOT_ALLOWED
            && !sim
                .fabric()
                .delivered_writes_after(&sim.peer("A")?, &sim.peer("C")?, trigger)
                .is_empty(),
        format!("mandate reply {status}"),
        at(sim),
    );
    receipt.finish(FINAL_NOT_NEEDED, refused && no_wait && !b_admin, at(sim));
    Ok(())
}

async fn mandate_variants(sim: &mut Sim, receipt: &mut Receipt, variant: Variant) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let (home, _) = home_with(sim, FOUR_E, None, &[]).await?;
    let group = home.gid.clone();
    let (a, _) = sim.ids("A")?;
    let a_hex = sim.agent_hex("A")?;
    let b_hex = sim.agent_hex("B")?;
    let e_hex = sim.agent_hex("E")?;
    settled(sim, FOUR_E, &group, &a).await?;
    receipt.setup_done(at(sim));
    past_sync_wait(sim, receipt).await?;

    let trigger = sim
        .fabric()
        .mark_indexed(format!("case: t=0 revocations ({variant:?})"));
    self_revoke(sim, "A").await?;
    if variant.revokes_e() {
        self_revoke(sim, "E").await?;
    }
    await_holders(sim, &["B", "C"], &a_hex).await?;
    if variant.revokes_e() {
        await_holders(sim, &["B", "C"], &e_hex).await?;
    }
    let waited = sim
        .until(
            "B and C show the owner-recovery wait",
            EVIDENCE,
            async |s: &Sim| {
                shows_wait(s, "B", &group, &a_hex).await && shows_wait(s, "C", &group, &a_hex).await
            },
        )
        .await;
    let waits_typed = match waited {
        Ok(()) => true,
        Err(error) if expired(&error) => false,
        Err(error) => return Err(error),
    };
    receipt.evidence(
        "b_and_c_wait_for_owner_recovery_naming_a",
        waits_typed,
        statuses(sim, &["B", "C"], &group).await?,
        at(sim),
    );

    // A mandate naming the revoked member E.
    let (status_e, refused_e) = if variant.revokes_e() {
        let (status_e, body_e) = mandate(sim, "C", &group, &e_hex).await?;
        receipt.note(format!("C's mandate naming revoked E: {status_e} {body_e}"));
        (
            status_e,
            !status_e.is_success() && body_e["error"] == "recovery_member_ineligible",
        )
    } else {
        (StatusCode::OK, true)
    };

    // C's mandate names B (offline in the offline variant).
    if variant.b_offline() {
        sim.stop("B", RestartMode::Graceful).await?;
    }
    let (status_b, body_b) = mandate(sim, "C", &group, &b_hex).await?;
    let signed = status_b == StatusCode::ACCEPTED
        && body_b["state"] == "waiting_for_recovery_member"
        && body_b["promoted_member"].as_str() == Some(b_hex.as_str());
    let c_body = group_body(sim, "C", &group).await?;
    receipt.note(format!(
        "C's mandate naming offline B: {status_b} {body_b}; C's admin_availability {}",
        c_body["admin_availability"]
    ));
    let early_admin = if variant.b_offline() {
        pause(sim, "B offline", OFFLINE).await?;
        let early = sees_admin(sim, "C", &group, "B").await?;
        sim.start_again("B").await?;
        early
    } else {
        false
    };
    let started = sim.fabric().now();
    let mut reached: Option<Duration> = None;
    let waited = sim
        .until(
            "B commits the owner recovery after its return",
            RECOVERY,
            async |s: &Sim| {
                let done = sees_admin(s, "C", &group, "B").await.unwrap_or(false)
                    && views_now(s, &["C"], &group, &a).await.is_ok_and(|seen| {
                        seen.iter().all(|(_, view)| {
                            view.as_ref().is_some_and(|view| {
                                !view.lists_b && view.b_state.as_deref() == Some("Removed")
                            })
                        })
                    });
                if done {
                    reached.get_or_insert(s.fabric().now().saturating_sub(started));
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
    let end = views(sim, &["C"], &group, &a).await?;
    let committed = reached.is_some();
    receipt.note(format!(
        "refused E recovery_member_ineligible {refused_e}; B mandate signed {signed}; B admin on \
         C while offline {early_admin}; recovery committed {committed} at {reached:?} after B's \
         return; C about A: {}; S4 status {}",
        describe_all(&end),
        statuses(sim, &["B", "C"], &group).await?
    ));
    receipt.request_delivered(
        "c_answered_the_mandates_and_a_reached_c",
        status_b != StatusCode::NOT_FOUND
            && !sim
                .fabric()
                .delivered_writes_after(&sim.peer("A")?, &sim.peer("C")?, trigger)
                .is_empty(),
        format!("mandate replies {status_e} / {status_b}"),
        at(sim),
    );
    let passed = waits_typed && refused_e && signed && !early_admin && committed;
    receipt.finish(variant.final_name(), passed, at(sim));
    Ok(())
}

async fn run_variant(case: &str, seed: u64, variant: Variant) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 s4_owner_recovery variant {variant:?}. Timing from \
         S4Timing::default(): {:?}.",
        timing()
    ));
    match Sim::empty(case, seed, variant.labels()) {
        Ok(mut sim) => {
            let fabric = Arc::clone(sim.fabric());
            let watchdog = real_time_watchdog(case, fabric);
            let outcome = match variant {
                Variant::NotNeeded => not_needed(&mut sim, &mut receipt).await,
                Variant::IneligibleMember | Variant::OfflinePromotee => {
                    mandate_variants(&mut sim, &mut receipt, variant).await
                }
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
        receipt.reclassify(variant.final_name());
    }
    receipt.emit();
    receipt
}

async fn expect_variant(case: &str, seed: u64, variant: Variant, want: Verdict) -> Result<()> {
    let receipt = run_variant(case, seed, variant).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// ADR 0110 `s4_owner_recovery`, the "D is still an eligible admin"
/// variant: GREEN with S4.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1581m_recovery_not_needed_while_d_is_eligible() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_variant(
            "w3h_1581m_recovery_not_needed_while_d_is_eligible",
            0x1581_0050,
            Variant::NotNeeded,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_owner_recovery`, the revoked-member variant: GREEN with
/// S4.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1581m_recovery_refuses_a_revoked_member() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_variant(
            "w3h_1581m_recovery_refuses_a_revoked_member",
            0x1581_0051,
            Variant::IneligibleMember,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_owner_recovery`, the "B is offline until t = 10 s"
/// variant: GREEN with S4.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1581m_recovery_offline_promotee_commits_on_return() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_variant(
            "w3h_1581m_recovery_offline_promotee_commits_on_return",
            0x1581_0052,
            Variant::OfflinePromotee,
            Verdict::Green,
        )
        .await
    })
}
