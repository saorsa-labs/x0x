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
//! - `w3h_1581m_recovery_refuses_a_revoked_member` (nodes A, B, C, E; A
//!   the only admin). At t = 0 A and E revoke their own agents; B and C
//!   hold both records and show the owner-recovery wait. C's mandate
//!   naming the revoked member E is refused with
//!   `recovery_member_ineligible`; C's mandate naming B answers `202
//!   waiting_for_recovery_member`. B commits the recovery (on C, B is an
//!   Admin and A is Removed): GREEN since the #1973 fix, where the
//!   owner-recovery seal tolerates the seated revoked member E (E's own
//!   S4 row removes it one epoch later). This arm was pinned RED for
//!   #1973 until then. A regression (B's seal refused for E, so the
//!   recovery never commits) records [`CAUSE_REVOKED_SEAT_BLOCKS_SEAL`]
//!   and ends RED, which fails the GREEN expectation.
//! - `w3h_1581m_recovery_offline_promotee_commits_on_return` (nodes A, B,
//!   C, E; A the only admin, only A revoked). B stops (the ADR's "B is
//!   offline until t = 10 s"), and C's mandate naming B answers `202
//!   waiting_for_recovery_member`; for 10 s B is not an admin on C. B
//!   starts again and commits the recovery: on C, B is an Admin and A is
//!   Removed.
//!
//! Not here (named on #1581): a mandate naming an older head, signed by a
//! non-owner key, or replayed on a later head (each needs a mandate built
//! outside the route, which always signs the current head with the local
//! U); the expired-member form; a released 0.46.1 member L; the joiner
//! J's `JoinPendingNotice`; and the
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
/// The #1973 regression: the recovery seal refuses while another revoked
/// member is seated.
const CAUSE_REVOKED_SEAT_BLOCKS_SEAL: &str = "B's owner-recovery seal is refused (ADR-0038 \
     explicit eviction+rekey) for revoked member E, which is still seated, so the recovery never \
     commits";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    NotNeeded,
    /// A and E revoked; the mandate naming E is refused; the one naming
    /// B (online) is committed while E is still seated (#1973).
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

/// Whether `observer` shows the owner-recovery wait naming A. A failed
/// read is an error, never "no wait": an absence check must not pass on
/// an unreadable status.
async fn shows_wait(sim: &Sim, observer: &str, group: &str, a_hex: &str) -> Result<bool> {
    Ok(waits_for_owner_recovery(
        &group_body(sim, observer, group).await?,
        a_hex,
    ))
}

/// After `await_holders` (which does not fail when the wait ends without
/// the record): every holder must hold `subject_hex`'s revocation, else
/// the arm tests nothing new and is INFRA.
async fn holders_hold(
    sim: &Sim,
    receipt: &mut Receipt,
    name: &str,
    holders: &[&'static str],
    subject_hex: &str,
) -> Result<()> {
    await_holders(sim, holders, subject_hex).await?;
    let held = held_by(sim, holders, subject_hex).await?;
    receipt.evidence(
        name,
        all_hold(&held),
        format!("revocation held {held:?}"),
        sim.fabric().now().as_micros(),
    );
    Ok(())
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
    holders_hold(
        sim,
        receipt,
        "d_b_and_c_hold_a_revocation_before_the_mandate",
        &["D", "B", "C"],
        &a_hex,
    )
    .await?;
    let (status, body) = mandate(sim, "C", &group, &b_hex).await?;
    pause(sim, "after the refused mandate", QUIET).await?;
    let refused = status == StatusCode::CONFLICT && body["error"] == "recovery_not_needed";
    let mut waits = Vec::new();
    for label in ["D", "B", "C"] {
        waits.push((label, shows_wait(sim, label, &group, &a_hex).await?));
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
    holders_hold(
        sim,
        receipt,
        "b_and_c_hold_a_revocation",
        &["B", "C"],
        &a_hex,
    )
    .await?;
    if variant.revokes_e() {
        holders_hold(
            sim,
            receipt,
            "b_and_c_hold_e_revocation",
            &["B", "C"],
            &e_hex,
        )
        .await?;
    }
    let waited = sim
        .until(
            "B and C show the owner-recovery wait",
            EVIDENCE,
            async |s: &Sim| {
                // A failed read while polling is "not yet"; the evidence
                // stage below records the final state.
                matches!(shows_wait(s, "B", &group, &a_hex).await, Ok(true))
                    && matches!(shows_wait(s, "C", &group, &a_hex).await, Ok(true))
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
        "C's mandate naming B: {status_b} {body_b}; C's admin_availability {}",
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
    let outcome = Outcome {
        waits_typed,
        refused_e,
        signed,
        early_admin,
        committed,
    };
    if !committed && variant.revokes_e() {
        // A #1973 regression: B's seal refusal that names E.
        let refusals = sim.logs_containing(&[
            "owner recovery deferred: seal failed",
            "explicit eviction+rekey",
            e_hex.as_str(),
        ]);
        receipt.note(format!(
            "B's seal refusals naming E: {}; first {:?}",
            refusals.len(),
            refusals.first().map(|log| (log.at, log.text.clone()))
        ));
        pin_1973(
            receipt,
            outcome,
            refusals.first().map(|log| log.text.clone()),
            at(sim),
        );
    }
    receipt.finish(variant.final_name(), outcome.passed(), at(sim));
    Ok(())
}

/// What a mandate arm observed.
#[derive(Clone, Copy, Debug)]
struct Outcome {
    waits_typed: bool,
    refused_e: bool,
    signed: bool,
    early_admin: bool,
    committed: bool,
}

impl Outcome {
    /// Every desired step before the commit holds.
    fn before_commit(self) -> bool {
        self.waits_typed && self.refused_e && self.signed && !self.early_admin
    }

    fn passed(self) -> bool {
        self.before_commit() && self.committed
    }
}

/// Records the #1973 cause when the recovery did not commit. It classifies
/// (the arm ends RED, a named #1973 regression) only when B's seal refusal
/// naming E was seen AND every step before the commit holds: a wrong reply
/// to the mandate naming E or B, a missing owner-recovery wait, or B an
/// admin early leaves the cause unmet and the arm INFRA.
fn pin_1973(receipt: &mut Receipt, outcome: Outcome, refusal: Option<String>, at_us: u128) {
    let ok = refusal.is_some() && outcome.before_commit();
    receipt.cause(CAUSE_REVOKED_SEAT_BLOCKS_SEAL, refusal, ok, at_us);
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
    meets(case, &run_variant(case, seed, variant).await, want)
}

/// The receipt has the expected verdict; an expected RED also names
/// exactly the #1973 cause.
fn meets(case: &str, receipt: &Receipt, want: Verdict) -> Result<()> {
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    // An expected RED is eligible only with the named gap observed.
    if want == Verdict::Red {
        ensure!(
            receipt.named_causes() == [CAUSE_REVOKED_SEAT_BLOCKS_SEAL],
            "{case}: RED for another cause: {:?}",
            receipt.named_causes()
        );
    }
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

/// ADR 0110 `s4_owner_recovery`, the revoked-member variant. The mandate
/// naming E is refused, and B's recovery commits while E is still seated:
/// GREEN with the #1973 fix (was pinned RED before it).
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

mod pin_tests {
    use super::*;

    const ALL_BUT_COMMIT: Outcome = Outcome {
        waits_typed: true,
        refused_e: true,
        signed: true,
        early_admin: false,
        committed: false,
    };
    const REFUSAL: &str = "owner recovery deferred: seal failed: explicit eviction+rekey E";

    /// The receipt the revoked-member arm writes after its preconditions
    /// hold, for `outcome` and an optional seal refusal naming E.
    fn arm(outcome: Outcome, refusal: Option<&str>) -> Receipt {
        let mut receipt = Receipt::new("pin", 1);
        receipt.setup_done(1);
        receipt.evidence("b_and_c_hold_a_revocation", true, "", 2);
        receipt.request_delivered("c_answered", true, "", 3);
        if !outcome.committed {
            pin_1973(&mut receipt, outcome, refusal.map(str::to_string), 4);
        }
        receipt.finish(FINAL_INELIGIBLE, outcome.passed(), 5);
        receipt
    }

    #[test]
    fn pin_1973_holds_only_when_the_commit_alone_is_missing() {
        assert!(meets("pin", &arm(ALL_BUT_COMMIT, Some(REFUSAL)), Verdict::Red).is_ok());
    }

    #[test]
    fn pin_1973_needs_the_seal_refusal() {
        assert!(meets("pin", &arm(ALL_BUT_COMMIT, None), Verdict::Red).is_err());
    }

    #[test]
    fn pin_1973_fails_on_a_broken_mandate_reply() {
        for broken in [
            Outcome {
                refused_e: false,
                ..ALL_BUT_COMMIT
            },
            Outcome {
                signed: false,
                ..ALL_BUT_COMMIT
            },
            Outcome {
                waits_typed: false,
                ..ALL_BUT_COMMIT
            },
            Outcome {
                early_admin: true,
                ..ALL_BUT_COMMIT
            },
        ] {
            let receipt = arm(broken, Some(REFUSAL));
            assert!(
                meets("pin", &receipt, Verdict::Red).is_err(),
                "{broken:?} kept the pin: {:?}",
                receipt.verdict()
            );
        }
    }

    #[test]
    fn a_committed_recovery_is_green() {
        let done = Outcome {
            committed: true,
            ..ALL_BUT_COMMIT
        };
        assert!(meets("pin", &arm(done, None), Verdict::Green).is_ok());
        assert!(meets("pin", &arm(done, None), Verdict::Red).is_err());
    }
}
