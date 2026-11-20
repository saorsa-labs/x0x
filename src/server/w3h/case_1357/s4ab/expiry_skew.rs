//! W3-H cases for #1581 (ADR 0110 S4 Validation row
//! `s4_certificate_expiry_skew`), the runs the single-binary sim can drive
//! with every node on the same wall-clock offset: (1), (5a) and (8).
//!
//! Setup (every arm): a Home (`OwnerCertified`, owner user U) that A
//! provisions; D, E, B and C are certified same-owner devices. Admins
//! A < D < E by agent id (A is the owner device; A promotes D and E), so A
//! is the designated admin. B is the target, C a survivor. B's own device
//! certificate is issued through the public `POST /owner/agents/issue`
//! route with `not_after` N; the case calls no seal. The case's t = 0 is
//! N − 60 s, so N is the ADR's t = 60 s. Every node runs with offset 0
//! (the shim's wall clock = base + virtual time); the runs that need a
//! different offset per node, (2), (3), (4) and (6), need a per-node shim
//! offset and are not here.
//!
//! - `w3h_1581j_expiry_skew_run1_all_offsets_zero` (run (1)), in the
//!   TreeKEM Home. Desired: no survivor removes B before its clock passes
//!   raw N; the survivors A, D, E and C then exclude B once (B Removed, one
//!   epoch step, one leaf fewer), the head commit is A's, it is committed
//!   after raw N, and it lands within the completion bound from A's own
//!   trigger N + τ. After the exclusion, A's new ciphertext opens on C, D
//!   and E and not on B.
//! - `w3h_1581j_expiry_skew_run5a_announced_renewal_rebinds_at_expiry` (run
//!   (5a)). At t = 55 s, B's renewal (issued by U through the same route)
//!   reaches A, D and E only by announce: B restarts with the renewal as its
//!   own certificate and announces it; the case checks that A, D and E hold
//!   the renewal in their discovery entry for B. The row's "B is evicted"
//!   predates §4a: ADR 0110 L289 and `s4_certificate_rebind` run (2) have
//!   the designated worker commit the rebind instead of `MemberRemoved`
//!   when it holds a verified renewal from any source, an announce cache
//!   included (D135: the announce alone cancels nothing; the rebinding
//!   commit keeps the seat). A09 (16 Nov 2026) records this reading.
//!   Desired: nothing moves before raw N; then every survivor holds A's
//!   rebind, committed after raw N and within the completion bound from
//!   A's trigger N + τ: B stays Active with the renewal's digest, the epoch
//!   and leaf count do not move, and A's new ciphertext opens on C, D and
//!   E. (B's own restarted record waits for the owner-certified restore
//!   re-verification, so B's decrypt is only noted.)
//! - `w3h_1581j_expiry_skew_run8_signed_public` (run (8)): run (1) in an
//!   `OwnerCertified` `SignedPublic` group that A creates and D, E, B, C
//!   join through invites (`mode: home`). Desired: B is Removed on every
//!   survivor's head, signed by A after raw N and within the bound, with
//!   no crypto event (no TreeKEM group, no epoch).
//!
//! The other runs are not here: (5b) and the late admin rebind overlap
//! `s4_certificate_rebind` run (6); (5c), (7) and (9) are follow-ups on
//! #1581. The shim moves the daemons' wall clock with virtual time, so
//! these arms are `#[ignore]`d outside it and the W3-H gate runs them
//! (`--run-ignored all`), as for `s4_certificate_rebind` run (6).

use super::*;

/// B's certificate expires this long after it is issued. Setup must end
/// before t = 0 = N − [`T0_BEFORE_N`].
const NOT_AFTER_OFFSET: u64 = 600;
/// t = 0 is this long before N (the ADR's N is t = 60 s).
const T0_BEFORE_N: u64 = 60;
/// Run (5a): the renewal reaches the admins by announce this long before
/// N (the ADR's t = 55 s).
const RENEWAL_BEFORE_N: u64 = 5;

const FIVE_SKEW: &[&str] = &["A", "D", "E", "B", "C"];
const SURVIVORS: &[&str] = &["A", "D", "E", "C"];

const FINAL_EXPIRY: &str =
    "survivors_exclude_the_expired_seat_once_after_raw_not_after_within_the_bound";

const CAUSE_NO_EXPIRY_EVICTION: &str = "no expiry eviction: after A's trigger N + \u{3c4} and the \
                                        completion bound every survivor still lists B Active on \
                                        its first certificate (the ADR's red-on-main \
                                        observation)";
const CAUSE_EARLY: &str = "a survivor removed B before its own clock passed raw not_after";
const CAUSE_SIBLING: &str =
    "B was excluded, but the head commit is not the designated admin A's (a sibling signed it)";
const CAUSE_LATE: &str =
    "B was excluded by A, but later than A's trigger N + \u{3c4} plus the completion bound";
const FINAL_REBIND: &str = "the_designated_admin_rebinds_the_announced_renewal_at_expiry";
const CAUSE_RENEWAL_IGNORED: &str = "A held B's verified renewal by announce, but the survivors \
                                     excluded B instead of committing the rebind (ADR 0110 \
                                     L289, s4_certificate_rebind run (2))";
const CAUSE_NO_REBIND: &str = "after A's trigger N + \u{3c4} and the completion bound every \
                               survivor still lists B Active on its first certificate: no rebind \
                               and no eviction";

/// Which run an arm does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SkewRun {
    /// (1): all offsets 0, TreeKEM Home.
    AllZero,
    /// (5a): run (1) with U's renewal reaching the admins by announce at
    /// t = 55 s.
    AnnouncedRenewal,
    /// (8): run (1) in an `OwnerCertified` `SignedPublic` group.
    SignedPublic,
}

impl SkewRun {
    fn treekem(self) -> bool {
        self != Self::SignedPublic
    }

    fn final_name(self) -> &'static str {
        if self == Self::AnnouncedRenewal {
            FINAL_REBIND
        } else {
            FINAL_EXPIRY
        }
    }
}

/// Every label holds A's state revision for `group`.
async fn same_head(sim: &Sim, labels: &[&'static str], group: &str, b: &AgentId) -> Result<()> {
    sim.until("every node holds A's head", SETUP, async |s: &Sim| {
        let Ok(Some(authority)) = try_view_now(s, "A", group, b).await else {
            return false;
        };
        for label in labels {
            match try_view_now(s, label, group, b).await {
                Ok(Some(seen)) if seen.state_revision == authority.state_revision => {}
                _ => return false,
            }
        }
        true
    })
    .await
}

/// A creates an `OwnerCertified` `SignedPublic` group; D, E, B and C join
/// it through unaddressed invites (`mode: home`, pinned to U); A promotes
/// D and E. Returns the group's ids.
async fn signed_public_group(
    sim: &Sim,
    home: &super::super::super::home::HomeIds,
) -> Result<super::super::super::home::HomeIds> {
    let created = ok_call(
        sim,
        "A",
        Method::POST,
        "/groups",
        json!({
            "name": "w3h 1581j",
            "display_name": "A",
            "policy": {
                "discoverability": "listed_to_contacts",
                "admission": {"owner_certified": home.owner_user_id},
                "confidentiality": "signed_public",
                "read_access": "members_only",
                "write_access": "members_only",
            },
        }),
    )
    .await?;
    let ids = super::super::super::home::HomeIds {
        gid: created["group_id"]
            .as_str()
            .context("create response has no group_id")?
            .to_string(),
        owner_user_id: home.owner_user_id.clone(),
    };
    for member in ["D", "E", "B", "C"] {
        let link = invite(sim, "A", &ids.gid).await?;
        ensure!(
            sim.join_home("A", member, &ids, &link, SETUP).await?,
            "setup: {member} could not join A's SignedPublic group"
        );
    }
    let observers: Vec<&str> = FIVE_SKEW.iter().copied().filter(|l| *l != "A").collect();
    for admin in ["D", "E"] {
        sim.promote_admin("A", admin, &ids, &observers).await?;
    }
    Ok(ids)
}

/// Run (5a): B restarts with `renewal` (storage encoding, base64) as its
/// own certificate and announces it. Returns whether A, D and E then hold
/// the renewal (digest `d1`) in their discovery entry for B, with what
/// each holds.
async fn announce_renewal(sim: &mut Sim, renewal: &str, d1: &str) -> Result<(bool, String)> {
    sim.stop("B", RestartMode::Graceful).await?;
    let identity = sim
        .data_dir("B")?
        .parent()
        .context("B's data dir has no parent")?
        .join("identity");
    crate::storage::write_private_bytes(&identity.join("agent.cert"), BASE64.decode(renewal)?)
        .await?;
    sim.start_again("B").await?;
    ok_call(
        sim,
        "B",
        Method::POST,
        "/announce",
        json!({"include_user_identity": true, "human_consent": true}),
    )
    .await?;
    let (b_id, _) = sim.ids("B")?;
    let mut held = String::new();
    let mut all = false;
    let waited = sim
        .until(
            "A, D and E hold B's announced renewal",
            EVIDENCE,
            async |s: &Sim| {
                let mut seen = Vec::with_capacity(3);
                let mut every = true;
                for admin in ["A", "D", "E"] {
                    let digest = match s.state(admin) {
                        Ok(state) => state
                            .agent
                            .discovered_agent(b_id)
                            .await
                            .ok()
                            .flatten()
                            .and_then(|entry| entry.agent_certificate)
                            .map(|cert| crate::groups::owner_cert::certificate_digest_hex(&cert)),
                        Err(_) => None,
                    };
                    every &= digest.as_deref() == Some(d1);
                    seen.push(format!("{admin}: {digest:?}"));
                }
                held = seen.join(", ");
                all = every;
                every
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    Ok((all, held))
}

/// B is excluded on one survivor's view: not Active, and for the TreeKEM
/// Home one epoch step and one leaf fewer; for `SignedPublic` no epoch.
fn excluded_on(seat: &Seat, run: SkewRun, e0: Option<u64>, leaves0: Option<u32>) -> bool {
    let removed = !seat.active() && !seat.view.lists_b && !seat.view.quarantined;
    if run.treekem() {
        removed
            && seat.view.epoch == e0.map(|epoch| epoch + 1)
            && seat.view.leaves == leaves0.map(|leaves| leaves - 1)
    } else {
        removed && seat.view.epoch.is_none() && e0.is_none()
    }
}

async fn skew_scenario(sim: &mut Sim, run: SkewRun, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    if sim.shim.is_none() {
        bail!(
            "s4_certificate_expiry_skew needs the W3-H shim: the expiry follows the daemons' \
             wall clock, which without the shim does not move with virtual time"
        );
    }
    let timing = timing();
    sim.rank_keys(&["A", "D", "E"])?;
    let (home, not_after) =
        home_with(sim, FIVE_SKEW, Some(("B", NOT_AFTER_OFFSET)), &["D", "E"]).await?;
    let n = not_after.context("B's not_after")?;
    let group = match run {
        SkewRun::AllZero | SkewRun::AnnouncedRenewal => home.gid.clone(),
        SkewRun::SignedPublic => signed_public_group(sim, &home).await?.gid,
    };
    let (b, _) = sim.ids("B")?;
    let a_hex = sim.agent_hex("A")?;
    same_head(sim, FIVE_SKEW, &group, &b).await?;
    let base = seats(sim, FIVE_SKEW, &group, &b).await?;
    let a_base = base
        .first()
        .and_then(|(_, seat)| seat.clone())
        .context("A has no record of the group")?;
    let e0 = a_base.view.epoch;
    let leaves0 = a_base.view.leaves;
    let d0 = a_base
        .digest
        .clone()
        .context("A holds no committed certificate digest for B")?;
    let before = if run.treekem() {
        data_plane(sim, &group, "A", &["B", "C", "D", "E"]).await?
    } else {
        Vec::new()
    };
    receipt.setup_done(at(sim));
    let (same, detail) = runtime_timing(sim, FIVE_SKEW)?;
    receipt.evidence("every_node_runs_s4timing_default", same, detail, at(sim));
    let mut ranked: Vec<(String, &str)> = ["A", "D", "E"]
        .into_iter()
        .map(|label| sim.agent_hex(label).map(|hex| (hex, label)))
        .collect::<Result<_>>()?;
    ranked.sort();
    let order: Vec<&str> = ranked.iter().map(|(_, label)| *label).collect();
    receipt.evidence(
        "admins_rank_a_before_d_before_e",
        order == ["A", "D", "E"],
        format!("admin agent-id order {order:?}"),
        at(sim),
    );
    let plane_shape = if run.treekem() {
        e0.is_some() && leaves0 == Some(5) && a_base.view.tracks_b == Some(true)
    } else {
        e0.is_none() && leaves0.is_none()
    };
    receipt.evidence(
        "group_settled_with_b_seated_on_its_expiring_certificate",
        all_bind(&base, &d0)
            && plane_shape
            && base.iter().all(|(_, seat)| {
                seat.as_ref()
                    .is_some_and(|seat| seat.active() && seat.not_after == Some(n))
            }),
        format!(
            "run {run:?}; e0={e0:?} leaves0={leaves0:?} d0={d0} N={n}; {}",
            describe_seats(&base)
        ),
        at(sim),
    );
    if run.treekem() {
        receipt.evidence(
            "b_c_d_e_decrypt_before_the_expiry",
            before.iter().all(|(_, ok, _)| *ok),
            format!("{before:?}"),
            at(sim),
        );
    }
    pinned_bindings_ready(sim, FIVE_SKEW, receipt).await?;
    past_sync_wait(sim, receipt).await?;
    let t0_s = n - T0_BEFORE_N;
    receipt.evidence(
        "setup_ended_before_t0",
        wall_ms() / 1000 < t0_s,
        format!("wall {} s; t0 {t0_s} s; N {n} s", wall_ms() / 1000),
        at(sim),
    );
    pause_until_wall(sim, "wait to t = 0 (N − 60 s)", t0_s * 1000).await?;
    let trigger = sim.fabric().mark_indexed(format!(
        "case: t=0, B's not_after N={n} is 60 s away (run {run:?})"
    ));

    let mut renewal_digest: Option<String> = None;
    if run == SkewRun::AnnouncedRenewal {
        pause_until_wall(
            sim,
            "wait to t = 55 s (N − 5 s)",
            (n - RENEWAL_BEFORE_N) * 1000,
        )
        .await?;
        // The pause above returns at once when the wall clock is already
        // past N − 5 s, so the timing is proved here: A, D and E must hold
        // the renewal before raw N, or the run shows nothing about a
        // renewal that arrives before the expiry (INFRA, #1951 review).
        let announce_from_ms = wall_ms();
        let (renewal, d1, _) = issue_for(sim, "A", "B", n + RENEWAL_EXTRA).await?;
        let (held, detail) = announce_renewal(sim, &renewal, &d1).await?;
        let held_ms = wall_ms();
        let before_n = held_ms < n * 1000;
        receipt.evidence(
            "a_d_e_hold_b_s_renewal_by_announce_only_before_raw_not_after",
            held && before_n,
            format!(
                "renewal digest {d1}; announce from wall {announce_from_ms} ms, held at wall \
                 {held_ms} ms, raw N {} ms; discovery entries: {detail}",
                n * 1000
            ),
            at(sim),
        );
        ensure!(
            held && before_n,
            "INFRA: A, D and E did not hold B's renewal before raw not_after (held {held}, at \
             wall {held_ms} ms, N {} ms)",
            n * 1000
        );
        renewal_digest = Some(d1);
    }
    // Run (5a)'s outcome on one survivor: the seat is still Active with
    // its base role and leaf tracking, bound to the renewal, at the same
    // epoch and leaf count (ADR 0110 §4a: no crypto event).
    let rebound = |label: &str, seat: &Seat| -> bool {
        let Some(digest) = renewal_digest.as_deref() else {
            return false;
        };
        let was = base
            .iter()
            .find(|(base_label, _)| *base_label == label)
            .and_then(|(_, seat)| seat.as_ref());
        was.is_some_and(|was| {
            seat.active()
                && seat.view.lists_b
                && seat.role == was.role
                && seat.digest.as_deref() == Some(digest)
                && seat.view.epoch == e0
                && seat.view.leaves == leaves0
                && seat.view.tracks_b == was.view.tracks_b
                && !seat.view.quarantined
        })
    };
    let outcome = |label: &str, seat: &Seat| -> bool {
        if run == SkewRun::AnnouncedRenewal {
            rebound(label, seat)
        } else {
            excluded_on(seat, run, e0, leaves0)
        }
    };

    // Just before raw N: no survivor has removed B.
    pause_until_wall(sim, "wait to just before raw not_after", (n - 1) * 1000).await?;
    let early = seats(sim, SURVIVORS, &group, &b).await?;
    let early_unmoved = all_bind(&early, &d0)
        && early
            .iter()
            .all(|(_, seat)| seat.as_ref().is_some_and(Seat::active));
    receipt.note(format!(
        "just before raw not_after ({} s): {}",
        n - 1,
        describe_seats(&early)
    ));

    // H: A's own trigger is N + τ; the exclusion must land within the
    // completion bound from there.
    let deadline_ms = (n + TAU) * 1000
        + u64::try_from(timing.completion_bound.as_millis()).unwrap_or(u64::MAX)
        + 1000;
    let budget = Duration::from_millis(deadline_ms.saturating_sub(wall_ms()));
    let mut reached_ms: Option<u64> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the survivors exclude B", budget, async |s: &Sim| {
            let Some(now) = seen.observe(seats_now(s, SURVIVORS, &group, &b)).await else {
                return true;
            };
            let done = now
                .iter()
                .all(|(label, seat)| seat.as_ref().is_some_and(|seat| outcome(label, seat)));
            if done {
                reached_ms.get_or_insert(wall_ms());
            }
            done
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("the survivors exclude B")?;
    if reached_ms.is_some() {
        pause(sim, "the exclusion settles", SETTLE).await?;
    }
    let end = seats(sim, SURVIVORS, &group, &b).await?;
    let once = end
        .iter()
        .all(|(label, seat)| seat.as_ref().is_some_and(|seat| outcome(label, seat)));
    let by_a = head_signed_by(&end, &a_hex);
    let after_raw = end.iter().all(|(_, seat)| {
        seat.as_ref()
            .and_then(|seat| seat.head_committed_at_ms)
            .is_some_and(|ms| ms > n * 1000)
    });
    let in_bound = reached_ms.is_some_and(|ms| ms <= deadline_ms);
    let plane = if run.treekem() {
        data_plane(sim, &group, "A", &["C", "D", "E", "B"]).await?
    } else {
        Vec::new()
    };
    // Run (5a) restarted B to load its renewal, so B's own record of the
    // owner-certified group waits for the restore re-verification and its
    // decrypt is no S4 observation: only the survivors' reads count. In
    // the other runs B must not open the post-exclusion ciphertext.
    let plane_ok = plane.iter().all(|(reader, ok, _)| {
        if reader.as_str() == "B" {
            run == SkewRun::AnnouncedRenewal || !*ok
        } else {
            *ok
        }
    });
    let passed = early_unmoved && once && by_a && after_raw && in_bound && plane_ok;
    receipt.note(format!(
        "run {run:?}: unmoved before raw N {early_unmoved}; outcome once on every survivor \
         {once}; head signed by A {by_a}; head committed after raw N {after_raw}; reached at wall \
         {reached_ms:?} ms (deadline {deadline_ms} = (N + \u{3c4}) + completion bound + 1 s: \
         {in_bound}); data plane after {plane:?}; end: {}",
        describe_seats(&end)
    ));
    receipt.note(format!(
        "S4 status at the end: {}",
        statuses(sim, SURVIVORS, &group).await?
    ));
    let to_c = sim
        .fabric()
        .delivered_writes_after(&sim.peer("A")?, &sim.peer("C")?, trigger)
        .len();
    receipt.request_delivered(
        "a_reached_c_after_t0",
        to_c > 0,
        format!("frames since t=0: A->C={to_c}"),
        at(sim),
    );
    if !passed {
        let unmoved_end = all_bind(&end, &d0)
            && end
                .iter()
                .all(|(_, seat)| seat.as_ref().is_some_and(Seat::active));
        if !early_unmoved {
            receipt.cause(CAUSE_EARLY, Some(describe_seats(&early)), true, at(sim));
        } else if unmoved_end {
            let cause = if run == SkewRun::AnnouncedRenewal {
                CAUSE_NO_REBIND
            } else {
                CAUSE_NO_EXPIRY_EVICTION
            };
            receipt.cause(cause, Some(describe_seats(&end)), true, at(sim));
        } else if run == SkewRun::AnnouncedRenewal
            && end.iter().all(|(_, seat)| {
                seat.as_ref()
                    .is_some_and(|seat| excluded_on(seat, SkewRun::AllZero, e0, leaves0))
            })
        {
            receipt.cause(
                CAUSE_RENEWAL_IGNORED,
                Some(describe_seats(&end)),
                true,
                at(sim),
            );
        } else if once && !by_a {
            receipt.cause(CAUSE_SIBLING, Some(describe_seats(&end)), true, at(sim));
        } else if once && by_a && !in_bound {
            receipt.cause(CAUSE_LATE, Some(format!("{reached_ms:?}")), true, at(sim));
        } else {
            // Any other shape (a partial exclusion, a second epoch step, a
            // removal before raw N, a broken data plane) is not a named
            // red cause.
            receipt.cause(
                CAUSE_NO_EXPIRY_EVICTION,
                Some(describe_seats(&end)),
                false,
                at(sim),
            );
        }
    }
    receipt.finish(run.final_name(), passed, at(sim));
    Ok(())
}

/// How often the stall watchdog reads the daemons' wall clock.
const STALL_POLL: Duration = Duration::from_secs(5);

/// A stall watchdog for one run of these arms. [`real_time_watchdog`] ends
/// a case that is still running [`REAL_TIME_STALL`] after its start,
/// whatever the case is doing. One arm here is about 900 virtual seconds:
/// 105-125 s of real time in the 12-CPU VM and 172-185 s on the 4-vCPU CI
/// runner when it passes, so that limit also ended healthy runs on a slower
/// runner (main CI run 43891524690, each arm at 200 s in rerun 1). This one
/// ends the run only when virtual time has not moved for
/// [`REAL_TIME_STALL`] of real time, which is what a stall in a barrier
/// does. The shim's wall clock is base + virtual time on every thread, so
/// the watchdog thread reads it with [`wall_ms`]; nextest's kill for these
/// arms (the `w3h-gate` override) stays the limit on a run that moves.
pub(super) fn stall_watchdog(case: &str, fabric: Arc<SimFabric>) -> Watchdog {
    let disarmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&disarmed);
    let case = case.to_string();
    std::thread::spawn(move || {
        let mut last_ms = wall_ms();
        let mut still = Duration::ZERO;
        loop {
            std::thread::sleep(STALL_POLL);
            if flag.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let now_ms = wall_ms();
            if now_ms != last_ms {
                last_ms = now_ms;
                still = Duration::ZERO;
                continue;
            }
            still += STALL_POLL;
            if still >= REAL_TIME_STALL {
                break;
            }
        }
        let trace = fabric.canonical_trace();
        println!(
            "W3H-STALL {case}: virtual time has not moved for {REAL_TIME_STALL:?} of real time \
             (wall {last_ms} ms); last trace lines (newest first):"
        );
        for line in trace.lines().rev().take(60) {
            println!("W3H-STALL {line}");
        }
        std::process::exit(101);
    });
    Watchdog { disarmed }
}

async fn run_skew(case: &str, seed: u64, run: SkewRun) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1581 / ADR 0110 S4 s4_certificate_expiry_skew run {run:?}. Timing from \
         S4Timing::default() (D69, D73): {:?}; \u{3c4} = {TAU} s.",
        timing()
    ));
    match Sim::empty(case, seed, FIVE_SKEW) {
        Ok(mut sim) => {
            let fabric = Arc::clone(sim.fabric());
            let watchdog = stall_watchdog(case, fabric);
            let outcome = skew_scenario(&mut sim, run, &mut receipt).await;
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
        receipt.reclassify(run.final_name());
    }
    receipt.emit();
    receipt
}

async fn expect_skew(case: &str, seed: u64, run: SkewRun, want: Verdict) -> Result<()> {
    let receipt = run_skew(case, seed, run).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// ADR 0110 `s4_certificate_expiry_skew` run (1): GREEN with S4.
#[test]
#[ignore = "needs the W3-H LD_PRELOAD shim: the W3-H gate runs it with --run-ignored all"]
fn w3h_1581j_expiry_skew_run1_all_offsets_zero() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_skew(
            "w3h_1581j_expiry_skew_run1_all_offsets_zero",
            0x1581_0030,
            SkewRun::AllZero,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_certificate_expiry_skew` run (5a), read with §4a (L289):
/// GREEN with S4's rebinding commit.
#[test]
#[ignore = "needs the W3-H LD_PRELOAD shim: the W3-H gate runs it with --run-ignored all"]
fn w3h_1581j_expiry_skew_run5a_announced_renewal_rebinds_at_expiry() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_skew(
            "w3h_1581j_expiry_skew_run5a_announced_renewal_rebinds_at_expiry",
            0x1581_0031,
            SkewRun::AnnouncedRenewal,
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_certificate_expiry_skew` run (8): GREEN with S4.
#[test]
#[ignore = "needs the W3-H LD_PRELOAD shim: the W3-H gate runs it with --run-ignored all"]
fn w3h_1581j_expiry_skew_run8_signed_public() -> Result<()> {
    super::super::super::block_on_paused(async move {
        expect_skew(
            "w3h_1581j_expiry_skew_run8_signed_public",
            0x1581_0032,
            SkewRun::SignedPublic,
            Verdict::Green,
        )
        .await
    })
}
