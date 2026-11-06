//! ADR 0109 §10 row H-S3-rm2 (receiver rule, D156, #1572). H-S3-c runs up
//! to A's re-seat call, with member M (here M1, seated before invite I) on
//! the candidate. Every write that A or J originates is held from M1 from
//! the removal of J (r+3) on, so A's real re-seat seal (r+4) does not
//! reach M1. A then publishes to M1, one at a time as gossip, a copy of
//! its re-seat `MemberAdded` whose `reseat_mandate` the harness changes in
//! one way and re-signs with A's agent key (except (1)). M1 must refuse
//! each with `reseat_mandate_invalid` and the typed cause, and keep its
//! committed state at r+3. Then A publishes its real seal again, and M1
//! must apply it at r+4.
//!
//! Injections, in ADR order: (1) one signature byte changed, not
//! re-signed (`signature`); (2) a wrong policy hash (`policy_mismatch`);
//! (3) a seating commit that did not seat J: O's r+1, which removes X
//! before J joins (`not_previously_seated`); (4) O's removal commit r+1
//! in place of A's r+3 (`removal_mismatch`); (5) a different owner
//! certificate digest for J (`certificate_invalid`); (6) role Admin,
//! where J was a Member (`role_raised`); (7) a terminal roster hash that
//! does not match (`binding_mismatch`). Check 2 is not injected (the ADR's
//! own note).
//!
//! (3) and (5) are the Engineer's option (b) (4 Nov 2026 04:32 GMT), a
//! test-only change to the ADR text. The ADR's (3) "subject E, never
//! seated" cannot reach check 4: the product's check 1 also binds the
//! mandate subject to the event's added agent
//! (`src/groups/recovery.rs:1414`), so it refuses as `signature`, and an
//! event that adds E is refused before the §3a rule by the certificate
//! gate (`src/server/routes/named_groups.rs:16637`). The ADR's (5) "a
//! revoked owner certificate for J" cannot reach check 6: revocation is
//! per identity, not per certificate, and the product checks it in check
//! 5 (`src/groups/recovery.rs:1474`, `removal_mismatch`); the same
//! certificate gate also refuses a revoked J first, with no typed cause.
//!
//! The observable is M1's WARN line `MemberAdded: reseat_mandate_invalid`
//! with its `cause` field (the receive path exposes no API field or
//! counter for it). A captured log has no node label, so the row makes
//! the attribution exact: a forged frame reaches M1 only (no other node
//! receives it, from any sender), one forgery is out at a time, and each
//! new refusal line in its window must carry that forgery's cause.
//!
//! RED: a delivered forgery that M1 applies, or refuses with no or another
//! cause, or after which M1's record moves; or A's released seal reaching
//! M1 with no apply. A missing prerequisite, a forgery that never reaches
//! M1, or a real-seal frame that leaks to M1 early is INFRA.

use super::*;
use crate::groups::recovery::ReseatMandateV1;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const FINAL_RM2: &str = "m1_refuses_each_bad_reseat_mandate_typed_then_applies_the_real_seal";
const CAUSE_RM2: &str = "the row's main observation: M1 applies a forged re-seat mandate, or \
                         refuses one with no or another cause, or its record moves; or M1 \
                         does not apply A's released real seal; `observed` lists each \
                         failing step";
/// How long M1 has to log its refusal of one forgery. A window reads every
/// refusal line from its own start. [`M1Hold`] drops a resend outside its
/// window, but a refusal that M1 logs after its window has expired also
/// counts in the next window. The row cannot pass by it: the late window
/// has no cause and the next one a wrong cause, both failing sub-checks.
const REFUSAL_WAIT: Duration = Duration::from_secs(60);
/// The refusal line and its cause field, as `LogText` records them.
const REFUSAL: &str = "reseat_mandate_invalid";

/// One forged copy of A's re-seat `MemberAdded`.
struct Forgery {
    what: &'static str,
    cause: &'static str,
    bytes: Vec<u8>,
    /// The forged signature's leading hex: it marks the forgery's frames.
    needle: String,
}

/// M1's answer to one forgery.
struct Answer {
    to_m1: usize,
    elsewhere: usize,
    causes: Vec<String>,
    unchanged: bool,
}

/// The fault for this row, after the prefix's own: while `held`, every
/// write that A or J originates is dropped at M1, except pubsub messages
/// that A first sends while `injecting` (the forgeries). A forgery is
/// dropped at every other node, always. A forgery reaches M1 only in its
/// own window (`window`): a later resend of it is dropped at M1 too, so no
/// refusal of an earlier forgery falls into the window of the next one.
struct M1Hold {
    held: Arc<AtomicBool>,
    injecting: Arc<AtomicBool>,
    window: Arc<AtomicU64>,
}

fn hold_m1(sim: &Sim) -> Result<M1Hold> {
    let (a, j, m1) = (sim.peer("A")?.0, sim.peer("J")?.0, sim.peer("M1")?.0);
    let held = Arc::new(AtomicBool::new(true));
    let injecting = Arc::new(AtomicBool::new(false));
    let window = Arc::new(AtomicU64::new(0));
    let seen: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::default();
    let forged: Arc<Mutex<HashMap<[u8; 32], u64>>> = Arc::default();
    let hold = install_hold(sim);
    let (h, inj, win) = (
        Arc::clone(&held),
        Arc::clone(&injecting),
        Arc::clone(&window),
    );
    set_hold(
        sim,
        &hold,
        "A's and J's writes to M1 held; A's forgeries reach M1 only",
        move |origin, dst, msg| {
            let mut forged_in = None;
            if let (Some(id), true) = (msg, origin == a) {
                let (Ok(mut seen), Ok(mut forged)) = (seen.lock(), forged.lock()) else {
                    return true;
                };
                let open = inj.load(Ordering::SeqCst);
                if let Some(at) = forged.get(&id) {
                    forged_in = Some(*at);
                } else if !seen.contains(&id) && open {
                    let at = win.load(Ordering::SeqCst);
                    forged.insert(id, at);
                    forged_in = Some(at);
                } else {
                    seen.insert(id);
                }
            }
            if let Some(at) = forged_in {
                let live = inj.load(Ordering::SeqCst) && at == win.load(Ordering::SeqCst);
                return !(live && dst == m1);
            }
            h.load(Ordering::SeqCst) && dst == m1 && (origin == a || origin == j)
        },
    );
    sim.fabric().mark("fault: A's and J's writes to M1 held");
    Ok(M1Hold {
        held,
        injecting,
        window,
    })
}

/// Delivered pubsub writes after `cut` that carry `needle`: to M1, and to
/// every other node (from any sender).
fn needle_deliveries(sim: &Sim, cut: usize, needle: &[u8]) -> Result<(usize, usize)> {
    use crate::network::sim::{Fate, LaneClass};
    let m1 = sim.peer("M1")?.0;
    let (mut to_m1, mut elsewhere) = (0, 0);
    for (position, write, fate) in sim.fabric().writes_with_positions() {
        let hit = position >= cut
            && write.lane.class == LaneClass::PubSub
            && matches!(fate, Some(Fate::Delivered { .. }))
            && write.bytes.windows(needle.len()).any(|w| w == needle);
        if hit {
            match write.lane.dst == m1 {
                true => to_m1 += 1,
                false => elsewhere += 1,
            }
        }
    }
    Ok((to_m1, elsewhere))
}

/// The `cause` of each refusal line captured since virtual time `from`.
fn refusal_causes(sim: &Sim, from: Duration) -> Vec<String> {
    sim.logs_containing(&[REFUSAL])
        .into_iter()
        .filter(|log| log.at >= from)
        .map(|log| {
            log.text
                .split("cause=\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or("none")
                .to_string()
        })
        .collect()
}

fn needle_of(mandate: &ReseatMandateV1) -> String {
    mandate.signature.chars().take(64).collect()
}

/// The seven forgeries, built from A's real event `real` (its JSON).
/// `r1_hash` is O's r+1 removal of X as M1 holds it.
fn forgeries(sim: &Sim, real: &Value, r1_hash: &str) -> Result<Vec<Forgery>> {
    let mandate: ReseatMandateV1 = serde_json::from_value(
        real.get("reseat_mandate")
            .cloned()
            .context("A's re-seat MemberAdded carries no reseat_mandate")?,
    )?;
    let state = sim.state("A")?;
    let keypair = state.agent.identity().agent_keypair();
    let event_with = |forged: &ReseatMandateV1| -> Result<Vec<u8>> {
        let mut event = real.clone();
        event["reseat_mandate"] = serde_json::to_value(forged)?;
        Ok(serde_json::to_vec(&event)?)
    };
    let mut out = Vec::new();
    let mut one = |what, cause, forged: ReseatMandateV1| -> Result<()> {
        out.push(Forgery {
            what,
            cause,
            bytes: event_with(&forged)?,
            needle: needle_of(&forged),
        });
        Ok(())
    };
    let mut raw = hex::decode(&mandate.signature)?;
    *raw.first_mut().context("A's mandate has no signature")? ^= 0x01;
    let mut flipped = mandate.clone();
    flipped.signature = hex::encode(raw);
    one("(1) one signature byte changed", "signature", flipped)?;
    type Edit = fn(&mut crate::groups::recovery::ReseatMandateFields, &str);
    let edits: [(&'static str, &'static str, Edit); 6] = [
        ("(2) a wrong policy hash", "policy_mismatch", |f, _| {
            f.policy_hash = blake3::hash(b"w3h rm2: wrong policy").to_hex().to_string();
        }),
        (
            "(3) a seating commit that did not seat J",
            "not_previously_seated",
            |f, r1| {
                f.seating_commit_hash = r1.to_string();
            },
        ),
        (
            "(4) O's removal r+1 in place of r+3",
            "removal_mismatch",
            |f, r1| {
                f.removal_commit_hash = r1.to_string();
            },
        ),
        (
            "(5) a different owner certificate for J",
            "certificate_invalid",
            |f, _| {
                f.certificate_digest = blake3::hash(b"w3h rm2: another certificate")
                    .to_hex()
                    .to_string();
            },
        ),
        ("(6) role Admin for a Member", "role_raised", |f, _| {
            f.role = crate::groups::GroupRole::Admin;
        }),
        (
            "(7) a terminal roster hash that does not match",
            "binding_mismatch",
            |f, _| {
                f.terminal_roster_hash =
                    blake3::hash(b"w3h rm2: wrong roster").to_hex().to_string();
            },
        ),
    ];
    for (what, cause, edit) in edits {
        let mut fields = mandate.fields.clone();
        edit(&mut fields, r1_hash);
        let signed = ReseatMandateV1::sign(fields, keypair)
            .map_err(|e| anyhow!("A re-signs {what}: {e:?}"))?;
        one(what, cause, signed)?;
    }
    Ok(out)
}

/// A publishes `forgery`; M1 must log its refusal with the forgery's cause
/// and keep `base`.
async fn inject(
    sim: &Sim,
    group: &str,
    topic: &str,
    base: &View,
    hold: &M1Hold,
    forgery: &Forgery,
) -> Result<Answer> {
    let cut = sim
        .fabric()
        .mark_indexed(format!("case: A publishes {}", forgery.what));
    let from = sim.fabric().now();
    hold.window.fetch_add(1, Ordering::SeqCst);
    hold.injecting.store(true, Ordering::SeqCst);
    let published = sim
        .state("A")?
        .agent
        .publish(topic, forgery.bytes.clone())
        .await;
    if let Err(error) = published {
        hold.injecting.store(false, Ordering::SeqCst);
        return Err(error.into());
    }
    let needle = forgery.needle.as_bytes();
    let waited = sim
        .until(
            &format!("M1 refuses {}", forgery.what),
            REFUSAL_WAIT,
            async |s: &Sim| {
                needle_deliveries(s, cut, needle).is_ok_and(|(n, _)| n > 0)
                    && !refusal_causes(s, from).is_empty()
            },
        )
        .await;
    // Open until M1 has the frame: gossip writes it after `publish` returns.
    hold.injecting.store(false, Ordering::SeqCst);
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    let (to_m1, elsewhere) = needle_deliveries(sim, cut, needle)?;
    let now = view(sim, "M1", group).await?;
    Ok(Answer {
        to_m1,
        elsewhere,
        causes: refusal_causes(sim, from),
        unchanged: same_record(Some(&now), Some(base)) && now.state_revision == base.state_revision,
    })
}

/// A's re-seat `MemberAdded(J)` publish since `from`: (topic, bytes).
fn real_seal(sim: &Sim, from: usize, j_hex: &str) -> Result<Option<(String, Vec<u8>)>> {
    let state = sim.state("A")?;
    let published = state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let has = |b: &[u8], n: &[u8]| b.windows(n.len()).any(|w| w == n);
    Ok(published
        .iter()
        .skip(from)
        .find(|(_, b)| {
            has(b, b"\"member_added\"") && has(b, j_hex.as_bytes()) && has(b, b"\"reseat_mandate\"")
        })
        .cloned())
}

/// The state hash and signer of the commit at `revision` in `label`'s
/// retained log.
async fn retained(
    sim: &Sim,
    label: &str,
    group: &str,
    revision: u64,
) -> Result<Option<(String, String)>> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    Ok(
        crate::server::resolve_group_entry_locked(&groups, group).and_then(|(_, info)| {
            info.commit_log
                .iter()
                .find(|e| e.commit.revision == revision)
                .map(|e| (e.commit.state_hash.clone(), e.commit.committed_by.clone()))
        }),
    )
}

/// H-S3-rm2 (ADR 0109 §10).
async fn mandate_refusals(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let Some(p) = fork_prefix(sim, receipt, false, true, FINAL_RM2).await? else {
        return Ok(());
    };
    let window = (GATE_WINDOW, "not_on_chain");
    let Some(adv) = advance(sim, receipt, &p, false, window, FINAL_RM2).await? else {
        return Ok(());
    };
    let (group, j_hex) = (p.group.clone(), p.j_hex.clone());
    // The capability floor: A holds O's and M1's current mandate adverts.
    let bit = crate::dm::CapabilityRegistry::GROUP_RESEAT_MANDATE_V1;
    let (o_agent, m1_agent) = (sim.ids("O")?.0, sim.ids("M1")?.0);
    let floor = sim
        .until(
            "A holds O's and M1's mandate adverts",
            SETUP,
            async |s: &Sim| {
                let Ok(st) = s.state("A") else {
                    return false;
                };
                let mut all = true;
                for agent in [o_agent, m1_agent] {
                    let store = st.agent.capability_store();
                    if store.verified_registry_supports(&agent, bit) != Some(true) {
                        st.agent.refresh_application_capability(agent, bit).await;
                        all = false;
                    }
                }
                all
            },
        )
        .await
        .is_ok();
    sim.stop("O", RestartMode::Graceful).await?;
    p.o_to_j_held.store(false, Ordering::SeqCst);
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = sim.api("A", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "A removes J: {code} {body}");
    let j_removal = view(sim, "A", &group).await?;
    all_reach(sim, &["M1"], &group, &j_removal.state_hash).await?;
    let base = view(sim, "M1", &group).await?;
    let r1 = retained(sim, "M1", &group, p.minted.state_revision + 1).await?;
    let hold = hold_m1(sim)?;
    let recorded_from = sim
        .state("A")?
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .map_or(0, |p| p.len());
    let swap = reseat_and_swap(sim, receipt, &p, &adv, ("A", false), &j_removal).await?;
    sim.within("A's seal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let real = real_seal(sim, recorded_from, &j_hex)?;
    let o_hex = sim.agent_hex("O")?;
    let r1_by_o = r1
        .as_ref()
        .is_some_and(|(_, by)| by.eq_ignore_ascii_case(&o_hex));
    let mut checks: Vec<(String, bool)> = [
        ("a_holds_o_and_m1_mandate_adverts", floor),
        (
            "a_removal_at_r_plus_3",
            j_removal.state_revision == p.minted.state_revision + 3 && !j_removal.lists(&j_hex),
        ),
        ("m1_at_a_removal", base.state_hash == j_removal.state_hash),
        ("m1_holds_o_removal_r_plus_1", r1_by_o),
        (
            "reseat_route_accepts_with_owner_offline",
            swap.code.is_success(),
        ),
        (
            "a_seal_at_r_plus_4",
            swap.head.state_revision == p.minted.state_revision + 4,
        ),
        ("a_publishes_a_reseat_mandate", real.is_some()),
    ]
    .into_iter()
    .map(|(name, ok)| (name.to_string(), ok))
    .collect();
    let real_json = real
        .as_ref()
        .and_then(|(_, b)| serde_json::from_slice::<Value>(b).ok());
    checks.push((
        "a_real_seal_parses_as_json".to_string(),
        real_json.is_some(),
    ));
    let (Some((topic, real_bytes)), Some(real_json), Some((r1_hash, _)), true) =
        (real.clone(), real_json, r1, checks.iter().all(|c| c.1))
    else {
        let failing: Vec<&str> = checks
            .iter()
            .filter(|c| !c.1)
            .map(|c| c.0.as_str())
            .collect();
        let observed = format!(
            "failing {failing:?}; reseat {}; A {}; M1 {}",
            swap.code,
            swap.head.describe(),
            base.describe()
        );
        // `advance` has recorded `o_reached_j`, but no forgery has reached
        // M1 yet. A failing step here is a false `cause` stage, so the
        // receipt is INFRA; only a missing re-seat route (404, pre-S3
        // `main`) is RED, as in H-S3-c3 and H-S3-d3.
        let red = swap.code == StatusCode::NOT_FOUND;
        conclude_row(
            receipt,
            (FINAL_RM2, CAUSE_RM2),
            &failing,
            observed,
            red,
            at(sim),
        );
        return Ok(());
    };
    let real_mandate: ReseatMandateV1 =
        serde_json::from_value(real_json["reseat_mandate"].clone())?;
    let real_needle = needle_of(&real_mandate);
    let (early, _) = needle_deliveries(sim, 0, real_needle.as_bytes())?;
    let m1_held = view(sim, "M1", &group).await?;
    receipt.evidence(
        "a_real_seal_held_from_m1",
        early == 0 && same_record(Some(&m1_held), Some(&base)),
        format!("real-seal frames to M1 {early}; M1 {}", m1_held.describe()),
        at(sim),
    );
    if early > 0 || !same_record(Some(&m1_held), Some(&base)) {
        receipt.note("A's real seal reached M1 before the injections: the hold leaked");
        receipt.finish(FINAL_RM2, false, at(sim));
        return Ok(());
    }

    let forged = forgeries(sim, &real_json, &r1_hash)?;
    let mut answers = Vec::new();
    for forgery in &forged {
        answers.push(inject(sim, &group, &topic, &base, &hold, forgery).await?);
    }

    // Release A's real seal: A publishes its recorded bytes again.
    hold.held.store(false, Ordering::SeqCst);
    let released = sim
        .fabric()
        .mark_indexed("case: A re-publishes its real seal");
    sim.state("A")?.agent.publish(&topic, real_bytes).await?;
    let applied = reaches(sim, "M1", &group, &swap.head.state_hash, SETUP).await;
    let (real_to_m1, _) = needle_deliveries(sim, released, real_needle.as_bytes())?;
    let m1_end = view(sim, "M1", &group).await?;

    let mut red = false;
    for (forgery, answer) in forged.iter().zip(&answers) {
        let refused = !answer.causes.is_empty() && answer.causes.iter().all(|c| c == forgery.cause);
        red |= answer.to_m1 > 0 && !(refused && answer.unchanged);
        receipt.note(format!(
            "{}: frames to M1 {}, to other nodes {}; causes {:?} (want {}); M1 unchanged {}",
            forgery.what,
            answer.to_m1,
            answer.elsewhere,
            answer.causes,
            forgery.cause,
            answer.unchanged
        ));
        // Each forgery has a distinct cause, so it names its sub-checks.
        let cause = forgery.cause;
        checks.push((
            format!("{cause}_forgery_reaches_m1_only"),
            answer.to_m1 > 0 && answer.elsewhere == 0,
        ));
        checks.push((format!("m1_refuses_{cause}_forgery_typed"), refused));
        checks.push((
            format!("m1_state_unchanged_after_{cause}_forgery"),
            answer.unchanged,
        ));
    }
    red |= real_to_m1 > 0 && !applied;
    checks.push(("m1_applies_a_real_seal_at_r_plus_4".to_string(), applied));
    receipt.request_delivered(
        "a_reached_m1",
        answers.iter().all(|a| a.to_m1 > 0),
        format!(
            "forged frames to M1 {:?}; released real-seal frames to M1 {real_to_m1}",
            answers.iter().map(|a| a.to_m1).collect::<Vec<_>>()
        ),
        at(sim),
    );
    let failing: Vec<&str> = checks
        .iter()
        .filter(|c| !c.1)
        .map(|c| c.0.as_str())
        .collect();
    receipt.note(format!("sub-checks {checks:?}"));
    let observed = format!(
        "failing {failing:?}; M1 before {}; M1 at the end {}; A {}",
        base.describe(),
        m1_end.describe(),
        swap.head.describe()
    );
    conclude_row(
        receipt,
        (FINAL_RM2, CAUSE_RM2),
        &failing,
        observed,
        red,
        at(sim),
    );
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("ADR 0109 S3 (#1356, #1572) H-S3-rm2; M1 refuses bad re-seat mandates");
    match Sim::empty(case, seed, D3_LABELS) {
        Ok(mut sim) => {
            if let Err(error) = mandate_refusals(&mut sim, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL_RM2);
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64) -> Result<()> {
    let receipt = run(case, seed).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// H-S3-rm2 (receiver rule): a control; on `main` M judges an add with no
/// owner mandate by ADR 0064 §1b.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_rm2_reseat_mandate_refusals_typed() -> Result<()> {
    let case = "w3h_1356_control_s3_rm2_reseat_mandate_refusals_typed";
    super::super::super::block_on_paused(expect(case, 0x1356_0117))
}
