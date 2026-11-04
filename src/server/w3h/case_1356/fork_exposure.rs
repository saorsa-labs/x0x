//! ADR 0109 §10 row H-S3-d2 (D77, exposure contained; #1572). Control,
//! expected GREEN with S3.
//!
//! Setup: S0. A (creator) seats M1, M2 and X, promotes X to admin and
//! makes the four policy changes. X mints invite I_X at r−1; A renames
//! (r). Then every message between {X, J} and {A, M1, M2} is held. A
//! removes X (r+1), X renames (r+1′), J redeems I_X and X seals J (r+2′).
//! The case advances [`CATCHUP`].
//!
//! **Engineer ruling (b), 4 Nov 2026 (test-only).** With I_X at r (the
//! ADR text) J never holds a marker (VM runs d2-3, d2-4): a joiner keeps
//! its served links, not its base, so `fork_candidate_authenticated`
//! cannot read A's role at r. With I_X at r−1, X serves r and r+1′, J
//! keeps r, and A's r+1 authenticates. The link at r is a rename, because
//! a policy change in a served chain stops `validate_alternate_chain`.
//!
//! Release: J and {A, M1, M2} pass; X stays cut. The fabric drops a held
//! write, so A publishes its recorded r+1 bytes again until J holds a
//! marker. After one request interval X sends its join-carry ATA to J
//! again, as a `group_attest_response` for J's head.
//!
//! Desired: after the first advance, J is Active at r+2′ on X's branch,
//! and A, M1 and M2 are unchanged. After the release, J holds a marker
//! naming A's r+1; A, M1 and M2 each answer `not_a_member` (§1 step 3);
//! J shows `reseat_required {not_a_member}`; the ATA retires nothing and
//! no node commits. J's `recovery.asked` shows each answer (§8). Only an
//! admin's `GET /groups/:id/recovery` lists requesters (§8), so A's list
//! also shows J was refused before any walk; M1's and M2's are empty.
//!
//! Fidelity: the hold keys on a write's origin (the first sender of its
//! pubsub message ID), so relays are held too. Transport control passes.
//! Before the hold, each node fetches the others' adverts (§5).
//! A missing prerequisite is INFRA; a failed row assertion is RED.

use super::gaps::{answered, promote, recovery_route, recovery_text, sees_s3};
use super::*;
use crate::groups::recovery::{
    encode_message, AdminTerminalAttestation, AttestAnswer, GroupAttestResponseV1,
    GroupRecoveryMessageV1,
};
use crate::network::sim::{Fault, Key, LaneClass};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const LABELS: &[&str] = &["A", "M1", "M2", "X", "J"];
const MAIN: [&str; 3] = ["A", "M1", "M2"];
const FINAL: &str = "j_exposed_on_x_fork_then_reseat_required_not_a_member_and_ata_inert";
const CAUSE: &str = "the row's assertions: J is not Active at r+2′ on X's branch after the \
                     first advance (the base marks J at r+2′ before the release), or A, M1 or \
                     M2 change, or J's marker, answers or typed state differ, or the ATA \
                     retires or commits anything; `observed` lists each failing step";
const RESEAT: &str = "reseat_required{not_a_member}";
/// One request interval (§11: the first retry after 60 s, plus margin).
const REQUEST_INTERVAL: Duration = Duration::from_secs(70);
/// A publishes its r+1 bytes again after this long with no marker on J.
const REPUBLISH: Duration = Duration::from_secs(10);
/// One direct send with J's ack held: every attempt and its retry.
const SEND_BOUND: Duration = Duration::from_secs(60);
/// After the injection, J's answer path has run.
const AFTER_INJECT: Duration = Duration::from_secs(30);

/// Hold phases: open; every message between {X, J} and {A, M1, M2};
/// everything to and from X; as `CUT_X`, except X's writes to J.
const OPEN: u8 = 0;
const SPLIT: u8 = 1;
const CUT_X: u8 = 2;
const INJECT: u8 = 3;

struct Hold {
    phase: Arc<AtomicU8>,
    dropped: Arc<AtomicUsize>,
}

impl Hold {
    fn install(sim: &Sim) -> Result<Self> {
        let (x, j) = (sim.peer("X")?.0, sim.peer("J")?.0);
        let main: Vec<Key> = MAIN
            .iter()
            .map(|label| Ok(sim.peer(label)?.0))
            .collect::<Result<_>>()?;
        let phase = Arc::new(AtomicU8::new(OPEN));
        let dropped = Arc::new(AtomicUsize::new(0));
        let origins: Mutex<std::collections::HashMap<[u8; 32], Key>> = Mutex::default();
        let (rule_phase, rule_dropped) = (Arc::clone(&phase), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            if matches!(
                write.lane.class,
                LaneClass::Membership | LaneClass::PlaneHello
            ) {
                return Fault::Pass;
            }
            let msg = (write.lane.class == LaneClass::PubSub)
                .then(|| pubsub_header(&write.bytes))
                .flatten();
            let origin = match (msg, origins.lock()) {
                (Some((_, id)), Ok(mut map)) => *map.entry(id).or_insert(write.lane.src),
                (Some(_), Err(_)) => return Fault::Drop,
                (None, _) => write.lane.src,
            };
            let dst = write.lane.dst;
            let side = |key: Key| key == x || key == j;
            let drop = match rule_phase.load(Ordering::SeqCst) {
                SPLIT => {
                    (side(origin) && main.contains(&dst)) || (main.contains(&origin) && side(dst))
                }
                CUT_X => origin == x || dst == x,
                INJECT => (origin == x && dst != j) || dst == x,
                _ => false,
            };
            if drop {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                return Fault::Drop;
            }
            Fault::Pass
        });
        Ok(Self { phase, dropped })
    }

    fn set(&self, sim: &Sim, phase: u8, what: &str) {
        self.phase.store(phase, Ordering::SeqCst);
        sim.fabric().mark(format!("fault: H-S3-d2 hold now {what}"));
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

/// `f` applied to `label`'s record of `group`, if it has one.
async fn record<T>(
    sim: &Sim,
    label: &str,
    group: &str,
    f: impl FnOnce(&crate::groups::GroupInfo) -> T,
) -> Result<Option<T>> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    Ok(crate::server::resolve_group_entry_locked(&groups, group).map(|(_, info)| f(info)))
}

/// `label`'s marker as `(revision, state hash, committed_by)`.
async fn marker_of(sim: &Sim, label: &str, group: &str) -> Result<Option<(u64, String, String)>> {
    Ok(record(sim, label, group, |info| {
        info.fork_quarantine
            .as_ref()
            .map(|m| (m.revision, m.state_hash.clone(), m.committed_by.clone()))
    })
    .await?
    .flatten())
}

/// The `(topic, bytes)` that `label` has published, in order.
fn publishes(sim: &Sim, label: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let state = sim.state(label)?;
    let all = state.named_group_test_recorders.publish_bytes.lock();
    let all = all
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok(all)
}

/// The join-carry ATA in `issuer`'s last recorded join result for `joiner`.
fn join_carry(sim: &Sim, issuer: &str, joiner: &str) -> Result<Option<AdminTerminalAttestation>> {
    use crate::server::routes::named_groups::JoinResultMessage;
    let joiner_hex = sim.agent_hex(joiner)?;
    let state = sim.state(issuer)?;
    let served = state.named_group_test_recorders.join_result_serves.lock();
    let served = served.unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(served
        .iter()
        .rev()
        .filter(|(to, _, _)| to.eq_ignore_ascii_case(&joiner_hex))
        .find_map(|(_, _, payload)| match serde_json::from_slice(payload) {
            Ok(JoinResultMessage::Result {
                admin_attestation, ..
            }) => admin_attestation.map(|ata| *ata),
            _ => None,
        }))
}

/// Each label's `(state revision, state hash)`.
async fn heads(sim: &Sim, group: &str) -> Result<Vec<(&'static str, u64, String)>> {
    let mut out = Vec::new();
    for label in LABELS {
        let v = view(sim, label, group).await?;
        out.push((*label, v.state_revision, v.state_hash));
    }
    Ok(out)
}

/// J's `recovery.asked` shows `not_a_member` from each of `targets`, and
/// A's requester list shows J refused `not_a_member` and never walked.
fn all_refused(j_recovery: &Value, targets: &[String], a_route: &Value, j_hex: &str) -> bool {
    let asked = |hex: &String| {
        j_recovery["asked"].as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row["agent"]
                    .as_str()
                    .is_some_and(|id| id.eq_ignore_ascii_case(hex))
                    && row["answer"] == "not_a_member"
            })
        })
    };
    targets.iter().all(asked)
        && answered(a_route, j_hex, "not_a_member")
        && ["attested", "on_chain", "not_on_chain"]
            .iter()
            .all(|w| !answered(a_route, j_hex, w))
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    mesh(sim, LABELS).await?;
    let hold = Hold::install(sim)?;
    let group = create_group(sim, "A").await?;
    for member in ["M1", "M2", "X"] {
        seat(sim, "A", member, &group).await?;
    }
    promote(sim, "A", "X", &group, &["A", "M1", "M2", "X"]).await?;
    for write_access in POLICY_CHANGES {
        let path = format!("/groups/{group}/policy");
        let body = json!({"write_access": write_access});
        let (code, answer) = sim.api("A", Method::PATCH, &path, Some(body)).await?;
        ensure!(code.is_success(), "policy {write_access}: {code} {answer}");
    }
    settled(sim, &["M1", "M2", "X"], &group, "every member holds r−1").await?;
    let minted = view(sim, "X", &group).await?;
    let link = invite(sim, "X", &group).await?;
    rename(sim, "A", &group, "w3h d2 A r").await?;
    settled(sim, &["M1", "M2", "X"], &group, "every member holds r").await?;
    let base = view(sim, "X", &group).await?;
    // §5: the hold blocks advert refreshes (15 min lifetime).
    for label in ["X", "A", "M1", "M2"] {
        sees_s3(sim, "J", label).await?;
        sees_s3(sim, label, "J").await?;
    }
    let (a_hex, x_hex, j_hex) = (
        sim.agent_hex("A")?,
        sim.agent_hex("X")?,
        sim.agent_hex("J")?,
    );

    hold.set(sim, SPLIT, "every message between {X, J} and {A, M1, M2}");
    let a_from = publishes(sim, "A")?.len();
    let path = format!("/groups/{group}/members/{x_hex}");
    let (code, body) = sim.api("A", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "A removes X: {code} {body}");
    let has = |b: &[u8], n: &[u8]| b.windows(n.len()).any(|w| w == n);
    let (topic, bytes) = publishes(sim, "A")?
        .into_iter()
        .skip(a_from)
        .find(|(_, b)| has(b, b"\"member_removed\"") && has(b, x_hex.as_bytes()))
        .context("A's r+1 event was not recorded")?;
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold A's r+1").await?;
    let removal = view(sim, "A", &group).await?;
    rename(sim, "X", &group, "w3h d2 X fork").await?;
    let fork = view(sim, "X", &group).await?;
    let joined_at = sim.fabric().mark_indexed("case: J redeems I_X");
    join(sim, "J", &link).await?;
    sim.until("X seals J", SETUP, async |s: &Sim| {
        view_now(s, "X", &group)
            .await
            .is_ok_and(|v| v.lists(&j_hex))
    })
    .await?;
    let sealed = view(sim, "X", &group).await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "ownerless_group_x_admin_mints_i_x_at_r_minus_1_and_holds_r",
        !minted.owner_axis
            && minted.marker.is_none()
            && base.state_revision == minted.state_revision + 1,
        format!(
            "X at the mint {}; X at r {}",
            minted.describe(),
            base.describe()
        ),
        at(sim),
    );
    receipt.evidence(
        "a_removes_x_at_r_plus_1_and_x_forks_at_r_plus_1_prime",
        removal.state_revision == base.state_revision + 1
            && !removal.lists(&x_hex)
            && fork.state_revision == removal.state_revision
            && fork.state_hash != removal.state_hash,
        format!("A {}; X {}", removal.describe(), fork.describe()),
        at(sim),
    );
    // First advance: J on X's branch; A, M1 and M2 unchanged.
    let mut j_marked: Option<String> = None;
    let mut main_changed: Option<String> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the first advance", CATCHUP, async |s: &Sim| {
            for label in MAIN {
                let Some(v) = seen.observe(view_now(s, label, &group)).await else {
                    return true;
                };
                if v.marker.is_some() || v.state_hash != removal.state_hash {
                    main_changed.get_or_insert_with(|| {
                        format!("at {} us: {label} {}", at(s), v.describe())
                    });
                }
            }
            let Some(j) = seen.observe(try_view_now(s, "J", &group)).await else {
                return true;
            };
            if let Some(j) = j.filter(|j| j.marker.is_some()) {
                j_marked.get_or_insert_with(|| format!("at {} us: J {}", at(s), j.describe()));
            }
            false
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    seen.verify("the first advance")?;
    // X records its join result when it serves it, after the seal.
    let carry = join_carry(sim, "X", "J")?;
    receipt.evidence(
        "x_seals_j_at_r_plus_2_prime_with_a_join_carry_ata",
        sealed.state_revision == base.state_revision + 2
            && carry
                .as_ref()
                .is_some_and(|a| a.fields.sequence.contains(&base.state_hash)),
        format!(
            "X {}; carry {:?}",
            sealed.describe(),
            carry
                .as_ref()
                .map(|a| (a.fields.from_revision, a.fields.sequence.len()))
        ),
        at(sim),
    );
    let x1 = view(sim, "X", &group).await?;
    let j1 = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let membership = status(sim, "J", &group)
        .await?
        .and_then(|st| st.membership.clone());
    let exposed = j_marked.is_none()
        && x1.state_hash == sealed.state_hash
        && caught_up(j1.as_ref(), &x1, membership.as_deref());
    let to_x = delivered_after(sim, "J", "X", joined_at)?;
    receipt.request_delivered(
        "j_join_reached_x",
        to_x > 0 && sealed.lists(&j_hex),
        format!("frames J->X since the join: {to_x}"),
        at(sim),
    );
    let j1_text = j1
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);
    receipt.note(format!(
        "after the first advance: J {j1_text} membership {membership:?}; X {}; J marked \
         {j_marked:?}; A/M1/M2 first change {main_changed:?}; held writes {}",
        x1.describe(),
        hold.dropped()
    ));
    if !exposed {
        let observed =
            format!("J {j1_text}; marked {j_marked:?}; A/M1/M2 first change {main_changed:?}");
        let red = j_marked.is_some() || main_changed.is_some();
        receipt.cause(CAUSE, Some(observed), red, at(sim));
        receipt.finish(FINAL, false, at(sim));
        return Ok(());
    }
    let mut failing: Vec<&str> = Vec::new();
    if main_changed.is_some() {
        failing.push("a_m1_m2_unchanged_in_the_first_advance");
    }
    let before = heads(sim, &group).await?;
    let holds_r = record(sim, "J", &group, |info| {
        info.commit_log
            .iter()
            .any(|e| e.commit.state_hash == base.state_hash)
    })
    .await?
    .unwrap_or(false);
    receipt.evidence(
        "j_retains_the_commit_at_r",
        holds_r,
        format!("r {} on J: {holds_r}", short(&base.state_hash)),
        at(sim),
    );

    // Release: J and {A, M1, M2} pass; X stays cut. A's r+1 first.
    hold.set(sim, CUT_X, "everything to and from X");
    let released_at = sim.fabric().mark_indexed("case: A publishes r+1 again");
    let mut republished = 0;
    let mut last: Option<Duration> = None;
    let marked = sim
        .until("J holds a marker naming A's r+1", SETUP, async |s: &Sim| {
            let now = s.fabric().now();
            if last.is_none_or(|t| now >= t + REPUBLISH) {
                last = Some(now);
                if let Ok(state) = s.state("A") {
                    if state.agent.publish(&topic, bytes.clone()).await.is_ok() {
                        republished += 1;
                    }
                }
            }
            marker_of(s, "J", &group).await.ok().flatten().is_some()
        })
        .await
        .is_ok();
    let marker = marker_of(sim, "J", &group).await?;
    let names_r1 = marker.as_ref().is_some_and(|(rev, hash, by)| {
        *rev == removal.state_revision
            && *hash == removal.state_hash
            && by.eq_ignore_ascii_case(&a_hex)
    });
    let mut r1_frames = 0;
    for label in MAIN {
        let (src, dst) = (sim.peer(label)?, sim.peer("J")?);
        r1_frames += sim
            .fabric()
            .delivered_writes_after(&src, &dst, released_at)
            .iter()
            .filter(|(w, _)| has(&w.bytes, b"\"member_removed\""))
            .count();
    }
    receipt.request_delivered(
        "a_r_plus_1_reached_j",
        marked && r1_frames > 0,
        format!(
            "A published r+1 {republished} times; frames to J carrying member_removed \
             {r1_frames}; J {}",
            view(sim, "J", &group).await?.describe()
        ),
        at(sim),
    );
    if !names_r1 {
        failing.push("j_marker_names_a_r_plus_1");
    }

    // One request interval: A, M1 and M2 each refuse `not_a_member`.
    let asked_at = sim.fabric().mark_indexed("case: one request interval");
    let main_hex: Vec<String> = MAIN
        .iter()
        .map(|label| sim.agent_hex(label))
        .collect::<Result<_>>()?;
    let mut states: Vec<String> = Vec::new();
    let mut j_recovery = Value::Null;
    let mut a_route = Value::Null;
    let _ = sim
        .until(
            "J's requests are answered",
            REQUEST_INTERVAL,
            async |s: &Sim| {
                if let Ok(Some(st)) = status_now(s, "J", &group).await {
                    j_recovery = st.recovery;
                }
                let text = recovery_text(&j_recovery);
                if states.last() != Some(&text) {
                    states.push(text.clone());
                }
                if let Ok(route) = recovery_route(s, "A", &group).await {
                    a_route = route;
                }
                text == RESEAT && all_refused(&j_recovery, &main_hex, &a_route, &j_hex)
            },
        )
        .await;
    let j_requests: usize = MAIN
        .iter()
        .map(|l| delivered_after(sim, "J", l, asked_at))
        .sum::<Result<usize>>()?;
    receipt.request_delivered(
        "j_requests_reached_a_m1_m2",
        j_requests > 0,
        format!("frames J->A,M1,M2 in the interval: {j_requests}"),
        at(sim),
    );
    if !all_refused(&j_recovery, &main_hex, &a_route, &j_hex) {
        failing.push("a_m1_m2_each_refuse_not_a_member");
    }
    let typed = status(sim, "J", &group).await?.is_some_and(|st| {
        st.recovery_state() == Some("reseat_required")
            && st.recovery_cause() == Some("not_a_member")
    });
    if !typed {
        failing.push("j_shows_reseat_required_not_a_member");
    }

    // X's join-carry ATA to J again, for J's head.
    let carry = carry.context("X's join-carry ATA was not recorded")?;
    let j2 = view(sim, "J", &group).await?;
    // The production check J runs on it, at the ATA's own issue time (so
    // only the head decides): J has moved on from the ATA's `from`.
    let local = carry.verify_for_subject(
        &carry.fields.group,
        &j_hex,
        j2.state_revision,
        &j2.state_hash,
        carry.fields.issued_at_ms,
        false,
    );
    let payload = encode_message(&GroupRecoveryMessageV1::Response(GroupAttestResponseV1 {
        group: carry.fields.group.clone(),
        subject: sim.ids("J")?.0 .0,
        for_head_state_hash: j2.state_hash.clone(),
        answer: AttestAnswer::Attested(Box::new(carry)),
    }))?;
    hold.set(sim, INJECT, "X cut, except X's writes to J");
    let injected_at = sim
        .fabric()
        .mark_indexed("case: X injects its join-carry ATA");
    let (agent, j_id) = (sim.state("X")?.agent.clone(), sim.ids("J")?.0);
    sim.within("X sends the ATA", SEND_BOUND, async {
        let _ = agent.send_direct(&j_id, payload).await;
    })
    .await?;
    hold.set(sim, CUT_X, "everything to and from X");
    let injected = delivered_after(sim, "X", "J", injected_at)?;
    receipt.request_delivered(
        "x_ata_reached_j",
        injected > 0,
        format!("frames X->J for the injection: {injected}; local verify {local:?}"),
        at(sim),
    );
    sim.within("J handles the ATA", AFTER_INJECT + secs(2), async {
        tokio::time::sleep(AFTER_INJECT).await;
    })
    .await?;
    let after = heads(sim, &group).await?;
    let marker_after = marker_of(sim, "J", &group).await?;
    let end_text = status(sim, "J", &group)
        .await?
        .map_or_else(|| "none".to_string(), |st| recovery_text(&st.recovery));
    if marker_after != marker || end_text != RESEAT {
        failing.push("re_injected_ata_retires_nothing");
    }
    if after != before {
        failing.push("no_node_commits_after_the_release");
    }
    let observed = format!(
        "failing {failing:?}; J marker {marker:?} -> {marker_after:?} (A's r+1 {} by {}); J \
         states {states:?} -> {end_text}; J asked {}; A's requesters {}; heads {before:?} -> \
         {after:?}; held writes {}",
        short(&removal.state_hash),
        short(&a_hex),
        j_recovery["asked"],
        a_route["requesters"],
        hold.dropped()
    );
    receipt.note(observed.clone());
    if !failing.is_empty() {
        receipt.cause(CAUSE, Some(observed), true, at(sim));
    }
    receipt.finish(FINAL, failing.is_empty(), at(sim));
    Ok(())
}

/// H-S3-d2 (D77): control, GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_d2_fork_exposure_contained() -> Result<()> {
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_d2_fork_exposure_contained";
        let receipt = run(case, 0x1356_0132).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt
        .note("ADR 0109 S3 (#1356, #1572) H-S3-d2: X's fork seats J; the exposure stays contained");
    match Sim::start(case, seed, LABELS).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}
