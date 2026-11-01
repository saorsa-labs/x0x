//! ADR 0109 §10 row H-S3-x (conflict, §2 "Conflict"; #1572). Control,
//! expected GREEN with S3.
//!
//! **Shape (Engineer ruling (a), 29 Oct 2026).** The row as ADR 0109
//! writes it partitions B before J's seal. B then refuses J with
//! `not_a_member` (§1 step 3) and signs no ATA, so the row cannot reach a
//! conflict. Here B forks after it applies J's seal, and C's catch-up is
//! held until B's late reply:
//!
//! 1. S0 (skewed clocks) with A on the previous release (`gaps::pre_s3`).
//!    A seats and promotes B and C, then mints invite I at r. Agent IDs
//!    rise B, C, so J asks B first (D40); A is not capable.
//! 2. A removes M2 (r+1). J joins with I; A seals J (r+2). Every message
//!    between J and {B, C} is dropped from J's join on, so J's first
//!    requests get no answer. J is marked; B and C apply the seal.
//! 3. Partition B (every message to or from B is dropped). B renames
//!    (r+3′). A renames (r+3); C applies it, and nothing from A, M1 or
//!    M2 reaches J.
//! 4. J's messages reach B and C again, on any relay path, and B's pulls
//!    of J's messages (IWANT) pass on time. B's messages to J are delayed
//!    by [`B_LATE`] and C's by [`C_LATE`]; transport control passes on
//!    time. A write that B made while partitioned stays
//!    dropped (by message ID), so r+3′ never reaches J. J first gets
//!    current capability adverts from B and C (they expire after 15 min,
//!    and only a current one makes a target). J asks B, then C. C's ATA
//!    arrives first and arms; J applies the attested links of its kept
//!    served chain that it can (it moves to r+1, its marker names r+2).
//!    J asks again from r+1, B first. B's late reply (r+2, r+3′) arrives
//!    after C's renewal (r+2, r+3) and before any catch-up page from C.
//! 5. Once J shows its typed state, every hold ends. The case advances
//!    [`AFTER_HEAL`].
//!
//! Desired (§2): J's sidecar holds C's ATA as the active one and B's ATA
//! as the recorded conflict, or (in 1 of 74 CI iterations, when B's answer
//! from r arrives first) B's as the active one and C's as the conflict.
//! The delays do not fix the order, and §2 records the second diverging
//! ATA as the conflict whichever admin signed it, so the row accepts
//! both. The ATAs diverge after the seal (r+3 against r+3′), so nothing
//! past the common prefix (r+2) applies: J's state
//! revision never passes r+2, and J never holds r+3 or r+3′. J shows
//! `reseat_required {attestation_conflict}` to the end. The ATAs are read
//! from J's sidecar file with the production decoder.
//!
//! The reply that conflicts is B's answer to J's request from its head at
//! that time (r+1). B's answer to J's first request (from r) arrives after
//! J has moved to r+1, and §2 drops an answer for an old head. That is
//! the second reason the row as written is not reachable.

use super::gaps::{
    answered, promote, recovery_route, recovery_text, remove, s0, seal_j, sees_s3, start_ranked,
};
use super::*;
use crate::network::sim::{Fault, Key, LaneClass};
use std::collections::{HashMap, HashSet};

const LABELS: &[&str] = &["A", "M1", "M2", "B", "C", "J"];
const FINAL: &str = "j_reseat_required_attestation_conflict_nothing_past_the_common_prefix";
const CAUSE: &str = "J holds ATAs from B and C that diverge after the seal, and J applies a \
                     link past their common prefix or never shows reseat_required \
                     {attestation_conflict}";
/// The extra one-way delay on C's messages to J in step 4.
const C_LATE: Duration = Duration::from_secs(20);
/// The extra one-way delay on B's messages to J in step 4 (B's late
/// reply). J asks B one answer wait (10 s) before C, so B's reply comes
/// after C's answer and before C's catch-up page (`10 s + C_LATE <
/// B_LATE < 2 × C_LATE`).
const B_LATE: Duration = Duration::from_secs(35);
/// Step 4's ceiling: J's next request round after the backoff that steps
/// 2 and 3 built up, with both late replies.
const ASK_WINDOW: Duration = Duration::from_secs(900);
/// Step 5: after every hold ends.
const AFTER_HEAL: Duration = Duration::from_secs(130);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Every write passes.
    Open,
    /// Step 2: every message between J and {B, C} is dropped.
    Fence,
    /// Step 3: also every message to or from B, and every message to J.
    Partition,
    /// Step 4: J reaches B and C; their messages to J are late.
    Late,
}

#[derive(Clone, Copy)]
struct Nodes {
    b: Key,
    c: Key,
    j: Key,
}

/// The fabric rule of this row. A gossip frame's origin is the node that
/// first wrote its message ID, so a relay keeps its origin. An IWANT's
/// header names the first message it asks for, so an IWANT's origin is
/// that message's origin, not the node that asks.
struct Hold {
    phase: Arc<Mutex<Phase>>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
    replays: Arc<std::sync::atomic::AtomicUsize>,
    /// B's IWANTs for J's messages that passed in step 4.
    pulls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Hold {
    fn install(sim: &Sim) -> Result<Self> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let nodes = Nodes {
            b: sim.peer("B")?.0,
            c: sim.peer("C")?.0,
            j: sim.peer("J")?.0,
        };
        let j_inbox = crate::dm::dm_inbox_topic(&sim.ids("J")?.0).to_bytes();
        let phase = Arc::new(Mutex::new(Phase::Open));
        let dropped = Arc::new(AtomicUsize::new(0));
        let replays = Arc::new(AtomicUsize::new(0));
        let pulls = Arc::new(AtomicUsize::new(0));
        let origins: Mutex<HashMap<[u8; 32], Key>> = Mutex::new(HashMap::new());
        let partitioned: Mutex<HashSet<[u8; 32]>> = Mutex::new(HashSet::new());
        let (rule_phase, rule_dropped, rule_replays, rule_pulls) = (
            Arc::clone(&phase),
            Arc::clone(&dropped),
            Arc::clone(&replays),
            Arc::clone(&pulls),
        );
        sim.fabric().add_rule(move |write| {
            let header = (write.lane.class == LaneClass::PubSub)
                .then(|| pubsub_header(&write.bytes))
                .flatten();
            let (topic, msg_id) = (header.map(|(t, _)| t), header.map(|(_, id)| id));
            let iwant = header.is_some()
                && write
                    .bytes
                    .get(1..)
                    .and_then(saorsa_gossip_pubsub::peek_message_kind)
                    == Some(saorsa_gossip_types::MessageKind::IWant);
            let origin = match msg_id {
                Some(id) => match origins.lock() {
                    Ok(mut map) => *map.entry(id).or_insert(write.lane.src),
                    Err(_) => return Fault::Drop,
                },
                None => write.lane.src,
            };
            let Ok(current) = rule_phase.lock().map(|phase| *phase) else {
                return Fault::Drop;
            };
            let (src, dst) = (write.lane.src, write.lane.dst);
            let touches_b = src == nodes.b || dst == nodes.b || origin == nodes.b;
            let fault = match current {
                Phase::Open => Fault::Pass,
                Phase::Fence => {
                    let fenced = (dst == nodes.j && (origin == nodes.b || origin == nodes.c))
                        || (origin == nodes.j && (dst == nodes.b || dst == nodes.c));
                    if fenced {
                        Fault::Drop
                    } else {
                        Fault::Pass
                    }
                }
                Phase::Partition => {
                    if touches_b {
                        if let (Some(id), true) = (msg_id, origin == nodes.b) {
                            if let Ok(mut ids) = partitioned.lock() {
                                ids.insert(id);
                            }
                        }
                        Fault::Drop
                    } else if dst == nodes.j || (origin == nodes.j && dst == nodes.c) {
                        Fault::Drop
                    } else {
                        Fault::Pass
                    }
                }
                Phase::Late => {
                    let replay = msg_id
                        .is_some_and(|id| partitioned.lock().map_or(true, |ids| ids.contains(&id)));
                    let to_j_inbox = topic == Some(j_inbox);
                    if replay {
                        if dst == nodes.j {
                            rule_replays.fetch_add(1, Ordering::SeqCst);
                        }
                        Fault::Drop
                    } else if origin == nodes.j && dst == nodes.b {
                        // J's messages reach B, on any relay path.
                        Fault::Pass
                    } else if iwant && origin == nodes.j && src == nodes.b {
                        // B pulls one of J's messages that a peer offered
                        // it (lazy push). Without this, J's request reaches
                        // B only by an eager push, so a B that J holds lazy
                        // never gets it, and J backs off past the window
                        // (s3 job, run 41233639089 attempt 2, iteration 3).
                        rule_pulls.fetch_add(1, Ordering::SeqCst);
                        Fault::Pass
                    } else if origin == nodes.b && dst == nodes.j {
                        late(write.lane.class, B_LATE)
                    } else if origin == nodes.b && to_j_inbox {
                        // B's direct messages to J, relayed by another node.
                        Fault::Pass
                    } else if touches_b {
                        Fault::Drop
                    } else if dst == nodes.j {
                        if origin == nodes.c {
                            late(write.lane.class, C_LATE)
                        } else {
                            Fault::Drop
                        }
                    } else {
                        Fault::Pass
                    }
                }
            };
            if fault == Fault::Drop {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
            }
            fault
        });
        sim.fabric().mark("fault: H-S3-x hold installed (open)");
        Ok(Self {
            phase,
            dropped,
            replays,
            pulls,
        })
    }

    fn set(&self, sim: &Sim, phase: Phase) {
        if let Ok(mut slot) = self.phase.lock() {
            *slot = phase;
        }
        sim.fabric()
            .mark(format!("fault: H-S3-x hold now {phase:?}"));
    }

    fn counts(&self) -> String {
        use std::sync::atomic::Ordering;
        format!(
            "dropped {}, replays of partitioned writes dropped {}, B's pulls of J's messages \
             passed {}",
            self.dropped.load(Ordering::SeqCst),
            self.replays.load(Ordering::SeqCst),
            self.pulls.load(Ordering::SeqCst)
        )
    }
}

/// A late message: the message lanes are delayed; transport control
/// (membership, plane hello) passes on time, so the link stays up.
fn late(class: LaneClass, by: Duration) -> Fault {
    match class {
        LaneClass::Membership | LaneClass::PlaneHello => Fault::Pass,
        _ => Fault::Delay(by),
    }
}

/// One ATA as `(signer label, from revision, sequence)`.
type Ata = (String, u64, Vec<String>);

/// The active ATA and the recorded conflict in `label`'s S3 sidecar, read
/// from its data directory with the production decoder.
fn sidecar_atas(sim: &Sim, label: &str) -> Result<(Option<Ata>, Option<Ata>)> {
    use crate::groups::recovery::{decode_sidecar, AdminTerminalAttestation, GROUP_RECOVERY_DIR};
    let dir = sim.state(label)?.data_dir.join(GROUP_RECOVERY_DIR);
    let mut names = BTreeMap::new();
    for peer in LABELS {
        names.insert(sim.agent_hex(peer)?, (*peer).to_string());
    }
    let describe = |ata: &AdminTerminalAttestation| -> Ata {
        let by = &ata.fields.attested_by;
        (
            names
                .get(by)
                .cloned()
                .unwrap_or_else(|| short(by).to_string()),
            ata.fields.from_revision,
            ata.fields.sequence.clone(),
        )
    };
    let mut out = (None, None);
    for entry in std::fs::read_dir(&dir).with_context(|| format!("{}", dir.display()))? {
        let path = entry?.path();
        let Ok(body) = decode_sidecar(&std::fs::read(&path)?) else {
            continue;
        };
        out.0 = out.0.or(body.active_ata.as_ref().map(describe));
        out.1 = out.1.or(body.attestation_conflict.as_ref().map(describe));
    }
    Ok(out)
}

/// What the case saw of J from step 4 on.
#[derive(Default)]
struct Seen {
    states: Vec<String>,
    max_revision: u64,
    held_r3: Option<String>,
    conflict_at: Option<u128>,
    left_conflict: Option<String>,
}

impl Seen {
    /// One sample of J. `main` and `fork` are the r+3 and r+3′ hashes.
    async fn sample(&mut self, sim: &Sim, group: &str, main: &str, fork: &str) -> Result<bool> {
        let j = view_now(sim, "J", group).await?;
        let recovery = status_now(sim, "J", group)
            .await?
            .map(|st| st.recovery)
            .unwrap_or(Value::Null);
        let text = recovery_text(&recovery);
        if self.states.last() != Some(&text) {
            self.states.push(text.clone());
        }
        self.max_revision = self.max_revision.max(j.state_revision);
        if j.state_hash == main || j.state_hash == fork {
            self.held_r3
                .get_or_insert_with(|| format!("at {} us: J {}", at(sim), j.describe()));
        }
        let conflict = text == "reseat_required{attestation_conflict}";
        if conflict {
            self.conflict_at.get_or_insert(at(sim));
        } else if self.conflict_at.is_some() {
            self.left_conflict
                .get_or_insert_with(|| format!("at {} us: {text}", at(sim)));
        }
        Ok(conflict)
    }

    /// Sample J until `stop` holds on the last sample, or `budget` passes.
    async fn watch(
        &mut self,
        sim: &Sim,
        group: &str,
        (main, fork): (&str, &str),
        what: &str,
        budget: Duration,
        stop_at_conflict: bool,
    ) -> Result<()> {
        let mut failed: Option<String> = None;
        let waited = sim
            .until(what, budget, async |s: &Sim| {
                match self.sample(s, group, main, fork).await {
                    Ok(conflict) => stop_at_conflict && conflict,
                    Err(error) => {
                        failed = Some(format!("{error:#}"));
                        true
                    }
                }
            })
            .await;
        if let Some(error) = failed {
            bail!("INFRA: {what}: {error}");
        }
        if let Err(error) = waited {
            if !expired(&error) {
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Returns once `observer` holds a current verified advert from `label`
/// that sets bit 8. It asks for a fresh advert every [`C_LATE`], not on
/// every poll, so a late answer does not meet a flood of requests.
async fn fresh_advert(sim: &Sim, observer: &str, label: &str) -> Result<()> {
    let bit = crate::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1;
    let agent = sim.ids(label)?.0;
    let mut asked: Option<Duration> = None;
    sim.until(
        &format!("{observer} holds a current advert from {label}"),
        SETUP,
        async |s: &Sim| {
            let Ok(st) = s.state(observer) else {
                return false;
            };
            if st
                .agent
                .capability_store()
                .verified_registry_supports(&agent, bit)
                == Some(true)
            {
                return true;
            }
            let now = s.fabric().now();
            if asked.is_none_or(|at| now.saturating_sub(at) >= C_LATE) {
                asked = Some(now);
                st.agent.refresh_application_capability(agent, bit).await;
            }
            false
        },
    )
    .await
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    start_ranked(sim, LABELS, &["B", "C"]).await?;
    let (group, _) = s0(sim, LABELS, true, &["A"]).await?;
    for admin in ["B", "C"] {
        seat(sim, "A", admin, &group).await?;
    }
    for admin in ["B", "C"] {
        promote(sim, "A", admin, &group, &["A", "M1", "M2", "B", "C"]).await?;
    }
    for admin in ["B", "C"] {
        sees_s3(sim, "J", admin).await?;
    }
    settled(
        sim,
        &["M1", "M2", "B", "C"],
        &group,
        "every member holds A's head",
    )
    .await?;
    let minted = view(sim, "A", &group).await?;
    let link = invite(sim, "A", &group).await?;
    remove(sim, "A", "M2", &group).await?;
    settled(
        sim,
        &["M1", "B", "C"],
        &group,
        "M1, B and C hold the removal",
    )
    .await?;
    sim.within("the removal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let hold = Hold::install(sim)?;
    hold.set(sim, Phase::Fence);
    let sealed = seal_j(sim, &link, &group).await?;
    settled(sim, &["M1", "B", "C"], &group, "M1, B and C hold J's seal").await?;
    let j_hex = sim.agent_hex("J")?;
    sim.until("J is marked", SETUP, async |s: &Sim| {
        view_now(s, "J", &group)
            .await
            .is_ok_and(|j| j.marker.is_some() || j.gap_refusal.is_some())
    })
    .await?;
    let j_marked = view(sim, "J", &group).await?;
    sim.within("the seal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    hold.set(sim, Phase::Partition);
    rename(sim, "B", &group, "w3h x B").await?;
    let fork = view(sim, "B", &group).await?;
    rename(sim, "A", &group, "w3h x A").await?;
    settled(sim, &["M1", "C"], &group, "M1 and C hold A's r+3").await?;
    let main = view(sim, "A", &group).await?;
    sim.within("B's resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let j0 = view(sim, "J", &group).await?;
    let b_view = view(sim, "B", &group).await?;
    let c_view = view(sim, "C", &group).await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "b_and_c_admins_applied_j_seal_then_b_forked",
        sealed.state_revision == minted.state_revision + 2
            && fork.state_revision == sealed.state_revision + 1
            && main.state_revision == fork.state_revision
            && main.state_hash != fork.state_hash
            && b_view.lists(&j_hex)
            && c_view.lists(&j_hex)
            && b_view.marker.is_none()
            && c_view.state_hash == main.state_hash,
        format!(
            "minted {}; sealed {}; A {}; B {}; C {}",
            minted.state_revision,
            sealed.describe(),
            main.describe(),
            b_view.describe(),
            c_view.describe()
        ),
        at(sim),
    );
    receipt.evidence(
        "j_marked_behind_the_seal",
        j0.state_revision < sealed.state_revision,
        format!(
            "J at the mark {}; J now {}",
            j_marked.describe(),
            j0.describe()
        ),
        at(sim),
    );
    let since = sim
        .fabric()
        .mark_indexed("case: J reaches B and C; their replies are late");
    hold.set(sim, Phase::Late);
    // J's adverts from B and C may have expired while B and C were held
    // (15 min TTL), and only a current one makes a target (§2). J asks for
    // fresh ones; the answers are late too.
    for admin in ["B", "C"] {
        fresh_advert(sim, "J", admin).await?;
    }
    // A responder answers only a requester whose current advert it holds,
    // and sends nothing at all otherwise (§2), so B and C need J's too.
    for admin in ["B", "C"] {
        fresh_advert(sim, admin, "J").await?;
    }
    let hashes = (main.state_hash.as_str(), fork.state_hash.as_str());
    let mut seen = Seen::default();
    seen.watch(
        sim,
        &group,
        hashes,
        "J shows its typed state",
        ASK_WINDOW,
        true,
    )
    .await?;
    let j_at_conflict = view(sim, "J", &group).await?;
    let atas = sidecar_atas(sim, "J")?;
    let j_recovery = status(sim, "J", &group)
        .await?
        .map_or(Value::Null, |st| st.recovery);
    receipt.note(format!("J's recovery at the conflict {j_recovery}"));
    let b_route = sim
        .at_instant("read B's recovery", recovery_route(sim, "B", &group))
        .await??;
    let c_route = sim
        .at_instant("read C's recovery", recovery_route(sim, "C", &group))
        .await??;
    let (to_b, to_c) = (
        delivered_after(sim, "J", "B", since)?,
        delivered_after(sim, "J", "C", since)?,
    );
    receipt.request_delivered(
        "j_reached_b_and_c",
        to_b > 0 && to_c > 0,
        format!("frames J->B {to_b}, J->C {to_c}; {}", hold.counts()),
        at(sim),
    );
    hold.set(sim, Phase::Open);
    seen.watch(
        sim,
        &group,
        hashes,
        "advance after the heal",
        AFTER_HEAL,
        false,
    )
    .await?;
    let j_end = view(sim, "J", &group).await?;
    let j_status = status(sim, "J", &group).await?;
    let end_text = j_status
        .as_ref()
        .map_or_else(|| "null".to_string(), |st| recovery_text(&st.recovery));
    let by_b = answered(&b_route, &j_hex, "attested");
    let by_c = answered(&c_route, &j_hex, "attested");
    let within_prefix = seen.max_revision <= sealed.state_revision && seen.held_r3.is_none();
    let conflict = seen.conflict_at.is_some()
        && seen.left_conflict.is_none()
        && end_text == "reseat_required{attestation_conflict}";
    // §2: J's sidecar holds one ATA as the active one and the other as the
    // recorded conflict. C's sequence holds r+3 and B's holds r+3′. The
    // step 4 delays make C's ATA arrive first in most runs, but they do
    // not fix the order: in 1 of 74 CI iterations (run 41182384539, job
    // 124482285010) B's answer from r arrived first and armed, and C's
    // answer from r+1 became the conflict. That run met every other
    // check. §2 records the second diverging ATA as the conflict whichever
    // admin signed it, so the check accepts either order.
    let signed = |ata: &Option<Ata>, by: &str, hash: &str| {
        ata.as_ref()
            .is_some_and(|(signer, _, sequence)| signer == by && sequence.iter().any(|h| h == hash))
    };
    let c_active = signed(&atas.0, "C", &main.state_hash) && signed(&atas.1, "B", &fork.state_hash);
    let b_active = signed(&atas.0, "B", &fork.state_hash) && signed(&atas.1, "C", &main.state_hash);
    let recorded = c_active || b_active;
    let short_ata = |ata: &Option<Ata>| {
        ata.as_ref().map(|(by, from, sequence)| {
            let hashes: Vec<&str> = sequence.iter().map(|h| short(h)).collect();
            format!("{by} from {from} {hashes:?}")
        })
    };
    receipt.note(format!(
        "J's sidecar at the conflict: active {:?}, conflict {:?}; r+3 {} r+3' {}; active \
         signer {}",
        short_ata(&atas.0),
        short_ata(&atas.1),
        short(&main.state_hash),
        short(&fork.state_hash),
        if b_active {
            "B"
        } else if c_active {
            "C"
        } else {
            "neither"
        }
    ));
    receipt.note(format!(
        "J at the conflict {}; J at the end {}; J states {:?}; J max revision {}; J held r+3 \
         or r+3' {:?}; left the conflict {:?}; B requesters {}; C requesters {}; {}",
        j_at_conflict.describe(),
        j_end.describe(),
        seen.states,
        seen.max_revision,
        seen.held_r3,
        seen.left_conflict,
        b_route["requesters"],
        c_route["requesters"],
        hold.counts()
    ));
    let passed = by_b && by_c && recorded && within_prefix && conflict;
    if !passed {
        receipt.cause(
            CAUSE,
            Some(format!(
                "attested by B {by_b}, by C {by_c}; conflict recorded {recorded}; within \
                 the prefix {within_prefix}; conflict shown {conflict}"
            )),
            by_b && by_c && (!recorded || !within_prefix || !conflict),
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "ADR 0109 S3 (#1356, #1572) H-S3-x: attestation conflict, in the Engineer's (a) \
         shape: B forks after it applies J's seal; C's catch-up is held until B's late reply"
            .to_string(),
    );
    // H-S3-x ranks B and C before each start.
    match Sim::empty(case, seed, LABELS) {
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

/// H-S3-x (§2 "Conflict"): control, GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_x_attestation_conflict_stops_at_common_prefix() -> Result<()> {
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_x_attestation_conflict_stops_at_common_prefix";
        let receipt = run(case, 0x1356_0107).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
