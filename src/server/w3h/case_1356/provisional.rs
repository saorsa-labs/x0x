//! ADR 0109 §10 row H-S3-d6 (provisional ATA, bogus hashes; #1572).
//! Control, expected GREEN with S3 (on `main` before S3, J stays marked,
//! as in H-S3-b).
//!
//! Setup S0 (skewed clocks) with A on the previous release
//! (`gaps::pre_s3`), M1 and M2 on the candidate, and member M3. A promotes
//! M1 (r+1), removes M3 (r+2), and J joins with invite I; A seals J (r+3).
//! Every direct message from M1 or M2 to J is dropped from J's join on.
//! The case advances 130 s. It then injects to J, as M2's reply, an ATA
//! that M2 signs, `from` J's head, with two bogus sequence hashes. Then it
//! releases M1's replies.
//!
//! Desired: after the injection, J shows `awaiting_attestation
//! {provisional_unverified}` and has armed nothing (no active ATA in its
//! sidecar, its head and marker unchanged). After the release, J asks M1
//! again; M1's ATA arms, J applies the gap, replays its add, retires its
//! marker and holds keys. J never shows `reseat_required`.
//!
//! **The gap step (deviation from the row).** The row's gap is the
//! promotion alone (r+1, then the seal at r+2). On this build a single
//! promotion gap converges with no marker (H-S3-b, `gaps.rs`), so J would
//! never need M1's ATA. H-S3-b adds A's removal of M2 for that reason.
//! Here M2 signs the bogus ATA and must stay seated, so A removes an added
//! member M3 instead. M1 stays the only capable admin.
//!
//! **J's head (observed, VM run of 4 Nov 2026).** J applies A's promotion
//! from the served chain and is marked at r+1, on A's add at r+3. So M1 is
//! an admin on J's head and its ATA arms as verified; J then applies the
//! removal (r+2) and replays its add (r+3). The row's "J applies r+1" is
//! already done before the injection. M2 is still a member on J's head,
//! so M2's ATA stays provisional, which is what the row tests.
//!
//! **Hold.** The fabric cannot tell a recovery DM from other DMs, so the
//! hold drops every direct message from M1 or M2 to J, and every write on
//! J's DM inbox topic that M1 or M2 originated. J's own messages pass.
//! During the injection only M1's messages are held, so M2's send passes.
//!
//! **Injection.** The ATA is built and signed with M2's agent key by the
//! production code (`AdminTerminalAttestation::sign`), wrapped in a
//! `GroupAttestResponseV1` for J's head with the production encoder, and
//! sent by M2's own agent (`Agent::send_direct`), so the DM layer signs it
//! with M2's key. The two hashes come from the seed, so a rerun is the same
//! run; they match no link of J's kept served chain. J accepts an
//! unsolicited `attested` answer (`handle_response`): the signed ATA
//! carries its own authority. M2 is a member on J's base roster, so the
//! ATA is provisional, and only J's kept chain can verify it.

use super::gaps::{answered, promote, recovery_route, recovery_text, remove, s0, seal_j};
use super::*;
use crate::groups::recovery::{
    decode_message, decode_sidecar, encode_message, AdminTerminalAttestation, AtaFields,
    AttestAnswer, GroupAttestResponseV1, GroupRecoveryMessageV1, GROUP_RECOVERY_DIR,
};
use crate::network::sim::{Fault, LaneClass};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const LABELS: &[&str] = &["A", "M1", "M2", "M3", "J"];
const FINAL: &str = "j_arms_nothing_on_m2_bogus_ata_then_catches_up_through_m1";
const CAUSE: &str = "J stays marked with no recovery object: no admin answers";
/// The 130 s advance after the seal.
const ADVANCE: Duration = Duration::from_secs(130);
/// The longest wait for J to show its state after the injection.
const INJECTED_WAIT: Duration = Duration::from_secs(10);
/// After the release: J's next request round, after the backoff that the
/// held rounds built up, and M1's catch-up, with margin.
const RELEASE_WINDOW: Duration = Duration::from_secs(600);

/// What the hold drops: nothing, M1 only, or M1 and M2.
const OPEN: u8 = 0;
const M1_ONLY: u8 = 1;
const BOTH: u8 = 2;

/// The fabric rule of this row. A gossip frame's origin is the node that
/// first wrote its message ID, so a relay keeps its origin.
struct Hold {
    phase: Arc<AtomicU8>,
    dropped: Arc<AtomicUsize>,
}

impl Hold {
    fn install(sim: &Sim) -> Result<Self> {
        let (m1, m2, j) = (sim.peer("M1")?.0, sim.peer("M2")?.0, sim.peer("J")?.0);
        let j_inbox = crate::dm::dm_inbox_topic(&sim.ids("J")?.0).to_bytes();
        let phase = Arc::new(AtomicU8::new(OPEN));
        let dropped = Arc::new(AtomicUsize::new(0));
        let origins: std::sync::Mutex<HashMap<[u8; 32], _>> = std::sync::Mutex::new(HashMap::new());
        let (rule_phase, rule_dropped) = (Arc::clone(&phase), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            let current = rule_phase.load(Ordering::SeqCst);
            if current == OPEN {
                return Fault::Pass;
            }
            let held = |node| node == m1 || (current == BOTH && node == m2);
            let (src, dst) = (write.lane.src, write.lane.dst);
            let drop = match write.lane.class {
                LaneClass::Direct | LaneClass::RelayedDm => dst == j && held(src),
                LaneClass::PubSub => match pubsub_header(&write.bytes) {
                    Some((topic, id)) if topic == j_inbox => {
                        let origin = match origins.lock() {
                            Ok(mut map) => *map.entry(id).or_insert(src),
                            Err(_) => return Fault::Drop,
                        };
                        held(origin)
                    }
                    _ => false,
                },
                _ => false,
            };
            if drop {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { phase, dropped })
    }

    fn set(&self, sim: &Sim, phase: u8) {
        self.phase.store(phase, Ordering::SeqCst);
        sim.fabric().mark(format!(
            "fault: H-S3-d6 hold now {phase} (0 open, 1 M1, 2 M1+M2)"
        ));
    }
}

/// The signer of the active ATA in `label`'s S3 sidecars, if any.
fn active_ata(sim: &Sim, label: &str) -> Result<Option<String>> {
    let dir = sim.state(label)?.data_dir.join(GROUP_RECOVERY_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(None);
    };
    for entry in entries {
        let path = entry?.path();
        let Ok(body) = decode_sidecar(&std::fs::read(&path)?) else {
            continue;
        };
        if let Some(ata) = body.active_ata {
            return Ok(Some(ata.fields.attested_by));
        }
    }
    Ok(None)
}

/// The stable group ID that `label` holds for `group`.
async fn stable_id(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("{label} has no record of {group}"))?;
    Ok(info.stable_group_id().to_string())
}

/// M2's bogus ATA for J's head `j`, signed with M2's key, as the encoded
/// S3 direct message of M2's reply.
async fn bogus_reply(sim: &Sim, group: &str, j: &View, seed: u64) -> Result<Vec<u8>> {
    let stable = stable_id(sim, "J", group).await?;
    let m2 = sim.state("M2")?.agent.clone();
    let keypair = m2.identity().agent_keypair();
    let sequence = (0..2)
        .map(|index| {
            blake3::hash(format!("w3h d6 {seed} bogus link {index}").as_bytes())
                .to_hex()
                .to_string()
        })
        .collect();
    let fields = AtaFields {
        group: stable.clone(),
        subject: sim.agent_hex("J")?,
        attested_by: hex::encode(keypair.agent_id().as_bytes()),
        signer_public_key: hex::encode(keypair.public_key().as_bytes()),
        from_revision: j.state_revision,
        from_state_hash: j.state_hash.clone(),
        sequence,
        segment_terminal_revision: j.state_revision + 2,
        segment_terminal_epoch: None,
        issued_at_ms: crate::server::routes::named_groups::now_millis_u64(),
    };
    let ata = AdminTerminalAttestation::sign(fields, keypair)
        .map_err(|refusal| anyhow!("M2 signs the bogus ATA: {refusal:?}"))?;
    Ok(encode_message(&GroupRecoveryMessageV1::Response(
        GroupAttestResponseV1 {
            group: stable,
            subject: sim.ids("J")?.0 .0,
            for_head_state_hash: j.state_hash.clone(),
            answer: AttestAnswer::Attested(Box::new(ata)),
        },
    ))?)
}

/// J's recovery states, each change once, from its `GET /groups/:id`.
#[derive(Default)]
struct States(Vec<String>);

impl States {
    async fn sample(&mut self, sim: &Sim, group: &str) -> Result<String> {
        let text = status_now(sim, "J", group)
            .await?
            .map_or_else(|| "404".to_string(), |st| recovery_text(&st.recovery));
        if self.0.last() != Some(&text) {
            self.0.push(text.clone());
        }
        Ok(text)
    }

    fn reseat_required(&self) -> bool {
        self.0.iter().any(|s| s.starts_with("reseat_required"))
    }
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt, seed: u64) -> Result<()> {
    let (group, _) = s0(sim, LABELS, true, &["A"]).await?;
    seat(sim, "A", "M3", &group).await?;
    settled(
        sim,
        &["M1", "M2", "M3"],
        &group,
        "M1, M2 and M3 hold A's revision",
    )
    .await?;
    let minted = view(sim, "A", &group).await?;
    let link = invite(sim, "A", &group).await?;
    promote(sim, "A", "M1", &group, &["A", "M1", "M2"]).await?;
    remove(sim, "A", "M3", &group).await?;
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold the removal").await?;
    sim.within("the gap resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let hold = Hold::install(sim)?;
    hold.set(sim, BOTH);
    let mut rx = sim.state("J")?.agent.subscribe_direct();
    let joined_at = sim.fabric().mark_indexed("case: J redeems invite I");
    let sealed = seal_j(sim, &link, &group).await?;
    let stub = view(sim, "J", &group).await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "gap_is_the_promotion_of_m1_the_removal_of_m3_and_the_seal",
        sealed.state_revision == minted.state_revision + 3
            && stub.base_revision == Some(minted.state_revision),
        format!(
            "minted at {}; A {}; J {}",
            minted.state_revision,
            sealed.describe(),
            stub.describe()
        ),
        at(sim),
    );

    let mut states = States::default();
    let mut seen = Observations::default();
    let advanced = sim
        .until("advance 130 s", ADVANCE, async |s: &Sim| {
            seen.observe(states.sample(s, &group)).await.is_none()
        })
        .await;
    if let Err(error) = advanced {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("advance 130 s")?;
    let before = view(sim, "J", &group).await?;
    let before_state = states.0.last().cloned().unwrap_or_default();

    // The injection: only M1's messages stay held while M2 sends.
    let payload = bogus_reply(sim, &group, &before, seed).await?;
    let (j_id, _) = sim.ids("J")?;
    let m2 = sim.state("M2")?.agent.clone();
    let injected_at = sim.fabric().mark_indexed("case: M2's bogus ATA to J");
    hold.set(sim, M1_ONLY);
    let sent = sim
        .within("M2 sends the bogus ATA", secs(10), async {
            m2.send_direct(&j_id, payload).await
        })
        .await?;
    // The fabric decides each write's fault at send time, and
    // `send_direct` returns after J's ack, so M2's frames have passed.
    hold.set(sim, BOTH);
    sent.map_err(|error| anyhow!("M2's bogus ATA: {error}"))?;
    let shown = sim
        .until(
            "J shows the provisional ATA",
            INJECTED_WAIT,
            async |s: &Sim| {
                states
                    .sample(s, &group)
                    .await
                    .is_ok_and(|text| text == "awaiting_attestation{provisional_unverified}")
            },
        )
        .await;
    if let Err(error) = shown {
        if !expired(&error) {
            return Err(error);
        }
    }
    let after = view(sim, "J", &group).await?;
    let armed = active_ata(sim, "J")?;
    let after_state = status(sim, "J", &group)
        .await?
        .map_or_else(|| "404".to_string(), |st| recovery_text(&st.recovery));
    let injected = delivered_after(sim, "M2", "J", injected_at)?;
    receipt.request_delivered(
        "m2_bogus_ata_reached_j",
        injected > 0,
        format!("frames M2->J since the injection: {injected}"),
        at(sim),
    );
    let unverified = after_state == "awaiting_attestation{provisional_unverified}"
        && before_state != after_state;
    let nothing_armed = armed.is_none()
        && after.state_revision == before.state_revision
        && after.state_hash == before.state_hash
        && after.marker.is_some() == before.marker.is_some();
    receipt.evidence(
        "after_injection_provisional_unverified_and_armed_nothing",
        unverified && nothing_armed,
        format!(
            "J before {before_state} {}; after {after_state} {}; active ATA {armed:?}",
            before.describe(),
            after.describe()
        ),
        at(sim),
    );

    // The release: J's next round asks M1 again, and M1's answer passes.
    hold.set(sim, OPEN);
    let a = view(sim, "A", &group).await?;
    let mut seen = Observations::default();
    let released = sim
        .until(
            "J catches up through M1",
            RELEASE_WINDOW,
            async |s: &Sim| {
                if seen.observe(states.sample(s, &group)).await.is_none() {
                    return true;
                }
                let Some(j) = seen.observe(try_view_now(s, "J", &group)).await else {
                    return true;
                };
                let Some(st) = seen.observe(status_now(s, "J", &group)).await else {
                    return true;
                };
                let membership = st.as_ref().and_then(|st| st.membership.as_deref());
                caught_up(j.as_ref(), &a, membership)
            },
        )
        .await;
    if let Err(error) = released {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("J catches up through M1")?;
    let j = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let j_status = status(sim, "J", &group).await?;
    let membership = j_status.as_ref().and_then(|st| st.membership.clone());
    let caught = caught_up(j.as_ref(), &a, membership.as_deref());

    // M1's and M2's answers at J, by sender.
    let (m1_id, m2_id) = (sim.ids("M1")?.0, sim.ids("M2")?.0);
    let mut answers = Vec::new();
    while let Some(msg) = rx.try_recv() {
        let from = if msg.sender == m1_id {
            "M1"
        } else if msg.sender == m2_id {
            "M2"
        } else {
            continue;
        };
        if let Ok(GroupRecoveryMessageV1::Response(response)) = decode_message(&msg.payload) {
            answers.push(format!("{from} {}", response.answer.name()));
        }
    }
    let m1_route = sim
        .at_instant("read M1's recovery", recovery_route(sim, "M1", &group))
        .await??;
    let by_m1 = answered(&m1_route, &sim.agent_hex("J")?, "attested")
        || answers.iter().any(|a| a == "M1 attested");
    let to_m1 = delivered_after(sim, "J", "M1", joined_at)?;
    receipt.request_delivered(
        "j_reached_m1",
        to_m1 > 0,
        format!("frames J->M1 since the join: {to_m1}"),
        at(sim),
    );
    receipt.note(format!(
        "J recovery states {:?}; answers at J {answers:?}; hold dropped {}; M1 requesters {}; \
         J at the end {}",
        states.0,
        hold.dropped.load(Ordering::SeqCst),
        m1_route["requesters"],
        j.as_ref()
            .map_or_else(|| "has no record".to_string(), View::describe)
    ));
    let passed = unverified && nothing_armed && caught && by_m1 && !states.reseat_required();
    if !passed {
        let marked = after.marker.is_some() || j.as_ref().is_some_and(|j| j.marker.is_some());
        let no_recovery = states.0.iter().all(|s| s == "null");
        receipt.cause(
            CAUSE,
            Some(format!("J states {:?}", states.0)),
            marked && no_recovery,
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("ADR 0109 S3 (#1356, #1572) H-S3-d6: provisional ATA, bogus hashes".to_string());
    match Sim::start(case, seed, LABELS).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, seed).await {
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

/// H-S3-d6: control, GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_d6_provisional_ata_bogus_hashes() -> Result<()> {
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_d6_provisional_ata_bogus_hashes";
        let receipt = run(case, 0x1356_0112).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
