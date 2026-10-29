//! ADR 0109 §10 row H-S3-d7 (request flood, D83; #1572). Control,
//! expected GREEN with S3 (on `main` before S3, A drops the unknown DMs).
//!
//! Setup S0′ with every node on the candidate, plus node E, which is never
//! seated. Within one request interval M1 sends A 50 `group_attest_request`s,
//! each with a different head hash, then E sends 50. The case then advances
//! 1 min. Desired (§1 step 2, §11): A answers M1's first request with a
//! typed refusal that is not `rate_limited`, and each later one with
//! `refused {rate_limited}`. E's first request gets `not_a_member` and the
//! rest get `rate_limited`. A signs no ATA, and `GET /groups/:id/recovery`
//! on A lists at most one entry each for M1 and E.
//!
//! **Injection.** Each request is built with the production encoder
//! (`recovery::encode_message`) and sent by the requester's own agent
//! (`Agent::send_direct`), so the DM layer signs it with the requester's
//! key. The case sends the next request only after the requester has A's
//! answer to the last one, so A never holds more than one build and the
//! §11 concurrent-build cap does not drop a request. Each request names
//! A's revision plus one with a hash from the seed, so a request that A
//! admits in full gets the typed refusal `attester_behind` (M1) or
//! `not_a_member` (E).
//!
//! **Answers.** The case reads A's answers at M1 and E from their direct
//! message streams (`Agent::subscribe_direct`) and decodes each with
//! `recovery::decode_message`. M1's daemon ignores them (no request of its
//! own is pending for the hash), and E has no group record.
//!
//! **`admin_attest_issued`.** ADR 0109 §9 names this counter, but this
//! build does not have it. The case checks the same fact from the outside:
//! no answer at M1 or E is `attested`, and no entry on A's recovery list
//! is `attested`.

use super::gaps::{recovery_route, s0, sees_s3};
use super::*;
use crate::groups::recovery::{
    decode_message, encode_message, AttestAnswer, GroupAttestRequestV1, GroupRecoveryMessageV1,
};

const LABELS: &[&str] = &["A", "M1", "M2", "E"];
const FINAL: &str = "a_answers_each_requester_once_then_rate_limited_and_signs_nothing";
const CAUSE: &str = "A answers a repeated request within the interval in full, not with \
                     refused {rate_limited}";
/// Requests from each requester (ADR 0109 H-S3-d7).
const FLOOD: usize = 50;
/// One request interval (§11 `RESPONDER_PER_REQUESTER_INTERVAL`).
const INTERVAL: Duration = Duration::from_secs(60);
/// The longest wait for A's answer to one request.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// A's answers that `requester` received: `(head hash, answer name)`.
struct Answers {
    requester: &'static str,
    rx: crate::direct::DirectMessageReceiver,
    seen: Vec<(String, String)>,
}

impl Answers {
    fn drain(&mut self, a: &crate::identity::AgentId) {
        while let Some(msg) = self.rx.try_recv() {
            if &msg.sender != a {
                continue;
            }
            if let Ok(GroupRecoveryMessageV1::Response(response)) = decode_message(&msg.payload) {
                let name = match &response.answer {
                    AttestAnswer::Refused(reason) => format!("refused {}", reason.as_str()),
                    other => other.name().to_string(),
                };
                self.seen.push((response.for_head_state_hash, name));
            }
        }
    }

    /// The answer to the request that named `head`.
    fn to(&self, head: &str) -> Option<&str> {
        self.seen
            .iter()
            .find(|(hash, _)| hash == head)
            .map(|(_, name)| name.as_str())
    }
}

/// `requester` sends A `FLOOD` requests, one at a time; returns the answer
/// to each, in order (`"none"` when no answer came within [`ANSWER_WAIT`]).
async fn flood(
    sim: &Sim,
    group: &str,
    head_revision: u64,
    answers: &mut Answers,
) -> Result<Vec<String>> {
    let (a, _) = sim.ids("A")?;
    let (requester, _) = sim.ids(answers.requester)?;
    let agent = sim.state(answers.requester)?.agent.clone();
    let mut out = Vec::new();
    for index in 0..FLOOD {
        let head = blake3::hash(format!("w3h d7 {} {index}", answers.requester).as_bytes())
            .to_hex()
            .to_string();
        let payload = encode_message(&GroupRecoveryMessageV1::Request(GroupAttestRequestV1 {
            group: group.to_string(),
            requester: requester.0,
            head_revision,
            head_state_hash: head.clone(),
            refs: Vec::new(),
        }))?;
        agent
            .send_direct(&a, payload)
            .await
            .map_err(|error| anyhow!("{} request {index}: {error}", answers.requester))?;
        let started = tokio::time::Instant::now();
        loop {
            answers.drain(&a);
            if answers.to(&head).is_some() || started.elapsed() >= ANSWER_WAIT {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        out.push(answers.to(&head).unwrap_or("none").to_string());
    }
    Ok(out)
}

/// The first answer is a typed refusal other than `rate_limited` and is
/// `first` when given; every later one is `refused {rate_limited}`.
fn limited(answers: &[String], first: Option<&str>) -> bool {
    let Some((head, rest)) = answers.split_first() else {
        return false;
    };
    head.starts_with("refused ")
        && head != "refused rate_limited"
        && first.is_none_or(|want| head == want)
        && rest.iter().all(|answer| answer == "refused rate_limited")
}

/// How many times each answer occurs.
fn count(answers: &[String]) -> BTreeMap<&str, usize> {
    let mut tally = BTreeMap::new();
    for answer in answers {
        *tally.entry(answer.as_str()).or_default() += 1;
    }
    tally
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let (group, minted) = s0(sim, LABELS, false, &[]).await?;
    invite(sim, "A", &group).await?;
    for label in ["M1", "E"] {
        sees_s3(sim, "A", label).await?;
    }
    let a_view = view(sim, "A", &group).await?;
    let (m1_hex, e_hex) = (sim.agent_hex("M1")?, sim.agent_hex("E")?);
    receipt.setup_done(at(sim));
    receipt.evidence(
        "m1_seated_and_e_never_seated",
        a_view.lists(&m1_hex) && !a_view.lists(&e_hex) && a_view.marker.is_none(),
        format!(
            "A {}; minted at {}",
            a_view.describe(),
            minted.state_revision
        ),
        at(sim),
    );
    let mut m1 = Answers {
        requester: "M1",
        rx: sim.state("M1")?.agent.subscribe_direct(),
        seen: Vec::new(),
    };
    let mut e = Answers {
        requester: "E",
        rx: sim.state("E")?.agent.subscribe_direct(),
        seen: Vec::new(),
    };
    let since = sim.fabric().mark_indexed("case: M1, then E, floods A");
    let head_revision = a_view.state_revision + 1;
    let started = sim.fabric().now();
    let (from_m1, from_e) = sim
        .within("M1 and E flood A", INTERVAL * 2, async {
            let from_m1 = flood(sim, &group, head_revision, &mut m1).await?;
            let from_e = flood(sim, &group, head_revision, &mut e).await?;
            anyhow::Ok((from_m1, from_e))
        })
        .await??;
    let flood_took = sim.fabric().now().saturating_sub(started);
    receipt.evidence(
        "flood_within_one_request_interval",
        flood_took < INTERVAL,
        format!("{} ms of virtual time", flood_took.as_millis()),
        at(sim),
    );
    let to_a = delivered_after(sim, "M1", "A", since)? + delivered_after(sim, "E", "A", since)?;
    let back = delivered_after(sim, "A", "M1", since)? + delivered_after(sim, "A", "E", since)?;
    receipt.request_delivered(
        "m1_and_e_reached_a",
        to_a > 0 && back > 0,
        format!("frames M1,E->A {to_a}; A->M1,E {back}"),
        at(sim),
    );
    let _ = sim
        .until("advance 1 min", INTERVAL, async |_s: &Sim| false)
        .await;
    m1.drain(&sim.ids("A")?.0);
    e.drain(&sim.ids("A")?.0);
    let route = sim
        .at_instant("read A's recovery", recovery_route(sim, "A", &group))
        .await??;
    let entries = |hex: &str| {
        route["requesters"].as_array().map_or(0, |rows| {
            rows.iter()
                .filter(|row| {
                    row["requester"]
                        .as_str()
                        .is_some_and(|id| id.eq_ignore_ascii_case(hex))
                })
                .count()
        })
    };
    let (m1_entries, e_entries) = (entries(&m1_hex), entries(&e_hex));
    let listed_attested = route["requesters"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| row["answer"] == "attested"));
    let any_attested = m1
        .seen
        .iter()
        .chain(e.seen.iter())
        .any(|(_, answer)| answer == "attested");
    let m1_ok = limited(&from_m1, None);
    let e_ok = limited(&from_e, Some("refused not_a_member"));
    receipt.note(format!(
        "M1 first {:?}, all {:?}; E first {:?}, all {:?}; answers after the advance: M1 {}, \
         E {}; A lists M1 {m1_entries}, E {e_entries}; attested at M1/E {any_attested}, on \
         A's list {listed_attested}; A requesters {}",
        from_m1.first(),
        count(&from_m1),
        from_e.first(),
        count(&from_e),
        m1.seen.len(),
        e.seen.len(),
        route["requesters"]
    ));
    let passed = m1_ok
        && e_ok
        && m1.seen.len() == FLOOD
        && e.seen.len() == FLOOD
        && !any_attested
        && !listed_attested
        && m1_entries <= 1
        && e_entries <= 1;
    if !passed {
        // The rate limit is missing when a repeated request is answered in
        // full: the same typed answer as the first.
        let repeated = |answers: &[String]| {
            answers.len() > 1 && answers.iter().skip(1).any(|answer| answer == &answers[0])
        };
        receipt.cause(
            CAUSE,
            Some(format!("M1 {:?}; E {:?}", count(&from_m1), count(&from_e))),
            repeated(&from_m1) || repeated(&from_e),
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("ADR 0109 S3 (#1356, #1572) H-S3-d7: request flood".to_string());
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

/// H-S3-d7 (D83): control, GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_d7_request_flood_rate_limited() -> Result<()> {
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_d7_request_flood_rate_limited";
        let receipt = run(case, 0x1356_0106).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
