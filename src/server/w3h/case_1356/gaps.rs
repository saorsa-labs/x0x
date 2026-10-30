//! The ADR 0109 §10 W3-H rows that `case_1356` did not cover (#1572):
//! H-S3-b, H-S3-t (1) to (4) and H-S3-d5 run as gate cases. Each red arm
//! keeps its `_red_` name, is shown RED on `main` in the DIAG PR, and
//! expects GREEN here. A red arm that fails with the observation its
//! `CAUSE_*` names (the base's behaviour) is RED; any other failure is
//! INFRA.
//!
//! Rows that cannot run on this build (evidence in #1533 and #1572):
//! - H-S3-c and H-S3-c2 need admins A and X with owner certificates on
//!   installs without the owner's USER key. `Agent::build` loads an agent
//!   certificate only beside a user keypair, and an identity announce
//!   needs the user key, so such an install has no certificate and cannot
//!   join an OwnerCertified group (`no agent certificate resolved`).
//! - H-S3-t (5) holds the staged Welcome. Its fetch is an encrypted direct
//!   message the fabric cannot tell apart, and here it runs before the
//!   attested catch-up, so holding it holds the whole join.
//! - H-S3-r: with A's log capped, A serves no chain and no join carry, so
//!   J holds no marker or gap record and §2 sends no request. It is kept
//!   as the probe `probe_w3h_1356_s3_r_beyond_retention`, not a gate case.
//!
//! **"On the previous release".** The harness runs one in-process build,
//! so it cannot run a released binary. A node that the ADR puts "on the
//! previous release" runs this build with S3 switched off for that node
//! ([`pre_s3`]): its advert lacks bits 8 and 9, it drops every `X0XGRC1`
//! frame (as a released node drops the unknown DM), it carries no join
//! ATA and it sends no request. This models S3's absence, which is what
//! these rows test. It does not model any other difference between
//! releases. On `main` (the DIAG branch) every node is pre-S3 already, and
//! [`pre_s3`] there only marks the trace.
//!
//! Setups are ADR 0109's S0 (four policy changes before the mint skew the
//! clocks, as `case_818`) and S0′ (none). A (creator, admin), M1 and M2
//! (members) are seated before the mint; J redeems invite I, minted at r.

use super::*;

/// One request interval (§11: the first retry after 60 s, plus margin).
const REQUEST_INTERVAL: Duration = Duration::from_secs(70);

/// ADR 0109 "on the previous release" for each of `labels`, from now on
/// (see the module notes). Returns once `observer` holds, for each, a
/// current verified advert that lacks bit 8; it asks for a fresh advert
/// each round, as S3 itself does for unknown support. All nodes switch
/// before the wait, so no observer caches a capable advert from a node
/// that switches later.
async fn pre_s3(sim: &Sim, labels: &[&str], observer: &str) -> Result<()> {
    use crate::dm::CapabilityRegistry;
    let bit = CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1;
    let mut agents = Vec::new();
    for label in labels {
        let state = sim.state(label)?;
        state.group_recovery.model_pre_s3();
        let mut registry = state.agent.current_dm_capabilities().application_registry;
        registry.bits &= !(bit | CapabilityRegistry::GROUP_RESEAT_MANDATE_V1);
        state.agent.set_application_registry_for_test(registry);
        sim.fabric()
            .mark(format!("case: {label} runs as a release without S3"));
        agents.push(sim.ids(label)?.0);
    }
    sim.until(
        &format!("{observer} sees {labels:?} without bit 8"),
        SETUP,
        async |s: &Sim| {
            let Ok(st) = s.state(observer) else {
                return false;
            };
            let mut all = true;
            for agent in &agents {
                if st
                    .agent
                    .capability_store()
                    .verified_registry_supports(agent, bit)
                    != Some(false)
                {
                    all = false;
                    st.agent.refresh_application_capability(*agent, bit).await;
                }
            }
            all
        },
    )
    .await
}

/// Returns once `observer` holds a current verified advert from `label`
/// that sets bit 8 (a node restarted on the candidate); it asks for a
/// fresh advert each round, as S3 itself does for unknown support.
pub(super) async fn sees_s3(sim: &Sim, observer: &str, label: &str) -> Result<()> {
    let bit = crate::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1;
    let agent = sim.ids(label)?.0;
    sim.until(
        &format!("{observer} sees {label} with bit 8"),
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
            st.agent.refresh_application_capability(agent, bit).await;
            false
        },
    )
    .await
}

/// S0 (`skew`) or S0′ up to the mint: A creates the group and seats M1 and
/// M2; with `skew`, A makes the four policy changes. `pre` names the
/// nodes that run as the previous release from the start. Returns the
/// group and A's view at the mint.
pub(super) async fn s0(
    sim: &Sim,
    labels: &[&str],
    skew: bool,
    pre: &[&str],
) -> Result<(String, View)> {
    mesh(sim, labels).await?;
    if !pre.is_empty() {
        pre_s3(sim, pre, "J").await?;
    }
    let group = create_group(sim, "A").await?;
    for member in ["M1", "M2"] {
        seat(sim, "A", member, &group).await?;
    }
    if skew {
        for write_access in POLICY_CHANGES {
            let (code, body) = sim
                .api(
                    "A",
                    Method::PATCH,
                    &format!("/groups/{group}/policy"),
                    Some(json!({"write_access": write_access})),
                )
                .await?;
            ensure!(code.is_success(), "policy {write_access}: {code} {body}");
        }
    }
    settled(sim, &["M1", "M2"], &group, "M1 and M2 hold A's revision").await?;
    let minted = view(sim, "A", &group).await?;
    Ok((group, minted))
}

pub(super) async fn promote(
    sim: &Sim,
    admin: &str,
    member: &str,
    group: &str,
    observers: &[&str],
) -> Result<()> {
    let hex = sim.agent_hex(member)?;
    let (code, promoted) = sim
        .api(
            admin,
            Method::PATCH,
            &format!("/groups/{group}/members/{hex}/role"),
            Some(json!({"role": "admin"})),
        )
        .await?;
    ensure!(
        code.is_success(),
        "{admin} promotes {member}: {code} {promoted}"
    );
    sim.until(
        &format!("every node sees {member} as admin"),
        SETUP,
        async |s: &Sim| {
            for label in observers {
                let admin = roster(s, label, group).await.is_ok_and(|rows| {
                    rows.iter()
                        .any(|(id, role)| id.eq_ignore_ascii_case(&hex) && role == "admin")
                });
                if !admin {
                    return false;
                }
            }
            true
        },
    )
    .await
}

/// `admin` removes `member`; returns once `admin` no longer lists it.
pub(super) async fn remove(sim: &Sim, admin: &str, member: &str, group: &str) -> Result<()> {
    let hex = sim.agent_hex(member)?;
    let (code, removed) = sim
        .api(
            admin,
            Method::DELETE,
            &format!("/groups/{group}/members/{hex}"),
            None,
        )
        .await?;
    ensure!(
        code.is_success(),
        "{admin} removes {member}: {code} {removed}"
    );
    sim.until(
        &format!("{admin} no longer lists {member}"),
        SETUP,
        async |s: &Sim| {
            view_now(s, admin, group)
                .await
                .is_ok_and(|v| !v.lists(&hex))
        },
    )
    .await
}

/// J redeems `link`; returns once A lists J, with A's view after the seal.
pub(super) async fn seal_j(sim: &Sim, link: &str, group: &str) -> Result<View> {
    join(sim, "J", link).await?;
    let j_hex = sim.agent_hex("J")?;
    sim.until("A seals J", SETUP, async |s: &Sim| {
        view_now(s, "A", group).await.is_ok_and(|a| a.lists(&j_hex))
    })
    .await?;
    view(sim, "A", group).await
}

/// The S3 sidecar files in `label`'s data directory (S3 engaged there).
fn sidecars(sim: &Sim, label: &str) -> Vec<String> {
    let Ok(dir) = sim.data_dir(label) else {
        return Vec::new();
    };
    std::fs::read_dir(dir.join(crate::groups::recovery::GROUP_RECOVERY_DIR))
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// `GET /groups/:id/recovery` on `label` (`Null` when absent, as on the
/// base).
pub(super) async fn recovery_route(sim: &Sim, label: &str, group: &str) -> Result<Value> {
    let (code, body) = sim
        .request(
            label,
            Method::GET,
            &format!("/groups/{group}/recovery"),
            None,
        )
        .await?;
    Ok(if code.is_success() { body } else { Value::Null })
}

/// Whether `admin`'s requester list shows `requester` answered with
/// `answer` (a JSON string or an object keyed by it).
pub(super) fn answered(route: &Value, requester: &str, answer: &str) -> bool {
    route["requesters"].as_array().is_some_and(|rows| {
        rows.iter().any(|row| {
            row["requester"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(requester))
                && (row["answer"].as_str() == Some(answer)
                    || row["answer"].get(answer).is_some()
                    || row["answer"]["kind"].as_str() == Some(answer)
                    || row["answer"]["reason"].as_str() == Some(answer))
        })
    })
}

/// What the window saw of J.
#[derive(Default)]
struct JWindow {
    marked: Option<String>,
    recovery_states: Vec<String>,
    caught_up_at: Option<String>,
}

impl JWindow {
    fn saw_state(&mut self, recovery: &Value) {
        let text = recovery_text(recovery);
        if self.recovery_states.last() != Some(&text) {
            self.recovery_states.push(text);
        }
    }
}

/// `{state}` plus its `reason` or `cause`, as one short string.
pub(super) fn recovery_text(recovery: &Value) -> String {
    if recovery.is_null() {
        return "null".to_string();
    }
    let state = recovery["state"].as_str().unwrap_or("?");
    match recovery["reason"].as_str().or(recovery["cause"].as_str()) {
        Some(detail) => format!("{state}{{{detail}}}"),
        None => state.to_string(),
    }
}

/// Watch J against `authority` for `budget`; stop early once J is caught
/// up when `stop_when_caught_up`.
async fn watch_j(
    sim: &Sim,
    group: &str,
    authority: &str,
    what: &str,
    budget: Duration,
    stop_when_caught_up: bool,
    window: &mut JWindow,
) -> Result<()> {
    let mut seen = Observations::default();
    let waited = sim
        .until(what, budget, async |s: &Sim| {
            let Some(a) = seen.observe(view_now(s, authority, group)).await else {
                return true;
            };
            let Some(j) = seen.observe(try_view_now(s, "J", group)).await else {
                return true;
            };
            let Some(j_status) = seen.observe(status_now(s, "J", group)).await else {
                return true;
            };
            let now = s.fabric().now().as_micros();
            if let Some(j) = j.as_ref().filter(|j| j.marker.is_some()) {
                window
                    .marked
                    .get_or_insert_with(|| format!("at {now} us: J {}", j.describe()));
            }
            if let Some(st) = j_status.as_ref() {
                window.saw_state(&st.recovery);
            }
            let membership = j_status.as_ref().and_then(|st| st.membership.as_deref());
            let done = caught_up(j.as_ref(), &a, membership);
            if done {
                window
                    .caught_up_at
                    .get_or_insert_with(|| format!("at {now} us"));
            }
            stop_when_caught_up && done
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify(what)
}

/// J's end state against `authority`, as receipt text.
async fn j_end(
    sim: &Sim,
    group: &str,
    authority: &str,
) -> Result<(bool, String, Option<View>, Option<Status>)> {
    let a = view(sim, authority, group).await?;
    let j = sim
        .at_instant("read J's group", try_view_now(sim, "J", group))
        .await??;
    let j_status = status(sim, "J", group).await?;
    let membership = j_status.as_ref().and_then(|st| st.membership.clone());
    let passed = caught_up(j.as_ref(), &a, membership.as_deref());
    let text = format!(
        "{authority} {}; J {}; J {}",
        a.describe(),
        j_status
            .as_ref()
            .map_or_else(|| "404".to_string(), Status::describe),
        j.as_ref()
            .map_or_else(|| "has no record".to_string(), View::describe)
    );
    Ok((passed, text, j, j_status))
}

// ─── H-S3-b: provisional-ATA promotion (L1, D82) ──────────────────────────

const B_LABELS: &[&str] = &["A", "M1", "M2", "J"];
const FINAL_B: &str = "j_catches_up_through_m1_provisional_ata_and_holds_keys";
const CAUSE_B: &str = "J stays marked (no_anchor) with no recovery object: no admin answers";

/// H-S3-b: S0 with A on the previous release. A promotes M1 (r+1) and
/// removes M2 (r+2, see below); J joins with I and A seals J (r+3).
/// Advance 130 s, then one request interval. Desired: J asks M1, which is
/// provisional (a member on J's base roster); J's kept served chain proves
/// M1's promotion at r+1, so M1's ATA arms; J applies the gap, replays its
/// add, retires its marker and holds keys. Main: J stays marked.
async fn provisional_promotion(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let (group, minted) = s0(sim, B_LABELS, true, &["A"]).await?;
    let link = invite(sim, "A", &group).await?;
    promote(sim, "A", "M1", &group, &["A", "M1", "M2"]).await?;
    let promoted = view(sim, "A", &group).await?;
    ensure!(
        promoted.state_revision == minted.state_revision + 1,
        "INFRA: the promotion moved A from {} to {}",
        minted.state_revision,
        promoted.state_revision
    );
    // The row's single promotion gap converges on this build with no
    // marker (local run, 25 Oct 2026): J applies the promotion from A's
    // served chain. The row expects J marked on the base, so the case adds
    // H-S3-a's gap step, A's removal of M2 (r+2), which marks a skewed
    // joiner on the base (`case_818`). M1 stays the only capable admin.
    remove(sim, "A", "M2", &group).await?;
    settled(sim, &["M1"], &group, "M1 holds the removal").await?;
    sim.within("the gap resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let joined_at = sim.fabric().mark_indexed("case: J redeems invite I");
    let sealed = seal_j(sim, &link, &group).await?;
    let stub = view(sim, "J", &group).await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "j_seeded_at_r_and_m1_a_member_there",
        stub.base_revision == Some(minted.state_revision) && !stub.owner_axis,
        format!(
            "invite base {}; J {}",
            minted.state_revision,
            stub.describe()
        ),
        at(sim),
    );
    receipt.evidence(
        "gap_is_the_promotion_of_m1_and_the_removal_of_m2",
        sealed.state_revision == minted.state_revision + 3 && sealed.marker.is_none(),
        format!("A {}", sealed.describe()),
        at(sim),
    );
    let mut window = JWindow::default();
    watch_j(
        sim,
        &group,
        "A",
        "J catches up through M1",
        CATCHUP + REQUEST_INTERVAL,
        true,
        &mut window,
    )
    .await?;
    let (caught, text, j, j_status) = j_end(sim, &group, "A").await?;
    let j_hex = sim.agent_hex("J")?;
    let m1_route = sim
        .at_instant("read M1's recovery", recovery_route(sim, "M1", &group))
        .await??;
    let a_route = sim
        .at_instant("read A's recovery", recovery_route(sim, "A", &group))
        .await??;
    let by_m1 = answered(&m1_route, &j_hex, "attested");
    let passed = caught && by_m1;
    let to_m1 = delivered_after(sim, "J", "M1", joined_at)?;
    let to_a = delivered_after(sim, "J", "A", joined_at)?;
    receipt.request_delivered(
        "j_reached_a_and_m1",
        to_a > 0 && to_m1 > 0,
        format!("frames since the join: J->A={to_a} J->M1={to_m1}"),
        at(sim),
    );
    receipt.note(format!(
        "at the end: {text}; J first marked {:?}; J recovery states {:?}; caught up {:?}; \
         S3 sidecars: J {:?}, A {:?}, M1 {:?}; M1 requesters {}; A requesters {}",
        window.marked,
        window.recovery_states,
        window.caught_up_at,
        sidecars(sim, "J"),
        sidecars(sim, "A"),
        sidecars(sim, "M1"),
        m1_route["requesters"],
        a_route["requesters"]
    ));
    if !passed {
        let marked = window.marked.is_some() || j.as_ref().is_some_and(|j| j.marker.is_some());
        let no_recovery = j_status.as_ref().is_none_or(|st| st.recovery.is_null())
            && window.recovery_states.iter().all(|s| s == "null");
        receipt.cause(CAUSE_B, Some(text), marked && no_recovery, at(sim));
    }
    receipt.finish(FINAL_B, passed, at(sim));
    Ok(())
}

// ─── H-S3-t: typed waits (D64) ────────────────────────────────────────────

const T_LABELS: &[&str] = &["A", "M1", "M2", "J"];
const FINAL_T: &str = "j_shows_each_typed_wait_in_turn_never_a_bare_timed_out";
const FINAL_T4: &str = "j_shows_recovery_deferred_until_host_commit_then_asks";
const CAUSE_T: &str = "J has no recovery object in the whole run, and join-status ends with \
                       no named S3 cause";
/// A transition that waits for J's next retry round, which by step (2) can
/// be 480 s out (the counter carries from step (1)), with margin.
const RETRY_TRANSITION: Duration = Duration::from_secs(600);
/// H-S3-t (3): the ADR's "advance 3 h", as a ceiling; the case stops once
/// it has seen two retry rounds (see [`backoff_doubles`]).
const PARTITION_WINDOW: Duration = Duration::from_secs(3 * 60 * 60);
/// A typed-wait transition after a change: one request interval and the
/// backoff the earlier steps built up (at most 240 s by then), with margin.
const TRANSITION: Duration = Duration::from_secs(300);

/// J's `GET /groups/:id/join-status` `last_join_outcome` (`outcome`,
/// `reason`), or `None`.
async fn join_outcome(sim: &Sim, group: &str) -> Result<Option<(String, Option<String>)>> {
    let (_, body) = sim
        .request(
            "J",
            Method::GET,
            &format!("/groups/{group}/join-status"),
            None,
        )
        .await?;
    Ok(body["last_join_outcome"]["outcome"]
        .as_str()
        .map(|outcome| {
            (
                outcome.to_string(),
                body["last_join_outcome"]["reason"]
                    .as_str()
                    .map(str::to_string),
            )
        }))
}

/// What a typed-wait window saw on J.
#[derive(Default)]
struct Waits {
    states: Vec<String>,
    outcomes: Vec<String>,
    bare_timed_out: Option<String>,
    /// Virtual ms of each retry round seen.
    retry_at: Vec<u64>,
    last_retry: Option<u64>,
}

impl Waits {
    async fn sample(&mut self, sim: &Sim, group: &str) -> Result<Value> {
        let recovery = status_now(sim, "J", group)
            .await?
            .map(|st| st.recovery)
            .unwrap_or(Value::Null);
        let text = recovery_text(&recovery);
        if self.states.last() != Some(&text) {
            self.states.push(text);
        }
        // A retry round moves `next_retry_at_ms` by its backoff. Record the
        // virtual time of each such jump (over 30 s), so the steps hold
        // with or without the shim's wall clock.
        if let Some(at) = recovery["next_retry_at_ms"].as_u64() {
            if self
                .last_retry
                .is_none_or(|last| at.abs_diff(last) > 30_000)
            {
                self.retry_at
                    .push(u64::try_from(sim.fabric().now().as_millis()).unwrap_or(u64::MAX));
            }
            self.last_retry = Some(at);
        }
        if let Some((outcome, reason)) = join_outcome(sim, group).await? {
            let text = format!("{outcome}/{}", reason.as_deref().unwrap_or("-"));
            if self.outcomes.last() != Some(&text) {
                self.outcomes.push(text);
            }
            if outcome == "timed_out" {
                self.bare_timed_out
                    .get_or_insert_with(|| format!("at {} us", sim.fabric().now().as_micros()));
            }
        }
        Ok(recovery)
    }

    /// Sample J until `done` holds on its `recovery` object, or `budget`
    /// passes. Returns whether `done` held.
    async fn until(
        &mut self,
        sim: &Sim,
        group: &str,
        what: &str,
        budget: Duration,
        done: impl Fn(&Value) -> bool,
    ) -> Result<bool> {
        let mut failed: Option<String> = None;
        let mut met = false;
        let waited = sim
            .until(what, budget, async |s: &Sim| {
                match self.sample(s, group).await {
                    Ok(recovery) => {
                        met = done(&recovery);
                        met
                    }
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
        Ok(met)
    }
}

impl Waits {
    /// Sample J until `rounds` retry rounds are recorded, or `budget`
    /// passes.
    async fn until_rounds(
        &mut self,
        sim: &Sim,
        group: &str,
        what: &str,
        budget: Duration,
        rounds: usize,
    ) -> Result<()> {
        let mut failed: Option<String> = None;
        let waited = sim
            .until(what, budget, async |s: &Sim| {
                match self.sample(s, group).await {
                    Ok(_) => self.retry_at.len() >= rounds,
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

fn waiting_for(recovery: &Value, reason: &str) -> bool {
    recovery["state"] == "awaiting_attestation" && recovery["reason"] == reason
}

/// The steps between successive `next_retry_at_ms` values, in seconds.
fn retry_steps(retry_at: &[u64]) -> Vec<u64> {
    retry_at
        .windows(2)
        .map(|pair| pair[1].saturating_sub(pair[0]) / 1000)
        .collect()
}

/// §11 backoff across two rounds in the partition. Each round's virtual
/// interval is its backoff plus a constant overhead (the wait for the
/// unanswered reply, about 10 s in local runs). Net of that overhead the
/// second step doubles the first, and both are 60 s doubled (capped at
/// 1 h). The cap itself is `request_backoff`'s unit test
/// (`groups::recovery`), not this case: ADR 0109's "advance 3 h" is 20
/// reruns × about 4 min of real time, past the W3-H shard's 120-min cap.
fn backoff_doubles(steps: &[u64]) -> bool {
    const SLACK: u64 = 3;
    let [first, second, ..] = steps else {
        return false;
    };
    let base = second.saturating_sub(*first);
    let overhead = first.saturating_sub(base);
    let series = |step: u64| (0..7).any(|k| step.abs_diff((60_u64 << k).min(3600)) <= SLACK);
    overhead <= 30
        && series(base)
        && second
            .saturating_sub(overhead)
            .abs_diff((base * 2).min(3600))
            <= SLACK
}

/// Write an uncommitted ADR 0094 upgrade journal into `label`'s data
/// directory (`phase` `health_committed`), or move it to `host_committed`.
/// The same record as the S3 unit tests' `write_upgrade_journal`.
fn upgrade_journal(sim: &Sim, label: &str, phase: &str) -> Result<()> {
    let data_dir = sim.state(label)?.data_dir.clone();
    let artifact = |name: &str| {
        json!({
            "target_path": data_dir.join(name),
            "staged_path": data_dir.join(format!("{name}.staged")),
            "backup_path": data_dir.join(format!("{name}.backup")),
            "previous_sha256": vec![1_u8; 32],
            "candidate_sha256": vec![2_u8; 32],
        })
    };
    let record = json!({
        "schema_version": 1,
        "record_kind": "journal",
        "transaction_id": "w3h-1356-t4",
        "sequence": 1,
        "generation": 1,
        "plan": {
            "previous_version": "0.48.1",
            "candidate_version": "0.48.2",
            "manifest_sha256": vec![3_u8; 32],
            "daemon": artifact("x0xd"),
            "cli": artifact("x0x"),
            "participants": [{
                "instance_id": label,
                "executable": data_dir.join("x0xd"),
                "data_root": data_dir,
                "identity_root": data_dir,
                "argv": ["x0xd"],
                "cwd": data_dir,
                "env": {},
                "restart": {
                    "mode": "TransactionalHandoff",
                    "supervised_exit_code": null,
                    "supervision_signal": null,
                    "launchd_verified": null,
                    "systemd_verified": null,
                    "launcher": null
                },
                "old_pid": 1234,
                "process_start": 100,
                "boot_id": "boot-w3h",
                "was_running": true
            }]
        },
        "phase": phase,
        "cause": null,
        "daemon_progress": {"swapped": true, "restored": false, "observed_sha256": null},
        "cli_progress": {"swapped": true, "restored": false, "observed_sha256": null}
    });
    std::fs::write(
        data_dir.join(crate::upgrade::journal::JOURNAL_FILE_NAME),
        serde_json::to_vec(&record)?,
    )?;
    sim.fabric()
        .mark(format!("case: {label}'s ADR 0094 journal phase {phase}"));
    Ok(())
}

/// H-S3-t (1) to (3), or the (4) host-commit variant: S0 with A, M1 and M2
/// on the previous release, then as H-S3-a (A removes M2 at r+1; J joins
/// with I; A seals J at r+2); advance 130 s.
/// (1) J's `join-status` and `recovery` show `awaiting_attestation
/// {no_capable_peer}`, never a bare `timed_out`. (2) M1 restarts on the
/// candidate (a capable non-admin): `reason: not_an_admin`. (3) M1 goes
/// offline (every capable peer partitioned); advance 3 h: `reason:
/// no_reply`, and `next_retry_at` steps double up to 1 h and stay there.
/// (4) J's host is inside an uncommitted ADR 0094 trial before the join:
/// `recovery_deferred {host_commit_pending}` through (1); after the host
/// commit, the request path (`awaiting_attestation`).
async fn typed_waits(sim: &mut Sim, receipt: &mut Receipt, host_commit: bool) -> Result<()> {
    let (group, minted) = s0(sim, T_LABELS, true, &["A", "M1", "M2"]).await?;
    let link = invite(sim, "A", &group).await?;
    remove(sim, "A", "M2", &group).await?;
    settled(sim, &["M1"], &group, "M1 holds the removal").await?;
    sim.within("the removal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    if host_commit {
        upgrade_journal(sim, "J", "health_committed")?;
    }
    let joined_at = sim.fabric().mark_indexed("case: J redeems invite I");
    let sealed = seal_j(sim, &link, &group).await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "gap_is_the_authority_removal_of_m2",
        sealed.state_revision == minted.state_revision + 2 && sealed.marker.is_none(),
        format!("A {}", sealed.describe()),
        at(sim),
    );
    let mut waits = Waits::default();
    waits
        .until(sim, &group, "the 130 s window", CATCHUP, |_| false)
        .await?;
    let first = sim
        .at_instant("read J's recovery", status_now(sim, "J", &group))
        .await??
        .map(|st| st.recovery)
        .unwrap_or(Value::Null);
    let first_outcome = sim
        .at_instant("read J's join-status", join_outcome(sim, &group))
        .await??;
    let to_a = delivered_after(sim, "J", "A", joined_at)?;
    receipt.request_delivered(
        "j_join_reached_a",
        to_a > 0 && sealed.lists(&sim.agent_hex("J")?),
        format!("frames J->A since the join: {to_a}"),
        at(sim),
    );
    let step1 = if host_commit {
        first["state"] == "recovery_deferred" && first["cause"] == "host_commit_pending"
    } else {
        waiting_for(&first, "no_capable_peer")
            && first_outcome.as_ref().is_some_and(|(outcome, reason)| {
                outcome == "awaiting_attestation"
                    && reason.as_deref() == Some("adr0109_recovery_held")
            })
    };
    receipt.note(format!(
        "after 130 s: J recovery {first}; join-status {first_outcome:?}"
    ));
    let mut steps_ok = vec![("1", step1)];
    // A failed step ends the run: the later steps build on it, and on the
    // base they would only wait out their budgets (past nextest's kill).
    if step1 && host_commit {
        upgrade_journal(sim, "J", "host_committed")?;
        let asked = waits
            .until(
                sim,
                &group,
                "J asks after the host commit",
                TRANSITION,
                |r| r["state"] == "awaiting_attestation",
            )
            .await?;
        steps_ok.push(("4-after-host-commit", asked));
    } else if step1 {
        sim.restart("M1", RestartMode::Graceful).await?;
        // Both ways: a responder with no current advert from the requester
        // refreshes it and sends nothing on that round (§5), so a fresh M1
        // would answer only one backoff step later.
        sees_s3(sim, "J", "M1").await?;
        sees_s3(sim, "M1", "J").await?;
        let not_admin = waits
            .until(
                sim,
                &group,
                "J hears not_an_admin from M1",
                RETRY_TRANSITION,
                |r| waiting_for(r, "not_an_admin"),
            )
            .await?;
        steps_ok.push(("2", not_admin));
    }
    if steps_ok.iter().all(|(_, ok)| *ok) && !host_commit {
        sim.set_online("M1", false)?;
        let no_reply = waits
            .until(sim, &group, "J hears no reply", TRANSITION, |r| {
                waiting_for(r, "no_reply")
            })
            .await?;
        steps_ok.push(("3-no_reply", no_reply));
    }
    if steps_ok.len() == 3 && steps_ok.iter().all(|(_, ok)| *ok) {
        let held_from = waits.retry_at.len().saturating_sub(1);
        waits
            .until_rounds(
                sim,
                &group,
                "two retry rounds in the partition",
                PARTITION_WINDOW,
                held_from + 3,
            )
            .await?;
        let steps = retry_steps(&waits.retry_at[held_from..]);
        let still_no_reply = waits
            .states
            .last()
            .is_some_and(|s| s == "awaiting_attestation{no_reply}");
        receipt.note(format!(
            "next_retry_at steps after the partition (s): {steps:?}"
        ));
        steps_ok.push(("3-backoff", backoff_doubles(&steps) && still_no_reply));
    }
    let never_bare = waits.bare_timed_out.is_none();
    steps_ok.push(("never-bare-timed_out", never_bare));
    receipt.note(format!(
        "J recovery states {:?}; join-status outcomes {:?}; bare timed_out {:?}; steps {steps_ok:?}",
        waits.states, waits.outcomes, waits.bare_timed_out
    ));
    let passed = steps_ok.iter().all(|(_, ok)| *ok);
    if !passed {
        let never_recovery = waits.states.iter().all(|s| s == "null") && first.is_null();
        let unnamed = waits
            .outcomes
            .iter()
            .all(|outcome| !outcome.contains("adr0109_recovery_held"));
        receipt.cause(
            CAUSE_T,
            Some(format!(
                "states {:?}; outcomes {:?}",
                waits.states, waits.outcomes
            )),
            never_recovery && unnamed,
            at(sim),
        );
    }
    receipt.finish(
        if host_commit { FINAL_T4 } else { FINAL_T },
        passed,
        at(sim),
    );
    Ok(())
}

// ─── Origin holds ─────────────────────────────────────────────────────────

/// One write as an [`OriginHold`] policy sees it.
struct Frame {
    /// The node whose write carried this pubsub message ID first, or the
    /// sender of any other write.
    origin: Key,
    dst: Key,
}

type Policy = Box<dyn Fn(&Frame) -> bool + Send + Sync>;

/// Holds every message between node sets, including gossip relays. The
/// policy decides from the [`Frame`] whether a write is dropped, and can
/// change.
#[derive(Clone)]
struct OriginHold {
    policy: Arc<Mutex<Policy>>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

type Key = crate::network::sim::Key;

impl OriginHold {
    fn install(sim: &Sim, what: &str) -> Self {
        use crate::network::sim::{Fault, LaneClass};
        use std::collections::HashMap;
        let hold = Self {
            policy: Arc::new(Mutex::new(Box::new(|_| false))),
            dropped: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let origins: Mutex<HashMap<[u8; 32], Key>> = Mutex::new(HashMap::new());
        let (policy, dropped) = (Arc::clone(&hold.policy), Arc::clone(&hold.dropped));
        sim.fabric().add_rule(move |write| {
            let msg = (write.lane.class == LaneClass::PubSub)
                .then(|| pubsub_header(&write.bytes))
                .flatten();
            let origin = match msg {
                Some((_, msg_id)) => match origins.lock() {
                    Ok(mut map) => *map.entry(msg_id).or_insert(write.lane.src),
                    Err(_) => return Fault::Drop,
                },
                None => write.lane.src,
            };
            let frame = Frame {
                origin,
                dst: write.lane.dst,
            };
            let drop = policy.lock().map_or(true, |policy| policy(&frame));
            if drop {
                dropped.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        sim.fabric()
            .mark(format!("fault: origin hold installed ({what})"));
        hold
    }

    fn set(&self, sim: &Sim, what: &str, policy: impl Fn(&Frame) -> bool + Send + Sync + 'static) {
        if let Ok(mut slot) = self.policy.lock() {
            *slot = Box::new(policy);
        }
        sim.fabric().mark(format!("fault: origin hold now {what}"));
    }

    fn dropped(&self) -> usize {
        self.dropped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn keys(sim: &Sim, labels: &[&str]) -> Result<Vec<Key>> {
    labels.iter().map(|label| Ok(sim.peer(label)?.0)).collect()
}

// ─── H-S3-r: beyond retention (D97, D119) ─────────────────────────────────

const R_LABELS: &[&str] = &["A", "M1", "M2", "B", "J"];
const FINAL_R: &str = "j_readmission_required_then_b_attests_and_j_catches_up";
const CAUSE_R: &str = "J is marked or its join times out, with no typed state in the window";
/// H-S3-r: "A's commit-log cap set to 4 by test configuration".
const R_CAP: usize = 4;

/// The H-S3-r cap: `COMMIT_LOG_CAP` is a compile-time 4096, so the harness
/// trims A's in-memory commit log to its newest [`R_CAP`] entries.
async fn cap_log(sim: &Sim, label: &str, group: &str) -> Result<usize> {
    let state = sim.state(label)?;
    let mut groups = state.named_groups.write().await;
    let key = crate::server::resolve_group_entry_locked(&groups, group)
        .map(|(key, _)| key.to_string())
        .with_context(|| format!("{label} has no record of {group}"))?;
    let info = groups
        .get_mut(&key)
        .with_context(|| format!("{label} has no record of {group}"))?;
    let mut revisions: Vec<u64> = info.commit_log.iter().map(|e| e.commit.revision).collect();
    revisions.sort_unstable();
    let keep_from = revisions
        .len()
        .checked_sub(R_CAP)
        .and_then(|cut| revisions.get(cut).copied())
        .unwrap_or(0);
    info.commit_log
        .retain(|entry| entry.commit.revision >= keep_from);
    Ok(info.commit_log.len())
}

/// H-S3-r: S0 with A's commit log capped at 4 and admin B (default cap)
/// seated after step 2. Every message between B and J is held. After the
/// mint A renames 6 times (r+1 to r+6) and seals J (r+7); B applies them.
/// Advance 130 s and one request interval. Desired: A answers
/// `base_beyond_retention`; J shows `readmission_required
/// {base_beyond_retention}` with an `exit`, applies no link and keeps its
/// containment. Then the B–J messages pass: B's ATA arms, J leaves the
/// state, catches up and holds keys. Main: J is marked or times out with
/// no typed state.
async fn beyond_retention(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    mesh(sim, R_LABELS).await?;
    let group = create_group(sim, "A").await?;
    for member in ["M1", "M2", "B"] {
        seat(sim, "A", member, &group).await?;
    }
    promote(sim, "A", "B", &group, &["A", "M1", "M2", "B"]).await?;
    for write_access in POLICY_CHANGES {
        let (code, body) = sim
            .api(
                "A",
                Method::PATCH,
                &format!("/groups/{group}/policy"),
                Some(json!({"write_access": write_access})),
            )
            .await?;
        ensure!(code.is_success(), "policy {write_access}: {code} {body}");
    }
    settled(
        sim,
        &["M1", "M2", "B"],
        &group,
        "M1, M2 and B hold A's revision",
    )
    .await?;
    let hold = OriginHold::install(sim, "B and J");
    let (b, j) = (sim.peer("B")?.0, sim.peer("J")?.0);
    hold.set(sim, "holding every message between B and J", move |f| {
        (f.origin == b && f.dst == j) || (f.origin == j && f.dst == b)
    });
    let minted = view(sim, "A", &group).await?;
    let link = invite(sim, "A", &group).await?;
    for n in 1..=6 {
        rename(sim, "A", &group, &format!("w3h r {n}")).await?;
    }
    settled(sim, &["B"], &group, "B holds A's six renames").await?;
    let kept = cap_log(sim, "A", &group).await?;
    sim.within("the rename resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let joined_at = sim.fabric().mark_indexed("case: J redeems invite I");
    let sealed = seal_j(sim, &link, &group).await?;
    let kept_after = cap_log(sim, "A", &group).await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "gap_is_six_renames_and_a_keeps_only_four_commits",
        sealed.state_revision == minted.state_revision + 7 && kept <= R_CAP && kept_after <= R_CAP,
        format!(
            "mint at {}; A {}; A's log kept {kept} then {kept_after}",
            minted.state_revision,
            sealed.describe()
        ),
        at(sim),
    );
    let mut first = JWindow::default();
    watch_j(
        sim,
        &group,
        "A",
        "the held window",
        CATCHUP + REQUEST_INTERVAL,
        false,
        &mut first,
    )
    .await?;
    let (caught_early, held_text, j_held, j_held_status) = j_end(sim, &group, "A").await?;
    let readmission = j_held_status.as_ref().is_some_and(|st| {
        st.recovery_state() == Some("readmission_required")
            && st.recovery_cause() == Some("base_beyond_retention")
            && !st.recovery["exit"].is_null()
    });
    let j_rev = j_held.as_ref().map(|j| j.state_revision);
    let to_a = delivered_after(sim, "J", "A", joined_at)?;
    receipt.request_delivered(
        "j_reached_a",
        to_a > 0,
        format!(
            "frames J->A since the join: {to_a}; held B<->J writes {}",
            hold.dropped()
        ),
        at(sim),
    );
    receipt.note(format!(
        "after the held window: {held_text}; states {:?}; first marked {:?}",
        first.recovery_states, first.marked
    ));
    hold.set(sim, "passing everything", |_| false);
    let mut second = JWindow::default();
    watch_j(
        sim,
        &group,
        "A",
        "J catches up through B",
        TRANSITION,
        true,
        &mut second,
    )
    .await?;
    let (caught, end_text, _, _) = j_end(sim, &group, "A").await?;
    let j_hex = sim.agent_hex("J")?;
    let b_route = sim
        .at_instant("read B's recovery", recovery_route(sim, "B", &group))
        .await??;
    let by_b = answered(&b_route, &j_hex, "attested");
    receipt.note(format!(
        "after the release: {end_text}; states {:?}; B requesters {}",
        second.recovery_states, b_route["requesters"]
    ));
    let passed = readmission && !caught_early && caught && by_b;
    receipt.note(format!(
        "readmission={readmission} caught_early={caught_early} caught={caught} by_b={by_b} \
         J revision while held {j_rev:?}"
    ));
    if !passed {
        let typed = first
            .recovery_states
            .iter()
            .chain(second.recovery_states.iter())
            .any(|state| state != "null");
        receipt.cause(
            CAUSE_R,
            Some(format!("{held_text}; then {end_text}")),
            !typed && (first.marked.is_some() || j_held.is_none() || !caught),
            at(sim),
        );
    }
    receipt.finish(FINAL_R, passed, at(sim));
    Ok(())
}

/// Start every label in `labels`. The labels in `ranked` get their
/// pre-generated keys reassigned among themselves so that their agent IDs
/// rise in that order.
pub(super) async fn start_ranked(sim: &mut Sim, labels: &[&str], ranked: &[&str]) -> Result<()> {
    let mut pairs = Vec::new();
    for label in ranked {
        pairs.push(sim.take_keys(label)?);
    }
    pairs.sort_by_key(|(_, agent)| agent.agent_id().0);
    let mut provisions = BTreeMap::new();
    for (label, (machine, agent)) in ranked.iter().zip(pairs) {
        provisions.insert(
            label.to_string(),
            Provision {
                machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
                agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
                user_key: None,
                agent_cert: None,
            },
        );
    }
    for label in labels {
        let provision = provisions.remove(*label).unwrap_or_default();
        sim.start_node_with(label, provision).await?;
    }
    Ok(())
}

// ─── H-S3-d5: sibling marker, manual clear (D80) ──────────────────────────

const D5_LABELS: &[&str] = &["A", "M1", "M2", "B", "C", "J"];
const FINAL_D5: &str = "c_and_j_manual_clear_required_c_contained_clear_frees_only_c";
const CAUSE_D5: &str = "C and J hold markers naming B's r+2', with no recovery object";

/// H-S3-d5: S0′ with admins B and C promoted after step 2. J joins with I;
/// A seals J (r+1). Every message between B and {A, C, J} is held. A
/// renames (r+2); B renames (r+2′). A's r+2 reaches C and J, then B's r+2′
/// reaches C and J only. Advance one request interval. C calls the re-seat
/// route for M1; C's operator force-clears C's marker. Desired: C and J
/// hold a marker naming r+2′; A answers their requests `on_chain`; each
/// shows `manual_clear_required {ref}`; C refuses J with
/// `attester_quarantined`; C's re-seat returns `admin_contained`; after
/// the force clear C has no marker and can send, and J stays
/// `manual_clear_required`. Main: markers with no recovery object.
async fn sibling_marker(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    // J asks capable admins lowest agent ID first (D40) and stops at the
    // first definitive answer. The row has C refuse J, so C takes the
    // lowest agent ID of the admins, then B, then A.
    start_ranked(sim, D5_LABELS, &["C", "B", "A"]).await?;
    mesh(sim, D5_LABELS).await?;
    let group = create_group(sim, "A").await?;
    for member in ["M1", "M2", "B", "C"] {
        seat(sim, "A", member, &group).await?;
    }
    for admin in ["B", "C"] {
        promote(sim, "A", admin, &group, &["A", "M1", "M2", "B", "C"]).await?;
    }
    settled(
        sim,
        &["M1", "M2", "B", "C"],
        &group,
        "every member holds A's revision",
    )
    .await?;
    let link = invite(sim, "A", &group).await?;
    let sealed = seal_j(sim, &link, &group).await?;
    settled(
        sim,
        &["M1", "M2", "B", "C", "J"],
        &group,
        "every node holds J's seal",
    )
    .await?;
    sim.within("the seal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    let hold = OriginHold::install(sim, "B");
    let b = sim.peer("B")?.0;
    let others = keys(sim, &["A", "C", "J"])?;
    let c_and_j = keys(sim, &["C", "J"])?;
    {
        let others = others.clone();
        hold.set(
            sim,
            "holding every message between B and {A, C, J}",
            move |f| {
                (f.origin == b && others.contains(&f.dst))
                    || (others.contains(&f.origin) && f.dst == b)
            },
        );
    }
    let b_rev_before = view(sim, "B", &group).await?;
    rename(sim, "A", &group, "w3h d5 A").await?;
    settled(sim, &["C", "J"], &group, "C and J hold A's r+2").await?;
    let main = view(sim, "A", &group).await?;
    rename(sim, "B", &group, "w3h d5 B").await?;
    let fork = view(sim, "B", &group).await?;
    {
        let others = others.clone();
        let c_and_j = c_and_j.clone();
        hold.set(sim, "B's messages reach C and J only", move |f| {
            (f.origin == b && !c_and_j.contains(&f.dst))
                || (others.contains(&f.origin) && f.dst == b)
        });
    }
    let b_hex = sim.agent_hex("B")?;
    sim.until("C and J hold a marker naming B", SETUP, async |s: &Sim| {
        let mut both = true;
        for label in ["C", "J"] {
            let marked = view_now(s, label, &group).await.is_ok_and(|v| {
                v.marker
                    .as_ref()
                    .is_some_and(|m| m.committed_by.eq_ignore_ascii_case(&b_hex))
            });
            both &= marked;
        }
        both
    })
    .await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "b_forked_at_r_plus_2_beside_a",
        fork.state_revision == main.state_revision
            && fork.state_hash != main.state_hash
            && b_rev_before.state_revision + 1 == fork.state_revision
            && sealed.marker.is_none(),
        format!("A {}; B {}", main.describe(), fork.describe()),
        at(sim),
    );
    let c0 = view(sim, "C", &group).await?;
    let j0 = view(sim, "J", &group).await?;
    receipt.evidence(
        "c_and_j_on_a_chain_with_a_marker_naming_b",
        c0.state_hash == main.state_hash && j0.state_hash == main.state_hash,
        format!("C {}; J {}", c0.describe(), j0.describe()),
        at(sim),
    );
    let since = sim.fabric().mark_indexed("case: one request interval");
    let mut c_state = String::new();
    let mut j_state = String::new();
    let _ = sim
        .until(
            "C and J show their typed state",
            REQUEST_INTERVAL * 3,
            async |s: &Sim| {
                let c = status_now(s, "C", &group).await.ok().flatten();
                let j = status_now(s, "J", &group).await.ok().flatten();
                c_state = c.map(|st| recovery_text(&st.recovery)).unwrap_or_default();
                j_state = j.map(|st| recovery_text(&st.recovery)).unwrap_or_default();
                c_state.starts_with("manual_clear_required")
                    && j_state.starts_with("manual_clear_required")
            },
        )
        .await;
    let to_a = delivered_after(sim, "J", "A", since)? + delivered_after(sim, "C", "A", since)?;
    receipt.request_delivered(
        "c_and_j_reached_a",
        to_a > 0,
        format!(
            "frames C,J->A in the interval: {to_a}; held writes {}",
            hold.dropped()
        ),
        at(sim),
    );
    let (c_hex, j_hex, m1_hex) = (
        sim.agent_hex("C")?,
        sim.agent_hex("J")?,
        sim.agent_hex("M1")?,
    );
    let a_route = sim
        .at_instant("read A's recovery", recovery_route(sim, "A", &group))
        .await??;
    let c_route = sim
        .at_instant("read C's recovery", recovery_route(sim, "C", &group))
        .await??;
    let on_chain = answered(&a_route, &c_hex, "on_chain") && answered(&a_route, &j_hex, "on_chain");
    let quarantined = answered(&c_route, &j_hex, "attester_quarantined");
    let j_status = status(sim, "J", &group).await?;
    let ref_named = j_status.as_ref().is_some_and(|st| {
        st.recovery["ref"]["committed_by"]
            .as_str()
            .is_some_and(|by| by.eq_ignore_ascii_case(&b_hex))
    });
    let (code, reseat_answer) = sim
        .api(
            "C",
            Method::POST,
            &format!("/groups/{group}/members/{m1_hex}/reseat"),
            Some(json!({"reason": "w3h #1356 d5", "basis": {"kind": "removal", "revision": 1, "state_hash": "00"}})),
        )
        .await?;
    let contained =
        reseat_answer["reason"] == "admin_contained" || reseat_answer["error"] == "admin_contained";
    let (clear_code, cleared) = sim
        .api(
            "C",
            Method::POST,
            &format!("/groups/{group}/quarantine/clear"),
            Some(json!({"force": true, "reason": "w3h #1356 d5: C's operator clears"})),
        )
        .await?;
    let c1 = view(sim, "C", &group).await?;
    // The row's `POST /groups/:id/send` is for SignedPublic groups; this
    // group is MlsEncrypted, so C's uncontained write is a rename (a
    // contained admin's commit is refused).
    let (send_code, sent) = sim
        .api(
            "C",
            Method::PATCH,
            &format!("/groups/{group}"),
            Some(json!({"name": "w3h d5 C after clear"})),
        )
        .await?;
    let _ = sim
        .until("J after C's clear", REQUEST_INTERVAL, async |_s: &Sim| {
            false
        })
        .await;
    let j_after = status(sim, "J", &group).await?;
    let j_still = j_after
        .as_ref()
        .is_some_and(|st| st.recovery_state() == Some("manual_clear_required"));
    receipt.note(format!(
        "C {c_state}; J {j_state}; A answered on_chain {on_chain}; C answered J \
         attester_quarantined {quarantined}; J ref names B {ref_named}; C reseat {code} \
         {reseat_answer}; C clear {clear_code} {cleared}; C after {}; C send {send_code} {sent}; \
         J after {:?}; A requesters {}; C requesters {}",
        c1.describe(),
        j_after.as_ref().map(Status::describe),
        a_route["requesters"],
        c_route["requesters"]
    ));
    let passed = c_state.starts_with("manual_clear_required")
        && j_state.starts_with("manual_clear_required")
        && on_chain
        && quarantined
        && ref_named
        && contained
        && clear_code.is_success()
        && c1.marker.is_none()
        && send_code.is_success()
        && j_still;
    if !passed {
        let marked = c0.marker.is_some() && j0.marker.is_some();
        receipt.cause(
            CAUSE_D5,
            Some(format!("C {c_state:?}; J {j_state:?}")),
            marked && c_state == "null" && j_state == "null",
            at(sim),
        );
    }
    receipt.finish(FINAL_D5, passed, at(sim));
    Ok(())
}

// ─── Runners ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Row {
    /// H-S3-b.
    Provisional,
    /// H-S3-t (1) to (3).
    TypedWaits,
    /// H-S3-t (4).
    HostCommit,
    /// H-S3-r.
    Retention,
    /// H-S3-d5.
    Sibling,
}

impl Row {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::Provisional => B_LABELS,
            Self::TypedWaits | Self::HostCommit => T_LABELS,
            Self::Retention => R_LABELS,
            Self::Sibling => D5_LABELS,
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::Provisional => FINAL_B,
            Self::TypedWaits => FINAL_T,
            Self::HostCommit => FINAL_T4,
            Self::Retention => FINAL_R,
            Self::Sibling => FINAL_D5,
        }
    }
}

async fn run_row(case: &str, seed: u64, row: Row) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "ADR 0109 S3 (#1356, #1572) {row:?}; a node 'on the previous release' runs this \
         build with S3 off (see the module notes)"
    ));
    let sim = match row {
        // H-S3-d5 ranks its admins' identities before each start.
        Row::Sibling => Sim::empty(case, seed, row.labels()),
        _ => Sim::start(case, seed, row.labels()).await,
    };
    match sim {
        Ok(mut sim) => {
            let outcome = match row {
                Row::Provisional => provisional_promotion(&mut sim, &mut receipt).await,
                Row::TypedWaits => typed_waits(&mut sim, &mut receipt, false).await,
                Row::HostCommit => typed_waits(&mut sim, &mut receipt, true).await,
                Row::Retention => beyond_retention(&mut sim, &mut receipt).await,
                Row::Sibling => sibling_marker(&mut sim, &mut receipt).await,
            };
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
        receipt.reclassify(row.final_name());
    }
    receipt.emit();
    receipt
}

async fn expect_row(case: &str, seed: u64, row: Row, want: Verdict) -> Result<()> {
    let receipt = run_row(case, seed, row).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// H-S3-b (L1, D82): RED on the base; GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_red_s3_b_provisional_admin_ata_promotes() -> Result<()> {
    super::super::block_on_paused(async move {
        expect_row(
            "w3h_1356_red_s3_b_provisional_admin_ata_promotes",
            0x1356_0101,
            Row::Provisional,
            Verdict::Green,
        )
        .await
    })
}

/// H-S3-t (1) to (3) (D64): RED on the base; GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_red_s3_t_typed_waits_name_their_cause() -> Result<()> {
    super::super::block_on_paused(async move {
        expect_row(
            "w3h_1356_red_s3_t_typed_waits_name_their_cause",
            0x1356_0102,
            Row::TypedWaits,
            Verdict::Green,
        )
        .await
    })
}

/// H-S3-t (4) (D64, ADR 0094): RED on the base; GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_red_s3_t_deferred_until_host_commit() -> Result<()> {
    super::super::block_on_paused(async move {
        expect_row(
            "w3h_1356_red_s3_t_deferred_until_host_commit",
            0x1356_0103,
            Row::HostCommit,
            Verdict::Green,
        )
        .await
    })
}

/// H-S3-r (D97, D119) as ADR 0109 writes it. Not a gate case: it cannot
/// reach its candidate state on this build (#1572). With A's log capped
/// at 4, A serves no chain and no join carry, so J holds no marker, no gap
/// record and no exhausted segment; §2 sends a request only for one of
/// those, so J never asks A and never sees `base_beyond_retention`. Run it
/// by hand (`--run-ignored all`): this test.
#[test]
#[ignore = "ADR 0109 H-S3-r cannot reach its candidate state under §2's request triggers (#1572); a probe, not a gate case"]
fn probe_w3h_1356_s3_r_beyond_retention() -> Result<()> {
    super::super::block_on_paused(async move {
        let receipt = run_row(
            "probe_w3h_1356_s3_r_beyond_retention",
            0x1356_0104,
            Row::Retention,
        )
        .await;
        ensure!(receipt.verdict().is_some(), "no verdict");
        Ok(())
    })
}

/// H-S3-d5 (D80): RED on the base; GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_red_s3_d5_sibling_marker_needs_manual_clear() -> Result<()> {
    super::super::block_on_paused(async move {
        expect_row(
            "w3h_1356_red_s3_d5_sibling_marker_needs_manual_clear",
            0x1356_0105,
            Row::Sibling,
            Verdict::Green,
        )
        .await
    })
}
