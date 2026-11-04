//! W3-H case for #1360 (ADR 0113 H7-1, #824): a device with a copied
//! owner key does not mint a second Home. O holds Home H. O certifies,
//! trusts and enrolls B. With O~B partitioned, B starts with the copied
//! `user.key` and a sync store that already enrolls O and B, then trusts
//! O. C (never started) gives the seat's third agent id. The block lasts
//! 200 s from the end of B's setup; at 10 s the case calls `POST /home`
//! on B, at 195 s `POST /home/seat` for C. After the lift O seats B and B
//! redeems in Home mode.
//!
//! GREEN (§2, §3, §6): B never holds a Home-shaped group other than H.
//! For the whole block `GET /home` is `binding_pending`, `waiting_for:
//! owner_sync_session`, naming O; `POST /home` is 409 `binding_pending`;
//! the seat is 409 `home_unbound`. Then B is `bound` to H, `seated`.
//! RED (`main`): provisioning waits `(rank + 1) × 90 s`, then provisions
//! locally, and the seat returns 200 with that group's id ([`CAUSE`]).
//!
//! Differences from the ADR row: (1) RED accepts a duplicate up to the
//! end of the 200 s block, not only within 180 s (`main`'s latest
//! deadline is 180 s, so the cause is the same). (2) B dials O once after
//! the lift; the harness has no redial. (3) The `bound.group_id` /
//! `bound.source` shape is a guess from §6. (4) The test name does not
//! match the ADR's proposed `test(w3h_s7_)` selector (repo convention).

#![cfg(test)]

use super::home::HomeIds;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::identity::{MachineId, UserId, UserKeypair};
use anyhow::ensure;
use base64::Engine as _;
use serde_json::{json, Value};

const LABELS: &[&str] = &["O", "B", "C"];
const SEED: u64 = 0x1360_0001;
/// ADR 0113 H7-1: "Drop every O↔B session for 200 s".
const BLOCK: Duration = Duration::from_secs(200);
/// When the case calls `POST /home` on B, from B's start.
const CREATE_AT: Duration = Duration::from_secs(10);
/// When the case calls `POST /home/seat` on B, from B's start: after
/// `main`'s latest deadline (180 s) and before the block lifts.
const SEAT_AT: Duration = Duration::from_secs(195);
/// Budget for the post-block owner sync, seat and redemption.
const AFTER: Duration = Duration::from_secs(180);
/// Extra wait budget so that a wait ends at its own deadline check, never
/// in the middle of a read.
const SLACK: Duration = Duration::from_secs(30);
/// GET /home on B once per this many 100 ms polls.
const HOME_EVERY: u32 = 10;
const FINAL: &str = "b_never_holds_a_second_home_and_binds_to_h_as_seated";
const CAUSE: &str = "B provisions a Home-shaped group other than H during the O~B block, \
                     and POST /home/seat on B returns 200 with that group_id";

/// What the case saw on B.
#[derive(Debug, Default)]
struct Watch {
    /// First Home-shaped group on B other than H, with its virtual time.
    duplicate: Option<(String, u128)>,
    /// Every distinct `GET /home` state seen on B during the block.
    block_states: Vec<String>,
    /// A `GET /home` body during the block that had the typed settle wait.
    typed_wait: Option<Value>,
    /// A `GET /home` sample during the block without the typed wait (the
    /// ADR says the wait holds for the whole block).
    untyped: bool,
    /// Last `GET /home` body during the block.
    last_block_home: Value,
}

fn owner_of(sim: &Sim, label: &str) -> Result<UserId> {
    sim.state(label)?
        .agent
        .identity()
        .user_keypair()
        .map(|keypair| keypair.user_id())
        .with_context(|| format!("{label} has no owner key"))
}

/// The Home-shaped groups `label` holds (exact Home policy for `owner`),
/// as (key, stable id).
async fn home_shaped(sim: &Sim, label: &str, owner: &UserId) -> Result<Vec<(String, String)>> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    Ok(groups
        .iter()
        .filter(|(_, info)| crate::server::routes::home::is_home_policy(&info.policy, owner))
        .map(|(key, info)| (key.clone(), info.stable_group_id().to_string()))
        .collect())
}

/// The first of `groups` that is not `gid` (by key or stable id).
fn other_than(groups: Vec<(String, String)>, gid: &str) -> Option<String> {
    groups
        .into_iter()
        .find(|(key, stable)| key != gid && stable != gid)
        .map(|(_, stable)| stable)
}

/// The fixed facts the watch compares against.
struct Ctx {
    owner: UserId,
    gid: String,
    o_machine: String,
}

async fn get_home(sim: &Sim, label: &str) -> Result<Value> {
    let (status, body) = sim.request(label, Method::GET, "/home", None).await?;
    Ok(json!({"status": status.as_u16(), "body": body}))
}

/// ADR 0113 §2 settle rule: `binding_pending`, `waiting_for:
/// owner_sync_session`, naming O's machine.
fn is_typed_settle_wait(home: &Value, o_machine: &str) -> bool {
    let body = &home["body"];
    body["state"] == "binding_pending"
        && body["waiting_for"] == "owner_sync_session"
        && body.to_string().contains(o_machine)
}

/// ADR 0113 §6: the binding is bound to `gid` with `source: seated`.
fn is_seated_binding(home: &Value, gid: &str) -> bool {
    let bound = &home["body"]["bound"];
    bound["group_id"] == gid && bound["source"] == "seated"
}

/// A 409 whose body names `reason` (as `reason`, `state` or `error`).
fn is_conflict(status: StatusCode, body: &Value, reason: &str) -> bool {
    status == StatusCode::CONFLICT
        && [&body["reason"], &body["state"], &body["error"]]
            .iter()
            .any(|field| field.as_str() == Some(reason))
}

/// The two ways O refuses the seat when B's duplicate won the election:
/// the seat helper's wait for O to serve H expires, or a 409
/// `adoption_pending`. Any other error (a hung seat call too) is INFRA.
fn seat_refused(error: &anyhow::Error) -> bool {
    let serve_wait = error
        .downcast_ref::<BudgetExceeded>()
        .is_some_and(|budget| budget.barrier == "O serves the canonical Home");
    serve_wait || format!("{error:#}").contains("\"reason\":\"adoption_pending\"")
}

/// Observe B until `until` (virtual time since the fabric origin).
async fn watch_b(
    sim: &Sim,
    what: &str,
    until: Duration,
    ctx: &Ctx,
    watch: &mut Watch,
) -> Result<()> {
    if sim.fabric().now() >= until {
        return Ok(());
    }
    let budget = until.saturating_sub(sim.fabric().now()) + SLACK;
    let mut seen = Observations::default();
    let mut polls: u32 = 0;
    sim.until(what, budget, async |s: &Sim| {
        let Some(groups) = seen.observe(home_shaped(s, "B", &ctx.owner)).await else {
            return true;
        };
        if let Some(other) = other_than(groups, &ctx.gid) {
            watch
                .duplicate
                .get_or_insert((other, s.fabric().now().as_micros()));
        }
        if polls.is_multiple_of(HOME_EVERY) {
            let Some(home) = seen.observe(get_home(s, "B")).await else {
                return true;
            };
            let state = home["body"]["state"].as_str().unwrap_or("-").to_string();
            if !watch.block_states.contains(&state) {
                watch.block_states.push(state);
            }
            if !is_typed_settle_wait(&home, &ctx.o_machine) {
                watch.untyped = true;
            } else if watch.typed_wait.is_none() {
                watch.typed_wait = Some(home.clone());
            }
            watch.last_block_home = home;
        }
        polls = polls.wrapping_add(1);
        s.fabric().now() >= until
    })
    .await?;
    seen.verify(what)
}

async fn ok_api(sim: &Sim, label: &str, method: Method, path: &str, body: Value) -> Result<Value> {
    let (status, response) = sim.api(label, method, path, Some(body)).await?;
    ensure!(
        status.is_success() && response["ok"] != false,
        "{label} {path}: {status} {response}"
    );
    Ok(response)
}

/// Write B's owner-sync store before B starts, so that B's daemon loads
/// with O and B already enrolled (the H7-1 precondition).
async fn enroll_before_start(sim: &Sim, owner: &UserKeypair, b: MachineId) -> Result<()> {
    let store = crate::owner_sync::OwnerSyncStore::load(&sim.root.path().join("B").join("data"))
        .await
        .map_err(|error| anyhow!("B sync store: {error}"))?;
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let o = MachineId(sim.peer("O")?.0);
    for machine in [o, b] {
        let enrollment = crate::owner_sync::OwnerEnrollment::sign(machine, owner, now_ms, None)?;
        store
            .enroll(enrollment)
            .await
            .map_err(|error| anyhow!("enroll before start: {error}"))?;
    }
    Ok(())
}

/// Prepare and start B with the copied owner key, partitioned from O.
async fn start_copied_key_device(sim: &mut Sim, owner: &UserKeypair) -> Result<()> {
    let (machine, agent) = sim.take_keys("B")?;
    let issued = ok_api(
        sim,
        "O",
        Method::POST,
        "/owner/agents/issue",
        json!({
            "agent_public_key": hex::encode(agent.public_key().as_bytes()),
            "mode": "acp",
            "label": "w3h-B",
        }),
    )
    .await?;
    let cert = base64::engine::general_purpose::STANDARD.decode(
        issued["certificate"]["storage_b64"]
            .as_str()
            .context("certificate.storage_b64")?,
    )?;
    ok_api(
        sim,
        "O",
        Method::POST,
        "/contacts/trust",
        json!({"agent_id": hex::encode(agent.agent_id().as_bytes()), "level": "trusted"}),
    )
    .await?;
    ok_api(
        sim,
        "O",
        Method::POST,
        "/sync/devices/enroll",
        json!({"machine_id": hex::encode(machine.machine_id().0)}),
    )
    .await?;
    let b_peer = ant_quic::PeerId(machine.machine_id().0);
    sim.fabric()
        .mark("fault O~B partitioned (ADR 0113 H7-1 block)");
    sim.fabric().set_partitioned(&sim.peer("O")?, &b_peer, true);
    enroll_before_start(sim, owner, machine.machine_id()).await?;
    sim.start_node_with(
        "B",
        Provision {
            machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
            agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
            user_key: Some(crate::storage::serialize_user_keypair(owner)?),
            agent_cert: Some(cert),
        },
    )
    .await?;
    let o_agent = sim.agent_hex("O")?;
    let trust = json!({"agent_id": o_agent, "level": "trusted"});
    ok_api(sim, "B", Method::POST, "/contacts/trust", trust).await?;
    Ok(())
}

/// B dials O once the block lifts (its startup dial fell inside it).
async fn b_dials_o(sim: &Sim) -> Result<()> {
    let network = sim
        .state("B")?
        .agent
        .network()
        .cloned()
        .context("B has no network")?;
    let addr = super::sim_addr(sim.node_index("O")?)?;
    sim.within("B dials O", secs(10), network.connect_addr(addr))
        .await?
        .map_err(|error| anyhow!("B could not dial O: {error}"))?;
    Ok(())
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    // Before any daemon starts, like the node keys (`Sim::empty`).
    let owner = UserKeypair::generate()?;
    let (_, third) = sim.take_keys("C")?;
    let third_hex = hex::encode(third.agent_id().as_bytes());
    let home: HomeIds = sim.start_owner_device("O", &owner).await?;
    let gid = home.gid.clone();
    let owner_id = owner.user_id();
    let ctx = Ctx {
        owner: owner_id,
        gid: gid.clone(),
        o_machine: sim.machine_hex("O")?,
    };

    start_copied_key_device(sim, &owner).await?;
    let started = sim.fabric().now();
    let block_mark = sim.fabric().mark_indexed("case: B started, O~B blocked");
    let b_start = sim
        .at_instant(
            "B's Home-shaped groups at start",
            home_shaped(sim, "B", &owner_id),
        )
        .await??;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "o_holds_h_and_b_starts_with_no_home_shaped_group",
        b_start.is_empty() && !gid.is_empty(),
        format!("H={gid}; B at start {b_start:?}"),
        at(sim),
    );
    receipt.evidence(
        "b_holds_the_copied_owner_key",
        owner_of(sim, "B")? == owner_id && owner_of(sim, "O")? == owner_id,
        format!("owner {}", hex::encode(owner_id.as_bytes())),
        at(sim),
    );

    let mut watch = Watch::default();
    watch_b(
        sim,
        "B before POST /home",
        started + CREATE_AT,
        &ctx,
        &mut watch,
    )
    .await?;
    let (create_status, create_body) = sim.api("B", Method::POST, "/home", Some(json!({}))).await?;
    watch_b(
        sim,
        "B in the O~B block",
        started + SEAT_AT,
        &ctx,
        &mut watch,
    )
    .await?;
    let seat = json!({"agent_id": third_hex});
    let (seat_status, seat_body) = sim.api("B", Method::POST, "/home/seat", Some(seat)).await?;
    watch_b(
        sim,
        "B to the block lift",
        started + BLOCK,
        &ctx,
        &mut watch,
    )
    .await?;
    let b_peer = sim.peer("B")?;
    let o_peer = sim.peer("O")?;
    let frames = |from, to, mark| sim.fabric().delivered_writes_after(from, to, mark).len();
    let blocked = frames(&o_peer, &b_peer, block_mark) + frames(&b_peer, &o_peer, block_mark);
    receipt.evidence(
        "no_o_b_frame_delivered_during_the_block",
        blocked == 0,
        format!("O<->B frames delivered during the block: {blocked}"),
        at(sim),
    );
    sim.fabric().set_partitioned(&o_peer, &b_peer, false);
    let lift_mark = sim.fabric().mark_indexed("fault O~B healed");
    b_dials_o(sim).await?;

    // O seats B, B redeems. On `main` B's duplicate can win the election
    // and O refuses (see `seat_refused`): a note, not INFRA.
    let invite = match sim.home_seat("O", "B", &home).await {
        Ok(invite) => invite,
        Err(error) if watch.duplicate.is_some() && seat_refused(&error) => {
            receipt.note(format!("O seat for B after the lift: {error:#}"));
            String::new()
        }
        Err(error) => return Err(error),
    };
    let (join_status, join_body) = if invite.is_empty() {
        (StatusCode::PRECONDITION_FAILED, json!("not attempted"))
    } else {
        let join = json!({
            "invite": invite,
            "mode": "home",
            "expected_owner_user_id": home.owner_user_id,
        });
        sim.api("B", Method::POST, "/groups/join", Some(join))
            .await?
    };
    let mut seated: Option<Value> = None;
    let mut last_after = Value::Null;
    let mut seen = Observations::default();
    // Once B holds a duplicate the row cannot pass (`main`'s end state), so
    // the wait stops after that read.
    let deadline = sim.fabric().now() + AFTER;
    sim.until("B binds to H as seated", AFTER + SLACK, async |s: &Sim| {
        let Some(groups) = seen.observe(home_shaped(s, "B", &ctx.owner)).await else {
            return true;
        };
        if let Some(other) = other_than(groups, &ctx.gid) {
            watch
                .duplicate
                .get_or_insert((other, s.fabric().now().as_micros()));
        }
        let Some(home) = seen.observe(get_home(s, "B")).await else {
            return true;
        };
        last_after = home.clone();
        if is_seated_binding(&home, &gid) {
            seated = Some(home);
            return true;
        }
        watch.duplicate.is_some() || s.fabric().now() >= deadline
    })
    .await?;
    seen.verify("B binds to H as seated")?;
    let (to_b, to_o) = (
        frames(&o_peer, &b_peer, lift_mark),
        frames(&b_peer, &o_peer, lift_mark),
    );
    receipt.request_delivered(
        "o_b_sessions_resume_after_the_block",
        to_b > 0 && to_o > 0,
        format!("frames after the lift: O->B={to_b} B->O={to_o}"),
        at(sim),
    );

    let create_typed = is_conflict(create_status, &create_body, "binding_pending");
    let seat_typed = is_conflict(seat_status, &seat_body, "home_unbound");
    // The invite string is long and says nothing the receipt needs.
    let mut seat_shown = seat_body.clone();
    if let Some(fields) = seat_shown.as_object_mut() {
        fields.remove("invite");
    }
    receipt.note(format!(
        "B GET /home states during the block: {:?}; last {}; POST /home -> {create_status} \
         {create_body}; POST /home/seat -> {seat_status} {seat_shown}; join -> {join_status} \
         {join_body}; last GET /home after the lift: {last_after}",
        watch.block_states, watch.last_block_home
    ));
    let passed = watch.duplicate.is_none()
        && watch.typed_wait.is_some()
        && !watch.untyped
        && create_typed
        && seat_typed
        && seated.is_some();
    if !passed {
        let seat_gid = seat_body["group_id"].as_str().unwrap_or_default();
        let duplicate = watch.duplicate.as_ref();
        let observed = duplicate.is_some_and(|(dup, at_us)| {
            *at_us <= (started + BLOCK).as_micros()
                && seat_status == StatusCode::OK
                && seat_gid == dup
                && seat_gid != gid
        });
        receipt.cause(
            CAUSE,
            Some(format!(
                "duplicate {duplicate:?} (block from {} us to {} us); seat {seat_status} \
                 group_id={seat_gid:?}; H={gid}",
                started.as_micros(),
                (started + BLOCK).as_micros()
            )),
            observed,
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str) -> Receipt {
    let mut receipt = Receipt::new(case, SEED);
    receipt.note(
        "ADR 0113 H7-1 (#824). The O~B block is a fabric partition set before B \
         starts; B has no other peer and dials O once when it lifts.",
    );
    match Sim::empty(case, SEED, LABELS) {
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

/// ADR 0113 H7-1 red baseline: RED on `main` (#824: B provisions a
/// second Home after its owner-sync deadline). The ADR 0113 §2/§3 slice
/// flips the expectation to GREEN.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
#[cfg_attr(
    target_os = "linux",
    ignore = "#1559: needs the W3-H entropy shim (nextest profile w3h / w3h-gate \
              --run-ignored all); plain suites run unseeded entropy, which is not an \
              observation"
)]
fn w3h_1360_red_s7_h7_1_copied_key_creates_no_duplicate() -> Result<()> {
    super::block_on_paused(async move {
        let case = "w3h_1360_red_s7_h7_1_copied_key_creates_no_duplicate";
        let receipt = run(case).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Red) && receipt.named_causes() == [CAUSE],
            "{case}: expected RED with the #824 cause, got {:?} {:?}",
            receipt.verdict(),
            receipt.named_causes()
        );
        Ok(())
    })
}
