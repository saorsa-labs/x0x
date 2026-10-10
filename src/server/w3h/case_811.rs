//! W3-H case for #811 (ADR 0111 C2), on the private-KV path the testnet
//! fixture uses (`tests/e2e_vps_private_kv.py` `run_private`).
//!
//! Nodes: O (owner), P (plain member), A (admin), J (late joiner).
//!
//! O creates a `private_secure` group and seats P. O and P write the wiki
//! store and the web store: an owner key, a member key, and a key that O
//! writes and then deletes. O seats A and promotes A. A then opens each
//! store and writes an admin key. P must hold that key. A mints J's invite.
//! O stops. The fabric takes O offline before shutdown (`RestartMode::Crash`),
//! so no later frame leaves O. J joins through A. P must list J. A then
//! stops the same way. P is the only member still online and still holds
//! both stores. J has not opened either store. J then opens both stores cold.
//!
//! Desired result: within 120 s J reads the owner, member, and admin keys
//! in both stores, and both deleted keys stay absent. That is ADR 0111 C2.
//! The testnet missed the web owner key inside that bound (#811). This case
//! records that result. It does not change production code.
//!
//! A miss is RED only when every store J still lacks has its own state-sync
//! request delivered to P. Counters are deltas from a per-store baseline
//! taken before the cold opens. A frame that is not bound to that store is
//! not delivery. Two controls check the attribution: dropping web requests
//! while wiki succeeds is INFRA, and withholding web history after P has
//! received the web request is RED.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh, put_value};
use super::home::{membership_state, roster};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, Write};
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

const SEED: u64 = 0x0811_0001;
const CASE: &str = "w3h_811_late_joiner_reads_history_from_plain_member";
const CASE_DROP: &str = "w3h_811_control_web_request_dropped_is_infra";
const CASE_WITHHOLD: &str = "w3h_811_control_web_history_withheld_is_red";
const FINAL: &str = "j_reads_full_history_within_120s";
const READ_BUDGET: Duration = Duration::from_secs(120);
const SEAT_BUDGET: Duration = Duration::from_secs(180);

/// What this run does to web's state-sync path after the cold opens.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WebFault {
    /// Both stores sync with no injected fault.
    None,
    /// Drop J→P frames on the web state-sync topic. Wiki is left alone.
    DropRequests,
    /// Drop P→J frames that carry the web store topic, so the history P
    /// publishes in answer never arrives. The request itself is J→P and
    /// is not dropped.
    WithholdHistory,
}

#[derive(Clone, Copy)]
struct StoreSpec {
    name: &'static str,
    owner_key: &'static str,
    owner_value: &'static str,
    member_key: &'static str,
    member_value: &'static str,
    admin_key: &'static str,
    admin_value: &'static str,
    removed_key: &'static str,
}

struct Store {
    spec: StoreSpec,
    id: String,
}

const WIKI: StoreSpec = StoreSpec {
    name: "wiki",
    owner_key: "w3h-811-owner-wiki",
    owner_value: "owner-wiki",
    member_key: "w3h-811-member-wiki",
    member_value: "member-wiki",
    admin_key: "w3h-811-admin-wiki",
    admin_value: "admin-wiki",
    removed_key: "w3h-811-removed-wiki",
};

const WEB: StoreSpec = StoreSpec {
    name: "web",
    owner_key: "w3h-811-owner-web",
    owner_value: "owner-web",
    member_key: "w3h-811-member-web",
    member_value: "member-web",
    admin_key: "w3h-811-admin-web",
    admin_value: "admin-web",
    removed_key: "w3h-811-removed-web",
};

fn path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn store_key_path(store: &str, key: &str) -> String {
    format!("/stores/{}/{}", path_segment(store), path_segment(key))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

async fn holds_value(sim: &Sim, label: &str, store: &str, key: &str, want: &str) -> Result<bool> {
    let (status, body) = sim
        .request(label, Method::GET, &store_key_path(store, key), None)
        .await?;
    if !status.is_success() {
        return Ok(false);
    }
    let Some(encoded) = body["value"].as_str() else {
        return Ok(false);
    };
    let bytes = BASE64
        .decode(encoded)
        .with_context(|| format!("{label} {key}: value is not base64"))?;
    Ok(String::from_utf8(bytes).ok().as_deref() == Some(want))
}

async fn is_absent(sim: &Sim, label: &str, store: &str, key: &str) -> Result<bool> {
    let (status, _) = sim
        .request(label, Method::GET, &store_key_path(store, key), None)
        .await?;
    Ok(status == StatusCode::NOT_FOUND)
}

/// One present key or one deleted key, as J and P each report it.
struct Check {
    label: String,
    j_ok: bool,
    p_ok: bool,
}

async fn history_checks(sim: &Sim, stores: &[Store]) -> Result<Vec<Check>> {
    let mut checks = Vec::with_capacity(stores.len() * 4);
    for store in stores {
        let spec = store.spec;
        for (kind, key, value) in [
            ("owner", spec.owner_key, spec.owner_value),
            ("member", spec.member_key, spec.member_value),
            ("admin", spec.admin_key, spec.admin_value),
        ] {
            checks.push(Check {
                label: format!("{} {kind}", spec.name),
                j_ok: holds_value(sim, "J", &store.id, key, value).await?,
                p_ok: holds_value(sim, "P", &store.id, key, value).await?,
            });
        }
        checks.push(Check {
            label: format!("{} removed", spec.name),
            j_ok: is_absent(sim, "J", &store.id, spec.removed_key).await?,
            p_ok: is_absent(sim, "P", &store.id, spec.removed_key).await?,
        });
    }
    Ok(checks)
}

fn describe_checks(checks: &[Check]) -> String {
    checks
        .iter()
        .map(|check| format!("{} j={} p={}", check.label, check.j_ok, check.p_ok))
        .collect::<Vec<_>>()
        .join("; ")
}

fn is_store(label: &str, name: &str) -> bool {
    label
        .strip_prefix(name)
        .is_some_and(|rest| rest.starts_with(' '))
}

fn store_settled(checks: &[Check], name: &str) -> bool {
    let mine: Vec<_> = checks
        .iter()
        .filter(|check| is_store(&check.label, name))
        .collect();
    !mine.is_empty() && mine.iter().all(|check| check.j_ok)
}

fn store_missing(checks: &[Check], name: &str) -> bool {
    checks
        .iter()
        .any(|check| is_store(&check.label, name) && !check.j_ok)
}

async fn open_named(sim: &Sim, label: &str, group: &str, name: &str) -> Result<String> {
    let (status, store) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": name})),
        )
        .await?;
    ensure!(status.is_success(), "{label} open {name}: {status} {store}");
    Ok(store["id"]
        .as_str()
        .context("store response has no id")?
        .to_string())
}

async fn wait_holds(
    sim: &Sim,
    what: &str,
    label: &str,
    store: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let mut seen = Observations::default();
    let waited = sim
        .until(what, READ_BUDGET, async |s: &Sim| {
            match seen.observe(holds_value(s, label, store, key, value)).await {
                Some(true) => true,
                Some(false) => false,
                None => true,
            }
        })
        .await;
    seen.verify(what)?;
    waited.with_context(|| format!("INFRA: {what}"))
}

async fn wait_absent(sim: &Sim, what: &str, label: &str, store: &str, key: &str) -> Result<()> {
    let mut seen = Observations::default();
    let waited = sim
        .until(what, READ_BUDGET, async |s: &Sim| {
            match seen.observe(is_absent(s, label, store, key)).await {
                Some(true) => true,
                Some(false) => false,
                None => true,
            }
        })
        .await;
    seen.verify(what)?;
    waited.with_context(|| format!("INFRA: {what}"))
}

async fn seed_store(sim: &Sim, group: &str, spec: StoreSpec) -> Result<Store> {
    let id = open_named(sim, "O", group, spec.name).await?;
    let opened = open_named(sim, "P", group, spec.name).await?;
    ensure!(
        opened == id,
        "P opened a different {} store: {opened} != {id}",
        spec.name
    );
    put_value(sim, "O", &id, spec.owner_key, spec.owner_value).await?;
    put_value(sim, "P", &id, spec.member_key, spec.member_value).await?;
    wait_holds(
        sim,
        &format!("P reads O's {} key", spec.name),
        "P",
        &id,
        spec.owner_key,
        spec.owner_value,
    )
    .await?;
    wait_holds(
        sim,
        &format!("O reads P's {} key", spec.name),
        "O",
        &id,
        spec.member_key,
        spec.member_value,
    )
    .await?;
    put_value(sim, "O", &id, spec.removed_key, "gone").await?;
    wait_holds(
        sim,
        &format!("P reads the {} key before O deletes it", spec.name),
        "P",
        &id,
        spec.removed_key,
        "gone",
    )
    .await?;
    let (status, deleted) = sim
        .api(
            "O",
            Method::DELETE,
            &store_key_path(&id, spec.removed_key),
            None,
        )
        .await?;
    ensure!(
        status.is_success(),
        "O delete {}: {status} {deleted}",
        spec.removed_key
    );
    wait_absent(
        sim,
        &format!("P sees the deleted {} key absent", spec.name),
        "P",
        &id,
        spec.removed_key,
    )
    .await?;
    Ok(Store { spec, id })
}

async fn wait_active(sim: &Sim, authority: &str, member: &str, group: &str) -> Result<()> {
    let id = sim.agent_hex(member)?;
    let what = format!("{member} is active on {authority} and locally");
    let mut seen = Observations::default();
    let waited = sim
        .until(&what, SEAT_BUDGET, async |s: &Sim| {
            let Some(listed) = seen.observe(members(s, authority, group)).await else {
                return true;
            };
            let Some(state) = seen.observe(membership_state(s, member, group)).await else {
                return true;
            };
            listed.contains(&id) && state.as_deref() == Some("active")
        })
        .await;
    seen.verify(&what)?;
    waited.with_context(|| format!("INFRA: {what}"))
}

async fn promote_admin(sim: &Sim, group: &str) -> Result<()> {
    let member_hex = sim.agent_hex("A")?;
    let (status, promoted) = sim
        .api(
            "O",
            Method::PATCH,
            &format!("/groups/{group}/members/{member_hex}/role"),
            Some(json!({"role": "admin"})),
        )
        .await?;
    ensure!(
        status.is_success() && promoted["role"] == "admin",
        "promotion: {status} {promoted}"
    );
    for observer in ["A", "P"] {
        let what = format!("{observer} sees A as admin");
        let wanted = member_hex.clone();
        let mut seen = Observations::default();
        let waited = sim
            .until(&what, SEAT_BUDGET, async |s: &Sim| {
                let Some(rows) = seen.observe(roster(s, observer, group)).await else {
                    return true;
                };
                rows.iter()
                    .any(|(agent, role)| agent == &wanted && role == "admin")
            })
            .await;
        seen.verify(&what)?;
        waited.with_context(|| format!("INFRA: {what}"))?;
    }
    Ok(())
}

/// A opens each store after promotion and writes one key. P must hold it
/// before O and A leave, so the history J later reads includes A's record.
async fn seed_admin_history(sim: &Sim, group: &str, stores: &[Store]) -> Result<()> {
    for store in stores {
        let spec = store.spec;
        let opened = open_named(sim, "A", group, spec.name).await?;
        ensure!(
            opened == store.id,
            "A opened a different {} store: {opened} != {}",
            spec.name,
            store.id
        );
        put_value(sim, "A", &store.id, spec.admin_key, spec.admin_value).await?;
        wait_holds(
            sim,
            &format!("P holds A's {} key", spec.name),
            "P",
            &store.id,
            spec.admin_key,
            spec.admin_value,
        )
        .await?;
    }
    Ok(())
}

fn node_offline(sim: &Sim, label: &str) -> Result<bool> {
    Ok(sim.fabric().is_online(&sim.peer(label)?) == Some(false))
}

async fn j_stores_closed(sim: &Sim, stores: &[Store]) -> Result<bool> {
    let (status, body) = sim
        .request("J", Method::GET, "/diagnostics/state-sync", None)
        .await?;
    ensure!(status.is_success(), "J state-sync: {status} {body}");
    let open = &body["stores"];
    Ok(stores.iter().all(|store| open.get(&store.id).is_none()))
}

async fn counter(sim: &Sim, label: &str, store: &str, field: &str) -> Result<u64> {
    let (status, body) = sim
        .request(label, Method::GET, "/diagnostics/state-sync", None)
        .await?;
    ensure!(status.is_success(), "{label} state-sync: {status} {body}");
    Ok(body["stores"][store][field].as_u64().unwrap_or(0))
}

/// State-sync counters for one store. A missing store's request is this
/// store's own `requests_received` or `retained_pages_served` on P, never
/// another store's counters and never an undecoded frame.
#[derive(Clone, Copy)]
struct StoreSync {
    name: &'static str,
    j_requests: u64,
    p_received: u64,
    p_answered: u64,
    p_served: u64,
    j_merges: u64,
}

async fn store_sync(sim: &Sim, store: &Store) -> Result<StoreSync> {
    Ok(StoreSync {
        name: store.spec.name,
        j_requests: counter(sim, "J", &store.id, "requests_sent").await?,
        p_received: counter(sim, "P", &store.id, "requests_received").await?,
        p_answered: counter(sim, "P", &store.id, "requests_answered").await?,
        p_served: counter(sim, "P", &store.id, "retained_pages_served").await?,
        j_merges: counter(sim, "J", &store.id, "incoming_record_merges").await?,
    })
}

async fn sync_rows(sim: &Sim, stores: &[Store]) -> Result<Vec<StoreSync>> {
    let mut rows = Vec::with_capacity(stores.len());
    for store in stores {
        rows.push(store_sync(sim, store).await?);
    }
    Ok(rows)
}

fn deltas(after: &[StoreSync], before: &[StoreSync]) -> Vec<StoreSync> {
    after
        .iter()
        .map(|row| {
            let prior = before.iter().find(|earlier| earlier.name == row.name);
            let sub = |now: u64, pick: fn(&StoreSync) -> u64| {
                now.saturating_sub(prior.map(pick).unwrap_or(0))
            };
            StoreSync {
                name: row.name,
                j_requests: sub(row.j_requests, |earlier| earlier.j_requests),
                p_received: sub(row.p_received, |earlier| earlier.p_received),
                p_answered: sub(row.p_answered, |earlier| earlier.p_answered),
                p_served: sub(row.p_served, |earlier| earlier.p_served),
                j_merges: sub(row.j_merges, |earlier| earlier.j_merges),
            }
        })
        .collect()
}

/// P accepted this store's request. `requests_sent` is J's local send, not
/// delivery. `incoming_record_merges` means history arrived, which is a
/// separate question from whether the request reached P.
fn request_reached(row: &StoreSync) -> bool {
    row.p_received > 0 || row.p_served > 0
}

fn describe_sync(rows: &[StoreSync]) -> String {
    rows.iter()
        .map(|row| {
            format!(
                "{}: J sent={} merges={} P received={} answered={} served={}",
                row.name,
                row.j_requests,
                row.j_merges,
                row.p_received,
                row.p_answered,
                row.p_served
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Bind a fault to one store by the topic string a signed pubsub frame
/// carries. The sealed state-sync body is not decoded, and a frame that
/// does not carry the topic is not treated as that store's request.
fn install_web_fault(sim: &Sim, fault: WebFault, web_topic: &str) -> Result<()> {
    let joiner = sim.peer("J")?.0;
    let holder = sim.peer("P")?.0;
    match fault {
        WebFault::None => Ok(()),
        WebFault::DropRequests => {
            let side = format!("{web_topic}/state-sync");
            sim.fabric().add_rule(move |write: &Write| {
                if write.lane.src == joiner
                    && write.lane.dst == holder
                    && contains(&write.bytes, side.as_bytes())
                {
                    Fault::Drop
                } else {
                    Fault::Pass
                }
            });
            Ok(())
        }
        WebFault::WithholdHistory => {
            let topic = web_topic.to_string();
            sim.fabric().add_rule(move |write: &Write| {
                if write.lane.src == holder
                    && write.lane.dst == joiner
                    && contains(&write.bytes, topic.as_bytes())
                {
                    Fault::Drop
                } else {
                    Fault::Pass
                }
            });
            Ok(())
        }
    }
}

fn missing_requests_delivered(checks: &[Check], fresh: &[StoreSync]) -> bool {
    let missing: Vec<_> = fresh
        .iter()
        .filter(|row| store_missing(checks, row.name))
        .collect();
    !missing.is_empty() && missing.iter().all(|row| request_reached(row))
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt, fault: WebFault) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, &["O", "P", "A", "J"]).await?;
    let group = create_group(sim, "O").await?;
    let link = invite(sim, "O", &group).await?;
    join(sim, "P", &link).await?;
    wait_active(sim, "O", "P", &group).await?;
    let wiki = seed_store(sim, &group, WIKI).await?;
    let web = seed_store(sim, &group, WEB).await?;
    let stores = [wiki, web];
    let link = invite(sim, "O", &group).await?;
    join(sim, "A", &link).await?;
    wait_active(sim, "O", "A", &group).await?;
    promote_admin(sim, &group).await?;
    seed_admin_history(sim, &group, &stores).await?;
    let late_invite = invite(sim, "A", &group).await?;

    sim.stop("O", RestartMode::Crash).await?;
    join(sim, "J", &late_invite).await?;
    wait_active(sim, "A", "J", &group).await?;
    wait_active(sim, "P", "J", &group).await?;
    sim.stop("A", RestartMode::Crash).await?;

    let p_before = history_checks(sim, &stores).await?;
    let p_holds = p_before.iter().all(|check| check.p_ok);
    let offline = node_offline(sim, "O")? && node_offline(sim, "A")?;
    let closed = j_stores_closed(sim, &stores).await?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "p_holds_o_and_a_history",
        p_holds,
        describe_checks(&p_before),
        at(sim),
    );
    receipt.evidence(
        "o_and_a_offline",
        offline,
        format!(
            "O online={:?} A online={:?}",
            sim.fabric().is_online(&sim.peer("O")?),
            sim.fabric().is_online(&sim.peer("A")?),
        ),
        at(sim),
    );
    receipt.evidence(
        "j_active_and_has_not_opened_the_stores",
        closed && membership_state(sim, "J", &group).await?.as_deref() == Some("active"),
        format!("stores closed={closed}"),
        at(sim),
    );

    // The fault is in force before either cold open, and it stays in force
    // for the whole 120 s bound. It selects by topic, so wiki frames pass.
    let web_topic = stores
        .iter()
        .find(|store| store.spec.name == "web")
        .context("web store")?
        .id
        .clone();
    install_web_fault(sim, fault, &web_topic)?;

    // One 120 s bound covers both cold opens and the history reads. Opening
    // a store starts its sync, so the wiki open must count against the same
    // budget as the web open and the later poll.
    let bound_start = sim.fabric().now();
    let baseline = sync_rows(sim, &stores).await?;
    for store in &stores {
        let opened = open_named(sim, "J", &group, store.spec.name).await?;
        ensure!(
            opened == store.id,
            "J opened a different {} store: {opened} != {}",
            store.spec.name,
            store.id
        );
    }
    let elapsed = sim.fabric().now().saturating_sub(bound_start);
    let left = READ_BUDGET.saturating_sub(elapsed);
    let mut seen = Observations::default();
    let waited = if left.is_zero() {
        Err(anyhow::Error::new(BudgetExceeded {
            barrier: "J reads the full history from P".to_string(),
            budget: left,
        }))
    } else {
        let baseline = baseline.clone();
        sim.until("J reads the full history from P", left, async |s: &Sim| {
            let Some(checks) = seen.observe(history_checks(s, &stores)).await else {
                return true;
            };
            if checks.iter().all(|check| check.j_ok) {
                return true;
            }
            // Once wiki has arrived, the web request's fate is what the
            // controls exist to show. Keep polling until that fate is
            // visible, then hold the rest of the bound in one sleep so
            // a late page would still count.
            if fault == WebFault::None || !store_settled(&checks, "wiki") {
                return false;
            }
            let Some(now) = seen.observe(sync_rows(s, &stores)).await else {
                return true;
            };
            let fresh = deltas(&now, &baseline);
            let reached = fresh
                .iter()
                .any(|row| row.name == "web" && request_reached(row));
            match fault {
                WebFault::DropRequests => !reached,
                WebFault::WithholdHistory => reached,
                WebFault::None => false,
            }
        })
        .await
    };
    seen.verify("J reads the full history from P")?;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    let mid = history_checks(sim, &stores).await?;
    let elapsed = sim.fabric().now().saturating_sub(bound_start);
    let rest = READ_BUDGET.saturating_sub(elapsed);
    if !mid.iter().all(|check| check.j_ok) && !rest.is_zero() {
        sim.within(
            "hold the remainder of the 120s history bound",
            rest.saturating_add(Duration::from_secs(1)),
            async { tokio::time::sleep(rest).await },
        )
        .await?;
    }
    let checks = history_checks(sim, &stores).await?;
    let passed = checks.iter().all(|check| check.j_ok);
    let fresh = deltas(&sync_rows(sim, &stores).await?, &baseline);
    // Setup traffic is in `baseline`. A miss is RED only when each store J
    // still lacks had its own request reach P. Wiki's counters do not
    // deliver the web request. A pass still needs post-open activity on
    // every store, so an earlier exchange cannot satisfy the request stage.
    let delivered = if passed {
        fresh
            .iter()
            .all(|row| request_reached(row) || row.j_merges > 0)
    } else {
        missing_requests_delivered(&checks, &fresh)
    };
    receipt.request_delivered(
        "j_history_request_reached_p",
        delivered,
        format!("since J's open: {}", describe_sync(&fresh)),
        at(sim),
    );
    if !passed {
        let holder_still_has_every_miss = checks.iter().all(|check| check.j_ok || check.p_ok)
            && checks.iter().any(|check| !check.j_ok);
        let displaced = sim.logs_containing(&["displacing an idle retained image"]);
        receipt.cause(
            "at 120s J lacks a history key that P still holds",
            Some(format!(
                "{}; retained-image displacements={}",
                describe_checks(&checks),
                displaced.len()
            )),
            holder_still_has_every_miss,
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64, fault: WebFault) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "O and A leave the fabric before shutdown (RestartMode::Crash). \
         Sim delivery has no QUIC flow control. State-sync bodies are sealed; \
         delivery is the per-store requests_received or retained_pages_served \
         delta on P since the cold open.",
    );
    match Sim::start(case, seed, &["O", "P", "A", "J"]).await {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt, fault).await {
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

fn stage<'a>(receipt: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    receipt["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|stage| stage["stage"] == name))
}

fn sync_field(detail: &str, store: &str, field: &str) -> Result<u64> {
    let prefix = format!("{store}:");
    let segment = detail
        .split(" | ")
        .find(|part| part.starts_with(&prefix))
        .with_context(|| format!("no {store} segment in {detail}"))?;
    let needle = format!("{field}=");
    let token = segment
        .split_whitespace()
        .find(|token| token.starts_with(&needle))
        .with_context(|| format!("no {field} in {segment}"))?;
    token[needle.len()..]
        .parse()
        .with_context(|| format!("counter {token}"))
}

/// The controls must reach the implicated state: evidence holds, there is
/// no harness error, wiki arrived, and web's present keys did not.
fn assert_control(receipt: &Receipt, expected: Verdict, web_request_delivered: bool) -> Result<()> {
    ensure!(
        receipt.verdict() == Some(expected),
        "verdict {:?}, expected {expected:?}",
        receipt.verdict()
    );
    let value = serde_json::to_value(receipt).context("receipt json")?;
    ensure!(stage(&value, "infra").is_none(), "harness error: {value}");
    ensure!(
        stage(&value, "setup_done").is_some(),
        "setup did not finish"
    );
    let evidence = value["stages"]
        .as_array()
        .context("stages")?
        .iter()
        .filter(|stage| stage["stage"] == "evidence")
        .collect::<Vec<_>>();
    ensure!(
        !evidence.is_empty() && evidence.iter().all(|stage| stage["ok"] == true),
        "evidence: {evidence:?}"
    );
    let request = stage(&value, "request_delivered").context("no request stage")?;
    ensure!(
        request["ok"] == web_request_delivered,
        "request_delivered: {request}"
    );
    let final_stage = stage(&value, "final").context("no final")?;
    ensure!(
        final_stage["passed"] == false,
        "final passed: {final_stage}"
    );
    let cause = stage(&value, "cause").context("no cause")?;
    ensure!(cause["ok"] == true, "cause: {cause}");
    let observed = cause["observed"].as_str().unwrap_or("");
    for label in [
        "wiki owner j=true",
        "wiki admin j=true",
        "web owner j=false",
        "web admin j=false",
    ] {
        ensure!(
            observed.contains(label),
            "observed missing {label}: {observed}"
        );
    }
    let detail = request["detail"].as_str().unwrap_or("");
    let web_received = sync_field(detail, "web", "received")?;
    let web_served = sync_field(detail, "web", "served")?;
    if web_request_delivered {
        ensure!(
            web_received > 0 || web_served > 0,
            "web request was not proven: {detail}"
        );
        ensure!(
            sync_field(detail, "web", "merges")? == 0,
            "withheld web history still merged: {detail}"
        );
    } else {
        ensure!(
            web_received == 0 && web_served == 0,
            "dropped web request still reached P: {detail}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_811_late_joiner_reads_history_from_plain_member() -> Result<()> {
    let receipt = run(CASE, SEED, WebFault::None).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{CASE} verdict {:?}, expected GREEN",
        receipt.verdict()
    );
    Ok(())
}

/// Wiki syncs. Web's state-sync requests are dropped before they reach P.
/// J lacks web keys P holds, but the missing store's request was not
/// delivered, so the receipt stays INFRA.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_811_control_web_request_dropped_is_infra() -> Result<()> {
    let receipt = run(CASE_DROP, 0x0811_0002, WebFault::DropRequests).await;
    assert_control(&receipt, Verdict::Infra, false)
}

/// The web request reaches P (`requests_received` moves). P's web history
/// frames toward J are dropped, so J still lacks web keys P holds. That is
/// RED. Wiki is not faulted and must arrive.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_811_control_web_history_withheld_is_red() -> Result<()> {
    let receipt = run(CASE_WITHHOLD, 0x0811_0003, WebFault::WithholdHistory).await;
    assert_control(&receipt, Verdict::Red, true)
}
