//! W3-H case for #811 (ADR 0111 C2), on the private-KV path the testnet
//! fixture uses (`tests/e2e_vps_private_kv.py` `run_private`).
//!
//! Nodes: O (owner), P (plain member), A (admin), J (late joiner).
//!
//! O creates a `private_secure` group and seats P. O and P write the wiki
//! store and the web store: an owner key, a member key, and a key that O
//! writes and then deletes. O seats A and promotes A. A mints J's invite.
//! O stops. The fabric takes O offline before shutdown (`RestartMode::Crash`),
//! so no later frame leaves O. J joins through A. P must list J. A then
//! stops the same way. P is the only member still online and still holds
//! both stores. J has not opened either store. J then opens both stores cold.
//!
//! Desired result: within 120 s J reads both owner keys and both member
//! keys, and both deleted keys stay absent. That is ADR 0111 C2. The
//! testnet missed the web owner key inside that bound (#811). This case
//! records that result. It does not change production code.

#![cfg(test)]

use super::control::{create_group, invite, join, members, mesh, put_value};
use super::home::{membership_state, roster};
use super::receipt::{Receipt, Verdict};
use super::*;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

const SEED: u64 = 0x0811_0001;
const CASE: &str = "w3h_811_late_joiner_reads_history_from_plain_member";
const FINAL: &str = "j_reads_full_history_within_120s";
const READ_BUDGET: Duration = Duration::from_secs(120);
const SEAT_BUDGET: Duration = Duration::from_secs(180);

/// The verdict this case must keep. C2's desired result is GREEN: J reads
/// the history from P. A RED receipt means the #811 miss reproduced.
const EXPECTED: Verdict = Verdict::Green;

#[derive(Clone, Copy)]
struct StoreSpec {
    name: &'static str,
    owner_key: &'static str,
    owner_value: &'static str,
    member_key: &'static str,
    member_value: &'static str,
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
    removed_key: "w3h-811-removed-wiki",
};

const WEB: StoreSpec = StoreSpec {
    name: "web",
    owner_key: "w3h-811-owner-web",
    owner_value: "owner-web",
    member_key: "w3h-811-member-web",
    member_value: "member-web",
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
    let mut checks = Vec::with_capacity(stores.len() * 3);
    for store in stores {
        let spec = store.spec;
        for (kind, key, value) in [
            ("owner", spec.owner_key, spec.owner_value),
            ("member", spec.member_key, spec.member_value),
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

async fn sum_counter(sim: &Sim, label: &str, stores: &[Store], field: &str) -> Result<u64> {
    let mut total = 0;
    for store in stores {
        total += counter(sim, label, &store.id, field).await?;
    }
    Ok(total)
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
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
        "p_holds_both_stores",
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

    for store in &stores {
        let opened = open_named(sim, "J", &group, store.spec.name).await?;
        ensure!(
            opened == store.id,
            "J opened a different {} store: {opened} != {}",
            store.spec.name,
            store.id
        );
    }
    let open_mark = sim
        .fabric()
        .mark_indexed("J opens wiki and web with O and A offline");
    let mut seen = Observations::default();
    let waited = sim
        .until(
            "J reads the full history from P",
            READ_BUDGET,
            async |s: &Sim| match seen.observe(history_checks(s, &stores)).await {
                Some(checks) => checks.iter().all(|check| check.j_ok),
                None => true,
            },
        )
        .await;
    seen.verify("J reads the full history from P")?;
    let passed = match waited {
        Ok(()) => true,
        Err(error) if expired(&error) => false,
        Err(error) => return Err(error),
    };
    let checks = history_checks(sim, &stores).await?;
    let j_requests = sum_counter(sim, "J", &stores, "requests_sent").await?;
    let p_received = sum_counter(sim, "P", &stores, "requests_received").await?;
    let p_answered = sum_counter(sim, "P", &stores, "requests_answered").await?;
    let p_served = sum_counter(sim, "P", &stores, "retained_pages_served").await?;
    let j_merges = sum_counter(sim, "J", &stores, "incoming_record_merges").await?;
    let frames = sim
        .fabric()
        .delivered_writes_after(&sim.peer("J")?, &sim.peer("P")?, open_mark);
    let delivered = passed || p_received > 0 || p_served > 0 || j_merges > 0 || !frames.is_empty();
    receipt.request_delivered(
        "j_history_request_reached_p",
        delivered,
        format!(
            "J requests_sent={j_requests} incoming_record_merges={j_merges}; \
             P requests_received={p_received} requests_answered={p_answered} \
             retained_pages_served={p_served}; {} frames J→P after trace #{open_mark}",
            frames.len()
        ),
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

async fn run() -> Receipt {
    let mut receipt = Receipt::new(CASE, SEED);
    receipt.note(
        "O and A leave the fabric before shutdown (RestartMode::Crash). \
         Sim delivery has no QUIC flow control.",
    );
    match Sim::start(CASE, SEED, &["O", "P", "A", "J"]).await {
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

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_811_late_joiner_reads_history_from_plain_member() -> Result<()> {
    let receipt = run().await;
    ensure!(
        receipt.verdict() == Some(EXPECTED),
        "{CASE} verdict {:?}, expected {EXPECTED:?}",
        receipt.verdict()
    );
    Ok(())
}
