//! W3-H case `w3h_1161_card_import_invite` (#1161 / A08 liveness).
//!
//! Nodes: A (owner) and J (joiner). Public HTTP only.
//!
//! 1. A creates a `public_request_secure` group (discoverable card).
//! 2. J imports A's signed group card (`POST /groups/cards/import`), which
//!    inserts the inert local stub (owner-only roster, no extended seat, no
//!    secret).
//! 3. A mints a verified v4 invite. J posts `POST /groups/join`.
//! 4. Fixed: the stub clears, J completes the join (`active`, listed by A),
//!    and a cross-peer encrypted store round trip succeeds (A writes, J
//!    opens the same store id and reads — needs `SecureShareDelivered`).
//!
//! Negative control `w3h_1161_control_share_withheld_is_red`: same join
//! path with every DM carrying `secure_share_delivered` to J dropped. Roster
//! membership alone must not pass; the encrypted round trip must fail and
//! the receipt is RED.
//!
//! Baseline on main: step 3 is 409 with the lineage-free `join failed` /
//! `fresh invite cannot replace` refusal (`JoinFailed` — no
//! `InertCardImportStub` clear). The fix-branch test expects GREEN; the
//! red-proof branch expects RED. D55's #1150(a) exception does not apply;
//! this case is the A08 / D181 harness-first reproduction.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::control::{
    invite, local_membership, members, mesh, open_store, put_value, read_value, try_open_store,
};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass, Write};
use anyhow::ensure;
use axum::http::StatusCode;
use serde_json::json;

const SEED: u64 = 0x1161_0001;
const SEED_WITHHOLD: u64 = 0x1161_0002;
const CASE: &str = "w3h_1161_card_import_invite";
const CASE_WITHHOLD: &str = "w3h_1161_control_share_withheld_is_red";
const FINAL: &str = "card_import_stub_clears_and_encrypted_round_trip";
const FINAL_WITHHOLD: &str = "share_withheld_blocks_encrypted_round_trip";
const JOIN_BUDGET: Duration = Duration::from_secs(120);
const STORE_BUDGET: Duration = Duration::from_secs(90);
/// JSON tag from `NamedGroupMetadataEvent` (`event: secure_share_delivered`).
const SECURE_SHARE_MARKER: &[u8] = b"secure_share_delivered";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// Fixed path: stub clear + usable encryption.
    Plain,
    /// Key delivery withheld: encrypted round trip must fail (RED).
    WithholdShare,
}

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn is_dm(write: &Write) -> bool {
    matches!(write.lane.class, LaneClass::Direct | LaneClass::RelayedDm)
}

/// Drops DM frames to `target` that carry a `SecureShareDelivered` payload.
struct ShareWithhold {
    /// Kept so the rule stays armed for the whole run (never released).
    _held: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl ShareWithhold {
    fn install(sim: &Sim, target: &str) -> Result<Self> {
        let machine = sim.peer(target)?.0;
        let dropped = Arc::new(AtomicUsize::new(0));
        let rule_dropped = Arc::clone(&dropped);
        // Held for the whole run; the negative control never releases.
        let held = Arc::new(AtomicBool::new(true));
        let rule_held = Arc::clone(&held);
        sim.fabric().add_rule(move |write: &Write| {
            let hit = rule_held.load(Ordering::SeqCst)
                && write.lane.dst == machine
                && is_dm(write)
                && contains(&write.bytes, SECURE_SHARE_MARKER);
            if hit {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self {
            _held: held,
            dropped,
        })
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

async fn create_discoverable_group(sim: &Sim, owner: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({
                "name": "w3h 1161 card",
                "display_name": owner,
                "preset": "public_request_secure"
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

/// True when J can open A's group store and read A's ciphertext.
async fn encrypted_round_trip(sim: &Sim, group: &str, store: &str) -> bool {
    match try_open_store(sim, "J", group).await {
        Ok(id) if id == store => {
            read_value(sim, "J", store, "w3h-1161").await.as_deref() == Some("delivered")
        }
        _ => false,
    }
}

async fn scenario(sim: &Sim, receipt: &mut Receipt, arm: Arm) -> Result<bool> {
    mesh(sim, &["A", "J"]).await?;
    let group = create_discoverable_group(sim, "A").await?;
    receipt.setup_done(at(sim));

    let withhold = if arm == Arm::WithholdShare {
        Some(ShareWithhold::install(sim, "J")?)
    } else {
        None
    };

    let (card_status, card) = sim
        .api("A", Method::GET, &format!("/groups/cards/{group}"), None)
        .await?;
    ensure!(card_status.is_success(), "GET card: {card_status} {card}");
    ensure!(
        card.get("group_id").is_some(),
        "card payload missing group_id: {card}"
    );

    let (import_status, imported) = sim
        .api("J", Method::POST, "/groups/cards/import", Some(card))
        .await?;
    ensure!(
        import_status.is_success() && imported["ok"] != false,
        "card import: {import_status} {imported}"
    );

    let membership = local_membership(sim, "J", &group).await;
    let stub_not_member = membership.as_deref() == Some("not_member");
    receipt.evidence(
        "J holds a card-import stub (membership_state not_member)",
        stub_not_member,
        format!("membership_state={membership:?}"),
        at(sim),
    );
    ensure!(
        stub_not_member,
        "card import did not leave a not_member stub"
    );

    let link = invite(sim, "A", &group).await?;
    let (join_status, join_body) = sim
        .api(
            "J",
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": "J"})),
        )
        .await?;
    receipt.request_delivered(
        "POST /groups/join with verified invite after card import",
        true,
        format!("status={join_status} body={join_body}"),
        at(sim),
    );

    let refused = join_status == StatusCode::CONFLICT
        && join_body["error"].as_str().is_some_and(|error| {
            error.contains("join failed") && error.contains("fresh invite cannot replace")
        });
    if refused {
        receipt.cause(
            "POST /groups/join returns 409 JoinFailed on card-import stub",
            Some(format!("{join_status} {join_body}")),
            true,
            at(sim),
        );
        return Ok(false);
    }

    ensure!(
        join_status.is_success() && join_body["ok"] != false,
        "unexpected join response: {join_status} {join_body}"
    );
    receipt.note(format!("join accepted: {join_body}"));

    let j_hex = sim.agent_hex("J")?;
    sim.until(
        "J active after card-stub invite",
        JOIN_BUDGET,
        async |s: &Sim| {
            if local_membership(s, "J", &group).await.as_deref() != Some("active") {
                return false;
            }
            let Ok(list) = members(s, "A", &group).await else {
                return false;
            };
            list.iter().any(|id| id.eq_ignore_ascii_case(&j_hex))
        },
    )
    .await?;

    // Roster membership alone is not GREEN: require a usable group key via
    // an encrypted store round trip (A → J).
    let store = open_store(sim, "A", &group).await?;
    put_value(sim, "A", &store, "w3h-1161", "delivered").await?;

    let rt = sim
        .until(
            "J encrypted round trip after card-stub invite",
            STORE_BUDGET,
            async |s: &Sim| encrypted_round_trip(s, &group, &store).await,
        )
        .await;

    match (arm, rt) {
        (Arm::Plain, Ok(())) => {
            receipt.evidence(
                "J opens A's store and reads A's encrypted write",
                true,
                format!("store={store} key=w3h-1161"),
                at(sim),
            );
            Ok(true)
        }
        (Arm::WithholdShare, Ok(())) => {
            receipt.infra(
                "encrypted round trip succeeded while SecureShareDelivered was withheld",
                at(sim),
            );
            Ok(false)
        }
        (Arm::WithholdShare, Err(error)) if expired(&error) => {
            let dropped = withhold.as_ref().map(ShareWithhold::dropped).unwrap_or(0);
            receipt.evidence(
                "SecureShareDelivered DMs to J were dropped",
                dropped > 0,
                format!("dropped={dropped}"),
                at(sim),
            );
            ensure!(
                dropped > 0,
                "withhold arm dropped no secure_share_delivered frames; fault did not exercise"
            );
            let j_open = try_open_store(sim, "J", &group).await;
            let j_read = read_value(sim, "J", &store, "w3h-1161").await;
            receipt.cause(
                "J cannot complete encrypted round trip when SecureShareDelivered is withheld",
                Some(format!("open={j_open:?} read={j_read:?} dropped={dropped}")),
                true,
                at(sim),
            );
            Ok(false)
        }
        (Arm::Plain, Err(error)) => Err(error).context("encrypted round trip on fixed path"),
        (_, Err(error)) => Err(error),
    }
}

async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    let final_label = match arm {
        Arm::Plain => FINAL,
        Arm::WithholdShare => FINAL_WITHHOLD,
    };
    let seated = match Sim::start(case, seed, &["A", "J"]).await {
        Ok(sim) => {
            let outcome = match scenario(&sim, &mut receipt, arm).await {
                Ok(seated) => seated,
                Err(error) => {
                    receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
                    false
                }
            };
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
            outcome
        }
        Err(error) => {
            receipt.infra(format!("sim: {error:#}"), 0);
            false
        }
    };
    if receipt.verdict().is_none() {
        receipt.finish(final_label, seated && !receipt.has_infra(), 0);
    }
    if receipt.has_infra() {
        receipt.reclassify(final_label);
    }
    receipt.emit();
    receipt
}

/// Fixed path: card-import stub clears, invite join seats, encrypted RT.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1161_card_import_invite() -> Result<()> {
    let receipt = run(CASE, SEED, Arm::Plain).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{CASE}: expected GREEN, got {:?} (RED is the #1161 baseline on main)",
        receipt.verdict()
    );
    Ok(())
}

/// Negative control: withhold `SecureShareDelivered` to J → RED.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1161_control_share_withheld_is_red() -> Result<()> {
    let receipt = run(CASE_WITHHOLD, SEED_WITHHOLD, Arm::WithholdShare).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Red),
        "{CASE_WITHHOLD}: expected RED, got {:?}",
        receipt.verdict()
    );
    Ok(())
}
