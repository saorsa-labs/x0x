//! ADR 0109 §10 row H-S3-d4 (route refusals, D156, D170; #1572). Control,
//! expected GREEN with S3 (on `main` before S3, the route returns 404).
//!
//! Nodes are H-S3-d3's: O holds the owner's USER key; A, M1 and J hold
//! owner-issued agent certificates only (see `owner_axis`). O promotes A
//! to admin. O seats B, and A bans it. Node E is never seated. On A, the
//! case calls `POST /groups/:id/members/:agent_id/reseat`:
//! (1) for J with an empty `reason`; (2) for M1, which is Active; (3) for
//! B; (4) for E. Then O removes J (r+3), and (5) A calls the route for J
//! with a reason and the basis `Removal(r+3)`.
//!
//! Desired (§3, §3a): (1) `reason_required`; (2) `subject_active`;
//! (3) `subject_banned_or_revoked`; (4) `basis_unknown`;
//! (5) `reseat_removal_not_own`, because A holds no owner USER key and O,
//! not A, committed the removal. After each call A has signed and stored
//! no authorisation (`issued_reseats` on `GET /groups/:id/recovery` stays
//! empty), has minted no invite (its issued-invite records do not change)
//! and has committed nothing (its state hash does not move).
//!
//! The reason check comes before the subject checks, so J's state at
//! call (1) does not change the answer. Calls (2) to (4) send a removal
//! basis that names A's head; no removal of M1, B or E is on the chain.

use super::gaps::recovery_route;
use super::owner_axis::{
    all_reach, announce_all, create_group, join_owner, seal_rename, start_certified,
};
use super::*;

const LABELS: &[&str] = &["O", "A", "M1", "B", "J", "E"];
const FINAL: &str = "a_refuses_each_reseat_call_with_its_typed_reason_and_signs_nothing";
const CAUSE: &str = "the re-seat route is missing (404 on every call), as on main before S3";

/// A's issued-invite records for `group` (secrets, sorted).
async fn invites(sim: &Sim, group: &str) -> Result<Vec<String>> {
    let state = sim.state("A")?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .ok_or_else(|| anyhow!("A has no record of {group}"))?;
    let mut secrets: Vec<String> = info.issued_invites.keys().cloned().collect();
    secrets.extend(info.issued_invite_secrets.iter().cloned());
    secrets.sort();
    Ok(secrets)
}

/// A's `issued_reseats` list. A failed read or a body without the list is
/// no observation (INFRA).
async fn issued(sim: &Sim, group: &str) -> Result<Vec<Value>> {
    let route = recovery_route(sim, "A", group).await?;
    route["issued_reseats"]
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("A's recovery route has no `issued_reseats` list: {route}"))
}

/// A calls the re-seat route for `subject`; returns `(status, reason)`.
async fn call(sim: &Sim, group: &str, subject: &str, body: Value) -> Result<(u16, String)> {
    let hex = sim.agent_hex(subject)?;
    let path = format!("/groups/{group}/members/{hex}/reseat");
    let (code, answer) = sim.api("A", Method::POST, &path, Some(body)).await?;
    let reason = answer["reason"]
        .as_str()
        .or_else(|| answer["error"].as_str())
        .unwrap_or("")
        .to_string();
    Ok((code.as_u16(), reason))
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let owner = crate::identity::UserKeypair::from_seed(&[0x13; 32])?;
    start_certified(sim, "O", &owner, true).await?;
    for label in &LABELS[1..] {
        start_certified(sim, label, &owner, false).await?;
    }
    mesh(sim, LABELS).await?;
    sim.until("O provisions its Home", SETUP, async |s: &Sim| {
        let home = s.request("O", Method::GET, "/home", None).await;
        home.is_ok_and(|(code, body)| code.is_success() && body["state"] != "provisioning_pending")
    })
    .await?;
    announce_all(sim, LABELS).await?;
    // A pinned send with no binding runs a blocking Lookup that stalls
    // paused virtual time (see `owner_axis`).
    sim.until("every node pins every peer", SETUP, async |s: &Sim| {
        for (from, to) in LABELS
            .iter()
            .flat_map(|f| LABELS.iter().map(move |t| (f, t)))
        {
            let (Ok(state), Ok((id, _))) = (s.state(from), s.ids(to)) else {
                return false;
            };
            if from != to && state.agent.pinned_binding_now(&id).await.is_none() {
                return false;
            }
        }
        true
    })
    .await?;
    let group = create_group(sim, &owner).await?;
    for member in ["A", "M1", "B", "J"] {
        join_owner(sim, member, &group, &owner).await?;
    }
    let a_hex = sim.agent_hex("A")?;
    let path = format!("/groups/{group}/members/{a_hex}/role");
    let (code, body) = sim
        .api("O", Method::PATCH, &path, Some(json!({"role": "admin"})))
        .await?;
    ensure!(code.is_success(), "O promotes A: {code} {body}");
    seal_rename(sim, "A", &group, "w3h d4 A warm").await?;
    let head = view(sim, "A", &group).await?;
    all_reach(sim, &["O", "A"], &group, &head.state_hash).await?;
    let b_hex = sim.agent_hex("B")?;
    let path = format!("/groups/{group}/ban/{b_hex}");
    let (code, body) = sim.api("A", Method::POST, &path, None).await?;
    ensure!(code.is_success(), "A bans B: {code} {body}");
    let banned = view(sim, "A", &group).await?;
    all_reach(sim, &["O"], &group, &banned.state_hash).await?;
    let e_hex = sim.agent_hex("E")?;
    receipt.setup_done(at(sim));
    receipt.evidence(
        "m1_and_j_active_b_banned_e_never_seated",
        banned.lists(&sim.agent_hex("M1")?)
            && banned.lists(&sim.agent_hex("J")?)
            && !banned.lists(&b_hex)
            && !banned.lists(&e_hex),
        format!("A {}", banned.describe()),
        at(sim),
    );

    let head_basis = reseat_body(&banned);
    let mut calls: Vec<(&str, &str, Value, u16, &str)> = vec![
        (
            "1_empty_reason",
            "J",
            json!({"reason": "", "basis": head_basis["basis"]}),
            400,
            "reason_required",
        ),
        (
            "2_subject_active",
            "M1",
            head_basis.clone(),
            409,
            "subject_active",
        ),
        (
            "3_subject_banned",
            "B",
            head_basis.clone(),
            409,
            "subject_banned_or_revoked",
        ),
        ("4_never_seated", "E", head_basis, 409, "basis_unknown"),
    ];
    let mut observed = Vec::new();
    let mut all_typed = true;
    let mut all_404 = true;
    let mut quiet = true;
    let mut answered = 0_usize;
    for step in 0..5 {
        if step == 4 {
            // O removes J (r+3); A then holds the removal O committed.
            let j_hex = sim.agent_hex("J")?;
            let path = format!("/groups/{group}/members/{j_hex}");
            let (code, body) = sim.api("O", Method::DELETE, &path, None).await?;
            ensure!(code.is_success(), "O removes J: {code} {body}");
            let removal = view(sim, "O", &group).await?;
            all_reach(sim, &["A"], &group, &removal.state_hash).await?;
            calls.push((
                "5_removal_not_own",
                "J",
                reseat_body(&removal),
                409,
                "reseat_removal_not_own",
            ));
        }
        let (what, subject, body, want_code, want) = calls[step].clone();
        let (before_hash, before_invites) = (
            view(sim, "A", &group).await?.state_hash,
            invites(sim, &group).await?,
        );
        let (got_code, got) = call(sim, &group, subject, body).await?;
        let after_hash = view(sim, "A", &group).await?.state_hash;
        let after_invites = invites(sim, &group).await?;
        let reseats = issued(sim, &group).await?;
        let typed = got_code == want_code && got == want;
        let unchanged =
            before_hash == after_hash && before_invites == after_invites && reseats.is_empty();
        all_typed &= typed;
        all_404 &= got_code == 404;
        quiet &= unchanged;
        observed.push(format!(
            "{what}: {got_code} {got:?} (want {want_code} {want:?}); hash moved {}, invites \
             {}->{}, issued_reseats {}",
            before_hash != after_hash,
            before_invites.len(),
            after_invites.len(),
            reseats.len()
        ));
        answered += 1;
    }
    // Each call is a local route request: an answer means it reached A.
    receipt.request_delivered(
        "five_reseat_calls_answered_by_a",
        answered == 5,
        format!("{answered} answers"),
        at(sim),
    );
    receipt.note(observed.join("; "));
    let passed = all_typed && quiet;
    if !passed {
        receipt.cause(CAUSE, Some(observed.join("; ")), all_404, at(sim));
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("ADR 0109 S3 (#1356, #1572) H-S3-d4: re-seat route refusals".to_string());
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

/// H-S3-d4 (D156, D170): control, GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_d4_reseat_route_refusals() -> Result<()> {
    super::super::block_on_paused(async move {
        let case = "w3h_1356_control_s3_d4_reseat_route_refusals";
        let receipt = run(case, 0x1356_0108).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
