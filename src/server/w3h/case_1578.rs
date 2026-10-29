//! W3-H case for #1578 (a GSS survivor whose own roster seat carries no
//! ML-KEM-768 public key installs the verified S4 exclusion frame
//! keyless), the W3-H reproduction the #1627 review demanded (Codex P2:
//! ADR 0088 §4 G4 and A08 require the failure reproduced in W3-H before
//! the fix).
//!
//! Nodes: A (owner, the only admin — the S4 committer), B (the leaver)
//! and C (the stranded survivor). The group is `public_request_secure`
//! (`MlsEncrypted`), so it runs the GSS plane (#969's shape; only Hidden
//! encrypted groups are TreeKEM).
//!
//! The #1578 shape and the injection. A seat's KEM public key is local
//! data: `compute_roster_root` hashes only `id:role:state[:cert]`, and
//! the roster projection a state commit carries has no KEM field at
//! all, so one member's view of a seat differs from another's by
//! design. The inviter seats a joiner's key from its verified
//! `MemberJoined`; the joiner's OWN copy of its own seat never carries
//! one — the join stub seats `kem_public_key_b64: None` and no later
//! event re-seats it. So the receiver side of #1578
//! (`own_seat_cannot_take_a_share`) needs no injection: C's own view is
//! keyless from its join. The injection strips the ONE copy that is
//! keyed — A's, the author side, under A's own `named_groups` write
//! lock — so `spawn_gss_share_to` then logs `no KEM key on record for a
//! survivor` and skips the seal, and no share of the rotated secret can
//! ever reach C. Each daemon keeps its own `agent_kem_keypair`; only
//! the roster row is stripped, so the sealed chain and every head stay
//! untouched. This mirrors the local fixture
//! `gss_leave_fixture_build(None, false)`
//! (`revocation_eviction/crypto_exclusion.rs`), which seats no key on
//! either side — the mirror of the `set_member_kem_public_key` calls its
//! recovery half uses.
//!
//! The trigger. B leaves (`DELETE /groups/:id` sent by B). A GSS
//! self-leave changes the roster and not the secret, so the leaver keeps
//! the key; A's S4 worker then commits the GSS `CryptoExclusionV1` frame
//! (one rotation, `next_secret_epoch`) and delivers it to the survivors
//! by direct DM (`X0XCE1`). The admin-remove route is NOT the trigger:
//! `DELETE /groups/:id/members/:agent_id` is the F1 §2 inline rotation,
//! which fails closed (424) when a survivor seat has no key in the
//! author's view, and no seal endpoint is involved.
//!
//! RED on `main` (the baseline this branch fixes): every author skips
//! the seal, and the verified frame installs only with its share
//! (#1508), so C keeps it `WaitingForShare` for ever — C's head stays
//! at the parent, the frame stays pending in the stash and the `.celog`,
//! and A's delivery row keeps resending (#1578's hang). Desired (GREEN
//! here): C installs the frame keyless — the head moves to the verified
//! result, `secret_epoch` advances and the old secret (which B still
//! holds) is dropped — the durable typed hold withholds new ciphertext
//! (409 on `POST /groups/:id/secure/encrypt` with `a verified removal
//! waits for its new group secret; ciphertext is withheld`), C's served
//! catch-up answer omits `responder_state_hash` (David's ruling,
//! 28 Oct 02:09 GMT), and A's row for B stays `committed_delivery_pending`
//! (the keyless install never proves delivery; Engineer ruling,
//! 27 Oct 22:10 GMT).
//!
//! Red baseline procedure (D16/D54/D181, harness first; macOS cannot
//! run it — W3-H daemon cases need the Linux isolated namespace): as
//! #1357 did (DIAG PR #1496), branch a DIAG branch from `main`,
//! cherry-pick only this file, the `mod case_1578;` line and the gate
//! flags (everything this case touches exists on `main`), then run
//! `RUSTFLAGS="--cfg tokio_unstable" python3 scripts/dev/test-isolated.py
//! nextest --all-features --lib -- --profile w3h w3h_1578_red_` once.
//! The run must print a `W3H-RECEIPT` with verdict RED; keep the
//! receipt and trace with the PR. On this branch the `_red_` name keeps
//! the provenance and the case expects GREEN, as #1256 and #1357 did.
//!
//! D196: the 20 verdict-stable rerun receipts come from the W3-H gate —
//! CI's `w3h-harness` job, or locally `just test-w3h-gate` — which runs
//! every case `--stress-count 20` and checks
//! `scripts/ci/w3h-trace-check.py target/w3h/traces --runs 20 --require
//! w3h_1578_red_gss_survivor_without_a_roster_kem_key_installs_the_frame_keyless
//! --expect w3h_1578_red_gss_survivor_without_a_roster_kem_key_installs_the_frame_keyless=GREEN`.

#![cfg(test)]

use super::control::{invite, join, local_membership, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::dm::CapabilityRegistry;
use crate::groups::eviction::S4Timing;
use crate::groups::GroupMemberState;
use crate::mls::SecureGroupPlane;
use crate::network::sim::LaneClass;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The signed `CryptoExclusionV1` wire prefix every CE frame starts with.
const CE_PREFIX: &[u8] = crate::groups::crypto_exclusion::CRYPTO_EXCLUSION_PREFIX;
/// The typed 409 refusal the `PendingGssRemoval` hold answers with.
const HOLD_REASON: &str =
    "a verified removal waits for its new group secret; ciphertext is withheld";
const PROBE: &[u8] = b"w3h-1578 probe";
const SEED: u64 = 0x1578_0001;
const CASE: &str = "w3h_1578_red_gss_survivor_without_a_roster_kem_key_installs_the_frame_keyless";
const FINAL: &str =
    "the_keyless_survivor_installs_the_frame_withholds_ciphertext_and_claims_no_head";
const CAUSE: &str =
    "on main no author can seal the rotated secret to a keyless seat: the verified \
                     frame waits for its share for ever, C's head stays at the parent, C keeps the \
                     old secret (it still encrypts under it) and A's delivery row keeps resending";
/// Setup readiness waits (seats, the leave's propagation, the S4 commit).
const SETUP: Duration = Duration::from_secs(180);
/// Evidence budgets (the commit, the frame's delivery to C).
const EVIDENCE: Duration = Duration::from_secs(60);
/// The keyless-install window, from the S4 commit: the completion bound
/// (18 s) covers the designated path, and `main` never installs (the
/// wait for a share has no time limit), so the window must close as a
/// RED instead of hanging the harness.
const KEYLESS_WINDOW: Duration = Duration::from_secs(60);

fn at(sim: &Sim) -> u128 {
    sim.fabric().now().as_micros()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// `label`'s saved GSS view of `group`: head, secret epoch, and whether
/// it holds a shared secret — the three #1578 observables. No barrier;
/// for use inside one.
async fn gss_view_now(sim: &Sim, label: &str, group: &str) -> Result<(String, u64, bool)> {
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("{label} holds no record of {group}"))?;
    Ok((
        info.state_hash.clone(),
        info.secret_epoch,
        info.shared_secret.is_some(),
    ))
}

/// [`gss_view_now`] at a frozen instant.
async fn gss_view(sim: &Sim, label: &str, group: &str, what: &str) -> Result<(String, u64, bool)> {
    sim.at_instant(what, gss_view_now(sim, label, group))
        .await?
}

/// Whether `holder`'s roster for `group` seats `seat_hex` with a KEM
/// public key. No barrier; for use inside one.
async fn seat_kem(sim: &Sim, holder: &str, group: &str, seat_hex: &str) -> Result<bool> {
    let state = sim.state(holder)?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("{holder} holds no record of {group}"))?;
    Ok(info.members_v2.values().any(|member| {
        member.agent_id.eq_ignore_ascii_case(seat_hex) && member.kem_public_key_b64.is_some()
    }))
}

/// The #1578 injection: remove `seat_hex`'s KEM public key from `node`'s
/// OWN copy of `group`'s roster, under the node's `named_groups` write
/// lock. The key is local data (not in the roster root), so the chain
/// and the head are untouched; the daemon's own KEM keypair stays.
async fn strip_seat_kem(sim: &Sim, node: &str, group: &str, seat_hex: &str) -> Result<()> {
    let state = sim.state(node)?;
    let what = format!("strip {node}'s roster KEM key for the seat");
    sim.within(&what, secs(5), async {
        let mut groups = state.named_groups.write().await;
        let key = crate::server::resolve_group_entry_locked(&groups, group)
            .with_context(|| format!("{node} holds no record of {group}"))?
            .0
            .to_string();
        let seat = groups
            .get_mut(&key)
            .with_context(|| format!("{node} lost {group} under its own write lock"))?
            .members_v2
            .get_mut(seat_hex)
            .with_context(|| format!("{group} has no seat for {seat_hex} on {node}"))?;
        ensure!(
            seat.state == GroupMemberState::Active,
            "{node}'s seat for {seat_hex} is {:?}, not Active",
            seat.state
        );
        ensure!(
            seat.kem_public_key_b64.is_some(),
            "{node}'s seat for {seat_hex} already carries no KEM key"
        );
        seat.kem_public_key_b64 = None;
        Ok(())
    })
    .await?
}

/// `label`'s public S4 row for `target_hex` in `group` (`GET /groups/:id`,
/// `revocation_evictions`), without a barrier; for use inside one.
async fn s4_row(
    sim: &Sim,
    label: &str,
    group: &str,
    target_hex: &str,
) -> Result<Option<serde_json::Value>> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(body["revocation_evictions"]
        .as_array()
        .context("no revocation_evictions array")?
        .iter()
        .find(|row| {
            row["target"]
                .as_str()
                .is_some_and(|target| target.eq_ignore_ascii_case(target_hex))
        })
        .cloned())
}

/// Delivered DM frames `from`→`to` carrying the signed `CryptoExclusionV1`
/// wire prefix, after trace position `after`.
fn ce_frames_delivered(sim: &Sim, from: &str, to: &str, after: usize) -> Result<usize> {
    let writes = sim
        .fabric()
        .delivered_writes_after(&sim.peer(from)?, &sim.peer(to)?, after);
    Ok(writes
        .iter()
        .filter(|(write, _)| matches!(write.lane.class, LaneClass::Direct | LaneClass::RelayedDm))
        .filter(|(write, _)| contains(&write.bytes, CE_PREFIX))
        .count())
}

/// `label` encrypts the probe on `POST /groups/:id/secure/encrypt` (its
/// own barrier); the raw status and body, for the 200 and the 409 shapes.
async fn encrypt_probe(
    sim: &Sim,
    label: &str,
    group: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    sim.api(
        label,
        Method::POST,
        &format!("/groups/{group}/secure/encrypt"),
        Some(json!({"payload_b64": BASE64.encode(PROBE)})),
    )
    .await
}

/// Whether `label` recovers the probe from the encrypt answer `cipher`.
async fn decrypts(
    sim: &Sim,
    label: &str,
    group: &str,
    cipher: &serde_json::Value,
) -> Result<(bool, String)> {
    let (status, body) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/secure/decrypt"),
            Some(json!({
                "ciphertext_b64": cipher["ciphertext_b64"],
                "nonce_b64": cipher["nonce_b64"],
                "secret_epoch": cipher["secret_epoch"],
            })),
        )
        .await?;
    let ok = status.is_success()
        && body["payload_b64"]
            .as_str()
            .and_then(|payload| BASE64.decode(payload).ok())
            .is_some_and(|payload| payload == PROBE);
    Ok((ok, format!("{label} decrypt: {status} {body}")))
}

/// Drive `responder`'s REAL catch-up serve path for `requester` (the
/// handler `dispatch_treekem_catchup_message` runs, `verified`, with the
/// requester's own request shape — never a hand-built answer) and report
/// whether the served page omits `responder_state_hash` (David's ruling,
/// 28 Oct 02:09 GMT: a keyless GSS responder claims no head; every other
/// responder serves its saved head, as on main).
async fn served_head_claim(
    sim: &Sim,
    responder: &str,
    requester: &str,
    group: &str,
) -> Result<(bool, String)> {
    let state = sim.state(responder)?;
    let requester_id = sim.ids(requester)?.0;
    // The recorder holds only this run's pages.
    if let Ok(mut recorded) = state.named_group_test_recorders.catchup_responses.lock() {
        recorded.clear();
    }
    let what = format!("serve {responder}'s catch-up answer");
    sim.within(&what, API_BUDGET, async {
        let (revision, head) = {
            let groups = state.named_groups.read().await;
            let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
                .with_context(|| format!("{responder} holds no record of {group}"))?;
            (info.state_revision, info.state_hash.clone())
        };
        let body = json!({
            "message_type": "treekem_catchup_request",
            "group_id": group,
            "requester_agent_id": hex::encode(requester_id.as_bytes()),
            "from_revision": revision,
            "from_treekem_epoch": 0,
            "current_state_hash": head,
            "missing_prev_state_hash": null,
            "target_member_id": null,
            "limit": 64,
        });
        let request: crate::server::routes::named_groups::TreeKemCatchupRequest =
            serde_json::from_value(body).context("the catch-up request did not decode")?;
        crate::server::routes::named_groups::handle_treekem_catchup_request(
            &state,
            &requester_id,
            // #1616: the DM's QUIC-authenticated sender machine; clean
            // here (the clean-machine id no test revokes).
            &crate::identity::MachineId([0x16; 32]),
            true,
            request,
        )
        .await;
        let pages = state
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let page = pages
            .iter()
            .rev()
            .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
            .find(|page| page["group_id"].as_str() == Some(group))
            .context("no catch-up page was served for the group")?;
        let served = page["responder_state_hash"].as_str();
        Ok((
            served.is_none(),
            format!(
                "responder_state_hash omitted={}; served head {:?}",
                served.is_none(),
                served
            ),
        ))
    })
    .await?
}

/// Whether A's group record runs the GSS plane under the `MlsEncrypted`
/// policy — its own future so [`Sim::within`] infers the error type.
async fn group_is_gss(sim: &Sim, group: &str) -> Result<bool> {
    let state = sim.state("A")?;
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
        .with_context(|| format!("A holds no record of {group}"))?;
    Ok(info.secure_plane == SecureGroupPlane::Gss
        && info.policy.confidentiality == crate::groups::GroupConfidentiality::MlsEncrypted)
}

/// Whether C's own copy and A's copy of C's seat both carry no KEM key —
/// its own future so [`Sim::within`] infers the error type.
async fn both_copies_keyless(sim: &Sim, group: &str, c_hex: &str) -> Result<(bool, bool)> {
    Ok((
        !seat_kem(sim, "C", group, c_hex).await?,
        !seat_kem(sim, "A", group, c_hex).await?,
    ))
}

/// Wait until `member` is listed by `owner` and reports itself active
/// (#969's shape).
async fn wait_seated(sim: &Sim, owner: &str, member: &str, group: &str, what: &str) -> Result<()> {
    let id = sim.agent_hex(member)?;
    let mut seen = Observations::default();
    sim.until(what, SETUP, async |s: &Sim| {
        let Some(listed) = seen.observe(members(s, owner, group)).await else {
            return true;
        };
        listed.contains(&id)
            && local_membership(s, member, group).await.as_deref() == Some("active")
    })
    .await?;
    seen.verify(what)?;
    Ok(())
}

/// Returns once `observer` holds `label`'s current verified advert setting
/// `bit`; each round asks for a fresh advert, as S4 itself does for
/// unknown support (#1356's idiom). The D76 gate on A's commit needs
/// this before the leave.
async fn sees_bit(sim: &Sim, observer: &str, label: &str, bit: u64, what: &str) -> Result<()> {
    let agent = sim.ids(label)?.0;
    sim.until(what, SETUP, async |s: &Sim| {
        let Ok(state) = s.state(observer) else {
            return false;
        };
        if state
            .agent
            .capability_store()
            .verified_registry_supports(&agent, bit)
            == Some(true)
        {
            return true;
        }
        state.agent.refresh_application_capability(agent, bit).await;
        false
    })
    .await
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let labels = ["A", "B", "C"];
    mesh(sim, &labels).await?;
    let (status, created) = sim
        .api(
            "A",
            Method::POST,
            "/groups",
            Some(json!({
                "name": "w3h 1578 keyless survivor",
                "display_name": "A",
                "preset": "public_request_secure"
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    let group = created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string();

    let (card_status, card) = sim
        .api("A", Method::GET, &format!("/groups/cards/{group}"), None)
        .await?;
    ensure!(card_status.is_success(), "GET card: {card_status} {card}");
    for joiner in ["B", "C"] {
        let (import_status, imported) = sim
            .api(
                joiner,
                Method::POST,
                "/groups/cards/import",
                Some(card.clone()),
            )
            .await?;
        ensure!(
            import_status.is_success() && imported["ok"] != false,
            "{joiner} card import: {import_status} {imported}"
        );
        let link = invite(sim, "A", &group).await?;
        join(sim, joiner, &link).await?;
        wait_seated(
            sim,
            "A",
            joiner,
            &group,
            &format!("{joiner} seated in A's group"),
        )
        .await?;
    }

    let b_hex = sim.agent_hex("B")?;
    let c_hex = sim.agent_hex("C")?;

    // The precondition the injection removes: C's seat carries a KEM key
    // in A's copy (the inviter seated it from C's verified MemberJoined).
    // C's own copy never carries one — the join stub seats no KEM
    // material on the joiner's own view and no later event re-seats it —
    // which supplies the receiver-side half of the #1578 shape with no
    // injection at all.
    let what = "C's seat carries a KEM key on A";
    let mut seen = Observations::default();
    sim.until(what, SETUP, async |s: &Sim| {
        match seen.observe(seat_kem(s, "A", &group, &c_hex)).await {
            Some(true) => {}
            Some(false) => return false,
            None => return true,
        }
        true
    })
    .await?;
    seen.verify(what)?;
    let c_own_copy_keyed = sim
        .within(
            "read C's own copy of its seat",
            secs(5),
            seat_kem(sim, "C", &group, &c_hex),
        )
        .await??;
    ensure!(
        !c_own_copy_keyed,
        "C's own copy of its seat carries a KEM key; the #1578 receiver \
         side is not the natural joiner state"
    );

    // Pre-leave data plane: A's ciphertext opens on C, so C holds the
    // epoch-e0 secret before anything rotates it.
    let cipher = encrypt_probe(sim, "A", &group).await?;
    ensure!(
        cipher.0.is_success() && cipher.1["ok"] != false,
        "A encrypt at e0: {} {}",
        cipher.0,
        cipher.1
    );
    let (c_before, c_before_detail) = decrypts(sim, "C", &group, &cipher.1).await?;

    // The plane: a TreeKEM group seals no GSS secret at all, so the case
    // would prove nothing.
    let (a_head, e0, a_secret) = gss_view(sim, "A", &group, "read A's group state").await?;
    let gss_plane = sim
        .within("read A's group plane", secs(5), group_is_gss(sim, &group))
        .await??;
    let plane = gss_plane && a_secret;
    // ADR 0110 §2: no S4 seal before a node's restart sync wait from
    // process start. Every node started before setup ended, so waiting
    // that long from here puts t = 0 past every node's boot gate.
    let sync_wait = S4Timing::default().restart_sync_wait;
    sim.within(
        "every node's restart sync wait",
        sync_wait + secs(2),
        async {
            tokio::time::sleep(sync_wait).await;
        },
    )
    .await?;
    // D76: A must hold C's verified `crypto_exclusion_v1` advert, or the
    // commit stays `waiting_for_receiver_upgrade`.
    sees_bit(
        sim,
        "A",
        "C",
        CapabilityRegistry::CRYPTO_EXCLUSION_V1,
        "A holds C's verified crypto_exclusion_v1 advert",
    )
    .await?;

    receipt.setup_done(at(sim));
    receipt.evidence(
        "group_runs_the_gss_plane_with_a_shared_secret",
        plane,
        format!("e0={e0} a_head={a_head} secret={a_secret}"),
        at(sim),
    );
    ensure!(
        plane,
        "the group is not on the GSS plane; the case proves nothing"
    );
    receipt.evidence(
        "c_seat_carried_a_kem_key_before_the_injection",
        true,
        "waited until A's copy seated the key; C's own copy never carries one".to_string(),
        at(sim),
    );
    receipt.evidence(
        "c_decrypts_a_ciphertext_at_e0_before_the_leave",
        c_before,
        c_before_detail,
        at(sim),
    );
    ensure!(c_before, "C could not decrypt at e0 before the leave");

    // The injection (A's copy only; see the module notes). C's own copy
    // is keyless by daemon reality, asserted above.
    strip_seat_kem(sim, "A", &group, &c_hex).await?;
    sim.fabric()
        .mark("fault: C's roster seat carries no KEM key (A's copy stripped; C's own never carried one; #1578 shape)");
    let (c_keyless, a_keyless) = sim
        .within(
            "read both copies of C's seat",
            secs(5),
            both_copies_keyless(sim, &group, &c_hex),
        )
        .await??;
    receipt.evidence(
        "c_own_roster_seat_carries_no_kem_public_key",
        c_keyless,
        "C's own copy of its Active seat has no KEM key; the keyless-install predicate".to_string(),
        at(sim),
    );
    receipt.evidence(
        "a_holds_no_kem_key_for_c_so_no_author_can_seal",
        a_keyless,
        "A's copy of C's seat has no KEM key; spawn_gss_share_to skips the seal".to_string(),
        at(sim),
    );
    ensure!(
        c_keyless && a_keyless,
        "the injection did not leave C's seat keyless on both copies"
    );

    // t = 0: B leaves. The S4 worker on A commits the GSS crypto-only
    // exclusion frame and rotates the secret.
    let trigger = sim
        .fabric()
        .mark_indexed("case: t=0 B leaves the group (GSS self-leave)");
    let (leave_status, leave_body) = sim
        .api("B", Method::DELETE, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        leave_status.is_success(),
        "B leaves: {leave_status} {leave_body}"
    );

    let what = "A commits the S4 GSS crypto-only exclusion and rotates the secret";
    let mut detail = String::new();
    let mut result_head: Option<String> = None;
    let mut result_epoch: Option<u64> = None;
    let mut seen = Observations::default();
    sim.until(what, EVIDENCE, async |s: &Sim| {
        let Some(row) = seen.observe(s4_row(s, "A", &group, &b_hex)).await else {
            return true;
        };
        // No row yet: the S4 intake has not recorded the leave.
        let Some(row) = row else {
            return false;
        };
        let Some((head, epoch, secret)) = seen.observe(gss_view_now(s, "A", &group)).await else {
            return true;
        };
        let row_head = row["result_head"].as_str().map(str::to_string);
        let row_epoch = row["result_epoch"].as_u64();
        let ok = row["phase"].as_str() == Some("committed_delivery_pending")
            && row_epoch.is_some_and(|epoch| epoch > e0)
            && row_head.as_deref() == Some(head.as_str())
            && row_epoch == Some(epoch)
            && secret;
        if ok {
            result_head = row_head.clone();
            result_epoch = row_epoch;
        } else {
            detail = format!(
                "phase={:?} result_epoch={row_epoch:?} result_head={row_head:?}; \
                 A head={head} epoch={epoch} secret={secret}",
                row["phase"].as_str()
            );
        }
        ok
    })
    .await?;
    seen.verify(what)?;
    let Some(result_head) = result_head else {
        bail!("A never committed the S4 GSS exclusion: {detail}");
    };
    let result_epoch = result_epoch.context("no result epoch was read")?;
    let listed = sim
        .at_instant("A's roster after B's leave", members(sim, "A", &group))
        .await??;
    receipt.evidence(
        "b_self_leave_committed_the_s4_gss_crypto_exclusion",
        !listed.contains(&b_hex),
        format!(
            "e0={e0} result_epoch={result_epoch} result_head={result_head}; \
             A no longer lists B: {}",
            !listed.contains(&b_hex)
        ),
        at(sim),
    );
    ensure!(
        !listed.contains(&b_hex),
        "A still lists B after its self-leave"
    );

    // The frame reached C (a delivered CE DM after t = 0) — true on this
    // branch and on `main` alike, so the receipt's delivery stage holds
    // for the red baseline too.
    let what = "the S4 crypto-exclusion frame is delivered to C";
    sim.until(what, EVIDENCE, async |s: &Sim| {
        ce_frames_delivered(s, "A", "C", trigger).unwrap_or(0) > 0
    })
    .await?;
    let frames = ce_frames_delivered(sim, "A", "C", trigger)?;
    receipt.request_delivered(
        "the_s4_crypto_exclusion_frame_reached_c",
        frames > 0,
        format!("{frames} delivered DM frame(s) with the X0XCE1 prefix after t=0"),
        at(sim),
    );
    ensure!(frames > 0, "the crypto-exclusion frame never reached C");

    // The keyless install. Expected on this branch within the window; on
    // `main` it never happens, and the expired window is the RED cause.
    let what = "C installs the verified frame keyless (its head reaches the result)";
    let mut seen = Observations::default();
    let waited = sim
        .until(what, KEYLESS_WINDOW, async |s: &Sim| {
            match seen.observe(gss_view_now(s, "C", &group)).await {
                Some((head, ..)) => head == result_head,
                None => true,
            }
        })
        .await;
    seen.verify(what)?;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }

    // The four observables of the fix.
    let (c_head, c_epoch, c_secret) =
        gss_view(sim, "C", &group, "read C's group after the window").await?;
    let installed = c_head == result_head && c_epoch == result_epoch && !c_secret;
    let (enc_status, enc_body) = encrypt_probe(sim, "C", &group).await?;
    let withheld = enc_status == StatusCode::CONFLICT
        && enc_body["error"]
            .as_str()
            .is_some_and(|text| text.contains(HOLD_REASON));
    let (answer_omitted, answer_detail) = served_head_claim(sim, "C", "A", &group).await?;
    let (row_status, row_body) = sim
        .api("A", Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        row_status.is_success(),
        "A GET /groups/{group}: {row_status} {row_body}"
    );
    let row = row_body["revocation_evictions"]
        .as_array()
        .context("no revocation_evictions array")?
        .iter()
        .find(|row| {
            row["target"]
                .as_str()
                .is_some_and(|target| target.eq_ignore_ascii_case(&b_hex))
        })
        .context("A holds no S4 row for B at the end")?;
    let row_phase = row["phase"].as_str().unwrap_or_default().to_string();
    let row_open = row_phase == "committed_delivery_pending";
    receipt.note(format!(
        "e0={e0} result_epoch={result_epoch} result_head={result_head}; C head={c_head} \
         epoch={c_epoch} secret={c_secret} (installed={installed}); C encrypt {enc_status} \
         {enc_body} (withheld={withheld}); C's catch-up answer: {answer_detail} \
         (omitted={answer_omitted}); A's row for B phase={row_phase} (open={row_open})"
    ));

    let passed = installed && withheld && answer_omitted && row_open;
    if !passed {
        // The `main` shape only: the head never reached the result and C
        // keeps the old secret. Anything else is INFRA, not RED.
        receipt.cause(
            CAUSE,
            Some(format!(
                "C head={c_head} epoch={c_epoch} secret={c_secret}; installed={installed}; \
                 withheld={withheld}; {answer_detail}; A's row phase={row_phase}"
            )),
            c_head != result_head && c_secret && c_epoch == e0,
            at(sim),
        );
    }
    receipt.finish(FINAL, passed, at(sim));
    Ok(())
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "The #1578 injection removes the survivor seat's KEM public key from the live roster \
         map of A (the author: no share can be sealed to the seat). The receiver's own view \
         never carries the key — the join stub seats none and the roster projection has no \
         KEM field — so the keyless-install predicate reads C's natural joiner state. The \
         key is local data, not in the roster root, so the chain and every head are \
         untouched; each daemon keeps its own agent_kem_keypair. This mirrors \
         gss_leave_fixture_build(None, false) in the local fixture.",
    );
    match Sim::start(case, seed, &["A", "B", "C"]).await {
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

async fn expect(case: &str, seed: u64, want: Verdict) -> Result<()> {
    let receipt = run(case, seed).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// The #1578 case: RED on `main` (the frame waits for its share for
/// ever; the DIAG procedure in the module notes), GREEN with this
/// branch's keyless install.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1578_red_gss_survivor_without_a_roster_kem_key_installs_the_frame_keyless() -> Result<()> {
    super::block_on_paused(async move {
        expect(
            CASE,
            SEED,
            // #1578 fixed: RED on main (the DIAG run), GREEN here.
            Verdict::Green,
        )
        .await
    })
}
