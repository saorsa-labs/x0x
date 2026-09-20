//! ADR-0066 §1 rows 1, 2, 4 and 6 + §4 (slice 9) — the fork-quarantine
//! re-check the four OUTBOUND paths run immediately before their irreversible
//! effect.
//!
//! WHY these tests exist. Slices 1–6 gate these rows at request START, so an
//! operation is admitted only when the group carried no marker at that moment.
//! §4 names the window they leave, and for these rows it is the widest one in
//! the ADR: between the entry gate and the effect these handlers await on the
//! rider-token mutex, a revocation-record read, the TreeKEM per-group mutex and
//! a pubsub listener spawn. A fork observation landing at any of those
//! suspension points would otherwise export contested state — a signed public
//! message on the wire, a TreeKEM ciphertext plus a burned ratchet generation,
//! a GSS ciphertext and its durable history row, or the group's shared secret
//! sealed to a member — on an authorization that is no longer true.
//!
//! Each test states the claim it defends:
//!
//! - a marker installed mid-operation REFUSES with the slice-1 §5 body, and
//!   the effect does not happen: nothing published, no ratchet generation
//!   burned, no history row, no envelope handed out, every durable file
//!   byte-identical;
//! - the refusal is ATTRIBUTABLE to the re-check and not to the entry gate —
//!   each fixture asserts the live record carried no marker when the request
//!   began, and then asserts the refusal body names the revision of the
//!   marker the barrier injected, a value the entry gate could not have seen;
//! - a group with NO marker behaves exactly as it did before this slice — each
//!   install-mid-op test carries a CONTROL arm on a second, never-armed group
//!   that must still succeed. That pair is this slice's negative control:
//!   delete the re-check and the armed arm behaves like the control arm, so
//!   the test fails rather than passing quietly;
//! - and an ALIAS-KEYED group (roster map key ≠ stable group id) is not
//!   exempt, because the re-check resolves both spellings.
//!
//! Determinism: no sleeps anywhere. The interleaving is injected by
//! [`send_recheck_barrier`], which is `cfg(test)` end to end — a release build
//! compiles neither the module nor its call site — and which is keyed per
//! group id so these tests can run in parallel with each other and with the
//! rest of the binary.

use super::*;

use super::fork_quarantine::assert_fork_quarantine_refusal_body;
use crate::server::routes::named_groups::{
    reject_fork_quarantine_installed_before_effect, send_recheck_barrier,
};

/// The revision the injected marker carries. Distinctive so an assertion that
/// the refusal body names *this* marker cannot pass by coincidence.
const INJECTED_REVISION: u64 = 4_242;

/// A well-formed authenticated-evidence marker at [`INJECTED_REVISION`].
fn injected_marker(no_anchor: bool) -> x0x::groups::ForkQuarantine {
    let scratch = x0x::groups::GroupInfo::with_policy(
        "slice9-marker-snapshot".to_string(),
        String::new(),
        x0x::identity::AgentId([0u8; 32]),
        "slice9-marker-scratch".to_string(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    let header = scratch.terminal_commit_header();
    x0x::groups::ForkQuarantine {
        revision: INJECTED_REVISION,
        state_hash: "5e".repeat(32),
        committed_by: "ff".repeat(32),
        observed_at_ms: 1_700_000_009_999,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor,
    }
}

/// Arm the barrier so that the next send-path re-check for `lookup_id`
/// observes a freshly installed marker on the record filed under `map_key`.
///
/// The hook runs immediately before the re-check takes its read guard, which
/// is the tightest interleaving a concurrent writer can achieve against a
/// read-lock re-check — and precisely the interleaving the rule must survive.
fn arm_install(map_key: &str, lookup_id: &str) -> send_recheck_barrier::BarrierGuard {
    let owned_key = map_key.to_string();
    send_recheck_barrier::install(
        lookup_id,
        Box::new(move |groups| {
            if let Some(info) = groups.get_mut(&owned_key) {
                info.fork_quarantine = Some(injected_marker(true));
            }
        }),
    )
}

/// Assert the record filed under `map_key` carries no marker.
///
/// This is the PRECONDITION that makes every refusal below attributable to the
/// re-check: the entry gate reads the same field, so if it were already set the
/// gate would have refused and these tests would prove nothing about §4.
async fn assert_entry_gate_admitted(state: &AppState, map_key: &str) {
    assert!(
        !state
            .named_groups
            .read()
            .await
            .get(map_key)
            .expect("fixture group installed")
            .is_fork_quarantined(),
        "precondition: the entry gate must ADMIT this request — a marker already \
         present would mean the refusal came from the gate, not the §4 re-check"
    );
}

/// The refusal body is the slice-1 §5 one AND names the injected marker.
///
/// The revision clause is the attribution proof: at request start the live
/// record had no marker, so only a re-check that re-read the record after the
/// install can have produced this revision.
fn assert_recheck_refusal(body: &serde_json::Value) {
    assert_fork_quarantine_refusal_body(body);
    assert_eq!(
        body["fork_quarantine"]["revision"].as_u64(),
        Some(INJECTED_REVISION),
        "the body must name the marker the re-check observed, which the entry gate \
         could not have seen: {body}"
    );
    assert_eq!(
        body["fork_quarantine"]["no_anchor"].as_bool(),
        Some(true),
        "an ordinary group's marker surfaces `no_anchor` so the remedy named is the \
         one that can succeed: {body}"
    );
}

async fn roster_bytes(state: &AppState) -> Option<Vec<u8>> {
    tokio::fs::read(&state.named_groups_path).await.ok()
}

/// Rows in the durable MLS history store for one group scope.
fn mls_history_rows(state: &AppState, stable_group_id: &str) -> usize {
    let Some(history) = state.agent.history() else {
        panic!("the fixture needs a live history store to prove a row was NOT written")
    };
    history
        .store()
        .query(&x0x::history::HistoryQuery {
            scope: Some(x0x::history::Scope::Group(stable_group_id.to_string())),
            ..Default::default()
        })
        .expect("query group history")
        .len()
}

/// A **happens-after barrier** for the history writer, so "no row was written"
/// is a real zero and not a not-yet.
///
/// `record_mls_history` enqueues on the writer's channel and returns; the
/// commit happens on the writer thread. Polling with a sleep would make the
/// assertion timing-dependent, so instead this enqueues a sentinel through
/// `record_committed` — the SAME FIFO channel — and awaits its commit ack.
/// Once that ack arrives, every record enqueued before it has been written, so
/// a group whose row count is still zero never had one enqueued.
///
/// The sentinel lands under its own scope, so it cannot perturb the counts the
/// caller is asserting.
async fn drain_history_writer(state: &AppState, sentinel_scope: &str) {
    let Some(history) = state.agent.history() else {
        panic!("the fixture needs a live history store")
    };
    let now = i64::try_from(x0x::dm::now_unix_ms()).unwrap_or(i64::MAX);
    history
        .record_committed(x0x::history::HistoryRecord {
            msg_id: x0x::history::HistoryRecord::compute_epoch_msg_id(
                sentinel_scope,
                0,
                b"slice9 history barrier",
            ),
            scope: x0x::history::Scope::Group(sentinel_scope.to_string()),
            author_agent: None,
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: now,
            seen_at_ms: now,
            direction: x0x::history::Direction::Outbound,
            content_type: "text/plain".to_string(),
            payload: b"slice9 history barrier".to_vec(),
            signed_artifact: None,
            signature: None,
            sig_context: None,
            provenance: x0x::history::Provenance::LocalAppDecrypt,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        })
        .await
        .expect("the sentinel must commit, or the barrier proves nothing");
}

// ───────────────────── the rule, as a truth table ─────────────────────

/// The re-check's four cases, stated once so the rows below assert behaviour
/// rather than re-derive the rule.
///
/// The asymmetry is the clause worth reading: `Some(marker) -> None` (a marker
/// CLEARED mid-operation) does not refuse, and cannot occur, because an
/// operation is admitted only when the entry gate saw no marker. That is why
/// the live-side test — "a marker is present that the capture did not carry" —
/// is the whole rule for these rows, and why it differs on purpose from the
/// persist-lock re-check, which refuses on a clear too.
#[tokio::test]
async fn the_recheck_refuses_exactly_a_marker_that_appeared_or_changed() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let key = "slice9-truth-table";
    install_secure_endpoint_group(&state, key, key, x0x::mls::SecureGroupPlane::Gss).await;

    let clean = {
        let groups = state.named_groups.read().await;
        groups.get(key).expect("installed").lifecycle_epoch_token()
    };

    // absent marker -> absent marker: proceed. This is every unquarantined
    // group on the hot path, so a regression here is a total outage.
    assert!(
        reject_fork_quarantine_installed_before_effect(&state, key, Some(&clean))
            .await
            .is_none(),
        "a group with no marker must never be refused"
    );

    // no record at all: not a marker, and not this helper's question. The
    // withdrawn / not-found paths own record absence; inventing a quarantine
    // refusal here would change behaviour where no marker is involved.
    assert!(
        reject_fork_quarantine_installed_before_effect(&state, "slice9-no-such-group", None)
            .await
            .is_none(),
        "a resolver miss is not a marker"
    );

    // absent marker -> present marker: REFUSE. The single hazard §4 names.
    {
        let mut groups = state.named_groups.write().await;
        groups.get_mut(key).expect("installed").fork_quarantine = Some(injected_marker(true));
    }
    let (status, body) = reject_fork_quarantine_installed_before_effect(&state, key, Some(&clean))
        .await
        .expect("a marker that appeared mid-operation must refuse");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_recheck_refusal(&body.0);

    // present marker -> the SAME marker: no refusal. Unreachable for an
    // admitted operation, and asserted so the comparison stays an ADR-0067
    // identity equality rather than decaying into `is_fork_quarantined()`.
    let quarantined = {
        let groups = state.named_groups.read().await;
        groups.get(key).expect("installed").lifecycle_epoch_token()
    };
    assert!(
        reject_fork_quarantine_installed_before_effect(&state, key, Some(&quarantined))
            .await
            .is_none(),
        "the marker the operation was authorized with is not a change"
    );

    // The resolver's SECOND branch: a record filed under an alias key,
    // looked up by its stable id. Covered here rather than on a row, because
    // the rows reach the re-check through handlers that already resolved the
    // caller's spelling, while the helper itself must handle both.
    {
        let alias_key = "slice9-truth-table-alias-key";
        let alias_stable = "slice9-truth-table-alias-stable";
        install_secure_endpoint_group(
            &state,
            alias_key,
            alias_stable,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;
        let alias_clean = {
            let groups = state.named_groups.read().await;
            groups
                .get(alias_key)
                .expect("installed")
                .lifecycle_epoch_token()
        };
        assert!(
            reject_fork_quarantine_installed_before_effect(
                &state,
                alias_stable,
                Some(&alias_clean)
            )
            .await
            .is_none(),
            "a clean alias-keyed group resolved by stable id must not be refused"
        );
        state
            .named_groups
            .write()
            .await
            .get_mut(alias_key)
            .expect("installed")
            .fork_quarantine = Some(injected_marker(true));
        let (status, body) = reject_fork_quarantine_installed_before_effect(
            &state,
            alias_stable,
            Some(&alias_clean),
        )
        .await
        .expect("an alias-keyed record must be found by its stable id, or the check fails open");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_recheck_refusal(&body.0);
    }

    // present marker -> a DIFFERENT marker (advanced evidence): REFUSE.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(key).expect("installed");
        let mut advanced = injected_marker(true);
        advanced.revision = INJECTED_REVISION;
        advanced.state_hash = "ab".repeat(32);
        info.fork_quarantine = Some(advanced);
    }
    assert!(
        reject_fork_quarantine_installed_before_effect(&state, key, Some(&quarantined))
            .await
            .is_some(),
        "a marker advanced to different evidence is a change and must refuse"
    );
    Ok(())
}

// ───────── row 1 — POST /groups/:id/send, the gossip publish ─────────

/// **Row 1.** A marker installed between the entry gate and the publish must
/// stop the publish. This is the highest-severity of the four: the effect is
/// bytes on the gossip wire, which no local refusal can recall.
///
/// The CONTROL arm is a second, never-armed group in the same daemon that must
/// still publish — that pair is this row's negative control. Remove the
/// re-check and the armed arm publishes exactly like the control arm, failing
/// the `fan_out`/cache/status assertions below.
#[tokio::test]
async fn row1_marker_installed_before_publish_refuses_and_publishes_nothing() -> Result<()> {
    let plane = format!("slice9-row1-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let armed = insert_local_public_group(state.as_ref(), &"a1".repeat(16)).await;
    let control = insert_local_public_group(state.as_ref(), &"a2".repeat(16)).await;

    // ── control arm: no marker, no injection. Must behave as before. ──
    let publishes_before = state
        .agent
        .gossip_stats()
        .map(|s| s.publish_zero_fanout)
        .unwrap_or(0);
    let (status, body) = post_group_send(Arc::clone(&state), &control, "control").await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unquarantined send must be untouched by this slice: {body}"
    );
    assert!(
        body["msg_id"].as_str().is_some(),
        "the control arm publishes and reports a msg_id: {body}"
    );
    let publishes_after_control = state
        .agent
        .gossip_stats()
        .map(|s| s.publish_zero_fanout)
        .unwrap_or(0);
    assert_eq!(
        publishes_after_control,
        publishes_before + 1,
        "the control arm must reach the gossip publish — otherwise the armed arm below \
         proves nothing"
    );

    // ── armed arm: the marker lands just before the publish. ──
    assert_entry_gate_admitted(&state, &armed).await;
    let roster_before = roster_bytes(&state).await;
    let guard = arm_install(&armed, &armed);
    let (status, body) =
        post_group_send(Arc::clone(&state), &armed, "must not reach the wire").await?;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a marker installed before the publish must refuse: {body}"
    );
    assert_recheck_refusal(&body);
    assert!(
        body.get("msg_id").is_none(),
        "a refusal must not report a message id: {body}"
    );
    assert_eq!(
        state
            .agent
            .gossip_stats()
            .map(|s| s.publish_zero_fanout)
            .unwrap_or(0),
        publishes_after_control,
        "NOTHING was published — the gossip publish counter did not move"
    );
    let stable = state
        .named_groups
        .read()
        .await
        .get(&armed)
        .expect("armed group")
        .stable_group_id()
        .to_string();
    assert!(
        !state.public_messages.read().await.contains_key(&stable),
        "the local hot-tail cache is written only after a successful publish, so a \
         refusal must leave it empty"
    );
    assert_eq!(
        roster_bytes(&state).await,
        roster_before,
        "the send path persists no roster state, and a refusal must not change that"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// A SignedPublic group whose roster map key is deliberately NOT its stable
/// group id — the shape a daemon ends up in when it learned the group under an
/// alias. `insert_local_public_group` cannot produce it: with no genesis the
/// stable id falls back to the map key.
async fn insert_alias_keyed_public_group(
    state: &Arc<AppState>,
    map_key: &str,
    stable_group_id: &str,
) {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "slice9-alias-public".to_string(),
        String::new(),
        state.agent.agent_id(),
        map_key.to_string(),
        x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        stable_group_id.to_string(),
        hex::encode(state.agent.agent_id().as_bytes()),
        info.created_at,
        String::new(),
    ));
    state
        .named_groups
        .write()
        .await
        .insert(map_key.to_string(), info);
}

/// **Row 1, alias-keyed.** The roster map is keyed by whichever spelling this
/// daemon learned the group under, and `stable_group_id()` can differ from that
/// key. A re-check that looked the group up by stable id alone would miss an
/// alias-keyed record and fail OPEN, so this fixture pins the resolver.
#[tokio::test]
async fn row1_alias_keyed_group_is_not_exempt() -> Result<()> {
    let plane = format!("slice9-row1-alias-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let key = "slice9-row1-alias-key";
    let stable = "slice9-row1-alias-stable";
    assert_ne!(key, stable, "fixture precondition");
    insert_alias_keyed_public_group(&state, key, stable).await;
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(key)
            .expect("group installed")
            .stable_group_id(),
        stable,
        "fixture precondition: the record's stable id is not its map key, or this test \
         degenerates into the plain one"
    );

    assert_entry_gate_admitted(&state, key).await;
    let _guard = arm_install(key, key);
    let (status, body) = post_group_send(Arc::clone(&state), key, "alias").await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an alias-keyed group must be re-checked exactly like a stable-keyed one: {body}"
    );
    assert_recheck_refusal(&body);
    state.agent.shutdown().await;
    Ok(())
}

// ────────────── row 2 — TreeKEM encrypt, the send ratchet ──────────────

/// Seed a real TreeKEM group into BOTH the roster map and the live
/// `treekem_groups` map, filed under `map_key` with `stable_group_id` as its
/// genesis id, and with the live ratchet keyed by `live_key`.
///
/// `live_key` is a parameter because the two maps are keyed INDEPENDENTLY.
/// The roster is keyed by whichever alias this daemon learned the group under;
/// `treekem_groups` is keyed by whatever the loader filed it under, and #750's
/// own fixtures (`adr0066_treekem_gates.rs::alias_keyed_treekem_group`) seed it
/// under the STABLE spelling — the TOCTOU end state where the roster has been
/// re-keyed and the live map has not followed. Which spelling reaches the
/// ratchet is therefore state, not an invariant, and the row-2 fixtures below
/// exercise both.
async fn seed_treekem_keyed(
    state: &Arc<AppState>,
    map_key: &str,
    stable_group_id: &str,
    live_key: &str,
    id_byte: u8,
) -> Result<Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>> {
    let group_id_bytes = vec![id_byte; 32];
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, state.agent.agent_id(), &seed)?;
    let epoch = group.epoch();
    install_secure_endpoint_group(
        state,
        map_key,
        stable_group_id,
        x0x::mls::SecureGroupPlane::TreeKem,
    )
    .await;
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(map_key).expect("group installed");
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
    }
    let handle = Arc::new(tokio::sync::Mutex::new(group));
    state
        .treekem_groups
        .write()
        .await
        .insert(live_key.to_string(), Arc::clone(&handle));
    Ok(handle)
}

/// The ordinary shape: both maps keyed the same way.
async fn seed_treekem(
    state: &Arc<AppState>,
    map_key: &str,
    stable_group_id: &str,
    id_byte: u8,
) -> Result<Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>> {
    seed_treekem_keyed(state, map_key, stable_group_id, map_key, id_byte).await
}

/// **Row 2.** The TreeKEM effect is a RATCHET ADVANCE, so the re-check has to
/// run before `encrypt_message`, not after it: a refusal that arrived later
/// would have burned a send generation no message ever used, and PR #750's
/// alias fixtures assert the ratchet epoch is unmoved on a refusal.
///
/// "Unmoved" is asserted on the group's own snapshot bytes, not just its
/// epoch: an MLS epoch does not move per message, while the send generation
/// inside the snapshot does. Byte-identical snapshot bytes are therefore the
/// exact statement "no generation was burned".
///
/// The control arm on a second, never-armed group is this row's negative
/// control: with the re-check deleted the armed arm encrypts, its snapshot
/// bytes move and the assertions below fail.
#[tokio::test]
async fn row2_marker_installed_before_encrypt_refuses_with_the_ratchet_unmoved() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let armed_key = "slice9-row2-armed";
    let control_key = "slice9-row2-control";
    let armed_group = seed_treekem(&state, armed_key, armed_key, 0x21).await?;
    let control_group = seed_treekem(&state, control_key, control_key, 0x22).await?;

    // ── control arm: no marker, no injection. ──
    let (status, body) = treekem_group_encrypt(
        state.as_ref(),
        control_key,
        Some(control_key),
        "aGVsbG8=",
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unquarantined TreeKEM encrypt must be untouched by this slice: {}",
        body.0
    );
    assert!(
        body.0["ciphertext_b64"].as_str().is_some(),
        "the control arm produces a ciphertext: {}",
        body.0
    );
    assert!(
        control_group.lock().await.to_snapshot_bytes().is_ok(),
        "the control group's ratchet is intact after a successful encrypt"
    );

    // ── armed arm: the marker lands while the group mutex is held, one
    //    statement before the ratchet would advance. ──
    assert_entry_gate_admitted(&state, armed_key).await;
    let ratchet_before = armed_group.lock().await.to_snapshot_bytes()?;
    let epoch_before = armed_group.lock().await.epoch();
    let snapshot_path_exists_before = state.treekem_dir.join(format!("{armed_key}.snap")).exists();

    let guard = arm_install(armed_key, armed_key);
    let (status, body) =
        treekem_group_encrypt(state.as_ref(), armed_key, Some(armed_key), "aGVsbG8=", None).await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a marker installed before the ratchet advance must refuse: {}",
        body.0
    );
    assert_recheck_refusal(&body.0);
    assert!(
        body.0.get("ciphertext_b64").is_none(),
        "a refusal must hand out no ciphertext: {}",
        body.0
    );
    assert_eq!(
        armed_group.lock().await.to_snapshot_bytes()?,
        ratchet_before,
        "THE RATCHET IS UNMOVED: byte-identical snapshot state means no send \
         generation was burned on a refusal"
    );
    assert_eq!(
        armed_group.lock().await.epoch(),
        epoch_before,
        "the group epoch is unmoved too"
    );
    assert_eq!(
        state.treekem_dir.join(format!("{armed_key}.snap")).exists(),
        snapshot_path_exists_before,
        "the advanced-state persist is never reached, so no snapshot is written"
    );
    Ok(())
}

/// **Row 2, alias-keyed, MAP-KEY spelling.** A group whose roster map key is
/// not its stable id must still be re-checked, and its ratchet must still be
/// unmoved on the refusal.
///
/// The stable-id spelling gets its own fixture below. An earlier revision of
/// this file claimed that spelling was unreachable because `treekem_groups` is
/// "keyed by the local group key" — #750 showed that is state, not an
/// invariant, and its own fixtures build the opposite state deliberately.
#[tokio::test]
async fn row2_alias_keyed_group_is_not_exempt() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let key = "slice9-row2-alias-key";
    let stable = "slice9-row2-alias-stable";
    assert_ne!(key, stable, "fixture precondition");
    let group = seed_treekem(&state, key, stable, 0x23).await?;
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(key)
            .expect("installed")
            .stable_group_id(),
        stable,
        "fixture precondition: the record's stable id is not its map key"
    );
    let ratchet_before = group.lock().await.to_snapshot_bytes()?;

    assert_entry_gate_admitted(&state, key).await;
    let _guard = arm_install(key, key);
    let (status, body) =
        treekem_group_encrypt(state.as_ref(), key, Some(stable), "aGVsbG8=", None).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an alias-keyed group must be re-checked exactly like a stable-keyed one: {}",
        body.0
    );
    assert_recheck_refusal(&body.0);
    assert_eq!(
        group.lock().await.to_snapshot_bytes()?,
        ratchet_before,
        "the refusal burned no generation"
    );
    Ok(())
}

/// **Row 2, alias-keyed, STABLE-ID spelling — the TOCTOU end state #750 named.**
///
/// The roster is keyed by an alias while `treekem_groups` holds the live
/// ratchet under the STABLE id: the state left behind when a roster re-key is
/// not mirrored into the live map. That is exactly the configuration
/// `adr0066_treekem_gates.rs::alias_keyed_treekem_group` builds, and in it a
/// stable-id caller is **not** stopped by the 424 — it resolves the roster
/// through the shared resolver, finds the ratchet under its own spelling, and
/// reaches the effect. So the §4 re-check has to hold on this spelling too,
/// and this fixture is what says so.
///
/// Three assertions, in the order that makes each meaningful:
///
/// 1. a REACHABILITY control first — with no marker, the same stable-id call
///    must NOT be a 424; if this ever starts failing, the spelling has become
///    unreachable again and the refusal below would be proving nothing;
/// 2. install-mid-op ⇒ §5 refusal naming the injected marker;
/// 3. `to_snapshot_bytes()` byte-identical — no generation burned, the same
///    property PR #750's alias fixtures pin.
#[tokio::test]
async fn row2_stable_id_spelling_reaches_the_recheck_and_is_refused() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let key = "slice9-row2-toctou-key";
    let stable = "slice9-row2-toctou-stable";
    assert_ne!(key, stable, "fixture precondition");
    // Roster under the alias; live ratchet under the stable id.
    let group = seed_treekem_keyed(&state, key, stable, stable, 0x24).await?;
    let ratchet_before = group.lock().await.to_snapshot_bytes()?;

    // (1) Reachability control: unarmed, the stable-id call must get PAST the
    //     `treekem_groups` lookup and actually reach the ratchet. A 424 here
    //     would mean this spelling never reaches the re-check, and the refusal
    //     below would be vacuous.
    //
    //     Reachability is asserted as "not 424 AND the ratchet moved", NOT as a
    //     200. In this state a clean call reaches the ratchet, advances it, and
    //     then fails its snapshot persist with a 500: `persist_treekem_snapshot_bound`
    //     still resolves ONE spelling (`groups.get(group_id_hex)`), so it cannot
    //     find an alias-keyed roster record by stable id. That is a PRE-EXISTING
    //     gap on a non-quarantine path — a burned generation with no persisted
    //     snapshot — reported separately, not introduced or fixed here. Binding
    //     this control to a 200 would couple the §4 fixture to that unrelated
    //     bug's lifetime; the moved ratchet is the direct evidence the effect
    //     point was reached, which is all this control needs to establish.
    assert_entry_gate_admitted(&state, key).await;
    let (status, body) =
        treekem_group_encrypt(state.as_ref(), stable, Some(stable), "aGVsbG8=", None).await;
    assert_ne!(
        status,
        StatusCode::FAILED_DEPENDENCY,
        "the stable-id spelling must REACH the ratchet in this state, or the refusal \
         below proves nothing: {}",
        body.0
    );
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "no marker is installed, so nothing may refuse this call: {}",
        body.0
    );
    // That control DID advance the ratchet, so re-baseline before the armed arm.
    let ratchet_after_control = group.lock().await.to_snapshot_bytes()?;
    assert_ne!(
        ratchet_after_control, ratchet_before,
        "the control call must have REACHED and moved the ratchet — this is the \
         reachability proof, and without it 'unmoved' below is not a property this \
         fixture can observe"
    );

    // (2) + (3) Armed: the marker lands between the entry gate and the advance.
    assert_entry_gate_admitted(&state, key).await;
    let _guard = arm_install(key, stable);
    let (status, body) =
        treekem_group_encrypt(state.as_ref(), stable, Some(stable), "aGVsbG8=", None).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a stable-id caller that reaches the ratchet must be re-checked too: {}",
        body.0
    );
    assert_recheck_refusal(&body.0);
    assert!(
        body.0.get("ciphertext_b64").is_none(),
        "a refusal hands out no ciphertext: {}",
        body.0
    );
    assert_eq!(
        group.lock().await.to_snapshot_bytes()?,
        ratchet_after_control,
        "THE RATCHET IS UNMOVED on the stable spelling too — no send generation burned"
    );
    Ok(())
}

// ────────── row 4 — POST /groups/:id/secure/encrypt (GSS plane) ──────────

fn encrypt_request() -> Result<SecureEncryptRequest> {
    Ok(serde_json::from_value(
        serde_json::json!({ "payload_b64": "aGVsbG8=" }),
    )?)
}

/// **Row 4.** The GSS plane has no ratchet — a fixed epoch key with a fresh
/// random nonce per message — so there is no generation to burn. Its
/// irreversible effects are the durable history row and the ciphertext handed
/// back to the caller, and both are stopped by refusing before
/// `record_mls_history`.
///
/// The control arm on a second, never-armed group is this row's negative
/// control.
#[tokio::test]
async fn row4_marker_installed_before_effect_refuses_and_records_no_history() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let armed = "slice9-row4-armed";
    let control = "slice9-row4-control";
    install_secure_endpoint_group(&state, armed, armed, x0x::mls::SecureGroupPlane::Gss).await;
    install_secure_endpoint_group(&state, control, control, x0x::mls::SecureGroupPlane::Gss).await;

    // ── control arm ──
    let (status, body) = secure_group_encrypt(
        State(Arc::clone(&state)),
        Path(control.to_string()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(encrypt_request()?),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unquarantined GSS encrypt must be untouched by this slice: {}",
        body.0
    );
    assert!(
        body.0["ciphertext_b64"].as_str().is_some(),
        "the control arm produces a ciphertext: {}",
        body.0
    );

    // ── armed arm ──
    assert_entry_gate_admitted(&state, armed).await;
    let roster_before = roster_bytes(&state).await;
    let epoch_before = state
        .named_groups
        .read()
        .await
        .get(armed)
        .expect("installed")
        .secret_epoch;

    let guard = arm_install(armed, armed);
    let (status, body) = secure_group_encrypt(
        State(Arc::clone(&state)),
        Path(armed.to_string()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(encrypt_request()?),
    )
    .await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a marker installed before the effect must refuse: {}",
        body.0
    );
    assert_recheck_refusal(&body.0);
    assert!(
        body.0.get("ciphertext_b64").is_none() && body.0.get("nonce_b64").is_none(),
        "a refusal must hand out neither ciphertext nor nonce: {}",
        body.0
    );
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(armed)
            .expect("installed")
            .secret_epoch,
        epoch_before,
        "the GSS epoch is unmoved — there is no generation to burn and none was"
    );

    // THE DURABLE HISTORY ROW — the effect this test is named for (omp review
    // nit 1: asserting the epoch and the roster did not cover it).
    //
    // Barrier first, so the zero below is a real zero: the history writer
    // commits on its own thread, and every record enqueued before the sentinel
    // is committed by the time the sentinel's ack arrives. The control arm's
    // row is asserted present through the SAME barrier, so the mechanism is
    // proven capable of landing a row on this state — a `0` for the armed group
    // therefore means `record_mls_history` was never reached, not that the
    // write is still in flight.
    drain_history_writer(&state, "slice9-row4-history-barrier").await;
    assert_eq!(
        mls_history_rows(&state, control),
        1,
        "the control arm's encrypt MUST have written its history row — without this the \
         armed arm's zero would prove nothing about the re-check"
    );
    assert_eq!(
        mls_history_rows(&state, armed),
        0,
        "NO HISTORY ROW: the refusal happens before `record_mls_history`, so the \
         quarantined group's plaintext never reaches the durable store"
    );
    assert_eq!(
        roster_bytes(&state).await,
        roster_before,
        "a refusal persists nothing"
    );
    Ok(())
}

/// **Row 4, alias-keyed.** The route's `:id` is the roster map key while the
/// group's stable id differs; the re-check must resolve the spelling the route
/// gave it.
#[tokio::test]
async fn row4_alias_keyed_group_is_not_exempt() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let key = "slice9-row4-alias-key";
    let stable = "slice9-row4-alias-stable";
    assert_ne!(key, stable, "fixture precondition");
    install_secure_endpoint_group(&state, key, stable, x0x::mls::SecureGroupPlane::Gss).await;
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(key)
            .expect("installed")
            .stable_group_id(),
        stable,
        "fixture precondition: the record's stable id is not its map key"
    );

    assert_entry_gate_admitted(&state, key).await;
    let _guard = arm_install(key, key);
    let (status, body) = secure_group_encrypt(
        State(Arc::clone(&state)),
        Path(key.to_string()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(encrypt_request()?),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an alias-keyed group must be re-checked exactly like a stable-keyed one: {}",
        body.0
    );
    assert_recheck_refusal(&body.0);
    Ok(())
}

// ─────────── row 6 — POST /groups/:id/secure/reseal (GSS plane) ───────────

/// Give the local agent a published KEM key on `map_key` so it can be its own
/// reseal recipient, and return that recipient hex.
async fn seal_recipient(state: &Arc<AppState>, map_key: &str) -> String {
    let recipient = hex::encode(state.agent.agent_id().as_bytes());
    state
        .named_groups
        .write()
        .await
        .get_mut(map_key)
        .expect("group installed")
        .set_member_kem_public_key(
            &recipient,
            BASE64.encode(&state.agent_kem_keypair.public_bytes),
        );
    recipient
}

/// **Row 6.** Reseal persists nothing and advances no ratchet: its effect is
/// that the group's SHARED SECRET, sealed to a member's ML-KEM key, leaves the
/// node in the response. A contested group must not hand its key material
/// onward, so the re-check runs immediately before the response is built and
/// the computed envelope is discarded.
///
/// The control arm on a second, never-armed group is this row's negative
/// control.
#[tokio::test]
async fn row6_marker_installed_before_return_hands_out_no_envelope() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let armed = "slice9-row6-armed";
    let control = "slice9-row6-control";
    install_secure_endpoint_group(&state, armed, armed, x0x::mls::SecureGroupPlane::Gss).await;
    install_secure_endpoint_group(&state, control, control, x0x::mls::SecureGroupPlane::Gss).await;
    let armed_recipient = seal_recipient(&state, armed).await;
    let control_recipient = seal_recipient(&state, control).await;

    // ── control arm ──
    let (status, body) = secure_group_reseal(
        State(Arc::clone(&state)),
        Path(control.to_string()),
        Json(ResealRequest {
            recipient: control_recipient,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unquarantined reseal must be untouched by this slice: {}",
        body.0
    );
    assert!(
        body.0["kem_ciphertext_b64"].as_str().is_some(),
        "the control arm produces a sealed envelope: {}",
        body.0
    );

    // ── armed arm ──
    assert_entry_gate_admitted(&state, armed).await;
    let roster_before = roster_bytes(&state).await;
    let epoch_before = state
        .named_groups
        .read()
        .await
        .get(armed)
        .expect("installed")
        .secret_epoch;
    let guard = arm_install(armed, armed);
    let (status, body) = secure_group_reseal(
        State(Arc::clone(&state)),
        Path(armed.to_string()),
        Json(ResealRequest {
            recipient: armed_recipient,
        }),
    )
    .await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a marker installed before the return must refuse: {}",
        body.0
    );
    assert_recheck_refusal(&body.0);
    for field in [
        "kem_ciphertext_b64",
        "aead_nonce_b64",
        "aead_ciphertext_b64",
    ] {
        assert!(
            body.0.get(field).is_none(),
            "a refusal must not hand out {field} — the sealed secret never leaves the \
             node: {}",
            body.0
        );
    }
    // omp review nit 2: assert the epoch is unmoved here as row 4 already
    // does. A reseal seals the CURRENT `secret_epoch`, so the epoch is the
    // state a refusal must leave alone — if a future change ever rotated the
    // secret as part of resealing, this refusal would have to roll that back
    // and this assertion is what would fail first.
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(armed)
            .expect("installed")
            .secret_epoch,
        epoch_before,
        "the GSS epoch is unmoved — a refused reseal rotates nothing"
    );
    assert_eq!(
        roster_bytes(&state).await,
        roster_before,
        "a refusal persists nothing"
    );
    Ok(())
}

/// **Row 6, alias-keyed.**
#[tokio::test]
async fn row6_alias_keyed_group_is_not_exempt() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let key = "slice9-row6-alias-key";
    let stable = "slice9-row6-alias-stable";
    assert_ne!(key, stable, "fixture precondition");
    install_secure_endpoint_group(&state, key, stable, x0x::mls::SecureGroupPlane::Gss).await;
    let recipient = seal_recipient(&state, key).await;
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(key)
            .expect("installed")
            .stable_group_id(),
        stable,
        "fixture precondition: the record's stable id is not its map key"
    );

    assert_entry_gate_admitted(&state, key).await;
    let _guard = arm_install(key, key);
    let (status, body) = secure_group_reseal(
        State(Arc::clone(&state)),
        Path(key.to_string()),
        Json(ResealRequest { recipient }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an alias-keyed group must be re-checked exactly like a stable-keyed one: {}",
        body.0
    );
    assert_recheck_refusal(&body.0);
    Ok(())
}
