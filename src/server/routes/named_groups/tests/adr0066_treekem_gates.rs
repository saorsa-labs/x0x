//! #732 — the two TreeKEM crypto gates fire for an ALIAS-KEYED roster.
//!
//! WHY, precisely (cross-model review of PR #750). On `origin/main` both
//! `treekem_group_encrypt` and `treekem_group_decrypt` wrapped BOTH of their
//! pre-crypto gates — `reject_unverified_owner_certified_restore` (ADR-0038
//! restore authority) and `reject_fork_quarantined` (ADR-0066 §3) — in a single
//! `if let Some(info) = groups.get(group_id_hex)`. A miss therefore skipped
//! both and let the ratchet advance: the only arm in this family that fails
//! OPEN rather than 404-ing.
//!
//! The reviewer confirmed that mechanism but NOT a deterministic remote
//! bypass: these two helpers' only callers (`secure_group_encrypt`/`_decrypt`)
//! 404 an unknown spelling at route level first and run both gates on the map
//! key under the same lock hold. The reachable shape is a TOCTOU — the roster
//! is re-keyed between the route's `drop(groups)` and this inner re-acquire
//! while `treekem_groups` still holds the old spelling. This fixture builds
//! exactly that end state and calls the helper directly, which is what makes
//! it a test of the gate rather than of the route above it:
//!
//! - `named_groups` keyed by a LOCAL ALIAS,
//! - `treekem_groups` keyed by the STABLE id (the spelling the caller and the
//!   live ratchet still use — deliberately not the alias, because an alias-keyed
//!   ratchet entry would answer 424 `TreeKEM group not loaded` and prove
//!   nothing about the gate),
//! - the helper called with the STABLE id.
//!
//! Each test asserts the refusal AND that the ratchet epoch did not move, so a
//! gate that refuses after burning a generation would still fail.
//!
//! The same end state also covers the CLEAN direction — known gap (g) of
//! `docs/runbooks/fork-quarantine.md`. Cross-model review of PR #751 found that
//! `named_groups.rs::persist_treekem_snapshot_bound` resolved only one spelling,
//! so a clean alias-keyed encrypt passed both gates, advanced the send ratchet
//! and then 500'd on the persist, burning a generation whose ciphertext was
//! discarded. See
//! `issue732_treekem_encrypt_persists_the_snapshot_for_an_alias_keyed_group`.

use super::*;

/// `(alias_key, stable_id, live ratchet)` for one MlsEncrypted/TreeKEM group
/// whose roster entry is filed under an alias.
async fn alias_keyed_treekem_group(
    state: &AppState,
    alias_key: &str,
    genesis_id: &str,
) -> Result<(
    String,
    String,
    Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>,
)> {
    let group_id_bytes = hex::decode(genesis_id)?;
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let group =
        x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), state.agent.agent_id(), &seed)?;
    let epoch = group.epoch();
    let mut info = x0x::groups::GroupInfo::with_policy(
        "issue732-treekem-gates".to_string(),
        "alias-keyed TreeKEM fixture".to_string(),
        state.agent.agent_id(),
        genesis_id.to_string(),
        x0x::groups::GroupPolicy {
            discoverability: x0x::groups::GroupDiscoverability::Hidden,
            admission: x0x::groups::GroupAdmission::InviteOnly,
            confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.secret_epoch = epoch;
    info.security_binding = Some(format!("treekem:epoch={epoch}"));
    let stable = info.stable_group_id().to_string();
    assert_ne!(
        stable, alias_key,
        "fixture precondition: the roster key must NOT be the stable id"
    );
    state
        .named_groups
        .write()
        .await
        .insert(alias_key.to_string(), info);
    let live = Arc::new(tokio::sync::Mutex::new(group));
    // Under the STABLE spelling: the ratchet the caller would reach if the
    // roster gate missed. This is the TOCTOU end state, not a hand-picked
    // convenience — see the module docs.
    state
        .treekem_groups
        .write()
        .await
        .insert(stable.clone(), Arc::clone(&live));
    Ok((alias_key.to_string(), stable, live))
}

fn marker(info: &x0x::groups::GroupInfo) -> x0x::groups::ForkQuarantine {
    x0x::groups::ForkQuarantine {
        revision: 7,
        state_hash: info.state_hash.clone(),
        committed_by: "9e".repeat(32),
        observed_at_ms: 1_726_000_000_000,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: info.terminal_commit_header(),
            conflicting_commit: info.terminal_commit_header(),
            classification: None,
        },
        no_anchor: true,
    }
}

/// Mutate the roster record filed under `alias_key`.
async fn amend(state: &AppState, alias_key: &str, f: impl FnOnce(&mut x0x::groups::GroupInfo)) {
    let mut groups = state.named_groups.write().await;
    if let Some(info) = groups.get_mut(alias_key) {
        f(info);
    }
}

/// ADR-0066 §3: encrypt refuses with the §5 body, and the ratchet is untouched.
#[tokio::test]
async fn issue732_treekem_encrypt_gate_fires_for_an_alias_keyed_quarantined_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (alias_key, stable_id, live) =
        alias_keyed_treekem_group(&state, &"5e".repeat(16), &"a7".repeat(32)).await?;
    amend(&state, &alias_key, |info| {
        info.fork_quarantine = Some(marker(info));
    })
    .await;
    let epoch_before = live.lock().await.epoch();

    let (status, body) = treekem_group_encrypt(&state, &stable_id, None, "aGVsbG8=", None).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the §3 gate must fire on the stable spelling: {}",
        body.0
    );
    assert_eq!(
        body.0["reason"].as_str(),
        Some("fork_quarantined"),
        "ADR-0066 §5: clients match on `reason`: {}",
        body.0
    );
    assert_eq!(
        live.lock().await.epoch(),
        epoch_before,
        "a refusal before the crypto must not burn a ratchet generation"
    );
    Ok(())
}

/// ADR-0066 §3: decrypt refuses identically. The base64 decode happens before
/// the gate, so a valid-but-meaningless ciphertext is enough to reach it.
#[tokio::test]
async fn issue732_treekem_decrypt_gate_fires_for_an_alias_keyed_quarantined_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (alias_key, stable_id, live) =
        alias_keyed_treekem_group(&state, &"6f".repeat(16), &"b8".repeat(32)).await?;
    amend(&state, &alias_key, |info| {
        info.fork_quarantine = Some(marker(info));
    })
    .await;
    let epoch_before = live.lock().await.epoch();

    let (status, body) = treekem_group_decrypt(&state, &stable_id, None, "aGVsbG8=").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the §3 gate must fire before any decrypt attempt: {}",
        body.0
    );
    assert_eq!(
        body.0["reason"].as_str(),
        Some("fork_quarantined"),
        "{}",
        body.0
    );
    assert_eq!(live.lock().await.epoch(), epoch_before);
    Ok(())
}

/// The OTHER gate in the same `if let`: ADR-0038's restore re-verification.
/// It shared the single-spelling lookup, so it was skipped by the same miss —
/// which is why the fix is not only about quarantine.
#[tokio::test]
async fn issue732_treekem_gates_fire_for_an_alias_keyed_unverified_restore() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (alias_key, stable_id, live) =
        alias_keyed_treekem_group(&state, &"7a".repeat(16), &"c9".repeat(32)).await?;
    amend(&state, &alias_key, |info| {
        // No fork marker: this isolates the ADR-0038 gate.
        info.owner_cert_reverify_required = true;
    })
    .await;
    let epoch_before = live.lock().await.epoch();

    for (label, (status, body)) in [
        (
            "encrypt",
            treekem_group_encrypt(&state, &stable_id, None, "aGVsbG8=", None).await,
        ),
        (
            "decrypt",
            treekem_group_decrypt(&state, &stable_id, None, "aGVsbG8=").await,
        ),
    ] {
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{label}: the ADR-0038 restore gate must fire: {}",
            body.0
        );
        assert!(
            body.0["error"]
                .as_str()
                .unwrap_or_default()
                .contains("state re-verification"),
            "{label}: the ADR-0038 remedy names the seal route: {}",
            body.0
        );
    }
    assert_eq!(
        live.lock().await.epoch(),
        epoch_before,
        "neither call burned a ratchet generation"
    );
    Ok(())
}

/// The control in the other direction: a clean alias-keyed group is NOT
/// refused by either gate. Without this, "the gate fires" could just mean
/// "the resolver refuses everything it resolves".
#[tokio::test]
async fn issue732_treekem_gates_do_not_refuse_a_clean_alias_keyed_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (_alias_key, stable_id, _live) =
        alias_keyed_treekem_group(&state, &"8b".repeat(16), &"da".repeat(32)).await?;

    let (status, body) = treekem_group_encrypt(&state, &stable_id, None, "aGVsbG8=", None).await;
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "no marker and no restore flag: neither gate may refuse: {}",
        body.0
    );
    Ok(())
}

/// The per-sender generation counter of an encoded `ApplicationCiphertext`.
///
/// Read off the wire bytes rather than the live group because
/// `TreeKemMlsGroup` exposes no send-generation accessor — and the wire value
/// is the one that matters: it is what pins the AEAD nonce, so "the same
/// generation twice" is exactly the reuse the snapshot persist exists to
/// prevent.
fn ciphertext_generation(ciphertext_b64: &str) -> Result<u32> {
    use base64::Engine as _;
    let bytes = BASE64.decode(ciphertext_b64)?;
    let ct: saorsa_mls::treekem_group::ApplicationCiphertext = postcard::from_bytes(&bytes)?;
    Ok(ct.generation)
}

/// #732 known gap (g): the CLEAN alias-keyed encrypt must SUCCEED, not 500.
///
/// WHY this matters, and why the control above could not see it. That control
/// asserts only `status != CONFLICT`, so it passed while the route answered
/// 500: both gates resolved the alias-keyed roster and let the encrypt through
/// (which is what it was written to prove), the send ratchet advanced, and then
/// `persist_treekem_snapshot_bound`'s bare `groups.get(group_id_hex)` missed the
/// alias-keyed entry and failed the request. The generation was burned and its
/// ciphertext discarded — an availability defect, not a confidentiality one: a
/// burned generation is never reused, so there is no nonce reuse.
///
/// So the assertions here are the three things a correct persist owes the
/// caller, and each can fail on its own:
///
/// 1. the request succeeds and returns a ciphertext (500 before the fix);
/// 2. the snapshot is on disk AND is the ADVANCED ratchet, byte-for-byte —
///    a persist that wrote a pre-encrypt snapshot would restore a state that
///    re-issues this generation after a restart, which IS nonce reuse;
/// 3. the generation advances EXACTLY once per accepted encrypt (0 then 1),
///    so neither a skipped nor a repeated generation passes.
///
/// Then a round-trip decrypt of the first ciphertext, to prove the advanced,
/// persisted state is still a usable ratchet rather than merely a changed one.
#[tokio::test]
async fn issue732_treekem_encrypt_persists_the_snapshot_for_an_alias_keyed_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let (alias_key, stable_id, live) =
        alias_keyed_treekem_group(&state, &"9c".repeat(16), &"eb".repeat(32)).await?;
    let snapshot_path = treekem_snapshot_path(&state.treekem_dir, &stable_id);
    assert!(
        !tokio::fs::try_exists(&snapshot_path).await?,
        "fixture precondition: nothing is persisted yet"
    );

    let (status, body) = treekem_group_encrypt(&state, &stable_id, None, "aGVsbG8=", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a clean alias-keyed encrypt must not burn a generation on a persist \
         that cannot find the roster entry the gates just resolved: {}",
        body.0
    );
    let first = body.0["ciphertext_b64"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !first.is_empty(),
        "the route returns a ciphertext: {}",
        body.0
    );

    // (2) the persisted snapshot is the POST-encrypt ratchet, byte-for-byte.
    let envelope = decode_treekem_snapshot_envelope(&tokio::fs::read(&snapshot_path).await?)?
        .ok_or_else(|| anyhow::anyhow!("persisted bytes are not a TreeKEM snapshot envelope"))?;
    assert_eq!(
        envelope.snapshot,
        live.lock().await.to_snapshot_bytes()?,
        "the snapshot must capture the ADVANCED ratchet, not the state before \
         the encrypt"
    );
    {
        let groups = state.named_groups.read().await;
        let info = groups
            .get(&alias_key)
            .ok_or_else(|| anyhow::anyhow!("alias-keyed roster entry vanished"))?;
        assert!(
            treekem_snapshot_envelope_matches_info(&envelope, info),
            "the envelope binds to the ALIAS-keyed roster entry the gates \
             resolved, not to some other record"
        );
    }

    // (3) exactly one generation per accepted encrypt.
    assert_eq!(
        ciphertext_generation(&first)?,
        0,
        "the first encrypt on a fresh ratchet is generation 0"
    );
    let (status, body) = treekem_group_encrypt(&state, &stable_id, None, "aGVsbG8=", None).await;
    assert_eq!(status, StatusCode::OK, "{}", body.0);
    assert_eq!(
        ciphertext_generation(body.0["ciphertext_b64"].as_str().unwrap_or_default())?,
        1,
        "the ratchet advanced exactly once per accepted encrypt — a burned \
         generation would show up here as a skip"
    );

    // The advanced, persisted ratchet is still usable.
    let (status, body) = treekem_group_decrypt(&state, &stable_id, None, &first).await;
    assert_eq!(status, StatusCode::OK, "round-trip decrypt: {}", body.0);
    assert_eq!(
        body.0["payload_b64"].as_str(),
        Some("aGVsbG8="),
        "the plaintext round-trips: {}",
        body.0
    );
    Ok(())
}
