//! ADR-0066 §4 / ADR-0067 (slice 7) — the lifecycle epoch token, re-checked
//! under the persist lock.
//!
//! WHY these tests exist. Slices 1–6 all check the `fork_quarantine` marker
//! at the START of an operation. §4 names the window they leave: a marker
//! installed — or cleared, or advanced to a new evidence revision — BETWEEN
//! that check and the persist. For the two sites covered here the hazard is
//! not merely "an act proceeds on a stale authorization": both persist a
//! WHOLE `GroupInfo` captured earlier, so a marker that arrives in the window
//! is **erased** by the write, and containment silently disappears.
//!
//! Each test states the claim it defends:
//!
//! - the token MOVES on every lifecycle event a §4 re-check must catch, and
//!   does not move on a change that is not one (the forensic snapshot);
//! - an install / clear / revision-advance landing mid-operation refuses, and
//!   refuses having written NOTHING — a refusal after the mutation is an
//!   error message, not containment;
//! - a group with NO marker behaves exactly as it did before this slice;
//! - every lookup resolves BOTH spellings, so a group filed under an alias
//!   key is not silently exempt;
//! - and the NEGATIVE CONTROL: the same injection through the plain persist
//!   helper (the one without the re-check) DOES land. That is what proves the
//!   re-check is load-bearing rather than incidental.
//!
//! Determinism: no sleeps anywhere. The interleaving is injected by
//! `epoch_recheck_barrier`, which is `cfg(test)` end to end — a release build
//! compiles neither the module nor its call site, so none of this is a
//! production surface.

use super::*;

use crate::server::routes::named_groups::{
    epoch_recheck_barrier, persist_named_groups_mutation_epoch_checked_unlocked,
    persist_named_groups_mutation_unlocked, EpochCheckedPersist, EpochScope,
};

/// A minimal loopback-only daemon state on a temp dir. No sockets, no peers:
/// every assertion here is about local state and local files.
async fn epoch_state() -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(data_dir, agent).await?;
    Ok((state, dir))
}

fn epoch_policy() -> x0x::groups::GroupPolicy {
    x0x::groups::GroupPolicy {
        discoverability: x0x::groups::GroupDiscoverability::Hidden,
        admission: x0x::groups::GroupAdmission::InviteOnly,
        confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    }
}

fn group(creator: x0x::identity::AgentId, mls_group_id: &str) -> x0x::groups::GroupInfo {
    x0x::groups::GroupInfo::with_policy(
        "adr0066-epoch-token".to_string(),
        "slice 7 fixture".to_string(),
        creator,
        mls_group_id.to_string(),
        epoch_policy(),
    )
}

/// An authenticated-evidence marker. `revision` is a parameter because a
/// marker ADVANCING to a new evidence revision is one of the three lifecycle
/// events §4 must catch, and it is distinct from an install.
fn marker(revision: u64, no_anchor: bool) -> x0x::groups::ForkQuarantine {
    // The snapshot needs a well-formed commit header; any group's terminal
    // header will do, since identity never reads the snapshot.
    let scratch = group(x0x::identity::AgentId([0u8; 32]), "marker-snapshot-scratch");
    x0x::groups::ForkQuarantine {
        revision,
        state_hash: format!("cafe{revision:04x}"),
        committed_by: "11".repeat(32),
        observed_at_ms: 1_700_000_000_000 + revision,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: scratch.terminal_commit_header(),
            conflicting_commit: scratch.terminal_commit_header(),
            classification: None,
        },
        no_anchor,
    }
}

// ───────────────────────── the derivation itself ─────────────────────────

/// The token is an identity: re-deriving it from an unchanged record gives
/// the same value. Without this, every re-check would refuse everything.
#[test]
fn token_is_stable_across_re_derivation() {
    let info = group(
        x0x::identity::AgentKeypair::generate().unwrap().agent_id(),
        "g1",
    );
    assert_eq!(info.lifecycle_epoch_token(), info.lifecycle_epoch_token());
}

/// Install, clear and revision-advance each MOVE the token. These are the
/// three events §4 enumerates, and a token that missed any of them would
/// leave exactly the window this slice exists to close.
#[test]
fn every_lifecycle_event_moves_the_token() {
    let creator = x0x::identity::AgentKeypair::generate().unwrap().agent_id();
    let clean = group(creator, "g1");
    let clean_token = clean.lifecycle_epoch_token();

    let mut installed = clean.clone();
    installed.fork_quarantine = Some(marker(7, true));
    let installed_token = installed.lifecycle_epoch_token();
    assert_ne!(
        clean_token, installed_token,
        "an INSTALL must move the token — this is the primary §4 hazard"
    );
    assert!(installed_token.is_fork_quarantined());

    // Clear: back to the clean identity, which is still a MOVE relative to
    // the quarantined capture a mid-operation clear would be compared against.
    let mut cleared = installed.clone();
    cleared.fork_quarantine = None;
    assert_ne!(
        installed_token,
        cleared.lifecycle_epoch_token(),
        "a CLEAR must move the token relative to a quarantined capture"
    );

    // Revision advance: a NEW fork observation on an already-quarantined
    // group. Missing this would let a second, different fork slip through on
    // the first one's authorization.
    let mut advanced = clean.clone();
    advanced.fork_quarantine = Some(marker(9, true));
    assert_ne!(
        installed_token,
        advanced.lifecycle_epoch_token(),
        "a marker ADVANCING to a new evidence revision must move the token"
    );

    // The group's own lifecycle advancing moves it too — the other half of
    // the compound token.
    let mut rolled = clean.clone();
    rolled.state_revision += 1;
    assert_ne!(clean_token, rolled.lifecycle_epoch_token());
}

/// The forensic snapshot is DELIBERATELY excluded from marker identity: it is
/// derived from the same evidence, so it cannot differ between two markers
/// whose identity fields agree. This test documents that exclusion so a
/// future reader does not "fix" it by accident.
#[test]
fn forensic_snapshot_is_not_part_of_marker_identity() {
    let creator = x0x::identity::AgentKeypair::generate().unwrap().agent_id();
    let mut a = group(creator, "g1");
    a.fork_quarantine = Some(marker(7, true));
    let mut b = a.clone();
    if let Some(m) = b.fork_quarantine.as_mut() {
        m.snapshot.classification = Some("a-different-forensic-note".to_string());
    }
    assert_eq!(
        a.lifecycle_epoch_token(),
        b.lifecycle_epoch_token(),
        "snapshot detail is forensic, not identity — see ForkQuarantineIdentity"
    );
}

/// `same_marker` ignores `state_revision` and ONLY that. It exists for the
/// one site that persists an advanced state; if it ever started ignoring the
/// marker too, that site would silently stop being a gate.
#[test]
fn same_marker_ignores_revision_but_never_the_marker() {
    let creator = x0x::identity::AgentKeypair::generate().unwrap().agent_id();
    let base = group(creator, "g1");

    let mut advanced = base.clone();
    advanced.state_revision += 5;
    assert!(
        base.lifecycle_epoch_token()
            .same_marker(&advanced.lifecycle_epoch_token()),
        "a pure revision advance is what same_marker is allowed to ignore"
    );

    let mut quarantined = base.clone();
    quarantined.fork_quarantine = Some(marker(7, true));
    assert!(
        !base
            .lifecycle_epoch_token()
            .same_marker(&quarantined.lifecycle_epoch_token()),
        "same_marker must NEVER ignore an install — that is the whole gate"
    );
}

// ─────────────────────── both spellings (alias keys) ───────────────────────

/// A group filed under an alias key must be found by its STABLE id, and the
/// token must carry its marker. The negative control in the same test is the
/// bare lookup this replaced: it misses, which is precisely why a shared
/// resolver exists.
#[tokio::test]
async fn token_resolves_a_group_filed_under_an_alias_key() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let mut info = group(state.agent.agent_id(), "alias-fixture");
    info.fork_quarantine = Some(marker(7, true));
    let stable = info.stable_group_id().to_string();
    let alias = "local-alias-not-the-stable-id";
    assert_ne!(stable, alias, "fixture precondition");
    state
        .named_groups
        .write()
        .await
        .insert(alias.to_string(), info);

    let groups = state.named_groups.read().await;

    // NEGATIVE CONTROL: the bare lookup this slice removed cannot see it.
    assert!(
        groups.get(&stable).is_none(),
        "control: a bare get(stable_id) misses an alias-keyed group — if this ever \
         starts passing, the fixture has stopped testing the alias path"
    );

    let token = crate::server::lifecycle_epoch_token_locked(&groups, &stable)
        .expect("the shared resolver must find an alias-keyed group by its stable id");
    assert!(
        token.is_fork_quarantined(),
        "and it must carry the marker, or an alias-keyed group is exempt from §4"
    );
    Ok(())
}

// ──────────────── the re-check, under the persist lock ────────────────

/// Read the on-disk roster file verbatim, so "nothing was persisted" is a
/// claim about bytes rather than about the in-memory map.
async fn roster_bytes(state: &AppState) -> Option<Vec<u8>> {
    tokio::fs::read(&state.named_groups_path).await.ok()
}

/// Seed a clean group, then run an epoch-checked persist whose barrier
/// installs `injected` between the capture and the re-check.
///
/// Returns the outcome plus before/after on-disk bytes.
async fn run_with_injection(
    state: &AppState,
    key: &str,
    lookup_id: &str,
    injected: Option<x0x::groups::ForkQuarantine>,
    bump_revision: bool,
) -> (EpochCheckedPersist, Option<Vec<u8>>, Option<Vec<u8>>) {
    let captured = {
        let groups = state.named_groups.read().await;
        crate::server::lifecycle_epoch_token_locked(&groups, lookup_id)
    };
    let before = roster_bytes(state).await;

    let owned_key = key.to_string();
    let _guard = epoch_recheck_barrier::install(
        lookup_id,
        Box::new(move |groups| {
            // Mutate the very map the persist is about to write — the tightest
            // interleaving a concurrent writer could achieve.
            if let Some(info) = groups.get_mut(&owned_key) {
                if bump_revision {
                    info.state_revision += 1;
                } else {
                    info.fork_quarantine = injected.clone();
                }
            }
        }),
    );

    let outcome = persist_named_groups_mutation_epoch_checked_unlocked(
        state,
        lookup_id,
        captured.as_ref(),
        EpochScope::Full,
        |groups| {
            groups.insert(
                "a-group-this-operation-had-no-business-writing".to_string(),
                group(state.agent.agent_id(), "effect-marker"),
            );
            true
        },
    )
    .await;
    let after = roster_bytes(state).await;
    (outcome, before, after)
}

async fn seed(state: &AppState, key: &str) -> String {
    let info = group(state.agent.agent_id(), key);
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(key.to_string(), info);
    stable
}

/// A marker installed mid-operation refuses, and NOTHING is persisted — not
/// the roster file, not the effect the mutation would have had.
#[tokio::test]
async fn install_mid_operation_refuses_and_persists_nothing() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let key = "g-install";
    seed(&state, key).await;

    let (outcome, before, after) =
        run_with_injection(&state, key, key, Some(marker(7, true)), false).await;

    match outcome {
        EpochCheckedPersist::EpochMoved { observed } => {
            assert!(
                observed.is_some_and(|t| t.is_fork_quarantined()),
                "the re-check must report the marker it observed under the lock"
            );
        }
        EpochCheckedPersist::Applied(_) => {
            panic!("a marker installed between capture and persist MUST refuse")
        }
    }
    assert_eq!(
        before, after,
        "a refusal must leave the on-disk roster byte-identical"
    );
    assert!(
        !state
            .named_groups
            .read()
            .await
            .contains_key("a-group-this-operation-had-no-business-writing"),
        "the mutation closure must never have run"
    );
    Ok(())
}

/// NEGATIVE CONTROL for the test above. The same injection, through the PLAIN
/// persist helper that has no re-check, DOES land. This is the evidence that
/// the refusal above comes from the re-check and not from something else in
/// the stack — remove the re-check and the test above degrades into this one.
#[tokio::test]
async fn without_the_recheck_the_same_injection_lands() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let key = "g-control";
    seed(&state, key).await;

    let owned_key = key.to_string();
    let _guard = epoch_recheck_barrier::install(
        key,
        Box::new(move |groups| {
            if let Some(info) = groups.get_mut(&owned_key) {
                info.fork_quarantine = Some(marker(7, true));
            }
        }),
    );

    // The plain helper never consults the barrier, so inject directly to make
    // the control exact: the marker is present before the mutation runs.
    {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(key) {
            info.fork_quarantine = Some(marker(7, true));
        }
    }
    let outcome = persist_named_groups_mutation_unlocked(&state, |groups| {
        groups.insert(
            "control-effect".to_string(),
            group(state.agent.agent_id(), "control-effect"),
        );
        true
    })
    .await;
    assert!(
        outcome.is_ok(),
        "control: the un-checked helper persists regardless of the marker"
    );
    assert!(
        state
            .named_groups
            .read()
            .await
            .contains_key("control-effect"),
        "control: without a re-check the write lands even though the group is now \
         quarantined — that is the defect §4 closes"
    );
    Ok(())
}

/// A marker CLEARED mid-operation also refuses. ADR-0066 §4 says "a mismatch
/// aborts" without qualification and ADR-0067 keeps that: the captured
/// authorization was computed against a record that no longer exists. The
/// refusal is retryable, which is why this is safe rather than a lockout.
#[tokio::test]
async fn clear_mid_operation_refuses_and_persists_nothing() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let key = "g-clear";
    seed(&state, key).await;
    // Start quarantined, so the injection can clear it.
    {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(key) {
            info.fork_quarantine = Some(marker(7, true));
        }
    }

    let (outcome, before, after) = run_with_injection(&state, key, key, None, false).await;

    match outcome {
        EpochCheckedPersist::EpochMoved { observed } => assert!(
            observed.is_some_and(|t| !t.is_fork_quarantined()),
            "the observed token must show the cleared state"
        ),
        EpochCheckedPersist::Applied(_) => {
            panic!("a marker cleared between capture and persist MUST refuse (ADR-0067)")
        }
    }
    assert_eq!(before, after, "and must write nothing");
    Ok(())
}

/// A marker advancing to a NEW evidence revision mid-operation refuses. A
/// second, different fork must not ride the first one's authorization.
#[tokio::test]
async fn revision_advance_mid_operation_refuses() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let key = "g-advance";
    seed(&state, key).await;
    {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(key) {
            info.fork_quarantine = Some(marker(7, true));
        }
    }

    let (outcome, before, after) =
        run_with_injection(&state, key, key, Some(marker(9, true)), false).await;

    assert!(
        matches!(outcome, EpochCheckedPersist::EpochMoved { .. }),
        "a marker advanced to a new evidence revision MUST refuse"
    );
    assert_eq!(before, after);
    Ok(())
}

/// The group's own lifecycle advancing mid-operation refuses too — the other
/// half of the compound token, and the reason it is compound.
#[tokio::test]
async fn state_revision_advance_mid_operation_refuses() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let key = "g-staterev";
    seed(&state, key).await;

    let (outcome, before, after) = run_with_injection(&state, key, key, None, true).await;

    assert!(
        matches!(outcome, EpochCheckedPersist::EpochMoved { .. }),
        "a state_revision advance must move the compound token"
    );
    assert_eq!(before, after);
    Ok(())
}

/// NO marker, nothing injected: the epoch-checked helper must behave exactly
/// like the plain one. This is the blast-radius test — a slice that gates a
/// contested group is only correct if it is invisible to every other group.
#[tokio::test]
async fn no_marker_is_unchanged_behaviour() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let key = "g-clean";
    let _stable = seed(&state, key).await;

    let captured = {
        let groups = state.named_groups.read().await;
        crate::server::lifecycle_epoch_token_locked(&groups, key)
    };
    let outcome = persist_named_groups_mutation_epoch_checked_unlocked(
        &state,
        key,
        captured.as_ref(),
        EpochScope::Full,
        |groups| {
            groups.insert(
                "clean-effect".to_string(),
                group(state.agent.agent_id(), "clean-effect"),
            );
            true
        },
    )
    .await;
    match outcome {
        EpochCheckedPersist::Applied(result) => {
            result.expect("an unquarantined group persists exactly as before");
        }
        EpochCheckedPersist::EpochMoved { .. } => {
            panic!(
                "an unchanged group must never be refused — this would be a regression \
                    for every group on the install"
            )
        }
    }
    assert!(
        state.named_groups.read().await.contains_key("clean-effect"),
        "the mutation must have run"
    );
    Ok(())
}

/// The re-check honours BOTH spellings: a group filed under an alias key,
/// with the token captured and re-checked by its stable id, still refuses
/// when a marker lands mid-operation. Without the shared resolver this test
/// would pass vacuously (the lookup would miss and the capture would be
/// `None`), so it also asserts the capture actually saw the group.
#[tokio::test]
async fn alias_keyed_group_is_not_exempt_from_the_recheck() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let alias = "alias-key-for-epoch";
    let info = group(state.agent.agent_id(), "alias-epoch-fixture");
    let stable = info.stable_group_id().to_string();
    assert_ne!(stable, alias, "fixture precondition");
    state
        .named_groups
        .write()
        .await
        .insert(alias.to_string(), info);

    // Precondition: the capture must resolve through the alias, or the test
    // proves nothing.
    {
        let groups = state.named_groups.read().await;
        assert!(
            crate::server::lifecycle_epoch_token_locked(&groups, &stable).is_some(),
            "capture must resolve the alias-keyed group by stable id"
        );
    }

    let (outcome, before, after) =
        run_with_injection(&state, alias, &stable, Some(marker(7, true)), false).await;

    assert!(
        matches!(outcome, EpochCheckedPersist::EpochMoved { .. }),
        "an alias-keyed group must be gated exactly like a stable-keyed one"
    );
    assert_eq!(before, after);
    Ok(())
}

/// A capture of `None` (no local record) that finds a marker under the lock
/// refuses. This is the first-join shape: the operation was about to seat a
/// group that has since been quarantined, and "no record" must never read as
/// "unchanged".
#[tokio::test]
async fn absent_capture_refuses_when_a_marker_appears() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let key = "g-appears";
    let captured: Option<x0x::groups::LifecycleEpochToken> = None;

    let owned_key = key.to_string();
    let creator = state.agent.agent_id();
    let _guard = epoch_recheck_barrier::install(
        key,
        Box::new(move |groups| {
            let mut info = group(creator, "appears-fixture");
            info.fork_quarantine = Some(marker(7, true));
            groups.insert(owned_key.clone(), info);
        }),
    );

    let outcome = persist_named_groups_mutation_epoch_checked_unlocked(
        &state,
        key,
        captured.as_ref(),
        EpochScope::Full,
        |_groups| panic!("the mutation must not run"),
    )
    .await;
    assert!(
        matches!(outcome, EpochCheckedPersist::EpochMoved { .. }),
        "absent -> present must refuse; treating a missing record as unchanged is the \
         fail-open reading"
    );
    Ok(())
}

/// An absent capture that is STILL absent under the lock proceeds — the
/// normal first-join case. Without this, the re-check would break every
/// fresh join on the install.
#[tokio::test]
async fn absent_capture_still_absent_proceeds() -> Result<()> {
    let (state, _dir) = epoch_state().await?;
    let captured: Option<x0x::groups::LifecycleEpochToken> = None;
    let outcome = persist_named_groups_mutation_epoch_checked_unlocked(
        &state,
        "g-never-existed",
        captured.as_ref(),
        EpochScope::Full,
        |groups| {
            groups.insert(
                "fresh-join".to_string(),
                group(state.agent.agent_id(), "fresh-join"),
            );
            true
        },
    )
    .await;
    assert!(
        matches!(outcome, EpochCheckedPersist::Applied(Ok(_))),
        "absent -> absent is a MATCH: a first join must not be refused"
    );
    Ok(())
}

// ───── ADR-0067 Validation: the TreeKEM atomic-persist re-check site ─────
//
// Nit (b) from the cross-model security review: ADR-0067's Validation says
// "per re-check site", and this site had no barrier-driven fixture. The two
// tests below pin its asymmetric rule in BOTH directions, including the
// direction it deliberately permits.

/// Owner-axis (Home-shaped) state, the population the TreeKEM atomic persist
/// serves.
async fn owner_axis_state() -> Result<(Arc<AppState>, tempfile::TempDir, x0x::identity::UserKeypair)>
{
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let owner_seed = [0x67u8; 32];
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_user_key(x0x::identity::UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(data_dir, agent).await?;
    Ok((
        state,
        dir,
        x0x::identity::UserKeypair::from_seed(&owner_seed)?,
    ))
}

/// Seed a real TreeKEM group and return `(hex id, info, live group)`.
async fn seed_treekem_group(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    id_byte: u8,
) -> Result<(String, x0x::groups::GroupInfo, x0x::mls::TreeKemMlsGroup)> {
    let group_id = format!("{id_byte:02x}").repeat(32);
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, state.agent.agent_id(), &seed)?;
    let epoch = group.epoch();
    let mut info = x0x::groups::GroupInfo::with_policy(
        "adr0067-treekem".to_string(),
        "slice 7 treekem fixture".to_string(),
        state.agent.agent_id(),
        group_id.clone(),
        x0x::groups::GroupPolicy {
            discoverability: x0x::groups::GroupDiscoverability::Hidden,
            admission: x0x::groups::GroupAdmission::OwnerCertified(owner.user_id()),
            confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.secret_epoch = epoch;
    info.security_binding = Some(format!("treekem:epoch={epoch}"));
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info.clone());
    Ok((group_id, info, group))
}

/// **Erasure is refused.** A marker installed while a TreeKEM
/// roster+snapshot persist is in flight must abort the persist, because that
/// persist writes a WHOLE record captured before the marker existed and would
/// otherwise erase it.
#[tokio::test]
async fn treekem_atomic_persist_refuses_when_a_marker_lands_mid_operation() -> Result<()> {
    let (state, _dir, owner) = owner_axis_state().await?;
    let (id, info, group) = seed_treekem_group(&state, &owner, 0x61).await?;

    // The marker lands after `info` was captured, exactly as a concurrent
    // `install_fork_evidence` would leave it.
    {
        let mut groups = state.named_groups.write().await;
        if let Some(live) = groups.get_mut(&id) {
            live.fork_quarantine = Some(marker(11, false));
        }
    }

    let result = persist_treekem_and_named_groups_atomic_with_info(&state, &id, info, &group).await;
    let message = result
        .expect_err("a marker landing mid-persist must abort the persist")
        .to_string();
    assert!(
        message.contains("fork_quarantined"),
        "the refusal must name the condition, got: {message}"
    );
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&id)
            .is_some_and(x0x::groups::GroupInfo::is_fork_quarantined),
        "and the marker must SURVIVE — erasing it is the defect this gate exists to stop"
    );
    Ok(())
}

/// **Resurrection is PERMITTED here, deliberately, and this test is the
/// record of that decision** (the "stale snapshot" case raised in review).
///
/// At this site "the incoming record adds a marker" is indistinguishable from
/// "this IS the install path" — `install_fork_evidence` reaches the roster the
/// same way — so a snapshot captured before a clear can re-assert a
/// just-cleared marker. That direction fails CLOSED: the group is
/// re-contained, never released, so an operator clears again. Making it
/// refuse would make the marker unsettable, which is ADR-0066 §2's explicit
/// trap.
///
/// `EpochScope::MarkerOnly` — used by the Home seal paths, which never install
/// a marker — refuses BOTH directions precisely because that ambiguity does
/// not exist there. If this assertion ever flips, the asymmetry has been
/// tightened and the install path needs re-verifying.
#[tokio::test]
async fn treekem_stale_snapshot_may_resurrect_a_cleared_marker() -> Result<()> {
    let (state, _dir, owner) = owner_axis_state().await?;
    let (id, mut stale, group) = seed_treekem_group(&state, &owner, 0x62).await?;

    // The captured snapshot carries a marker; the live record has none (an
    // operator cleared it during the window).
    stale.fork_quarantine = Some(marker(11, false));
    assert!(
        !state
            .named_groups
            .read()
            .await
            .get(&id)
            .is_some_and(x0x::groups::GroupInfo::is_fork_quarantined),
        "precondition: the live record is clear"
    );

    persist_treekem_and_named_groups_atomic_with_info(&state, &id, stale, &group)
        .await
        .expect("the install direction must NOT be gated — see ADR-0066 §2");
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&id)
            .is_some_and(x0x::groups::GroupInfo::is_fork_quarantined),
        "documented, accepted outcome: a stale snapshot re-contains the group. Fail-closed \
         direction — the operator clears again."
    );
    Ok(())
}

/// #732 r8 (boundary review, Sol P1): the TreeKEM atomic writer used to
/// insert its `info` into ONE map key, encode that divergent candidate
/// durably, and install the same single slot into memory — so the
/// documented stale-marker resurrection (the test above) wrote a MARKED
/// exact alias beside a CLEAN sibling of the same stable id, and a caller
/// resolving by the clean spelling bypassed containment while the writer's
/// own spelling was contained. The durable candidate and both memory
/// installs now converge, so the resurrection reaches EVERY spelling, in
/// memory and on disk.
#[tokio::test]
async fn treekem_stale_marker_resurrection_spreads_to_every_alias_spelling() -> Result<()> {
    let (state, _dir, owner) = owner_axis_state().await?;
    let (id, mut stale, group) = seed_treekem_group(&state, &owner, 0x63).await?;
    stale.fork_quarantine = Some(marker(11, false));

    // The legitimate alias shape: a second, differently keyed record for the
    // same stable id, clean like the live one.
    let alias_key = format!("issue732-treekem-alias-{id}");
    let mut alias = stale.clone();
    alias.fork_quarantine = None;
    state
        .named_groups
        .write()
        .await
        .insert(alias_key.clone(), alias);

    persist_treekem_and_named_groups_atomic_with_info(&state, &id, stale, &group)
        .await
        .expect("the install direction must NOT be gated — see the test above");

    // Memory: BOTH spellings contained, byte-identical marker, and an exact
    // key still resolves to itself (the resolver prefers exact keys, which is
    // exactly why a clean duplicate was a silent bypass).
    {
        let groups = state.named_groups.read().await;
        for key in [id.as_str(), alias_key.as_str()] {
            let (resolved_key, info) = crate::server::resolve_group_entry_locked(&groups, key)
                .ok_or_else(|| anyhow::anyhow!("resolver lost {key}"))?;
            assert_eq!(resolved_key, key, "an exact key must resolve to itself");
            assert!(
                info.is_fork_quarantined(),
                "#732 r8: the resurrection reached the `{key}` spelling"
            );
        }
        let marked = groups[&id]
            .fork_quarantine
            .clone()
            .ok_or_else(|| anyhow::anyhow!("marker missing on the writer's spelling"))?;
        assert_eq!(
            groups[&alias_key].fork_quarantine.as_ref(),
            Some(&marked),
            "both spellings carry the SAME marker — no divergence survives the writer"
        );
    }
    // Disk: the converged candidate is what was encoded, so the merged
    // reload carries the same whole containment on every spelling.
    let merged =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    assert!(
        merged[&alias_key].fork_quarantine.is_some(),
        "the durable candidate was converged BEFORE encoding"
    );
    assert_eq!(
        merged[&alias_key].fork_quarantine, merged[&id].fork_quarantine,
        "the disk bytes agree across spellings"
    );
    Ok(())
}

/// #732 r8: the token is a property of the GROUP, not the spelling. Two
/// spellings of one stable id must answer the SAME token — and, the review
/// constraint that rejected a `max` fold, a LAGGING spelling's advance must
/// MOVE it: with spellings at 4 and 9, `max` stays 9 when the 4 advances to
/// 5, and this token's contract is that a lifecycle advance is DETECTED.
/// Equalizing the spelling must never weaken the change detector.
#[test]
fn group_wide_token_is_identical_across_spellings_and_detects_a_lagging_advance() -> Result<()> {
    let creator = x0x::identity::AgentId([7u8; 32]);
    let stable = "71".repeat(32);
    let alias_key = format!("{stable}-alias");
    let seeded = |revision: u64| {
        let mut info = group(creator, &stable);
        info.state_revision = revision;
        info.fork_quarantine = Some(marker(3, false));
        info
    };

    let mut groups = std::collections::HashMap::new();
    groups.insert(alias_key.clone(), seeded(4));
    groups.insert(stable.clone(), seeded(9));

    let by_alias = crate::server::lifecycle_epoch_token_locked(&groups, &alias_key)
        .ok_or_else(|| anyhow::anyhow!("token missing for the alias spelling"))?;
    let by_stable = crate::server::lifecycle_epoch_token_locked(&groups, &stable)
        .ok_or_else(|| anyhow::anyhow!("token missing for the stable spelling"))?;
    assert_eq!(
        by_alias, by_stable,
        "the token cannot depend on the spelling"
    );

    // Permuting the SAME revision multiset across alias keys must not move the
    // token. The former binary reducer kept the first revision raw and mixed
    // only later operands, so this content swap changed the result despite no
    // group-wide lifecycle change.
    groups.insert(alias_key.clone(), seeded(9));
    groups.insert(stable.clone(), seeded(4));
    let after_permutation = crate::server::lifecycle_epoch_token_locked(&groups, &stable)
        .ok_or_else(|| anyhow::anyhow!("token missing after alias content permutation"))?;
    assert_eq!(
        after_permutation, by_stable,
        "the alias revision fold must be symmetric, not dependent on which key holds a revision"
    );

    // Restore the original placement, then advance the LAGGING spelling: 4 ->
    // 5. A `max` fold would not move.
    groups.insert(alias_key.clone(), seeded(5));
    groups.insert(stable.clone(), seeded(9));
    let after_lagging_alias = crate::server::lifecycle_epoch_token_locked(&groups, &stable)
        .ok_or_else(|| anyhow::anyhow!("token missing after the lagging advance"))?;
    assert_ne!(
        by_stable, after_lagging_alias,
        "a lagging spelling's advance must be DETECTED — max would hide it"
    );
    assert_eq!(
        after_lagging_alias,
        crate::server::lifecycle_epoch_token_locked(&groups, &alias_key)
            .ok_or_else(|| anyhow::anyhow!("token missing"))?,
        "and both spellings still agree on the moved token"
    );

    // The LEADING spelling advances too: 9 -> 10. Also detected.
    groups.insert(stable.clone(), seeded(10));
    let after_leading = crate::server::lifecycle_epoch_token_locked(&groups, &alias_key)
        .ok_or_else(|| anyhow::anyhow!("token missing after the leading advance"))?;
    assert_ne!(
        after_leading, after_lagging_alias,
        "the leading spelling's advance is detected too"
    );

    // A single-spelling group keeps the identity fold: one entry, one token.
    let single = seeded(6);
    let expected = single.lifecycle_epoch_token();
    let mut solo = std::collections::HashMap::new();
    solo.insert(stable.clone(), single);
    assert_eq!(
        crate::server::lifecycle_epoch_token_locked(&solo, &stable),
        Some(expected),
        "the fold of one spelling is that spelling's token, unchanged"
    );
    Ok(())
}
