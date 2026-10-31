//! #1574 (the #1729 refusal shape, the two whole-map persist cores): a
//! durability-preflight refusal in
//! `persist_named_groups_mutation_with_gss_guard` and
//! `persist_named_groups_quarantine_clear_durable_only` must be reported
//! as a refusal (`NotReplaced`), never as `ReplacedNotDurable`. The #759
//! Watson meaning of `ReplacedNotDurable` is "the caller's replacement is
//! visible, only its directory fsync is unconfirmed". The preflight
//! refuses BEFORE the caller's mutation closure runs, so that claim is
//! false: the refusal reports the confirming re-save of the EARLIER
//! unconfirmed replacement, and nothing of the caller's candidate is
//! staged. Local temp state only: no network config, sockets or
//! bootstrap.

use super::*;

/// #1574: the mutation core reports a durability refusal as a refusal.
/// The flag is set (an earlier `ReplacedNotDurable`) and the confirming
/// re-save renames the current roster again but its parent-dir fsync
/// fails again (`SaveFault::ReplacedNotDurableAfterWrite`, the refusal
/// shape #1729 root-fixed for `persist_named_group_info`). Before the
/// fix the refusal was returned as `ReplacedNotDurable`, so a caller
/// could keep its candidate and proceed for a mutation that never ran.
/// The refusal is `NotReplaced`, the closure did not run, the live map
/// keeps the old record and the flag stays set — and once the re-save is
/// durable, the same mutation lands.
#[tokio::test]
async fn a_mutation_refuses_a_durability_preflight_refusal() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let signer = x0x::identity::AgentKeypair::generate()?;
    let key = "74".repeat(16);
    let mut info = x0x::groups::GroupInfo::new(
        "preflight-refusal".to_string(),
        String::new(),
        signer.agent_id(),
        key.clone(),
    );
    info.seal_commit(&signer, 1_000)?;
    state
        .named_groups
        .write()
        .await
        .insert(key.clone(), info.clone());
    assert!(matches!(
        save_named_groups_checked(&state).await,
        Ok(AtomicWriteOutcome::Durable)
    ));

    // An earlier replacement is unconfirmed, and its confirming re-save
    // renames the current roster again but its parent-dir fsync fails
    // again: the preflight refuses.
    state
        .named_groups_requires_durability_confirmation
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let fault = set_save_fault(&state, SaveFault::ReplacedNotDurableAfterWrite);
    let mut ran = false;
    let rename = |groups: &mut HashMap<String, x0x::groups::GroupInfo>| {
        groups.get_mut(&key).is_some_and(|info| {
            info.name = "renamed-by-mutation".to_string();
            true
        })
    };
    let outcome = {
        let _persistence = state.named_groups_persistence_lock.lock().await;
        let gss = state.gss_publication_gate.write().await;
        persist_named_groups_mutation_with_gss_guard(&state, &gss, |groups| {
            ran = true;
            rename(groups)
        })
        .await
    };
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::NotReplaced)),
        "a preflight refusal must not read as a staged replacement: {outcome:?}"
    );
    assert!(!ran, "the mutation closure never ran");
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(&key)
            .map(|stored| stored.name.clone()),
        Some(info.name.clone()),
        "nothing of the refused mutation is in the live map"
    );
    assert!(
        state
            .named_groups_requires_durability_confirmation
            .load(std::sync::atomic::Ordering::SeqCst),
        "the flag stays set, so the next save retries the preflight"
    );

    // The fault is one-shot: the retry's preflight re-save is durable and
    // the same mutation lands.
    let outcome = {
        let _persistence = state.named_groups_persistence_lock.lock().await;
        let gss = state.gss_publication_gate.write().await;
        persist_named_groups_mutation_with_gss_guard(&state, &gss, |groups| {
            ran = true;
            rename(groups)
        })
        .await
    };
    drop(fault);
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the retry runs the mutation once the preflight is durable: {outcome:?}"
    );
    assert!(ran, "the retry ran the mutation closure");
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(&key)
            .map(|stored| stored.name.clone()),
        Some("renamed-by-mutation".to_string()),
        "the retry installed the mutation"
    );
    assert!(!state
        .named_groups_requires_durability_confirmation
        .load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

/// #1574: the durable-only quarantine clear reports a durability refusal
/// as a refusal. The flag is set and the confirming re-save renames the
/// current roster again but its parent-dir fsync fails again. Before the
/// fix the refusal was returned as `ReplacedNotDurable` — for this entry
/// point the outcome whose meaning is "the clear's write renamed; the
/// live record stays contained, memory is re-saved, the caller retries" —
/// a claim about a clear that never ran. The refusal is `NotReplaced`,
/// the closure did not run, the live record keeps its marker and the flag
/// stays set — and once the re-save is durable, the same clear lands.
#[tokio::test]
async fn a_quarantine_clear_refuses_a_durability_preflight_refusal() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let signer = x0x::identity::AgentKeypair::generate()?;
    let signer_hex = hex::encode(signer.agent_id().as_bytes());
    let key = "75".repeat(16);
    let mut info = x0x::groups::GroupInfo::new(
        "clear-preflight-refusal".to_string(),
        String::new(),
        signer.agent_id(),
        key.clone(),
    );
    info.seal_commit(&signer, 1_000)?;
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        committed_by: signer_hex,
        observed_at_ms: 1_001,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: info.terminal_commit_header(),
            conflicting_commit: info.terminal_commit_header(),
            classification: None,
        },
        no_anchor: false,
    });
    state
        .named_groups
        .write()
        .await
        .insert(key.clone(), info.clone());
    assert!(matches!(
        save_named_groups_checked(&state).await,
        Ok(AtomicWriteOutcome::Durable)
    ));

    state
        .named_groups_requires_durability_confirmation
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let fault = set_save_fault(&state, SaveFault::ReplacedNotDurableAfterWrite);
    let mut ran = false;
    let clear = |groups: &mut HashMap<String, x0x::groups::GroupInfo>| {
        let Some(info) = groups.get_mut(&key) else {
            return false;
        };
        info.fork_quarantine = None;
        info.reset_fork_evidence_after_quarantine_clear();
        true
    };
    let outcome = persist_named_groups_quarantine_clear_durable_only(&state, |groups| {
        ran = true;
        clear(groups)
    })
    .await;
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::NotReplaced)),
        "a preflight refusal must not read as a staged replacement: {outcome:?}"
    );
    assert!(!ran, "the clear closure never ran");
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&key)
            .is_some_and(|stored| stored.fork_quarantine.is_some()),
        "the live record stays armed"
    );
    assert!(
        state
            .named_groups_requires_durability_confirmation
            .load(std::sync::atomic::Ordering::SeqCst),
        "the flag stays set, so the next save retries the preflight"
    );

    // The fault is one-shot: the retry's preflight re-save is durable and
    // the same clear lands.
    let outcome = persist_named_groups_quarantine_clear_durable_only(&state, |groups| {
        ran = true;
        clear(groups)
    })
    .await;
    drop(fault);
    assert!(
        matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
        "the retry runs the clear once the preflight is durable: {outcome:?}"
    );
    assert!(ran, "the retry ran the clear closure");
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&key)
            .is_some_and(|stored| stored.fork_quarantine.is_none()),
        "the retry published the cleared record"
    );
    assert!(!state
        .named_groups_requires_durability_confirmation
        .load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}
