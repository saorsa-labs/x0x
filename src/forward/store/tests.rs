#![allow(clippy::unwrap_used, clippy::expect_used)]

//! ADR-0074 §2 slice-2 intent tests for `forwards.json`. Deterministic: no
//! network, no listener; each asserts a property that goes red if its
//! check is removed.

use super::*;
use crate::identity::UserId;
use crate::names::{
    resolve_with, AgentCandidate, BindSource, Candidates, MachineCandidate, NameRef, NameStore,
};

const NOW: u64 = 1_900_000_000;
const OWNER: UserId = UserId([0x0a; 32]);

/// A committed owner add must never be visible with its old retry state.
#[tokio::test]
async fn owner_add_commits_record_and_retry_reset_together() {
    let store = ForwardStore::in_memory();
    let original = machine_spec(true);
    original.remember(&store).await.unwrap();
    let mut retries = store.restore_retries.lock().await;
    let mut retry = RestoreRetry::default();
    retry.finish(&Err(RestoreFailure::Permanent("name_changed".into())));
    retries.insert(original.spec.local_addr, retry);
    let mut replacement = original.clone();
    replacement.spec.target_port += 1;
    let add = replacement.remember(&store);
    tokio::pin!(add);
    assert!(futures::poll!(&mut add).is_pending());
    assert_eq!(
        store.records().await.unwrap(),
        vec![record(&original)],
        "the record must not commit while its retry reset is blocked"
    );
    drop(retries);
    assert!(add.await.unwrap());
    let session = store.begin_restore().await.unwrap();
    assert_eq!(session.records, vec![record(&replacement)]);
    assert!(!session.retries.contains_key(&replacement.spec.local_addr));
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Parts {
    spec: ForwardSpec,
    binding: ForwardBinding,
}

impl Parts {
    fn pair(&self) -> (ForwardSpec, ForwardBinding) {
        (self.spec.clone(), self.binding.clone())
    }

    async fn remember(&self, store: &ForwardStore) -> Result<bool, ForwardStoreError> {
        store.remember(&self.spec, &self.binding).await
    }

    fn check(&self, store: &ForwardStore) -> Result<(), ForwardStoreError> {
        store.check(&self.spec, &self.binding)
    }
}

fn machine_spec(persistent: bool) -> Parts {
    Parts {
        spec: ForwardSpec {
            local_addr: "127.0.0.1:18022".parse().unwrap(),
            peer_agent: AgentId([0x44; 32]),
            target_host: "::1".to_string(),
            target_port: 22,
        },
        binding: ForwardBinding {
            name: Some("machine:box.me".to_string()),
            kind: NameKind::Machine,
            pinned_machine: Some(MachineId([0x11; 32])),
            persistent,
        },
    }
}

fn agent_spec(port: u16) -> Parts {
    Parts {
        spec: ForwardSpec {
            local_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            peer_agent: AgentId([0x55; 32]),
            target_host: "127.0.0.1".to_string(),
            target_port: 8080,
        },
        binding: ForwardBinding {
            name: Some("agent:studio.bob".to_string()),
            kind: NameKind::Agent,
            pinned_machine: Some(MachineId([0x66; 32])),
            persistent: true,
        },
    }
}

fn record(parts: &Parts) -> ForwardRecord {
    ForwardRecord::from_spec(&parts.spec, &parts.binding)
        .unwrap()
        .unwrap()
}

fn resolved_machine(agent: [u8; 32], machine: [u8; 32]) -> Resolved {
    Resolved {
        name: "machine:box.me".to_string(),
        kind: NameKind::Machine,
        owner: OWNER,
        agent_id: Some(AgentId(agent)),
        machine_id: Some(MachineId(machine)),
        newly_pinned: false,
    }
}

/// WHY (ADR-0074 §2, Q3): a forward survives a daemon restart with every
/// field it needs to come back on the same ids — including `target_host`
/// (a `::1` target must round-trip) and the pinned machine — and the file
/// is private (0600).
#[tokio::test]
async fn persisted_forward_survives_restart_with_its_target_and_pins() {
    let dir = tempfile::tempdir().unwrap();
    let path = ForwardStore::path_in(dir.path());
    {
        let store = ForwardStore::load(path.clone()).await;
        assert!(machine_spec(true).remember(&store).await.unwrap());
        assert!(agent_spec(18023).remember(&store).await.unwrap());
    }
    // "Restart": a fresh store from the same file.
    let store = ForwardStore::load(path.clone()).await;
    assert_eq!(store.load_error(), None);
    let records = store.records().await.unwrap();
    assert_eq!(
        records,
        vec![record(&machine_spec(true)), record(&agent_spec(18023))]
    );
    // It comes back up on exactly its pinned ids when the name still
    // resolves to them.
    let (spec, binding) = restore_decision(
        &records[0],
        Some(Ok(resolved_machine([0x44; 32], [0x11; 32]))),
    )
    .unwrap();
    let want = machine_spec(true);
    assert_eq!(spec, want.spec);
    assert_eq!(binding, want.binding);
    assert_eq!(spec.target_host, "::1");
    assert_eq!(binding.pinned_machine, Some(MachineId([0x11; 32])));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "forwards.json must be private");
    }
    // Deleting the forward deletes its record for the next restart too.
    assert!(store
        .forget("127.0.0.1:18022".parse().unwrap())
        .await
        .unwrap());
    let store = ForwardStore::load(path).await;
    assert_eq!(
        store.records().await.unwrap(),
        vec![record(&agent_spec(18023))]
    );
}

/// WHY (Q3): `--ephemeral` opts out — the forward leaves no record, so it
/// does not come back after a restart, while a persistent one beside it
/// does.
#[tokio::test]
async fn ephemeral_forward_is_not_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let path = ForwardStore::path_in(dir.path());
    {
        let store = ForwardStore::load(path.clone()).await;
        assert!(!machine_spec(false).remember(&store).await.unwrap());
        assert!(!path.exists(), "an ephemeral forward writes nothing");
        assert!(agent_spec(18023).remember(&store).await.unwrap());
    }
    let store = ForwardStore::load(path).await;
    let records = store.records().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].local_addr, agent_spec(18023).spec.local_addr);
}

/// WHY (ADR-0074 §1): every persisted forward must reach a pinned
/// machine, so a persistent forward without one is refused, not stored
/// unpinned. And a record the loader would reject (a hostname target) is
/// refused before it is written, so one bad forward can never make the
/// whole file fail closed at the next start.
#[tokio::test]
async fn unpinned_or_unloadable_forward_is_refused_not_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = ForwardStore::path_in(dir.path());
    let store = ForwardStore::load(path.clone()).await;
    let mut unpinned = agent_spec(18023);
    unpinned.binding.pinned_machine = None;
    assert!(matches!(
        unpinned.check(&store),
        Err(ForwardStoreError::Unpinned(_))
    ));
    assert!(matches!(
        unpinned.remember(&store).await,
        Err(ForwardStoreError::Unpinned(_))
    ));
    let mut hostname = agent_spec(18024);
    hostname.spec.target_host = "localhost".to_string();
    assert!(matches!(
        hostname.check(&store),
        Err(ForwardStoreError::Invalid(_))
    ));
    assert!(matches!(
        hostname.remember(&store).await,
        Err(ForwardStoreError::Invalid(_))
    ));
    assert!(!path.exists(), "nothing was written");
    // A requested `:0` is checkable before the kernel assigns the port.
    let mut any_port = agent_spec(18025);
    any_port.spec.local_addr.set_port(0);
    assert_eq!(any_port.check(&store), Ok(()));
}

/// WHY: a corrupt, unknown-schema or tampered file must fail closed:
/// nothing is restored, persistent adds are refused, and the file is never
/// overwritten (so nothing the user had is silently lost).
#[tokio::test]
async fn corrupt_store_fails_closed_and_is_never_overwritten() {
    let good = serde_json::to_value(ForwardsFile {
        version: STORE_VERSION,
        forwards: vec![RecordJson::from_record(&record(&machine_spec(true)))],
    })
    .unwrap();
    let with = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = good.clone();
        f(&mut v);
        serde_json::to_vec(&v).unwrap()
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("garbage", b"{not json".to_vec()),
        ("unknown top-level field", with(&|v| v["extra"] = 1.into())),
        (
            "unknown record field",
            with(&|v| v["forwards"][0]["bogus"] = true.into()),
        ),
        ("future version", with(&|v| v["version"] = 2.into())),
        (
            "non-loopback target",
            with(&|v| v["forwards"][0]["target_host"] = "10.0.0.1".into()),
        ),
        (
            "hostname target",
            with(&|v| v["forwards"][0]["target_host"] = "localhost".into()),
        ),
        (
            "id not its local_addr",
            with(&|v| v["forwards"][0]["id"] = "127.0.0.1:1".into()),
        ),
        (
            "non-canonical name",
            with(&|v| v["forwards"][0]["name"] = "box.me".into()),
        ),
        (
            "machine forward without machine",
            with(&|v| {
                v["forwards"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("pinned_machine_id");
            }),
        ),
        (
            "duplicate id",
            with(&|v| {
                let dup = v["forwards"][0].clone();
                v["forwards"].as_array_mut().unwrap().push(dup);
            }),
        ),
    ];
    // Sanity: the unmodified file loads, so each case fails for its edit.
    let dir = tempfile::tempdir().unwrap();
    let path = ForwardStore::path_in(dir.path());
    std::fs::write(&path, serde_json::to_vec(&good).unwrap()).unwrap();
    assert_eq!(ForwardStore::load(path.clone()).await.load_error(), None);

    for (case, bytes) in cases {
        std::fs::write(&path, &bytes).unwrap();
        let store = ForwardStore::load(path.clone()).await;
        assert!(store.load_error().is_some(), "{case}: must fail closed");
        assert!(
            matches!(store.records().await, Err(ForwardStoreError::Unusable(_))),
            "{case}: nothing may be restored"
        );
        assert!(
            matches!(
                agent_spec(18023).remember(&store).await,
                Err(ForwardStoreError::Unusable(_))
            ),
            "{case}: persistent adds are refused"
        );
        assert!(
            store
                .forget("127.0.0.1:18022".parse().unwrap())
                .await
                .is_err(),
            "{case}: deletes are refused"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "{case}: the file is never overwritten"
        );
        // An ephemeral forward needs no store and still works.
        assert!(!machine_spec(false).remember(&store).await.unwrap());
    }
}

fn agent_candidate(id: u8) -> Candidates {
    Candidates {
        agents: vec![AgentCandidate {
            agent_id: AgentId([id; 32]),
            label: Some("studio".to_string()),
            machine_id: None,
            verified: true,
        }],
        machines: Vec::new(),
    }
}

/// WHY (ADR-0074 §2, known_hosts semantics): at restart the name is
/// re-resolved through the name store, where its pin applies. When the
/// name now points at a different key the forward stays down as
/// `name_changed` — never silently retargeted — and an unknown name stays
/// down with its reason. Only the pinned ids bring it back up.
#[tokio::test]
async fn restore_with_a_pin_mismatch_leaves_the_forward_disabled() {
    let names = NameStore::in_memory();
    // The resolver refuses an unbound owner label (`UnknownName`). `me` is
    // the local owner and needs no row; `bob` must be bound first.
    names
        .bind_owner("bob", OWNER, BindSource::Manual, NOW)
        .await
        .unwrap();
    let name = NameRef::parse("agent:studio.bob").unwrap();
    // First use pins agent 0x55 (the forward's pinned agent).
    let first = resolve_with(&names, &name, OWNER, &agent_candidate(0x55), NOW)
        .await
        .unwrap();
    assert_eq!(first.agent_id, Some(AgentId([0x55; 32])));
    let rec = record(&agent_spec(18023));

    // Same key after restart: comes back up.
    let again = resolve_with(&names, &name, OWNER, &agent_candidate(0x55), NOW).await;
    let (spec, _) = restore_decision(&rec, Some(again)).unwrap();
    assert_eq!(spec.peer_agent, AgentId([0x55; 32]));

    // An impostor now answers to the name: the pin refuses it and the
    // forward stays down.
    let moved = resolve_with(&names, &name, OWNER, &agent_candidate(0x77), NOW).await;
    assert!(matches!(moved, Err(NameError::PinMismatch { .. })));
    let reason = restore_decision(&rec, Some(moved)).unwrap_err();
    assert!(reason.starts_with(NAME_CHANGED), "{reason}");

    // Even if the user drops the pin and it re-pins to the new key, the
    // forward's own pinned ids still differ: still down, not retargeted.
    assert!(names.unpin("agent:studio.bob").await.unwrap());
    let repinned = resolve_with(&names, &name, OWNER, &agent_candidate(0x77), NOW).await;
    assert_eq!(
        repinned.as_ref().unwrap().agent_id,
        Some(AgentId([0x77; 32]))
    );
    let reason = restore_decision(&rec, Some(repinned)).unwrap_err();
    assert!(reason.starts_with(NAME_CHANGED), "{reason}");

    // A name that resolves to nothing stays down with its reason.
    let gone = resolve_with(&names, &name, OWNER, &Candidates::default(), NOW).await;
    let reason = restore_decision(&rec, Some(gone)).unwrap_err();
    assert!(reason.starts_with("unknown_name"), "{reason}");

    // A machine name must still reach the pinned machine AND its agent.
    let mrec = record(&machine_spec(true));
    for (agent, machine) in [([0x44; 32], [0x99; 32]), ([0x98; 32], [0x11; 32])] {
        let reason =
            restore_decision(&mrec, Some(Ok(resolved_machine(agent, machine)))).unwrap_err();
        assert!(reason.starts_with(NAME_CHANGED), "{reason}");
    }
    // A machine candidate that now carries the name is not the pinned one.
    let machines = Candidates {
        agents: Vec::new(),
        machines: vec![MachineCandidate {
            machine_id: MachineId([0x11; 32]),
            label: "box".to_string(),
            verified: true,
            agent_id: Some(AgentId([0x44; 32])),
        }],
    };
    let ok = resolve_with(
        &names,
        &NameRef::parse("machine:box.me").unwrap(),
        OWNER,
        &machines,
        NOW,
    )
    .await;
    assert_eq!(
        restore_decision(&mrec, Some(ok)).unwrap(),
        machine_spec(true).pair()
    );
}

fn assert_unconfirmed(result: &Result<bool, ForwardStoreError>) {
    assert!(
        matches!(result, Err(e) if e.durability_unconfirmed() && e.to_string().contains("not confirmed")),
        "post-rename failure must not ACK: {result:?}"
    );
}

/// WHY (#1101, same contract as NameStore): a parent-directory fsync that
/// fails after the rename has already replaced `forwards.json`. Add and
/// delete must keep memory equal to that file, refuse to ACK, and a retry
/// under the fault must not ACK either. After the fault drops, the retry
/// confirms durability and a reload agrees.
#[tokio::test]
async fn after_rename_failure_keeps_add_and_delete_and_reload_agrees() {
    let dir = tempfile::tempdir().unwrap();
    let path = ForwardStore::path_in(dir.path());
    let store = ForwardStore::load(path.clone()).await;
    let first = agent_spec(18022);
    let second = agent_spec(18023);

    // Before the rename, disk and memory stay on the old set.
    {
        let seam = crate::storage::arm_fail_durable_before_rename_for_testing(&path);
        let err = first.remember(&store).await.unwrap_err();
        assert!(
            matches!(err, ForwardStoreError::Write(_)),
            "before-rename must not install: {err}"
        );
        assert!(!err.durability_unconfirmed());
        assert!(store.records().await.unwrap().is_empty());
        drop(seam);
    }
    assert!(!path.exists(), "a before-rename failure must not publish");

    let seam = crate::storage::arm_fail_parent_dir_fsync_for_testing(&path);
    let added = first.remember(&store).await;
    assert_unconfirmed(&added);
    assert_eq!(store.records().await.unwrap(), vec![record(&first)]);

    // Identical retry while fsync still fails must not ACK.
    let retry_add = first.remember(&store).await;
    assert_unconfirmed(&retry_add);
    assert_eq!(store.records().await.unwrap(), vec![record(&first)]);

    // A second add under the same fault keeps both records (memory == disk).
    let added_second = second.remember(&store).await;
    assert_unconfirmed(&added_second);
    assert_eq!(
        store.records().await.unwrap(),
        vec![record(&first), record(&second)]
    );

    let deleted = store.forget(first.spec.local_addr).await;
    assert_unconfirmed(&deleted);
    assert_eq!(store.records().await.unwrap(), vec![record(&second)]);
    let retry_delete = store.forget(first.spec.local_addr).await;
    assert_unconfirmed(&retry_delete);
    assert_eq!(
        store.records().await.unwrap(),
        vec![record(&second)],
        "a retry must not resurrect the deleted forward"
    );

    drop(seam);
    let reloaded_while_pending = ForwardStore::load(path.clone()).await;
    assert_eq!(
        reloaded_while_pending.records().await.unwrap(),
        vec![record(&second)],
        "reload must see the renamed file, not the pre-fault set"
    );

    assert!(
        !second.remember(&store).await.unwrap(),
        "durability retry of an identical record ACKs only after the fault drops"
    );
    assert!(
        !store.forget(first.spec.local_addr).await.unwrap(),
        "the deleted id stays gone once durability is confirmed"
    );
    let reloaded = ForwardStore::load(path).await;
    assert_eq!(reloaded.records().await.unwrap(), vec![record(&second)]);
    assert_eq!(
        reloaded.records().await.unwrap(),
        store.records().await.unwrap()
    );
}

/// WHY (same contract as [`NameStore::load`]): the test above drops the
/// fsync fault before reload. A restart while that fault is still active
/// must keep durability pending, and an identical `remember` must not ACK
/// until a later sync succeeds.
#[tokio::test]
async fn reload_keeps_pending_durability_until_directory_sync() {
    use std::sync::atomic::Ordering;

    let dir = tempfile::tempdir().unwrap();
    let path = ForwardStore::path_in(dir.path());
    let store = ForwardStore::load(path.clone()).await;
    let spec = agent_spec(18022);
    let seam = crate::storage::arm_fail_parent_dir_fsync_for_testing(&path);
    let added = spec.remember(&store).await;
    assert_unconfirmed(&added);
    assert!(
        store.pending_durability.load(Ordering::Acquire),
        "the failed directory sync must stay pending"
    );

    let reloaded = ForwardStore::load(path.clone()).await;
    assert!(
        reloaded.load_error().is_none(),
        "{:?}",
        reloaded.load_error()
    );
    assert!(
        reloaded.pending_durability.load(Ordering::Acquire),
        "reload must not forget an unconfirmed directory sync"
    );
    assert_eq!(reloaded.records().await.unwrap(), vec![record(&spec)]);
    let retry = spec.remember(&reloaded).await;
    assert_unconfirmed(&retry);
    assert!(reloaded.pending_durability.load(Ordering::Acquire));

    drop(seam);
    assert!(
        !spec.remember(&reloaded).await.unwrap(),
        "an identical remember ACKs only after the directory sync succeeds"
    );
    assert!(
        !reloaded.pending_durability.load(Ordering::Acquire),
        "a confirmed directory sync clears the flag"
    );
}
