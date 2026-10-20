#![allow(clippy::unwrap_used, clippy::expect_used)]

//! ADR-0074 §1 slice-1 intent tests. Every test is deterministic (no
//! network, no clock race: times are fixed or far from any boundary) and
//! each asserts a refusal that goes red if its check is removed.

use super::*;
use crate::identity::{AgentKeypair, UserKeypair};
use crate::share_grant::{Grantee, ShareCap};

const NOW: u64 = 1_900_000_000;

fn user() -> UserKeypair {
    UserKeypair::generate().unwrap()
}

fn agent() -> AgentKeypair {
    AgentKeypair::generate().unwrap()
}

fn observed(
    kp: &AgentKeypair,
    announced: Option<UserId>,
    cert_by: Option<&UserKeypair>,
    name: &str,
    machine: Option<MachineId>,
) -> ObservedAgent {
    ObservedAgent {
        agent_id: kp.agent_id(),
        announced_user: announced,
        certificate: cert_by.map(|u| AgentCertificate::issue(u, kp).unwrap()),
        self_name: Some(name.to_string()),
        machine_id: machine,
        revoked: false,
    }
}

fn name(raw: &str) -> NameRef {
    NameRef::parse(raw).unwrap()
}

fn agent_only(agents: Vec<AgentCandidate>) -> Candidates {
    Candidates {
        agents,
        machines: Vec::new(),
    }
}

fn verified_agent(id: u8, label: &str) -> AgentCandidate {
    AgentCandidate {
        agent_id: AgentId([id; 32]),
        label: label.to_string(),
        machine_id: None,
        verified: true,
    }
}

fn verified_machine(id: u8, label: &str) -> MachineCandidate {
    MachineCandidate {
        machine_id: MachineId([id; 32]),
        label: label.to_string(),
        verified: true,
        agent_id: None,
    }
}

// ── Grammar ────────────────────────────────────────────────────────────────

/// WHY: the grammar is the first gate; every accepted form must parse to
/// exactly the kind/label/owner the user wrote.
#[test]
fn grammar_accepts_the_three_forms() {
    let cases = [
        ("studio.me", None, "studio", "me"),
        ("agent:studio.me", Some(NameKind::Agent), "studio", "me"),
        ("machine:box-1.bob", Some(NameKind::Machine), "box-1", "bob"),
        ("a.b", None, "a", "b"),
        ("x0x.alice-2", None, "x0x", "alice-2"),
    ];
    for (raw, kind, label, owner) in cases {
        let parsed = NameRef::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert_eq!(parsed.kind, kind, "{raw}");
        assert_eq!(parsed.label, label, "{raw}");
        assert_eq!(parsed.owner, owner, "{raw}");
    }
    let long = "a".repeat(MAX_LABEL_LEN);
    assert!(
        NameRef::parse(&format!("{long}.me")).is_ok(),
        "63 chars is legal"
    );
}

/// WHY: anything outside the grammar must be refused, never normalised
/// into a different name (fail closed).
#[test]
fn grammar_rejects_bad_inputs() {
    let long = "a".repeat(MAX_LABEL_LEN + 1);
    let too_long = format!("{long}.me");
    let cases: Vec<(&str, &str)> = vec![
        ("", "invalid_name"),
        ("studio", "invalid_name"),
        ("studio.", "invalid_name"),
        (".me", "invalid_name"),
        ("a.b.c", "invalid_name"),
        ("Studio.me", "invalid_name"),
        ("studio.ME", "invalid_name"),
        ("stu dio.me", "invalid_name"),
        (" studio.me", "invalid_name"),
        ("studio.me ", "invalid_name"),
        ("-studio.me", "invalid_name"),
        ("studio-.me", "invalid_name"),
        ("stu_dio.me", "invalid_name"),
        ("stüdio.me", "invalid_name"),
        ("host:studio.me", "invalid_name"),
        ("agent:machine:studio.me", "invalid_name"),
        ("agent:", "invalid_name"),
        ("studio.me.x0x", "invalid_name"),
        (too_long.as_str(), "invalid_name"),
        ("me.me", "reserved_label"),
        ("agent.me", "reserved_label"),
        ("machine.bob", "reserved_label"),
        ("agent:machine.me", "reserved_label"),
        ("studio.agent", "reserved_label"),
        ("studio.machine", "reserved_label"),
    ];
    for (raw, code) in cases {
        match NameRef::parse(raw) {
            Ok(parsed) => panic!("{raw:?} must be refused, parsed as {parsed:?}"),
            Err(e) => assert_eq!(e.code(), code, "{raw:?}: {e}"),
        }
    }
}

/// WHY: hex stays valid everywhere; a forward refuses a `machine:` name
/// until slice 2 checks the stream reaches the pinned MachineId.
#[test]
fn peer_ref_accepts_hex_and_forward_peer_refuses_machine_names() {
    let hex_id = "ab".repeat(32);
    assert_eq!(
        PeerRef::parse(&hex_id).unwrap(),
        PeerRef::Hex(AgentId([0xab; 32]))
    );
    assert_eq!(
        PeerRef::parse(&"AB".repeat(32)).unwrap(),
        PeerRef::Hex(AgentId([0xab; 32]))
    );
    assert!(matches!(
        PeerRef::parse_forward_peer("agent:studio.me").unwrap(),
        PeerRef::Name(_)
    ));
    assert!(matches!(
        PeerRef::parse_forward_peer("studio.me").unwrap(),
        PeerRef::Name(_)
    ));
    let err = PeerRef::parse_forward_peer("machine:studio.me").unwrap_err();
    assert_eq!(err.code(), "machine_target_unsupported", "{err}");
    // A bare label that resolves to a machine is refused the same way.
    let resolved = Resolved {
        name: "machine:studio.me".into(),
        kind: NameKind::Machine,
        owner: UserId([1; 32]),
        agent_id: Some(AgentId([2; 32])),
        machine_id: Some(MachineId([3; 32])),
        newly_pinned: false,
    };
    let err = require_agent_target(&resolved, &name("studio.me")).unwrap_err();
    assert_eq!(err.code(), "machine_target_unsupported");
}

#[test]
fn display_names_map_to_labels_or_to_nothing() {
    let cases = [
        ("Studio", Some("studio")),
        ("Studio Mac", Some("studio-mac")),
        ("  m5_max.local ", Some("m5-max-local")),
        ("David  Irvine", Some("david-irvine")),
        ("--x--", Some("x")),
        ("Me", None),
        ("agent", None),
        ("", None),
        ("Stüdio", None),
        ("a/b", None),
    ];
    for (display, want) in cases {
        assert_eq!(label_from_display(display).as_deref(), want, "{display:?}");
    }
}

// ── Selection ──────────────────────────────────────────────────────────────

/// WHY: a bare label naming both an agent and a machine must fail with
/// AmbiguousKind, and each prefix must then pick its own kind.
#[test]
fn bare_label_naming_agent_and_machine_is_ambiguous_kind_until_prefixed() {
    let candidates = Candidates {
        agents: vec![verified_agent(1, "studio")],
        machines: vec![verified_machine(2, "studio")],
    };
    let err = select(&name("studio.me"), &candidates).unwrap_err();
    assert_eq!(err, NameError::AmbiguousKind("studio.me".into()));
    let agent = select(&name("agent:studio.me"), &candidates).unwrap();
    assert_eq!((agent.kind, agent.id), (NameKind::Agent, [1; 32]));
    let machine = select(&name("machine:studio.me"), &candidates).unwrap();
    assert_eq!((machine.kind, machine.id), (NameKind::Machine, [2; 32]));
}

/// WHY: two candidates of one kind is AmbiguousName listing both hex ids,
/// never a silent pick.
#[test]
fn two_agents_with_one_label_are_ambiguous_and_listed() {
    let candidates = agent_only(vec![verified_agent(1, "bot"), verified_agent(2, "bot")]);
    match select(&name("bot.bob"), &candidates).unwrap_err() {
        NameError::AmbiguousName { candidates, .. } => {
            assert_eq!(
                candidates,
                vec![hex::encode([1u8; 32]), hex::encode([2u8; 32])]
            );
        }
        other => panic!("expected AmbiguousName, got {other:?}"),
    }
}

/// WHY: a same-name impostor under another owner is never resolved; with
/// only the impostor present the name is refused, and it never displaces
/// the genuine agent.
#[test]
fn same_name_impostor_of_another_owner_is_not_resolved() {
    let alice = user();
    let mallory = user();
    let genuine = agent();
    let impostor = agent();
    // The impostor even announces alice's user id; its cert is mallory's.
    let impostor_obs = observed(
        &impostor,
        Some(alice.user_id()),
        Some(&mallory),
        "studio",
        None,
    );
    let only_impostor =
        agent_candidates(&alice.user_id(), std::slice::from_ref(&impostor_obs), NOW);
    let err = select(&name("studio.alice"), &agent_only(only_impostor)).unwrap_err();
    assert_eq!(err.code(), "unverified_owner", "{err}");

    let both = agent_candidates(
        &alice.user_id(),
        &[
            impostor_obs,
            observed(
                &genuine,
                Some(alice.user_id()),
                Some(&alice),
                "studio",
                None,
            ),
        ],
        NOW,
    );
    let chosen = select(&name("studio.alice"), &agent_only(both)).unwrap();
    assert_eq!(chosen.agent_id, Some(genuine.agent_id()));

    // Under mallory's own owner label the impostor's agent is mallory's,
    // not alice's: owners never leak into each other.
    let mallory_view = agent_candidates(
        &mallory.user_id(),
        &[observed(
            &genuine,
            Some(alice.user_id()),
            Some(&alice),
            "studio",
            None,
        )],
        NOW,
    );
    assert!(mallory_view.is_empty(), "alice's agent is not mallory's");
}

/// WHY: `me` resolves only agents certified by the local owner: a claim
/// without a certificate, or a revoked agent, is refused.
#[test]
fn me_resolves_only_certified_unrevoked_agents() {
    let owner = user();
    let certified = agent();
    let uncertified = agent();
    let revoked = agent();
    let mut revoked_obs = observed(&revoked, Some(owner.user_id()), Some(&owner), "old", None);
    revoked_obs.revoked = true;
    let candidates = agent_only(agent_candidates(
        &owner.user_id(),
        &[
            observed(
                &certified,
                Some(owner.user_id()),
                Some(&owner),
                "studio",
                None,
            ),
            observed(&uncertified, Some(owner.user_id()), None, "laptop", None),
            revoked_obs,
        ],
        NOW,
    ));
    let ok = select(&name("studio.me"), &candidates).unwrap();
    assert_eq!(ok.agent_id, Some(certified.agent_id()));
    for refused in ["laptop.me", "old.me"] {
        let err = select(&name(refused), &candidates).unwrap_err();
        assert_eq!(err.code(), "unverified_owner", "{refused}: {err}");
    }
    let err = select(&name("nobody.me"), &candidates).unwrap_err();
    assert_eq!(err.code(), "unknown_name");
}

/// WHY: machine names come ONLY from machines with a current ADR-0041
/// enrollment by the local owner. An unenrolled machine carrying the same
/// kind of synced name, a foreign-owner enrollment and an expired
/// enrollment are all refused.
#[test]
fn machine_name_resolves_only_for_an_enrolled_machine() {
    let owner = user();
    let stranger = user();
    let now_ms = NOW * 1000;
    let enrolled = MachineId([1; 32]);
    let unenrolled = MachineId([2; 32]);
    let foreign = MachineId([3; 32]);
    let expired = MachineId([4; 32]);
    let enrollments = vec![
        OwnerEnrollment::sign(enrolled, &owner, now_ms - 10, None).unwrap(),
        OwnerEnrollment::sign(foreign, &stranger, now_ms - 10, None).unwrap(),
        OwnerEnrollment::sign(
            expired,
            &owner,
            now_ms - 10_000_000,
            Some(now_ms - 5_000_000),
        )
        .unwrap(),
    ];
    let names = vec![
        (enrolled, "Studio".to_string()),
        (unenrolled, "Laptop".to_string()),
        (foreign, "Foreign".to_string()),
        (expired, "Old Box".to_string()),
    ];
    let machines = own_machine_candidates(
        &owner.user_id(),
        &enrollments,
        &names,
        &BTreeSet::new(),
        &[],
        now_ms,
    );
    let candidates = Candidates {
        agents: Vec::new(),
        machines,
    };
    let ok = select(&name("machine:studio.me"), &candidates).unwrap();
    assert_eq!(ok.machine_id, Some(enrolled));
    for refused in [
        "machine:laptop.me",
        "machine:foreign.me",
        "machine:old-box.me",
    ] {
        let err = select(&name(refused), &candidates).unwrap_err();
        assert_eq!(err.code(), "unverified_owner", "{refused}: {err}");
    }

    // A revoked machine is refused even while enrolled.
    let revoked = own_machine_candidates(
        &owner.user_id(),
        &enrollments,
        &names,
        &BTreeSet::from([enrolled.0]),
        &[],
        now_ms,
    );
    let err = select(
        &name("machine:studio.me"),
        &Candidates {
            agents: Vec::new(),
            machines: revoked,
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), "unverified_owner");
}

/// WHY: a shared machine resolves only while it hosts a certified agent of
/// an active, unrevoked grant signed by that owner ("or granted"); expiry,
/// revocation and a grant from anyone else refuse it.
#[test]
fn shared_machine_name_resolves_only_while_granted() {
    let bob = user();
    let me = user();
    let other = user();
    let bob_agent = agent();
    let machine = MachineId([9; 32]);
    let agents = agent_candidates(
        &bob.user_id(),
        &[observed(
            &bob_agent,
            Some(bob.user_id()),
            Some(&bob),
            "srv",
            Some(machine),
        )],
        NOW,
    );
    let grant = |by: &UserKeypair, expiry: u64| {
        crate::share_grant::ShareGrant::sign(
            by,
            [7; 32],
            Grantee::User(me.user_id()),
            vec![bob_agent.agent_id()],
            vec![ShareCap::Connect { ports: vec![22] }],
            NOW - 100,
            expiry,
        )
        .unwrap()
    };
    let labels = vec![("box".to_string(), machine)];
    let resolve = |received: &[(ShareGrant, bool)], now: u64| {
        let machines = shared_machine_candidates(
            &bob.user_id(),
            &labels,
            received,
            &agents,
            &BTreeSet::new(),
            now,
        );
        select(
            &name("machine:box.bob"),
            &Candidates {
                agents: agents.clone(),
                machines,
            },
        )
    };
    let active = grant(&bob, NOW + 3600);
    let ok = resolve(&[(active.clone(), false)], NOW).unwrap();
    assert_eq!(ok.machine_id, Some(machine));
    assert_eq!(
        ok.agent_id,
        Some(bob_agent.agent_id()),
        "only the granted agent"
    );

    type GrantCase = (&'static str, Vec<(ShareGrant, bool)>, u64);
    let cases: Vec<GrantCase> = vec![
        ("no grant", Vec::new(), NOW),
        ("expired", vec![(active.clone(), false)], NOW + 7200),
        ("revoked", vec![(active, true)], NOW),
        (
            "signed by someone else",
            vec![(grant(&other, NOW + 3600), false)],
            NOW,
        ),
    ];
    for (why, received, now) in cases {
        let err = resolve(&received, now).unwrap_err();
        assert_eq!(err.code(), "unverified_owner", "{why}: {err}");
    }
}

// ── Pins and persistence ───────────────────────────────────────────────────

/// WHY: the first successful resolution pins the name; later resolutions
/// to the same id are not re-pinned.
#[tokio::test]
async fn first_use_pins_the_name() {
    let store = NameStore::in_memory();
    let owner = UserId([5; 32]);
    let candidates = agent_only(vec![verified_agent(1, "studio")]);
    let first = resolve_with(&store, &name("studio.me"), owner, &candidates, NOW)
        .await
        .unwrap();
    assert!(first.newly_pinned);
    assert_eq!(first.name, "agent:studio.me");
    let pin = store.get_pin("agent:studio.me").await.unwrap().unwrap();
    assert_eq!((pin.id, pin.owner), ([1; 32], owner));
    assert_eq!(pin.source, BindSource::FirstUse);
    let again = resolve_with(
        &store,
        &name("agent:studio.me"),
        owner,
        &candidates,
        NOW + 1,
    )
    .await
    .unwrap();
    assert!(!again.newly_pinned);
}

/// WHY: the core invariant — a pinned name that now resolves to a
/// different key fails loud and the pin is never rewritten.
#[tokio::test]
async fn pin_mismatch_is_refused_and_the_pin_is_kept() {
    let store = NameStore::in_memory();
    let owner = UserId([5; 32]);
    resolve_with(
        &store,
        &name("studio.bob"),
        owner,
        &agent_only(vec![verified_agent(1, "studio")]),
        NOW,
    )
    .await
    .unwrap();
    // The genuine agent is gone; a different (still validly certified)
    // agent now announces the same name.
    let moved = agent_only(vec![verified_agent(2, "studio")]);
    let err = resolve_with(&store, &name("studio.bob"), owner, &moved, NOW + 1)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        NameError::PinMismatch {
            name: "agent:studio.bob".into(),
            pinned: hex::encode([1u8; 32]),
            current: hex::encode([2u8; 32]),
        }
    );
    // Same id under a different owner key is also a mismatch.
    let err = resolve_with(
        &store,
        &name("studio.bob"),
        UserId([6; 32]),
        &agent_only(vec![verified_agent(1, "studio")]),
        NOW + 2,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "pin_mismatch");
    let pin = store.get_pin("agent:studio.bob").await.unwrap().unwrap();
    assert_eq!((pin.id, pin.owner), ([1; 32], owner), "pin unchanged");

    // The owner's explicit re-pin: drop the pin, next use pins anew.
    assert!(store.unpin("agent:studio.bob").await.unwrap());
    let repinned = resolve_with(&store, &name("studio.bob"), owner, &moved, NOW + 3)
        .await
        .unwrap();
    assert!(repinned.newly_pinned);
    assert_eq!(repinned.agent_id, Some(AgentId([2; 32])));
}

/// WHY: owner petnames are frozen at first bind; rebinding to another key
/// is refused until the owner removes the label (which drops its pins).
#[tokio::test]
async fn owner_petname_is_frozen_at_first_bind() {
    let store = NameStore::in_memory();
    let (u1, u2) = (UserId([1; 32]), UserId([2; 32]));
    assert_eq!(
        store
            .bind_owner("bob", u1, BindSource::Card, NOW)
            .await
            .unwrap(),
        BindOutcome::Inserted
    );
    assert_eq!(
        store
            .bind_owner("bob", u1, BindSource::Manual, NOW)
            .await
            .unwrap(),
        BindOutcome::Unchanged
    );
    let err = store
        .bind_owner("bob", u2, BindSource::Manual, NOW)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "pin_mismatch");
    assert_eq!(store.owner("bob").await.unwrap().unwrap().user_id, u1);
    for reserved in ["me", "agent", "machine"] {
        let err = store
            .bind_owner(reserved, u2, BindSource::Manual, NOW)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "reserved_label", "{reserved}");
    }
    assert!(store.owner("nobody").await.unwrap().is_none());

    store
        .pin("agent:studio.bob", u1, [3; 32], BindSource::FirstUse, NOW)
        .await
        .unwrap();
    store
        .pin("agent:studio.bobby", u1, [4; 32], BindSource::FirstUse, NOW)
        .await
        .unwrap();
    assert!(store.unbind_owner("bob").await.unwrap());
    assert!(store.get_pin("agent:studio.bob").await.unwrap().is_none());
    assert!(
        store.get_pin("agent:studio.bobby").await.unwrap().is_some(),
        "only pins under exactly `bob` go"
    );
    assert_eq!(
        store
            .bind_owner("bob", u2, BindSource::Manual, NOW)
            .await
            .unwrap(),
        BindOutcome::Inserted
    );
}

/// WHY: names persist by default. Petnames and pins survive a restart, a
/// pin still refuses a different key after reload, and a corrupt file
/// fails closed instead of silently forgetting pins.
#[tokio::test]
async fn names_and_pins_persist_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = NameStore::path_in(dir.path());
    let owner = UserId([8; 32]);
    {
        let store = NameStore::load(path.clone()).await;
        assert!(store.load_error().is_none());
        store
            .bind_owner("bob", owner, BindSource::Manual, NOW)
            .await
            .unwrap();
        resolve_with(
            &store,
            &name("studio.bob"),
            owner,
            &agent_only(vec![verified_agent(1, "studio")]),
            NOW,
        )
        .await
        .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "names.json must be private");
    }
    let reloaded = NameStore::load(path.clone()).await;
    assert!(
        reloaded.load_error().is_none(),
        "{:?}",
        reloaded.load_error()
    );
    assert_eq!(reloaded.owner("bob").await.unwrap().unwrap().user_id, owner);
    let err = resolve_with(
        &reloaded,
        &name("studio.bob"),
        owner,
        &agent_only(vec![verified_agent(2, "studio")]),
        NOW + 1,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "pin_mismatch", "the pin survived the restart");

    // Unknown fields and a wrong version are corruption, not slack.
    for bad in [
        r#"{"version":1,"owners":{},"pins":{},"extra":1}"#,
        r#"{"version":2,"owners":{},"pins":{}}"#,
        r#"{"version":1,"owners":{"Bob":{"user_id":"00","bound_at":0,"source":"manual"}},"pins":{}}"#,
        "not json",
    ] {
        std::fs::write(&path, bad).unwrap();
        let broken = NameStore::load(path.clone()).await;
        assert!(broken.load_error().is_some(), "{bad}");
        let err = resolve_with(
            &broken,
            &name("studio.bob"),
            owner,
            &agent_only(vec![verified_agent(2, "studio")]),
            NOW,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), "name_store", "{bad}: must refuse, not re-pin");
    }
}
