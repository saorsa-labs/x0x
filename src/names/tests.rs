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
        label: Some(label.to_string()),
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
    assert!(matches!(
        PeerRef::parse_forward_peer("machine:studio.me").unwrap(),
        PeerRef::Name(_)
    ));
    let resolved = Resolved {
        name: "machine:studio.me".into(),
        kind: NameKind::Machine,
        owner: UserId([1; 32]),
        agent_id: Some(AgentId([2; 32])),
        machine_id: Some(MachineId([3; 32])),
        newly_pinned: false,
    };
    let (agent, pinned) = forward_target(&resolved, &name("machine:studio.me")).unwrap();
    assert_eq!(agent, AgentId([2; 32]));
    assert_eq!(pinned, Some(MachineId([3; 32])));
}

/// WHY (Claude #1494 e338df79): a bare label that resolves to a machine must
/// not pin when the caller asked for an agent-only resolution.
/// `resolve_with_options` checks kind before `pin`. `POST /forwards` does
/// not use that flag: a machine name is pinned and bound (ADR-0074 slice 2).
#[tokio::test]
async fn agent_only_resolve_refuses_machine_before_pinning() {
    let store = NameStore::in_memory();
    let owner = UserId([9; 32]);
    let candidates = Candidates {
        agents: vec![],
        machines: vec![verified_machine(3, "studio")],
    };
    let err = resolve_with_options(&store, &name("studio.me"), owner, &candidates, NOW, true)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "machine_target_unsupported", "{err}");
    assert!(
        store.get_pin("machine:studio.me").await.unwrap().is_none(),
        "refused forward must not write a machine pin"
    );
}

/// WHY (Claude #1494 e338df79): `unbind_owner` validates the label first.
#[tokio::test]
async fn unbind_owner_rejects_invalid_label() {
    let store = NameStore::in_memory();
    let err = store.unbind_owner("Not A Label").await.unwrap_err();
    assert_eq!(err.code(), "invalid_name", "{err}");
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

/// WHY (Claude #1494 e338df79 P2): announce `self_name` is verified only
/// when the announce machine equals the authority-selected machine.
#[test]
fn verified_announce_self_name_requires_authenticated_machine_match() {
    let announce = MachineId([1; 32]);
    let auth = MachineId([1; 32]);
    let other = MachineId([2; 32]);
    assert_eq!(
        verified_announce_self_name(announce, Some(auth), Some("studio".into())).as_deref(),
        Some("studio")
    );
    assert!(
        verified_announce_self_name(announce, Some(other), Some("evil".into())).is_none(),
        "foreign announce machine must drop the label"
    );
    assert!(
        verified_announce_self_name(announce, None, Some("evil".into())).is_none(),
        "no auth binding while announce claims a name ⇒ unverified"
    );
    assert!(
        verified_announce_self_name(
            MachineId([0; 32]),
            Some(MachineId([0; 32])),
            Some("x".into())
        )
        .is_none(),
        "all-zero machine id is not a verified announce source"
    );
}

/// WHY (Claude #1494 e338df79 P2): a certified peer claiming the same label
/// from a foreign announce machine is stripped at the gatherer. Modelled
/// via [`verified_announce_self_name`]: the spoofed label is absent, the
/// legitimate candidate still resolves, and there is no AmbiguousName.
#[test]
fn foreign_machine_self_name_spoof_does_not_hijack_or_ambiguate() {
    let bob = user();
    let real = agent();
    let spoof_agent = agent();
    let auth_machine = MachineId([4; 32]);
    let foreign_machine = MachineId([5; 32]);
    // Legitimate observation (gatherer kept self_name — machines matched).
    let legit = observed(
        &real,
        Some(bob.user_id()),
        Some(&bob),
        "studio",
        Some(auth_machine),
    );
    // Second certified agent under the same owner. If the gatherer trusted
    // its announce self_name ("studio") despite machine mismatch, select
    // would return AmbiguousName. After the strip, it has no label.
    let mut spoof_stripped = observed(
        &spoof_agent,
        Some(bob.user_id()),
        Some(&bob),
        "studio",
        Some(foreign_machine),
    );
    spoof_stripped.self_name =
        verified_announce_self_name(foreign_machine, Some(auth_machine), Some("studio".into()));
    assert!(spoof_stripped.self_name.is_none());
    // ObservedAgent.machine_id is the authenticated binding (gatherer).
    spoof_stripped.machine_id = Some(auth_machine);
    let agents = agent_candidates(&bob.user_id(), &[legit, spoof_stripped], NOW);
    let studio = select(&name("studio.bob"), &agent_only(agents)).unwrap();
    assert_eq!(studio.agent_id, Some(real.agent_id()));
    let ambiguated = agent_candidates(
        &bob.user_id(),
        &[
            observed(
                &real,
                Some(bob.user_id()),
                Some(&bob),
                "studio",
                Some(auth_machine),
            ),
            observed(
                &spoof_agent,
                Some(bob.user_id()),
                Some(&bob),
                "studio",
                Some(foreign_machine),
            ),
        ],
        NOW,
    );
    assert!(
        matches!(
            select(&name("studio.bob"), &agent_only(ambiguated)),
            Err(NameError::AmbiguousName { .. })
        ),
        "control: trusting both announce labels would AmbiguousName"
    );
}

/// WHY (PR #1494 P2b): a certified granted agent with no display name still
/// proves shared-machine eligibility — machine binding is independent of
/// agent-label matching.
#[test]
fn shared_machine_resolves_when_granted_agent_has_no_display_name() {
    let bob = user();
    let me = user();
    let bob_agent = agent();
    let machine = MachineId([9; 32]);
    let mut obs = observed(
        &bob_agent,
        Some(bob.user_id()),
        Some(&bob),
        "srv",
        Some(machine),
    );
    obs.self_name = None;
    let agents = agent_candidates(&bob.user_id(), &[obs], NOW);
    assert!(
        agents.iter().any(|a| a.verified && a.label.is_none()),
        "unlabeled verified host must remain a candidate"
    );
    assert!(
        select(&name("agent:srv.bob"), &agent_only(agents.clone())).is_err(),
        "no DNS self-name ⇒ no agent-label match"
    );
    let grant = crate::share_grant::ShareGrant::sign(
        &bob,
        [7; 32],
        Grantee::User(me.user_id()),
        vec![bob_agent.agent_id()],
        vec![ShareCap::Connect { ports: vec![22] }],
        NOW - 100,
        NOW + 3600,
    )
    .unwrap();
    let machines = shared_machine_candidates(
        &bob.user_id(),
        &[("box".to_string(), machine)],
        &[(grant, false)],
        &agents,
        &BTreeSet::new(),
        NOW,
    );
    let ok = select(&name("machine:box.bob"), &Candidates { agents, machines }).unwrap();
    assert_eq!(ok.machine_id, Some(machine));
    assert_eq!(ok.agent_id, Some(bob_agent.agent_id()));
}

/// WHY (PR #1494 P2b): a Unicode self-name (`René`) is not a DNS label, but
/// the certified granted agent on that machine still verifies a shared
/// machine label.
#[test]
fn shared_machine_resolves_when_granted_agent_has_unicode_name() {
    let bob = user();
    let me = user();
    let bob_agent = agent();
    let machine = MachineId([11; 32]);
    let obs = observed(
        &bob_agent,
        Some(bob.user_id()),
        Some(&bob),
        "René",
        Some(machine),
    );
    assert!(
        label_from_display("René").is_none(),
        "Unicode display must not yield a DNS label"
    );
    let agents = agent_candidates(&bob.user_id(), &[obs], NOW);
    assert!(
        agents
            .iter()
            .any(|a| a.verified && a.label.is_none() && a.machine_id == Some(machine)),
        "Unicode-named verified host must remain for machine checks"
    );
    let grant = crate::share_grant::ShareGrant::sign(
        &bob,
        [8; 32],
        Grantee::User(me.user_id()),
        vec![bob_agent.agent_id()],
        vec![ShareCap::Connect { ports: vec![22] }],
        NOW - 100,
        NOW + 3600,
    )
    .unwrap();
    let machines = shared_machine_candidates(
        &bob.user_id(),
        &[("box".to_string(), machine)],
        &[(grant, false)],
        &agents,
        &BTreeSet::new(),
        NOW,
    );
    let ok = select(&name("machine:box.bob"), &Candidates { agents, machines }).unwrap();
    assert_eq!(ok.machine_id, Some(machine));
    assert_eq!(ok.agent_id, Some(bob_agent.agent_id()));
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

/// WHY: ADR 0074 §1. When the pinned kind is gone and only the other kind
/// remains, the bare name is `pin_mismatch` and must not mint a second pin.
/// A pin does not win while both kinds are still present; that case is
/// [`bare_name_is_ambiguous_kind_despite_an_existing_pin`].
#[tokio::test]
async fn bare_name_keeps_inferred_kind_across_a_kind_change() {
    let store = NameStore::in_memory();
    let owner = UserId([5; 32]);
    let machine = Candidates {
        agents: vec![],
        machines: vec![verified_machine(3, "studio")],
    };
    let first = resolve_with(&store, &name("studio.me"), owner, &machine, NOW)
        .await
        .unwrap();
    assert_eq!(first.name, "machine:studio.me");
    assert_eq!(first.kind, NameKind::Machine);
    assert!(first.newly_pinned);

    let agent = Candidates {
        agents: vec![verified_agent(7, "studio")],
        machines: vec![],
    };
    let err = resolve_with(&store, &name("studio.me"), owner, &agent, NOW + 1)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        NameError::PinMismatch {
            name: "machine:studio.me".into(),
            pinned: hex::encode([3u8; 32]),
            current: hex::encode([7u8; 32]),
        }
    );
    assert!(
        store.get_pin("agent:studio.me").await.unwrap().is_none(),
        "a kind change must not write a second pin"
    );
    let pin = store.get_pin("machine:studio.me").await.unwrap().unwrap();
    assert_eq!((pin.id, pin.owner), ([3; 32], owner));
}

/// WHY: ADR 0074 §1. A bare name that matches a verified agent and a
/// verified machine is `AmbiguousKind` even when a pin already exists.
#[tokio::test]
async fn bare_name_is_ambiguous_kind_despite_an_existing_pin() {
    let store = NameStore::in_memory();
    let owner = UserId([5; 32]);
    let machine = Candidates {
        agents: vec![],
        machines: vec![verified_machine(3, "studio")],
    };
    let first = resolve_with(&store, &name("studio.me"), owner, &machine, NOW)
        .await
        .unwrap();
    assert_eq!(first.name, "machine:studio.me");
    assert!(first.newly_pinned);

    let both = Candidates {
        agents: vec![verified_agent(7, "studio")],
        machines: vec![verified_machine(3, "studio")],
    };
    let err = resolve_with(&store, &name("studio.me"), owner, &both, NOW + 1)
        .await
        .unwrap_err();
    assert_eq!(err, NameError::AmbiguousKind("studio.me".into()));
    assert!(
        store.get_pin("agent:studio.me").await.unwrap().is_none(),
        "ambiguity must not write the other kind"
    );
    let pin = store.get_pin("machine:studio.me").await.unwrap().unwrap();
    assert_eq!((pin.id, pin.owner), ([3; 32], owner));

    let prefixed = resolve_with(&store, &name("machine:studio.me"), owner, &both, NOW + 2)
        .await
        .unwrap();
    assert_eq!(prefixed.kind, NameKind::Machine);
    assert!(!prefixed.newly_pinned);
}

/// WHY: two bare resolves that see different single-kind snapshots must
/// not both insert. The kind check and the insert share one commit.
#[tokio::test]
async fn concurrent_bare_resolves_do_not_pin_both_kinds() {
    let store = std::sync::Arc::new(NameStore::in_memory());
    let owner = UserId([5; 32]);
    let machine = Candidates {
        agents: vec![],
        machines: vec![verified_machine(3, "studio")],
    };
    let agent = Candidates {
        agents: vec![verified_agent(7, "studio")],
        machines: vec![],
    };
    let left_store = std::sync::Arc::clone(&store);
    let left = tokio::spawn(async move {
        resolve_with(&left_store, &name("studio.me"), owner, &machine, NOW).await
    });
    let right_store = std::sync::Arc::clone(&store);
    let right = tokio::spawn(async move {
        resolve_with(&right_store, &name("studio.me"), owner, &agent, NOW).await
    });
    let left = left.await.unwrap();
    let right = right.await.unwrap();
    let results = [left, right];
    let pinned = results.iter().filter(|result| result.is_ok()).count();
    let mismatched = results
        .iter()
        .filter(|result| matches!(result, Err(NameError::PinMismatch { .. })))
        .count();
    assert_eq!(pinned, 1, "{results:?}");
    assert_eq!(mismatched, 1, "{results:?}");
    let agent_pin = store.get_pin("agent:studio.me").await.unwrap();
    let machine_pin = store.get_pin("machine:studio.me").await.unwrap();
    assert!(
        agent_pin.is_some() ^ machine_pin.is_some(),
        "exactly one kind may be pinned: agent={agent_pin:?} machine={machine_pin:?}"
    );
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

/// WHY (#1101 / PR #1494 P2a): when the durable store write fails AFTER the
/// atomic rename, the new binding is already in `names.json`. Commit must
/// keep it in memory (memory == disk) and still return [`NameError::Store`]
/// — never roll memory back below an advanced disk. An identical retry while
/// fsync still fails must not ACK as [`BindOutcome::Unchanged`]. Uses the
/// parent-dir fsync AfterRename seam (`arm_fail_parent_dir_fsync_for_testing`);
/// the corrupt-after-rename seam would overwrite the new bytes and break the
/// agreement assertion.
#[tokio::test]
async fn commit_after_rename_failure_keeps_binding_and_reload_agrees() {
    let dir = tempfile::tempdir().unwrap();
    let path = NameStore::path_in(dir.path());
    let owner = UserId([9; 32]);
    let store = NameStore::load(path.clone()).await;
    assert!(store.load_error().is_none());

    let seam = crate::storage::arm_fail_parent_dir_fsync_for_testing(&path);
    let outcome = store
        .bind_owner("bob", owner, BindSource::Manual, NOW)
        .await;
    assert!(
        matches!(&outcome, Err(NameError::Store(msg)) if msg.contains("not confirmed")),
        "post-rename failure must not ACK: {outcome:?}"
    );

    // Memory keeps the binding: it matches the advanced disk.
    let mem = store.owner("bob").await.unwrap().expect("memory has bob");
    assert_eq!(mem.user_id, owner);

    // Identical retry while fsync still fails: pending durability must
    // re-attempt the write and still refuse the ACK (not Unchanged).
    let retry_while_faulted = store
        .bind_owner("bob", owner, BindSource::Manual, NOW)
        .await;
    assert!(
        matches!(&retry_while_faulted, Err(NameError::Store(msg)) if msg.contains("not confirmed")),
        "retry under AfterRename fault must not ACK Unchanged: {retry_while_faulted:?}"
    );
    assert_eq!(
        store
            .owner("bob")
            .await
            .unwrap()
            .expect("still bob")
            .user_id,
        owner
    );

    // A reload from disk agrees with memory — the binding really is stored.
    drop(seam);
    let confirmed = store
        .bind_owner("bob", owner, BindSource::Manual, NOW)
        .await
        .expect("durability retry after seam drop");
    assert_eq!(confirmed, BindOutcome::Unchanged);

    let reloaded = NameStore::load(path).await;
    assert!(
        reloaded.load_error().is_none(),
        "{:?}",
        reloaded.load_error()
    );
    let disk = reloaded.owner("bob").await.unwrap().expect("disk has bob");
    assert_eq!(disk.user_id, owner);
    assert_eq!(disk, mem);
}

/// WHY (PR #1494 RC6): the test above repairs durability before reload.
/// A restart while the parent-directory fsync is still failing must keep
/// `pending_durability` set, and an identical bind must not ACK until a
/// later sync succeeds.
#[tokio::test]
async fn reload_keeps_pending_durability_until_directory_sync() {
    let dir = tempfile::tempdir().unwrap();
    let path = NameStore::path_in(dir.path());
    let owner = UserId([9; 32]);
    let store = NameStore::load(path.clone()).await;
    assert!(store.load_error().is_none());

    let seam = crate::storage::arm_fail_parent_dir_fsync_for_testing(&path);
    let outcome = store
        .bind_owner("bob", owner, BindSource::Manual, NOW)
        .await;
    assert!(
        matches!(&outcome, Err(NameError::Store(msg)) if msg.contains("not confirmed")),
        "post-rename failure must not ACK: {outcome:?}"
    );
    assert!(
        store
            .pending_durability
            .load(std::sync::atomic::Ordering::Acquire),
        "the failed directory sync must stay pending"
    );

    let reloaded = NameStore::load(path.clone()).await;
    assert!(
        reloaded.load_error().is_none(),
        "{:?}",
        reloaded.load_error()
    );
    assert!(
        reloaded
            .pending_durability
            .load(std::sync::atomic::Ordering::Acquire),
        "reload must not forget an unconfirmed directory sync"
    );
    assert_eq!(
        reloaded
            .owner("bob")
            .await
            .unwrap()
            .expect("disk has bob")
            .user_id,
        owner
    );
    let retry = reloaded
        .bind_owner("bob", owner, BindSource::Manual, NOW)
        .await;
    assert!(
        matches!(&retry, Err(NameError::Store(msg)) if msg.contains("not confirmed")),
        "identical bind after reload must not ACK Unchanged: {retry:?}"
    );
    assert!(reloaded
        .pending_durability
        .load(std::sync::atomic::Ordering::Acquire));

    drop(seam);
    let confirmed = reloaded
        .bind_owner("bob", owner, BindSource::Manual, NOW)
        .await
        .expect("durability retry after seam drop");
    assert_eq!(confirmed, BindOutcome::Unchanged);
    assert!(
        !reloaded
            .pending_durability
            .load(std::sync::atomic::Ordering::Acquire),
        "a confirmed directory sync clears the flag"
    );
}

/// WHY (PR #1494 RC4): cancellation during the rename must not drop the
/// publish. The name lock stays held until memory matches the file a
/// blocking rename can still finish, so a later write cannot replace the
/// published binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_during_rename_keeps_pin_for_later_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = NameStore::path_in(dir.path());
    let store = std::sync::Arc::new(NameStore::load(path.clone()).await);
    assert!(store.load_error().is_none());
    let bob = UserId([9; 32]);
    let ada = UserId([3; 32]);
    let pause = crate::storage::arm_durable_rename_pause_for_testing(&path);

    let writer_store = std::sync::Arc::clone(&store);
    let writer = tokio::spawn(async move {
        writer_store
            .bind_owner("bob", bob, BindSource::Manual, NOW)
            .await
    });
    let start = std::time::Instant::now();
    while !crate::storage::durable_rename_pause_entered_for_testing(&path) {
        if start.elapsed() > std::time::Duration::from_secs(5) {
            panic!("rename did not reach the cancellation point");
        }
        tokio::task::yield_now().await;
    }

    let later_store = std::sync::Arc::clone(&store);
    let later = tokio::spawn(async move {
        later_store
            .bind_owner("ada", ada, BindSource::Manual, NOW)
            .await
    });
    let start = std::time::Instant::now();
    while store.state_lock_waiters() == 0 {
        if start.elapsed() > std::time::Duration::from_secs(5) {
            panic!("later write did not queue on the name lock");
        }
        tokio::task::yield_now().await;
    }

    writer.abort();
    let aborted = writer.await.expect_err("the rename task must be cancelled");
    assert!(aborted.is_cancelled());
    drop(pause);

    let ada_outcome = tokio::time::timeout(std::time::Duration::from_secs(5), later)
        .await
        .expect("later write finished")
        .expect("later write task")
        .expect("later write");
    assert_eq!(ada_outcome, BindOutcome::Inserted);
    assert_eq!(
        store
            .owner("bob")
            .await
            .unwrap()
            .expect("memory kept bob")
            .user_id,
        bob
    );
    assert_eq!(store.owner("ada").await.unwrap().expect("ada").user_id, ada);

    let reloaded = NameStore::load(path).await;
    assert!(
        reloaded.load_error().is_none(),
        "{:?}",
        reloaded.load_error()
    );
    assert_eq!(
        reloaded
            .owner("bob")
            .await
            .unwrap()
            .expect("disk kept bob")
            .user_id,
        bob,
        "a later write must not replace the published binding"
    );
    assert_eq!(
        reloaded
            .owner("ada")
            .await
            .unwrap()
            .expect("disk has ada")
            .user_id,
        ada
    );
}

fn discovered_named(
    agent_id: AgentId,
    machine: MachineId,
    owner: UserId,
    cert: AgentCertificate,
    label: &str,
) -> crate::DiscoveredAgent {
    crate::DiscoveredAgent {
        agent_id,
        machine_id: machine,
        user_id: Some(owner),
        addresses: Vec::new(),
        announced_at: 0,
        last_seen: 0,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: Some(cert),
        cert_digest: None,
        agent_public_key: Vec::new(),
        self_name: Some(label.to_string()),
    }
}

/// WHY (PR #1494 RC4): a class-B peer authenticated only by usable ADR 0089
/// evidence never fills `authenticated_machine_bindings`. After restart the
/// accepted announcement must still resolve its label and shared machine.
#[tokio::test]
async fn evidence_backed_peer_resolves_name_without_authenticated_cache() {
    let dir = tempfile::tempdir().unwrap();
    let mut local = crate::Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_agent_cert_path(dir.path().join("agent.cert"))
        .with_user_key_path(dir.path().join("user.key"))
        .with_identity_dir(dir.path())
        .with_contact_store_path(dir.path().join("contacts.json"))
        .with_peer_cache_disabled()
        .build()
        .await
        .unwrap();
    assert!(local.network.is_none());

    let bob = user();
    let real_kp = agent();
    let spoof_kp = agent();
    let real_machine_kp = crate::identity::MachineKeypair::generate().unwrap();
    let spoof_machine = MachineId([5; 32]);
    let real_machine = real_machine_kp.machine_id();
    let real_cert = AgentCertificate::issue(&bob, &real_kp).unwrap();
    let spoof_cert = AgentCertificate::issue(&bob, &spoof_kp).unwrap();
    let now_ms = crate::dm_capability::now_unix_ms();
    let now = now_ms / 1000;

    let policy = std::sync::Arc::new(crate::peer_evidence::RuntimePolicy::new(
        local.agent_id(),
        local.owner_trust.clone(),
        std::sync::Arc::clone(&local.revocation_set),
    ));
    let real_id = real_kp.agent_id();
    policy.set_groups(std::sync::Arc::new(move |candidate| {
        Some(candidate == real_id)
    }));
    let evidence = std::sync::Arc::new(
        crate::peer_evidence::PeerEvidenceStore::open(
            dir.path(),
            Default::default(),
            policy,
            now_ms,
        )
        .unwrap(),
    );
    let v2 = crate::IdentityAnnouncement {
        self_name: Some("studio".to_string()),
        agent_id: real_id,
        machine_id: real_machine,
        user_id: Some(bob.user_id()),
        agent_certificate: Some(real_cert.clone()),
        machine_public_key: real_machine_kp.public_key().as_bytes().to_vec(),
        machine_signature: vec![],
        addresses: vec![],
        announced_at: now,
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: vec![],
        relay_candidates: vec![],
        agent_public_key: real_kp.public_key().as_bytes().to_vec(),
    };
    let mut announcement = crate::announce_v3::IdentityAnnouncementV3::build_from_v2(
        &v2,
        real_machine_kp.secret_key(),
        0,
    )
    .unwrap();
    announcement
        .sign_v3_1(real_machine_kp.secret_key())
        .unwrap();
    let kem = crate::groups::kem_envelope::AgentKemKeypair::generate().unwrap();
    let mut advert = crate::dm_capability::CapabilityAdvert {
        protocol_version: crate::dm_capability_service::ADVERT_PROTOCOL_VERSION,
        agent_id: real_id.0,
        machine_id: real_machine.0,
        created_at_unix_ms: now_ms,
        capabilities: crate::dm::DmCapabilities {
            gossip_inbox: true,
            kem_public_key: kem.public_bytes,
            ..crate::dm::DmCapabilities::pending()
        },
        signature: vec![],
    };
    advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        real_kp.secret_key(),
        &advert.signed_bytes().unwrap(),
    )
    .unwrap()
    .as_bytes()
    .to_vec();
    evidence
        .ingest(
            crate::peer_evidence::EvidenceRecordV1 {
                announcement: crate::announce_v3::serialize_v3_1(&announcement).unwrap(),
                advert: postcard::to_stdvec(&advert).unwrap(),
                certificate: None,
                relation: crate::peer_evidence::GROUP,
                stored_at_ms: now_ms,
            },
            crate::peer_evidence::IngestSource::Gossip,
            now_ms,
        )
        .unwrap();
    let (runtime, ready) = crate::peer_evidence::EvidenceRuntime::loading_store_for_test(
        std::sync::Arc::clone(&evidence),
    );
    ready.cancel();
    let mut caps = crate::dm_capability::CapabilityStore::new();
    caps.evidence = runtime;
    local.capability_store = std::sync::Arc::new(caps);
    local.owner_trust.install_evidence(local.peer_evidence());
    assert!(
        local
            .peer_evidence()
            .usable(real_id, real_machine, now_ms)
            .is_some(),
        "the ADR 0089 record must be usable"
    );
    assert!(local
        .authenticated_machine_bindings
        .read()
        .await
        .peek(&real_id)
        .is_none());
    assert!(local
        .announced_machine_bindings
        .read()
        .await
        .peek(&real_id)
        .is_none());

    local.identity_discovery_cache.write().await.insert(
        real_id,
        discovered_named(real_id, real_machine, bob.user_id(), real_cert, "studio"),
    );
    local.identity_discovery_cache.write().await.insert(
        spoof_kp.agent_id(),
        discovered_named(
            spoof_kp.agent_id(),
            spoof_machine,
            bob.user_id(),
            spoof_cert,
            "studio",
        ),
    );

    let names = NameStore::in_memory();
    names
        .bind_owner("bob", bob.user_id(), BindSource::Manual, now)
        .await
        .unwrap();
    let grant = ShareGrant::sign(
        &bob,
        [7; 32],
        Grantee::Agent(local.agent_id()),
        vec![real_id],
        vec![ShareCap::Connect { ports: vec![22] }],
        now.saturating_sub(10),
        now + 3600,
    )
    .unwrap();
    let grants = std::sync::Arc::new(crate::share_grant::ShareGrantStore::in_memory(
        local.agent_id(),
        local.user_id(),
    ));
    grants.accept(grant, now).await.unwrap();
    local.install_share_grant_store(grants);

    let resolved = local
        .resolve_name(&names, None, &name("studio.bob"))
        .await
        .expect("evidence-backed label");
    assert_eq!(resolved.agent_id, Some(real_id));

    let labelled = local
        .label_shared_machine(&names, &name("machine:box.bob"), real_machine)
        .await
        .expect("shared machine uses the evidence machine");
    assert_eq!(labelled, BindOutcome::Inserted);
    let machine = local
        .resolve_name(&names, None, &name("machine:box.bob"))
        .await
        .expect("shared machine name");
    assert_eq!(machine.machine_id, Some(real_machine));
    assert_eq!(machine.agent_id, Some(real_id));
    local.shutdown().await;
}
