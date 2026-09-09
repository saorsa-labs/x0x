//! Inert queue/dispatch-plan controls: no Agent, AppState or network constructor.
use super::super::*;
use x0x::groups::{GroupInfo, GroupMemberState, GroupPolicy, GroupRole, GroupStateCommit};
use x0x::identity::AgentKeypair;

struct Fixture {
    info: GroupInfo,
    member: AgentKeypair,
    local: AgentId,
}

impl Fixture {
    fn new() -> Self {
        let owner = AgentKeypair::generate().expect("owner key");
        let member = AgentKeypair::generate().expect("member key");
        let local = owner.agent_id();
        let mut info = GroupInfo::with_policy(
            "queue".into(),
            String::new(),
            local,
            "ab".repeat(16),
            GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.add_member(
            hex::encode(member.agent_id().as_bytes()),
            GroupRole::Member,
            None,
            None,
        );
        for n in 1..=4 {
            info.add_member(
                hex::encode(AgentId([n; 32]).as_bytes()),
                GroupRole::Member,
                None,
                None,
            );
        }
        Self {
            info,
            member,
            local,
        }
    }

    fn event(&self) -> NamedGroupMetadataEvent {
        let actor = hex::encode(self.member.agent_id().as_bytes());
        let commit = GroupStateCommit::sign(
            self.info.stable_group_id().to_string(),
            self.info.state_revision + 4,
            Some("missing predecessor".into()),
            "future roster".into(),
            "policy".into(),
            "metadata".into(),
            None,
            false,
            1,
            &self.member,
        )
        .expect("signed future commit");
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: self.info.stable_group_id().to_string(),
            revision: self.info.roster_revision + 4,
            actor: actor.clone(),
            agent_id: actor,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            commit: Some(commit),
        }
    }

    fn admit(
        &self,
        queue: &mut VecDeque<PendingTreeKemMetadataEvent>,
        event: &NamedGroupMetadataEvent,
    ) -> Option<Vec<AgentId>> {
        admit_treekem_pending_event(
            self.info.stable_group_id(),
            &self.info,
            queue,
            event,
            self.member.agent_id(),
            &hex::encode(self.local.as_bytes()),
        )
    }
}

fn commit_mut(event: &mut NamedGroupMetadataEvent) -> &mut GroupStateCommit {
    match event {
        NamedGroupMetadataEvent::MemberRemoved {
            commit: Some(commit),
            ..
        } => commit,
        _ => panic!("fixture self-leave"),
    }
}

fn resign(commit: &mut GroupStateCommit, key: &AgentKeypair) {
    *commit = GroupStateCommit::sign(
        commit.group_id.clone(),
        commit.revision,
        commit.prev_state_hash.clone(),
        commit.roster_root.clone(),
        commit.policy_hash.clone(),
        commit.public_meta_hash.clone(),
        commit.security_binding.clone(),
        commit.withdrawn,
        commit.committed_at,
        key,
    )
    .expect("resign independent negative");
    commit
        .verify_structure()
        .expect("negative has authentic signature");
}

#[test]
fn active_member_missing_predecessor_queues_and_plans_bounded_catchup() {
    let f = Fixture::new();
    let event = f.event();
    assert_eq!(
        treekem_state_frontier_gap_reason(&f.info, &event, &hex::encode(f.local.as_bytes()), None)
            .as_deref(),
        Some("revision_gap")
    );
    let mut queue = VecDeque::new();
    let peers = f.admit(&mut queue, &event).expect("valid gap admitted");
    assert_eq!(queue.len(), 1);
    assert_eq!(
        peers,
        vec![f.member.agent_id(), AgentId([1; 32]), AgentId([2; 32])]
    );
    assert!(
        f.admit(&mut queue, &event).is_none(),
        "duplicate cannot dispatch again"
    );
    assert_eq!(queue.len(), 1);
    // Resolving a group through a local alias must not reject its stable-bound commit.
    let mut aliased = event.clone();
    if let NamedGroupMetadataEvent::MemberRemoved { group_id, .. } = &mut aliased {
        *group_id = "local-alias".into();
    }
    assert!(admit_treekem_pending_event(
        "local-alias",
        &f.info,
        &mut VecDeque::new(),
        &aliased,
        f.member.agent_id(),
        &hex::encode(f.local.as_bytes())
    )
    .is_some());
}

#[test]
fn nonmember_self_leave_never_enters_queue_or_plans_dispatch() {
    for state in [
        Some(GroupMemberState::Removed),
        Some(GroupMemberState::Banned),
        Some(GroupMemberState::Pending),
        None,
    ] {
        let mut f = Fixture::new();
        let event = f.event();
        let member = hex::encode(f.member.agent_id().as_bytes());
        match state {
            Some(state) => f.info.members_v2.get_mut(&member).expect("member").state = state,
            None => {
                f.info.members_v2.remove(&member);
            }
        }
        let mut queue = VecDeque::new();
        assert!(
            f.admit(&mut queue, &event).is_none(),
            "ineligible state {state:?}"
        );
        assert!(queue.is_empty());
    }
}

#[test]
fn invalid_signature_group_and_actor_bindings_are_rejected() {
    let f = Fixture::new();
    let mut cases = Vec::new();
    let mut bad = f.event();
    commit_mut(&mut bad).signature = "00".into();
    cases.push(bad);
    let mut bad = f.event();
    commit_mut(&mut bad).group_id = "foreign".into();
    resign(commit_mut(&mut bad), &f.member);
    cases.push(bad);
    let mut bad = f.event();
    resign(
        commit_mut(&mut bad),
        &AgentKeypair::generate().expect("foreign signer"),
    );
    cases.push(bad);
    let mut bad = f.event();
    if let NamedGroupMetadataEvent::MemberRemoved { group_id, .. } = &mut bad {
        *group_id = "foreign".into();
    }
    cases.push(bad);
    let mut bad = f.event();
    if let NamedGroupMetadataEvent::MemberRemoved { actor, .. } = &mut bad {
        *actor = hex::encode(f.local.as_bytes());
    }
    cases.push(bad);
    for (i, event) in cases.iter().enumerate() {
        let mut queue = VecDeque::new();
        assert!(f.admit(&mut queue, event).is_none(), "binding case {i}");
        assert!(queue.is_empty());
    }
}

#[test]
fn subject_and_self_leave_action_shape_cannot_consume_queue() {
    let f = Fixture::new();
    let mut cases = Vec::new();
    let mut bad = f.event();
    if let NamedGroupMetadataEvent::MemberRemoved { agent_id, .. } = &mut bad {
        *agent_id = hex::encode(f.local.as_bytes());
    }
    cases.push(bad);
    let mut bad = f.event();
    if let NamedGroupMetadataEvent::MemberRemoved { secret_epoch, .. } = &mut bad {
        *secret_epoch = Some(9);
    }
    cases.push(bad);
    let mut bad = f.event();
    if let NamedGroupMetadataEvent::MemberRemoved {
        treekem_epoch,
        treekem_commit_b64,
        ..
    } = &mut bad
    {
        *treekem_epoch = Some(9);
        *treekem_commit_b64 = Some("bad".into());
    }
    cases.push(bad);
    for (i, event) in cases.iter().enumerate() {
        let mut queue = VecDeque::new();
        assert!(f.admit(&mut queue, event).is_none(), "action case {i}");
        assert!(queue.is_empty());
    }
    // The same signed, structurally eligible admin action remains queueable.
    let mut admin = Fixture::new();
    admin.info.set_member_role(
        &hex::encode(admin.member.agent_id().as_bytes()),
        GroupRole::Admin,
    );
    let mut removal = admin.event();
    if let NamedGroupMetadataEvent::MemberRemoved {
        agent_id,
        treekem_epoch,
        treekem_commit_b64,
        ..
    } = &mut removal
    {
        *agent_id = hex::encode(AgentId([4; 32]).as_bytes());
        *treekem_epoch = Some(9);
        *treekem_commit_b64 = Some("opaque future commit".into());
    }
    assert!(admin.admit(&mut VecDeque::new(), &removal).is_some());
    if let NamedGroupMetadataEvent::MemberRemoved { agent_id, .. } = &mut removal {
        *agent_id = hex::encode(admin.member.agent_id().as_bytes());
    }
    assert!(
        admin.admit(&mut VecDeque::new(), &removal).is_none(),
        "admin self-leave cannot carry a rekey"
    );
}

#[test]
fn invalid_high_frontiers_cannot_evict_sixty_four_real_pending_entries() {
    let f = Fixture::new();
    let mut queue = VecDeque::new();
    let valid = f.event();
    for n in 1..=64 {
        let mut event = valid.clone();
        if let NamedGroupMetadataEvent::MemberRemoved { revision, .. } = &mut event {
            *revision = n;
        }
        assert!(f.admit(&mut queue, &event).is_some());
    }
    let before: Vec<_> = queue
        .iter()
        .map(|p| treekem_membership_event_key(&p.event))
        .collect();
    for n in 65..=194 {
        let mut event = valid.clone();
        if let NamedGroupMetadataEvent::MemberRemoved { revision, .. } = &mut event {
            *revision = n;
        }
        commit_mut(&mut event).signature = "00".into();
        assert!(f.admit(&mut queue, &event).is_none());
    }
    assert_eq!(queue.len(), TREEKEM_PENDING_EVENTS_PER_GROUP_CAP);
    assert_eq!(
        before,
        queue
            .iter()
            .map(|p| treekem_membership_event_key(&p.event))
            .collect::<Vec<_>>()
    );
    let mut next = valid;
    if let NamedGroupMetadataEvent::MemberRemoved { revision, .. } = &mut next {
        *revision = 195;
    }
    assert!(f.admit(&mut queue, &next).is_some());
    assert_eq!(queue.len(), 64);
    assert_eq!(
        treekem_membership_event_sort_key(&queue.front().expect("retained").event).0,
        2
    );
}

#[test]
fn failed_replay_discards_newly_unauthorized_or_invalid_gap() {
    let mut f = Fixture::new();
    let mut queue = VecDeque::new();
    assert!(f.admit(&mut queue, &f.event()).is_some());
    let mut pending = queue.pop_front().expect("queued");
    let local = hex::encode(f.local.as_bytes());
    let group = f.info.stable_group_id().to_string();
    assert!(retain_pending_treekem_event(
        &group, &f.info, &pending, &local, None
    ));
    let good = pending.event.clone();
    commit_mut(&mut pending.event).signature = "00".into();
    assert!(!retain_pending_treekem_event(
        &group, &f.info, &pending, &local, None
    ));
    pending.event = good;
    f.info
        .remove_member(&hex::encode(f.member.agent_id().as_bytes()), None);
    assert!(!retain_pending_treekem_event(
        &group, &f.info, &pending, &local, None
    ));
}

#[test]
fn replay_reinsertion_keeps_valid_gap_and_discards_removed_author() {
    let mut f = Fixture::new();
    let mut candidates = VecDeque::new();
    assert!(f.admit(&mut candidates, &f.event()).is_some());
    let local = hex::encode(f.local.as_bytes());
    let group = f.info.stable_group_id().to_string();
    let revoked = x0x::revocation::RevocationSet::new();
    let mut queue = VecDeque::new();
    requeue_treekem_pending_events(
        &group, &f.info, &mut queue, candidates, &local, None, &revoked,
    );
    assert_eq!(
        queue.len(),
        1,
        "valid still-gapped entry survives actual reinsertion"
    );
    f.info
        .remove_member(&hex::encode(f.member.agent_id().as_bytes()), None);
    let candidates = std::mem::take(&mut queue);
    requeue_treekem_pending_events(
        &group, &f.info, &mut queue, candidates, &local, None, &revoked,
    );
    assert!(queue.is_empty(), "removed author must not be requeued");
}
