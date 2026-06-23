//! Property-based tests for groups.
#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use std::collections::BTreeMap;
use x0x::groups::state_commit::validate_apply;
use x0x::groups::{
    card::AgentCard, compute_policy_hash, compute_public_meta_hash, compute_roster_root,
    enforce_last_admin_invariant, invite::SignedInvite, last_admin_precheck_error,
    last_admin_self_leave_precheck_error, ActionKind, ApplyContext, ApplyError,
    GroupDiscoverability, GroupInfo, GroupMember, GroupMemberState, GroupPolicyPreset, GroupRole,
    GroupStateCommit, LAST_ADMIN_PRECHECK_ERROR, LAST_ADMIN_SELF_LEAVE_PRECHECK_ERROR,
};
use x0x::identity::{AgentId, AgentKeypair};

const LAST_ADMIN_SEQUENCE_AGENT_SLOTS: usize = 5;
const LAST_ADMIN_SEQUENCE_CASES: u32 = 128;
const LAST_ADMIN_MAX_ACTIONS: usize = 24;

fn agent(bytes: [u8; 32]) -> AgentId {
    AgentId(bytes)
}

#[derive(Debug, Clone)]
struct RosterMemberSpec {
    role: GroupRole,
    state: GroupMemberState,
}

fn member_spec(role: GroupRole, state: GroupMemberState) -> RosterMemberSpec {
    RosterMemberSpec { role, state }
}

fn arb_member_spec() -> impl Strategy<Value = RosterMemberSpec> {
    (
        prop_oneof![
            Just(GroupRole::Owner),
            Just(GroupRole::Admin),
            Just(GroupRole::Moderator),
            Just(GroupRole::Member),
            Just(GroupRole::Guest),
        ],
        prop_oneof![
            Just(GroupMemberState::Active),
            Just(GroupMemberState::Pending),
            Just(GroupMemberState::Removed),
            Just(GroupMemberState::Banned),
        ],
    )
        .prop_map(|(role, state)| member_spec(role, state))
}

fn arb_last_admin_case() -> impl Strategy<Value = (Vec<RosterMemberSpec>, bool)> {
    prop_oneof![
        // Zero-admin live rosters.
        Just((Vec::new(), false)),
        Just((
            vec![member_spec(GroupRole::Member, GroupMemberState::Active)],
            false
        )),
        Just((
            vec![member_spec(GroupRole::Moderator, GroupMemberState::Active)],
            false
        )),
        Just((
            vec![member_spec(GroupRole::Guest, GroupMemberState::Active)],
            false
        )),
        // Exactly-one-admin live boundaries.
        Just((
            vec![member_spec(GroupRole::Admin, GroupMemberState::Active)],
            false
        )),
        Just((
            vec![member_spec(GroupRole::Owner, GroupMemberState::Active)],
            false
        )),
        // Admin-rank members in non-active states must not count.
        Just((
            vec![member_spec(GroupRole::Admin, GroupMemberState::Banned)],
            false
        )),
        Just((
            vec![member_spec(GroupRole::Owner, GroupMemberState::Banned)],
            false
        )),
        Just((
            vec![member_spec(GroupRole::Admin, GroupMemberState::Removed)],
            false
        )),
        Just((
            vec![member_spec(GroupRole::Owner, GroupMemberState::Pending)],
            false
        )),
        // Withdrawal is the explicit exit valve even with no active admins.
        Just((Vec::new(), true)),
        Just((
            vec![member_spec(GroupRole::Admin, GroupMemberState::Banned)],
            true
        )),
        // Mixed arbitrary rosters keep shrinking useful while still exploring.
        (
            prop::collection::vec(arb_member_spec(), 0..16),
            any::<bool>()
        ),
    ]
}

fn roster_from_specs(specs: &[RosterMemberSpec]) -> BTreeMap<String, GroupMember> {
    specs
        .iter()
        .enumerate()
        .map(|(idx, spec)| {
            let agent_id = format!("{idx:064x}");
            (
                agent_id.clone(),
                GroupMember {
                    agent_id,
                    user_id: None,
                    role: spec.role,
                    state: spec.state,
                    display_name: None,
                    joined_at: idx as u64,
                    updated_at: idx as u64,
                    added_by: None,
                    removed_by: None,
                    kem_public_key_b64: None,
                    treekem_key_package_b64: None,
                },
            )
        })
        .collect()
}

fn independent_last_admin_oracle(specs: &[RosterMemberSpec], withdrawn: bool) -> bool {
    withdrawn
        || specs.iter().any(|spec| {
            matches!(spec.state, GroupMemberState::Active)
                && matches!(spec.role, GroupRole::Admin | GroupRole::Owner)
        })
}

#[derive(Debug, Clone)]
enum LastAdminAction {
    AddMember {
        actor: usize,
        target: usize,
    },
    RemoveMember {
        actor: usize,
        target: usize,
    },
    BanMember {
        actor: usize,
        target: usize,
    },
    SetRole {
        actor: usize,
        target: usize,
        role: GroupRole,
    },
    SelfLeave {
        actor: usize,
    },
    UpdatePolicy {
        actor: usize,
        preset: GroupPolicyPreset,
    },
    Withdraw {
        actor: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LastAdminActionKind {
    AddMember,
    RemoveMember,
    BanMember,
    SetRole,
    SelfLeave,
    UpdatePolicy,
    Withdraw,
}

impl LastAdminAction {
    fn kind(&self) -> LastAdminActionKind {
        match self {
            Self::AddMember { .. } => LastAdminActionKind::AddMember,
            Self::RemoveMember { .. } => LastAdminActionKind::RemoveMember,
            Self::BanMember { .. } => LastAdminActionKind::BanMember,
            Self::SetRole { .. } => LastAdminActionKind::SetRole,
            Self::SelfLeave { .. } => LastAdminActionKind::SelfLeave,
            Self::UpdatePolicy { .. } => LastAdminActionKind::UpdatePolicy,
            Self::Withdraw { .. } => LastAdminActionKind::Withdraw,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct SequencePathStats {
    accepted: usize,
    rejected: usize,
    accepted_add_member: usize,
    accepted_remove_member: usize,
    accepted_ban_member: usize,
    accepted_set_role: usize,
    accepted_self_leave: usize,
    accepted_update_policy: usize,
    accepted_withdraw: usize,
}

impl SequencePathStats {
    fn record(&mut self, action: &LastAdminAction, outcome: SequenceOutcome) {
        match outcome {
            SequenceOutcome::Accepted => {
                self.accepted += 1;
                match action.kind() {
                    LastAdminActionKind::AddMember => self.accepted_add_member += 1,
                    LastAdminActionKind::RemoveMember => self.accepted_remove_member += 1,
                    LastAdminActionKind::BanMember => self.accepted_ban_member += 1,
                    LastAdminActionKind::SetRole => self.accepted_set_role += 1,
                    LastAdminActionKind::SelfLeave => self.accepted_self_leave += 1,
                    LastAdminActionKind::UpdatePolicy => self.accepted_update_policy += 1,
                    LastAdminActionKind::Withdraw => self.accepted_withdraw += 1,
                }
            }
            SequenceOutcome::Rejected => self.rejected += 1,
        }
    }

    fn total(&self) -> usize {
        self.accepted + self.rejected
    }

    fn assert_all_semantically_valid_actions_accepted(&self, path: &str) {
        for (kind, count) in [
            ("add member", self.accepted_add_member),
            ("remove member", self.accepted_remove_member),
            ("ban member", self.accepted_ban_member),
            ("role change", self.accepted_set_role),
            ("self leave", self.accepted_self_leave),
            ("policy update", self.accepted_update_policy),
            ("withdrawal", self.accepted_withdraw),
        ] {
            assert!(
                count > 0,
                "{path} deterministic coverage did not accept {kind}; stats: {self:?}"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceOutcome {
    Accepted,
    Rejected,
}

fn arb_initial_member_spec() -> impl Strategy<Value = RosterMemberSpec> {
    (
        prop_oneof![
            Just(GroupRole::Owner),
            Just(GroupRole::Admin),
            Just(GroupRole::Member),
        ],
        prop_oneof![
            Just(GroupMemberState::Active),
            Just(GroupMemberState::Pending),
            Just(GroupMemberState::Removed),
            Just(GroupMemberState::Banned),
        ],
    )
        .prop_map(|(role, state)| member_spec(role, state))
}

fn arb_initial_roster() -> impl Strategy<Value = Vec<RosterMemberSpec>> {
    (
        prop_oneof![Just(GroupRole::Owner), Just(GroupRole::Admin)],
        prop::collection::vec(
            arb_initial_member_spec(),
            LAST_ADMIN_SEQUENCE_AGENT_SLOTS - 1..LAST_ADMIN_SEQUENCE_AGENT_SLOTS,
        ),
    )
        .prop_map(|(first_role, mut rest)| {
            let mut specs = vec![member_spec(first_role, GroupMemberState::Active)];
            specs.append(&mut rest);
            specs
        })
}

fn arb_role_update() -> impl Strategy<Value = GroupRole> {
    prop_oneof![
        Just(GroupRole::Admin),
        Just(GroupRole::Member),
        Just(GroupRole::Moderator),
        Just(GroupRole::Guest),
    ]
}

fn arb_policy_preset() -> impl Strategy<Value = GroupPolicyPreset> {
    prop_oneof![
        Just(GroupPolicyPreset::PrivateSecure),
        Just(GroupPolicyPreset::PublicRequestSecure),
        Just(GroupPolicyPreset::PublicOpen),
        Just(GroupPolicyPreset::PublicAnnounce),
    ]
}

fn arb_slot() -> impl Strategy<Value = usize> {
    0..LAST_ADMIN_SEQUENCE_AGENT_SLOTS
}

fn arb_last_admin_action() -> impl Strategy<Value = LastAdminAction> {
    prop_oneof![
        (arb_slot(), arb_slot())
            .prop_map(|(actor, target)| LastAdminAction::AddMember { actor, target }),
        (arb_slot(), arb_slot())
            .prop_map(|(actor, target)| LastAdminAction::RemoveMember { actor, target }),
        (arb_slot(), arb_slot())
            .prop_map(|(actor, target)| LastAdminAction::BanMember { actor, target }),
        (arb_slot(), arb_slot(), arb_role_update()).prop_map(|(actor, target, role)| {
            LastAdminAction::SetRole {
                actor,
                target,
                role,
            }
        }),
        arb_slot().prop_map(|actor| LastAdminAction::SelfLeave { actor }),
        (arb_slot(), arb_policy_preset())
            .prop_map(|(actor, preset)| { LastAdminAction::UpdatePolicy { actor, preset } }),
        arb_slot().prop_map(|actor| LastAdminAction::Withdraw { actor }),
    ]
}

fn arb_last_admin_sequence() -> impl Strategy<Value = Vec<LastAdminAction>> {
    prop::collection::vec(arb_last_admin_action(), 0..LAST_ADMIN_MAX_ACTIONS).prop_map(
        |mut generated| {
            let mut actions = vec![LastAdminAction::UpdatePolicy {
                actor: 0,
                preset: GroupPolicyPreset::PublicOpen,
            }];
            actions.append(&mut generated);
            actions
        },
    )
}

fn arb_last_admin_zero_admin_rest_attempt() -> impl Strategy<Value = LastAdminAction> {
    prop_oneof![
        Just(LastAdminAction::RemoveMember {
            actor: 0,
            target: 0
        }),
        Just(LastAdminAction::BanMember {
            actor: 0,
            target: 0
        }),
        Just(LastAdminAction::SetRole {
            actor: 0,
            target: 0,
            role: GroupRole::Member,
        }),
        Just(LastAdminAction::SelfLeave { actor: 0 }),
    ]
}

fn sequence_keypairs() -> Vec<AgentKeypair> {
    (0..LAST_ADMIN_SEQUENCE_AGENT_SLOTS)
        .map(deterministic_agent_keypair)
        .collect()
}

fn deterministic_agent_keypair(slot: usize) -> AgentKeypair {
    use fips204::traits::{KeyGen, SerDes};

    let mut seed = [0x42; 32];
    seed[0] = slot as u8;
    seed[31] = 0xa6;
    let (public_key, secret_key) = fips204::ml_dsa_65::KG::keygen_from_seed(&seed);
    AgentKeypair::from_bytes(&public_key.into_bytes(), &secret_key.into_bytes()).unwrap()
}

fn keypair_hex(keypairs: &[AgentKeypair], slot: usize) -> String {
    hex::encode(keypairs[slot].agent_id().as_bytes())
}

fn member_from_spec(
    agent_id: String,
    spec: &RosterMemberSpec,
    added_by: Option<String>,
) -> GroupMember {
    GroupMember {
        agent_id,
        user_id: None,
        role: spec.role,
        state: spec.state,
        display_name: None,
        joined_at: 0,
        updated_at: 0,
        added_by,
        removed_by: None,
        kem_public_key_b64: None,
        treekem_key_package_b64: None,
    }
}

fn group_from_initial_specs(keypairs: &[AgentKeypair], specs: &[RosterMemberSpec]) -> GroupInfo {
    let creator_hex = keypair_hex(keypairs, 0);
    let mut info = GroupInfo::with_policy(
        "last-admin-proptest".to_string(),
        "generated sequence".to_string(),
        keypairs[0].agent_id(),
        "ab".repeat(16),
        GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    info.members_v2.clear();
    for (slot, spec) in specs.iter().enumerate() {
        let agent_hex = keypair_hex(keypairs, slot);
        let added_by = (slot != 0).then(|| creator_hex.clone());
        info.members_v2.insert(
            agent_hex.clone(),
            member_from_spec(agent_hex, spec, added_by),
        );
    }
    info.roster_revision = 0;
    info.policy_revision = 0;
    info.state_revision = 0;
    info.prev_state_hash = None;
    info.withdrawn = false;
    info.recompute_state_hash();
    info
}

fn state_snapshot(info: &GroupInfo) -> String {
    serde_json::to_string(info).unwrap()
}

fn explicitly_active_member(member: &GroupMember) -> bool {
    matches!(member.state, GroupMemberState::Active)
}

fn explicitly_active_admin(member: &GroupMember) -> bool {
    matches!(member.state, GroupMemberState::Active)
        && matches!(member.role, GroupRole::Admin | GroupRole::Owner)
}

fn independent_active_admin_count(info: &GroupInfo) -> usize {
    info.members_v2
        .values()
        .filter(|member| explicitly_active_admin(member))
        .count()
}

fn independent_has_active_admin(info: &GroupInfo) -> bool {
    independent_active_admin_count(info) > 0
}

fn member_at_slot<'a>(
    info: &'a GroupInfo,
    keypairs: &[AgentKeypair],
    slot: usize,
) -> Option<&'a GroupMember> {
    let member_hex = keypair_hex(keypairs, slot);
    info.members_v2.get(member_hex.as_str())
}

fn slot_is_active_member(info: &GroupInfo, keypairs: &[AgentKeypair], slot: usize) -> bool {
    member_at_slot(info, keypairs, slot).is_some_and(explicitly_active_member)
}

fn slot_is_active_admin(info: &GroupInfo, keypairs: &[AgentKeypair], slot: usize) -> bool {
    member_at_slot(info, keypairs, slot).is_some_and(explicitly_active_admin)
}

fn target_can_be_added(info: &GroupInfo, keypairs: &[AgentKeypair], slot: usize) -> bool {
    member_at_slot(info, keypairs, slot).is_none_or(|member| {
        !matches!(
            member.state,
            GroupMemberState::Active | GroupMemberState::Banned
        )
    })
}

fn target_is_active(info: &GroupInfo, keypairs: &[AgentKeypair], slot: usize) -> bool {
    slot_is_active_member(info, keypairs, slot)
}

fn rest_role_is_assignable(role: GroupRole) -> bool {
    matches!(role, GroupRole::Admin | GroupRole::Member)
}

fn reject_without_mutation(info: &GroupInfo, before: &str) -> SequenceOutcome {
    assert_eq!(state_snapshot(info), before);
    SequenceOutcome::Rejected
}

fn seal_rest_state(
    info: &mut GroupInfo,
    mut next: GroupInfo,
    signer: &AgentKeypair,
    now_ms: u64,
    before: &str,
) -> SequenceOutcome {
    match next.seal_commit(signer, now_ms) {
        Ok(commit) => {
            commit.verify_structure().unwrap();
            assert_ne!(state_snapshot(&next), before);
            *info = next;
            SequenceOutcome::Accepted
        }
        Err(_) => reject_without_mutation(info, before),
    }
}

fn reject_last_admin_precheck_and_seal_chokepoint(
    info: &GroupInfo,
    mut next: GroupInfo,
    signer: &AgentKeypair,
    now_ms: u64,
    before: &str,
) -> SequenceOutcome {
    assert!(!next.withdrawn);
    assert!(!independent_has_active_admin(&next));
    assert!(matches!(
        next.seal_commit(signer, now_ms),
        Err(ApplyError::Invariant(_))
    ));
    reject_without_mutation(info, before)
}

fn production_precheck_error_for_rest_zero_admin_attempt(
    info: &GroupInfo,
    keypairs: &[AgentKeypair],
    action: &LastAdminAction,
) -> Option<&'static str> {
    match action {
        LastAdminAction::RemoveMember { actor, target } => last_admin_precheck_error(info, |g| {
            mutate_remove_member(g, keypairs, *actor, *target);
        }),
        LastAdminAction::BanMember { actor, target } => last_admin_precheck_error(info, |g| {
            mutate_ban_member(g, keypairs, *actor, *target);
        }),
        LastAdminAction::SetRole { target, role, .. } => last_admin_precheck_error(info, |g| {
            mutate_set_role(g, keypairs, *target, *role);
        }),
        LastAdminAction::SelfLeave { actor } => {
            let actor_hex = keypair_hex(keypairs, *actor);
            last_admin_self_leave_precheck_error(info, &actor_hex)
        }
        LastAdminAction::AddMember { .. }
        | LastAdminAction::UpdatePolicy { .. }
        | LastAdminAction::Withdraw { .. } => None,
    }
}

fn apply_rest_action(
    info: &mut GroupInfo,
    keypairs: &[AgentKeypair],
    action: &LastAdminAction,
    now_ms: u64,
) -> SequenceOutcome {
    let before = state_snapshot(info);
    if info.withdrawn {
        return reject_without_mutation(info, &before);
    }

    match action {
        LastAdminAction::AddMember { actor, target } => {
            if !slot_is_active_admin(info, keypairs, *actor)
                || !target_can_be_added(info, keypairs, *target)
            {
                return reject_without_mutation(info, &before);
            }
            let mut next = info.clone();
            mutate_add_member(&mut next, keypairs, *actor, *target);
            seal_rest_state(info, next, &keypairs[*actor], now_ms, &before)
        }
        LastAdminAction::RemoveMember { actor, target } => {
            if !slot_is_active_admin(info, keypairs, *actor)
                || !target_is_active(info, keypairs, *target)
            {
                return reject_without_mutation(info, &before);
            }
            if let Some(error) = last_admin_precheck_error(info, |g| {
                mutate_remove_member(g, keypairs, *actor, *target);
            }) {
                assert_eq!(error, LAST_ADMIN_PRECHECK_ERROR);
                let mut next = info.clone();
                mutate_remove_member(&mut next, keypairs, *actor, *target);
                return reject_last_admin_precheck_and_seal_chokepoint(
                    info,
                    next,
                    &keypairs[*actor],
                    now_ms,
                    &before,
                );
            }
            let mut next = info.clone();
            mutate_remove_member(&mut next, keypairs, *actor, *target);
            seal_rest_state(info, next, &keypairs[*actor], now_ms, &before)
        }
        LastAdminAction::BanMember { actor, target } => {
            if !slot_is_active_admin(info, keypairs, *actor)
                || !target_is_active(info, keypairs, *target)
            {
                return reject_without_mutation(info, &before);
            }
            if let Some(error) = last_admin_precheck_error(info, |g| {
                mutate_ban_member(g, keypairs, *actor, *target);
            }) {
                assert_eq!(error, LAST_ADMIN_PRECHECK_ERROR);
                let mut next = info.clone();
                mutate_ban_member(&mut next, keypairs, *actor, *target);
                return reject_last_admin_precheck_and_seal_chokepoint(
                    info,
                    next,
                    &keypairs[*actor],
                    now_ms,
                    &before,
                );
            }
            let mut next = info.clone();
            mutate_ban_member(&mut next, keypairs, *actor, *target);
            seal_rest_state(info, next, &keypairs[*actor], now_ms, &before)
        }
        LastAdminAction::SetRole {
            actor,
            target,
            role,
        } => {
            if !rest_role_is_assignable(*role)
                || !slot_is_active_admin(info, keypairs, *actor)
                || !target_is_active(info, keypairs, *target)
            {
                return reject_without_mutation(info, &before);
            }
            if let Some(error) = last_admin_precheck_error(info, |g| {
                mutate_set_role(g, keypairs, *target, *role);
            }) {
                assert_eq!(error, LAST_ADMIN_PRECHECK_ERROR);
                let mut next = info.clone();
                mutate_set_role(&mut next, keypairs, *target, *role);
                return reject_last_admin_precheck_and_seal_chokepoint(
                    info,
                    next,
                    &keypairs[*actor],
                    now_ms,
                    &before,
                );
            }
            let mut next = info.clone();
            mutate_set_role(&mut next, keypairs, *target, *role);
            seal_rest_state(info, next, &keypairs[*actor], now_ms, &before)
        }
        LastAdminAction::SelfLeave { actor } => {
            if !slot_is_active_member(info, keypairs, *actor) {
                return reject_without_mutation(info, &before);
            }
            let actor_hex = keypair_hex(keypairs, *actor);
            if let Some(error) = last_admin_self_leave_precheck_error(info, &actor_hex) {
                assert_eq!(error, LAST_ADMIN_SELF_LEAVE_PRECHECK_ERROR);
                let mut next = info.clone();
                mutate_self_leave(&mut next, keypairs, *actor);
                return reject_last_admin_precheck_and_seal_chokepoint(
                    info,
                    next,
                    &keypairs[*actor],
                    now_ms,
                    &before,
                );
            }
            let mut next = info.clone();
            mutate_self_leave(&mut next, keypairs, *actor);
            seal_rest_state(info, next, &keypairs[*actor], now_ms, &before)
        }
        LastAdminAction::UpdatePolicy { actor, preset } => {
            if !slot_is_active_admin(info, keypairs, *actor) {
                return reject_without_mutation(info, &before);
            }
            let mut next = info.clone();
            mutate_policy(&mut next, *preset);
            seal_rest_state(info, next, &keypairs[*actor], now_ms, &before)
        }
        LastAdminAction::Withdraw { actor } => {
            if !slot_is_active_admin(info, keypairs, *actor) {
                return reject_without_mutation(info, &before);
            }
            let mut next = info.clone();
            next.withdrawn = true;
            seal_rest_state(info, next, &keypairs[*actor], now_ms, &before)
        }
    }
}

fn craft_sequence_commit(
    parent: &GroupInfo,
    scratch: &GroupInfo,
    signer: &AgentKeypair,
    now_ms: u64,
) -> Result<GroupStateCommit, ApplyError> {
    GroupStateCommit::sign(
        parent.stable_group_id().to_string(),
        parent.state_revision.saturating_add(1),
        Some(parent.state_hash.clone()),
        compute_roster_root(&scratch.members_v2),
        compute_policy_hash(&scratch.policy),
        compute_public_meta_hash(&scratch.public_meta()),
        scratch.security_binding.clone(),
        scratch.withdrawn,
        now_ms,
        signer,
    )
}

fn apply_gossip_commit(
    info: &mut GroupInfo,
    commit: &GroupStateCommit,
    action_kind: ActionKind,
    mutate: impl FnOnce(&mut GroupInfo),
    before: &str,
) -> SequenceOutcome {
    let ctx = ApplyContext {
        current_state_hash: &info.state_hash,
        current_revision: info.state_revision,
        current_withdrawn: info.withdrawn,
        members_v2: &info.members_v2,
        group_id: info.stable_group_id(),
    };
    if validate_apply(&ctx, commit, action_kind).is_err() {
        return reject_without_mutation(info, before);
    }

    let mut next = info.clone();
    mutate(&mut next);
    match next.finalize_applied_commit(commit) {
        Ok(()) => {
            assert_ne!(state_snapshot(&next), before);
            *info = next;
            SequenceOutcome::Accepted
        }
        Err(_) => reject_without_mutation(info, before),
    }
}

fn apply_gossip_action(
    info: &mut GroupInfo,
    keypairs: &[AgentKeypair],
    action: &LastAdminAction,
    now_ms: u64,
) -> SequenceOutcome {
    let before = state_snapshot(info);
    if info.withdrawn {
        return reject_without_mutation(info, &before);
    }

    match action {
        LastAdminAction::AddMember { actor, target } => {
            if !target_can_be_added(info, keypairs, *target) {
                return reject_without_mutation(info, &before);
            }
            let mut scratch = info.clone();
            mutate_add_member(&mut scratch, keypairs, *actor, *target);
            match craft_sequence_commit(info, &scratch, &keypairs[*actor], now_ms) {
                Ok(commit) => apply_gossip_commit(
                    info,
                    &commit,
                    ActionKind::AdminOrHigher,
                    |next| mutate_add_member(next, keypairs, *actor, *target),
                    &before,
                ),
                Err(_) => reject_without_mutation(info, &before),
            }
        }
        LastAdminAction::RemoveMember { actor, target } => {
            if !target_is_active(info, keypairs, *target) {
                return reject_without_mutation(info, &before);
            }
            let mut scratch = info.clone();
            mutate_remove_member(&mut scratch, keypairs, *actor, *target);
            match craft_sequence_commit(info, &scratch, &keypairs[*actor], now_ms) {
                Ok(commit) => apply_gossip_commit(
                    info,
                    &commit,
                    ActionKind::AdminOrHigher,
                    |next| mutate_remove_member(next, keypairs, *actor, *target),
                    &before,
                ),
                Err(_) => reject_without_mutation(info, &before),
            }
        }
        LastAdminAction::BanMember { actor, target } => {
            if !target_is_active(info, keypairs, *target) {
                return reject_without_mutation(info, &before);
            }
            let mut scratch = info.clone();
            mutate_ban_member(&mut scratch, keypairs, *actor, *target);
            match craft_sequence_commit(info, &scratch, &keypairs[*actor], now_ms) {
                Ok(commit) => apply_gossip_commit(
                    info,
                    &commit,
                    ActionKind::AdminOrHigher,
                    |next| mutate_ban_member(next, keypairs, *actor, *target),
                    &before,
                ),
                Err(_) => reject_without_mutation(info, &before),
            }
        }
        LastAdminAction::SetRole {
            actor,
            target,
            role,
        } => {
            if !target_is_active(info, keypairs, *target) {
                return reject_without_mutation(info, &before);
            }
            let mut scratch = info.clone();
            mutate_set_role(&mut scratch, keypairs, *target, *role);
            match craft_sequence_commit(info, &scratch, &keypairs[*actor], now_ms) {
                Ok(commit) => apply_gossip_commit(
                    info,
                    &commit,
                    ActionKind::AdminOrHigher,
                    |next| mutate_set_role(next, keypairs, *target, *role),
                    &before,
                ),
                Err(_) => reject_without_mutation(info, &before),
            }
        }
        LastAdminAction::SelfLeave { actor } => {
            let mut scratch = info.clone();
            mutate_self_leave(&mut scratch, keypairs, *actor);
            match craft_sequence_commit(info, &scratch, &keypairs[*actor], now_ms) {
                Ok(commit) => apply_gossip_commit(
                    info,
                    &commit,
                    ActionKind::MemberSelf,
                    |next| mutate_self_leave(next, keypairs, *actor),
                    &before,
                ),
                Err(_) => reject_without_mutation(info, &before),
            }
        }
        LastAdminAction::UpdatePolicy { actor, preset } => {
            let mut scratch = info.clone();
            mutate_policy(&mut scratch, *preset);
            match craft_sequence_commit(info, &scratch, &keypairs[*actor], now_ms) {
                Ok(commit) => apply_gossip_commit(
                    info,
                    &commit,
                    ActionKind::AdminOrHigher,
                    |next| mutate_policy(next, *preset),
                    &before,
                ),
                Err(_) => reject_without_mutation(info, &before),
            }
        }
        LastAdminAction::Withdraw { actor } => {
            let mut scratch = info.clone();
            scratch.withdrawn = true;
            match craft_sequence_commit(info, &scratch, &keypairs[*actor], now_ms) {
                Ok(commit) => apply_gossip_commit(
                    info,
                    &commit,
                    ActionKind::AdminOrHigher,
                    |next| next.withdrawn = true,
                    &before,
                ),
                Err(_) => reject_without_mutation(info, &before),
            }
        }
    }
}

fn mutate_add_member(info: &mut GroupInfo, keypairs: &[AgentKeypair], actor: usize, target: usize) {
    let actor_hex = keypair_hex(keypairs, actor);
    let target_hex = keypair_hex(keypairs, target);
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.add_member(target_hex, GroupRole::Member, Some(actor_hex), None);
}

fn mutate_remove_member(
    info: &mut GroupInfo,
    keypairs: &[AgentKeypair],
    actor: usize,
    target: usize,
) {
    let actor_hex = keypair_hex(keypairs, actor);
    let target_hex = keypair_hex(keypairs, target);
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.remove_member(&target_hex, Some(actor_hex));
}

fn mutate_ban_member(info: &mut GroupInfo, keypairs: &[AgentKeypair], actor: usize, target: usize) {
    let actor_hex = keypair_hex(keypairs, actor);
    let target_hex = keypair_hex(keypairs, target);
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.ban_member(&target_hex, Some(actor_hex));
}

fn mutate_set_role(
    info: &mut GroupInfo,
    keypairs: &[AgentKeypair],
    target: usize,
    role: GroupRole,
) {
    let target_hex = keypair_hex(keypairs, target);
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.set_member_role(&target_hex, role);
}

fn mutate_self_leave(info: &mut GroupInfo, keypairs: &[AgentKeypair], actor: usize) {
    let actor_hex = keypair_hex(keypairs, actor);
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.remove_member(&actor_hex, None);
}

fn mutate_policy(info: &mut GroupInfo, preset: GroupPolicyPreset) {
    info.policy = preset.to_policy();
    info.policy_revision = info.policy_revision.saturating_add(1);
    if info.policy.discoverability != GroupDiscoverability::Hidden
        && info.discovery_card_topic.is_none()
    {
        info.discovery_card_topic = Some(format!(
            "x0x.group.{}.card",
            &info.mls_group_id[..16.min(info.mls_group_id.len())]
        ));
    }
}

fn sole_admin_initial_specs(role: GroupRole) -> Vec<RosterMemberSpec> {
    vec![
        member_spec(role, GroupMemberState::Active),
        member_spec(GroupRole::Admin, GroupMemberState::Banned),
        member_spec(GroupRole::Owner, GroupMemberState::Removed),
        member_spec(GroupRole::Admin, GroupMemberState::Pending),
        member_spec(GroupRole::Member, GroupMemberState::Active),
    ]
}

proptest! {
    #[test]
    fn invite_link_roundtrip(
        group_id_bytes in prop::array::uniform16(any::<u8>()),
        group_name in prop::string::string_regex("[a-zA-Z0-9 -]{1,32}").unwrap(),
        inviter_bytes in prop::array::uniform32(any::<u8>()),
        expiry_secs in 0u64..1_000_000,
    ) {
        let inviter = agent(inviter_bytes);
        let invite = SignedInvite::new(
            hex::encode(group_id_bytes),
            group_name.clone(),
            &inviter,
            expiry_secs,
        );

        let parsed = SignedInvite::from_link(&invite.to_link());
        prop_assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        prop_assert_eq!(parsed.group_id, invite.group_id);
        prop_assert_eq!(parsed.group_name, group_name);
        prop_assert_eq!(parsed.inviter, invite.inviter);
        prop_assert_eq!(parsed.invite_secret, invite.invite_secret);
        prop_assert_eq!(parsed.expires_at, invite.expires_at);
    }

    #[test]
    fn signable_bytes_deterministic(
        group_id_bytes in prop::array::uniform16(any::<u8>()),
        group_name in prop::string::string_regex("[a-zA-Z0-9 -]{1,32}").unwrap(),
        inviter_bytes in prop::array::uniform32(any::<u8>()),
        expiry_secs in 0u64..1_000_000,
    ) {
        let invite = SignedInvite::new(
            hex::encode(group_id_bytes),
            group_name,
            &agent(inviter_bytes),
            expiry_secs,
        );
        prop_assert_eq!(invite.signable_bytes(), invite.signable_bytes());
    }

    #[test]
    fn general_chat_topic_uses_general_room(
        name in prop::string::string_regex("[a-zA-Z]{1,16}").unwrap(),
        description in prop::string::string_regex("[a-zA-Z0-9 ]{0,32}").unwrap(),
        creator_bytes in prop::array::uniform32(any::<u8>()),
        group_id_bytes in prop::array::uniform16(any::<u8>()),
    ) {
        let info = GroupInfo::new(
            name,
            description,
            agent(creator_bytes),
            hex::encode(group_id_bytes),
        );
        let topic = info.general_chat_topic();
        prop_assert!(topic.starts_with("x0x.group."));
        prop_assert!(topic.ends_with("/general"));
    }

    #[test]
    fn display_name_fallback_is_non_empty(
        name in prop::string::string_regex("[a-zA-Z]{1,16}").unwrap(),
        creator_bytes in prop::array::uniform32(any::<u8>()),
        member_bytes in prop::array::uniform32(any::<u8>()),
        group_id_bytes in prop::array::uniform16(any::<u8>()),
    ) {
        let info = GroupInfo::new(
            name,
            String::new(),
            agent(creator_bytes),
            hex::encode(group_id_bytes),
        );
        let fallback = info.display_name(&hex::encode(member_bytes));
        prop_assert!(!fallback.is_empty());
    }

    #[test]
    fn agent_card_link_roundtrip(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        machine_bytes in prop::array::uniform32(any::<u8>()),
        display_name in prop::string::string_regex("[a-zA-Z0-9_-]{1,16}").unwrap(),
    ) {
        let agent_id = agent(agent_bytes);
        let machine_id = hex::encode(machine_bytes);
        let card = AgentCard::new(display_name.clone(), &agent_id, &machine_id);

        let parsed = AgentCard::from_link(&card.to_link());
        prop_assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        prop_assert!(parsed.short_display().contains(&parsed.display_name));
        prop_assert_eq!(&parsed.agent_id, &hex::encode(agent_bytes));
        prop_assert_eq!(&parsed.machine_id, &machine_id);
        prop_assert_eq!(parsed.display_name, display_name);
    }

    #[test]
    fn last_admin_invariant_matches_independent_oracle(case in arb_last_admin_case()) {
        let (specs, withdrawn) = case;
        let members = roster_from_specs(&specs);
        let result = enforce_last_admin_invariant(&members, withdrawn);
        let expected_ok = independent_last_admin_oracle(&specs, withdrawn);

        prop_assert_eq!(result.is_ok(), expected_ok);
        if !expected_ok {
            prop_assert!(matches!(result, Err(ApplyError::Invariant(_))));
        }
    }
}

proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: LAST_ADMIN_SEQUENCE_CASES,
        ..Default::default()
    })]

    #[test]
    fn last_admin_generated_sequences_hold_on_rest_and_gossip_paths(
        initial in arb_initial_roster(),
        actions in arb_last_admin_sequence(),
    ) {
        let rest_keypairs = sequence_keypairs();
        let gossip_keypairs = sequence_keypairs();
        let mut rest_group = group_from_initial_specs(&rest_keypairs, &initial);
        let mut gossip_group = group_from_initial_specs(&gossip_keypairs, &initial);

        prop_assert!(independent_has_active_admin(&rest_group));
        prop_assert!(independent_has_active_admin(&gossip_group));

        let mut rest_stats = SequencePathStats::default();
        let mut gossip_stats = SequencePathStats::default();

        for (idx, action) in actions.iter().enumerate() {
            let now_ms = 1_000 + idx as u64;

            let rest_outcome = apply_rest_action(
                &mut rest_group,
                &rest_keypairs,
                action,
                now_ms,
            );
            rest_stats.record(action, rest_outcome);
            prop_assert!(
                rest_group.withdrawn || independent_has_active_admin(&rest_group),
                "REST path reached live zero-admin state after action {idx}: {action:?}"
            );

            let gossip_outcome = apply_gossip_action(
                &mut gossip_group,
                &gossip_keypairs,
                action,
                now_ms,
            );
            gossip_stats.record(action, gossip_outcome);
            prop_assert!(
                gossip_group.withdrawn || independent_has_active_admin(&gossip_group),
                "gossip path reached live zero-admin state after action {idx}: {action:?}"
            );
        }

        prop_assert_eq!(rest_stats.total(), actions.len());
        prop_assert_eq!(gossip_stats.total(), actions.len());
        prop_assert!(
            rest_stats.accepted > 0,
            "REST sequence had no accepted mutations; stats: {rest_stats:?}"
        );
        prop_assert!(
            gossip_stats.accepted > 0,
            "gossip sequence had no accepted mutations; stats: {gossip_stats:?}"
        );
    }

    #[test]
    fn last_admin_rest_generated_zero_admin_attempts_hit_precheck_and_seal_chokepoint(
        sole_admin_role in prop_oneof![Just(GroupRole::Admin), Just(GroupRole::Owner)],
        action in arb_last_admin_zero_admin_rest_attempt(),
    ) {
        let initial = sole_admin_initial_specs(sole_admin_role);
        let keypairs = sequence_keypairs();
        let mut group = group_from_initial_specs(&keypairs, &initial);
        let before = state_snapshot(&group);

        prop_assert_eq!(independent_active_admin_count(&group), 1);
        let expected_precheck_error = match action {
            LastAdminAction::SelfLeave { .. } => LAST_ADMIN_SELF_LEAVE_PRECHECK_ERROR,
            _ => LAST_ADMIN_PRECHECK_ERROR,
        };
        prop_assert_eq!(
            production_precheck_error_for_rest_zero_admin_attempt(&group, &keypairs, &action),
            Some(expected_precheck_error)
        );
        let outcome = apply_rest_action(&mut group, &keypairs, &action, 7_000);

        prop_assert_eq!(outcome, SequenceOutcome::Rejected);
        prop_assert_eq!(state_snapshot(&group), before);
        prop_assert_eq!(independent_active_admin_count(&group), 1);
    }

    #[test]
    fn last_admin_withdrawal_reachable_from_sole_admin_states(
        sole_admin_role in prop_oneof![Just(GroupRole::Admin), Just(GroupRole::Owner)],
    ) {
        let initial = sole_admin_initial_specs(sole_admin_role);
        let rest_keypairs = sequence_keypairs();
        let gossip_keypairs = sequence_keypairs();
        let mut rest_group = group_from_initial_specs(&rest_keypairs, &initial);
        let mut gossip_group = group_from_initial_specs(&gossip_keypairs, &initial);

        prop_assert_eq!(independent_active_admin_count(&rest_group), 1);
        prop_assert_eq!(independent_active_admin_count(&gossip_group), 1);

        let action = LastAdminAction::Withdraw { actor: 0 };
        let rest_outcome = apply_rest_action(&mut rest_group, &rest_keypairs, &action, 9_000);
        let gossip_outcome = apply_gossip_action(&mut gossip_group, &gossip_keypairs, &action, 9_000);

        prop_assert_eq!(rest_outcome, SequenceOutcome::Accepted);
        prop_assert_eq!(gossip_outcome, SequenceOutcome::Accepted);
        prop_assert!(rest_group.withdrawn);
        prop_assert!(gossip_group.withdrawn);
    }
}

#[test]
fn last_admin_deterministic_sequence_covers_accepted_mutations_on_rest_and_gossip_paths() {
    let initial = vec![
        member_spec(GroupRole::Admin, GroupMemberState::Active),
        member_spec(GroupRole::Member, GroupMemberState::Active),
        member_spec(GroupRole::Member, GroupMemberState::Removed),
        member_spec(GroupRole::Member, GroupMemberState::Active),
        member_spec(GroupRole::Admin, GroupMemberState::Active),
    ];
    let actions = [
        LastAdminAction::AddMember {
            actor: 0,
            target: 2,
        },
        LastAdminAction::SetRole {
            actor: 0,
            target: 1,
            role: GroupRole::Admin,
        },
        LastAdminAction::RemoveMember {
            actor: 1,
            target: 2,
        },
        LastAdminAction::BanMember {
            actor: 1,
            target: 3,
        },
        LastAdminAction::UpdatePolicy {
            actor: 1,
            preset: GroupPolicyPreset::PublicOpen,
        },
        LastAdminAction::SelfLeave { actor: 0 },
        LastAdminAction::Withdraw { actor: 1 },
    ];

    let rest_keypairs = sequence_keypairs();
    let gossip_keypairs = sequence_keypairs();
    let mut rest_group = group_from_initial_specs(&rest_keypairs, &initial);
    let mut gossip_group = group_from_initial_specs(&gossip_keypairs, &initial);
    let mut rest_stats = SequencePathStats::default();
    let mut gossip_stats = SequencePathStats::default();

    for (idx, action) in actions.iter().enumerate() {
        let now_ms = 20_000 + idx as u64;

        let rest_outcome = apply_rest_action(&mut rest_group, &rest_keypairs, action, now_ms);
        assert_eq!(
            rest_outcome,
            SequenceOutcome::Accepted,
            "REST deterministic action should be accepted: {action:?}"
        );
        rest_stats.record(action, rest_outcome);
        assert!(rest_group.withdrawn || independent_has_active_admin(&rest_group));

        let gossip_outcome =
            apply_gossip_action(&mut gossip_group, &gossip_keypairs, action, now_ms);
        assert_eq!(
            gossip_outcome,
            SequenceOutcome::Accepted,
            "gossip deterministic action should be accepted: {action:?}"
        );
        gossip_stats.record(action, gossip_outcome);
        assert!(gossip_group.withdrawn || independent_has_active_admin(&gossip_group));
    }

    rest_stats.assert_all_semantically_valid_actions_accepted("REST");
    gossip_stats.assert_all_semantically_valid_actions_accepted("gossip");
    assert!(rest_group.withdrawn);
    assert!(gossip_group.withdrawn);
}
