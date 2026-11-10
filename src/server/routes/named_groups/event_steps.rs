//! #1606: the pure step of an ordinary metadata event. The ordinary apply
//! ([`super::apply_named_group_metadata_event`]) and the GSS later-admin
//! held-chain walk (`owner_recovery::next_held_state`) both call it.
//!
//! A step holds three things: the event's own authority checks, the
//! [`ActionKind`] that the commit signer must hold, and the [`GroupInfo`]
//! change. It has no side effects. The apply adds its side effects
//! (persist, card cache, parking). The walk adds its own GSS-only rules.
//! So the walk and the apply accept the same commits from one rule, with
//! no hand copy.
//!
//! The steps cover the role update, the rename, the policy update, the
//! unban, and the rejection and cancellation of a join request. The
//! removal, ban, GSS add, join request and approval arms are not here yet
//! (#1606).

use crate as x0x;
use x0x::groups::{ActionKind, GroupInfo, GroupPolicy, GroupRole};

/// Why a step refuses its event. The ordinary apply rejects the event in
/// every case; it parks it, or logs it, as the variant says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum StepRefusal {
    /// The event fails its authority or state checks.
    Refused,
    /// The target has no seat yet (or only the join's key-only marker
    /// row). The ordinary apply parks a role update for it.
    NotSeated,
    /// A policy update changes or removes the OwnerCertified owner axis.
    OwnerAxisChanged,
}

/// The action the commit signer must hold, and the change to apply.
pub(in crate::server) type Step<F> = Result<(ActionKind, F), StepRefusal>;

/// `actor` is the sender and an admin of `cursor`.
fn admin_signed(cursor: &GroupInfo, actor: &str, sender_hex: &str) -> bool {
    actor == sender_hex
        && cursor
            .caller_role(actor)
            .is_some_and(|role| role.at_least(GroupRole::Admin))
}

/// `MemberRoleUpdated`.
pub(in crate::server) fn role_update<'a>(
    cursor: &GroupInfo,
    sender_hex: &str,
    revision: u64,
    actor: &str,
    agent_id: &'a str,
    role: GroupRole,
) -> Step<impl FnOnce(&mut GroupInfo) + 'a> {
    if !admin_signed(cursor, actor, sender_hex) {
        return Err(StepRefusal::Refused);
    }
    // #1578 rc11: the join's key-only marker row is not a seat.
    let target = cursor
        .members_v2
        .get(agent_id)
        .filter(|_| !cursor.join_seat_key_marker_only(agent_id))
        .ok_or(StepRefusal::NotSeated)?;
    // ADR-0016: signed gossip apply rejects only Owner (admin-equivalent).
    if target.is_removed() || target.is_banned() || role == GroupRole::Owner {
        return Err(StepRefusal::Refused);
    }
    Ok((ActionKind::AdminOrHigher, move |next: &mut GroupInfo| {
        next.roster_revision = super::adopt_roster_revision(next.roster_revision, revision);
        next.set_member_role(agent_id, role);
    }))
}

/// `GroupMetadataUpdated` (a rename or a new description).
pub(in crate::server) fn metadata_update<'a>(
    cursor: &GroupInfo,
    sender_hex: &str,
    revision: u64,
    actor: &str,
    name: &'a Option<String>,
    description: &'a Option<String>,
    committed_at: u64,
) -> Step<impl FnOnce(&mut GroupInfo) + 'a> {
    if !admin_signed(cursor, actor, sender_hex) {
        return Err(StepRefusal::Refused);
    }
    Ok((ActionKind::AdminOrHigher, move |next: &mut GroupInfo| {
        next.roster_revision = super::adopt_roster_revision(next.roster_revision, revision);
        if let Some(name) = name.clone() {
            next.name = name;
        }
        if let Some(description) = description.clone() {
            next.description = description;
        }
        next.updated_at = committed_at;
    }))
}

/// `PolicyUpdated`. The ordinary apply does not check the event's actor
/// field; only the commit signer's [`ActionKind::AdminOrHigher`] is
/// checked. The GSS held-chain walk adds its own actor check: the actor
/// must be the sender and an admin.
pub(in crate::server) fn policy_update<'a>(
    cursor: &GroupInfo,
    revision: u64,
    policy: &'a GroupPolicy,
    committed_at: u64,
) -> Step<impl FnOnce(&mut GroupInfo) + 'a> {
    // ADR-0038 review B2: an existing OwnerCertified owner axis never
    // changes or goes, even inside an admin-signed commit.
    if let Some(owner) = cursor.policy.admission.owner_certified_user_id() {
        if policy.admission.owner_certified_user_id() != Some(owner) {
            return Err(StepRefusal::OwnerAxisChanged);
        }
    }
    Ok((ActionKind::AdminOrHigher, move |next: &mut GroupInfo| {
        super::set_policy_update(next, revision, policy, committed_at)
    }))
}

/// `MemberUnbanned`.
pub(in crate::server) fn unban<'a>(
    cursor: &GroupInfo,
    sender_hex: &str,
    revision: u64,
    actor: &str,
    agent_id: &'a str,
    committed_at: u64,
) -> Step<impl FnOnce(&mut GroupInfo) + 'a> {
    if !admin_signed(cursor, actor, sender_hex) {
        return Err(StepRefusal::Refused);
    }
    Ok((ActionKind::AdminOrHigher, move |next: &mut GroupInfo| {
        next.roster_revision = super::adopt_roster_revision(next.roster_revision, revision);
        if next.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
            // #1578 rc11 (audit): the join's key-only marker row is not
            // a seat — main holds no row to flip.
            if !next.join_seat_key_marker_only(agent_id) {
                if let Some(member) = next.members_v2.get_mut(agent_id) {
                    member.state = x0x::groups::GroupMemberState::Removed;
                    member.updated_at = committed_at;
                    member.removed_by = None;
                }
            }
        } else {
            next.unban_member(agent_id);
        }
    }))
}

/// #1623: a `JoinRequestRejected` event names the request that its commit
/// signer rejected. The commit covers no join request, so two rules tie
/// the event to its signer:
///
/// - `actor` is `commit.committed_by`. Every caller also needs the
///   authenticated sender to be `actor`, so only the commit signer can
///   present its reject. Another admin cannot reuse the commit under its
///   own name.
/// - `request_binding`, when present, is the signer's signature over the
///   commit, `request_id` and `requester_agent_id`
///   (`state_commit::verify_join_request_reject`). A copy with another
///   request or requester is refused.
///
/// A reject with no binding is the form of a signer older than #1623. It
/// is accepted under the first rule alone, so a chain that holds such a
/// link still applies. A third party cannot remove the binding to
/// re-label a reject: without the signer's transport identity the first
/// rule refuses its copy.
pub(in crate::server) fn reject_names_its_request(
    commit: &x0x::groups::GroupStateCommit,
    reject: RejectedRequest<'_>,
) -> bool {
    commit.committed_by == reject.actor
        && reject.request_binding.is_none_or(|binding| {
            x0x::groups::state_commit::verify_join_request_reject(
                commit,
                reject.request_id,
                reject.requester_agent_id,
                binding,
            )
            .is_ok()
        })
}

/// The fields of a `JoinRequestRejected` event that its step reads.
#[derive(Clone, Copy)]
pub(in crate::server) struct RejectedRequest<'a> {
    pub request_id: &'a str,
    pub actor: &'a str,
    pub requester_agent_id: &'a str,
    pub request_binding: Option<&'a str>,
}

/// `JoinRequestRejected`: an admin rejects a pending request. The event
/// must name the request that the commit signer rejected
/// ([`reject_names_its_request`], #1623).
pub(in crate::server) fn join_request_rejected<'a>(
    cursor: &GroupInfo,
    sender_hex: &str,
    reject: RejectedRequest<'a>,
    commit: &x0x::groups::GroupStateCommit,
) -> Step<impl FnOnce(&mut GroupInfo) + 'a> {
    let RejectedRequest {
        request_id, actor, ..
    } = reject;
    if !admin_signed(cursor, actor, sender_hex)
        || !cursor
            .join_requests
            .get(request_id)
            .is_some_and(|request| request.is_pending())
        || !reject_names_its_request(commit, reject)
    {
        return Err(StepRefusal::Refused);
    }
    let committed_at = commit.committed_at;
    Ok((ActionKind::AdminOrHigher, move |next: &mut GroupInfo| {
        super::set_join_request_rejected(next, request_id, actor, committed_at)
    }))
}

/// `JoinRequestCancelled`: the requester cancels its own pending request.
pub(in crate::server) fn join_request_cancelled<'a>(
    cursor: &GroupInfo,
    sender_hex: &str,
    request_id: &'a str,
    requester_agent_id: &'a str,
) -> Step<impl FnOnce(&mut GroupInfo) + 'a> {
    if sender_hex != requester_agent_id
        || !cursor.join_requests.get(request_id).is_some_and(|request| {
            request.requester_agent_id == requester_agent_id && request.is_pending()
        })
    {
        return Err(StepRefusal::Refused);
    }
    Ok((ActionKind::NonMemberRequest, move |next: &mut GroupInfo| {
        super::set_join_request_cancelled(next, request_id, requester_agent_id)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1606 review: a policy update keeps an existing OwnerCertified
    /// owner axis; it may not change or remove it.
    #[test]
    fn a_policy_update_keeps_the_owner_axis() {
        let owner = x0x::identity::UserId([1; 32]);
        let mut cursor = GroupInfo::new(
            "g".into(),
            "d".into(),
            x0x::identity::AgentId([2; 32]),
            "g".into(),
        );
        cursor.policy = GroupPolicy::home(&owner);
        let other = GroupPolicy::home(&x0x::identity::UserId([3; 32]));
        let open = x0x::groups::GroupPolicyPreset::PublicOpen.to_policy();
        for policy in [&other, &open] {
            assert_eq!(
                policy_update(&cursor, 1, policy, 0).err(),
                Some(StepRefusal::OwnerAxisChanged)
            );
        }
        let same = cursor.policy.clone();
        assert!(policy_update(&cursor, 1, &same, 0).is_ok());
    }

    /// #1606 review: a rejection of a request that is not pending, and a
    /// cancellation by an agent that is not the requester, are `Refused`.
    #[test]
    fn resolved_or_foreign_requests_are_refused() {
        let admin = x0x::identity::AgentId([2; 32]);
        let admin_hex = hex::encode(admin.as_bytes());
        let requester = "ee".repeat(32);
        let mut cursor = GroupInfo::new("g".into(), "d".into(), admin, "g".into());
        let mut request = x0x::groups::JoinRequest::new("g".into(), requester.clone(), None, 0);
        request.request_id = "r".into();
        cursor.join_requests.insert("r".into(), request.clone());
        // A pending request: only its requester may cancel it.
        assert_eq!(
            join_request_cancelled(&cursor, &admin_hex, "r", &requester).err(),
            Some(StepRefusal::Refused)
        );
        // The step reads the commit's signer; the apply verifies the commit.
        let commit = x0x::groups::GroupStateCommit {
            group_id: "g".into(),
            revision: 1,
            prev_state_hash: None,
            roster_root: String::new(),
            policy_hash: String::new(),
            public_meta_hash: String::new(),
            security_binding: None,
            state_hash: String::new(),
            withdrawn: false,
            committed_by: admin_hex.clone(),
            committed_at: 0,
            signer_public_key: String::new(),
            signature: String::new(),
        };
        let reject = RejectedRequest {
            request_id: "r",
            actor: &admin_hex,
            requester_agent_id: &requester,
            request_binding: None,
        };
        assert!(join_request_rejected(&cursor, &admin_hex, reject, &commit).is_ok());
        // A resolved request: no admin may reject it.
        request.status = x0x::groups::JoinRequestStatus::Rejected;
        cursor.join_requests.insert("r".into(), request);
        assert_eq!(
            join_request_rejected(&cursor, &admin_hex, reject, &commit).err(),
            Some(StepRefusal::Refused)
        );
    }

    /// #1606 review: a role update for an agent with no seat is
    /// `NotSeated`, so the apply parks it.
    #[test]
    fn a_role_update_without_a_seat_is_not_seated() {
        let admin = x0x::identity::AgentId([2; 32]);
        let cursor = GroupInfo::new("g".into(), "d".into(), admin, "g".into());
        let admin_hex = hex::encode(admin.as_bytes());
        let absent = "ee".repeat(32);
        assert_eq!(
            role_update(
                &cursor,
                &admin_hex,
                1,
                &admin_hex,
                &absent,
                GroupRole::Admin
            )
            .err(),
            Some(StepRefusal::NotSeated)
        );
    }
}
