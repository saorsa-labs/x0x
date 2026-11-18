//! Issue #1840 (ask 4): the typed outcome an authority sends back when its
//! validation refuses a `JoinRequestCreated` offer.
//!
//! The offer is a typed DM that carries the requester-signed V2 envelope.
//! When the authority refuses it before any roster write, the requester
//! used to learn nothing. This module is the one definition of the reply:
//! a typed DM (`x0x-group-join-outcome-v1\0` ‖ JSON [`JoinRequestOutcome`]).
//!
//! The outcome has no signature of its own. The DM envelope authenticates
//! the sender agent, and the requester accepts an outcome only from the
//! authority it sent that offer to, and only when `group_id`, `request_id`
//! and `envelope_digest` all equal its own pending offer. The digest covers
//! the exact signed envelope, so an outcome for one offer cannot be moved
//! to another request or to a re-sealed envelope of the same request.
//!
//! The body is JSON without `deny_unknown_fields`: a later optional field
//! is ignored by this release. An unknown `reason` decodes to
//! [`JoinRequestRefusalReason::Unknown`], which is terminal.
//!
//! Issue #1840 routes 1–3 (A08 amendment of 15 Nov 2026): a `stale`
//! outcome may carry the authority's current head ([`JoinRequestOutcome::
//! head`]): its signed head commit, the roster projection that commit's
//! `roster_root` hashes, and the public metadata it sealed. A requester
//! that holds only a card stub, a copy from before an edit, or an old
//! member copy cannot seal a link the authority accepts, because the link
//! signs hashes of state it does not hold. With the head it checks the
//! state ([`adopt_join_head`]), installs it, and signs the same request
//! again. The field is optional: an outcome without it is the outcome of
//! the first release, and an authority sends a head only to a requester
//! that advertises it can use one.

use serde::{Deserialize, Serialize};

use crate::groups::state_commit::{
    compute_policy_hash, compute_public_meta_hash, roster_root_of_projection, RetainedCommit,
};
use crate::groups::{GroupAdmission, GroupInfo, GroupMemberState, GroupRole};

/// Versioned, NUL-terminated DM prefix of a join-request outcome.
pub const JOIN_REQUEST_OUTCOME_DM_PREFIX: &[u8] = b"x0x-group-join-outcome-v1\0";

/// Upper bound on one encoded outcome without a head, prefix included. A
/// real outcome is about 250 bytes.
pub const MAX_JOIN_REQUEST_OUTCOME_BYTES: usize = 1024;

/// Upper bound on one encoded outcome that carries a head, prefix
/// included. It stays below the direct-message payload bound
/// ([`crate::dm::MAX_PAYLOAD_BYTES`], 48 KiB) with room for the DM framing.
/// The signed head commit is about 11 KB; each roster row is about 250
/// bytes without certificate bytes. An authority whose head does not fit
/// sends the outcome without a head.
pub const MAX_JOIN_REQUEST_HEAD_OUTCOME_BYTES: usize = 45_056;

/// Why the authority refused the request. A closed set.
///
/// Disclosure rule: the requester can be any agent that knows the group
/// id, so a reason names only (a) a fact about the requester itself
/// (`AlreadyMember`, `Banned`, `PendingExists`), (b) `Stale`, or (c)
/// `Invalid`. `Stale` is ONE reason for every refusal that depends on the
/// authority's group state (revision, chain head, roster, admission
/// policy), so it does not show which of those checks refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JoinRequestRefusalReason {
    /// The requester's copy of the group is not the authority's current
    /// state: the signed commit is behind the head, does not chain to it,
    /// seals another roster, the group does not admit by request, or the
    /// request id is already in the authority's roster.
    Stale,
    /// The requester already holds an active seat.
    AlreadyMember,
    /// The requester is banned from the group.
    Banned,
    /// The authority already holds a pending request from this requester.
    PendingExists,
    /// The envelope is not acceptable (terminal): a check of the envelope
    /// alone refused it, or a check that runs after its commit matched the
    /// authority's revision and chain head.
    Invalid,
    /// A reason this release does not know, from a newer authority. Never
    /// encoded.
    #[serde(other, skip_serializing)]
    Unknown,
}

impl JoinRequestRefusalReason {
    /// The stable API and wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::AlreadyMember => "already_member",
            Self::Banned => "banned",
            Self::PendingExists => "pending_exists",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }

    /// `true` when a NEW envelope, made from a current copy of the group,
    /// can succeed. The same envelope is never worth another offer.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Stale)
    }
}

/// The body of a join-request outcome DM. Today the only outcome is a
/// refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestOutcome {
    /// Stable group id of the refused request.
    pub group_id: String,
    /// The refused request id.
    pub request_id: String,
    /// Hex blake3 digest of the refused requester-signed V2 envelope.
    pub envelope_digest: String,
    /// Why the authority refused it.
    pub reason: JoinRequestRefusalReason,
    /// The authority's current head, for a `stale` refusal only: the signed
    /// head commit, the roster projection without certificate bytes, and
    /// the public metadata (`meta`, required). `None` on every other
    /// outcome and from an authority of the first release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<RetainedCommit>,
}

impl JoinRequestOutcome {
    /// Encode the DM payload (prefix ‖ JSON).
    ///
    /// # Errors
    /// The reason is `Unknown`, a head rides on a reason other than
    /// `Stale`, the body does not encode, or the payload is over its bound
    /// ([`MAX_JOIN_REQUEST_OUTCOME_BYTES`], or
    /// [`MAX_JOIN_REQUEST_HEAD_OUTCOME_BYTES`] with a head).
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.reason == JoinRequestRefusalReason::Unknown {
            return Err("an unknown refusal reason is never sent".to_string());
        }
        if self.head.is_some() && self.reason != JoinRequestRefusalReason::Stale {
            return Err("a head rides only on a stale refusal".to_string());
        }
        let body = serde_json::to_vec(self).map_err(|e| format!("encode: {e}"))?;
        let mut out = Vec::with_capacity(JOIN_REQUEST_OUTCOME_DM_PREFIX.len() + body.len());
        out.extend_from_slice(JOIN_REQUEST_OUTCOME_DM_PREFIX);
        out.extend_from_slice(&body);
        if out.len() > Self::bound(self.head.is_some()) {
            return Err("join-request outcome over bound".to_string());
        }
        Ok(out)
    }

    /// Decode a DM payload. `None` for a wrong prefix, an oversized payload,
    /// a body that is not an outcome, or a head on a reason other than
    /// `Stale`.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() > MAX_JOIN_REQUEST_HEAD_OUTCOME_BYTES {
            return None;
        }
        let body = payload.strip_prefix(JOIN_REQUEST_OUTCOME_DM_PREFIX)?;
        let outcome: Self = serde_json::from_slice(body).ok()?;
        let headed = outcome.head.is_some();
        if payload.len() > Self::bound(headed)
            || (headed && outcome.reason != JoinRequestRefusalReason::Stale)
        {
            return None;
        }
        Some(outcome)
    }

    fn bound(headed: bool) -> usize {
        if headed {
            MAX_JOIN_REQUEST_HEAD_OUTCOME_BYTES
        } else {
            MAX_JOIN_REQUEST_OUTCOME_BYTES
        }
    }
}

/// Why a requester did not adopt the head of a `stale` outcome. A head that
/// is not adopted changes nothing: the requester keeps its copy and records
/// the refusal as before.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JoinHeadError {
    /// The head commit names another group.
    #[error("the head is for another group")]
    OtherGroup,
    /// The head commit's hash or signature does not verify.
    #[error("the head commit does not verify: {0}")]
    Unverified(String),
    /// The roster projection does not hash to the signed `roster_root`.
    #[error("the head roster does not hash to the signed roster root")]
    Roster,
    /// The public metadata is missing or does not hash to the signed value.
    #[error("the head metadata is missing or does not hash to the signed value")]
    Meta,
    /// The local policy is not request access, or does not hash to the
    /// signed `policy_hash`: the requester's copy has another policy.
    #[error("the head policy is not this copy's request-access policy")]
    Policy,
    /// The head does not move this copy forward: it is at an older
    /// revision than the copy's base, or at the same revision with another
    /// state hash.
    #[error("the head is not ahead of this copy")]
    NotAhead,
    /// The group's creator is not an Active admin or owner in the head
    /// roster.
    #[error("the head roster drops the group's owner")]
    OwnerMissing,
    /// The head or this copy is withdrawn.
    #[error("the group is withdrawn")]
    Withdrawn,
    /// The requester holds an Active seat or is Banned in the head.
    #[error("the requester is already seated or banned in the head")]
    Seated,
    /// The checked head did not install on this copy.
    #[error("the head does not install: {0}")]
    Install(String),
}

/// Check a head from a `stale` outcome against the requester's local copy
/// `local`, and return that copy with the head installed: the head roster,
/// the head metadata and the head chain fields, with the commit log reset to
/// the head link. The caller signs its request again over the result. The
/// local copy is not changed.
///
/// Trust: the only trust anchor is the authority. The caller has matched
/// the outcome to its own pending offer and its authenticated sender to the
/// authority that offer went to, the same authority whose card the
/// requester imported. The checks below prove the head is intact and fits
/// this group; they do not prove who may have written it. In particular
/// the commit's signer is not checked against the head roster, because
/// that roster comes from the same head (a key could list itself as an
/// admin), and the newest link is often another requester's request link,
/// which that requester signed.
///
/// Chain: the requester is not a member, so its copy is a card stub, a copy
/// from before an edit, or the copy it kept as a removed member. It holds
/// none of the links between that copy and the head, so it cannot check
/// ancestry. The rule is forward-only instead: the head must be at a
/// higher revision than the copy's base, or at the same revision with the
/// same state hash (a card stub holds the authority's real hash with a
/// partial roster). The base is the copy's head, or the link before it when
/// the newest link is the requester's own request link. So a head can
/// never move the copy back. Clearing the copy's log is allowed for the
/// same reason: a non-member's log holds no link that a later check reads,
/// and the installed copy keeps the head link, which is what the next seal
/// chains to.
///
/// `requester_agent_id` is this daemon's agent.
///
/// Checks, each a [`JoinHeadError`]:
/// - the head commit is for this group, and its hash and ML-DSA-65
///   signature verify (the commit is intact);
/// - the group's creator is an Active admin or owner in the head roster;
/// - the roster projection re-derives the signed `roster_root`, and the
///   metadata re-derives the signed `public_meta_hash`;
/// - the local policy is request access and re-derives the signed
///   `policy_hash`;
/// - the head is ahead of the copy's base, as above;
/// - neither is withdrawn, and the requester is not Active or Banned in the
///   head roster;
/// - the installed copy re-derives the head's full `state_hash`.
///
/// # Errors
/// The first check that fails.
pub fn adopt_join_head(
    local: &GroupInfo,
    head: &RetainedCommit,
    requester_agent_id: &str,
) -> Result<GroupInfo, JoinHeadError> {
    let commit = &head.commit;
    if commit.group_id != local.stable_group_id() {
        return Err(JoinHeadError::OtherGroup);
    }
    commit
        .verify_structure()
        .map_err(|e| JoinHeadError::Unverified(e.to_string()))?;
    if roster_root_of_projection(&head.roster) != commit.roster_root {
        return Err(JoinHeadError::Roster);
    }
    let meta = head
        .meta
        .as_ref()
        .filter(|meta| compute_public_meta_hash(meta) == commit.public_meta_hash)
        .ok_or(JoinHeadError::Meta)?;
    if local.policy.admission != GroupAdmission::RequestAccess
        || compute_policy_hash(&local.policy) != commit.policy_hash
    {
        return Err(JoinHeadError::Policy);
    }
    let creator_hex = hex::encode(local.creator.as_bytes());
    if !head.roster.get(&creator_hex).is_some_and(|snap| {
        snap.state == GroupMemberState::Active && snap.role.at_least(GroupRole::Admin)
    }) {
        return Err(JoinHeadError::OwnerMissing);
    }
    let own_link_on_top = local.commit_log.last().is_some_and(|link| {
        link.commit.committed_by == requester_agent_id
            && link.commit.revision == local.state_revision
    });
    let (base_revision, base_hash) = if own_link_on_top {
        (
            local.state_revision.saturating_sub(1),
            local.prev_state_hash.clone(),
        )
    } else {
        (local.state_revision, Some(local.state_hash.clone()))
    };
    let ahead = commit.revision > base_revision
        || (commit.revision == base_revision
            && base_hash.as_deref() == Some(commit.state_hash.as_str()));
    if !ahead {
        return Err(JoinHeadError::NotAhead);
    }
    if commit.withdrawn || local.withdrawn {
        return Err(JoinHeadError::Withdrawn);
    }
    if head.roster.get(requester_agent_id).is_some_and(|snap| {
        matches!(
            snap.state,
            GroupMemberState::Active | GroupMemberState::Banned
        )
    }) {
        return Err(JoinHeadError::Seated);
    }
    let mut next = local.clone();
    next.commit_log.clear();
    next.apply_reconstructed_roster(&head.roster);
    next.finalize_adopted_commit_reconstructed(commit, meta, &[])
        .map_err(|e| JoinHeadError::Install(e.to_string()))?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue1840_outcome_round_trips_and_ignores_later_fields() {
        let outcome = JoinRequestOutcome {
            group_id: "g".to_string(),
            request_id: "r".to_string(),
            envelope_digest: "ab".repeat(32),
            reason: JoinRequestRefusalReason::Stale,
            head: None,
        };
        let payload = outcome.encode().expect("encode");
        assert_eq!(JoinRequestOutcome::decode(&payload), Some(outcome));

        let mut later = JOIN_REQUEST_OUTCOME_DM_PREFIX.to_vec();
        later.extend_from_slice(
            br#"{"group_id":"g","request_id":"r","envelope_digest":"00","reason":"from_the_future","later":{"revision":7}}"#,
        );
        let decoded = JoinRequestOutcome::decode(&later).expect("a later optional field decodes");
        assert_eq!(decoded.reason, JoinRequestRefusalReason::Unknown);
        assert!(!decoded.reason.is_retryable());
        assert!(decoded.encode().is_err(), "Unknown is never sent");
        assert!(JoinRequestOutcome::decode(b"ordinary text").is_none());

        let mut bad_head = JOIN_REQUEST_OUTCOME_DM_PREFIX.to_vec();
        bad_head.extend_from_slice(
            br#"{"group_id":"g","request_id":"r","envelope_digest":"00","reason":"stale","head":{"revision":7}}"#,
        );
        assert!(JoinRequestOutcome::decode(&bad_head).is_none());
    }

    use crate::groups::{GroupPolicyPreset, GroupRole};
    use crate::identity::AgentKeypair;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn authority_and_stale_copy(extra: usize) -> (AgentKeypair, GroupInfo, GroupInfo) {
        let owner = AgentKeypair::generate().expect("owner key");
        let mut info = GroupInfo::with_policy(
            "1840 head".to_string(),
            String::new(),
            owner.agent_id(),
            hex::encode(blake3::hash(b"1840-head").as_bytes()),
            GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.seal_commit(&owner, now_ms()).expect("genesis head");
        let stale = info.clone();
        let owner_hex = hex::encode(owner.agent_id().as_bytes());
        for i in 0..extra {
            info.add_member(
                format!("{:064x}", 0x1840_1000u64 + i as u64),
                GroupRole::Member,
                Some(owner_hex.clone()),
                None,
            );
        }
        info.name = "renamed by an edit".to_string();
        info.seal_commit(&owner, now_ms()).expect("authority head");
        (owner, info, stale)
    }

    fn head_of(info: &GroupInfo) -> RetainedCommit {
        let mut head = info.commit_log.last().expect("head link").clone();
        for snap in head.roster.values_mut() {
            snap.certificate = None;
        }
        head
    }

    fn requester() -> String {
        hex::encode(AgentKeypair::generate().expect("key").agent_id().as_bytes())
    }

    #[test]
    fn issue1840_a_stale_copy_adopts_the_checked_head() {
        let (_owner, authority, stale) = authority_and_stale_copy(2);
        let adopted = adopt_join_head(&stale, &head_of(&authority), &requester())
            .expect("a valid head is adopted");
        assert_eq!(adopted.state_hash, authority.state_hash);
        assert_eq!(adopted.state_revision, authority.state_revision);
        assert_eq!(adopted.name, authority.name);
        assert_eq!(
            crate::groups::state_commit::compute_roster_root(&adopted.members_v2),
            crate::groups::state_commit::compute_roster_root(&authority.members_v2)
        );
        assert_eq!(adopted.commit_log.len(), 1, "the log restarts at the head");
        assert_ne!(
            stale.state_hash, adopted.state_hash,
            "the input copy is unchanged"
        );
    }

    #[test]
    fn issue1840_requester_seals_over_a_digest_only_head() {
        let (owner, mut authority, stale) = authority_and_stale_copy(2);
        for member in authority.members_v2.values_mut() {
            member.certificate = None;
            member.certificate_digest = Some("cd".repeat(32));
        }
        authority
            .seal_commit(&owner, now_ms())
            .expect("head over digest seats");
        let joiner = AgentKeypair::generate().expect("joiner");
        let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
        let mut adopted =
            adopt_join_head(&stale, &head_of(&authority), &joiner_hex).expect("adopted");
        assert!(adopted
            .members_v2
            .values()
            .all(|m| m.certificate.is_none() && m.certificate_digest.is_some()));
        let link = adopted
            .seal_commit(&joiner, now_ms())
            .expect("plain requester seal");
        assert_eq!(link.revision, authority.state_revision + 1);
        assert_eq!(
            link.prev_state_hash.as_deref(),
            Some(authority.state_hash.as_str())
        );
        assert_eq!(link.roster_root, head_of(&authority).commit.roster_root);
    }

    #[test]
    fn issue1840_a_head_that_fails_a_check_is_not_adopted() {
        let (owner, authority, stale) = authority_and_stale_copy(1);
        let stale_before = stale.clone();
        let owner_hex = hex::encode(owner.agent_id().as_bytes());
        let me = requester();
        let adopt = |head: &RetainedCommit, local: &GroupInfo| adopt_join_head(local, head, &me);

        let mut other = head_of(&authority);
        other.commit.group_id = "00".repeat(32);
        assert_eq!(adopt(&other, &stale), Err(JoinHeadError::OtherGroup));

        let mut forged = head_of(&authority);
        forged.commit.committed_at += 1;
        assert!(matches!(
            adopt(&forged, &stale),
            Err(JoinHeadError::Unverified(_))
        ));

        let other_requester = AgentKeypair::generate().expect("requester");
        let mut by_requester = authority.clone();
        by_requester
            .seal_commit(&other_requester, now_ms())
            .expect("seal");
        assert!(adopt(&head_of(&by_requester), &stale).is_ok());

        let mut roster = head_of(&authority);
        roster.roster.pop_first();
        assert_eq!(adopt(&roster, &stale), Err(JoinHeadError::Roster));

        let mut no_meta = head_of(&authority);
        no_meta.meta = None;
        assert_eq!(adopt(&no_meta, &stale), Err(JoinHeadError::Meta));
        let mut wrong_meta = head_of(&authority);
        if let Some(meta) = wrong_meta.meta.as_mut() {
            meta.name.push('!');
        }
        assert_eq!(adopt(&wrong_meta, &stale), Err(JoinHeadError::Meta));

        let mut other_policy = stale.clone();
        other_policy.policy = GroupPolicyPreset::PublicOpen.to_policy();
        assert_eq!(
            adopt(&head_of(&authority), &other_policy),
            Err(JoinHeadError::Policy)
        );

        let mut ahead = stale.clone();
        ahead.state_revision = authority.state_revision + 2;
        assert_eq!(
            adopt(&head_of(&authority), &ahead),
            Err(JoinHeadError::NotAhead)
        );
        assert_eq!(
            adopt(&head_of(&stale), &authority),
            Err(JoinHeadError::NotAhead)
        );
        let mut fork = stale.clone();
        fork.state_revision -= 1;
        fork.name = "a fork at the same revision".to_string();
        fork.seal_commit(&owner, now_ms()).expect("fork seal");
        assert_eq!(fork.state_revision, stale.state_revision);
        assert_eq!(adopt(&head_of(&fork), &stale), Err(JoinHeadError::NotAhead));

        let me_key = AgentKeypair::generate().expect("requester key");
        let me_hex = hex::encode(me_key.agent_id().as_bytes());
        let mut asked = stale.clone();
        asked
            .seal_commit(&me_key, now_ms())
            .expect("own request link");
        assert_eq!(asked.state_revision, authority.state_revision);
        assert!(adopt_join_head(&asked, &head_of(&authority), &me_hex).is_ok());

        let mut ownerless = authority.clone();
        let admin = ownerless
            .members_v2
            .keys()
            .find(|id| **id != owner_hex)
            .expect("member")
            .clone();
        if let Some(member) = ownerless.members_v2.get_mut(&admin) {
            member.role = GroupRole::Admin;
        }
        ownerless.members_v2.remove(&owner_hex);
        let stranger = AgentKeypair::generate().expect("stranger");
        ownerless
            .seal_commit(&stranger, now_ms())
            .expect("seal without the owner");
        assert_eq!(
            adopt(&head_of(&ownerless), &stale),
            Err(JoinHeadError::OwnerMissing)
        );

        let mut withdrawn = stale.clone();
        withdrawn.withdrawn = true;
        assert_eq!(
            adopt(&head_of(&authority), &withdrawn),
            Err(JoinHeadError::Withdrawn)
        );

        let seated = authority
            .members_v2
            .keys()
            .find(|id| **id != owner_hex)
            .expect("member")
            .clone();
        assert_eq!(
            adopt_join_head(&stale, &head_of(&authority), &seated),
            Err(JoinHeadError::Seated)
        );

        let mut head_withdrawn = authority.clone();
        head_withdrawn
            .seal_withdrawal(&owner, now_ms())
            .expect("withdrawal seal");
        assert_eq!(
            adopt(&head_of(&head_withdrawn), &stale),
            Err(JoinHeadError::Withdrawn)
        );

        let mut banned = authority.clone();
        banned.ban_member(&me, Some(owner_hex.clone()));
        banned.seal_commit(&owner, now_ms()).expect("ban seal");
        assert_eq!(adopt(&head_of(&banned), &stale), Err(JoinHeadError::Seated));

        assert_eq!(stale, stale_before);
    }

    #[test]
    fn issue1840_own_link_on_the_head_itself_is_not_behind() {
        let (_owner, authority, _stale) = authority_and_stale_copy(1);
        let me = AgentKeypair::generate().expect("requester key");
        let me_hex = hex::encode(me.agent_id().as_bytes());
        let mut asked = authority.clone();
        asked.seal_commit(&me, now_ms()).expect("own request link");
        assert_eq!(asked.state_revision, authority.state_revision + 1);
        assert!(adopt_join_head(&asked, &head_of(&authority), &me_hex).is_ok());
    }

    #[test]
    fn issue1840_headed_outcome_bounds_and_round_trip() {
        let (_owner, authority, _stale) = authority_and_stale_copy(3);
        let outcome = JoinRequestOutcome {
            group_id: authority.stable_group_id().to_string(),
            request_id: "r".to_string(),
            envelope_digest: "ab".repeat(32),
            reason: JoinRequestRefusalReason::Stale,
            head: Some(head_of(&authority)),
        };
        let payload = outcome.encode().expect("encode");
        assert!(
            payload.len() > MAX_JOIN_REQUEST_OUTCOME_BYTES,
            "a headed outcome does not fit the first release's bound ({} bytes)",
            payload.len()
        );
        assert!(payload.len() <= MAX_JOIN_REQUEST_HEAD_OUTCOME_BYTES);
        assert_eq!(JoinRequestOutcome::decode(&payload), Some(outcome.clone()));

        let mut banned = outcome.clone();
        banned.reason = JoinRequestRefusalReason::Banned;
        assert!(banned.encode().is_err(), "a head rides only on stale");
        let body = serde_json::to_vec(&banned).expect("json");
        let mut forged = JOIN_REQUEST_OUTCOME_DM_PREFIX.to_vec();
        forged.extend_from_slice(&body);
        assert!(JoinRequestOutcome::decode(&forged).is_none());

        let mut oversized = JOIN_REQUEST_OUTCOME_DM_PREFIX.to_vec();
        oversized.resize(MAX_JOIN_REQUEST_HEAD_OUTCOME_BYTES + 1, b' ');
        assert!(JoinRequestOutcome::decode(&oversized).is_none());

        let mut padded = serde_json::to_value(JoinRequestOutcome {
            head: None,
            ..outcome
        })
        .expect("json");
        padded["pad"] = serde_json::json!("x".repeat(MAX_JOIN_REQUEST_OUTCOME_BYTES));
        let mut long = JOIN_REQUEST_OUTCOME_DM_PREFIX.to_vec();
        long.extend_from_slice(&serde_json::to_vec(&padded).expect("json"));
        assert!(JoinRequestOutcome::decode(&long).is_none());
    }
}
