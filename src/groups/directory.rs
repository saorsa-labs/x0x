//! Discoverable group cards (Phase C + Phase D.3).
//!
//! A [`GroupCard`] is the public projection of a group's committed state —
//! the information a non-member needs to decide whether to request access.
//!
//! Phase D.3: cards carry an **authority signature** over canonical card
//! bytes and a `state_hash` tying them to the current signed state commit.
//! Relays may re-publish exact signed card blobs but cannot mint new
//! revisions unless they are group-state authorities. Receivers drop cards
//! whose signature fails or whose revision is stale, and a cached card is
//! replaced only by its own authority ([`GroupCard::replacement_verdict`]).

use crate::groups::policy::GroupPolicySummary;
use crate::groups::state_commit::{ApplyError, CARD_SIGNATURE_DOMAIN, DEFAULT_CARD_TTL_SECS};
use crate::identity::AgentKeypair;
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Largest revision step a card may take over the live cached card it
/// replaces.
///
/// A group's state chain advances by one revision for each sealed commit,
/// and a live cached card is at most one card TTL old (24 h). 2^20 commits
/// in one TTL is about 12 commits per second for a full day, which is far
/// above real use. A larger step does not come from a live state chain.
pub const MAX_CARD_REVISION_STEP: u64 = 1 << 20;

/// Why a card cannot take the place of the live cached card for its group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardRefusal {
    /// The card uses the reserved top revision (`u64::MAX`), which no state
    /// chain reaches.
    RevisionCeiling,
    /// The card advances the revision by more than
    /// [`MAX_CARD_REVISION_STEP`] over the cached card.
    RevisionStep,
    /// The card is not signed by an authority of the cached card.
    Authority,
}

impl CardRefusal {
    /// Stable short name for logs and counters.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevisionCeiling => "revision_ceiling",
            Self::RevisionStep => "revision_step",
            Self::Authority => "authority",
        }
    }
}

/// Result of a comparison between a card and the live cached card for the
/// same group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardReplacement {
    /// The card can take the place of the cached card (or remove it, for a
    /// withdrawal). This is also the result when no card is cached.
    Replace,
    /// The card comes from an authority of the cached card but is not newer.
    Stale,
    /// The card is refused.
    Refused(CardRefusal),
}

/// Public-facing card for a discoverable group.
///
/// Contains the information a non-member needs to decide whether to request
/// access. Does NOT include private content, roster, or encrypted data.
///
/// Phase D.3 fields (`revision`, `state_hash`, `prev_state_hash`,
/// `issued_at`, `expires_at`, `authority_agent_id`, `authority_public_key`,
/// `withdrawn`, `signature`) are serde-default for backward compatibility
/// with pre-D.3 blobs. Newly-issued cards set all of them and are signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupCard {
    pub group_id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub banner_url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub policy_summary: GroupPolicySummary,
    pub owner_agent_id: String,
    pub admin_count: u32,
    pub member_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
    pub request_access_enabled: bool,
    /// Bootstrap hint for non-member stubs so they can publish metadata-plane
    /// request events to the authority's actual topic. For newly signed cards
    /// this field is part of the v2 card signature domain.
    #[serde(default)]
    pub metadata_topic: Option<String>,

    // ── Phase D.3: state-commit binding and authority signature ─────────
    /// Monotonic revision of the signed state commit this card represents.
    /// Higher revisions supersede lower ones immediately.
    #[serde(default)]
    pub revision: u64,
    /// `state_hash` of the commit this card derives from.
    #[serde(default)]
    pub state_hash: String,
    /// Previous `state_hash` for chain linking on the directory plane.
    #[serde(default)]
    pub prev_state_hash: Option<String>,
    /// Unix milliseconds when the card was issued.
    #[serde(default)]
    pub issued_at: u64,
    /// Unix milliseconds after which the card is cache-cleanup candidate.
    /// TTL is **not** the primary validity mechanism — higher revisions
    /// supersede older cards immediately regardless of expiry.
    #[serde(default)]
    pub expires_at: u64,
    /// Hex agent_id of the authority who signed this card (owner/admin).
    #[serde(default)]
    pub authority_agent_id: String,
    /// Hex ML-DSA-65 public key of the authority, for standalone verify.
    #[serde(default)]
    pub authority_public_key: String,
    /// Withdrawal marker — `true` means this card supersedes any previous
    /// public card and signals the group has been hidden/deleted.
    #[serde(default)]
    pub withdrawn: bool,
    /// Hex ML-DSA-65 signature over the canonical card bytes.
    #[serde(default)]
    pub signature: String,
}

impl GroupCard {
    fn signable_bytes_legacy(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(CARD_SIGNATURE_DOMAIN);
        push_len_prefixed(&mut buf, self.group_id.as_bytes());
        buf.extend_from_slice(&self.revision.to_le_bytes());
        push_len_prefixed(&mut buf, self.state_hash.as_bytes());
        push_len_prefixed(
            &mut buf,
            self.prev_state_hash.as_deref().unwrap_or("").as_bytes(),
        );
        buf.extend_from_slice(&self.issued_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        push_len_prefixed(&mut buf, self.name.as_bytes());
        push_len_prefixed(&mut buf, self.description.as_bytes());
        push_len_prefixed(
            &mut buf,
            self.avatar_url.as_deref().unwrap_or("").as_bytes(),
        );
        push_len_prefixed(
            &mut buf,
            self.banner_url.as_deref().unwrap_or("").as_bytes(),
        );
        let mut tags = self.tags.clone();
        tags.sort();
        tags.dedup();
        buf.extend_from_slice(&(tags.len() as u32).to_le_bytes());
        for t in &tags {
            push_len_prefixed(&mut buf, t.as_bytes());
        }
        let policy_bytes = bincode::serialize(&self.policy_summary).unwrap_or_default();
        push_len_prefixed(&mut buf, &policy_bytes);
        push_len_prefixed(&mut buf, self.owner_agent_id.as_bytes());
        buf.extend_from_slice(&self.admin_count.to_le_bytes());
        buf.extend_from_slice(&self.member_count.to_le_bytes());
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.updated_at.to_le_bytes());
        buf.push(if self.request_access_enabled { 1 } else { 0 });
        buf.push(if self.withdrawn { 1 } else { 0 });
        push_len_prefixed(&mut buf, self.authority_agent_id.as_bytes());
        push_len_prefixed(&mut buf, self.authority_public_key.as_bytes());
        buf
    }

    /// Canonical v2 bytes signed by the authority to produce `signature`.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = self.signable_bytes_legacy();
        push_len_prefixed(
            &mut buf,
            self.metadata_topic.as_deref().unwrap_or("").as_bytes(),
        );
        buf
    }

    /// Sign this card with the given authority keypair. Populates
    /// `authority_agent_id`, `authority_public_key`, and `signature`.
    pub fn sign(&mut self, keypair: &AgentKeypair) -> Result<(), ApplyError> {
        self.authority_agent_id = hex::encode(keypair.agent_id().as_bytes());
        self.authority_public_key = hex::encode(keypair.public_key().as_bytes());
        self.signature = String::new();
        let sig = sign_with_ml_dsa(keypair.secret_key(), &self.signable_bytes())
            .map_err(|e| ApplyError::InvalidSignature(format!("card sign: {e:?}")))?;
        self.signature = hex::encode(sig.as_bytes());
        Ok(())
    }

    /// Verify the authority signature on this card.
    ///
    /// Checks:
    /// - `authority_public_key` hex decodes to a valid ML-DSA-65 key,
    /// - the derived AgentId matches `authority_agent_id`,
    /// - `signature` verifies over `signable_bytes()`.
    ///
    /// Returns `Ok(())` on success. Does **not** check whether the signer
    /// is currently authorised for the group: that is done at apply time
    /// against the local roster view, and by
    /// [`GroupCard::replacement_verdict`] for cached cards.
    pub fn verify_signature(&self) -> Result<(), ApplyError> {
        if self.signature.is_empty() || self.authority_public_key.is_empty() {
            return Err(ApplyError::InvalidSignature("missing signature".into()));
        }
        let pubkey_bytes = hex::decode(&self.authority_public_key)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad pubkey hex: {e}")))?;
        let pubkey = MlDsaPublicKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad pubkey: {e:?}")))?;
        let derived = hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0);
        if derived != self.authority_agent_id {
            return Err(ApplyError::InvalidSignature(format!(
                "authority_agent_id {} != derived {}",
                self.authority_agent_id, derived
            )));
        }
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad sig hex: {e}")))?;
        let sig = MlDsaSignature::from_bytes(&sig_bytes)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad sig: {e:?}")))?;
        if verify_with_ml_dsa(&pubkey, &self.signable_bytes(), &sig).is_ok() {
            return Ok(());
        }
        if self.metadata_topic.is_none()
            && verify_with_ml_dsa(&pubkey, &self.signable_bytes_legacy(), &sig).is_ok()
        {
            return Ok(());
        }
        Err(ApplyError::InvalidSignature(
            "card verify failed for both v2 and legacy domains".into(),
        ))
    }

    /// Seconds-since-epoch convenience for default card TTL.
    #[must_use]
    pub fn default_ttl_secs() -> u64 {
        DEFAULT_CARD_TTL_SECS
    }

    /// Helper: decide whether `other` supersedes `self` for the same `group_id`.
    /// Higher `revision` wins; on ties the higher `issued_at` wins. Caller
    /// must have verified both signatures first.
    #[must_use]
    pub fn supersedes(&self, other: &GroupCard) -> bool {
        if self.group_id != other.group_id {
            return false;
        }
        self.revision > other.revision
            || (self.revision == other.revision && self.issued_at > other.issued_at)
    }

    /// True when the card carries an authority signature. This does not
    /// verify it: callers run [`Self::verify_signature`] first.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty() && !self.authority_public_key.is_empty()
    }

    /// Unix milliseconds after which this card is no longer live. A card
    /// without a usable `expires_at` lives one default TTL from `issued_at`.
    #[must_use]
    pub fn expiry_millis(&self) -> u64 {
        if self.expires_at > self.issued_at {
            self.expires_at
        } else {
            self.issued_at
                .saturating_add(Self::default_ttl_secs().saturating_mul(1_000))
        }
    }

    /// Decide whether this card can take the place of `cached`, the live
    /// cached card for the same group.
    ///
    /// A cached card is replaced only by its own authority:
    /// - a card signed with the same key, in normal revision order;
    /// - a card from an agent in `roster_admins` when the cached signer is
    ///   not in it (`roster_admins` holds the active admins of this node's
    ///   own roster for the group, and is empty for a non-member);
    /// - a card from the owner that `cached` names, when `cached` was signed
    ///   by another agent.
    ///
    /// A signed card replaces an unsigned legacy card; an unsigned card never
    /// replaces a signed one. The top revision is always refused, and a
    /// revision step above [`MAX_CARD_REVISION_STEP`] is refused when normal
    /// order applies. The caller removes expired cards from the cache first,
    /// and verifies the signature of a signed card first.
    #[must_use]
    pub fn replacement_verdict(
        &self,
        cached: Option<&GroupCard>,
        roster_admins: &BTreeSet<String>,
    ) -> CardReplacement {
        self.authority_verdict(cached, roster_admins, |card, cached| {
            card.supersedes(cached)
        })
    }

    /// Like [`Self::replacement_verdict`], for a withdrawal card that would
    /// remove `cached`. In normal order an equal revision with an equal or
    /// later `issued_at` also removes, as before.
    #[must_use]
    pub fn withdrawal_verdict(
        &self,
        cached: Option<&GroupCard>,
        roster_admins: &BTreeSet<String>,
    ) -> CardReplacement {
        self.authority_verdict(cached, roster_admins, |card, cached| {
            card.revision > cached.revision
                || (card.revision == cached.revision && card.issued_at >= cached.issued_at)
        })
    }

    fn authority_verdict(
        &self,
        cached: Option<&GroupCard>,
        roster_admins: &BTreeSet<String>,
        is_newer: impl Fn(&GroupCard, &GroupCard) -> bool,
    ) -> CardReplacement {
        if self.revision == u64::MAX {
            return CardReplacement::Refused(CardRefusal::RevisionCeiling);
        }
        let Some(cached) = cached else {
            return CardReplacement::Replace;
        };
        if self.group_id != cached.group_id {
            return CardReplacement::Stale;
        }
        let in_order = || {
            if self.revision > cached.revision.saturating_add(MAX_CARD_REVISION_STEP) {
                CardReplacement::Refused(CardRefusal::RevisionStep)
            } else if is_newer(self, cached) {
                CardReplacement::Replace
            } else {
                CardReplacement::Stale
            }
        };
        match (self.is_signed(), cached.is_signed()) {
            (false, true) => return CardReplacement::Refused(CardRefusal::Authority),
            (true, false) => return CardReplacement::Replace,
            (false, false) => return in_order(),
            (true, true) => {}
        }
        if self.authority_agent_id == cached.authority_agent_id
            && self
                .authority_public_key
                .eq_ignore_ascii_case(&cached.authority_public_key)
        {
            return in_order();
        }
        let signer_in_roster = roster_admins.contains(&self.authority_agent_id);
        let cached_in_roster = roster_admins.contains(&cached.authority_agent_id);
        match (signer_in_roster, cached_in_roster) {
            (true, true) => return in_order(),
            (true, false) => return CardReplacement::Replace,
            (false, true) => return CardReplacement::Refused(CardRefusal::Authority),
            (false, false) => {}
        }
        if !cached.owner_agent_id.is_empty()
            && self
                .authority_agent_id
                .eq_ignore_ascii_case(&cached.owner_agent_id)
        {
            return CardReplacement::Replace;
        }
        CardReplacement::Refused(CardRefusal::Authority)
    }
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::policy::{
        GroupAdmission, GroupConfidentiality, GroupDiscoverability, GroupReadAccess,
        GroupWriteAccess,
    };

    fn sample_summary() -> GroupPolicySummary {
        GroupPolicySummary {
            discoverability: GroupDiscoverability::PublicDirectory,
            admission: GroupAdmission::RequestAccess,
            confidentiality: GroupConfidentiality::MlsEncrypted,
            read_access: GroupReadAccess::MembersOnly,
            write_access: GroupWriteAccess::MembersOnly,
        }
    }

    fn sample_card() -> GroupCard {
        GroupCard {
            group_id: "abcd".repeat(16),
            name: "Test".into(),
            description: "desc".into(),
            avatar_url: None,
            banner_url: None,
            tags: vec!["rust".into()],
            policy_summary: sample_summary(),
            owner_agent_id: "ff".repeat(32),
            admin_count: 1,
            member_count: 5,
            created_at: 0,
            updated_at: 0,
            request_access_enabled: true,
            metadata_topic: None,
            revision: 1,
            state_hash: "sh-1".into(),
            prev_state_hash: None,
            issued_at: 100,
            expires_at: 200,
            authority_agent_id: String::new(),
            authority_public_key: String::new(),
            withdrawn: false,
            signature: String::new(),
        }
    }

    #[test]
    fn card_roundtrip() {
        let c = sample_card();
        let json = serde_json::to_string(&c).unwrap();
        let c2: GroupCard = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn card_sign_and_verify_roundtrip() {
        let kp = AgentKeypair::generate().unwrap();
        let mut c = sample_card();
        c.sign(&kp).unwrap();
        assert!(!c.signature.is_empty());
        c.verify_signature().unwrap();
    }

    #[test]
    fn card_signature_detects_tamper() {
        let kp = AgentKeypair::generate().unwrap();
        let mut c = sample_card();
        c.sign(&kp).unwrap();

        let mut bad = c.clone();
        bad.name = "Tampered".into();
        assert!(bad.verify_signature().is_err());

        let mut bad = c.clone();
        bad.revision = 999;
        assert!(bad.verify_signature().is_err());

        let mut bad = c.clone();
        bad.withdrawn = true;
        assert!(bad.verify_signature().is_err());
    }

    #[test]
    fn card_signature_rejects_wrong_authority() {
        let kp1 = AgentKeypair::generate().unwrap();
        let kp2 = AgentKeypair::generate().unwrap();
        let mut c = sample_card();
        c.sign(&kp1).unwrap();
        // Swap the claimed agent_id to kp2 — mismatch must be detected.
        c.authority_agent_id = hex::encode(kp2.agent_id().as_bytes());
        assert!(c.verify_signature().is_err());
    }

    #[test]
    fn supersedes_by_revision() {
        let kp = AgentKeypair::generate().unwrap();
        let mut lo = sample_card();
        lo.revision = 1;
        lo.sign(&kp).unwrap();
        let mut hi = sample_card();
        hi.revision = 2;
        hi.sign(&kp).unwrap();
        assert!(hi.supersedes(&lo));
        assert!(!lo.supersedes(&hi));
    }

    #[test]
    fn supersedes_by_issued_at_on_revision_tie() {
        let kp = AgentKeypair::generate().unwrap();
        let mut a = sample_card();
        a.revision = 1;
        a.issued_at = 100;
        a.sign(&kp).unwrap();
        let mut b = sample_card();
        b.revision = 1;
        b.issued_at = 200;
        b.sign(&kp).unwrap();
        assert!(b.supersedes(&a));
        assert!(!a.supersedes(&b));
    }

    #[test]
    fn supersedes_requires_same_group_id() {
        let kp = AgentKeypair::generate().unwrap();
        let mut a = sample_card();
        a.revision = 1;
        a.sign(&kp).unwrap();
        let mut b = sample_card();
        b.revision = 2;
        b.group_id = "different".into();
        b.sign(&kp).unwrap();
        assert!(!b.supersedes(&a));
    }

    #[test]
    fn unsigned_card_verify_fails() {
        let c = sample_card();
        assert!(c.verify_signature().is_err());
    }

    #[test]
    fn metadata_topic_is_bound_in_v2_signature() {
        let kp = AgentKeypair::generate().unwrap();
        let mut c = sample_card();
        c.metadata_topic = Some("x0x.group.test.meta".into());
        c.sign(&kp).unwrap();
        c.verify_signature().unwrap();

        let mut bad = c.clone();
        bad.metadata_topic = Some("x0x.group.evil.meta".into());
        assert!(bad.verify_signature().is_err());
    }

    #[test]
    fn legacy_card_without_metadata_topic_still_verifies() {
        let kp = AgentKeypair::generate().unwrap();
        let mut c = sample_card();
        c.authority_agent_id = hex::encode(kp.agent_id().as_bytes());
        c.authority_public_key = hex::encode(kp.public_key().as_bytes());
        let sig = sign_with_ml_dsa(kp.secret_key(), &c.signable_bytes_legacy()).unwrap();
        c.signature = hex::encode(sig.as_bytes());
        c.verify_signature().unwrap();
    }
}
