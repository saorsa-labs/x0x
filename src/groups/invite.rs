//! Signed invite tokens for group membership.
//!
//! Invite tokens are one-time links that allow one agent to join a group.
//! Today admission is authenticated by the invite secret + join handshake;
//! the inviter records the secret locally, enforces expiry/role caps, consumes
//! it on first successful use, then publishes an authority-signed membership
//! commit. The `signature` field is retained as future-facing/vestigial
//! metadata and is not currently enforced on the wire.

use crate::groups::policy::GroupPolicy;
use crate::groups::GroupMember;
use crate::identity::AgentId;
use crate::mls::SecureGroupPlane;
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default invite expiry: 7 days in seconds.
pub const DEFAULT_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;

/// Safe upper bound on an encoded invite link.
///
/// The gossip-inbox DM path caps user payloads at
/// [`crate::dm::MAX_PAYLOAD_BYTES`] (49 152). Invite links travel as the bulk
/// of the `group_join` cmd-DM, so a link near that cap used to be rejected at
/// the sender with an opaque `envelope_construction` 400 (issue #188; now a
/// truthful `payload_too_large` 413). 40 KiB leaves room for the cmd-DM
/// envelope wrapper while flagging roster growth at the mint site instead of
/// as a mysterious cross-node rejection. See issues #188 / #205.
pub const INVITE_LINK_MAX_BYTES: usize = 40 * 1024;

/// A signed invite token for joining a group.
///
/// Tokens are serialized to base64url for sharing via email, chat, QR codes, etc.
/// Each token is accepted at most once by the inviter that minted it.
/// The format is: `x0x://invite/<base64url(json(SignedInvite))>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInvite {
    /// MLS group ID (hex-encoded).
    pub group_id: String,
    /// Stable D.3 group_id, if known.
    #[serde(default)]
    pub stable_group_id: Option<String>,
    /// Authority-created timestamp for the group.
    #[serde(default)]
    pub group_created_at: Option<u64>,
    /// Human-readable group name.
    pub group_name: String,
    /// Human-readable group description.
    #[serde(default)]
    pub group_description: Option<String>,
    /// Full policy snapshot used to seed the joiner's local GroupInfo.
    #[serde(default)]
    pub policy: Option<GroupPolicy>,
    /// Authority genesis nonce so invite-joined peers reconstruct the same
    /// `GroupGenesis` payload, not just the same stable group id.
    #[serde(default)]
    pub genesis_creation_nonce: Option<String>,
    /// Authority state revision at invite creation time. Joiners seed their
    /// local state from this so later signed membership commits validate
    /// against the authority's actual state-chain frontier.
    #[serde(default)]
    pub base_state_revision: Option<u64>,
    /// Authority state hash at invite creation time.
    #[serde(default)]
    pub base_state_hash: Option<String>,
    /// Authority active roster snapshot at invite creation time. Needed because
    /// state-hash validation commits to the roster root; a joiner stub with
    /// only the owner cannot validate later membership commits.
    #[serde(default)]
    pub base_members_v2: Option<BTreeMap<String, GroupMember>>,
    /// Authority previous state hash at invite creation time.
    #[serde(default)]
    pub base_prev_state_hash: Option<String>,
    /// #458 r3: the authority's Home metadata at the base revision. The
    /// base `state_hash` commits to its digest (`home_digest` rides the
    /// public-meta hash), and the joiner's stub cannot reconstruct what it
    /// never received — without this field a Home-group stub can NEVER
    /// recompute the base hash, so its `MemberAdded` apply fails
    /// `StateHashMismatch` even when the chain links perfectly. None on
    /// legacy invites (and non-Home groups) hashes exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_home: Option<crate::groups::HomeMetadata>,
    /// Secure-group crypto plane at invite creation time. Missing means legacy
    /// pre-ADR-0012 invite; treat as GSS-compatible for backwards compatibility.
    #[serde(default)]
    pub secure_plane: Option<SecureGroupPlane>,
    /// Authority's base secret epoch at invite creation time.
    #[serde(default)]
    pub base_secret_epoch: Option<u64>,
    /// Authority's base security binding at invite creation time.
    #[serde(default)]
    pub base_security_binding: Option<String>,
    /// Agent ID of the inviter (hex-encoded).
    pub inviter: String,
    /// One-time invite secret (32 bytes, hex-encoded).
    /// Used to authenticate the join handshake and consumed by the inviter
    /// when it publishes the authoritative membership commit.
    pub invite_secret: String,
    /// Unix seconds when this invite was created.
    pub created_at: u64,
    /// Unix seconds when this invite expires (0 = never).
    pub expires_at: u64,
    /// Optional future-facing ML-DSA-65 signature over the invite fields
    /// (hex-encoded). Currently not validated by the join flow.
    #[serde(default)]
    pub signature: String,

    // ── #469 InviteV4 (authenticated invites) ───────────────────────────
    /// Wire format version. `0` (absent) is the legacy sentinel; v4
    /// constructors emit `4`. The joiner refuses anything below 4 with a
    /// typed `invite_unsigned` (issue #469).
    #[serde(default)]
    pub version: u8,
    /// #469: exact `GroupPublicMeta` snapshot at the base revision — the
    /// precise input of `compute_public_meta_hash`, so the joiner can
    /// recompute the base state hash bit-for-bit (previously tags, avatar
    /// and banner were silently dropped and non-default metadata could
    /// never round-trip).
    #[serde(default)]
    pub public_meta: Option<crate::groups::state_commit::GroupPublicMeta>,
    /// #469: the roster PROJECTION at the base revision — exactly what
    /// `roster_root_of_projection` hashes (role, state, TreeKEM key-package
    /// hash, certificate digest). Replaces `base_members_v2` for v4;
    /// certificate BYTES are not carried (joiners hydrate them later via
    /// the announce/discovery cache, matching the authoritative digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_roster: Option<BTreeMap<String, crate::groups::state_commit::RosterMemberSnapshot>>,
    /// #469: the agent this invite was minted for, if addressed. The
    /// authority compares it with `MemberJoined.member_agent_id` before
    /// consuming the secret (issue #469/A4); any other agent's join is
    /// refused with a typed `invite_not_addressed_to_me`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_joiner: Option<String>,
    /// #469: explicit signed creator agent id (hex). Replaces the
    /// best-effort `added_by`/timestamp derivation for v4 invites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    /// #469 (v6 E4): the inviter's ML-DSA-65 public key, INLINE and
    /// self-authenticating — `AgentId::from_public_key` of these bytes must
    /// equal `inviter` (the id IS SHA-256 of the key). Carried inside the
    /// signed view, so a swapped key breaks the inviter signature anyway;
    /// the id check makes the failure typed and immediate. Base64.
    #[serde(default)]
    pub inviter_public_key_b64: String,
    /// #469 (v6 E4): the admission owner's ML-DSA-65 USER public key for
    /// owner-axis invites, INLINE and self-authenticating against
    /// `policy.admission`'s OwnerCertified user id. Base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_public_key_b64: Option<String>,
    /// #469: ML-DSA-65 signature by the INVITER's agent key over the v4
    /// canonical bytes (base64). Required on every v4 invite; verified
    /// against the inline key above after its id binding.
    #[serde(default)]
    pub inviter_signature_b64: String,
    /// #469: ML-DSA-65 countersignature by the OWNER USER key over the v4
    /// canonical bytes (base64). Present iff the policy admission carries
    /// an OwnerCertified axis; required by the Home-join mode pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_countersignature_b64: Option<String>,
}

// ─── #469 InviteV4: signing domains, caps, signed view ───────────────────

/// Current invite wire-format version (#469).
pub const INVITE_VERSION_V4: u8 = 4;

/// Domain prefix for the v4 canonical signed bytes.
pub const INVITE_V4_CANONICAL_DOMAIN: &[u8] = b"x0x.invite.v4\0";
/// Domain prefix for the inviter agent-key signature over the canonical
/// bytes.
pub const INVITE_V4_INVITER_DOMAIN: &[u8] = b"x0x.invite.v4.inviter\0";
/// Domain prefix for the owner user-key countersignature over the
/// canonical bytes.
pub const INVITE_V4_OWNER_DOMAIN: &[u8] = b"x0x.invite.v4.owner\0";

// ─── D5: per-field caps ──────────────────────────────────────────────────
//
// A roster-entry count alone cannot bound the encoded link while metadata
// strings are unbounded input, so every non-roster field is capped at mint
// AND verified at join. The FINAL encoded-size check (`encode_link`)
// remains authoritative regardless of these caps.

/// Maximum `group_name` length (#469 D5).
pub const INVITE_MAX_GROUP_NAME: usize = 128;
/// Maximum `group_description` length (#469 D5).
pub const INVITE_MAX_GROUP_DESCRIPTION: usize = 1024;
/// Maximum number of public-meta tags (#469 D5).
pub const INVITE_MAX_TAGS: usize = 16;
/// Maximum length of one public-meta tag (#469 D5).
pub const INVITE_MAX_TAG_LEN: usize = 32;
/// Maximum `avatar_url` / `banner_url` length (#469 D5).
pub const INVITE_MAX_URL_LEN: usize = 512;
/// Maximum roster entries in a v4 invite (#469 D5 / v7 F4). DERIVED from
/// the final-encoder worst-case fixture (all string caps simultaneous,
/// two inline keys + two signatures, N certificate-bearing projection
/// entries with max-length ids/hashes) against BOTH the 40,960 link
/// safety budget and the 49,152 DM ceiling — the pinned test fails if
/// this constant is raised above the derived maximum. The final
/// encoded-size check remains authoritative regardless.
pub const MAX_INVITE_ROSTER_ENTRIES: usize = 32;

/// Typed refusal reasons for v4 invite verification (#469 A2). These are
/// the `reason` strings counted by `invites_refused{reason}` and surfaced
/// as typed 4xx errors by the join route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteRefusal {
    /// `version < 4` (including the absent-field legacy sentinel).
    Unsigned,
    /// The vestigial legacy `signature` field is non-empty on a v4 invite.
    SignatureInvalid,
    /// The inviter signature does not verify under the inline inviter key.
    InviterSignatureInvalid,
    /// `AgentId::from_public_key(inviter_public_key_b64) != inviter`.
    InviterKeyMismatch,
    /// The inviter agent key is in the local revocation set.
    InviterKeyRevoked,
    /// The owner countersignature does not verify under the inline owner
    /// key, or the inline owner key fails its `UserId` binding.
    OwnerCountersignatureInvalid,
    /// An owner-axis invite carries no owner countersignature.
    OwnerCountersignatureMissing,
    /// A D5 field cap or structural equality rule failed (duplicated meta
    /// or home-digest mismatch).
    Malformed,
}

impl InviteRefusal {
    /// The stable wire/diagnostic string for this refusal.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unsigned => "invite_unsigned",
            Self::SignatureInvalid => "invite_signature_invalid",
            Self::InviterSignatureInvalid => "invite_signature_invalid",
            Self::InviterKeyMismatch => "inviter_key_mismatch",
            Self::InviterKeyRevoked => "inviter_key_revoked",
            Self::OwnerCountersignatureInvalid => "invite_owner_countersignature_invalid",
            Self::OwnerCountersignatureMissing => "invite_owner_countersignature_missing",
            Self::Malformed => "invite_malformed",
        }
    }
}

/// The FROZEN v4 signed view: every semantically loadable field of
/// [`SignedInvite`] EXCEPT the three signature outputs (`signature`,
/// `inviter_signature_b64`, `owner_countersignature_b64`) and the legacy
/// fat roster (`base_members_v2` — v4 carries the projection instead and
/// the constructor refuses a non-empty legacy roster).
///
/// Field ORDER is frozen and pinned by a canonical-byte vector test;
/// postcard is deterministic for this value graph, so any reorder,
/// insert, or type change changes the canonical bytes.
///
/// #469 v6 E1: the constructor [`InviteSignedViewV4::from_invite`]
/// destructures the WHOLE `SignedInvite` by name — adding a field to
/// `SignedInvite` without routing it through the view is a compile
/// error, so nothing can ride unsigned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InviteSignedViewV4 {
    /// Wire version (always 4 on minted invites; the sentinel 0 never
    /// reaches a signed view).
    pub version: u8,
    /// MLS group id (hex). Must equal `stable_group_id` (E1).
    pub group_id: String,
    /// Stable D.3 group id (hex).
    pub stable_group_id: String,
    /// Authority-created timestamp.
    pub group_created_at: u64,
    /// Human-readable name; must equal `public_meta.name` (D1).
    pub group_name: String,
    /// Human-readable description; must equal `public_meta.description`.
    /// Option-preserving (r1 Codex 8): None and Some("") are DISTINCT
    /// signed states — postcard encodes the Option tag.
    pub group_description: Option<String>,
    /// Authority genesis nonce (Option-preserving, r1 Codex 8).
    pub genesis_creation_nonce: Option<String>,
    /// Explicit signed creator agent id (hex).
    pub creator: String,
    /// Exact public-metadata snapshot (tags/avatar/banner/home_digest).
    pub public_meta: crate::groups::state_commit::GroupPublicMeta,
    /// The `HomeMetadata` preimage; `compute_home_digest(base_home)` must
    /// equal `public_meta.home_digest` when the latter is present (D1).
    pub base_home: Option<crate::groups::HomeMetadata>,
    /// Secure-group crypto plane at the base revision.
    pub secure_plane: crate::mls::SecureGroupPlane,
    /// Full policy snapshot.
    pub policy: crate::groups::policy::GroupPolicy,
    /// Base state revision.
    pub base_state_revision: u64,
    /// Base state hash (hex).
    pub base_state_hash: String,
    /// Base previous state hash (hex; None at genesis — Option-preserving,
    /// r1 Codex 8).
    pub base_prev_state_hash: Option<String>,
    /// The roster PROJECTION at the base revision.
    pub base_roster: BTreeMap<String, crate::groups::state_commit::RosterMemberSnapshot>,
    /// Base secret epoch.
    pub base_secret_epoch: u64,
    /// Base security binding (None when absent — Option-preserving, r1
    /// Codex 8).
    pub base_security_binding: Option<String>,
    /// Inviter agent id (hex).
    pub inviter: String,
    /// Inviter ML-DSA-65 public key (base64) — self-authenticating via
    /// `AgentId::from_public_key == inviter` (v6 E4).
    pub inviter_public_key_b64: String,
    /// Owner ML-DSA-65 USER public key (base64) on owner-axis invites —
    /// self-authenticating via the policy's OwnerCertified user id.
    pub owner_public_key_b64: Option<String>,
    /// BLAKE3-256 of the strictly decoded 32 raw bytes of the hex
    /// `invite_secret` — NOT of the hex text (v3 review item 1).
    pub secret_hash: [u8; 32],
    /// Mint time (unix seconds).
    pub created_at: u64,
    /// Expiry (unix seconds; 0 = never).
    pub expires_at: u64,
    /// Intended joiner agent id (hex), when addressed.
    pub intended_joiner: Option<String>,
}

impl InviteSignedViewV4 {
    /// Build the signed view from a whole invite. E1 compile-time
    /// exhaustiveness guard: EVERY `SignedInvite` field is destructured
    /// by name (no `..`) and consumed into a view field or an explicit
    /// refusal — adding a field to `SignedInvite` without extending this
    /// function is a compile error.
    ///
    /// # Errors
    ///
    /// Returns [`InviteRefusal::Unsigned`] when a legacy fat roster is
    /// present (v4 carries the projection) or any v4-required field is
    /// missing, and [`InviteRefusal::Malformed`] when a duplicated-meta
    /// equality rule fails.
    pub fn from_invite(invite: &SignedInvite) -> Result<Self, InviteRefusal> {
        // E1: exhaustive destructure — no `..`. The three signature
        // outputs and the legacy fat roster are consumed by name into
        // explicit refusals; everything else lands in the view.
        let SignedInvite {
            group_id,
            stable_group_id,
            group_created_at,
            group_name,
            group_description,
            policy,
            genesis_creation_nonce,
            base_state_revision,
            base_state_hash,
            base_members_v2,
            base_prev_state_hash,
            base_home,
            secure_plane,
            base_secret_epoch,
            base_security_binding,
            inviter,
            invite_secret,
            created_at,
            expires_at,
            signature: _legacy_signature,
            version,
            public_meta,
            base_roster,
            intended_joiner,
            creator,
            inviter_public_key_b64,
            owner_public_key_b64,
            inviter_signature_b64: _inviter_signature,
            owner_countersignature_b64: _owner_countersignature,
        } = invite;

        if *version != INVITE_VERSION_V4 {
            return Err(InviteRefusal::Unsigned);
        }
        // v4 carries the projection; a fat legacy roster alongside is a
        // malformed mint (and would ride unsigned).
        if base_members_v2.is_some() {
            return Err(InviteRefusal::Unsigned);
        }
        let stable_group_id = stable_group_id.clone().ok_or(InviteRefusal::Unsigned)?;
        // E1: the MLS/stable-id invariant is part of the signed contract.
        if *group_id != stable_group_id {
            return Err(InviteRefusal::Malformed);
        }
        let group_created_at = (*group_created_at).ok_or(InviteRefusal::Unsigned)?;
        let base_state_revision = (*base_state_revision).ok_or(InviteRefusal::Unsigned)?;
        let base_state_hash = base_state_hash.clone().ok_or(InviteRefusal::Unsigned)?;
        let base_roster = base_roster.clone().ok_or(InviteRefusal::Unsigned)?;
        let base_secret_epoch = (*base_secret_epoch).ok_or(InviteRefusal::Unsigned)?;
        let public_meta = public_meta.clone().ok_or(InviteRefusal::Unsigned)?;
        let creator = creator.clone().ok_or(InviteRefusal::Unsigned)?;
        if inviter_public_key_b64.is_empty() {
            return Err(InviteRefusal::Unsigned);
        }

        // D1 equality rules: duplicated metadata must agree, and the Home
        // preimage must hash to the committed digest.
        if group_name != &public_meta.name {
            return Err(InviteRefusal::Malformed);
        }
        if group_description.as_deref().unwrap_or("") != public_meta.description {
            return Err(InviteRefusal::Malformed);
        }
        if let Some(home) = base_home.as_ref() {
            let digest = crate::groups::state_commit::compute_home_digest(home);
            if public_meta.home_digest.as_deref() != Some(digest.as_str()) {
                return Err(InviteRefusal::Malformed);
            }
        } else if public_meta.home_digest.is_some() {
            return Err(InviteRefusal::Malformed);
        }

        // Raw-secret normalization: strictly 32 bytes after hex decode.
        // r1 (Codex 8): STRICT 64-hex — no trimming; a padded secret is
        // malformed, not normalized.
        if invite_secret.len() != 64 || hex::decode(invite_secret.as_bytes()).is_err() {
            return Err(InviteRefusal::Malformed);
        }
        let secret_bytes = hex::decode(invite_secret.as_bytes())
            .map_err(|_| InviteRefusal::Malformed)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).map_err(|_| InviteRefusal::Malformed))?;
        let secret_hash = *blake3::hash(&secret_bytes).as_bytes();

        Ok(Self {
            version: *version,
            group_id: group_id.clone(),
            stable_group_id,
            group_created_at,
            group_name: group_name.clone(),
            group_description: group_description.clone(),
            genesis_creation_nonce: genesis_creation_nonce.clone(),
            creator,
            public_meta,
            base_home: base_home.clone(),
            secure_plane: secure_plane.unwrap_or(crate::mls::SecureGroupPlane::Gss),
            policy: policy.clone().unwrap_or_default(),
            base_state_revision,
            base_state_hash,
            base_prev_state_hash: base_prev_state_hash.clone(),
            base_roster,
            base_secret_epoch,
            base_security_binding: base_security_binding.clone(),
            inviter: inviter.clone(),
            inviter_public_key_b64: inviter_public_key_b64.clone(),
            owner_public_key_b64: owner_public_key_b64.clone(),
            secret_hash,
            created_at: *created_at,
            expires_at: *expires_at,
            intended_joiner: intended_joiner.clone(),
        })
    }

    /// Canonical signed bytes: `INVITE_V4_CANONICAL_DOMAIN ‖
    /// postcard(view)`. Deterministic; pinned by a byte-vector test.
    ///
    /// # Errors
    ///
    /// Returns the postcard error on serialization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        let mut out = Vec::with_capacity(INVITE_V4_CANONICAL_DOMAIN.len() + 1024);
        out.extend_from_slice(INVITE_V4_CANONICAL_DOMAIN);
        out.extend_from_slice(&postcard::to_stdvec(self)?);
        Ok(out)
    }
}
/// Error returned when an encoded invite link exceeds the safe DM budget.
///
/// Carries the measured and limit sizes so callers can surface a structured
/// error at the mint site (issue #205) instead of letting the link fail later
/// at `/direct/send` with `payload_too_large` (issue #188 — formerly an
/// opaque `envelope_construction` 400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteLinkTooLarge {
    /// Measured encoded link length in bytes.
    pub actual: usize,
    /// Budget enforced by [`INVITE_LINK_MAX_BYTES`].
    pub limit: usize,
}

impl std::fmt::Display for InviteLinkTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "encoded invite link ({} B) exceeds safe DM budget ({} B); \
             strip key packages or slim the roster before minting",
            self.actual, self.limit
        )
    }
}

impl std::error::Error for InviteLinkTooLarge {}

impl SignedInvite {
    /// Create a new invite (without signature — call `sign()` separately).
    ///
    /// # Arguments
    ///
    /// * `group_id` - MLS group ID (hex).
    /// * `group_name` - Human-readable group name.
    /// * `inviter` - Inviter's agent ID.
    /// * `expiry_secs` - Seconds until expiry (0 = never).
    #[must_use]
    pub fn new(group_id: String, group_name: String, inviter: &AgentId, expiry_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate random invite secret
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut secret_bytes);

        let expires_at = if expiry_secs > 0 {
            now + expiry_secs
        } else {
            0
        };

        Self {
            group_id,
            stable_group_id: None,
            group_created_at: None,
            group_name,
            group_description: None,
            policy: None,
            genesis_creation_nonce: None,
            base_state_revision: None,
            base_state_hash: None,
            base_members_v2: None,
            base_prev_state_hash: None,
            base_home: None,
            secure_plane: None,
            base_secret_epoch: None,
            base_security_binding: None,
            inviter: hex::encode(inviter.as_bytes()),
            invite_secret: hex::encode(secret_bytes),
            created_at: now,
            expires_at,
            signature: String::new(),
            version: INVITE_VERSION_V4,
            public_meta: None,
            base_roster: None,
            intended_joiner: None,
            creator: None,
            inviter_public_key_b64: String::new(),
            owner_public_key_b64: None,
            inviter_signature_b64: String::new(),
            owner_countersignature_b64: None,
        }
    }

    /// Get the canonical bytes that would be signed if invite signatures are
    /// enforced in the future.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"x0x.invite.v3|");
        data.extend_from_slice(self.group_id.as_bytes());
        data.extend_from_slice(self.stable_group_id.as_deref().unwrap_or("").as_bytes());
        data.extend_from_slice(&self.group_created_at.unwrap_or_default().to_le_bytes());
        data.extend_from_slice(self.group_name.as_bytes());
        data.extend_from_slice(self.group_description.as_deref().unwrap_or("").as_bytes());
        let policy_json = serde_json::to_vec(&self.policy).unwrap_or_default();
        data.extend_from_slice(&policy_json);
        data.extend_from_slice(
            self.genesis_creation_nonce
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        data.extend_from_slice(&self.base_state_revision.unwrap_or_default().to_le_bytes());
        data.extend_from_slice(self.base_state_hash.as_deref().unwrap_or("").as_bytes());
        let members_json = serde_json::to_vec(&self.base_members_v2).unwrap_or_default();
        data.extend_from_slice(&members_json);
        data.extend_from_slice(
            self.base_prev_state_hash
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        // #458 r3: base_home is integrity-covered — a stripped/ swapped
        // Home-metadata claim breaks the invite signature. `None` hashes
        // as empty, byte-identical to every legacy invite.
        let home_json = serde_json::to_vec(&self.base_home).unwrap_or_default();
        data.extend_from_slice(&home_json);
        if let Some(secure_plane) = self.secure_plane {
            let secure_plane_json = serde_json::to_vec(&secure_plane).unwrap_or_default();
            data.extend_from_slice(&secure_plane_json);
        }
        data.extend_from_slice(&self.base_secret_epoch.unwrap_or_default().to_le_bytes());
        data.extend_from_slice(
            self.base_security_binding
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        data.extend_from_slice(self.inviter.as_bytes());
        data.extend_from_slice(self.invite_secret.as_bytes());
        data.extend_from_slice(&self.created_at.to_le_bytes());
        data.extend_from_slice(&self.expires_at.to_le_bytes());
        data
    }

    /// Check if this invite has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // Never expires
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Check if the signature field is populated.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    /// Derive best-effort historical creator provenance from the invite's
    /// embedded base-state roster snapshot.
    ///
    /// `inviter` is unsigned routing metadata. Current invite-join handling must
    /// not treat it as creator provenance. The derived value seeds the display
    /// `creator` / genesis field only and is never consulted for authority.
    /// This is not a tamper-evident or exhaustive historical reconstruction:
    /// unusual roster shapes (for example, a creator re-added with
    /// `added_by = Some`) may not be represented by the `added_by.is_none()`
    /// filter. Because creator identity is non-authority metadata, this helper
    /// intentionally keeps the derivation simple instead of adding tiebreaking
    /// logic for unusual history.
    ///
    /// # Errors
    ///
    /// Returns an error when the invite has no base roster snapshot, no seeded
    /// base-state member entry, or the derived member id is not a 32-byte hex
    /// agent id. Legacy/missing-base invites are rejected by the current join
    /// path rather than falling back to unsigned `inviter` metadata.
    pub fn creator_agent_id_from_base_state(&self) -> Result<String, String> {
        let base_members = self.base_members_v2.as_ref().ok_or_else(|| {
            "invite missing base member snapshot; cannot derive creator provenance".to_string()
        })?;

        let mut candidates: Vec<_> = base_members
            .iter()
            .filter(|(agent_id, member)| {
                member.added_by.is_none() && member.agent_id.eq_ignore_ascii_case(agent_id)
            })
            .collect();

        if let Some(created_at) = self.group_created_at {
            let created_at_candidates: Vec<_> = candidates
                .iter()
                .copied()
                .filter(|(_, member)| member.joined_at == created_at)
                .collect();
            if !created_at_candidates.is_empty() {
                candidates = created_at_candidates;
            }
        }

        let (creator_hex, _) = candidates
            .into_iter()
            .min_by(|(left_id, left), (right_id, right)| {
                left.joined_at
                    .cmp(&right.joined_at)
                    .then_with(|| left.updated_at.cmp(&right.updated_at))
                    .then_with(|| left_id.cmp(right_id))
            })
            .ok_or_else(|| {
                "invite base member snapshot has no seeded creator provenance".to_string()
            })?;

        let creator_bytes =
            hex::decode(creator_hex).map_err(|e| format!("invalid base-state creator hex: {e}"))?;
        if creator_bytes.len() != crate::identity::PEER_ID_LENGTH {
            return Err(format!(
                "invalid base-state creator length: expected 32 bytes, got {}",
                creator_bytes.len()
            ));
        }

        Ok(creator_hex.to_string())
    }

    /// D5: validate every capped field. Returns the first violation.
    #[must_use]
    pub fn v4_field_caps_violation(&self) -> Option<(&'static str, usize)> {
        if self.group_name.len() > INVITE_MAX_GROUP_NAME {
            return Some(("group_name", self.group_name.len()));
        }
        if let Some(description) = self.group_description.as_ref() {
            if description.len() > INVITE_MAX_GROUP_DESCRIPTION {
                return Some(("group_description", description.len()));
            }
        }
        if let Some(meta) = self.public_meta.as_ref() {
            if meta.name.len() > INVITE_MAX_GROUP_NAME {
                return Some(("public_meta.name", meta.name.len()));
            }
            if meta.description.len() > INVITE_MAX_GROUP_DESCRIPTION {
                return Some(("public_meta.description", meta.description.len()));
            }
            if meta.tags.len() > INVITE_MAX_TAGS {
                return Some(("public_meta.tags", meta.tags.len()));
            }
            if let Some(len) = meta.tags.iter().map(String::len).max() {
                if len > INVITE_MAX_TAG_LEN {
                    return Some(("public_meta.tag_len", len));
                }
            }
            for (field, url) in [
                ("public_meta.avatar_url", meta.avatar_url.as_deref()),
                ("public_meta.banner_url", meta.banner_url.as_deref()),
            ] {
                if let Some(url) = url {
                    if url.len() > INVITE_MAX_URL_LEN {
                        return Some((field, url.len()));
                    }
                }
            }
        }
        if let Some(roster) = self.base_roster.as_ref() {
            if roster.len() > MAX_INVITE_ROSTER_ENTRIES {
                return Some(("base_roster", roster.len()));
            }
        }
        None
    }

    /// Sign this v4 invite with the inviter's agent key and, for
    /// owner-axis policies, the owner's USER key (#469).
    ///
    /// Populates `inviter_public_key_b64`, `inviter_signature_b64` and
    /// (when `owner_kp` is supplied) `owner_public_key_b64` +
    /// `owner_countersignature_b64`. The view construction enforces the
    /// D1/E1 structural rules (projection-only roster, id invariants,
    /// duplicated-meta equality) BEFORE anything is signed.
    ///
    /// # Errors
    ///
    /// Returns the refusal reason when the invite is not a well-formed
    /// v4 candidate, or a signing error string on ML-DSA failure.
    pub fn sign_v4(
        &mut self,
        inviter_kp: &crate::identity::AgentKeypair,
        owner_kp: Option<&crate::identity::UserKeypair>,
    ) -> Result<(), String> {
        self.inviter_public_key_b64 = B64_STD.encode(inviter_kp.public_key().as_bytes());
        if let Some(owner) = owner_kp {
            self.owner_public_key_b64 = Some(B64_STD.encode(owner.public_key().as_bytes()));
        }
        if let Some((field, size)) = self.v4_field_caps_violation() {
            return Err(format!(
                "invite field {field} exceeds cap ({size} bytes/entries)"
            ));
        }
        let view = InviteSignedViewV4::from_invite(self).map_err(|r| r.reason().to_string())?;
        let canonical = view
            .canonical_bytes()
            .map_err(|e| format!("invite canonical bytes: {e}"))?;
        let mut inviter_input = INVITE_V4_INVITER_DOMAIN.to_vec();
        inviter_input.extend_from_slice(&canonical);
        let sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            inviter_kp.secret_key(),
            &inviter_input,
        )
        .map_err(|e| format!("inviter sign: {e:?}"))?;
        self.inviter_signature_b64 = B64_STD.encode(sig.as_bytes());
        if let Some(owner) = owner_kp {
            let mut owner_input = INVITE_V4_OWNER_DOMAIN.to_vec();
            owner_input.extend_from_slice(&canonical);
            let sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                owner.secret_key(),
                &owner_input,
            )
            .map_err(|e| format!("owner countersign: {e:?}"))?;
            self.owner_countersignature_b64 = Some(B64_STD.encode(sig.as_bytes()));
        }
        Ok(())
    }

    /// Verify the v4 signatures and inline key bindings (#469, v6 E4).
    ///
    /// Order: view construction (version/projection/id invariants/meta
    /// equality — `invite_unsigned` / `invite_malformed`) → legacy
    /// `signature` must be empty → inline inviter key id binding →
    /// inviter signature → owner axis: inline owner key present + id
    /// binding + countersignature. Revocation-set checks are the
    /// caller's (the server owns the set; map to
    /// [`InviteRefusal::InviterKeyRevoked`] — the AGENT subject only; there
    /// is no user revocation subject, see v7 F3 and the ADR-0016
    /// amendment).
    pub fn verify_v4_signatures(&self) -> Result<(), InviteRefusal> {
        if !self.signature.is_empty() {
            return Err(InviteRefusal::SignatureInvalid);
        }
        let view = InviteSignedViewV4::from_invite(self)?;
        let canonical = view
            .canonical_bytes()
            .map_err(|_| InviteRefusal::Malformed)?;

        // Inline inviter key: self-authenticating id binding (E4).
        let inviter_key_bytes = B64_STD
            .decode(view.inviter_public_key_b64.as_bytes())
            .map_err(|_| InviteRefusal::InviterKeyMismatch)?;
        let inviter_key = ant_quic::MlDsaPublicKey::from_bytes(&inviter_key_bytes)
            .map_err(|_| InviteRefusal::InviterKeyMismatch)?;
        let derived_inviter = crate::identity::AgentId::from_public_key(&inviter_key);
        if hex::encode(derived_inviter.as_bytes()) != view.inviter {
            return Err(InviteRefusal::InviterKeyMismatch);
        }
        let sig_bytes = B64_STD
            .decode(self.inviter_signature_b64.as_bytes())
            .map_err(|_| InviteRefusal::InviterSignatureInvalid)?;
        let sig = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&sig_bytes)
            .map_err(|_| InviteRefusal::InviterSignatureInvalid)?;
        let mut inviter_input = INVITE_V4_INVITER_DOMAIN.to_vec();
        inviter_input.extend_from_slice(&canonical);
        if ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &inviter_key,
            &inviter_input,
            &sig,
        )
        .is_err()
        {
            return Err(InviteRefusal::InviterSignatureInvalid);
        }

        // Owner axis: countersignature required and verified under the
        // inline owner user key, itself bound to the policy's owner id.
        if let Some(owner_id) = view.policy.admission.owner_certified_user_id() {
            let Some(owner_key_b64) = view.owner_public_key_b64.as_deref() else {
                return Err(InviteRefusal::OwnerCountersignatureMissing);
            };
            let owner_key_bytes = B64_STD
                .decode(owner_key_b64)
                .map_err(|_| InviteRefusal::OwnerCountersignatureInvalid)?;
            let owner_key = ant_quic::MlDsaPublicKey::from_bytes(&owner_key_bytes)
                .map_err(|_| InviteRefusal::OwnerCountersignatureInvalid)?;
            let derived_owner = crate::identity::UserId::from_public_key(&owner_key);
            if derived_owner != *owner_id {
                return Err(InviteRefusal::OwnerCountersignatureInvalid);
            }
            let Some(countersig_b64) = self.owner_countersignature_b64.as_deref() else {
                return Err(InviteRefusal::OwnerCountersignatureMissing);
            };
            let countersig = B64_STD
                .decode(countersig_b64)
                .and_then(|bytes| {
                    ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&bytes)
                        .map_err(|_| {
                            base64::DecodeError::InvalidByte(0, 0) // never observed: mapped below
                        })
                })
                .map_err(|_| InviteRefusal::OwnerCountersignatureInvalid)?;
            let mut owner_input = INVITE_V4_OWNER_DOMAIN.to_vec();
            owner_input.extend_from_slice(&canonical);
            if ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
                &owner_key,
                &owner_input,
                &countersig,
            )
            .is_err()
            {
                return Err(InviteRefusal::OwnerCountersignatureInvalid);
            }
        }
        Ok(())
    }

    /// Encode this invite as a shareable link.
    ///
    /// Format: `x0x://invite/<base64url(json)>`
    #[must_use]
    pub fn to_link(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("x0x://invite/{b64}")
    }

    /// Encode this invite as a shareable link, rejecting oversized payloads.
    ///
    /// Wraps [`Self::to_link`] with the [`INVITE_LINK_MAX_BYTES`] budget check
    /// so a roster that would blow the gossip-DM cap fails loudly at the mint
    /// site (issue #205) rather than 400-ing later at `/direct/send`.
    ///
    /// # Errors
    ///
    /// Returns [`InviteLinkTooLarge`] when the encoded link exceeds the budget.
    pub fn encode_link(&self) -> Result<String, InviteLinkTooLarge> {
        let link = self.to_link();
        if link.len() > INVITE_LINK_MAX_BYTES {
            return Err(InviteLinkTooLarge {
                actual: link.len(),
                limit: INVITE_LINK_MAX_BYTES,
            });
        }
        Ok(link)
    }

    /// Parse an invite from a link string.
    ///
    /// Accepts both `x0x://invite/<base64>` and raw `<base64>` formats.
    ///
    /// # Errors
    ///
    /// Returns an error if the link is malformed or the invite can't be deserialized.
    pub fn from_link(link: &str) -> std::result::Result<Self, String> {
        let b64 = link.strip_prefix("x0x://invite/").unwrap_or(link).trim();

        use base64::Engine;
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("invalid base64: {e}"))?;

        let json_str = String::from_utf8(json_bytes).map_err(|e| format!("invalid UTF-8: {e}"))?;

        serde_json::from_str(&json_str).map_err(|e| format!("invalid invite JSON: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::policy::{GroupAdmission, GroupConfidentiality};
    use crate::groups::state_commit::{compute_home_digest, GroupPublicMeta, RosterMemberSnapshot};
    use crate::groups::{GroupMemberState, GroupRole, HomeMetadata};
    use crate::identity::{AgentKeypair, UserId, UserKeypair};

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_create_invite() {
        let invite = SignedInvite::new(
            "aabb".repeat(8),
            "Test Group".to_string(),
            &agent(1),
            DEFAULT_EXPIRY_SECS,
        );

        assert_eq!(invite.group_name, "Test Group");
        assert!(!invite.invite_secret.is_empty());
        assert_eq!(invite.invite_secret.len(), 64); // 32 bytes hex
        assert!(invite.created_at > 0);
        assert!(invite.expires_at > invite.created_at);
        assert!(!invite.is_expired());
        assert!(!invite.is_signed());
    }

    #[test]
    fn test_invite_no_expiry() {
        let invite = SignedInvite::new("aabb".repeat(8), "Forever Group".to_string(), &agent(1), 0);
        assert_eq!(invite.expires_at, 0);
        assert!(!invite.is_expired());
    }

    #[test]
    fn test_invite_expired() {
        let mut invite = SignedInvite::new("aabb".repeat(8), "Old Group".to_string(), &agent(1), 1);
        // Force expiry in the past
        invite.expires_at = 1000;
        assert!(invite.is_expired());
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let mut invite1 = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 3600);
        let mut invite2 = invite1.clone();

        // Same fields → same signable bytes
        invite1.invite_secret = "aa".repeat(32);
        invite2.invite_secret = "aa".repeat(32);
        invite1.created_at = 1000;
        invite2.created_at = 1000;
        invite1.expires_at = 2000;
        invite2.expires_at = 2000;

        assert_eq!(invite1.signable_bytes(), invite2.signable_bytes());
    }

    #[test]
    fn test_link_roundtrip() {
        let invite = SignedInvite::new(
            "aabb".repeat(8),
            "Test Group".to_string(),
            &agent(1),
            DEFAULT_EXPIRY_SECS,
        );

        let link = invite.to_link();
        assert!(link.starts_with("x0x://invite/"));

        let restored = SignedInvite::from_link(&link).expect("parse link");
        assert_eq!(invite.group_id, restored.group_id);
        assert_eq!(invite.group_name, restored.group_name);
        assert_eq!(invite.inviter, restored.inviter);
        assert_eq!(invite.invite_secret, restored.invite_secret);
    }

    #[test]
    fn test_from_link_raw_base64() {
        let invite = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 0);

        let link = invite.to_link();
        // Strip the prefix — should still parse
        let raw = link.strip_prefix("x0x://invite/").expect("prefix");
        let restored = SignedInvite::from_link(raw).expect("parse raw");
        assert_eq!(invite.group_id, restored.group_id);
    }

    #[test]
    fn test_from_link_invalid() {
        let result = SignedInvite::from_link("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_json_serialization() {
        let invite = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 3600);
        let json = serde_json::to_string(&invite).expect("serialize");
        let restored: SignedInvite = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(invite.group_id, restored.group_id);
    }

    #[test]
    fn test_optional_metadata_roundtrip() {
        let mut invite = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 3600);
        invite.stable_group_id = Some("bb".repeat(32));
        invite.group_created_at = Some(1_234_567);
        invite.group_description = Some("desc".to_string());
        invite.policy = Some(GroupPolicy::default());
        invite.genesis_creation_nonce = Some("cc".repeat(32));
        invite.base_state_revision = Some(7);
        invite.base_state_hash = Some("state-7".to_string());
        invite.base_members_v2 = Some(BTreeMap::new());
        invite.base_prev_state_hash = Some("state-6".to_string());
        invite.secure_plane = Some(SecureGroupPlane::TreeKem);

        let json = serde_json::to_string(&invite).expect("serialize metadata invite");
        let restored: SignedInvite =
            serde_json::from_str(&json).expect("deserialize metadata invite");
        assert_eq!(invite.stable_group_id, restored.stable_group_id);
        assert_eq!(invite.group_created_at, restored.group_created_at);
        assert_eq!(invite.group_description, restored.group_description);
        assert_eq!(invite.policy, restored.policy);
        assert_eq!(
            invite.genesis_creation_nonce,
            restored.genesis_creation_nonce
        );
        assert_eq!(invite.base_state_revision, restored.base_state_revision);
        assert_eq!(invite.base_state_hash, restored.base_state_hash);
        assert_eq!(invite.base_members_v2, restored.base_members_v2);
        assert_eq!(invite.base_prev_state_hash, restored.base_prev_state_hash);
        assert_eq!(invite.secure_plane, restored.secure_plane);
    }

    #[test]
    fn creator_provenance_comes_from_base_state_not_inviter() {
        let creator = agent(1);
        let inviter = agent(2);
        let mut info =
            crate::groups::GroupInfo::new("T".to_string(), String::new(), creator, "aa".repeat(16));
        let creator_hex = hex::encode(creator.as_bytes());
        let inviter_hex = hex::encode(inviter.as_bytes());
        info.add_member(
            inviter_hex.clone(),
            crate::groups::GroupRole::Admin,
            Some(creator_hex.clone()),
            None,
        );

        let mut invite =
            SignedInvite::new(info.mls_group_id.clone(), info.name.clone(), &inviter, 0);
        invite.group_created_at = Some(info.created_at);
        invite.base_members_v2 = Some(info.members_v2.clone());

        assert_eq!(invite.inviter, inviter_hex);
        assert_eq!(
            invite
                .creator_agent_id_from_base_state()
                .expect("derive creator from base roster"),
            creator_hex
        );
    }

    #[test]
    fn creator_provenance_survives_creator_role_changes() {
        let creator = agent(1);
        let inviter = agent(2);
        let mut info =
            crate::groups::GroupInfo::new("T".to_string(), String::new(), creator, "aa".repeat(16));
        let creator_hex = hex::encode(creator.as_bytes());
        let inviter_hex = hex::encode(inviter.as_bytes());
        info.add_member(
            inviter_hex,
            crate::groups::GroupRole::Admin,
            Some(creator_hex.clone()),
            None,
        );
        info.set_member_role(&creator_hex, crate::groups::GroupRole::Member);

        let mut invite =
            SignedInvite::new(info.mls_group_id.clone(), info.name.clone(), &inviter, 0);
        invite.group_created_at = Some(info.created_at);
        invite.base_members_v2 = Some(info.members_v2.clone());

        assert_eq!(
            invite
                .creator_agent_id_from_base_state()
                .expect("creator provenance is history, not authority"),
            creator_hex
        );
    }

    #[test]
    fn creator_provenance_does_not_fall_back_to_unsigned_inviter() {
        let inviter = agent(2);
        let invite = SignedInvite::new("aa".repeat(16), "T".to_string(), &inviter, 0);

        assert_eq!(
            invite.creator_agent_id_from_base_state().unwrap_err(),
            "invite missing base member snapshot; cannot derive creator provenance"
        );
    }

    #[test]
    fn test_legacy_invite_missing_secure_plane_defaults_none() {
        let json = serde_json::json!({
            "group_id": "aabb".repeat(8),
            "group_name": "Legacy",
            "inviter": hex::encode(agent(1).as_bytes()),
            "invite_secret": "11".repeat(32),
            "created_at": 1,
            "expires_at": 0,
            "signature": ""
        });
        let restored: SignedInvite =
            serde_json::from_value(json).expect("deserialize legacy invite");
        assert_eq!(restored.secure_plane, None);
        assert_ne!(restored.secure_plane, Some(SecureGroupPlane::TreeKem));
    }

    // ─── #469 InviteV4: canonical bytes, typed refusals, caps, budget ────

    /// Deterministic shared fixture roster: two projection entries with
    /// 64-hex member ids and both hash fields populated.
    fn fixture_roster() -> BTreeMap<String, RosterMemberSnapshot> {
        [0x11u8, 0xee]
            .into_iter()
            .map(|byte| {
                (
                    format!("{byte:02x}").repeat(32),
                    RosterMemberSnapshot {
                        role: GroupRole::Admin,
                        state: GroupMemberState::Active,
                        treekem_key_package_hash: Some("0f".repeat(32)),
                        certificate_digest: Some("5a".repeat(32)),
                    },
                )
            })
            .collect()
    }

    /// Deterministic v4 invite fixture. `owner_kp` switches the policy to
    /// the OwnerCertified axis (the countersignature path); timestamps,
    /// secret, and roster are fixed so failures localize to the mutation.
    fn v4_fixture(inviter_kp: &AgentKeypair, owner_kp: Option<&UserKeypair>) -> SignedInvite {
        let mut policy = GroupPolicy::default();
        if let Some(owner) = owner_kp {
            policy.admission =
                GroupAdmission::OwnerCertified(UserId::from_public_key(owner.public_key()));
        }
        let mut invite = SignedInvite::new(
            "cd".repeat(32),
            "fixture group".to_string(),
            &AgentId::from_public_key(inviter_kp.public_key()),
            86_400,
        );
        invite.stable_group_id = Some("cd".repeat(32));
        invite.group_created_at = Some(1_699_000_000);
        invite.group_description = Some("fixture description".to_string());
        invite.invite_secret = "ab".repeat(32);
        invite.created_at = 1_700_000_000;
        invite.expires_at = 1_700_086_400;
        invite.policy = Some(policy);
        invite.genesis_creation_nonce = Some("ee".repeat(32));
        invite.base_state_revision = Some(7);
        invite.base_state_hash = Some("aa".repeat(32));
        invite.base_prev_state_hash = Some("bb".repeat(32));
        invite.secure_plane = Some(SecureGroupPlane::TreeKem);
        invite.base_secret_epoch = Some(3);
        invite.base_security_binding = Some("cc".repeat(32));
        invite.public_meta = Some(GroupPublicMeta {
            name: "fixture group".to_string(),
            description: "fixture description".to_string(),
            tags: vec!["fixture".to_string()],
            avatar_url: None,
            banner_url: None,
            home_digest: None,
        });
        invite.base_roster = Some(fixture_roster());
        invite.creator = Some("12".repeat(32));
        invite.inviter_public_key_b64 = B64_STD.encode(inviter_kp.public_key().as_bytes());
        invite
    }

    /// Pinned BLAKE3-256 (hex) over the canonical bytes of the fixed-field
    /// view below — any field reorder, insertion, or representation change
    /// in `InviteSignedViewV4` (or one of its member types) moves this
    /// digest and fails the pin.
    const PINNED_VIEW_CANONICAL_BLAKE3: &str =
        "d19b8c48198a63aac9d7263f867cf9a325f2aa8d7adc5970b33c5b20c72ae4ea";

    /// The fixed-field view pinned by `canonical_bytes_pinned_vector`:
    /// deterministic key bytes, secret, timestamps, roster, and metadata —
    /// no generated key material anywhere.
    fn pinned_view() -> InviteSignedViewV4 {
        InviteSignedViewV4 {
            version: INVITE_VERSION_V4,
            group_id: "cd".repeat(32),
            stable_group_id: "cd".repeat(32),
            group_created_at: 1_699_000_000,
            group_name: "pinned vector group".to_string(),
            group_description: Some("pinned vector fixture".to_string()),
            genesis_creation_nonce: Some("ee".repeat(32)),
            creator: "12".repeat(32),
            public_meta: GroupPublicMeta {
                name: "pinned vector group".to_string(),
                description: "pinned vector fixture".to_string(),
                tags: vec!["pinned".to_string()],
                avatar_url: Some("https://example.com/a.png".to_string()),
                banner_url: None,
                home_digest: None,
            },
            base_home: None,
            secure_plane: SecureGroupPlane::TreeKem,
            policy: GroupPolicy::default(),
            base_state_revision: 7,
            base_state_hash: "aa".repeat(32),
            base_prev_state_hash: Some("bb".repeat(32)),
            base_roster: fixture_roster(),
            base_secret_epoch: 3,
            base_security_binding: Some("cc".repeat(32)),
            inviter: "ab".repeat(32),
            inviter_public_key_b64: B64_STD.encode([7u8; 1952]),
            owner_public_key_b64: None,
            secret_hash: *blake3::hash(&[0xAB; 32]).as_bytes(),
            created_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            intended_joiner: None,
        }
    }

    /// An invite whose `from_invite` view is EXACTLY `pinned_view()` —
    /// pins the constructor's field mapping, including the raw-secret
    /// hash derivation (`blake3(hex-decoded 32 bytes)`, not the text).
    fn invite_matching_pinned_view() -> SignedInvite {
        let view = pinned_view();
        let mut invite = SignedInvite::new(
            view.group_id.clone(),
            view.group_name.clone(),
            &agent(0xAB),
            86_400,
        );
        invite.stable_group_id = Some(view.stable_group_id.clone());
        invite.group_created_at = Some(view.group_created_at);
        invite.group_description = view.group_description.clone();
        invite.invite_secret = "ab".repeat(32);
        invite.created_at = view.created_at;
        invite.expires_at = view.expires_at;
        invite.policy = Some(view.policy.clone());
        invite.genesis_creation_nonce = view.genesis_creation_nonce.clone();
        invite.base_state_revision = Some(view.base_state_revision);
        invite.base_state_hash = Some(view.base_state_hash.clone());
        invite.base_prev_state_hash = view.base_prev_state_hash.clone();
        invite.secure_plane = Some(view.secure_plane);
        invite.base_secret_epoch = Some(view.base_secret_epoch);
        invite.base_security_binding = view.base_security_binding.clone();
        invite.public_meta = Some(view.public_meta.clone());
        invite.base_roster = Some(view.base_roster.clone());
        invite.creator = Some(view.creator.clone());
        invite.inviter = view.inviter.clone();
        invite.inviter_public_key_b64 = view.inviter_public_key_b64.clone();
        invite
    }

    #[test]
    fn canonical_bytes_pinned_vector() {
        let view = pinned_view();
        let canonical = view.canonical_bytes().expect("canonical bytes");
        assert!(
            canonical.starts_with(INVITE_V4_CANONICAL_DOMAIN),
            "canonical bytes must open with the signing domain"
        );
        // Determinism: a fresh identical view serializes byte-identically.
        assert_eq!(
            canonical,
            pinned_view()
                .canonical_bytes()
                .expect("canonical bytes (rebuild)")
        );
        // The pinned digest freezes the whole value graph.
        assert_eq!(
            hex::encode(blake3::hash(&canonical).as_bytes()),
            PINNED_VIEW_CANONICAL_BLAKE3,
            "v4 canonical-byte layout changed — repin deliberately"
        );
        // BTreeMap insertion order never leaks into the canonical bytes.
        let mut reversed = pinned_view();
        reversed.base_roster = fixture_roster().into_iter().rev().collect();
        assert_eq!(
            canonical,
            reversed
                .canonical_bytes()
                .expect("canonical bytes (reversed insertion)")
        );
        // The constructor maps a matching invite onto exactly this view.
        assert_eq!(
            InviteSignedViewV4::from_invite(&invite_matching_pinned_view()).expect("view"),
            view
        );
    }

    #[test]
    fn v4_missing_field_matrix_maps_typed_refusals() {
        let inviter_kp = AgentKeypair::generate().expect("agent keypair");
        let owner_kp = UserKeypair::generate().expect("user keypair");
        let mut invite = v4_fixture(&inviter_kp, Some(&owner_kp));
        invite
            .sign_v4(&inviter_kp, Some(&owner_kp))
            .expect("sign baseline");
        assert_eq!(invite.verify_v4_signatures(), Ok(()));

        // Pre-v4 versions — including the absent-field legacy sentinel 0.
        for version in [0u8, 3] {
            let mut t = invite.clone();
            t.version = version;
            assert_eq!(
                t.verify_v4_signatures(),
                Err(InviteRefusal::Unsigned),
                "version {version}"
            );
        }
        // A non-empty legacy `signature` is refused before anything else.
        let mut t = invite.clone();
        t.signature = "deadbeef".to_string();
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::SignatureInvalid)
        );
        // A legacy fat roster would ride unsigned next to the projection.
        let mut t = invite.clone();
        let mut fat = BTreeMap::new();
        fat.insert(
            "11".repeat(32),
            GroupMember::new_admin("11".repeat(32), None, 0),
        );
        t.base_members_v2 = Some(fat);
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Unsigned));
        // stable ≠ MLS id breaks the signed id invariant (E1).
        let mut t = invite.clone();
        t.stable_group_id = Some("ce".repeat(32));
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Malformed));
        // Required v4 inputs absent ⇒ Unsigned.
        let mut t = invite.clone();
        t.stable_group_id = None;
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Unsigned));
        let mut t = invite.clone();
        t.public_meta = None;
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Unsigned));
        let mut t = invite.clone();
        t.base_roster = None;
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Unsigned));
        let mut t = invite.clone();
        t.creator = None;
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Unsigned));
        // invite_secret: non-hex text, and valid hex of the wrong length.
        let mut t = invite.clone();
        t.invite_secret = "zz".repeat(32);
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Malformed));
        let mut t = invite.clone();
        t.invite_secret = "ab".repeat(31);
        assert_eq!(t.verify_v4_signatures(), Err(InviteRefusal::Malformed));
    }

    #[test]
    fn v4_sign_verify_roundtrip_and_tamper_matrix() {
        let inviter_kp = AgentKeypair::generate().expect("agent keypair");
        let owner_kp = UserKeypair::generate().expect("user keypair");

        // Owner axis: both signatures mint, verify, and survive the link.
        let mut invite = v4_fixture(&inviter_kp, Some(&owner_kp));
        invite
            .sign_v4(&inviter_kp, Some(&owner_kp))
            .expect("sign owner-axis invite");
        assert_eq!(invite.verify_v4_signatures(), Ok(()));
        let restored =
            SignedInvite::from_link(&invite.encode_link().expect("link fits")).expect("parse");
        assert_eq!(restored.inviter_signature_b64, invite.inviter_signature_b64);
        assert_eq!(
            restored.owner_countersignature_b64,
            invite.owner_countersignature_b64
        );
        assert_eq!(restored.verify_v4_signatures(), Ok(()));

        // Tampering any signed field yields its typed refusal.
        let mut t = invite.clone();
        t.group_name.push('!');
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::Malformed),
            "renamed group breaks the meta equality rule first"
        );
        let mut t = invite.clone();
        t.policy.as_mut().expect("policy").confidentiality = GroupConfidentiality::SignedPublic;
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::InviterSignatureInvalid),
            "policy rides the signed view"
        );
        let mut t = invite.clone();
        let mut roster = t.base_roster.clone().expect("roster");
        let first = roster.keys().next().cloned().expect("roster entry");
        roster.get_mut(&first).expect("entry").role = GroupRole::Member;
        t.base_roster = Some(roster);
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::InviterSignatureInvalid),
            "roster entries ride the signed view"
        );
        let mut t = invite.clone();
        t.public_meta
            .as_mut()
            .expect("meta")
            .tags
            .push("tampered".to_string());
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::InviterSignatureInvalid),
            "public-meta tags ride the signed view"
        );
        let mut t = invite.clone();
        t.invite_secret = format!("{}ac", "ab".repeat(31));
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::InviterSignatureInvalid),
            "one secret hex char flips the signed secret hash"
        );
        let mut t = invite.clone();
        t.expires_at += 1;
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::InviterSignatureInvalid),
            "expiry rides the signed view"
        );

        // r1 Option-preserving fields (Codex 8): Some(value) → None flips
        // the signed bytes. A dropped description ALSO trips the equality
        // rule (None ≡ "" there) and refuses as Malformed — still caught.
        let mut t = invite.clone();
        t.group_description = None;
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::Malformed),
            "dropping a present description breaks the equality rule"
        );
        type InviteMutator<'a> = (&'a str, &'a dyn Fn(&mut SignedInvite));
        let flip_to_none: [InviteMutator; 3] = [
            ("genesis_creation_nonce", &|t: &mut SignedInvite| {
                t.genesis_creation_nonce = None;
            }),
            ("base_prev_state_hash", &|t: &mut SignedInvite| {
                t.base_prev_state_hash = None;
            }),
            ("base_security_binding", &|t: &mut SignedInvite| {
                t.base_security_binding = None;
            }),
        ];
        for (label, mutate) in flip_to_none {
            let mut t = invite.clone();
            mutate(&mut t);
            assert_eq!(
                t.verify_v4_signatures(),
                Err(InviteRefusal::InviterSignatureInvalid),
                "{label}: Some(..) → None must change the signed bytes"
            );
        }
        // The other direction on a genesis-shape fixture (all four Option
        // fields None, empty description): None → Some("") is a DISTINCT
        // signed state on every one of them.
        let mut genesis = v4_fixture(&inviter_kp, None);
        genesis.group_description = None;
        genesis.genesis_creation_nonce = None;
        genesis.base_prev_state_hash = None;
        genesis.base_security_binding = None;
        genesis.public_meta.as_mut().expect("meta").description = String::new();
        genesis
            .sign_v4(&inviter_kp, None)
            .expect("sign genesis-shape invite");
        assert_eq!(genesis.verify_v4_signatures(), Ok(()));
        let flip_to_some_empty: [InviteMutator; 4] = [
            ("group_description", &|t: &mut SignedInvite| {
                t.group_description = Some(String::new());
            }),
            ("genesis_creation_nonce", &|t: &mut SignedInvite| {
                t.genesis_creation_nonce = Some(String::new());
            }),
            ("base_prev_state_hash", &|t: &mut SignedInvite| {
                t.base_prev_state_hash = Some(String::new());
            }),
            ("base_security_binding", &|t: &mut SignedInvite| {
                t.base_security_binding = Some(String::new());
            }),
        ];
        for (label, mutate) in flip_to_some_empty {
            let mut t = genesis.clone();
            mutate(&mut t);
            assert_eq!(
                t.verify_v4_signatures(),
                Err(InviteRefusal::InviterSignatureInvalid),
                "{label}: None → Some(\"\") must change the signed bytes"
            );
        }

        // Key swaps. Swapped inviter key: id binding fails first.
        let stranger_kp = AgentKeypair::generate().expect("stranger agent keypair");
        let mut t = invite.clone();
        t.inviter_public_key_b64 = B64_STD.encode(stranger_kp.public_key().as_bytes());
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::InviterKeyMismatch)
        );
        // Swapped inline owner key: the key rides the SIGNED view, so the
        // inviter signature catches the swap before the owner checks run.
        let stranger_user = UserKeypair::generate().expect("stranger user keypair");
        let mut t = invite.clone();
        t.owner_public_key_b64 = Some(B64_STD.encode(stranger_user.public_key().as_bytes()));
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::InviterSignatureInvalid),
            "the inline owner key rides the signed view"
        );
        // Right owner key, but the countersignature is by the WRONG user
        // key over the same canonical bytes (binding passes, sig fails).
        let mut t = invite.clone();
        let canonical = InviteSignedViewV4::from_invite(&t)
            .expect("view")
            .canonical_bytes()
            .expect("canonical bytes");
        let mut owner_input = INVITE_V4_OWNER_DOMAIN.to_vec();
        owner_input.extend_from_slice(&canonical);
        let forged = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            stranger_user.secret_key(),
            &owner_input,
        )
        .expect("forge countersignature");
        t.owner_countersignature_b64 = Some(B64_STD.encode(forged.as_bytes()));
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::OwnerCountersignatureInvalid)
        );
        // Swapped owner key that IS covered by a fresh inviter signature,
        // plus a matching stranger countersignature: the inviter signature
        // now verifies and the owner UserId binding is what fails.
        let mut t = invite.clone();
        t.owner_public_key_b64 = Some(B64_STD.encode(stranger_user.public_key().as_bytes()));
        t.owner_countersignature_b64 = None;
        t.sign_v4(&inviter_kp, None)
            .expect("re-sign over the swapped owner key");
        let swapped_canonical = InviteSignedViewV4::from_invite(&t)
            .expect("view")
            .canonical_bytes()
            .expect("canonical bytes");
        let mut swapped_input = INVITE_V4_OWNER_DOMAIN.to_vec();
        swapped_input.extend_from_slice(&swapped_canonical);
        let swapped_forged = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            stranger_user.secret_key(),
            &swapped_input,
        )
        .expect("forge swapped-owner countersignature");
        t.owner_countersignature_b64 = Some(B64_STD.encode(swapped_forged.as_bytes()));
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::OwnerCountersignatureInvalid),
            "a stranger owner key fails the UserId binding even when signed"
        );
        // Stripped countersignature on an owner-axis invite.
        let mut t = invite.clone();
        t.owner_countersignature_b64 = None;
        assert_eq!(
            t.verify_v4_signatures(),
            Err(InviteRefusal::OwnerCountersignatureMissing)
        );

        // Non-owner axis: no countersignature required or present.
        let mut plain = v4_fixture(&inviter_kp, None);
        plain
            .sign_v4(&inviter_kp, None)
            .expect("sign invite-only invite");
        assert!(plain.owner_countersignature_b64.is_none());
        assert_eq!(plain.verify_v4_signatures(), Ok(()));
    }

    #[test]
    fn v4_equality_rules_and_non_default_meta_roundtrip() {
        let inviter_kp = AgentKeypair::generate().expect("agent keypair");
        let home = HomeMetadata {
            primary_agent: "12".repeat(32),
            placements: BTreeMap::new(),
            provisioned_at_ms: 1_699_000_000_000,
        };

        // Name mismatch between the top-level field and the meta snapshot.
        let mut t = v4_fixture(&inviter_kp, None);
        t.group_name = "different".to_string();
        assert_eq!(
            InviteSignedViewV4::from_invite(&t),
            Err(InviteRefusal::Malformed)
        );
        // Description mismatch.
        let mut t = v4_fixture(&inviter_kp, None);
        t.group_description = Some("different".to_string());
        assert_eq!(
            InviteSignedViewV4::from_invite(&t),
            Err(InviteRefusal::Malformed)
        );
        // Home preimage present but digest mismatched.
        let mut t = v4_fixture(&inviter_kp, None);
        t.base_home = Some(home.clone());
        t.public_meta.as_mut().expect("meta").home_digest = Some("00".repeat(32));
        assert_eq!(
            InviteSignedViewV4::from_invite(&t),
            Err(InviteRefusal::Malformed)
        );
        // Digest claimed with no preimage.
        let mut t = v4_fixture(&inviter_kp, None);
        t.public_meta.as_mut().expect("meta").home_digest = Some(compute_home_digest(&home));
        assert_eq!(
            InviteSignedViewV4::from_invite(&t),
            Err(InviteRefusal::Malformed)
        );

        // Non-default metadata (tags, avatar, banner, Home preimage +
        // matching digest) signs, verifies, and round-trips exactly.
        let meta = GroupPublicMeta {
            name: "fixture group".to_string(),
            description: "fixture description".to_string(),
            tags: vec!["one".to_string(), "two".to_string()],
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            banner_url: Some("https://example.com/banner.png".to_string()),
            home_digest: Some(compute_home_digest(&home)),
        };
        let mut invite = v4_fixture(&inviter_kp, None);
        invite.public_meta = Some(meta.clone());
        invite.base_home = Some(home);
        invite
            .sign_v4(&inviter_kp, None)
            .expect("sign non-default meta");
        assert_eq!(invite.verify_v4_signatures(), Ok(()));
        let restored =
            SignedInvite::from_link(&invite.encode_link().expect("link fits")).expect("parse");
        assert_eq!(restored.public_meta, Some(meta));
        assert_eq!(restored.verify_v4_signatures(), Ok(()));
    }

    #[test]
    fn v4_field_caps_matrix() {
        let inviter_kp = AgentKeypair::generate().expect("agent keypair");
        // Boundary: every capped field AT its cap — and the invite is
        // fully mintable (structural rules hold, signs and verifies).
        let mut boundary = SignedInvite::new(
            "cd".repeat(32),
            "n".repeat(INVITE_MAX_GROUP_NAME),
            &AgentId::from_public_key(inviter_kp.public_key()),
            0,
        );
        boundary.stable_group_id = Some("cd".repeat(32));
        boundary.group_created_at = Some(1);
        boundary.group_description = Some("d".repeat(INVITE_MAX_GROUP_DESCRIPTION));
        boundary.invite_secret = "ab".repeat(32);
        boundary.policy = Some(GroupPolicy::default());
        boundary.base_state_revision = Some(1);
        boundary.base_state_hash = Some("aa".repeat(32));
        boundary.base_secret_epoch = Some(1);
        boundary.public_meta = Some(GroupPublicMeta {
            name: "n".repeat(INVITE_MAX_GROUP_NAME),
            description: "d".repeat(INVITE_MAX_GROUP_DESCRIPTION),
            tags: vec!["t".repeat(INVITE_MAX_TAG_LEN); INVITE_MAX_TAGS],
            avatar_url: Some("u".repeat(INVITE_MAX_URL_LEN)),
            banner_url: Some("u".repeat(INVITE_MAX_URL_LEN)),
            home_digest: None,
        });
        boundary.base_roster = Some(
            (0..MAX_INVITE_ROSTER_ENTRIES)
                .map(|i| {
                    (
                        format!("{i:064x}"),
                        RosterMemberSnapshot {
                            role: GroupRole::Admin,
                            state: GroupMemberState::Active,
                            treekem_key_package_hash: Some("0f".repeat(32)),
                            certificate_digest: Some("5a".repeat(32)),
                        },
                    )
                })
                .collect(),
        );
        boundary.creator = Some("12".repeat(32));
        assert_eq!(boundary.v4_field_caps_violation(), None);
        boundary
            .sign_v4(&inviter_kp, None)
            .expect("sign at the caps boundary");
        assert_eq!(boundary.verify_v4_signatures(), Ok(()));

        // Each cap exceeded in isolation reports (field, measured size).
        let over = |mutate: &dyn Fn(&mut SignedInvite)| -> (&'static str, usize) {
            let mut t = boundary.clone();
            mutate(&mut t);
            t.v4_field_caps_violation()
                .unwrap_or_else(|| panic!("expected a caps violation"))
        };
        assert_eq!(
            over(&|t| {
                t.group_name = "n".repeat(INVITE_MAX_GROUP_NAME + 1);
            }),
            ("group_name", INVITE_MAX_GROUP_NAME + 1)
        );
        assert_eq!(
            over(&|t| {
                t.group_description = Some("d".repeat(INVITE_MAX_GROUP_DESCRIPTION + 1));
            }),
            ("group_description", INVITE_MAX_GROUP_DESCRIPTION + 1)
        );
        assert_eq!(
            over(&|t| {
                t.public_meta.as_mut().expect("meta").name = "n".repeat(INVITE_MAX_GROUP_NAME + 1);
            }),
            ("public_meta.name", INVITE_MAX_GROUP_NAME + 1)
        );
        assert_eq!(
            over(&|t| {
                t.public_meta.as_mut().expect("meta").description =
                    "d".repeat(INVITE_MAX_GROUP_DESCRIPTION + 1);
            }),
            ("public_meta.description", INVITE_MAX_GROUP_DESCRIPTION + 1)
        );
        assert_eq!(
            over(&|t| {
                t.public_meta.as_mut().expect("meta").tags =
                    vec!["t".repeat(INVITE_MAX_TAG_LEN); INVITE_MAX_TAGS + 1];
            }),
            ("public_meta.tags", INVITE_MAX_TAGS + 1)
        );
        assert_eq!(
            over(&|t| {
                let mut tags = vec!["t".repeat(INVITE_MAX_TAG_LEN); INVITE_MAX_TAGS];
                tags[0] = "t".repeat(INVITE_MAX_TAG_LEN + 1);
                t.public_meta.as_mut().expect("meta").tags = tags;
            }),
            ("public_meta.tag_len", INVITE_MAX_TAG_LEN + 1)
        );
        assert_eq!(
            over(&|t| {
                t.public_meta.as_mut().expect("meta").avatar_url =
                    Some("u".repeat(INVITE_MAX_URL_LEN + 1));
            }),
            ("public_meta.avatar_url", INVITE_MAX_URL_LEN + 1)
        );
        assert_eq!(
            over(&|t| {
                t.public_meta.as_mut().expect("meta").banner_url =
                    Some("u".repeat(INVITE_MAX_URL_LEN + 1));
            }),
            ("public_meta.banner_url", INVITE_MAX_URL_LEN + 1)
        );
        assert_eq!(
            over(&|t| {
                let mut roster = t.base_roster.clone().expect("roster");
                roster.insert(
                    "ff".repeat(32),
                    RosterMemberSnapshot {
                        role: GroupRole::Admin,
                        state: GroupMemberState::Active,
                        treekem_key_package_hash: None,
                        certificate_digest: None,
                    },
                );
                t.base_roster = Some(roster);
            }),
            ("base_roster", MAX_INVITE_ROSTER_ENTRIES + 1)
        );
    }

    /// v7 F4: `MAX_INVITE_ROSTER_ENTRIES` is DERIVED, not chosen. The
    /// worst-case mintable fixture below puts every capped string at its
    /// cap, carries both inline ML-DSA-65 keys (1 952 B → 2 604 base64
    /// chars) and both signatures (3 309 B → 4 412 base64 chars), and N
    /// projection entries with max-length ids/hashes and the longest role
    /// and state wire strings — measured through the FINAL encoder
    /// (`to_link`). The largest N fitting the 40 960-byte link budget is
    /// the derived maximum; raising the constant above it fails here.
    #[test]
    fn f4_worst_case_link_budget_pins_roster_cap() {
        fn worst_case(n: usize) -> SignedInvite {
            let hex64 = || "ab".repeat(32);
            let mut invite = SignedInvite::new(
                "cd".repeat(32),
                "n".repeat(INVITE_MAX_GROUP_NAME),
                &agent(1),
                0,
            );
            invite.stable_group_id = Some("cd".repeat(32));
            invite.group_created_at = Some(u64::MAX);
            invite.group_description = Some("d".repeat(INVITE_MAX_GROUP_DESCRIPTION));
            invite.invite_secret = hex64();
            invite.created_at = u64::MAX;
            invite.expires_at = u64::MAX;
            invite.policy = Some(GroupPolicy {
                admission: GroupAdmission::OwnerCertified(UserId([0x5A; 32])),
                ..GroupPolicy::default()
            });
            invite.genesis_creation_nonce = Some(hex64());
            invite.base_state_revision = Some(u64::MAX);
            invite.base_state_hash = Some(hex64());
            invite.base_prev_state_hash = Some(hex64());
            let home = HomeMetadata {
                primary_agent: hex64(),
                placements: BTreeMap::new(),
                provisioned_at_ms: u64::MAX,
            };
            invite.base_home = Some(home.clone());
            invite.secure_plane = Some(SecureGroupPlane::TreeKem);
            invite.base_secret_epoch = Some(u64::MAX);
            invite.base_security_binding = Some(hex64());
            invite.public_meta = Some(GroupPublicMeta {
                name: "n".repeat(INVITE_MAX_GROUP_NAME),
                description: "d".repeat(INVITE_MAX_GROUP_DESCRIPTION),
                tags: vec!["t".repeat(INVITE_MAX_TAG_LEN); INVITE_MAX_TAGS],
                avatar_url: Some("u".repeat(INVITE_MAX_URL_LEN)),
                banner_url: Some("u".repeat(INVITE_MAX_URL_LEN)),
                home_digest: Some(compute_home_digest(&home)),
            });
            invite.base_roster = Some(
                (0..n)
                    .map(|i| {
                        (
                            format!("{i:064x}"),
                            RosterMemberSnapshot {
                                role: GroupRole::Moderator,
                                state: GroupMemberState::Pending,
                                treekem_key_package_hash: Some(hex64()),
                                certificate_digest: Some(hex64()),
                            },
                        )
                    })
                    .collect(),
            );
            invite.creator = Some(hex64());
            invite.intended_joiner = Some(hex64());
            invite.inviter = hex64();
            invite.inviter_public_key_b64 = B64_STD.encode([0u8; 1952]);
            invite.owner_public_key_b64 = Some(B64_STD.encode([0u8; 1952]));
            invite.inviter_signature_b64 = B64_STD.encode([0u8; 3309]);
            invite.owner_countersignature_b64 = Some(B64_STD.encode([0u8; 3309]));
            invite
        }

        // The fixture is a MINTABLE worst case at the constant: structural
        // rules hold, no D5 cap fires, and the final encoder accepts it.
        let at_cap = worst_case(MAX_INVITE_ROSTER_ENTRIES);
        assert!(InviteSignedViewV4::from_invite(&at_cap).is_ok());
        assert_eq!(at_cap.v4_field_caps_violation(), None);
        let cap_link = at_cap
            .encode_link()
            .expect("worst case at the roster cap fits the budget");
        assert!(cap_link.len() <= INVITE_LINK_MAX_BYTES);

        // Derive the largest N whose worst-case link fits (link length is
        // monotonic in N, so stop at the first overflow).
        let mut derived_max = 0usize;
        for n in 1..=1024usize {
            if worst_case(n).to_link().len() <= INVITE_LINK_MAX_BYTES {
                derived_max = n;
            } else {
                break;
            }
        }
        assert!(
            MAX_INVITE_ROSTER_ENTRIES <= derived_max,
            "MAX_INVITE_ROSTER_ENTRIES ({MAX_INVITE_ROSTER_ENTRIES}) exceeds the \
             worst-case derived maximum ({derived_max})"
        );
        // The final encoder refuses the first over-budget N.
        let over_budget = worst_case(derived_max + 1);
        let err = over_budget
            .encode_link()
            .expect_err("first over-budget N must be refused");
        assert_eq!(err.limit, INVITE_LINK_MAX_BYTES);
        assert_eq!(err.actual, over_budget.to_link().len());
        assert!(err.actual > INVITE_LINK_MAX_BYTES);
    }
}
