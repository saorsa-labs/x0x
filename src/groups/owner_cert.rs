//! ADR-0038: OwnerCertified admission — certificate-chain verification.
//!
//! A group whose [`GroupAdmission`](crate::groups::policy::GroupAdmission)
//! axis is `OwnerCertified(owner)` admits (and keeps) only agents whose
//! `AgentCertificate` chains to `owner`: the cert signature must verify under
//! the owner's user key, bind exactly the member's agent id, be unexpired,
//! and the agent must not be in the local ADR-0018 revocation set.
//!
//! Enforcement points (all fail closed):
//!
//! 1. **Invite-accept** — the inviter authority verifies the joiner's cert
//!    before consuming the invite and committing `MemberAdded`. Admin role is
//!    inert here: an admin-issued invite to an uncertified agent is rejected.
//! 2. **Every state-commit seal** —
//!    [`GroupInfo::seal_commit_with_owner_certs`] re-verifies every active
//!    member and evicts (roster-removes) the failures before the commit is
//!    signed, so a stolen invite or a revoked/expired cert cannot survive the
//!    next seal.
//!
//! Certificate RESOLUTION is the V3 announce blob-fetch path (PR #419): the
//! verifier daemon resolves `(user_id, AgentCertificate)` pairs from verified
//! announce blobs cached off the mesh — no side channel. This module is pure:
//! callers snapshot the evidence (certs + revocations + clock) into
//! [`OwnerCertEvidence`] and the predicates here never touch the network.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::groups::member::GroupMember;
use crate::identity::{AgentCertificate, UserId};

/// Wall-clock unix seconds for pure (evidence-snapshot-free) verifications
/// — receiver-side event gates and the restore-from-disk sweep. Returns 0
/// if the clock is before the epoch (verification then fails closed for
/// expiring certs, which is the safe direction).
#[must_use]
pub fn restore_clock_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// ADR-0038 round-2 (finding 5): how long a member may sit with MISSING
/// certificate evidence (`NoCertificate`) before a seal evicts it. The
/// announce pipeline is eventually-consistent — a cold cache miss triggers
/// a background blob fetch and the NEXT heartbeat lands the pair, and
/// invite volleys re-send (#333) — so a member whose evidence simply has
/// not arrived yet gets a retry window instead of a destructive eviction.
/// Definitive failures (revoked, invalid signature, wrong owner, wrong
/// agent, expired) get NO grace: they are facts about the certificate,
/// not about fetch lag.
pub const OWNER_CERT_MISSING_EVIDENCE_GRACE_SECS: u64 = 300;

/// Snapshot of the certificate evidence available to a verifier at one
/// decision point (invite-accept or seal).
/// Deliberately a value snapshot, not a live view: the underlying discovery
/// cache and revocation set are async-guarded, while the verification
/// predicates here are pure and synchronous (and callable from the sealing
/// path, which must not hold cross-lock await points). Seals are rare,
/// membership-scale events, so the copy cost is irrelevant next to the
/// ML-DSA-65 signature verifications each check performs.
#[derive(Debug, Clone, Default)]
pub struct OwnerCertEvidence {
    /// Verified certificates by agent id (hex), resolved via the V3 announce
    /// blob path or held locally by this daemon's own identity. A member
    /// whose latest announce committed to a digest that has NOT resolved
    /// yet is ABSENT here (fetch in flight) — see `digests`.
    certs: HashMap<String, AgentCertificate>,
    /// The cert digest each agent's LATEST announcement committed to (hex
    /// keyed). Round-3: this is what couples evidence freshness to the
    /// announce stream — a digest present without a matching `certs` entry
    /// means a warranted fetch is outstanding; a digest that differs from
    /// the roster-embedded cert's digest means the embedded cert is STALE
    /// and must not seat the member.
    digests: HashMap<String, [u8; 32]>,
    /// Agent ids (hex) present in the local ADR-0018 revocation set.
    revoked: HashSet<String>,
    /// Wall-clock unix seconds used for expiry checks.
    now_unix: u64,
}

impl OwnerCertEvidence {
    /// Empty evidence at `now_unix` — no certs, no revocations.
    #[must_use]
    pub fn new(now_unix: u64) -> Self {
        Self {
            certs: HashMap::new(),
            digests: HashMap::new(),
            revoked: HashSet::new(),
            now_unix,
        }
    }

    /// Record a (verified) certificate for `agent_hex`, with the announce
    /// digest it was resolved under (when known).
    pub fn insert_cert(&mut self, agent_hex: impl Into<String>, cert: AgentCertificate) {
        let agent_hex = agent_hex.into();
        let digest = crate::announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone()));
        self.digests.insert(agent_hex.clone(), digest);
        self.certs.insert(agent_hex, cert);
    }

    /// Record the digest an agent's LATEST announcement committed to, when
    /// the certificate itself has not resolved yet (warranted fetch in
    /// flight). Absent cert + present digest = evidence in flight.
    pub fn observe_pending_digest(&mut self, agent_hex: impl Into<String>, digest: [u8; 32]) {
        let agent_hex = agent_hex.into();
        self.digests.insert(agent_hex, digest);
    }

    /// Record that `agent_hex` is in the local revocation set.
    pub fn mark_revoked(&mut self, agent_hex: impl Into<String>) {
        self.revoked.insert(agent_hex.into());
    }

    /// The digest-coupled certificate resolved for `agent_hex`, if any.
    /// Returns `None` while a warranted fetch is outstanding.
    #[must_use]
    pub fn cert_for(&self, agent_hex: &str) -> Option<&AgentCertificate> {
        self.certs.get(agent_hex)
    }

    /// The digest the agent's latest announce committed to, when observed.
    #[must_use]
    pub fn digest_for(&self, agent_hex: &str) -> Option<[u8; 32]> {
        self.digests.get(agent_hex).copied()
    }

    /// Whether a warranted fetch is outstanding for `agent_hex` (announce
    /// committed to a digest whose certificate has not resolved here).
    #[must_use]
    pub fn fetch_in_flight(&self, agent_hex: &str) -> bool {
        self.digest_for(agent_hex).is_some() && self.cert_for(agent_hex).is_none()
    }

    /// Whether `agent_hex` is locally known to be revoked (ADR-0018).
    #[must_use]
    pub fn is_revoked(&self, agent_hex: &str) -> bool {
        self.revoked.contains(agent_hex)
    }

    /// Wall-clock unix seconds for expiry evaluation.
    #[must_use]
    pub fn now_unix(&self) -> u64 {
        self.now_unix
    }
}

/// Why a member failed OwnerCertified verification. Ordered by the sequence
/// the checks run: revocation is examined FIRST because positive knowledge of
/// compromise must dominate every other consideration (a revoked agent must
/// never pass because its cert otherwise looks valid).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerCertFailure {
    /// The agent is in the local ADR-0018 revocation set.
    Revoked,
    /// No certificate could be resolved for the agent (announce blob not
    /// fetched yet, or the agent never held one).
    NoCertificate,
    /// The certificate signature does not verify under the owner user key.
    InvalidSignature,
    /// The certificate chains to a different `UserId` than the group owner.
    NotChainedToOwner,
    /// The certificate binds a different agent id than the member.
    AgentMismatch,
    /// The certificate's `not_after` has passed (with clock-skew tolerance).
    Expired,
}

impl std::fmt::Display for OwnerCertFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Revoked => "agent is revoked (ADR-0018)",
            Self::NoCertificate => "no agent certificate resolved",
            Self::InvalidSignature => "certificate signature invalid",
            Self::NotChainedToOwner => "certificate does not chain to the group owner",
            Self::AgentMismatch => "certificate binds a different agent id",
            Self::Expired => "certificate expired",
        };
        f.write_str(text)
    }
}

/// Verify one member against the OwnerCertified admission rule.
///
/// `member_agent_hex` is the roster/member id (hex, as carried in
/// `members_v2` keys and `MemberJoined.member_agent_id`).
pub fn verify_owner_certified_member(
    owner: &UserId,
    member_agent_hex: &str,
    evidence: &OwnerCertEvidence,
) -> Result<(), OwnerCertFailure> {
    // Revocation first (positive knowledge of compromise dominates), then
    // resolve the announce-path certificate and run the pure core over it.
    // A cache MISS is `NoCertificate` — deny + retryable, never fail-open:
    // the background blob fetch (PR #419) fills the discovery cache, and
    // the next invite volley / seal re-runs this check.
    if evidence.is_revoked(member_agent_hex) {
        return Err(OwnerCertFailure::Revoked);
    }
    let cert = evidence
        .cert_for(member_agent_hex)
        .ok_or(OwnerCertFailure::NoCertificate)?;
    verify_cert_against_owner(
        owner,
        member_agent_hex,
        cert,
        evidence.is_revoked(member_agent_hex),
        evidence.now_unix(),
    )
}

/// Every ACTIVE member of `members_v2` that fails OwnerCertified
/// verification against `owner`, in roster (BTreeMap) order so evictions are
/// deterministic. Non-active members (Removed/Pending/Banned) hold no access
/// and are not re-verified.
pub fn failing_active_members(
    owner: &UserId,
    members_v2: &BTreeMap<String, GroupMember>,
    evidence: &OwnerCertEvidence,
) -> Vec<(String, OwnerCertFailure)> {
    members_v2
        .iter()
        .filter(|(_, m)| m.is_active())
        .filter_map(|(agent_hex, _)| {
            verify_owner_certified_member(owner, agent_hex, evidence)
                .err()
                .map(|failure| (agent_hex.clone(), failure))
        })
        .collect()
}

/// BLAKE3-256 (hex) over the certificate's canonical bincode bytes — the
/// digest the ADR-0038 roster root binds per cert-carrying member
/// (`compute_roster_root`). Serialization of this struct is infallible in
/// practice; the fallback (digest over the agent public key) keeps the
/// function total and deterministic without panicking.
#[must_use]
pub fn certificate_digest_hex(cert: &AgentCertificate) -> String {
    let bytes = bincode::serialize(cert).unwrap_or_else(|_| cert.agent_public_key().to_vec());
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// Verify one certificate against the admission owner, given the live
/// revocation flag and clock — the pure core shared by evidence-based
/// (announce-resolved) checks and roster-embedded (committed-evidence)
/// checks.
///
/// Expiry policy (ADR-0018 / `identity.rs` `AgentCertificate`): a
/// certificate with `not_after == None` is a LEGACY certificate that never
/// expires — it stays valid until the owner revokes it (an issuer- or
/// self-revocation in the ADR-0018 set). A present `not_after` is enforced
/// with the fleet's clock-skew tolerance. Choosing "absent expiry ⇒
/// revoked-at-seal" would evict every pre-#130 fleet cert on upgrade, so
/// absent expiry is honored as valid-indefinitely, and revocation is the
/// kill switch for stale legacy certificates.
pub fn verify_cert_against_owner(
    owner: &UserId,
    member_agent_hex: &str,
    cert: &AgentCertificate,
    revoked: bool,
    now_unix: u64,
) -> Result<(), OwnerCertFailure> {
    // Revocation first: positive knowledge of compromise outranks everything
    // else — a still-valid-looking certificate must not rescue a revoked key.
    if revoked {
        return Err(OwnerCertFailure::Revoked);
    }
    cert.verify()
        .map_err(|_| OwnerCertFailure::InvalidSignature)?;
    // The chain: the cert must have been signed by the group owner's user
    // key. `cert.user_id()` is derived from the user public key inside the
    // (just-verified) certificate signature, so this comparison IS the
    // chain check.
    let cert_user = cert
        .user_id()
        .map_err(|_| OwnerCertFailure::InvalidSignature)?;
    if &cert_user != owner {
        return Err(OwnerCertFailure::NotChainedToOwner);
    }
    // The cert must bind exactly the member claiming it — otherwise agent A
    // could present agent B's owner-signed cert.
    let cert_agent = cert
        .agent_id()
        .map_err(|_| OwnerCertFailure::InvalidSignature)?;
    let cert_agent_hex = hex::encode(cert_agent.as_bytes());
    if !cert_agent_hex.eq_ignore_ascii_case(member_agent_hex) {
        return Err(OwnerCertFailure::AgentMismatch);
    }
    if cert.is_expired(now_unix) {
        return Err(OwnerCertFailure::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::member::GroupMemberState;
    use crate::identity::{AgentKeypair, UserKeypair};

    fn owner_and_certified_agent() -> (UserKeypair, AgentKeypair, AgentCertificate) {
        let user = UserKeypair::generate().expect("user keypair");
        let agent = AgentKeypair::generate().expect("agent keypair");
        let cert = AgentCertificate::issue(&user, &agent).expect("cert issue");
        (user, agent, cert)
    }

    fn agent_hex(agent: &AgentKeypair) -> String {
        hex::encode(agent.agent_id().as_bytes())
    }
    fn active_member(hex: &str) -> GroupMember {
        let mut m = GroupMember::new_member(hex.to_string(), None, None, 0);
        m.state = GroupMemberState::Active;
        m
    }

    #[test]
    fn certified_agent_passes() {
        // WHY: the positive case — a fresh owner-signed cert binding exactly
        // this agent — must verify, else Home could never hold any member.
        let (user, agent, cert) = owner_and_certified_agent();
        let mut evidence = OwnerCertEvidence::new(1_000);
        evidence.insert_cert(agent_hex(&agent), cert);
        assert_eq!(
            verify_owner_certified_member(&user.user_id(), &agent_hex(&agent), &evidence),
            Ok(())
        );
    }

    #[test]
    fn missing_certificate_fails_closed() {
        // WHY: "no evidence" must mean "no admission" — otherwise a node
        // that simply has not fetched the announce blob yet would admit (or
        // keep) an uncertified agent.
        let (user, agent, _cert) = owner_and_certified_agent();
        let evidence = OwnerCertEvidence::new(1_000);
        assert_eq!(
            verify_owner_certified_member(&user.user_id(), &agent_hex(&agent), &evidence),
            Err(OwnerCertFailure::NoCertificate)
        );
    }

    #[test]
    fn revoked_agent_fails_even_with_valid_certificate() {
        // WHY: revocation is positive knowledge of compromise and must
        // outrank a still-verifiable signature — checked FIRST so a
        // later-added expiry or chain check can never mask it.
        let (user, agent, cert) = owner_and_certified_agent();
        let hex = agent_hex(&agent);
        let mut evidence = OwnerCertEvidence::new(1_000);
        evidence.insert_cert(hex.clone(), cert);
        evidence.mark_revoked(hex.clone());
        assert_eq!(
            verify_owner_certified_member(&user.user_id(), &hex, &evidence),
            Err(OwnerCertFailure::Revoked)
        );
    }

    #[test]
    fn foreign_owner_certificate_fails() {
        // WHY: a cert signed by ANOTHER user must not admit — this is the
        // "no other human can ever join" guarantee.
        let (_owner, agent, cert) = owner_and_certified_agent();
        let stranger = UserKeypair::generate().expect("stranger keypair");
        let mut evidence = OwnerCertEvidence::new(1_000);
        evidence.insert_cert(agent_hex(&agent), cert);
        assert_eq!(
            verify_owner_certified_member(&stranger.user_id(), &agent_hex(&agent), &evidence),
            Err(OwnerCertFailure::NotChainedToOwner)
        );
    }

    #[test]
    fn certificate_for_other_agent_fails() {
        // WHY: presenting someone else's owner-signed cert must fail the
        // agent binding, else one certified agent could vouch the fleet.
        let (user, _agent, cert) = owner_and_certified_agent();
        let other = AgentKeypair::generate().expect("other keypair");
        let mut evidence = OwnerCertEvidence::new(1_000);
        evidence.insert_cert(agent_hex(&other), cert);
        assert_eq!(
            verify_owner_certified_member(&user.user_id(), &agent_hex(&other), &evidence),
            Err(OwnerCertFailure::AgentMismatch)
        );
    }

    #[test]
    fn expired_certificate_fails() {
        // WHY: ADR-0018 expiry must actually evict — a stale cert that still
        // verifies must not carry membership past `not_after`.
        let user = UserKeypair::generate().expect("user keypair");
        let agent = AgentKeypair::generate().expect("agent keypair");
        let past = 1_700_000_000;
        let cert =
            AgentCertificate::issue_with_expiry(&user, &agent, Some(past)).expect("cert issue");
        let mut evidence = OwnerCertEvidence::new(past + 10 * 365 * 24 * 3600);
        evidence.insert_cert(agent_hex(&agent), cert);
        assert_eq!(
            verify_owner_certified_member(&user.user_id(), &agent_hex(&agent), &evidence),
            Err(OwnerCertFailure::Expired)
        );
    }

    #[test]
    fn tampered_certificate_fails_signature() {
        // WHY: the signature is the only thing binding the cert payload to
        // the owner's key. Corrupt one byte inside the serialized signature
        // (the trailing 9 bytes are `issued_at` + `not_after` tag, so the
        // byte just before them is signature payload) and the cert must
        // fail at signature verification rather than being trusted.
        let (user, agent, cert) = owner_and_certified_agent();
        let mut bytes = bincode::serialize(&cert).expect("cert serializes for tampering");
        let corrupt_at = bytes.len() - 10;
        bytes[corrupt_at] ^= 0xFF;
        let tampered: AgentCertificate =
            bincode::deserialize(&bytes).expect("tampered cert still deserializes");
        assert_ne!(tampered, cert, "corruption must change the certificate");
        let mut evidence = OwnerCertEvidence::new(1_000);
        evidence.insert_cert(agent_hex(&agent), tampered);
        assert_eq!(
            verify_owner_certified_member(&user.user_id(), &agent_hex(&agent), &evidence),
            Err(OwnerCertFailure::InvalidSignature)
        );
    }

    #[test]
    fn failing_active_members_skips_inactive_and_orders_by_roster() {
        // WHY: eviction must sweep exactly the ACCESS-BEARING roster —
        // Removed/Pending members hold no key material, and re-verifying
        // them would produce spurious eviction noise; order must be
        // deterministic (BTreeMap) so committed rosters are reproducible.
        let (user, good, good_cert) = owner_and_certified_agent();
        let bad = AgentKeypair::generate().expect("bad keypair");
        let mut members = BTreeMap::new();
        members.insert(agent_hex(&bad), active_member(&agent_hex(&bad)));
        members.insert(agent_hex(&good), active_member(&agent_hex(&good)));
        let removed = "ff".repeat(32);
        members.insert(removed.clone(), {
            let mut m = active_member(&removed);
            m.state = GroupMemberState::Removed;
            m
        });
        let mut evidence = OwnerCertEvidence::new(1_000);
        evidence.insert_cert(agent_hex(&good), good_cert);
        let failing = failing_active_members(&user.user_id(), &members, &evidence);
        assert_eq!(
            failing,
            vec![(agent_hex(&bad), OwnerCertFailure::NoCertificate)]
        );
    }
}
