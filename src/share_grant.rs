//! ShareGrant (ADR-0070 §2, slice 3): an owner-signed, scoped, expiring and
//! revocable grant that lets another human (or a user-less agent) reach a
//! chosen subset of the owner's agents.
//!
//! # Model
//!
//! A [`ShareGrant`] names the owner (grantor), the grantee
//! ([`Grantee::User`] or [`Grantee::Agent`]), a non-empty sorted set of the
//! owner's agents, a non-empty capability set ([`ShareCap`]), and a
//! `[not_before, expiry)` validity window. It is signed with the OWNER user
//! key over a domain-separated canonical encoding ([`ShareGrant::signed_bytes`]).
//! Authority is the owner key only: a daemon honours a grant only when the
//! grant's owner is its own local owner, and only for its own agent.
//!
//! # Delivery
//!
//! The owner install delivers a grant as a durable typed DM
//! (`x0x-sharegrant-v1\0` ‖ bincode) to the grantee's agents and to each
//! shared agent's daemon. The receiving handler verifies the grant, stores
//! it, and only then completes the DM — so the durable v2 ACK is released
//! only once the grant is persisted. A malformed, forged, expired or
//! unrelated grant completes with `Err`: the ACK is withheld, nothing is
//! stored, and the bytes never reach generic DM consumers (the typed route
//! owns the prefix).
//!
//! # Storage
//!
//! [`ShareGrantStore`] keeps two roles in one file (`share-grants.bin`,
//! written durably — temp, fsync, rename, dir fsync — with mode 0600): **issued** grants (signed by this
//! install's owner — the set enforcement reads) and **received** grants
//! (this install is the grantee; informational).
//!
//! # Fallback
//!
//! Unknown, not-yet-valid, expired, revoked, malformed or wrong-owner
//! grants evaluate as if no grant existed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaPublicKey, MlDsaSignature,
};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use tokio::sync::RwLock;

use crate::contacts::ContactStore;
use crate::dm_inbox::{
    AuthenticatedMachineBindings, DmTypedPayload, DmTypedPayloadCompletion,
    DmTypedPayloadCompletionResult,
};
use crate::identity::{AgentId, MachineId, UserId, UserKeypair};
use crate::owner_trust::OwnerTrust;
use crate::revocation::RevocationSet;
use crate::DiscoveredAgent;

/// Versioned, NUL-terminated DM prefix of a share-grant delivery.
pub const SHARE_GRANT_DM_PREFIX: &[u8] = b"x0x-sharegrant-v1\0";

/// #926 (ADR-0070 §2): grantee-attached grant fetch — a daemon that
/// missed a grant delivery can request it from a holder by id.
/// Request wire: `SHARE_GRANT_FETCH_DM_PREFIX ‖ grant_id[32]`.
pub const SHARE_GRANT_FETCH_DM_PREFIX: &[u8] = b"x0x-sharegrant-fetch-v1\0";
/// Response wire: `SHARE_GRANT_FETCH_RESPONSE_DM_PREFIX ‖ grant_dm_payload`
/// (the SAME signed wire form a direct delivery carries, so one verifier
/// serves both paths).
/// #967 r3 (B3): the grantee-side ATTACHMENT frame of ADR-0070 par 2 —
/// prefix + bincode(Vec<grant_id>) (at most 32 ids), sent alongside a DM
/// open so a daemon that missed a delivery can request the grants.
pub const SHARE_GRANT_HINT_DM_PREFIX: &[u8] = b"x0x-sharegrant-hint-v1\0";
/// Cap on ids one hint frame carries (and the receiver decodes).
pub const SHARE_GRANT_HINT_MAX_IDS: usize = 32;
/// How often the grantee re-attaches hints for one recipient.
pub const SHARE_GRANT_HINT_INTERVAL_MS: u64 = 30_000;
pub const SHARE_GRANT_FETCH_RESPONSE_DM_PREFIX: &[u8] = b"x0x-sharegrant-fetch-response-v1\0";
/// How long a fetch this node sent stays "in flight" (the only responses
/// accepted for that id) and how long a re-fetch is suppressed.
pub const GRANT_FETCH_TTL_MS: u64 = 60_000;
/// Cap on the (peer-keyed) in-flight map — swept to the live universe on
/// every insert, oldest evicted at the cap.
pub const GRANT_FETCH_MAX_ENTRIES: usize = 4096;

/// Domain separation for the owner signature.
const SHARE_GRANT_SIG_DOMAIN: &[u8] = b"x0x-sharegrant-sig-v1";

/// Magic of the on-disk grant store.
const STORE_MAGIC: &[u8; 4] = b"X0SG";

/// Store file name in the daemon data dir.
pub const SHARE_GRANT_STORE_FILE: &str = "share-grants.bin";

/// Upper bound on one encoded grant (well above a real grant: two ML-DSA-65
/// blobs are ~5.3 KB, 64 agents are 2 KB).
pub const MAX_SHARE_GRANT_BYTES: usize = 32 * 1024;

/// Maximum agents one grant may cover.
pub const MAX_GRANT_AGENTS: usize = 64;

/// Maximum ports in one `Connect` capability.
pub const MAX_GRANT_PORTS: usize = 64;

/// Maximum grants held per role; beyond it expired grants are pruned and a
/// still-full store refuses new grants.
pub const MAX_STORED_GRANTS: usize = 1024;

/// Who a grant is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grantee {
    /// Every agent whose `AgentCertificate` chains to this user.
    User(UserId),
    /// Exactly this agent (for a grantee with no user identity).
    Agent(AgentId),
}

/// One capability a grant confers on the covered agents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareCap {
    /// DMs to a shared agent are accepted (`Unknown` → `Accept`).
    Dm,
    /// `principal = "grant"` exec ACL entries may match.
    Exec,
    /// `principal = "grant"` connect ACL entries may match, for these
    /// loopback target ports only.
    Connect {
        /// Sorted, unique, non-zero ports.
        ports: Vec<u16>,
    },
    /// The grantee may seed groups for shared agents without a contact
    /// entry. Never satisfies `GroupAdmission::OwnerCertified` (Home).
    GroupInvite,
    /// ADR-0073 calling. Carried and signed; not yet enforced anywhere.
    Call,
}

impl ShareCap {
    fn tag(&self) -> u8 {
        match self {
            Self::Dm => 1,
            Self::Exec => 2,
            Self::Connect { .. } => 3,
            Self::GroupInvite => 4,
            Self::Call => 5,
        }
    }
}

/// An owner-signed share grant (ADR-0070 §2).
///
/// `owner_public_key` is carried so the grant verifies from its own bytes;
/// `owner` must equal its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareGrant {
    /// Random grant id.
    pub grant_id: [u8; 32],
    /// The grantor; the signer.
    pub owner: UserId,
    /// The grantor's ML-DSA-65 public key.
    pub owner_public_key: Vec<u8>,
    /// Who the grant is for.
    pub grantee: Grantee,
    /// Non-empty, sorted, unique subset of the owner's agents.
    pub agents: Vec<AgentId>,
    /// Non-empty capability set; at most one `Connect`.
    pub caps: BTreeSet<ShareCap>,
    /// Unix seconds; valid from here (inclusive).
    pub not_before: u64,
    /// Unix seconds; valid until here (exclusive). Mandatory.
    pub expiry: u64,
    /// ML-DSA-65 signature by the owner key over [`Self::signed_bytes`].
    pub signature: Vec<u8>,
}

/// Why a grant was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareGrantError {
    /// Structurally invalid (empty agents/caps, bad ports, bad window, …).
    #[error("invalid share grant: {0}")]
    Invalid(String),
    /// The signature or owner key does not verify.
    #[error("share grant signature invalid: {0}")]
    BadSignature(String),
    /// Wire bytes are not a canonical encoded grant.
    #[error("malformed share grant: {0}")]
    Malformed(String),
    /// The grant is past its expiry.
    #[error("share grant expired")]
    Expired,
    /// The grant is neither signed by this install's owner nor addressed to
    /// this install.
    #[error("share grant is not for this install")]
    NotForUs,
    /// Same id already held with different content.
    #[error("a different share grant with this id is already held")]
    Conflict,
    /// The store is full, unreadable, or could not be written.
    #[error("share grant store: {0}")]
    Store(String),
}

impl ShareGrant {
    /// Canonical, domain-separated bytes the owner signs. Fixed-width fields
    /// and explicit counts: no two distinct grants share an encoding.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SHARE_GRANT_SIG_DOMAIN.len() + 32 + 32 + 8 + self.owner_public_key.len() + 33 + 64,
        );
        out.extend_from_slice(SHARE_GRANT_SIG_DOMAIN);
        out.extend_from_slice(&self.grant_id);
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(&(self.owner_public_key.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.owner_public_key);
        match &self.grantee {
            Grantee::User(user) => {
                out.push(1);
                out.extend_from_slice(user.as_bytes());
            }
            Grantee::Agent(agent) => {
                out.push(2);
                out.extend_from_slice(agent.as_bytes());
            }
        }
        out.extend_from_slice(&(self.agents.len() as u32).to_le_bytes());
        for agent in &self.agents {
            out.extend_from_slice(agent.as_bytes());
        }
        out.extend_from_slice(&(self.caps.len() as u32).to_le_bytes());
        for cap in &self.caps {
            out.push(cap.tag());
            if let ShareCap::Connect { ports } = cap {
                out.extend_from_slice(&(ports.len() as u32).to_le_bytes());
                for port in ports {
                    out.extend_from_slice(&port.to_le_bytes());
                }
            }
        }
        out.extend_from_slice(&self.not_before.to_le_bytes());
        out.extend_from_slice(&self.expiry.to_le_bytes());
        out
    }

    /// Structural checks (no crypto): non-empty sorted unique agents within
    /// the cap, non-empty caps with at most one `Connect` whose ports are
    /// sorted, unique, non-zero and bounded, `not_before < expiry`, and no
    /// self-grant (`grantee` is not the owner, nor one of the shared agents).
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`] naming the problem.
    pub fn validate(&self) -> Result<(), ShareGrantError> {
        let invalid = |m: &str| Err(ShareGrantError::Invalid(m.to_string()));
        if self.agents.is_empty() {
            return invalid("agents must not be empty");
        }
        if self.agents.len() > MAX_GRANT_AGENTS {
            return invalid("too many agents");
        }
        if self.agents.windows(2).any(|w| w[0].0 >= w[1].0) {
            return invalid("agents must be sorted and unique");
        }
        if self.caps.is_empty() {
            return invalid("caps must not be empty");
        }
        let mut connect_caps = 0usize;
        for cap in &self.caps {
            if let ShareCap::Connect { ports } = cap {
                connect_caps += 1;
                if ports.is_empty() || ports.len() > MAX_GRANT_PORTS {
                    return invalid("connect ports must be non-empty and bounded");
                }
                if ports.contains(&0) || ports.windows(2).any(|w| w[0] >= w[1]) {
                    return invalid("connect ports must be sorted, unique and non-zero");
                }
            }
        }
        if connect_caps > 1 {
            return invalid("at most one connect capability");
        }
        if self.not_before >= self.expiry {
            return invalid("not_before must be before expiry");
        }
        match self.grantee {
            Grantee::User(user) if user == self.owner => {
                return invalid("an owner cannot grant to itself");
            }
            Grantee::Agent(agent) if self.agents.contains(&agent) => {
                return invalid("a shared agent cannot be its own grantee");
            }
            _ => {}
        }
        Ok(())
    }

    /// Full verification: [`Self::validate`], the owner key hashes to
    /// `owner`, and the signature verifies over [`Self::signed_bytes`].
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`] or [`ShareGrantError::BadSignature`].
    pub fn verify(&self) -> Result<(), ShareGrantError> {
        self.validate()?;
        let key = MlDsaPublicKey::from_bytes(&self.owner_public_key)
            .map_err(|_| ShareGrantError::BadSignature("invalid owner public key".into()))?;
        if UserId::from_public_key(&key) != self.owner {
            return Err(ShareGrantError::BadSignature(
                "owner public key does not match owner".into(),
            ));
        }
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| ShareGrantError::BadSignature(format!("signature format: {e:?}")))?;
        verify_with_ml_dsa(&key, &self.signed_bytes(), &signature)
            .map_err(|e| ShareGrantError::BadSignature(format!("{e:?}")))
    }

    /// Build and sign a grant with the owner key. Agents are sorted and
    /// de-duplicated; `Connect` ports are sorted, de-duplicated and merged
    /// into one capability.
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`] if the result fails [`Self::validate`],
    /// or [`ShareGrantError::BadSignature`] if signing fails.
    pub fn sign(
        owner_key: &UserKeypair,
        grant_id: [u8; 32],
        grantee: Grantee,
        agents: Vec<AgentId>,
        caps: Vec<ShareCap>,
        not_before: u64,
        expiry: u64,
    ) -> Result<Self, ShareGrantError> {
        let mut agents = agents;
        agents.sort_by_key(|a| a.0);
        agents.dedup();
        let mut ports: BTreeSet<u16> = BTreeSet::new();
        let mut has_connect = false;
        let mut set = BTreeSet::new();
        for cap in caps {
            match cap {
                ShareCap::Connect { ports: p } => {
                    has_connect = true;
                    ports.extend(p);
                }
                other => {
                    set.insert(other);
                }
            }
        }
        if has_connect {
            set.insert(ShareCap::Connect {
                ports: ports.into_iter().collect(),
            });
        }
        let mut grant = Self {
            grant_id,
            owner: owner_key.user_id(),
            owner_public_key: owner_key.public_key().as_bytes().to_vec(),
            grantee,
            agents,
            caps: set,
            not_before,
            expiry,
            signature: Vec::new(),
        };
        grant.validate()?;
        let signature = sign_with_ml_dsa(owner_key.secret_key(), &grant.signed_bytes())
            .map_err(|e| ShareGrantError::BadSignature(format!("signing failed: {e:?}")))?;
        grant.signature = signature.as_bytes().to_vec();
        Ok(grant)
    }

    /// Whether `now_unix` is inside `[not_before, expiry)`.
    #[must_use]
    pub fn is_active_at(&self, now_unix: u64) -> bool {
        self.not_before <= now_unix && now_unix < self.expiry
    }

    /// Hex grant id.
    #[must_use]
    pub fn id_hex(&self) -> String {
        hex::encode(self.grant_id)
    }

    /// Typed DM payload: `SHARE_GRANT_DM_PREFIX ‖ bincode(grant)`.
    ///
    /// # Errors
    /// [`ShareGrantError::Malformed`] on encode failure.
    pub fn to_dm_payload(&self) -> Result<Vec<u8>, ShareGrantError> {
        let body = bincode::serialize(self)
            .map_err(|e| ShareGrantError::Malformed(format!("encode: {e}")))?;
        let mut out = Vec::with_capacity(SHARE_GRANT_DM_PREFIX.len() + body.len());
        out.extend_from_slice(SHARE_GRANT_DM_PREFIX);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Strictly decode a typed DM payload: the prefix, a size bound, and a
    /// canonical bincode body (re-encoding must reproduce it exactly, so
    /// trailing or non-canonical bytes are refused). Verification is a
    /// separate step ([`Self::verify`]).
    ///
    /// # Errors
    /// [`ShareGrantError::Malformed`].
    pub fn from_dm_payload(payload: &[u8]) -> Result<Self, ShareGrantError> {
        let body = payload
            .strip_prefix(SHARE_GRANT_DM_PREFIX)
            .ok_or_else(|| ShareGrantError::Malformed("missing prefix".into()))?;
        if body.len() > MAX_SHARE_GRANT_BYTES {
            return Err(ShareGrantError::Malformed("oversized".into()));
        }
        let grant: Self = strict_decode(body, MAX_SHARE_GRANT_BYTES as u64)
            .map_err(|e| ShareGrantError::Malformed(format!("decode: {e}")))?;
        let canonical = bincode::serialize(&grant)
            .map_err(|e| ShareGrantError::Malformed(format!("re-encode: {e}")))?;
        if canonical != body {
            return Err(ShareGrantError::Malformed("non-canonical encoding".into()));
        }
        Ok(grant)
    }

    /// Lifecycle status at `now_unix`, given whether it is revoked.
    #[must_use]
    pub fn status_at(&self, now_unix: u64, revoked: bool) -> &'static str {
        if revoked {
            "revoked"
        } else if now_unix < self.not_before {
            "not_yet_valid"
        } else if now_unix >= self.expiry {
            "expired"
        } else {
            "active"
        }
    }

    /// REST/CLI view (hex ids; no key or signature bytes).
    #[must_use]
    pub fn to_view(&self, now_unix: u64, revoked: bool) -> serde_json::Value {
        let grantee = match self.grantee {
            Grantee::User(user) => serde_json::json!({ "user": hex::encode(user.as_bytes()) }),
            Grantee::Agent(agent) => {
                serde_json::json!({ "agent": hex::encode(agent.as_bytes()) })
            }
        };
        serde_json::json!({
            "grant_id": self.id_hex(),
            "owner": hex::encode(self.owner.as_bytes()),
            "grantee": grantee,
            "agents": self.agents.iter().map(|a| hex::encode(a.as_bytes())).collect::<Vec<_>>(),
            "caps": self.caps,
            "not_before": self.not_before,
            "expiry": self.expiry,
            "status": self.status_at(now_unix, revoked),
        })
    }
}

/// Which side of a grant this install holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRole {
    /// Signed by this install's owner (enforcement reads these).
    Issued,
    /// This install is the grantee.
    Received,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    issued: Vec<ShareGrant>,
    received: Vec<ShareGrant>,
}

#[derive(Debug, Default)]
struct StoreState {
    issued: BTreeMap<[u8; 32], ShareGrant>,
    received: BTreeMap<[u8; 32], ShareGrant>,
}

impl StoreState {
    fn role_mut(&mut self, role: GrantRole) -> &mut BTreeMap<[u8; 32], ShareGrant> {
        match role {
            GrantRole::Issued => &mut self.issued,
            GrantRole::Received => &mut self.received,
        }
    }
}

/// Persistent store of issued and received share grants.
///
/// All in-memory access is under a short synchronous lock never held across
/// an await; writes are serialised by an async lock so snapshots reach disk
/// in order.
#[derive(Debug)]
pub struct ShareGrantStore {
    path: Option<PathBuf>,
    local_agent: AgentId,
    local_owner: Option<UserId>,
    state: std::sync::RwLock<StoreState>,
    write_lock: tokio::sync::Mutex<()>,
    /// Set when the file on disk could not be read: the store then holds
    /// nothing and refuses writes so the file is never silently replaced.
    load_error: Option<String>,
    /// #926: grant ids THIS node has requested by fetch, with the request
    /// time — the only responses accepted, and the per-id re-fetch
    /// suppression. Swept + capped (peer-supplied ids are untrusted).
    fetch_in_flight: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// #967 B2: last time this peer's fetch was served (the per-peer
    /// rate limit). Swept + capped like the in-flight map.
    fetch_peer_served: std::sync::Mutex<std::collections::HashMap<AgentId, std::time::Instant>>,
    /// #967 r3: last time hints were attached for one recipient.
    hint_sent: std::sync::Mutex<std::collections::HashMap<AgentId, std::time::Instant>>,
    /// #967 r4 (S1): last time a hint frame from this sender was accepted.
    hint_received: std::sync::Mutex<std::collections::HashMap<AgentId, std::time::Instant>>,
}

impl ShareGrantStore {
    /// An empty in-memory store (tests, or no data dir).
    #[must_use]
    pub fn in_memory(local_agent: AgentId, local_owner: Option<UserId>) -> Self {
        Self {
            path: None,
            local_agent,
            local_owner,
            state: std::sync::RwLock::new(StoreState::default()),
            write_lock: tokio::sync::Mutex::new(()),
            load_error: None,
            fetch_in_flight: std::sync::Mutex::new(std::collections::HashMap::new()),
            fetch_peer_served: std::sync::Mutex::new(std::collections::HashMap::new()),
            hint_sent: std::sync::Mutex::new(std::collections::HashMap::new()),
            hint_received: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Load `path` (missing ⇒ empty). Every stored grant is re-verified and
    /// re-classified; one that no longer verifies is dropped. An unreadable
    /// or malformed file yields an empty store that refuses writes
    /// ([`Self::load_error`]).
    pub async fn load(path: PathBuf, local_agent: AgentId, local_owner: Option<UserId>) -> Self {
        let mut store = Self::in_memory(local_agent, local_owner);
        store.path = Some(path.clone());
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return store,
            Err(e) => {
                store.load_error = Some(format!("read {}: {e}", path.display()));
                return store;
            }
        };
        let file = if bytes.len() >= STORE_MAGIC.len() && &bytes[..STORE_MAGIC.len()] == STORE_MAGIC
        {
            // Strict: trailing bytes after a valid body are corruption, not
            // slack — they fail closed into `load_error` like any other.
            let body = &bytes[STORE_MAGIC.len()..];
            strict_decode::<StoreFile>(body, body.len() as u64)
                .map_err(|e| format!("decode {}: {e}", path.display()))
        } else {
            Err(format!("{} missing X0SG magic", path.display()))
        };
        match file {
            Ok(file) => {
                let mut state = StoreState::default();
                for grant in file.issued.into_iter().chain(file.received) {
                    if grant.verify().is_err() {
                        continue;
                    }
                    if let Some(role) = store.classify(&grant) {
                        state.role_mut(role).insert(grant.grant_id, grant);
                    }
                }
                store.state = std::sync::RwLock::new(state);
            }
            Err(e) => {
                tracing::warn!("share-grant store unreadable, holding no grants: {e}");
                store.load_error = Some(e);
            }
        }
        store
    }

    /// The agent this daemon hosts (the only agent its grants can open).
    #[must_use]
    pub fn local_agent(&self) -> AgentId {
        self.local_agent
    }

    /// This install's owner, if any.
    #[must_use]
    pub fn local_owner(&self) -> Option<UserId> {
        self.local_owner
    }

    /// Why the on-disk store is not in force, if it is not.
    #[must_use]
    pub fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    /// Which role a verified grant takes here, if any: `Issued` when it is
    /// signed by this install's owner, `Received` when this install's agent
    /// or owner is the grantee.
    #[must_use]
    pub fn classify(&self, grant: &ShareGrant) -> Option<GrantRole> {
        if self.local_owner == Some(grant.owner) {
            return Some(GrantRole::Issued);
        }
        match grant.grantee {
            Grantee::Agent(agent) if agent == self.local_agent => Some(GrantRole::Received),
            Grantee::User(user) if self.local_owner == Some(user) => Some(GrantRole::Received),
            _ => None,
        }
    }

    fn read_state(&self) -> std::sync::RwLockReadGuard<'_, StoreState> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, StoreState> {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Snapshot of held grants in `role`.
    #[must_use]
    pub fn grants(&self, role: GrantRole) -> Vec<ShareGrant> {
        let state = self.read_state();
        match role {
            GrantRole::Issued => state.issued.values().cloned().collect(),
            GrantRole::Received => state.received.values().cloned().collect(),
        }
    }

    /// One issued grant by id.
    #[must_use]
    pub fn issued(&self, grant_id: &[u8; 32]) -> Option<ShareGrant> {
        self.read_state().issued.get(grant_id).cloned()
    }

    /// #926: one held grant by id, either role (the fetch responder serves
    /// grants it issued OR received — a re-share is impossible: the bytes
    /// are owner-signed and the receiver verifies against its own owner).
    #[must_use]
    pub fn by_id(&self, grant_id: &[u8; 32]) -> Option<ShareGrant> {
        let state = self.read_state();
        state
            .issued
            .get(grant_id)
            .or_else(|| state.received.get(grant_id))
            .cloned()
    }

    /// #926: record that this node requested `grant_id` by fetch. Returns
    /// `true` when this call started a fresh in-flight window (a repeat
    /// inside the TTL is suppressed). Sweeps expired ids and evicts the
    /// oldest at the cap.
    pub fn note_fetch(&self, grant_id: &[u8; 32], responder: Option<&AgentId>) -> bool {
        let now = std::time::Instant::now();
        let mut map = self
            .fetch_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.retain(|_, at| (now.duration_since(*at).as_millis() as u64) < GRANT_FETCH_TTL_MS);
        let key = fetch_window_key(grant_id, responder);
        if map.contains_key(&key) {
            return false;
        }
        if map.len() >= GRANT_FETCH_MAX_ENTRIES {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
        map.insert(key, now);
        true
    }

    /// #967 r3: rate-limit hint attachment per recipient. Returns true
    /// when a hint may be sent now (one per peer per 30 s window).
    pub fn note_hint_sent(&self, peer: &AgentId) -> bool {
        let now = std::time::Instant::now();
        let mut map = self
            .hint_sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.retain(|_, at| {
            (now.duration_since(*at).as_millis() as u64) < SHARE_GRANT_HINT_INTERVAL_MS
        });
        if map.contains_key(peer) {
            return false;
        }
        if map.len() >= GRANT_FETCH_MAX_ENTRIES {
            if let Some(oldest) = map.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) {
                map.remove(&oldest);
            }
        }
        map.insert(*peer, now);
        true
    }

    /// #967 r4 (S1): one ACCEPTED hint frame per sender per window — a
    /// stranger cannot flood the hint consumer or open fetch windows on
    /// demand. Swept + capped like the other peer maps.
    pub fn note_hint_received(&self, sender: &AgentId) -> bool {
        let now = std::time::Instant::now();
        let mut map = self
            .hint_received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.retain(|_, at| {
            (now.duration_since(*at).as_millis() as u64) < SHARE_GRANT_HINT_INTERVAL_MS
        });
        if map.contains_key(sender) {
            return false;
        }
        if map.len() >= GRANT_FETCH_MAX_ENTRIES {
            if let Some(oldest) = map.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) {
                map.remove(&oldest);
            }
        }
        map.insert(*sender, now);
        true
    }

    /// #967 B2: one served fetch per peer per window. Returns `true`
    /// when this peer may be served now; a repeat inside the window is
    /// rate-limited. Swept + capped.
    pub fn note_peer_fetch(&self, peer: &AgentId) -> bool {
        let now = std::time::Instant::now();
        let mut map = self
            .fetch_peer_served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.retain(|_, at| {
            (now.duration_since(*at).as_millis() as u64) < GRANT_FETCH_PEER_INTERVAL_MS
        });
        if map.contains_key(peer) {
            return false;
        }
        if map.len() >= GRANT_FETCH_MAX_ENTRIES {
            if let Some(oldest) = map.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) {
                map.remove(&oldest);
            }
        }
        map.insert(*peer, now);
        true
    }

    /// #926: whether a fetch for `grant_id` is in flight (responses for
    /// other ids are dropped).
    #[must_use]
    pub fn is_fetch_in_flight(&self, grant_id: &[u8; 32], responder: Option<&AgentId>) -> bool {
        let now = std::time::Instant::now();
        self.fetch_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&fetch_window_key(grant_id, responder))
            .is_some_and(|at| (now.duration_since(*at).as_millis() as u64) < GRANT_FETCH_TTL_MS)
    }

    /// #926: end the in-flight window (the grant arrived or was refused
    /// terminally).
    pub fn clear_fetch(&self, grant_id: &[u8; 32]) {
        // Both possible key spellings (responder-bound and legacy) go.
        let mut map = self
            .fetch_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prefix = format!("{}:", hex::encode(grant_id));
        map.retain(|k, _| !k.starts_with(&prefix));
    }

    /// Issued grants that can open THIS daemon's agent at `now_unix`: signed
    /// by the local owner, listing the local agent, inside their window.
    /// Filters under the read lock and clones only the candidates.
    #[must_use]
    pub fn candidates_for_local_agent(&self, now_unix: u64) -> Vec<ShareGrant> {
        let Some(owner) = self.local_owner else {
            return Vec::new();
        };
        let state = self.read_state();
        state
            .issued
            .values()
            .filter(|g| {
                g.owner == owner && g.agents.contains(&self.local_agent) && g.is_active_at(now_unix)
            })
            .cloned()
            .collect()
    }

    /// Verify, classify and durably store a grant.
    ///
    /// Returns `Inserted` or `Duplicate` only once the grant is on disk (or
    /// the store is in-memory). Every refusal leaves the store unchanged.
    ///
    /// # Errors
    /// Any [`ShareGrantError`]: invalid/forged ([`ShareGrant::verify`]),
    /// `Expired` at `now_unix`, `NotForUs`, `Conflict`, or `Store`.
    pub async fn accept(
        &self,
        grant: ShareGrant,
        now_unix: u64,
    ) -> Result<DmTypedPayloadCompletion, ShareGrantError> {
        grant.verify()?;
        if now_unix >= grant.expiry {
            return Err(ShareGrantError::Expired);
        }
        let role = self.classify(&grant).ok_or(ShareGrantError::NotForUs)?;
        if let Some(e) = &self.load_error {
            return Err(ShareGrantError::Store(format!(
                "store not writable (unreadable file): {e}"
            )));
        }
        let _write = self.write_lock.lock().await;
        {
            let mut state = self.write_state();
            let map = state.role_mut(role);
            if let Some(held) = map.get(&grant.grant_id) {
                return if *held == grant {
                    Ok(DmTypedPayloadCompletion::Duplicate)
                } else {
                    Err(ShareGrantError::Conflict)
                };
            }
            if map.len() >= MAX_STORED_GRANTS {
                map.retain(|_, g| now_unix < g.expiry);
            }
            if map.len() >= MAX_STORED_GRANTS {
                return Err(ShareGrantError::Store("grant store is full".into()));
            }
            map.insert(grant.grant_id, grant.clone());
        }
        if let Err(e) = self.persist().await {
            // Roll back: a grant that is not durable must not be reported
            // as stored (the durable ACK would be a lie).
            self.write_state().role_mut(role).remove(&grant.grant_id);
            return Err(ShareGrantError::Store(e));
        }
        Ok(DmTypedPayloadCompletion::Inserted)
    }

    /// Write the store atomically (mode 0600). Callers hold `write_lock`.
    async fn persist(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = {
            let state = self.read_state();
            StoreFile {
                issued: state.issued.values().cloned().collect(),
                received: state.received.values().cloned().collect(),
            }
        };
        let body = bincode::serialize(&file).map_err(|e| format!("encode: {e}"))?;
        let mut bytes = Vec::with_capacity(STORE_MAGIC.len() + body.len());
        bytes.extend_from_slice(STORE_MAGIC);
        bytes.extend_from_slice(&body);
        // Durable (temp + fsync + rename + dir fsync): the completion that
        // follows releases a v2 ACK meaning "stored", which must survive
        // power loss.
        crate::storage::write_private_bytes_durable(path, bytes)
            .await
            .map_err(|e| format!("write {}: {e}", path.display()))
    }
}

/// Bincode decode matching `bincode::serialize`'s encoding (fixint, little
/// endian) but STRICT: trailing bytes are an error and reads are bounded by
/// `limit` (which also bounds preallocation).
fn strict_decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: u64,
) -> Result<T, Box<bincode::ErrorKind>> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(bytes)
}

pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What the grants held here confer on one requester pair, for this
/// daemon's own agent (ADR-0070 §2). The union over every matching grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantAccess {
    /// `Dm`: DMs are accepted (`Unknown`/`AcceptWithFlag` → `Accept`).
    pub dm: bool,
    /// `Exec`: `principal = "grant"` exec entries may match.
    pub exec: bool,
    /// `Connect`: `principal = "grant"` connect entries may match for these
    /// target ports.
    pub connect_ports: BTreeSet<u16>,
    /// `GroupInvite`: groups may be seeded without a contact entry.
    pub group_invite: bool,
    /// `Call` (ADR-0073): carried, not yet enforced.
    pub call: bool,
}

impl GrantAccess {
    /// Whether no capability is conferred.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether a `Connect` capability covers `port`.
    #[must_use]
    pub fn allows_connect_port(&self, port: u16) -> bool {
        self.connect_ports.contains(&port)
    }

    fn absorb(&mut self, caps: &BTreeSet<ShareCap>) {
        for cap in caps {
            match cap {
                ShareCap::Dm => self.dm = true,
                ShareCap::Exec => self.exec = true,
                ShareCap::Connect { ports } => self.connect_ports.extend(ports.iter().copied()),
                ShareCap::GroupInvite => self.group_invite = true,
                ShareCap::Call => self.call = true,
            }
        }
    }
}

/// Evaluate the grants held in `store` for `(requester_agent,
/// requester_machine)` at `now_unix`. Every failure is "no grant":
///
/// 1. a grant counts only when signed by this install's owner, listing this
///    daemon's agent, and inside `[not_before, expiry)`;
/// 2. the requester's machine must equal its AUTHENTICATED binding (#890;
///    the slice-1 hardened rule) — a claimed or rewritten discovery-cache
///    machine never pairs, so a spoofed raw Direct claim (#898) gains
///    nothing;
/// 3. the requester agent, machine and ADR-0043 binding must not be revoked,
///    and the grant itself must not be revoked (`x0x.revocation.v3`);
/// 4. `Grantee::Agent(a)` matches exactly `a`; `Grantee::User(u)` matches a
///    requester whose cached `AgentCertificate` is valid, unexpired, binds
///    exactly this agent and is signed by `u`.
///
/// Callers apply explicit local denials (`Blocked`, machine-pin mismatch)
/// first — see [`OwnerTrust::grant_access`].
pub async fn evaluate_grant_access(
    store: &ShareGrantStore,
    bindings: &AuthenticatedMachineBindings,
    discovery_cache: &RwLock<HashMap<AgentId, DiscoveredAgent>>,
    revocation_set: &RwLock<RevocationSet>,
    requester_agent: &AgentId,
    requester_machine: &MachineId,
    now_unix: u64,
) -> GrantAccess {
    let mut access = GrantAccess::default();
    // A failed clock read maps to 0; never evaluate validity windows
    // against it (it could reactivate a long-expired grant). Fail closed.
    if now_unix == 0 {
        return access;
    }
    let candidates = store.candidates_for_local_agent(now_unix);
    if candidates.is_empty() {
        return access;
    }
    match crate::dm_inbox::authenticated_machine_binding(bindings, requester_agent).await {
        Some(bound) if bound == *requester_machine => {}
        _ => return access,
    }
    let live: Vec<ShareGrant> = {
        let revoked = revocation_set.read().await;
        if revoked.is_agent_revoked(requester_agent)
            || revoked.is_machine_revoked(requester_machine)
            || revoked.is_binding_revoked(requester_agent, requester_machine)
        {
            return access;
        }
        candidates
            .into_iter()
            .filter(|g| !revoked.is_share_grant_revoked(&g.grant_id, &g.owner))
            .collect()
    };
    let cert = if live.iter().any(|g| matches!(g.grantee, Grantee::User(_))) {
        discovery_cache
            .read()
            .await
            .get(requester_agent)
            .and_then(|entry| entry.agent_certificate.clone())
    } else {
        None
    };
    for grant in &live {
        let grantee_matches = match grant.grantee {
            Grantee::Agent(agent) => agent == *requester_agent,
            Grantee::User(user) => cert.as_ref().is_some_and(|cert| {
                crate::owner_trust::certificate_chains_to_owner(
                    &user,
                    requester_agent,
                    cert,
                    false,
                    now_unix,
                )
            }),
        };
        if grantee_matches {
            access.absorb(&grant.caps);
        }
    }
    access
}

/// The DM-acceptance input of ADR-0070 §2, handed to the DM inbox: a
/// grantee holding a current `Dm` grant for this daemon's agent is promoted
/// from `Unknown`/`AcceptWithFlag` to `Accept`.
#[derive(Clone)]
pub struct ShareGrantDmGate {
    owner_trust: OwnerTrust,
    discovery_cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>,
}

impl std::fmt::Debug for ShareGrantDmGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareGrantDmGate").finish_non_exhaustive()
    }
}

impl ShareGrantDmGate {
    /// Gate over the agent's owner-trust source (which holds the grant
    /// store and authenticated bindings) and its discovery cache.
    #[must_use]
    pub fn new(
        owner_trust: OwnerTrust,
        discovery_cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>,
    ) -> Self {
        Self {
            owner_trust,
            discovery_cache,
        }
    }

    /// Whether a current `Dm` grant covers `(sender, sender_machine)`.
    pub async fn dm_allowed(
        &self,
        contacts: &RwLock<ContactStore>,
        revocation_set: &RwLock<RevocationSet>,
        sender: &AgentId,
        sender_machine: &MachineId,
    ) -> bool {
        self.owner_trust
            .grant_access(
                contacts,
                &self.discovery_cache,
                revocation_set,
                sender,
                sender_machine,
            )
            .await
            .dm
    }
}

/// Handle one typed share-grant DM (the durable route's handler).
///
/// Resolves the completion with `Inserted`/`Duplicate` only once the grant
/// is verified and stored; every failure resolves `Err`, which withholds the
/// v2 ACK. Returns the outcome for logging and tests.
pub async fn handle_share_grant_dm(
    store: Option<&ShareGrantStore>,
    typed: DmTypedPayload,
) -> DmTypedPayloadCompletionResult {
    let DmTypedPayload {
        sender,
        payload,
        completion,
        ..
    } = typed;
    let result = match store {
        None => Err("share grants are not enabled on this daemon".to_string()),
        Some(store) => match ShareGrant::from_dm_payload(&payload) {
            Ok(grant) => store
                .accept(grant, unix_now_secs())
                .await
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
    };
    match &result {
        Ok(outcome) => tracing::info!(
            sender = %hex::encode(sender.as_bytes()),
            ?outcome,
            "share grant received and stored"
        ),
        Err(reason) => tracing::info!(
            sender = %hex::encode(sender.as_bytes()),
            reason = %reason,
            "share grant refused; not stored, ACK withheld"
        ),
    }
    if let Some(completion) = completion {
        let _ = completion.send(result.clone());
    }
    result
}

/// The outcome of one grant-FETCH typed DM: the completion for the
/// durable route plus the signed grant bytes to send back, if any.
#[derive(Debug)]
pub struct GrantFetchOutcome {
    /// The handler's completion (resolved to the durable route).
    pub result: DmTypedPayloadCompletionResult,
    /// `Some(grant_dm_payload)` — the reply to send back to the sender.
    pub reply: Option<Vec<u8>>,
}

/// #926: handle one grant-FETCH typed DM (the grantee-attached grant_id
/// fetch of ADR-0070 §2). The requester is a daemon whose owner signed
/// the grant (a shared agent) but which missed the delivery; the
/// responder is any daemon holding the grant — grantee or another
/// owner-trusted install.
///
/// Serve authorization: ONLY a sender that is a SUBJECT of the grant
/// (`grant.agents`) may receive it — the grant names them, so serving it
/// leaks nothing, and a stranger gets nothing. A grant this daemon does
/// not hold resolves Err (transient: the fetch may precede the owner's
/// delivery here), which withholds the v2 ACK so the sender retries.
/// #967 r4 (N2): the grant id a fetch REQUEST names (prefix-stripped),
/// for callers that must pre-resolve the target without running the
/// handler.
pub fn share_grant_fetch_target(payload: &[u8]) -> Option<[u8; 32]> {
    let body = payload.strip_prefix(SHARE_GRANT_FETCH_DM_PREFIX)?;
    if body.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(body);
    Some(id)
}

/// The in-flight window key: (grant id, expected responder). Binding
/// the responder is B1's core: a response is accepted only from the peer
/// this daemon actually asked, and that peer must be owner-trusted.
fn fetch_window_key(grant_id: &[u8; 32], responder: Option<&AgentId>) -> String {
    match responder {
        Some(r) => format!("{}:{}", hex::encode(grant_id), hex::encode(r.as_bytes())),
        None => hex::encode(grant_id),
    }
}

/// How the fetch handlers ask "is this grant revoked" (#967 B1). The
/// daemon wiring passes a closure over its revocation set; tests pass a
/// predicate over known-revoked ids.
pub type GrantRevoked<'a> = &'a (dyn Fn(&ShareGrant) -> bool + Send + Sync);

/// #967 B2: one served fetch per peer per window (a stranger cannot
/// hammer the responder); swept and capped like the other maps.
pub const GRANT_FETCH_PEER_INTERVAL_MS: u64 = 30_000;
/// #967 B2: the served-grant reply is bounded — a grant wire form larger
/// than this is corruption, not loadable state.
pub const GRANT_FETCH_REPLY_MAX_BYTES: usize = 64 * 1024;

pub async fn handle_share_grant_fetch(
    store: Option<&ShareGrantStore>,
    revoked: Option<GrantRevoked<'_>>,
    now_unix: u64,
    typed: DmTypedPayload,
) -> GrantFetchOutcome {
    let DmTypedPayload {
        sender,
        payload,
        completion,
        ..
    } = typed;
    let outcome = match store {
        None => GrantFetchOutcome {
            result: Err("share grants are not enabled on this daemon".to_string()),
            reply: None,
        },
        Some(store) => {
            // B2: per-peer rate limit BEFORE any store work.
            if !store.note_peer_fetch(&sender) {
                GrantFetchOutcome {
                    result: Err("grant fetch rate limited for this peer; retry".to_string()),
                    reply: None,
                }
            } else {
                match parse_fetch_request(&payload) {
                    Err(reason) => GrantFetchOutcome {
                        result: Err(reason),
                        reply: None,
                    },
                    Ok(grant_id) => match store.by_id(&grant_id) {
                        None => {
                            tracing::info!(
                                grant_id = %hex::encode(grant_id),
                                "#926: grant fetch for a grant this daemon does not hold; retry"
                            );
                            GrantFetchOutcome {
                                result: Err("grant not held here; retry".to_string()),
                                reply: None,
                            }
                        }
                        Some(grant) => {
                            if store.classify(&grant) != Some(GrantRole::Issued) {
                                // #967 r3 (B1, design b): ONLY an owner install
                                // (this daemon's owner == the grant's signer)
                                // may serve a fetch. A GRANTEE-held (Received)
                                // grant is never served: a hostile or stale
                                // grantee must not be able to push grants —
                                // least of all ones the requester's missed
                                // revocations for. Owner installs are the
                                // revocation source, so fetching from them
                                // bounds the offline-through-revocation window
                                // to the owner's own v3 propagation.
                                tracing::warn!(
                                    grant_id = %hex::encode(grant_id),
                                    "#967: fetch served only by owner installs; this holder is not one; refused"
                                );
                                GrantFetchOutcome {
                                    result: Err(
                                        "fetches are served only by owner installs".to_string()
                                    ),
                                    reply: None,
                                }
                            } else if !grant.agents.contains(&sender) {
                                tracing::warn!(
                                    sender = %hex::encode(sender.as_bytes()),
                                    grant_id = %hex::encode(grant_id),
                                    "#926: grant fetch from an agent that is not a subject of the grant; refused"
                                );
                                GrantFetchOutcome {
                                    result: Err(
                                        "requester is not a subject of this grant".to_string()
                                    ),
                                    reply: None,
                                }
                            } else if !grant.is_active_at(now_unix) {
                                // B1: never serve expired or not-yet-valid
                                // state.
                                tracing::info!(
                                    grant_id = %hex::encode(grant_id),
                                    "#967: fetch for an inactive grant; refused"
                                );
                                GrantFetchOutcome {
                                    result: Err("grant is not active".to_string()),
                                    reply: None,
                                }
                            } else if revoked.is_some_and(|is_revoked| is_revoked(&grant)) {
                                // B1: a revoked grant must not be
                                // resurrected by a fetch — the offline
                                // daemon missed the revocation gossip.
                                tracing::warn!(
                                    grant_id = %hex::encode(grant_id),
                                    "#967: fetch for a REVOKED grant; refused"
                                );
                                GrantFetchOutcome {
                                    result: Err("grant is revoked".to_string()),
                                    reply: None,
                                }
                            } else {
                                match grant.to_dm_payload() {
                                    Ok(reply) => {
                                        if reply.len() > GRANT_FETCH_REPLY_MAX_BYTES {
                                            GrantFetchOutcome {
                                                result: Err(format!(
                                                    "grant wire form {} bytes exceeds the {}-byte bound",
                                                    reply.len(),
                                                    GRANT_FETCH_REPLY_MAX_BYTES
                                                )),
                                                reply: None,
                                            }
                                        } else {
                                            GrantFetchOutcome {
                                                result: Ok(DmTypedPayloadCompletion::Inserted),
                                                reply: Some(reply),
                                            }
                                        }
                                    }
                                    Err(e) => GrantFetchOutcome {
                                        result: Err(e.to_string()),
                                        reply: None,
                                    },
                                }
                            }
                        }
                    },
                }
            }
        }
    };
    if let Some(tx) = completion {
        let _ = tx.send(outcome.result.clone());
    }
    outcome
}

/// `prefix ‖ id[32]` or a reason.
fn parse_fetch_request(payload: &[u8]) -> Result<[u8; 32], String> {
    let Some(id) = payload.strip_prefix(SHARE_GRANT_FETCH_DM_PREFIX) else {
        return Err("share-grant fetch payload missing its prefix".to_string());
    };
    if id.len() != 32 {
        return Err("share-grant fetch id must be exactly 32 bytes".to_string());
    }
    let mut grant_id = [0u8; 32];
    grant_id.copy_from_slice(id);
    Ok(grant_id)
}

/// #926: handle one grant-fetch RESPONSE typed DM. The response is
/// accepted only when this node requested that id inside the window, the
/// payload is the signed grant wire form, and the store's own accept
/// path (verify, classify, durable persist — exactly what a direct
/// delivery runs) succeeds. The path is idempotent, and the in-flight
/// window closes on success.
/// The decoded, window-checked half of a fetch response (#967 r3): no
/// revocation decision, no store mutation — so the DAEMON can evaluate
/// revocation under a scoped guard and DROP it before the accept await.
pub struct PreparedGrantFetch {
    pub grant: ShareGrant,
    pub sender: AgentId,
    pub machine_id: crate::identity::MachineId,
    pub completion: Option<tokio::sync::oneshot::Sender<DmTypedPayloadCompletionResult>>,
    /// The response's sender is owner-trusted for THIS grant's owner
    /// (decided by the daemon between prepare and finish).
    pub responder_trusted: bool,
}

impl PreparedGrantFetch {
    /// Convenience for callers WITHOUT a daemon revocation set (tests):
    /// run the revocation check and the accept in one call.
    pub async fn finish_with(
        self,
        store: Option<&ShareGrantStore>,
        revoked: Option<GrantRevoked<'_>>,
        now_unix: u64,
    ) -> DmTypedPayloadCompletionResult {
        finish_share_grant_fetch_response(store, self, revoked, now_unix).await
    }
}

/// Decode and window-check one fetch response. Errors are terminal
/// outcomes (resolved to the completion when present).
pub async fn prepare_share_grant_fetch_response(
    store: Option<&ShareGrantStore>,
    typed: DmTypedPayload,
) -> Result<PreparedGrantFetch, DmTypedPayloadCompletionResult> {
    let DmTypedPayload {
        sender,
        machine_id,
        payload,
        completion,
        ..
    } = typed;
    let err =
        |reason: String,
         completion: Option<tokio::sync::oneshot::Sender<DmTypedPayloadCompletionResult>>| {
            if let Some(tx) = completion {
                let _ = tx.send(Err(reason.clone()));
            }
            Err(Err(reason))
        };
    let Some(store) = store else {
        return err(
            "share grants are not enabled on this daemon".to_string(),
            completion,
        );
    };
    let Some(grant_payload) = payload.strip_prefix(SHARE_GRANT_FETCH_RESPONSE_DM_PREFIX) else {
        return err(
            "share-grant fetch response missing its prefix".to_string(),
            completion,
        );
    };
    if grant_payload.len() > GRANT_FETCH_REPLY_MAX_BYTES {
        // B2 nit: the size bound runs BEFORE the decode.
        return err(
            format!(
                "grant fetch response {} bytes exceeds the {}-byte bound",
                grant_payload.len(),
                GRANT_FETCH_REPLY_MAX_BYTES
            ),
            completion,
        );
    }
    let grant = match ShareGrant::from_dm_payload(grant_payload) {
        Ok(grant) => grant,
        Err(e) => return err(e.to_string(), completion),
    };
    if !store.is_fetch_in_flight(&grant.grant_id, Some(&sender)) {
        tracing::warn!(
            grant_id = %hex::encode(grant.grant_id),
            "#926: grant fetch response for an id we did not request; dropped"
        );
        return err(
            "no share-grant fetch in flight for this id".to_string(),
            completion,
        );
    }
    Ok(PreparedGrantFetch {
        grant,
        sender,
        machine_id,
        completion,
        responder_trusted: false,
    })
}

/// The revocation + accept half. The caller has already dropped any
/// revocation-set guard: `revoked` here must not hold one across this
/// await (the store's write lock and disk persist run inside).
pub async fn finish_share_grant_fetch_response(
    store: Option<&ShareGrantStore>,
    prepared: PreparedGrantFetch,
    revoked: Option<GrantRevoked<'_>>,
    now_unix: u64,
) -> DmTypedPayloadCompletionResult {
    let PreparedGrantFetch {
        grant,
        sender,
        completion,
        responder_trusted,
        ..
    } = prepared;
    if !responder_trusted {
        // B1: the responder is not owner-trusted for this grant's owner.
        // A hostile grantee holding the owner-signed bytes must not be
        // able to answer a fetch — least of all for a grant whose
        // revocation this daemon missed.
        tracing::warn!(
            grant_id = %hex::encode(grant.grant_id),
            sender = %hex::encode(sender.as_bytes()),
            "#967 B1: fetch response from a sender that is not owner-trusted; not stored"
        );
        let reason = "fetch responses are accepted only from owner-trusted responders".to_string();
        if let Some(tx) = completion {
            let _ = tx.send(Err(reason.clone()));
        }
        return Err(reason);
    }
    if revoked.is_some_and(|is_revoked| is_revoked(&grant)) {
        tracing::warn!(
            grant_id = %hex::encode(grant.grant_id),
            "#967: fetched grant is revoked here; not stored"
        );
        let reason = "grant is revoked".to_string();
        if let Some(tx) = completion {
            let _ = tx.send(Err(reason.clone()));
        }
        return Err(reason);
    }
    let grant_id = grant.grant_id;
    let outcome = match store {
        None => Err("share grants are not enabled on this daemon".to_string()),
        Some(store) => store
            .accept(grant, now_unix)
            .await
            .map_err(|e| e.to_string()),
    };
    if outcome.is_ok() {
        if let Some(store) = store {
            store.clear_fetch(&grant_id);
        }
    }
    if let Some(tx) = completion {
        let _ = tx.send(outcome.clone());
    }
    outcome
}

/// Composed form (prepare + finish in one call) for callers that do not
/// need to interleave a scoped revocation guard (tests, tooling).
/// `owner_trusted_responder` (#967 r4 B1): whether the response's sender
/// is owner-trusted for the grant's owner; the daemon computes it from
/// OwnerTrust between prepare and finish, tests pass it directly.
pub async fn handle_share_grant_fetch_response(
    store: Option<&ShareGrantStore>,
    revoked: Option<GrantRevoked<'_>>,
    now_unix: u64,
    owner_trusted_responder: bool,
    typed: DmTypedPayload,
) -> DmTypedPayloadCompletionResult {
    match prepare_share_grant_fetch_response(store, typed).await {
        Err(result) => result,
        Ok(mut prepared) => {
            prepared.responder_trusted = owner_trusted_responder;
            finish_share_grant_fetch_response(store, prepared, revoked, now_unix).await
        }
    }
}

/// #967 r4 (B2): the owner installs this daemon may fetch grants from —
/// discovery-cache agents that are owner-trusted here (ADR-0070 par-2
/// design (b): the fetch target is the revocation source, never the
/// hinter). Capped; first candidate is used first.
pub async fn owner_install_candidates(agent: &crate::Agent, cap: usize) -> Vec<AgentId> {
    let mut out: Vec<AgentId> = Vec::new();
    let entries: Vec<AgentId> = {
        let cache = agent.identity_discovery_cache.blocking_read();
        cache.keys().copied().collect()
    };
    for id in entries {
        if out.len() >= cap {
            break;
        }
        if agent
            .is_owner_trusted_pair(&id, &crate::identity::MachineId([0u8; 32]))
            .await
        {
            out.push(id);
        }
    }
    out
}

/// #967 r4 (B3): the DM-open attachment, SPAWNED off the caller's send
/// path (REST /direct/send and the WS DM path call this AFTER their own
/// send resolves; Agent::send_direct itself stays hook-free so no caller
/// is ever delayed by a hint round trip).
pub fn spawn_grant_hints(agent: &std::sync::Arc<crate::Agent>, to: &AgentId) {
    let Some(payload) = agent.grant_hint_payload_for(to) else {
        return;
    };
    let agent = std::sync::Arc::clone(agent);
    let to = *to;
    tokio::spawn(async move {
        if let Err(e) = agent
            .send_direct_with_config(&to, payload, crate::dm::DmSendConfig::default())
            .await
        {
            tracing::debug!(error = %e, "#967: grant hint frame not delivered");
        }
    });
}

/// Encode a hint frame: prefix + bincode(Vec<grant_id>).
pub fn share_grant_hint_payload(ids: &[[u8; 32]]) -> Vec<u8> {
    let capped: Vec<[u8; 32]> = ids.iter().copied().take(SHARE_GRANT_HINT_MAX_IDS).collect();
    let body = bincode::serialize(&capped).unwrap_or_default();
    let mut p = Vec::with_capacity(SHARE_GRANT_HINT_DM_PREFIX.len() + body.len());
    p.extend_from_slice(SHARE_GRANT_HINT_DM_PREFIX);
    p.extend_from_slice(&body);
    p
}

/// Decode a hint frame body (prefix already stripped by the route).
pub fn decode_share_grant_hint(body: &[u8]) -> Vec<[u8; 32]> {
    bincode::deserialize::<Vec<[u8; 32]>>(body)
        .unwrap_or_default()
        .into_iter()
        .take(SHARE_GRANT_HINT_MAX_IDS)
        .collect()
}

/// Send-layer retries for one grant delivery. Every retry reuses the same
/// logical request id, so a receiver that already stored the grant answers
/// `Duplicate` and the retry is idempotent.
pub const GRANT_DELIVERY_RETRIES: u8 = 3;

/// Outcome of delivering a grant to one recipient agent.
#[derive(Debug, Clone, Serialize)]
pub struct GrantDelivery {
    /// Recipient agent (hex).
    pub agent: String,
    /// `true` once the recipient's durable v2 ACK arrived.
    pub delivered: bool,
    /// Why delivery failed, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl crate::Agent {
    /// Install the grant store (the daemon does this once at startup).
    pub fn install_share_grant_store(&self, store: Arc<ShareGrantStore>) {
        self.owner_trust().install_share_grant_store(store);
    }

    /// The installed grant store, if any.
    #[must_use]
    pub fn share_grant_store(&self) -> Option<Arc<ShareGrantStore>> {
        self.owner_trust().share_grant_store()
    }

    /// What the held grants confer on `(agent_id, machine_id)` for this
    /// daemon's agent (ADR-0070 §2). `machine_id` must be the
    /// transport-authenticated peer; see [`evaluate_grant_access`].
    pub async fn share_grant_access(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
    ) -> GrantAccess {
        self.owner_trust()
            .grant_access(
                &self.contact_store,
                &self.identity_discovery_cache,
                &self.revocation_set,
                agent_id,
                machine_id,
            )
            .await
    }

    /// Whether this install's owner has revoked `grant`.
    pub async fn is_share_grant_revoked(&self, grant: &ShareGrant) -> bool {
        self.revocation_set
            .read()
            .await
            .is_share_grant_revoked(&grant.grant_id, &grant.owner)
    }

    /// Sign a new grant with this install's owner key and store it as
    /// issued. Every shared agent must be this daemon's own agent or have a
    /// known certificate from this owner (no re-sharing of others' agents).
    ///
    /// # Errors
    /// No owner key, no grant store, an agent not provably this owner's, an
    /// invalid grant, or a store failure.
    pub async fn issue_share_grant(
        &self,
        grantee: Grantee,
        agents: Vec<AgentId>,
        caps: Vec<ShareCap>,
        not_before: u64,
        expiry: u64,
    ) -> Result<ShareGrant, ShareGrantError> {
        let owner_key = self.identity.user_keypair().ok_or_else(|| {
            ShareGrantError::Invalid("share grants need an owner identity (user key)".into())
        })?;
        let store = self
            .share_grant_store()
            .ok_or_else(|| ShareGrantError::Store("no grant store installed".into()))?;
        let owner = owner_key.user_id();
        for agent in &agents {
            if !self.agent_is_certified_by(agent, &owner).await {
                return Err(ShareGrantError::Invalid(format!(
                    "agent {} has no known certificate from this owner",
                    hex::encode(agent.as_bytes())
                )));
            }
        }
        let mut grant_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut grant_id);
        let grant = ShareGrant::sign(
            owner_key, grant_id, grantee, agents, caps, not_before, expiry,
        )?;
        store.accept(grant.clone(), unix_now_secs()).await?;
        Ok(grant)
    }

    /// Whether `agent` is this daemon's own agent (with a certificate from
    /// `owner`) or has a cached, valid certificate chaining to `owner`.
    async fn agent_is_certified_by(&self, agent: &AgentId, owner: &UserId) -> bool {
        let now = unix_now_secs();
        if *agent == self.agent_id() {
            return self.identity.agent_certificate().is_some_and(|cert| {
                crate::owner_trust::certificate_chains_to_owner(owner, agent, cert, false, now)
            });
        }
        let cert = self
            .identity_discovery_cache
            .read()
            .await
            .get(agent)
            .and_then(|entry| entry.agent_certificate.clone());
        cert.is_some_and(|cert| {
            crate::owner_trust::certificate_chains_to_owner(owner, agent, &cert, false, now)
        })
    }

    /// Recipients a grant is delivered to: the grantee's known agents
    /// (`Agent(a)` ⇒ `a`; `User(u)` ⇒ cached agents whose certificate names
    /// `u`), each shared agent other than this daemon's, and `extra`.
    pub async fn share_grant_recipients(
        &self,
        grant: &ShareGrant,
        extra: &[AgentId],
    ) -> Vec<AgentId> {
        let mut out: BTreeSet<[u8; 32]> = BTreeSet::new();
        match grant.grantee {
            Grantee::Agent(agent) => {
                out.insert(agent.0);
            }
            Grantee::User(user) => {
                let cache = self.identity_discovery_cache.read().await;
                for (agent, entry) in cache.iter() {
                    let names_user = entry
                        .agent_certificate
                        .as_ref()
                        .and_then(|c| c.user_id().ok())
                        .is_some_and(|u| u == user);
                    if names_user {
                        out.insert(agent.0);
                    }
                }
            }
        }
        for agent in grant.agents.iter().chain(extra) {
            out.insert(agent.0);
        }
        out.remove(&self.agent_id().0);
        out.into_iter().map(AgentId).collect()
    }

    /// Deliver a grant to each recipient as a durable typed DM, concurrently.
    /// A recipient counts as delivered only on its durable v2 ACK, which its
    /// handler releases once the grant is stored.
    ///
    /// # Why delivery is reliable without a grant fetch
    ///
    /// ADR-0070 §2 also sketches a grantee-attached `grant_id` so a daemon
    /// that missed delivery can request the grant. That fetch is NOT
    /// implemented (follow-up). Delivery is still reliable, because it can
    /// never silently lose a grant:
    /// - the route is DURABLE: the receiver withholds the v2 ACK until the
    ///   grant is verified and written to its store, so `delivered = true`
    ///   means "stored", never "sent";
    /// - without that ACK the sender retries ([`GRANT_DELIVERY_RETRIES`])
    ///   under the same logical request id, which the receiver answers
    ///   idempotently (`Duplicate`), and finally reports the recipient as
    ///   not delivered in the `POST /grants` response;
    /// - a shared agent's daemon that never received the grant grants
    ///   nothing — the failure is closed, and visible to the owner.
    pub async fn deliver_share_grant(
        &self,
        grant: &ShareGrant,
        recipients: &[AgentId],
    ) -> Vec<GrantDelivery> {
        let payload = match grant.to_dm_payload() {
            Ok(payload) => payload,
            Err(e) => {
                return recipients
                    .iter()
                    .map(|a| GrantDelivery {
                        agent: hex::encode(a.as_bytes()),
                        delivered: false,
                        error: Some(e.to_string()),
                    })
                    .collect();
            }
        };
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&blake3::hash(&payload).as_bytes()[..16]);
        let sends = recipients.iter().map(|recipient| {
            let payload = payload.clone();
            async move {
                let config = crate::dm::DmSendConfig {
                    require_durable_app_ack: true,
                    prefer_raw_quic_if_connected: false,
                    logical_request_id: Some(request_id),
                    max_retries: GRANT_DELIVERY_RETRIES,
                    ..crate::dm::DmSendConfig::default()
                };
                let result = self
                    .send_direct_with_config(recipient, payload, config)
                    .await;
                GrantDelivery {
                    agent: hex::encode(recipient.as_bytes()),
                    delivered: result.is_ok(),
                    error: result.err().map(|e| e.to_string()),
                }
            }
        });
        futures::future::join_all(sends).await
    }

    /// Revoke an issued grant (owner key only): sign a
    /// [`crate::revocation::RevokedSubject::ShareGrant`] record, apply it
    /// locally (effective at the next evaluation, no restart), persist
    /// `revocations-v3.bin`, and publish the v3 set.
    ///
    /// The revocation names `(grant_id, this owner)`, so it can only ever
    /// revoke a grant this owner signed (from any of its installs). It also
    /// signs the grant's `expiry` as its GC horizon, taken from the issued
    /// grant held here; for a grant this install does not hold the horizon
    /// is `u64::MAX` (never collected), so a revocation can never lapse
    /// while its grant could still be honoured.
    ///
    /// # Errors
    /// No owner key, or a signing/verification failure.
    pub async fn revoke_share_grant(
        &self,
        grant_id: [u8; 32],
        reason: Option<String>,
    ) -> Result<crate::revocation::RevocationRecord, ShareGrantError> {
        let owner_key = self.identity.user_keypair().ok_or_else(|| {
            ShareGrantError::Invalid("revoking a grant needs the owner key".into())
        })?;
        let owner = owner_key.user_id();
        let grant_expiry = self
            .share_grant_store()
            .and_then(|store| store.issued(&grant_id))
            .filter(|grant| grant.owner == owner)
            .map_or(u64::MAX, |grant| grant.expiry);
        let subject = crate::revocation::RevokedSubject::ShareGrant(
            crate::revocation::ShareGrantRevocation {
                grant_id,
                owner,
                grant_expiry,
            },
        );
        let record = crate::revocation::RevocationRecord::sign(
            subject,
            owner_key.public_key(),
            owner_key.secret_key(),
            unix_now_secs(),
            reason,
        )
        .map_err(|e| ShareGrantError::BadSignature(e.to_string()))?;
        self.revocation_set
            .write()
            .await
            .verify_and_insert(record.clone(), None)
            .map_err(|e| ShareGrantError::BadSignature(e.to_string()))?;
        crate::persist_share_grant_revocations(&self.revocation_set, self.identity_dir.as_deref())
            .await;
        if let Some(rt) = &self.gossip_runtime {
            let records = self.revocation_set.read().await.share_grant_records();
            if let Ok(bytes) = bincode::serialize(&records) {
                let _ = rt
                    .pubsub()
                    .publish(
                        crate::REVOCATION_V3_TOPIC.to_string(),
                        bytes::Bytes::from(bytes),
                    )
                    .await;
            }
        }
        Ok(record)
    }

    /// #967 B3: the production trigger. A daemon that MISSED a grant
    /// delivery (it holds nothing for `grant_id`) asks `holder` for it:
    /// opens the fetch window in its store and sends the fetch request
    /// over the DM wire. The ADR-0070 §2 flow is then automatic — the
    /// holder's responder serves, the response handler stores.
    pub async fn request_share_grant_fetch(
        &self,
        grant_id: [u8; 32],
        holder: &AgentId,
    ) -> Result<(), crate::dm::DmError> {
        let Some(store) = self.share_grant_store() else {
            return Ok(());
        };
        if store.by_id(&grant_id).is_some() {
            // Already held — nothing to fetch.
            return Ok(());
        }
        // #967 r4 (S1): honour the suppression — a repeat inside the TTL
        // does not send (the r3 code opened the window and sent anyway).
        if !store.note_fetch(&grant_id, Some(holder)) {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(SHARE_GRANT_FETCH_DM_PREFIX.len() + 32);
        payload.extend_from_slice(SHARE_GRANT_FETCH_DM_PREFIX);
        payload.extend_from_slice(&grant_id);
        self.send_direct(holder, payload).await.map(|_| ())
    }

    /// #967 B3: the grantee-side attachment helper — the ids a grantee
    /// holds (received) that should ride along when it opens a DM or
    /// stream to a shared agent, so a daemon that missed delivery can
    /// request them (ADR-0070 §2). Callers attach these to their open
    /// frames; the shared daemon feeds each id to
    /// request_share_grant_fetch (see the Agent impl above).
    pub fn held_grant_ids_for(&self, shared_agent: &AgentId) -> Vec<[u8; 32]> {
        let Some(store) = self.share_grant_store() else {
            return Vec::new();
        };
        let now = unix_now_secs();
        store
            .grants(GrantRole::Received)
            .into_iter()
            .filter(|g| g.agents.contains(shared_agent) && g.is_active_at(now))
            .map(|g| g.grant_id)
            .collect()
    }

    /// #967 r3 (B3): the DM-open attachment. After a successful DM to
    /// `to`, send (spawned, off the hot path) the grant ids this grantee
    /// holds for that shared agent, rate-limited per recipient — the
    /// ADR-0070 par-2 "attaches the grant grant_id when opening a DM"
    /// carrier. A shared daemon that missed a delivery receives the hint
    /// and requests the grants (see on_share_grant_hints).
    /// #967 r4 (B3): the DM-open attachment, PREPARED. Returns the hint
    /// frame this grantee should attach for `to` (rate-limited per
    /// recipient), or None. The caller SPAWNS the send so the DM's own
    /// receipt is never delayed (r3 awaited it inline).
    pub fn grant_hint_payload_for(&self, to: &AgentId) -> Option<Vec<u8>> {
        if *to == self.agent_id() {
            return None;
        }
        let ids = self.held_grant_ids_for(to);
        if ids.is_empty() {
            return None;
        }
        let store = self.share_grant_store()?;
        if !store.note_hint_sent(to) {
            return None; // rate-limited per recipient
        }
        Some(share_grant_hint_payload(&ids))
    }

    /// #967 r3 (B3): the shared-daemon side of the attachment: for every
    /// id this daemon does NOT hold, request the grant from the hint's
    /// sender (ADR par 2: the requester asks the attacher; only OWNER
    /// installs ever answer — see the responder's Issued-role gate).
    /// Returns the number of fetch requests started.
    /// #967 r4 (B2): the shared-daemon side of the attachment. The hint
    /// names grant ids; the FETCH goes to an OWNER install of this
    /// daemon's owner (the revocation source — design (b)), never to the
    /// hinter (r3 fetched from the sender, which a grantee always is, so
    /// every fetch refused). `owner_install` is chosen by the caller
    /// from this daemon's owner-trusted peers.
    pub async fn fetch_missing_grants_via(
        &self,
        owner_install: &AgentId,
        ids: &[[u8; 32]],
    ) -> usize {
        let mut started = 0usize;
        for id in ids.iter().take(SHARE_GRANT_HINT_MAX_IDS) {
            if self
                .request_share_grant_fetch(*id, owner_install)
                .await
                .is_ok()
            {
                started += 1;
            }
        }
        started
    }
}

#[cfg(test)]
mod tests;
