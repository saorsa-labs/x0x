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
//! owns the prefix). A recipient that does not ACK is queued in the durable
//! owner-side redelivery outbox ([`outbox`], #926) and retried until it ACKs,
//! the grant is revoked, or the entry expires.
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
    /// ADR-0073 calling: the holder may ring the granted agents (inbound
    /// call gate only, `Agent::call_gate_inbound`; opens no stream).
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

fn unix_now_secs() -> u64 {
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
    /// `Call` (ADR-0073): the inbound call gate admits the caller (#980).
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
    /// `true` when delivery failed and the grant was durably queued in the
    /// owner-side redelivery outbox (#926), which keeps retrying it.
    pub queued: bool,
    /// Why delivery failed, if it did (and why it was not queued, if it
    /// was not).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The exact typed-DM payload and logical request id a grant is delivered
/// with. The request id is derived from the payload, so the first delivery
/// and every outbox retry (#926) are the SAME logical request: a receiver
/// that already stored the grant answers `Duplicate`.
///
/// # Errors
/// The grant cannot be encoded ([`ShareGrant::to_dm_payload`]).
pub fn grant_delivery_request(grant: &ShareGrant) -> Result<(Vec<u8>, [u8; 16]), ShareGrantError> {
    let payload = grant.to_dm_payload()?;
    let mut request_id = [0u8; 16];
    request_id.copy_from_slice(&blake3::hash(&payload).as_bytes()[..16]);
    Ok((payload, request_id))
}

/// Deliver `grant` to each recipient concurrently through `send` (which
/// must return `Ok` only on the recipient's durable v2 ACK) and durably
/// queue every failed recipient in `outbox` for redelivery (#926).
pub async fn deliver_grant_via<F, Fut>(
    grant: &ShareGrant,
    recipients: &[AgentId],
    outbox: Option<&outbox::GrantRedeliveryOutbox>,
    now_unix: u64,
    send: F,
) -> Vec<GrantDelivery>
where
    F: Fn(AgentId, Vec<u8>, [u8; 16]) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let (payload, request_id) = match grant_delivery_request(grant) {
        Ok(request) => request,
        Err(e) => {
            return recipients
                .iter()
                .map(|a| GrantDelivery {
                    agent: hex::encode(a.as_bytes()),
                    delivered: false,
                    queued: false,
                    error: Some(e.to_string()),
                })
                .collect();
        }
    };
    let sends = recipients.iter().map(|recipient| {
        let fut = send(*recipient, payload.clone(), request_id);
        async move { (*recipient, fut.await) }
    });
    let mut out = Vec::with_capacity(recipients.len());
    for (recipient, result) in futures::future::join_all(sends).await {
        let mut delivery = GrantDelivery {
            agent: hex::encode(recipient.as_bytes()),
            delivered: result.is_ok(),
            queued: false,
            error: result.err(),
        };
        if !delivery.delivered {
            delivery.queued =
                queue_failed_delivery(grant, recipient, outbox, now_unix, &mut delivery.error)
                    .await;
        }
        out.push(delivery);
    }
    out
}

/// Queue one failed delivery; returns whether it is now queued. A refusal
/// is appended to `error` so the owner sees why it will not be retried.
async fn queue_failed_delivery(
    grant: &ShareGrant,
    recipient: AgentId,
    outbox: Option<&outbox::GrantRedeliveryOutbox>,
    now_unix: u64,
    error: &mut Option<String>,
) -> bool {
    let Some(outbox) = outbox else {
        return false;
    };
    match outbox.enqueue(grant, recipient, now_unix).await {
        Ok(_) => true,
        Err(e) => {
            let reason = format!("not queued for redelivery: {e}");
            *error = Some(match error.take() {
                Some(prev) => format!("{prev}; {reason}"),
                None => reason,
            });
            false
        }
    }
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
    /// # Missed deliveries: the owner-side outbox (#926)
    ///
    /// Without that ACK the sender retries ([`GRANT_DELIVERY_RETRIES`])
    /// under the same logical request id, which the receiver answers
    /// idempotently (`Duplicate`). A recipient that is still unreachable is
    /// durably queued in the redelivery outbox ([`outbox`]) and retried on
    /// bounded backoff — and promptly when its machine connects again —
    /// until it ACKs, the grant is revoked, or the entry's deadline passes.
    /// ADR-0070 §2's grantee-attached fetch is not implemented: the outbox
    /// closes the same gap with no wire change and no new request type.
    /// Until delivery succeeds, a shared agent's daemon that has not
    /// received the grant grants nothing (fail closed).
    pub async fn deliver_share_grant(
        &self,
        grant: &ShareGrant,
        recipients: &[AgentId],
    ) -> Vec<GrantDelivery> {
        let outbox = self.share_grant_outbox();
        deliver_grant_via(
            grant,
            recipients,
            outbox.as_deref(),
            unix_now_secs(),
            |recipient, payload, request_id| {
                self.send_share_grant_dm(recipient, payload, request_id, GRANT_DELIVERY_RETRIES)
            },
        )
        .await
    }

    /// One durable typed-DM grant send; `Ok` only on the durable v2 ACK.
    async fn send_share_grant_dm(
        &self,
        recipient: AgentId,
        payload: Vec<u8>,
        request_id: [u8; 16],
        max_retries: u8,
    ) -> Result<(), String> {
        let config = crate::dm::DmSendConfig {
            require_durable_app_ack: true,
            prefer_raw_quic_if_connected: false,
            logical_request_id: Some(request_id),
            max_retries,
            ..crate::dm::DmSendConfig::default()
        };
        self.send_direct_with_config(&recipient, payload, config)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Install the owner-side grant redelivery outbox (#926; the daemon does
    /// this once at startup).
    pub fn install_share_grant_outbox(&self, outbox: Arc<outbox::GrantRedeliveryOutbox>) {
        self.owner_trust().install_share_grant_outbox(outbox);
    }

    /// The installed grant redelivery outbox, if any.
    #[must_use]
    pub fn share_grant_outbox(&self) -> Option<Arc<outbox::GrantRedeliveryOutbox>> {
        self.owner_trust().share_grant_outbox()
    }

    /// One redelivery-outbox pass (see
    /// [`outbox::GrantRedeliveryOutbox::step`]). `None` when no outbox is
    /// installed.
    pub async fn share_grant_outbox_step(&self) -> Option<outbox::OutboxStepReport> {
        let outbox = self.share_grant_outbox()?;
        Some(
            outbox
                .step(
                    unix_now_secs(),
                    &self.revocation_set,
                    |recipient, payload, request_id| {
                        self.send_share_grant_dm(
                            recipient,
                            payload,
                            request_id,
                            outbox::OUTBOX_SEND_RETRIES,
                        )
                    },
                )
                .await,
        )
    }

    /// `machine` connected: make every queued grant delivery to an agent
    /// known to run on it due now. Cheap when the outbox is empty.
    pub async fn nudge_share_grant_outbox_for_machine(&self, machine: &MachineId) -> bool {
        let Some(outbox) = self.share_grant_outbox() else {
            return false;
        };
        if outbox.is_empty() {
            return false;
        }
        let agents: Vec<AgentId> = self
            .identity_discovery_cache
            .read()
            .await
            .values()
            .filter(|entry| entry.machine_id == *machine)
            .map(|entry| entry.agent_id)
            .filter(|agent| outbox.has_recipient(agent))
            .collect();
        !agents.is_empty() && outbox.nudge(&agents, unix_now_secs())
    }

    /// Revoke an issued grant (owner key only): sign a
    /// [`crate::revocation::RevokedSubject::ShareGrant`] record, apply it
    /// locally (effective at the next evaluation, no restart), durably
    /// persist `revocations-v3.bin`, drop the grant's queued redeliveries
    /// (#926; see [`record_local_share_grant_revocation`]), and publish the
    /// v3 set.
    ///
    /// The revocation names `(grant_id, this owner)`, so it can only ever
    /// revoke a grant this owner signed (from any of its installs). It also
    /// signs the grant's `expiry` as its GC horizon, taken from the issued
    /// grant held here; for a grant this install does not hold the horizon
    /// is `u64::MAX` (never collected), so a revocation can never lapse
    /// while its grant could still be honoured.
    ///
    /// # Errors
    /// No owner key, a signing/verification failure, or `Store` when the
    /// revocation or the outbox removal is not durable (a 5xx to the API
    /// caller; retrying is idempotent).
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
        let outbox = self.share_grant_outbox();
        let durable = record_local_share_grant_revocation(
            record.clone(),
            &self.revocation_set,
            self.identity_dir.as_deref(),
            outbox.as_deref(),
        )
        .await;
        // Publish even when a local write failed: the revocation is in force
        // here and the owner's other installs should learn it. The caller
        // still gets the error (a 5xx), and a retry rewrites both files.
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
        durable.map(|()| record)
    }
}

/// Record a LOCAL share-grant revocation (#926): under the outbox's
/// revocation barrier, insert `record`, write `revocations-v3.bin` durably,
/// and durably drop the grant's queued deliveries.
///
/// The barrier makes a concurrent redelivery pass finish its in-flight sends
/// first and keeps a new pass from starting until the revocation is in the
/// set, so no send of this grant can begin after this returns.
///
/// Returns `Ok` only when BOTH writes are durable, so `DELETE /grants/:id`
/// never answers success for a revocation a restart would forget (which
/// would let the reloaded outbox redeliver the grant). The in-memory
/// revocation and removal stand either way (fail closed for this run), and
/// a retry is idempotent and rewrites both files.
///
/// # Errors
/// `BadSignature` if the record does not verify; `Store` if either write
/// failed.
pub async fn record_local_share_grant_revocation(
    record: crate::revocation::RevocationRecord,
    revocation_set: &RwLock<RevocationSet>,
    identity_dir: Option<&std::path::Path>,
    outbox: Option<&outbox::GrantRedeliveryOutbox>,
) -> Result<(), ShareGrantError> {
    let grant_id = match &record.subject {
        crate::revocation::RevokedSubject::ShareGrant(subject) => Some(subject.grant_id),
        _ => None,
    };
    let _barrier = match outbox {
        Some(outbox) => Some(outbox.revocation_barrier().await),
        None => None,
    };
    revocation_set
        .write()
        .await
        .verify_and_insert(record, None)
        .map_err(|e| ShareGrantError::BadSignature(e.to_string()))?;
    let mut failures = Vec::new();
    if let Err(e) =
        crate::persist_share_grant_revocations_durable(revocation_set, identity_dir).await
    {
        failures.push(e);
    }
    if let (Some(outbox), Some(grant_id)) = (outbox, grant_id) {
        if let Err(e) = outbox.remove_grant(&grant_id).await {
            failures.push(e.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        let joined = failures.join("; ");
        tracing::error!("share-grant revocation not durable: {joined}");
        Err(ShareGrantError::Store(format!(
            "revocation is in force until restart but not durable: {joined}"
        )))
    }
}

pub mod outbox;

#[cfg(test)]
mod tests;
