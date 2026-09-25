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
//! written atomically with mode 0600): **issued** grants (signed by this
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

use crate::dm_inbox::{DmTypedPayload, DmTypedPayloadCompletion, DmTypedPayloadCompletionResult};
use crate::identity::{AgentId, UserId, UserKeypair};

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
        let grant: Self = bincode::deserialize(body)
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
            bincode::deserialize::<StoreFile>(&bytes[STORE_MAGIC.len()..])
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
        crate::storage::save_private_bytes_to(path, bytes)
            .await
            .map_err(|e| format!("write {}: {e}", path.display()))
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    /// revoke a grant this owner signed (from any of its installs).
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
        let subject = crate::revocation::RevokedSubject::ShareGrant(
            crate::revocation::ShareGrantRevocation { grant_id, owner },
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
}

#[cfg(test)]
mod tests;
