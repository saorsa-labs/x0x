//! GSS-backed [`KvSecureContext`] for encrypted group KvStores (issue #341
//! Phase B).
//!
//! ## ADR scope (read before claiming properties)
//!
//! This is the v1 secure backend chosen by the encrypted-KvStore design
//! (`docs/design/encrypted-kvstore.md`): the named-group **GSS** plane —
//! the legacy plane ADR-0010 describes and ADR-0012 explicitly RETAINS for
//! grandfathered groups and public encrypted presets. Its entire crypto
//! state is `GroupInfo.shared_secret` + `secret_epoch`.
//!
//! - **GSS is not TreeKEM.** This backend provides rekey-on-removal FUTURE
//!   confidentiality only: there is NO per-message forward secrecy within
//!   an epoch and NO post-compromise security. Old records already received
//!   by a removed member stay readable to them. Do not claim otherwise.
//! - Encrypted KvStore v1 REJECTS `SecureGroupPlane::TreeKem` groups (the
//!   daemon route gate does this explicitly) — a TreeKEM-backed context is
//!   future work and any decision to ship it stays Proposed until human
//!   engineering review. The [`KvSecureContext`] trait is the boundary that
//!   keeps that future change store/sync-neutral.
//!
//! The context keeps a **synchronous internal snapshot** (secret, epoch,
//! active-member set) of the authoritative `GroupInfo` because the store
//! layer calls the trait from non-async authorization paths. The daemon
//! refreshes the snapshot through [`GssKvSecureContext::update_from_group`]
//! — the sync loops invoke a caller-supplied refresh hook before every
//! seal/open, so a rekey (ban/remove rotating the shared secret) takes
//! effect on the next record, and a removed member fails the membership
//! check on its next write attempt.

use super::{GroupConfidentiality, GroupInfo, GroupReadAccess, GroupRole, GroupWriteAccess};
use crate::identity::AgentId;
use crate::kv::encrypted::{
    bind_public_payload, encrypted_record_aad, seal_mutation_with_snapshot, store_record_key,
    AuthorSigning, EncryptedKvStoreRecordV1, KvMutationKind, KvSecureContext,
};
use crate::kv::{KvError, KvStoreId, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::collections::HashSet;
use std::sync::Arc;

/// Snapshot of the security-relevant `GroupInfo` fields.
#[derive(Debug, Clone)]
struct GssState {
    stable_group_id: String,
    shared_secret: Option<Vec<u8>>,
    secret_epoch: u64,
    active_members: HashSet<AgentId>,
    member_roles: std::collections::HashMap<AgentId, GroupRole>,
    write_access: GroupWriteAccess,
}

impl GssState {
    fn from_group(info: &GroupInfo) -> Self {
        let active_members = info
            .active_members()
            .filter_map(|m| agent_from_hex(&m.agent_id))
            .collect();
        let member_roles = info
            .active_members()
            .filter_map(|m| agent_from_hex(&m.agent_id).map(|agent| (agent, m.role)))
            .collect();
        Self {
            stable_group_id: info.stable_group_id().to_string(),
            shared_secret: info.shared_secret.clone(),
            secret_epoch: info.secret_epoch,
            active_members,
            member_roles,
            write_access: info.policy.write_access,
        }
    }

    fn authorizes_writer(&self, agent: &AgentId) -> bool {
        match self.write_access {
            GroupWriteAccess::MembersOnly => self.active_members.contains(agent),
            GroupWriteAccess::AdminOnly => self
                .member_roles
                .get(agent)
                .is_some_and(|role| role.at_least(GroupRole::Admin)),
            GroupWriteAccess::ModeratedPublic => false,
        }
    }
}

fn agent_from_hex(hex_str: &str) -> Option<AgentId> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() == crate::identity::PEER_ID_LENGTH {
        let mut arr = [0u8; crate::identity::PEER_ID_LENGTH];
        arr.copy_from_slice(&bytes);
        Some(AgentId(arr))
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct PublicState {
    stable_group_id: String,
    state_revision: u64,
    roster_root: String,
    read_access: GroupReadAccess,
    write_access: GroupWriteAccess,
    writers: std::collections::HashMap<AgentId, GroupRole>,
    valid: bool,
}

impl PublicState {
    fn from_group(info: &GroupInfo) -> Self {
        let writers = info
            .active_members()
            .filter_map(|member| agent_from_hex(&member.agent_id).map(|agent| (agent, member.role)))
            .collect();
        Self {
            stable_group_id: info.stable_group_id().to_string(),
            state_revision: info.state_revision,
            roster_root: super::compute_roster_root(&info.members_v2),
            read_access: info.policy.read_access,
            write_access: info.policy.write_access,
            writers,
            valid: !info.withdrawn
                && !info.is_fork_quarantined()
                && info.policy.confidentiality == GroupConfidentiality::SignedPublic,
        }
    }

    fn authorizes(&self, agent: &AgentId) -> bool {
        if !self.valid {
            return false;
        }
        match self.write_access {
            GroupWriteAccess::MembersOnly => self.writers.contains_key(agent),
            GroupWriteAccess::AdminOnly => self
                .writers
                .get(agent)
                .is_some_and(|role| role.at_least(GroupRole::Admin)),
            GroupWriteAccess::ModeratedPublic => false,
        }
    }

    fn authorizes_reader(&self, agent: &AgentId) -> bool {
        self.valid
            && match self.read_access {
                GroupReadAccess::Public => true,
                GroupReadAccess::MembersOnly => self.writers.contains_key(agent),
            }
    }

    fn authorization_binding(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.kv.public-roster-policy.v1");
        hasher.update(&(self.stable_group_id.len() as u64).to_le_bytes());
        hasher.update(self.stable_group_id.as_bytes());
        hasher.update(&self.state_revision.to_le_bytes());
        hasher.update(self.roster_root.as_bytes());
        hasher.update(&[match self.read_access {
            GroupReadAccess::Public => 0,
            GroupReadAccess::MembersOnly => 1,
        }]);
        hasher.update(&[match self.write_access {
            GroupWriteAccess::MembersOnly => 0,
            GroupWriteAccess::ModeratedPublic => 1,
            GroupWriteAccess::AdminOnly => 2,
        }]);
        *hasher.finalize().as_bytes()
    }
}

/// Current-policy authorization for a plaintext group-signed store.
#[derive(Debug, Clone)]
pub struct PublicGroupKvContext {
    state: Arc<std::sync::RwLock<PublicState>>,
}

impl PublicGroupKvContext {
    #[must_use]
    pub fn from_group(info: &GroupInfo) -> Option<Self> {
        (info.policy.confidentiality == GroupConfidentiality::SignedPublic).then(|| Self {
            state: Arc::new(std::sync::RwLock::new(PublicState::from_group(info))),
        })
    }

    pub fn update_from_group(&self, info: &GroupInfo) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if info.stable_group_id() == state.stable_group_id {
            *state = PublicState::from_group(info);
        }
    }

    #[must_use]
    pub fn refresh_hook<F, Fut>(ctx: Arc<Self>, fetch_group: F) -> crate::kv::sync::SecureRefreshFn
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Option<GroupInfo>> + Send + 'static,
    {
        let fetch_group = Arc::new(fetch_group);
        Arc::new(move || {
            let ctx = Arc::clone(&ctx);
            let fetch_group = Arc::clone(&fetch_group);
            Box::pin(async move {
                match fetch_group().await {
                    Some(info) => ctx.update_from_group(&info),
                    None => ctx.invalidate(),
                }
            })
        })
    }
}

impl KvSecureContext for PublicGroupKvContext {
    fn group_id(&self) -> Vec<u8> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stable_group_id
            .as_bytes()
            .to_vec()
    }

    fn current_epoch(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state_revision
    }

    fn seal(&self, _: &KvStoreId, _: &[u8]) -> Result<(u64, [u8; 24], Vec<u8>)> {
        Err(KvError::SecureRecord(
            "public group context cannot encrypt".to_string(),
        ))
    }

    fn open(&self, _: &KvStoreId, _: u64, _: &[u8; 24], _: &[u8]) -> Result<Vec<u8>> {
        Err(KvError::SecureRecord(
            "public group context cannot decrypt".to_string(),
        ))
    }

    fn is_active_member(&self, agent: &AgentId) -> bool {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.valid && state.writers.contains_key(agent)
    }

    fn is_authorized_writer(&self, agent: &AgentId) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .authorizes(agent)
    }

    fn is_authorized_reader(&self, agent: &AgentId) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .authorizes_reader(agent)
    }

    fn authorization_binding(&self) -> Option<[u8; 32]> {
        Some(
            self.state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .authorization_binding(),
        )
    }

    fn sign_authorized(
        &self,
        signing: &AuthorSigning,
        kind: KvMutationKind,
        store_id: &KvStoreId,
        payload: &[u8],
    ) -> Result<crate::kv::encrypted::SignedKvMutation> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.authorizes(&signing.agent_id) {
            return Err(KvError::Unauthorized(
                "public group publication refused by current writer policy".to_string(),
            ));
        }
        let payload = bind_public_payload(state.authorization_binding(), payload);
        crate::kv::encrypted::sign_mutation_with_snapshot(
            state.stable_group_id.as_bytes().to_vec(),
            state.state_revision,
            signing,
            kind,
            store_id,
            &payload,
        )
    }

    fn sign_control_authorized(
        &self,
        signing: &AuthorSigning,
        store_id: &KvStoreId,
        payload: &[u8],
        reader_only: bool,
    ) -> Result<crate::kv::encrypted::SignedKvMutation> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let authorized = if reader_only {
            state.authorizes_reader(&signing.agent_id)
        } else {
            state.authorizes(&signing.agent_id)
        };
        if !authorized {
            return Err(KvError::Unauthorized(
                "public group control message refused by current policy".to_string(),
            ));
        }
        let payload = bind_public_payload(state.authorization_binding(), payload);
        crate::kv::encrypted::sign_mutation_with_snapshot(
            state.stable_group_id.as_bytes().to_vec(),
            state.state_revision,
            signing,
            KvMutationKind::Control,
            store_id,
            &payload,
        )
    }

    fn invalidate(&self) {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .valid = false;
    }
}

/// GSS secure context bound to one named group.
///
/// Construct with [`GssKvSecureContext::from_group`] (returns `None` for
/// groups without a shared secret — `SignedPublic` groups cannot back an
/// encrypted store) and keep it refreshed with
/// [`GssKvSecureContext::update_from_group`].
#[derive(Debug, Clone)]
pub struct GssKvSecureContext {
    state: Arc<std::sync::RwLock<GssState>>,
}

/// Synchronous authorization view attached to an encrypted store whose wire
/// protection is provided by the daemon's async real-TreeKEM adapter.
#[derive(Debug, Clone)]
pub struct TreeKemKvAuthorizationContext {
    state: Arc<std::sync::RwLock<GssState>>,
}

impl TreeKemKvAuthorizationContext {
    #[must_use]
    pub fn from_group(info: &GroupInfo) -> Option<Self> {
        (info.policy.confidentiality == GroupConfidentiality::MlsEncrypted
            && info.secure_plane == crate::mls::SecureGroupPlane::TreeKem
            && !info.withdrawn
            && !info.is_fork_quarantined())
        .then(|| Self {
            state: Arc::new(std::sync::RwLock::new(GssState::from_group(info))),
        })
    }

    pub fn update_from_group(&self, info: &GroupInfo) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if info.withdrawn
            || info.is_fork_quarantined()
            || info.secure_plane != crate::mls::SecureGroupPlane::TreeKem
        {
            state.active_members.clear();
            state.member_roles.clear();
            return;
        }
        *state = GssState::from_group(info);
    }
}

impl KvSecureContext for TreeKemKvAuthorizationContext {
    fn group_id(&self) -> Vec<u8> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stable_group_id
            .as_bytes()
            .to_vec()
    }

    fn current_epoch(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .secret_epoch
    }

    fn seal(&self, _: &KvStoreId, _: &[u8]) -> Result<(u64, [u8; 24], Vec<u8>)> {
        Err(KvError::SecureRecord(
            "TreeKEM authorization context cannot seal records".to_string(),
        ))
    }

    fn open(&self, _: &KvStoreId, _: u64, _: &[u8; 24], _: &[u8]) -> Result<Vec<u8>> {
        Err(KvError::SecureRecord(
            "TreeKEM authorization context cannot open records".to_string(),
        ))
    }

    fn is_active_member(&self, agent: &AgentId) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_members
            .contains(agent)
    }

    fn is_authorized_writer(&self, agent: &AgentId) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .authorizes_writer(agent)
    }

    fn invalidate(&self) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_members.clear();
        state.member_roles.clear();
    }
}

impl GssKvSecureContext {
    /// Build from the group's current security state.
    ///
    /// Returns `None` when the group holds no shared secret (a
    /// `SignedPublic` group, or a `MlsEncrypted` group whose secret this
    /// agent has not received yet) — such a group cannot seal records.
    #[must_use]
    pub fn from_group(info: &GroupInfo) -> Option<Self> {
        info.shared_secret.as_ref()?;
        Some(Self {
            state: Arc::new(std::sync::RwLock::new(GssState::from_group(info))),
        })
    }

    /// Refresh the snapshot from the authoritative group state.
    ///
    /// Cheap no-op when nothing security-relevant changed. Ignores group
    /// states for a DIFFERENT stable group id (guards against a mis-wired
    /// refresh hook silently re-keying the context onto another group).
    ///
    /// A WITHDRAWN group is terminal lifecycle (#341): the snapshot is
    /// INVALIDATED (secret dropped, roster emptied) and never re-armed from
    /// a tombstone, so an `invalidate()`d context cannot be resurrected by
    /// refreshing from withdrawn state.
    pub fn update_from_group(&self, info: &GroupInfo) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if info.stable_group_id() != state.stable_group_id {
            tracing::warn!(
                target: "x0x::kv",
                "gss kv context refresh skipped: group id mismatch (bound {}, got {})",
                state.stable_group_id,
                info.stable_group_id()
            );
            return;
        }
        if info.withdrawn {
            tracing::warn!(
                target: "x0x::kv",
                "gss kv context INVALIDATED for group {} (epoch {}): authoritative state is WITHDRAWN —                  sealing, opening, and membership all fail closed",
                state.stable_group_id,
                state.secret_epoch
            );
            state.shared_secret = None;
            state.active_members.clear();
            return;
        }
        // ADR-0066 §4 / ADR-0067 — make a marker a REFRESH TRIGGER for this
        // cached context, closing the bind-time gap in §1 rows 10–12 for the
        // GSS plane.
        //
        // This was the one cached KV context blind to the marker.
        // `PublicState::from_group` folds `!is_fork_quarantined()` into
        // `valid`, and `TreeKemKvAuthorizationContext::update_from_group`
        // clears its roster while quarantined — but `GssState` had no notion
        // of quarantine at all, and neither did the refresh that feeds it. So
        // a marker installed AFTER a GSS store bound was invisible to work
        // already in flight: the cached roster kept authorizing writers on an
        // authorization taken before the fork was observed. That is exactly
        // the bind-time gap §4 exists to close, and the reason §4 asks for the
        // install to be a refresh trigger "from both ends".
        //
        // The shape deliberately matches the TreeKEM context's: empty the
        // roster and drop the secret so sealing, opening and membership all
        // fail closed. It is NOT terminal like `withdrawn` — a later refresh
        // after a manual clear re-arms the context from live state, because a
        // quarantine is recoverable and a withdrawal is not.
        if info.is_fork_quarantined() {
            tracing::warn!(
                target: "x0x::kv",
                "gss kv context suspended for group {} (epoch {}): ADR-0066 fork quarantine — \
                 sealing, opening and membership fail closed until the marker is cleared",
                state.stable_group_id,
                state.secret_epoch
            );
            state.shared_secret = None;
            state.active_members.clear();
            state.member_roles.clear();
            return;
        }
        let next = GssState::from_group(info);
        let changed = state.shared_secret != next.shared_secret
            || state.secret_epoch != next.secret_epoch
            || state.active_members != next.active_members
            || state.member_roles != next.member_roles
            || state.write_access != next.write_access;
        if changed {
            tracing::debug!(
                target: "x0x::kv",
                "gss kv context refreshed for group {}: epoch {} -> {}, active members {} -> {}",
                state.stable_group_id,
                state.secret_epoch,
                next.secret_epoch,
                state.active_members.len(),
                next.active_members.len()
            );
            *state = next;
        }
    }

    /// Build the async refresh hook the sync loops call before every
    /// seal/open.
    ///
    /// `fetch_group` re-reads the authoritative `GroupInfo` (however the
    /// embedder holds it — the daemon reads its named-groups map) and this
    /// context is refreshed from whatever it returns.
    ///
    /// Lifecycle: `None` means the group NO LONGER EXISTS locally (left,
    /// removed) — the context is INVALIDATED, never left holding the stale
    /// secret/roster. A returned withdrawn tombstone likewise invalidates
    /// (see [`update_from_group`](Self::update_from_group)). `fetch_group`
    /// must therefore return the last-known state while a read is merely
    /// contended, and `None` only when the group is truly gone.
    #[must_use]
    pub fn refresh_hook<F, Fut>(ctx: Arc<Self>, fetch_group: F) -> crate::kv::sync::SecureRefreshFn
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Option<GroupInfo>> + Send + 'static,
    {
        // Shared with each invocation: the async block moves its own Arc
        // clone, so the outer closure stays `Fn` (callable many times).
        let fetch_group = Arc::new(fetch_group);
        Arc::new(move || {
            let ctx = Arc::clone(&ctx);
            let fetch_group = Arc::clone(&fetch_group);
            Box::pin(async move {
                match fetch_group().await {
                    Some(info) => ctx.update_from_group(&info),
                    None => {
                        tracing::warn!(
                            target: "x0x::kv",
                            "gss kv refresh found NO group state — invalidating context (group left or removed)"
                        );
                        ctx.invalidate();
                    }
                }
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        })
    }

    /// Seal bytes using one already-held GSS snapshot.
    fn seal_snapshot(
        state: &GssState,
        store_id: &KvStoreId,
        plaintext: &[u8],
    ) -> Result<(u64, [u8; 24], Vec<u8>)> {
        let secret = state.shared_secret.as_ref().ok_or_else(|| {
            KvError::SecureRecord(
                "local agent holds no group shared secret — cannot seal store record".to_string(),
            )
        })?;
        let epoch = state.secret_epoch;
        let group_id = state.stable_group_id.as_bytes();
        let key = store_record_key(secret, epoch, group_id, store_id.as_bytes());
        let mut nonce = [0u8; 24];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let aad = encrypted_record_aad(group_id, store_id.as_bytes(), epoch);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| KvError::SecureRecord("AEAD seal failed".to_string()))?;
        Ok((epoch, nonce, ciphertext))
    }
}

impl KvSecureContext for GssKvSecureContext {
    fn group_id(&self) -> Vec<u8> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stable_group_id
            .as_bytes()
            .to_vec()
    }

    fn current_epoch(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .secret_epoch
    }

    fn seal(&self, store_id: &KvStoreId, plaintext: &[u8]) -> Result<(u64, [u8; 24], Vec<u8>)> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::seal_snapshot(&state, store_id, plaintext)
    }

    fn seal_authorized(
        &self,
        signing: &AuthorSigning,
        kind: KvMutationKind,
        store_id: &KvStoreId,
        payload: &[u8],
    ) -> Result<EncryptedKvStoreRecordV1> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let authorized = if kind == KvMutationKind::Control {
            state.active_members.contains(&signing.agent_id)
        } else {
            state.authorizes_writer(&signing.agent_id)
        };
        if !authorized {
            return Err(KvError::SecureRecord(
                "encrypted publication refused by current member/write policy".to_string(),
            ));
        }
        seal_mutation_with_snapshot(
            state.stable_group_id.as_bytes().to_vec(),
            state.secret_epoch,
            signing,
            kind,
            store_id,
            payload,
            |plaintext| Self::seal_snapshot(&state, store_id, plaintext),
        )
    }

    fn open(
        &self,
        store_id: &KvStoreId,
        epoch: u64,
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // GSS holds only the CURRENT epoch secret: past epochs are gone (a
        // late joiner never needs them) and future epochs have not arrived.
        if epoch != state.secret_epoch {
            return Err(KvError::SecureRecord(format!(
                "no group secret for epoch {epoch} (local epoch is {})",
                state.secret_epoch
            )));
        }
        let secret = state.shared_secret.as_ref().ok_or_else(|| {
            KvError::SecureRecord("local agent holds no group shared secret".to_string())
        })?;
        let group_id = state.stable_group_id.as_bytes();
        let key = store_record_key(secret, epoch, group_id, store_id.as_bytes());
        let cipher = XChaCha20Poly1305::new((&key).into());
        let aad = encrypted_record_aad(group_id, store_id.as_bytes(), epoch);
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                KvError::SecureRecord("AEAD open failed (wrong key or tampered record)".to_string())
            })
    }

    fn is_active_member(&self, agent: &AgentId) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_members
            .contains(agent)
    }

    fn is_authorized_writer(&self, agent: &AgentId) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .authorizes_writer(agent)
    }

    fn invalidate(&self) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shared_secret.is_some() || !state.active_members.is_empty() {
            tracing::warn!(
                target: "x0x::kv",
                "gss kv context INVALIDATED for group {} (epoch {}): group left/removed/withdrawn —                  sealing, opening, and membership all fail closed until a re-armed refresh",
                state.stable_group_id,
                state.secret_epoch
            );
        }
        state.shared_secret = None;
        state.active_members.clear();
        state.member_roles.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal MlsEncrypted GroupInfo (default policy is
    /// PrivateSecure / MlsEncrypted) whose creator is Active and which holds
    /// a rotated shared secret (epoch >= 1).
    fn group(unique_id: &str, member: AgentId) -> GroupInfo {
        let mut info = GroupInfo::new(
            unique_id.to_string(),
            String::new(),
            member,
            unique_id.to_string(),
        );
        info.migrate_from_v1();
        let _ = info.rotate_shared_secret();
        info
    }

    #[test]
    fn from_group_requires_shared_secret() {
        let member = AgentId([1; 32]);
        let mut info = group("g", member);
        info.shared_secret = None;
        assert!(GssKvSecureContext::from_group(&info).is_none());
        let info = group("g", member);
        assert!(GssKvSecureContext::from_group(&info).is_some());
    }

    #[test]
    fn seal_open_round_trip_and_membership() {
        let member = AgentId([1; 32]);
        let outsider = AgentId([2; 32]);
        let info = group("ctx-g", member);
        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let store_id = KvStoreId::new([5; 32]);

        let (epoch, nonce, ct) = ctx.seal(&store_id, b"secret-value").expect("seal");
        assert_eq!(epoch, info.secret_epoch);
        let pt = ctx.open(&store_id, epoch, &nonce, &ct).expect("open");
        assert_eq!(pt, b"secret-value");

        assert!(ctx.is_active_member(&member));
        assert!(!ctx.is_active_member(&outsider));
    }

    #[test]
    fn seal_authorized_admits_member_and_rejects_removed_member() {
        let keypair = crate::identity::AgentKeypair::generate().expect("keypair");
        let member = keypair.agent_id();
        let mut info = group("authorized-g", member);
        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let signing = AuthorSigning::from_keypair(&keypair).expect("signing");
        let store_id = KvStoreId::new([15; 32]);

        let record = ctx
            .seal_authorized(
                &signing,
                KvMutationKind::Delta,
                &store_id,
                b"authorized-payload",
            )
            .expect("active member can seal");
        assert_eq!(record.epoch, ctx.current_epoch());
        assert!(!record.ciphertext.is_empty());

        info.remove_member(&hex::encode(member.as_bytes()), None);
        ctx.update_from_group(&info);
        let err = ctx
            .seal_authorized(&signing, KvMutationKind::Delta, &store_id, b"must-not-seal")
            .expect_err("removed member must fail atomic admission");
        assert!(err
            .to_string()
            .contains("refused by current member/write policy"));
    }

    #[test]
    fn update_from_group_rotates_epoch_and_drops_removed_member() {
        let member = AgentId([1; 32]);
        let peer = AgentId([3; 32]);
        let mut info = group("rot-g", member);
        let creator_hex = hex::encode(member.as_bytes());
        // Add a second active member (new_member seeds Active).
        info.members_v2.insert(
            hex::encode(peer.as_bytes()),
            crate::groups::GroupMember::new_member(
                hex::encode(peer.as_bytes()),
                None,
                Some(creator_hex.clone()),
                0,
            ),
        );

        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let store_id = KvStoreId::new([6; 32]);
        let (epoch0, nonce0, ct0) = ctx.seal(&store_id, b"pre-rekey").expect("seal");
        assert!(ctx.is_active_member(&peer));

        // Rekey + remove the peer (ban flow): new secret, new epoch, roster
        // without the peer.
        let (_, epoch1) = info.rotate_shared_secret();
        info.remove_member(&hex::encode(peer.as_bytes()), Some(creator_hex));
        ctx.update_from_group(&info);

        assert_eq!(ctx.current_epoch(), epoch1);
        assert!(epoch1 > epoch0);
        assert!(!ctx.is_active_member(&peer));

        // Old-epoch record no longer opens; new-epoch records do.
        assert!(ctx.open(&store_id, epoch0, &nonce0, &ct0).is_err());
        let (epoch, _, _) = ctx.seal(&store_id, b"post-rekey").expect("seal");
        assert_eq!(epoch, epoch1);
    }

    #[test]
    fn invalidate_fails_closed_everywhere() {
        let member = AgentId([1; 32]);
        let info = group("inv-g", member);
        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let store_id = KvStoreId::new([7; 32]);
        assert!(ctx.seal(&store_id, b"x").is_ok());
        assert!(ctx.is_active_member(&member));

        ctx.invalidate();
        // No key: seal and open refuse...
        assert!(ctx.seal(&store_id, b"x").is_err());
        let (_, nonce, ct) = {
            // A pre-invalidation record can no longer be opened either.
            let pre = GssKvSecureContext::from_group(&info).expect("context");
            let (e, n, c) = pre.seal(&store_id, b"old").expect("seal");
            assert!(ctx.open(&store_id, e, &n, &c).is_err());
            (e, n, c)
        };
        let _ = (nonce, ct);
        // ...and the roster is gone: the v1 write rule admits nobody.
        assert!(!ctx.is_active_member(&member));

        // A later refresh from a REJOINED group state re-arms the context.
        let rejoined = group("inv-g", member);
        ctx.update_from_group(&rejoined);
        assert!(ctx.seal(&store_id, b"x").is_ok());
        assert!(ctx.is_active_member(&member));
    }

    #[tokio::test]
    async fn refresh_hook_invalidates_when_group_disappears() {
        // Regression (PR #508 review r2 P1): the exported helper used to
        // treat `None` from the authoritative source as a no-op, retaining
        // the stale secret and roster after the group vanished (leave or
        // removal). `None` is lifecycle: the context must fail closed on
        // sealing, opening, AND membership until a re-armed refresh.
        let member = AgentId([1; 32]);
        let info = group("gone-g", member);
        let ctx = Arc::new(GssKvSecureContext::from_group(&info).expect("context"));
        let store_id = KvStoreId::new([8; 32]);
        let (epoch, nonce, ciphertext) = ctx.seal(&store_id, b"before leave").expect("seal");
        assert!(ctx.is_active_member(&member));

        // The authoritative state is gone: fetch returns None.
        let hook = GssKvSecureContext::refresh_hook(Arc::clone(&ctx), || async { None });
        hook().await;

        assert!(
            !ctx.is_active_member(&member),
            "stale roster must not survive a missing-group refresh"
        );
        assert!(
            ctx.seal(&store_id, b"after leave").is_err(),
            "stale secret must not survive a missing-group refresh"
        );
        assert!(
            ctx.open(&store_id, epoch, &nonce, &ciphertext).is_err(),
            "old-epoch records must not open after a missing-group refresh"
        );

        // Re-arm ONLY from a live, matching, non-withdrawn group state.
        let rejoined = group("gone-g", member);
        let rearm = GssKvSecureContext::refresh_hook(Arc::clone(&ctx), move || {
            let rejoined = rejoined.clone();
            async move { Some(rejoined) }
        });
        rearm().await;
        assert!(ctx.seal(&store_id, b"rejoined").is_ok());
        assert!(ctx.is_active_member(&member));
    }

    #[tokio::test]
    async fn refresh_hook_never_rearms_from_withdrawn_tombstone() {
        // Regression (PR #508 review r2 P1): a withdrawn GroupInfo passed
        // through the helper used to RESTORE the secret and roster — even
        // on an already-invalidated context. A tombstone is terminal
        // lifecycle: it must deepen the invalidation, never re-arm it.
        let member = AgentId([1; 32]);
        let mut info = group("wd-g", member);
        let ctx = Arc::new(GssKvSecureContext::from_group(&info).expect("context"));
        // Retired context (e.g. the leave path already invalidated it).
        ctx.invalidate();
        // The tombstone still carries a secret + roster (as retained
        // withdrawn state can); refreshing from it must NOT re-arm.
        info.withdrawn = true;
        let hook = GssKvSecureContext::refresh_hook(Arc::clone(&ctx), move || {
            let info = info.clone();
            async move { Some(info) }
        });
        hook().await;

        assert!(
            !ctx.is_active_member(&member),
            "withdrawn refresh must not restore the roster"
        );
        assert!(
            ctx.seal(&KvStoreId::new([9; 32]), b"after withdrawal")
                .is_err(),
            "withdrawn refresh must not restore the secret"
        );
    }

    #[tokio::test]
    async fn update_from_group_withdrawn_invalidates_armed_context() {
        // Direct boundary coverage: update_from_group itself (not only the
        // helper) invalidates an ARMED context on withdrawn state — and a
        // FOREIGN group's tombstone still does nothing (guard ordering).
        let member = AgentId([1; 32]);
        let info = group("arm-g", member);
        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let store_id = KvStoreId::new([4; 32]);
        assert!(ctx.seal(&store_id, b"armed").is_ok());

        // Foreign tombstone: ignored entirely, context stays armed.
        let mut foreign = group("other-g", member);
        foreign.withdrawn = true;
        ctx.update_from_group(&foreign);
        assert!(
            ctx.seal(&store_id, b"still armed").is_ok(),
            "a foreign tombstone must not touch this context"
        );

        // Matching tombstone: invalidates.
        let mut withdrawn = group("arm-g", member);
        withdrawn.withdrawn = true;
        ctx.update_from_group(&withdrawn);
        assert!(!ctx.is_active_member(&member));
        assert!(ctx.seal(&store_id, b"post-withdraw").is_err());
    }

    #[test]
    fn update_ignores_foreign_group() {
        let member = AgentId([1; 32]);
        let info = group("g-one", member);
        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let other = group("g-two", member);
        ctx.update_from_group(&other);
        // Still bound to the original group.
        assert_eq!(ctx.group_id(), b"g-one".to_vec());
    }

    #[test]
    fn public_context_enforces_current_role_policy_and_revision() {
        let owner = AgentId([1; 32]);
        let member = AgentId([2; 32]);
        let mut info = GroupInfo::new(
            "public".to_string(),
            String::new(),
            owner,
            "public-group".to_string(),
        );
        info.migrate_from_v1();
        info.policy.confidentiality = GroupConfidentiality::SignedPublic;
        info.add_member(
            hex::encode(member.as_bytes()),
            GroupRole::Member,
            Some(hex::encode(owner.as_bytes())),
            None,
        );
        let ctx = PublicGroupKvContext::from_group(&info).expect("public context");
        assert!(ctx.is_authorized_writer(&member));

        info.policy.write_access = GroupWriteAccess::AdminOnly;
        info.state_revision = 7;
        ctx.update_from_group(&info);
        assert!(!ctx.is_authorized_writer(&member));
        assert!(ctx.is_authorized_writer(&owner));
        assert_eq!(ctx.current_epoch(), 7);

        let before = ctx.authorization_binding().expect("binding");
        info.members_v2.remove(&hex::encode(member.as_bytes()));
        // Same numeric revision with a different roster must not share a
        // public-store authorization identity.
        ctx.update_from_group(&info);
        assert_eq!(ctx.current_epoch(), 7);
        assert_ne!(ctx.authorization_binding().expect("binding"), before);

        info.policy.write_access = GroupWriteAccess::ModeratedPublic;
        ctx.update_from_group(&info);
        assert!(!ctx.is_authorized_writer(&owner));

        let terminal = info.terminal_commit_header();
        info.fork_quarantine = Some(crate::groups::ForkQuarantine {
            revision: info.state_revision,
            state_hash: info.state_hash.clone(),
            committed_by: hex::encode(owner.as_bytes()),
            observed_at_ms: 1,
            snapshot: crate::groups::ForkSnapshot {
                terminal_commit: terminal.clone(),
                conflicting_commit: terminal,
                classification: Some("signer_only".to_string()),
            },
            no_anchor: false,
        });
        info.policy.write_access = GroupWriteAccess::MembersOnly;
        ctx.update_from_group(&info);
        assert!(!ctx.is_active_member(&owner));
        assert!(!ctx.is_authorized_writer(&owner));
        assert!(!ctx.is_authorized_reader(&owner));
    }

    /// An authenticated-evidence marker, minimal but well-formed.
    fn quarantine_marker(info: &GroupInfo, revision: u64) -> crate::groups::ForkQuarantine {
        crate::groups::ForkQuarantine {
            revision,
            state_hash: info.state_hash.clone(),
            committed_by: "22".repeat(32),
            observed_at_ms: 1,
            snapshot: crate::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        }
    }

    /// ADR-0066 §4 / ADR-0067 — the bind-time gap, GSS plane (§1 rows 10–12).
    ///
    /// This was the ONE cached KV context blind to the marker: `PublicState`
    /// folds `!is_fork_quarantined()` into `valid` and the TreeKEM context
    /// clears its roster, but `GssState` had no notion of quarantine at all.
    /// So a marker installed AFTER a GSS store bound was invisible to work
    /// already in flight — the cached roster kept authorizing writers on an
    /// authorization taken before the fork was observed.
    ///
    /// The claim defended here: a refresh that SEES the marker suspends the
    /// context, so sealing, opening and membership all fail closed.
    #[test]
    fn gss_context_suspends_when_a_marker_appears_after_the_bind() {
        let keypair = crate::identity::AgentKeypair::generate().expect("keypair");
        let member = keypair.agent_id();
        let mut info = group("gss-quarantine-g", member);
        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let store_id = KvStoreId::new([21; 32]);

        // Bound on a healthy group: the member is authorized and can seal.
        assert!(ctx.is_active_member(&member));
        assert!(ctx.seal(&store_id, b"before").is_ok());

        // A fork observation lands.
        info.fork_quarantine = Some(quarantine_marker(&info, 7));
        ctx.update_from_group(&info);

        assert!(
            !ctx.is_active_member(&member),
            "the cached roster must be emptied, or a contested roster keeps authorizing"
        );
        assert!(
            !ctx.is_authorized_writer(&member),
            "writes must fail closed while the group is quarantined"
        );
        assert!(
            ctx.seal(&store_id, b"after").is_err(),
            "the secret must be dropped so nothing new can be sealed under the fork"
        );
    }

    /// ...and a quarantine is RECOVERABLE, unlike a withdrawal. After a manual
    /// clear the next refresh re-arms the context from live state. Getting this
    /// wrong would turn every quarantine into a permanently dead store, which
    /// is why it is a separate assertion rather than a footnote.
    #[test]
    fn gss_context_re_arms_after_the_marker_is_cleared() {
        let keypair = crate::identity::AgentKeypair::generate().expect("keypair");
        let member = keypair.agent_id();
        let mut info = group("gss-clear-g", member);
        let ctx = GssKvSecureContext::from_group(&info).expect("context");
        let store_id = KvStoreId::new([22; 32]);

        info.fork_quarantine = Some(quarantine_marker(&info, 7));
        ctx.update_from_group(&info);
        assert!(!ctx.is_active_member(&member));

        info.fork_quarantine = None;
        ctx.update_from_group(&info);
        assert!(
            ctx.is_active_member(&member),
            "a cleared quarantine must re-arm the context — it is not terminal like withdrawal"
        );
        assert!(
            ctx.seal(&store_id, b"after-clear").is_ok(),
            "and sealing must work again once the marker is gone"
        );
    }
}
