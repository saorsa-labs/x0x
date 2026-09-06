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

use super::GroupInfo;
use crate::identity::AgentId;
use crate::kv::encrypted::{encrypted_record_aad, store_record_key, KvSecureContext};
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
}

impl GssState {
    fn from_group(info: &GroupInfo) -> Self {
        let active_members = info
            .active_members()
            .filter_map(|m| agent_from_hex(&m.agent_id))
            .collect();
        Self {
            stable_group_id: info.stable_group_id().to_string(),
            shared_secret: info.shared_secret.clone(),
            secret_epoch: info.secret_epoch,
            active_members,
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
        let next = GssState::from_group(info);
        let changed = state.shared_secret != next.shared_secret
            || state.secret_epoch != next.secret_epoch
            || state.active_members != next.active_members;
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
}
