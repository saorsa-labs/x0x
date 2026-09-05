//! Encrypted group-scoped KvStore wire format and secure-context boundary
//! (issue #341 Phase B, design: `docs/design/encrypted-kvstore.md`).
//!
//! An encrypted store never publishes a plaintext [`KvStoreDelta`]. Every
//! gossip publication — incremental delta, full-state serve, or state-sync
//! control message — is wrapped in a **sign-then-encrypt** envelope:
//!
//! ```text
//! KvStore mutation / control message
//!   -> canonical bytes signed with the author's ML-DSA-65 agent key
//!   -> AEAD-sealed (XChaCha20-Poly1305) under the group's per-epoch key
//!   -> EncryptedKvStoreRecordV1 on the store topic
//! ```
//!
//! Security properties (see the design doc for the full model):
//!
//! - **Confidentiality on gossip**: keys, values, metadata, and mutation
//!   shape are inside the ciphertext; the envelope carries only routing
//!   metadata (group, store, epoch, nonce). AEAD key derivation is
//!   store-scoped, so group-message keys and store-record keys never
//!   coincide.
//! - **Authorship**: the inner ML-DSA-65 signature binds author, group,
//!   store, epoch, and payload. Because the group AEAD is a shared secret,
//!   decryption alone only proves "some current member wrote this" — the
//!   inner signature preserves *who*. Receivers derive the `AgentId` from
//!   the included public key and reject any record whose claimed author
//!   does not match that derivation, BEFORE signature verification.
//! - **Cross-group / cross-store / cross-epoch replay**: the AEAD AAD and
//!   the signed bytes both bind domain, group, store, and epoch.
//! - **Rekey-on-ban**: the envelope epoch is plaintext so receivers pick
//!   the key; only the current epoch's secret is held, so a member that has
//!   not received the post-rekey secret cannot read or write new-epoch
//!   records, and a removed member (no new secret) is cut off after the
//!   group rekeys. Stale pre-rekey records are rejected, not applied.
//!
//! The AEAD choice is XChaCha20-Poly1305 with a fresh random 192-bit nonce
//! per record (the design doc's stated preference): no persisted counter is
//! needed and the birthday bound is unreachable at store-record volumes.

use crate::identity::AgentId;
use crate::kv::{KvError, KvStoreId, Result};
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Domain-separation tag for the outer AEAD AAD.
pub const ENCRYPTED_RECORD_DOMAIN: &[u8] = b"x0x.kv.encrypted-record.v1";

/// Domain-separation tag for the inner signed mutation bytes.
pub const SIGNED_MUTATION_DOMAIN: &[u8] = b"x0x.kv.signed-mutation.v1";

/// Key-derivation domain for the store-scoped AEAD key. Deliberately
/// distinct from the group-message derivation (`x0x.group.secure`), so a
/// store record's key can never equal a secure-group message key even for
/// the same (secret, epoch, group).
const STORE_RECORD_KEY_DOMAIN: &[u8] = b"x0x.kv.store-record\0";

/// AEAD algorithm identifier carried in the envelope-adjacent signed
/// mutation. Only ML-DSA-65 exists today; the field is forward-looking so a
/// future algorithm cannot be smuggled past an old parser silently.
pub const SIG_ALGORITHM_ML_DSA65: u8 = 0;

/// What the sealed payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KvMutationKind {
    /// An incremental [`KvStoreDelta`] (a regular put/remove/update).
    Delta = 0,
    /// A full-state delta (bootstrap / post-rekey current-state serve).
    FullState = 1,
    /// A state-sync control message (`KvSyncMessage` bytes) on the
    /// `/state-sync` side topic.
    Control = 2,
}

/// Outer gossip envelope for an encrypted store record.
///
/// Carries only routing/decryption metadata; every content-bearing field is
/// inside `ciphertext`. The epoch is plaintext BY DESIGN (receivers must
/// select the right epoch key before decryption) — the design doc's
/// security-properties section documents the resulting metadata leak: gossip
/// observers can see epoch boundaries (rekey timing), never contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedKvStoreRecordV1 {
    /// Stable group id bytes this record belongs to (cross-group replay
    /// defense; must equal the local context's group id).
    pub group_id: Vec<u8>,
    /// The 32-byte store id (cross-store replay defense).
    pub store_id: [u8; 32],
    /// Group secret epoch the record was sealed under.
    pub epoch: u64,
    /// Fresh random 192-bit XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// AEAD ciphertext (inner `SignedKvMutation` bincode).
    pub ciphertext: Vec<u8>,
}

/// Inner sign-then-encrypt record: author-bound mutation bytes, sealed
/// inside an [`EncryptedKvStoreRecordV1`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedKvMutation {
    /// Stable group id bytes (bound by the signature).
    pub group_id: Vec<u8>,
    /// The 32-byte store id (bound by the signature).
    pub store_id: [u8; 32],
    /// Group secret epoch (bound by the signature; equals the envelope's).
    pub epoch: u64,
    /// Claimed author. Receivers MUST verify this equals
    /// `AgentId::from_public_key(author_pubkey)` before trusting it.
    pub author_id: AgentId,
    /// Author's ML-DSA-65 public key bytes (self-proving).
    pub author_pubkey: Vec<u8>,
    /// Signature algorithm (`SIG_ALGORITHM_ML_DSA65`).
    pub algorithm: u8,
    /// What `payload` serializes (see [`KvMutationKind`]).
    pub kind: KvMutationKind,
    /// Canonical serialized payload (delta / full-state delta / control).
    pub payload: Vec<u8>,
    /// ML-DSA-65 signature over [`SignedKvMutation::signing_bytes`].
    pub signature: Vec<u8>,
}

impl SignedKvMutation {
    /// The exact bytes covered by the author's signature: everything except
    /// the signature itself, length-prefixed where variable-length.
    ///
    /// Layout: `SIGNED_MUTATION_DOMAIN || lp(group_id) || store_id ||
    /// epoch_le || author_id || algorithm || kind || lp(payload)`.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + self.payload.len());
        buf.extend_from_slice(SIGNED_MUTATION_DOMAIN);
        lp(&mut buf, &self.group_id);
        buf.extend_from_slice(&self.store_id);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(self.author_id.as_bytes());
        buf.push(self.algorithm);
        // `kind` serializes as its discriminant (repr u8) — mirror that
        // byte exactly so the signed bytes are independent of bincode
        // representation choices.
        buf.push(match self.kind {
            KvMutationKind::Delta => 0,
            KvMutationKind::FullState => 1,
            KvMutationKind::Control => 2,
        });
        lp(&mut buf, &self.payload);
        buf
    }
}

/// Write a length-prefixed byte slice (64-bit LE length + data).
fn lp(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
}

/// The deterministic AEAD AAD for a store record: domain, group, store, and
/// epoch, length-prefixed. Identically computable by sealer and opener, and
/// bound a second time inside the signed bytes.
#[must_use]
pub fn encrypted_record_aad(group_id: &[u8], store_id: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(ENCRYPTED_RECORD_DOMAIN);
    lp(&mut buf, group_id);
    buf.extend_from_slice(store_id);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf
}

/// Derive the store-scoped, epoch-bound 32-byte AEAD key.
///
/// `secret` is the group's current shared secret. The derivation is
/// domain-separated from the group secure-message key so the two planes
/// never share a key.
#[must_use]
pub fn store_record_key(
    secret: &[u8],
    epoch: u64,
    group_id: &[u8],
    store_id: &[u8; 32],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(secret.len() + 80);
    material.extend_from_slice(STORE_RECORD_KEY_DOMAIN);
    material.extend_from_slice(secret);
    material.extend_from_slice(&epoch.to_le_bytes());
    lp(&mut material, group_id);
    material.extend_from_slice(store_id);
    *blake3::hash(&material).as_bytes()
}

/// The secure-context capability an encrypted store binds to (design doc:
/// "SecureContext boundary").
///
/// It deliberately knows nothing about `GroupInfo`, gossip, or the daemon:
/// it answers exactly the questions the encrypted store sync path needs —
/// which group am I bound to, what is the current epoch, seal/open bytes,
/// and is this author an active member. The v1 backend is the named-group
/// GSS plane ([`crate::groups::GssKvSecureContext`]); a TreeKEM backend can
/// implement the same trait later without touching store or sync code.
///
/// The trait is **synchronous** by design: the store layer calls it from
/// non-async authorization paths (`merge_delta`, `authorize_local_write`).
/// Backends backed by async state (the daemon's group map) keep a sync
/// internal snapshot refreshed by the caller before network I/O — see
/// [`crate::groups::GssKvSecureContext::update_from_group`].
pub trait KvSecureContext: Send + Sync {
    /// The stable group id bytes this context is bound to.
    fn group_id(&self) -> Vec<u8>;

    /// The current group secret epoch records are sealed under.
    fn current_epoch(&self) -> u64;

    /// Seal `plaintext` for this store under the current epoch.
    ///
    /// Returns `(epoch, nonce, ciphertext)`; the nonce is freshly random
    /// per call. The implementation binds `group_id || store_id || epoch`
    /// into the AEAD AAD (see [`encrypted_record_aad`]).
    ///
    /// # Errors
    ///
    /// [`KvError::SecureRecord`] when the context has no usable group key
    /// (e.g. the local agent has not received the group secret yet) or the
    /// AEAD operation fails.
    fn seal(&self, store_id: &KvStoreId, plaintext: &[u8]) -> Result<(u64, [u8; 24], Vec<u8>)>;

    /// Open a record sealed for this store at `epoch`.
    ///
    /// The implementation MUST reject a foreign `epoch` (one it holds no
    /// key for — v1 backends hold only the current epoch) and MUST bind the
    /// AAD exactly as [`encrypted_record_aad`] computes it.
    ///
    /// # Errors
    ///
    /// [`KvError::SecureRecord`] on unknown epoch, AAD mismatch, or AEAD
    /// authentication failure.
    fn open(
        &self,
        store_id: &KvStoreId,
        epoch: u64,
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    /// Whether `agent` is an active member of the bound group — the v1
    /// write rule for encrypted stores.
    fn is_active_member(&self, agent: &AgentId) -> bool;
}

/// The local agent's ML-DSA-65 signing material for sealed mutations.
///
/// Every member signs its own deltas (not just the store owner), so this is
/// distinct from the owner-only checkpoint signing material: it is required
/// on any sync that publishes to an encrypted store.
#[derive(Clone)]
pub struct AuthorSigning {
    /// The author identity — must equal
    /// `AgentId::from_public_key(&public_key)` (verified at construction).
    pub agent_id: AgentId,
    public_key: ant_quic::MlDsaPublicKey,
    secret_key: ant_quic::MlDsaSecretKey,
}

impl std::fmt::Debug for AuthorSigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorSigning")
            .field("agent_id", &self.agent_id)
            .finish_non_exhaustive()
    }
}

impl AuthorSigning {
    /// Build from raw ML-DSA-65 key bytes.
    ///
    /// # Errors
    ///
    /// [`KvError::Gossip`] if either key fails to parse, or
    /// [`KvError::OwnerTokenInvalid`] if the public key does not derive to
    /// `agent_id` (the author binding would be unverifiable downstream).
    pub fn from_bytes(agent_id: AgentId, pk: &[u8], sk: &[u8]) -> Result<Self> {
        let public_key = ant_quic::MlDsaPublicKey::from_bytes(pk)
            .map_err(|e| KvError::Gossip(format!("author public key parse failed: {e:?}")))?;
        let secret_key = ant_quic::MlDsaSecretKey::from_bytes(sk)
            .map_err(|e| KvError::Gossip(format!("author secret key parse failed: {e:?}")))?;
        let derived = AgentId::from_public_key(&public_key);
        if derived != agent_id {
            return Err(KvError::OwnerTokenInvalid(
                "author signing material: public key does not derive to agent_id".to_string(),
            ));
        }
        Ok(Self {
            agent_id,
            public_key,
            secret_key,
        })
    }

    /// Build from the agent keypair held by an [`crate::identity::Identity`].
    ///
    /// # Errors
    ///
    /// As [`AuthorSigning::from_bytes`].
    pub fn from_keypair(keypair: &crate::identity::AgentKeypair) -> Result<Self> {
        let (pk, sk) = keypair.to_bytes();
        Self::from_bytes(keypair.agent_id(), &pk, &sk)
    }

    /// The author's public key bytes (carried inside every sealed record).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Sign `bytes` with the author's secret key.
    ///
    /// # Errors
    ///
    /// [`KvError::Gossip`] if the ML-DSA-65 sign operation fails.
    pub fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        sign_with_ml_dsa(&self.secret_key, bytes)
            .map(|s| s.as_bytes().to_vec())
            .map_err(|e| KvError::Gossip(format!("author sign failed: {e:?}")))
    }
}

/// Seal a signed mutation into an [`EncryptedKvStoreRecordV1`] (publish
/// path).
///
/// Signs `payload` (canonical bincode of the caller's message) with
/// `signing`, then seals the whole mutation under `ctx`'s current epoch.
///
/// # Errors
///
/// [`KvError::SecureRecord`] if the context cannot seal (no group key),
/// [`KvError::Gossip`] on serialization/signature failure.
pub fn seal_mutation(
    ctx: &dyn KvSecureContext,
    signing: &AuthorSigning,
    kind: KvMutationKind,
    store_id: &KvStoreId,
    payload: &[u8],
) -> Result<EncryptedKvStoreRecordV1> {
    let group_id = ctx.group_id();
    let epoch = ctx.current_epoch();
    let mut mutation = SignedKvMutation {
        group_id: group_id.clone(),
        store_id: *store_id.as_bytes(),
        epoch,
        author_id: signing.agent_id,
        author_pubkey: signing.public_key_bytes(),
        algorithm: SIG_ALGORITHM_ML_DSA65,
        kind,
        payload: payload.to_vec(),
        signature: Vec::new(),
    };
    mutation.signature = signing.sign(&mutation.signing_bytes())?;
    let plaintext = bincode::serialize(&mutation)
        .map_err(|e| KvError::Gossip(format!("sealed mutation serialize failed: {e}")))?;
    let (sealed_epoch, nonce, ciphertext) = ctx.seal(store_id, &plaintext)?;
    // The envelope epoch and the signed epoch must agree; a context
    // re-keying between the two calls would otherwise produce an
    // unverifiable record.
    if sealed_epoch != epoch {
        return Err(KvError::SecureRecord(format!(
            "secure context epoch moved during seal ({epoch} -> {sealed_epoch}); retry"
        )));
    }
    Ok(EncryptedKvStoreRecordV1 {
        group_id,
        store_id: *store_id.as_bytes(),
        epoch,
        nonce,
        ciphertext,
    })
}

/// Open an [`EncryptedKvStoreRecordV1`] and fully verify its inner mutation
/// (receive path, steps 2–5 of the design doc's receive flow).
///
/// Checks, in order:
/// 1. envelope group binding (must equal the context's group),
/// 2. envelope store binding,
/// 3. epoch gate — a record AHEAD of the local epoch is rejected (the
///    receiver is behind on group-secret sync and MUST NOT fall back to any
///    older key); a record BEHIND is rejected as stale pre-rekey material,
/// 4. AEAD open under the current epoch key + AAD,
/// 5. inner mutation field bindings (group/store/epoch, algorithm),
/// 6. author binding — `author_id` must be the deterministic derivation of
///    the included public key (checked BEFORE signature verification so a
///    mis-attributed record never even reaches crypto),
/// 7. ML-DSA-65 signature over the signed bytes.
///
/// Membership (step 6 of the receive flow) is intentionally NOT checked
/// here — the caller enforces it at the merge decision point so the verified
/// author is preserved for policy layers.
///
/// # Errors
///
/// [`KvError::SecureRecord`] with the specific rejection reason.
pub fn open_mutation(
    ctx: &dyn KvSecureContext,
    expected_store_id: &KvStoreId,
    record: &EncryptedKvStoreRecordV1,
) -> Result<SignedKvMutation> {
    let group_id = ctx.group_id();
    if record.group_id != group_id {
        return Err(KvError::SecureRecord(format!(
            "record group {} does not match local group {}",
            hex::encode(&record.group_id),
            hex::encode(&group_id)
        )));
    }
    if record.store_id != *expected_store_id.as_bytes() {
        return Err(KvError::SecureRecord(format!(
            "record store {} does not match local store {expected_store_id}",
            hex::encode(record.store_id)
        )));
    }
    let local_epoch = ctx.current_epoch();
    if record.epoch > local_epoch {
        return Err(KvError::SecureRecord(format!(
            "record epoch {epoch_ahead} is ahead of local group epoch {local_epoch} — \
             waiting for group secret sync",
            epoch_ahead = record.epoch,
        )));
    }
    if record.epoch < local_epoch {
        return Err(KvError::SecureRecord(format!(
            "stale record epoch {} behind local group epoch {local_epoch} (pre-rekey material)",
            record.epoch
        )));
    }
    let plaintext = ctx.open(
        expected_store_id,
        record.epoch,
        &record.nonce,
        &record.ciphertext,
    )?;
    let mutation: SignedKvMutation = bincode::deserialize(&plaintext).map_err(|e| {
        KvError::SecureRecord(format!("decrypted payload is not a signed mutation: {e}"))
    })?;
    if mutation.group_id != group_id
        || mutation.store_id != *expected_store_id.as_bytes()
        || mutation.epoch != record.epoch
    {
        return Err(KvError::SecureRecord(
            "decrypted mutation bindings (group/store/epoch) do not match the envelope".to_string(),
        ));
    }
    verify_mutation_author(&mutation)?;
    Ok(mutation)
}

/// Verify the author binding and signature of a mutation (no group context
/// required — pure crypto + binding checks).
///
/// # Errors
///
/// [`KvError::SecureRecord`] on unknown algorithm, unparseable public key,
/// author-id derivation mismatch, or signature failure.
pub fn verify_mutation_author(mutation: &SignedKvMutation) -> Result<()> {
    if mutation.algorithm != SIG_ALGORITHM_ML_DSA65 {
        return Err(KvError::SecureRecord(format!(
            "unknown signature algorithm {}",
            mutation.algorithm
        )));
    }
    let pubkey = ant_quic::MlDsaPublicKey::from_bytes(&mutation.author_pubkey)
        .map_err(|e| KvError::SecureRecord(format!("author public key parse failed: {e:?}")))?;
    // Author binding BEFORE signature verification (design doc receive flow
    // step 4): the claimed author must be the deterministic derivation of
    // the INCLUDED key, so a member cannot sign with its own key while
    // claiming another member's identity.
    let derived = AgentId::from_public_key(&pubkey);
    if derived != mutation.author_id {
        return Err(KvError::SecureRecord(
            "claimed author_id does not match the included public key".to_string(),
        ));
    }
    let sig = MlDsaSignature::from_bytes(&mutation.signature)
        .map_err(|e| KvError::SecureRecord(format!("signature parse failed: {e:?}")))?;
    verify_with_ml_dsa(&pubkey, &mutation.signing_bytes(), &sig).map_err(|e| {
        KvError::SecureRecord(format!("author signature verification failed: {e:?}"))
    })?;
    Ok(())
}

/// Deterministic store identity for a group-scoped encrypted store.
///
/// Every member computes the SAME `(store_id, topic)` from the stable group
/// id and the store name — no creator-local input, so members never disagree
/// (design doc "Store scope and identity"). The derivation is
/// domain-separated from every other `KvStoreId` derivation.
///
/// The topic embeds the store id so distinct stores of one group (same
/// group, different names) never share a gossip topic.
#[must_use]
pub fn group_store_identity(stable_group_id: &str, name: &str) -> (KvStoreId, String) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x0x.store.group.v1");
    hasher.update(stable_group_id.as_bytes());
    lp_hash_update(&mut hasher, name.as_bytes());
    let id = KvStoreId::new(*hasher.finalize().as_bytes());
    let topic = format!(
        "x0x/group/{stable_group_id}/kv/{}",
        hex::encode(id.as_bytes())
    );
    (id, topic)
}

/// Length-prefixed update for the identity hash (mirrors [`lp`]).
fn lp_hash_update(hasher: &mut blake3::Hasher, data: &[u8]) {
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
}

/// Convenience alias for a shared secure context handle.
pub type SharedKvSecureContext = Arc<dyn KvSecureContext>;

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Fixed-secret context for unit tests — same derivation path as the
    /// GSS backend, no groups dependency.
    struct MockContext {
        group_id: Vec<u8>,
        members: Mutex<HashSet<AgentId>>,
    }

    impl MockContext {
        fn new(group: u8) -> Self {
            let mut members = HashSet::new();
            members.insert(AgentId([group; 32]));
            Self {
                group_id: vec![group; 16],
                members: Mutex::new(members),
            }
        }

        fn secret(&self) -> [u8; 32] {
            let mut s = [0u8; 32];
            s[..16].copy_from_slice(&self.group_id);
            s
        }
    }

    impl KvSecureContext for MockContext {
        fn group_id(&self) -> Vec<u8> {
            self.group_id.clone()
        }

        fn current_epoch(&self) -> u64 {
            7
        }

        fn seal(&self, store_id: &KvStoreId, plaintext: &[u8]) -> Result<(u64, [u8; 24], Vec<u8>)> {
            let epoch = self.current_epoch();
            let mut nonce = [0u8; 24];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut nonce);
            let key = store_record_key(&self.secret(), epoch, &self.group_id, store_id.as_bytes());
            let cipher = XChaCha20Poly1305::new((&key).into());
            let aad = encrypted_record_aad(&self.group_id, store_id.as_bytes(), epoch);
            let ct = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| KvError::SecureRecord("seal failed".to_string()))?;
            Ok((epoch, nonce, ct))
        }

        fn open(
            &self,
            store_id: &KvStoreId,
            epoch: u64,
            nonce: &[u8; 24],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>> {
            if epoch != self.current_epoch() {
                return Err(KvError::SecureRecord(format!("no key for epoch {epoch}")));
            }
            let key = store_record_key(&self.secret(), epoch, &self.group_id, store_id.as_bytes());
            let cipher = XChaCha20Poly1305::new((&key).into());
            let aad = encrypted_record_aad(&self.group_id, store_id.as_bytes(), epoch);
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| KvError::SecureRecord("AEAD open failed".to_string()))
        }

        fn is_active_member(&self, agent: &AgentId) -> bool {
            self.members
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(agent)
        }
    }

    fn signing(n: u8) -> AuthorSigning {
        let keypair = crate::identity::AgentKeypair::generate().expect("keypair");
        let _ = n;
        AuthorSigning::from_keypair(&keypair).expect("author signing")
    }

    fn test_store_id() -> KvStoreId {
        KvStoreId::new([9; 32])
    }

    #[test]
    fn sealed_mutation_round_trips() {
        let ctx = MockContext::new(1);
        let author = signing(0);
        let payload = b"payload-bytes".to_vec();
        let record = seal_mutation(
            &ctx,
            &author,
            KvMutationKind::Delta,
            &test_store_id(),
            &payload,
        )
        .expect("seal");
        assert_eq!(record.epoch, 7);
        assert_eq!(record.group_id, ctx.group_id());
        // Ciphertext must not leak the payload.
        assert!(!record
            .ciphertext
            .windows(payload.len())
            .any(|w| w == payload.as_slice()));

        let mutation = open_mutation(&ctx, &test_store_id(), &record).expect("open");
        assert_eq!(mutation.kind, KvMutationKind::Delta);
        assert_eq!(mutation.payload, payload);
        assert_eq!(mutation.author_id, author.agent_id);
        assert_eq!(mutation.epoch, record.epoch);
    }

    #[test]
    fn wrong_group_store_or_epoch_is_rejected() {
        let ctx = MockContext::new(1);
        let author = signing(0);
        let record = seal_mutation(&ctx, &author, KvMutationKind::Delta, &test_store_id(), b"p")
            .expect("seal");

        // Foreign group context.
        let other_group = MockContext::new(2);
        let err = open_mutation(&other_group, &test_store_id(), &record).unwrap_err();
        assert!(err.to_string().contains("does not match local group"));

        // Cross-store replay.
        let other_store = KvStoreId::new([8; 32]);
        let err = open_mutation(&ctx, &other_store, &record).unwrap_err();
        assert!(err.to_string().contains("does not match local store"));
    }

    #[test]
    fn tampered_ciphertext_or_nonce_is_rejected() {
        let ctx = MockContext::new(1);
        let author = signing(0);
        let mut record =
            seal_mutation(&ctx, &author, KvMutationKind::Delta, &test_store_id(), b"p")
                .expect("seal");
        record.ciphertext[0] ^= 0x01;
        assert!(open_mutation(&ctx, &test_store_id(), &record).is_err());

        let mut record =
            seal_mutation(&ctx, &author, KvMutationKind::Delta, &test_store_id(), b"p")
                .expect("seal");
        record.nonce[0] ^= 0x01;
        assert!(open_mutation(&ctx, &test_store_id(), &record).is_err());
    }

    #[test]
    fn forged_author_is_rejected_before_signature_matters() {
        // Real author B signs, but the record claims author A: the derived
        // agent id of the INCLUDED key must match the claimed author, so the
        // record is rejected regardless of signature validity.
        let ctx = MockContext::new(1);
        let real_author = signing(0);
        let claimed = AgentId([0xEE; 32]);
        let payload = b"p".to_vec();
        let mut mutation = SignedKvMutation {
            group_id: ctx.group_id(),
            store_id: *test_store_id().as_bytes(),
            epoch: ctx.current_epoch(),
            author_id: claimed,
            author_pubkey: real_author.public_key_bytes(),
            algorithm: SIG_ALGORITHM_ML_DSA65,
            kind: KvMutationKind::Delta,
            payload,
            signature: Vec::new(),
        };
        mutation.signature = real_author.sign(&mutation.signing_bytes()).expect("sign");
        let plaintext = bincode::serialize(&mutation).expect("serialize");
        let (_e, nonce, ct) = ctx.seal(&test_store_id(), &plaintext).expect("seal");
        let record = EncryptedKvStoreRecordV1 {
            group_id: ctx.group_id(),
            store_id: *test_store_id().as_bytes(),
            epoch: 7,
            nonce,
            ciphertext: ct,
        };
        let err = open_mutation(&ctx, &test_store_id(), &record).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match the included public key"));
    }

    #[test]
    fn tampered_payload_or_signature_is_rejected() {
        let ctx = MockContext::new(1);
        let author = signing(0);
        let record = seal_mutation(
            &ctx,
            &author,
            KvMutationKind::Delta,
            &test_store_id(),
            b"original",
        )
        .expect("seal");
        // Unseal, tamper, reseal under the same key — signature must fail.
        let plaintext = ctx
            .open(
                &test_store_id(),
                record.epoch,
                &record.nonce,
                &record.ciphertext,
            )
            .expect("open");
        let mut mutation: SignedKvMutation = bincode::deserialize(&plaintext).expect("decode");
        mutation.payload = b"tampered".to_vec();
        let tampered = bincode::serialize(&mutation).expect("serialize");
        let (_e, nonce, ct) = ctx.seal(&test_store_id(), &tampered).expect("reseal");
        let record = EncryptedKvStoreRecordV1 {
            nonce,
            ciphertext: ct,
            ..record
        };
        let err = open_mutation(&ctx, &test_store_id(), &record).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn epoch_gate_rejects_ahead_and_behind() {
        let ctx = MockContext::new(1);
        let author = signing(0);
        let mut record =
            seal_mutation(&ctx, &author, KvMutationKind::Delta, &test_store_id(), b"p")
                .expect("seal");

        record.epoch = 8; // ahead of local epoch 7
        let err = open_mutation(&ctx, &test_store_id(), &record).unwrap_err();
        assert!(err.to_string().contains("ahead of local group epoch"));

        record.epoch = 6; // behind local epoch 7
        let err = open_mutation(&ctx, &test_store_id(), &record).unwrap_err();
        assert!(err.to_string().contains("stale record epoch"));
    }

    #[test]
    fn aad_binds_group_store_epoch() {
        // Distinct group/store/epoch inputs must yield distinct AADs, and the
        // derivation must be deterministic.
        let a = encrypted_record_aad(&[1u8; 4], &[2u8; 32], 3);
        let b = encrypted_record_aad(&[1u8; 4], &[2u8; 32], 3);
        assert_eq!(a, b);
        assert_ne!(a, encrypted_record_aad(&[1u8; 4], &[2u8; 32], 4));
        assert_ne!(a, encrypted_record_aad(&[1u8; 5], &[2u8; 32], 3));
        assert_ne!(a, encrypted_record_aad(&[1u8; 4], &[3u8; 32], 3));
    }

    #[test]
    fn store_record_key_is_store_scoped_and_epoch_bound() {
        let secret = [7u8; 32];
        let s1 = KvStoreId::new([1; 32]);
        let s2 = KvStoreId::new([2; 32]);
        assert_ne!(
            store_record_key(&secret, 1, &[3u8; 8], s1.as_bytes()),
            store_record_key(&secret, 2, &[3u8; 8], s1.as_bytes())
        );
        assert_ne!(
            store_record_key(&secret, 1, &[3u8; 8], s1.as_bytes()),
            store_record_key(&secret, 1, &[4u8; 8], s1.as_bytes())
        );
        assert_ne!(
            store_record_key(&secret, 1, &[3u8; 8], s1.as_bytes()),
            store_record_key(&secret, 1, &[3u8; 8], s2.as_bytes())
        );
    }

    #[test]
    fn group_store_identity_is_deterministic_and_name_bound() {
        let (id1, topic1) = group_store_identity("abc", "notes");
        let (id2, topic2) = group_store_identity("abc", "notes");
        assert_eq!(id1, id2);
        assert_eq!(topic1, topic2);
        let (id3, topic3) = group_store_identity("abc", "tasks");
        assert_ne!(id1, id3);
        assert_ne!(topic1, topic3);
        let (id4, topic4) = group_store_identity("abd", "notes");
        assert_ne!(id1, id4);
        assert_ne!(topic1, topic4);
        assert!(topic1.starts_with("x0x/group/abc/kv/"));
    }
}
