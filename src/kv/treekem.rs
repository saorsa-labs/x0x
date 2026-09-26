//! Async TreeKEM protection boundary for group-retained KvStore records.
//!
//! GSS records retain their existing `EncryptedKvStoreRecordV1` bytes. A
//! TreeKEM application ciphertext is self-describing, so this backend uses a
//! distinct versioned envelope and delegates mutable-ratchet persistence to
//! the daemon adapter that owns the live TreeKEM group.

use super::{AuthorSigning, KvError, KvMutationKind, KvStoreId, Result, SignedKvMutation};
use crate::identity::AgentId;
use crate::kv::encrypted::{sign_mutation_with_snapshot, verify_mutation_author};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Versioned outer record for a store protected by the named group's live
/// TreeKEM application ratchet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeKemKvStoreRecordV1 {
    /// Envelope version. Version one is the only admitted format.
    pub version: u8,
    /// Stable canonical group id bytes.
    pub group_id: Vec<u8>,
    /// Deterministic shared store id.
    pub store_id: [u8; 32],
    /// TreeKEM epoch at which the inner signed mutation was encrypted.
    pub epoch: u64,
    /// True only for a read-side state request. This flag is also covered by
    /// the encrypted inner signature.
    pub reader_only: bool,
    /// Encoded TreeKEM `ApplicationCiphertext` containing a signed mutation.
    pub ciphertext: Vec<u8>,
}

/// Async TreeKEM record protection boundary used by KvStore sync.
///
/// Implementations own the live mutable ratchet and its durable snapshot.
/// `seal_record` persists the advanced send ratchet before returning a record
/// for publication. `open_record` persists the advanced receive replay window
/// before returning plaintext for merge. Both methods bind the canonical
/// current group roster and role policy and fail closed after withdrawal,
/// quarantine, removal, or durability failure.
#[async_trait::async_trait]
pub trait TreeKemKvProtector: Send + Sync {
    /// Canonical stable group id bound to this protector.
    fn group_id(&self) -> Vec<u8>;

    /// Atomically authorize, sign, TreeKEM-encrypt, and durably advance the
    /// send ratchet for one typed store mutation.
    async fn seal_record(
        &self,
        signing: &AuthorSigning,
        kind: KvMutationKind,
        store_id: &KvStoreId,
        payload: &[u8],
        reader_only: bool,
    ) -> Result<TreeKemKvStoreRecordV1>;

    /// TreeKEM-decrypt, durably advance replay state, verify the inner author
    /// signature and current role policy, and return the admitted mutation.
    async fn open_record(
        &self,
        store_id: &KvStoreId,
        record: &TreeKemKvStoreRecordV1,
    ) -> Result<OpenedTreeKemKvRecord>;

    /// Current local reader admission for cached API access and state request.
    async fn is_authorized_reader(&self, agent: &AgentId) -> bool;

    /// Current local writer admission for content/history endorsement.
    async fn is_authorized_writer(&self, agent: &AgentId) -> bool;

    /// Recheck current authority and merge while the backend's membership
    /// transaction lock remains held through acquisition of the store lock.
    async fn merge_main_record(
        &self,
        opened: OpenedTreeKemKvRecord,
        sender_peer: PeerId,
        local_peer: PeerId,
        store: &Arc<tokio::sync::RwLock<super::KvStore>>,
        retained_image: Option<Vec<u8>>,
    ) -> Result<()>;

    /// Report whether a verified main record actually changed the KV store.
    /// Existing protectors retain their accepted-record behavior by default;
    /// `None` means their applied outcome is unknown and is not counted.
    async fn merge_main_record_with_outcome(
        &self,
        opened: OpenedTreeKemKvRecord,
        sender_peer: PeerId,
        local_peer: PeerId,
        store: &Arc<tokio::sync::RwLock<super::KvStore>>,
        retained_image: Option<Vec<u8>>,
    ) -> Result<Option<bool>> {
        self.merge_main_record(opened, sender_peer, local_peer, store, retained_image)
            .await
            .map(|()| None)
    }

    /// Permanently fence this live protector after local group retirement.
    fn invalidate(&self);
}

/// Shared TreeKEM protector handle captured by sync tasks.
pub type SharedTreeKemKvProtector = Arc<dyn TreeKemKvProtector>;

/// Authenticated TreeKEM mutation plus its control admission class.
pub struct OpenedTreeKemKvRecord {
    pub mutation: SignedKvMutation,
    pub reader_only: bool,
    pub authorization_binding: [u8; 32],
    pub epoch: u64,
}

/// Immutable context covered by an encrypted inner mutation signature.
pub struct TreeKemInnerBinding<'a> {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub store_id: &'a KvStoreId,
    pub authorization_binding: [u8; 32],
    pub reader_only: bool,
}

/// Build the signed inner mutation that is encrypted by TreeKEM.
///
/// Keeping this in the library gives the daemon adapter the same canonical
/// signed bytes and author binding as the existing GSS envelope.
pub fn sign_inner_mutation(
    signing: &AuthorSigning,
    kind: KvMutationKind,
    payload: &[u8],
    binding: TreeKemInnerBinding<'_>,
) -> Result<Vec<u8>> {
    let mut bound_payload = Vec::with_capacity(33 + payload.len());
    bound_payload.extend_from_slice(&binding.authorization_binding);
    bound_payload.push(u8::from(binding.reader_only));
    bound_payload.extend_from_slice(payload);
    let mutation = sign_mutation_with_snapshot(
        binding.group_id,
        binding.epoch,
        signing,
        kind,
        binding.store_id,
        &bound_payload,
    )?;
    bincode::serialize(&mutation)
        .map_err(|e| KvError::Gossip(format!("TreeKEM mutation serialize failed: {e}")))
}

/// Decode and authenticate a TreeKEM-decrypted inner mutation.
pub fn open_inner_mutation(
    group_id: &[u8],
    epoch: u64,
    store_id: &KvStoreId,
    plaintext: &[u8],
    authorization_binding: [u8; 32],
) -> Result<OpenedTreeKemKvRecord> {
    let mutation: SignedKvMutation = bincode::deserialize(plaintext)
        .map_err(|e| KvError::SecureRecord(format!("invalid TreeKEM mutation: {e}")))?;
    if mutation.group_id != group_id
        || mutation.epoch != epoch
        || mutation.store_id != *store_id.as_bytes()
    {
        return Err(KvError::SecureRecord(
            "TreeKEM mutation binding does not match group/store/epoch".to_string(),
        ));
    }
    verify_mutation_author(&mutation)?;
    if mutation.payload.len() < 33 || mutation.payload[..32] != authorization_binding {
        return Err(KvError::SecureRecord(
            "TreeKEM mutation roster/policy binding is stale or foreign".to_string(),
        ));
    }
    let reader_only = match mutation.payload[32] {
        0 => false,
        1 => true,
        _ => {
            return Err(KvError::SecureRecord(
                "TreeKEM mutation admission class is invalid".to_string(),
            ));
        }
    };
    let mut mutation = mutation;
    mutation.payload.drain(..33);
    Ok(OpenedTreeKemKvRecord {
        mutation,
        reader_only,
        authorization_binding,
        epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_mutation_binds_authority_and_reader_admission() {
        let keypair = crate::identity::AgentKeypair::generate().expect("keypair");
        let signing = AuthorSigning::from_keypair(&keypair).expect("signing");
        let store_id = KvStoreId::new([5; 32]);
        let plaintext = sign_inner_mutation(
            &signing,
            KvMutationKind::Control,
            b"request",
            TreeKemInnerBinding {
                group_id: b"stable-group".to_vec(),
                epoch: 7,
                store_id: &store_id,
                authorization_binding: [8; 32],
                reader_only: true,
            },
        )
        .expect("signed inner");
        let opened =
            open_inner_mutation(b"stable-group", 7, &store_id, &plaintext, [8; 32]).expect("open");
        assert!(opened.reader_only);
        assert_eq!(opened.mutation.payload, b"request");
        assert!(open_inner_mutation(b"stable-group", 7, &store_id, &plaintext, [9; 32]).is_err());
    }
}
