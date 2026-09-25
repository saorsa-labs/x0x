//! Group-key sealing for task lists bound to an encrypted named group (#895).
//!
//! A task list whose id is group-scoped (`x0x.group.<gid>.symphony.<lid>`)
//! used to publish its deltas — incremental and the `/state-sync` full-state
//! serve — as plaintext `(PeerId, TaskListDelta)` on a topic any peer who
//! knows the group id can derive. Group KV stores were already sealed, so a
//! group's Wiki was confidential while its Board was not.
//!
//! This module reuses the group KV store envelopes rather than adding crypto:
//!
//! - GSS plane: [`EncryptedKvStoreRecordV1`] sealed by
//!   [`GssKvSecureContext`] (XChaCha20-Poly1305 under a key derived from the
//!   group's current shared secret and epoch, AAD binding group, record id and
//!   epoch; inner ML-DSA-65 author signature).
//! - TreeKEM plane: [`TreeKemKvStoreRecordV1`] produced by the daemon's live
//!   TreeKEM protector (the same one group KV stores use).
//!
//! The record id a list seals under is derived from the stable group id and
//! the list topic under a task-specific domain
//! ([`group_task_list_record_id`]), so a task record can never be opened as a
//! KV store record or vice versa.
//!
//! The CRDT layer does not know about groups: the daemon installs a
//! [`TaskDeltaProtector`] that resolves the group LIVE on every call, which is
//! how a rekey (GSS rotation, TreeKEM commit) takes effect on the very next
//! delta. With a protector installed the sync loop publishes only sealed
//! records and refuses plaintext unless the protector says the group is
//! signed-public (see [`TaskDeltaProtector::admits_plaintext`]).

use crate::groups::{GroupInfo, GssKvSecureContext};
use crate::identity::AgentId;
use crate::kv::encrypted::{
    open_mutation, AuthorSigning, EncryptedKvStoreRecordV1, KvMutationKind,
};
use crate::kv::{KvSecureContext, KvStoreId, TreeKemKvStoreRecordV1};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};

/// Domain tag carried in every sealed task record. A payload whose domain is
/// not exactly this is not a sealed task record (it is plaintext, or garbage).
pub const SEALED_TASK_RECORD_DOMAIN: &[u8] = b"x0x.tasks.sealed-record.v1";

/// Domain for [`group_task_list_record_id`]. Distinct from the group KV store
/// identity domain (`x0x.store.group.v1`), so the derived AEAD key of a task
/// list never equals a store's.
const TASK_RECORD_ID_DOMAIN: &[u8] = b"x0x.tasks.group-list-record.v1";

/// The sealed body, one variant per group secure plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SealedTaskRecordBody {
    /// Sealed under the group's current GSS shared-secret epoch.
    Gss(EncryptedKvStoreRecordV1),
    /// Sealed by the group's live TreeKEM application ratchet.
    TreeKem(TreeKemKvStoreRecordV1),
}

/// Wire record published on a sealed task list's main topic, inside the usual
/// `(PeerId, _)` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedTaskRecord {
    domain: Vec<u8>,
    body: SealedTaskRecordBody,
}

/// A sealed record after decryption and author verification.
#[derive(Debug, Clone)]
pub struct OpenedTaskPayload {
    /// The ML-DSA-65-verified author of the sealed payload.
    pub author: AgentId,
    /// The plaintext `(PeerId, TaskListDelta)` bytes that were sealed.
    pub payload: Vec<u8>,
}

/// Why an inbound task payload was refused on a sealed list. Every refusal is
/// fail-closed: the payload is dropped and never merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskSealRejection {
    /// A plaintext delta arrived for a list whose group is encrypted (or
    /// unresolvable). An un-upgraded peer produces exactly this.
    PlaintextRefused,
    /// The record could not be opened: wrong or missing epoch key (a removed
    /// member, or a receiver behind on the rekey), tampering, a foreign
    /// group/list binding, or an author who is not a current writer.
    OpenFailed,
    /// The record opened, but its verified author is not the gossip-verified
    /// sender of the message that carried it.
    SenderMismatch,
}

/// A boxed future, as used by the object-safe [`TaskDeltaProtector`].
pub type TaskSealFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = crate::crdt::Result<T>> + Send + 'a>>;

/// Seals and opens a group-bound task list's wire payloads (#895).
///
/// Installed by the daemon through [`crate::TaskListBinding`] BEFORE the sync
/// loops start, so no delta is ever published or merged without it.
pub trait TaskDeltaProtector: Send + Sync + 'static {
    /// Seal `payload` (the encoded `(PeerId, TaskListDelta)`) under the
    /// group's current key. `Ok(None)` means the group is signed-public and
    /// the payload is published as plaintext, as before. Any error means the
    /// payload is NOT published.
    fn seal<'a>(
        &'a self,
        kind: KvMutationKind,
        payload: &'a [u8],
    ) -> TaskSealFuture<'a, Option<SealedTaskRecordBody>>;

    /// Open a sealed record under the group's current key and verify that
    /// its author is a current writer.
    fn open<'a>(&'a self, body: &'a SealedTaskRecordBody) -> TaskSealFuture<'a, OpenedTaskPayload>;

    /// Whether a plaintext delta may be merged right now: only when the group
    /// resolves and is signed-public. An unknown group answers `false`.
    fn admits_plaintext(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;

    /// Record a refusal (diagnostics counter).
    fn on_rejected(&self, reason: TaskSealRejection);
}

/// Deterministic id a group task list seals under, shared by every member.
#[must_use]
pub fn group_task_list_record_id(stable_group_id: &str, topic: &str) -> KvStoreId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TASK_RECORD_ID_DOMAIN);
    hasher.update(&(stable_group_id.len() as u64).to_le_bytes());
    hasher.update(stable_group_id.as_bytes());
    hasher.update(&(topic.len() as u64).to_le_bytes());
    hasher.update(topic.as_bytes());
    KvStoreId::new(*hasher.finalize().as_bytes())
}

/// Encode a sealed body for publication on the task-list topic.
///
/// # Errors
///
/// Serialization failure.
pub fn encode_sealed_task_record(
    sender: PeerId,
    body: SealedTaskRecordBody,
) -> crate::crdt::Result<Vec<u8>> {
    let record = SealedTaskRecord {
        domain: SEALED_TASK_RECORD_DOMAIN.to_vec(),
        body,
    };
    crate::gossip::wire::encode_delta(sender, &record)
        .map_err(|e| crate::crdt::CrdtError::Gossip(format!("sealed task record encode: {e}")))
}

/// Decode a sealed task record, or `None` when `payload` is not one (a
/// plaintext delta, or garbage).
#[must_use]
pub fn decode_sealed_task_record(payload: &[u8]) -> Option<(PeerId, SealedTaskRecordBody)> {
    let (peer, record) = crate::gossip::wire::decode_delta::<SealedTaskRecord>(payload).ok()?;
    (record.domain == SEALED_TASK_RECORD_DOMAIN).then_some((peer, record.body))
}

fn sealed_err(message: impl std::fmt::Display) -> crate::crdt::CrdtError {
    crate::crdt::CrdtError::Gossip(format!("sealed task record: {message}"))
}

/// Seal a task payload under a GSS group's CURRENT secret epoch, the same way
/// the group's encrypted KV stores seal (author admitted and sealed from one
/// snapshot, under the group's write policy).
///
/// # Errors
///
/// The group holds no shared secret, the author is not a current writer, or
/// the seal fails.
pub fn seal_gss_task_payload(
    info: &GroupInfo,
    signing: &AuthorSigning,
    kind: KvMutationKind,
    topic: &str,
    payload: &[u8],
) -> crate::crdt::Result<SealedTaskRecordBody> {
    let ctx = GssKvSecureContext::from_group(info)
        .ok_or_else(|| sealed_err("group holds no shared secret"))?;
    let record_id = group_task_list_record_id(info.stable_group_id(), topic);
    ctx.seal_authorized(signing, kind, &record_id, payload)
        .map(SealedTaskRecordBody::Gss)
        .map_err(sealed_err)
}

/// Open a GSS-sealed task record with the group's CURRENT epoch key.
///
/// Fails closed on any other epoch (a removed member still holding the old
/// secret cannot open a post-rotation record, and a stale pre-rotation record
/// is not applied), a foreign group or list, a bad author signature, or an
/// author who is not a current writer.
///
/// # Errors
///
/// As above.
pub fn open_gss_task_record(
    info: &GroupInfo,
    topic: &str,
    record: &EncryptedKvStoreRecordV1,
) -> crate::crdt::Result<OpenedTaskPayload> {
    let ctx = GssKvSecureContext::from_group(info)
        .ok_or_else(|| sealed_err("group holds no shared secret"))?;
    let record_id = group_task_list_record_id(info.stable_group_id(), topic);
    let mutation = open_mutation(&ctx, &record_id, record).map_err(sealed_err)?;
    accept_opened(
        mutation.kind,
        ctx.is_authorized_writer(&mutation.author_id),
        mutation.author_id,
        mutation.payload,
    )
}

/// Final checks shared by both planes: only content kinds, only current
/// writers.
///
/// # Errors
///
/// A control/retained kind, or an unauthorized author.
pub fn accept_opened(
    kind: KvMutationKind,
    author_is_writer: bool,
    author: AgentId,
    payload: Vec<u8>,
) -> crate::crdt::Result<OpenedTaskPayload> {
    if !matches!(kind, KvMutationKind::Delta | KvMutationKind::FullState) {
        return Err(sealed_err("record kind is not a task delta"));
    }
    if !author_is_writer {
        return Err(sealed_err("author is not a current group writer"));
    }
    Ok(OpenedTaskPayload { author, payload })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{TaskItem, TaskListDelta, TaskMetadata};

    const TOPIC: &str = "x0x.group.g895.symphony.board";
    const SECRET_TITLE: &str = "SECRET-TITLE-895";
    const SECRET_BODY: &str = "SECRET-DESCRIPTION-895";

    fn keypair() -> crate::identity::AgentKeypair {
        crate::identity::AgentKeypair::generate().expect("keypair")
    }

    fn group_with(creator: AgentId) -> GroupInfo {
        let mut info = GroupInfo::new("g895".to_string(), String::new(), creator, "g895".into());
        info.migrate_from_v1();
        let _ = info.rotate_shared_secret();
        info
    }

    fn secret_payload() -> Vec<u8> {
        let peer = PeerId::new([7; 32]);
        let meta = TaskMetadata::new(
            SECRET_TITLE.to_string(),
            SECRET_BODY.to_string(),
            0,
            AgentId([7; 32]),
            1,
        );
        let task = TaskItem::new(crate::crdt::TaskId::from_bytes([9; 32]), meta, peer);
        let mut delta = TaskListDelta::new(1);
        delta.added_tasks.insert(*task.id(), (task, (peer, 1)));
        crate::gossip::wire::encode_delta(peer, &delta).expect("encode")
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    /// WHY: the whole point of #895 — the bytes a group list puts on the wire
    /// must not carry task content.
    #[test]
    fn sealed_wire_bytes_do_not_carry_title_or_description() {
        let kp = keypair();
        let signing = AuthorSigning::from_keypair(&kp).expect("signing");
        let info = group_with(kp.agent_id());
        let payload = secret_payload();
        assert!(
            contains(&payload, SECRET_TITLE),
            "fixture must be plaintext-bearing"
        );
        let body = seal_gss_task_payload(&info, &signing, KvMutationKind::Delta, TOPIC, &payload)
            .expect("seal");
        let wire = encode_sealed_task_record(PeerId::new([1; 32]), body).expect("encode");
        assert!(!contains(&wire, SECRET_TITLE));
        assert!(!contains(&wire, SECRET_BODY));
        let (_, decoded) = decode_sealed_task_record(&wire).expect("is sealed");
        let opened = open_gss_task_record(
            &info,
            TOPIC,
            match &decoded {
                SealedTaskRecordBody::Gss(r) => r,
                SealedTaskRecordBody::TreeKem(_) => panic!("GSS record expected"),
            },
        )
        .expect("member opens");
        assert_eq!(opened.payload, payload);
        assert_eq!(opened.author, kp.agent_id());
    }

    /// WHY: plaintext must never be mistaken for a sealed record, or the
    /// plaintext-refusal rule would have nothing to key on.
    #[test]
    fn plaintext_delta_is_not_a_sealed_record() {
        assert!(decode_sealed_task_record(&secret_payload()).is_none());
    }

    /// WHY (lead requirement 1): after a rotation a removed member still
    /// holds the epoch-N secret; a record sealed at N+1 must not open with it.
    #[test]
    fn removed_member_with_old_epoch_key_cannot_open_new_epoch_record() {
        let owner = keypair();
        let signing = AuthorSigning::from_keypair(&owner).expect("signing");
        let at_n = group_with(owner.agent_id());
        let mut at_n1 = at_n.clone();
        let _ = at_n1.rotate_shared_secret();
        assert!(at_n1.secret_epoch > at_n.secret_epoch);
        let body = seal_gss_task_payload(
            &at_n1,
            &signing,
            KvMutationKind::Delta,
            TOPIC,
            &secret_payload(),
        )
        .expect("seal at N+1");
        let SealedTaskRecordBody::Gss(record) = body else {
            panic!("GSS record expected");
        };
        assert!(open_gss_task_record(&at_n, TOPIC, &record).is_err());
        assert!(open_gss_task_record(&at_n1, TOPIC, &record).is_ok());
    }

    /// WHY: a peer with no group secret at all (a non-member who derived the
    /// topic) cannot open, and a record for one list cannot be replayed into
    /// another list of the same group.
    #[test]
    fn non_member_and_foreign_list_fail_closed() {
        let owner = keypair();
        let signing = AuthorSigning::from_keypair(&owner).expect("signing");
        let info = group_with(owner.agent_id());
        let SealedTaskRecordBody::Gss(record) = seal_gss_task_payload(
            &info,
            &signing,
            KvMutationKind::Delta,
            TOPIC,
            &secret_payload(),
        )
        .expect("seal") else {
            panic!("GSS record expected");
        };
        let mut outsider = info.clone();
        outsider.shared_secret = None;
        assert!(open_gss_task_record(&outsider, TOPIC, &record).is_err());
        let other = group_with(keypair().agent_id());
        assert!(open_gss_task_record(&other, TOPIC, &record).is_err());
        assert!(open_gss_task_record(&info, "x0x.group.g895.symphony.other", &record).is_err());
    }

    /// WHY: sealing must refuse an author the group does not seat, so a
    /// departed member's daemon cannot keep publishing under a cached key.
    #[test]
    fn non_member_cannot_seal() {
        let owner = keypair();
        let outsider = keypair();
        let info = group_with(owner.agent_id());
        let signing = AuthorSigning::from_keypair(&outsider).expect("signing");
        assert!(
            seal_gss_task_payload(&info, &signing, KvMutationKind::Delta, TOPIC, b"x").is_err()
        );
    }

    /// WHY: a task record id must not collide with the group KV store id of
    /// the same name, or the two planes would share an AEAD key.
    #[test]
    fn record_id_is_domain_separated_from_kv_store_ids() {
        let (store_id, _) = crate::kv::encrypted::group_store_identity("g895", TOPIC);
        assert_ne!(group_task_list_record_id("g895", TOPIC), store_id);
        assert_ne!(
            group_task_list_record_id("g895", TOPIC),
            group_task_list_record_id("g896", TOPIC)
        );
    }
}
