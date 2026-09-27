//! `NoteUpdateRecordV1`: one write-once, author-signed record per save
//! (ADR 0081 §5).
//!
//! The record is the VALUE of key `n/<note_id>/u/<author_agent_hex>/<seq>`
//! in the group's sealed `notes` store. It lives only inside
//! `KvEntry.value`, which the #914 envelope seals; no outer field is added.
//! Receivers accept a record only when its author signature verifies under
//! a key that derives to the key segment's author, whoever published it.

use super::error::NoteError;
use crate::identity::AgentId;
use crate::kv::encrypted::AuthorSigning;
use ant_quic::crypto::raw_public_keys::pqc::{verify_with_ml_dsa, MlDsaSignature};
use bincode::Options as _;
use serde::{Deserialize, Serialize};

/// Domain prefix of every record signature.
pub const RECORD_SIGNATURE_DOMAIN: &[u8] = b"x0x.notes.update-record.v1";

/// Largest encoded record accepted from a peer: the KV inline value cap.
pub const MAX_RECORD_BYTES: u64 = crate::kv::entry::MAX_INLINE_SIZE as u64;

/// Content type of an update record entry.
pub const RECORD_CONTENT_TYPE: &str = "application/x-x0x-note-update-v1";

/// Worst-case bytes a record adds around its `update`: the fixed fields,
/// length prefixes, an ML-DSA-65 public key (seq 0) and signature, plus
/// margin. `MAX_INLINE_SIZE - RECORD_OVERHEAD_BYTES` is the largest update
/// one record carries.
pub const RECORD_OVERHEAD_BYTES: usize = 32 + 8 + 8 + 8 + 1 + 8 + 1952 + 8 + 3309 + 256;

/// Largest loro update one record may carry.
pub const MAX_UPDATE_BYTES: usize = crate::kv::entry::MAX_INLINE_SIZE - RECORD_OVERHEAD_BYTES;

/// A signed note update record (ADR 0081 §5, field order is normative).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteUpdateRecordV1 {
    /// Author agent id; must equal the key's author segment.
    pub author: [u8; 32],
    /// Sequence number; must equal the key's seq segment.
    pub seq: u64,
    /// The session peer id that produced `update`.
    pub loro_peer: u64,
    /// loro `export(ExportMode::updates(vv_before_save))` (or one counter
    /// range of it when a save is split across seqs).
    pub update: Vec<u8>,
    /// ML-DSA-65 public key; present only when `seq == 0`.
    pub author_pubkey: Option<Vec<u8>>,
    /// ML-DSA-65 signature over [`signing_bytes`].
    pub author_sig: Vec<u8>,
}

/// The signed fields, in the record's order, for the `blake3(bincode(..))`
/// digest.
#[derive(Serialize)]
struct SignedFields<'a> {
    author: &'a [u8; 32],
    seq: u64,
    loro_peer: u64,
    update: &'a [u8],
    author_pubkey: &'a Option<Vec<u8>>,
}

fn codec() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_RECORD_BYTES)
        .reject_trailing_bytes()
}

/// `"x0x.notes.update-record.v1" || store_id || key || blake3(bincode(fields))`.
///
/// # Errors
///
/// [`NoteError::Signing`] if the fields cannot be encoded.
pub fn signing_bytes(
    store_id: &[u8; 32],
    key: &str,
    author: &[u8; 32],
    seq: u64,
    loro_peer: u64,
    update: &[u8],
    author_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>, NoteError> {
    let fields = SignedFields {
        author,
        seq,
        loro_peer,
        update,
        author_pubkey,
    };
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .serialize(&fields)
        .map_err(|e| NoteError::Signing(e.to_string()))?;
    let digest = blake3::hash(&encoded);
    let mut out = Vec::with_capacity(
        RECORD_SIGNATURE_DOMAIN.len() + 32 + key.len() + digest.as_bytes().len(),
    );
    out.extend_from_slice(RECORD_SIGNATURE_DOMAIN);
    out.extend_from_slice(store_id);
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(digest.as_bytes());
    Ok(out)
}

/// Parsed `n/<note_id>/u/<author_hex>/<seq>` record key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordKey<'a> {
    /// The note id segment.
    pub note_id: &'a str,
    /// The author segment, decoded.
    pub author: [u8; 32],
    /// The sequence segment.
    pub seq: u64,
}

/// Length of a note id: 16 random bytes, lower-case hex.
pub const NOTE_ID_HEX_LEN: usize = 32;

/// Whether `id` is a well-formed note id.
#[must_use]
pub fn is_note_id(id: &str) -> bool {
    id.len() == NOTE_ID_HEX_LEN && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The key of a note's metadata value.
#[must_use]
pub fn meta_key(note_id: &str) -> String {
    format!("n/{note_id}/meta")
}

/// The prefix shared by a note's update records.
#[must_use]
pub fn record_prefix(note_id: &str) -> String {
    format!("n/{note_id}/u/")
}

/// The key of one update record.
#[must_use]
pub fn record_key(note_id: &str, author: &[u8; 32], seq: u64) -> String {
    format!("n/{note_id}/u/{}/{seq}", hex::encode(author))
}

/// Parse a record key strictly: canonical lower-case hex author and a
/// decimal seq without leading zeros. Anything else is not a record key
/// (import keys, `n/<note>/u/import/…`, belong to a later slice).
#[must_use]
pub fn parse_record_key(key: &str) -> Option<RecordKey<'_>> {
    let rest = key.strip_prefix("n/")?;
    let (note_id, rest) = rest.split_once('/')?;
    if !is_note_id(note_id) {
        return None;
    }
    let rest = rest.strip_prefix("u/")?;
    let (author_hex, seq_str) = rest.split_once('/')?;
    if author_hex.len() != 64
        || !author_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut author = [0u8; 32];
    hex::decode_to_slice(author_hex, &mut author).ok()?;
    let seq: u64 = seq_str.parse().ok()?;
    if seq.to_string() != seq_str {
        return None;
    }
    Some(RecordKey {
        note_id,
        author,
        seq,
    })
}

/// Build and sign one record.
///
/// # Errors
///
/// [`NoteError::Signing`] on encode or signature failure.
pub fn sign_record(
    signing: &AuthorSigning,
    store_id: &[u8; 32],
    note_id: &str,
    seq: u64,
    loro_peer: u64,
    update: Vec<u8>,
) -> Result<(String, NoteUpdateRecordV1), NoteError> {
    let author = signing.agent_id.0;
    let key = record_key(note_id, &author, seq);
    let author_pubkey = (seq == 0).then(|| signing.public_key_bytes());
    let message = signing_bytes(
        store_id,
        &key,
        &author,
        seq,
        loro_peer,
        &update,
        &author_pubkey,
    )?;
    let author_sig = signing
        .sign(&message)
        .map_err(|e| NoteError::Signing(e.to_string()))?;
    Ok((
        key,
        NoteUpdateRecordV1 {
            author,
            seq,
            loro_peer,
            update,
            author_pubkey,
            author_sig,
        },
    ))
}

/// Encode a record as the KV entry value.
///
/// # Errors
///
/// [`NoteError::Signing`] if encoding fails or exceeds the inline cap.
pub fn encode_record(record: &NoteUpdateRecordV1) -> Result<Vec<u8>, NoteError> {
    codec()
        .serialize(record)
        .map_err(|e| NoteError::Signing(format!("record encode failed: {e}")))
}

/// Decode a record from peer bytes with the inline-cap size limit and no
/// trailing bytes. Run inside the isolation by callers.
///
/// # Errors
///
/// A description of the decode failure.
pub fn decode_record(bytes: &[u8]) -> Result<NoteUpdateRecordV1, String> {
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err("record larger than the inline cap".into());
    }
    codec()
        .deserialize(bytes)
        .map_err(|e| format!("record decode failed: {e}"))
}

/// Why a record was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordRejection {
    /// Bytes are not a record, or the record does not match its key. Never
    /// retried.
    Malformed(String),
    /// The signature does not verify, or the key does not derive to the
    /// author. Never retried.
    BadSignature(String),
    /// The author's key is not known yet (its seq-0 record is missing).
    /// Retried on a later sync.
    AuthorKeyUnknown,
    /// The author is not a current writer. Retried on a later sync (the
    /// roster may change).
    NotWriter,
}

impl RecordRejection {
    /// Whether the rejection is final for these exact bytes.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Malformed(_) | Self::BadSignature(_))
    }
}

/// Verify a decoded record against its key (ADR 0081 §5 receiver rule).
///
/// `known_key` is the author's public key from a verified seq-0 record of
/// the same note; a seq-0 record carries its own. The caller checks the
/// writer rule after this returns the verified author.
///
/// # Errors
///
/// A [`RecordRejection`].
pub fn verify_record(
    store_id: &[u8; 32],
    key: &str,
    record: &NoteUpdateRecordV1,
    known_key: Option<&[u8]>,
) -> Result<AgentId, RecordRejection> {
    let parsed = parse_record_key(key)
        .ok_or_else(|| RecordRejection::Malformed("not a record key".into()))?;
    if record.author != parsed.author {
        return Err(RecordRejection::Malformed(
            "record author does not match the key segment".into(),
        ));
    }
    if record.seq != parsed.seq {
        return Err(RecordRejection::Malformed(
            "record seq does not match the key segment".into(),
        ));
    }
    let pubkey_bytes: &[u8] = match (&record.author_pubkey, record.seq) {
        (Some(pk), 0) => pk,
        (None, 0) => {
            return Err(RecordRejection::Malformed(
                "seq 0 record carries no public key".into(),
            ))
        }
        (Some(_), _) => {
            return Err(RecordRejection::Malformed(
                "public key present on a seq > 0 record".into(),
            ))
        }
        (None, _) => known_key.ok_or(RecordRejection::AuthorKeyUnknown)?,
    };
    let pubkey = ant_quic::MlDsaPublicKey::from_bytes(pubkey_bytes)
        .map_err(|e| RecordRejection::BadSignature(format!("public key parse: {e:?}")))?;
    if AgentId::from_public_key(&pubkey).0 != parsed.author {
        return Err(RecordRejection::BadSignature(
            "public key does not derive to the key's author".into(),
        ));
    }
    let message = signing_bytes(
        store_id,
        key,
        &record.author,
        record.seq,
        record.loro_peer,
        &record.update,
        &record.author_pubkey,
    )
    .map_err(|e| RecordRejection::Malformed(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(&record.author_sig)
        .map_err(|e| RecordRejection::BadSignature(format!("signature parse: {e:?}")))?;
    verify_with_ml_dsa(&pubkey, &message, &sig)
        .map_err(|e| RecordRejection::BadSignature(format!("signature: {e:?}")))?;
    Ok(AgentId(parsed.author))
}

/// Whether `value` is a record under `key` whose author signature verifies
/// (ADR 0081 §5). For `seq > 0` the author's key comes from the seq-0
/// record found by `lookup` (any seq-0 value will do: `verify_record`
/// still requires the key to derive to the author). Runs the decode and
/// verification inside `catch_unwind`; any failure is `false`.
///
/// The KV layer uses this to keep record keys write-once: a value that
/// verifies is never replaced by one that does not.
pub fn record_value_verifies(
    store_id: &[u8; 32],
    key: &str,
    value: &[u8],
    lookup: impl Fn(&str) -> Option<Vec<u8>>,
) -> bool {
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let parsed = parse_record_key(key)?;
        let record = decode_record(value).ok()?;
        let known = if record.seq == 0 {
            None
        } else {
            let seq0 = record_key(parsed.note_id, &parsed.author, 0);
            lookup(&seq0)
                .and_then(|bytes| decode_record(&bytes).ok())
                .and_then(|r| r.author_pubkey)
        };
        verify_record(store_id, key, &record, known.as_deref()).ok()
    }));
    matches!(checked, Ok(Some(_)))
}
