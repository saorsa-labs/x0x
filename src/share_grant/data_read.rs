//! Issue #1094 slice D1 (A03 amendment of 15 Nov 2026): a grantee reads a
//! store it holds a [`ShareCap::Data`](super::ShareCap::Data) grant for.
//!
//! The grantee's daemon sends a [`DataReadRequest`] as a typed DM to one of
//! the granted agents. That daemon checks the sender's grants
//! (`Agent::share_grant_access`, which binds the transport-authenticated
//! machine, the grantee and revocation), reads its own copy of the store
//! and answers with one [`DataReadReply`]. Both are one attempt, with no
//! retry: the grantee's HTTP call waits for the reply or times out.
//!
//! Slice D2 (A03 amendment of 16 Nov 2026): a grantee whose grant is `rw`
//! writes the store the same way. It sends a [`DataWriteRequest`] (put or
//! delete); the granted agent applies it as its own write to the store, so
//! the store's plane, policy and write refusals all apply unchanged, and
//! answers with one [`DataReadReply`].
//!
//! Wire: a prefix, then JSON. A peer without
//! [`crate::dm::CapabilityRegistry::DATA_READ_V1`] is never sent a read; a
//! peer without [`crate::dm::CapabilityRegistry::DATA_WRITE_V1`] is never
//! sent a write.

use serde::{Deserialize, Serialize};

/// Typed-DM prefix of a read request (grantee → granted agent).
pub const DATA_READ_REQUEST_DM_PREFIX: &[u8] = b"x0x-data-read-v1\0";

/// Typed-DM prefix of a read reply (granted agent → grantee).
pub const DATA_READ_REPLY_DM_PREFIX: &[u8] = b"x0x-data-reply-v1\0";

/// Typed-DM prefix of a write request (grantee → granted agent). The reply
/// uses [`DATA_READ_REPLY_DM_PREFIX`].
pub const DATA_WRITE_REQUEST_DM_PREFIX: &[u8] = b"x0x-data-write-v1\0";

/// Largest request, prefix included: four fields (request id, group,
/// store, key) at [`MAX_DATA_READ_FIELD_BYTES`], each escaped in the worst
/// case, fit with room to spare.
pub const MAX_DATA_READ_REQUEST_BYTES: usize = 8192;

/// Largest reply, prefix included: inside the 48 KiB DM payload limit
/// ([`crate::dm::MAX_PAYLOAD_BYTES`]) with room for the DM framing.
pub const MAX_DATA_READ_REPLY_BYTES: usize = 45_056;

/// Longest group id, store name or key a request may carry.
pub const MAX_DATA_READ_FIELD_BYTES: usize = 256;

/// Longest content type a `get` reply carries. A longer one is answered
/// [`DataReadStatus::ContentTypeTooLong`].
pub const MAX_DATA_READ_CONTENT_TYPE_BYTES: usize = 128;

/// JSON escapes a control character as `\u00XX`: at most 6 bytes per input
/// byte. Every other character is written as its own UTF-8 bytes.
const JSON_ESCAPE_WORST: usize = 6;

/// Fixed bytes of a `get` reply besides its strings: prefix, field names,
/// quotes, braces, the status and a 20-digit `updated_at` (under 140 bytes;
/// the test `worst_case_get_reply_fits` checks it).
const GET_REPLY_FIXED_BYTES: usize = 256;

/// Base64 bytes left for the value in a worst-case `get` reply: the reply
/// bound less the fixed bytes and the escaped request id, key and content
/// type at their bounds.
const VALUE_B64_BUDGET: usize = MAX_DATA_READ_REPLY_BYTES
    - GET_REPLY_FIXED_BYTES
    - JSON_ESCAPE_WORST * (2 * MAX_DATA_READ_FIELD_BYTES + MAX_DATA_READ_CONTENT_TYPE_BYTES);

/// Largest value a `get` reply carries, derived from the reply bound
/// ([`MAX_DATA_READ_REPLY_BYTES`]) so a value at this size always fits,
/// whatever its key, request id and content type within their bounds:
/// 30 720 bytes. A store value can be larger (up to 64 KiB inline); a
/// larger value is answered [`DataReadStatus::TooLarge`]. The DM payload
/// limit ([`crate::dm::MAX_PAYLOAD_BYTES`], 48 KiB) does not allow more.
pub const MAX_DATA_READ_VALUE_BYTES: usize = VALUE_B64_BUDGET / 4 * 3;

const _: () = assert!(
    GET_REPLY_FIXED_BYTES
        + JSON_ESCAPE_WORST * (2 * MAX_DATA_READ_FIELD_BYTES + MAX_DATA_READ_CONTENT_TYPE_BYTES)
        + MAX_DATA_READ_VALUE_BYTES.div_ceil(3) * 4
        <= MAX_DATA_READ_REPLY_BYTES
);
const _: () = assert!(MAX_DATA_READ_VALUE_BYTES == 30_720);
const _: () = assert!(
    GET_REPLY_FIXED_BYTES + JSON_ESCAPE_WORST * 4 * MAX_DATA_READ_FIELD_BYTES
        <= MAX_DATA_READ_REQUEST_BYTES
);

/// Largest write request, prefix included: the same bound as a reply.
pub const MAX_DATA_WRITE_REQUEST_BYTES: usize = MAX_DATA_READ_REPLY_BYTES;

/// Fixed bytes of a `put` request besides its strings: prefix, field
/// names, quotes and braces (under 140 bytes; the test
/// `worst_case_put_request_fits` checks it).
const PUT_REQUEST_FIXED_BYTES: usize = 256;

/// Base64 bytes left for the value in a worst-case `put` request: the bound
/// less the fixed bytes and the escaped request id, group, store, key and
/// content type at their bounds.
const WRITE_VALUE_B64_BUDGET: usize = MAX_DATA_WRITE_REQUEST_BYTES
    - PUT_REQUEST_FIXED_BYTES
    - JSON_ESCAPE_WORST * (4 * MAX_DATA_READ_FIELD_BYTES + MAX_DATA_READ_CONTENT_TYPE_BYTES);

/// Largest value a `put` request carries, derived from
/// [`MAX_DATA_WRITE_REQUEST_BYTES`] the same way as
/// [`MAX_DATA_READ_VALUE_BYTES`]: 28 416 bytes. The grantee's route answers
/// a larger value with 413 and sends nothing.
pub const MAX_DATA_WRITE_VALUE_BYTES: usize = WRITE_VALUE_B64_BUDGET / 4 * 3;

/// Base64 length of a value at [`MAX_DATA_WRITE_VALUE_BYTES`].
const MAX_DATA_WRITE_VALUE_B64_BYTES: usize = MAX_DATA_WRITE_VALUE_BYTES.div_ceil(3) * 4;

/// Longest error text a `refused` write reply carries.
pub const MAX_DATA_WRITE_ERROR_BYTES: usize = 256;

const _: () = assert!(
    PUT_REQUEST_FIXED_BYTES
        + JSON_ESCAPE_WORST * (4 * MAX_DATA_READ_FIELD_BYTES + MAX_DATA_READ_CONTENT_TYPE_BYTES)
        + MAX_DATA_WRITE_VALUE_B64_BYTES
        <= MAX_DATA_WRITE_REQUEST_BYTES
);
const _: () = assert!(MAX_DATA_WRITE_VALUE_BYTES == 28_416);
const _: () = assert!(
    GET_REPLY_FIXED_BYTES
        + JSON_ESCAPE_WORST * (MAX_DATA_READ_FIELD_BYTES + MAX_DATA_WRITE_ERROR_BYTES)
        <= MAX_DATA_READ_REPLY_BYTES
);

/// What a request reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DataReadOp {
    /// The store's keys, with sizes, without values.
    Keys,
    /// One key's value.
    Get {
        /// The key.
        key: String,
    },
}

/// A grantee's read of one store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataReadRequest {
    /// Random id; the reply carries it back.
    pub request_id: String,
    /// Stable group id, as in the grant.
    pub group: String,
    /// Store name, as in the grant.
    pub store: String,
    /// What to read.
    #[serde(flatten)]
    pub op: DataReadOp,
}

/// How a read ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataReadStatus {
    /// Read; `keys` or `entry` holds the result.
    Ok,
    /// No grant held here covers reading this store for the sender.
    Forbidden,
    /// The key is not in the store.
    NotFound,
    /// The value is over [`MAX_DATA_READ_VALUE_BYTES`].
    TooLarge,
    /// The value's content type is over [`MAX_DATA_READ_CONTENT_TYPE_BYTES`].
    ContentTypeTooLong,
    /// This daemon does not hold the store open, or the read failed, or the
    /// result does not fit in one reply.
    Unavailable,
    /// Slice D2: the store or its group refused the write (the store's
    /// access policy, an immutable key, or the ADR 0110 write refusal);
    /// `error` says why.
    Refused,
}

/// One key of a `keys` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataReadKey {
    /// The key.
    pub key: String,
    /// The value's content type.
    pub content_type: String,
    /// Value size in bytes.
    pub size: usize,
    /// Unix milliseconds of the last write.
    pub updated_at: u64,
}

/// The value of a `get` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataReadEntry {
    /// The key.
    pub key: String,
    /// Base64 of the value bytes.
    pub value_b64: String,
    /// The value's content type.
    pub content_type: String,
    /// Unix milliseconds of the last write.
    pub updated_at: u64,
}

/// The granted agent's answer to one [`DataReadRequest`], or to one
/// [`DataWriteRequest`] (slice D2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataReadReply {
    /// The request's id.
    pub request_id: String,
    /// How the read ended.
    pub status: DataReadStatus,
    /// `keys` result when `status` is `Ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<DataReadKey>>,
    /// `true` when `keys` was cut to fit one reply.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// `get` result when `status` is `Ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<DataReadEntry>,
    /// Slice D2: for an `Ok` write, whether the store published it
    /// (`false`: saved on the granted agent, not yet published).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,
    /// Slice D2: why a write was `Refused`, at most
    /// [`MAX_DATA_WRITE_ERROR_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DataReadReply {
    /// A reply with `status` and no result.
    #[must_use]
    pub fn status(request_id: &str, status: DataReadStatus) -> Self {
        Self {
            request_id: request_id.to_string(),
            status,
            keys: None,
            truncated: false,
            entry: None,
            published: None,
            error: None,
        }
    }
}

fn encode_bounded<T: Serialize>(prefix: &[u8], value: &T, max: usize) -> Option<Vec<u8>> {
    let body = serde_json::to_vec(value).ok()?;
    let mut out = Vec::with_capacity(prefix.len() + body.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&body);
    (out.len() <= max).then_some(out)
}

fn decode_bounded<T: for<'de> Deserialize<'de>>(
    prefix: &[u8],
    payload: &[u8],
    max: usize,
) -> Option<T> {
    if payload.len() > max {
        return None;
    }
    serde_json::from_slice(payload.strip_prefix(prefix)?).ok()
}

fn field_ok(field: &str) -> bool {
    !field.is_empty() && field.len() <= MAX_DATA_READ_FIELD_BYTES
}

impl DataReadRequest {
    /// Whether every field is inside its bound.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let key_ok = match &self.op {
            DataReadOp::Keys => true,
            DataReadOp::Get { key } => field_ok(key),
        };
        field_ok(&self.request_id) && field_ok(&self.group) && field_ok(&self.store) && key_ok
    }

    /// Prefixed wire bytes; `None` when malformed or over the bound.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !self.is_well_formed() {
            return None;
        }
        encode_bounded(
            DATA_READ_REQUEST_DM_PREFIX,
            self,
            MAX_DATA_READ_REQUEST_BYTES,
        )
    }

    /// Parse wire bytes; `None` when not a well-formed request.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        decode_bounded::<Self>(
            DATA_READ_REQUEST_DM_PREFIX,
            payload,
            MAX_DATA_READ_REQUEST_BYTES,
        )
        .filter(Self::is_well_formed)
    }
}

/// What a write does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DataWriteOp {
    /// Set one key's value.
    Put {
        /// The key.
        key: String,
        /// Base64 of the value bytes, at most [`MAX_DATA_WRITE_VALUE_BYTES`]
        /// once decoded.
        value_b64: String,
        /// The value's content type, at most
        /// [`MAX_DATA_READ_CONTENT_TYPE_BYTES`].
        content_type: String,
    },
    /// Remove one key.
    Delete {
        /// The key.
        key: String,
    },
}

/// A grantee's write to one store (slice D2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataWriteRequest {
    /// Random id; the reply carries it back.
    pub request_id: String,
    /// Stable group id, as in the grant.
    pub group: String,
    /// Store name, as in the grant.
    pub store: String,
    /// What to write.
    #[serde(flatten)]
    pub op: DataWriteOp,
}

impl DataWriteRequest {
    /// Whether every field is inside its bound.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let op_ok = match &self.op {
            DataWriteOp::Put {
                key,
                value_b64,
                content_type,
            } => {
                field_ok(key)
                    && value_b64.len() <= MAX_DATA_WRITE_VALUE_B64_BYTES
                    && !content_type.is_empty()
                    && content_type.len() <= MAX_DATA_READ_CONTENT_TYPE_BYTES
            }
            DataWriteOp::Delete { key } => field_ok(key),
        };
        field_ok(&self.request_id) && field_ok(&self.group) && field_ok(&self.store) && op_ok
    }

    /// Prefixed wire bytes; `None` when malformed or over the bound.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !self.is_well_formed() {
            return None;
        }
        encode_bounded(
            DATA_WRITE_REQUEST_DM_PREFIX,
            self,
            MAX_DATA_WRITE_REQUEST_BYTES,
        )
    }

    /// Parse wire bytes; `None` when not a well-formed request.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        decode_bounded::<Self>(
            DATA_WRITE_REQUEST_DM_PREFIX,
            payload,
            MAX_DATA_WRITE_REQUEST_BYTES,
        )
        .filter(Self::is_well_formed)
    }
}

/// `text` cut to at most `max` bytes, at a character boundary.
#[must_use]
pub fn truncate_utf8(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

impl DataReadReply {
    /// Prefixed wire bytes; `None` when over [`MAX_DATA_READ_REPLY_BYTES`].
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        encode_bounded(DATA_READ_REPLY_DM_PREFIX, self, MAX_DATA_READ_REPLY_BYTES)
    }

    /// Parse wire bytes; `None` when not a reply.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        decode_bounded(
            DATA_READ_REPLY_DM_PREFIX,
            payload,
            MAX_DATA_READ_REPLY_BYTES,
        )
    }

    /// A `keys` reply that fits [`MAX_DATA_READ_REPLY_BYTES`]: keys are
    /// dropped from the end, and `truncated` set, until it fits.
    #[must_use]
    pub fn keys_fitting(request_id: &str, mut keys: Vec<DataReadKey>) -> Option<Vec<u8>> {
        let mut truncated = false;
        loop {
            let reply = Self {
                keys: Some(keys.clone()),
                truncated,
                ..Self::status(request_id, DataReadStatus::Ok)
            };
            if let Some(bytes) = reply.encode() {
                return Some(bytes);
            }
            if keys.is_empty() {
                return None;
            }
            let drop = (keys.len() / 8).max(1);
            keys.truncate(keys.len() - drop);
            truncated = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_and_bounds() {
        let request = DataReadRequest {
            request_id: "ab".repeat(16),
            group: "cd".repeat(16),
            store: "scratch".to_string(),
            op: DataReadOp::Get {
                key: "note".to_string(),
            },
        };
        let bytes = request.encode().expect("encode");
        assert!(bytes.starts_with(DATA_READ_REQUEST_DM_PREFIX));
        assert_eq!(DataReadRequest::decode(&bytes), Some(request.clone()));

        let keys = DataReadRequest {
            op: DataReadOp::Keys,
            ..request.clone()
        };
        assert_eq!(
            DataReadRequest::decode(&keys.encode().expect("encode")),
            Some(keys)
        );

        let long = DataReadRequest {
            op: DataReadOp::Get {
                key: "k".repeat(MAX_DATA_READ_FIELD_BYTES + 1),
            },
            ..request.clone()
        };
        assert!(long.encode().is_none());
        let empty = DataReadRequest {
            store: String::new(),
            ..request
        };
        assert!(empty.encode().is_none());
        assert!(DataReadRequest::decode(b"x0x-data-read-v1\0{}").is_none());
        assert!(DataReadRequest::decode(b"not a request").is_none());
    }

    /// The derived value limit fits the reply bound in the worst case:
    /// request id, key and content type at their bounds and made only of
    /// control characters (6 bytes each once escaped).
    #[test]
    fn worst_case_request_fits() {
        let control = |n: usize| "\u{1}".repeat(n);
        let request = DataReadRequest {
            request_id: control(MAX_DATA_READ_FIELD_BYTES),
            group: control(MAX_DATA_READ_FIELD_BYTES),
            store: control(MAX_DATA_READ_FIELD_BYTES),
            op: DataReadOp::Get {
                key: control(MAX_DATA_READ_FIELD_BYTES),
            },
        };
        let bytes = request.encode().expect("the worst case fits");
        assert_eq!(DataReadRequest::decode(&bytes), Some(request));
    }

    #[test]
    fn worst_case_get_reply_fits() {
        let control = |n: usize| "\u{1}".repeat(n);
        let reply = DataReadReply {
            request_id: control(MAX_DATA_READ_FIELD_BYTES),
            status: DataReadStatus::Ok,
            keys: None,
            truncated: false,
            entry: Some(DataReadEntry {
                key: control(MAX_DATA_READ_FIELD_BYTES),
                value_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    vec![0xff; MAX_DATA_READ_VALUE_BYTES],
                ),
                content_type: control(MAX_DATA_READ_CONTENT_TYPE_BYTES),
                updated_at: u64::MAX,
            }),
            published: None,
            error: None,
        };
        let bytes = reply.encode().expect("the worst case fits");
        assert!(bytes.len() <= MAX_DATA_READ_REPLY_BYTES);
        let strings = JSON_ESCAPE_WORST
            * (2 * MAX_DATA_READ_FIELD_BYTES + MAX_DATA_READ_CONTENT_TYPE_BYTES)
            + MAX_DATA_READ_VALUE_BYTES.div_ceil(3) * 4;
        assert!(
            bytes.len() - strings <= GET_REPLY_FIXED_BYTES,
            "fixed bytes {} exceed the allowance",
            bytes.len() - strings
        );
    }

    #[test]
    fn reply_round_trip_and_truncation() {
        let reply = DataReadReply {
            request_id: "01".repeat(16),
            status: DataReadStatus::Ok,
            keys: None,
            truncated: false,
            entry: Some(DataReadEntry {
                key: "note".to_string(),
                value_b64: "aGk=".to_string(),
                content_type: "text/plain".to_string(),
                updated_at: 7,
            }),
            published: None,
            error: None,
        };
        let bytes = reply.encode().expect("encode");
        assert_eq!(DataReadReply::decode(&bytes), Some(reply));
        let too_large = DataReadReply::status("x", DataReadStatus::TooLarge);
        assert!(
            String::from_utf8_lossy(&too_large.encode().expect("encode")).contains("too_large")
        );
        let forbidden = DataReadReply::status("x", DataReadStatus::Forbidden);
        assert_eq!(
            DataReadReply::decode(&forbidden.encode().expect("encode")),
            Some(forbidden)
        );

        let many: Vec<DataReadKey> = (0..2_000)
            .map(|i| DataReadKey {
                key: format!("key-{i:06}-{}", "x".repeat(40)),
                content_type: "text/plain".to_string(),
                size: i,
                updated_at: 1,
            })
            .collect();
        let bytes = DataReadReply::keys_fitting("id", many).expect("fits");
        assert!(bytes.len() <= MAX_DATA_READ_REPLY_BYTES);
        let decoded = DataReadReply::decode(&bytes).expect("decode");
        assert!(decoded.truncated);
        assert!(!decoded.keys.expect("keys").is_empty());
    }

    /// Slice D2: the derived write value limit fits the write request bound
    /// in the worst case (every string at its bound, made only of control
    /// characters).
    #[test]
    fn worst_case_put_request_fits() {
        let control = |n: usize| "\u{1}".repeat(n);
        let request = DataWriteRequest {
            request_id: control(MAX_DATA_READ_FIELD_BYTES),
            group: control(MAX_DATA_READ_FIELD_BYTES),
            store: control(MAX_DATA_READ_FIELD_BYTES),
            op: DataWriteOp::Put {
                key: control(MAX_DATA_READ_FIELD_BYTES),
                value_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    vec![0xff; MAX_DATA_WRITE_VALUE_BYTES],
                ),
                content_type: control(MAX_DATA_READ_CONTENT_TYPE_BYTES),
            },
        };
        let bytes = request.encode().expect("the worst case fits");
        assert!(bytes.len() <= MAX_DATA_WRITE_REQUEST_BYTES);
        assert_eq!(DataWriteRequest::decode(&bytes), Some(request));
        let strings = JSON_ESCAPE_WORST
            * (4 * MAX_DATA_READ_FIELD_BYTES + MAX_DATA_READ_CONTENT_TYPE_BYTES)
            + MAX_DATA_WRITE_VALUE_B64_BYTES;
        assert!(
            bytes.len() - strings <= PUT_REQUEST_FIXED_BYTES,
            "fixed bytes {} exceed the allowance",
            bytes.len() - strings
        );
    }

    #[test]
    fn write_request_round_trip_and_bounds() {
        let put = DataWriteRequest {
            request_id: "ab".repeat(16),
            group: "cd".repeat(16),
            store: "scratch".to_string(),
            op: DataWriteOp::Put {
                key: "note".to_string(),
                value_b64: "aGk=".to_string(),
                content_type: "text/plain".to_string(),
            },
        };
        let bytes = put.encode().expect("encode");
        assert!(bytes.starts_with(DATA_WRITE_REQUEST_DM_PREFIX));
        assert_eq!(DataWriteRequest::decode(&bytes), Some(put.clone()));
        assert!(
            DataReadRequest::decode(&bytes).is_none(),
            "a write is never a read"
        );
        let delete = DataWriteRequest {
            op: DataWriteOp::Delete {
                key: "note".to_string(),
            },
            ..put.clone()
        };
        assert_eq!(
            DataWriteRequest::decode(&delete.encode().expect("encode")),
            Some(delete)
        );
        let over = DataWriteRequest {
            op: DataWriteOp::Put {
                key: "note".to_string(),
                value_b64: "A".repeat(MAX_DATA_WRITE_VALUE_B64_BYTES + 4),
                content_type: "text/plain".to_string(),
            },
            ..put.clone()
        };
        assert!(over.encode().is_none());
        let no_type = DataWriteRequest {
            op: DataWriteOp::Put {
                key: "note".to_string(),
                value_b64: "aGk=".to_string(),
                content_type: String::new(),
            },
            ..put
        };
        assert!(no_type.encode().is_none());
    }

    #[test]
    fn write_reply_fields_round_trip() {
        let mut refused = DataReadReply::status("id", DataReadStatus::Refused);
        refused.error = Some(truncate_utf8(&"é".repeat(200), MAX_DATA_WRITE_ERROR_BYTES));
        assert!(refused
            .error
            .as_deref()
            .is_some_and(|e| e.len() <= MAX_DATA_WRITE_ERROR_BYTES));
        assert_eq!(
            DataReadReply::decode(&refused.encode().expect("encode")),
            Some(refused)
        );
        let mut ok = DataReadReply::status("id", DataReadStatus::Ok);
        ok.published = Some(false);
        assert_eq!(
            DataReadReply::decode(&ok.encode().expect("encode")),
            Some(ok)
        );
        // A read reply carries neither field, as before.
        let read = DataReadReply::status("id", DataReadStatus::NotFound)
            .encode()
            .expect("encode");
        let text = String::from_utf8_lossy(&read);
        assert!(!text.contains("published") && !text.contains("error"));
    }
}
