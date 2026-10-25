//! Forward compatibility for wire-format enums (#1604).
//!
//! `#[non_exhaustive]` is a compile-time marker only. It changes no bytes
//! and no decoder behaviour. This module gives every decoder one typed,
//! counted and logged outcome for a variant that this node does not know:
//!
//! - The JSON unit enums carry `#[serde(other, skip_serializing)] Unknown`.
//!   A value that holds one decodes, but [`reject_unknown`] refuses it
//!   before any signature or hash check, and it can never be encoded again,
//!   so it is never re-signed, re-gossiped or stored.
//! - Every other decoder maps an unknown variant to
//!   [`WireDecodeError::UnknownVariant`] through [`decode_json`],
//!   [`decode_bincode`] or [`classify_bincode`].
//!
//! Each unknown variant increments a per-type counter
//! ([`unknown_variant_count`]). The first one of each type logs at `warn`;
//! later ones log at `debug`, so a newer peer cannot flood the log.

use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// A wire value this node refuses to act on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum WireDecodeError {
    /// The value names a variant this node does not know.
    #[error("{wire_type}: unsupported variant ({detail})")]
    UnknownVariant {
        /// The wire type that failed.
        wire_type: &'static str,
        /// What was not known.
        detail: String,
    },
    /// The bytes are not a valid encoding of the type.
    #[error("{wire_type}: malformed ({detail})")]
    Malformed {
        /// The wire type that failed.
        wire_type: &'static str,
        /// The decoder's message.
        detail: String,
    },
}

/// Part of serde's error for a `skip_serializing` variant ("the enum
/// variant X::Unknown cannot be serialized"). [`reject_unknown`] depends on
/// this text; a test pins it.
const SKIPPED_UNKNOWN_MESSAGE: &str = "::Unknown cannot be serialized";

static UNKNOWN_VARIANTS: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());

/// Count and log one unknown variant of `wire_type`. Returns the typed
/// error for the caller to propagate.
pub(crate) fn note_unknown(wire_type: &'static str, detail: impl Into<String>) -> WireDecodeError {
    let detail = detail.into();
    let count = {
        let mut counts = UNKNOWN_VARIANTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = counts.entry(wire_type).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    };
    if count == 1 {
        tracing::warn!(
            target: "x0x::wire_compat",
            wire_type,
            %detail,
            count,
            "refused a wire value with a variant this node does not know; a newer peer may need this node to upgrade"
        );
    } else {
        tracing::debug!(
            target: "x0x::wire_compat",
            wire_type,
            %detail,
            count,
            "refused a wire value with a variant this node does not know"
        );
    }
    WireDecodeError::UnknownVariant { wire_type, detail }
}

/// How many unknown variants of `wire_type` this process has refused.
#[cfg(test)]
#[must_use]
pub(crate) fn unknown_variant_count(wire_type: &str) -> u64 {
    UNKNOWN_VARIANTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(wire_type)
        .copied()
        .unwrap_or(0)
}

/// Refuse `value` if it holds an `Unknown` variant anywhere.
///
/// The `Unknown` variants are `skip_serializing`, so a value that holds one
/// cannot be encoded. A trial encode into [`Probe`], which accepts every
/// serde shape and writes nothing, finds it without a per-type walk.
///
/// Call this before any signature or hash check: a value with an `Unknown`
/// can never re-encode to the bytes that were signed.
///
/// # Errors
/// [`WireDecodeError::UnknownVariant`] (counted and logged) if the value
/// holds an `Unknown`; [`WireDecodeError::Malformed`] if it cannot be
/// encoded for another reason.
pub(crate) fn reject_unknown<T: Serialize>(
    wire_type: &'static str,
    value: T,
) -> Result<T, WireDecodeError> {
    match value.serialize(Probe) {
        Ok(()) => Ok(value),
        Err(ProbeError(detail)) => {
            if detail.contains(SKIPPED_UNKNOWN_MESSAGE) {
                Err(note_unknown(wire_type, detail))
            } else {
                Err(WireDecodeError::Malformed { wire_type, detail })
            }
        }
    }
}

/// A serde serializer that writes nothing and accepts every data shape
/// (unlike bincode, it takes sequences and maps of unknown length; unlike
/// JSON, it takes any map key). Its only errors are the ones a value's own
/// `Serialize` raises, such as a `skip_serializing` variant.
struct Probe;

/// The message of an error raised while probing.
#[derive(Debug)]
struct ProbeError(String);

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProbeError {}

impl serde::ser::Error for ProbeError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

/// Primitive `serialize_*` methods of [`Probe`]: accept and discard.
macro_rules! probe_accepts {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(fn $method(self, _: $ty) -> Result<(), ProbeError> { Ok(()) })*
    };
}

impl serde::Serializer for Probe {
    type Ok = ();
    type Error = ProbeError;
    type SerializeSeq = Probe;
    type SerializeTuple = Probe;
    type SerializeTupleStruct = Probe;
    type SerializeTupleVariant = Probe;
    type SerializeMap = Probe;
    type SerializeStruct = Probe;
    type SerializeStructVariant = Probe;

    probe_accepts!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8]),
        serialize_unit_struct(&'static str),
    );

    fn serialize_none(self) -> Result<(), ProbeError> {
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn serialize_unit(self) -> Result<(), ProbeError> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<(), ProbeError> {
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        value: &T,
    ) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Probe, ProbeError> {
        Ok(Probe)
    }
    fn serialize_tuple(self, _: usize) -> Result<Probe, ProbeError> {
        Ok(Probe)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Probe, ProbeError> {
        Ok(Probe)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Probe, ProbeError> {
        Ok(Probe)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Probe, ProbeError> {
        Ok(Probe)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Probe, ProbeError> {
        Ok(Probe)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Probe, ProbeError> {
        Ok(Probe)
    }
}

impl serde::ser::SerializeSeq for Probe {
    type Ok = ();
    type Error = ProbeError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

impl serde::ser::SerializeTuple for Probe {
    type Ok = ();
    type Error = ProbeError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

impl serde::ser::SerializeTupleStruct for Probe {
    type Ok = ();
    type Error = ProbeError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

impl serde::ser::SerializeTupleVariant for Probe {
    type Ok = ();
    type Error = ProbeError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

impl serde::ser::SerializeMap for Probe {
    type Ok = ();
    type Error = ProbeError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), ProbeError> {
        key.serialize(Probe)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

impl serde::ser::SerializeStruct for Probe {
    type Ok = ();
    type Error = ProbeError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

impl serde::ser::SerializeStructVariant for Probe {
    type Ok = ();
    type Error = ProbeError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), ProbeError> {
        value.serialize(Probe)
    }
    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

/// The variant name in a serde "unknown variant" error, if it is one.
fn unknown_variant_name(message: &str) -> Option<&str> {
    let rest = message.split("unknown variant `").nth(1)?;
    rest.split('`').next()
}

/// Classify a `serde_json` decode error. An unknown variant whose name
/// starts with `family` is counted and logged; `family` keeps probes over
/// mixed payloads (a DM may hold any JSON) from counting other families.
pub(crate) fn classify_json(
    wire_type: &'static str,
    family: &str,
    err: &serde_json::Error,
) -> WireDecodeError {
    let message = err.to_string();
    match unknown_variant_name(&message) {
        Some(name) if name.starts_with(family) => note_unknown(wire_type, message),
        _ => WireDecodeError::Malformed {
            wire_type,
            detail: message,
        },
    }
}

/// Decode a JSON wire message and refuse it if it holds an `Unknown`.
///
/// An unknown top-level variant is counted only if its name starts with
/// `family` (`""` counts every name: use it on a channel that carries only
/// this type).
///
/// # Errors
/// [`WireDecodeError`], counted and logged for an unknown variant.
pub(crate) fn decode_json<T: DeserializeOwned + Serialize>(
    wire_type: &'static str,
    family: &str,
    bytes: &[u8],
) -> Result<T, WireDecodeError> {
    let value = serde_json::from_slice(bytes).map_err(|e| classify_json(wire_type, family, &e))?;
    reject_unknown(wire_type, value)
}

/// Classify a bincode decode error. serde reports an unknown variant index
/// as "invalid value: integer `N`, expected variant index 0 <= i < M".
pub(crate) fn classify_bincode(
    wire_type: &'static str,
    err: &bincode::ErrorKind,
) -> WireDecodeError {
    let message = err.to_string();
    if message.contains("expected variant index") {
        note_unknown(wire_type, message)
    } else {
        WireDecodeError::Malformed {
            wire_type,
            detail: message,
        }
    }
}

/// `bincode::deserialize` with a typed, counted unknown-variant error.
///
/// # Errors
/// [`WireDecodeError`].
pub(crate) fn decode_bincode<T: DeserializeOwned>(
    wire_type: &'static str,
    bytes: &[u8],
) -> Result<T, WireDecodeError> {
    bincode::deserialize(bytes).map_err(|e| classify_bincode(wire_type, &e))
}

/// Read one postcard varint (LEB128, at most 10 bytes).
fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Number of `DmBody` variants this node knows.
const DM_BODY_VARIANTS: u64 = 2;
/// `DmBody::Ack` variant index.
const DM_BODY_ACK: u64 = 1;
/// Number of `DmAckOutcome` variants this node knows.
const DM_ACK_OUTCOME_VARIANTS: u64 = 4;

/// After a postcard `DmEnvelope` decode failed: find whether the cause is
/// an unknown `DmBody` or `DmAckOutcome` variant. If so, count and log it.
///
/// The envelope prefix is fixed by the postcard layout of `DmEnvelope`:
/// `protocol_version` (varint), `request_id` (16 bytes), three 32-byte
/// ids, two varint timestamps, then the `DmBody` variant index. An `Ack`
/// body starts with a 16-byte request id and the `DmAckOutcome` index.
pub(crate) fn dm_envelope_unknown_variant(bytes: &[u8]) -> Option<WireDecodeError> {
    let mut pos = 0usize;
    read_varint(bytes, &mut pos)?;
    pos = pos.checked_add(16 + 32 * 3)?;
    read_varint(bytes, &mut pos)?;
    read_varint(bytes, &mut pos)?;
    let body = read_varint(bytes, &mut pos)?;
    if body >= DM_BODY_VARIANTS {
        return Some(note_unknown("DmBody", format!("variant index {body}")));
    }
    if body != DM_BODY_ACK {
        return None;
    }
    pos = pos.checked_add(16)?;
    let outcome = read_varint(bytes, &mut pos)?;
    (outcome >= DM_ACK_OUTCOME_VARIANTS)
        .then(|| note_unknown("DmAckOutcome", format!("variant index {outcome}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_variant_name_parses_serde_messages() {
        let err = serde_json::from_str::<crate::groups::JoinRequestStatus>("7").unwrap_err();
        assert_eq!(unknown_variant_name(&err.to_string()), None);
        assert_eq!(
            unknown_variant_name("unknown variant `file-new`, expected one of `a`"),
            Some("file-new")
        );
    }

    #[test]
    fn reject_unknown_refuses_nested_unknown_and_counts_it() {
        let policy: crate::groups::GroupPolicy = serde_json::from_value(serde_json::json!({
            "discoverability": "hidden",
            "admission": "invite_only",
            "confidentiality": "quantum_sealed",
            "read_access": "members_only",
            "write_access": "members_only",
        }))
        .expect("an unknown policy string decodes as Unknown");
        assert_eq!(
            policy.confidentiality,
            crate::groups::GroupConfidentiality::Unknown
        );
        let before = unknown_variant_count("test.GroupPolicy");
        let err = reject_unknown("test.GroupPolicy", policy).unwrap_err();
        assert!(
            matches!(err, WireDecodeError::UnknownVariant { .. }),
            "{err}"
        );
        assert_eq!(unknown_variant_count("test.GroupPolicy"), before + 1);
        assert!(
            serde_json::to_vec(&crate::groups::GroupConfidentiality::Unknown).is_err(),
            "Unknown is never encoded"
        );
    }

    #[test]
    fn probe_accepts_shapes_bincode_and_json_refuse() {
        // A map with a non-string key (JSON refuses) inside a flattened
        // struct (bincode refuses an unknown-length map).
        #[derive(Serialize)]
        struct Inner {
            by_id: std::collections::BTreeMap<[u8; 2], u8>,
        }
        #[derive(Serialize)]
        struct Outer {
            #[serde(flatten)]
            inner: Inner,
        }
        let value = Outer {
            inner: Inner {
                by_id: [([1, 2], 3)].into_iter().collect(),
            },
        };
        assert!(serde_json::to_vec(&value).is_err());
        assert!(bincode::serialize(&value).is_err());
        assert!(reject_unknown("test.Outer", value).is_ok());
    }

    #[test]
    fn reject_unknown_passes_known_values() {
        let policy = crate::groups::GroupPolicy::default();
        assert!(reject_unknown("test.GroupPolicy", policy).is_ok());
    }

    #[test]
    fn bincode_unknown_index_is_typed_and_counted() {
        let mut bytes = 99u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let before = unknown_variant_count("test.ExecFrame");
        let err = decode_bincode::<crate::exec::protocol::ExecFrame>("test.ExecFrame", &bytes)
            .unwrap_err();
        assert!(
            matches!(err, WireDecodeError::UnknownVariant { .. }),
            "{err}"
        );
        assert_eq!(unknown_variant_count("test.ExecFrame"), before + 1);
        let err =
            decode_bincode::<crate::exec::protocol::ExecFrame>("test.ExecFrame", &[1]).unwrap_err();
        assert!(matches!(err, WireDecodeError::Malformed { .. }), "{err}");
        assert_eq!(unknown_variant_count("test.ExecFrame"), before + 1);
    }

    #[test]
    fn json_unknown_variant_counts_only_its_family() {
        let bytes = br#"{"type":"file-teleport","transfer_id":"t"}"#;
        let err = serde_json::from_slice::<crate::files::FileMessage>(bytes).unwrap_err();
        let before = unknown_variant_count("test.FileMessage");
        assert!(matches!(
            classify_json("test.FileMessage", "file-", &err),
            WireDecodeError::UnknownVariant { .. }
        ));
        assert_eq!(unknown_variant_count("test.FileMessage"), before + 1);
        let other = br#"{"type":"chat","text":"hi"}"#;
        let err = serde_json::from_slice::<crate::files::FileMessage>(other).unwrap_err();
        assert!(matches!(
            classify_json("test.FileMessage", "file-", &err),
            WireDecodeError::Malformed { .. }
        ));
        assert_eq!(unknown_variant_count("test.FileMessage"), before + 1);
    }

    #[test]
    fn varint_reader_rejects_overlong_input() {
        let mut pos = 0;
        assert_eq!(read_varint(&[0xff; 11], &mut pos), None);
        let mut pos = 0;
        assert_eq!(read_varint(&[0xac, 0x02], &mut pos), Some(300));
        assert_eq!(pos, 2);
    }
}
