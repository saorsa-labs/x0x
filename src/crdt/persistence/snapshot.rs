use crate::crdt::persistence::migration::{
    evaluate_snapshot_schema, MigrationError, MigrationResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CODEC_MARKER_BINC: &str = "bincode";
pub const CODEC_VERSION_V1: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityMetadata {
    pub algorithm: String,
    pub digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEnvelope {
    pub schema_version: u32,
    pub codec_marker: String,
    pub codec_version: u32,
    pub integrity: IntegrityMetadata,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SnapshotDecodeError {
    #[error("invalid snapshot envelope encoding: {0}")]
    InvalidEncoding(String),
    #[error("unexpected codec marker: {0}")]
    UnexpectedCodec(String),
    #[error("integrity mismatch for snapshot payload")]
    IntegrityMismatch,
    #[error(transparent)]
    Migration(#[from] MigrationError),
}

impl SnapshotEnvelope {
    #[must_use]
    pub fn new(schema_version: u32, payload: Vec<u8>) -> Self {
        let digest_hex = blake3::hash(&payload).to_hex().to_string();
        Self {
            schema_version,
            codec_marker: CODEC_MARKER_BINC.to_string(),
            codec_version: CODEC_VERSION_V1,
            integrity: IntegrityMetadata {
                algorithm: "blake3".to_string(),
                digest_hex,
            },
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SnapshotDecodeError> {
        serde_json::to_vec(self).map_err(|e| SnapshotDecodeError::InvalidEncoding(e.to_string()))
    }

    pub fn decode(input: &[u8]) -> Result<(Self, MigrationResult), SnapshotDecodeError> {
        let value: Value = serde_json::from_slice(input)
            .map_err(|e| SnapshotDecodeError::InvalidEncoding(e.to_string()))?;

        if looks_like_legacy_encrypted_artifact_value(&value) {
            return Err(SnapshotDecodeError::Migration(
                MigrationError::UnsupportedLegacyEncryptedArtifact,
            ));
        }

        let envelope: Self = serde_json::from_value(value)
            .map_err(|e| SnapshotDecodeError::InvalidEncoding(e.to_string()))?;

        if envelope.codec_marker != CODEC_MARKER_BINC {
            return Err(SnapshotDecodeError::UnexpectedCodec(envelope.codec_marker));
        }

        let expected = blake3::hash(&envelope.payload).to_hex().to_string();
        if expected != envelope.integrity.digest_hex {
            return Err(SnapshotDecodeError::IntegrityMismatch);
        }

        let migration = evaluate_snapshot_schema(envelope.schema_version)?;
        Ok((envelope, migration))
    }
}

#[must_use]
pub fn looks_like_legacy_encrypted_artifact(input: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(input) else {
        return false;
    };

    looks_like_legacy_encrypted_artifact_value(&value)
}

fn looks_like_legacy_encrypted_artifact_value(value: &Value) -> bool {
    let Value::Object(map) = value else {
        return false;
    };

    let has_ciphertext = map.contains_key("ciphertext");
    let has_nonce = map.contains_key("nonce") || map.contains_key("iv");
    let has_key_marker = map.contains_key("key_id")
        || map.contains_key("kdf")
        || map.contains_key("aad")
        || map.contains_key("encryption");

    has_ciphertext && has_nonce && has_key_marker
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::persistence::migration::CURRENT_SNAPSHOT_SCHEMA_VERSION;

    #[test]
    fn snapshot_decode_validates_integrity_and_schema() {
        let envelope = SnapshotEnvelope::new(CURRENT_SNAPSHOT_SCHEMA_VERSION, vec![1, 2, 3]);
        let encoded = envelope.encode().expect("encode envelope");

        let (decoded, result) = SnapshotEnvelope::decode(&encoded).expect("decode envelope");
        assert_eq!(decoded, envelope);
        assert_eq!(result, MigrationResult::Current);
    }

    #[test]
    fn snapshot_decode_rejects_tampering() {
        let mut envelope = SnapshotEnvelope::new(CURRENT_SNAPSHOT_SCHEMA_VERSION, vec![1, 2, 3]);
        envelope.payload = vec![9, 9, 9];
        let encoded = envelope.encode().expect("encode envelope");

        let err = SnapshotEnvelope::decode(&encoded).expect_err("must reject integrity mismatch");
        assert_eq!(err, SnapshotDecodeError::IntegrityMismatch);
    }

    #[test]
    fn snapshot_decode_rejects_unsupported_legacy_encrypted_artifacts() {
        let payload = br#"{"ciphertext":"abc","nonce":"123","key_id":"k1"}"#;
        let err = SnapshotEnvelope::decode(payload).expect_err("must reject legacy artifact");
        assert_eq!(
            err,
            SnapshotDecodeError::Migration(MigrationError::UnsupportedLegacyEncryptedArtifact)
        );
    }

    #[test]
    fn snapshot_decode_invalid_json_remains_invalid_encoding_error() {
        let err =
            SnapshotEnvelope::decode(b"not-json").expect_err("invalid json should fail decode");
        assert!(matches!(err, SnapshotDecodeError::InvalidEncoding(_)));
    }
}
