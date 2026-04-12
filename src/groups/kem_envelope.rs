//! ML-KEM-768 per-recipient sealed envelopes for group shared-secret delivery.
//!
//! # What this gives (and does not give)
//!
//! This module replaces the earlier obfuscation-grade envelope (which derived
//! the AEAD key from public values observable in gossip) with **true recipient
//! confidentiality** via post-quantum ML-KEM-768 key encapsulation.
//!
//! - Sealer inputs: recipient's published ML-KEM-768 **public** key.
//! - Sealer output: `(kem_ciphertext, aead_nonce, aead_ciphertext)`.
//! - Opener inputs: recipient's own ML-KEM-768 **private** key.
//!
//! An observer of the wire payload who does **not** hold the recipient's
//! private key cannot recover the shared secret. This is enforced by the
//! ML-KEM IND-CCA2 security property. The adversarial E2E proof in
//! `tests/e2e_named_groups.sh` verifies this behaviorally.
//!
//! # Non-goals
//!
//! - This is not full MLS TreeKEM. It gives recipient-confidential delivery
//!   and rekey-on-ban, not per-message forward secrecy within an epoch.
//! - This is not deniability. Sealer identity is NOT hidden from the recipient
//!   (the sender's agent hex is part of the outer event).

use crate::error::{IdentityError, Result};
use saorsa_pqc::api::kem::{MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemVariant};
use serde::{Deserialize, Serialize};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// The KEM variant used for all group shared-secret delivery. ML-KEM-768 is
/// NIST Level 3 PQC — the same strength used elsewhere in the x0x + ant-quic
/// stack.
pub const KEM_VARIANT: MlKemVariant = MlKemVariant::MlKem768;

/// An agent's ML-KEM-768 keypair. This is **separate** from the ML-DSA-65
/// signing keypair — ML-DSA is for authenticity, ML-KEM is for confidentiality.
/// Storing them separately keeps the existing AgentKeypair binary format
/// untouched.
#[derive(Serialize, Deserialize)]
pub struct AgentKemKeypair {
    /// Public-key bytes (1184 bytes for ML-KEM-768).
    pub public_bytes: Vec<u8>,
    /// Secret-key bytes (2400 bytes for ML-KEM-768). NEVER log or serialize
    /// this outside of the protected on-disk store.
    pub secret_bytes: Vec<u8>,
}

impl std::fmt::Debug for AgentKemKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKemKeypair")
            .field(
                "public_bytes",
                &format!("{} bytes", self.public_bytes.len()),
            )
            .field("secret_bytes", &"<REDACTED>")
            .finish()
    }
}

impl AgentKemKeypair {
    /// Generate a fresh ML-KEM-768 keypair.
    pub fn generate() -> Result<Self> {
        let kem = MlKem::new(KEM_VARIANT);
        let (pk, sk) = kem
            .generate_keypair()
            .map_err(|e| IdentityError::KeyGeneration(format!("ML-KEM-768 keygen: {e}")))?;
        Ok(Self {
            public_bytes: pk.to_bytes(),
            secret_bytes: sk.to_bytes(),
        })
    }

    /// Load a keypair from disk, or generate a fresh one and persist it if no
    /// existing file is present. Sets mode 0600 on Unix.
    pub async fn load_or_generate<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
            let kp: AgentKemKeypair = bincode::deserialize(&bytes)
                .map_err(|e| IdentityError::Serialization(format!("ML-KEM load: {e}")))?;
            // Basic sanity: public length matches ML-KEM-768.
            if kp.public_bytes.len() != KEM_VARIANT.public_key_size() {
                return Err(IdentityError::Serialization(format!(
                    "ML-KEM public-key size {} != expected {}",
                    kp.public_bytes.len(),
                    KEM_VARIANT.public_key_size()
                )));
            }
            return Ok(kp);
        }
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(IdentityError::from)?;
        }
        let kp = Self::generate()?;
        let bytes = bincode::serialize(&kp)
            .map_err(|e| IdentityError::Serialization(format!("ML-KEM save: {e}")))?;
        tokio::fs::write(path, bytes)
            .await
            .map_err(IdentityError::from)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(path)
                .await
                .map_err(IdentityError::from)?
                .permissions();
            perms.set_mode(0o600);
            tokio::fs::set_permissions(path, perms)
                .await
                .map_err(IdentityError::from)?;
        }
        Ok(kp)
    }

    /// Decapsulate a `MlKemCiphertext` into the 32-byte shared secret.
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<[u8; 32]> {
        let kem = MlKem::new(KEM_VARIANT);
        let sk = MlKemSecretKey::from_bytes(KEM_VARIANT, &self.secret_bytes)
            .map_err(|e| IdentityError::Serialization(format!("ML-KEM secret-key decode: {e}")))?;
        let ct = MlKemCiphertext::from_bytes(KEM_VARIANT, ciphertext_bytes)
            .map_err(|e| IdentityError::Serialization(format!("ML-KEM ciphertext decode: {e}")))?;
        let ss = kem
            .decapsulate(&sk, &ct)
            .map_err(|e| IdentityError::Serialization(format!("ML-KEM decaps: {e}")))?;
        Ok(ss.to_bytes())
    }
}

/// Seal a 32-byte group shared secret to a recipient's ML-KEM-768 public key.
///
/// Returns `(kem_ciphertext, aead_nonce, aead_ciphertext)`. All three are
/// required by the opener.
///
/// The returned `kem_ciphertext` is ~1088 bytes; `aead_nonce` is 12 bytes;
/// `aead_ciphertext` is `secret.len() + 16` bytes.
pub fn seal_group_secret_to_recipient(
    recipient_public_bytes: &[u8],
    aad: &[u8],
    secret: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12], Vec<u8>)> {
    let pk = MlKemPublicKey::from_bytes(KEM_VARIANT, recipient_public_bytes).map_err(|e| {
        IdentityError::Serialization(format!("recipient ML-KEM public-key decode: {e}"))
    })?;
    let kem = MlKem::new(KEM_VARIANT);
    let (shared, kem_ct) = kem
        .encapsulate(&pk)
        .map_err(|e| IdentityError::Serialization(format!("ML-KEM encaps: {e}")))?;

    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(shared.as_bytes())
        .map_err(|e| IdentityError::Serialization(format!("AEAD init (sealer): {e}")))?;
    let aead_ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret.as_slice(),
                aad,
            },
        )
        .map_err(|e| IdentityError::Serialization(format!("AEAD encrypt: {e}")))?;
    Ok((kem_ct.to_bytes(), nonce, aead_ct))
}

/// Open a sealed envelope using the recipient's ML-KEM private key.
/// Returns the 32-byte secret on success.
///
/// An observer without the recipient's private key cannot successfully call
/// this — they cannot derive `shared_secret` from `kem_ciphertext` without
/// ML-KEM-768's IND-CCA2 protected `decapsulate()`.
pub fn open_group_secret(
    kp: &AgentKemKeypair,
    aad: &[u8],
    kem_ciphertext: &[u8],
    aead_nonce: &[u8; 12],
    aead_ciphertext: &[u8],
) -> Result<[u8; 32]> {
    let shared = kp.decapsulate(kem_ciphertext)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&shared)
        .map_err(|e| IdentityError::Serialization(format!("AEAD init (opener): {e}")))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(aead_nonce),
            Payload {
                msg: aead_ciphertext,
                aad,
            },
        )
        .map_err(|e| IdentityError::Serialization(format!("AEAD decrypt: {e}")))?;
    if plaintext.len() != 32 {
        return Err(IdentityError::Serialization(
            "decrypted secret must be 32 bytes".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seal_open() {
        let kp = AgentKemKeypair::generate().expect("generate");
        let secret = [42u8; 32];
        let aad = b"test-aad";
        let (kem_ct, nonce, aead_ct) =
            seal_group_secret_to_recipient(&kp.public_bytes, aad, &secret).expect("seal");
        let got = open_group_secret(&kp, aad, &kem_ct, &nonce, &aead_ct).expect("open");
        assert_eq!(got, secret);
    }

    #[test]
    fn wrong_keypair_cannot_open() {
        // Seal to kp_a; try to open with kp_b. Must fail.
        let kp_a = AgentKemKeypair::generate().unwrap();
        let kp_b = AgentKemKeypair::generate().unwrap();
        let secret = [7u8; 32];
        let aad = b"aad";
        let (kem_ct, nonce, aead_ct) =
            seal_group_secret_to_recipient(&kp_a.public_bytes, aad, &secret).unwrap();
        // kp_b's decapsulation of ciphertext targeted at kp_a yields a
        // different shared secret → AEAD auth-tag check fails.
        let res = open_group_secret(&kp_b, aad, &kem_ct, &nonce, &aead_ct);
        assert!(res.is_err(), "non-recipient must not open the envelope");
    }

    #[test]
    fn wrong_aad_fails() {
        let kp = AgentKemKeypair::generate().unwrap();
        let secret = [7u8; 32];
        let (kem_ct, nonce, aead_ct) =
            seal_group_secret_to_recipient(&kp.public_bytes, b"aad-a", &secret).unwrap();
        let res = open_group_secret(&kp, b"aad-b", &kem_ct, &nonce, &aead_ct);
        assert!(res.is_err(), "AAD mismatch must fail auth-tag check");
    }
}
