//! MLS message encryption and decryption using ChaCha20-Poly1305 AEAD.
//!
//! This module implements authenticated encryption for MLS group messages using
//! ChaCha20-Poly1305, providing both confidentiality and authenticity.

use crate::mls::{MlsError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

/// MLS cipher for encrypting and decrypting messages with ChaCha20-Poly1305.
///
/// The cipher uses a 32-byte key and derives per-message nonces from a base nonce
/// and message counter. This provides authenticated encryption with additional data (AEAD).
#[derive(Debug, Clone)]
pub struct MlsCipher {
    /// Encryption key (32 bytes for ChaCha20).
    key: Vec<u8>,
    /// Base nonce (12 bytes) - XORed with counter for each message.
    base_nonce: Vec<u8>,
}

impl MlsCipher {
    /// Creates a new MLS cipher with the given key and base nonce.
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key for ChaCha20-Poly1305
    /// * `base_nonce` - 12-byte base nonce (XORed with counter for each message)
    ///
    /// # Security
    /// The key should be securely derived from an MLS key schedule. The base nonce
    /// is combined with a counter to ensure unique nonces for each message.
    #[must_use]
    pub fn new(key: Vec<u8>, base_nonce: Vec<u8>) -> Self {
        Self { key, base_nonce }
    }

    /// Encrypts plaintext with authenticated encryption.
    ///
    /// Uses ChaCha20-Poly1305 AEAD to encrypt the plaintext and authenticate both
    /// the ciphertext and additional authenticated data (AAD).
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    /// * `counter` - Message counter for nonce derivation
    ///
    /// # Returns
    /// Ciphertext with authentication tag appended (ciphertext.len() == plaintext.len() + 16).
    ///
    /// # Errors
    /// Returns `MlsError::EncryptionError` if encryption fails (e.g., invalid key length).
    ///
    /// # Security
    /// **CRITICAL**: Never reuse the same counter with the same key. Counter reuse
    /// completely breaks ChaCha20-Poly1305 security.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8], counter: u64) -> Result<Vec<u8>> {
        // Derive nonce from base_nonce XOR counter
        let nonce = self.derive_nonce(counter);

        // Create cipher instance
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| MlsError::EncryptionError(format!("invalid key length: {}", e)))?;

        // Create nonce
        let nonce_arr = Nonce::from_slice(&nonce[..12]); // ChaCha20-Poly1305 uses 12-byte nonces

        // Encrypt with AAD
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        cipher
            .encrypt(nonce_arr, payload)
            .map_err(|e| MlsError::EncryptionError(format!("encryption failed: {}", e)))
    }

    /// Decrypts ciphertext with authenticated decryption.
    ///
    /// Uses ChaCha20-Poly1305 AEAD to decrypt and verify the authentication tag.
    /// Both the ciphertext and AAD are authenticated.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with authentication tag appended
    /// * `aad` - Additional authenticated data (must match encryption AAD)
    /// * `counter` - Message counter for nonce derivation (must match encryption counter)
    ///
    /// # Returns
    /// Decrypted plaintext.
    ///
    /// # Errors
    /// * `MlsError::DecryptionError` - Authentication tag verification failed or decryption failed
    /// * `MlsError::EncryptionError` - Invalid key length
    ///
    /// # Security
    /// Authentication failure indicates either:
    /// - Wrong key
    /// - Tampered ciphertext
    /// - Wrong AAD
    /// - Wrong counter
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8], counter: u64) -> Result<Vec<u8>> {
        // Derive nonce from base_nonce XOR counter
        let nonce = self.derive_nonce(counter);

        // Create cipher instance
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| MlsError::EncryptionError(format!("invalid key length: {}", e)))?;

        // Create nonce
        let nonce_arr = Nonce::from_slice(&nonce[..12]);

        // Decrypt with AAD
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        cipher
            .decrypt(nonce_arr, payload)
            .map_err(|e| MlsError::DecryptionError(format!("decryption failed: {}", e)))
    }

    /// Derives a unique nonce for a specific message counter.
    ///
    /// XORs the base nonce with the counter to produce a unique nonce for each message.
    fn derive_nonce(&self, counter: u64) -> Vec<u8> {
        let counter_bytes = counter.to_le_bytes();
        let mut nonce = self.base_nonce.clone();

        // XOR counter into nonce (last 8 bytes)
        for (i, byte) in counter_bytes.iter().enumerate() {
            if i + 4 < nonce.len() {
                nonce[i + 4] ^= byte;
            }
        }

        nonce
    }

    /// Gets the encryption key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Gets the base nonce.
    #[must_use]
    pub fn base_nonce(&self) -> &[u8] {
        &self.base_nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0u8; 32] // 32-byte key for ChaCha20
    }

    fn test_nonce() -> Vec<u8> {
        vec![0u8; 12] // 12-byte nonce for ChaCha20-Poly1305
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"Hello, MLS!";
        let aad = b"additional data";
        let counter = 1;

        // Encrypt
        let ciphertext = cipher.encrypt(plaintext, aad, counter);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap();

        // Ciphertext should be plaintext + 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        // Decrypt
        let decrypted = cipher.decrypt(&ciphertext, aad, counter);
        assert!(decrypted.is_ok());
        let decrypted = decrypted.unwrap();

        // Should match original plaintext
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_authentication_tag_verification() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"secret message";
        let aad = b"context";
        let counter = 5;

        // Encrypt
        let ciphertext = cipher.encrypt(plaintext, aad, counter).unwrap();

        // Tamper with ciphertext (flip a bit)
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;

        // Decryption should fail
        let result = cipher.decrypt(&tampered, aad, counter);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::DecryptionError(_)));
    }

    #[test]
    fn test_wrong_aad_fails() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"secret";
        let aad = b"original aad";
        let wrong_aad = b"wrong aad";
        let counter = 10;

        // Encrypt with original AAD
        let ciphertext = cipher.encrypt(plaintext, aad, counter).unwrap();

        // Decrypt with wrong AAD should fail
        let result = cipher.decrypt(&ciphertext, wrong_aad, counter);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::DecryptionError(_)));
    }

    #[test]
    fn test_wrong_counter_fails() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"data";
        let aad = b"aad";
        let counter = 42;
        let wrong_counter = 43;

        // Encrypt with counter 42
        let ciphertext = cipher.encrypt(plaintext, aad, counter).unwrap();

        // Decrypt with counter 43 should fail (different nonce)
        let result = cipher.decrypt(&ciphertext, aad, wrong_counter);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::DecryptionError(_)));
    }

    #[test]
    fn test_different_counters_produce_different_ciphertexts() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"same message";
        let aad = b"same aad";

        // Encrypt with different counters
        let ct1 = cipher.encrypt(plaintext, aad, 1).unwrap();
        let ct2 = cipher.encrypt(plaintext, aad, 2).unwrap();
        let ct3 = cipher.encrypt(plaintext, aad, 100).unwrap();

        // Ciphertexts should be different (different nonces)
        assert_ne!(ct1, ct2);
        assert_ne!(ct2, ct3);
        assert_ne!(ct1, ct3);
    }

    #[test]
    fn test_empty_plaintext() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"";
        let aad = b"aad";
        let counter = 0;

        // Encrypt empty plaintext
        let ciphertext = cipher.encrypt(plaintext, aad, counter).unwrap();

        // Should have 16-byte auth tag
        assert_eq!(ciphertext.len(), 16);

        // Decrypt should succeed
        let decrypted = cipher.decrypt(&ciphertext, aad, counter).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_aad() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"message";
        let aad = b"";
        let counter = 7;

        // Encrypt with empty AAD
        let ciphertext = cipher.encrypt(plaintext, aad, counter).unwrap();

        // Decrypt with empty AAD
        let decrypted = cipher.decrypt(&ciphertext, aad, counter).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = vec![0x42u8; 10000]; // 10KB
        let aad = b"large message aad";
        let counter = 1000;

        // Encrypt large message
        let ciphertext = cipher.encrypt(&plaintext, aad, counter).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        // Decrypt
        let decrypted = cipher.decrypt(&ciphertext, aad, counter).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_counter_zero() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"first message";
        let aad = b"aad";
        let counter = 0;

        // Counter 0 should work
        let ciphertext = cipher.encrypt(plaintext, aad, counter).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, aad, counter).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_counter_max() {
        let cipher = MlsCipher::new(test_key(), test_nonce());
        let plaintext = b"last message";
        let aad = b"aad";
        let counter = u64::MAX;

        // Max counter should work
        let ciphertext = cipher.encrypt(plaintext, aad, counter).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, aad, counter).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_accessors() {
        let key = test_key();
        let nonce = test_nonce();
        let cipher = MlsCipher::new(key.clone(), nonce.clone());

        assert_eq!(cipher.key(), key.as_slice());
        assert_eq!(cipher.base_nonce(), nonce.as_slice());
    }

    #[test]
    fn test_nonce_derivation_deterministic() {
        let cipher = MlsCipher::new(test_key(), test_nonce());

        let nonce1 = cipher.derive_nonce(42);
        let nonce2 = cipher.derive_nonce(42);

        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let key1 = vec![1u8; 32];
        let key2 = vec![2u8; 32];
        let nonce = test_nonce();

        let cipher1 = MlsCipher::new(key1, nonce.clone());
        let cipher2 = MlsCipher::new(key2, nonce);

        let plaintext = b"test";
        let aad = b"aad";
        let counter = 1;

        let ct1 = cipher1.encrypt(plaintext, aad, counter).unwrap();
        let ct2 = cipher2.encrypt(plaintext, aad, counter).unwrap();

        assert_ne!(ct1, ct2);
    }
}
