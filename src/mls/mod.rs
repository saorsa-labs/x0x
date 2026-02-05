//! MLS (Messaging Layer Security) group encryption for secure agent communication.
//!
//! This module provides end-to-end encryption for group communications using
//! MLS-inspired protocols with ChaCha20-Poly1305 AEAD encryption.

pub mod error;

pub use error::{MlsError, Result};
