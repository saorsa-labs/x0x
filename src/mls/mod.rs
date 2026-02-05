//! MLS (Messaging Layer Security) group encryption for secure agent communication.
//!
//! This module provides end-to-end encryption for group communications using
//! MLS-inspired protocols with ChaCha20-Poly1305 AEAD encryption.

pub mod cipher;
pub mod error;
pub mod group;
pub mod keys;
pub mod welcome;

pub use cipher::MlsCipher;
pub use error::{MlsError, Result};
pub use group::{CommitOperation, MlsCommit, MlsGroup, MlsGroupContext, MlsMemberInfo};
pub use keys::MlsKeySchedule;
pub use welcome::MlsWelcome;
