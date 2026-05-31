//! MLS (Messaging Layer Security) group encryption for secure agent communication.
//!
//! Two planes live here:
//! - [`group`] wraps `saorsa_mls::MlsGroup` — the **legacy GSS** plane
//!   (per-epoch shared secret; no forward secrecy / no post-compromise
//!   security). Retained for grandfathered groups.
//! - [`treekem`] wraps `saorsa_mls::TreeKemGroup` — **real RFC-9420 TreeKEM**
//!   (FS + PCS), the default for new `MlsEncrypted` groups.
//!
//! See ADR-0010 (GSS) and ADR-0012 (TreeKEM default) for the migration plan.

pub mod cipher;
pub mod error;
pub mod group;
pub mod keys;
pub mod treekem;
pub mod welcome;

pub use cipher::MlsCipher;
pub use error::{MlsError, Result};
pub use group::{CommitOperation, MlsCommit, MlsGroup, MlsGroupContext, MlsMemberInfo};
pub use keys::MlsKeySchedule;
pub use treekem::{TreeKemMlsGroup, TreeKemPlane};
pub use welcome::MlsWelcome;
