//! MLS (Messaging Layer Security) group encryption for secure agent communication.
//!
//! Two planes live here:
//! - `group` wraps `saorsa_mls::MlsGroup` — the **legacy GSS** plane
//!   (per-epoch shared secret; no forward secrecy / no post-compromise
//!   security). Retained for grandfathered groups.
//! - `treekem` wraps `saorsa_mls::TreeKemGroup` — **real RFC-9420 TreeKEM**
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
pub use treekem::TreeKemMlsGroup;
pub use welcome::MlsWelcome;

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};

/// Which secure-group plane a group runs on. Persisted in group metadata so the
/// daemon can dispatch secure-content and membership operations to the right
/// implementation while the legacy GSS plane (`group`) and the real-TreeKEM
/// plane (`treekem`) coexist (ADR-0012). Lives here, not inside either plane,
/// because it is the neutral discriminator *between* them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureGroupPlane {
    /// Legacy Group-Shared-Secret plane (`group`). No FS/PCS.
    Gss,
    /// Real RFC-9420 TreeKEM plane (`treekem`). FS + PCS.
    #[default]
    TreeKem,
}

/// Deterministic legacy-GSS bridge from an x0x [`AgentId`] (32 bytes) to a
/// saorsa-mls `MemberId` (16 bytes): the first 16 bytes of the AgentId.
///
/// Real TreeKEM groups deliberately do **not** use this stable cross-group label;
/// they derive a per-group `MemberId` in `treekem` so one agent is unlinkable
/// across groups. Keep this helper scoped to the legacy GSS plane and migration
/// code that explicitly accepts that stable label.
///
/// Note: this truncates a 32-byte SHA-256-derived id to 16 bytes, so `MemberId`
/// is a stable *label*, not a collision-free unique key; do not rely on it for
/// agent uniqueness (the leaf's public keys are the cryptographic identity).
pub(crate) fn agent_id_to_member_id(agent_id: &AgentId) -> saorsa_mls::MemberId {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&agent_id.as_bytes()[..16]);
    saorsa_mls::MemberId::from_bytes(bytes)
}
