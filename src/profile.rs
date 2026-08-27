//! Owner singleton and self-profile persistence (ADR-0036).
//!
//! Two pieces of daemon-trusted naming state, deliberately kept apart:
//!
//! - [`OwnerProfile`] — WHO owns this install. Written by
//!   `x0x user-id create` next to the user key (`owner.json` in the key's
//!   directory, i.e. inside the instance data dir for named instances).
//!   One owner per install: `create` refuses to record a second, different
//!   `UserId` unless `--rotate-owner` is passed, and the daemon refuses to
//!   adopt a user key that does not match the recorded owner.
//! - [`SelfProfile`] — WHAT this install calls itself. The daemon-side
//!   `{ human_name, display_name, machine_name }` served by
//!   `PUT/GET /profile` and persisted at `<data_dir>/profile.json`.
//!   `display_name` feeds the V3 announce self-name so peers render it
//!   without importing a card.
//!
//! Both files are plain JSON with `#[serde(default)]` on every field so
//! older payloads (and partial PUT bodies) deserialize without error.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name of the owner record, sibling of the `user.key` it describes.
pub const OWNER_PROFILE_FILE: &str = "owner.json";

/// File name of the daemon self-profile, inside the instance data dir.
pub const SELF_PROFILE_FILE: &str = "profile.json";

/// The single owner recorded for an install (ADR-0036).
///
/// `user_id` is hex-encoded so the record is inspectable JSON; `human_name`
/// is optional because `user-id create` can run before the owner has named
/// themselves (`PUT /profile` fills it in later).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerProfile {
    /// Hex-encoded `UserId` (SHA-256 of the owner's ML-DSA-65 public key).
    pub user_id: String,
    /// Human-readable owner name, e.g. "David Irvine".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_name: Option<String>,
}

impl OwnerProfile {
    /// Record an owner for the install that keeps its user key at `key_path`.
    #[must_use]
    pub fn path_for_key(key_path: &Path) -> PathBuf {
        key_path.with_file_name(OWNER_PROFILE_FILE)
    }

    /// Persist next to the user key (best-effort directory creation —
    /// `user-id create` already created it for the key itself).
    ///
    /// # Errors
    /// Returns the underlying IO error if the record cannot be written.
    pub async fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::other(format!("serialize owner profile: {e}")))?;
        tokio::fs::write(path, bytes).await
    }

    /// Load the owner record, if one exists.
    ///
    /// # Errors
    /// Returns the underlying IO/parse error. A missing file is `Ok(None)`;
    /// a corrupt file is surfaced loudly rather than treated as absent —
    /// an install must never silently "forget" who owns it.
    pub async fn load_from(path: &Path) -> std::io::Result<Option<Self>> {
        match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| std::io::Error::other(format!("parse owner profile: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// The daemon-side self-profile served by `PUT/GET /profile` (ADR-0036).
///
/// All three names are optional: an unnamed install is valid, and a PUT
/// body may update any subset of the fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfProfile {
    /// Owner's human name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_name: Option<String>,
    /// This agent's display name (rides the V3 announce as the self-name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Label for this machine, e.g. "MacBook Pro (kitchen)".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_name: Option<String>,
}

impl SelfProfile {
    /// Path of the self-profile inside the daemon data dir.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(SELF_PROFILE_FILE)
    }

    /// Persist to `path`.
    ///
    /// # Errors
    /// Returns the underlying IO error if the profile cannot be written.
    pub async fn save_to(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::other(format!("serialize self profile: {e}")))?;
        tokio::fs::write(path, bytes).await
    }

    /// Load the self-profile, if one exists. A missing file is an empty
    /// profile (`Ok(None)`), not an error — every field is optional.
    ///
    /// # Errors
    /// Returns the underlying IO error. A corrupt file is surfaced loudly:
    /// round-tripping names across restart must never silently reset.
    pub async fn load_from(path: &Path) -> std::io::Result<Option<Self>> {
        match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| std::io::Error::other(format!("parse self profile: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Apply a partial update: every `Some` field replaces the stored
    /// value, every `None` field is left untouched. Returns whether
    /// anything changed.
    #[must_use]
    pub fn merge(&mut self, update: &SelfProfile) -> bool {
        let mut changed = false;
        if let Some(v) = &update.human_name {
            changed |= self.human_name.as_ref() != Some(v);
            self.human_name = Some(v.clone());
        }
        if let Some(v) = &update.display_name {
            changed |= self.display_name.as_ref() != Some(v);
            self.display_name = Some(v.clone());
        }
        if let Some(v) = &update.machine_name {
            changed |= self.machine_name.as_ref() != Some(v);
            self.machine_name = Some(v.clone());
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[tokio::test]
    async fn owner_profile_round_trips_on_disk() {
        // WHY: the owner record is the install's authority anchor — a lost or
        // corrupted record silently disables single-owner enforcement.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.json");
        let owner = OwnerProfile {
            user_id: "ab".repeat(32),
            human_name: Some("David Irvine".to_string()),
        };
        owner.save_to(&path).await.unwrap();
        let loaded = OwnerProfile::load_from(&path).await.unwrap();
        assert_eq!(loaded.as_ref(), Some(&owner));
    }

    #[tokio::test]
    async fn owner_profile_missing_file_is_none_but_corrupt_file_is_error() {
        // WHY: absent = first run (no owner yet); corrupt = someone or
        // something damaged the authority record — must never read as
        // "unowned" and let a second owner take over.
        let dir = tempfile::tempdir().unwrap();
        assert!(OwnerProfile::load_from(&dir.path().join("nope.json"))
            .await
            .unwrap()
            .is_none());
        let corrupt = dir.path().join("owner.json");
        tokio::fs::write(&corrupt, b"{ not json").await.unwrap();
        assert!(OwnerProfile::load_from(&corrupt).await.is_err());
    }

    #[tokio::test]
    async fn self_profile_round_trips_across_restart() {
        // WHY: ADR-0036 validation — GET /profile must round-trip across a
        // daemon restart; names are daemon-persisted, not client state.
        let dir = tempfile::tempdir().unwrap();
        let path = SelfProfile::path_in(dir.path());
        let profile = SelfProfile {
            human_name: Some("David Irvine".to_string()),
            display_name: Some("fae".to_string()),
            machine_name: Some("m5".to_string()),
        };
        profile.save_to(&path).await.unwrap();
        assert_eq!(SelfProfile::load_from(&path).await.unwrap(), Some(profile));
    }

    #[test]
    fn self_profile_merge_updates_only_present_fields() {
        // WHY: PUT /profile is partial — omitted fields must not clobber
        // stored names (a client setting only machine_name keeps the rest).
        let mut profile = SelfProfile {
            human_name: Some("David".to_string()),
            display_name: Some("fae".to_string()),
            machine_name: None,
        };
        let changed = profile.merge(&SelfProfile {
            human_name: None,
            display_name: None,
            machine_name: Some("m5".to_string()),
        });
        assert!(changed);
        assert_eq!(profile.human_name.as_deref(), Some("David"));
        assert_eq!(profile.display_name.as_deref(), Some("fae"));
        assert_eq!(profile.machine_name.as_deref(), Some("m5"));

        // Merging the same values again reports no change (callers use this
        // to skip re-announcing).
        assert!(!profile.merge(&SelfProfile {
            machine_name: Some("m5".to_string()),
            ..SelfProfile::default()
        }));
    }
}
