//! Owner singleton and self-profile persistence (ADR-0036).
//!
//! Two pieces of daemon-trusted naming state, deliberately kept apart:
//!
//! - [`crate::profile::OwnerProfile`] — WHO owns this install. Written by
//!   `x0x user-id create` next to the user key (`owner.json` in the key's
//!   directory, i.e. inside the instance data dir for named instances).
//!   One owner per install: `create` refuses to record a second, different
//!   `UserId` unless `--rotate-owner` is passed, and the daemon refuses to
//!   adopt a user key that does not match the recorded owner.
//! - [`crate::profile::SelfProfile`] — WHAT this install calls itself. The daemon-side
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

    /// Persist next to the user key. ATOMIC (review P1): temp file +
    /// rename, so a crash never leaves a truncated owner record — a torn
    /// `owner.json` would either disable enforcement (parse error is loud,
    /// but still an outage) or worse, read as a different owner.
    ///
    /// # Errors
    /// Returns the underlying IO error if the record cannot be written.
    pub async fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::other(format!("serialize owner profile: {e}")))?;
        write_atomically(path, &bytes).await
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

    /// Persist to `path` atomically (temp + rename), so a crash mid-write
    /// can never truncate the stored names.
    ///
    /// # Errors
    /// Returns the underlying IO error if the profile cannot be written.
    pub async fn save_to(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::other(format!("serialize self profile: {e}")))?;
        write_atomically(path, &bytes).await
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

    /// Apply a partial update. Field semantics (review P2):
    /// - `None` (field omitted or JSON `null`) — leave the stored name
    ///   untouched;
    /// - `Some("")` (EMPTY STRING) — explicitly CLEAR the stored name;
    /// - `Some(name)` — set/replace.
    ///
    /// Returns whether anything changed.
    #[must_use]
    pub fn merge(&mut self, update: &SelfProfile) -> bool {
        /// `Some("")` clears; otherwise replace.
        fn apply(slot: &mut Option<String>, v: &Option<String>) -> bool {
            match v {
                None => false,
                Some(v) if v.is_empty() => {
                    let changed = slot.is_some();
                    *slot = None;
                    changed
                }
                Some(v) => {
                    let changed = slot.as_ref() != Some(v);
                    *slot = Some(v.clone());
                    changed
                }
            }
        }
        let mut changed = false;
        changed |= apply(&mut self.human_name, &update.human_name);
        changed |= apply(&mut self.display_name, &update.display_name);
        changed |= apply(&mut self.machine_name, &update.machine_name);
        changed
    }

    /// Maximum accepted name length. Names reach the announce wire, agent
    /// cards, and API responses — a bounded, small cap keeps every consumer
    /// cheap and blocks storage/wire abuse via megabyte-scale "names".
    pub const MAX_NAME_LEN: usize = 128;

    /// Validate one name (review P2): 1..=MAX_NAME_LEN chars after
    /// trimming surrounding whitespace, no control characters. The empty
    /// string is NOT accepted here — it is the CLEAR sentinel handled by
    /// [`SelfProfile::merge`] and must not be stored.
    ///
    /// # Errors
    /// Returns a human-readable reason string.
    pub fn validate_name(field: &str, value: &str) -> std::result::Result<(), String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(format!("{field} must not be blank"));
        }
        if trimmed.len() > Self::MAX_NAME_LEN {
            return Err(format!(
                "{field} exceeds {} bytes (got {})",
                Self::MAX_NAME_LEN,
                trimmed.len()
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(format!("{field} must not contain control characters"));
        }
        Ok(())
    }
}

/// Write `bytes` to `path` via a unique temp file + rename (atomic on both
/// unix and windows for same-directory renames). The temp name embeds the
/// pid + a counter so concurrent writers never collide.
pub(crate) async fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "profile path has no file name",
        )
    })?;
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    tokio::fs::write(&tmp, bytes).await?;
    match tokio::fs::rename(&tmp, path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(e)
        }
    }
}

/// One line of the append-only owner certificate journal (ADR-0036,
/// review R2): the minimal issuance record — which agent the owner
/// certified, when, the certificate's digest, and its expiry. Written at
/// certificate-issue time and when an owner-bound certificate is first
/// observed via a verified announcement; read by `GET /owner/agents` as
/// the authoritative base roster (discovery only ENRICHES it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCertRecord {
    /// Hex-encoded `UserId` of the ISSUING owner (R3: records are
    /// owner-scoped — after `--rotate-owner` the previous owner's lines
    /// stay in the file as history but are EXCLUDED from the roster by the
    /// current-owner filter). Required, no default: journal lines from
    /// before this field existed fail to parse and are skipped by the
    /// tolerant loader (the journal ships in this same release).
    pub user_id: String,
    /// Hex-encoded certified agent id.
    pub agent_id: String,
    /// BLAKE3 (hex) of the certificate's storage bytes — identifies the
    /// exact issuance (renewals differ) and dedupes journal appends.
    pub cert_digest: String,
    /// Unix seconds when the certificate was issued.
    pub issued_at: u64,
    /// Certificate expiry (unix seconds); `None` = no expiry.
    pub not_after: Option<u64>,
    /// Hosting mode of the certified agent (ADR-0039). Defaults to `Acp`
    /// for pre-existing lines and the daemon's own self-issuance; rider
    /// mode is written by `POST /owner/agents/issue` only.
    #[serde(default)]
    pub mode: CertMode,
    /// Operator-assigned label for the certified agent (ADR-0039).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Base64 of the certificate's storage bytes. Retained ONLY for
    /// sub-agents issued via `POST /owner/agents/issue`: ADR-0018
    /// issuer-revocation (`DELETE /owner/agents/:id`) must re-present the
    /// exact certificate binding that owner to the agent, and no other
    /// durable copy of an offline sub-agent's certificate exists. The
    /// daemon's own self-issuance keeps the journal lean (`agent.cert` is
    /// the durable copy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_b64: Option<String>,
}

/// Hosting mode of a certified sub-agent (ADR-0039): an ACP-attached
/// harness instance running its own key file, or an API-key rider sending
/// through the owner's daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertMode {
    /// Harness-attached instance owning its key (also the mode of the
    /// daemon's own certificate and of pre-ADR-0039 journal lines).
    #[default]
    Acp,
    /// API-key rider: scoped token authenticates to the owner's daemon,
    /// which signs on the sub-agent's behalf with provenance marks.
    Rider,
}

/// File name of the owner certificate journal, in the instance data dir
/// (sibling of `agent.cert`).
pub const CERT_JOURNAL_FILE: &str = "owner-cert-journal.jsonl";

/// BLAKE3 hex digest of a certificate's storage bytes.
#[must_use]
pub fn cert_storage_digest(cert: &crate::identity::AgentCertificate) -> String {
    let bytes = cert.to_storage_bytes().unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

impl IssuedCertRecord {
    /// Build the record for a certificate about to be journaled, scoped to
    /// the issuing owner.
    #[must_use]
    pub fn from_cert(
        owner: &crate::identity::UserId,
        cert: &crate::identity::AgentCertificate,
    ) -> Option<Self> {
        let agent_id = cert.agent_id().ok()?;
        Some(Self {
            user_id: hex::encode(owner.as_bytes()),
            agent_id: hex::encode(agent_id.as_bytes()),
            cert_digest: cert_storage_digest(cert),
            issued_at: cert.issued_at(),
            not_after: cert.not_after(),
            mode: CertMode::Acp,
            label: None,
            cert_b64: None,
        })
    }

    /// Build a sub-agent issuance record (ADR-0039) scoped to the issuing
    /// owner, carrying the hosting `mode`, optional `label`, and the full
    /// certificate bytes (base64) so a later
    /// `DELETE /owner/agents/:id` can present the exact certificate the
    /// ADR-0018 issuer-revocation authority check requires.
    #[must_use]
    pub fn from_cert_with_mode(
        owner: &crate::identity::UserId,
        cert: &crate::identity::AgentCertificate,
        mode: CertMode,
        label: Option<String>,
    ) -> Option<Self> {
        let agent_id = cert.agent_id().ok()?;
        let cert_b64 = cert.to_storage_bytes().ok().map(|bytes| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(bytes)
        });
        Some(Self {
            user_id: hex::encode(owner.as_bytes()),
            agent_id: hex::encode(agent_id.as_bytes()),
            cert_digest: cert_storage_digest(cert),
            issued_at: cert.issued_at(),
            not_after: cert.not_after(),
            mode,
            label,
            cert_b64,
        })
    }

    /// Append one record as a JSONL line (creates the file on first write;
    /// append-only — renewals add lines, history is never rewritten).
    ///
    /// # Errors
    /// Returns the underlying IO error. Journal failures are non-fatal at
    /// the issuance call sites (warn + continue): a missing journal line
    /// degrades the roster to discovery-derived, it never blocks startup.
    pub async fn append(path: &Path, record: &Self) -> std::io::Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::other(format!("serialize journal record: {e}")))?;
        let tmp = path.with_file_name(format!(
            ".{}.{}.journal.tmp",
            path.file_name().map_or_else(
                || "journal".to_string(),
                |n| n.to_string_lossy().into_owned()
            ),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        // Append via read-modify-write under a temp+rename: JSONL appends
        // through File::open(append) are single-write atomic on practice,
        // but the temp+rename shape keeps the file NEVER partially written
        // even on weird filesystems.
        let mut content = tokio::fs::read(path).await.unwrap_or_default();
        content.extend_from_slice(line.as_bytes());
        content.push(b'\n');
        tokio::fs::write(&tmp, &content).await?;
        match tokio::fs::rename(&tmp, path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(e)
            }
        }
    }

    /// Load the journal; malformed lines are skipped (the journal is
    /// advisory-authoritative, and one corrupt line must not blank the
    /// roster).
    ///
    /// # Errors
    /// Returns the underlying IO error only when the file cannot be READ
    /// (a missing file is an empty journal).
    #[must_use]
    pub async fn load(path: &Path) -> Vec<Self> {
        match tokio::fs::read_to_string(path).await {
            Ok(text) => text
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
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
        // WHY: PUT /profile is partial — omitted/null fields must not
        // clobber stored names (a client setting only machine_name keeps
        // the rest), while an EMPTY STRING is the explicit clear.
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

        // Empty string clears; null/omitted never does.
        assert!(profile.merge(&SelfProfile {
            display_name: Some(String::new()),
            ..SelfProfile::default()
        }));
        assert_eq!(profile.display_name, None);
        assert_eq!(profile.human_name.as_deref(), Some("David"));
    }

    #[tokio::test]
    async fn cert_journal_appends_and_loads_tolerantly() {
        // WHY (review R2): the journal is the roster's authoritative base —
        // appends must persist verbatim, and one malformed line (partial
        // write on a foreign filesystem, manual edit) must never blank the
        // whole roster.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CERT_JOURNAL_FILE);
        let r1 = IssuedCertRecord {
            user_id: "07".repeat(32),
            agent_id: "ab".repeat(32),
            cert_digest: "cd".repeat(32),
            issued_at: 100,
            not_after: None,
            mode: CertMode::Acp,
            label: None,
            cert_b64: None,
        };
        let r2 = IssuedCertRecord {
            user_id: "07".repeat(32),
            agent_id: "ef".repeat(32),
            cert_digest: "12".repeat(32),
            issued_at: 200,
            not_after: Some(300),
            mode: CertMode::Rider,
            label: Some("ci-agent".into()),
            cert_b64: None,
        };
        IssuedCertRecord::append(&path, &r1).await.unwrap();
        IssuedCertRecord::append(&path, &r2).await.unwrap();
        assert_eq!(IssuedCertRecord::load(&path).await, vec![r1, r2]);

        // Malformed line is skipped, the rest survive.
        let mut text = tokio::fs::read_to_string(&path).await.unwrap();
        text.insert_str(0, "{not json}\n");
        tokio::fs::write(&path, text).await.unwrap();
        let loaded = IssuedCertRecord::load(&path).await;
        assert_eq!(loaded.len(), 2, "corrupt line skipped, records kept");
        assert_eq!(
            loaded[1].mode,
            CertMode::Rider,
            "ADR-0039 mode/label round-trip through the journal"
        );
        assert_eq!(loaded[1].label.as_deref(), Some("ci-agent"));
        // Pre-ADR-0039 lines (no mode/label/cert_b64 keys) parse as ACP defaults.
        let legacy_line = format!(
            "{{\"user_id\":\"{}\",\"agent_id\":\"{}\",\"cert_digest\":\"{}\",\"issued_at\":300,\"not_after\":null}}",
            "07".repeat(32),
            "ab".repeat(32),
            "cd".repeat(32)
        );
        let legacy: IssuedCertRecord = serde_json::from_str(&legacy_line).unwrap();
        assert_eq!(legacy.mode, CertMode::Acp);
        assert_eq!(legacy.label, None);
        assert_eq!(legacy.cert_b64, None);

        // Missing file is an empty journal, not an error.
        assert!(IssuedCertRecord::load(&dir.path().join("nope.jsonl"))
            .await
            .is_empty());
    }

    #[test]
    fn validate_name_rejects_blank_long_and_control_names() {
        // WHY (review P2): names persist to disk and propagate to the wire
        // and cards — blank, oversized, or control-character "names" are
        // garbage or abuse at every consumer.
        assert!(SelfProfile::validate_name("human_name", "David Irvine").is_ok());
        assert!(SelfProfile::validate_name("human_name", "  padded  ").is_ok());
        assert!(SelfProfile::validate_name("display_name", "").is_err());
        assert!(SelfProfile::validate_name("display_name", "   ").is_err());
        assert!(SelfProfile::validate_name(
            "machine_name",
            &"x".repeat(SelfProfile::MAX_NAME_LEN + 1)
        )
        .is_err());
        assert!(SelfProfile::validate_name("machine_name", "bad\u{0007}name").is_err());
    }
}
