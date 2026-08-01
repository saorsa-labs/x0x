//! Daemon TOML section-placement diagnosis (x0x cleanup, item (b)).
//!
//! `DaemonConfig` deserializes from TOML *without* `deny_unknown_fields`, so a
//! key an operator places under the wrong section (e.g. `data_dir` under
//! `[history]`, where it is silently dropped because `[history]` owns
//! `db_path`, not `data_dir`) is accepted without error and without effect.
//! The operator's intent is lost without a trace and the daemon runs on the
//! derived default.
//!
//! Per the 0.35.1 cleanup ruling we **warn loudly and continue** — we do not
//! reject, because rejecting could brick a drifted live config on upgrade.
//! Rejection is a later minor with notice. This module detects the misplaced
//! keys and emits a structured [`SectionMisplacement`] so callers (the daemon
//! loader) and tests share one source of truth for both the finding and the
//! message format.
//!
//! The detection scans every TOML sub-table for keys owned by the root
//! (`DaemonConfig`). The registry below is the complete set of root scalar
//! fields at this commit; none of them collides with a field of any known
//! sub-section (`[history]`, `[gossip]`, `[update]`, `[peer_relay]`,
//! `[forward]`), so the scan produces no false positives. Adding a new root
//! scalar without registering it here degrades gracefully: that key simply
//! would not be diagnosed if misplaced — it never causes a spurious warning.

/// The TOML section a root-owned key belongs to (always the file root).
const ROOT_SECTION: &str = "top level";

/// Keys owned by the root `[DaemonConfig]` table, i.e. the complete set of
/// root *scalar* fields. Landing any of these under a sub-section is a
/// silent misconfiguration: serde drops the unknown field and the daemon
/// uses the derived default. Sorted alphabetically for stable test output.
///
/// Sub-tables (`history`, `gossip`, `update`, `peer_relay`, `forward`) are
/// intentionally excluded — a key valid *for a section* is not a misplacement.
const ROOT_OWNED_KEYS: &[&str] = &[
    "api_address",
    "bind_address",
    "bootstrap_peers",
    "data_dir",
    "directory_digest_interval_secs",
    "directory_resubscribe_jitter_ms",
    "group_card_republish_interval_secs",
    "heartbeat_interval_secs",
    "identity_dir",
    "identity_ttl_secs",
    "instance_name",
    "log_format",
    "log_level",
    "network_id",
    "observed_prefix_enabled",
    "port_mapping_enabled",
    "presence_beacon_interval_secs",
    "presence_event_poll_interval_secs",
    "presence_offline_timeout_secs",
    "rendezvous_enabled",
    "rendezvous_validity_ms",
    "user_key_path",
    "zero_peer_restart_secs",
];

/// A root-owned key found under a sub-section where serde ignores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionMisplacement {
    /// The misplaced key (e.g. `data_dir`).
    pub key: String,
    /// The section it was found under (e.g. `history`).
    pub found_under: String,
    /// Where it actually belongs — always `ROOT_SECTION` today.
    pub expected_section: String,
}

impl SectionMisplacement {
    /// Human-readable warning text naming the key, the wrong section, and the
    /// expected section. The daemon loader emits this verbatim via
    /// `tracing::warn!`; tests assert on its contents so the warn message and
    /// the finding stay in lockstep.
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "config key `{}` is set under section `[{}]` but belongs at `{}`; it is ignored there. \
             Move it to the top level of the config file.",
            self.key, self.found_under, self.expected_section
        )
    }
}

/// Scan `root` for root-owned keys misplaced under a sub-section.
///
/// Returns one [`SectionMisplacement`] per (section, key) hit, sorted by
/// section then key for deterministic output. An empty vec means no known
/// misplacement was found. Unknown sub-sections and unknown root-level keys
/// are not reported here — only the documented defect class (a root-owned key
/// silently dropped under a section).
#[must_use]
pub fn diagnose_section_placement(root: &toml::Table) -> Vec<SectionMisplacement> {
    let mut found = Vec::new();
    for (section, value) in root.iter() {
        // Only a sub-table can swallow a misplaced key; a root scalar/array is
        // already at the root by construction.
        let Some(sub) = value.as_table() else {
            continue;
        };
        for &key in ROOT_OWNED_KEYS {
            if sub.contains_key(key) {
                found.push(SectionMisplacement {
                    key: key.to_string(),
                    found_under: section.clone(),
                    expected_section: ROOT_SECTION.to_string(),
                });
            }
        }
    }
    found.sort_by(|a, b| {
        a.found_under
            .cmp(&b.found_under)
            .then_with(|| a.key.cmp(&b.key))
    });
    found
}

/// Emit a `tracing::warn!` for each finding. Called by the daemon loader after
/// parsing; the warnings appear in the startup log so an operator sees the
/// drift before it bites.
pub fn warn_section_misplacements(findings: &[SectionMisplacement]) {
    for finding in findings {
        tracing::warn!("{}", finding.message());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(src: &str) -> toml::Table {
        toml::from_str(src).expect("test fixture must parse")
    }

    #[test]
    fn clean_config_has_no_misplacements() {
        let t = root(
            "data_dir = \"/var/lib/x0x\"\n\
             bind_address = \"0.0.0.0:0\"\n\
             [history]\n\
             enabled = true\n\
             db_path = \"/var/lib/x0x/history.db\"\n",
        );
        assert!(diagnose_section_placement(&t).is_empty());
    }

    #[test]
    fn data_dir_under_history_is_flagged() {
        let t = root("[history]\ndata_dir = \"/var/lib/x0x\"\nenabled = true\n");
        let findings = diagnose_section_placement(&t);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0],
            SectionMisplacement {
                key: "data_dir".to_string(),
                found_under: "history".to_string(),
                expected_section: "top level".to_string(),
            }
        );
        let msg = findings[0].message();
        assert!(msg.contains("data_dir"), "message names the key: {msg}");
        assert!(
            msg.contains("[history]"),
            "message names the wrong section: {msg}"
        );
        assert!(
            msg.contains("top level"),
            "message names the expected section: {msg}"
        );
    }

    #[test]
    fn multiple_misplacements_are_sorted_and_complete() {
        // `data_dir` and `log_level` both misplaced under [history]; `bind_address`
        // correctly at root must NOT appear.
        let t = root(
            "bind_address = \"0.0.0.0:0\"\n\
             [history]\n\
             data_dir = \"/x\"\n\
             log_level = \"debug\"\n",
        );
        let findings = diagnose_section_placement(&t);
        let keys: Vec<&str> = findings.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(keys, vec!["data_dir", "log_level"], "sorted, both flagged");
        // The root-level bind_address is not a misplacement.
        assert!(
            !findings.iter().any(|f| f.key == "bind_address"),
            "root-level keys are not flagged"
        );
    }

    #[test]
    fn unknown_section_still_flags_root_key() {
        // A typo'd section is also a misplacement for a root-owned key.
        let t = root("[gossip_typo]\napi_address = \"127.0.0.1:12700\"\n");
        let findings = diagnose_section_placement(&t);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].key, "api_address");
        assert_eq!(findings[0].found_under, "gossip_typo");
    }

    #[test]
    fn valid_section_key_is_not_flagged() {
        // `enabled` is a valid [history] field, not a root key — never flagged.
        let t = root("[history]\nenabled = false\n");
        assert!(diagnose_section_placement(&t).is_empty());
    }
}
