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

use super::DaemonConfig;

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

/// Parse a daemon config and return every key the schema dropped, at any
/// depth, as dotted paths (e.g. `machine_key_path`, `gossip.machine_key_path`).
///
/// `DaemonConfig` deliberately carries no `deny_unknown_fields` (rejecting
/// would brick a drifted live config on upgrade — 0.35.1 ruling), so without
/// this the only evidence of a misspelt or non-existent key is the daemon
/// quietly using a default. Issue #385: `.deployment/deploy-443.sh` wrote
/// `machine_key_path`, a field that has never existed, and every bootstrap
/// host's `:443` daemon fell back to the prod daemon's `~/.x0x` keys — two
/// transports advertising one identity, unnoticed for months.
///
/// # Errors
/// Returns the TOML/serde error when the document does not parse into
/// `DaemonConfig` at all.
pub fn parse_with_ignored_keys(
    content: &str,
) -> Result<(DaemonConfig, Vec<String>), toml::de::Error> {
    let mut ignored = Vec::new();
    let config: DaemonConfig =
        serde_ignored::deserialize(toml::Deserializer::new(content), |path| {
            ignored.push(path.to_string());
        })?;
    Ok((config, ignored))
}

/// Emit a `tracing::warn!` per ignored key from [`parse_with_ignored_keys`].
pub fn warn_ignored_keys(ignored: &[String]) {
    for key in ignored {
        tracing::warn!(
            "config key `{key}` is not a recognised setting and is ignored — \
             check its name and section against `DaemonConfig` (src/server/state.rs)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(src: &str) -> toml::Table {
        toml::from_str(src).expect("test fixture must parse")
    }

    #[test]
    fn ignored_keys_are_reported_with_their_path() {
        // Issue #385: `machine_key_path` is not a field at any level. Both the
        // top-level and the `[gossip]`-scoped form (what the live :443 configs
        // actually carried) must be named, so the operator learns the key did
        // nothing rather than the daemon quietly using `~/.x0x`.
        let src = "bind_address = '[::]:443'
machine_key_path = '/var/lib/x0x-443/machine.key'

[gossip]
machine_key_path = '/x'
";
        let (config, ignored) = parse_with_ignored_keys(src).expect("parses");
        assert_eq!(config.bind_address.port(), 443);
        assert_eq!(
            ignored,
            vec![
                "machine_key_path".to_string(),
                "gossip.machine_key_path".to_string()
            ],
            "every dropped key must be reported with its dotted path"
        );
    }

    #[test]
    fn recognised_keys_are_not_reported() {
        let src = "bind_address = '[::]:443'
identity_dir = '/var/lib/x0x-443/identity'

[update]
enabled = false
";
        let (config, ignored) = parse_with_ignored_keys(src).expect("parses");
        assert_eq!(
            config.identity_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/x0x-443/identity"))
        );
        assert!(ignored.is_empty(), "got spurious ignored keys: {ignored:?}");
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
