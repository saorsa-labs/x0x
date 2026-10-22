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
    "mdns_enabled",
    "network_id",
    "observed_prefix_enabled",
    "port_mapping_enabled",
    "presence_beacon_interval_secs",
    "presence_event_poll_interval_secs",
    "presence_offline_timeout_secs",
    "rendezvous_enabled",
    "rendezvous_validity_ms",
    "skip_legacy_dm_bus",
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

/// Root keys that choose which gossip plane a daemon joins, or whether it
/// discovers LAN peers (N7, charter I13). Unlike every other key, dropping one
/// of these does not merely fall back to a default: an unset `network_id`
/// joins the well-known prod plane (`PROD_PLANE_ID`), so a testnet daemon
/// whose `network_id` sits under `[gossip]` silently joins prod. That is how
/// the testnet ran on `x0x.prod`. A plane key anywhere but the top level is
/// therefore fatal at startup and in `--check`, not warn-only.
pub const PLANE_KEYS: &[&str] = &["network_id", "mdns_enabled"];

/// Everything the loader found wrong with a daemon config (N7).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigFindings {
    /// Plane keys found below the top level, as dotted paths
    /// (e.g. `gossip.network_id`). Non-empty means refuse to start.
    pub misplaced_plane_keys: Vec<String>,
    /// Every other key the schema dropped, as dotted paths (#385).
    pub ignored_keys: Vec<String>,
    /// Root-owned keys placed under a sub-section (0.35.1 cleanup).
    pub misplacements: Vec<SectionMisplacement>,
}

impl ConfigFindings {
    /// Whether nothing at all was found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.misplaced_plane_keys.is_empty()
            && self.ignored_keys.is_empty()
            && self.misplacements.is_empty()
    }

    /// The fatal error for misplaced plane keys, or `None` when there are none.
    #[must_use]
    pub fn plane_error(&self) -> Option<String> {
        if self.misplaced_plane_keys.is_empty() {
            return None;
        }
        Some(format!(
            "refusing to start: plane-isolation key(s) {} are not at the top level of the \
             config, so they would be ignored and this daemon would join the default plane \
             `{}`. Move `network_id` / `mdns_enabled` above the first `[section]` header.",
            self.misplaced_plane_keys
                .iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(", "),
            super::state::PROD_PLANE_ID
        ))
    }

    /// Human-readable lines for the non-fatal findings, in a stable order.
    #[must_use]
    pub fn warning_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self.misplacements.iter().map(|m| m.message()).collect();
        for key in &self.ignored_keys {
            let reported = self
                .misplacements
                .iter()
                .any(|m| *key == format!("{}.{}", m.found_under, m.key));
            if reported {
                continue;
            }
            lines.push(format!(
                "config key `{key}` is not a recognised setting and is ignored — \
                 check its name and section against `DaemonConfig` (src/server/state.rs)"
            ));
        }
        lines
    }
}

/// Parse a daemon config and classify everything it drops (N7).
///
/// # Errors
/// Returns the TOML/serde error when the document does not parse into
/// `DaemonConfig` at all.
pub fn analyze(content: &str) -> Result<(DaemonConfig, ConfigFindings), toml::de::Error> {
    let (config, ignored) = parse_with_ignored_keys(content)?;
    let root = toml::from_str::<toml::Table>(content).unwrap_or_default();
    // Scan the raw document, not serde's ignored list: serde reports an
    // unknown table only by its own path (`gossip_typo`), never the keys
    // inside it, so a plane key under an unknown or misspelt section would
    // otherwise go unseen.
    let mut misplaced_plane_keys = Vec::new();
    for (section, value) in &root {
        // A root-level scalar is where a plane key belongs; only nested
        // tables and arrays (of tables, at any depth) can hide one.
        if value.is_table() || value.is_array() {
            collect_plane_keys(section, value, &mut misplaced_plane_keys);
        }
    }
    // serde reports an ignored enclosing table or array by its own path;
    // drop it when a plane key inside it is already fatal, so the operator
    // sees one message per problem.
    let is_plane_path = |path: &String| {
        misplaced_plane_keys.iter().any(|plane: &String| {
            path == plane
                || plane.starts_with(&format!("{path}."))
                || plane.starts_with(&format!("{path}["))
        })
    };
    let ignored_keys = ignored
        .into_iter()
        .filter(|path| !is_plane_path(path))
        .collect();
    let misplacements = diagnose_section_placement(&root)
        .into_iter()
        .filter(|m| !PLANE_KEYS.contains(&m.key.as_str()))
        .collect();
    Ok((
        config,
        ConfigFindings {
            misplaced_plane_keys,
            ignored_keys,
            misplacements,
        },
    ))
}

/// Append the dotted path of every plane key inside `value`, recursing
/// through tables and arrays (including arrays of tables, `[[section]]`, and
/// inline arrays) at any depth. Array elements are addressed as `path[i]`.
fn collect_plane_keys(prefix: &str, value: &toml::Value, out: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                let path = format!("{prefix}.{key}");
                if PLANE_KEYS.contains(&key.as_str()) {
                    out.push(path);
                } else {
                    collect_plane_keys(&path, child, out);
                }
            }
        }
        toml::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_plane_keys(&format!("{prefix}[{index}]"), item, out);
            }
        }
        _ => {}
    }
}

/// Whether startup must refuse a named instance.
///
/// A loaded config file with no top-level `network_id` would join prod
/// without saying so. No config file is allowed: unset means prod. Stop
/// must not create a file that turns this allowance into a refusal.
#[must_use]
pub fn named_instance_refuses_startup(config_file_loaded: bool, network_id: Option<&str>) -> bool {
    config_file_loaded && network_id.is_none()
}

/// The startup error for a named instance (`--name`) whose config file sets no
/// top-level `network_id` (David, 2026-09-29): it would silently join prod.
#[must_use]
pub fn named_instance_missing_network_id(instance: &str) -> String {
    format!(
        "named instance '{instance}' has no network_id; set network_id = \"x0x.testnet\" \
         (or another plane, e.g. \"{plane}\" for prod) at the top level of its config \
         file, or omit --name for the prod plane",
        plane = super::state::PROD_PLANE_ID
    )
}

/// The warning for a named instance (`--name`) running WITHOUT a config file,
/// which therefore joins the prod plane (N7). Warn-only: `install.sh --name`
/// and `x0x daemon start --name` write no config file, and a named instance
/// with a file but no `network_id` is refused at startup instead.
#[must_use]
pub fn named_instance_plane_warning(instance: &str, network_id: Option<&str>) -> Option<String> {
    if network_id.is_some() {
        return None;
    }
    Some(format!(
        "named instance `{instance}` sets no top-level `network_id`, so it joins the prod \
         plane `{plane}`. If that is intended, set `network_id = \"{plane}\"` to say so; for \
         a test or private plane, set its id at the top level of the config.",
        plane = super::state::PROD_PLANE_ID
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plane_key_under_a_section_is_fatal_at_any_depth() {
        // N7: exactly the testnet-on-prod shape, plus a deeper table.
        let src = "bind_address = '127.0.0.1:6483'
[gossip]
network_id = 'x0x.testnet'
[forward.extra]
mdns_enabled = false
";
        let (config, findings) = analyze(src).expect("parses");
        assert_eq!(config.network_id, None, "the nested key really was ignored");
        assert_eq!(
            findings.misplaced_plane_keys,
            vec![
                "forward.extra.mdns_enabled".to_string(),
                "gossip.network_id".to_string()
            ]
        );
        let err = findings.plane_error().expect("fatal");
        assert!(err.contains("`gossip.network_id`") && err.contains("x0x.prod"));
        assert!(
            !findings
                .warning_lines()
                .iter()
                .any(|l| l.contains("network_id") || l.contains("mdns_enabled")),
            "a fatal plane key is not also reported as a mere warning"
        );
    }

    #[test]
    fn plane_key_under_an_unknown_section_is_fatal() {
        // serde reports only `testnet` as ignored here, never its contents.
        let src = "[testnet]
network_id = 'x0x.testnet'
";
        let (_, findings) = analyze(src).expect("parses");
        assert_eq!(
            findings.misplaced_plane_keys,
            vec!["testnet.network_id".to_string()]
        );
        assert!(findings.plane_error().is_some());
        assert!(
            findings.warning_lines().is_empty(),
            "the enclosing unknown table is not double-reported: {:?}",
            findings.warning_lines()
        );
    }

    #[test]
    fn plane_key_inside_arrays_is_fatal() {
        // Codex #1063 r1 P1: an array of tables, an inline array and a
        // nested array all hid plane keys from a tables-only walk.
        let src = "[[testnet]]
network_id = 'x0x.testnet'

[gossip]
extra = [{ mdns_enabled = false }]
deep = [[{ network_id = 'x' }]]
";
        let (_, findings) = analyze(src).expect("parses");
        assert_eq!(
            findings.misplaced_plane_keys,
            vec![
                "gossip.deep[0][0].network_id".to_string(),
                "gossip.extra[0].mdns_enabled".to_string(),
                "testnet[0].network_id".to_string(),
            ]
        );
        assert!(findings.plane_error().is_some());
        assert!(
            findings.warning_lines().is_empty(),
            "enclosing ignored arrays are not double-reported: {:?}",
            findings.warning_lines()
        );
    }

    #[test]
    fn top_level_plane_keys_are_accepted() {
        let src = "network_id = 'x0x.testnet'
mdns_enabled = false
[gossip]
";
        let (config, findings) = analyze(src).expect("parses");
        assert_eq!(config.network_id.as_deref(), Some("x0x.testnet"));
        assert!(findings.is_clean());
        assert_eq!(findings.plane_error(), None);
    }

    #[test]
    fn other_dropped_keys_warn_but_are_not_fatal() {
        // Live prod configs carry `zero_peer_restart_secs` under [gossip]
        // (N7 inventory, 10 of 12 prod files): fatal here would stop prod
        // from starting after a self-update.
        let src = "bogus_key = 1
[gossip]
zero_peer_restart_secs = 300
";
        let (_, findings) = analyze(src).expect("parses");
        assert_eq!(findings.plane_error(), None);
        assert!(!findings.is_clean());
        let lines = findings.warning_lines();
        assert!(lines.iter().any(|l| l.contains("bogus_key")));
        assert!(lines.iter().any(|l| l.contains("zero_peer_restart_secs")));
    }

    #[test]
    fn named_instance_without_network_id_is_warned() {
        let warning = named_instance_plane_warning("alice", None).expect("warned");
        assert!(warning.contains("`alice`") && warning.contains("x0x.prod"));
        assert_eq!(
            named_instance_plane_warning("alice", Some("x0x.testnet")),
            None
        );
        assert_eq!(
            named_instance_plane_warning("alice", Some("x0x.prod")),
            None
        );
    }

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
    fn skip_legacy_dm_bus_is_a_recognised_root_key() {
        let (default_config, default_ignored) =
            parse_with_ignored_keys("").expect("empty config parses");
        assert!(!default_config.skip_legacy_dm_bus);
        assert!(default_ignored.is_empty());

        let (config, ignored) =
            parse_with_ignored_keys("skip_legacy_dm_bus = true\n").expect("parses");
        assert!(config.skip_legacy_dm_bus);
        assert!(ignored.is_empty(), "got spurious ignored keys: {ignored:?}");

        let findings = diagnose_section_placement(&root("[gossip]\nskip_legacy_dm_bus = true\n"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].key, "skip_legacy_dm_bus");
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
