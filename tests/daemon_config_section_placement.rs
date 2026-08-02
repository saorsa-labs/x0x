//! Wrong-section TOML placement integration test (ADR-0027 §3 daemon hardening (b)).
//!
//! # Contract
//!
//! The merged daemon hardening (b) requires a **loud startup warn** (not
//! reject) when a known top-level key appears under the wrong TOML section.
//! Rejecting is a later minor with notice — the 0.35.1 rule is "loud warn
//! and continue" so a drifted live config does not brick an upgrade. The
//! daemon loader therefore:
//!
//! - Parses the config into a `toml::Table`.
//! - Calls `x0x::server::config::diagnose_section_placement` to find
//!   root-owned keys that landed under a sub-section where serde drops
//!   them silently.
//! - Calls `x0x::server::config::warn_section_misplacements` to emit a
//!   `tracing::warn!` per finding, naming the key, the wrong section,
//!   and the expected section.
//!
//! # What this test covers
//!
//! Two angles the unit suite in `src/server/config.rs:tests` does not:
//!
//! - The integration diagnostic pipeline on a TOML that exercises both
//!   single- and multi-misplacement paths in one fixture, asserting on
//!   `SectionMisplacement` fields and the exact `.message()` text the
//!   loader forwards verbatim.
//! - The end-to-end warn pipeline: a thread-local WARN-level fmt
//!   subscriber captures the operator-visible output and confirms each
//!   finding produces its own warn line. This is the path an operator
//!   sees in the daemon startup log.
//!
//! # Run
//!
//! Default test run. The five-test unit suite lives in
//! `src/server/config.rs`; this file is the integration complement. No
//! daemon is spawned — the cluster harness lives in
//! `tests/active_recipient_sealing_gates.rs`.

use std::sync::{Arc, Mutex};

use x0x::server::config::{
    diagnose_section_placement, warn_section_misplacements, SectionMisplacement,
};

/// Build a daemon config that mis-places both `data_dir` and `log_level`
/// under `[history]` (both are root-owned keys) while keeping
/// `bind_address` correctly at the top level. The fixture proves
/// diagnostic-vs-valid discrimination: the valid `[history]` fields
/// (`enabled`, `db_path`) are not flagged, the correctly-rooted
/// `data_dir` and `bind_address` are not flagged, and the two misplaced
/// keys surface in sorted order.
fn two_misplacements_with_valid_root() -> String {
    r#"
data_dir = "/var/lib/x0x"
bind_address = "0.0.0.0:0"

[history]
enabled = true
db_path = "/var/lib/x0x/history.db"
data_dir = "/var/lib/x0x"
log_level = "debug"
"#
    .to_string()
}

/// Diagnostic pipeline — parse a TOML with two misplaced root keys and
/// the valid `[history]` fields mixed in. Assert
/// `diagnose_section_placement` returns exactly the two misplaced keys
/// (no false positives on the valid `[history]` fields, no false
/// positives on the correctly-rooted `data_dir`/`bind_address`), in
/// sorted order. Assert every `.message()` names the key, the wrong
/// section, and the expected section so the operator-visible text stays
/// in lockstep with the structured finding.
#[test]
fn diagnose_section_placement_finds_data_dir_and_log_level_under_history() {
    let parsed: toml::Table =
        toml::from_str(&two_misplacements_with_valid_root()).expect("fixture parses");
    let findings = diagnose_section_placement(&parsed);

    assert_eq!(
        findings.len(),
        2,
        "expected exactly two findings, got: {findings:#?}"
    );

    let expected = vec![
        SectionMisplacement {
            key: "data_dir".to_string(),
            found_under: "history".to_string(),
            expected_section: "top level".to_string(),
        },
        SectionMisplacement {
            key: "log_level".to_string(),
            found_under: "history".to_string(),
            expected_section: "top level".to_string(),
        },
    ];
    assert_eq!(
        findings, expected,
        "findings sorted by (section, key); valid [history] fields are not flagged"
    );

    for (i, finding) in findings.iter().enumerate() {
        let msg = finding.message();
        assert!(
            msg.contains(&finding.key),
            "finding #{i} message must name the key `{key}`: {msg}",
            key = finding.key,
        );
        assert!(
            msg.contains(&format!("[{}]", finding.found_under)),
            "finding #{i} message must name the wrong section `[{}]`: {msg}",
            finding.found_under,
        );
        assert!(
            msg.contains(&finding.expected_section),
            "finding #{i} message must name the expected section `{}`: {msg}",
            finding.expected_section,
        );
        assert!(
            msg.contains("Move it to the top level"),
            "finding #{i} message must include the operator remediation hint: {msg}",
        );
    }
}

/// Warn pipeline — install a thread-local WARN-level fmt subscriber
/// writing into an in-memory buffer, run the same fixture through
/// `diagnose_section_placement`, call `warn_section_misplacements`, and
/// assert every finding renders as its own warn line naming the key, the
/// wrong section, and the expected section. This is the exact path the
/// daemon loader takes on startup, minus the `x0xd` process boundary.
#[test]
fn warn_section_misplacements_emits_one_warn_per_finding() {
    let (capture, _guard) = capture_warn_logs();
    let parsed: toml::Table =
        toml::from_str(&two_misplacements_with_valid_root()).expect("fixture parses");
    let findings = diagnose_section_placement(&parsed);
    assert_eq!(
        findings.len(),
        2,
        "fixture must produce two findings for the warn count assertion"
    );

    warn_section_misplacements(&findings);

    let body = capture.text();
    assert!(
        body.to_lowercase().contains("warn"),
        "captured event must be at WARN level: {body}"
    );
    assert!(
        body.contains("data_dir"),
        "warn output must name the misplaced key data_dir: {body}"
    );
    assert!(
        body.contains("log_level"),
        "warn output must name the second misplaced key log_level: {body}"
    );
    assert!(
        body.contains("[history]"),
        "warn output must name the wrong section [history]: {body}"
    );
    assert!(
        body.contains("top level"),
        "warn output must name the expected section: {body}"
    );

    // Two findings, two distinct warn lines. The loader's `tracing::warn!`
    // passes each `.message()` as the event message, and the fmt layer
    // prefixes it; we anchor on the stable fragment "config key" that
    // every finding's message starts with.
    let warn_count = body.matches("config key").count();
    assert_eq!(
        warn_count, 2,
        "expected exactly two `config key` warn lines (one per finding): {body}"
    );
}

/// Clean fixture — a TOML with the correct section placement for every
/// key (no root-owned keys under any sub-section) produces an empty
/// findings vec, and `warn_section_misplacements` on that vec emits
/// zero warn lines. This pins the "loud only when there is drift" half
/// of the (b) contract.
#[test]
fn clean_config_produces_no_warnings() {
    let clean = r#"
data_dir = "/var/lib/x0x"
bind_address = "0.0.0.0:0"

[history]
enabled = true
db_path = "/var/lib/x0x/history.db"
"#;
    let parsed: toml::Table = toml::from_str(clean).expect("clean fixture parses");
    let findings = diagnose_section_placement(&parsed);
    assert!(
        findings.is_empty(),
        "clean config must produce no findings: {findings:#?}"
    );

    let (capture, _guard) = capture_warn_logs();
    warn_section_misplacements(&findings);
    let body = capture.text();
    assert!(
        body.is_empty(),
        "warn_section_misplacements on empty findings must emit nothing: {body:?}"
    );
}

// ─── tracing capture helpers (lifted from src/forward.rs pattern) ───────────

/// In-memory sink for the fmt subscriber. Cloneable so the subscriber
/// closure can hold its own handle while the test holds another.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut v) = self.0.lock() {
            v.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    /// Captured bytes as lossy UTF-8 text.
    fn text(&self) -> String {
        self.0
            .lock()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    }
}

/// Install a thread-local WARN-level fmt subscriber writing into a
/// [`LogCapture`]. The guard is thread-scoped; `#[test]` runs each test
/// on its own thread by default, so events from one test never bleed
/// into another.
fn capture_warn_logs() -> (LogCapture, tracing::subscriber::DefaultGuard) {
    let capture = LogCapture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (capture, guard)
}
