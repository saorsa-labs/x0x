//! `POST /report` (#1354 slices 2 and 3): build a redacted problem-report
//! bundle, store it in the daemon's data directory and, when the caller
//! names one of the owner's devices with `deliver_to`, queue a smaller
//! sent copy to that device on the durable direct-send outbox (#1109).
//!
//! The stored bundle is local: the route writes one JSON file under
//! `<data_dir>/reports/` and answers with its path and size. The sent copy
//! ([`build_sent_report`]) leaves out the two sections whose redaction is
//! not complete (the log tail and the data-directory names), so nothing
//! the redactor keeps leaves the machine. It travels as the payload of an
//! ordinary durable direct message: the outbox retries it while the
//! device is offline, up to the outbox's 24-hour deadline. Nothing is
//! sent to the maintainers.
//!
//! Redaction is the core rule. The bundle is built from an allow-list of
//! sections (generator, host, short identity prefixes, the redacted
//! `/health` body, a name-and-size listing of the data directory, and a
//! bounded log tail). No file content other than the log tail is read.
//! Every string in the bundle then passes through [`Redactor`], which
//! removes the API token, contact labels, home and data-directory paths,
//! the user name, quoted log values, long hex runs (cut to an 8-character
//! prefix) and long base64-like runs.
//!
//! Every read is bounded ([`LOG_TAIL_READ_BYTES`], [`MAX_INVENTORY_ENTRIES`])
//! and the serialized bundle never exceeds [`MAX_BUNDLE_BYTES`].

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::rider_auth::ActorContext;
use super::state::AppState;

/// Schema name written into every report bundle.
pub(crate) const REPORT_SCHEMA: &str = "x0x-report-bundle";
/// Directory under the data directory that holds report bundles.
pub(crate) const REPORTS_DIR: &str = "reports";
/// The serialized bundle never exceeds this many bytes.
pub(crate) const MAX_BUNDLE_BYTES: usize = 256 * 1024;
/// At most this many bytes are read from the end of the log file.
pub(crate) const LOG_TAIL_READ_BYTES: u64 = 128 * 1024;
/// At most this many log lines go into the bundle.
pub(crate) const MAX_LOG_LINES: usize = 200;
/// Each log line is cut to this many characters after redaction.
pub(crate) const MAX_LOG_LINE_CHARS: usize = 400;
/// At most this many data-directory entries are listed.
pub(crate) const MAX_INVENTORY_ENTRIES: usize = 128;
/// At most this many directory entries are examined to pick the listing.
const MAX_INVENTORY_SCAN: usize = 1024;
/// The route keeps the newest this many bundles and deletes older ones.
pub(crate) const MAX_STORED_REPORTS: usize = 10;
/// One report per data directory in this window.
pub(crate) const REPORT_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Hex runs at least this long are cut to a prefix.
const HEX_RUN_MIN: usize = 16;
/// Characters of a long hex run that stay visible.
const HEX_PREFIX_CHARS: usize = 8;
/// Base64-like runs at least this long are removed.
const B64_RUN_MIN: usize = 32;
/// Known secrets shorter than this are not used as match strings: a very
/// short string would wreck unrelated text and protects nothing.
const MIN_SECRET_CHARS: usize = 3;
/// The API token file is read up to this many bytes.
const API_TOKEN_READ_BYTES: u64 = 4096;
/// The sent copy of a bundle never exceeds this many bytes. It is below
/// the DM payload limit ([`crate::dm::MAX_PAYLOAD_BYTES`], 48 KiB).
pub(crate) const MAX_SENT_REPORT_BYTES: usize = 32 * 1024;
/// Prefix of the `logical_id` a sent report is queued under; the creation
/// second follows it.
pub(crate) const REPORT_LOGICAL_ID_PREFIX: &str = "x0x-report-";
/// Sections the sent copy leaves out: they stay on this machine.
pub(crate) const SENT_REPORT_WITHHELD: [&str; 2] = ["data_dir", "log_tail"];

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Text scrubber for every string that goes into a bundle.
#[derive(Debug, Clone, Default)]
pub(crate) struct Redactor {
    /// Exact strings to remove (API token, contact labels), longest first.
    secrets: Vec<String>,
    /// Path prefixes to replace, longest first, with their placeholder.
    paths: Vec<(String, &'static str)>,
    /// The local user name, removed wherever it appears.
    user_name: Option<String>,
    /// `false` only in the red-proof test: the scrubber passes text
    /// through unchanged so the test can show it detects leaks.
    #[cfg(test)]
    disabled: bool,
}

impl Redactor {
    /// A scrubber for the given secrets, paths and user name.
    pub(crate) fn new(
        secrets: impl IntoIterator<Item = String>,
        data_dir: Option<&Path>,
        home_dir: Option<&Path>,
        user_name: Option<String>,
    ) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| s.chars().count() >= MIN_SECRET_CHARS)
            .collect();
        // Longest first, so a secret that contains another is removed whole.
        secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        let mut paths = Vec::new();
        if let Some(dir) = data_dir {
            push_path_forms(&mut paths, dir, "<x0x-data>");
        }
        if let Some(dir) = home_dir {
            push_path_forms(&mut paths, dir, "~");
        }
        paths.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        let user_name = user_name
            .map(|u| u.trim().to_string())
            .filter(|u| u.chars().count() >= MIN_SECRET_CHARS);
        Self {
            secrets,
            paths,
            user_name,
            #[cfg(test)]
            disabled: false,
        }
    }

    /// Red-proof switch for tests: turn every scrubbing step off.
    #[cfg(test)]
    pub(crate) fn disabled_for_red_proof(mut self) -> Self {
        self.disabled = true;
        self
    }

    #[cfg(test)]
    fn is_disabled(&self) -> bool {
        self.disabled
    }

    #[cfg(not(test))]
    fn is_disabled(&self) -> bool {
        false
    }

    /// Scrub one string: known secrets, paths, the user name, then long
    /// hex and base64-like runs.
    pub(crate) fn scrub(&self, text: &str) -> String {
        if self.is_disabled() {
            return text.to_string();
        }
        let mut out = text.to_string();
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), "[redacted]");
            }
        }
        for (path, placeholder) in &self.paths {
            if out.contains(path.as_str()) {
                out = out.replace(path.as_str(), placeholder);
            }
        }
        out = scrub_user_dirs(&out);
        if let Some(user) = &self.user_name {
            if out.contains(user.as_str()) {
                out = out.replace(user.as_str(), "<user>");
            }
        }
        scrub_runs(&out)
    }

    /// Scrub one log line: quoted values first (they carry message,
    /// payload and name text), then the general [`Redactor::scrub`].
    /// A JSON log line keeps only its timestamp, level, target and message.
    pub(crate) fn scrub_log_line(&self, line: &str) -> String {
        if self.is_disabled() {
            return line.to_string();
        }
        let trimmed = line.trim();
        let reduced = if trimmed.starts_with('{') {
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(value) => json_log_summary(&value),
                Err(_) => redact_quoted(trimmed),
            }
        } else {
            redact_quoted(trimmed)
        };
        truncate_chars(&self.scrub(&reduced), MAX_LOG_LINE_CHARS)
    }

    /// Scrub every string (keys included) in a JSON value in place.
    pub(crate) fn scrub_value(&self, value: &mut serde_json::Value) {
        if self.is_disabled() {
            return;
        }
        match value {
            serde_json::Value::String(s) => *s = self.scrub(s),
            serde_json::Value::Array(items) => {
                for item in items {
                    self.scrub_value(item);
                }
            }
            serde_json::Value::Object(map) => {
                let entries: Vec<(String, serde_json::Value)> =
                    std::mem::take(map).into_iter().collect();
                for (key, mut item) in entries {
                    self.scrub_value(&mut item);
                    map.insert(self.scrub(&key), item);
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
    }
}

/// Add a path and its canonical form (when different) with a placeholder.
fn push_path_forms(paths: &mut Vec<(String, &'static str)>, dir: &Path, placeholder: &'static str) {
    let mut forms = vec![dir.to_path_buf()];
    if let Ok(canonical) = dir.canonicalize() {
        forms.push(canonical);
    }
    for form in forms {
        let text = form
            .to_string_lossy()
            .trim_end_matches(['/', '\\'])
            .to_string();
        // A root or one-character path would replace every separator.
        if text.chars().count() >= MIN_SECRET_CHARS && !paths.iter().any(|(p, _)| *p == text) {
            paths.push((text, placeholder));
        }
    }
}

/// Replace the user segment of `/Users/<name>`, `/home/<name>` and
/// `\Users\<name>` with `<user>`, whatever the name is.
fn scrub_user_dirs(text: &str) -> String {
    const MARKERS: [&str; 3] = ["/Users/", "/home/", "\\Users\\"];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let next = MARKERS
            .iter()
            .filter_map(|m| rest.find(m).map(|at| (at, *m)))
            .min_by_key(|(at, _)| *at);
        let Some((at, marker)) = next else {
            out.push_str(rest);
            return out;
        };
        let after = at + marker.len();
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        let end = tail
            .find(|c: char| {
                c == '/' || c == '\\' || c == '"' || c == '\'' || c.is_whitespace() || c == ','
            })
            .unwrap_or(tail.len());
        if end > 0 {
            out.push_str("<user>");
        }
        rest = &tail[end..];
    }
}

/// Characters that make up a hex or base64-like run.
fn is_run_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '_' || c == '-'
}

/// Cut long hex runs to a prefix and remove long base64-like runs.
fn scrub_runs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.is_empty() {
            return;
        }
        let len = run.chars().count();
        let all_hex = run.chars().all(|c| c.is_ascii_hexdigit());
        if all_hex && len >= HEX_RUN_MIN {
            out.extend(run.chars().take(HEX_PREFIX_CHARS));
            out.push('…');
        } else if len >= B64_RUN_MIN
            && run.chars().any(|c| c.is_ascii_digit())
            && run.chars().any(|c| c.is_ascii_alphabetic())
        {
            out.push_str("[redacted]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if is_run_char(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Replace the content of every double-quoted span with `[redacted]`.
/// An unclosed quote redacts to the end of the line.
fn redact_quoted(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        out.push(c);
        if c != '"' {
            continue;
        }
        let mut escaped = false;
        let mut closed = false;
        for inner in chars.by_ref() {
            if escaped {
                escaped = false;
                continue;
            }
            if inner == '\\' {
                escaped = true;
                continue;
            }
            if inner == '"' {
                closed = true;
                break;
            }
        }
        out.push_str("[redacted]");
        if closed {
            out.push('"');
        }
    }
    out
}

/// A JSON log line reduced to `timestamp level target: message`; the
/// structured fields (which carry ids, names and payload values) are
/// dropped and quoted spans in the message are redacted.
fn json_log_summary(value: &serde_json::Value) -> String {
    let field = |key: &str| value.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let message = value
        .pointer("/fields/message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    format!(
        "{} {} {}: {}",
        field("timestamp"),
        field("level"),
        field("target"),
        redact_quoted(message)
    )
}

/// The first `max` characters of `text`, with a marker when cut.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push_str(" [cut]");
    out
}

// ---------------------------------------------------------------------------
// Bundle assembly
// ---------------------------------------------------------------------------

/// Everything a bundle is built from. The route fills it from the daemon
/// state; tests fill it from a temporary data directory.
#[derive(Debug, Clone)]
pub(crate) struct ReportInputs {
    /// The daemon data directory (listed by name and size, never read).
    pub(crate) data_dir: PathBuf,
    /// The daemon's own log file, when it writes one (`X0X_LOG_DIR`).
    pub(crate) log_file: Option<PathBuf>,
    /// The redacted `/health` body.
    pub(crate) health: serde_json::Value,
    /// Full agent id hex; only a short prefix goes into the bundle.
    pub(crate) agent_id_hex: String,
    /// Full machine id hex; only a short prefix goes into the bundle.
    pub(crate) machine_id_hex: String,
    /// Daemon uptime in seconds.
    pub(crate) uptime_secs: u64,
    /// Bundle creation time (seconds since the Unix epoch).
    pub(crate) created_unix: u64,
}

/// One built bundle: the serialized bytes plus counts for the response.
#[derive(Debug, Clone)]
pub(crate) struct BuiltReport {
    /// Pretty JSON, at most [`MAX_BUNDLE_BYTES`].
    pub(crate) bytes: Vec<u8>,
    /// Log lines kept in the bundle.
    pub(crate) log_lines: usize,
    /// Log lines dropped to fit the size bound.
    pub(crate) log_lines_dropped: usize,
}

/// Short id prefix: never more than [`HEX_PREFIX_CHARS`] characters.
fn id_prefix(hex_id: &str) -> String {
    hex_id.chars().take(HEX_PREFIX_CHARS).collect()
}

/// Read the API token from `<data_dir>/api-token`, bounded, so the
/// redactor knows it even when the caller did not pass it.
fn read_api_token(data_dir: &Path) -> Option<String> {
    let file = std::fs::File::open(data_dir.join("api-token")).ok()?;
    let mut text = String::new();
    file.take(API_TOKEN_READ_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    let token = text.trim().to_string();
    (!token.is_empty()).then_some(token)
}

/// Open `path` for reading only when it is a regular file. A symlink is
/// refused (checked with `symlink_metadata`, and on unix again at open
/// time with `O_NOFOLLOW`), and a FIFO or device is refused without
/// blocking (`O_NONBLOCK` on unix, then a check on the opened handle).
fn open_regular_file(path: &Path) -> Result<std::fs::File> {
    let meta = std::fs::symlink_metadata(path).context("log file metadata")?;
    if !meta.file_type().is_file() {
        anyhow::bail!("log path is not a regular file (symlink, FIFO or other)");
    }
    let mut options = std::fs::File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open log file")?;
    if !file.metadata().context("log file metadata")?.is_file() {
        anyhow::bail!("log path is not a regular file (symlink, FIFO or other)");
    }
    Ok(file)
}

/// The last lines of `path`: at most [`LOG_TAIL_READ_BYTES`] read from the
/// end, at most [`MAX_LOG_LINES`] lines, each scrubbed.
fn log_tail(path: &Path, redactor: &Redactor) -> Result<Vec<String>> {
    let mut file = open_regular_file(path)?;
    let len = file.metadata().context("log file metadata")?.len();
    let start = len.saturating_sub(LOG_TAIL_READ_BYTES);
    file.seek(SeekFrom::Start(start)).context("seek log file")?;
    let mut bytes = Vec::new();
    file.take(LOG_TAIL_READ_BYTES)
        .read_to_end(&mut bytes)
        .context("read log file")?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    // A read that started mid-file starts mid-line: drop that partial line.
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let skip = lines.len().saturating_sub(MAX_LOG_LINES);
    Ok(lines
        .into_iter()
        .skip(skip)
        .filter(|line| !line.trim().is_empty())
        .map(|line| redactor.scrub_log_line(line))
        .collect())
}

/// Top-level entries of the data directory: name, kind and file size.
/// Nothing is opened or followed.
fn data_dir_inventory(data_dir: &Path) -> Vec<serde_json::Value> {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut rows: Vec<(String, &'static str, Option<u64>)> = entries
        .take(MAX_INVENTORY_SCAN)
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = std::fs::symlink_metadata(entry.path()).ok();
            let (kind, size) = match &meta {
                Some(m) if m.file_type().is_symlink() => ("symlink", None),
                Some(m) if m.is_dir() => ("dir", None),
                Some(m) => ("file", Some(m.len())),
                None => ("unknown", None),
            };
            (name, kind, size)
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.truncate(MAX_INVENTORY_ENTRIES);
    rows.into_iter()
        .map(|(name, kind, size)| serde_json::json!({ "name": name, "kind": kind, "size": size }))
        .collect()
}

/// Assemble the bundle value with `log` lines.
fn bundle_value(
    inputs: &ReportInputs,
    inventory: &[serde_json::Value],
    log_source: &str,
    log: &[String],
    log_lines_dropped: usize,
) -> serde_json::Value {
    serde_json::json!({
        "schema": REPORT_SCHEMA,
        "version": 1,
        "created_unix": inputs.created_unix,
        "generator": { "name": "x0xd", "version": crate::VERSION },
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "uptime_secs": inputs.uptime_secs,
        },
        "identity": {
            "agent_id_prefix": id_prefix(&inputs.agent_id_hex),
            "machine_id_prefix": id_prefix(&inputs.machine_id_hex),
        },
        "health": inputs.health,
        "data_dir": inventory,
        "log_tail": {
            "source": log_source,
            "lines": log,
            "lines_dropped_for_size": log_lines_dropped,
        },
        "redaction": {
            "rules": [
                "allow-list sections only; no key, store or message file is read",
                "API token and contact labels removed",
                "home, data-directory and user-directory paths and the user name replaced",
                "quoted log values removed; JSON log lines keep timestamp, level, target and message",
                "hex runs of 16+ characters cut to an 8-character prefix",
                "base64-like runs of 32+ characters removed",
            ],
        },
    })
}

/// Build a redacted bundle. The log tail is dropped oldest-first until the
/// serialized bundle fits [`MAX_BUNDLE_BYTES`].
pub(crate) fn build_report(inputs: &ReportInputs, redactor: &Redactor) -> Result<BuiltReport> {
    let (log_source, mut log) = match &inputs.log_file {
        Some(path) => match log_tail(path, redactor) {
            Ok(lines) => ("daemon log file (X0X_LOG_DIR)", lines),
            Err(e) if format!("{e:#}").contains("not a regular file") => (
                "skipped: the daemon log path is not a regular file (symlink, FIFO or other)",
                Vec::new(),
            ),
            Err(_) => ("daemon log file could not be read", Vec::new()),
        },
        None => (
            "none: x0xd writes no log file unless X0X_LOG_DIR is set",
            Vec::new(),
        ),
    };
    let inventory = data_dir_inventory(&inputs.data_dir);
    let mut dropped = 0usize;
    loop {
        let mut value = bundle_value(inputs, &inventory, log_source, &log, dropped);
        redactor.scrub_value(&mut value);
        let bytes = serde_json::to_vec_pretty(&value).context("serialize report bundle")?;
        if bytes.len() <= MAX_BUNDLE_BYTES {
            return Ok(BuiltReport {
                bytes,
                log_lines: log.len(),
                log_lines_dropped: dropped,
            });
        }
        if log.is_empty() {
            anyhow::bail!(
                "report bundle is {} bytes without any log lines, over the {MAX_BUNDLE_BYTES}-byte bound",
                bytes.len()
            );
        }
        // Drop a quarter of the remaining lines (at least one) per pass.
        let cut = (log.len() / 4).max(1);
        log.drain(..cut);
        dropped += cut;
    }
}

/// Why a sent copy could not be built.
#[derive(Debug)]
pub(crate) enum SentReportError {
    /// The compact copy is this many bytes, over [`MAX_SENT_REPORT_BYTES`].
    TooLarge(usize),
    /// Serialization failed.
    Serialize(String),
}

/// Build the copy of a bundle that is sent to an owner device (#1354
/// slice 3). It is the local bundle without the sections in
/// [`SENT_REPORT_WITHHELD`]: the log tail and the data-directory listing
/// are not read at all, because the redactor keeps peer addresses,
/// four-word addresses and free text in log lines, and file names. The
/// rest (generator, host, id prefixes, the redacted `/health` body that
/// any caller may read) passes the same [`Redactor`]. Compact JSON, at
/// most [`MAX_SENT_REPORT_BYTES`].
pub(crate) fn build_sent_report(
    inputs: &ReportInputs,
    redactor: &Redactor,
) -> std::result::Result<Vec<u8>, SentReportError> {
    let mut value = bundle_value(inputs, &[], "", &[], 0);
    if let Some(map) = value.as_object_mut() {
        for section in SENT_REPORT_WITHHELD {
            map.remove(section);
        }
        map.insert("profile".to_string(), serde_json::json!("sent"));
        map.insert(
            "withheld".to_string(),
            serde_json::json!(SENT_REPORT_WITHHELD),
        );
        if let Some(rules) = map
            .get_mut("redaction")
            .and_then(|r| r.get_mut("rules"))
            .and_then(serde_json::Value::as_array_mut)
        {
            rules.push(serde_json::json!(
                "sent copy: no log lines and no data-directory names; they stay on this machine"
            ));
        }
    }
    redactor.scrub_value(&mut value);
    let bytes =
        serde_json::to_vec(&value).map_err(|e| SentReportError::Serialize(e.to_string()))?;
    if bytes.len() > MAX_SENT_REPORT_BYTES {
        return Err(SentReportError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// A refused `deliver_to`: status, error code and detail.
pub(crate) type RecipientRefusal = (StatusCode, &'static str, String);

/// Check that `recipient_hex` names one of the owner's devices (#1354
/// slice 3): an agent whose certificate this owner issued (the owner's
/// issued-certificate roster, which keeps offline agents), not this
/// daemon's own agent, not a rider (a rider is hosted by this daemon, it
/// is not a device), and with a certificate not expired at `now_secs`.
pub(crate) fn check_owner_recipient(
    recipient_hex: &str,
    own_agent: &crate::identity::AgentId,
    roster: &[crate::OwnerIssuedCert],
    now_secs: u64,
) -> std::result::Result<crate::identity::AgentId, RecipientRefusal> {
    let bytes = hex::decode(recipient_hex.trim()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            "invalid_agent_id",
            format!("deliver_to is not hex: {e}"),
        )
    })?;
    let id: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
        (
            StatusCode::BAD_REQUEST,
            "invalid_agent_id",
            format!(
                "deliver_to must be 32 bytes (64 hex chars), got {}",
                b.len()
            ),
        )
    })?;
    let recipient = crate::identity::AgentId(id);
    if &recipient == own_agent {
        return Err((
            StatusCode::BAD_REQUEST,
            "deliver_to_self",
            "deliver_to names this daemon's own agent; the report is already stored here"
                .to_string(),
        ));
    }
    let hex_id = hex::encode(id);
    let not_owned = || {
        (
            StatusCode::FORBIDDEN,
            "not_an_owner_device",
            "deliver_to is not an agent this owner issued a certificate to \
             (GET /owner/agents lists them)"
                .to_string(),
        )
    };
    let entry = roster
        .iter()
        .find(|c| c.agent_id.eq_ignore_ascii_case(&hex_id))
        .ok_or_else(not_owned)?;
    if entry.mode == crate::profile::CertMode::Rider {
        return Err(not_owned());
    }
    if entry.not_after.is_some_and(|t| t <= now_secs) {
        return Err((
            StatusCode::FORBIDDEN,
            "certificate_expired",
            "the owner certificate of deliver_to has expired".to_string(),
        ));
    }
    Ok(recipient)
}

/// The `logical_id` a report created at `secs` is queued under.
pub(crate) fn report_logical_id(secs: u64) -> String {
    format!("{REPORT_LOGICAL_ID_PREFIX}{secs}")
}

/// The durable direct-send obligation that carries a sent copy to
/// `recipient` (#1354 slice 3): the `logical_id` from the creation second,
/// the request id derived from it as `POST /direct/send` derives it, and
/// the outbox's longest deadline.
pub(crate) fn report_obligation(
    sender: crate::identity::AgentId,
    recipient: crate::identity::AgentId,
    created_unix: u64,
    payload: Vec<u8>,
    now_ms: u64,
) -> std::result::Result<super::routes::direct_outbox::DirectSendObligation, String> {
    let logical_id = report_logical_id(created_unix);
    let request_id = crate::dm::DmLogicalId::parse(&logical_id)?.request_id(sender, recipient);
    Ok(super::routes::direct_outbox::DirectSendObligation {
        recipient: hex::encode(recipient.as_bytes()),
        logical_id,
        request_id: hex::encode(request_id),
        payload,
        deliver_until_ms: now_ms
            .saturating_add(super::routes::direct_outbox::DIRECT_SEND_MAX_HORIZON_MS),
        first_seen_ms: now_ms,
        retry_count: 0,
        next_retry_at_ms: 0,
        last_error: None,
        options: super::routes::direct_outbox::DirectSendOptions::default(),
    })
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// File name of a bundle created at `secs`.
pub(crate) fn report_file_name(secs: u64) -> String {
    format!("x0x-report-{secs}.json")
}

/// The creation second a bundle file name carries, if it is one.
fn report_file_secs(name: &str) -> Option<u64> {
    name.strip_prefix("x0x-report-")?
        .strip_suffix(".json")?
        .parse()
        .ok()
}

/// Write `bytes` as a new bundle file in `reports_dir` (created 0700 on
/// unix). The file is created new with mode 0600; an existing file or
/// symlink at the path is refused.
pub(crate) fn store_report(reports_dir: &Path, secs: u64, bytes: &[u8]) -> Result<PathBuf> {
    match std::fs::symlink_metadata(reports_dir) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => anyhow::bail!(
            "{} exists and is not a plain directory (a symlink is refused)",
            reports_dir.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(reports_dir)
                .with_context(|| format!("create {}", reports_dir.display()))?;
        }
        Err(e) => {
            return Err(e).with_context(|| format!("inspect {}", reports_dir.display()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(reports_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set permissions on {}", reports_dir.display()))?;
    }
    let path = reports_dir.join(report_file_name(secs));
    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("create report bundle {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write report bundle {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync report bundle {}", path.display()))?;
    Ok(path)
}

/// Delete the oldest bundles so at most `keep` remain. Only files named
/// like a bundle are touched. Returns how many were deleted.
pub(crate) fn prune_reports(reports_dir: &Path, keep: usize) -> usize {
    let Ok(entries) = std::fs::read_dir(reports_dir) else {
        return 0;
    };
    let mut bundles: Vec<(u64, PathBuf)> = entries
        .take(MAX_INVENTORY_SCAN)
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|entry| {
            let secs = report_file_secs(&entry.file_name().to_string_lossy())?;
            Some((secs, entry.path()))
        })
        .collect();
    if bundles.len() <= keep {
        return 0;
    }
    bundles.sort_by_key(|(secs, _)| *secs);
    let excess = bundles.len() - keep;
    bundles
        .into_iter()
        .take(excess)
        .filter(|(_, path)| std::fs::remove_file(path).is_ok())
        .count()
}

// ---------------------------------------------------------------------------
// Rate limit
// ---------------------------------------------------------------------------

/// Last accepted report per data directory.
fn report_slots() -> &'static Mutex<HashMap<PathBuf, Instant>> {
    static SLOTS: OnceLock<Mutex<HashMap<PathBuf, Instant>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Claim the report slot for `data_dir` at `now`. `Err` carries the
/// seconds until the next report is allowed.
pub(crate) fn claim_report_slot(
    slots: &Mutex<HashMap<PathBuf, Instant>>,
    data_dir: &Path,
    now: Instant,
) -> std::result::Result<(), u64> {
    let mut slots = slots
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(last) = slots.get(data_dir) {
        let elapsed = now.saturating_duration_since(*last);
        if elapsed < REPORT_MIN_INTERVAL {
            let wait = REPORT_MIN_INTERVAL - elapsed;
            return Err(wait.as_secs().max(1));
        }
    }
    slots.insert(data_dir.to_path_buf(), now);
    Ok(())
}

/// Give back a slot claimed at `claimed` after a failed build, so the
/// owner can retry at once.
fn release_report_slot(
    slots: &Mutex<HashMap<PathBuf, Instant>>,
    data_dir: &Path,
    claimed: Instant,
) {
    let mut slots = slots
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slots.get(data_dir) == Some(&claimed) {
        slots.remove(data_dir);
    }
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

/// The redacted `/health` body, from the `/health` handler itself with
/// `?detail=redacted`, so the two can never disagree.
async fn redacted_health(state: &Arc<AppState>) -> serde_json::Value {
    let mut params = HashMap::new();
    params.insert("detail".to_string(), "redacted".to_string());
    let response = super::routes::health(
        State(Arc::clone(state)),
        None,
        axum::http::HeaderMap::new(),
        axum::extract::Query(params),
    )
    .await;
    match axum::body::to_bytes(response.into_body(), MAX_BUNDLE_BYTES).await {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .map(|mut body| {
                super::health_verdict::redact_health_detail(&mut body);
                body
            })
            .unwrap_or_else(|e| serde_json::json!({ "error": format!("health body: {e}") })),
        Err(e) => serde_json::json!({ "error": format!("health body: {e}") }),
    }
}

/// The daemon's own log file, when `X0X_LOG_DIR` is set (see x0xd).
fn daemon_log_file() -> Option<PathBuf> {
    let dir = std::env::var_os("X0X_LOG_DIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())?;
    Some(dir.join(format!("x0xd-{}.log", std::process::id())))
}

/// The local user name, from the environment or the home directory.
fn local_user_name(home: Option<&Path>) -> Option<String> {
    std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("USERNAME").ok())
        .or_else(|| {
            home.and_then(|h| h.file_name())
                .map(|n| n.to_string_lossy().into_owned())
        })
}

fn error_response(status: StatusCode, error: &str, detail: String) -> Response {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": error, "detail": detail })),
    )
        .into_response()
}

/// What the blocking build step of `POST /report` produced.
enum BuiltLocalAndSent {
    /// The sent copy was refused; nothing was stored.
    SentRefused(SentReportError),
    /// The bundle is stored at `path`; `sent` is the copy to queue.
    Built {
        path: PathBuf,
        report: BuiltReport,
        pruned: usize,
        sent: Option<Vec<u8>>,
    },
}

/// Body of `POST /report` (#1354 slice 3). An empty body (no JSON content
/// type) is the default: store the bundle, send nothing.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReportRequest {
    /// Hex agent id of one of the owner's devices. When set, a sent copy
    /// of the bundle is queued to it on the durable direct-send outbox.
    #[serde(default)]
    pub(super) deliver_to: Option<String>,
}

/// The checked delivery target of one request: the recipient and this
/// daemon's own agent (the sender the request id is derived for).
struct DeliveryTarget {
    sender: crate::identity::AgentId,
    recipient: crate::identity::AgentId,
}

/// Resolve `deliver_to` against the owner roster and the contact store.
async fn delivery_target(
    state: &Arc<AppState>,
    recipient_hex: &str,
) -> std::result::Result<DeliveryTarget, RecipientRefusal> {
    if state.agent.identity().user_keypair().is_none() {
        return Err((
            StatusCode::CONFLICT,
            "no_owner_identity",
            "deliver_to needs an owner (user) identity on this daemon".to_string(),
        ));
    }
    let sender = state.agent.agent_id();
    let roster = state.agent.owner_issued_certificates().await;
    let now_secs = super::routes::direct_outbox::now_unix_ms() / 1000;
    let recipient = check_owner_recipient(recipient_hex, &sender, &roster, now_secs)?;
    {
        let contacts = state.contacts.read().await;
        if contacts.trust_level(&recipient) == crate::contacts::TrustLevel::Blocked
            || contacts.is_revoked(&recipient)
        {
            return Err((
                StatusCode::FORBIDDEN,
                super::routes::direct_outbox::RECIPIENT_BLOCKED,
                "deliver_to is blocked or revoked in the contact store".to_string(),
            ));
        }
    }
    Ok(DeliveryTarget { sender, recipient })
}

/// Queue `obligation` and describe it, or the refusal as
/// `(status, code, detail)`.
async fn queue_report(
    state: &Arc<AppState>,
    obligation: super::routes::direct_outbox::DirectSendObligation,
) -> std::result::Result<serde_json::Value, RecipientRefusal> {
    use super::routes::direct_outbox::{EnqueueOutcome, LedgerReceipt};
    let ledger = match obligation.request_id_bytes() {
        Some(rid) => LedgerReceipt::of(&state.agent.dm_inflight_acks(), &rid),
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "report_failed",
                "report request id is not 16 bytes of hex".to_string(),
            ))
        }
    };
    let mut delivery = serde_json::json!({
        "outcome": "queued",
        "agent_id": obligation.recipient,
        "logical_id": obligation.logical_id,
        "request_id": obligation.request_id,
        "deliver_until_ms": obligation.deliver_until_ms,
        "size_bytes": obligation.payload.len(),
    });
    match state.direct_send_outbox.enqueue(obligation, ledger).await {
        EnqueueOutcome::Queued => Ok(delivery),
        EnqueueOutcome::AlreadyQueued { deliver_until_ms } => {
            delivery["deliver_until_ms"] = serde_json::json!(deliver_until_ms);
            Ok(delivery)
        }
        EnqueueOutcome::Conflict | EnqueueOutcome::InFlight => Err((
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "a report with this logical_id is already queued or sent to this device".to_string(),
        )),
        EnqueueOutcome::Full => Err((
            StatusCode::TOO_MANY_REQUESTS,
            "outbox_full",
            "the durable send outbox is full for this device or daemon; retry later".to_string(),
        )),
        EnqueueOutcome::NotDurable(detail) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "outbox_not_durable",
            format!("the sent copy is held but its durability is not confirmed: {detail}"),
        )),
        EnqueueOutcome::WriteFailed(detail) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "outbox_write_failed",
            detail,
        )),
    }
}

/// Parse the optional body: no JSON content type means the default.
fn report_request(
    body: std::result::Result<Json<ReportRequest>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<ReportRequest, Box<Response>> {
    match body {
        Ok(Json(req)) => Ok(req),
        Err(axum::extract::rejection::JsonRejection::MissingJsonContentType(_)) => {
            Ok(ReportRequest::default())
        }
        Err(e) => Err(Box::new(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            e.body_text(),
        ))),
    }
}

/// `POST /report` (#1354 slices 2 and 3): build a redacted problem-report
/// bundle and store it under `<data_dir>/reports/`. Durable owner token
/// only. One report per minute; the newest [`MAX_STORED_REPORTS`] are
/// kept. With `deliver_to`, the sent copy ([`build_sent_report`]) is also
/// queued to that owner device on the durable direct-send outbox; the call
/// itself sends nothing (`sent: false`), the outbox worker does.
pub(super) async fn create_report(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<ActorContext>,
    body: std::result::Result<Json<ReportRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !actor.is_durable_owner() {
        return error_response(
            StatusCode::FORBIDDEN,
            "durable_owner_required",
            "a problem report reads daemon logs; only the durable API token may create one"
                .to_string(),
        );
    }
    let request = match report_request(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    // A refused target is answered before the rate slot is claimed.
    let target = match request.deliver_to.as_deref() {
        Some(hex_id) => match delivery_target(&state, hex_id).await {
            Ok(target) => Some(target),
            Err((status, code, detail)) => return error_response(status, code, detail),
        },
        None => None,
    };
    let slots = report_slots();
    let claimed = Instant::now();
    if let Err(retry_after_secs) = claim_report_slot(slots, &state.data_dir, claimed) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": "rate_limited",
                "retry_after_secs": retry_after_secs,
            })),
        )
            .into_response();
    }

    let created_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            release_report_slot(slots, &state.data_dir, claimed);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "clock_error",
                e.to_string(),
            );
        }
    };
    let health = redacted_health(&state).await;
    let mut secrets = vec![state.api_token.clone()];
    secrets.extend(
        state
            .contacts
            .read()
            .await
            .list()
            .into_iter()
            .filter_map(|c| c.label.clone()),
    );
    let inputs = ReportInputs {
        data_dir: state.data_dir.clone(),
        log_file: daemon_log_file(),
        health,
        agent_id_hex: hex::encode(state.agent.agent_id().as_bytes()),
        machine_id_hex: hex::encode(state.agent.machine_id().as_bytes()),
        uptime_secs: state.start_time.elapsed().as_secs(),
        created_unix,
    };
    let data_dir = state.data_dir.clone();
    let send = target.is_some();
    let built = tokio::task::spawn_blocking(move || -> Result<BuiltLocalAndSent> {
        let home = dirs::home_dir();
        let mut all_secrets = secrets;
        all_secrets.extend(read_api_token(&inputs.data_dir));
        let redactor = Redactor::new(
            all_secrets,
            Some(&inputs.data_dir),
            home.as_deref(),
            local_user_name(home.as_deref()),
        );
        let report = build_report(&inputs, &redactor)?;
        // The sent copy is built before anything is stored, so a copy
        // over its bound refuses the whole request.
        let sent = if send {
            match build_sent_report(&inputs, &redactor) {
                Ok(bytes) => Some(bytes),
                Err(e) => return Ok(BuiltLocalAndSent::SentRefused(e)),
            }
        } else {
            None
        };
        let reports_dir = inputs.data_dir.join(REPORTS_DIR);
        let path = store_report(&reports_dir, inputs.created_unix, &report.bytes)?;
        let pruned = prune_reports(&reports_dir, MAX_STORED_REPORTS);
        Ok(BuiltLocalAndSent::Built {
            path,
            report,
            pruned,
            sent,
        })
    })
    .await;

    match built {
        Ok(Ok(BuiltLocalAndSent::SentRefused(e))) => {
            release_report_slot(slots, &data_dir, claimed);
            match e {
                SentReportError::TooLarge(len) => error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "report_too_large_to_send",
                    format!(
                        "the sent copy is {len} bytes, over the {MAX_SENT_REPORT_BYTES}-byte \
                         bound; nothing was stored or queued"
                    ),
                ),
                SentReportError::Serialize(detail) => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "report_failed", detail)
                }
            }
        }
        Ok(Ok(BuiltLocalAndSent::Built {
            path,
            report,
            pruned,
            sent,
        })) => {
            let mut body = serde_json::json!({
                "ok": true,
                "path": path.to_string_lossy(),
                "file_name": report_file_name(created_unix),
                "schema": REPORT_SCHEMA,
                "created_unix": created_unix,
                "size_bytes": report.bytes.len(),
                "log_lines": report.log_lines,
                "log_lines_dropped_for_size": report.log_lines_dropped,
                "older_reports_deleted": pruned,
                "sent": false,
                "delivery": null,
            });
            if let (Some(target), Some(payload)) = (target, sent) {
                let queued = match report_obligation(
                    target.sender,
                    target.recipient,
                    created_unix,
                    payload,
                    super::routes::direct_outbox::now_unix_ms(),
                ) {
                    Ok(obligation) => queue_report(&state, obligation).await,
                    Err(detail) => {
                        Err((StatusCode::INTERNAL_SERVER_ERROR, "report_failed", detail))
                    }
                };
                match queued {
                    Ok(delivery) => body["delivery"] = delivery,
                    Err((status, code, detail)) => {
                        // The bundle is stored; only the queue failed. Give
                        // the slot back so the owner can retry at once.
                        release_report_slot(slots, &data_dir, claimed);
                        body["ok"] = serde_json::json!(false);
                        body["error"] = serde_json::json!(code);
                        body["detail"] = serde_json::json!(detail);
                        return (status, Json(body)).into_response();
                    }
                }
            }
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Ok(Err(e)) => {
            release_report_slot(slots, &data_dir, claimed);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "report_failed",
                format!("{e:#}"),
            )
        }
        Err(e) => {
            release_report_slot(slots, &data_dir, claimed);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "report_failed",
                e.to_string(),
            )
        }
    }
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
