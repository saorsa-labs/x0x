//! Restart-loaded exec ACL parser and argv matcher.

use crate::identity::{AgentId, MachineId};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default Linux/macOS ACL location.
#[must_use]
pub fn default_exec_acl_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/usr/local/etc/x0x/exec-acl.toml")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/etc/x0x/exec-acl.toml")
    }
}

/// How the ACL path was supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    /// Default path: a missing file disables exec safely.
    DefaultPath,
    /// Explicit CLI flag: a missing file is a configuration error.
    ExplicitPath,
}

/// Loaded exec policy.
#[derive(Debug, Clone)]
pub enum ExecPolicy {
    Disabled {
        path: PathBuf,
        reason: String,
        loaded_at_unix_ms: u64,
    },
    Enabled(ExecAcl),
}

impl Default for ExecPolicy {
    /// Exec is disabled unless an ACL is explicitly loaded. This is the
    /// safe default for embedders that build [`ServeOptions`](crate::server::ServeOptions)
    /// without supplying an exec ACL.
    fn default() -> Self {
        Self::Disabled {
            path: default_exec_acl_path(),
            reason: "no exec ACL configured".to_string(),
            loaded_at_unix_ms: 0,
        }
    }
}

impl ExecPolicy {
    /// Whether the policy enables remote exec.
    #[must_use]
    pub fn enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    /// Path used when loading this policy.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Disabled { path, .. } => path,
            Self::Enabled(acl) => &acl.loaded_from,
        }
    }

    /// Summary safe for diagnostics.
    #[must_use]
    pub fn summary(&self) -> AclSummary {
        match self {
            Self::Disabled {
                path,
                reason,
                loaded_at_unix_ms,
            } => AclSummary {
                enabled: false,
                loaded_from: path.display().to_string(),
                loaded_at_unix_ms: *loaded_at_unix_ms,
                allow_entry_count: 0,
                command_entry_count: 0,
                disabled_reason: Some(reason.clone()),
            },
            Self::Enabled(acl) => AclSummary {
                enabled: true,
                loaded_from: acl.loaded_from.display().to_string(),
                loaded_at_unix_ms: acl.loaded_at_unix_ms,
                allow_entry_count: acl.allow.len(),
                command_entry_count: acl.allow.iter().map(|e| e.commands.len()).sum(),
                disabled_reason: None,
            },
        }
    }
}

/// Diagnostics-safe ACL summary.
#[derive(Debug, Clone, Serialize)]
pub struct AclSummary {
    pub enabled: bool,
    pub loaded_from: String,
    pub loaded_at_unix_ms: u64,
    pub allow_entry_count: usize,
    pub command_entry_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
}

/// Fully validated ACL.
#[derive(Debug, Clone)]
pub struct ExecAcl {
    pub loaded_from: PathBuf,
    pub loaded_at_unix_ms: u64,
    pub caps: ExecCaps,
    pub audit_log_path: PathBuf,
    pub audit_tasklist_id: Option<String>,
    pub allow: Vec<AllowEntry>,
}

/// Effective caps.
#[derive(Debug, Clone, Serialize)]
pub struct ExecCaps {
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_stdin_bytes: u64,
    pub max_duration_secs: u64,
    pub max_concurrent_per_agent: u32,
    pub max_concurrent_total: u32,
    pub warn_stdout_bytes: u64,
    pub warn_stderr_bytes: u64,
    pub warn_duration_secs: u64,
    pub default_cwd: Option<PathBuf>,
}

impl Default for ExecCaps {
    fn default() -> Self {
        Self {
            max_stdout_bytes: 16_777_216,
            max_stderr_bytes: 16_777_216,
            max_stdin_bytes: 1_048_576,
            max_duration_secs: 300,
            max_concurrent_per_agent: 4,
            max_concurrent_total: 32,
            warn_stdout_bytes: 8_388_608,
            warn_stderr_bytes: 8_388_608,
            warn_duration_secs: 60,
            default_cwd: None,
        }
    }
}

/// One allowed requester pair.
#[derive(Debug, Clone)]
pub struct AllowEntry {
    pub description: Option<String>,
    pub agent_id: AgentId,
    pub machine_id: MachineId,
    pub max_duration_secs: Option<u64>,
    pub commands: Vec<AllowedCommand>,
}

/// One allowed argv pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedCommand {
    pub argv: Vec<AllowedToken>,
}

/// Supported argv allowlist token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedToken {
    Literal(String),
    Int,
    UrlPath,
    LiteralWithUrlPathSuffix(String),
}

/// Result of a command match.
#[derive(Debug, Clone)]
pub struct MatchedCommand<'a> {
    pub entry: &'a AllowEntry,
    pub command: &'a AllowedCommand,
    pub effective_max_duration_secs: u64,
}

/// ACL load/validation error.
#[derive(Debug, thiserror::Error)]
pub enum AclError {
    #[error("exec ACL file not found: {0}")]
    Missing(String),
    #[error("failed to read exec ACL {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse exec ACL {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("invalid exec ACL {path}: {reason}")]
    Invalid { path: String, reason: String },
}

// ---------------------------------------------------------------------------
// TOML schema (deny_unknown_fields — mirroring connect::acl)
// ---------------------------------------------------------------------------

// NOTE: `deny_unknown_fields` is on the `[exec]` section, the allow entries,
// and the command entries (the security property — a misspelled `enable` vs
// `enabled`, `comand` vs `command`, or `taregts` vs `targets` fails loudly),
// but NOT on the root file envelope, so other top-level sections (`[connect]`,
// `[logging]`, …) may coexist in a future unified config. This mirrors the
// decision made for `connect::acl::ConnectFileToml` — see ADR-0019.
#[derive(Debug, Deserialize)]
struct AclFileToml {
    exec: Option<ExecSectionToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecSectionToml {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_max_stdout_bytes")]
    max_stdout_bytes: u64,
    #[serde(default = "default_max_stderr_bytes")]
    max_stderr_bytes: u64,
    #[serde(default = "default_max_stdin_bytes")]
    max_stdin_bytes: u64,
    #[serde(default = "default_max_duration_secs")]
    max_duration_secs: u64,
    #[serde(default = "default_max_concurrent_per_agent")]
    max_concurrent_per_agent: u32,
    #[serde(default = "default_max_concurrent_total")]
    max_concurrent_total: u32,
    #[serde(default = "default_warn_stdout_bytes")]
    warn_stdout_bytes: u64,
    #[serde(default = "default_warn_stderr_bytes")]
    warn_stderr_bytes: u64,
    #[serde(default = "default_warn_duration_secs")]
    warn_duration_secs: u64,
    #[serde(default)]
    default_cwd: Option<PathBuf>,
    #[serde(default = "default_audit_log_path")]
    audit_log_path: PathBuf,
    #[serde(default)]
    audit_tasklist_id: Option<String>,
    #[serde(default)]
    allow: Vec<AllowEntryToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowEntryToml {
    description: Option<String>,
    agent_id: String,
    machine_id: String,
    max_duration_secs: Option<u64>,
    #[serde(default)]
    commands: Vec<CommandToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandToml {
    argv: Vec<String>,
}

fn default_max_stdout_bytes() -> u64 {
    ExecCaps::default().max_stdout_bytes
}
fn default_max_stderr_bytes() -> u64 {
    ExecCaps::default().max_stderr_bytes
}
fn default_max_stdin_bytes() -> u64 {
    ExecCaps::default().max_stdin_bytes
}
fn default_max_duration_secs() -> u64 {
    ExecCaps::default().max_duration_secs
}
fn default_max_concurrent_per_agent() -> u32 {
    ExecCaps::default().max_concurrent_per_agent
}
fn default_max_concurrent_total() -> u32 {
    ExecCaps::default().max_concurrent_total
}
fn default_warn_stdout_bytes() -> u64 {
    ExecCaps::default().warn_stdout_bytes
}
fn default_warn_stderr_bytes() -> u64 {
    ExecCaps::default().warn_stderr_bytes
}
fn default_warn_duration_secs() -> u64 {
    ExecCaps::default().warn_duration_secs
}
fn default_audit_log_path() -> PathBuf {
    PathBuf::from("/var/log/x0x/exec.log")
}

/// Load an exec policy from an optional explicit path.
pub async fn load_exec_policy(path: Option<&Path>, mode: LoadMode) -> Result<ExecPolicy, AclError> {
    let acl_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_exec_acl_path);
    let loaded_at_unix_ms = now_unix_ms();
    if !acl_path.exists() {
        if mode == LoadMode::ExplicitPath {
            return Err(AclError::Missing(acl_path.display().to_string()));
        }
        return Ok(ExecPolicy::Disabled {
            path: acl_path,
            reason: "acl_missing".to_string(),
            loaded_at_unix_ms,
        });
    }

    let text = tokio::fs::read_to_string(&acl_path)
        .await
        .map_err(|source| AclError::Read {
            path: acl_path.display().to_string(),
            source,
        })?;
    parse_exec_policy(&acl_path, loaded_at_unix_ms, &text)
}

/// Parse ACL TOML. Public for tests and `x0xd --check`.
pub fn parse_exec_policy(
    path: &Path,
    loaded_at_unix_ms: u64,
    text: &str,
) -> Result<ExecPolicy, AclError> {
    let parsed: AclFileToml = toml::from_str(text).map_err(|source| AclError::Parse {
        path: path.display().to_string(),
        source,
    })?;
    let Some(exec) = parsed.exec else {
        return Ok(ExecPolicy::Disabled {
            path: path.to_path_buf(),
            reason: "missing_exec_section".to_string(),
            loaded_at_unix_ms,
        });
    };
    if !exec.enabled {
        return Ok(ExecPolicy::Disabled {
            path: path.to_path_buf(),
            reason: "exec_disabled".to_string(),
            loaded_at_unix_ms,
        });
    }

    validate_caps(path, &exec)?;
    let caps = ExecCaps {
        max_stdout_bytes: exec.max_stdout_bytes,
        max_stderr_bytes: exec.max_stderr_bytes,
        max_stdin_bytes: exec.max_stdin_bytes,
        max_duration_secs: exec.max_duration_secs,
        max_concurrent_per_agent: exec.max_concurrent_per_agent,
        max_concurrent_total: exec.max_concurrent_total,
        warn_stdout_bytes: exec.warn_stdout_bytes.min(exec.max_stdout_bytes),
        warn_stderr_bytes: exec.warn_stderr_bytes.min(exec.max_stderr_bytes),
        warn_duration_secs: exec.warn_duration_secs.min(exec.max_duration_secs),
        default_cwd: exec.default_cwd,
    };

    let mut allow = Vec::with_capacity(exec.allow.len());
    for (idx, entry) in exec.allow.into_iter().enumerate() {
        let agent_id = parse_agent_id(&entry.agent_id).map_err(|reason| AclError::Invalid {
            path: path.display().to_string(),
            reason: format!("allow[{idx}].agent_id: {reason}"),
        })?;
        let machine_id =
            parse_machine_id(&entry.machine_id).map_err(|reason| AclError::Invalid {
                path: path.display().to_string(),
                reason: format!("allow[{idx}].machine_id: {reason}"),
            })?;
        if entry.commands.is_empty() {
            return Err(AclError::Invalid {
                path: path.display().to_string(),
                reason: format!("allow[{idx}] must contain at least one command"),
            });
        }
        let mut commands = Vec::with_capacity(entry.commands.len());
        for (cmd_idx, cmd) in entry.commands.into_iter().enumerate() {
            if cmd.argv.is_empty() {
                return Err(AclError::Invalid {
                    path: path.display().to_string(),
                    reason: format!("allow[{idx}].commands[{cmd_idx}].argv must not be empty"),
                });
            }
            let mut argv = Vec::with_capacity(cmd.argv.len());
            for token in cmd.argv {
                argv.push(parse_allowed_token(path, idx, cmd_idx, &token)?);
            }
            commands.push(AllowedCommand { argv });
        }
        allow.push(AllowEntry {
            description: entry.description,
            agent_id,
            machine_id,
            max_duration_secs: entry.max_duration_secs,
            commands,
        });
    }

    Ok(ExecPolicy::Enabled(ExecAcl {
        loaded_from: path.to_path_buf(),
        loaded_at_unix_ms,
        caps,
        audit_log_path: exec.audit_log_path,
        audit_tasklist_id: exec.audit_tasklist_id,
        allow,
    }))
}

fn validate_caps(path: &Path, exec: &ExecSectionToml) -> Result<(), AclError> {
    let invalid = exec.max_stdout_bytes == 0
        || exec.max_stderr_bytes == 0
        || exec.max_stdin_bytes == 0
        || exec.max_duration_secs == 0
        || exec.max_concurrent_per_agent == 0
        || exec.max_concurrent_total == 0;
    if invalid {
        return Err(AclError::Invalid {
            path: path.display().to_string(),
            reason: "all exec caps must be positive".to_string(),
        });
    }
    if exec.max_concurrent_per_agent > exec.max_concurrent_total {
        return Err(AclError::Invalid {
            path: path.display().to_string(),
            reason: "max_concurrent_per_agent must be <= max_concurrent_total".to_string(),
        });
    }
    Ok(())
}

fn parse_allowed_token(
    path: &Path,
    allow_idx: usize,
    cmd_idx: usize,
    token: &str,
) -> Result<AllowedToken, AclError> {
    if token == "<INT>" {
        return Ok(AllowedToken::Int);
    }
    if token == "<URL_PATH>" {
        return Ok(AllowedToken::UrlPath);
    }
    if let Some(prefix) = token.strip_suffix("<URL_PATH>") {
        if prefix.is_empty() {
            return Ok(AllowedToken::UrlPath);
        }
        if prefix.contains('<') || prefix.contains('>') {
            return Err(AclError::Invalid {
                path: path.display().to_string(),
                reason: format!(
                    "allow[{allow_idx}].commands[{cmd_idx}] has unsupported template token in {token:?}"
                ),
            });
        }
        return Ok(AllowedToken::LiteralWithUrlPathSuffix(prefix.to_string()));
    }
    if token.contains('<') || token.contains('>') {
        return Err(AclError::Invalid {
            path: path.display().to_string(),
            reason: format!(
                "allow[{allow_idx}].commands[{cmd_idx}] has unsupported template token in {token:?}"
            ),
        });
    }
    Ok(AllowedToken::Literal(token.to_string()))
}

impl ExecAcl {
    /// Find an allowlist command for `(agent_id, machine_id, argv)`.
    #[must_use]
    pub fn match_command<'a>(
        &'a self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        argv: &[String],
    ) -> Option<MatchedCommand<'a>> {
        self.allow
            .iter()
            .filter(|entry| entry.agent_id == *agent_id && entry.machine_id == *machine_id)
            .find_map(|entry| {
                entry.commands.iter().find_map(|command| {
                    command.matches(argv).then_some(MatchedCommand {
                        entry,
                        command,
                        effective_max_duration_secs: entry
                            .max_duration_secs
                            .unwrap_or(self.caps.max_duration_secs)
                            .min(self.caps.max_duration_secs),
                    })
                })
            })
    }

    /// Whether any ACL entry matches this requester pair.
    #[must_use]
    pub fn has_agent_machine(&self, agent_id: &AgentId, machine_id: &MachineId) -> bool {
        self.allow
            .iter()
            .any(|entry| entry.agent_id == *agent_id && entry.machine_id == *machine_id)
    }
}

impl AllowedCommand {
    /// Check a requested argv vector against this allowlist entry.
    #[must_use]
    pub fn matches(&self, argv: &[String]) -> bool {
        self.argv.len() == argv.len()
            && self
                .argv
                .iter()
                .zip(argv.iter())
                .all(|(allow, request)| allow.matches(request))
    }
}

impl AllowedToken {
    /// Match a single request token.
    #[must_use]
    pub fn matches(&self, request: &str) -> bool {
        match self {
            Self::Literal(lit) => lit == request,
            Self::Int => is_valid_int_token(request),
            Self::UrlPath => is_valid_url_path(request),
            Self::LiteralWithUrlPathSuffix(prefix) => {
                request.strip_prefix(prefix).is_some_and(is_valid_url_path)
            }
        }
    }
}

/// Shell metacharacter defence-in-depth check.
#[must_use]
pub fn contains_shell_metachar(token: &str) -> bool {
    token
        .chars()
        .any(|ch| matches!(ch, ';' | '|' | '&' | '>' | '<' | '`' | '$' | '\n' | '\0'))
}

/// True if the whole argv vector is free from shell metacharacters.
#[must_use]
pub fn argv_has_shell_metachar(argv: &[String]) -> bool {
    argv.iter().any(|token| contains_shell_metachar(token))
}

fn is_valid_int_token(token: &str) -> bool {
    let len = token.len();
    if len == 0 || len > 6 {
        return false;
    }
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_digit() && first != '0' && chars.all(|ch| ch.is_ascii_digit())
}

fn is_valid_url_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 257 || !path.starts_with('/') || path.contains("..") {
        return false;
    }
    path.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '.' | '-'))
}

/// Parse 64-character hex AgentId.
pub fn parse_agent_id(hex_str: &str) -> Result<AgentId, String> {
    parse_32_byte_hex(hex_str).map(AgentId)
}

/// Parse 64-character hex MachineId.
pub fn parse_machine_id(hex_str: &str) -> Result<MachineId, String> {
    parse_32_byte_hex(hex_str).map(MachineId)
}

fn parse_32_byte_hex(hex_str: &str) -> Result<[u8; 32], String> {
    let decoded = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if decoded.len() != 32 {
        return Err(format!(
            "expected 32 bytes / 64 hex chars, got {} bytes",
            decoded.len()
        ));
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn templates_match_expected_tokens() {
        assert!(AllowedToken::Int.matches("1"));
        assert!(AllowedToken::Int.matches("999999"));
        assert!(!AllowedToken::Int.matches("0"));
        assert!(!AllowedToken::Int.matches("1000000"));
        assert!(!AllowedToken::Int.matches("1e5"));
        assert!(AllowedToken::UrlPath.matches("/health"));
        assert!(AllowedToken::UrlPath.matches("/foo/bar_1.2-3"));
        assert!(!AllowedToken::UrlPath.matches("/.."));
        assert!(!AllowedToken::UrlPath.matches("/foo bar"));
        assert!(!AllowedToken::UrlPath.matches("/foo;ls"));
        assert!(
            AllowedToken::LiteralWithUrlPathSuffix("http://127.0.0.1:12600".to_string())
                .matches("http://127.0.0.1:12600/health")
        );
    }

    #[test]
    fn parse_rejects_unknown_template() {
        let toml = format!(
            r#"
[exec]
enabled = true

[[exec.allow]]
agent_id = "{}"
machine_id = "{}"

[[exec.allow.commands]]
argv = ["echo", "<ANY>"]
"#,
            id_hex(1),
            id_hex(2)
        );
        let err = parse_exec_policy(Path::new("acl.toml"), 0, &toml).expect_err("must reject");
        assert!(err.to_string().contains("unsupported template"));
    }

    #[test]
    fn command_matching_is_strict() {
        let toml = format!(
            r#"
[exec]
enabled = true
max_duration_secs = 30

[[exec.allow]]
description = "alice"
agent_id = "{}"
machine_id = "{}"

[[exec.allow.commands]]
argv = ["journalctl", "-u", "x0xd", "-n", "<INT>"]
"#,
            id_hex(1),
            id_hex(2)
        );
        let policy = parse_exec_policy(Path::new("acl.toml"), 0, &toml).expect("valid");
        let ExecPolicy::Enabled(acl) = policy else {
            panic!("expected enabled acl")
        };
        let agent = AgentId([1; 32]);
        let machine = MachineId([2; 32]);
        let ok = vec!["journalctl", "-u", "x0xd", "-n", "100"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(acl.match_command(&agent, &machine, &ok).is_some());
        let bad = vec!["journalctl", "-u", "x0xd", "-n", "0"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(acl.match_command(&agent, &machine, &bad).is_none());
    }

    #[test]
    fn shell_metachar_detects_dangerous_tokens() {
        assert!(contains_shell_metachar("hello;ls"));
        assert!(contains_shell_metachar("$(id)"));
        assert!(!contains_shell_metachar("/safe/path-1.2"));
    }

    #[test]
    fn default_exec_acl_path_returns_expected() {
        let path = default_exec_acl_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with("exec-acl.toml"),
            "path should end with exec-acl.toml: {path_str}"
        );
    }

    #[test]
    fn exec_policy_path_disabled() {
        let policy = ExecPolicy::Disabled {
            path: PathBuf::from("/tmp/test-acl.toml"),
            reason: "test".to_string(),
            loaded_at_unix_ms: 100,
        };
        assert_eq!(policy.path(), Path::new("/tmp/test-acl.toml"));
    }

    #[test]
    fn exec_policy_path_enabled() {
        let acl = ExecAcl {
            loaded_from: PathBuf::from("/etc/x0x/exec-acl.toml"),
            loaded_at_unix_ms: 200,
            caps: ExecCaps::default(),
            audit_log_path: PathBuf::from("/var/log/x0x/exec-audit.jsonl"),
            audit_tasklist_id: None,
            allow: vec![],
        };
        let policy = ExecPolicy::Enabled(acl);
        assert_eq!(policy.path(), Path::new("/etc/x0x/exec-acl.toml"));
    }

    #[test]
    fn exec_policy_enabled_flag() {
        let disabled = ExecPolicy::Disabled {
            path: PathBuf::from("test"),
            reason: "test".to_string(),
            loaded_at_unix_ms: 0,
        };
        assert!(!disabled.enabled());

        let acl = ExecAcl {
            loaded_from: PathBuf::from("test"),
            loaded_at_unix_ms: 0,
            caps: ExecCaps::default(),
            audit_log_path: PathBuf::from("audit.jsonl"),
            audit_tasklist_id: None,
            allow: vec![],
        };
        let enabled = ExecPolicy::Enabled(acl);
        assert!(enabled.enabled());
    }

    // ========================================================================
    // #124 / WS1.3 tranche 2 — load_exec_policy fail-closed matrix.
    //
    // Exec is fail-closed by construction: the only way to ENABLE remote
    // command execution is a present, valid, enabled ACL. Every other load
    // outcome yields either Disabled or a hard error. These pin each branch
    // of that matrix so a future refactor cannot silently flip one to "allow".
    // ========================================================================

    #[tokio::test]
    async fn load_policy_missing_file_at_default_path_is_disabled() {
        // A missing ACL at the DEFAULT path must DISABLE exec safely — the
        // whole design hinges on "no ACL configured" meaning "no exec", never
        // "exec anything". Use an explicit nonexistent path (not `None`) so the
        // result does not depend on whether the real default path exists on
        // the developer's machine.
        let dir = tempfile::tempdir().expect("tmpdir");
        let missing = dir.path().join("absent-exec-acl.toml");
        let policy = load_exec_policy(Some(&missing), LoadMode::DefaultPath)
            .await
            .expect("missing-at-default must be Ok(Disabled)");
        match policy {
            ExecPolicy::Disabled { reason, .. } => {
                assert_eq!(reason, "acl_missing", "must report the fail-closed reason");
            }
            ExecPolicy::Enabled(_) => panic!("missing ACL must never enable exec"),
        }
    }

    #[tokio::test]
    async fn load_policy_missing_file_at_explicit_path_is_hard_error() {
        // An operator who EXPLICITLY points at an ACL that doesn't exist has a
        // misconfiguration: that must be a hard error, not a silent disable —
        // otherwise a typo in the --exec-acl flag would quietly turn exec off
        // (or, worse, a future change could make it quietly turn on).
        let dir = tempfile::tempdir().expect("tmpdir");
        let missing = dir.path().join("absent-exec-acl.toml");
        let err = load_exec_policy(Some(&missing), LoadMode::ExplicitPath)
            .await
            .expect_err("explicit missing path must error");
        assert!(
            matches!(err, AclError::Missing(_)),
            "expected AclError::Missing, got {err:?}"
        );
    }

    #[tokio::test]
    async fn load_policy_malformed_toml_is_hard_error() {
        // Garbage TOML must be a hard Parse error, never a silent disable.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("bad-acl.toml");
        std::fs::write(&path, "this is not = valid = toml [[[").expect("write");
        let err = load_exec_policy(Some(&path), LoadMode::ExplicitPath)
            .await
            .expect_err("malformed TOML must error");
        assert!(
            matches!(err, AclError::Parse { .. }),
            "expected AclError::Parse, got {err:?}"
        );
    }

    #[tokio::test]
    async fn load_policy_missing_exec_section_is_disabled() {
        // A valid TOML file with no [exec] section disables exec: the file is
        // present but doesn't configure exec, so exec stays off.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("no-exec-section.toml");
        std::fs::write(&path, "# some unrelated config\n[other]\nfoo = 1\n").expect("write");
        let policy = load_exec_policy(Some(&path), LoadMode::ExplicitPath)
            .await
            .expect("present file is not a Missing error");
        match policy {
            ExecPolicy::Disabled { reason, .. } => {
                assert_eq!(reason, "missing_exec_section");
            }
            ExecPolicy::Enabled(_) => panic!("no [exec] section must not enable exec"),
        }
    }

    #[tokio::test]
    async fn load_policy_enabled_false_is_disabled() {
        // enabled = false is an explicit opt-out: the ACL is well-formed and
        // present, but the operator turned exec off. Disabled, reason pinned.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("disabled-acl.toml");
        std::fs::write(&path, "[exec]\nenabled = false\n").expect("write");
        let policy = load_exec_policy(Some(&path), LoadMode::ExplicitPath)
            .await
            .expect("well-formed file is not a Missing error");
        match policy {
            ExecPolicy::Disabled { reason, .. } => {
                assert_eq!(reason, "exec_disabled");
            }
            ExecPolicy::Enabled(_) => panic!("enabled=false must not enable exec"),
        }
    }

    // ========================================================================
    // #124 / WS1.3 tranche 2 — match_command token semantics.
    //
    // The allowlist is the last line of defence before a child is spawned.
    // Literal tokens must match EXACTLY (no substring/prefix leakage), and
    // LiteralWithUrlPathSuffix must not let a registered host be hijacked by
    // an attacker-controlled suffix (the classic `http://a` vs `http://a.evil`
    // confusion).
    // ========================================================================

    fn acl_with_command(agent: u8, machine: u8, argv: Vec<AllowedToken>) -> ExecAcl {
        ExecAcl {
            loaded_from: PathBuf::from("exec-acl.toml"),
            loaded_at_unix_ms: 1,
            caps: ExecCaps::default(),
            audit_log_path: PathBuf::from("audit.jsonl"),
            audit_tasklist_id: None,
            allow: vec![AllowEntry {
                description: None,
                agent_id: AgentId([agent; 32]),
                machine_id: MachineId([machine; 32]),
                max_duration_secs: None,
                commands: vec![AllowedCommand { argv }],
            }],
        }
    }

    #[test]
    fn literal_token_matches_only_an_exact_string() {
        // A Literal allowlist entry accepts ONLY the exact string — never a
        // prefix, suffix, or the same string plus extra argv. This is what
        // stops `echo ok` from authorising `echo ok && rm -rf /`.
        let acl = acl_with_command(
            1,
            2,
            vec![
                AllowedToken::Literal("echo".to_string()),
                AllowedToken::Literal("ok".to_string()),
            ],
        );
        let agent = AgentId([1; 32]);
        let machine = MachineId([2; 32]);

        // Exact match — allowed.
        assert!(acl
            .match_command(&agent, &machine, &["echo".into(), "ok".into()])
            .is_some());
        // Extra argv — the allowlist is length-pinned, so a trailing arg
        // (e.g. `echo ok; rm`) must NOT match even when the prefix tokens do.
        assert!(acl
            .match_command(&agent, &machine, &["echo".into(), "ok".into(), "x".into()])
            .is_none());
        // Prefix of a literal — `echop` is not `echo`.
        assert!(acl
            .match_command(&agent, &machine, &["echop".into(), "ok".into()])
            .is_none());
        // Wrong second token — `echo nope` is not `echo ok`.
        assert!(acl
            .match_command(&agent, &machine, &["echo".into(), "nope".into()])
            .is_none());
        // Empty argv.
        assert!(acl.match_command(&agent, &machine, &[]).is_none());
    }

    #[test]
    fn url_path_suffix_token_rejects_host_confusion() {
        // LiteralWithUrlPathSuffix("https://a") must match a path UNDER
        // `https://a` but NOT a host whose name merely STARTS with `https://a`
        // — otherwise an attacker registers `https://a.evil` and rides the
        // allowlist entry. The suffix after the prefix MUST be a valid URL
        // path (leading `/`, no `..`), which `https://a.evil/path` is not.
        let acl = acl_with_command(
            3,
            4,
            vec![AllowedToken::LiteralWithUrlPathSuffix(
                "https://a".to_string(),
            )],
        );
        let agent = AgentId([3; 32]);
        let machine = MachineId([4; 32]);

        // Valid path under the registered host — allowed.
        assert!(acl
            .match_command(&agent, &machine, &["https://a/health".into()])
            .is_some());
        // Host confusion: `https://a.evil/...` must NOT match. The bytes after
        // `https://a` are `.evil/...`, which is not a valid URL path (no
        // leading `/`), so the suffix token rejects it.
        assert!(
            acl.match_command(&agent, &machine, &["https://a.evil/path".into()])
                .is_none(),
            "LiteralWithUrlPathSuffix must not let `https://a` authorize `https://a.evil`"
        );
        // Bare prefix with no path at all — `https://a` strips to an empty
        // suffix, which is not a valid URL path, so it is rejected.
        assert!(
            acl.match_command(&agent, &machine, &["https://a".into()])
                .is_none(),
            "bare prefix with empty suffix must not match (not a valid URL path)"
        );
        // Path traversal — rejected by the URL-path validator (no `..`).
        assert!(acl
            .match_command(&agent, &machine, &["https://a/../etc".into()])
            .is_none());
    }

    // ========================================================================
    // #170 — deny_unknown_fields: misspelled keys in the exec ACL must be a
    // hard Parse error, never a silent policy deviation.
    //
    // In a security allowlist a misspelled field (e.g. `enable` instead of
    // `enabled`, `comand` instead of `command`) must be caught at load time.
    // Silently ignoring an unknown key would mean an operator who types
    // `enable = true` (instead of `enabled = true`) sees exec remain disabled
    // with no warning — the exact failure mode these tests pin.
    // ========================================================================

    #[test]
    fn unknown_key_in_exec_section_is_hard_error() {
        // `enable` is a common misspelling of `enabled` — must fail loudly.
        let err = parse_exec_policy(
            Path::new("/tmp/x"),
            0,
            "[exec]\nenabled = true\nenable = true\n",
        )
        .unwrap_err();
        assert!(
            matches!(err, AclError::Parse { .. }),
            "unknown field in [exec] section must be AclError::Parse: {err}"
        );
    }

    #[test]
    fn unknown_key_in_allow_entry_is_hard_error() {
        // `comand` is a misspelling of `command` — must fail loudly.
        let toml = format!(
            "[exec]\nenabled = true\n\
             [[exec.allow]]\nagent_id = \"{}\"\nmachine_id = \"{}\"\n\
             comand = \"typo\"\n",
            id_hex(1),
            id_hex(2)
        );
        let err = parse_exec_policy(Path::new("/tmp/x"), 0, &toml).unwrap_err();
        assert!(
            matches!(err, AclError::Parse { .. }),
            "unknown field in allow entry must be AclError::Parse: {err}"
        );
    }
}
