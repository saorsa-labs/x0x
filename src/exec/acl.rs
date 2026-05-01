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

#[derive(Debug, Deserialize)]
struct AclFileToml {
    exec: Option<ExecSectionToml>,
}

#[derive(Debug, Deserialize)]
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
struct AllowEntryToml {
    description: Option<String>,
    agent_id: String,
    machine_id: String,
    max_duration_secs: Option<u64>,
    #[serde(default)]
    commands: Vec<CommandToml>,
}

#[derive(Debug, Deserialize)]
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
}
