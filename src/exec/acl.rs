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
                allow_entry_count: acl.allow.len() + acl.owner_allow.len(),
                command_entry_count: acl.allow.iter().map(|e| e.commands.len()).sum::<usize>()
                    + acl
                        .owner_allow
                        .iter()
                        .map(|e| e.commands.len())
                        .sum::<usize>(),
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
    /// `principal = "owner"` entries (ADR-0070 §1): argv allowlists for any
    /// owner-trusted `(agent, machine)` pair. Kept apart from [`Self::allow`]
    /// so the exact-pair lookups keep their meaning; only the
    /// `*_for_principal` lookups consult it.
    pub owner_allow: Vec<OwnerAllowEntry>,
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

/// One `principal = "owner"` entry (ADR-0070 §1). Argv stays an exact
/// allowlist, exactly as for [`AllowEntry`].
#[derive(Debug, Clone)]
pub struct OwnerAllowEntry {
    pub description: Option<String>,
    pub max_duration_secs: Option<u64>,
    pub commands: Vec<AllowedCommand>,
}

/// Requester selector of one ACL entry (exec and connect share it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclPrincipal {
    /// Exact `(agent_id, machine_id)` pair — the pre-ADR-0070 form.
    Pair {
        agent_id: AgentId,
        machine_id: MachineId,
    },
    /// `principal = "owner"`: any pair that is owner-trusted per ADR-0070 §1
    /// (see [`crate::owner_trust`]).
    Owner,
}

/// Parse an ACL entry's requester selector.
///
/// Exactly one form is accepted: `principal = "owner"` with no `agent_id` /
/// `machine_id`, or no `principal` with both ids. Anything else — an unknown
/// principal (including the reserved slice-3 `"grant"`), a principal mixed
/// with ids, or a missing id — is an error, so a typo cannot silently widen
/// or narrow the policy.
///
/// # Errors
/// A human-readable reason (never a panic).
pub fn parse_principal(
    principal: Option<&str>,
    agent_id: Option<&str>,
    machine_id: Option<&str>,
) -> Result<AclPrincipal, String> {
    match principal {
        Some("owner") => {
            if agent_id.is_some() || machine_id.is_some() {
                return Err(
                    "principal = \"owner\" entries must not also set agent_id or machine_id"
                        .to_string(),
                );
            }
            Ok(AclPrincipal::Owner)
        }
        Some(other) => Err(format!(
            "unsupported principal {other:?} (supported: \"owner\")"
        )),
        None => {
            let agent_id = agent_id
                .ok_or_else(|| "missing agent_id (or principal = \"owner\")".to_string())
                .and_then(|raw| parse_agent_id(raw).map_err(|e| format!("agent_id: {e}")))?;
            let machine_id = machine_id
                .ok_or_else(|| "missing machine_id".to_string())
                .and_then(|raw| parse_machine_id(raw).map_err(|e| format!("machine_id: {e}")))?;
            Ok(AclPrincipal::Pair {
                agent_id,
                machine_id,
            })
        }
    }
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

/// Result of a command match against a `principal = "owner"` entry.
#[derive(Debug, Clone)]
pub struct OwnerMatchedCommand<'a> {
    pub entry: &'a OwnerAllowEntry,
    pub command: &'a AllowedCommand,
    pub effective_max_duration_secs: u64,
}

/// Result of [`ExecAcl::match_command_for_principal`]: which selector matched.
#[derive(Debug, Clone)]
pub enum PrincipalMatch<'a> {
    /// An exact `(agent_id, machine_id)` entry matched.
    Pair(MatchedCommand<'a>),
    /// A `principal = "owner"` entry matched (ADR-0070 §1).
    Owner(OwnerMatchedCommand<'a>),
}

impl PrincipalMatch<'_> {
    /// Description of the matched entry.
    #[must_use]
    pub fn description(&self) -> Option<&String> {
        match self {
            Self::Pair(m) => m.entry.description.as_ref(),
            Self::Owner(m) => m.entry.description.as_ref(),
        }
    }

    /// Effective duration cap of the matched entry.
    #[must_use]
    pub fn effective_max_duration_secs(&self) -> u64 {
        match self {
            Self::Pair(m) => m.effective_max_duration_secs,
            Self::Owner(m) => m.effective_max_duration_secs,
        }
    }
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
    allow: Vec<ExecAclEntrySpec>,
}

/// One exec allow entry in its wire schema — the `[[exec.allow]]` TOML
/// table and, identically, the `POST /acl/exec` JSON body (ADR-0070 §3).
/// `deny_unknown_fields` applies to both surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecAclEntrySpec {
    /// Free-text note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `"owner"` (ADR-0070 §1) instead of `agent_id` + `machine_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Requester agent id (64 hex chars) for an exact-pair entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Requester machine id (64 hex chars) for an exact-pair entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    /// Per-entry duration cap (clamped to the floor's `max_duration_secs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u64>,
    /// Exact argv allowlist (ADR-0046 templates).
    #[serde(default)]
    pub commands: Vec<ExecAclCommandSpec>,
}

/// One allowed argv pattern in wire schema (`[[exec.allow.commands]]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecAclCommandSpec {
    /// Argv tokens: literals or `<INT>` / `<URL_PATH>` templates.
    pub argv: Vec<String>,
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
    let mut owner_allow = Vec::new();
    for (idx, entry) in exec.allow.into_iter().enumerate() {
        match build_exec_entry(path, &format!("allow[{idx}]"), entry)? {
            BuiltExecEntry::Pair(entry) => allow.push(entry),
            BuiltExecEntry::Owner(entry) => owner_allow.push(entry),
        }
    }

    Ok(ExecPolicy::Enabled(ExecAcl {
        loaded_from: path.to_path_buf(),
        loaded_at_unix_ms,
        caps,
        audit_log_path: exec.audit_log_path,
        audit_tasklist_id: exec.audit_tasklist_id,
        allow,
        owner_allow,
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

/// One validated entry, split by requester selector.
enum BuiltExecEntry {
    Pair(AllowEntry),
    Owner(OwnerAllowEntry),
}

/// Validate one allow entry — the single code path for TOML floor entries
/// and ADR-0070 §3 API-managed entries alike. `label` names the entry in
/// error messages (`allow[3]`, `api[0]`).
fn build_exec_entry(
    path: &Path,
    label: &str,
    entry: ExecAclEntrySpec,
) -> Result<BuiltExecEntry, AclError> {
    let principal = parse_principal(
        entry.principal.as_deref(),
        entry.agent_id.as_deref(),
        entry.machine_id.as_deref(),
    )
    .map_err(|reason| AclError::Invalid {
        path: path.display().to_string(),
        reason: format!("{label}: {reason}"),
    })?;
    if entry.commands.is_empty() {
        return Err(AclError::Invalid {
            path: path.display().to_string(),
            reason: format!("{label} must contain at least one command"),
        });
    }
    let mut commands = Vec::with_capacity(entry.commands.len());
    for (cmd_idx, cmd) in entry.commands.into_iter().enumerate() {
        if cmd.argv.is_empty() {
            return Err(AclError::Invalid {
                path: path.display().to_string(),
                reason: format!("{label}.commands[{cmd_idx}].argv must not be empty"),
            });
        }
        let mut argv = Vec::with_capacity(cmd.argv.len());
        for token in cmd.argv {
            argv.push(parse_allowed_token(path, label, cmd_idx, &token)?);
        }
        commands.push(AllowedCommand { argv });
    }
    Ok(match principal {
        AclPrincipal::Pair {
            agent_id,
            machine_id,
        } => BuiltExecEntry::Pair(AllowEntry {
            description: entry.description,
            agent_id,
            machine_id,
            max_duration_secs: entry.max_duration_secs,
            commands,
        }),
        AclPrincipal::Owner => BuiltExecEntry::Owner(OwnerAllowEntry {
            description: entry.description,
            max_duration_secs: entry.max_duration_secs,
            commands,
        }),
    })
}

// ---------------------------------------------------------------------------
// ADR-0070 §3 — API-managed overlay entries on top of the TOML floor
// ---------------------------------------------------------------------------

/// Validate one API-supplied entry exactly as the TOML parser validates a
/// floor entry (same struct, same `deny_unknown_fields`, same checks).
///
/// # Errors
/// [`AclError::Invalid`] naming the offending field.
pub fn validate_exec_entry_spec(path: &Path, spec: &ExecAclEntrySpec) -> Result<(), AclError> {
    build_exec_entry(path, "api", spec.clone()).map(|_| ())
}

/// Effective policy = TOML floor ∪ API overlay (ADR-0070 §3).
///
/// A `Disabled` floor stays `Disabled`: overlay entries never enable a
/// plane the operator's file leaves off. Caps and audit settings come only
/// from the floor. Every overlay entry is validated by the same code path
/// as a floor entry; one invalid entry fails the whole composition (fail
/// closed — callers keep the last good policy).
///
/// # Errors
/// [`AclError::Invalid`] naming the offending `api[i]` entry.
pub fn compose_exec_policy(
    floor: &ExecPolicy,
    overlay: &[ExecAclEntrySpec],
) -> Result<ExecPolicy, AclError> {
    let ExecPolicy::Enabled(floor_acl) = floor else {
        return Ok(floor.clone());
    };
    let mut acl = floor_acl.clone();
    for (idx, spec) in overlay.iter().enumerate() {
        match build_exec_entry(&acl.loaded_from, &format!("api[{idx}]"), spec.clone())? {
            BuiltExecEntry::Pair(entry) => acl.allow.push(entry),
            BuiltExecEntry::Owner(entry) => acl.owner_allow.push(entry),
        }
    }
    Ok(ExecPolicy::Enabled(acl))
}

/// Whether `next` may replace `current` by hot reload (ADR-0070 §3).
///
/// Allow entries and caps are hot-reloadable. Enabling/disabling exec and
/// changing the audit sink (`audit_log_path`, `audit_tasklist_id`) are not:
/// the audit writer is bound once at service start, so a reload that moved
/// it would silently keep writing to the old sink. Both require a restart.
///
/// # Errors
/// A human-readable reason.
pub fn exec_reload_compatible(current: &ExecPolicy, next: &ExecPolicy) -> Result<(), String> {
    match (current, next) {
        (ExecPolicy::Enabled(cur), ExecPolicy::Enabled(nxt)) => {
            if cur.audit_log_path != nxt.audit_log_path
                || cur.audit_tasklist_id != nxt.audit_tasklist_id
            {
                return Err("reload would change the exec audit sink (audit_log_path / \
                     audit_tasklist_id); that requires a daemon restart"
                    .to_string());
            }
            Ok(())
        }
        (ExecPolicy::Disabled { .. }, ExecPolicy::Disabled { .. }) => Ok(()),
        _ => Err(format!(
            "reload would change exec from {} to {}; enabling or disabling the exec \
             plane requires a daemon restart",
            if current.enabled() {
                "enabled"
            } else {
                "disabled"
            },
            if next.enabled() {
                "enabled"
            } else {
                "disabled"
            }
        )),
    }
}

/// Hot-reload bookkeeping for one ACL plane (ADR-0070 §3), surfaced in
/// `/diagnostics/exec` and `/diagnostics/connect`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AclReloadStatus {
    /// Successful reloads since start.
    pub reloads_ok: u64,
    /// Rejected reloads since start (last good ACL kept each time).
    pub reloads_failed: u64,
    /// Time of the last reload attempt, success or failure.
    pub last_attempt_unix_ms: Option<u64>,
    /// Why the last reload was rejected; cleared by the next success.
    pub last_error: Option<String>,
    /// API-managed entries currently in the effective ACL.
    pub api_entry_count: usize,
    /// Times the API overlay file was found malformed or invalid (at
    /// startup or on reload). The file is left untouched on disk.
    pub overlay_load_failures: u64,
    /// Why the overlay on disk is not in force. While set, the effective
    /// ACL excludes the overlay and API writes are refused (`409`) so the
    /// broken file is never silently overwritten; cleared by a successful
    /// reload.
    pub overlay_error: Option<String>,
}

impl AllowedToken {
    /// The token in its TOML/API template form (`<INT>`, `<URL_PATH>`,
    /// `prefix<URL_PATH>`, or the literal).
    #[must_use]
    pub fn to_template(&self) -> String {
        match self {
            Self::Literal(lit) => lit.clone(),
            Self::Int => "<INT>".to_string(),
            Self::UrlPath => "<URL_PATH>".to_string(),
            Self::LiteralWithUrlPathSuffix(prefix) => format!("{prefix}<URL_PATH>"),
        }
    }
}

fn command_specs(commands: &[AllowedCommand]) -> Vec<ExecAclCommandSpec> {
    commands
        .iter()
        .map(|c| ExecAclCommandSpec {
            argv: c.argv.iter().map(AllowedToken::to_template).collect(),
        })
        .collect()
}

impl ExecAcl {
    /// Every entry in TOML/API schema form: exact pairs, then owner entries.
    #[must_use]
    pub fn entry_specs(&self) -> Vec<ExecAclEntrySpec> {
        self.allow
            .iter()
            .map(|e| ExecAclEntrySpec {
                description: e.description.clone(),
                principal: None,
                agent_id: Some(hex::encode(e.agent_id.as_bytes())),
                machine_id: Some(hex::encode(e.machine_id.as_bytes())),
                max_duration_secs: e.max_duration_secs,
                commands: command_specs(&e.commands),
            })
            .chain(self.owner_allow.iter().map(|e| ExecAclEntrySpec {
                description: e.description.clone(),
                principal: Some("owner".to_string()),
                agent_id: None,
                machine_id: None,
                max_duration_secs: e.max_duration_secs,
                commands: command_specs(&e.commands),
            }))
            .collect()
    }
}

fn parse_allowed_token(
    path: &Path,
    label: &str,
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
                    "{label}.commands[{cmd_idx}] has unsupported template token in {token:?}"
                ),
            });
        }
        return Ok(AllowedToken::LiteralWithUrlPathSuffix(prefix.to_string()));
    }
    if token.contains('<') || token.contains('>') {
        return Err(AclError::Invalid {
            path: path.display().to_string(),
            reason: format!(
                "{label}.commands[{cmd_idx}] has unsupported template token in {token:?}"
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

    /// Find an allowlist command for the requester across both selectors:
    /// exact-pair entries first, then — only when `owner_trusted` —
    /// `principal = "owner"` entries. `owner_trusted` must come from
    /// [`crate::owner_trust`]; `false` reduces this to [`Self::match_command`].
    #[must_use]
    pub fn match_command_for_principal<'a>(
        &'a self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        owner_trusted: bool,
        argv: &[String],
    ) -> Option<PrincipalMatch<'a>> {
        if let Some(matched) = self.match_command(agent_id, machine_id, argv) {
            return Some(PrincipalMatch::Pair(matched));
        }
        if !owner_trusted {
            return None;
        }
        self.owner_allow.iter().find_map(|entry| {
            entry.commands.iter().find_map(|command| {
                command
                    .matches(argv)
                    .then_some(PrincipalMatch::Owner(OwnerMatchedCommand {
                        entry,
                        command,
                        effective_max_duration_secs: entry
                            .max_duration_secs
                            .unwrap_or(self.caps.max_duration_secs)
                            .min(self.caps.max_duration_secs),
                    }))
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

    /// Whether any entry names this requester: an exact pair, or — only
    /// when `owner_trusted` — a `principal = "owner"` entry.
    #[must_use]
    pub fn has_entry_for_principal(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        owner_trusted: bool,
    ) -> bool {
        self.has_agent_machine(agent_id, machine_id)
            || (owner_trusted && !self.owner_allow.is_empty())
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
            owner_allow: Vec::new(),
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
            owner_allow: Vec::new(),
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
            owner_allow: Vec::new(),
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

    // ── ADR-0070 §1: `principal = "owner"` ─────────────────────────────

    const OWNER_EXEC_TOML: &str = "[exec]\nenabled = true\n\
         [[exec.allow]]\nprincipal = \"owner\"\nmax_duration_secs = 5\n\
         [[exec.allow.commands]]\nargv = [\"uptime\"]\n";

    fn owner_exec_acl() -> ExecAcl {
        match parse_exec_policy(Path::new("/tmp/x"), 0, OWNER_EXEC_TOML).expect("parse") {
            ExecPolicy::Enabled(acl) => acl,
            ExecPolicy::Disabled { reason, .. } => panic!("expected Enabled, got {reason}"),
        }
    }

    #[test]
    fn owner_principal_entry_parses_into_owner_allow() {
        let acl = owner_exec_acl();
        assert!(acl.allow.is_empty(), "owner entry is not an exact pair");
        assert_eq!(acl.owner_allow.len(), 1);
        assert_eq!(acl.owner_allow[0].max_duration_secs, Some(5));
    }

    #[test]
    fn owner_principal_matches_owner_trusted_pairs_only_with_exact_argv() {
        // WHY: the owner selector must never authorise a non-owner pair, and
        // argv stays an exact allowlist for owner pairs too (ADR-0046).
        let acl = owner_exec_acl();
        let agent = AgentId([1; 32]);
        let machine = MachineId([2; 32]);
        let uptime = vec!["uptime".to_string()];
        let other = vec!["reboot".to_string()];

        let matched = acl
            .match_command_for_principal(&agent, &machine, true, &uptime)
            .expect("owner-trusted pair matches the owner entry");
        assert!(matches!(matched, PrincipalMatch::Owner(_)));
        assert_eq!(matched.effective_max_duration_secs(), 5);
        assert!(acl.has_entry_for_principal(&agent, &machine, true));

        assert!(acl
            .match_command_for_principal(&agent, &machine, false, &uptime)
            .is_none());
        assert!(!acl.has_entry_for_principal(&agent, &machine, false));
        assert!(acl
            .match_command_for_principal(&agent, &machine, true, &other)
            .is_none());
        // The exact-pair API never sees owner entries.
        assert!(acl.match_command(&agent, &machine, &uptime).is_none());
        assert!(!acl.has_agent_machine(&agent, &machine));
    }

    #[test]
    fn owner_trust_without_owner_entry_matches_nothing() {
        // PR #896 decision 1: owner trust does not open exec by itself.
        let acl = acl_with_command(1, 2, vec![AllowedToken::Literal("uptime".into())]);
        let owner_agent = AgentId([9; 32]);
        let owner_machine = MachineId([8; 32]);
        assert!(!acl.has_entry_for_principal(&owner_agent, &owner_machine, true));
        assert!(acl
            .match_command_for_principal(
                &owner_agent,
                &owner_machine,
                true,
                &["uptime".to_string()]
            )
            .is_none());
    }

    #[test]
    fn principal_selector_errors_are_invalid() {
        let owner_with_ids = format!(
            "[exec]\nenabled = true\n[[exec.allow]]\nprincipal = \"owner\"\n\
             machine_id = \"{}\"\n[[exec.allow.commands]]\nargv = [\"uptime\"]\n",
            id_hex(2)
        );
        let grant = "[exec]\nenabled = true\n[[exec.allow]]\nprincipal = \"grant\"\n\
                     [[exec.allow.commands]]\nargv = [\"uptime\"]\n"
            .to_string();
        let no_selector = "[exec]\nenabled = true\n[[exec.allow]]\n\
                           [[exec.allow.commands]]\nargv = [\"uptime\"]\n"
            .to_string();
        for toml in [owner_with_ids, grant, no_selector] {
            let err = parse_exec_policy(Path::new("/tmp/x"), 0, &toml).unwrap_err();
            assert!(matches!(err, AclError::Invalid { .. }), "{toml}: {err}");
        }
    }
}
