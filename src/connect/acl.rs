//! Connect ACL policy types, load, parse, validate.
//!
//! Connection-ACL (default-closed connectivity policy). Modeled line-by-line
//! on the exec ACL ([`crate::exec::acl`]); see ADR-0019 and
//! `docs/plans/2026-07-issue-131-connect-acl-plan.md`.
//!
//! ## Scope
//!
//! Fail-closed policy loader, loopback-only target validator, and a pure
//! gate function ([`crate::connect::gate::evaluate_connect_gate`]). The
//! forwarder shipped in v0.29.0 (#183) and calls the gate at its inbound
//! accept seam — after the peer is verified + trusted and before
//! `TcpStream::connect`. See ADR-0019.
//!
//! ## Security invariants
//! - **Default = disabled.** [`ConnectPolicy::default()`] is `Disabled`, so an
//!   embedder that builds [`ServeOptions`](crate::server::ServeOptions)
//!   without supplying a connect ACL gets default-deny for free.
//! - **Loopback-only targets.** `parse_target` rejects any non-loopback
//!   address (and hostnames like `localhost`) as a **load-time hard error**.
//! - **Numeric IP only.** No DNS resolution in the trusted computing base.
//! - **Exact `host:port` only.** No port ranges, no CIDR.
//! - **`deny_unknown_fields`** on every TOML struct: a misspelled key
//!   (`taregts`, `enable`) fails loudly rather than silently yielding a
//!   different policy.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::exec::acl::{parse_agent_id, parse_machine_id, LoadMode};
use crate::identity::{AgentId, MachineId};

// ---------------------------------------------------------------------------
// Path
// ---------------------------------------------------------------------------

/// Default connect ACL file location.
#[must_use]
pub fn default_connect_acl_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/usr/local/etc/x0x/connect-acl.toml")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/etc/x0x/connect-acl.toml")
    }
}

/// Default connect-ACL file location for a named instance.
///
/// Named instances get a plane-specific default — the same directory as
/// [`default_connect_acl_path`] but named `connect-acl-<name>.toml` — so
/// co-located daemons (prod / testnet / `:443`) do not silently share one
/// connect-ACL file (issue #189). An explicit `--connect-acl` always wins; a
/// missing plane-specific file disables connect with the same fail-closed
/// behaviour as the base default. `server::validate_instance_name` restricts
/// the name to `[a-zA-Z0-9-]`, so the derived filename is path-traversal-safe.
#[must_use]
pub fn default_connect_acl_path_for(name: &str) -> PathBuf {
    debug_assert!(
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
        "instance name must be validated before deriving a connect-ACL path"
    );
    let file = format!("connect-acl-{name}.toml");
    default_connect_acl_path()
        .parent()
        .map(|dir| dir.join(&file))
        .unwrap_or_else(|| PathBuf::from(file))
}

// ---------------------------------------------------------------------------
// Policy + ACL types
// ---------------------------------------------------------------------------

/// Loaded connect policy.
///
/// Mirrors [`crate::exec::acl::ExecPolicy`] one-for-one: a `Disabled` variant
/// carrying provenance + reason, and an `Enabled` variant holding a validated
/// [`ConnectAcl`].
#[derive(Debug, Clone)]
pub enum ConnectPolicy {
    Disabled {
        path: PathBuf,
        reason: String,
        loaded_at_unix_ms: u64,
    },
    Enabled(ConnectAcl),
}

impl Default for ConnectPolicy {
    /// Connect is disabled unless an ACL is explicitly loaded. This is the
    /// safe default for embedders that build
    /// [`ServeOptions`](crate::server::ServeOptions) without supplying a
    /// connect ACL — they get default-deny with zero host effort.
    fn default() -> Self {
        Self::Disabled {
            path: default_connect_acl_path(),
            reason: "no connect ACL configured".to_string(),
            loaded_at_unix_ms: 0,
        }
    }
}

impl ConnectPolicy {
    /// Whether the policy enables connect-forwarding.
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
    pub fn summary(&self) -> ConnectAclSummary {
        match self {
            Self::Disabled {
                path,
                reason,
                loaded_at_unix_ms,
            } => ConnectAclSummary {
                enabled: false,
                loaded_from: path.display().to_string(),
                loaded_at_unix_ms: *loaded_at_unix_ms,
                allow_entry_count: 0,
                target_entry_count: 0,
                disabled_reason: Some(reason.clone()),
            },
            Self::Enabled(acl) => ConnectAclSummary {
                enabled: true,
                loaded_from: acl.loaded_from.display().to_string(),
                loaded_at_unix_ms: acl.loaded_at_unix_ms,
                allow_entry_count: acl.allow.len(),
                target_entry_count: acl.allow.iter().map(|e| e.targets.len()).sum(),
                disabled_reason: None,
            },
        }
    }
}

/// Diagnostics-safe connect ACL summary.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectAclSummary {
    pub enabled: bool,
    pub loaded_from: String,
    pub loaded_at_unix_ms: u64,
    pub allow_entry_count: usize,
    pub target_entry_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
}

/// Fully validated connect ACL.
#[derive(Debug, Clone)]
pub struct ConnectAcl {
    /// File the ACL was loaded from (provenance).
    pub loaded_from: PathBuf,
    /// When the ACL was loaded (provenance + diagnostics).
    pub loaded_at_unix_ms: u64,
    /// Allowed (agent, machine, target) triples. v1 has **no caps struct** —
    /// per-flow stream limits are T4 forwarder config, not ACL policy.
    pub allow: Vec<ConnectAllowEntry>,
}

impl ConnectAcl {
    /// Look up the allow entry for an exact (agent, machine) pair.
    #[must_use]
    pub fn entry_for(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
    ) -> Option<&ConnectAllowEntry> {
        self.allow
            .iter()
            .find(|e| &e.agent_id == agent_id && &e.machine_id == machine_id)
    }

    /// Exact-triple membership test: `true` iff `(agent, machine, target)` is
    /// an explicit allow entry. Note: `127.0.0.1:22` does **not** grant
    /// `\[::1\]:22`; matching is exact `SocketAddr` equality.
    #[must_use]
    pub fn is_allowed(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        target: &SocketAddr,
    ) -> bool {
        self.entry_for(agent_id, machine_id)
            .is_some_and(|e| e.targets.iter().any(|t| t == target))
    }
}

/// One allowed requester pair + their permitted loopback targets.
#[derive(Debug, Clone)]
pub struct ConnectAllowEntry {
    pub description: Option<String>,
    pub agent_id: AgentId,
    pub machine_id: MachineId,
    pub targets: Vec<SocketAddr>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Connect ACL load/validation error.
///
/// Mirrors [`crate::exec::acl::AclError`] shapes; the `Missing` vs `Read` vs
/// `Parse` vs `Invalid` split is what lets `--check` and daemon startup fail
/// loudly on a malformed/missing-at-explicit-path ACL.
#[derive(Debug, thiserror::Error)]
pub enum ConnectAclError {
    #[error("connect ACL file not found: {0}")]
    Missing(String),
    #[error("failed to read connect ACL {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse connect ACL {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("invalid connect ACL {path}: {reason}")]
    Invalid { path: String, reason: String },
}

// ---------------------------------------------------------------------------
// Load + parse (mirror exec control flow byte-for-byte)
// ---------------------------------------------------------------------------

/// Load a connect policy from an optional explicit path.
///
/// Control flow is identical to [`crate::exec::acl::load_exec_policy`]:
/// `!exists()` + `ExplicitPath` ⇒ `Err(Missing)`; `!exists()` + `DefaultPath`
/// ⇒ `Ok(Disabled{reason:"acl_missing"})`; read error ⇒ `Err(Read)`; else
/// parse.
///
/// # Errors
/// See [`ConnectAclError`].
pub async fn load_connect_policy(
    path: Option<&Path>,
    mode: LoadMode,
) -> Result<ConnectPolicy, ConnectAclError> {
    let acl_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_connect_acl_path);
    let loaded_at_unix_ms = now_unix_ms();
    if !acl_path.exists() {
        if mode == LoadMode::ExplicitPath {
            return Err(ConnectAclError::Missing(acl_path.display().to_string()));
        }
        return Ok(ConnectPolicy::Disabled {
            path: acl_path,
            reason: "acl_missing".to_string(),
            loaded_at_unix_ms,
        });
    }

    let text = tokio::fs::read_to_string(&acl_path)
        .await
        .map_err(|source| ConnectAclError::Read {
            path: acl_path.display().to_string(),
            source,
        })?;
    parse_connect_policy(&acl_path, loaded_at_unix_ms, &text)
}

/// Parse connect ACL TOML. Public for tests and `x0xd --check`.
///
/// # Errors
/// See [`ConnectAclError`]. Malformed TOML ⇒ `Parse`; a missing `[connect]`
/// section or `enabled = false` ⇒ `Disabled` (not an error); per-entry
/// validation failure ⇒ `Invalid` with `allow[{idx}].{field}: …` context.
pub fn parse_connect_policy(
    path: &Path,
    loaded_at_unix_ms: u64,
    text: &str,
) -> Result<ConnectPolicy, ConnectAclError> {
    // NOTE: `deny_unknown_fields` on all three structs (deliberate divergence
    // from exec — see ADR-0019). In a security allowlist, a misspelled key
    // (`taregts`, `enable`) must fail loudly, not silently yield a different
    // policy.
    let parsed: ConnectFileToml =
        toml::from_str(text).map_err(|source| ConnectAclError::Parse {
            path: path.display().to_string(),
            source,
        })?;
    let Some(connect) = parsed.connect else {
        return Ok(ConnectPolicy::Disabled {
            path: path.to_path_buf(),
            reason: "missing_connect_section".to_string(),
            loaded_at_unix_ms,
        });
    };
    if !connect.enabled {
        return Ok(ConnectPolicy::Disabled {
            path: path.to_path_buf(),
            reason: "connect_disabled".to_string(),
            loaded_at_unix_ms,
        });
    }

    let mut allow = Vec::with_capacity(connect.allow.len());
    for (idx, entry) in connect.allow.into_iter().enumerate() {
        let agent_id =
            parse_agent_id(&entry.agent_id).map_err(|reason| ConnectAclError::Invalid {
                path: path.display().to_string(),
                reason: format!("allow[{idx}].agent_id: {reason}"),
            })?;
        let machine_id =
            parse_machine_id(&entry.machine_id).map_err(|reason| ConnectAclError::Invalid {
                path: path.display().to_string(),
                reason: format!("allow[{idx}].machine_id: {reason}"),
            })?;
        if entry.targets.is_empty() {
            return Err(ConnectAclError::Invalid {
                path: path.display().to_string(),
                reason: format!("allow[{idx}] must contain at least one target"),
            });
        }
        // Each target must be a numeric-IP loopback address. parse_target is
        // the loopback-only crown jewel — every non-loopback address (and any
        // hostname such as `localhost`) is a hard error at load time.
        let mut targets = Vec::with_capacity(entry.targets.len());
        for (tidx, raw) in entry.targets.into_iter().enumerate() {
            let addr = parse_target(&raw).map_err(|reason| ConnectAclError::Invalid {
                path: path.display().to_string(),
                reason: format!("allow[{idx}].targets[{tidx}]: {reason}"),
            })?;
            targets.push(addr);
        }
        allow.push(ConnectAllowEntry {
            description: entry.description,
            agent_id,
            machine_id,
            targets,
        });
    }

    Ok(ConnectPolicy::Enabled(ConnectAcl {
        loaded_from: path.to_path_buf(),
        loaded_at_unix_ms,
        allow,
    }))
}

// ---------------------------------------------------------------------------
// Target validation — the loopback-only crown jewel
// ---------------------------------------------------------------------------

/// Parse + validate a single connect target as a loopback `SocketAddr`.
///
/// Rules (all failures are hard errors — used at load time):
/// 1. Numeric IP literal only (`SocketAddr::parse`). Any parse failure ⇒
///    error. **`localhost` is rejected** (doesn't parse as `SocketAddr`):
///    name resolution is ambiguous and removes the resolver from the TCB.
/// 2. Port `0` ⇒ error ("not a connectable target").
/// 3. Non-loopback IP ⇒ error naming the v1 policy (loopback-only).
/// 4. IPv4-mapped IPv6 (`\[::ffff:127.0.0.1\]:22`) is rejected with an
///    actionable message ("write it as 127.0.0.1:PORT") — `is_loopback()` is
///    already `false` for it, so step 3 catches it; this branch just improves
///    the message.
///
/// # Errors
/// Returns a human-readable `String` reason (never a panic) on any rejection.
pub fn parse_target(raw: &str) -> Result<SocketAddr, String> {
    // 1. Numeric IP:port only. `localhost:22` does NOT parse as SocketAddr.
    let addr: SocketAddr = raw.parse().map_err(|_| {
        "targets must be numeric IP:port (e.g. \"127.0.0.1:22\" or \"[::1]:22\"); \
         hostnames such as \"localhost\" are not accepted"
            .to_string()
    })?;

    // 2. Port 0 is not a connectable target.
    if addr.port() == 0 {
        return Err("port 0 is not a connectable target".to_string());
    }

    // 4. Diagnose IPv4-mapped IPv6 with an actionable message (correctness is
    // already handled by step 3 — is_loopback is false for v4-mapped — but the
    // generic message is unhelpful).
    if let std::net::IpAddr::V6(v6) = addr.ip() {
        if v6.to_ipv4_mapped().is_some() {
            return Err(format!(
                "IPv4-mapped IPv6 target {addr} is not loopback; write it as 127.0.0.1:{}",
                addr.port()
            ));
        }
    }

    // 3. Loopback-only (127.0.0.0/8 for v4, ::1 for v6).
    if !is_loopback(addr.ip()) {
        return Err(format!(
            "only loopback targets (127.0.0.0/8, ::1) are permitted in this release; \
             {addr} is not loopback (LAN/subnet targets are not supported)"
        ));
    }

    Ok(addr)
}

/// Loopback check factored for property-test reuse.
///
/// `Ipv4Addr::is_loopback()` covers all of 127.0.0.0/8; `Ipv6Addr::is_loopback()`
/// covers exactly `::1`. IPv4-mapped IPv6 (`::ffff:...`) is **not** loopback
/// under `Ipv6Addr::is_loopback()`, so it is correctly rejected.
#[must_use]
pub fn is_loopback(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// TOML schema (deny_unknown_fields — see ADR-0019)
// ---------------------------------------------------------------------------

// NOTE: `deny_unknown_fields` is on the `[connect]` section and the allow
// entries (the security property — a misspelled `taregts`/`enable` fails
// loudly), but NOT on the root file envelope, so other top-level sections
// (`[exec]`, `[logging]`, …) may coexist in a future unified config. This
// mirrors `exec::acl::AclFileToml` and is the deliberate deviation from the
// plan's literal "all three structs" — see ADR-0019.
#[derive(Debug, Deserialize)]
struct ConnectFileToml {
    connect: Option<ConnectSectionToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectSectionToml {
    /// Defaults to `false` when absent ⇒ Disabled. This is the fail-closed
    /// default: a file that forgets `enabled = true` disables connect.
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    allow: Vec<ConnectAllowEntryToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectAllowEntryToml {
    description: Option<String>,
    agent_id: String,
    machine_id: String,
    targets: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests (matrices A + B from the plan)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
