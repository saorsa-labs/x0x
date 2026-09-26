//! Connect ACL policy types, load, parse, validate.
//!
//! Connection-ACL (default-closed connectivity policy). Modeled line-by-line
//! on the exec ACL ([`crate::exec::acl`]); see ADR-0019 and
//! `docs/connect-acl.md`.
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

use crate::exec::acl::{parse_principal, AclPrincipal, LoadMode};
use crate::identity::{AgentId, MachineId};
use crate::server::InstanceName;

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
/// behaviour as the base default. [`InstanceName`] construction enforces the
/// shared CLI/config grammar before this function can derive a path.
#[must_use]
pub fn default_connect_acl_path_for(name: &InstanceName) -> PathBuf {
    let file = format!("connect-acl-{}.toml", name.as_str());
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
                allow_entry_count: acl.allow.len() + acl.owner_allow.len() + acl.grant_allow.len(),
                target_entry_count: acl.allow.iter().map(|e| e.targets.len()).sum::<usize>()
                    + acl
                        .owner_allow
                        .iter()
                        .chain(acl.grant_allow.iter())
                        .map(|e| e.targets.len())
                        .sum::<usize>(),
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
    /// `principal = "owner"` entries (ADR-0070 §1): targets allowed to any
    /// owner-trusted `(agent, machine)` pair. Kept apart from [`Self::allow`]
    /// so the exact-pair lookups ([`Self::entry_for`], [`Self::is_allowed`])
    /// keep their meaning; only the `*_for_principal` lookups consult it.
    pub owner_allow: Vec<ConnectOwnerEntry>,
    /// `principal = "grant"` entries (ADR-0070 §2): targets allowed to a
    /// requester holding a current ShareGrant whose `Connect { ports }`
    /// covers the target's port. Same shape as owner entries.
    pub grant_allow: Vec<ConnectOwnerEntry>,
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

    /// Whether the ACL has any `principal = "owner"` entry.
    #[must_use]
    pub fn has_owner_entries(&self) -> bool {
        !self.owner_allow.is_empty()
    }

    /// Whether any entry names this requester: an exact `(agent, machine)`
    /// pair, or — only when `owner_trusted` — a `principal = "owner"` entry.
    ///
    /// `owner_trusted` must come from [`crate::owner_trust`]; passing `false`
    /// reduces this to the exact-pair check.
    #[must_use]
    pub fn has_entry_for_principal(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        owner_trusted: bool,
    ) -> bool {
        self.entry_for(agent_id, machine_id).is_some()
            || (owner_trusted && self.has_owner_entries())
    }

    /// Exact-target membership test across both selectors: the exact pair's
    /// targets, plus — only when `owner_trusted` — every `principal =
    /// "owner"` entry's targets. Target matching stays exact `SocketAddr`
    /// equality for both.
    #[must_use]
    pub fn is_allowed_for_principal(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        owner_trusted: bool,
        target: &SocketAddr,
    ) -> bool {
        self.is_allowed(agent_id, machine_id, target)
            || (owner_trusted
                && self
                    .owner_allow
                    .iter()
                    .any(|e| e.targets.iter().any(|t| t == target)))
    }

    /// [`Self::has_entry_for_principal`] plus — only when `grant_connect`
    /// (the requester holds a current `Connect` grant) — a `principal =
    /// "grant"` entry.
    #[must_use]
    pub fn has_entry_for_principals(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        owner_trusted: bool,
        grant_connect: bool,
    ) -> bool {
        self.has_entry_for_principal(agent_id, machine_id, owner_trusted)
            || (grant_connect && !self.grant_allow.is_empty())
    }

    /// [`Self::is_allowed_for_principal`] plus the ADR-0070 §2 grant
    /// selector: a `principal = "grant"` entry listing exactly `target`
    /// matches only when `grant_port_allowed` — the requester's current
    /// `Connect { ports }` grant covers `target.port()`. Both the entry and
    /// the grant must allow the target.
    #[must_use]
    pub fn is_allowed_for_principals(
        &self,
        agent_id: &AgentId,
        machine_id: &MachineId,
        owner_trusted: bool,
        grant_port_allowed: bool,
        target: &SocketAddr,
    ) -> bool {
        self.is_allowed_for_principal(agent_id, machine_id, owner_trusted, target)
            || (grant_port_allowed
                && self
                    .grant_allow
                    .iter()
                    .any(|e| e.targets.iter().any(|t| t == target)))
    }
}

/// One `principal = "owner"` entry (ADR-0070 §1): loopback targets allowed
/// to any owner-trusted pair. Targets are explicit, exactly as for pairs.
#[derive(Debug, Clone)]
pub struct ConnectOwnerEntry {
    pub description: Option<String>,
    pub targets: Vec<SocketAddr>,
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
    let mut owner_allow = Vec::new();
    let mut grant_allow = Vec::new();
    for (idx, entry) in connect.allow.into_iter().enumerate() {
        match build_connect_entry(path, &format!("allow[{idx}]"), entry)? {
            BuiltConnectEntry::Pair(entry) => allow.push(entry),
            BuiltConnectEntry::Owner(entry) => owner_allow.push(entry),
            BuiltConnectEntry::Grant(entry) => grant_allow.push(entry),
        }
    }

    Ok(ConnectPolicy::Enabled(ConnectAcl {
        loaded_from: path.to_path_buf(),
        loaded_at_unix_ms,
        allow,
        owner_allow,
        grant_allow,
    }))
}

/// One validated entry, split by requester selector.
enum BuiltConnectEntry {
    Pair(ConnectAllowEntry),
    Owner(ConnectOwnerEntry),
    Grant(ConnectOwnerEntry),
}

/// Validate one allow entry — the single code path for TOML floor entries
/// and ADR-0070 §3 API-managed entries alike. `label` names the entry in
/// error messages (`allow[3]`, `api[0]`).
fn build_connect_entry(
    path: &Path,
    label: &str,
    entry: ConnectAclEntrySpec,
) -> Result<BuiltConnectEntry, ConnectAclError> {
    let principal = parse_principal(
        entry.principal.as_deref(),
        entry.agent_id.as_deref(),
        entry.machine_id.as_deref(),
    )
    .map_err(|reason| ConnectAclError::Invalid {
        path: path.display().to_string(),
        reason: format!("{label}: {reason}"),
    })?;
    if entry.targets.is_empty() {
        return Err(ConnectAclError::Invalid {
            path: path.display().to_string(),
            reason: format!("{label} must contain at least one target"),
        });
    }
    // Each target must be a numeric-IP loopback address. parse_target is
    // the loopback-only crown jewel — every non-loopback address (and any
    // hostname such as `localhost`) is a hard error at load time.
    let mut targets = Vec::with_capacity(entry.targets.len());
    for (tidx, raw) in entry.targets.into_iter().enumerate() {
        let addr = parse_target(&raw).map_err(|reason| ConnectAclError::Invalid {
            path: path.display().to_string(),
            reason: format!("{label}.targets[{tidx}]: {reason}"),
        })?;
        targets.push(addr);
    }
    Ok(match principal {
        AclPrincipal::Pair {
            agent_id,
            machine_id,
        } => BuiltConnectEntry::Pair(ConnectAllowEntry {
            description: entry.description,
            agent_id,
            machine_id,
            targets,
        }),
        AclPrincipal::Owner => BuiltConnectEntry::Owner(ConnectOwnerEntry {
            description: entry.description,
            targets,
        }),
        AclPrincipal::Grant => BuiltConnectEntry::Grant(ConnectOwnerEntry {
            description: entry.description,
            targets,
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
/// [`ConnectAclError::Invalid`] naming the offending field.
pub fn validate_connect_entry_spec(
    path: &Path,
    spec: &ConnectAclEntrySpec,
) -> Result<(), ConnectAclError> {
    build_connect_entry(path, "api", spec.clone()).map(|_| ())
}

/// Effective policy = TOML floor ∪ API overlay (ADR-0070 §3).
///
/// A `Disabled` floor stays `Disabled`: overlay entries never enable a
/// plane the operator's file leaves off. Every overlay entry is validated
/// by the same code path as a floor entry; one invalid entry fails the
/// whole composition (fail closed — callers keep the last good policy).
///
/// # Errors
/// [`ConnectAclError::Invalid`] naming the offending `api[i]` entry.
pub fn compose_connect_policy(
    floor: &ConnectPolicy,
    overlay: &[ConnectAclEntrySpec],
) -> Result<ConnectPolicy, ConnectAclError> {
    let ConnectPolicy::Enabled(floor_acl) = floor else {
        return Ok(floor.clone());
    };
    let mut acl = floor_acl.clone();
    for (idx, spec) in overlay.iter().enumerate() {
        match build_connect_entry(&acl.loaded_from, &format!("api[{idx}]"), spec.clone())? {
            BuiltConnectEntry::Pair(entry) => acl.allow.push(entry),
            BuiltConnectEntry::Owner(entry) => acl.owner_allow.push(entry),
            BuiltConnectEntry::Grant(entry) => acl.grant_allow.push(entry),
        }
    }
    Ok(ConnectPolicy::Enabled(acl))
}

/// Whether `next` may replace `current` by hot reload (ADR-0070 §3).
///
/// Only allow entries are hot-reloadable. Flipping the plane between
/// enabled and disabled is refused: the forwarder is only started for an
/// enabled policy at boot, and a `Disabled` connect policy lifts the
/// byte-stream accept constraint entirely, so a reload that disables
/// connect would widen access. Both directions require a restart.
///
/// # Errors
/// A human-readable reason.
pub fn connect_reload_compatible(
    current: &ConnectPolicy,
    next: &ConnectPolicy,
) -> Result<(), String> {
    if current.enabled() != next.enabled() {
        return Err(format!(
            "reload would change connect from {} to {}; enabling or disabling the \
             connect plane requires a daemon restart",
            enabled_word(current.enabled()),
            enabled_word(next.enabled())
        ));
    }
    Ok(())
}

fn enabled_word(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

impl ConnectAllowEntry {
    /// The entry in its TOML/API schema form (for listings).
    #[must_use]
    pub fn to_spec(&self) -> ConnectAclEntrySpec {
        ConnectAclEntrySpec {
            description: self.description.clone(),
            principal: None,
            agent_id: Some(hex::encode(self.agent_id.as_bytes())),
            machine_id: Some(hex::encode(self.machine_id.as_bytes())),
            targets: self.targets.iter().map(ToString::to_string).collect(),
        }
    }
}

impl ConnectOwnerEntry {
    /// The entry in its TOML/API schema form (for listings).
    #[must_use]
    pub fn to_spec(&self) -> ConnectAclEntrySpec {
        self.to_spec_as("owner")
    }

    /// The entry as a `principal = "grant"` spec (ADR-0070 §2).
    #[must_use]
    pub fn to_grant_spec(&self) -> ConnectAclEntrySpec {
        self.to_spec_as("grant")
    }

    fn to_spec_as(&self, principal: &str) -> ConnectAclEntrySpec {
        ConnectAclEntrySpec {
            description: self.description.clone(),
            principal: Some(principal.to_string()),
            agent_id: None,
            machine_id: None,
            targets: self.targets.iter().map(ToString::to_string).collect(),
        }
    }
}

impl ConnectAcl {
    /// Every entry in TOML/API schema form: exact pairs, then owner
    /// entries, then grant entries.
    #[must_use]
    pub fn entry_specs(&self) -> Vec<ConnectAclEntrySpec> {
        self.allow
            .iter()
            .map(ConnectAllowEntry::to_spec)
            .chain(self.owner_allow.iter().map(ConnectOwnerEntry::to_spec))
            .chain(
                self.grant_allow
                    .iter()
                    .map(ConnectOwnerEntry::to_grant_spec),
            )
            .collect()
    }
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
    allow: Vec<ConnectAclEntrySpec>,
}

/// One connect allow entry in its wire schema — the `[[connect.allow]]`
/// TOML table and, identically, the `POST /acl/connect` JSON body
/// (ADR-0070 §3). `deny_unknown_fields` applies to both surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectAclEntrySpec {
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
    /// Loopback `IP:port` targets (numeric, exact).
    pub targets: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests (matrices A + B from the plan)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
