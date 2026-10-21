//! Names for agents and machines (ADR-0074 §1, slice 1).
//!
//! Grammar (CLI/REST): `[agent:|machine:]<label>.<owner>`. Both parts follow
//! DNS-label rules: lowercase `[a-z0-9-]`, 1–63 characters, no leading or
//! trailing hyphen. `me`, `agent` and `machine` are reserved labels; `me`
//! is valid only as the owner part and names this install's owner
//! (ADR-0036). A 64-character hex `AgentId` stays valid wherever a name is
//! accepted.
//!
//! - **Owner label → `UserId`** is a local petname in [`NameStore`], never a
//!   network claim. A signed contact card binds its `owner_name` only when
//!   that contact is Known or Trusted. Unknown and Blocked stay unbound.
//!   The local owner can still bind a label explicitly. A label is frozen
//!   at first bind: rebinding it to a different key fails with
//!   [`NameError::PinMismatch`] until the owner removes the label.
//! - **Agent label** matches the announced self-name of an agent whose
//!   valid, unexpired, unrevoked `AgentCertificate` chains to that owner.
//! - **Machine label** (own machines) matches the ADR-0036 `machine_name`
//!   synced for a machine holding a current ADR-0041 `OwnerEnrollment` by
//!   the local owner. **Shared machines** are machines hosting an agent of an
//!   active received ADR-0070 `ShareGrant` from that owner; the local owner
//!   labels them explicitly ([`crate::Agent::label_shared_machine`]).
//! - Every successful resolution is **pinned at first use** (TOFU): the
//!   canonical name records the id it resolved to, and a later resolution to
//!   a different id fails loud with [`NameError::PinMismatch`]. A bare name
//!   that matches both an agent and a machine is [`NameError::AmbiguousKind`]
//!   even when a pin already exists (ADR-0074 §1). `PinMismatch` applies only
//!   when one pin exists and the single remaining candidate's kind differs
//!   from that pin. That path writes no second pin. Nothing silently rebinds;
//!   the owner re-pins by removing the pin.
//!
//! Resolution is local, makes no network query and adds **no trust**: it
//! only maps a name to an id. The identity gate, the contact rules and the
//! connect ACL still decide whether anything may be reached.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::identity::{AgentCertificate, AgentId, MachineId, UserId};
use crate::owner_sync::OwnerEnrollment;
use crate::share_grant::ShareGrant;

/// File name of the name store inside the instance data dir.
pub const NAMES_STORE_FILE: &str = "names.json";

/// The owner label that names this install's owner.
pub const LOCAL_OWNER_LABEL: &str = "me";

/// Labels that can never be bound as an agent, machine or owner petname.
pub const RESERVED_LABELS: [&str; 3] = ["me", "agent", "machine"];

/// Longest label (DNS-label rule).
pub const MAX_LABEL_LEN: usize = 63;

/// Most owner petnames the store holds.
pub const MAX_OWNER_LABELS: usize = 1024;

/// Most pins the store holds.
pub const MAX_PINS: usize = 4096;

const STORE_VERSION: u32 = 1;

/// Which kind of target a name addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameKind {
    /// An agent (`AgentId`).
    Agent,
    /// A machine (`MachineId`).
    Machine,
}

impl NameKind {
    /// The name prefix (`agent` / `machine`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Machine => "machine",
        }
    }
}

/// Why a name was refused. Every variant is a refusal: nothing resolves.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The input does not follow the grammar.
    #[error("invalid name: {0}")]
    Invalid(String),
    /// A reserved label (`me`, `agent`, `machine`) was used as a label.
    #[error("reserved label: {0}")]
    Reserved(String),
    /// No owner petname, agent or machine by that name.
    #[error("unknown name: {0}")]
    UnknownName(String),
    /// Something claims the name, but without a valid certificate chain,
    /// enrollment or grant.
    #[error("unverified owner: {0}")]
    UnverifiedOwner(String),
    /// Two candidates of one kind carry the name.
    #[error("ambiguous name {name}: candidates {}", candidates.join(", "))]
    AmbiguousName {
        /// The name as given.
        name: String,
        /// Hex ids of every candidate.
        candidates: Vec<String>,
    },
    /// A bare label names both an agent and a machine.
    #[error(
        "ambiguous kind: {0} names both an agent and a machine; retry with agent: or machine:"
    )]
    AmbiguousKind(String),
    /// The name is pinned to a different key than it now resolves to.
    #[error("pin mismatch: {name} is pinned to {pinned} but now resolves to {current}")]
    PinMismatch {
        /// The canonical name (or owner label).
        name: String,
        /// The pinned id (hex).
        pinned: String,
        /// The id it resolves to now (hex).
        current: String,
    },
    /// A machine name was given where only agent targets are accepted.
    ///
    /// `POST /forwards` does not use this: a machine name is a valid forward
    /// target and is pinned (ADR-0074 slice 2). Agent-only resolution still
    /// returns it, and does so before any pin is written.
    #[error("machine names are not accepted here: {0}")]
    MachineTargetUnsupported(String),
    /// The store could not be read or written (fail closed).
    #[error("name store: {0}")]
    Store(String),
}

impl NameError {
    /// Stable machine-readable code for REST bodies.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_name",
            Self::Reserved(_) => "reserved_label",
            Self::UnknownName(_) => "unknown_name",
            Self::UnverifiedOwner(_) => "unverified_owner",
            Self::AmbiguousName { .. } => "ambiguous_name",
            Self::AmbiguousKind(_) => "ambiguous_kind",
            Self::PinMismatch { .. } => "pin_mismatch",
            Self::MachineTargetUnsupported(_) => "machine_target_unsupported",
            Self::Store(_) => "name_store",
        }
    }
}

/// Validate one DNS label (`[a-z0-9-]`, 1–63, no edge hyphen).
///
/// # Errors
/// [`NameError::Invalid`] naming the rule broken.
pub fn validate_label(label: &str) -> Result<(), NameError> {
    if label.is_empty() {
        return Err(NameError::Invalid("empty label".into()));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(NameError::Invalid(format!(
            "label longer than {MAX_LABEL_LEN} characters"
        )));
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(NameError::Invalid(format!(
            "{label:?}: labels are lowercase [a-z0-9-]"
        )));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(NameError::Invalid(format!(
            "{label:?}: a label cannot start or end with '-'"
        )));
    }
    Ok(())
}

fn is_reserved(label: &str) -> bool {
    RESERVED_LABELS.contains(&label)
}

/// Announce `self_name` is a verified agent label only when the announce's
/// machine equals the authority-selected machine for that agent.
///
/// V3 announces are machine-signed. The caller passes the machine from the
/// ADR 0115 authority rules (announced binding, authenticated binding, or a
/// usable ADR 0089 record). A mismatch, a missing authority machine, or the
/// all-zero id drops the label. Used when gathering name candidates.
#[must_use]
pub fn verified_announce_self_name(
    announce_machine: MachineId,
    authority_machine: Option<MachineId>,
    announce_self_name: Option<String>,
) -> Option<String> {
    match (authority_machine, announce_self_name) {
        (Some(authority), name)
            if authority == announce_machine && announce_machine.0 != [0u8; 32] =>
        {
            name
        }
        _ => None,
    }
}

/// Map a free-form display name (announced self-name, synced
/// `machine_name`, card `owner_name`) to the label it answers to.
///
/// ASCII letters are lowercased; runs of whitespace, `_`, `.` and `-`
/// become one `-`. Any other character, an empty result, an over-long
/// result or a reserved label yields `None`: such a name answers to no
/// label (fail closed; the owner can still bind or pin explicitly).
#[must_use]
pub fn label_from_display(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    let mut pending_dash = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() || matches!(ch, '_' | '.' | '-') {
            pending_dash = true;
        } else {
            return None;
        }
    }
    if validate_label(&out).is_err() || is_reserved(&out) {
        return None;
    }
    Some(out)
}

/// A parsed `[agent:|machine:]<label>.<owner>` name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRef {
    /// Explicit kind prefix, if any.
    pub kind: Option<NameKind>,
    /// The agent or machine label.
    pub label: String,
    /// The owner label (`me` or a local petname).
    pub owner: String,
}

impl NameRef {
    /// Parse a name. No trimming or case folding: anything outside the
    /// grammar is refused.
    ///
    /// # Errors
    /// [`NameError::Invalid`] or [`NameError::Reserved`].
    pub fn parse(raw: &str) -> Result<Self, NameError> {
        let (kind, rest) = if let Some(rest) = raw.strip_prefix("agent:") {
            (Some(NameKind::Agent), rest)
        } else if let Some(rest) = raw.strip_prefix("machine:") {
            (Some(NameKind::Machine), rest)
        } else {
            (None, raw)
        };
        if rest.contains(':') {
            return Err(NameError::Invalid(format!(
                "{raw:?}: the only prefixes are agent: and machine:"
            )));
        }
        let mut parts = rest.split('.');
        let (Some(label), Some(owner), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(NameError::Invalid(format!(
                "{raw:?}: expected [agent:|machine:]<label>.<owner>"
            )));
        };
        validate_label(label)?;
        validate_label(owner)?;
        if is_reserved(label) {
            return Err(NameError::Reserved(label.to_string()));
        }
        if owner != LOCAL_OWNER_LABEL && is_reserved(owner) {
            return Err(NameError::Reserved(owner.to_string()));
        }
        Ok(Self {
            kind,
            label: label.to_string(),
            owner: owner.to_string(),
        })
    }

    /// Whether the owner part is `me`.
    #[must_use]
    pub fn is_local_owner(&self) -> bool {
        self.owner == LOCAL_OWNER_LABEL
    }

    /// The canonical, kind-prefixed spelling used as the pin key.
    #[must_use]
    pub fn canonical(&self, kind: NameKind) -> String {
        format!("{}:{}.{}", kind.as_str(), self.label, self.owner)
    }
}

impl std::fmt::Display for NameRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            Some(kind) => write!(f, "{}:{}.{}", kind.as_str(), self.label, self.owner),
            None => write!(f, "{}.{}", self.label, self.owner),
        }
    }
}

/// A peer given as hex or as a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRef {
    /// A 64-hex-character `AgentId`.
    Hex(AgentId),
    /// A name, still to be resolved.
    Name(NameRef),
}

impl PeerRef {
    /// Parse hex (exactly 64 hex characters) or a name.
    ///
    /// # Errors
    /// Any [`NameRef::parse`] error.
    pub fn parse(raw: &str) -> Result<Self, NameError> {
        if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut id = [0u8; 32];
            hex::decode_to_slice(raw, &mut id)
                .map_err(|e| NameError::Invalid(format!("agent id: {e}")))?;
            return Ok(Self::Hex(AgentId(id)));
        }
        NameRef::parse(raw).map(Self::Name)
    }

    /// Parse a forward peer: hex or a name (agent or machine).
    ///
    /// # Errors
    /// Any parse error.
    pub fn parse_forward_peer(raw: &str) -> Result<Self, NameError> {
        Self::parse(raw)
    }
}

/// Where a forward to a resolved name goes: the agent its streams open to,
/// and — for a machine name — the `MachineId` every stream must reach
/// (ADR-0074 §1 machine binding; the forwarder checks `PeerStream::peer()`
/// against it before any forward-header byte is sent).
///
/// # Errors
/// [`NameError::UnknownName`] when a machine name has no single agent that
/// its daemon announces (nothing to open a stream to).
pub fn forward_target(
    resolved: &Resolved,
    name: &NameRef,
) -> Result<(AgentId, Option<MachineId>), NameError> {
    match (resolved.kind, resolved.agent_id, resolved.machine_id) {
        (NameKind::Agent, Some(agent), _) => Ok((agent, None)),
        (NameKind::Machine, Some(agent), Some(machine)) => Ok((agent, Some(machine))),
        _ => Err(NameError::UnknownName(format!(
            "{name}: no single agent is announced on that machine"
        ))),
    }
}

// ─── Candidates ────────────────────────────────────────────────────────────

/// An agent that claims the owner, with its announced name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCandidate {
    /// The agent.
    pub agent_id: AgentId,
    /// The label its announced self-name answers to, when DNS-compatible.
    ///
    /// `None` when the agent has no display name or a name that cannot
    /// become a DNS label (Unicode, reserved, …). Such agents never match
    /// an agent name, but their verified machine binding still supports
    /// shared-machine (and sole-agent) resolution.
    pub label: Option<String>,
    /// Its authenticated machine, if known.
    pub machine_id: Option<MachineId>,
    /// Valid, unexpired, unrevoked certificate chaining to the owner.
    pub verified: bool,
}

/// A machine that carries a label for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineCandidate {
    /// The machine.
    pub machine_id: MachineId,
    /// Its label.
    pub label: String,
    /// Current enrollment (own) or active grant (shared).
    pub verified: bool,
    /// The agent a stream to this machine would open to, when exactly one
    /// qualifies (own: owner-certified agent bound there; shared: granted
    /// agent bound there).
    pub agent_id: Option<AgentId>,
}

/// Everything resolution may match for one owner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidates {
    /// Agents.
    pub agents: Vec<AgentCandidate>,
    /// Machines.
    pub machines: Vec<MachineCandidate>,
}

/// One discovered agent, as the gatherer sees it.
#[derive(Debug, Clone)]
pub struct ObservedAgent {
    /// The agent.
    pub agent_id: AgentId,
    /// The user id it announces, if any.
    pub announced_user: Option<UserId>,
    /// Its cached certificate, if any.
    pub certificate: Option<AgentCertificate>,
    /// Its announced self-name.
    pub self_name: Option<String>,
    /// Its authenticated machine binding.
    pub machine_id: Option<MachineId>,
    /// Whether the agent (or its machine) is revoked.
    pub revoked: bool,
}

/// Agents that claim `owner` (by announced user id or certificate), each
/// marked verified only when its certificate chains to `owner`.
#[must_use]
pub fn agent_candidates(
    owner: &UserId,
    observed: &[ObservedAgent],
    now_unix: u64,
) -> Vec<AgentCandidate> {
    let mut out: BTreeMap<[u8; 32], AgentCandidate> = BTreeMap::new();
    for agent in observed {
        let cert_user = agent.certificate.as_ref().and_then(|c| c.user_id().ok());
        if agent.announced_user != Some(*owner) && cert_user != Some(*owner) {
            continue;
        }
        // Agent-label matching needs a DNS-compatible self-name; machine
        // eligibility (shared / sole-agent) uses verified binding only.
        let label = agent.self_name.as_deref().and_then(label_from_display);
        let verified = agent.certificate.as_ref().is_some_and(|cert| {
            crate::owner_trust::certificate_chains_to_owner(
                owner,
                &agent.agent_id,
                cert,
                agent.revoked,
                now_unix,
            )
        });
        let entry = AgentCandidate {
            agent_id: agent.agent_id,
            label,
            machine_id: agent.machine_id,
            verified,
        };
        // A verified observation of an agent wins over an unverified one.
        match out.get(&agent.agent_id.0) {
            Some(held) if held.verified && !entry.verified => {}
            _ => {
                out.insert(agent.agent_id.0, entry);
            }
        }
    }
    out.into_values().collect()
}

/// Exactly one verified agent bound to `machine`, else `None`.
fn sole_agent_on(agents: &[AgentCandidate], machine: &MachineId) -> Option<AgentId> {
    let on: BTreeSet<[u8; 32]> = agents
        .iter()
        .filter(|a| a.verified && a.machine_id.as_ref() == Some(machine))
        .map(|a| a.agent_id.0)
        .collect();
    if on.len() == 1 {
        on.into_iter().next().map(AgentId)
    } else {
        None
    }
}

/// The local owner's machines: every machine with a synced name, verified
/// only when it holds a current `OwnerEnrollment` signed by `owner` and is
/// not revoked. `names` are `(machine, synced machine_name)` pairs.
#[must_use]
pub fn own_machine_candidates(
    owner: &UserId,
    enrollments: &[OwnerEnrollment],
    names: &[(MachineId, String)],
    revoked_machines: &BTreeSet<[u8; 32]>,
    agents: &[AgentCandidate],
    now_ms: u64,
) -> Vec<MachineCandidate> {
    let enrolled: BTreeSet<[u8; 32]> = enrollments
        .iter()
        .filter(|e| e.verify_owner(owner).is_ok() && e.is_current_at(now_ms))
        .map(|e| e.machine_id)
        .collect();
    names
        .iter()
        .filter_map(|(machine, name)| {
            let label = label_from_display(name)?;
            let verified = enrolled.contains(&machine.0) && !revoked_machines.contains(&machine.0);
            Some(MachineCandidate {
                machine_id: *machine,
                label,
                verified,
                agent_id: if verified {
                    sole_agent_on(agents, machine)
                } else {
                    None
                },
            })
        })
        .collect()
}

/// Another owner's shared machines: every machine the local owner labelled
/// under that owner (`labels`: `(label, machine)`), verified only while it
/// hosts an agent of an active, unrevoked received grant signed by `owner`
/// whose certificate chains to `owner` (`agents` holds the verification).
#[must_use]
pub fn shared_machine_candidates(
    owner: &UserId,
    labels: &[(String, MachineId)],
    received: &[(ShareGrant, bool)],
    agents: &[AgentCandidate],
    revoked_machines: &BTreeSet<[u8; 32]>,
    now_unix: u64,
) -> Vec<MachineCandidate> {
    let granted: BTreeSet<[u8; 32]> = received
        .iter()
        .filter(|(g, revoked)| !revoked && g.owner == *owner && g.is_active_at(now_unix))
        .flat_map(|(g, _)| g.agents.iter().map(|a| a.0))
        .collect();
    labels
        .iter()
        .map(|(label, machine)| {
            let hosted: BTreeSet<[u8; 32]> = agents
                .iter()
                .filter(|a| {
                    a.verified
                        && a.machine_id.as_ref() == Some(machine)
                        && granted.contains(&a.agent_id.0)
                })
                .map(|a| a.agent_id.0)
                .collect();
            let verified = !hosted.is_empty() && !revoked_machines.contains(&machine.0);
            MachineCandidate {
                machine_id: *machine,
                label: label.clone(),
                verified,
                agent_id: if verified && hosted.len() == 1 {
                    hosted.into_iter().next().map(AgentId)
                } else {
                    None
                },
            }
        })
        .collect()
}

/// What a name selects before pinning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// Agent or machine.
    pub kind: NameKind,
    /// The pinned id (`AgentId` or `MachineId` bytes).
    pub id: [u8; 32],
    /// The agent a stream would open to.
    pub agent_id: Option<AgentId>,
    /// The machine, for a machine target.
    pub machine_id: Option<MachineId>,
}

/// Select the single target `name` denotes among `candidates` (pure).
///
/// # Errors
/// `AmbiguousKind`, `AmbiguousName`, `UnverifiedOwner` or `UnknownName`.
pub fn select(name: &NameRef, candidates: &Candidates) -> Result<Selection, NameError> {
    let want_agent = name.kind != Some(NameKind::Machine);
    let want_machine = name.kind != Some(NameKind::Agent);
    let agents: BTreeMap<[u8; 32], &AgentCandidate> = if want_agent {
        candidates
            .agents
            .iter()
            .filter(|a| a.verified && a.label.as_deref() == Some(name.label.as_str()))
            .map(|a| (a.agent_id.0, a))
            .collect()
    } else {
        BTreeMap::new()
    };
    let machines: BTreeMap<[u8; 32], &MachineCandidate> = if want_machine {
        candidates
            .machines
            .iter()
            .filter(|m| m.verified && m.label == name.label)
            .map(|m| (m.machine_id.0, m))
            .collect()
    } else {
        BTreeMap::new()
    };
    if name.kind.is_none() && !agents.is_empty() && !machines.is_empty() {
        return Err(NameError::AmbiguousKind(name.to_string()));
    }
    if agents.len() > 1 {
        return Err(NameError::AmbiguousName {
            name: name.to_string(),
            candidates: agents.keys().map(hex::encode).collect(),
        });
    }
    if machines.len() > 1 {
        return Err(NameError::AmbiguousName {
            name: name.to_string(),
            candidates: machines.keys().map(hex::encode).collect(),
        });
    }
    if let Some((agent, _)) = agents.into_iter().next() {
        return Ok(Selection {
            kind: NameKind::Agent,
            id: agent,
            agent_id: Some(AgentId(agent)),
            machine_id: None,
        });
    }
    if let Some((machine, candidate)) = machines.into_iter().next() {
        return Ok(Selection {
            kind: NameKind::Machine,
            id: machine,
            agent_id: candidate.agent_id,
            machine_id: Some(MachineId(machine)),
        });
    }
    let claimed = (want_agent
        && candidates
            .agents
            .iter()
            .any(|a| !a.verified && a.label.as_deref() == Some(name.label.as_str())))
        || (want_machine
            && candidates
                .machines
                .iter()
                .any(|m| !m.verified && m.label == name.label));
    if claimed {
        Err(NameError::UnverifiedOwner(format!(
            "{name}: claimed without a valid certificate chain, enrollment or grant"
        )))
    } else {
        Err(NameError::UnknownName(name.to_string()))
    }
}

// ─── Store ─────────────────────────────────────────────────────────────────

/// How a binding or pin was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindSource {
    /// From an imported, signed contact card's `owner_name`.
    Card,
    /// Explicitly by the local owner (REST/CLI).
    Manual,
    /// Pinned at the first successful resolution.
    FirstUse,
}

/// An owner petname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerBinding {
    /// The bound owner.
    pub user_id: UserId,
    /// Unix seconds bound.
    pub bound_at: u64,
    /// How it was bound.
    pub source: BindSource,
}

/// A pinned name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamePin {
    /// The pinned `AgentId` / `MachineId` bytes.
    pub id: [u8; 32],
    /// The owner the name was resolved under.
    pub owner: UserId,
    /// Unix seconds pinned.
    pub pinned_at: u64,
    /// How it was pinned.
    pub source: BindSource,
}

/// Outcome of a bind or pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// Newly recorded (and durable).
    Inserted,
    /// Already recorded with the same key.
    Unchanged,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRecord {
    user_id: String,
    bound_at: u64,
    source: BindSource,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    id: String,
    owner: String,
    pinned_at: u64,
    source: BindSource,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamesFile {
    version: u32,
    owners: BTreeMap<String, OwnerRecord>,
    pins: BTreeMap<String, PinRecord>,
}

#[derive(Debug, Default, Clone)]
struct NamesState {
    owners: BTreeMap<String, OwnerBinding>,
    pins: BTreeMap<String, NamePin>,
}

fn decode32(field: &str, raw: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(raw, &mut out).map_err(|e| format!("{field}: {e}"))?;
    Ok(out)
}

/// Split a canonical pin key into `(kind, NameRef)`, refusing anything that
/// is not exactly canonical.
fn parse_pin_key(key: &str) -> Result<(NameKind, NameRef), NameError> {
    let name = NameRef::parse(key)?;
    let kind = name.kind.ok_or_else(|| {
        NameError::Invalid(format!("{key:?}: a pin key needs agent: or machine:"))
    })?;
    Ok((kind, name))
}

impl NamesState {
    fn from_file(file: NamesFile) -> Result<Self, String> {
        if file.version != STORE_VERSION {
            return Err(format!("unsupported names.json version {}", file.version));
        }
        if file.owners.len() > MAX_OWNER_LABELS || file.pins.len() > MAX_PINS {
            return Err("names.json exceeds its size bounds".into());
        }
        let mut state = Self::default();
        for (label, record) in file.owners {
            validate_label(&label).map_err(|e| e.to_string())?;
            if is_reserved(&label) {
                return Err(format!("owner label {label:?} is reserved"));
            }
            state.owners.insert(
                label,
                OwnerBinding {
                    user_id: UserId(decode32("owner user_id", &record.user_id)?),
                    bound_at: record.bound_at,
                    source: record.source,
                },
            );
        }
        for (key, record) in file.pins {
            parse_pin_key(&key).map_err(|e| e.to_string())?;
            state.pins.insert(
                key,
                NamePin {
                    id: decode32("pin id", &record.id)?,
                    owner: UserId(decode32("pin owner", &record.owner)?),
                    pinned_at: record.pinned_at,
                    source: record.source,
                },
            );
        }
        Ok(state)
    }

    fn to_file(&self) -> NamesFile {
        NamesFile {
            version: STORE_VERSION,
            owners: self
                .owners
                .iter()
                .map(|(label, b)| {
                    (
                        label.clone(),
                        OwnerRecord {
                            user_id: hex::encode(b.user_id.as_bytes()),
                            bound_at: b.bound_at,
                            source: b.source,
                        },
                    )
                })
                .collect(),
            pins: self
                .pins
                .iter()
                .map(|(key, p)| {
                    (
                        key.clone(),
                        PinRecord {
                            id: hex::encode(p.id),
                            owner: hex::encode(p.owner.as_bytes()),
                            pinned_at: p.pinned_at,
                            source: p.source,
                        },
                    )
                })
                .collect(),
        }
    }
}

/// Persistent owner petnames and name pins (`<data_dir>/names.json`).
///
/// Versioned JSON with `deny_unknown_fields`, written durably with mode
/// `0600` (temp file, fsync, atomic rename). A missing file is an empty
/// store; an unreadable or malformed file leaves the store holding nothing
/// and refusing every name operation ([`NameError::Store`]), so pins are
/// never silently lost and re-learned. All mutations are serialised under
/// one lock held across the durable write. `commit` runs the lock, the
/// write, and the memory install on a task the caller cannot cancel.
/// Dropping the caller's future detaches the task, which keeps the
/// lock until memory matches the published file. A sync rename still
/// publishes if that task is cancelled at its own await. A failure before
/// the rename leaves memory and disk on the old state; a failure after the
/// rename keeps the new state in memory so it matches the advanced disk
/// (issue #1101) and raises a pending-durability flag until a later write
/// confirms the parent-directory fsync. Load syncs a visible file and its
/// directory. If that sync fails, the flag stays set across restart. An
/// identical retry must not ACK as [`BindOutcome::Unchanged`] while that
/// flag is set.
#[derive(Debug)]
pub struct NameStore {
    path: Option<PathBuf>,
    state: std::sync::Arc<tokio::sync::Mutex<NamesState>>,
    load_error: Option<String>,
    /// Set when a write crossed the rename but parent-dir fsync failed.
    /// Cleared only by a successful durable persist. While set, `commit`
    /// re-attempts the write even when the mutate is a no-op.
    pending_durability: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Staged by the post-rename callback; drained into [`Self::state`]
    /// under the lock so a cancelled persist await cannot lose the
    /// advanced disk state (Send-safe; no raw pointers in the future).
    install_slot: std::sync::Arc<std::sync::Mutex<Option<NamesState>>>,
    /// Tasks blocked in [`Self::lock_state`], not the holder. The rename
    /// cancellation test waits until a later write is queued on this lock.
    #[cfg(test)]
    lock_waiters: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// One-shot pause before the next pin commit. Taken by the resolver.
    #[cfg(test)]
    pin_gate: std::sync::Mutex<Option<std::sync::Arc<PinInterleave>>>,
}

fn install_staged(slot: &std::sync::Mutex<Option<NamesState>>, guard: &mut NamesState) {
    if let Ok(mut staged) = slot.lock() {
        if let Some(next) = staged.take() {
            *guard = next;
        }
    }
}

/// Test seam. Resolution waits here after it has read an owner and before
/// the pin commit, so a test can unbind in that window.
#[cfg(test)]
#[derive(Debug)]
struct PinInterleave {
    entered: std::sync::atomic::AtomicBool,
    release: std::sync::atomic::AtomicBool,
    wake: tokio::sync::Notify,
}

/// Holds the name-store lock until drop, and installs a staged publish
/// into that lock before releasing it.
struct HeldCommit<'a> {
    guard: tokio::sync::MutexGuard<'a, NamesState>,
    slot: std::sync::Arc<std::sync::Mutex<Option<NamesState>>>,
    pending: std::sync::Arc<std::sync::atomic::AtomicBool>,
    install_on_drop: bool,
}

impl HeldCommit<'_> {
    fn drain(&mut self) {
        install_staged(&self.slot, &mut self.guard);
    }
}

impl Drop for HeldCommit<'_> {
    fn drop(&mut self) {
        if self.install_on_drop {
            self.drain();
        }
    }
}

impl NameStore {
    /// An empty in-memory store (tests, or no data dir).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            state: std::sync::Arc::new(tokio::sync::Mutex::new(NamesState::default())),
            load_error: None,
            pending_durability: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            install_slot: std::sync::Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            lock_waiters: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            pin_gate: std::sync::Mutex::new(None),
        }
    }

    /// Pause the next pin commit until the test sets the gate's release flag.
    #[cfg(test)]
    fn arm_pin_interleave(&self) -> std::sync::Arc<PinInterleave> {
        let gate = std::sync::Arc::new(PinInterleave {
            entered: std::sync::atomic::AtomicBool::new(false),
            release: std::sync::atomic::AtomicBool::new(false),
            wake: tokio::sync::Notify::new(),
        });
        *self
            .pin_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(std::sync::Arc::clone(&gate));
        gate
    }

    /// If a test armed the pin gate, signal entry and wait for release.
    ///
    /// The wait is before the name lock, so `unbind_owner` can finish and
    /// the following commit can see that the owner is gone.
    #[cfg(test)]
    async fn wait_pin_interleave(&self) {
        let gate = self
            .pin_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(gate) = gate else {
            return;
        };
        gate.entered
            .store(true, std::sync::atomic::Ordering::SeqCst);
        gate.wake.notify_waiters();
        loop {
            let notified = gate.wake.notified();
            tokio::pin!(notified);
            if gate.release.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            notified.await;
        }
    }

    /// The store path inside `data_dir`.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(NAMES_STORE_FILE)
    }

    /// Load `path` (missing ⇒ empty; unreadable/malformed ⇒ fail closed).
    pub async fn load(path: PathBuf) -> Self {
        let mut store = Self::in_memory();
        store.path = Some(path.clone());
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return store,
            Err(e) => {
                store.load_error = Some(format!("read {}: {e}", path.display()));
                return store;
            }
        };
        let parsed = serde_json::from_slice::<NamesFile>(&bytes)
            .map_err(|e| format!("decode {}: {e}", path.display()))
            .and_then(NamesState::from_file);
        match parsed {
            Ok(state) => {
                store.state = std::sync::Arc::new(tokio::sync::Mutex::new(state));
                // A previous process may have published this file and then
                // failed the parent-directory fsync. Confirm both syncs
                // before any later identical bind may ACK.
                if let Err(error) = crate::storage::confirm_published_durability(&path).await {
                    tracing::warn!(
                        "name store at {} is loaded but directory sync is not confirmed: {error}",
                        path.display()
                    );
                    store
                        .pending_durability
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            }
            Err(e) => {
                tracing::warn!("name store unreadable, refusing name operations: {e}");
                store.load_error = Some(e);
            }
        }
        store
    }

    /// Why the on-disk store is not in force, if it is not.
    #[must_use]
    pub fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    fn usable(&self) -> Result<(), NameError> {
        match &self.load_error {
            Some(e) => Err(NameError::Store(format!("store not usable: {e}"))),
            None => Ok(()),
        }
    }

    /// Write `state` atomically (mode 0600). `on_renamed` runs when the
    /// new bytes are visible (after rename, before parent-dir fsync).
    async fn persist_with_install(
        path: &Option<PathBuf>,
        state: &NamesState,
        on_renamed: impl FnOnce() + Send,
    ) -> Result<(), crate::storage::DurableWriteError> {
        let Some(path) = path.as_deref() else {
            on_renamed();
            return Ok(());
        };
        let bytes = serde_json::to_vec_pretty(&state.to_file()).map_err(|e| {
            crate::storage::DurableWriteError::BeforeRename(std::io::Error::other(format!(
                "encode: {e}"
            )))
        })?;
        crate::storage::write_private_bytes_durable_typed_after_rename(path, bytes, on_renamed)
            .await
            .map_err(|e| e.with_path(path))
    }

    async fn lock_parts<'a>(
        state: &'a tokio::sync::Mutex<NamesState>,
        slot: &std::sync::Mutex<Option<NamesState>>,
        #[cfg(test)] waiters: &std::sync::atomic::AtomicUsize,
    ) -> tokio::sync::MutexGuard<'a, NamesState> {
        #[cfg(test)]
        waiters.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut guard = state.lock().await;
        #[cfg(test)]
        waiters.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        install_staged(slot, &mut guard);
        guard
    }

    async fn lock_state(&self) -> tokio::sync::MutexGuard<'_, NamesState> {
        Self::lock_parts(
            &self.state,
            &self.install_slot,
            #[cfg(test)]
            &self.lock_waiters,
        )
        .await
    }

    /// Tasks waiting to take the name-store lock. Test builds only.
    #[cfg(test)]
    fn state_lock_waiters(&self) -> usize {
        self.lock_waiters.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Apply `mutate` to a copy, persist it, then commit.
    ///
    /// The critical section runs on a spawned task. Awaiting the join is
    /// the success path. Dropping this future detaches that task. It does
    /// not abort it, so the task still holds the name lock until memory
    /// matches the published file.
    ///
    /// Success installs the new state. `BeforeRename` keeps the old memory
    /// (disk unchanged). `AfterRename` stages the new state in
    /// [`Self::install_slot`] inside the rename callback (cancel-safe),
    /// drains it into the lock, marks durability pending, then still
    /// returns [`NameError::Store`]. A later identical mutate (`changed =
    /// false`) retries the write while pending. It must not ACK as success
    /// until a parent-directory fsync succeeds.
    async fn commit<T>(
        &self,
        mutate: impl FnOnce(&mut NamesState) -> Result<(T, bool), NameError> + Send + 'static,
    ) -> Result<T, NameError>
    where
        T: Send + 'static,
    {
        self.usable()?;
        let state = std::sync::Arc::clone(&self.state);
        let slot = std::sync::Arc::clone(&self.install_slot);
        let pending = std::sync::Arc::clone(&self.pending_durability);
        let path = self.path.clone();
        #[cfg(test)]
        let waiters = std::sync::Arc::clone(&self.lock_waiters);
        let task = tokio::spawn(Self::commit_holding_lock(
            state,
            slot,
            pending,
            path,
            #[cfg(test)]
            waiters,
            mutate,
        ));
        match task.await {
            Ok(result) => result,
            Err(error) => Err(NameError::Store(format!(
                "name commit task failed: {error}"
            ))),
        }
    }

    async fn commit_holding_lock<T>(
        state: std::sync::Arc<tokio::sync::Mutex<NamesState>>,
        slot: std::sync::Arc<std::sync::Mutex<Option<NamesState>>>,
        pending: std::sync::Arc<std::sync::atomic::AtomicBool>,
        path: Option<PathBuf>,
        #[cfg(test)] waiters: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        mutate: impl FnOnce(&mut NamesState) -> Result<(T, bool), NameError> + Send,
    ) -> Result<T, NameError> {
        use std::sync::atomic::Ordering;
        let mut held = HeldCommit {
            guard: Self::lock_parts(
                &state,
                &slot,
                #[cfg(test)]
                &waiters,
            )
            .await,
            slot,
            pending,
            install_on_drop: true,
        };
        let mut next = held.guard.clone();
        let (out, changed) = mutate(&mut next)?;
        if changed {
            let to_install = next.clone();
            let slot = std::sync::Arc::clone(&held.slot);
            let pending = std::sync::Arc::clone(&held.pending);
            match Self::persist_with_install(&path, &next, move || {
                if let Ok(mut g) = slot.lock() {
                    *g = Some(to_install);
                }
                pending.store(true, Ordering::Release);
            })
            .await
            {
                Ok(()) => {
                    held.drain();
                    held.pending.store(false, Ordering::Release);
                    held.install_on_drop = false;
                }
                Err(e) if e.crossed_rename() => {
                    held.drain();
                    held.install_on_drop = false;
                    return Err(NameError::Store(format!(
                        "applied, but durability is not confirmed (directory fsync failed): \
                         {e}; the change is in effect"
                    )));
                }
                Err(e) => {
                    let _ = held.slot.lock().map(|mut s| s.take());
                    held.install_on_drop = false;
                    return Err(NameError::Store(format!("write {e}")));
                }
            }
        } else if held.pending.load(Ordering::Acquire) {
            let pending = std::sync::Arc::clone(&held.pending);
            let snapshot = held.guard.clone();
            match Self::persist_with_install(&path, &snapshot, move || {
                pending.store(true, Ordering::Release);
            })
            .await
            {
                Ok(()) => {
                    held.pending.store(false, Ordering::Release);
                    held.install_on_drop = false;
                }
                Err(e) if e.crossed_rename() => {
                    held.install_on_drop = false;
                    return Err(NameError::Store(format!(
                        "applied, but durability is not confirmed (directory fsync failed): \
                         {e}; the change is in effect"
                    )));
                }
                Err(e) => {
                    held.install_on_drop = false;
                    return Err(NameError::Store(format!("write {e}")));
                }
            }
        } else {
            held.install_on_drop = false;
        }
        Ok(out)
    }

    /// The owner bound to `label` (`None` if unbound).
    ///
    /// # Errors
    /// [`NameError::Store`] when the store is not usable.
    pub async fn owner(&self, label: &str) -> Result<Option<OwnerBinding>, NameError> {
        self.usable()?;
        Ok(self.lock_state().await.owners.get(label).copied())
    }

    /// The label bound to `user`, if any.
    ///
    /// # Errors
    /// [`NameError::Store`] when the store is not usable.
    pub async fn label_for(&self, user: &UserId) -> Result<Option<String>, NameError> {
        self.usable()?;
        Ok(self
            .lock_state()
            .await
            .owners
            .iter()
            .find(|(_, b)| b.user_id == *user)
            .map(|(label, _)| label.clone()))
    }

    /// Bind owner petname `label` to `user`. Frozen at first bind: the same
    /// user is `Unchanged`; a different user is [`NameError::PinMismatch`].
    ///
    /// # Errors
    /// Invalid/reserved label, `PinMismatch`, a full store, or `Store`.
    pub async fn bind_owner(
        &self,
        label: &str,
        user: UserId,
        source: BindSource,
        now_unix: u64,
    ) -> Result<BindOutcome, NameError> {
        validate_label(label)?;
        if is_reserved(label) {
            return Err(NameError::Reserved(label.to_string()));
        }
        let label = label.to_string();
        self.commit(move |state| {
            if let Some(held) = state.owners.get(&label) {
                return if held.user_id == user {
                    Ok((BindOutcome::Unchanged, false))
                } else {
                    Err(NameError::PinMismatch {
                        name: label,
                        pinned: hex::encode(held.user_id.as_bytes()),
                        current: hex::encode(user.as_bytes()),
                    })
                };
            }
            if state.owners.len() >= MAX_OWNER_LABELS {
                return Err(NameError::Store("owner label table is full".into()));
            }
            state.owners.insert(
                label,
                OwnerBinding {
                    user_id: user,
                    bound_at: now_unix,
                    source,
                },
            );
            Ok((BindOutcome::Inserted, true))
        })
        .await
    }

    /// Remove owner petname `label` and every pin under it. `false` when
    /// the label was not bound.
    ///
    /// # Errors
    /// [`NameError::Store`].
    pub async fn unbind_owner(&self, label: &str) -> Result<bool, NameError> {
        validate_label(label)?;
        let label = label.to_string();
        let suffix = format!(".{label}");
        self.commit(move |state| {
            if state.owners.remove(&label).is_none() {
                return Ok((false, false));
            }
            state.pins.retain(|key, _| !key.ends_with(&suffix));
            Ok((true, true))
        })
        .await
    }

    /// Pin canonical `key` to `id` under `owner`, or check an existing pin.
    ///
    /// This is the TOFU rule: an existing pin to a different id or owner is
    /// refused with [`NameError::PinMismatch`] and never rewritten.
    ///
    /// # Errors
    /// `PinMismatch`, a full store, or `Store`.
    pub async fn pin(
        &self,
        key: &str,
        owner: UserId,
        id: [u8; 32],
        source: BindSource,
        now_unix: u64,
    ) -> Result<BindOutcome, NameError> {
        parse_pin_key(key)?;
        let key = key.to_string();
        self.commit(move |state| install_pin(state, key, owner, id, source, now_unix))
            .await
    }

    /// Remove the pin for canonical `key` (the owner's re-pin step).
    ///
    /// # Errors
    /// Invalid key, or `Store`.
    pub async fn unpin(&self, key: &str) -> Result<bool, NameError> {
        parse_pin_key(key)?;
        let key = key.to_string();
        self.commit(move |state| {
            let removed = state.pins.remove(&key).is_some();
            Ok((removed, removed))
        })
        .await
    }

    /// The pin for canonical `key`, if any.
    ///
    /// # Errors
    /// [`NameError::Store`].
    pub async fn get_pin(&self, key: &str) -> Result<Option<NamePin>, NameError> {
        self.usable()?;
        Ok(self.lock_state().await.pins.get(key).copied())
    }

    /// Machine labels pinned under `owner_label`: `(label, machine)`.
    ///
    /// # Errors
    /// [`NameError::Store`].
    pub async fn machine_labels(
        &self,
        owner_label: &str,
    ) -> Result<Vec<(String, MachineId)>, NameError> {
        self.usable()?;
        let state = self.lock_state().await;
        Ok(state
            .pins
            .iter()
            .filter_map(|(key, pin)| {
                let (kind, name) = parse_pin_key(key).ok()?;
                (kind == NameKind::Machine && name.owner == owner_label)
                    .then_some((name.label, MachineId(pin.id)))
            })
            .collect())
    }

    /// Snapshot for listing: `(owners, pins)`.
    ///
    /// # Errors
    /// [`NameError::Store`].
    pub async fn snapshot(
        &self,
    ) -> Result<(BTreeMap<String, OwnerBinding>, BTreeMap<String, NamePin>), NameError> {
        self.usable()?;
        let state = self.lock_state().await;
        Ok((state.owners.clone(), state.pins.clone()))
    }
}

/// A resolved name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The canonical, kind-prefixed name (the pin key).
    pub name: String,
    /// Agent or machine.
    pub kind: NameKind,
    /// The owner the name resolved under.
    pub owner: UserId,
    /// The agent a stream would open to (the agent itself, or the agent
    /// the machine's daemon announces, when exactly one qualifies).
    pub agent_id: Option<AgentId>,
    /// The machine, for a machine target.
    pub machine_id: Option<MachineId>,
    /// Whether this resolution created the pin.
    pub newly_pinned: bool,
}

/// Select among `candidates`, then pin at first use (or check the pin).
///
/// # Errors
/// Any [`select`] error, or `PinMismatch` / `Store` from the pin.
pub async fn resolve_with(
    store: &NameStore,
    name: &NameRef,
    owner: UserId,
    candidates: &Candidates,
    now_unix: u64,
) -> Result<Resolved, NameError> {
    resolve_with_options(store, name, owner, candidates, now_unix, false).await
}

fn machine_forward_refusal(name: &NameRef) -> NameError {
    NameError::MachineTargetUnsupported(format!(
        "{name}: only an agent name is accepted for this resolution"
    ))
}

/// Refuse a pin when petname `label` is not bound to `owner`.
///
/// `me` has no petname row. This runs inside the pin commit, under the same
/// lock as `unbind_owner`, so a concurrent unbind cannot leave a pin for an
/// owner that is no longer bound.
fn require_bound_owner(state: &NamesState, label: &str, owner: UserId) -> Result<(), NameError> {
    if label == LOCAL_OWNER_LABEL {
        return Ok(());
    }
    match state.owners.get(label) {
        Some(binding) if binding.user_id == owner => Ok(()),
        _ => Err(NameError::UnknownName(format!(
            "owner label {label:?} is not bound to this user"
        ))),
    }
}

/// Insert `key` or refuse an existing pin that names a different id or owner.
fn install_pin(
    state: &mut NamesState,
    key: String,
    owner: UserId,
    id: [u8; 32],
    source: BindSource,
    now_unix: u64,
) -> Result<(BindOutcome, bool), NameError> {
    if let Some(held) = state.pins.get(&key) {
        if held.id != id || held.owner != owner {
            return Err(NameError::PinMismatch {
                name: key,
                pinned: hex::encode(held.id),
                current: hex::encode(id),
            });
        }
        return Ok((BindOutcome::Unchanged, false));
    }
    if state.pins.len() >= MAX_PINS {
        return Err(NameError::Store("pin table is full".into()));
    }
    state.pins.insert(
        key,
        NamePin {
            id,
            owner,
            pinned_at: now_unix,
            source,
        },
    );
    Ok((BindOutcome::Inserted, true))
}

/// Check both bare-name pins and insert the selected kind under one lock.
///
/// Both pins already stored is [`NameError::AmbiguousKind`]. One pin whose
/// kind differs from `selection` is [`NameError::PinMismatch`] and writes
/// nothing. No pin inserts `selection` unless `agent_only` refuses a machine.
fn pin_bare_locked(
    state: &mut NamesState,
    name: &NameRef,
    owner: UserId,
    selection: Selection,
    agent_only: bool,
    now_unix: u64,
) -> Result<(BindOutcome, bool), NameError> {
    let agent_key = name.canonical(NameKind::Agent);
    let machine_key = name.canonical(NameKind::Machine);
    let held = match (
        state.pins.get(&agent_key).copied(),
        state.pins.get(&machine_key).copied(),
    ) {
        (Some(_), Some(_)) => return Err(NameError::AmbiguousKind(name.to_string())),
        (Some(pin), None) => Some((NameKind::Agent, agent_key, pin)),
        (None, Some(pin)) => Some((NameKind::Machine, machine_key, pin)),
        (None, None) => None,
    };
    if let Some((pinned_kind, pinned_key, pin)) = held {
        if selection.kind != pinned_kind || pin.id != selection.id || pin.owner != owner {
            return Err(NameError::PinMismatch {
                name: pinned_key,
                pinned: hex::encode(pin.id),
                current: hex::encode(selection.id),
            });
        }
        if agent_only && selection.kind != NameKind::Agent {
            return Err(machine_forward_refusal(name));
        }
        return Ok((BindOutcome::Unchanged, false));
    }
    if agent_only && selection.kind != NameKind::Agent {
        return Err(machine_forward_refusal(name));
    }
    install_pin(
        state,
        name.canonical(selection.kind),
        owner,
        selection.id,
        BindSource::FirstUse,
        now_unix,
    )
}

/// Like [`resolve_with`], but when `agent_only` is set, refuse a machine
/// selection **before** pinning.
///
/// `POST /forwards` passes `agent_only = false`: a machine name is a valid
/// forward target and is pinned (ADR-0074 slice 2). An agent-only caller
/// sets the flag so a refused machine does not write `names.json`.
///
/// A bare name that matches both verified kinds is [`NameError::AmbiguousKind`]
/// even when a pin exists. `PinMismatch` is only when the single remaining
/// candidate's kind differs from the one existing pin. The kind check and
/// the insert share one commit, so two bare resolves cannot pin both kinds.
/// That same commit rechecks the owner petname. A concurrent unbind that
/// wins the lock leaves no pin.
///
/// # Errors
/// Any [`select`] error, [`NameError::MachineTargetUnsupported`], or
/// `PinMismatch` / `Store` from the pin.
pub async fn resolve_with_options(
    store: &NameStore,
    name: &NameRef,
    owner: UserId,
    candidates: &Candidates,
    now_unix: u64,
    agent_only: bool,
) -> Result<Resolved, NameError> {
    // Both verified kinds refuse here, pin or not. `select` does not
    // consult the store, so a pin cannot hide the collision.
    let selection = select(name, candidates)?;
    // After the owner was read, before the pin lock. A test unbinds here.
    #[cfg(test)]
    store.wait_pin_interleave().await;
    let outcome = if name.kind.is_none() {
        let pinned_name = name.clone();
        let owner_label = pinned_name.owner.clone();
        store
            .commit(move |state| {
                require_bound_owner(state, &owner_label, owner)?;
                pin_bare_locked(state, &pinned_name, owner, selection, agent_only, now_unix)
            })
            .await?
    } else if agent_only && selection.kind != NameKind::Agent {
        return Err(machine_forward_refusal(name));
    } else {
        let key = name.canonical(selection.kind);
        let owner_label = name.owner.clone();
        store
            .commit(move |state| {
                require_bound_owner(state, &owner_label, owner)?;
                install_pin(
                    state,
                    key,
                    owner,
                    selection.id,
                    BindSource::FirstUse,
                    now_unix,
                )
            })
            .await?
    };
    Ok(Resolved {
        name: name.canonical(selection.kind),
        kind: selection.kind,
        owner,
        agent_id: selection.agent_id,
        machine_id: selection.machine_id,
        newly_pinned: outcome == BindOutcome::Inserted,
    })
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl crate::Agent {
    /// The owner a name's owner label denotes: `me` is this install's owner;
    /// any other label must be a bound petname.
    ///
    /// # Errors
    /// `UnknownName` (unbound label, or `me` on an ownerless install) or
    /// `Store`.
    pub async fn name_owner(
        &self,
        names: &NameStore,
        owner_label: &str,
    ) -> Result<UserId, NameError> {
        if owner_label == LOCAL_OWNER_LABEL {
            names.usable()?;
            return self.user_id().ok_or_else(|| {
                NameError::UnknownName("me: this install has no owner (x0x user-id create)".into())
            });
        }
        names
            .owner(owner_label)
            .await?
            .map(|b| b.user_id)
            .ok_or_else(|| {
                NameError::UnknownName(format!("owner label {owner_label:?} is not bound"))
            })
    }

    /// Gather the candidates for `owner` from local state only: the
    /// discovery cache (certificates, self-names), the ADR 0115 authority
    /// machine (announced binding, authenticated binding, or usable ADR
    /// 0089 evidence), the revocation set, the ADR-0041 device set
    /// (`devices`, for the local owner) and received share grants (other
    /// owners).
    pub async fn name_candidates(
        &self,
        names: &NameStore,
        owner_label: &str,
        owner: &UserId,
        devices: Option<&crate::owner_sync::OwnerSyncStore>,
    ) -> Result<Candidates, NameError> {
        let now = unix_now_secs();
        let entries: Vec<crate::DiscoveredAgent> = {
            let cache = self.identity_discovery_cache.read().await;
            cache
                .values()
                .filter(|d| {
                    d.user_id == Some(*owner)
                        || d.agent_certificate.as_ref().and_then(|c| c.user_id().ok())
                            == Some(*owner)
                })
                .cloned()
                .collect()
        };
        let mut observed = Vec::with_capacity(entries.len() + 1);
        for entry in entries {
            // ADR 0115 §2. Class B may be authenticated only by usable ADR
            // 0089 evidence, which does not fill `authenticated_machine_bindings`.
            // After restart that cache is empty; the authority machine still
            // names the peer, so the label and shared-machine host stay.
            let machine_id = self
                .authorized_routing_machine(&entry.agent_id, Some(entry.machine_id))
                .await;
            // V3 `self_name` is machine-signed only. Trust it as a label
            // solely when the announce's machine is the authority machine;
            // otherwise a foreign machine can re-announce a real certified
            // agent under another label (Claude #1494 e338df79 P2).
            let self_name =
                verified_announce_self_name(entry.machine_id, machine_id, entry.self_name);
            observed.push(ObservedAgent {
                agent_id: entry.agent_id,
                announced_user: entry.user_id,
                certificate: entry.agent_certificate,
                self_name,
                machine_id,
                revoked: false,
            });
        }
        if self.user_id() == Some(*owner) {
            observed.push(ObservedAgent {
                agent_id: self.agent_id(),
                announced_user: self.user_id(),
                certificate: self.agent_certificate().cloned(),
                self_name: self.self_name(),
                machine_id: Some(self.machine_id()),
                revoked: false,
            });
        }
        let revoked_machines: BTreeSet<[u8; 32]> = {
            let revoked = self.revocation_set.read().await;
            for agent in &mut observed {
                agent.revoked = revoked.is_agent_revoked(&agent.agent_id)
                    || agent.machine_id.is_some_and(|m| {
                        revoked.is_machine_revoked(&m)
                            || revoked.is_binding_revoked(&agent.agent_id, &m)
                    });
            }
            let mut machines = BTreeSet::new();
            if let Some(devices) = devices {
                for e in devices.enrolled_devices().await {
                    let m = MachineId(e.machine_id);
                    if revoked.is_machine_revoked(&m) {
                        machines.insert(m.0);
                    }
                }
            }
            for (_, m) in names.machine_labels(owner_label).await? {
                if revoked.is_machine_revoked(&m) {
                    machines.insert(m.0);
                }
            }
            machines
        };
        let agents = agent_candidates(owner, &observed, now);
        let machines = if owner_label == LOCAL_OWNER_LABEL {
            match devices {
                Some(devices) => {
                    let mut named = Vec::new();
                    for record in devices.records_snapshot().await {
                        if let crate::owner_sync::SyncValue::MachineNames {
                            machine_name: Some(machine_name),
                            ..
                        } = &record.value
                        {
                            let Ok(bytes) = decode32("machine", &record.key) else {
                                continue;
                            };
                            if record.verify_owner(owner).is_ok() {
                                named.push((MachineId(bytes), machine_name.clone()));
                            }
                        }
                    }
                    own_machine_candidates(
                        owner,
                        &devices.enrolled_devices().await,
                        &named,
                        &revoked_machines,
                        &agents,
                        now.saturating_mul(1000),
                    )
                }
                None => Vec::new(),
            }
        } else {
            let labels = names.machine_labels(owner_label).await?;
            let mut received = Vec::new();
            if let Some(store) = self.share_grant_store() {
                for grant in store.grants(crate::share_grant::GrantRole::Received) {
                    let revoked = self.is_share_grant_revoked(&grant).await;
                    received.push((grant, revoked));
                }
            }
            shared_machine_candidates(owner, &labels, &received, &agents, &revoked_machines, now)
        };
        Ok(Candidates { agents, machines })
    }

    /// Resolve `name` locally and pin it at first use (ADR-0074 §1).
    /// Adds no trust: the caller's gates still decide.
    ///
    /// # Errors
    /// Any [`NameError`].
    pub async fn resolve_name(
        &self,
        names: &NameStore,
        devices: Option<&crate::owner_sync::OwnerSyncStore>,
        name: &NameRef,
    ) -> Result<Resolved, NameError> {
        self.resolve_name_opts(names, devices, name, false).await
    }

    async fn resolve_name_opts(
        &self,
        names: &NameStore,
        devices: Option<&crate::owner_sync::OwnerSyncStore>,
        name: &NameRef,
        agent_only: bool,
    ) -> Result<Resolved, NameError> {
        let owner = self.name_owner(names, &name.owner).await?;
        let candidates = self
            .name_candidates(names, &name.owner, &owner, devices)
            .await?;
        resolve_with_options(names, name, owner, &candidates, unix_now_secs(), agent_only).await
    }

    /// Label a shared machine: `machine:<label>.<owner>` → `machine`, for a
    /// non-`me` owner, only while `machine` hosts an agent of an active
    /// received grant from that owner. Pinned like any name.
    ///
    /// # Errors
    /// `Invalid` (no `machine:` prefix, or owner `me`: own machines are
    /// named by the synced `machine_name`), `UnknownName`,
    /// `UnverifiedOwner`, `PinMismatch` or `Store`.
    pub async fn label_shared_machine(
        &self,
        names: &NameStore,
        name: &NameRef,
        machine: MachineId,
    ) -> Result<BindOutcome, NameError> {
        if name.kind != Some(NameKind::Machine) {
            return Err(NameError::Invalid(format!(
                "{name}: a machine label needs the machine: prefix"
            )));
        }
        if name.is_local_owner() {
            return Err(NameError::Invalid(
                "own machines are named by their synced machine_name (x0x profile set --machine-name)"
                    .into(),
            ));
        }
        let owner = self.name_owner(names, &name.owner).await?;
        let mut candidates = self
            .name_candidates(names, &name.owner, &owner, None)
            .await?;
        let probe = vec![(name.label.clone(), machine)];
        let mut received = Vec::new();
        if let Some(store) = self.share_grant_store() {
            for grant in store.grants(crate::share_grant::GrantRole::Received) {
                let revoked = self.is_share_grant_revoked(&grant).await;
                received.push((grant, revoked));
            }
        }
        let revoked_machines: BTreeSet<[u8; 32]> = {
            let revoked = self.revocation_set.read().await;
            if revoked.is_machine_revoked(&machine) {
                BTreeSet::from([machine.0])
            } else {
                BTreeSet::new()
            }
        };
        candidates.machines = shared_machine_candidates(
            &owner,
            &probe,
            &received,
            &candidates.agents,
            &revoked_machines,
            unix_now_secs(),
        );
        if !candidates.machines.iter().any(|m| m.verified) {
            return Err(NameError::UnverifiedOwner(format!(
                "{name}: machine {} hosts no agent of an active grant from this owner",
                hex::encode(machine.as_bytes())
            )));
        }
        names
            .pin(
                &name.canonical(NameKind::Machine),
                owner,
                machine.0,
                BindSource::Manual,
                unix_now_secs(),
            )
            .await
    }
}

#[cfg(test)]
mod tests;
