//! Shared endpoint registry for the x0x REST API.
//!
//! Both `x0xd` (the daemon) and `x0x` (the CLI) consume this registry,
//! ensuring routes and CLI commands never drift out of sync.

pub mod agent_signing;

/// HTTP method for an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// HTTP GET
    Get,
    /// HTTP POST
    Post,
    /// HTTP PUT
    Put,
    /// HTTP PATCH
    Patch,
    /// HTTP DELETE
    Delete,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Get => write!(f, "GET"),
            Method::Post => write!(f, "POST"),
            Method::Put => write!(f, "PUT"),
            Method::Patch => write!(f, "PATCH"),
            Method::Delete => write!(f, "DELETE"),
        }
    }
}
/// Where a request field lives on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldLocation {
    /// JSON request body.
    Body,
    /// URL query string.
    Query,
}

impl FieldLocation {
    /// Wire label used in the generated manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            FieldLocation::Body => "body",
            FieldLocation::Query => "query",
        }
    }
}

/// How the `x0x` CLI surfaces one request field.
#[derive(Debug, Clone)]
pub enum CliExpose {
    /// A `--kebab-case(name)` flag or a `<NAME>` positional — the default
    /// CLI naming conventions.
    Default,
    /// The exact token as it appears in `x0x <cmd> --help` output
    /// (e.g. `"--trust"`, `"PUBLIC_KEY_HEX"`).
    Token(&'static str),
    /// The CLI synthesizes the value from other arguments (e.g. it
    /// base64-encodes `--file` into `payload_b64`); no help token exists.
    Derived,
    /// Accepted by the request struct but ignored (or rejected) by the
    /// handler — deliberately not surfaced to users.
    Ignored,
    /// Exposed through the caller-supplied JSON document the CLI posts
    /// verbatim (a per-field flag would be a lie about the interface).
    JsonDoc,
    /// An `Option<bool>` whose daemon default when omitted is TRUE: the CLI
    /// must expose it as a value-taking `--flag <true|false>` so `false` is
    /// reachable (a bare SetTrue flag could only restate the default).
    BoolValue,
}

/// One named request field an endpoint accepts, beyond its path parameters.
#[derive(Debug, Clone)]
pub struct RequestField {
    /// Wire field name (the serde name).
    pub name: &'static str,
    /// Body or query-string location.
    pub location: FieldLocation,
    /// Whether the handler requires the field (no serde default).
    pub required: bool,
    /// How the CLI exposes the field.
    pub cli: CliExpose,
}

impl RequestField {
    /// Body field whose CLI surface is DERIVED (synthesized from flag
    /// pairs, not a 1:1 name/value mapping) — the generic parity shape
    /// check skips it; a targeted exact-wire test owns the contract.
    pub const fn derived_body(name: &'static str) -> Self {
        Self {
            name,
            location: FieldLocation::Body,
            required: false,
            cli: CliExpose::Derived,
        }
    }

    /// Body field using the default CLI naming convention.
    pub const fn body(name: &'static str, required: bool) -> Self {
        Self {
            name,
            location: FieldLocation::Body,
            required,
            cli: CliExpose::Default,
        }
    }

    /// Query field using the default CLI naming convention.
    pub const fn query(name: &'static str, required: bool) -> Self {
        Self {
            name,
            location: FieldLocation::Query,
            required,
            cli: CliExpose::Default,
        }
    }

    /// Body field bound to a specific `--help` token.
    pub const fn body_as(name: &'static str, required: bool, token: &'static str) -> Self {
        Self {
            name,
            location: FieldLocation::Body,
            required,
            cli: CliExpose::Token(token),
        }
    }

    /// Query field bound to a specific `--help` token.
    pub const fn query_as(name: &'static str, required: bool, token: &'static str) -> Self {
        Self {
            name,
            location: FieldLocation::Query,
            required,
            cli: CliExpose::Token(token),
        }
    }

    /// Body field the CLI synthesizes from other arguments.
    pub const fn body_derived(name: &'static str, required: bool) -> Self {
        Self {
            name,
            location: FieldLocation::Body,
            required,
            cli: CliExpose::Derived,
        }
    }

    /// Body field the request struct carries but the handler ignores or
    /// rejects (e.g. a tombstoned pre-migration knob).
    pub const fn body_ignored(name: &'static str) -> Self {
        Self {
            name,
            location: FieldLocation::Body,
            required: false,
            cli: CliExpose::Ignored,
        }
    }

    /// Body `Option<bool>` field defaulting to true when omitted; the CLI
    /// flag must take an explicit value.
    pub const fn body_bool_default_true(name: &'static str) -> Self {
        Self {
            name,
            location: FieldLocation::Body,
            required: false,
            cli: CliExpose::BoolValue,
        }
    }

    /// Body field supplied through the verbatim JSON document argument.
    pub const fn body_json_doc(name: &'static str, required: bool) -> Self {
        Self {
            name,
            location: FieldLocation::Body,
            required,
            cli: CliExpose::JsonDoc,
        }
    }

    /// Query field the request struct carries but the handler ignores.
    pub const fn query_ignored(name: &'static str) -> Self {
        Self {
            name,
            location: FieldLocation::Query,
            required: false,
            cli: CliExpose::Ignored,
        }
    }
}

/// Request-shape metadata for one endpoint.
///
/// `tests/cli_request_parity.rs` enforces this contract against both the
/// CLI argument parser and the daemon's request structs: a field hidden
/// from the CLI is a hidden capability, and a registry entry that drifts
/// from the request struct is a lying manifest.
#[derive(Debug, Clone)]
pub enum RequestSpec {
    /// No request data beyond path parameters.
    None,
    /// Named body/query fields.
    Fields(&'static [RequestField]),
    /// The CLI posts a caller-supplied JSON document verbatim (from a
    /// literal, `@file`, or stdin), so every struct field is exposed by
    /// construction.
    Passthrough,
}

/// A single API endpoint definition.
#[derive(Debug, Clone)]
pub struct EndpointDef {
    /// HTTP method.
    pub method: Method,
    /// URL path pattern (e.g. "/contacts/:agent_id").
    pub path: &'static str,
    /// CLI command name (e.g. "contacts update").
    pub cli_name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Grouping category.
    pub category: &'static str,
    /// Request-shape contract (body/query fields) for CLI parity.
    pub request: RequestSpec,
}
/// Complete registry of all x0x API endpoints.
pub const ENDPOINTS: &[EndpointDef] = &[
    // ── Status ──────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/health",
        cli_name: "health",
        description: "Health check",
        category: "status",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/status",
        cli_name: "status",
        description: "Runtime status with uptime",
        category: "status",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/shutdown",
        cli_name: "stop",
        description: "Gracefully stop the daemon",
        category: "status",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/auth/session",
        cli_name: "auth session",
        description: "Exchange the durable API token for a short-lived browser session token",
        category: "status",
        request: RequestSpec::None,
    },
    // ── Identity ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/agent",
        cli_name: "agent",
        description: "Agent identity info",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/announce",
        cli_name: "announce",
        description: "Announce identity to network",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("include_user_identity", false, "--include-user"), RequestField::body_as("human_consent", false, "--consent")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/agent/user-id",
        cli_name: "agent user-id",
        description: "Current agent user ID",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/agent/card",
        cli_name: "agent card",
        description: "Generate shareable identity card",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::query_as("display_name", false, "DISPLAY_NAME"), RequestField::query("include_groups", false), RequestField::query("include_local_addresses", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/introduction",
        cli_name: "agent introduction",
        description: "Introduction card with trust-scoped disclosure",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::query("peer", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/card/import",
        cli_name: "agent import",
        description: "Import agent card to contacts",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("card", true, "CARD"), RequestField::body_as("trust_level", false, "--trust")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/sign",
        cli_name: "agent sign",
        description: "Detached ML-DSA-65 signature over a caller-supplied payload",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body("context", true), RequestField::body_as("payload_b64", true, "--payload-b64")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/verify",
        cli_name: "agent verify",
        description: "Verify a detached ML-DSA-65 signature against a caller-supplied public key",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("payload_b64", true, "--payload-b64"), RequestField::body("signature_b64", true), RequestField::body("public_key_b64", true), RequestField::body("context", true), RequestField::body("algorithm", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/identity/revoke",
        cli_name: "identity revoke",
        description: "Issue a signed revocation for an agent-id or machine-id keypair",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body("agent_id", false), RequestField::body("machine_id", false), RequestField::body("move_epoch", false), RequestField::body("reason", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/identity/revocations",
        cli_name: "identity revocations",
        description: "List all revocation records held by this daemon",
        category: "identity",
        request: RequestSpec::None,
    },
    // ── ADR-0043 agent key-move ceremony + placement ledger ────────────
    EndpointDef {
        method: Method::Post,
        path: "/agent/move",
        cli_name: "move authorize",
        description: "Owner-authorize an agent move (chain MoveAuthorization; source seals)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("to_machine", true, "TO_MACHINE"), RequestField::body_as("placement", true, "PLACEMENT"), RequestField::body_derived("pin", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/move/export",
        cli_name: "move export",
        description: "Source machine seals the export envelope + ExportReceipt",
        category: "identity",
        request: RequestSpec::Passthrough,
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/move/import",
        cli_name: "move import",
        description: "Target machine imports a transfer bundle (unwrap + store + receipt)",
        category: "identity",
        request: RequestSpec::Passthrough,
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/move/activate",
        cli_name: "move activate",
        description: "Owner commits a move (ActivationBundle on the activation topic)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("move_epoch", true, "EPOCH")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/move/abort",
        cli_name: "move abort",
        description: "Owner rolls back a pre-activation move (epoch burned)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("move_epoch", true, "EPOCH"), RequestField::body_as("reason", false, "--reason")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/move/retire",
        cli_name: "move retire",
        description: "Source machine retires after activation (delete key + receipt)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("move_epoch", true, "EPOCH")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/agent/moves",
        cli_name: "move list",
        description: "Move-log view + derived state (custodian, quiesce, placement)",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/owner/placement",
        cli_name: "owner placement",
        description: "Derived placement ledger (lazy mint + ≥1-Roaming Home invariant)",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/owner/agents/:id/placement",
        cli_name: "owner agents placement",
        description: "One agent's placement record + fold",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/profile",
        cli_name: "profile",
        description: "Daemon self-profile names (human/display/machine)",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Put,
        path: "/profile",
        cli_name: "profile set",
        description: "Update stored self-profile names (partial update)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body("human_name", false), RequestField::body("display_name", false), RequestField::body("machine_name", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/home",
        cli_name: "home",
        description: "ADR-0038 Home space: group id, primary agent, members, warnings",
        category: "groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/home/rename",
        cli_name: "home rename",
        description: "Rename the Home space (admin-gated, sealed)",
        category: "groups",
        request: RequestSpec::Fields(&[RequestField::body_as("name", true, "NAME")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/owner/agents",
        cli_name: "owner agents",
        description: "Roster of agents certified by this install's owner (journal-backed; survives restarts)",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/owner/agents/issue",
        cli_name: "owner agents issue",
        description: "Owner-sign an AgentCertificate over a harness-submitted agent public key (ADR-0039)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_public_key", true, "PUBLIC_KEY_HEX"), RequestField::body("mode", false), RequestField::body("label", false), RequestField::body("not_after", false)]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/owner/agents/:id",
        cli_name: "owner agents revoke",
        description: "ADR-0018 owner issuer-revocation of a registered sub-agent",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body("reason", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/owner/riders",
        cli_name: "owner riders issue",
        description: "Mint a scoped rider token for a registered rider-mode sub-agent (ADR-0039; the required harness-signed delegation is supplied via --delegation-payload-b64/--delegation-signature)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("sub_agent_id", true, "AGENT_ID"), RequestField::body_as("groups", false, "--group"), RequestField::body("label", false), RequestField::body("ttl_secs", false), RequestField::body_as("delegation", true, "--delegation-payload-b64")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/owner/riders",
        cli_name: "owner riders",
        description: "List rider-token records (no secrets; hashed identifiers only)",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Delete,
        path: "/owner/riders/:id",
        cli_name: "owner riders revoke",
        description: "Revoke a rider token; it fails on the next request",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/sync/devices",
        cli_name: "sync devices",
        description: "ADR-0041 Tier-1: enrolled owner devices + last-sync status",
        category: "identity",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/sync/devices/enroll",
        cli_name: "sync enroll",
        description: "Owner-key-sign a DeviceEnrollment for a machine (ADR-0041 Tier-1; owner-gated)",
        category: "identity",
        request: RequestSpec::Fields(&[RequestField::body_as("machine_id", false, "MACHINE_ID"), RequestField::body("ttl_secs", false)]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/sync/devices/:machine_id",
        cli_name: "sync revoke",
        description: "Remove a machine from the owner device set (ADR-0041 Tier-1; owner-gated)",
        category: "identity",
        request: RequestSpec::None,
    },
    // ── Network ─────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/peers",
        cli_name: "peers",
        description: "Connected gossip peers",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence",
        cli_name: "presence",
        description: "Online agents (gossip presence view; /presence/online is the discovery-cache view)",
        category: "presence",
        request: RequestSpec::None,
    },
    // ── Presence ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/presence/online",
        cli_name: "presence online",
        description: "List all currently online agents (network view, non-blocked)",
        category: "presence",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/foaf",
        cli_name: "presence foaf",
        description: "FOAF random-walk discovery of nearby agents (social view)",
        category: "presence",
        request: RequestSpec::Fields(&[RequestField::query("ttl", false), RequestField::query("timeout_ms", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/find/:id",
        cli_name: "presence find",
        description: "Find a specific agent by ID via FOAF random walk",
        category: "presence",
        request: RequestSpec::Fields(&[RequestField::query("ttl", false), RequestField::query("timeout_ms", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/status/:id",
        cli_name: "presence status",
        description: "Get local cache presence status for an agent",
        category: "presence",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/events",
        cli_name: "presence events",
        description: "Server-Sent Events stream of presence online/offline events",
        category: "presence",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/network/status",
        cli_name: "network status",
        description: "Network connectivity details",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/network/bootstrap-cache",
        cli_name: "network cache",
        description: "Bootstrap peer cache stats",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/connectivity",
        cli_name: "diagnostics connectivity",
        description: "Connectivity snapshot (NodeStatus + transport_environment VPN/MTU assessment)",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/ack",
        cli_name: "diagnostics ack",
        description: "ACK-v2 per-stage latency buckets and outcome counters",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/gossip",
        cli_name: "diagnostics gossip",
        description: "PubSub drop-detection counters (publish/deliver deltas)",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/transport",
        cli_name: "diagnostics transport",
        description: "Transport connection accounting (zombie-connection hunt, #368)",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/relay",
        cli_name: "diagnostics relay",
        description: "ADR-0035 relay-decentralization metering: advert census + inbound-dialer evidence",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/dm",
        cli_name: "diagnostics dm",
        description: "Direct-message send/receive counters and per-peer health",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/groups",
        cli_name: "diagnostics groups",
        description: "Per-group ingest counters, listener state, and drop buckets",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/history",
        cli_name: "diagnostics history",
        description: "Durable-history writer/reaper counters (ADR-0023)",
        category: "network",
        request: RequestSpec::None,
    },
    // ── History (ADR-0023 durable local history) ────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/history",
        cli_name: "history list",
        description: "List durable history for one scope (dm:/group:/topic:), keyset-paginated",
        category: "history",
        request: RequestSpec::Fields(&[RequestField::query_as("scope", true, "SCOPE"), RequestField::query("since_ms", false), RequestField::query("until_ms", false), RequestField::query("limit", false), RequestField::query("before_id", false), RequestField::query_ignored("q")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/history/message/:msg_id",
        cli_name: "history message",
        description: "Point lookup of one durable history row by exposed msg_id (canonical group ids need ?scope=)",
        category: "history",
        request: RequestSpec::Fields(&[RequestField::query("scope", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/history/search",
        cli_name: "history search",
        description: "Full-text search over text history payloads within a scope",
        category: "history",
        request: RequestSpec::Fields(&[RequestField::query_as("scope", true, "SCOPE"), RequestField::query_as("q", true, "QUERY"), RequestField::query("since_ms", false), RequestField::query("until_ms", false), RequestField::query("limit", false), RequestField::query("before_id", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/history/stats",
        cli_name: "history stats",
        description: "History row counts, database size, and retention bounds",
        category: "history",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Delete,
        path: "/history",
        cli_name: "history purge",
        description: "Purge one scope from the local history store (local-only)",
        category: "history",
        request: RequestSpec::Fields(&[RequestField::query_as("scope", true, "SCOPE")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/exec",
        cli_name: "diagnostics exec",
        description: "Remote exec counters, warnings, active sessions, and ACL summary",
        category: "exec",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/connect",
        cli_name: "diagnostics connect",
        description: "Connect-ACL policy summary and stream allow/deny counters",
        category: "connect",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/ws",
        cli_name: "diagnostics ws",
        description: "WebSocket outbound-queue health: capacity and drop/slow-consumer-close counters",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/peers/:peer_id/probe",
        cli_name: "peer probe",
        description: "Active ant-quic probe_peer liveness + RTT (ant-quic 0.27.2 #173)",
        category: "network",
        request: RequestSpec::Fields(&[RequestField::query("timeout_ms", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/peers/:peer_id/health",
        cli_name: "peer health",
        description: "Connection health snapshot for a peer (ant-quic 0.27.1 #170)",
        category: "network",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/peers/events",
        cli_name: "peer events",
        description: "SSE stream of peer lifecycle events (ant-quic 0.27.1 #171)",
        category: "network",
        request: RequestSpec::None,
    },
    // ── Messaging ───────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/publish",
        cli_name: "publish",
        description: "Publish message to topic",
        category: "messaging",
        request: RequestSpec::Fields(&[RequestField::body_as("topic", true, "TOPIC"), RequestField::body_as("payload", true, "PAYLOAD")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/subscribe",
        cli_name: "subscribe",
        description: "Subscribe to topic",
        category: "messaging",
        request: RequestSpec::Fields(&[RequestField::body_as("topic", true, "TOPIC")]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/subscribe/:id",
        cli_name: "unsubscribe",
        description: "Unsubscribe by ID",
        category: "messaging",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/events",
        cli_name: "events",
        description: "SSE event stream",
        category: "messaging",
        request: RequestSpec::None,
    },
    // ── Discovery ───────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/agents/discovered",
        cli_name: "agents list",
        description: "List discovered agents",
        category: "discovery",
        request: RequestSpec::Fields(&[RequestField::query("unfiltered", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/agents/discovered/:agent_id",
        cli_name: "agents get",
        description: "Get discovered agent details",
        category: "discovery",
        request: RequestSpec::Fields(&[RequestField::query("wait", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/agents/:agent_id/machine",
        cli_name: "agents machine",
        description: "Resolve agent to current machine endpoint",
        category: "discovery",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/machines/discovered",
        cli_name: "machines discovered",
        description: "List discovered machine endpoints",
        category: "machines",
        request: RequestSpec::Fields(&[RequestField::query("unfiltered", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/machines/discovered/:machine_id",
        cli_name: "machines get",
        description: "Get discovered machine endpoint details",
        category: "machines",
        request: RequestSpec::Fields(&[RequestField::query("wait", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/agents/find/:agent_id",
        cli_name: "agents find",
        description: "Find agent on network",
        category: "discovery",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/agents/reachability/:agent_id",
        cli_name: "agents reachability",
        description: "Agent reachability info",
        category: "discovery",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/users/:user_id/agents",
        cli_name: "agents by-user",
        description: "Agents by user ID",
        category: "discovery",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/users/:user_id/machines",
        cli_name: "machines by-user",
        description: "Machine endpoints by user ID",
        category: "machines",
        request: RequestSpec::None,
    },
    // ── Contacts ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/contacts",
        cli_name: "contacts list",
        description: "List contacts",
        category: "contacts",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts",
        cli_name: "contacts add",
        description: "Add contact",
        category: "contacts",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("trust_level", false, "--trust"), RequestField::body_as("label", false, "--label")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/trust",
        cli_name: "trust set",
        description: "Quick trust/block",
        category: "contacts",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("level", true, "LEVEL")]),
    },
    EndpointDef {
        method: Method::Patch,
        path: "/contacts/:agent_id",
        cli_name: "contacts update",
        description: "Update contact trust",
        category: "contacts",
        request: RequestSpec::Fields(&[RequestField::body_as("trust_level", false, "--trust"), RequestField::body_as("identity_type", false, "--identity-type")]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/contacts/:agent_id",
        cli_name: "contacts remove",
        description: "Remove contact",
        category: "contacts",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/:agent_id/revoke",
        cli_name: "contacts revoke",
        description: "Revoke contact",
        category: "contacts",
        request: RequestSpec::Fields(&[RequestField::body_as("reason", true, "--reason")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/contacts/:agent_id/revocations",
        cli_name: "contacts revocations",
        description: "List revocations",
        category: "contacts",
        request: RequestSpec::None,
    },
    // ── Machines ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/contacts/:agent_id/machines",
        cli_name: "machines list",
        description: "List machines for contact",
        category: "machines",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/:agent_id/machines",
        cli_name: "machines add",
        description: "Add machine record",
        category: "machines",
        request: RequestSpec::Fields(&[RequestField::body_as("machine_id", true, "MACHINE_ID"), RequestField::body("label", false), RequestField::body_as("pinned", false, "--pin")]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/contacts/:agent_id/machines/:machine_id",
        cli_name: "machines remove",
        description: "Remove machine record",
        category: "machines",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/:agent_id/machines/:machine_id/pin",
        cli_name: "machines pin",
        description: "Pin machine",
        category: "machines",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Delete,
        path: "/contacts/:agent_id/machines/:machine_id/pin",
        cli_name: "machines unpin",
        description: "Unpin machine",
        category: "machines",
        request: RequestSpec::None,
    },
    // ── Trust ───────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/trust/evaluate",
        cli_name: "trust evaluate",
        description: "Evaluate trust for agent+machine",
        category: "trust",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("machine_id", true, "MACHINE_ID")]),
    },
    // ── Direct messaging ────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/agents/connect",
        cli_name: "direct connect",
        description: "Connect to agent",
        category: "direct",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/machines/connect",
        cli_name: "machines connect",
        description: "Connect to machine",
        category: "direct",
        request: RequestSpec::Fields(&[RequestField::body_as("machine_id", true, "MACHINE_ID")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/direct/send",
        cli_name: "direct send",
        description: "Send direct message",
        category: "direct",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_as("payload", true, "MESSAGE"), RequestField::body_bool_default_true("prefer_raw_quic_if_connected"), RequestField::body("raw_quic_receive_ack_ms", false), RequestField::body("stop_fallback_on_raw_error", false), RequestField::body("require_gossip", false), RequestField::body_ignored("require_gossip_ack"), RequestField::body_as("require_ack_ms", false, "--require-ack-ms"), RequestField::body_as("require_durable_app_ack", false, "--no-durable-ack"), RequestField::body("logical_id", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/direct/connections",
        cli_name: "direct connections",
        description: "List direct connections",
        category: "direct",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/direct/events",
        cli_name: "direct events",
        description: "Stream direct messages",
        category: "direct",
        request: RequestSpec::Fields(&[RequestField::query("backfill", false)]),
    },
    // ── Exec ───────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/exec/run",
        cli_name: "exec",
        description: "Run a strictly allowlisted non-interactive command on a remote daemon",
        category: "exec",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body_derived("argv", true), RequestField::body_as("stdin_b64", false, "--stdin-file"), RequestField::body_as("timeout_ms", false, "--timeout"), RequestField::body("cwd", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/exec/cancel",
        cli_name: "exec cancel",
        description: "Cancel an in-flight remote exec request",
        category: "exec",
        request: RequestSpec::Fields(&[RequestField::body_as("request_id", true, "REQUEST_ID"), RequestField::body("agent_id", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/exec/sessions",
        cli_name: "exec sessions",
        description: "List local pending and remote active exec sessions",
        category: "exec",
        request: RequestSpec::None,
    },
    // ── MLS groups ──────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups",
        cli_name: "groups create",
        description: "Create encrypted group",
        category: "groups",
        request: RequestSpec::Fields(&[RequestField::body_as("group_id", false, "--id")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/mls/groups",
        cli_name: "groups list",
        description: "List groups",
        category: "groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/mls/groups/:id",
        cli_name: "groups get",
        description: "Get group details",
        category: "groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/members",
        cli_name: "groups add-member",
        description: "Add member to group",
        category: "groups",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID")]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/mls/groups/:id/members/:agent_id",
        cli_name: "groups remove-member",
        description: "Remove member",
        category: "groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/encrypt",
        cli_name: "groups encrypt",
        description: "Encrypt for group",
        category: "groups",
        request: RequestSpec::Fields(&[RequestField::body_as("payload", true, "PAYLOAD")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/decrypt",
        cli_name: "groups decrypt",
        description: "Decrypt from group",
        category: "groups",
        request: RequestSpec::Fields(&[RequestField::body_as("ciphertext", true, "CIPHERTEXT"), RequestField::body("epoch", true)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/welcome",
        cli_name: "groups welcome",
        description: "Create welcome for member",
        category: "groups",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID")]),
    },
    // ── Named groups (high-level) ─────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/groups",
        cli_name: "group create",
        description: "Create named group",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("name", true, "NAME"), RequestField::body("description", false), RequestField::body("display_name", false), RequestField::body("preset", false), RequestField::body_as("policy", false, "--policy")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups",
        cli_name: "group list",
        description: "List groups",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id",
        cli_name: "group info",
        description: "Get group info",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/members",
        cli_name: "group members",
        description: "List named-group members",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/members",
        cli_name: "group add-member",
        description: "Add named-group member",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("agent_id", true, "AGENT_ID"), RequestField::body("display_name", false), RequestField::body_as("treekem_key_package_b64", false, "--key-package")]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id/members/:agent_id",
        cli_name: "group remove-member",
        description: "Remove named-group member",
        category: "named-groups",
        request: RequestSpec::None,
    },
    // ── Phase E: public-group messaging ──────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/send",
        cli_name: "group send",
        description: "Publish a signed message to a SignedPublic group",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("body", true, "BODY"), RequestField::body("kind", false), RequestField::body("thread_root", false), RequestField::body_as("thread_parent", false, "--reply-to"), RequestField::body_as("mentions", false, "--mentions"), RequestField::body_as("delegation_digest", false, "--delegation-digest")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/messages",
        cli_name: "group messages",
        description: "Retrieve cached public messages (non-members on Public read)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::query("thread_root", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/delegate",
        cli_name: "group delegate",
        description: "Issue a signed delegation (effective on durable history commit)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("to_agent", true, "--to-agent"), RequestField::body_as("scope", true, "--scope"), RequestField::body_as("verbs", false, "--verb"), RequestField::body_as("expiry_ms", true, "--expiry-ms"), RequestField::body("task", false), RequestField::body("parent", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/delegations",
        cli_name: "group delegations",
        description: "List effective delegations re-derived from durable history",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/invite",
        cli_name: "group invite",
        description: "Generate invite link",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("expiry_secs", false, "--expiry")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/join",
        cli_name: "group join",
        description: "Join group via invite (mode=home with --home --owner pins the expected Home owner, #468/#469)",
        category: "named-groups",
        request: RequestSpec::Fields(&[
            RequestField::body_as("invite", true, "INVITE"),
            RequestField::body("display_name", false),
            // #468/#469: `--home` serializes as the literal "home" mode
            // value; `--owner <HEX>` is the expected owner user id pin.
            // Both are only sent together (clap `requires` both ways).
            // #469 A3: mode/owner pin are Derived — `--home` is a bool
            // flag pair whose VALUES the CLI synthesizes ("home" mode +
            // the --owner token), so the generic shape check skips them;
            // tests/cli_group_join_wire.rs pins the exact wire instead.
            RequestField::derived_body("mode"),
            RequestField::derived_body("expected_owner_user_id"),
        ]),
    },
    EndpointDef {
        method: Method::Put,
        path: "/groups/:id/display-name",
        cli_name: "group set-name",
        description: "Set display name in group",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("name", true, "NAME")]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id",
        cli_name: "group leave",
        description: "Leave a group (sole-member leave deletes the group)",
        category: "named-groups",
        request: RequestSpec::None,
    },
    // ── Phase D.3: state-commit chain ────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/state",
        cli_name: "group state",
        description: "Inspect the signed state-commit chain for a group",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/state/commits",
        cli_name: "group state-commits",
        description: "Read retained state-commit history (members only, paged)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::query("from_revision", false), RequestField::query("limit", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/state/seal",
        cli_name: "group state-seal",
        description: "Advance the state-commit chain and republish signed card",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/state/withdraw",
        cli_name: "group delete",
        description: "Delete a group with a terminal withdrawal commit",
        category: "named-groups",
        request: RequestSpec::None,
    },
    // ── Named groups: policy, roles, join requests, discovery ───────────
    EndpointDef {
        method: Method::Patch,
        path: "/groups/:id",
        cli_name: "group update",
        description: "Update group name/description (admin+)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("name", false, "--new-name"), RequestField::body("description", false)]),
    },
    EndpointDef {
        method: Method::Patch,
        path: "/groups/:id/policy",
        cli_name: "group policy",
        description: "Update group policy (admin+)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body("preset", false), RequestField::body("discoverability", false), RequestField::body("admission", false), RequestField::body("confidentiality", false), RequestField::body("read_access", false), RequestField::body("write_access", false)]),
    },
    EndpointDef {
        method: Method::Patch,
        path: "/groups/:id/members/:agent_id/role",
        cli_name: "group set-role",
        description: "Change a member's role (admin+)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("role", true, "ROLE")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/ban/:agent_id",
        cli_name: "group ban",
        description: "Ban a member (admin+)",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id/ban/:agent_id",
        cli_name: "group unban",
        description: "Unban a member (admin+)",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/requests",
        cli_name: "group requests",
        description: "List join requests (admin+)",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/requests",
        cli_name: "group request-access",
        description: "Submit a join request",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body("message", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/requests/:request_id/approve",
        cli_name: "group approve-request",
        description: "Approve a join request (admin+)",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/requests/:request_id/reject",
        cli_name: "group reject-request",
        description: "Reject a join request (admin+)",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id/requests/:request_id",
        cli_name: "group cancel-request",
        description: "Cancel own pending join request",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/discover",
        cli_name: "group discover",
        description: "List locally known discoverable groups",
        category: "named-groups",
        request: RequestSpec::None,
    },
    // ── Phase C.2: shard-based distributed discovery ─────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/groups/discover/nearby",
        cli_name: "group discover-nearby",
        description: "Presence-social browse of PublicDirectory groups",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/discover/subscriptions",
        cli_name: "group discover-subscriptions",
        description: "List active shard subscriptions",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/discover/subscribe",
        cli_name: "group discover-subscribe",
        description: "Subscribe to a tag/name/id directory shard",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("kind", true, "KIND"), RequestField::body("key", false), RequestField::body("shard", false)]),
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/discover/subscribe/:kind/:shard",
        cli_name: "group discover-unsubscribe",
        description: "Unsubscribe from a directory shard",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/cards/:id",
        cli_name: "group card",
        description: "Fetch a single group card",
        category: "named-groups",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/cards/import",
        cli_name: "group card-import",
        description: "Import a group card into local cache",
        category: "named-groups",
        request: RequestSpec::Passthrough,
    },
    // ── Phase D.2: cross-daemon group shared-secret encryption ──────────
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/secure/encrypt",
        cli_name: "group secure-encrypt",
        description: "Encrypt content with the group's shared secret (member-only)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("payload_b64", true, "PAYLOAD")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/secure/decrypt",
        cli_name: "group secure-decrypt",
        description:
            "Decrypt content with the group's shared secret (member-only, epoch must match)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("ciphertext_b64", true, "CIPHERTEXT_B64"), RequestField::body_as("nonce_b64", false, "NONCE_B64"), RequestField::body_as("secret_epoch", false, "SECRET_EPOCH")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/secure/reseal",
        cli_name: "group secure-reseal",
        description:
            "Re-seal the current group shared secret to a named recipient (produces a real SecureShareDelivered-format envelope)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_as("recipient", true, "RECIPIENT")]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/secure/open-envelope",
        cli_name: "group secure-open-envelope",
        description:
            "Attempt to open a SecureShareDelivered envelope with this daemon's KEM key (adversarial test)",
        category: "named-groups",
        request: RequestSpec::Fields(&[RequestField::body_json_doc("group_id", true), RequestField::body_json_doc("recipient", true), RequestField::body_json_doc("secret_epoch", true), RequestField::body_json_doc("kem_ciphertext_b64", true), RequestField::body_json_doc("aead_nonce_b64", true), RequestField::body_json_doc("aead_ciphertext_b64", true)]),
    },
    // ── Task lists ──────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/task-lists",
        cli_name: "tasks list",
        description: "List task lists",
        category: "tasks",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/task-lists",
        cli_name: "tasks create",
        description: "Create task list",
        category: "tasks",
        request: RequestSpec::Fields(&[RequestField::body_as("name", true, "NAME"), RequestField::body_as("topic", true, "TOPIC")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/task-lists/:id/tasks",
        cli_name: "tasks show",
        description: "Show tasks in list",
        category: "tasks",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/task-lists/:id/tasks",
        cli_name: "tasks add",
        description: "Add task to list",
        category: "tasks",
        request: RequestSpec::Fields(&[RequestField::body_as("title", true, "TITLE"), RequestField::body("description", false)]),
    },
    EndpointDef {
        method: Method::Patch,
        path: "/task-lists/:id/tasks/:tid",
        cli_name: "tasks claim / tasks complete",
        description: "Claim or complete a task (action: claim|complete)",
        category: "tasks",
        request: RequestSpec::Fields(&[RequestField::body_derived("action", true), RequestField::body("fence_token", false), RequestField::body("delegation", false)]),
    },
    // ── Key-value stores ────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/stores",
        cli_name: "store list",
        description: "List key-value stores",
        category: "stores",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/stores",
        cli_name: "store create",
        description: "Create key-value store",
        category: "stores",
        request: RequestSpec::Fields(&[RequestField::body_as("name", true, "NAME"), RequestField::body_as("topic", true, "TOPIC"), RequestField::body("policy", false)]),
    },
    EndpointDef {
        method: Method::Post,
        path: "/stores/:id/join",
        cli_name: "store join",
        description: "Join existing store",
        category: "stores",
        request: RequestSpec::Fields(&[RequestField::body_as("expected_owner", false, "--owner"), RequestField::body("policy", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/stores/:id/keys",
        cli_name: "store keys",
        description: "List keys in store",
        category: "stores",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Put,
        path: "/stores/:id/:key",
        cli_name: "store put",
        description: "Put value in store",
        category: "stores",
        request: RequestSpec::Fields(&[RequestField::body_as("value", true, "VALUE"), RequestField::body_as("content_type", false, "--content-type")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/stores/:id/:key",
        cli_name: "store get",
        description: "Get value from store",
        category: "stores",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Delete,
        path: "/stores/:id/:key",
        cli_name: "store rm",
        description: "Remove key from store",
        category: "stores",
        request: RequestSpec::None,
    },
    // ── Files ──────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/files/send",
        cli_name: "send-file",
        description: "Send file to agent",
        category: "files",
        request: RequestSpec::Passthrough,
    },
    EndpointDef {
        method: Method::Get,
        path: "/files/transfers",
        cli_name: "transfers",
        description: "List file transfers",
        category: "files",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/files/transfers/:id",
        cli_name: "transfer-status",
        description: "Transfer status",
        category: "files",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/files/accept/:id",
        cli_name: "accept-file",
        description: "Accept incoming transfer",
        category: "files",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/files/reject/:id",
        cli_name: "reject-file",
        description: "Reject incoming transfer",
        category: "files",
        request: RequestSpec::Fields(&[RequestField::body_as("reason", false, "--reason")]),
    },
    // ── Constitution ──────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/constitution",
        cli_name: "constitution",
        description: "Display the x0x Constitution (Markdown)",
        category: "status",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/constitution/json",
        cli_name: "constitution --json",
        description: "Constitution with version metadata (JSON)",
        category: "status",
        request: RequestSpec::None,
    },
    // ── Upgrade ─────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/upgrade",
        cli_name: "upgrade",
        description: "Daemon-side check for updates over x0x/release manifests (the CLI x0x upgrade is a standalone GitHub updater and does not call this)",
        category: "upgrade",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Post,
        path: "/upgrade/apply",
        cli_name: "upgrade --apply",
        description: "Daemon applies the latest verified release manifest with transactional restart (CLI x0x upgrade applies via its standalone GitHub path instead)",
        category: "upgrade",
        request: RequestSpec::None,
    },
    // ── WebSocket ───────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/ws",
        cli_name: "ws",
        description: "General-purpose WebSocket session",
        category: "websocket",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/ws/direct",
        cli_name: "ws direct",
        description: "WebSocket session for direct messaging",
        category: "websocket",
        request: RequestSpec::Fields(&[RequestField::query("backfill", false)]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/ws/sessions",
        cli_name: "ws sessions",
        description: "List WebSocket sessions",
        category: "websocket",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/gui",
        cli_name: "gui",
        description: "Open the embedded GUI",
        category: "websocket",
        request: RequestSpec::None,
    },
    // ── Tailnet forwarding (#132 T6) ────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/forwards",
        cli_name: "forward add",
        description: "Add a local port forward to a peer's loopback service",
        category: "connect",
        request: RequestSpec::Fields(&[RequestField::body_as("local_addr", true, "--local"), RequestField::body_as("peer_agent", true, "--peer"), RequestField::body_as("target_host", true, "--target"), RequestField::body_as("target_port", true, "--target-port")]),
    },
    EndpointDef {
        method: Method::Get,
        path: "/forwards",
        cli_name: "forward list",
        description: "List registered port forwards",
        category: "connect",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Delete,
        path: "/forwards/:local_addr",
        cli_name: "forward rm",
        description: "Remove a port forward by its local bind address",
        category: "connect",
        request: RequestSpec::None,
    },
    EndpointDef {
        method: Method::Get,
        path: "/streams",
        cli_name: "streams",
        description: "Active forward-stream count + connect-ACL counters",
        category: "connect",
        request: RequestSpec::None,
    },
];

/// Find an endpoint by its CLI name.
pub fn find_by_cli_name(name: &str) -> Option<&'static EndpointDef> {
    ENDPOINTS.iter().find(|e| e.cli_name == name)
}

/// Get all endpoints in a given category.
pub fn by_category(category: &str) -> Vec<&'static EndpointDef> {
    ENDPOINTS
        .iter()
        .filter(|e| e.category == category)
        .collect()
}

/// Get all unique categories, in order of first appearance.
pub fn categories() -> Vec<&'static str> {
    let mut cats: Vec<&'static str> = Vec::new();
    for ep in ENDPOINTS {
        if !cats.contains(&ep.category) {
            cats.push(ep.category);
        }
    }
    cats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_is_not_empty() {
        assert!(!ENDPOINTS.is_empty());
    }

    #[test]
    fn every_endpoint_has_non_empty_fields() {
        for ep in ENDPOINTS {
            assert!(!ep.path.is_empty(), "path empty for {}", ep.cli_name);
            assert!(!ep.cli_name.is_empty(), "cli_name empty for {}", ep.path);
            assert!(
                !ep.description.is_empty(),
                "description empty for {}",
                ep.cli_name
            );
            assert!(
                !ep.category.is_empty(),
                "category empty for {}",
                ep.cli_name
            );
        }
    }

    #[test]
    fn every_path_starts_with_slash() {
        for ep in ENDPOINTS {
            assert!(
                ep.path.starts_with('/'),
                "path '{}' for {} does not start with /",
                ep.path,
                ep.cli_name
            );
        }
    }

    #[test]
    fn cli_names_are_unique() {
        let mut names: Vec<&str> = ENDPOINTS.iter().map(|e| e.cli_name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), ENDPOINTS.len());
    }

    #[test]
    fn paths_are_unique_per_method() {
        // Same path can appear with different methods (e.g. GET vs POST)
        // Use a HashSet of (method, path) tuples
        let mut seen = std::collections::HashSet::new();
        for ep in ENDPOINTS {
            let key = (ep.method as u8, ep.path);
            assert!(
                seen.insert(key),
                "duplicate (method={}, path={})",
                ep.method,
                ep.path
            );
        }
    }

    #[test]
    fn find_by_cli_name_finds_existing() {
        let health = find_by_cli_name("health");
        assert!(health.is_some());
        assert_eq!(health.unwrap().path, "/health");
    }

    #[test]
    fn find_by_cli_name_returns_none_for_unknown() {
        assert!(find_by_cli_name("nonexistent-command-xyz").is_none());
    }

    #[test]
    fn by_category_returns_all_matching() {
        let status = by_category("status");
        assert!(!status.is_empty());
        for ep in &status {
            assert_eq!(ep.category, "status");
        }
    }

    #[test]
    fn by_category_returns_empty_for_unknown() {
        let result = by_category("nonexistent-category");
        assert!(result.is_empty());
    }

    #[test]
    fn categories_returns_unique_sorted_order() {
        let cats = categories();
        assert!(!cats.is_empty());
        // Verify no duplicates
        let mut sorted = cats.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), cats.len());
    }

    #[test]
    fn method_display() {
        assert_eq!(Method::Get.to_string(), "GET");
        assert_eq!(Method::Post.to_string(), "POST");
        assert_eq!(Method::Put.to_string(), "PUT");
        assert_eq!(Method::Patch.to_string(), "PATCH");
        assert_eq!(Method::Delete.to_string(), "DELETE");
    }

    #[test]
    fn every_endpoint_has_valid_method() {
        for ep in ENDPOINTS {
            match ep.method {
                Method::Get | Method::Post | Method::Put | Method::Patch | Method::Delete => {}
            }
        }
    }

    #[test]
    fn categories_contains_expected() {
        let cats = categories();
        assert!(cats.contains(&"status"), "missing status");
        assert!(cats.contains(&"identity"), "missing identity");
        assert!(cats.contains(&"contacts"), "missing contacts");
        assert!(cats.contains(&"groups"), "missing groups");
        assert!(cats.contains(&"named-groups"), "missing named-groups");
        assert!(cats.contains(&"tasks"), "missing tasks");
        assert!(cats.contains(&"files"), "missing files");
        assert!(cats.contains(&"exec"), "missing exec");
        assert!(cats.contains(&"upgrade"), "missing upgrade");
        assert!(cats.contains(&"network"), "missing network");
        assert!(cats.contains(&"presence"), "missing presence");
        assert!(cats.contains(&"messaging"), "missing messaging");
        assert!(cats.contains(&"stores"), "missing stores");
        assert!(cats.contains(&"direct"), "missing direct");
        assert!(cats.contains(&"discovery"), "missing discovery");
        assert!(cats.contains(&"machines"), "missing machines");
        assert!(cats.contains(&"trust"), "missing trust");
        assert!(cats.contains(&"websocket"), "missing websocket");
    }
}
