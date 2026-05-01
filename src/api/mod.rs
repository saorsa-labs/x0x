//! Shared endpoint registry for the x0x REST API.
//!
//! Both `x0xd` (the daemon) and `x0x` (the CLI) consume this registry,
//! ensuring routes and CLI commands never drift out of sync.

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
    },
    EndpointDef {
        method: Method::Get,
        path: "/status",
        cli_name: "status",
        description: "Runtime status with uptime",
        category: "status",
    },
    EndpointDef {
        method: Method::Post,
        path: "/shutdown",
        cli_name: "stop",
        description: "Gracefully stop the daemon",
        category: "status",
    },
    // ── Identity ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/agent",
        cli_name: "agent",
        description: "Agent identity info",
        category: "identity",
    },
    EndpointDef {
        method: Method::Post,
        path: "/announce",
        cli_name: "announce",
        description: "Announce identity to network",
        category: "identity",
    },
    EndpointDef {
        method: Method::Get,
        path: "/agent/user-id",
        cli_name: "agent user-id",
        description: "Current agent user ID",
        category: "identity",
    },
    EndpointDef {
        method: Method::Get,
        path: "/agent/card",
        cli_name: "agent card",
        description: "Generate shareable identity card",
        category: "identity",
    },
    EndpointDef {
        method: Method::Get,
        path: "/introduction",
        cli_name: "agent introduction",
        description: "Introduction card with trust-scoped disclosure",
        category: "identity",
    },
    EndpointDef {
        method: Method::Post,
        path: "/agent/card/import",
        cli_name: "agent import",
        description: "Import agent card to contacts",
        category: "identity",
    },
    // ── Network ─────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/peers",
        cli_name: "peers",
        description: "Connected gossip peers",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence",
        cli_name: "presence",
        description: "Online agents (alias for /presence/online)",
        category: "presence",
    },
    // ── Presence ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/presence/online",
        cli_name: "presence online",
        description: "List all currently online agents (network view, non-blocked)",
        category: "presence",
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/foaf",
        cli_name: "presence foaf",
        description: "FOAF random-walk discovery of nearby agents (social view)",
        category: "presence",
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/find/:id",
        cli_name: "presence find",
        description: "Find a specific agent by ID via FOAF random walk",
        category: "presence",
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/status/:id",
        cli_name: "presence status",
        description: "Get local cache presence status for an agent",
        category: "presence",
    },
    EndpointDef {
        method: Method::Get,
        path: "/presence/events",
        cli_name: "presence events",
        description: "Server-Sent Events stream of presence online/offline events",
        category: "presence",
    },
    EndpointDef {
        method: Method::Get,
        path: "/network/status",
        cli_name: "network status",
        description: "Network connectivity details",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/network/bootstrap-cache",
        cli_name: "network cache",
        description: "Bootstrap peer cache stats",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/connectivity",
        cli_name: "diagnostics connectivity",
        description: "Ant-quic NodeStatus snapshot (UPnP, NAT, relay, mDNS)",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/gossip",
        cli_name: "diagnostics gossip",
        description: "PubSub drop-detection counters (publish/deliver deltas)",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/dm",
        cli_name: "diagnostics dm",
        description: "Direct-message send/receive counters and per-peer health",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/groups",
        cli_name: "diagnostics groups",
        description: "Per-group ingest counters, listener state, and drop buckets",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/diagnostics/exec",
        cli_name: "diagnostics exec",
        description: "Remote exec counters, warnings, active sessions, and ACL summary",
        category: "exec",
    },
    EndpointDef {
        method: Method::Post,
        path: "/peers/:peer_id/probe",
        cli_name: "peer probe",
        description: "Active ant-quic probe_peer liveness + RTT (ant-quic 0.27.2 #173)",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/peers/:peer_id/health",
        cli_name: "peer health",
        description: "Connection health snapshot for a peer (ant-quic 0.27.1 #170)",
        category: "network",
    },
    EndpointDef {
        method: Method::Get,
        path: "/peers/events",
        cli_name: "peer events",
        description: "SSE stream of peer lifecycle events (ant-quic 0.27.1 #171)",
        category: "network",
    },
    // ── Messaging ───────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/publish",
        cli_name: "publish",
        description: "Publish message to topic",
        category: "messaging",
    },
    EndpointDef {
        method: Method::Post,
        path: "/subscribe",
        cli_name: "subscribe",
        description: "Subscribe to topic",
        category: "messaging",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/subscribe/:id",
        cli_name: "unsubscribe",
        description: "Unsubscribe by ID",
        category: "messaging",
    },
    EndpointDef {
        method: Method::Get,
        path: "/events",
        cli_name: "events",
        description: "SSE event stream",
        category: "messaging",
    },
    // ── Discovery ───────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/agents/discovered",
        cli_name: "agents list",
        description: "List discovered agents",
        category: "discovery",
    },
    EndpointDef {
        method: Method::Get,
        path: "/agents/discovered/:agent_id",
        cli_name: "agents get",
        description: "Get discovered agent details",
        category: "discovery",
    },
    EndpointDef {
        method: Method::Get,
        path: "/agents/:agent_id/machine",
        cli_name: "agents machine",
        description: "Resolve agent to current machine endpoint",
        category: "discovery",
    },
    EndpointDef {
        method: Method::Get,
        path: "/machines/discovered",
        cli_name: "machines discovered",
        description: "List discovered machine endpoints",
        category: "machines",
    },
    EndpointDef {
        method: Method::Get,
        path: "/machines/discovered/:machine_id",
        cli_name: "machines get",
        description: "Get discovered machine endpoint details",
        category: "machines",
    },
    EndpointDef {
        method: Method::Post,
        path: "/agents/find/:agent_id",
        cli_name: "agents find",
        description: "Find agent on network",
        category: "discovery",
    },
    EndpointDef {
        method: Method::Get,
        path: "/agents/reachability/:agent_id",
        cli_name: "agents reachability",
        description: "Agent reachability info",
        category: "discovery",
    },
    EndpointDef {
        method: Method::Get,
        path: "/users/:user_id/agents",
        cli_name: "agents by-user",
        description: "Agents by user ID",
        category: "discovery",
    },
    EndpointDef {
        method: Method::Get,
        path: "/users/:user_id/machines",
        cli_name: "machines by-user",
        description: "Machine endpoints by user ID",
        category: "machines",
    },
    // ── Contacts ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/contacts",
        cli_name: "contacts list",
        description: "List contacts",
        category: "contacts",
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts",
        cli_name: "contacts add",
        description: "Add contact",
        category: "contacts",
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/trust",
        cli_name: "trust set",
        description: "Quick trust/block",
        category: "contacts",
    },
    EndpointDef {
        method: Method::Patch,
        path: "/contacts/:agent_id",
        cli_name: "contacts update",
        description: "Update contact trust",
        category: "contacts",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/contacts/:agent_id",
        cli_name: "contacts remove",
        description: "Remove contact",
        category: "contacts",
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/:agent_id/revoke",
        cli_name: "contacts revoke",
        description: "Revoke contact",
        category: "contacts",
    },
    EndpointDef {
        method: Method::Get,
        path: "/contacts/:agent_id/revocations",
        cli_name: "contacts revocations",
        description: "List revocations",
        category: "contacts",
    },
    // ── Machines ────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/contacts/:agent_id/machines",
        cli_name: "machines list",
        description: "List machines for contact",
        category: "machines",
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/:agent_id/machines",
        cli_name: "machines add",
        description: "Add machine record",
        category: "machines",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/contacts/:agent_id/machines/:machine_id",
        cli_name: "machines remove",
        description: "Remove machine record",
        category: "machines",
    },
    EndpointDef {
        method: Method::Post,
        path: "/contacts/:agent_id/machines/:machine_id/pin",
        cli_name: "machines pin",
        description: "Pin machine",
        category: "machines",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/contacts/:agent_id/machines/:machine_id/pin",
        cli_name: "machines unpin",
        description: "Unpin machine",
        category: "machines",
    },
    // ── Trust ───────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/trust/evaluate",
        cli_name: "trust evaluate",
        description: "Evaluate trust for agent+machine",
        category: "trust",
    },
    // ── Direct messaging ────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/agents/connect",
        cli_name: "direct connect",
        description: "Connect to agent",
        category: "direct",
    },
    EndpointDef {
        method: Method::Post,
        path: "/machines/connect",
        cli_name: "machines connect",
        description: "Connect to machine",
        category: "direct",
    },
    EndpointDef {
        method: Method::Post,
        path: "/direct/send",
        cli_name: "direct send",
        description: "Send direct message",
        category: "direct",
    },
    EndpointDef {
        method: Method::Get,
        path: "/direct/connections",
        cli_name: "direct connections",
        description: "List direct connections",
        category: "direct",
    },
    EndpointDef {
        method: Method::Get,
        path: "/direct/events",
        cli_name: "direct events",
        description: "Stream direct messages",
        category: "direct",
    },
    // ── Exec ───────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/exec/run",
        cli_name: "exec",
        description: "Run a strictly allowlisted non-interactive command on a remote daemon",
        category: "exec",
    },
    EndpointDef {
        method: Method::Post,
        path: "/exec/cancel",
        cli_name: "exec cancel",
        description: "Cancel an in-flight remote exec request",
        category: "exec",
    },
    EndpointDef {
        method: Method::Get,
        path: "/exec/sessions",
        cli_name: "exec sessions",
        description: "List local pending and remote active exec sessions",
        category: "exec",
    },
    // ── MLS groups ──────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups",
        cli_name: "groups create",
        description: "Create encrypted group",
        category: "groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/mls/groups",
        cli_name: "groups list",
        description: "List groups",
        category: "groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/mls/groups/:id",
        cli_name: "groups get",
        description: "Get group details",
        category: "groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/members",
        cli_name: "groups add-member",
        description: "Add member to group",
        category: "groups",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/mls/groups/:id/members/:agent_id",
        cli_name: "groups remove-member",
        description: "Remove member",
        category: "groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/encrypt",
        cli_name: "groups encrypt",
        description: "Encrypt for group",
        category: "groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/decrypt",
        cli_name: "groups decrypt",
        description: "Decrypt from group",
        category: "groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/mls/groups/:id/welcome",
        cli_name: "groups welcome",
        description: "Create welcome for member",
        category: "groups",
    },
    // ── Named groups (high-level) ─────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/groups",
        cli_name: "group create",
        description: "Create named group",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups",
        cli_name: "group list",
        description: "List groups",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id",
        cli_name: "group info",
        description: "Get group info",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/members",
        cli_name: "group members",
        description: "List named-group members",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/members",
        cli_name: "group add-member",
        description: "Add named-group member",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id/members/:agent_id",
        cli_name: "group remove-member",
        description: "Remove named-group member",
        category: "named-groups",
    },
    // ── Phase E: public-group messaging ──────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/send",
        cli_name: "group send",
        description: "Publish a signed message to a SignedPublic group",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/messages",
        cli_name: "group messages",
        description: "Retrieve cached public messages (non-members on Public read)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/invite",
        cli_name: "group invite",
        description: "Generate invite link",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/join",
        cli_name: "group join",
        description: "Join group via invite",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Put,
        path: "/groups/:id/display-name",
        cli_name: "group set-name",
        description: "Set display name in group",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id",
        cli_name: "group leave",
        description: "Leave or delete a group",
        category: "named-groups",
    },
    // ── Phase D.3: state-commit chain ────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/state",
        cli_name: "group state",
        description: "Inspect the signed state-commit chain for a group",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/state/seal",
        cli_name: "group state-seal",
        description: "Advance the state-commit chain and republish signed card",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/state/withdraw",
        cli_name: "group state-withdraw",
        description: "Seal a terminal withdrawal commit and supersede public card",
        category: "named-groups",
    },
    // ── Named groups: policy, roles, join requests, discovery ───────────
    EndpointDef {
        method: Method::Patch,
        path: "/groups/:id",
        cli_name: "group update",
        description: "Update group name/description (admin+)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Patch,
        path: "/groups/:id/policy",
        cli_name: "group policy",
        description: "Update group policy (owner only)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Patch,
        path: "/groups/:id/members/:agent_id/role",
        cli_name: "group set-role",
        description: "Change a member's role (admin+)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/ban/:agent_id",
        cli_name: "group ban",
        description: "Ban a member (admin+)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id/ban/:agent_id",
        cli_name: "group unban",
        description: "Unban a member (admin+)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/:id/requests",
        cli_name: "group requests",
        description: "List join requests (admin+)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/requests",
        cli_name: "group request-access",
        description: "Submit a join request",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/requests/:request_id/approve",
        cli_name: "group approve-request",
        description: "Approve a join request (admin+)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/requests/:request_id/reject",
        cli_name: "group reject-request",
        description: "Reject a join request (admin+)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/:id/requests/:request_id",
        cli_name: "group cancel-request",
        description: "Cancel own pending join request",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/discover",
        cli_name: "group discover",
        description: "List locally known discoverable groups",
        category: "named-groups",
    },
    // ── Phase C.2: shard-based distributed discovery ─────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/groups/discover/nearby",
        cli_name: "group discover-nearby",
        description: "Presence-social browse of PublicDirectory groups",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/discover/subscriptions",
        cli_name: "group discover-subscriptions",
        description: "List active shard subscriptions",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/discover/subscribe",
        cli_name: "group discover-subscribe",
        description: "Subscribe to a tag/name/id directory shard",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/groups/discover/subscribe/:kind/:shard",
        cli_name: "group discover-unsubscribe",
        description: "Unsubscribe from a directory shard",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Get,
        path: "/groups/cards/:id",
        cli_name: "group card",
        description: "Fetch a single group card",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/cards/import",
        cli_name: "group card-import",
        description: "Import a group card into local cache",
        category: "named-groups",
    },
    // ── Phase D.2: cross-daemon group shared-secret encryption ──────────
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/secure/encrypt",
        cli_name: "group secure-encrypt",
        description: "Encrypt content with the group's shared secret (member-only)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/secure/decrypt",
        cli_name: "group secure-decrypt",
        description:
            "Decrypt content with the group's shared secret (member-only, epoch must match)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/:id/secure/reseal",
        cli_name: "group secure-reseal",
        description:
            "Re-seal the current group shared secret to a named recipient (produces a real SecureShareDelivered-format envelope)",
        category: "named-groups",
    },
    EndpointDef {
        method: Method::Post,
        path: "/groups/secure/open-envelope",
        cli_name: "group secure-open-envelope",
        description:
            "Attempt to open a SecureShareDelivered envelope with this daemon's KEM key (adversarial test)",
        category: "named-groups",
    },
    // ── Task lists ──────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/task-lists",
        cli_name: "tasks list",
        description: "List task lists",
        category: "tasks",
    },
    EndpointDef {
        method: Method::Post,
        path: "/task-lists",
        cli_name: "tasks create",
        description: "Create task list",
        category: "tasks",
    },
    EndpointDef {
        method: Method::Get,
        path: "/task-lists/:id/tasks",
        cli_name: "tasks show",
        description: "Show tasks in list",
        category: "tasks",
    },
    EndpointDef {
        method: Method::Post,
        path: "/task-lists/:id/tasks",
        cli_name: "tasks add",
        description: "Add task to list",
        category: "tasks",
    },
    EndpointDef {
        method: Method::Patch,
        path: "/task-lists/:id/tasks/:tid",
        cli_name: "tasks claim / tasks complete",
        description: "Claim or complete a task (action: claim|complete)",
        category: "tasks",
    },
    // ── Key-value stores ────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/stores",
        cli_name: "store list",
        description: "List key-value stores",
        category: "stores",
    },
    EndpointDef {
        method: Method::Post,
        path: "/stores",
        cli_name: "store create",
        description: "Create key-value store",
        category: "stores",
    },
    EndpointDef {
        method: Method::Post,
        path: "/stores/:id/join",
        cli_name: "store join",
        description: "Join existing store",
        category: "stores",
    },
    EndpointDef {
        method: Method::Get,
        path: "/stores/:id/keys",
        cli_name: "store keys",
        description: "List keys in store",
        category: "stores",
    },
    EndpointDef {
        method: Method::Put,
        path: "/stores/:id/:key",
        cli_name: "store put",
        description: "Put value in store",
        category: "stores",
    },
    EndpointDef {
        method: Method::Get,
        path: "/stores/:id/:key",
        cli_name: "store get",
        description: "Get value from store",
        category: "stores",
    },
    EndpointDef {
        method: Method::Delete,
        path: "/stores/:id/:key",
        cli_name: "store rm",
        description: "Remove key from store",
        category: "stores",
    },
    // ── Files ──────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Post,
        path: "/files/send",
        cli_name: "send-file",
        description: "Send file to agent",
        category: "files",
    },
    EndpointDef {
        method: Method::Get,
        path: "/files/transfers",
        cli_name: "transfers",
        description: "List file transfers",
        category: "files",
    },
    EndpointDef {
        method: Method::Get,
        path: "/files/transfers/:id",
        cli_name: "transfer-status",
        description: "Transfer status",
        category: "files",
    },
    EndpointDef {
        method: Method::Post,
        path: "/files/accept/:id",
        cli_name: "accept-file",
        description: "Accept incoming transfer",
        category: "files",
    },
    EndpointDef {
        method: Method::Post,
        path: "/files/reject/:id",
        cli_name: "reject-file",
        description: "Reject incoming transfer",
        category: "files",
    },
    // ── Constitution ──────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/constitution",
        cli_name: "constitution",
        description: "Display the x0x Constitution (Markdown)",
        category: "status",
    },
    EndpointDef {
        method: Method::Get,
        path: "/constitution/json",
        cli_name: "constitution --json",
        description: "Constitution with version metadata (JSON)",
        category: "status",
    },
    // ── Upgrade ─────────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/upgrade",
        cli_name: "upgrade",
        description: "Check for updates",
        category: "upgrade",
    },
    EndpointDef {
        method: Method::Post,
        path: "/upgrade/apply",
        cli_name: "upgrade --apply",
        description: "Apply the latest verified release manifest",
        category: "upgrade",
    },
    // ── WebSocket ───────────────────────────────────────────────────────
    EndpointDef {
        method: Method::Get,
        path: "/ws",
        cli_name: "ws",
        description: "General-purpose WebSocket session",
        category: "websocket",
    },
    EndpointDef {
        method: Method::Get,
        path: "/ws/direct",
        cli_name: "ws direct",
        description: "WebSocket session for direct messaging",
        category: "websocket",
    },
    EndpointDef {
        method: Method::Get,
        path: "/ws/sessions",
        cli_name: "ws sessions",
        description: "List WebSocket sessions",
        category: "websocket",
    },
    EndpointDef {
        method: Method::Get,
        path: "/gui",
        cli_name: "gui",
        description: "Open the embedded GUI",
        category: "websocket",
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
