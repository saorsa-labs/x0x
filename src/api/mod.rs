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
        description: "Online agents",
        category: "network",
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
