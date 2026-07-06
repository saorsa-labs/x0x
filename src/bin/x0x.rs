//! `x0x` — unified CLI for the x0x agent network.
//!
//! Starts, stops, and controls a running `x0xd` daemon through its REST API.
//! Every endpoint is available as a subcommand.
//!
//! ## Usage
//!
//! ```bash
//! x0x start                            # start daemon
//! x0x health                           # health check
//! x0x agent                            # show identity
//! x0x contacts                         # list contacts
//! x0x publish "topic" "hello"          # publish message
//! x0x --json status                    # JSON output
//! x0x --name alice health              # target named instance
//! ```

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use x0x::cli::commands;
use x0x::cli::{DaemonClient, OutputFormat};

/// x0x agent network — control a running x0xd daemon.
#[derive(Parser)]
#[command(name = "x0x", version = x0x::VERSION, about = "x0x agent network — control a running x0xd daemon")]
struct Cli {
    /// Named instance to target (reads port from data dir). [dev]
    //
    // The clap field id MUST stay distinct from any subcommand's `name`
    // argument: a shared id collides under `global = true` and the
    // last-parsed value wins, so a positional like `group create <NAME>`
    // would otherwise bleed into this instance selector and route the
    // command at a non-existent daemon instance. Keep the `--name` long flag
    // (established dev/multi-instance API) but bind it to `instance`.
    #[arg(long = "name", global = true, hide = true)]
    instance: Option<String>,

    /// Daemon API address override (default: auto-detect). [dev]
    #[arg(long, global = true, hide = true, alias = "api-url")]
    api: Option<String>,

    /// Backward-compatible output format selector (`json` or `text`). [dev]
    #[arg(long, global = true, hide = true)]
    format: Option<String>,

    /// Output as JSON.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the x0xd daemon.
    Start {
        /// Path to config file.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Run in foreground (default: background).
        #[arg(long)]
        foreground: bool,
    },
    /// Stop a running daemon.
    Stop,
    /// List running daemon instances. [dev]
    #[command(hide = true)]
    Instances,
    /// Pre-flight diagnostics. [dev]
    #[command(hide = true)]
    Doctor,
    /// Configure daemon to start on boot (systemd/launchd).
    Autostart {
        /// Remove autostart configuration.
        #[arg(long)]
        remove: bool,
    },
    /// Health check.
    Health,
    /// Runtime status with uptime and connectivity.
    Status,
    /// Show agent identity.
    Agent {
        #[command(subcommand)]
        sub: Option<AgentSub>,
    },
    /// Manage user identity.
    UserId {
        #[command(subcommand)]
        sub: UserIdSub,
    },
    /// Announce identity to network.
    Announce {
        /// Include user identity in announcement.
        #[arg(long)]
        include_user: bool,
        /// Consent to share human identity.
        #[arg(long)]
        consent: bool,
    },
    /// List connected gossip peers.
    Peers,
    /// Presence and agent discovery operations.
    Presence {
        #[command(subcommand)]
        sub: Option<PresenceSub>,
    },
    /// Network diagnostics.
    Network {
        #[command(subcommand)]
        sub: NetworkSub,
    },
    /// Peer-level observability (ant-quic 0.27 surface).
    Peer {
        #[command(subcommand)]
        sub: PeerSub,
    },
    /// Connectivity diagnostics (ant-quic NodeStatus snapshot).
    Diagnostics {
        #[command(subcommand)]
        sub: DiagnosticsSub,
    },
    /// Session-token management (#127 / WS1.6).
    Auth {
        #[command(subcommand)]
        sub: AuthSub,
    },
    /// Find agents by 4-word speakable identity.
    Find {
        /// Identity words (4 words for agent, or 8 with @ separator).
        words: Vec<String>,
    },
    /// Connect to an agent by 4-word location words.
    Connect {
        /// Location words (4 words decoded to IP:port).
        words: Vec<String>,
    },
    /// Discovered agents.
    Agents {
        #[command(subcommand)]
        sub: Option<AgentsSub>,
    },
    /// Manage contacts.
    Contacts {
        #[command(subcommand)]
        sub: Option<ContactsSub>,
    },
    /// Manage machine records for contacts.
    Machines {
        #[command(subcommand)]
        sub: MachinesSub,
    },
    /// Trust management.
    Trust {
        #[command(subcommand)]
        sub: TrustSub,
    },
    /// Publish a message to a gossip topic.
    Publish {
        /// Topic name.
        topic: String,
        /// Message payload (auto base64-encoded).
        payload: String,
    },
    /// Subscribe to a topic (streams messages to stdout).
    Subscribe {
        /// Topic name.
        topic: String,
    },
    /// Unsubscribe from a topic by subscription ID.
    Unsubscribe {
        /// Subscription ID.
        id: String,
    },
    /// Stream all gossip events to stdout.
    Events,
    /// Remote non-interactive exec over the x0x mesh.
    ///
    /// Run a command:   `x0x exec <agent_id> -- <argv...>`
    /// List sessions:   `x0x exec sessions`
    /// Cancel a request: `x0x exec cancel <request_id>` (or `--cancel <id>`)
    ///
    /// Note: `sessions` and `cancel` are reserved sub-actions. They never
    /// collide with a real target because agent IDs are 64-char hex strings.
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Exec {
        /// Target agent ID (64-char hex).
        agent_id: Option<String>,
        /// Remote timeout in seconds (remote ACL caps apply).
        #[arg(long)]
        timeout: Option<u32>,
        /// Send stdin from this file.
        #[arg(long)]
        stdin_file: Option<PathBuf>,
        /// Cancel an in-flight request id.
        #[arg(long)]
        cancel: Option<String>,
        /// Command argv. Use `--` before argv to preserve flags.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
        /// `sessions` / `cancel` sub-actions.
        #[command(subcommand)]
        sub: Option<ExecSub>,
    },
    /// Direct messaging.
    Direct {
        #[command(subcommand)]
        sub: DirectSub,
    },
    /// MLS encrypted groups.
    Groups {
        #[command(subcommand)]
        sub: Option<GroupsSub>,
    },
    /// Named group management (create, invite, join).
    Group {
        #[command(subcommand)]
        sub: Option<GroupSub>,
    },
    /// Key-value store operations.
    Store {
        #[command(subcommand)]
        sub: Option<StoreSub>,
    },
    /// Collaborative task lists (CRDTs).
    Tasks {
        #[command(subcommand)]
        sub: Option<TasksSub>,
    },
    /// Check for updates and upgrade (no daemon needed).
    Upgrade {
        /// Just check for updates, don't apply.
        #[arg(long)]
        check: bool,
        /// Apply the latest verified release manifest. Mirrors
        /// `POST /upgrade/apply`. Default behaviour when no flags are
        /// passed; this flag exists so the REST/CLI parity tests can
        /// drive `x0x upgrade --apply` explicitly.
        #[arg(long)]
        apply: bool,
        /// Skip version comparison, download and install latest.
        #[arg(long)]
        force: bool,
    },
    /// WebSocket session info. [dev]
    #[command(hide = true)]
    Ws {
        #[command(subcommand)]
        sub: Option<WsSub>,
    },
    /// Open the x0x GUI in your browser.
    Gui,
    /// Print all API routes. [dev]
    #[command(hide = true)]
    Routes {
        /// Emit the route table as JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Show all commands in a tree view.
    Tree,
    /// Uninstall x0x binaries (keeps your data and keys).
    Uninstall,
    /// Remove ALL x0x data, keys, and configuration. DESTRUCTIVE.
    Purge,
    /// Display the x0x Constitution — The Four Laws of Intelligent Coexistence.
    Constitution {
        /// Output raw markdown instead of prettified text.
        #[arg(long)]
        raw: bool,
        /// Output as JSON (version, status, content).
        #[arg(long)]
        json: bool,
    },
    /// Send a file to an agent.
    SendFile {
        /// Target agent ID (hex).
        agent_id: String,
        /// Path to file to send.
        path: PathBuf,
    },
    /// Watch for incoming file transfers.
    ReceiveFile {
        /// Only accept from this agent.
        #[arg(long)]
        accept_from: Option<String>,
        /// Output directory (default: ~/Downloads/x0x/).
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// List active and recent file transfers.
    Transfers,
    /// Show status for a single file transfer.
    TransferStatus {
        /// Transfer ID.
        transfer_id: String,
    },
    /// Accept an incoming file transfer.
    AcceptFile {
        /// Transfer ID.
        transfer_id: String,
    },
    /// Reject an incoming file transfer.
    RejectFile {
        /// Transfer ID.
        transfer_id: String,
        /// Rejection reason.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Manage key lifecycle: issue and list revocations.
    Identity {
        #[command(subcommand)]
        sub: IdentitySub,
    },
    /// Tailnet port-forwarding (`ssh -L` over x0x byte-streams).
    Forward {
        #[command(subcommand)]
        sub: ForwardSub,
    },
    /// Active byte-stream + connect-ACL diagnostics.
    Streams,
}

// ── Nested subcommands ──────────────────────────────────────────────────

#[derive(Subcommand)]
enum AgentSub {
    /// Show current agent's user ID.
    UserId,
    /// Generate a shareable identity card.
    Card {
        /// Your display name (e.g. "David").
        display_name: Option<String>,
        /// Include group invite links in the card.
        #[arg(long)]
        include_groups: bool,
    },
    /// Show this agent's introduction card.
    Introduction,
    /// Import an agent card (add to contacts).
    Import {
        /// Card link (x0x://agent/...) or raw base64.
        card: String,
        /// Trust level: trusted, known, blocked.
        #[arg(long, default_value = "known")]
        trust: String,
    },
    /// Produce a detached ML-DSA-65 signature over a payload using this
    /// agent's signing key. Pass either `--file <PATH>` (use `-` for
    /// stdin) or `--payload-b64 <BASE64>`.
    Sign {
        /// Path to a file whose bytes will be signed verbatim. Use `-` for stdin.
        #[arg(long, conflicts_with = "payload_b64")]
        file: Option<String>,
        /// Base64-encoded bytes to sign.
        #[arg(long)]
        payload_b64: Option<String>,
        /// Required domain-separation context (e.g.
        /// `x0x-symphony-handoff-v1`). The daemon signs the external DST
        /// `[0xF0]|magic|len|context|payload`, disjoint from every internal
        /// x0x signing input (issue #133). Must match `[a-z0-9._-]{1,64}`.
        #[arg(long)]
        context: String,
    },
    /// Verify a detached ML-DSA-65 signature against a caller-supplied
    /// public key. Pass either `--file <PATH>` (use `-` for stdin) or
    /// `--payload-b64 <BASE64>`. Exits 0 when the signature is valid,
    /// non-zero when it is not.
    Verify {
        /// Path to a file whose bytes were signed verbatim. Use `-` for stdin.
        #[arg(long, conflicts_with = "payload_b64")]
        file: Option<String>,
        /// Base64-encoded bytes the signature was computed over.
        #[arg(long)]
        payload_b64: Option<String>,
        /// Base64-encoded detached ML-DSA-65 signature.
        #[arg(long)]
        signature_b64: String,
        /// Base64-encoded ML-DSA-65 public key (1952 bytes decoded).
        #[arg(long)]
        public_key_b64: String,
        /// Required domain-separation context the signature was produced with.
        #[arg(long)]
        context: String,
    },
}

#[derive(Subcommand)]
enum UserIdSub {
    /// Create a new user identity keypair (ML-DSA-65). Defaults to ~/.x0x/user.key.
    /// Overwrites any existing file at the target path without prompting.
    Create {
        /// Output path. Existing file at this path is overwritten.
        path: Option<PathBuf>,
        /// Derive the keypair deterministically from a 32-byte hex seed
        /// (64 hex chars) via FIPS 204 seeded KeyGen. Same seed, same keypair.
        #[arg(long, value_name = "HEX")]
        from_seed: Option<String>,
    },
    /// Read and validate a user identity file (no daemon needed).
    /// Defaults to ~/.x0x/user.key.
    Inspect {
        /// Path of the key file to inspect.
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum NetworkSub {
    /// Network connectivity status.
    Status,
    /// Bootstrap peer cache stats.
    Cache,
}

/// Peer subcommands (ant-quic 0.27 surface).
#[derive(Subcommand)]
enum PeerSub {
    /// Active-liveness probe (ant-quic 0.27.2 #173). Returns measured RTT.
    Probe {
        /// Peer ID (hex, 32 bytes = 64 hex chars).
        peer_id: String,
        /// Optional probe timeout in milliseconds (default 2000, clamped 100..30000).
        #[arg(long)]
        timeout_ms: Option<u64>,
    },
    /// Connection health snapshot for a peer (ant-quic 0.27.1 #170).
    Health {
        /// Peer ID (hex, 32 bytes = 64 hex chars).
        peer_id: String,
    },
    /// Stream peer lifecycle events via SSE (ant-quic 0.27.1 #171).
    Events,
}

#[derive(Subcommand)]
enum DiagnosticsSub {
    /// Print the ant-quic NodeStatus snapshot (UPnP, NAT, relay, mDNS).
    Connectivity,
    /// Print ACK-v2 stage latency buckets and outcome counters.
    Ack,
    /// Print PubSub drop-detection counters (publish/deliver deltas).
    Gossip,
    /// Print direct-message counters, fan-out health, and per-peer state.
    Dm,
    /// Print per-group ingest counters and drop-reason buckets.
    Groups,
    /// Print remote exec counters, warnings, and ACL summary.
    Exec,
    /// Print connect-ACL policy summary and stream allow/deny counters.
    Connect,
    /// Print WebSocket outbound-queue health (capacity, drops, slow-consumer closes).
    Ws,
}

/// Auth sub-actions (`x0x auth session`).
#[derive(Subcommand)]
enum AuthSub {
    /// Exchange the durable API token for a short-lived browser session token.
    Session,
}

/// Key lifecycle sub-actions (`x0x identity revoke`, `x0x identity revocations`).
#[derive(Subcommand)]
enum IdentitySub {
    /// Issue a signed revocation for an agent-id or machine-id keypair.
    ///
    /// The daemon uses its own agent keypair as the issuer.  Self-revocations
    /// (revoking own agent-id or machine-id) always succeed.  Revoking a
    /// third-party identity requires that the user keypair previously signed
    /// an AgentCertificate for the subject.
    Revoke {
        /// Agent ID to revoke (hex, 64 chars). Exactly one of --agent-id or --machine-id.
        #[arg(long)]
        agent_id: Option<String>,
        /// Machine ID to revoke (hex, 64 chars). Exactly one of --agent-id or --machine-id.
        #[arg(long)]
        machine_id: Option<String>,
        /// Optional human-readable reason stored in the revocation record.
        #[arg(long)]
        reason: Option<String>,
    },
    /// List all revocation records held by this daemon.
    Revocations,
}

/// `x0x forward` sub-actions.
#[derive(Subcommand)]
enum ForwardSub {
    /// Add a local port forward to a peer's loopback service.
    Add {
        /// Local bind address, e.g. `127.0.0.1:8022`.
        #[arg(long)]
        local: String,
        /// Peer agent id (hex).
        #[arg(long)]
        peer: String,
        /// Loopback target host on the peer (numeric IP). Default `127.0.0.1`.
        #[arg(long)]
        target: Option<String>,
        /// Loopback target port on the peer.
        #[arg(long)]
        target_port: u16,
    },
    /// List registered forwards.
    List,
    /// Remove a forward by its local bind address.
    #[command(alias = "rm")]
    Remove {
        /// Local bind address, e.g. `127.0.0.1:8022`.
        local_addr: String,
    },
}

/// Remote exec sub-actions (`x0x exec sessions`, `x0x exec cancel <id>`).
#[derive(Subcommand)]
enum ExecSub {
    /// List exec sessions originated by this local daemon.
    Sessions,
    /// Cancel an in-flight exec request by id.
    Cancel {
        /// Request id to cancel.
        request_id: String,
        /// Optional target agent id the request was sent to.
        #[arg(long)]
        agent_id: Option<String>,
    },
}

/// Presence subcommands.
#[derive(Subcommand)]
enum PresenceSub {
    /// List all currently online agents (network view, non-blocked).
    Online,
    /// FOAF random-walk discovery of nearby agents (social view: Trusted + Known).
    Foaf {
        /// Maximum hop count for the random walk (1–5).
        #[arg(long, default_value = "3")]
        ttl: u8,
        /// Query timeout in milliseconds.
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
    },
    /// Find a specific agent by ID via FOAF random walk.
    Find {
        /// Agent ID (hex, 64 chars).
        id: String,
        /// Maximum hop count for the random walk (1–5).
        #[arg(long, default_value = "3")]
        ttl: u8,
        /// Query timeout in milliseconds.
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
    },
    /// Get local cache presence status for an agent (no network I/O).
    Status {
        /// Agent ID (hex, 64 chars).
        id: String,
    },
    /// Stream presence online/offline events (Server-Sent Events).
    Events,
}

#[derive(Subcommand)]
enum AgentsSub {
    /// List discovered agents.
    List {
        /// Include TTL-expired agents.
        #[arg(long)]
        unfiltered: bool,
    },
    /// Get details for a discovered agent.
    Get {
        /// Agent ID (hex).
        agent_id: String,
        /// Wait for agent to appear (seconds).
        #[arg(long)]
        wait: Option<u64>,
    },
    /// Find an agent on the network (3-stage lookup).
    Find {
        /// Agent ID (hex).
        agent_id: String,
    },
    /// Check agent reachability (direct vs coordinated).
    Reachability {
        /// Agent ID (hex).
        agent_id: String,
    },
    /// Resolve an agent to its current discovered machine endpoint.
    Machine {
        /// Agent ID (hex).
        agent_id: String,
    },
    /// List agents belonging to a user.
    ByUser {
        /// User ID (hex).
        user_id: String,
    },
}

#[derive(Subcommand)]
enum ContactsSub {
    /// List all contacts.
    List,
    /// Add a new contact.
    Add {
        /// Agent ID (hex).
        agent_id: String,
        /// Trust level: blocked, unknown, known, trusted.
        #[arg(long)]
        trust: String,
        /// Optional display label.
        #[arg(long)]
        label: Option<String>,
    },
    /// Update a contact's trust level or identity type.
    Update {
        /// Agent ID (hex).
        agent_id: String,
        /// New trust level.
        #[arg(long)]
        trust: Option<String>,
        /// New identity type.
        #[arg(long)]
        identity_type: Option<String>,
    },
    /// Remove a contact.
    Remove {
        /// Agent ID (hex).
        agent_id: String,
    },
    /// Revoke a contact.
    Revoke {
        /// Agent ID (hex).
        agent_id: String,
        /// Reason for revocation.
        #[arg(long)]
        reason: String,
    },
    /// List revocations for a contact.
    Revocations {
        /// Agent ID (hex).
        agent_id: String,
    },
}

#[derive(Subcommand)]
enum MachinesSub {
    /// List discovered machine endpoints.
    Discovered {
        /// Include TTL-expired machines.
        #[arg(long)]
        unfiltered: bool,
    },
    /// Get details for a discovered machine endpoint.
    Get {
        /// Machine ID (hex).
        machine_id: String,
        /// Wait for the machine to appear before returning.
        #[arg(long)]
        wait: bool,
    },
    /// List machine endpoints belonging to a user.
    ByUser {
        /// User ID (hex).
        user_id: String,
    },
    /// Connect to a discovered machine endpoint.
    Connect {
        /// Machine ID (hex).
        machine_id: String,
    },
    /// List machines for a contact.
    List {
        /// Agent ID (hex).
        agent_id: String,
    },
    /// Add a machine record.
    Add {
        /// Agent ID (hex).
        agent_id: String,
        /// Machine ID (hex).
        machine_id: String,
        /// Pin this machine.
        #[arg(long)]
        pin: bool,
    },
    /// Remove a machine record.
    Remove {
        /// Agent ID (hex).
        agent_id: String,
        /// Machine ID (hex).
        machine_id: String,
    },
    /// Pin a machine to a contact.
    Pin {
        /// Agent ID (hex).
        agent_id: String,
        /// Machine ID (hex).
        machine_id: String,
    },
    /// Unpin a machine from a contact.
    Unpin {
        /// Agent ID (hex).
        agent_id: String,
        /// Machine ID (hex).
        machine_id: String,
    },
}

#[derive(Subcommand)]
enum TrustSub {
    /// Quick-set trust level for an agent.
    Set {
        /// Agent ID (hex).
        agent_id: String,
        /// Trust level: blocked, unknown, known, trusted.
        level: String,
    },
    /// Evaluate trust for an agent+machine pair.
    Evaluate {
        /// Agent ID (hex).
        agent_id: String,
        /// Machine ID (hex).
        machine_id: String,
    },
}

#[derive(Subcommand)]
enum DirectSub {
    /// Establish a direct connection to an agent.
    Connect {
        /// Agent ID (hex).
        agent_id: String,
    },
    /// Send a direct message to an agent.
    Send {
        /// Agent ID (hex).
        agent_id: String,
        /// Message payload.
        message: String,
        /// Opt-in: wait up to this many ms for a post-send liveness probe
        /// (ant-quic 0.27.1 `probe_peer`). Response includes RTT or reason.
        #[arg(long)]
        require_ack_ms: Option<u64>,
    },
    /// List established direct connections.
    Connections,
    /// Stream incoming direct messages.
    Events,
}

#[derive(Subcommand)]
enum GroupsSub {
    /// List all groups.
    List,
    /// Create an encrypted group.
    Create {
        /// Optional group ID (hex, auto-generated if omitted).
        #[arg(long)]
        id: Option<String>,
    },
    /// Get group details.
    Get {
        /// Group ID (hex).
        group_id: String,
    },
    /// Add a member to a group.
    AddMember {
        /// Group ID (hex).
        group_id: String,
        /// Agent ID to add (hex).
        agent_id: String,
    },
    /// Remove a member from a group.
    RemoveMember {
        /// Group ID (hex).
        group_id: String,
        /// Agent ID to remove (hex).
        agent_id: String,
    },
    /// Encrypt a payload for the group.
    Encrypt {
        /// Group ID (hex).
        group_id: String,
        /// Plaintext payload.
        payload: String,
    },
    /// Decrypt ciphertext from a group.
    Decrypt {
        /// Group ID (hex).
        group_id: String,
        /// Ciphertext (base64).
        ciphertext: String,
        /// Epoch number.
        #[arg(long)]
        epoch: u64,
    },
    /// Create a welcome message for a new member.
    Welcome {
        /// Group ID (hex).
        group_id: String,
        /// Agent ID to welcome (hex).
        agent_id: String,
    },
}

#[derive(Subcommand)]
enum GroupSub {
    /// List all groups.
    List,
    /// Create a new named group.
    Create {
        /// Group name.
        name: String,
        /// Group description.
        #[arg(long)]
        description: Option<String>,
        /// Your display name in this group.
        #[arg(long)]
        display_name: Option<String>,
        /// Policy preset: private_secure | public_request_secure | public_open | public_announce.
        #[arg(long)]
        preset: Option<String>,
    },
    /// Get group details.
    Info {
        /// Group ID.
        group_id: String,
    },
    /// List named-group members.
    Members {
        /// Group ID.
        group_id: String,
    },
    /// Add a member to a named group.
    AddMember {
        /// Group ID.
        group_id: String,
        /// Agent ID.
        agent_id: String,
        /// Optional display name to store locally for that member.
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Remove a member from a named group.
    RemoveMember {
        /// Group ID.
        group_id: String,
        /// Agent ID.
        agent_id: String,
    },
    /// Generate an invite link.
    Invite {
        /// Group ID.
        group_id: String,
        /// Seconds until expiry (default: 7 days).
        #[arg(long, default_value = "604800")]
        expiry: u64,
    },
    /// Join a group via invite link.
    Join {
        /// Invite link (x0x://invite/...) or raw base64 token.
        invite: String,
        /// Your display name in this group.
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Set your display name in a group.
    SetName {
        /// Group ID.
        group_id: String,
        /// Display name.
        name: String,
    },
    /// Leave this member/daemon; the group continues (last admin is blocked).
    Leave {
        /// Group ID.
        group_id: String,
    },
    /// Update group name and/or description (admin+).
    Update {
        /// Group ID.
        group_id: String,
        /// New name. (`--new-name`, not `--name`: the global `--name` instance
        /// selector reserves that long flag.)
        #[arg(long = "new-name")]
        new_name: Option<String>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Update the group's access policy (admin+).
    Policy {
        /// Group ID.
        group_id: String,
        /// Preset: private_secure | public_request_secure | public_open | public_announce.
        #[arg(long)]
        preset: Option<String>,
        /// Discoverability: hidden | listed_to_contacts | public_directory.
        #[arg(long)]
        discoverability: Option<String>,
        /// Admission: invite_only | request_access | open_join.
        #[arg(long)]
        admission: Option<String>,
        /// Confidentiality: mls_encrypted | signed_public.
        #[arg(long)]
        confidentiality: Option<String>,
        /// Read access: members_only | public.
        #[arg(long)]
        read_access: Option<String>,
        /// Write access: members_only | moderated_public | admin_only.
        #[arg(long)]
        write_access: Option<String>,
    },
    /// Change a member's role (admin+).
    #[command(
        after_help = "Assignable roles:\n  admin   Full group control: membership, policy, rekey, and delete.\n  member  Group participant.\n\nLegacy owner entries render/read as admin-equivalent but cannot be assigned. Keep the admin set small; do not map softer application roles onto x0x Admin."
    )]
    SetRole {
        /// Group ID.
        group_id: String,
        /// Target agent hex.
        agent_id: String,
        /// Role to assign: admin | member.
        role: String,
    },
    /// Ban a member (admin+).
    Ban {
        /// Group ID.
        group_id: String,
        /// Agent hex.
        agent_id: String,
    },
    /// Unban a member (admin+).
    Unban {
        /// Group ID.
        group_id: String,
        /// Agent hex.
        agent_id: String,
    },
    /// List join requests for a group (admin+).
    Requests {
        /// Group ID.
        group_id: String,
    },
    /// Submit a join request for a RequestAccess group.
    RequestAccess {
        /// Group ID.
        group_id: String,
        /// Optional message to the admins.
        #[arg(long)]
        message: Option<String>,
    },
    /// Approve a pending join request (admin+).
    ApproveRequest {
        /// Group ID.
        group_id: String,
        /// Request ID.
        request_id: String,
    },
    /// Reject a pending join request (admin+).
    RejectRequest {
        /// Group ID.
        group_id: String,
        /// Request ID.
        request_id: String,
    },
    /// Cancel your own pending join request.
    CancelRequest {
        /// Group ID.
        group_id: String,
        /// Request ID.
        request_id: String,
    },
    /// List locally known discoverable groups (optionally filtered by query).
    Discover {
        /// Tag or name substring.
        #[arg(long)]
        q: Option<String>,
    },
    /// Browse PublicDirectory groups observed via shard gossip.
    DiscoverNearby,
    /// List active directory-shard subscriptions.
    DiscoverSubscriptions,
    /// Subscribe to a tag/name/id directory shard.
    DiscoverSubscribe {
        /// Shard kind: tag | name | id.
        kind: String,
        /// Key (tag string, name word, or group id). Required unless --shard given.
        #[arg(long)]
        key: Option<String>,
        /// Direct shard id (u32). Skips key normalisation.
        #[arg(long)]
        shard: Option<u32>,
    },
    /// Unsubscribe from a directory shard.
    DiscoverUnsubscribe {
        /// Shard kind: tag | name | id.
        kind: String,
        /// Shard id.
        shard: u32,
    },
    /// Fetch a group card by group ID.
    Card {
        /// Group ID.
        group_id: String,
    },
    /// Import a signed group card from a JSON file (or `-` for stdin).
    CardImport {
        /// Path to signed-card JSON, or `-` for stdin.
        path: String,
    },
    /// Publish a SignedPublic message to a group.
    Send {
        /// Group ID.
        group_id: String,
        /// Message body (UTF-8).
        body: String,
        /// Message kind: chat (default) | announcement.
        #[arg(long)]
        kind: Option<String>,
    },
    /// Retrieve cached SignedPublic messages for a group.
    Messages {
        /// Group ID.
        group_id: String,
    },
    /// Inspect the state-commit chain for a group.
    State {
        /// Group ID.
        group_id: String,
    },
    /// Read retained state-commit history (members only, paged).
    StateCommits {
        /// Group ID.
        group_id: String,
        /// Only return commits with revision >= this value.
        #[arg(long, default_value_t = 0)]
        from_revision: u64,
        /// Page size (daemon caps at 500).
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Advance the state-commit chain and republish the signed card.
    StateSeal {
        /// Group ID.
        group_id: String,
    },
    /// Irreversibly delete for everyone; retains a withdrawn keyless terminality marker.
    #[command(alias = "state-withdraw")]
    Delete {
        /// Group ID.
        group_id: String,
    },
    /// Encrypt content with the group's current shared secret (member-only).
    SecureEncrypt {
        /// Group ID.
        group_id: String,
        /// Payload — either raw UTF-8 or @path-to-file.
        payload: String,
    },
    /// Decrypt group shared-secret ciphertext (member-only).
    SecureDecrypt {
        /// Group ID.
        group_id: String,
        /// Base64 ciphertext.
        ciphertext_b64: String,
        /// Base64 nonce (12 bytes).
        nonce_b64: String,
        /// Secret epoch the ciphertext was produced under.
        secret_epoch: u64,
    },
    /// Re-seal the current shared secret to a recipient (admin+).
    SecureReseal {
        /// Group ID.
        group_id: String,
        /// Recipient agent hex (must be an active member with a KEM public key).
        recipient: String,
    },
    /// Adversarial test: attempt to open an envelope with this daemon's KEM key.
    SecureOpenEnvelope {
        /// Path to envelope JSON, or `-` for stdin.
        path: String,
    },
}

#[derive(Subcommand)]
enum StoreSub {
    /// List all stores.
    List,
    /// Create a new store.
    Create {
        /// Store name.
        name: String,
        /// Gossip topic for sync.
        topic: String,
    },
    /// Join an existing store by topic.
    Join {
        /// Gossip topic.
        topic: String,
    },
    /// List keys in a store.
    Keys {
        /// Store ID (topic).
        store_id: String,
    },
    /// Put a value.
    Put {
        /// Store ID (topic).
        store_id: String,
        /// Key name.
        key: String,
        /// Value (string).
        value: String,
        /// Content type.
        #[arg(long)]
        content_type: Option<String>,
    },
    /// Get a value.
    Get {
        /// Store ID (topic).
        store_id: String,
        /// Key name.
        key: String,
    },
    /// Remove a key.
    Rm {
        /// Store ID (topic).
        store_id: String,
        /// Key name.
        key: String,
    },
}

#[derive(Subcommand)]
enum TasksSub {
    /// List all task lists.
    List,
    /// Create a new task list.
    Create {
        /// Task list name.
        name: String,
        /// Gossip topic for sync.
        topic: String,
    },
    /// Show tasks in a list.
    Show {
        /// Task list ID.
        list_id: String,
    },
    /// Add a task to a list.
    Add {
        /// Task list ID.
        list_id: String,
        /// Task title.
        title: String,
        /// Task description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Claim a task.
    Claim {
        /// Task list ID.
        list_id: String,
        /// Task ID.
        task_id: String,
    },
    /// Mark a task as complete.
    Complete {
        /// Task list ID.
        list_id: String,
        /// Task ID.
        task_id: String,
    },
}

#[derive(Subcommand)]
enum WsSub {
    /// List active WebSocket sessions.
    Sessions,
    /// Print the WebSocket URL for the direct-messaging stream.
    Direct,
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let format = if cli.json || cli.format.as_deref() == Some("json") {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    };

    let result = run(
        cli.command,
        cli.instance.as_deref(),
        cli.api.as_deref(),
        format,
    )
    .await;

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("not running") {
                x0x::cli::print_error(&msg);
                ExitCode::from(2)
            } else {
                x0x::cli::print_error(&msg);
                ExitCode::FAILURE
            }
        }
    }
}

async fn run(
    command: Commands,
    name: Option<&str>,
    api: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    // Commands that don't need a running daemon.
    match &command {
        Commands::Routes { json } => return commands::routes(*json),
        Commands::Tree => return print_command_tree(),
        Commands::Uninstall => return uninstall().await,
        Commands::Purge => return purge().await,
        Commands::Constitution { raw, json } => {
            return commands::constitution::display(*raw, *json);
        }
        Commands::Upgrade {
            check,
            apply: _,
            force,
        } => {
            return commands::upgrade::run(*check, *force).await;
        }
        Commands::Instances => return commands::daemon::instances().await,
        Commands::Start { config, foreground } => {
            return commands::daemon::start(name, config.as_deref(), *foreground).await;
        }
        Commands::Autostart { remove } => {
            return if *remove {
                commands::daemon::autostart_remove().await
            } else {
                commands::daemon::autostart(name).await
            };
        }
        Commands::UserId { sub } => match sub {
            UserIdSub::Create { path, from_seed } => {
                let resolved =
                    commands::user_id::create(path.clone(), from_seed.as_deref()).await?;
                match format {
                    OutputFormat::Json => x0x::cli::print_value(
                        format,
                        &serde_json::json!({ "path": resolved.to_string_lossy() }),
                    ),
                    OutputFormat::Text => {
                        println!("Created user identity keypair at {}", resolved.display());
                    }
                }
                return Ok(());
            }
            UserIdSub::Inspect { path } => {
                let report = commands::user_id::inspect(path.clone()).await?;
                match format {
                    OutputFormat::Json => {
                        x0x::cli::print_value(format, &serde_json::to_value(&report)?)
                    }
                    OutputFormat::Text => {
                        println!("User identity at {}:", report.path);
                        println!("user_id:    {}", report.user_id);
                        if let Some(words) = &report.user_words {
                            println!("user_words: {words}");
                        }
                    }
                }
                return Ok(());
            }
        },
        _ => {}
    }

    let client = DaemonClient::new(name, api, format)?;

    // Commands that need a running daemon.
    match command {
        Commands::Gui => {
            // Ensure daemon is running and open GUI in browser.
            // #127 / WS1.6: exchange the durable API token for a short-lived
            // session token *before* constructing the URL, so the durable
            // secret never appears in the browser's address bar / history.
            client.ensure_running().await?;
            let Some(durable) = client.api_token() else {
                anyhow::bail!("API token not found; set X0X_API_TOKEN or restart x0xd");
            };
            let session = client.post_empty("/auth/session").await?;
            let token = session["session_token"].as_str().unwrap_or(durable);
            let url = format!("{}/gui?token={token}", client.base_url());
            eprintln!("x0x GUI: {}/gui", client.base_url());

            let opened = {
                #[cfg(target_os = "macos")]
                {
                    std::process::Command::new("open").arg(&url).spawn().is_ok()
                }
                #[cfg(target_os = "linux")]
                {
                    std::process::Command::new("xdg-open")
                        .arg(&url)
                        .spawn()
                        .is_ok()
                }
                #[cfg(target_os = "windows")]
                {
                    std::process::Command::new("cmd")
                        .args(["/C", "start", &url])
                        .spawn()
                        .is_ok()
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                {
                    false
                }
            };

            if !opened {
                eprintln!("Could not open browser. Open this URL manually: {url}");
            }
            Ok(())
        }
        Commands::Health => commands::network::health(&client).await,
        Commands::Status => commands::network::status(&client).await,
        Commands::Agent { sub } => match sub {
            None => commands::identity::agent(&client).await,
            Some(AgentSub::UserId) => commands::identity::user_id(&client).await,
            Some(AgentSub::Card {
                display_name,
                include_groups,
            }) => commands::identity::card(&client, display_name.as_deref(), include_groups).await,
            Some(AgentSub::Introduction) => commands::identity::introduction(&client).await,
            Some(AgentSub::Import { card, trust }) => {
                commands::identity::import_card(&client, &card, Some(trust.as_str())).await
            }
            Some(AgentSub::Sign {
                file,
                payload_b64,
                context,
            }) => {
                commands::identity::sign(&client, file.as_deref(), payload_b64.as_deref(), &context)
                    .await
            }
            Some(AgentSub::Verify {
                file,
                payload_b64,
                signature_b64,
                public_key_b64,
                context,
            }) => {
                commands::identity::verify(
                    &client,
                    file.as_deref(),
                    payload_b64.as_deref(),
                    &signature_b64,
                    &public_key_b64,
                    &context,
                )
                .await
            }
        },
        Commands::Announce {
            include_user,
            consent,
        } => commands::identity::announce(&client, include_user, consent).await,
        Commands::Peers => commands::network::peers(&client).await,
        Commands::Presence { sub } => match sub {
            None => commands::network::presence(&client).await,
            Some(PresenceSub::Online) => commands::presence::online(&client).await,
            Some(PresenceSub::Foaf { ttl, timeout_ms }) => {
                commands::presence::foaf(&client, ttl, timeout_ms).await
            }
            Some(PresenceSub::Find {
                id,
                ttl,
                timeout_ms,
            }) => commands::presence::find(&client, &id, ttl, timeout_ms).await,
            Some(PresenceSub::Status { id }) => commands::presence::status(&client, &id).await,
            Some(PresenceSub::Events) => commands::presence::events(&client).await,
        },
        Commands::Network { sub } => match sub {
            NetworkSub::Status => commands::network::network_status(&client).await,
            NetworkSub::Cache => commands::network::bootstrap_cache(&client).await,
        },
        Commands::Peer { sub } => match sub {
            PeerSub::Probe {
                peer_id,
                timeout_ms,
            } => commands::network::peers_probe(&client, &peer_id, timeout_ms).await,
            PeerSub::Health { peer_id } => commands::network::peers_health(&client, &peer_id).await,
            PeerSub::Events => commands::network::peers_events(&client).await,
        },
        Commands::Diagnostics { sub } => match sub {
            DiagnosticsSub::Connectivity => {
                commands::network::diagnostics_connectivity(&client).await
            }
            DiagnosticsSub::Ack => commands::network::diagnostics_ack(&client).await,
            DiagnosticsSub::Gossip => commands::network::diagnostics_gossip(&client).await,
            DiagnosticsSub::Dm => commands::network::diagnostics_dm(&client).await,
            DiagnosticsSub::Groups => commands::network::diagnostics_groups(&client).await,
            DiagnosticsSub::Exec => commands::exec::diagnostics(&client).await,
            DiagnosticsSub::Connect => commands::network::diagnostics_connect(&client).await,
            DiagnosticsSub::Ws => commands::network::diagnostics_ws(&client).await,
        },
        Commands::Auth { sub } => match sub {
            AuthSub::Session => commands::auth::session(&client).await,
        },
        Commands::Find { words } => commands::find::find(&client, &words).await,
        Commands::Connect { words } => commands::connect::connect(&client, &words).await,
        Commands::Agents { sub } => match sub {
            None => commands::discovery::list(&client, false).await,
            Some(AgentsSub::List { unfiltered }) => {
                commands::discovery::list(&client, unfiltered).await
            }
            Some(AgentsSub::Get { agent_id, wait }) => {
                commands::discovery::get(&client, &agent_id, wait).await
            }
            Some(AgentsSub::Find { agent_id }) => {
                commands::discovery::find(&client, &agent_id).await
            }
            Some(AgentsSub::Reachability { agent_id }) => {
                commands::discovery::reachability(&client, &agent_id).await
            }
            Some(AgentsSub::Machine { agent_id }) => {
                commands::discovery::machine(&client, &agent_id).await
            }
            Some(AgentsSub::ByUser { user_id }) => {
                commands::discovery::by_user(&client, &user_id).await
            }
        },
        Commands::Contacts { sub } => match sub {
            None => commands::contacts::list(&client).await,
            Some(ContactsSub::List) => commands::contacts::list(&client).await,
            Some(ContactsSub::Add {
                agent_id,
                trust,
                label,
            }) => commands::contacts::add(&client, &agent_id, &trust, label.as_deref()).await,
            Some(ContactsSub::Update {
                agent_id,
                trust,
                identity_type,
            }) => {
                commands::contacts::update(
                    &client,
                    &agent_id,
                    trust.as_deref(),
                    identity_type.as_deref(),
                )
                .await
            }
            Some(ContactsSub::Remove { agent_id }) => {
                commands::contacts::remove(&client, &agent_id).await
            }
            Some(ContactsSub::Revoke { agent_id, reason }) => {
                commands::contacts::revoke(&client, &agent_id, &reason).await
            }
            Some(ContactsSub::Revocations { agent_id }) => {
                commands::contacts::revocations(&client, &agent_id).await
            }
        },
        Commands::Machines { sub } => match sub {
            MachinesSub::Discovered { unfiltered } => {
                commands::machines::discovered(&client, unfiltered).await
            }
            MachinesSub::Get { machine_id, wait } => {
                commands::machines::get_discovered(&client, &machine_id, wait).await
            }
            MachinesSub::ByUser { user_id } => commands::machines::by_user(&client, &user_id).await,
            MachinesSub::Connect { machine_id } => {
                commands::machines::connect(&client, &machine_id).await
            }
            MachinesSub::List { agent_id } => commands::machines::list(&client, &agent_id).await,
            MachinesSub::Add {
                agent_id,
                machine_id,
                pin,
            } => commands::machines::add(&client, &agent_id, &machine_id, pin).await,
            MachinesSub::Remove {
                agent_id,
                machine_id,
            } => commands::machines::remove(&client, &agent_id, &machine_id).await,
            MachinesSub::Pin {
                agent_id,
                machine_id,
            } => commands::machines::pin(&client, &agent_id, &machine_id).await,
            MachinesSub::Unpin {
                agent_id,
                machine_id,
            } => commands::machines::unpin(&client, &agent_id, &machine_id).await,
        },
        Commands::Trust { sub } => match sub {
            TrustSub::Set { agent_id, level } => {
                commands::contacts::trust_set(&client, &agent_id, &level).await
            }
            TrustSub::Evaluate {
                agent_id,
                machine_id,
            } => commands::contacts::trust_evaluate(&client, &agent_id, &machine_id).await,
        },
        Commands::Publish { topic, payload } => {
            commands::messaging::publish(&client, &topic, &payload).await
        }
        Commands::Subscribe { topic } => commands::messaging::subscribe(&client, &topic).await,
        Commands::Unsubscribe { id } => commands::messaging::unsubscribe(&client, &id).await,
        Commands::Events => commands::messaging::events(&client).await,
        Commands::Exec {
            agent_id,
            timeout,
            stdin_file,
            cancel,
            argv,
            sub,
        } => match sub {
            Some(ExecSub::Sessions) => commands::exec::sessions(&client).await,
            Some(ExecSub::Cancel {
                request_id,
                agent_id,
            }) => commands::exec::cancel(&client, &request_id, agent_id.as_deref()).await,
            None => {
                if let Some(request_id) = cancel {
                    commands::exec::cancel(&client, &request_id, agent_id.as_deref()).await
                } else {
                    let Some(agent_id) = agent_id else {
                        anyhow::bail!("usage: x0x exec <agent_id> [--timeout <secs>] [--stdin-file <path>] -- <argv...>");
                    };
                    commands::exec::run(&client, &agent_id, &argv, timeout, stdin_file.as_deref())
                        .await
                }
            }
        },
        Commands::Direct { sub } => match sub {
            DirectSub::Connect { agent_id } => commands::direct::connect(&client, &agent_id).await,
            DirectSub::Send {
                agent_id,
                message,
                require_ack_ms,
            } => commands::direct::send(&client, &agent_id, &message, require_ack_ms).await,
            DirectSub::Connections => commands::direct::connections(&client).await,
            DirectSub::Events => commands::direct::events(&client).await,
        },
        Commands::Groups { sub } => match sub {
            None => commands::groups::list(&client).await,
            Some(GroupsSub::List) => commands::groups::list(&client).await,
            Some(GroupsSub::Create { id }) => {
                commands::groups::create(&client, id.as_deref()).await
            }
            Some(GroupsSub::Get { group_id }) => commands::groups::get(&client, &group_id).await,
            Some(GroupsSub::AddMember { group_id, agent_id }) => {
                commands::groups::add_member(&client, &group_id, &agent_id).await
            }
            Some(GroupsSub::RemoveMember { group_id, agent_id }) => {
                commands::groups::remove_member(&client, &group_id, &agent_id).await
            }
            Some(GroupsSub::Encrypt { group_id, payload }) => {
                commands::groups::encrypt(&client, &group_id, &payload).await
            }
            Some(GroupsSub::Decrypt {
                group_id,
                ciphertext,
                epoch,
            }) => commands::groups::decrypt(&client, &group_id, &ciphertext, epoch).await,
            Some(GroupsSub::Welcome { group_id, agent_id }) => {
                commands::groups::welcome(&client, &group_id, &agent_id).await
            }
        },
        Commands::Group { sub } => match sub {
            None => commands::group::list(&client).await,
            Some(GroupSub::List) => commands::group::list(&client).await,
            Some(GroupSub::Create {
                name,
                description,
                display_name,
                preset,
            }) => {
                commands::group::create(
                    &client,
                    &name,
                    description.as_deref(),
                    display_name.as_deref(),
                    preset.as_deref(),
                )
                .await
            }
            Some(GroupSub::Info { group_id }) => commands::group::info(&client, &group_id).await,
            Some(GroupSub::Members { group_id }) => {
                commands::group::members(&client, &group_id).await
            }
            Some(GroupSub::AddMember {
                group_id,
                agent_id,
                display_name,
            }) => {
                commands::group::add_member(&client, &group_id, &agent_id, display_name.as_deref())
                    .await
            }
            Some(GroupSub::RemoveMember { group_id, agent_id }) => {
                commands::group::remove_member(&client, &group_id, &agent_id).await
            }
            Some(GroupSub::Invite { group_id, expiry }) => {
                commands::group::invite(&client, &group_id, expiry).await
            }
            Some(GroupSub::Join {
                invite,
                display_name,
            }) => commands::group::join(&client, &invite, display_name.as_deref()).await,
            Some(GroupSub::SetName { group_id, name }) => {
                commands::group::set_name(&client, &group_id, &name).await
            }
            Some(GroupSub::Leave { group_id }) => commands::group::leave(&client, &group_id).await,
            Some(GroupSub::Update {
                group_id,
                new_name,
                description,
            }) => {
                commands::group::update(
                    &client,
                    &group_id,
                    new_name.as_deref(),
                    description.as_deref(),
                )
                .await
            }
            Some(GroupSub::Policy {
                group_id,
                preset,
                discoverability,
                admission,
                confidentiality,
                read_access,
                write_access,
            }) => {
                commands::group::policy(
                    &client,
                    &group_id,
                    preset.as_deref(),
                    discoverability.as_deref(),
                    admission.as_deref(),
                    confidentiality.as_deref(),
                    read_access.as_deref(),
                    write_access.as_deref(),
                )
                .await
            }
            Some(GroupSub::SetRole {
                group_id,
                agent_id,
                role,
            }) => commands::group::set_role(&client, &group_id, &agent_id, &role).await,
            Some(GroupSub::Ban { group_id, agent_id }) => {
                commands::group::ban(&client, &group_id, &agent_id).await
            }
            Some(GroupSub::Unban { group_id, agent_id }) => {
                commands::group::unban(&client, &group_id, &agent_id).await
            }
            Some(GroupSub::Requests { group_id }) => {
                commands::group::requests(&client, &group_id).await
            }
            Some(GroupSub::RequestAccess { group_id, message }) => {
                commands::group::request_access(&client, &group_id, message.as_deref()).await
            }
            Some(GroupSub::ApproveRequest {
                group_id,
                request_id,
            }) => commands::group::approve_request(&client, &group_id, &request_id).await,
            Some(GroupSub::RejectRequest {
                group_id,
                request_id,
            }) => commands::group::reject_request(&client, &group_id, &request_id).await,
            Some(GroupSub::CancelRequest {
                group_id,
                request_id,
            }) => commands::group::cancel_request(&client, &group_id, &request_id).await,
            Some(GroupSub::Discover { q }) => {
                commands::group::discover(&client, q.as_deref()).await
            }
            Some(GroupSub::DiscoverNearby) => commands::group::discover_nearby(&client).await,
            Some(GroupSub::DiscoverSubscriptions) => {
                commands::group::discover_subscriptions(&client).await
            }
            Some(GroupSub::DiscoverSubscribe { kind, key, shard }) => {
                commands::group::discover_subscribe(&client, &kind, key.as_deref(), shard).await
            }
            Some(GroupSub::DiscoverUnsubscribe { kind, shard }) => {
                commands::group::discover_unsubscribe(&client, &kind, shard).await
            }
            Some(GroupSub::Card { group_id }) => commands::group::card(&client, &group_id).await,
            Some(GroupSub::CardImport { path }) => {
                commands::group::card_import(&client, &path).await
            }
            Some(GroupSub::Send {
                group_id,
                body,
                kind,
            }) => commands::group::send(&client, &group_id, &body, kind.as_deref()).await,
            Some(GroupSub::Messages { group_id }) => {
                commands::group::messages(&client, &group_id).await
            }
            Some(GroupSub::State { group_id }) => commands::group::state(&client, &group_id).await,
            Some(GroupSub::StateCommits {
                group_id,
                from_revision,
                limit,
            }) => commands::group::state_commits(&client, &group_id, from_revision, limit).await,
            Some(GroupSub::StateSeal { group_id }) => {
                commands::group::state_seal(&client, &group_id).await
            }
            Some(GroupSub::Delete { group_id }) => {
                commands::group::delete(&client, &group_id).await
            }
            Some(GroupSub::SecureEncrypt { group_id, payload }) => {
                let bytes = if let Some(path) = payload.strip_prefix('@') {
                    std::fs::read(path)
                        .map_err(|e| anyhow::anyhow!("read payload from {path}: {e}"))?
                } else {
                    payload.into_bytes()
                };
                commands::group::secure_encrypt(&client, &group_id, &bytes).await
            }
            Some(GroupSub::SecureDecrypt {
                group_id,
                ciphertext_b64,
                nonce_b64,
                secret_epoch,
            }) => {
                commands::group::secure_decrypt(
                    &client,
                    &group_id,
                    &ciphertext_b64,
                    &nonce_b64,
                    secret_epoch,
                )
                .await
            }
            Some(GroupSub::SecureReseal {
                group_id,
                recipient,
            }) => commands::group::secure_reseal(&client, &group_id, &recipient).await,
            Some(GroupSub::SecureOpenEnvelope { path }) => {
                commands::group::secure_open_envelope(&client, &path).await
            }
        },
        Commands::Store { sub } => match sub {
            None => commands::store::list(&client).await,
            Some(StoreSub::List) => commands::store::list(&client).await,
            Some(StoreSub::Create { name, topic }) => {
                commands::store::create(&client, &name, &topic).await
            }
            Some(StoreSub::Join { topic }) => commands::store::join(&client, &topic).await,
            Some(StoreSub::Keys { store_id }) => commands::store::keys(&client, &store_id).await,
            Some(StoreSub::Put {
                store_id,
                key,
                value,
                content_type,
            }) => {
                commands::store::put(&client, &store_id, &key, &value, content_type.as_deref())
                    .await
            }
            Some(StoreSub::Get { store_id, key }) => {
                commands::store::get(&client, &store_id, &key).await
            }
            Some(StoreSub::Rm { store_id, key }) => {
                commands::store::rm(&client, &store_id, &key).await
            }
        },
        Commands::Tasks { sub } => match sub {
            None => commands::tasks::list(&client).await,
            Some(TasksSub::List) => commands::tasks::list(&client).await,
            Some(TasksSub::Create { name, topic }) => {
                commands::tasks::create(&client, &name, &topic).await
            }
            Some(TasksSub::Show { list_id }) => commands::tasks::show(&client, &list_id).await,
            Some(TasksSub::Add {
                list_id,
                title,
                description,
            }) => commands::tasks::add(&client, &list_id, &title, description.as_deref()).await,
            Some(TasksSub::Claim { list_id, task_id }) => {
                commands::tasks::update(&client, &list_id, &task_id, "claim").await
            }
            Some(TasksSub::Complete { list_id, task_id }) => {
                commands::tasks::update(&client, &list_id, &task_id, "complete").await
            }
        },
        Commands::Upgrade { .. } => {
            anyhow::bail!("command dispatched earlier — dispatch table out of sync")
        }
        Commands::Ws { sub } => match sub {
            None => commands::ws::general(&client).await,
            Some(WsSub::Sessions) => commands::ws::sessions(&client).await,
            Some(WsSub::Direct) => commands::ws::direct(&client).await,
        },
        Commands::Stop => commands::daemon::stop(&client).await,
        Commands::Doctor => commands::daemon::doctor(&client).await,
        Commands::SendFile { agent_id, path } => {
            commands::files::send_file(&client, &agent_id, &path).await
        }
        Commands::ReceiveFile {
            accept_from,
            output_dir,
        } => {
            commands::files::receive_file(&client, accept_from.as_deref(), output_dir.as_deref())
                .await
        }
        Commands::Transfers => commands::files::transfers(&client).await,
        Commands::TransferStatus { transfer_id } => {
            commands::files::transfer_status(&client, &transfer_id).await
        }
        Commands::AcceptFile { transfer_id } => {
            commands::files::accept_file(&client, &transfer_id).await
        }
        Commands::RejectFile {
            transfer_id,
            reason,
        } => commands::files::reject_file(&client, &transfer_id, reason.as_deref()).await,
        Commands::Identity { sub } => match sub {
            IdentitySub::Revoke {
                agent_id,
                machine_id,
                reason,
            } => {
                commands::identity::revoke(
                    &client,
                    agent_id.as_deref(),
                    machine_id.as_deref(),
                    reason.as_deref(),
                )
                .await
            }
            IdentitySub::Revocations => commands::identity::revocations(&client).await,
        },
        Commands::Forward { sub } => match sub {
            ForwardSub::Add {
                local,
                peer,
                target,
                target_port,
            } => {
                commands::forward::add(
                    &client,
                    &local,
                    &peer,
                    target.as_deref().unwrap_or("127.0.0.1"),
                    target_port,
                )
                .await
            }
            ForwardSub::List => commands::forward::list(&client).await,
            ForwardSub::Remove { local_addr } => {
                commands::forward::remove(&client, &local_addr).await
            }
        },
        Commands::Streams => commands::forward::streams(&client).await,
        Commands::Routes { .. }
        | Commands::Tree
        | Commands::Uninstall
        | Commands::Purge
        | Commands::Constitution { .. }
        | Commands::UserId { .. }
        | Commands::Start { .. }
        | Commands::Instances
        | Commands::Autostart { .. } => {
            anyhow::bail!("command dispatched earlier — dispatch table out of sync")
        }
    }
}

// ── Tree view ──────────────────────────────────────────────────────────────

fn print_command_tree() -> anyhow::Result<()> {
    let tree = "\
x0x (v{VERSION})
|
+-- Daemon
|   +-- start              Start the x0xd daemon
|   +-- stop               Stop a running daemon
|   +-- instances          List running daemon instances
|   +-- doctor             Pre-flight diagnostics
|   +-- autostart          Configure daemon to start on boot
|
+-- Identity
|   +-- agent              Show agent identity
|   |   +-- user-id        Show user ID
|   |   +-- card           Generate shareable identity card
|   |   +-- import         Import an agent card to contacts
|   +-- user-id create     Create user identity keypair
|   +-- user-id inspect    Validate a user identity file (daemonless)
|   +-- announce           Announce identity to network
|
+-- Network
|   +-- health             Health check
|   +-- status             Runtime status (uptime, peers, addresses)
|   +-- peers              Connected gossip peers
|   +-- network status     NAT type, connectivity diagnostics
|   +-- network cache      Bootstrap peer cache stats
|
+-- Presence
|   +-- presence online    Online agents (network view, non-blocked)
|   +-- presence foaf      FOAF discovery (social view: Trusted + Known)
|   +-- presence find      Find agent by ID via FOAF random walk
|   +-- presence status    Local cache lookup for an agent (no network I/O)
|
+-- Discovery
|   +-- agents list        List discovered agents
|   +-- agents get         Get agent details
|   +-- agents find        Find an agent (3-stage: cache/shard/rendezvous)
|   +-- agents reachability  Check if agent is directly reachable
|   +-- agents machine     Resolve agent to current machine endpoint
|   +-- agents by-user     Find agents by user ID
|
+-- Contacts & Trust
|   +-- contacts list      List contacts
|   +-- contacts add       Add a contact with trust level
|   +-- contacts update    Update trust or identity type
|   +-- contacts remove    Remove a contact
|   +-- contacts revoke    Revoke a contact (with reason)
|   +-- contacts revocations  List revocations
|   +-- trust set          Quick-set trust level
|   +-- trust evaluate     Evaluate agent+machine trust
|   +-- machines discovered  List discovered machine endpoints
|   +-- machines get       Get discovered machine endpoint details
|   +-- machines by-user   Find machine endpoints by user ID
|   +-- machines connect   Connect to a discovered machine
|   +-- machines list      List machine records for contact
|   +-- machines add       Add machine record
|   +-- machines remove    Remove machine record
|   +-- machines pin       Pin machine for identity verification
|   +-- machines unpin     Unpin machine
|
+-- Messaging
|   +-- publish            Publish message to gossip topic
|   +-- subscribe          Subscribe and stream topic messages
|   +-- unsubscribe        Unsubscribe from topic
|   +-- events             Stream all gossip events
|   +-- direct connect     Establish QUIC connection to agent
|   +-- direct send        Send direct (point-to-point) message
|   +-- direct connections List direct connections
|   +-- direct events      Stream incoming direct messages
|
+-- MLS Encryption (saorsa-mls PQC)
|   +-- groups list        List encrypted MLS groups
|   +-- groups create      Create a new encrypted group
|   +-- groups get         Get group details and members
|   +-- groups add-member  Add member (ML-KEM-768 key exchange)
|   +-- groups remove-member  Remove member
|   +-- groups encrypt     Encrypt payload with group key
|   +-- groups decrypt     Decrypt ciphertext
|   +-- groups welcome     Generate welcome message for new member
|
+-- Named Groups
|   +-- group list         List named groups
|   +-- group create       Create a named group
|   +-- group info         Get group info
|   +-- group members      List named-group members
|   +-- group add-member   Add named-group member
|   +-- group remove-member  Remove named-group member
|   +-- group invite       Generate invite link
|   +-- group join         Join via invite link
|   +-- group set-name     Set display name in group
|   +-- group leave        Leave group
|   +-- group delete       Delete group
|
+-- Data
|   +-- store list         List key-value stores
|   +-- store create       Create a KV store
|   +-- store join         Join existing store by topic
|   +-- store keys         List keys
|   +-- store put          Write a value
|   +-- store get          Read a value
|   +-- store rm           Delete a key
|   +-- tasks list         List CRDT task lists
|   +-- tasks create       Create a task list
|   +-- tasks show         Show tasks in a list
|   +-- tasks add          Add a task
|   +-- tasks claim        Claim a task
|   +-- tasks complete     Mark task as done
|
+-- Files
|   +-- send-file          Send file to an agent
|   +-- receive-file       Watch for incoming transfers
|   +-- transfers          List active/recent transfers
|   +-- transfer-status    Check transfer progress
|   +-- accept-file        Accept incoming transfer
|   +-- reject-file        Reject incoming transfer
|
+-- System
    +-- constitution       Display the x0x Constitution
    +-- upgrade            Check for updates and upgrade (no daemon needed)
    |   +-- --check        Just check, don't apply
    |   +-- --force        Force reinstall latest version
    +-- gui                Open embedded web GUI
    +-- routes             Print all 130 REST API routes
    +-- tree               This command tree
    +-- ws sessions        List WebSocket sessions
    +-- uninstall          Remove x0x binaries (keeps data)
    +-- purge              Remove ALL data and keys (destructive)
";
    print!("{}", tree.replace("{VERSION}", x0x::VERSION));
    Ok(())
}

fn remove_binary_file(path: &Path, output_prefix: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            eprintln!("{output_prefix}Removed {}", path.display());
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "{output_prefix}Failed to remove {}: {error}",
                path.display()
            );
            Err(format!("{}: {error}", path.display()))
        }
    }
}

fn report_binary_removal_failures(failures: &[String]) -> anyhow::Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("failed to remove binaries: {}", failures.join("; "))
    }
}

// ── Uninstall ──────────────────────────────────────────────────────────────

async fn uninstall() -> anyhow::Result<()> {
    eprintln!("x0x uninstall");
    eprintln!("=============");
    eprintln!();
    eprintln!("This will remove x0x binaries but keep your data and keys.");
    eprintln!();

    // Find binaries
    let x0x_path = std::env::current_exe()?;
    let x0xd_path = x0x_path.parent().map(|p| p.join("x0xd"));

    eprintln!("Binaries to remove:");
    eprintln!("  {}", x0x_path.display());
    if let Some(ref d) = x0xd_path {
        if d.exists() {
            eprintln!("  {}", d.display());
        }
    }

    // Data dirs preserved
    if let Some(data_dir) = dirs::data_dir().map(|d| d.join("x0x")) {
        eprintln!();
        eprintln!("Data preserved at: {}", data_dir.display());
    }
    if let Some(home) = dirs::home_dir().map(|h| h.join(".x0x")) {
        if home.exists() {
            eprintln!("Keys preserved at: {}", home.display());
        }
    }

    eprintln!();
    eprint!("Proceed? [y/N] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() != "y" {
        eprintln!("Cancelled.");
        return Ok(());
    }

    // Stop daemon if running
    eprintln!("Stopping daemon...");
    let _ = tokio::process::Command::new(&x0x_path)
        .arg("stop")
        .output()
        .await;

    // Remove launchd/systemd autostart
    eprintln!("Removing autostart...");
    let _ = tokio::process::Command::new(&x0x_path)
        .args(["autostart", "--remove"])
        .output()
        .await;

    // Remove binaries
    let mut removal_failures = Vec::new();
    if let Some(ref d) = x0xd_path {
        if d.exists() {
            if let Err(error) = remove_binary_file(d, "") {
                removal_failures.push(error);
            }
        }
    }
    // Remove self last
    if let Err(error) = remove_binary_file(&x0x_path, "") {
        removal_failures.push(error);
    }
    report_binary_removal_failures(&removal_failures)?;

    eprintln!();
    eprintln!("x0x uninstalled. Your data and keys are preserved.");
    eprintln!("To reinstall: curl -sfL https://x0x.md | sh");
    Ok(())
}

// ── Purge ──────────────────────────────────────────────────────────────────

async fn purge() -> anyhow::Result<()> {
    eprintln!("\x1b[31;1m");
    eprintln!("  WARNING: DESTRUCTIVE OPERATION");
    eprintln!("  ==============================");
    eprintln!("\x1b[0m");
    eprintln!("This will permanently delete:");
    eprintln!();

    let data_dir = dirs::data_dir();
    let home_dir = dirs::home_dir();
    let paths_to_remove =
        commands::purge::collect_purge_paths(data_dir.as_deref(), home_dir.as_deref());
    for purge_path in &paths_to_remove {
        match purge_path.kind {
            commands::purge::PurgePathKind::Data => eprintln!(
                "  Data:    {} (contacts, groups, stores, transfers)",
                purge_path.path.display()
            ),
            commands::purge::PurgePathKind::InstanceData => {
                eprintln!("  Instance: {} (data)", purge_path.path.display());
            }
            commands::purge::PurgePathKind::Keys => eprintln!(
                "  Keys:    {} (machine.key, agent.key, agent.cert)",
                purge_path.path.display()
            ),
            commands::purge::PurgePathKind::LegacyInstanceKeys => {
                eprintln!("  Instance: {} (legacy keys)", purge_path.path.display());
            }
        }
    }
    // Binaries
    let x0x_path = std::env::current_exe()?;
    let x0xd_path = x0x_path.parent().map(|p| p.join("x0xd"));
    eprintln!("  Binary:  {}", x0x_path.display());
    if let Some(ref d) = x0xd_path {
        if d.exists() {
            eprintln!("  Binary:  {}", d.display());
        }
    }

    if paths_to_remove.is_empty() {
        eprintln!();
        eprintln!("No data directories found. Nothing to purge.");
        return Ok(());
    }

    // ── Confirmation 1: Acknowledge understanding ──
    eprintln!();
    eprintln!("\x1b[33mStep 1/3: This will destroy your agent identity and all data.\x1b[0m");
    eprintln!("Your agent ID and keys cannot be recovered after deletion.");
    eprint!("Type 'I understand' to continue: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "I understand" {
        eprintln!("Cancelled.");
        return Ok(());
    }

    // ── Confirmation 2: Type PURGE ──
    input.clear();
    eprintln!();
    eprintln!("\x1b[33mStep 2/3: Final safety check.\x1b[0m");
    eprint!("Type 'PURGE' in capitals to confirm: ");
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "PURGE" {
        eprintln!("Cancelled.");
        return Ok(());
    }

    // ── Confirmation 3: Agent ID verification ──
    input.clear();
    eprintln!();
    eprintln!("\x1b[33mStep 3/3: Verify your agent ID.\x1b[0m");
    let agent_id_hint = match commands::purge::agent_id_confirmation_hint(home_dir.as_deref()) {
        Ok(hint) => hint,
        Err(error) => {
            eprintln!("Cannot verify your agent ID: {error:#}");
            eprintln!("Cancelled without removing data.");
            return Ok(());
        }
    };
    eprintln!("Your agent ID starts with: {agent_id_hint}...");
    eprint!("Type the first 8 characters of your agent ID to confirm: ");
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != agent_id_hint {
        eprintln!("Agent ID mismatch. Cancelled.");
        return Ok(());
    }

    // ── Execute purge ──
    eprintln!();
    eprintln!("Stopping daemon...");
    let _ = tokio::process::Command::new(&x0x_path)
        .arg("stop")
        .output()
        .await;

    eprintln!("Removing autostart...");
    let _ = tokio::process::Command::new(&x0x_path)
        .args(["autostart", "--remove"])
        .output()
        .await;

    for purge_path in &paths_to_remove {
        if purge_path.path.is_dir() {
            match std::fs::remove_dir_all(&purge_path.path) {
                Ok(()) => eprintln!("  Removed {}", purge_path.path.display()),
                Err(e) => eprintln!("  Failed to remove {}: {}", purge_path.path.display(), e),
            }
        }
    }

    // Remove binaries
    let mut removal_failures = Vec::new();
    if let Some(ref d) = x0xd_path {
        if d.exists() {
            if let Err(error) = remove_binary_file(d, "  ") {
                removal_failures.push(error);
            }
        }
    }
    if let Err(error) = remove_binary_file(&x0x_path, "  ") {
        removal_failures.push(error);
    }
    report_binary_removal_failures(&removal_failures)?;

    eprintln!();
    eprintln!("x0x has been completely removed.");
    eprintln!("To reinstall: curl -sfL https://x0x.md | sh");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_presence_alias_parses_without_nested_subcommand() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["x0x", "presence"])?;
        match cli.command {
            Commands::Presence { sub: None } => Ok(()),
            _ => anyhow::bail!("expected bare presence to parse without nested subcommand"),
        }
    }

    #[test]
    fn bare_ws_alias_parses_without_nested_subcommand() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["x0x", "ws"])?;
        match cli.command {
            Commands::Ws { sub: None } => Ok(()),
            _ => anyhow::bail!("expected bare ws to parse without nested subcommand"),
        }
    }

    // Regression: the global `--name` instance selector and a subcommand's
    // positional `name` once shared the clap arg id `name`, so under
    // `global = true` the positional value bled into the instance selector and
    // every `* create <NAME>` (group/store/task-list) routed at a non-existent
    // daemon instance instead of the default daemon. The global is now bound to
    // `instance`; these tests pin that a positional name never sets it.
    #[test]
    fn group_create_positional_name_does_not_set_instance() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["x0x", "group", "create", "demo"])?;
        assert!(
            cli.instance.is_none(),
            "group name must not populate the --name instance selector"
        );
        match cli.command {
            Commands::Group {
                sub: Some(GroupSub::Create { name, .. }),
            } => {
                assert_eq!(name, "demo");
                Ok(())
            }
            _ => anyhow::bail!("expected group create to parse with the positional name"),
        }
    }

    #[test]
    fn store_create_positional_name_does_not_set_instance() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["x0x", "store", "create", "mystore", "mytopic"])?;
        assert!(
            cli.instance.is_none(),
            "store name must not populate the --name instance selector"
        );
        Ok(())
    }

    #[test]
    fn explicit_instance_flag_still_targets_named_instance() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["x0x", "--name", "alice", "group", "create", "demo"])?;
        assert_eq!(
            cli.instance.as_deref(),
            Some("alice"),
            "explicit --name must still select the daemon instance"
        );
        match cli.command {
            Commands::Group {
                sub: Some(GroupSub::Create { name, .. }),
            } => {
                assert_eq!(name, "demo", "group name and instance must not conflate");
                Ok(())
            }
            _ => anyhow::bail!("expected group create under an explicit instance"),
        }
    }

    #[test]
    fn group_update_uses_new_name_flag_not_name() -> anyhow::Result<()> {
        // `--name` would be the global instance selector; renaming a group uses
        // `--new-name`.
        let cli = Cli::try_parse_from(["x0x", "group", "update", "gid", "--new-name", "Renamed"])?;
        assert!(cli.instance.is_none());
        match cli.command {
            Commands::Group {
                sub: Some(GroupSub::Update { new_name, .. }),
            } => {
                assert_eq!(new_name.as_deref(), Some("Renamed"));
                Ok(())
            }
            _ => anyhow::bail!("expected group update with --new-name"),
        }
    }
}
