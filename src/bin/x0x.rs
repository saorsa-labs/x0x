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
use std::path::PathBuf;
use std::process::ExitCode;

use x0x::cli::commands;
use x0x::cli::{DaemonClient, OutputFormat};

/// x0x agent network — control a running x0xd daemon.
#[derive(Parser)]
#[command(name = "x0x", version = x0x::VERSION, about = "x0x agent network — control a running x0xd daemon")]
struct Cli {
    /// Named instance to target (reads port from data dir). [dev]
    #[arg(long, global = true, hide = true)]
    name: Option<String>,

    /// Daemon API address override (default: auto-detect). [dev]
    #[arg(long, global = true, hide = true)]
    api: Option<String>,

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
        sub: PresenceSub,
    },
    /// Network diagnostics.
    Network {
        #[command(subcommand)]
        sub: NetworkSub,
    },
    /// Find agents by identity words (permanent hash-derived name).
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
        /// Skip version comparison, download and install latest.
        #[arg(long)]
        force: bool,
    },
    /// WebSocket session info. [dev]
    #[command(hide = true)]
    Ws {
        #[command(subcommand)]
        sub: WsSub,
    },
    /// Open the x0x GUI in your browser.
    Gui,
    /// Print all API routes. [dev]
    #[command(hide = true)]
    Routes,
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
}

#[derive(Subcommand)]
enum NetworkSub {
    /// Network connectivity status.
    Status,
    /// Bootstrap peer cache stats.
    Cache,
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
    },
    /// Get group details.
    Info {
        /// Group ID.
        group_id: String,
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
    /// Leave (or delete) a group.
    Leave {
        /// Group ID.
        group_id: String,
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
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let format = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    };

    let result = run(cli.command, cli.name.as_deref(), cli.api.as_deref(), format).await;

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
        Commands::Routes => return commands::routes(),
        Commands::Tree => return print_command_tree(),
        Commands::Uninstall => return uninstall().await,
        Commands::Purge => return purge().await,
        Commands::Constitution { raw, json } => {
            return commands::constitution::display(*raw, *json);
        }
        Commands::Upgrade { check, force } => {
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
        _ => {}
    }

    let client = DaemonClient::new(name, api, format)?;

    // Commands that need a running daemon.
    match command {
        Commands::Gui => {
            // Ensure daemon is running and open GUI in browser
            client.ensure_running().await?;
            let url = format!("{}/gui", client.base_url());
            eprintln!("x0x GUI: {url}");

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
                eprintln!("Could not open browser. Open the URL above manually.");
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
        },
        Commands::Announce {
            include_user,
            consent,
        } => commands::identity::announce(&client, include_user, consent).await,
        Commands::Peers => commands::network::peers(&client).await,
        Commands::Presence { sub } => match sub {
            PresenceSub::Online => commands::presence::online(&client).await,
            PresenceSub::Foaf { ttl, timeout_ms } => {
                commands::presence::foaf(&client, ttl, timeout_ms).await
            }
            PresenceSub::Find {
                id,
                ttl,
                timeout_ms,
            } => commands::presence::find(&client, &id, ttl, timeout_ms).await,
            PresenceSub::Status { id } => commands::presence::status(&client, &id).await,
        },
        Commands::Network { sub } => match sub {
            NetworkSub::Status => commands::network::network_status(&client).await,
            NetworkSub::Cache => commands::network::bootstrap_cache(&client).await,
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
        Commands::Direct { sub } => match sub {
            DirectSub::Connect { agent_id } => commands::direct::connect(&client, &agent_id).await,
            DirectSub::Send { agent_id, message } => {
                commands::direct::send(&client, &agent_id, &message).await
            }
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
            }) => {
                commands::group::create(
                    &client,
                    &name,
                    description.as_deref(),
                    display_name.as_deref(),
                )
                .await
            }
            Some(GroupSub::Info { group_id }) => commands::group::info(&client, &group_id).await,
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
        Commands::Upgrade { .. } => unreachable!(),
        Commands::Ws { sub } => match sub {
            WsSub::Sessions => commands::ws::sessions(&client).await,
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
        Commands::Routes
        | Commands::Tree
        | Commands::Uninstall
        | Commands::Purge
        | Commands::Constitution { .. }
        | Commands::Start { .. }
        | Commands::Instances
        | Commands::Autostart { .. } => unreachable!(),
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
|   +-- group invite       Generate invite link
|   +-- group join         Join via invite link
|   +-- group set-name     Set display name in group
|   +-- group leave        Leave or delete group
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
    +-- routes             Print all 70 REST API routes
    +-- tree               This command tree
    +-- ws sessions        List WebSocket sessions
    +-- uninstall          Remove x0x binaries (keeps data)
    +-- purge              Remove ALL data and keys (destructive)
";
    print!("{}", tree.replace("{VERSION}", x0x::VERSION));
    Ok(())
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
    if let Some(ref d) = x0xd_path {
        if d.exists() {
            std::fs::remove_file(d).ok();
            eprintln!("Removed {}", d.display());
        }
    }
    // Remove self last
    std::fs::remove_file(&x0x_path).ok();
    eprintln!("Removed {}", x0x_path.display());

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

    let mut paths_to_remove: Vec<std::path::PathBuf> = Vec::new();

    // Data directory
    if let Some(data_dir) = dirs::data_dir().map(|d| d.join("x0x")) {
        if data_dir.exists() {
            eprintln!(
                "  Data:    {} (contacts, groups, stores, transfers)",
                data_dir.display()
            );
            paths_to_remove.push(data_dir);
        }
    }
    // Keys directory
    if let Some(home) = dirs::home_dir().map(|h| h.join(".x0x")) {
        if home.exists() {
            eprintln!(
                "  Keys:    {} (machine.key, agent.key, agent.cert)",
                home.display()
            );
            paths_to_remove.push(home);
        }
    }
    // Named instances
    if let Some(home) = dirs::home_dir() {
        for entry in std::fs::read_dir(&home).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(".x0x-") && entry.path().is_dir() {
                eprintln!("  Instance: {}", entry.path().display());
                paths_to_remove.push(entry.path());
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
    // Try to read agent ID from key file
    let agent_id_hint = if let Some(home) = dirs::home_dir() {
        let key_path = home.join(".x0x/agent.key");
        if key_path.exists() {
            match std::fs::read(&key_path) {
                Ok(data) => match x0x::storage::deserialize_agent_keypair(&data) {
                    Ok(kp) => hex::encode(&kp.agent_id().as_bytes()[..4]),
                    Err(_) => "unknown".to_string(),
                },
                Err(_) => "unknown".to_string(),
            }
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
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

    for path in &paths_to_remove {
        if path.is_dir() {
            match std::fs::remove_dir_all(path) {
                Ok(()) => eprintln!("  Removed {}", path.display()),
                Err(e) => eprintln!("  Failed to remove {}: {}", path.display(), e),
            }
        }
    }

    // Remove binaries
    if let Some(ref d) = x0xd_path {
        if d.exists() {
            std::fs::remove_file(d).ok();
            eprintln!("  Removed {}", d.display());
        }
    }
    std::fs::remove_file(&x0x_path).ok();
    eprintln!("  Removed {}", x0x_path.display());

    eprintln!();
    eprintln!("x0x has been completely removed.");
    eprintln!("To reinstall: curl -sfL https://x0x.md | sh");
    Ok(())
}
