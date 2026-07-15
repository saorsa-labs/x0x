//! x0xd — local agent daemon for the x0x gossip network.
//!
//! Runs a persistent x0x agent with a REST API for local control.
//! Designed to be started once and left running; external tools
//! (CLI, Fae, scripts) interact through the HTTP endpoints.
//!
//! ## Usage
//!
//! ```bash
//! x0xd                                  # default config
//! x0xd --config /path/to/config.toml    # custom config
//! x0xd --check                          # validate config and exit
//! x0xd --check-updates                  # check/apply updates and exit
//! x0xd --skip-update-check              # start daemon without startup update check
//! x0xd --name alice                     # run a named instance (separate identity)
//! x0xd --list                           # list running instances
//! ```

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "profile-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// jemalloc as the daemon's global allocator. Eliminates the 50 MB+
// heap-to-RSS amplification observed under glibc malloc, where retired
// arenas held pages indefinitely. dirty_decay_ms / muzzy_decay_ms are
// configured via MALLOC_CONF below for aggressive page return.
#[cfg(all(feature = "jemalloc", not(feature = "profile-heap")))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", not(feature = "profile-heap")))]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static MALLOC_CONF: &[u8] =
    b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0,abort_conf:true\0";

use x0x::server::{DaemonConfig, InstanceName, ServeOptions};

/// Resolve CLI/config precedence before deriving any instance-scoped ACL path.
///
/// A CLI name is already validated because it may be needed to locate the
/// named default config file. A config name is validated only when it wins,
/// so an invalid discarded config value cannot override a valid CLI name.
fn resolve_instance_startup(
    cli_name: Option<InstanceName>,
    config_name: Option<String>,
    connect_acl_override: Option<&Path>,
) -> Result<(Option<InstanceName>, Option<PathBuf>)> {
    let instance_name = match cli_name {
        Some(name) => Some(name),
        None => config_name.map(InstanceName::try_from).transpose()?,
    };
    let connect_acl_path = match (connect_acl_override, instance_name.as_ref()) {
        (Some(path), _) => Some(path.to_path_buf()),
        (None, Some(name)) => Some(x0x::connect::default_connect_acl_path_for(name)),
        (None, None) => None,
    };
    Ok((instance_name, connect_acl_path))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // dhat heap profiler. Each daemon writes its own file so multi-daemon
    // runs don't overwrite each other's dump. Set DHAT_OUT_DIR to override.
    #[cfg(feature = "profile-heap")]
    let _dhat_profiler = {
        let dir = std::env::var("DHAT_OUT_DIR").unwrap_or_else(|_| ".".to_string());
        let path = format!("{}/dhat-heap-{}.json", dir, std::process::id());
        eprintln!("dhat: writing heap dump to {} on exit", path);
        dhat::Profiler::builder().file_name(&path).build()
    };

    let args: Vec<String> = std::env::args().collect();

    // Handle --version and --help before anything else
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("x0xd {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("x0xd {} — x0x agent daemon", env!("CARGO_PKG_VERSION"));
        println!();
        println!("USAGE:");
        println!("    x0xd [OPTIONS]");
        println!();
        println!("OPTIONS:");
        println!("    --config <PATH>                 Path to config file (TOML)");
        println!("    --name <NAME>                   Instance name for multi-instance support");
        println!("    --api-port <PORT>               Override API server port");
        println!(
            "    --no-hard-coded-bootstrap       Skip embedded bootstrap peers (config peers kept)"
        );
        println!("    --disable-peer-cache            Do not load or save cached peers");
        println!("    --exec-acl <PATH>               Override default exec ACL path");
        println!("    --connect-acl <PATH>            Override default connect ACL path");
        println!("    --check                         Check configuration and exit");
        println!("    --check-updates       Check for updates and exit");
        println!("    --skip-update-check   Skip update check on startup");
        println!("    --doctor              Run diagnostics");
        println!("    --version, -V         Print version and exit");
        println!("    --help, -h            Print this help and exit");
        return Ok(());
    }

    let config_path = if let Some(idx) = args.iter().position(|a| a == "--config") {
        Some(
            args.get(idx + 1)
                .context("--config requires a path argument")?
                .clone(),
        )
    } else {
        None
    };

    let exec_acl_override = if let Some(idx) = args.iter().position(|a| a == "--exec-acl") {
        Some(PathBuf::from(
            args.get(idx + 1)
                .context("--exec-acl requires a path argument")?
                .clone(),
        ))
    } else {
        None
    };
    let exec_acl_load_mode = if exec_acl_override.is_some() {
        x0x::exec::LoadMode::ExplicitPath
    } else {
        x0x::exec::LoadMode::DefaultPath
    };

    let connect_acl_override = if let Some(idx) = args.iter().position(|a| a == "--connect-acl") {
        Some(PathBuf::from(
            args.get(idx + 1)
                .context("--connect-acl requires a path argument")?
                .clone(),
        ))
    } else {
        None
    };
    let connect_acl_load_mode = if connect_acl_override.is_some() {
        x0x::connect::LoadMode::ExplicitPath
    } else {
        x0x::connect::LoadMode::DefaultPath
    };

    let check_only = args.contains(&"--check".to_string());
    let check_updates_only = args.contains(&"--check-updates".to_string());
    let skip_update_check = args.contains(&"--skip-update-check".to_string());
    let doctor_mode = args.iter().any(|arg| arg == "doctor" || arg == "--doctor");
    let no_hard_coded_bootstrap = args.contains(&"--no-hard-coded-bootstrap".to_string());
    let legacy_no_bootstrap = args.contains(&"--no-bootstrap".to_string());
    if legacy_no_bootstrap {
        eprintln!("warning: --no-bootstrap is deprecated; use --no-hard-coded-bootstrap");
    }
    let disable_configured_bootstrap = no_hard_coded_bootstrap || legacy_no_bootstrap;

    // X0X-0062 reviewer P2 #2: `--no-port-mapping` lets operators disable
    // ant-quic's best-effort UPnP IGD on networks without IGD support or
    // where operator policy forbids unsolicited router port mappings. This
    // overrides the daemon config's `port_mapping_enabled` field.
    let cli_no_port_mapping = args.contains(&"--no-port-mapping".to_string());
    let cli_disable_peer_cache = args.contains(&"--disable-peer-cache".to_string());

    // Parse --api-port for overriding the API server port
    let api_port_override = if let Some(idx) = args.iter().position(|a| a == "--api-port") {
        let port_str = args
            .get(idx + 1)
            .context("--api-port requires a port number")?;
        let port: u16 = port_str
            .parse()
            .context("--api-port value must be a valid port number (0-65535)")?;
        Some(port)
    } else {
        None
    };

    // Parse and validate --name before using it to locate a named config file.
    let cli_instance_name = if let Some(idx) = args.iter().position(|a| a == "--name") {
        let name = args
            .get(idx + 1)
            .context("--name requires an instance name")?
            .clone();
        Some(InstanceName::try_from(name)?)
    } else {
        None
    };

    // Handle --list: discover running instances and exit
    if args.contains(&"--list".to_string()) {
        x0x::server::list_instances().await?;
        return Ok(());
    }

    let mut config = match &config_path {
        Some(path) => load_config(path).await?,
        None => {
            let config_dir_name = match &cli_instance_name {
                Some(name) => format!("x0x-{}", name.as_str()),
                None => "x0x".to_string(),
            };
            let default_path = dirs::config_dir()
                .map(|d| d.join(&config_dir_name).join("config.toml"))
                .unwrap_or_else(|| PathBuf::from("/etc/x0x/config.toml"));
            if default_path.exists() {
                load_config(default_path.to_str().unwrap_or("/etc/x0x/config.toml")).await?
            } else {
                DaemonConfig::default()
            }
        }
    };

    let (instance_name, effective_connect_acl_path) = resolve_instance_startup(
        cli_instance_name,
        config.instance_name.clone(),
        connect_acl_override.as_deref(),
    )?;

    // Apply instance-scoped defaults for data_dir and api_address when --name
    // is active but the config didn't explicitly set instance-scoped values.
    if let Some(ref name) = instance_name {
        let default_data_dir = x0x::server::default_data_dir();
        if config.data_dir == default_data_dir {
            config.data_dir = dirs::data_dir()
                .map(|d| d.join(format!("x0x-{}", name.as_str())))
                .unwrap_or_else(|| PathBuf::from(format!("/var/lib/x0x-{}", name.as_str())));
        }
        if config.api_address == x0x::server::default_api_address() {
            config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
        }
        // Use ephemeral QUIC port for named instances to avoid conflicts
        // when running multiple instances on the same machine. Keep the
        // family at `[::]` (IPv6 unspecified, dual-stack) so both IPv4
        // and IPv6 inbound reach the daemon — otherwise IPv6-only peers
        // on the same machine can't connect and `external_addrs` is
        // IPv4-only on multi-family hosts.
        if config.bind_address == x0x::server::default_bind_address() {
            config.bind_address = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0));
        }
        config.instance_name = Some(name.as_str().to_owned());
    }

    // CLI --api-port overrides config (applied after instance defaults)
    if let Some(port) = api_port_override {
        config.api_address.set_port(port);
    }

    // CLI --no-hard-coded-bootstrap clears the *embedded* global bootstrap
    // network only. When the config file explicitly set `bootstrap_peers`
    // (Some), the operator's list is honored verbatim; when the value came
    // from the embedded default (None), flip it to an explicit empty list so
    // no seed peers are dialed. See DaemonConfig::resolved_bootstrap_peers.
    if disable_configured_bootstrap && config.bootstrap_peers.is_none() {
        config.bootstrap_peers = Some(Vec::new());
    }

    config
        .gossip
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid gossip config: {e}"))?;

    init_logging(&config.log_level, &config.log_format)?;

    let exec_policy = x0x::exec::load_exec_policy(exec_acl_override.as_deref(), exec_acl_load_mode)
        .await
        .context("failed to load exec ACL")?;

    let connect_policy = x0x::connect::load_connect_policy(
        effective_connect_acl_path.as_deref(),
        connect_acl_load_mode,
    )
    .await
    .context("failed to load connect ACL")?;
    tracing::info!(
        target: "x0x::startup",
        path = %effective_connect_acl_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| x0x::connect::default_connect_acl_path().display().to_string()),
        explicit = connect_acl_override.is_some(),
        "Resolved connect-ACL policy path"
    );

    if doctor_mode {
        return run_doctor(&config).await;
    }

    if check_only {
        println!("Configuration is valid");
        println!("{:#?}", config);
        println!("Exec ACL summary: {:#?}", exec_policy.summary());
        println!("Connect ACL summary: {:#?}", connect_policy.summary());
        return Ok(());
    }

    // `--check-updates` is a print-and-exit mode: run the update check, report,
    // and return without serving (matches pre-extraction behaviour).
    if check_updates_only {
        return x0x::server::run_update_check_and_report(&config, skip_update_check).await;
    }

    // Phase 2 (Issue #110): start the server via the library handle. The daemon
    // opts in to self-update (so behaviour is unchanged) and owns Ctrl-C itself
    // — the library must not steal the host's signal.
    let self_update_enabled = config.update_enabled();
    let options = ServeOptions {
        skip_update_check,
        cli_no_port_mapping,
        cli_disable_peer_cache,
        instance_name: instance_name.map(InstanceName::into_string),
        exec_policy,
        connect_policy,
        self_update_enabled,
    };
    let handle = x0x::server::serve_with_options(config, options).await?;

    // Own Ctrl-C in the binary: a detached watcher cancels the server's
    // shutdown token on signal, while the main path awaits run-to-completion.
    // The `/shutdown` HTTP path drives the same exit. The library never installs
    // a Ctrl-C handler itself — that signal belongs to the host process.
    let cancel = handle.cancellation_token();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel.cancel();
        }
    });
    // SIGTERM (what systemd/launchd send on stop/restart) must drive the same
    // graceful exit as Ctrl-C: the shutdown path closes connections and
    // flushes the bootstrap peer cache so learned peers survive restart.
    #[cfg(unix)]
    {
        let cancel = handle.cancellation_token();
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sigterm) => {
                    if sigterm.recv().await.is_some() {
                        cancel.cancel();
                    }
                }
                Err(e) => tracing::warn!("failed to install SIGTERM handler: {e}"),
            }
        });
    }
    handle.wait().await
}

async fn run_doctor(config: &DaemonConfig) -> Result<()> {
    let mut warnings = 0usize;
    let mut failures = 0usize;

    let print_pass = |msg: &str| println!("PASS  {msg}");
    let mut print_warn = |msg: &str| {
        warnings += 1;
        println!("WARN  {msg}");
    };
    let mut print_fail = |msg: &str| {
        failures += 1;
        println!("FAIL  {msg}");
    };

    println!("x0xd doctor");
    println!("-----------");

    // Binary location
    match std::env::current_exe() {
        Ok(path) => print_pass(&format!("binary: {}", path.display())),
        Err(err) => print_warn(&format!("could not determine binary path: {err}")),
    }

    // PATH check
    let in_path = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join("x0xd").exists()))
        .unwrap_or(false);
    if in_path {
        print_pass("x0xd found on PATH");
    } else {
        print_warn("x0xd not found on PATH");
    }

    print_pass("configuration loaded");

    // Probe daemon endpoints
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client")?;

    let base = format!("http://{}", config.api_address);
    let mut daemon_reachable = false;

    match client.get(format!("{base}/health")).send().await {
        Ok(resp) if resp.status().is_success() => {
            daemon_reachable = true;
            print_pass(&format!("daemon reachable at {}", config.api_address));
            match resp.json::<serde_json::Value>().await {
                Ok(body) if body.get("ok").and_then(|v| v.as_bool()) == Some(true) => {
                    print_pass("/health ok=true");
                }
                Ok(body) => print_warn(&format!("/health unexpected payload: {body}")),
                Err(err) => print_warn(&format!("/health invalid JSON: {err}")),
            }
        }
        Ok(resp) => print_warn(&format!("/health HTTP {}", resp.status())),
        Err(err) => print_warn(&format!(
            "daemon not reachable at {}: {err}",
            config.api_address
        )),
    }

    if daemon_reachable {
        // /agent check
        if let Ok(resp) = client.get(format!("{base}/agent")).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    let has_id = body
                        .get("agent_id")
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| !v.is_empty());
                    if has_id {
                        print_pass("/agent returned agent_id");
                    } else {
                        print_warn("/agent response missing agent_id");
                    }
                }
            }
        }

        // /status check
        if let Ok(resp) = client.get(format!("{base}/status")).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    let state = body
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    print_pass(&format!("/status connectivity: {state}"));
                }
            }
        }

        // ADR-0011 §4: full-tunnel-VPN / constrained-MTU environment check.
        if let Ok(resp) = client
            .get(format!("{base}/diagnostics/connectivity"))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    match body.get("transport_environment") {
                        Some(env)
                            if env.get("degraded").and_then(|v| v.as_bool()) == Some(true) =>
                        {
                            let guidance = env
                                .get("guidance")
                                .and_then(|v| v.as_str())
                                .unwrap_or("transport path is degraded");
                            print_warn(&format!("transport environment degraded: {guidance}"));
                            if let Some(reasons) = env.get("reasons").and_then(|v| v.as_array()) {
                                for reason in reasons.iter().filter_map(|r| r.as_str()) {
                                    println!("        • {reason}");
                                }
                            }
                        }
                        Some(_) => print_pass("transport environment: healthy"),
                        None => {}
                    }
                }
            }
        }
    } else {
        // Check if port is free (daemon not running) or blocked (conflict)
        match tokio::net::TcpListener::bind(config.api_address).await {
            Ok(listener) => {
                drop(listener);
                print_warn(&format!(
                    "daemon not running (port {} is free)",
                    config.api_address.port()
                ));
            }
            Err(err) => {
                print_fail(&format!(
                    "port {} in use by another process: {err}",
                    config.api_address.port()
                ));
            }
        }
    }

    println!("-----------");
    if failures > 0 {
        println!("FAIL  {failures} failure(s), {warnings} warning(s)");
        anyhow::bail!("doctor detected failures")
    } else if warnings > 0 {
        println!("WARN  {warnings} warning(s)");
        Ok(())
    } else {
        println!("PASS  all checks passed");
        Ok(())
    }
}

/// Load configuration from TOML file.
async fn load_config(path: &str) -> Result<DaemonConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config file: {path}"))?;
    toml::from_str(&content).with_context(|| format!("failed to parse config file: {path}"))
}

/// Initialize structured logging.
///
/// Filter resolution order:
/// 1. `RUST_LOG` env var if set (supports targets like `ant_quic=debug,x0x=info`)
/// 2. Falls back to the `log_level` config value applied as a global directive
///
/// The effective filter string is logged at startup so operators can verify
/// what ended up active.
fn init_logging(level: &str, format: &str) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    let fallback = level.to_lowercase();
    let fallback_directive = match fallback.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => fallback.as_str(),
        // Unknown values fall back to the privacy-preserving default (#85).
        _ => "warn",
    };

    let (filter, source) = match std::env::var("RUST_LOG") {
        Ok(val) if !val.trim().is_empty() => match EnvFilter::try_new(&val) {
            Ok(f) => (f, format!("RUST_LOG={val}")),
            Err(e) => (
                EnvFilter::new(fallback_directive),
                format!("RUST_LOG invalid ({e}), falling back to {fallback_directive}"),
            ),
        },
        _ => (
            EnvFilter::new(fallback_directive),
            format!("config log_level={fallback_directive}"),
        ),
    };

    // `X0X_LOG_DIR` = opt-in per-daemon log file. When set and writable, the
    // subscriber appends structured lines to `<dir>/x0xd-<pid>.log` in addition
    // to stdout. Format (json vs pretty) follows the same `format` arg; this is
    // the drop-detection substrate required by e2e_full_audit/e2e_stress.
    let log_dir = std::env::var_os("X0X_LOG_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());

    let file_writer = match log_dir.as_ref() {
        Some(dir) => match std::fs::create_dir_all(dir) {
            Ok(()) => {
                let path = dir.join(format!("x0xd-{}.log", std::process::id()));
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                {
                    Ok(f) => Some((path, f)),
                    Err(e) => {
                        eprintln!(
                            "x0xd: X0X_LOG_DIR set but could not open {}: {e}",
                            path.display()
                        );
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "x0xd: X0X_LOG_DIR set but mkdir -p {} failed: {e}",
                    dir.display()
                );
                None
            }
        },
        None => None,
    };

    let file_path_for_log = file_writer.as_ref().map(|(p, _)| p.display().to_string());

    // Compose the subscriber so stdout ALWAYS receives events; the optional
    // file sink is installed as a second fmt layer so it tees rather than
    // replaces stdout. tracing-subscriber's layered Registry guarantees each
    // layer gets every event that matches `filter`.
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let stdout_layer: Box<dyn tracing_subscriber::Layer<_> + Send + Sync + 'static> =
        if format == "json" {
            Box::new(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::io::stdout),
            )
        } else {
            Box::new(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        };

    let file_layer: Option<Box<dyn tracing_subscriber::Layer<_> + Send + Sync + 'static>> =
        match file_writer {
            Some((_, f)) => {
                let writer = std::sync::Mutex::new(f);
                if format == "json" {
                    Some(Box::new(
                        tracing_subscriber::fmt::layer().json().with_writer(writer),
                    ))
                } else {
                    Some(Box::new(
                        tracing_subscriber::fmt::layer().with_writer(writer),
                    ))
                }
            }
            None => None,
        };

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer);
    if let Some(layer) = file_layer {
        registry.with(layer).init();
    } else {
        registry.init();
    }

    if let Some(path) = file_path_for_log.as_deref() {
        tracing::info!(
            target: "x0x::startup",
            source = %source,
            log_file = %path,
            "tracing subscriber initialised (file sink active)"
        );
    } else {
        tracing::info!(
            target: "x0x::startup",
            source = %source,
            "tracing subscriber initialised"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x0x::server::InstanceName;

    /// Construct a valid `InstanceName` from test data. Mirrors the CLI's own
    /// `InstanceName::try_from(name)?` construction at the `--name` parse site.
    fn valid_name(raw: &str) -> InstanceName {
        InstanceName::try_from(raw.to_owned())
            .unwrap_or_else(|e| panic!("{raw:?}: expected valid instance name, got {e}"))
    }

    #[test]
    fn cli_name_wins_over_invalid_config_loser() {
        // A CLI name is already validated; a config name is validated only when
        // it wins. So an invalid config value must be silently discarded, never
        // allowed to veto a valid CLI name. The named CLI instance still owns
        // the identity and derives its plane-scoped ACL path.
        let cli = valid_name("prod");
        let expected_path = x0x::connect::default_connect_acl_path_for(&cli);
        let (instance, path) =
            resolve_instance_startup(Some(cli.clone()), Some("../etc/passwd".to_owned()), None)
                .expect("valid CLI name must shadow an invalid config loser");
        assert_eq!(
            instance,
            Some(cli),
            "CLI name must win the instance identity"
        );
        assert_eq!(
            path,
            Some(expected_path),
            "named CLI instance must derive its plane-scoped ACL path"
        );
    }

    #[test]
    fn config_only_traversal_name_is_rejected_with_canonical_error() {
        // No CLI name: the config value is validated, and a traversal name must
        // be rejected before any ACL path is derived. `resolve_instance_startup`
        // is pure (no filesystem access), so this needs no fixtures. The bare
        // `?` means the CLI/config invalid winner surfaces the exact, established
        // InstanceName error — no extra context added.
        let bad = "../etc/passwd".to_owned();
        let resolver_err = resolve_instance_startup(None, Some(bad.clone()), None)
            .expect_err("traversal config name must be rejected before path derivation")
            .to_string();
        let canonical_err = InstanceName::try_from(bad)
            .expect_err("traversal name must be rejected by the grammar")
            .to_string();
        assert_eq!(
            resolver_err, canonical_err,
            "resolver must propagate the canonical InstanceName error unchanged"
        );
        assert!(
            resolver_err.contains("alphanumeric"),
            "expected the grammar error, got {resolver_err:?}"
        );
    }

    #[test]
    fn unnamed_instance_has_no_default_acl_path() {
        // No name anywhere and no explicit override: no instance identity and
        // no derived ACL path. The unnamed daemon falls through to the base
        // default and load_connect_policy's DefaultPath fail-closed behaviour.
        let (instance, path) =
            resolve_instance_startup(None, None, None).expect("no inputs resolves trivially");
        assert_eq!(instance, None, "no name ⇒ no instance identity");
        assert_eq!(path, None, "no name and no override ⇒ no derived ACL path");
    }

    #[test]
    fn connect_acl_override_shadows_named_instance() {
        // An explicit --connect-acl path always wins, even over a named
        // instance's plane-scoped default. The CLI name still owns identity.
        let cli = valid_name("prod");
        let override_path = std::path::Path::new("/etc/x0x/custom-connect.toml");
        let (instance, path) = resolve_instance_startup(
            Some(cli.clone()),
            Some("testnet".to_owned()), // a valid config loser, also ignored for identity
            Some(override_path),
        )
        .expect("override + valid names resolve");
        assert_eq!(instance, Some(cli), "CLI name owns the instance identity");
        assert_eq!(
            path.as_deref(),
            Some(override_path),
            "explicit override must shadow the named default path"
        );
    }

    #[test]
    fn valid_config_name_resolves_when_no_cli_name() {
        // The config-name arm: with no CLI name, the config value is validated
        // and becomes the instance identity, deriving its own plane-scoped path.
        let resolved = valid_name("testnet");
        let expected_path = x0x::connect::default_connect_acl_path_for(&resolved);
        let (instance, path) = resolve_instance_startup(None, Some("testnet".to_owned()), None)
            .expect("valid config name resolves");
        assert_eq!(
            instance,
            Some(resolved),
            "config name wins when no CLI name is present"
        );
        assert_eq!(
            path,
            Some(expected_path),
            "config name derives its plane-scoped default"
        );
    }
}
