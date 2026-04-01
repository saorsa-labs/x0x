//! Daemon lifecycle CLI commands.

use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;

use crate::cli::DaemonClient;

/// `x0x start` — spawn x0xd as a background process.
pub async fn start(name: Option<&str>, config: Option<&Path>, foreground: bool) -> Result<()> {
    // Find x0xd binary: same directory as x0x, then PATH.
    let x0xd_path = find_x0xd()?;

    // Check if the target instance is already running.
    let format = crate::cli::OutputFormat::Text;
    if let Some(base_url) = discovered_base_url(name)? {
        let client = DaemonClient::new(name, Some(&base_url), format)?;
        if client.ensure_running().await.is_ok() {
            println!("Daemon already running at {}", client.base_url());
            return Ok(());
        }
    }

    let mut cmd = std::process::Command::new(&x0xd_path);
    if let Some(n) = name {
        cmd.arg("--name").arg(n);
    }
    if let Some(c) = config {
        cmd.arg("--config").arg(c);
    }

    if foreground {
        // Replace current process with x0xd.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = cmd.exec();
            anyhow::bail!("failed to exec x0xd: {err}");
        }
        #[cfg(not(unix))]
        {
            let status = cmd.status().context("failed to run x0xd")?;
            if !status.success() {
                anyhow::bail!("x0xd exited with {status}");
            }
            return Ok(());
        }
    }

    // Background: spawn and wait for health.
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let _child = cmd.spawn().context("failed to spawn x0xd")?;

    // Poll health for up to 5 seconds.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let Some(base_url) = discovered_base_url(name)? else {
            continue;
        };
        let client = DaemonClient::new(name, Some(&base_url), format)?;
        if client.ensure_running().await.is_ok() {
            println!("Daemon started at {}", client.base_url());
            return Ok(());
        }
    }

    let fallback_url =
        discovered_base_url(name)?.unwrap_or_else(|| String::from("http://127.0.0.1:12700"));
    println!("Daemon spawned but not yet reachable at {fallback_url}");
    Ok(())
}

/// `x0x stop` — POST /shutdown
pub async fn stop(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    match client.post_empty("/shutdown").await {
        Ok(_) => println!("Daemon shutting down."),
        Err(e) => {
            // Connection reset is expected when the server shuts down.
            let msg = format!("{e:#}");
            if msg.contains("connection") || msg.contains("reset") || msg.contains("closed") {
                println!("Daemon shutting down.");
            } else {
                return Err(e);
            }
        }
    }
    Ok(())
}

/// `x0x doctor` — run diagnostics against the daemon.
pub async fn doctor(client: &DaemonClient) -> Result<()> {
    println!("Running diagnostics...\n");

    // 1. Health check.
    print!("Health check: ");
    match client.ensure_running().await {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("FAIL — {e}");
            return Ok(());
        }
    }

    // 2. Agent identity.
    print!("Agent identity: ");
    match client.get("/agent").await {
        Ok(val) => {
            let agent_id = val
                .get("agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("{agent_id}");
        }
        Err(e) => println!("FAIL — {e}"),
    }

    // 3. Network status.
    print!("Network: ");
    match client.get("/status").await {
        Ok(val) => {
            let peers = val.get("peers").and_then(|v| v.as_u64()).unwrap_or(0);
            let connectivity = val
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("{peers} peers, {connectivity}");
        }
        Err(e) => println!("FAIL — {e}"),
    }

    // 4. Contacts.
    print!("Contacts: ");
    match client.get("/contacts").await {
        Ok(val) => {
            let count = val
                .get("contacts")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            println!("{count} contacts");
        }
        Err(e) => println!("FAIL — {e}"),
    }

    println!("\nDiagnostics complete.");
    Ok(())
}

/// `x0x instances` — list running daemon instances.
pub async fn instances() -> Result<()> {
    let data_dir = dirs::data_dir().context("cannot determine data directory")?;

    let mut found = Vec::new();

    // Check default instance.
    let default_port = data_dir.join("x0x").join("api.port");
    if default_port.exists() {
        found.push(("(default)".to_string(), default_port));
    }

    // Check named instances.
    if let Ok(entries) = std::fs::read_dir(&data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(instance) = name_str.strip_prefix("x0x-") {
                let port_file = entry.path().join("api.port");
                if port_file.exists() {
                    found.push((instance.to_string(), port_file));
                }
            }
        }
    }

    if found.is_empty() {
        println!("No running instances found.");
        return Ok(());
    }

    let name_width = found.iter().map(|(n, _)| n.len()).max().unwrap_or(4).max(4);
    println!("{:<name_width$}  {:<21}  {:<10}", "NAME", "API", "STATUS");

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;

    for (name, port_file) in &found {
        let addr = std::fs::read_to_string(port_file)
            .unwrap_or_default()
            .trim()
            .to_string();
        let status = if !addr.is_empty() {
            match http_client
                .get(format!("http://{addr}/health"))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => "running",
                _ => "stale",
            }
        } else {
            "stale"
        };
        println!("{:<name_width$}  {:<21}  {:<10}", name, addr, status);
    }

    Ok(())
}

/// `x0x autostart` — configure daemon to start on boot.
pub async fn autostart(name: Option<&str>) -> Result<()> {
    let x0xd_path = find_x0xd()?;
    let x0xd = x0xd_path.to_string_lossy();

    #[cfg(target_os = "linux")]
    {
        let mut args = Vec::new();
        if let Some(n) = name {
            args.push("--name".to_string());
            args.push(n.to_string());
        }
        let args_str = args.join(" ");
        let unit_dir = dirs::config_dir()
            .context("cannot determine config directory")?
            .join("systemd/user");
        std::fs::create_dir_all(&unit_dir)?;

        let unit_path = unit_dir.join("x0xd.service");
        let unit = format!(
            "[Unit]\n\
             Description=x0x Agent Daemon\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={x0xd} {args_str}\n\
             Restart=always\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        );
        std::fs::write(&unit_path, unit)?;

        let status = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .context("systemctl daemon-reload failed")?;
        if !status.success() {
            anyhow::bail!("systemctl daemon-reload failed");
        }

        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "x0xd"])
            .status()
            .context("systemctl enable failed")?;
        if !status.success() {
            anyhow::bail!("systemctl enable failed");
        }

        println!("Autostart enabled (systemd user service)");
        println!("  systemctl --user start x0xd");
        println!("  systemctl --user status x0xd");
        println!("  systemctl --user stop x0xd");
    }

    #[cfg(target_os = "macos")]
    {
        let plist_dir = dirs::home_dir()
            .context("cannot determine home directory")?
            .join("Library/LaunchAgents");
        std::fs::create_dir_all(&plist_dir)?;

        let plist_path = plist_dir.join("com.saorsalabs.x0xd.plist");
        let mut prog_args = format!("        <string>{x0xd}</string>\n");
        if let Some(n) = name {
            prog_args.push_str(&format!(
                "        <string>--name</string>\n        <string>{n}</string>\n"
            ));
        }

        let data_dir = if let Some(n) = name {
            dirs::data_dir()
                .context("cannot determine data directory")?
                .join(format!("x0x-{n}"))
        } else {
            dirs::data_dir()
                .context("cannot determine data directory")?
                .join("x0x")
        };
        std::fs::create_dir_all(&data_dir)?;
        let log_path = data_dir.join("x0xd.log");

        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
                 <key>Label</key>\n\
                 <string>com.saorsalabs.x0xd</string>\n\
                 <key>ProgramArguments</key>\n\
                 <array>\n\
             {prog_args}\
                 </array>\n\
                 <key>RunAtLoad</key>\n\
                 <true/>\n\
                 <key>KeepAlive</key>\n\
                 <true/>\n\
                 <key>StandardOutPath</key>\n\
                 <string>{}</string>\n\
                 <key>StandardErrorPath</key>\n\
                 <string>{}</string>\n\
             </dict>\n\
             </plist>\n",
            log_path.display(),
            log_path.display()
        );
        std::fs::write(&plist_path, plist)?;

        // Unload any existing agent first (ignore errors if not loaded).
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .output();

        // Load the agent so it starts now and on boot.
        let status = std::process::Command::new("launchctl")
            .args(["load", &plist_path.to_string_lossy()])
            .status()
            .context("failed to run launchctl load")?;
        if !status.success() {
            anyhow::bail!("launchctl load failed (exit {})", status);
        }

        println!("Autostart enabled (launchd agent)");
        println!("  Plist:  {}", plist_path.display());
        println!("  Status: launchctl list | grep x0xd");
        println!("  Remove: x0x autostart --remove");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        println!("Autostart not supported on this platform.");
        println!("Run x0xd manually or configure your OS service manager.");
    }

    Ok(())
}

/// `x0x autostart --remove` — remove autostart configuration.
pub async fn autostart_remove() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "x0xd"])
            .status();
        let unit_path = dirs::config_dir()
            .context("cannot determine config directory")?
            .join("systemd/user/x0xd.service");
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)?;
        }
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        println!("Autostart removed (systemd)");
    }

    #[cfg(target_os = "macos")]
    {
        let plist_path = dirs::home_dir()
            .context("cannot determine home directory")?
            .join("Library/LaunchAgents/com.saorsalabs.x0xd.plist");
        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", &plist_path.to_string_lossy()])
                .status();
            std::fs::remove_file(&plist_path)?;
        }
        println!("Autostart removed (launchd)");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    println!("Autostart not supported on this platform.");

    Ok(())
}

fn discovered_base_url(name: Option<&str>) -> Result<Option<String>> {
    let port_file = port_file_path(name)?;
    if !port_file.exists() {
        return Ok(None);
    }

    let addr = std::fs::read_to_string(&port_file)
        .context("failed to read port file")?
        .trim()
        .to_string();
    if addr.is_empty() {
        return Ok(None);
    }

    Ok(Some(format!("http://{addr}")))
}

fn port_file_path(name: Option<&str>) -> Result<std::path::PathBuf> {
    let data_dir = dirs::data_dir().context("cannot determine data directory")?;
    let dir_name = match name {
        Some(instance) => format!("x0x-{instance}"),
        None => "x0x".to_string(),
    };
    Ok(data_dir.join(dir_name).join("api.port"))
}

/// Find the x0xd binary.
fn find_x0xd() -> Result<std::path::PathBuf> {
    // Same directory as x0x binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("x0xd");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Search PATH.
    if let Ok(path) = which::which("x0xd") {
        return Ok(path);
    }

    anyhow::bail!("x0xd not found. Install it or ensure it's in the same directory as x0x.")
}
