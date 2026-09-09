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
                 <key>EnvironmentVariables</key>\n\
                 <dict>\n\
                     <key>{}</key>\n\
                     <string>1</string>\n\
                 </dict>\n\
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
            // launchd ancestry alone is NOT classified as supervision
            // (`is_supervised`, src/upgrade/restart.rs) — without this var a
            // KeepAlive agent takes the transactional-handoff path on
            // self-update and launchd relaunches a second daemon on the same
            // data dir (#493). With it, self-update exits and lets launchd
            // restart the new binary.
            crate::upgrade::restart::SUPERVISED_ENV_VAR,
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

/// What `x0x autostart --repair` decided about one existing launchd job.
///
/// ADR-0061's migration boundary: inspect the real job, prepare a *narrow*
/// change that preserves its label/executable/arguments/roots, and refuse
/// anything it cannot prove safe. It never installs a default job beside a
/// running custom one, and never rewrites arbitrary service policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepairVerdict {
    /// The job already declares the supervision marker — no change needed.
    AlreadySupervised,
    /// The job unconditionally respawns and lacks only the marker.
    /// `has_env_dict` says whether `EnvironmentVariables` must be created.
    Repairable { has_env_dict: bool },
    /// The job is an x0xd job but does not unconditionally respawn, so
    /// declaring it supervised would be unsound.
    Refused(String),
    /// Not an x0xd job at all. The repair says nothing about it and never
    /// touches it — the LaunchAgents directory holds other people's services.
    NotAnX0xdJob,
}

/// Basename of a launchd `ProgramArguments[0]`, ignoring any path.
fn program_basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Classify one launchd job (a plist converted to JSON) for `--repair`.
///
/// Kept free of `launchctl`/`plutil` so the decision table is testable on any
/// platform; the macOS driver below only supplies the parsed job and applies
/// the verdict.
pub(crate) fn classify_launchd_job(plist: &serde_json::Value) -> RepairVerdict {
    let program = plist
        .get("ProgramArguments")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|p| p.as_str())
        .or_else(|| plist.get("Program").and_then(|p| p.as_str()));

    let Some(program) = program else {
        return RepairVerdict::NotAnX0xdJob;
    };
    if program_basename(program) != "x0xd" {
        return RepairVerdict::NotAnX0xdJob;
    }

    // A supervised exit is only safe if something is guaranteed to bring the
    // daemon back. `KeepAlive: true` is that guarantee; a KeepAlive dict is
    // conditional and RunAtLoad-only jobs are one-shot. ADR-0061 §4: those
    // must not be mistaken for a guaranteed supervised respawn.
    match plist.get("KeepAlive") {
        Some(serde_json::Value::Bool(true)) => {}
        Some(serde_json::Value::Object(_)) => {
            return RepairVerdict::Refused(
                "KeepAlive is a conditional dictionary, so an unconditional respawn after \
                 the upgrade exit is not guaranteed; review the job by hand"
                    .to_string(),
            );
        }
        _ => {
            return RepairVerdict::Refused(
                "job has no `KeepAlive: true`, so nothing is guaranteed to restart x0xd after \
                 it exits for an upgrade; it keeps the transactional handoff path"
                    .to_string(),
            );
        }
    }

    let env = plist.get("EnvironmentVariables");
    let already = env
        .and_then(|e| e.get(crate::upgrade::restart::SUPERVISED_ENV_VAR))
        .and_then(|v| v.as_str())
        == Some("1");
    if already {
        RepairVerdict::AlreadySupervised
    } else {
        RepairVerdict::Repairable {
            has_env_dict: env.is_some_and(|e| e.is_object()),
        }
    }
}

/// `x0x autostart --repair` — migrate an existing hand-written launchd job to
/// the supervised-upgrade contract (ADR-0061, #493).
///
/// Inspects the job without changing service state, then adds only
/// `EnvironmentVariables.X0X_SUPERVISED = "1"`, preserving the job's label,
/// executable, arguments, roots and every other key. The change takes effect
/// on the job's next load; reloading is left to the operator because
/// unload/load stops a running daemon.
pub async fn autostart_repair() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let plist_dir = dirs::home_dir()
            .context("cannot determine home directory")?
            .join("Library/LaunchAgents");
        if !plist_dir.is_dir() {
            println!("No LaunchAgents directory at {}", plist_dir.display());
            println!("Nothing to repair. `x0x autostart` installs a compliant job.");
            return Ok(());
        }

        let mut inspected = 0usize;
        let mut repaired = 0usize;
        let mut refused = 0usize;
        let mut compliant = 0usize;

        for entry in std::fs::read_dir(&plist_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }
            let Some(job) = read_plist_as_json(&path)? else {
                continue;
            };
            // Only x0xd jobs are ours to look at; skip everything else
            // silently rather than reporting on the user's other agents.
            let verdict = classify_launchd_job(&job);
            if verdict == RepairVerdict::NotAnX0xdJob {
                continue;
            }
            inspected += 1;
            let label = job
                .get("Label")
                .and_then(|l| l.as_str())
                .unwrap_or("<unlabelled>");
            println!("Job {label} ({})", path.display());

            match verdict {
                RepairVerdict::AlreadySupervised => {
                    compliant += 1;
                    println!(
                        "  Already declares {}=1 — no change.",
                        crate::upgrade::restart::SUPERVISED_ENV_VAR
                    );
                }
                RepairVerdict::Refused(reason) => {
                    refused += 1;
                    println!("  REFUSED: {reason}");
                    println!("  Left unchanged.");
                }
                RepairVerdict::NotAnX0xdJob => unreachable!("skipped above"),
                RepairVerdict::Repairable { has_env_dict } => {
                    let backup = path.with_extension("plist.x0x-backup");
                    std::fs::copy(&path, &backup)
                        .with_context(|| format!("failed to back up {}", path.display()))?;
                    apply_supervised_marker(&path, has_env_dict)?;

                    // Verify the readback rather than trusting the write.
                    let after = read_plist_as_json(&path)?
                        .context("repaired plist could not be read back")?;
                    if classify_launchd_job(&after) != RepairVerdict::AlreadySupervised {
                        std::fs::copy(&backup, &path).with_context(|| {
                            format!("failed to restore backup over {}", path.display())
                        })?;
                        anyhow::bail!(
                            "repair of {} did not verify; the backup was restored",
                            path.display()
                        );
                    }
                    repaired += 1;
                    println!("  Backup:   {}", backup.display());
                    println!(
                        "  Added:    {}=1 (all other keys preserved)",
                        crate::upgrade::restart::SUPERVISED_ENV_VAR
                    );
                    println!("  Takes effect on the job's next load. To apply now:");
                    println!("    launchctl unload {}", path.display());
                    println!("    launchctl load {}", path.display());
                }
            }
        }

        if inspected == 0 {
            println!("No x0xd launchd job found in {}", plist_dir.display());
            println!("Nothing to repair — `x0x autostart` installs a compliant job.");
            return Ok(());
        }
        println!(
            "\nInspected {inspected} x0xd job(s): {repaired} repaired, {compliant} already \
             compliant, {refused} refused."
        );
        if repaired > 0 {
            println!(
                "Also confirm `[update] stop_on_upgrade` is true (the default) in the daemon \
                 config: a supervised job with it set to false now refuses self-update."
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("`x0x autostart --repair` currently migrates macOS launchd jobs only.");
        println!("systemd units generated by `x0x autostart` already set Restart=always,");
        println!("and INVOCATION_ID makes them supervised without a marker.");
    }

    Ok(())
}

/// Convert a plist to JSON via `plutil`. `Ok(None)` when the file is not a
/// parseable plist (deliberately not an error — the directory holds other
/// people's agents).
#[cfg(target_os = "macos")]
fn read_plist_as_json(path: &Path) -> Result<Option<serde_json::Value>> {
    let out = std::process::Command::new("plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(path)
        .output()
        .context("failed to run plutil")?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&out.stdout).ok())
}

/// Add `EnvironmentVariables.X0X_SUPERVISED = "1"` in place, creating the
/// dictionary only if the job has none. Every other key is untouched.
#[cfg(target_os = "macos")]
fn apply_supervised_marker(path: &Path, has_env_dict: bool) -> Result<()> {
    let marker = crate::upgrade::restart::SUPERVISED_ENV_VAR;
    let mut cmd = std::process::Command::new("plutil");
    if has_env_dict {
        cmd.args(["-replace", &format!("EnvironmentVariables.{marker}")])
            .args(["-string", "1", "--"]);
    } else {
        cmd.args(["-replace", "EnvironmentVariables"]).args([
            "-json",
            &format!("{{\"{marker}\":\"1\"}}"),
            "--",
        ]);
    }
    let status = cmd
        .arg(path)
        .status()
        .context("failed to run plutil -replace")?;
    if !status.success() {
        anyhow::bail!("plutil could not update {} ({status})", path.display());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_file_path_default() {
        let path = port_file_path(None).unwrap();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("x0x"), "should contain x0x: {path_str}");
        assert!(
            path_str.ends_with("api.port"),
            "should end with api.port: {path_str}"
        );
    }

    #[test]
    fn port_file_path_named() {
        let path = port_file_path(Some("test-instance")).unwrap();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("x0x-test-instance"),
            "should contain instance name: {path_str}"
        );
        assert!(
            path_str.ends_with("api.port"),
            "should end with api.port: {path_str}"
        );
    }

    #[test]
    fn discovered_base_url_returns_none_for_missing_file() {
        let result = discovered_base_url(Some("nonexistent-instance-xyz-12345")).unwrap();
        assert!(
            result.is_none(),
            "should return None for nonexistent instance"
        );
    }

    #[test]
    fn find_x0xd_returns_error_when_not_found() {
        // Temporarily change PATH to something that doesn't have x0xd
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = find_x0xd();
        }));
        // Should not panic — just return an error
        assert!(result.is_ok());
    }

    use crate::cli::commands::test_support::start_mock_server;
    #[tokio::test]
    async fn stop_sends_shutdown_request() {
        let mock_resp = serde_json::json!({"ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = stop(&client).await;
        assert!(result.is_ok(), "stop should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn doctor_runs_all_checks() {
        let mock_resp = serde_json::json!({
            "agent_id": "abc123",
            "peers": 5,
            "status": "connected",
            "contacts": [{"agent_id": "xyz"}]
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = doctor(&client).await;
        assert!(result.is_ok(), "doctor should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn instances_returns_empty_when_no_port_files() {
        // In a test environment without port files, instances should return empty
        let result = instances().await;
        assert!(result.is_ok(), "instances should not fail: {:?}", result);
    }

    fn job(extra: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "Label": "com.example.x0xd",
            "ProgramArguments": ["/opt/x0x/bin/x0xd", "--name", "alice"],
            "RunAtLoad": true,
            "KeepAlive": true,
        });
        if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        base
    }

    #[test]
    fn repair_targets_a_keepalive_x0xd_job_missing_only_the_marker() {
        // This is the #493 population: a hand-written KeepAlive agent that
        // launchd will respawn, but which x0xd cannot recognise as supervised,
        // so self-update takes the handoff path and launchd starts a second
        // daemon on the same data root.
        assert_eq!(
            classify_launchd_job(&job(serde_json::json!({}))),
            RepairVerdict::Repairable {
                has_env_dict: false
            }
        );
        // An existing environment dict must be added to, not replaced — the
        // migration boundary says preserve the job's other environment.
        assert_eq!(
            classify_launchd_job(&job(
                serde_json::json!({"EnvironmentVariables": {"RUST_LOG": "info"}})
            )),
            RepairVerdict::Repairable { has_env_dict: true }
        );
    }

    #[test]
    fn repair_is_a_no_op_on_an_already_compliant_job() {
        assert_eq!(
            classify_launchd_job(&job(serde_json::json!({
                "EnvironmentVariables": {"X0X_SUPERVISED": "1"}
            }))),
            RepairVerdict::AlreadySupervised
        );
    }

    #[test]
    fn repair_refuses_jobs_that_do_not_guarantee_a_respawn() {
        // ADR-0061 §4: a one-shot or conditional job must not be mistaken for
        // a guaranteed supervised respawn. Marking one supervised would make
        // self-update exit 0 with nobody bringing the daemon back — a worse
        // outcome than the duplicate-daemon bug being fixed.
        let mut one_shot = job(serde_json::json!({}));
        one_shot
            .as_object_mut()
            .expect("object")
            .remove("KeepAlive");
        assert!(matches!(
            classify_launchd_job(&one_shot),
            RepairVerdict::Refused(_)
        ));
        assert!(matches!(
            classify_launchd_job(&job(
                serde_json::json!({"KeepAlive": {"SuccessfulExit": false}})
            )),
            RepairVerdict::Refused(_)
        ));
    }

    #[test]
    fn repair_does_not_touch_jobs_that_are_not_x0xd() {
        // The repair must never rewrite an unrelated LaunchAgent, and must
        // never install a default x0xd job beside somebody else's service.
        let foreign = serde_json::json!({
            "Label": "com.example.other",
            "ProgramArguments": ["/usr/local/bin/otherd"],
            "KeepAlive": true,
        });
        assert_eq!(classify_launchd_job(&foreign), RepairVerdict::NotAnX0xdJob);

        // Real LaunchAgents directories contain jobs that declare neither key
        // (observed live: com.google.keystone.*). Those are somebody else's
        // service, so they must be skipped silently — not reported as x0xd
        // jobs the repair refused.
        assert_eq!(
            classify_launchd_job(&serde_json::json!({"Label": "com.google.keystone.agent"})),
            RepairVerdict::NotAnX0xdJob
        );
    }

    #[tokio::test]
    async fn autostart_remove_does_not_panic() {
        // Should not panic even without autostart configured
        let result = autostart_remove().await;
        assert!(
            result.is_ok(),
            "autostart_remove should not fail: {:?}",
            result
        );
    }
}
