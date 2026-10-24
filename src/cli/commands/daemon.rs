//! Daemon lifecycle CLI commands.

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::cli::{DaemonClient, OutputFormat};

/// Bounded timeout for doctor's first `/health` probe (matches `ensure_running`).
const DOCTOR_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Per-check status in a doctor report (`x0x doctor --json`, #1382).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorCheckStatus {
    Ok,
    Warn,
    Fail,
}

/// One named check in the doctor summary.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DoctorCheck {
    pub(crate) status: DoctorCheckStatus,
    pub(crate) detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evidence: Option<serde_json::Value>,
}

impl DoctorCheck {
    fn ok_with(detail: impl Into<String>, evidence: serde_json::Value) -> Self {
        Self {
            status: DoctorCheckStatus::Ok,
            detail: detail.into(),
            evidence: Some(evidence),
        }
    }

    fn warn(detail: impl Into<String>, evidence: Option<serde_json::Value>) -> Self {
        Self {
            status: DoctorCheckStatus::Warn,
            detail: detail.into(),
            evidence,
        }
    }

    fn fail(detail: impl Into<String>) -> Self {
        Self {
            status: DoctorCheckStatus::Fail,
            detail: detail.into(),
            evidence: None,
        }
    }
}

/// Machine-readable `x0x doctor` summary (#1382 / M1).
///
/// Fields are the four local health signals named by #1167: connectivity,
/// key health, store integrity and upgrade state. `ok` is false when any
/// check is `fail`; warnings alone keep `ok` true (exit zero).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) ok: bool,
    pub(crate) connectivity: DoctorCheck,
    pub(crate) key_health: DoctorCheck,
    pub(crate) store_integrity: DoctorCheck,
    pub(crate) upgrade: DoctorCheck,
}

impl DoctorReport {
    fn from_checks(
        connectivity: DoctorCheck,
        key_health: DoctorCheck,
        store_integrity: DoctorCheck,
        upgrade: DoctorCheck,
    ) -> Self {
        let ok = ![&connectivity, &key_health, &store_integrity, &upgrade]
            .iter()
            .any(|c| c.status == DoctorCheckStatus::Fail);
        Self {
            ok,
            connectivity,
            key_health,
            store_integrity,
            upgrade,
        }
    }

    /// Serialize for agent parsers and the Done-when test.
    pub(crate) fn to_json_value(&self) -> Result<serde_json::Value> {
        serde_json::to_value(self).context("serialize doctor report")
    }
}

/// Collect the four doctor checks against a live (or mock) daemon.
pub(crate) async fn collect_doctor_report(client: &DaemonClient) -> DoctorReport {
    let connectivity = check_connectivity(client).await;
    let daemon_up = connectivity.status != DoctorCheckStatus::Fail;

    let key_health = if daemon_up {
        check_key_health(client).await
    } else {
        DoctorCheck::fail("skipped: daemon unreachable")
    };
    let store_integrity = if daemon_up {
        check_store_integrity(client).await
    } else {
        DoctorCheck::fail("skipped: daemon unreachable")
    };
    let upgrade = if daemon_up {
        check_upgrade_state(client).await
    } else {
        DoctorCheck::fail("skipped: daemon unreachable")
    };

    DoctorReport::from_checks(connectivity, key_health, store_integrity, upgrade)
}

async fn check_connectivity(client: &DaemonClient) -> DoctorCheck {
    match client
        .get_with_timeout("/health", DOCTOR_HEALTH_TIMEOUT)
        .await
    {
        Ok(val) => {
            let status = val
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let peers = val.get("peers").and_then(|v| v.as_u64()).unwrap_or(0);
            let detail = format!("{status}, {peers} peers");
            let evidence = serde_json::json!({
                "status": status,
                "peers": peers,
                "degraded_reason": val.get("degraded_reason").cloned().unwrap_or(serde_json::Value::Null),
            });
            match status {
                "healthy" | "ok" | "connected" => DoctorCheck::ok_with(detail, evidence),
                "degraded" => DoctorCheck::warn(detail, Some(evidence)),
                other => DoctorCheck::fail(format!("health status {other}")),
            }
        }
        Err(e) => DoctorCheck::fail(format!("daemon not reachable: {e:#}")),
    }
}

async fn check_key_health(client: &DaemonClient) -> DoctorCheck {
    match client.get("/agent").await {
        Ok(val) => {
            let agent_id = val.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
            let machine_id = val.get("machine_id").and_then(|v| v.as_str()).unwrap_or("");
            if agent_id.is_empty() || machine_id.is_empty() {
                return DoctorCheck::fail("agent_id or machine_id missing from /agent");
            }
            DoctorCheck::ok_with(
                format!("agent_id={agent_id}"),
                serde_json::json!({
                    "agent_id": agent_id,
                    "machine_id": machine_id,
                    "user_id": val.get("user_id").cloned().unwrap_or(serde_json::Value::Null),
                }),
            )
        }
        Err(e) => DoctorCheck::fail(format!("/agent: {e:#}")),
    }
}

async fn check_store_integrity(client: &DaemonClient) -> DoctorCheck {
    match client.get("/stores").await {
        Ok(val) => {
            let stores = val
                .get("stores")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let degraded: Vec<String> = stores
                .iter()
                .filter(|s| s.get("durability_degraded").and_then(|v| v.as_bool()) == Some(true))
                .filter_map(|s| s.get("id").and_then(|v| v.as_str()).map(str::to_string))
                .collect();
            if !degraded.is_empty() {
                return DoctorCheck::fail(format!(
                    "{} store(s) durability_degraded: {}",
                    degraded.len(),
                    degraded.join(", ")
                ));
            }
            DoctorCheck::ok_with(
                format!("{} store(s) readable", stores.len()),
                serde_json::json!({ "store_count": stores.len() }),
            )
        }
        Err(e) => DoctorCheck::fail(format!("/stores: {e:#}")),
    }
}

async fn check_upgrade_state(client: &DaemonClient) -> DoctorCheck {
    // Prefer `/diagnostics/upgrade` when #1381 ships; fall back to GET /upgrade.
    // Until then `/upgrade` is a release *lookup*, not apply/rollback health:
    // lookup failure and HTTP errors are `warn`; an available update stays `ok`.
    let (path, val) = match client.get("/diagnostics/upgrade").await {
        Ok(val) => ("/diagnostics/upgrade", val),
        Err(_) => match client.get("/upgrade").await {
            Ok(val) => ("/upgrade", val),
            Err(e) => {
                return DoctorCheck::warn(
                    format!("/upgrade lookup unavailable: {e:#}"),
                    Some(serde_json::json!({ "source": "/upgrade", "lookup_error": true })),
                );
            }
        },
    };

    if val.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        let err = val
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("upgrade check failed");
        return DoctorCheck::warn(
            format!("{path} lookup failed: {err}"),
            Some(serde_json::json!({
                "source": path,
                "lookup_error": true,
                "error": err,
            })),
        );
    }

    let update_available = val
        .get("update_available")
        .or_else(|| val.get("pending"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let current = val
        .get("current_version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let latest = val
        .get("version")
        .or_else(|| val.get("latest_version"))
        .and_then(|v| v.as_str());
    let detail = if update_available {
        match latest {
            Some(v) => format!("update available: {current} → {v}"),
            None => format!("update available (current {current})"),
        }
    } else {
        format!("up to date ({current})")
    };
    DoctorCheck::ok_with(
        detail,
        serde_json::json!({
            "source": path,
            "update_available": update_available,
            "current_version": current,
            "latest_version": latest,
        }),
    )
}

fn write_doctor_text(report: &DoctorReport, out: &mut dyn Write) -> Result<()> {
    writeln!(out, "Running diagnostics...\n")?;
    for (name, check) in [
        ("Connectivity", &report.connectivity),
        ("Key health", &report.key_health),
        ("Store integrity", &report.store_integrity),
        ("Upgrade", &report.upgrade),
    ] {
        let label = match check.status {
            DoctorCheckStatus::Ok => "OK",
            DoctorCheckStatus::Warn => "WARN",
            DoctorCheckStatus::Fail => "FAIL",
        };
        writeln!(out, "{name}: {label} — {}", check.detail)?;
    }
    writeln!(out)?;
    if report.ok {
        writeln!(out, "Diagnostics complete.")?;
    } else {
        writeln!(out, "Diagnostics complete with failures.")?;
    }
    Ok(())
}

/// Four-check failure summary when the daemon cannot be addressed at all
/// (named instance with no `api.port`, or equivalent discovery failure).
pub(crate) fn unreachable_doctor_report(detail: impl Into<String>) -> DoctorReport {
    let detail = detail.into();
    DoctorReport::from_checks(
        DoctorCheck::fail(detail),
        DoctorCheck::fail("skipped: daemon unreachable"),
        DoctorCheck::fail("skipped: daemon unreachable"),
        DoctorCheck::fail("skipped: daemon unreachable"),
    )
}

/// Print the report and return `Err` when any check failed (#1382).
pub(crate) fn finish_doctor(format: OutputFormat, report: &DoctorReport) -> Result<()> {
    finish_doctor_write(format, report, &mut std::io::stdout())
}

/// Write the report to `out` and return `Err` when any check failed.
///
/// Tests capture `out` so they assert the exact JSON stdout contract.
pub(crate) fn finish_doctor_write(
    format: OutputFormat,
    report: &DoctorReport,
    out: &mut dyn Write,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let value = report.to_json_value()?;
            let text = serde_json::to_string_pretty(&value).context("serialize doctor JSON")?;
            writeln!(out, "{text}")?;
        }
        OutputFormat::Text => write_doctor_text(report, out)?,
    }
    if report.ok {
        Ok(())
    } else {
        anyhow::bail!("doctor detected failures")
    }
}

/// `x0x doctor` when named-instance discovery fails before any HTTP client
/// exists. Still emits the JSON/text summary; does not fall back to default.
pub fn doctor_unreachable(format: OutputFormat, err: &anyhow::Error) -> Result<()> {
    let report = unreachable_doctor_report(format!("daemon not reachable: {err:#}"));
    finish_doctor(format, &report)
}

/// `x0x doctor` — run diagnostics against the daemon.
///
/// With `--json`, prints one summary object (connectivity, key health, store
/// integrity, upgrade). Exits non-zero when any check is `fail`.
pub async fn doctor(client: &DaemonClient) -> Result<()> {
    let report = collect_doctor_report(client).await;
    finish_doctor(client.format(), &report)
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

/// Template identity stamped into every `x0x autostart`-generated service
/// definition (ADR-0061 §3, #690): the plist key `X0XTemplateVersion` on
/// macOS and the unit `Environment=X0X_TEMPLATE_VERSION=` on systemd. A
/// version alone is NOT a support claim — it identifies the template
/// generation a deployment was created from so upgrade-time drift detection
/// (the loaded-policy readbacks) can tell a known template from a drifted
/// one. Bump when the template's semantics change and teach repair about
/// the migration.
pub(crate) const AUTOSTART_TEMPLATE_VERSION: u32 = 1;

/// Escape one argument for a plist `<string>` element: the five XML
/// predefined entities, so an install path or `--name` carrying `&`, `<`,
/// `>`, `'` or `"` renders as data, never as markup.
#[cfg(any(test, target_os = "macos"))]
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_autostart_value(value: &str) -> Result<()> {
    if value.chars().any(|c| c.is_control() && !matches!(c, '\t')) {
        anyhow::bail!("autostart arguments and paths must not contain control characters");
    }
    Ok(())
}

/// Render one argument for a systemd `ExecStart=` line per `man
/// systemd.service` COMMAND LINES: every argument is wrapped in double
/// quotes, with `"` and `\\` backslash-escaped inside; a literal `%` is
/// doubled (`%%`) because `%` introduces a specifier. Always quoting also
/// preserves apostrophes and a standalone semicolon as argument data.
#[cfg(any(test, target_os = "linux"))]
fn escape_systemd_exec_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    // Quote every argument. Besides preserving whitespace this keeps single
    // quotes and a standalone `;` as data rather than systemd command-line
    // syntax.
    out.push('"');
    for c in arg.chars() {
        match c {
            // % introduces a specifier (man systemd.service, SPECIFIERS);
            // a literal % is written %%.
            '%' => out.push_str("%%"),
            // $ introduces environment variable substitution ("${FOO}"
            // / "$FOO" — man systemd.service, COMMAND LINES); a literal $
            // is written $$.
            '$' => out.push_str("$$"),
            // \\ is the escape character itself (man systemd.service,
            // COMMAND LINES): a literal backslash is written \\\\,
            // unconditionally — inside AND outside quotes — because an
            // unescaped backslash would consume the next character.
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render the ExecStart EXECUTABLE path: like [`escape_systemd_exec_arg`]
/// except a literal `$` stays RAW — systemd never environment-expands the
/// executable path (the execve target is the stored path verbatim), so
/// `$$`-doubling there would address a different file. `%%` still doubles
/// because the path does go through load-time `%`-specifier expansion.
#[cfg(any(test, target_os = "linux"))]
fn escape_systemd_exec_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('"');
    for c in path.chars() {
        match c {
            '%' => out.push_str("%%"),
            // Raw on purpose — see the doc comment above.
            '$' => out.push('$'),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(any(test, target_os = "linux"))]
fn render_systemd_unit(executable: &str, args: &[String]) -> Result<String> {
    validate_autostart_value(executable)?;
    for arg in args {
        validate_autostart_value(arg)?;
    }
    // `$`-bearing executables use systemd's `@` argv[0] override: the raw
    // path stays the execve target, while the `$$`-escaped copy becomes
    // argv[0] and spawn-collapses back to the literal path (without the
    // override, the implicit argv[0] copy of the path diverges for
    // `${FOO}`/`$$` paths and the readback cannot bind it). `$`-free
    // executables keep the plain form (byte-identical legacy output).
    let exec_start = if executable.contains('$') {
        std::iter::once(format!("@{}", escape_systemd_exec_path(executable)))
            .chain(std::iter::once(escape_systemd_exec_arg(executable)))
            .chain(args.iter().map(|arg| escape_systemd_exec_arg(arg)))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        std::iter::once(escape_systemd_exec_path(executable))
            .chain(args.iter().map(|arg| escape_systemd_exec_arg(arg)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    Ok(format!(
        "[Unit]\nDescription=x0x Agent Daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec_start}\nEnvironment={env_key}={template_version}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        env_key = crate::upgrade::restart::SYSTEMD_TEMPLATE_ENV_KEY,
        template_version = AUTOSTART_TEMPLATE_VERSION,
    ))
}

#[cfg(any(test, target_os = "macos"))]
fn render_launchd_plist(executable: &str, args: &[String], log_path: &Path) -> Result<String> {
    validate_autostart_value(executable)?;
    for arg in args {
        validate_autostart_value(arg)?;
    }
    let log_path = log_path.to_string_lossy();
    validate_autostart_value(&log_path)?;
    let prog_args = std::iter::once(executable)
        .chain(args.iter().map(String::as_str))
        .map(|arg| format!("        <string>{}</string>\n", xml_escape(arg)))
        .collect::<String>();
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>com.saorsalabs.x0xd</string>\n    <key>ProgramArguments</key>\n    <array>\n{prog_args}    </array>\n    <key>EnvironmentVariables</key>\n    <dict>\n        <key>{supervised_key}</key>\n        <string>1</string>\n    </dict>\n    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n    <key>{template_key}</key>\n    <integer>{template_version}</integer>\n    <key>StandardOutPath</key>\n    <string>{log}</string>\n    <key>StandardErrorPath</key>\n    <string>{log}</string>\n</dict>\n</plist>\n",
        supervised_key = crate::upgrade::restart::SUPERVISED_ENV_VAR,
        template_key = crate::upgrade::restart::LAUNCHD_TEMPLATE_VERSION_KEY,
        template_version = AUTOSTART_TEMPLATE_VERSION,
        log = xml_escape(&log_path),
    ))
}

/// The versioned Windows supervision wrapper template (#621, ADR-0061 §3):
/// a PowerShell script that restarts x0xd after exit 100 (the supervised
/// upgrade request) and propagates every other exit status. The daemon
/// verifies the generated script at upgrade time through
/// [`crate::upgrade::restart::readback_windows_wrapper_script`], so the
/// template's marker lines must stay exactly what that readback parses.
#[cfg(any(test, target_os = "windows"))]
const WINDOWS_WRAPPER_TEMPLATE: &str = include_str!("windows-wrapper.ps1");

/// File name of the generated wrapper inside the config directory. Only the
/// Windows autostart/remove drivers use it; tests render the template
/// directly.
#[cfg(any(test, target_os = "windows"))]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WINDOWS_WRAPPER_FILE_NAME: &str = "x0xd-wrapper.ps1";

/// Scheduled-task name the Windows autostart registers.
#[cfg(target_os = "windows")]
const WINDOWS_AUTOSTART_TASK: &str = "x0xd";

/// Escape one value for a PowerShell single-quoted string: a literal
/// apostrophe is doubled (`''`) — inside single quotes PowerShell expands
/// nothing else.
#[cfg(any(test, target_os = "windows"))]
fn ps_single_quote_escape(s: &str) -> String {
    s.replace('\'', "''")
}

/// Render the Windows supervision wrapper script for one instance (#621):
/// the tested wrapper version, the restart-on-exit-100 policy, and the
/// executable/arguments binding the upgrade-time readback verifies. ASCII
/// only — Windows PowerShell 5.1 reads a no-BOM file as ANSI, so a non-ASCII
/// path or `--name` would corrupt the binding silently.
#[cfg(any(test, target_os = "windows"))]
fn render_windows_wrapper(executable: &str, args: &[String]) -> Result<String> {
    validate_autostart_value(executable)?;
    for arg in args {
        validate_autostart_value(arg)?;
    }
    if !executable.is_ascii() || args.iter().any(|arg| !arg.is_ascii()) {
        anyhow::bail!(
            "autostart on Windows needs ASCII paths and arguments (Windows PowerShell 5.1 \
             reads a no-BOM script as ANSI)"
        );
    }
    let arguments = args
        .iter()
        .map(|arg| format!("'{}'", ps_single_quote_escape(arg)))
        .collect::<Vec<_>>()
        .join(",");
    Ok(WINDOWS_WRAPPER_TEMPLATE
        .replace(
            "__X0X_WRAPPER_VERSION__",
            &crate::upgrade::restart::WINDOWS_WRAPPER_TESTED_VERSION.to_string(),
        )
        .replace("__X0X_EXECUTABLE__", &ps_single_quote_escape(executable))
        .replace("__X0X_ARGUMENTS__", &arguments))
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
        // #690: correctly escaped ExecStart — every argument rendered
        // through the systemd command-line escaper so a name with spaces or
        // quotes stays ONE argument — plus the template version stamp in
        // the unit Environment where the loaded-policy readback observes it.
        let unit_dir = dirs::config_dir()
            .context("cannot determine config directory")?
            .join("systemd/user");
        std::fs::create_dir_all(&unit_dir)?;

        let unit_path = unit_dir.join("x0xd.service");
        let unit = render_systemd_unit(&x0xd, &args)?;
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
        // #690: XML-escape every rendered argument and stamp the template
        // version so upgrade-time drift detection identifies the generation.
        let mut args = Vec::new();
        if let Some(n) = name {
            args.extend(["--name".to_string(), n.to_string()]);
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

        // The pure renderer used by tests is the only template path.
        let plist = render_launchd_plist(&x0xd, &args, &log_path)?;
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

    #[cfg(target_os = "windows")]
    {
        let mut args = Vec::new();
        if let Some(n) = name {
            args.push("--name".to_string());
            args.push(n.to_string());
        }
        // #621 / ADR-0061 §3: the supported Windows deployment is this
        // versioned wrapper (restart after exit 100 only), which the daemon
        // verifies at upgrade time before accepting a supervised exit.
        let config_dir = dirs::config_dir()
            .context("cannot determine config directory")?
            .join("x0x");
        std::fs::create_dir_all(&config_dir)?;
        let wrapper_path = config_dir.join(WINDOWS_WRAPPER_FILE_NAME);
        let wrapper = render_windows_wrapper(&x0xd, &args)?;
        std::fs::write(&wrapper_path, &wrapper)?;

        // Verify through the same readback the upgrade path uses, never
        // trusting the write.
        let written = std::fs::read_to_string(&wrapper_path)
            .with_context(|| format!("failed to read back {}", wrapper_path.display()))?;
        let mut wrapper_argv = vec![x0xd.to_string()];
        wrapper_argv.extend(args.iter().cloned());
        if !matches!(
            crate::upgrade::restart::readback_windows_wrapper_script(&written, &wrapper_argv),
            crate::upgrade::restart::WindowsWrapperReadback::Verified { .. }
        ) {
            anyhow::bail!(
                "the generated wrapper {} did not verify against the upgrade-time \
                 readback; nothing was registered",
                wrapper_path.display()
            );
        }

        // Register a per-user logon task (best effort — no admin needed).
        // The /TR value is passed as one argv element, so the quotes around
        // the script path are plain `"` characters: std::process::Command
        // performs the Windows argument escaping itself, and a literal `\`
        // would survive into the stored task and break PowerShell's -File
        // parsing (review round 1 of #1612). -WindowStyle Hidden keeps the
        // logon task from leaving a console window open (a brief flash can
        // still appear; verified behaviour is VM-acceptance work).
        let task_run = format!(
            "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \
             \"{}\"",
            wrapper_path.display()
        );
        let registered = std::process::Command::new("schtasks")
            .args(["/Create", "/TN", WINDOWS_AUTOSTART_TASK, "/SC", "ONLOGON"])
            .arg("/TR")
            .arg(&task_run)
            .arg("/F")
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if registered {
            println!("Autostart enabled (Windows wrapper + logon task)");
            println!("  Verify: schtasks /Query /TN {WINDOWS_AUTOSTART_TASK} /V /FO LIST");
        } else {
            println!("Autostart wrapper written, but the logon task could not be registered.");
            println!("  Register it manually, or run the wrapper from your own service manager:");
            println!(
                "    schtasks /Create /TN {WINDOWS_AUTOSTART_TASK} /SC ONLOGON /TR \"{task_run}\""
            );
        }
        println!("  Wrapper: {}", wrapper_path.display());
        println!("  Policy:  restart after exit 100 (upgrade); every other exit stops.");
        println!("  Remove:  x0x autostart --remove");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
// Only the macOS `--repair` driver calls these; on other platforms they exist
// for the unit tests, which is where the decision table is pinned.
#[cfg(any(test, target_os = "macos"))]
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
// Only the macOS `--repair` driver calls these; on other platforms they exist
// for the unit tests, which is where the decision table is pinned.
#[cfg(any(test, target_os = "macos"))]
fn program_basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Classify one launchd job (a plist converted to JSON) for `--repair`.
///
/// Kept free of `launchctl`/`plutil` so the decision table is testable on any
/// platform; the macOS driver below only supplies the parsed job and applies
/// the verdict.
// Only the macOS `--repair` driver calls these; on other platforms they exist
// for the unit tests, which is where the decision table is pinned.
#[cfg(any(test, target_os = "macos"))]
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
        #[cfg(target_os = "windows")]
        println!(
            "On Windows, `x0x autostart` (re)generates the supervised wrapper — run it \
             instead of --repair."
        );
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

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("schtasks")
            .args(["/Delete", "/TN", WINDOWS_AUTOSTART_TASK, "/F"])
            .status();
        let wrapper_path = dirs::config_dir()
            .context("cannot determine config directory")?
            .join("x0x")
            .join(WINDOWS_WRAPPER_FILE_NAME);
        if wrapper_path.exists() {
            std::fs::remove_file(&wrapper_path)?;
        }
        println!("Autostart removed (Windows wrapper)");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
/// Candidate file names for the daemon binary: `x0xd.exe` on Windows
/// (releases ship `x0xd.exe`), bare `x0xd` everywhere else.
fn x0xd_binary_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["x0xd.exe", "x0xd"]
    } else {
        &["x0xd"]
    }
}

fn find_x0xd() -> Result<std::path::PathBuf> {
    // Same directory as x0x binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in x0xd_binary_names() {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    // Search PATH.
    for name in x0xd_binary_names() {
        if let Ok(path) = which::which(name) {
            return Ok(path);
        }
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
            "ok": true,
            "agent_id": "abc123",
            "machine_id": "def456",
            "peers": 5,
            "status": "healthy",
            "stores": [],
            "update_available": false,
            "current_version": "0.1.0"
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = doctor(&client).await;
        assert!(result.is_ok(), "doctor should succeed: {:?}", result);
    }

    /// Parse exactly one JSON value from captured doctor stdout and assert
    /// the exit Result matches `report.ok`.
    fn assert_doctor_json_stdout(report: &DoctorReport, expect_ok: bool) -> serde_json::Value {
        let mut stdout = Vec::new();
        let result = finish_doctor_write(crate::cli::OutputFormat::Json, report, &mut stdout);
        let text = String::from_utf8(stdout).expect("doctor stdout utf-8");
        let parsed: serde_json::Value = serde_json::from_str(text.trim())
            .expect("doctor stdout must be exactly one JSON value");
        assert_eq!(parsed["ok"], expect_ok, "summary ok mismatch: {parsed}");
        if expect_ok {
            assert!(result.is_ok(), "doctor must exit zero when ok: {result:?}");
        } else {
            assert!(
                result.is_err(),
                "doctor must exit non-zero when a check fails: {result:?}"
            );
        }
        parsed
    }

    /// Done-when for #1382: captured JSON stdout + non-zero exit on FAIL.
    /// Path-aware: /agent lacks identity so key_health fails by design.
    #[tokio::test]
    async fn doctor_json_nonzero_exit_on_failed_check() {
        let mock_resp = serde_json::json!({
            "ok": true,
            "peers": 2,
            "status": "healthy",
            "stores": [],
            "update_available": false,
            "current_version": "0.1.0"
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

        let report = collect_doctor_report(&client).await;
        let parsed = assert_doctor_json_stdout(&report, false);

        assert_eq!(
            parsed["key_health"]["status"], "fail",
            "key_health must FAIL when agent_id/machine_id are missing: {parsed}"
        );
        assert_eq!(parsed["connectivity"]["status"], "ok");
        assert_eq!(parsed["store_integrity"]["status"], "ok");
        assert_eq!(parsed["upgrade"]["status"], "ok");
    }

    #[tokio::test]
    async fn doctor_json_nonzero_exit_when_daemon_unreachable() {
        // Bind then drop so the address refuses connections immediately
        // (avoids the client's 30 s connect timeout on a black-hole port).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let client = DaemonClient::new(
            None,
            Some(&format!("http://{addr}")),
            crate::cli::OutputFormat::Json,
        )
        .unwrap();
        let report = collect_doctor_report(&client).await;
        let parsed = assert_doctor_json_stdout(&report, false);
        assert_eq!(parsed["connectivity"]["status"], "fail");
    }

    /// Named instance with no api.port: emit four-check JSON and exit non-zero.
    #[test]
    fn doctor_json_named_instance_missing_port_emits_report() {
        let err = match DaemonClient::new(
            Some("absent-instance-doctor-1382-xyz"),
            None,
            crate::cli::OutputFormat::Json,
        ) {
            Ok(_) => panic!("named instance without api.port must fail discovery"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("absent-instance-doctor-1382-xyz"),
            "discovery error should name the instance: {msg}"
        );

        let mut stdout = Vec::new();
        let result = {
            let report = unreachable_doctor_report(format!("daemon not reachable: {err:#}"));
            finish_doctor_write(crate::cli::OutputFormat::Json, &report, &mut stdout)
        };
        let text = String::from_utf8(stdout).expect("utf-8");
        let parsed: serde_json::Value =
            serde_json::from_str(text.trim()).expect("exactly one JSON value on stdout");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["connectivity"]["status"], "fail");
        assert_eq!(parsed["key_health"]["status"], "fail");
        assert_eq!(parsed["store_integrity"]["status"], "fail");
        assert_eq!(parsed["upgrade"]["status"], "fail");
        assert!(result.is_err(), "must exit non-zero: {result:?}");
    }

    /// First health probe must use the short (2 s) timeout, not the 30 s client default.
    #[tokio::test]
    async fn doctor_connectivity_uses_short_health_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Accept and hold without answering HTTP — wedged daemon shape.
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::time::sleep(Duration::from_secs(60)).await;
                drop(socket);
            }
        });

        let client = DaemonClient::new(
            None,
            Some(&format!("http://{addr}")),
            crate::cli::OutputFormat::Json,
        )
        .unwrap();
        let started = std::time::Instant::now();
        let report = collect_doctor_report(&client).await;
        let elapsed = started.elapsed();

        assert_eq!(report.connectivity.status, DoctorCheckStatus::Fail);
        assert!(
            elapsed < Duration::from_secs(8),
            "health probe must not wait the 30s client timeout; took {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(500),
            "health probe should wait for the short timeout; took {elapsed:?}"
        );
        let parsed = assert_doctor_json_stdout(&report, false);
        assert_eq!(parsed["connectivity"]["status"], "fail");
    }

    /// Failed upgrade *lookup* is warn (exit zero); update_available stays ok.
    #[tokio::test]
    async fn doctor_upgrade_lookup_failure_is_warn() {
        let mock_resp = serde_json::json!({
            "ok": false,
            "error": "upgrade check unavailable",
            "agent_id": "abc123",
            "machine_id": "def456",
            "peers": 1,
            "status": "healthy",
            "stores": []
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let report = collect_doctor_report(&client).await;
        let parsed = assert_doctor_json_stdout(&report, true);
        assert_eq!(parsed["upgrade"]["status"], "warn");
        assert_eq!(parsed["connectivity"]["status"], "ok");
        assert_eq!(parsed["key_health"]["status"], "ok");
    }

    #[tokio::test]
    async fn doctor_warn_only_exits_zero() {
        let mock_resp = serde_json::json!({
            "ok": true,
            "agent_id": "abc123",
            "machine_id": "def456",
            "peers": 0,
            "status": "degraded",
            "degraded_reason": "no peers",
            "stores": [],
            "update_available": false,
            "current_version": "0.1.0"
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let report = collect_doctor_report(&client).await;
        let parsed = assert_doctor_json_stdout(&report, true);
        assert_eq!(parsed["connectivity"]["status"], "warn");
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
    // ===================================================================
    // #690: versioned template rendering and argument escaping
    // ===================================================================

    #[test]
    fn xml_escape_renders_all_five_entities() {
        assert_eq!(xml_escape("&<>\"'"), "&amp;&lt;&gt;&quot;&apos;");
        assert_eq!(xml_escape("/plain/path"), "/plain/path");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn systemd_exec_arg_escapes_specifier_dollar_and_backslash() {
        // Plain arguments receive only the always-present outer quotes.
        assert_eq!(escape_systemd_exec_arg("--name"), "\"--name\"");
        assert_eq!(
            escape_systemd_exec_arg("/opt/x0x/x0xd"),
            "\"/opt/x0x/x0xd\""
        );
        // Whitespace remains one argument inside the outer quotes.
        assert_eq!(escape_systemd_exec_arg("a b"), "\"a b\"");
        // % → %% (specifier escape, man systemd.service SPECIFIERS).
        assert_eq!(escape_systemd_exec_arg("100%"), "\"100%%\"");
        // $ → $$ (variable substitution escape, man systemd.service
        // COMMAND LINES).
        assert_eq!(escape_systemd_exec_arg("$FOO"), "\"$$FOO\"");
        assert_eq!(escape_systemd_exec_arg("${FOO}"), "\"$${FOO}\"");
        // \ → \\ (escape character itself) — unconditionally, not just
        // inside quotes.
        assert_eq!(escape_systemd_exec_arg("C:\\path"), "\"C:\\\\path\"");
        assert_eq!(escape_systemd_exec_arg("\"quoted\""), "\"\\\"quoted\\\"\"");
        // Empty argument renders as quoted empty string (systemd cannot
        // express a bare empty token otherwise).
        assert_eq!(escape_systemd_exec_arg(""), "\"\"");
        assert_eq!(escape_systemd_exec_arg("'alice'"), "\"'alice'\"");
        assert_eq!(escape_systemd_exec_arg(";"), "\";\"");
    }

    /// The plist template with a name containing XML-special characters
    /// must render as parseable XML with the value intact as data.
    #[cfg(target_os = "macos")]
    #[test]
    fn plist_renders_escaped_and_versioned() {
        let dir = tempfile::tempdir().expect("fixture dir");
        let log = dir.path().join("logs & output/x0xd.log");
        let args = vec!["--name".to_string(), "a & <b> \"c\" 'd'".to_string()];
        let rendered = render_launchd_plist("/Applications/x0x & tools/x0xd", &args, &log)
            .expect("render production plist");
        let path = dir.path().join("fixture.plist");
        std::fs::write(&path, rendered).expect("write fixture plist");
        let parsed = read_plist_as_json(&path)
            .expect("run plutil")
            .expect("actual generated plist parses");
        assert_eq!(
            parsed["ProgramArguments"],
            serde_json::json!([
                "/Applications/x0x & tools/x0xd",
                "--name",
                "a & <b> \"c\" 'd'"
            ])
        );
        assert_eq!(parsed["EnvironmentVariables"]["X0X_SUPERVISED"], "1");
        assert_eq!(parsed["X0XTemplateVersion"], AUTOSTART_TEMPLATE_VERSION);
        assert_eq!(parsed["StandardOutPath"], log.to_string_lossy().as_ref());
        assert_eq!(parsed["StandardErrorPath"], log.to_string_lossy().as_ref());
    }

    /// The systemd template's ExecStart and Environment lines are
    /// well-formed for the escaping contract (verified on any platform —
    /// the template text is the same).
    #[test]
    fn systemd_template_renders_escaped_and_versioned() {
        let name = "a b&c%d$e\\f";
        let args = ["--name".to_string(), name.to_string()];
        let unit =
            render_systemd_unit("/opt/x0x tools/x0xd", &args).expect("render production unit");
        let exec = unit
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .expect("actual ExecStart line");
        assert_eq!(
            exec,
            "\"/opt/x0x tools/x0xd\" \"--name\" \"a b&c%%d$$e\\\\f\""
        );
        assert!(unit.lines().any(|line| {
            line == format!(
                "Environment={}={AUTOSTART_TEMPLATE_VERSION}",
                crate::upgrade::restart::SYSTEMD_TEMPLATE_ENV_KEY
            )
        }));
        assert!(unit.lines().any(|line| line == "Type=simple"));
        assert!(unit.lines().any(|line| line == "Restart=always"));
    }

    /// `$`-bearing executables render the proven `@` argv[0]-override form:
    /// raw path, `$$`-escaped argv[0] copy, then arguments. `$`-free
    /// executables keep the plain legacy form.
    #[test]
    fn systemd_template_renders_escaped_argv0_for_dollar_paths() {
        let unit = render_systemd_unit(
            "/opt/x0x$prod/x0xd",
            &["--name".to_string(), "$x".to_string()],
        )
        .expect("`$` executable path renders");
        let exec = unit
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .expect("actual ExecStart line");
        // Experiment-exact shape: `@` + raw path, `$$`-escaped argv[0]
        // copy, then normally-escaped arguments.
        assert_eq!(
            exec,
            "@\"/opt/x0x$prod/x0xd\" \"/opt/x0x$$prod/x0xd\" \"--name\" \"$$x\""
        );
        // `${FOO}` and `$$` shapes take the same form (braced/double-dollar
        // receipt cases).
        let braced =
            render_systemd_unit("/opt/p${FOO}/x0xd", &[]).expect("braced executable path renders");
        assert!(braced
            .lines()
            .any(|l| l == "ExecStart=@\"/opt/p${FOO}/x0xd\" \"/opt/p$${FOO}/x0xd\""));
        let doubled = render_systemd_unit("/opt/p$$literal/x0xd", &[])
            .expect("double-dollar executable path renders");
        assert!(doubled
            .lines()
            .any(|l| l == "ExecStart=@\"/opt/p$$literal/x0xd\" \"/opt/p$$$$literal/x0xd\""));
        // `%`-only executables keep the plain form: `%%` for the load-time
        // expander, no `@`, no duplicate (`percent-path` receipt).
        let pct =
            render_systemd_unit("/opt/x0x%prod/x0xd", &[]).expect("`%` executable path renders");
        assert!(pct
            .lines()
            .any(|l| l == "ExecStart=\"/opt/x0x%%prod/x0xd\""));
    }

    #[test]
    fn autostart_templates_reject_raw_controls() {
        assert!(render_systemd_unit("/opt/x0xd", &["--name\nforged".to_string()]).is_err());
        assert!(render_launchd_plist(
            "/opt/x0xd",
            &["--name\rforged".to_string()],
            Path::new("/tmp/x0xd.log")
        )
        .is_err());
    }

    // ===================================================================
    // #621: Windows supervision wrapper template (ADR-0061 §3)
    // ===================================================================

    /// Render the wrapper for one instance and build the argv a daemon
    /// started by that wrapper would report.
    fn windows_wrapper_fixture(executable: &str, args: &[String]) -> (String, Vec<String>) {
        let script = render_windows_wrapper(executable, args).expect("render production wrapper");
        let mut argv = vec![executable.to_string()];
        argv.extend(args.iter().cloned());
        (script, argv)
    }

    #[test]
    fn windows_wrapper_renders_versioned_and_readback_verified() {
        let (script, argv) = windows_wrapper_fixture(
            "C:\\Program Files\\x0x\\x0xd.exe",
            &["--name".to_string(), "alice".to_string()],
        );
        assert!(script.lines().any(|line| {
            line == format!(
                "$x0xWrapperVersion = {}",
                crate::upgrade::restart::WINDOWS_WRAPPER_TESTED_VERSION
            )
        }));
        assert!(script.lines().any(|l| l == "$x0xRestartOnExit100 = $true"));
        // The cross-pin that keeps the renderer and the verifier honest: the
        // generated template is exactly what the upgrade-time readback
        // accepts for the instance it was rendered for.
        assert_eq!(
            crate::upgrade::restart::readback_windows_wrapper_script(&script, &argv),
            crate::upgrade::restart::WindowsWrapperReadback::Verified {
                wrapper_version: crate::upgrade::restart::WINDOWS_WRAPPER_TESTED_VERSION
            }
        );
    }

    #[test]
    fn windows_wrapper_escapes_and_still_verifies() {
        // An apostrophe doubles inside the single-quoted string; a comma
        // inside quotes is data, not a separator.
        let (script, argv) = windows_wrapper_fixture(
            "C:\\Tools\\x0xd.exe",
            &["--name".to_string(), "a'b,c d".to_string()],
        );
        assert!(script.contains("'--name','a''b,c d'"));
        assert_eq!(
            crate::upgrade::restart::readback_windows_wrapper_script(&script, &argv),
            crate::upgrade::restart::WindowsWrapperReadback::Verified {
                wrapper_version: crate::upgrade::restart::WINDOWS_WRAPPER_TESTED_VERSION
            }
        );
        // Empty argument list renders the empty array literal and verifies.
        let (empty, argv) = windows_wrapper_fixture("C:\\Tools\\x0xd.exe", &[]);
        assert!(empty.contains("$x0xArguments = @()"));
        assert!(matches!(
            crate::upgrade::restart::readback_windows_wrapper_script(&empty, &argv),
            crate::upgrade::restart::WindowsWrapperReadback::Verified { .. }
        ));
    }

    #[test]
    fn windows_wrapper_rejects_raw_controls_and_non_ascii() {
        // Controls would forge marker lines; non-ASCII would be corrupted by
        // Windows PowerShell 5.1's ANSI read of a no-BOM script.
        assert!(render_windows_wrapper("C:\\x0xd.exe", &["--name\nforged".to_string()]).is_err());
        assert!(render_windows_wrapper("C:\\J\u{fc}rgen\\x0xd.exe", &[]).is_err());
        assert!(render_windows_wrapper(
            "C:\\x0xd.exe",
            &["--name".to_string(), "\u{fc}".to_string()]
        )
        .is_err());
    }
}
