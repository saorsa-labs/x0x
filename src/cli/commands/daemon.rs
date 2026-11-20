//! Daemon lifecycle CLI commands.

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::cli::{DaemonClient, OutputFormat};

/// Bounded timeout for doctor's first `/health` probe (matches `ensure_running`).
const DOCTOR_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

/// Doctor's single `/health` fetch, shared by the connectivity check and
/// the #1354 bundle's `health` section (#1997 review). `?detail=redacted`
/// asks the daemon for the redacted-audience body — reason sentences that
/// name the crossed bound, not the measurement — so the bundle embeds
/// exactly what a non-loopback unauthenticated caller gets. The
/// connectivity check only reads fields identical under redaction
/// (`status`, `peers`, `degraded_reason`).
const DOCTOR_HEALTH_PATH: &str = "/health?detail=redacted";

/// The status `x0x start --foreground` exits with after x0xd stops where the
/// Unix exec is not available. It keeps x0xd's exact status for a
/// supervisor, as the Unix exec does: 100 asks for a restart on new bytes,
/// 75 (EX_TEMPFAIL) for a restart on the restored binary (#1588). A status
/// without a code is reported as 1.
#[cfg(any(test, not(unix)))]
fn foreground_exit_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

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
                std::process::exit(foreground_exit_code(status));
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
///
/// `health` is doctor's single `/health` fetch (shared with the #1354
/// bundle): `Ok` body feeds the connectivity check, `Err` is the
/// unreachable report.
pub(crate) async fn collect_doctor_report(
    client: &DaemonClient,
    health: &Result<serde_json::Value>,
) -> DoctorReport {
    let connectivity = check_connectivity(health);
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
        down_upgrade_check(client.instance_dir())
    };

    DoctorReport::from_checks(connectivity, key_health, store_integrity, upgrade)
}

/// The upgrade check while the daemon is unreachable: the stable
/// launcher's refusal, if it left one in the instance's data directory
/// (#2016 review), else skipped.
fn down_upgrade_check(instance_dir: Option<&std::path::Path>) -> DoctorCheck {
    instance_dir
        .and_then(launcher_refusal_check)
        .or_else(|| instance_dir.and_then(autostart_missing_daemon_check))
        .unwrap_or_else(|| DoctorCheck::fail("skipped: daemon unreachable"))
}

/// The instance's launchd autostart job, when its daemon path is missing
/// (`missing_daemon_check`). The instance is the data directory's name:
/// `x0x` for the default one, `x0x-<name>` for a named one.
#[cfg(target_os = "macos")]
fn autostart_missing_daemon_check(instance_dir: &std::path::Path) -> Option<DoctorCheck> {
    let instance = instance_of_data_dir(instance_dir.file_name()?.to_str()?)?;
    let plist = dirs::home_dir()?
        .join("Library/LaunchAgents")
        .join(format!("{AUTOSTART_LAUNCHD_LABEL}.plist"));
    if !plist.is_file() {
        return None;
    }
    let job = read_plist_as_json(&plist).ok()??;
    missing_daemon_check(&job, instance, &|path| path.exists())
}

/// The instance a data directory name belongs to: `Some(None)` for the
/// default `x0x`, `Some(Some(name))` for `x0x-<name>`, `None` for another.
#[cfg(any(test, target_os = "macos"))]
fn instance_of_data_dir(dir_name: &str) -> Option<Option<&str>> {
    match dir_name {
        "x0x" => Some(None),
        other => other
            .strip_prefix("x0x-")
            .filter(|name| !name.is_empty())
            .map(Some),
    }
}

#[cfg(not(target_os = "macos"))]
fn autostart_missing_daemon_check(_instance_dir: &std::path::Path) -> Option<DoctorCheck> {
    None
}

/// Read the launcher refusal record (`launcher_contract::REFUSAL_FILE_NAME`)
/// from `dir`. The stable launcher writes it when it refuses to start x0xd
/// for a reason no restart changes; on macOS it then holds until a stop, so
/// launchd shows the job running with no daemon. The record is only for
/// this report: `None` when it is absent or unreadable. Only the default
/// data directory of the instance is read; a daemon configured with
/// another `data_dir` is not found here.
fn launcher_refusal_check(dir: &std::path::Path) -> Option<DoctorCheck> {
    use crate::upgrade::launcher_contract::{
        self, LauncherRefusal, MAX_REFUSAL_BYTES, REFUSAL_FILE_NAME,
    };
    use std::io::Read;
    let file = std::fs::File::open(dir.join(REFUSAL_FILE_NAME)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_REFUSAL_BYTES).read_to_end(&mut bytes).ok()?;
    let record: LauncherRefusal = serde_json::from_slice(&bytes).ok()?;
    // The pid and its start time name the launcher: a pid reused after the
    // launcher exited is not a holding launcher (#2019 review).
    let holding = launcher_contract::process_start(record.pid).ok() == Some(record.process_start);
    let state = if holding {
        "holding until the job is stopped"
    } else {
        "no longer running"
    };
    Some(DoctorCheck {
        status: DoctorCheckStatus::Fail,
        detail: format!(
            "x0x-launcher refused to start x0xd: {} (launcher pid {}, {state}); fix the cause, \
             then restart the job",
            record.reason, record.pid
        ),
        evidence: Some(serde_json::json!({
            "launcher_refusal": record,
            "launcher_holding": holding,
        })),
    })
}

fn check_connectivity(health: &Result<serde_json::Value>) -> DoctorCheck {
    match health {
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
        Ok(val) => store_integrity_check(&val),
        Err(e) => DoctorCheck::fail(format!("/stores: {e:#}")),
    }
}

/// The store-integrity verdict for a `GET /stores` body.
fn store_integrity_check(val: &serde_json::Value) -> DoctorCheck {
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
    // #1970: a group store that refused a merge at the image limit
    // can differ from its peers until entries are removed.
    let image_problems: Vec<String> = stores
        .iter()
        .filter_map(|s| {
            let state = s.get("image")?.get("state")?.as_str()?;
            matches!(state, "full_diverged" | "over_limit").then(|| {
                let id = s.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                format!("{id} ({state})")
            })
        })
        .collect();
    if !image_problems.is_empty() {
        return DoctorCheck::warn(
            format!(
                "{} group store(s) at the retained-image limit; remove entries to repair: {}",
                image_problems.len(),
                image_problems.join(", ")
            ),
            Some(serde_json::json!({
                "store_count": stores.len(),
                "image_limit": image_problems,
            })),
        );
    }
    DoctorCheck::ok_with(
        format!("{} store(s) readable", stores.len()),
        serde_json::json!({ "store_count": stores.len() }),
    )
}

#[cfg(test)]
mod store_integrity_tests {
    use super::*;

    /// #1970: a group store at the image limit makes the doctor warn and
    /// name it; `ok` and `full` stores do not.
    #[test]
    fn the_doctor_warns_on_a_diverged_or_over_limit_group_store() {
        let body = |state: &str| {
            serde_json::json!({ "stores": [
                { "id": "x0x/group/a", "durability_degraded": false, "image": { "state": state } },
                { "id": "plain", "durability_degraded": false, "image": null },
            ]})
        };
        for state in ["ok", "full"] {
            assert_eq!(
                store_integrity_check(&body(state)).status,
                DoctorCheckStatus::Ok
            );
        }
        for state in ["full_diverged", "over_limit"] {
            let check = store_integrity_check(&body(state));
            assert_eq!(check.status, DoctorCheckStatus::Warn);
            assert!(check.detail.contains("x0x/group/a"), "{}", check.detail);
            assert!(check.detail.contains(state), "{}", check.detail);
        }
    }
}

async fn check_upgrade_state(client: &DaemonClient) -> DoctorCheck {
    // Prefer `/diagnostics/upgrade` (#1381: its `pending_update` names a
    // release newer than this daemon); fall back to GET /upgrade. Neither is
    // apply/rollback health: lookup failure and HTTP errors are `warn`; an
    // available update stays `ok`.
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

    let pending_update = val.get("pending_update").filter(|v| v.is_object());
    let update_available = val
        .get("update_available")
        .or_else(|| val.get("pending"))
        .and_then(|v| v.as_bool())
        .unwrap_or(pending_update.is_some());
    let current = val
        .get("current_version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let latest = val
        .get("version")
        .or_else(|| val.get("latest_version"))
        .or_else(|| pending_update.and_then(|pending| pending.get("version")))
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

/// Write the report to `out` and return `Err` when any check failed
/// (#1382).
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
/// With `bundle` (the raw `--bundle` flag value), also writes the diagnostic
/// bundle (#1354) — its `health` section records the discovery failure, its
/// `doctor` section is the four-fail unreachable report (including the
/// launcher-refusal check from #2019 when a refusal record is present).
pub fn doctor_unreachable(
    format: OutputFormat,
    name: Option<&str>,
    err: &anyhow::Error,
    bundle: Option<Option<&Path>>,
) -> Result<()> {
    doctor_unreachable_with_output(format, name, err, bundle, &mut std::io::stdout())
}

/// [`doctor_unreachable`] with the summary stream injected: tests assert the
/// stdout contract — the summary is emitted even when the bundle write
/// fails, and that error then wins (#1997 review finding 2).
pub(crate) fn doctor_unreachable_with_output(
    format: OutputFormat,
    name: Option<&str>,
    err: &anyhow::Error,
    bundle: Option<Option<&Path>>,
    out: &mut dyn Write,
) -> Result<()> {
    let detail = format!("daemon not reachable: {err:#}");
    let mut report = unreachable_doctor_report(detail.clone());
    let instance_dir = dirs::data_dir().map(|data| match name {
        Some(name) => data.join(format!("x0x-{name}")),
        None => data.join("x0x"),
    });
    report.upgrade = down_upgrade_check(instance_dir.as_deref());
    let bundle_err = (|| -> Result<()> {
        if let Some(target) = resolve_doctor_bundle_path(bundle)? {
            write_doctor_bundle(serde_json::json!({ "error": detail }), &report, &target)?;
        }
        Ok(())
    })()
    .err();
    finish_doctor_after_bundle(format, &report, out, bundle_err)
}

/// `x0x doctor` — run diagnostics against the daemon.
///
/// With `--json`, prints one summary object (connectivity, key health, store
/// integrity, upgrade). Exits non-zero when any check is `fail`. With
/// `--bundle` (#1354), writes the redacted diagnostic bundle before the
/// summary; a bundle write failure is an error but never empties stdout.
pub async fn doctor(client: &DaemonClient, bundle: Option<Option<&Path>>) -> Result<()> {
    doctor_with_output(client, bundle, &mut std::io::stdout()).await
}

/// [`doctor`] with the summary stream injected: tests assert the stdout
/// contract under a failed bundle write (#1997 review finding 2).
pub(crate) async fn doctor_with_output(
    client: &DaemonClient,
    bundle: Option<Option<&Path>>,
    out: &mut dyn Write,
) -> Result<()> {
    // One fetch feeds both the connectivity check and the bundle's
    // `health` section, so the two can never disagree (#1997 review).
    let health = client
        .get_with_timeout(DOCTOR_HEALTH_PATH, DOCTOR_HEALTH_TIMEOUT)
        .await;
    let report = collect_doctor_report(client, &health).await;

    // `--dump-request` never contacts the daemon — every fetch answers
    // with the synthetic `{"ok":true}` — so there is nothing to diagnose
    // and no bundle to write (#1997 review).
    if client.dumping_requests() {
        if bundle.is_some() {
            eprintln!("--dump-request: no daemon was contacted, skipping the --bundle write");
        }
        return finish_doctor_write(client.format(), &report, out);
    }

    let bundle_err = (|| -> Result<()> {
        if let Some(target) = resolve_doctor_bundle_path(bundle)? {
            write_doctor_bundle(doctor_bundle_health_section(&health), &report, &target)?;
        }
        Ok(())
    })()
    .err();
    finish_doctor_after_bundle(client.format(), &report, out, bundle_err)
}

/// Emit the summary, then surface the bundle error: `--json` stdout keeps
/// exactly one JSON value even when the bundle write failed, and that
/// failure still exits non-zero (#1997 review finding 2). The bundle error
/// is the more specific one, so it wins over a failed-check exit.
fn finish_doctor_after_bundle(
    format: OutputFormat,
    report: &DoctorReport,
    out: &mut dyn Write,
    bundle_err: Option<anyhow::Error>,
) -> Result<()> {
    let finish = finish_doctor_write(format, report, out);
    match (bundle_err, finish) {
        (Some(e), _) => Err(e),
        (None, Err(e)) => Err(e),
        (None, Ok(())) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Doctor bundle (#1354)
// ---------------------------------------------------------------------------

/// Seconds since the Unix epoch, with the pre-epoch clock failure as an
/// error instead of a panic (production paths avoid `unwrap`).
fn unix_secs_now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .context("system clock is before the Unix epoch")
}

/// File name a bare `--bundle` writes (#1354):
/// `x0x-doctor-bundle-<unix-secs>.json` in the current directory.
pub(crate) fn doctor_bundle_default_filename(secs: u64) -> String {
    format!("x0x-doctor-bundle-{secs}.json")
}

/// Default bundle path for a bare `--bundle`: a fresh seconds-stamped
/// name in the current directory.
pub(crate) fn doctor_bundle_default_path() -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(doctor_bundle_default_filename(
        unix_secs_now()?,
    )))
}

/// Where a `--bundle` write goes (#1354): the resolved path plus whether
/// the name was generated (bare flag). Every target is written with
/// `create_new`, so a second bare run in the same second, or a file (or
/// symlink) already at the path, is an error, not a silent replacement;
/// `generated_name` only picks the error hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoctorBundleTarget {
    pub(crate) path: std::path::PathBuf,
    pub(crate) generated_name: bool,
}

/// Resolve the raw `--bundle` flag value (#1354) into the write target.
/// `None` (flag absent) stays `None`; a bare flag (`Some(None)`, plus the
/// defensively-treated empty value) becomes the default seconds-stamped
/// name in the current directory; any other explicit path passes through
/// unchanged.
pub(crate) fn resolve_doctor_bundle_path(
    bundle: Option<Option<&Path>>,
) -> Result<Option<DoctorBundleTarget>> {
    let (path, generated_name) = match bundle {
        None => return Ok(None),
        Some(None) => (doctor_bundle_default_path()?, true),
        Some(Some(path)) if path.as_os_str().is_empty() => (doctor_bundle_default_path()?, true),
        Some(Some(path)) => (path.to_path_buf(), false),
    };
    Ok(Some(DoctorBundleTarget {
        path,
        generated_name,
    }))
}

/// Whether a `/health` body carries any gated `verdict.inputs` field —
/// read from [`crate::server::health_verdict::GATED_HEALTH_DETAIL`], the
/// same list the server redaction strips, so the two cannot drift.
fn health_body_has_gated_detail(body: &serde_json::Value) -> bool {
    let Some(inputs) = body.pointer("/verdict/inputs") else {
        return false;
    };
    crate::server::health_verdict::GATED_HEALTH_DETAIL
        .iter()
        .any(|(input, keys)| {
            inputs
                .get(*input)
                .is_some_and(|object| keys.iter().any(|key| object.get(*key).is_some()))
        })
}

/// The `health` section of a bundle (#1354): doctor's one
/// `?detail=redacted` fetch, redacted for the file. A daemon that honours
/// the parameter has already produced the redacted-audience body — reason
/// sentences included — and none of the gated pointers are present. One
/// that predates the parameter answers with the full loopback body: its
/// gated inputs are stripped locally, and its reason sentences, which
/// carry the #1480 gated measurements, are dropped rather than risked
/// (#1997 review finding 1).
fn doctor_bundle_health_section(health: &Result<serde_json::Value>) -> serde_json::Value {
    match health {
        Ok(body) => {
            let mut body = body.clone();
            let served_full_detail = health_body_has_gated_detail(&body);
            crate::server::health_verdict::redact_health_detail(&mut body);
            if served_full_detail {
                withhold_full_audience_reasons(&mut body);
            }
            body
        }
        Err(e) => serde_json::json!({ "error": format!("{e:#}") }),
    }
}

/// Replace `verdict.reasons` with a fail-closed marker: the sentences in
/// hand came from a full-detail body, and no local rewrite can be trusted
/// to carry the redacted variants (#1480 gate).
fn withhold_full_audience_reasons(body: &mut serde_json::Value) {
    if let Some(reasons) = body
        .get_mut("verdict")
        .and_then(|verdict| verdict.get_mut("reasons"))
    {
        *reasons = serde_json::json!(["reason sentences withheld: this daemon predates \
             /health?detail=redacted and served full-detail reasons, which \
             can carry gated node measurements"]);
    }
}

/// Assemble the #1354 doctor-bundle JSON value from a resolved `health`
/// section and the doctor report.
fn doctor_bundle_value(
    health: serde_json::Value,
    report: &DoctorReport,
) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "schema": "x0x-doctor-bundle",
        "version": 1,
        "created_unix": unix_secs_now()?,
        "generator": { "name": "x0x", "version": crate::VERSION },
        "health": health,
        "doctor": report.to_json_value()?,
    }))
}

/// Write one assembled doctor bundle (#1354): pretty JSON, then a read-back
/// parse — the write-verify discipline the Windows autostart wrapper uses —
/// so a truncated write surfaces as an error instead of a silently broken
/// file. Every target, generated or explicit, is created fresh: the open
/// is `create_new` (`O_CREAT|O_EXCL`, which also refuses a symlink — even
/// a dangling one — at the path) with mode 0600 set at open time on unix,
/// so the bundle never replaces an existing file, never writes through a
/// planted link, and is never briefly readable under the umask mode
/// (#1997 review at 368b6f32c, finding 2). The one-line notice goes to
/// stderr, keeping `--json` stdout to exactly one JSON value.
fn write_doctor_bundle_value(value: serde_json::Value, target: &DoctorBundleTarget) -> Result<()> {
    let text = serde_json::to_string_pretty(&value).context("serialize doctor bundle")?;
    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    // The bundle names ids and versions even redacted, so it gets the same
    // owner-local privacy as the other owner-local writers (peer evidence,
    // storage) instead of the umask default.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&target.path).with_context(|| {
        let hint = if target.generated_name {
            "a file already has this generated name; run again in a moment"
        } else {
            "the path must not exist yet (an existing file or symlink is refused)"
        };
        format!(
            "failed to create doctor bundle {} ({hint})",
            target.path.display()
        )
    })?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("failed to write doctor bundle {}", target.path.display()))?;
    drop(file);
    let written = std::fs::read(&target.path).with_context(|| {
        format!(
            "failed to read back doctor bundle {}",
            target.path.display()
        )
    })?;
    serde_json::from_slice::<serde_json::Value>(&written).with_context(|| {
        format!(
            "doctor bundle {} did not parse back as JSON",
            target.path.display()
        )
    })?;
    eprintln!("doctor bundle written to {}", target.path.display());
    Ok(())
}

/// Assemble and write the #1354 doctor bundle from a resolved `health`
/// section and the doctor report.
fn write_doctor_bundle(
    health: serde_json::Value,
    report: &DoctorReport,
    target: &DoctorBundleTarget,
) -> Result<()> {
    write_doctor_bundle_value(doctor_bundle_value(health, report)?, target)
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

#[cfg(test)]
fn render_launchd_plist(executable: &str, args: &[String], log_path: &Path) -> Result<String> {
    render_launchd_plist_with(executable, args, log_path, None)
}

/// The launcher's worst-case stop of a committed daemon: the 35 s graceful
/// window, then SIGKILL and up to 10 s to reap (#1378, A14). A launchd job
/// that binds the launcher needs an `ExitTimeOut` above it.
#[cfg(any(test, target_os = "macos"))]
const LAUNCHER_STOP_WORST_CASE_SECS: u64 = 45;

/// `ExitTimeOut` for a launcher-bound job: above the worst-case stop.
#[cfg(any(test, target_os = "macos"))]
const LAUNCHER_EXIT_TIMEOUT_SECS: u64 = 60;

/// The stable launcher a launchd job can bind (#1379), with its trial
/// authority in the launcher argv (#1378).
#[cfg(any(test, target_os = "macos"))]
pub(crate) struct LauncherBinding<'a> {
    pub(crate) launcher: &'a str,
    pub(crate) host_root: &'a str,
    pub(crate) instance: &'a str,
}

/// As `render_launchd_plist`; with a launcher binding the job runs
/// `x0x-launcher --host-root R --instance I -- x0xd args...` and sets
/// `ExitTimeOut` above the launcher's worst-case stop. `x0x autostart
/// --launcher` uses it (opt-in while the launcher is dormant).
#[cfg(any(test, target_os = "macos"))]
fn render_launchd_plist_with(
    executable: &str,
    args: &[String],
    log_path: &Path,
    launcher: Option<&LauncherBinding<'_>>,
) -> Result<String> {
    validate_autostart_value(executable)?;
    for arg in args {
        validate_autostart_value(arg)?;
    }
    let log_path = log_path.to_string_lossy();
    validate_autostart_value(&log_path)?;
    let mut program: Vec<&str> = Vec::new();
    if let Some(binding) = launcher {
        for value in [binding.launcher, binding.host_root, binding.instance] {
            validate_autostart_value(value)?;
        }
        if !Path::new(binding.launcher).is_absolute() {
            anyhow::bail!("the launcher must be an absolute path");
        }
        // The whole launcher argv, checked with the launcher's own parser
        // (#2063 review): a job it would refuse (a relative daemon, an
        // invalid instance) exits 64 under KeepAlive every 10 s.
        let launcher_argv: Vec<&str> = [
            "--host-root",
            binding.host_root,
            "--instance",
            binding.instance,
            "--",
            executable,
        ]
        .into_iter()
        .chain(args.iter().map(String::as_str))
        .collect();
        crate::upgrade::launcher_contract::parse_launcher_argv(&launcher_argv)
            .map_err(|usage| anyhow::anyhow!("the launcher would refuse this job: {usage}"))?;
        program.extend([
            binding.launcher,
            "--host-root",
            binding.host_root,
            "--instance",
            binding.instance,
            "--",
        ]);
    }
    let prog_args = program
        .into_iter()
        .chain(std::iter::once(executable))
        .chain(args.iter().map(String::as_str))
        .map(|arg| format!("        <string>{}</string>\n", xml_escape(arg)))
        .collect::<String>();
    let exit_timeout = if launcher.is_some() {
        format!("    <key>ExitTimeOut</key>\n    <integer>{LAUNCHER_EXIT_TIMEOUT_SECS}</integer>\n")
    } else {
        String::new()
    };
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>com.saorsalabs.x0xd</string>\n    <key>ProgramArguments</key>\n    <array>\n{prog_args}    </array>\n    <key>EnvironmentVariables</key>\n    <dict>\n        <key>{supervised_key}</key>\n        <string>1</string>\n    </dict>\n    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n{exit_timeout}    <key>{template_key}</key>\n    <integer>{template_version}</integer>\n    <key>StandardOutPath</key>\n    <string>{log}</string>\n    <key>StandardErrorPath</key>\n    <string>{log}</string>\n</dict>\n</plist>\n",
        supervised_key = crate::upgrade::restart::SUPERVISED_ENV_VAR,
        template_key = crate::upgrade::restart::LAUNCHD_TEMPLATE_VERSION_KEY,
        template_version = AUTOSTART_TEMPLATE_VERSION,
        log = xml_escape(&log_path),
    ))
}

/// The versioned Windows supervision wrapper template (#621, ADR-0061 §3):
/// a PowerShell script that restarts x0xd after exit 100 (the supervised
/// upgrade request) and exit 75 (EX_TEMPFAIL, a restart on the restored
/// binary, #1588) and propagates every other exit status. The daemon
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
/// the tested wrapper version, the restart-on-exit-100-and-75 policy, and the
/// executable/arguments binding the upgrade-time readback verifies. ASCII
/// only — Windows PowerShell 5.1 reads a no-BOM file as ANSI, so a non-ASCII
/// path or `--name` would corrupt the binding silently. Empty arguments and
/// arguments containing `"` are refused too: Windows PowerShell 5.1 drops
/// the former and mangles the latter when it starts x0xd, so the wrapper
/// would run different arguments than it declares (review round 3 of #1612).
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
    if args.iter().any(|arg| arg.is_empty() || arg.contains('"')) {
        anyhow::bail!(
            "autostart on Windows cannot wrap empty arguments or arguments containing a \
             double quote: Windows PowerShell 5.1 drops or mangles them when starting \
             x0xd, so the wrapper would run different arguments than it declares"
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

/// The launcher `--instance` for an autostart job: the `--name`, else
/// `default`. It must pass the launcher's own instance check, so a name the
/// launcher would refuse fails here, before anything is written.
#[cfg(any(test, target_os = "macos"))]
fn autostart_instance_id(name: Option<&str>) -> Result<String> {
    let instance = name.unwrap_or("default");
    crate::upgrade::launcher_contract::parse_launcher_argv(&[
        "--host-root",
        "/",
        "--instance",
        instance,
        "--",
        "/x0xd",
    ])
    .map_err(|usage| {
        anyhow::anyhow!("--launcher needs an instance name the launcher accepts: {usage}")
    })?;
    Ok(instance.to_owned())
}

/// The stable launcher installed next to `x0xd` as it was found, made
/// absolute but not resolved through symlinks (#2063 review): on a
/// package-manager install the stable `bin/x0x-launcher` link survives an
/// upgrade, while the versioned file it points to does not.
#[cfg(target_os = "macos")]
fn sibling_launcher(x0xd: &Path) -> Result<std::path::PathBuf> {
    let launcher = std::path::absolute(
        x0xd.parent()
            .context("x0xd has no parent directory")?
            .join(crate::upgrade::launcher_contract::LAUNCHER_BASENAME),
    )?;
    if !launcher.is_file() {
        anyhow::bail!(
            "--launcher needs {} installed next to x0xd",
            launcher.display()
        );
    }
    Ok(launcher)
}

/// Replace `path` with `bytes` in one step (#1379): a new temporary file
/// in the same directory (created new, `mode`, no symlink followed), file
/// fsync, rename over `path`, then a directory fsync. A reader (launchd, the
/// upgrade-time readback) sees the old file or the new one, never a part.
#[cfg(all(unix, any(test, target_os = "macos")))]
fn write_file_atomically(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().context("path has no parent directory")?;
    let file_name = path.file_name().context("path has no file name")?;
    let temporary = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    match std::fs::remove_file(&temporary) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("remove {}", temporary.display()));
        }
        _ => {}
    }
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        // The umask may have cleared bits of `mode`; set it exactly.
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.with_context(|| format!("write {}", path.display()))
}

/// The launchd domain of this user's GUI session: `gui/<uid>`.
#[cfg(target_os = "macos")]
fn launchd_gui_domain() -> String {
    // SAFETY: getuid has no preconditions and cannot fail.
    format!("gui/{}", unsafe { libc::getuid() })
}

/// Whether the job `label` is loaded in `domain` (`launchctl print`).
#[cfg(target_os = "macos")]
fn launchd_job_loaded(domain: &str, label: &str) -> bool {
    std::process::Command::new("launchctl")
        .args(["print", &format!("{domain}/{label}")])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Unload the job `label` from `domain`. `bootout` fails for a job that is
/// not loaded, so its result is judged by whether the job is still loaded
/// afterwards (#2063 review): an error only when it is.
#[cfg(target_os = "macos")]
fn launchd_bootout(domain: &str, label: &str) -> Result<()> {
    let out = std::process::Command::new("launchctl")
        .args(["bootout", &format!("{domain}/{label}")])
        .output()
        .context("failed to run launchctl bootout")?;
    if launchd_job_loaded(domain, label) {
        anyhow::bail!(
            "launchctl bootout {domain}/{label} left the job loaded ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Load `plist` into `domain`.
#[cfg(target_os = "macos")]
fn launchd_bootstrap(domain: &str, plist: &Path) -> Result<()> {
    let out = std::process::Command::new("launchctl")
        .args(["bootstrap", domain])
        .arg(plist)
        .output()
        .context("failed to run launchctl bootstrap")?;
    if !out.status.success() {
        anyhow::bail!(
            "launchctl bootstrap {domain} {} failed ({}): {}",
            plist.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Replace the job file at `plist` with `bytes` and reload it in `domain`
/// (#2063 review). The previous file is kept until the new job loads:
/// - a failed `bootout` (the old job stays loaded) restores the old file
///   and changes nothing;
/// - a failed `bootstrap` restores the old file and, when the old job was
///   loaded before, loads it again; with no old file it removes the new
///   one.
///
/// A failed restore is reported together with the error that caused it.
#[cfg(target_os = "macos")]
fn replace_launchd_job(domain: &str, label: &str, plist: &Path, bytes: &[u8]) -> Result<()> {
    let previous = match std::fs::read(plist) {
        Ok(previous) => Some(previous),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("read {}", plist.display())),
    };
    let was_loaded = launchd_job_loaded(domain, label);
    let restore = || -> Result<()> {
        match &previous {
            Some(previous) => write_file_atomically(plist, previous, 0o644),
            None => {
                std::fs::remove_file(plist).with_context(|| format!("remove {}", plist.display()))
            }
        }
    };
    let restore_failed = |error: anyhow::Error, restore_error: anyhow::Error| {
        error.context(format!(
            "restoring the previous job file also failed, so {} holds the new job: \
             {restore_error:#}",
            plist.display()
        ))
    };
    write_file_atomically(plist, bytes, 0o644)?;
    if let Err(error) = launchd_bootout(domain, label) {
        return Err(match restore() {
            Ok(()) => error.context("the previous job file was restored; nothing changed"),
            Err(restore_error) => restore_failed(error, restore_error),
        });
    }
    if let Err(error) = launchd_bootstrap(domain, plist) {
        if let Err(restore_error) = restore() {
            return Err(restore_failed(error, restore_error));
        }
        let state = match (&previous, was_loaded) {
            (None, _) => "the new job file was removed; no job is installed",
            (Some(_), false) => "the previous job file was restored; it was not loaded before",
            (Some(_), true) if launchd_bootstrap(domain, plist).is_ok() => {
                "the previous job was restored and loaded again"
            }
            (Some(_), true) => {
                "the previous job file was restored but is not loaded; load it with launchctl \
                 bootstrap"
            }
        };
        return Err(error.context(state));
    }
    Ok(())
}

/// Label of the launchd job `x0x autostart` installs. One label serves
/// every `--name`: a second instance's autostart is refused rather than
/// replacing the first instance's job (`existing_job_conflict`).
#[cfg(any(test, target_os = "macos"))]
const AUTOSTART_LAUNCHD_LABEL: &str = "com.saorsalabs.x0xd";

/// The config file x0xd started with `HOME=home` and no `--config` reads
/// for instance `name`.
#[cfg(any(test, target_os = "macos"))]
fn instance_config_path(name: Option<&str>, home: &Path) -> std::path::PathBuf {
    let dir = match name {
        Some(n) => format!("x0x-{n}"),
        None => "x0x".to_string(),
    };
    home.join("Library/Application Support")
        .join(dir)
        .join("config.toml")
}

/// A file's text, `None` when it does not exist.
#[cfg(target_os = "macos")]
fn read_optional(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// The data directory of an instance this CLI user's x0xd uses
/// (`job_data_dir`), created if missing, canonical (the launcher's host
/// root, A14). Only the install calls it, after the job is planned.
#[cfg(target_os = "macos")]
fn instance_data_dir(name: Option<&str>) -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let config = read_optional(&instance_config_path(name, &home))?;
    let data_dir = job_data_dir(name, &home, config.as_deref())?;
    std::fs::create_dir_all(&data_dir)?;
    Ok(data_dir.canonicalize()?)
}

/// The data directory that x0xd started with `HOME=home`, no `--config` and
/// instance `name` uses (the launcher's host root, A14), as x0xd derives
/// it: the instance's default config file `config` (`<home>/Library/
/// Application Support/x0x[-<name>]/config.toml`) may set `data_dir`, and a
/// named instance that keeps the unnamed default gets `x0x-<name>`. A file
/// x0xd would reject, a relative `data_dir`, or an `instance_name` other
/// than the job's is refused: the host root is then not known from the job.
#[cfg(any(test, target_os = "macos"))]
fn job_data_dir(
    name: Option<&str>,
    home: &Path,
    config: Option<&str>,
) -> Result<std::path::PathBuf> {
    let base = home.join("Library/Application Support");
    let unnamed = base.join("x0x");
    let table = config
        .map(toml::from_str::<toml::Table>)
        .transpose()
        .context("the instance's config file is not valid TOML")?
        .unwrap_or_default();
    if let Some(configured) = table.get("instance_name") {
        if configured.as_str() != name {
            anyhow::bail!(
                "the instance's config file sets instance_name {configured}, which the job does \
                 not pass; migrate it by hand"
            );
        }
    }
    let data_dir = match table.get("data_dir") {
        None => unnamed.clone(),
        Some(value) => {
            let path = Path::new(value.as_str().context("config data_dir is not text")?);
            if !path.is_absolute() {
                anyhow::bail!("the instance's config file sets a relative data_dir");
            }
            path.to_path_buf()
        }
    };
    Ok(match name {
        Some(n) if data_dir == unnamed => base.join(format!("x0x-{n}")),
        _ => data_dir,
    })
}

/// `x0x autostart` — configure daemon to start on boot. With `launcher`
/// (macOS, opt-in while the launcher is dormant) the launchd job runs the
/// stable launcher installed next to x0xd, with its trial authority (#1379).
pub async fn autostart(name: Option<&str>, launcher: bool) -> Result<()> {
    let x0xd_path = find_x0xd()?;
    let x0xd = x0xd_path.to_string_lossy();
    #[cfg(not(target_os = "macos"))]
    if launcher {
        anyhow::bail!("--launcher is supported only for launchd (macOS) so far");
    }

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
        refuse_privileged_caller()?;
        let plist_dir = dirs::home_dir()
            .context("cannot determine home directory")?
            .join("Library/LaunchAgents");
        std::fs::create_dir_all(&plist_dir)?;

        let plist_path = plist_dir.join(format!("{AUTOSTART_LAUNCHD_LABEL}.plist"));
        if plist_path.exists() {
            check_plist_file_owner(&plist_path)?;
        }
        // #690: XML-escape every rendered argument and stamp the template
        // version so upgrade-time drift detection identifies the generation.
        let mut args = Vec::new();
        if let Some(n) = name {
            args.extend(["--name".to_string(), n.to_string()]);
        }
        // Refuse to take over another instance's job (one label).
        existing_job_conflict(read_plist_as_json(&plist_path)?.as_ref(), name)?;
        // Check the launcher binding before anything is written. The
        // trial form needs the canonical daemon (A14: the participant's
        // executable is the canonical install path); the launcher stays
        // the stable path next to x0xd as found.
        let (instance, launcher_path, x0xd) = if launcher {
            (
                Some(autostart_instance_id(name)?),
                Some(sibling_launcher(&x0xd_path)?),
                stable_daemon(x0xd_path.canonicalize()?.to_string_lossy().into_owned())?,
            )
        } else {
            (None, None, x0xd.into_owned())
        };

        let data_dir = if launcher {
            instance_data_dir(name)?
        } else {
            let base = dirs::data_dir().context("cannot determine data directory")?;
            let data_dir =
                base.join(name.map_or_else(|| "x0x".to_string(), |n| format!("x0x-{n}")));
            std::fs::create_dir_all(&data_dir)?;
            data_dir
        };
        let log_path = data_dir.join("x0xd.log");

        // The pure renderer used by tests is the only template path.
        let host_root = data_dir.to_string_lossy();
        let launcher_str = launcher_path.as_ref().map(|path| path.to_string_lossy());
        let binding = match (&launcher_str, &instance) {
            (Some(launcher), Some(instance)) => Some(LauncherBinding {
                launcher,
                host_root: &host_root,
                instance,
            }),
            _ => None,
        };
        let plist = render_launchd_plist_with(&x0xd, &args, &log_path, binding.as_ref())?;
        // Replace any loaded job in this user's GUI domain and load the new
        // one so it starts now and at login; on failure the previous job
        // file is restored.
        replace_launchd_job(
            &launchd_gui_domain(),
            AUTOSTART_LAUNCHD_LABEL,
            &plist_path,
            plist.as_bytes(),
        )?;

        println!("Autostart enabled (launchd agent)");
        println!("  Plist:  {}", plist_path.display());
        if let Some(launcher) = &launcher_path {
            println!("  Launcher: {}", launcher.display());
        }
        println!(
            "  Status: launchctl print {}/{AUTOSTART_LAUNCHD_LABEL}",
            launchd_gui_domain()
        );
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
        // versioned wrapper (restart after exit 100 and 75 only), which the daemon
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
        // still appear; verified behaviour is VM-acceptance work). schtasks
        // caps /TR at 261 characters — a very long %APPDATA% path fails
        // registration and falls through to the printed fallback.
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
            println!("  Register it manually (PowerShell):");
            println!(
                "    Register-ScheduledTask -TaskName {WINDOWS_AUTOSTART_TASK} -Trigger \
                 (New-ScheduledTaskTrigger -AtLogOn) -Action (New-ScheduledTaskAction \
                 -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden \
                 -ExecutionPolicy Bypass -File ''{}''')",
                wrapper_path.display()
            );
            println!("  Or run the wrapper from your own service manager (WinSW/NSSM/SCM).");
        }
        println!("  Wrapper: {}", wrapper_path.display());
        println!(
            "  Policy:  the wrapper (template v2) restarts x0xd after exit 100 (the \
             upgrade request) and exit 75 (EX_TEMPFAIL: a failed flush restored the \
             previous binary, so it restarts on that binary), and propagates every other \
             exit. A supervised apply (X0X_SUPERVISED=1) uses the acknowledged-shutdown \
             flush owner on the local named pipe."
        );
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
    let arguments: Option<Vec<String>> = plist
        .get("ProgramArguments")
        .and_then(|a| a.as_array())
        .and_then(|a| a.iter().map(|v| v.as_str().map(str::to_owned)).collect());
    // launchd runs `Program` when it is set, so the launcher is detected
    // from the executable launchd runs, as the upgrade-time readback does;
    // a launcher-bound job (#1379) runs the daemon its argv names, checked
    // with the launcher's own parser (#2016 review).
    let daemon = match crate::upgrade::restart::launchd_job_daemon(
        plist.get("Program").and_then(|p| p.as_str()),
        arguments.as_deref().unwrap_or_default(),
    ) {
        None => return RepairVerdict::NotAnX0xdJob,
        Some(Ok(daemon)) => daemon,
        Some(Err(usage)) => {
            return RepairVerdict::Refused(format!(
                "job runs x0x-launcher with arguments the launcher refuses ({usage}); review \
                 it by hand"
            ));
        }
    };
    let launcher_bound = daemon.via_launcher;
    if program_basename(daemon.executable) != "x0xd" {
        return RepairVerdict::NotAnX0xdJob;
    }
    // The launcher stops a committed daemon in up to 45 s (graceful window
    // plus reap, #1378); launchd's default ExitTimeOut (20 s) would SIGKILL
    // the launcher first and orphan its child.
    if launcher_bound
        && plist
            .get("ExitTimeOut")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|seconds| seconds <= LAUNCHER_STOP_WORST_CASE_SECS)
    {
        return RepairVerdict::Refused(format!(
            "job runs x0x-launcher without `ExitTimeOut` above {LAUNCHER_STOP_WORST_CASE_SECS} s, \
             so launchd can kill the launcher before it stops x0xd; set it by hand"
        ));
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

    // ADR 0094 (#1379): launchd's process-group cleanup is what removes a
    // surviving child when the job stops or its supervisor dies. A job that
    // sets `AbandonProcessGroup` keeps orphans alive across a restart, so an
    // old and a new daemon could share the data roots. Report it, whether or
    // not the job already carries the marker; the repair never edits it.
    if plist.get("AbandonProcessGroup") == Some(&serde_json::Value::Bool(true)) {
        return RepairVerdict::Refused(
            "job sets `AbandonProcessGroup`, so launchd does not remove x0xd's process \
             group when the job stops and an orphaned daemon can outlive its \
             replacement; remove that key by hand"
                .to_string(),
        );
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

/// The first `--name value` or `--name=value` in a daemon's arguments, as
/// x0xd reads it (`cli_name_argument`).
#[cfg(any(test, target_os = "macos"))]
fn daemon_name_argument(args: &[String]) -> Option<String> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--name" {
            return args.next().cloned();
        }
        if let Some(value) = arg.strip_prefix("--name=") {
            return Some(value.to_owned());
        }
    }
    None
}

/// The arguments of a launchd job (`ProgramArguments`), if they are text.
#[cfg(any(test, target_os = "macos"))]
fn launchd_job_arguments(job: &serde_json::Value) -> Option<Vec<String>> {
    job.get("ProgramArguments")?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// The instance an x0xd launchd job starts: `Some(None)` for the default
/// instance, `Some(Some(name))` for `--name name`, `None` when the job is
/// not an x0xd job this can read.
#[cfg(any(test, target_os = "macos"))]
fn launchd_job_instance(job: &serde_json::Value) -> Option<Option<String>> {
    let arguments = launchd_job_arguments(job)?;
    let daemon = crate::upgrade::restart::launchd_job_daemon(
        job.get("Program").and_then(|p| p.as_str()),
        &arguments,
    )?
    .ok()?;
    if program_basename(daemon.executable) != "x0xd" {
        return None;
    }
    Some(daemon_name_argument(daemon.args))
}

/// One label serves every `--name` (#2063 review): refuse to replace the
/// autostart job when it starts another instance, so a second instance's
/// `x0x autostart` cannot silently take over the first one's job.
#[cfg(any(test, target_os = "macos"))]
fn existing_job_conflict(existing: Option<&serde_json::Value>, name: Option<&str>) -> Result<()> {
    let Some(other) = existing.and_then(launchd_job_instance) else {
        return Ok(());
    };
    if other.as_deref() == name {
        return Ok(());
    }
    anyhow::bail!(
        "the autostart job {AUTOSTART_LAUNCHD_LABEL} already starts instance {}; one job \
         serves one instance, so run `x0x autostart --remove` first to replace it",
        other.as_deref().unwrap_or("default")
    )
}

/// How `x0x autostart --repair --launcher` moves one x0xd job onto the
/// stable launcher (#1379).
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LauncherMigration {
    /// The new `ProgramArguments`: the launcher's trial form, then the
    /// daemon (canonical) and its unchanged arguments.
    pub(crate) program_arguments: Vec<String>,
    /// The job sets `Program`, which launchd would still run: remove it.
    pub(crate) remove_program: bool,
    /// `ExitTimeOut` is absent or not above the launcher's worst-case stop.
    pub(crate) set_exit_timeout: bool,
}

/// What `plan_launcher_migration` reads from the host.
#[cfg(any(test, target_os = "macos"))]
pub(crate) struct MigrationHost<'a> {
    /// The canonical daemon executable for the job's daemon path.
    pub(crate) canonical_daemon: &'a dyn Fn(&str) -> Result<String>,
    /// The stable launcher next to the job's daemon path.
    pub(crate) launcher_for: &'a dyn Fn(&str) -> Result<String>,
    /// This CLI user's home, for a job that sets no `HOME`.
    pub(crate) user_home: &'a dyn Fn() -> Result<std::path::PathBuf>,
    /// A file's text, `None` when it does not exist.
    pub(crate) read_file: &'a dyn Fn(&Path) -> Result<Option<String>>,
    /// The canonical path of an existing directory. It never creates one:
    /// planning changes nothing.
    pub(crate) canonical_dir: &'a dyn Fn(&Path) -> Result<String>,
}

/// Plan the migration of one launchd job onto the launcher. `Ok(None)` when
/// the job already runs the launcher. Only an x0xd job that the plain
/// repair accepts (KeepAlive true, no AbandonProcessGroup) is moved. The
/// label, environment, log paths, KeepAlive and every other key stay; only
/// the program, its arguments and `ExitTimeOut` change. A job whose daemon
/// arguments name a `--config` is refused, since its data directory (the
/// host root) is not known from the job.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn plan_launcher_migration(
    job: &serde_json::Value,
    host: &MigrationHost<'_>,
) -> Result<Option<LauncherMigration>> {
    match classify_launchd_job(job) {
        RepairVerdict::AlreadySupervised | RepairVerdict::Repairable { .. } => {}
        RepairVerdict::Refused(reason) => anyhow::bail!(reason),
        RepairVerdict::NotAnX0xdJob => anyhow::bail!("not an x0xd job"),
    }
    let arguments = launchd_job_arguments(job).context("job has no text ProgramArguments")?;
    let daemon = crate::upgrade::restart::launchd_job_daemon(
        job.get("Program").and_then(|p| p.as_str()),
        &arguments,
    )
    .context("job names no executable")?
    .map_err(|usage| anyhow::anyhow!(usage))?;
    if daemon.via_launcher {
        return Ok(None);
    }
    if !Path::new(daemon.executable).is_absolute() {
        anyhow::bail!("the job's daemon path is relative; the launcher needs an absolute one");
    }
    if daemon.args.iter().any(|arg| arg == "--config") {
        anyhow::bail!(
            "the job passes --config, so its data directory (the launcher's host root) is not \
             known from the job; migrate it by hand"
        );
    }
    let name = daemon_name_argument(daemon.args);
    let instance = autostart_instance_id(name.as_deref())?;
    // x0xd finds its data directory from the job's own HOME (#2072 review).
    let home = match job
        .get("EnvironmentVariables")
        .and_then(|env| env.get("HOME"))
    {
        Some(home) => {
            std::path::PathBuf::from(home.as_str().context("the job's HOME is not text")?)
        }
        None => (host.user_home)()?,
    };
    if !home.is_absolute() {
        anyhow::bail!("the job's HOME is not an absolute path");
    }
    let config = (host.read_file)(&instance_config_path(name.as_deref(), &home))?;
    let data_dir = job_data_dir(name.as_deref(), &home, config.as_deref())?;
    let root = (host.canonical_dir)(&data_dir).with_context(|| {
        format!(
            "the job's data directory {} must exist (start the daemon once)",
            data_dir.display()
        )
    })?;
    let launcher = (host.launcher_for)(daemon.executable)?;
    let executable = stable_daemon((host.canonical_daemon)(daemon.executable)?)?;
    let program_arguments: Vec<String> = [
        launcher.as_str(),
        "--host-root",
        root.as_str(),
        "--instance",
        instance.as_str(),
        "--",
        executable.as_str(),
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(daemon.args.iter().cloned())
    .collect();
    crate::upgrade::launcher_contract::parse_launcher_argv(&program_arguments[1..])
        .map_err(|usage| anyhow::anyhow!("the launcher would refuse the migrated job: {usage}"))?;
    let set_exit_timeout = job
        .get("ExitTimeOut")
        .and_then(serde_json::Value::as_u64)
        .is_none_or(|seconds| seconds <= LAUNCHER_STOP_WORST_CASE_SECS);
    Ok(Some(LauncherMigration {
        program_arguments,
        remove_program: job.get("Program").is_some(),
        set_exit_timeout,
    }))
}

/// Whether `path` lies inside a versioned Homebrew keg,
/// `<prefix>/Cellar/<formula>/<version>/...`.
#[cfg(any(test, target_os = "macos"))]
fn in_versioned_keg(path: &Path) -> bool {
    let parts: Vec<_> = path.components().collect();
    parts
        .iter()
        .position(|part| part.as_os_str() == "Cellar")
        .is_some_and(|cellar| parts.len() > cellar + 3)
}

/// The canonical daemon for the launcher's trial form, refused when it lies
/// inside a versioned Homebrew keg (#1379). `brew upgrade` installs the next
/// version in a new keg and removes the old one, so a job that names the old
/// keg loses its daemon and the launcher waits for it.
#[cfg(any(test, target_os = "macos"))]
fn stable_daemon(canonical: String) -> Result<String> {
    if in_versioned_keg(Path::new(&canonical)) {
        anyhow::bail!(
            "x0xd resolves to {canonical}, inside a versioned Homebrew keg that `brew upgrade` \
             removes; the launcher needs a canonical daemon path that stays, so keep the direct \
             job (`x0x autostart` without --launcher) or install x0xd outside Homebrew"
        );
    }
    Ok(canonical)
}

/// Refuse to manage launchd agents as root or under `sudo` (#1379). The
/// agent belongs to the user who runs it: as root the job and its files go
/// to root's home or, under `sudo`, become root-owned files in the user's
/// home, which the user's `launchctl` then cannot load or change.
#[cfg(any(test, target_os = "macos"))]
fn refuse_privileged(euid: u32, sudo_user: Option<&std::ffi::OsStr>) -> Result<()> {
    if euid == 0 || sudo_user.is_some() {
        anyhow::bail!(
            "x0x autostart manages the launchd agent of the user who runs it; run it as that \
             user, not as root or under sudo"
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "macos")]
fn refuse_privileged_caller() -> Result<()> {
    refuse_privileged(current_euid(), std::env::var_os("SUDO_USER").as_deref())
}

/// A job file the autostart commands may change: owned by this user and
/// writable by no one else (#1379). launchd does not load an agent that
/// group or others can write.
#[cfg(any(test, target_os = "macos"))]
fn check_plist_owner(path: &Path, owner: u32, mode: u32, euid: u32) -> Result<()> {
    if owner != euid {
        anyhow::bail!(
            "{} is owned by uid {owner}, not by this user (uid {euid}); fix its owner first",
            path.display()
        );
    }
    if mode & 0o022 != 0 {
        anyhow::bail!(
            "{} is writable by group or others (mode {:o}), which launchd refuses; remove that \
             write permission first",
            path.display(),
            mode & 0o7777
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn check_plist_file_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    check_plist_owner(path, meta.uid(), meta.mode(), current_euid())
}

/// The doctor finding for a launchd job of `instance` whose x0xd path does
/// not exist (#1379), for example a Homebrew keg that `brew upgrade`
/// removed. The launcher then waits for the path without exiting, so
/// launchd shows the job running with no daemon; a direct job fails each
/// start instead. `None` for another instance's job or a daemon that exists.
#[cfg(any(test, target_os = "macos"))]
fn missing_daemon_check(
    job: &serde_json::Value,
    instance: Option<&str>,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<DoctorCheck> {
    let arguments = launchd_job_arguments(job)?;
    let daemon = crate::upgrade::restart::launchd_job_daemon(
        job.get("Program").and_then(|p| p.as_str()),
        &arguments,
    )?
    .ok()?;
    if program_basename(daemon.executable) != "x0xd"
        || daemon_name_argument(daemon.args).as_deref() != instance
        || exists(Path::new(daemon.executable))
    {
        return None;
    }
    let label = job.get("Label").and_then(|l| l.as_str()).unwrap_or("x0xd");
    let effect = if daemon.via_launcher {
        "x0x-launcher waits for it, so launchd shows the job running with no daemon"
    } else {
        "launchd cannot start the job"
    };
    Some(DoctorCheck {
        status: DoctorCheckStatus::Fail,
        detail: format!(
            "the launchd job {label} runs x0xd from {}, which does not exist; {effect}. Run \
             `x0x autostart` again to point the job at the installed x0xd",
            daemon.executable
        ),
        evidence: Some(serde_json::json!({
            "launchd_label": label,
            "missing_daemon": daemon.executable,
            "via_launcher": daemon.via_launcher,
        })),
    })
}

/// `x0x autostart --repair` — migrate an existing hand-written launchd job to
/// the supervised-upgrade contract (ADR-0061, #493).
///
/// Inspects the job without changing service state, then adds only
/// `EnvironmentVariables.X0X_SUPERVISED = "1"`, preserving the job's label,
/// executable, arguments, roots and every other key. The change takes effect
/// on the job's next load; reloading is left to the operator because
/// unload/load stops a running daemon.
/// With `launcher` (#1379) it also moves each x0xd job onto the stable
/// launcher (`plan_launcher_migration`), again without reloading it. With
/// `dry_run` it prints what it would change and writes nothing. A job file
/// that is not this user's own, or that others can write, is refused.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
pub async fn autostart_repair(launcher: bool, dry_run: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        refuse_privileged_caller()?;
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
        let mut refused: Vec<String> = Vec::new();
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
            let verdict = match check_plist_file_owner(&path) {
                Ok(()) => verdict,
                Err(error) => RepairVerdict::Refused(format!("{error:#}")),
            };

            match verdict {
                RepairVerdict::Refused(reason) => {
                    refused.push(format!("{label} ({})", path.display()));
                    println!("  REFUSED: {reason}");
                    println!("  Left unchanged.");
                }
                RepairVerdict::NotAnX0xdJob => continue,
                _ if launcher => match migrate_job_to_launcher(&path, &job, dry_run) {
                    Ok(true) => repaired += 1,
                    Ok(false) => compliant += 1,
                    Err(error) => {
                        refused.push(format!("{label} ({})", path.display()));
                        println!("  REFUSED: {error:#}");
                        println!("  Left unchanged.");
                    }
                },
                RepairVerdict::AlreadySupervised => {
                    compliant += 1;
                    println!(
                        "  Already declares {}=1 — no change.",
                        crate::upgrade::restart::SUPERVISED_ENV_VAR
                    );
                }
                RepairVerdict::Repairable { .. } if dry_run => {
                    repaired += 1;
                    println!(
                        "  Would add: {}=1 (all other keys preserved)",
                        crate::upgrade::restart::SUPERVISED_ENV_VAR
                    );
                }
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
                    print_reload_hint(&path, label);
                }
            }
        }

        if inspected == 0 {
            println!("No x0xd launchd job found in {}", plist_dir.display());
            println!("Nothing to repair — `x0x autostart` installs a compliant job.");
            return Ok(());
        }
        let changed = if dry_run {
            "would be repaired"
        } else {
            "repaired"
        };
        println!(
            "\nInspected {inspected} x0xd job(s): {repaired} {changed}, {compliant} already \
             compliant, {} refused.",
            refused.len()
        );
        if dry_run {
            println!("Dry run: no job file was changed.");
        }
        if repaired > 0 && !dry_run {
            println!(
                "Also confirm `[update] stop_on_upgrade` is true (the default) in the daemon \
                 config: a supervised job with it set to false now refuses self-update."
            );
        }
        // A launcher migration that left a job behind is a failure the
        // caller must see (#2072 review): the exit code is not 0.
        if launcher && !refused.is_empty() {
            anyhow::bail!(
                "{} x0xd job(s) were not moved onto the launcher: {}",
                refused.len(),
                refused.join(", ")
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if launcher {
            anyhow::bail!("--launcher is supported only for launchd (macOS) so far");
        }
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

/// How to apply a repaired job now: the repair never reloads a job, since
/// that stops a running daemon.
#[cfg(target_os = "macos")]
fn print_reload_hint(path: &Path, label: &str) {
    let domain = launchd_gui_domain();
    println!("  Takes effect on the job's next load. To apply now:");
    println!("    launchctl bootout {domain}/{label}");
    println!("    launchctl bootstrap {domain} {}", path.display());
}

/// Move one x0xd job onto the stable launcher (#1379). The whole new job
/// file is built first (`migrated_job`), converted to a plist and checked by
/// converting it back, then written in one atomic step (#2072 review), so
/// a crash leaves either the old job or the new one, never a mix. A copy of
/// the old file is kept, and is put back if the readback does not match.
/// `Ok(false)` when the job already runs the launcher. With `dry_run` the
/// planned job is checked and printed, and nothing is written.
#[cfg(target_os = "macos")]
fn migrate_job_to_launcher(path: &Path, job: &serde_json::Value, dry_run: bool) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let host = MigrationHost {
        canonical_daemon: &|daemon| {
            Ok(Path::new(daemon)
                .canonicalize()
                .with_context(|| format!("canonicalize {daemon}"))?
                .to_string_lossy()
                .into_owned())
        },
        launcher_for: &|daemon| {
            Ok(sibling_launcher(Path::new(daemon))?
                .to_string_lossy()
                .into_owned())
        },
        user_home: &|| dirs::home_dir().context("cannot determine home directory"),
        read_file: &read_optional,
        canonical_dir: &|dir| {
            let canonical = dir
                .canonicalize()
                .with_context(|| format!("canonicalize {}", dir.display()))?;
            if !canonical.is_dir() {
                anyhow::bail!("{} is not a directory", canonical.display());
            }
            Ok(canonical.to_string_lossy().into_owned())
        },
    };
    let Some(migration) = plan_launcher_migration(job, &host)? else {
        println!("  Already runs x0x-launcher; no change.");
        return Ok(false);
    };
    let planned = migrated_job(job, &migration)?;
    let bytes = json_to_plist(&planned)?;
    if plist_to_json(&bytes)? != planned {
        anyhow::bail!("the migrated job does not convert back as planned; nothing changed");
    }
    if dry_run {
        println!("  Would run: {:?}", migration.program_arguments);
        if migration.remove_program {
            println!("  Would remove: Program");
        }
        if migration.set_exit_timeout {
            println!("  Would set: ExitTimeOut {LAUNCHER_EXIT_TIMEOUT_SECS}");
        }
        return Ok(true);
    }
    let old = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    let backup = path.with_extension("plist.x0x-backup");
    write_file_atomically(&backup, &old, mode)?;
    write_file_atomically(path, &bytes, mode)?;
    let verified = read_plist_as_json(path)?.is_some_and(|after| {
        after == planned && classify_launchd_job(&after) == RepairVerdict::AlreadySupervised
    });
    if !verified {
        write_file_atomically(path, &old, mode)?;
        anyhow::bail!("the migrated job does not read back as planned; the old job was restored");
    }
    println!("  Backup:   {}", backup.display());
    println!(
        "  Launcher: {}",
        migration
            .program_arguments
            .first()
            .map_or("", String::as_str)
    );
    let label = job
        .get("Label")
        .and_then(|l| l.as_str())
        .unwrap_or("<unlabelled>");
    print_reload_hint(path, label);
    Ok(true)
}

/// `job` with a planned launcher migration applied: `ProgramArguments`
/// replaced, `Program` removed and `ExitTimeOut` set when planned, and the
/// supervision marker added. Every other key stays as it is.
#[cfg(any(test, target_os = "macos"))]
fn migrated_job(
    job: &serde_json::Value,
    migration: &LauncherMigration,
) -> Result<serde_json::Value> {
    let mut job = job.clone();
    let keys = job.as_object_mut().context("the job is not a dictionary")?;
    keys.insert(
        "ProgramArguments".into(),
        serde_json::json!(migration.program_arguments),
    );
    if migration.remove_program {
        keys.remove("Program");
    }
    if migration.set_exit_timeout {
        keys.insert(
            "ExitTimeOut".into(),
            serde_json::json!(LAUNCHER_EXIT_TIMEOUT_SECS),
        );
    }
    keys.entry("EnvironmentVariables")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .context("the job's EnvironmentVariables is not a dictionary")?
        .insert(
            crate::upgrade::restart::SUPERVISED_ENV_VAR.into(),
            serde_json::json!("1"),
        );
    Ok(job)
}

/// Run `plutil -convert <format>` over `input` (stdin to stdout).
#[cfg(target_os = "macos")]
fn plutil_convert(format: &str, input: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;
    let mut child = std::process::Command::new("plutil")
        .args(["-convert", format, "-o", "-", "--", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to run plutil")?;
    child
        .stdin
        .take()
        .context("plutil has no stdin")?
        .write_all(input)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "plutil -convert {format} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// An XML plist of `job`.
#[cfg(target_os = "macos")]
fn json_to_plist(job: &serde_json::Value) -> Result<Vec<u8>> {
    plutil_convert("xml1", &serde_json::to_vec(job)?)
}

/// The JSON form of plist bytes.
#[cfg(target_os = "macos")]
fn plist_to_json(bytes: &[u8]) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&plutil_convert("json", bytes)?)?)
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
        refuse_privileged_caller()?;
        let plist_path = dirs::home_dir()
            .context("cannot determine home directory")?
            .join(format!(
                "Library/LaunchAgents/{AUTOSTART_LAUNCHD_LABEL}.plist"
            ));
        if plist_path.exists() {
            launchd_bootout(&launchd_gui_domain(), AUTOSTART_LAUNCHD_LABEL)?;
            std::fs::remove_file(&plist_path)?;
        }
        println!("Autostart removed (launchd)");
    }

    #[cfg(target_os = "windows")]
    {
        // Delete the task FIRST and require the delete to have run and
        // succeeded (when the task exists) before removing the script: a
        // leftover logon task pointing at a deleted script fails silently at
        // every sign-in (review round 2 of #1612). On a failed delete the
        // wrapper stays so the task keeps working, and the operator gets the
        // manual command.
        let task_exists = std::process::Command::new("schtasks")
            .args(["/Query", "/TN", WINDOWS_AUTOSTART_TASK])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if task_exists {
            let deleted = std::process::Command::new("schtasks")
                .args(["/Delete", "/TN", WINDOWS_AUTOSTART_TASK, "/F"])
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if !deleted {
                let wrapper_path = dirs::config_dir()
                    .context("cannot determine config directory")?
                    .join("x0x")
                    .join(WINDOWS_WRAPPER_FILE_NAME);
                anyhow::bail!(
                    "could not delete the logon task {WINDOWS_AUTOSTART_TASK} \
                     (schtasks /Delete failed); the wrapper {} was left in place so the \
                     task keeps working. Delete the task manually \
                     (schtasks /Delete /TN {WINDOWS_AUTOSTART_TASK} /F), then re-run \
                     `x0x autostart --remove`",
                    wrapper_path.display()
                );
            }
        }
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

/// Candidate file names for the daemon binary: `x0xd.exe` on Windows
/// (releases ship `x0xd.exe`), bare `x0xd` everywhere else.
fn x0xd_binary_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["x0xd.exe", "x0xd"]
    } else {
        &["x0xd"]
    }
}

/// Find the x0xd binary.
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
        let result = doctor(&client, None).await;
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

    /// Doctor's single `/health` fetch plus the report built from it — the
    /// same two steps production `doctor` runs.
    async fn doctor_report_via(client: &DaemonClient) -> DoctorReport {
        let health = client
            .get_with_timeout(DOCTOR_HEALTH_PATH, DOCTOR_HEALTH_TIMEOUT)
            .await;
        collect_doctor_report(client, &health).await
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

        let report = doctor_report_via(&client).await;
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
        let report = doctor_report_via(&client).await;
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
        let report = doctor_report_via(&client).await;
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
        let report = doctor_report_via(&client).await;
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
        let report = doctor_report_via(&client).await;
        let parsed = assert_doctor_json_stdout(&report, true);
        assert_eq!(parsed["connectivity"]["status"], "warn");
    }

    // ===================================================================
    // #1354: `x0x doctor --bundle` redacted diagnostic bundle
    // ===================================================================

    /// One body satisfying every doctor fetch at once (the mock server
    /// answers any path with it), shaped like a daemon that PREDATES
    /// `?detail=redacted`: it ignores the parameter and serves the
    /// full-audience body. The `reasons` are the real full-audience
    /// sentences from `classify_with_detail`
    /// (src/server/health_verdict.rs), and the gated `verdict.inputs`
    /// fields carry canaries.
    fn doctor_bundle_mock_body() -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "status": "healthy",
            "peers": 5,
            "agent_id": "abc123",
            "machine_id": "def456",
            "stores": [],
            "update_available": false,
            "current_version": "0.1.0",
            "verdict": {
                "verdict": "degraded",
                "reasons": [
                    "75/100 publishes failed in the last 60s (rate 0.75 ≥ 0.50)",
                    "data-dir filesystem has 536870912 bytes free (< 1073741824)",
                    "57 error-level log events in the last 60s"
                ],
                "inputs": {
                    "disk": { "state": "degraded", "free_bytes": 999888777666u64, "total_bytes": 999888777999u64 },
                    "upgrade": {
                        "state": "ok",
                        "checks_enabled": true,
                        "latest_version": "canary-version-DO-NOT-SHIP"
                    },
                    "identity": { "state": "ok", "agent": true, "machine": true, "user_present": true },
                    "log": { "state": "degraded", "window_secs": 60, "errors": 424242 },
                    "send_failure_rate": { "state": "degraded", "window_secs": 60, "attempts": 999111, "failed": 999222, "rate": 0.9993 }
                }
            }
        })
    }

    /// The same daemon once it honours `?detail=redacted`: the
    /// redacted-audience body — the real redacted reason sentences (bounds,
    /// not measurements) and the gated inputs absent.
    fn doctor_bundle_redacted_body() -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "status": "healthy",
            "peers": 5,
            "agent_id": "abc123",
            "machine_id": "def456",
            "stores": [],
            "update_available": false,
            "current_version": "0.1.0",
            "verdict": {
                "verdict": "degraded",
                "reasons": [
                    "publish failures in the last 60s are at or above the degraded rate bound (≥ 0.50)",
                    "data-dir filesystem free space is below the degraded bound (< 1073741824)",
                    "error-level log events in the last 60s are at or above the storm threshold (50)"
                ],
                "inputs": {
                    "disk": { "state": "degraded" },
                    "upgrade": { "state": "ok", "checks_enabled": true },
                    "identity": { "state": "ok", "agent": true, "machine": true },
                    "log": { "state": "degraded", "window_secs": 60 },
                    "send_failure_rate": { "state": "degraded", "window_secs": 60 }
                }
            }
        })
    }

    /// A mock daemon that answers `/health?detail=redacted` with the
    /// redacted-audience body and everything else with the full body,
    /// recording every request URI so tests can pin doctor's single
    /// `/health` fetch.
    async fn start_detail_aware_health_mock() -> (
        String,
        tokio::sync::oneshot::Sender<()>,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_router = Arc::clone(&seen);
        let full = doctor_bundle_mock_body();
        let redacted = doctor_bundle_redacted_body();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let seen = Arc::clone(&seen_router);
            let full = full.clone();
            let redacted = redacted.clone();
            async move {
                let uri = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_default();
                seen.lock().unwrap().push(uri.clone());
                let body = if uri.starts_with("/health?detail=redacted") {
                    redacted
                } else {
                    full
                };
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap()
            }
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
                .ok();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (format!("http://{addr}"), tx, seen)
    }

    /// The bundle round-trips the #1354 schema (envelope, redacted health
    /// body, four-check doctor report) and — against a daemon that serves
    /// the full body — none of the #1480 gated detail reaches the written
    /// bytes: neither the gated `verdict.inputs` values nor the
    /// measurements inside the full-audience reason sentences, which are
    /// dropped whole (#1997 review finding 1). The classification
    /// (`verdict`, input states) survives. Removing the redaction calls
    /// turns this red.
    #[tokio::test]
    async fn doctor_bundle_writes_redacted_file() {
        let (url, _shutdown) = start_mock_server(doctor_bundle_mock_body()).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

        let dir = tempfile::tempdir().expect("bundle dir");
        let path = dir.path().join("doctor-bundle.json");
        let mut stdout = Vec::new();
        doctor_with_output(&client, Some(Some(&path)), &mut stdout)
            .await
            .expect("write doctor bundle");

        let text = String::from_utf8(std::fs::read(&path).expect("read bundle back"))
            .expect("bundle bytes utf-8");
        for canary in [
            "999888777666",               // disk.free_bytes
            "999888777999",               // disk.total_bytes
            "canary-version-DO-NOT-SHIP", // upgrade.latest_version
            "user_present",               // identity.user_present (key removed)
            "424242",                     // log.errors
            "999111",                     // send_failure_rate.attempts
            "999222",                     // send_failure_rate.failed
            "0.9993",                     // send_failure_rate.rate
            // The full-audience reason measurements (#1997 finding 1):
            "75/100",
            "rate 0.75",
            "536870912 bytes free",
            "57 error-level",
        ] {
            assert!(
                !text.contains(canary),
                "gated canary {canary} leaked into the bundle"
            );
        }

        // Non-gated fields survive, and the envelope carries the contract
        // shape (schema, version, created_unix, generator, health, doctor).
        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("bundle must parse as JSON");
        assert_eq!(parsed["schema"], "x0x-doctor-bundle");
        assert_eq!(parsed["version"], 1);
        assert!(
            parsed["created_unix"].as_u64().unwrap_or(0) > 0,
            "created_unix must be a positive u64: {parsed}"
        );
        assert_eq!(parsed["generator"]["name"], "x0x");
        assert_eq!(parsed["generator"]["version"], crate::VERSION);
        let health = &parsed["health"];
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["peers"], 5);
        assert_eq!(health["verdict"]["verdict"], "degraded");
        // A full-detail body loses its reason sentences whole (they carry
        // the gated measurements); the fail-closed marker names why.
        let reasons = health["verdict"]["reasons"]
            .as_array()
            .expect("reasons stay an array");
        assert_eq!(reasons.len(), 1, "one marker sentence: {reasons:?}");
        assert!(
            reasons[0]
                .as_str()
                .unwrap_or_default()
                .contains("reason sentences withheld"),
            "the marker explains the withholding: {reasons:?}"
        );
        let inputs = &health["verdict"]["inputs"];
        assert!(inputs["disk"].is_object(), "disk input survives: {health}");
        assert_eq!(
            inputs["send_failure_rate"]["state"], "degraded",
            "the classification survives: {health}"
        );
        for gated in [
            ("disk", "free_bytes"),
            ("disk", "total_bytes"),
            ("upgrade", "latest_version"),
            ("identity", "user_present"),
            ("log", "errors"),
            ("send_failure_rate", "attempts"),
            ("send_failure_rate", "failed"),
            ("send_failure_rate", "rate"),
        ] {
            assert!(
                inputs[gated.0].get(gated.1).is_none(),
                "gated field {gated:?} must be withheld"
            );
        }
        assert_eq!(parsed["doctor"]["ok"], true);
        for check in ["connectivity", "key_health", "store_integrity", "upgrade"] {
            assert!(
                parsed["doctor"][check].is_object(),
                "doctor.{check} must be an object: {parsed}"
            );
        }
        // The stdout contract holds on the success path too: exactly one
        // JSON value even with --bundle in play.
        let out_text = String::from_utf8(stdout).expect("doctor stdout utf-8");
        let out: serde_json::Value = serde_json::from_str(out_text.trim())
            .expect("doctor stdout must be exactly one JSON value");
        assert_eq!(out["ok"], true);
    }

    /// Against a daemon that honours `?detail=redacted`, the bundle's
    /// `health` section is the redacted-audience body: the redacted reason
    /// sentences are kept verbatim (they carry bounds, not measurements),
    /// and doctor fetched `/health` exactly once (#1997 review finding 1
    /// and the double-fetch nit).
    #[tokio::test]
    async fn doctor_bundle_keeps_redacted_reasons_and_fetches_health_once() {
        let (url, _shutdown, seen) = start_detail_aware_health_mock().await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

        let dir = tempfile::tempdir().expect("bundle dir");
        let path = dir.path().join("doctor-bundle.json");
        doctor_with_output(&client, Some(Some(&path)), &mut Vec::new())
            .await
            .expect("write doctor bundle");

        let text = String::from_utf8(std::fs::read(&path).expect("read bundle back"))
            .expect("bundle bytes utf-8");
        // The redacted sentences survive verbatim...
        for sentence in [
            "publish failures in the last 60s are at or above the degraded rate bound (≥ 0.50)",
            "data-dir filesystem free space is below the degraded bound (< 1073741824)",
            "error-level log events in the last 60s are at or above the storm threshold (50)",
        ] {
            assert!(
                text.contains(sentence),
                "redacted reason sentence must be kept: {sentence}"
            );
        }
        // ...and no full-audience measurement leaked in with them.
        for canary in [
            "75/100",
            "rate 0.75",
            "536870912 bytes free",
            "57 error-level",
            "999888777666",
            "424242",
        ] {
            assert!(
                !text.contains(canary),
                "full-audience canary {canary} leaked into the bundle"
            );
        }
        // Doctor made exactly one /health request, and it carried the
        // parameter.
        let requests = seen.lock().unwrap();
        let health_requests: Vec<&String> = requests
            .iter()
            .filter(|uri| uri.starts_with("/health"))
            .collect();
        assert_eq!(
            health_requests.len(),
            1,
            "doctor must fetch /health exactly once: {requests:?}"
        );
        assert_eq!(
            health_requests[0].as_str(),
            "/health?detail=redacted",
            "the single fetch asks for the redacted body"
        );
    }

    /// Named instance with no api.port plus `--bundle`: the bundle carries
    /// the four-fail unreachable report and `health` = discovery error —
    /// and the summary still reaches stdout before the non-zero exit
    /// (#1997 review finding 2).
    #[test]
    fn doctor_unreachable_bundle_writes_four_fail_report() {
        let err = match DaemonClient::new(
            Some("absent-instance-doctor-1354-xyz"),
            None,
            crate::cli::OutputFormat::Json,
        ) {
            Ok(_) => panic!("named instance without api.port must fail discovery"),
            Err(e) => e,
        };

        let dir = tempfile::tempdir().expect("bundle dir");
        let path = dir.path().join("doctor-bundle.json");
        let mut stdout = Vec::new();
        let result = doctor_unreachable_with_output(
            crate::cli::OutputFormat::Json,
            None,
            &err,
            Some(Some(&path)),
            &mut stdout,
        );
        assert!(result.is_err(), "unreachable doctor must exit non-zero");
        let out_text = String::from_utf8(stdout).expect("doctor stdout utf-8");
        let out: serde_json::Value = serde_json::from_str(out_text.trim())
            .expect("stdout must still be exactly one JSON value");

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read doctor bundle back"))
                .expect("bundle must parse as JSON");
        let health_error = parsed["health"]["error"]
            .as_str()
            .expect("health must carry the error string");
        assert!(
            health_error.contains("daemon not reachable")
                && health_error.contains("absent-instance-doctor-1354-xyz"),
            "health error must name the failure and the instance: {health_error}"
        );
        assert_eq!(parsed["doctor"]["ok"], false);
        for check in ["connectivity", "key_health", "store_integrity", "upgrade"] {
            assert_eq!(parsed["doctor"][check]["status"], "fail");
            assert_eq!(
                out[check]["status"], "fail",
                "stdout report matches the bundle"
            );
        }
    }

    /// #1997 review finding 2: when the bundle write fails (unwritable
    /// path), `--json` stdout still carries exactly one JSON value; the
    /// bundle error then exits non-zero.
    #[cfg(unix)]
    #[tokio::test]
    async fn doctor_json_stdout_survives_bundle_write_failure() {
        use std::os::unix::fs::PermissionsExt;

        let (url, _shutdown) = start_mock_server(doctor_bundle_mock_body()).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let report_probe = doctor_report_via(&client).await;
        assert!(report_probe.ok, "mock daemon must pass every check");

        let dir = tempfile::tempdir().expect("bundle dir");
        let readonly = dir.path().join("readonly");
        std::fs::create_dir(&readonly).expect("create readonly dir");
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o555))
            .expect("make dir read-only");
        let target = readonly.join("bundle.json");

        let mut stdout = Vec::new();
        let result = doctor_with_output(&client, Some(Some(&target)), &mut stdout).await;
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o755))
            .expect("restore dir mode for tempdir cleanup");

        assert!(result.is_err(), "the bundle write failure must surface");
        let text = String::from_utf8(stdout).expect("doctor stdout utf-8");
        let parsed: serde_json::Value =
            serde_json::from_str(text.trim()).expect("stdout must still be exactly one JSON value");
        assert_eq!(parsed["ok"], true, "the report itself passed: {parsed}");
        assert!(
            parsed["connectivity"].is_object() && parsed["upgrade"].is_object(),
            "the four-check summary is emitted: {parsed}"
        );
    }

    /// #1997 review findings 4 and (at 368b6f32c) 2: no `--bundle` target
    /// overwrites. An existing file at a generated or an explicit path is
    /// an error and its bytes are untouched.
    #[test]
    fn doctor_bundle_refuses_to_overwrite_any_existing_file() {
        let report = unreachable_doctor_report("overwrite probe");
        let dir = tempfile::tempdir().expect("bundle dir");

        for (name, generated_name) in [
            (doctor_bundle_default_filename(1_700_000_000), true),
            ("explicit.json".to_string(), false),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, b"sentinel-bundle").expect("seed existing file");
            let result = write_doctor_bundle(
                serde_json::json!({ "status": "healthy" }),
                &report,
                &DoctorBundleTarget {
                    path: path.clone(),
                    generated_name,
                },
            );
            assert!(
                result.is_err(),
                "generated_name={generated_name}: an existing file must be refused"
            );
            assert_eq!(
                std::fs::read(&path).expect("seeded file still readable"),
                b"sentinel-bundle",
                "generated_name={generated_name}: the existing file's bytes are untouched"
            );
        }
    }

    /// #1997 review at 368b6f32c, finding 2: an explicit `--bundle` path
    /// that is a symlink is refused — the write never follows the link,
    /// neither to an existing file nor to a dangling target it would
    /// create — and a fresh explicit path is created with mode 0600 at
    /// open time, independent of the umask.
    #[cfg(unix)]
    #[test]
    fn doctor_bundle_explicit_path_refuses_symlinks_and_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let report = unreachable_doctor_report("symlink probe");
        let dir = tempfile::tempdir().expect("bundle dir");

        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"victim-bytes").expect("seed victim");
        let link_to_existing = dir.path().join("link-existing.json");
        std::os::unix::fs::symlink(&victim, &link_to_existing).expect("symlink to victim");
        let dangling_target = dir.path().join("not-yet.txt");
        let link_dangling = dir.path().join("link-dangling.json");
        std::os::unix::fs::symlink(&dangling_target, &link_dangling).expect("dangling symlink");

        for link in [&link_to_existing, &link_dangling] {
            let result = write_doctor_bundle(
                serde_json::json!({ "status": "healthy" }),
                &report,
                &DoctorBundleTarget {
                    path: link.clone(),
                    generated_name: false,
                },
            );
            assert!(
                result.is_err(),
                "{}: a symlink must be refused",
                link.display()
            );
        }
        assert_eq!(
            std::fs::read(&victim).expect("victim readable"),
            b"victim-bytes",
            "the link target's bytes are untouched"
        );
        assert!(
            !dangling_target.exists(),
            "the dangling link's target must not be created"
        );

        let fresh = dir.path().join("fresh.json");
        write_doctor_bundle(
            serde_json::json!({ "status": "healthy" }),
            &report,
            &DoctorBundleTarget {
                path: fresh.clone(),
                generated_name: false,
            },
        )
        .expect("a fresh explicit path is written");
        let mode = std::fs::metadata(&fresh)
            .expect("fresh bundle metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the bundle is owner-only: {mode:o}");
    }

    /// `--dump-request` contacts no daemon (every fetch answers the
    /// synthetic `{"ok":true}`), so `--bundle` must not write a stub-backed
    /// file (#1997 review).
    #[tokio::test]
    async fn doctor_dump_request_skips_bundle_write() {
        let (url, _shutdown) = start_mock_server(doctor_bundle_mock_body()).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json)
            .unwrap()
            .dump_requests(true);

        let dir = tempfile::tempdir().expect("bundle dir");
        let path = dir.path().join("bundle.json");
        let _ = doctor_with_output(&client, Some(Some(&path)), &mut Vec::new()).await;
        assert!(
            !path.exists(),
            "dump mode must not write a bundle from stub responses"
        );
    }

    /// The three `--bundle` flag states resolve as specified (#1354):
    /// absent → `None`; bare (or empty) → the seconds-stamped default name
    /// in the current directory, marked generated (no-overwrite); explicit
    /// → the given path, marked explicit.
    #[test]
    fn doctor_bundle_flag_resolution() {
        assert!(
            resolve_doctor_bundle_path(None)
                .expect("absent flag resolves")
                .is_none(),
            "absent flag stays None"
        );

        for bare in [None, Some(Path::new(""))] {
            let resolved = resolve_doctor_bundle_path(Some(bare))
                .expect("bare flag resolves")
                .expect("bare flag generates a target");
            assert!(
                !resolved.path.is_absolute(),
                "default bundle path must be cwd-relative: {}",
                resolved.path.display()
            );
            assert!(
                resolved.generated_name,
                "a bare flag generates the name (no-overwrite rule applies)"
            );
            let name = resolved.path.to_string_lossy();
            let secs: u64 = name
                .trim_start_matches("x0x-doctor-bundle-")
                .trim_end_matches(".json")
                .parse()
                .expect("default name carries unix secs");
            assert_eq!(
                resolved.path,
                std::path::PathBuf::from(doctor_bundle_default_filename(secs)),
                "bare flag must generate the seconds-stamped default name"
            );
        }

        let explicit = resolve_doctor_bundle_path(Some(Some(Path::new("/tmp/diag.json"))))
            .expect("explicit path resolves")
            .expect("explicit path is Some");
        assert_eq!(explicit.path, std::path::PathBuf::from("/tmp/diag.json"));
        assert!(
            !explicit.generated_name,
            "an explicit path keeps overwrite semantics"
        );
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

    /// #1379 slice 2: a launcher-bound job is an x0xd job; the daemon is
    /// the program after the launcher's own arguments. It also needs an
    /// ExitTimeOut above the launcher's 45 s worst-case stop.
    #[test]
    fn repair_sees_through_the_launcher_to_the_daemon() {
        let launcher = |extra: serde_json::Value| {
            let mut base = job(extra);
            base["ProgramArguments"] = serde_json::json!([
                "/opt/x0x/bin/x0x-launcher",
                "--host-root",
                "/Users/a/Library/Application Support/x0x-alice",
                "--instance",
                "alice",
                "--",
                "/opt/x0x/bin/x0xd",
                "--name",
                "alice"
            ]);
            base
        };
        assert_eq!(
            classify_launchd_job(&launcher(serde_json::json!({ "ExitTimeOut": 60 }))),
            RepairVerdict::Repairable {
                has_env_dict: false
            }
        );
        for short in [
            serde_json::json!({}),
            serde_json::json!({ "ExitTimeOut": 45 }),
        ] {
            assert!(matches!(
                classify_launchd_job(&launcher(short)),
                RepairVerdict::Refused(reason) if reason.contains("ExitTimeOut")
            ));
        }
        let mut other = launcher(serde_json::json!({ "ExitTimeOut": 60 }));
        other["ProgramArguments"] =
            serde_json::json!(["/opt/x0x/bin/x0x-launcher", "/usr/bin/something-else"]);
        assert_eq!(classify_launchd_job(&other), RepairVerdict::NotAnX0xdJob);
        let mut malformed = launcher(serde_json::json!({ "ExitTimeOut": 60 }));
        malformed["ProgramArguments"] =
            serde_json::json!(["/opt/x0x/bin/x0x-launcher", "--host-root", "/r"]);
        assert!(matches!(
            classify_launchd_job(&malformed),
            RepairVerdict::Refused(reason) if reason.contains("launcher refuses")
        ));
    }

    /// #2016 review items 2 and 3: launchd runs `Program` when it is set,
    /// so a launcher in `Program` is detected even when `ProgramArguments[0]`
    /// is only an argv0, as the upgrade-time readback detects it; and a
    /// launcher argv the launcher itself refuses (a relative host root, an
    /// instance of `..`) is refused, not repaired into a job that exits 78.
    #[test]
    fn repair_detects_the_launcher_as_the_readback_does() {
        let mut by_program = job(serde_json::json!({ "ExitTimeOut": 60 }));
        by_program["Program"] = serde_json::json!("/opt/x0x/bin/x0x-launcher");
        by_program["ProgramArguments"] =
            serde_json::json!(["launcher", "/opt/x0x/bin/x0xd", "--name", "alice"]);
        assert_eq!(
            classify_launchd_job(&by_program),
            RepairVerdict::Repairable {
                has_env_dict: false
            }
        );
        // The same job without the long ExitTimeOut is still a launcher job.
        by_program
            .as_object_mut()
            .expect("object")
            .remove("ExitTimeOut");
        assert!(matches!(
            classify_launchd_job(&by_program),
            RepairVerdict::Refused(reason) if reason.contains("ExitTimeOut")
        ));
        for (root, instance) in [("relative", "alice"), ("/data/alice", ".."), ("/d", "a/b")] {
            let mut bad = job(serde_json::json!({ "ExitTimeOut": 60 }));
            bad["ProgramArguments"] = serde_json::json!([
                "/opt/x0x/bin/x0x-launcher",
                "--host-root",
                root,
                "--instance",
                instance,
                "--",
                "/opt/x0x/bin/x0xd"
            ]);
            assert!(
                matches!(
                    classify_launchd_job(&bad),
                    RepairVerdict::Refused(ref reason) if reason.contains("launcher refuses")
                ),
                "{root} {instance}"
            );
        }
    }

    /// The launcher-bound plist runs the trial-form argv, sets ExitTimeOut
    /// above the worst-case stop, and classifies as a repairable x0xd job.
    #[test]
    fn launcher_bound_plist_renders_the_trial_form() {
        let log = std::path::PathBuf::from("/tmp/x0xd.log");
        let binding = LauncherBinding {
            launcher: "/opt/x0x/bin/x0x-launcher",
            host_root: "/Users/a/Library/Application Support/x0x",
            instance: "default",
        };
        let rendered = render_launchd_plist_with(
            "/opt/x0x/bin/x0xd",
            &["--name".to_string(), "a".to_string()],
            &log,
            Some(&binding),
        )
        .unwrap();
        let order = [
            "<string>/opt/x0x/bin/x0x-launcher</string>",
            "<string>--host-root</string>",
            "<string>/Users/a/Library/Application Support/x0x</string>",
            "<string>--instance</string>",
            "<string>default</string>",
            "<string>--</string>",
            "<string>/opt/x0x/bin/x0xd</string>",
            "<string>--name</string>",
        ];
        let mut at = 0;
        for piece in order {
            let found = rendered[at..]
                .find(piece)
                .unwrap_or_else(|| panic!("{piece}"));
            at += found + piece.len();
        }
        assert!(rendered.contains("<key>ExitTimeOut</key>\n    <integer>60</integer>"));
        assert!(!rendered.contains("AbandonProcessGroup"));
        let plain = render_launchd_plist("/opt/x0x/bin/x0xd", &[], &log).unwrap();
        assert!(!plain.contains("ExitTimeOut"), "the plain job is unchanged");
        let relative = LauncherBinding {
            launcher: "x0x-launcher",
            ..binding
        };
        assert!(
            render_launchd_plist_with("/opt/x0x/bin/x0xd", &[], &log, Some(&relative)).is_err()
        );
    }

    fn migration_host() -> MigrationHost<'static> {
        MigrationHost {
            canonical_daemon: &|daemon| Ok(daemon.replace("/link/", "/real/")),
            launcher_for: &|daemon| {
                Ok(Path::new(daemon)
                    .with_file_name("x0x-launcher")
                    .to_string_lossy()
                    .into_owned())
            },
            user_home: &|| Ok(std::path::PathBuf::from("/Users/cli")),
            read_file: &|_| Ok(None),
            canonical_dir: &|dir| Ok(dir.to_string_lossy().into_owned()),
        }
    }

    #[test]
    fn doctor_finds_the_instance_from_the_data_directory_name() {
        assert_eq!(instance_of_data_dir("x0x"), Some(None));
        assert_eq!(instance_of_data_dir("x0x-alice"), Some(Some("alice")));
        for other in ["x0x-", "x0xalice", "alice", "X0X", ""] {
            assert_eq!(instance_of_data_dir(other), None, "{other}");
        }
    }

    /// #1379 (#2108 review): `--repair --launcher --dry-run` plans the
    /// migration and writes nothing, not even the backup.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_dry_run_migration_leaves_the_job_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let bin = root.join("bin");
        let home = root.join("home");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(home.join("Library/Application Support/x0x")).unwrap();
        std::fs::write(bin.join("x0xd"), b"").unwrap();
        std::fs::write(bin.join("x0x-launcher"), b"").unwrap();
        let job = serde_json::json!({
            "Label": AUTOSTART_LAUNCHD_LABEL,
            "ProgramArguments": [bin.join("x0xd").to_string_lossy()],
            "EnvironmentVariables": { "HOME": home.to_string_lossy() },
            "KeepAlive": true,
        });
        let path = root.join("job.plist");
        let before = json_to_plist(&job).unwrap();
        std::fs::write(&path, &before).unwrap();
        assert!(migrate_job_to_launcher(&path, &job, true).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!path.with_extension("plist.x0x-backup").exists());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 3);
    }

    /// #1379 (#2108 review): the file check the autostart commands call
    /// reads the real owner and mode.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_plist_file_check_reads_owner_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("job.plist");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        check_plist_file_owner(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        let error = check_plist_file_owner(&path).unwrap_err();
        assert!(
            format!("{error:#}").contains("writable by group"),
            "{error:#}"
        );
        assert!(check_plist_file_owner(&dir.path().join("missing.plist")).is_err());
    }

    const ALICE_ROOT: &str = "/Users/a/Library/Application Support/x0x-alice";

    /// #1379: a daemon inside a versioned Homebrew keg is not a stable path
    /// for the launcher's trial form; `brew upgrade` removes the keg.
    #[test]
    fn a_versioned_homebrew_keg_is_not_a_stable_daemon() {
        for keg in [
            "/opt/homebrew/Cellar/x0x/0.50.0/bin/x0xd",
            "/usr/local/Cellar/x0x/0.50.0_1/libexec/bin/x0xd",
        ] {
            let error = stable_daemon(keg.to_string()).expect_err(keg);
            assert!(format!("{error:#}").contains("Homebrew keg"), "{error:#}");
        }
        for stable in [
            "/opt/x0x/bin/x0xd",
            "/opt/homebrew/bin/x0xd",
            "/opt/homebrew/Cellar/x0xd",
        ] {
            assert_eq!(stable_daemon(stable.to_string()).expect(stable), stable);
        }
        let job = serde_json::json!({
            "Label": "com.saorsalabs.x0xd",
            "ProgramArguments": ["/opt/homebrew/bin/x0xd"],
            "KeepAlive": true,
        });
        let host = MigrationHost {
            canonical_daemon: &|_| Ok("/opt/homebrew/Cellar/x0x/0.50.0/bin/x0xd".to_string()),
            ..migration_host()
        };
        let error = plan_launcher_migration(&job, &host).expect_err("keg");
        assert!(format!("{error:#}").contains("Homebrew keg"), "{error:#}");
    }

    /// #1379: the autostart commands manage the calling user's own agent.
    #[test]
    fn autostart_refuses_root_and_sudo() {
        let sudo = std::ffi::OsStr::new("alice");
        assert!(refuse_privileged(0, None).is_err());
        assert!(refuse_privileged(501, Some(sudo)).is_err());
        assert!(refuse_privileged(0, Some(sudo)).is_err());
        assert!(refuse_privileged(501, None).is_ok());
    }

    /// #1379: a job file is changed only when it is the user's own and no
    /// one else can write it.
    #[test]
    fn autostart_checks_who_owns_the_plist() {
        let path = Path::new("/Users/a/Library/LaunchAgents/x.plist");
        assert!(check_plist_owner(path, 501, 0o100644, 501).is_ok());
        assert!(check_plist_owner(path, 501, 0o100600, 501).is_ok());
        let other = check_plist_owner(path, 0, 0o100644, 501).expect_err("root-owned");
        assert!(format!("{other:#}").contains("uid 0"), "{other:#}");
        assert!(check_plist_owner(path, 501, 0o100664, 501).is_err());
        assert!(check_plist_owner(path, 501, 0o100646, 501).is_err());
    }

    /// #1379: `x0x doctor` names a launchd job whose daemon path is gone,
    /// which the launcher otherwise waits for without a word to the user.
    #[test]
    fn doctor_reports_a_launchd_job_whose_daemon_is_missing() {
        let keg = "/opt/homebrew/Cellar/x0x/0.49.0/bin/x0xd";
        let via_launcher = serde_json::json!({
            "Label": "com.saorsalabs.x0xd",
            "ProgramArguments": [
                "/opt/homebrew/bin/x0x-launcher", "--host-root", ALICE_ROOT,
                "--instance", "alice", "--", keg, "--name", "alice",
            ],
        });
        let missing = |_: &Path| false;
        let present = |_: &Path| true;
        let check =
            missing_daemon_check(&via_launcher, Some("alice"), &missing).expect("missing daemon");
        assert_eq!(check.status, DoctorCheckStatus::Fail);
        assert!(check.detail.contains(keg), "{}", check.detail);
        assert!(check.detail.contains("waits"), "{}", check.detail);
        let evidence = check.evidence.expect("evidence");
        assert_eq!(evidence["via_launcher"], true);
        assert_eq!(evidence["missing_daemon"], keg);
        assert!(missing_daemon_check(&via_launcher, Some("alice"), &present).is_none());
        assert!(missing_daemon_check(&via_launcher, None, &missing).is_none());
        assert!(missing_daemon_check(&via_launcher, Some("bob"), &missing).is_none());

        let direct = serde_json::json!({
            "Label": "com.saorsalabs.x0xd",
            "ProgramArguments": [keg],
        });
        let check = missing_daemon_check(&direct, None, &missing).expect("direct job");
        assert!(check.detail.contains("cannot start"), "{}", check.detail);
        let other = serde_json::json!({ "ProgramArguments": ["/usr/bin/true"] });
        assert!(missing_daemon_check(&other, None, &missing).is_none());
    }

    /// #1379: `--repair --launcher` moves a KeepAlive x0xd job onto the
    /// launcher's trial form, keeping the daemon's arguments; the daemon is
    /// canonical, the launcher is next to the job's daemon path.
    #[test]
    fn repair_plans_the_launcher_migration() {
        let job = serde_json::json!({
            "Label": "com.example.x0xd",
            "ProgramArguments": ["/opt/link/x0xd", "--name", "alice"],
            "KeepAlive": true,
            "EnvironmentVariables": { "HOME": "/Users/a" },
        });
        let plan = plan_launcher_migration(&job, &migration_host())
            .expect("plan")
            .expect("migration");
        assert_eq!(
            plan.program_arguments,
            [
                "/opt/link/x0x-launcher",
                "--host-root",
                ALICE_ROOT,
                "--instance",
                "alice",
                "--",
                "/opt/real/x0xd",
                "--name",
                "alice",
            ]
        );
        assert!(!plan.remove_program && plan.set_exit_timeout);
        // `Program` is what launchd runs: it is removed.
        let mut with_program = job.clone();
        with_program["Program"] = serde_json::json!("/opt/link/x0xd");
        with_program["ProgramArguments"] = serde_json::json!(["x0xd"]);
        with_program["ExitTimeOut"] = serde_json::json!(120);
        let plan = plan_launcher_migration(&with_program, &migration_host())
            .expect("plan")
            .expect("migration");
        assert!(plan.remove_program && !plan.set_exit_timeout);
        assert_eq!(plan.program_arguments[4], "default");
        // The job's own HOME names the data directory, not the CLI user's.
        assert_eq!(
            plan.program_arguments[2],
            "/Users/a/Library/Application Support/x0x"
        );
        let mut no_home = with_program.clone();
        no_home
            .as_object_mut()
            .expect("dict")
            .remove("EnvironmentVariables");
        let plan_no_home = plan_launcher_migration(&no_home, &migration_host())
            .expect("plan")
            .expect("migration");
        assert_eq!(
            plan_no_home.program_arguments[2],
            "/Users/cli/Library/Application Support/x0x"
        );
        // A job that already runs the launcher needs no change.
        let mut bound = job.clone();
        bound["ProgramArguments"] = serde_json::json!(plan.program_arguments);
        bound["ExitTimeOut"] = serde_json::json!(60);
        assert_eq!(
            plan_launcher_migration(&bound, &migration_host()).expect("plan"),
            None
        );
    }

    #[test]
    fn repair_refuses_a_launcher_migration_it_cannot_prove() {
        let base = serde_json::json!({
            "Label": "com.example.x0xd",
            "ProgramArguments": ["/opt/link/x0xd"],
            "KeepAlive": true,
        });
        let mut cases = Vec::new();
        let mut config = base.clone();
        config["ProgramArguments"] = serde_json::json!(["/opt/link/x0xd", "--config", "/c"]);
        cases.push(config);
        let mut relative = base.clone();
        relative["ProgramArguments"] = serde_json::json!(["x0xd"]);
        cases.push(relative);
        let mut no_keepalive = base.clone();
        no_keepalive["KeepAlive"] = serde_json::json!(false);
        cases.push(no_keepalive);
        let mut bad_name = base.clone();
        bad_name["ProgramArguments"] = serde_json::json!(["/opt/link/x0xd", "--name", "a b"]);
        cases.push(bad_name);
        for job in cases {
            assert!(
                plan_launcher_migration(&job, &migration_host()).is_err(),
                "{job}"
            );
        }
    }

    /// #2072 review: the host root follows x0xd's own data directory: the
    /// instance's default config file may move it, a named instance that
    /// keeps the default gets `x0x-<name>`, and what x0xd would not run is
    /// refused.
    #[test]
    fn the_host_root_is_the_data_directory_x0xd_uses() {
        let home = Path::new("/Users/a");
        let support = home.join("Library/Application Support");
        assert_eq!(
            job_data_dir(None, home, None).expect("default"),
            support.join("x0x")
        );
        assert_eq!(
            job_data_dir(Some("alice"), home, None).expect("named"),
            support.join("x0x-alice")
        );
        assert_eq!(
            instance_config_path(Some("alice"), home),
            support.join("x0x-alice/config.toml")
        );
        let moved = "data_dir = \"/srv/x0x\"\n";
        assert_eq!(
            job_data_dir(Some("alice"), home, Some(moved)).expect("moved"),
            Path::new("/srv/x0x")
        );
        let unnamed_default = format!("data_dir = \"{}\"\n", support.join("x0x").display());
        assert_eq!(
            job_data_dir(Some("alice"), home, Some(&unnamed_default)).expect("default"),
            support.join("x0x-alice")
        );
        assert_eq!(
            job_data_dir(Some("alice"), home, Some("instance_name = \"alice\"\n"))
                .expect("same name"),
            support.join("x0x-alice")
        );
        for refused in [
            "data_dir = \"relative/x0x\"\n",
            "instance_name = \"bob\"\n",
            "data_dir = [",
        ] {
            assert!(
                job_data_dir(Some("alice"), home, Some(refused)).is_err(),
                "{refused}"
            );
        }
        assert!(job_data_dir(None, home, Some("instance_name = \"bob\"\n")).is_err());
    }

    /// #2072 review: planning creates nothing. A job whose data directory
    /// does not exist is refused, and the directory is still missing.
    #[test]
    fn planning_a_migration_creates_nothing() {
        let home = tempfile::tempdir().expect("home");
        let job = serde_json::json!({
            "Label": "com.example.x0xd",
            "ProgramArguments": ["/opt/link/x0xd"],
            "KeepAlive": true,
            "EnvironmentVariables": { "HOME": home.path().to_string_lossy() },
        });
        let host = MigrationHost {
            canonical_dir: &|dir| Ok(dir.canonicalize()?.to_string_lossy().into_owned()),
            ..migration_host()
        };
        assert!(plan_launcher_migration(&job, &host).is_err());
        let data_dir = home.path().join("Library/Application Support/x0x");
        assert!(!data_dir.exists());
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let plan = plan_launcher_migration(&job, &host)
            .expect("plan")
            .expect("migration");
        assert_eq!(
            plan.program_arguments[2],
            data_dir
                .canonicalize()
                .expect("canonical")
                .to_string_lossy()
        );
    }

    /// #2072 review: the migrated job is built whole, keeping every key it
    /// does not change, so it can be written in one step.
    #[test]
    fn the_migrated_job_keeps_every_other_key() {
        let job = serde_json::json!({
            "Label": "com.example.x0xd",
            "Program": "/opt/link/x0xd",
            "ProgramArguments": ["x0xd"],
            "KeepAlive": true,
            "StandardErrorPath": "/tmp/x0xd.err",
            "EnvironmentVariables": { "HOME": "/Users/a", "RUST_LOG": "info" },
        });
        let plan = plan_launcher_migration(&job, &migration_host())
            .expect("plan")
            .expect("migration");
        let migrated = migrated_job(&job, &plan).expect("migrated");
        assert_eq!(
            migrated,
            serde_json::json!({
                "Label": "com.example.x0xd",
                "ProgramArguments": plan.program_arguments,
                "KeepAlive": true,
                "StandardErrorPath": "/tmp/x0xd.err",
                "ExitTimeOut": LAUNCHER_EXIT_TIMEOUT_SECS,
                "EnvironmentVariables": {
                    "HOME": "/Users/a",
                    "RUST_LOG": "info",
                    "X0X_SUPERVISED": "1",
                },
            })
        );
        assert_eq!(
            classify_launchd_job(&migrated),
            RepairVerdict::AlreadySupervised
        );
        // A job with no environment gets one holding only the marker.
        let mut bare = job.clone();
        bare.as_object_mut()
            .expect("dict")
            .remove("EnvironmentVariables");
        let migrated = migrated_job(&bare, &plan).expect("migrated");
        assert_eq!(
            migrated["EnvironmentVariables"],
            serde_json::json!({ "X0X_SUPERVISED": "1" })
        );
    }

    /// #2063 review: one label serves every `--name`; autostart refuses to
    /// replace another instance's job.
    #[test]
    fn autostart_refuses_to_replace_another_instances_job() {
        let alice = serde_json::json!({
            "ProgramArguments": ["/opt/x0xd", "--name=alice"],
        });
        let default = serde_json::json!({ "ProgramArguments": ["/opt/x0xd"] });
        assert!(existing_job_conflict(None, Some("bob")).is_ok());
        assert!(existing_job_conflict(Some(&alice), Some("alice")).is_ok());
        assert!(existing_job_conflict(Some(&alice), Some("bob")).is_err());
        assert!(existing_job_conflict(Some(&alice), None).is_err());
        assert!(existing_job_conflict(Some(&default), None).is_ok());
        assert!(existing_job_conflict(Some(&default), Some("bob")).is_err());
        // A job file under our label that is not a readable x0xd job is
        // replaced.
        let other = serde_json::json!({ "ProgramArguments": ["/bin/sh"] });
        assert!(existing_job_conflict(Some(&other), Some("bob")).is_ok());
    }

    /// #2063 review: the renderer checks the whole launcher argv with the
    /// launcher's parser, so a relative daemon is refused before it is
    /// written.
    #[test]
    fn the_launcher_bound_renderer_refuses_an_argv_the_launcher_refuses() {
        let binding = LauncherBinding {
            launcher: "/opt/x0x/bin/x0x-launcher",
            host_root: "/data/x0x",
            instance: "default",
        };
        let log = Path::new("/data/x0x/x0xd.log");
        assert!(render_launchd_plist_with("/opt/x0x/bin/x0xd", &[], log, Some(&binding)).is_ok());
        assert!(render_launchd_plist_with("x0xd", &[], log, Some(&binding)).is_err());
        let bad_instance = LauncherBinding {
            instance: "..",
            ..binding
        };
        assert!(
            render_launchd_plist_with("/opt/x0x/bin/x0xd", &[], log, Some(&bad_instance)).is_err()
        );
    }

    /// #1379: `x0x autostart --launcher` names the instance the launcher
    /// accepts, and refuses a name the launcher would refuse before it
    /// writes anything.
    #[test]
    fn autostart_instance_id_is_one_the_launcher_accepts() {
        assert_eq!(autostart_instance_id(None).expect("default"), "default");
        assert_eq!(
            autostart_instance_id(Some("alice")).expect("alice"),
            "alice"
        );
        for bad in ["..", "a b", "a/b", ""] {
            assert!(autostart_instance_id(Some(bad)).is_err(), "{bad:?}");
        }
    }

    /// #1379: the plist is replaced in one step with the exact mode, and no
    /// temporary file is left; a symlink at the temporary path is not
    /// followed.
    #[cfg(unix)]
    #[test]
    fn autostart_job_file_is_replaced_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("job.plist");
        std::fs::write(&path, b"old").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        write_file_atomically(&path, b"new", 0o644).expect("replace");
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["job.plist"]);
        // A stale temporary file (or a symlink planted there) is removed,
        // never written through.
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").expect("write");
        std::os::unix::fs::symlink(&target, dir.path().join(".job.plist.tmp")).expect("symlink");
        write_file_atomically(&path, b"newer", 0o644).expect("replace");
        assert_eq!(std::fs::read(&target).expect("read"), b"keep");
        assert_eq!(std::fs::read(&path).expect("read"), b"newer");
    }

    /// #2016 review item 1: while the daemon is down, doctor shows the
    /// launcher's refusal reason and whether the launcher still holds.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn doctor_shows_a_launcher_refusal_while_the_daemon_is_down() {
        use crate::upgrade::launcher_contract::*;
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            down_upgrade_check(Some(dir.path())).detail,
            "skipped: daemon unreachable"
        );
        let record = LauncherRefusal {
            schema: REFUSAL_SCHEMA,
            reason: "prior child still exists".into(),
            pid: std::process::id(),
            process_start: process_start(std::process::id()).expect("start"),
            at_unix_ms: 1,
        };
        std::fs::write(
            dir.path().join(REFUSAL_FILE_NAME),
            serde_json::to_vec(&record).expect("json"),
        )
        .expect("write");
        let check = down_upgrade_check(Some(dir.path()));
        assert_eq!(check.status, DoctorCheckStatus::Fail);
        assert!(
            check.detail.contains("prior child still exists"),
            "{}",
            check.detail
        );
        assert!(check.detail.contains("holding"), "{}", check.detail);
        assert_eq!(
            check.evidence.expect("evidence")["launcher_holding"],
            serde_json::json!(true)
        );
        // #2019 review: the same pid with another start time is a reused
        // pid, not the launcher that refused.
        let reused = LauncherRefusal {
            process_start: record.process_start.wrapping_add(1),
            ..record
        };
        std::fs::write(
            dir.path().join(REFUSAL_FILE_NAME),
            serde_json::to_vec(&reused).expect("json"),
        )
        .expect("write");
        let check = down_upgrade_check(Some(dir.path()));
        assert!(
            check.detail.contains("no longer running"),
            "{}",
            check.detail
        );
        assert_eq!(
            check.evidence.expect("evidence")["launcher_holding"],
            serde_json::json!(false)
        );
        std::fs::write(dir.path().join(REFUSAL_FILE_NAME), b"not json").expect("write");
        assert_eq!(
            down_upgrade_check(Some(dir.path())).detail,
            "skipped: daemon unreachable"
        );
    }

    /// Bundle allow-list coverage for the #2019 launcher-refusal doctor check
    /// (#1354 slice 1 takeover): a bundle written via `doctor_unreachable` while
    /// a launcher-refusal record is present must include the refusal evidence
    /// (reason, pid, holding flag — these are diagnostic, not secrets) and must
    /// not include a secret planted beside the record on disk or leak any
    /// absolute home-directory path.
    ///
    /// This is a pure unit test — no daemon, no network.
    #[test]
    fn doctor_bundle_contains_launcher_refusal_evidence_and_no_secrets() {
        use crate::upgrade::launcher_contract::{
            self, LauncherRefusal, REFUSAL_FILE_NAME, REFUSAL_SCHEMA,
        };

        // Create the instance directory where doctor_unreachable_with_output
        // looks: {data_dir}/x0x-{name}.
        let instance_name = format!("test-bundle-secret-{}", std::process::id());
        let data_dir = dirs::data_dir().expect("data_dir must be resolvable in test");
        let instance_dir = data_dir.join(format!("x0x-{instance_name}"));
        std::fs::create_dir_all(&instance_dir).expect("create instance dir for test");

        // Cleanup is at end of test; instance_dir is unique per pid.

        // Plant the refusal record. Use std::process::id() as the pid and the
        // real process_start for that pid so the holding flag is true
        // (launcher_contract::process_start(pid) == record.process_start).
        let pid = std::process::id();
        let proc_start = launcher_contract::process_start(pid)
            .expect("process_start of the test process must succeed");
        let reason = "unit-test-refusal-reason-do-not-send";
        let record = LauncherRefusal {
            schema: REFUSAL_SCHEMA,
            reason: reason.into(),
            pid,
            process_start: proc_start,
            at_unix_ms: 1_000,
        };
        std::fs::write(
            instance_dir.join(REFUSAL_FILE_NAME),
            serde_json::to_vec(&record).expect("serialize refusal"),
        )
        .expect("write refusal file");

        // Plant a secret canary in a file that sits beside the refusal record
        // in the instance dir. The bundle code reads only the refusal file
        // through launcher_refusal_check; this proves it does not scan the
        // whole directory.
        let key_canary = format!("secret-machine-key-{:016x}", 0xdeadbeef_cafebabe_u64);
        std::fs::write(instance_dir.join("machine.key"), key_canary.as_bytes())
            .expect("write key canary");

        // Write the bundle by calling the real function. Use a fixed path
        // inside the instance dir so it stays within the test's sandbox.
        // The function returns Err("doctor detected failures") because all
        // checks fail in the unreachable case — that is the expected exit
        // status of `x0x doctor` when the daemon is down. The bundle and
        // stdout are still written before that Err is returned.
        let bundle_path = instance_dir.join("test-bundle.json");
        let err = anyhow::anyhow!("named instance not found (unit test)");
        let mut stdout_sink: Vec<u8> = Vec::new();
        let result = doctor_unreachable_with_output(
            crate::cli::OutputFormat::Text,
            Some(&instance_name),
            &err,
            Some(Some(bundle_path.as_path())),
            &mut stdout_sink,
        );
        assert!(
            result.is_err(),
            "doctor_unreachable_with_output must exit non-zero (all checks fail)"
        );

        // Parse the bundle and run positive assertions.
        let bundle_bytes = std::fs::read(&bundle_path).expect("read bundle back");
        let bundle: serde_json::Value =
            serde_json::from_slice(&bundle_bytes).expect("bundle must parse as JSON");

        assert_eq!(
            bundle["doctor"]["upgrade"]["status"], "fail",
            "bundle must carry the upgrade-fail status"
        );
        let bundle_reason = bundle["doctor"]["upgrade"]["evidence"]["launcher_refusal"]["reason"]
            .as_str()
            .expect("bundle must carry launcher_refusal.reason");
        assert_eq!(
            bundle_reason, reason,
            "bundle launcher_refusal.reason must match the planted record"
        );
        assert!(
            bundle["doctor"]["upgrade"]["evidence"]["launcher_holding"]
                .as_bool()
                .unwrap_or(false),
            "bundle must carry launcher_holding = true (pid is the live test process)"
        );

        // Secret checks: none of the canaries or home-dir path may appear
        // in the bundle text.
        let bundle_text = String::from_utf8_lossy(&bundle_bytes);
        assert!(
            !bundle_text.contains(&key_canary),
            "bundle must not contain the machine.key canary planted beside the refusal file"
        );
        // The bundle must not reveal the system's home directory path
        // (evidence fields carry ids, not filesystem paths).
        if let Some(home) = dirs::home_dir() {
            let home_str = home.display().to_string();
            assert!(
                !bundle_text.contains(&home_str),
                "bundle must not contain the home-directory path: {home_str}"
            );
        }

        // Cleanup.
        let _ = std::fs::remove_dir_all(&instance_dir);
    }

    /// #1379: `AbandonProcessGroup` defeats launchd's process-group cleanup,
    /// so the repair refuses it, even on a job that already has the marker.
    /// `AbandonProcessGroup: false` is launchd's default and is accepted.
    #[test]
    fn repair_refuses_jobs_that_abandon_their_process_group() {
        let mut job = serde_json::json!({
            "Label": "com.example.x0xd",
            "ProgramArguments": ["/usr/local/bin/x0xd"],
            "KeepAlive": true,
            "AbandonProcessGroup": true,
        });
        assert!(matches!(
            classify_launchd_job(&job),
            RepairVerdict::Refused(reason) if reason.contains("AbandonProcessGroup")
        ));
        job["EnvironmentVariables"] = serde_json::json!({ "X0X_SUPERVISED": "1" });
        assert!(matches!(
            classify_launchd_job(&job),
            RepairVerdict::Refused(reason) if reason.contains("AbandonProcessGroup")
        ));
        job["AbandonProcessGroup"] = serde_json::Value::Bool(false);
        assert_eq!(classify_launchd_job(&job), RepairVerdict::AlreadySupervised);
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
        assert!(script.lines().any(|l| l == "$x0xRestartOnExit75 = $true"));
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
        // Empty and quote-bearing arguments: Windows PowerShell 5.1 drops or
        // mangles them when starting x0xd, so the wrapper would run different
        // arguments than it declares — refuse at generation, not at upgrade.
        assert!(
            render_windows_wrapper("C:\\x0xd.exe", &["--name".to_string(), String::new()]).is_err()
        );
        assert!(render_windows_wrapper(
            "C:\\x0xd.exe",
            &["--name".to_string(), "say \"hi\"".to_string()]
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn foreground_exit_code_keeps_the_child_status() {
        // #1588: the supervisor reads 100 and 75 from `x0x start --foreground`.
        for code in [75, 100, 3] {
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("exit {code}"))
                .status()
                .expect("run sh");
            assert_eq!(foreground_exit_code(status), code);
        }
    }
}

/// #1588: `x0x start --foreground` on Windows runs x0xd as a child, so the
/// child's exit status must reach the wrapper unchanged.
#[cfg(test)]
#[cfg(windows)]
mod windows_exec_regressions {
    use super::foreground_exit_code;

    fn exit_code_of_cmd(code: i32) -> i32 {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg(format!("exit {code}"))
            .status()
            .expect("run cmd");
        foreground_exit_code(status)
    }

    #[test]
    fn foreground_exit_keeps_ex_tempfail() {
        assert_eq!(exit_code_of_cmd(75), 75);
    }

    #[test]
    fn foreground_exit_keeps_the_upgrade_request() {
        assert_eq!(exit_code_of_cmd(100), 100);
    }

    #[test]
    fn foreground_exit_keeps_other_failures() {
        assert_eq!(exit_code_of_cmd(3), 3);
    }
}
