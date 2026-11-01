//! Read-only GitHub release checks. Installation belongs to the daemon.
//!
//! `--check` and `--apply` honour `--name` and `--api`. The daemon version
//! comes from that daemon's loopback `GET /health`, using the same address
//! discovery as [`crate::cli::DaemonClient`]. The split-install check asks
//! whether this CLI sits beside the daemon that is running. It reads that
//! executable from the selected instance's process. It does not ask the
//! daemon for a path. When that executable cannot be read, the check says
//! it cannot tell. An available update still names `x0x upgrade --apply`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;

use crate::cli::DaemonClient;
use crate::upgrade::apply::{self, CLI_REINSTALL_HINT};
use crate::upgrade::monitor::UpgradeMonitor;
use crate::upgrade::UpgradeError;

const REPO: &str = "saorsa-labs/x0x";

/// Quiet result when the running daemon executable cannot be read.
pub(crate) const CANNOT_TELL_SPLIT: &str =
    "Cannot tell whether this CLI sits beside the running daemon.";

/// Next step when an update is available and apply can still install it.
const APPLY_HINT: &str = "Use `x0x upgrade --apply` to install through the running daemon.";

/// Where this CLI sits relative to the daemon that is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SplitView {
    /// The canonical CLI directory is the running daemon's directory.
    Beside,
    /// The canonical CLI directory is not the running daemon's directory.
    Apart,
    /// The running daemon executable could not be read. Do not warn.
    Unknown,
}

/// Facts `x0x upgrade --check` can state without installing anything.
pub(crate) struct CheckFacts<'a> {
    pub cli_version: &'a str,
    pub cli_path: Option<&'a Path>,
    pub daemon_exe: Option<&'a Path>,
    pub split: SplitView,
    pub daemon_version: Option<&'a str>,
    pub release_version: Option<&'a str>,
    pub force: bool,
    /// Set when the fetched release is not newer than this CLI.
    /// The published version is still in `release_version`.
    pub already_current: bool,
    /// Set when `--force` finds no GitHub release.
    pub missing_release: bool,
}

/// Text of `x0x upgrade --check`, including a split-install report.
pub(crate) fn check_report(facts: &CheckFacts<'_>) -> String {
    let mut lines = Vec::new();
    lines.push(format!("x0x v{}", facts.cli_version));
    match facts.daemon_version {
        Some(version) => lines.push(format!("Daemon v{version}")),
        None => lines.push("Daemon version unavailable".to_string()),
    }
    if let Some(release) = facts.release_version {
        lines.push(format!("Release v{release}"));
    }

    // The reinstall hint is only for a CLI that is apart from the running
    // daemon and older than that daemon. A CLI beside that daemon is replaced
    // by apply. An unknown executable must not produce that warning. An
    // available update still names `x0x upgrade --apply`.
    let cli_older_than_daemon = facts
        .daemon_version
        .filter(|daemon| release_is_newer(facts.cli_version, daemon));
    match (facts.split, facts.cli_path, cli_older_than_daemon) {
        (SplitView::Apart, Some(path), Some(daemon)) => {
            lines.extend(cli_not_upgraded_lines(
                path,
                facts.daemon_exe,
                facts.cli_version,
                daemon,
            ));
        }
        (SplitView::Unknown, _, _) if facts.daemon_version.is_some() => {
            lines.push(CANNOT_TELL_SPLIT.to_string());
        }
        _ => {}
    }

    if let Some(release) = facts.release_version {
        if release_is_newer(facts.cli_version, release) {
            lines.push(format!(
                "Update available: v{} → v{release}",
                facts.cli_version
            ));
            match facts.split {
                SplitView::Apart => {
                    lines.push(
                        "The daemon apply does not upgrade a CLI installed apart from x0xd."
                            .to_string(),
                    );
                    // The older-than-daemon block already printed the hint.
                    // A newer release with no daemon version still needs a command.
                    if cli_older_than_daemon.is_none() {
                        lines.push(CLI_REINSTALL_HINT.to_string());
                    }
                }
                SplitView::Beside | SplitView::Unknown => lines.push(APPLY_HINT.to_string()),
            }
        } else {
            lines.push(format!(
                "Already on the latest version (v{}).",
                facts.cli_version
            ));
            if facts.force {
                lines.push(format!(
                    "Release v{release} is not newer than v{}.",
                    facts.cli_version
                ));
            }
        }
    } else if facts.already_current {
        lines.push(format!(
            "Already on the latest version (v{}).",
            facts.cli_version
        ));
    }
    if facts.missing_release {
        lines.push("No release found on GitHub.".to_string());
    }

    lines.join("\n")
}

fn cli_not_upgraded_lines(
    cli_path: &Path,
    daemon_exe: Option<&Path>,
    cli_version: &str,
    daemon_version: &str,
) -> Vec<String> {
    let place = match daemon_exe {
        Some(daemon) => format!(
            "{} is not beside the running daemon {}.",
            cli_path.display(),
            daemon.display()
        ),
        None => format!("{} is not beside the running daemon.", cli_path.display()),
    };
    vec![
        "CLI not upgraded".to_string(),
        place,
        format!("CLI v{cli_version} is older than daemon v{daemon_version}."),
        CLI_REINSTALL_HINT.to_string(),
    ]
}

/// Notice after apply when this CLI is apart from the running daemon and
/// older than the applied `version`. The response body is unchanged (#1104).
pub fn split_cli_notice_after_apply(
    response: &serde_json::Value,
    name: Option<&str>,
    api: Option<&str>,
) -> Option<String> {
    let applied_version = applied_release_version(response)?;
    let cli_path = std::env::current_exe().ok();
    let daemon_exe = dirs::data_dir()
        .and_then(|root| running_daemon_executable(&root, name, api, process_executable));
    split_cli_notice(
        cli_path.as_deref(),
        daemon_exe.as_deref(),
        crate::VERSION,
        applied_version,
    )
}

pub(crate) fn split_cli_notice(
    cli_path: Option<&Path>,
    daemon_exe: Option<&Path>,
    cli_version: &str,
    applied_version: &str,
) -> Option<String> {
    // Same or newer than the applied release: say nothing. "Cannot tell" is
    // only for a CLI that may still be behind, including Windows, where the
    // process path cannot be read.
    let behind = release_is_newer(cli_version, applied_version);
    let Some(cli_path) = cli_path else {
        return behind.then(|| CANNOT_TELL_SPLIT.to_string());
    };
    match split_relation(cli_path, daemon_exe) {
        SplitView::Beside => None,
        SplitView::Unknown => behind.then(|| CANNOT_TELL_SPLIT.to_string()),
        SplitView::Apart => {
            if !behind {
                return None;
            }
            let shown = path_for_display(cli_path);
            Some(
                cli_not_upgraded_lines(&shown, daemon_exe, cli_version, applied_version).join("\n"),
            )
        }
    }
}

/// Compare canonical paths. A symlink to the CLI does not look like a split
/// install. A `x0xd` file beside the CLI does not count unless it is the
/// running daemon.
pub(crate) fn split_relation(cli: &Path, daemon_exe: Option<&Path>) -> SplitView {
    let Some(daemon_exe) = daemon_exe else {
        return SplitView::Unknown;
    };
    match (canonical_parent(cli), canonical_parent(daemon_exe)) {
        (Some(cli_dir), Some(daemon_dir)) if cli_dir == daemon_dir => SplitView::Beside,
        (Some(_), Some(_)) => SplitView::Apart,
        _ => SplitView::Unknown,
    }
}

fn canonical_parent(path: &Path) -> Option<PathBuf> {
    let path = strip_deleted_suffix(path.to_path_buf());
    std::fs::canonicalize(path)
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

fn path_for_display(path: &Path) -> PathBuf {
    let path = strip_deleted_suffix(path.to_path_buf());
    std::fs::canonicalize(&path).unwrap_or(path)
}

fn applied_release_version(response: &serde_json::Value) -> Option<&str> {
    if response.get("applied").and_then(|value| value.as_bool()) != Some(true) {
        return None;
    }
    response.get("version").and_then(|value| value.as_str())
}

/// True when `release` is a strictly newer semver than `current`.
/// An unparseable version is not an update (#1104).
pub(crate) fn release_is_newer(current: &str, release: &str) -> bool {
    crate::upgrade::manifest::is_newer(release, current)
}

/// Check releases without installing; refuse standalone installation.
///
/// `instance` is `--name`. `api` is `--api`. Both select the daemon whose
/// `/health` this check reads and whose process this check compares.
pub async fn run(
    check_only: bool,
    force: bool,
    instance: Option<&str>,
    api: Option<&str>,
) -> Result<()> {
    if !check_only {
        anyhow::bail!(
            "Standalone upgrade installation is disabled to avoid replacing a live daemon. \
             Use authenticated POST /upgrade/apply on the running daemon \
             (Authorization: Bearer <api-token>); use `x0x upgrade --check` for a read-only check."
        );
    }

    let current = crate::VERSION;
    eprintln!("Checking for updates...");

    let observed = observe_selected_daemon(instance, api).await;
    let monitor = UpgradeMonitor::new(REPO, "x0x", current)
        .map_err(|e| anyhow::anyhow!("failed to create upgrade monitor: {e}"))?;

    let mut release_version = None;
    let mut already_current = false;
    let mut missing_release = false;
    let mut fetch_error = None;

    if force {
        match monitor.fetch_current_manifest().await {
            Ok(Some(verified)) => release_version = Some(verified.manifest.version),
            Ok(None) => missing_release = true,
            Err(e) => fetch_error = Some(e),
        }
    } else {
        match monitor.fetch_release_for_check().await {
            Ok(fetched) => {
                already_current = fetched.update.is_none();
                release_version = Some(fetched.version);
            }
            Err(e) => fetch_error = Some(e),
        }
    }

    let report = check_report(&CheckFacts {
        cli_version: current,
        cli_path: observed.cli_path.as_deref(),
        daemon_exe: observed.daemon_exe.as_deref(),
        split: observed.split,
        daemon_version: observed.daemon_version.as_deref(),
        release_version: release_version.as_deref(),
        force,
        already_current,
        missing_release,
    });
    eprintln!("{report}");
    if let Some(error) = fetch_error {
        print_signature_recovery_hint(&error, current);
        return Err(if force {
            anyhow::anyhow!("failed to fetch release from GitHub: {error}")
        } else {
            anyhow::anyhow!("failed to check for updates: {error}")
        });
    }
    Ok(())
}

struct ObservedDaemon {
    cli_path: Option<PathBuf>,
    daemon_exe: Option<PathBuf>,
    daemon_version: Option<String>,
    split: SplitView,
}

/// Daemon selected by `--name` / `--api`, as `run` observes it.
async fn observe_selected_daemon(instance: Option<&str>, api: Option<&str>) -> ObservedDaemon {
    let cli_path = std::env::current_exe().ok();
    let data_root = dirs::data_dir();
    let base_url = data_root
        .as_ref()
        .and_then(|root| DaemonClient::resolve_base_url(instance, api, root).ok());
    let daemon_version = match base_url.as_deref() {
        Some(url) => running_daemon_version(url).await,
        None => None,
    };
    let daemon_exe = data_root
        .and_then(|root| running_daemon_executable(&root, instance, api, process_executable));
    let split = match cli_path.as_deref() {
        Some(path) => split_relation(path, daemon_exe.as_deref()),
        None => SplitView::Unknown,
    };
    let shown = cli_path.as_ref().map(|path| path_for_display(path));
    ObservedDaemon {
        cli_path: shown,
        daemon_exe,
        daemon_version,
        split,
    }
}

/// Executable of the daemon selected by `--name` or `--api`.
///
/// The pid is the one recorded in that instance's `instance.lock`. This is
/// the running process, not a `x0xd` file that merely sits beside the CLI.
/// `--api` selects the instance whose `api.port` matches that address.
/// A service definition is not used: it can name a binary that is not the
/// process answering this check. `None` means the check cannot tell.
///
/// `exe_for_pid` receives the instance name from the selected directory
/// (`None` is the default instance). A pid whose command line names a
/// different instance is not this daemon.
pub(crate) fn running_daemon_executable(
    data_root: &Path,
    name: Option<&str>,
    api: Option<&str>,
    exe_for_pid: impl Fn(u32, Option<&str>) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let dir = selected_instance_dir(data_root, name, api)?;
    let instance = expected_daemon_name(&dir)?;
    let pid = read_instance_pid(&dir)?;
    let exe = exe_for_pid(pid, instance.as_deref())?;
    exe.file_name()
        .is_some_and(|file| file == apply::daemon_file_name())
        .then_some(exe)
}

/// `--name` recorded for this instance directory.
///
/// The outer `Option` is `None` when `dir` is not an instance directory.
/// The inner `Option` is the `--name` value. `None` is the default instance.
fn expected_daemon_name(dir: &Path) -> Option<Option<String>> {
    let file_name = dir.file_name()?.to_str()?;
    if file_name == "x0x" {
        return Some(None);
    }
    let name = file_name.strip_prefix("x0x-")?;
    if name.is_empty() {
        return None;
    }
    Some(Some(name.to_string()))
}

fn selected_instance_dir(
    data_root: &Path,
    name: Option<&str>,
    api: Option<&str>,
) -> Option<PathBuf> {
    if let Some(api) = api {
        return instance_dir_for_endpoint(data_root, api);
    }
    Some(data_root.join(instance_dir_name(name)))
}

fn instance_dir_name(name: Option<&str>) -> String {
    match name {
        Some(name) => format!("x0x-{name}"),
        None => "x0x".to_string(),
    }
}

fn instance_dir_for_endpoint(data_root: &Path, api: &str) -> Option<PathBuf> {
    let want = endpoint_key(api)?;
    let mut found = None;
    for entry in std::fs::read_dir(data_root).ok()?.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name != "x0x" && !name.starts_with("x0x-") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path().join("api.port")) else {
            continue;
        };
        if endpoint_key(&text) == Some(want.clone()) {
            if found.is_some() {
                return None;
            }
            found = Some(entry.path());
        }
    }
    found
}

fn read_instance_pid(dir: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(dir.join("instance.lock")).ok()?;
    let pid = text.trim().parse::<u32>().ok()?;
    (pid > 0).then_some(pid)
}

fn endpoint_key(addr: &str) -> Option<String> {
    let addr = addr.trim().trim_end_matches('/');
    if addr.is_empty() {
        return None;
    }
    let rest = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))
        .unwrap_or(addr);
    if rest.is_empty() || rest.contains(['/', ' ', '\\']) {
        return None;
    }
    let Some((host, port)) = split_host_port(rest) else {
        return Some(rest.to_string());
    };
    // `localhost` and `127.0.0.1` are one endpoint. `[::1]` stays distinct:
    // a daemon bound to one of those addresses does not listen on the other.
    let host = if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1"
    } else {
        host
    };
    if rest.starts_with('[') {
        Some(format!("[{host}]:{port}"))
    } else {
        Some(format!("{host}:{port}"))
    }
}

/// Loopback `host:port` only. A non-loopback address is not queried.
pub(crate) fn health_addr_allowed(addr: &str) -> bool {
    let Some(addr) = endpoint_key(addr) else {
        return false;
    };
    if addr.len() > 128 {
        return false;
    }
    let Some((host, port)) = split_host_port(&addr) else {
        return false;
    };
    let port_ok = port.parse::<u16>().ok().is_some_and(|value| value > 0);
    port_ok && is_loopback_host(host)
}

fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host, port));
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host, port))
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

pub(crate) fn version_from_health_body(bytes: &[u8]) -> Option<String> {
    const HEALTH_BODY_CAP: usize = 16 * 1024;
    if bytes.len() > HEALTH_BODY_CAP {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let version = body.get("version")?.as_str()?;
    if version.is_empty()
        || version.len() > 128
        || version.chars().any(|c| c.is_control() || !c.is_ascii())
    {
        return None;
    }
    Some(version.to_string())
}

/// Read one daemon's version from loopback `/health`.
///
/// The client does not use a proxy. A missing daemon or a non-loopback
/// address is `None`. The request carries no token and times out after 2 seconds.
async fn running_daemon_version(base_url: &str) -> Option<String> {
    let root = base_url.trim_end_matches('/');
    let addr = root
        .strip_prefix("https://")
        .or_else(|| root.strip_prefix("http://"))
        .unwrap_or(root);
    if !health_addr_allowed(addr) {
        return None;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .no_proxy()
        .build()
        .ok()?;
    let bytes = client
        .get(format!("{root}/health"))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .bytes()
        .await
        .ok()?;
    version_from_health_body(&bytes)
}

fn process_executable(pid: u32, instance: Option<&str>) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        linux_process_executable(pid, instance)
    }
    #[cfg(target_os = "macos")]
    {
        macos_process_executable(pid, instance)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (pid, instance);
        None
    }
}

/// Accept `exe` only when it is `x0xd` and `args` is that instance.
///
/// A stale `instance.lock` can name a pid that now belongs to another
/// `x0xd`. The command line's `--name` is how those processes differ.
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn exe_if_this_instance(exe: PathBuf, args: &[String], instance: Option<&str>) -> Option<PathBuf> {
    let exe = strip_deleted_suffix(exe);
    if exe
        .file_name()
        .is_none_or(|file| file != apply::daemon_file_name())
    {
        return None;
    }
    argv_names_instance(args, instance).then_some(exe)
}

/// Linux `current_exe` appends ` (deleted)` after the file is replaced.
fn strip_deleted_suffix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_suffix(" (deleted)") {
        Some(clean) => PathBuf::from(clean),
        None => path,
    }
}

#[cfg(any(test, target_os = "linux"))]
fn argv_from_nul_bytes(buf: &[u8]) -> Vec<String> {
    buf.split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .filter_map(|part| std::str::from_utf8(part).ok())
        .map(str::to_string)
        .collect()
}

/// `true` when `args` is the `x0xd` for `instance`.
///
/// `instance` `None` is the default daemon: it has no `--name` argument.
/// An empty argument list does not match. The caller could not read a
/// command line, so the pid is not treated as this daemon.
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn argv_names_instance(args: &[String], instance: Option<&str>) -> bool {
    if args.is_empty() {
        return false;
    }
    let named = args
        .windows(2)
        .find(|pair| pair[0] == "--name")
        .map(|pair| pair[1].as_str());
    match (instance, named) {
        (None, None) => true,
        (Some(want), Some(got)) => want == got,
        _ => false,
    }
}

/// Parse the `KERN_PROCARGS2` buffer: argc, executable path, padding, argv.
#[cfg(any(test, target_os = "macos"))]
fn argv_from_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[0..4].try_into().ok()?);
    let count = usize::try_from(argc).ok()?;
    if count == 0 || count > 1024 {
        return None;
    }
    let mut index = 4;
    while index < buf.len() && buf[index] != 0 {
        index += 1;
    }
    while index < buf.len() && buf[index] == 0 {
        index += 1;
    }
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        if index >= buf.len() {
            return None;
        }
        let start = index;
        while index < buf.len() && buf[index] != 0 {
            index += 1;
        }
        let text = std::str::from_utf8(buf.get(start..index)?).ok()?;
        args.push(text.to_string());
        index += 1;
    }
    Some(args)
}

#[cfg(target_os = "linux")]
fn linux_process_executable(pid: u32, instance: Option<&str>) -> Option<PathBuf> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    if comm.trim() != apply::daemon_file_name() {
        return None;
    }
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    exe_if_this_instance(path, &argv_from_nul_bytes(&cmdline), instance)
}

#[cfg(target_os = "macos")]
fn macos_process_executable(pid: u32, instance: Option<&str>) -> Option<PathBuf> {
    let path = macos_pid_path(pid)?;
    let args = macos_process_args(pid)?;
    exe_if_this_instance(path, &args, instance)
}

#[cfg(target_os = "macos")]
fn macos_pid_path(pid: u32) -> Option<PathBuf> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `proc_pidpath` writes at most `buf.len()` bytes into `buf`
    // and reads only this pid. A non-positive return is an error.
    let cap = u32::try_from(buf.len()).ok()?;
    let wrote = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), cap) };
    if wrote <= 0 {
        return None;
    }
    let bytes = std::ffi::CStr::from_bytes_until_nul(&buf).ok()?.to_bytes();
    Some(PathBuf::from(std::str::from_utf8(bytes).ok()?))
}

#[cfg(target_os = "macos")]
fn macos_process_args(pid: u32) -> Option<Vec<String>> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let namelen = libc::c_uint::try_from(mib.len()).ok()?;
    let mut size: libc::size_t = 0;
    // SAFETY: a null output buffer asks for the byte count only. `mib`
    // stays valid for the call. No value is written to the kernel.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            namelen,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size == 0 || size > 1_048_576 {
        return None;
    }
    let mut buf = vec![0u8; size];
    // SAFETY: `buf` has `size` bytes and is exclusive to this call.
    // The call reads process arguments. It does not write a kernel value.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            namelen,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size > buf.len() {
        return None;
    }
    buf.truncate(size);
    argv_from_procargs2(&buf)
}

/// Text shown when the release signature does not match this binary's key.
/// The command installs only the CLI. It does not replace `x0xd`.
fn signature_recovery_hint(current: &str) -> String {
    format!(
        "\nThe release signature could not be verified with this binary's\n\
embedded signing key. This typically means your x0x installation\n\
(v{current}) predates a signing key update.\n\
\n\
To update this CLI only, run:\n\
\n\
  cargo install x0x --bin x0x --force\n\
\n\
That command installs only the x0x CLI. It does not replace x0xd.\n"
    )
}

/// If the error is a signature verification failure, print recovery instructions
/// so users on older builds with a mismatched signing key can still upgrade.
fn print_signature_recovery_hint(err: &UpgradeError, current: &str) {
    if !matches!(err, UpgradeError::ManifestSignatureInvalid) {
        return;
    }
    eprintln!("{}", signature_recovery_hint(current));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upgrade::UpgradeError;
    use std::path::PathBuf;

    fn write_bin(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, b"bin").unwrap();
        path
    }

    fn report(split: SplitView, cli: &str, daemon: &str, release: &str, force: bool) -> String {
        check_report(&CheckFacts {
            cli_version: cli,
            cli_path: Some(Path::new("/home/user/.cargo/bin/x0x")),
            daemon_exe: Some(Path::new("/usr/local/bin/x0xd")),
            split,
            daemon_version: Some(daemon),
            release_version: Some(release),
            force,
            already_current: false,
            missing_release: false,
        })
    }

    #[test]
    fn print_signature_recovery_hint_is_cli_only() {
        let hint = signature_recovery_hint("0.19.42");
        assert!(hint.contains("v0.19.42"), "{hint}");
        assert!(
            hint.contains("cargo install x0x --bin x0x --force"),
            "{hint}"
        );
        assert!(
            hint.contains("installs only the x0x CLI") && hint.contains("does not replace x0xd"),
            "{hint}"
        );
        assert!(!hint.contains("install.sh"), "{hint}");
        assert!(!hint.contains("cargo install x0x --force\n"), "{hint}");
        print_signature_recovery_hint(&UpgradeError::ManifestSignatureInvalid, "0.19.42");
    }

    #[test]
    fn print_signature_recovery_hint_skips_for_other_errors() {
        print_signature_recovery_hint(
            &UpgradeError::ManifestFetchFailed("network error".to_string()),
            "0.19.42",
        );
    }

    // Inert architectural regression: installation must belong to the daemon's
    // authenticated upgrade transaction, never this standalone CLI module.
    #[test]
    fn standalone_upgrade_cannot_replace_or_restart_daemon() {
        let source = include_str!("upgrade.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [".perform_upgrade(", ".spawn(", "/shutdown"] {
            assert!(
                !production.contains(forbidden),
                "standalone upgrade must use POST /upgrade/apply, found {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn standalone_apply_refuses_before_io_even_with_force() {
        for force in [false, true] {
            let error = run(false, force, None, None)
                .await
                .expect_err("apply must refuse");
            let message = error.to_string();
            assert!(message.contains("authenticated POST /upgrade/apply"));
            assert!(message.contains("api-token"));
            assert!(message.contains("x0x upgrade --check"));
        }
    }

    #[test]
    fn issue1104_split_cli_check_reports_not_upgraded_and_reinstall_hint() {
        let report = report(SplitView::Apart, "1.2.0", "1.3.0", "1.2.0", true);
        assert!(
            report.contains("CLI not upgraded") && report.contains("is not beside"),
            "{report}"
        );
        assert!(
            report.contains(CLI_REINSTALL_HINT) && !report.contains("install.sh"),
            "{report}"
        );
        assert!(
            report.contains("x0x v1.2.0") && report.contains("Daemon v1.3.0"),
            "{report}"
        );
        assert!(report.contains("Release v1.2.0"), "{report}");
        assert!(
            report.contains("CLI v1.2.0 is older than daemon v1.3.0."),
            "{report}"
        );
        assert!(
            !report.contains("Update available") && report.contains("not newer"),
            "{report}"
        );
        assert!(!report.contains("Use `x0x upgrade --apply`"), "{report}");
    }

    #[test]
    fn issue1104_split_install_with_update_available_omits_apply_command() {
        let report = report(SplitView::Apart, "1.0.0", "1.2.0", "1.3.0", false);
        assert!(
            report.contains("CLI not upgraded") && report.contains(CLI_REINSTALL_HINT),
            "{report}"
        );
        assert!(
            report.contains("Update available: v1.0.0 → v1.3.0"),
            "{report}"
        );
        assert!(
            report.contains("The daemon apply does not upgrade a CLI installed apart from x0xd."),
            "{report}"
        );
        assert!(!report.contains("Use `x0x upgrade --apply`"), "{report}");
    }

    #[test]
    fn issue1104_beside_daemon_version_mismatch_has_no_reinstall_hint() {
        let older = report(SplitView::Beside, "1.0.0", "1.5.0", "1.5.0", false);
        assert!(
            !older.contains("CLI not upgraded") && !older.contains(CLI_REINSTALL_HINT),
            "{older}"
        );
        assert!(
            older.contains("Use `x0x upgrade --apply` to install through the running daemon."),
            "{older}"
        );
        let newer_cli = report(SplitView::Beside, "2.0.0", "1.0.0", "2.0.0", true);
        assert!(
            !newer_cli.contains("CLI not upgraded") && !newer_cli.contains(CLI_REINSTALL_HINT),
            "{newer_cli}"
        );
        assert!(
            !newer_cli.contains("Use `x0x upgrade --apply`"),
            "{newer_cli}"
        );
    }

    #[test]
    fn issue1104_cargo_bin_is_apart_from_the_running_usr_local_daemon() {
        let root = tempfile::tempdir().unwrap();
        let cargo = root.path().join(".cargo/bin");
        let local = root.path().join("usr/local/bin");
        let cli = write_bin(&cargo, apply::cli_file_name());
        write_bin(&cargo, apply::daemon_file_name());
        let daemon = write_bin(&local, apply::daemon_file_name());
        assert_eq!(
            split_relation(&cli, Some(&daemon)),
            SplitView::Apart,
            "a sibling x0xd in ~/.cargo/bin is not the running daemon"
        );
        let report = check_report(&CheckFacts {
            cli_version: "1.0.0",
            cli_path: Some(&cli),
            daemon_exe: Some(&daemon),
            split: SplitView::Apart,
            daemon_version: Some("1.2.0"),
            release_version: Some("1.2.0"),
            force: false,
            already_current: false,
            missing_release: false,
        });
        assert!(report.contains("CLI not upgraded"), "{report}");
        assert!(report.contains(&daemon.display().to_string()), "{report}");
    }

    #[cfg(unix)]
    #[test]
    fn issue1104_symlinked_cli_beside_the_daemon_is_not_a_split() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("usr/local/bin");
        let link_dir = root.path().join("home/bin");
        let real_cli = write_bin(&bin, apply::cli_file_name());
        let daemon = write_bin(&bin, apply::daemon_file_name());
        std::fs::create_dir_all(&link_dir).unwrap();
        let link = link_dir.join(apply::cli_file_name());
        symlink(&real_cli, &link).unwrap();
        assert_eq!(split_relation(&link, Some(&daemon)), SplitView::Beside);
        let report = check_report(&CheckFacts {
            cli_version: "1.0.0",
            cli_path: Some(&link),
            daemon_exe: Some(&daemon),
            split: split_relation(&link, Some(&daemon)),
            daemon_version: Some("1.5.0"),
            release_version: Some("1.5.0"),
            force: false,
            already_current: false,
            missing_release: false,
        });
        assert!(
            !report.contains("CLI not upgraded") && !report.contains(CANNOT_TELL_SPLIT),
            "{report}"
        );
    }

    #[test]
    fn issue1104_unknown_daemon_executable_does_not_warn() {
        let root = tempfile::tempdir().unwrap();
        let cargo = root.path().join(".cargo/bin");
        let cli = write_bin(&cargo, apply::cli_file_name());
        write_bin(&cargo, apply::daemon_file_name());
        assert_eq!(split_relation(&cli, None), SplitView::Unknown);
        let report = check_report(&CheckFacts {
            cli_version: "1.0.0",
            cli_path: Some(&cli),
            daemon_exe: None,
            split: SplitView::Unknown,
            daemon_version: Some("1.4.0"),
            release_version: Some("1.4.0"),
            force: false,
            already_current: false,
            missing_release: false,
        });
        assert!(report.contains(CANNOT_TELL_SPLIT), "{report}");
        assert!(!report.contains("CLI not upgraded"), "{report}");
        assert!(!report.contains(CLI_REINSTALL_HINT), "{report}");
        assert!(
            report.contains(APPLY_HINT),
            "an unknown split with an update still names apply: {report}"
        );
    }

    #[test]
    fn issue1104_apply_notice_when_split_cli_is_older() {
        let root = tempfile::tempdir().unwrap();
        let cli = write_bin(&root.path().join("B"), apply::cli_file_name());
        let daemon = write_bin(&root.path().join("A"), apply::daemon_file_name());
        let response = serde_json::json!({"applied": true, "version": "1.4.0"});
        let applied = applied_release_version(&response).expect("version");
        let notice = split_cli_notice(Some(&cli), Some(&daemon), "1.0.0", applied).expect("notice");
        assert!(notice.contains("CLI not upgraded"), "{notice}");
        assert!(
            notice.contains("cargo install x0x --bin x0x --force"),
            "{notice}"
        );
        assert!(
            !notice.contains("install.sh") && !notice.contains("cargo install x0x --force"),
            "{notice}"
        );
        assert!(split_cli_notice(Some(&cli), Some(&daemon), "1.4.0", applied).is_none());
        assert!(split_cli_notice(Some(&cli), Some(&daemon), "2.0.0", applied).is_none());
        let beside = write_bin(daemon.parent().unwrap(), apply::cli_file_name());
        assert!(split_cli_notice(Some(&beside), Some(&daemon), "1.0.0", applied).is_none());
        let unknown = split_cli_notice(Some(&cli), None, "1.0.0", applied).expect("cannot tell");
        assert!(unknown.contains(CANNOT_TELL_SPLIT), "{unknown}");
        assert!(!unknown.contains("CLI not upgraded"), "{unknown}");
        assert!(
            split_cli_notice(Some(&cli), None, "1.4.0", applied).is_none(),
            "a current CLI must not be told the path is unknown"
        );
        assert!(split_cli_notice(Some(&cli), None, "2.0.0", applied).is_none());
        let missing = split_cli_notice(None, Some(&daemon), "1.0.0", applied).expect("behind");
        assert!(missing.contains(CANNOT_TELL_SPLIT), "{missing}");
        assert!(split_cli_notice(None, Some(&daemon), "1.4.0", applied).is_none());
        assert!(applied_release_version(&serde_json::json!({"applied": false})).is_none());
    }

    #[test]
    fn issue1104_name_and_api_select_the_daemon_run_observes() {
        let root = tempfile::tempdir().unwrap();
        let default_dir = root.path().join("x0x");
        let alice_dir = root.path().join("x0x-alice");
        std::fs::create_dir_all(&default_dir).unwrap();
        std::fs::create_dir_all(&alice_dir).unwrap();
        std::fs::write(default_dir.join("api.port"), "127.0.0.1:12700\n").unwrap();
        std::fs::write(alice_dir.join("api.port"), "127.0.0.1:13999\n").unwrap();
        std::fs::write(default_dir.join("instance.lock"), "11").unwrap();
        std::fs::write(alice_dir.join("instance.lock"), "22").unwrap();
        let local = root.path().join("usr/local/bin");
        let cargo = root.path().join(".cargo/bin");
        let local_daemon = write_bin(&local, apply::daemon_file_name());
        let cargo_daemon = write_bin(&cargo, apply::daemon_file_name());

        let named = DaemonClient::resolve_base_url(Some("alice"), None, root.path()).unwrap();
        assert_eq!(named, "http://127.0.0.1:13999");
        let by_api =
            DaemonClient::resolve_base_url(Some("alice"), Some("127.0.0.1:14000"), root.path())
                .unwrap();
        assert_eq!(by_api, "http://127.0.0.1:14000");
        let empty = tempfile::tempdir().unwrap();
        let fallback = DaemonClient::resolve_base_url(None, None, empty.path()).unwrap();
        assert_eq!(fallback, "http://127.0.0.1:12700");
        assert!(DaemonClient::resolve_base_url(Some("bob"), None, empty.path()).is_err());

        let exe_for_pid = |pid: u32, _instance: Option<&str>| match pid {
            11 => Some(local_daemon.clone()),
            22 => Some(cargo_daemon.clone()),
            _ => None,
        };
        assert_eq!(
            running_daemon_executable(root.path(), Some("alice"), None, exe_for_pid),
            Some(cargo_daemon.clone()),
            "--name must reach the named instance process"
        );
        assert_eq!(
            running_daemon_executable(
                root.path(),
                Some("alice"),
                Some("http://127.0.0.1:12700"),
                exe_for_pid
            ),
            Some(local_daemon.clone()),
            "--api must select the instance whose port matches, not --name"
        );
        assert!(
            running_daemon_executable(
                root.path(),
                Some("alice"),
                Some("127.0.0.1:14000"),
                exe_for_pid
            )
            .is_none(),
            "an --api with no matching port file must not use another instance"
        );
        assert!(
            running_daemon_executable(root.path(), None, None, |_, _| Some(PathBuf::from(
                "/bin/sh"
            )))
            .is_none(),
            "a process that is not x0xd must not count as the daemon"
        );
    }

    #[test]
    fn issue1104_health_body_yields_version_and_rejects_bad_input() {
        assert!(health_addr_allowed("127.0.0.1:12700"));
        assert!(health_addr_allowed("localhost:12700"));
        assert!(health_addr_allowed("[::1]:12700"));
        assert!(!health_addr_allowed(""));
        assert!(!health_addr_allowed("127.0.0.1:12700/health"));
        assert!(!health_addr_allowed("10.1.2.3:12700"));
        assert!(!health_addr_allowed("0.0.0.0:12700"));
        assert!(!health_addr_allowed("127.0.0.1:0"));
        assert_eq!(
            version_from_health_body(br#"{"ok":true,"version":"1.2.3"}"#).as_deref(),
            Some("1.2.3")
        );
        assert!(version_from_health_body(br#"{"version":"1.2.3\n"}"#).is_none());
        assert!(version_from_health_body("{\"version\":\"1.2.3\u{200b}\"}".as_bytes()).is_none());
        let huge = vec![b'{'; 16 * 1024 + 1];
        assert!(version_from_health_body(&huge).is_none());
    }

    #[test]
    fn issue1104_force_compares_versions_before_claiming_an_update() {
        let same = report(SplitView::Beside, "1.2.3", "1.2.3", "1.2.3", true);
        assert!(
            !same.contains("Update available") && !same.contains("CLI not upgraded"),
            "{same}"
        );
        assert!(
            same.contains("Already on the latest version (v1.2.3)."),
            "{same}"
        );
        assert!(
            same.contains("Release v1.2.3 is not newer than v1.2.3."),
            "{same}"
        );
        let older_release = report(SplitView::Beside, "1.2.3", "1.2.3", "1.0.0", true);
        assert!(
            !older_release.contains("Update available"),
            "{older_release}"
        );
        assert!(
            older_release.contains("Release v1.0.0 is not newer than v1.2.3."),
            "{older_release}"
        );
        let newer = report(SplitView::Beside, "1.0.0", "1.0.0", "1.1.0", true);
        assert!(
            newer.contains("Update available: v1.0.0 → v1.1.0"),
            "{newer}"
        );
        assert!(
            newer.contains("Use `x0x upgrade --apply` to install through the running daemon."),
            "{newer}"
        );
        assert!(!newer.contains(CLI_REINSTALL_HINT), "{newer}");
    }

    #[test]
    fn issue1104_unparseable_version_is_not_an_update() {
        assert!(!release_is_newer("1.2.3", "not-a-version"));
        assert!(!release_is_newer("not-a-version", "1.2.3"));
        let report = report(SplitView::Beside, "1.2.3", "1.2.3", "not-a-version", true);
        assert!(!report.contains("Update available"), "{report}");
        assert!(
            report.contains("Release vnot-a-version is not newer than v1.2.3."),
            "{report}"
        );
    }

    #[test]
    fn issue1104_split_update_without_daemon_version_still_prints_the_hint() {
        let report = check_report(&CheckFacts {
            cli_version: "1.0.0",
            cli_path: Some(Path::new("/home/user/.cargo/bin/x0x")),
            daemon_exe: Some(Path::new("/usr/local/bin/x0xd")),
            split: SplitView::Apart,
            daemon_version: None,
            release_version: Some("1.2.0"),
            force: false,
            already_current: false,
            missing_release: false,
        });
        assert!(report.contains("Daemon version unavailable"), "{report}");
        assert!(
            report.contains("Update available: v1.0.0 → v1.2.0"),
            "{report}"
        );
        assert!(
            report.contains("The daemon apply does not upgrade a CLI installed apart from x0xd."),
            "{report}"
        );
        assert!(report.contains(CLI_REINSTALL_HINT), "{report}");
        assert!(!report.contains("CLI not upgraded"), "{report}");
        assert!(!report.contains("Use `x0x upgrade --apply`"), "{report}");
    }

    #[test]
    fn issue1104_already_current_and_missing_release_paths() {
        let current = check_report(&CheckFacts {
            cli_version: "1.2.3",
            cli_path: None,
            daemon_exe: None,
            split: SplitView::Unknown,
            daemon_version: None,
            release_version: None,
            force: false,
            already_current: true,
            missing_release: false,
        });
        assert!(
            current.contains("Already on the latest version (v1.2.3)."),
            "{current}"
        );
        assert!(!current.contains("Update available"), "{current}");
        assert!(!current.contains("Release v"), "{current}");
        assert!(
            !current.contains(CANNOT_TELL_SPLIT),
            "no daemon version means no split verdict: {current}"
        );

        let missing = check_report(&CheckFacts {
            cli_version: "1.2.3",
            cli_path: None,
            daemon_exe: None,
            split: SplitView::Beside,
            daemon_version: Some("1.2.3"),
            release_version: None,
            force: true,
            already_current: false,
            missing_release: true,
        });
        assert!(missing.contains("No release found on GitHub."), "{missing}");
        assert!(!missing.contains("Update available"), "{missing}");
    }

    #[test]
    fn current_check_prints_the_published_release() {
        let current = check_report(&CheckFacts {
            cli_version: "1.2.3",
            cli_path: None,
            daemon_exe: None,
            split: SplitView::Unknown,
            daemon_version: Some("1.2.3"),
            release_version: Some("1.2.3"),
            force: false,
            already_current: true,
            missing_release: false,
        });
        assert!(current.contains("Release v1.2.3"), "{current}");
        assert!(
            current.contains("Already on the latest version (v1.2.3)."),
            "{current}"
        );
        assert!(!current.contains("Update available"), "{current}");
        assert!(
            !current.contains("is not newer than"),
            "a normal current check names the release without the force line: {current}"
        );

        let ahead = check_report(&CheckFacts {
            cli_version: "1.4.0",
            cli_path: None,
            daemon_exe: None,
            split: SplitView::Beside,
            daemon_version: Some("1.2.3"),
            release_version: Some("1.2.3"),
            force: false,
            already_current: true,
            missing_release: false,
        });
        assert!(ahead.contains("x0x v1.4.0"), "{ahead}");
        assert!(ahead.contains("Daemon v1.2.3"), "{ahead}");
        assert!(ahead.contains("Release v1.2.3"), "{ahead}");
        assert!(
            ahead.contains("Already on the latest version (v1.4.0)."),
            "{ahead}"
        );
        assert!(!ahead.contains("Update available"), "{ahead}");
    }

    #[test]
    fn issue1104_deleted_cli_suffix_is_still_beside_the_daemon() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let cli = write_bin(&bin, apply::cli_file_name());
        let daemon = write_bin(&bin, apply::daemon_file_name());
        let deleted = PathBuf::from(format!("{} (deleted)", cli.display()));
        assert_eq!(
            split_relation(&deleted, Some(&daemon)),
            SplitView::Beside,
            "the Linux deleted suffix must not hide a sibling CLI"
        );
        let applied = "9.0.0";
        assert!(
            split_cli_notice(Some(&deleted), Some(&daemon), "1.0.0", applied).is_none(),
            "a successful sibling swap must not print Cannot tell"
        );
    }

    #[test]
    fn issue1104_missing_path_is_unknown_and_does_not_claim_a_split() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing").join(apply::cli_file_name());
        let daemon = write_bin(&root.path().join("bin"), apply::daemon_file_name());
        assert_eq!(split_relation(&missing, Some(&daemon)), SplitView::Unknown);
        let report = check_report(&CheckFacts {
            cli_version: "1.0.0",
            cli_path: None,
            daemon_exe: Some(&daemon),
            split: SplitView::Unknown,
            daemon_version: Some("1.4.0"),
            release_version: Some("1.4.0"),
            force: false,
            already_current: false,
            missing_release: false,
        });
        assert!(report.contains(CANNOT_TELL_SPLIT), "{report}");
        assert!(report.contains(APPLY_HINT), "{report}");
        assert!(!report.contains("CLI not upgraded"), "{report}");
        let current = check_report(&CheckFacts {
            cli_version: "1.4.0",
            cli_path: None,
            daemon_exe: None,
            split: SplitView::Unknown,
            daemon_version: Some("1.4.0"),
            release_version: Some("1.4.0"),
            force: false,
            already_current: false,
            missing_release: false,
        });
        assert!(
            !current.contains(APPLY_HINT),
            "no update means no apply line: {current}"
        );
    }

    #[test]
    fn issue1104_localhost_matches_the_ipv4_loopback_port_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("x0x");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("api.port"), "127.0.0.1:12700\n").unwrap();
        std::fs::write(dir.join("instance.lock"), "11").unwrap();
        let daemon = write_bin(&root.path().join("bin"), apply::daemon_file_name());
        for api in [
            "localhost:12700",
            "http://LOCALHOST:12700",
            "127.0.0.1:12700",
        ] {
            let found = running_daemon_executable(root.path(), None, Some(api), |pid, instance| {
                assert_eq!(pid, 11, "{api}");
                assert_eq!(instance, None, "{api}");
                Some(daemon.clone())
            });
            assert_eq!(found.as_deref(), Some(daemon.as_path()), "{api}");
        }
        assert!(
            running_daemon_executable(root.path(), None, Some("[::1]:12700"), |_, _| Some(
                daemon.clone()
            ))
            .is_none(),
            "[::1] is a different socket from 127.0.0.1"
        );
    }

    #[test]
    fn issue1104_duplicate_port_or_bad_lock_is_not_a_daemon() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("x0x");
        let second = root.path().join("x0x-bob");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("api.port"), "127.0.0.1:12700\n").unwrap();
        std::fs::write(second.join("api.port"), "localhost:12700\n").unwrap();
        std::fs::write(first.join("instance.lock"), "11").unwrap();
        std::fs::write(second.join("instance.lock"), "22").unwrap();
        let daemon = write_bin(&root.path().join("bin"), apply::daemon_file_name());
        assert!(
            running_daemon_executable(root.path(), None, Some("127.0.0.1:12700"), |_, _| {
                Some(daemon.clone())
            })
            .is_none(),
            "two port files for one endpoint must not pick a daemon"
        );
        for text in ["0", "nope", "", "-1"] {
            std::fs::write(first.join("instance.lock"), text).unwrap();
            std::fs::write(second.join("api.port"), "127.0.0.1:13999\n").unwrap();
            assert!(
                running_daemon_executable(root.path(), None, None, |_, _| Some(daemon.clone()))
                    .is_none(),
                "lock {text:?} must not select a daemon"
            );
        }
    }

    #[test]
    fn issue1104_stale_lock_pid_owned_by_another_daemon_does_not_match() {
        let default_args = vec!["/usr/local/bin/x0xd".to_string()];
        let alice = vec![
            "/usr/local/bin/x0xd".to_string(),
            "--name".to_string(),
            "alice".to_string(),
        ];
        let bob = vec![
            "/opt/x0x/x0xd".to_string(),
            "--name".to_string(),
            "bob".to_string(),
        ];
        assert!(argv_names_instance(&default_args, None));
        assert!(!argv_names_instance(&alice, None));
        assert!(argv_names_instance(&alice, Some("alice")));
        assert!(!argv_names_instance(&bob, Some("alice")));
        assert!(!argv_names_instance(&default_args, Some("alice")));
        assert!(!argv_names_instance(&[], None));

        let daemon = PathBuf::from(format!("/usr/local/bin/{}", apply::daemon_file_name()));
        assert!(exe_if_this_instance(daemon.clone(), &alice, Some("alice")).is_some());
        assert!(exe_if_this_instance(daemon.clone(), &bob, Some("alice")).is_none());
        let deleted = PathBuf::from(format!(
            "/usr/local/bin/{} (deleted)",
            apply::daemon_file_name()
        ));
        assert_eq!(
            exe_if_this_instance(deleted, &default_args, None).as_deref(),
            Some(daemon.as_path())
        );
        assert!(exe_if_this_instance(PathBuf::from("/bin/sh"), &default_args, None).is_none());

        let mut buf = Vec::new();
        buf.extend_from_slice(&3i32.to_ne_bytes());
        buf.extend_from_slice(b"/usr/local/bin/x0xd\0\0\0\0");
        for arg in ["/usr/local/bin/x0xd", "--name", "alice"] {
            buf.extend_from_slice(arg.as_bytes());
            buf.push(0);
        }
        let parsed = argv_from_procargs2(&buf).expect("procargs");
        assert!(argv_names_instance(&parsed, Some("alice")));
        let nul = b"/usr/local/bin/x0xd\0--name\0bob\0";
        assert!(argv_names_instance(&argv_from_nul_bytes(nul), Some("bob")));
    }

    #[test]
    fn issue1104_apart_cli_newer_than_its_daemon_still_prints_the_reinstall_hint() {
        let report = report(SplitView::Apart, "1.5.0", "1.0.0", "2.0.0", false);
        assert!(!report.contains("CLI not upgraded"), "{report}");
        assert!(report.contains(CLI_REINSTALL_HINT), "{report}");
        assert!(
            report.contains("does not upgrade a CLI installed apart"),
            "{report}"
        );
        assert!(!report.contains(APPLY_HINT), "{report}");
    }

    #[test]
    fn issue1104_check_edges_the_coverage_run_left_red() {
        let lines = cli_not_upgraded_lines(Path::new("/tmp/x0x"), None, "1.0.0", "1.2.0");
        assert!(
            lines[1].contains("is not beside the running daemon.")
                && !lines[1].contains("running daemon /"),
            "{lines:?}"
        );

        let root = tempfile::tempdir().unwrap();
        let empty_name = root.path().join("x0x-");
        std::fs::create_dir(&empty_name).unwrap();
        assert!(expected_daemon_name(&empty_name).is_none());

        let named = root.path().join("x0x-alice");
        std::fs::create_dir(&named).unwrap();
        let skipped = root.path().join("x0x-bob");
        std::fs::create_dir(&skipped).unwrap();
        // APFS rejects a non-UTF-8 name. Linux coverage still walks that entry.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = root
                .path()
                .join(std::ffi::OsString::from_vec(b"x0x-\xff".to_vec()));
            std::fs::create_dir(&bad).unwrap();
        }
        std::fs::write(named.join("api.port"), "example.com\n").unwrap();
        assert_eq!(endpoint_key("example.com").as_deref(), Some("example.com"));
        assert!(!health_addr_allowed("example.com"));
        assert!(!health_addr_allowed(&format!(
            "http://{}.example",
            "a".repeat(130)
        )));
        assert!(split_host_port("1:2:3").is_none());
        assert_eq!(
            instance_dir_for_endpoint(root.path(), "example.com").as_deref(),
            Some(named.as_path())
        );

        assert!(argv_from_procargs2(&[]).is_none());
        assert!(argv_from_procargs2(&0i32.to_ne_bytes()).is_none());
        let mut short = 1i32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"/x0xd");
        assert!(argv_from_procargs2(&short).is_none());

        #[cfg(target_os = "linux")]
        assert!(process_executable(std::process::id(), None).is_none());
    }
}
