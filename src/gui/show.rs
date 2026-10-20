//! Local GUI show runtime (ADR 0083 slice 1).
//!
//! Holds `[gui_show]` config, the rate limiter, the per-agent block list, and
//! the platform opener behind a test seam.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::identity::AgentId;

use super::rate_limit::GuiShowRateLimit;

/// How long a pending banner waits for its GUI window to connect.
const PENDING_FRESHNESS: Duration = Duration::from_secs(60);

/// How long a platform opener may run before a missing successful exit is
/// `no_display`. Spawn success is not a display: `xdg-open` can start and
/// then exit nonzero on a headless host.
const OPENER_WAIT: Duration = Duration::from_secs(2);

/// Pending banner for one freshly opened GUI window (no live WS yet).
///
/// Keyed by the session token minted into that window's URL, so two shows
/// before either browser connects each keep their own banner.
#[derive(Debug, Clone)]
pub struct PendingGuiShow {
    pub view: String,
    pub banner: String,
    pub agent_id: String,
    pub machine_id: String,
    pub rider: bool,
    pub request_id: String,
    /// Browser session token from the opened `/gui?token=` URL.
    pub session_token: String,
    pub created_at: Instant,
}

/// TOML `[gui_show]` (ADR 0083 §5). Defaults are both on (David, 2026-09-28).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuiShowConfig {
    /// `POST /gui/show` without a remote target.
    #[serde(default = "default_true")]
    pub local_enabled: bool,
    /// Accept shows from other owner machines (slice 3; stored for reload).
    #[serde(default = "default_true")]
    pub remote_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for GuiShowConfig {
    fn default() -> Self {
        Self {
            local_enabled: true,
            remote_enabled: true,
        }
    }
}

/// Wire outcome for `POST /gui/show` (ADR 0083 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiShowOutcome {
    /// Platform opener launched a new GUI window.
    Opened,
    /// An open WS session navigated in place.
    Navigated,
    /// Sender is blocked or otherwise refused.
    Refused,
    /// `[gui_show] local_enabled = false` (or remote disabled on receive).
    Disabled,
    /// Rate limit exceeded.
    RateLimited,
    /// Opener could not run (headless / no display).
    NoDisplay,
    /// View failed the Rust grammar.
    InvalidView,
    /// No machine qualifies as `active` (slice 3).
    NoActiveMachine,
    /// Human has not confirmed (reserved).
    Unconfirmed,
}

/// Request body for `POST /gui/show`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiShowRequest {
    /// Deep-link route (`people`, `dm/<hex>`, `groups/<hex>/board`, …).
    pub view: String,
    /// Absent / null = this machine (slice 1). Remote targets are slice 3.
    #[serde(default)]
    pub target_machine: Option<String>,
}

/// Response body for `POST /gui/show`. Never carries a URL or session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiShowResponse {
    pub outcome: GuiShowOutcome,
    pub machine_id: String,
    pub request_id: String,
}

/// How the daemon opens a GUI URL when no WS tab is live.
pub trait ShowOpener: Send + Sync {
    /// Open `url` in the platform browser. Returns `true` on success.
    fn open(&self, url: &str) -> bool;
}

/// Production opener: `open` / `xdg-open` / `cmd /C start`.
#[derive(Debug, Default)]
pub struct PlatformOpener;

impl ShowOpener for PlatformOpener {
    fn open(&self, url: &str) -> bool {
        match platform_opener_spawn(url) {
            Some(Ok(child)) => opener_displayed(child, OPENER_WAIT),
            Some(Err(_)) | None => false,
        }
    }
}

/// Start the platform opener. `None` means this OS has no opener.
fn platform_opener_spawn(url: &str) -> Option<std::io::Result<std::process::Child>> {
    #[cfg(target_os = "macos")]
    {
        Some(std::process::Command::new("open").arg(url).spawn())
    }
    #[cfg(target_os = "linux")]
    {
        Some(std::process::Command::new("xdg-open").arg(url).spawn())
    }
    #[cfg(target_os = "windows")]
    {
        Some(
            std::process::Command::new("cmd")
                .args(["/C", "start", url])
                .spawn(),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = url;
        None
    }
}

/// Wait until `child` exits, or until `bound` elapses.
///
/// The wait polls `try_wait`, so it does not block in the kernel. A nonzero
/// exit is not a display. A child still running at `bound` is not a display
/// either. The child is always reaped: a timeout kills it and waits, so it
/// cannot stay a zombie.
fn opener_displayed(mut child: std::process::Child, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Capturing opener for tests (ADR 0083 validation: invalid_view invokes none).
#[derive(Debug, Default, Clone)]
pub struct CapturingOpener {
    /// URLs passed to [`ShowOpener::open`].
    pub urls: Arc<Mutex<Vec<String>>>,
    /// When false, `open` reports failure (`no_display`).
    pub succeed: Arc<Mutex<bool>>,
}

impl CapturingOpener {
    /// New capturing opener that reports success.
    pub fn new() -> Self {
        Self {
            urls: Arc::new(Mutex::new(Vec::new())),
            succeed: Arc::new(Mutex::new(true)),
        }
    }
}

impl ShowOpener for CapturingOpener {
    fn open(&self, url: &str) -> bool {
        if let Ok(mut g) = self.urls.lock() {
            g.push(url.to_string());
        }
        self.succeed.lock().map(|g| *g).unwrap_or(false)
    }
}

/// Daemon-side state for local (and later remote) GUI show.
pub struct GuiShowRuntime {
    config: Mutex<GuiShowConfig>,
    rate_limit: Mutex<GuiShowRateLimit>,
    blocked: Mutex<HashSet<[u8; 32]>>,
    opener: Mutex<Arc<dyn ShowOpener>>,
    /// Optional daemon TOML path for `POST /acl/reload` re-read.
    config_path: Mutex<Option<PathBuf>>,
    blocked_path: PathBuf,
    /// Shows waiting for the GUI window that was opened for each one.
    pending: Mutex<VecDeque<PendingGuiShow>>,
}

impl std::fmt::Debug for GuiShowRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuiShowRuntime")
            .field("blocked_path", &self.blocked_path)
            .finish_non_exhaustive()
    }
}

impl GuiShowRuntime {
    /// Build runtime from config, optional daemon TOML path, and data dir.
    pub fn new(
        config: GuiShowConfig,
        config_path: Option<PathBuf>,
        data_dir: &std::path::Path,
        opener: Arc<dyn ShowOpener>,
    ) -> Self {
        let blocked_path = data_dir.join("gui_show_blocked.json");
        let blocked = load_blocked(&blocked_path);
        Self {
            config: Mutex::new(config),
            rate_limit: Mutex::new(GuiShowRateLimit::default()),
            blocked: Mutex::new(blocked),
            opener: Mutex::new(opener),
            config_path: Mutex::new(config_path),
            blocked_path,
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// Production default: platform opener, no config path.
    pub fn with_defaults(config: GuiShowConfig, data_dir: &std::path::Path) -> Self {
        Self::new(config, None, data_dir, Arc::new(PlatformOpener))
    }

    /// Snapshot of `[gui_show]`.
    pub fn config(&self) -> GuiShowConfig {
        self.config.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Replace config (tests / acl reload after a successful TOML parse).
    pub fn set_config(&self, config: GuiShowConfig) {
        if let Ok(mut g) = self.config.lock() {
            *g = config;
        }
    }

    /// Re-read `[gui_show]` from the daemon TOML when a path is known.
    pub fn reload_from_disk(&self) {
        let path = self.config_path.lock().ok().and_then(|g| g.clone());
        let Some(path) = path else {
            return;
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        #[derive(Deserialize)]
        struct Partial {
            #[serde(default)]
            gui_show: GuiShowConfig,
        }
        if let Ok(partial) = toml::from_str::<Partial>(&text) {
            self.set_config(partial.gui_show);
        }
    }

    /// Whether `agent` is on the local block list.
    pub fn is_blocked(&self, agent: &AgentId) -> bool {
        self.blocked
            .lock()
            .map(|g| g.contains(agent.as_bytes()))
            .unwrap_or(false)
    }

    /// Add `agent` to the block list and persist.
    pub fn block_agent(&self, agent: &AgentId) {
        if let Ok(mut g) = self.blocked.lock() {
            g.insert(*agent.as_bytes());
            let _ = persist_blocked(&self.blocked_path, &g);
        }
    }

    /// Rate-limit gate; `true` means the show may proceed.
    pub fn try_rate_limit(&self, agent: &AgentId, now: Instant) -> bool {
        self.rate_limit
            .lock()
            .map(|mut g| g.try_acquire(agent, now))
            .unwrap_or(false)
    }

    /// Open a GUI URL via the configured opener.
    pub fn open_url(&self, url: &str) -> bool {
        self.opener.lock().map(|g| g.open(url)).unwrap_or(false)
    }

    /// Test seam: replace the opener without rebuilding `AppState`.
    pub fn replace_opener_for_test(&self, opener: Arc<dyn ShowOpener>) {
        if let Ok(mut g) = self.opener.lock() {
            *g = opener;
        }
    }

    /// Startup: remember the daemon config path for `POST /acl/reload`.
    pub fn set_config_path(&self, path: Option<PathBuf>) {
        if let Ok(mut g) = self.config_path.lock() {
            *g = path;
        }
    }

    /// Remember a show that opened a new window so that window's GUI socket
    /// can deliver the origin banner. Older shows in the freshness window stay.
    pub fn enqueue_pending(&self, pending: PendingGuiShow) {
        if let Ok(mut queue) = self.pending.lock() {
            let now = Instant::now();
            queue.retain(|item| pending_is_fresh(item, now));
            queue.push_back(pending);
        }
    }

    /// Take the fresh pending show minted for this GUI session token.
    ///
    /// A miss leaves every other pending show in place. Stale entries are
    /// dropped. An agent socket must not call this.
    pub fn take_pending_for_session(
        &self,
        session_token: &str,
        now: Instant,
    ) -> Option<PendingGuiShow> {
        let Ok(mut queue) = self.pending.lock() else {
            return None;
        };
        queue.retain(|item| pending_is_fresh(item, now));
        let idx = queue
            .iter()
            .position(|item| item.session_token == session_token)?;
        queue.remove(idx)
    }
}

fn pending_is_fresh(pending: &PendingGuiShow, now: Instant) -> bool {
    now.saturating_duration_since(pending.created_at) <= PENDING_FRESHNESS
}

/// Path of the daemon TOML that startup loaded.
///
/// An explicit `--config` wins. Otherwise this is the instance default file
/// when that file exists. `POST /acl/reload` re-reads `[gui_show]` from this
/// path. A missing default file means startup used in-memory defaults and
/// there is nothing to re-read.
pub fn startup_config_path(explicit: Option<&Path>, default_path: &Path) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    if default_path.exists() {
        Some(default_path.to_path_buf())
    } else {
        None
    }
}

/// Whether a WebSocket query is a visible GUI tab, and its session token.
///
/// The embedded GUI connects with `gui=1` only while the tab is visible.
/// Agent clients on `/ws` and `/ws/direct` omit it, and a hidden tab omits it
/// too, so they are not a live GUI and must not take a pending banner.
pub fn parse_gui_ws_query(query: Option<&str>) -> (bool, Option<String>) {
    let Some(query) = query else {
        return (false, None);
    };
    let mut visible_gui = false;
    let mut session_token = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("gui=") {
            visible_gui = value == "1";
        } else if let Some(value) = pair.strip_prefix("token=") {
            if !value.is_empty() {
                session_token = Some(value.to_string());
            }
        }
    }
    (visible_gui, session_token)
}

fn load_blocked(path: &std::path::Path) -> HashSet<[u8; 32]> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    let Ok(ids) = serde_json::from_str::<Vec<String>>(&text) else {
        return HashSet::new();
    };
    ids.into_iter()
        .filter_map(|h| {
            let bytes = hex::decode(h).ok()?;
            let arr: [u8; 32] = bytes.try_into().ok()?;
            Some(arr)
        })
        .collect()
}

fn persist_blocked(path: &std::path::Path, set: &HashSet<[u8; 32]>) -> std::io::Result<()> {
    let list: Vec<String> = set.iter().map(hex::encode).collect();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(&list).unwrap_or_default())
}

/// Mint a fresh request id (32 hex chars).
pub fn new_request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Build the origin banner text from locally resolved names (ADR 0083 §5).
pub fn origin_banner(agent_label: &str, machine_label: &str, rider: bool) -> String {
    if rider {
        format!("Opened by {agent_label} (rider) on {machine_label}")
    } else {
        format!("Opened by {agent_label} on {machine_label}")
    }
}

/// Short hex id for banner fallbacks (10 chars + ellipsis in the GUI; we
/// keep the short hex here without the ellipsis character for the WS payload).
pub fn short_id_hex(hex64: &str) -> String {
    let take = hex64.len().min(10);
    hex64[..take].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(dir: &Path, config_path: Option<PathBuf>) -> GuiShowRuntime {
        GuiShowRuntime::new(
            GuiShowConfig::default(),
            config_path,
            dir,
            Arc::new(CapturingOpener::new()),
        )
    }

    fn pending(token: &str, view: &str, created_at: Instant) -> PendingGuiShow {
        PendingGuiShow {
            view: view.to_string(),
            banner: "Opened by test on test".to_string(),
            agent_id: "aa".repeat(32),
            machine_id: "bb".repeat(32),
            rider: false,
            request_id: "req".to_string(),
            session_token: token.to_string(),
            created_at,
        }
    }

    #[test]
    fn blocking_the_daemon_agent_refuses_local_shows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let daemon = AgentId([1u8; 32]);
        rt.block_agent(&daemon);
        assert!(
            rt.is_blocked(&daemon),
            "ADR 0083 §5 refuses a blocked sender, including this daemon's agent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn opener_that_fails_after_spawn_is_not_a_display() {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 0.15; exit 1"])
            .spawn()
            .expect("spawn");
        let pid = child.id();
        assert!(
            !opener_displayed(child, Duration::from_secs(2)),
            "a launcher that exits nonzero is no_display, even when spawn succeeded"
        );
        assert!(!process_is_zombie(pid), "the failed opener must be reaped");
    }

    #[cfg(unix)]
    #[test]
    fn opener_still_running_at_the_bound_is_reaped_and_not_a_display() {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("spawn");
        let pid = child.id();
        let started = Instant::now();
        assert!(!opener_displayed(child, Duration::from_millis(200)));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must stay inside its bound"
        );
        assert!(!process_is_zombie(pid), "a timed-out opener must be reaped");
        let still = std::process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()
            .expect("ps");
        assert!(
            !still.status.success(),
            "a timed-out opener must not keep running: {}",
            String::from_utf8_lossy(&still.stdout)
        );
    }

    #[cfg(unix)]
    fn process_is_zombie(pid: u32) -> bool {
        let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
        else {
            return false;
        };
        String::from_utf8_lossy(&output.stdout).contains('Z')
    }

    #[test]
    fn two_shows_before_connect_keep_both_pending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let now = Instant::now();
        rt.enqueue_pending(pending("session-a", "people", now));
        rt.enqueue_pending(pending("session-b", "network", now));
        assert!(
            rt.take_pending_for_session("agent-socket", now).is_none(),
            "an unrelated socket must not drop either pending show"
        );
        let first = rt
            .take_pending_for_session("session-a", now)
            .expect("first show still pending");
        let second = rt
            .take_pending_for_session("session-b", now)
            .expect("second show still pending");
        assert_eq!(first.view, "people");
        assert_eq!(second.view, "network");
        assert!(rt.take_pending_for_session("session-a", now).is_none());
    }

    #[test]
    fn stale_pending_show_is_dropped_without_taking_the_fresh_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let now = Instant::now();
        let stale_at = now
            .checked_sub(PENDING_FRESHNESS + Duration::from_secs(1))
            .expect("instant");
        rt.enqueue_pending(pending("stale", "people", stale_at));
        rt.enqueue_pending(pending("fresh", "network", now));
        assert!(rt.take_pending_for_session("stale", now).is_none());
        assert_eq!(
            rt.take_pending_for_session("fresh", now)
                .expect("fresh show")
                .view,
            "network"
        );
    }

    #[test]
    fn reload_reads_local_enabled_from_the_startup_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let default_path = dir.path().join("config.toml");
        assert!(
            startup_config_path(None, &default_path).is_none(),
            "a missing default file is not a reload path"
        );
        std::fs::write(
            &default_path,
            "[gui_show]\nlocal_enabled = false\nremote_enabled = true\n",
        )
        .expect("write config");
        let loaded = startup_config_path(None, &default_path).expect("default file was loaded");
        assert_eq!(loaded, default_path);
        let explicit = dir.path().join("other.toml");
        assert_eq!(
            startup_config_path(Some(&explicit), &default_path).as_deref(),
            Some(explicit.as_path()),
            "an explicit --config path wins over the default file"
        );
        let rt = runtime(dir.path(), Some(loaded));
        assert!(rt.config().local_enabled);
        rt.reload_from_disk();
        assert!(
            !rt.config().local_enabled,
            "[gui_show] local_enabled=false in the file startup loaded must apply on reload"
        );
    }

    #[test]
    fn agent_ws_query_is_not_a_visible_gui() {
        assert_eq!(parse_gui_ws_query(None), (false, None));
        assert_eq!(
            parse_gui_ws_query(Some("token=abc")),
            (false, Some("abc".to_string()))
        );
        assert_eq!(parse_gui_ws_query(Some("backfill=1")), (false, None));
        assert_eq!(
            parse_gui_ws_query(Some("token=abc&gui=1")),
            (true, Some("abc".to_string()))
        );
        assert_eq!(parse_gui_ws_query(Some("gui=1")), (true, None));
    }

    #[test]
    fn origin_banner_can_be_hidden_after_three_seconds_without_blocking() {
        let html = include_str!("x0x-gui.html");
        assert!(
            html.contains("id=\"gui-show-banner-dismiss\""),
            "the banner needs a hide control that is not the block control"
        );
        let start = html
            .find("function hideGuiShowBanner")
            .expect("hide helper");
        let end = html[start..]
            .find("function navigate")
            .expect("navigate follows the banner helpers");
        let src = &html[start..start + end];
        assert!(
            src.contains("3000"),
            "the banner stays non-dismissable for 3 seconds"
        );
        let hide = src
            .find("function hideGuiShowBanner")
            .expect("hide helper in slice");
        let show = src.find("function showGuiShowBanner").expect("show helper");
        let hide_body = &src[hide..show];
        assert!(
            !hide_body.contains("gui.block"),
            "hiding the banner must not block the agent: {hide_body}"
        );
        assert!(
            src.contains("hide.onclick=hideGuiShowBanner"),
            "after the wait, Hide clears the banner without gui.block"
        );
        assert!(
            html.contains("function guiTabVisible"),
            "the GUI socket must advertise gui=1 only while the tab is visible"
        );
    }

    #[test]
    fn hidden_tab_does_not_advertise_a_live_gui() {
        let html = include_str!("x0x-gui.html");
        let ws_url = fn_source(html, "function wsUrl()", "let ws=");
        assert!(
            ws_url.contains("guiTabVisible()"),
            "wsUrl must read real visibility before it sends gui=1: {ws_url}"
        );
        assert!(
            !ws_url.contains("return base+'?gui=1';"),
            "a hidden tab must not be hard-coded as a live GUI: {ws_url}"
        );
        assert!(
            !ws_url.contains("return base+'?token='+SESSION_TOKEN+'&gui=1';"),
            "a tokenised socket must not always send gui=1: {ws_url}"
        );
        let advertise = fn_source(
            html,
            "function advertiseGuiVisibility()",
            "function wsConnect()",
        );
        assert!(
            advertise.contains("type:'gui.visible'") || advertise.contains("type: 'gui.visible'"),
            "visibility changes must update the daemon: {advertise}"
        );
        assert!(
            advertise.contains("guiTabVisible()"),
            "the update must carry the real visibility: {advertise}"
        );
        let listener = html
            .find("addEventListener('visibilitychange'")
            .expect("visibility listener");
        let listener_src = &html[listener..listener + 180];
        assert!(
            listener_src.contains("advertiseGuiVisibility"),
            "hiding the tab must stop advertising a live GUI: {listener_src}"
        );
        let onopen = fn_source(html, "ws.onopen=async()", "ws.onclose");
        assert!(
            onopen.contains("advertiseGuiVisibility()"),
            "a reconnect must report the visibility at open time: {onopen}"
        );
    }

    fn fn_source<'a>(html: &'a str, start: &str, end: &str) -> &'a str {
        let at = html
            .find(start)
            .unwrap_or_else(|| panic!("missing {start}"));
        let rest = &html[at..];
        let stop = rest
            .find(end)
            .unwrap_or_else(|| panic!("missing {end} after {start}"));
        &rest[..stop]
    }
}
