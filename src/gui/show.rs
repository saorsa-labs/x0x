//! Local GUI show runtime (ADR 0083 slice 1).
//!
//! Holds `[gui_show]` config, the rate limiter, the per-agent block list, and
//! the platform opener behind a test seam.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::identity::AgentId;

use super::rate_limit::GuiShowRateLimit;

/// Pending banner for a freshly opened GUI window (no live WS yet).
#[derive(Debug, Clone)]
pub struct PendingGuiShow {
    pub view: String,
    pub banner: String,
    pub agent_id: String,
    pub machine_id: String,
    pub rider: bool,
    pub request_id: String,
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
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("open").arg(url).spawn().is_ok()
        }
        #[cfg(target_os = "linux")]
        {
            std::process::Command::new("xdg-open")
                .arg(url)
                .spawn()
                .is_ok()
        }
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("cmd")
                .args(["/C", "start", url])
                .spawn()
                .is_ok()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = url;
            false
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
    /// Last opened show waiting for a GUI WS to attach (banner delivery).
    pending: Mutex<Option<PendingGuiShow>>,
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
            pending: Mutex::new(None),
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

    /// Remember a show that opened a new window so the first WS connect
    /// can deliver the origin banner.
    pub fn set_pending(&self, pending: PendingGuiShow) {
        if let Ok(mut g) = self.pending.lock() {
            *g = Some(pending);
        }
    }

    /// Take a pending show if it is still fresh (≤ 60 s).
    pub fn take_pending(&self, now: Instant) -> Option<PendingGuiShow> {
        let Ok(mut g) = self.pending.lock() else {
            return None;
        };
        let pending = g.take()?;
        if now.duration_since(pending.created_at) > Duration::from_secs(60) {
            None
        } else {
            Some(pending)
        }
    }
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
