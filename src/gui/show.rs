//! Local GUI show runtime (ADR 0083 slice 1).
//!
//! Holds `[gui_show]` config, the rate limiter, the per-agent block list, and
//! the platform opener behind a test seam.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::identity::AgentId;

use super::rate_limit::GuiShowRateLimit;

/// Signers kept for a later rider Stop. One entry is one displayed show.
const RIDER_PRESENTED_SIGNERS: usize = 64;
/// Subjects kept for one signer.
const RIDER_PRESENTED_SUBJECTS: usize = 32;

/// Replaces one remote show send. Production leaves the slot empty.
type ShowSendHook = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), crate::dm::DmError>> + Send>> + Send + Sync,
>;

/// Reply sends that may be in flight together.
const REPLY_SEND_SLOTS: usize = 4;

/// Refusals to a sender that is not owner-trusted, inside one minute.
const UNTRUSTED_REFUSAL_LIMIT: u32 = 1;

/// Window for [`UNTRUSTED_REFUSAL_LIMIT`].
const UNTRUSTED_REFUSAL_WINDOW: Duration = Duration::from_secs(60);

/// Refusals already sent to untrusted show senders.
#[derive(Debug, Default)]
struct UntrustedRefusalWindow {
    start: Option<Instant>,
    sent: u32,
}

/// How long a pending banner waits for its GUI window to connect.
///
/// The banner stays until the session token TTL, matching a hidden tab
/// revealed later.
const PENDING_FRESHNESS: Duration = crate::server::SESSION_TOKEN_TTL;

/// Predecessor tokens retained for one refresh chain.
///
/// Each record expires from the time it was noted, plus the session-token
/// TTL. A chain that refreshes again inside that window still adds one
/// record per refresh. Past this cap the oldest records are dropped, so
/// the map and the scan that walks it stay bounded.
const MAX_GUI_SESSION_SUCCESSORS: usize = 8;

/// `error.message` prefix when Stop is off in memory but the marker was not saved.
///
/// `gui.block` has no success frame. This prefix marks the existing error
/// frame. Local show is already off.
pub const LOCAL_SHOW_DISABLE_FAILED: &str = "local show is off, but the stop marker was not saved";

/// Sentence the local-show banner uses to name the recovery path.
///
/// Stop writes `gui_show_local_disabled` in the data directory. Deleting
/// that marker turns local show back on.
pub const LOCAL_SHOW_REENABLE: &str =
    "Delete gui_show_local_disabled in the data directory to turn local show back on.";

/// Sentence a rider banner uses to name the recovery path.
///
/// Stop for a rider writes that agent into `gui_show_blocked.json`.
/// Deleting `gui_show_local_disabled` does not remove the entry. The
/// block list is loaded when the daemon starts, so the daemon must be
/// restarted after the id is removed.
pub const RIDER_SHOW_REENABLE: &str = "Remove this agent's id from gui_show_blocked.json in the data directory and restart the daemon to allow shows from this rider again.";

/// Data-directory marker Stop writes for this daemon.
///
/// A named instance with no config file is a normal start (`x0xd --name`,
/// `serve(config)`). Creating `config.toml` that holds only `[gui_show]`
/// makes the next start refuse: the file is loaded and has no `network_id`.
pub(crate) const LOCAL_SHOW_STOP_FILE: &str = "gui_show_local_disabled";

/// How long the daemon waits for a display confirmation.
///
/// This bound is not the opener's lifetime. `xdg-open` can still be running
/// after it has opened the application. A child that is still running here
/// counts as `opened` and is not killed.
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
    /// Start of the current session token's lifetime.
    ///
    /// Show sets this to the mint. Refresh moves it to that refresh. The
    /// banner then lasts one session-token TTL from here, the same window
    /// the refreshed token stays valid.
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
    /// A visible GUI tab accepted the show frame on its outbound queue.
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
    /// `issued_at` is outside ±120 s. Replay stays a drop, with no result.
    StaleRequest,
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

    /// Open `url`, returning when `stop` is set.
    ///
    /// Shutdown sets `stop` and then joins the launch. A launch that ignores
    /// `stop` keeps running after that join: the blocking pool cannot abort it.
    fn open_until(&self, url: &str, stop: &AtomicBool) -> bool {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        self.open(url)
    }
}

/// Production opener: `open` / `xdg-open` / `cmd /C start`.
#[derive(Debug, Default)]
pub struct PlatformOpener;

impl ShowOpener for PlatformOpener {
    fn open(&self, url: &str) -> bool {
        self.open_until(url, open_stop_never())
    }

    fn open_until(&self, url: &str, stop: &AtomicBool) -> bool {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        match platform_opener_spawn(url) {
            Some(Ok(child)) => opener_displayed_until(child, OPENER_WAIT, stop),
            Some(Err(_)) | None => false,
        }
    }
}

/// A stop flag that is never set. Tests of the display wait use it.
fn open_stop_never() -> &'static AtomicBool {
    static NEVER: AtomicBool = AtomicBool::new(false);
    &NEVER
}

/// Start the platform opener. `None` means this OS has no opener.
fn platform_opener_spawn(url: &str) -> Option<std::io::Result<std::process::Child>> {
    #[cfg(target_os = "macos")]
    {
        let mut cmd = std::process::Command::new("open");
        cmd.arg(url);
        silenced_stdio(&mut cmd);
        Some(cmd.spawn())
    }
    #[cfg(target_os = "linux")]
    {
        let mut cmd = std::process::Command::new("xdg-open");
        cmd.arg(url);
        silenced_stdio(&mut cmd);
        Some(cmd.spawn())
    }
    #[cfg(target_os = "windows")]
    {
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "start", url]);
        silenced_stdio(&mut cmd);
        Some(cmd.spawn())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = url;
        None
    }
}

/// Discard the opener's stdin, stdout, and stderr.
///
/// A failed `xdg-open` prints the URL it was given. That URL contains the
/// session token, so an inherited stderr would put the token in the daemon log.
fn silenced_stdio(cmd: &mut std::process::Command) {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
}

/// Display confirmation for one opener. This does not decide how long the
/// process may live, and it does not kill `child`.
///
/// A zero exit within `bound` is a display. A nonzero exit is not. A child
/// that is still running at `bound` is a display: on Linux, `xdg-open` can
/// remain running after it has opened the application.
#[cfg(test)]
fn opener_display_confirmed(child: &mut std::process::Child, bound: Duration) -> bool {
    opener_display_confirmed_until(child, bound, open_stop_never())
}

fn opener_display_confirmed_until(
    child: &mut std::process::Child,
    bound: Duration,
    stop: &AtomicBool,
) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() >= deadline => return true,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Reap `child` when it exits. A child that is still running keeps running.
///
/// The wait sits on its own thread so the display decision can return at
/// [`OPENER_WAIT`] without killing the opener. Dropping `Child` without a
/// wait would leave a zombie after a later exit.
fn retain_opener_until_exit(mut child: std::process::Child) {
    match child.try_wait() {
        Ok(Some(_)) => {}
        Err(_) => {
            let _ = child.wait();
        }
        Ok(None) => {
            let _ = std::thread::Builder::new()
                .name("x0x-gui-opener".to_string())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

/// Confirm a display, then hand the process to [`retain_opener_until_exit`].
#[cfg(test)]
fn opener_displayed(child: std::process::Child, bound: Duration) -> bool {
    opener_displayed_until(child, bound, open_stop_never())
}

fn opener_displayed_until(
    mut child: std::process::Child,
    bound: Duration,
    stop: &AtomicBool,
) -> bool {
    let confirmed = opener_display_confirmed_until(&mut child, bound, stop);
    retain_opener_until_exit(child);
    confirmed
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
    /// Embedder or last TOML `[gui_show]`, without the Stop override.
    ///
    /// Stop forces the published `local_enabled` off. It does not write
    /// this copy. Deleting the marker restores it when no daemon config
    /// file is available to re-read.
    supplied_config: Mutex<GuiShowConfig>,
    rate_limit: Mutex<GuiShowRateLimit>,
    blocked: Mutex<HashSet<[u8; 32]>>,
    opener: Mutex<Arc<dyn ShowOpener>>,
    /// Daemon TOML that `POST /acl/reload` re-reads. `None` means startup
    /// loaded no file.
    config_path: Mutex<Option<PathBuf>>,
    /// Daemon config path a later file can be read from.
    ///
    /// This is the loaded config, or the default config path when startup
    /// loaded no file. Stop does not create or modify it.
    write_path: Mutex<Option<PathBuf>>,
    blocked_path: PathBuf,
    /// `data_dir/gui_show_local_disabled`. Stop always writes this marker.
    local_stop_path: PathBuf,
    /// True after this process saved the marker, or found it at startup.
    ///
    /// Deleting that marker clears it. A failed marker write leaves this
    /// false: the file is absent, and only [`Self::local_stopped`] keeps
    /// show off for this process.
    stop_persisted: AtomicBool,
    /// In-memory Stop. Set before the marker write, so a failed write still
    /// rejects a later reload of `local_enabled = true`. Cleared only when
    /// a marker this process saved is deleted.
    local_stopped: AtomicBool,
    /// Set by the shutdown drain. An in-flight launch polls it and returns.
    ///
    /// The launch runs on the blocking pool, which shutdown cannot abort.
    /// The drain sets this flag, then joins the tracked launch.
    open_stop: Arc<AtomicBool>,
    /// Shows waiting for the GUI window that was opened for each one.
    pending: Mutex<VecDeque<PendingGuiShow>>,
    /// Session token a refresh replaced, for an upgrade that authenticated
    /// with the old token and registers after the refresh.
    ///
    /// The pending banner moves in the same critical section as this map.
    /// A take follows the chain, so refresh cannot leave the banner on a
    /// token the socket no longer searches. A socket already in the roster
    /// is updated after this map. Registration consults the map too.
    session_successors: Mutex<HashMap<String, (String, Instant)>>,
    /// Waiters shared by the remote show sender and the receive handler.
    remote_hub: crate::gui::remote::RemoteHub,
    /// Unix seconds when a GUI window was last visible.
    last_gui_visible_at: Mutex<Option<u64>>,
    /// Show request ids already seen, for the ADR 0050 replay window.
    replay: Mutex<crate::gui::remote::ReplayCache>,
    /// In-flight result and activity reply sends.
    reply_permits: Arc<tokio::sync::Semaphore>,
    /// Refusals sent to senders that are not owner-trusted.
    untrusted_refusals: Mutex<UntrustedRefusalWindow>,
    /// Rider subjects presented by each envelope signer.
    ///
    /// Stop records `(signer, subject)` from this map and blocks the signer.
    /// It does not add the subject to [`Self::blocked`]. The map drops the
    /// signer on Stop and evicts the lowest id past the caps below.
    rider_presented: Mutex<HashMap<[u8; 32], HashSet<[u8; 32]>>>,
    /// Rider shows refused for one `(envelope signer, subject)` pair.
    rider_pairs: Mutex<HashSet<([u8; 32], [u8; 32])>>,
    /// Senders a test treats as owner-trusted. Production leaves this empty.
    ///
    /// The AppState test agent has no user key. Installing one starts
    /// owner sync, and that constructor dials.
    trusted_senders: Mutex<HashSet<AgentId>>,
    /// Replaces the remote show send when a test installs it.
    ///
    /// Production leaves this empty. The send function calls it and does
    /// not branch on `cfg(test)`.
    send_hook: Mutex<Option<ShowSendHook>>,
    /// Test seam: milliseconds `send_show_result` waits before it returns.
    ///
    /// Zero uses the real send. The receive tests arm this so one slow
    /// reply is visible without a network attempt.
    #[cfg(test)]
    reply_delay_ms: std::sync::atomic::AtomicU64,
    /// How many test reply sends ran while `reply_delay_ms` was set.
    #[cfg(test)]
    reply_sends: std::sync::atomic::AtomicU32,
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
        let local_stop_path = data_dir.join(LOCAL_SHOW_STOP_FILE);
        let blocked = load_blocked(&blocked_path);
        let runtime = Self {
            config: Mutex::new(config.clone()),
            supplied_config: Mutex::new(config),
            rate_limit: Mutex::new(GuiShowRateLimit::default()),
            blocked: Mutex::new(blocked),
            opener: Mutex::new(opener),
            config_path: Mutex::new(config_path),
            write_path: Mutex::new(None),
            blocked_path,
            local_stop_path,
            stop_persisted: AtomicBool::new(false),
            local_stopped: AtomicBool::new(false),
            open_stop: Arc::new(AtomicBool::new(false)),
            pending: Mutex::new(VecDeque::new()),
            session_successors: Mutex::new(HashMap::new()),
            remote_hub: crate::gui::remote::RemoteHub::new(),
            last_gui_visible_at: Mutex::new(None),
            replay: Mutex::new(crate::gui::remote::ReplayCache::new()),
            reply_permits: Arc::new(tokio::sync::Semaphore::new(REPLY_SEND_SLOTS)),
            untrusted_refusals: Mutex::new(UntrustedRefusalWindow::default()),
            rider_presented: Mutex::new(HashMap::new()),
            rider_pairs: Mutex::new(HashSet::new()),
            trusted_senders: Mutex::new(HashSet::new()),
            send_hook: Mutex::new(None),
            #[cfg(test)]
            reply_delay_ms: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            reply_sends: std::sync::atomic::AtomicU32::new(0),
        };
        // Honour a stop recorded before this process. The marker wins over
        // a config that already says `local_enabled = true`, because Stop
        // does not rewrite that file.
        runtime.apply_persisted_local_stop();
        runtime
    }

    /// Production default: platform opener, no config path.
    pub fn with_defaults(config: GuiShowConfig, data_dir: &std::path::Path) -> Self {
        Self::new(config, None, data_dir, Arc::new(PlatformOpener))
    }

    /// Snapshot of `[gui_show]`.
    ///
    /// A deleted stop marker is applied here, so the next show sees it
    /// without a new route and without `POST /acl/reload`.
    pub fn config(&self) -> GuiShowConfig {
        self.lift_stop_if_marker_deleted();
        let mut config = self.config_snapshot();
        if self.local_stop_in_force() {
            config.local_enabled = false;
        }
        config
    }

    /// Hub the requester waits on and the receive handler completes.
    pub fn remote_hub(&self) -> &crate::gui::remote::RemoteHub {
        &self.remote_hub
    }

    /// Arm a per-state reply delay and clear the send counter.
    #[cfg(test)]
    pub fn arm_reply_delay_for_test(&self, delay_ms: u64) {
        self.reply_sends
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.reply_delay_ms
            .store(delay_ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// Reply sends observed while the test delay is armed.
    #[cfg(test)]
    pub fn reply_sends_for_test(&self) -> u32 {
        self.reply_sends.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Milliseconds the test reply path waits. Zero means use the real send.
    #[cfg(test)]
    pub(crate) fn reply_delay_ms_for_test(&self) -> u64 {
        self.reply_delay_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Count one delayed test reply.
    #[cfg(test)]
    pub(crate) fn count_reply_send_for_test(&self) {
        self.reply_sends
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Make the remote show send wait past the 10 s deadline.
    ///
    /// The wait lives in this hook. `send_gui_dm` only calls the hook.
    #[cfg(test)]
    pub fn arm_send_stall_for_test(&self) {
        let hook: ShowSendHook = Arc::new(|| {
            Box::pin(async {
                tokio::time::sleep(super::remote::RESULT_WAIT + std::time::Duration::from_secs(30))
                    .await;
                Err(crate::dm::DmError::RecipientUndiscovered(
                    "gui show test stall".to_string(),
                ))
            }) as Pin<Box<dyn Future<Output = Result<(), crate::dm::DmError>> + Send>>
        });
        if let Ok(mut guard) = self.send_hook.lock() {
            *guard = Some(hook);
        }
    }

    /// Treat `agent` as owner-trusted on the receive path.
    #[cfg(test)]
    pub fn trust_sender_for_test(&self, agent: &AgentId) {
        if let Ok(mut guard) = self.trusted_senders.lock() {
            guard.insert(*agent);
        }
    }

    /// One slot for a detached reply send. `None` when every slot is in use.
    pub(crate) fn try_reply_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.reply_permits.clone().try_acquire_owned().ok()
    }

    /// Whether this process may send one more refusal to an untrusted sender.
    ///
    /// The window is one minute. A full window skips the send. The caller
    /// does not wait.
    pub(crate) fn allow_untrusted_refusal(&self, now: Instant) -> bool {
        let Ok(mut window) = self.untrusted_refusals.lock() else {
            return false;
        };
        match window.start {
            Some(start) if now.saturating_duration_since(start) < UNTRUSTED_REFUSAL_WINDOW => {}
            _ => {
                window.start = Some(now);
                window.sent = 0;
            }
        }
        if window.sent >= UNTRUSTED_REFUSAL_LIMIT {
            return false;
        }
        window.sent = window.sent.saturating_add(1);
        true
    }

    /// Record that a GUI window was visible at `unix_secs`.
    ///
    /// Active-machine selection reads this stamp. A poisoned lock is recovered.
    pub fn note_gui_visible(&self, unix_secs: u64) {
        *self
            .last_gui_visible_at
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Some(unix_secs);
    }

    /// Last unix time a GUI window was visible, if one has been seen.
    pub fn last_gui_visible_at(&self) -> Option<u64> {
        *self
            .last_gui_visible_at
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    /// Remember a show request. True when that id is still inside the replay window.
    pub fn observe_show_replay(
        &self,
        sender: &[u8; 32],
        request_id: [u8; 16],
        now_unix: u64,
    ) -> bool {
        self.with_replay_cache(|cache| cache.observe(sender, request_id, now_unix))
    }

    /// Run `body` against the show replay cache.
    ///
    /// The receive handler passes this cache into ingress_show. The lock
    /// ends when `body` returns, so it is not held across an await. A
    /// poisoned lock is recovered.
    pub(crate) fn with_replay_cache<R>(
        &self,
        body: impl FnOnce(&mut crate::gui::remote::ReplayCache) -> R,
    ) -> R {
        let mut cache = self.replay.lock().unwrap_or_else(|err| err.into_inner());
        body(&mut cache)
    }

    fn config_snapshot(&self) -> GuiShowConfig {
        self.config.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Replace config (tests / acl reload after a successful TOML parse).
    ///
    /// A stop marker, or an in-memory Stop whose marker write failed, forces
    /// `local_enabled` off in the same critical section as the store. A
    /// reload cannot publish `true` after Stop, including when the marker
    /// file was never created.
    pub fn set_config(&self, config: GuiShowConfig) {
        if let Ok(mut supplied) = self.supplied_config.lock() {
            *supplied = config.clone();
        }
        self.publish_config(config);
    }

    /// Store `config`, with Stop still forcing `local_enabled` off.
    ///
    /// The supplied copy is unchanged. Callers that replace the embedder
    /// or TOML value use [`Self::set_config`].
    fn publish_config(&self, mut config: GuiShowConfig) {
        if let Ok(mut guard) = self.config.lock() {
            if self.local_stop_path.is_file() {
                config.local_enabled = false;
                self.stop_persisted.store(true, Ordering::SeqCst);
                self.local_stopped.store(true, Ordering::SeqCst);
            } else if self.local_stopped.load(Ordering::SeqCst) {
                config.local_enabled = false;
            }
            *guard = config;
        }
    }

    fn supplied_snapshot(&self) -> GuiShowConfig {
        self.supplied_config
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn local_stop_in_force(&self) -> bool {
        self.local_stopped.load(Ordering::SeqCst) || self.local_stop_path.is_file()
    }

    /// Re-read `[gui_show]` from the daemon TOML when a path is known.
    ///
    /// No path means startup loaded no file. A missing write path is not an
    /// error. A read failure or a TOML error is returned and does not change
    /// the in-memory config.
    ///
    /// The stop marker stays in force while the file exists, including when
    /// the daemon config already says `local_enabled = true`. Deleting the
    /// marker returns control to that config. With no config file, deleting
    /// the marker restores the configuration supplied to this process. The
    /// default is on. An embedder that passed `local_enabled = false` stays off.
    pub fn reload_from_disk(&self) -> Result<(), String> {
        let had_config_path = self.stored_config_path().is_some();
        let Some(path) = self.reload_config_path() else {
            self.lift_stop_if_marker_deleted();
            return Ok(());
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("failed to read GUI config {}: {error}", path.display()))?;
        let gui_show = parse_gui_show_table(&text)
            .map_err(|error| format!("failed to parse GUI config {}: {error}", path.display()))?;
        self.set_config(gui_show);
        if !had_config_path {
            self.set_config_path(Some(path));
        }
        Ok(())
    }

    /// Apply a data-directory stop from an earlier process.
    ///
    /// The marker forces show off, including when the loaded config sets
    /// `local_enabled = true` and when startup loaded no file (`serve(config)`,
    /// or `x0xd --name` with no config). Stop does not rewrite the config, so
    /// that existing value is not a new enable decision.
    pub(crate) fn apply_persisted_local_stop(&self) {
        if !self.local_stop_path.is_file() {
            return;
        }
        self.stop_persisted.store(true, Ordering::SeqCst);
        self.local_stopped.store(true, Ordering::SeqCst);
        self.publish_config(self.supplied_snapshot());
    }

    /// A human deleted a marker this process had saved.
    ///
    /// A failed marker write sets [`Self::local_stopped`] and leaves
    /// `stop_persisted` false, so this returns without turning show on.
    /// With a daemon config, the file's `[gui_show]` applies again once the
    /// saved marker is gone. With no file, show returns to the configuration
    /// supplied to this process. Stop does not replace that value.
    fn lift_stop_if_marker_deleted(&self) {
        if self.local_stop_path.is_file() {
            return;
        }
        if !self.stop_persisted.swap(false, Ordering::SeqCst) {
            return;
        }
        self.local_stopped.store(false, Ordering::SeqCst);
        let Some(path) = self.reload_config_path() else {
            self.set_config(self.supplied_snapshot());
            return;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            self.stop_persisted.store(true, Ordering::SeqCst);
            self.local_stopped.store(true, Ordering::SeqCst);
            return;
        };
        match parse_gui_show_table(&text) {
            Ok(gui_show) => self.set_config(gui_show),
            Err(_) => {
                self.stop_persisted.store(true, Ordering::SeqCst);
                self.local_stopped.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Config path `POST /acl/reload` reads when startup loaded no file.
    pub fn set_write_path(&self, path: Option<PathBuf>) {
        if let Ok(mut guard) = self.write_path.lock() {
            *guard = path;
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

    /// Record that local show is off, then write the data-directory marker.
    ///
    /// This is the Stop control for a local show (`gui.block` of this
    /// daemon's agent). It does not add the agent to `gui_show_blocked`.
    /// The banner tells the human to delete `gui_show_local_disabled` in
    /// the data directory to turn show back on.
    ///
    /// Show is turned off in memory first, so a marker write failure still
    /// leaves show off. Stop writes only that marker. It does not create or
    /// modify the daemon config: a named instance would then refuse to start.
    pub fn disable_local_show(&self) -> Result<(), String> {
        self.local_stopped.store(true, Ordering::SeqCst);
        self.remember_local_stop();
        let wrote = self.write_local_stop_file();
        if wrote.is_ok() {
            self.stop_persisted.store(true, Ordering::SeqCst);
            // The marker exists now. Store again so a reload that parsed
            // `local_enabled = true` cannot publish that value afterwards.
            self.remember_local_stop();
        }
        wrote
    }

    fn remember_local_stop(&self) {
        self.publish_config(self.supplied_snapshot());
    }

    fn write_local_stop_file(&self) -> Result<(), String> {
        let report = |error: std::io::Error| {
            format!(
                "{LOCAL_SHOW_DISABLE_FAILED}: failed to write {}: {error}",
                self.local_stop_path.display()
            )
        };
        if let Some(parent) = self.local_stop_path.parent() {
            std::fs::create_dir_all(parent).map_err(&report)?;
        }
        std::fs::write(&self.local_stop_path, b"local_enabled = false\n").map_err(report)
    }

    fn stored_config_path(&self) -> Option<PathBuf> {
        self.config_path.lock().ok().and_then(|guard| guard.clone())
    }

    fn stored_write_path(&self) -> Option<PathBuf> {
        self.write_path.lock().ok().and_then(|guard| guard.clone())
    }

    /// Config file `POST /acl/reload` should read.
    ///
    /// The path startup loaded wins, even when it is missing, so a read
    /// error is reported. When startup loaded no file, a config the human
    /// has since created at the write path is the re-enable file.
    fn reload_config_path(&self) -> Option<PathBuf> {
        if let Some(path) = self.stored_config_path() {
            return Some(path);
        }
        let write = self.stored_write_path()?;
        if write.is_file() {
            Some(write)
        } else {
            None
        }
    }

    /// Rate-limit gate; `true` means the show may proceed.
    pub fn try_rate_limit(&self, agent: &AgentId, now: Instant) -> bool {
        self.try_rate_limit_agents(std::slice::from_ref(agent), now)
    }

    /// Rate-limit gate for every distinct agent on one show.
    ///
    /// One hourly slot is spent when every agent still has a token.
    pub fn try_rate_limit_agents(&self, agents: &[AgentId], now: Instant) -> bool {
        self.rate_limit
            .lock()
            .map(|mut guard| guard.try_acquire_all(agents, now))
            .unwrap_or(false)
    }

    /// Remember that `signer` displayed a rider show naming `subject`.
    ///
    /// A signer or subject past the cap replaces the lowest id. Stop still
    /// blocks the signer when that signer's row was evicted.
    pub fn note_rider_presentation(&self, signer: &AgentId, subject: &AgentId) {
        let Ok(mut presented) = self.rider_presented.lock() else {
            return;
        };
        let signer_key = *signer.as_bytes();
        let subject_key = *subject.as_bytes();
        if !presented.contains_key(&signer_key) && presented.len() >= RIDER_PRESENTED_SIGNERS {
            if let Some(evict) = presented.keys().copied().min() {
                presented.remove(&evict);
            }
        }
        let subjects = presented.entry(signer_key).or_default();
        if !subjects.contains(&subject_key) && subjects.len() >= RIDER_PRESENTED_SUBJECTS {
            if let Some(evict) = subjects.iter().copied().min() {
                subjects.remove(&evict);
            }
        }
        subjects.insert(subject_key);
    }

    /// Record `(signer, subject)` for every subject this signer presented.
    ///
    /// Does not add those subjects to the block list. The signer row is
    /// removed, so a later show starts a new set.
    pub fn record_rider_stop(&self, signer: &AgentId) {
        let subjects = self
            .rider_presented
            .lock()
            .ok()
            .and_then(|mut presented| presented.remove(signer.as_bytes()))
            .unwrap_or_default();
        let Ok(mut pairs) = self.rider_pairs.lock() else {
            return;
        };
        for subject in subjects {
            pairs.insert((*signer.as_bytes(), subject));
        }
    }

    /// Whether Stop on a rider show from `signer` named `subject`.
    pub fn rider_pair_blocked(&self, signer: &AgentId, subject: &AgentId) -> bool {
        self.rider_pairs
            .lock()
            .map(|pairs| pairs.contains(&(*signer.as_bytes(), *subject.as_bytes())))
            .unwrap_or(false)
    }

    /// Whether a test opted this sender in as owner-trusted.
    ///
    /// Production stays false. The receive path calls this instead of a
    /// `cfg(test)` branch.
    pub(crate) fn trust_hook_allows(&self, agent: &AgentId) -> bool {
        self.trusted_senders
            .lock()
            .map(|guard| guard.contains(agent))
            .unwrap_or(false)
    }

    /// Run a test send replacement. `None` means use the real send.
    pub(crate) async fn invoke_send_hook(&self) -> Option<Result<(), crate::dm::DmError>> {
        let hook = self.send_hook.lock().ok().and_then(|guard| guard.clone())?;
        Some(hook().await)
    }

    /// Opener for one launch.
    ///
    /// The mutex only publishes the opener. The launch must not run under
    /// it: the platform wait lasts up to [`OPENER_WAIT`], and holding the
    /// lock queues later launches behind that wait.
    pub(crate) fn opener_for_launch(&self) -> Option<Arc<dyn ShowOpener>> {
        self.opener.lock().ok().map(|guard| Arc::clone(&guard))
    }

    /// Flag the shutdown drain sets so an in-flight launch returns.
    pub(crate) fn open_stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.open_stop)
    }

    /// Ask every in-flight browser launch to return.
    ///
    /// The shutdown drain calls this before it joins those launches.
    pub(crate) fn stop_opening(&self) {
        self.open_stop.store(true, Ordering::Release);
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
    ///
    /// A banner put back after a full queue follows the same refresh chain
    /// as a take. Refresh cannot strand it on the token it left.
    pub fn enqueue_pending(&self, mut pending: PendingGuiShow) {
        let Ok(mut map) = self.session_successors.lock() else {
            return;
        };
        let Ok(mut queue) = self.pending.lock() else {
            return;
        };
        let now = Instant::now();
        expire_session_successors(&mut map, now);
        pending.session_token = current_token_locked(&map, &pending.session_token);
        queue.retain(|item| pending_is_fresh(item, now));
        queue.push_back(pending);
    }

    /// Remember that `from_token` was refreshed to `to_token`.
    ///
    /// An upgrade can authenticate with `from_token` and register only after
    /// this refresh. The banner already sits on `to_token`. Registration
    /// reads the map so the socket does too. Older tokens point at the newest
    /// one and keep the expiry from the refresh that recorded them. A later
    /// refresh does not extend that time. The oldest records are dropped
    /// once the map reaches its cap.
    pub(crate) fn note_gui_session_successor(&self, from_token: &str, to_token: &str) {
        if from_token.is_empty() || to_token.is_empty() || from_token == to_token {
            return;
        }
        let Ok(mut map) = self.session_successors.lock() else {
            return;
        };
        note_successor_locked(&mut map, from_token, to_token, Instant::now());
    }

    /// Token a GUI socket should store after any refreshes of `token`.
    pub(crate) fn current_gui_session_token(&self, token: &str) -> String {
        let Ok(mut map) = self.session_successors.lock() else {
            return token.to_string();
        };
        let now = Instant::now();
        expire_session_successors(&mut map, now);
        current_token_locked(&map, token)
    }

    /// Keep a queued origin banner when this GUI session token is refreshed.
    ///
    /// A hidden tab can refresh before its WebSocket reconnects. The new
    /// connection presents the new token. The banner stays with that tab
    /// for the new token's TTL, which starts at this refresh. Other
    /// sessions stay on their own tokens and their own clocks.
    ///
    /// The banner move and the successor record share one critical section.
    /// A take cannot observe the banner on the old token after the map has
    /// already moved, or on the new token before the map says so.
    pub fn rebind_pending_session(&self, from_token: &str, to_token: &str) {
        if from_token.is_empty() || to_token.is_empty() || from_token == to_token {
            return;
        }
        let Ok(mut map) = self.session_successors.lock() else {
            return;
        };
        let Ok(mut queue) = self.pending.lock() else {
            return;
        };
        let now = Instant::now();
        note_successor_locked(&mut map, from_token, to_token, now);
        for item in queue.iter_mut() {
            if item.session_token == from_token {
                item.session_token = to_token.to_string();
                // `SessionStore::refresh` sets the new token's expiry to
                // `now + SESSION_TOKEN_TTL`. The banner uses that same start.
                item.created_at = now;
            }
        }
    }

    /// Take the fresh pending show minted for this GUI session token.
    ///
    /// The token may be the one the upgrade captured. Refresh may already
    /// have moved the banner. This follows that chain under the same locks
    /// the move uses, then takes the banner. A miss leaves every other
    /// pending show in place. Stale entries are dropped. An agent socket
    /// must not call this.
    pub fn take_pending_for_session(
        &self,
        session_token: &str,
        now: Instant,
    ) -> Option<PendingGuiShow> {
        let Ok(mut map) = self.session_successors.lock() else {
            return None;
        };
        let Ok(mut queue) = self.pending.lock() else {
            return None;
        };
        expire_session_successors(&mut map, now);
        let current = current_token_locked(&map, session_token);
        queue.retain(|item| pending_is_fresh(item, now));
        let idx = queue
            .iter()
            .position(|item| item.session_token == current)?;
        queue.remove(idx)
    }

    /// Drop one queued banner. Other sessions stay queued.
    ///
    /// Used when the platform opener fails after the banner was queued.
    pub fn drop_pending_for_session(&self, session_token: &str) {
        if let Ok(mut queue) = self.pending.lock() {
            queue.retain(|item| item.session_token != session_token);
        }
    }

    /// Whether a fresh-or-stale pending show is still queued for `session_token`.
    pub fn has_pending_session(&self, session_token: &str) -> bool {
        self.pending
            .lock()
            .map(|queue| queue.iter().any(|item| item.session_token == session_token))
            .unwrap_or(false)
    }
}

fn expire_session_successors(map: &mut HashMap<String, (String, Instant)>, now: Instant) {
    map.retain(|_, (_, noted)| now.saturating_duration_since(*noted) <= PENDING_FRESHNESS);
}

/// Point `from_token`, and any older token that still names it, at `to_token`.
fn note_successor_locked(
    map: &mut HashMap<String, (String, Instant)>,
    from_token: &str,
    to_token: &str,
    now: Instant,
) {
    expire_session_successors(map, now);
    // Point older records at the new token. Leave each record's noted
    // time alone: that is when this predecessor was recorded, and a later
    // refresh must not extend it.
    for (next, _) in map.values_mut() {
        if next == from_token {
            *next = to_token.to_string();
        }
    }
    map.insert(from_token.to_string(), (to_token.to_string(), now));
    bound_session_successors(map, from_token);
}

/// Drop the oldest predecessor records once the map is past the cap.
///
/// `keep` is the record just inserted. It is the newest and stays.
fn bound_session_successors(map: &mut HashMap<String, (String, Instant)>, keep: &str) {
    while map.len() > MAX_GUI_SESSION_SUCCESSORS {
        let oldest = map
            .iter()
            .filter(|(token, _)| token.as_str() != keep)
            .min_by_key(|(_, (_, noted))| *noted)
            .map(|(token, _)| token.clone());
        let Some(oldest) = oldest else {
            break;
        };
        map.remove(&oldest);
    }
}

/// Newest token reachable from `token`. The caller already holds the map.
fn current_token_locked(map: &HashMap<String, (String, Instant)>, token: &str) -> String {
    let mut current = token.to_string();
    for _ in 0..MAX_GUI_SESSION_SUCCESSORS {
        let Some((next, _)) = map.get(&current) else {
            break;
        };
        if next == &current {
            break;
        }
        current = next.clone();
    }
    current
}

/// Whether `pending` is still inside its current session token TTL.
///
/// The window starts at [`PendingGuiShow::created_at`]. Show sets that to
/// the mint. Refresh moves it with the new token. A hidden tab revealed
/// inside that window still receives the banner and its Stop control.
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
///
/// The second sentence follows the sender. A local show names
/// `gui_show_local_disabled`. A rider names `gui_show_blocked.json` and
/// a daemon restart, because Stop writes that file and the process reads
/// it at start.
pub fn origin_banner(agent_label: &str, machine_label: &str, rider: bool) -> String {
    let opened = if rider {
        format!("Opened by {agent_label} (rider) on {machine_label}")
    } else {
        format!("Opened by {agent_label} on {machine_label}")
    };
    let recovery = if rider {
        RIDER_SHOW_REENABLE
    } else {
        LOCAL_SHOW_REENABLE
    };
    format!("{opened}. {recovery}")
}

/// `[gui_show]` from a daemon TOML document.
///
/// Absent keys use [`GuiShowConfig`]'s defaults. A parse error is the TOML
/// error text.
fn parse_gui_show_table(text: &str) -> Result<GuiShowConfig, String> {
    #[derive(Deserialize)]
    struct Partial {
        #[serde(default)]
        gui_show: GuiShowConfig,
    }
    toml::from_str::<Partial>(text)
        .map(|partial| partial.gui_show)
        .map_err(|error| error.to_string())
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

    #[test]
    fn another_agent_block_is_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let local = AgentId([2u8; 32]);
        let other = AgentId([3u8; 32]);
        rt.block_agent(&other);
        assert!(rt.is_blocked(&other));
        assert!(!rt.is_blocked(&local));
        let text =
            std::fs::read_to_string(dir.path().join("gui_show_blocked.json")).expect("block file");
        assert!(
            !text.contains(&hex::encode(local.as_bytes())),
            "the persisted list must not contain this daemon's agent: {text}"
        );
    }

    #[test]
    fn stop_local_show_persists_disabled_and_reload_reenables() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let original = "log_level = \"info\" # keep\n\n[gui_show]\nremote_enabled = true # stay\nlocal_enabled = true # operator\n\n[other]\nlocal_enabled = true\n";
        std::fs::write(&path, original).expect("write config");
        let rt = runtime(dir.path(), Some(path.clone()));
        let daemon = AgentId([2u8; 32]);
        rt.disable_local_show()
            .expect("stop records the data-dir marker");
        assert!(
            !rt.config().local_enabled,
            "stop applies local_enabled = false in memory"
        );
        assert!(rt.config().remote_enabled);
        assert!(
            !rt.is_blocked(&daemon),
            "stop must not use the per-agent block list"
        );
        assert!(
            !dir.path().join("gui_show_blocked.json").exists(),
            "stop must not create the block file"
        );
        let text = std::fs::read_to_string(&path).expect("config");
        assert_eq!(text, original, "stop leaves the daemon config unchanged");
        assert!(
            dir.path().join(LOCAL_SHOW_STOP_FILE).is_file(),
            "stop writes the data-dir marker"
        );
        std::fs::write(&path, original).expect("human sets local_enabled = true");
        rt.reload_from_disk().expect("reload after re-enable");
        assert!(
            !rt.config().local_enabled,
            "an unchanged local_enabled = true does not cancel Stop"
        );
        assert!(
            dir.path().join(LOCAL_SHOW_STOP_FILE).is_file(),
            "reload leaves the stop marker in place"
        );
        std::fs::remove_file(dir.path().join(LOCAL_SHOW_STOP_FILE)).expect("delete marker");
        assert!(
            rt.config().local_enabled,
            "deleting the marker turns local show back on"
        );
        assert!(rt.config().remote_enabled);
    }

    #[test]
    fn stop_never_writes_config_and_keeps_network_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let original = "network_id = \"x0x.testnet\"\nlog_level = \"info\"\n";
        std::fs::write(&path, original).expect("write config");
        let rt = runtime(dir.path(), Some(path.clone()));
        rt.disable_local_show().expect("stop writes the marker");
        let text = std::fs::read_to_string(&path).expect("config");
        assert_eq!(text, original, "stop leaves the daemon config unchanged");
        assert!(dir.path().join(LOCAL_SHOW_STOP_FILE).is_file());
        assert!(!rt.config().local_enabled);
        let (parsed, _) =
            crate::server::config::analyze(&text).expect("startup can parse the file");
        assert_eq!(parsed.network_id.as_deref(), Some("x0x.testnet"));
        assert!(
            !crate::server::config::named_instance_refuses_startup(
                true,
                parsed.network_id.as_deref()
            ),
            "a named instance whose config still has network_id starts"
        );

        #[cfg(unix)]
        {
            let link_dir = tempfile::tempdir().expect("tempdir");
            let target = link_dir.path().join("real-config.toml");
            let link = link_dir.path().join("config.toml");
            let linked = "network_id = \"x0x.symlink\"\n# keep this comment\n[gui_show]\nlocal_enabled = true\n";
            std::fs::write(&target, linked).expect("symlink target");
            std::os::unix::fs::symlink(&target, &link).expect("symlink config");
            let linked_rt = runtime(link_dir.path(), Some(link.clone()));
            linked_rt
                .disable_local_show()
                .expect("stop writes the marker and leaves the symlink");
            let meta = std::fs::symlink_metadata(&link).expect("symlink metadata");
            assert!(
                meta.file_type().is_symlink(),
                "stop leaves the config symlink in place"
            );
            assert_eq!(
                std::fs::read_to_string(&target).expect("target"),
                linked,
                "stop leaves the symlink target unchanged"
            );
            assert_eq!(std::fs::read_to_string(&link).expect("link"), linked);
            assert!(link_dir.path().join(LOCAL_SHOW_STOP_FILE).is_file());
            assert!(!linked_rt.config().local_enabled);
            assert!(!linked_rt.is_blocked(&AgentId([2u8; 32])));
            let (parsed, _) = crate::server::config::analyze(linked).expect("parses");
            assert_eq!(parsed.network_id.as_deref(), Some("x0x.symlink"));
            assert!(!crate::server::config::named_instance_refuses_startup(
                true,
                parsed.network_id.as_deref()
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn stop_keeps_show_off_when_the_marker_directory_is_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let original = "log_level = \"info\" # keep\n\n[gui_show]\nlocal_enabled = true\n";
        std::fs::write(&path, original).expect("write config");
        let rt = runtime(dir.path(), Some(path.clone()));
        let saved = std::fs::metadata(dir.path())
            .expect("data dir metadata")
            .permissions();
        struct RestorePerms {
            path: PathBuf,
            permissions: std::fs::Permissions,
        }
        impl Drop for RestorePerms {
            fn drop(&mut self) {
                let permissions = self.permissions.clone();
                let _ = std::fs::set_permissions(&self.path, permissions);
            }
        }
        let _restore = RestorePerms {
            path: dir.path().to_path_buf(),
            permissions: saved,
        };
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555))
            .expect("chmod");
        let error = rt
            .disable_local_show()
            .expect_err("the marker write is reported");
        assert!(error.starts_with(LOCAL_SHOW_DISABLE_FAILED), "{error}");
        let marker = dir.path().join(LOCAL_SHOW_STOP_FILE);
        assert!(error.contains(&marker.display().to_string()), "{error}");
        assert!(
            !rt.config().local_enabled,
            "show is off in memory when the marker write fails"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("config"),
            original,
            "stop leaves the daemon config unchanged"
        );
        assert!(!marker.exists(), "a failed marker write leaves no marker");
        rt.reload_from_disk()
            .expect("reload reads the unchanged config");
        assert!(
            !rt.config().local_enabled,
            "reload must not turn show on when the marker write failed"
        );
    }

    #[test]
    fn stop_on_a_named_instance_with_no_config_still_starts() {
        let data = tempfile::tempdir().expect("tempdir");
        let config_dir = tempfile::tempdir().expect("tempdir");
        let default_path = config_dir.path().join("config.toml");
        let rt = runtime(data.path(), None);
        rt.set_write_path(Some(default_path.clone()));
        rt.disable_local_show()
            .expect("stop persists without creating a config file");
        assert!(!rt.config().local_enabled);
        assert!(
            !default_path.exists(),
            "stop must not invent a daemon config"
        );
        assert!(data.path().join(LOCAL_SHOW_STOP_FILE).is_file());

        let loaded = startup_config_path(None, &default_path);
        assert!(loaded.is_none(), "startup still sees no config file");
        assert!(
            !crate::server::config::named_instance_refuses_startup(loaded.is_some(), None),
            "a named instance with no config file still starts"
        );

        let invented = "[gui_show]\nlocal_enabled = false\n";
        let (parsed, _) = crate::server::config::analyze(invented).expect("the old file parses");
        assert!(
            parsed.network_id.is_none(),
            "a gui_show-only file has no network_id"
        );
        assert!(
            crate::server::config::named_instance_refuses_startup(
                true,
                parsed.network_id.as_deref()
            ),
            "that file is what makes a named instance refuse to start"
        );

        let restarted = runtime(data.path(), None);
        assert!(
            !restarted.config().local_enabled,
            "the next start of the same data directory stays stopped"
        );

        std::fs::write(
            &default_path,
            "network_id = \"x0x.testnet\"\n\n[gui_show]\nlocal_enabled = true\n",
        )
        .expect("a real config that already enables show");
        let text = std::fs::read_to_string(&default_path).expect("config");
        let (parsed, _) = crate::server::config::analyze(&text).expect("startup parses it");
        assert!(
            !crate::server::config::named_instance_refuses_startup(
                startup_config_path(None, &default_path).is_some(),
                parsed.network_id.as_deref(),
            ),
            "the re-enable config still has network_id, so the named instance starts"
        );
        let still_stopped = runtime(data.path(), Some(default_path.clone()));
        assert!(
            !still_stopped.config().local_enabled,
            "a config that already says local_enabled = true does not clear the marker"
        );
        assert!(data.path().join(LOCAL_SHOW_STOP_FILE).is_file());
        std::fs::remove_file(data.path().join(LOCAL_SHOW_STOP_FILE)).expect("delete marker");
        let reenabled = runtime(data.path(), Some(default_path));
        assert!(
            reenabled.config().local_enabled,
            "deleting the marker lets the next start turn show on"
        );
        assert!(!data.path().join(LOCAL_SHOW_STOP_FILE).exists());
    }

    #[test]
    fn stop_without_a_config_path_persists_for_embedded_serve() {
        let data = tempfile::tempdir().expect("tempdir");
        let rt = runtime(data.path(), None);
        rt.disable_local_show()
            .expect("serve(config) has no config path");
        assert!(!rt.config().local_enabled);
        assert!(data.path().join(LOCAL_SHOW_STOP_FILE).is_file());
        assert!(
            rt.reload_from_disk().is_ok(),
            "reload with no config file is not an error"
        );
        assert!(
            !rt.config().local_enabled,
            "reload must not turn show back on while the marker is present"
        );

        std::fs::remove_file(data.path().join(LOCAL_SHOW_STOP_FILE)).expect("delete marker");
        assert!(
            rt.reload_from_disk().is_ok(),
            "reload after the marker is deleted is not an error"
        );
        assert!(
            rt.config().local_enabled,
            "deleting the marker turns show back on when no config file exists"
        );

        let restarted = runtime(data.path(), None);
        assert!(
            restarted.config().local_enabled,
            "the next serve of the same data directory follows the deleted marker"
        );
    }

    /// `serve(config)` passed `local_enabled = false` and has no config file.
    /// A marker from an earlier process forces Stop on top of that setting.
    /// Deleting the marker must restore the embedder's false, not enable show.
    #[test]
    fn deleting_a_stale_stop_marker_restores_an_embedder_disable() {
        let data = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            data.path().join(LOCAL_SHOW_STOP_FILE),
            b"local_enabled = false\n",
        )
        .expect("stale marker from a previous run");
        let rt = GuiShowRuntime::new(
            GuiShowConfig {
                local_enabled: false,
                remote_enabled: true,
            },
            None,
            data.path(),
            Arc::new(CapturingOpener::new()),
        );
        assert!(
            !rt.config().local_enabled,
            "the stale marker keeps show off"
        );
        assert!(rt.config().remote_enabled);
        std::fs::remove_file(data.path().join(LOCAL_SHOW_STOP_FILE)).expect("delete marker");
        assert!(
            !rt.config().local_enabled,
            "removing Stop restores the embedder's disabled setting"
        );
        assert!(rt.config().remote_enabled);
        assert!(
            rt.reload_from_disk().is_ok(),
            "reload with no config file is not an error"
        );
        assert!(
            !rt.config().local_enabled,
            "reload must not enable show when the embedder passed false"
        );
    }

    #[test]
    fn reload_keeps_a_side_file_stop_until_the_marker_is_deleted() {
        let data = tempfile::tempdir().expect("tempdir");
        let config_dir = tempfile::tempdir().expect("tempdir");
        let path = config_dir.path().join("config.toml");
        let rt = runtime(data.path(), None);
        rt.set_write_path(Some(path.clone()));
        rt.disable_local_show().expect("side-file stop");
        assert!(data.path().join(LOCAL_SHOW_STOP_FILE).is_file());

        std::fs::write(&path, "[gui_show]\nlocal_enabled = \n").expect("broken config");
        let error = rt.reload_from_disk().expect_err("invalid TOML");
        assert!(error.contains("failed to parse GUI config"), "{error}");
        assert!(!rt.config().local_enabled);
        assert!(data.path().join(LOCAL_SHOW_STOP_FILE).is_file());

        std::fs::write(&path, "network_id = \"x0x.testnet\"\n").expect("config without the key");
        rt.reload_from_disk().expect("reload");
        assert!(
            !rt.config().local_enabled,
            "a config that does not set local_enabled = true leaves the stop in place"
        );
        assert!(data.path().join(LOCAL_SHOW_STOP_FILE).is_file());
        let (parsed, _) = crate::server::config::analyze("network_id = \"x0x.testnet\"\n")
            .expect("named config parses");
        assert!(!crate::server::config::named_instance_refuses_startup(
            true,
            parsed.network_id.as_deref()
        ));

        std::fs::write(
            &path,
            "network_id = \"x0x.testnet\"\n\n[gui_show]\nlocal_enabled = true\n",
        )
        .expect("human re-enable");
        rt.reload_from_disk()
            .expect("POST /acl/reload reads local_enabled = true");
        assert!(
            !rt.config().local_enabled,
            "reload leaves Stop in force while the marker exists"
        );
        assert!(
            data.path().join(LOCAL_SHOW_STOP_FILE).is_file(),
            "reload does not delete the stop marker"
        );
        std::fs::remove_file(data.path().join(LOCAL_SHOW_STOP_FILE)).expect("delete marker");
        assert!(
            rt.config().local_enabled,
            "deleting the marker applies the config that sets local_enabled = true"
        );

        let restarted = runtime(data.path(), Some(path.clone()));
        restarted.set_config(GuiShowConfig {
            local_enabled: true,
            remote_enabled: true,
        });
        restarted.apply_persisted_local_stop();
        assert!(
            restarted.config().local_enabled,
            "a later start with no marker keeps show on"
        );
    }

    #[test]
    fn concurrent_reload_cannot_undo_stop() {
        use std::sync::{Arc, Barrier};

        let data = tempfile::tempdir().expect("tempdir");
        let path = data.path().join("config.toml");
        std::fs::write(
            &path,
            "[gui_show]\nlocal_enabled = true\nremote_enabled = true\n",
        )
        .expect("config");
        let rt = Arc::new(runtime(data.path(), Some(path)));
        rt.set_config(GuiShowConfig {
            local_enabled: true,
            remote_enabled: true,
        });
        let start = Arc::new(Barrier::new(2));
        let reload = {
            let rt = Arc::clone(&rt);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..40 {
                    rt.reload_from_disk().expect("reload");
                }
            })
        };
        let stop = {
            let rt = Arc::clone(&rt);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                rt.disable_local_show().expect("stop");
            })
        };
        reload.join().expect("reload thread");
        stop.join().expect("stop thread");
        assert!(
            data.path().join(LOCAL_SHOW_STOP_FILE).is_file(),
            "stop still owns the marker"
        );
        assert!(
            !rt.config().local_enabled,
            "a reload that parsed local_enabled = true must not outlive the marker"
        );
        rt.set_config(GuiShowConfig {
            local_enabled: true,
            remote_enabled: true,
        });
        assert!(
            !rt.config().local_enabled,
            "config() keeps show off while the marker exists"
        );
        rt.reload_from_disk().expect("reload after stop");
        assert!(!rt.config().local_enabled);
    }

    #[test]
    fn drop_pending_removes_only_the_failed_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let now = Instant::now();
        rt.enqueue_pending(pending("keep", "people", now));
        rt.enqueue_pending(pending("drop-me", "network", now));
        rt.drop_pending_for_session("drop-me");
        assert!(rt.take_pending_for_session("drop-me", now).is_none());
        assert_eq!(
            rt.take_pending_for_session("keep", now)
                .expect("the other show stays queued")
                .view,
            "people"
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
    fn opener_still_running_at_the_deadline_counts_as_opened_and_is_not_killed() {
        assert_eq!(
            OPENER_WAIT,
            Duration::from_secs(2),
            "the production display deadline is 2 seconds"
        );
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("spawn");
        let pid = child.id();
        let _guard = KillOnDrop(pid);
        let started = Instant::now();
        assert!(
            opener_display_confirmed(&mut child, Duration::from_millis(200)),
            "an opener still running at the deadline counts as opened"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "display confirmation returns at its own deadline"
        );
        assert!(
            process_is_running(pid),
            "display confirmation must not kill the opener"
        );
        retain_opener_until_exit(child);
        assert!(
            process_is_running(pid),
            "opener lifetime must not kill a running opener"
        );
    }

    #[cfg(unix)]
    #[test]
    fn opener_stop_flag_ends_the_display_wait() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("spawn");
        let pid = child.id();
        let _guard = KillOnDrop(pid);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            flag.store(true, Ordering::Release);
        });
        let started = Instant::now();
        assert!(
            !opener_display_confirmed_until(&mut child, OPENER_WAIT, &stop),
            "shutdown must end the display wait"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the display wait ignored the stop flag: {:?}",
            started.elapsed()
        );
        retain_opener_until_exit(child);
    }

    #[cfg(unix)]
    #[test]
    fn opener_silenced_stdio_hides_the_session_url_on_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = dir.path().join("stderr-target");
        let record_path = record.to_str().expect("utf8 temp path");
        // The child writes a session URL to stderr, records where fd 2 points,
        // then exits 1. Linux `readlink /dev/fd/2` prints that path. macOS
        // fdesc nodes are not symlinks, so the same script compares the fd
        // with `/dev/null` and records that path. `silenced_stdio` is the
        // production helper; this command does not set stdio itself.
        let script = r#"
printf '%s\n' 'http://127.0.0.1/gui?token=SECRETTOKEN' >&2
target=$(readlink /dev/fd/2 || true)
if [ -z "$target" ]; then
  fd_id=$(stat -f '%d:%i' /dev/fd/2)
  null_id=$(stat -f '%d:%i' /dev/null)
  if [ "$fd_id" = "$null_id" ]; then
    target=/dev/null
  else
    target=$fd_id
  fi
fi
printf '%s\n' "$target" > "$1"
exit 1
"#;
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", script, "sh", record_path]);
        silenced_stdio(&mut cmd);
        let child = cmd.spawn().expect("spawn");
        let pid = child.id();
        assert!(
            !opener_displayed(child, OPENER_WAIT),
            "a launcher that exits nonzero is no_display"
        );
        assert!(!process_is_zombie(pid), "the failed opener must be reaped");
        let recorded = std::fs::read_to_string(&record).expect("fd target");
        assert_eq!(
            recorded.trim(),
            "/dev/null",
            "stderr must be /dev/null so the session URL cannot enter a daemon log: {recorded}"
        );
        assert!(
            !recorded.contains("token=SECRETTOKEN"),
            "the failure path must not keep the session URL: {recorded}"
        );
    }

    #[cfg(unix)]
    struct KillOnDrop(u32);

    #[cfg(unix)]
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = std::process::Command::new("kill")
                .arg(self.0.to_string())
                .status();
        }
    }

    #[cfg(unix)]
    fn process_is_running(pid: u32) -> bool {
        std::process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
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
    fn take_follows_the_token_a_refresh_already_moved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let now = Instant::now();
        rt.enqueue_pending(pending("old-token", "people", now));
        rt.enqueue_pending(pending("other-tab", "network", now));
        rt.rebind_pending_session("old-token", "new-token");
        assert!(
            !rt.has_pending_session("old-token"),
            "refresh moves the banner off the captured token"
        );
        assert!(rt.has_pending_session("new-token"));
        let taken = rt
            .take_pending_for_session("old-token", now)
            .expect("the captured token must still find the banner");
        assert_eq!(taken.view, "people");
        assert_eq!(taken.session_token, "new-token");
        assert!(
            rt.has_pending_session("other-tab"),
            "another tab's banner must stay queued"
        );
    }

    #[test]
    fn hidden_refresh_at_minute_nine_keeps_banner_at_minute_eleven() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let refresh_at = Instant::now();
        let shown_at = refresh_at
            .checked_sub(Duration::from_secs(9 * 60))
            .expect("show is nine minutes before the refresh");
        let notice = origin_banner("agent", "machine", false);
        let mut shown = pending("shown-token", "people", shown_at);
        shown.banner = notice.clone();
        rt.enqueue_pending(shown);
        rt.enqueue_pending(pending("other-tab", "network", shown_at));

        // Hidden: refresh swaps the token and does not reveal the tab.
        rt.rebind_pending_session("shown-token", "refreshed-token");
        let refreshed_at = Instant::now();
        assert!(
            rt.has_pending_session("refreshed-token"),
            "the banner stays queued on the refreshed session while the tab is hidden"
        );
        assert!(!rt.has_pending_session("shown-token"));

        let revealed_at = shown_at + Duration::from_secs(11 * 60);
        assert!(
            revealed_at.saturating_duration_since(shown_at) > PENDING_FRESHNESS,
            "minute eleven is past the original show"
        );
        assert!(
            revealed_at.saturating_duration_since(refreshed_at) <= PENDING_FRESHNESS,
            "minute eleven is inside the refreshed session"
        );
        let kept = rt
            .take_pending_for_session("refreshed-token", revealed_at)
            .expect("reveal at minute eleven still delivers the origin banner and Stop control");
        assert_eq!(kept.view, "people");
        assert_eq!(kept.banner, notice);
        assert!(
            !rt.has_pending_session("other-tab"),
            "a session that was not refreshed still expires ten minutes after its show"
        );

        // The refreshed banner lasts one session-token TTL from the refresh.
        let mut again = pending("later-token", "people", shown_at);
        again.banner = notice;
        rt.enqueue_pending(again);
        rt.rebind_pending_session("later-token", "later-refreshed");
        let later_refresh = Instant::now();
        let past_session =
            later_refresh + crate::server::SESSION_TOKEN_TTL + Duration::from_secs(1);
        assert!(
            rt.take_pending_for_session("later-refreshed", past_session)
                .is_none(),
            "the banner expires with the refreshed session"
        );
    }

    #[test]
    fn refresh_chain_keeps_predecessor_expiry_and_stays_bounded() {
        let mut map = std::collections::HashMap::new();
        let origin = Instant::now();
        note_successor_locked(&mut map, "t0", "t1", origin);
        let original = map.get("t0").expect("t0 recorded").1;

        let mut prev = "t1".to_string();
        for step in 2..=MAX_GUI_SESSION_SUCCESSORS + 8 {
            let at = origin + Duration::from_secs(u64::try_from(step).expect("step"));
            let next = format!("t{step}");
            note_successor_locked(&mut map, &prev, &next, at);
            prev = next;
            if let Some((_, noted)) = map.get("t0") {
                assert_eq!(*noted, original, "refresh at +{step}s extended t0's expiry");
            }
        }
        assert!(
            map.len() <= MAX_GUI_SESSION_SUCCESSORS,
            "refresh history grew to {}",
            map.len()
        );

        let late = origin + PENDING_FRESHNESS - Duration::from_secs(1);
        let tail = "t-late".to_string();
        note_successor_locked(&mut map, &prev, &tail, late);
        if let Some((_, noted)) = map.get("t0") {
            assert_eq!(*noted, original, "the late refresh extended t0");
        }
        let after = origin + PENDING_FRESHNESS + Duration::from_secs(1);
        note_successor_locked(&mut map, &tail, "t-end", after);
        assert!(
            !map.contains_key("t0"),
            "t0 outlived the expiry recorded at its own refresh"
        );
        assert!(
            map.contains_key("t-late") || map.values().any(|(next, _)| next == "t-end"),
            "a mapping noted inside the window must remain"
        );
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
    fn pending_banner_at_61s_is_returned_and_expires_after_session_ttl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let now = Instant::now();
        let hidden_tab = now.checked_sub(Duration::from_secs(61)).expect("instant");
        rt.enqueue_pending(pending("hidden-tab", "people", hidden_tab));
        assert!(
            rt.take_pending_for_session("agent-socket", now).is_none(),
            "an agent socket must not take another session's banner"
        );
        let kept = rt
            .take_pending_for_session("hidden-tab", now)
            .expect("a banner 61s old is still inside the session token TTL");
        assert_eq!(kept.view, "people");
        assert_eq!(kept.banner, "Opened by test on test");

        let expired_at = now
            .checked_sub(crate::server::SESSION_TOKEN_TTL + Duration::from_secs(1))
            .expect("instant");
        rt.enqueue_pending(pending("expired", "network", expired_at));
        assert!(
            rt.take_pending_for_session("expired", now).is_none(),
            "a banner older than the session token TTL is stale"
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
        rt.reload_from_disk().expect("valid config reloads");
        assert!(
            !rt.config().local_enabled,
            "[gui_show] local_enabled=false in the file startup loaded must apply on reload"
        );
    }

    #[test]
    fn reload_reports_a_toml_error_and_keeps_the_previous_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[gui_show]\nlocal_enabled = \n").expect("write");
        let rt = runtime(dir.path(), Some(path));
        rt.set_config(GuiShowConfig {
            local_enabled: true,
            remote_enabled: false,
        });
        let error = rt.reload_from_disk().expect_err("invalid TOML");
        assert!(error.contains("failed to parse GUI config"), "{error}");
        assert!(rt.config().local_enabled);
        assert!(!rt.config().remote_enabled);
    }

    #[test]
    fn reload_reports_a_read_error_and_keeps_the_previous_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.toml");
        let rt = runtime(dir.path(), Some(path));
        rt.set_config(GuiShowConfig {
            local_enabled: false,
            remote_enabled: true,
        });
        let error = rt.reload_from_disk().expect_err("missing file");
        assert!(error.contains("failed to read GUI config"), "{error}");
        assert!(!rt.config().local_enabled);
        assert!(rt.config().remote_enabled);
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
            src.contains("block.hidden=false"),
            "Stop stays available for a local show: {src}"
        );
        assert!(
            !src.contains("block.hidden=own"),
            "Stop is not hidden for this daemon's agent: {src}"
        );
        assert!(
            src.contains("type:'gui.block'"),
            "Stop uses the existing gui.block command: {src}"
        );
        assert!(
            html.contains(">Stop local shows</button>"),
            "slice 1 Stop control reads Stop local shows"
        );
        assert!(
            !src.contains("Future shows from this agent will be blocked"),
            "Stop must not claim success before a server reply: {src}"
        );
        assert!(
            html.contains(LOCAL_SHOW_DISABLE_FAILED),
            "a marker that was not saved uses the existing error frame"
        );
        let banner = origin_banner("Ada", "desk", false);
        assert!(
            banner.contains(LOCAL_SHOW_REENABLE),
            "the banner says how to turn local show back on: {banner}"
        );
        assert!(banner.starts_with("Opened by Ada on desk"));
        assert!(
            html.contains("function guiTabVisible"),
            "the GUI socket must advertise gui=1 only while the tab is visible"
        );
    }

    /// Rider Stop writes `gui_show_blocked.json`. The banner and the button
    /// must say that, and must not tell the human to delete the local marker.
    #[test]
    fn rider_stop_names_the_block_file_and_its_own_control() {
        let rider = origin_banner("Ada", "desk", true);
        assert!(
            rider.contains(RIDER_SHOW_REENABLE),
            "rider Stop persists gui_show_blocked.json: {rider}"
        );
        assert!(
            rider.contains("gui_show_blocked.json"),
            "rider Stop persists gui_show_blocked.json: {rider}"
        );
        assert!(
            rider.contains("restart the daemon"),
            "the block list loads when the daemon starts: {rider}"
        );
        assert!(
            !rider.contains("gui_show_local_disabled"),
            "deleting the local marker does not unblock a rider: {rider}"
        );
        assert!(rider.starts_with("Opened by Ada (rider) on desk"));

        let local = origin_banner("Ada", "desk", false);
        assert!(
            local.contains(LOCAL_SHOW_REENABLE),
            "a local show still names the marker: {local}"
        );
        assert!(
            !local.contains("gui_show_blocked.json"),
            "local Stop does not use the block file: {local}"
        );

        let html = include_str!("x0x-gui.html");
        let on_show = fn_source(html, "function onGuiShow(m){", "function hideGuiShowBanner");
        assert!(
            on_show.contains("!!m.rider"),
            "the show frame must pass the rider flag into the control: {on_show}"
        );
        let src = fn_source(html, "function showGuiShowBanner", "function navigate");
        assert!(
            src.contains("Stop shows from this rider"),
            "a local rider Stop names that rider: {src}"
        );
        assert!(
            src.contains("Stop shows from this machine"),
            "a remote rider Stop blocks shows from that machine: {src}"
        );
        assert!(
            src.contains("from that machine"),
            "the remote banner sentence selects the machine Stop control: {src}"
        );
        assert!(
            src.contains("gui_show_blocked.json") && src.contains("&&!rider"),
            "an ordinary remote show uses the machine Stop label: {src}"
        );
        assert!(
            !src.contains("!rider?'Stop local shows'"),
            "an ordinary remote show must not say Stop local shows: {src}"
        );
    }

    /// The presentation map stays bounded. Stop still blocks a signer whose
    /// row was evicted, and a kept subject is still recorded.
    #[test]
    fn rider_presented_evicts_the_lowest_id_past_the_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rt = runtime(dir.path(), None);
        let subject = AgentId([0x7F; 32]);
        for n in 0..super::RIDER_PRESENTED_SIGNERS {
            let mut id = [0u8; 32];
            id[31] = u8::try_from(n).expect("signer index fits");
            rt.note_rider_presentation(&AgentId(id), &subject);
        }
        let newest = AgentId([0xFF; 32]);
        rt.note_rider_presentation(&newest, &subject);
        let oldest = AgentId([0u8; 32]);
        rt.record_rider_stop(&oldest);
        assert!(
            !rt.rider_pair_blocked(&oldest, &subject),
            "the lowest signer id is evicted when the map is full"
        );
        rt.record_rider_stop(&newest);
        assert!(rt.rider_pair_blocked(&newest, &subject));

        let signer = AgentId([0x11; 32]);
        for n in 0..super::RIDER_PRESENTED_SUBJECTS {
            let mut id = [0u8; 32];
            id[31] = u8::try_from(n).expect("subject index fits");
            rt.note_rider_presentation(&signer, &AgentId(id));
        }
        let newest_subject = AgentId([0xEE; 32]);
        rt.note_rider_presentation(&signer, &newest_subject);
        rt.record_rider_stop(&signer);
        assert!(!rt.rider_pair_blocked(&signer, &AgentId([0u8; 32])));
        assert!(rt.rider_pair_blocked(&signer, &newest_subject));
    }

    #[test]
    fn hidden_tab_does_not_advertise_a_live_gui() {
        let html = include_str!("x0x-gui.html");
        let ws_url = fn_source(html, "function wsUrl()", "let ws=");
        assert!(
            ws_url.contains("liveGuiTab()"),
            "wsUrl must read live GUI state before it sends gui=1: {ws_url}"
        );
        assert!(
            !ws_url.contains("return base+'?gui=1';"),
            "a hidden tab must not be hard-coded as a live GUI: {ws_url}"
        );
        assert!(
            !ws_url.contains("return base+'?token='+SESSION_TOKEN+'&gui=1';"),
            "a tokenised socket must not always send gui=1: {ws_url}"
        );
        let live = fn_source(html, "function liveGuiTab()", "function wsUrl()");
        assert!(
            live.contains("guiTabVisible()"),
            "a hidden tab must not count as a live GUI: {live}"
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
            advertise.contains("liveGuiTab()"),
            "the update must carry live GUI state: {advertise}"
        );
        let listener = html
            .find("addEventListener('visibilitychange'")
            .expect("visibility listener");
        let listener_src = &html[listener..listener + 420];
        let refresh_at = listener_src
            .find("await refreshSession()")
            .expect("an overdue reveal waits for refresh");
        let advertise_at = listener_src
            .find("advertiseGuiVisibility")
            .expect("hiding the tab must stop advertising a live GUI");
        assert!(
            refresh_at < advertise_at,
            "visibility is advertised only after an overdue refresh: {listener_src}"
        );
        let onopen = fn_source(html, "ws.onopen=async()", "ws.onclose");
        assert!(
            onopen.contains("advertiseGuiVisibility()"),
            "a reconnect must report the visibility at open time: {onopen}"
        );
    }

    #[test]
    fn expired_gui_session_stops_advertising_a_live_tab() {
        let html = include_str!("x0x-gui.html");
        let live = fn_source(html, "function liveGuiTab()", "function wsUrl()");
        assert!(
            live.contains("!sessionExpired"),
            "an expired session is not a live GUI: {live}"
        );
        assert!(
            live.contains("guiTabVisible()"),
            "a hidden tab is not a live GUI: {live}"
        );
        assert!(
            live.contains("SESSION_REFRESH_MS"),
            "an overdue session is not a live GUI: {live}"
        );
        let refresh = fn_source(
            html,
            "async function refreshSession()",
            "function maybeRefreshSession()",
        );
        let (success, failure) = refresh
            .split_once("sessionExpired=true")
            .expect("refresh marks the session expired");
        let before_request = success
            .split_once("await apiWith")
            .expect("refresh calls the session endpoint")
            .0;
        assert!(
            before_request.contains("advertiseGuiVisibility()"),
            "an overdue refresh clears visibility before the request: {before_request}"
        );
        let after_issue = success
            .split_once("sessionIssuedAt=Date.now()")
            .expect("refresh records the new issue time")
            .1;
        assert!(
            after_issue.contains("advertiseGuiVisibility()"),
            "a successful refresh re-advertises visibility: {after_issue}"
        );
        assert!(
            failure.contains("advertiseGuiVisibility()"),
            "a rejected refresh tells the daemon this tab is not a live GUI: {failure}"
        );
        let source = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            r#"
const document = {
  visibilityState: 'visible',
  createElement() { return {}; },
  getElementById() { return { appendChild() {} }; }
};
const sessionStorage = { getItem() { return ''; }, setItem() {}, removeItem() {} };
const sent = [];
function wsSend(obj) { sent.push(obj); }
let refreshBody = null;
async function apiWith() { return refreshBody; }
const BASE = 'http://127.0.0.1:9';
let SESSION_TOKEN = 'tok';
const SESSION_REFRESH_MS = 8*60*1000;
let sessionExpired = false;
let sessionRefreshing = false;
let sessionIssuedAt = 0;
let sessionClockKnown = true;
"#,
            fn_source(html, "function guiTabVisible()", "function liveGuiTab()"),
            live,
            fn_source(
                html,
                "function wsUrl()",
                "function advertiseGuiVisibility()"
            ),
            fn_source(html, "function advertiseGuiVisibility()", "let ws="),
            refresh,
            fn_source(
                html,
                "function maybeRefreshSession()",
                "function readOwnerToken()"
            ),
            r#"
(async () => {
  advertiseGuiVisibility();
  if (!sent[0] || sent[0].visible !== true) {
    throw new Error('a visible session must advertise: ' + JSON.stringify(sent));
  }
  if (!wsUrl().includes('gui=1')) throw new Error('wsUrl dropped gui=1: ' + wsUrl());
  refreshBody = null;
  await refreshSession();
  if (sessionExpired) throw new Error('an unreachable daemon must not expire the session');
  if (sent[sent.length - 1].visible !== true) {
    throw new Error('unreachable refresh cleared visibility: ' + JSON.stringify(sent));
  }
  sessionIssuedAt = Date.now() - 9 * 60 * 1000;
  advertiseGuiVisibility();
  if (sent[sent.length - 1].visible !== false) {
    throw new Error('an 8-10 minute token must reconnect as hidden: ' + JSON.stringify(sent));
  }
  if (wsUrl().includes('gui=1')) {
    throw new Error('an overdue token must omit gui=1: ' + wsUrl());
  }
  refreshBody = { _http_ok: true, session_token: 'refreshed-token' };
  const beforeRefresh = sent.length;
  await refreshSession();
  if (sessionExpired) throw new Error('a successful refresh must not expire the session');
  if (SESSION_TOKEN !== 'refreshed-token') {
    throw new Error('refresh did not install the new token: ' + SESSION_TOKEN);
  }
  const readvertised = sent[sent.length - 1];
  if (sent.length === beforeRefresh || !readvertised || readvertised.type !== 'gui.visible' || readvertised.visible !== true) {
    throw new Error('a successful refresh must re-advertise visible:true: ' + JSON.stringify(sent));
  }
  if (!wsUrl().includes('gui=1')) {
    throw new Error('a refreshed visible tab must count as a live GUI: ' + wsUrl());
  }
  sent.length = 0;
  sessionIssuedAt = Date.now() - 9 * 60 * 1000;
  refreshBody = null;
  await maybeRefreshSession();
  if (sent.length !== 1 || !sent[0] || sent[0].type !== 'gui.visible' || sent[0].visible !== false) {
    throw new Error('a periodic retry must hide an overdue tab before refresh: ' + JSON.stringify(sent));
  }
  refreshBody = { _http_ok: true, session_token: 'retried-token' };
  await maybeRefreshSession();
  if (sent[0].visible !== false || sent.length < 2 || sent[sent.length - 1].visible !== true) {
    throw new Error('the next periodic retry must restore visible:true after success: ' + JSON.stringify(sent));
  }
  if (SESSION_TOKEN !== 'retried-token') {
    throw new Error('periodic retry did not install the new token: ' + SESSION_TOKEN);
  }
  sessionIssuedAt = Date.now() - 11 * 60 * 1000;
  advertiseGuiVisibility();
  if (sent[sent.length - 1].visible !== false) {
    throw new Error('an overdue session advertised a live tab: ' + JSON.stringify(sent));
  }
  sessionIssuedAt = Date.now();
  advertiseGuiVisibility();
  if (sent[sent.length - 1].visible !== true) {
    throw new Error('a fresh session must advertise again: ' + JSON.stringify(sent));
  }
  refreshBody = { _http_ok: false, _http_status: 401 };
  await refreshSession();
  if (!sessionExpired) throw new Error('a rejected refresh must expire the session');
  const cleared = sent[sent.length - 1];
  if (!cleared || cleared.type !== 'gui.visible' || cleared.visible !== false) {
    throw new Error('expiry must clear GUI availability: ' + JSON.stringify(sent));
  }
  if (wsUrl().includes('gui=1')) {
    throw new Error('an expired session must not reconnect as a live GUI: ' + wsUrl());
  }
  document.visibilityState = 'visible';
  advertiseGuiVisibility();
  if (sent[sent.length - 1].visible !== false) {
    throw new Error('a later visibility event re-advertised the expired tab: ' + JSON.stringify(sent));
  }
})().catch((error) => { console.error(error); process.exit(1); });
"#
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("expired-session.js");
        std::fs::write(&script, source).expect("write script");
        let output = std::process::Command::new("node")
            .arg(&script)
            .output()
            .expect("node runs the GUI session functions");
        assert!(
            output.status.success(),
            "expired session still advertises a live GUI\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn delayed_bootstrap_does_not_advertise_an_expired_token() {
        let html = include_str!("x0x-gui.html");
        let source = format!(
            "{}\n{}\n{}",
            r#"
let now = 9 * 60 * 1000;
Date.now = () => now;
const store = {};
const sessionStorage = {
  getItem(k) { return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
  setItem(k, v) { store[k] = String(v); },
  removeItem(k) { delete store[k]; }
};
const location = {
  origin: 'http://127.0.0.1:9',
  pathname: '/gui',
  search: '?token=minted-token',
  hash: '#/people'
};
const history = { replaceState() { location.search = ''; } };
const BASE = location.origin;
const document = {
  visibilityState: 'visible',
  createElement() { return {}; },
  getElementById() { return { appendChild() {} }; }
};
let daemonToken = 'minted-token';
let daemonExpiry = 10 * 60 * 1000;
const sent = [];
function wsSend(obj) { sent.push(obj); }
async function apiWith(token, path) {
  if (path !== '/auth/session/refresh') return null;
  if (token !== daemonToken || now >= daemonExpiry) {
    return { _http_ok: false, _http_status: 401 };
  }
  daemonToken = 'refreshed-' + now;
  daemonExpiry = now + 10 * 60 * 1000;
  return { _http_ok: true, session_token: daemonToken, expires_in: 600 };
}
"#,
            fn_source(
                html,
                "function readSessionToken()",
                "function readOwnerToken()"
            ),
            r#"
(async () => {
  if (sessionClockKnown) {
    throw new Error('page load adopted a clock the daemon did not issue');
  }
  await bootstrapGuiSession();
  if (!sessionClockKnown) {
    throw new Error('bootstrap did not confirm the daemon issue time');
  }
  if (SESSION_TOKEN === 'minted-token') {
    throw new Error('bootstrap did not refresh the minted token');
  }
  now = 11 * 60 * 1000;
  if (now >= daemonExpiry) {
    throw new Error('refresh did not extend the daemon TTL');
  }
  if (!liveGuiTab()) {
    throw new Error('a token the daemon still accepts must stay a live tab');
  }
  if (wsUrl().indexOf('gui=1') < 0) {
    throw new Error('a live tab omitted gui=1: ' + wsUrl());
  }
  // Mint at 0, load at 11. The token is already dead. This tab must not
  // suppress a browser open.
  now = 11 * 60 * 1000;
  daemonToken = 'late-token';
  daemonExpiry = 10 * 60 * 1000;
  location.search = '?token=late-token';
  sessionExpired = false;
  sessionRefreshing = false;
  SESSION_TOKEN = readSessionToken();
  noteSessionClock();
  await bootstrapGuiSession();
  if (liveGuiTab()) {
    throw new Error('a token that expired before load still suppresses a browser open');
  }
  if (wsUrl().indexOf('gui=1') >= 0) {
    throw new Error('a late load advertised gui=1: ' + wsUrl());
  }
})().catch((error) => { console.error(error); process.exit(1); });
"#
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("delayed-bootstrap.js");
        std::fs::write(&script, source).expect("write script");
        let output = std::process::Command::new("node")
            .arg(&script)
            .output()
            .expect("node runs the delayed bootstrap");
        assert!(
            output.status.success(),
            "a delayed GUI load advertised an expired token\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
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
