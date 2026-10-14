//! Staged rollout (ADR 0094 §1, rulings D183/D184, #1106).
//!
//! A node does not apply a verified release at first receipt. It waits a
//! delay that is a pure function of its MachineId, the release version and
//! the effective rollout window:
//!
//! `delay = SHA-256(machine_id ‖ version)[0..8] as u64 × window_secs / 2^64`
//!
//! The delay is in `[0, window)`. Different nodes get different delays for one
//! release, and the version salt changes the order for each release. The wait
//! that a node has served is persisted per release in
//! `<data_dir>/upgrade-rollout.json`, so a duplicate receipt or a restart does
//! not reset or re-roll it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;

/// Compiled default rollout window in minutes (D183: 60 minutes). The fleet
/// default and minimum is also 60 (D184); the inventory check, not the daemon,
/// enforces the fleet minimum, and private rehearsal hosts may set 0.
pub const DEFAULT_ROLLOUT_WINDOW_MINUTES: u64 = 60;

/// File name of the per-instance rollout state in the daemon data directory.
pub const ROLLOUT_STATE_FILE_NAME: &str = "upgrade-rollout.json";

/// `format` marker of the rollout state file.
pub const ROLLOUT_STATE_FORMAT: &str = "x0x.upgrade-rollout";

/// Current `version` of the rollout state file.
pub const ROLLOUT_STATE_VERSION: u32 = 1;

/// Staged rollout delay calculator.
///
/// Uses a deterministic hash of the node ID to spread upgrades across a time
/// window, preventing all nodes from upgrading simultaneously.
pub struct StagedRollout {
    /// The node's unique identifier (typically MachineId, 32 bytes).
    node_id: Vec<u8>,
    /// Maximum delay in minutes.
    max_delay_minutes: u64,
}

impl StagedRollout {
    /// Create a new staged rollout calculator.
    ///
    /// # Arguments
    /// * `node_id` - Unique node identifier (MachineId bytes)
    /// * `max_delay_minutes` - Maximum rollout window in minutes (0 = no delay)
    pub fn new(node_id: &[u8], max_delay_minutes: u64) -> Self {
        Self {
            node_id: node_id.to_vec(),
            max_delay_minutes,
        }
    }

    /// Calculate the rollout delay for this node.
    ///
    /// Returns Duration::ZERO if max_delay_minutes is 0.
    pub fn calculate_delay(&self) -> Duration {
        if self.max_delay_minutes == 0 {
            return Duration::ZERO;
        }

        let hash = Sha256::digest(&self.node_id);
        let delay = delay_from_hash(&hash, self.window_secs());
        log_delay(delay);
        delay
    }

    /// Calculate a version-specific delay.
    ///
    /// Includes the version string in the hash so that different releases
    /// produce different delay orderings across the fleet.
    pub fn calculate_delay_for_version(&self, version: &str) -> Duration {
        if self.max_delay_minutes == 0 {
            return Duration::ZERO;
        }

        let mut hasher = Sha256::new();
        hasher.update(&self.node_id);
        hasher.update(version.as_bytes());
        let hash = hasher.finalize();

        let delay = delay_from_hash(&hash, self.window_secs());
        log_delay(delay);
        delay
    }

    fn window_secs(&self) -> u64 {
        self.max_delay_minutes.saturating_mul(60)
    }
}

fn log_delay(delay: Duration) {
    let delay_secs = delay.as_secs();
    let hours = delay_secs / 3600;
    let minutes = (delay_secs % 3600) / 60;
    let seconds = delay_secs % 60;
    debug!(
        delay_hours = hours,
        delay_minutes = minutes,
        delay_seconds = seconds,
        "Calculated staged rollout delay: {}h {}m {}s",
        hours,
        minutes,
        seconds
    );
}

/// Map a SHA-256 hash to a delay in `[0, window_secs)`.
///
/// The first 8 hash bytes are a fraction `value / 2^64` in `[0, 1)` (ADR 0094
/// §1). Integer arithmetic keeps the result exact and the same on every
/// platform.
pub(crate) fn delay_from_hash(hash: &[u8], window_secs: u64) -> Duration {
    let mut prefix = [0u8; 8];
    for (slot, byte) in prefix.iter_mut().zip(hash.iter()) {
        *slot = *byte;
    }
    let value = u128::from(u64::from_be_bytes(prefix));
    let delay_secs = (value * u128::from(window_secs)) >> 64;
    Duration::from_secs(u64::try_from(delay_secs).unwrap_or(u64::MAX))
}

/// Which apply path offered a release to the staged rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutTrigger {
    /// The post-bind startup GitHub check.
    Startup,
    /// A signed manifest received on the `x0x/release` gossip topic.
    Gossip,
    /// The periodic GitHub fallback poll.
    Poll,
    /// Authenticated `POST /upgrade/apply`.
    Manual,
}

impl RolloutTrigger {
    /// Stable lower-case name for logs and the state file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Gossip => "gossip",
            Self::Poll => "poll",
            Self::Manual => "manual",
        }
    }
}

impl std::fmt::Display for RolloutTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The persisted wait of one staged release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedRelease {
    /// Release version (semver).
    pub version: String,
    /// Apply path of the first eligible receipt.
    pub first_trigger: RolloutTrigger,
    /// Wall-clock second of the first eligible receipt. Diagnostic only: the
    /// due decision never reads the wall clock.
    pub first_receipt_unix: u64,
    /// Effective rollout window that chose `delay_secs`.
    pub window_minutes: u64,
    /// The chosen delay: a pure function of node, version and window.
    pub delay_secs: u64,
    /// Monotonic wait served so far, checkpointed while the daemon runs.
    /// Time while the daemon is stopped does not count.
    pub waited_secs: u64,
}

impl StagedRelease {
    /// The chosen delay.
    pub fn delay(&self) -> Duration {
        Duration::from_secs(self.delay_secs)
    }

    /// The wait that is still to serve.
    pub fn remaining(&self) -> Duration {
        Duration::from_secs(self.delay_secs.saturating_sub(self.waited_secs))
    }

    /// Whether the node has served its whole delay for this release.
    pub fn is_due(&self) -> bool {
        self.waited_secs >= self.delay_secs
    }
}

/// The last completed upgrade that the new process has reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnouncedUpgrade {
    /// Version that applied the upgrade.
    pub from_version: String,
    /// Version that the upgrade installed.
    pub to_version: String,
    /// `started_at` of the handoff record (identifies the transaction).
    pub started_at: u64,
}

/// Why a stored rollout state could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutStateProblem {
    /// Human-readable reason.
    pub reason: String,
}

/// Per-instance rollout state (`<data_dir>/upgrade-rollout.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutState {
    /// Always [`ROLLOUT_STATE_FORMAT`].
    pub format: String,
    /// Always [`ROLLOUT_STATE_VERSION`] for this binary.
    pub version: u32,
    /// Staged releases newer than the running version.
    #[serde(default)]
    pub releases: Vec<StagedRelease>,
    /// The last upgrade reported at start ("upgraded from X to Y").
    #[serde(default)]
    pub announced_upgrade: Option<AnnouncedUpgrade>,
    /// Why the stored state cannot be trusted (unreadable, unparseable, or
    /// another format or version). While set, nothing may apply and the file
    /// is never overwritten (ADR 0094 §6 fail closed). Not stored.
    #[serde(skip)]
    pub blocked: Option<String>,
}

impl Default for RolloutState {
    fn default() -> Self {
        Self {
            format: ROLLOUT_STATE_FORMAT.to_string(),
            version: ROLLOUT_STATE_VERSION,
            releases: Vec::new(),
            announced_upgrade: None,
            blocked: None,
        }
    }
}

impl RolloutState {
    /// Path of the state file in `data_dir`.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(ROLLOUT_STATE_FILE_NAME)
    }

    /// Load the state. A missing file is an empty state.
    ///
    /// ADR 0094 §6 fail closed (review F4): a file that cannot be read or
    /// parsed, or that has another format or a newer version, is not trusted
    /// and is not moved. The returned state is blocked: nothing may apply,
    /// and [`RolloutState::save`] refuses to overwrite the record. A
    /// supported binary or an explicit repair (an operator moves the file
    /// away) resolves it.
    pub fn load(path: &Path) -> (Self, Option<RolloutStateProblem>) {
        let reason = match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(state)
                    if state.format == ROLLOUT_STATE_FORMAT
                        && state.version == ROLLOUT_STATE_VERSION =>
                {
                    return (state, None);
                }
                Ok(state) => format!(
                    "unsupported format {:?} version {} (this binary reads {:?} version {})",
                    state.format, state.version, ROLLOUT_STATE_FORMAT, ROLLOUT_STATE_VERSION
                ),
                Err(e) => format!("unparseable: {e}"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Self::default(), None),
            Err(e) => format!("cannot read {}: {e}", path.display()),
        };
        let state = Self {
            blocked: Some(reason.clone()),
            ..Self::default()
        };
        (state, Some(RolloutStateProblem { reason }))
    }

    /// Persist the state with a record barrier: write a temp file, fsync
    /// it, rename it over the state file, then fsync the directory.
    ///
    /// A blocked state never writes: the unreadable record stays as it is.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(reason) = &self.blocked {
            return Err(std::io::Error::other(format!(
                "staged-rollout state is blocked ({reason}); the record is not overwritten"
            )));
        }
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let mut tmp_name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        tmp_name.push(format!(".tmp-{}", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        if let Err(e) = write_synced_then_rename(&tmp, &json, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// The staged entry for `version`, if any.
    pub fn entry(&self, version: &str) -> Option<&StagedRelease> {
        self.releases.iter().find(|r| r.version == version)
    }

    /// Stage `version` for this node (idempotent). Returns the entry and
    /// whether this receipt created it.
    ///
    /// The delay is recomputed on every receipt, but it is a pure function
    /// of node, version and window, so a duplicate receipt or a restart gets
    /// the same delay (no re-roll). A changed window gives the delay for the
    /// new window; the served wait is kept. Releases at or below
    /// `current_version` are dropped, and at most
    /// [`MAX_STAGED_RELEASES`] newer ones are kept.
    pub fn stage(
        &mut self,
        version: &str,
        node_id: &[u8],
        window_minutes: u64,
        trigger: RolloutTrigger,
        now_unix: u64,
        current_version: &str,
    ) -> (StagedRelease, bool) {
        self.releases
            .retain(|r| super::manifest::is_newer(&r.version, current_version));
        let delay_secs = StagedRollout::new(node_id, window_minutes)
            .calculate_delay_for_version(version)
            .as_secs();
        if let Some(entry) = self.releases.iter_mut().find(|r| r.version == version) {
            entry.window_minutes = window_minutes;
            entry.delay_secs = delay_secs;
            return (entry.clone(), false);
        }
        let staged = StagedRelease {
            version: version.to_string(),
            first_trigger: trigger,
            first_receipt_unix: now_unix,
            window_minutes,
            delay_secs,
            waited_secs: 0,
        };
        self.releases.push(staged.clone());
        if self.releases.len() > MAX_STAGED_RELEASES {
            // Keep the newest releases; drop the oldest by semver.
            self.releases.sort_by(|a, b| {
                match (
                    semver::Version::parse(&a.version),
                    semver::Version::parse(&b.version),
                ) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    _ => std::cmp::Ordering::Equal,
                }
            });
            let excess = self.releases.len() - MAX_STAGED_RELEASES;
            self.releases.drain(..excess);
        }
        (staged, true)
    }

    /// Record the total monotonic wait served for `version`. The value only
    /// grows and is capped at the delay.
    pub fn set_waited(&mut self, version: &str, waited_secs: u64) -> Option<StagedRelease> {
        let entry = self.releases.iter_mut().find(|r| r.version == version)?;
        entry.waited_secs = entry.waited_secs.max(waited_secs).min(entry.delay_secs);
        Some(entry.clone())
    }

    /// Return the "upgraded from" notice once per handoff transaction.
    ///
    /// The handoff record (`upgrade-handoff.json`) names the version that
    /// applied the upgrade and the version it installed. When this binary is
    /// the installed version and the transaction was not reported yet, the
    /// notice is returned and recorded; a later restart returns `None`.
    pub fn take_upgrade_notice(
        &mut self,
        from_version: &str,
        to_version: &str,
        started_at: u64,
        current_version: &str,
    ) -> Option<AnnouncedUpgrade> {
        if to_version != current_version || from_version == to_version {
            return None;
        }
        let notice = AnnouncedUpgrade {
            from_version: from_version.to_string(),
            to_version: to_version.to_string(),
            started_at,
        };
        if self.announced_upgrade.as_ref() == Some(&notice) {
            return None;
        }
        self.announced_upgrade = Some(notice.clone());
        Some(notice)
    }
}

/// At most this many staged releases are kept in the state file.
pub const MAX_STAGED_RELEASES: usize = 4;

fn write_synced_then_rename(tmp: &Path, bytes: &[u8], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_delay_when_disabled() {
        let rollout = StagedRollout::new(b"test-node", 0);
        assert_eq!(rollout.calculate_delay(), Duration::ZERO);
    }

    #[test]
    fn test_zero_delay_for_version_when_disabled() {
        let rollout = StagedRollout::new(b"test-node", 0);
        assert_eq!(rollout.calculate_delay_for_version("1.0.0"), Duration::ZERO);
    }

    #[test]
    fn test_delay_within_expected_range() {
        let rollout = StagedRollout::new(b"test-node-1", 1440);
        let delay = rollout.calculate_delay();
        assert!(delay <= Duration::from_secs(1440 * 60));
    }

    #[test]
    fn test_deterministic_delays() {
        let rollout1 = StagedRollout::new(b"same-node", 1440);
        let rollout2 = StagedRollout::new(b"same-node", 1440);
        assert_eq!(rollout1.calculate_delay(), rollout2.calculate_delay());
    }

    #[test]
    fn test_different_nodes_get_different_delays() {
        let rollout1 = StagedRollout::new(b"node-alpha", 1440);
        let rollout2 = StagedRollout::new(b"node-beta", 1440);
        // Extremely unlikely (but theoretically possible) to be equal
        assert_ne!(rollout1.calculate_delay(), rollout2.calculate_delay());
    }

    #[test]
    fn test_delay_scales_with_max_hours() {
        let rollout_short = StagedRollout::new(b"node-x", 120);
        let rollout_long = StagedRollout::new(b"node-x", 1440);

        let short_delay = rollout_short.calculate_delay();
        let long_delay = rollout_long.calculate_delay();

        assert!(short_delay <= Duration::from_secs(120 * 60));
        assert!(long_delay <= Duration::from_secs(1440 * 60));
        // The ratio should be approximately 120:1440 = 1:12
        // Allow some tolerance due to the hash distribution
        assert!(long_delay > short_delay);
    }

    #[test]
    fn test_version_specific_delays_differ() {
        let rollout = StagedRollout::new(b"same-node", 1440);
        let delay_v1 = rollout.calculate_delay_for_version("1.0.0");
        let delay_v2 = rollout.calculate_delay_for_version("2.0.0");
        // Different versions should produce different delays for the same node
        assert_ne!(delay_v1, delay_v2);
    }

    #[test]
    fn test_empty_node_id() {
        let rollout = StagedRollout::new(b"", 1440);
        let delay = rollout.calculate_delay();
        assert!(delay <= Duration::from_secs(1440 * 60));
    }

    #[test]
    fn test_large_node_id() {
        let large_id = vec![0xABu8; 1024];
        let rollout = StagedRollout::new(&large_id, 1440);
        let delay = rollout.calculate_delay();
        assert!(delay <= Duration::from_secs(1440 * 60));
    }

    #[test]
    fn test_distribution_across_100_nodes() {
        let max_minutes = 1440u64;
        let max_secs = max_minutes * 60;
        let mut delays: Vec<u64> = Vec::new();

        for i in 0..100u32 {
            let node_id = i.to_be_bytes();
            let rollout = StagedRollout::new(&node_id, max_minutes);
            let delay = rollout.calculate_delay();
            delays.push(delay.as_secs());
        }

        // All delays should be within range
        assert!(delays.iter().all(|&d| d <= max_secs));

        // Check reasonable spread: delays should span at least 50% of the window
        let min_delay = *delays.iter().min().unwrap();
        let max_delay = *delays.iter().max().unwrap();
        let spread = max_delay - min_delay;
        assert!(
            spread > max_secs / 2,
            "Distribution too narrow: spread={spread}s out of {max_secs}s window"
        );
    }

    // ------------------------------------------------------------------
    // #1106 / ADR 0094 §1: the staged wait through the persisted state.
    // ------------------------------------------------------------------

    const WINDOW_MINUTES: u64 = 60;
    const CURRENT: &str = "0.48.0";
    const RELEASE: &str = "0.48.1";

    fn node(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn staged_delay(node_id: &[u8], version: &str) -> u64 {
        let mut state = RolloutState::default();
        let (staged, _) = state.stage(
            version,
            node_id,
            WINDOW_MINUTES,
            RolloutTrigger::Gossip,
            1_000,
            CURRENT,
        );
        staged.delay_secs
    }

    #[test]
    fn two_nodes_get_different_staged_delays_for_one_release() {
        let a = staged_delay(&node(1), RELEASE);
        let b = staged_delay(&node(2), RELEASE);
        assert_ne!(a, b, "two MachineIds must not share one delay");
        for delay in [a, b] {
            assert!(
                delay < WINDOW_MINUTES * 60,
                "delay {delay}s must be inside the {WINDOW_MINUTES}-minute window"
            );
        }
        assert!(
            a > 0 || b > 0,
            "a 60-minute window must stagger at least one of two nodes"
        );
    }

    #[test]
    fn a_new_release_reorders_the_nodes() {
        let order = |version: &str| {
            let mut nodes: Vec<(u64, u8)> = (0u8..16)
                .map(|b| (staged_delay(&node(b), version), b))
                .collect();
            nodes.sort();
            nodes.into_iter().map(|(_, b)| b).collect::<Vec<u8>>()
        };
        let first = order("0.48.1");
        let second = order("0.48.2");
        assert_ne!(
            first, second,
            "the version salt must change the apply order for each release"
        );
    }

    #[test]
    fn staged_delay_is_strictly_inside_the_window() {
        let window_secs = WINDOW_MINUTES * 60;
        let mut max_seen = 0;
        for b in 0u8..=255 {
            let delay = staged_delay(&node(b), RELEASE);
            assert!(
                delay < window_secs,
                "delay {delay}s >= window {window_secs}s"
            );
            max_seen = max_seen.max(delay);
        }
        assert!(
            max_seen > window_secs / 2,
            "256 nodes must spread over the window, max {max_seen}s"
        );
        // The highest possible hash still maps strictly below the window
        // (ADR 0094 §1: the fraction is in [0, 1)).
        assert!(delay_from_hash(&[0xFF; 32], window_secs) < Duration::from_secs(window_secs));
        assert_eq!(delay_from_hash(&[0x00; 32], window_secs), Duration::ZERO);
    }

    #[test]
    fn zero_window_stages_a_due_release() {
        let mut state = RolloutState::default();
        let (staged, _) = state.stage(RELEASE, &node(7), 0, RolloutTrigger::Poll, 1_000, CURRENT);
        assert_eq!(staged.delay_secs, 0);
        assert!(staged.is_due());
    }

    #[test]
    fn staged_wait_survives_a_restart_without_a_reroll() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = RolloutState::path_in(dir.path());
        // Pick a node whose delay is long enough to observe a partial wait.
        let id = (0u8..=255)
            .map(node)
            .find(|id| staged_delay(id, RELEASE) > 600)
            .expect("some node has a delay above 10 minutes");

        let mut state = RolloutState::default();
        let (first, is_new) = state.stage(
            RELEASE,
            &id,
            WINDOW_MINUTES,
            RolloutTrigger::Gossip,
            1_000,
            CURRENT,
        );
        assert!(is_new);
        assert!(first.delay_secs > 600);
        state.set_waited(RELEASE, 300);
        state.save(&path).unwrap();

        // Restart: a new process loads the file and sees a duplicate receipt.
        let (mut reloaded, problem) = RolloutState::load(&path);
        assert_eq!(problem, None);
        let (again, is_new) = reloaded.stage(
            RELEASE,
            &id,
            WINDOW_MINUTES,
            RolloutTrigger::Poll,
            9_999,
            CURRENT,
        );
        assert!(!is_new, "a duplicate receipt must not create a new wait");
        assert_eq!(
            again.delay_secs, first.delay_secs,
            "no re-roll after restart"
        );
        assert_eq!(again.waited_secs, 300, "the served wait is kept");
        assert_eq!(
            again.remaining(),
            Duration::from_secs(first.delay_secs - 300)
        );
        assert_eq!(again.first_trigger, RolloutTrigger::Gossip);
        assert_eq!(again.first_receipt_unix, 1_000);
    }

    #[test]
    fn a_window_change_recomputes_the_delay_and_keeps_the_wait() {
        let mut state = RolloutState::default();
        let id = node(3);
        state.stage(RELEASE, &id, 60, RolloutTrigger::Gossip, 1_000, CURRENT);
        state.set_waited(RELEASE, 50);
        let (restaged, _) = state.stage(RELEASE, &id, 120, RolloutTrigger::Gossip, 2_000, CURRENT);
        assert_eq!(
            restaged.delay_secs,
            StagedRollout::new(&id, 120)
                .calculate_delay_for_version(RELEASE)
                .as_secs()
        );
        assert_eq!(restaged.window_minutes, 120);
        assert_eq!(restaged.waited_secs, 50);
    }

    #[test]
    fn releases_at_or_below_the_running_version_are_pruned() {
        let mut state = RolloutState::default();
        state.stage("0.48.1", &node(1), 60, RolloutTrigger::Gossip, 1, "0.48.0");
        state.stage("0.48.2", &node(1), 60, RolloutTrigger::Gossip, 2, "0.48.0");
        // The daemon now runs 0.48.1.
        state.stage("0.48.2", &node(1), 60, RolloutTrigger::Gossip, 3, "0.48.1");
        let versions: Vec<&str> = state.releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(versions, vec!["0.48.2"]);
    }

    #[test]
    fn an_unreadable_state_file_blocks_apply_and_is_preserved() {
        // Codex F4 / ADR 0094 §6: fail closed means no apply, the record
        // kept in place, and a degraded report; not a fresh timer.
        let dir = tempfile::TempDir::new().unwrap();
        let path = RolloutState::path_in(dir.path());
        let cases: [&[u8]; 2] = [
            b"{ not json",
            br#"{"format":"x0x.upgrade-rollout","version":2,"releases":[],"wait":"new"}"#,
        ];
        for bytes in cases {
            std::fs::write(&path, bytes).unwrap();
            let (state, problem) = RolloutState::load(&path);
            assert!(problem.is_some(), "the unreadable file is reported");
            assert!(
                state.blocked.is_some(),
                "an unreadable record blocks every apply"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                bytes,
                "the active record stays in place, byte for byte"
            );
            assert!(
                state.save(&path).is_err(),
                "a blocked state never overwrites the record"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn the_upgraded_from_notice_fires_once_per_handoff() {
        let mut state = RolloutState::default();
        // A stale handoff from an older upgrade says nothing.
        assert_eq!(
            state.take_upgrade_notice("0.44.0", "0.45.0", 10, "0.48.1"),
            None
        );
        let notice = state
            .take_upgrade_notice("0.48.0", "0.48.1", 20, "0.48.1")
            .expect("first start after the upgrade reports it");
        assert_eq!(notice.from_version, "0.48.0");
        assert_eq!(notice.to_version, "0.48.1");
        // A later restart of the same binary does not repeat it.
        assert_eq!(
            state.take_upgrade_notice("0.48.0", "0.48.1", 20, "0.48.1"),
            None
        );
        // A new transaction to the same version (a re-apply) reports again.
        assert!(state
            .take_upgrade_notice("0.48.0", "0.48.1", 30, "0.48.1")
            .is_some());
    }
}
