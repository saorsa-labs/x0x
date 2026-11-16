//! The candidate side of the S3d host commit gate (ADR 0094 §3, §4; #1377
//! part 2). A daemon started by the M2 launcher as a trial candidate writes
//! its per-instance health commit (`journal::HealthRecord`) beside its data
//! root once its local health has held for the stable interval. The
//! launcher coordinator verifies the full set before host commit
//! (`upgrade/launcher/commit.rs`).
//!
//! Dormant: only a launcher candidate has a boot record naming this
//! process, and the launcher starts none while activation is held. The
//! detection is one boot-record read at startup; every other daemon pays
//! nothing per tick.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::upgrade::journal::{self, LocalVerdict};

/// The stable interval a candidate's health must hold before it commits.
/// It equals the launcher's `STABLE_MS` (D192 direction; provisional).
pub(super) const STABLE: Duration = Duration::from_secs(60);
/// D193: how long a previously connected candidate with healthy local
/// inputs may go without a stable send-ready peer before it records the
/// miss. It equals the launcher's per-attempt readiness bound `READY_MS`.
pub(super) const PEER_WAIT: Duration = Duration::from_secs(120);

/// What binds this process to its launcher trial, read once at startup.
#[derive(Debug, Clone)]
pub(super) struct Candidate {
    boot: journal::BootRecord,
    data_root: PathBuf,
    identity_root: PathBuf,
    executable_sha256: [u8; 32],
    previously_connected: bool,
}

/// This process is a launcher trial candidate when the data root's boot
/// record names it (PID, start time and boot) and the host has not
/// committed yet. Anything else is `None`: an ordinary daemon, a daemon
/// after host commit, or a record that cannot be read.
pub(super) fn detect(data_root: &Path, identity_root: Option<PathBuf>) -> Option<Candidate> {
    let executable = std::env::current_exe().ok()?.canonicalize().ok()?;
    detect_with(data_root, identity_root, &executable)
}

/// `detect` with the executable to hash given explicitly.
fn detect_with(
    data_root: &Path,
    identity_root: Option<PathBuf>,
    executable: &Path,
) -> Option<Candidate> {
    if journal::host_commit_gate_open(data_root) {
        return None;
    }
    let records = journal::read_boot_records(data_root);
    let journal::RecordRead::Boot(boot) = records.boot else {
        return None;
    };
    let own = own_identity()?;
    if boot.pid != own.0 || boot.process_start != own.1 || boot.boot_id != own.2 {
        return None;
    }
    // D193: the OLD instance recorded its send-ready peer count when it
    // armed this transaction's handoff.
    let previously_connected = match &records.handoff {
        journal::RecordRead::Handoff(handoff)
            if handoff.transaction_id == boot.transaction_id
                && handoff.generation == boot.generation =>
        {
            handoff
                .legacy
                .get(journal::HANDOFF_SEND_READY_PEERS)
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|peers| peers > 0)
        }
        _ => false,
    };
    let executable_sha256 = executable_digest(executable)?;
    Some(Candidate {
        boot,
        data_root: data_root.to_path_buf(),
        // As the flush owner compares it with the plan: canonical.
        identity_root: identity_root?.canonicalize().ok()?,
        executable_sha256,
        previously_connected,
    })
}

/// The executable's hash, as the pair engine hashes an installed file.
#[cfg(unix)]
fn executable_digest(executable: &Path) -> Option<[u8; 32]> {
    crate::upgrade::pair::digest_file(executable, crate::upgrade::pair::MAX_BINARY_BYTES).ok()
}

/// The pair engine is Unix-only and the launcher is Linux-only: no
/// candidate.
#[cfg(not(unix))]
fn executable_digest(_executable: &Path) -> Option<[u8; 32]> {
    None
}

/// `(pid, start time, boot id)` of this process, as the launcher records
/// child identities.
#[cfg(target_os = "linux")]
fn own_identity() -> Option<(u32, u64, String)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let start = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()?;
    let boot = crate::upgrade::probe::ProbeClock::now().ok()?.boot_id;
    Some((std::process::id(), start, boot))
}

/// The launcher holds process custody on Linux only (#1379 adds launchd).
#[cfg(not(target_os = "linux"))]
fn own_identity() -> Option<(u32, u64, String)> {
    None
}

/// One refresher observation of the candidate's own health.
#[derive(Debug, Clone, Copy)]
pub(super) struct Observation {
    /// Every store initialized. A serving daemon has loaded its stores
    /// before it serves.
    pub stores_initialized: bool,
    /// The M1 verdict over local inputs only (D193: local checks block
    /// commit; network inputs never do on their own).
    pub local_verdict: LocalVerdict,
    pub send_ready_peers: usize,
}

/// The M1 verdict over the local inputs of `sample`, with the live
/// delivery-probe results merged in. The refresher's sample does not carry
/// them; without the merge the probe input is always `ok` and a candidate
/// with a wedged local dispatch could commit.
pub(super) fn candidate_local_verdict(
    snapshot: &super::routes::status::HealthSnapshot,
    sample: &super::health_verdict::VerdictSample,
) -> LocalVerdict {
    let mut sample = sample.clone();
    snapshot.merge_probe_results(&mut sample);
    super::health_verdict::local_verdict(&super::health_verdict::classify_with_detail(
        &sample,
        super::health_verdict::DetailAccess::Full,
    ))
}

/// Continuity of the candidate's health across refresher ticks.
#[derive(Debug, Default)]
pub(super) struct Tracker {
    local_ok_since: Option<Instant>,
    peer_since: Option<Instant>,
    written: bool,
}

impl Tracker {
    /// Record one observation and write the health commit when it is due.
    /// `Ok(true)` is the one successful write. A failed write leaves the
    /// commit due: the next observation tries again, and the launcher's
    /// trial deadline bounds the retries.
    pub(super) fn commit(
        &mut self,
        candidate: &Candidate,
        observation: Observation,
        now: Instant,
    ) -> std::io::Result<bool> {
        self.commit_with(candidate, observation, now, write)
    }

    /// `commit` with the record writer given explicitly.
    fn commit_with(
        &mut self,
        candidate: &Candidate,
        observation: Observation,
        now: Instant,
        writer: impl FnOnce(&Candidate, &journal::HealthRecord) -> std::io::Result<()>,
    ) -> std::io::Result<bool> {
        let Some(record) = self.observe(candidate, observation, now) else {
            return Ok(false);
        };
        writer(candidate, &record)?;
        self.written = true;
        Ok(true)
    }

    /// Record one observation. Returns the health commit that is due, until
    /// `commit` has written one:
    /// - local health held for `STABLE` and, for a previously connected
    ///   host, a send-ready peer held for `STABLE`: `peer_continuity` true;
    /// - local health held for `PEER_WAIT` on a previously connected host
    ///   with no stable peer: `peer_continuity` false, which the launcher
    ///   rolls back as Interrupted (D193).
    ///
    /// A host that never had a peer commits on local health alone.
    fn observe(
        &mut self,
        candidate: &Candidate,
        observation: Observation,
        now: Instant,
    ) -> Option<journal::HealthRecord> {
        if self.written {
            return None;
        }
        let local_ok =
            observation.stores_initialized && observation.local_verdict == LocalVerdict::Ok;
        if !local_ok {
            self.local_ok_since = None;
            self.peer_since = None;
            return None;
        }
        let local_since = *self.local_ok_since.get_or_insert(now);
        if observation.send_ready_peers > 0 {
            self.peer_since.get_or_insert(now);
        } else {
            self.peer_since = None;
        }
        let local_held = now.duration_since(local_since);
        if local_held < STABLE {
            return None;
        }
        let peer_held = self
            .peer_since
            .is_some_and(|since| now.duration_since(since) >= STABLE);
        let peer_continuity = if candidate.previously_connected {
            if !peer_held && local_held < PEER_WAIT {
                return None;
            }
            peer_held
        } else {
            peer_held
        };
        Some(record(candidate, observation, peer_continuity))
    }
}

fn record(
    candidate: &Candidate,
    observation: Observation,
    peer_continuity: bool,
) -> journal::HealthRecord {
    journal::HealthRecord {
        schema_version: journal::SCHEMA_VERSION,
        record_kind: "health".into(),
        transaction_id: candidate.boot.transaction_id.clone(),
        generation: candidate.boot.generation,
        instance_id: candidate.boot.instance_id.clone(),
        attempt: candidate.boot.attempt,
        pid: candidate.boot.pid,
        process_start: candidate.boot.process_start,
        boot_id: candidate.boot.boot_id.clone(),
        version: env!("CARGO_PKG_VERSION").into(),
        data_root: candidate.data_root.clone(),
        identity_root: candidate.identity_root.clone(),
        executable_sha256: candidate.executable_sha256,
        stores_initialized: observation.stores_initialized,
        local_verdict: observation.local_verdict,
        previously_connected: candidate.previously_connected,
        peer_continuity,
    }
}

/// Write the health commit beside the data root, with its record barrier.
fn write(candidate: &Candidate, record: &journal::HealthRecord) -> std::io::Result<()> {
    journal::write_auxiliary_record(
        &candidate.data_root.join(journal::HEALTH_FILE_NAME),
        record,
        journal::validate_health,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(previously_connected: bool) -> Candidate {
        Candidate {
            boot: journal::BootRecord {
                schema_version: 1,
                record_kind: "boot".into(),
                transaction_id: "transaction-1".into(),
                generation: 2,
                instance_id: "alice".into(),
                attempt: 1,
                pid: 41,
                process_start: 7,
                boot_id: "boot-1".into(),
                started_at_ns: 1,
                deadline_ns: 2,
            },
            data_root: PathBuf::from("/var/lib/x0x"),
            identity_root: PathBuf::from("/var/lib/x0x/identity"),
            executable_sha256: [9; 32],
            previously_connected,
        }
    }

    fn healthy(peers: usize) -> Observation {
        Observation {
            stores_initialized: true,
            local_verdict: LocalVerdict::Ok,
            send_ready_peers: peers,
        }
    }

    #[test]
    fn local_health_must_hold_for_the_stable_interval() {
        let c = candidate(false);
        let mut tracker = Tracker::default();
        let start = Instant::now();
        assert!(tracker.observe(&c, healthy(0), start).is_none());
        assert!(tracker
            .observe(&c, healthy(0), start + STABLE - Duration::from_secs(1))
            .is_none());
        let record = tracker
            .observe(&c, healthy(0), start + STABLE)
            .expect("commit after the stable interval");
        assert!(!record.previously_connected);
        assert_eq!(record.local_verdict, LocalVerdict::Ok);
        assert_eq!((record.pid, record.attempt), (41, 1));
    }

    /// A failed write leaves the commit due; the next observation writes
    /// it, once. Before the fix `observe` marked the commit written before
    /// the save, so one transient error ended in a trial rollback.
    #[test]
    fn a_failed_write_is_retried_and_a_successful_write_is_final() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut c = candidate(false);
        c.data_root = dir.path().to_path_buf();
        let mut tracker = Tracker::default();
        let start = Instant::now();
        assert!(!tracker.commit(&c, healthy(0), start).expect("not due"));
        let failing = |candidate: &Candidate, record: &journal::HealthRecord| {
            journal::write_auxiliary_record_with_failure(
                &candidate.data_root.join(journal::HEALTH_FILE_NAME),
                record,
                journal::validate_health,
                journal::BarrierStep::Rename,
            )
        };
        tracker
            .commit_with(&c, healthy(0), start + STABLE, failing)
            .expect_err("the injected failure");
        assert_eq!(journal::read_health(dir.path()).expect("read"), None);

        let retry = start + STABLE + Duration::from_secs(5);
        assert!(tracker.commit(&c, healthy(0), retry).expect("retry"));
        let written = journal::read_health(dir.path())
            .expect("read")
            .expect("the retried commit");
        assert_eq!((written.pid, written.attempt), (41, 1));
        // Written once.
        assert!(!tracker
            .commit(&c, healthy(0), start + STABLE * 2)
            .expect("already written"));
    }

    /// The candidate's local verdict reads the live delivery probe: the
    /// refresher's sample never carries probe results. Before the fix the
    /// raw sample was classified and a failed probe still read `ok`.
    #[test]
    fn a_failed_delivery_probe_degrades_the_candidate_local_verdict() {
        use crate::server::health_verdict::VerdictSample;
        use crate::server::routes::status::HealthSnapshot;

        let snapshot = HealthSnapshot::default();
        let mut sample = VerdictSample::unsampled();
        sample.seeds_configured = 2;
        sample.seeds_connected = 2;
        assert_eq!(
            candidate_local_verdict(&snapshot, &sample),
            LocalVerdict::Ok
        );
        snapshot.record_probe(true, Some(3));
        assert_eq!(
            candidate_local_verdict(&snapshot, &sample),
            LocalVerdict::Ok
        );

        snapshot.record_probe(false, None);
        assert_eq!(
            candidate_local_verdict(&snapshot, &sample),
            LocalVerdict::Degraded
        );
        // A degraded tick restarts the stable interval.
        let c = candidate(false);
        let mut tracker = Tracker::default();
        let start = Instant::now();
        tracker.observe(&c, healthy(0), start);
        let mut observation = healthy(0);
        observation.local_verdict = candidate_local_verdict(&snapshot, &sample);
        assert!(tracker.observe(&c, observation, start + STABLE).is_none());
        assert!(tracker
            .observe(&c, healthy(0), start + STABLE + Duration::from_secs(5))
            .is_none());
    }

    #[test]
    fn a_degraded_local_verdict_or_uninitialized_store_restarts_the_interval() {
        let c = candidate(false);
        let mut tracker = Tracker::default();
        let start = Instant::now();
        tracker.observe(&c, healthy(0), start);
        let mut degraded = healthy(0);
        degraded.local_verdict = LocalVerdict::Degraded;
        assert!(tracker
            .observe(&c, degraded, start + Duration::from_secs(30))
            .is_none());
        assert!(tracker.observe(&c, healthy(0), start + STABLE).is_none());
        let mut stores = healthy(0);
        stores.stores_initialized = false;
        assert!(tracker
            .observe(&c, stores, start + STABLE + Duration::from_secs(5))
            .is_none());
    }

    /// D193: a previously connected host commits only with a stable peer;
    /// without one, after `PEER_WAIT` it records the miss.
    #[test]
    fn d193_a_previously_connected_candidate_needs_peer_continuity() {
        let c = candidate(true);
        let mut tracker = Tracker::default();
        let start = Instant::now();
        tracker.observe(&c, healthy(0), start);
        assert!(tracker.observe(&c, healthy(0), start + STABLE).is_none());
        tracker.observe(&c, healthy(1), start + STABLE);
        let record = tracker
            .observe(&c, healthy(1), start + STABLE * 2)
            .expect("stable peer commits");
        assert!(record.previously_connected && record.peer_continuity);

        let mut tracker = Tracker::default();
        tracker.observe(&c, healthy(0), start);
        assert!(tracker
            .observe(&c, healthy(0), start + PEER_WAIT - Duration::from_secs(1))
            .is_none());
        let miss = tracker
            .observe(&c, healthy(0), start + PEER_WAIT)
            .expect("the miss is recorded");
        assert!(miss.previously_connected && !miss.peer_continuity);
    }

    #[test]
    fn the_record_validates_and_round_trips() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut c = candidate(false);
        c.data_root = dir.path().to_path_buf();
        let mut tracker = Tracker::default();
        let start = Instant::now();
        tracker.observe(&c, healthy(0), start);
        let record = tracker
            .observe(&c, healthy(0), start + STABLE)
            .expect("record");
        write(&c, &record).expect("write");
        assert_eq!(
            journal::read_health(dir.path()).expect("read"),
            Some(record)
        );
    }

    #[test]
    fn an_ordinary_daemon_is_not_a_candidate() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert!(detect(dir.path(), Some(dir.path().to_path_buf())).is_none());
    }

    /// An uncommitted journal for `dir` in `phase`, as the S4 gate test
    /// writes it.
    #[cfg(target_os = "linux")]
    fn write_journal(dir: &Path, phase: &str) {
        let artifact = |name: &str| {
            serde_json::json!({
                "target_path": dir.join(name),
                "staged_path": dir.join(format!("{name}.staged")),
                "backup_path": dir.join(format!("{name}.backup")),
                "previous_sha256": vec![1_u8; 32],
                "candidate_sha256": vec![2_u8; 32],
            })
        };
        let record = serde_json::json!({
            "schema_version": 1, "record_kind": "journal",
            "transaction_id": "transaction-1", "sequence": 1, "generation": 2,
            "plan": {
                "previous_version": "0.0.1", "candidate_version": "9.9.9",
                "manifest_sha256": vec![3_u8; 32],
                "daemon": artifact("x0xd"), "cli": artifact("x0x"),
                "participants": [{
                    "instance_id": "alice", "executable": dir.join("x0xd"),
                    "data_root": dir, "identity_root": dir, "argv": ["x0xd"],
                    "cwd": dir, "env": {},
                    "restart": {"mode": "TransactionalHandoff", "supervised_exit_code": null,
                        "supervision_signal": null, "launchd_verified": null,
                        "systemd_verified": null, "launcher": null},
                    "old_pid": 1234, "process_start": 100, "boot_id": "boot-a",
                    "was_running": true
                }]
            },
            "phase": phase, "cause": null,
            "daemon_progress": {"swapped": true, "restored": false, "observed_sha256": null},
            "cli_progress": {"swapped": true, "restored": false, "observed_sha256": null}
        });
        std::fs::write(
            dir.join(journal::JOURNAL_FILE_NAME),
            serde_json::to_vec(&record).expect("json"),
        )
        .expect("journal");
    }

    /// A boot record naming this process during an uncommitted trial makes
    /// it a candidate; the handoff's send-ready count sets D193. After
    /// host commit it is no longer a candidate.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_boot_record_naming_this_process_makes_it_a_candidate() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().canonicalize().expect("canonical");
        write_journal(&root, "booting");
        let (pid, start, boot) = own_identity().expect("identity");
        let record = journal::BootRecord {
            schema_version: 1,
            record_kind: "boot".into(),
            transaction_id: "transaction-1".into(),
            generation: 2,
            instance_id: "alice".into(),
            attempt: 1,
            pid,
            process_start: start,
            boot_id: boot,
            started_at_ns: 1,
            deadline_ns: 2,
        };
        journal::write_record(&root.join(journal::BOOT_FILE_NAME), &record).expect("boot");
        let handoff = serde_json::json!({
            "schema_version": 1, "record_kind": "handoff",
            "transaction_id": "transaction-1", "generation": 2, "instance_id": "alice",
            "from_version": "0.0.1", "to_version": "9.9.9",
            "target_path": "/owned/bin/x0xd", "backup_path": "/owned/bin/x0xd.backup",
            "argv": ["x0xd"], "cwd": "/owned", "env": {}, "old_pid": 24,
            "api_addr": "127.0.0.1:12700", "started_at": 1_792_500_000_u64,
            "mode": "TransactionalHandoff", "launchd_verified": null,
            "systemd_verified": null, "send_ready_peers": 3
        });
        journal::write_record(&root.join(journal::HANDOFF_FILE_NAME), &handoff).expect("handoff");

        // A small stand-in executable: a debug test binary can be past the
        // 200 MiB hash bound.
        let executable = root.join("x0xd");
        std::fs::write(&executable, b"daemon").expect("executable");
        match journal::read_boot_records(&root).handoff {
            journal::RecordRead::Handoff(_) => {}
            journal::RecordRead::Refused(reason) => panic!("handoff fixture refused: {reason}"),
            _ => panic!("handoff fixture is not an M2 handoff"),
        }
        let candidate = detect_with(&root, Some(root.clone()), &executable).expect("candidate");
        assert!(candidate.previously_connected);
        assert_eq!(candidate.boot.pid, pid);

        write_journal(&root, "host_committed");
        assert!(detect_with(&root, Some(root.clone()), &executable).is_none());
    }
}
