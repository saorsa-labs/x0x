//! The gated prepare producer in the OLD daemon's apply worker (#2012,
//! design decision A): it writes the host journal through `SwappedCli` and
//! hands off by `SupervisedExit`, but only for a host that a launcher which
//! reads the journal protects.
//!
//! The gate (`evaluate`) is open only when all of these hold, checked in
//! this order:
//! 1. `launcher_contract::LAUNCHER_ENABLED` is true (false in this build,
//!    so the gate is always closed and the producer writes nothing);
//! 2. the restart plan is `SupervisedExit`;
//! 3. the systemd readback of THIS instance found a loaded `ExecStart` that
//!    runs `x0x-launcher` in the trial form with `--plan-anchor`, and its
//!    host root is this daemon's data root;
//! 4. the unit is bound now: systemd needs no daemon reload, and the
//!    launcher drop-in (`30-x0x-launcher.conf`) is one of the unit's loaded
//!    drop-ins, a regular file whose last `ExecStart=` is exactly the loaded
//!    command. A drop-in removed or edited by hand closes the gate, even
//!    while the anchor still names the unit;
//! 5. the plan anchor passes the launcher's own checks and names exactly
//!    this install and one participant: this instance with this data root.
//!    Hosts with more than one participant (`x0xd` and `x0xd-443` from one
//!    install) are not supported yet: their journal copies are not kept in
//!    step (#2012, PR 4);
//! 6. the installed launcher answers `x0x-launcher --capabilities` with
//!    `trial-v1`. A dormant launcher (or one older than the flag) does not.
//!
//! A closed gate is the unchanged unprotected apply. The last decision is
//! kept for `GET /diagnostics/upgrade` (`last_gate`).
//!
//! When the gate is open, the worker (all install locks held, admission
//! done) runs `Transaction::run`: durable backups, the frozen plan, the
//! Staged journal and its binding (the anchor read under the data root's
//! stage lock), Prepared, the daemon swap then SwappedDaemon, the CLI swap
//! then SwappedCli. Each swap is a rename of a synced file followed by a
//! sync of the directory, before the journal records it. A failure before
//! the hand-off restores what was swapped and writes Superseded.
#![cfg(unix)]

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::install_lock::InstallLock;
use super::journal::{self, ArtifactPlan, Participant, Phase, RestartBinding, RestartOwner};
use super::launcher_contract;
use super::plan_binding;
use super::prepare::{self, HostLock, PlanInput, Prepared};
use super::restart::{RestartMode, RestartPlan};
use super::{UpgradeError, UpgradeResult, Upgrader};

/// The launcher drop-in the installer writes (`launcher-dropin.py`).
pub(crate) const DROPIN_NAME: &str = "30-x0x-launcher.conf";

/// How long `x0x-launcher --capabilities` may run.
const CAPABILITIES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why the gate is closed in a build with the launcher off.
const DORMANT_REASON: &str = "the launcher is dormant in this build (LAUNCHER_ENABLED is false)";

/// The anchor's owner: root (`plan_binding::read_anchor`).
const ANCHOR_OWNER: u32 = 0;

static IDENTITY_ROOT: OnceLock<PathBuf> = OnceLock::new();
static LAST_GATE: Mutex<Option<GateReport>> = Mutex::new(None);

/// Record this daemon's identity root once at start, for the participant
/// entry of a plan. Without it the gate stays closed.
pub fn record_identity_root(root: Option<PathBuf>) {
    if let Some(root) = root {
        let _ = IDENTITY_ROOT.set(root);
    }
}

/// The last gate decision this process made, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GateReport {
    /// Whether the producer ran for that apply.
    pub open: bool,
    /// Why the gate was closed, or what it found when open.
    pub reason: String,
    /// The plan anchor the unit names, when the readback found one.
    pub plan_anchor: Option<PathBuf>,
}

/// The last gate decision of this process; `None` before the first apply.
pub fn last_gate() -> Option<GateReport> {
    LAST_GATE.lock().ok().and_then(|last| last.clone())
}

fn remember(report: GateReport) {
    if let Ok(mut last) = LAST_GATE.lock() {
        *last = Some(report);
    }
}

/// What the gate found when it is open.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Open {
    pub(crate) anchor_path: PathBuf,
    pub(crate) instance: String,
    pub(crate) data_root: PathBuf,
    pub(crate) launcher: PathBuf,
    pub(crate) command: Vec<String>,
}

// The command carries the daemon's arguments.
impl std::fmt::Debug for Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Open(<redacted>)")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    Closed(String),
    Open(Box<Open>),
}

/// The unit's drop-in state as systemd reports it now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UnitFiles {
    pub(crate) need_daemon_reload: bool,
    pub(crate) dropins: Vec<PathBuf>,
}

/// The gate's reads of the host, injected so the tests can drive each one.
pub(crate) trait Probe {
    fn unit_files(&self, unit: &str, user_manager: bool) -> io::Result<UnitFiles>;
    fn anchor(&self, path: &Path) -> io::Result<plan_binding::Anchored>;
    fn capabilities(&self, launcher: &Path) -> io::Result<Vec<String>>;
}

/// Evaluate the gate for `plan`; `cli_target` is the CLI the apply would
/// replace (canonical). Every closed answer names its reason.
pub(crate) fn evaluate(
    enabled: bool,
    plan: &RestartPlan,
    cli_target: &Path,
    probe: &dyn Probe,
) -> Gate {
    let closed = |reason: &str| Gate::Closed(reason.to_string());
    if !enabled {
        return closed(DORMANT_REASON);
    }
    if plan.mode != RestartMode::SupervisedExit {
        return closed("the restart is not a supervised exit");
    }
    let Some(unit) = &plan.systemd_verified else {
        return closed("no systemd unit was verified for this instance");
    };
    let Some(loaded) = &unit.launcher else {
        return closed("the unit does not run x0x-launcher in the trial form");
    };
    let Some(anchor_path) = &loaded.trial.plan_anchor else {
        return closed("the unit's launcher command has no --plan-anchor");
    };
    let data_root = match plan.data_root.canonicalize() {
        Ok(root) => root,
        Err(_) => return closed("the data root cannot be resolved"),
    };
    if loaded.trial.host_root != data_root {
        return closed("the launcher's --host-root is not this daemon's data root");
    }
    let files = match probe.unit_files(&unit.unit, unit.user_manager) {
        Ok(files) => files,
        Err(_) => return closed("systemd did not report the unit's drop-ins"),
    };
    if files.need_daemon_reload {
        return closed("the unit changed on disk since systemd loaded it (daemon-reload needed)");
    }
    if !dropin_names_command(&files.dropins, &loaded.command) {
        return closed(
            "the launcher drop-in is missing, not a regular file, or does not name the loaded command",
        );
    }
    let anchored = match probe.anchor(anchor_path) {
        Ok(anchored) => anchored,
        Err(_) => return closed("the plan anchor fails the launcher's checks"),
    };
    let anchor = anchored.anchor();
    let daemon = match plan.executable.canonicalize() {
        Ok(daemon) => daemon,
        Err(_) => return closed("the daemon executable cannot be resolved"),
    };
    if anchor.daemon_target != daemon || anchor.cli_target != cli_target {
        return closed("the plan anchor names another install");
    }
    match anchor.participants.as_slice() {
        [only] if only.instance_id == loaded.trial.instance && only.data_root == data_root => {}
        [_] => return closed("the plan anchor's participant is not this instance"),
        _ => {
            return closed(
                "the plan anchor names more than one participant; multi-instance hosts are not \
                 supported yet",
            )
        }
    }
    match probe.capabilities(&loaded.executable) {
        Ok(found)
            if found
                .iter()
                .any(|c| c == launcher_contract::TRIAL_CAPABILITY) => {}
        Ok(_) => return closed("the installed launcher does not answer trial-v1"),
        Err(_) => return closed("the installed launcher's --capabilities did not answer"),
    }
    Gate::Open(Box::new(Open {
        anchor_path: anchor_path.clone(),
        instance: loaded.trial.instance.clone(),
        data_root,
        launcher: loaded.executable.clone(),
        command: loaded.command.clone(),
    }))
}

/// Exactly one loaded drop-in is the launcher's, it is a regular file (not
/// a link), and its last `ExecStart=` line is the loaded command.
fn dropin_names_command(dropins: &[PathBuf], command: &[String]) -> bool {
    let mut launcher = dropins
        .iter()
        .filter(|path| path.file_name().and_then(|n| n.to_str()) == Some(DROPIN_NAME));
    let (Some(path), None) = (launcher.next(), launcher.next()) else {
        return false;
    };
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    let mut text = String::new();
    let read =
        std::fs::File::open(path).and_then(|file| file.take(64 * 1024).read_to_string(&mut text));
    if read.is_err() {
        return false;
    }
    let last = text
        .lines()
        .rev()
        .filter_map(|line| line.trim().strip_prefix("ExecStart="))
        .map(str::trim)
        .find(|value| !value.is_empty());
    last == Some(command.join(" ").as_str())
}

/// The host's real reads.
pub(crate) struct HostProbe;

impl Probe for HostProbe {
    fn unit_files(&self, unit: &str, user_manager: bool) -> io::Result<UnitFiles> {
        let mut command = std::process::Command::new("systemctl");
        if user_manager {
            command.arg("--user");
        }
        let output = command
            .args(["show", unit, "--property", "NeedDaemonReload,DropInPaths"])
            .stdin(std::process::Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("systemctl show failed"));
        }
        parse_unit_files(&String::from_utf8_lossy(&output.stdout))
    }

    fn anchor(&self, path: &Path) -> io::Result<plan_binding::Anchored> {
        read_root_anchor(path)
    }

    fn capabilities(&self, launcher: &Path) -> io::Result<Vec<String>> {
        run_capabilities(launcher, CAPABILITIES_TIMEOUT)
    }
}

/// `systemctl show -p NeedDaemonReload,DropInPaths` output. A missing
/// `NeedDaemonReload` is an error, not "no reload needed".
pub(crate) fn parse_unit_files(text: &str) -> io::Result<UnitFiles> {
    let mut reload = None;
    let mut dropins = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("NeedDaemonReload=") {
            reload = Some(value.trim() == "yes");
        } else if let Some(value) = line.strip_prefix("DropInPaths=") {
            dropins = value.split_whitespace().map(PathBuf::from).collect();
        }
    }
    Ok(UnitFiles {
        need_daemon_reload: reload
            .ok_or_else(|| io::Error::other("systemctl reported no NeedDaemonReload"))?,
        dropins,
    })
}

/// Run `<launcher> --capabilities` with an empty environment and no input,
/// and return its lines. Exit 0 within `timeout` is required; a launcher
/// that runs longer is killed.
pub(crate) fn run_capabilities(
    launcher: &Path,
    timeout: std::time::Duration,
) -> io::Result<Vec<String>> {
    let mut child = std::process::Command::new(launcher)
        .arg(launcher_contract::CAPABILITIES_FLAG)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "x0x-launcher --capabilities did not exit",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut out = String::new();
    if let Some(stdout) = child.stdout.take() {
        stdout.take(4096).read_to_string(&mut out)?;
    }
    if !status.success() {
        return Err(io::Error::other(format!(
            "x0x-launcher --capabilities exited {status}"
        )));
    }
    Ok(out.lines().map(|line| line.trim().to_string()).collect())
}

/// Evaluate the gate on the host for one apply and remember the decision.
/// Returns the transaction to run when the gate is open.
pub(crate) fn gate_for_apply(
    plan: &RestartPlan,
    cli_target: Option<&Path>,
    release: Release,
) -> Option<Transaction> {
    let anchor = plan
        .systemd_verified
        .as_ref()
        .and_then(|unit| unit.launcher.as_ref())
        .and_then(|loaded| loaded.trial.plan_anchor.clone());
    let decided = match cli_target.map(Path::canonicalize) {
        Some(Ok(cli)) => evaluate(launcher_contract::LAUNCHER_ENABLED, plan, &cli, &HostProbe),
        _ if !launcher_contract::LAUNCHER_ENABLED => Gate::Closed(DORMANT_REASON.into()),
        _ => Gate::Closed("the install has no sibling x0x CLI".into()),
    };
    let transaction = match decided {
        Gate::Closed(reason) => Err(reason),
        Gate::Open(open) => Transaction::new(plan, *open, release),
    };
    match transaction {
        Ok(transaction) => {
            remember(GateReport {
                open: true,
                reason: "launcher-bound unit, anchored install, launcher answers trial-v1".into(),
                plan_anchor: anchor,
            });
            Some(transaction)
        }
        Err(reason) => {
            remember(GateReport {
                open: false,
                reason,
                plan_anchor: anchor,
            });
            None
        }
    }
}

/// The release the apply installs.
#[derive(Debug, Clone)]
pub(crate) struct Release {
    pub(crate) previous_version: String,
    pub(crate) candidate_version: String,
    pub(crate) manifest_sha256: [u8; 32],
}

/// One producer transaction, built when the gate is open and run by the
/// apply worker after admission.
pub(crate) struct Transaction {
    transaction_id: String,
    anchor_path: PathBuf,
    data_root: PathBuf,
    release: Release,
    participant: Participant,
    /// The anchor reader, called under the stage lock: the launcher's own
    /// root-owner checks in production.
    read_anchor: fn(&Path) -> io::Result<plan_binding::Anchored>,
}

fn read_root_anchor(path: &Path) -> io::Result<plan_binding::Anchored> {
    plan_binding::read_anchor(path, ANCHOR_OWNER)
}

impl Transaction {
    fn new(plan: &RestartPlan, open: Open, release: Release) -> Result<Self, String> {
        let identity_root = IDENTITY_ROOT
            .get()
            .ok_or_else(|| "this daemon recorded no identity root".to_string())?;
        let participant = super::prepare_live::observe_this_daemon(
            &open.instance,
            &open.data_root,
            identity_root,
            restart_binding(plan, &open),
        )
        .map_err(|error| format!("this daemon cannot be observed as a participant: {error}"))?;
        Ok(Self {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            anchor_path: open.anchor_path,
            data_root: open.data_root,
            release,
            participant,
            read_anchor: read_root_anchor,
        })
    }

    /// The protected pair swap, every install lock held and admission done.
    /// On success the restart owner gets the host lock and the journal (in
    /// SwappedCli), so a refused restart can settle it.
    pub(crate) fn run(
        self,
        cli_lock: Option<InstallLock>,
        daemon_lock: InstallLock,
        upgrader: &Upgrader,
        extracted: &Path,
        companion: Option<(Upgrader, PathBuf)>,
    ) -> Result<super::apply::Swapped, UpgradeError> {
        let refused =
            |reason: String| UpgradeError::Other(format!("launcher plan refused: {reason}"));
        let (Some((cli_upgrader, cli_candidate)), Some(cli_lock)) = (companion, cli_lock) else {
            return Err(refused(
                "the plan needs the sibling x0x CLI; nothing was replaced".into(),
            ));
        };
        let daemon_target = canonical(upgrader.target_path())?;
        let cli_target = canonical(cli_upgrader.target_path())?;
        let daemon_backup = durable_backup(&daemon_target)?;
        let cli_backup = durable_backup(&cli_target)?;
        let artifact = |target: &Path, staged: &Path, backup: &Path| -> io::Result<ArtifactPlan> {
            Ok(ArtifactPlan {
                target_path: target.to_path_buf(),
                staged_path: staged.to_path_buf(),
                backup_path: backup.canonicalize()?,
                previous_sha256: sha256_of(target)?,
                candidate_sha256: sha256_of(staged)?,
            })
        };
        let plan = prepare::freeze_plan(PlanInput {
            previous_version: self.release.previous_version.clone(),
            candidate_version: self.release.candidate_version.clone(),
            manifest_sha256: self.release.manifest_sha256,
            daemon: artifact(&daemon_target, extracted, &daemon_backup).map_err(io_error)?,
            cli: artifact(&cli_target, &cli_candidate, &cli_backup).map_err(io_error)?,
            participants: vec![self.participant],
        })
        .map_err(|error| refused(error.to_string()))?;
        let lock = HostLock::adopt(&plan, cli_lock, daemon_lock)
            .map_err(|refusal| refused(refusal.error.to_string()))?;
        let (anchor_path, read_anchor) = (self.anchor_path, self.read_anchor);
        let mut prepared = Prepared::stage_reading_anchor(
            &lock,
            &self.data_root,
            &self.transaction_id,
            plan.clone(),
            || read_anchor(&anchor_path),
        )
        .map_err(|error| refused(error.to_string()))?;
        let mut swapped = [false, false];
        let steps = (|| -> io::Result<()> {
            prepared.advance(&lock, Phase::Prepared)?;
            #[cfg(test)]
            tests::step("prepared");
            install_durably(extracted, &daemon_target)?;
            swapped[0] = true;
            #[cfg(test)]
            tests::step("daemon swapped");
            prepared.advance(&lock, Phase::SwappedDaemon)?;
            install_durably(&cli_candidate, &cli_target)?;
            swapped[1] = true;
            #[cfg(test)]
            tests::step("cli swapped");
            prepared.advance(&lock, Phase::SwappedCli)
        })();
        if let Err(error) = steps {
            return Err(give_up(&lock, &mut prepared, &plan, swapped, &error));
        }
        Ok(super::apply::Swapped::Done {
            result: UpgradeResult::Success {
                version: self.release.candidate_version,
            },
            swapped: vec![(daemon_target, daemon_backup), (cli_target, cli_backup)],
            locks: super::apply::HeldInstallLocks::producer(lock, prepared),
        })
    }
}

/// After a failed producer step: restore every artifact this run swapped
/// (a copy of its backup, synced, renamed over the target, then the
/// directory synced; the backup stays), then write Superseded. Each outcome
/// is logged as it is and named in the returned error.
fn give_up(
    lock: &HostLock,
    prepared: &mut Prepared,
    plan: &journal::FrozenPlan,
    swapped: [bool; 2],
    error: &io::Error,
) -> UpgradeError {
    let mut restored = [false, false];
    for (index, artifact) in [&plan.daemon, &plan.cli].into_iter().enumerate() {
        if !swapped[index] {
            continue;
        }
        match restore_copy(&artifact.backup_path, &artifact.target_path) {
            Ok(()) => restored[index] = true,
            Err(restore) => {
                tracing::error!(
                    %error,
                    restore_error = %restore,
                    target = %artifact.target_path.display(),
                    "launcher plan failed and a swapped binary cannot be restored; \
                     the host journal stays as it is and the install needs manual recovery"
                );
                return UpgradeError::Other(format!(
                    "launcher plan failed ({error}); restoring {} failed ({restore}); the host \
                     journal stays in {:?}; manual recovery applies",
                    artifact.target_path.display(),
                    prepared.record().phase
                ));
            }
        }
    }
    match prepared.abandon(lock, restored) {
        Ok(()) => {
            tracing::warn!(%error, "launcher plan failed before the hand-off; the previous pair is installed and the host journal is superseded");
            UpgradeError::Other(format!(
                "launcher plan failed ({error}); the previous pair is installed and the host \
                 journal is superseded"
            ))
        }
        Err(settle) => {
            tracing::error!(%error, settle_error = %settle, "launcher plan failed; the previous pair is installed but the host journal could not be superseded; applies stay refused until it is settled");
            UpgradeError::Other(format!(
                "launcher plan failed ({error}); the previous pair is installed but the host \
                 journal could not be superseded ({settle})"
            ))
        }
    }
}

fn io_error(error: io::Error) -> UpgradeError {
    UpgradeError::Other(error.to_string())
}

fn canonical(path: &Path) -> Result<PathBuf, UpgradeError> {
    path.canonicalize().map_err(io_error)
}

/// The participant's restart binding: the supervised exit through the
/// launcher-bound systemd unit.
fn restart_binding(plan: &RestartPlan, open: &Open) -> RestartBinding {
    RestartBinding {
        mode: RestartOwner::SupervisedExit,
        supervised_exit_code: plan.supervised_exit_code,
        supervision_signal: plan.supervision_signal.clone(),
        launchd_verified: None,
        systemd_verified: plan
            .systemd_verified
            .as_ref()
            .map(|unit| journal::SystemdBinding {
                unit: unit.unit.clone(),
                user_manager: unit.user_manager,
                restart: unit.restart.clone(),
                template_version: unit.template_version,
            }),
        launcher: Some(journal::LauncherBinding {
            executable: open.launcher.clone(),
            argv: open.command.clone(),
            pid: None,
            process_start: None,
            boot_id: super::shutdown_flush::boot_identity().unwrap_or_default(),
            manager_exit_code: 75,
        }),
    }
}

pub(crate) fn sha256_of(path: &Path) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no directory"))?;
    journal::open_for_sync(parent, true)?.sync_all()
}

/// A temporary file beside `target`, created exclusively, mode 0700.
fn temporary_beside(target: &Path, tag: &str) -> io::Result<(PathBuf, std::fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::other("target has no file name"))?
        .to_string_lossy()
        .into_owned();
    let path = target.with_file_name(format!(".{name}.{tag}.{}.tmp", uuid::Uuid::new_v4()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    Ok((path, file))
}

/// Copy `from` to `to` durably: a synced temporary file renamed over `to`,
/// then the directory synced. The temporary file is removed on failure.
fn copy_durably(from: &Path, to: &Path, mode: u32, tag: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let (temporary, mut file) = temporary_beside(to, tag)?;
    let result = (|| {
        let mut source = std::fs::File::open(from)?;
        io::copy(&mut source, &mut file)?;
        file.flush()?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::rename(&temporary, to)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    sync_dir(to)
}

/// `<target>.backup` (the name the unprotected path uses), durable before
/// any journal names it.
fn durable_backup(target: &Path) -> Result<PathBuf, UpgradeError> {
    let backup = target.with_extension("backup");
    copy_durably(target, &backup, 0o755, "backup").map_err(io_error)?;
    Ok(backup)
}

/// Put the candidate at `target`: mode 0755, synced, renamed, directory
/// synced. Only then may the journal record the swap.
fn install_durably(candidate: &Path, target: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    #[cfg(test)]
    tests::fail_install(target)?;
    std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(0o755))?;
    std::fs::File::open(candidate)?.sync_all()?;
    std::fs::rename(candidate, target)?;
    sync_dir(target)
}

/// Restore `target` from `backup`, keeping the backup.
fn restore_copy(backup: &Path, target: &Path) -> io::Result<()> {
    copy_durably(backup, target, 0o755, "restore")
}

#[cfg(test)]
#[path = "producer_tests.rs"]
pub(crate) mod tests;
