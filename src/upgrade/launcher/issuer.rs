//! The launcher-side issuer (#1378): the launcher argv names the host root
//! and this launcher's participant, and the issuer reads and verifies the
//! prepared host journal there before it gives the main loop a host.
//!
//! The argv contract (provisional and dormant, frozen before `ENABLED`):
//!
//! ```text
//! x0x-launcher /abs/x0xd [daemon args...]
//! x0x-launcher --host-root <abs data_root> --instance <id> -- /abs/x0xd [daemon args...]
//! ```
//!
//! The first form never owns a trial. The writer of the journal is the M2
//! prepare producer (#2012); the launcher only reads it. A journal it cannot
//! verify is an error (the main loop exits 75), never a guess.
use super::*;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;

/// Where this launcher's trial authority would be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrialArgs {
    pub(crate) host_root: PathBuf,
    pub(crate) instance: String,
}

pub(crate) struct LauncherArgs {
    pub(crate) trial: Option<TrialArgs>,
    pub(crate) command: forward::DaemonCommand,
}

/// Parse the launcher argv (after the launcher's own name).
pub(crate) fn launcher_argv(argv: &[OsString]) -> io::Result<LauncherArgs> {
    if argv.first().map(OsString::as_os_str) != Some(std::ffi::OsStr::new("--host-root")) {
        return Ok(LauncherArgs {
            trial: None,
            command: forward::daemon_argv(argv)?,
        });
    }
    let usage = || {
        invalid(
            "usage: x0x-launcher --host-root /absolute/data-root --instance ID -- \
             /absolute/daemon [daemon args]",
        )
    };
    let [_, root, flag, instance, separator, rest @ ..] = argv else {
        return Err(usage());
    };
    if flag != "--instance" || separator != "--" {
        return Err(usage());
    }
    let host_root = PathBuf::from(root);
    if !host_root.is_absolute() {
        return Err(invalid("--host-root must be absolute"));
    }
    let instance = instance
        .to_str()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
        // `.` and `..` would name a directory if the id were ever joined to
        // a path; the character set already excludes any separator.
        .filter(|id| *id != "." && *id != "..")
        .ok_or_else(|| invalid("--instance must be 1-128 of [A-Za-z0-9._-], not . or .."))?
        .to_owned();
    Ok(LauncherArgs {
        trial: Some(TrialArgs {
            host_root,
            instance,
        }),
        command: forward::daemon_argv(rest)?,
    })
}

/// The issuer for a launcher whose argv names a host root and instance.
pub(super) struct JournalIssuer<'a>(pub(super) &'a TrialArgs);

impl start::Issuer for JournalIssuer<'_> {
    fn issue(&self, command: &forward::DaemonCommand) -> io::Result<Option<start::Issued>> {
        issue_as(self.0, command, effective_uid())
    }
}

/// `uid` is the account the root and records must belong to: the
/// launcher's effective uid.
fn issue_as(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    uid: u32,
) -> io::Result<Option<start::Issued>> {
    issue_with(args, command, uid, uid)
}

/// As `issue_as`, with the root's and the journal's expected owners apart,
/// so a test can make only the journal foreign (#2014 review).
fn issue_with(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    root_uid: u32,
    record_uid: u32,
) -> io::Result<Option<start::Issued>> {
    check_root(&args.host_root, root_uid)?;
    let Some(record) = read_journal(&args.host_root, record_uid)? else {
        return no_authority(args);
    };
    if !owns_trial(record.phase)? {
        return no_authority(args);
    }
    let participant = record
        .plan
        .participants
        .iter()
        .find(|p| p.instance_id == args.instance)
        .ok_or_else(|| start::refused("instance is not a participant of the host journal"))?;
    // `argv[0]` is the process's argv0, which the launcher sets itself at
    // spawn; the daemon's arguments are the rest (`child::Owned::spawn`).
    let planned = participant.argv.get(1..).unwrap_or_default();
    let args_match = planned.len() == command.args.len()
        && planned
            .iter()
            .zip(&command.args)
            .all(|(planned, given)| given.to_str() == Some(planned.as_str()));
    if participant.data_root != args.host_root
        || participant.executable.as_os_str() != command.executable
        || !args_match
    {
        return Err(start::refused(
            "launcher argv does not match its participant in the host journal",
        ));
    }
    // Canonical install and participant paths (`Host::new`).
    // A plan path that is missing or not canonical stays so on a restart:
    // a fixed refusal. Any other I/O error may pass (#2014 review).
    let host = recovery::Host::new(args.host_root.clone(), record).map_err(|error| {
        if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::Other) {
            start::refused(format!("host journal plan is not usable: {error}"))
        } else {
            error
        }
    })?;
    Ok(Some(start::Issued {
        host,
        instance: args.instance.clone(),
    }))
}

/// Read the host journal through one descriptor: open it without following
/// a symlink, check owner, mode, type and size on that descriptor, and read
/// from it, so nothing can swap the file between the check and the read
/// (#2014 review). `Ok(None)` only when there is no journal.
fn read_journal(root: &Path, uid: u32) -> io::Result<Option<journal::JournalRecord>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let path = root.join(journal::JOURNAL_FILE_NAME);
    let opened = std::fs::OpenOptions::new()
        .read(true)
        // No symlink is followed; a FIFO opens without blocking and then
        // fails the regular-file check.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path);
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(start::refused("host journal is a symlink"));
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    // The record's authority is its owner, mode and place (#2012): only
    // this account wrote it, and only this account can read or change it.
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > journal::MAX_RECORD_BYTES
    {
        return Err(start::refused(
            "host journal must be a regular file of this account with mode 0600",
        ));
    }
    let mut bytes = Vec::new();
    file.take(journal::MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > journal::MAX_RECORD_BYTES {
        return Err(start::refused("host journal exceeds the size limit"));
    }
    match journal::classify_record(&bytes, "journal") {
        journal::RecordRead::Journal(record) => Ok(Some(*record)),
        _ => Err(start::refused(
            "host journal is corrupt or of an unknown schema",
        )),
    }
}

/// No in-flight journal names this launcher. That is an ordinary start
/// only if no unfinished trial of this participant is on disk: a Booting or
/// Authorized trial means a swapped candidate could start unsupervised, so
/// the start is refused instead (#2014 review). A Committed or Restored
/// trial is finished: its daemon is the installed or the restored bytes.
fn no_authority(args: &TrialArgs) -> io::Result<Option<start::Issued>> {
    let path = args.host_root.join(coordinator::TRIAL_FILE_NAME);
    let bytes = match journal::read_auxiliary_record(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        // A symlinked, non-regular or oversized trial record stays so: a
        // fixed refusal, never a passthrough (#2014 review).
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Err(start::refused(format!("trial record is unusable: {error}")));
        }
        Err(error) => return Err(error),
    };
    let trial: Trial =
        serde_json::from_slice(&bytes).map_err(|_| start::refused("trial record is unreadable"))?;
    match trial.phase {
        Phase::Committed | Phase::Restored if trial.instance == args.instance => Ok(None),
        _ => Err(start::refused(
            "an unfinished trial exists without an in-flight host journal",
        )),
    }
}

/// Whether the journal phase gives the launcher trial authority. Before
/// any swap the installed bytes are unchanged and idle or superseded
/// records are history (an ordinary start, unless a trial is unfinished).
/// A daemon swapped without its CLI is a mixed pair the launcher must not
/// start or guess at.
fn owns_trial(phase: journal::Phase) -> io::Result<bool> {
    use journal::Phase::*;
    match phase {
        Staged | Probed | Prepared | Idle | Superseded => Ok(false),
        SwappedDaemon => Err(start::refused(
            "host journal is between the daemon and CLI swap",
        )),
        SwappedCli | HandoffArmed | Booting | HealthCommitted | HostCommitted | RollingBack
        | FailedReleaseHold | Restored | RecoveryFailed => Ok(true),
    }
}

/// The host root must be canonical (no symlink can move it), a directory
/// of this account, and writable by nobody else.
fn check_root(root: &Path, uid: u32) -> io::Result<()> {
    if root.canonicalize()? != root {
        return Err(start::refused("--host-root must be canonical"));
    }
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(start::refused(
            "--host-root must be a directory of this account that no other can write",
        ));
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use testkit::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_plain_form_owns_no_trial() {
        let parsed = launcher_argv(&os(&["/usr/bin/x0xd", "--name", "a"])).unwrap();
        assert!(parsed.trial.is_none());
        assert_eq!(parsed.command.executable, "/usr/bin/x0xd");
        assert_eq!(parsed.command.args, os(&["--name", "a"]));
    }

    #[test]
    fn the_trial_form_names_root_and_instance() {
        let parsed = launcher_argv(&os(&[
            "--host-root",
            "/var/lib/x0x",
            "--instance",
            "alice",
            "--",
            "/usr/bin/x0xd",
            "--name",
            "a",
        ]))
        .unwrap();
        assert_eq!(
            parsed.trial,
            Some(TrialArgs {
                host_root: "/var/lib/x0x".into(),
                instance: "alice".into(),
            })
        );
        assert_eq!(parsed.command.executable, "/usr/bin/x0xd");
        assert_eq!(parsed.command.args, os(&["--name", "a"]));
    }

    #[test]
    fn a_malformed_trial_form_is_refused() {
        for argv in [
            vec!["--host-root"],
            vec!["--host-root", "/r", "--instance", "a", "/usr/bin/x0xd"],
            vec!["--host-root", "/r", "--name", "a", "--", "/usr/bin/x0xd"],
            vec![
                "--host-root",
                "rel",
                "--instance",
                "a",
                "--",
                "/usr/bin/x0xd",
            ],
            vec!["--host-root", "/r", "--instance", "", "--", "/usr/bin/x0xd"],
            vec![
                "--host-root",
                "/r",
                "--instance",
                "a/b",
                "--",
                "/usr/bin/x0xd",
            ],
            vec![
                "--host-root",
                "/r",
                "--instance",
                ".",
                "--",
                "/usr/bin/x0xd",
            ],
            vec![
                "--host-root",
                "/r",
                "--instance",
                "..",
                "--",
                "/usr/bin/x0xd",
            ],
            vec!["--host-root", "/r", "--instance", "a", "--", "x0xd"],
            vec!["--host-root", "/r", "--instance", "a", "--"],
        ] {
            assert!(launcher_argv(&os(&argv)).is_err(), "{argv:?}");
        }
    }

    /// A launcher argv that matches the fixture's participant `alice`.
    fn matching(record: &journal::JournalRecord) -> (TrialArgs, forward::DaemonCommand) {
        let alice = &record.plan.participants[0];
        (
            TrialArgs {
                host_root: alice.data_root.clone(),
                instance: alice.instance_id.clone(),
            },
            forward::DaemonCommand {
                executable: alice.executable.clone().into_os_string(),
                args: alice.argv.iter().skip(1).map(OsString::from).collect(),
            },
        )
    }

    /// The fixture's journal is in alice's data root, the launcher's host
    /// root. Alice gets one daemon argument, so argument checks bite.
    fn rooted(phase: journal::Phase) -> (tempfile::TempDir, PathBuf, journal::JournalRecord) {
        let (dir, root, _host, record) = fixture_with(phase, |record| {
            record.plan.participants[0].argv.push("--name".into());
        });
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, root, record)
    }

    #[test]
    fn a_matching_in_flight_journal_issues_a_host() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let issued = issue_as(&args, &command, effective_uid())
            .unwrap()
            .expect("issued");
        assert_eq!(issued.instance, "alice");
        assert_eq!(issued.host.root(), root);
    }

    #[test]
    fn no_journal_or_a_settled_one_is_an_ordinary_start() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        for phase in [
            journal::Phase::Staged,
            journal::Phase::Prepared,
            journal::Phase::Idle,
        ] {
            let mut settled = record.clone();
            settled.phase = phase;
            journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &settled).unwrap();
            assert!(
                issue_as(&args, &command, effective_uid())
                    .unwrap()
                    .is_none(),
                "{phase:?}"
            );
        }
        std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
        assert!(issue_as(&args, &command, effective_uid())
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_half_swapped_pair_is_refused() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedDaemon);
        let (args, command) = matching(&record);
        assert!(issue_as(&args, &command, effective_uid()).is_err());
    }

    /// Every mismatch between the launcher argv and the participant is an
    /// error, never an ordinary start.
    #[test]
    fn a_mismatched_argv_is_refused() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let mut other_instance = args.clone();
        other_instance.instance = "nobody".into();
        assert!(issue_as(&other_instance, &command, effective_uid()).is_err());
        let mut other_exe = forward::DaemonCommand {
            executable: "/usr/bin/other".into(),
            args: command.args.clone(),
        };
        assert!(issue_as(&args, &other_exe, effective_uid()).is_err());
        other_exe.executable = command.executable.clone();
        other_exe.args.push("--extra".into());
        assert!(issue_as(&args, &other_exe, effective_uid()).is_err());
    }

    #[test]
    fn a_writable_or_foreign_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            issue_as(&args, &command, effective_uid()).is_err(),
            "group-readable journal"
        );
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            issue_as(&args, &command, effective_uid()).is_err(),
            "group-writable root"
        );
    }

    /// A symlinked host root could move the journal out from under the
    /// checks; it is refused, even when its target is valid.
    #[test]
    fn a_symlinked_host_root_is_refused() {
        let (dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (mut args, command) = matching(&record);
        let link = dir.path().canonicalize().unwrap().join("link");
        std::os::unix::fs::symlink(&args.host_root, &link).unwrap();
        args.host_root = link;
        assert!(issue_as(&args, &command, effective_uid()).is_err());
    }

    /// End to end: the trial-form argv, the journal issuer and the main
    /// loop. A stop before the first attempt saves the trial Stopped.
    #[test]
    fn the_trial_form_runs_the_issued_trial() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let host = recovery::Host::new(root.clone(), record).unwrap();
        let path = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        trial.phase = Phase::Authorized;
        trial.save(&path).unwrap();
        let exit = start::start_with(
            &JournalIssuer(&args),
            &command,
            || {},
            Clock::now,
            || true,
            || {},
        );
        assert_eq!(exit, start::Start::Exit(0));
        let on_disk = Trial::load(&path, &host.binding().unwrap(), "alice").unwrap();
        assert_eq!(on_disk.phase, Phase::Stopped);
    }

    fn refused(result: io::Result<Option<start::Issued>>) -> bool {
        match result {
            Err(error) => start::is_refusal(&error),
            Ok(_) => false,
        }
    }

    fn write_0600(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Save alice's trial through `phases` (the save guard checks each).
    fn trial_through(root: &Path, record: &journal::JournalRecord, phases: &[Phase]) {
        let host = recovery::Host::new(root.to_path_buf(), record.clone()).unwrap();
        let path = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        for phase in phases {
            match phase {
                Phase::Booting | Phase::Provisional => {
                    trial.attempts = 1;
                    trial.ready_since_ms = Some(trial.started_ms);
                    trial.child = Some(Identity {
                        pid: 1,
                        start: 1,
                        boot: trial.boot.clone(),
                    });
                }
                _ => trial.child = None,
            }
            trial.phase = phase.clone();
            trial.save(&path).unwrap();
        }
    }

    /// #2014 review item 2: no in-flight journal (absent, or rewritten to
    /// a settled phase) while an unfinished trial is on disk is a fixed
    /// refusal, never an unsupervised start of a swapped candidate.
    #[test]
    fn an_unfinished_trial_without_an_in_flight_journal_is_refused() {
        for unfinished in [
            &[Phase::Authorized][..],
            &[Phase::Authorized, Phase::Booting][..],
            &[Phase::Authorized, Phase::Stopped][..],
        ] {
            let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
            let (args, command) = matching(&record);
            trial_through(&root, &record, unfinished);
            for phase in [
                journal::Phase::Staged,
                journal::Phase::Prepared,
                journal::Phase::Idle,
            ] {
                let mut settled = record.clone();
                settled.phase = phase;
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &settled).unwrap();
                assert!(
                    refused(issue_as(&args, &command, effective_uid())),
                    "{unfinished:?} {phase:?}"
                );
            }
            std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
            assert!(
                refused(issue_as(&args, &command, effective_uid())),
                "{unfinished:?} no journal"
            );
        }
    }

    /// A Committed trial is finished: an idle or absent journal is an
    /// ordinary start.
    #[test]
    fn a_finished_trial_allows_an_ordinary_start() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        trial_through(
            &root,
            &record,
            &[Phase::Authorized, Phase::Provisional, Phase::Committed],
        );
        let mut idle = record.clone();
        idle.phase = journal::Phase::Idle;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &idle).unwrap();
        assert!(issue_as(&args, &command, effective_uid())
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_corrupt_or_unknown_schema_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        write_0600(&journal, b"{ not json");
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "corrupt"
        );
        let mut value = serde_json::to_value(&record).unwrap();
        value["schema_version"] = 99.into();
        write_0600(&journal, &serde_json::to_vec(&value).unwrap());
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "schema 99"
        );
    }

    #[test]
    fn a_participant_in_another_data_root_is_refused() {
        let (_dir, root, mut record) = rooted(journal::Phase::SwappedCli);
        let other = root.join("other");
        std::fs::create_dir(&other).unwrap();
        record.plan.participants[0].data_root = other;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let (mut args, command) = matching(&record);
        args.host_root = root;
        assert!(refused(issue_as(&args, &command, effective_uid())));
    }

    #[test]
    fn a_symlinked_or_irregular_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        let moved = root.join("elsewhere.json");
        std::fs::rename(&journal, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &journal).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "symlink"
        );
        std::fs::remove_file(&journal).unwrap();
        std::fs::create_dir(&journal).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "directory"
        );
    }

    /// Exactly 0600 and this account: 0400 and a foreign owner are refused.
    #[test]
    fn a_journal_that_is_not_0600_of_this_account_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(refused(issue_as(&args, &command, effective_uid())), "0400");
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(issue_as(&args, &command, effective_uid())
            .unwrap()
            .is_some());
        // Only the journal is foreign: the root check passes, so the
        // descriptor owner check is the one that refuses (#2014 review).
        let foreign = effective_uid().wrapping_add(1);
        assert!(
            refused(issue_with(&args, &command, effective_uid(), foreign)),
            "foreign journal owner"
        );
    }

    /// Fixed refusals exit 78; a failed read (here a host root that does
    /// not exist) exits 75.
    #[test]
    fn issuer_refusals_exit_78_and_read_errors_75() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedDaemon);
        let (args, command) = matching(&record);
        let exit = |args: &TrialArgs| {
            start::start_with(
                &JournalIssuer(args),
                &command,
                || {},
                Clock::now,
                || false,
                || {},
            )
        };
        assert_eq!(exit(&args), start::Start::Exit(start::EXIT_FINAL));
        let missing = TrialArgs {
            host_root: root.join("missing"),
            instance: "alice".into(),
        };
        assert_eq!(exit(&missing), start::Start::Exit(start::EXIT_TEMPFAIL));
    }

    /// #2014 review item 4: a plan path that is missing is a fixed
    /// refusal (78), not a retry.
    #[test]
    fn a_missing_plan_path_is_a_fixed_refusal() {
        let (_dir, root, mut record) = rooted(journal::Phase::SwappedCli);
        record.plan.cli.backup_path = root.join("missing-backup");
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let (args, command) = matching(&record);
        assert!(refused(issue_as(&args, &command, effective_uid())));
    }

    /// #2014 review item 4: a symlinked or non-regular trial record with no
    /// in-flight journal is a fixed refusal, never a passthrough.
    #[test]
    fn an_unusable_trial_record_is_a_fixed_refusal() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
        let trial = root.join(coordinator::TRIAL_FILE_NAME);
        let target = root.join("elsewhere.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &trial).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "symlink"
        );
        std::fs::remove_file(&trial).unwrap();
        std::fs::create_dir(&trial).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "directory"
        );
    }
}
