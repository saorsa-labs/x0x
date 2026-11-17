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
        .ok_or_else(|| invalid("--instance must be 1-128 of [A-Za-z0-9._-]"))?
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
        issue(self.0, command)
    }
}

fn issue(args: &TrialArgs, command: &forward::DaemonCommand) -> io::Result<Option<start::Issued>> {
    check_root(&args.host_root)?;
    let journal_path = args.host_root.join(journal::JOURNAL_FILE_NAME);
    let metadata = match std::fs::symlink_metadata(&journal_path) {
        // No transaction on this host: an ordinary start.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(metadata) => metadata,
    };
    // The record's authority is its owner, mode and place (#2012): only
    // this account may have written it, and nobody else may change it.
    if !metadata.is_file() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(invalid(
            "host journal must be a regular file of this account with mode 0600",
        ));
    }
    let record = match journal::read_boot_records(&args.host_root).journal {
        journal::RecordRead::Journal(record) => *record,
        journal::RecordRead::Missing => return Ok(None),
        _ => return Err(invalid("host journal is unreadable or not a journal")),
    };
    if !owns_trial(record.phase)? {
        return Ok(None);
    }
    let participant = record
        .plan
        .participants
        .iter()
        .find(|p| p.instance_id == args.instance)
        .ok_or_else(|| invalid("instance is not a participant of the host journal"))?;
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
        return Err(invalid(
            "launcher argv does not match its participant in the host journal",
        ));
    }
    // Canonical install and participant paths (`Host::new`).
    let host = recovery::Host::new(args.host_root.clone(), record)?;
    Ok(Some(start::Issued {
        host,
        instance: args.instance.clone(),
    }))
}

/// Whether the journal phase gives the launcher trial authority. Before
/// any swap the installed bytes are unchanged and idle or superseded
/// records are history: an ordinary start. A daemon swapped without its
/// CLI is a mixed pair the launcher must not start or guess at.
fn owns_trial(phase: journal::Phase) -> io::Result<bool> {
    use journal::Phase::*;
    match phase {
        Staged | Probed | Prepared | Idle | Superseded => Ok(false),
        SwappedDaemon => Err(invalid("host journal is between the daemon and CLI swap")),
        SwappedCli | HandoffArmed | Booting | HealthCommitted | HostCommitted | RollingBack
        | FailedReleaseHold | Restored | RecoveryFailed => Ok(true),
    }
}

/// The host root must be canonical (no symlink can move it), a directory
/// of this account, and writable by nobody else.
fn check_root(root: &Path) -> io::Result<()> {
    if root.canonicalize()? != root {
        return Err(invalid("--host-root must be canonical"));
    }
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.uid() != effective_uid() || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
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
        let issued = issue(&args, &command).unwrap().expect("issued");
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
            assert!(issue(&args, &command).unwrap().is_none(), "{phase:?}");
        }
        std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
        assert!(issue(&args, &command).unwrap().is_none());
    }

    #[test]
    fn a_half_swapped_pair_is_refused() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedDaemon);
        let (args, command) = matching(&record);
        assert!(issue(&args, &command).is_err());
    }

    /// Every mismatch between the launcher argv and the participant is an
    /// error, never an ordinary start.
    #[test]
    fn a_mismatched_argv_is_refused() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let mut other_instance = args.clone();
        other_instance.instance = "nobody".into();
        assert!(issue(&other_instance, &command).is_err());
        let mut other_exe = forward::DaemonCommand {
            executable: "/usr/bin/other".into(),
            args: command.args.clone(),
        };
        assert!(issue(&args, &other_exe).is_err());
        other_exe.executable = command.executable.clone();
        other_exe.args.push("--extra".into());
        assert!(issue(&args, &other_exe).is_err());
    }

    #[test]
    fn a_writable_or_foreign_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(issue(&args, &command).is_err(), "group-readable journal");
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(issue(&args, &command).is_err(), "group-writable root");
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
        assert!(issue(&args, &command).is_err());
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
}
