//! The integrity binding of the M2 host journal (#2012, design B4).
//!
//! The journal (`JournalRecord`) carries no hash or signature, and its
//! shape cannot change (`deny_unknown_fields`). Two more records bind it:
//!
//! - The **plan anchor**: a JSON file that root writes when it installs the
//!   launcher (the systemd drop-in installer). It names the approved
//!   install: the daemon target, the CLI target, and each participant's
//!   instance id and data root. The launcher argv names it with
//!   `--plan-anchor <path>`. Root owns it, no group or other account can
//!   write it or any directory above it, so the daemon's account cannot
//!   change it.
//! - The **plan binding**: a sidecar `upgrade-plan-binding.json` beside the
//!   journal, written by the prepare producer before the Staged journal.
//!   It holds the transaction, the generation, the SHA-256 of the frozen
//!   plan and the SHA-256 of the anchor the plan was checked against.
//!
//! A launcher gives a trial only when the plan names exactly the anchored
//! install and the binding matches the journal and the anchor.
//!
//! Limit: the binding fixes which install a plan can name (the targets,
//! the participants and their data roots). It does not authenticate the
//! artifact hashes or versions inside the plan: anything that runs as the
//! daemon's account can still write a journal and a matching binding for
//! the anchored install.
//!
//! This file depends only on `journal`, so the launcher includes it by
//! path, as it does `journal.rs`.
//!
//! `dead_code` is allowed for the whole file because each compiling target
//! uses a different half: the library (the producer) uses `bind` and
//! `validate_binding` but not yet the reader, which the apply path will
//! use (PR 5 of the #2012 plan); the launcher uses the reader and `verify`
//! but never `bind`. Per-item allows would cover about ten items.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::journal::{FrozenPlan, JournalRecord};

/// The sidecar beside each host journal.
pub(crate) const BINDING_FILE_NAME: &str = "upgrade-plan-binding.json";
/// Upper bound on the anchor's and the binding's size.
pub(crate) const MAX_BYTES: u64 = 64 * 1024;
const SCHEMA: u32 = 1;
const ANCHOR_KIND: &str = "plan_anchor";
const BINDING_KIND: &str = "plan_binding";

/// One participant the anchor approves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnchorParticipant {
    pub instance_id: String,
    pub data_root: PathBuf,
}

/// The approved install, written by root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanAnchor {
    pub schema: u32,
    pub record_kind: String,
    pub daemon_target: PathBuf,
    pub cli_target: PathBuf,
    pub participants: Vec<AnchorParticipant>,
}

/// The sidecar that binds one transaction's plan to the anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanBinding {
    pub schema: u32,
    pub record_kind: String,
    pub transaction_id: String,
    pub generation: u64,
    pub plan_sha256: [u8; 32],
    pub anchor_sha256: [u8; 32],
}

fn refused(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

/// The plan digest: SHA-256 of the plan's JSON, the same digest the trial
/// binding and the arm receipt use (`launcher::digest`).
pub(crate) fn plan_sha256(plan: &FrozenPlan) -> io::Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(plan).map_err(io::Error::other)?).into())
}

/// A plan anchor that parsed and passed its own checks, with the exact
/// bytes it was read from (the binding hashes those bytes).
#[derive(Debug, Clone)]
pub(crate) struct Anchored {
    bytes: Vec<u8>,
    anchor: PlanAnchor,
}

impl Anchored {
    /// Parse anchor bytes: schema 1, kind `plan_anchor`, absolute targets
    /// that differ, and at least one participant, each with a valid
    /// instance id (the launcher's rule), an absolute data root, and no
    /// instance id twice.
    pub(crate) fn parse(bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.len() as u64 > MAX_BYTES {
            return Err(refused("plan anchor exceeds the size limit"));
        }
        let anchor: PlanAnchor = serde_json::from_slice(&bytes)
            .map_err(|error| refused(format!("plan anchor is unreadable: {error}")))?;
        if anchor.schema != SCHEMA || anchor.record_kind != ANCHOR_KIND {
            return Err(refused("plan anchor has an unknown schema or kind"));
        }
        if !anchor.daemon_target.is_absolute()
            || !anchor.cli_target.is_absolute()
            || anchor.daemon_target == anchor.cli_target
        {
            return Err(refused(
                "plan anchor targets must be absolute and must differ",
            ));
        }
        if anchor.participants.is_empty() {
            return Err(refused("plan anchor names no participant"));
        }
        let mut seen = BTreeSet::new();
        for participant in &anchor.participants {
            let id = participant.instance_id.as_str();
            if !valid_instance(id) || !participant.data_root.is_absolute() {
                return Err(refused(format!(
                    "plan anchor participant {id:?} is not valid"
                )));
            }
            if !seen.insert(id) {
                return Err(refused(format!("plan anchor names instance {id} twice")));
            }
        }
        Ok(Self { bytes, anchor })
    }

    pub(crate) fn anchor(&self) -> &PlanAnchor {
        &self.anchor
    }

    pub(crate) fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    /// The plan names exactly the anchored install: the same daemon and
    /// CLI targets, and the same set of (instance id, data root).
    pub(crate) fn names(&self, plan: &FrozenPlan) -> io::Result<()> {
        if plan.daemon.target_path != self.anchor.daemon_target
            || plan.cli.target_path != self.anchor.cli_target
        {
            return Err(refused(
                "the plan's install pair is not the anchored install",
            ));
        }
        let planned: BTreeSet<AnchorParticipant> = plan
            .participants
            .iter()
            .map(|p| AnchorParticipant {
                instance_id: p.instance_id.clone(),
                data_root: p.data_root.clone(),
            })
            .collect();
        let anchored: BTreeSet<AnchorParticipant> =
            self.anchor.participants.iter().cloned().collect();
        if planned.len() != plan.participants.len() || planned != anchored {
            return Err(refused(
                "the plan's participants are not the anchored participants",
            ));
        }
        Ok(())
    }

    /// The binding for one transaction of `plan`, after `names`.
    pub(crate) fn bind(
        &self,
        transaction_id: &str,
        generation: u64,
        plan: &FrozenPlan,
    ) -> io::Result<PlanBinding> {
        self.names(plan)?;
        Ok(PlanBinding {
            schema: SCHEMA,
            record_kind: BINDING_KIND.into(),
            transaction_id: transaction_id.into(),
            generation,
            plan_sha256: plan_sha256(plan)?,
            anchor_sha256: self.sha256(),
        })
    }

    /// `binding` binds `record`'s transaction and plan to this anchor, and
    /// the plan names this anchor's install.
    pub(crate) fn verify(&self, binding: &PlanBinding, record: &JournalRecord) -> io::Result<()> {
        if binding.schema != SCHEMA || binding.record_kind != BINDING_KIND {
            return Err(refused("plan binding has an unknown schema or kind"));
        }
        if binding.transaction_id != record.transaction_id
            || binding.generation != record.generation
        {
            return Err(refused(
                "plan binding is for another transaction or generation",
            ));
        }
        if binding.plan_sha256 != plan_sha256(&record.plan)? {
            return Err(refused("plan binding does not match the journal's plan"));
        }
        if binding.anchor_sha256 != self.sha256() {
            return Err(refused("plan binding was made against another anchor"));
        }
        self.names(&record.plan)
    }
}

/// Parse a plan binding's bytes.
pub(crate) fn parse_binding(bytes: &[u8]) -> io::Result<PlanBinding> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(refused("plan binding exceeds the size limit"));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| refused(format!("plan binding is unreadable: {error}")))
}

/// Strict check for `journal::write_auxiliary_record`.
pub(crate) fn validate_binding(bytes: &[u8]) -> io::Result<()> {
    let binding = parse_binding(bytes)?;
    if binding.schema != SCHEMA || binding.record_kind != BINDING_KIND {
        return Err(refused("plan binding has an unknown schema or kind"));
    }
    Ok(())
}

/// The launcher's instance rule (`launcher_contract::parse_launcher_argv`):
/// 1-128 of `[A-Za-z0-9._-]`, not `.` or `..`.
fn valid_instance(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && id != "."
        && id != ".."
}

/// The uid that owns a production anchor: root.
pub(crate) const ANCHOR_OWNER: u32 = 0;

/// Read the plan anchor at `path`. `owner` is the account that must own
/// the anchor and may own its ancestors besides root ([`ANCHOR_OWNER`] in
/// production, so both must be root; a test passes its own uid).
///
/// - `path` must be absolute and canonical.
/// - Every ancestor must be a directory owned by root or `owner` that no
///   group or other account can write, unless it is sticky (a sticky
///   directory lets only an entry's owner rename it).
/// - The file is opened once without following a symlink; type, owner,
///   mode (no group or other write) and size are checked on that
///   descriptor, and it is read from it.
///
/// The mode check reads the permission bits only. An access control list
/// (macOS, or POSIX ACLs on Linux) is not read: only root can set one on
/// a root-owned anchor or directory, so it is a limit of the check, not a
/// way round it for the daemon's account.
///
/// A failed check is `InvalidData`; a missing file is `NotFound`. Each
/// check has its own reason, so a refusal names what failed.
#[cfg(unix)]
pub(crate) fn read_anchor(path: &Path, owner: u32) -> io::Result<Anchored> {
    read_anchor_as(path, owner, owner)
}

/// `read_anchor` with the ancestors' and the file's expected owners apart,
/// so a test can make only one of them foreign.
#[cfg(unix)]
fn read_anchor_as(path: &Path, ancestor_owner: u32, file_owner: u32) -> io::Result<Anchored> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err(refused(format!(
            "plan anchor {} must be absolute and canonical",
            path.display()
        )));
    }
    for ancestor in path.ancestors().skip(1) {
        check_ancestor(ancestor, ancestor_owner)?;
    }
    let file = open_anchor(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(refused("plan anchor is not a regular file"));
    }
    if metadata.uid() != file_owner {
        return Err(refused(format!(
            "plan anchor is owned by uid {}, not root",
            metadata.uid()
        )));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(refused("plan anchor is writable by group or others"));
    }
    if metadata.len() > MAX_BYTES {
        return Err(refused("plan anchor file is larger than 64 KiB"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    Anchored::parse(bytes)
}

/// One ancestor of the anchor: a directory (not a symlink; a canonical
/// path has none, but the path can change after `canonicalize`), owned by
/// root or `owner`, that no group or other account can write unless it is
/// sticky.
#[cfg(unix)]
fn check_ancestor(ancestor: &Path, owner: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(ancestor)?;
    if !metadata.is_dir() {
        return Err(refused(format!(
            "plan anchor ancestor {} is not a directory",
            ancestor.display()
        )));
    }
    if metadata.uid() != 0 && metadata.uid() != owner {
        return Err(refused(format!(
            "plan anchor ancestor {} is owned by uid {}, not root",
            ancestor.display(),
            metadata.uid()
        )));
    }
    if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
        return Err(refused(format!(
            "plan anchor ancestor {} is writable by group or others",
            ancestor.display()
        )));
    }
    Ok(())
}

/// Open the anchor without following a symlink at its last component.
#[cfg(unix)]
fn open_anchor(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                refused("plan anchor is a symlink")
            } else {
                error
            }
        })
}

/// Test support: the anchor bytes for `plan`'s own install.
#[cfg(all(test, unix))]
pub(crate) fn test_anchor_bytes(plan: &FrozenPlan) -> Vec<u8> {
    let anchor = PlanAnchor {
        schema: SCHEMA,
        record_kind: ANCHOR_KIND.into(),
        daemon_target: plan.daemon.target_path.clone(),
        cli_target: plan.cli.target_path.clone(),
        participants: plan
            .participants
            .iter()
            .map(|p| AnchorParticipant {
                instance_id: p.instance_id.clone(),
                data_root: p.data_root.clone(),
            })
            .collect(),
    };
    serde_json::to_vec_pretty(&anchor).unwrap()
}

/// Test support: a parsed anchor for `plan`'s own install, with no file.
#[cfg(all(test, unix))]
pub(crate) fn test_anchored(plan: &FrozenPlan) -> Anchored {
    Anchored::parse(test_anchor_bytes(plan)).unwrap()
}

/// Test support: write an anchor for `plan`'s install in `dir` (mode
/// 0644, owned by the test's account) and return its path.
#[cfg(all(test, unix))]
pub(crate) fn write_test_anchor(dir: &Path, plan: &FrozenPlan) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    // Written by rename, so a test that stages from two threads never
    // reads a half-written anchor.
    let path = dir.join(TEST_ANCHOR_NAME);
    let mut temporary = tempfile::NamedTempFile::new_in(dir).unwrap();
    std::io::Write::write_all(&mut temporary, &test_anchor_bytes(plan)).unwrap();
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .unwrap();
    temporary.persist(&path).unwrap();
    path
}

/// Test support: the anchor's file name in a test directory.
#[cfg(all(test, unix))]
pub(crate) const TEST_ANCHOR_NAME: &str = "plan-anchor.json";

/// Test support: an anchor read as the test's own account.
#[cfg(all(test, unix))]
pub(crate) fn read_test_anchor(path: &Path) -> Anchored {
    // SAFETY: geteuid takes no arguments and cannot fail.
    read_anchor(path, unsafe { libc::geteuid() }).unwrap()
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::prepare::tests::input_in;
    use super::super::prepare::{freeze_plan, tests::root};
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn plan_in(root: &Path) -> FrozenPlan {
        freeze_plan(input_in(root)).unwrap()
    }

    fn uid() -> u32 {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn edited(
        plan: &FrozenPlan,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> io::Result<Anchored> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&test_anchor_bytes(plan)).unwrap();
        edit(&mut value);
        Anchored::parse(serde_json::to_vec(&value).unwrap())
    }

    #[test]
    fn a_malformed_anchor_is_refused() {
        let (_dir, root) = root();
        let plan = plan_in(&root);
        assert!(edited(&plan, |_| {}).is_ok());
        let edits: [fn(&mut serde_json::Value); 9] = [
            |a| a["schema"] = 2.into(),
            |a| a["record_kind"] = "journal".into(),
            |a| a["extra"] = true.into(),
            |a| a["daemon_target"] = "relative/x0xd".into(),
            |a| a["cli_target"] = a["daemon_target"].clone(),
            |a| a["participants"] = serde_json::json!([]),
            |a| a["participants"][0]["instance_id"] = "..".into(),
            |a| a["participants"][0]["data_root"] = "relative".into(),
            |a| {
                let first = a["participants"][0].clone();
                a["participants"].as_array_mut().unwrap().push(first);
            },
        ];
        for (index, edit) in edits.into_iter().enumerate() {
            let error = edited(&plan, edit).expect_err("refused");
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "edit {index}: {error}"
            );
        }
    }

    #[test]
    fn the_plan_must_name_exactly_the_anchored_install() {
        let (_dir, root) = root();
        let plan = plan_in(&root);
        let anchor = test_anchored(&plan);
        anchor.names(&plan).unwrap();
        let edits: [fn(&mut FrozenPlan); 4] = [
            |p| p.daemon.target_path = "/elsewhere/x0xd".into(),
            |p| p.cli.target_path = "/elsewhere/x0x".into(),
            |p| p.participants[0].data_root = "/elsewhere".into(),
            |p| {
                let mut bob = p.participants[0].clone();
                bob.instance_id = "bob".into();
                p.participants.push(bob);
            },
        ];
        for (index, edit) in edits.into_iter().enumerate() {
            let mut other = plan.clone();
            edit(&mut other);
            assert!(anchor.names(&other).is_err(), "edit {index}");
            assert!(anchor.bind("tx", 1, &other).is_err(), "edit {index}");
        }
    }

    #[test]
    fn a_binding_verifies_only_its_own_journal_and_anchor() {
        let (_dir, root) = root();
        let plan = plan_in(&root);
        let anchor = test_anchored(&plan);
        let record = JournalRecord {
            schema_version: super::super::journal::SCHEMA_VERSION,
            record_kind: "journal".into(),
            transaction_id: "tx".into(),
            sequence: 1,
            generation: 1,
            plan: plan.clone(),
            phase: super::super::journal::Phase::SwappedCli,
            cause: None,
            daemon_progress: super::super::journal::ArtifactProgress {
                swapped: true,
                restored: false,
                observed_sha256: None,
            },
            cli_progress: super::super::journal::ArtifactProgress {
                swapped: true,
                restored: false,
                observed_sha256: None,
            },
        };
        let binding = anchor.bind("tx", 1, &plan).unwrap();
        anchor.verify(&binding, &record).unwrap();
        validate_binding(&serde_json::to_vec(&binding).unwrap()).unwrap();

        let mut wrong = binding.clone();
        wrong.transaction_id = "other".into();
        assert!(anchor.verify(&wrong, &record).is_err(), "transaction");
        let mut wrong = binding.clone();
        wrong.generation = 2;
        assert!(anchor.verify(&wrong, &record).is_err(), "generation");
        let mut wrong = binding.clone();
        wrong.plan_sha256[0] ^= 1;
        assert!(anchor.verify(&wrong, &record).is_err(), "plan");
        let mut wrong = binding.clone();
        wrong.record_kind = "plan_anchor".into();
        assert!(anchor.verify(&wrong, &record).is_err(), "kind");
        let mut changed = record.clone();
        changed.plan.manifest_sha256[0] ^= 1;
        assert!(anchor.verify(&binding, &changed).is_err(), "changed plan");
        let mut bytes = test_anchor_bytes(&plan);
        bytes.push(b'\n');
        let other_anchor = Anchored::parse(bytes).unwrap();
        assert!(
            other_anchor.verify(&binding, &record).is_err(),
            "other anchor"
        );
    }

    /// The reason of a refused read: an `InvalidData` refusal naming
    /// `reason`.
    fn refused_for(result: io::Result<Anchored>, reason: &str) {
        let error = result.expect_err("refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(
            error.to_string().contains(reason),
            "want {reason:?}: {error}"
        );
    }

    /// Each check of `read_anchor` has a case that only it refuses, so the
    /// removal of any one check fails a case (#2171 review).
    #[test]
    fn read_anchor_checks_owner_mode_type_and_ancestors() {
        let (dir, root) = root();
        let plan = plan_in(&root);
        let path = write_test_anchor(&root, &plan);
        let me = uid();
        assert_eq!(
            read_anchor(&path, me).unwrap().anchor(),
            test_anchored(&plan).anchor()
        );

        // Only the file's owner is foreign: the file owner check alone.
        refused_for(
            read_anchor_as(&path, me, me + 1),
            "plan anchor is owned by uid",
        );
        // Only the ancestors' owner is foreign: the test's own directories
        // are not root's, so the ancestor owner check alone.
        refused_for(
            read_anchor_as(&path, me + 1, me),
            &format!("ancestor {} is owned by uid", root.display()),
        );
        // A group-writable file, in good directories.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        refused_for(read_anchor(&path, me), "plan anchor is writable by group");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o646)).unwrap();
        refused_for(read_anchor(&path, me), "plan anchor is writable by group");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        // A non-sticky ancestor others can write; a sticky one is allowed.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        refused_for(
            read_anchor(&path, me),
            &format!("ancestor {} is writable by group", root.display()),
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(
            read_anchor(&path, me).is_ok(),
            "a sticky ancestor is allowed"
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A symlinked directory component: the canonical check.
        let linked_dir = dir.path().canonicalize().unwrap().join("linked-dir");
        std::os::unix::fs::symlink(&root, &linked_dir).unwrap();
        refused_for(
            read_anchor(&linked_dir.join(TEST_ANCHOR_NAME), me),
            "must be absolute and canonical",
        );
        // A directory at the anchor path: the regular-file check.
        let directory = root.join("directory.json");
        std::fs::create_dir(&directory).unwrap();
        refused_for(read_anchor(&directory, me), "not a regular file");
        // An oversized file: the descriptor's size check, before parsing.
        let large = root.join("large.json");
        std::fs::write(&large, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        std::fs::set_permissions(&large, std::fs::Permissions::from_mode(0o644)).unwrap();
        refused_for(read_anchor(&large, me), "larger than 64 KiB");
        // Missing.
        let missing = read_anchor(&root.join("missing.json"), me).err().unwrap();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    /// The opener alone refuses a symlink at the last component (the
    /// canonical check before it would too, but the path can change in
    /// between), and the ancestor check alone refuses a symlink or a file
    /// where a directory should be.
    #[test]
    fn the_opener_and_the_ancestor_check_refuse_links() {
        let (_dir, root) = root();
        let plan = plan_in(&root);
        let path = write_test_anchor(&root, &plan);
        let link = root.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let error = open_anchor(&link).expect_err("refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(open_anchor(&path).is_ok());

        let linked_dir = root.join("linked-dir");
        std::os::unix::fs::symlink(&root, &linked_dir).unwrap();
        let error = check_ancestor(&linked_dir, uid()).expect_err("refused");
        assert!(error.to_string().contains("is not a directory"), "{error}");
        let error = check_ancestor(&path, uid()).expect_err("refused");
        assert!(error.to_string().contains("is not a directory"), "{error}");
        check_ancestor(&root, uid()).unwrap();
    }
}
