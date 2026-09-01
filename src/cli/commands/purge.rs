//! Path discovery for destructive CLI purge.

use anyhow::Context;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurgePathKind {
    Data,
    InstanceData,
    Keys,
    LegacyInstanceKeys,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurgePath {
    pub kind: PurgePathKind,
    pub path: PathBuf,
}

/// Collect purgeable paths. `x0x_home` is the RESOLVED default identity
/// directory (issue #456: `$X0X_HOME` when set — which may be any path the
/// operator chose, NOT necessarily `<something>/.x0x` — else `<home>/.x0x`).
/// The keys dir is that directory itself; legacy named-instance key dirs
/// (`.x0x-<name>`) are its siblings.
pub fn collect_purge_paths(data_dir: Option<&Path>, x0x_home: Option<&Path>) -> Vec<PurgePath> {
    let mut paths = Vec::new();

    if let Some(data_dir) = data_dir {
        push_existing_dir(&mut paths, PurgePathKind::Data, data_dir.join("x0x"));

        if let Ok(entries) = std::fs::read_dir(data_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("x0x-") && entry.path().is_dir() {
                    paths.push(PurgePath {
                        kind: PurgePathKind::InstanceData,
                        path: entry.path(),
                    });
                }
            }
        }
    }

    if let Some(x0x_home) = x0x_home {
        push_existing_dir(&mut paths, PurgePathKind::Keys, x0x_home.to_path_buf());

        if let Some(parent) = x0x_home.parent() {
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(".x0x-") && entry.path().is_dir() {
                        paths.push(PurgePath {
                            kind: PurgePathKind::LegacyInstanceKeys,
                            path: entry.path(),
                        });
                    }
                }
            }
        }
    }

    paths
}

/// Confirmation hint read from the resolved default identity directory
/// (see [`collect_purge_paths`]).
pub fn agent_id_confirmation_hint(x0x_home: Option<&Path>) -> anyhow::Result<String> {
    let x0x_home =
        x0x_home.ok_or_else(|| anyhow::anyhow!("default identity directory is unavailable"))?;
    let key_path = x0x_home.join("agent.key");
    let data = std::fs::read(&key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let keypair = crate::storage::deserialize_agent_keypair(&data)
        .with_context(|| format!("failed to parse {}", key_path.display()))?;

    Ok(hex::encode(&keypair.agent_id().as_bytes()[..4]))
}

fn push_existing_dir(paths: &mut Vec<PurgePath>, kind: PurgePathKind, path: PathBuf) {
    if path.is_dir() {
        paths.push(PurgePath { kind, path });
    }
}

#[cfg(test)]
mod tests {
    use super::{agent_id_confirmation_hint, collect_purge_paths, PurgePathKind};
    use crate::identity::AgentKeypair;
    use crate::storage::serialize_agent_keypair;

    #[test]
    fn includes_named_instance_data_dirs() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join("data");
        let home_dir = tmp.path().join("home");
        let default_data = data_dir.join("x0x");
        let alice_data = data_dir.join("x0x-alice");
        let bob_data = data_dir.join("x0x-bob");
        let unrelated_data = data_dir.join("not-x0x");
        let named_data_file = data_dir.join("x0x-file");
        let keys = home_dir.join(".x0x");
        let legacy_keys = home_dir.join(".x0x-alice");
        let misleading_home_data = home_dir.join("x0x-charlie");

        std::fs::create_dir_all(&default_data)?;
        std::fs::create_dir_all(&alice_data)?;
        std::fs::create_dir_all(&bob_data)?;
        std::fs::create_dir_all(&unrelated_data)?;
        std::fs::write(&named_data_file, b"not a directory")?;
        std::fs::create_dir_all(&keys)?;
        std::fs::create_dir_all(&legacy_keys)?;
        std::fs::create_dir_all(&misleading_home_data)?;

        let paths = collect_purge_paths(Some(&data_dir), Some(&keys));

        assert!(paths
            .iter()
            .any(|path| { path.kind == PurgePathKind::Data && path.path == default_data }));
        assert!(paths
            .iter()
            .any(|path| { path.kind == PurgePathKind::InstanceData && path.path == alice_data }));
        assert!(paths
            .iter()
            .any(|path| { path.kind == PurgePathKind::InstanceData && path.path == bob_data }));
        assert!(paths
            .iter()
            .any(|path| { path.kind == PurgePathKind::Keys && path.path == keys }));
        assert!(paths.iter().any(|path| {
            path.kind == PurgePathKind::LegacyInstanceKeys && path.path == legacy_keys
        }));
        assert!(!paths.iter().any(|path| path.path == unrelated_data));
        assert!(!paths.iter().any(|path| path.path == named_data_file));
        assert!(!paths.iter().any(|path| path.path == misleading_home_data));

        Ok(())
    }

    #[test]
    fn agent_id_confirmation_hint_errors_when_key_is_missing() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let result = agent_id_confirmation_hint(Some(&tmp.path().join(".x0x")));

        assert!(result.is_err());
        assert!(!matches!(result.as_deref(), Ok("unknown")));

        Ok(())
    }

    #[test]
    fn agent_id_confirmation_hint_errors_when_key_is_corrupt() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let key_dir = tmp.path().join(".x0x");
        std::fs::create_dir_all(&key_dir)?;
        std::fs::write(key_dir.join("agent.key"), b"not an agent key")?;

        let result = agent_id_confirmation_hint(Some(&key_dir));

        assert!(result.is_err());
        assert!(!matches!(result.as_deref(), Ok("unknown")));

        Ok(())
    }

    #[test]
    fn agent_id_confirmation_hint_returns_first_eight_hex_chars() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let key_dir = tmp.path().join(".x0x");
        std::fs::create_dir_all(&key_dir)?;

        let keypair = AgentKeypair::generate()?;
        let expected = hex::encode(&keypair.agent_id().as_bytes()[..4]);
        std::fs::write(
            key_dir.join("agent.key"),
            serialize_agent_keypair(&keypair)?,
        )?;

        assert_eq!(agent_id_confirmation_hint(Some(&key_dir))?, expected);

        Ok(())
    }

    /// Review r2 (#456): with an X0X_HOME override of arbitrary shape
    /// (e.g. `/tmp/site/x0x` — not `<parent>/.x0x`), the KEYS purge target
    /// is the override directory ITSELF; nothing may target
    /// `<parent>/.x0x`, and the confirmation hint reads the override's
    /// agent.key.
    #[test]
    fn override_shaped_x0x_home_is_purged_directly() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let site = tmp.path().join("site");
        let override_home = site.join("x0x"); // X0X_HOME=/…/site/x0x
        let decoy = site.join(".x0x"); // must NOT be targeted (does not exist)
        let sibling_instance = site.join(".x0x-alice"); // sibling instances still are
        std::fs::create_dir_all(&override_home)?;
        std::fs::create_dir_all(&sibling_instance)?;

        let paths = collect_purge_paths(None, Some(&override_home));

        assert!(paths
            .iter()
            .any(|path| path.kind == PurgePathKind::Keys && path.path == override_home));
        assert!(
            !paths.iter().any(|path| path.path == decoy),
            "the parent's .x0x must not be targeted when the override differs"
        );
        assert!(paths.iter().any(|path| {
            path.kind == PurgePathKind::LegacyInstanceKeys && path.path == sibling_instance
        }));
        Ok(())
    }
}
