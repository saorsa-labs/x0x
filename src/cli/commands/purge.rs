//! Path discovery for destructive CLI purge.

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

pub fn collect_purge_paths(data_dir: Option<&Path>, home_dir: Option<&Path>) -> Vec<PurgePath> {
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

    if let Some(home_dir) = home_dir {
        push_existing_dir(&mut paths, PurgePathKind::Keys, home_dir.join(".x0x"));

        if let Ok(entries) = std::fs::read_dir(home_dir) {
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

    paths
}

fn push_existing_dir(paths: &mut Vec<PurgePath>, kind: PurgePathKind, path: PathBuf) {
    if path.is_dir() {
        paths.push(PurgePath { kind, path });
    }
}

#[cfg(test)]
mod tests {
    use super::{collect_purge_paths, PurgePathKind};

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

        let paths = collect_purge_paths(Some(&data_dir), Some(&home_dir));

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
}
