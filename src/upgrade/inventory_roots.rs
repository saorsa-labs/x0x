//! Private path calculation from supplied daemon launch/config evidence.
//!
//! This does no I/O or environment/account lookup. Results are lexical paths,
//! not canonical filesystem identities or proof of the running daemon's roots.
//! The collector must bind the account, cwd, config bytes and executable version,
//! prove config absence when applicable, validate startup, resolve symlinks and
//! recheck the evidence. In particular, a config edited after process startup
//! cannot establish the running process's roots. Collection stays dormant.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::server::InstanceName;
use crate::storage::{resolve_x0x_home, resolve_x0x_instance_dir};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_ARGS: usize = 16384;

#[derive(Clone, Copy)]
pub(super) enum Platform {
    Linux,
    Macos,
}

pub(super) struct Selection {
    pub config_path: PathBuf,
    explicit_config: bool,
    name: Option<InstanceName>,
    cwd: PathBuf,
    home: PathBuf,
    data_base: PathBuf,
    identity_override: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct LexicalRoots {
    pub name: Option<String>,
    pub data: PathBuf,
    pub identity: PathBuf,
}

/// Select the config before reading it, as x0xd does. The CLI name selects the
/// default config path; a name inside that file cannot select a different file.
/// Missing HOME requires an independently observed account home. Relative HOME,
/// parent traversal, repeated root flags and equals spellings refuse here even
/// where ordinary startup is more permissive. No current-process fallback.
pub(super) fn select(
    platform: Platform,
    argv: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    account_home: Option<&Path>,
) -> io::Result<Selection> {
    if argv.is_empty()
        || argv[0].is_empty()
        || argv.len() > MAX_ARGS
        || argv
            .iter()
            .map(|s| s.len().saturating_add(1))
            .try_fold(0usize, |sum, len| sum.checked_add(len))
            .is_none_or(|sum| sum > MAX_BYTES)
        || argv.iter().any(|s| s.contains('\0'))
        || !cwd.is_absolute()
    {
        return Err(bad("invalid launch arguments or cwd"));
    }
    checked_path(cwd, cwd)?;
    let home = env
        .get("HOME")
        .filter(|s| !s.is_empty())
        .map(Path::new)
        .or(account_home)
        .ok_or_else(|| bad("participant home is unknown"))?;
    if !home.is_absolute() || home.to_str().is_none() {
        return Err(bad("participant home is not absolute UTF-8"));
    }
    let home = checked_path(home, cwd)?;
    let base = |key, fallback: &str| match platform {
        Platform::Linux => env
            .get(key)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(fallback)),
        Platform::Macos => home.join("Library/Application Support"),
    };
    let name = argument(argv, "--name")?.map(valid_name).transpose()?;
    let explicit = argument(argv, "--config")?;
    let config = explicit.map(PathBuf::from).unwrap_or_else(|| {
        base("XDG_CONFIG_HOME", ".config")
            .join(
                name.as_ref()
                    .map(|n| format!("x0x-{}", n.as_str()))
                    .unwrap_or_else(|| "x0x".into()),
            )
            .join("config.toml")
    });
    let identity_override = env.get("X0X_HOME").filter(|s| !s.is_empty()).cloned();
    if let Some(path) = &identity_override {
        checked_path(Path::new(path), cwd)?;
    }
    let data_base = checked_path(&base("XDG_DATA_HOME", ".local/share"), cwd)?;
    Ok(Selection {
        config_path: checked_path(&config, cwd)?,
        explicit_config: explicit.is_some(),
        name,
        cwd: cwd.to_owned(),
        home,
        data_base,
        identity_override,
    })
}

#[derive(Default, serde::Deserialize)]
struct RootFields {
    instance_name: Option<String>,
    data_dir: Option<PathBuf>,
    identity_dir: Option<PathBuf>,
}

impl Selection {
    /// `None` means the collector proved this selected default file absent.
    /// Explicit missing files refuse. This parses only root-relevant TOML fields;
    /// it does not validate unrelated startup policy or claim that a job can run.
    pub(super) fn resolve(&self, config: Option<&[u8]>) -> io::Result<LexicalRoots> {
        let fields: RootFields = match config {
            Some(bytes) => {
                if bytes.len() > MAX_BYTES {
                    return Err(bad("config exceeds bound"));
                }
                let text = std::str::from_utf8(bytes).map_err(|_| bad("config is not UTF-8"))?;
                toml::from_str(text).map_err(|_| bad("invalid root configuration"))?
            }
            None if !self.explicit_config => RootFields::default(),
            None => return Err(bad("explicit config is missing")),
        };
        let name = match &self.name {
            Some(name) => Some(name.clone()),
            None => fields
                .instance_name
                .as_deref()
                .map(valid_name)
                .transpose()?,
        };
        let default_data = self.data_base.join("x0x");
        let mut data = fields.data_dir.unwrap_or_else(|| default_data.clone());
        // x0xd compares the value, including an explicitly supplied default.
        if data == default_data {
            if let Some(name) = &name {
                data = self.data_base.join(format!("x0x-{}", name.as_str()));
            }
        }
        let identity = match fields.identity_dir {
            Some(path) => path,
            None => {
                let base =
                    resolve_x0x_home(self.identity_override.as_deref(), Some(self.home.clone()));
                match &name {
                    Some(name) => resolve_x0x_instance_dir(base, name.as_str()),
                    None => base,
                }
                .ok_or_else(|| bad("identity root cannot be resolved"))?
            }
        };
        Ok(LexicalRoots {
            name: name.map(InstanceName::into_string),
            data: checked_path(&data, &self.cwd)?,
            identity: checked_path(&identity, &self.cwd)?,
        })
    }
}

fn valid_name(raw: &str) -> io::Result<InstanceName> {
    InstanceName::try_from(raw.to_owned()).map_err(|_| bad("invalid instance name"))
}

fn argument<'a>(argv: &'a [String], flag: &str) -> io::Result<Option<&'a str>> {
    let mut result = None;
    for (index, value) in argv.iter().enumerate() {
        if value == flag {
            let next = argv
                .get(index + 1)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| bad("missing root argument"))?;
            if index == 0 || result.replace(next.as_str()).is_some() {
                return Err(bad("ambiguous root argument"));
            }
        } else if value
            .strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('='))
        {
            return Err(bad("unsupported root argument spelling"));
        }
    }
    Ok(result)
}

fn checked_path(path: &Path, cwd: &Path) -> io::Result<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_BYTES
        || bytes.contains(&0)
        || path.components().any(|c| c == Component::ParentDir)
    {
        return Err(bad("unsupported participant path"));
    }
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    };
    if path.as_os_str().len() > MAX_BYTES {
        return Err(bad("resolved path exceeds bound"));
    }
    Ok(path)
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
include!("../../tests/upgrade_inventory_roots.rs");

#[cfg(test)]
inventory_roots_tests!();
