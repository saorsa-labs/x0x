//! The data directory of the daemon a launcher argv names (#1378). The host
//! root selects the journal and the trial record, so the issuer refuses a
//! `--host-root` that is not the directory this daemon uses: a launcher
//! that read another directory's records could pass through to a swapped
//! candidate. The directory is derived as `x0xd` derives it at startup
//! (`src/bin/x0xd.rs`), from the environment the launcher passes on to it.
//! `tests/launcher_data_dir_parity.rs` checks it against `x0xd --check`.
use super::*;
use std::ffi::{OsStr, OsString};
use std::fs::File;

/// The base directories `x0xd` takes from its environment (the `dirs`
/// crate): `None` where `dirs` finds none.
pub(super) struct Bases {
    pub(super) config: Option<PathBuf>,
    pub(super) data: Option<PathBuf>,
}

impl Bases {
    /// This process's bases. A passthrough `exec`s the daemon with this
    /// process's environment, so they are the daemon's bases too.
    pub(super) fn of_process() -> Self {
        Self {
            config: dirs::config_dir(),
            data: dirs::data_dir(),
        }
    }
}

/// The config file is read only up to this size.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The data directory `x0xd` started with the daemon arguments `args`
/// (`argv[1..]`) and `bases` uses: the `data_dir` of the config file
/// (`--config`, else `<config base>/x0x[-<name>]/config.toml` when it
/// exists), else `<data base>/x0x`; a named instance (`--name`, else the
/// file's `instance_name`) that keeps that default uses `<data base>/
/// x0x-<name>`. What `x0xd` would refuse at startup, a relative data
/// directory, and a repeated `--config` or `--name` or the `--config=`
/// spelling (`x0xd` reads the first and ignores the rest) are typed
/// refusals: the directory is then not known. An unreadable config file is
/// a failed read.
pub(super) fn data_dir(args: &[OsString], bases: &Bases) -> io::Result<PathBuf> {
    let config = flag(args, "--config", false)?;
    let cli_name = flag(args, "--name", true)?
        .map(|name| instance_name(name.to_str()))
        .transpose()?;
    let named = |base: &str, name: Option<&str>| match name {
        Some(name) => format!("{base}-{name}"),
        None => base.to_owned(),
    };
    let default_config = bases
        .config
        .as_ref()
        .map(|dir| {
            dir.join(named("x0x", cli_name.as_deref()))
                .join("config.toml")
        })
        .unwrap_or_else(|| PathBuf::from("/etc/x0x/config.toml"));
    let path = match config {
        Some(path) => Some(PathBuf::from(path)),
        None => default_config.exists().then_some(default_config),
    };
    let table = match &path {
        Some(path) => read_config(path)?,
        None => toml::Table::new(),
    };
    let name = match cli_name {
        Some(name) => Some(name),
        None => match table.get("instance_name") {
            None => None,
            Some(value) => Some(instance_name(value.as_str())?),
        },
    };
    let in_data_base = |dir: &str| match &bases.data {
        Some(base) => base.join(dir),
        None => Path::new("/var/lib").join(dir),
    };
    let default = in_data_base("x0x");
    let configured = match table.get("data_dir") {
        None => default.clone(),
        Some(value) => PathBuf::from(
            value
                .as_str()
                .ok_or_else(|| start::refused("the daemon's config data_dir is not text"))?,
        ),
    };
    // x0xd compares the value, so an explicitly configured default is
    // renamed for a named instance too.
    let data_dir = match &name {
        Some(name) if configured == default => in_data_base(&named("x0x", Some(name))),
        _ => configured,
    };
    if !data_dir.is_absolute() {
        return Err(start::refused(format!(
            "the daemon's data directory {} is relative",
            data_dir.display()
        )));
    }
    Ok(data_dir)
}

/// Whether `data_dir` names the canonical directory `root`. Its parent is
/// resolved, but its last component is not followed: a data directory that
/// is a symlink is not the root, even when it points there, so no later
/// change of the link can move the daemon off the records the launcher
/// read. A parent that does not exist names no root.
pub(super) fn names_root(data_dir: &Path, root: &Path) -> io::Result<bool> {
    let (Some(parent), Some(name)) = (data_dir.parent(), data_dir.file_name()) else {
        return Ok(false);
    };
    match parent.canonicalize() {
        Ok(parent) => Ok(parent.join(name) == root),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// The one value of `name` in `args`: `name value`, or `name=value` where
/// `equals` allows it. A missing or empty value, a second occurrence, or
/// `name=` where it is not allowed is a typed refusal.
fn flag<'a>(args: &'a [OsString], name: &str, equals: bool) -> io::Result<Option<&'a OsStr>> {
    let mut found = None;
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        index += 1;
        let value = if arg == name {
            index += 1;
            args.get(index - 1).map(OsString::as_os_str)
        } else if let Some(value) = arg
            .as_encoded_bytes()
            .strip_prefix(name.as_bytes())
            .and_then(|rest| rest.strip_prefix(b"="))
        {
            if !equals {
                return Err(start::refused(format!(
                    "the daemon argument {name}= is not read by x0xd; use {name} <value>"
                )));
            }
            let value = std::str::from_utf8(value)
                .map_err(|_| start::refused(format!("the daemon's {name} is not UTF-8")))?;
            Some(OsStr::new(value))
        } else {
            continue;
        };
        let value = value
            .filter(|value| !value.is_empty())
            .ok_or_else(|| start::refused(format!("the daemon argument {name} has no value")))?;
        if found.replace(value).is_some() {
            return Err(start::refused(format!(
                "the daemon arguments repeat {name}, so its data directory is not known"
            )));
        }
    }
    Ok(found)
}

/// An instance name `x0xd` accepts: 1 to 64 characters, ASCII letters,
/// digits and `-`, starting with a letter or digit.
fn instance_name(name: Option<&str>) -> io::Result<String> {
    match name {
        Some(name)
            if (1..=64).contains(&name.len())
                && name.starts_with(|c: char| c.is_ascii_alphanumeric())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') =>
        {
            Ok(name.to_owned())
        }
        _ => Err(start::refused(
            "the daemon's instance name is not one x0xd accepts",
        )),
    }
}

fn read_config(path: &Path) -> io::Result<toml::Table> {
    use std::io::Read;
    let mut text = String::new();
    File::open(path)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| match error.kind() {
            io::ErrorKind::InvalidData => start::refused("the daemon's config file is not UTF-8"),
            _ => error,
        })?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(start::refused("the daemon's config file exceeds 1 MiB"));
    }
    toml::from_str(&text).map_err(|_| start::refused("the daemon's config file is not valid TOML"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    struct Env {
        _dir: tempfile::TempDir,
        base: PathBuf,
        bases: Bases,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let bases = Bases {
            config: Some(base.join("config")),
            data: Some(base.join("data")),
        };
        Env {
            _dir: dir,
            base,
            bases,
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn the_default_and_named_data_directories_follow_x0xd() {
        let env = env();
        let data = env.base.join("data");
        assert_eq!(data_dir(&[], &env.bases).unwrap(), data.join("x0x"));
        for args in [&["--name", "alice"][..], &["--name=alice"][..]] {
            assert_eq!(
                data_dir(&os(args), &env.bases).unwrap(),
                data.join("x0x-alice"),
                "{args:?}"
            );
        }
        let none = Bases {
            config: None,
            data: None,
        };
        assert_eq!(
            data_dir(&os(&["--name", "alice"]), &none).unwrap(),
            Path::new("/var/lib/x0x-alice")
        );
    }

    #[test]
    fn the_config_file_sets_the_data_directory_and_the_name() {
        let env = env();
        let explicit = env.base.join("etc/x0x.toml");
        write(&explicit, "data_dir = \"/srv/x0x\"\n");
        let args = os(&["--config", explicit.to_str().unwrap()]);
        assert_eq!(data_dir(&args, &env.bases).unwrap(), Path::new("/srv/x0x"));

        // The named default file, and the explicit default renamed for the
        // name the file sets.
        let named = env.base.join("config/x0x-bob/config.toml");
        write(&named, "data_dir = \"/srv/bob\"\n");
        assert_eq!(
            data_dir(&os(&["--name", "bob"]), &env.bases).unwrap(),
            Path::new("/srv/bob")
        );
        let default = env.base.join("data/x0x");
        write(
            &env.base.join("config/x0x/config.toml"),
            &format!(
                "instance_name = \"carol\"\ndata_dir = \"{}\"\n",
                default.display()
            ),
        );
        assert_eq!(
            data_dir(&[], &env.bases).unwrap(),
            env.base.join("data/x0x-carol")
        );
    }

    #[test]
    fn an_unknown_data_directory_is_a_typed_refusal() {
        let env = env();
        let config = env.base.join("x0x.toml");
        let path = config.to_str().unwrap();
        for (why, text, args) in [
            ("relative", "data_dir = \"rel\"\n", os(&["--config", path])),
            ("not text", "data_dir = 1\n", os(&["--config", path])),
            ("bad toml", "data_dir = \n", os(&["--config", path])),
            ("bad name", "", os(&["--name", "-a"])),
            (
                "config name",
                "instance_name = \"a/b\"\n",
                os(&["--config", path]),
            ),
            ("no value", "", os(&["--config"])),
            ("empty", "", os(&["--name="])),
            ("repeated", "", os(&["--name", "a", "--name=b"])),
            ("equals", "", os(&[&format!("--config={path}")])),
        ] {
            write(&config, text);
            let error = data_dir(&args, &env.bases).unwrap_err();
            assert!(start::is_refusal(&error), "{why}: {error}");
        }
        let missing = os(&["--config", env.base.join("missing.toml").to_str().unwrap()]);
        let error = data_dir(&missing, &env.bases).unwrap_err();
        assert!(!start::is_refusal(&error), "a failed read: {error}");
    }

    #[test]
    fn a_data_directory_names_the_root_only_without_a_final_symlink() {
        let env = env();
        let root = env.base.join("root");
        std::fs::create_dir(&root).unwrap();
        assert!(names_root(&root, &root).unwrap());
        std::os::unix::fs::symlink(&env.base, env.base.join("up")).unwrap();
        assert!(names_root(&env.base.join("up/root"), &root).unwrap());
        std::os::unix::fs::symlink(&root, env.base.join("link")).unwrap();
        assert!(!names_root(&env.base.join("link"), &root).unwrap());
        assert!(!names_root(&env.base.join("other"), &root).unwrap());
        assert!(!names_root(&env.base.join("missing/root"), &root).unwrap());
        assert!(!names_root(Path::new("/"), &root).unwrap());
    }
}
