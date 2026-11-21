#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Parity of the launcher's data-directory derivation
//! (`src/upgrade/launcher/daemon_root.rs`) with x0xd's own (#1378): for
//! each case, `x0xd <args> --check` reports the data directory it would
//! use, and `daemon_root::data_dir` must give the same one. `--check` loads
//! the config and ACLs, prints and exits: no identity, no sockets, no
//! network. `HOME` and the XDG dirs point at a temporary directory.

// The launcher module's surroundings that `daemon_root.rs` uses.
use std::io;
use std::path::{Path, PathBuf};

pub(crate) mod start {
    use std::io;

    #[derive(Debug)]
    struct Refusal(String);

    impl std::fmt::Display for Refusal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Refusal {}

    pub(crate) fn refused(reason: impl Into<String>) -> io::Error {
        io::Error::other(Refusal(reason.into()))
    }

    pub(crate) fn is_refusal(error: &io::Error) -> bool {
        error
            .get_ref()
            .is_some_and(|inner| inner.downcast_ref::<Refusal>().is_some())
    }
}

#[allow(dead_code)]
#[path = "../src/upgrade/launcher/daemon_root.rs"]
mod daemon_root;

/// The data directory `x0xd <args> --check` reports with `home` as its
/// `HOME` and the XDG bases under it.
fn reported(home: &Path, args: &[&str]) -> PathBuf {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_x0xd"))
        .args(args)
        .arg("--check")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("NO_COLOR", "1")
        .current_dir(home)
        .output()
        .expect("spawn x0xd --check");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{args:?}: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("    data_dir: \""))
        .filter_map(|rest| rest.strip_suffix("\","))
        .collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}");
    PathBuf::from(lines[0])
}

/// The bases the `dirs` crate gives x0xd in that environment.
fn bases(home: &Path) -> daemon_root::Bases {
    if cfg!(target_os = "macos") {
        let support = home.join("Library/Application Support");
        daemon_root::Bases {
            config: Some(support.clone()),
            data: Some(support),
        }
    } else {
        daemon_root::Bases {
            config: Some(home.join("config")),
            data: Some(home.join("data")),
        }
    }
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn derived(home: &Path, args: &[&str]) -> io::Result<PathBuf> {
    let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
    daemon_root::data_dir(&args, &bases(home))
}

#[test]
fn the_launcher_derives_the_data_directory_x0xd_reports() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().canonicalize().unwrap();
    let config_base = bases(&home).config.unwrap();
    let data_base = bases(&home).data.unwrap();
    let plane = "network_id = \"x0x.parity\"\n";
    let explicit = home.join("etc/explicit.toml");
    write(&explicit, "data_dir = \"/srv/x0x-explicit\"\n");
    let named_explicit = home.join("etc/named.toml");
    write(
        &named_explicit,
        &format!("{plane}data_dir = \"/srv/x0x-named\"\n"),
    );
    let named_default = home.join("etc/named-default.toml");
    write(
        &named_default,
        &format!(
            "{plane}data_dir = \"{}\"\n",
            data_base.join("x0x").display()
        ),
    );
    write(
        &config_base.join("x0x-bob/config.toml"),
        &format!("{plane}data_dir = \"/srv/x0x-bob\"\n"),
    );
    write(&config_base.join("x0x-alice/config.toml"), plane);
    write(&config_base.join("x0x-dave/config.toml"), plane);
    let carol = home.join("etc/carol.toml");
    write(&carol, &format!("{plane}instance_name = \"carol\"\n"));
    let explicit = explicit.to_str().unwrap();
    let named_explicit = named_explicit.to_str().unwrap();
    let named_default = named_default.to_str().unwrap();
    let carol = carol.to_str().unwrap();
    let cases: &[&[&str]] = &[
        &[],
        &["--name", "alice"],
        &["--name=dave"],
        &["--name", "bob"],
        &["--config", explicit],
        &["--name", "eve", "--config", named_explicit],
        &["--name", "frank", "--config", named_default],
        &["--config", carol],
        &["--relay", "--name", "alice", "--api-port", "0"],
    ];
    for args in cases {
        assert_eq!(
            derived(&home, args).unwrap(),
            reported(&home, args),
            "{args:?}"
        );
    }
    // The unnamed default file is read when it exists.
    write(
        &config_base.join("x0x/config.toml"),
        "data_dir = \"/srv/x0x-default\"\n",
    );
    assert_eq!(
        derived(&home, &[]).unwrap(),
        reported(&home, &[]),
        "default file"
    );
}
