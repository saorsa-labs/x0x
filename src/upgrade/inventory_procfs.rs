//! Bounded parsers for supplied Linux procfs evidence (ADR 0094 S2c).
//!
//! No files, processes or namespaces are inspected here. Passing these checks
//! does not establish source provenance, freshness, namespace visibility or
//! complete host inventory. Collection and transaction admission remain dormant.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io;

const MAX_BYTES: usize = 1_048_576;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProcessStat {
    pub(crate) pid: u32,
    pub(crate) state: u8,
    pub(crate) flags: u64,
    pub(crate) start_ticks: u64,
}

/// Linux proc_pid_stat(5), fields 1, 3, 9 and 22. The comm field is opaque:
/// it can contain spaces, newlines, parentheses and non-UTF-8 bytes.
pub(crate) fn parse_stat(bytes: &[u8]) -> io::Result<ProcessStat> {
    bounded(bytes)?;
    let open = bytes.iter().position(|b| *b == b'(').ok_or_else(invalid)?;
    let close = bytes.iter().rposition(|b| *b == b')').ok_or_else(invalid)?;
    if open < 2 || close < open || bytes.get(open - 1) != Some(&b' ') {
        return Err(invalid());
    }
    let pid = number(&bytes[..open - 1])?;
    let pid = u32::try_from(pid).map_err(|_| invalid())?;
    if pid == 0 || bytes.get(close + 1) != Some(&b' ') {
        return Err(invalid());
    }
    let fields: Vec<_> = words(&bytes[close + 2..]).collect();
    let state = fields.first().ok_or_else(invalid)?;
    if state.len() != 1 || !b"RSDZTtWXxKPI".contains(&state[0]) {
        return Err(invalid());
    }
    Ok(ProcessStat {
        pid,
        state: state[0],
        flags: number(fields.get(6).ok_or_else(invalid)?)?,
        start_ticks: number(fields.get(19).ok_or_else(invalid)?)?,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Credentials {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// Bind all four real/effective/saved/filesystem IDs. Mixed ownership and
/// duplicate rows refuse; no ambient account lookup fills missing fields.
pub(crate) fn parse_credentials(bytes: &[u8]) -> io::Result<Credentials> {
    bounded(bytes)?;
    let mut uid = None;
    let mut gid = None;
    for line in bytes.split(|b| *b == b'\n') {
        let (values, slot) = if let Some(values) = line.strip_prefix(b"Uid:") {
            (values, &mut uid)
        } else if let Some(values) = line.strip_prefix(b"Gid:") {
            (values, &mut gid)
        } else {
            continue;
        };
        if slot.is_some() {
            return Err(invalid());
        }
        let values: Vec<_> = words(values).map(number).collect::<io::Result<_>>()?;
        if values.len() != 4 || values.iter().any(|v| *v != values[0]) {
            return Err(invalid());
        }
        *slot = Some(u32::try_from(values[0]).map_err(|_| invalid())?);
    }
    Ok(Credentials {
        uid: uid.ok_or_else(invalid)?,
        gid: gid.ok_or_else(invalid)?,
    })
}

/// Check only the supplied mount view. A single unfiltered procfs root is
/// required. Submounts under /proc conservatively refuse, including non-PID
/// paths: a later collector also needs unobscured boot and namespace evidence.
/// This is not proof that the observer is in the initial host namespaces.
pub(crate) fn check_mountinfo(bytes: &[u8]) -> io::Result<()> {
    bounded(bytes)?;
    let mut roots = 0;
    let mut ids = BTreeSet::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let fields: Vec<_> = words(line).collect();
        let separator = fields.iter().position(|f| *f == b"-").ok_or_else(invalid)?;
        if separator < 6 || fields.len() != separator + 4 {
            return Err(invalid());
        }
        if !ids.insert(number(fields[0])?) {
            return Err(invalid());
        }
        number(fields[1])?;
        let mut device = fields[2].split(|b| *b == b':');
        number(device.next().ok_or_else(invalid)?)?;
        number(device.next().ok_or_else(invalid)?)?;
        if device.next().is_some() {
            return Err(invalid());
        }
        let root = mount_path(fields[3])?;
        let mount = mount_path(fields[4])?;
        if mount == b"/proc" {
            roots += 1;
            if root != b"/" || fields[separator + 1] != b"proc" {
                return Err(invalid());
            }
            for option in fields[5]
                .split(|b| *b == b',')
                .chain(fields[separator + 3].split(|b| *b == b','))
            {
                proc_option(option)?;
            }
        } else if mount.starts_with(b"/proc/") {
            return Err(invalid());
        }
    }
    if roots != 1 {
        return Err(invalid());
    }
    Ok(())
}

fn proc_option(option: &[u8]) -> io::Result<()> {
    match option {
        b"rw" | b"ro" | b"nosuid" | b"nodev" | b"noexec" | b"relatime" | b"strictatime"
        | b"noatime" | b"nodiratime" | b"sync" | b"async" | b"dirsync" | b"lazytime"
        | b"hidepid=0" | b"hidepid=off" => Ok(()),
        _ if option.starts_with(b"gid=") => number(&option[4..]).map(|_| ()),
        // Unknown options cannot be treated as proof of an unfiltered view.
        _ => Err(invalid()),
    }
}

/// mountinfo uses the mounts(5) escapes for space, tab, newline and backslash.
/// Decode before classifying a path; malformed/unknown escapes refuse.
fn mount_path(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if !bytes.starts_with(b"/") {
        return Err(invalid());
    }
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let escaped = bytes.get(i + 1..i + 4).ok_or_else(invalid)?;
            result.push(match escaped {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid()),
            });
            i += 4;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    // Kernel mount paths have no empty, dot or parent components. Refuse
    // ambiguous supplied paths instead of normalising away an overmount.
    if result != b"/"
        && result[1..]
            .split(|b| *b == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(invalid());
    }
    Ok(result)
}

fn words(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
}

fn bounded(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES || bytes.contains(&0) {
        return Err(invalid());
    }
    Ok(())
}

fn number(bytes: &[u8]) -> io::Result<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .parse()
        .map_err(|_| invalid())
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported or ambiguous procfs evidence",
    )
}

#[cfg(test)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/upgrade_inventory_procfs.rs"
));
#[cfg(test)]
inventory_procfs_regression_tests!();
