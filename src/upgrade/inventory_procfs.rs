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
    let bad = || invalid("malformed stat identity or fields");
    let open = bytes.iter().position(|b| *b == b'(').ok_or_else(bad)?;
    let close = bytes.iter().rposition(|b| *b == b')').ok_or_else(bad)?;
    if open < 2 || close < open || bytes.get(open - 1) != Some(&b' ') {
        return Err(bad());
    }
    let pid = numeric_id(&bytes[..open - 1])?;
    if pid == 0 || bytes.get(close + 1) != Some(&b' ') {
        return Err(bad());
    }
    let fields: Vec<_> = words(&bytes[close + 2..]).collect();
    let state = fields.first().ok_or_else(bad)?;
    if state.len() != 1 || !b"RSDZTtWXxKPI".contains(&state[0]) {
        return Err(invalid("unknown process state"));
    }
    Ok(ProcessStat {
        pid,
        state: state[0],
        flags: number(fields.get(6).ok_or_else(bad)?)?,
        start_ticks: number(fields.get(19).ok_or_else(bad)?)?,
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
            return Err(invalid("duplicate credential row"));
        }
        let values: Vec<_> = words(values).map(numeric_id).collect::<io::Result<_>>()?;
        if values.len() != 4 || values.iter().any(|v| *v != values[0]) {
            return Err(invalid("mixed or incomplete credential row"));
        }
        *slot = Some(values[0]);
    }
    Ok(Credentials {
        uid: uid.ok_or_else(|| invalid("missing UID row"))?,
        gid: gid.ok_or_else(|| invalid("missing GID row"))?,
    })
}

/// Check only the supplied mount view. A single unfiltered procfs root is
/// required, parented by the sole `/` mount; stacked roots refuse without
/// assuming row order. Proc submounts refuse except systemd's exact binfmt_misc
/// path with autofs/binfmt_misc type, which cannot hide process or boot evidence.
/// Mount and propagation IDs are u64 tokens, not proof of kernel allocation.
/// The binfmt exception checks only path/type, not that subtree's parent/root.
/// This is not proof that the observer is in the initial host namespaces.
pub(crate) fn check_mountinfo(bytes: &[u8]) -> io::Result<()> {
    bounded(bytes)?;
    let mut host_root = None;
    let mut proc_parent = None;
    let mut ids = BTreeSet::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        // Kernel fields use literal spaces; the mount source alone may be empty.
        let fields: Vec<_> = line.split(|b| *b == b' ').collect();
        let bad = || invalid("malformed mountinfo row");
        let sep = fields.iter().position(|f| *f == b"-").ok_or_else(bad)?;
        if sep < 6
            || fields.len() != sep + 4
            || fields
                .iter()
                .enumerate()
                .any(|(i, f)| f.is_empty() && i != sep + 2)
        {
            return Err(bad());
        }
        let id = number(fields[0])?;
        if !ids.insert(id) {
            return Err(invalid("duplicate mount ID"));
        }
        let parent = number(fields[1])?;
        let mut device = fields[2].split(|b| *b == b':');
        number(device.next().ok_or_else(bad)?)?;
        number(device.next().ok_or_else(bad)?)?;
        if device.next().is_some() {
            return Err(bad());
        }
        for field in &fields[6..sep] {
            if *field == b"unbindable" {
                continue;
            }
            let value = [b"shared:".as_slice(), b"master:", b"propagate_from:"]
                .iter()
                .find_map(|tag| field.strip_prefix(*tag))
                .ok_or_else(bad)?;
            if number(value)? == 0 {
                return Err(invalid("zero propagation group ID"));
            }
        }
        let mount = mount_path(fields[4])?;
        if mount == b"/" && host_root.replace(id).is_some() {
            return Err(invalid("stacked host roots"));
        }
        if mount == b"/proc" {
            // Other filesystems may report opaque roots such as net:[inode].
            if proc_parent.replace(parent).is_some()
                || mount_path(fields[3])? != b"/"
                || fields[sep + 1] != b"proc"
            {
                return Err(invalid("duplicate, rebound or non-proc root"));
            }
            for option in fields[5]
                .split(|b| *b == b',')
                .chain(fields[sep + 3].split(|b| *b == b','))
            {
                proc_option(option)?;
            }
        } else if mount.starts_with(b"/proc/")
            && !(mount == b"/proc/sys/fs/binfmt_misc"
                && matches!(fields[sep + 1], b"autofs" | b"binfmt_misc"))
        {
            return Err(invalid("proc submount hides inventory evidence"));
        }
    }
    if host_root.is_none() || proc_parent != host_root {
        return Err(invalid("missing host/proc root or hidden proc parent"));
    }
    Ok(())
}

fn proc_option(option: &[u8]) -> io::Result<()> {
    match option {
        b"rw" | b"ro" | b"nosuid" | b"nodev" | b"noexec" | b"relatime" | b"strictatime"
        | b"noatime" | b"nodiratime" | b"sync" | b"async" | b"dirsync" | b"lazytime"
        | b"nosymfollow" | b"mand" | b"hidepid=0" | b"hidepid=off" => Ok(()),
        _ if option.starts_with(b"gid=") => numeric_id(&option[4..]).map(|_| ()),
        // Known filters and unknown options cannot prove an unfiltered view.
        _ => Err(invalid("filtered or unknown proc mount option")),
    }
}

/// The four octal escapes are described in getmntent(3): space, tab, newline
/// and backslash. mountinfo permits these escapes in mount paths.
/// Decode before classifying a path; malformed/unknown escapes refuse.
fn mount_path(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if !bytes.starts_with(b"/") {
        return Err(invalid("mount point is not absolute"));
    }
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let escaped = bytes
                .get(i + 1..i + 4)
                .ok_or_else(|| invalid("truncated mount escape"))?;
            result.push(match escaped {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid("unknown mount escape")),
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
        return Err(invalid("noncanonical mount path"));
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
        return Err(invalid("empty, oversized or NUL-containing evidence"));
    }
    Ok(())
}

fn number(bytes: &[u8]) -> io::Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("noncanonical unsigned decimal"))?;
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(invalid("noncanonical unsigned decimal"));
    }
    text.parse().map_err(|_| invalid("number exceeds u64"))
}

fn numeric_id(bytes: &[u8]) -> io::Result<u32> {
    match u32::try_from(number(bytes)?) {
        Ok(id) if id != u32::MAX => Ok(id),
        _ => Err(invalid("out-of-range or reserved identity")),
    }
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/upgrade_inventory_procfs.rs"
));
#[cfg(test)]
inventory_procfs_regression_tests!();
