//! Bounded parsing of supplied Linux process launch bytes (ADR 0094 section 2).
//!
//! This dormant module performs no I/O or ambient environment lookup. Parsing
//! cannot establish source completeness, process identity, freshness or roots.
//! Proc cmdline is process-mutable; environ need not reflect later mutations.
//! Collection and independent reconciliation must precede any admission.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;

const MAX_BYTES: usize = 1_048_576;
const MAX_ENTRIES: usize = 16_384;
const ROOT_KEYS: [&str; 4] = ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "X0X_HOME"];

/// Parse the normal proc_pid_cmdline(5) NUL-terminated layout. Keep argument
/// boundaries, empty non-leading arguments and all UTF-8 data verbatim.
/// Empty argv[0] and non-UTF-8 argv are unsupported, as this producer must
/// reconstruct the daemon's string-based launch context. argv[0] is not proof
/// of executable identity, even if it looks like an absolute path.
pub(crate) fn parse_cmdline(bytes: &[u8]) -> io::Result<Vec<String>> {
    let entries = records(bytes, true)?;
    if entries.first().is_none_or(|entry| entry.is_empty()) {
        return Err(refusal("missing process argv[0]"));
    }
    entries
        .into_iter()
        .map(|entry| {
            std::str::from_utf8(entry)
                .map(str::to_owned)
                .map_err(|_| refusal("process argument is not UTF-8"))
        })
        .collect()
}

/// Select only root-relevant entries from supplied proc_pid_environ(5) bytes.
/// A final NUL is optional in this format: only a collector can prove EOF.
/// Empty input means no supplied entries, never permission to use local HOME.
/// Preserve empty/relative values; a later root resolver must interpret them.
/// Ignore unrelated entries without decoding their potentially sensitive data.
pub(crate) fn parse_root_environment(bytes: &[u8]) -> io::Result<BTreeMap<String, String>> {
    let mut output = BTreeMap::new();
    for entry in records(bytes, false)? {
        let separator = entry.iter().position(|byte| *byte == b'=');
        let key = match separator {
            Some(index) => &entry[..index],
            None => entry,
        };
        let Some(name) = ROOT_KEYS.iter().find(|name| name.as_bytes() == key) else {
            continue;
        };
        let separator = separator.ok_or_else(|| refusal("root environment entry lacks equals"))?;
        let value = std::str::from_utf8(&entry[separator + 1..])
            .map_err(|_| refusal("root environment value is not UTF-8"))?;
        if output
            .insert((*name).to_owned(), value.to_owned())
            .is_some()
        {
            return Err(refusal("duplicate root environment key"));
        }
    }
    Ok(output)
}

fn records(bytes: &[u8], require_terminator: bool) -> io::Result<Vec<&[u8]>> {
    if bytes.len() > MAX_BYTES {
        return Err(refusal("process launch input exceeds byte bound"));
    }
    if require_terminator && bytes.last() != Some(&0) {
        return Err(refusal("process argv lacks final NUL"));
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    // Remove exactly one framing NUL. Further empty records are data, not
    // padding; in argv they must survive, and all records count toward the cap.
    let data = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let entries: Vec<_> = data
        .split(|byte| *byte == 0)
        .take(MAX_ENTRIES + 1)
        .collect();
    if entries.len() > MAX_ENTRIES {
        return Err(refusal("process launch input exceeds entry bound"));
    }
    Ok(entries)
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/upgrade_inventory_argv.rs"
));
#[cfg(test)]
inventory_argv_regression_tests!();
