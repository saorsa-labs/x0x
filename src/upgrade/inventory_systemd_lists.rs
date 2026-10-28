//! Bounded, supplied systemd method replies for the dormant ADR 0094 inventory.
//!
//! The wire shapes follow systemd v255's Manager interface and busctl's
//! json_transform_message: `data` contains one method argument (the row array).
//! Keep every unit type and state, in source order. These are candidate names,
//! not executable membership, effective configuration, or completeness proof.
//! A collector must independently establish manager scope/visibility, collect
//! both lists and configuration sources, resolve launch authority, and recheck.
//! No manager commands, filesystem access, or production callers live here.
#![cfg(unix)]
#![allow(dead_code)]

use serde::{de::DeserializeOwned, Deserialize};
use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply<T> {
    #[serde(rename = "type")]
    signature: String,
    data: [Vec<T>; 1],
}

/// All ten fields of ListUnits, including aliases and queued-job information.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct LoadedUnit {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub following: String,
    pub object: String,
    pub job_id: u32,
    pub job_type: String,
    pub job_object: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct UnitFile {
    /// Supplied absolute spelling only; never canonicalized or opened here.
    pub path: PathBuf,
    pub state: String,
}

pub(super) fn loaded(bytes: &[u8]) -> io::Result<Vec<LoadedUnit>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        u32,
        String,
        String,
    );
    let rows: Vec<Row> = decode(bytes, "a(ssssssouso)")?;
    let mut names = BTreeSet::new();
    let mut result = Vec::with_capacity(rows.len());
    for (
        name,
        description,
        load_state,
        active_state,
        sub_state,
        following,
        object,
        job_id,
        job_type,
        job_object,
    ) in rows
    {
        for value in [
            &name,
            &description,
            &load_state,
            &active_state,
            &sub_state,
            &following,
            &object,
            &job_type,
            &job_object,
        ] {
            text(value)?;
        }
        unit_name(&name)?;
        if !following.is_empty() {
            unit_name(&following)?;
        }
        object_path(&object)?;
        object_path(&job_object)?;
        if !names.insert(name.clone()) {
            return Err(refusal("duplicate loaded unit name"));
        }
        result.push(LoadedUnit {
            name,
            description,
            load_state,
            active_state,
            sub_state,
            following,
            object,
            job_id,
            job_type,
            job_object,
        });
    }
    Ok(result)
}

pub(super) fn configured(bytes: &[u8]) -> io::Result<Vec<UnitFile>> {
    let rows: Vec<(String, String)> = decode(bytes, "a(ss)")?;
    let mut names = BTreeSet::new();
    let mut result = Vec::with_capacity(rows.len());
    for (path, state) in rows {
        text(&path)?;
        text(&state)?;
        // Refuse ambiguous spellings rather than normalize away evidence.
        if !path.starts_with('/')
            || path[1..]
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(refusal("configured unit path is unresolved"));
        }
        let name = path
            .rsplit('/')
            .next()
            .ok_or_else(|| refusal("missing unit name"))?;
        unit_name(name)?;
        // Do not let map insertion silently discard a second source path.
        if !names.insert(name.to_owned()) {
            return Err(refusal("duplicate configured unit name"));
        }
        result.push(UnitFile {
            path: path.into(),
            state,
        });
    }
    Ok(result)
}

fn decode<T: DeserializeOwned>(bytes: &[u8], signature: &str) -> io::Result<Vec<T>> {
    if bytes.len() > MAX_BYTES {
        return Err(refusal("manager reply exceeds byte bound"));
    }
    if bytes.iter().find(|byte| !b" \t\r\n".contains(byte)) != Some(&b'{') {
        return Err(refusal("manager reply is not an object"));
    }
    // Typed deserialization rejects missing/duplicate envelope fields, wrong
    // tuple arity/types, extra method arguments and trailing JSON. Preserve
    // serde_json's default recursion bound and never echo parser/input text.
    let reply: Reply<T> = serde_json::from_slice(bytes)
        .map_err(|_| refusal("manager reply has an invalid structure"))?;
    let [rows] = reply.data;
    if reply.signature != signature || rows.len() > MAX_ROWS {
        return Err(refusal("manager reply signature or row bound is invalid"));
    }
    Ok(rows)
}

fn text(value: &str) -> io::Result<()> {
    if value.contains('\0') {
        return Err(refusal("manager string contains NUL"));
    }
    Ok(())
}

fn unit_name(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.contains('/')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(refusal("unit name is unresolved"));
    }
    Ok(())
}

fn object_path(value: &str) -> io::Result<()> {
    if value != "/"
        && (!value.starts_with('/')
            || value[1..].split('/').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            }))
    {
        return Err(refusal("manager object path is invalid"));
    }
    Ok(())
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/upgrade/inventory_systemd_lists.rs"
));
