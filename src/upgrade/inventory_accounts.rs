//! Parse supplied Unix account records under a strictly files-only NSS policy.
//!
//! This dormant component performs no I/O or NSS lookup. A valid table binds
//! the supplied bytes; it does not prove their provenance, freshness or complete
//! host inventory. Source capture and launch authority remain separate work.
#![cfg(unix)]
#![allow(dead_code)] // Private parser; inventory activation is not part of this slice.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::{fmt, io};

use sha2::{Digest, Sha256};

const MAX_INPUT: u64 = 1024 * 1024;
const MAX_MEMBERS: usize = 4096;
// glibc parses NSS policy bytewise with isspace. Support the C whitespace
// subset and refuse non-ASCII policy tokens instead of normalizing authority.
const POLICY_WHITESPACE: [char; 6] = [' ', '\t', '\n', '\r', '\x0b', '\x0c'];

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Account {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AccountTable {
    users: BTreeMap<String, Account>,
    groups: BTreeMap<String, u32>,
    pub digest: [u8; 32],
}

// Inventory diagnostics must not disclose account records or their digest.
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Account(<redacted>)")
    }
}

impl fmt::Debug for AccountTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountTable(<redacted>)")
    }
}

impl AccountTable {
    pub(crate) fn parse(policy: &[u8], passwd: &[u8], group: &[u8]) -> io::Result<Self> {
        let policy = input(policy)?;
        let passwd_text = input(passwd)?;
        let group_text = input(group)?;
        let mut databases = BTreeSet::new();
        for line in policy.lines() {
            let line = line.split('#').next().unwrap_or("");
            if !line.is_ascii() {
                return Err(refusal("non-ASCII NSS policy authority is unsupported"));
            }
            let line = line.trim_matches(POLICY_WHITESPACE);
            if line.is_empty() {
                continue;
            }
            if line.contains('\\') {
                return Err(refusal("continued NSS policy is unsupported"));
            }
            let (database, sources) = line
                .split_once(':')
                .ok_or_else(|| refusal("invalid NSS policy row"))?;
            let database = database.trim_matches(POLICY_WHITESPACE);
            if ["passwd", "group", "initgroups"].contains(&database) {
                if !databases.insert(database)
                    || sources
                        .split(POLICY_WHITESPACE)
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        != ["files"]
                {
                    return Err(refusal("account authority is not exclusively files"));
                }
            } else if database.starts_with("passwd")
                || database.starts_with("group")
                || database.starts_with("initgroups")
            {
                return Err(refusal("alternate account policy is unsupported"));
            }
        }
        if !databases.contains("passwd") || !databases.contains("group") {
            return Err(refusal("files-only account policy is incomplete"));
        }
        let mut users = BTreeMap::new();
        let mut uids = BTreeSet::new();
        for line in rows(passwd_text) {
            let row: Vec<_> = line.split(':').collect();
            if row.len() != 7 || !valid_name(row[0]) {
                return Err(refusal("invalid files account row"));
            }
            let uid = numeric_id(row[2])?;
            let gid = numeric_id(row[3])?;
            let home = PathBuf::from(row[5]);
            if !home.is_absolute() || !uids.insert(uid) || users.len() >= MAX_MEMBERS {
                return Err(refusal("ambiguous or excessive files account table"));
            }
            if users
                .insert(row[0].to_owned(), Account { uid, gid, home })
                .is_some()
            {
                return Err(refusal("duplicate files account name"));
            }
        }
        let mut groups = BTreeMap::new();
        let mut gids = BTreeSet::new();
        for line in rows(group_text) {
            let row: Vec<_> = line.split(':').collect();
            if row.len() != 4 || !valid_name(row[0]) {
                return Err(refusal("invalid files group row"));
            }
            let gid = numeric_id(row[2])?;
            if !gids.insert(gid) || groups.len() >= MAX_MEMBERS {
                return Err(refusal("ambiguous or excessive files group table"));
            }
            if !row[3].is_empty() && row[3].split(',').any(|name| !users.contains_key(name)) {
                return Err(refusal("files group contains an unknown account"));
            }
            if groups.insert(row[0].to_owned(), gid).is_some() {
                return Err(refusal("duplicate files group name"));
            }
        }
        if !users.values().any(|user| user.uid == 0 && user.gid == 0)
            || !gids.contains(&0)
            || users.values().any(|user| !gids.contains(&user.gid))
        {
            return Err(refusal("files account authority has unresolved IDs"));
        }
        // Length-delimited serialization binds all exact input bytes, including
        // ignored fields, without retaining password fields or account secrets.
        let digest = Sha256::digest(
            serde_json::to_vec(&(policy.as_bytes(), passwd, group)).map_err(refusal)?,
        )
        .into();
        Ok(Self {
            users,
            groups,
            digest,
        })
    }

    pub(crate) fn by_uid(&self, uid: u32) -> io::Result<&Account> {
        self.users
            .values()
            .find(|user| user.uid == uid)
            .ok_or_else(|| refusal("UID is absent from the bound account table"))
    }

    pub(crate) fn uids(&self) -> impl Iterator<Item = u32> + '_ {
        self.users.values().map(|user| user.uid)
    }

    pub(crate) fn resolve_user(&self, name: &str, default_uid: u32) -> io::Result<&Account> {
        if name.is_empty() {
            self.by_uid(default_uid)
        } else if name.bytes().all(|byte| byte.is_ascii_digit()) {
            self.by_uid(numeric_id(name)?)
        } else {
            self.users
                .get(name)
                .ok_or_else(|| refusal("user is absent from the bound account table"))
        }
    }

    pub(crate) fn resolve_group(&self, name: &str, default_gid: u32) -> io::Result<u32> {
        let gid = if name.is_empty() {
            default_gid
        } else if name.bytes().all(|byte| byte.is_ascii_digit()) {
            numeric_id(name)?
        } else {
            return self
                .groups
                .get(name)
                .copied()
                .ok_or_else(|| refusal("group is absent from the bound account table"));
        };
        if !self.groups.values().any(|value| *value == gid) {
            return Err(refusal("GID is absent from the bound account table"));
        }
        Ok(gid)
    }
}

fn input(bytes: &[u8]) -> io::Result<&str> {
    if bytes.len() as u64 > MAX_INPUT || bytes.contains(&0) {
        return Err(refusal("account source exceeds bounds or contains NUL"));
    }
    std::str::from_utf8(bytes).map_err(|_| refusal("account source is not UTF-8"))
}
fn rows(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['+', '-'])
        && name.bytes().any(|byte| !byte.is_ascii_digit())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.$".contains(&byte))
}
fn numeric_id(value: &str) -> io::Result<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refusal("invalid account numeric ID"));
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value != u32::MAX)
        .ok_or_else(|| refusal("account numeric ID is out of range"))
}

fn refusal(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/upgrade_inventory_accounts.rs"
));
#[cfg(test)]
inventory_accounts_regression_tests!();
