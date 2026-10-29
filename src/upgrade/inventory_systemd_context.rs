//! Supplied systemd v255 execution-context properties for dormant inventory.
//!
//! Decode one Service `busctl --json=short get-property` reply. The collector
//! must bind it to its manager, unit, interface and property. These values do
//! not establish effective accounts, roots, environment or launch authority.
//! Empty strings, special working-directory spellings and unresolved paths
//! remain literal evidence. Boolean properties are the manager's projection,
//! not proof of which setting was explicitly configured. No I/O or caller here.
#![cfg(unix)]
#![allow(dead_code)]

use serde::{de::DeserializeOwned, Deserialize};
use std::{fmt, io};

const MAX_BYTES: usize = 1_048_576;
const MAX_ENTRIES: usize = 4096;

#[derive(PartialEq, Eq)]
pub(crate) enum ContextProperty {
    User(String),
    Group(String),
    WorkingDirectory(String),
    RootDirectory(String),
    RootImage(String),
    PamName(String),
    DynamicUser(bool),
    PrivateUsers(bool),
    SetLoginEnvironment(bool),
    SupplementaryGroups(Vec<String>),
    ExecSearchPath(Vec<String>),
}

// Account/path strings can contain private host information. Debug deliberately
// reports only the property name, including when nested in a future receipt.
impl fmt::Debug for ContextProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User(_) => "User(<redacted>)",
            Self::Group(_) => "Group(<redacted>)",
            Self::WorkingDirectory(_) => "WorkingDirectory(<redacted>)",
            Self::RootDirectory(_) => "RootDirectory(<redacted>)",
            Self::RootImage(_) => "RootImage(<redacted>)",
            Self::PamName(_) => "PAMName(<redacted>)",
            Self::DynamicUser(_) => "DynamicUser(<redacted>)",
            Self::PrivateUsers(_) => "PrivateUsers(<redacted>)",
            Self::SetLoginEnvironment(_) => "SetLoginEnvironment(<redacted>)",
            Self::SupplementaryGroups(_) => "SupplementaryGroups(<redacted>)",
            Self::ExecSearchPath(_) => "ExecSearchPath(<redacted>)",
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    #[serde(rename = "type")]
    signature: String,
    // get-property exposes the variant itself, without a method-return array.
    data: T,
}

pub(crate) fn parse_property(property: &str, bytes: &[u8]) -> io::Result<ContextProperty> {
    if bytes.len() > MAX_BYTES
        || bytes.iter().find(|byte| !b" \t\r\n".contains(byte)) != Some(&b'{')
    {
        return Err(refusal());
    }
    Ok(match property {
        "User" => ContextProperty::User(text(bytes)?),
        "Group" => ContextProperty::Group(text(bytes)?),
        "WorkingDirectory" => ContextProperty::WorkingDirectory(text(bytes)?),
        "RootDirectory" => ContextProperty::RootDirectory(text(bytes)?),
        "RootImage" => ContextProperty::RootImage(text(bytes)?),
        "PAMName" => ContextProperty::PamName(text(bytes)?),
        "DynamicUser" => ContextProperty::DynamicUser(decode(bytes, "b")?),
        "PrivateUsers" => ContextProperty::PrivateUsers(decode(bytes, "b")?),
        "SetLoginEnvironment" => ContextProperty::SetLoginEnvironment(decode(bytes, "b")?),
        "SupplementaryGroups" => ContextProperty::SupplementaryGroups(strings(bytes)?),
        "ExecSearchPath" => ContextProperty::ExecSearchPath(strings(bytes)?),
        _ => return Err(refusal()),
    })
}

fn decode<T: DeserializeOwned>(bytes: &[u8], signature: &str) -> io::Result<T> {
    let envelope: Envelope<T> = serde_json::from_slice(bytes).map_err(|_| refusal())?;
    if envelope.signature != signature {
        return Err(refusal());
    }
    Ok(envelope.data)
}

fn text(bytes: &[u8]) -> io::Result<String> {
    let value: String = decode(bytes, "s")?;
    if value.contains('\0') {
        return Err(refusal());
    }
    Ok(value)
}

fn strings(bytes: &[u8]) -> io::Result<Vec<String>> {
    let values: Vec<String> = decode(bytes, "as")?;
    if values.len() > MAX_ENTRIES
        || values
            .iter()
            .any(|value| value.is_empty() || value.contains('\0'))
    {
        return Err(refusal());
    }
    // Preserve order and duplicates: especially, search path order matters.
    Ok(values)
}

fn refusal() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid execution-context reply",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade/inventory_systemd_context.rs"
    ));
}
