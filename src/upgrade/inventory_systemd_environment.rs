//! Bounded supplied systemd environment-property evidence for ADR 0094 S2c.
//!
//! Decode systemd v255 `busctl --json=short get-property` replies without bus
//! access, file reads, expansion or environment merging. These four properties
//! alone do not establish the effective environment: manager scope, manager
//! variables, environment-file contents, PAM and generated values still matter.
//! Callers must bind each reply to its manager, unit, interface and property.
//! An empty list is data only, not evidence that no job or other source exists.
#![allow(dead_code)] // Dormant until the complete inventory producer is integrated.

use serde::{de::DeserializeOwned, Deserialize};
use std::io;

const MAX_BYTES: usize = 1_048_576;
const MAX_ENTRIES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EnvironmentFile {
    /// Literal manager-side path or glob; not resolved against the unit root.
    pub(crate) path: String,
    /// Preserve the bus boolean; it is not evidence that the file is absent.
    pub(crate) ignore_missing: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EnvironmentProperty {
    Environment(Vec<String>),
    Files(Vec<EnvironmentFile>),
    Pass(Vec<String>),
    Unset(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    #[serde(rename = "type")]
    signature: String,
    // get-property exposes the variant directly, without a call-return wrapper.
    data: Vec<T>,
}

/// Retain source order, duplicate entries and literal bytes. This validates
/// transport shape and bounds, not variable-name syntax, paths or precedence.
/// In particular, an unset name and an unset assignment remain distinct.
pub(crate) fn parse_property(property: &str, bytes: &[u8]) -> io::Result<EnvironmentProperty> {
    if ![
        "Environment",
        "EnvironmentFiles",
        "PassEnvironment",
        "UnsetEnvironment",
    ]
    .contains(&property)
    {
        return Err(refusal("unsupported environment property"));
    }
    if bytes.len() > MAX_BYTES
        || bytes
            .iter()
            .find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            != Some(&b'{')
    {
        return Err(refusal("environment reply is oversized or not an object"));
    }
    if property == "EnvironmentFiles" {
        // dbus-execute.c property_get_environment_files emits (path, optional).
        let rows: Vec<(String, bool)> = decode(bytes, "a(sb)")?;
        let files = rows
            .into_iter()
            .map(|(path, ignore_missing)| {
                valid_string(&path)?;
                Ok(EnvironmentFile {
                    path,
                    ignore_missing,
                })
            })
            .collect::<io::Result<_>>()?;
        return Ok(EnvironmentProperty::Files(files));
    }
    let values: Vec<String> = decode(bytes, "as")?;
    for value in &values {
        valid_string(value)?;
    }
    match property {
        "Environment" => Ok(EnvironmentProperty::Environment(values)),
        "PassEnvironment" => Ok(EnvironmentProperty::Pass(values)),
        "UnsetEnvironment" => Ok(EnvironmentProperty::Unset(values)),
        _ => Err(refusal("unsupported environment property")),
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8], signature: &str) -> io::Result<Vec<T>> {
    let envelope: Envelope<T> = serde_json::from_slice(bytes)
        .map_err(|_| refusal("malformed environment-property reply"))?;
    if envelope.signature != signature || envelope.data.len() > MAX_ENTRIES {
        return Err(refusal(
            "environment signature or entry count is unsupported",
        ));
    }
    Ok(envelope.data)
}

fn valid_string(value: &str) -> io::Result<()> {
    if value.is_empty() || value.contains('\0') {
        return Err(refusal("environment entry is empty or contains NUL"));
    }
    Ok(())
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade/inventory_systemd_environment.rs"
    ));
}
