//! Bounded evidence from one supplied systemd execution-property JSON reply.
//!
//! This decodes `busctl --json=short get-property` for the seven Service Exec
//! properties and their Ex forms (systemd v255). It does not read the bus, run
//! commands, expand arguments, resolve executable identity or establish launch
//! authority. An empty property grants no absence or complete-host authority.
//! Callers must bind the supplied property to the queried manager, unit and
//! interface separately.
#![cfg(unix)]
#![allow(dead_code)]

use serde::{de::DeserializeOwned, Deserialize};
use std::fmt;
use std::io;

const MAX_BYTES: usize = 1_048_576;
const MAX_COMMANDS: usize = 4096;
const MAX_ARGUMENTS: usize = 4096;
const MAX_FLAGS: usize = 64;
const LEGACY_SIGNATURE: &str = "a(sasbttttuii)";
const EXTENDED_SIGNATURE: &str = "a(sasasttttuii)";
const PROPERTIES: [&str; 7] = [
    "ExecCondition",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];

#[derive(Eq, PartialEq)]
pub(crate) enum ExecutionFlags {
    /// The legacy property omits all flags other than ignore-failure. It must
    /// never be interpreted as evidence that other launch flags are absent.
    LegacyIgnoreFailure(bool),
    /// Preserve every flag, including unknown ones, in source order. This is
    /// raw evidence, not a classification of supported or safe launch options.
    Extended(Vec<String>),
}

#[derive(Eq, PartialEq)]
pub(crate) struct ExecutionCommand {
    pub(crate) executable: String,
    pub(crate) argv: Vec<String>,
    pub(crate) flags: ExecutionFlags,
    pub(crate) start_realtime_usec: u64,
    pub(crate) start_monotonic_usec: u64,
    pub(crate) exit_realtime_usec: u64,
    pub(crate) exit_monotonic_usec: u64,
    pub(crate) pid: u32,
    pub(crate) code: i32,
    pub(crate) status: i32,
}

#[derive(Eq, PartialEq)]
pub(crate) struct ExecutionProperty {
    pub(crate) property: String,
    pub(crate) commands: Vec<ExecutionCommand>,
}

// Executable paths, argv and launch flags are host-private inventory.
impl fmt::Debug for ExecutionFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutionFlags(<redacted>)")
    }
}

impl fmt::Debug for ExecutionCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutionCommand(<redacted>)")
    }
}

impl fmt::Debug for ExecutionProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutionProperty(<redacted>)")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    #[serde(rename = "type")]
    signature: String,
    // get-property decodes one variant directly. Unlike `busctl call`, there
    // is no outer array containing the message's return arguments.
    data: Vec<T>,
}

// dbus-execute.c append_exec_command / append_exec_ex_command, systemd v255.
#[derive(Deserialize)]
struct RawCommand<F>(String, Vec<String>, F, u64, u64, u64, u64, u32, i32, i32);

/// Decode the entire supplied reply or refuse it. Never discard helper paths,
/// duplicate commands, historical results, alternate argv[0], or expansions.
/// None of these raw fields grants participant membership or restart authority.
pub(crate) fn parse_property(property: &str, bytes: &[u8]) -> io::Result<ExecutionProperty> {
    let (base, extended) = property
        .strip_suffix("Ex")
        .map_or((property, false), |base| (base, true));
    if !PROPERTIES.contains(&base) {
        return Err(refusal("unsupported execution property"));
    }
    if bytes.len() > MAX_BYTES
        || bytes.iter().find(|byte| !b" \t\r\n".contains(byte)) != Some(&b'{')
    {
        return Err(refusal("execution reply is oversized or not an object"));
    }
    let commands = if extended {
        decode(bytes, EXTENDED_SIGNATURE, ExecutionFlags::Extended)?
    } else {
        decode(bytes, LEGACY_SIGNATURE, ExecutionFlags::LegacyIgnoreFailure)?
    };
    Ok(ExecutionProperty {
        property: property.to_owned(),
        commands,
    })
}

fn decode<F: DeserializeOwned>(
    bytes: &[u8],
    signature: &str,
    flags: impl Fn(F) -> ExecutionFlags,
) -> io::Result<Vec<ExecutionCommand>> {
    let envelope: Envelope<RawCommand<F>> =
        serde_json::from_slice(bytes).map_err(|_| refusal("malformed execution-property reply"))?;
    if envelope.signature != signature || envelope.data.len() > MAX_COMMANDS {
        return Err(refusal(
            "execution signature or command count is unsupported",
        ));
    }
    envelope
        .data
        .into_iter()
        .map(
            |RawCommand(
                path,
                argv,
                raw_flags,
                start_r,
                start_m,
                exit_r,
                exit_m,
                pid,
                code,
                status,
            )| {
                let flags = flags(raw_flags);
                if path.is_empty()
                    || path.contains('\0')
                    || argv.is_empty()
                    || argv.len() > MAX_ARGUMENTS
                    || argv.iter().any(|arg| arg.contains('\0'))
                {
                    return Err(refusal("execution path or arguments are invalid"));
                }
                if let ExecutionFlags::Extended(values) = &flags {
                    if values.len() > MAX_FLAGS
                        || values
                            .iter()
                            .any(|flag| flag.is_empty() || flag.contains('\0'))
                    {
                        return Err(refusal("execution flags are invalid"));
                    }
                }
                Ok(ExecutionCommand {
                    executable: path,
                    argv,
                    flags,
                    start_realtime_usec: start_r,
                    start_monotonic_usec: start_m,
                    exit_realtime_usec: exit_r,
                    exit_monotonic_usec: exit_m,
                    pid,
                    code,
                    status,
                })
            },
        )
        .collect()
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade/inventory_systemd_exec.rs"
    ));
}
