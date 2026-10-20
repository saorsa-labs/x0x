//! Bounded literal evidence from one supplied systemd source or argument list.
//!
//! This parser does not read files, resolve executable identity, merge unit
//! sources, or establish configured-job absence or complete host inventory.
//! A different executable stays unresolved: even a native helper can start the
//! installed daemon. Callers must independently establish all launch authority.
#![cfg(unix)]
// This private parser remains dormant until complete inventory is integrated.
#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};

const MAX_BYTES: usize = 1_048_576;
const MAX_ARGUMENTS: usize = 4096;
const MAX_COMMANDS: usize = 4096;
// systemd v255 string-util.h WHITESPACE: other Unicode whitespace is data.
const SOURCE_WHITESPACE: [char; 4] = [' ', '\t', '\n', '\r'];
const COMMAND_PROPERTIES: [&str; 7] = [
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiteralCommand {
    pub(crate) executable: PathBuf,
    pub(crate) argv: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceCommand {
    pub(crate) property: String,
    pub(crate) command: LiteralCommand,
}

/// Keep every nonempty command assignment in source order. Empty resets do not
/// erase earlier evidence: this is not an effective-unit or drop-in merger.
/// An empty result says only that this supplied component had no command.
pub(crate) fn parse_source(
    name: &str,
    bytes: &[u8],
    install: &Path,
) -> io::Result<Vec<SourceCommand>> {
    literal_path(install)?;
    if name.len() > MAX_BYTES || name.contains(['\0', '@']) {
        return Err(refusal("configured instance or source name is unresolved"));
    }
    if bytes.len() > MAX_BYTES || bytes.contains(&0) {
        return Err(refusal("configured source exceeds bounds or contains NUL"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| refusal("unit source is not UTF-8"))?;
    let mut section = "";
    let mut commands = Vec::new();
    for line in text
        .lines()
        .map(|line| line.trim_matches(SOURCE_WHITESPACE))
        .filter(|line| !line.is_empty() && !line.starts_with(['#', ';']))
    {
        if line.ends_with('\\') {
            return Err(refusal("configured continuation is unresolved"));
        }
        if line.starts_with('[') {
            if !line.ends_with(']')
                || line.len() <= 2
                || line[1..line.len() - 1].contains(['[', ']'])
            {
                return Err(refusal("ambiguous configured section header"));
            }
            section = line;
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| refusal("ambiguous configured assignment"))?;
        let (key, value) = (
            key.trim_matches(SOURCE_WHITESPACE),
            value.trim_matches(SOURCE_WHITESPACE),
        );
        if section.is_empty()
            || key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(refusal("ambiguous configured property name"));
        }
        if section != "[Service]" {
            continue;
        }
        // Check every service value before classifying commands. In particular,
        // Environment and $$ passed to a shell cannot disappear as nonmembers.
        if value.contains(['$', '%']) {
            return Err(refusal("configured service expansion is unresolved"));
        }
        if key.starts_with("Exec") && !COMMAND_PROPERTIES.contains(&key) {
            return Err(refusal("unknown configured execution property"));
        }
        if !COMMAND_PROPERTIES.contains(&key) || value.is_empty() {
            continue;
        }
        if commands.len() == MAX_COMMANDS {
            return Err(refusal("configured command count exceeds bounds"));
        }
        let argv = words(value)?;
        let executable = argv
            .first()
            .ok_or_else(|| refusal("configured command is empty"))?;
        let command = parse_command(Path::new(executable), &argv, install)?;
        commands.push(SourceCommand {
            property: key.to_owned(),
            command,
        });
    }
    Ok(commands)
}

/// Validate supplied literal arguments without resolving their executable.
/// Exact spelling equality is evidence only; no canonical path or inode claim
/// follows from this check. Bounds count each argument's bytes once, including
/// argv[0], without adding separators or counting the executable a second time.
pub(crate) fn parse_command(
    path: &Path,
    argv: &[String],
    install: &Path,
) -> io::Result<LiteralCommand> {
    literal_path(path)?;
    literal_path(install)?;
    if argv.is_empty()
        || argv.len() > MAX_ARGUMENTS
        || argv
            .first()
            .is_none_or(|argument| std::ffi::OsStr::new(argument.as_str()) != path.as_os_str())
    {
        return Err(refusal("service executable and arguments are inconsistent"));
    }
    let mut bytes = 0usize;
    for argument in argv {
        bytes = bytes
            .checked_add(argument.len())
            .filter(|total| *total <= MAX_BYTES)
            .ok_or_else(|| refusal("service arguments exceed bounds"))?;
        if argument.contains(['\0', '$', '%']) {
            return Err(refusal("service argument expansion is unresolved"));
        }
    }
    // Do not normalize spelling or exclude arbitrary native helper commands.
    // A different literal executable needs independent launch authority.
    if path.as_os_str() != install.as_os_str() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "non-install command has no independently enforced launch authority",
        ));
    }
    Ok(LiteralCommand {
        executable: path.to_path_buf(),
        argv: argv.to_vec(),
    })
}

fn literal_path(path: &Path) -> io::Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| refusal("service executable is not UTF-8"))?;
    if !path.is_absolute() || text.len() > MAX_BYTES || text.contains(['\0', '$', '%']) {
        return Err(refusal("service executable spelling is unresolved"));
    }
    Ok(())
}

fn words(text: &str) -> io::Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    for character in text.chars() {
        // Accept only a bounded literal subset, without interpreting escapes or
        // systemd's compound-command syntax, even inside quoted words.
        if matches!(character, '\\' | ';') {
            return Err(refusal("escaped or compound service syntax is unsupported"));
        }
        if Some(character) == quote {
            quote = None;
            started = true;
        } else if quote.is_none() && (character == '\'' || character == '"') {
            quote = Some(character);
            started = true;
        } else if quote.is_none() && SOURCE_WHITESPACE.contains(&character) {
            if started {
                push_word(&mut words, std::mem::take(&mut word))?;
                started = false;
            }
        } else {
            word.push(character);
            started = true;
        }
    }
    if quote.is_some() {
        return Err(refusal("unterminated configured service quote"));
    }
    if started {
        push_word(&mut words, word)?;
    }
    Ok(words)
}

fn push_word(words: &mut Vec<String>, word: String) -> io::Result<()> {
    if words.len() == MAX_ARGUMENTS {
        return Err(refusal("configured argument count exceeds bounds"));
    }
    words.push(word);
    Ok(())
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/upgrade_inventory_commands.rs"
));
#[cfg(test)]
inventory_commands_regression_tests!();
