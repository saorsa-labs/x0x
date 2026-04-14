//! CLI parity — every `ENDPOINTS` entry is reachable from the `x0x` binary.
//!
//! The REST/CLI contract is: for every endpoint registered in
//! `src/api/mod.rs::ENDPOINTS`, invoking `x0x <cli_name> --help` must
//! succeed. If a developer adds an endpoint without a matching CLI
//! subcommand, this test fails and names every missing command.
//!
//! Runs `cargo nextest run --test parity_cli` against the binary built by
//! cargo. No daemon is needed — we only exercise clap's argument parser.

use std::collections::BTreeSet;
use std::process::Command;

use x0x::api::ENDPOINTS;

/// Resolve an `EndpointDef::cli_name` into the list of argv invocations
/// we should prove clap accepts.
///
/// Handles the conventions used in `ENDPOINTS`:
/// - `"tasks claim / tasks complete"` → two separate invocations
/// - `"constitution --json"` → keep the flag; clap still parses it
///   against the `constitution` subcommand
fn tokenize_cli_name(cli: &str) -> Vec<Vec<&str>> {
    cli.split(" / ")
        .map(|variant| variant.split_whitespace().collect::<Vec<_>>())
        .filter(|v| !v.is_empty())
        .collect()
}

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_x0x")
}

/// Exercise `x0x <tokens> --help`. Returns `Ok(())` on clap exit 0, else
/// a diagnostic string capturing the failed invocation and stderr.
fn run_cli(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new(bin_path())
        .args(args)
        .output()
        .map_err(|e| format!("failed to spawn {}: {e}", bin_path()))
}

fn probe_help(tokens: &[&str]) -> Result<(), String> {
    let mut args: Vec<&str> = tokens.to_vec();
    args.push("--help");

    let output = run_cli(&args)?;

    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "`x0x {}` failed (status {:?})\nstderr: {}",
        args.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim(),
    ))
}

#[test]
fn every_endpoint_is_reachable_from_cli() {
    let mut failures = Vec::new();
    let mut seen: BTreeSet<Vec<&str>> = BTreeSet::new();

    for ep in ENDPOINTS {
        for tokens in tokenize_cli_name(ep.cli_name) {
            if !seen.insert(tokens.clone()) {
                continue;
            }
            if let Err(msg) = probe_help(&tokens) {
                failures.push(format!(
                    "  {} {} (cli_name: \"{}\"): {}",
                    ep.method, ep.path, ep.cli_name, msg
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "\n\nCLI parity violations — endpoints in ENDPOINTS have no matching \
         `x0x` subcommand ({} failures):\n{}\n\n\
         Fix: add the subcommand to src/bin/x0x.rs or correct the cli_name \
         in src/api/mod.rs::ENDPOINTS.\n",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn group_update_rejects_empty_patch_before_daemon_check() {
    let output = run_cli(&["group", "update", "deadbeef"]).expect("spawn x0x group update");
    assert!(!output.status.success(), "empty group update should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("group update requires at least one of: --name, --description"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn group_policy_rejects_empty_patch_before_daemon_check() {
    let output = run_cli(&["group", "policy", "deadbeef"]).expect("spawn x0x group policy");
    assert!(!output.status.success(), "empty group policy should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "group policy requires at least one of: --preset, --discoverability, --admission, --confidentiality, --read-access, --write-access"
        ),
        "unexpected stderr: {stderr}"
    );
}
