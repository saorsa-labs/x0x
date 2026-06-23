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
fn group_delete_primary_and_state_withdraw_alias_parse() {
    let delete_help =
        run_cli(&["group", "delete", "--help"]).expect("spawn x0x group delete --help");
    assert!(
        delete_help.status.success(),
        "group delete --help should parse"
    );

    let alias_help = run_cli(&["group", "state-withdraw", "--help"])
        .expect("spawn x0x group state-withdraw --help");
    assert!(
        alias_help.status.success(),
        "hidden state-withdraw alias should remain parseable"
    );
}

#[test]
fn group_set_role_help_lists_only_assignable_roles() {
    let help = run_cli(&["group", "set-role", "--help"]).expect("spawn x0x group set-role --help");
    assert!(help.status.success(), "group set-role --help should parse");
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(
        text.contains("admin   Full group control: membership, policy, rekey, and delete."),
        "set-role help must explain admin semantics:\n{text}"
    );
    assert!(
        text.contains("member  Group participant."),
        "set-role help must explain member semantics:\n{text}"
    );
    assert!(
        text.contains(
            "Legacy owner entries render/read as admin-equivalent but cannot be assigned."
        ),
        "set-role help must preserve legacy owner readability without assignability:\n{text}"
    );
    assert!(
        !text.contains("moderator") && !text.contains("guest"),
        "set-role help must not list reserved roles as assignable:\n{text}"
    );
}

/// `x0x exec` exposes `sessions` and `cancel` as real, discoverable
/// subcommands (not magic first-positional sentinels), while the
/// `x0x exec <agent> -- <argv>` run form still parses. These assert the
/// documented invocation shapes keep working after the clap restructure.
#[test]
fn exec_sub_actions_are_discoverable_subcommands() {
    let help = run_cli(&["exec", "--help"]).expect("spawn x0x exec --help");
    assert!(help.status.success(), "exec --help should succeed");
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(
        text.contains("sessions") && text.contains("cancel"),
        "exec --help must list the sessions/cancel subcommands:\n{text}"
    );

    // `sessions` and `cancel <id>` must parse (they fail later only because no
    // daemon is running, never with a clap usage error).
    for args in [vec!["exec", "sessions"], vec!["exec", "cancel", "req-1"]] {
        let out = run_cli(&args).expect("spawn x0x exec sub-action");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("Usage:") && !stderr.contains("unexpected argument"),
            "`x0x {}` should parse as a subcommand, got clap error:\n{stderr}",
            args.join(" ")
        );
    }
}

#[test]
fn exec_run_form_still_parses_with_flags() {
    let agent = "a".repeat(64);
    // run form with `--` argv and a typed `--timeout` flag must parse.
    let out = run_cli(&["exec", &agent, "--timeout", "5", "--", "echo", "hi"])
        .expect("spawn x0x exec run form");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Usage:") && !stderr.contains("unexpected argument"),
        "exec run form with --timeout should parse, got clap error:\n{stderr}"
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
