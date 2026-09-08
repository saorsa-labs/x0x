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

/// Spawn the CLI with `--dump-request` and a fully scratch environment.
///
/// WHY: the three `exec` cases below invoke REAL verbs, not `--help`.
/// Without `--dump-request`, `DaemonClient::ensure_running` (src/cli/mod.rs)
/// short-circuits only in dump mode, so those verbs would perform a real
/// loopback `GET /health` and then their own request against whatever daemon
/// happens to be listening. With it, every verb returns `emit_dump` output
/// and no socket is opened.
///
/// `--dump-request` and `--api` are `global = true` in `src/bin/x0x.rs`, but
/// they are inserted BEFORE the subcommand deliberately: appending them after
/// `exec <agent> -- echo hi` would place them past the `--` boundary and turn
/// them into exec argv, silently disarming the isolation.
///
/// `--api` pins a dummy base URL so `discover_api` never reads a real
/// `api.port`. `X0X_API_TOKEN` is set to a dummy NON-SECRET value rather than
/// removed, because removing it alone still permits the token-file fallback.
/// HOME/X0X_HOME/XDG_DATA_HOME/TMPDIR point at a caller-supplied scratch dir
/// (each test owns one; a test may reuse it across its own invocations), and
/// proxy vars are cleared so nothing can be redirected outward.
fn run_cli_hermetic(scratch: &std::path::Path, tokens: &[&str]) -> std::process::Output {
    let mut args: Vec<&str> = vec!["--dump-request", "--api", "http://127.0.0.1:1"];
    args.extend_from_slice(tokens);
    let scratch_str = scratch.to_string_lossy().to_string();
    let mut cmd = Command::new(bin_path());
    cmd.args(&args)
        .env("HOME", &scratch_str)
        .env("X0X_HOME", &scratch_str)
        .env("XDG_DATA_HOME", &scratch_str)
        .env("TMPDIR", &scratch_str)
        .env("X0X_API_TOKEN", "dummy-not-a-secret")
        .stdin(std::process::Stdio::null());
    for proxy in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ] {
        cmd.env_remove(proxy);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin_path()))
}

/// The single `{"method","path","body"}` line `emit_dump` prints.
fn dumped(out: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{') && l.contains("\"method\""))
        .unwrap_or_else(|| {
            panic!(
                "no request dump on stdout (status {:?})\nstderr: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            )
        });
    serde_json::from_str(line).expect("dump line is JSON")
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
    // The flag is `--new-name` (wire field `name`); the message must name
    // the real flag, not the wire field.
    assert!(
        stderr.contains("group update requires at least one of: --new-name, --description"),
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

    // `sessions` and `cancel <id>` must parse AS SUBCOMMANDS and build the
    // documented request. Asserting the emitted method/path (not merely the
    // absence of a clap usage error) is what proves they dispatched to the
    // right verb rather than failing somewhere earlier for another reason.
    let scratch = tempfile::tempdir().expect("scratch home");
    let out = run_cli_hermetic(scratch.path(), &["exec", "sessions"]);
    let dump = dumped(&out);
    assert_eq!(dump["method"], "GET", "exec sessions: {dump}");
    assert_eq!(dump["path"], "/exec/sessions", "exec sessions: {dump}");

    let out = run_cli_hermetic(scratch.path(), &["exec", "cancel", "req-1"]);
    let dump = dumped(&out);
    assert_eq!(dump["method"], "POST", "exec cancel: {dump}");
    assert_eq!(dump["path"], "/exec/cancel", "exec cancel: {dump}");
    assert_eq!(
        dump["body"]["request_id"], "req-1",
        "the positional id must reach the body: {dump}"
    );
}

#[test]
fn exec_run_form_still_parses_with_flags() {
    let scratch = tempfile::tempdir().expect("scratch home");
    let agent = "a".repeat(64);
    // Run form with `--` argv and a typed `--timeout` flag. The global
    // isolation flags go BEFORE `exec`; after the `--` they would become argv.
    let out = run_cli_hermetic(
        scratch.path(),
        &["exec", &agent, "--timeout", "5", "--", "echo", "hi"],
    );
    let dump = dumped(&out);
    assert_eq!(dump["method"], "POST", "exec run: {dump}");
    assert_eq!(dump["path"], "/exec/run", "exec run: {dump}");
    assert_eq!(dump["body"]["agent_id"], agent.as_str(), "{dump}");
    assert_eq!(
        dump["body"]["argv"],
        serde_json::json!(["echo", "hi"]),
        "argv after `--` must survive verbatim: {dump}"
    );
    assert_eq!(
        dump["body"]["timeout_ms"], 5000,
        "the typed flag must reach the body as milliseconds (exec.rs converts \
         --timeout seconds via saturating_mul(1000)), not fall into argv: {dump}"
    );
}

/// WHY: the isolation must not hide a real validation. `exec` with no argv
/// bails in the CLI (src/cli/commands/exec.rs `argv.is_empty()`) before any
/// request is built, so no dump is emitted even in dump mode — the control
/// that proves the dump above came from dispatch, not from a stub.
#[test]
fn exec_run_without_argv_bails_before_building_a_request() {
    let scratch = tempfile::tempdir().expect("scratch home");
    let agent = "a".repeat(64);
    let out = run_cli_hermetic(scratch.path(), &["exec", &agent]);
    assert!(!out.status.success(), "empty argv must fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("\"path\""),
        "no request may be built when argv is empty: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("usage: x0x exec <agent_id>"),
        "expected the CLI's own usage bail, got: {stderr}"
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
