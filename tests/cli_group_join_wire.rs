#![allow(clippy::expect_used, clippy::panic)]

//! Exact-wire tests for `x0x group join` Home-join mode (#468/#469, A3).
//!
//! WHY: the generic parity suite (`cli_request_parity.rs`) proves every
//! registry FIELD reaches the wire, but not the exact SHAPE — which of
//! the optional fields appear together, and that clap enforces the
//! `--home` ⇄ `--owner` pin pairing BEFORE any request is built. These
//! tests pin the three bodies the server's mode/pin matrix distinguishes
//! (design v4 A3 + v3 review item 3) by driving the real binary with
//! `--dump-request`, the same technique `cli_request_parity.rs` uses.

use std::process::Command;

use serde_json::Value;

/// 64-hex-char stand-in owner user id (a real UserId is 32 bytes hex).
const OWNER_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const INVITE: &str = "x0x://invite/eyJub3RfYS1yZWFsLXRva2VuIjp0cnVlfQ";

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_x0x")
}

/// Run `x0x <args> --dump-request` and return the parsed dump line.
fn dump(args: &[&str]) -> Value {
    let mut argv: Vec<&str> = args.to_vec();
    argv.push("--dump-request");
    let out = Command::new(bin_path())
        .args(&argv)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin_path()));
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find(|l| l.starts_with('{') && l.contains("\"method\""))
        .and_then(|l| serde_json::from_str(l).ok())
        .unwrap_or_else(|| {
            panic!(
                "`x0x {}` produced no request dump (status {:?}): {}",
                argv.join(" "),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            )
        })
}

/// Run `x0x <args>` expecting a clap rejection: nonzero exit whose
/// stderr names the missing argument.
fn assert_clap_rejection(args: &[&str], missing_flag: &str) {
    let out = Command::new(bin_path())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin_path()));
    assert!(
        !out.status.success(),
        "`x0x {}` must fail at argument parsing",
        args.join(" ")
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("required arguments were not provided"),
        "`x0x {}` should be a missing-required-argument error, got: {}",
        args.join(" "),
        stderr.trim()
    );
    assert!(
        stderr.contains(missing_flag),
        "`x0x {}` error must name the missing `{missing_flag}` flag, got: {}",
        args.join(" "),
        stderr.trim()
    );
}

/// `--home --owner <hex>` dumps exactly the Home-join body: invite +
/// literal `"mode":"home"` + the owner pin — nothing else.
#[test]
fn group_join_home_owner_dumps_exact_wire() {
    let dumped = dump(&["group", "join", INVITE, "--home", "--owner", OWNER_HEX]);
    assert_eq!(dumped["method"], "POST");
    assert_eq!(dumped["path"], "/groups/join");
    assert_eq!(
        dumped["body"],
        serde_json::json!({
            "invite": INVITE,
            "mode": "home",
            "expected_owner_user_id": OWNER_HEX,
        }),
        "Home-join body must carry exactly the mode/pin pair (design v4 A3)"
    );
}

/// `--home --owner <hex> --display-name` adds only `display_name`.
#[test]
fn group_join_home_owner_display_name_dumps_exact_wire() {
    let dumped = dump(&[
        "group",
        "join",
        INVITE,
        "--home",
        "--owner",
        OWNER_HEX,
        "--display-name",
        "Alice",
    ]);
    assert_eq!(
        dumped["body"],
        serde_json::json!({
            "invite": INVITE,
            "display_name": "Alice",
            "mode": "home",
            "expected_owner_user_id": OWNER_HEX,
        })
    );
}

/// Plain join omits BOTH new fields — the daemon default (group mode)
/// must stay reachable byte-identically for mixed fleets.
#[test]
fn plain_group_join_omits_mode_and_owner_pin() {
    let dumped = dump(&["group", "join", INVITE]);
    assert_eq!(
        dumped["body"],
        serde_json::json!({ "invite": INVITE }),
        "plain join must not carry mode/expected_owner_user_id/display_name"
    );
}

/// `--home` without `--owner` is rejected by clap before any request is
/// built (a Home join without a pin would hit the server's
/// `home_mode_requires_pin`; refusing client-side is the CLI contract).
#[test]
fn home_join_requires_owner_flag() {
    assert_clap_rejection(&["group", "join", INVITE, "--home"], "--owner");
}

/// `--owner` without `--home` is rejected too: a pin in group mode is
/// meaningless (the server would answer `pin_requires_home_mode`).
#[test]
fn owner_pin_requires_home_flag() {
    assert_clap_rejection(&["group", "join", INVITE, "--owner", OWNER_HEX], "--home");
}
