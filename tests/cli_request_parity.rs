#![allow(clippy::expect_used, clippy::panic)]

//! CLI request-field parity — argument-level, not just token-level.
//!
//! WHY: the CLI is the only non-Rust integration surface besides raw HTTP;
//! a request-struct field the CLI does not expose is a hidden capability.
//! `parity_cli::every_endpoint_is_reachable_from_cli` proves a subcommand
//! token path exists; these tests prove the subcommand accepts every
//! request field the daemon's handler struct defines.
//!
//! Three artifacts are locked together:
//! 1. the daemon's request structs (source-parsed from `src/server/**`,
//!    the same technique `api_coverage::route_set_matches_registry` uses),
//! 2. the registry's `RequestSpec` metadata in `src/api/mod.rs`,
//! 3. the `x0x <cli_name> --help` surface the user actually sees.
//!
//! Any drift between two of the three fails with a diff naming the field.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::LazyLock;

use x0x::api::{CliExpose, EndpointDef, FieldLocation, RequestSpec, ENDPOINTS};

// ─── CLI help-surface probing ───────────────────────────────────────────

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_x0x")
}
/// Resolve an `EndpointDef::cli_name` into argv invocations (handles the
/// `"tasks claim / tasks complete"` and `"constitution --json"`
/// conventions; mirrors `parity_cli::tokenize_cli_name`).
fn tokenize_cli_name(cli: &str) -> Vec<Vec<String>> {
    cli.split(" / ")
        .map(|variant| {
            variant
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .collect()
}

/// Cached `--help` output for an endpoint's CLI command, if it parses.
fn help_for(method: &str, path: &str) -> Option<String> {
    let ep = ENDPOINTS
        .iter()
        .find(|e| e.method.to_string().to_uppercase() == method && e.path == path)?;
    tokenize_cli_name(ep.cli_name)
        .into_iter()
        .next()
        .map(|tokens| cached_help(&tokens))
}

fn cached_help(tokens: &[String]) -> String {
    static HELPS: LazyLock<BTreeMap<Vec<String>, String>> = LazyLock::new(|| {
        let mut m: BTreeMap<Vec<String>, String> = BTreeMap::new();
        for ep in ENDPOINTS {
            for tokens in tokenize_cli_name(ep.cli_name) {
                if m.contains_key(&tokens) {
                    continue;
                }
                let mut args = tokens.clone();
                args.push("--help".to_string());
                let out = Command::new(bin_path())
                    .args(&args)
                    .output()
                    .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin_path()));
                assert!(
                    out.status.success(),
                    "`x0x {} --help` failed: {}",
                    tokens.join(" "),
                    String::from_utf8_lossy(&out.stderr)
                );
                m.insert(tokens, String::from_utf8_lossy(&out.stdout).to_string());
            }
        }
        m
    });
    HELPS.get(tokens).cloned().unwrap_or_else(|| {
        panic!(
            "no cached help for `x0x {}` (registry drift?)",
            tokens.join(" ")
        )
    })
}

fn kebab(name: &str) -> String {
    name.replace('_', "-")
}

/// Normalize a bracketed positional value name (`<AGENT_ID>`, `[QUERY]`)
/// to the field-name spelling (`agent_id`).
fn normalize_positional(inner: &str) -> String {
    inner
        .trim()
        .trim_matches(|c| c == '<' || c == '>' || c == '[' || c == ']')
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
}

/// The structural CLI surface parsed from `--help`, immune to
/// description-text false positives (review r2, finding 2): a flag counts
/// only when it is the leading token of an option line, a positional only
/// when it appears in the Arguments section or the Usage line.
#[derive(Debug, Default)]
struct HelpSurface {
    /// Exact flag spellings, e.g. `--payload-b64`, `-h`.
    flags: BTreeSet<String>,
    /// Flags that take a value (`--flag <VAL>`), i.e. can express
    /// non-default values including an explicit `false`.
    value_flags: BTreeSet<String>,
    /// Positional value names normalized (`<AGENT_ID>` -> `agent_id`).
    positionals: BTreeSet<String>,
    /// The raw Usage line (requiredness evidence: required options appear
    /// unbracketed there; required positionals as `<X>` not `[X]`).
    usage_raw: String,
    /// flag -> its `<VAL>` placeholder spelling (dummy-value heuristics).
    flag_placeholders: BTreeMap<String, String>,
    /// flag -> first clap `possible value` when the arg has fixed choices.
    flag_choices: BTreeMap<String, String>,
    /// Positional value names in usage order, with bracketing preserved
    /// (`<NAME>` required, `[NAME]` optional).
    ordered_positionals: Vec<String>,
}

fn is_value_token(tok: &str) -> bool {
    (tok.starts_with('<') && tok.ends_with('>') && tok.len() > 2)
        || (tok.starts_with('[') && tok.ends_with(']') && tok.len() > 2)
}

fn parse_help_surface(help: &str) -> HelpSurface {
    let mut out = HelpSurface::default();
    let mut in_arguments_section = false;
    for line in help.lines() {
        let trimmed = line.trim();
        if trimmed == "Arguments:" {
            in_arguments_section = true;
            continue;
        }
        if trimmed == "Options:" || trimmed == "Commands:" {
            in_arguments_section = false;
        }
        if trimmed.starts_with("Usage:") {
            out.usage_raw = trimmed.to_string();
            let mut prev_was_flag = false;
            for tok in trimmed.split_whitespace().skip(1) {
                if tok.starts_with('-') && tok.len() > 1 {
                    prev_was_flag = true;
                    continue;
                }
                // A value token right after a flag is that flag's VALUE
                // placeholder (e.g. `--context <CONTEXT>`), not a positional.
                if is_value_token(tok) && tok != "[OPTIONS]" && tok != "[COMMAND]" && !prev_was_flag
                {
                    out.positionals.insert(normalize_positional(tok));
                    out.ordered_positionals.push(tok.to_string());
                }
                prev_was_flag = false;
            }
            continue;
        }
        // Leading-token run of an argument/option line: everything up to
        // the first token that is not a flag or value placeholder. The
        // description after it can mention other flags harmlessly.
        let first = trimmed.split_whitespace().next().unwrap_or("");
        let is_opt_line = trimmed.starts_with('-');
        let is_arg_line = in_arguments_section && is_value_token(first);
        if !(is_opt_line || is_arg_line) {
            continue;
        }
        let mut last_flag: Option<String> = None;
        for tok in trimmed.split_whitespace() {
            let bare = tok.trim_end_matches(',');
            if bare.starts_with('-') && bare.len() > 1 {
                out.flags.insert(bare.to_string());
                last_flag = Some(bare.to_string());
            } else if is_value_token(tok) {
                if let Some(flag) = &last_flag {
                    out.value_flags.insert(flag.clone());
                    out.flag_placeholders
                        .entry(flag.clone())
                        .or_insert_with(|| tok.to_string());
                    if in_arguments_section {
                        out.positionals.insert(normalize_positional(tok));
                    }
                }
                last_flag = None;
            } else if tok == "..." {
                continue;
            } else {
                break;
            }
        }
        // clap prints fixed choices as `[possible values: a, b]` on the
        // option's own line; capture the first for dummy-value synthesis.
        if let Some(leading) = trimmed.split_whitespace().find(|t| t.starts_with("--")) {
            let leading = leading.trim_end_matches(',');
            if let Some(idx) = trimmed.find("[possible values: ") {
                let rest = &trimmed[idx + "[possible values: ".len()..];
                if let Some(first) = rest.split(',').next() {
                    let first = first.trim_end_matches(']').trim().trim_end();
                    if !first.is_empty() {
                        out.flag_choices
                            .insert(leading.to_string(), first.to_string());
                    }
                }
            }
        }
    }
    out
}

/// Assert one `RequestField` is visible in the structural CLI surface.
fn field_exposed(surface: &HelpSurface, field: &x0x::api::RequestField) -> Result<(), String> {
    match &field.cli {
        CliExpose::Derived | CliExpose::Ignored | CliExpose::JsonDoc => Ok(()),
        CliExpose::BoolValue => {
            let flag = format!("--{}", kebab(field.name));
            if surface.flags.contains(&flag) {
                Ok(())
            } else {
                Err(format!("flag `{flag}` is not an argument of this command"))
            }
        }
        CliExpose::Token(token) => {
            if token.starts_with('-') {
                if surface.flags.contains(*token) {
                    Ok(())
                } else {
                    Err(format!("flag `{token}` is not an argument of this command"))
                }
            } else if surface.positionals.contains(&normalize_positional(token)) {
                Ok(())
            } else {
                Err(format!(
                    "positional `{token}` is not an argument of this command"
                ))
            }
        }
        CliExpose::Default => {
            let flag = format!("--{}", kebab(field.name));
            if surface.flags.contains(&flag) || surface.positionals.contains(field.name) {
                Ok(())
            } else {
                Err(format!(
                    "neither flag `{flag}` nor a matching positional is an argument of this command"
                ))
            }
        }
    }
}

/// Is `flag` present in the Usage line OUTSIDE brackets (i.e. required)?
fn usage_has_required_flag(usage: &str, flag: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = usage[from..].find(flag) {
        let start = from + pos;
        let unbracketed = usage[..start]
            .chars()
            .rev()
            .find(|c| *c == '[' || *c == ']')
            != Some('[');
        if unbracketed {
            return true;
        }
        from = start + flag.len();
    }
    false
}

/// Required-on-the-wire fields whose requiredness is enforced by the CLI
/// BEFORE dispatch rather than by clap, because the argument shape is an
/// XOR/multi-form command. Each is pinned with its enforcement site so the
/// exemption cannot rot silently.
const CLIENT_ENFORCED_REQUIRED: &[(&str, &str, &str, &str)] = &[
    // `--payload-b64` XOR `--file` (or `-` stdin): exactly one is required
    // and validated before any daemon contact (payload_b64_from_args).
    (
        "POST",
        "/agent/sign",
        "payload_b64",
        "src/cli/commands/identity.rs::payload_b64_from_args",
    ),
    (
        "POST",
        "/agent/verify",
        "payload_b64",
        "src/cli/commands/identity.rs::payload_b64_from_args",
    ),
    // `x0x exec` is a multi-form command (run / --cancel / sub-actions);
    // the run form requires the agent and bails pre-dispatch.
    (
        "POST",
        "/exec/run",
        "agent_id",
        "src/cli/commands/exec.rs::run (argv-empty bail)",
    ),
];

/// WHY (review r3, item 1): registry `required` must match clap's own
/// requiredness — a required field exposed as an optional flag (or an
/// optional positional) silently shifts validation to the daemon.
#[test]
fn registry_requiredness_matches_clap() {
    let mut failures = Vec::new();
    for ep in ENDPOINTS {
        let RequestSpec::Fields(fields) = &ep.request else {
            continue;
        };
        for tokens in tokenize_cli_name(ep.cli_name) {
            let surface = parse_help_surface(&cached_help(&tokens));
            for field in *fields {
                if !field.required {
                    continue;
                }
                if CLIENT_ENFORCED_REQUIRED.iter().any(|(m, p, f, _)| {
                    *m == ep.method.to_string().to_uppercase() && *p == ep.path && *f == field.name
                }) {
                    continue;
                }
                let flag = match &field.cli {
                    CliExpose::BoolValue => format!("--{}", kebab(field.name)),
                    CliExpose::Token(t) if t.starts_with('-') => t.to_string(),
                    CliExpose::Token(t) => {
                        let bracketed = format!("[{t}]");
                        if surface.usage_raw.contains(&bracketed)
                            && !surface.usage_raw.contains(&format!("<{t}>"))
                        {
                            failures.push(format!(
                                "  {} {}: `{}` is required on the wire but positional `{t}` is optional",
                                ep.method, ep.path, field.name
                            ));
                        }
                        if !surface.usage_raw.contains(&format!("<{t}>")) {
                            failures.push(format!(
                                "  {} {}: required positional `{t}` missing from the usage line",
                                ep.method, ep.path
                            ));
                        }
                        continue;
                    }
                    CliExpose::Default => format!("--{}", kebab(field.name)),
                    _ => continue,
                };
                if CLIENT_ENFORCED_REQUIRED.iter().any(|(m, p, f, _)| {
                    *m == ep.method.to_string().to_uppercase() && *p == ep.path && *f == field.name
                }) {
                    continue;
                }
                if surface.flags.contains(&flag) {
                    if !usage_has_required_flag(&surface.usage_raw, &flag) {
                        failures.push(format!(
                            "  {} {}: `{}` is required on the wire but `{flag}` is optional (or absent) in the usage line",
                            ep.method, ep.path, field.name
                        ));
                    }
                } else if let CliExpose::Default = field.cli {
                    let bracketed = format!("[{}]", field.name.to_uppercase());
                    let angled = format!("<{}>", field.name.to_uppercase());
                    if surface.usage_raw.contains(&bracketed)
                        && !surface.usage_raw.contains(&angled)
                    {
                        failures.push(format!(
                            "  {} {}: `{}` is required on the wire but its positional is optional",
                            ep.method, ep.path, field.name
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "\n\nRegistry requiredness vs clap mismatches ({}):\n{}\n",
        failures.len(),
        failures.join("\n")
    );
}

/// Dummy CLI value for a flag/positional: BOOL placeholders need a real
/// boolean, PATH/JSON placeholders point at a valid-JSON temp file (some
/// commands read AND parse the file client-side), everything else "1"
/// (parses as every scalar type clap accepts).
fn dummy_value(placeholder: &str) -> String {
    let up = placeholder.to_ascii_uppercase();
    if up.contains("BOOL") {
        "true".to_string()
    } else if up.contains("FILE") {
        "/dev/null".to_string()
    } else if up.contains("PATH") || up.contains("JSON") || up.contains("ENVELOPE") {
        static JSON_TMP: LazyLock<String> = LazyLock::new(|| {
            let p = std::env::temp_dir().join("x0x-parity-dummy.json");
            let _ = std::fs::write(&p, "{}");
            p.display().to_string()
        });
        JSON_TMP.clone()
    } else {
        "1".to_string()
    }
}

/// Build argv exercising the command's path-parameter positionals plus
/// every registry flag field, and run `x0x ... --dump-request`.
fn dump_request(ep: &EndpointDef, tokens: &[String]) -> Result<serde_json::Value, String> {
    let surface = parse_help_surface(&cached_help(tokens));
    let mut argv: Vec<String> = tokens.to_vec();

    // Positionals in usage order (covers path params AND field positionals).
    for tok in &surface.ordered_positionals {
        let inner = tok
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_start_matches('<')
            .trim_end_matches('>');
        argv.push(dummy_value(inner));
    }
    // Flags from the registry fields.
    if let RequestSpec::Fields(fields) = &ep.request {
        for field in *fields {
            let flag = match &field.cli {
                CliExpose::BoolValue => format!("--{}", kebab(field.name)),
                CliExpose::Token(t) if t.starts_with('-') => t.to_string(),
                // Default fields are `--kebab` flags when the command has
                // that flag (positional Defaults are covered by the
                // usage-order pass above).
                CliExpose::Default => format!("--{}", kebab(field.name)),
                _ => continue,
            };
            if !surface.flags.contains(&flag) {
                continue; // presence already enforced by the other tests
            }
            argv.push(flag.clone());
            if surface.value_flags.contains(&flag) {
                let value = surface.flag_choices.get(&flag).cloned().unwrap_or_else(|| {
                    surface
                        .flag_placeholders
                        .get(&flag)
                        .map(|p| dummy_value(p))
                        .unwrap_or_else(|| "1".to_string())
                });
                argv.push(value);
            }
        }
    }
    // Required flags named in the usage line that the registry did not
    // already cover (e.g. a `requires =` sibling like
    // --delegation-signature) must also be supplied.
    let pushed: BTreeSet<String> = argv.iter().cloned().collect();
    let mut prev_was_flag = false;
    for tok in surface.usage_raw.split_whitespace().skip(1) {
        if tok.starts_with("--") && tok.len() > 2 {
            prev_was_flag = true;
            let flag = tok.trim_end_matches(',');
            if !pushed.contains(flag) && surface.flags.contains(flag) {
                argv.push(flag.to_string());
                if surface.value_flags.contains(flag) {
                    let value = surface.flag_choices.get(flag).cloned().unwrap_or_else(|| {
                        surface
                            .flag_placeholders
                            .get(flag)
                            .map(|p| dummy_value(p))
                            .unwrap_or_else(|| "1".to_string())
                    });
                    argv.push(value);
                }
            }
            continue;
        }
        if prev_was_flag && is_value_token(tok) {
            continue; // flag value placeholder, handled above
        }
        prev_was_flag = false;
    }
    argv.push("--dump-request".to_string());
    // Trailing var-args (`[ARGV]...` in the usage line) need one element
    // or the command bails pre-dispatch — AFTER the global flag, which
    // would otherwise be swallowed as remote argv.
    if surface.usage_raw.contains("ARGV]") {
        argv.push("--".to_string());
        argv.push("1".to_string());
    }

    // clap conflicts (e.g. --no-durable-ack vs --logical-id): run one
    // variant per side of each conflict so BOTH fields get their wire
    // presence proven across the collected dumps.
    let mut variants: Vec<Vec<String>> = vec![argv];
    let mut dumps: Vec<serde_json::Value> = Vec::new();
    let mut last_err = String::new();
    while let Some(candidate) = variants.pop() {
        match run_dump(&candidate) {
            Ok(dumped) => dumps.push(dumped),
            Err(msg) => {
                last_err = msg.clone();
                if let Some((first, second)) = conflicting_flag(&msg) {
                    for drop_flag in [first, second] {
                        let Some(pos) = candidate.iter().position(|a| *a == drop_flag) else {
                            continue;
                        };
                        let mut variant = candidate.clone();
                        let has_value = pos + 1 < variant.len()
                            && !variant[pos + 1].starts_with('-')
                            && surface.value_flags.contains(&drop_flag);
                        variant.drain(pos..=pos + usize::from(has_value));
                        variants.push(variant);
                    }
                }
            }
        }
    }
    if dumps.is_empty() {
        return Err(last_err);
    }
    Ok(serde_json::Value::Array(dumps))
}

/// Parse `the argument 'A' cannot be used with 'B'` from a clap error.
fn conflicting_flag(err: &str) -> Option<(String, String)> {
    let first_idx = err.find("the argument '")? + "the argument '".len();
    let first_end = first_idx + err[first_idx..].find('\'')?;
    let first = err[first_idx..first_end]
        .split_whitespace()
        .next()?
        .to_string();
    let second_idx = err.find("cannot be used with '")? + "cannot be used with '".len();
    let second_end = second_idx + err[second_idx..].find('\'')?;
    let second = err[second_idx..second_end]
        .split_whitespace()
        .next()?
        .to_string();
    Some((first, second))
}

fn run_dump(argv: &[String]) -> Result<serde_json::Value, String> {
    let out = Command::new(bin_path())
        .args(argv)
        .output()
        .map_err(|e| format!("spawn failed: {e}"))?;
    // Streaming commands (subscribe/events) dump their request and then
    // exit non-zero when no daemon answers — the dump line is the proof.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let dumped = stdout
        .lines()
        .find(|l| l.starts_with('{') && l.contains("\"method\""))
        .and_then(|l| serde_json::from_str(l).ok());
    if let Some(dumped) = dumped {
        return Ok(dumped);
    }
    Err(format!(
        "`x0x {}` produced no request dump (status {:?}): {}",
        argv.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

/// Endpoints whose CLI command deliberately issues no HTTP request (URL
/// printers for external clients) — dispatch-to-wire does not apply.
const DISPATCH_EXEMPT: &[(&str, &str, &str)] = &[
    // `x0x ws direct` prints the WebSocket URL (with ?backfill=) for an
    // external client to dial; the CLI never opens the socket.
    (
        "GET",
        "/ws/direct",
        "ws/commands/ws.rs::direct (URL printer)",
    ),
];

/// WHY (review r3, item 1): presence checks cannot prove the DISPATCH
/// serializes a field. `--dump-request` emits the exact wire request the
/// builder would send; this test asserts every registry field of every
/// field-bearing endpoint actually lands in the emitted body/query, and
/// that the emitted method matches the registry.
#[test]
fn dispatched_requests_carry_every_registry_field() {
    let mut failures = Vec::new();
    for ep in ENDPOINTS {
        let RequestSpec::Fields(fields) = &ep.request else {
            continue;
        };
        if DISPATCH_EXEMPT
            .iter()
            .any(|(m, p, _)| *m == ep.method.to_string().to_uppercase() && *p == ep.path)
        {
            continue;
        }
        for tokens in tokenize_cli_name(ep.cli_name) {
            let dumped = match dump_request(ep, &tokens) {
                Ok(d) => d,
                Err(msg) => {
                    failures.push(format!("  {} {}: {msg}", ep.method, ep.path));
                    continue;
                }
            };
            let variants = dumped.as_array().cloned().unwrap_or_else(|| vec![dumped]);
            for field in *fields {
                if matches!(
                    field.cli,
                    CliExpose::Derived | CliExpose::Ignored | CliExpose::JsonDoc
                ) {
                    continue;
                }
                // Present if ANY conflict-variant dump carries the field
                // (mutually exclusive flags prove presence across variants).
                let present = variants.iter().any(|d| {
                    d["body"]
                        .as_object()
                        .map(|o| o.contains_key(field.name))
                        .unwrap_or(false)
                        || d["path"]
                            .as_str()
                            .map(|p| p.contains(&format!("{}=", field.name)))
                            .unwrap_or(false)
                });
                if !present {
                    failures.push(format!(
                        "  {} {}: field `{}` never reaches the wire request built by `x0x {}`",
                        ep.method,
                        ep.path,
                        field.name,
                        tokens.join(" ")
                    ));
                }
            }
            for d in &variants {
                let method = d["method"].as_str().unwrap_or_default();
                if method != ep.method.to_string().to_uppercase() {
                    failures.push(format!(
                        "  {} {}: dump emitted method {method}",
                        ep.method, ep.path
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "\n\nDispatch-to-wire violations ({}):\n{}\n\n\
         Fix the body/query builder in src/cli/commands/ — the argument \
         exists but is not serialized.",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_request_field_is_exposed_by_the_cli() {
    let mut failures = Vec::new();
    for ep in ENDPOINTS {
        let RequestSpec::Fields(fields) = &ep.request else {
            continue;
        };
        for tokens in tokenize_cli_name(ep.cli_name) {
            let surface = parse_help_surface(&cached_help(&tokens));
            for field in *fields {
                if let Err(msg) = field_exposed(&surface, field) {
                    failures.push(format!(
                        "  {} {} ({} {}): field `{}` — {msg}",
                        ep.method,
                        ep.path,
                        ep.cli_name,
                        tokens.join(" "),
                        field.name
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "\n\nCLI request-field parity violations — registry request fields \
         with no CLI argument ({} failures):\n{}\n\n\
         Fix: add the flag/positional to src/bin/x0x.rs (and the body \
         builder in src/cli/commands/) or correct the RequestSpec in \
         src/api/mod.rs::ENDPOINTS.\n",
        failures.len(),
        failures.join("\n")
    );
}

// ─── Registry ⇄ request-struct drift guard ──────────────────────────────

/// Daemon sources holding router wiring, handlers, and request DTOs.
/// Keep in sync with `src/server/` layout (same convention as
/// `api_coverage::COVERAGE_MARKER_SOURCES`).
const SERVER_SOURCES: &[&str] = &[
    "src/server/mod.rs",
    "src/server/auth.rs",
    "src/server/delegations.rs",
    "src/server/sse.rs",
    "src/server/ws.rs",
    "src/server/routes/mod.rs",
    "src/server/routes/connect.rs",
    "src/server/routes/contacts.rs",
    "src/server/routes/direct.rs",
    "src/server/routes/discovery.rs",
    "src/server/routes/exec.rs",
    "src/server/routes/files.rs",
    "src/server/routes/groups.rs",
    "src/server/routes/history.rs",
    "src/server/routes/home.rs",
    "src/server/routes/identity.rs",
    "src/server/routes/key_move.rs",
    "src/server/routes/machines.rs",
    "src/server/routes/messaging.rs",
    "src/server/routes/named_groups.rs",
    "src/server/routes/network.rs",
    "src/server/routes/owner.rs",
    "src/server/routes/presence.rs",
    "src/server/routes/profile.rs",
    "src/server/routes/public_group_bootstrap_outbox.rs",
    "src/server/routes/status.rs",
    "src/server/routes/stores.rs",
    "src/server/routes/sync.rs",
    "src/server/routes/tasks.rs",
    "src/server/routes/trust.rs",
    "src/server/routes/upgrade.rs",
];

/// How a handler consumes request data, from its extractor signature.
#[derive(Debug, PartialEq, Eq, Clone)]
enum Extracted {
    /// `Json<Struct>` / `Query<Struct>` (also `Option<Json<Struct>>`).
    Struct(FieldLocation, String),
    /// `Json<serde_json::Value>` — loosely parsed body.
    RawValue,
    /// `Query<HashMap<..>>` — free-form query keys.
    FreeFormQuery,
    /// No body/query extractor at all.
    None,
}

fn crate_root(relative: &str) -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative)
}

/// `(method, path) -> handler identifier` from the axum router builder.
fn router_handlers(server_mod: &str) -> BTreeMap<(String, String), Vec<(&'static str, String)>> {
    let flat = server_mod.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: BTreeMap<(String, String), Vec<(&'static str, String)>> = BTreeMap::new();
    let marker = ".route(";
    let mut i = 0usize;
    while let Some(pos) = flat[i..].find(marker) {
        let start = i + pos + marker.len();
        // Walk to the matching close paren (string-aware).
        let bytes = flat.as_bytes();
        let mut depth = 1usize;
        let mut j = start;
        while j < bytes.len() && depth > 0 {
            match bytes[j] as char {
                '"' => {
                    j += 1;
                    while j < bytes.len() {
                        match bytes[j] as char {
                            '\\' => j += 2,
                            '"' => break,
                            _ => j += 1,
                        }
                    }
                }
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        if j <= start {
            break;
        }
        let inner = flat[start..j - 1].trim();
        i = j;

        let Some(path_start) = inner.find('"') else {
            continue;
        };
        let rest = &inner[path_start + 1..];
        let Some(path_end) = rest.find('"') else {
            continue;
        };
        let path = rest[..path_end].to_string();
        let methods_src = &rest[path_end + 1..];

        for (needle, method) in [
            ("get(", "GET"),
            ("post(", "POST"),
            ("put(", "PUT"),
            ("patch(", "PATCH"),
            ("delete(", "DELETE"),
        ] {
            if let Some(fn_pos) = methods_src.find(needle) {
                let after = &methods_src[fn_pos + needle.len()..];
                let name: String = after
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                if !name.is_empty() {
                    out.entry((method.to_string(), path.clone()))
                        .or_default()
                        .push((method, name));
                }
            }
        }
    }
    out
}

/// `handler -> Extracted` from every `fn <name>(...)` signature found in
/// the source set (last segment of path-qualified router names matches).
fn handler_extractors(sources: &[(String, String)]) -> BTreeMap<String, Extracted> {
    let mut out = BTreeMap::new();
    for (_path, src) in sources {
        let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut search = 0usize;
        while let Some(pos) = flat[search..].find("fn ") {
            let after = &flat[search + pos + 3..];
            // Only top-level-ish `pub ... fn name(` / `fn name(` shapes.
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let rest_offset = name.len();
            let rest = after[rest_offset..].trim_start();
            if let Some(params_src) = rest.strip_prefix('(') {
                let close = matching_paren(params_src);
                let params = &params_src[..close];
                let extracted = if params.contains("Json<serde_json::Value>")
                    || params.contains("Json<Value>")
                {
                    Extracted::RawValue
                } else if params.contains("Query<std::collections::HashMap")
                    || params.contains("Query<HashMap")
                {
                    Extracted::FreeFormQuery
                } else if let Some(t) = first_generic(params, "Json<") {
                    Extracted::Struct(FieldLocation::Body, t)
                } else if let Some(t) = first_generic(params, "Query<") {
                    Extracted::Struct(FieldLocation::Query, t)
                } else {
                    Extracted::None
                };
                out.insert(name, extracted);
                search += pos + 3 + rest_offset + 1 + close;
            } else {
                search += pos + 3;
            }
        }
    }
    out
}

/// Length of `haystack` before the closing paren matching the one that
/// opens `haystack` at position 0.
fn matching_paren(haystack: &str) -> usize {
    let mut depth = 1usize;
    for (idx, ch) in haystack.char_indices() {
        match ch {
            '(' | '<' | '[' => depth += 1,
            ')' | '>' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return idx;
                }
            }
            _ => {}
        }
    }
    haystack.len()
}

/// First `Outer<Ident>` argument in the params list (Ident is a single
/// path-free identifier, so `Json<serde_json::Value>` returns None).
fn first_generic(params: &str, outer: &str) -> Option<String> {
    let needle = outer;
    let mut from = 0usize;
    while let Some(pos) = params[from..].find(needle) {
        let start = from + pos + needle.len();
        let ident: String = params[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        // Must actually be followed by `>`.
        let after = &params[start + ident.len()..];
        if !ident.is_empty() && after.starts_with('>') {
            return Some(ident);
        }
        from = start;
    }
    None
}

/// `StructName -> field names` for `struct Name { ... }` definitions
/// outside `#[cfg(test)]` modules (parsed on the raw source so the
/// one-field-per-line layout survives).
fn struct_fields(sources: &[(String, String)]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (_path, src) in sources {
        let cleaned = strip_test_mods(src);
        let mut rest: &str = &cleaned;
        while let Some(pos) = rest.find("struct ") {
            let after = &rest[pos + "struct ".len()..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let between = &after[name.len()..];
            // Skip tuple structs / unit structs / generics we don't model.
            if let Some(open) = between.find('{') {
                let pre_brace = &between[..open];
                if pre_brace.trim().is_empty() {
                    let body = &between[open + 1..];
                    let close = flat_brace_close(body);
                    let fields = parse_struct_fields(&body[..close]);
                    out.insert(name, fields);
                    rest = &body[close..];
                    continue;
                }
            }
            rest = after;
        }
    }
    out
}

fn strip_test_mods(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(pos) = rest.find("mod tests") {
        out.push_str(&rest[..pos]);
        let after_brace = match rest[pos..].find('{') {
            Some(b) => pos + b + 1,
            None => return out,
        };
        let close = flat_brace_close(&rest[after_brace..]);
        rest = &rest[after_brace + close..];
    }
    out.push_str(rest);
    out
}

fn flat_brace_close(body: &str) -> usize {
    let mut depth = 1usize;
    for (idx, ch) in body.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return idx;
                }
            }
            _ => {}
        }
    }
    body.len()
}

fn parse_struct_fields(body: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with("pub(crate)")
            || trimmed.starts_with('*')
        {
            continue;
        }
        let no_vis = trimmed.strip_prefix("pub ").or_else(|| {
            trimmed
                .strip_prefix("pub(")
                .and_then(|rest| rest.find(')').map(|i| &rest[i + 1..]))
                .map(|rest| rest.trim_start())
        });
        let candidate = no_vis.unwrap_or(trimmed);
        let Some((name, tail)) = candidate.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.is_empty()
            && !keywords().contains(&name)
        {
            let ty = tail.split(',').next().unwrap_or("").trim().to_string();
            fields.insert(name.to_string(), ty);
        }
    }
    fields
}

fn keywords() -> BTreeSet<&'static str> {
    [
        "fn", "let", "match", "if", "for", "while", "impl", "struct", "enum",
    ]
    .into_iter()
    .collect()
}

/// Endpoints whose registry `Fields` cannot be checked against a resolvable
/// handler struct (manual `Bytes`/`Value` body parsing). Pinned EXACTLY —
/// endpoints AND their field lists — so a new manual endpoint or a field
/// change on an existing one is a conscious edit, not silent drift
/// (review r2, finding 2c).
const PINNED_MANUAL_BODY_ENDPOINTS: &[(&str, &str, &[&str])] = &[
    // parse_optional_json over raw Bytes (announce_identity)
    (
        "POST",
        "/announce",
        &["human_consent", "include_user_identity"],
    ),
    // parse_optional_json over raw Bytes (create_group_invite)
    ("POST", "/groups/:id/invite", &["expiry_secs"]),
    // raw Bytes -> serde GroupCard passthrough (import_group_card)
    ("POST", "/groups/cards/import", &[]),
];

#[test]
fn registry_request_metadata_matches_handler_structs() {
    let sources: Vec<(String, String)> = SERVER_SOURCES
        .iter()
        .map(|rel| {
            let p = crate_root(rel);
            (
                p.clone(),
                std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("failed to read {p}: {e}")),
            )
        })
        .collect();
    let server_mod = sources
        .iter()
        .find(|(p, _)| p.ends_with("src/server/mod.rs"))
        .expect("server/mod.rs in source set")
        .1
        .clone();
    let routes = router_handlers(&server_mod);
    let extractors = handler_extractors(&sources);
    let structs = struct_fields(&sources);

    let mut failures = Vec::new();
    let mut manual_bodies: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut resolved = 0usize;

    for ep in ENDPOINTS {
        let method = ep.method.to_string().to_uppercase();
        let Some(handlers) = routes.get(&(method.clone(), ep.path.to_string())) else {
            failures.push(format!(
                "  {} {} not found in router wiring",
                method, ep.path
            ));
            continue;
        };
        for (_m, handler) in handlers {
            let short = handler.rsplit("::").next().unwrap_or(handler);
            let Some(extracted) = extractors.get(short) else {
                failures.push(format!(
                    "  {} {}: handler `{}` not found in scanned sources",
                    method, ep.path, handler
                ));
                continue;
            };
            match extracted {
                Extracted::None => {
                    // Manual body parsing (raw `Bytes` + parse_optional_json);
                    // both Fields (documented keys) and Passthrough are honest.
                    if let RequestSpec::Fields(fields) = &ep.request {
                        manual_bodies.push((
                            method.clone(),
                            ep.path.to_string(),
                            fields.iter().map(|f| f.name.to_string()).collect(),
                        ));
                    } else if matches!(ep.request, RequestSpec::Passthrough) {
                        manual_bodies.push((method.clone(), ep.path.to_string(), Vec::new()));
                    }
                }
                Extracted::RawValue => {
                    if !matches!(
                        ep.request,
                        RequestSpec::Fields(_) | RequestSpec::Passthrough
                    ) {
                        failures.push(format!(
                            "  {} {}: handler `{}` takes a raw JSON value; registry must be Fields or Passthrough",
                            method, ep.path, handler
                        ));
                    }
                }
                Extracted::FreeFormQuery => {
                    if !matches!(ep.request, RequestSpec::None) {
                        failures.push(format!(
                            "  {} {}: handler `{}` takes a free-form query map; registry must be None",
                            method, ep.path, handler
                        ));
                    }
                }
                Extracted::Struct(location, struct_name) => {
                    resolved += 1;
                    let Some(fields) = structs.get(struct_name) else {
                        // Struct defined outside the scanned server tree
                        // (e.g. `TransferBundle` in src/key_move.rs): the CLI
                        // can only post such a document verbatim.
                        if !matches!(ep.request, RequestSpec::Passthrough) {
                            failures.push(format!(
                                "  {} {}: external request struct `{}` is only reachable as a verbatim JSON document; registry request must be Passthrough",
                                method, ep.path, struct_name
                            ));
                        }
                        continue;
                    };
                    let RequestSpec::Fields(registry_fields) = &ep.request else {
                        failures.push(format!(
                            "  {} {}: handler takes `{struct_name}` with fields [{}] but registry request is {:?}",
                            method,
                            ep.path,
                            fields.keys().cloned().collect::<Vec<_>>().join(", "),
                            request_kind(ep)
                        ));
                        continue;
                    };
                    let registry_names: BTreeSet<&str> =
                        registry_fields.iter().map(|f| f.name).collect();
                    let struct_names: BTreeSet<&str> = fields.keys().map(|s| s.as_str()).collect();
                    let missing: Vec<_> = struct_names.difference(&registry_names).collect();
                    let extra: Vec<_> = registry_names.difference(&struct_names).collect();
                    if !missing.is_empty() {
                        failures.push(format!(
                            "  {} {}: struct `{struct_name}` fields missing from registry ENDPOINTS: {:?}",
                            method, ep.path, missing
                        ));
                    }
                    if !extra.is_empty() {
                        failures.push(format!(
                            "  {} {}: registry fields not present in struct `{struct_name}`: {:?}",
                            method, ep.path, extra
                        ));
                    }
                    for f in *registry_fields {
                        // WHY (review r3, item 1): the daemon's field TYPE
                        // must be compatible with the CLI's argument shape:
                        // booleans may be bare flags; everything else must
                        // take a value (flag or positional). Catches e.g. a
                        // daemon u64 exposed as a valueless switch.
                        if let Some(ty) = fields.get(f.name) {
                            let inner = ty.replace("Option<", "").trim_end_matches('>').to_string();
                            let is_bool =
                                inner.trim() == "bool" || inner.trim().starts_with("bool");
                            let shape_ok = help_for(&method, ep.path)
                                .as_deref()
                                .map(|h| {
                                    let surface = parse_help_surface(h);
                                    let flag = match &f.cli {
                                        CliExpose::Default | CliExpose::BoolValue => {
                                            format!("--{}", kebab(f.name))
                                        }
                                        CliExpose::Token(t) if t.starts_with('-') => t.to_string(),
                                        CliExpose::Token(t) => {
                                            // Positional binding: its value
                                            // name may differ from the wire
                                            // field name (e.g. EPOCH for
                                            // move_epoch).
                                            return surface
                                                .positionals
                                                .contains(&normalize_positional(t));
                                        }
                                        _ => return true,
                                    };
                                    let positional_names = [f.name.to_string(), kebab(f.name)];
                                    if surface
                                        .positionals
                                        .intersection(&positional_names.iter().cloned().collect())
                                        .next()
                                        .is_some()
                                    {
                                        true
                                    } else if is_bool {
                                        surface.flags.contains(&flag)
                                    } else {
                                        surface.value_flags.contains(&flag)
                                    }
                                })
                                .unwrap_or(true);
                            if !shape_ok {
                                failures.push(format!(
                                    "  {} {}: daemon types `{}` as `{ty}` but the CLI exposes it without a value",
                                    method, ep.path, f.name
                                ));
                            }
                        }
                        // WHY (review r2, finding 1): an `Option<bool>` whose
                        // daemon default when omitted is TRUE can only be
                        // steered to false by an explicit value; a bare
                        // SetTrue flag could never serialize `false`. Fields
                        // marked CliExpose::BoolValue must therefore be a
                        // value-taking flag AND typed Option<bool> on the
                        // daemon (default-false bools are exempt — omission
                        // already reaches false).
                        if matches!(f.cli, CliExpose::BoolValue) {
                            let flag = format!("--{}", f.name.replace('_', "-"));
                            let ty = fields.get(f.name).cloned().unwrap_or_default();
                            let value_flag = help_for(&method, ep.path)
                                .as_deref()
                                .map(|h| parse_help_surface(h).value_flags.contains(&flag))
                                .unwrap_or(true);
                            if !ty.contains("Option<bool>") {
                                failures.push(format!(
                                    "  {} {}: field `{}` is marked BoolValue but the daemon types it `{ty}`",
                                    method, ep.path, f.name
                                ));
                            }
                            if !value_flag {
                                failures.push(format!(
                                    "  {} {}: field `{}` defaults to true when omitted; the CLI flag `{flag}` must take an explicit true|false value or `false` is unreachable",
                                    method, ep.path, f.name
                                ));
                            }
                        }
                        if f.location != *location {
                            failures.push(format!(
                                "  {} {}: field `{}` is {} in the registry but the handler extracts it from the {}",
                                method,
                                ep.path,
                                f.name,
                                f.location.as_str(),
                                location.as_str()
                            ));
                        }
                    }
                }
            }
        }
    }

    let mut pinned: Vec<(String, String, Vec<String>)> = PINNED_MANUAL_BODY_ENDPOINTS
        .iter()
        .map(|(m, p, fs)| {
            (
                m.to_string(),
                p.to_string(),
                fs.iter().map(|f| f.to_string()).collect(),
            )
        })
        .collect();
    for (_, _, fs) in &mut pinned {
        fs.sort();
    }
    pinned.sort();
    let mut actual = manual_bodies.clone();
    for (_, _, fs) in &mut actual {
        fs.sort();
    }
    actual.sort();
    assert_eq!(
        actual, pinned,
        "endpoints with registry Fields but no resolvable handler struct \
         (or their field lists) changed; update PINNED_MANUAL_BODY_ENDPOINTS \
         consciously after verifying each one parses its body manually"
    );
    assert!(
        resolved >= 50,
        "struct drift guard resolved only {resolved} handler request structs; \
         the source parser is rotting and the guard is losing teeth"
    );
    assert!(
        failures.is_empty(),
        "\n\nRegistry ⇄ request-struct drift ({} failures):\n{}\n",
        failures.len(),
        failures.join("\n")
    );
}

fn request_kind(ep: &EndpointDef) -> &'static str {
    match ep.request {
        RequestSpec::None => "None",
        RequestSpec::Fields(_) => "Fields",
        RequestSpec::Passthrough => "Passthrough",
    }
}
