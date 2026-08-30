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
            for tok in trimmed.split_whitespace().skip(1) {
                if is_value_token(tok) && tok != "[OPTIONS]" && tok != "[COMMAND]" {
                    out.positionals.insert(normalize_positional(tok));
                }
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
