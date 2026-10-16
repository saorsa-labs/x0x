//! Manifest-driven parity proof for the embedded HTML GUI's
//! named-groups surface.
//!
//! This is the one source of truth for "does the GUI cover the
//! named-groups REST API". It enumerates every endpoint registered in
//! `src/api/mod.rs::ENDPOINTS` with `category == "named-groups"` and
//! asserts that the GUI HTML contains a call-site for it.
//!
//! Each endpoint must satisfy **one** of:
//!
//! 1. The HTML contains a `<method>` `api(..., "<path fragment>", ...)`
//!    reference that the scanner can match (primary path).
//! 2. The path is listed in `DEFERRED` below with an explicit reason.
//!    Deferred paths DO NOT count as coverage — they are visible in
//!    the failure output so we cannot accidentally claim parity.
//!
//! When a new named-groups endpoint is added to `ENDPOINTS`, this test
//! fails until either the GUI is updated or a DEFERRED entry is added
//! here with a reason. That prevents the GUI from silently drifting.

use std::collections::HashSet;
use x0x::api::{EndpointDef, FieldLocation, Method, RequestSpec, ENDPOINTS};

const GUI_HTML: &str = include_str!("../src/gui/x0x-gui.html");

/// Named-groups endpoints we have consciously chosen NOT to wire into
/// the embedded HTML GUI, with an explicit reason. Anything in this
/// list is counted as a **gap**, not coverage — the signoff doc must
/// reflect that.
///
/// Adding an entry here is a downgrade that must show up in
/// `docs/proof/NAMED_GROUPS_PARITY_SIGNOFF.md`.
const DEFERRED: &[(Method, &str, &str)] = &[
    // #477: the pending-join status (with the typed terminal refusal
    // outcome) is a CLI/REST-first surface — `x0x group join-status` and
    // `x0x group join --wait`. GUI wiring (a join-progress panel) is
    // deferred with the other #477 follow-ups (issue #481).
    (
        Method::Get,
        "/groups/:id/join-status",
        "CLI/REST-first join-status surface; GUI join-progress panel deferred (#481)",
    ),
    // issue #111: retained state-commit history is a verification / governance
    // read surface (audit, dispute evidence), not a routine browser action.
    // Exposed via the CLI (`x0x group state-commits`) and the REST API; a GUI
    // history viewer is deferred until there is a product need.
    (
        Method::Get,
        "/groups/:id/state/commits",
        "verification/audit read surface; exposed via CLI + REST, GUI viewer deferred",
    ),
    // ADR-0040 delegation is an agent-to-agent authority surface: agents
    // (and their harnesses) delegate via the CLI/REST, not a routine
    // browser action. A GUI delegation manager (issue + list + revoke) is
    // deferred until there is a product need; the WS mention event it
    // would consume is already emitted daemon-side.
    (
        Method::Post,
        "/groups/:id/delegate",
        "agent-to-agent authority surface; exposed via CLI + REST, GUI manager deferred",
    ),
    (
        Method::Get,
        "/groups/:id/delegations",
        "agent-to-agent authority surface; exposed via CLI + REST, GUI manager deferred",
    ),
    // The adversarial test endpoint is only meaningful as a CLI /
    // harness probe; exposing it in the browser UI would be confusing
    // and has no product use case.
    (
        Method::Post,
        "/groups/secure/open-envelope",
        "adversarial test endpoint, not a user-facing action",
    ),
    // Secure-plane encrypt/decrypt/reseal are consumed via MLS group
    // chat, not a direct user action in the embedded GUI. The CLI and
    // both clients expose them.
    (
        Method::Post,
        "/groups/:id/secure/encrypt",
        "secure-plane primitive; consumed implicitly by encrypted chat",
    ),
    (
        Method::Post,
        "/groups/:id/secure/decrypt",
        "secure-plane primitive; consumed implicitly by encrypted chat",
    ),
    (
        Method::Post,
        "/groups/:id/secure/reseal",
        "secure-plane primitive; server-side rekey on approve/ban",
    ),
    // Explicit add-member by agent hex is an admin flow covered by the
    // invite path in the GUI. Deferred until the GUI gains an
    // agent-picker; the CLI and both clients expose it.
    (
        Method::Post,
        "/groups/:id/members",
        "admin flow; GUI currently uses invite links instead of direct add-by-agent",
    ),
    (
        Method::Delete,
        "/groups/:id/members/:agent_id",
        "admin flow; GUI currently uses ban rather than direct remove-by-agent",
    ),
    // GET /groups/cards/:id — card inspection UI still deferred. The
    // card-import action below is now wired; inspection-by-id will
    // come with a richer "discovered groups" detail panel.
    (
        Method::Get,
        "/groups/cards/:id",
        "GUI gap: card inspection-by-id UI not yet wired (import action is)",
    ),
    // Shard subscriptions are a power-user surface; CLI covers it.
    (
        Method::Get,
        "/groups/discover/subscriptions",
        "power-user surface; CLI covers it",
    ),
    (
        Method::Post,
        "/groups/discover/subscribe",
        "power-user surface; CLI covers it",
    ),
    (
        Method::Delete,
        "/groups/discover/subscribe/:kind/:shard",
        "power-user surface; CLI covers it",
    ),
    // Cancel-own-request is a nice-to-have follow-up; the GUI
    // currently surfaces the admin review path but not the requester-
    // side cancel.
    (
        Method::Delete,
        "/groups/:id/requests/:request_id",
        "GUI gap: requester-side cancel-request UI not yet wired",
    ),
    // Presence events are used globally by the GUI via WebSocket
    // rather than the named-groups discovery path.
    // ADR-0064 slice 3 (#472 decision 1): the manual fork-quarantine clear
    // is an operator/ops endpoint (owner-key node clear or force+reason
    // with an audit trail) — CLI + REST first; a GUI ops panel is deferred
    // with the ADR-0064 runbook work.
    (
        Method::Post,
        "/groups/:id/quarantine/clear",
        "operator/ops endpoint; exposed via CLI + REST, GUI ops panel deferred (ADR-0064)",
    ),
];

/// One observed daemon call: the path expression text (including
/// concatenations and template substitutions) plus the parsed HTTP
/// method from the options object (`{method: 'PATCH'}`). `None`
/// method means GET.
#[derive(Debug)]
struct ApiCall {
    expr: String,
    method: Option<String>,
    /// Text after the path argument. Holds the options object when the
    /// call sends one.
    options: String,
    /// Byte index of the call name (`api`, `ownerApi`, or `apiWith`).
    at: usize,
    /// Byte index one past the call's closing parenthesis.
    end: usize,
}

/// `ownerApi(`, `apiWith(`, and `api(` are daemon calls. A preceding
/// identifier character excludes `symApi(` (the symphony daemon).
fn call_name_at(bytes: &[u8], index: usize) -> Option<&'static str> {
    if index > 0 {
        let prev = bytes[index - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'$' {
            return None;
        }
    }
    const NAMES: &[&str] = &["ownerApi(", "apiWith(", "api("];
    NAMES
        .iter()
        .copied()
        .find(|name| bytes[index..].starts_with(name.as_bytes()))
}

/// Walk the GUI HTML and capture every daemon `api(...)` invocation.
/// The extractor handles `'/foo/'+x+'/bar'`, `` `/foo/${x}/bar` ``, and
/// the optional options object `{method: 'X'}`. `apiWith(bearer, path,
/// opt)` is included when the path is a literal; the wrappers `api` and
/// `ownerApi` pass a variable and are skipped.
fn gui_api_calls() -> Vec<ApiCall> {
    let bytes = GUI_HTML.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Issue #446: owner-act call sites go through `ownerApi(...)` —
        // the same daemon base URL and path surface as `api(...)`, so it
        // counts for parity. (`symApi(...)` targets the separate
        // symphony daemon and deliberately does NOT match.)
        let Some(name) = call_name_at(bytes, i) else {
            i += 1;
            continue;
        };
        let start = i + name.len();
        // Find the matching close paren, respecting strings and
        // brace nesting.
        let mut depth = 1usize;
        let mut j = start;
        let mut in_str: Option<u8> = None;
        while j < bytes.len() && depth > 0 {
            let c = bytes[j];
            if let Some(q) = in_str {
                if c == b'\\' {
                    j += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
            } else {
                match c {
                    b'\'' | b'"' | b'`' => in_str = Some(c),
                    b'(' | b'{' | b'[' => depth += 1,
                    b')' | b'}' | b']' => depth -= 1,
                    _ => {}
                }
            }
            j += 1;
        }
        // `j` is now one past the closing `)`; arguments span [start, j-1].
        let args_end = j.saturating_sub(1);
        let args = &GUI_HTML[start..args_end];
        // Split into first-arg expression + remainder by the
        // first top-level comma. `apiWith` puts the bearer first.
        let (first, rest) = split_top_level_comma(args);
        let (expr, options_src) = if name.starts_with("apiWith") {
            let rest = rest.trim_start_matches(',').trim_start();
            let (path, after) = split_top_level_comma(rest);
            (path.trim().to_string(), after)
        } else {
            (first.trim().to_string(), rest)
        };
        let method = extract_method_kw(options_src);
        let options = options_src
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_string();
        // Heuristic: only keep calls whose path arg looks like a
        // path literal (starts with a quote followed by `/`).
        if looks_like_path_arg(&expr) {
            out.push(ApiCall {
                expr,
                method,
                options,
                at: i,
                end: j,
            });
        }
        i = j;
    }
    out
}

/// Split `args` at the first comma that is not inside a string or a
/// nested bracket. Returns `(first_arg, rest_including_comma)`.
fn split_top_level_comma(args: &str) -> (&str, &str) {
    let bytes = args.as_bytes();
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => return (&args[..i], &args[i..]),
                _ => {}
            }
        }
        i += 1;
    }
    (args, "")
}

/// Pick `method: 'X'` out of an optional second arg.
fn extract_method_kw(rest: &str) -> Option<String> {
    let needle = "method:";
    let mpos = rest.find(needle)?;
    let mrest = rest[mpos + needle.len()..].trim_start();
    let q = mrest.bytes().next()?;
    if q != b'\'' && q != b'"' {
        return None;
    }
    let after = &mrest[1..];
    let end = after.find(q as char)?;
    Some(after[..end].to_string())
}

fn looks_like_path_arg(expr: &str) -> bool {
    let trimmed = expr.trim_start();
    let bytes = trimmed.as_bytes();
    if bytes.len() < 3 {
        return false;
    }
    matches!(bytes[0], b'\'' | b'"' | b'`') && bytes[1] == b'/'
}

#[derive(Debug, PartialEq, Eq)]
enum PathSegment {
    Literal(String),
    Dynamic,
}

fn path_segments(path: &str) -> Vec<PathSegment> {
    let path = path.find('?').map_or(path, |index| &path[..index]);
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment == ":" || segment.starts_with(':') {
                PathSegment::Dynamic
            } else {
                PathSegment::Literal(segment.to_string())
            }
        })
        .collect()
}

fn template_path_segments(template: &str) -> Vec<PathSegment> {
    path_segments(template)
}

fn expr_path_segments(expr: &str) -> Vec<PathSegment> {
    let bytes = expr.as_bytes();
    let mut normalized = String::new();
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => i = append_quoted_literal(expr, i, &mut normalized),
            b'`' => i = append_template_literal(expr, i, &mut normalized),
            b'+' | b' ' | b'\n' | b'\r' | b'\t' => i += 1,
            _ => {
                normalized.push(':');
                i = skip_dynamic_operand(bytes, i);
            }
        }
    }

    path_segments(&normalized)
}

fn append_quoted_literal(expr: &str, start: usize, normalized: &mut String) -> usize {
    let bytes = expr.as_bytes();
    let quote = bytes[start];
    let mut i = start + 1;

    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            if let Some(next) = bytes.get(i + 1) {
                normalized.push(*next as char);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if c == quote {
            return i + 1;
        }
        normalized.push(c as char);
        i += 1;
    }

    i
}

fn append_template_literal(expr: &str, start: usize, normalized: &mut String) -> usize {
    let bytes = expr.as_bytes();
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if let Some(next) = bytes.get(i + 1) {
                    normalized.push(*next as char);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'`' => return i + 1,
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                normalized.push(':');
                i = skip_template_placeholder(bytes, i + 2);
            }
            c => {
                normalized.push(c as char);
                i += 1;
            }
        }
    }

    i
}

fn skip_dynamic_operand(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = start;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth = depth.saturating_sub(1),
                b'+' if depth == 0 => return i,
                _ => {}
            }
        }
        i += 1;
    }

    i
}

fn skip_template_placeholder(bytes: &[u8], start: usize) -> usize {
    let mut depth = 1usize;
    let mut in_str: Option<u8> = None;
    let mut i = start;

    while i < bytes.len() && depth > 0 {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }

    i
}

/// Does the call's expression text contain the same ordered path
/// segments as `template`? Parameter segments (`:foo`) must be backed
/// by a dynamic expression segment in the GUI call.
fn expr_contains_template(expr: &str, template: &str) -> bool {
    expr_path_segments(expr) == template_path_segments(template)
}

fn gui_covers(method: Method, path: &str, calls: &[ApiCall]) -> bool {
    let wanted = format!("{method}");
    calls.iter().any(|c| {
        let method_matches = match &c.method {
            Some(m) => m.eq_ignore_ascii_case(&wanted),
            None => wanted == "GET",
        };
        method_matches && expr_contains_template(&c.expr, path)
    })
}

/// Named-groups endpoints enumerated from the registry at test time.
fn named_group_endpoints() -> Vec<(Method, &'static str)> {
    ENDPOINTS
        .iter()
        .filter(|e| e.category == "named-groups")
        .map(|e| (e.method, e.path))
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum GuiParityStatus {
    Wired,
    Deferred,
    Missing,
}

fn deferred_paths() -> HashSet<(String, String)> {
    DEFERRED
        .iter()
        .map(|(m, p, _)| (format!("{m}"), (*p).to_string()))
        .collect()
}

fn is_deferred(method: Method, path: &str, deferred: &HashSet<(String, String)>) -> bool {
    deferred.contains(&(format!("{method}"), path.to_string()))
}

fn classify_gui_endpoint(
    method: Method,
    path: &str,
    calls: &[ApiCall],
    deferred: &HashSet<(String, String)>,
) -> GuiParityStatus {
    if is_deferred(method, path, deferred) {
        GuiParityStatus::Deferred
    } else if gui_covers(method, path, calls) {
        GuiParityStatus::Wired
    } else {
        GuiParityStatus::Missing
    }
}

#[test]
fn expr_contains_template_matches_complete_path_segments() {
    assert!(!expr_contains_template("'/groups/cards/import'", "/groups"));
    assert!(!expr_contains_template("'/groups'", "/groups/:id"));
    assert!(expr_contains_template("'/groups/'+gid", "/groups/:id"));
    assert!(expr_contains_template(
        "`/groups/${gid}/members/${aid}/role`",
        "/groups/:id/members/:agent_id/role"
    ));
    assert!(expr_contains_template(
        "'/groups/discover?q='+encodeURIComponent(q)",
        "/groups/discover"
    ));
}

#[test]
fn gui_named_group_parity_against_manifest() {
    let all = named_group_endpoints();
    let call_sites = gui_api_calls();
    let deferred = deferred_paths();

    let mut covered = Vec::new();
    let mut deferred_seen = Vec::new();
    let mut missing = Vec::new();

    for (method, path) in &all {
        match classify_gui_endpoint(*method, path, &call_sites, &deferred) {
            GuiParityStatus::Wired => covered.push((*method, *path)),
            GuiParityStatus::Deferred => deferred_seen.push((*method, *path)),
            GuiParityStatus::Missing => missing.push((*method, *path)),
        }
    }

    // Warn (not fail) about DEFERRED entries so the gap stays visible
    // on every clean run.
    if !deferred_seen.is_empty() {
        eprintln!(
            "\n[gui_named_group_parity] {} named-groups endpoints are \
             DEFERRED in the embedded GUI (see tests/gui_named_group_parity.rs \
             DEFERRED and docs/proof/NAMED_GROUPS_PARITY_SIGNOFF.md):",
            deferred_seen.len()
        );
        for (method, path) in &deferred_seen {
            let reason = DEFERRED
                .iter()
                .find(|(m, p, _)| m == method && p == path)
                .map(|(_, _, r)| *r)
                .unwrap_or("—");
            eprintln!("  deferred: {method} {path}  ({reason})");
        }
        eprintln!(
            "Coverage: {}/{} wired in GUI, {} deferred, {} missing.\n",
            covered.len(),
            all.len(),
            deferred_seen.len(),
            missing.len()
        );
    }

    assert!(
        missing.is_empty(),
        "\n\nEmbedded GUI is missing API call sites for {} named-groups \
         endpoint(s) that are not listed in DEFERRED. Either wire the \
         endpoint in src/gui/x0x-gui.html or add a DEFERRED entry with \
         an explicit reason (and reflect it in the signoff doc):\n{}\n",
        missing.len(),
        missing
            .iter()
            .map(|(m, p)| format!("  {m} {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn deferred_entries_remain_deferred_when_a_gui_call_matches() {
    let deferred = deferred_paths();
    let method = Method::Post;
    let path = "/groups/:id/members";
    let calls = [ApiCall {
        expr: "'/groups/' + groupId + '/members'".to_string(),
        method: Some("POST".to_string()),
        options: String::new(),
        at: 0,
        end: 0,
    }];

    assert!(
        gui_covers(method, path, &calls),
        "mock call must match before this can prove classification order"
    );
    assert_eq!(
        classify_gui_endpoint(method, path, &calls, &deferred),
        GuiParityStatus::Deferred,
        "DEFERRED endpoints must remain visible as gaps until the entry is removed"
    );
}

/// Every DEFERRED entry must still point at a real named-groups
/// endpoint. Prevents stale entries hiding a rename.
#[test]
fn deferred_entries_reference_real_endpoints() {
    let valid: HashSet<(String, String)> = ENDPOINTS
        .iter()
        .filter(|e| e.category == "named-groups")
        .map(|e| (format!("{}", e.method), e.path.to_string()))
        .collect();

    let mut stale = Vec::new();
    for (method, path, reason) in DEFERRED {
        if !valid.contains(&(format!("{method}"), (*path).to_string())) {
            stale.push(format!("  stale deferred: {method} {path} — {reason}"));
        }
    }
    assert!(
        stale.is_empty(),
        "\n\nDEFERRED entries reference paths not in ENDPOINTS \
         (probably a rename — update both):\n{}\n",
        stale.join("\n")
    );
}

#[test]
fn gui_exposes_all_four_presets() {
    for preset in [
        "private_secure",
        "public_request_secure",
        "public_open",
        "public_announce",
    ] {
        assert!(
            GUI_HTML.contains(preset),
            "GUI must expose the '{preset}' preset in the create-space modal"
        );
    }
}

#[test]
fn gui_renders_discover_view() {
    assert!(
        GUI_HTML.contains("function renderDiscover()"),
        "GUI must define renderDiscover for the /discover navigation target"
    );
    assert!(
        GUI_HTML.contains("navigate('discover')"),
        "GUI sidebar must link to the discover view"
    );
}

#[test]
fn gui_renders_admin_controls_inline() {
    assert!(GUI_HTML.contains("nag-admin-"));
    assert!(GUI_HTML.contains("nagRenderAdmin"));
    assert!(GUI_HTML.contains("data-nag-policy-apply"));
    assert!(GUI_HTML.contains("data-nag-state-seal"));
    assert!(GUI_HTML.contains("data-nag-state-withdraw"));
}

fn registry_body_fields(
    method: Method,
    path: &str,
) -> Result<(Vec<&'static str>, Vec<&'static str>), String> {
    let endpoint = ENDPOINTS
        .iter()
        .find(|endpoint| endpoint.method == method && endpoint.path == path)
        .ok_or_else(|| format!("no endpoint {method} {path}"))?;
    let RequestSpec::Fields(fields) = endpoint.request else {
        return Err(format!("{method} {path} has no named field list"));
    };
    let body: Vec<_> = fields
        .iter()
        .filter(|field| field.location == FieldLocation::Body)
        .collect();
    let allowed: Vec<_> = body.iter().map(|field| field.name).collect();
    let required: Vec<_> = body
        .iter()
        .filter(|field| field.required)
        .map(|field| field.name)
        .collect();
    Ok((allowed, required))
}

fn body_contract_error(sent: &[&str], allowed: &[&str], required: &[&str]) -> Option<String> {
    let missing: Vec<_> = required
        .iter()
        .copied()
        .filter(|name| !sent.contains(name))
        .collect();
    let unknown: Vec<_> = sent
        .iter()
        .copied()
        .filter(|name| !allowed.contains(name))
        .collect();
    if missing.is_empty() && unknown.is_empty() {
        None
    } else {
        Some(format!(
            "missing required {missing:?}; unknown {unknown:?}; sent {sent:?}; allowed {allowed:?}"
        ))
    }
}

fn skip_ws(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn read_key(src: &str, start: usize) -> Result<(String, usize), String> {
    let bytes = src.as_bytes();
    let index = skip_ws(bytes, start);
    if index >= bytes.len() {
        return Err("missing object key".to_string());
    }
    let quote = bytes[index];
    if quote == b'\'' || quote == b'"' {
        let mut end = index + 1;
        while end < bytes.len() {
            if bytes[end] == b'\\' {
                end += 2;
                continue;
            }
            if bytes[end] == quote {
                return Ok((src[index + 1..end].to_string(), end + 1));
            }
            end += 1;
        }
        return Err("unterminated object key".to_string());
    }
    if !(quote.is_ascii_alphabetic() || quote == b'_' || quote == b'$') {
        return Err(format!("unsupported object key at '{}'", quote as char));
    }
    let mut end = index + 1;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'$')
    {
        end += 1;
    }
    Ok((src[index..end].to_string(), end))
}

fn read_value(src: &str, start: usize) -> Result<(String, usize), String> {
    let bytes = src.as_bytes();
    let value_start = skip_ws(bytes, start);
    let mut index = value_start;
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    while index < bytes.len() {
        let current = bytes[index];
        if let Some(quote) = in_str {
            if current == b'\\' {
                index += 2;
                continue;
            }
            if current == quote {
                in_str = None;
            }
            index += 1;
            continue;
        }
        match current {
            b'\'' | b'"' | b'`' => {
                in_str = Some(current);
                index += 1;
            }
            b'(' | b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b')' | b'}' | b']' if depth == 0 => break,
            b')' | b'}' | b']' => {
                depth -= 1;
                index += 1;
            }
            b',' if depth == 0 => break,
            _ => index += 1,
        }
    }
    if index == value_start {
        return Err("missing object value".to_string());
    }
    Ok((src[value_start..index].trim().to_string(), index))
}

fn parse_object_fields(src: &str) -> Result<(Vec<(String, String)>, usize), String> {
    let bytes = src.as_bytes();
    if bytes.first() != Some(&b'{') {
        return Err("object literal must start with '{'".to_string());
    }
    let mut index = 1usize;
    let mut fields = Vec::new();
    loop {
        index = skip_ws(bytes, index);
        if index >= bytes.len() {
            return Err("unterminated object literal".to_string());
        }
        if bytes[index] == b'}' {
            return Ok((fields, index + 1));
        }
        let (name, next) = read_key(src, index)?;
        index = skip_ws(bytes, next);
        let value = if index < bytes.len() && bytes[index] == b':' {
            index += 1;
            let (value, next) = read_value(src, index)?;
            index = next;
            value
        } else {
            name.clone()
        };
        fields.push((name, value));
        index = skip_ws(bytes, index);
        if index >= bytes.len() {
            return Err("unterminated object literal".to_string());
        }
        match bytes[index] {
            b',' => index += 1,
            b'}' => return Ok((fields, index + 1)),
            other => {
                return Err(format!(
                    "expected ',' or '}}' after a field, found '{}'",
                    other as char
                ));
            }
        }
    }
}

fn is_fn_start(bytes: &[u8], index: usize) -> bool {
    if index > 0 && bytes[index - 1] != b'\n' {
        return false;
    }
    let rest = &bytes[index..];
    rest.starts_with(b"async function ") || rest.starts_with(b"function ")
}

fn function_bounds(at: usize) -> (usize, usize) {
    let bytes = GUI_HTML.as_bytes();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < at && index < bytes.len() {
        if is_fn_start(bytes, index) {
            start = index;
        }
        index += 1;
    }
    let mut end = bytes.len();
    index = at.saturating_add(1);
    while index < bytes.len() {
        if is_fn_start(bytes, index) {
            end = index;
            break;
        }
        index += 1;
    }
    (start, end)
}

fn is_ident_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// Move `index` back to a UTF-8 boundary. Lookback windows subtract a
/// fixed byte count and can land inside a multibyte character.
fn char_floor(src: &str, mut index: usize) -> usize {
    if index > src.len() {
        index = src.len();
    }
    while index > 0 && !src.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn is_ident_at(src: &str, index: usize, ident: &str) -> bool {
    let bytes = src.as_bytes();
    // The scanners walk bytes. A multibyte character (for example an
    // em dash in a comment) is not an identifier start.
    if !src.is_char_boundary(index) || !src[index..].starts_with(ident) {
        return false;
    }
    let end = index + ident.len();
    let prev_ok = index == 0 || !is_ident_char(bytes[index - 1]);
    let next_ok = end >= bytes.len() || !is_ident_char(bytes[end]);
    prev_ok && next_ok
}

fn ident_at(src: &str, index: usize) -> Option<&str> {
    let bytes = src.as_bytes();
    if !src.is_char_boundary(index)
        || index >= bytes.len()
        || !is_ident_char(bytes[index])
        || bytes[index].is_ascii_digit()
    {
        return None;
    }
    let mut end = index + 1;
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }
    Some(&src[index..end])
}

fn trailing_ident(src: &str) -> Option<String> {
    let bytes = src.as_bytes();
    if bytes.is_empty() || !is_ident_char(*bytes.last()?) || bytes.last()?.is_ascii_digit() {
        return None;
    }
    let mut start = bytes.len();
    while start > 0 && is_ident_char(bytes[start - 1]) {
        start -= 1;
    }
    if bytes[start].is_ascii_digit() {
        return None;
    }
    Some(src[start..].to_string())
}

fn skip_js_string(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == quote {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn match_delim(src: &str, open_at: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = src.as_bytes();
    if bytes.get(open_at) != Some(&open) {
        return None;
    }
    let mut depth = 1usize;
    let mut index = open_at + 1;
    let mut in_str: Option<u8> = None;
    while index < bytes.len() && depth > 0 {
        let current = bytes[index];
        if let Some(quote) = in_str {
            if current == b'\\' {
                index += 2;
                continue;
            }
            if current == quote {
                in_str = None;
            }
            index += 1;
            continue;
        }
        match current {
            b'\'' | b'"' => {
                index = skip_js_string(bytes, index);
            }
            b'`' => index = skip_template_bytes(bytes, index),
            found if found == open => {
                depth += 1;
                index += 1;
            }
            found if found == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn skip_template_bytes(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == b'`' {
            return index + 1;
        }
        if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'{') {
            let Some(end) = match_delim(
                std::str::from_utf8(&bytes[index + 1..]).unwrap_or(""),
                0,
                b'{',
                b'}',
            ) else {
                return bytes.len();
            };
            index = index + 1 + end + 1;
            continue;
        }
        index += 1;
    }
    bytes.len()
}

fn arrow_shadows(src: &str, arrow_at: usize, binding: &str) -> bool {
    let before = src[..arrow_at].trim_end();
    if let Some(close) = before
        .len()
        .checked_sub(1)
        .filter(|_| before.ends_with(')'))
    {
        let Some(open) = before[..close].rfind('(') else {
            return false;
        };
        let params = &before[open + 1..close];
        return params.split(',').any(|param| param.trim() == binding);
    }
    trailing_ident(before).as_deref() == Some(binding)
}

fn skip_arrow_body(src: &str, start: usize) -> usize {
    let bytes = src.as_bytes();
    let rest = src[start..].trim_start();
    let at = start + (src[start..].len() - rest.len());
    if rest.starts_with('{') {
        return match_delim(src, at, b'{', b'}')
            .map(|index| index + 1)
            .unwrap_or(bytes.len());
    }
    let mut index = at;
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    while index < bytes.len() {
        let current = bytes[index];
        if let Some(quote) = in_str {
            if current == b'\\' {
                index += 2;
                continue;
            }
            if current == quote {
                in_str = None;
            }
            index += 1;
            continue;
        }
        match current {
            b'\'' | b'"' => index = skip_js_string(bytes, index),
            b'`' => index = skip_template_bytes(bytes, index),
            b'(' | b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b')' | b'}' | b']' if depth == 0 => return index,
            b')' | b'}' | b']' => {
                depth -= 1;
                index += 1;
            }
            b',' | b';' if depth == 0 => return index,
            _ => index += 1,
        }
    }
    bytes.len()
}

fn collect_props(src: &str, binding: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let mut index = 0usize;
    let mut found = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                index = skip_js_string(bytes, index);
                continue;
            }
            b'`' => {
                index = collect_template_props(src, index, binding, &mut found);
                continue;
            }
            b'=' if bytes.get(index + 1) == Some(&b'>') && arrow_shadows(src, index, binding) => {
                index = skip_arrow_body(src, index + 2);
                continue;
            }
            _ => {}
        }
        if is_ident_at(src, index, binding) {
            let after = index + binding.len();
            let (prop_at, prop_off) =
                if bytes.get(after) == Some(&b'?') && bytes.get(after + 1) == Some(&b'.') {
                    (after + 2, 2)
                } else if bytes.get(after) == Some(&b'.') {
                    (after + 1, 1)
                } else {
                    index = after;
                    continue;
                };
            if let Some(prop) = ident_at(src, prop_at) {
                if !found.contains(&prop.to_string()) {
                    found.push(prop.to_string());
                }
                index = after + prop_off + prop.len();
                continue;
            }
        }
        index += 1;
    }
    found
}

fn collect_template_props(
    src: &str,
    start: usize,
    binding: &str,
    found: &mut Vec<String>,
) -> usize {
    let bytes = src.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == b'`' {
            return index + 1;
        }
        if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'{') {
            let expr_start = index + 2;
            let Some(expr_end) = match_delim(src, index + 1, b'{', b'}') else {
                return bytes.len();
            };
            for prop in collect_props(&src[expr_start..expr_end], binding) {
                if !found.contains(&prop) {
                    found.push(prop);
                }
            }
            index = expr_end + 1;
            continue;
        }
        index += 1;
    }
    bytes.len()
}

fn assigned_binding(before: &str) -> Option<String> {
    let trimmed = before.trim_end();
    let trimmed = trimmed.strip_suffix("await").unwrap_or(trimmed).trim_end();
    let trimmed = trimmed.strip_suffix('=')?;
    if before.trim_end().ends_with("==") || before.trim_end().ends_with("=>") {
        return None;
    }
    let ident = trailing_ident(trimmed.trim_end())?;
    if matches!(ident.as_str(), "const" | "let" | "var" | "await" | "return") {
        None
    } else {
        Some(ident)
    }
}

fn destructured_names(head: &str) -> Option<Vec<String>> {
    let eq = head.rfind('=')?;
    let before_eq = head[..eq].trim_end();
    if !before_eq.ends_with(']') {
        return None;
    }
    let close = before_eq.len() - 1;
    let open = before_eq[..close].rfind('[')?;
    let names: Vec<String> = before_eq[open + 1..close]
        .split(',')
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

fn count_daemon_calls(src: &str) -> usize {
    let bytes = src.as_bytes();
    let mut count = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if call_name_at(bytes, index).is_some() {
            count += 1;
        }
        index += 1;
    }
    count
}

fn promise_all_binding(call: &ApiCall) -> Option<(String, usize)> {
    let search_from = char_floor(GUI_HTML, call.at.saturating_sub(1500));
    let before = &GUI_HTML[search_from..call.at];
    let marker = "Promise.all([";
    let rel = before.rfind(marker)?;
    let abs = search_from + rel;
    let bracket = abs + marker.len() - 1;
    let close = match_delim(GUI_HTML, bracket, b'[', b']')?;
    if close < call.at {
        return None;
    }
    let index = count_daemon_calls(&GUI_HTML[bracket + 1..call.at]);
    let head = &GUI_HTML[char_floor(GUI_HTML, abs.saturating_sub(300))..abs];
    let names = destructured_names(head)?;
    let name = names.get(index)?.clone();
    Some((name, close + 1))
}

fn then_callback(call: &ApiCall) -> Option<(String, usize, usize)> {
    let tail = &GUI_HTML[call.end..];
    let trimmed = tail.trim_start();
    if !trimmed.starts_with(".then(") {
        return None;
    }
    let then_at = call.end + (tail.len() - trimmed.len()) + ".then(".len();
    let args = GUI_HTML[then_at..].trim_start();
    let args_at = then_at + (GUI_HTML[then_at..].len() - args.len());
    let (name, arrow_rel) = if let Some(ident) = ident_at(args, 0) {
        let after = args[ident.len()..].trim_start();
        if !after.starts_with("=>") {
            return None;
        }
        let arrow = args_at + ident.len() + (args[ident.len()..].len() - after.len());
        (ident.to_string(), arrow)
    } else if args.starts_with('(') {
        let close = match_delim(GUI_HTML, args_at, b'(', b')')?;
        let params = &GUI_HTML[args_at + 1..close];
        let name = params.split(',').next()?.trim();
        if name.is_empty() || name.contains(' ') {
            return None;
        }
        let after = GUI_HTML[close + 1..].trim_start();
        if !after.starts_with("=>") {
            return None;
        }
        let arrow = close + 1 + (GUI_HTML[close + 1..].len() - after.len());
        (name.to_string(), arrow)
    } else {
        return None;
    };
    let body_at = arrow_rel + 2;
    let body = GUI_HTML[body_at..].trim_start();
    let body_off = body_at + (GUI_HTML[body_at..].len() - body.len());
    let end = if body.starts_with('{') {
        match_delim(GUI_HTML, body_off, b'{', b'}')? + 1
    } else {
        skip_arrow_body(GUI_HTML, body_off)
    };
    Some((name, body_off, end))
}

fn reassign_end(src: &str, binding: &str) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                index = skip_js_string(bytes, index);
                continue;
            }
            b'`' => {
                index = skip_template_bytes(bytes, index);
                continue;
            }
            _ => {}
        }
        if is_ident_at(src, index, binding) {
            let after = index + binding.len();
            let rest = src[after..].trim_start();
            if rest.starts_with('=') && !rest.starts_with("==") && !rest.starts_with("=>") {
                return Some(after);
            }
            index = after;
            continue;
        }
        index += 1;
    }
    None
}

fn response_reads(call: &ApiCall) -> Vec<String> {
    if let Some((binding, start, end)) = then_callback(call) {
        return collect_props(&GUI_HTML[start..end], &binding)
            .into_iter()
            .filter(|name| !is_envelope(name))
            .collect();
    }
    let (binding, window_start) = if let Some((name, after_all)) = promise_all_binding(call) {
        (name, after_all)
    } else {
        let before = &GUI_HTML[char_floor(GUI_HTML, call.at.saturating_sub(80))..call.at];
        let Some(name) = assigned_binding(before) else {
            return Vec::new();
        };
        (name, call.end)
    };
    let (_, fn_end) = function_bounds(call.at);
    if window_start >= fn_end {
        return Vec::new();
    }
    let window = &GUI_HTML[window_start..fn_end];
    let end = reassign_end(window, &binding).unwrap_or(window.len());
    collect_props(&window[..end], &binding)
        .into_iter()
        .filter(|name| !is_envelope(name))
        .collect()
}

fn is_envelope(name: &str) -> bool {
    matches!(
        name,
        "ok" | "error" | "reason" | "message" | "_http_ok" | "_http_status"
    )
}

fn body_argument(options: &str) -> Option<&str> {
    let search_from = options.find("body:").unwrap_or(0);
    let marker = "JSON.stringify(";
    let rel = options[search_from..].find(marker)?;
    let start = search_from + rel + marker.len();
    Some(options[start..].trim_start())
}

enum BodyContract {
    Passthrough,
    Named {
        allowed: Vec<&'static str>,
        required: Vec<&'static str>,
    },
}

fn body_contract(method: Method, path: &str) -> Result<BodyContract, String> {
    let endpoint = ENDPOINTS
        .iter()
        .find(|endpoint| endpoint.method == method && endpoint.path == path)
        .ok_or_else(|| format!("no endpoint {method} {path}"))?;
    match endpoint.request {
        RequestSpec::Passthrough => Ok(BodyContract::Passthrough),
        RequestSpec::None => Ok(BodyContract::Named {
            allowed: Vec::new(),
            required: Vec::new(),
        }),
        RequestSpec::Fields(fields) => {
            let body: Vec<_> = fields
                .iter()
                .filter(|field| field.location == FieldLocation::Body)
                .collect();
            Ok(BodyContract::Named {
                allowed: body.iter().map(|field| field.name).collect(),
                required: body
                    .iter()
                    .filter(|field| field.required)
                    .map(|field| field.name)
                    .collect(),
            })
        }
    }
}

/// A literal segment may fill a `:param` (for example the store key
/// `channels_index`). A dynamic segment still cannot fill a fixed
/// segment, so `/groups/cards/import` does not match `/groups/:id`.
fn expr_fills_template(expr: &str, template: &str) -> bool {
    let call = expr_path_segments(expr);
    let route = template_path_segments(template);
    if call.len() != route.len() {
        return false;
    }
    call.iter()
        .zip(route)
        .all(|(left, right)| match (left, right) {
            (PathSegment::Literal(left), PathSegment::Literal(right)) => left == &right,
            (_, PathSegment::Dynamic) => true,
            (PathSegment::Dynamic, PathSegment::Literal(_)) => false,
        })
}

fn endpoint_for(call: &ApiCall) -> Result<(Method, &'static str), String> {
    let wanted = call.method.as_deref().unwrap_or("GET");
    let same_method =
        |endpoint: &&EndpointDef| endpoint.method.to_string().eq_ignore_ascii_case(wanted);
    let strict: Vec<_> = ENDPOINTS
        .iter()
        .filter(same_method)
        .filter(|endpoint| expr_contains_template(&call.expr, endpoint.path))
        .collect();
    let matches = if strict.is_empty() {
        ENDPOINTS
            .iter()
            .filter(same_method)
            .filter(|endpoint| expr_fills_template(&call.expr, endpoint.path))
            .collect()
    } else {
        strict
    };
    match matches.len() {
        1 => Ok((matches[0].method, matches[0].path)),
        0 => Err(format!("no endpoint for {wanted} {}", call.expr)),
        count => Err(format!("{count} endpoints match {wanted} {}", call.expr)),
    }
}

fn select_data_keys() -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = GUI_HTML;
    while let Some(rel) = rest.find("<select") {
        let end = rest[rel..]
            .find('>')
            .map(|index| rel + index)
            .unwrap_or(rest.len());
        let tag = &rest[rel..end];
        if let Some(value) = tag_attr(tag, "data-k") {
            if !keys.contains(&value) {
                keys.push(value);
            }
        }
        rest = &rest[end..];
    }
    keys
}

fn tag_attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

enum IdentAssign {
    Object(Vec<(String, String)>),
    Parse(Option<String>),
    Prop(String),
    DynamicSelect,
}

fn ident_events(prefix: &str, ident: &str) -> Result<Vec<IdentAssign>, String> {
    let bytes = prefix.as_bytes();
    let mut index = 0usize;
    let mut events = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                index = skip_js_string(bytes, index);
                continue;
            }
            b'`' => {
                index = skip_template_bytes(bytes, index);
                continue;
            }
            _ => {}
        }
        if !is_ident_at(prefix, index, ident) {
            index += 1;
            continue;
        }
        let after = index + ident.len();
        let rest = prefix[after..].trim_start();
        let gap = prefix[after..].len() - rest.len();
        if let Some(stripped) = rest.strip_prefix('.') {
            let prop_src = stripped.trim_start();
            if let Some(prop) = ident_at(prop_src, 0) {
                let after_prop = prop_src[prop.len()..].trim_start();
                if after_prop.starts_with('=')
                    && !after_prop.starts_with("==")
                    && !after_prop.starts_with("=>")
                {
                    events.push(IdentAssign::Prop(prop.to_string()));
                }
            }
            index = after + gap + 1;
            continue;
        }
        if rest.starts_with('[') {
            let open = after + gap;
            if let Some(close) = match_delim(prefix, open, b'[', b']') {
                let inside = &prefix[open..=close];
                if inside.contains("data-k") {
                    events.push(IdentAssign::DynamicSelect);
                }
                index = close + 1;
                continue;
            }
        }
        if rest.starts_with('=') && !rest.starts_with("==") && !rest.starts_with("=>") {
            let rhs = rest[1..].trim_start();
            if rhs.starts_with('{') {
                let abs = after + gap + 1 + (rest[1..].len() - rhs.len());
                let (fields, consumed) = parse_object_fields(&prefix[abs..])?;
                events.push(IdentAssign::Object(fields));
                index = abs + consumed;
                continue;
            }
            if rhs.starts_with("JSON.parse") {
                let snippet = &rhs[..rhs.len().min(240)];
                events.push(IdentAssign::Parse(element_id_in(snippet)));
            }
        }
        index = after;
    }
    Ok(events)
}

fn element_id_in(src: &str) -> Option<String> {
    for needle in ["getElementById('", "getElementById(\""] {
        if let Some(rel) = src.find(needle) {
            let start = rel + needle.len();
            let quote = needle.as_bytes()[needle.len() - 1];
            let end = src.as_bytes()[start..]
                .iter()
                .position(|byte| *byte == quote)?;
            return Some(src[start..start + end].to_string());
        }
    }
    None
}

struct SentBody {
    keys: Vec<String>,
    values: Vec<(String, String)>,
    operator_element: Option<String>,
}

fn sent_body(call: &ApiCall) -> Result<Option<SentBody>, String> {
    let Some(arg) = body_argument(&call.options) else {
        return Ok(None);
    };
    if arg.starts_with('{') {
        let (fields, _) = parse_object_fields(arg)?;
        return Ok(Some(SentBody {
            keys: fields.iter().map(|(name, _)| name.clone()).collect(),
            values: fields,
            operator_element: None,
        }));
    }
    let Some(ident) = ident_at(arg, 0) else {
        return Err("JSON.stringify argument is not an object or a name".to_string());
    };
    let (fn_start, _) = function_bounds(call.at);
    let events = ident_events(&GUI_HTML[fn_start..call.at], ident)?;
    let mut base_at = None;
    for (index, event) in events.iter().enumerate().rev() {
        if matches!(event, IdentAssign::Object(_) | IdentAssign::Parse(_)) {
            base_at = Some(index);
            break;
        }
    }
    let Some(base_at) = base_at else {
        return Err(format!("cannot see the object assigned to {ident}"));
    };
    let values = match &events[base_at] {
        IdentAssign::Parse(element) => {
            return Ok(Some(SentBody {
                keys: Vec::new(),
                values: Vec::new(),
                operator_element: element.clone(),
            }));
        }
        IdentAssign::Object(fields) => fields.clone(),
        IdentAssign::Prop(_) | IdentAssign::DynamicSelect => {
            return Err(format!("{ident} has no object before the call"));
        }
    };
    let mut keys: Vec<String> = values.iter().map(|(name, _)| name.clone()).collect();
    for event in events.iter().skip(base_at + 1) {
        match event {
            IdentAssign::Prop(name) if !keys.contains(name) => keys.push(name.clone()),
            IdentAssign::DynamicSelect => {
                for name in select_data_keys() {
                    if !keys.contains(&name) {
                        keys.push(name);
                    }
                }
            }
            IdentAssign::Object(_) | IdentAssign::Parse(_) | IdentAssign::Prop(_) => {}
        }
    }
    Ok(Some(SentBody {
        keys,
        values,
        operator_element: None,
    }))
}

fn placeholder_keys(id: &str) -> Result<Vec<String>, String> {
    let double = format!("id=\"{id}\"");
    let single = format!("id='{id}'");
    let pos = GUI_HTML
        .find(&double)
        .or_else(|| GUI_HTML.find(&single))
        .ok_or_else(|| format!("no element id {id}"))?;
    // The placeholder belongs to this tag. A nearby textarea must not
    // supply its keys.
    let tag_start = GUI_HTML[..pos]
        .rfind('<')
        .ok_or_else(|| format!("{id} is not inside a tag"))?;
    let tag_end = GUI_HTML[pos..]
        .find('>')
        .map(|index| pos + index)
        .ok_or_else(|| format!("{id} tag is not closed"))?;
    let tag = &GUI_HTML[tag_start..tag_end];
    let (rel, quote) = if let Some(found) = tag.find("placeholder='") {
        (found + "placeholder='".len(), b'\'')
    } else if let Some(found) = tag.find("placeholder=\"") {
        (found + "placeholder=\"".len(), b'"')
    } else {
        return Err(format!("{id} has no placeholder"));
    };
    let value = &tag[rel..];
    let close = value
        .bytes()
        .position(|byte| byte == quote)
        .ok_or_else(|| format!("{id} placeholder is unterminated"))?;
    let placeholder = &value[..close];
    if !placeholder.trim_start().starts_with('{') {
        return Err(format!("{id} placeholder is not a JSON object"));
    }
    let (fields, _) = parse_object_fields(placeholder.trim_start())?;
    Ok(fields.into_iter().map(|(name, _)| name).collect())
}

fn objects_written_to(id: &str) -> Result<Vec<Vec<String>>, String> {
    let mut found = Vec::new();
    for needle in [
        format!("getElementById('{id}')"),
        format!("getElementById(\"{id}\")"),
    ] {
        let mut search_from = 0usize;
        while let Some(rel) = GUI_HTML[search_from..].find(&needle) {
            let after = search_from + rel + needle.len();
            let rest = GUI_HTML[after..].trim_start();
            if let Some(assigned) = rest.strip_prefix(".value") {
                let assigned = assigned.trim_start();
                if let Some(rhs) = assigned.strip_prefix('=') {
                    let rhs = rhs.trim_start();
                    if let Some(arg) = rhs.strip_prefix("JSON.stringify(") {
                        let arg = arg.trim_start();
                        if arg.starts_with('{') {
                            let (fields, _) = parse_object_fields(arg)?;
                            found.push(fields.into_iter().map(|(name, _)| name).collect());
                        }
                    }
                }
            }
            search_from = after;
        }
    }
    Ok(found)
}

fn value_is_u8encode(call: &ApiCall, value: &str) -> bool {
    if value.contains("u8encode(") {
        return true;
    }
    let Some(ident) = ident_at(value.trim_start(), 0) else {
        return false;
    };
    if value.trim() != ident {
        return false;
    }
    let (fn_start, _) = function_bounds(call.at);
    let prefix = &GUI_HTML[fn_start..call.at];
    let marker = format!("{ident}=");
    prefix.match_indices(&marker).any(|(index, _)| {
        let prev_ok = index == 0 || !is_ident_char(prefix.as_bytes()[index - 1]);
        prev_ok
            && prefix[index + marker.len()..]
                .trim_start()
                .starts_with("u8encode(")
    })
}

fn requires_u8encode(method: Method, path: &str, field: &str) -> bool {
    matches!(
        (method, path, field),
        (Method::Post, "/mls/groups/:id/encrypt", "payload")
            | (Method::Post, "/groups/:id/secure/encrypt", "payload_b64")
            | (Method::Post, "/agent/sign", "payload_b64")
    )
}

fn check_keys(method: Method, path: &str, keys: &[String]) -> Result<(), String> {
    let BodyContract::Named { allowed, required } = body_contract(method, path)? else {
        return Ok(());
    };
    let sent: Vec<&str> = keys.iter().map(String::as_str).collect();
    if let Some(error) = body_contract_error(&sent, &allowed, &required) {
        return Err(format!("{method} {path}: {error}"));
    }
    Ok(())
}

fn check_request(call: &ApiCall, method: Method, path: &str) -> Result<(), String> {
    let Some(sent) = sent_body(call)? else {
        return Ok(());
    };
    if matches!(body_contract(method, path)?, BodyContract::Passthrough) {
        return Ok(());
    }
    if let Some(id) = &sent.operator_element {
        let keys = placeholder_keys(id)?;
        check_keys(method, path, &keys).map_err(|error| format!("{id} placeholder: {error}"))?;
        for written in objects_written_to(id)? {
            check_keys(method, path, &written).map_err(|error| format!("{id} writer: {error}"))?;
        }
        return Ok(());
    }
    check_keys(method, path, &sent.keys)?;
    for (name, value) in &sent.values {
        if requires_u8encode(method, path, name) && !value_is_u8encode(call, value) {
            return Err(format!(
                "{method} {path}: {name} must be standard base64 via u8encode, got {value}"
            ));
        }
    }
    Ok(())
}

/// Success JSON names the GUI may read, besides `ok`, `error`, `reason`,
/// and `message`. These are the handler's top-level keys (`ApiResponse`
/// flattens `data`). A read that is not listed fails the parity test.
fn response_fields(method: Method, path: &str) -> &'static [&'static str] {
    const FIELDS: &[(Method, &str, &[&str])] = &[
        (
            Method::Post,
            "/auth/session/refresh",
            &["session_token", "expires_in"],
        ),
        (
            Method::Get,
            "/agent",
            &[
                "agent_id",
                "machine_id",
                "user_id",
                "kem_public_key_b64",
                "human_name",
                "display_name",
                "machine_name",
            ],
        ),
        (
            Method::Get,
            "/home",
            &[
                "group_id",
                "human_name",
                "primary_agent",
                "warnings",
                "name",
            ],
        ),
        (
            Method::Get,
            "/groups/:id",
            &[
                "chat_topic",
                "policy",
                "group_id",
                "name",
                "description",
                "member_count",
                "creator",
                "members",
                "membership_state",
            ],
        ),
        (Method::Get, "/groups/:id/state", &["group_id"]),
        (Method::Get, "/groups/:id/members", &["members"]),
        (Method::Get, "/groups/:id/requests", &["requests"]),
        (Method::Get, "/groups", &["groups"]),
        (Method::Post, "/groups", &["group_id", "policy"]),
        (Method::Post, "/groups/join", &["group_id", "group_name"]),
        (Method::Post, "/groups/cards/import", &["group_id"]),
        (Method::Post, "/groups/:id/invite", &["invite_link"]),
        (Method::Delete, "/groups/:id", &["deleted"]),
        (Method::Get, "/groups/discover", &["groups"]),
        (Method::Get, "/groups/discover/nearby", &["groups"]),
        (
            Method::Get,
            "/health",
            &[
                "status",
                "version",
                "peers",
                "uptime_secs",
                "send_ready_peers",
            ],
        ),
        (Method::Get, "/agents/discovered", &["agents"]),
        (
            Method::Get,
            "/upgrade",
            &["update_available", "current_version", "version"],
        ),
        (
            Method::Post,
            "/upgrade/apply",
            &[
                "applied",
                "version",
                "previous_version",
                "restart_scheduled",
                "rolled_back",
            ],
        ),
        (Method::Get, "/agent/card", &["link"]),
        (
            Method::Post,
            "/agent/card/import",
            &["display_name", "agent_id", "trust_level"],
        ),
        (Method::Post, "/groups/:id/send", &[]),
        (Method::Get, "/groups/:id/messages", &["messages"]),
        (Method::Get, "/task-lists", &["task_lists"]),
        (
            Method::Get,
            "/task-lists/:id/tasks",
            &["tasks", "board_migration_pending"],
        ),
        (Method::Get, "/files/transfers", &["transfers"]),
        (
            Method::Post,
            "/groups/:id/stores",
            &["id", "topic", "store_id"],
        ),
        (
            Method::Get,
            "/groups/:id/stores/:app/legacy-imports",
            &["candidates"],
        ),
        (
            Method::Post,
            "/groups/:id/stores/:app/legacy-imports/:source_id",
            &["imported_locally", "publish_accepted"],
        ),
        (
            Method::Get,
            "/groups/:id/stores/:app/legacy-imports/:source_id",
            &["snapshot_b64", "source_store_id", "source_digest"],
        ),
        (Method::Get, "/stores/:id/:key", &["value", "published"]),
        (Method::Put, "/stores/:id/:key", &["published"]),
        (Method::Get, "/stores/:id/keys", &["keys"]),
        (
            Method::Post,
            "/direct/send",
            &[
                "require_ack",
                "path",
                "retries_used",
                "request_id",
                "observed_ack_ingress",
            ],
        ),
        (Method::Get, "/contacts", &["contacts"]),
        (Method::Get, "/contacts/:agent_id/machines", &["machines"]),
        (
            Method::Get,
            "/contacts/:agent_id/revocations",
            &["revocations"],
        ),
        (Method::Post, "/machines/connect", &["outcome"]),
        (Method::Get, "/machines/discovered", &["machines"]),
        (Method::Get, "/users/:user_id/agents", &["agents"]),
        (
            Method::Get,
            "/users/:user_id/machines",
            &["machines", "user_id"],
        ),
        (
            Method::Get,
            "/network/status",
            &[
                "direct_connections",
                "relayed_connections",
                "avg_rtt_ms",
                "external_addrs",
            ],
        ),
        (
            Method::Get,
            "/diagnostics/connectivity",
            &[
                "nat_type",
                "can_receive_direct",
                "relay",
                "coordinator",
                "mdns",
                "port_mapping",
                "transport_environment",
            ],
        ),
        (Method::Get, "/peers", &["peers"]),
        (
            Method::Get,
            "/network/bootstrap-cache",
            &["connected_peers", "connection_count"],
        ),
        (Method::Get, "/diagnostics/transport", &["transport"]),
        (
            Method::Get,
            "/diagnostics/gossip",
            &["stats", "leaf_egress"],
        ),
        (Method::Get, "/presence/online", &["agents"]),
        (Method::Get, "/presence/foaf", &["agents"]),
        (Method::Get, "/presence/find/:id", &["agent"]),
        (Method::Get, "/presence/status/:id", &["online", "agent"]),
        (
            Method::Get,
            "/agents/discovered/:agent_id",
            &["agent_id", "reachable", "addresses", "via"],
        ),
        (
            Method::Get,
            "/agents/reachability/:agent_id",
            &["online", "reachable", "last_beacon_secs", "trust_level"],
        ),
        (Method::Get, "/mls/groups", &["groups"]),
        (
            Method::Post,
            "/mls/groups",
            &["group_id", "epoch", "members"],
        ),
        (
            Method::Get,
            "/mls/groups/:id",
            &["group_id", "epoch", "members"],
        ),
        (
            Method::Post,
            "/mls/groups/:id/encrypt",
            &["ciphertext", "epoch"],
        ),
        (Method::Post, "/mls/groups/:id/decrypt", &["payload"]),
        (
            Method::Post,
            "/groups/:id/secure/encrypt",
            &["ciphertext_b64", "nonce_b64", "secret_epoch"],
        ),
        (
            Method::Post,
            "/groups/:id/secure/decrypt",
            &["payload_b64", "secret_epoch"],
        ),
        (
            Method::Post,
            "/groups/:id/secure/reseal",
            &[
                "group_id",
                "recipient",
                "secret_epoch",
                "kem_ciphertext_b64",
                "aead_nonce_b64",
                "aead_ciphertext_b64",
            ],
        ),
        (Method::Get, "/sync/devices", &["devices"]),
        (
            Method::Get,
            "/constitution/json",
            &["version", "status", "content"],
        ),
    ];
    FIELDS
        .iter()
        .find(|(seen_method, seen_path, _)| *seen_method == method && *seen_path == path)
        .map(|(_, _, fields)| *fields)
        .unwrap_or(&[])
}

fn check_call(call: &ApiCall) -> Result<(), String> {
    let has_body = body_argument(&call.options).is_some();
    let reads = response_reads(call);
    if !has_body && reads.is_empty() {
        return Ok(());
    }
    let (method, path) = endpoint_for(call)?;
    if has_body {
        check_request(call, method, path)?;
    }
    let allowed = response_fields(method, path);
    let unknown: Vec<_> = reads
        .iter()
        .filter(|name| !allowed.contains(&name.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "{method} {path} reads {unknown:?}; response contract is {allowed:?}"
        ));
    }
    Ok(())
}

#[test]
fn object_literal_keys_cover_shorthand_and_explicit_fields() {
    let shorthand = parse_object_fields("{plaintext}").expect("shorthand object");
    assert_eq!(
        shorthand.0,
        vec![("plaintext".to_string(), "plaintext".to_string())]
    );
    let encoded = parse_object_fields("{payload:u8encode(plaintext)}").expect("explicit object");
    assert_eq!(
        encoded.0,
        vec![("payload".to_string(), "u8encode(plaintext)".to_string())]
    );
    let display = parse_object_fields("{display_name: name}").expect("display name object");
    assert_eq!(
        display.0,
        vec![("display_name".to_string(), "name".to_string())]
    );
    let name = parse_object_fields("{name}").expect("name shorthand");
    assert_eq!(name.0, vec![("name".to_string(), "name".to_string())]);
}

#[test]
fn issue_1399_old_body_keys_do_not_match_the_routes() {
    let (allowed, required) =
        registry_body_fields(Method::Post, "/mls/groups/:id/encrypt").expect("encrypt fields");
    let encrypt = body_contract_error(&["plaintext"], &allowed, &required);
    assert!(
        encrypt.is_some(),
        "plaintext must not satisfy the payload field"
    );

    let (allowed, required) =
        registry_body_fields(Method::Put, "/groups/:id/display-name").expect("display-name fields");
    let display = body_contract_error(&["display_name"], &allowed, &required);
    assert!(
        display.is_some(),
        "display_name must not satisfy the name field"
    );

    let (allowed, required) =
        registry_body_fields(Method::Post, "/groups/:id/secure/encrypt").expect("secure encrypt");
    assert!(
        body_contract_error(&["plaintext"], &allowed, &required).is_some(),
        "plaintext must not satisfy payload_b64"
    );
    let (allowed, required) =
        registry_body_fields(Method::Post, "/groups/:id/secure/reseal").expect("secure reseal");
    assert!(
        body_contract_error(&["plaintext"], &allowed, &required).is_some(),
        "plaintext must not satisfy recipient"
    );
    assert!(response_fields(Method::Post, "/mls/groups/:id/decrypt").contains(&"payload"));
    assert!(!response_fields(Method::Post, "/mls/groups/:id/decrypt").contains(&"plaintext"));
    assert!(response_fields(Method::Post, "/groups/:id/secure/decrypt").contains(&"payload_b64"));
    assert!(!response_fields(Method::Post, "/groups/:id/secure/decrypt").contains(&"plaintext"));
}

fn js_function(name: &str) -> String {
    let marker = format!("function {name}(");
    let start = GUI_HTML
        .find(&marker)
        .unwrap_or_else(|| panic!("GUI is missing {name}"));
    let brace = GUI_HTML[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("{name} has no body"));
    let end = match_delim(GUI_HTML, brace, b'{', b'}')
        .unwrap_or_else(|| panic!("{name} body does not close"));
    GUI_HTML[start..=end].to_string()
}

#[test]
fn get_group_detail_renders_the_handler_response() {
    let fields = response_fields(Method::Get, "/groups/:id");
    for absent in ["policy_summary", "mls_group_id", "display_names"] {
        assert!(
            !fields.contains(&absent),
            "GET /groups/:id does not return {absent}"
        );
    }
    assert!(fields.contains(&"policy"));
    assert!(fields.contains(&"members"));

    let render = js_function("renderSpaceDetail");
    assert!(
        render.contains("spaceDetailEncryptedBadge(g)"),
        "the space pane must paint the badge from the handler policy"
    );
    assert!(
        render.contains("spaceOwnDisplayName(g,S.get('agentId'))"),
        "the space pane must fill the name from the caller's member row"
    );
    assert!(
        !render.contains("mls_group_id") && !render.contains("display_names"),
        "renderSpaceDetail still reads a field GET /groups/:id does not return"
    );

    let src = format!(
        "{}\n{}\n",
        js_function("spaceDetailEncryptedBadge"),
        js_function("spaceOwnDisplayName")
    );
    let dir = std::env::temp_dir().join(format!("x0x-gui-1399-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let fns = dir.join("fns.js");
    let run = dir.join("run.js");
    std::fs::write(&fns, src).expect("write functions");
    std::fs::write(
        &run,
        r#"
const fs = require('node:fs');
const vm = require('node:vm');
const src = fs.readFileSync(process.env.FNS, 'utf8');
const handler = {
  ok: true,
  group_id: 'aabb',
  membership_state: 'active',
  name: 'Lab',
  description: 'notes',
  creator: 'cc',
  chat_topic: 'topic',
  withdrawn: false,
  policy: {
    discoverability: 'hidden',
    admission: 'invite_only',
    confidentiality: 'mls_encrypted',
    read_access: 'members_only',
    write_access: 'members_only'
  },
  member_count: 2,
  members: [
    { agent_id: 'bob', role: 'member', state: 'active', display_name: 'Bob', joined_at: 1, added_by: null },
    { agent_id: 'ada', role: 'owner', state: 'active', display_name: 'Ada', joined_at: 1, added_by: null }
  ]
};
const signed = JSON.parse(JSON.stringify(handler));
signed.policy.confidentiality = 'signed_public';
const alias = {
  ok: true,
  mls_group_id: 'dead',
  display_names: { ada: 'Ada' },
  policy_summary: { confidentiality: 'mls_encrypted' }
};
const empty = JSON.parse(JSON.stringify(handler));
empty.members[1].display_name = '';
const result = {};
vm.runInNewContext(src + `
  result.encrypted = spaceDetailEncryptedBadge(handler);
  result.signed = spaceDetailEncryptedBadge(signed);
  result.alias = spaceDetailEncryptedBadge(alias);
  result.name = spaceOwnDisplayName(handler, 'ada');
  result.aliasName = spaceOwnDisplayName(alias, 'ada');
  result.empty = spaceOwnDisplayName(empty, 'ada');
`, { handler, signed, alias, empty, result });
const banned = ['policy_summary', 'mls_group_id', 'display_names'];
result.handlerHasAlias = banned.some((key) => Object.prototype.hasOwnProperty.call(handler, key));
console.log(JSON.stringify(result));
"#,
    )
    .expect("write node driver");
    let output = std::process::Command::new("node")
        .arg(&run)
        .env("FNS", &fns)
        .output()
        .expect("node is required to render the space detail fixture");
    assert!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered: serde_json::Value = serde_json::from_slice(&output.stdout).expect("node JSON");
    let encrypted = rendered["encrypted"].as_str().unwrap_or("");
    assert!(
        encrypted.contains("End-to-end encrypted"),
        "handler-shaped mls_encrypted group hid the badge: {encrypted}"
    );
    assert_eq!(rendered["signed"].as_str().unwrap_or("missing"), "");
    assert_eq!(
        rendered["alias"].as_str().unwrap_or("missing"),
        "",
        "mls_group_id and policy_summary must not paint the badge"
    );
    assert_eq!(rendered["name"].as_str().unwrap_or(""), "Ada");
    assert_eq!(
        rendered["aliasName"].as_str().unwrap_or("missing"),
        "",
        "display_names must not fill the saved name"
    );
    assert_eq!(rendered["empty"].as_str().unwrap_or("missing"), "");
    assert_eq!(rendered["handlerHasAlias"], false);
}

#[test]
fn gui_json_bodies_match_route_fields() {
    let mut failures = Vec::new();
    for call in gui_api_calls() {
        if let Err(error) = check_call(&call) {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "\n\nGUI JSON field names do not match the routes (#1399):\n{}\n",
        failures.join("\n")
    );
}

const GUI_PARITY_REPORT_PATH: &str = "tests/proof-reports/parity/gui-named-groups-coverage.txt";
const REGEN_GUI_PARITY_REPORT_ENV: &str = "X0X_REGEN_GUI_PARITY_REPORT";

fn render_gui_parity_report() -> String {
    let all = named_group_endpoints();
    let call_sites = gui_api_calls();
    let deferred = deferred_paths();

    let mut lines = Vec::new();
    lines.push(format!(
        "# GUI named-groups parity report — {} endpoints total",
        all.len()
    ));
    let mut wired = 0usize;
    let mut deferred_count = 0usize;
    let mut missing_count = 0usize;
    for (method, path) in &all {
        match classify_gui_endpoint(*method, path, &call_sites, &deferred) {
            GuiParityStatus::Wired => {
                wired += 1;
                lines.push(format!("  WIRED     {method} {path}"));
            }
            GuiParityStatus::Deferred => {
                deferred_count += 1;
                let reason = DEFERRED
                    .iter()
                    .find(|(m, p, _)| m == method && p == path)
                    .map(|(_, _, r)| *r)
                    .unwrap_or("—");
                lines.push(format!("  DEFERRED  {method} {path}  // {reason}"));
            }
            GuiParityStatus::Missing => {
                missing_count += 1;
                lines.push(format!("  MISSING   {method} {path}"));
            }
        }
    }
    lines.push(format!(
        "\nCoverage: {wired}/{} wired; {deferred_count} deferred; {missing_count} missing",
        all.len()
    ));

    let mut report = lines.join("\n");
    report.push('\n');
    report
}

fn gui_parity_report_abs_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GUI_PARITY_REPORT_PATH)
}

/// Summary verifier that always runs. Normal test runs compare the
/// committed report without mutating the checkout. Set
/// X0X_REGEN_GUI_PARITY_REPORT=1 to rewrite the source-tree artifact.
#[test]
fn emit_gui_parity_report() -> std::io::Result<()> {
    let expected = render_gui_parity_report();
    let path = gui_parity_report_abs_path();

    if std::env::var(REGEN_GUI_PARITY_REPORT_ENV).is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &expected)?;
        eprintln!("[gui_named_group_parity] regenerated {}", path.display());
        return Ok(());
    }

    let actual = std::fs::read_to_string(&path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "failed to read {}: {error}\n\
                 Generate it with: {REGEN_GUI_PARITY_REPORT_ENV}=1 cargo test --test \
                 gui_named_group_parity emit_gui_parity_report",
                path.display()
            ),
        )
    })?;

    if actual != expected {
        return Err(std::io::Error::other(format!(
            "{} is stale vs tests/gui_named_group_parity.rs.\n\
             Regenerate with: {REGEN_GUI_PARITY_REPORT_ENV}=1 cargo test --test \
             gui_named_group_parity emit_gui_parity_report",
            path.display()
        )));
    }

    eprintln!("[gui_named_group_parity] verified {}", path.display());
    Ok(())
}
