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
use x0x::api::{Method, ENDPOINTS};

const GUI_HTML: &str = include_str!("../src/gui/x0x-gui.html");

/// Named-groups endpoints we have consciously chosen NOT to wire into
/// the embedded HTML GUI, with an explicit reason. Anything in this
/// list is counted as a **gap**, not coverage — the signoff doc must
/// reflect that.
///
/// Adding an entry here is a downgrade that must show up in
/// `docs/proof/NAMED_GROUPS_PARITY_SIGNOFF.md`.
const DEFERRED: &[(Method, &str, &str)] = &[
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
    // GET /groups/:id/messages — message-history read-back from the
    // daemon cache. The send path now routes SignedPublic groups
    // through `POST /groups/:id/send`, and the daemon publishes the
    // signed envelope so the existing gossip subscription receives
    // own-messages just like before. Pulling history from the REST
    // endpoint (so non-member-authored signed posts that arrived
    // while we were offline appear in the chat history) is the
    // remaining piece of work.
    (
        Method::Get,
        "/groups/:id/messages",
        "GUI gap: signed-message HISTORY read-back from /messages not \
         yet wired (SignedPublic SEND now is)",
    ),
    // Presence events are used globally by the GUI via WebSocket
    // rather than the named-groups discovery path.
    // (nothing here — kept for future additions)
];

/// One observed `api(...)` call: the first-argument expression text
/// (including all string concatenations and template substitutions)
/// plus the parsed HTTP method from the optional second-argument
/// object literal (`{method: 'PATCH'}` etc). `None` method means GET.
#[derive(Debug)]
struct ApiCall {
    expr: String,
    method: Option<String>,
}

/// Walk the GUI HTML and capture every `api(...)` invocation. The
/// extractor is JS-aware enough to handle `'/foo/'+x+'/bar'`,
/// `` `/foo/${x}/bar` ``, and the optional second-arg `{method: 'X'}`.
fn gui_api_calls() -> Vec<ApiCall> {
    let bytes = GUI_HTML.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if &bytes[i..i + 4] == b"api(" {
            let start = i + 4;
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
            // first top-level comma.
            let (expr, rest) = split_top_level_comma(args);
            let expr = expr.trim().to_string();
            let method = extract_method_kw(rest);
            // Heuristic: only keep calls whose first arg looks like a
            // path literal (starts with a quote followed by `/`).
            let is_pathish = looks_like_path_arg(&expr);
            if is_pathish {
                out.push(ApiCall { expr, method });
            }
            i = j;
        } else {
            i += 1;
        }
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

/// Does the call's expression text contain every literal segment of
/// `template` in order? Parameter segments (`:foo`) are skipped.
fn expr_contains_template(expr: &str, template: &str) -> bool {
    // Build an ordered list of literal segments. Anchor on the leading
    // `/` so `/groups/:id/members` requires `/groups/` AND `/members`
    // (each with a `/` prefix to avoid false hits like
    // `groups-discover` matching `/groups`).
    let mut segments: Vec<String> = Vec::new();
    let mut buf = String::new();
    for raw in template.split('/').filter(|s| !s.is_empty()) {
        if raw.starts_with(':') {
            if !buf.is_empty() {
                segments.push(format!("/{buf}"));
                buf.clear();
            }
        } else {
            if !buf.is_empty() {
                buf.push('/');
            }
            buf.push_str(raw);
        }
    }
    if !buf.is_empty() {
        segments.push(format!("/{buf}"));
    }
    if segments.is_empty() {
        // Root-only path like "/" — accept if `expr` contains it.
        return expr.contains('/');
    }
    let mut cursor = 0usize;
    for seg in &segments {
        // Allow either the bare literal segment OR a literal followed
        // by an immediate quote-end so we don't accidentally match
        // `/groups/cards` against the literal `/groups`.
        match expr[cursor..].find(seg.as_str()) {
            Some(p) => {
                let abs = cursor + p;
                let after = abs + seg.len();
                let next = expr.as_bytes().get(after).copied();
                let ok_boundary = matches!(
                    next,
                    Some(b'/') | Some(b'\'') | Some(b'"') | Some(b'`') | Some(b'?')
                ) || next.is_none();
                if !ok_boundary {
                    // Skip this match; try later in the string.
                    cursor = abs + 1;
                    continue;
                }
                cursor = after;
            }
            None => return false,
        }
    }
    true
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

#[test]
fn gui_named_group_parity_against_manifest() {
    let all = named_group_endpoints();
    let call_sites = gui_api_calls();
    let deferred: HashSet<(String, String)> = DEFERRED
        .iter()
        .map(|(m, p, _)| (format!("{m}"), (*p).to_string()))
        .collect();

    let mut covered = Vec::new();
    let mut deferred_seen = Vec::new();
    let mut missing = Vec::new();

    for (method, path) in &all {
        if gui_covers(*method, path, &call_sites) {
            covered.push((*method, *path));
        } else if deferred.contains(&(format!("{method}"), (*path).to_string())) {
            deferred_seen.push((*method, *path));
        } else {
            missing.push((*method, *path));
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

/// Summary printer that always runs. Writes to a persistent file so
/// the exact covered/deferred/missing split is visible without
/// needing stdout capture.
#[test]
fn emit_gui_parity_report() {
    use std::io::Write as _;
    let all = named_group_endpoints();
    let call_sites = gui_api_calls();
    let deferred: HashSet<(String, String)> = DEFERRED
        .iter()
        .map(|(m, p, _)| (format!("{m}"), (*p).to_string()))
        .collect();

    let mut lines = Vec::new();
    lines.push(format!(
        "# GUI named-groups parity report — {} endpoints total",
        all.len()
    ));
    let mut wired = 0usize;
    let mut deferred_count = 0usize;
    let mut missing_count = 0usize;
    for (method, path) in &all {
        if gui_covers(*method, path, &call_sites) {
            wired += 1;
            lines.push(format!("  WIRED     {method} {path}"));
        } else if deferred.contains(&(format!("{method}"), (*path).to_string())) {
            deferred_count += 1;
            let reason = DEFERRED
                .iter()
                .find(|(m, p, _)| m == method && p == path)
                .map(|(_, _, r)| *r)
                .unwrap_or("—");
            lines.push(format!("  DEFERRED  {method} {path}  // {reason}"));
        } else {
            missing_count += 1;
            lines.push(format!("  MISSING   {method} {path}"));
        }
    }
    lines.push(format!(
        "\nCoverage: {wired}/{} wired; {deferred_count} deferred; {missing_count} missing",
        all.len()
    ));

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/proof-reports/parity/gui-named-groups-coverage.txt"
    );
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut f = std::fs::File::create(path).expect("write coverage report");
    writeln!(f, "{}", lines.join("\n")).expect("write coverage report");
    eprintln!("[gui_named_group_parity] coverage report → {path}");
}
