//! GUI endpoint coverage checker.
//!
//! Compares every `api(...)` call in `src/gui/x0x-gui.html` against the
//! authoritative endpoint registry in `src/api/mod.rs`. Emits a coverage
//! report and exits non-zero when coverage falls below the configured
//! threshold (default 95 %) or when the GUI calls a path the daemon does
//! not expose.
//!
//! Usage:
//!   gui-coverage [--gui PATH] [--whitelist PATH] [--threshold PCT] [--json]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use x0x::api::{self, EndpointDef, Method};

const DEFAULT_GUI: &str = "src/gui/x0x-gui.html";
const DEFAULT_WHITELIST: &str = "src/gui/coverage-whitelist.txt";
const DEFAULT_THRESHOLD_PCT: f64 = 95.0;

#[derive(Debug, Clone)]
struct Args {
    gui: PathBuf,
    whitelist: PathBuf,
    threshold: f64,
    json: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut gui = PathBuf::from(DEFAULT_GUI);
        let mut whitelist = PathBuf::from(DEFAULT_WHITELIST);
        let mut threshold = DEFAULT_THRESHOLD_PCT;
        let mut json = false;

        let mut args = env::args().skip(1);
        while let Some(a) = args.next() {
            match a.as_str() {
                "--gui" => {
                    gui = PathBuf::from(args.next().ok_or("--gui requires a path".to_string())?);
                }
                "--whitelist" => {
                    whitelist = PathBuf::from(
                        args.next()
                            .ok_or("--whitelist requires a path".to_string())?,
                    );
                }
                "--threshold" => {
                    threshold = args
                        .next()
                        .ok_or("--threshold requires a percentage".to_string())?
                        .parse::<f64>()
                        .map_err(|e| format!("--threshold: {e}"))?;
                }
                "--json" => json = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown arg: {other}")),
            }
        }

        Ok(Self {
            gui,
            whitelist,
            threshold,
            json,
        })
    }
}

fn print_help() {
    println!("GUI endpoint coverage checker");
    println!();
    println!("USAGE: gui-coverage [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --gui PATH         Path to GUI HTML (default: {DEFAULT_GUI})");
    println!("  --whitelist PATH   Path to exclusion list (default: {DEFAULT_WHITELIST})");
    println!("  --threshold PCT    Minimum coverage percent (default: {DEFAULT_THRESHOLD_PCT:.1})");
    println!("  --json             Emit machine-readable JSON");
}

/// Normalise a registry path into its coverage key: `/a/:id/b` → `/a/*/b`.
fn registry_key(path: &str) -> String {
    path.split('/')
        .map(|seg| if seg.starts_with(':') { "*" } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

/// Does a GUI call (`method` + `path`) match a registry entry?
///
/// Segment rules:
/// - `:param` (registry) matches any GUI segment (literal or `*`).
/// - Literal registry segment matches itself **or** a GUI `*` — a runtime
///   substitution could still produce that literal, so we assume it covers.
fn call_matches(gui_method: &str, gui_path: &str, ep: &EndpointDef) -> bool {
    if gui_method != "ANY" && method_str(ep.method) != gui_method {
        return false;
    }
    let reg: Vec<&str> = ep.path.split('/').collect();
    let gui: Vec<&str> = gui_path.split('/').collect();
    if reg.len() != gui.len() {
        return false;
    }
    reg.iter().zip(gui.iter()).all(|(r, g)| {
        if r.starts_with(':') {
            true
        } else {
            *r == *g || *g == "*"
        }
    })
}

/// Extract all `api('/path', {method: 'POST'})` style calls from the GUI.
///
/// The parser walks the entire file as one string, tracking line numbers
/// so a multi-line `api(...)` call is recognised the same as a one-liner.
fn extract_gui_calls(html: &str) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !(i + 4 <= bytes.len() && &bytes[i..i + 4] == b"api(") {
            i += 1;
            continue;
        }
        let prev_ok = i == 0 || !is_ident_char(bytes[i - 1]);
        if !prev_ok {
            i += 1;
            continue;
        }
        let start = i + 4;
        let (raw_args, consumed) = match take_balanced_parens(&html[start..]) {
            Some(x) => x,
            None => {
                i = start;
                continue;
            }
        };
        let line_no = html[..i].bytes().filter(|b| *b == b'\n').count() + 1;
        i = start + consumed;

        if let Some((method, path)) = parse_api_args(&raw_args) {
            out.push((method, path, line_no));
        }
    }
    out
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Scan `s` until the opening `api(` is balanced and return the argument text
/// plus the number of bytes consumed up to and including the closing `)`.
fn take_balanced_parens(s: &str) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let mut depth = 1i32;
    let mut in_str: Option<u8> = None;
    let mut escape = false;
    let mut out = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        out.push(b as char);
        if escape {
            escape = false;
            continue;
        }
        if let Some(q) = in_str {
            if b == b'\\' {
                escape = true;
            } else if b == q {
                in_str = None;
            }
            continue;
        }
        match b {
            b'"' | b'\'' | b'`' => in_str = Some(b),
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    out.pop(); // drop final ')'
                    return Some((out, i + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract `(method, normalised_path)` from the raw argument list of `api(...)`.
fn parse_api_args(raw: &str) -> Option<(String, String)> {
    let first_arg = first_string_literal(raw)?;
    let path = normalise_gui_path(&first_arg);
    let method = extract_method(raw);
    Some((method, path))
}

/// Pull the first string literal from `raw`, stopping at the comma that
/// separates it from the options object. Handles `'a'+b+'c'` concatenation by
/// merging literal segments and replacing variable segments with `*`.
fn first_string_literal(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = skip_ws(bytes, 0);
    if i >= bytes.len() {
        return None;
    }
    if !matches!(bytes[i], b'\'' | b'"' | b'`') {
        return None;
    }
    let mut out = String::new();
    loop {
        i = skip_ws(bytes, i);
        if i >= bytes.len() {
            break;
        }
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                let quote = bytes[i];
                i += 1;
                let lit_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                let lit = &raw[lit_start..i.min(raw.len())];
                out.push_str(&collapse_template(lit));
                if i < bytes.len() {
                    i += 1;
                }
            }
            _ => {
                out.push('*');
                i = skip_expr(bytes, i);
            }
        }
        i = skip_ws(bytes, i);
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'+' {
            i += 1;
            continue;
        }
        return Some(out);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn skip_expr(bytes: &[u8], mut i: usize) -> usize {
    let mut depth = 0i32;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            b'+' | b',' if depth == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    i
}

/// `/files/accept/${x.id}` → `/files/accept/*`.
fn collapse_template(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            let mut depth = 1i32;
            i += 2;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            out.push('*');
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Convert a raw GUI path into the canonical coverage key.
///
/// - Strip query strings (everything from `?` onward).
/// - Replace every path segment built from expressions (`*`) with `*`.
/// - Drop trailing slashes except for the root.
fn normalise_gui_path(raw: &str) -> String {
    let no_query = raw.split('?').next().unwrap_or(raw).to_string();
    let mut parts: Vec<&str> = no_query.split('/').collect();
    for p in parts.iter_mut() {
        if p.contains('*') {
            *p = "*";
        }
    }
    while parts.last().is_some_and(|s| s.is_empty()) && parts.len() > 1 {
        parts.pop();
    }
    parts.join("/")
}

/// Extract the HTTP method from the raw options arg. Returns `ANY` when the
/// method is supplied dynamically (e.g. `{method}` shorthand or `method: m`).
fn extract_method(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    for (literal, method) in &[
        ("'post'", "POST"),
        ("\"post\"", "POST"),
        ("'put'", "PUT"),
        ("\"put\"", "PUT"),
        ("'patch'", "PATCH"),
        ("\"patch\"", "PATCH"),
        ("'delete'", "DELETE"),
        ("\"delete\"", "DELETE"),
    ] {
        let needle = format!("method:{literal}");
        let needle_sp = format!("method: {literal}");
        if lower.contains(&needle) || lower.contains(&needle_sp) {
            return (*method).to_string();
        }
    }
    // `method` key present but value is not a literal string → dynamic.
    if lower.contains("method:") || lower.contains("method ") || lower.contains("{method}") {
        return "ANY".into();
    }
    "GET".into()
}

fn load_whitelist(path: &PathBuf) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return out,
    };
    for line in contents.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        out.insert(trimmed.to_string());
    }
    out
}

fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
    }
}

fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let html = match fs::read_to_string(&args.gui) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading {:?}: {e}", args.gui);
            return ExitCode::from(2);
        }
    };

    let whitelist = load_whitelist(&args.whitelist);

    let registry: BTreeMap<String, &EndpointDef> = api::ENDPOINTS
        .iter()
        .map(|ep| {
            (
                format!("{} {}", method_str(ep.method), registry_key(ep.path)),
                ep,
            )
        })
        .collect();

    let mut called: BTreeMap<String, usize> = BTreeMap::new();
    let mut unknown: Vec<(String, String, usize)> = Vec::new();

    for (method, path, line_no) in extract_gui_calls(&html) {
        let matches: Vec<&EndpointDef> = api::ENDPOINTS
            .iter()
            .filter(|ep| call_matches(&method, &path, ep))
            .collect();
        if matches.is_empty() {
            unknown.push((method, path, line_no));
        } else {
            for ep in matches {
                let key = format!("{} {}", method_str(ep.method), registry_key(ep.path));
                *called.entry(key).or_insert(0) += 1;
            }
        }
    }

    let total = registry.len();
    let whitelisted: Vec<&str> = registry
        .keys()
        .filter(|k| whitelist.contains(k.as_str()))
        .map(String::as_str)
        .collect();
    let counted_total = total - whitelisted.len();
    let covered = called.len();
    let pct = if counted_total == 0 {
        100.0
    } else {
        (covered as f64 / counted_total as f64) * 100.0
    };

    let uncovered: Vec<String> = registry
        .keys()
        .filter(|k| !called.contains_key(k.as_str()) && !whitelist.contains(k.as_str()))
        .cloned()
        .collect();

    let pass = pct >= args.threshold && unknown.is_empty();

    if args.json {
        print_json_report(
            total,
            covered,
            counted_total,
            pct,
            args.threshold,
            &uncovered,
            &unknown,
            &whitelisted,
            pass,
        );
    } else {
        print_human_report(
            total,
            covered,
            counted_total,
            pct,
            args.threshold,
            &uncovered,
            &unknown,
            &whitelisted,
            pass,
        );
    }

    if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[allow(clippy::too_many_arguments)]
fn print_human_report(
    total: usize,
    covered: usize,
    counted_total: usize,
    pct: f64,
    threshold: f64,
    uncovered: &[String],
    unknown: &[(String, String, usize)],
    whitelisted: &[&str],
    pass: bool,
) {
    println!("GUI coverage report");
    println!("-------------------");
    println!("Registry endpoints:    {total}");
    println!("Whitelisted (ignored): {}", whitelisted.len());
    println!("Counted:               {counted_total}");
    println!("Covered by GUI:        {covered}");
    println!("Coverage:              {pct:.1}% (threshold {threshold:.1}%)");
    println!();

    if !uncovered.is_empty() {
        println!("Uncovered endpoints ({}):", uncovered.len());
        for k in uncovered {
            println!("  - {k}");
        }
        println!();
    }

    if !unknown.is_empty() {
        println!("Unknown paths called by GUI ({}):", unknown.len());
        for (m, p, line) in unknown {
            println!("  - {m} {p}  (x0x-gui.html:{line})");
        }
        println!();
    }

    if !whitelisted.is_empty() {
        println!("Whitelisted (excluded from coverage):");
        for k in whitelisted {
            println!("  - {k}");
        }
        println!();
    }

    if pass {
        println!("PASS: coverage meets threshold and no unknown paths.");
    } else {
        println!("FAIL: see above.");
    }
}

#[allow(clippy::too_many_arguments)]
fn print_json_report(
    total: usize,
    covered: usize,
    counted_total: usize,
    pct: f64,
    threshold: f64,
    uncovered: &[String],
    unknown: &[(String, String, usize)],
    whitelisted: &[&str],
    pass: bool,
) {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"pass\": {pass},\n"));
    out.push_str(&format!("  \"coverage_pct\": {pct:.2},\n"));
    out.push_str(&format!("  \"threshold_pct\": {threshold:.2},\n"));
    out.push_str(&format!("  \"registry_total\": {total},\n"));
    out.push_str(&format!("  \"counted_total\": {counted_total},\n"));
    out.push_str(&format!("  \"covered\": {covered},\n"));
    out.push_str(&format!(
        "  \"whitelisted\": [{}],\n",
        whitelisted
            .iter()
            .map(|s| json_str(s))
            .collect::<Vec<_>>()
            .join(",")
    ));
    out.push_str(&format!(
        "  \"uncovered\": [{}],\n",
        uncovered
            .iter()
            .map(|s| json_str(s))
            .collect::<Vec<_>>()
            .join(",")
    ));
    out.push_str("  \"unknown\": [");
    for (i, (m, p, line)) in unknown.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"method\":{},\"path\":{},\"line\":{line}}}",
            json_str(m),
            json_str(p)
        ));
    }
    out.push_str("]\n}");
    println!("{out}");
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
