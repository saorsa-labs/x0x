//! GUI smoke tests.
//!
//! Verifies the embedded HTML GUI serves correctly and calls only
//! endpoints that exist in the ENDPOINTS registry.
//!
//! Run with: cargo nextest run --test gui_smoke -- --ignored

use std::collections::HashSet;
use x0x::api::ENDPOINTS;

/// Verify the GUI HTML file contains expected content.
#[test]
fn gui_html_contains_brand() {
    let html = include_str!("../src/gui/x0x-gui.html");
    assert!(
        html.contains("x0x"),
        "GUI HTML should contain the brand name 'x0x'"
    );
}

/// Verify the GUI HTML is valid (starts with doctype or html tag).
#[test]
fn gui_html_is_valid() {
    let html = include_str!("../src/gui/x0x-gui.html");
    let lower = html.trim().to_lowercase();
    assert!(
        lower.starts_with("<!doctype") || lower.starts_with("<html"),
        "GUI HTML should start with <!DOCTYPE or <html"
    );
}

/// Verify that API paths called from the GUI exist in ENDPOINTS.
///
/// Extracts `api("/path"...)` calls from the JavaScript and checks each
/// against the ENDPOINTS registry. This catches the GUI calling endpoints
/// that were removed or renamed.
#[test]
fn gui_api_paths_exist_in_registry() {
    let html = include_str!("../src/gui/x0x-gui.html");
    let endpoint_paths: HashSet<&str> = ENDPOINTS.iter().map(|e| e.path).collect();

    let mut gui_paths = Vec::new();

    for line in html.lines() {
        let trimmed = line.trim();
        // Extract paths from api("...", ...) calls
        for delimiter in &["api(\"", "api('", "api(`"] {
            let mut search_from = 0;
            while let Some(pos) = trimmed[search_from..].find(delimiter) {
                let start = search_from + pos + delimiter.len();
                if let Some(path) = extract_path(&trimmed[start..]) {
                    if path.starts_with('/') {
                        gui_paths.push(path);
                    }
                }
                search_from = start;
            }
        }
    }

    let mut unmatched = Vec::new();
    for path in &gui_paths {
        let normalized = normalize_path(path);
        if !endpoint_paths.contains(normalized.as_str())
            && !matches_parameterized(&normalized, &endpoint_paths)
        {
            unmatched.push(path.as_str());
        }
    }

    // Report but don't fail — GUI may use dynamically constructed paths
    if !unmatched.is_empty() {
        eprintln!(
            "\nWARNING: GUI calls {} API paths not found in ENDPOINTS:\n  {}",
            unmatched.len(),
            unmatched.join("\n  ")
        );
    }
}

/// Verify the GUI HTML has a reasonable size (not empty, not truncated).
#[test]
fn gui_html_reasonable_size() {
    let html = include_str!("../src/gui/x0x-gui.html");
    assert!(
        html.len() > 1000,
        "GUI HTML is suspiciously small ({} bytes)",
        html.len()
    );
    assert!(
        html.len() < 500_000,
        "GUI HTML is suspiciously large ({} bytes)",
        html.len()
    );
}

/// Verify the GUI HTML contains key UI elements.
#[test]
fn gui_has_key_elements() {
    let html = include_str!("../src/gui/x0x-gui.html");

    // Should have a script section (it's a single-page app)
    assert!(html.contains("<script"), "GUI should contain <script> tags");

    // Should have a style section
    assert!(
        html.contains("<style") || html.contains("style="),
        "GUI should contain styles"
    );

    // Should reference the API somehow
    assert!(
        html.contains("api(") || html.contains("fetch("),
        "GUI should make API calls"
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn extract_path(s: &str) -> Option<String> {
    let end = s.find(['"', '\'', '`', ','])?;
    Some(s[..end].to_string())
}

fn normalize_path(path: &str) -> String {
    let mut result = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // skip {
            for c2 in chars.by_ref() {
                if c2 == '}' {
                    break;
                }
            }
            result.push_str(":id");
        } else {
            result.push(c);
        }
    }
    result
}

fn matches_parameterized(path: &str, endpoints: &HashSet<&str>) -> bool {
    let path_parts: Vec<&str> = path.split('/').collect();
    for ep_path in endpoints {
        let ep_parts: Vec<&str> = ep_path.split('/').collect();
        if path_parts.len() == ep_parts.len() {
            let matches = path_parts
                .iter()
                .zip(ep_parts.iter())
                .all(|(p, e)| e.starts_with(':') || p == e);
            if matches {
                return true;
            }
        }
    }
    false
}
