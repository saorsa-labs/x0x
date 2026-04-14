//! API manifest — deterministic projection of `x0x::api::ENDPOINTS` to JSON.
//!
//! Downstream clients (communitas Rust client, Swift client, the embedded
//! GUI, and cross-surface parity tests) read
//! `docs/design/api-manifest.json` to know which REST endpoints exist and
//! which CLI names back them. The manifest is **generated**, not hand-
//! maintained, so it cannot drift from the `ENDPOINTS` registry.
//!
//! Modes:
//! - Default (`cargo nextest run --test api_manifest`): validates that the
//!   committed manifest matches the live registry. Fails with a diff on
//!   drift.
//! - Regenerate (`X0X_REGEN_MANIFEST=1 cargo test --test api_manifest`):
//!   rewrites the manifest. Run this whenever you add/rename endpoints.

use std::path::PathBuf;

use x0x::api::ENDPOINTS;

/// Relative path (from crate root) of the committed manifest.
const MANIFEST_PATH: &str = "docs/design/api-manifest.json";

/// Pretty-printed JSON projection of `ENDPOINTS`. Stable field order
/// (`method`, `path`, `cli_name`, `category`, `description`) so diffs are
/// review-friendly and consumers can rely on the shape.
fn render_manifest() -> String {
    let entries: Vec<serde_json::Value> = ENDPOINTS
        .iter()
        .map(|ep| {
            serde_json::json!({
                "method": ep.method.to_string(),
                "path": ep.path,
                "cli_name": ep.cli_name,
                "category": ep.category,
                "description": ep.description,
            })
        })
        .collect();

    let root = serde_json::json!({
        "schema": "x0x-api-manifest/v1",
        "source": "src/api/mod.rs::ENDPOINTS",
        "generator": "tests/api_manifest.rs",
        "endpoint_count": ENDPOINTS.len(),
        "endpoints": entries,
    });

    let mut out = serde_json::to_string_pretty(&root).expect("serialize manifest");
    out.push('\n');
    out
}

fn manifest_abs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_PATH)
}

#[test]
fn manifest_matches_registry() {
    let expected = render_manifest();
    let path = manifest_abs_path();

    if std::env::var("X0X_REGEN_MANIFEST").is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create manifest dir");
        }
        std::fs::write(&path, &expected).expect("write manifest");
        eprintln!("regenerated {}", path.display());
        return;
    }

    let actual = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => panic!(
            "failed to read {}: {e}\n\
             Generate it with: X0X_REGEN_MANIFEST=1 cargo test --test api_manifest",
            path.display()
        ),
    };

    if actual != expected {
        panic!(
            "{} is stale vs src/api/mod.rs::ENDPOINTS.\n\
             Regenerate with: X0X_REGEN_MANIFEST=1 cargo test --test api_manifest\n\
             \n\
             First diverging byte: {}\n",
            path.display(),
            first_diff(&actual, &expected)
        );
    }
}

fn first_diff(a: &str, b: &str) -> String {
    let max = a.len().min(b.len());
    for (i, (ac, bc)) in a.bytes().zip(b.bytes()).take(max).enumerate() {
        if ac != bc {
            let ctx = 40;
            let start = i.saturating_sub(ctx);
            let a_end = (i + ctx).min(a.len());
            let b_end = (i + ctx).min(b.len());
            return format!(
                "offset {i}\n  committed: …{}…\n  expected:  …{}…",
                &a[start..a_end].escape_debug(),
                &b[start..b_end].escape_debug(),
            );
        }
    }
    format!(
        "length differs (committed={}, expected={})",
        a.len(),
        b.len()
    )
}

#[test]
fn every_endpoint_has_cli_name() {
    let mut blanks = Vec::new();
    for ep in ENDPOINTS {
        if ep.cli_name.trim().is_empty() {
            blanks.push(format!("  {} {}", ep.method, ep.path));
        }
    }
    assert!(
        blanks.is_empty(),
        "endpoints without a cli_name (CLI parity violation):\n{}",
        blanks.join("\n")
    );
}

#[test]
fn cli_names_are_unique() {
    use std::collections::HashMap;
    let mut seen: HashMap<&str, Vec<String>> = HashMap::new();
    for ep in ENDPOINTS {
        seen.entry(ep.cli_name)
            .or_default()
            .push(format!("{} {}", ep.method, ep.path));
    }
    let mut dupes: Vec<String> = seen
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(n, v)| format!("  \"{n}\" → {}", v.join(", ")))
        .collect();
    dupes.sort();
    assert!(
        dupes.is_empty(),
        "duplicate cli_name values — each endpoint must map to a unique CLI command:\n{}",
        dupes.join("\n")
    );
}
