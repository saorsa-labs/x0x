//! #732 — a source-scanning guard so the single-spelling roster lookup
//! cannot come back.
//!
//! WHY this is a source scan and not a behavioural test. The defect class is
//! "someone writes `groups.get(id)` on a quarantine path": cross-model review
//! found that same bug independently in ADR-0066 slices 3, 4 and 6, and a
//! seventh site (the manual clear route) survived all three reviews. Each
//! instance is invisible unless a test happens to exercise *that* path with an
//! alias-keyed roster — there is no single behaviour to assert, because the
//! next occurrence will be in code that does not exist yet. So the invariant
//! is stated over the SOURCE, the way `adr0066_coverage_map` states §1's
//! enumeration over the route registry: every quarantine-relevant lookup goes
//! through [`crate::server::resolve_group_entry_locked`], or carries an
//! explicit waiver naming why the single spelling is correct there.
//!
//! The heuristic, stated so a reviewer can judge it rather than trust it:
//!
//! 1. scan every non-test `.rs` file under `src/server`, with `//`/`/* */`
//!    comments blanked out (so prose about a bare lookup is not a bare
//!    lookup) and `#[cfg(test)]` blocks skipped;
//! 2. find `.get(`, `.get_mut(`, `.contains_key(`, `.get_key_value(` and
//!    `.entry(` whose receiver is the
//!    named-groups map — the guard-binding names `groups` and `named_groups`,
//!    which are the only two spellings this codebase uses for it;
//! 3. keep only those whose surrounding lines (2 before, 25 after) mention
//!    `fork_quarantine` / `is_fork_quarantined`. That window is what makes
//!    this "a lookup feeding a quarantine decision" rather than "any roster
//!    lookup in a file that also mentions quarantine somewhere": the 25-line
//!    reach covers the lookup, its `else` arm, an intervening decision
//!    `match`, and the gate call that consumes the `info`. See [`LOOKAHEAD`]
//!    for why this is not the enclosing function;
//! 4. a kept site must carry `ADR0066-LOOKUP-WAIVER: <reason>` within the six
//!    source lines above it, with a non-empty reason. That is the allow-list,
//!    and it lives AT the site on purpose — a table in this file would drift
//!    by line number and a future author would never read it.
//!
//! False negatives are possible (a lookup 20 lines from its gate, a receiver
//! named something else) and that is accepted: this guard exists to stop the
//! recurrence of a shape that has now appeared seven times, not to prove a
//! universal. False positives cost one waiver line with a reason, which is
//! the outcome we want anyway.

/// One flagged lookup: where it is and which method it used.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    line: usize,
    method: &'static str,
    waived: bool,
}

/// Every borrow/insert entry point onto the map that returns one group. Review
/// of #750 named `.get_key_value(` and `.entry(` as unscanned evasions.
const METHODS: [&str; 5] = [
    ".get(",
    ".get_mut(",
    ".contains_key(",
    ".get_key_value(",
    ".entry(",
];
/// The only two names this codebase binds the named-groups map to.
const RECEIVERS: [&str; 2] = ["groups", "named_groups"];
const WAIVER: &str = "ADR0066-LOOKUP-WAIVER:";
/// Lines after the lookup that may carry the quarantine mention.
///
/// Widened from 15 to 25 by review of #750, which showed
/// `install_fork_evidence`'s FIRST `get_mut` — the actual install decision —
/// sitting 20 lines from its `fork_quarantine` mention and therefore
/// unflagged. 25 covers the lookup, its `else` arm, and a decision `match`
/// between the two.
///
/// WHY NOT the enclosing function, the other option review offered: in this
/// codebase the enclosing function reaches ~600 lines
/// (`apply_named_group_metadata_event_inner_serialized`), and function scope
/// flags 23 sites where 25-line scope flags 12. About half of those 11 extra
/// waivers would read "this lookup has nothing to do with quarantine, the
/// mention is 400 lines away" — and an allow-list whose reasons are mostly
/// noise is one reviewers learn to skim. The window is the proximity claim
/// ("this lookup feeds that decision") stated honestly; a site that moves its
/// gate further away than this is a false negative we accept and name.
const LOOKAHEAD: usize = 25;
/// Lines above the lookup that may carry the waiver, so a multi-line reason
/// can be written as prose instead of one unreadable line.
const WAIVER_REACH: usize = 6;

/// Blank out comments, keeping every byte position and newline so line
/// numbers and the raw source stay aligned. `//` is only honoured outside a
/// string literal (an odd number of unescaped `"` before it on the line means
/// we are inside one), which keeps a `"http://…"` literal from swallowing the
/// rest of its line.
fn blank_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_block = 0usize;
    for line in source.split('\n') {
        let bytes: Vec<char> = line.chars().collect();
        let mut masked: Vec<char> = Vec::with_capacity(bytes.len());
        let mut quotes = 0usize;
        let mut i = 0usize;
        while i < bytes.len() {
            if in_block > 0 {
                if bytes[i] == '*' && bytes.get(i + 1) == Some(&'/') {
                    in_block -= 1;
                    masked.push(' ');
                    masked.push(' ');
                    i += 2;
                    continue;
                }
                if bytes[i] == '/' && bytes.get(i + 1) == Some(&'*') {
                    in_block += 1;
                    masked.push(' ');
                    masked.push(' ');
                    i += 2;
                    continue;
                }
                masked.push(' ');
                i += 1;
                continue;
            }
            let outside_string = quotes.is_multiple_of(2);
            if outside_string && bytes[i] == '/' && bytes.get(i + 1) == Some(&'/') {
                while masked.len() < bytes.len() {
                    masked.push(' ');
                }
                i = bytes.len();
                continue;
            }
            if outside_string && bytes[i] == '/' && bytes.get(i + 1) == Some(&'*') {
                in_block += 1;
                masked.push(' ');
                masked.push(' ');
                i += 2;
                continue;
            }
            if bytes[i] == '"' && (i == 0 || bytes[i - 1] != '\\') {
                quotes += 1;
            }
            masked.push(bytes[i]);
            i += 1;
        }
        out.extend(masked);
        out.push('\n');
    }
    // `split('\n')` yields one trailing empty piece for a newline-terminated
    // file; drop the newline we added for it so the length is preserved.
    out.pop();
    out
}

/// Line ranges (1-based, inclusive) covered by a `#[cfg(test)]` MODULE.
///
/// Found by INDENTATION, not by counting braces: rustfmt guarantees a module's
/// closing brace sits alone at the attribute's own indentation, whereas brace
/// counting desynchronises on the first `"}"` inside a string literal — which
/// is exactly how an earlier draft of this guard leaked two `mod tests`
/// lookups into its findings. `#[cfg(test)]` on a plain `fn`/`static` is NOT a
/// span: those are production-shaped helpers, and one that grew a quarantine
/// lookup should waive it like anything else.
fn test_line_spans(masked: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = masked.split('\n').collect();
    let mut spans = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() != "#[cfg(test)]" {
            continue;
        }
        let indent = &line[..line.len() - line.trim_start().len()];
        // Skip further attributes and blank lines between the attribute and
        // the item it applies to.
        let Some(declaration) = lines
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, body)| {
                let trimmed = body.trim();
                !trimmed.is_empty() && !trimmed.starts_with("#[")
            })
            .filter(|(_, body)| body.contains("mod ") && body.trim_end().ends_with('{'))
        else {
            continue;
        };
        let closing = format!("{indent}}}");
        if let Some((end, _)) = lines
            .iter()
            .enumerate()
            .skip(declaration.0 + 1)
            .find(|(_, body)| body.trim_end() == closing)
        {
            spans.push((index + 1, end + 1));
        }
    }
    spans
}

/// The identifier immediately left of `at`, if the text there ends in one.
fn receiver_before(line: &str, at: usize) -> String {
    line[..at]
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

/// Every quarantine-relevant roster lookup in one file, sorted by line so the
/// result never depends on read order.
fn sites(file: &str, source: &str) -> Vec<Site> {
    let masked = blank_comments(source);
    let spans = test_line_spans(&masked);
    let masked_lines: Vec<&str> = masked.split('\n').collect();
    let raw_lines: Vec<&str> = source.split('\n').collect();
    let mut found = Vec::new();
    for (index, line) in masked_lines.iter().enumerate() {
        let number = index + 1;
        if spans
            .iter()
            .any(|(from, to)| number >= *from && number <= *to)
        {
            continue;
        }
        for method in METHODS {
            let mut from = 0usize;
            while let Some(hit) = line[from..].find(method) {
                let at = from + hit;
                from = at + 1;
                let receiver = receiver_before(line, at);
                if !RECEIVERS.contains(&receiver.as_str()) {
                    continue;
                }
                let window_from = index.saturating_sub(2);
                let window_to = (index + LOOKAHEAD + 1).min(masked_lines.len());
                let window = masked_lines[window_from..window_to].join("\n");
                if !window.contains("fork_quarantine") && !window.contains("is_fork_quarantined") {
                    continue;
                }
                let waived = raw_lines[index.saturating_sub(WAIVER_REACH)..index]
                    .iter()
                    .any(|above| {
                        above
                            .split_once(WAIVER)
                            .is_some_and(|(_, reason)| !reason.trim().is_empty())
                    });
                found.push(Site {
                    file: file.to_string(),
                    line: number,
                    method,
                    waived,
                });
            }
        }
    }
    found.sort();
    found
}

/// Every `.rs` file under `src/server`, excluding test-only directories,
/// returned in sorted order.
fn server_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server");
    let mut pending = vec![root.clone()];
    let mut out = Vec::new();
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("#732 guard must read {}: {error}", dir.display()));
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) => panic!("#732 guard must stat every entry: {error}"),
            };
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "rs") {
                let relative = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                let source = std::fs::read_to_string(&path).unwrap_or_else(|error| {
                    panic!("#732 guard must read {}: {error}", path.display())
                });
                out.push((relative, source));
            }
        }
    }
    out.sort();
    out
}

fn all_sites() -> Vec<Site> {
    let mut all: Vec<Site> = server_sources()
        .iter()
        .flat_map(|(file, source)| sites(file, source))
        .collect();
    all.sort();
    all
}

/// The invariant: no quarantine-relevant roster lookup spells the
/// both-spellings rule out for itself. A site that genuinely must use one
/// spelling says so at the site.
#[test]
fn adr0066_every_quarantine_lookup_resolves_both_spellings_or_waives() {
    let unwaived: Vec<Site> = all_sites()
        .into_iter()
        .filter(|site| !site.waived)
        .collect();
    assert!(
        unwaived.is_empty(),
        "#732: these roster lookups sit on a fork-quarantine path with a single \
         spelling. Route them through `crate::server::resolve_group_entry_locked` \
         (direct key, then a scan by `stable_group_id()`), or, if one spelling is \
         genuinely correct there, put `{WAIVER} <why>` on the line above:\n{}",
        unwaived
            .iter()
            .map(|site| format!("  src/server/{}:{} {}", site.file, site.line, site.method))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Anti-vacuity: a scanner that silently stopped finding anything would pass
/// the test above forever. The waived population is the #732 census, so it is
/// pinned — adding or removing a waiver is a deliberate edit here too.
#[test]
fn adr0066_lookup_guard_still_sees_the_waived_census() {
    let sites = all_sites();
    assert_eq!(
        sites.len(),
        12,
        "#732 census: 12 single-spelling roster lookups remain on quarantine \
         paths, each waived at the site (8 at the original 15-line window, 4 \
         more once review of #750 widened it to 25). If you added or removed \
         one, say so here:\n{sites:#?}"
    );
    assert!(
        sites.iter().all(|site| site.waived),
        "every census site carries its reason: {sites:#?}"
    );
    assert!(
        server_sources().len() > 5,
        "the walk must actually reach src/server"
    );
}

/// The negative control, run through the very same [`sites`] function the
/// real scan uses — a synthetic file rather than a temporary edit to the
/// tree, so it is reproducible and leaves nothing behind.
#[test]
fn adr0066_lookup_guard_fires_on_a_reintroduced_bare_lookup() {
    let bare = r#"
async fn gate(state: &AppState, id: &str) -> bool {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return false;
    };
    info.is_fork_quarantined()
}
"#;
    let flagged = sites("synthetic.rs", bare);
    assert_eq!(flagged.len(), 1, "the bare lookup is flagged: {flagged:#?}");
    assert_eq!(flagged[0].method, ".get(");
    assert!(!flagged[0].waived, "with no waiver it is a violation");

    // The same source, waived: flagged but not a violation.
    let waived = bare.replace(
        "    let Some(info) = groups.get(id)",
        "    // ADR0066-LOOKUP-WAIVER: synthetic control\n    let Some(info) = groups.get(id)",
    );
    let flagged = sites("synthetic.rs", &waived);
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].waived, "a reason lifts it to the allow-list");

    // A waiver marker with no reason is not a waiver.
    let empty = bare.replace(
        "    let Some(info) = groups.get(id)",
        "    // ADR0066-LOOKUP-WAIVER:\n    let Some(info) = groups.get(id)",
    );
    assert!(
        !sites("synthetic.rs", &empty)[0].waived,
        "the marker alone is not an argument"
    );

    // The shared resolver is not a map lookup, so it is never flagged.
    let resolved = r#"
async fn gate(state: &AppState, id: &str) -> bool {
    let groups = state.named_groups.read().await;
    let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, id) else {
        return false;
    };
    info.is_fork_quarantined()
}
"#;
    assert!(sites("synthetic.rs", resolved).is_empty());
}

/// The three ways the scan is allowed to stay quiet, each pinned so a future
/// tightening of the heuristic is a deliberate, visible change.
#[test]
fn adr0066_lookup_guard_scope_is_explicit() {
    // (a) prose about a bare lookup is not a bare lookup.
    let commented = "
// let Some(info) = groups.get(id); // fork_quarantine used to live here
/* groups.get_mut(id) fork_quarantine */
fn nothing() {}
";
    assert!(sites("synthetic.rs", commented).is_empty());

    // (b) a roster lookup with no quarantine decision near it is out of scope
    //     — this guard is about quarantine paths, not every lookup.
    let unrelated = "
fn name(groups: &Map, id: &str) -> Option<String> {
    groups.get(id).map(|info| info.name.clone())
}
";
    assert!(sites("synthetic.rs", unrelated).is_empty());

    // (c) test code may reach into the map under one spelling: a fixture that
    //     just inserted the key is entitled to assume it.
    let in_test = "
#[cfg(test)]
mod tests {
    fn set_marker(groups: &mut Map, id: &str) {
        if let Some(info) = groups.get_mut(id) {
            info.fork_quarantine = Some(marker());
        }
    }
}
";
    assert!(sites("synthetic.rs", in_test).is_empty());

    // Order independence: the same file scanned twice, and the whole tree
    // scanned twice, give byte-identical results.
    assert_eq!(all_sites(), all_sites());
}
