//! Rust-side GUI view grammar (ADR 0083 §4).
//!
//! Mirrors `applyHashRoute` in `x0x-gui.html`: `dm/<hex>`,
//! `groups/<hex>[/<HASH_SPACE_APPS>]`, and the `HASH_VIEWS` singletons.
//! Anything else is `invalid_view`.

/// Top-level hash views accepted by `applyHashRoute` (keep in lock-step with
/// `HASH_VIEWS` in `src/gui/x0x-gui.html`).
pub const HASH_VIEWS: &[&str] = &[
    "home",
    "homespace",
    "discover",
    "people",
    "network",
    "presence",
    "mls",
    "admin",
    "settings",
    "constitution",
    "about",
];

/// Space-app suffixes accepted under `#/groups/<id>/<app>` (keep in lock-step
/// with `HASH_SPACE_APPS` in `src/gui/x0x-gui.html`).
pub const HASH_SPACE_APPS: &[&str] = &["chat", "board", "files", "swarm", "feed", "wiki", "web"];

/// A validated GUI deep-link route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedView {
    /// Single-segment top-level view (`people`, `network`, …).
    TopLevel(&'static str),
    /// `#/dm/<agent_id>`.
    Dm { agent_id: String },
    /// `#/groups/<group_id>[/<app>]`.
    Group {
        group_id: String,
        app: Option<&'static str>,
    },
}

impl ParsedView {
    /// Canonical route string without a leading `#/` (e.g. `people`,
    /// `dm/<hex>`, `groups/<hex>/board`).
    pub fn as_route(&self) -> String {
        match self {
            ParsedView::TopLevel(name) => (*name).to_string(),
            ParsedView::Dm { agent_id } => format!("dm/{agent_id}"),
            ParsedView::Group {
                group_id,
                app: None,
            } => format!("groups/{group_id}"),
            ParsedView::Group {
                group_id,
                app: Some(app),
            } => format!("groups/{group_id}/{app}"),
        }
    }
}

/// Why a view string failed the grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidView;

impl std::fmt::Display for InvalidView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid_view")
    }
}

impl std::error::Error for InvalidView {}

/// Parse a view route the way `applyHashRoute` does.
///
/// Accepts optional leading `#/` or `/`. Returns [`InvalidView`] for anything
/// the GUI would toast as an unknown link.
pub fn parse(view: &str) -> Result<ParsedView, InvalidView> {
    let route = view
        .trim()
        .trim_start_matches('#')
        .trim_start_matches('/')
        .trim_end_matches('/');
    if route.is_empty() {
        return Err(InvalidView);
    }
    let parts: Vec<&str> = route.split('/').filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        [name] => {
            let name = *name;
            HASH_VIEWS
                .iter()
                .find(|&&v| v == name)
                .copied()
                .map(ParsedView::TopLevel)
                .ok_or(InvalidView)
        }
        ["dm", agent_id] if is_hex_id(agent_id) => Ok(ParsedView::Dm {
            agent_id: agent_id.to_ascii_lowercase(),
        }),
        ["groups", group_id] if is_hex_id(group_id) => Ok(ParsedView::Group {
            group_id: group_id.to_ascii_lowercase(),
            app: None,
        }),
        ["groups", group_id, app] if is_hex_id(group_id) => {
            let app = *app;
            HASH_SPACE_APPS
                .iter()
                .find(|&&a| a == app)
                .copied()
                .map(|app| ParsedView::Group {
                    group_id: group_id.to_ascii_lowercase(),
                    app: Some(app),
                })
                .ok_or(InvalidView)
        }
        _ => Err(InvalidView),
    }
}

fn is_hex_id(s: &str) -> bool {
    let len = s.len();
    (16..=128).contains(&len) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_toplevel_and_structured_routes() {
        assert_eq!(parse("people").unwrap(), ParsedView::TopLevel("people"));
        assert_eq!(parse("#/home").unwrap(), ParsedView::TopLevel("home"));
        let hex = "ab".repeat(16);
        assert_eq!(
            parse(&format!("dm/{hex}")).unwrap(),
            ParsedView::Dm {
                agent_id: hex.clone()
            }
        );
        assert_eq!(
            parse(&format!("groups/{hex}/board")).unwrap(),
            ParsedView::Group {
                group_id: hex.clone(),
                app: Some("board"),
            }
        );
        assert_eq!(
            parse(&format!("groups/{hex}")).unwrap(),
            ParsedView::Group {
                group_id: hex,
                app: None,
            }
        );
    }

    #[test]
    fn rejects_urls_traversal_bad_hex_and_unknown_app() {
        assert!(parse("https://evil.example").is_err());
        assert!(parse("../x").is_err());
        assert!(parse("dm/zz").is_err());
        let hex = "ab".repeat(16);
        assert!(parse(&format!("groups/{hex}/unknownapp")).is_err());
        assert!(parse("not-a-view").is_err());
    }

    #[test]
    fn grammar_parity_with_x0x_gui_html() {
        let html = include_str!("x0x-gui.html");
        let views = extract_js_string_array(html, "HASH_VIEWS");
        let apps = extract_js_string_array(html, "HASH_SPACE_APPS");
        assert_eq!(
            views, HASH_VIEWS,
            "HASH_VIEWS drifted from x0x-gui.html applyHashRoute"
        );
        assert_eq!(
            apps, HASH_SPACE_APPS,
            "HASH_SPACE_APPS drifted from x0x-gui.html applyHashRoute"
        );
    }

    fn extract_js_string_array<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
        let marker = format!("const {name}=[");
        let start = html
            .find(&marker)
            .unwrap_or_else(|| panic!("missing {name} in x0x-gui.html"));
        let after = &html[start + marker.len()..];
        let end = after
            .find(']')
            .unwrap_or_else(|| panic!("unclosed {name} in x0x-gui.html"));
        after[..end]
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_matches('\''))
            .collect()
    }
}
