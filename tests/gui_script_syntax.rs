//! Parse gate for the embedded GUI's inline script.
//!
//! The GUI is ONE inline `<script>`: a single unbalanced delimiter makes the
//! whole script fail to parse, so nothing binds, nothing fetches and the page
//! renders blank — with only a console `SyntaxError` to show for it.
//!
//! That shipped. v0.41.1 (commit `bdd3f46`) converted the peer-events log from
//! `onmessage = e => {...};` to `addEventListener('peer-lifecycle', e => {...}`
//! and kept the assignment's `};` terminator instead of `});`. The GUI was dead
//! in v0.41.1 and v0.41.2 while every existing GUI suite stayed green, because
//! those suites match endpoint strings and never check that the script parses.
//!
//! The check therefore uses a REAL JavaScript parser rather than a hand-rolled
//! scanner: correctly distinguishing a regex literal from division needs full
//! parser context, so any heuristic either rejects valid code
//! (`return /[)]/.test(s)`) or accepts invalid code (`i++ / (x;`).
//!
//! Specifically it compiles with `node:vm`'s `Script`, which is the BROWSER
//! CLASSIC-SCRIPT grammar the GUI is actually served under — not `node --check`,
//! whose CommonJS grammar diverges in both directions (it accepts top-level
//! `return;` and rejects `let require = 1;`). All GitHub-hosted runner images
//! ship Node, so this runs for real in CI; if Node is missing the test FAILS
//! LOUDLY rather than skipping, so the gate can never pass vacuously.

use std::process::Command;

const GUI_HTML: &str = include_str!("../src/gui/x0x-gui.html");

/// The largest inline `<script>` body — the GUI's application script.
fn extract_main_script(html: &str) -> &str {
    let mut best = "";
    let mut rest = html;
    while let Some(open) = rest.find("<script") {
        let after_tag = match rest[open..].find('>') {
            Some(i) => open + i + 1,
            None => break,
        };
        let Some(close) = rest[after_tag..].find("</script>") else {
            break;
        };
        let body = &rest[after_tag..after_tag + close];
        if body.len() > best.len() {
            best = body;
        }
        rest = &rest[after_tag + close..];
    }
    best
}

/// Compile `source` as a BROWSER CLASSIC SCRIPT and report any syntax error.
///
/// Deliberately not `node --check`: that applies CommonJS grammar, which
/// diverges from a `<script>` in both directions — it accepts top-level
/// `return;` (a browser rejects it) and rejects `let require = 1;` (a browser
/// accepts it). `new vm.Script(...)` compiles a real classic script and never
/// executes it, which is exactly the grammar the GUI is served under. Both
/// divergences are pinned by `parse_gate_uses_browser_script_grammar`.
fn parse_as_classic_script(source: &str, label: &str) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!(
        "x0x-gui-parse-{}-{}",
        std::process::id(),
        label.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir for the parse check");
    let path = dir.join("script.js");
    std::fs::write(&path, source).expect("write the extracted script");

    let out = Command::new("node")
        .arg("-e")
        .arg(
            "const fs=require('node:fs'),vm=require('node:vm');\
             const p=process.env.X0X_GUI_SCRIPT_PATH;\
             new vm.Script(fs.readFileSync(p,'utf8'),{filename:p});",
        )
        .env("X0X_GUI_SCRIPT_PATH", &path)
        .output();
    let _ = std::fs::remove_dir_all(&dir);

    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => panic!(
            "cannot run Node to validate the embedded GUI script: {e}.\n\
             This gate needs Node — every GitHub-hosted runner image ships it, and \
             it is required locally too. It deliberately fails instead of skipping: \
             a fatal GUI SyntaxError shipped twice (v0.41.1, v0.41.2) precisely \
             because nothing parsed the script."
        ),
    }
}

/// The regression gate: the embedded GUI's inline script must parse.
///
/// A failure here means the browser throws `SyntaxError` on load and the entire
/// GUI renders blank.
#[test]
fn embedded_gui_script_parses() {
    let script = extract_main_script(GUI_HTML);
    assert!(
        script.len() > 10_000,
        "expected to extract the GUI's application script from \
         src/gui/x0x-gui.html, got {} bytes — the extractor is broken, which \
         would make this gate pass vacuously",
        script.len()
    );

    if let Err(stderr) = parse_as_classic_script(script, "gui") {
        panic!(
            "src/gui/x0x-gui.html: the inline GUI script does NOT parse.\n\
             The whole GUI is ONE script, so this renders a blank page in every \
             browser (regression of v0.41.1 commit bdd3f46, where an \
             addEventListener(...) call was closed with '}};' instead of '}});').\n\
             Line numbers below are relative to the extracted script.\n\n{stderr}"
        );
    }
}

/// Guards the gate itself: it must reject the exact defect shape and accept the
/// corrected one, so a broken harness cannot silently pass.
#[test]
fn parse_gate_rejects_the_v0_41_1_defect_shape() {
    let broken = r#"
      el.addEventListener('peer-lifecycle', e => {
        doThing(e.data);
      };
      el.onerror = () => {};
    "#;
    assert!(
        parse_as_classic_script(broken, "broken").is_err(),
        "the gate must reject an addEventListener call closed with '}};'"
    );

    let fixed = r#"
      el.addEventListener('peer-lifecycle', e => {
        doThing(e.data);
      });
      el.onerror = () => {};
    "#;
    assert!(
        parse_as_classic_script(fixed, "fixed").is_ok(),
        "the gate must accept the corrected form"
    );

    // Constructs a hand-rolled scanner gets wrong, which a real parser does not:
    // a regex literal containing brackets, division that looks like a regex, and
    // template literals nested inside `${...}` (the space renderer's shape).
    let tricky = r#"
      function f(s){ return /[)}\]]/.test(s); }
      let i = 2; let q = i++ / (i + 1);
      const html = `<div>${items.map(t => `<b>${t}</b>`).join('')}</div>`;
    "#;
    assert!(
        parse_as_classic_script(tricky, "tricky").is_ok(),
        "the gate must accept valid regex literals, division and nested templates"
    );
}

/// The gate must use browser classic-script grammar, not Node's CommonJS
/// grammar. These two cases are exactly where the two diverge, so they fail if
/// anyone swaps `vm.Script` back for `node --check`.
#[test]
fn parse_gate_uses_browser_script_grammar() {
    assert!(
        parse_as_classic_script("return;", "toplevel_return").is_err(),
        "top-level `return;` is invalid in a browser <script> and must be \
         rejected — `node --check` wrongly accepts it via the CommonJS wrapper"
    );
    assert!(
        parse_as_classic_script("let require = 1;", "shadow_require").is_ok(),
        "`let require = 1;` is valid in a browser <script> and must be \
         accepted — `node --check` wrongly rejects it as a CommonJS binding"
    );
}
