//! The embedded GUI is ONE inline `<script>`: a single unbalanced delimiter
//! makes the whole script fail to parse, so nothing binds, nothing fetches
//! and the page renders blank — with only a console `SyntaxError` to show
//! for it.
//!
//! That shipped: v0.41.1 (commit bdd3f46) converted the peer-events log from
//! `onmessage = e => {...};` to `addEventListener('peer-lifecycle', e => {...}`
//! and kept the assignment's `};` terminator instead of `});`. The GUI was
//! dead in v0.41.1 and v0.41.2 while every existing GUI suite stayed green,
//! because they match endpoint strings and never check that the script parses.
//!
//! CI has no Node, so this is a dependency-free delimiter scanner over the
//! extracted script. It skips string literals, template literals, comments and
//! regex literals, then asserts the bracket stack balances — exactly the
//! property the shipped bug violated.

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
    assert!(
        !best.is_empty(),
        "no inline <script> found in the embedded GUI"
    );
    best
}

#[derive(Debug)]
struct Unbalanced {
    line: usize,
    detail: String,
}

/// Scan JS source and report the first delimiter imbalance.
///
/// Conservative by construction: anything inside a string, template, comment
/// or regex literal is skipped, so only real code delimiters are counted.
/// Template literals are handled with a mode stack so that `${...}`
/// interpolations — which may themselves contain further template literals,
/// as the space renderer does — are scanned as code, not skipped as text.
fn find_imbalance(src: &str) -> Option<Unbalanced> {
    let b = src.as_bytes();
    // `(`/`{`/`[` plus a `$` marker for an open `${` interpolation.
    let mut stack: Vec<(u8, usize)> = Vec::new();
    // false = scanning code, true = scanning template-literal text.
    let mut template_modes: Vec<bool> = vec![false];
    let mut line = 1usize;
    let mut i = 0usize;
    // Tracks whether a `/` here starts a regex literal (as opposed to
    // division): true right after an operator, comma, or opening bracket.
    let mut regex_allowed = true;

    while i < b.len() {
        // Inside template text: only `\`, `${` and the closing backtick matter.
        if *template_modes.last().unwrap_or(&false) {
            match b[i] {
                b'\\' => i += 2,
                b'\n' => {
                    line += 1;
                    i += 1;
                }
                b'`' => {
                    template_modes.pop();
                    i += 1;
                    regex_allowed = false;
                }
                b'$' if i + 1 < b.len() && b[i + 1] == b'{' => {
                    stack.push((b'$', line));
                    template_modes.push(false);
                    i += 2;
                    regex_allowed = true;
                }
                _ => i += 1,
            }
            continue;
        }

        let c = b[i];
        match c {
            b'`' => {
                template_modes.push(true);
                i += 1;
            }
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    if b[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            b'/' if regex_allowed => {
                // Regex literal: skip to the unescaped closing slash.
                i += 1;
                let mut in_class = false;
                while i < b.len() {
                    match b[i] {
                        b'\\' => i += 1,
                        b'[' => in_class = true,
                        b']' => in_class = false,
                        b'/' if !in_class => break,
                        b'\n' => {
                            // Unterminated regex — treat as division after all.
                            break;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
                regex_allowed = false;
            }
            b'\'' | b'"' => {
                let quote = c;
                i += 1;
                while i < b.len() {
                    match b[i] {
                        b'\\' => i += 1,
                        b'\n' => line += 1,
                        q if q == quote => break,
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
                regex_allowed = false;
            }
            b'(' | b'{' | b'[' => {
                stack.push((c, line));
                i += 1;
                regex_allowed = true;
            }
            // `}` closing a `${` interpolation returns to template text.
            b'}' if matches!(stack.last(), Some((b'$', _))) => {
                stack.pop();
                template_modes.pop();
                i += 1;
                regex_allowed = false;
            }
            b')' | b']' | b'}' => {
                let want = match c {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                match stack.pop() {
                    Some((open, _)) if open == want => {}
                    Some((open, open_line)) => {
                        return Some(Unbalanced {
                            line,
                            detail: format!(
                                "found '{}' closing a '{}' opened on line {open_line}",
                                c as char, open as char
                            ),
                        });
                    }
                    None => {
                        return Some(Unbalanced {
                            line,
                            detail: format!("stray closing '{}'", c as char),
                        });
                    }
                }
                i += 1;
                regex_allowed = false;
            }
            _ => {
                // Operators and punctuation permit a following regex literal;
                // identifiers, numbers and `)`/`]` do not.
                regex_allowed = matches!(
                    c,
                    b'=' | b'+'
                        | b'-'
                        | b'*'
                        | b'%'
                        | b'&'
                        | b'|'
                        | b'^'
                        | b'!'
                        | b'?'
                        | b':'
                        | b';'
                        | b','
                        | b'<'
                        | b'>'
                        | b'~'
                );
                i += 1;
            }
        }
    }

    if let Some((open, open_line)) = stack.pop() {
        return Some(Unbalanced {
            line: open_line,
            detail: format!("'{}' opened here is never closed", open as char),
        });
    }
    if template_modes.len() > 1 || template_modes.first() == Some(&true) {
        return Some(Unbalanced {
            line,
            detail: "a template literal (`) is never closed".to_string(),
        });
    }
    None
}

/// The regression gate: the embedded GUI's script must have balanced
/// delimiters. An imbalance means the browser throws `SyntaxError` on load and
/// the entire GUI is dead.
#[test]
fn embedded_gui_script_delimiters_balance() {
    let script = extract_main_script(GUI_HTML);
    if let Some(bad) = find_imbalance(script) {
        panic!(
            "src/gui/x0x-gui.html: the inline GUI script has unbalanced delimiters \
             (script-relative line {}): {}.\n\
             The whole GUI is ONE script — this makes the browser throw \
             SyntaxError on load and render a blank page (regression of v0.41.1 \
             commit bdd3f46, where an addEventListener(...) call was closed with \
             '}};' instead of '}});').",
            bad.line, bad.detail
        );
    }
}

/// Every `addEventListener(` call in the GUI must be closed as a CALL
/// (`});`/`})`), never with an assignment's `};` — the exact v0.41.1 defect.
#[test]
fn gui_add_event_listener_calls_are_closed_as_calls() {
    let script = extract_main_script(GUI_HTML);
    for (idx, _) in script.match_indices("addEventListener(") {
        let tail = &script[idx..];
        // Walk to the matching close of this call's argument list.
        let bytes = tail.as_bytes();
        let mut depth = 0i32;
        let mut end = None;
        let mut i = tail.find('(').unwrap_or(0);
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                b'\'' | b'"' | b'`' => {
                    let quote = bytes[i];
                    i += 1;
                    while i < bytes.len() && bytes[i] != quote {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        assert!(
            end.is_some(),
            "src/gui/x0x-gui.html: an addEventListener( call near byte {idx} is \
             never closed — its argument list has no matching ')'. This is the \
             v0.41.1 blank-GUI regression."
        );
    }
}

/// Sanity: the scanner actually rejects the exact shipped defect, so the gate
/// above cannot pass vacuously.
#[test]
fn scanner_rejects_the_v0_41_1_defect_shape() {
    let broken = r#"
      el.addEventListener('peer-lifecycle',e=>{
        doThing(e.data);
      };
      el.onerror=()=>{};
    "#;
    assert!(
        find_imbalance(broken).is_some(),
        "the scanner must reject an addEventListener call closed with '}};'"
    );

    let fixed = r#"
      el.addEventListener('peer-lifecycle',e=>{
        doThing(e.data);
      });
      el.onerror=()=>{};
    "#;
    assert!(
        find_imbalance(fixed).is_none(),
        "the scanner must accept the corrected form"
    );

    // Strings, comments and regex literals must not confuse the scanner.
    let tricky = r#"
      const re=/[)}\]]+/g, s=") } ]", t=`${x} )`; // trailing ) in a comment
      /* block ) } ] */
      f(function(){ return s.replace(re,''); });
    "#;
    assert!(
        find_imbalance(tricky).is_none(),
        "the scanner must ignore delimiters inside strings, comments and regexes"
    );

    // NESTED template literals: a `${...}` interpolation containing another
    // template literal (the space renderer's sub-tabs shape). An earlier
    // scanner skipped to the wrong backtick and reported a phantom imbalance.
    let nested = r#"
      el.innerHTML=`<div>${tabs.map(t=>
        `<button onclick="go('${sid}','${t}')">${t.slice(1)}</button>`
      ).join('')}</div>`;
    "#;
    assert!(
        find_imbalance(nested).is_none(),
        "the scanner must handle template literals nested inside ${{...}}"
    );

    // ...and still catch a real imbalance that occurs inside an interpolation.
    let nested_broken = r#"
      el.innerHTML=`<div>${tabs.map(t=>
        `<button>${t}</button>`
      .join('')}</div>`;
    "#;
    assert!(
        find_imbalance(nested_broken).is_some(),
        "the scanner must still catch an imbalance inside an interpolation"
    );
}
