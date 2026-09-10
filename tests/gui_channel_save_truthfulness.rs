//! Behavioral truthfulness tests for the GUI's Space channel-index save
//! path (issue #565).
//!
//! The GUI is one inline classic script; these tests EXECUTE it (the same
//! `node:vm` approach as `gui_script_syntax.rs`, which exists because
//! substring suites stayed green while the GUI was dead in v0.41.1/v0.41.2)
//! against a fully mocked DOM and REST surface, then drive
//! `createChannel`/`loadSpaceChannels` directly.
//!
//! WHY THIS MATTERS (#565): a save that cannot report its own failure is
//! user-visible data loss — the user is told "Channel created" for a write
//! that never landed. The old code ignored the create/PUT responses and
//! toasted success unconditionally. These tests pin the contract from both
//! sides: a FAILED save must NOT be reported as success (and must keep the
//! user's draft), and a successful save still is. They also pin the
//! store-binding half: a PRIVATE space's channel index must go to the
//! group-bound store, never the unbound generic Signed store.
//!
//! Node is required (as for the parse gate); a missing Node FAILS the test
//! rather than skipping it, so the gate cannot pass vacuously.

use std::process::Command;

const GUI_HTML: &str = include_str!("../src/gui/x0x-gui.html");

/// Run the GUI script plus `driver` (appended in the same classic-script
/// scope, so it can observe and reassign the script's own globals) inside a
/// sandboxed `node:vm` context. Returns (success, captured stdout).
fn run_driver(driver: &str, label: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!(
        "x0x-gui-565-{}-{}",
        std::process::id(),
        label.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir for the GUI driver");
    let html_path = dir.join("gui.html");
    std::fs::write(&html_path, GUI_HTML).expect("write GUI html");

    let node_program = r#"
        const fs = require('node:fs');
        const vm = require('node:vm');
        const html = fs.readFileSync(process.env.X0X_GUI_HTML_PATH, 'utf8');
        let best = '';
        let rest = html;
        for (;;) {
            const open = rest.indexOf('<script');
            if (open < 0) break;
            const gt = rest.indexOf('>', open);
            if (gt < 0) break;
            const close = rest.indexOf('</script>', gt);
            if (close < 0) break;
            const body = rest.slice(gt + 1, close);
            if (body.length > best.length) best = body;
            rest = rest.slice(close + 9);
        }
        // ---- minimal DOM/storage/network sandbox ----
        function fakeElement(id) {
            const el = {
                id: id, value: '', textContent: '', innerHTML: '', srcdoc: '',
                style: {}, dataset: {}, checked: false, files: [],
                children: [], _listeners: {},
                setAttribute() {}, getAttribute() { return null },
                appendChild(c) { this.children.push(c); return c },
                removeChild() {}, remove() {},
                addEventListener(t, f) { (this._listeners[t] ||= []).push(f) },
                removeEventListener() {},
                dispatchEvent() { return true },
                focus() {}, click() {}, blur() {}, select() {},
                querySelector() { return fakeElement(id + '-q') },
                querySelectorAll() { return [] },
                closest() { return null },
                contains() { return false },
                classList: { add() {}, remove() {}, toggle() {}, contains() { return false } },
                insertAdjacentHTML() {},
            };
            Object.defineProperty(el, 'src', { set() {}, get() { return '' } });
            return el;
        }
        const byId = new Map();
        function elem(id) {
            if (!byId.has(id)) byId.set(id, fakeElement(id));
            return byId.get(id);
        }
        const modalOverlay = fakeElement('modal-overlay');
        modalOverlay.closest = () => modalOverlay;
        modalOverlay.remove = () => { sandbox.__modalRemoved = true; };
        const storage = () => {
            const m = new Map();
            return {
                getItem: k => (m.has(k) ? m.get(k) : null),
                setItem: (k, v) => m.set(k, String(v)),
                removeItem: k => m.delete(k),
                clear: () => m.clear(),
            };
        };
        const captured = [];
        const sandbox = {
            console: {
                log(...a) { captured.push(a.map(String).join(' ')) },
                error(...a) { captured.push('console.error ' + a.map(String).join(' ')) },
                warn(...a) { captured.push('console.warn ' + a.map(String).join(' ')) },
            },
            setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
            clearInterval() {}, queueMicrotask() {},
            Date, Math, JSON, Object, Array, String, Number, Boolean, Map, Set,
            Promise, RegExp, Error, Uint8Array, ArrayBuffer, TextEncoder,
            TextDecoder, URL, encodeURIComponent, decodeURIComponent,
            btoa: s => Buffer.from(s, 'binary').toString('base64'),
            atob: s => Buffer.from(s, 'base64').toString('binary'),
            fetch: () => Promise.resolve({ ok: false, status: 0, statusText: 'stub', json: () => Promise.resolve({}) }),
            WebSocket: class { constructor() {} send() {} close() {} addEventListener() {} },
            EventSource: class { constructor() {} addEventListener() {} close() {} },
            matchMedia: () => ({ matches: false, media: '', addEventListener() {}, removeEventListener() {} }),
            navigator: { userAgent: 'test' },
            location: { href: 'http://127.0.0.1/', origin: 'http://127.0.0.1', reload() {} },
            history: { pushState() {}, replaceState() {} },
            alert() {}, prompt: () => null, confirm: () => false,
            localStorage: storage(), sessionStorage: storage(),
            document: {
                getElementById: id => elem(id),
                querySelector: sel => (sel === '.modal-overlay' ? modalOverlay : fakeElement(sel)),
                querySelectorAll: () => [],
                createElement: tag => fakeElement(tag),
                createTextNode: t => ({ textContent: t }),
                addEventListener() {}, removeEventListener() {},
                body: fakeElement('body'), documentElement: fakeElement('html'),
            },
            __modalRemoved: false,
            window: null,
        };
        sandbox.window = sandbox;
        sandbox.globalThis = sandbox;
        (async () => {
            try {
                vm.runInNewContext(best + '\n;\n' + process.env.X0X_DRIVER, sandbox, {
                    filename: 'gui.js', timeout: 20000,
                });
                // The driver stores its completion promise on globalThis so
                // its async continuations (awaited API stubs) finish before
                // the process reads the captured console output.
                if (sandbox.__done) await sandbox.__done;
                await new Promise(resolve => setImmediate(resolve));
            } catch (e) {
                process.stdout.write('DRIVER_THREW ' + e + '\n');
                process.exit(3);
            }
            process.stdout.write(captured.join('\n') + '\n');
        })();
        "#;

    let out = Command::new("node")
        .arg("-e")
        .arg(node_program)
        .env("X0X_GUI_HTML_PATH", html_path)
        .env("X0X_DRIVER", driver)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            (o.status.success(), stdout)
        }
        Err(e) => (false, format!("failed to run node: {e}")),
    }
}

/// Shared driver preamble: stub `api` after the script has loaded (the
/// script's own `api` is a top-level function declaration, so reassigning
/// the binding replaces it for every later caller), capture toasts, seed the
/// modal inputs, and provide a small routing table.
const DRIVER_PREAMBLE: &str = r#"
const CALLS = [];
const TOASTS = [];
toast = (msg, type) => { TOASTS.push({ msg: String(msg), type: type || 'info' }); };
let ROUTES = {};
api = async (path, opt) => {
    const method = (opt && opt.method) || 'GET';
    CALLS.push(method + ' ' + path);
    const key = method + ' ' + path;
    const r = (ROUTES[key] !== undefined) ? ROUTES[key] : { _http_ok: true, ok: true };
    return Object.assign({}, r);
};
function seedModal(name, desc) {
    document.getElementById('modal-chan-name').value = name;
    document.getElementById('modal-chan-desc').value = desc;
    document.getElementById('modal-chan-error').style.display = 'none';
    document.getElementById('modal-chan-error').textContent = '';
    __modalRemoved = false;
}
function modalErrorText() {
    const e = document.getElementById('modal-chan-error');
    return { shown: e.style.display !== 'none', text: e.textContent };
}
"#;

fn public_space_routes() -> &'static str {
    // A signed_public space whose page store already exists.
    r#"
    ROUTES['GET /groups/sid1'] = { _http_ok: true, ok: true, policy: { confidentiality: 'signed_public' } };
    ROUTES['GET /stores'] = { _http_ok: true, ok: true, stores: [{ id: 'x0x-channels-sid1' }] };
    "#
}

/// #565 (the serious half): a FAILED index PUT must NOT be reported as
/// success — no success toast, the modal stays open with the draft and an
/// error, and the channel is not cached or navigated to.
#[test]
fn gui_failed_channel_save_is_not_reported_as_success() {
    let driver = format!(
        r#"
{DRIVER_PREAMBLE}
{routes}
ROUTES['GET /stores/x0x-channels-sid1/channels_index'] = {{ _http_ok: false, _http_status: 404 }};
ROUTES['PUT /stores/x0x-channels-sid1/channels_index'] = {{ _http_ok: false, _http_status: 500, error: 'disk on fire' }};
S.set('agentId', 'aa');
seedModal('launch', 'the launch channel');
globalThis.__done = createChannel('sid1').then(() => {{
    const toasts = TOASTS;
    const err = modalErrorText();
    const cached = channelCache['sid1'];
    const result = {{
        successToastShown: toasts.some(t => t.msg.indexOf('created') !== -1 && t.type === 'success'),
        errorToastShown: toasts.some(t => t.type === 'error'),
        modalErrorShown: err.shown,
        modalErrorMentionsFailure: err.shown && /NOT created/i.test(err.text),
        modalKeptOpen: !__modalRemoved,
        channelNotCached: !cached,
        stayedOnChannel: (S.get('channel') || 'general') === 'general',
    }};
    console.log('RESULT ' + JSON.stringify(result));
}}).catch(e => {{ console.log('DRIVER_THREW ' + e); process.exit(4); }});
"#,
        DRIVER_PREAMBLE = DRIVER_PREAMBLE,
        routes = public_space_routes(),
    );
    let (ok, stdout) = run_driver(&driver, "failed-save");
    assert!(ok, "node driver failed; stdout:\n{stdout}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap_or_else(|| panic!("driver printed no RESULT; stdout:\n{stdout}"));
    let r: serde_json::Value =
        serde_json::from_str(line.trim_start_matches("RESULT ")).expect("RESULT json");
    let get = |k: &str| r[k].as_bool().unwrap_or_else(|| panic!("field {k}"));
    assert!(
        !get("successToastShown"),
        "a FAILED save must not produce a success toast"
    );
    assert!(
        get("modalErrorShown"),
        "a failed save must surface its error"
    );
    assert!(
        get("modalErrorMentionsFailure"),
        "the error must say the channel was NOT created"
    );
    assert!(
        get("modalKeptOpen"),
        "a failed save must keep the modal (and the user's draft) open"
    );
    assert!(
        get("channelNotCached"),
        "a failed save must not update the channel cache"
    );
    assert!(
        get("stayedOnChannel"),
        "a failed save must not navigate into the channel"
    );
}

/// The other side of the same contract: a genuinely successful save IS
/// reported (exactly once), cached, and navigated to.
#[test]
fn gui_successful_channel_save_is_reported_and_cached() {
    let driver = format!(
        r#"
{DRIVER_PREAMBLE}
{routes}
ROUTES['GET /stores/x0x-channels-sid1/channels_index'] = {{ _http_ok: false, _http_status: 404 }};
ROUTES['PUT /stores/x0x-channels-sid1/channels_index'] = {{ _http_ok: true, ok: true }};
S.set('agentId', 'aa');
seedModal('launch', 'the launch channel');
globalThis.__done = createChannel('sid1').then(() => {{
    const result = {{
        successToastShown: TOASTS.filter(t => t.type === 'success' && t.msg.indexOf('#launch') !== -1).length,
        modalClosed: __modalRemoved,
        channelCached: !!(channelCache['sid1'] || []).some(c => c.name === 'launch'),
        navigated: S.get('channel') === 'launch',
    }};
    console.log('RESULT ' + JSON.stringify(result));
}}).catch(e => {{ console.log('DRIVER_THREW ' + e); process.exit(4); }});
"#,
        DRIVER_PREAMBLE = DRIVER_PREAMBLE,
        routes = public_space_routes(),
    );
    let (ok, stdout) = run_driver(&driver, "ok-save");
    assert!(ok, "node driver failed; stdout:\n{stdout}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap_or_else(|| panic!("driver printed no RESULT; stdout:\n{stdout}"));
    let r: serde_json::Value =
        serde_json::from_str(line.trim_start_matches("RESULT ")).expect("RESULT json");
    assert_eq!(
        r["successToastShown"].as_i64(),
        Some(1),
        "a successful save reports success exactly once"
    );
    assert_eq!(r["modalClosed"].as_bool(), Some(true));
    assert_eq!(r["channelCached"].as_bool(), Some(true));
    assert_eq!(r["navigated"].as_bool(), Some(true));
}

/// #565 (the binding half): in a PRIVATE space the channel index must be
/// written to the GROUP-BOUND store returned by POST /groups/:id/stores —
/// the unbound generic `/stores` path must never be touched, not even to
/// create or list.
#[test]
fn gui_private_space_channel_index_uses_group_store_only() {
    let driver = format!(
        r#"
{DRIVER_PREAMBLE}
ROUTES['GET /groups/sid2'] = {{ _http_ok: true, ok: true, policy: {{ confidentiality: 'mls_encrypted' }} }};
ROUTES['POST /groups/sid2/stores'] = {{ _http_ok: true, ok: true, id: 'x0x/group/g2/kv/channels', topic: 'x0x/group/g2/kv/channels' }};
ROUTES['GET /stores/x0x%2Fgroup%2Fg2%2Fkv%2Fchannels/channels_index'] = {{ _http_ok: false, _http_status: 404 }};
ROUTES['PUT /stores/x0x%2Fgroup%2Fg2%2Fkv%2Fchannels/channels_index'] = {{ _http_ok: true, ok: true }};
S.set('agentId', 'aa');
seedModal('ops', '');
globalThis.__done = createChannel('sid2').then(() => {{
    const generic = CALLS.some(c => c === 'GET /stores' || c === 'POST /stores' || /^PUT \/stores\/x0x-channels/.test(c));
    const groupPut = CALLS.some(c => c === 'PUT /stores/x0x%2Fgroup%2Fg2%2Fkv%2Fchannels/channels_index');
    const result = {{ genericStoresTouched: generic, groupStoreWritten: groupPut, successToastShown: TOASTS.some(t => t.type === 'success'), modalError: modalErrorText().text, calls: CALLS.join(' ; ') }};
    console.log('RESULT ' + JSON.stringify(result));
}}).catch(e => {{ console.log('DRIVER_THREW ' + e); process.exit(4); }});
"#,
        DRIVER_PREAMBLE = DRIVER_PREAMBLE,
    );
    let (ok, stdout) = run_driver(&driver, "private-binding");
    assert!(ok, "node driver failed; stdout:\n{stdout}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap_or_else(|| panic!("driver printed no RESULT; stdout:\n{stdout}"));
    let r: serde_json::Value =
        serde_json::from_str(line.trim_start_matches("RESULT ")).expect("RESULT json");
    assert_eq!(
        r["genericStoresTouched"].as_bool(),
        Some(false),
        "a private space must never touch the generic /stores API",
    );
    assert_eq!(
        r["groupStoreWritten"].as_bool(),
        Some(true),
        "the channel index must land in the group-bound store; calls: {}",
        r["calls"].as_str().unwrap_or_default()
    );
    assert_eq!(r["successToastShown"].as_bool(), Some(true));
}

/// #565 (loads): a FAILED channel-index read must not masquerade as "this
/// space has no channels" — the failure is recorded and surfaced, while the
/// functional default keeps the chat usable.
#[test]
fn gui_failed_channel_load_is_distinguished_from_empty() {
    let driver = format!(
        r#"
{DRIVER_PREAMBLE}
{routes}
ROUTES['GET /stores/x0x-channels-sid1/channels_index'] = {{ _http_ok: false, _http_status: 500, error: 'store backend down' }};
globalThis.__done = loadSpaceChannels('sid1').then(channels => {{
    const result = {{
        errorRecorded: !!channelErrors['sid1'],
        errorTextMentionsFailure: /Could not load/.test(String(channelErrors['sid1'] || '')),
        functionalDefault: channels.length === 1 && channels[0].name === 'general',
    }};
    console.log('RESULT ' + JSON.stringify(result));
}}).catch(e => {{ console.log('DRIVER_THREW ' + e); process.exit(4); }});
"#,
        DRIVER_PREAMBLE = DRIVER_PREAMBLE,
        routes = public_space_routes(),
    );
    let (ok, stdout) = run_driver(&driver, "failed-load");
    assert!(ok, "node driver failed; stdout:\n{stdout}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap_or_else(|| panic!("driver printed no RESULT; stdout:\n{stdout}"));
    let r: serde_json::Value =
        serde_json::from_str(line.trim_start_matches("RESULT ")).expect("RESULT json");
    assert_eq!(
        r["errorRecorded"].as_bool(),
        Some(true),
        "a failed read must be recorded as a failure"
    );
    assert!(r["errorTextMentionsFailure"].as_bool() == Some(true));
    assert_eq!(
        r["functionalDefault"].as_bool(),
        Some(true),
        "the default #general must remain usable after a failed read"
    );
}
