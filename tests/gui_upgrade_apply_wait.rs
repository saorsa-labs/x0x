//! Pending ordinary GUI upgrade apply (#1535).
//!
//! Executes the banner and `applyUpgrade` from `src/gui/x0x-gui.html`.
//! While `POST /upgrade/apply` is in flight, the control stays disabled and
//! the page says the request can wait for the rollout window. The text gives
//! no phase, progress percentage, or ETA. The same check then settles the
//! request and checks the existing success, refusal, and error states.
//!
//! Node is required. A missing Node fails the test.

use std::process::Command;

#[test]
fn gui_ordinary_apply_explains_rollout_wait_then_settles() {
    let html = concat!(env!("CARGO_MANIFEST_DIR"), "/src/gui/x0x-gui.html");
    let output = Command::new("node")
        .arg("-e")
        .arg(NODE_PROGRAM)
        .env("X0X_GUI_HTML_PATH", html)
        .output()
        .expect("Node is required for the ordinary upgrade-apply GUI check");
    assert!(
        output.status.success(),
        "ordinary upgrade-apply GUI check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

const NODE_PROGRAM: &str = r#"
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(process.env.X0X_GUI_HTML_PATH, 'utf8');
const startMark = '// gui-upgrade-apply-wait:start';
const endMark = '// gui-upgrade-apply-wait:end';
const start = html.indexOf(startMark);
const end = html.indexOf(endMark);
assert(start >= 0 && end > start, 'upgrade apply section markers exist');
const source = html.slice(start, end);
assert.equal(source.includes('/upgrade/apply?now'), false);
assert.equal(source.includes("ownerApi('/upgrade/apply',{method:'POST'})"), true);

const driver = `
const calls = [];
const toasts = [];
let gate;
const nodes = {};
function make(id) {
  return {
    id,
    innerHTML: '',
    textContent: '',
    disabled: false,
    style: {},
    children: [],
    parentElement: null,
    appendChild(child) {
      child.parentElement = this;
      this.children.push(child);
      if (child.id) nodes[child.id] = child;
      return child;
    },
    remove() {
      if (this.parentElement) {
        this.parentElement.children = this.parentElement.children.filter(child => child !== this);
      }
      if (nodes[this.id] === this) delete nodes[this.id];
    },
  };
}
const document = {
  getElementById(id) { return nodes[id] || null; },
  createElement() { return make(''); },
};
function toast(msg, type) { toasts.push({ msg, type }); }
function esc(s) {
  return String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}
async function ownerApi(path, opt) {
  calls.push({ path, opt });
  return gate;
}
function resetDom() {
  for (const key of Object.keys(nodes)) delete nodes[key];
  const banner = make('h-upgrade-banner');
  const card = make('upg-banner');
  const btn = make('upg-apply-btn');
  btn.textContent = 'Apply update';
  card.appendChild(btn);
  banner.appendChild(card);
  nodes['h-upgrade-banner'] = banner;
  nodes['upg-banner'] = card;
  nodes['upg-apply-btn'] = btn;
}
function assertNoProgressClaim(text) {
  assert.equal(/\\bphase\\b/i.test(text), false, text);
  assert.equal(/percent|percentage|\\bETA\\b|%|\\d/i.test(text), false, text);
}
function bannerHtml() {
  return document.getElementById('h-upgrade-banner').innerHTML;
}
async function flushUntilCall() {
  for (let i = 0; i < 8 && calls.length < 1; i++) await Promise.resolve();
}
const release = { update_available: true, version: '2.0.0', current_version: '1.0.0' };
const cases = [
  {
    name: 'applied',
    response: { ok: true, applied: true, version: '9.9.9' },
    button: 'Applied',
    disabled: true,
    toastType: 'success',
    toast: 'Upgrade applied: v9.9.9. Daemon will restart.',
  },
  {
    name: 'no upgrade',
    response: { ok: true, applied: false, reason: 'No upgrade required' },
    button: 'Apply update',
    disabled: false,
    toastType: 'info',
    toast: 'No upgrade required',
  },
  {
    name: 'ok without an install',
    response: { ok: true },
    button: 'Apply update',
    disabled: false,
    toastType: 'info',
    toast: 'No upgrade required',
  },
  {
    name: 'error',
    response: { ok: false, error: 'manifest rejected' },
    button: 'Apply update',
    disabled: false,
    toastType: 'error',
    toast: 'Upgrade failed: manifest rejected',
  },
  {
    name: 'error reason',
    response: { ok: false, reason: 'held' },
    button: 'Apply update',
    disabled: false,
    toastType: 'error',
    toast: 'Upgrade failed: held',
  },
  {
    name: 'no response',
    response: null,
    button: 'Apply update',
    disabled: false,
    toastType: 'error',
    toast: 'Apply failed: no response',
  },
];
globalThis.__done = (async () => {
  assert.equal(
    UPGRADE_APPLY_WAIT_TEXT,
    'This request can wait for the rollout window before it installs. This may take over an hour.'
  );
  assertNoProgressClaim(UPGRADE_APPLY_WAIT_TEXT);
  resetDom();
  renderUpgradeBanner(release);
  const idle = bannerHtml();
  assert.equal(idle.includes('upg-apply-wait'), false);
  assert.equal(idle.includes('>Apply update</button>'), true);
  assert.equal(idle.includes(' disabled'), false);
  assertNoProgressClaim(UPGRADE_APPLY_WAIT_TEXT);
  renderUpgradeBanner(null);
  assert.equal(document.getElementById('h-upgrade-banner').style.display, 'none');
  assert.equal(bannerHtml(), '');

  for (const c of cases) {
    calls.length = 0;
    toasts.length = 0;
    upgradeApplyInFlight = false;
    resetDom();
    let resolveGate;
    gate = new Promise(resolve => { resolveGate = resolve; });
    const done = applyUpgrade();
    await flushUntilCall();
    assert.equal(calls.length, 1, c.name + ' request count');
    assert.equal(calls[0].path, '/upgrade/apply', c.name);
    assert.equal(calls[0].opt.method, 'POST', c.name);
    assert.equal(JSON.stringify(calls[0].opt).includes('now'), false, c.name);
    assert.equal(upgradeApplyInFlight, true, c.name);
    const btn = document.getElementById('upg-apply-btn');
    assert.equal(btn.disabled, true, c.name);
    assert.equal(btn.textContent, 'Applying…', c.name);
    const note = document.getElementById('upg-apply-wait');
    assert.equal(note.textContent, UPGRADE_APPLY_WAIT_TEXT, c.name);
    await applyUpgrade();
    assert.equal(calls.length, 1, c.name + ' duplicate');
    assert.equal(btn.disabled, true, c.name + ' still disabled');
    renderUpgradeBanner(release);
    const pendingHtml = bannerHtml();
    assert.equal(pendingHtml.split(UPGRADE_APPLY_WAIT_TEXT).length - 1, 1, c.name);
    assert.equal(pendingHtml.includes('id="upg-apply-wait"'), true, c.name);
    assert.equal(pendingHtml.includes('Applying…'), true, c.name);
    assert.equal(pendingHtml.includes(' disabled'), true, c.name);
    assert.equal(calls.length, 1, c.name + ' redraw');
    resolveGate(c.response);
    await done;
    assert.equal(upgradeApplyInFlight, false, c.name);
    assert.equal(document.getElementById('upg-apply-wait'), null, c.name);
    assert.equal(btn.textContent, c.button, c.name);
    assert.equal(btn.disabled, c.disabled, c.name);
    assert.equal(toasts.length, 1, c.name);
    assert.equal(toasts[0].type, c.toastType, c.name);
    assert.equal(toasts[0].msg, c.toast, c.name);
    renderUpgradeBanner(release);
    const settled = bannerHtml();
    assert.equal(settled.includes('upg-apply-wait'), false, c.name);
    assert.equal(settled.includes(UPGRADE_APPLY_WAIT_TEXT), false, c.name);
    assert.equal(settled.includes('>Apply update</button>'), true, c.name);
    assert.equal(settled.includes(' disabled'), false, c.name);
    console.log('PASS ' + c.name);
  }
})();
`;

const sandbox = {
  console,
  assert,
  Promise,
  JSON,
  Object,
  String,
  Array,
  Error,
  RegExp,
};
sandbox.globalThis = sandbox;
try {
  vm.runInNewContext(source + '\n' + driver, sandbox, {
    filename: 'gui-upgrade-apply-wait.js',
    timeout: 10000,
  });
} catch (error) {
  console.error(error);
  process.exit(1);
}
if (sandbox.__done) {
  sandbox.__done.then(
    () => process.exit(0),
    error => {
      console.error(error);
      process.exit(1);
    }
  );
} else {
  console.error('driver did not start');
  process.exit(1);
}
"#;
