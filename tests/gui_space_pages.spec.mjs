// #565 stage-1 containment controls for the Space Wiki/Web page tabs.
//
// FULLY INTERCEPTED: the GUI document is served from disk and EVERY request
// the page makes is answered by this file. No daemon, no x0xd, no network, no
// listening socket. Each test records the exact request paths the GUI issued,
// so "the private Space never touches the generic store API" is proven by the
// absence of the request rather than by reading the source.
//
// Run: npx playwright test tests/gui_space_pages.spec.mjs
//
// These controls cover containment only. They do NOT prove the full #565 goal
// (Home/TreeKEM group stores, collaborative multi-writer sharing); that work
// is a separate backend change under independent review.

import { test, expect } from 'playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
// X0X_GUI_HTML_PATH lets a reviewer re-point these controls at another copy of
// the GUI (e.g. the pre-patch file from git) to confirm they genuinely fail
// without the fix rather than passing vacuously.
const GUI_HTML = readFileSync(
  process.env.X0X_GUI_HTML_PATH || join(HERE, '..', 'src', 'gui', 'x0x-gui.html'),
  'utf8',
);

const chromeCandidates = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].filter(Boolean);
const executablePath = chromeCandidates.find((p) => {
  try { return existsSync(p); } catch { return false; }
});
if (executablePath) test.use({ launchOptions: { executablePath } });

const ORIGIN = 'http://x0x-gui-565.test';

/// Mount the GUI with a scripted API. `routes` maps `METHOD /path` to
/// `{status, body}`; anything unmatched returns 404 and is still recorded.
async function mountGui(page, routes, opts) {
  const seen = [];
  const gate = (opts && opts.gate) || null;
  await page.route('**/*', async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (url.origin !== ORIGIN) return route.abort();
    if (url.pathname === '/gui') {
      return route.fulfill({ status: 200, contentType: 'text/html', body: GUI_HTML });
    }
    const key = `${req.method()} ${url.pathname}`;
    seen.push(key);
    const hit = routes[key];
    if (!hit) {
      return route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({ ok: false, error: 'no fixture for ' + key }),
      });
    }
    // A route may be held open so a slow response can be released after a
    // later, faster one has already completed.
    if (gate && gate.holds[key]) await gate.holds[key].promise;
    return route.fulfill({
      status: hit.status,
      contentType: 'application/json',
      body: JSON.stringify(hit.body),
    });
  });
  await page.goto(`${ORIGIN}/gui?token=test-session-token`, { waitUntil: 'domcontentloaded' });
  // Wait on entry points that exist in BOTH the candidate and the pre-patch
  // tree, so a baseline run reaches its behavioural assertions instead of
  // timing out on a helper this patch introduces. (Senior P3.)
  await page.waitForFunction(() =>
    typeof window.api === 'function' &&
    typeof window.saveWikiPage === 'function' &&
    typeof window.editWikiPage === 'function' &&
    typeof window.previewWebPage === 'function' &&
    typeof window.renderSpaceWiki === 'function');
  return seen;
}

/// A releasable hold for one route key.
function makeGate(keys) {
  const holds = {};
  for (const k of keys) {
    let release;
    holds[k] = { promise: new Promise((r) => { release = r; }) };
    holds[k].release = release;
  }
  return { holds };
}

const SID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function privateGroup() {
  return { status: 200, body: { ok: true, policy: { confidentiality: 'mls_encrypted' } } };
}
function publicGroup() {
  return { status: 200, body: { ok: true, policy: { confidentiality: 'signed_public' } } };
}

test('private space never issues a generic /stores request when the group store is refused', async ({ page }) => {
  const seen = await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    // The shipped daemon refuses a TreeKEM-plane group here (400).
    [`POST /groups/${SID}/stores`]: {
      status: 400,
      body: { ok: false, error: 'encrypted stores v1 are GSS-backed (ADR-0010); TreeKEM-plane groups are not supported yet' },
    },
  });

  // Behavioural entry point present in both trees.
  await page.evaluate((sid) => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div>');
    return window.loadWikiPages(sid);
  }, SID);
  const shown = await page.innerHTML('#wiki-pages');
  // Plain user-facing wording, no crypto/plane jargon leading the sentence.
  expect(shown).toContain('Private pages are not available in this space yet');

  // The whole point of the containment: no generic store API call at all.
  const generic = seen.filter((k) => /\s\/stores(\/|$)/.test(k));
  expect(generic, `generic store requests leaked: ${JSON.stringify(generic)}`).toEqual([]);
});

test('private space save shows the failure, keeps the draft, and issues no PUT', async ({ page }) => {
  const seen = await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 403, body: { ok: false, error: 'not a member' } },
  });

  await page.evaluate((sid) => {
    document.body.insertAdjacentHTML('beforeend',
      '<div id="wiki-editor" style="display:block"><h3 id="wiki-title"></h3>' +
      '<textarea id="wiki-content"></textarea><div id="wiki-error" style="display:none"></div></div>');
    document.getElementById('wiki-content').value = 'DRAFT KEEP ME';
    window.currentWikiSlug = 'notes';
    return window.saveWikiPage(sid);
  }, SID);

  // Draft intact, editor still open, real error shown, no bogus success toast.
  expect(await page.inputValue('#wiki-content')).toBe('DRAFT KEEP ME');
  expect(await page.evaluate(() => document.getElementById('wiki-editor').style.display)).toBe('block');
  const err = await page.textContent('#wiki-error');
  expect(err).toContain('not a member');
  expect(await page.evaluate(() => document.getElementById('wiki-error').style.display)).toBe('block');
  expect(seen.filter((k) => k.startsWith('PUT '))).toEqual([]);
  expect(seen.filter((k) => /\s\/stores(\/|$)/.test(k))).toEqual([]);
});

test('private space uses the identifier the group opener returned, not a client-built alias', async ({ page }) => {
  const RETURNED = 'x0x.group.store.deadbeefdeadbeef.wiki';
  const seen = await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: {
      status: 200,
      body: { ok: true, id: RETURNED, topic: RETURNED, store_id: 'ff00', policy: 'encrypted', epoch: 3 },
    },
    [`GET /stores/${RETURNED}/notes`]: { status: 200, body: { ok: true, value: btoa('# hello') } },
    [`PUT /stores/${RETURNED}/notes`]: { status: 200, body: { ok: true } },
  });

  // Drive the real entry points: editWikiPage() selects the page (and is the
  // only thing that sets the script-scoped current slug), then saveWikiPage()
  // writes it back.
  await page.evaluate(async (sid) => {
    document.body.insertAdjacentHTML('beforeend',
      '<div id="wiki-editor" style="display:none"><h3 id="wiki-title"></h3>' +
      '<textarea id="wiki-content"></textarea><div id="wiki-error" style="display:none"></div></div>');
    await window.editWikiPage(sid, 'notes');
    return window.saveWikiPage(sid);
  }, SID);

  expect(seen).toContain(`PUT /stores/${RETURNED}/notes`);
  // Never the old Space-id-prefixed alias.
  expect(seen.some((k) => k.includes('x0x-wiki-'))).toBe(false);
  expect(seen.filter((k) => k === 'POST /stores')).toEqual([]);
});

test('page names with reserved URL characters are sent as exactly one segment', async ({ page }) => {
  const RETURNED = 'grp-store-1';
  const KEY = 'docs/start?draft=1#top a/b';
  const seen = await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/${encodeURIComponent(KEY)}`]: { status: 200, body: { ok: true, value: btoa('x') } },
    [`PUT /stores/${RETURNED}/${encodeURIComponent(KEY)}`]: { status: 200, body: { ok: true } },
  });

  await page.evaluate(async ({ sid, key }) => {
    document.body.insertAdjacentHTML('beforeend',
      '<div id="wiki-editor" style="display:none"><h3 id="wiki-title"></h3>' +
      '<textarea id="wiki-content"></textarea><div id="wiki-error" style="display:none"></div></div>');
    await window.editWikiPage(sid, key);
    return window.saveWikiPage(sid);
  }, { sid: SID, key: KEY });

  // Both the read and the write must use one encoded segment.
  const gets = seen.filter((k) => k.startsWith('GET /stores/'));
  expect(gets).toContain(`GET /stores/${RETURNED}/${encodeURIComponent(KEY)}`);
  const puts = seen.filter((k) => k.startsWith('PUT '));
  expect(puts).toHaveLength(1);
  // One store segment + one fully-encoded key segment; the query/fragment
  // characters must not have split the path or leaked into a query string.
  const path = puts[0].slice('PUT '.length);
  expect(path).toBe(`/stores/${RETURNED}/${encodeURIComponent(KEY)}`);
  expect(path.split('/')).toHaveLength(4);
});

test('a failed page read never leaves the previous page in the preview', async ({ page }) => {
  const RETURNED = 'grp-store-web';
  await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/pageA`]: { status: 200, body: { ok: true, value: btoa('PAGE-A-BODY') } },
    [`GET /stores/${RETURNED}/pageB`]: { status: 500, body: { ok: false, error: 'store read failed' } },
  });

  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="web-preview"></div>');
  });
  await page.evaluate((sid) => window.previewWebPage(sid, 'pageA'), SID);
  expect(await page.innerHTML('#web-preview')).toContain('iframe');

  await page.evaluate((sid) => window.previewWebPage(sid, 'pageB'), SID);
  const after = await page.innerHTML('#web-preview');
  expect(after).not.toContain('iframe');
  expect(after).toContain('Could not open');
  expect(after).toContain('pageB');
});

test('a failed listing is reported, not rendered as an empty wiki', async ({ page }) => {
  const RETURNED = 'grp-store-2';
  await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/keys`]: { status: 500, body: { ok: false, error: 'listing unavailable' } },
  });

  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div>');
  });
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  const html = await page.innerHTML('#wiki-pages');
  expect(html).toContain('Could not list');
  expect(html).not.toContain('No wiki pages yet');
});

test('a public space uses the legacy local-agent store and is described truthfully', async ({ page }) => {
  const seen = await mountGui(page, {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
  });

  await page.evaluate((sid) => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div>');
    return window.loadWikiPages(sid);
  }, SID);
  expect(seen).toContain('GET /stores');

  // The public lane still uses the LEGACY generic store, whose identity the
  // daemon derives from the topic and the LOCAL agent
  // (lib.rs:15724-15727 for_topic_owner(topic, &self.agent_id())). The GUI
  // never anchors the Space owner, so the tab must not claim the Space owner
  // is the only writer, must not tell anyone they are read-only, and must not
  // claim collaborative editing either. (Senior P2.)
  const blurb = await page.evaluate((sid) => {
    const el = document.createElement('div');
    window.renderSpaceWiki(el, sid);
    return el.querySelector('p').textContent;
  }, SID);
  const low = blurb.toLowerCase();
  expect(low).not.toContain('only the space owner');
  expect(low).not.toContain('read-only');
  expect(low).not.toContain('collaborative');
  expect(low).toContain('your own device');
});

test('a failed wiki read keeps the open draft, its title and the save target', async ({ page }) => {
  const RETURNED = 'grp-store-draft';
  const seen = await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/pageA`]: { status: 200, body: { ok: true, value: btoa('# A') } },
    [`GET /stores/${RETURNED}/pageB`]: { status: 500, body: { ok: false, error: 'read failed' } },
    [`PUT /stores/${RETURNED}/pageA`]: { status: 200, body: { ok: true } },
  });

  await page.evaluate(async (sid) => {
    document.body.insertAdjacentHTML('beforeend',
      '<div id="wiki-pages"></div><div id="wiki-editor" style="display:none">' +
      '<h3 id="wiki-title"></h3><textarea id="wiki-content"></textarea>' +
      '<div id="wiki-error" style="display:none"></div></div>');
    await window.editWikiPage(sid, 'pageA');
    // Unsaved edit in progress.
    document.getElementById('wiki-content').value = '# A EDITED UNSAVED';
    await window.editWikiPage(sid, 'pageB');
  }, SID);

  // The failed read for B must not have touched A's draft, title or editor.
  expect(await page.inputValue('#wiki-content')).toBe('# A EDITED UNSAVED');
  expect(await page.textContent('#wiki-title')).toBe('pageA');
  expect(await page.evaluate(() => document.getElementById('wiki-editor').style.display)).toBe('block');
  expect(await page.innerHTML('#wiki-pages')).toContain('Could not open');

  // And the save target must still be A, not the page whose read failed.
  await page.evaluate((sid) => window.saveWikiPage(sid), SID);
  expect(seen).toContain(`PUT /stores/${RETURNED}/pageA`);
  expect(seen.some((k) => k === `PUT /stores/${RETURNED}/pageB`)).toBe(false);
});

test('a slow preview response cannot overwrite a newer selection', async ({ page }) => {
  const RETURNED = 'grp-store-race';
  const gate = makeGate([`GET /stores/${RETURNED}/pageA`]);
  await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/pageA`]: { status: 200, body: { ok: true, value: btoa('PAGE-A-BODY') } },
    [`GET /stores/${RETURNED}/pageB`]: { status: 500, body: { ok: false, error: 'store read failed' } },
  }, { gate });

  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="web-preview"></div>');
  });
  // Start A (held), then run B to completion (fails), then release A.
  const aDone = page.evaluate((sid) => window.previewWebPage(sid, 'pageA'), SID);
  await page.evaluate((sid) => window.previewWebPage(sid, 'pageB'), SID);
  gate.holds[`GET /stores/${RETURNED}/pageA`].release();
  await aDone;

  // B's failure must still be on screen; A's late success must be discarded.
  const after = await page.innerHTML('#web-preview');
  expect(after).toContain('Could not open');
  expect(after).toContain('pageB');
  expect(after).not.toContain('iframe');
});

test('a preview in flight cannot paint into a re-rendered Web tab', async ({ page }) => {
  const RETURNED = 'grp-store-remount';
  const gate = makeGate([`GET /stores/${RETURNED}/pageA`]);
  await mountGui(page, {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/pageA`]: { status: 200, body: { ok: true, value: btoa('STALE-A') } },
    [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
  }, { gate });

  // The ONLY #web-preview is the one renderSpaceWeb creates inside #host, so
  // a stale paint has nowhere else to land and the control discriminates.
  await page.evaluate((sid) => {
    document.body.insertAdjacentHTML('beforeend', '<div id="host"></div>');
    window.renderSpaceWeb(document.getElementById('host'), sid);
  }, SID);
  const aDone = page.evaluate((sid) => window.previewWebPage(sid, 'pageA'), SID);
  // Tab re-render while A is still in flight.
  await page.evaluate((sid) => window.renderSpaceWeb(document.getElementById('host'), sid), SID);
  gate.holds[`GET /stores/${RETURNED}/pageA`].release();
  await aDone;

  const host = await page.innerHTML('#host');
  expect(host).not.toContain('STALE-A');
  expect(host).not.toContain('iframe');
});

test('an unrecognised confidentiality is treated as private (fails closed)', async ({ page }) => {
  const seen = await mountGui(page, {
    [`GET /groups/${SID}`]: { status: 200, body: { ok: true, policy: { confidentiality: 'something_new' } } },
    [`POST /groups/${SID}/stores`]: { status: 400, body: { ok: false, error: 'unsupported' } },
  });

  await page.evaluate((sid) => {
    document.body.insertAdjacentHTML('beforeend', '<div id="web-pages"></div><div id="web-preview"></div>');
    return window.loadWebPages(sid);
  }, SID);
  expect(await page.innerHTML('#web-pages')).toContain('not available in this space yet');
  expect(seen.filter((k) => /\s\/stores(\/|$)/.test(k))).toEqual([]);
});
