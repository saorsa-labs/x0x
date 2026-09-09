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
    if (opts && opts.onRequest) await opts.onRequest(key);
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
    // Per-REQUEST holds: `KEY#N` holds the Nth occurrence of KEY only, so a
    // test can complete a NEWER request while an OLDER one of the same key is
    // still held. A bare KEY holds every occurrence.
    if (gate) {
      gate.counts[key] = (gate.counts[key] || 0) + 1;
      const hold = gate.holds[`${key}#${gate.counts[key]}`] || gate.holds[key];
      if (hold) {
        hold.markEntered();
        await hold.promise;
      }
    }
    if (hit.abort) return route.abort();
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
    let release, entered;
    holds[k] = {
      promise: new Promise((r) => { release = r; }),
      // Resolved when the route handler actually REACHES this hold, so a
      // test can wait on the real request boundary instead of guessing.
      // `waitForFunction(() => true)` is not a barrier. (Root P2.)
      enteredPromise: new Promise((r) => { entered = r; }),
    };
    holds[k].release = release;
    holds[k].markEntered = entered;
  }
  return { holds, counts: {} };
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

// ── #565 / Greptile P1: the warm cache must not outlive the policy ────────
//
// `PATCH /groups/:id/policy` lets any admin set `confidentiality` on a LIVE
// group (`named_groups.rs` update_group_policy — only the owner axis of
// `admission` is immutable). A Space warm-cached while `signed_public` can
// therefore become `mls_encrypted` under an open tab. WHY these controls
// matter: if the resolver answers from cache before re-reading the policy,
// list/read/WRITE stay pointed at the generic unbound Signed store, so pages
// written AFTER the space went private land outside the group-bound store.

/// Warm the resolver as a public space, then flip the fixture to private.
async function warmPublicThenGoPrivate(page, app, extra) {
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    ...(extra || {}),
  };
  const seen = await mountGui(page, routes);
  const loader = app === 'wiki' ? 'loadWikiPages' : 'loadWebPages';
  await page.evaluate(([sid, fn]) => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div><div id="web-pages"></div>');
    return window[fn](sid);
  }, [SID, loader]);
  expect(seen).toContain('GET /stores');       // warmed on the public lane
  routes[`GET /groups/${SID}`] = privateGroup();
  seen.length = 0;
  return { seen, routes };
}

for (const app of ['wiki', 'web']) {
  const RETURNED = `grp-store-${app}-transition`;
  const loader = app === 'wiki' ? 'loadWikiPages' : 'loadWebPages';

  test(`${app}: a live public -> private transition re-resolves the listing onto the group store`, async ({ page }) => {
    const { seen } = await warmPublicThenGoPrivate(page, app, {
      [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
      [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
    });

    await page.evaluate(([sid, fn]) => window[fn](sid), [SID, loader]);

    // The policy MUST be re-read, and the listing MUST move to the
    // group-bound opener. A stale warm cache shows up as a second
    // `GET /stores` (the generic lane) and no group-store open.
    expect(seen).toContain(`GET /groups/${SID}`);
    expect(seen).toContain(`POST /groups/${SID}/stores`);
    expect(seen).not.toContain('GET /stores');
  });

  test(`${app}: a save after the space goes private never writes to the generic store`, async ({ page }) => {
    const { seen } = await warmPublicThenGoPrivate(page, app, {
      [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
      [`PUT /stores/${RETURNED}/`]: { status: 200, body: { ok: true } },
    });

    // Real editor DOM: the save handlers read `<app>-content` and hide
    // `<app>-editor` (x0x-gui.html saveWikiPage/saveWebPage).
    await page.evaluate(([a, slug]) => {
      document.body.insertAdjacentHTML('beforeend',
        `<textarea id="${a}-content">after going private</textarea>` +
        `<div id="${a}-editor"></div><div id="${a}-error"></div>`);
      // The slug is module-scoped and irrelevant here: the assertion is on
      // WHICH STORE the PUT addresses, not which page.
      void slug;
    }, [app, 'secret']);
    const saver = app === 'wiki' ? 'saveWikiPage' : 'saveWebPage';
    await page.evaluate(([sid, fn]) => window[fn](sid), [SID, saver]);

    // The write must land on the EXACT intended group-bound store, not merely
    // avoid the generic alias — "no PUT at all" would otherwise pass.
    const generic = `x0x-${app}-${SID.slice(0, 16)}`;
    expect(seen.some((k) => k.startsWith('PUT ') && k.includes(`/stores/${RETURNED}/`))).toBe(true);
    expect(seen.some((k) => k.includes(generic))).toBe(false);
  });

  test(`${app}: an unreadable policy fails closed instead of reusing the warm public store`, async ({ page }) => {
    const { seen, routes } = await warmPublicThenGoPrivate(page, app, {});
    routes[`GET /groups/${SID}`] = { status: 500, body: { ok: false, error: 'policy unavailable' } };

    await page.evaluate(([sid, fn]) => window[fn](sid), [SID, loader]);

    // Fail closed: NO store traffic of any kind on an unreadable policy —
    // including sub-paths such as `/stores/<id>/keys`. The previously cached
    // public resolution must NOT be used as a fallback. (Root: the earlier
    // assertion only forbade the exact `GET /stores` key.)
    expect(seen).toContain(`GET /groups/${SID}`);
    expect(seen.filter((k) => / \/stores(\/|$)/.test(k))).toEqual([]);
    expect(seen).not.toContain(`POST /groups/${SID}/stores`);
  });
}

test('an old-policy resolution released after private is observed cannot save to the generic store', async ({ page }) => {
  // Root's negative, as a browser control: hold the OLD public `GET /stores`
  // at its real entry barrier, let another operation observe `private` and
  // open the group store, then release the old one. The released resolver
  // must not issue a generic POST/PUT, must not publish a public cache entry,
  // and must not report a false save success to its own caller.
  const RETURNED = 'grp-store-stale-inflight';
  const gate = makeGate(['GET /stores']);
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
    [`PUT /stores/${RETURNED}/`]: { status: 200, body: { ok: true } },
  };
  const seen = await mountGui(page, routes, { gate });
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend',
      '<textarea id="wiki-content">secret after transition</textarea>' +
      '<div id="wiki-editor"></div><div id="wiki-error"></div><div id="wiki-pages"></div>');
  });

  // Start a real SAVE under the public policy; it blocks inside its resolver.
  const save = page.evaluate((sid) => window.saveWikiPage(sid), SID);
  await gate.holds['GET /stores'].enteredPromise;   // REAL request boundary

  // The space goes private and another operation observes it.
  routes[`GET /groups/${SID}`] = privateGroup();
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  expect(seen).toContain(`POST /groups/${SID}/stores`);

  // Everything recorded from here on is strictly AFTER private was observed.
  const boundary = seen.length;
  gate.holds['GET /stores'].release();
  await save;
  const after = seen.slice(boundary);

  const generic = `x0x-wiki-${SID.slice(0, 16)}`;
  // The generic creation POSTs to EXACTLY `/stores` (the alias is in the
  // BODY, not the path), so matching the alias in the path can never fire.
  // (Root P2.) Assert the real method+path, and the generic write by path.
  expect(after).not.toContain('POST /stores');
  expect(after.some((k) => k.startsWith('PUT ') && k.includes(`/stores/${generic}/`))).toBe(false);

  // Real publication behaviour: the shared cache must not have been
  // downgraded back to the public store by the released resolver. A fresh
  // render must still resolve PRIVATELY — if the stale entry had been
  // published, this would take the generic lane instead.
  seen.length = 0;
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  // It legitimately REUSES the valid private entry (same generation), so it
  // addresses the private store directly rather than re-opening it. What must
  // never appear is the generic lane — that is what a downgraded cache from
  // the released stale resolver would produce.
  expect(seen.some((k) => k.includes(`/stores/${RETURNED}/`))).toBe(true);
  expect(seen).not.toContain('POST /stores');
  expect(seen).not.toContain('GET /stores');
  expect(seen.some((k) => k.includes(generic))).toBe(false);
  // The stale resolver must not claim success: either it rerouted to the
  // group store, or it failed closed with the draft preserved.
  const state = await page.evaluate(() => ({
    editorHidden: document.getElementById('wiki-editor').style.display === 'none',
    draft: document.getElementById('wiki-content').value,
    err: document.getElementById('wiki-error').textContent || '',
  }));
  expect(state.draft).toBe('secret after transition');   // draft preserved
  if (!state.editorHidden) {
    expect(state.err).not.toBe('');                      // failed closed, told the user
  } else {
    // If it did report success, the write must have gone to the GROUP store.
    expect(seen.some((k) => k.startsWith('PUT ') && k.includes(`/stores/${RETURNED}/`))).toBe(true);
  }
});

test('a policy change observed in the Wiki also invalidates a warm Web resolution', async ({ page }) => {
  const RETURNED = 'grp-store-crossapp';
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
  };
  const seen = await mountGui(page, routes);
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div><div id="web-pages"></div>');
  });
  // Warm BOTH apps on the public lane.
  await page.evaluate((sid) => window.loadWebPages(sid), SID);
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);

  // The space goes private; only the WIKI observes it.
  routes[`GET /groups/${SID}`] = privateGroup();
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  seen.length = 0;

  // The Web tab must now resolve privately too — its warm public entry was
  // invalidated by the Wiki's observation, not left for it to reuse.
  await page.evaluate((sid) => window.loadWebPages(sid), SID);
  expect(seen).toContain(`POST /groups/${SID}/stores`);
  expect(seen.some((k) => k.includes(`x0x-web-${SID.slice(0, 16)}`))).toBe(false);
});

// ── R3: policy-response ordering and the unavailable observation ──────────

test('a save held under public cannot complete generically after the policy read fails', async ({ page }) => {
  // Root R2 P2: the unavailable branch returned WITHOUT observing, so the old
  // public generation stayed valid and the held resolver still went generic.
  const gate = makeGate(['GET /stores']);
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
  };
  const seen = await mountGui(page, routes, { gate });
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend',
      '<textarea id="wiki-content">draft under unavailable policy</textarea>' +
      '<div id="wiki-editor"></div><div id="wiki-error"></div><div id="wiki-pages"></div>');
  });

  const save = page.evaluate((sid) => window.saveWikiPage(sid), SID);
  await gate.holds['GET /stores'].enteredPromise;          // real boundary

  // A newer policy read FAILS while the save is held.
  routes[`GET /groups/${SID}`] = { status: 500, body: { ok: false, error: 'policy unavailable' } };
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);

  const boundary = seen.length;
  gate.holds['GET /stores'].release();
  await save;
  const after = seen.slice(boundary);

  // No generic creation and no write may follow an unavailable observation.
  expect(after).not.toContain('POST /stores');
  expect(after.some((k) => k.startsWith('PUT '))).toBe(false);
  // Fail closed, draft kept, user told.
  const state = await page.evaluate(() => ({
    hidden: document.getElementById('wiki-editor').style.display === 'none',
    draft: document.getElementById('wiki-content').value,
    err: document.getElementById('wiki-error').textContent || '',
  }));
  expect(state.draft).toBe('draft under unavailable policy');
  expect(state.hidden).toBe(false);
  expect(state.err).not.toBe('');
});

test('an older public policy reply landing after a newer private one is ignored', async ({ page }) => {
  // TRUE ordering: hold the FIRST policy read, let the SECOND complete
  // privately end-to-end, and only THEN release the first. The older reply
  // must not overwrite the newer observation. Removing the ticket guard in
  // observeSpacePolicy makes this fail.
  const RETURNED = 'grp-store-late-public';
  const gate = makeGate([`GET /groups/${SID}#1`]);
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
  };
  const seen = await mountGui(page, routes, { gate });
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div>');
  });

  const older = page.evaluate((sid) => window.loadWikiPages(sid), SID);
  await gate.holds[`GET /groups/${SID}#1`].enteredPromise;

  // NEWER read completes FIRST, privately, while the older is still held.
  routes[`GET /groups/${SID}`] = privateGroup();
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  expect(seen).toContain(`POST /groups/${SID}/stores`);

  // Boundary BEFORE the release, so the released resolver's OWN traffic is
  // inside the measured window — that traffic is exactly what a missing
  // ticket guard produces.
  const boundary = seen.length;
  gate.holds[`GET /groups/${SID}#1`].release();
  await older;
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  const after = seen.slice(boundary);
  // The late public reply must have left nothing behind: still private, and
  // the stale resolver itself must not have taken the public lane.
  expect(after.some((k) => k.includes(`/stores/${RETURNED}/`))).toBe(true);
  expect(after).not.toContain('POST /stores');
  expect(after).not.toContain('GET /stores');
});

test('an older FAILED policy reply cannot erase a newer valid observation', async ({ page }) => {
  // TRUE ordering: the FAILING read is held, a newer VALID private read
  // completes, then the failure is released. Its stale ticket must be dropped.
  const RETURNED = 'grp-store-late-fail';
  const gate = makeGate([`GET /groups/${SID}#1`]);
  const routes = {
    [`GET /groups/${SID}`]: { status: 500, body: { ok: false, error: 'unavailable' } },
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
  };
  const seen = await mountGui(page, routes, { gate });
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div>');
  });

  const older = page.evaluate((sid) => window.loadWikiPages(sid), SID);
  await gate.holds[`GET /groups/${SID}#1`].enteredPromise;

  routes[`GET /groups/${SID}`] = privateGroup();
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  expect(seen).toContain(`POST /groups/${SID}/stores`);

  // Boundary BEFORE the release, for the same reason as above.
  const boundary = seen.length;
  gate.holds[`GET /groups/${SID}#1`].release();
  await older;
  await page.evaluate((sid) => window.loadWikiPages(sid), SID);
  const after = seen.slice(boundary);
  // The late FAILURE must not have downgraded the valid private observation:
  // the next render must still reuse the private store, never re-open it.
  expect(after.some((k) => k.includes(`/stores/${RETURNED}/`))).toBe(true);
  expect(after).not.toContain('POST /stores');
  expect(after).not.toContain('GET /stores');
  expect(after.filter((k) => k === `POST /groups/${SID}/stores`).length).toBe(0);
});

test('two concurrent renders under the SAME policy still share one resolution', async ({ page }) => {
  // The ticket/generation logic must not break legitimate same-policy dedup.
  const RETURNED = 'grp-store-dedup';
  const routes = {
    [`GET /groups/${SID}`]: privateGroup(),
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
  };
  const seen = await mountGui(page, routes);
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div>');
  });
  await page.evaluate((sid) => Promise.all([
    window.loadWikiPages(sid), window.loadWikiPages(sid), window.loadWikiPages(sid),
  ]), SID);
  // One shared resolution: the group opener is not issued three times.
  expect(seen.filter((k) => k === `POST /groups/${SID}/stores`).length).toBe(1);
});

// ── R4: the GUI's OWN policy mutation must invalidate held resolutions ────
//
// Root/Senior P1: a save that already passed its public policy GET and is held
// at `GET /stores` released into a still-valid generation after the user made
// the space private through the real admin form (`nagApplyPolicy` PATCH), so
// the generic POST and PUT happened AFTER the private mutation succeeded. No
// read-replica lag and no GET-after-PATCH is assumed anywhere here.

/// Mount the admin policy form the real handler reads, and apply `private`.
async function applyPrivateThroughTheRealForm(page, sid) {
  await page.evaluate((gid) => {
    document.body.insertAdjacentHTML('beforeend',
      `<div data-nag-policy="${gid}">` +
      '<select data-k="confidentiality"><option value="mls_encrypted" selected>mls_encrypted</option></select>' +
      '<div data-k="policy-feedback"></div></div>');
    return window.nagApplyPolicy(gid);      // the ACTUAL handler
  }, sid);
}

for (const app of ['wiki', 'web']) {
  test(`${app}: a held save cannot go generic after the real policy form makes the space private`, async ({ page }) => {
    const RETURNED = `grp-store-patch-${app}`;
    const gate = makeGate(['GET /stores']);
    const routes = {
      [`GET /groups/${SID}`]: publicGroup(),
      'GET /stores': { status: 200, body: { ok: true, stores: [] } },
      'POST /stores': { status: 200, body: { ok: true } },
      [`PATCH /groups/${SID}/policy`]: { status: 200, body: { ok: true } },
      [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
      [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
      [`PUT /stores/${RETURNED}/`]: { status: 200, body: { ok: true } },
    };
    const seen = await mountGui(page, routes, { gate });
    await page.evaluate((a) => {
      document.body.insertAdjacentHTML('beforeend',
        `<textarea id="${a}-content">draft across a policy change</textarea>` +
        `<div id="${a}-editor"></div><div id="${a}-error"></div>` +
        '<div id="wiki-pages"></div><div id="web-pages"></div>');
    }, app);

    const saver = app === 'wiki' ? 'saveWikiPage' : 'saveWebPage';
    const save = page.evaluate(([sid, fn]) => window[fn](sid), [SID, saver]);
    await gate.holds['GET /stores'].enteredPromise;      // real boundary

    // The user makes the space private through the REAL admin form, and the
    // PATCH SUCCEEDS, before the held save is released.
    await applyPrivateThroughTheRealForm(page, SID);
    expect(seen).toContain(`PATCH /groups/${SID}/policy`);

    const boundary = seen.length;
    gate.holds['GET /stores'].release();
    await save;
    const after = seen.slice(boundary);

    const generic = `x0x-${app}-${SID.slice(0, 16)}`;
    // Exact absence: no generic creation, no generic write, after the PATCH.
    expect(after).not.toContain('POST /stores');
    expect(after.some((k) => k.startsWith('PUT ') && k.includes(`/stores/${generic}/`))).toBe(false);
    // Draft truth: nothing was saved, the draft is intact and the user is told.
    const state = await page.evaluate((a) => ({
      hidden: document.getElementById(`${a}-editor`).style.display === 'none',
      draft: document.getElementById(`${a}-content`).value,
      err: document.getElementById(`${a}-error`).textContent || '',
    }), app);
    expect(state.draft).toBe('draft across a policy change');
    expect(state.hidden).toBe(false);
    expect(state.err).not.toBe('');

    // Valid private positive. The PATCH mutated server state, so the fixture
    // now reports private. NOTE: the absence assertions above needed no GET at
    // all — the invalidation is driven by the mutation itself, not by any
    // GET-after-PATCH. This flip only makes the POSITIVE meaningful.
    routes[`GET /groups/${SID}`] = privateGroup();
    seen.length = 0;
    const loader = app === 'wiki' ? 'loadWikiPages' : 'loadWebPages';
    await page.evaluate(([sid, fn]) => window[fn](sid), [SID, loader]);
    expect(seen).toContain(`POST /groups/${SID}/stores`);
    expect(seen).not.toContain('POST /stores');
    expect(seen.some((k) => k.includes(generic))).toBe(false);
  });
}

test('the real policy form invalidates the OTHER app’s warm resolution too', async ({ page }) => {
  const RETURNED = 'grp-store-patch-crossapp';
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [`PATCH /groups/${SID}/policy`]: { status: 200, body: { ok: true } },
    [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: RETURNED } },
    [`GET /stores/${RETURNED}/keys`]: { status: 200, body: { ok: true, keys: [] } },
  };
  const seen = await mountGui(page, routes);
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div><div id="web-pages"></div>');
  });
  await page.evaluate((sid) => window.loadWebPages(sid), SID);   // warm WEB, public

  await applyPrivateThroughTheRealForm(page, SID);
  routes[`GET /groups/${SID}`] = privateGroup();
  seen.length = 0;

  // The Web tab's warm public entry must have been invalidated by the PATCH.
  await page.evaluate((sid) => window.loadWebPages(sid), SID);
  expect(seen).toContain(`POST /groups/${SID}/stores`);
  expect(seen).not.toContain('POST /stores');
  expect(seen.some((k) => k.includes(`x0x-web-${SID.slice(0, 16)}`))).toBe(false);
});

test('a FAILED policy PATCH is still treated as uncertain, not as no-op', async ({ page }) => {
  const gate = makeGate(['GET /stores']);
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [`PATCH /groups/${SID}/policy`]: { status: 500, body: { ok: false, error: 'patch failed' } },
  };
  const seen = await mountGui(page, routes, { gate });
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend',
      '<textarea id="wiki-content">draft across an uncertain patch</textarea>' +
      '<div id="wiki-editor"></div><div id="wiki-error"></div>');
  });

  const save = page.evaluate((sid) => window.saveWikiPage(sid), SID);
  await gate.holds['GET /stores'].enteredPromise;
  await applyPrivateThroughTheRealForm(page, SID);   // PATCH errors

  const boundary = seen.length;
  gate.holds['GET /stores'].release();
  await save;
  const after = seen.slice(boundary);

  // A failed PATCH does not prove the mutation was not applied, so the held
  // save must still not go generic.
  expect(after).not.toContain('POST /stores');
  expect(after.some((k) => k.startsWith('PUT '))).toBe(false);
  expect(await page.evaluate(() => document.getElementById('wiki-content').value))
    .toBe('draft across an uncertain patch');
});

// ── R5 retained no-write/draft controls ──────────────────────────────────
// The former caller-handoff P1 was withdrawn. Pending-mutation refusal now
// finishes before a stores request; these controls await that terminal return
// instead of the obsolete store-entry barrier. Both PATCH outcomes remain.
//
/// Mount the policy form and START the PATCH without awaiting it.
function startPolicyPatch(page, sid) {
  return page.evaluate((gid) => {
    document.body.insertAdjacentHTML('beforeend',
      `<div data-nag-policy="${gid}">` +
      '<select data-k="confidentiality"><option value="mls_encrypted" selected>mls_encrypted</option></select>' +
      '<div data-k="policy-feedback"></div></div>');
    return window.nagApplyPolicy(gid);      // NOT awaited by the caller
  }, sid);
}

for (const [app, saver, contentId, editorId, errId] of [
  ['wiki', 'saveWikiPage', 'wiki-content', 'wiki-editor', 'wiki-error'],
  ['web', 'saveWebPage', 'web-content', 'web-editor', 'web-error'],
]) {
  for (const patchOk of [true, false]) {
    const label = patchOk ? 'successful' : 'failed';
    test(`${app}: a ${label} pending PATCH blocks the caller before and after completion`, async ({ page }) => {
      // A save during the admitted PATCH must settle without a page request.
      const gate = makeGate([`PATCH /groups/${SID}/policy`]);
      const generic0 = `x0x-${app}-${SID.slice(0, 16)}`;
      const routes = {
        [`GET /groups/${SID}`]: publicGroup(),
        'GET /stores': { status: 200, body: { ok: true, stores: [{ id: generic0 }] } },
        'POST /stores': { status: 200, body: { ok: true } },
        [`PUT /stores/${generic0}/`]: { status: 200, body: { ok: true } },
        [`PATCH /groups/${SID}/policy`]: patchOk
          ? { status: 200, body: { ok: true } }
          : { status: 500, body: { ok: false, error: 'patch failed' } },
      };
      const seen = await mountGui(page, routes, { gate });
      await page.evaluate(([c, e, x]) => {
        document.body.insertAdjacentHTML('beforeend',
          `<textarea id="${c}">draft across the handoff</textarea>` +
          `<div id="${e}"></div><div id="${x}"></div>`);
      }, [contentId, editorId, errId]);

      // 1. PATCH admitted, held in flight.
      const patch = startPolicyPatch(page, SID);
      await gate.holds[`PATCH /groups/${SID}/policy`].enteredPromise;

      // 2. Save settles by early refusal; no absent-store-request timeout.
      const save = page.evaluate(([sid, fn]) => window[fn](sid), [SID, saver]);
      await save; // Pending mutations now refuse before any policy/store GET.

      // 3. Complete PATCH; keep the original no-write/draft/error oracles.
      const boundary = 0;
      gate.holds[`PATCH /groups/${SID}/policy`].release();
      await patch;                       // completion invalidation has landed
      await save;
      const after = seen.slice(boundary);

      const generic = `x0x-${app}-${SID.slice(0, 16)}`;
      // No generic write may follow, on EITHER PATCH outcome — a failed PATCH
      // does not prove the mutation was not applied.
      expect(after.some((k) => k.startsWith('PUT ') && k.includes(`/stores/${generic}/`))).toBe(false);
      expect(after.some((k) => k.startsWith('PUT '))).toBe(false);
      // Draft truth: nothing saved, editor still open, user told.
      const state = await page.evaluate(([c, e, x]) => ({
        hidden: document.getElementById(e).style.display === 'none',
        draft: document.getElementById(c).value,
        err: document.getElementById(x).textContent || '',
      }), [contentId, editorId, errId]);
      expect(state.draft).toBe('draft across the handoff');
      expect(state.hidden).toBe(false);
      expect(state.err).not.toBe('');
    });
  }
}

test('a NEW resolver started after PATCH admission is still blocked when the PATCH completes', async ({ page }) => {
  // Preserve the post-admission no-create/no-write oracle. Its former held
  // listing barrier is replaced by terminal early refusal, which is stronger.
  const gate = makeGate([`PATCH /groups/${SID}/policy`]);
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [`PATCH /groups/${SID}/policy`]: { status: 200, body: { ok: true } },
  };
  const seen = await mountGui(page, routes, { gate });
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend',
      '<textarea id="wiki-content">draft after admission</textarea>' +
      '<div id="wiki-editor"></div><div id="wiki-error"></div>');
  });

  const patch = startPolicyPatch(page, SID);
  await gate.holds[`PATCH /groups/${SID}/policy`].enteredPromise;

  // NEW resolver must now refuse without issuing that old-policy GET.
  const save = page.evaluate((sid) => window.saveWikiPage(sid), SID);
  await save; // Early refusal replaces the former held-store barrier.

  const boundary = 0;
  gate.holds[`PATCH /groups/${SID}/policy`].release();
  await patch;                                   // COMPLETION invalidation
  await save;
  const after = seen.slice(boundary);

  expect(after).not.toContain('POST /stores');
  expect(after.some((k) => k.startsWith('PUT '))).toBe(false);
  const state = await page.evaluate(() => ({
    hidden: document.getElementById('wiki-editor').style.display === 'none',
    draft: document.getElementById('wiki-content').value,
  }));
  expect(state.draft).toBe('draft after admission');
  expect(state.hidden).toBe(false);
});

// ── R6: truthful outcome after a WRITE that may already have landed ───────
//
// Root R5 P2: the post-PUT stale guard reused a message claiming "nothing was
// read or written" AFTER the PUT had been issued and returned HTTP success.
// That is false, and it invites a blind retry that could duplicate the page.
// These controls hold the PUT RESPONSE until after the real policy form's
// PATCH completes, so the write is observed by the fixture and succeeds.

for (const [app, saver, contentId, editorId, errId] of [
  ['wiki', 'saveWikiPage', 'wiki-content', 'wiki-editor', 'wiki-error'],
  ['web', 'saveWebPage', 'web-content', 'web-editor', 'web-error'],
]) {
  test(`${app}: a save whose PUT already succeeded is reported truthfully, not as unwritten`, async ({ page }) => {
    const generic = `x0x-${app}-${SID.slice(0, 16)}`;
    const PUTKEY = `PUT /stores/${generic}/`;
    const gate = makeGate([PUTKEY]);
    const routes = {
      [`GET /groups/${SID}`]: publicGroup(),
      'GET /stores': { status: 200, body: { ok: true, stores: [{ id: generic }] } },
      'POST /stores': { status: 200, body: { ok: true } },
      [PUTKEY]: { status: 200, body: { ok: true } },      // the write SUCCEEDS
      [`PATCH /groups/${SID}/policy`]: { status: 200, body: { ok: true } },
    };
    const seen = await mountGui(page, routes, { gate });
    await page.evaluate(([c, e, x]) => {
      document.body.insertAdjacentHTML('beforeend',
        `<textarea id="${c}">text that may already be stored</textarea>` +
        `<div id="${e}"></div><div id="${x}"></div>`);
    }, [contentId, editorId, errId]);

    // Save runs; its PUT is OBSERVED by the fixture and then held.
    const save = page.evaluate(([sid, fn]) => window[fn](sid), [SID, saver]);
    await gate.holds[PUTKEY].enteredPromise;
    expect(seen).toContain(PUTKEY);                       // the write happened

    // The policy changes through the REAL form while the PUT is in flight.
    await applyPrivateThroughTheRealForm(page, SID);
    gate.holds[PUTKEY].release();                          // ...and succeeds
    await save;

    const state = await page.evaluate(([c, e, x]) => ({
      hidden: document.getElementById(e).style.display === 'none',
      draft: document.getElementById(c).value,
      err: document.getElementById(x).textContent || '',
    }), [contentId, editorId, errId]);

    // Draft and editor retained — the user does not lose their text.
    expect(state.draft).toBe('text that may already be stored');
    expect(state.hidden).toBe(false);
    // MESSAGE ORACLE. It must NOT claim the page is unwritten...
    expect(state.err).not.toBe('');
    expect(state.err.toLowerCase()).not.toContain('nothing was read or written');
    expect(state.err.toLowerCase()).not.toContain('nothing was written');
    // ...it must say the save MAY have completed, and tell the user to CHECK
    // before saving again rather than implying a safe retry.
    expect(state.err.toLowerCase()).toContain('may already have completed');
    expect(state.err.toLowerCase()).toContain('check');
    // No automatic re-send: exactly one PUT for this page.
    expect(seen.filter((k) => k === PUTKEY).length).toBe(1);
  });
}

test('a read interrupted after its request cannot claim nothing was read', async ({ page }) => {
  const generic = `x0x-wiki-${SID.slice(0, 16)}`;
  const KEYS = `GET /stores/${generic}/keys`;
  const gate = makeGate([KEYS]);
  const routes = {
    [`GET /groups/${SID}`]: publicGroup(),
    'GET /stores': { status: 200, body: { ok: true, stores: [{ id: generic }] } },
    'POST /stores': { status: 200, body: { ok: true } },
    [KEYS]: { status: 200, body: { ok: true, keys: ['page-a'] } },
    [`PATCH /groups/${SID}/policy`]: { status: 200, body: { ok: true } },
  };
  await mountGui(page, routes, { gate });
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<div id="wiki-pages"></div>');
  });

  const load = page.evaluate((sid) => window.loadWikiPages(sid), SID);
  await gate.holds[KEYS].enteredPromise;
  await applyPrivateThroughTheRealForm(page, SID);
  gate.holds[KEYS].release();
  await load;

  const shown = await page.innerHTML('#wiki-pages');
  expect(shown.toLowerCase()).not.toContain('nothing was read or written');
  expect(shown.toLowerCase()).toContain('may reflect the previous setting');
  expect(shown).not.toContain('page-a');          // the stale listing is not painted
});

// Pending-mutation controls use response-entry barriers, never sleeps or a
// timeout waiting for a request that a correct early refusal will not issue.
const pendingState = (page, sid = SID) => page.evaluate((id) => ({
  pending: typeof spacePolicyPending === 'undefined' ? 0 : (spacePolicyPending[id] || 0),
  observed: { ...spacePolicy[id] },
}), sid);

for (const app of ['wiki', 'web']) {
  test(`pending mutation: ${app} refuses before delayed PATCH response and recovers through fresh GET`, async ({ page }) => {
    const patchKey = `PATCH /groups/${SID}/policy`;
    const groupKey = `GET /groups/${SID}`;
    const generic = `x0x-${app}-${SID.slice(0, 16)}`;
    const bound = `bound-${app}`;
    const gate = makeGate([patchKey]);
    let committed = false;
    const trace = [];
    const routes = {
      [groupKey]: publicGroup(),
      [patchKey]: { status: 200, body: { ok: true } },
      'GET /stores': { status: 200, body: { ok: true, stores: [{ id: generic }] } },
      [`PUT /stores/${generic}/`]: { status: 200, body: { ok: true } },
      [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: bound } },
    };
    const seen = await mountGui(page, routes, { gate, onRequest: (key) => trace.push({ key, committed }) });
    await page.evaluate((name) => document.body.insertAdjacentHTML('beforeend',
      `<textarea id="${name}-content">kept pending draft</textarea>` +
      `<div id="${name}-editor"></div><div id="${name}-error"></div>`), app);
    const patch = startPolicyPatch(page, SID);
    await gate.holds[patchKey].enteredPromise;
    const admitted = await pendingState(page);
    const boundary = seen.length;
    // Model backend commit independently from response delivery. The existing
    // GET route still offers its old public snapshot until PATCH is released.
    committed = true;
    await page.evaluate(([sid, name]) => window[name === 'wiki' ? 'saveWikiPage' : 'saveWebPage'](sid), [SID, app]);
    const during = seen.slice(boundary);
    const state = await page.evaluate((name) => ({
      hidden: document.getElementById(name + '-editor').style.display === 'none',
      text: document.getElementById(name + '-content').value,
      error: document.getElementById(name + '-error').textContent,
    }), app);
    trace.push({ event: 'save settled before PATCH response', admitted, state: await pendingState(page) });
    routes[groupKey] = privateGroup();
    gate.holds[patchKey].release();
    await patch;
    const recovery = seen.length;
    const result = await page.evaluate(([sid, name]) => openSpacePageStore(sid, name), [SID, app]);
    console.log('PENDING_REPAIR_TRACE ' + JSON.stringify({ app, trace }));
    expect(during).toEqual([]);
    expect(admitted.pending).toBe(1);
    expect(state).toMatchObject({ hidden: false, text: 'kept pending draft' });
    expect(state.error).toContain('being updated');
    expect(result).toMatchObject({ ok: true, id: bound });
    expect(seen.slice(recovery)).toEqual([groupKey, `POST /groups/${SID}/stores`]);
    expect((await pendingState(page)).pending).toBe(0);
  });
}

for (const reverse of [false, true]) {
  for (const outcome of ['success', 'failure', 'network-error']) {
    test(`pending mutation: overlapping PATCHes settle ${reverse ? 'reverse' : 'forward'} with ${outcome}`, async ({ page }) => {
      const key = `PATCH /groups/${SID}/policy`;
      const groupKey = `GET /groups/${SID}`;
      const other = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      const gate = makeGate([key + '#1', key + '#2']);
      const routes = {
        [key]: outcome === 'network-error' ? { abort: true } : {
          status: outcome === 'success' ? 200 : 500,
          body: { ok: outcome === 'success', error: 'fixture failure' },
        },
        [groupKey]: privateGroup(),
        [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: 'after-pending' } },
        [`GET /groups/${other}`]: privateGroup(),
        [`POST /groups/${other}/stores`]: { status: 200, body: { ok: true, id: 'other-space' } },
      };
      // Abort happens after the explicit response barrier, like an errored fetch.
      const seen = await mountGui(page, routes, { gate });
      const first = startPolicyPatch(page, SID);
      await gate.holds[key + '#1'].enteredPromise;
      const second = startPolicyPatch(page, SID);
      await gate.holds[key + '#2'].enteredPromise;
      expect((await pendingState(page)).pending).toBe(2);
      const otherResult = await page.evaluate((sid) => openSpacePageStore(sid, 'wiki'), other);
      expect(otherResult).toMatchObject({ ok: true, id: 'other-space' });
      const order = reverse ? [2, 1] : [1, 2];
      gate.holds[key + '#' + order[0]].release();
      await (order[0] === 1 ? first : second);
      expect((await pendingState(page)).pending).toBe(1);
      const before = seen.length;
      for (const app of ['wiki', 'web']) {
        const result = await page.evaluate(([sid, name]) => openSpacePageStore(sid, name), [SID, app]);
        expect(result.ok).toBe(false);
      }
      expect(seen.slice(before)).toEqual([]);
      gate.holds[key + '#' + order[1]].release();
      await (order[1] === 1 ? first : second);
      const settled = await pendingState(page);
      expect(settled.pending).toBe(0);
      expect(settled.observed.conf).toBe('\u0000uncertain');
      const recovery = seen.length;
      expect(await page.evaluate((sid) => openSpacePageStore(sid, 'wiki'), SID)).toMatchObject({ ok: true, id: 'after-pending' });
      expect(seen.slice(recovery)).toEqual([groupKey, `POST /groups/${SID}/stores`]);
    });
  }
}

for (const settleFirst of [false, true]) {
  test(`pending mutation: pre-admission GET cannot restore public policy ${settleFirst ? 'after' : 'during'} PATCH`, async ({ page }) => {
    const groupKey = `GET /groups/${SID}`;
    const patchKey = `PATCH /groups/${SID}/policy`;
    const generic = `x0x-wiki-${SID.slice(0, 16)}`;
    const gate = makeGate([groupKey + '#1', patchKey]);
    const routes = {
      [groupKey]: publicGroup(),
      [patchKey]: { status: 200, body: { ok: true } },
      'GET /stores': { status: 200, body: { ok: true, stores: [{ id: generic }] } },
      [`PUT /stores/${generic}/`]: { status: 200, body: { ok: true } },
      [`POST /groups/${SID}/stores`]: { status: 200, body: { ok: true, id: 'private-after' } },
    };
    const seen = await mountGui(page, routes, { gate });
    await page.evaluate(() => document.body.insertAdjacentHTML('beforeend',
      '<textarea id="wiki-content">old GET draft</textarea><div id="wiki-editor"></div><div id="wiki-error"></div>'));
    const save = page.evaluate((sid) => saveWikiPage(sid), SID);
    await gate.holds[groupKey + '#1'].enteredPromise;
    const patch = startPolicyPatch(page, SID);
    await gate.holds[patchKey].enteredPromise;
    // Captured old GET response is unchanged; future reads see committed private.
    routes[groupKey] = privateGroup();
    if (settleFirst) { gate.holds[patchKey].release(); await patch; }
    const boundary = seen.length;
    gate.holds[groupKey + '#1'].release();
    await save;
    expect(seen.slice(boundary)).toEqual([]);
    expect(await page.inputValue('#wiki-content')).toBe('old GET draft');
    expect(await page.evaluate(() => document.getElementById('wiki-editor').style.display)).not.toBe('none');
    if (!settleFirst) { gate.holds[patchKey].release(); await patch; }
    const recovery = seen.length;
    expect(await page.evaluate((sid) => openSpacePageStore(sid, 'wiki'), SID)).toMatchObject({ ok: true, id: 'private-after' });
    expect(seen.slice(recovery)).toEqual([groupKey, `POST /groups/${SID}/stores`]);
  });
}
