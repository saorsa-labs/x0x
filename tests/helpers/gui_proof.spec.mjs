import { test, expect } from 'playwright/test';
import { existsSync, readFileSync } from 'node:fs';

const chromeCandidates = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].filter(Boolean);
const executablePath = chromeCandidates.find((p) => {
  try {
    return existsSync(p);
  } catch {
    return false;
  }
});

if (executablePath) {
  test.use({ launchOptions: { executablePath } });
}

test('gui can import card and send direct message', async ({ page }) => {
  const baseUrl = process.env.GUI_BASE_URL;
  const cardLink = process.env.GUI_CARD_LINK;
  const targetAgentId = process.env.GUI_TARGET_AGENT_ID;
  const message = process.env.GUI_MESSAGE;

  expect(baseUrl, 'GUI_BASE_URL env is required').toBeTruthy();
  expect(cardLink, 'GUI_CARD_LINK env is required').toBeTruthy();
  expect(targetAgentId, 'GUI_TARGET_AGENT_ID env is required').toBeTruthy();
  expect(message, 'GUI_MESSAGE env is required').toBeTruthy();

  // Clawpatch 7fc6183: /gui serves no injected token — bootstrap via ?token=
  // with a session token (GUI_SESSION_TOKEN), like the GUI itself does.
  const guiSessionToken = process.env.GUI_SESSION_TOKEN || '';
  const guiUrl = guiSessionToken
    ? `${baseUrl.replace(/\/$/, '')}/gui?token=${encodeURIComponent(guiSessionToken)}`
    : `${baseUrl.replace(/\/$/, '')}/gui`;
  await page.goto(guiUrl, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof window.S !== 'undefined' && typeof window.navigate !== 'undefined');
  await page.waitForFunction(() => window.S.get('agentId'));

  await page.evaluate(async ({ cardLink }) => {
    window.navigate('people');
    await new Promise((resolve) => setTimeout(resolve, 300));
    const input = document.getElementById('import-card');
    if (!input) throw new Error('import-card input not found');
    input.value = cardLink;
    await window.importCard();
  }, { cardLink });

  await page.waitForFunction((targetAgentId) => {
    const contacts = window.S.get('contacts') || [];
    return contacts.some((c) => c.agent_id === targetAgentId);
  }, targetAgentId);

  await page.evaluate(async ({ targetAgentId, message }) => {
    window.navigateDm(targetAgentId);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const input = document.getElementById('dm-in');
    if (!input) throw new Error('dm-in input not found');
    input.value = message;
    await window.sendDm();
  }, { targetAgentId, message });

  await page.waitForFunction((message) => {
    const msgs = document.getElementById('dm-msgs');
    return !!msgs && msgs.textContent.includes(message);
  }, message);
});

// No daemon: run the real renderers in a browser with inert startup IO.
test('agent names preserve labels, update peer names and escape HTML', async ({ page }) => {
  await page.route('**/*', route => route.abort());
  const html = readFileSync(new URL('../../src/gui/x0x-gui.html', import.meta.url), 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  // Keep every real function; omit only the startup calls and interval timers.
  await page.setContent('<table><tbody id="h-agents"></tbody></table><div id="rows"></div><div id="detail"></div>');
  await page.addScriptTag({ content: script.split('// Apply theme on startup')[0] });
  const agentId = 'a1'.repeat(32);
  async function render(label, selfName) {
    await page.evaluate(async ({ agentId, label, selfName }) => {
      const contact = { agent_id: agentId, label, machines: [], trust_level: 'Known' };
      const discovered = { agent_id: agentId, self_name: selfName };
      S.set('contacts', [contact]);
      api = async path => path === '/agents/discovered' ? {agents:[discovered]} : null;
      refreshAgentIdentity = async () => {};
      refreshUpgradeBanner = async () => {};
      await pollDash();
      document.getElementById('rows').innerHTML = renderAgentRow({...contact, discovered});
      renderAgentDetail(document.getElementById('detail'), {agentId, contact, disc:discovered});
    }, {agentId, label, selfName});
  }
  for (const [label, peer, expected] of [
    ['', 'Remote name', 'Remote name'],
    ['My label', 'Remote name', 'My label'],
    ['', 'Updated name', 'Updated name'],
    ['', '', agentId.slice(0,10)+'…'],
    ['', '<img src=x onerror="window.nameInjected=true">', '<img src=x onerror="window.nameInjected=true">'],
    ['<svg onload="window.nameInjected=true">', 'Peer', '<svg onload="window.nameInjected=true">'],
  ]) {
    await render(label, peer);
    for (const selector of ['#h-agents', '#rows', '#detail']) {
      await expect(page.locator(selector)).toContainText(expected);
      await expect(page.locator(selector)).toContainText(agentId.slice(0,10));
      await expect(page.locator(selector+' img, '+selector+' svg')).toHaveCount(0);
    }
    expect(await page.evaluate(() => window.nameInjected)).toBeUndefined();
  }
});
