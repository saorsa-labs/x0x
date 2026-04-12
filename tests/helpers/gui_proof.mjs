import { chromium } from 'playwright-core';
import { existsSync } from 'node:fs';

const [, , mode, ...args] = process.argv;

function usage() {
  console.error(`usage:
  gui_proof.mjs send-dm <base_url> <card_link> <target_agent_id> <message>`);
  process.exit(2);
}

if (!mode) usage();

async function waitForApp(page) {
  await page.goto(`${new URL('/gui', page.context()._options.baseURL || 'http://127.0.0.1').toString()}`, { waitUntil: 'domcontentloaded' });
}

async function bootstrap(page, baseUrl) {
  await page.goto(`${baseUrl.replace(/\/$/, '')}/gui`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof S !== 'undefined' && typeof navigate !== 'undefined' && typeof api === 'function');
  const agentId = await page.evaluate(async () => {
    const info = await api('/agent');
    if (!info || !info.agent_id) throw new Error('gui api(/agent) did not return agent_id');
    S.set('agentId', info.agent_id);
    return info.agent_id;
  });
  return { agentId };
}

function resolveChromePath() {
  const candidates = [
    process.env.CHROME_BIN,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  return candidates.find((p) => {
    try {
      return existsSync(p);
    } catch {
      return false;
    }
  });
}

async function runSendDm(baseUrl, cardLink, targetAgentId, message) {
  const executablePath = resolveChromePath();
  const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
  const page = await browser.newPage();
  const result = { ok: false, mode: 'send-dm' };
  try {
    const { agentId } = await bootstrap(page, baseUrl);
    result.agentId = agentId;

    await page.evaluate(async ({ cardLink }) => {
      navigate('people');
      await new Promise((resolve) => setTimeout(resolve, 500));
      const input = document.getElementById('import-card');
      if (!input) throw new Error('import-card input not found');
      input.value = cardLink;
      await importCard();
    }, { cardLink });

    await page.waitForTimeout(1500);
    const hasContact = await page.evaluate((targetAgentId) => {
      const contacts = S.get('contacts') || [];
      return contacts.some((c) => c.agent_id === targetAgentId);
    }, targetAgentId);
    if (!hasContact) throw new Error('target agent missing from GUI contacts after import');

    const requestPromise = page.waitForRequest((req) => {
      return req.url().includes('/direct/send') && req.method() === 'POST';
    }, { timeout: 10000 });

    await page.evaluate(async ({ targetAgentId, message }) => {
      navigateDm(targetAgentId);
      await new Promise((resolve) => setTimeout(resolve, 500));
      const input = document.getElementById('dm-in');
      if (!input) throw new Error('dm-in input not found');
      input.value = message;
      await sendDm();
    }, { targetAgentId, message });

    const sentRequest = await requestPromise;
    await page.waitForTimeout(1500);
    const messageVisible = await page.evaluate((message) => {
      const msgs = document.getElementById('dm-msgs');
      return !!msgs && msgs.textContent.includes(message);
    }, message);
    if (!messageVisible) throw new Error('GUI message not visible in dm-msgs after send');

    const contactsCount = await page.evaluate(() => (S.get('contacts') || []).length);
    let requestBody = sentRequest.postData() || '';
    let payloadB64 = '';
    try {
      payloadB64 = JSON.parse(requestBody).payload || '';
    } catch {
      payloadB64 = '';
    }
    result.ok = true;
    result.contactsCount = contactsCount;
    result.messageVisible = true;
    result.requestBody = requestBody;
    result.payloadB64 = payloadB64;
  } finally {
    await browser.close();
  }
  console.log(JSON.stringify(result));
}

if (mode === 'send-dm') {
  if (args.length !== 4) usage();
  runSendDm(args[0], args[1], args[2], args[3]).catch((err) => {
    console.error(JSON.stringify({ ok: false, mode, error: String(err?.message || err) }));
    process.exit(1);
  });
} else {
  usage();
}
