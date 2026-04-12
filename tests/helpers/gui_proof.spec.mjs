import { test, expect } from '@playwright/test';
import { existsSync } from 'node:fs';

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

  await page.goto(`${baseUrl.replace(/\/$/, '')}/gui`, { waitUntil: 'domcontentloaded' });
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
