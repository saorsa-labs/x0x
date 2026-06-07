#!/usr/bin/env node
// Browser proof for the live MacBook/studio x0x GUI dogfood run.
//
// Consumes the JSON manifest emitted by tests/e2e_studio_live.py and drives:
// - daemon-served embedded GUIs for both daemons
// - the shipped example apps via file:// with ?api=...&token=...

import { chromium } from "playwright";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { resolve, join } from "node:path";

const argv = process.argv.slice(2);
const flag = (name, def = "") => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : def;
};

const MANIFEST = resolve(flag("--manifest"));
const PROOF_DIR = resolve(flag("--proof-dir", `proofs/studio-gui-full-${Date.now()}`));
if (!MANIFEST) {
    console.error("usage: node tests/e2e_studio_gui_full.mjs --manifest <manifest.json> --proof-dir <dir>");
    process.exit(2);
}
mkdirSync(PROOF_DIR, { recursive: true });

const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const report = {
    run_started_at: new Date().toISOString(),
    manifest: MANIFEST,
    capabilities: {},
    totals: { pass: 0, fail: 0, skip: 0 },
};

function record(name, status, details = {}) {
    report.capabilities[name] = { status, ...details };
    report.totals[status] = (report.totals[status] || 0) + 1;
    console.log(`[${status.toUpperCase()}] ${name}${details.reason ? " - " + details.reason : ""}`);
}

function failFast(cond, msg) {
    if (!cond) throw new Error(msg);
}

function chromePath() {
    if (!process.env.CHROME_BIN) return undefined;
    return [
        process.env.CHROME_BIN,
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ].filter(Boolean).find(p => existsSync(p));
}

function authHeaders(target, json = false) {
    return {
        ...(json ? { "content-type": "application/json" } : {}),
        ...(target.token ? { authorization: `Bearer ${target.token}` } : {}),
    };
}

async function api(target, method, path, body = undefined, accept = status => status >= 200 && status < 300) {
    const res = await fetch(`${target.api_base}${path}`, {
        method,
        headers: authHeaders(target, body !== undefined),
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const parsed = text ? JSON.parse(text) : {};
    if (!accept(res.status)) {
        throw new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 500)}`);
    }
    return parsed;
}

async function waitForText(page, selector, text, timeout = 15000) {
    await page.waitForFunction(
        ({ selector, text }) => {
            const el = document.querySelector(selector);
            return !!el && el.textContent.includes(text);
        },
        { selector, text },
        { timeout },
    );
}

async function openGui(context, target, label) {
    const page = await context.newPage();
    const consoleLog = [];
    page.on("console", msg => consoleLog.push({ type: msg.type(), text: msg.text(), location: msg.location() }));
    page.on("pageerror", err => consoleLog.push({ type: "pageerror", text: String(err) }));
    await page.goto(`${target.api_base}/gui?token=${encodeURIComponent(target.token)}`, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => typeof S !== "undefined" && typeof navigate === "function" && typeof api === "function", null, { timeout: 30000 })
        .catch(e => {
            throw new Error(`${label} GUI runtime not ready: ${e.message}`);
        });
    await page.waitForFunction(() => document.getElementById("st-conn")?.textContent === "Connected", null, { timeout: 30000 })
        .catch(async e => {
            const status = await page.locator("#st-conn").textContent().catch(() => "<missing>");
            throw new Error(`${label} GUI websocket not connected, status=${status}: ${e.message}`);
        });
    const agentId = await page.evaluate(() => S.get("agentId"));
    failFast(agentId === target.agent.agent_id, `${label} GUI agent mismatch ${agentId}`);
    try {
        await page.screenshot({
            path: join(PROOF_DIR, `${label}-gui-home.png`),
            animations: "disabled",
            timeout: 5000,
        });
    } catch (e) {
        writeFileSync(join(PROOF_DIR, `${label}-gui-home.html`), await page.content());
        writeFileSync(join(PROOF_DIR, `${label}-gui-screenshot-error.txt`), String(e?.message || e));
        record(`${label}.embedded-gui-screenshot`, "skip", { reason: String(e?.message || e).slice(0, 200) });
    }
    writeFileSync(join(PROOF_DIR, `${label}-gui-console.jsonl`), consoleLog.map(x => JSON.stringify(x)).join("\n"));
    return { page, consoleLog };
}

async function proveGuiViews(page, label, groupId) {
    const views = ["home", "discover", "people", "network", "presence", "mls", "admin", "constitution", "settings", "about"];
    for (const view of views) {
        await page.evaluate(view => navigate(view), view);
        await page.waitForTimeout(500);
        const len = await page.locator("#view-container").evaluate(el => el.textContent.trim().length);
        failFast(len > 20, `${label} ${view} rendered too little content`);
    }
    const apps = ["chat", "board", "files", "swarm", "feed", "wiki", "web"];
    for (const app of apps) {
        await page.evaluate(({ groupId, app }) => navigateSpace(groupId, app), { groupId, app });
        await page.waitForTimeout(800);
        const len = await page.locator("#view-container").evaluate(el => el.textContent.trim().length);
        failFast(len > 20, `${label} space/${app} rendered too little content`);
    }
    record(`${label}.embedded-gui-visible-views`, "pass", { views, apps });
}

async function ensureSpace(local, studio) {
    const created = await api(local, "POST", "/groups", {
        name: `GUI Full ${Date.now()}`,
        description: "Studio GUI full proof",
        preset: "public_open",
    });
    const groupId = created.group_id || created.id;
    failFast(groupId, "created group missing id");
    const inviteRes = await api(local, "POST", `/groups/${groupId}/invite`);
    const invite = inviteRes.invite_link || inviteRes.invite;
    failFast(invite && invite.startsWith("x0x://invite/"), "missing invite link");
    const joined = await api(studio, "POST", "/groups/join", { invite });
    await new Promise(resolve => setTimeout(resolve, 2500));
    return { localGroupId: groupId, studioGroupId: joined.group_id || joined.id || groupId };
}

async function proveGuiDm(localPage, studioPage, local, studio) {
    const localMsg = `gui dm local to studio ${Date.now()}`;
    const studioMsg = `gui dm studio to local ${Date.now()}`;
    await localPage.evaluate(({ target, message }) => {
        navigateDm(target);
        document.getElementById("dm-in").value = message;
        return sendDm();
    }, { target: studio.agent.agent_id, message: localMsg });
    await studioPage.evaluate(({ target, message }) => {
        navigateDm(target);
        document.getElementById("dm-in").value = message;
        return sendDm();
    }, { target: local.agent.agent_id, message: studioMsg });
    await waitForText(localPage, "#dm-msgs", studioMsg, 20000);
    await waitForText(studioPage, "#dm-msgs", localMsg, 20000);
    record("embedded-gui.dm-bidirectional-visible", "pass");
}

async function proveGuiRecovery(page) {
    await page.evaluate(() => ws.close());
    await page.waitForFunction(() => document.getElementById("st-conn")?.textContent === "Disconnected", null, { timeout: 10000 });
    await page.evaluate(() => wsConnect());
    await page.waitForFunction(() => document.getElementById("st-conn")?.textContent === "Connected", null, { timeout: 15000 });
    record("embedded-gui.websocket-offline-recovered", "pass");
}

async function startExampleServer() {
    const root = resolve("examples/apps");
    const server = createServer((req, res) => {
        try {
            const path = new URL(req.url || "/", "http://127.0.0.1").pathname;
            const file = resolve(root, path.replace(/^\/+/, ""));
            if (!file.startsWith(root) || !file.endsWith(".html")) {
                res.writeHead(404);
                res.end("not found");
                return;
            }
            res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
            res.end(readFileSync(file));
        } catch (e) {
            res.writeHead(500);
            res.end(String(e?.message || e));
        }
    });
    await new Promise(resolveListen => server.listen(0, "127.0.0.1", resolveListen));
    const addr = server.address();
    return { server, base: `http://127.0.0.1:${addr.port}` };
}

function appUrl(exampleBase, name, target, extra = "") {
    const url = new URL(`${exampleBase}/${name}.html`);
    url.searchParams.set("api", target.api_base);
    url.searchParams.set("token", target.token);
    if (extra) url.hash = extra;
    return url.toString();
}

async function proveChat(context, exampleBase, local, studio) {
    const lp = await context.newPage();
    const sp = await context.newPage();
    await lp.goto(appUrl(exampleBase, "x0x-chat", local), { waitUntil: "domcontentloaded" });
    await sp.goto(appUrl(exampleBase, "x0x-chat", studio), { waitUntil: "domcontentloaded" });
    await waitForText(lp, "#statusText", "Connected");
    await waitForText(sp, "#statusText", "Connected");
    const msg = `example chat ${Date.now()}`;
    await lp.fill("#msgInput", msg);
    await lp.click("#btnSend");
    await waitForText(sp, "#messages", msg, 20000);
    record("example-app.chat-cross-machine", "pass");
    await lp.close();
    await sp.close();
}

async function proveBoard(context, exampleBase, target, label) {
    const page = await context.newPage();
    await page.goto(appUrl(exampleBase, "x0x-board", target), { waitUntil: "domcontentloaded" });
    await page.waitForSelector("#selectView", { state: "visible", timeout: 15000 });
    const boardName = `${label} board ${Date.now()}`;
    await page.fill("#newBoardName", boardName);
    await page.fill("#newBoardTopic", boardName.toLowerCase().replace(/\s+/g, "-"));
    await page.click("button.btn-cyan");
    await page.waitForSelector("#board", { state: "visible", timeout: 10000 });
    await page.fill("#newTask", `${label} task`);
    await page.keyboard.press("Enter");
    await page.waitForSelector("#todoCards .card", { timeout: 10000 });
    await page.click("#todoCards .card-btn.claim");
    await page.waitForSelector("#progressCards .card", { timeout: 10000 });
    await page.click("#progressCards .card-btn.done");
    await page.waitForSelector("#doneCards .card", { timeout: 10000 });
    record(`example-app.board-${label}`, "pass");
    await page.close();
}

async function proveNetwork(context, exampleBase, target, label) {
    const page = await context.newPage();
    await page.goto(appUrl(exampleBase, "x0x-network", target), { waitUntil: "domcontentloaded" });
    await waitForText(page, "#i-agent", target.agent.agent_id.slice(0, 16), 15000);
    await waitForText(page, "#ct-count", "", 15000);
    record(`example-app.network-${label}`, "pass");
    await page.close();
}

async function proveSwarm(context, exampleBase, local, studio) {
    const session = Math.random().toString(16).slice(2, 10);
    const lp = await context.newPage();
    const sp = await context.newPage();
    await lp.goto(appUrl(exampleBase, "x0x-swarm", local, session), { waitUntil: "domcontentloaded" });
    await sp.goto(appUrl(exampleBase, "x0x-swarm", studio, session), { waitUntil: "domcontentloaded" });
    await waitForText(lp, "#statusText", "Connected", 15000);
    await waitForText(sp, "#statusText", "Connected", 15000);
    const task = `example swarm ${Date.now()}`;
    await lp.fill("#taskDesc", task);
    await lp.click("#submitBtn");
    await waitForText(sp, "#feed", task, 20000);
    record("example-app.swarm-cross-machine", "pass");
    await lp.close();
    await sp.close();
}

async function proveDrop(context, exampleBase, local, studio) {
    const lp = await context.newPage();
    const sp = await context.newPage();
    await lp.goto(appUrl(exampleBase, "x0x-drop", local), { waitUntil: "domcontentloaded" });
    await sp.goto(appUrl(exampleBase, "x0x-drop", studio), { waitUntil: "domcontentloaded" });
    await waitForText(lp, "#conn-label", "Connected", 15000);
    await waitForText(sp, "#conn-label", "Connected", 15000);
    await lp.waitForSelector("#agent-list .peer", { timeout: 15000 });
    await lp.click("#agent-list .peer");
    const upload = join(PROOF_DIR, "example-drop-upload.txt");
    writeFileSync(upload, `x0x drop proof ${Date.now()}`);
    await lp.setInputFiles("#fileIn", upload);
    await lp.waitForSelector("#send-btn", { state: "visible", timeout: 10000 });
    await lp.click("#send-btn");
    await sp.waitForSelector("#xfer-list button", { timeout: 20000 });
    await sp.click("#xfer-list button:has-text('Accept')");
    await waitForText(sp, "#xfer-list", "Complete", 30000);
    record("example-app.drop-cross-machine", "pass");
    await lp.close();
    await sp.close();
}

async function main() {
    const executablePath = chromePath();
    const browser = await chromium.launch({ headless: !process.env.X0X_GUI_HEADED, ...(executablePath ? { executablePath } : {}) });
    const context = await browser.newContext({ viewport: { width: 1440, height: 920 } });
    const examples = await startExampleServer();
    const local = manifest.local;
    const studio = manifest.studio;
    try {
        record("setup.example-loopback-server", "pass", { base: examples.base });
        const space = await ensureSpace(local, studio);
        record("setup.public-open-space", "pass", space);

        const localGui = await openGui(context, local, "macbook");
        const studioGui = await openGui(context, studio, "studio");
        await proveGuiViews(localGui.page, "macbook", space.localGroupId);
        await proveGuiViews(studioGui.page, "studio", space.studioGroupId);
        await proveGuiDm(localGui.page, studioGui.page, local, studio);
        await proveGuiRecovery(localGui.page);

        await proveChat(context, examples.base, local, studio);
        await proveBoard(context, examples.base, local, "macbook");
        await proveBoard(context, examples.base, studio, "studio");
        await proveNetwork(context, examples.base, local, "macbook");
        await proveNetwork(context, examples.base, studio, "studio");
        await proveSwarm(context, examples.base, local, studio);
        await proveDrop(context, examples.base, local, studio);
    } catch (e) {
        record("harness.failure", "fail", { reason: e.message });
    } finally {
        await context.close();
        await browser.close();
        await new Promise(resolveClose => examples.server.close(resolveClose));
        report.run_completed_at = new Date().toISOString();
        writeFileSync(join(PROOF_DIR, "studio-gui-full-report.json"), JSON.stringify(report, null, 2));
    }
    process.exit(report.totals.fail > 0 ? 1 : 0);
}

main().catch(err => {
    record("harness.uncaught", "fail", { reason: String(err?.message || err) });
    writeFileSync(join(PROOF_DIR, "studio-gui-full-report.json"), JSON.stringify(report, null, 2));
    process.exit(1);
});
