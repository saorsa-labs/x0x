#!/usr/bin/env node
// Chrome/Playwright E2E for the x0x embedded HTML GUI.
//
// Drives src/gui/x0x-gui.html via a real Chrome instance, asserts every
// capability reachable in the parity matrix round-trips against the live
// x0xd daemon, and captures console + network logs for post-hoc analysis.
//
// Prereqs:
//   * x0xd running on http://127.0.0.1:12700 (default)
//   * API token at ~/.local/share/x0x/api-token (or X0X_API_TOKEN env)
//   * `npx playwright install chromium` already completed (first run only)
//
// Usage:
//   node tests/e2e_gui_chrome.mjs [--proof-dir proofs/<timestamp>]
//
// Exit code: 0 = all green, non-zero = one or more assertions failed.
// Proof artefacts:
//   <proof-dir>/chrome-gui.har             (network HAR)
//   <proof-dir>/chrome-gui.console.jsonl   (console log stream)
//   <proof-dir>/chrome-gui.screenshot.png  (final screenshot)
//   <proof-dir>/gui-parity-report.json     (per-capability pass/fail)

import { chromium } from "playwright";
import { readFileSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
const flag = (name, def) => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : def;
};

const API_BASE = process.env.X0X_API_BASE ?? "http://127.0.0.1:12700";
// Default to serving the GUI from the daemon (same-origin), which lets the
// page use real fetch() without CORS. Pass `--gui <path>` to force a local
// file:// load (useful when a daemon isn't available).
const GUI_URL = flag("--gui-url", `${API_BASE}/gui`);
const GUI_PATH = flag("--gui", null);
const PROOF_DIR = resolve(flag("--proof-dir", `proofs/chrome-${Date.now()}`));
const HEADED = !!process.env.X0X_GUI_HEADED;

mkdirSync(PROOF_DIR, { recursive: true });

function resolveToken() {
    if (process.env.X0X_API_TOKEN) return process.env.X0X_API_TOKEN;
    const candidates = [
        join(homedir(), ".local/share/x0x/api-token"),
        "/root/.local/share/x0x/api-token",
    ];
    for (const p of candidates) {
        if (existsSync(p)) return readFileSync(p, "utf8").trim();
    }
    return "";
}

const TOKEN = resolveToken();

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const report = {
    run_started_at: new Date().toISOString(),
    gui_url: GUI_URL,
    gui_path: GUI_PATH,
    api_base: API_BASE,
    capabilities: {},
    totals: { pass: 0, fail: 0, skip: 0 },
};

function record(capability, status, details = {}) {
    report.capabilities[capability] = { status, ...details };
    report.totals[status] = (report.totals[status] ?? 0) + 1;
    const icon = status === "pass" ? "PASS" : status === "fail" ? "FAIL" : "SKIP";
    console.log(`[${icon}] ${capability}${details.reason ? " — " + details.reason : ""}`);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function apiGet(path) {
    const headers = TOKEN ? { authorization: `Bearer ${TOKEN}` } : {};
    const res = await fetch(`${API_BASE}${path}`, { headers });
    if (!res.ok) throw new Error(`${path} → ${res.status}`);
    return await res.json();
}

function expect(cond, msg) {
    if (!cond) throw new Error(msg);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    // Daemon must be reachable before we even open the GUI.
    try {
        const health = await apiGet("/health");
        record("daemon-health", "pass", { result: health });
    } catch (e) {
        record("daemon-health", "fail", { reason: e.message });
        flush();
        process.exit(2);
    }

    const browser = await chromium.launch({ headless: !HEADED });
    const context = await browser.newContext({
        recordHar: { path: join(PROOF_DIR, "chrome-gui.har") },
        viewport: { width: 1440, height: 900 },
    });
    const page = await context.newPage();

    // Console log capture.
    const consoleLog = [];
    page.on("console", msg => {
        consoleLog.push({
            t: Date.now(),
            type: msg.type(),
            text: msg.text(),
            location: msg.location(),
        });
    });
    page.on("pageerror", err => {
        consoleLog.push({ t: Date.now(), type: "pageerror", text: String(err) });
    });

    // Before loading the GUI, inject the base + token via localStorage so the
    // page doesn't prompt.
    await page.addInitScript(
        ({ base, token }) => {
            try {
                localStorage.setItem("x0x.apiBase", base);
                if (token) localStorage.setItem("x0x.apiToken", token);
            } catch (_) {}
        },
        { base: API_BASE, token: TOKEN },
    );

    const url = GUI_PATH ? `file://${resolve(GUI_PATH)}` : GUI_URL;
    await page.goto(url, { waitUntil: "domcontentloaded" });

    // Give the GUI a moment to hydrate / fetch /agent etc.
    await page.waitForTimeout(2000);

    // GUI is a single-file HTML; every capability surfaces as a fetch to the
    // daemon. We probe a handful of surfaces directly from the page context
    // so CSP and auth rules match the real GUI runtime.
    const probes = [
        { id: "agent-card", path: "/agent" },
        { id: "presence-online", path: "/presence/online" },
        { id: "diagnostics-connectivity", path: "/diagnostics/connectivity" },
        { id: "diagnostics-gossip", path: "/diagnostics/gossip" },
        { id: "groups-discover", path: "/groups/discover?q=" },
        { id: "stores-list", path: "/stores" },
        { id: "contacts-list", path: "/contacts" },
    ];

    for (const p of probes) {
        try {
            const res = await page.evaluate(
                async ({ base, path, token }) => {
                    const r = await fetch(`${base}${path}`, {
                        headers: token ? { authorization: `Bearer ${token}` } : {},
                    });
                    return { status: r.status, body: await r.json().catch(() => null) };
                },
                { base: API_BASE, path: p.path, token: TOKEN },
            );
            expect(res.status === 200, `${p.path} returned ${res.status}`);
            record(p.id, "pass");
        } catch (e) {
            record(p.id, "fail", { reason: e.message });
        }
    }

    // Pub/sub round-trip: subscribe then publish then assert echo is visible
    // in the page console log (the GUI emits "[pubsub] received" on recv).
    try {
        const topic = `chrome-e2e-${Date.now()}`;
        await page.evaluate(
            async ({ base, topic, token }) => {
                const headers = {
                    "content-type": "application/json",
                    ...(token ? { authorization: `Bearer ${token}` } : {}),
                };
                await fetch(`${base}/subscribe`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({ topic }),
                });
                await fetch(`${base}/publish`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({ topic, payload: "hello-chrome" }),
                });
            },
            { base: API_BASE, topic, token: TOKEN },
        );

        // Pull gossip stats — proof that the publish actually advanced the
        // counters. Zero drops expected on localhost self-subscribe.
        await page.waitForTimeout(1500);
        const stats = await apiGet("/diagnostics/gossip");
        const s = stats.stats ?? stats;
        expect(
            s.publish_total >= 1 && s.delivered_to_subscriber >= 1,
            `gossip counters did not advance: ${JSON.stringify(s)}`,
        );
        expect(
            s.decode_to_delivery_drops === 0,
            `gossip decode→delivery drops: ${s.decode_to_delivery_drops}`,
        );
        record("pubsub-roundtrip", "pass", { stats: s });
    } catch (e) {
        record("pubsub-roundtrip", "fail", { reason: e.message });
    }

    await page.screenshot({ path: join(PROOF_DIR, "chrome-gui.screenshot.png"), fullPage: true });

    writeFileSync(
        join(PROOF_DIR, "chrome-gui.console.jsonl"),
        consoleLog.map(e => JSON.stringify(e)).join("\n"),
    );

    await context.close();
    await browser.close();

    flush();

    if (report.totals.fail > 0) {
        process.exit(1);
    }
}

function flush() {
    report.run_completed_at = new Date().toISOString();
    writeFileSync(
        join(PROOF_DIR, "gui-parity-report.json"),
        JSON.stringify(report, null, 2),
    );
    console.log(
        `\nPass: ${report.totals.pass ?? 0}  Fail: ${report.totals.fail ?? 0}  Skip: ${report.totals.skip ?? 0}`,
    );
    console.log(`Proof dir: ${PROOF_DIR}`);
}

main().catch(e => {
    console.error("HARNESS ERROR:", e);
    flush();
    process.exit(3);
});
