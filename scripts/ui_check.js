// Headless UI check: every view at desktop (1440px) and phone (390px) width, plus keyboard triage.
// Needs playwright-core and a Chromium (headless shell) outside this repo; no node deps are added here.
//
//   NODE_PATH=/path/to/node_modules CHROME=/path/to/chrome-headless-shell node scripts/ui_check.js
//
// It starts its own server on SIEM_PORT (default 8090) with a throwaway database under /tmp, loads the
// synthetic demo data as admin, runs the checks, and stops that server by PID. Exit code 1 on any failure.
// What it asserts per view: no horizontal page scroll, every visible input/select/textarea/button and
// link has an accessible name (a small in-page audit, not axe), landmarks and aria-current are present,
// tap targets are at least 40px tall at 390px, and no JS errors. It is not a screen-reader audit.
"use strict";
const { chromium } = require("playwright-core");
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = process.env.SIEM_PORT || "8090";
const BASE = `http://127.0.0.1:${PORT}/`;
const ADMIN_PW = "ui-check-admin-pass-1";
const VIEWER_PW = "ui-check-viewer-pass-1";
const failures = [];
const fail = (msg) => { failures.push(msg); console.log(`  FAIL ${msg}`); };
const ok = (msg) => console.log(`  ok   ${msg}`);
const check = (cond, msg) => (cond ? ok(msg) : fail(msg));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startServer() {
  const dir = fs.mkdtempSync(path.join("/tmp", "watchpost-ui-"));
  const env = { ...process.env, SIEM_PORT: PORT, SIEM_HOST: "127.0.0.1", SIEM_DB: path.join(dir, "ui.db"),
    SIEM_ADMIN_PASSWORD: ADMIN_PW, SIEM_ANALYST_PASSWORD: "ui-check-analyst-pass-1", SIEM_VIEWER_PASSWORD: VIEWER_PW,
    SIEM_RATE_LIMIT: "0" };
  const proc = spawn("python3", ["main.py"], { cwd: path.join(__dirname, ".."), env, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  proc.stderr.on("data", (d) => { stderr += d; });
  return { proc, dir, stderr: () => stderr };
}

async function waitReady() {
  for (let i = 0; i < 100; i += 1) {
    try { const r = await fetch(`${BASE}api/health`); if (r.status === 200 || r.status === 503) return; } catch { /* not up yet */ }
    await sleep(100);
  }
  throw new Error("server did not start");
}

// In-page audit. Accessible name: aria-labelledby, aria-label, a wrapping or for= label, title, or text.
function audit(minTap) {
  const visible = (n) => {
    const r = n.getBoundingClientRect();
    const st = getComputedStyle(n);
    return r.width > 0 && r.height > 0 && st.visibility !== "hidden" && !n.closest("[hidden]") && !n.closest("svg");
  };
  const name = (n) => {
    const by = n.getAttribute("aria-labelledby");
    if (by) return by.split(/\s+/).map((id) => document.getElementById(id)?.textContent || "").join(" ").trim();
    if (n.getAttribute("aria-label")) return n.getAttribute("aria-label").trim();
    if (["INPUT", "SELECT", "TEXTAREA"].includes(n.tagName)) {
      const lab = n.closest("label") || (n.id && document.querySelector(`label[for="${n.id}"]`));
      if (lab) return lab.textContent.trim() || (n.type === "checkbox" ? "(checkbox label)" : "");
      return (n.getAttribute("title") || "").trim();
    }
    return (n.textContent || "").trim() || (n.getAttribute("title") || "").trim();
  };
  const problems = [];
  const scope = document.querySelector("dialog[open]") || document;
  for (const n of scope.querySelectorAll("input:not([type=hidden]), select, textarea, button, a[href]")) {
    if (!visible(n)) continue;
    const desc = `${n.tagName.toLowerCase()}${n.name ? `[name=${n.name}]` : ""}${n.className ? `.${String(n.className).split(" ")[0]}` : ""}`;
    if (!name(n)) problems.push(`unlabeled ${desc}`);
    // Inline text links are exempt from the target size (WCAG 2.5.8); link-styled buttons are not.
    if (minTap && (n.tagName !== "A" || n.classList.contains("button")) && n.type !== "checkbox" && n.type !== "radio") {
      const h = n.getBoundingClientRect().height;
      if (h < minTap - 0.5) problems.push(`small tap target ${desc} "${name(n).slice(0, 30)}" ${Math.round(h)}px`);
    }
  }
  const sw = document.scrollingElement.scrollWidth, vw = window.innerWidth;
  if (sw > vw) {
    // Name the widest offenders to make a failure actionable.
    const wide = [...document.querySelectorAll("body *")].filter((n) => n.getBoundingClientRect().right > vw + 1 && !n.closest(".table-wrap, .cov-scroll, svg") && visible(n))
      .slice(0, 4).map((n) => `${n.tagName.toLowerCase()}.${String(n.className).split(" ")[0]}`);
    problems.push(`horizontal scroll ${sw}px > ${vw}px (${wide.join(", ")})`);
  }
  if (document.querySelectorAll("main").length !== 1) problems.push("expected exactly one <main>");
  const nav = document.querySelector("nav");
  if (!nav || !nav.getAttribute("aria-label")) problems.push("nav without aria-label");
  return problems;
}

async function login(browser, user, pw, width) {
  const ctx = await browser.newContext({ viewport: { width, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => {
    // 4xx answers the UI handles itself (409 on demo reload, 404 optional routes) are not JS errors.
    if (m.type() === "error" && !/status of 4\d\d/.test(m.text())) errors.push(`console: ${m.text()}`);
  });
  await page.goto(BASE);
  await page.fill("input[name=username]", user);
  await page.fill("input[name=password]", pw);
  await page.click("#login-form button[type=submit]");
  await page.waitForSelector("body.authed");
  return { ctx, page, errors };
}

async function show(page, hash) {
  await page.evaluate((h) => { location.hash = h; }, hash);
  await page.waitForFunction(() => document.querySelector("#view").childElementCount > 0);
  await page.waitForTimeout(700);
}

async function auditView(page, label, width) {
  const problems = await page.evaluate(audit, width <= 400 ? 40 : 0);
  check(!problems.length, `${width}px ${label}${problems.length ? `: ${problems.join("; ")}` : ""}`);
}

async function main() {
  const server = startServer();
  console.log(`server pid ${server.proc.pid}, db ${server.dir}`);
  const browser = await chromium.launch({ executablePath: process.env.CHROME });
  try {
    await waitReady();

    // Login form (logged out), both widths.
    for (const width of [1440, 390]) {
      const ctx = await browser.newContext({ viewport: { width, height: 900 } });
      const p = await ctx.newPage();
      await p.goto(BASE);
      await p.waitForSelector("#login-view:not([hidden])");
      await auditView(p, "login form", width);
      await ctx.close();
    }

    // Demo data, loaded through the Admin view like a person would.
    const admin = await login(browser, "admin", ADMIN_PW, 1440);
    await show(admin.page, "admin");
    await admin.page.click("text=Load synthetic demo data");
    await admin.page.waitForSelector("text=Alerts created", { timeout: 60000 });
    ok("demo data loaded");
    const alertId = await admin.page.evaluate(async () => (await (await fetch("/api/alerts?status=open")).json())[0].id);
    const incidentId = await admin.page.evaluate(async () => (await (await fetch("/api/incidents")).json())[0]?.id);
    const ruleId = await admin.page.evaluate(async () => (await (await fetch("/api/rules")).json())[0].id);
    await admin.ctx.close();

    const views = ["dashboard", "incidents", "alerts", `alerts/${alertId}`, incidentId ? `incidents/${incidentId}` : null, "events",
      "hunt", "hunt/user%3Aalice%20last%3A7d", "overview", "ingest", "rules", "noise", "coverage", "health", "admin", "account",
      "entity/user/alice"].filter(Boolean);

    for (const width of [1440, 390]) {
      console.log(`\n== ${width}px, admin ==`);
      const { ctx, page, errors } = await login(browser, "admin", ADMIN_PW, width);
      if (width <= 400) {
        check(await page.isHidden("#nav"), "390px nav folded behind the Menu button");
        await page.click("#nav-toggle");
        check(await page.isVisible("#nav") && (await page.getAttribute("#nav-toggle", "aria-expanded")) === "true", "Menu opens the nav (aria-expanded=true)");
        await page.click("#nav button[data-view=alerts]");
        await page.waitForTimeout(500);
        check(await page.isHidden("#nav") && page.url().endsWith("#alerts"), "choosing a view closes the menu");
      }
      for (const v of views) {
        await show(page, v);
        await auditView(page, `#${v}`, width);
      }
      await show(page, "overview");
      const triage = await page.evaluate(() => { const c = document.querySelector("#triage-metrics");
        return { rows: c ? c.querySelectorAll("tbody tr").length : 0, synth: !!c?.querySelector(".pill.synthetic") }; });
      check(triage.rows > 0 && triage.synth, `${width}px overview renders the triage metrics panel with the synthetic label (${triage.rows} rows)`);
      const current = await page.evaluate(() => [...document.querySelectorAll("#nav [aria-current=page]")].map((b) => b.dataset.view));
      check(current.length <= 1, `aria-current marks at most one nav item (${current.join(",") || "none on the entity page"})`);
      await show(page, "rules");
      check((await page.evaluate(() => document.querySelector("#nav [aria-current=page]")?.dataset.view)) === "rules", "aria-current=page on the Rules nav item");

      // Dialogs: each one fits the screen, is labelled, and passes the audit.
      const dialogs = [
        ["resolve dialog", `alerts/${alertId}`, "button:has-text('Resolve…')"],
        ["event dialog", "events", "#view tr.clickable"],
        ["propose-change dialog", "rules", `#rule-${ruleId} button:has-text('Propose change…')`],
        ["rules import dialog", "rules", "button:has-text('Import rules…')"],
        ["asset dialog", "admin", "button:has-text('Add asset')"],
        ["shortcut help", "alerts", "#kbd-help"],
      ];
      for (const [label, view, trigger] of dialogs) {
        await show(page, view);
        if (width <= 400 && trigger === "#kbd-help") { await page.click("#nav-toggle"); }
        await page.locator(trigger).first().click();
        await page.waitForSelector("#modal[open]");
        const box = await page.evaluate(() => { const r = document.querySelector("#modal").getBoundingClientRect(); return { l: r.left, r: r.right, w: innerWidth, label: document.querySelector("#modal").getAttribute("aria-labelledby") }; });
        check(box.l >= 0 && box.r <= box.w, `${width}px ${label} fits the screen (${Math.round(box.l)}..${Math.round(box.r)} of ${box.w})`);
        check(!!box.label, `${width}px ${label} is labelled by its heading`);
        await auditView(page, label, width);
        await page.keyboard.press("Escape");
        check(await page.isHidden("#modal"), `${width}px Esc closes the ${label}`);
      }

      // Backtest: preview a draft in the propose dialog, submit it, then find the same block in the review evidence.
      await show(page, "rules");
      await page.locator("#rule-brute_force_ip button:has-text('Propose change…')").click();
      await page.waitForSelector("#modal[open]");
      await page.fill("#modal textarea[name=params]", JSON.stringify({ threshold: 1000 }));
      await page.click("#backtest-run");
      await page.waitForFunction(() => /Backtest done/.test(document.querySelector("#backtest-status")?.textContent || ""), null, { timeout: 30000 });
      const preview = await page.evaluate(() => ({ text: document.querySelector("#backtest-preview")?.textContent || "",
        live: document.querySelector("#backtest-status")?.getAttribute("role") }));
      check(preview.text.includes("Backtest on stored events") && /Lost [1-9]/.test(preview.text) && preview.text.includes("Warning: loses"),
        `${width}px backtest preview shows lost findings and the open-alert warning`);
      check(preview.live === "status", `${width}px backtest result is announced in a status live region`);
      await page.locator("#backtest-preview summary").first().click();
      const fits = await page.evaluate(() => { const r = document.querySelector("#modal").getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth; });
      check(fits, `${width}px propose dialog with the backtest still fits the screen`);
      await auditView(page, "backtest preview", width);
      await page.fill("#modal textarea[name=reason]", `ui check backtest at ${width}px`);
      await page.click("#modal button[type=submit]");
      await page.waitForSelector("#modal", { state: "hidden" });
      await show(page, "rules");
      const block = page.locator("#view .backtest").first();
      check(await block.count() === 1 && (await block.textContent()).includes("Warning: loses"), `${width}px review evidence shows the backtest block`);
      await block.locator("summary").first().click();
      check(await block.locator("details[open] a[href^='#entity/']").count() > 0, `${width}px expanded backtest list links to entity pages`);
      await auditView(page, "rules with an expanded backtest", width);
      check(!errors.length, `${width}px no JS errors${errors.length ? `: ${errors.join(" | ")}` : ""}`);
      await ctx.close();
    }

    // Keyboard triage as admin.
    console.log("\n== keyboard triage (admin) ==");
    {
      const { ctx, page, errors } = await login(browser, "admin", ADMIN_PW, 1440);
      await show(page, "alerts");
      const rows = await page.$$eval("[data-kbd-list] tr.clickable", (r) => r.map((x) => x.dataset.id));
      check(rows.length >= 2, `alerts list has ${rows.length} rows`);
      const sel = () => page.evaluate(() => ({ id: document.activeElement?.dataset?.id, cls: document.activeElement?.classList.contains("kbd-selected"),
        ring: getComputedStyle(document.activeElement).outlineStyle }));
      await page.keyboard.press("j");
      let s = await sel();
      check(s.id === rows[0] && s.cls && s.ring !== "none", `j selects the first alert with a visible focus ring (${s.ring})`);
      await page.keyboard.press("j");
      check((await sel()).id === rows[1], "j moves to the second alert");
      await page.keyboard.press("k");
      check((await sel()).id === rows[0], "k moves back");
      await page.keyboard.press("j");
      await page.keyboard.press("Enter");
      await page.waitForFunction((id) => location.hash === `#alerts/${id}`, rows[1]);
      await page.waitForTimeout(500);
      ok("Enter opens the selected alert");
      await page.fill("textarea[name=body]", "");
      await page.focus("textarea[name=body]");
      await page.keyboard.type("jkr/?");
      check((await page.evaluate(() => location.hash)) === `#alerts/${rows[1]}` && await page.isHidden("#modal")
        && (await page.inputValue("textarea[name=body]")) === "jkr/?", "keys typed in the note box stay text, no shortcut fires");
      await page.fill("textarea[name=body]", "");
      await page.evaluate(() => document.activeElement.blur());
      const statusBefore = await page.evaluate(() => document.querySelector("#view .card .row .pill:nth-child(2)").textContent);
      if (statusBefore === "open") {
        await page.keyboard.press("a");
        await page.waitForFunction(() => document.querySelector("#view .card .row .pill:nth-child(2)")?.textContent === "investigating");
        ok("a starts investigating");
      }
      await page.keyboard.press("r");
      await page.waitForSelector("#modal[open]");
      check((await page.textContent("#modal h2")) === "Resolve alert", "r opens the resolve dialog");
      await page.keyboard.press("j");
      check((await page.evaluate(() => location.hash)) === `#alerts/${rows[1]}`, "j does nothing while the dialog is open");
      await page.keyboard.press("Escape");
      check(await page.isHidden("#modal"), "Esc closes the dialog first");
      check((await page.evaluate(() => location.hash)) === `#alerts/${rows[1]}`, "and stays on the alert");
      await page.keyboard.press("Escape");
      await page.waitForFunction(() => location.hash === "#alerts");
      await page.waitForTimeout(600);
      check((await sel()).id === rows[1], "Esc returns to the list with the alert still selected");
      await page.keyboard.press("/");
      await page.waitForFunction(() => location.hash.startsWith("#hunt"));
      await page.waitForTimeout(600);
      check(await page.evaluate(() => document.activeElement?.name === "q"), "/ opens Hunt and focuses the query box");
      await page.evaluate(() => document.activeElement.blur());
      await page.keyboard.press("?");
      check((await page.textContent("#modal h2")) === "Keyboard shortcuts", "? shows the shortcut help");
      await page.keyboard.press("Escape");
      await show(page, "incidents");
      await page.keyboard.press("j");
      const inc = await page.evaluate(() => document.activeElement?.getAttribute("href"));
      check(/^#(incidents|alerts)\/\d+$/.test(inc || ""), `j selects the first incident card (${inc})`);
      await page.keyboard.press("Enter");
      await page.waitForFunction((h) => location.hash === h, inc);
      await page.waitForTimeout(500);
      await page.keyboard.press("Escape");
      await page.waitForFunction(() => location.hash === "#incidents");
      await page.waitForTimeout(500);
      check((await page.evaluate(() => document.activeElement?.getAttribute("href"))) === inc, "Esc returns to Incidents with the card selected");
      check(!errors.length, `no JS errors during triage${errors.length ? `: ${errors.join(" | ")}` : ""}`);
      await ctx.close();
    }

    // Viewer: can move and open, has no action keys.
    console.log("\n== keyboard triage (viewer) ==");
    {
      const { ctx, page, errors } = await login(browser, "viewer", VIEWER_PW, 390);
      await show(page, "alerts");
      await page.keyboard.press("j");
      const id = await page.evaluate(() => document.activeElement?.dataset?.id);
      await page.keyboard.press("Enter");
      await page.waitForFunction((x) => location.hash === `#alerts/${x}`, id);
      await page.waitForTimeout(500);
      ok("viewer: j + Enter opens an alert");
      await page.keyboard.press("r");
      await page.keyboard.press("a");
      await page.waitForTimeout(400);
      check(await page.isHidden("#modal"), "viewer: r opens no resolve dialog");
      check((await page.evaluate(() => [...document.querySelectorAll("#view button")].map((b) => b.textContent))).every((t) => !/Resolve|investigating/.test(t)), "viewer: no action buttons");
      await page.keyboard.press("Escape");
      await page.waitForFunction(() => location.hash === "#alerts");
      ok("viewer: Esc returns to the list");
      await page.keyboard.press("?");
      check(!/(^|\n)r\b/.test(await page.textContent("#modal")) && !(await page.textContent("#modal")).includes("resolve dialog"), "viewer: help lists no action keys");
      await page.keyboard.press("Escape");
      for (const v of ["dashboard", "alerts", "hunt", "coverage", "rules"]) { await show(page, v); await auditView(page, `viewer #${v}`, 390); }
      check(await page.locator("a[href='/api/rules/export']").count() === 1 && await page.locator("button:has-text('Import rules…')").count() === 0,
        "viewer: rules export link shown, no import button");
      check(!errors.length, `viewer: no JS errors${errors.length ? `: ${errors.join(" | ")}` : ""}`);
      await ctx.close();
    }
  } finally {
    await browser.close();
    server.proc.kill("SIGTERM");  // our own server only, by PID
    fs.rmSync(server.dir, { recursive: true, force: true });
  }
  console.log(`\n${failures.length ? `UI CHECK FAILED (${failures.length})` : "UI CHECK OK"}`);
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
