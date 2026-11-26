// Headless UI check: every view at 320px, 390px and 1440px, plus keyboard triage.
// Needs playwright-core and a Chromium (headless shell) outside this repo; no node deps are added here.
//
//   NODE_PATH=/path/to/node_modules CHROME=/path/to/chrome-headless-shell node scripts/ui_check.js
//
// It starts its own server on SIEM_PORT (default 8090) with a throwaway database under /tmp, loads the
// synthetic demo data as admin, runs the checks, and stops that server by PID. Exit code 1 on any failure.
// What it asserts per view: no horizontal page scroll, every visible input/select/textarea/button and
// link has an accessible name (a small in-page audit, not axe), landmarks and aria-current are present,
// tap targets are at least 44px tall on phones, and no JS errors. It is not a screen-reader audit.
"use strict";
const { checkDashboardGlobe } = require("./check_dashboard_globe");
const { checkSavedViewDraft, checkFeedPause, checkEmptyFlatMap } = require("./check_dashboard_state");
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
    return r.width > 0 && r.height > 0 && st.visibility !== "hidden" && n.checkVisibility() && !n.closest("[hidden]") && !n.closest("svg");
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
  for (const n of scope.querySelectorAll("input:not([type=hidden]), select, textarea, button, a[href], summary")) {
    if (!visible(n)) continue;
    const desc = `${n.tagName.toLowerCase()}${n.name ? `[name=${n.name}]` : ""}${n.className ? `.${String(n.className).split(" ")[0]}` : ""}`;
    if (!name(n)) problems.push(`unlabeled ${desc}`);
    // Inline text links are exempt from the target size (WCAG 2.5.8); link-styled buttons are not.
    if (minTap && (n.tagName !== "A" || n.matches(".button, .ph a, .bmore, .page-head a"))) {
      const target = ["checkbox", "radio"].includes(n.type) ? n.closest("label") || n : n;
      const h = target.getBoundingClientRect().height;
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
  const ctx = await browser.newContext({ viewport: { width, height: width === 320 ? 568 : width === 390 ? 844 : 900 } });
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
  const problems = await page.evaluate(audit, width <= 400 ? 44 : 0);
  check(!problems.length, `${width}px ${label}${problems.length ? `: ${problems.join("; ")}` : ""}`);
}

// SVG font-size is in user units. Include the screen transform to catch a
// readable CSS declaration being scaled down by the chart's viewBox.
function matrixGeometry(box) {
  const labels = [...box.querySelectorAll(".heat text")];
  const columns = [...box.querySelectorAll(".tactic")];
  const bounds = box.getBoundingClientRect();
  const edges = columns.map((column) => {
    const ctm = column.getScreenCTM();
    return { left: ctm.e, right: ctm.e + column.width.baseVal.value * ctm.a };
  });
  const impact = columns.findIndex((column) => column.querySelector(".th title").textContent === "Impact");
  return {
    columns: columns.length,
    font: Math.min(...labels.map((el) => {
      const m = el.getScreenCTM();
      return parseFloat(getComputedStyle(el).fontSize) * Math.hypot(m.c, m.d);
    })),
    fit: edges.every(({ left, right }) => left >= bounds.left - 0.02 && right <= bounds.right + 0.02),
    clipped: labels.filter((el) => {
      const { left, right } = el.getBoundingClientRect();
      const column = el.ownerSVGElement;
      const m = column.getScreenCTM();
      return left < m.e - 0.02 || right > m.e + column.width.baseVal.value * m.a + 0.02;
    }).map((el) => el.firstChild.textContent),
    impactRight: edges[impact]?.right, containerRight: bounds.right,
    contentWidth: box.scrollWidth, containerWidth: box.clientWidth, pageWidth: document.scrollingElement.scrollWidth,
  };
}

async function main() {
  const server = startServer();
  console.log(`server pid ${server.proc.pid}, db ${server.dir}`);
  const browser = await chromium.launch({ executablePath: process.env.CHROME });
  try {
    await waitReady();

    // Login form (logged out), phones first.
    for (const width of [320, 390, 1440]) {
      const ctx = await browser.newContext({ viewport: { width, height: width === 320 ? 568 : width === 390 ? 844 : 900 } });
      const p = await ctx.newPage();
      await p.goto(BASE);
      await p.waitForSelector("#login-view:not([hidden])");
      await auditView(p, "login form", width);
      check(await p.locator("#login-view").getByText("All data is synthetic.").isVisible(),
        `${width}px sign-in includes the data disclosure`);
      await ctx.close();
    }

    // Demo data, loaded through the Admin view like a person would.
    const admin = await login(browser, "admin", ADMIN_PW, 1440);
    await show(admin.page, "admin");
    await admin.page.click("text=Load demo data");
    await admin.page.waitForSelector("text=Alerts created", { timeout: 60000 });
    ok("demo data loaded");
    for (const checkDashboard of [checkSavedViewDraft, checkFeedPause, checkEmptyFlatMap, checkDashboardGlobe]) {
      const dashboardPage = await admin.ctx.newPage();
      try {
        await checkDashboard(dashboardPage, BASE);
        ok(checkDashboard.name);
      } finally { await dashboardPage.close(); }
    }
    await admin.page.goto(BASE + "#dashboard");
    for (const width of [1101, 1180, 1280, 1440, 1920]) {
      await admin.page.setViewportSize({ width, height: 900 });
      await admin.page.reload();
      await admin.page.waitForSelector("#attack-chart .cellg");
      const size = await admin.page.locator("#attack-chart").evaluate(matrixGeometry);
      check(size.columns === 15 && size.fit && size.impactRight <= size.containerRight + 0.02
        && size.contentWidth === size.containerWidth && size.pageWidth === width && !size.clipped.length && size.font >= 11,
        `${width}px ATT&CK matrix: ${size.font.toFixed(2)}px labels, IMPACT right ${size.impactRight?.toFixed(2)} / ${size.containerRight.toFixed(2)}, clipped [${size.clipped}]`);
    }
    await admin.page.setViewportSize({ width: 1440, height: 900 });

    const alertId = await admin.page.evaluate(async () => (await (await fetch("/api/alerts?status=open")).json())[0].id);
    const incidentId = await admin.page.evaluate(async () => (await (await fetch("/api/incidents")).json())[0]?.id);
    const ruleId = await admin.page.evaluate(async () => (await (await fetch("/api/rules")).json())[0].id);
    // A saved search, so the hunt page shows "Promote to detection…" (state.csrf is the app's own token).
    const savedStatus = await admin.page.evaluate(async () => (await fetch("/api/hunt/saved", { method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrf },
      body: JSON.stringify({ name: "UI check failed logins", query: "event_type:auth_failure" }) })).status);
    check(savedStatus === 201, `saved a search for the promote dialog (${savedStatus})`);
    // Exercise logout, expired MFA and sign-in again in the same tab.
    const page = admin.page;
    check(await page.locator("#login-view[hidden]").count() === 1, "signed-in page keeps the sign-in section hidden");
    await page.click("#logout");
    const expired = "sign-in step expired; sign in again";
    await page.route("**/api/auth/login", (route) => route.fulfill({
      json: { mfa_required: true, mfa_token: "ui-test-challenge" },
    }), { times: 1 });
    await page.route("**/api/auth/mfa", (route) => route.fulfill({ status: 401, json: { error: expired } }), { times: 1 });
    await page.fill("#login-form [name=username]", "admin");
    await page.fill("#login-form [name=password]", ADMIN_PW);
    await page.click("#login-form button[type=submit]");
    await page.fill("#mfa-code", "000000");
    await page.click("#mfa-form button[type=submit]");
    await page.waitForSelector("#login-error:visible");
    check(await page.textContent("#login-error") === expired && await page.isVisible("#login-form")
      && await page.locator("#mfa-form").count() === 0, "expired MFA after logout restores the password form and shows the server message in #login-error");
    await page.fill("#login-form [name=username]", "admin");
    await page.fill("#login-form [name=password]", ADMIN_PW);
    await page.click("#login-form button[type=submit]");
    await page.waitForSelector("body.authed");
    check(await page.locator("#login-view[hidden]").count() === 1 && !admin.errors.length, "sign-in succeeds after the expired challenge");
    await admin.ctx.close();

    const views = ["dashboard", "graph", "incidents", "alerts", `alerts/${alertId}`, incidentId ? `incidents/${incidentId}` : null, "events",
      "hunt", "hunt/user%3Aalice%20last%3A7d", "overview", "ingest", "rules", "noise", "coverage", "health", "admin", "account",
      "entity/user/alice"].filter(Boolean);

    for (const width of [320, 390, 1440]) {
      console.log(`\n== ${width}px, admin ==`);
      const { ctx, page, errors } = await login(browser, "admin", ADMIN_PW, width);
      if (width <= 400) {
        check(await page.isHidden("#nav"), `${width}px nav folded behind the Menu button`);
        await page.click("#nav-toggle");
        check(await page.isVisible("#nav") && (await page.getAttribute("#nav-toggle", "aria-expanded")) === "true", "Menu opens the nav (aria-expanded=true)");
        await page.click("#nav button[data-view=alerts]");
        await page.waitForTimeout(500);
        check(await page.isHidden("#nav") && page.url().endsWith("#alerts"), "choosing a view closes the menu");
      }
      for (const v of views) {
        await show(page, v);
        await auditView(page, `#${v}`, width);
        check(await page.locator("#strip .synthetic, #view .synthetic, #view .syn").count() === 0,
          `${width}px #${v} has no repeated origin badges`);
        if (v === "alerts") {
          const related = page.locator(".active-incidents");
          await related.locator("summary").click();
          check(await related.locator("tbody tr[data-id]").first().isVisible(), `${width}px active incidents expand`);
          await related.locator("summary").click();
        }
        if (v === "events") {
          const message = await page.locator(".event-log tr[data-id] td:last-child").first().innerText();
          check(message.length > 0 && !message.includes("[SYNTHETIC"), `${width}px event rows show the message without its fixture marker`);
        }
        if (width >= 390 && v === "dashboard") {
          await page.waitForSelector("#attack-chart .cellg");
          const size = await page.locator("#attack-chart").evaluate((box) => {
            box.scrollLeft = box.scrollWidth;
            const result = { offset: box.scrollLeft, total: box.scrollWidth, visible: box.clientWidth,
              page: document.scrollingElement.scrollWidth, overflow: getComputedStyle(box).overflowX };
            box.scrollLeft = 0;
            return result;
          });
          if (width === 390) {
            check(["auto", "scroll"].includes(size.overflow) && size.offset > 0
              && size.offset === size.total - size.visible && size.page === width,
              `390px ATT&CK matrix scrolls ${size.offset}px inside its ${size.visible}px box (${size.total}px content, ${size.page}px page)`);
          } else {
            check(size.offset === 0 && size.total === size.visible, `${width}px ATT&CK matrix fits its ${size.visible}px box`);
          }
        }
      }
      await show(page, "overview");
      const triage = await page.evaluate(() => { const c = document.querySelector("#triage-metrics");
        return { rows: c ? c.querySelectorAll("tbody tr").length : 0, synth: !!c?.querySelector(".pill.synthetic") }; });
      check(triage.rows > 0 && !triage.synth, `${width}px overview renders triage metrics without a repeating origin badge (${triage.rows} rows)`);
      await show(page, "health");
      const sources = await page.evaluate(() => { const c = document.querySelector("#source-health");
        return { rows: c ? c.querySelectorAll("tbody tr").length : 0, pills: c ? c.querySelectorAll(".pill").length : 0 }; });
      check(sources.rows > 0 && sources.pills > 0, `${width}px health renders the log source health panel (${sources.rows} rows)`);
      await show(page, `hunt/${encodeURIComponent("event_type:auth_failure | top src_ip")}`);
      const top = await page.evaluate(() => { const t = document.querySelector("#hunt-agg table");
        return { cols: t ? [...t.querySelectorAll("th")].map((h) => h.textContent).join(",") : "", links: t ? t.querySelectorAll("tbody a").length : 0 }; });
      check(top.cols === "src_ip,count,percent" && top.links > 0, `${width}px hunt "| top src_ip" renders a table with pivot links (${top.links})`);
      await auditView(page, "hunt top", width);
      const current = await page.evaluate(() => [...document.querySelectorAll("#nav [aria-current=page]")].map((b) => b.dataset.view));
      check(current.length <= 1, `aria-current marks at most one nav item (${current.join(",") || "none on the entity page"})`);
      await show(page, "rules");
      check((await page.evaluate(() => document.querySelector("#nav [aria-current=page]")?.dataset.view)) === "rules", "aria-current=page on the Rules nav item");

      // Dialogs: each one fits the screen, is labelled, and passes the audit.
      const dialogs = [
        ["resolve dialog", `alerts/${alertId}`, "button:has-text('Resolve…')"],
        ["event dialog", "events", "#view tr.clickable"],
        ["propose-change dialog", "rules", `#rule-${ruleId} button:has-text('Propose change…')`],
        ["rule-suppression dialog", "rules", `#rule-${ruleId} button:has-text('Schedule suppression…')`],
        ["rules import dialog", "rules", "button:has-text('Import rules…')"],
        ["sigma import dialog", "rules", "button:has-text('Import Sigma rule…')"],
        ["promote dialog", "hunt", "button:has-text('Promote to detection…')"],
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

    // Motion follows the document scroll and preserves layout, navigation and fallbacks.
    console.log("\n== scroll motion and reload ==");
    {
      const { ctx, page } = await login(browser, "admin", ADMIN_PW, 320);
      await show(page, "dashboard");
      await page.waitForTimeout(1000);
      check(await page.locator("#p-health").evaluate((n) => getComputedStyle(n).opacity === "0"), "below-fold panel waits for scrolling");
      const motion = await page.locator("#p-health").evaluate(async (node) => {
        const before = { top: node.offsetTop, height: node.offsetHeight };
        let shifts = 0;
        const observer = new PerformanceObserver((list) => { for (const entry of list.getEntries()) if (!entry.hadRecentInput) shifts += entry.value; });
        observer.observe({ type: "layout-shift" });
        node.scrollIntoView({ block: "center" });
        const samples = [];
        const start = performance.now();
        await new Promise((resolve) => {
          const frame = () => { samples.push(Number(getComputedStyle(node).opacity));
            if (performance.now() - start < 1100) requestAnimationFrame(frame); else resolve(); };
          requestAnimationFrame(frame);
        });
        observer.disconnect();
        return { animated: samples.some((v) => v > 0 && v < 1), visible: Number(getComputedStyle(node).opacity) === 1,
          stable: node.offsetTop === before.top && node.offsetHeight === before.height, shifts };
      });
      check(motion.animated && motion.visible, "scrolling reveals the panel and leaves it readable");
      check(motion.stable && motion.shifts === 0, `reveal preserves layout (CLS ${motion.shifts})`);
      await page.evaluate(() => { history.replaceState(null, "", location.pathname); scrollTo(0, 600); });
      await page.reload();
      await page.waitForSelector("#soc");
      await page.waitForTimeout(1000);
      check(await page.evaluate(() => scrollY === 0 && history.scrollRestoration === "manual"), "reload returns to the document top");
      await page.evaluate(() => { location.hash = "main"; });
      await page.waitForTimeout(100);
      check(await page.evaluate(() => scrollY > 0 && document.body.dataset.view === "dashboard"), "in-page hash jumps without replacing the view");
      await page.reload();
      await page.waitForSelector("#soc");
      await page.waitForTimeout(1000);
      check(await page.evaluate(() => Math.abs(document.querySelector("#main").getBoundingClientRect().top) < 1), "reload preserves the hash destination");
      await page.emulateMedia({ reducedMotion: "reduce" });
      check(await page.locator(".reveal-pending").evaluateAll((nodes) => nodes.every((n) => getComputedStyle(n).opacity === "1" && getComputedStyle(n).transform === "none")), "enabling reduced motion makes pending content visible immediately");
      await show(page, "overview");
      check(await page.locator(".reveal-pending").count() === 0
        && await page.locator("#view h1").evaluate((n) => getComputedStyle(n).animationName === "none"), "reduced motion disables reveals and intros on new views");
      await ctx.close();
      const noScript = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 320, height: 568 } });
      const plain = await noScript.newPage();
      await plain.goto(BASE);
      check(await plain.locator("#login-form").isVisible()
        && await plain.locator(".credit").last().isVisible(), "sign-in content and footer remain visible without JavaScript");
      await noScript.close();
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
      // Leave Hunt before its query returns, then reopen it without the shortcut.
      let releaseQuery;
      const held = new Promise((resolve) => { releaseQuery = resolve; });
      await page.route("**/api/hunt?*", async (route) => { await held; await route.continue(); }, { times: 1 });
      const started = page.waitForRequest("**/api/hunt?*");
      await page.keyboard.press("/");
      await started;
      await page.click('#nav [data-view="incidents"]');
      await page.waitForSelector('[data-kbd-list="incidents"]');
      releaseQuery();
      await page.click('#nav [data-view="hunt"]');
      await page.waitForSelector("#view [data-search]");
      check(await page.locator('#nav [data-view="hunt"]').evaluate((b) => b === document.activeElement),
        "leaving a pending Hunt cancels shortcut focus on the next visit");
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
      for (const v of ["dashboard", "graph", "alerts", "hunt", "coverage", "rules"]) { await show(page, v); await auditView(page, `viewer #${v}`, 390); }
      check(await page.locator("a[href='/api/rules/export']").count() === 1 && await page.locator("button:has-text('Import rules…')").count() === 0
        && await page.locator("button:has-text('Import Sigma rule…')").count() === 0,
        "viewer: rules export link shown, no import buttons");
      await show(page, "hunt");
      check(await page.locator("button:has-text('Promote to detection…')").count() === 0, "viewer: no promote button on saved searches");
      check(await page.locator("#masked-pill").count() === 0, "viewer: no Masked view pill while viewer_masking is off (the default)");
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
