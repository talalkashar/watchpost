// Browser regressions for the dashboard's async toolbar and projection navigation.
// Called with a signed-in page from the seeded UI suite.
const assert = require("node:assert/strict");

async function checkSavedViewDraft(page, base) {
  const views = "**/api/dashboard/views";
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  const holdViews = async route => {
    await waiting;
    await route.fulfill({ json: [{ id: 17, name: "Existing view", visibility: "private" }] });
  };
  await page.route(views, holdViews);
  try {
    await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
    await page.locator(".view-save summary").click();
    const form = page.locator(".view-save-form");
    await form.locator("[name=filter]").selectOption("critical");
    await form.locator("[name=layout]").selectOption("triage");
    await form.locator("[name=visibility]").selectOption("shared");
    await form.locator("[name=name]").fill("Morning triage");
    release();
    await page.locator('[name=saved_view] option[value="17"]').waitFor({ state: "attached" });
    assert.ok(await form.isVisible(), "loading saved views closed the draft");
    assert.deepEqual(await form.evaluate(f => Object.fromEntries(new FormData(f))), {
      name: "Morning triage", filter: "critical", layout: "triage", visibility: "shared",
    });
    assert.ok(await form.locator("[name=name]").evaluate(input => input === document.activeElement));
  } finally {
    release();
    await page.unroute(views, holdViews);
  }
}

async function checkFeedPause(page, base) {
  await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
  const pause = page.locator("#feed-pause");
  await pause.click();
  assert.equal(await pause.getAttribute("aria-pressed"), "true");
  await page.locator("#map-flat").click();
  await page.waitForURL("**/#map-2d");
  await page.locator("#map-globe").click();
  await page.waitForURL("**/#dashboard");
  assert.equal(await pause.textContent(), "Resume");
  assert.equal(await pause.getAttribute("aria-pressed"), "true");
  await pause.click();
  assert.equal(await pause.textContent(), "Pause");
  assert.equal(await pause.getAttribute("aria-pressed"), "false");
}

async function checkEmptyFlatMap(page, base) {
  const summary = "**/api/dashboard";
  const empty = route => route.fulfill({ json: { events_total: 0, events_per_minute: [],
    alerts_open: 0, alerts_investigating: 0, alerts_critical_open: 0 } });
  await page.route(summary, empty);
  try {
    await page.goto(base + "#map-2d", { waitUntil: "domcontentloaded" });
    await page.locator(".flat-map-view").waitFor({ state: "attached" });
    await page.waitForFunction(() => document.querySelector("#k-events")?.textContent === "0");
    assert.ok(await page.getByRole("heading", { name: "No events yet" }).isVisible(),
      "2D should explain why the store is empty");
    assert.ok(await page.getByRole("button", { name: "Load demo data" }).isVisible());
  } finally {
    await page.unroute(summary, empty);
  }
}

module.exports = { checkSavedViewDraft, checkFeedPause, checkEmptyFlatMap };
