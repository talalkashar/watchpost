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

async function checkAccountViews(page, base, viewerPassword) {
  const views = "**/api/dashboard/views";
  const privateView = { id: 27, name: "Analyst handoff", owner: "admin", visibility: "private",
    filters: { severities: ["critical"] }, layout: ["p-feed"] };
  await page.route(views, route => route.fulfill({ json: [privateView] }));
  await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
  const bar = page.locator("#dashboard-view-bar");
  await bar.locator('[name=saved_view]').selectOption("27");
  await bar.getByRole("button", { name: "Apply" }).click();
  await bar.getByRole("heading", { name: privateView.name }).waitFor();

  // Hold a refresh from the outgoing account across sign-out and viewer sign-in.
  let holdOutgoing, holdIncoming;
  const outgoingRequest = new Promise(resolve => { holdOutgoing = resolve; });
  const incomingRequest = new Promise(resolve => { holdIncoming = resolve; });
  await page.route(views, holdIncoming);
  await page.route(views, holdOutgoing, { times: 1 });
  await page.evaluate(() => { window.oldViewsRequest = Dash.loadViews(); });
  const outgoing = await outgoingRequest;
  await page.locator("#logout").dispatchEvent("click");
  await page.locator("#login-form [name=username]").fill("viewer");
  await page.locator("#login-form [name=password]").fill(viewerPassword);
  await page.locator("#login-form button[type=submit]").click();
  await bar.locator("[name=saved_view]").waitFor();
  const whileLoading = await bar.textContent();
  await outgoing.fulfill({ json: [privateView] });
  await page.evaluate(() => window.oldViewsRequest);
  assert.ok(!whileLoading.includes(privateView.name), "previous account's view appeared before the viewer's list arrived");
  assert.ok(!(await bar.textContent()).includes(privateView.name), "late response restored the previous account's view");
  await (await incomingRequest).fulfill({ json: [{ id: 28, name: "Viewer handoff", visibility: "private", owner: "viewer" }] });
  await bar.locator('option[value="28"]').waitFor({ state: "attached" });
}

async function checkFeedCatchup(page, base) {
  const summary = await (await page.request.get(base + "api/dashboard")).json();
  const first = { ...summary.recent_events[0], id: 1, event_type: "first.sample" };
  const second = { ...first, id: 2, event_type: "second.sample" };
  const third = { ...first, id: 3, event_type: "third.sample" };
  const older = { ...first, id: 4, ts: "2000-01-01T00:00:00Z", event_type: "late.sample" };
  let recent = [first];
  await page.route("**/api/dashboard", route => route.fulfill({ json: { ...summary, recent_events: recent } }));
  await page.goto(base + "#map-2d", { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => Dash.mapView?.flat && Dash.data?.recent_events[0]?.id === 1);
  await page.evaluate(events => Live.onEvents(events, events.length), [second, older]);
  // The fresh snapshot overlaps the stream and includes a row missed by the stream.
  recent = [third, second, first];
  await page.locator("#map-globe").click();
  await page.waitForFunction(() => !Dash.mapView?.flat && Dash.data?.recent_events[0]?.id === 3);
  await page.waitForFunction(() => Dash.queue.length === 0);
  assert.deepEqual(await page.locator("#feed .fn").allTextContents(), ["third.sample", "second.sample", "first.sample", "late.sample"]);
}

async function checkFirstFlatPulse(page, base) {
  const source = "192.0.2.157";
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto(base + "#map-2d", { waitUntil: "domcontentloaded" });
  await page.locator("#map").scrollIntoViewIfNeeded();
  await page.waitForFunction(() => Dash.mapView?.near && Dash.mapDims && Dash.hq());
  await page.route("**/api/geo?*", route => {
    const ips = new URL(route.request().url()).searchParams.get("ips").split(",");
    return ips.includes(source) ? route.fulfill({ json: { ips: { [source]: { city: "Test", lon: 10, lat: 50 } } } })
      : route.continue();
  });
  await page.evaluate(src_ip => {
    Live.onEvents([{ id: 71, src_ip, dest_ip: "10.0.0.10", severity: "high" }], 1);
  }, source);
  await page.waitForFunction(ip => Geo.get(ip), source);
  assert.equal(await page.locator("#map g.fx .shot.s-high").count(), 1, "first event from a cold source should draw one pulse");
}

module.exports = { checkSavedViewDraft, checkFeedPause, checkEmptyFlatMap, checkAccountViews, checkFeedCatchup, checkFirstFlatPulse };
