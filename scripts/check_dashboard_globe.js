// Run from the UI suite against a signed-in, seeded dashboard. Watch from document
// creation so a flat SVG that is attached and removed between paints still fails.
const assert = require("node:assert/strict");

async function checkSelectedRoute(page, base) {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
  await page.locator("#map-globe").scrollIntoViewIfNeeded();
  await page.locator('#p-map[data-mode="3d"]').waitFor();
  const source = page.locator("#map-side button").first();
  await source.click();
  const city = await source.getAttribute("data-city");
  const detail = page.locator(".orbit-detail strong");
  assert.equal(await detail.textContent(), city);
  await page.locator("#map-flat").click();
  await page.locator(".flat-map-view #map-side button").first().waitFor();
  const flatCity = await detail.textContent();
  await page.locator("#map-globe").click();
  await page.locator('#p-map[data-mode="3d"] #map-side button').first().waitFor();
  assert.deepEqual([flatCity, await detail.textContent(), await page.locator(".orbit-motion").getAttribute("data-running")],
    [city, city, "false"], "both projections should retain the source and the globe should stay paused");
}

async function checkProjectionCamera(page, base) {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
  const surface = page.locator('#p-map[data-mode="3d"] .orbit-beams');
  await surface.scrollIntoViewIfNeeded();
  const box = await surface.boundingBox();
  const x = box.x + box.width / 2, y = box.y + box.height / 2;
  await page.mouse.move(x, y);
  await page.mouse.down();
  await page.mouse.move(x + 36, y + 20, { steps: 4 });
  await page.mouse.up();
  const zoom = page.getByRole("button", { name: "Zoom in", exact: true });
  await zoom.click();
  await zoom.click();
  const bearing = page.locator(".orbit-bearing");
  await bearing.filter({ hasText: "×2.0" }).waitFor();
  assert.equal(await page.locator(".orbit-motion").getAttribute("data-running"), "false");
  const paused = await bearing.textContent();
  assert.doesNotMatch(paused, /31\.0°N/, "drag should change the latitude");

  await page.locator("#map-flat").click();
  await page.locator(".flat-map-view #map-globe").click();
  await page.locator('#p-map[data-mode="3d"] .orbit-bearing').filter({ hasText: "×" }).waitFor();
  assert.equal(await bearing.textContent(), paused, "globe bearing and zoom should survive a projection switch");
}

async function checkStationaryGlobe(page, base) {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
  const globe = page.locator("#map-globe");
  await globe.scrollIntoViewIfNeeded();
  await page.waitForFunction(() => Dash.mapView?.near);
  assert.equal(await page.locator("#p-map").getAttribute("data-mode"), "preview");
  assert.equal(await page.locator(".orbit-stage canvas").count(), 0);
  await globe.click();
  await page.locator('#p-map[data-mode="3d"] .orbit-bearing').waitFor();
  assert.equal(await page.locator(".orbit-motion").getAttribute("data-running"), "false");
  assert.ok(await page.locator(".orbit-motion").isHidden());
  for (const name of ["Zoom in", "Zoom out", "Fit globe"]) {
    await page.getByRole("button", { name, exact: true }).click();
  }
  const overhead = page.getByRole("button", { name: /Overhead view/ });
  await page.locator("#map-side button").first().waitFor();
  await overhead.click();
  assert.equal(await overhead.getAttribute("aria-pressed"), "true");

  await page.locator("#map-flat").click();
  await page.locator(".flat-map-view").waitFor();
  await globe.click();
  await page.locator('#p-map[data-mode="3d"] .orbit-bearing').waitFor();
  assert.equal(await page.locator(".orbit-motion").getAttribute("data-running"), "false");
  assert.equal(await overhead.getAttribute("aria-pressed"), "true", "Overhead camera was lost");
  assert.equal(await page.locator(".orbit-stage").getAttribute("data-tactical"), "true", "range rings were lost");
}

async function checkCameraHint(page, base) {
  await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
  await page.locator('#p-map[data-mode="3d"] .orbit-overhead').waitFor();
  const hint = page.locator(".orbit-hint");
  if (page.viewportSize().width > 760) {
    assert.ok(await hint.isHidden());
    return;
  }
  const [text, tools, arcs] = await Promise.all([hint, page.locator(".orbit-tools"), page.locator("#map-side")]
    .map(node => node.boundingBox()));
  assert.ok(text && text.y >= tools.y && text.y + text.height <= Math.min(tools.y + tools.height, arcs.y) + 0.5,
    "camera hint extends beyond the toolbar");
}

async function checkDashboardGlobe(page, base) {
  page.setDefaultTimeout(30000);
  await page.addInitScript(() => {
    window.flatMapAttachments = 0;
    new MutationObserver(records => {
      if (location.hash === "#map-2d") return;
      for (const { addedNodes } of records) {
        for (const node of addedNodes) {
          if (node.matches?.(".worldmap") || node.querySelector?.(".worldmap")) window.flatMapAttachments++;
        }
      }
    }).observe(document, { subtree: true, childList: true });
  });
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  const hold = async route => { await waiting; await route.continue(); };
  await page.route("**/orbit.js", hold);
  try {
    await page.goto(base + "#dashboard", { waitUntil: "domcontentloaded" });
    await page.locator("#map-side button").first().waitFor();
    assert.equal(await page.evaluate(() => window.flatMapAttachments), 0, "flat map attached while globe was loading");
    const stage = page.locator(".orbit-stage");
    const pending = await stage.boundingBox();
    release();
    await page.locator(".orbit-bearing").filter({ hasText: "°" }).waitFor();
    assert.equal(await page.evaluate(() => window.flatMapAttachments), 0, "flat map attached before first globe frame");
    assert.deepEqual(await stage.boundingBox(), pending, "globe stage moved on first draw");
  } finally {
    release();
    await page.unroute("**/orbit.js", hold);
  }

  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.locator("#map-side button").first().click();
  assert.equal(await page.locator("#p-map").getAttribute("data-mode"), "preview");
  assert.equal(await page.evaluate(() => window.flatMapAttachments), 0, "flat map attached with reduced motion");

  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.addInitScript(() => {
    const getContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (type, ...options) {
      return type === "webgl2" ? null : getContext.call(this, type, ...options);
    };
  });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.locator('#map-globe[title*="unavailable"]').waitFor();
  await page.locator("#map-side button").first().click();
  assert.equal(await page.evaluate(() => window.flatMapAttachments), 0, "flat map attached without WebGL");

  await page.locator("#map-flat").click();
  await page.waitForURL("**/#map-2d");
  await page.locator(".worldmap .mk .core").first().click();
  assert.equal(await page.locator("#map-side button[aria-pressed=true]").count(), 1);
  await page.locator("#map-globe").click();
  await page.waitForURL("**/#dashboard");
  await page.locator(".orbit-placeholder").waitFor();
  assert.equal(await page.evaluate(() => window.flatMapAttachments), 0, "flat map attached on return to dashboard");
}
module.exports = { checkProjectionCamera, checkCameraHint, checkSelectedRoute, checkDashboardGlobe, checkStationaryGlobe };
