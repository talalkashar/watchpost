// Run from the UI suite against a signed-in, seeded dashboard. Watch from document
// creation so a flat SVG that is attached and removed between paints still fails.
const assert = require("node:assert/strict");

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
module.exports = { checkDashboardGlobe };
