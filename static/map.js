"use strict";
// Watchpost attacker map: hand-drawn, simplified continent outlines ([lon, lat] rings),
// equirectangular projection, rendered as a dot matrix. No tiles, no network, no library.
// Positions for attackers come from the server's synthetic geo table (/api/geo), never
// from a real geo lookup; addresses outside that table are listed as "unknown".

const LAT_TOP = 83, LAT_BOTTOM = -57;

const LAND = [
  // North America
  [[-168, 66], [-162, 70], [-156, 71.5], [-140, 70], [-128, 70], [-115, 68], [-95, 72], [-85, 70], [-80, 64], [-94, 59],
    [-92, 57], [-82, 55], [-79, 52], [-77, 58], [-72, 62], [-64, 60], [-61, 56], [-56, 52], [-60, 47], [-66, 45], [-70, 42],
    [-74, 40], [-76, 35], [-81, 31], [-80, 26], [-82, 27], [-84, 30], [-89, 30], [-94, 29.5], [-97, 27], [-97, 22],
    [-95, 18.5], [-91, 19], [-87, 21.5], [-88, 16], [-84, 15], [-83, 11], [-80, 9], [-78, 8], [-80, 7.5], [-83, 8.5],
    [-86, 12], [-92, 14.5], [-96, 16], [-105, 20], [-106, 23], [-110, 23], [-114, 28], [-117, 32], [-121, 35], [-124, 40],
    [-124, 46], [-125, 49], [-130, 54], [-135, 58], [-140, 60], [-146, 61], [-152, 59], [-158, 57], [-164, 55], [-160, 58],
    [-165, 61], [-166, 64]],
  // Arctic archipelago
  [[-120, 74], [-100, 78], [-80, 82], [-65, 82], [-75, 76], [-90, 74], [-110, 72]],
  // Greenland
  [[-55, 60], [-44, 60], [-40, 65], [-22, 70], [-20, 76], [-18, 81], [-35, 83], [-60, 82], [-72, 78], [-67, 76], [-58, 75],
    [-52, 69], [-50, 64]],
  // South America
  [[-78, 8], [-72, 12], [-64, 10.5], [-60, 8.5], [-52, 5], [-50, 0], [-44, -2.5], [-35, -5], [-35, -9], [-39, -15],
    [-40, -22], [-48, -26], [-53, -34], [-58, -38.5], [-62, -39], [-65, -42], [-65, -47], [-69, -51], [-68, -55],
    [-72, -54], [-75, -50], [-74, -44], [-73, -37], [-71.5, -30], [-70, -18], [-76, -14], [-81, -6], [-80, -2], [-77, 4]],
  // Eurasia
  [[-9.5, 37], [-6, 36], [-2, 36.8], [0, 38.5], [3, 41.5], [3.5, 43.3], [7, 43.5], [9, 44.3], [12, 42], [16, 38],
    [15.5, 40.5], [18.5, 40.2], [13, 45.5], [19, 42], [20, 39.5], [23, 36.5], [24, 38], [23, 40], [26, 40.8], [26, 38.5],
    [28, 36.7], [32, 36.1], [36, 36.2], [35.5, 33], [34.3, 31.3], [34.5, 29.5], [35, 28], [37, 25], [39, 21], [42.8, 14],
    [43.5, 12.7], [45, 13], [52, 16], [55, 17.5], [58.5, 20.5], [59.8, 22.5], [56.5, 24.5], [56, 26.3], [54, 24.2],
    [51.5, 24.5], [50, 26.5], [48, 29.5], [50, 30], [51, 27.8], [54.5, 26.5], [57, 25.7], [61.5, 25.2], [66.5, 25.4],
    [67.5, 24], [70, 21], [72.8, 19], [73.5, 16], [75, 12], [76.5, 8.5], [77.5, 8], [80, 10], [80.3, 13.5], [82, 16.5],
    [86.5, 20], [87, 21.5], [89, 22], [91.5, 22.5], [92.5, 20.5], [94, 18], [94.5, 16], [97.5, 16.5], [98.5, 13],
    [98.3, 10], [98.5, 8], [100.3, 6], [101, 3], [103.5, 1.3], [104.2, 1.5], [103.5, 4], [102.5, 6], [100.5, 7.5],
    [99.5, 10], [100, 13.5], [102, 12.5], [105, 9], [106.5, 10.5], [109, 11.5], [109, 14], [108, 16.5], [106.5, 18.5],
    [106.8, 20.5], [108.5, 21.6], [110.5, 20.3], [111, 21.5], [113.5, 22.2], [117, 23.5], [119.5, 26], [121.5, 29.5],
    [121.8, 31], [120.5, 32.5], [119.2, 35], [121, 36.8], [122.5, 37.4], [119, 37.2], [118, 38.5], [117.8, 39], [119, 39.3],
    [121.5, 40.9], [122, 39.2], [121.3, 39], [124, 39.8], [125.3, 37.7], [126.6, 34.5], [129.3, 35.2], [129.5, 37.8],
    [128, 39.5], [130, 42.5], [133, 42.8], [135.5, 43.8], [138, 46.5], [140.5, 49], [140.8, 53], [137, 54], [141, 58],
    [143.5, 59.3], [149, 59.5], [155, 59.3], [156.7, 57], [156, 51.5], [158.5, 53], [162, 56], [163.5, 59.7], [170, 60],
    [179.9, 64.5], [179.9, 68.5], [176, 69.8], [170, 70], [160, 69.8], [150, 71], [140, 72.5], [130, 71], [128, 73],
    [113, 73.5], [110, 76.5], [104, 77.7], [98, 76], [88, 75.5], [80, 73.5], [72, 72.8], [68.5, 71], [66, 69], [60, 69.8],
    [55, 68.5], [44, 68.3], [41, 66.5], [35, 66.5], [33, 69.2], [28, 71], [20, 70], [15, 68], [12.5, 65.8], [10, 63.5],
    [5, 62], [5.5, 59], [7, 58], [10, 59], [11.5, 58.5], [12.5, 56.3], [12.8, 55.5], [14.3, 55.6], [16, 56.5], [16.5, 57.8],
    [17, 60.5], [18.5, 60.2], [21, 62.8], [25, 65.2], [22, 65.8], [21.5, 63.8], [21.4, 60.8], [22.8, 59.9], [28, 60.4],
    [29.5, 59.9], [23.5, 59.2], [21.5, 57.5], [21, 56], [19.8, 54.5], [14.3, 53.9], [11, 54], [10, 55.3], [8.5, 57.1],
    [8, 55.5], [8.6, 53.6], [7, 53.4], [4.8, 52.5], [3.3, 51.3], [1.6, 50.9], [-1.5, 49.7], [-2, 48.6], [-4.7, 48.4],
    [-2.5, 47.3], [-1.2, 44.7], [-1.8, 43.4], [-8, 43.7], [-9.2, 43], [-8.8, 41.5], [-9.5, 39]],
  // Africa
  [[-17, 21], [-16.5, 24], [-13, 27.7], [-10, 29.5], [-9.8, 31.5], [-6.8, 34], [-5.9, 35.8], [-2, 35.1], [1, 36.5],
    [10, 37.2], [11, 35.2], [10, 34], [11, 33.2], [15.3, 32.2], [19.8, 30.8], [20.5, 32.5], [25, 32], [29, 30.9],
    [32.3, 31.3], [34.2, 31.2], [34.9, 29.5], [32.5, 29.8], [35.5, 23.7], [37.2, 21], [38.5, 18], [43.3, 12.5], [44, 10.5],
    [51, 11.8], [51.2, 10.5], [48.5, 5], [41.5, -1.5], [39, -5], [40.5, -10.5], [40.5, -15.5], [35.3, -22], [35.5, -24],
    [32.8, -26], [32.5, -28.7], [30, -31.4], [27, -33.6], [22.5, -34], [20, -34.8], [18.4, -34], [18, -31.5], [15.2, -27],
    [14.5, -22.5], [11.8, -17], [12.5, -13.5], [13.8, -11], [12.3, -6], [9.6, -2.3], [9.5, 3], [8.5, 4.5], [5.5, 4.2],
    [1, 6], [-2, 4.8], [-7.5, 4.4], [-11.5, 6.9], [-13.3, 9], [-15, 11], [-16.8, 13.5], [-17.5, 14.7], [-16.5, 19.5]],
  // Madagascar
  [[49.3, -12], [50.5, -15.5], [49.5, -17.5], [47.2, -25], [45, -25.5], [43.3, -22], [44.4, -16.5], [47, -15]],
  // Great Britain, Ireland, Iceland
  [[-5.7, 50], [1.4, 51.2], [1.7, 52.7], [0, 53.5], [-1.6, 55.6], [-2, 57.6], [-3, 58.6], [-5, 58.6], [-6.2, 56.5],
    [-5.1, 55], [-3, 54.2], [-4.8, 52.8], [-4.2, 51.6]],
  [[-6, 52], [-6.2, 54], [-7.5, 55.2], [-10, 54.2], [-10.2, 51.8], [-8, 51.6]],
  [[-22, 64], [-14, 64.5], [-13.6, 65.5], [-16, 66.5], [-22.5, 66.4], [-24, 65.4]],
  // Japan
  [[130, 31], [131.8, 33.5], [135, 33.5], [137, 34.5], [140, 35], [141, 38], [142, 40.5], [141.5, 41.5], [140, 40.5],
    [139.5, 38], [137, 37], [136, 36], [133, 35.5], [130.8, 34]],
  [[140, 41.5], [141.5, 42.5], [143.5, 42], [145.5, 43.3], [145, 44.3], [141.8, 45.4], [141.5, 43.4], [140, 42.5]],
  // Maritime Southeast Asia
  [[120, 18.5], [122.2, 18.5], [122, 16], [124, 13], [126, 8], [125.5, 6], [122, 7], [120.5, 10.5], [119.8, 15.5]],
  [[95.3, 5.5], [97.5, 5.2], [100, 2.3], [104, -1.5], [106, -5.8], [104.5, -5.8], [101, -3], [98.7, 0.5]],
  [[105.5, -6], [108, -6.3], [112, -6.8], [114.5, -7.8], [111, -8.3], [106, -7.5]],
  [[109, 1.5], [110.5, 1.7], [114, 4.5], [116.5, 6.9], [119, 5], [118, 1], [116.5, -2.5], [116, -4], [113, -3.3],
    [110.2, -3], [109, -0.5]],
  [[119.5, -5.5], [120.5, -2], [119, 0.7], [120.5, 1.2], [125, 1.5], [123, -0.8], [121.5, -1], [123.5, -5.5], [121.8, -4.8]],
  [[131, -1], [134, -1], [138, -1.6], [141, -2.6], [145, -4.3], [148, -8], [150.5, -10.5], [147, -10], [143.5, -9],
    [141, -9.2], [138, -8.3], [137.5, -5], [133.5, -4], [132, -2.8]],
  // Australia, Tasmania, New Zealand
  [[113.5, -22], [114, -26.5], [115, -31], [115, -34.2], [118, -35], [123, -33.8], [126, -32.3], [131, -31.5],
    [135, -34.8], [138, -35.5], [140, -38], [144, -38.3], [146.3, -39], [150, -37.5], [151, -34], [153, -31],
    [153.6, -28.3], [153, -25], [150.5, -22.5], [149, -20.5], [146.3, -19], [145.3, -15], [143.5, -14], [142.5, -10.7],
    [141.5, -13], [141.5, -16.5], [140, -17.7], [136.5, -15.5], [137, -12.3], [136.7, -12], [132.5, -11.2],
    [130.5, -12.3], [129.5, -15], [127, -14], [125.2, -15], [123, -16.5], [122.2, -18], [119, -20], [116.7, -20.6]],
  [[144.6, -40.7], [148.3, -40.9], [148, -43], [146.5, -43.6], [145.2, -42.2]],
  [[172.7, -34.4], [174.5, -36], [176, -37.6], [178.5, -37.7], [177, -39.3], [176, -41.3], [174.7, -41.3], [175, -40],
    [173.8, -39.2], [174.5, -38]],
  [[172.7, -40.5], [174.3, -41.7], [173.2, -43], [171.2, -44.5], [170.5, -45.9], [168.4, -46.6], [166.5, -45.8],
    [168.3, -44], [171, -42]],
  // Sri Lanka, Cuba, Hispaniola
  [[79.8, 6], [80, 9.8], [81.9, 7.5], [81.2, 6.1]],
  [[-85, 21.9], [-82, 23.2], [-77.5, 21.8], [-74.2, 20.2], [-77.7, 19.9], [-80.5, 22]],
  [[-74.5, 18.5], [-72.8, 19.9], [-69, 19.8], [-68.3, 18.6], [-71, 18]],
];

// Inland seas cut out of Eurasia.
const WATER = [
  [[28, 41.5], [28, 44], [30, 46.5], [33, 46], [36, 45.3], [38, 47], [39.8, 44], [41.5, 41.5], [36, 41.5], [31, 41.2]],
  [[47, 37.5], [49.5, 37.5], [54, 37], [54, 41], [52.5, 42], [54, 44], [51, 47], [47.5, 46.5], [47.5, 43], [49.5, 40.5]],
];

function project(lon, lat, w, h) {
  return [((lon + 180) / 360) * w, ((LAT_TOP - lat) / (LAT_TOP - LAT_BOTTOM)) * h];
}

function inside(lon, lat, ring) {
  let hit = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i], [xj, yj] = ring[j];
    if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) hit = !hit;
  }
  return hit;
}

let dotCache = null;
function landDots(step = 2.4) {
  if (dotCache && dotCache.step === step) return dotCache.dots;
  const dots = [];
  for (let lat = LAT_TOP - step / 2; lat > LAT_BOTTOM; lat -= step) {
    for (let lon = -180 + step / 2; lon < 180; lon += step) {
      if (LAND.some((r) => inside(lon, lat, r)) && !WATER.some((r) => inside(lon, lat, r))) dots.push([lon, lat]);
    }
  }
  dotCache = { step, dots };
  return dots;
}

const r2 = (v) => Math.round(v * 10) / 10;

// At 2x, sample the land about twice as fine. 1x keeps the caller's step.
function crispStep(step) {
  const dpr = typeof window !== "undefined" && window.devicePixelRatio ? window.devicePixelRatio : 1;
  if (dpr < 2) return step;
  return Math.min(step, Math.max(0.95, step * 0.56));
}

// Static layer: ocean, graticule, coastlines, land dots. Returns an SVG string.
function baseMap(w, h, { step = 2.4 } = {}) {
  const used = crispStep(step);
  const rw = r2(w), rh = r2(h);
  let out = `<svg xmlns="http://www.w3.org/2000/svg" class="worldmap" width="${rw}" height="${rh}" viewBox="0 0 ${rw} ${rh}" role="group" aria-label="Attacker map" shape-rendering="geometricPrecision">`;
  // Keep city labels readable when a bright arc or land dot passes underneath.
  out += `<defs><radialGradient id="map-ocean" cx="50%" cy="40%" r="78%"><stop offset="0%" stop-color="#16181d"/><stop offset="100%" stop-color="#0c0c0e"/></radialGradient>`;
  out += `<filter id="map-label-plate" x="-5%" y="-5%" width="110%" height="110%" color-interpolation-filters="sRGB"><feFlood flood-color="#191919" flood-opacity=".88"/><feComposite in="SourceGraphic" operator="over"/></filter></defs>`;
  out += `<rect class="ocean" x="0" y="0" width="${rw}" height="${rh}" fill="url(#map-ocean)"/><g class="graticule">`;
  for (let lon = -150; lon < 180; lon += 30) {
    const [x] = project(lon, 0, w, h);
    out += `<line x1="${r2(x)}" x2="${r2(x)}" y1="0" y2="${rh}"/>`;
  }
  for (let lat = -30; lat <= 60; lat += 30) {
    const [, y] = project(0, lat, w, h);
    out += `<line class="${lat === 0 ? "equator" : ""}" x1="0" x2="${rw}" y1="${r2(y)}" y2="${r2(y)}"/>`;
  }
  out += `</g><g class="coast">`;
  for (const ring of LAND) {
    out += `<path d="${ring.map(([lon, lat], i) => { const [x, y] = project(lon, lat, w, h); return `${i ? "L" : "M"}${r2(x)} ${r2(y)}`; }).join("")}Z"/>`;
  }
  out += `</g><g class="land">`;
  const rad = Math.max(0.45, (w / 360) * used * 0.38);
  for (const [lon, lat] of landDots(used)) {
    const [x, y] = project(lon, lat, w, h);
    out += `<circle cx="${r2(x)}" cy="${r2(y)}" r="${r2(rad)}"/>`;
  }
  return out + `</g><g class="arcs"></g><g class="marks"></g><g class="fx"></g></svg>`;
}

// Curved path from a to b ([lon, lat]), bowed toward the pole for a flight-path look.
function arcPath(a, b, w, h) {
  const [x1, y1] = project(a[0], a[1], w, h);
  const [x2, y2] = project(b[0], b[1], w, h);
  const dist = Math.hypot(x2 - x1, y2 - y1);
  const cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.min(h * 0.45, dist * 0.35);
  return `M${r2(x1)} ${r2(y1)}Q${r2(cx)} ${r2(cy)} ${r2(x2)} ${r2(y2)}`;
}

globalThis.WPMap = Object.freeze({ LAND, WATER, project, inside, landDots, baseMap, arcPath });

// Decorate the dashboard map after it paints. dashboard.js owns the geometry.
// Scoped so classic scripts do not share these names with app.js.
(function () {
"use strict";
const SVG_NS = "http://www.w3.org/2000/svg";
const SEVS = ["critical", "high", "medium", "low", "info"];
const COUNTRY = {
  Northhaven: "Sweden",
  Saltmere: "Australia",
  "Kestrel Bay": "Japan",
  Duskport: "Brazil",
  Ironvale: "Russia",
  Emberfield: "Nigeria",
  "Riverton HQ": "United States",
  "Lakeside branch": "United States",
  "Hillcrest remote site": "United States",
  "Watchpost HQ (internal)": "United States",
};
const rulesByIp = new Map();
let rulesPromise = null;
let activeMark = null;

function ns(name) { return document.createElementNS(SVG_NS, name); }
function countryOf(city) { return COUNTRY[city] || "—"; }
function sevName(g) {
  for (const s of SEVS) if (g.classList.contains("sev-" + s)) return s;
  return "info";
}
function clip(value, n) {
  const s = String(value || "—");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function parseMark(g) {
  const raw = g.querySelector("title") ? g.querySelector("title").textContent : "";
  const lines = raw.split("\n");
  const city = (lines[0] || "").trim();
  const ips = (lines[1] || "").split(",").map((s) => s.trim()).filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip));
  const found = raw.match(/(\d+)\s+events/);
  return { city, ips, events: found ? Number(found[1]) : 0, sev: sevName(g) };
}
function arcStart(d) {
  const m = /M\s*(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)/.exec(d || "");
  return m ? [Number(m[1]), Number(m[2])] : null;
}
function weightName(events, max) {
  if (!max) return "wt-1";
  const t = events / max;
  if (t >= 0.75) return "wt-4";
  if (t >= 0.45) return "wt-3";
  if (t >= 0.2) return "wt-2";
  return "wt-1";
}
function setWt(node, wt) {
  for (let n = 1; n <= 4; n++) node.classList.toggle("wt-" + n, wt === "wt-" + n);
}
function setPh(node, ph) {
  for (let n = 0; n < 6; n++) node.classList.toggle("ph-" + n, ph === "ph-" + n);
}
function hit(a, b, pad) {
  return a.x < b.x + b.w + pad && a.x + a.w + pad > b.x && a.y < b.y + b.h + pad && a.y + a.h + pad > b.y;
}
function circleBox(c) {
  const x = Number(c.getAttribute("cx")), y = Number(c.getAttribute("cy")), r = Number(c.getAttribute("r")) || 0;
  return { x: x - r, y: y - r, w: r * 2, h: r * 2 };
}
function attrBox(rect) {
  return {
    x: Number(rect.getAttribute("x")), y: Number(rect.getAttribute("y")),
    w: Number(rect.getAttribute("width")), h: Number(rect.getAttribute("height")),
  };
}
function panelBoxes(svg) {
  const ctm = svg.getScreenCTM();
  if (!ctm) return null;
  const inv = ctm.inverse();
  const boxes = [];
  for (const el of [document.getElementById("map-side"), document.querySelector("#p-map .map-legend")]) {
    if (!el) continue;
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") continue;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) continue;
    const a = svg.createSVGPoint(); a.x = r.left; a.y = r.top;
    const b = svg.createSVGPoint(); b.x = r.right; b.y = r.bottom;
    const p = a.matrixTransform(inv), q = b.matrixTransform(inv);
    boxes.push({ x: Math.min(p.x, q.x), y: Math.min(p.y, q.y), w: Math.abs(q.x - p.x), h: Math.abs(q.y - p.y) });
  }
  return boxes;
}
async function readJson(path) {
  const res = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!res.ok) return null;
  return res.json();
}
function topRule(ips) {
  let best = null;
  for (const ip of ips) {
    const rows = rulesByIp.get(ip);
    if (!rows) continue;
    for (const row of rows) if (!best || row.count > best.count) best = row;
  }
  return best;
}
function loadRules(schedule) {
  if (rulesPromise) return rulesPromise;
  rulesPromise = (async () => {
    try {
      const [alerts, dash] = await Promise.all([readJson("/api/alerts?limit=200"), readJson("/api/dashboard")]);
      const names = new Map();
      for (const rule of (dash && dash.top_rules) || []) {
        if (rule && rule.rule_id) names.set(rule.rule_id, rule.name || rule.rule_id);
      }
      const tally = new Map();
      for (const alert of Array.isArray(alerts) ? alerts : []) {
        const key = String(alert.group_key || "");
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(key)) continue;
        const id = alert.rule_id || "";
        const count = Number(alert.event_count) || 0;
        const list = tally.get(key) || [];
        let row = list.find((item) => item.id === id);
        if (!row) {
          row = { id, name: names.get(id) || id || "—", count: 0 };
          list.push(row);
        } else if (names.get(id)) row.name = names.get(id);
        row.count += count > 0 ? count : 1;
        tally.set(key, list);
      }
      rulesByIp.clear();
      for (const [ip, list] of tally) rulesByIp.set(ip, list);
    } catch { /* tooltip falls back to an em dash */ }
    schedule();
  })();
  return rulesPromise;
}
function paintArcs(svg) {
  const arcs = svg.querySelector("g.arcs");
  if (!arcs) return;
  const infos = [...svg.querySelectorAll("g.marks > g.mk")].map((g) => {
    const core = g.querySelector("circle.core");
    const info = parseMark(g);
    return {
      x: core ? Number(core.getAttribute("cx")) : 0,
      y: core ? Number(core.getAttribute("cy")) : 0,
      events: info.events,
    };
  });
  const max = infos.reduce((m, info) => Math.max(m, info.events), 0);
  [...arcs.querySelectorAll(":scope > path.arc:not(.arc-guide)")].forEach((path, i) => {
    const start = arcStart(path.getAttribute("d"));
    let events = 0;
    if (start && infos.length) {
      let best = Infinity, n = 0;
      for (const info of infos) {
        const d = Math.hypot(info.x - start[0], info.y - start[1]);
        if (d < best) { best = d; n = info.events; }
      }
      if (best <= 2.5) events = n;
    }
    let guide = path.previousElementSibling;
    if (!guide || !guide.classList.contains("arc-guide")) {
      guide = path.cloneNode(false);
      guide.classList.remove("arc-pulse");
      guide.classList.add("arc-guide");
      path.parentNode.insertBefore(guide, path);
    }
    const wt = weightName(events, max);
    path.classList.add("arc-pulse");
    guide.classList.remove("arc-pulse");
    for (const node of [path, guide]) setWt(node, wt);
    setPh(path, "ph-" + (i % 6));
  });
}
function placeOne(svg, text, core, obstacles, placed) {
  if (!core) return "hidden";
  const cx = Number(core.getAttribute("cx"));
  const cy = Number(core.getAttribute("cy"));
  const r = Number(core.getAttribute("r")) || 4;
  const vb = svg.viewBox.baseVal;
  const candidates = [
    [cx + r + 10, cy + 3, "start"],
    [cx - r - 10, cy + 3, "end"],
    [cx, cy - r - 8, "middle"],
    [cx, cy + r + 14, "middle"],
    [cx + r + 36, cy - 2, "start"],
    [cx, cy - r - 22, "middle"],
    [cx - r - 14, cy + r + 14, "end"],
  ];
  let plate = text.previousElementSibling;
  if (!plate || !plate.classList.contains("chip-plate")) {
    plate = ns("rect");
    plate.setAttribute("class", "chip-plate");
    plate.setAttribute("rx", "5");
    text.parentNode.insertBefore(plate, text);
  }
  for (const [x, y, anchor] of candidates) {
    text.setAttribute("x", String(r2(x)));
    text.setAttribute("y", String(r2(y)));
    text.setAttribute("text-anchor", anchor);
    text.setAttribute("visibility", "visible");
    plate.setAttribute("visibility", "visible");
    let b;
    try { b = text.getBBox(); }
    catch { return "retry"; }
    const box = { x: b.x - 5, y: b.y - 3, w: b.width + 10, h: b.height + 6 };
    plate.setAttribute("x", String(r2(box.x)));
    plate.setAttribute("y", String(r2(box.y)));
    plate.setAttribute("width", String(r2(box.w)));
    plate.setAttribute("height", String(r2(box.h)));
    if (box.x < 1 || box.y < 1 || box.x + box.w > vb.width - 1 || box.y + box.h > vb.height - 1) continue;
    if (obstacles.some((o) => hit(box, o, 3))) continue;
    if (placed.some((o) => hit(box, o, 4))) continue;
    placed.push(box);
    return "shown";
  }
  text.setAttribute("visibility", "hidden");
  plate.setAttribute("visibility", "hidden");
  return "hidden";
}
function tipText(cls, value) {
  const t = ns("text");
  t.setAttribute("class", cls);
  t.textContent = value;
  return t;
}
function ensureTip(svg) {
  let tip = svg.querySelector("g.tips");
  if (tip) return tip;
  tip = ns("g");
  tip.setAttribute("class", "tips");
  tip.setAttribute("id", "map-tip");
  tip.setAttribute("visibility", "hidden");
  const bg = ns("rect");
  bg.setAttribute("class", "tip-bg");
  bg.setAttribute("rx", "8");
  tip.append(bg);
  svg.append(tip);
  return tip;
}
function layoutTip(svg, tip, g) {
  const core = g.querySelector("circle.core");
  if (!core) return;
  const cx = Number(core.getAttribute("cx"));
  const cy = Number(core.getAttribute("cy"));
  const rad = Number(core.getAttribute("r")) || 4;
  let y = 16, maxW = 72;
  for (const t of tip.querySelectorAll("text")) {
    t.setAttribute("x", "10");
    t.setAttribute("y", String(y));
    try { maxW = Math.max(maxW, t.getBBox().width); } catch { /* measure after layout */ }
    y += 15;
  }
  const width = Math.ceil(maxW + 20), height = y + 6;
  const bg = tip.querySelector("rect");
  bg.setAttribute("x", "0");
  bg.setAttribute("y", "0");
  bg.setAttribute("width", String(width));
  bg.setAttribute("height", String(height));
  const vb = svg.viewBox.baseVal;
  let x = cx + rad + 10;
  let ty = cy - height / 2;
  if (x + width > vb.width - 6) x = cx - rad - 10 - width;
  if (x < 6) x = 6;
  if (ty < 6) ty = 6;
  if (ty + height > vb.height - 6) ty = Math.max(6, vb.height - 6 - height);
  const panels = panelBoxes(svg) || [];
  if (panels.some((p) => hit({ x, y: ty, w: width, h: height }, p, 2))) {
    const flip = cx - rad - 10 - width;
    if (flip > 6) x = flip;
  }
  tip.setAttribute("transform", `translate(${r2(x)} ${r2(ty)})`);
}
function showTip(svg, g) {
  activeMark = g;
  const info = parseMark(g);
  const rule = topRule(info.ips);
  const ruleText = clip(rule ? rule.name : "—", 28);
  const tip = ensureTip(svg);
  const sig = [info.city, info.events, ruleText, info.sev].join("|");
  if (tip.dataset.sig !== sig) {
    const bg = tip.querySelector("rect");
    tip.replaceChildren(bg);
    tip.append(
      tipText("tip-city", info.city || "—"),
      tipText("tip-muted", countryOf(info.city)),
      tipText("tip-line", info.events + " events"),
      tipText("tip-line", ruleText),
      tipText("tip-sev tip-sev-" + info.sev, info.sev),
    );
    tip.dataset.sig = sig;
  }
  layoutTip(svg, tip, g);
  tip.setAttribute("visibility", "visible");
}
function hideTip(svg) {
  activeMark = null;
  const tip = svg.querySelector("g.tips");
  if (tip) tip.setAttribute("visibility", "hidden");
}
function bindMark(g, svg) {
  if (g.dataset.bound) return;
  g.dataset.bound = "1";
  const enter = () => showTip(svg, g);
  const leave = () => { if (activeMark === g) hideTip(svg); };
  g.addEventListener("mouseenter", enter);
  g.addEventListener("mouseleave", leave);
  g.addEventListener("focus", enter);
  g.addEventListener("blur", leave);
}
function paintMarks(svg) {
  const map = svg.closest("#map");
  const panels = panelBoxes(svg);
  const ready = svg.getBoundingClientRect().width >= 20 && panels;
  for (const g of svg.querySelectorAll("g.marks > g.mk")) {
    const info = parseMark(g);
    const rule = topRule(info.ips);
    const label = `${info.city || "—"}, ${countryOf(info.city)}, ${info.events} events, ${rule ? rule.name : "—"}, ${info.sev}`;
    if (g.getAttribute("aria-label") !== label) g.setAttribute("aria-label", label);
    if (g.getAttribute("tabindex") !== "0") g.setAttribute("tabindex", "0");
    if (g.getAttribute("role") !== "group") g.setAttribute("role", "group");
    bindMark(g, svg);
  }
  const texts = [...svg.querySelectorAll("g.marks .ml")];
  if (!ready) {
    const n = Number(svg.dataset.placeTries || "0");
    if (svg.getBoundingClientRect().width >= 20 && n < 8 && map) {
      svg.dataset.placeTries = String(n + 1);
      requestAnimationFrame(() => enhance(map));
    }
    return;
  }
  if (svg.dataset.placeTries !== "0") svg.dataset.placeTries = "0";
  if (texts.every((t) => t.dataset.placed === "1")) return;
  const obstacles = panels.slice();
  svg.querySelectorAll("g.marks circle.core, g.hq circle.core, g.hq circle.ring").forEach((c) => obstacles.push(circleBox(c)));
  const placed = [];
  for (const text of texts) {
    if (text.dataset.placed === "1") {
      const chip = text.previousElementSibling;
      if (chip && chip.classList.contains("chip-plate") && chip.getAttribute("visibility") !== "hidden") placed.push(attrBox(chip));
      continue;
    }
    const result = placeOne(svg, text, text.parentNode.querySelector("circle.core"), obstacles, placed);
    if (result === "retry") {
      const n = Number(svg.dataset.placeTries || "0") + 1;
      svg.dataset.placeTries = String(n);
      if (n < 8 && map) requestAnimationFrame(() => enhance(map));
      return;
    }
    text.dataset.placed = "1";
  }
}
function enhance(map) {
  const svg = map.querySelector("svg.worldmap");
  if (!svg) return;
  const count = document.getElementById("map-count");
  if (count && !count.classList.contains("map-stat")) count.classList.add("map-stat");
  paintArcs(svg);
  paintMarks(svg);
  if (activeMark && !activeMark.isConnected) hideTip(svg);
  else if (activeMark && activeMark.isConnected) showTip(svg, activeMark);
}
function watch(map) {
  let frame = 0, running = false, sub = null, ro = null;
  const run = () => {
    frame = 0;
    if (!map.isConnected) {
      if (sub) sub.disconnect();
      if (ro) ro.disconnect();
      return;
    }
    if (running) return;
    running = true;
    try { enhance(map); }
    finally { running = false; }
  };
  const schedule = () => {
    if (!map.isConnected) {
      if (sub) sub.disconnect();
      if (ro) ro.disconnect();
      return;
    }
    if (frame) return;
    frame = requestAnimationFrame(run);
  };
  sub = new MutationObserver(schedule);
  sub.observe(map, { childList: true, subtree: true });
  if (typeof ResizeObserver !== "undefined") {
    ro = new ResizeObserver(() => {
      for (const t of map.querySelectorAll(".ml")) delete t.dataset.placed;
      schedule();
    });
    ro.observe(map);
  }
  loadRules(schedule);
  schedule();
}
function boot() {
  const arm = () => {
    const map = document.getElementById("map");
    if (!map || map.dataset.mapWatch === "1") return;
    map.dataset.mapWatch = "1";
    watch(map);
  };
  arm();
  new MutationObserver(arm).observe(document.documentElement, { childList: true, subtree: true });
}
if (typeof document !== "undefined") boot();
})();
