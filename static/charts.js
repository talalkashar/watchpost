"use strict";
// Watchpost charts: pure functions from data to an inline SVG string. No libraries.
// Every piece of text goes through esc(). Colors come from CSS classes (f-*, s-*, h0..h5),
// never style attributes, so the strict CSP holds and the theme lives in style.css.
// The dashboard parses these strings with DOMParser as image/svg+xml (scripts never run).

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

const n2 = (v) => (Math.round(v * 100) / 100).toString();

function svgOpen(w, h, cls, label) {
  return `<svg xmlns="http://www.w3.org/2000/svg" class="chart ${esc(cls || "")}" width="${n2(w)}" height="${n2(h)}" ` +
    `viewBox="0 0 ${n2(w)} ${n2(h)}" role="img" aria-label="${esc(label || "chart")}">`;
}

function scaleMax(values) {
  const max = Math.max(0, ...values.filter(Number.isFinite));
  return max > 0 ? max : 1;
}

function pathFrom(points) {
  return points.map(([x, y], i) => `${i ? "L" : "M"}${n2(x)} ${n2(y)}`).join("");
}

// Tiny trend line with a soft area; the last point is marked.
function sparkline(values, { w = 120, h = 28, cls = "accent", label = "trend" } = {}) {
  const vals = values.length ? values : [0];
  const max = scaleMax(vals);
  const step = vals.length > 1 ? w / (vals.length - 1) : w;
  const pts = vals.map((v, i) => [i * step, h - 2 - (Math.max(0, v) / max) * (h - 4)]);
  const [lx, ly] = pts[pts.length - 1];
  return svgOpen(w, h, "spark", label) +
    `<path class="area f-${esc(cls)}" d="${pathFrom(pts)}L${n2(w)} ${h}L0 ${h}Z"/>` +
    `<path class="stroke s-${esc(cls)}" d="${pathFrom(pts)}"/>` +
    `<circle class="f-${esc(cls)}" cx="${n2(lx)}" cy="${n2(ly)}" r="2.2"/></svg>`;
}

// Multi-series line chart. series: [{values, cls, label}], labels: x labels (first/last shown).
function line(series, { w = 400, h = 140, labels = [], label = "line chart", pad = 22 } = {}) {
  const all = series.flatMap((s) => s.values);
  const max = scaleMax(all);
  const count = Math.max(1, ...series.map((s) => s.values.length));
  const iw = w - pad - 6, ih = h - 18;
  const x = (i) => pad + (count > 1 ? (i * iw) / (count - 1) : 0);
  const y = (v) => 4 + ih - (v / max) * (ih - 4);
  let out = svgOpen(w, h, "line", label);
  for (let t = 0; t <= 2; t++) {
    const v = (max * t) / 2, yy = y(v);
    out += `<line class="grid" x1="${pad}" x2="${n2(w - 6)}" y1="${n2(yy)}" y2="${n2(yy)}"/>` +
      `<text class="tick" x="${pad - 4}" y="${n2(yy + 3)}" text-anchor="end">${esc(Math.round(v))}</text>`;
  }
  for (const s of series) {
    const pts = s.values.map((v, i) => [x(i), y(Math.max(0, v))]);
    out += `<path class="area f-${esc(s.cls)}" d="${pathFrom(pts)}L${n2(x(pts.length - 1))} ${n2(y(0))}L${pad} ${n2(y(0))}Z"/>` +
      `<path class="stroke s-${esc(s.cls)}" d="${pathFrom(pts)}"><title>${esc(s.label || "")}</title></path>`;
  }
  if (labels.length) {
    out += `<text class="tick" x="${pad}" y="${h - 3}">${esc(labels[0])}</text>` +
      `<text class="tick" x="${n2(w - 6)}" y="${h - 3}" text-anchor="end">${esc(labels[labels.length - 1])}</text>`;
  }
  return out + "</svg>";
}

// Simple vertical bars. values: numbers; titles: optional per-bar tooltip text.
function bars(values, { w = 300, h = 100, cls = "accent", titles = [], label = "bar chart" } = {}) {
  const max = scaleMax(values);
  const bw = w / Math.max(1, values.length);
  let out = svgOpen(w, h, "bars", label);
  values.forEach((v, i) => {
    const bh = (Math.max(0, v) / max) * (h - 2);
    out += `<rect class="f-${esc(cls)}" x="${n2(i * bw + 1)}" y="${n2(h - bh)}" width="${n2(Math.max(1, bw - 2))}" height="${n2(bh)}">` +
      `<title>${esc(titles[i] ?? v)}</title></rect>`;
  });
  return out + "</svg>";
}

// Stacked bars with an optional overlay line (e.g. event volume on its own scale).
// bins: [{...}], keys: stacking order bottom-up, each key maps to class f-<key>.
function stackedBars(bins, keys, { w = 400, h = 150, overlay = null, labels = [], title = null, label = "stacked bars" } = {}) {
  const pad = 22, top = 6, bottom = 16;
  const ih = h - top - bottom, iw = w - pad - 4;
  const totals = bins.map((b) => keys.reduce((sum, k) => sum + (b[k] || 0), 0));
  const max = scaleMax(totals);
  const bw = iw / Math.max(1, bins.length);
  let out = svgOpen(w, h, "stacked", label);
  for (let t = 0; t <= 2; t++) {
    const v = Math.round((max * t) / 2), yy = top + ih - (v / max) * ih;
    out += `<line class="grid" x1="${pad}" x2="${n2(w - 4)}" y1="${n2(yy)}" y2="${n2(yy)}"/>` +
      `<text class="tick" x="${pad - 4}" y="${n2(yy + 3)}" text-anchor="end">${esc(v)}</text>`;
  }
  if (overlay && overlay.length) {
    const omax = scaleMax(overlay);
    const pts = overlay.map((v, i) => [pad + i * bw + bw / 2, top + ih - (Math.max(0, v) / omax) * ih * 0.9]);
    out += `<path class="area f-volume" d="${pathFrom(pts)}L${n2(pts[pts.length - 1][0])} ${top + ih}L${n2(pts[0][0])} ${top + ih}Z"/>` +
      `<path class="stroke s-volume" d="${pathFrom(pts)}"/>`;
  }
  bins.forEach((b, i) => {
    let y = top + ih;
    const x = pad + i * bw + 1.5, width = Math.max(1, bw - 3);
    const tip = title ? title(b, i) : String(totals[i]);
    if (!totals[i]) out += `<rect class="empty" x="${n2(x)}" y="${n2(top + ih - 1)}" width="${n2(width)}" height="1"/>`;
    for (const k of keys) {
      const v = b[k] || 0;
      if (!v) continue;
      const bh = (v / max) * ih;
      y -= bh;
      out += `<rect class="f-${esc(k)}" x="${n2(x)}" y="${n2(y)}" width="${n2(width)}" height="${n2(Math.max(1, bh - 0.5))}"><title>${esc(tip)}</title></rect>`;
    }
  });
  if (labels.length) {
    const mid = Math.floor(labels.length / 2);
    out += `<text class="tick" x="${pad}" y="${h - 3}">${esc(labels[0])}</text>` +
      `<text class="tick" x="${n2(pad + iw / 2)}" y="${h - 3}" text-anchor="middle">${esc(labels[mid])}</text>` +
      `<text class="tick" x="${n2(w - 4)}" y="${h - 3}" text-anchor="end">${esc(labels[labels.length - 1])}</text>`;
  }
  return out + "</svg>";
}

// Horizontal ranked bars. rows: [{label, sub, value, cls, tag}]
function clip(text, chars) {
  const s = String(text ?? "");
  return s.length > chars ? `${s.slice(0, Math.max(1, chars - 1))}…` : s;
}

function hbars(rows, { w = 300, rowH = 22, labelW = 118, label = "ranking" } = {}) {
  const fit = Math.floor(labelW / 6.7), fitSub = Math.floor(labelW / 5.2);
  const h = Math.max(rowH, rows.length * rowH);
  const max = scaleMax(rows.map((r) => r.value));
  const trackX = labelW + 6, trackW = Math.max(20, w - trackX - 40);
  let out = svgOpen(w, h, "hbars", label);
  rows.forEach((r, i) => {
    const y = i * rowH;
    const bw = (Math.max(0, r.value) / max) * trackW;
    out += `<g class="hrow"><title>${esc(r.title ?? `${r.label}: ${r.value}`)}</title>` +
      `<text class="hl" x="0" y="${n2(y + (r.sub ? 9 : 14))}">${esc(clip(r.label, fit))}</text>` +
      (r.sub ? `<text class="hs${r.subCls ? " " + esc(r.subCls) : ""}" x="0" y="${n2(y + 19)}">${esc(clip(r.sub, fitSub))}</text>` : "") +
      `<rect class="track" x="${trackX}" y="${n2(y + 7)}" width="${n2(trackW)}" height="7"/>` +
      `<rect class="f-${esc(r.cls || "accent")}" x="${trackX}" y="${n2(y + 7)}" width="${n2(Math.max(1.5, bw))}" height="7"/>` +
      `<text class="hv" x="${n2(w)}" y="${n2(y + 14)}" text-anchor="end">${esc(r.value)}</text></g>`;
  });
  return out + "</svg>";
}

// ATT&CK-style heat matrix. columns: [{name, short, cells: [{id, name, value, covered, rules}]}]
// value -> heat class h0..h5 on a log-ish scale; uncovered cells are drawn hollow.
function heatMatrix(columns, { w = 700, cellH = 22, headH = 30, maxRows = 8, label = "coverage matrix" } = {}) {
  const cols = Math.max(1, columns.length);
  const cw = w / cols;
  const rows = Math.min(maxRows, Math.max(1, ...columns.map((c) => c.cells.length)));
  const h = headH + rows * (cellH + 3);
  const max = scaleMax(columns.flatMap((c) => c.cells.map((x) => x.value || 0)));
  const level = (v) => (!v ? 0 : Math.min(5, 1 + Math.floor((Math.log(v + 1) / Math.log(max + 1)) * 4.999)));
  let out = svgOpen(w, h, "heat", label);
  columns.forEach((c, ci) => {
    const x = ci * cw;
    const hits = c.cells.reduce((s, x2) => s + (x2.value || 0), 0);
    out += `<text class="th" x="${n2(x + 3)}" y="11">${esc(c.short || c.name)}<title>${esc(c.name)}</title></text>` +
      `<text class="tc${hits ? " hot" : ""}" x="${n2(x + 3)}" y="23">${esc(c.cells.length)} tech · ${esc(hits)}</text>`;
    for (let r = 0; r < rows; r++) {
      const cell = c.cells[r];
      const y = headH + r * (cellH + 3);
      if (!cell) {
        out += `<rect class="cell void" x="${n2(x + 1.5)}" y="${n2(y)}" width="${n2(cw - 3)}" height="${cellH}"/>`;
        continue;
      }
      const lv = cell.covered === false ? "gap" : `h${level(cell.value || 0)}`;
      const tip = `${cell.id} ${cell.name || ""}\n${c.name}\n${cell.value || 0} hits` + (cell.level ? `\nlevel: ${cell.level}` : "") +
        (cell.rules && cell.rules.length ? `\nrules: ${cell.rules.join(", ")}` : "\nno rule covers this");
      out += `<g class="cellg"><title>${esc(tip)}</title>` +
        `<rect class="cell ${lv}" x="${n2(x + 1.5)}" y="${n2(y)}" width="${n2(cw - 3)}" height="${cellH}"/>` +
        `<text class="cid ${lv}" x="${n2(x + 4)}" y="${n2(y + cellH / 2 + 3.2)}">${esc(cell.id)}</text>` +
        (cell.value ? `<text class="cv ${lv}" x="${n2(x + cw - 4)}" y="${n2(y + cellH / 2 + 3.2)}" text-anchor="end">${esc(cell.value)}</text>` : "") +
        `</g>`;
    }
  });
  return out + "</svg>";
}

globalThis.WPCharts = Object.freeze({ esc, clip, sparkline, line, bars, stackedBars, hbars, heatMatrix });
