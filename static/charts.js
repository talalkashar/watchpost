"use strict";
// Watchpost charts: render data as inline SVG strings. No libraries.
// Every piece of text goes through esc(). Colors come from CSS classes (f-*, s-*, h0..h5),
// never style attributes, so the strict CSP holds and the theme lives in style.css.
// The dashboard parses these strings with DOMParser as image/svg+xml (scripts never run).

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const n2 = (v) => (Math.round(num(v) * 100) / 100).toString();

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
  const vals = (values.length ? values : [0]).map((v) => Math.max(0, num(v)));
  const max = scaleMax(vals);
  const step = vals.length > 1 ? w / (vals.length - 1) : w;
  const pts = vals.map((v, i) => [i * step, h - 2 - (v / max) * (h - 4)]);
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
  const y = (v) => 4 + ih - (Math.max(0, num(v)) / max) * (ih - 4);
  let out = svgOpen(w, h, "line", label);
  for (let t = 0; t <= 2; t++) {
    const v = (max * t) / 2, yy = y(v);
    out += `<line class="grid" x1="${pad}" x2="${n2(w - 6)}" y1="${n2(yy)}" y2="${n2(yy)}"/>` +
      `<text class="tick" x="${pad - 4}" y="${n2(yy + 3)}" text-anchor="end">${esc(Math.round(v))}</text>`;
  }
  for (const s of series) {
    const pts = s.values.map((v, i) => [x(i), y(v)]);
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
    const bh = (Math.max(0, num(v)) / max) * (h - 2);
    out += `<rect class="f-${esc(cls)}" x="${n2(i * bw + 1)}" y="${n2(h - bh)}" width="${n2(Math.max(1, bw - 2))}" height="${n2(bh)}">` +
      `<title>${esc(titles[i] ?? v)}</title></rect>`;
  });
  return out + "</svg>";
}

// Stacked bars with an optional overlay line (e.g. event volume on its own scale).
// bins: [{...}], keys: stacking order bottom-up, each key maps to class f-<key>.
function stackedBars(bins, keys, { w = 400, h = 150, overlay = null, labels = [], title = null, label = "stacked bars" } = {}) {
  const pad = 30, top = 8, bottom = 18;
  const ih = h - top - bottom, iw = w - pad - 4;
  const totals = bins.map((b) => keys.reduce((sum, k) => sum + Math.max(0, num(b[k])), 0));
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
    const pts = overlay.map((v, i) => [pad + i * bw + bw / 2, top + ih - (Math.max(0, num(v)) / omax) * ih * 0.9]);
    out += `<path class="area f-volume" d="${pathFrom(pts)}L${n2(pts[pts.length - 1][0])} ${top + ih}L${n2(pts[0][0])} ${top + ih}Z"/>` +
      `<path class="stroke s-volume" d="${pathFrom(pts)}"/>`;
  }
  bins.forEach((b, i) => {
    let y = top + ih;
    const x = pad + i * bw + 1.5, width = Math.max(1, bw - 3);
    const tip = title ? title(b, i) : String(totals[i]);
    if (!totals[i]) out += `<rect class="empty" x="${n2(x)}" y="${n2(top + ih - 1)}" width="${n2(width)}" height="1"/>`;
    for (const k of keys) {
      const v = Math.max(0, num(b[k]));
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
  const fit = Math.floor(labelW / 7.2), fitSub = Math.floor(labelW / 6.4);
  const h = Math.max(rowH, rows.length * rowH);
  const max = scaleMax(rows.map((r) => r.value));
  const trackX = labelW + 6, trackW = Math.max(20, w - trackX - 40);
  const barH = 8;
  let out = svgOpen(w, h, "hbars", label);
  rows.forEach((r, i) => {
    const y = i * rowH;
    const mid = y + rowH / 2;
    const bw = (Math.max(0, num(r.value)) / max) * trackW;
    const labelY = r.sub ? y + rowH * 0.40 : mid + 4;
    out += `<g class="hrow"><title>${esc(r.title ?? `${r.label}: ${r.value}`)}</title>` +
      `<text class="hl" x="0" y="${n2(labelY)}">${esc(clip(r.label, fit))}</text>` +
      (r.sub ? `<text class="hs${r.subCls ? " " + esc(r.subCls) : ""}" x="0" y="${n2(y + rowH * 0.84)}">${esc(clip(r.sub, fitSub))}</text>` : "") +
      `<rect class="track" x="${trackX}" y="${n2(mid - barH / 2)}" width="${n2(trackW)}" height="${barH}"/>` +
      `<rect class="f-${esc(r.cls || "accent")}" x="${trackX}" y="${n2(mid - barH / 2)}" width="${n2(bw > 0 ? Math.max(1.5, bw) : 0)}" height="${barH}"/>` +
      `<text class="hv" x="${n2(w)}" y="${n2(mid + 4)}" text-anchor="end">${esc(r.value)}</text></g>`;
  });
  return out + "</svg>";
}

// ATT&CK-style heat matrix. columns: [{name, short, cells: [{id, name, value, covered, level, rules}]}]
// A validated technique (or a cell with no level, when covered is not false) uses heat class h0..h5
// from its hit count. mapped, disabled, and gap keep their own classes so a mapped technique is not
// drawn as a gap. Cells past maxRows are named in a "+N" caption instead of disappearing.
const LEVEL_TIP = {
  validated: "validated on a labeled test scenario",
  mapped: "mapped only; no labeled scenario proves detection",
  disabled: "only disabled rules map here",
  gap: "no rule maps here",
};
function cellClass(cell, heat) {
  const crit = cell.crit ? " crit" : "";
  if (cell.level === "mapped" || cell.level === "disabled" || cell.level === "gap") return cell.level + crit;
  if (cell.level === "validated" || cell.covered !== false) return `h${heat}` + crit;
  return "gap" + crit;
}
function heatMatrix(columns, { w = 700, cellH = 22, headH = 30, maxRows = 8, label = "coverage matrix" } = {}) {
  const list = columns.length ? columns : [{ name: "", short: "", cells: [] }];
  const any = list.some((c) => c.cells.length);
  // The dashboard supplies a scrollable minimum width. Desktop layout uses the
  // actual box width so the SVG can wrap tactics without shrinking its text.
  const desktopWidth = globalThis.matchMedia?.("(min-width: 1101px)").matches
    && Math.floor(document.getElementById("attack-chart")?.getBoundingClientRect().width || 0);
  const hits = list.map((c) => c.cells.reduce((sum, cell) => sum + (cell.value || 0), 0));
  const summaries = list.map((c, i) => `${c.cells.length} tech · ${hits[i]}`);
  // 84px fits the tactic headers. Allow 7px per 11px monospace character
  // plus insets so larger counts still fit alongside the technique ID.
  const minColumn = Math.max(84, ...summaries.map((s) => 6 + 7 * s.length),
    ...list.flatMap((c) => c.cells.map((cell) => 10 + 7 * (String(cell.id).length + String(cell.value || "").length))));
  const capacity = desktopWidth ? Math.max(1, Math.floor(desktopWidth / minColumn)) : list.length;
  const bands = Math.ceil(list.length / capacity);
  const perRow = Math.ceil(list.length / bands);
  const cw = desktopWidth ? desktopWidth / perRow : Math.max(90, w / list.length);
  const rows = Math.min(maxRows, Math.max(1, ...list.map((c) => c.cells.length || 1)));
  const overflow = list.some((c) => c.cells.length > rows);
  const h = headH + rows * (cellH + 3) + (overflow ? 12 : 0);
  const max = scaleMax(list.flatMap((c) => c.cells.map((x) => x.value || 0)));
  const heatOf = (v) => { const n = num(v); return n <= 0 ? 0 : Math.min(5, 1 + Math.floor((Math.log(n + 1) / Math.log(max + 1)) * 4.999)); };
  const bandGap = 8;
  let out = svgOpen(cw * perRow, bands * h + (bands - 1) * bandGap, "heat", label);
  list.forEach((c, i) => {
    const x = (i % perRow) * cw;
    const yOffset = Math.floor(i / perRow) * (h + bandGap);
    out += `<svg class="tactic" x="${n2(x)}" y="${n2(yOffset)}" width="${n2(cw)}" height="${h}">`;
    const quiet = any && !c.cells.length;
    const hidden = c.cells.slice(rows);
    const headTip = hidden.length ? `${c.name}\nnot shown: ${hidden.map((cell) => cell.id).join(", ")}` : c.name;
    out += `<text class="th${quiet ? " quiet" : ""}" x="3" y="12">${esc(c.short || c.name)}<title>${esc(headTip)}</title></text>` +
      `<text class="tc${hits[i] ? " hot" : ""}${quiet ? " quiet" : ""}" x="3" y="25">${esc(summaries[i])}</text>`;
    if (!quiet) {
      for (let r = 0; r < rows; r++) {
        const cell = c.cells[r];
        const y = headH + r * (cellH + 3);
        if (!cell) {
          out += `<rect class="cell void" x="1.5" y="${n2(y)}" width="${n2(Math.max(1, cw - 3))}" height="${cellH}"/>`;
          continue;
        }
        const lv = cellClass(cell, heatOf(cell.value || 0));
        const tip = `${cell.id} ${cell.name || ""}\n${c.name}\n${cell.value || 0} hits` +
          (LEVEL_TIP[cell.level] ? `\n${LEVEL_TIP[cell.level]}` : "") +
          (cell.rules && cell.rules.length ? `\nrules: ${cell.rules.join(", ")}` : "\nno rule covers this");
        out += `<g class="cellg"><title>${esc(tip)}</title>` +
          `<rect class="cell ${lv}" x="1.5" y="${n2(y)}" width="${n2(Math.max(1, cw - 3))}" height="${cellH}"/>` +
          `<text class="cid ${lv}" x="4" y="${n2(y + cellH / 2 + 3.2)}">${esc(cell.id)}</text>` +
          (cell.value ? `<text class="cv ${lv}" x="${n2(cw - 4)}" y="${n2(y + cellH / 2 + 3.2)}" text-anchor="end">${esc(cell.value)}</text>` : "") +
          `</g>`;
      }
      if (hidden.length) {
        out += `<text class="more" x="3" y="${n2(headH + rows * (cellH + 3) + 10)}">+${hidden.length}` +
          `<title>${esc(hidden.map((cell) => cell.id).join(", "))}</title></text>`;
      }
    }
    out += "</svg>";
  });
  return out + "</svg>";
}

globalThis.WPCharts = Object.freeze({ esc, clip, sparkline, line, bars, stackedBars, hbars, heatMatrix });
