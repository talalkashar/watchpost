"use strict";
// Watchpost charts: render data as inline SVG strings. No libraries.
// Every piece of text goes through esc(). Colors come from CSS classes (f-*, s-*, h0..h5),
// never style attributes, so the strict CSP holds and the theme lives in style.css.
// The dashboard parses these strings with DOMParser as image/svg+xml (scripts never run).

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

const n2 = (v) => (Math.round(v * 100) / 100).toString();

// Chart fills must use the same f-* / s-* classes as the rest of the console.
// Aliases collapse onto those names so a "crit" series cannot pick up a different color.
const SEVERITY_TONE = { critical: "critical", crit: "critical", high: "high", medium: "medium", med: "medium", low: "low", info: "info" };
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
let chartSeq = 0;

function tone(cls) {
  const key = String(cls || "accent").toLowerCase();
  return SEVERITY_TONE[key] || key;
}

function bySeverity(names) {
  return names.slice().sort((a, b) => {
    const ia = SEVERITY_ORDER.indexOf(tone(a));
    const ib = SEVERITY_ORDER.indexOf(tone(b));
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
}

// Keep a count that is already written as its own number. "12 events" contains 12; "T1190" does not contain 1.
function withCount(text, value) {
  const n = Number.isFinite(Number(value)) ? String(value) : "0";
  const base = text == null || String(text).trim() === "" ? n : String(text);
  const needle = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^\\d.])${needle}([^\\d]|$)`).test(base) ? base : `${base}: ${n}`;
}

function legendMarkup(items, x, y, maxW) {
  let cursor = x;
  let out = "";
  for (const item of items) {
    const textW = Math.ceil(String(item.text).length * 6.4);
    const sw = item.cls ? (item.line ? 14 : 12) : 0;
    const need = sw + textW + 8;
    if (cursor > x && cursor + need > x + maxW) break;
    if (item.line) {
      out += `<line class="stroke s-${esc(item.cls)}" x1="${n2(cursor)}" x2="${n2(cursor + 10)}" y1="${n2(y + 4)}" y2="${n2(y + 4)}"/>`;
      cursor += 14;
    } else if (item.cls) {
      out += `<rect class="f-${esc(item.cls)}" x="${n2(cursor)}" y="${n2(y)}" width="8" height="8"/>`;
      cursor += 12;
    }
    out += `<text class="tick" x="${n2(cursor)}" y="${n2(y + 8)}">${esc(item.text)}</text>`;
    cursor += textW + 8;
  }
  return out;
}

function svgOpen(w, h, cls, label, detail) {
  const name = label || "chart";
  const descId = detail ? `wpcd-${++chartSeq}` : "";
  const described = descId ? ` aria-describedby="${descId}"` : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" class="chart ${esc(cls || "")}" width="${n2(w)}" height="${n2(h)}" ` +
    `viewBox="0 0 ${n2(w)} ${n2(h)}" role="img" aria-label="${esc(name)}"${described}>` +
    `<title>${esc(name)}</title>` +
    (detail ? `<desc id="${descId}">${esc(detail)}</desc>` : "");
}

function scaleMax(values) {
  const max = Math.max(0, ...values.filter(Number.isFinite));
  return max > 0 ? max : 1;
}

function pathFrom(points) {
  return points.map(([x, y], i) => `${i ? "L" : "M"}${n2(x)} ${n2(y)}`).join("");
}

// Tiny trend line with a soft area; the last point is marked.
// The accessible name always carries latest and peak, and the hover text lists every count.
function sparkline(values, { w = 120, h = 28, cls = "accent", label = "trend" } = {}) {
  const nums = (values.length ? values : [0]).map((v) => (Number.isFinite(v) ? Math.max(0, v) : 0));
  const max = scaleMax(nums);
  const step = nums.length > 1 ? w / (nums.length - 1) : w;
  const pts = nums.map((v, i) => [i * step, h - 2 - (v / max) * (h - 4)]);
  const [lx, ly] = pts[pts.length - 1];
  const latest = nums[nums.length - 1];
  const peak = Math.max(...nums);
  const summary = `latest ${latest}, peak ${peak}`;
  const named = label && label !== "trend" && /\d/.test(label) ? label : `${label && label !== "trend" ? label : "sparkline"}, ${summary}`;
  const detail = `${nums.length} points, ${summary}, counts ${nums.join(", ")}`;
  const toneCls = tone(cls);
  return svgOpen(w, h, "spark", named, detail) +
    `<path class="area f-${esc(toneCls)}" d="${pathFrom(pts)}L${n2(w)} ${h}L0 ${h}Z"/>` +
    `<path class="stroke s-${esc(toneCls)}" d="${pathFrom(pts)}"><title>${esc(detail)}</title></path>` +
    `<circle class="f-${esc(toneCls)}" cx="${n2(lx)}" cy="${n2(ly)}" r="2.2"><title>${esc(`latest ${latest}`)}</title></circle></svg>`;
}

// Multi-series line chart. series: [{values, cls, label}], labels: x labels (first/mid/last shown).
function line(series, { w = 400, h = 140, labels = [], label = "line chart", pad = 22, yLabel = "count" } = {}) {
  const items = series.length ? series : [{ values: [0], cls: "accent", label: "series" }];
  const finite = (v) => (Number.isFinite(v) ? Math.max(0, v) : 0);
  const all = items.flatMap((s) => s.values.map(finite));
  const max = scaleMax(all);
  const count = Math.max(1, ...items.map((s) => s.values.length));
  const legendH = 16, bottom = 18, axisPad = Math.max(pad, 36), right = 8, top = 4 + legendH;
  const iw = Math.max(4, w - axisPad - right), ih = Math.max(4, h - top - bottom);
  const x = (i) => axisPad + (count > 1 ? (i * iw) / (count - 1) : 0);
  const y = (v) => top + ih - (finite(v) / max) * ih;
  const named = label && label !== "line chart" ? label
    : `line chart, ${items.map((s) => `${s.label || "series"} peak ${Math.max(0, ...s.values.map(finite))}`).join(", ")}`;
  const detail = items.map((s) => `${s.label || "series"}: ${s.values.map((v, i) => `${labels[i] ? `${labels[i]} ` : ""}${finite(v)}`).join(", ")}`).join("; ");
  let out = svgOpen(w, h, "line", named, `${yLabel} on the vertical axis. ${detail}`);
  out += legendMarkup([{ text: yLabel }, ...items.map((s, i) => ({ cls: tone(s.cls), text: s.label || `series ${i + 1}` }))], 2, 2, w - 4);
  for (let t = 0; t <= 2; t++) {
    const v = Math.round((max * t) / 2), yy = y(v);
    out += `<line class="grid" x1="${axisPad}" x2="${n2(w - right)}" y1="${n2(yy)}" y2="${n2(yy)}"/>` +
      `<text class="tick" x="${axisPad - 4}" y="${n2(yy + 3)}" text-anchor="end">${esc(v)}</text>`;
  }
  for (const s of items) {
    if (!s.values.length) continue;
    const toneCls = tone(s.cls);
    const name = s.label || "series";
    const pts = s.values.map((v, i) => [x(i), y(v)]);
    const last = pts.length - 1;
    out += `<path class="area f-${esc(toneCls)}" d="${pathFrom(pts)}L${n2(pts[last][0])} ${n2(y(0))}L${n2(pts[0][0])} ${n2(y(0))}Z"/>` +
      `<path class="stroke s-${esc(toneCls)}" d="${pathFrom(pts)}"><title>${esc(`${name}: ${s.values.map(finite).join(", ")}`)}</title></path>`;
    s.values.forEach((v, i) => {
      const when = labels[i] || `point ${i + 1}`;
      out += `<circle class="f-${esc(toneCls)}" cx="${n2(pts[i][0])}" cy="${n2(pts[i][1])}" r="2.6">` +
        `<title>${esc(`${name}, ${when}: ${finite(v)}`)}</title></circle>`;
    });
  }
  if (labels.length) {
    out += `<text class="tick" x="${axisPad}" y="${h - 3}">${esc(labels[0])}</text>`;
    if (labels.length > 2) out += `<text class="tick" x="${n2(axisPad + iw / 2)}" y="${h - 3}" text-anchor="middle">${esc(labels[Math.floor(labels.length / 2)])}</text>`;
    if (labels.length > 1) out += `<text class="tick" x="${n2(w - right)}" y="${h - 3}" text-anchor="end">${esc(labels[labels.length - 1])}</text>`;
  }
  return out + "</svg>";
}

// Simple vertical bars. values: numbers; titles: optional per-bar tooltip text.
// labels, when passed, are the x-axis captions. The y-axis is the count.
function bars(values, { w = 300, h = 100, cls = "accent", titles = [], labels = [], label = "bar chart", yLabel = "count" } = {}) {
  const nums = values.map((v) => (Number.isFinite(v) ? Math.max(0, v) : 0));
  const max = scaleMax(nums);
  const toneCls = tone(cls);
  const legendH = 14, bottom = 16, pad = 36, top = 4 + legendH;
  const plotH = Math.max(4, h - top - bottom);
  const plotW = Math.max(4, w - pad - 4);
  const bw = plotW / Math.max(1, nums.length);
  const total = nums.reduce((sum, v) => sum + v, 0);
  const peak = nums.length ? Math.max(...nums) : 0;
  const named = label && label !== "bar chart" ? label : `bar chart, total ${total}, peak ${peak}`;
  const caption = (i) => labels[i] || titles[i] || String(i + 1);
  const detail = nums.map((v, i) => `${caption(i)} ${v}`).join(", ");
  let out = svgOpen(w, h, "bars", named, `${yLabel}. ${detail}`);
  const swatch = toneCls === "accent" ? "value" : toneCls;
  out += legendMarkup([{ text: yLabel }, { cls: toneCls, text: swatch }], 2, 2, w - 4);
  for (let t = 0; t <= 2; t++) {
    const v = Math.round((max * t) / 2);
    const yy = top + plotH - (v / max) * plotH;
    out += `<line class="grid" x1="${pad}" x2="${n2(w - 4)}" y1="${n2(yy)}" y2="${n2(yy)}"/>` +
      `<text class="tick" x="${pad - 4}" y="${n2(yy + 3)}" text-anchor="end">${esc(v)}</text>`;
  }
  nums.forEach((v, i) => {
    const bh = v ? (v / max) * plotH : 1;
    const y = top + plotH - bh;
    out += `<rect class="${v ? `f-${esc(toneCls)}` : "empty"}" x="${n2(pad + i * bw + 1)}" y="${n2(y)}" width="${n2(Math.max(1, bw - 2))}" height="${n2(bh)}">` +
      `<title>${esc(withCount(caption(i), v))}</title></rect>`;
  });
  const xAt = (i) => pad + i * bw;
  const tick = (i, anchor, x) => `<text class="tick" x="${n2(x)}" y="${n2(h - 3)}" text-anchor="${anchor}">${esc(clip(caption(i), 8))}</text>`;
  if (nums.length && nums.length <= 4) nums.forEach((_, i) => { out += tick(i, "middle", xAt(i) + bw / 2); });
  else if (nums.length) {
    out += tick(0, "start", pad);
    if (nums.length > 2) out += tick(Math.floor(nums.length / 2), "middle", pad + plotW / 2);
    out += tick(nums.length - 1, "end", w - 4);
  }
  return out + "</svg>";
}

// Stacked bars with an optional overlay line (event volume on its own scale).
// bins: [{...}], keys: stacking order bottom-up. Fill class is f-<severity>, not the raw key,
// so crit/med still use the console severity colors. Left axis is the stack; right axis is the overlay.
function stackedBars(bins, keys, { w = 400, h = 150, overlay = null, labels = [], title = null, label = "stacked bars" } = {}) {
  const dual = Boolean(overlay && overlay.length);
  const legendH = 16, bottom = labels.length ? 18 : 8, padL = 36, padR = dual ? 36 : 6, top = 4 + legendH;
  const ih = Math.max(8, h - top - bottom), iw = Math.max(8, w - padL - padR);
  const totals = bins.map((b) => keys.reduce((sum, k) => sum + (b[k] || 0), 0));
  const max = scaleMax(totals);
  const bw = iw / Math.max(1, bins.length);
  const when = (i) => labels[i] || `bucket ${i + 1}`;
  const exact = (b, i) => keys.map((k) => `${tone(k)} ${b[k] || 0}`).join(", ") + (dual ? `, events ${overlay[i] || 0}` : "");
  const totalAlerts = totals.reduce((sum, n) => sum + n, 0);
  const named = label && label !== "stacked bars" ? label : `stacked bars, ${totalAlerts} alerts` + (dual ? `, ${overlay.reduce((sum, n) => sum + (n || 0), 0)} events` : "");
  const detail = `Left axis is alert counts.${dual ? " Right axis is events on a separate scale." : ""} ` +
    bins.map((b, i) => `${when(i)}: ${exact(b, i)}`).join("; ");
  let out = svgOpen(w, h, "stacked", named, detail);
  const legend = [{ text: "alerts" }];
  if (dual) legend.push({ cls: "volume", line: true, text: "events" });
  for (const k of bySeverity(keys)) legend.push({ cls: tone(k), text: tone(k) });
  out += legendMarkup(legend, 2, 2, w - 4);
  for (let t = 0; t <= 2; t++) {
    const v = Math.round((max * t) / 2), yy = top + ih - (v / max) * ih;
    out += `<line class="grid" x1="${padL}" x2="${n2(w - padR)}" y1="${n2(yy)}" y2="${n2(yy)}"/>` +
      `<text class="tick" x="${padL - 4}" y="${n2(yy + 3)}" text-anchor="end">${esc(v)}</text>`;
  }
  let pts = [];
  if (dual) {
    const omax = scaleMax(overlay);
    for (let t = 0; t <= 2; t++) {
      const v = Math.round((omax * t) / 2), yy = top + ih - (t / 2) * ih;
      out += `<text class="tick" x="${n2(w - 2)}" y="${n2(yy + 3)}" text-anchor="end">${esc(v)}</text>`;
    }
    pts = overlay.map((v, i) => [padL + i * bw + bw / 2, top + ih - (Math.max(0, v) / omax) * ih]);
    out += `<path class="area f-volume" d="${pathFrom(pts)}L${n2(pts[pts.length - 1][0])} ${n2(top + ih)}L${n2(pts[0][0])} ${n2(top + ih)}Z"/>`;
  }
  bins.forEach((b, i) => {
    let y = top + ih;
    const x = padL + i * bw + 1.5, width = Math.max(1, bw - 3);
    const custom = title ? String(title(b, i)) : "";
    const bucket = custom || `${when(i)}: ${exact(b, i)}`;
    if (!totals[i]) {
      out += `<rect class="empty" x="${n2(x)}" y="${n2(top + ih - 1)}" width="${n2(width)}" height="1"><title>${esc(withCount(bucket, 0))}</title></rect>`;
    }
    for (const k of keys) {
      const v = b[k] || 0;
      if (!v) continue;
      const bh = (v / max) * ih;
      y -= bh;
      const head = `${tone(k)}: ${v}`;
      const tip = custom ? (custom.includes(head) ? custom : `${head}\n${custom}`) : `${when(i)}: ${exact(b, i)}`;
      out += `<rect class="f-${esc(tone(k))}" x="${n2(x)}" y="${n2(y)}" width="${n2(width)}" height="${n2(Math.max(1, bh - 0.5))}"><title>${esc(tip)}</title></rect>`;
    }
  });
  if (dual) {
    out += `<path class="stroke s-volume" d="${pathFrom(pts)}"><title>${esc(`events: ${overlay.map((v, i) => `${when(i)} ${v || 0}`).join(", ")}`)}</title></path>`;
    pts.forEach(([px, py], i) => {
      out += `<circle class="f-volume" cx="${n2(px)}" cy="${n2(py)}" r="2.4"><title>${esc(`${when(i)}: ${overlay[i] || 0} events`)}</title></circle>`;
    });
  }
  if (labels.length) {
    const mid = Math.floor(labels.length / 2);
    out += `<text class="tick" x="${padL}" y="${h - 3}">${esc(labels[0])}</text>` +
      `<text class="tick" x="${n2(padL + iw / 2)}" y="${h - 3}" text-anchor="middle">${esc(labels[mid])}</text>` +
      `<text class="tick" x="${n2(w - padR)}" y="${h - 3}" text-anchor="end">${esc(labels[labels.length - 1])}</text>`;
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
  const present = SEVERITY_ORDER.filter((s) => rows.some((r) => tone(r.cls || "") === s));
  const legendH = present.length ? 14 : 0;
  const body = Math.max(rowH, rows.length * rowH);
  // A full attacker list stays inside the panel, so the legend is squeezed in when each
  // row still has 20px. A short list would be crushed, and the panel has room, so grow.
  const squeeze = rows.length && (body - legendH) / rows.length >= 20;
  const h = legendH && !squeeze ? body + legendH : body;
  const step = rows.length ? (h - legendH) / rows.length : rowH;
  const max = scaleMax(rows.map((r) => r.value));
  const trackX = labelW + 6, trackW = Math.max(20, w - trackX - 40);
  const barH = 8;
  const named = label && label !== "ranking" ? label : `ranking, ${rows.map((r) => `${r.label} ${r.value}`).join(", ")}`;
  const detail = rows.map((r) => {
    const sev = tone(r.cls || "");
    return `${r.label}: ${Number.isFinite(Number(r.value)) ? r.value : 0}${SEVERITY_ORDER.includes(sev) ? ` ${sev}` : ""}`;
  }).join("; ");
  let out = svgOpen(w, h, "hbars", named, detail ? `count. ${detail}` : "count");
  if (legendH) {
    out += legendMarkup(present.map((s) => ({ cls: s, text: s })), 0, 1, Math.max(40, w - 48));
    out += `<text class="tick" x="${n2(w)}" y="11" text-anchor="end">count</text>`;
  }
  rows.forEach((r, i) => {
    const y = legendH + i * step;
    const mid = y + step / 2;
    const bw = (Math.max(0, r.value) / max) * trackW;
    const labelY = legendH ? (r.sub ? y + step * 0.38 : mid + 4) : (r.sub ? y + rowH * 0.40 : mid + 4);
    const subY = legendH ? y + step * 0.86 : y + rowH * 0.84;
    const sev = tone(r.cls || "");
    let tip = withCount(r.title ?? `${r.label}: ${r.value}`, r.value);
    if (SEVERITY_ORDER.includes(sev) && !tip.toLowerCase().includes(sev)) tip = `${tip} (${sev})`;
    out += `<g class="hrow"><title>${esc(tip)}</title>` +
      `<text class="hl" x="0" y="${n2(labelY)}">${esc(clip(r.label, fit))}</text>` +
      (r.sub ? `<text class="hs${r.subCls ? " " + esc(r.subCls) : ""}" x="0" y="${n2(subY)}">${esc(clip(r.sub, fitSub))}</text>` : "") +
      `<rect class="track" x="${trackX}" y="${n2(mid - barH / 2)}" width="${n2(trackW)}" height="${barH}"/>` +
      `<rect class="f-${esc(tone(r.cls || "accent"))}" x="${trackX}" y="${n2(mid - barH / 2)}" width="${n2(Math.max(1.5, bw))}" height="${barH}"/>` +
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
  const heatOf = (v) => (!v ? 0 : Math.min(5, 1 + Math.floor((Math.log(v + 1) / Math.log(max + 1)) * 4.999)));
  const bandGap = 8;
  const hitTotal = hits.reduce((sum, n) => sum + n, 0);
  const named = label && label !== "coverage matrix" ? label : `coverage matrix, ${list.length} tactics, ${hitTotal} hits`;
  const detail = list.map((c, i) => {
    const cells = c.cells.map((cell) => `${cell.id} ${cell.value || 0} hits`).join(", ");
    return `${c.name || c.short || "tactic"}: ${hits[i]} hits` + (cells ? `; ${cells}` : "");
  }).join(". ");
  let out = svgOpen(cw * perRow, bands * h + (bands - 1) * bandGap, "heat", named, detail);
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
