"use strict";
// SOC dashboard, status strip, and the live stream client.
// Live updates come from GET /api/stream (Server-Sent Events). If the stream fails, the
// client polls every 3 seconds and retries the stream every 30. Routes that other
// workstreams add (/api/incidents, /api/attack/coverage, /api/storyline/status) are
// optional: a 404 renders a "pending" panel and the rest keeps working.
// Uses el(), api(), can(), go(), render(), fmtTime(), entityLink() from app.js (loaded after this file,
// called only at runtime).

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const TACTICS = [
  ["Reconnaissance", "Recon"], ["Resource Development", "Res Dev"], ["Initial Access", "Init Access"],
  ["Execution", "Execution"], ["Persistence", "Persist"], ["Privilege Escalation", "Priv Esc"],
  ["Defense Evasion", "Def Evasion"], ["Credential Access", "Cred Access"], ["Discovery", "Discovery"],
  ["Lateral Movement", "Lateral"], ["Collection", "Collect"], ["Command and Control", "C2"],
  ["Exfiltration", "Exfil"], ["Impact", "Impact"],
];
const HQ_DEFAULT = { city: "Watchpost HQ (internal)", lat: 39.1, lon: -94.6, internal: true, synthetic: true };
const FEED_MAX = 140;
const DASH_PANELS = ["p-map", "p-feed", "p-timeline", "p-attackers", "p-attack", "p-board", "p-rules", "p-health", "p-entities"];
const DASH_LAYOUTS = {
  full: DASH_PANELS,
  triage: ["p-board", "p-timeline", "p-feed", "p-entities"],
  telemetry: ["p-map", "p-feed", "p-attackers", "p-health"],
};
const DASH_FILTERS = {
  all: ["critical", "high", "medium", "low"],
  elevated: ["critical", "high"],
  critical: ["critical"],
};

// ---------- small helpers ----------
function svgNode(markup) {
  const doc = new DOMParser().parseFromString(markup, "image/svg+xml");
  const root = doc.documentElement;
  if (!root || root.nodeName !== "svg") return document.createTextNode("");
  return document.importNode(root, true);
}
function mountSvg(container, markup) { if (container) container.replaceChildren(svgNode(markup)); }
function setSvgChildren(group, inner) {
  if (!group) return;
  const wrap = svgNode(`<svg xmlns="http://www.w3.org/2000/svg">${inner}</svg>`);
  group.replaceChildren(...(wrap.childNodes ? [...wrap.childNodes] : []));
}
const shortTime = (ts) => (ts ? String(ts).slice(11, 16) : "");
function ago(ts) {
  if (!ts) return "—";
  const s = Math.max(0, (Date.now() - Date.parse(ts)) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
function parseMaybeJson(v) {
  if (typeof v !== "string") return v;
  try { return JSON.parse(v); } catch { return v; }
}
const asList = (v) => { const p = parseMaybeJson(v); return Array.isArray(p) ? p : p ? [p] : []; };
const fmtN = (v) => (v === null || v === undefined ? "—" : Number(v).toLocaleString());
// First paint of the status strip. Open alerts, critical, and stored events come from
// /api/dashboard; until that returns they are skeletons, not em dashes. Incidents use the
// same skeleton until /api/incidents returns. A later failure keeps the last number.
function stripDashboardTiles(summary) {
  if (!summary) {
    return {
      open: { loading: true },
      critical: { loading: true, hot: false },
      stored: { loading: true },
    };
  }
  return {
    open: { loading: false, text: fmtN(summary.alerts_open + summary.alerts_investigating) },
    critical: { loading: false, text: fmtN(summary.alerts_critical_open), hot: summary.alerts_critical_open > 0 },
    stored: { loading: false, text: fmtN(summary.events_total) },
  };
}
function stripIncidentTile(incidents) {
  const state = incidents && incidents.state;
  if (state === "ok") {
    const open = incidents.list.filter((i) => boardColumn(i.status) !== "resolved").length;
    return { loading: false, text: fmtN(open), dim: false, title: "" };
  }
  if (state === "pending") {
    return {
      loading: false,
      text: "pending",
      dim: true,
      title: "Incidents arrive with the correlation engine (/api/incidents)",
    };
  }
  if (state === "error") return { keep: true, dim: true };
  return { loading: true, dim: false, title: "" };
}
function applyStripTile(node, tile) {
  if (!node || !tile) return;
  if (tile.keep) {
    node.classList.toggle("dim", !!tile.dim);
    return;
  }
  node.classList.toggle("skel", tile.loading === true);
  node.classList.toggle("dim", !!tile.dim);
  if (Object.prototype.hasOwnProperty.call(tile, "title")) node.title = tile.title;
  if (tile.loading) {
    node.setAttribute("aria-busy", "true");
    if (!node.querySelector(".skel-bar")) {
      node.replaceChildren(
        el("span", { class: "skel-bar", "aria-hidden": "true" }),
        el("span", { class: "sr-only" }, "Loading"));
    }
    return;
  }
  node.removeAttribute("aria-busy");
  node.textContent = tile.text;
}
const sevOf = (s) => (SEV_RANK[s] !== undefined ? s : "info");
const maxSev = (a, b) => (SEV_RANK[sevOf(a)] >= SEV_RANK[sevOf(b)] ? sevOf(a) : sevOf(b));
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

async function optional(path) {
  try { return { state: "ok", data: await api(path) }; }
  catch (e) {
    if (e.status === 404) return { state: "pending" };
    return { state: "error", error: e.message };
  }
}

function panel(id, title, meta, ...body) {
  return el("section", { class: "panel", id },
    el("header", { class: "ph" }, el("h2", {}, title), el("div", { class: "pm", id: `${id}-meta` }, ...(meta || []))),
    el("div", { class: "pb", id: `${id}-body` }, ...body));
}

// A store with zero events is one explanation, not a note in every panel.
// Only an admin gets the control that loads the labeled synthetic dataset.
function emptyDashboard(eventsTotal, isAdmin) {
  if (typeof eventsTotal !== "number" || eventsTotal !== 0) return null;
  const load = isAdmin === true;
  return {
    title: "No events yet",
    body: "Ingest a log file or load demo data to populate the dashboard.",
    load,
    hint: load ? "" : "Ask an admin to load demo data.",
  };
}
// The public <title> stays the search title. Once signed in, the tab names the open critical count.
const PUBLIC_TITLE = "Watchpost: an open-source SIEM and SOC console in Python";
function consoleTitle(signedIn, criticalOpen) {
  if (signedIn !== true) return PUBLIC_TITLE;
  if (typeof criticalOpen !== "number" || !Number.isInteger(criticalOpen) || criticalOpen < 0) return PUBLIC_TITLE;
  return `Watchpost · ${criticalOpen} critical`;
}
// How often the feed polls after the event stream fails. The feed sentence uses this same interval.
const STREAM_POLL_MS = 3000;
function feedPollNote(mode) {
  if (mode !== "poll") return "";
  const seconds = STREAM_POLL_MS / 1000;
  if (!Number.isInteger(seconds) || seconds <= 0) return "";
  return `polling every ${seconds}s`;
}
const chip = (text, cls = "") => el("span", { class: `chip ${cls}` }, text);
const SEV_SHORT = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };
const sevTag = (s) => el("span", { class: `sevtag sev-${sevOf(s)}` }, SEV_SHORT[sevOf(s)]);

// ---------- tolerant readers for workstream A payloads ----------
function normIncidents(payload) {
  const list = Array.isArray(payload) ? payload : (payload && (payload.incidents || payload.items)) || [];
  return list.map((i) => {
    const alerts = asList(i.alerts);
    return {
      id: i.id, title: i.title || `Incident #${i.id}`, severity: sevOf(i.severity || "medium"),
      status: String(i.status || "open"), first_seen: i.first_seen, last_seen: i.last_seen || i.updated_at,
      alert_count: i.alert_count ?? i.alerts_count ?? (alerts.length || asList(i.alert_ids).length),
      tactics: asList(i.kill_chain ?? i.stages ?? i.kill_chain_stages ?? i.tactics).map((t) => (typeof t === "string" ? t : t.name || t.tactic)).filter(Boolean),
      top_technique: techniqueRef(i.top_technique),
      entities: parseMaybeJson(i.entities ?? i.entity_summary) || {},
    };
  });
}
function normCoverage(payload) {
  const list = Array.isArray(payload) ? payload : (payload && (payload.techniques || payload.coverage || payload.items)) || [];
  return list.map((t) => ({
    id: t.id || t.technique_id || "?", name: t.name || "",
    tactics: asList(t.tactics ?? t.tactic).map((x) => (typeof x === "string" ? x : x.name)).filter(Boolean),
    rules: asList(t.rules ?? t.rule_ids).map((r) => (typeof r === "string" ? r : r.id || r.rule_id)).filter(Boolean),
    hits: Number(t.hits ?? t.hit_count ?? t.alerts ?? t.alert_count ?? 0) || 0,
    covered: t.covered,  // true only when the technique is validated on a labeled scenario; "mapped" is not covered
    level: t.level,
  }));
}
const tacticKey = (name) => String(name).toLowerCase().replace(/[^a-z]/g, "");

function techniqueRef(value) {
  if (!value) return null;
  if (typeof value === "string") return value ? { id: value, name: "", tactic: "" } : null;
  const id = value.id || value.technique_id;
  if (!id) return null;
  return { id: String(id), name: value.name || "", tactic: value.tactic || "" };
}

// Evidence counts for the one-line chip shown when a layout hides the matrix.
// A payload with no level still treats a covered technique as validated, matching the matrix.
function coverageLevel(technique) {
  const level = technique && technique.level;
  if (level === "validated" || level === "mapped" || level === "disabled" || level === "gap") return level;
  const rules = technique && technique.rules;
  const proven = technique && (technique.covered ?? (Array.isArray(rules) && rules.length > 0));
  return proven ? "validated" : "gap";
}
function coverageCounts(list) {
  const counts = { validated: 0, mapped: 0, disabled: 0, gap: 0 };
  for (const technique of list || []) counts[coverageLevel(technique)] += 1;
  return counts;
}
function coverageChipText(counts) {
  return `${counts.validated} validated · ${counts.mapped} mapped · ${counts.disabled} disabled · ${counts.gap} gap`;
}
function layoutHidesMatrix(layout) {
  return !(layout || []).includes("p-attack");
}
function coverageChipLabel(coverage) {
  if (!coverage || coverage.state === "loading") return "coverage loading";
  if (coverage.state !== "ok") return coverage.state === "error" ? "coverage unavailable" : "coverage pending";
  return coverageChipText(coverageCounts(coverage.list));
}

// The heat matrix is an SVG image, so its cells are not text. One row per cell, including
// cells the chart clips behind "+N", names the technique, the tactic, and the evidence level.
function matrixTextRows(columns) {
  const rows = [];
  for (const column of columns || []) {
    const tactic = (column && (column.name || column.short)) || "Unmapped";
    for (const cell of (column && column.cells) || []) {
      if (!cell || cell.id === undefined || cell.id === null || String(cell.id) === "") continue;
      rows.push({ id: String(cell.id), tactic: String(tactic), level: coverageLevel(cell) });
    }
  }
  return rows;
}
function matrixTextLine(row) {
  return `${row.id}, ${row.tactic}, ${row.level}`;
}
function mountMatrixText(box, columns) {
  if (!box) return;
  const items = matrixTextRows(columns).map((row) => el("li", {}, matrixTextLine(row)));
  box.append(el("ul", { class: "sr-only", id: "attack-text" }, ...items));
}

// Tactic tags (at most four) plus the earliest kill-chain technique, the same order as the matrix.
function boardTags(tactics, technique) {
  const tags = [];
  const tech = techniqueRef(technique);
  if (tech) tags.push({ kind: "tech", id: tech.id, name: tech.name, tactic: tech.tactic });
  for (const name of (Array.isArray(tactics) ? tactics : []).slice(0, 4)) {
    if (name) tags.push({ kind: "tactic", text: String(name) });
  }
  return tags;
}

function techniqueTagTitle(tag) {
  const name = tag.name ? ` ${tag.name}` : "";
  const tactic = tag.tactic ? ` (${tag.tactic})` : "";
  return `${tag.id}${name}${tactic}`;
}
function boardColumn(status) {
  const s = String(status).toLowerCase();
  if (["resolved", "closed", "false_positive", "benign"].includes(s)) return "resolved";
  if (["investigating", "contained", "in_progress", "triage", "acknowledged"].includes(s)) return "investigating";
  return "open";
}

// ---------- synthetic geo cache ----------
// Side list for the attack map. Each arc is one fictional city aimed at HQ, busiest first.
// `unknown` counts source IPs the synthetic geo table does not know.
// A locate() of undefined is still in flight and is neither an arc nor unknown.
function mapSide(sources, locate) {
  const cities = new Map();
  let unknown = 0;
  for (const s of sources || []) {
    const loc = locate(s.ip);
    if (loc === undefined) continue;
    if (loc === null) { unknown += 1; continue; }
    if (loc.internal || !loc.city) continue;
    const row = cities.get(loc.city) || { city: loc.city, events: 0, sev: "info", ips: 0 };
    row.events += Number(s.events) || 0;
    row.ips += 1;
    row.sev = maxSev(row.sev, s.sev);
    cities.set(loc.city, row);
  }
  const ranked = [...cities.values()].sort((a, b) =>
    b.events - a.events || SEV_RANK[b.sev] - SEV_RANK[a.sev] || a.city.localeCompare(b.city));
  return { arcs: ranked.slice(0, 5), locations: ranked.length, unknown };
}

const Geo = {
  cache: new Map(),  // ip -> location | null (null = no table entry: "unknown")
  get(ip) { return this.cache.get(ip); },
  async resolve(ips) {
    const missing = [...new Set(ips)].filter((ip) => ip && !this.cache.has(ip));
    for (let i = 0; i < missing.length; i += 200) {
      const chunk = missing.slice(i, i + 200);
      try {
        const r = await api(`/api/geo?ips=${encodeURIComponent(chunk.join(","))}`);
        for (const ip of chunk) this.cache.set(ip, r.ips[ip] ?? null);
      } catch { /* retried on the next update */ }
    }
    return missing.length > 0;
  },
};

// ---------- live stream + status strip ----------
const Live = {
  es: null, mode: "off", timers: {}, errors: 0, opened: false, subscribers: 0,
  lastEventId: 0, epm: [], summary: null, incidents: { state: "loading" }, health: {}, healthStatus: null,
  story: undefined,

  start() {
    if (this.timers.clock) return;
    this.timers.clock = setInterval(() => this.tick(), 1000);
    this.tick();
    this.refreshSummary();
    this.refreshIncidents();
    this.connect();
    this.pollStory();
    this.timers.summary = setInterval(() => this.refreshSummary(), 30000);
  },
  stop() {
    if (this.es) { this.es.close(); this.es = null; }
    for (const t of Object.values(this.timers)) { clearInterval(t); clearTimeout(t); }
    this.timers = {};
    this.setMode("off");
  },

  connect() {
    if (this.es) this.es.close();
    this.opened = false;
    let es;
    try { es = new EventSource("/api/stream"); } catch { return this.startPolling(); }
    this.es = es;
    const on = (kind, fn) => es.addEventListener(kind, (m) => { try { fn(JSON.parse(m.data)); } catch (e) { console.warn(kind, e); } });
    on("hello", () => { this.opened = true; this.errors = 0; this.stopPolling(); this.setMode("live"); });
    on("event", (d) => this.onEvents(d.events || [], d.count || 0));
    on("alert", (a) => this.onAlert(a));
    on("incident", () => this.refreshIncidents());
    on("health", (h) => this.onHealth(h));
    on("heartbeat", (h) => { this.subscribers = h.subscribers; if (Dash.mounted) Dash.renderHealth(); });
    on("resync", () => { this.refreshSummary(); this.refreshIncidents(); });
    es.onerror = () => {
      this.errors += 1;
      if (es.readyState === EventSource.CLOSED || this.errors >= 3 || !this.opened) {
        es.close();
        if (this.es === es) this.es = null;
        this.startPolling();
      } else this.setMode("reconnecting");
    };
  },

  startPolling() {
    if (!state.user || this.timers.poll) return;
    this.setMode("poll");
    let ticks = 0;
    const poll = async () => {
      ticks += 1;
      try {
        const r = await api(`/api/events?limit=50&since_id=${this.lastEventId}`);
        if (this.lastEventId && r.events.length) this.onEvents(r.events, r.total);
        this.lastEventId = Math.max(this.lastEventId, ...r.events.map((e) => e.id));
        if (ticks % 5 === 0) this.refreshSummary();
      } catch { /* api() already handles 401 */ }
    };
    poll();
    this.timers.poll = setInterval(poll, STREAM_POLL_MS);
    this.timers.retry = setTimeout(() => { this.stopPolling(); this.connect(); }, 30000);
  },
  stopPolling() {
    clearInterval(this.timers.poll); clearTimeout(this.timers.retry);
    delete this.timers.poll; delete this.timers.retry;
  },
  setMode(mode) {
    this.mode = mode;
    const pill = $("#k-live");
    if (pill) {
      pill.dataset.mode = mode;
      $("#k-live-text").textContent = { live: "LIVE · SSE", poll: "POLLING 3s", reconnecting: "RECONNECTING", off: "OFFLINE" }[mode] || mode;
      if (Dash.mounted) Dash.renderHealth();
    }
    this.paintFeedPoll();
  },
  paintFeedPoll() {
    const note = $("#feed-poll");
    if (!note) return;
    const text = feedPollNote(this.mode);
    note.textContent = text;
    note.hidden = !text;
  },

  onEvents(events, count) {
    this.bumpEpm(count);
    if (this.summary) this.summary.events_total += count;
    for (const e of events) this.lastEventId = Math.max(this.lastEventId, e.id || 0);
    this.renderStrip();
    if (Dash.mounted) {
      // The first stored event replaces the empty-store card with the panels.
      if ($("#soc")?.hidden && this.summary && this.summary.events_total > 0) Dash.update(this.summary);
      Dash.enqueue(events);
    }
  },
  onAlert(a) {
    if (Dash.mounted && a.change === "created") Dash.alertRow(a);
    this.scheduleRefresh();
  },
  onHealth(h) {
    Object.assign(this.health, h.checks || {});
    if (!h.partial && h.status) this.healthStatus = h.status;
    else {
      const worst = Object.values(this.health).reduce((w, s) => (s === "failing" ? "failing" : s === "degraded" && w !== "failing" ? "degraded" : w), "ok");
      this.healthStatus = worst;
    }
    this.renderStrip();
    if (Dash.mounted) Dash.loadHealthDetails();
    if (typeof refreshBanner === "function") refreshBanner();
  },

  scheduleRefresh: debounce(() => { Live.refreshSummary(); Live.refreshIncidents(); }, 1200),
  async refreshSummary() {
    if (!state.user) return;
    try {
      const d = await api("/api/dashboard");
      this.summary = d;
      this.epm = d.events_per_minute.slice();
      if (!this.lastEventId) this.lastEventId = Math.max(0, ...d.recent_events.map((e) => e.id));
      this.renderStrip();
      if (Dash.mounted) Dash.update(d);
    } catch { /* offline; the strip keeps its last values */ }
  },
  async refreshIncidents() {
    if (!state.user) return;
    const r = await optional("/api/incidents");
    this.incidents = r.state === "ok" ? { state: "ok", list: normIncidents(r.data) } : r;
    this.renderStrip();
    if (Dash.mounted) Dash.renderBoard();
  },

  bumpEpm(count) {
    if (!count) return;
    const key = new Date().toISOString().slice(0, 16) + ":00Z";
    const last = this.epm[this.epm.length - 1];
    if (last && last.minute === key) last.count += count;
    else { this.epm.push({ minute: key, count }); if (this.epm.length > 60) this.epm.shift(); }
  },
  rollingEpm() {
    // Events in (roughly) the last 60 seconds: this minute plus the unexpired part of the last.
    const key = new Date().toISOString().slice(0, 16) + ":00Z";
    const n = this.epm.length;
    if (!n) return 0;
    const frac = new Date().getUTCSeconds() / 60;
    const cur = this.epm[n - 1].minute === key ? this.epm[n - 1].count : 0;
    const prevEntry = this.epm[n - 1].minute === key ? this.epm[n - 2] : this.epm[n - 1];
    const prevKey = new Date(Date.now() - 60000).toISOString().slice(0, 16) + ":00Z";
    const prev = prevEntry && prevEntry.minute === prevKey ? prevEntry.count : 0;
    return Math.round(cur + prev * (1 - frac));
  },

  tick() {
    const now = new Date();
    const c = $("#k-clock");
    if (c) c.replaceChildren(now.toISOString().slice(11, 19), el("small", {}, "UTC"));
    const epm = $("#k-epm");
    if (epm) epm.textContent = fmtN(this.rollingEpm());
    if (now.getUTCSeconds() === 0) this.bumpEpm(0);
    if (now.getUTCSeconds() % 5 === 0) this.renderSpark();
  },
  renderSpark() {
    const vals = this.epm.slice(-30).map((m) => m.count);
    const summary = vals.length ? `: latest ${vals[vals.length - 1]}, peak ${Math.max(...vals)}` : ": no data yet";
    mountSvg($("#k-epm-spark"), WPCharts.sparkline(vals, { w: 112, h: 28, cls: "accent", label: `events per minute, last 30 minutes${summary}` }));
  },
  renderStrip() {
    const d = this.summary;
    document.title = consoleTitle(!!state.user, d ? d.alerts_critical_open : undefined);
    const tiles = stripDashboardTiles(d);
    applyStripTile($("#k-open"), tiles.open);
    applyStripTile($("#k-crit"), tiles.critical);
    $("#k-crit").parentElement.classList.toggle("hot", !!tiles.critical.hot);
    applyStripTile($("#k-events"), tiles.stored);
    applyStripTile($("#k-inc"), stripIncidentTile(this.incidents));
    $("#k-epm").textContent = fmtN(this.rollingEpm());
    this.renderSpark();
    const checks = Object.entries(this.health);
    $("#k-health").replaceChildren(...(checks.length ? checks.map(([name, s]) =>
      el("span", { class: `hc st-${s}`, title: `${name}: ${s}` }, el("i"), { storage: "store", ingestion: "ingest", detection: "detect", dependencies: "deps" }[name] || name,
        el("span", { class: "sr-only" }, ` ${s}`))) : [el("span", { class: "muted" }, "…")]));
  },

  async pollStory() {
    const r = await optional("/api/storyline/status");
    const tile = $("#k-story");
    if (r.state === "pending" || !state.user) { if (tile) tile.hidden = true; return; }  // storyline not merged yet
    if (r.state === "ok" && tile) {
      const s = r.data || {};
      const running = s.running ?? s.state === "running";
      tile.hidden = !running && !s.stage;
      tile.classList.toggle("running", !!running);
      const pct = s.progress !== undefined ? ` ${Math.round((s.progress <= 1 ? s.progress * 100 : s.progress))}%` : "";
      $("#k-story-text").textContent = running ? `${s.stage || "running"}${pct}` : (s.stage ? `done · ${s.stage}` : "idle");
      this.timers.story = setTimeout(() => this.pollStory(), running ? 3000 : 15000);
    } else this.timers.story = setTimeout(() => this.pollStory(), 30000);
  },
};

// ---------- the dashboard view ----------
const Dash = {
  mounted: false, data: null, coverage: { state: "loading" }, details: null,
  queue: [], feedCount: 0, paused: false, live: new Map(), mapSize: null, timers: {}, observer: null,
  views: [], currentView: null, severities: DASH_FILTERS.all, layout: DASH_LAYOUTS.full, queueSort: "severity",

  mount() {
    this.unmount();
    this.mounted = true;
    this.mapSize = null;
    this.feedCount = 0;
    const pause = el("button", { class: "mini ghost", id: "feed-pause", onclick: () => this.togglePause() }, "Pause");
    render(el("div", { class: "view-bar", id: "dashboard-view-bar" }, el("p", { class: "muted" }, "Loading saved dashboard views…")),
      el("div", { id: "dash-empty", hidden: true }),
      el("div", { class: "soc", id: "soc" },
      panel("p-map", "Attack map", [el("span", { class: "muted", id: "map-count" })],
        el("div", { class: "mapwrap", id: "map" }),
        el("div", { class: "map-side", id: "map-side" }),
        el("div", { class: "map-legend" }, ...["critical", "high", "medium", "low"].map((s) => el("span", {}, el("i", { class: `dot sev-${s}` }), s)),
          el("span", {}, el("i", { class: "dot hq" }), "HQ target"))),
      panel("p-feed", "Live event stream", [el("span", { class: "muted", id: "feed-poll", hidden: true }), el("span", { class: "muted", id: "feed-rate" }), pause],
        el("div", { class: "feed-head" }, el("span", {}, "Time"), el("span", {}, "Sev"), el("span", {}, "Event")),
        el("div", { class: "feed", id: "feed", onmouseenter: () => this.hover(true), onmouseleave: () => this.hover(false) })),
      panel("p-timeline", "Alerts over time", [el("span", { class: "muted", id: "tl-bucket" })], el("div", { class: "chartbox", id: "tl-chart" }),
        el("div", { class: "legend" }, ...["critical", "high", "medium", "low"].map((s) => el("span", {}, el("i", { class: `dot sev-${s}` }), s)),
          el("span", {}, el("i", { class: "dot volume" }), "event volume"))),
      panel("p-attackers", "Top attacker IPs", [el("span", { class: "muted" }, "by evidence events")], el("div", { class: "chartbox", id: "atk-chart" })),
      panel("p-attack", "MITRE ATT&CK coverage", [el("span", { class: "muted", id: "attack-meta" }), el("a", { href: "/api/attack/navigator.json", download: "watchpost-navigator-layer.json", title: "MITRE ATT&CK Navigator layer (JSON) colored by evidence level" }, "Export Navigator layer")], el("div", { class: "chartbox", id: "attack-chart", tabindex: "0", role: "region", "aria-label": "ATT&CK technique matrix" }), el("div", { class: "heat-legend", id: "attack-legend" })),
      panel("p-board", "Incident board", [el("span", { id: "board-meta" })],
        el("div", { class: "board", id: "board", "data-kbd-list": "board" })),
      panel("p-rules", "Top rules", [el("span", { class: "muted" }, "alerts all time")], el("div", { class: "chartbox", id: "rules-chart" })),
      panel("p-health", "Health", [el("a", { href: "#health", class: "muted" }, "details →")], el("div", { id: "health-body" })),
      panel("p-entities", "Riskiest entities", [el("span", { class: "muted" }, "alert weight, decayed by age")], el("div", { id: "ent-list" })),
    ));
    Live.paintFeedPoll();
    this.timers.drip = setInterval(() => this.drip(), 110);
    this.timers.details = setInterval(() => this.loadHealthDetails(), 30000);
    const soc = $("#soc");
    if (window.ResizeObserver && soc) {
      const onResize = debounce(() => this.redraw(), 150);
      this.observer = new ResizeObserver(onResize);
      this.observer.observe(soc);
    }
    this.loadViews();
  },
  unmount() {
    if (!this.mounted) return;
    this.mounted = false;
    for (const t of Object.values(this.timers)) clearInterval(t);
    this.timers = {};
    if (this.observer) { this.observer.disconnect(); this.observer = null; }
    this.queue = [];
  },

  async load() {
    if (Live.summary) this.update(Live.summary);
    Live.refreshSummary();
    this.renderBoard();
    this.loadCoverage();
    this.loadHealthDetails();
  },
  async update(d) {
    this.data = d;
    if (this.renderEmpty()) return;
    if (!this.feedCount) this.fillFeed(d.recent_events);
    const ips = [...d.attackers.map((a) => a.ip), ...d.recent_events.map((e) => e.src_ip), ...d.recent_events.map((e) => e.dest_ip), "10.0.0.10"].filter(Boolean);
    this.redraw();
    if (await Geo.resolve(ips)) this.renderMarks();
    this.renderAttackers();
  },
  // Returns true when the store is empty: one card, and the panel grid stays hidden.
  renderEmpty() {
    const box = $("#dash-empty");
    const soc = $("#soc");
    if (!box || !soc || !this.data) return false;
    const copy = emptyDashboard(this.data.events_total, can("admin"));
    if (!copy) {
      if (soc.hidden || !box.hidden) {
        box.hidden = true;
        box.replaceChildren();
        delete box.dataset.mode;
        soc.hidden = false;
      }
      return false;
    }
    soc.hidden = true;
    const mode = copy.load ? "load" : "wait";
    if (box.hidden || box.dataset.mode !== mode) {
      box.dataset.mode = mode;
      box.hidden = false;
      box.replaceChildren(el("div", { class: "card dash-empty", role: "status" },
        el("h2", {}, copy.title),
        el("p", {}, copy.body),
        copy.load
          ? el("button", { type: "button", id: "dash-load-demo", onclick: () => guarded(() => this.loadDemo()) }, "Load demo data")
          : el("p", { class: "muted" }, copy.hint)));
    }
    return true;
  },
  async loadDemo() {
    const button = $("#dash-load-demo");
    if (button) button.disabled = true;
    try {
      let loaded;
      try { loaded = await api("/api/demo/load", { method: "POST", body: {} }); }
      catch (e) {
        if (e.status !== 409 || !confirm(`${e.message}. Load another copy?`)) throw e;
        loaded = await api("/api/demo/load", { method: "POST", body: { force: true } });
      }
      toast(`Demo loaded (${Object.keys(loaded).length} scenarios).`);
      await Live.refreshSummary();
      await Live.refreshIncidents();
      this.loadCoverage();
    } finally {
      if (button && button.isConnected) button.disabled = false;
    }
  },
  redraw() {
    if (!this.mounted || !this.data || emptyDashboard(this.data.events_total, false)) return;
    this.renderMap(); this.renderTimeline(); this.renderAttackers(); this.renderRules(); this.renderEntities(); this.renderMatrix(); this.renderBoard(); this.renderHealth();
    this.applyView();
  },
  async loadViews() {
    if (!this.mounted) return;
    try { this.views = await api("/api/dashboard/views"); }
    catch (e) { return $("#dashboard-view-bar")?.replaceChildren(el("p", { class: "error" }, e.message)); }
    this.renderViewBar();
  },
  viewPayload(form) {
    const f = new FormData(form);
    return { name: f.get("name").trim(), visibility: f.get("visibility"),
      filters: { severities: DASH_FILTERS[f.get("filter")] }, layout: DASH_LAYOUTS[f.get("layout")] };
  },
  renderViewBar() {
    const bar = $("#dashboard-view-bar");
    if (!bar) return;
    const picker = el("select", { name: "saved_view", "aria-label": "Saved dashboard view" },
      el("option", { value: "" }, "Default view"),
      ...this.views.map((v) => el("option", { value: v.id }, `${v.name} · ${v.visibility}${v.owner === state.user.username ? " · mine" : ""}`)));
    const apply = () => {
      const selected = this.views.find((v) => String(v.id) === picker.value);
      this.currentView = selected || null;
      this.severities = selected ? selected.filters.severities : DASH_FILTERS.all;
      this.layout = selected ? selected.layout : DASH_LAYOUTS.full;
      this.applyView(); this.renderViewBar();
    };
    picker.value = this.currentView ? String(this.currentView.id) : "";
    const controls = [picker, el("button", { type: "button", class: "ghost", onclick: apply }, "Apply")];
    let save = null;
    if (can("analyst")) {
      if (this.currentView?.owner === state.user.username) controls.push(
        el("button", { type: "button", class: "danger", onclick: () => confirm(`Delete dashboard view "${this.currentView.name}"?`) && guarded(async () => {
          await api(`/api/dashboard/views/${this.currentView.id}/delete`, { method: "POST" });
          this.currentView = null; this.severities = DASH_FILTERS.all; this.layout = DASH_LAYOUTS.full;
          await this.loadViews(); this.applyView();
        }) }, "Delete mine"));
      const form = el("form", { class: "view-save-form" },
        el("label", {}, "Name", el("input", { name: "name", required: true, maxlength: 80 })),
        el("label", {}, "Severity", el("select", { name: "filter" },
          el("option", { value: "all" }, "All severities"), el("option", { value: "elevated" }, "Critical + high"), el("option", { value: "critical" }, "Critical only"))),
        el("label", {}, "Panels", el("select", { name: "layout" },
          el("option", { value: "full" }, "Full dashboard"), el("option", { value: "triage" }, "Triage focus"), el("option", { value: "telemetry" }, "Telemetry focus"))),
        el("label", {}, "Visibility", el("select", { name: "visibility" },
          el("option", { value: "private" }, "Private"), el("option", { value: "shared" }, "Shared"))),
        el("button", { type: "submit" }, "Save new"));
      form.addEventListener("submit", (ev) => { ev.preventDefault(); guarded(async () => {
        this.currentView = await api("/api/dashboard/views", { method: "POST", body: this.viewPayload(form) });
        this.severities = this.currentView.filters.severities; this.layout = this.currentView.layout;
        await this.loadViews(); this.applyView(); toast(`Saved dashboard view "${this.currentView.name}"`);
      }); });
      save = el("details", { class: "view-save" }, el("summary", {}, "Save a view"), form);
    }
    const lead = [el("h1", { class: "view-name" }, this.currentView ? this.currentView.name : "Dashboard")];
    if (layoutHidesMatrix(this.layout)) {
      lead.push(el("a", {
        class: "chip coverage-chip", id: "coverage-chip", href: "#coverage",
        title: "Open coverage for this layout",
      }, coverageChipLabel(this.coverage)));
    }
    bar.replaceChildren(...lead, el("div", { class: "view-controls" }, ...controls), ...(save ? [save] : []));
  },
  applyView() {
    const soc = $("#soc");
    if (!soc) return;
    for (const id of DASH_PANELS) {
      const panelNode = $(`#${id}`);
      if (!panelNode) continue;
      panelNode.hidden = !this.layout.includes(id);
      if (!panelNode.hidden) soc.append(panelNode);
    }
    for (const severity of SEV_ORDER) {
      for (const node of soc.querySelectorAll(`.sev-${severity}`)) node.hidden = !this.severities.includes(severity);
    }
  },
  width(id, fallback = 300) { const n = $(id); return n ? Math.max(120, n.clientWidth) : fallback; },

  // --- map ---
  hq() {
    const loc = Geo.get("10.0.0.10");
    return loc || HQ_DEFAULT;
  },
  renderMap() {
    const box = $("#map");
    if (!box) return;
    const w = Math.max(320, box.clientWidth), h = Math.max(160, box.clientHeight);
    const size = `${w}x${h}`;
    if (this.mapSize !== size) {
      // Fit the 360x140-degree projection inside the box, centered.
      const mw = Math.min(w, h * (360 / 140)), mh = mw * (140 / 360);
      mountSvg(box, WPMap.baseMap(mw, mh, { step: 1.8 }));
      this.mapSize = size;
      this.mapDims = [mw, mh];
    }
    this.renderMarks();
  },
  sources() {
    const out = new Map();
    const add = (ip, events, sev, alerts, last) => {
      const cur = out.get(ip) || { ip, events: 0, alerts: 0, sev: "info", last: null };
      cur.events += events; cur.alerts = Math.max(cur.alerts, alerts || 0); cur.sev = maxSev(cur.sev, sev);
      if (!cur.last || (last && last > cur.last)) cur.last = last;
      out.set(ip, cur);
    };
    for (const a of (this.data && this.data.attackers) || []) add(a.ip, a.events, a.max_severity, a.alerts, a.last_seen);
    for (const [ip, s] of this.live) add(ip, s.events, s.sev, 0, s.last);
    return [...out.values()];
  },
  renderMarks() {
    const svg = $("#map svg");
    if (!svg || !this.mapDims) return;
    const [w, h] = this.mapDims;
    const hq = this.hq();
    const cities = new Map();
    for (const s of this.sources()) {
      const loc = Geo.get(s.ip);
      if (!loc || loc.internal) continue;
      const c = cities.get(loc.city) || { ...loc, ips: [], events: 0, sev: "info" };
      c.ips.push(s.ip); c.events += s.events; c.sev = maxSev(c.sev, s.sev);
      cities.set(loc.city, c);
    }
    const ranked = [...cities.values()].sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || b.events - a.events);
    const esc = WPCharts.esc;
    const [hx, hy] = WPMap.project(hq.lon, hq.lat, w, h);
    const sideEl = $("#map-side");
    let coverRight = 0;
    if (sideEl) {
      const svgRect = svg.getBoundingClientRect();
      const sideRect = sideEl.getBoundingClientRect();
      if (svgRect.width > 0 && sideRect.width > 0) coverRight = (sideRect.right - svgRect.left) / (svgRect.width / w) + 8;
    }
    const placed = [{ x: hx, y: hy }];
    const crowded = (x, y) => placed.some((p) => Math.hypot(p.x - x, p.y - y) < 52);
    let arcs = "", marks = "";
    ranked.forEach((c, i) => {
      arcs += `<path class="arc s-${c.sev}" pathLength="100" d="${WPMap.arcPath([c.lon, c.lat], [hq.lon, hq.lat], w, h)}"/>`;
      const [x, y] = WPMap.project(c.lon, c.lat, w, h);
      const r = 2.6 + Math.min(5, Math.log2(1 + c.events) * 0.8);
      let label = "";
      if (i < 7 && x > coverRight && !crowded(x, y)) {
        const end = x > w - 72;
        const lx = end ? x - r - 4 : x + r + 4;
        const ly = y > 18 ? y - r - 3 : y + r + 12;
        label = `<text class="ml" x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${end ? "end" : "start"}">${esc(c.city)}</text>`;
        placed.push({ x, y });
      }
      marks += `<g class="mk sev-${c.sev}"><title>${esc(`${c.city}\n${c.ips.join(", ")}\n${c.events} events`)}</title>` +
        `<circle class="halo" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(r * 2.2).toFixed(1)}"/>` +
        `<circle class="core" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(1)}"/>` +
        label + `</g>`;
    });
    const hqClear = hx + 28 < coverRight;
    const hqEnd = !hqClear && hx > w - 72;
    const hqx = hqClear ? coverRight : (hqEnd ? hx - 12 : hx + 12);
    const hqy = hqClear ? Math.min(h - 8, Math.max(14, hy + 3)) : (hy > 18 ? hy - 8 : hy + 16);
    marks += `<g class="hq"><title>${esc(hq.city)}</title><circle class="ring" cx="${hx.toFixed(1)}" cy="${hy.toFixed(1)}" r="9"/>` +
      `<circle class="core" cx="${hx.toFixed(1)}" cy="${hy.toFixed(1)}" r="3.6"/>` +
      `<text class="ml" x="${hqx.toFixed(1)}" y="${hqy.toFixed(1)}" text-anchor="${hqEnd ? "end" : "start"}">HQ</text></g>`;
    setSvgChildren(svg.querySelector("g.arcs"), arcs);
    setSvgChildren(svg.querySelector("g.marks"), marks);
    const summary = mapSide(this.sources(), (ip) => Geo.get(ip));
    const count = $("#map-count");
    if (count) count.textContent = `${summary.locations} ${summary.locations === 1 ? "arc" : "arcs"} · ${summary.unknown} no geo entry`;
    const side = $("#map-side");
    if (!side) return;
    const arcRow = (a) => el("div", { class: "ms-row", title: `${a.city} → HQ · ${a.events} events from ${a.ips} source ${a.ips === 1 ? "IP" : "IPs"}` },
      el("i", { class: `dot sev-${a.sev}` }),
      el("span", { class: "ms-city" }, a.city),
      el("b", { class: "ms-n" }, String(a.events)));
    side.replaceChildren(
      el("div", { class: "ms-h" }, "Busiest arcs"),
      ...(summary.arcs.length ? summary.arcs.map(arcRow) : [el("div", { class: "muted" }, "No external arcs yet. They appear when a source IP has a geo entry.")]));
  },
  pulse(e) {
    const svg = $("#map svg");
    if (!svg || !this.mapDims || !e.src_ip) return;
    const loc = Geo.get(e.src_ip);
    if (!loc || loc.internal) return;
    const [w, h] = this.mapDims;
    const fx = svg.querySelector("g.fx");
    if (!fx || fx.childNodes.length > 40) return;
    const target = (e.dest_ip && Geo.get(e.dest_ip) && Geo.get(e.dest_ip).internal) ? Geo.get(e.dest_ip) : this.hq();
    const [x, y] = WPMap.project(loc.lon, loc.lat, w, h);
    const s = sevOf(e.severity);
    const wrap = svgNode(`<svg xmlns="http://www.w3.org/2000/svg"><circle class="ping sev-${s}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3"/>` +
      `<path class="shot s-${s}" pathLength="100" d="${WPMap.arcPath([loc.lon, loc.lat], [target.lon, target.lat], w, h)}"/></svg>`);
    const nodes = [...wrap.childNodes];
    fx.append(...nodes);
    setTimeout(() => nodes.forEach((n) => n.remove()), 1700);
  },

  // --- live feed ---
  fillFeed(events) {
    const feed = $("#feed");
    if (!feed) return;
    feed.replaceChildren(...(events.length ? events.slice(0, FEED_MAX).map((e) => this.feedRow(e, false))
      : [el("p", { class: "empty-note" }, "No events received yet. Ingest a log or load demo data to start the stream.")]));
    this.feedCount = events.length || 1;
  },
  enqueue(events) {
    // Batches arrive newest-first; drip them in oldest-first so the stream reads in order.
    for (const e of [...events].reverse()) this.queue.push(e);
    if (this.queue.length > 600) this.queue.splice(0, this.queue.length - 600);
    const ips = events.flatMap((e) => [e.src_ip, e.dest_ip]).filter(Boolean);
    for (const e of events) {
      if (!e.src_ip || (SEV_RANK[sevOf(e.severity)] < 2 && e.event_type !== "auth_failure")) continue;
      const cur = this.live.get(e.src_ip) || { events: 0, sev: "info", last: null };
      cur.events += 1; cur.sev = maxSev(cur.sev, e.severity); cur.last = e.ts;
      this.live.set(e.src_ip, cur);
    }
    Geo.resolve(ips).then((changed) => { if (changed) this.renderMarks(); });
    this.scheduleMarks();
  },
  scheduleMarks: debounce(() => Dash.renderMarks(), 800),
  drip() {
    const rate = $("#feed-rate");
    if (rate) rate.textContent = this.queue.length ? `${this.queue.length} queued` : "";
    if (this.paused || !this.queue.length) return;
    const feed = $("#feed");
    if (!feed) return;
    feed.querySelector(".empty-note")?.remove();
    const take = Math.min(this.queue.length, Math.max(1, Math.ceil(this.queue.length / 10)));
    for (const e of this.queue.splice(0, take)) {
      feed.prepend(this.feedRow(e, true));
      this.pulse(e);
    }
    this.feedCount += take;
    while (feed.childElementCount > FEED_MAX) feed.lastElementChild.remove();
  },
  feedRow(e, fresh) {
    const s = sevOf(e.severity);
    const target = e.user || e.host || e.dest_ip || "";
    const msg = eventMessage(e);
    const route = (e.src_ip || target) ? el("span", { class: "route" },
      e.src_ip ? el("code", {}, e.src_ip) : null,
      e.src_ip && target ? el("span", { class: "arrow" }, "→") : null,
      target ? el("span", { class: "fu" }, target) : null) : null;
    return el("div", { class: `fr sev-${s}${fresh ? " new" : ""}`, title: msg },
      relTime(e.ts, "ft"),
      sevTag(s),
      el("span", { class: "fy" }, el("span", { class: "fn" }, e.event_type)),
      el("span", { class: "fd" }, route, msg ? el("span", { class: "fm" }, msg) : null));
  },
  alertRow(a) {
    const feed = $("#feed");
    if (!feed) return;
    const row = el("a", { class: `fr alert-row sev-${sevOf(a.severity)} new`, href: `#alerts/${a.id}`,
      title: [a.rule_id, a.status, exactTime(a.last_seen)].filter(Boolean).join(" · ") },
      relTime(a.last_seen, "ft"), sevTag(a.severity),
      el("span", { class: "fy" }, el("span", { class: "fn" }, a.title), a.status ? statusPill(a.status) : null),
      el("span", { class: "fd" }, el("span", { class: "fm" }, a.rule_id)));
    feed.prepend(row);
    const p = $("#p-feed");
    if (p) { p.classList.remove("flash"); void p.offsetWidth; p.classList.add("flash"); }
  },
  hover(on) { this.hovering = on; this.paused = on || this.userPaused; },
  togglePause() {
    this.userPaused = !this.userPaused;
    this.paused = this.userPaused || this.hovering;
    $("#feed-pause").textContent = this.userPaused ? "Resume" : "Pause";
  },

  // --- charts ---
  renderTimeline() {
    const t = this.data.alert_timeline;
    const box = $("#tl-chart");
    if (!box) return;
    $("#tl-bucket").textContent = t.bins.length ? `${t.bucket_minutes === 60 ? "hourly" : `${t.bucket_minutes}-min`} · event time` : "";
    if (!t.bins.length) { box.replaceChildren(el("p", { class: "empty-note" }, "No alerts yet. Load demo data or run the storyline.")); return; }
    const w = this.width("#tl-chart"), h = Math.max(110, box.clientHeight || 130);
    const keys = ["low", "medium", "high", "critical"];
    mountSvg(box, WPCharts.stackedBars(t.bins, keys, {
      w, h, overlay: t.bins.map((b) => b.events), labels: t.bins.map((b) => shortTime(b.start)),
      title: (b) => `${fmtTime(b.start)}\n${keys.slice().reverse().map((k) => `${k}: ${b[k]}`).join("  ")}\nevents: ${b.events}`,
      label: `alerts over time by severity, ${t.bins.length} buckets: ${keys.slice().reverse().map((k) => `${k} ${t.bins.reduce((n, b) => n + (b[k] || 0), 0)}`).join(", ")}`,
    }));
  },
  renderAttackers() {
    const box = $("#atk-chart");
    if (!box || !this.data) return;
    const rows = this.data.attackers.slice(0, 6).map((a) => {
      const loc = Geo.get(a.ip);
      return { label: a.ip, value: a.events, cls: sevOf(a.max_severity),
        sub: loc === undefined ? "…" : loc === null ? "no geo entry" : loc.city,
        subCls: loc === null ? "unknown" : "",
        title: `${a.ip}: ${a.events} evidence events in ${a.alerts} alerts (${a.open_alerts} open)${loc && loc.city ? ` · ${loc.city}` : ""}` };
    });
    if (!rows.length) { box.replaceChildren(el("p", { class: "empty-note" }, "No attacker IPs in alert evidence yet. They appear once an alert cites a source IP.")); return; }
    mountSvg(box, WPCharts.hbars(rows, { w: this.width("#atk-chart"), rowH: 26, labelW: 140, label: `top attacker IPs by evidence events: ${rows.map((r) => `${r.label} ${r.value}`).join(", ")}` }));
  },
  renderRules() {
    const box = $("#rules-chart");
    if (!box) return;
    const rows = this.data.top_rules.map((r) => ({ label: r.name || r.rule_id, sub: `${r.rule_id} · ${r.open} open`, value: r.alerts, cls: sevOf(r.severity) }));
    if (!rows.length) { box.replaceChildren(el("p", { class: "empty-note" }, "No rule has fired yet. Run detection or load demo data.")); return; }
    // The rules column is a third of the board. A side label cannot hold these names, so the
    // name sits on its own line and the bar uses the full width under it.
    const shown = rows.slice(0, 7);
    const max = Math.max(1, ...shown.map((r) => r.value));
    box.replaceChildren(el("div", { class: "rules", role: "group", "aria-label": `alerts by rule: ${shown.map((r) => `${r.label} ${r.value}`).join(", ")}` },
      ...shown.map((r) => el("div", { class: `rrow sev-${r.cls || "info"}`, title: r.title || `${r.label}: ${r.value}` },
        el("div", { class: "rname" }, el("span", {}, r.label), el("b", {}, r.value)),
        r.sub ? el("div", { class: "rsub" }, r.sub) : null,
        el("div", { class: "rtrack", "aria-hidden": "true" },
          el("i", { style: { width: `${Math.max(4, Math.round((r.value / max) * 100))}%` } }))))));
  },
  renderEntities() {
    const box = $("#ent-list");
    if (!box) return;
    const rows = this.data.risky_entities || [];
    if (!rows.length) { box.replaceChildren(el("p", { class: "empty-note" }, "No entity has a counted alert yet. They appear after the first counted alert.")); return; }
    box.replaceChildren(...rows.map((r) => el("div", { class: "erow", title: `${r.alerts} counted alert(s), ${r.open_alerts} open` },
      sevTag(r.max_severity), el("span", { class: "tag" }, ENTITY_KINDS[r.kind] || r.kind), entityLink(r.kind, r.value),
      el("b", {}, r.score))));
  },

  // --- ATT&CK matrix ---
  async loadCoverage() {
    const r = await optional("/api/attack/coverage");
    this.coverage = r.state === "ok" ? { state: "ok", list: normCoverage(r.data) } : r;
    this.renderMatrix();
  },
  renderMatrix() {
    const chipNode = $("#coverage-chip");
    if (chipNode) chipNode.textContent = coverageChipLabel(this.coverage);
    const box = $("#attack-chart");
    if (!box) return;
    const cov = this.coverage;
    const w = this.width("#attack-chart", 900);
    const byTactic = new Map(TACTICS.map(([name, short]) => [tacticKey(name), { name, short, cells: [] }]));
    // Rules behind critical alerts: a technique they map to and that was observed is drawn red.
    const critRules = new Set([...(this.data?.alerts || []), ...(this.data?.top_rules || [])]
      .filter((a) => sevOf(a.severity) === "critical").map((a) => a.rule_id));
    if (cov.state === "ok") {
      for (const t of cov.list) {
        for (const tac of t.tactics.length ? t.tactics : ["Unmapped"]) {
          const key = tacticKey(tac);
          if (!byTactic.has(key)) byTactic.set(key, { name: tac, short: tac, cells: [] });
          byTactic.get(key).cells.push({ id: t.id, name: t.name, value: t.hits, covered: t.covered ?? t.rules.length > 0, level: t.level, rules: t.rules,
            crit: t.hits > 0 && t.rules.some((id) => critRules.has(id)) });
        }
      }
      for (const col of byTactic.values()) col.cells.sort((a, b) => a.id.localeCompare(b.id));
    }
    // Empty tactics stay in the row so a gap in the kill chain is visible, not dropped.
    const columns = [...byTactic.values()];
    const meta = $("#attack-meta");
    const legend = $("#attack-legend");
    if (cov.state === "ok") {
      const validated = cov.list.filter((t) => (t.level ? t.level === "validated" : (t.covered ?? t.rules.length > 0))).length;
      const mapped = cov.list.filter((t) => t.level === "mapped").length;
      const hot = cov.list.filter((t) => t.hits > 0).length;
      const tallest = columns.reduce((n, c) => Math.max(n, c.cells.length), 0);
      const levelNote = cov.list.some((t) => t.level) ? ` · ${mapped} mapped only` : "";
      meta.textContent = `${validated}/${cov.list.length} validated${levelNote} · ${hot} observed · `;
      meta.append(el("a", { href: "#coverage" }, "details"));
      mountSvg(box, WPCharts.heatMatrix(columns.length ? columns : [{ name: "None", short: "—", cells: [] }], {
        w: Math.max(w, columns.length * 86), cellH: 22, maxRows: Math.max(tallest, 1),
        label: `ATT&CK coverage: ${validated} of ${cov.list.length} techniques validated on test scenarios, ${mapped} mapped only, ${hot} seen in alerts. Empty tactics have no catalog technique. Colors match the Coverage view.`,
      }));
      mountMatrixText(box, columns);
      if (legend) legend.replaceChildren(
        ...[["heat", "Validated (heat = alert count)"], ["mapped", "Mapped only"], ["disabled", "Disabled"], ["gap", "Gap"], ["crit", "On a critical alert"]]
          .map(([cls, text]) => el("span", {}, el("i", { class: `swatch ${cls}`, "aria-hidden": "true" }), text)));
      box.parentElement.querySelector(".cov-quiet")?.remove();
      return;
    }
    if (legend) legend.replaceChildren();
    meta.textContent = cov.state === "pending" ? "" : cov.state === "error" ? cov.error : "loading…";
    const ghost = svgNode(WPCharts.heatMatrix(columns, { w, cellH: 21, maxRows: 3, label: "ATT&CK matrix (pending)" }));
    box.replaceChildren(el("div", { class: "pending-wrap" }, ghost,
      el("div", { class: "pending" }, el("b", {}, cov.state === "error" ? "Coverage unavailable" : "ATT&CK coverage pending"),
        el("span", {}, cov.state === "error" ? cov.error : "Technique mapping lands with the correlation engine (GET /api/attack/coverage). Everything else here is live."))));
  },

  // --- incident board ---
  renderBoard() {
    const box = $("#board");
    if (!box) return;
    const sort = this.queueSort === "time" ? "time" : "severity";
    const inc = Live.incidents;
    const columns = incidentBoard(inc, this.data ? this.data.alerts : [], 5, sort);
    box.replaceChildren(...columns);
    if (!box.querySelector("a.bcard")) {
      box.prepend(el("p", { class: "empty-note", style: { flex: "1 0 100%", margin: "0 0 8px" } }, boardEmptyCopy(inc)));
    }
    const meta = $("#board-meta");
    meta.replaceChildren(
      boardSortSelect(sort, (mode) => { this.queueSort = mode; this.renderBoard(); }),
      inc.state === "ok" ? el("a", { href: "#incidents", class: "muted" }, "all incidents →")
        : chip(inc.state === "loading" ? "LOADING" : "INCIDENTS PENDING · SHOWING ALERTS", "pendingchip"));
  },

  // --- health ---
  async loadHealthDetails() {
    if (!this.mounted) return;
    try { this.details = await api("/api/health/details", { allow: [503] }); } catch { /* keep last */ }
    this.renderHealth();
  },
  renderHealth() {
    const box = $("#health-body");
    if (!box) return;
    const d = this.details;
    const checks = d ? d.checks.map((c) => [c.name, c.status, c.message, c.latency_ms]) : Object.entries(Live.health).map(([n, s]) => [n, s, "", null]);
    const runs = d ? d.recent_detection_runs.slice().reverse() : [];
    box.replaceChildren(...[
      ...checks.map(([name, s, msg, ms]) => el("div", { class: "hrow2", title: msg || "" },
        el("span", { class: `hc st-${s}` }, el("i"), el("span", { class: "sr-only" }, `${s}: `)), el("b", {}, name), el("span", { class: "muted hmsg" }, msg), el("span", { class: "hms" }, ms === null ? "" : `${ms} ms`))),
      el("div", { class: "hrow2" }, el("span", { class: `hc st-${Live.mode === "live" ? "ok" : Live.mode === "poll" ? "degraded" : "failing"}` }, el("i")),
        el("b", {}, "stream"), el("span", { class: "muted hmsg" }, `${$("#k-live-text").textContent}${Live.subscribers ? ` · ${Live.subscribers} viewer(s)` : ""}`), el("span", { class: "hms" }, "")),
      runs.length ? el("div", { class: "runs" }, el("span", { class: "muted" }, "detection runs"),
        el("span", { class: "rundots", role: "img", "aria-label": `${runs.length} recent runs: ${runs.filter((r) => r.status === "ok").length} ok, ${runs.filter((r) => r.status === "failed").length} failed` }, ...runs.map((r) => el("i", { class: `st-${r.status === "ok" ? "ok" : r.status === "failed" ? "failing" : "degraded"}`, title: `#${r.id} ${r.trigger} · ${r.status} · ${r.events_scanned} scanned · +${r.alerts_created}` })))) : null].filter(Boolean));
  },
};

// Severity: highest first, newest inside that level. Time: newest first, then severity.
// Same order on the dashboard board and the incidents page.
function queueOrder(mode) {
  const sev = (x, y) => SEV_RANK[sevOf(y.sev)] - SEV_RANK[sevOf(x.sev)];
  const newestFirst = (x, y) => String(y.time || "").localeCompare(String(x.time || ""));
  if (mode === "time") return (x, y) => newestFirst(x, y) || sev(x, y);
  return (x, y) => sev(x, y) || newestFirst(x, y);
}
function exactTime(ts) {
  if (!ts) return "";
  if (typeof fmtTime === "function") return fmtTime(ts);
  return String(ts).replace("T", " ").replace(/\.\d+Z$/, "Z");
}
// Relative stamp. The title is the exact timestamp, so a hover answers "when".
function relTime(ts, cls) {
  const exact = exactTime(ts);
  return el("time", { class: cls || "muted", datetime: ts || "", title: exact || null }, ago(ts));
}
function statusPill(s) {
  const name = String(s || "open").toLowerCase();
  return el("b", { class: `pill st-${name}` }, name);
}
function columnEmpty(name) {
  if (name === "open") return "No open items. New alerts land here.";
  if (name === "investigating") return "Nothing in progress. Open a card and start investigating.";
  return "Nothing resolved yet. Close an item from its page when the work is done.";
}
function boardEmptyCopy(inc) {
  if (inc && inc.state === "ok") {
    return "No incidents yet. Alerts that share an IP, account, or host within 30 minutes group into one. Triage them from Alerts.";
  }
  return "No alerts on the board yet. Ingest a log or load demo data, then work the queue from Alerts.";
}
function boardSortSelect(current, onPick) {
  return el("span", { class: "row" },
    el("label", {}, "Sort",
      el("select", { "aria-label": "Sort board by severity or time", onchange: (ev) => onPick(ev.target.value) },
        el("option", { value: "severity", selected: current !== "time" }, "Severity"),
        el("option", { value: "time", selected: current === "time" }, "Time"))));
}

// Board columns shared by the dashboard panel and the incidents page.
// j/k and Enter come from app.js: the board carries data-kbd-list and each card is a.bcard.
function incidentBoard(inc, alerts, perColumn, sortMode) {
  const cols = { open: [], investigating: [], resolved: [] };
  if (inc.state === "ok") {
    for (const i of inc.list) cols[boardColumn(i.status)].push({
      href: `#incidents/${i.id}`, sev: i.severity, title: i.title, time: i.last_seen,
      meta: `${i.alert_count || 0} ${i.alert_count === 1 ? "alert" : "alerts"}`, tags: boardTags(i.tactics, i.top_technique),
    });
  } else {
    for (const a of alerts || []) cols[boardColumn(a.status)].push({
      href: `#alerts/${a.id}`, sev: a.severity, title: a.title, time: a.last_seen,
      meta: `${a.event_count} events · ${a.rule_id}`, tags: [],
    });
  }
  const order = queueOrder(sortMode);
  return Object.entries(cols).map(([name, items]) => {
    items.sort(order);
    return el("div", { class: `bcol bc-${name}` },
      el("div", { class: "bh" }, el("span", {}, name[0].toUpperCase() + name.slice(1)), el("b", {}, items.length)),
      ...items.slice(0, perColumn).map((c) => el("a", { class: `bcard sev-${sevOf(c.sev)}`, href: c.href },
        el("div", { class: "bt" }, c.title),
        el("div", { class: "bm" }, sevTag(c.sev), statusPill(name), el("span", {}, c.meta), relTime(c.time)),
        c.tags.length ? el("div", { class: "btags" }, ...c.tags.map((t) => (t.kind === "tech"
          ? el("span", { class: "tag tech", title: techniqueTagTitle(t) }, t.id)
          : el("span", { class: "tag" }, t.text)))) : null)),
      items.length > perColumn ? el("div", { class: "muted bmore" }, `+${items.length - perColumn} more`) : null,
      !items.length ? el("div", { class: "muted bmore" }, columnEmpty(name)) : null);
  });
}

async function socDashboard() {
  Dash.mount();
  await Dash.load();
}

// ---------- incidents pages ----------
async function incidentsView() {
  await Live.refreshIncidents();
  const inc = Live.incidents;
  const alerts = inc.state === "ok" ? [] : await api("/api/alerts?limit=200");
  const sort = Dash.queueSort === "time" ? "time" : "severity";
  render(
    el("div", { class: "page-head" }, el("h1", {}, "Incidents"),
      inc.state === "ok" ? null : chip("INCIDENTS PENDING · SHOWING ALERTS", "pendingchip"),
      boardSortSelect(sort, (mode) => { Dash.queueSort = mode; incidentsView(); })),
    inc.state !== "ok" ? el("p", { class: "muted" }, inc.state === "error" ? inc.error
      : "Alerts become incidents once the correlation engine ships (GET /api/incidents). Until then this board groups alerts by status.") : null,
    el("div", { class: "board big", "data-kbd-list": "incidents" }, ...incidentBoard(inc, alerts, 50, sort)));
  restoreSelection(`[data-kbd-list] a.bcard[href="#incidents/${state.restore}"]`);
}
