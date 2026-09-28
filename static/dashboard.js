"use strict";
// SOC dashboard, status strip, and the live stream client.
// Live updates come from GET /api/stream (Server-Sent Events). If the stream fails, the
// client polls every 3 seconds and retries the stream every 30. Routes that other
// workstreams add (/api/incidents, /api/attack/coverage, /api/storyline/status) are
// optional: a 404 renders a "pending" panel and the rest keeps working.
// Uses el(), api(), can(), go(), render(), fmtTime() from app.js (loaded after this file,
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
const clock = (ts) => (ts ? String(ts).slice(11, 19) : "--:--:--");
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
      entities: parseMaybeJson(i.entities ?? i.entity_summary) || {}, synthetic: i.synthetic,
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
    covered: t.covered,  // A: true only when an enabled rule covers the technique
  }));
}
const tacticKey = (name) => String(name).toLowerCase().replace(/[^a-z]/g, "");
function boardColumn(status) {
  const s = String(status).toLowerCase();
  if (["resolved", "closed", "false_positive", "benign"].includes(s)) return "resolved";
  if (["investigating", "contained", "in_progress", "triage", "acknowledged"].includes(s)) return "investigating";
  return "open";
}

// ---------- synthetic geo cache ----------
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
    this.timers.poll = setInterval(poll, 3000);
    this.timers.retry = setTimeout(() => { this.stopPolling(); this.connect(); }, 30000);
  },
  stopPolling() {
    clearInterval(this.timers.poll); clearTimeout(this.timers.retry);
    delete this.timers.poll; delete this.timers.retry;
  },
  setMode(mode) {
    this.mode = mode;
    const pill = $("#k-live");
    if (!pill) return;
    pill.dataset.mode = mode;
    $("#k-live-text").textContent = { live: "LIVE · SSE", poll: "POLLING 3s", reconnecting: "RECONNECTING", off: "OFFLINE" }[mode] || mode;
    if (Dash.mounted) Dash.renderHealth();
  },

  onEvents(events, count) {
    this.bumpEpm(count);
    if (this.summary) this.summary.events_total += count;
    for (const e of events) this.lastEventId = Math.max(this.lastEventId, e.id || 0);
    this.renderStrip();
    if (Dash.mounted) Dash.enqueue(events);
    if (events.some((e) => e.synthetic)) $("#k-synth").hidden = false;
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
      $("#k-synth").hidden = !d.synthetic_events;
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
    mountSvg($("#k-epm-spark"), WPCharts.sparkline(vals, { w: 84, h: 22, cls: "accent", label: "events per minute, last 30 minutes" }));
  },
  renderStrip() {
    const d = this.summary;
    if (d) {
      $("#k-open").textContent = fmtN(d.alerts_open + d.alerts_investigating);
      $("#k-crit").textContent = fmtN(d.alerts_critical_open);
      $("#k-crit").parentElement.classList.toggle("hot", d.alerts_critical_open > 0);
      $("#k-events").textContent = fmtN(d.events_total);
    }
    const inc = this.incidents;
    const kInc = $("#k-inc");
    if (inc.state === "ok") { kInc.textContent = fmtN(inc.list.filter((i) => boardColumn(i.status) !== "resolved").length); kInc.title = ""; }
    else if (inc.state === "pending") { kInc.textContent = "pending"; kInc.title = "Incidents arrive with the correlation engine (/api/incidents)"; }
    kInc.classList.toggle("dim", inc.state !== "ok");
    $("#k-epm").textContent = fmtN(this.rollingEpm());
    this.renderSpark();
    const checks = Object.entries(this.health);
    $("#k-health").replaceChildren(...(checks.length ? checks.map(([name, s]) =>
      el("span", { class: `hc st-${s}`, title: `${name}: ${s}` }, el("i"), { storage: "store", ingestion: "ingest", detection: "detect", dependencies: "deps" }[name] || name)) : [el("span", { class: "muted" }, "…")]));
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

  mount() {
    this.unmount();
    this.mounted = true;
    this.mapSize = null;
    this.feedCount = 0;
    const pause = el("button", { class: "mini ghost", id: "feed-pause", onclick: () => this.togglePause() }, "Pause");
    render(el("div", { class: "soc", id: "soc" },
      panel("p-map", "Attack map", [chip("SYNTHETIC GEO", "synthetic"), el("span", { class: "muted", id: "map-count" })],
        el("div", { class: "mapwrap", id: "map" }),
        el("div", { class: "map-side", id: "map-side" }),
        el("div", { class: "map-legend" }, ...["critical", "high", "medium", "low"].map((s) => el("span", {}, el("i", { class: `dot sev-${s}` }), s)),
          el("span", {}, el("i", { class: "dot hq" }), "HQ target"))),
      panel("p-feed", "Live event stream", [el("span", { class: "muted", id: "feed-rate" }), pause],
        el("div", { class: "feed-head" }, el("span", {}, "TIME"), el("span", {}, "SEV"), el("span", {}, "TYPE"), el("span", {}, "SOURCE → TARGET")),
        el("div", { class: "feed", id: "feed", onmouseenter: () => this.hover(true), onmouseleave: () => this.hover(false) })),
      panel("p-timeline", "Alerts over time", [el("span", { class: "muted", id: "tl-bucket" })], el("div", { class: "chartbox", id: "tl-chart" }),
        el("div", { class: "legend" }, ...["critical", "high", "medium", "low"].map((s) => el("span", {}, el("i", { class: `dot sev-${s}` }), s)),
          el("span", {}, el("i", { class: "dot volume" }), "event volume"))),
      panel("p-attackers", "Top attacker IPs", [el("span", { class: "muted" }, "by evidence events")], el("div", { class: "chartbox", id: "atk-chart" })),
      panel("p-attack", "MITRE ATT&CK coverage", [el("span", { class: "muted", id: "attack-meta" })], el("div", { class: "chartbox", id: "attack-chart" })),
      panel("p-board", "Incident board", [el("span", { id: "board-meta" })], el("div", { class: "board", id: "board" })),
      panel("p-rules", "Top rules", [el("span", { class: "muted" }, "alerts all time")], el("div", { class: "chartbox", id: "rules-chart" })),
      panel("p-health", "Health", [el("a", { href: "#health", class: "muted" }, "details →")], el("div", { id: "health-body" })),
    ));
    this.timers.drip = setInterval(() => this.drip(), 110);
    this.timers.details = setInterval(() => this.loadHealthDetails(), 30000);
    const soc = $("#soc");
    if (window.ResizeObserver && soc) {
      const onResize = debounce(() => this.redraw(), 150);
      this.observer = new ResizeObserver(onResize);
      this.observer.observe(soc);
    }
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
    if (!this.feedCount) this.fillFeed(d.recent_events);
    const ips = [...d.attackers.map((a) => a.ip), ...d.recent_events.map((e) => e.src_ip), ...d.recent_events.map((e) => e.dest_ip), "10.0.0.10"].filter(Boolean);
    this.redraw();
    if (await Geo.resolve(ips)) this.renderMarks();
    this.renderAttackers();
  },
  redraw() {
    if (!this.mounted || !this.data) return;
    this.renderMap(); this.renderTimeline(); this.renderAttackers(); this.renderRules(); this.renderMatrix(); this.renderBoard(); this.renderHealth();
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
      mountSvg(box, WPMap.baseMap(mw, mh));
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
    const unknown = [], internal = [];
    for (const s of this.sources()) {
      const loc = Geo.get(s.ip);
      if (loc === undefined) continue;
      if (loc === null) { unknown.push(s); continue; }
      if (loc.internal) { internal.push(s); continue; }
      const c = cities.get(loc.city) || { ...loc, ips: [], events: 0, sev: "info" };
      c.ips.push(s.ip); c.events += s.events; c.sev = maxSev(c.sev, s.sev);
      cities.set(loc.city, c);
    }
    const ranked = [...cities.values()].sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || b.events - a.events);
    const esc = WPCharts.esc;
    let arcs = "", marks = "";
    ranked.forEach((c, i) => {
      arcs += `<path class="arc s-${c.sev}" pathLength="100" d="${WPMap.arcPath([c.lon, c.lat], [hq.lon, hq.lat], w, h)}"/>`;
      const [x, y] = WPMap.project(c.lon, c.lat, w, h);
      const r = 2.6 + Math.min(5, Math.log2(1 + c.events) * 0.8);
      marks += `<g class="mk sev-${c.sev}"><title>${esc(`${c.city} (synthetic geo)\n${c.ips.join(", ")}\n${c.events} events`)}</title>` +
        `<circle class="halo" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(r * 2.2).toFixed(1)}"/>` +
        `<circle class="core" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(1)}"/>` +
        (i < 7 ? `<text class="ml" x="${(x + r + 3).toFixed(1)}" y="${(y + 3).toFixed(1)}">${esc(c.city)}</text>` : "") + `</g>`;
    });
    const [hx, hy] = WPMap.project(hq.lon, hq.lat, w, h);
    marks += `<g class="hq"><title>${esc(`${hq.city} (synthetic geo)`)}</title><circle class="ring" cx="${hx.toFixed(1)}" cy="${hy.toFixed(1)}" r="9"/>` +
      `<circle class="core" cx="${hx.toFixed(1)}" cy="${hy.toFixed(1)}" r="3.6"/><text class="ml" x="${(hx + 8).toFixed(1)}" y="${(hy + 12).toFixed(1)}">HQ</text></g>`;
    setSvgChildren(svg.querySelector("g.arcs"), arcs);
    setSvgChildren(svg.querySelector("g.marks"), marks);
    $("#map-count").textContent = `${ranked.length} source locations · ${unknown.length} unknown`;

    const side = $("#map-side");
    const row = (s, where, cls) => el("div", { class: "ms-row" }, el("i", { class: `dot sev-${s.sev}` }), el("code", {}, s.ip), el("span", { class: cls || "" }, where));
    const top = this.sources().filter((s) => Geo.get(s.ip) && !Geo.get(s.ip).internal)
      .sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || b.events - a.events).slice(0, 5);
    side.replaceChildren(...[
      el("div", { class: "ms-h" }, "Top sources"),
      ...(top.length ? top.map((s) => row(s, Geo.get(s.ip).city)) : [el("div", { class: "muted" }, "No external sources yet")]),
      el("div", { class: "ms-h" }, `Unknown · no geo entry · ${unknown.length}`),
      ...(unknown.length ? unknown.slice(0, 4).map((s) => row(s, "unknown", "muted")) : [el("div", { class: "muted" }, "none")]),
      unknown.length > 4 ? el("div", { class: "muted" }, `+${unknown.length - 4} more`) : null,
      internal.length ? el("div", { class: "ms-h" }, `Internal sources · ${internal.length}`) : null].filter(Boolean));
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
    feed.replaceChildren(...events.slice(0, FEED_MAX).map((e) => this.feedRow(e, false)));
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
    if (rate) rate.textContent = `${fmtN(Live.rollingEpm())}/min${this.queue.length ? ` · ${this.queue.length} queued` : ""}`;
    if (this.paused || !this.queue.length) return;
    const feed = $("#feed");
    if (!feed) return;
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
    return el("div", { class: `fr sev-${s}${fresh ? " new" : ""}`, title: e.message || "" },
      el("span", { class: "ft" }, clock(e.ts)),
      sevTag(s),
      el("span", { class: "fy" }, e.event_type),
      el("span", { class: "fd" },
        e.src_ip ? el("code", {}, e.src_ip) : null, target ? el("span", { class: "arrow" }, " → ") : null,
        target ? el("span", { class: "fu" }, target) : null,
        e.message ? el("span", { class: "fm" }, ` ${e.message.replace(/^\[SYNTHETIC\]\s*/, "")}`) : null,
        e.synthetic ? el("span", { class: "syn" }, "SYN") : null));
  },
  alertRow(a) {
    const feed = $("#feed");
    if (!feed) return;
    const row = el("a", { class: `fr alert-row sev-${sevOf(a.severity)} new`, href: `#alerts/${a.id}` },
      el("span", { class: "ft" }, clock(a.last_seen)), sevTag(a.severity), el("span", { class: "fy" }, "▲ ALERT"),
      el("span", { class: "fd" }, el("b", {}, a.title), el("span", { class: "fm" }, ` ${a.rule_id}`)));
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
      label: "alerts over time by severity",
    }));
  },
  renderAttackers() {
    const box = $("#atk-chart");
    if (!box || !this.data) return;
    const rows = this.data.attackers.slice(0, 6).map((a) => {
      const loc = Geo.get(a.ip);
      return { label: a.ip, value: a.events, cls: sevOf(a.max_severity),
        sub: loc === undefined ? "…" : loc === null ? "unknown · no geo entry" : `${loc.city}${loc.internal ? "" : " · synthetic geo"}`,
        subCls: loc === null ? "unknown" : "", title: `${a.ip}: ${a.events} evidence events in ${a.alerts} alerts (${a.open_alerts} open)` };
    });
    if (!rows.length) { box.replaceChildren(el("p", { class: "empty-note" }, "No attacker IPs in alert evidence yet.")); return; }
    mountSvg(box, WPCharts.hbars(rows, { w: this.width("#atk-chart"), rowH: 25, labelW: 136, label: "top attacker IPs" }));
  },
  renderRules() {
    const box = $("#rules-chart");
    if (!box) return;
    const rows = this.data.top_rules.map((r) => ({ label: r.name || r.rule_id, sub: `${r.rule_id} · ${r.open} open`, value: r.alerts, cls: sevOf(r.severity) }));
    if (!rows.length) { box.replaceChildren(el("p", { class: "empty-note" }, "No rule has fired yet.")); return; }
    mountSvg(box, WPCharts.hbars(rows.slice(0, 7), { w: this.width("#rules-chart"), rowH: 25, labelW: 150, label: "alerts by rule" }));
  },

  // --- ATT&CK matrix ---
  async loadCoverage() {
    const r = await optional("/api/attack/coverage");
    this.coverage = r.state === "ok" ? { state: "ok", list: normCoverage(r.data) } : r;
    this.renderMatrix();
  },
  renderMatrix() {
    const box = $("#attack-chart");
    if (!box) return;
    const cov = this.coverage;
    const w = this.width("#attack-chart", 900);
    const byTactic = new Map(TACTICS.map(([name, short]) => [tacticKey(name), { name, short, cells: [] }]));
    if (cov.state === "ok") {
      for (const t of cov.list) {
        for (const tac of t.tactics.length ? t.tactics : ["Unmapped"]) {
          const key = tacticKey(tac);
          if (!byTactic.has(key)) byTactic.set(key, { name: tac, short: tac, cells: [] });
          byTactic.get(key).cells.push({ id: t.id, name: t.name, value: t.hits, covered: t.covered ?? t.rules.length > 0, rules: t.rules });
        }
      }
      for (const col of byTactic.values()) col.cells.sort((a, b) => b.value - a.value || a.id.localeCompare(b.id));
    }
    let columns = [...byTactic.values()];
    if (w < 900 && cov.state === "ok") columns = columns.filter((c) => c.cells.length);
    const meta = $("#attack-meta");
    if (cov.state === "ok") {
      const covered = cov.list.filter((t) => t.covered ?? t.rules.length > 0).length;
      const hot = cov.list.filter((t) => t.hits > 0).length;
      meta.textContent = `${covered}/${cov.list.length} techniques covered · ${hot} observed`;
      mountSvg(box, WPCharts.heatMatrix(columns, { w, cellH: 21, maxRows: Math.max(3, Math.min(7, ...[Math.max(...columns.map((c) => c.cells.length))])), label: "ATT&CK coverage heat matrix" }));
      return;
    }
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
    box.replaceChildren(...incidentBoard(Live.incidents, this.data ? this.data.alerts : [], 5));
    const meta = $("#board-meta");
    meta.replaceChildren(Live.incidents.state === "ok" ? el("a", { href: "#incidents", class: "muted" }, "all incidents →")
      : chip(Live.incidents.state === "loading" ? "LOADING" : "INCIDENTS PENDING · SHOWING ALERTS", "pendingchip"));
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
        el("span", { class: `hc st-${s}` }, el("i")), el("b", {}, name), el("span", { class: "muted hmsg" }, msg), el("span", { class: "hms" }, ms === null ? "" : `${ms} ms`))),
      el("div", { class: "hrow2" }, el("span", { class: `hc st-${Live.mode === "live" ? "ok" : Live.mode === "poll" ? "degraded" : "failing"}` }, el("i")),
        el("b", {}, "stream"), el("span", { class: "muted hmsg" }, `${$("#k-live-text").textContent}${Live.subscribers ? ` · ${Live.subscribers} viewer(s)` : ""}`), el("span", { class: "hms" }, "")),
      runs.length ? el("div", { class: "runs" }, el("span", { class: "muted" }, "detection runs"),
        el("span", { class: "rundots" }, ...runs.map((r) => el("i", { class: `st-${r.status === "ok" ? "ok" : r.status === "failed" ? "failing" : "degraded"}`, title: `#${r.id} ${r.trigger} · ${r.status} · ${r.events_scanned} scanned · +${r.alerts_created}` })))) : null].filter(Boolean));
  },
};

// Board columns shared by the dashboard panel and the incidents page.
function incidentBoard(inc, alerts, perColumn) {
  const cols = { open: [], investigating: [], resolved: [] };
  if (inc.state === "ok") {
    for (const i of inc.list) cols[boardColumn(i.status)].push({
      href: `#incidents/${i.id}`, sev: i.severity, title: i.title, time: i.last_seen, synthetic: i.synthetic,
      meta: `${i.alert_count || 0} alerts`, tags: i.tactics.slice(0, 4),
    });
  } else {
    for (const a of alerts || []) cols[boardColumn(a.status)].push({
      href: `#alerts/${a.id}`, sev: a.severity, title: a.title, time: a.last_seen, synthetic: a.synthetic,
      meta: `${a.event_count} events · ${a.rule_id}`, tags: [],
    });
  }
  const order = (x, y) => SEV_RANK[sevOf(y.sev)] - SEV_RANK[sevOf(x.sev)] || String(y.time).localeCompare(String(x.time));
  return Object.entries(cols).map(([name, items]) => {
    items.sort(order);
    return el("div", { class: `bcol bc-${name}` },
      el("div", { class: "bh" }, el("span", {}, name.toUpperCase()), el("b", {}, items.length)),
      ...items.slice(0, perColumn).map((c) => el("a", { class: `bcard sev-${sevOf(c.sev)}`, href: c.href },
        el("div", { class: "bt" }, c.title),
        el("div", { class: "bm" }, sevTag(c.sev), el("span", {}, c.meta), el("span", { class: "muted" }, ago(c.time)), c.synthetic ? el("span", { class: "syn" }, "SYN") : null),
        c.tags.length ? el("div", { class: "btags" }, ...c.tags.map((t) => el("span", { class: "tag" }, t))) : null)),
      items.length > perColumn ? el("div", { class: "muted bmore" }, `+${items.length - perColumn} more`) : null,
      !items.length ? el("div", { class: "muted bmore" }, "—") : null);
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
  render(
    el("div", { class: "page-head" }, el("h1", {}, "Incidents"),
      inc.state === "ok" ? el("span", { class: "muted" }, `${inc.list.length} incidents`) : chip("INCIDENTS PENDING · SHOWING ALERTS", "pendingchip")),
    inc.state !== "ok" ? el("p", { class: "muted" }, inc.state === "error" ? inc.error
      : "Alerts become incidents once the correlation engine ships (GET /api/incidents). Until then this board groups alerts by status.") : null,
    el("div", { class: "board big" }, ...incidentBoard(inc, alerts, 50)));
}
