"use strict";
// Watchpost UI shell and the classic views. All server data is rendered with textContent
// (via el()), never innerHTML. The SOC dashboard and live stream live in dashboard.js; its
// charts are SVG strings from charts.js/map.js with every text value escaped.

const state = { user: null, csrf: null, view: "dashboard", alertId: null };
const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };
const can = (role) => state.user && ROLE_RANK[state.user.role] >= ROLE_RANK[role];

// ---------- helpers ----------
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "style") Object.assign(node.style, v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = (sel) => document.querySelector(sel);
const fmtTime = (ts) => (ts ? ts.replace("T", " ").replace(/\.\d+Z$/, "Z") : "—");
const pill = (text, cls) => el("span", { class: `pill ${cls}` }, text);
const sev = (s) => pill(s, `sev-${s}`);
const status = (s) => pill(s, `st-${s}`);
const synth = (flag) => (flag ? pill("synthetic", "synthetic") : null);
const pct = (v) => (v === null || v === undefined ? "—" : `${Math.round(v * 100)}%`);

function toast(msg) {
  const t = el("div", { class: "toast", role: "status" }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 4000);
}

async function api(path, { method = "GET", body, raw, contentType, allow = [] } = {}) {
  const headers = {};
  if (method !== "GET" && state.csrf) headers["X-CSRF-Token"] = state.csrf;
  let payload;
  if (raw !== undefined) { payload = raw; headers["Content-Type"] = contentType || "text/plain"; }
  else if (body !== undefined) { payload = JSON.stringify(body); headers["Content-Type"] = "application/json"; }
  const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && path !== "/api/auth/login") { showLogin(); throw new Error("Session expired"); }
  if (!res.ok && res.status !== 207 && !allow.includes(res.status)) {
    const err = new Error((data && data.error) || `HTTP ${res.status}`);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

function table(headers, rows, onClick) {
  return el("div", { class: "table-wrap" },
    el("table", {},
      el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
      el("tbody", {}, rows.length ? rows.map((r) =>
        el("tr", { class: [onClick ? "clickable" : "", r.cls || ""].join(" "), onclick: onClick ? () => onClick(r) : null },
          r.cells.map((c) => (c && c.num !== undefined ? el("td", { class: "num" }, c.num) : el("td", {}, c)))))
        : el("tr", {}, el("td", { colspan: headers.length, class: "muted" }, "Nothing to show.")))));
}

function render(...nodes) {
  const view = $("#view");
  view.replaceChildren(...nodes.flat().filter((n) => n !== null && n !== undefined && n !== false));
}

async function guarded(fn) {
  try { await fn(); } catch (e) { if (e.message !== "Session expired") toast(e.message); }
}

// ---------- auth ----------
function showLogin() {
  state.user = null; state.csrf = null;
  Live.stop();
  document.body.classList.remove("authed");
  $("#login-view").hidden = false;
  $("#rail").hidden = true; $("#strip").hidden = true; $("#who").hidden = true;
  render();
}

async function boot() {
  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    $("#login-error").textContent = "";
    try {
      const data = await api("/api/auth/login", { method: "POST", body: { username: f.get("username"), password: f.get("password") } });
      ev.target.reset();
      onLogin(data);
    } catch (e) { $("#login-error").textContent = e.message; }
  });
  $("#logout").addEventListener("click", async () => { await api("/api/auth/logout", { method: "POST" }).catch(() => {}); showLogin(); });
  document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => go(b.dataset.view)));
  window.addEventListener("hashchange", () => route());
  try { onLogin(await api("/api/auth/me")); } catch { showLogin(); }
}

function onLogin(data) {
  state.user = data.user; state.csrf = data.csrf_token;
  $("#login-view").hidden = true;
  document.body.classList.add("authed");
  $("#rail").hidden = false; $("#strip").hidden = false; $("#who").hidden = false;
  $("#who-name").textContent = `${data.user.username} · ${data.user.role}`;
  document.querySelectorAll("#nav [data-role]").forEach((b) => { b.hidden = !can(b.dataset.role); });
  route();
  refreshBanner();
  Live.start();
}

function go(view, id) { location.hash = id ? `${view}/${id}` : view; }

function route() {
  if (!state.user) return;
  const [view, id] = (location.hash.slice(1) || "dashboard").split("/");
  state.view = view;
  document.body.dataset.view = view;
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  if (view !== "dashboard") Dash.unmount();
  const views = { dashboard: socDashboard, incidents: () => (id ? incidentDetail(Number(id)) : incidentsView()),
    alerts: () => (id ? alertDetail(Number(id)) : alerts()), events, overview, ingest, rules, health, admin };
  guarded(views[view] || socDashboard);
}

async function refreshBanner() {
  try {
    const h = await api("/api/health", { allow: [503] });  // 503 = failing, still a valid report
    const b = $("#banner");
    const bad = Object.entries(h.checks).filter(([, s]) => s !== "ok");
    b.hidden = h.status === "ok";
    b.className = `banner ${h.status === "failing" ? "bad" : ""}`;
    b.replaceChildren(`System ${h.status}: ${bad.map(([n, s]) => `${n} ${s}`).join(", ")}. `,
      el("a", { href: "#health" }, "Open Health for details and recovery steps."));
  } catch {
    const b = $("#banner");
    b.hidden = false;
    b.className = "banner bad";
    b.textContent = "Cannot reach the Watchpost health endpoint. The server may be down.";
  }
}

// ---------- metrics overview (the 1.0 dashboard) ----------
async function overview() {
  const m = await api("/api/metrics");
  const kpi = (v, l) => el("div", { class: "kpi" }, el("div", { class: "v" }, v ?? "—"), el("div", { class: "l" }, l));
  const hist = m.activity_last_24h_of_data;
  const max = Math.max(1, ...hist.map((h) => h.events));
  const bars = el("div", { class: "bars", "aria-label": "Events per hour" }, hist.map((h) =>
    el("div", { class: "b", title: `${fmtTime(h.hour)} — ${h.events} events, ${h.failures} failed logins` },
      el("span", { class: "fail", style: { height: `${(h.failures / max) * 110}px` } }),
      el("span", { class: "all", style: { height: `${((h.events - h.failures) / max) * 110}px` } }))));
  const hbars = (rows, key) => {
    const top = Math.max(1, ...rows.map((r) => r.count));
    return rows.length ? rows.map((r) => el("div", { class: "hbar" }, el("span", { class: "mono" }, r[key]),
      el("div", { class: "track" }, el("div", { class: "fill", style: { width: `${(r.count / top) * 100}%` } })),
      el("span", { class: "num" }, r.count))) : el("p", { class: "muted" }, "No data yet.");
  };
  const empty = m.events_total === 0 ? el("div", { class: "card" },
    el("h2", {}, "No events yet"),
    el("p", {}, "Load the labeled synthetic dataset (Admin → Demo data), upload a log file (Ingest), or POST to /api/ingest."),
    can("admin") ? el("button", { onclick: () => go("admin") }, "Go to demo data") : null) : null;

  render(
    el("h1", {}, "Metrics overview"),
    empty,
    el("div", { class: "kpis" },
      kpi(m.alerts_open, "Open alerts"), kpi(m.alerts_investigating, "Investigating"),
      kpi(m.alerts_resolved, "Resolved"),
      kpi(m.mean_time_to_resolve_minutes === null ? "—" : `${m.mean_time_to_resolve_minutes}m`, "Mean time to resolve"),
      kpi(m.events_total.toLocaleString(), "Events stored"),
      kpi(m.synthetic_events.toLocaleString(), "of which synthetic")),
    el("div", { class: "card" },
      el("div", { class: "row", style: { justifyContent: "space-between" } },
        el("h2", {}, "Activity — 24 hours ending at the newest event"),
        el("div", { class: "legend" }, el("span", {}, el("i", { class: "all" }), "other events"),
          el("span", {}, el("i", { class: "fail" }), "failed logins"))),
      bars,
      el("div", { class: "axis" }, el("span", {}, fmtTime(hist[0]?.hour)), el("span", {}, fmtTime(hist[hist.length - 1]?.hour)))),
    el("div", { class: "grid" },
      el("div", { class: "card" }, el("h2", {}, "Open alerts by severity"),
        hbars(["critical", "high", "medium", "low"].map((s) => ({ severity: s, count: (m.alerts_by_severity.find((x) => x.severity === s) || {}).count || 0 })), "severity")),
      el("div", { class: "card" }, el("h2", {}, "Alerts by rule (all time)"), hbars(m.alerts_by_rule, "rule_id")),
      el("div", { class: "card" }, el("h2", {}, "Top failed-login sources"), hbars(m.top_failure_ips, "src_ip")),
      el("div", { class: "card" }, el("h2", {}, "Most targeted accounts"), hbars(m.top_failure_users, "user")),
      el("div", { class: "card" }, el("h2", {}, "Analyst verdicts"), hbars(m.dispositions, "disposition")),
      el("div", { class: "card" }, el("h2", {}, "Events by type"), hbars(m.events_by_type, "event_type"))),
  );
}

// ---------- alerts ----------
async function alerts() {
  const params = new URLSearchParams(sessionStorage.getItem("alertFilter") || "status=open,investigating");
  const form = el("form", { class: "row card" },
    el("label", {}, "Status", el("select", { name: "status" },
      [["open,investigating", "Active"], ["open", "Open"], ["investigating", "Investigating"], ["resolved", "Resolved"], ["", "All"]]
        .map(([v, t]) => el("option", { value: v, selected: params.get("status") === v || (!params.get("status") && v === "") }, t)))),
    el("label", {}, "Severity", el("select", { name: "severity" },
      ["", "critical", "high", "medium", "low"].map((v) => el("option", { value: v, selected: params.get("severity") === v }, v || "Any")))),
    el("button", { type: "submit" }, "Filter"));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const p = new URLSearchParams();
    for (const [k, v] of new FormData(form)) if (v) p.set(k, v);
    try { sessionStorage.setItem("alertFilter", p.toString()); } catch { /* ignore */ }
    guarded(alerts);
  });
  const list = await api(`/api/alerts?${params}`);
  render(el("h1", {}, "Alerts"), form, el("div", { class: "card" }, table(
    ["Severity", "Alert", "Rule", "Status", "Events", "Last seen", ""],
    list.map((a) => ({ id: a.id, cells: [sev(a.severity), a.title, el("code", {}, a.rule_id),
      el("span", {}, status(a.status), a.disposition ? ` ${a.disposition.replace("_", " ")}` : ""),
      { num: a.event_count }, fmtTime(a.last_seen), synth(a.synthetic)] })),
    (r) => go("alerts", r.id))));
}

async function alertDetail(id) {
  const a = await api(`/api/alerts/${id}`);
  const actions = el("div", { class: "row" });
  if (can("analyst")) {
    if (a.status === "open") actions.append(el("button", { onclick: () => setStatus(id, { status: "investigating" }) }, "Start investigating"));
    if (a.status !== "resolved") actions.append(el("button", { onclick: () => resolveDialog(id) }, "Resolve…"));
    else actions.append(el("button", { class: "ghost", onclick: () => setStatus(id, { status: "open" }) }, "Reopen"));
  }
  const noteForm = can("analyst") ? el("form", {},
    el("textarea", { name: "body", maxlength: 5000, required: true, placeholder: "Add an investigation note…" }),
    el("button", { type: "submit" }, "Add note")) : null;
  noteForm?.addEventListener("submit", (ev) => {
    ev.preventDefault();
    guarded(async () => {
      await api(`/api/alerts/${id}/notes`, { method: "POST", body: { body: new FormData(noteForm).get("body") } });
      alertDetail(id);
    });
  });

  render(
    el("p", {}, el("a", { href: "#alerts" }, "← All alerts")),
    el("div", { class: "split" },
      el("div", {},
        el("div", { class: "card" },
          el("div", { class: "row" }, sev(a.severity), status(a.status), synth(a.synthetic)),
          el("h1", { style: { marginTop: "8px" } }, a.title),
          el("div", { class: "explain" }, el("strong", {}, "Why this fired: "), a.explanation),
          el("p", { class: "muted" }, `Rule: ${a.rule?.name ?? a.rule_id} (v${a.rule_version}). ${a.rule?.description ?? ""}`),
          actions),
        el("div", { class: "card" }, el("h2", {}, `Evidence (${a.evidence.length} events)`),
          table(["Time", "Type", "User", "Source IP", "Host", "Message"],
            a.evidence.map((e) => ({ cells: [fmtTime(e.ts), e.event_type, e.user ?? "—", el("code", {}, e.src_ip ?? "—"), e.host ?? "—", e.message ?? ""] })))),
        el("div", { class: "card" }, el("h2", {}, "Related timeline"),
          el("p", { class: "muted" }, "Every event involving these IPs or accounts from 30 minutes before to 30 minutes after. Highlighted rows are evidence."),
          table(["Time", "Type", "User", "Source IP", "Source", "Message"],
            a.timeline.map((e) => ({ cls: e.is_evidence ? "evidence" : "", cells: [fmtTime(e.ts), e.event_type, e.user ?? "—", el("code", {}, e.src_ip ?? "—"), e.source, e.message ?? ""] }))))),
      el("div", {},
        el("div", { class: "card" }, el("h2", {}, "Details"), el("dl", { class: "kv" },
          ...[["Alert", `#${a.id}`], ["Group", a.group_key], ["First seen", fmtTime(a.first_seen)], ["Last seen", fmtTime(a.last_seen)],
            ["Assignee", a.assignee ?? "—"], ["Verdict", a.disposition ?? "—"], ["Resolved", fmtTime(a.resolved_at)]]
            .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]))),
        el("div", { class: "card" }, el("h2", {}, "Notes"),
          a.notes.length ? a.notes.map((n) => el("div", { class: "note" }, el("div", { class: "muted" }, `${n.author} · ${fmtTime(n.created_at)}`), el("div", {}, n.body)))
            : el("p", { class: "muted" }, "No notes yet."),
          noteForm),
        el("div", { class: "card" }, el("h2", {}, "Activity"),
          a.activity.map((x) => el("div", { class: "note" }, el("span", { class: "muted" }, `${fmtTime(x.created_at)} · ${x.actor} `), `${x.action.replace("_", " ")}${x.detail ? ` — ${x.detail}` : ""}`))))),
  );
}

async function setStatus(id, body) {
  await guarded(async () => { await api(`/api/alerts/${id}/status`, { method: "POST", body }); alertDetail(id); });
}

function resolveDialog(id) {
  const form = el("form", {},
    el("h2", {}, "Resolve alert"),
    el("label", {}, "Verdict (feeds rule performance tracking)", el("select", { name: "disposition", required: true },
      el("option", { value: "true_positive" }, "True positive — real malicious activity"),
      el("option", { value: "false_positive" }, "False positive — rule fired on legitimate activity"),
      el("option", { value: "benign" }, "Benign — real but expected/authorized"))),
    el("label", {}, "Resolution note", el("textarea", { name: "note", maxlength: 5000 })),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Resolve"),
      el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    $("#modal").close();
    setStatus(id, { status: "resolved", disposition: f.get("disposition"), note: f.get("note") || null });
  });
  $("#modal-body").replaceChildren(form);
  $("#modal").showModal();
}

// ---------- events ----------
async function events(offset = 0) {
  const saved = new URLSearchParams(sessionStorage.getItem("eventFilter") || "");
  const field = (name, label, attrs = {}) => el("label", {}, label, el("input", { name, value: saved.get(name) || "", ...attrs }));
  const form = el("form", { class: "card" },
    el("div", { class: "row" },
      field("start", "From (UTC)", { placeholder: "2026-09-15T00:00:00Z", size: 20 }),
      field("end", "To (UTC)", { placeholder: "2026-09-16T00:00:00Z", size: 20 }),
      field("source", "Source", { placeholder: "demo:*", size: 12 }),
      field("user", "User", { size: 10 }),
      field("ip", "IP (src or dest)", { size: 13 }),
      el("label", {}, "Event type", el("select", { name: "event_type" },
        ["", "auth_failure", "auth_success", "account_lockout", "user_created", "privilege_use", "process_start", "network_connection", "file_access", "other"]
          .map((v) => el("option", { value: v, selected: saved.get("event_type") === v }, v || "Any")))),
      el("label", {}, "Min severity", el("select", { name: "severity" },
        ["", "low", "medium", "high", "critical"].map((v) => el("option", { value: v, selected: saved.get("severity") === v }, v || "Any")))),
      field("q", "Message contains", { size: 14 }),
      el("label", {}, "Data", el("select", { name: "synthetic" },
        [["", "All"], ["0", "Real only"], ["1", "Synthetic only"]].map(([v, t]) => el("option", { value: v, selected: saved.get("synthetic") === v }, t)))),
      el("button", { type: "submit" }, "Search"),
      el("button", { type: "button", class: "ghost", onclick: () => { sessionStorage.removeItem("eventFilter"); guarded(() => events()); } }, "Clear")));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const p = new URLSearchParams();
    for (const [k, v] of new FormData(form)) if (v) p.set(k, v.trim());
    try { sessionStorage.setItem("eventFilter", p.toString()); } catch { /* ignore */ }
    guarded(() => events(0));
  });
  const query = new URLSearchParams(saved);
  if (query.get("severity")) query.set("severity_mode", "min");
  query.set("limit", "100"); query.set("offset", String(offset));
  let data;
  try { data = await api(`/api/events?${query}`); }
  catch (e) { render(el("h1", {}, "Event search"), form, el("p", { class: "error" }, e.message)); return; }
  const pager = el("div", { class: "row" },
    el("span", { class: "muted" }, `${data.total.toLocaleString()} matching events · showing ${data.total ? offset + 1 : 0}–${offset + data.events.length}`),
    el("button", { class: "ghost", disabled: offset === 0, onclick: () => guarded(() => events(Math.max(0, offset - 100))) }, "Newer"),
    el("button", { class: "ghost", disabled: offset + 100 >= data.total, onclick: () => guarded(() => events(offset + 100)) }, "Older"));
  render(el("h1", {}, "Event search"), form, el("div", { class: "card" }, pager,
    table(["Time", "Severity", "Type", "User", "Source IP", "Host", "Source", "Message"],
      data.events.map((e) => ({ id: e.id, cells: [fmtTime(e.ts), sev(e.severity), e.event_type, e.user ?? "—", el("code", {}, e.src_ip ?? "—"), e.host ?? "—", el("span", {}, e.source, " ", synth(e.synthetic)), e.message ?? ""] })),
      (r) => guarded(() => eventDialog(r.id)))));
}

async function eventDialog(id) {
  const e = await api(`/api/events/${id}`);
  $("#modal-body").replaceChildren(
    el("h2", {}, `Event #${e.id}`),
    el("dl", { class: "kv" }, ...["ts", "ingested_at", "source", "host", "event_type", "outcome", "severity", "user", "src_ip", "dest_ip", "batch_id"]
      .flatMap((k) => [el("dt", {}, k), el("dd", {}, e[k] ?? "—")]), el("dt", {}, "synthetic"), el("dd", {}, e.synthetic ? "yes (demo data)" : "no")),
    el("h3", {}, "Linked alerts"),
    e.alerts.length ? e.alerts.map((a) => el("div", {}, el("a", { href: `#alerts/${a.id}`, onclick: () => $("#modal").close() }, `#${a.id} ${a.title}`), " ", status(a.status)))
      : el("p", { class: "muted" }, "None."),
    el("h3", {}, "Original record (secrets redacted)"), el("pre", {}, e.raw ?? ""),
    el("p", {}, el("button", { onclick: () => $("#modal").close() }, "Close")));
  $("#modal").showModal();
}

// ---------- ingest ----------
async function ingest() {
  const batches = await api("/api/ingest/batches");
  const scenarios = await api("/api/demo/scenarios");
  const result = el("div");
  const upload = el("form", { class: "card" },
    el("h2", {}, "Upload a log file"),
    el("div", { class: "row" },
      el("label", {}, "File", el("input", { type: "file", name: "file", required: true, accept: ".log,.txt,.json,.jsonl,.csv" })),
      el("label", {}, "Format", el("select", { name: "format" }, ["auto", "authlog", "json", "jsonl", "csv"].map((f) => el("option", { value: f }, f)))),
      el("label", {}, "Source name", el("input", { name: "source", value: "upload", pattern: "[A-Za-z0-9_.:\\-]{1,64}", required: true })),
      el("label", {}, "Year (BSD syslog)", el("input", { name: "year", type: "number", min: 2000, max: 2100, placeholder: "auto" })),
      el("label", { style: { flexDirection: "row", alignItems: "center" } }, el("input", { type: "checkbox", name: "synthetic", value: "1" }), "Mark as synthetic"),
      el("button", { type: "submit", disabled: !can("analyst") }, "Ingest")),
    el("p", { class: "muted" }, "Samples live in samples/ (all synthetic). Max 5 MB per upload."),
    result);
  upload.addEventListener("submit", (ev) => {
    ev.preventDefault();
    guarded(async () => {
      const f = new FormData(upload);
      const file = f.get("file");
      const q = new URLSearchParams({ format: f.get("format"), source: f.get("source") });
      if (f.get("year")) q.set("year", f.get("year"));
      if (f.get("synthetic")) q.set("synthetic", "1");
      let r;
      try { r = await api(`/api/ingest/upload?${q}`, { method: "POST", raw: await file.text(), contentType: "text/plain" }); }
      catch (e) { r = e.data; if (!r || r.accepted === undefined) throw e; }
      result.replaceChildren(ingestSummary(r));
      refreshBanner();
    });
  });

  const sim = el("form", { class: "card" },
    el("h2", {}, "Replay an attack simulation"),
    el("p", { class: "muted" }, "Writes labeled synthetic events (RFC 5737 documentation IPs) into this instance only. Nothing is sent to other systems."),
    el("div", { class: "row" },
      el("label", {}, "Scenario", el("select", { name: "scenario" }, scenarios.map((s) => el("option", { value: s.name }, `${s.name} — ${s.malicious ? "malicious" : "benign"}`)))),
      el("button", { type: "submit", disabled: !can("analyst") }, "Replay")),
    el("ul", { class: "muted" }, scenarios.map((s) => el("li", {}, el("code", {}, s.name), `: ${s.description}`, s.expected_rules.length ? ` Expected: ${s.expected_rules.join(", ")}.` : " Expected: no alerts."))));
  const simResult = el("div");
  sim.append(simResult);
  sim.addEventListener("submit", (ev) => {
    ev.preventDefault();
    guarded(async () => {
      const r = await api("/api/demo/simulate", { method: "POST", body: { scenario: new FormData(sim).get("scenario") } });
      simResult.replaceChildren(ingestSummary(r));
      refreshBanner();
    });
  });

  render(
    el("h1", {}, "Ingest"),
    el("div", { class: "grid" }, upload, sim),
    el("div", { class: "card" }, el("h2", {}, "Ingest API"),
      el("p", {}, "Create a token under Admin → API tokens, then:"),
      el("pre", {}, `curl -X POST http://127.0.0.1:8080/api/ingest \\
  -H "Authorization: Bearer $SIEM_INGEST_TOKEN" -H "Content-Type: application/json" \\
  -d '{"source":"vpn01","events":[{"timestamp":"2026-09-15T14:00:00Z","type":"login_failed","user":"alice","src_ip":"203.0.113.7"}]}'`),
      el("p", { class: "muted" }, "Responses: 201 all accepted · 207 partially accepted (see rejections) · 422 none accepted · 400 malformed · 401/403 auth. Full schema in docs/API.md.")),
    el("div", { class: "card" }, el("h2", {}, "Recent batches"),
      table(["Received", "Source", "Format", "Accepted", "Rejected", "Detection", "By", "Rejection reasons"],
        batches.map((b) => ({ cells: [fmtTime(b.created_at), el("span", {}, b.source, " ", synth(b.synthetic)), b.format, { num: b.accepted }, { num: b.rejected },
          pill(b.detection_status, { ok: "st-ok", recovered: "st-ok", failed: "st-failing" }[b.detection_status] || "st-degraded"),
          b.submitted_by, b.errors.slice(0, 3).map((e) => `#${e.index}: ${e.reason}`).join("; ") + (b.errors.length > 3 ? ` (+${b.errors.length - 3} more)` : "")] })))),
  );
}

function ingestSummary(r) {
  const d = r.detection || {};
  return el("div", { class: "explain" },
    el("div", {}, `Accepted ${r.accepted}, rejected ${r.rejected}. Detection: ${d.status}${d.error ? ` — ${d.error}` : ""}. Alerts created ${d.alerts_created ?? 0}, updated ${d.alerts_updated ?? 0}.`),
    r.rejections?.length ? el("ul", {}, r.rejections.slice(0, 10).map((x) => el("li", {}, `Record ${x.index}: ${x.reason}`))) : null);
}

// ---------- rules ----------
async function rules() {
  const [list, changes, settings, evals] = await Promise.all([api("/api/rules"), api("/api/changes"), api("/api/settings"), api("/api/evaluations")]);
  const pending = changes.filter((c) => c.status === "pending");
  const ruleCards = list.map((r) => {
    const p = r.performance || {};
    const ev = r.evaluation;
    return el("div", { class: "card" },
      el("div", { class: "row", style: { justifyContent: "space-between" } },
        el("h2", {}, r.name), el("span", {}, sev(r.severity), " ", r.enabled ? pill("enabled", "st-ok") : pill("disabled", "st-rejected"))),
      el("p", { class: "muted" }, r.description),
      el("div", { class: "grid" },
        el("div", {}, el("h3", {}, `Parameters (v${r.version})`), el("pre", {}, JSON.stringify(r.params, null, 2))),
        el("div", {},
          el("h3", {}, "Analyst feedback"),
          el("dl", { class: "kv" }, ...[["Alerts", p.total], ["Open / investigating", `${p.open} / ${p.investigating}`], ["True positives", p.tp], ["False positives", p.fp], ["Benign", p.benign], ["Precision (TP / (TP+FP))", pct(p.precision)]]
            .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v ?? 0)])),
          el("h3", {}, "Latest scenario evaluation"),
          ev ? el("dl", { class: "kv" }, ...[["Detected", ev.detected.join(", ") || "—"], ["Missed", ev.missed.join(", ") || "none"], ["False positives on", ev.false_positives.join(", ") || "none"], ["Recall", pct(ev.recall)], ["Precision", pct(ev.precision)]]
            .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])) : el("p", { class: "muted" }, "Not evaluated yet — use 'Run evaluation'."))),
      el("div", { class: "row" },
        can("analyst") ? el("button", { class: "ghost", onclick: () => proposeDialog(r) }, "Propose change…") : null,
        el("button", { class: "ghost", onclick: () => guarded(() => historyDialog(r)) }, "History")));
  });

  const changeRows = changes.slice(0, 30).map((c) => ({ cells: [
    `#${c.id}`, status(c.status), el("code", {}, `${c.kind === "rule_update" ? "rule" : "setting"}:${c.target}`),
    el("pre", {}, JSON.stringify(c.payload)), c.reason,
    c.evaluation ? `FP ${c.evaluation.before.fp}→${c.evaluation.after.fp}, TP ${c.evaluation.before.tp}→${c.evaluation.after.tp}, missed ${c.evaluation.after.missed.join(", ") || "none"}` : "—",
    c.proposed_by, c.reviewed_by ? `${c.reviewed_by}${c.review_note ? `: ${c.review_note}` : ""}` : "—",
    c.status === "pending" && can("admin") ? el("span", { class: "row" },
      el("button", { disabled: c.proposed_by === state.user.username, title: c.proposed_by === state.user.username ? "A different admin must review your own proposal" : "", onclick: () => review(c.id, "approve") }, "Approve"),
      el("button", { class: "ghost", disabled: c.proposed_by === state.user.username, onclick: () => review(c.id, "reject") }, "Reject")) : "",
  ] }));

  render(
    el("h1", {}, "Detection rules"),
    el("div", { class: "card" },
      el("h2", {}, "How rules change"),
      el("p", {}, "Rules are fixed thresholds you can read and test. No machine learning. Changes to rules or security settings are proposals until a ",
        el("strong", {}, "different"), " admin approves them. Each proposal is scored against the labeled synthetic scenarios before review. Suggestions come from analyst verdicts: when at least two false positives share a cause, such as one IP or one account, Watchpost proposes an exclusion or a new threshold. It never applies the change itself."),
      el("div", { class: "row" },
        can("analyst") ? el("button", { onclick: () => guarded(async () => { const r = await api("/api/rules/suggestions", { method: "POST" }); toast(r.message); rules(); }) }, "Suggest improvements from feedback") : null,
        can("analyst") ? el("button", { class: "ghost", onclick: () => guarded(async () => { await api("/api/evaluations", { method: "POST" }); toast("Evaluation recorded"); rules(); }) }, "Run evaluation") : null,
        el("span", { class: "muted" }, evals[0] ? `Last evaluation ${fmtTime(evals[0].created_at)} (${evals[0].trigger})` : "No evaluations yet"))),
    el("div", { class: "card" }, el("h2", {}, `Change requests (${pending.length} pending)`),
      table(["ID", "Status", "Target", "Change", "Reason", "Scenario impact (before→after)", "Proposed by", "Reviewed", ""], changeRows)),
    ...ruleCards,
    el("div", { class: "card" }, el("h2", {}, "Security settings"),
      table(["Setting", "Value", "Allowed", "Last changed", ""], settings.map((s) => ({ cells: [
        el("span", {}, el("code", {}, s.key), el("div", { class: "muted" }, s.description)), s.value, `${s.min}–${s.max}`,
        `${fmtTime(s.updated_at)} by ${s.updated_by ?? "—"}`,
        can("admin") ? el("button", { class: "ghost", onclick: () => settingDialog(s) }, "Propose…") : ""] })))),
    el("div", { class: "card" }, el("h2", {}, "Evaluation history"),
      table(["When", "Trigger", "By", "Summary"], evals.map((e) => ({ cells: [fmtTime(e.created_at), e.trigger, e.created_by,
        Object.entries(e.results.rules).map(([id, r]) => `${id}: TP ${r.tp} FN ${r.fn} FP ${r.fp}`).join(" · ")] })))),
  );
}

async function review(id, decision) {
  const note = prompt(`${decision === "approve" ? "Approve" : "Reject"} change #${id}. Review note:`) ?? null;
  if (note === null) return;
  await guarded(async () => { await api(`/api/changes/${id}/review`, { method: "POST", body: { decision, note } }); toast(`Change #${id} ${decision}d`); rules(); });
}

function proposeDialog(rule) {
  const form = el("form", {},
    el("h2", {}, `Propose change: ${rule.id}`),
    el("label", {}, "Parameter changes (JSON; only the keys you want to change)", el("textarea", { name: "params", class: "mono" }, JSON.stringify(rule.params, null, 2))),
    el("label", {}, "Enabled", el("select", { name: "enabled" }, el("option", { value: "true", selected: !!rule.enabled }, "enabled"), el("option", { value: "false", selected: !rule.enabled }, "disabled"))),
    el("label", {}, "Reason (required)", el("textarea", { name: "reason", required: true, minlength: 5, maxlength: 2000 })),
    el("p", { class: "error", id: "propose-error" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Submit for review"), el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    const body = { reason: f.get("reason") };
    try {
      const params = JSON.parse(f.get("params"));
      const changed = Object.fromEntries(Object.entries(params).filter(([k, v]) => JSON.stringify(v) !== JSON.stringify(rule.params[k])));
      if (Object.keys(changed).length) body.params = changed;
      if ((f.get("enabled") === "true") !== !!rule.enabled) body.enabled = f.get("enabled") === "true";
      await api(`/api/rules/${rule.id}/proposals`, { method: "POST", body });
      $("#modal").close();
      toast("Proposal submitted for review");
      rules();
    } catch (e) { $("#propose-error").textContent = e instanceof SyntaxError ? "Parameters must be valid JSON" : e.message; }
  });
  $("#modal-body").replaceChildren(form);
  $("#modal").showModal();
}

function settingDialog(s) {
  const form = el("form", {},
    el("h2", {}, `Propose: ${s.key}`), el("p", { class: "muted" }, s.description),
    el("label", {}, `New value (${s.min}–${s.max})`, el("input", { name: "value", type: "number", min: s.min, max: s.max, value: s.value, required: true })),
    el("label", {}, "Reason", el("textarea", { name: "reason", required: true, minlength: 5 })),
    el("p", { class: "error", id: "setting-error" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Submit for review"), el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    try {
      await api(`/api/settings/${s.key}/proposals`, { method: "POST", body: { value: Number(f.get("value")), reason: f.get("reason") } });
      $("#modal").close(); toast("Proposal submitted; a different admin must approve it"); rules();
    } catch (e) { $("#setting-error").textContent = e.message; }
  });
  $("#modal-body").replaceChildren(form);
  $("#modal").showModal();
}

async function historyDialog(rule) {
  const h = await api(`/api/rules/${rule.id}/history`);
  $("#modal-body").replaceChildren(el("h2", {}, `History: ${rule.id}`),
    table(["Version", "When", "Proposed by", "Approved by", "Enabled", "Params", "Note"], h.map((x) => ({ cells: [
      `v${x.version}`, fmtTime(x.changed_at), x.changed_by, x.approved_by ?? "—", x.enabled ? "yes" : "no", el("pre", {}, JSON.stringify(x.params)), x.note ?? ""] }))),
    el("p", {}, el("button", { onclick: () => $("#modal").close() }, "Close")));
  $("#modal").showModal();
}

// ---------- health ----------
async function health() {
  const h = await api("/api/health/details");
  render(
    el("h1", {}, "System health"),
    el("div", { class: "card" },
      el("div", { class: "row", style: { justifyContent: "space-between" } },
        el("h2", {}, "Overall: ", status(h.status)),
        el("div", { class: "row" },
          can("analyst") ? el("button", { onclick: () => guarded(async () => { const r = await api("/api/detection/run", { method: "POST" }); toast(`Detection ${r.status}: ${r.alerts_created} created, ${r.alerts_updated} updated${r.error ? ` — ${r.error}` : ""}`); health(); refreshBanner(); }) }, "Run detection (full scan)") : null,
          el("button", { class: "ghost", onclick: () => guarded(() => { refreshBanner(); return health(); }) }, "Re-check"))),
      el("p", { class: "muted" }, `Checked ${fmtTime(h.checked_at)}. Unauthenticated monitors can poll GET /api/health (statuses only; HTTP 503 when failing).`),
      h.checks.map((c) => el("div", { class: "check" },
        el("div", {}, el("strong", {}, c.name), el("div", {}, status(c.status)), el("div", { class: "muted" }, `${c.latency_ms} ms`)),
        el("div", {}, el("div", {}, c.message),
          c.guidance ? el("div", { class: "guidance" }, el("strong", {}, "What to do: "), c.guidance) : null,
          el("details", {}, el("summary", { class: "muted" }, "details"), el("pre", {}, JSON.stringify(c.details, null, 2))))))),
    el("div", { class: "card" }, el("h2", {}, "Recent errors (redacted)"),
      table(["When", "Component", "Error", "Guidance"], h.recent_errors.map((e) => ({ cells: [fmtTime(e.created_at), e.component, el("code", {}, e.message), e.guidance ?? ""] })))),
    el("div", { class: "card" }, el("h2", {}, "Recent detection runs"),
      table(["#", "Started", "Trigger", "Status", "Scanned", "Created", "Updated", "Error"], h.recent_detection_runs.map((r) => ({ cells: [
        r.id, fmtTime(r.started_at), r.trigger, pill(r.status, r.status === "ok" ? "st-ok" : r.status === "failed" ? "st-failing" : "st-degraded"),
        { num: r.events_scanned }, { num: r.alerts_created }, { num: r.alerts_updated }, r.error ?? ""] })))),
  );
}

// ---------- admin ----------
async function admin() {
  if (!can("admin")) return render(el("p", {}, "Admins only."));
  const [tokens, audit] = await Promise.all([api("/api/tokens"), api("/api/audit")]);
  const tokenOut = el("div");
  const tokenForm = el("form", { class: "row" },
    el("label", {}, "Token name", el("input", { name: "name", required: true, maxlength: 64, placeholder: "e.g. web01-forwarder" })),
    el("button", { type: "submit" }, "Create ingest token"));
  tokenForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    guarded(async () => {
      const r = await api("/api/tokens", { method: "POST", body: { name: new FormData(tokenForm).get("name") } });
      tokenOut.replaceChildren(el("div", { class: "explain" }, el("strong", {}, "Copy this now; it will not be shown again: "), el("code", {}, r.token)));
      tokenForm.reset();
    });
  });
  const demoOut = el("div");
  render(
    el("h1", {}, "Administration"),
    el("div", { class: "card" }, el("h2", {}, "Demo data"),
      el("p", {}, "Loads the labeled synthetic dataset: normal office activity, brute force, password spraying, a compromised account, an off-hours root login, and a noisy but authorized internal scanner. Events are dated on the most recent weekday, tagged ", el("code", {}, "demo:*"), ", and marked synthetic everywhere in the UI."),
      el("button", { onclick: () => guarded(async () => {
        let r;
        try { r = await api("/api/demo/load", { method: "POST", body: {} }); }
        catch (e) {
          if (e.status !== 409 || !confirm(`${e.message}. Load another copy?`)) throw e;
          r = await api("/api/demo/load", { method: "POST", body: { force: true } });
        }
        demoOut.replaceChildren(table(["Scenario", "Accepted", "Detection", "Alerts created"], Object.entries(r).map(([n, x]) => ({ cells: [n, { num: x.accepted }, x.detection.status, { num: x.detection.alerts_created ?? 0 }] }))));
        refreshBanner();
      }) }, "Load synthetic demo data"), demoOut),
    el("div", { class: "card" }, el("h2", {}, "API tokens (ingest only)"), tokenForm, tokenOut,
      table(["Name", "Prefix", "Created", "Last used", "Status", ""], tokens.map((t) => ({ cells: [t.name, el("code", {}, `${t.prefix}…`), `${fmtTime(t.created_at)} by ${t.created_by}`, fmtTime(t.last_used_at),
        t.revoked_at ? pill("revoked", "st-rejected") : pill("active", "st-ok"),
        t.revoked_at ? "" : el("button", { class: "danger", onclick: () => confirm(`Revoke token "${t.name}"?`) && guarded(async () => { await api(`/api/tokens/${t.id}/revoke`, { method: "POST" }); admin(); }) }, "Revoke")] })))),
    el("div", { class: "card" }, el("h2", {}, "Audit log"),
      table(["When", "Actor", "Action", "Target", "Detail"], audit.map((a) => ({ cells: [fmtTime(a.created_at), a.actor, a.action, a.target ?? "", el("code", {}, a.detail ?? "")] })))),
  );
}

boot();
