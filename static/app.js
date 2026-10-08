"use strict";
// Watchpost UI shell and the classic views. All server data is rendered with textContent
// (via el()), never innerHTML. The SOC dashboard and live stream live in dashboard.js; its
// charts are SVG strings from charts.js/map.js with every text value escaped.

const state = { user: null, csrf: null, view: "dashboard", alertId: null, keys: null, restore: null, focusSearch: false };
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
const technique = (t) => el("span", { class: "pill technique", title: `${t.name} (${t.tactic})` }, `${t.id} ${t.name}`);
// Entity pages (user, src_ip, host). Values can hold dots, colons, pipes, or slashes, so they are
// always percent-encoded on the way into the hash and the API path.
const ENTITY_KINDS = { user: "Account", src_ip: "Source IP", host: "Host" };
const entityLink = (kind, value) => (value === null || value === undefined || value === "" ? "—"
  : el("a", { href: `#entity/${kind}/${encodeURIComponent(value)}`, title: `${ENTITY_KINDS[kind]} risk and history` }, value));
const entityLinks = (kind, list) => (list && list.length ? el("span", {}, list.flatMap((v, n) => [n ? ", " : null, entityLink(kind, v)])) : "—");
const techniques = (list) => (list && list.length ? el("span", { class: "row" }, list.map(technique)) : "—");
const assetChip = (a) => el("span", { class: `pill asset crit-${a.criticality}`,
  title: `${a.kind || "asset"} · ${a.criticality} criticality${a.data_tags?.length ? ` · sensitive data: ${a.data_tags.join(", ")}` : ""}` },
  `${a.name} · ${a.criticality}${a.data_tags?.length ? ` · ${a.data_tags.join(" ")}` : ""}`);
const assetChips = (list) => (list && list.length ? el("span", { class: "row" }, list.map(assetChip)) : el("span", { class: "muted" }, "none inventoried"));

// Toasts go into two live regions that exist from page load (index.html), so screen readers announce them:
// #toast-status (polite) for confirmations, #toast-alert (assertive) for errors.
function toast(msg, isError = false) {
  const t = el("div", { class: `toast${isError ? " toast-error" : ""}` }, msg);
  $(isError ? "#toast-alert" : "#toast-status").append(t);
  setTimeout(() => t.remove(), isError ? 7000 : 4000);
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
  if (res.status === 401 && path !== "/api/auth/login" && path !== "/api/auth/mfa") { showLogin(); throw new Error("Session expired"); }
  if (!res.ok && res.status !== 207 && !allow.includes(res.status)) {
    const err = new Error((data && data.error) || `HTTP ${res.status}`);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

// Clickable rows are focusable and open with Enter or Space, so the mouse is never required.
function table(headers, rows, onClick) {
  const onKey = (r) => (ev) => {
    if (ev.target !== ev.currentTarget || (ev.key !== "Enter" && ev.key !== " ")) return;
    ev.preventDefault();
    onClick(r);
  };
  return el("div", { class: "table-wrap" },
    el("table", {},
      el("thead", {}, el("tr", {}, headers.map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows.length ? rows.map((r) =>
        el("tr", { class: [onClick ? "clickable" : "", r.cls || ""].join(" "), onclick: onClick ? () => onClick(r) : null,
          tabindex: onClick ? "0" : null, onkeydown: onClick ? onKey(r) : null, "data-id": onClick && r.id !== undefined ? r.id : null },
          r.cells.map((c) => (c && c.num !== undefined ? el("td", { class: "num" }, c.num) : el("td", {}, c)))))
        : el("tr", {}, el("td", { colspan: headers.length, class: "muted" }, "Nothing to show.")))));
}

function render(...nodes) {
  const view = $("#view");
  view.replaceChildren(...nodes.flat().filter((n) => n !== null && n !== undefined && n !== false));
}

async function guarded(fn) {
  try { await fn(); } catch (e) { if (e.message !== "Session expired") toast(e.message, true); }
}

// One <dialog> serves every modal: showModal() makes the page behind it inert (the browser traps focus)
// and Esc closes it. This names it after its heading and hands focus back to the trigger on close.
let modalReturn = null;
function openModal() {
  const m = $("#modal");
  const h = $("#modal-body").querySelector("h2");
  if (h) { h.id = "modal-title"; m.setAttribute("aria-labelledby", "modal-title"); } else m.removeAttribute("aria-labelledby");
  if (!m.open) modalReturn = document.activeElement;
  m.showModal();
}

// ---------- auth ----------
function showLogin() {
  state.user = null; state.csrf = null;
  Live.stop();
  document.body.classList.remove("authed");
  $("#login-view").hidden = false;
  mfaStep(null);
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
      if (data.mfa_required) mfaStep(data.mfa_token); else onLogin(data);
    } catch (e) { $("#login-error").textContent = e.message; }
  });
  $("#logout").addEventListener("click", async () => { await api("/api/auth/logout", { method: "POST" }).catch(() => {}); showLogin(); });
  document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => {
    const menuOpen = $("#rail").classList.contains("menu-open");
    go(b.dataset.view);
    if (menuOpen) { setMenu(false); $("#nav-toggle").focus(); }  // the button just clicked is about to be hidden
  }));
  $("#nav-toggle").addEventListener("click", () => setMenu($("#nav-toggle").getAttribute("aria-expanded") !== "true"));
  $("#kbd-help").addEventListener("click", shortcutHelp);
  $("#modal").addEventListener("close", () => {
    // Back to the trigger; if a re-render removed it, to <main>, so focus never stays in the closed dialog.
    const back = modalReturn && modalReturn.isConnected && modalReturn !== document.body ? modalReturn : $("#main");
    modalReturn = null;
    back.focus({ preventScroll: true });
  });
  document.addEventListener("keydown", onShortcut);
  window.addEventListener("hashchange", () => route());
  try { onLogin(await api("/api/auth/me")); } catch { showLogin(); }
}

// Second sign-in step for an account with an authenticator app enrolled. The token from the password step is
// short-lived and kept only in this closure; null removes the step and shows the password form again.
function mfaStep(mfaToken) {
  $("#mfa-form")?.remove();
  $("#login-form").hidden = Boolean(mfaToken);
  if (!mfaToken) return;
  const error = el("p", { class: "error", role: "alert" });
  const code = el("input", { id: "mfa-code", name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: 6, required: true });
  const form = el("form", { id: "mfa-form" },
    el("p", {}, "Enter the 6-digit code from your authenticator app."),
    el("label", {}, "Authentication code", code),
    el("button", { type: "submit" }, "Verify"),
    el("button", { type: "button", class: "ghost", onclick: () => mfaStep(null) }, "Back"),
    error);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.textContent = "";
    try {
      const data = await api("/api/auth/mfa", { method: "POST", body: { mfa_token: mfaToken, code: code.value.trim() } });
      mfaStep(null);
      onLogin(data);
    } catch (e) {
      error.textContent = e.message;
      code.value = "";
      // An expired or locked step cannot be retried: back to the password.
      if (e.status === 429 || /expired/.test(e.message)) { mfaStep(null); $("#login-error").textContent = e.message; }
    }
  });
  $("#login-form").after(form);
  code.focus();
}

function onLogin(data) {
  state.user = data.user; state.csrf = data.csrf_token;
  $("#login-view").hidden = true;
  document.body.classList.add("authed");
  $("#rail").hidden = false; $("#strip").hidden = false; $("#who").hidden = false;
  $("#who-name").textContent = `${data.user.username} · ${data.user.role}${data.user.role === "viewer" ? " (read-only)" : ""}`;
  $("#masked-pill")?.remove();
  if (data.masked) $("#who-name").after(el("span", { class: "pill tag", id: "masked-pill", title: "Masked view: usernames and internal IP addresses are shown as consistent pseudonyms (user-…, internal-…). Public IPs are not masked. Filters and pivots on a pseudonym still work." }, "Masked view"));
  document.querySelectorAll("#nav [data-role]").forEach((b) => { b.hidden = !can(b.dataset.role); });
  route();
  refreshBanner();
  Live.start();
}

function go(view, id) { location.hash = id ? `${view}/${id}` : view; }

// Narrow screens fold the nav behind a Menu button (CSS shows the button below 760px only).
function setMenu(open) {
  $("#rail").classList.toggle("menu-open", open);
  $("#nav-toggle").setAttribute("aria-expanded", String(open));
}

function route() {
  if (!state.user) return;
  const [view, id, ...rest] = (location.hash.slice(1) || "dashboard").split("/");
  state.view = view;
  document.body.dataset.view = view;
  state.keys = null;  // per-view shortcut keys; the view that owns them sets them again
  setMenu(false);
  document.querySelectorAll("#nav button").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === view);
    if (b.dataset.view === view) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  if (view !== "dashboard") Dash.unmount();
  const views = { dashboard: socDashboard, incidents: () => (id ? incidentDetail(Number(id)) : incidentsView()),
    alerts: () => (id ? alertDetail(Number(id)) : alerts()), events, overview, ingest, rules: () => rules(id),
    noise: noiseLab, coverage: coverageView, health, admin, account, hunt: () => huntView(huntQueryFromHash([id, ...rest].join("/"))),
    entity: () => entityDetail(id, decodeURIComponent(rest.join("/"))) };
  guarded(views[view] || socDashboard);
}

async function refreshBanner() {
  try {
    const h = await api("/api/health", { allow: [503] });  // 503 = failing, still a valid report
    const b = $("#banner");
    const bad = Object.entries(h.checks).filter(([, s]) => s !== "ok");
    const text = `System ${h.status}: ${bad.map(([n, s]) => `${n} ${s}`).join(", ")}. `;
    b.hidden = h.status === "ok";
    b.className = `banner ${h.status === "failing" ? "bad" : ""}`;
    // The banner is a live region and health pushes arrive often: rewrite it only when it says something new.
    if (b.firstChild?.textContent !== text) b.replaceChildren(text, el("a", { href: "#health" }, "Open Health for details and recovery steps."));
  } catch {
    const b = $("#banner");
    const text = "Cannot reach the Watchpost health endpoint. The server may be down.";
    b.hidden = false;
    b.className = "banner bad";
    if (b.textContent !== text) b.textContent = text;
  }
}

// ---------- metrics overview (the 1.0 dashboard) ----------
async function overview() {
  const [m, tri] = await Promise.all([api("/api/metrics"), api("/api/metrics/triage")]);
  const kpi = (v, l) => el("div", { class: "kpi" }, el("div", { class: "v" }, v ?? "—"), el("div", { class: "l" }, l));
  const hist = m.activity_last_24h_of_data;
  const max = Math.max(1, ...hist.map((h) => h.events));
  const bars = el("div", { class: "bars", role: "img", "aria-label": `Events per hour over 24 hours: ${hist.reduce((n, h) => n + h.events, 0)} events, ${hist.reduce((n, h) => n + h.failures, 0)} failed logins, busiest hour ${Math.max(0, ...hist.map((h) => h.events))} events` }, hist.map((h) =>
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
    el("h2", {}, "SOC metrics"),
    el("div", { class: "grid" },
      el("div", { class: "card" }, el("h2", {}, "Time to resolve by severity"),
        table(["Severity", "Resolved", "Mean", "Longest"], m.time_to_resolve_by_severity.map((r) => ({ cells: [sev(r.severity), { num: r.resolved }, { num: `${r.mean_minutes}m` }, { num: `${r.max_minutes}m` }] })))),
      el("div", { class: "card" }, el("h2", {}, "False-positive rate by rule"),
        table(["Rule", "Reviewed", "False positive", "Benign", "FP rate"], m.false_positive_rate_by_rule.map((r) => ({ cells: [el("code", {}, r.rule_id), { num: r.reviewed }, { num: r.false_positive }, { num: r.benign }, { num: pct(r.false_positive_rate) }] })))),
      el("div", { class: "card" }, el("h2", {}, "Open-alert aging"), hbars(m.open_alert_aging.buckets, "label"),
        el("p", { class: "muted" }, m.open_alert_aging.oldest_minutes === null ? "No open alerts." : `Oldest open alert has waited ${Math.round(m.open_alert_aging.oldest_minutes)} minutes.`))),
    triageCard(tri),
    el("div", { class: "card" }, el("h2", {}, "Left out on purpose"),
      el("p", { class: "muted" }, "The numbers above use the times this instance created and resolved each alert, and verdicts analysts recorded. These metrics are not shown because replayed synthetic timestamps would make them misleading:"),
      el("ul", { class: "muted" }, m.omitted_metrics.map((o) => el("li", {}, el("code", {}, o.metric), `: ${o.reason}`)))),
  );
}

// Triage metrics (/api/metrics/triage): created → acknowledged and created → resolved, per severity.
const minutes = (v) => (v === null || v === undefined ? "—" : `${v}m`);
const timeStats = (t) => (t.samples ? `${minutes(t.mean_minutes)} / ${minutes(t.median_minutes)} / ${minutes(t.p90_minutes)}` : "—");
function triageCard(t) {
  const rows = t.severities.filter((r) => r.count);
  const unknown = t.severities.reduce((n, r) => n + r.ack_unknown, 0);
  return el("div", { class: "card", id: "triage-metrics" },
    el("div", { class: "row", style: { justifyContent: "space-between" } },
      el("h2", {}, `Triage metrics — alerts created ${t.window === "all" ? "at any time" : `in the last ${t.window}`}`),
      t.synthetic !== "none" ? pill(t.synthetic === "all" ? "synthetic" : `${t.synthetic_alerts} synthetic`, "synthetic") : null),
    table(["Severity", "Alerts", "Open", "MTTA mean / median / p90", "MTTR mean / median / p90", "SLA target (ack / resolve)", "Ack breaches", "Resolve breaches"],
      rows.map((r) => ({ cells: [sev(r.severity), { num: r.count }, { num: r.open }, { num: timeStats(r.mtta) }, { num: timeStats(r.mttr) },
        { num: `${minutes(r.sla.ack_target_minutes)} / ${minutes(r.sla.resolve_target_minutes)}` }, { num: r.sla.ack_breaches }, { num: r.sla.resolve_breaches }] }))),
    el("p", { class: "muted" }, "MTTA: alert created to first acknowledgement (leaving open). MTTR: created to resolved. p90 is nearest-rank. A breach is a step that took, or has been pending for, longer than its target.",
      unknown ? ` ${unknown} alert(s) left open before acknowledgements were recorded and are not counted for MTTA or ack breaches.` : ""));
}

// SLA badge for unresolved alerts past their ack or resolve target (sla_breach from /api/alerts).
const slaBadge = (list) => (list && list.length ? el("span", { class: "pill sev-critical", title: `Past the ${list.join(" and ")} target for this severity` },
  `SLA: ${list.join(" + ")} overdue`) : null);

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
  const [list, incidents] = await Promise.all([api(`/api/alerts?${params}`), api("/api/incidents?status=open,investigating")]);
  render(el("h1", {}, "Alerts"),
    el("div", { class: "card" }, el("h2", {}, `Active incidents (${incidents.length})`),
      el("p", { class: "muted" }, "Alerts that share a source IP, account, or host within 30 minutes are grouped into one incident. Severity rises one level when an incident spans three or more ATT&CK tactics."),
      table(["Severity", "Incident", "Kill chain", "Alerts", "Status", "Last seen", ""],
        incidents.map((i) => ({ id: i.id, cells: [sev(i.severity), i.title, i.stages.join(" → ") || "—", { num: i.alert_count },
          status(i.status), fmtTime(i.last_seen), synth(i.synthetic)] })),
        (r) => go("incidents", r.id))),
    form, el("div", { class: "card", "data-kbd-list": "alerts" }, table(
    ["Severity", "Alert", "Rule", "Status", "Events", "Last seen", ""],
    list.map((a) => ({ id: a.id, cells: [sev(a.severity), a.title, el("code", {}, a.rule_id),
      el("span", {}, status(a.status), a.disposition ? ` ${a.disposition.replace("_", " ")}` : "", a.sla_breach?.length ? " " : null, slaBadge(a.sla_breach)),
      { num: a.event_count }, fmtTime(a.last_seen), synth(a.synthetic)] })),
    (r) => go("alerts", r.id))));
  restoreSelection(`[data-kbd-list] tr[data-id="${state.restore}"]`);
}

async function alertDetail(id) {
  const a = await api(`/api/alerts/${id}`);
  // Triage keys (see keyboard section): Esc for everyone; a and r only for roles that may act.
  state.keys = state.view === "alerts" ? { Escape: () => { state.restore = id; go("alerts"); } } : null;
  if (state.keys && can("analyst") && a.status !== "resolved") {
    state.keys.a = () => (a.status === "open" ? setStatus(id, { status: "investigating" }) : toast("Already investigating"));
    state.keys.r = () => resolveDialog(id);
  }
  const actions = el("div", { class: "row" });
  if (can("analyst")) {
    if (a.status === "open") actions.append(el("button", { onclick: () => setStatus(id, { status: "investigating" }) }, "Start investigating"));
    if (a.status !== "resolved") actions.append(el("button", { onclick: () => resolveDialog(id) }, "Resolve…"));
    else actions.append(el("button", { class: "ghost", onclick: () => setStatus(id, { status: "open" }) }, "Reopen"));
  }
  actions.append(reportLinks("alerts", id));
  const noteForm = can("analyst") ? el("form", {},
    el("textarea", { name: "body", maxlength: 5000, required: true, placeholder: "Add an investigation note…", "aria-label": "Investigation note" }),
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
          el("p", {}, el("strong", {}, "MITRE ATT&CK: "), techniques(a.rule?.techniques)),
          el("p", {}, el("strong", {}, "Assets: "), assetChips(a.assets),
            a.base_severity && a.base_severity !== a.severity ? el("span", { class: "muted" }, ` Rule severity ${a.base_severity}; ${a.severity_note}.`) : null),
          actions),
        el("div", { class: "card" }, el("h2", {}, `Evidence (${a.evidence.length} events)`),
          table(["Time", "Type", "User", "Source IP", "Host", "Message"],
            a.evidence.map((e) => ({ cells: [fmtTime(e.ts), e.event_type, entityLink("user", e.user), el("code", {}, entityLink("src_ip", e.src_ip)), entityLink("host", e.host), e.message ?? ""] })))),
        el("div", { class: "card" }, el("h2", {}, "Related timeline"),
          el("p", { class: "muted" }, "Every event involving these IPs or accounts from 30 minutes before to 30 minutes after. Highlighted rows are evidence."),
          table(["Time", "Type", "User", "Source IP", "Source", "Message"],
            a.timeline.map((e) => ({ cls: e.is_evidence ? "evidence" : "", cells: [fmtTime(e.ts), e.event_type, entityLink("user", e.user), el("code", {}, entityLink("src_ip", e.src_ip)), e.source, e.message ?? ""] }))))),
      el("div", {},
        el("div", { class: "card" }, el("h2", {}, "Details"), el("dl", { class: "kv" },
          ...[["Alert", `#${a.id}`], ["Group", a.group_key], ["First seen", fmtTime(a.first_seen)], ["Last seen", fmtTime(a.last_seen)],
            ["Assignee", a.assignee ?? "—"], ["Acknowledged", fmtTime(a.acknowledged_at)], ["Verdict", a.disposition ?? "—"], ["Resolved", fmtTime(a.resolved_at)]]
            .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]))),
        el("div", { class: "card" }, el("h2", {}, "Notes"),
          a.notes.length ? a.notes.map((n) => el("div", { class: "note" }, el("div", { class: "muted" }, `${n.author} · ${fmtTime(n.created_at)}`), el("div", {}, n.body)))
            : el("p", { class: "muted" }, "No notes yet."),
          noteForm),
        el("div", { class: "card" }, el("h2", {}, "Activity"),
          a.activity.map((x) => el("div", { class: "note" }, el("span", { class: "muted" }, `${fmtTime(x.created_at)} · ${x.actor} `), `${x.action.replace("_", " ")}${x.detail ? ` — ${x.detail}` : ""}`))))),
  );
}

// Report downloads (every role, viewers included). kind is "alerts" or "incidents"; plain GET links carry the session cookie.
function reportLinks(kind, id) {
  return el("span", { class: "row" },
    el("a", { class: "button", href: `/api/${kind}/${id}/report.pdf`, download: "" }, "Report (PDF)"),
    el("a", { class: "button", href: `/api/${kind}/${id}/report.md`, download: "" }, "Report (Markdown)"));
}

// ---------- incidents ----------
async function incidentDetail(id) {
  const i = await api(`/api/incidents/${id}`);
  const setIncident = (body) => guarded(async () => { await api(`/api/incidents/${id}/status`, { method: "POST", body }); incidentDetail(id); });
  state.keys = state.view === "incidents" ? { Escape: () => { state.restore = id; go("incidents"); } } : null;
  if (state.keys && can("analyst") && i.status === "open") state.keys.a = () => setIncident({ status: "investigating" });
  const actions = el("div", { class: "row" });
  if (can("analyst")) {
    if (i.status === "open") actions.append(el("button", { onclick: () => setIncident({ status: "investigating" }) }, "Start investigating"));
    if (i.status !== "resolved") actions.append(el("button", { onclick: () => setIncident({ status: "resolved" }) }, "Resolve"));
    else actions.append(el("button", { class: "ghost", onclick: () => setIncident({ status: "open" }) }, "Reopen"));
  }
  actions.append(reportLinks("incidents", id));
  render(
    el("p", {}, el("a", { href: "#incidents" }, "← Incidents")),
    el("div", { class: "split" },
      el("div", {},
        el("div", { class: "card" },
          el("div", { class: "row" }, sev(i.severity), status(i.status), synth(i.synthetic), i.escalated ? pill("escalated: 3+ tactics", "sev-critical") : null),
          el("h1", { style: { marginTop: "8px" } }, `Incident #${i.id}: ${i.title}`),
          el("div", { class: "row" }, i.stages.map((t, n) => el("span", {}, n ? "→ " : "", pill(t, "stage")))),
          actions),
        el("div", { class: "card" }, el("h2", {}, `Alert timeline (${i.alerts.length})`),
          table(["First seen", "Severity", "Alert", "Tactics", "Techniques", "Status"],
            i.timeline.map((t) => ({ id: t.alert_id, cells: [fmtTime(t.ts), sev(t.severity), t.title, t.tactics.join(", "), t.techniques.join(", "), status(t.status)] })),
            (r) => go("alerts", r.id))),
        el("div", { class: "card" }, el("h2", {}, `Evidence (${i.events.length} events)`),
          table(["Time", "Type", "User", "Source IP", "Host", "Message"],
            i.events.map((e) => ({ cells: [fmtTime(e.ts), e.event_type, entityLink("user", e.user), el("code", {}, entityLink("src_ip", e.src_ip)), entityLink("host", e.host), e.message ?? ""] }))))),
      el("div", {},
        el("div", { class: "card" }, el("h2", {}, "Details"), el("dl", { class: "kv" },
          ...[["Incident", `#${i.id}`], ["First seen", fmtTime(i.first_seen)], ["Last seen", fmtTime(i.last_seen)],
            ["Source IPs", entityLinks("src_ip", i.entities.src_ip)], ["Accounts", entityLinks("user", i.entities.user)],
            ["Hosts", entityLinks("host", i.entities.host)], ["Assignee", i.assignee ?? "—"], ["Resolved", fmtTime(i.resolved_at)]]
            .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]))),
        el("div", { class: "card" }, el("h2", {}, "Assets involved"),
          el("p", { class: "muted" }, "Inventoried systems reached by this incident. Alerts touching high or critical assets, or systems that process sensitive data, carry a raised severity."),
          assetChips(i.assets)),
        el("div", { class: "card" }, el("h2", {}, "MITRE ATT&CK"),
          i.techniques_by_tactic.map((g) => el("div", { class: "note" }, el("h3", {}, g.tactic), techniques(g.techniques)))))),
  );
}

// ---------- entity page ----------
async function entityDetail(kind, value) {
  if (!Object.hasOwn(ENTITY_KINDS, kind)) throw new Error("Unknown entity kind");
  const e = await api(`/api/entities/${kind}/${encodeURIComponent(value)}`);
  const kpi = (v, l) => el("div", { class: "kpi" }, el("div", { class: "v" }, v ?? "—"), el("div", { class: "l" }, l));
  const counted = e.contributions.filter((c) => c.counted);
  const weights = Object.entries(e.severity_weights).map(([s, w]) => `${s} ${w}`).join(", ");
  render(
    el("p", {}, el("a", { href: "#dashboard" }, "← Dashboard")),
    el("div", { class: "card" },
      el("div", { class: "row" }, pill(ENTITY_KINDS[e.kind], "stage"), synth(e.synthetic)),
      el("h1", { style: { marginTop: "8px" } }, e.value),
      el("p", {}, huntLink(e.kind, e.value, `Hunt this ${ENTITY_KINDS[e.kind].toLowerCase()} (last 7 days)`)),
      el("div", { class: "kpis" },
        kpi(e.score, "Risk score"), kpi(counted.length, "Alerts counted"), kpi(e.incidents.length, "Incidents"),
        kpi(e.event_count.toLocaleString(), "Events"), kpi(fmtTime(e.first_seen), "First seen"), kpi(fmtTime(e.last_seen), "Last seen"))),
    el("div", { class: "card" }, el("h2", {}, "Why this score"),
      el("p", { class: "muted" }, `Each alert whose evidence includes this ${ENTITY_KINDS[e.kind].toLowerCase()} adds its severity weight (${weights}), halved for every ${e.half_life_hours} hours between the alert and the newest event in the data (${fmtTime(e.anchor)}). Alerts closed as ${e.excluded_dispositions.map((d) => d.replace("_", " ")).join(" or ")} add nothing. The weights below sum to the score.`),
      table(["Alert", "Severity", "Status", "Last seen", "Base weight", "Age (h)", "Decay", "Weight"],
        e.contributions.map((c) => ({ id: c.alert_id, cells: [`#${c.alert_id} ${c.title}`,
          c.base_severity !== c.severity ? el("span", { title: c.asset_note || "" }, sev(c.severity), ` raised from ${c.base_severity} by asset weight`) : sev(c.severity),
          el("span", {}, status(c.status), c.disposition ? ` ${c.disposition.replace("_", " ")}` : ""), fmtTime(c.last_seen),
          { num: c.base_weight }, { num: c.age_hours }, { num: c.decay }, { num: c.counted ? c.weight : "not counted" }] })),
        (r) => go("alerts", r.id))),
    el("div", { class: "card" }, el("h2", {}, `Incidents (${e.incidents.length})`),
      table(["Severity", "Incident", "Alerts", "Status", "Last seen", ""],
        e.incidents.map((i) => ({ id: i.id, cells: [sev(i.severity), i.title, { num: i.alert_count }, status(i.status), fmtTime(i.last_seen), synth(i.synthetic)] })),
        (r) => go("incidents", r.id))),
    el("div", { class: "card" }, el("h2", {}, `Recent events (latest ${e.recent_events.length} of ${e.event_count.toLocaleString()})`),
      table(["Time", "Severity", "Type", "User", "Source IP", "Host", "Source", "Message"],
        e.recent_events.map((x) => ({ cells: [fmtTime(x.ts), sev(x.severity), x.event_type, entityLink("user", x.user), el("code", {}, entityLink("src_ip", x.src_ip)), entityLink("host", x.host), el("span", {}, x.source, " ", synth(x.synthetic)), x.message ?? ""] })))),
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
  openModal();
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
        ["", "auth_failure", "auth_success", "account_lockout", "user_created", "privilege_use", "process_start", "network_connection", "file_access", "syslog", "other"]
          .map((v) => el("option", { value: v, selected: saved.get("event_type") === v }, v || "Any")))),
      el("label", {}, "Min severity", el("select", { name: "severity" },
        ["", "low", "medium", "high", "critical"].map((v) => el("option", { value: v, selected: saved.get("severity") === v }, v || "Any")))),
      field("q", "Message contains", { size: 14, "data-search": "" }),
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
  catch (e) { render(el("h1", {}, "Event search"), form, el("p", { class: "error", role: "alert" }, e.message)); return; }
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
      .flatMap((k) => [el("dt", {}, k), el("dd", {}, e[k] ?? "—",
        HUNT_PIVOTS.includes(k) && e[k] !== null ? [" ", huntLink(k, e[k], "Hunt", () => $("#modal").close())] : null)]), el("dt", {}, "synthetic"), el("dd", {}, e.synthetic ? "yes (demo data)" : "no")),
    el("h3", {}, "Linked alerts"),
    e.alerts.length ? e.alerts.map((a) => el("div", {}, el("a", { href: `#alerts/${a.id}`, onclick: () => $("#modal").close() }, `#${a.id} ${a.title}`), " ", status(a.status)))
      : el("p", { class: "muted" }, "None."),
    el("h3", {}, "Original record (secrets redacted)"), el("pre", {}, e.raw ?? ""),
    el("p", {}, el("button", { onclick: () => $("#modal").close() }, "Close")));
  openModal();
}

// ---------- hunt ----------
// The query lives in the hash (#hunt/<percent-encoded query>), so a hunt is a shareable link.
// The server parses it (watchpost/hunt.py) and echoes how each term was read; nothing is parsed here.
const HUNT_PIVOTS = ["user", "src_ip", "dest_ip", "host", "event_type"];
const HUNT_SYNTAX = [
  ["field:value", "user:alice", "Exact match (user names ignore case)"],
  ["field:prefix*", "host:web*", "Starts with (unquoted values only)"],
  ['field:"quoted"', 'user:"svc backup"', "Literal value; * and spaces are not special"],
  ["word or \"phrase\"", '"invalid password"', "Message contains"],
  ["NOT term or -term", "NOT src_ip:10.0.0.5", "Excludes (events missing the field are kept)"],
  ["last:15m|24h|7d", "last:24h", "Time window up to now (at most 365d)"],
  ["since: / until:", "since:2026-10-01 until:2026-10-02T06:00Z", "ISO times, UTC unless stated"],
  ["| stats count[, dc(f)] [by f1[, f2]]", "event_type:auth_failure | stats count, dc(user) by src_ip", "Grouped counts, largest first (at most 1000 groups)"],
  ["| top [N] field", "event_type:auth_failure | top 10 src_ip", "Top N values (1–100, default 10), count and percent of matched events"],
  ["| timechart span=5m|15m|1h|6h|1d [count] [by f]", "last:24h | timechart span=1h by user", "Events per time bucket (at most 500 buckets); by keeps the top 5 plus other"],
];
const HUNT_FIELDS = "user host source outcome src_ip dest_ip ip batch_id event_type severity dest_port synthetic message last since until";
const huntHref = (q) => `#hunt/${encodeURIComponent(q)}`;
const huntValue = (v) => (/^[^\s"\\]+$/.test(v) && !v.endsWith("*") ? v : `"${v.replace(/[\\"]/g, "\\$&")}"`);
const huntLink = (field, value, label, onclick) => el("a", { href: huntHref(`${field}:${huntValue(String(value))} last:7d`),
  title: `Hunt events where ${field} is ${value} in the last 7 days`, onclick }, label);

function huntQueryFromHash(encoded) {
  try { return decodeURIComponent(encoded || ""); } catch { return ""; }
}

function openHunt(q) {
  if (location.hash === huntHref(q)) guarded(() => huntView(q));  // same hash: no hashchange fires
  else location.hash = huntHref(q);
}

async function huntView(query = "", offset = 0) {
  const input = el("input", { name: "q", value: query, maxlength: 500, autocomplete: "off", spellcheck: "false",
    placeholder: 'user:alice NOT src_ip:10.0.0.5 "invalid password" last:24h', style: { width: "100%" }, "data-search": "" });
  const form = el("form", { class: "card" },
    el("div", { class: "row" },
      el("label", { style: { flex: "1 1 220px", minWidth: "0" } }, "Query", input),
      el("button", { type: "submit" }, "Hunt"),
      can("analyst") ? el("button", { type: "button", class: "ghost", onclick: () => saveHuntDialog(input.value.trim()) }, "Save search") : null),
    el("details", { style: { marginTop: "10px" } }, el("summary", { class: "muted" }, "Syntax"),
      el("p", { class: "muted" }, "Terms are ANDed; there is no OR. Fields: ", el("code", {}, HUNT_FIELDS), ". ip matches source or destination."),
      el("p", { class: "muted" }, "One ", el("code", {}, "|"), " stage may follow the filter to aggregate it (a | inside quotes is part of the value). ",
        "Group by any field except message, ip and the time filters. Click a value in the result to add it to the filter."),
      table(["Form", "Example", "Meaning"], HUNT_SYNTAX.map(([f, x, m]) => ({ cells: [el("code", {}, f), el("code", {}, x), m] })))));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    openHunt(input.value.trim());
  });
  const params = new URLSearchParams({ q: query, limit: "100", offset: String(offset) });
  const [saved, data] = await Promise.all([api("/api/hunt/saved"), api(`/api/hunt?${params}`).catch((e) => e)]);
  const remove = (s) => confirm(`Delete saved search "${s.name}"?`) && guarded(async () => {
    await api(`/api/hunt/saved/${s.id}/delete`, { method: "POST" });
    toast("Saved search deleted");
    huntView(query);
  });
  const mayDelete = (s) => can("analyst") && (s.owner === state.user.username || can("admin"));
  const savedCard = el("div", { class: "card" }, el("h2", {}, `Saved searches (${saved.length})`),
    table(["Name", "Query", "Owner", ""], saved.map((s) => ({ cells: [
      el("span", {}, el("a", { href: huntHref(s.query) }, s.name), s.description ? el("div", { class: "muted" }, s.description) : null),
      el("code", {}, s.query), `${s.owner} · ${fmtTime(s.created_at)}`,
      el("span", { class: "row" },
        can("analyst") ? el("button", { class: "ghost", onclick: () => promoteDialog(s) }, "Promote to detection…") : null,
        mayDelete(s) ? el("button", { class: "danger", onclick: () => remove(s) }, "Delete") : null)] }))));
  if (data instanceof Error) {
    render(el("h1", {}, "Hunt"), form, el("div", { class: "card" }, el("p", { class: "error", role: "alert" }, data.message)), savedCard);
    return;
  }
  const parsed = el("div", { class: "row", style: { alignItems: "center" } }, el("span", { class: "muted" }, "Parsed as:"),
    data.terms.length ? data.terms.map((t) => pill(t.text, "technique")) : el("span", { class: "muted" }, "no terms, so every event"));
  if (data.kind) {
    if (state.focusSearch) { state.focusSearch = false; queueMicrotask(() => input.focus()); }
    render(el("h1", {}, "Hunt"), form, el("div", { class: "card", id: "hunt-agg" }, parsed, huntAggregate(data)), savedCard);
    return;
  }
  const pager = el("div", { class: "row" },
    el("span", { class: "muted" }, `${data.total.toLocaleString()} matching events · showing ${data.total ? offset + 1 : 0}–${offset + data.events.length}`),
    el("button", { class: "ghost", disabled: offset === 0, onclick: () => guarded(() => huntView(query, Math.max(0, offset - 100))) }, "Newer"),
    el("button", { class: "ghost", disabled: offset + 100 >= data.total, onclick: () => guarded(() => huntView(query, offset + 100)) }, "Older"));
  if (state.focusSearch) { state.focusSearch = false; queueMicrotask(() => input.focus()); }
  render(el("h1", {}, "Hunt"), form, el("div", { class: "card" }, parsed, pager,
    table(["Time", "Severity", "Type", "User", "Source IP", "Host", "Source", "Message"],
      data.events.map((e) => ({ id: e.id, cells: [fmtTime(e.ts), sev(e.severity), e.event_type, e.user ?? "—", el("code", {}, e.src_ip ?? "—"), e.host ?? "—", el("span", {}, e.source, " ", synth(e.synthetic)), e.message ?? ""] })),
      (r) => guarded(() => eventDialog(r.id)))), savedCard);
}

// Pipeline results (| stats, | top, | timechart). Value cells pivot: they add field:value to the filter
// (the part before the |) and show the matching events.
const HUNT_FIELD_NAMES = HUNT_FIELDS.split(" ");
const huntPivot = (filter, field, value) => el("a", { href: huntHref(`${filter} ${field}:${huntValue(String(value))}`.trim()),
  title: `Add ${field}:${value} to the filter and show the events` }, String(value));

function huntAggregate(data) {
  const note = data.truncated ? el("p", { class: "muted", role: "status" }, data.kind === "top"
    ? `More values exist than the ${data.rows.length} shown.` : `Showing the first ${data.rows.length} groups; narrow the filter to see the rest.`) : null;
  if (data.kind === "timechart") return [note, huntTimechart(data)];
  const cell = (c, v) => (HUNT_FIELD_NAMES.includes(c) ? huntPivot(data.filter, c, v) : { num: c === "percent" ? `${v}%` : Number(v).toLocaleString() });
  return [note, el("p", { class: "muted" }, `${data.rows.length.toLocaleString()} ${data.kind === "top" ? "values" : "rows"}`),
    table(data.columns, data.rows.map((r) => ({ cells: r.map((v, i) => cell(data.columns[i], v)) })))];
}

const SVG_NS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  // style is set through CSSOM like el(); the CSP (style-src 'self') blocks style attributes.
  for (const [k, v] of Object.entries(attrs)) if (k === "style") Object.assign(node.style, v); else node.setAttribute(k, v);
  for (const c of children.flat()) if (c !== null && c !== undefined) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}

// Bars for one series, lines for several (by), and the same numbers as a table for screen readers and copying.
function huntTimechart(data) {
  if (!data.rows.length) return el("p", { class: "muted" }, "No matching events.");
  const series = data.columns.slice(1);
  const colors = ["--accent", "--high", "--low", "--med", "--synthetic", "--info"];
  const W = 760, H = 200, L = 44, B = 22, T = 8, n = data.rows.length;
  const max = Math.max(1, ...data.rows.flatMap((r) => r.slice(1)));
  const x = (i) => L + ((W - L - 4) * i) / n, y = (v) => T + (H - T - B) * (1 - v / max), step = (W - L - 4) / n;
  const label = (t) => fmtTime(t).slice(0, 16);
  const marks = series.length === 1
    ? data.rows.map((r, i) => svgEl("rect", { x: x(i) + step * 0.1, y: y(r[1]), width: Math.max(0.5, step * 0.8), height: y(0) - y(r[1]), style: { fill: "var(--accent)" } },
      svgEl("title", {}, `${label(r[0])}: ${r[1]}`)))
    : series.map((s, k) => svgEl("polyline", { fill: "none", "stroke-width": 1.5, style: { stroke: `var(${colors[k % colors.length]})` },
      points: data.rows.map((r, i) => `${x(i) + step / 2},${y(r[k + 1])}`).join(" ") }, svgEl("title", {}, s)));
  const peak = Math.max(...data.rows.flatMap((r) => r.slice(1)));
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", style: { maxWidth: "100%", height: "auto" },
    "aria-label": `Events per bucket from ${label(data.rows[0][0])} to ${label(data.rows[n - 1][0])} (${n} buckets, peak ${peak}), series: ${series.join(", ")}` },
    svgEl("line", { x1: L, x2: W - 4, y1: y(0), y2: y(0), style: { stroke: "var(--line-2)" } }),
    svgEl("text", { x: L - 6, y: y(max) + 4, "text-anchor": "end", "font-size": 11, style: { fill: "var(--muted)" } }, String(max)),
    svgEl("text", { x: L - 6, y: y(0), "text-anchor": "end", "font-size": 11, style: { fill: "var(--muted)" } }, "0"),
    svgEl("text", { x: L, y: H - 4, "font-size": 11, style: { fill: "var(--muted)" } }, label(data.rows[0][0])),
    svgEl("text", { x: W - 4, y: H - 4, "text-anchor": "end", "font-size": 11, style: { fill: "var(--muted)" } }, label(data.rows[n - 1][0])),
    marks);
  const legend = series.length > 1 ? el("div", { class: "row", "aria-hidden": "true" }, series.map((s, k) =>
    el("span", { class: "muted" }, el("span", { style: { display: "inline-block", width: "10px", height: "10px", marginRight: "4px", background: `var(${colors[k % colors.length]})` } }), s))) : null;
  return [svg, legend, el("details", {}, el("summary", { class: "muted" }, "Data table"),
    table(["Time", ...series], data.rows.map((r) => ({ cells: [fmtTime(r[0]), ...r.slice(1).map((v) => ({ num: v.toLocaleString() }))] }))))];
}

function saveHuntDialog(query) {
  const form = el("form", {},
    el("h2", {}, "Save search"),
    el("label", {}, "Name", el("input", { name: "name", required: true, maxlength: 80 })),
    el("label", {}, "Query (checked on save)", el("input", { name: "query", required: true, maxlength: 500, value: query })),
    el("label", {}, "Description (optional)", el("input", { name: "description", maxlength: 300 })),
    el("p", { class: "error", role: "alert", id: "hunt-error" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Save"),
      el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    try {
      const s = await api("/api/hunt/saved", { method: "POST", body: { name: f.get("name"), query: f.get("query"), description: f.get("description") } });
      $("#modal").close();
      toast(`Saved "${s.name}"`);
      openHunt(s.query);
    } catch (e) { $("#hunt-error").textContent = e.message; }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
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
async function rules(focus) {
  const [list, changes, settings, evals, exceptions] = await Promise.all([api("/api/rules"), api("/api/changes"), api("/api/settings"), api("/api/evaluations"), api("/api/suppressions")]);
  const pending = changes.filter((c) => c.status === "pending");
  const ruleCards = list.map((r) => {
    const p = r.performance || {};
    const ev = r.evaluation;
    return el("div", { class: "card", id: `rule-${r.id}`, tabindex: "-1" },
      el("div", { class: "row", style: { justifyContent: "space-between" } },
        el("h2", {}, r.name), el("span", {}, sev(r.severity), " ", r.enabled ? pill("enabled", "st-ok") : pill("disabled", "st-rejected"))),
      el("p", { class: "muted" }, r.description),
      el("p", {}, el("strong", {}, "MITRE ATT&CK: "), techniques(r.techniques)),
      el("div", { class: "grid" },
        r.sigma ? sigmaDetail(r) : r.search ? searchDetail(r) : el("div", {}, el("h3", {}, `Parameters (v${r.version})`), el("pre", {}, JSON.stringify(r.params, null, 2))),
        el("div", {},
          el("h3", {}, "Analyst feedback"),
          el("dl", { class: "kv" }, ...[["Alerts", p.total], ["Open / investigating", `${p.open} / ${p.investigating}`], ["True positives", p.tp], ["False positives", p.fp], ["Benign", p.benign], ["Precision (TP / (TP+FP))", pct(p.precision)]]
            .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v ?? 0)])),
          el("h3", {}, "Latest scenario evaluation"),
          ev ? el("dl", { class: "kv" }, ...[["Detected", ev.detected.join(", ") || "—"], ["Missed", ev.missed.join(", ") || "none"], ["False positives on", ev.false_positives.join(", ") || "none"], ["Recall", pct(ev.recall)], ["Precision", pct(ev.precision)]]
            .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])) : el("p", { class: "muted" }, "Not evaluated yet — use 'Run evaluation'."))),
      el("div", { class: "row" },
        can("analyst") ? el("button", { class: "ghost", onclick: () => proposeDialog(r) }, "Propose change…") : null,
        can("analyst") ? el("button", { class: "ghost", onclick: () => exceptionDialog(r) }, "Propose exception…") : null,
        can("analyst") && (r.sigma || r.search) ? el("button", { class: "ghost", onclick: () => sigmaSampleDialog(r) }, "Labeled sample…") : null,
        el("button", { class: "ghost", onclick: () => guarded(() => historyDialog(r)) }, "History")));
  });

  // Exception evidence from this database: the labeled scenarios alone cannot show what a key hides.
  const counts = (o) => Object.entries(o).map(([k, n]) => `${k} ${n}`).join(", ");
  const liveImpact = (li) => (li ? el("div", { class: "muted" },
    li.in_labeled_scenario !== false ? null : el("div", {}, el("strong", {}, "The scenario numbers do not cover this group key: "), "no labeled scenario contains it, so before and after say nothing about what it changes."),
    el("div", {}, `Live impact: ${li.alerts} existing alert(s) match`, li.alerts ? ` (${counts(li.by_status)}${Object.keys(li.by_disposition).length ? `; closed as ${counts(li.by_disposition)}` : ""})` : "", ". ", li.effect_note ?? ""),
    li.recent.map((a) => el("div", {}, `#${a.id} ${a.title} (${a.disposition || a.status})`)),
    li.ever_true_positive ? el("div", {}, el("strong", {}, `${li.ever_true_positive} matching alert(s) have been closed as a true positive at some point.`)) : null,
    li.proposer_verdict_changes?.count ? el("div", {}, el("strong", {}, `The proposer changed the status or verdict of these alerts ${li.proposer_verdict_changes.count} time(s): `),
      li.proposer_verdict_changes.recent.map((x) => `#${x.alert_id} ${x.detail} at ${fmtTime(x.created_at)}`).join("; ")) : null) : null);
  const lostNote = (c) => (c.kind === "rule_update" && detectionLoss(c).length
    ? el("div", {}, el("strong", {}, `Loses detection of labeled attack(s): ${detectionLoss(c).join(", ")}. `), "Approving requires an explicit acknowledgement.") : null);

  const changeRows = changes.slice(0, 30).map((c) => ({ cells: [
    `#${c.id}`, status(c.status), el("code", {}, isAssetChange(c) ? `asset:${c.evaluation?.asset ?? c.target}` : `${{ rule_update: "rule", suppression_add: "exception", sigma_add: "sigma", sigma_sample: "sample", search_add: "search", search_sample: "sample", maintenance_add: "maintenance" }[c.kind] || "setting"}:${c.target}`),
    isAssetChange(c) ? assetDiff(c) : isSigmaChange(c) ? (c.kind.endsWith("_add") ? el("code", {}, c.evaluation?.conditions ?? "—") : "labeled sample") : el("pre", {}, JSON.stringify(c.payload)), c.reason,
    isAssetChange(c) ? assetImpact(c) : isSigmaChange(c) ? sigmaEvidence(c) : c.evaluation ? el("span", {}, `FP ${c.evaluation.before.fp}→${c.evaluation.after.fp}, TP ${c.evaluation.before.tp}→${c.evaluation.after.tp}, missed ${c.evaluation.after.missed.join(", ") || "none"}`, lostNote(c), liveImpact(c.evaluation.live_impact),
      (c.evaluation.ignore_additions || []).map((x) => el("div", {}, el("strong", {}, `${x.change === "removed" ? "Removes" : "Adds"} ${x.value} ${x.change === "removed" ? "from" : "to"} ${x.param} (permanent, no expiry).`), liveImpact(x.live_impact))),
      backtestBlock(c.evaluation.backtest)) : "—",
    c.proposed_by, c.reviewed_by ? `${c.reviewed_by}${c.review_note ? `: ${c.review_note}` : ""}` : "—",
    c.status === "pending" && can("admin") ? el("span", { class: "row" },
      el("button", { disabled: c.proposed_by === state.user.username, title: c.proposed_by === state.user.username ? "A different admin must review your own proposal" : "", onclick: () => review(c, "approve") }, "Approve"),
      el("button", { class: "ghost", disabled: c.proposed_by === state.user.username, onclick: () => review(c, "reject") }, "Reject")) : "",
  ] }));

  render(
    el("h1", {}, "Detection rules"),
    el("div", { class: "card" },
      el("h2", {}, "How rules change"),
      el("p", {}, "Rules are fixed thresholds you can read and test. No machine learning. Changes to rules or security settings, and asset inventory edits that could lower alert severity, are proposals until a ",
        el("strong", {}, "different"), " admin approves them. Each proposal is scored against the labeled synthetic scenarios before review. Suggestions come from analyst verdicts: when at least two false positives share a cause, such as one IP or one account, Watchpost proposes an exclusion or a new threshold. It never applies the change itself."),
      el("div", { class: "row" },
        can("analyst") ? el("button", { onclick: () => guarded(async () => { const r = await api("/api/rules/suggestions", { method: "POST" }); toast(r.message); rules(); }) }, "Suggest improvements from feedback") : null,
        can("analyst") ? el("button", { class: "ghost", onclick: () => guarded(async () => { await api("/api/evaluations", { method: "POST" }); toast("Evaluation recorded"); rules(); }) }, "Run evaluation") : null,
        el("span", { class: "muted" }, evals[0] ? `Last evaluation ${fmtTime(evals[0].created_at)} (${evals[0].trigger})` : "No evaluations yet"))),
    el("div", { class: "card" }, el("h2", {}, "Export and import tuning"),
      el("p", { class: "muted" }, "The export holds each rule's parameters and enabled state as JSON. Detection logic is code and is not exported, so an import can only retune rules this instance already has. An import applies nothing: each rule that differs becomes a change request for the usual review and backtest."),
      el("div", { class: "row" },
        el("a", { class: "button", href: "/api/rules/export", download: "watchpost-rules.json" }, "Export rules (JSON)"),
        can("analyst") ? el("button", { class: "ghost", onclick: () => importDialog() }, "Import rules…") : null,
        can("analyst") ? el("button", { class: "ghost", onclick: () => sigmaDialog() }, "Import Sigma rule…") : null),
      el("p", { class: "muted" }, "A Sigma rule (a documented subset; see the README) is the one way to add detection logic. It becomes a change request, is added disabled, and can be enabled only once its labeled sample passes.")),
    el("div", { class: "card" }, el("h2", {}, `Change requests (${pending.length} pending)`),
      table(["ID", "Status", "Target", "Change", "Reason", "Scenario impact (before→after)", "Proposed by", "Reviewed", ""], changeRows)),
    el("div", { class: "card" }, el("h2", {}, `Tuning exceptions (${exceptions.filter((x) => x.active).length} active)`),
      el("p", { class: "muted" }, "An exception skips findings of one rule for one group key until it expires or an admin revokes it. The rule itself is not edited. An analyst proposes it, a different admin approves it, and each detection run counts what it skipped. One rule differs: for data_exfil_volume nothing is skipped. The exception turns on a baseline for that principal, which then alerts only when a burst is baseline_multiplier times its own recent normal or more."),
      table(["Rule", "Group key", "Reason", "Expires", "Proposed by", "Approved by", "Change", "State", ""], exceptions.map((x) => ({ cells: [
        el("code", {}, x.rule_id), el("code", {}, x.group_key), x.reason, fmtTime(x.expires_at), x.proposed_by, x.approved_by,
        x.change_request_id ? `#${x.change_request_id}` : "—",
        x.revoked_at ? el("span", { title: `Revoked by ${x.revoked_by} at ${fmtTime(x.revoked_at)}` }, pill("revoked", "st-rejected"), ` by ${x.revoked_by} ${fmtTime(x.revoked_at)}`)
          : x.active ? pill("active", "st-ok") : pill("expired", "st-rejected"),
        x.active && can("admin") ? el("button", { class: "danger", onclick: () => confirm(`Revoke the exception for ${x.rule_id} / ${x.group_key}? It stops applying at once.`) && guarded(async () => { await api(`/api/suppressions/${x.id}/revoke`, { method: "POST" }); toast("Exception revoked"); rules(); }) }, "Revoke") : ""] })))),
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
  const card = focus && document.getElementById(`rule-${focus}`);  // linked from the Coverage view
  if (card) { card.scrollIntoView({ block: "start" }); card.focus({ preventScroll: true }); }
}

// Asset inventory change requests (asset_add / asset_update / asset_delete). Evidence: assets.change_evidence.
const isAssetChange = (c) => c.kind.startsWith("asset_");
const fmtField = (v) => (Array.isArray(v) ? v.join(", ") || "none" : v ?? "—");

// One line for the inventory card, e.g. "lower db01 to low".
function assetChangeText(c) {
  const ev = c.evaluation || {};
  if (c.kind === "asset_delete") return `delete ${ev.asset}`;
  if (c.kind === "asset_add") return `add ${ev.asset} (${ev.after?.criticality})`;
  const crit = ["low", "medium", "high", "critical"];
  return (ev.changes || []).map((x) => {
    if (x.field === "criticality") return `${crit.indexOf(x.after) < crit.indexOf(x.before) ? "lower" : "raise"} ${ev.before.name} to ${x.after}`;
    if (x.field === "name") return `rename ${x.before} to ${x.after}`;
    if (Array.isArray(x.before)) {
      const gone = x.before.filter((v) => !x.after.includes(v)), added = x.after.filter((v) => !x.before.includes(v));
      return [gone.length ? `remove ${gone.join(", ")}` : "", added.length ? `add ${added.join(", ")}` : ""].filter(Boolean).join(", ") + ` (${x.field === "data_tags" ? "tags" : "addresses"})`;
    }
    return `${x.field}: ${fmtField(x.after)}`;
  }).join("; ");
}

// Before → after for each field the change touches; delete and add show the whole asset on one side.
function assetDiff(c) {
  const ev = c.evaluation || {};
  return el("div", { class: "diff" },
    c.kind === "asset_delete" ? el("div", {}, el("strong", {}, `Delete ${ev.asset}`)) : null,
    (ev.changes || []).map((x) => el("div", {}, el("code", {}, x.field), ": ",
      el("span", { class: "before" }, fmtField(x.before)), " → ", el("span", { class: "after" }, fmtField(x.after)))));
}

function assetImpact(c) {
  const ev = c.evaluation || {}, sc = ev.severity_changes || { alerts: 0, recent: [] };
  return el("div", {},
    ev.needs_review?.length ? el("div", {}, el("strong", {}, "Could lower severity: "), ev.needs_review.join("; "), ".")
      : el("div", { class: "muted" }, "Cannot lower severity (sent for review by choice)."),
    el("div", { class: "muted" }, `${sc.alerts} open alert(s) would change severity`, sc.alerts ? ":" : "."),
    sc.recent.map((a) => el("div", { class: "muted" }, `#${a.id} ${a.title}: ${a.from} → ${a.to}`)));
}

// Labeled attacks a rule change stops detecting, from the evidence on the change request.
const detectionLoss = (c) => (c.evaluation ? c.evaluation.before.detected.filter((n) => c.evaluation.after.missed.includes(n)) : []);
// Open alerts the backtest reproduces today and not with the change (backtest.py). Same acknowledgement.
const openAlertsLost = (c) => c.evaluation?.backtest?.counts.open_alerts_lost || 0;
const alertLinks = (list) => list.flatMap((a, n) => [n ? ", " : null, el("a", { href: `#alerts/${a.id}`, title: a.title }, `#${a.id}`)]);

// A rule change replayed over stored events: kept, new and lost findings by group key (backtest.py).
function backtestBlock(bt) {
  if (!bt) return null;
  const c = bt.counts;
  const entities = (x) => Object.keys(ENTITY_KINDS).filter((k) => x.entities[k].length)
    .flatMap((k) => [" · ", `${ENTITY_KINDS[k]}: `, entityLinks(k, x.entities[k])]);
  const finding = (x) => el("li", {}, el("code", {}, x.group_key), entities(x),
    el("div", { class: "muted" }, `${x.event_count} event(s)${x.event_count_today !== undefined && x.event_count_today !== x.event_count ? ` (today ${x.event_count_today})` : ""}, ${fmtTime(x.first_seen)} → ${fmtTime(x.last_seen)}; events #${x.evidence_event_ids.join(", #")}${x.event_count > x.evidence_event_ids.length ? " …" : ""}`),
    x.open_alert_ids.length ? el("div", { class: "bt-warn" }, "Open alert(s) lost: ", alertLinks(x.open_alert_ids.map((id) => ({ id })))) : null);
  const list = (label, items, n) => (n ? el("details", {}, el("summary", {}, `${label}: ${n}${items.length < n ? ` (first ${items.length} shown)` : ""}`),
    el("ul", { class: "bt-list" }, items.map(finding))) : null);
  return el("div", { class: "backtest" },
    el("h3", {}, "Backtest on stored events"),
    bt.window ? el("p", { class: "muted" }, `${fmtTime(bt.window.start)} → ${fmtTime(bt.window.end)} (last ${bt.window_days} day(s) of stored event time), ${bt.events_scanned} events scanned`,
      bt.capped ? el("strong", {}, `; capped at ${bt.max_events} events, so the window starts later`) : null,
      bt.synthetic !== "none" ? el("span", {}, ". ", pill(bt.synthetic === "all" ? "synthetic" : `${bt.synthetic_events} synthetic`, "synthetic")) : null,
      ". Replays stored events only; it cannot predict traffic that has not arrived.")
      : el("p", { class: "muted" }, "No stored events to replay."),
    !bt.running.proposed ? el("p", {}, el("strong", {}, "The change disables the rule: every finding is lost.")) : null,
    el("p", {}, el("strong", {}, `Kept ${c.kept} · New ${c.new} · Lost ${c.lost}`)),
    c.open_alerts_lost ? el("p", { class: "bt-warn" }, el("strong", {}, `Warning: loses ${c.open_alerts_lost} open alert(s) `), alertLinks(bt.open_alerts_lost),
      ". The change would not have raised them. Approving requires an explicit acknowledgement.") : null,
    list("Lost (fire today only)", bt.lost, c.lost), list("New (fire only with the change)", bt.new, c.new), list("Kept", bt.kept, c.kept));
}

// An approval names the evidence this page rendered by its digest; the server applies nothing if it differs.
async function sendReview(c, decision, note, acknowledged) {
  const body = { decision, note };
  if (decision === "approve") { body.evidence_digest = c.evidence_digest; if (acknowledged) body.acknowledge_detection_loss = true; }
  try { await api(`/api/changes/${c.id}/review`, { method: "POST", body }); }
  catch (e) { if (e.status === 409) rules(); throw e; }  // evidence was refreshed: show it, then report why
  toast(`Change #${c.id} ${decision}d`); rules();
}

async function review(c, decision) {
  if (decision === "approve" && c.kind === "rule_update" && (detectionLoss(c).length || openAlertsLost(c))) return lossDialog(c);
  const note = prompt(`${decision === "approve" ? "Approve" : "Reject"} change #${c.id}. Review note:`) ?? null;
  if (note === null) return;
  await guarded(() => sendReview(c, decision, note));
}

function lossDialog(c) {
  const form = el("form", {},
    el("h2", {}, `Approve change #${c.id}: ${c.target}`),
    detectionLoss(c).length ? el("p", {}, "After this change the rule no longer detects these labeled attacks, which it detects today: ", el("strong", {}, detectionLoss(c).join(", ")), ".") : null,
    openAlertsLost(c) ? el("p", {}, `Replayed over stored events, the changed rule would not have raised ${openAlertsLost(c)} alert(s) that are open now: `, alertLinks(c.evaluation.backtest.open_alerts_lost), ".") : null,
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "ack", required: true }), " I accept that this activity will go undetected by this rule"),
    el("label", {}, "Review note", el("textarea", { name: "note", maxlength: 2000 })),
    el("p", { class: "error", role: "alert", id: "loss-error" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Approve"), el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    try { await sendReview(c, "approve", f.get("note"), f.get("ack") === "on"); $("#modal").close(); }
    catch (e) { if (e.status === 409) { $("#modal").close(); toast(e.message); } else $("#loss-error").textContent = e.message; }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
}

function proposeDialog(rule) {
  const form = el("form", {},
    el("h2", {}, `Propose change: ${rule.id}`),
    el("label", {}, "Parameter changes (JSON; only the keys you want to change)", el("textarea", { name: "params", class: "mono" }, JSON.stringify(rule.params, null, 2))),
    el("label", {}, "Enabled", el("select", { name: "enabled" }, el("option", { value: "true", selected: !!rule.enabled }, "enabled"), el("option", { value: "false", selected: !rule.enabled }, "disabled"))),
    el("label", {}, "Reason (required)", el("textarea", { name: "reason", required: true, minlength: 5, maxlength: 2000 })),
    el("p", { class: "error", role: "alert", id: "propose-error" }),
    el("p", { class: "muted", role: "status", id: "backtest-status" }),
    el("div", { id: "backtest-preview" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Submit for review"),
      el("button", { type: "button", class: "ghost", id: "backtest-run", onclick: () => previewBacktest(form, rule) }, "Preview backtest"),
      el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    const body = { reason: f.get("reason") };
    try {
      const changed = changedParams(f, rule);
      if (Object.keys(changed).length) body.params = changed;
      if ((f.get("enabled") === "true") !== !!rule.enabled) body.enabled = f.get("enabled") === "true";
      await api(`/api/rules/${rule.id}/proposals`, { method: "POST", body });
      $("#modal").close();
      toast("Proposal submitted for review");
      rules();
    } catch (e) { $("#propose-error").textContent = e instanceof SyntaxError ? "Parameters must be valid JSON" : e.message; }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
}

// Only the keys that differ from the rule's current params, as a proposal sends them. Throws SyntaxError.
function changedParams(f, rule) {
  const params = JSON.parse(f.get("params"));
  return Object.fromEntries(Object.entries(params).filter(([k, v]) => JSON.stringify(v) !== JSON.stringify(rule.params[k])));
}

// Replays the draft params over stored events (GET /api/rules/{id}/backtest). Changes nothing.
async function previewBacktest(form, rule) {
  const statusLine = $("#backtest-status"), out = $("#backtest-preview");
  $("#propose-error").textContent = "";
  let changed;
  try { changed = changedParams(new FormData(form), rule); } catch { $("#propose-error").textContent = "Parameters must be valid JSON"; return; }
  statusLine.textContent = "Running backtest on stored events…";
  out.replaceChildren();
  try {
    const bt = await api(`/api/rules/${encodeURIComponent(rule.id)}/backtest?params=${encodeURIComponent(JSON.stringify(changed))}`);
    out.replaceChildren(backtestBlock(bt));
    const c = bt.counts;
    statusLine.textContent = `Backtest done: kept ${c.kept}, new ${c.new}, lost ${c.lost}${c.open_alerts_lost ? `, including ${c.open_alerts_lost} open alert(s)` : ""}.`;
  } catch (e) { statusLine.textContent = ""; $("#propose-error").textContent = e.message; }
}

// POST /api/rules/import: a dry run first shows each rule's outcome, then a confirm creates the proposals.
const IMPORT_OUTCOMES = { would_propose: ["would propose", "st-pending"], proposed: ["proposed", "st-pending"], unchanged: ["unchanged", "st-ok"], refused: ["refused", "st-rejected"] };
function importOutcomes(r) {
  const s = r.summary;
  return el("div", {},
    el("p", {}, r.dry_run ? `Dry run: ${s.would_propose} would be proposed, ${s.unchanged} unchanged, ${s.refused} refused. Nothing has been created.`
      : `${s.proposed} proposed for review, ${s.unchanged} unchanged, ${s.refused} refused.`),
    table(["Rule", "Outcome", "Detail"], r.rules.map((x) => ({ cells: [el("code", {}, x.id ?? "—"), pill(...(IMPORT_OUTCOMES[x.outcome] || [x.outcome, ""])),
      x.reason ?? (x.change_id ? `Change request #${x.change_id}` : x.changes ? el("pre", {}, JSON.stringify(x.changes)) : "Same as this instance")] }))));
}

function importDialog() {
  let text = null, label = "";
  const confirmBtn = el("button", { type: "button", id: "import-confirm", disabled: true }, "Create proposals");
  const form = el("form", {},
    el("h2", {}, "Import rules"),
    el("p", { class: "muted" }, "Choose a file from Export rules (JSON). The preview changes nothing. Creating proposals spends one backtest per changed rule from your quota, and a different admin still has to approve each one."),
    el("label", {}, "Rules file (JSON)", el("input", { type: "file", name: "file", required: true, accept: ".json,application/json", onchange: () => { text = null; confirmBtn.disabled = true; $("#import-preview").replaceChildren(); } })),
    el("p", { class: "error", role: "alert", id: "import-error" }),
    el("p", { class: "muted", role: "status", id: "import-status" }),
    el("div", { id: "import-preview" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Preview (dry run)"), confirmBtn,
      el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  const send = async (dryRun) => {
    $("#import-error").textContent = "";
    $("#import-status").textContent = dryRun ? "Checking the file…" : "Creating proposals…";
    try {
      const q = new URLSearchParams({ label });
      if (dryRun) q.set("dry_run", "1");
      const r = await api(`/api/rules/import?${q}`, { method: "POST", raw: text, contentType: "application/json" });
      $("#import-preview").replaceChildren(importOutcomes(r));
      $("#import-status").textContent = dryRun ? "Preview ready." : "Proposals created.";
      confirmBtn.disabled = !dryRun || !r.summary.would_propose;
      if (!dryRun) { toast(`${r.summary.proposed} proposal(s) submitted for review`); rules(); }
    } catch (e) { $("#import-status").textContent = ""; $("#import-error").textContent = e.message; }
  };
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const file = new FormData(form).get("file");
    label = file.name;
    text = await file.text();
    await send(true);
  });
  confirmBtn.addEventListener("click", () => { confirmBtn.disabled = true; send(false); });
  $("#modal-body").replaceChildren(form);
  openModal();
}

// Imported Sigma rules and promoted saved searches: sigma_add / search_add and their *_sample change requests
// (evidence: improve._evidence) and the rule card. Both are added disabled and enabled only on a passing sample.
const isSigmaChange = (c) => c.kind.startsWith("sigma_") || c.kind.startsWith("search_");
const sampleLine = (s) => (s ? el("div", {}, pill(s.passes ? "sample passes" : "sample fails", s.passes ? "st-ok" : "st-rejected"), ` ${s.summary} (${s.malicious} malicious, ${s.benign} benign)`)
  : el("div", { class: "muted" }, "No labeled sample: the rule cannot be enabled and its ATT&CK mapping is not validated."));
const sigmaPreview = (bt) => (bt && bt.window
  ? el("div", { class: "muted" }, `On stored events ${fmtTime(bt.window.start)} → ${fmtTime(bt.window.end)}: ${bt.matched_events} of ${bt.events_scanned} event(s) match, ${bt.findings} finding(s)${bt.group_keys.length ? ` (${bt.group_keys.join(", ")})` : ""}${bt.synthetic_events ? `; ${bt.synthetic_events} of the scanned events are synthetic` : ""}.`)
  : el("div", { class: "muted" }, "No stored events to preview against."));

function sigmaEvidence(c) {
  const ev = c.evaluation || {};
  if (c.kind.endsWith("_sample")) {
    return el("span", {}, ev.before ? el("div", { class: "muted" }, `Before: ${ev.before.summary}`) : null, sampleLine(ev.sample),
      ev.enabled && ev.sample && !ev.sample.passes ? el("div", {}, el("strong", {}, "The rule is enabled: a failing sample drops its ATT&CK coverage to mapped.")) : null);
  }
  if (c.kind === "search_add") {
    return el("span", {}, el("div", {}, `Added disabled. Severity ${ev.severity}; ATT&CK ${(ev.techniques || []).join(", ") || "none"}; query `, el("code", {}, ev.query ?? "—")),
      sampleLine(ev.sample), sigmaPreview(ev.backtest));
  }
  return el("span", {}, el("div", {}, `Added disabled. Severity ${ev.severity}; ATT&CK ${(ev.techniques || []).join(", ") || "none"}; sha256 ${(ev.sha256 || "").slice(0, 12)}…`),
    sampleLine(ev.sample), sigmaPreview(ev.backtest), (ev.warnings || []).map((w) => el("div", { class: "muted" }, w)));
}

function sigmaDetail(r) {
  const s = r.sigma;
  return el("div", {}, el("h3", {}, `Imported Sigma rule (v${r.version})`),
    el("p", {}, el("strong", {}, "Compiled: "), el("code", {}, s.conditions)),
    sampleLine(s.sample_result),
    el("p", { class: "muted" }, `sha256 ${s.sha256}. Imported by ${s.imported_by}, approved by ${s.approved_by}${s.change_request_id ? ` (change #${s.change_request_id})` : ""}. Not tunable: change the YAML and import it again.`),
    el("details", {}, el("summary", {}, "Source YAML (read-only)"), el("pre", { class: "mono" }, s.source)));
}

// POST /api/rules/sigma: a dry run shows the compiled conditions or the refusal, then a confirm sends the same body.
function sigmaDialog() {
  let checked = null;
  const confirmBtn = el("button", { type: "button", disabled: true }, "Submit for review");
  const reset = () => { checked = null; confirmBtn.disabled = true; $("#sigma-preview")?.replaceChildren(); };
  const form = el("form", {},
    el("h2", {}, "Import Sigma rule"),
    el("p", { class: "muted" }, "Only a documented subset of Sigma is supported; anything else is refused with a reason. The dry run compiles the rule and previews it on stored events (one backtest from your quota). Submitting creates a change request: a different admin approves it, and the rule is added disabled. It can be enabled only once its labeled sample passes."),
    el("label", {}, "Sigma file (.yml)", el("input", { type: "file", name: "file", accept: ".yml,.yaml", onchange: async (ev) => { const file = ev.target.files[0]; if (file) form.elements.source.value = await file.text(); reset(); } })),
    el("label", {}, "Sigma rule (YAML)", el("textarea", { name: "source", class: "mono", required: true, rows: 12, oninput: reset })),
    el("label", {}, "Labeled sample (JSON, optional): {\"malicious\": [events], \"benign\": [events]} with Watchpost field names", el("textarea", { name: "sample", class: "mono", rows: 5, oninput: reset })),
    el("label", {}, "Reason (optional)", el("input", { name: "reason", maxlength: 2000 })),
    el("p", { class: "error", role: "alert", id: "sigma-error" }),
    el("p", { class: "muted", role: "status", id: "sigma-status" }),
    el("div", { id: "sigma-preview" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Dry run"), confirmBtn,
      el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  const body = () => {
    const f = new FormData(form);
    const b = { source: f.get("source") };
    const sample = (f.get("sample") || "").trim(), reason = (f.get("reason") || "").trim();
    if (sample) b.sample = JSON.parse(sample);
    if (reason) b.reason = reason;
    return b;
  };
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("#sigma-error").textContent = "";
    reset();
    let b;
    try { b = body(); } catch { $("#sigma-error").textContent = "The sample must be valid JSON"; return; }
    $("#sigma-status").textContent = "Compiling…";
    try {
      const r = await api("/api/rules/sigma?dry_run=1", { method: "POST", body: b });
      const c = r.compiled;
      $("#sigma-status").textContent = r.ok ? "Dry run done. Nothing has been created." : "Refused. Nothing has been created.";
      $("#sigma-preview").replaceChildren(
        r.refused ? el("p", { class: "error" }, `Refused: ${r.refused}`) : null,
        c ? el("div", {},
          el("p", {}, el("strong", {}, "Rule id: "), el("code", {}, c.rule_id), ` · severity ${c.severity} · ATT&CK ${c.techniques.map((t) => t.id).join(", ") || "none"}`),
          el("p", {}, el("strong", {}, "Compiled conditions: "), el("code", {}, c.conditions)),
          c.warnings.map((w) => el("p", { class: "muted" }, w)),
          sampleLine(r.sample), sigmaPreview(r.backtest)) : null);
      if (r.ok) { checked = b; confirmBtn.disabled = false; }
    } catch (e) { $("#sigma-status").textContent = ""; $("#sigma-error").textContent = e.message; }
  });
  confirmBtn.addEventListener("click", async () => {
    confirmBtn.disabled = true;
    try {
      const change = await api("/api/rules/sigma", { method: "POST", body: checked });
      $("#modal").close();
      toast(`Change request #${change.id} submitted for review`);
      rules();
    } catch (e) { $("#sigma-error").textContent = e.message; }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
}

// The rule's labeled sample: malicious events that must match, benign look-alikes that must not. A promoted
// search counts: its malicious events together must raise a finding, its benign ones none.
function sigmaSampleDialog(rule) {
  const current = (rule.sigma || rule.search)?.sample ?? { malicious: [{ event_type: "" }], benign: [{ event_type: "" }] };
  const form = el("form", {},
    el("h2", {}, `Labeled sample: ${rule.id}`),
    el("p", { class: "muted" }, rule.search
      ? "The malicious events must raise a finding (reach the threshold within the window) and the benign look-alikes must raise none. Events without a ts are one second apart. Until the sample passes, the rule cannot be enabled and its ATT&CK techniques count as mapped, not validated. A different admin approves the change."
      : "Every malicious event must match and no benign look-alike may. Until the sample passes, the rule cannot be enabled and its ATT&CK techniques count as mapped, not validated. A different admin approves the change."),
    el("label", {}, "Sample (JSON)", el("textarea", { name: "sample", class: "mono", rows: 10 }, JSON.stringify(current, null, 2))),
    el("label", {}, "Reason (required)", el("textarea", { name: "reason", required: true, minlength: 5, maxlength: 2000 })),
    el("p", { class: "error", role: "alert", id: "sample-error" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Submit for review"),
      el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    let sample;
    try { sample = JSON.parse(f.get("sample")); } catch { $("#sample-error").textContent = "The sample must be valid JSON"; return; }
    try {
      await api(`/api/rules/${encodeURIComponent(rule.id)}/${rule.search ? "search" : "sigma"}-sample`, { method: "POST", body: { sample, reason: f.get("reason") } });
      $("#modal").close();
      toast("Sample submitted for review");
      rules();
    } catch (e) { $("#sample-error").textContent = e.message; }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
}

// A promoted saved search on its rule card: the query is read-only; threshold and window tune via "Propose change…".
function searchDetail(r) {
  const s = r.search;
  return el("div", {}, el("h3", {}, `Promoted saved search (v${r.version})`),
    el("p", {}, el("strong", {}, "Query (read-only): "), el("code", {}, s.query)),
    el("p", {}, el("strong", {}, "Fires on: "), s.conditions),
    sampleLine(s.sample_result),
    el("p", { class: "muted" }, `Proposed by ${s.proposed_by}, approved by ${s.approved_by}${s.change_request_id ? ` (change #${s.change_request_id})` : ""}. Tunable: threshold and window_seconds. A different query means promoting a new saved search.`),
    el("details", {}, el("summary", {}, "Parameters"), el("pre", {}, JSON.stringify({ group_by: r.params.group_by, threshold: r.params.threshold, window_seconds: r.params.window_seconds }, null, 2))));
}

// POST /api/hunt/saved/{id}/promote: a dry run previews the rule's findings on stored events, then a confirm sends
// the same body as a search_add change request. Both spend one backtest from the rule-proposal quota.
const PROMOTE_GROUP_BY = ["src_ip", "user", "host", "dest_ip", "source", "event_type", "dest_port"];
function promoteDialog(saved) {
  let checked = null;
  const confirmBtn = el("button", { type: "button", disabled: true }, "Submit for review");
  const reset = () => { checked = null; confirmBtn.disabled = true; $("#promote-preview")?.replaceChildren(); };
  const form = el("form", { oninput: reset },
    el("h2", {}, "Promote to detection"),
    el("p", { class: "muted" }, "The saved search's filter becomes a threshold rule: it fires when at least N matching events share one group-by value within a sliding window of W minutes. Time terms and | stages are refused; the window replaces them. The query is copied now and cannot be tuned later. The dry run previews findings on stored events; submitting creates a change request that a different admin approves. The rule is added disabled and can be enabled only once its labeled sample passes."),
    el("p", {}, el("strong", {}, "Query: "), el("code", {}, saved.query)),
    el("label", {}, "Rule name", el("input", { name: "name", required: true, maxlength: 80, value: saved.name })),
    el("div", { class: "row" },
      el("label", {}, "Group by", el("select", { name: "group_by" }, PROMOTE_GROUP_BY.map((f) => el("option", { value: f }, f)))),
      el("label", {}, "Threshold (events)", el("input", { name: "threshold", type: "number", min: 1, max: 100000, value: 5, required: true })),
      el("label", {}, "Window (minutes)", el("input", { name: "window_minutes", type: "number", min: 1, max: 1440, value: 10, required: true })),
      el("label", {}, "Severity", el("select", { name: "severity" }, ["low", "medium", "high", "critical"].map((v) => el("option", { value: v, selected: v === "medium" }, v))))),
    el("label", {}, "ATT&CK technique ids (optional, comma separated)", el("input", { name: "techniques", placeholder: "T1110, T1190" })),
    el("label", {}, "Labeled sample (JSON, optional): {\"malicious\": [events], \"benign\": [events]}", el("textarea", { name: "sample", class: "mono", rows: 4 })),
    el("label", {}, "Reason (optional)", el("input", { name: "reason", maxlength: 2000 })),
    el("p", { class: "error", role: "alert", id: "promote-error" }),
    el("p", { class: "muted", role: "status", id: "promote-status" }),
    el("div", { id: "promote-preview" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Dry run"), confirmBtn,
      el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  const body = () => {
    const f = new FormData(form);
    const b = { name: f.get("name"), group_by: f.get("group_by"), threshold: Number(f.get("threshold")),
      window_minutes: Number(f.get("window_minutes")), severity: f.get("severity"),
      techniques: (f.get("techniques") || "").split(",").map((t) => t.trim()).filter(Boolean) };
    const sample = (f.get("sample") || "").trim(), reason = (f.get("reason") || "").trim();
    if (sample) b.sample = JSON.parse(sample);
    if (reason) b.reason = reason;
    return b;
  };
  const url = `/api/hunt/saved/${saved.id}/promote`;
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("#promote-error").textContent = "";
    reset();
    let b;
    try { b = body(); } catch { $("#promote-error").textContent = "The sample must be valid JSON"; return; }
    $("#promote-status").textContent = "Compiling and previewing on stored events…";
    try {
      const r = await api(`${url}?dry_run=1`, { method: "POST", body: b });
      const c = r.compiled, bt = r.backtest;
      $("#promote-status").textContent = r.ok ? "Dry run done. Nothing has been created." : "Refused. Nothing has been created.";
      $("#promote-preview").replaceChildren(
        r.refused ? el("p", { class: "error" }, `Refused: ${r.refused}`) : null,
        c ? el("div", {},
          el("p", {}, el("strong", {}, "Rule id: "), el("code", {}, c.rule_id), ` · severity ${c.severity} · ATT&CK ${c.techniques.map((t) => t.id).join(", ") || "none"}`),
          el("p", {}, el("strong", {}, "Fires on: "), c.conditions),
          sampleLine(r.sample), sigmaPreview(bt),
          bt && bt.sample_findings.length ? table(["Group", "Events", "First seen", "Last seen"], bt.sample_findings.map((x) => ({ cells: [
            el("code", {}, x.group_key), { num: x.event_count }, fmtTime(x.first_seen), fmtTime(x.last_seen)] }))) : null) : null);
      if (r.ok) { checked = b; confirmBtn.disabled = false; }
    } catch (e) { $("#promote-status").textContent = ""; $("#promote-error").textContent = e.message; }
  });
  confirmBtn.addEventListener("click", async () => {
    confirmBtn.disabled = true;
    try {
      const change = await api(url, { method: "POST", body: checked });
      $("#modal").close();
      toast(`Change request #${change.id} submitted for review`);
    } catch (e) { $("#promote-error").textContent = e.message; }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
}

function exceptionDialog(rule) {
  const form = el("form", {},
    el("h2", {}, `Propose exception: ${rule.id}`),
    el("p", { class: "muted" }, "Findings of this rule with exactly this group key are skipped until the exception expires. Copy the group key from an alert of this rule. Use it for known, authorized activity such as the internal scanner 10.0.50.5. For data_exfil_volume the principal is not skipped: the exception makes the rule compare it with its own history, so it still alerts on a burst several times its normal."),
    el("label", {}, "Group key", el("input", { name: "group_key", class: "mono", required: true, maxlength: 256 })),
    el("label", {}, "Expires after (days, 1–90)", el("input", { name: "days", type: "number", min: 1, max: 90, value: 30, required: true })),
    el("label", {}, "Reason (required)", el("textarea", { name: "reason", required: true, minlength: 5, maxlength: 2000 })),
    el("p", { class: "error", role: "alert", id: "exception-error" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, "Submit for review"), el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    try {
      await api(`/api/rules/${rule.id}/suppressions`, { method: "POST", body: { group_key: f.get("group_key").trim(), days: Number(f.get("days")), reason: f.get("reason") } });
      $("#modal").close(); toast("Exception submitted; an admin must approve it"); rules();
    } catch (e) { $("#exception-error").textContent = e.message; }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
}

function settingDialog(s) {
  const form = el("form", {},
    el("h2", {}, `Propose: ${s.key}`), el("p", { class: "muted" }, s.description),
    el("label", {}, `New value (${s.min}–${s.max})`, el("input", { name: "value", type: "number", min: s.min, max: s.max, value: s.value, required: true })),
    el("label", {}, "Reason", el("textarea", { name: "reason", required: true, minlength: 5 })),
    el("p", { class: "error", role: "alert", id: "setting-error" }),
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
  openModal();
}

async function historyDialog(rule) {
  const h = await api(`/api/rules/${rule.id}/history`);
  $("#modal-body").replaceChildren(el("h2", {}, `History: ${rule.id}`),
    table(["Version", "When", "Proposed by", "Approved by", "Enabled", "Params", "Note"], h.map((x) => ({ cells: [
      `v${x.version}`, fmtTime(x.changed_at), x.changed_by, x.approved_by ?? "—", x.enabled ? "yes" : "no", el("pre", {}, JSON.stringify(x.params)), x.note ?? ""] }))),
    el("p", {}, el("button", { onclick: () => $("#modal").close() }, "Close")));
  openModal();
}

// ---------- noise lab ----------
const VERDICT_CLASS = { quiet: "st-ok", noisy: "st-degraded", blind: "st-failing", disabled: "st-rejected", untested: "st-rejected" };

async function noiseLab() {
  const lab = await api("/api/noise-lab");
  const names = (list) => (list.length ? list.join(", ") : "none");
  const rows = lab.rules.map((r) => ({ cells: [
    el("span", {}, r.name, el("div", { class: "muted" }, el("code", {}, r.rule_id))),
    pct(r.recall), pct(r.precision), names(r.lookalikes_tested),
    names(r.lookalikes_fired.concat(r.other_benign_fired)),
    { num: r.suppressed }, pill(r.verdict, VERDICT_CLASS[r.verdict] || "st-rejected"), r.summary] }));
  const lookalikes = lab.scenarios.filter((s) => s.lookalike_of);
  render(
    el("h1", {}, "Noise lab"),
    el("div", { class: "card" },
      el("h2", {}, "Where the rules get noisy"),
      el("p", {}, `Every rule runs against every labeled synthetic scenario, each in isolation: the attacks it should catch and ${lab.summary.lookalikes} benign look-alikes written to resemble them. ${lab.summary.noisy} of ${lab.summary.rules} rules fire on benign activity. That is shown here, not tuned away: a rule is only changed when there is a principled fix that keeps its attack detected.`),
      el("p", { class: "muted" }, "Recall is attacks caught out of attacks labeled. Precision is true detections out of everything the rule fired on, counted on these scenarios only: it says nothing about real traffic. Results use the current rule parameters and approved tuning exceptions (seed ", lab.seed, "). data_exfil_volume uses flat thresholds, so the nightly backup fires here until a tuning exception for the backup server is approved; only then is that one principal compared with its own history.")),
    el("div", { class: "card" }, el("h2", {}, "Rules against their look-alikes"),
      table(["Rule", "Recall", "Precision", "Look-alikes tested", "Benign scenarios that fired", "Excepted", "Verdict", "Reading"], rows)),
    el("div", { class: "card" }, el("h2", {}, "The benign look-alikes"),
      table(["Scenario", "Written for", "What happens"], lookalikes.map((s) => ({ cells: [
        el("span", {}, el("code", {}, s.name), " ", synth(true)), el("code", {}, s.lookalike_of), s.description] })))),
  );
}

// ---------- ATT&CK coverage ----------
const LEVEL_WORD = { validated: "Validated", mapped: "Mapped only", disabled: "Disabled", gap: "Gap" };
const levelPill = (level) => pill(LEVEL_WORD[level] || level, `lv-${level}`);

function coverageDetail(t, meaning) {
  return el("div", {},
    el("h2", {}, `${t.id} ${t.name}`),
    el("p", {}, levelPill(t.level), " ", meaning[t.level]),
    el("p", { class: "muted" }, `Tactic: ${t.tactic}. ${t.hits} live alert(s) from the rules mapped here.`),
    el("h3", {}, "Proving scenarios"),
    t.scenarios.length
      ? el("div", { class: "row" }, t.scenarios.map((n) => el("span", {}, el("code", {}, n), " ", synth(true))))
      : el("p", { class: "muted" }, "None: no labeled attack scenario proves that a running rule detects this technique."),
    el("h3", {}, "Rules"),
    t.rules.length ? table(["Rule", "State", "Noise-lab verdict", "Benign scenarios that fired", "Proves", "Alerts"], t.rules.map((r) => ({ cells: [
      el("a", { href: `#rules/${encodeURIComponent(r.id)}`, title: "Open in Rules & review" }, r.name),
      r.enabled ? pill("enabled", "st-ok") : pill("disabled", "st-rejected"),
      r.verdict ? pill(r.verdict, VERDICT_CLASS[r.verdict] || "st-rejected") : "—",
      r.lookalikes_fired.length ? r.lookalikes_fired.join(", ") : `none (${r.lookalikes_tested.length} look-alike(s) tested)`,
      r.proves.length ? r.proves.join(", ") : "—", { num: r.hits }] })))
      : el("p", { class: "muted" }, "No rule maps to this technique."));
}

async function coverageView() {
  const cov = await api("/api/attack/coverage");
  const lv = cov.summary.levels;
  const detail = el("div", { class: "card", "aria-live": "polite" },
    el("p", { class: "muted" }, "Select a technique to see its rules, their noise-lab verdicts, the scenarios that prove it, and its alerts."));
  const cells = new Map();
  const show = (t) => {
    cells.forEach((b, id) => b.setAttribute("aria-pressed", String(id === t.id)));
    detail.replaceChildren(coverageDetail(t, cov.level_meaning));
  };
  const columns = cov.tactics.map((tac) => {
    const list = cov.techniques.filter((t) => t.tactic === tac.name);
    return el("div", { class: "cov-col", role: "group", "aria-label": `${tac.name}: ${list.length} technique(s)` },
      el("div", { class: "cov-head" }, tac.name),
      list.length ? list.map((t) => {
        const b = el("button", { type: "button", class: `cov-cell lv-${t.level}`, "aria-pressed": "false",
          "aria-label": `${t.id} ${t.name}: ${LEVEL_WORD[t.level]}, ${t.hits} alert(s)`, onclick: () => show(t) },
          el("b", {}, t.id), el("span", {}, t.name.split(": ").pop()),
          el("small", {}, LEVEL_WORD[t.level], t.hits ? ` · ${t.hits} alerts` : ""));
        cells.set(t.id, b);
        return b;
      }) : el("p", { class: "cov-empty muted" }, "No catalog technique"));
  });
  const order = { gap: 0, disabled: 1, mapped: 2 };
  const gaps = cov.techniques.filter((t) => t.level !== "validated").sort((a, b) => order[a.level] - order[b.level] || a.id.localeCompare(b.id));
  render(
    el("div", { class: "page-head" }, el("h1", {}, "ATT&CK coverage"),
      el("a", { href: "/api/attack/navigator.json", download: "watchpost-navigator-layer.json" }, "Export Navigator layer")),
    el("div", { class: "card" },
      el("p", {}, `${lv.validated} of ${cov.summary.techniques} catalog techniques are validated. ${lv.mapped} are mapped by a rule with no labeled scenario proving it, ${lv.disabled} only by disabled rules, and ${lv.gap} by none. Only validated counts as covered.`),
      el("p", { class: "muted" }, "Honesty note: the scenarios are synthetic, so validated means a rule detected the project's own labeled data, not real-world coverage. The catalog holds only techniques a Watchpost rule maps to, not all of ATT&CK."),
      el("div", { class: "legend", role: "list", "aria-label": "Levels" }, cov.levels.map((l) =>
        el("span", { role: "listitem" }, levelPill(l), " ", cov.level_meaning[l])))),
    el("div", { class: "card" }, el("h2", {}, "Tactics × techniques"),
      el("div", { class: "cov-scroll" }, el("div", { class: "cov-grid" }, columns))),
    detail,
    el("div", { class: "card" }, el("h2", {}, `Gaps: not validated (${gaps.length})`),
      gaps.length ? el("ul", { class: "cov-gaps" }, gaps.map((t) => el("li", {}, levelPill(t.level), " ",
        el("button", { type: "button", class: "ghost mini", onclick: () => { show(t); detail.scrollIntoView({ block: "nearest" }); } }, `${t.id} ${t.name}`),
        " ", el("span", { class: "muted" }, t.rules.length ? `Rules: ${t.rules.map((r) => r.id + (r.enabled ? "" : " (disabled)")).join(", ")}` : "No rule"))))
        : el("p", { class: "muted" }, "Every catalog technique is validated on the labeled scenarios.")),
  );
}

// ---------- health ----------
// ---------- log source health ----------
// GET /api/sources/health: per (source, host) status computed from arrival times against the wall clock.
const SOURCE_STATUS = { healthy: "st-ok", late: "st-degraded", silent: "st-failing", learning: "st-pending" };
function agoText(ts) {
  if (!ts) return "—";
  const s = Math.max(0, (Date.now() - Date.parse(ts)) / 1000);
  return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`;
}
const durationText = (sec) => (sec === null || sec === undefined ? "—" : sec < 60 ? `${Math.round(sec)}s` : sec < 3600 ? `${Math.round(sec / 60)}m` : sec < 86400 ? `${(sec / 3600).toFixed(1)}h` : `${(sec / 86400).toFixed(1)}d`);
const sourceHunt = (r) => `source:${huntValue(r.source)}${r.host ? ` host:${huntValue(r.host)}` : ""} last:7d`;

function sourceHealthCard(s) {
  if (!s) return el("div", { class: "card", id: "source-health" }, el("h2", {}, "Log source health"), el("p", { class: "muted" }, "Could not load source health."));
  const t = s.thresholds;
  const where = (r) => `${r.source}${r.host ? ` on ${r.host}` : ""}`;
  const rows = s.sources.map((r) => ({ cells: [
    el("span", {}, el("code", {}, r.source), " ", synth(r.synthetic)),
    r.host ?? el("span", { class: "muted" }, "(no host)"),
    el("span", { class: "row" }, el("span", { class: `pill ${SOURCE_STATUS[r.status]}` }, r.status),
      r.maintenance ? el("span", { class: "pill st-pending", title: r.maintenance.reason }, `maintenance until ${fmtTime(r.maintenance.effective_end)}`) : null),
    el("time", { datetime: r.last_seen, title: fmtTime(r.last_seen) }, agoText(r.last_seen)),
    durationText(r.cadence_seconds), { num: r.events_24h },
    el("span", {}, r.reasons.join("; "),
      r.status === "late" || r.status === "silent"
        ? [" ", el("a", { href: huntHref(sourceHunt(r)), "aria-label": `Hunt its events: ${where(r)}` }, "Hunt its events")] : null)] }));
  const card = el("div", { class: "card", id: "source-health" },
    el("h2", {}, "Log source health"),
    el("p", { class: "muted" }, `Each source and host, by when its events arrived (not their timestamps) against the clock now. Cadence is the median gap between arrivals. `
      + `Late: quiet over ${t.late_multiplier}x cadence, ${durationText(t.late_floor_seconds)}, and its longest recent gap. Silent: over ${t.silent_multiplier}x cadence, ${durationText(t.silent_floor_seconds)}, and twice that gap (rule log_source_silent alerts). `
      + `Learning: under ${t.min_gaps} gaps or ${durationText(t.min_history_seconds)} of history.`),
    el("p", {}, ["silent", "late", "healthy", "learning"].map((k) => [el("span", { class: `pill ${SOURCE_STATUS[k]}` }, `${k} ${s.summary[k]}`), " "])),
    table(["Source", "Host", "Status", "Last arrival", "Cadence", "Events 24h", "Why"], rows),
    s.maintenance_windows.length ? el("div", {}, el("h3", {}, "Maintenance windows"),
      table(["#", "Source", "Host", "Window", "Reason", "Approved by", ""], s.maintenance_windows.map((w) => ({ cells: [
        `#${w.id}`, el("code", {}, w.source), w.host ?? "every host", `${fmtTime(w.starts_at)} – ${fmtTime(w.effective_end)}${w.active ? " (active)" : ""}`, w.reason, w.approved_by,
        can("admin") ? el("button", { class: "ghost", "aria-label": `End now: maintenance window ${w.id}`, onclick: () => guarded(async () => { await api(`/api/sources/maintenance/${w.id}/end`, { method: "POST" }); toast(`Maintenance window #${w.id} ended`); health(); }) }, "End now") : ""] })))) : null);
  if (can("admin")) {
    const form = el("form", { class: "row", "aria-label": "Propose a maintenance window" },
      el("label", {}, "Source", el("input", { name: "source", required: true, maxlength: 64 })),
      el("label", {}, "Host (blank: every host)", el("input", { name: "host", maxlength: 255 })),
      el("label", {}, "Start", el("input", { name: "start", type: "datetime-local", required: true })),
      el("label", {}, "End", el("input", { name: "end", type: "datetime-local", required: true })),
      el("label", {}, "Reason", el("input", { name: "reason", required: true, minlength: 5, maxlength: 2000 })),
      el("button", { type: "submit" }, "Propose window"));
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const f = new FormData(form);
      guarded(async () => {
        const c = await api("/api/sources/maintenance", { method: "POST", body: { source: f.get("source").trim(), host: f.get("host").trim() || null,
          start: new Date(f.get("start")).toISOString(), end: new Date(f.get("end")).toISOString(), reason: f.get("reason") } });
        toast(`Change request #${c.id} created: a second admin approves it on the Rules page`);
        form.reset();
      });
    });
    card.append(el("h3", {}, "Propose a maintenance window"), el("p", { class: "muted" }, "Silence inside an approved window does not alert. Times are your local time."), form);
  }
  return card;
}

async function health() {
  const [h, srcs] = await Promise.all([api("/api/health/details"), api("/api/sources/health").catch(() => null)]);
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
    sourceHealthCard(srcs),
    el("div", { class: "card" }, el("h2", {}, "Recent errors (redacted)"),
      table(["When", "Component", "Error", "Guidance"], h.recent_errors.map((e) => ({ cells: [fmtTime(e.created_at), e.component, el("code", {}, e.message), e.guidance ?? ""] })))),
    el("div", { class: "card" }, el("h2", {}, "Recent detection runs"),
      table(["#", "Started", "Trigger", "Status", "Scanned", "Created", "Updated", "Suppressed", "Error"], h.recent_detection_runs.map((r) => ({ cells: [
        r.id, fmtTime(r.started_at), r.trigger, pill(r.status, r.status === "ok" ? "st-ok" : r.status === "failed" ? "st-failing" : "st-degraded"),
        { num: r.events_scanned }, { num: r.alerts_created }, { num: r.alerts_updated }, { num: r.alerts_suppressed ?? 0 }, r.error ?? ""] })))),
  );
}

// ---------- admin ----------
async function admin() {
  if (!can("admin")) return render(el("p", {}, "Admins only."));
  const [tokens, audit, inventory, chain, sessions] = await Promise.all([api("/api/tokens"), api("/api/audit"), api("/api/assets"), api("/api/audit/verify"), api("/api/sessions")]);
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
  const resetForm = el("form", { class: "row" },
    el("label", {}, "Username", el("input", { name: "username", required: true, maxlength: 32, autocomplete: "off" })),
    el("button", { type: "submit", class: "danger" }, "Reset two-factor"));
  resetForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const username = new FormData(resetForm).get("username").trim();
    if (!confirm(`Turn off two-factor sign-in for "${username}"? They sign in with the password alone until they enroll again.`)) return;
    guarded(async () => { await api(`/api/users/${encodeURIComponent(username)}/mfa/reset`, { method: "POST" }); toast(`Two-factor reset for ${username}`); admin(); });
  });
  const demoOut = el("div");
  let inventoryCard = assetsCard(inventory);
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
        // The load seeds the demo inventory: redraw the card in place so the results above stay visible.
        const fresh = assetsCard(await api("/api/assets"));
        inventoryCard.replaceWith(fresh);
        inventoryCard = fresh;
      }) }, "Load synthetic demo data"), demoOut),
    storyCard(),
    inventoryCard,
    el("div", { class: "card" }, el("h2", {}, "API tokens (ingest only)"), tokenForm, tokenOut,
      table(["Name", "Prefix", "Created", "Last used", "Status", ""], tokens.map((t) => ({ cells: [t.name, el("code", {}, `${t.prefix}…`), `${fmtTime(t.created_at)} by ${t.created_by}`, fmtTime(t.last_used_at),
        t.revoked_at ? pill("revoked", "st-rejected") : pill("active", "st-ok"),
        t.revoked_at ? "" : el("button", { class: "danger", onclick: () => confirm(`Revoke token "${t.name}"?`) && guarded(async () => { await api(`/api/tokens/${t.id}/revoke`, { method: "POST" }); admin(); }) }, "Revoke")] })))),
    el("div", { class: "card" }, el("h2", {}, "Sign-in sessions"),
      el("p", { class: "muted" }, "Every active session. Revoking one signs that browser out at its next request. For someone who lost their authenticator app, reset their two-factor here: there are no recovery codes."),
      sessionsTable(sessions, "/api/sessions", admin, true), resetForm),
    el("div", { class: "card" }, el("h2", {}, "Audit log"), chainBadge(chain),
      table(["When", "Actor", "Action", "Target", "Detail"], audit.map((a) => ({ cells: [fmtTime(a.created_at), a.actor, a.action, a.target ?? "", el("code", {}, a.detail ?? "")] })))),
  );
}

// ---------- account security ----------
// Sessions are addressed by a non-secret id; the API never returns a session token or its hash.
function sessionsTable(rows, base, redraw, showUser = false) {
  const revoke = (r) => confirm(r.current ? "Revoke this session? You will be signed out." : `Revoke the session started ${fmtTime(r.created_at)}?`) && guarded(async () => {
    await api(`${base}/${r.id}/revoke`, { method: "POST" });
    if (r.current) return showLogin();
    toast("Session revoked");
    redraw();
  });
  return table([...(showUser ? ["User"] : []), "Started", "Last seen", "Expires", ""], rows.map((r) => ({ cells: [
    ...(showUser ? [r.username] : []), fmtTime(r.created_at), fmtTime(r.last_seen_at), fmtTime(r.expires_at),
    el("span", { class: "row" }, r.current ? pill("this browser", "st-ok") : null,
      can("analyst") ? el("button", { class: "danger", "aria-label": `Revoke session started ${fmtTime(r.created_at)}${showUser ? ` for ${r.username}` : ""}`, onclick: () => revoke(r) }, "Revoke") : null)] })));
}

async function account() {
  const [mfa, sessions] = await Promise.all([api("/api/auth/mfa/status"), api("/api/auth/sessions")]);
  const out = el("div");
  const codeForm = (label, action, onDone) => {
    const code = el("input", { name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: 6, required: true });
    const form = el("form", { class: "row" }, el("label", {}, "Authentication code", code), el("button", { type: "submit" }, label));
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      guarded(async () => { await api(action, { method: "POST", body: { code: code.value.trim() } }); onDone(); });
    });
    return form;
  };
  let twoFactor;
  if (!mfa.available) {
    twoFactor = el("p", { class: "muted" }, "This read-only account signs in with a password only.");
  } else if (mfa.enabled) {
    twoFactor = el("div", {}, el("p", {}, pill("on", "st-ok"), " Sign-in asks for a code from your authenticator app after the password."),
      el("p", { class: "muted" }, "To turn it off, enter a current code."),
      codeForm("Turn off two-factor", "/api/auth/mfa/disable", () => { toast("Two-factor sign-in is off"); account(); }));
  } else {
    const start = el("button", { onclick: () => guarded(async () => {
      const r = await api("/api/auth/mfa/enroll", { method: "POST" });
      out.replaceChildren(el("div", { class: "explain" },
        el("p", {}, "Enter this in your authenticator app (time-based, 6 digits, 30 seconds), then confirm with the code it shows. It is not active until you confirm."),
        el("p", {}, el("strong", {}, "Secret: "), el("code", {}, r.secret)),
        el("p", {}, el("strong", {}, "Setup URI: "), el("code", { style: { wordBreak: "break-all" } }, r.otpauth_uri)),
        codeForm("Confirm and turn on", "/api/auth/mfa/confirm", () => { toast("Two-factor sign-in is on"); account(); })));
    }) }, mfa.pending ? "Start over with a new secret" : "Set up two-factor sign-in");
    twoFactor = el("div", {}, el("p", {}, pill("off", "st-degraded"), " Add a code from an authenticator app to your sign-in."),
      mfa.pending ? el("p", { class: "muted" }, "A setup was started but not confirmed; it is not active.") : null, start, out);
  }
  render(
    el("h1", {}, "Account security"),
    el("div", { class: "card" }, el("h2", {}, "Two-factor sign-in"), twoFactor,
      mfa.available ? el("p", { class: "muted" }, "There are no recovery codes: if you lose the app, an admin can reset your two-factor.") : null),
    el("div", { class: "card" }, el("h2", {}, "Your sessions"), sessionsTable(sessions, "/api/auth/sessions", account)),
  );
}

// Result of GET /api/audit/verify: each entry's hash covers its contents and the hash of the entry before it.
function chainBadge(c) {
  const start = c.chain_started ? `entry #${c.chain_started.id} (${fmtTime(c.chain_started.created_at)})` : "";
  const badge = c.status === "verified"
    ? pill(`Chain verified from ${start}: ${c.entries} entries, head ${c.head.hash.slice(0, 12)}`, "st-ok")
    : c.status === "partial"
      // Rows older than the chain start were never hashed: intact is not the same as verified.
      ? pill(`Chain intact from ${start}, but ${c.legacy.entries} earlier entries are not verified`, "st-degraded")
      : pill(`Chain broken at entry #${c.first_break.id ?? "?"}: ${c.first_break.reason.replaceAll("_", " ")}`, "st-failing");
  const legacy = c.status === "broken" && c.legacy?.entries
    ? el("span", {}, " ", pill(`${c.legacy.entries} earlier entries predate the chain and are not verified`, "st-degraded"))
    : null;
  return el("p", {}, badge, legacy, " ",
    el("span", { class: "muted" }, c.status === "broken"
      ? `${c.first_break.detail}. The log was changed outside the application, or the server runs with another SIEM_AUDIT_KEY.`
      : `Edits and deletions after the chain start are detected. Record the head hash and chain start elsewhere to also catch removal of the newest entries, or a chain that restarts.${c.keyed ? "" : " Unkeyed (no SIEM_AUDIT_KEY): anyone who can write the database could recompute the chain."}`));
}

// ---------- asset inventory ----------
function assetsCard(inv) {
  const pending = inv.pending || [];
  const proposed = (c) => el("div", { class: "pending-note st-pending" }, `Proposed: ${assetChangeText(c)} (pending review, `, el("a", { href: "#rules" }, `change #${c.id}`), ")");
  // A delete always needs a second admin: it is proposed with a reason, never applied from here.
  const remove = (a) => {
    const reason = prompt(`Deleting "${a.name}" needs a second admin's approval. Reason for the change request:`);
    if (reason === null) return;
    guarded(async () => {
      const r = await api(`/api/assets/${a.id}/proposals`, { method: "POST", body: { delete: true, reason } });
      toast(`Delete proposed as change #${r.id}; a different admin must approve it`);
      admin();
    });
  };
  return el("div", { class: "card" }, el("h2", {}, "Asset inventory"),
    el("p", { class: "muted" }, "Give systems a weight of importance and tag the ones that process sensitive data. Alerts whose evidence touches a ",
      el("strong", {}, "high"), " asset gain one severity level, a ", el("strong", {}, "critical"), " asset two, and any sensitive-data tag one more (capped at two, never past critical). The rule's own severity stays visible on the alert. Changing the inventory re-weighs open alerts at once."),
    el("p", { class: "muted" }, "Edits that could lower alert severity (lower criticality, remove a tag or address, rename, delete, or claim another asset's address) are proposals until a ",
      el("strong", {}, "different"), " admin approves them under Rules & review. Everything else applies at once. Both are audited."),
    el("div", { class: "row" }, el("button", { onclick: () => assetDialog(inv) }, "Add asset")),
    pending.filter((c) => c.kind === "asset_add").map(proposed),
    table(["Asset", "Kind", "Criticality", "Sensitive data", "Addresses", "Owner", "Updated", ""], inv.assets.map((a) => ({ cells: [
      el("span", {}, el("strong", {}, a.name), a.synthetic ? el("span", {}, " ", synth(true)) : null, a.description ? el("div", { class: "muted" }, a.description) : null,
        pending.filter((c) => c.kind !== "asset_add" && c.target === String(a.id)).map(proposed)),
      a.kind, pill(a.criticality, `crit-${a.criticality}`),
      a.data_tags.length ? el("span", { class: "row" }, a.data_tags.map((t) => el("span", { class: "pill tag", title: inv.data_tags[t] || t }, t))) : el("span", { class: "muted" }, "—"),
      a.addresses.length ? el("code", {}, a.addresses.join(", ")) : "—", a.owner ?? "—", `${fmtTime(a.updated_at)} by ${a.updated_by}`,
      el("span", { class: "row" }, el("button", { class: "ghost", onclick: () => assetDialog(inv, a) }, "Edit"), el("button", { class: "danger", onclick: () => remove(a) }, "Delete"))] }))));
}

function assetDialog(inv, asset = null) {
  const opt = (values, current) => values.map((v) => el("option", { value: v, selected: v === current }, v));
  const tags = Object.entries(inv.data_tags).map(([t, help]) => el("label", { class: "check", title: help },
    el("input", { type: "checkbox", name: "data_tags", value: t, checked: asset?.data_tags.includes(t) || null }), ` ${t}`));
  const form = el("form", {},
    el("h2", {}, asset ? `Edit asset: ${asset.name}` : "Add asset"),
    el("label", {}, "Host name (matches the event host field)", el("input", { name: "name", required: true, maxlength: 128, pattern: "[A-Za-z0-9_.:\\-]+", value: asset?.name ?? "", placeholder: "e.g. db01" })),
    el("div", { class: "row" },
      el("label", {}, "Kind", el("select", { name: "kind" }, opt(inv.kinds, asset?.kind ?? "server"))),
      el("label", {}, "Criticality (weight of importance)", el("select", { name: "criticality" }, opt(inv.criticalities, asset?.criticality ?? "medium")))),
    el("fieldset", {}, el("legend", {}, "Processes sensitive data"), el("div", { class: "row" }, tags)),
    el("label", {}, "IP addresses (optional, comma-separated; match src/dest IP)", el("input", { name: "addresses", value: asset?.addresses.join(", ") ?? "", placeholder: "10.0.0.10, 10.0.0.11" })),
    el("label", {}, "Owner (optional)", el("input", { name: "owner", maxlength: 128, value: asset?.owner ?? "" })),
    el("label", {}, "Description (optional)", el("input", { name: "description", maxlength: 500, value: asset?.description ?? "" })),
    el("p", { class: "error", role: "alert", id: "asset-error" }),
    el("div", { id: "asset-review" }),
    el("div", { class: "row" }, el("button", { type: "submit" }, asset ? "Save" : "Add"), el("button", { type: "button", class: "ghost", onclick: () => $("#modal").close() }, "Cancel")));
  // The server refuses an edit that could lower alert severity (409, review_required) and names the
  // proposal route; the same body plus a reason becomes a change request for a different admin.
  const offerReview = (data, body) => {
    const reason = el("textarea", { name: "reason", maxlength: 2000 });
    $("#asset-error").textContent = "";
    $("#asset-review").replaceChildren(el("div", { class: "explain" },
      el("p", {}, el("strong", {}, "A different admin must approve this edit: "), `it ${data.reasons.join("; ")}.`),
      el("label", {}, "Reason for the change request", reason),
      el("button", { type: "button", onclick: async () => {
        try {
          const r = await api(data.proposal_route, { method: "POST", body: { ...body, reason: reason.value } });
          $("#modal").close();
          toast(`Proposed as change #${r.id}; pending review`);
          admin();
        } catch (e) { $("#asset-error").textContent = e.message; }
      } }, "Propose for review")));
  };
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    const body = { name: f.get("name"), kind: f.get("kind"), criticality: f.get("criticality"), data_tags: f.getAll("data_tags"),
      addresses: f.get("addresses"), owner: f.get("owner"), description: f.get("description"), synthetic: asset?.synthetic ? true : false };
    try {
      const r = await api(asset ? `/api/assets/${asset.id}` : "/api/assets", { method: "POST", body });
      $("#modal").close();
      toast(`Asset saved; ${r.alerts_rescored} open alert(s) changed severity`);
      admin();
    } catch (e) {
      if (e.status === 409 && e.data?.review_required) offerReview(e.data, body);
      else $("#asset-error").textContent = e.message;
    }
  });
  $("#modal-body").replaceChildren(form);
  openModal();
}

function storyCard() {
  const out = el("div", { class: "story-status muted" }, "Loading…");
  const speed = el("select", { "aria-label": "Storyline speed" }, ...[["1", "Real time (2 min)"], ["2", "2x (1 min)"], ["10", "10x (12 s)"], ["100", "Instant"]].map(([v, t]) => el("option", { value: v }, t)));
  let timer = null;
  const render = (s) => {
    const stage = s.running ? `stage: ${s.stage} · ${Math.round((s.progress || 0) * 100)}%` : s.finished_at ? `last run finished ${fmtTime(s.finished_at)}` : "idle";
    out.replaceChildren(el("div", {}, `${s.running ? "Running" : "Idle"} — ${stage}`),
      el("div", { class: "muted" }, `${s.events_sent ?? 0} synthetic events sent, ${s.alerts_created ?? 0} alerts raised${s.error ? ` · error: ${s.error}` : ""}`));
    if (s.running && !timer) timer = setInterval(poll, 2000);
    if (!s.running && timer) { clearInterval(timer); timer = null; refreshBanner(); }
  };
  const poll = () => api("/api/storyline/status").then(render).catch(() => {});
  poll();
  return el("div", { class: "card" }, el("h2", {}, "Attack storyline (synthetic)"),
    el("p", { class: "muted" }, "Replays a scripted six-stage intrusion — recon, credential attack, foothold, escalation, lateral movement, exfiltration — from RFC 5737 test addresses. Watch the SOC dashboard while it runs. Everything is labeled synthetic."),
    el("div", { class: "row" }, speed,
      el("button", { onclick: () => guarded(async () => { render(await api("/api/storyline/start", { method: "POST", body: { speed: Number(speed.value) } })); }) }, "Start storyline"),
      el("button", { class: "danger", onclick: () => guarded(async () => { render(await api("/api/storyline/stop", { method: "POST" })); }) }, "Stop")),
    out);
}

// ---------- keyboard triage ----------
// j/k move the selection through the list marked data-kbd-list (Alerts, Incidents); Enter opens it
// (rows handle Enter themselves, board cards are links). / focuses the view's search box or opens Hunt,
// ? shows the help. Views add their own keys in state.keys (alert detail: a, r, Esc). Nothing fires
// while typing in a field, while a dialog is open, or with Ctrl/Alt/Cmd held.
const KBD_ITEMS = "[data-kbd-list] tr.clickable, [data-kbd-list] a.bcard";
const isTyping = (t) => !!t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName));

function shortcutsAllowed(ev) {
  const m = $("#modal");
  // A field inside the just-closed dialog can hold focus until its close event runs: that is not typing.
  return !!state.user && !ev.ctrlKey && !ev.metaKey && !ev.altKey && !m.open && (!isTyping(ev.target) || m.contains(ev.target));
}

function selectItem(node) {
  document.querySelectorAll(".kbd-selected").forEach((n) => n.classList.remove("kbd-selected"));
  node.classList.add("kbd-selected");
  node.focus({ preventScroll: true });
  node.scrollIntoView({ block: "nearest" });
}

function moveSelection(step) {
  const items = [...document.querySelectorAll(KBD_ITEMS)];
  if (!items.length) return;
  let cur = items.indexOf(document.activeElement);
  if (cur === -1) cur = items.findIndex((n) => n.classList.contains("kbd-selected"));
  selectItem(items[cur === -1 ? (step > 0 ? 0 : items.length - 1) : Math.min(items.length - 1, Math.max(0, cur + step))]);
}

// After Esc from a detail page, put the selection back on the item it came from.
function restoreSelection(selector) {
  if (state.restore === null) return;
  state.restore = null;
  const node = document.querySelector(selector);
  if (node) selectItem(node);
}

function focusSearch() {
  const box = document.querySelector("#view [data-search]");
  if (box) { box.focus(); box.select(); return; }
  state.focusSearch = true;
  go("hunt");
}

function shortcutHelp() {
  const rows = [["j / k", "Next / previous alert or incident in the list"], ["Enter", "Open the selected alert or incident"],
    ["Esc", "Alert or incident page: back to the list. In a dialog: close it"]];
  if (can("analyst")) rows.push(["a", "Alert or incident page: start investigating"], ["r", "Alert page: open the resolve dialog"]);
  rows.push(["/", "Focus the search box (opens Hunt when the view has none)"], ["?", "Show this help"]);
  $("#modal-body").replaceChildren(el("h2", {}, "Keyboard shortcuts"),
    table(["Key", "Action"], rows.map(([k, a]) => ({ cells: [el("kbd", {}, k), a] }))),
    el("p", { class: "muted" }, "Shortcuts do nothing while you type in a field or while a dialog is open.",
      can("analyst") ? "" : " This account is read-only, so it can move and open but has no action keys."),
    el("p", {}, el("button", { onclick: () => $("#modal").close() }, "Close")));
  openModal();
}

function onShortcut(ev) {
  if (!shortcutsAllowed(ev)) return;
  const keys = { j: () => moveSelection(1), k: () => moveSelection(-1), "/": focusSearch, "?": shortcutHelp, ...(state.keys || {}) };
  const action = Object.hasOwn(keys, ev.key) ? keys[ev.key] : null;
  if (!action) return;
  ev.preventDefault();
  action();
}

boot();
