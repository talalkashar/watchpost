import { seedLayout, stepLayout, signalChains } from "./graph-layout.js";
import { galaxyGroups, particlePlan, galaxyMotion, nebulaTile } from "./graph-galaxy.js";
import { fitFrame, limitCenter } from "./graph-camera.js";

// An evidence graph is a snapshot. All geometry is local; ids and detail pivots come from the API.
const Graph = (() => {
  const types = {
    incident: { name: "Incident", plural: "Incidents", color: "#bb99ff" },
    alert: { name: "Alert", plural: "Alerts", color: "#ffbd66" },
    host: { name: "Host", plural: "Hosts", color: "#5ce3ee" },
    user: { name: "User", plural: "Users", color: "#72eab1" },
    src_ip: { name: "Source IP", plural: "Source IPs", color: "#75aaff" },
  };
  const severityColor = { critical: "#ff806f", high: "#ffac61", medium: "#f5db78", low: "#93b9ff", info: "#afc1d5" };
  const edgeColor = { evidence: "#b9cddb", membership: "#e1d4ef", correlation: "#ffe1b5" };
  const tau = Math.PI * 2;
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const cap = (s) => s[0].toUpperCase() + s.slice(1);
  let dispose = null;

  function glyph(ctx, kind, x, y, r) {
    ctx.beginPath();
    if (kind === "incident" || kind === "user") ctx.arc(x, y, r, 0, tau);
    else if (kind === "src_ip") ctx.rect(x - r * 0.82, y - r * 0.82, r * 1.64, r * 1.64);
    else {
      const count = kind === "host" ? 6 : 4;
      for (let i = 0; i < count; i++) {
        const angle = i * tau / count - Math.PI / 2;
        const xx = x + r * Math.cos(angle), yy = y + r * Math.sin(angle);
        if (i) ctx.lineTo(xx, yy); else ctx.moveTo(xx, yy);
      }
      ctx.closePath();
    }
  }

  async function open() {
    const data = await readView("graph", () => api("/api/graph"));
    if (!data) return;
    const nodes = data.nodes.map((n) => ({
      ...n, color: n.type === "alert" ? severityColor[n.severity] : types[n.type].color,
      caption: n.type === "incident" ? `Incident ${n.ref}` : n.type === "alert" ? (n.techniques[0] || `Alert ${n.ref}`) : n.label,
    }));
    const edges = data.edges.map((e) => ({ ...e, a: nodes[e.source], b: nodes[e.target] }));
    const groups = galaxyGroups(nodes, edges);
    let activeGroups = [], starCount = 0;
    const shownTypes = new Set(Object.keys(types));
    let severity = "all", visible = [], links = [], selected = null, neighborhood = new Set();
    let width = 0, height = 0, zoom = 1, scale = 1, bounds, cx = 0, cy = 0;
    let frame = 0, observer, drag = null, holdTimer = 0, clickTimer = 0;
    let onScreen = false, warmed = false, stepsLeft = 0, stepClock = 0, elapsed = 0, previous = null;
    let lastTap = null, followingFit = true, flight = null, locked = null, batches = [], chains = [];
    const pointers = new Map(), controller = new AbortController(), signal = controller.signal;
    const mobile = matchMedia("(max-width: 760px)");
    // Tablets and touch laptops are wider than the phone layout but still have no hover click.
    const coarse = matchMedia("(hover: none), (pointer: coarse)");
    const canvas = el("canvas", { class: "graph-canvas", tabindex: "0", role: "group",
      "aria-description": "Shift and arrow keys pan. Drag a node to pin it. Double-click to unpin and fit. Space toggles a pin.",
      "aria-label": "Investigation graph. Use the arrow keys to inspect nodes and Enter to open details." });
    const ctx = canvas.getContext("2d");
    const tip = el("div", { class: "graph-tip", hidden: true, role: "status" });
    const empty = el("div", { class: "graph-empty", hidden: true });
    const counts = el("div", { class: "graph-counts", "aria-live": "polite" });
    const zoomText = el("output", { "aria-label": "Zoom level" });
    const stage = el("div", { class: "graph-stage" }, canvas, tip, empty);
    const chip = (text, action, attrs = {}) => el("button", { type: "button", onclick: action, ...attrs }, text);
    const zoomBy = (factor) => zoomAt(width / 2, height / 2, factor);
    const camera = el("div", { class: "graph-camera", role: "group", "aria-label": "Graph camera" },
      chip("−", () => zoomBy(1 / 1.25), { "aria-label": "Zoom out" }), zoomText,
      chip("+", () => zoomBy(1.25), { "aria-label": "Zoom in" }),
      chip("Fit", () => { locked = null; select(null); fit(); }, { class: "graph-fit", "aria-label": "Fit graph to screen" }));
    const typeButtons = Object.entries(types).map(([key, t]) => {
      const count = nodes.filter((n) => n.type === key).length;
      return chip([el("i", { class: `graph-symbol symbol-${key}`, "aria-hidden": "true" }), t.plural,
        el("small", {}, count)], () => {
        if (shownTypes.has(key)) shownTypes.delete(key); else shownTypes.add(key);
        update();
      }, { class: "graph-type", "data-type": key, "aria-label": t.plural });
    });
    const severities = ["all", ...Object.keys(severityColor)];
    const severityButtons = severities.map((s) => chip(cap(s), () => { severity = s; update(); },
      { class: "graph-level", "data-level": s }));
    const filterState = el("small", { class: "graph-filter-state" });
    const results = el("div", { class: "graph-results" });
    const search = el("input", { type: "search", placeholder: "Find a node", "aria-label": "Find a node",
      autocomplete: "off", oninput: searchNodes });
    const key = el("details", { class: "graph-key", open: !mobile.matches },
      el("summary", {}, "Filters & legend", filterState),
      el("div", { class: "graph-key-body" },
        el("div", { class: "graph-search" }, search, results),
        el("p", { class: "graph-cloud-key" }, el("i", { "aria-hidden": "true" }), "Dust groups related evidence."),
        el("h2", {}, "Node types"), el("div", { class: "graph-types" }, typeButtons),
        el("h2", {}, "Severity"), el("div", { class: "graph-levels" }, severityButtons),
        el("h2", {}, "Connections"), el("ul", { class: "graph-lines" },
          [["evidence", "Alert evidence"], ["membership", "Incident member"], ["correlation", "Correlated alerts"]].map(
            ([k, name]) => el("li", {}, el("i", { class: `line-${k}` }), name)))));
    const desk = el("section", { class: "graph-desk", "aria-labelledby": "graph-title" },
      el("header", { class: "graph-head" }, el("div", {}, el("h1", { id: "graph-title" }, "Investigation graph"),
        el("p", {}, "Explore the evidence connecting alerts, entities and incidents.")), counts),
      el("div", { class: "graph-workspace" }, el("div", { class: "graph-map" }, stage,
        el("footer", { class: "graph-footer" }, el("span", { class: "graph-hint" },
          mobile.matches ? "Pinch to zoom · Hold to inspect" : "Drag to pan · Scroll to zoom · Click to investigate"), camera)), key),
      data.limited ? el("p", { class: "graph-limit" }, "Showing a bounded sample of the latest alerts and their evidence.") : null);
    render(desk);

    function update() {
      const matches = new Set(nodes.filter((n) => n.severity === severity));
      // Entities have no severity of their own. Keep the evidence of matching alerts.
      if (severity !== "all") {
        for (const e of edges) if (e.type === "evidence" && matches.has(e.a)) matches.add(e.b);
      }
      visible = nodes.filter((n) => shownTypes.has(n.type) && (severity === "all" || matches.has(n)));
      const included = new Set(visible);
      links = edges.filter((e) => included.has(e.a) && included.has(e.b));
      activeGroups = groups.filter(group => {
        group.shown = group.members.filter(n => included.has(n));
        return group.shown.length;
      });
      prepareDust();
      for (const n of visible) n.degree = 0;
      for (const e of links) { e.a.degree++; e.b.degree++; }
      // Prefer identifiable entities and incident hubs as labels compete for space.
      labelOrder = [...visible].sort((a, b) => (b.type === "incident") - (a.type === "incident") ||
        (a.type === "alert") - (b.type === "alert") || b.degree - a.degree);
      for (const b of typeButtons) b.setAttribute("aria-pressed", String(shownTypes.has(b.dataset.type)));
      for (const b of severityButtons) b.setAttribute("aria-pressed", String(b.dataset.level === severity));
      const count = (v, singular) => el("span", {}, el("b", {}, v), ` ${singular}${v === 1 ? "" : "s"}`);
      counts.replaceChildren(count(visible.length, "node"), count(links.length, "link"));
      const filters = [];
      if (severity !== "all") filters.push(cap(severity));
      if (shownTypes.size !== typeButtons.length) filters.push(`${shownTypes.size}/${typeButtons.length} types`);
      filterState.textContent = filters.join(" · ");
      empty.hidden = !!visible.length;
      empty.textContent = nodes.length ? "No nodes match these filters." : "No alerts yet. Detected alerts and their evidence will appear here.";
      locked = null;
      if (selected) select(null); else prepareLinks();
      searchNodes(); fit();
    }

    function searchNodes() {
      const query = search.value.trim().toLowerCase();
      results.replaceChildren();
      if (!query) return;
      const matches = labelOrder.filter(n => [n.label, n.title, n.caption, n.ref, n.rule]
        .some(value => value != null && String(value).toLowerCase().includes(query)));
      for (const n of matches.slice(0, 8)) {
        results.append(chip([el("small", {}, types[n.type].name, n.ref ? ` #${n.ref}` : ""),
          n.title || n.label], () => {
          if (mobile.matches) key.open = false;
          canvas.focus({ preventScroll: true }); stage.scrollIntoView({ block: "nearest" });
          resize(); focusNode(n);
        }));
      }
      if (!matches.length) results.append(el("small", { role: "status" }, "No matching nodes."));
    }

    function focusNode(n) {
      locked = n; select(n); followingFit = false;
      flight = { n, x: cx, y: cy, zoom, start: elapsed, endZoom: Math.min(bounds.maxZoom, Math.max(zoom, 2)) };
      requestDraw();
    }

    function setZoom(value) {
      zoom = value;
      const label = `${Math.round(zoom * 100)}%`;
      if (zoomText.textContent !== label) zoomText.textContent = label;
    }

    function fit() {
      flight = null; followingFit = true;
      bounds = fitFrame(visible, width, height); scale = bounds.scale;
      cx = (bounds.left + bounds.right) / 2; cy = (bounds.top + bounds.bottom) / 2;
      setZoom(1); requestDraw();
    }

    function constrain() {
      const center = limitCenter(bounds, visible, width, height, zoom, cx, cy);
      cx = center.x; cy = center.y;
    }

    function pan(dx, dy) {
      followingFit = false; flight = null;
      cx -= dx / (scale * zoom); cy -= dy / (scale * zoom);
      constrain(); requestDraw();
    }

    function resize() {
      const rect = stage.getBoundingClientRect();
      if (width === rect.width && height === rect.height) return;
      width = rect.width; height = rect.height;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); prepareDust(); fit();
    }

    function zoomAt(x, y, factor) {
      followingFit = false; flight = null;
      const next = clamp(zoom * factor, 1, bounds.maxZoom);
      cx += (x - width / 2) / scale * (1 / zoom - 1 / next);
      cy += (y - height / 2) / scale * (1 / zoom - 1 / next);
      setZoom(next); constrain(); requestDraw();
    }

    function select(n, viaTouch = false) {
      if (n === selected) return;
      selected = n;
      neighborhood = new Set([n]);
      if (n) {
        for (const e of links) {
          if (e.a === n) neighborhood.add(e.b);
          if (e.b === n) neighborhood.add(e.a);
        }
        const info = el("div", { class: "graph-tip-info", tabindex: mobile.matches ? "0" : null },
          el("small", {}, types[n.type].name, n.ref ? ` #${n.ref}` : "", n.severity ? ` · ${n.severity}` : ""),
          el("strong", {}, n.title || n.label),
          el("span", {}, n.type === "alert" ? [n.rule, ...n.techniques].join(" · ") : `${n.degree} visible connection${n.degree === 1 ? "" : "s"}`));
        if (n !== n.group.root) {
          const root = n.group.root;
          info.append(el("span", {}, `Cloud · ${types[root.type].name} #${root.ref}`));
        }
        tip.replaceChildren(info);
        // Phone layout is unchanged. Wider touch or coarse pointers get the same action, mice do not.
        if (mobile.matches || coarse.matches || viaTouch) {
          tip.append(chip("Investigate", () => detail(n), mobile.matches ? {} : { class: "graph-investigate" }));
        }
      }
      prepareLinks();
      tip.hidden = !n;
      canvas.classList.toggle("over-node", !!n);
      requestDraw();
    }

    function prepareLinks() {
      chains = signalChains(links, selected);
      const groups = new Map();
      for (const e of links) {
        const lit = selected && (e.a === selected || e.b === selected);
        const color = edgeColor[e.type];
        const id = e.type + color + !!lit;
        if (!groups.has(id)) groups.set(id, { color, type: e.type, lit, edges: [] });
        groups.get(id).edges.push(e);
      }
      batches = [...groups.values()].sort((a, b) => Number(!!a.lit) - Number(!!b.lit));
    }

    // Paint reusable node sprites at high resolution. Even a large graph only
    // needs one canvas draw per point, including the halo, glyph and bright core.
    const sprites = new Map();
    function sprite(n) {
      const id = n.group.seed + "/" + n.type + "/" + (n.severity || "");
      if (sprites.has(id)) return sprites.get(id);
      const tile = document.createElement("canvas");
      tile.width = tile.height = 96;
      const g = tile.getContext("2d"), core = severityColor[n.severity] || n.color;
      const halo = g.createRadialGradient(48, 48, 0, 48, 48, 48);
      halo.addColorStop(0, "#fff"); halo.addColorStop(.09, "#fff9ef");
      halo.addColorStop(.16, core + "ea");
      if (n.severity === "critical") halo.addColorStop(.22, "#ff6959a8");
      halo.addColorStop(.28, `hsl(${n.group.hue} 94% 72% / .49)`);
      halo.addColorStop(.48, `hsl(${n.group.hue} 98% 66% / .13)`);
      halo.addColorStop(.72, `hsl(${n.group.hue} 92% 63% / .035)`);
      halo.addColorStop(1, `hsl(${n.group.hue} 100% 60% / 0)`);
      g.fillStyle = halo; g.fillRect(0, 0, 96, 96);
      if (n.type === "incident") {
        // Narrow diffraction spikes distinguish the incident hubs inside the dust.
        g.save(); g.translate(48, 48); g.rotate(-.24); g.fillStyle = "#ffedd4a6";
        for (let i = 0; i < 4; i++) {
          g.beginPath(); g.moveTo(-1.6, 0); g.lineTo(0, i % 2 ? 23 : 31); g.lineTo(1.6, 0);
          g.fill(); g.rotate(Math.PI / 2);
        }
        g.restore();
      }
      g.fillStyle = "#fff7ed"; g.strokeStyle = n.type === "incident" ? types.incident.color : core;
      glyph(g, n.type, 48, 48, 7);
      if (n.type === "incident") {
        g.lineWidth = 2; g.stroke(); glyph(g, n.type, 48, 48, 3.7);
      }
      g.fill();
      sprites.set(id, tile); return tile;
    }

    function prepareDust() {
      const plan = particlePlan(width, height, activeGroups.map(group => group.shown.length));
      starCount = plan.stars;
      activeGroups.forEach((group, i) => {
        if (group.count !== plan.dust[i]) {
          group.count = plan.dust[i];
          group.tile = group.count ? nebulaTile(group, group.count) : null;
        }
      });
    }

    function starField(time) {
      const colors = ["", "#ddcfdc35", "#b3c6df59", "#e0eaff75"];
      for (let i = 1; i <= starCount; i++) {
        const layer = 1 + i % 3, size = .42 + layer * .27;
        const px = width * ((i * .75487767 + Math.sin(i * 11) * .17) % 1) - (cx * scale - time) * .06 * layer;
        const py = height * ((i * .56984029 + Math.cos(i * 7) * .21) % 1) - cy * scale * .06 * layer;
        ctx.fillStyle = colors[layer];
        ctx.fillRect((px % width + width) % width, (py % height + height) % height, size, size);
      }
    }

    function drawCloud(group, bloom) {
      if (!group.tile || !bloom) return;
      const members = group.shown, count = members.length;
      let x = 0, y = 0;
      for (const n of members) { x += n.px; y += n.py; }
      x /= count; y /= count;
      let xx = 0, xy = 0, yy = 0;
      for (const n of members) {
        const dx = n.px - x, dy = n.py - y;
        xx += dx * dx; xy += dx * dy; yy += dy * dy;
      }
      const angle = count > 1 ? .5 * Math.atan2(2 * xy, xx - yy) : group.seed * 2.4;
      const spread = Math.sqrt((xx + yy) / count);
      const unit = Math.min(1.4, scale) * zoom * bloom;
      const radius = Math.min(230 * unit, 62 * unit + 2.0 * spread);
      ctx.save(); ctx.translate(x, y); ctx.rotate(angle + group.breath * .015);
      ctx.scale(radius * (1 + .025 * group.breath), radius * (.74 - .025 * group.breath));
      ctx.globalAlpha = bloom * (selected && !members.some(n => neighborhood.has(n)) ? .19 : .94);
      ctx.drawImage(group.tile, -1, -1, 2, 2); ctx.restore();
    }

    function refreshBounds() {
      const absolute = scale * zoom;
      bounds = fitFrame(visible, width, height); scale = bounds.scale;
      if (followingFit) {
        cx = (bounds.left + bounds.right) / 2; cy = (bounds.top + bounds.bottom) / 2;
        setZoom(1);
      } else {
        setZoom(clamp(absolute / scale, 1, bounds.maxZoom)); constrain();
      }
    }

    function draw(time) {
      frame = 0;
      if (!width || !height || !onScreen || document.hidden) return;
      const dt = previous === null ? 0 : time - previous;
      previous = time; elapsed += dt;
      const reduced = Motion.reduced.matches;
      if (!warmed) {
        for (let i = 0; i < 80; i++) stepLayout(nodes, edges);
        warmed = true; stepsLeft = reduced ? 0 : 100;
        refreshBounds();
      }
      if (stepsLeft && !reduced) {
        stepClock += Math.min(dt, 50);
        if (stepClock >= 1000 / 60) {
          const steps = Math.min(stepsLeft, Math.floor(stepClock / (1000 / 60)));
          for (let i = 0; i < steps; i++) stepLayout(visible, links);
          stepClock %= 1000 / 60; stepsLeft -= steps;
          refreshBounds();
        }
      }
      if (flight) {
        const t = reduced ? 1 : clamp((elapsed - flight.start) / 460, 0, 1);
        const k = t * t * (3 - 2 * t);
        cx = flight.x + (flight.n.x - flight.x) * k; cy = flight.y + (flight.n.y - flight.y) * k;
        setZoom(clamp(flight.zoom + (flight.endZoom - flight.zoom) * k, 1, bounds.maxZoom));
        constrain(); if (t === 1) flight = null;
      }

      const motion = galaxyMotion(elapsed, reduced), bloom = motion.bloom;
      const density = clamp(Math.sqrt(width * height / Math.max(1, visible.length)) / 75, .52, 1);
      ctx.clearRect(0, 0, width, height); starField(motion.time);
      for (const group of activeGroups) {
        const phase = group.seed * 1.81 + motion.time * .27;
        group.breath = reduced ? 0 : Math.sin(phase);
        const dx = group.breath * 2.4, dy = reduced ? 0 : Math.cos(phase * .8) * 1.9;
        for (const n of group.shown) {
          const drift = !n.pinned && n !== selected && drag?.node !== n;
          n.px = width / 2 + ((n.x - cx) * scale * zoom + (drift ? dx : 0)) * bloom;
          n.py = height / 2 + ((n.y - cy) * scale * zoom + (drift ? dy : 0)) * bloom;
          n.r = ((n.type === "incident" ? 4.3 : 2.5) + Math.min(3.5, Math.sqrt(n.degree) * .76) +
            (SEVERITY_RANK[n.severity] || 0) * .46) * density * Math.min(1.6, Math.sqrt(zoom));
        }
        drawCloud(group, bloom);
      }
      for (const batch of batches) {
        const { color, type, lit } = batch;
        ctx.beginPath();
        for (const { a, b } of batch.edges) {
          ctx.moveTo(a.px, a.py);
          if (type === "correlation") ctx.quadraticCurveTo((a.px + b.px) / 2 - (b.py - a.py) * .13,
            (a.py + b.py) / 2 + (b.px - a.px) * .13, b.px, b.py);
          else ctx.lineTo(b.px, b.py);
        }
        ctx.strokeStyle = color;
        if (lit) { ctx.lineWidth = 4; ctx.globalAlpha = .09 * bloom; ctx.stroke(); }
        ctx.lineWidth = lit ? 1.25 : (type === "membership" ? .9 : .74);
        ctx.globalAlpha = bloom * (selected ? (lit ? .92 : .065) : (type === "evidence" ? .31 : .49));
        ctx.stroke();
      }
      if (motion.animate && bloom > .9) drawSignals();
      ctx.globalCompositeOperation = "lighter";
      for (const n of visible) {
        const { px: x, py: y, r } = n;
        const pulse = n.severity === "critical" && motion.animate ? 1 + .09 * Math.sin(motion.time * 2.0 + n.id) : 1;
        const halo = r * (neighborhood.has(n) ? 5.4 : 4.3) * pulse;
        if (x < -halo || x > width + halo || y < -halo || y > height + halo) continue;
        ctx.globalAlpha = bloom * (selected && !neighborhood.has(n) ? .21 : 1);
        ctx.drawImage(sprite(n), x - halo, y - halo, halo * 2, halo * 2);
        if (n === selected || n.pinned) {
          ctx.strokeStyle = n === selected ? "#ffffffc0" : n.color; ctx.lineWidth = 1;
          ctx.beginPath(); ctx.arc(x, y, r + 4, 0, tau); ctx.stroke();
        }
      }
      ctx.globalCompositeOperation = "source-over"; ctx.globalAlpha = 1;
      if (bloom > .93) drawLabels();
      if (selected) {
        const x = selected.px, y = selected.py, w = tip.offsetWidth, h = tip.offsetHeight;
        let left = Math.max(5, Math.min(width - w - 5, x + 18));
        let top = clamp(y + h + 12 < height ? y + 12 : y - h - 12, 5, height - h - 5);
        // The phone popover keeps its old anchor. The wider touch action is taller, so keep it off the node.
        if (tip.querySelector(".graph-investigate")) {
          const pad = selected.r + 8;
          const hits = (l, t) => l < x + pad && l + w > x - pad && t < y + pad && t + h > y - pad;
          if (hits(left, top)) {
            const below = y + pad, above = y - pad - h;
            if (below + h <= height - 5) top = below;
            else if (above >= 5) top = above;
          }
        }
        tip.style.left = left + "px";
        tip.style.top = top + "px";
      }
      if (visible.length && motion.animate) requestDraw();
    }

    function drawSignals() {
      for (const [i, path] of chains.entries()) {
        const phase = ((elapsed / 4800 + i / 3) % 1) * (path.length - 1);
        const leg = Math.floor(phase), t = phase - leg;
        const a = path[leg], b = path[leg + 1];
        const dx = b.px - a.px, dy = b.py - a.py;
        const x = a.px + dx * t, y = a.py + dy * t;
        const tail = Math.max(0, t - 8 / Math.max(1, Math.hypot(dx, dy)));
        ctx.strokeStyle = a.color; ctx.lineWidth = 2; ctx.globalAlpha = .8;
        ctx.beginPath(); ctx.moveTo(a.px + dx * tail, a.py + dy * tail); ctx.lineTo(x, y); ctx.stroke();
        ctx.fillStyle = "#fff"; ctx.globalAlpha = 1;
        ctx.beginPath(); ctx.arc(x, y, 1.7, 0, tau); ctx.fill();
      }
    }

    let labelOrder = [];
    function drawLabels() {
      const areas = [], budget = width < 450 ? 2 : width < 1100 ? 4 : 6;
      ctx.font = '500 11px ui-monospace, Menlo, monospace'; ctx.textAlign = "center";
      const order = selected ? [selected, ...labelOrder.filter(n => n !== selected && neighborhood.has(n))] : labelOrder;
      for (const n of order) {
        if (areas.length >= budget) break;
        if (n !== selected && n.type !== "incident" && n.degree < 3) continue;
        const text = n.caption.length > 22 ? n.caption.slice(0, 21) + "…" : n.caption;
        const w = ctx.measureText(text).width + 8;
        const x = clamp(n.px, w / 2 + 3, width - w / 2 - 3);
        if (Math.abs(n.px - x) > w / 2) continue;
        for (const y of [n.py - n.r - 7, n.py + n.r + 16]) {
          if (y < 12 || y > height - 3) continue;
          if (areas.some(a => Math.abs(x - a.x) < (a.w + w) / 2 && Math.abs(y - a.y) < 16)) continue;
          if (n !== selected && visible.some(m => m !== n && Math.abs(y - 4 - m.py) < m.r + 4 && Math.abs(x - m.px) < w / 2 + m.r)) continue;
          areas.push({ x, y, w });
          ctx.lineWidth = 3.5; ctx.lineJoin = "round"; ctx.strokeStyle = "#0a090c"; ctx.strokeText(text, x, y);
          ctx.fillStyle = n === selected ? "#fff" : "#e3dfe8"; ctx.fillText(text, x, y);
          break;
        }
      }
      ctx.globalAlpha = 1;
    }

    function requestDraw() {
      if (!frame && onScreen && !document.hidden) frame = requestAnimationFrame(draw);
    }
    function hit(p) {
      let closest = null, dist = Infinity;
      for (const n of visible) {
        const d = Math.hypot(n.px - p.x, n.py - p.y);
        if (d < dist && d <= Math.max(n.r + 4, mobile.matches ? 15 : 10)) { closest = n; dist = d; }
      }
      return closest;
    }
    function point(ev) {
      const r = canvas.getBoundingClientRect();
      return { x: ev.clientX - r.left, y: ev.clientY - r.top };
    }
    function detail(n) {
      if (n.type === "alert" || n.type === "incident") go(n.type + "s", n.ref);
      else go("entity", n.type + "/" + encodeURIComponent(n.label));
    }
    function pinch() {
      const [a, b] = pointers.values();
      return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2, distance: Math.max(1, Math.hypot(a.x - b.x, a.y - b.y)) };
    }
    canvas.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      canvas.classList.add("pointer-focus");
      flight = null; clearTimeout(clickTimer);
      canvas.setPointerCapture(ev.pointerId);
      const p = point(ev); pointers.set(ev.pointerId, p);
      clearTimeout(holdTimer);
      if (pointers.size === 1) {
        drag = { start: p, node: hit(p), moved: false };
        if (ev.pointerType === "touch" && drag.node) holdTimer = setTimeout(() => {
          drag.inspected = true; select(drag.node, true);
        }, 420);
      }
      if (pointers.size === 2) { lastTap = null; drag = { pinch: pinch(), moved: true }; }
      locked = null; select(null);
    });
    canvas.addEventListener("pointermove", (ev) => {
      const p = point(ev), prev = pointers.get(ev.pointerId);
      if (!prev) { if (ev.pointerType !== "touch") select(hit(p) || locked); return; }
      pointers.set(ev.pointerId, p);
      if (pointers.size === 2) {
        const next = pinch(), old = drag.pinch;
        if (old) {
          pan(next.x - old.x, next.y - old.y);
          zoomAt(next.x, next.y, next.distance / old.distance);
        }
        drag.pinch = next; return;
      }
      if (pointers.size !== 1) return;
      if (!drag.moved && Math.hypot(p.x - drag.start.x, p.y - drag.start.y) < 4) return;
      clearTimeout(holdTimer); select(null);
      const from = drag.moved ? prev : drag.start;
      drag.moved = true;
      if (drag.node) {
        const x = clamp(p.x, 0, width), y = clamp(p.y, 0, height);
        drag.node.pinned = true; followingFit = false; stepsLeft = 130;
        drag.node.x = cx + (x - width / 2) / (scale * zoom);
        drag.node.y = cy + (y - height / 2) / (scale * zoom);
        requestDraw();
      } else pan(p.x - from.x, p.y - from.y);
    });
    function release(ev) {
      if (!pointers.delete(ev.pointerId)) return;
      clearTimeout(holdTimer);
      if (drag.node && drag.moved) {
        refreshBounds();
      }
      const tap = ev.type === "pointerup" && !drag.moved && !drag.inspected;
      const n = drag.node;
      drag = pointers.size ? { moved: true, pinch: pointers.size === 2 ? pinch() : null } : null;
      if (tap && ev.pointerType === "touch") {
        const p = point(ev);
        if (lastTap && n === lastTap.n && ev.timeStamp - lastTap.time < 400 &&
            Math.hypot(p.x - lastTap.x, p.y - lastTap.y) < 16) resetNode(n);
        else { lastTap = { ...p, n, time: ev.timeStamp }; locked = n; select(n, true); }
      } else if (tap && n) {
        select(n); clickTimer = setTimeout(() => detail(n), 400);
      } else { lastTap = null; requestDraw(); }
    }
    function resetNode(n) {
      clearTimeout(clickTimer); lastTap = null;
      if (n?.pinned) { n.pinned = false; stepsLeft = 130; }
      locked = null; select(null); fit();
    }
    canvas.addEventListener("pointerup", release); canvas.addEventListener("pointercancel", release);
    canvas.addEventListener("lostpointercapture", release);
    canvas.addEventListener("dblclick", ev => resetNode(hit(point(ev))));
    canvas.addEventListener("pointerleave", () => { if (!drag && !mobile.matches) select(locked); });
    canvas.addEventListener("wheel", (ev) => {
      ev.preventDefault(); locked = null; select(null);
      const p = point(ev); zoomAt(p.x, p.y, Math.exp(-clamp(ev.deltaY, -200, 200) * 0.0025));
    }, { passive: false });
    canvas.addEventListener("keydown", (ev) => {
      canvas.classList.remove("pointer-focus");
      if (!visible.length) return;
      if (ev.key === "Enter" && selected) detail(selected);
      else if (ev.key === "Escape") { locked = null; select(null); }
      else if (ev.key === " " && selected) { selected.pinned = !selected.pinned; stepsLeft = 130; requestDraw(); }
      else if (["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp"].includes(ev.key)) {
        if (ev.shiftKey) {
          pan(({ ArrowRight: -60, ArrowLeft: 60 })[ev.key] || 0, ({ ArrowDown: -60, ArrowUp: 60 })[ev.key] || 0);
          ev.preventDefault(); return;
        }
        const forward = ["ArrowRight", "ArrowDown"].includes(ev.key), i = visible.indexOf(selected);
        const next = visible[i < 0 ? 0 : (i + (forward ? 1 : -1) + visible.length) % visible.length];
        if (next.px < 20 || next.px > width - 20 || next.py < 20 || next.py > height - 20) fit();
        locked = next; select(next);
      } else return;
      ev.preventDefault();
    });
    canvas.addEventListener("blur", ev => {
      canvas.classList.remove("pointer-focus");
      if (!tip.contains(ev.relatedTarget)) { locked = null; select(null); }
    });
    mobile.addEventListener("change", () => { key.open = !mobile.matches; }, { signal });
    function wake() {
      previous = null;
      cancelAnimationFrame(frame); frame = 0; requestDraw();
    }
    Motion.reduced.addEventListener("change", wake, { signal });
    document.addEventListener("visibilitychange", wake, { signal });
    const intersection = new IntersectionObserver(([entry]) => { onScreen = entry.isIntersecting; wake(); });
    intersection.observe(stage);
    observer = new ResizeObserver(resize); observer.observe(stage);
    dispose = () => {
      onScreen = false; controller.abort(); observer.disconnect(); intersection.disconnect();
      clearTimeout(holdTimer); clearTimeout(clickTimer); cancelAnimationFrame(frame);
    };
    const rect = stage.getBoundingClientRect();
    seedLayout(nodes, edges, clamp(rect.width / (rect.height || 1), .65, 2.5));
    update(); resize();
  }

  return { open, unmount() { if (dispose) dispose(); dispose = null; } };
})();

export const { open, unmount } = Graph;
