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
  const severityColor = { critical: "#ff718f", high: "#ffac61", medium: "#f5db78", low: "#93b9ff", info: "#afc1d5" };
  const edgeColor = { membership: "#b599ff", correlation: "#ffc47e" };
  const tau = Math.PI * 2;
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const cap = (s) => s[0].toUpperCase() + s.slice(1);
  let dispose = null;

  function graphLayout(nodes, edges) {
    // Springs along real links. Repulsion uses nearby grid cells, keeping each step local.
    const spacing = 120;
    const cols = Math.ceil(Math.sqrt(nodes.length) * 3) + 1000;
    for (let i = 0; i < nodes.length; i++) {
      const angle = i * 2.39996323, radius = Math.sqrt(i) * 47;
      Object.assign(nodes[i], { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius, vx: 0, vy: 0 });
    }
    for (let step = 0; step < 110; step++) {
      const grid = new Map();
      for (const n of nodes) {
        const gx = Math.floor(n.x / spacing), gy = Math.floor(n.y / spacing);
        for (let i = gx - 1; i <= gx + 1; i++) {
          for (let j = gy - 1; j <= gy + 1; j++) {
            const near = grid.get(i + j * cols);
            if (!near) continue;
            for (const m of near) {
              const dx = m.x - n.x, dy = m.y - n.y, d2 = Math.max(9, dx * dx + dy * dy);
              if (d2 > spacing * spacing) continue;
              const f = (spacing / Math.sqrt(d2) - 1) * 0.095;
              n.vx -= dx * f; n.vy -= dy * f;
              m.vx += dx * f; m.vy += dy * f;
            }
          }
        }
        const key = gx + gy * cols;
        if (!grid.has(key)) grid.set(key, []);
        grid.get(key).push(n);
      }
      for (const { a, b } of edges) {
        const dx = b.x - a.x, dy = b.y - a.y;
        const f = (1 - 66 / Math.max(1, Math.hypot(dx, dy))) * 0.022;
        a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
      }
      for (const n of nodes) {
        n.vx = (n.vx - n.x * 0.0013) * 0.63; n.vy = (n.vy - n.y * 0.0013) * 0.63;
        n.x += n.vx; n.y += n.vy;
      }
    }
  }

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
    graphLayout(nodes, edges);
    const shownTypes = new Set(Object.keys(types));
    let severity = "all", visible = [], links = [], selected = null, neighborhood = new Set();
    let width = 0, height = 0, zoom = 1, scale = 1, bounds, cx = 0, cy = 0;
    let frame = 0, observer, drag = null, holdTimer = 0, clickTimer = 0;
    const pointers = new Map(), controller = new AbortController(), signal = controller.signal;
    const mobile = matchMedia("(max-width: 760px)");
    const canvas = el("canvas", { class: "graph-canvas", tabindex: "0", role: "group",
      "aria-description": "Shift and arrow keys pan. Double-click to fit.",
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
      chip("Fit", fit, { class: "graph-fit", "aria-label": "Fit graph to screen" }));
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
    const key = el("details", { class: "graph-key", open: !mobile.matches },
      el("summary", {}, "Filters & legend", filterState),
      el("div", { class: "graph-key-body" },
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
      select(null); fit();
    }

    function fit() {
      bounds = fitFrame(visible, width, height); scale = bounds.scale;
      cx = (bounds.left + bounds.right) / 2; cy = (bounds.top + bounds.bottom) / 2;
      zoom = 1; zoomText.textContent = "100%"; requestDraw();
    }

    function constrain() {
      const center = limitCenter(bounds, visible, width, height, zoom, cx, cy);
      cx = center.x; cy = center.y;
    }

    function pan(dx, dy) {
      cx -= dx / (scale * zoom); cy -= dy / (scale * zoom);
      constrain(); requestDraw();
    }

    function resize() {
      const rect = stage.getBoundingClientRect();
      if (width === rect.width && height === rect.height) return;
      width = rect.width; height = rect.height;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); fit();
    }

    function zoomAt(x, y, factor) {
      const next = clamp(zoom * factor, 1, bounds.maxZoom);
      cx += (x - width / 2) / scale * (1 / zoom - 1 / next);
      cy += (y - height / 2) / scale * (1 / zoom - 1 / next);
      zoom = next; constrain(); zoomText.textContent = `${Math.round(zoom * 100)}%`; requestDraw();
    }

    function select(n) {
      if (n === selected) return;
      selected = n;
      neighborhood = new Set([n]);
      if (n) {
        for (const e of links) {
          if (e.a === n) neighborhood.add(e.b);
          if (e.b === n) neighborhood.add(e.a);
        }
        tip.replaceChildren(el("small", {}, types[n.type].name, n.ref ? ` #${n.ref}` : "", n.severity ? ` · ${n.severity}` : ""),
          el("strong", {}, n.title || n.label),
          el("span", {}, n.type === "alert" ? [n.rule, ...n.techniques].join(" · ") : `${n.degree} visible connection${n.degree === 1 ? "" : "s"}`));
      }
      tip.hidden = !n;
      canvas.classList.toggle("over-node", !!n);
      requestDraw();
    }

    // Reuse tiny radial sprites. Canvas shadowBlur per edge/node is expensive at the node cap.
    const glows = new Map();
    function glow(color) {
      if (!glows.has(color)) {
        const tile = document.createElement("canvas"); tile.width = tile.height = 96;
        const g = tile.getContext("2d"), grad = g.createRadialGradient(48, 48, 0, 48, 48, 48);
        grad.addColorStop(0, color + "78"); grad.addColorStop(0.35, color + "32"); grad.addColorStop(1, color + "00");
        g.fillStyle = grad; g.fillRect(0, 0, 96, 96); glows.set(color, tile);
      }
      return glows.get(color);
    }

    function draw(time) {
      frame = 0;
      if (!width || !height || document.hidden) return;
      ctx.clearRect(0, 0, width, height);
      const moving = !Motion.reduced.matches && !drag && !selected;
      const density = clamp(Math.sqrt(width * height / Math.max(1, visible.length)) / 74, 0.58, 1);
      for (const n of visible) {
        const phase = time * 0.00038 + n.id * 1.81;
        n.px = width / 2 + (n.x - cx) * scale * zoom + (moving ? 1.45 * Math.sin(phase) : 0);
        n.py = height / 2 + (n.y - cy) * scale * zoom + (moving ? 1.45 * Math.cos(phase) : 0);
        n.r = ((n.type === "incident" ? 8 : 4) + Math.min(6, Math.sqrt(n.degree)) +
          (SEVERITY_RANK[n.severity] || 0) * 0.65) * density * clamp(Math.sqrt(zoom), 0.7, 1.55);
      }
      for (const e of links) {
        const { a, b } = e, focus = selected && (a === selected || b === selected);
        const color = edgeColor[e.type] || b.color;
        ctx.globalAlpha = selected ? (focus ? 0.95 : 0.065) : (e.type === "evidence" ? 0.38 : 0.65);
        ctx.strokeStyle = color; ctx.lineWidth = focus ? 1.9 : (e.type === "evidence" ? 0.95 : 1.35);
        // A shallow arc separates direct correlation from the incident membership spokes.
        const bend = e.type === "correlation" ? 0.13 : 0;
        const mx = (a.px + b.px) / 2 - (b.py - a.py) * bend;
        const my = (a.py + b.py) / 2 + (b.px - a.px) * bend;
        ctx.beginPath(); ctx.moveTo(a.px, a.py);
        if (bend) ctx.quadraticCurveTo(mx, my, b.px, b.py); else ctx.lineTo(b.px, b.py);
        if (bend || focus) {
          const opacity = ctx.globalAlpha, weight = ctx.lineWidth;
          ctx.globalAlpha *= 0.13; ctx.lineWidth += 4; ctx.stroke();
          ctx.globalAlpha = opacity; ctx.lineWidth = weight;
        }
        ctx.stroke();
        if (e.type === "correlation" && !Motion.reduced.matches && (!selected || focus)) {
          const t = (time * 0.00023 + a.id * 0.23) % 1, u = 1 - t;
          const x = u * u * a.px + 2 * u * t * mx + t * t * b.px;
          const y = u * u * a.py + 2 * u * t * my + t * t * b.py;
          ctx.drawImage(glow(color), x - 7, y - 7, 14, 14);
          ctx.fillStyle = "#fff1bd"; ctx.beginPath(); ctx.arc(x, y, 1.6, 0, tau); ctx.fill();
        }
      }
      for (const n of visible) {
        const { px: x, py: y, r, color } = n;
        if (x < -30 || x > width + 30 || y < -30 || y > height + 30) continue;
        ctx.globalAlpha = selected && !neighborhood.has(n) ? 0.22 : 1;
        const halo = r * (n.type === "incident" ? 4.7 : 3.8);
        ctx.drawImage(glow(color), x - halo, y - halo, halo * 2, halo * 2);
        ctx.strokeStyle = color; ctx.lineWidth = n.type === "incident" ? 2.5 : 1.3;
        glyph(ctx, n.type, x, y, r); ctx.fillStyle = "#101620"; ctx.fill(); ctx.stroke();
        ctx.fillStyle = n.type === "incident" ? severityColor[n.severity] : color;
        glyph(ctx, n.type, x, y, r * (n.type === "incident" ? 0.42 : 0.57)); ctx.fill();
        if (selected === n || n.type === "incident") {
          ctx.strokeStyle = selected === n ? "#f4f7ff" : color + "70"; ctx.lineWidth = 1;
          ctx.beginPath(); ctx.arc(x, y, r + 4, 0, tau); ctx.stroke();
        }
      }
      ctx.globalAlpha = 1; drawLabels();
      if (selected) {
        const x = selected.px, y = selected.py, w = tip.offsetWidth, h = tip.offsetHeight;
        tip.style.left = Math.max(5, Math.min(width - w - 5, x + 18)) + "px";
        tip.style.top = clamp(y + h + 12 < height ? y + 12 : y - h - 12, 5, height - h - 5) + "px";
      }
      if (!Motion.reduced.matches && visible.length && !drag && (!selected || links.some((e) => e.type === "correlation" && (e.a === selected || e.b === selected)))) requestDraw();
    }

    let labelOrder = [];
    function drawLabels() {
      const areas = [], budget = Math.min(36, Math.max(6, Math.floor(width * height / 11500 * zoom)));
      ctx.font = '500 11px ui-monospace, Menlo, monospace'; ctx.textAlign = "center";
      const order = selected ? [selected, ...labelOrder.filter((n) => n !== selected && neighborhood.has(n))] : labelOrder;
      for (const n of order) {
        if (areas.length >= budget) break;
        const text = n.caption.length > 22 ? n.caption.slice(0, 21) + "…" : n.caption;
        const w = text.length * 6.7 + 9, x = clamp(n.px, w / 2 + 2, width - w / 2 - 2), y = n.py + n.r + 16;
        if (Math.abs(n.px - x) > w / 2 || y < 12 || y > height - 3) continue;
        if (areas.some((a) => Math.abs(x - a.x) < (a.w + w) / 2 && Math.abs(y - a.y) < 15)) continue;
        if (visible.some((m) => m !== n && Math.abs(y - 4 - m.py) < m.r + 5 && Math.abs(x - m.px) < w / 2 + m.r)) continue;
        areas.push({ x, y, w });
        ctx.lineWidth = 3.5; ctx.strokeStyle = "#101521"; ctx.strokeText(text, x, y);
        ctx.fillStyle = n.type === "incident" ? "#dbcaff" : "#d1dbea"; ctx.fillText(text, x, y);
      }
    }

    function requestDraw() {
      if (!frame && !document.hidden) frame = requestAnimationFrame(draw);
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
      canvas.setPointerCapture(ev.pointerId);
      const p = point(ev); pointers.set(ev.pointerId, p);
      clearTimeout(holdTimer);
      if (pointers.size === 1) {
        drag = { start: p, node: hit(p), moved: false };
        if (ev.pointerType === "touch" && drag.node) holdTimer = setTimeout(() => {
          drag.inspected = true; select(drag.node);
        }, 420);
      }
      if (pointers.size === 2) drag = { pinch: pinch(), moved: true };
      select(null);
    });
    canvas.addEventListener("pointermove", (ev) => {
      const p = point(ev), prev = pointers.get(ev.pointerId);
      if (!prev) { if (ev.pointerType !== "touch") select(hit(p)); return; }
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
        drag.node.x = cx + (x - width / 2) / (scale * zoom);
        drag.node.y = cy + (y - height / 2) / (scale * zoom);
        requestDraw();
      } else pan(p.x - from.x, p.y - from.y);
    });
    function release(ev) {
      if (!pointers.delete(ev.pointerId)) return;
      clearTimeout(holdTimer);
      if (drag.node && drag.moved) {
        const absoluteScale = scale * zoom;
        bounds = fitFrame(visible, width, height); scale = bounds.scale;
        zoom = clamp(absoluteScale / scale, 1, bounds.maxZoom);
        zoomText.textContent = `${Math.round(zoom * 100)}%`; constrain();
      }
      const clicked = ev.type === "pointerup" && !drag.moved && !drag.inspected && drag.node;
      drag = pointers.size ? { moved: true, pinch: pointers.size === 2 ? pinch() : null } : null;
      if (clicked) {
        clearTimeout(clickTimer);
        clickTimer = setTimeout(() => detail(clicked), 320);
      } else requestDraw();
    }
    canvas.addEventListener("pointerup", release); canvas.addEventListener("pointercancel", release);
    canvas.addEventListener("lostpointercapture", release);
    canvas.addEventListener("dblclick", () => { clearTimeout(clickTimer); select(null); fit(); });
    canvas.addEventListener("pointerleave", () => { if (!drag && !mobile.matches) select(null); });
    canvas.addEventListener("wheel", (ev) => {
      ev.preventDefault(); select(null);
      const p = point(ev); zoomAt(p.x, p.y, Math.exp(-clamp(ev.deltaY, -200, 200) * 0.0025));
    }, { passive: false });
    canvas.addEventListener("keydown", (ev) => {
      canvas.classList.remove("pointer-focus");
      if (!visible.length) return;
      if (ev.key === "Enter" && selected) detail(selected);
      else if (ev.key === "Escape") select(null);
      else if (["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp"].includes(ev.key)) {
        if (ev.shiftKey) {
          pan(({ ArrowRight: -60, ArrowLeft: 60 })[ev.key] || 0, ({ ArrowDown: -60, ArrowUp: 60 })[ev.key] || 0);
          ev.preventDefault(); return;
        }
        const forward = ["ArrowRight", "ArrowDown"].includes(ev.key), i = visible.indexOf(selected);
        const next = visible[i < 0 ? 0 : (i + (forward ? 1 : -1) + visible.length) % visible.length];
        if (next.px < 20 || next.px > width - 20 || next.py < 20 || next.py > height - 20) fit();
        select(next);
      } else return;
      ev.preventDefault();
    });
    canvas.addEventListener("blur", () => { canvas.classList.remove("pointer-focus"); select(null); });
    mobile.addEventListener("change", () => { key.open = !mobile.matches; }, { signal });
    Motion.reduced.addEventListener("change", requestDraw, { signal });
    document.addEventListener("visibilitychange", requestDraw, { signal });
    observer = new ResizeObserver(resize); observer.observe(stage);
    dispose = () => { controller.abort(); observer.disconnect(); clearTimeout(holdTimer); clearTimeout(clickTimer); cancelAnimationFrame(frame); };
    update(); resize();
  }

  return { open, unmount() { if (dispose) dispose(); dispose = null; } };
})();

export const { open, unmount } = Graph;
