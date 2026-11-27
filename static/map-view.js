"use strict";

// Each dashboard mount owns one controller. Only an intersecting card in globe
// mode imports the renderer and imagery.
class AttackMapView {
  constructor() {
    this.motion = matchMedia("(prefers-reduced-motion: reduce)");
    this.wantGlobe = true;
    this.active = false;
    this.rows = [];
    this.selected = null;
    this.running = !this.motion.matches;
    this.life = new AbortController();
    const on = (node, type, fn) => node.addEventListener(type, fn, { signal: this.life.signal });
    const modeButton = (id, text) => el("button", { id, type: "button", "aria-pressed": "false" }, text);
    this.flatButton = modeButton("map-flat", "2D");
    this.globeButton = modeButton("map-globe", "3D");
    this.motionButton = el("button", { class: "orbit-motion", type: "button", hidden: true });
    const cameraButton = (label, text, action) => {
      const button = el("button", { type: "button", title: label, "aria-label": label }, text);
      on(button, "click", action);
      return button;
    };
    // Overhead is the tactical "god's-eye" camera: straight down on HQ with range rings.
    this.overheadButton = cameraButton("Overhead view of HQ with range rings", "Overhead", () => this.overhead());
    this.overheadButton.classList.add("orbit-overhead");
    this.overheadButton.setAttribute("aria-pressed", "false");
    this.zoomControls = el("div", { class: "orbit-zoom", role: "group", "aria-label": "Globe camera", hidden: true },
      cameraButton("Zoom out", "−", () => this.orbit?.zoomBy(1 / 1.3)),
      cameraButton("Zoom in", "+", () => this.orbit?.zoomBy(1.3)),
      cameraButton("Fit globe", "Fit", () => this.orbit?.fit()),
      this.overheadButton);
    this.stage = el("div", { class: "orbit-stage" },
      el("div", { class: "mapwrap", id: "map" }),
      el("span", { class: "orbit-bearing", "aria-hidden": "true" }));
    const cameraTools = el("div", { class: "orbit-tools" }, this.zoomControls,
      el("span", { class: "orbit-hint" }, "Tap to steer", el("br"), " Pinch to zoom"), this.motionButton);
    this.list = el("div", { class: "orbit-list" });
    this.detail = el("div", { class: "orbit-detail", "aria-live": "polite" });
    this.side = el("aside", { id: "map-side", "aria-label": "Attack routes" },
      el("div", { class: "orbit-list-head" }, el("h3", {}, "Busiest arcs"), el("span", {}, "Events")), this.list, this.detail);
    this.legend = el("details", { class: "orbit-key" },
      el("summary", {}, "Map key"), el("div", { class: "orbit-swatches" },
        ...["critical", "high", "medium", "low", "HQ target"].map(s =>
          el("span", {}, el("i", { class: s === "HQ target" ? "orbit-hq" : `dot sev-${s}` }), s))));
    const narrow = matchMedia("(max-width: 760px)");
    this.legend.open = !narrow.matches;
    on(narrow, "change", () => { this.legend.open = !narrow.matches; });
    const metric = (label, id) => el("div", {}, el("dt", {}, label), el("dd", { id }, "—"));
    this.card = panel("p-map", "Attack map", [
      el("div", { class: "orbit-modes", role: "group", "aria-label": "Map projection" }, this.globeButton, this.flatButton)],
      el("div", { class: "orbit-main" }, el("div", { class: "orbit-view" }, this.stage, cameraTools), this.side),
      el("dl", { class: "orbit-metrics" }, metric("Mapped arcs", "map-count"), metric("Events/min", "map-rate"),
        metric("Last event", "map-last"), metric("UTC clock", "map-clock")),
      el("div", { class: "orbit-foot" }, this.legend, el("span", { id: "map-unknown" })));
    on(this.flatButton, "click", () => this.mode(false));
    on(this.globeButton, "click", () => this.mode(true));
    on(this.motionButton, "click", () => {
      this.running = !this.running;
      if (this.running) this.select(null);
      this.refreshMode();
    });
    on(this.motion, "change", () => {
      this.running = !this.motion.matches;
      this.mode(!this.motion.matches);
    });
    on(this.stage, "click", e => {
      const city = e.target.closest(".mk")?.dataset.city;
      if (city) this.select(city);
    });
    on(this.list, "click", e => this.select(e.target.closest("button")?.dataset.city));
    on(this.list, "pointerover", e => {
      if (e.pointerType !== "mouse") return;
      const city = e.target.closest("button")?.dataset.city;
      clearTimeout(this.hover);
      if (city) this.hover = setTimeout(() => this.select(city), 350);
    });
    on(this.list, "pointerleave", () => clearTimeout(this.hover));
    on(document, "visibilitychange", () => this.refreshMode());
    this.observer = new IntersectionObserver(([entry]) => {
      this.near = entry.isIntersecting;
      this.refreshMode();
    }, { rootMargin: "120px" });
    this.observer.observe(this.card);
    this.refreshMode();
  }

  mode(globe) {
    this.wantGlobe = globe;
    this.refreshMode();
  }

  async load() {
    this.loading = true;
    const signal = this.life.signal;
    let gl, handedOff = false;
    try {
      const surface = document.createElement("canvas");
      gl = surface.getContext("webgl2", { alpha: true, antialias: true, powerPreference: "low-power" });
      if (!gl) throw Error("WebGL 2 unavailable");
      const { createOrbit } = await import("./orbit.js");
      if (signal.aborted || !this.wantGlobe || !this.near) return;
      handedOff = true;
      this.orbit = await createOrbit(this.stage, gl, {
        select: city => this.select(city),
        drag: () => { this.running = false; this.select(null); this.refreshMode(); },
        lost: () => this.fallback(),
        overheadChanged: on => this.overheadButton.setAttribute("aria-pressed", String(on)),
        signal,
      });
      if (signal.aborted) { this.orbit.dispose(); return; }
      this.orbit.data(this.rows, this.hq);
      if (this.selected) { this.orbit.fly(this.selected); this.orbit.highlight(this.selected.city); }
    } catch {
      if (!signal.aborted) this.fallback();
    } finally {
      if (!handedOff) gl?.getExtension("WEBGL_lose_context")?.loseContext();
      this.loading = false;
      if (!signal.aborted) this.refreshMode();
    }
  }

  overhead() {
    const on = this.overheadButton.getAttribute("aria-pressed") !== "true";
    if (on) { this.running = false; this.select(null); }
    this.orbit?.overhead(on);
    this.refreshMode();
  }

  fallback() {
    this.failed = true;
    this.orbit?.dispose();
    this.orbit = null;
    this.refreshMode();
  }

  refreshMode() {
    const allowed = !this.failed;
    this.active = !!(this.orbit && this.wantGlobe && allowed);
    const flat = !this.wantGlobe || !allowed;
    this.card.dataset.mode = flat ? "2d" : (this.active ? "3d" : "loading");
    this.flatButton.setAttribute("aria-pressed", String(flat));
    this.globeButton.setAttribute("aria-pressed", String(!flat));
    this.globeButton.disabled = !allowed;
    this.globeButton.title = this.failed ? "3D view unavailable on this device" : "Orbital globe";
    this.motionButton.hidden = !this.active || this.motion.matches;
    this.zoomControls.hidden = !this.active;
    this.motionButton.textContent = this.running ? "Pause orbit" : "Resume orbit";
    this.motionButton.title = this.motionButton.textContent;
    this.motionButton.dataset.running = String(this.running);
    this.stage.querySelector(".orbit-bearing").hidden = !this.active;
    this.orbit?.state(this.active && this.near && !document.hidden, this.running, this.motion.matches);
    if (allowed && this.wantGlobe && this.near && !document.hidden && !this.orbit && !this.loading) this.load();
  }

  select(city) {
    this.selected = this.rows.find(r => r.city === city) || null;
    if (this.selected) {
      this.running = false;
      this.orbit?.fly(this.selected);
    }
    this.orbit?.highlight(this.selected?.city);
    this.paintDetail();
    this.refreshMode();
  }

  update(rows, hq, unknown) {
    this.rows = rows;
    this.hq = hq;
    this.selected = rows.find(r => r.city === this.selected?.city) || null;
    this.orbit?.data(rows, hq);
    this.orbit?.highlight(this.selected?.city);
    // Reconcile by city so a data refresh never replaces a focused source.
    const old = new Map([...this.list.querySelectorAll("button")].map(b => [b.dataset.city, b]));
    rows.forEach((r, i) => {
      let button = old.get(r.city);
      if (!button) {
        button = el("button", { class: "ms-row", type: "button", "data-city": r.city },
          el("i", { class: `dot sev-${r.sev}` }), el("span", { class: "ms-city" }, r.city), el("b", { class: "ms-n" }));
      }
      old.delete(r.city);
      button.firstChild.className = `dot sev-${r.sev}`;
      button.lastChild.textContent = fmtN(r.events);
      button.setAttribute("aria-label", `${r.city} to ${hq.city}, ${r.events} events, ${r.ips} source IPs, ${r.sev} severity`);
      if (this.list.children[i] !== button) this.list.insertBefore(button, this.list.children[i] || null);
    });
    old.forEach(b => b.remove());
    this.list.querySelector(".orbit-empty")?.remove();
    if (!rows.length) this.list.append(el("p", { class: "orbit-empty" }, hq ? "No mapped sources" : "Locating sources…"));
    this.card.querySelector("#map-count").textContent = hq ? String(rows.length) : "—";
    this.card.querySelector("#map-unknown").textContent = `${unknown} no geo entry`;
    this.paintDetail();
  }

  paintDetail() {
    const r = this.selected;
    this.list.querySelectorAll("button").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.city === r?.city)));
    this.stage.querySelectorAll(".mk").forEach(g => g.classList.toggle("is-selected", g.dataset.city === r?.city));
    if (!this.hq) { this.detail.textContent = "Awaiting HQ location"; this.detailKey = null; return; }
    const signature = JSON.stringify([r, this.hq.city]);
    if (signature === this.detailKey) return;
    this.detailKey = signature;
    this.detail.replaceChildren(el("span", { class: "orbit-caption" }, r ? "Selected source" : "Destination"),
      el("strong", {}, r?.city || this.hq.city),
      ...(r ? [el("span", {}, `${r.events} events · ${r.ips} ${r.ips === 1 ? "IP" : "IPs"} · ${r.sev}`)] : []));
  }

  tick(now, rate, last) {
    this.card.querySelector("#map-rate").textContent = fmtN(rate);
    this.card.querySelector("#map-clock").textContent = now.toISOString().slice(11, 19);
    const node = this.card.querySelector("#map-last");
    node.textContent = last ? clock(last) : "—";
    node.title = last || "No event timestamp";
    node.setAttribute("aria-label", node.title);
  }

  dispose() {
    clearTimeout(this.hover);
    this.life.abort();
    this.observer.disconnect();
    this.orbit?.dispose();
  }
}
