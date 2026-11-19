// Orthographic Earth with photographic textures. Bearings are geographic degrees.
// The overlay uses the same world vectors and camera basis as the WebGL sphere.
import { WebGLRenderer, OrthographicCamera, SphereGeometry, Scene, Mesh, ShaderMaterial,
  Texture, Vector3, LinearFilter, RepeatWrapping } from "./vendor/three/three.module.min.js";

const RAD = Math.PI / 180;
const colors = { critical: "#ff6b60", high: "#ffb55a", medium: "#e4d7ac", low: "#95abb9", info: "#95abb9" };

export function position({ lon, lat }) {
  const c = Math.cos(lat * RAD);
  return new Vector3(c * Math.cos(lon * RAD), Math.sin(lat * RAD), -c * Math.sin(lon * RAD));
}

// Sample the shortest great circle, lifting the beam above the surface.
export function track(from, to) {
  const a = position(from), b = position(to);
  const angle = a.angleTo(b);
  const tangent = b.clone().addScaledVector(a, -a.dot(b));
  if (tangent.lengthSq() < 1e-10) tangent.crossVectors(a, Math.abs(a.y) < .9 ? new Vector3(0, 1, 0) : new Vector3(1, 0, 0));
  tangent.normalize();
  return Array.from({ length: 65 }, (_, i) => {
    const t = i / 64;
    return a.clone().multiplyScalar(Math.cos(t * angle)).addScaledVector(tangent, Math.sin(t * angle))
      .multiplyScalar(1.006 + .12 * Math.min(1, angle) * Math.sin(Math.PI * t));
  });
}

const vertexShader = `
varying vec2 coord;
varying vec3 earthNormal;
varying vec3 eyeNormal;
void main() {
  coord = uv;
  earthNormal = normal;
  eyeNormal = normalMatrix * normal;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.);
}`;

const fragmentShader = `
uniform sampler2D day;
uniform sampler2D night;
varying vec2 coord;
varying vec3 earthNormal;
varying vec3 eyeNormal;
void main() {
  vec3 n = normalize(earthNormal);
  float sun = dot(n, normalize(vec3(-.72, .22, -.67)));
  float dawn = smoothstep(-.23, .38, sun);
  vec3 terrain = texture2D(day, coord).rgb;
  vec3 dark = texture2D(night, coord).rgb;
  // Preserve the warm VIIRS signal while lifting cool shadow detail.
  float lights = smoothstep(.025, .28, dark.r - dark.b);
  vec3 dusk = pow(dark, vec3(.82)) * vec3(.80, .98, 1.12) + terrain * .12
            + lights * vec3(.66, .42, .18) + vec3(.006, .014, .022);
  vec3 lit = terrain * (.50 + .40 * max(0., sun)) + vec3(.022, .045, .068);
  vec3 color = mix(dusk, lit, dawn);
  float rim = pow(1. - max(0., normalize(eyeNormal).z), 3.2);
  vec2 grid = coord * vec2(12., 6.);
  vec2 edge = abs(fract(grid + .5) - .5) / max(fwidth(grid), vec2(.0001));
  float line = 1. - smoothstep(0., .85, min(edge.x, edge.y));
  color += vec3(.023, .045, .052) * line + vec3(.18, .49, .74) * rim;
  gl_FragColor = vec4(color, 1.);
}`;

export async function createOrbit(stage, gl, { select, drag, lost, signal }) {
  const surface = gl.canvas;
  const overlay = document.createElement("canvas");
  surface.className = "orbit-surface";
  overlay.className = "orbit-beams";
  for (const c of [surface, overlay]) c.setAttribute("aria-hidden", "true");
  let renderer;
  try {
    renderer = new WebGLRenderer({ canvas: surface, context: gl, alpha: true, antialias: true });
    const size = matchMedia("(max-width: 760px)").matches ? 1024 : 2048;
    const [day, night] = await Promise.all(["day", "night"].map(async name => {
      const img = new Image();
      img.src = `/textures/earth-${name}-${size}.webp`;
      await img.decode();
      return img;
    }));
    signal.throwIfAborted();
    if (gl.isContextLost()) throw Error("WebGL context lost");
    return build(renderer, day, night);
  } catch (error) {
    renderer?.dispose();
    gl.getExtension("WEBGL_lose_context")?.loseContext();
    throw error;
  }

  function build(renderer, dayImage, nightImage) {
    const texture = img => {
      const t = new Texture(img);
      t.wrapS = RepeatWrapping;
      t.magFilter = LinearFilter;
      t.needsUpdate = true;
      return t;
    };
    const day = texture(dayImage), night = texture(nightImage);
    const geometry = new SphereGeometry(1, 96, 64);
    const material = new ShaderMaterial({ vertexShader, fragmentShader, uniforms: { day: { value: day }, night: { value: night } } });
    const scene = new Scene();
    scene.add(new Mesh(geometry, material));
    const camera = new OrthographicCamera(-1, 1, 1, -1, .1, 10);
    const ctx = overlay.getContext("2d");
    const listeners = new AbortController();
    const on = (node, type, fn) => node.addEventListener(type, fn, { signal: listeners.signal });
    stage.prepend(surface, overlay);
    let width, height, radius, cx, cy;
    let lon = -27, lat = 37, flight = null, gesture = null, selected = null;
    let active = false, running = true, raf = 0, previous = 0, phase = 0;
    let routes = [], flashes = [], target = null, hits = [];
    const bearing = stage.querySelector(".orbit-bearing");
    // Sparse fixed stars establish the silhouette without moving with the planet.
    const stars = Array.from({ length: 53 }, (_, i) => ({
      x: ((i*197 + 53) % 521) / 521, y: ((i*i*7 + i*17 + 5) % 347) / 347,
      r: .4 + (i % 4)*.13,
    }));
    const forward = new Vector3(), right = new Vector3(), up = new Vector3();

    function resize() {
      width = stage.clientWidth;
      height = stage.clientHeight;
      if (!width || !height) return;
      const dpr = Math.min(devicePixelRatio || 1, 1.75);
      radius = Math.min(width * .42, height * .44);
      cx = width * .5; cy = height * .5;
      renderer.setPixelRatio(dpr);
      renderer.setSize(width, height, false);
      overlay.width = Math.round(width * dpr); overlay.height = Math.round(height * dpr);
      ctx.setTransform(overlay.width / width, 0, 0, overlay.height / height, 0, 0);
      camera.left = -cx / radius; camera.right = (width - cx) / radius;
      camera.top = cy / radius; camera.bottom = -(height - cy) / radius;
      camera.updateProjectionMatrix();
      invalidate();
    }

    function project(v) {
      const x = v.dot(right), y = v.dot(up);
      return { x: cx + radius * x, y: cy - radius * y, visible: v.dot(forward) >= 0 || x*x + y*y > 1.001 };
    }
    function dot(x, y, r, color) {
      ctx.beginPath(); ctx.arc(x, y, r, 0, 2*Math.PI); ctx.fillStyle = color; ctx.fill();
    }
    function beam(route, index, progress) {
      const points = route.path.map(project);
      const color = colors[route.sev];
      ctx.beginPath();
      let pen = false;
      for (const p of points) {
        if (p.visible) {
          if (pen) ctx.lineTo(p.x, p.y); else ctx.moveTo(p.x, p.y);
        }
        pen = p.visible;
      }
      ctx.strokeStyle = color;
      ctx.globalAlpha = .14;
      ctx.lineWidth = route.weight + 2.8; ctx.stroke();
      ctx.globalAlpha = selected && route.city !== selected ? .4 : .88;
      ctx.lineWidth = route.weight; ctx.stroke();
      const t = progress ?? ((phase * .24 + index * .21) % 1);
      const pulse = points[Math.min(64, Math.floor(t * 64))];
      if (pulse.visible) {
        ctx.globalAlpha = .3;
        dot(pulse.x, pulse.y, 3.9, color);
        ctx.globalAlpha = .95;
        dot(pulse.x, pulse.y, 1.6, "#ffead6");
      }
      ctx.globalAlpha = 1;
    }

    function draw() {
      if (!width || !height) return;
      forward.copy(position({ lat, lon }));
      right.set(-Math.sin(lon*RAD), 0, -Math.cos(lon*RAD));
      up.crossVectors(forward, right);
      camera.position.copy(forward).multiplyScalar(3);
      camera.up.copy(up); camera.lookAt(0, 0, 0);
      renderer.render(scene, camera);
      ctx.clearRect(0, 0, width, height);
      const haze = ctx.createRadialGradient(cx, cy, radius - 1, cx, cy, radius * 1.09);
      haze.addColorStop(0, "rgba(80,173,226,.26)");
      haze.addColorStop(.3, "rgba(56,127,174,.10)");
      haze.addColorStop(1, "rgba(30,91,145,0)");
      ctx.beginPath(); ctx.arc(cx, cy, radius * 1.09, 0, Math.PI*2);
      ctx.arc(cx, cy, radius - 1, 0, Math.PI*2, true);
      ctx.fillStyle = haze; ctx.fill();
      for (const star of stars) {
        const x = star.x * width, y = star.y * height;
        if (Math.hypot(x - cx, y - cy) > radius + 3) dot(x, y, star.r, "#67808e");
      }
      const longitude = ((lon % 360 + 540) % 360) - 180;
      const coords = `${Math.abs(lat).toFixed(1)}°${lat < 0 ? "S" : "N"}  ${Math.abs(longitude).toFixed(1)}°${longitude < 0 ? "W" : "E"}`;
      if (bearing.textContent !== coords) bearing.textContent = coords;
      routes.forEach((r, i) => beam(r, i));
      flashes = flashes.filter(f => phase - f.start < 1.4);
      flashes.forEach(f => beam(f, 0, (phase - f.start) / 1.4));
      hits = [];
      const labels = [];
      function label(p, name, color, city) {
        ctx.font = "500 11px ui-monospace, Menlo, monospace";
        const w = ctx.measureText(name).width + 9;
        const x = p.x + w + 13 < width ? p.x + 10 : p.x - w - 10;
        const y = [p.y - 15, p.y + 4, p.y - 30].find(y =>
          y > 24 && y+16 < height-23 && !labels.some(b => x < b.x + b.w + 2 && x+w+2 > b.x && y < b.y + 17 && y+17 > b.y));
        if (y === undefined) return;
        const box = { x, y, w };
        labels.push(box);
        if (city) hits.push({ box, city });
        ctx.fillStyle = "rgba(5,15,21,.87)"; ctx.beginPath(); ctx.roundRect(x,y,w,16,3); ctx.fill();
        ctx.fillStyle = color; ctx.fillText(name, x+4, y+11.5);
      }
      if (target) {
        const p = project(target);
        if (p.visible) {
          const { x, y } = p;
          ctx.strokeStyle = "#9be6e5"; ctx.lineWidth = 1.2; ctx.beginPath();
          ctx.arc(x, y, 6.4, 0, 2*Math.PI); ctx.stroke();
          ctx.beginPath();
          for (const [dx,dy] of [[1,0],[-1,0],[0,1],[0,-1]]) {
            ctx.moveTo(x + dx*4, y + dy*4); ctx.lineTo(x + dx*10, y + dy*10);
          }
          ctx.stroke(); dot(x,y,1.8,"#d7ffff"); label(p, "HQ", "#b2edeb");
        }
      }
      const sorted = selected ? [...routes].sort((a,b) => Number(b.city === selected) - Number(a.city === selected)) : routes;
      for (const r of sorted) {
        const p = project(r.source);
        if (!p.visible) continue;
        const color = colors[r.sev];
        ctx.globalAlpha = .2; dot(p.x, p.y, 5.8 + Math.sin(phase*2)*1.1, color);
        ctx.globalAlpha = 1; dot(p.x, p.y, 3.2, color);
        dot(p.x, p.y, 1.15, "#fff2dc");
        label(p, r.city, "#f0f4f5", r.city);
        hits.push({ ...p, city: r.city });
      }
    }

    function invalidate() {
      if (active && !raf) raf = requestAnimationFrame(frame);
    }

    function frame(now) {
      raf = 0;
      if (!active) return;
      if (previous && now - previous < 1000/30) { invalidate(); return; }
      const dt = previous ? Math.min(.08, (now - previous)/1000) : 0;
      previous = now;
      if (running) { phase += dt; lon += dt * 1.15; }
      if (flight) {
        const progress = Math.min(1, (now - flight.start) / 780);
        const t = progress * progress * (3 - 2 * progress);
        lon = flight.lon + flight.dx*t; lat = flight.lat + flight.dy*t;
        if (progress === 1) flight = null;
      }
      draw();
      if (running || flight) invalidate(); else previous = 0;
    }
    const observer = new ResizeObserver(resize);
    observer.observe(stage);
    resize();
    on(surface, "webglcontextlost", lost);
    on(overlay, "pointerdown", e => {
      if (!e.isPrimary || e.button !== 0) return;
      gesture = { x: e.clientX, y: e.clientY, lon, lat, moved: false };
      overlay.setPointerCapture(e.pointerId);
    });
    on(overlay, "pointermove", e => {
      if (!gesture) return;
      const dx = e.clientX - gesture.x, dy = e.clientY - gesture.y;
      if (!gesture.moved && Math.hypot(dx,dy) < 4) return;
      if (!gesture.moved) { gesture.moved = true; flight = null; drag(); }
      lon = gesture.lon - dx * 65/radius;
      lat = Math.max(-85, Math.min(85, gesture.lat + dy * 65/radius));
      invalidate();
    });
    on(overlay, "pointerup", e => {
      if (gesture && !gesture.moved) {
        const hit = hits.find(p => p.box
          ? e.offsetX >= p.box.x && e.offsetX <= p.box.x+p.box.w && e.offsetY >= p.box.y && e.offsetY <= p.box.y+16
          : Math.hypot(p.x - e.offsetX, p.y - e.offsetY) < 13);
        if (hit) select(hit.city);
      }
      gesture = null;
    });
    on(overlay, "lostpointercapture", () => { gesture = null; });
    return {
      data(rows, hq) {
        target = hq && position(hq);
        routes = hq ? rows.map(r => ({ ...r, source: position(r), path: track(r, hq), weight: .65 + .19*Math.log2(1+r.events) })) : [];
        invalidate();
      },
      state(visible, rotate) {
        running = rotate;
        active = visible;
        if (active) invalidate();
        else { cancelAnimationFrame(raf); raf = 0; previous = 0; }
      },
      fly(r) {
        flight = { lon, lat, dx: ((r.lon - lon) % 360 + 540) % 360 - 180, dy: r.lat - lat, start: performance.now() };
        invalidate();
      },
      highlight(city) { selected = city; invalidate(); },
      pulse(loc, dest, sev) {
        if (active && running && flashes.length < 16) flashes.push({ path: track(loc,dest), sev, weight: 1.6, start: phase });
      },
      dispose() {
        active = false;
        cancelAnimationFrame(raf); observer.disconnect(); listeners.abort();
        day.dispose(); night.dispose(); geometry.dispose(); material.dispose(); renderer.dispose();
        renderer.forceContextLoss(); surface.remove(); overlay.remove();
      },
    };
  }
}
