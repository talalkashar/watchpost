// Start related nodes in the same part of the field, then relax the real links.
export function seedLayout(nodes, edges) {
  const incidents = nodes.filter(n => n.type === "incident");
  for (const [i, n] of nodes.entries()) {
    const a = i * 2.39996323, r = Math.sqrt(i) * 47;
    Object.assign(n, { x: Math.cos(a) * r, y: Math.sin(a) * r, vx: 0, vy: 0 });
  }
  const spread = Math.sqrt(nodes.length) * 66;
  for (const [i, n] of incidents.entries()) {
    const a = i * 2.39996323, r = spread * Math.sqrt((i + 0.5) / incidents.length);
    n.homeX = n.x = r * Math.cos(a); n.homeY = n.y = r * Math.sin(a);
  }
  for (const { type, a, b } of edges) {
    if (type === "membership") {
      a.x = b.x + 96 * Math.cos(a.id * 2.4); a.y = b.y + 96 * Math.sin(a.id * 2.4);
    }
  }
  // Exclusive evidence starts in its incident cluster. Shared evidence starts
  // between the alerts it actually connects, making bridges legible at fit.
  const centres = new Map();
  for (const { type, a, b } of edges) {
    if (type !== "evidence") continue;
    if (!centres.has(b)) centres.set(b, { x: 0, y: 0, count: 0 });
    const c = centres.get(b); c.x += a.x; c.y += a.y; c.count++;
  }
  for (const [n, c] of centres) {
    n.x = c.x / c.count + 75 * Math.cos(n.id * 2.4);
    n.y = c.y / c.count + 75 * Math.sin(n.id * 2.4);
  }
}

export function stepLayout(nodes, edges) {
  // Visit only neighbours in adjacent grid cells for repulsion.
  const spacing = 120, cols = 65536;
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
  for (const { a, b, type } of edges) {
    const dx = b.x - a.x, dy = b.y - a.y;
    const member = type === "membership";
    const stiffness = member ? .049 : type === "evidence" ? .019 : .009;
    const f = (1 - (member ? 66 : 86) / Math.max(1, Math.hypot(dx, dy))) * stiffness;
    a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
  }
  for (const n of nodes) {
    if (n.pinned) { n.vx = n.vy = 0; continue; }
    if (n.type === "incident") {
      n.vx += (n.homeX - n.x) * .027; n.vy += (n.homeY - n.y) * .027;
    }
    n.vx = (n.vx - n.x * 0.0013) * 0.63; n.vy = (n.vy - n.y * 0.0013) * 0.63;
    n.x += n.vx; n.y += n.vy;
  }
}

// API evidence links point from alert to entity. Play them back toward the alert,
// then follow its actual membership link to the incident. Never join unrelated alerts.
export function signalChains(links, focus) {
  const members = links.filter(e => e.type === "membership");
  const evidence = links.filter(e => e.type === "evidence");
  const active = focus || members[0]?.b || evidence[0]?.a;
  if (!active) return [];
  const cases = new Map();
  for (const e of members) {
    if (active.type !== "incident" || active === e.b) cases.set(e.a, e.b);
  }
  const chains = [];
  for (const link of evidence) {
    const incident = cases.get(link.a);
    if (active !== link.a && active !== link.b && active !== incident) continue;
    chains.push([link.b, link.a, incident].filter(Boolean));
    if (chains.length === 3) break;
  }
  if (!chains.length) {
    for (const e of members) {
      if (e.a === active || e.b === active) chains.push([e.a, e.b]);
      if (chains.length === 3) break;
    }
  }
  return chains;
}
