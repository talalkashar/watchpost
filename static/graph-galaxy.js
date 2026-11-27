// Keep successive incident colours distinct on black, including warm and cool clouds.
const hues = [146, 215, 275, 325, 14, 174, 235, 301, 347, 31, 116, 258, 194];

// Colour communities by the incident behind each alert. An alert that has no
// incident anchors its own cloud. Shared evidence votes once per linked alert.
export function galaxyGroups(nodes, edges) {
  const parent = new Map(), votes = new Map();
  for (const { type, a, b } of edges) if (type === "membership") parent.set(a, b);
  for (const { type, a, b } of edges) {
    if (type !== "evidence") continue;
    const root = parent.get(a) || a;
    if (!votes.has(b)) votes.set(b, new Map());
    const tally = votes.get(b);
    tally.set(root, (tally.get(root) || 0) + 1);
  }
  for (const [node, tally] of votes) {
    let best, count = 0;
    for (const [root, n] of tally) {
      if (n > count || (n === count && root.id < best.id)) { best = root; count = n; }
    }
    parent.set(node, best);
  }
  const groups = new Map();
  for (const node of nodes) {
    const root = parent.get(node) || node;
    if (!groups.has(root)) {
      const seed = (root.ref ?? root.id) * 2 + Number(root.type === "incident");
      const hue = (hues[seed % hues.length] + Math.floor(seed / hues.length) * 2.4) % 360;
      groups.set(root, { root, seed, hue, members: [] });
    }
    const group = groups.get(root);
    group.members.push(node);
    node.group = group;
  }
  return [...groups.values()];
}

// Budget in CSS pixels. A Retina phone gets the same dust count as a 1x phone.
// Cumulative rounding apportions the whole allowance across filtered communities.
export function particlePlan(width, height, sizes) {
  const total = sizes.reduce((a, b) => a + b, 0);
  if (!total || width <= 0 || height <= 0) return { stars: 0, dust: sizes.map(() => 0) };
  const budget = Math.min(16000, Math.ceil(width * height / 38));
  const stars = Math.min(210, Math.ceil(budget / 38));
  let sum = 0, allocated = 0;
  const dust = sizes.map(size => {
    sum += size;
    const end = Math.round((budget - stars) * sum / total);
    const count = end - allocated;
    allocated = end;
    return count;
  });
  return { stars, dust };
}

export function galaxyMotion(elapsed, reduced) {
  const t = reduced ? 1 : Math.min(1, elapsed / 1150);
  return { bloom: 1 - (1 - t) ** 3, time: reduced ? 0 : elapsed * .001, animate: !reduced };
}

// Bake an irregular, knotted ribbon of gas and fine grains once. Only the
// projection of this tile changes per frame, independent of its particle count.
export function nebulaTile(group, count) {
  const tile = document.createElement("canvas");
  const side = count > 650 ? 384 : count > 100 ? 256 : 128;
  tile.width = tile.height = side;
  const g = tile.getContext("2d");
  let state = (group.seed + 1) >>> 0;
  const random = () => ((state = (Math.imul(1664525, state) + 1013904223) >>> 0) / 4294967296);
  const normal = () => Math.sqrt(-2 * Math.log(1 - random())) * Math.cos(2 * Math.PI * random());
  const hue = group.hue, bend = (random() - .5) * .48, phase = random() * 6.28;
  const ridge = x => bend * Math.sin(x * 3.7 + phase) + .13 * Math.sin(x * 6 - phase);
  g.setTransform(side / 2, 0, 0, side / 2, side / 2, side / 2);
  g.globalCompositeOperation = "lighter";
  const knots = [-.42, -.12, .16, .45].map(x => {
    const y = ridge(x), radius = .25 + random() * .24;
    g.save(); g.translate(x, y); g.scale(1, .74);
    const halo = g.createRadialGradient(0, 0, 0, 0, 0, radius * 1.8);
    halo.addColorStop(0, `hsl(${hue} 96% 76% / .53)`);
    halo.addColorStop(.19, `hsl(${hue + 8} 96% 62% / .26)`);
    halo.addColorStop(.42, `hsl(${hue} 87% 52% / .10)`);
    halo.addColorStop(1, `hsl(${hue} 85% 45% / 0)`);
    g.fillStyle = halo; g.fillRect(-1, -1, 2, 2); g.restore();
    return { x, radius };
  });
  // Bright grains are sparse. Most of the texture is close to the black floor.
  const grain = count < 450 ? .0062 : .0038;
  for (let i = 0; i < count; i++) {
    const knot = knots[i % knots.length];
    const x = knot.x + normal() * knot.radius * .50;
    const y = ridge(x) + (i % 4 === 0 ? .14 * Math.sin(6 * x + phase) : 0) +
      normal() * knot.radius * (.17 + random() * .60);
    const fade = Math.max(0, 1 - (x * x + y * y) ** 2);
    const light = random() ** 3, r = (grain + .008 * light) * (.6 + random());
    g.fillStyle = `hsl(${hue + 22 * Math.sin(x * 4)} 95% ${60 + 34 * light}% / ${(.32 + .66 * light) * fade})`;
    g.fillRect(x, y, r, r);
  }
  const edge = g.createRadialGradient(0, 0, .50, 0, 0, .98);
  edge.addColorStop(0, "#fff"); edge.addColorStop(.64, "#ffffffc4"); edge.addColorStop(1, "#fff0");
  g.globalCompositeOperation = "destination-in"; g.fillStyle = edge; g.fillRect(-1, -1, 2, 2);
  return tile;
}
