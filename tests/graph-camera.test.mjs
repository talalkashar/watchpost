import assert from "node:assert/strict";
import test from "node:test";
import { fitFrame, limitCenter } from "../static/graph-camera.js";

const nodes = [{ x: -260, y: -140 }, { x: 3, y: 0 }, { x: 220, y: 160 }];
const overlap = (min, max, center, half) =>
  Math.min(max, center + half) - Math.max(min, center - half);

for (const [width, height] of [[272, 320], [340, 501], [960, 636]]) {
  test(`padded fit and 40% overlap after extreme and diagonal pans at ${width}px`, () => {
    const f = fitFrame(nodes, width, height);
    assert.ok((f.right - f.left) * f.scale <= width * 0.90);
    assert.ok((f.bottom - f.top) * f.scale <= height * 0.90);
    for (const zoom of [1, 1.5, f.maxZoom]) {
      const hw = width / (2 * zoom * f.scale), hh = height / (2 * zoom * f.scale);
      for (const x of [-1e5, 0, 1e5]) for (const y of [-1e5, 0, 1e5]) {
        const c = limitCenter(f, nodes, width, height, zoom, x, y);
        assert.ok(overlap(f.left, f.right, c.x, hw) >= .4 * (f.right - f.left) - 1e-8);
        assert.ok(overlap(f.top, f.bottom, c.y, hh) >= .4 * (f.bottom - f.top) - 1e-8);
        assert.ok(nodes.some(n => Math.abs(n.x - c.x) <= hw + 1e-8 && Math.abs(n.y - c.y) <= hh + 1e-8));
      }
    }
  });
}

test("empty, singleton and collinear filters keep a finite camera", () => {
  for (const group of [[], [{ x: 5, y: 2 }], [{ x: 2, y: 1 }, { x: 2, y: 101 }]]) {
    const f = fitFrame(group, 320, 540);
    const c = limitCenter(f, group, 320, 540, f.maxZoom, -1e9, 1e9);
    assert.ok(Object.values({ ...f, ...c }).every(Number.isFinite));
    if (group.length) assert.ok(group.some(n =>
      Math.abs(n.x - c.x) * f.scale * f.maxZoom <= 160 &&
      Math.abs(n.y - c.y) * f.scale * f.maxZoom <= 270));
  }
});
