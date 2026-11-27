// The camera zoom is relative to the padded fit. Work in layout coordinates throughout.
const keep = 0.4;
const clamp = (value, low, high) => Math.max(low, Math.min(value, high));

export function fitFrame(nodes, width, height) {
  let left = Infinity, right = -Infinity, top = Infinity, bottom = -Infinity;
  for (const { x, y } of nodes) {
    left = Math.min(left, x); right = Math.max(right, x);
    top = Math.min(top, y); bottom = Math.max(bottom, y);
  }
  if (!nodes.length) left = right = top = bottom = 0;
  const dx = right - left, dy = bottom - top;
  const scale = Math.max(0.001, Math.min(
    (width - 2 * Math.min(72, width * 0.095)) / Math.max(120, dx),
    (height - 2 * Math.min(60, height * 0.09)) / Math.max(120, dy)));
  // At greater magnification, 40% of the larger axis would no longer fit.
  const maxZoom = Math.max(1, Math.min(4, width / (scale * Math.max(1, dx) * keep),
    height / (scale * Math.max(1, dy) * keep)));
  return { left, right, top, bottom, scale, maxZoom };
}

export function limitCenter(frame, nodes, width, height, zoom, x, y) {
  const scale = frame.scale * zoom;
  const hw = width / (2 * scale), hh = height / (2 * scale);
  const { left, right, top, bottom } = frame;
  const kx = (right - left) * keep, ky = (bottom - top) * keep;
  x = clamp(x, left + kx - hw, right - kx + hw);
  y = clamp(y, top + ky - hh, bottom - ky + hh);

  // A sparse or diagonal layout can have empty corners inside its bounding box.
  // Move only far enough to put the nearest real node back within a small inset.
  const rx = hw * 0.90, ry = hh * 0.90;
  let nearest = Infinity, shiftX = 0, shiftY = 0;
  for (const n of nodes) {
    const dx = n.x - clamp(n.x, x - rx, x + rx);
    const dy = n.y - clamp(n.y, y - ry, y + ry);
    if (!dx && !dy) return { x, y };
    const dist = dx * dx + dy * dy;
    if (dist < nearest) { nearest = dist; shiftX = dx; shiftY = dy; }
  }
  return { x: clamp(x + shiftX, left + kx - hw, right - kx + hw),
    y: clamp(y + shiftY, top + ky - hh, bottom - ky + hh) };
}
