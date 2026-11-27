import assert from "node:assert/strict";
import test from "node:test";
import { seedLayout, signalChains, stepLayout } from "../static/graph-layout.js";

test("dragged nodes hold their position and transmit spring forces until released", () => {
  const nodes = [{ type: "host", id: 0 }, { type: "alert", id: 1 }];
  const links = [{ type: "evidence", a: nodes[1], b: nodes[0] }];
  seedLayout(nodes, links);
  const [anchor, neighbour] = nodes, initialX = neighbour.x;
  anchor.x = 500; anchor.pinned = true;
  for (let i = 0; i < 30; i++) stepLayout(nodes, links);
  assert.equal(anchor.x, 500);
  assert.ok(neighbour.x > initialX + 100);
  anchor.pinned = false; stepLayout(nodes, links);
  assert.ok(anchor.x < 500);
});

test("signals follow visible evidence to its own alert and incident", () => {
  const host = { type: "host" }, ip = { type: "src_ip" };
  const alert = { type: "alert" }, other = { type: "alert", id: 2 };
  const incident = { type: "incident" }, unrelated = { type: "incident", id: 7 };
  const links = [
    { type: "membership", a: alert, b: incident }, { type: "membership", a: other, b: unrelated },
    { type: "evidence", a: alert, b: host }, { type: "evidence", a: other, b: ip },
    { type: "correlation", a: alert, b: other },
  ];
  for (const focus of [null, host, alert, incident]) assert.deepEqual(signalChains(links, focus), [[host, alert, incident]]);
  assert.deepEqual(signalChains(links, ip), [[ip, other, unrelated]]);
  assert.deepEqual(signalChains(links.slice(2), host), [[host, alert]]);
  assert.deepEqual(signalChains(links.slice(0, 2), incident), [[alert, incident]]);
  assert.deepEqual(signalChains([], null), []);
});
