import assert from "node:assert/strict";
import test from "node:test";
import { galaxyGroups, galaxyMotion, particlePlan } from "../static/graph-galaxy.js";

test("shared evidence joins its most strongly linked community and unassigned alerts anchor their own", () => {
  const nodes = ["incident", "alert", "alert", "alert", "host", "user"].map((type, id) => ({ type, id }));
  const [incident, first, second, independent, host, user] = nodes;
  const edges = [[first, incident, "membership"], [second, incident, "membership"],
    [first, host, "evidence"], [independent, host, "evidence"], [second, host, "evidence"], [independent, user, "evidence"]]
    .map(([a, b, type]) => ({ a, b, type }));
  const groups = galaxyGroups(nodes, edges.reverse());
  assert.deepEqual(groups.map(group => group.members.map(n => n.id)), [[0, 1, 2, 4], [3, 5]]);
  assert.notEqual(incident.group.hue, independent.group.hue);
});

test("all dust and background stars share one viewport-sized particle cap", () => {
  function total(plan) { return plan.stars + plan.dust.reduce((a, b) => a + b, 0); }
  const sizes = [1, 4, 19, 2, 6];
  const phone = particlePlan(390, 501, sizes), desktop = particlePlan(963, 636, sizes);
  assert.ok(total(phone) <= Math.ceil(390 * 501 / 38));
  assert.ok(total(phone) < total(desktop));
  assert.ok(phone.dust[2] > phone.dust[0]);
  assert.equal(total(particlePlan(10000, 10000, Array(500).fill(1))), 16000);
  assert.equal(total(particlePlan(1, 1, sizes)), 1);
  assert.equal(total(particlePlan(0, 0, sizes)), 0);
  assert.equal(total(particlePlan(320, 568, [])), 0);
});

test("reduced motion paints the fully bloomed static scene at every timestamp", () => {
  for (const elapsed of [0, 100, 920, 42000]) {
    assert.deepEqual(galaxyMotion(elapsed, true), { bloom: 1, time: 0, animate: false });
  }
  assert.equal(galaxyMotion(0, false).bloom, 0);
  assert.ok(galaxyMotion(500, false).bloom > 0 && galaxyMotion(500, false).bloom < 1);
  assert.deepEqual(galaxyMotion(2000, false), { bloom: 1, time: 2, animate: true });
});
