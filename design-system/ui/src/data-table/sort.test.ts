// node --test src/sort.test.ts
import assert from "node:assert/strict";
import { test } from "node:test";
import { sortRows } from "./sort.ts";

test("sortRows orders numbers by size, text naturally, keeps empties last, and does not mutate", () => {
  const rows = [
    { n: 10, s: "agent-10" },
    { n: 2, s: "agent-2" },
    { n: null, s: "" },
    { n: 5, s: "Agent-5" },
  ];
  assert.deepEqual(
    sortRows(rows, (r) => r.n, "asc").map((r) => r.n),
    [2, 5, 10, null],
  );
  assert.deepEqual(
    sortRows(rows, (r) => r.n, "desc").map((r) => r.n),
    [10, 5, 2, null],
  );
  assert.deepEqual(
    sortRows(rows, (r) => r.s, "asc").map((r) => r.s),
    ["agent-2", "Agent-5", "agent-10", ""],
  );
  assert.deepEqual(
    sortRows(rows, (r) => r.s, "desc").map((r) => r.s),
    ["agent-10", "Agent-5", "agent-2", ""],
  );
  assert.equal(rows[0].n, 10);
});
