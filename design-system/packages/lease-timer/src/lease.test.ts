import assert from "node:assert/strict";
import { test } from "node:test";
import { lease } from "./lease.ts";

test("lease: fraction left is clamped, and the text moves from hours to minutes to Expired", () => {
  const total = 600_000; // ten minutes
  assert.deepEqual(lease(0, 600_000, total), { left: 1, text: "10:00" });
  assert.deepEqual(lease(0, 90_500, total), { left: 90_500 / total, text: "1:31" });
  assert.deepEqual(lease(0, 900_000, total), { left: 1, text: "15:00" });
  assert.deepEqual(lease(1000, 500, total), { left: 0, text: "Expired" });
  assert.equal(lease(0, 2 * 3600_000 + 5 * 60_000, 8 * 3600_000).text, "2h 05m");
  assert.deepEqual(lease(0, 1000, 0), { left: 0, text: "0:01" });
});
