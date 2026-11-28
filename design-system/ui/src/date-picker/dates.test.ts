import assert from "node:assert/strict";
import { test } from "node:test";
import { addDays, addMonths, clamp, daysBetween, monthGrid } from "./dates.ts";

test("date maths: days cross months and leap days, months clamp, grids start on the chosen weekday", () => {
  assert.equal(addDays("2026-12-31", 1), "2027-01-01");
  assert.equal(clamp("2026-01-05", "2026-01-10", "2026-01-20"), "2026-01-10");
  assert.equal(clamp("2026-02-01", "2026-01-10", "2026-01-20"), "2026-01-20");
  assert.equal(clamp("2026-01-15", "2026-01-10"), "2026-01-15");
  assert.equal(addDays("2028-02-28", 1), "2028-02-29");
  assert.equal(daysBetween("2026-11-26", "2026-12-31"), 35);
  assert.equal(daysBetween("2026-12-31", "2026-11-26"), -35);
  assert.equal(addMonths("2026-01-31", 1), "2026-02-28");
  assert.equal(addMonths("2026-12-15", 1), "2027-01-15");
  assert.equal(addMonths("2026-03-31", -1), "2026-02-28");
  const mon = monthGrid("2026-11-15"); // 1 Nov 2026 is a Sunday
  assert.equal(mon.length, 42);
  assert.equal(mon[0], "2026-10-26");
  assert.ok(mon.includes("2026-11-01") && mon.includes("2026-11-30"));
  assert.equal(monthGrid("2026-11-15", 0)[0], "2026-11-01");
});
