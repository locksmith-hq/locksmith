import { expect, test } from "vitest";
import type { BudgetLease, BudgetLeaseRequest } from "./index";

// The gateway-only lease contract (T9): the generated types carry the request and the answer.
test("budget lease contract types match the control-plane spec", () => {
  const req: BudgetLeaseRequest = { agent_id: "a", daily_limit: 100, count: 10 };
  const lease: BudgetLease = { granted: 0, used: 100, day: "2026-11-26" };
  expect(req.grant_id).toBeUndefined();
  expect(lease.granted).toBe(0);
});
