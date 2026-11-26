import { expect, test } from "vitest";
import { honeyTokenCreated, honeyTokenForbidden, honeyTokens } from "./fixtures";
import { notificationKindLabel } from "./index";

test("the list fixture has two tokens, one triggered", () => {
  expect(honeyTokens.items).toHaveLength(2);
  expect(honeyTokens.items.filter((t) => t.last_triggered_at !== null)).toHaveLength(1);
});

test("no honey fixture carries a value field", () => {
  const allowed = ["id", "name", "template", "created_at", "disabled_at", "last_triggered_at"].sort();
  for (const t of [...honeyTokens.items, honeyTokenCreated]) expect(Object.keys(t).sort()).toEqual(allowed);
});

test("the 403 is a problem body and the new kind has a label", () => {
  expect(honeyTokenForbidden.status).toBe(403);
  expect(notificationKindLabel("honey.triggered")).toBe("Honey token triggered");
});
