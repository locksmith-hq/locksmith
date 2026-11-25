import { expect, test } from "vitest";
import { notificationChannels, notificationForbidden, notificationInbox, notificationRules } from "./fixtures";

test("the inbox fixture has three items and one unread", () => {
  expect(notificationInbox.items).toHaveLength(3);
  expect(notificationInbox.items.filter((n) => n.read_at === null)).toHaveLength(1);
  expect(notificationInbox.unread_count).toBe(1);
});

test("the default matrix routes every kind to the owner's inbox", () => {
  expect(new Set(notificationRules.rules.map((r) => r.kind)).size).toBe(4);
  expect(notificationRules.rules.every((r) => r.channel === "inbox" && r.audience === "owner")).toBe(true);
});

test("Slack is shown as not configured and the 403 is a problem body", () => {
  expect(notificationChannels.slack).toEqual({ configured: false });
  expect(notificationForbidden.status).toBe(403);
});

test("no fixture carries a payload field outside the allow-list", () => {
  const allowed = ["kind", "actor", "object_name", "occurred_at", "link"];
  for (const n of notificationInbox.items) expect(Object.keys(n.payload).sort()).toEqual([...allowed].sort());
});

import { notificationSummary, toggleRule } from "./index";

test("summary uses allow-listed fields and toggleRule adds then removes a rule", () => {
  expect(notificationSummary(notificationInbox.items[0]!)).toBe("Relay denied on stripe by ci-agent");
  const added = toggleRule(notificationRules.rules, "relay.denied", "email");
  expect(added).toHaveLength(5);
  expect(toggleRule(added, "relay.denied", "email")).toEqual(notificationRules.rules);
});
