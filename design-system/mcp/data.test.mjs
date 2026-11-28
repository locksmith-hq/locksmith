import assert from "node:assert/strict";
import { test } from "node:test";
import { getComponent, getGuide, getTokens, listComponents } from "./data.mjs";

test("components: every package is listed with a description, and one reads back in full", () => {
  const all = listComponents();
  assert.ok(all.length > 60);
  assert.ok(all.every((c) => c.package.startsWith("@locksmith-hq/ui/") && c.about));

  const button = getComponent("Button");
  assert.equal(button.package, "@locksmith-hq/ui/button");
  assert.match(button.import, /import \{ Button.* \} from "@locksmith-hq\/ui\/button";/);
  assert.ok(button.variants.variant.includes("destructive"));
  assert.match(button.example, /<Button/);

  // a Locksmith-only component carries its documented props; names match with or without the dash
  const table = getComponent("DataTable");
  assert.equal(table.name, "data-table");
  assert.ok(table.props.DataTable.some((p) => p.name === "loading" && p.description));
  assert.equal(getComponent("no-such-thing"), null);
});

test("tokens and guide: colours come with both themes, and the guide is the README", () => {
  const brand = getTokens("brand");
  assert.match(brand.brand.light, /^#/);
  assert.notEqual(brand.brand.light, brand.brand.dark);
  assert.ok(Object.keys(getTokens("state")).includes("state-hover"));
  assert.ok(!("space-1" in getTokens()));
  assert.match(getGuide(), /@locksmith-hq:registry/);
});
