// Every component, through its demo on this site: it renders, and axe finds no accessibility violation in it.
// One file covers the whole kit, so a new component is tested the moment it has a page.
import { cleanup, render } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, test } from "vitest";
import { TooltipProvider } from "@locksmith-hq/ui/tooltip";
import { DEMOS } from "./demos";

afterEach(cleanup);

// jsdom has no layout, so the rules that need one cannot run; region is about whole pages, not fragments.
const RULES = { "color-contrast": { enabled: false }, region: { enabled: false } };

test.each(Object.keys(DEMOS))("%s renders with no accessibility violations", async (name) => {
  // The app wraps its root in one TooltipProvider, as the site does.
  const { container } = render(<TooltipProvider>{DEMOS[name][1]}</TooltipProvider>);
  expect(container.firstChild).not.toBeNull();
  const { violations } = await axe.run(container, { rules: RULES });
  expect(violations.map((v) => `${v.id}: ${v.help} (${v.nodes[0]?.html.slice(0, 120)})`)).toEqual([]);
});
