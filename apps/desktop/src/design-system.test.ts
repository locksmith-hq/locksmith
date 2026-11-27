import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const here = import.meta.dirname;
const old = "@locksmith/ui";

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory()
      ? sources(join(dir, e.name))
      : /\.(tsx?|css)$/.test(e.name) && !e.name.startsWith("design-system.test")
        ? [join(dir, e.name)]
        : [],
  );
}

describe("desktop uses the design system", () => {
  // Flip to a normal `it` once the last screen is moved (t11 group 3).
  it.fails("names the old kit nowhere in the sources or the manifest", () => {
    const manifest = readFileSync(join(here, "..", "package.json"), "utf8");
    expect(manifest).not.toContain(old);
    for (const f of sources(here)) expect(readFileSync(f, "utf8"), f).not.toContain(old);
  });
});
