import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Decision A0-5: tenant context is `set_config(..., true)` inside a transaction. A session-level
// `SET` (or `SET SESSION`, `set_config(..., false)`) would leak across pooled connections.
const BANNED: RegExp[] = [
  /\bset\s+(session\s+)?app\.[a-z_]+\s*(=|to\b)/i,
  /\bset\s+session\b/i,
  /set_config\s*\([^)]*,\s*false\s*\)/i,
];

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return sources(p);
    return p.endsWith(".ts") && !p.endsWith(".test.ts") ? [p] : [];
  });
}

describe("session-level SET ban", () => {
  it("the detector flags the banned forms", () => {
    for (const bad of ["SET app.org_id = 'x'", "set session app.org_id to 'x'", "select set_config('app.org_id', $1, false)"]) {
      expect(BANNED.some((r) => r.test(bad)), bad).toBe(true);
    }
    expect(BANNED.some((r) => r.test("select set_config('app.org_id', $1, true)"))).toBe(false);
  });

  it("no source file under src/ uses one", () => {
    const hits = sources(join(import.meta.dirname, "..")).filter((f) => {
      const text = readFileSync(f, "utf8");
      return BANNED.some((r) => r.test(text));
    });
    expect(hits).toEqual([]);
  });
});
