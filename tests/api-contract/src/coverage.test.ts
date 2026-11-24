import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { coverageGaps, operations } from "./coverage.ts";
import { EXCLUDED } from "./exclusions.ts";
import { loadScenarios } from "./scenario.ts";

const spec = JSON.parse(readFileSync(new URL("../../../services/control-plane/openapi.json", import.meta.url), "utf8"));

describe("coverage (logic)", () => {
  const ops = ["GET /a", "POST /a", "GET /b/{id}"];
  it("names an operation with no scenario and no exclusion", () => {
    expect(coverageGaps(ops, ["GET /a"], { "GET /b/{id}": "why" }).missing).toEqual(["POST /a"]);
  });
  it("flags an exclusion that is covered or not in the spec", () => {
    const g = coverageGaps(ops, ["GET /a", "POST /a", "GET /b/{id}"], { "GET /a": "x", "GET /gone": "y" });
    expect(g.staleExclusions).toEqual(["GET /a", "GET /gone"]);
  });
  it("flags a scenario that covers an operation the spec lacks", () => {
    expect(coverageGaps(ops, ["GET /nope"], {}).unknownCovers).toEqual(["GET /nope"]);
  });
});

describe("coverage (openapi.json)", () => {
  it("every path and method has a scenario or a reasoned exclusion", async () => {
    const covered = (await loadScenarios()).flatMap((s) => s.covers);
    const g = coverageGaps(operations(spec), covered, EXCLUDED);
    expect(g.missing, `no scenario for: ${g.missing.join(", ")}`).toEqual([]);
    expect(g.staleExclusions, `stale exclusions: ${g.staleExclusions.join(", ")}`).toEqual([]);
    expect(g.unknownCovers, `unknown paths: ${g.unknownCovers.join(", ")}`).toEqual([]);
  });
});
