import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { coverageGaps, operations } from "./coverage.ts";
import { EXCLUDED } from "./exclusions.ts";
import { loadScenarios } from "./scenario.ts";

const read = (rel: string) => JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8"));
const spec = read("../../../services/control-plane/openapi.json");
const nestSpec = read("../../../apps/api/openapi.nest.json");

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

describe("coverage (Nest-only document)", () => {
  const planted = { paths: { "/v1/planted": { get: {}, post: {} } } };
  it("names a planted Nest-only path that has no scenario or exclusion", () => {
    const g = coverageGaps(operations(planted), ["GET /v1/planted"], {});
    expect(g.missing).toEqual(["POST /v1/planted"]);
  });
});

describe("coverage (openapi.json and openapi.nest.json)", () => {
  it("every path and method has a scenario or a reasoned exclusion", async () => {
    const covered = (await loadScenarios()).flatMap((s) => s.covers);
    const g = coverageGaps([...operations(spec), ...operations(nestSpec)].sort(), covered, EXCLUDED);
    expect(g.missing, `no scenario for: ${g.missing.join(", ")}`).toEqual([]);
    expect(g.staleExclusions, `stale exclusions: ${g.staleExclusions.join(", ")}`).toEqual([]);
    expect(g.unknownCovers, `unknown paths: ${g.unknownCovers.join(", ")}`).toEqual([]);
  });
});
