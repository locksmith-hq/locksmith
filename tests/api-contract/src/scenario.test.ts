import { describe, expect, it } from "vitest";
import { loadScenarios, parseScenarioFilter } from "./scenario.ts";

describe("scenario filter", () => {
  it("parses a comma list and ignores blanks", () => {
    expect(parseScenarioFilter(" tenancy, ,agents,")).toEqual(["tenancy", "agents"]);
    expect(parseScenarioFilter(undefined)).toEqual([]);
  });
  it("loads only the named scenario files", async () => {
    const all = await loadScenarios([]);
    const some = await loadScenarios(["tenancy"]);
    expect(some.length).toBeGreaterThan(0);
    expect(some.length).toBeLessThan(all.length);
  });
  it("refuses an unknown file stem", async () => {
    await expect(loadScenarios(["nope"])).rejects.toThrow("unknown scenario file(s): nope");
  });
});
