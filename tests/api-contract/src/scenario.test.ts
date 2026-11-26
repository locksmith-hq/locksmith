import { describe, expect, it } from "vitest";
import { loadScenarios, parseScenarioFilter } from "./scenario.ts";

describe("scenario filter", () => {
  it("parses a comma list and ignores blanks", () => {
    expect(parseScenarioFilter(" auth, ,orgs,")).toEqual(["auth", "orgs"]);
    expect(parseScenarioFilter(undefined)).toEqual([]);
  });
  it("loads only the named scenario ids", async () => {
    const all = await loadScenarios([]);
    const some = await loadScenarios(["auth"]);
    expect(some).toHaveLength(1);
    expect(some.length).toBeLessThan(all.length);
  });
  it("refuses an unknown id", async () => {
    await expect(loadScenarios(["nope"])).rejects.toThrow("unknown scenario id(s): nope");
  });
});
