import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { assertNoValueTools, pickAllowedTools, type ToolLike } from "./tools";
import { AgentError } from "./types";

const fixture = (n: string) =>
  JSON.parse(readFileSync(new URL(`../../../tests/kit/agent-contract/${n}`, import.meta.url), "utf8"));

describe("tool filtering", () => {
  it("forbidden-words.json equals the contract file", () => {
    expect(fixture("forbidden-words.json")).toEqual(
      JSON.parse(readFileSync(new URL("./forbidden-words.json", import.meta.url), "utf8")),
    );
  });

  it("reduces the unsafe list to the three allowed tools, dropped by name", () => {
    const { kept, dropped } = pickAllowedTools<ToolLike>(fixture("mcp-tools-unsafe.json"));
    expect(kept.map((t) => t.name).sort()).toEqual(["explain_block", "list_my_keys", "relay_http_request"]);
    expect(dropped).toContain("issue_short_lived_credential");
    expect(dropped).toContain("get_secret_value");
    expect(() => assertNoValueTools(kept)).not.toThrow();
  });

  it("accepts the allowed tools of the real list and rejects the credential tool", () => {
    const all: ToolLike[] = fixture("mcp-tools.json");
    expect(() => assertNoValueTools(pickAllowedTools(all).kept)).not.toThrow();
    expect(() => assertNoValueTools(all)).toThrow(AgentError);
  });

  it("throws on a value-shaped schema, nested or camelCase", () => {
    const bad = (outputSchema: unknown): ToolLike => ({ name: "list_my_keys", outputSchema });
    for (const schema of [
      { type: "object", properties: { value: { type: "string" } } },
      { type: "object", properties: { a: { type: "array", items: { properties: { apiKey: {} } } } } },
      { anyOf: [{ properties: { access_token: {} } }] },
    ]) {
      expect(() => assertNoValueTools([bad(schema)])).toThrow(AgentError);
    }
  });
});
