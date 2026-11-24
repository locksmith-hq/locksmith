import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ALLOWED_TOOLS, AgentError } from "./types";

describe("types", () => {
  it("allows exactly the three relay-only tools", () => {
    expect([...ALLOWED_TOOLS]).toEqual(["list_my_keys", "relay_http_request", "explain_block"]);
  });

  it("AgentError carries a slug and status, never other text", () => {
    const e = new AgentError("no_grant", 403);
    expect(e.slug).toBe("no_grant");
    expect(e.status).toBe(403);
    expect(e.message).toBe("no_grant");
  });

  it("the slug union covers every slug of the contract fixture", () => {
    const src = readFileSync(new URL("./types.ts", import.meta.url), "utf8");
    const errors = JSON.parse(
      readFileSync(new URL("../../../tests/kit/agent-contract/errors.json", import.meta.url), "utf8"),
    ) as { slug: string }[];
    for (const { slug } of errors) expect(src).toContain(`"${slug}"`);
  });
});
