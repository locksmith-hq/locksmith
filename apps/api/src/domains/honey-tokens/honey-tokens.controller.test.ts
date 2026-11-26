import { describe, expect, it } from "vitest";
import { honeyTokenRoutes } from "./honey-token.schemas.js";
import { HoneyTokensController } from "./honey-tokens.controller.js";

describe("honey tokens contract", () => {
  it("registers list, create, disable and delete under an environment", () => {
    expect(honeyTokenRoutes.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /v1/projects/{project_id}/environments/{environment_id}/honey-tokens",
      "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens",
      "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}/disable",
      "DELETE /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}",
    ]);
  });

  it("never describes a value in a response", () => {
    const text = JSON.stringify(honeyTokenRoutes.map((r) => Object.keys(r.responses)));
    expect(text).not.toContain("value");
  });

  it("answers 501 from every stub until the module lands", () => {
    const c = new HoneyTokensController();
    for (const call of [() => c.list(), () => c.create(), () => c.disable(), () => c.remove()]) {
      expect(call).toThrow(/Not Implemented/);
    }
  });
});
