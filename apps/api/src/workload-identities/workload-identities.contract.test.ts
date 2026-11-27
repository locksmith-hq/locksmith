import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { diffAgainstFrozen, type RouteTable } from "../openapi/compare.js";
import { workloadIdentityRoutes } from "../openapi/registry.js";

const read = (rel: string) => JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8"));
const frozen = read("../../../../services/control-plane/openapi.json");

describe("workload identity routes vs the frozen contract", () => {
  it("generates the operations of openapi.json (route table not flipped yet)", () => {
    const table: RouteTable = {
      routes: workloadIdentityRoutes.map((r) => ({ method: r.method, path: r.path, owner: "nest" })),
    };
    expect(diffAgainstFrozen(workloadIdentityRoutes, frozen, table)).toEqual([]);
  });

  it("is still owned by rust in the route table", () => {
    const t = read("../../route-table.json") as RouteTable;
    for (const r of workloadIdentityRoutes)
      expect(t.routes.find((x) => x.method === r.method && x.path === r.path)?.owner).toBe("rust");
  });
});
