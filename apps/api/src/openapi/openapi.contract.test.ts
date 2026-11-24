import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineRoute } from "./build.js";
import { diffAgainstFrozen, type RouteTable } from "./compare.js";
import { routes } from "./registry.js";

const read = (rel: string) => JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8"));
const frozen = read("../../../../services/control-plane/openapi.json");
const table = read("../../route-table.json") as RouteTable;

describe("generated OpenAPI vs the frozen contract", () => {
  it("matches openapi.json for every path marked nest", () => {
    expect(diffAgainstFrozen(routes, frozen, table)).toEqual([]);
  });
});

describe("diffAgainstFrozen", () => {
  const frozenDoc = {
    paths: {
      "/v1/things/{id}": {
        get: {
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: {
            "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Thing" } } } },
            "404": {},
          },
        },
      },
    },
    components: {
      schemas: {
        Thing: { type: "object", required: ["id"], properties: { id: { type: "string", description: "the id" } } },
      },
    },
  };
  const tbl: RouteTable = { routes: [{ method: "GET", path: "/v1/things/{id}", owner: "nest" }] };
  const Thing = z.object({ id: z.string() });
  const route = (thing: z.ZodType) =>
    defineRoute({
      method: "GET",
      path: "/v1/things/{id}",
      params: z.object({ id: z.string() }),
      responses: { 200: thing, 404: null },
    });

  it("accepts a route whose shape equals the frozen operation", () => {
    expect(diffAgainstFrozen([route(Thing)], frozenDoc, tbl)).toEqual([]);
  });

  it("reports a changed response schema", () => {
    const d = diffAgainstFrozen([route(z.object({ id: z.number() }))], frozenDoc, tbl);
    expect(d).toHaveLength(1);
    expect(d[0]).toContain("differs from the frozen contract");
  });

  it("reports a nest path with no zod route, and a zod route not marked nest", () => {
    expect(diffAgainstFrozen([], frozenDoc, tbl)[0]).toContain("no zod route is registered");
    expect(
      diffAgainstFrozen([route(Thing)], frozenDoc, { routes: [{ ...tbl.routes[0]!, owner: "rust" }] })[0],
    ).toContain("does not mark it nest");
  });

  it("reports a nest path missing from the frozen document", () => {
    const t: RouteTable = { routes: [{ method: "GET", path: "/v1/nope", owner: "nest" }] };
    expect(diffAgainstFrozen([], frozenDoc, t)[0]).toContain("absent from the frozen");
  });
});
