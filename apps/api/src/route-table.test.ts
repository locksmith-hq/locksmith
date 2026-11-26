import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

type Table = { routes: { method: string; path: string; owner: string }[] };

const read = (rel: string) => JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8"));

describe("route-table.json", () => {
  const table = read("../route-table.json") as Table;
  const spec = read("../../../services/control-plane/openapi.json") as {
    paths: Record<string, Record<string, unknown>>;
  };
  const methods = ["get", "post", "put", "patch", "delete", "head", "options"];
  const expected = Object.entries(spec.paths)
    .flatMap(([path, ops]) =>
      Object.keys(ops)
        .filter((m) => methods.includes(m))
        .map((m) => `${m.toUpperCase()} ${path}`),
    )
    .sort();

  it("lists exactly the operations of the frozen openapi.json", () => {
    expect(table.routes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(expected);
  });

  it("gives every route an owner of rust or nest", () => {
    for (const r of table.routes) expect(["rust", "nest"]).toContain(r.owner);
  });
});
