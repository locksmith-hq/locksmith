import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { buildNestDocument, defineRoute, serialiseDocument } from "./build.js";
import { routes } from "./registry.js";

const frozen = JSON.parse(
  readFileSync(new URL("../../../../services/control-plane/openapi.json", import.meta.url), "utf8"),
);
const file = new URL("../../openapi.nest.json", import.meta.url);

// `npm run openapi:emit` sets OPENAPI_EMIT=1 to rewrite the committed document instead of checking it.
describe("openapi.nest.json", () => {
  it("equals the document generated from the zod registry", () => {
    const generated = serialiseDocument(buildNestDocument(routes, frozen));
    if (process.env.OPENAPI_EMIT) writeFileSync(file, generated);
    expect(readFileSync(file, "utf8")).toBe(generated);
  });

  it("has the Nest-only title and a trailing newline", () => {
    const text = readFileSync(file, "utf8");
    expect(text.endsWith("\n")).toBe(true);
    expect(JSON.parse(text).info.title).toBe("Locksmith API (Nest-only routes)");
  });

  it("lists a registered route that the frozen document lacks, and skips one it owns", () => {
    const fixture = defineRoute({
      method: "GET",
      path: "/v1/fixture/{id}",
      params: z.object({ id: z.string() }),
      responses: { 200: z.object({ id: z.string() }), 404: null },
    });
    const owned = defineRoute({ method: "GET", path: "/healthz", responses: { 200: null } });
    const doc = buildNestDocument([fixture, owned], frozen) as { paths: Record<string, unknown> };
    expect(Object.keys(doc.paths)).toEqual(["/v1/fixture/{id}"]);
    expect(serialiseDocument(doc)).toBe(serialiseDocument(buildNestDocument([owned, fixture], frozen)));
  });
});
