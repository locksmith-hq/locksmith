import { describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocksmith, LocksmithError, paginate, unwrap, VALUE_ROUTE_DENYLIST } from "./index";

const spec = JSON.parse(readFileSync(new URL("../../../services/control-plane/openapi.json", import.meta.url), "utf8"));

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": status >= 400 ? "application/problem+json" : "application/json" } });

describe("client", () => {
  it("sends the bearer token and returns typed data", async () => {
    const f = vi.fn(async (_r: Request) => json(200, []));
    const c = createLocksmith({ baseUrl: "http://cp", token: () => "tok", fetch: f as unknown as typeof fetch });
    const out = unwrap(await c.GET("/v1/agents"));
    expect(out).toEqual([]);
    expect(f.mock.calls[0]![0].headers.get("authorization")).toBe("Bearer tok");
  });

  it("returns undefined for a successful 204 instead of throwing", async () => {
    const f = async () => new Response(null, { status: 204 });
    const c = createLocksmith({ baseUrl: "http://cp", token: "t", fetch: f as unknown as typeof fetch });
    expect(unwrap(await c.DELETE("/v1/agents/{agent_id}", { params: { path: { agent_id: "a1" } } }))).toBeUndefined();
  });

  it("throws a LocksmithError carrying the problem fields on 403", async () => {
    const f = async () => json(403, { title: "Forbidden", detail: "no access", type: "about:blank" });
    const c = createLocksmith({ baseUrl: "http://cp", token: "t", fetch: f as unknown as typeof fetch });
    const err = await c.GET("/v1/agents").then(unwrap).catch((e) => e);
    expect(err).toBeInstanceOf(LocksmithError);
    expect(err.status).toBe(403);
    expect(err.message).toBe("no access");
    expect(err.problem.title).toBe("Forbidden");
  });

  it("surfaces a network error from fetch unchanged", async () => {
    const f = async () => {
      throw new TypeError("network down");
    };
    const c = createLocksmith({ baseUrl: "http://cp", token: "t", fetch: f as unknown as typeof fetch });
    await expect(c.GET("/v1/agents")).rejects.toThrow("network down");
  });

  it("pages through cursors", async () => {
    const pages = [{ items: [1], next: "c2" }, { items: [2], next: null }];
    const seen: (string | null)[] = [];
    const got: number[] = [];
    for await (const p of paginate(async (cur) => {
      seen.push(cur);
      return pages[seen.length - 1]!;
    })) got.push(...p.items);
    expect(got).toEqual([1, 2]);
    expect(seen).toEqual([null, "c2"]);
  });

  it("does not write to the console", async () => {
    const spies = (["log", "warn", "error", "info", "debug"] as const).map((m) => vi.spyOn(console, m));
    const c = createLocksmith({ baseUrl: "http://cp", token: "t", fetch: (async () => json(200, [])) as unknown as typeof fetch });
    unwrap(await c.GET("/v1/agents"));
    await c.GET("/v1/agents");
    spies.forEach((s) => expect(s).not.toHaveBeenCalled());
  });
});

describe("generated schema", () => {
  it("has no drift against the OpenAPI spec", () => {
    const dir = mkdtempSync(join(tmpdir(), "sdk-gen-"));
    const out = join(dir, "schema.d.ts");
    const bin = new URL("../node_modules/.bin/openapi-typescript", import.meta.url).pathname;
    const root = new URL("../../../node_modules/.bin/openapi-typescript", import.meta.url).pathname;
    const spec = new URL("../../../services/control-plane/openapi.json", import.meta.url).pathname;
    let tool = root;
    try { readFileSync(bin); tool = bin; } catch { /* hoisted to the root */ }
    execFileSync(tool, [spec, "-o", out], { stdio: "ignore" });
    expect(readFileSync(out, "utf8"), "schema.d.ts is stale: run `just sdk-gen`").toBe(readFileSync(new URL("./schema.d.ts", import.meta.url), "utf8"));
  });

  it("types every operationId in the spec", () => {
    const schema = readFileSync(new URL("./schema.d.ts", import.meta.url), "utf8");
    const ids: string[] = Object.values<Record<string, { operationId?: string }>>(spec.paths).flatMap((p) =>
      Object.values(p).map((op) => op.operationId).filter((x): x is string => !!x),
    );
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids) expect(schema, id).toContain(`${id}: {`);
  });

  it("exposes no plaintext value or material route", () => {
    const matching = Object.keys(spec.paths).filter((p) => /\/(value|material|plaintext)(\/|$)/.test(p));
    expect(VALUE_ROUTE_DENYLIST.length).toBeGreaterThan(0);
    // Every matching route in the spec is on the denylist, so a new one fails this test.
    for (const p of matching) expect(VALUE_ROUTE_DENYLIST as readonly string[], p).toContain(p);
    for (const p of VALUE_ROUTE_DENYLIST) expect(Object.keys(spec.paths), p).toContain(p);
  });

  it("does not type the material route on the client", () => {
    const c = createLocksmith({ baseUrl: "http://localhost", token: "t", fetch: async () => new Response("{}") });
    // @ts-expect-error the material route is not part of the SDK surface
    void c.GET("/internal/v1/secrets/{secret_id}/versions/{version}/material", {});
  });
});
