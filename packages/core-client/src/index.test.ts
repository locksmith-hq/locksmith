import { readFileSync } from "node:fs";
import openapiTS, { astToString } from "openapi-typescript";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CoreError, createCoreClient } from "./index";
import { fixtures, fixtureIds, unauthorized } from "./fixtures";

const specUrl = new URL("../../../services/core/openapi.json", import.meta.url);
const spec = JSON.parse(readFileSync(specUrl, "utf8")) as {
  paths: Record<string, Record<string, { operationId: string }>>;
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
afterEach(() => vi.unstubAllGlobals());

describe("contract drift", () => {
  it("src/schema.d.ts equals what openapi.json generates (run `npm run gen` to fix)", async () => {
    const generated = astToString(await openapiTS(specUrl));
    const committed = readFileSync(new URL("./schema.d.ts", import.meta.url), "utf8");
    // openapi-typescript's CLI prefixes a banner and ends with a newline; the body must match.
    expect(committed.trim().endsWith(generated.trim())).toBe(true);
  });

  const ops = Object.values(spec.paths).flatMap((p) => Object.values(p).map((o) => o.operationId));
  it("has exactly the eight OC-9 G1 operations plus the two B1-5 enrollment ones", () => {
    expect([...ops].sort()).toEqual([
      "appendAuditEvent", "generateEnrollmentSecret", "mintAgentToken", "mintWorkloadToken",
      "signAuditCheckpoint", "unwrapDek", "verifyAgentToken", "verifyEnrollmentSecret",
      "verifyWorkloadToken", "wrapDek",
    ]);
  });
  it("has a fixture and a client method for every operation", () => {
    const client = createCoreClient({ baseUrl: "http://x", token: "t" });
    for (const id of ops) {
      expect(fixtures).toHaveProperty(id);
      expect(typeof (client as unknown as Record<string, unknown>)[id]).toBe("function");
    }
  });
  it("declares no field that could carry plaintext or key bytes", () => {
    const names = [...JSON.stringify(spec).matchAll(/"([a-z_]+)":\s*\{/g)].map((m) => m[1]);
    for (const bad of ["plaintext", "dek", "key", "key_bytes", "secret_value", "value", "private_key"]) expect(names).not.toContain(bad);
  });
});

describe("core client", () => {
  it("posts to the right path with the bearer token and returns the fixture", async () => {
    const f = vi.fn().mockImplementation(async () => json(fixtures.wrapDek));
    const c = createCoreClient({ baseUrl: "http://core", token: () => "svc", fetch: f });
    const out = await c.wrapDek({ binding: { org_id: fixtureIds.org, secret_id: fixtureIds.agent, version: 1, purpose: "dek_wrap" } });
    expect(out).toEqual(fixtures.wrapDek);
    const req = f.mock.calls[0]![0] as Request;
    expect(req.url).toBe("http://core/v1/deks/wrap");
    expect(req.headers.get("authorization")).toBe("Bearer svc");
  });
  it("generates and verifies enrollment secrets without sending the secret back on verify", async () => {
    const f = vi.fn()
      .mockImplementationOnce(async () => json(fixtures.generateEnrollmentSecret))
      .mockImplementationOnce(async () => json(fixtures.verifyEnrollmentSecret));
    const c = createCoreClient({ baseUrl: "http://core", token: "svc", fetch: f });
    const g = await c.generateEnrollmentSecret({ org_id: fixtureIds.org, agent_id: fixtureIds.agent });
    expect(g).toEqual(fixtures.generateEnrollmentSecret);
    const v = await c.verifyEnrollmentSecret({ enrollment_secret: g.enrollment_secret, enrollment_hash: null });
    expect(v).toEqual(fixtures.verifyEnrollmentSecret);
    const [gen, ver] = f.mock.calls.map((call) => call[0] as Request);
    expect(gen!.url).toBe("http://core/v1/enrollment-secrets/generate");
    expect(ver!.url).toBe("http://core/v1/enrollment-secrets/verify");
    expect(await ver!.json()).toEqual({ enrollment_secret: g.enrollment_secret, enrollment_hash: null });
    expect(JSON.stringify(v)).not.toContain("lse_");
  });
  it("throws CoreError with the problem on 401", async () => {
    const f = vi.fn().mockImplementation(async () => json(unauthorized, 401));
    const c = createCoreClient({ baseUrl: "http://core", token: "bad", fetch: f });
    await expect(c.verifyAgentToken({ token: "x" })).rejects.toMatchObject({ name: "CoreError", status: 401 });
    await expect(c.verifyAgentToken({ token: "x" })).rejects.toBeInstanceOf(CoreError);
  });
});
