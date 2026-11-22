import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "./index";
import { agentSessions, agentsPaused, agentsResumed, mcpClients, mcpToolSettings } from "./fixtures";

const B = "http://cp.test";
const json = (body: unknown, status = 200) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));

afterEach(() => vi.unstubAllGlobals());

test("listMcpTools unwraps items and sends the org header", async () => {
  const f = vi.fn().mockReturnValue(json({ items: mcpToolSettings }));
  vi.stubGlobal("fetch", f);
  expect(await createClient("org1", B).listMcpTools()).toEqual(mcpToolSettings);
  const [url, init] = f.mock.calls[0] as [string, RequestInit];
  expect(url).toBe(`${B}/v1/mcp/tools`);
  const h = init.headers as Record<string, string>;
  expect(h["x-locksmith-dev-org"]).toBe("org1");
  expect(h.authorization).toBeUndefined();
  expect(init.cache).toBe("no-store");
});

test("setMcpTool PUTs the switch and returns the tool", async () => {
  const f = vi.fn().mockReturnValue(json({ ...mcpToolSettings[1], enabled: false, overridden: false }));
  vi.stubGlobal("fetch", f);
  const t = await createClient("org1", B).setMcpTool("hub", "revoke_grant", false);
  expect(t.enabled).toBe(false);
  const [url, init] = f.mock.calls[0] as [string, RequestInit];
  expect(url).toBe(`${B}/v1/mcp/tools/hub/revoke_grant`);
  expect(init.method).toBe("PUT");
  expect(init.body).toBe(JSON.stringify({ enabled: false }));
});

test("listMcpClients follows cursors", async () => {
  const f = vi
    .fn()
    .mockReturnValueOnce(json({ items: [mcpClients[0]], next: "c1" }))
    .mockReturnValueOnce(json({ items: [mcpClients[1]] }));
  vi.stubGlobal("fetch", f);
  expect(await createClient("org1", B).listMcpClients()).toEqual(mcpClients);
  expect(f.mock.calls[1]?.[0]).toBe(`${B}/v1/mcp/clients?cursor=c1`);
});

test("revokeMcpClient POSTs to the revoke path; a 403 surfaces as ApiError", async () => {
  const f = vi.fn().mockReturnValueOnce(json(mcpClients[1])).mockReturnValueOnce(json({ title: "Forbidden", detail: "no" }, 403));
  vi.stubGlobal("fetch", f);
  const c = createClient("org1", B);
  expect((await c.revokeMcpClient("abc")).revoked_at).toBeDefined();
  expect(f.mock.calls[0]?.[0]).toBe(`${B}/v1/mcp/clients/abc/revoke`);
  expect((f.mock.calls[0]?.[1] as RequestInit).method).toBe("POST");
  await expect(c.revokeMcpClient("abc")).rejects.toMatchObject({ name: "ApiError", status: 403, message: "no" });
});

test("listSessions follows cursors", async () => {
  const f = vi
    .fn()
    .mockReturnValueOnce(json({ items: [agentSessions[0]], next: "c1" }))
    .mockReturnValueOnce(json({ items: agentSessions.slice(1) }));
  vi.stubGlobal("fetch", f);
  expect(await createClient("org1", B).listSessions()).toEqual(agentSessions);
  expect(f.mock.calls[0]?.[0]).toBe(`${B}/v1/sessions`);
  expect(f.mock.calls[1]?.[0]).toBe(`${B}/v1/sessions?cursor=c1`);
});

test("revokeSession POSTs to the revoke path; a 403 surfaces as ApiError", async () => {
  const f = vi.fn().mockReturnValueOnce(json(agentSessions[1])).mockReturnValueOnce(json({ title: "Forbidden", detail: "no" }, 403));
  vi.stubGlobal("fetch", f);
  const c = createClient("org1", B);
  expect((await c.revokeSession("s1")).id).toBe(agentSessions[1]?.id);
  expect(f.mock.calls[0]?.[0]).toBe(`${B}/v1/sessions/s1/revoke`);
  expect((f.mock.calls[0]?.[1] as RequestInit).method).toBe("POST");
  await expect(c.revokeSession("s1")).rejects.toMatchObject({ name: "ApiError", status: 403, message: "no" });
});

test("revokeAllSessions POSTs to revoke-all and returns the count", async () => {
  const f = vi.fn().mockReturnValue(json({ revoked: 2 }));
  vi.stubGlobal("fetch", f);
  expect(await createClient("org1", B).revokeAllSessions()).toEqual({ revoked: 2 });
  expect(f.mock.calls[0]?.[0]).toBe(`${B}/v1/sessions/revoke-all`);
  expect((f.mock.calls[0]?.[1] as RequestInit).method).toBe("POST");
});

test("pauseAgents and resumeAgents POST to the org pause paths", async () => {
  const f = vi.fn().mockReturnValueOnce(json(agentsPaused)).mockReturnValueOnce(json(agentsResumed));
  vi.stubGlobal("fetch", f);
  const c = createClient("org1", B);
  expect(await c.pauseAgents()).toEqual(agentsPaused);
  expect(await c.resumeAgents()).toEqual(agentsResumed);
  expect(f.mock.calls[0]?.[0]).toBe(`${B}/v1/orgs/current/agents/pause`);
  expect(f.mock.calls[1]?.[0]).toBe(`${B}/v1/orgs/current/agents/resume`);
});

test("a 501 from a not-yet-built route surfaces as ApiError", async () => {
  vi.stubGlobal("fetch", vi.fn().mockReturnValue(json({ title: "Not implemented", status: 501 }, 501)));
  await expect(createClient("org1", B).listSessions()).rejects.toMatchObject({ name: "ApiError", status: 501 });
});

test("fixtures carry no token or value fields", () => {
  for (const o of [...mcpToolSettings, ...mcpClients, ...agentSessions, agentsPaused]) {
    for (const k of Object.keys(o)) expect(k).not.toMatch(/value|token|secret|password|key$/i);
  }
});

test("a bearer token replaces the dev org header", async () => {
  const f = vi.fn().mockReturnValue(json({ items: [] }));
  vi.stubGlobal("fetch", f);
  await createClient("org1", B, () => "tok").listMcpTools();
  const h = (f.mock.calls[0]?.[1] as RequestInit).headers as Record<string, string>;
  expect(h.authorization).toBe("Bearer tok");
  expect(h["x-locksmith-dev-org"]).toBeUndefined();
});

test("204 deletes resolve to undefined", async () => {
  vi.stubGlobal("fetch", vi.fn().mockReturnValue(Promise.resolve(new Response(null, { status: 204 }))));
  await expect(createClient("org1", B).deleteAgent("a/b")).resolves.toBeUndefined();
});

test("the enrollment secret lives only in the returned object: no console output, no storage", async () => {
  const SECRET = ["fake", "enrollment", "value"].join("-");
  const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) => vi.spyOn(console, m));
  const setItem = vi.fn();
  vi.stubGlobal("localStorage", { setItem });
  vi.stubGlobal("sessionStorage", { setItem });
  vi.stubGlobal("fetch", vi.fn().mockReturnValue(json({ agent: { id: "a1" }, enrollment_secret: SECRET })));
  const c = createClient("org1", B);
  const out = (await c.createAgent({ name: "x" } as never)) as unknown as Record<string, unknown>;
  expect(JSON.stringify(out)).toContain(SECRET);
  for (const s of spies) expect(s).not.toHaveBeenCalled();
  expect(setItem).not.toHaveBeenCalled();
  // a second call does not return it from any cache
  vi.stubGlobal("fetch", vi.fn().mockReturnValue(json({ items: [] })));
  expect(JSON.stringify(await c.listAgents())).not.toContain(SECRET);
});

test("a relative base URL fetches the path on the page's own origin", async () => {
  const f = vi.fn().mockReturnValue(json({ items: [] }));
  vi.stubGlobal("fetch", f);
  await createClient("org1").listMcpClients();
  expect(f.mock.calls[0]?.[0]).toBe("/v1/mcp/clients");
});
