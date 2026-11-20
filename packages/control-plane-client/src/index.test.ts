import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "./index";
import { mcpClients, mcpToolSettings } from "./fixtures";

const json = (body: unknown, status = 200) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));

afterEach(() => vi.unstubAllGlobals());

test("listMcpTools unwraps items and sends the org header", async () => {
  const f = vi.fn().mockReturnValue(json({ items: mcpToolSettings }));
  vi.stubGlobal("fetch", f);
  expect(await createClient("org1").listMcpTools()).toEqual(mcpToolSettings);
  const [url, init] = f.mock.calls[0] as [string, RequestInit];
  expect(url).toBe("/v1/mcp/tools");
  expect((init.headers as Record<string, string>)["x-locksmith-dev-org"]).toBe("org1");
});

test("setMcpTool PUTs the switch and returns the tool", async () => {
  const f = vi.fn().mockReturnValue(json({ ...mcpToolSettings[1], enabled: false, overridden: false }));
  vi.stubGlobal("fetch", f);
  const t = await createClient("org1").setMcpTool("hub", "revoke_grant", false);
  expect(t.enabled).toBe(false);
  const [url, init] = f.mock.calls[0] as [string, RequestInit];
  expect(url).toBe("/v1/mcp/tools/hub/revoke_grant");
  expect(init.method).toBe("PUT");
  expect(init.body).toBe(JSON.stringify({ enabled: false }));
});

test("listMcpClients follows cursors", async () => {
  const f = vi
    .fn()
    .mockReturnValueOnce(json({ items: [mcpClients[0]], next: "c1" }))
    .mockReturnValueOnce(json({ items: [mcpClients[1]] }));
  vi.stubGlobal("fetch", f);
  expect(await createClient("org1").listMcpClients()).toEqual(mcpClients);
  expect(f.mock.calls[1]?.[0]).toBe("/v1/mcp/clients?cursor=c1");
});

test("revokeMcpClient POSTs to the revoke path; a 403 surfaces as ApiError", async () => {
  const f = vi.fn().mockReturnValueOnce(json(mcpClients[1])).mockReturnValueOnce(json({ title: "Forbidden", detail: "no" }, 403));
  vi.stubGlobal("fetch", f);
  const c = createClient("org1");
  expect((await c.revokeMcpClient("abc")).revoked_at).toBeDefined();
  expect(f.mock.calls[0]?.[0]).toBe("/v1/mcp/clients/abc/revoke");
  expect((f.mock.calls[0]?.[1] as RequestInit).method).toBe("POST");
  await expect(c.revokeMcpClient("abc")).rejects.toMatchObject({ status: 403, message: "no" });
});

test("fixtures carry no token or value fields", () => {
  for (const o of [...mcpToolSettings, ...mcpClients]) {
    for (const k of Object.keys(o)) expect(k).not.toMatch(/value|token|secret|password|key$/i);
  }
});
