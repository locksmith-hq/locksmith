import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "./index";
import { agentSessions, agentsPaused, agentsResumed } from "./fixtures";

const B = "http://cp.test";
const json = (body: unknown, status = 200) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));

afterEach(() => vi.unstubAllGlobals());

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
