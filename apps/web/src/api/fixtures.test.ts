import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, createClient } from "@locksmith/control-plane-client";
import { installFixtureFetch } from "./fixtures";
import { withUnauthorizedHandler } from "./client";

afterEach(() => vi.unstubAllGlobals());

describe("fixtures", () => {
  it("serve the console routes and never a value or material route", async () => {
    const fx = installFixtureFetch();
    const c = createClient("o");
    const [p] = await c.listProjects();
    const [e] = await c.listEnvironments(p!.id);
    const [s] = await c.listSecrets(p!.id, e!.id);
    expect((await c.listSecretVersions(p!.id, e!.id, s!.id)).length).toBe(2);
    await c.createProject({ name: "new" });
    expect(fx.requests.some((r) => /material|value/.test(r))).toBe(false);
  });

  it("serve agent, grant, MCP and org routes", async () => {
    installFixtureFetch();
    const c = createClient("o");
    const { agent } = await c.createAgent({ name: "bot" });
    expect((await c.listAgents()).length).toBe(1);
    await c.rotateEnrollment(agent.id);
    const g = await c.createGrant(agent.id, { mode: "relay" } as never);
    expect((await c.listGrants(agent.id)).length).toBe(1);
    await c.revokeGrant(agent.id, g.id);
    expect((await c.listGrants(agent.id)).length).toBe(0);
    await c.deleteAgent(agent.id);
    expect(await c.listAgents()).toEqual([]);
    const [t] = await c.listMcpTools();
    expect((await c.setMcpTool(t!.layer, t!.tool, false)).enabled).toBe(false);
    const [mc] = await c.listMcpClients();
    expect((await c.revokeMcpClient(mc!.id)).revoked_at).toBeTruthy();
    expect((await c.getOrg("o")).id).toBe("o");
  });

  it("can return 409, 403 and empty lists", async () => {
    installFixtureFetch({ fail: { "POST /v1/projects": 409, "GET /v1/agents": 403 } });
    const c = createClient("o");
    await expect(c.createProject({ name: "x" })).rejects.toMatchObject({ status: 409 });
    await expect(c.listAgents()).rejects.toMatchObject({ status: 403 });
    installFixtureFetch({ empty: true });
    expect(await createClient("o").listProjects()).toEqual([]);
  });

  it("maps 401 to sign-out", async () => {
    installFixtureFetch({ fail: { "GET /v1/projects": 401 } });
    const out = vi.fn();
    const c = withUnauthorizedHandler(createClient("o"), out);
    await expect(c.listProjects()).rejects.toBeInstanceOf(ApiError);
    expect(out).toHaveBeenCalledOnce();
  });
});
