import { spawn, type ChildProcess } from "node:child_process";
import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { AgentError, createAgentClient } from "./index";

const MOCK = new URL("../../../tests/kit/mock_gateway.py", import.meta.url).pathname;
const procs: ChildProcess[] = [];
afterEach(() => {
  for (const p of procs.splice(0)) p.kill();
});

async function start(...args: string[]): Promise<string> {
  const p = spawn("python3", ["-I", MOCK, ...args], { stdio: ["ignore", "pipe", "ignore"] });
  procs.push(p);
  const line: string = await new Promise((res) => p.stdout!.once("data", (d) => res(String(d))));
  return `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
}

describe("agent client on the mock gateway", () => {
  it("lists grants and relays", async () => {
    const url = await start();
    const c = createAgentClient({ gatewayUrl: url, enrollmentSecret: "canary-enroll-secret" });
    const grants = await c.listGrants();
    expect(grants[0]?.secret_name).toBe("stripe-test");
    const r = await c.relay({
      secretId: grants[0]!.secret_id,
      version: 1,
      method: "GET",
      url: "http://127.0.0.1:9/v1/ping",
    });
    expect(r.status).toBe(200);
    expect(c.mcpUrl).toBe(`${url}/mcp`);
  });

  it("renews a token that is about to expire", async () => {
    const url = await start("--token-ttl", "2");
    const c = createAgentClient({ gatewayUrl: url, enrollmentSecret: "canary-enroll-secret" });
    await c.listGrants();
    await new Promise((r) => setTimeout(r, 2200));
    expect((await c.listGrants()).length).toBe(1);
  });

  it("maps gateway errors to slugs", async () => {
    const url = await start("--fail", "denied");
    const c = createAgentClient({ gatewayUrl: url, token: "x" });
    await expect(c.listGrants()).rejects.toMatchObject({ slug: "denied", status: 403 });
  });

  it("refuses a foreign origin and leaks no secret", async () => {
    const url = await start();
    const c = createAgentClient({ gatewayUrl: url, enrollmentSecret: "canary-enroll-secret" });
    await expect(c.authorizedFetch("http://example.invalid/x")).rejects.toBeInstanceOf(AgentError);
    await c.listGrants();
    for (const s of [JSON.stringify(c), inspect(c, { depth: 5 })]) {
      expect(s).not.toContain("canary-enroll-secret");
      expect(s).not.toContain("canary-agent-token");
    }
  });
});
