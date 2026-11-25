import { spawn, type ChildProcess } from "node:child_process";
import { setTracingDisabled } from "@openai/agents";
import { afterAll, afterEach, expect, it } from "vitest";
import { createAgentClient } from "@locksmith/agent";
import { locksmithMcpServer } from "./adapter";
import { offeredTools } from "./test-support";

setTracingDisabled(true);

const MOCK = new URL("../../../tests/kit/mock_gateway.py", import.meta.url).pathname;
const procs: ChildProcess[] = [];
afterAll(() => procs.forEach((p) => p.kill()));

async function startMock(...args: string[]): Promise<string> {
  const p = spawn("python3", ["-I", MOCK, ...args], { stdio: ["ignore", "pipe", "ignore"] });
  procs.push(p);
  const line: string = await new Promise((res) => p.stdout!.once("data", (d) => res(String(d))));
  return `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
}

const closers: Array<() => unknown> = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

async function open(...mockArgs: string[]) {
  const gatewayUrl = await startMock(...mockArgs);
  const client = createAgentClient({ gatewayUrl, enrollmentSecret: "canary-enrol" });
  const server = await locksmithMcpServer(client);
  closers.push(
    () => server.close(),
    () => client.close(),
  );
  return server;
}

it("exposes exactly the allowed tools", async () => {
  const server = await open();
  expect(await offeredTools(server)).toEqual(["explain_block", "list_my_keys", "relay_http_request"]);
});

it("a relay call reaches the mock with the token", async () => {
  const server = await open();
  expect(JSON.stringify(await server.callTool("list_my_keys", {}))).toContain("secret_id");
  const out = await server.callTool("relay_http_request", {
    secret_id: "sec_1",
    version: 1,
    method: "GET",
    url: "http://127.0.0.1:9/v1/ping",
  });
  expect(JSON.stringify(out)).toContain("200");
});

it("uses a renewed token after expiry", async () => {
  const server = await open("--token-ttl", "2");
  await new Promise((r) => setTimeout(r, 2500));
  expect(JSON.stringify(await server.callTool("list_my_keys", {}))).toContain("secret_id");
});
