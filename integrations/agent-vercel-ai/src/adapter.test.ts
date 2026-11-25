import { spawn, type ChildProcess } from "node:child_process";
import { afterAll, afterEach, expect, it } from "vitest";
import { createAgentClient } from "@locksmith/agent";
import { locksmithTools } from "./adapter";

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

it("exposes exactly the allowed tools", async () => {
  const gatewayUrl = await startMock();
  const client = createAgentClient({ gatewayUrl, enrollmentSecret: "canary-enrol" });
  const t = await locksmithTools(client);
  closers.push(
    () => t.close(),
    () => client.close(),
  );
  expect(Object.keys(t.tools).sort()).toEqual(["explain_block", "list_my_keys", "relay_http_request"]);
});

it("a relay call reaches the mock with the token", async () => {
  const gatewayUrl = await startMock();
  const client = createAgentClient({ gatewayUrl, enrollmentSecret: "canary-enrol" });
  const t = await locksmithTools(client);
  closers.push(
    () => t.close(),
    () => client.close(),
  );
  const keys = (await t.tools.list_my_keys!.execute!({}, { toolCallId: "1", messages: [], context: {} })) as unknown;
  expect(JSON.stringify(keys)).toContain("secret_id");
  const out = await t.tools.relay_http_request!.execute!(
    { secret_id: "sec_1", version: 1, method: "GET", url: "http://127.0.0.1:9/v1/ping" },
    { toolCallId: "2", messages: [], context: {} },
  );
  expect(JSON.stringify(out)).toContain("200");
});

it("uses a renewed token after expiry", async () => {
  const gatewayUrl = await startMock("--token-ttl", "2");
  const client = createAgentClient({ gatewayUrl, enrollmentSecret: "canary-enrol" });
  const t = await locksmithTools(client);
  closers.push(
    () => t.close(),
    () => client.close(),
  );
  await new Promise((r) => setTimeout(r, 2500));
  const out = await t.tools.list_my_keys!.execute!({}, { toolCallId: "3", messages: [], context: {} });
  expect(JSON.stringify(out)).toContain("secret_id");
});
