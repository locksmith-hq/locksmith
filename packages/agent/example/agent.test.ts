// The client alone: list grants, relay one GET, write a JSONL transcript. Uses the mock gateway
// unless LOCKSMITH_GATEWAY_URL is set (then the live stack, as `just agent-smoke client` runs it).
import { spawn, type ChildProcess } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import { afterAll, expect, it } from "vitest";
import { createAgentClient } from "../src/index";

const MOCK = new URL("../../../tests/kit/mock_gateway.py", import.meta.url).pathname;
let mock: ChildProcess | undefined;
afterAll(() => mock?.kill());

async function gatewayUrl(): Promise<string> {
  if (process.env.LOCKSMITH_GATEWAY_URL) return process.env.LOCKSMITH_GATEWAY_URL;
  mock = spawn("python3", ["-I", MOCK], { stdio: ["ignore", "pipe", "ignore"] });
  const line: string = await new Promise((res) => mock!.stdout!.once("data", (d) => res(String(d))));
  return `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
}

it("lists grants and relays one GET", async () => {
  const transcript = process.env.LOCKSMITH_TRANSCRIPT;
  if (transcript) writeFileSync(transcript, "");
  const log = (entry: object) => transcript && appendFileSync(transcript, JSON.stringify(entry) + "\n");

  const client = createAgentClient({
    gatewayUrl: await gatewayUrl(),
    enrollmentSecret: process.env.LOCKSMITH_ENROLLMENT_SECRET ?? "example-enrollment-secret",
  });
  const grants = await client.listGrants();
  log({ step: "listGrants", grants });
  expect(grants.length).toBeGreaterThan(0);

  const target = process.env.LOCKSMITH_SMOKE_URL ?? "http://127.0.0.1:9/v1/ping";
  const res = await client.relay({ secretId: grants[0]!.secret_id, version: 1, method: "GET", url: target });
  log({ step: "relay", url: target, status: res.status });
  expect(res.status).toBe(200);
  client.close();
});
