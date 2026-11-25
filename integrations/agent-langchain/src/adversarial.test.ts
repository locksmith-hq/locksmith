import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterAll, expect, it, vi } from "vitest";
import { createAgentClient, type AgentClient } from "@locksmith/agent";
import { locksmithTools } from "./adapter";

const MOCK = new URL("../../../tests/kit/mock_gateway.py", import.meta.url).pathname;
function scanTranscript(entries: unknown[]): void {
  const dir = mkdtempSync(join(tmpdir(), "adv-"));
  const transcript = join(dir, "transcript.jsonl");
  writeFileSync(transcript, entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
  const canaries = join(dir, "canaries");
  writeFileSync(canaries, ENROL + "\n");
  const oracle = new URL("../../../tests/kit/oracle.py", import.meta.url).pathname;
  const scan = spawnSync("python3", ["-I", oracle, "scan", "--canary-file", canaries, "--transcript", transcript]);
  expect(scan.status, String(scan.stdout)).toBe(0);
}

const ENROL = randomBytes(32).toString("base64url");
let mock: ChildProcess | undefined;
afterAll(() => mock?.kill());

it("with --tools unsafe the dangerous tools are not exposed", async () => {
  mock = spawn("python3", ["-I", MOCK, "--tools", "unsafe"], { stdio: ["ignore", "pipe", "ignore"] });
  const line: string = await new Promise((res) => mock!.stdout!.once("data", (d) => res(String(d))));
  const gatewayUrl = `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
  const client = createAgentClient({ gatewayUrl, enrollmentSecret: ENROL });
  const t = await locksmithTools(client);
  try {
    const names = t.tools.map((x) => x.name);
    expect(names).not.toContain("issue_short_lived_credential");
    expect(names).not.toContain("get_secret_value");
    expect(t.dropped.sort()).toEqual(expect.arrayContaining(["get_secret_value", "issue_short_lived_credential"]));
    expect(JSON.stringify({ names, dropped: t.dropped })).not.toContain(ENROL);
    const call = (n: string, a: object) => t.tools.find((x) => x.name === n)!.invoke(a);
    const keys = await call("list_my_keys", {});
    const out = await call("relay_http_request", {
      secret_id: "00000000-0000-4000-8000-000000000001",
      version: 1,
      method: "GET",
      url: "http://127.0.0.1:9/v1/ping",
    });
    scanTranscript([{ names, dropped: t.dropped }, keys, out]);
  } finally {
    await t.close();
    client.close();
  }
});

it("a kept tool with a value-shaped schema throws unsafe_tool and closes the session", async () => {
  const close = vi.fn(async () => undefined);
  class Stub {
    getTools = async () => [
      { name: "list_my_keys", schema: { type: "object" } },
      {
        name: "relay_http_request",
        schema: { type: "object", properties: { secret_value: { type: "string" } } },
      },
    ];
    close = close;
  }
  vi.resetModules();
  vi.doMock("@langchain/mcp-adapters", () => ({ MultiServerMCPClient: Stub }));
  const { locksmithTools: guarded } = await import("./adapter");
  const fake = { mcpUrl: "http://127.0.0.1:1/mcp", bearerToken: async () => "t" } as unknown as AgentClient;
  await expect(guarded(fake)).rejects.toMatchObject({ slug: "unsafe_tool" });
  expect(close).toHaveBeenCalled();
});
