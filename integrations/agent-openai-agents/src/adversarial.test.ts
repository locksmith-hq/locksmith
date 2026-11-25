import { spawn, type ChildProcess } from "node:child_process";
import { afterAll, expect, it, vi } from "vitest";
import { createAgentClient, type AgentClient } from "@locksmith/agent";
import { locksmithMcpServer } from "./adapter";
import { offeredTools } from "./test-support";

const MOCK = new URL("../../../tests/kit/mock_gateway.py", import.meta.url).pathname;
let mock: ChildProcess | undefined;
afterAll(() => mock?.kill());

it("with --tools unsafe the dangerous tools are not exposed", async () => {
  mock = spawn("python3", ["-I", MOCK, "--tools", "unsafe"], { stdio: ["ignore", "pipe", "ignore"] });
  const line: string = await new Promise((res) => mock!.stdout!.once("data", (d) => res(String(d))));
  const gatewayUrl = `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
  const client = createAgentClient({ gatewayUrl, enrollmentSecret: "canary-enrol-secret" });
  const server = await locksmithMcpServer(client);
  try {
    const names = await offeredTools(server);
    expect(names).toEqual(["explain_block", "list_my_keys", "relay_http_request"]);
    expect(names).not.toContain("issue_short_lived_credential");
    expect(names).not.toContain("get_secret_value");
    expect(JSON.stringify(names)).not.toContain("canary-enrol-secret");
  } finally {
    await server.close();
    client.close();
  }
});

it("a kept tool with a value-shaped schema throws unsafe_tool and closes the session", async () => {
  const close = vi.fn(async () => undefined);
  class Stub {
    connect = async () => undefined;
    close = close;
    listTools = async () => [
      { name: "list_my_keys", inputSchema: { type: "object" } },
      {
        name: "relay_http_request",
        inputSchema: { type: "object" },
        outputSchema: { type: "object", properties: { secret_value: { type: "string" } } },
      },
    ];
  }
  vi.resetModules();
  vi.doMock("@openai/agents", () => ({ MCPServerStreamableHttp: Stub }));
  const { locksmithMcpServer: guarded } = await import("./adapter");
  const fake = { mcpUrl: "http://127.0.0.1:1/mcp", authorizedFetch: fetch } as unknown as AgentClient;
  await expect(guarded(fake)).rejects.toMatchObject({ slug: "unsafe_tool" });
  expect(close).toHaveBeenCalled();
});
