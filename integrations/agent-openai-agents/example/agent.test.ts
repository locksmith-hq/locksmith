// A scripted Model drives an Agent run through the Locksmith MCP server: list_my_keys, relay_http_request on
// the first grant, then a final answer. JSONL transcript to LOCKSMITH_TRANSCRIPT. Mock gateway unless
// LOCKSMITH_GATEWAY_URL is set; a real model only with LOCKSMITH_LIVE=1 (and the provider key), else `skip live`.
import { spawn, type ChildProcess } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import { Agent, Usage, run, setTracingDisabled, type Model, type ModelRequest } from "@openai/agents";
import { afterAll, expect, it } from "vitest";
import { createAgentClient } from "@locksmith/agent";
import { locksmithMcpServer } from "../src/index";

setTracingDisabled(true);

const MOCK = new URL("../../../tests/kit/mock_gateway.py", import.meta.url).pathname;
let mock: ChildProcess | undefined;
afterAll(() => mock?.kill());

async function gatewayUrl(): Promise<string> {
  if (process.env.LOCKSMITH_GATEWAY_URL) return process.env.LOCKSMITH_GATEWAY_URL;
  mock = spawn("python3", ["-I", MOCK], { stdio: ["ignore", "pipe", "ignore"] });
  const line: string = await new Promise((res) => mock!.stdout!.once("data", (d) => res(String(d))));
  return `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
}

function call(callId: string, name: string, args: object) {
  return {
    type: "function_call" as const,
    callId,
    name,
    arguments: JSON.stringify(args),
    status: "completed" as const,
  };
}

function scriptedModel(target: string, seenTools: string[][]): Model {
  let step = 0;
  const getResponse = async (request: ModelRequest) => {
    step += 1;
    seenTools.push(request.tools.map((t) => ("name" in t ? String(t.name) : "hosted")));
    const usage = new Usage();
    if (step === 1) return { usage, output: [call("c1", "list_my_keys", {})] };
    if (step === 2) {
      const seen = JSON.stringify(request.input);
      const id = /secret_id\\*":\\*"([^"\\]+)/.exec(seen)?.[1] ?? "unknown";
      return {
        usage,
        output: [call("c2", "relay_http_request", { secret_id: id, version: 1, method: "GET", url: target })],
      };
    }
    return {
      usage,
      output: [
        {
          type: "message" as const,
          role: "assistant" as const,
          status: "completed" as const,
          content: [{ type: "output_text" as const, text: "Done: the relay call returned." }],
        },
      ],
    };
  };
  return {
    getResponse,
    // eslint-disable-next-line require-yield
    async *getStreamedResponse() {
      throw new Error("streaming is not used in this example");
    },
  };
}

it("scripted model lists keys, relays one GET, answers", async () => {
  const transcript = process.env.LOCKSMITH_TRANSCRIPT;
  if (transcript) writeFileSync(transcript, "");
  const log = (entry: object) => transcript && appendFileSync(transcript, JSON.stringify(entry) + "\n");

  const client = createAgentClient({
    gatewayUrl: await gatewayUrl(),
    enrollmentSecret: process.env.LOCKSMITH_ENROLLMENT_SECRET ?? "example-enrollment-secret",
  });
  const server = await locksmithMcpServer(client);
  try {
    const target = process.env.LOCKSMITH_SMOKE_URL ?? "http://127.0.0.1:9/v1/ping";
    const seenTools: string[][] = [];
    const agent = new Agent({
      name: "locksmith-example",
      instructions: "Use the Locksmith tools.",
      model: scriptedModel(target, seenTools),
      mcpServers: [server],
    });
    const result = await run(agent, "List my keys and relay one GET.");
    for (const item of result.newItems) log({ type: item.type, item: item.rawItem });
    expect(result.finalOutput).toContain("Done");
    expect(JSON.stringify(result.newItems)).toContain("200");
    expect([...seenTools[0]!].sort()).toEqual(["explain_block", "list_my_keys", "relay_http_request"]);
  } finally {
    await server.close();
    client.close();
  }
});

it.skipIf(process.env.LOCKSMITH_LIVE !== "1")("live model", async () => {
  // Needs a provider key; wired when the owner supplies it. `skip live` otherwise.
});
