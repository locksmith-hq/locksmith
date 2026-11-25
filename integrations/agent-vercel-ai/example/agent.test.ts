// A scripted model drives generateText through the Locksmith tools: list_my_keys, relay_http_request on the
// first grant, then a final answer. JSONL transcript to LOCKSMITH_TRANSCRIPT. Mock gateway unless
// LOCKSMITH_GATEWAY_URL is set; a real model only with LOCKSMITH_LIVE=1 (and the provider key), else `skip live`.
import { spawn, type ChildProcess } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import { generateText, stepCountIs } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { afterAll, expect, it } from "vitest";
import { createAgentClient } from "@locksmith/agent";
import { locksmithTools } from "../src/index";

const MOCK = new URL("../../../tests/kit/mock_gateway.py", import.meta.url).pathname;
let mock: ChildProcess | undefined;
afterAll(() => mock?.kill());

async function gatewayUrl(): Promise<string> {
  if (process.env.LOCKSMITH_GATEWAY_URL) return process.env.LOCKSMITH_GATEWAY_URL;
  mock = spawn("python3", ["-I", MOCK], { stdio: ["ignore", "pipe", "ignore"] });
  const line: string = await new Promise((res) => mock!.stdout!.once("data", (d) => res(String(d))));
  return `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
}

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};

function scriptedModel(target: string) {
  let step = 0;
  return new MockLanguageModelV4({
    doGenerate: async (options) => {
      step += 1;
      if (step === 1) {
        return {
          content: [{ type: "tool-call", toolCallId: "c1", toolName: "list_my_keys", input: "{}" }],
          finishReason: { unified: "tool-calls", raw: undefined },
          usage,
          warnings: [],
        };
      }
      if (step === 2) {
        const seen = JSON.stringify(options.prompt);
        const id = /secret_id\\*":\\*"([^"\\]+)/.exec(seen)?.[1] ?? "unknown";
        return {
          content: [
            {
              type: "tool-call",
              toolCallId: "c2",
              toolName: "relay_http_request",
              input: JSON.stringify({ secret_id: id, version: 1, method: "GET", url: target }),
            },
          ],
          finishReason: { unified: "tool-calls", raw: undefined },
          usage,
          warnings: [],
        };
      }
      return {
        content: [{ type: "text", text: "Done: the relay call returned." }],
        finishReason: { unified: "stop", raw: undefined },
        usage,
        warnings: [],
      };
    },
  });
}

it("scripted model lists keys, relays one GET, answers", async () => {
  const transcript = process.env.LOCKSMITH_TRANSCRIPT;
  if (transcript) writeFileSync(transcript, "");
  const log = (entry: object) => transcript && appendFileSync(transcript, JSON.stringify(entry) + "\n");

  const client = createAgentClient({
    gatewayUrl: await gatewayUrl(),
    enrollmentSecret: process.env.LOCKSMITH_ENROLLMENT_SECRET ?? "example-enrollment-secret",
  });
  const lt = await locksmithTools(client);
  try {
    const target = process.env.LOCKSMITH_SMOKE_URL ?? "http://127.0.0.1:9/v1/ping";
    const result = await generateText({
      model: scriptedModel(target),
      tools: lt.tools,
      prompt: "List my keys and relay one GET.",
      stopWhen: stepCountIs(5),
    });
    for (const step of result.steps) {
      log({ step: step.stepNumber, text: step.text, toolCalls: step.toolCalls, toolResults: step.toolResults });
    }
    expect(result.steps.length).toBe(3);
    expect(result.text).toContain("Done");
    expect(JSON.stringify(result.steps[1]!.toolResults)).toContain("200");
  } finally {
    await lt.close();
    client.close();
  }
});

it.skipIf(process.env.LOCKSMITH_LIVE !== "1")("live model", async () => {
  // Needs a provider package and key; wired when the owner supplies them. `skip live` otherwise.
});
