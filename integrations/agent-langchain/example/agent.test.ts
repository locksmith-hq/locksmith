// A scripted chat model drives the LangGraph.js prebuilt ReAct agent through the Locksmith tools:
// list_my_keys, relay_http_request on the first grant, then a final answer. JSONL transcript to
// LOCKSMITH_TRANSCRIPT. Mock gateway unless LOCKSMITH_GATEWAY_URL is set; a real model only with
// LOCKSMITH_LIVE=1 (and the provider key), else `skip live`.
import { spawn, type ChildProcess } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import { AIMessage, HumanMessage, type BaseMessage } from "@langchain/core/messages";
import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import type { ChatResult } from "@langchain/core/outputs";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
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

/** Scripted chat model: list keys, relay one GET on the first grant, answer. */
class ScriptedModel extends BaseChatModel {
  private step = 0;
  constructor(private readonly target: string) {
    super({});
  }
  _llmType(): string {
    return "scripted";
  }
  override bindTools(): this {
    return this;
  }
  async _generate(messages: BaseMessage[]): Promise<ChatResult> {
    this.step += 1;
    let message: AIMessage;
    if (this.step === 1) {
      message = new AIMessage({ content: "", tool_calls: [{ id: "c1", name: "list_my_keys", args: {} }] });
    } else if (this.step === 2) {
      const seen = JSON.stringify(messages.map((m) => m.content));
      const id = /secret_id\\*":\s*\\*"([0-9a-f-]{36})/.exec(seen)?.[1] ?? "unknown";
      message = new AIMessage({
        content: "",
        tool_calls: [
          {
            id: "c2",
            name: "relay_http_request",
            args: { secret_id: id, version: 1, method: "GET", url: this.target },
          },
        ],
      });
    } else {
      message = new AIMessage("Done: the relay call returned.");
    }
    return { generations: [{ text: String(message.content), message }] };
  }
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
    const agent = createReactAgent({ llm: new ScriptedModel(target), tools: lt.tools });
    const result = await agent.invoke({ messages: [new HumanMessage("List my keys and relay one GET.")] });
    for (const m of result.messages) {
      log({ type: m.getType(), content: m.content, toolCalls: (m as AIMessage).tool_calls ?? [] });
    }
    const tools = result.messages.filter((m) => m.getType() === "tool");
    expect(tools.length).toBe(2);
    expect(JSON.stringify(tools[1]!.content)).toContain("200");
    expect(String(result.messages.at(-1)!.content)).toContain("Done");
  } finally {
    await lt.close();
    client.close();
  }
});

it.skipIf(process.env.LOCKSMITH_LIVE !== "1")("live model", async () => {
  // Needs a provider package and key; wired when the owner supplies them. `skip live` otherwise.
});
