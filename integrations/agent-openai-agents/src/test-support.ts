import { Agent, Usage, run, type MCPServerStreamableHttp, type Model } from "@openai/agents";

/** Names of the tools an agent run offers the model on its first request. */
export async function offeredTools(server: MCPServerStreamableHttp): Promise<string[]> {
  let names: string[] = [];
  const model: Model = {
    async getResponse(request) {
      names = request.tools.map((t) => ("name" in t ? String(t.name) : "hosted")).sort();
      return {
        usage: new Usage(),
        output: [
          {
            type: "message",
            role: "assistant",
            status: "completed",
            content: [{ type: "output_text", text: "ok" }],
          },
        ],
      };
    },
    // eslint-disable-next-line require-yield
    async *getStreamedResponse() {
      throw new Error("not used");
    },
  };
  await run(new Agent({ name: "t", model, mcpServers: [server] }), "hi");
  return names;
}
