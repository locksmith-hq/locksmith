import { MultiServerMCPClient } from "@langchain/mcp-adapters";
import { assertNoValueTools, pickAllowedTools, type AgentClient } from "@locksmith/agent";

type McpTools = Awaited<ReturnType<MultiServerMCPClient["getTools"]>>;

export interface LocksmithTools {
  /** LangChain tools: `list_my_keys`, `relay_http_request` and `explain_block` only. */
  tools: McpTools;
  /** Names of the gateway tools that were left out; names only. */
  dropped: string[];
  /** Ends the MCP session. */
  close(): Promise<void>;
}

/**
 * Loads the Agent MCP tools with `MultiServerMCPClient` over Streamable HTTP. The token comes from an
 * `authProvider` that the MCP transport asks before every request, so it renews; only allowed tools return.
 */
export async function locksmithTools(client: AgentClient): Promise<LocksmithTools> {
  const mcp = new MultiServerMCPClient({
    prefixToolNameWithServerName: false,
    mcpServers: {
      locksmith: {
        transport: "http",
        url: client.mcpUrl,
        authProvider: {
          token: () => client.bearerToken(),
          onUnauthorized: async () => {
            await client.bearerToken(true);
          },
        },
      },
    },
  });
  try {
    const all = await mcp.getTools();
    const { kept, dropped } = pickAllowedTools(all.map((t) => ({ name: t.name, inputSchema: t.schema })));
    const names = new Set(kept.map((t) => t.name));
    const tools = all.filter((t) => names.has(t.name));
    assertNoValueTools(kept);
    return { tools, dropped, close: () => mcp.close() };
  } catch (err) {
    await mcp.close().catch(() => undefined);
    throw err;
  }
}
