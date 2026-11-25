import { createMCPClient } from "@ai-sdk/mcp";
import { assertNoValueTools, pickAllowedTools, type AgentClient } from "@locksmith/agent";

type McpClient = Awaited<ReturnType<typeof createMCPClient>>;

export interface LocksmithTools {
  /** The AI SDK tool set: `list_my_keys`, `relay_http_request` and `explain_block` only. */
  tools: Awaited<ReturnType<McpClient["tools"]>>;
  /** Names of the gateway tools that were left out; names only. */
  dropped: string[];
  /** Ends the MCP session. */
  close(): Promise<void>;
}

/**
 * Opens the AI SDK MCP client on the gateway over Streamable HTTP with the agent client's authorized
 * fetch (the token renews inside it) and returns only the allowed tools.
 */
export async function locksmithTools(client: AgentClient): Promise<LocksmithTools> {
  const mcp = await createMCPClient({
    transport: { type: "http", url: client.mcpUrl, fetch: client.authorizedFetch },
  });
  try {
    const listed = await mcp.listTools();
    const { kept, dropped } = pickAllowedTools(listed.tools);
    assertNoValueTools(kept);
    const tools = mcp.toolsFromDefinitions({ ...listed, tools: kept });
    return { tools, dropped, close: () => mcp.close() };
  } catch (err) {
    await mcp.close().catch(() => undefined);
    throw err;
  }
}
