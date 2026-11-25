import { MCPServerStreamableHttp } from "@openai/agents";
import { ALLOWED_TOOLS, assertNoValueTools, pickAllowedTools, type AgentClient } from "@locksmith/agent";

/**
 * Returns a connected `MCPServerStreamableHttp` on the gateway's MCP endpoint. The agent client's authorized
 * fetch carries the token (renewed inside it) and a static filter keeps only `ALLOWED_TOOLS`; the listed
 * tools are checked again for value-shaped schemas. Pass it in `Agent({ mcpServers: [server] })`; the caller
 * closes it with `server.close()`.
 */
export async function locksmithMcpServer(client: AgentClient): Promise<MCPServerStreamableHttp> {
  const server = new MCPServerStreamableHttp({
    url: client.mcpUrl,
    name: "locksmith",
    fetch: client.authorizedFetch,
    toolFilter: { allowedToolNames: [...ALLOWED_TOOLS] },
    cacheToolsList: true,
  });
  await server.connect();
  try {
    const { kept } = pickAllowedTools(await server.listTools());
    assertNoValueTools(kept);
    return server;
  } catch (err) {
    await server.close().catch(() => undefined);
    throw err;
  }
}
