#!/usr/bin/env node
// MCP server for the Locksmith design system, over stdio. It answers from the source in this repository, so
// what an agent reads is what is in the tree. See the design-system-mcp skill for how to set it up.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { getComponent, getGuide, getTokens, listComponents } from "./data.mjs";

const server = new McpServer({ name: "locksmith-design-system", version: "0.1.0" });
const text = (value) => ({
  content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }],
});

server.registerTool(
  "list_components",
  {
    description:
      "List every Locksmith design system component: its name, npm package and what it is for. Call this first to find the component for a job before writing any UI.",
    inputSchema: {},
  },
  async () => text(listComponents()),
);

server.registerTool(
  "get_component",
  {
    description:
      "Everything needed to use one component: the install and import lines, its exported parts, variants, documented props, and a working example taken from the docs site.",
    inputSchema: {
      name: z.string().describe('The component, as list_components names it: "button", "data-table", "empty-state".'),
    },
  },
  async ({ name }) => {
    const component = getComponent(name);
    return component
      ? text(component)
      : { isError: true, ...text(`No component named "${name}". Call list_components to see the names.`) };
  },
);

server.registerTool(
  "get_tokens",
  {
    description:
      'The colour tokens (CSS variables) with their light and dark values. Use a token, never a hex code. Pass a filter such as "state", "brand" or "chart" to narrow the list.',
    inputSchema: { filter: z.string().optional().describe("Keep only the tokens whose name contains this.") },
  },
  async ({ filter }) => text(getTokens(filter)),
);

server.registerTool(
  "get_guide",
  {
    description:
      "How to install the kit in an app (registry, packages, the CSS imports Tailwind needs, fonts, theme) and how to add or change a component.",
    inputSchema: {},
  },
  async () => text(getGuide()),
);

await server.connect(new StdioServerTransport());
