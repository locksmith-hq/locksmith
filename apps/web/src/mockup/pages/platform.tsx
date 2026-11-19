// Workspace-level pages: the notification center and MCP. Keys are "hub/<page>".
import type { Pages } from "../kit";
import { Mcp } from "./platformMcp";
import { Notifications } from "./platformNotify";

export const pages: Pages = { "hub/notifications": Notifications, "hub/mcp": Mcp };
