import forbiddenWords from "./forbidden-words.json" with { type: "json" };
import { AgentError, ALLOWED_TOOLS } from "./types";

/** The part of an MCP tool definition the adapters look at. */
export interface ToolLike {
  name: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
}

const FORBIDDEN = new Set<string>(forbiddenWords);
const ALLOWED = new Set<string>(ALLOWED_TOOLS);

/** Keeps only `ALLOWED_TOOLS`; the dropped tools are reported by name only. */
export function pickAllowedTools<T extends ToolLike>(tools: readonly T[]): { kept: T[]; dropped: string[] } {
  const kept: T[] = [];
  const dropped: string[] = [];
  for (const t of tools) {
    if (ALLOWED.has(t.name)) kept.push(t);
    else dropped.push(t.name);
  }
  return { kept, dropped };
}

function lastWord(property: string): string {
  const words = property
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean);
  return (words.at(-1) ?? "").toLowerCase();
}

function valueShaped(schema: unknown, depth = 0): boolean {
  if (!schema || typeof schema !== "object" || depth > 16) return false;
  const s = schema as Record<string, unknown>;
  const props = s.properties;
  if (props && typeof props === "object") {
    for (const [name, sub] of Object.entries(props)) {
      if (FORBIDDEN.has(lastWord(name)) || valueShaped(sub, depth + 1)) return true;
    }
  }
  for (const key of ["items", "additionalProperties", "not", "if", "then", "else"]) {
    if (valueShaped(s[key], depth + 1)) return true;
  }
  for (const key of ["anyOf", "oneOf", "allOf", "prefixItems"]) {
    const list = s[key];
    if (Array.isArray(list) && list.some((x) => valueShaped(x, depth + 1))) return true;
  }
  for (const key of ["$defs", "definitions"]) {
    const defs = s[key];
    if (defs && typeof defs === "object" && Object.values(defs).some((x) => valueShaped(x, depth + 1))) return true;
  }
  return false;
}

/** Throws `AgentError("unsafe_tool")` when a tool's input or output schema has a value-shaped property. */
export function assertNoValueTools(tools: readonly ToolLike[]): void {
  for (const t of tools) {
    if (valueShaped(t.inputSchema) || valueShaped(t.outputSchema)) throw new AgentError("unsafe_tool", 0);
  }
}
