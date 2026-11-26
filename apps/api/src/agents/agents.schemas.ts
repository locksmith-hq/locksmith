import { z } from "zod";

export interface Agent {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface GrantScope {
  actions: string[];
  resources: string[];
  max_duration_secs?: number;
}

export interface AgentGrant {
  id: string;
  agent_id: string;
  secret_id: string;
  secret_name: string;
  mode: "relay" | "delegate";
  scope: GrantScope | null;
  expires_at: string | null;
  created_at: string;
}

/** Rust `NewAgent` (`deny_unknown_fields`). */
export const NewAgent = z.strictObject({ name: z.string(), description: z.string().optional() });

/** Rust `GrantScope` (`deny_unknown_fields`, every field defaulted); `max_duration_secs` is a `u32`. */
const Scope = z.strictObject({
  actions: z.array(z.string()).default([]),
  resources: z.array(z.string()).default([]),
  max_duration_secs: z.number().int().min(0).max(4_294_967_295).nullish(),
});
export type ScopeInput = z.infer<typeof Scope>;

const UUID = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$/i;

/** Rust `NewAgentGrant`. */
export const NewAgentGrant = z.strictObject({
  secret_id: z.string().regex(UUID).transform((v) => v.toLowerCase()),
  mode: z.enum(["relay", "delegate"]).default("relay"),
  scope: Scope.nullish(),
  expires_at: z.iso.datetime({ offset: true }).nullish(),
});
export type NewAgentGrant = z.infer<typeof NewAgentGrant>;
