import { z } from "zod";

/** A registered agent. Never carries its enrollment secret or the secret's hash. */
export const Agent = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Agent = z.infer<typeof Agent>;

/** The allow-list a `delegate` grant carries (Rust `GrantScope`). */
export interface GrantScope {
  actions: string[];
  resources: string[];
  max_duration_secs?: number;
}

/** Hand-written so the generated schema is exactly the frozen one: utoipa's `oneOf`, open object, `minimum: 0`. */
const ScopeSchema = z.any().meta({
  oneOf: [
    {
      type: "object",
      properties: {
        actions: { type: "array", items: { type: "string" } },
        max_duration_secs: { type: ["integer", "null"], minimum: 0 },
        resources: { type: "array", items: { type: "string" } },
      },
    },
    { type: "null" },
  ],
});

/** A grant: names and ids only, never the value. */
export const AgentGrant = z.object({
  id: z.string(),
  agent_id: z.string(),
  secret_id: z.string(),
  secret_name: z.string(),
  mode: z.enum(["relay", "delegate"]),
  scope: ScopeSchema.optional(),
  expires_at: z.string().nullable().optional(),
  created_at: z.string(),
});
export type AgentGrant = Omit<z.infer<typeof AgentGrant>, "scope"> & { scope: GrantScope | null };

export const AgentParams = z.object({ agent_id: z.string() });
