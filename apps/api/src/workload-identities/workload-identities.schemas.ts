import { z } from "zod";

interface ConditionView {
  claim: string;
  pattern: string;
}

export interface WorkloadIdentity {
  id: string;
  name: string;
  issuer_kind: string;
  issuer: string;
  audience: string;
  agent_id: string;
  conditions: ConditionView[];
  handle: string;
  created_at: string;
  last_used_at: string | null;
}

const UUID = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$/i;

/** Rust `ConditionView` (no `deny_unknown_fields`). */
const ConditionViewSchema = z.object({ claim: z.string(), pattern: z.string() });

/** Rust `NewWorkloadIdentity` (`deny_unknown_fields`; `issuer` optional). */
export const NewWorkloadIdentity = z.strictObject({
  name: z.string(),
  issuer_kind: z.string(),
  issuer: z.string().nullish(),
  audience: z.string(),
  agent_id: z
    .string()
    .refine((v) => UUID.test(v)) // a refine adds no `pattern` to the generated schema, like Rust's `format: uuid`
    .transform((v) => v.toLowerCase()),
  conditions: z.array(ConditionViewSchema),
});
export type NewWorkloadIdentity = z.infer<typeof NewWorkloadIdentity>;

/** Response schema, for the OpenAPI registry. */
export const WorkloadIdentitySchema = z.object({
  id: z.string(),
  name: z.string(),
  issuer_kind: z.string(),
  issuer: z.string(),
  audience: z.string(),
  agent_id: z.string(),
  conditions: z.array(ConditionViewSchema),
  handle: z.string(),
  created_at: z.string(),
  last_used_at: z.string().nullable().optional(),
});

export const WorkloadIdentityParams = z.object({ id: z.string() });
