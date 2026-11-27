import { z } from "zod";

export const Secret = z.object({
  id: z.string(),
  project_id: z.string(),
  environment_id: z.string(),
  name: z.string(),
  description: z.string(),
  version_count: z.number().int(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Secret = z.infer<typeof Secret>;

/** `deny_unknown_fields` in Rust: a `value` key is a 400 and nothing is stored. */
export const NewSecret = z.strictObject({ name: z.string(), description: z.string().optional() });
