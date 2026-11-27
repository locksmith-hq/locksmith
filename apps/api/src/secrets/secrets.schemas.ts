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

/** Metadata only; the Rust `SecretVersion` has no value, DEK, ciphertext or wrapped DEK field either. */
const SecretVersion = z.object({
  secret_id: z.string(),
  version: z.number().int(),
  key_id: z.string(),
  created_at: z.string(),
});
export type SecretVersionList = { items: z.infer<typeof SecretVersion>[] };
