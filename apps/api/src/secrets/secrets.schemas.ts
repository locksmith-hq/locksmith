import { z } from "zod";

/** Rust `u32`: the frozen contract says `integer`, `minimum: 0` and nothing else. */
const UInt = z.number().meta({ type: "integer", minimum: 0 });

/** Secret metadata. Never carries a value, wrapped data key or ciphertext. */
export const Secret = z.object({
  id: z.string(),
  project_id: z.string(),
  environment_id: z.string(),
  name: z.string(),
  description: z.string(),
  version_count: UInt,
  created_at: z.string(),
  updated_at: z.string(),
});
export type Secret = z.infer<typeof Secret>;

/** Metadata of one stored version. Never carries the value or any key material. */
export const SecretVersion = z.object({
  secret_id: z.string(),
  version: UInt,
  key_id: z.string(),
  created_at: z.string(),
});
export type SecretVersion = z.infer<typeof SecretVersion>;

/** All versions of a secret, oldest first (not paged). */
export const SecretVersionList = z.object({ items: z.array(SecretVersion) });

export const SecretsParams = z.object({ project_id: z.string(), environment_id: z.string() });
export const SecretParams = z.object({
  project_id: z.string(),
  environment_id: z.string(),
  secret_id: z.string(),
});
