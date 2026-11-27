import { z } from "zod";

/** Rust `MAX_NAME_CHARS`, counted in Unicode scalar values like `chars().count()`. */
export const MAX_NAME_CHARS = 200;

export const NewOrg = z.strictObject({ name: z.string() });

/** Plain strings, as in the frozen contract (the `format` is not part of the compared shape). */
export const Org = z.object({
  id: z.string(),
  name: z.string(),
  region: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Org = z.infer<typeof Org>;

export const OrgParams = z.object({ org_id: z.string() });
