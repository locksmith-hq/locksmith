import { z } from "zod";

const Stamps = { created_at: z.string(), updated_at: z.string() };

export const Project = z.object({ id: z.string(), name: z.string(), description: z.string(), ...Stamps });
export type Project = z.infer<typeof Project>;

export const Environment = z.object({
  id: z.string(),
  project_id: z.string(),
  name: z.string(),
  description: z.string(),
  ...Stamps,
});
export type Environment = z.infer<typeof Environment>;

export const NewProject = z.strictObject({ name: z.string(), description: z.string().optional() });
const NewEnvironment = NewProject;
export { NewEnvironment };

/** `PATCH` body of projects, environments and secrets: either field may be null, as in Rust's `Option`. */
export const Patch = z.strictObject({ name: z.string().nullish(), description: z.string().nullish() });
export type Patch = z.infer<typeof Patch>;

export const Paged = <T extends z.ZodType>(item: T) =>
  z.object({ items: z.array(item), next: z.string().nullable().optional() });

export const ProjectParams = z.object({ project_id: z.string() });
export const EnvironmentParams = z.object({ project_id: z.string(), environment_id: z.string() });
export const PageQuerySchema = z.object({ limit: z.number().int().min(0).optional(), cursor: z.string().optional() });
