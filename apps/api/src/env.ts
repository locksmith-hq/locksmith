import { z } from "zod";

// No defaults for secrets: a missing DATABASE_URL fails startup.
const envSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
    DATABASE_URL: z.string().min(1),
    // Internal Rust core (audit, tokens, DEKs). The token is a secret: no default, never logged.
    LOCKSMITH_CORE_URL: z.url(),
    LOCKSMITH_CORE_SERVICE_TOKEN: z.string().min(1),
    JOBS_DATABASE_URL: z.string().min(1).optional(),
    // Dev header auth (Rust `LOCKSMITH_DEV_AUTH`): "1" on, unset, "" or "0" off, anything else invalid.
    LOCKSMITH_DEV_AUTH: z.enum(["", "0", "1"]).optional(),
    LOCKSMITH_ALLOW_DEV_AUTH: z.enum(["", "0", "1"]).optional(),
  })
  .refine((e) => !(e.LOCKSMITH_DEV_AUTH === "1" && e.NODE_ENV === "production" && e.LOCKSMITH_ALLOW_DEV_AUTH !== "1"), {
    path: ["LOCKSMITH_DEV_AUTH"],
    message: "dev auth is refused in production unless LOCKSMITH_ALLOW_DEV_AUTH=1 is also set",
  });

export type Env = z.infer<typeof envSchema>;

export function validateEnv(raw: Record<string, unknown>): Env {
  const parsed = envSchema.safeParse(raw);
  if (!parsed.success) {
    // Report names and reasons only, never values.
    const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`invalid environment: ${issues.join("; ")}`);
  }
  return parsed.data;
}
