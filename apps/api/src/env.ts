import { z } from "zod";

// No defaults for secrets: a missing DATABASE_URL fails startup.
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  DATABASE_URL: z.string().min(1),
  JOBS_DATABASE_URL: z.string().min(1).optional(),
  // Email delivery (N1): the job runs only when all three are set. The relay is plain SMTP with no
  // credentials in this slice; a credentialed relay comes with the secret-write path.
  SMTP_HOST: z.string().min(1).optional(),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  SMTP_FROM: z.string().min(3).optional(),
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
