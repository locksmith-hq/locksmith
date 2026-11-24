import { z } from "zod";

// Fails fast on startup. Secrets (DATABASE_URL carries a password) have no defaults.
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8081),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  DATABASE_URL: z.string().min(1),
});

export type Env = z.infer<typeof envSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    // Names only: never echo a value, even a malformed one.
    const bad = [...new Set(parsed.error.issues.map((i) => i.path.join(".")))].join(", ");
    throw new Error(`invalid environment: ${bad}`);
  }
  return parsed.data;
}
