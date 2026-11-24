import { z } from "zod";

// No defaults for secrets: a missing DATABASE_URL fails startup.
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  DATABASE_URL: z.string().min(1),
  JOBS_DATABASE_URL: z.string().min(1).optional(),
  // Human tokens (same names as the Rust control plane): all three or none. None refuses every token.
  LOCKSMITH_OIDC_ISSUER: z.string().min(1).optional(),
  LOCKSMITH_OIDC_AUDIENCE: z.string().min(1).optional(),
  LOCKSMITH_OIDC_JWKS_URL: z.url({ protocol: /^https?$/ }).optional(),
}).refine(
  (e) => [e.LOCKSMITH_OIDC_ISSUER, e.LOCKSMITH_OIDC_AUDIENCE, e.LOCKSMITH_OIDC_JWKS_URL].filter(Boolean).length % 3 === 0,
  { message: "LOCKSMITH_OIDC_ISSUER, LOCKSMITH_OIDC_AUDIENCE and LOCKSMITH_OIDC_JWKS_URL are set together or not at all" },
);

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
