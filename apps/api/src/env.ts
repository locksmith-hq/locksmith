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
  // Human tokens (same names as the Rust control plane): all three or none. None refuses every token.
  LOCKSMITH_OIDC_ISSUER: z.string().min(1).optional(),
  LOCKSMITH_OIDC_AUDIENCE: z.string().min(1).optional(),
  LOCKSMITH_OIDC_JWKS_URL: z.url({ protocol: /^https?$/ }).optional(),
  // Rust core (audit ledger): both or none. None makes sign-in and sign-out answer 503.
  LOCKSMITH_CORE_URL: z.url({ protocol: /^https?$/ }).optional(),
  LOCKSMITH_CORE_TOKEN: z.string().min(1).optional(),
}).refine(
  (e) => [e.LOCKSMITH_OIDC_ISSUER, e.LOCKSMITH_OIDC_AUDIENCE, e.LOCKSMITH_OIDC_JWKS_URL].filter(Boolean).length % 3 === 0,
  { message: "LOCKSMITH_OIDC_ISSUER, LOCKSMITH_OIDC_AUDIENCE and LOCKSMITH_OIDC_JWKS_URL are set together or not at all" },
).refine((e) => Boolean(e.LOCKSMITH_CORE_URL) === Boolean(e.LOCKSMITH_CORE_TOKEN), {
  message: "LOCKSMITH_CORE_URL and LOCKSMITH_CORE_TOKEN are set together or not at all",
});

export type Env = z.infer<typeof envSchema>;

export function validateEnv(raw: Record<string, unknown>): Env {
  // Empty counts as unset, as in the Rust config.
  const clean = Object.fromEntries(Object.entries(raw).filter(([k, v]) => !((k.startsWith("LOCKSMITH_OIDC_") || k.startsWith("LOCKSMITH_CORE_")) && v === "")));
  const parsed = envSchema.safeParse(clean);
  if (!parsed.success) {
    // Report names and reasons only, never values.
    const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`invalid environment: ${issues.join("; ")}`);
  }
  return parsed.data;
}
