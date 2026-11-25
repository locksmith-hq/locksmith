import type { HumanAuthConfig } from "./human-auth.js";

/** Same variable names as the Rust control plane. All three set, or none (auth then refuses everything). */
export function humanAuthConfig(env: Record<string, string | undefined>): HumanAuthConfig | null {
  // Trimmed, and empty counts as unset, as in the Rust config.
  const get = (k: string) => env[k]?.trim() || undefined;
  const issuer = get("LOCKSMITH_OIDC_ISSUER");
  if (!issuer) return null;
  const audience = get("LOCKSMITH_OIDC_AUDIENCE");
  const jwksUrl = get("LOCKSMITH_OIDC_JWKS_URL");
  if (!audience || !jwksUrl) {
    throw new Error("LOCKSMITH_OIDC_ISSUER needs LOCKSMITH_OIDC_AUDIENCE and LOCKSMITH_OIDC_JWKS_URL");
  }
  if (!/^https?:\/\//i.test(jwksUrl)) {
    throw new Error("LOCKSMITH_OIDC_JWKS_URL must be an http or https URL");
  }
  return { issuer, audience, jwksUrl };
}
