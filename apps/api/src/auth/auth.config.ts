import type { HumanAuthConfig } from "./human-auth.js";

/** Same variable names as the Rust control plane. All three set, or none (auth then refuses everything). */
export function humanAuthConfig(env: Record<string, string | undefined>): HumanAuthConfig | null {
  const issuer = env["LOCKSMITH_OIDC_ISSUER"];
  if (!issuer) return null;
  const audience = env["LOCKSMITH_OIDC_AUDIENCE"];
  const jwksUrl = env["LOCKSMITH_OIDC_JWKS_URL"];
  if (!audience || !jwksUrl) {
    throw new Error("LOCKSMITH_OIDC_ISSUER needs LOCKSMITH_OIDC_AUDIENCE and LOCKSMITH_OIDC_JWKS_URL");
  }
  return { issuer, audience, jwksUrl };
}
