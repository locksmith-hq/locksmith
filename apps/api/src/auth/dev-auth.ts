/** Injection token: whether the dev-only `X-Locksmith-Dev-Org` header may name an org. */
export const DEV_AUTH = Symbol("DEV_AUTH");

/** Rust `LOCKSMITH_DEV_AUTH`: only `1` turns it on; the env schema already rejects other values. */
export function devAuthEnabled(env: Record<string, string | undefined>): boolean {
  return env["LOCKSMITH_DEV_AUTH"]?.trim() === "1";
}

export const DEV_ORG_HEADER = "x-locksmith-dev-org";
