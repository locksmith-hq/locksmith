import {
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type JSONWebKeySet,
  type JWTVerifyGetKey,
} from "jose";

/** Longest bearer token examined; anything larger is refused before parsing (Rust `MAX_TOKEN_BYTES`). */
export const MAX_TOKEN_BYTES = 8 * 1024;
/** Clock skew tolerated on `exp` and `nbf` (Rust `LEEWAY_SECS`). */
export const LEEWAY_SECS = 60;
/** The only algorithms a token may use (Rust `ALLOWED`); never `none`, never HS*. */
export const ALLOWED_ALGS = ["RS256", "ES256"] as const;

/** Issuer settings, the same three values as `LOCKSMITH_OIDC_*` in the Rust control plane. */
export interface HumanAuthConfig {
  /** The `iss` every token must carry, compared exactly. */
  issuer: string;
  /** The `aud` every token must include. */
  audience: string;
  /** Where the issuer publishes its signing keys. */
  jwksUrl: string;
}

/** The verified identity in a token (Rust `HumanIdentity`). `subject` is the key, not email. */
export interface HumanIdentity {
  issuer: string;
  subject: string;
  email?: string;
  emailVerified: boolean;
  /** The OAuth client the token was issued to (`client_id`, else `azp`). */
  clientId?: string;
  /** When the person last signed in at the issuer (`auth_time`, unix seconds). */
  authTime?: number;
}

/** A refused token: only a static label, never token text. Callers answer 401 with no reason. */
export class Refused extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "Refused";
  }
}

const SEGMENT = /^[A-Za-z0-9_-]+$/;

/** Size, header parse, allowed algorithm and `kid`, in that order (Rust `jwt::pre_check`). */
export function preCheck(token: string): { alg: string; kid: string } {
  if (token.length > MAX_TOKEN_BYTES) throw new Refused("too_large");
  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every((p) => SEGMENT.test(p))) throw new Refused("malformed");
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new Refused("malformed");
  }
  if (typeof header.alg !== "string" || !(ALLOWED_ALGS as readonly string[]).includes(header.alg)) {
    throw new Refused("algorithm");
  }
  if (typeof header.kid !== "string" || header.kid === "") throw new Refused("no_kid");
  return { alg: header.alg, kid: header.kid };
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/** Verifier for one issuer (Rust `HumanAuth`). */
export class HumanAuth {
  private readonly keys: JWTVerifyGetKey;

  /** `keys` is injectable so tests can serve a local key set without a network. */
  constructor(
    private readonly config: HumanAuthConfig,
    keys?: JWTVerifyGetKey,
  ) {
    this.keys =
      keys ??
      createRemoteJWKSet(new URL(config.jwksUrl), {
        // A refresh for an unknown `kid` is rate limited, like the Rust `JwksCache`.
        cooldownDuration: 30_000,
        cacheMaxAge: 600_000,
        timeoutDuration: 10_000,
      });
  }

  static fromJwks(config: HumanAuthConfig, jwks: JSONWebKeySet): HumanAuth {
    return new HumanAuth(config, createLocalJWKSet(jwks));
  }

  /** Verify `token`; throws {@link Refused} with a static label for every failure. */
  async verify(token: string): Promise<HumanIdentity> {
    preCheck(token);
    let payload;
    try {
      // `algorithms` pins the key-compatible algorithm: a header alg that does not match the
      // key's type is refused by jose.
      ({ payload } = await jwtVerify(token, this.keys, {
        issuer: this.config.issuer,
        audience: this.config.audience,
        algorithms: [...ALLOWED_ALGS],
        clockTolerance: LEEWAY_SECS,
        requiredClaims: ["exp", "iss", "aud", "sub"],
      }));
    } catch (e) {
      const code = (e as { code?: string } | null)?.code;
      throw new Refused(code === "ERR_JWKS_NO_MATCHING_KEY" ? "unknown_key" : "invalid");
    }
    const sub = str(payload.sub);
    if (!sub) throw new Refused("invalid");
    const clientId = (str(payload["client_id"]) ?? str(payload["azp"]))?.trim();
    const authTime = payload["auth_time"];
    const email = str(payload["email"]);
    return {
      issuer: str(payload.iss) ?? this.config.issuer,
      subject: sub,
      ...(email !== undefined && { email }),
      emailVerified: payload["email_verified"] === true,
      ...(clientId && { clientId }),
      ...(typeof authTime === "number" && Number.isInteger(authTime) && { authTime }),
    };
  }
}

/** The credential of an `Authorization: Bearer <token>` value (Rust `auth::bearer`). */
export function bearer(value: string | undefined): string | undefined {
  if (value === undefined || value.length < 7) return undefined;
  if (value.slice(0, 7).toLowerCase() !== "bearer ") return undefined;
  const token = value.slice(7).trim();
  return token === "" ? undefined : token;
}
