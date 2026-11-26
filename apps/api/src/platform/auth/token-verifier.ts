import { decodeProtectedHeader, errors, jwtVerify, type JWTVerifyGetKey } from "jose";

// Same rules as services/control-plane/src/auth/jwt.rs and auth/human.rs.
const LEEWAY_SECS = 60;
export const MAX_TOKEN_BYTES = 8 * 1024;
const ALLOWED_ALGS = ["RS256", "ES256"] as const;

export type HumanAuthConfig = { issuer: string; audience: string; jwksUrl: string };

export type HumanIdentity = {
  issuer: string;
  subject: string;
  email: string | null;
  emailVerified: boolean;
  clientId: string | null;
  authTime: number | null;
};

// Static labels only: a refusal never carries token text.
export type RefusalReason = "too_large" | "malformed" | "algorithm" | "no_kid" | "unknown_key" | "invalid";

export class TokenRefused extends Error {
  constructor(readonly reason: RefusalReason) {
    super(reason);
    this.name = "TokenRefused";
  }
}

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

export class TokenVerifier {
  constructor(
    private readonly config: Pick<HumanAuthConfig, "issuer" | "audience">,
    private readonly getKey: JWTVerifyGetKey,
  ) {}

  async verify(token: string): Promise<HumanIdentity> {
    if (Buffer.byteLength(token) > MAX_TOKEN_BYTES) throw new TokenRefused("too_large");
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new TokenRefused("malformed");
    }
    if (!(ALLOWED_ALGS as readonly unknown[]).includes(header.alg)) throw new TokenRefused("algorithm");
    if (!header.kid) throw new TokenRefused("no_kid");

    let payload;
    try {
      ({ payload } = await jwtVerify(token, this.getKey, {
        algorithms: [...ALLOWED_ALGS],
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockTolerance: LEEWAY_SECS,
        requiredClaims: ["exp", "iss", "aud", "sub"],
      }));
    } catch (e) {
      throw new TokenRefused(e instanceof errors.JWKSNoMatchingKey ? "unknown_key" : "invalid");
    }
    const subject = str(payload.sub);
    if (!subject) throw new TokenRefused("invalid");
    const clientId = (str(payload["client_id"]) ?? str(payload["azp"]))?.trim();
    return {
      issuer: String(payload.iss),
      subject,
      email: str(payload["email"]),
      emailVerified: payload["email_verified"] === true,
      clientId: clientId ? clientId : null,
      authTime: typeof payload["auth_time"] === "number" ? payload["auth_time"] : null,
    };
  }
}
