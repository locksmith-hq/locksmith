import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet, type CryptoKey } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { AuthGuard } from "./auth.guard.js";
import { humanAuthConfig } from "./auth.config.js";
import { HumanAuth, MAX_TOKEN_BYTES, Refused, bearer, preCheck } from "./human-auth.js";
import type { ExecutionContext } from "@nestjs/common";

// Token shapes follow what Cognito and Keycloak issue: Cognito sets `client_id` and no `azp`,
// Keycloak sets `azp`, `email_verified` and `auth_time`. Keys are throwaway.
const COGNITO = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Pool123";
const KEYCLOAK = "http://localhost:8180/realms/locksmith";
const AUD = "locksmith-api";

let rsa: { privateKey: CryptoKey };
let ec: { privateKey: CryptoKey };
let jwks: JSONWebKeySet;

beforeAll(async () => {
  const r = await generateKeyPair("RS256", { extractable: true });
  const e = await generateKeyPair("ES256", { extractable: true });
  rsa = r;
  ec = e;
  jwks = {
    keys: [
      { ...(await exportJWK(r.publicKey)), kid: "rsa1", alg: "RS256", use: "sig" },
      { ...(await exportJWK(e.publicKey)), kid: "ec1", alg: "ES256", use: "sig" },
    ],
  };
});

type Opts = { iss?: string; aud?: string; kid?: string; alg?: "RS256" | "ES256"; exp?: string };

async function sign(claims: Record<string, unknown>, o: Opts = {}): Promise<string> {
  const alg = o.alg ?? "RS256";
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg, kid: o.kid ?? (alg === "RS256" ? "rsa1" : "ec1") })
    .setIssuedAt()
    .setExpirationTime(o.exp ?? "5m");
  if (o.iss !== "") jwt.setIssuer(o.iss ?? KEYCLOAK);
  if (o.aud !== "") jwt.setAudience(o.aud ?? AUD);
  return jwt.sign(alg === "RS256" ? rsa.privateKey : ec.privateKey);
}

const verifier = (issuer: string) =>
  HumanAuth.fromJwks({ issuer, audience: AUD, jwksUrl: "https://unused.example/jwks" }, jwks);

async function refusal(auth: HumanAuth, token: string): Promise<string> {
  try {
    await auth.verify(token);
  } catch (e) {
    if (e instanceof Refused) return e.reason;
    throw e;
  }
  return "accepted";
}

describe("human auth (mirrors services/control-plane auth/human.rs)", () => {
  it("maps a Keycloak-shaped token", async () => {
    const t = await sign(
      { sub: "kc-user-1", email: "a@example.com", email_verified: true, azp: " locksmith-web ", auth_time: 1700000000 },
      { iss: KEYCLOAK, alg: "ES256" },
    );
    expect(await verifier(KEYCLOAK).verify(t)).toEqual({
      issuer: KEYCLOAK,
      subject: "kc-user-1",
      email: "a@example.com",
      emailVerified: true,
      clientId: "locksmith-web",
      authTime: 1700000000,
    });
  });

  it("maps a Cognito-shaped token: client_id wins over azp, email unverified by default", async () => {
    const t = await sign({ sub: "cg-user-1", client_id: "cog-client", azp: "other" }, { iss: COGNITO });
    expect(await verifier(COGNITO).verify(t)).toEqual({
      issuer: COGNITO,
      subject: "cg-user-1",
      emailVerified: false,
      clientId: "cog-client",
    });
  });

  it("accepts an aud array containing the audience", async () => {
    const t = await new SignJWT({ sub: "u" })
      .setProtectedHeader({ alg: "RS256", kid: "rsa1" })
      .setIssuer(KEYCLOAK)
      .setAudience(["other", AUD])
      .setExpirationTime("5m")
      .sign(rsa.privateKey);
    expect((await verifier(KEYCLOAK).verify(t)).subject).toBe("u");
  });

  it("refuses wrong issuer, wrong audience, missing claims and expiry beyond leeway", async () => {
    const a = verifier(KEYCLOAK);
    expect(await refusal(a, await sign({ sub: "u" }, { iss: COGNITO }))).toBe("invalid");
    expect(await refusal(a, await sign({ sub: "u" }, { aud: "someone-else" }))).toBe("invalid");
    expect(await refusal(a, await sign({ sub: "u" }, { aud: "" }))).toBe("invalid");
    expect(await refusal(a, await sign({ sub: "u" }, { iss: "" }))).toBe("invalid");
    expect(await refusal(a, await sign({}))).toBe("invalid");
    expect(await refusal(a, await sign({ sub: "" }))).toBe("invalid");
    expect(await refusal(a, await sign({ sub: "u" }, { exp: "-2m" }))).toBe("invalid");
    // Within the 60 s leeway an expired token is still accepted.
    expect(await refusal(a, await sign({ sub: "u" }, { exp: "-30s" }))).toBe("accepted");
  });

  it("refuses an unknown kid and a signature from another key", async () => {
    const a = verifier(KEYCLOAK);
    expect(await refusal(a, await sign({ sub: "u" }, { kid: "nope" }))).toBe("unknown_key");
    // Signed as RS256 but naming the EC kid: the key decides the algorithm, so jose finds no
    // key for that kid and alg (the Rust verifier labels this `algorithm`; both refuse).
    const t = await new SignJWT({ sub: "u" })
      .setProtectedHeader({ alg: "RS256", kid: "ec1" })
      .setIssuer(KEYCLOAK)
      .setAudience(AUD)
      .setExpirationTime("5m")
      .sign(rsa.privateKey);
    expect(await refusal(a, t)).toBe("unknown_key");
  });

  it("refuses an oversized, malformed, none, HS256 or kid-less token before any key lookup", async () => {
    const a = verifier(KEYCLOAK);
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    expect(await refusal(a, "a".repeat(MAX_TOKEN_BYTES + 1))).toBe("too_large");
    expect(await refusal(a, "not-a-jwt")).toBe("malformed");
    expect(await refusal(a, `${b64({ alg: "none", kid: "k" })}.${b64({ sub: "u" })}.`)).toBe("malformed");
    expect(await refusal(a, `${b64({ alg: "none", kid: "k" })}.${b64({ sub: "u" })}.sig`)).toBe("algorithm");
    expect(await refusal(a, `${b64({ alg: "HS256", kid: "k" })}.${b64({ sub: "u" })}.sig`)).toBe("algorithm");
    expect(await refusal(a, `${b64({ alg: "RS256" })}.${b64({ sub: "u" })}.sig`)).toBe("no_kid");
    expect(preCheck(`${b64({ alg: "ES256", kid: "k1" })}.${b64({})}.sig`)).toEqual({ alg: "ES256", kid: "k1" });
  });

  it("never puts token text in a refusal", async () => {
    const t = await sign({ sub: "u" }, { aud: "wrong" });
    try {
      await verifier(KEYCLOAK).verify(t);
      expect.unreachable();
    } catch (e) {
      expect(JSON.stringify(e)).not.toContain(t.slice(0, 20));
      expect((e as Error).message).toBe("invalid");
    }
  });
});

describe("bearer", () => {
  it("parses the scheme case-insensitively", () => {
    expect(bearer("Bearer abc")).toBe("abc");
    expect(bearer("bearer  abc ")).toBe("abc");
    expect(bearer("Basic abc")).toBeUndefined();
    expect(bearer("Bearer ")).toBeUndefined();
    expect(bearer("Bearer")).toBeUndefined();
    expect(bearer(undefined)).toBeUndefined();
  });
});

describe("humanAuthConfig", () => {
  it("is null without an issuer and requires all three values otherwise", () => {
    expect(humanAuthConfig({})).toBeNull();
    expect(() => humanAuthConfig({ LOCKSMITH_OIDC_ISSUER: KEYCLOAK })).toThrow(/AUDIENCE/);
    expect(() =>
      humanAuthConfig({
        LOCKSMITH_OIDC_ISSUER: KEYCLOAK,
        LOCKSMITH_OIDC_AUDIENCE: AUD,
        LOCKSMITH_OIDC_JWKS_URL: "file:///etc/passwd",
      }),
    ).toThrow(/http/);
    expect(
      humanAuthConfig({
        LOCKSMITH_OIDC_ISSUER: KEYCLOAK,
        LOCKSMITH_OIDC_AUDIENCE: AUD,
        LOCKSMITH_OIDC_JWKS_URL: "https://x/jwks",
      }),
    ).toEqual({ issuer: KEYCLOAK, audience: AUD, jwksUrl: "https://x/jwks" });
  });
});

describe("AuthGuard", () => {
  const ctx = (authorization?: string) => {
    const req: { headers: Record<string, string | undefined>; identity?: unknown } = {
      headers: { authorization },
    };
    return { req, ctx: { switchToHttp: () => ({ getRequest: () => req }) } as unknown as ExecutionContext };
  };

  it("sets the identity for a valid bearer token", async () => {
    const t = await sign({ sub: "u1" });
    const { req, ctx: c } = ctx(`Bearer ${t}`);
    expect(await new AuthGuard(verifier(KEYCLOAK)).canActivate(c)).toBe(true);
    expect(req.identity).toMatchObject({ subject: "u1" });
  });

  it("answers 401 for no header, a bad token, and an unconfigured issuer (fail closed)", async () => {
    const t = await sign({ sub: "u1" });
    const bad = [
      () => new AuthGuard(verifier(KEYCLOAK)).canActivate(ctx().ctx),
      () => new AuthGuard(verifier(KEYCLOAK)).canActivate(ctx("Bearer junk").ctx),
      () => new AuthGuard(verifier(COGNITO)).canActivate(ctx(`Bearer ${t}`).ctx),
      () => new AuthGuard(null).canActivate(ctx(`Bearer ${t}`).ctx),
    ];
    for (const p of bad) await expect(p()).rejects.toMatchObject({ status: 401 });
  });
});
