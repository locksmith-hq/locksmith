import "reflect-metadata";
import { Controller, Get, INestApplication, Logger } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type CryptoKey, type JWK } from "jose";
import request from "supertest";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import fixtures from "./fixtures/claims.json" with { type: "json" };
import { AuthGuard, TOKEN_VERIFIER } from "./auth.guard.js";
import { Public } from "./public.decorator.js";
import { MAX_TOKEN_BYTES, TokenVerifier } from "./token-verifier.js";

const providers = [fixtures.cognito, fixtures.keycloak] as const;
let rsa: { privateKey: CryptoKey; publicKey: CryptoKey };
let ec: { privateKey: CryptoKey; publicKey: CryptoKey };
let rsaJwk: JWK;
let ecJwk: JWK;
let other: { privateKey: CryptoKey };
let rs512: { privateKey: CryptoKey };

beforeAll(async () => {
  rsa = await generateKeyPair("RS256", { extractable: true });
  ec = await generateKeyPair("ES256", { extractable: true });
  other = await generateKeyPair("RS256");
  rs512 = await generateKeyPair("RS512");
  rsaJwk = { ...(await exportJWK(rsa.publicKey)), kid: "rsa-1", alg: "RS256", use: "sig" };
  ecJwk = { ...(await exportJWK(ec.publicKey)), kid: "ec-1", alg: "ES256", use: "sig" };
});

const verifierFor = (p: (typeof providers)[number]) =>
  new TokenVerifier({ issuer: p.issuer, audience: p.audience }, (h, t) => createLocalJWKSet({ keys: [rsaJwk, ecJwk] })(h, t)); // built lazily: keys exist after beforeAll

type Opts = { kid?: string | null; alg?: string; key?: CryptoKey; iss?: string; aud?: string; exp?: string | number };
function sign(p: (typeof providers)[number], o: Opts = {}) {
  const alg = o.alg ?? "RS256";
  const header: Record<string, unknown> = { alg };
  if (o.kid !== null) header["kid"] = o.kid ?? (alg === "ES256" ? "ec-1" : "rsa-1");
  return new SignJWT({ ...p.claims })
    .setProtectedHeader(header as { alg: string })
    .setIssuer(o.iss ?? p.issuer)
    .setAudience(o.aud ?? p.audience)
    .setIssuedAt()
    .setExpirationTime(o.exp ?? "5m")
    .sign(o.key ?? (alg === "ES256" ? ec.privateKey : rsa.privateKey));
}

describe.each(providers.map((p) => [p.issuer, p] as const))("token verification (%s)", (_n, p) => {
  const verifier = verifierFor(p);

  it("accepts a valid RS256 and a valid ES256 token and maps the claims", async () => {
    for (const alg of ["RS256", "ES256"]) {
      const id = await verifier.verify(await sign(p, { alg }));
      expect(id.issuer).toBe(p.issuer);
      expect(id.subject).toBe(p.claims.sub);
      expect(id.email).toBe(p.claims.email);
      expect(id.emailVerified).toBe(p.claims.email_verified);
      expect(id.authTime).toBe(p.claims.auth_time);
    }
  });

  it("maps azp to the client id", async () => {
    const id = await verifier.verify(await sign(p));
    expect(id.clientId).toBe("azp" in p.claims ? p.claims.azp : null);
  });

  const cases: [string, () => Promise<string>, string][] = [
    ["expired", () => sign(p, { exp: Math.floor(Date.now() / 1000) - 3600 }), "invalid"],
    ["wrong audience", () => sign(p, { aud: "someone-else" }), "invalid"],
    ["wrong issuer", () => sign(p, { iss: "https://evil.example.test" }), "invalid"],
    ["unknown key id", () => sign(p, { kid: "nope" }), "unknown_key"],
    ["missing key id", () => sign(p, { kid: null }), "no_kid"],
    ["bad signature (right kid, other key)", () => sign(p, { key: other.privateKey }), "invalid"],
    ["algorithm outside the allowed set", () => sign(p, { alg: "RS512", key: rs512.privateKey }), "algorithm"],
    ["not a jwt", async () => "not-a-jwt", "malformed"],
    ["oversized", async () => "a".repeat(MAX_TOKEN_BYTES + 1), "too_large"],
  ];
  it.each(cases)("refuses: %s", async (_label, make, reason) => {
    await expect(verifier.verify(await make())).rejects.toMatchObject({ reason });
  });

  it("refuses alg none", async () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const t = `${b64({ alg: "none", kid: "rsa-1" })}.${b64({ ...p.claims, iss: p.issuer, aud: p.audience, exp: 9999999999 })}.`;
    await expect(verifier.verify(t)).rejects.toMatchObject({ reason: expect.stringMatching(/^(malformed|algorithm)$/) });
  });

  it("refuses an HS256 token signed with the public key as secret", async () => {
    const t = await new SignJWT({ ...p.claims })
      .setProtectedHeader({ alg: "HS256", kid: "rsa-1" })
      .setIssuer(p.issuer)
      .setAudience(p.audience)
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode(JSON.stringify(rsaJwk)));
    await expect(verifier.verify(t)).rejects.toMatchObject({ reason: "algorithm" });
  });
});

@Controller("probe")
class ProbeController {
  @Get("guarded") guarded() {
    return { ok: true };
  }
  @Public() @Get("open") open() {
    return { ok: true };
  }
}

describe("AuthGuard over HTTP", () => {
  let app: INestApplication;
  const p = fixtures.keycloak;
  const logged: unknown[] = [];

  afterEach(async () => {
    vi.restoreAllMocks();
    logged.length = 0;
    await app?.close();
  });

  async function boot(verifier: TokenVerifier | null) {
    vi.spyOn(Logger.prototype, "warn").mockImplementation((...a: unknown[]) => void logged.push(a));
    const mod = await Test.createTestingModule({
      controllers: [ProbeController],
      providers: [
        { provide: TOKEN_VERIFIER, useValue: verifier },
        { provide: "APP_GUARD_TEST", useClass: AuthGuard },
      ],
    }).compile();
    app = mod.createNestApplication();
    // Same effect as AuthModule's APP_GUARD, without the config plumbing.
    const { Reflector } = await import("@nestjs/core");
    app.useGlobalGuards(new AuthGuard(app.get(Reflector), verifier));
    await app.init();
  }

  it("lets a valid token through and refuses everything else with an opaque 401, never logging the token", async () => {
    await boot(verifierFor(p));
    const good = await sign(p);
    const bad = await sign(p, { aud: "wrong" });
    await request(app.getHttpServer()).get("/probe/guarded").set("authorization", `Bearer ${good}`).expect(200);
    await request(app.getHttpServer()).get("/probe/guarded").expect(401);
    const res = await request(app.getHttpServer()).get("/probe/guarded").set("authorization", `Bearer ${bad}`).expect(401);
    expect(JSON.stringify(res.body)).not.toContain("audience");
    await request(app.getHttpServer()).get("/probe/guarded").set("authorization", `Basic ${good}`).expect(401);
    await request(app.getHttpServer()).get("/probe/open").expect(200);
    const out = JSON.stringify(logged);
    expect(out).toContain("auth.reject");
    expect(out).not.toContain(good);
    expect(out).not.toContain(bad);
    expect(out).not.toContain(good.split(".")[1]!);
  });

  it("refuses every token when no issuer is configured", async () => {
    await boot(null);
    await request(app.getHttpServer()).get("/probe/guarded").set("authorization", `Bearer ${await sign(p)}`).expect(401);
    await request(app.getHttpServer()).get("/probe/open").expect(200);
  });
});
