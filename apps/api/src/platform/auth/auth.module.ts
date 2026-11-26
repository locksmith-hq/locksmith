import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { APP_GUARD } from "@nestjs/core";
import { createRemoteJWKSet } from "jose";
import type { Env } from "../../env.js";
import { AuthGuard, TOKEN_VERIFIER } from "./auth.guard.js";
import { TokenVerifier } from "./token-verifier.js";

@Module({
  providers: [
    {
      provide: TOKEN_VERIFIER,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) => {
        const issuer = config.get("LOCKSMITH_OIDC_ISSUER", { infer: true });
        const audience = config.get("LOCKSMITH_OIDC_AUDIENCE", { infer: true });
        const jwksUrl = config.get("LOCKSMITH_OIDC_JWKS_URL", { infer: true });
        if (!issuer || !audience || !jwksUrl) return null;
        // Rust JwksCache defaults: refresh an unknown kid at most every 30s, keep keys 1h.
        const keys = createRemoteJWKSet(new URL(jwksUrl), { cooldownDuration: 30_000, cacheMaxAge: 3_600_000 });
        return new TokenVerifier({ issuer, audience }, keys);
      },
    },
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
export class AuthModule {}
