import { CanActivate, ExecutionContext, Inject, Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { Request } from "express";
import { IS_PUBLIC } from "./public.decorator.js";
import { TokenRefused, type HumanIdentity, type TokenVerifier } from "./token-verifier.js";

export const TOKEN_VERIFIER = Symbol("TOKEN_VERIFIER");
type RequestWithIdentity = Request & { identity?: HumanIdentity };

/** Global guard: fail closed unless the route is @Public(). Without OIDC settings every token is refused. */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly log = new Logger("auth");

  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(TOKEN_VERIFIER) private readonly verifier: TokenVerifier | null,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    if (this.reflector.getAllAndOverride<boolean | undefined>(IS_PUBLIC, [ctx.getHandler(), ctx.getClass()])) {
      return true;
    }
    const req = ctx.switchToHttp().getRequest<RequestWithIdentity>();
    const token = bearer(req.headers.authorization);
    if (!token || !this.verifier) return this.reject(token ? "not_configured" : "no_token");
    try {
      req.identity = await this.verifier.verify(token);
      return true;
    } catch (e) {
      return this.reject(e instanceof TokenRefused ? e.reason : "invalid");
    }
  }

  // Opaque to the caller (401, no reason); the reason slug is logged, never the token.
  private reject(reason: string): never {
    this.log.warn({ event: "auth.reject", reason });
    throw new UnauthorizedException();
  }
}

function bearer(header: string | undefined): string | null {
  const m = /^Bearer +(\S+)$/i.exec(header ?? "");
  return m ? m[1]! : null;
}
