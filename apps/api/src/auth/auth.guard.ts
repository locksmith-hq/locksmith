import { type CanActivate, type ExecutionContext, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import type { Request } from "express";
import { bearer, type HumanAuth, type HumanIdentity } from "./human-auth.js";

export const HUMAN_AUTH = Symbol("HUMAN_AUTH");

/** The request carries its verified identity here once the guard passes. */
type AuthedRequest = Request & { identity?: HumanIdentity };

/**
 * Verifies the bearer token against the configured issuer. Every failure is the same 401: a
 * missing or malformed header, an unconfigured issuer (fail closed), a bad token. No reason and
 * no token text reaches the response or a log.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(@Inject(HUMAN_AUTH) private readonly auth: HumanAuth | null) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AuthedRequest>();
    const token = bearer(req.headers.authorization);
    if (!this.auth || !token) throw new UnauthorizedException();
    try {
      req.identity = await this.auth.verify(token);
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }
}
