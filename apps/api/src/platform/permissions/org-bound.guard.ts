import { CanActivate, ExecutionContext, Inject, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ProblemException } from "../problem/problem.js";
import type { RequestWithPrincipal } from "./principal.js";
import { REQUIRE_ORG } from "./require-org.decorator.js";

/**
 * Runs after the AuthGuard. On a @RequireOrg() route a principal with no bound org is refused
 * with 403 `forbidden`; a missing principal never reaches a handler (fail closed).
 */
@Injectable()
export class OrgBoundGuard implements CanActivate {
  constructor(@Inject(Reflector) private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    if (!this.reflector.getAllAndOverride<boolean | undefined>(REQUIRE_ORG, [ctx.getHandler(), ctx.getClass()])) {
      return true;
    }
    const principal = ctx.switchToHttp().getRequest<RequestWithPrincipal>().principal;
    if (!principal?.orgId) throw new ProblemException("forbidden");
    return true;
  }
}
