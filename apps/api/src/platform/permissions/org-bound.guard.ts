import { CanActivate, ExecutionContext, Inject, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ProblemException } from "../problem/problem.js";
import type { RequestWithPrincipal } from "./principal.js";
import { REQUIRE_HUMAN } from "./require-human.decorator.js";
import { REQUIRE_ORG } from "./require-org.decorator.js";

/**
 * Runs after the AuthGuard. On a @RequireOrg() route a principal with no bound org is refused
 * with 403 `forbidden`; a missing principal never reaches a handler (fail closed). On a @RequireHuman()
 * route an agent or service principal is refused the same way.
 */
@Injectable()
export class OrgBoundGuard implements CanActivate {
  constructor(@Inject(Reflector) private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const targets = [ctx.getHandler(), ctx.getClass()];
    const needsHuman = this.reflector.getAllAndOverride<boolean | undefined>(REQUIRE_HUMAN, targets);
    const needsOrg = this.reflector.getAllAndOverride<boolean | undefined>(REQUIRE_ORG, targets);
    if (!needsHuman && !needsOrg) return true;
    const principal = ctx.switchToHttp().getRequest<RequestWithPrincipal>().principal;
    if (needsOrg && !principal?.orgId) throw new ProblemException("forbidden");
    if (needsHuman && principal?.kind !== "human") throw new ProblemException("forbidden");
    return true;
  }
}
