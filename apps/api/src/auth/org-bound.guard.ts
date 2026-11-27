import { type CanActivate, Inject, Injectable } from "@nestjs/common";
import { ProblemException } from "../platform/problem.js";
import { TenantService } from "../tenant/tenant.service.js";

/**
 * Authorization is the org binding, enforced by row-level security: the Rust control plane has no
 * per-org roles (decision B6-2), so this guard does not invent a role matrix. A request whose
 * authenticated principal is not bound to an org is refused with 403 `forbidden`.
 * Run it after `AuthGuard`, which sets the org on the tenant context.
 */
@Injectable()
export class OrgBoundGuard implements CanActivate {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  canActivate(): boolean {
    if (!this.tenant.orgId()) throw new ProblemException("forbidden");
    return true;
  }
}
