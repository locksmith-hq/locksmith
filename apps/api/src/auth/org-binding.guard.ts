import { type CanActivate, type ExecutionContext, Inject, Injectable } from "@nestjs/common";
import type { Request } from "express";
import { ProblemException } from "../platform/problem.js";
import { TenantService } from "../tenant/tenant.service.js";
import { UsersService } from "../users/users.service.js";
import { AuthGuard } from "./auth.guard.js";
import { DEV_AUTH, DEV_ORG_HEADER } from "./dev-auth.js";
import type { HumanIdentity } from "./human-auth.js";

type AuthedRequest = Request & { identity?: HumanIdentity };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Binds the request to an org (Rust `auth::OrgBinding`). A bearer token is a human credential: it
 * is verified and its user resolved (a first sign-in creates the personal org), and a bad one is
 * never downgraded to the dev header. Without a token, the dev header names the org only when dev
 * auth is on. Every failure is the same 401. The org goes on the tenant context, so the tenant
 * interceptor opens the request's transaction.
 */
@Injectable()
export class OrgBindingGuard implements CanActivate {
  constructor(
    @Inject(AuthGuard) private readonly auth: AuthGuard,
    @Inject(UsersService) private readonly users: UsersService,
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(DEV_AUTH) private readonly devAuth: boolean,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AuthedRequest>();
    if (req.headers.authorization !== undefined) {
      await this.auth.canActivate(context);
      const { orgId } = await this.users.resolve(req.identity!);
      this.tenant.setOrgId(orgId);
      return true;
    }
    if (!this.devAuth) throw new ProblemException("unauthenticated");
    const value = req.headers[DEV_ORG_HEADER];
    const orgId = typeof value === "string" ? value.trim() : "";
    if (!UUID.test(orgId)) throw new ProblemException("unauthenticated");
    this.tenant.setOrgId(orgId.toLowerCase());
    return true;
  }
}
