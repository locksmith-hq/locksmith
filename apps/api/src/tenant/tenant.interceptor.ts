import { type CallHandler, type ExecutionContext, Inject, Injectable, type NestInterceptor } from "@nestjs/common";
import { from, lastValueFrom, type Observable } from "rxjs";
import { TenantService } from "./tenant.service.js";

/**
 * Wraps a handler in the tenant transaction when the auth guard has set an org id. Requests with
 * no org (health checks, sign-in) pass through without a transaction. The transaction commits when
 * the handler's stream completes and rolls back if it errors.
 */
@Injectable()
export class TenantInterceptor implements NestInterceptor {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  intercept(_ctx: ExecutionContext, next: CallHandler): Observable<unknown> {
    const orgId = this.tenant.orgId();
    if (!orgId) return next.handle();
    return from(this.tenant.runInRequest(orgId, () => lastValueFrom(next.handle(), { defaultValue: undefined })));
  }
}
