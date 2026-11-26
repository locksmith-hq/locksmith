import { timingSafeEqual } from "node:crypto";
import { type CanActivate, type ExecutionContext, Inject, Injectable } from "@nestjs/common";
import type { Request } from "express";
import { ProblemException } from "../platform/problem.js";
import { TenantService } from "../tenant/tenant.service.js";

/** Injection token: the gateway service token, or null when none is configured (every internal call is then refused). */
export const GATEWAY_SERVICE_TOKEN = Symbol("GATEWAY_SERVICE_TOKEN");
export const SERVICE_ORG_HEADER = "x-locksmith-org";
export const MIN_SERVICE_TOKEN_BYTES = 32;

/** Rust `config.rs`: unset or empty means off; a token that is padded or shorter than 32 bytes is refused at startup. */
export function gatewayServiceToken(env: Record<string, string | undefined>): string | null {
  const v = env["LOCKSMITH_GATEWAY_SERVICE_TOKEN"];
  if (v === undefined || v === "") return null;
  if (v.trim() !== v || Buffer.byteLength(v) < MIN_SERVICE_TOKEN_BYTES)
    throw new Error("LOCKSMITH_GATEWAY_SERVICE_TOKEN must be at least 32 bytes with no surrounding whitespace");
  return v;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Rust `auth::ServiceOrgBinding`: the caller is the gateway. A missing token configuration, a missing or wrong
 * bearer token, or a missing or non-UUID `X-Locksmith-Org` is the same 401. The token is compared in constant time
 * over equal-length digests, so neither its value nor its length leaks.
 */
@Injectable()
export class ServiceOrgGuard implements CanActivate {
  constructor(
    @Inject(GATEWAY_SERVICE_TOKEN) private readonly expected: string | null,
    @Inject(TenantService) private readonly tenant: TenantService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const header = req.headers.authorization;
    const m = typeof header === "string" ? /^bearer\s+(\S.*)$/i.exec(header.trim()) : null;
    if (!this.expected || !m) throw new ProblemException("unauthenticated");
    const presented = m[1]!.trim();
    const a = Buffer.from(presented);
    const b = Buffer.from(this.expected);
    // Length differs: still compare (against itself) so timing does not branch on it, then refuse.
    const same = a.length === b.length ? timingSafeEqual(a, b) : (timingSafeEqual(b, b), false);
    if (!same) throw new ProblemException("unauthenticated");
    const org = req.headers[SERVICE_ORG_HEADER];
    const orgId = typeof org === "string" ? org.trim() : "";
    if (!UUID.test(orgId)) throw new ProblemException("unauthenticated");
    this.tenant.setOrgId(orgId.toLowerCase());
    return true;
  }
}
