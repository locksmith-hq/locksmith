import { Controller, HttpCode, Inject, Post, Req, UseGuards } from "@nestjs/common";
import type { Request } from "express";
import { AUDIT_SINK, issuerHost, type AuditSink } from "../audit/audit-sink.js";
import { AuthGuard } from "../auth/auth.guard.js";
import type { HumanIdentity } from "../auth/human-auth.js";
import { UsersService } from "./users.service.js";

type AuthedRequest = Request & { identity?: HumanIdentity };

/**
 * `POST /v1/auth/sign-in` and `/v1/auth/sign-out` (Rust `api/session.rs`): record that a session
 * started or ended in the org's ledger. Authentication happens on every request; sign-out is
 * stateless (the client discards its tokens). Both return 204 with no body, and the event holds
 * the user id and issuer host only, never a token.
 */
@Controller("v1/auth")
@UseGuards(AuthGuard)
export class SessionController {
  constructor(
    @Inject(UsersService) private readonly users: UsersService,
    @Inject(AUDIT_SINK) private readonly audit: AuditSink,
  ) {}

  @Post("sign-in")
  @HttpCode(204)
  async signIn(@Req() req: AuthedRequest): Promise<void> {
    await this.record(req, "auth.sign_in");
  }

  @Post("sign-out")
  @HttpCode(204)
  async signOut(@Req() req: AuthedRequest): Promise<void> {
    await this.record(req, "auth.sign_out");
  }

  private async record(req: AuthedRequest, kind: "auth.sign_in" | "auth.sign_out"): Promise<void> {
    const identity = req.identity!;
    const { userId, orgId } = await this.users.resolve(identity);
    await this.audit.append({ kind, userId, orgId, issuerHost: issuerHost(identity.issuer), outcome: "ok" });
  }
}
