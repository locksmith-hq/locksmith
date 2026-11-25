import { Controller, HttpCode, Inject, Post, Req } from "@nestjs/common";
import type { Request } from "express";
import type { HumanIdentity } from "../auth/token-verifier.js";
import { ProblemException } from "../problem/problem.js";
import { SessionService } from "./session.service.js";

type RequestWithIdentity = Request & { identity?: HumanIdentity };

/** Both routes need a verified human bearer token (the global AuthGuard), take no body and answer 204. */
@Controller("v1/auth")
export class SessionController {
  constructor(@Inject(SessionService) private readonly session: SessionService) {}

  @Post("sign-in")
  @HttpCode(204)
  async signIn(@Req() req: RequestWithIdentity): Promise<void> {
    await this.session.signIn(identity(req));
  }

  @Post("sign-out")
  @HttpCode(204)
  async signOut(@Req() req: RequestWithIdentity): Promise<void> {
    await this.session.signOut(identity(req));
  }
}

function identity(req: RequestWithIdentity): HumanIdentity {
  // The guard sets it on every non-public route; fail closed if that ever changes.
  if (!req.identity) throw new ProblemException("unauthenticated");
  return req.identity;
}
