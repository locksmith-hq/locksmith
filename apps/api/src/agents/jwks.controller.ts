import { Controller, Get, Inject, Res } from "@nestjs/common";
import type { CoreClient } from "@locksmith/core-client";
import type { Response } from "express";
import { CORE_CLIENT } from "../core/core.tokens.js";
import { ProblemException } from "../platform/problem.js";

/**
 * `GET /.well-known/jwks.json` (Rust `api/agents.rs::jwks`): the public key that verifies agent tokens.
 * Public by design. The key lives in the core, which signs; this controller only relays the public set.
 * When the core has no signing key the set is empty (as the Rust API answers); an unreachable core is a 503.
 */
@Controller(".well-known")
export class JwksController {
  constructor(@Inject(CORE_CLIENT) private readonly core: CoreClient) {}

  @Get("jwks.json")
  async jwks(@Res({ passthrough: true }) res: Response) {
    let keys: unknown[];
    try {
      keys = (await this.core.getAgentTokenJwks()).keys;
    } catch (e) {
      if ((e as { status?: number }).status !== 503) throw new ProblemException("unavailable");
      keys = [];
    }
    res.setHeader("Cache-Control", "public, max-age=60");
    return { keys };
  }
}
