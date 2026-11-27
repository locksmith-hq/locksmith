import { Body, Controller, HttpCode, Inject, Post, Res } from "@nestjs/common";
import type { Response } from "express";
import { z } from "zod";
import { AgentTokensService } from "./agent-tokens.service.js";

/** Rust `AgentTokenRequest` (`deny_unknown_fields`). */
const AgentTokenRequest = z.strictObject({ enrollment_secret: z.string() });

/** No guard: the enrollment secret in the body is the credential (Rust `api/agents.rs::mint_token`). */
@Controller("v1/agent-tokens")
export class AgentTokensController {
  constructor(@Inject(AgentTokensService) private readonly svc: AgentTokensService) {}

  @Post()
  @HttpCode(200)
  async mint(@Body() body: unknown, @Res({ passthrough: true }) res: Response) {
    const input = AgentTokenRequest.parse(body);
    const out = await this.svc.mint(input.enrollment_secret);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    return out;
  }
}
