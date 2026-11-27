import { Body, Controller, HttpCode, Inject, Post, Req, Res } from "@nestjs/common";
import type { Request, Response } from "express";
import { z } from "zod";
import { WorkloadTokensService } from "./workload-tokens.service.js";

/** Rust `WorkloadTokenRequest` (`deny_unknown_fields`). */
const WorkloadTokenRequest = z.strictObject({ policy: z.string(), token: z.string() });

/**
 * `POST /v1/workload-tokens` (Rust `api/workload_tokens.rs`). No guard: the external token in the body is the
 * credential. The peer address is the socket's, never a forwarded header (Rust trusts none either).
 */
@Controller("v1/workload-tokens")
export class WorkloadTokensController {
  constructor(@Inject(WorkloadTokensService) private readonly svc: WorkloadTokensService) {}

  @Post()
  @HttpCode(200)
  async exchange(@Body() body: unknown, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const input = WorkloadTokenRequest.parse(body);
    const out = await this.svc.exchange(input.policy, input.token, req.socket.remoteAddress?.replace(/^::ffff:/i, ""));
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    return out;
  }
}
