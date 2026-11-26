import { Body, Controller, Delete, Get, HttpCode, Inject, Param, Post, Req } from "@nestjs/common";
import { z } from "zod";
import { ProblemException } from "../../platform/problem/problem.js";
import type { RequestWithPrincipal } from "../../platform/permissions/principal.js";
import { RequireHuman } from "../../platform/permissions/require-human.decorator.js";
import { RequireOrg } from "../../platform/permissions/require-org.decorator.js";
import { NewHoneyToken } from "./honey-token.schemas.js";
import { HoneyTokensService, type HoneyTokenView } from "./honey-tokens.service.js";

const uuid = z.uuid();

/** An id that is not a uuid cannot name a row: answer as a missing resource, like an unknown one. */
function id(v: string): string {
  if (!uuid.safeParse(v).success) throw new ProblemException("not-found");
  return v;
}

/** Owner-only (a human bound to the org); the route guards fail closed when the principal is missing. */
@Controller("v1/projects/:projectId/environments/:environmentId/honey-tokens")
@RequireOrg()
@RequireHuman()
export class HoneyTokensController {
  constructor(@Inject(HoneyTokensService) private readonly tokens: HoneyTokensService) {}

  @Get()
  async list(
    @Req() req: RequestWithPrincipal,
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
  ): Promise<{ items: HoneyTokenView[] }> {
    return { items: await this.tokens.list(scope(req, projectId, environmentId)) };
  }

  @Post()
  async create(
    @Req() req: RequestWithPrincipal,
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Body() body: unknown,
  ): Promise<HoneyTokenView> {
    const s = scope(req, projectId, environmentId);
    const parsed = NewHoneyToken.safeParse(body);
    if (!parsed.success) throw new ProblemException("unprocessable");
    return this.tokens.create(s, parsed.data);
  }

  @Post(":id/disable")
  @HttpCode(200)
  disable(
    @Req() req: RequestWithPrincipal,
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Param("id") tokenId: string,
  ): Promise<HoneyTokenView> {
    return this.tokens.disable(scope(req, projectId, environmentId), id(tokenId));
  }

  @Delete(":id")
  @HttpCode(204)
  async remove(
    @Req() req: RequestWithPrincipal,
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Param("id") tokenId: string,
  ): Promise<void> {
    await this.tokens.remove(scope(req, projectId, environmentId), id(tokenId));
  }
}

function scope(req: RequestWithPrincipal, projectId: string, environmentId: string) {
  // The guards ran first; fail closed if that ever changes.
  const orgId = req.principal?.orgId;
  if (!orgId) throw new ProblemException("forbidden");
  return { orgId, projectId: id(projectId), environmentId: id(environmentId) };
}
