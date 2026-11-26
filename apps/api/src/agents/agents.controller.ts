import { Body, Controller, Delete, Get, HttpCode, Inject, Param, Post, Query, Res, UseGuards } from "@nestjs/common";
import type { Response } from "express";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { pathId, resolvePage } from "../platform/paging.js";
import { NewAgent, NewAgentGrant } from "./agents.schemas.js";
import { AgentsService } from "./agents.service.js";

/** A response that carries a credential must not be cached (RFC 6749 section 5.1). */
function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

/** Rust `api/agents.rs`. Check order as in axum's extractors: org binding, path ids, query, body, then the handler. */
@Controller("v1/agents")
@UseGuards(OrgBindingGuard)
export class AgentsController {
  constructor(@Inject(AgentsService) private readonly svc: AgentsService) {}

  @Post()
  @HttpCode(201)
  async create(@Body() body: unknown, @Res({ passthrough: true }) res: Response) {
    const input = NewAgent.parse(body);
    const out = await this.svc.create(input.name, input.description ?? "");
    res.setHeader("Location", `/v1/agents/${out.agent.id}`);
    noStore(res);
    return out;
  }

  @Get()
  list(@Query() query: unknown) {
    return this.svc.list(resolvePage(query));
  }

  @Get(":agentId")
  one(@Param("agentId") agentId: string) {
    return this.svc.get(pathId(agentId));
  }

  @Delete(":agentId")
  @HttpCode(204)
  async remove(@Param("agentId") agentId: string): Promise<void> {
    await this.svc.remove(pathId(agentId));
  }

  @Post(":agentId/enrollment-secret")
  @HttpCode(200)
  async rotate(@Param("agentId") agentId: string, @Res({ passthrough: true }) res: Response) {
    const out = await this.svc.rotate(pathId(agentId));
    noStore(res);
    return out;
  }

  @Post(":agentId/grants")
  @HttpCode(201)
  async createGrant(@Param("agentId") agentId: string, @Body() body: unknown, @Res({ passthrough: true }) res: Response) {
    const id = pathId(agentId);
    const grant = await this.svc.createGrant(id, NewAgentGrant.parse(body));
    res.setHeader("Location", `/v1/agents/${id}/grants/${grant.id}`);
    return grant;
  }

  @Get(":agentId/grants")
  listGrants(@Param("agentId") agentId: string, @Query() query: unknown) {
    const id = pathId(agentId);
    return this.svc.listGrants(id, resolvePage(query));
  }

  @Delete(":agentId/grants/:grantId")
  @HttpCode(204)
  async revokeGrant(@Param("agentId") agentId: string, @Param("grantId") grantId: string): Promise<void> {
    const ids: [string, string] = [pathId(agentId), pathId(grantId)];
    await this.svc.revokeGrant(...ids);
  }
}
