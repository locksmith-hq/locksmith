import { Controller, Get, Inject, Param, Query, UseGuards } from "@nestjs/common";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { pathId, resolvePage } from "../platform/paging.js";
import { AgentsService } from "./agents.service.js";

/** Rust `api/agents.rs` read handlers. Check order as in axum: org binding (401), path id (404), query (400). */
@Controller("v1/agents")
@UseGuards(OrgBindingGuard)
export class AgentsController {
  constructor(@Inject(AgentsService) private readonly svc: AgentsService) {}

  @Get()
  list(@Query() query: unknown) {
    return this.svc.listAgents(resolvePage(query));
  }

  @Get(":agentId")
  one(@Param("agentId") agentId: string) {
    return this.svc.getAgent(pathId(agentId));
  }

  @Get(":agentId/grants")
  grants(@Param("agentId") agentId: string, @Query() query: unknown) {
    const id = pathId(agentId);
    return this.svc.listGrants(id, resolvePage(query));
  }
}
